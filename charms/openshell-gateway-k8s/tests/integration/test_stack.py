"""Integration tests for the composed OpenShell stack.

``terraform/openshell-stack`` deploys the gateway together with the Canonical
Identity Platform and cos-lite across four Juju models. These tests deploy
that stack on the session's controller and assert on the behaviors that only
exist once the pillars are wired: the models converge with their SAAS
relations, SSO works end to end through the identity platform, telemetry
reaches cos-lite, and a sandbox round-trips on the integrator's LXD. They
are the Python form of the stack CI's deployment setup and runtime
assertions, and skip themselves when the stack CI's environment is absent,
so plain charm-suite runs are unaffected.

Environment (set by the ``integration`` job of
``.github/workflows/ci-terraform.yaml``):

- ``STACK_IDENTITY_HOSTNAME``: the hostname the issuer is published on.
- ``STACK_EXTERNAL_HOSTNAME``: the hostname the gateway's ingress is
  published on.
- ``STACK_LXD_ENDPOINT``: the HTTPS endpoint of the LXD the integrator
  manages sandboxes on (the CI runner's MicroCloud LXD).
- ``STACK_LXD_CLIENT_CERT``, ``STACK_LXD_CLIENT_KEY`` and
  ``STACK_LXD_SERVER_CERT``: the client identity and server certificate for
  that endpoint.
- ``STACK_LXD_PROJECT`` (optional): the sandbox project, default
  ``openshell``.
- ``STACK_OPENSHELL_MODEL`` (optional): the pre-created openshell model's
  name, default ``openshell``.
- ``STACK_TF_DIR`` (optional): the stack module directory, default the
  repository's.
- ``STACK_VARS_FILE`` (optional): where the generated variables file is
  written, default ``/root/stack-vars.tfvars.json`` — the path the
  workflow's teardown step destroys with.

The tests run as root in the CI VM; the CA-trust installation depends on it.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import shutil
import subprocess
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import jubilant
import pytest
import yaml

from .helpers import (
    CHARM_DIR,
    K8S_CONTROLLER,
    OIDC_ADMIN_ROLE,
    OIDC_AUDIENCE,
    OIDC_ROLES_CLAIM,
    OIDC_USER_ROLE,
    REPO_ROOT,
    create_hydra_m2m_client,
    gateway_status,
    get_oidc_client_config,
    kubectl,
    openshell_gateway_add,
    openshell_gateway_remove,
    openshell_sandbox_create,
    openshell_sandbox_delete,
    openshell_sandbox_wait_running,
    openshell_status,
    run_cmd,
    unique_marker,
)
from .image_resolver import resolve_gateway_image
from .stack_lxd import StackLxd, StackLxdConfig

#: The gateway rock and the supervisor rock of one build, as this charm's
#: own `gateway-image` upstream source and `supervisor-image` default name
#: them.
GATEWAY_IMAGE = resolve_gateway_image()
SUPERVISOR_IMAGE = yaml.safe_load((CHARM_DIR / "charmcraft.yaml").read_text())["config"][
    "options"
]["supervisor-image"]["default"]

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.stack]

#: The CLI gateway registrations these tests create and remove again.
GATEWAY_NAME = "stack"
NOBODY_NAME = "stack-nobody"

CONVERGENCE_TIMEOUT = 40 * 60
TELEMETRY_TIMEOUT = 10 * 60
# Traefik creates its LoadBalancer service from its own hooks, well after
# terraform apply has returned.
LOAD_BALANCER_TIMEOUT = 20 * 60
POLL_INTERVAL = 15

#: The pillar keys of the stack module's ``models`` output, in the order the
#: convergence poll walks them.
PILLARS = ("openshell", "iam", "core", "cos_lite")

#: SAAS offers the openshell model must show once the glue is established.
EXPECTED_SAAS = (
    "oauth",
    "send-ca-cert",
    "prometheus-receive-remote-write",
    "grafana-dashboards",
)

_REQUIRED_ENV = (
    "STACK_IDENTITY_HOSTNAME",
    "STACK_EXTERNAL_HOSTNAME",
    "STACK_LXD_ENDPOINT",
    "STACK_LXD_CLIENT_CERT",
    "STACK_LXD_CLIENT_KEY",
    "STACK_LXD_SERVER_CERT",
)


@dataclasses.dataclass
class StackDeployment:
    """The deployed stack: model and application names plus connection details."""

    models: dict[str, dict[str, str]]
    app_names: dict[str, dict[str, Any]]
    identity_hostname: str
    external_hostname: str
    gateway_url: str
    tf_dir: Path


def _model_uuid(model: str) -> str:
    """Return the controller UUID of *model*, read from ``juju show-model``."""
    result = run_cmd("juju", "show-model", model, "--format", "json")
    assert result.returncode == 0, f"juju show-model {model} failed: {result.stderr}"
    entry = json.loads(result.stdout).get(model) or {}
    uuid = entry.get("model-uuid") or entry.get("uuid")
    assert uuid, f"juju show-model {model} returned no model uuid: {result.stdout}"
    return str(uuid)


def _terraform(tf_dir: Path, *args: str) -> None:
    """Run one terraform command against the stack module, failing loudly."""
    result = run_cmd("terraform", f"-chdir={tf_dir}", *args)
    assert result.returncode == 0, (
        f"terraform {' '.join(args)} failed ({result.returncode}):\n"
        f"{result.stdout}\n{result.stderr}"
    )


def _pending_units(status: jubilant.Status) -> list[str]:
    """Return one line per application or unit that is not converged yet.

    Convergence reads the workload state and the agent state the way the
    charm suite's own wait helpers do, through ``jubilant``'s status
    parsing — the agent state lives under ``juju-status`` for this
    controller type, not under ``agent-status``.
    """
    parts = []
    for name, app in status.apps.items():
        if app.app_status.current != "active":
            parts.append(f"{name} ({app.app_status.current})")
        for unit_name, unit in app.units.items():
            workload = unit.workload_status.current
            agent = unit.juju_status.current
            if workload == "active" and agent == "idle":
                continue
            message = unit.workload_status.message or ""
            parts.append(f"{unit_name} ({workload}/{agent}) {message}"[:120])
    return parts


def _await_convergence(models: dict[str, dict[str, str]]) -> None:
    """Poll every pillar model until every application and unit is active."""
    handles = {pillar: jubilant.Juju(model=model["name"]) for pillar, model in models.items()}
    deadline = time.monotonic() + CONVERGENCE_TIMEOUT
    while True:
        pending: dict[str, str] = {}
        for pillar, handle in handles.items():
            try:
                status = handle.status()
            except jubilant.CLIError as exc:
                pending[handle.model or pillar] = str(exc.stderr or exc).strip()[:120]
                continue
            problems = _pending_units(status)
            if problems:
                pending[handle.model or pillar] = ", ".join(problems[:8])
        if not pending:
            logger.info("All four models converged.")
            return
        if time.monotonic() > deadline:
            pytest.fail(f"the stack did not converge within {CONVERGENCE_TIMEOUT}s: {pending}")
        logger.info("waiting for convergence: %s", pending)
        time.sleep(30)


def _trust_model_ca(model: str, tls_app: str, cert_name: str) -> None:
    """Install a model's CA into the host trust store, like ``trust_self_signed_ca``."""
    handle = jubilant.Juju(model=model)
    result = handle.run(f"{tls_app}/0", "get-ca-certificate")
    assert result.status == "completed", result
    ca_pem = result.results.get("ca-certificate")
    assert ca_pem, f"get-ca-certificate returned no certificate: {result.results}"

    system_file = Path("/usr/local/share/ca-certificates") / f"{cert_name}.crt"
    if os.geteuid() == 0:
        system_file.write_text(ca_pem)
        update = run_cmd("update-ca-certificates")
    else:
        write = run_cmd("sudo", "tee", str(system_file), input=ca_pem)
        if write.returncode != 0:
            pytest.fail(f"could not install {cert_name} system-wide: {write.stderr}")
        update = run_cmd("sudo", "update-ca-certificates")
    assert update.returncode == 0, f"update-ca-certificates failed: {update.stderr}"


def _user_secret_uri(handle: jubilant.Juju, name: str) -> str | None:
    """Return the URI of the model's user secret *name*, if it already exists."""
    listing = json.loads(handle.cli("list-secrets", "--format", "json"))
    for uri, entry in (listing or {}).items():
        if entry.get("name") == name:
            return f"secret:{uri}"
    return None


def _model_lb_ip(model: str) -> str:
    """Return the load-balancer address announced in *model*'s namespace.

    Every pillar model runs exactly one Traefik, whose k8s service is the
    only LoadBalancer service in the model's namespace, so the announced
    address is the one the model's hostnames must resolve to. The charm
    creates that service itself once it is installed, so wait for it.
    """
    deadline = time.monotonic() + LOAD_BALANCER_TIMEOUT
    while True:
        services = json.loads(kubectl("-n", model, "get", "svc", "-o", "json"))
        addresses = [
            str(item["status"]["loadBalancer"]["ingress"][0]["ip"])
            for item in services.get("items", [])
            if item.get("spec", {}).get("type") == "LoadBalancer"
            and item.get("status", {}).get("loadBalancer", {}).get("ingress")
        ]
        assert len(addresses) <= 1, f"expected one load balancer in {model}, got: {addresses}"
        if addresses:
            return addresses[0]
        if time.monotonic() > deadline:
            pytest.fail(f"no load balancer announced in {model} within {LOAD_BALANCER_TIMEOUT}s")
        time.sleep(POLL_INTERVAL)


def _pod_ip(model: str, pod: str) -> str:
    """Return the pod IP of *pod*, discovered through kubectl."""
    address = kubectl("-n", model, "get", "pod", pod, "-o", "jsonpath={.status.podIP}").strip()
    assert address, f"no pod IP reported for {pod} in model {model}"
    return address


def _prometheus_query(model: str, pod_ip: str, query: str) -> list[dict[str, Any]]:
    """Run one instant query against cos-lite's Prometheus.

    cos-lite serves Prometheus over TLS on 9090, signed by the cos-lite CA,
    so the query goes to the pod IP with verification off — the assertion is
    on the series, not on the transport.
    """
    result = run_cmd(
        "curl",
        "-ksS",
        "--max-time",
        "10",
        "--get",
        "--data-urlencode",
        f"query={query}",
        f"https://{pod_ip}:9090/api/v1/query",
    )
    assert result.returncode == 0, f"prometheus query failed: {result.stdout}\n{result.stderr}"
    payload = json.loads(result.stdout)
    if payload.get("status") != "success":
        pytest.fail(f"prometheus query {query!r} failed: {result.stdout}")
    return payload["data"]["result"]


@pytest.fixture(scope="session")
def stack_environment() -> dict[str, str]:
    """Collect the stack CI environment, skipping when it is absent."""
    missing = [name for name in _REQUIRED_ENV if not os.environ.get(name)]
    for binary in ("juju", "terraform", "openshell", "tox"):
        if shutil.which(binary) is None:
            missing.append(binary)
    if missing:
        pytest.skip(f"stack integration environment not present (missing: {', '.join(missing)})")
    return {name: os.environ[name] for name in _REQUIRED_ENV}


@pytest.fixture(scope="session")
def stack_deployment(stack_environment: dict[str, str]) -> Generator[StackDeployment, None, None]:
    """Deploy the composed stack and destroy it again at session end.

    The LXD credentials secret follows the charm suite's order: the secret is
    added to the model before the apply, because its URI is part of the
    integrator's config, and granted after it, because granting needs the
    integrator application to exist. Nothing fires when the grant lands: the
    integrator reads the secret at its next ``update-status`` hook (every five
    minutes by default), and re-setting a config key to its current value is
    a no-op that runs no hook, so the convergence wait covers that interval.
    """
    tf_dir = Path(os.environ.get("STACK_TF_DIR") or (REPO_ROOT / "terraform" / "openshell-stack"))
    var_file = Path(os.environ.get("STACK_VARS_FILE") or "/root/stack-vars.tfvars.json")
    project = os.environ.get("STACK_LXD_PROJECT", "openshell")
    model_name = os.environ.get("STACK_OPENSHELL_MODEL", "openshell")
    identity_hostname = stack_environment["STACK_IDENTITY_HOSTNAME"]
    external_hostname = stack_environment["STACK_EXTERNAL_HOSTNAME"]

    # The stack's models live on the Kubernetes controller, so add-model
    # targets that controller explicitly. Switching is not an option: the
    # Juju CLI refuses it while JUJU_CONTROLLER overrides the controller,
    # which the stack CI sets. The model may pre-exist from an earlier run;
    # tolerating that failure keeps re-runs idempotent.
    try:
        jubilant.Juju().add_model(model_name, controller=K8S_CONTROLLER)
    except jubilant.CLIError as exc:
        if "already exists" not in (exc.stderr or ""):
            pytest.fail(f"juju add-model {model_name} failed: {exc.stderr}")

    # The LXD project and its driver-read profile: the module's documented
    # manual steps, driven over the REST API because
    # the VM has no lxc client.
    lxd = StackLxd(
        StackLxdConfig(
            endpoint=stack_environment["STACK_LXD_ENDPOINT"],
            client_cert=Path(stack_environment["STACK_LXD_CLIENT_CERT"]),
            client_key=Path(stack_environment["STACK_LXD_CLIENT_KEY"]),
            server_cert=Path(stack_environment["STACK_LXD_SERVER_CERT"]),
        )
    )
    lxd.ensure_project(project)
    lxd.ensure_project_profile(project)

    handle = jubilant.Juju(model=model_name)
    # A named user secret is created once: a re-run against a deployed
    # model reuses the one the earlier run minted.
    secret_uri = _user_secret_uri(handle, "lxd-credentials")
    if secret_uri is None:
        secret_uri = handle.add_secret(
            "lxd-credentials",
            {
                "client-cert": Path(stack_environment["STACK_LXD_CLIENT_CERT"]).read_text(),
                "client-key": Path(stack_environment["STACK_LXD_CLIENT_KEY"]).read_text(),
                "server-cert": Path(stack_environment["STACK_LXD_SERVER_CERT"]).read_text(),
            },
        )

    payload: dict[str, Any] = {
        "models": {"openshell": {"uuid": _model_uuid(model_name)}},
        "identity_hostname": identity_hostname,
        "openshell": {
            "external_hostname": external_hostname,
            # The gateway maps its RBAC roles from the token claim
            # `roles-claim` names. Hydra's M2M tokens carry the
            # granted scopes in `scp`, never `groups`, so the claim
            # and the role names follow the charm suite's constants —
            # with them, helpers/oidc.py and helpers/openshell_cli.py
            # apply unchanged.
            "oidc": {
                "admin_role": OIDC_ADMIN_ROLE,
                "user_role": OIDC_USER_ROLE,
                "roles_claim": OIDC_ROLES_CLAIM,
            },
            # Both openshell charms publish only latest/edge on
            # ubuntu@24.04 today, so the modules' latest/stable
            # default cannot resolve. The openshell snap stays on
            # latest/stable; the CLI/gateway pairing tolerates that
            # (see the repo gotcha on CLI versions).
            # The published revision bundles a gateway rock whose driver
            # defaults to `lxdbr0` instead of reading the project's default
            # profile, and defaults to a supervisor image without
            # /openshell-sandbox; pin both to the rocks this charm's own
            # defaults name, until a revision ships them.
            "gateway": {
                "channel": "latest/edge",
                "config": {"supervisor-image": SUPERVISOR_IMAGE},
                "resources": {"gateway-image": GATEWAY_IMAGE},
            },
            "integrator": {
                "channel": "latest/edge",
                "config": {
                    # The integrator's config takes a scheme-less host:port
                    # list; the environment's endpoint is an HTTPS URL
                    # because the LXD REST client here dials it directly.
                    "lxd-endpoints": stack_environment["STACK_LXD_ENDPOINT"].removeprefix(
                        "https://"
                    ),
                    "lxd-credentials": secret_uri,
                    "project": project,
                },
            },
        },
    }
    var_file.write_text(json.dumps(payload))

    _terraform(tf_dir, "init", "-input=false")
    _terraform(tf_dir, "apply", "-auto-approve", "-input=false", f"-var-file={var_file}")

    outputs = run_cmd("terraform", f"-chdir={tf_dir}", "output", "-json")
    assert outputs.returncode == 0, f"terraform output failed: {outputs.stderr}"
    rendered = json.loads(outputs.stdout)
    models = {pillar: dict(rendered["models"]["value"][pillar]) for pillar in PILLARS}
    app_names: dict[str, dict[str, Any]] = rendered["app_names"]["value"]

    # The k8s load balancer assigns the announced addresses in service
    # creation order, which is not stable across applies: the planned
    # hostnames can land on another pillar's Traefik than the one that
    # actually answers them. Read the announced addresses back from the
    # cluster and, when they differ, re-apply config-only with them
    # before waiting for convergence.
    announced_identity = _model_lb_ip(models["core"]["name"])
    announced_external = _model_lb_ip(models["openshell"]["name"])
    if announced_identity != identity_hostname or announced_external != external_hostname:
        logger.info(
            "load balancers announced %s/%s, planned %s/%s — re-applying config-only",
            announced_identity,
            announced_external,
            identity_hostname,
            external_hostname,
        )
        identity_hostname, external_hostname = announced_identity, announced_external
        payload["identity_hostname"] = identity_hostname
        payload["openshell"]["external_hostname"] = external_hostname
        var_file.write_text(json.dumps(payload))
        _terraform(tf_dir, "apply", "-auto-approve", "-input=false", f"-var-file={var_file}")

    handle.grant_secret("lxd-credentials", app_names["openshell"]["integrator"])

    _await_convergence(models)

    yield StackDeployment(
        models=models,
        app_names=app_names,
        identity_hostname=identity_hostname,
        external_hostname=external_hostname,
        gateway_url=f"https://{external_hostname}:8443",
        tf_dir=tf_dir,
    )

    # Best-effort: the workflow's teardown step repeats it when this did not
    # get the chance to run.
    try:
        result = run_cmd(
            "terraform",
            f"-chdir={tf_dir}",
            "destroy",
            "-auto-approve",
            "-input=false",
            f"-var-file={var_file}",
            timeout=1800,
        )
    except subprocess.TimeoutExpired:
        logger.warning("the stack destroy timed out")
        return
    if result.returncode != 0:
        logger.warning("the stack destroy failed: %s", result.stderr)


@pytest.fixture(scope="session")
def juju(stack_deployment: StackDeployment) -> Generator[jubilant.Juju, None, None]:
    """Provide a Jubilant handle to the openshell model.

    Named ``juju`` so the conftest failure diagnostics capture this model's
    status and debug log the way they do for the charm suite's own handle.
    """
    yield jubilant.Juju(model=stack_deployment.models["openshell"]["name"])


@pytest.fixture(scope="session")
def identity_login(
    stack_deployment: StackDeployment, juju: jubilant.Juju
) -> Generator[dict[str, str], None, None]:
    """Register the openshell CLI against the gateway through the composed SSO chain.

    The CLI talks to two TLS endpoints — the gateway's, signed by the
    openshell model's CA, and the issuer's, signed by the core model's CA —
    so both model CAs go into the host trust store before anything dials out.
    """
    iam = jubilant.Juju(model=stack_deployment.models["iam"]["name"])
    _trust_model_ca(
        stack_deployment.models["openshell"]["name"],
        stack_deployment.app_names["openshell"]["self_signed_certificates"],
        "stack-gateway-ca",
    )
    _trust_model_ca(
        stack_deployment.models["core"]["name"],
        stack_deployment.app_names["core"]["self_signed_certificates"],
        "stack-identity-ca",
    )

    oidc = get_oidc_client_config(juju)
    issuer_url = oidc["issuer"]
    audience = oidc.get("audience") or OIDC_AUDIENCE
    assert issuer_url.startswith("https://"), f"unexpected issuer URL: {issuer_url}"

    # A registration from an earlier session may persist in the CLI's own
    # config, and the add below demands a clean name.
    run_cmd("openshell", "gateway", "remove", GATEWAY_NAME)

    client_id, client_secret = create_hydra_m2m_client(iam, audience=audience)
    openshell_gateway_add(
        name=GATEWAY_NAME,
        gateway_url=stack_deployment.gateway_url,
        issuer_url=issuer_url,
        client_id=client_id,
        client_secret=client_secret,
        audience=audience,
    )
    try:
        yield {"issuer_url": issuer_url, "audience": audience}
    finally:
        openshell_gateway_remove(GATEWAY_NAME)


def test_all_four_models_converged(stack_deployment: StackDeployment, juju: jubilant.Juju) -> None:
    """Every pillar is active and the openshell model shows the composed offers.

    The deploy fixture already waited every model to active/idle; this asserts
    the part convergence alone does not prove — the SAAS relations the glue
    established over composed offers.
    """
    result = run_cmd(
        "juju", "status", "-m", stack_deployment.models["openshell"]["name"], "--format", "json"
    )
    assert result.returncode == 0, result.stderr
    # juju 3.x reports the model's consumed offers under
    # ``application-endpoints`` (``remote-applications`` is juju 2.x); the
    # keys are the SAAS applications the glue created over the composed
    # offer URLs.
    saas = sorted((json.loads(result.stdout).get("application-endpoints") or {}).keys())
    for expected in EXPECTED_SAAS:
        assert any(expected in offer for offer in saas), f"{expected} not among SAAS: {saas}"


def test_kratos_admin_account(stack_deployment: StackDeployment) -> None:
    """The identity platform's documented operator step succeeds."""
    iam = jubilant.Juju(model=stack_deployment.models["iam"]["name"])
    kratos = stack_deployment.app_names["iam"]["kratos"]
    result = iam.run(
        f"{kratos}/0",
        "create-admin-account",
        params={
            "username": "stack-admin",
            "email": "stack-admin@example.com",
            "password": "stack-ci-admin",
        },
    )
    assert result.status == "completed", result


def test_sso_login_accepted(
    identity_login: dict[str, str], stack_deployment: StackDeployment, juju: jubilant.Juju
) -> None:
    """The gateway accepts a Hydra-issued login over the composed chain.

    The registration in the identity_login fixture already exercised oauth
    offer, issuer hostname, CA transfer and OIDC discovery; the gateway's own
    status action reports the result of all of them.
    """
    status = gateway_status(juju)
    assert status.get("oauth-ready") == "True", status
    assert int(status.get("received-ca-certificates", "0")) >= 1, status
    logger.info("openshell status:\n%s", openshell_status(GATEWAY_NAME))


def test_unroled_principal_refused(
    identity_login: dict[str, str], stack_deployment: StackDeployment
) -> None:
    """A principal whose scopes map to no RBAC role is refused a sandbox.

    Hydra's M2M tokens carry the granted scopes in the claim the gateway
    reads roles from (`scp` in this deployment); a client scoped to nothing
    the charm's roles name therefore has no role, and the gateway has to
    refuse it — an admin-scoped login alone is not the whole SSO story.
    """
    iam = jubilant.Juju(model=stack_deployment.models["iam"]["name"])
    hydra = stack_deployment.app_names["iam"]["hydra"]
    audience = identity_login["audience"]
    result = iam.run(
        f"{hydra}/0",
        "create-oauth-client",
        params={
            "name": "openshell-cli-nobody",
            "grant-types": ["client_credentials"],
            "scope": ["openshell-nobody"],
            "audience": [audience],
            "token-endpoint-auth-method": "client_secret_post",
        },
    )
    assert result.status == "completed", result
    client_id = result.results.get("client-id")
    client_secret = result.results.get("client-secret") or result.results.get("secret")
    assert client_id and client_secret, f"missing client credentials: {result.results}"

    openshell_gateway_add(
        name=NOBODY_NAME,
        gateway_url=stack_deployment.gateway_url,
        issuer_url=identity_login["issuer_url"],
        client_id=client_id,
        client_secret=client_secret,
        audience=audience,
        scopes="openshell-nobody",
    )
    try:
        created = run_cmd(
            "openshell",
            "-g",
            NOBODY_NAME,
            "sandbox",
            "create",
            "--name",
            unique_marker("stack-ci-nobody"),
        )
    finally:
        openshell_gateway_remove(NOBODY_NAME)
    assert created.returncode != 0, (
        "a principal with no RBAC role created a sandbox; the gateway's role "
        f"mapping is not enforced:\n{created.stdout}\n{created.stderr}"
    )


def test_gateway_and_identity_metrics_reach_cos_lite(
    stack_deployment: StackDeployment, juju: jubilant.Juju
) -> None:
    """Gateway and identity-platform series land in cos-lite's Prometheus.

    ``up`` is the synthetic series every Prometheus-compatible scraper writes
    per target: a wired but broken target yields 0 and an unwired one yields
    no series at all, so a healthy ``up`` series is the remote-write and
    metrics glues proven, not merely configured.
    """
    cos_model = stack_deployment.models["cos_lite"]["name"]
    prometheus = stack_deployment.app_names["cos_lite"]["prometheus"]
    pod_ip = _pod_ip(cos_model, f"{prometheus}-0")

    gateway_app = stack_deployment.app_names["openshell"]["gateway"]
    iam_names = [stack_deployment.app_names["iam"][key] for key in ("hydra", "kratos", "login_ui")]
    iam_regex = "|".join(iam_names)
    iam_query = f'up{{juju_application=~"{iam_regex}"}}'

    deadline = time.monotonic() + TELEMETRY_TIMEOUT
    while True:
        gateway_series = _prometheus_query(
            cos_model, pod_ip, f'up{{juju_application="{gateway_app}"}}'
        )
        iam_series = _prometheus_query(cos_model, pod_ip, iam_query)
        gateway_healthy = any(
            sample.get("value", [None, "0"])[1] == "1" for sample in gateway_series
        )
        if gateway_healthy and len(iam_series) >= len(iam_names):
            return
        if time.monotonic() > deadline:
            pytest.fail(
                f"telemetry did not converge within {TELEMETRY_TIMEOUT}s: "
                f"gateway series={gateway_series} iam series={iam_series}"
            )
        logger.info(
            "waiting for telemetry: gateway series=%d iam series=%d",
            len(gateway_series),
            len(iam_series),
        )
        time.sleep(POLL_INTERVAL)


def test_gateway_and_identity_dashboards_in_cos_lite_grafana(
    stack_deployment: StackDeployment, juju: jubilant.Juju
) -> None:
    """The gateway's and the identity platform's dashboards exist in cos-lite."""
    cos_model = stack_deployment.models["cos_lite"]["name"]
    grafana = stack_deployment.app_names["cos_lite"]["grafana"]
    handle = jubilant.Juju(model=cos_model)
    result = handle.run(f"{grafana}/0", "get-admin-password")
    assert result.status == "completed", result
    password = result.results.get("admin-password")
    assert password, f"get-admin-password returned no password: {result.results}"
    pod_ip = _pod_ip(cos_model, f"{grafana}-0")

    deadline = time.monotonic() + TELEMETRY_TIMEOUT
    while True:
        search = run_cmd(
            "curl",
            "-ksS",
            "--max-time",
            "10",
            "-u",
            f"admin:{password}",
            f"https://{pod_ip}:3000/api/search",
        )
        assert search.returncode == 0, f"grafana search failed: {search.stderr}"
        dashboards = json.loads(search.stdout)
        titles = [str(entry.get("title", "")) for entry in dashboards if isinstance(entry, dict)]
        identity_dashboards = any(
            "Hydra" in title or "Kratos" in title or "Identity Platform" in title
            for title in titles
        )
        if "OpenShell Gateway" in titles and identity_dashboards:
            logger.info("cos-lite Grafana dashboards: %s", titles)
            return
        if time.monotonic() > deadline:
            pytest.fail(
                f"the expected dashboards did not appear within {TELEMETRY_TIMEOUT}s: {titles}"
            )
        time.sleep(POLL_INTERVAL)


def test_sandbox_round_trip(
    identity_login: dict[str, str], stack_deployment: StackDeployment
) -> None:
    """Create, run and delete a sandbox on the integrator's MicroCloud LXD.

    The CI builds MicroCloud precisely to supply the OVN network the
    driver's default ``restrict-sandbox-egress=true`` requires, so the
    round-trip is the composed stack's own proof that sandboxes work.
    """
    name = unique_marker("stack-ci")
    try:
        # The charm's default sandbox image: a plain `ubuntu:24.04` OCI image
        # carries nothing the supervisor needs, and its sandbox errors out.
        openshell_sandbox_create(name, gateway_name=GATEWAY_NAME)
        openshell_sandbox_wait_running(name, timeout=600, gateway_name=GATEWAY_NAME)
    finally:
        openshell_sandbox_delete(name, gateway_name=GATEWAY_NAME, check=False)
