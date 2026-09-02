"""Shared fixtures and helpers for OpenShell Gateway integration tests.

The full-stack deployment plumbing is shared across ``test_charm.py`` and the
provider-path modules ``test_lxd_integrator.py`` and ``test_lxd_offer.py``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.request
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jubilant
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .lxd_host import (
    HostLxdEndpoint,
    read_lxd_config,
    setup_host_lxd_endpoint,
    teardown_host_lxd_endpoint,
)

logger = logging.getLogger(__name__)

_gateway_urls: dict[str, str] = {}

CHARM_DIR = Path(__file__).parent.parent.parent
REPO_ROOT = CHARM_DIR.parent.parent
APP_NAME = "openshell-gateway-k8s"
CONTAINER_NAME = "gateway"
DB_GATEWAY_APP = "postgresql-gateway"
DB_HYDRA_APP = "postgresql-hydra"
HYDRA_APP = "hydra"
LOGIN_UI_APP = "login-ui"
TRAEFIK_APP = "traefik-k8s"
TLS_APP = "self-signed-certificates"
INTEGRATOR_APP = "lxd-integrator-k8s"

INFRA_APPS = [
    DB_GATEWAY_APP,
    DB_HYDRA_APP,
    HYDRA_APP,
    LOGIN_UI_APP,
    TRAEFIK_APP,
    TLS_APP,
]

OIDC_ADMIN_ROLE = "gw-admin"
OIDC_USER_ROLE = "gw-user"
OIDC_AUDIENCE = "openshell-cli"
OIDC_ROLES_CLAIM = "scp"


def _run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
    """Run a subprocess, returning a CompletedProcess with captured output."""
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        check=False,
        **kwargs,
    )


def _ensure_juju_readable(path: Path) -> Path:
    """Copy a charm file to a location the confined ``juju`` snap can read.

    The snap cannot access paths under ``/work`` in some CI environments, so
    charm files built there are copied under the user's home directory.
    """
    path = path.resolve()
    if str(path).startswith(str(Path.home())):
        return path

    cache_dir = Path.home() / ".cache" / "openshell-gateway-integration"
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = cache_dir / path.name
    shutil.copy2(path, dest)
    return dest


@pytest.fixture(scope="module")
def charm_file() -> str:
    """Resolve a .charm artifact that the confined ``juju`` snap can read.

    If ``CHARM_FILE`` is set, use it (after copying to an accessible path).
    Otherwise invoke ``charmcraft pack`` and copy the resulting artifact.
    """
    env_path = os.environ.get("CHARM_FILE")
    source = Path(env_path) if env_path else None

    if source is None:
        if shutil.which("charmcraft") is None:
            pytest.skip("CHARM_FILE not set and 'charmcraft' binary not found")
        result = subprocess.run(
            ["charmcraft", "pack"],
            cwd=str(CHARM_DIR),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip(f"charmcraft pack failed:\n{result.stderr}")
        charms = sorted(CHARM_DIR.glob("*.charm"))
        if not charms:
            pytest.skip("charmcraft pack succeeded but no .charm file found")
        source = charms[-1]

    accessible = _ensure_juju_readable(source)
    return str(accessible)


@pytest.fixture(scope="module")
def integrator_charm_file() -> str:
    """Resolve a ``lxd-integrator-k8s`` .charm artifact the ``juju`` snap can read.

    If ``INTEGRATOR_CHARM_FILE`` is set, use it (after copying to an accessible
    path). Otherwise invoke ``charmcraft pack`` in ``charms/lxd-integrator-k8s``
    and copy the resulting artifact.
    """
    env_path = os.environ.get("INTEGRATOR_CHARM_FILE")
    source = Path(env_path) if env_path else None

    if source is None:
        if shutil.which("charmcraft") is None:
            pytest.skip("INTEGRATOR_CHARM_FILE not set and 'charmcraft' not found")
        integrator_dir = REPO_ROOT / "charms" / "lxd-integrator-k8s"
        result = subprocess.run(
            ["charmcraft", "pack"],
            cwd=str(integrator_dir),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip(f"charmcraft pack failed for lxd-integrator-k8s:\n{result.stderr}")
        charms = sorted(integrator_dir.glob("*.charm"))
        if not charms:
            pytest.skip("charmcraft pack succeeded but no .charm file found")
        source = charms[-1]

    accessible = _ensure_juju_readable(source)
    return str(accessible)


def _find_rock_file() -> Path | None:
    """Locate a pre-built gateway rock in the repository."""
    candidates = [
        *REPO_ROOT.glob("*.rock"),
        *(REPO_ROOT / "rocks" / "openshell-gateway").glob("*.rock"),
    ]
    if not candidates:
        return None
    return sorted(candidates)[-1]


def _build_rock() -> Path:
    """Build the gateway rock with rockcraft and return the produced file."""
    if shutil.which("rockcraft") is None:
        pytest.skip("No gateway rock found and 'rockcraft' is not available")

    rock_dir = REPO_ROOT / "rocks" / "openshell-gateway"
    result = subprocess.run(
        ["rockcraft", "pack"],
        cwd=str(rock_dir),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"rockcraft pack failed:\n{result.stderr}")

    rocks = sorted(rock_dir.glob("*.rock"))
    if not rocks:
        pytest.skip("rockcraft pack succeeded but no .rock file found")
    return rocks[-1]


def _push_rock_to_registry(rock_file: Path, registry: str) -> str:
    """Push a local rock to the local registry using skopeo."""
    if shutil.which("skopeo") is None:
        pytest.skip("skopeo is required to import the gateway rock into the registry")

    dest = f"docker://{registry}/openshell-gateway:latest"
    logger.info("Pushing %s to %s", rock_file, dest)
    result = subprocess.run(
        [
            "skopeo",
            "copy",
            f"oci-archive:{rock_file}",
            dest,
            "--dest-tls-verify=false",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"skopeo copy failed:\n{result.stderr}")
    return f"{registry}/openshell-gateway:latest"


@pytest.fixture(scope="module")
def gateway_image() -> str:
    """Return the OCI image ref for the gateway workload.

    Precedence:
      1. ``GATEWAY_IMAGE`` env var (use an already-published image).
      2. ``ROCK_FILE`` env var or any ``*.rock`` in the repo, pushed to the
         local registry snap with ``skopeo``.
      3. Build the rock with ``rockcraft`` and push it.

    The local registry is read from ``LOCAL_REGISTRY`` and defaults to
    ``localhost:5000``.
    """
    image = os.environ.get("GATEWAY_IMAGE")
    if image:
        return image

    registry = os.environ.get("LOCAL_REGISTRY", "localhost:5000")
    # Sanity-check that the registry snap is reachable before spending time
    # building or copying the rock.
    try:
        urllib.request.urlopen(f"http://{registry}/v2/", timeout=5).read()
    except Exception as exc:
        pytest.skip(f"Local registry {registry} is not reachable: {exc}")

    rock_file = os.environ.get("ROCK_FILE")
    source = Path(rock_file) if rock_file else _find_rock_file() or _build_rock()

    return _push_rock_to_registry(source, registry)


@pytest.fixture(scope="module")
def openshell_available() -> None:
    """Skip tests that require the externally installed ``openshell`` snap."""
    if shutil.which("openshell") is None:
        pytest.skip("openshell snap not found on PATH; skipping CLI connectivity tests")


def _deploy_infrastructure(juju: jubilant.Juju) -> None:
    """Deploy and relate the supporting charms for the gateway."""
    logger.info("Deploying supporting infrastructure")

    juju.deploy("postgresql-k8s", app=DB_GATEWAY_APP, channel="14/stable", trust=True)
    juju.deploy("postgresql-k8s", app=DB_HYDRA_APP, channel="14/stable", trust=True)
    juju.deploy("self-signed-certificates", app=TLS_APP, channel="1/stable")
    juju.deploy("traefik-k8s", app=TRAEFIK_APP, channel="latest/stable", trust=True)
    juju.deploy("hydra", app=HYDRA_APP, channel="latest/stable", trust=True)
    juju.deploy(
        "identity-platform-login-ui-operator",
        app=LOGIN_UI_APP,
        channel="latest/stable",
        trust=True,
    )
    # Hydra needs cluster-scoped trust to manage its Kubernetes resources.
    juju.cli("trust", HYDRA_APP, "--scope=cluster")

    logger.info("Relating infrastructure charms")
    juju.integrate(f"{HYDRA_APP}:pg-database", f"{DB_HYDRA_APP}:database")
    juju.integrate(f"{HYDRA_APP}:ui-endpoint-info", f"{LOGIN_UI_APP}:ui-endpoint-info")
    juju.integrate(f"{HYDRA_APP}:public-route", f"{TRAEFIK_APP}:traefik-route")
    juju.integrate(f"{HYDRA_APP}:internal-route", f"{TRAEFIK_APP}:traefik-route")
    juju.integrate(f"{LOGIN_UI_APP}:public-route", f"{TRAEFIK_APP}:traefik-route")
    juju.integrate(f"{TRAEFIK_APP}:certificates", f"{TLS_APP}:certificates")

    logger.info("Waiting for infrastructure relations to converge")
    juju.wait(
        lambda s: jubilant.all_active(s, *INFRA_APPS) and jubilant.all_agents_idle(s, *INFRA_APPS),
        error=_fail_on_app_error(juju, *INFRA_APPS, hook_retry_limit=1),
        timeout=1800,
    )


def _fail_on_app_error(
    juju: jubilant.Juju,
    *app_names: str,
    hook_retry_limit: int = 0,
) -> Callable[[jubilant.Status], bool]:
    """Retry hook failures up to a limit, then fail with Juju logs."""
    hook_retries: dict[str, int] = {}
    retry_grace_deadlines: dict[str, float] = {}

    def _error(status: jubilant.Status) -> bool:
        for app_name in app_names:
            app = status.apps.get(app_name)
            if app is None or app.app_status.current != "error":
                continue
            failed_hook = (app.app_status.message or "").startswith("hook failed:")
            for unit_name, unit in app.units.items():
                if unit.workload_status.current != "error" or not failed_hook:
                    continue
                retries = hook_retries.get(unit_name, 0)
                if retries < hook_retry_limit:
                    logger.warning(
                        "%s entered error; retrying failed hook (%d/%d)",
                        unit_name,
                        retries + 1,
                        hook_retry_limit,
                    )
                    juju.cli("resolved", unit_name)
                    hook_retries[unit_name] = retries + 1
                    retry_grace_deadlines[unit_name] = time.monotonic() + 30
                    return False
                if time.monotonic() < retry_grace_deadlines.get(unit_name, 0):
                    return False
            try:
                log_output = juju.debug_log(limit=500)
            except (jubilant.CLIError, jubilant.TaskError):
                logger.exception("Failed to capture Juju debug logs")
            else:
                logger.error("Juju debug-log after %s entered error:\n%s", app_name, log_output)
            pytest.fail(f"{app_name} entered error: {app.app_status.message}")
        return False

    return _error


def _get_traefik_lb_address(juju: jubilant.Juju, timeout: int = 300) -> str:
    """Discover the external LoadBalancer address assigned to Traefik."""
    model = juju.model.split(":")[-1]
    deadline = time.monotonic() + timeout

    while True:
        for cmd_prefix in (["kubectl"], ["microk8s", "kubectl"]):
            if shutil.which(cmd_prefix[0]) is None:
                continue
            cmd = [
                *cmd_prefix,
                "-n",
                model,
                "get",
                "svc",
                f"{TRAEFIK_APP}-lb",
                "-o",
                "jsonpath={.status.loadBalancer.ingress[0].ip}",
            ]
            result = _run(*cmd)
            address = result.stdout.strip()
            if result.returncode == 0 and address:
                return address

            # Some clouds assign a hostname instead of an IP.
            cmd[-1] = "jsonpath={.status.loadBalancer.ingress[0].hostname}"
            result = _run(*cmd)
            address = result.stdout.strip()
            if result.returncode == 0 and address:
                return address

        if time.monotonic() > deadline:
            pytest.fail(
                f"Could not determine Traefik LoadBalancer address for service "
                f"{TRAEFIK_APP}-lb (is MetalLB configured and kubectl available?)"
            )
        time.sleep(5)


def _wait_for_gateway_blocked(
    juju: jubilant.Juju,
    message: str = "lxd relation missing",
    timeout: int = 300,
) -> None:
    """Wait until the gateway reports a blocked status containing *message*."""

    def _blocked(status: jubilant.Status) -> bool:
        app = status.apps.get(APP_NAME)
        if app is None:
            return False
        return app.app_status.current == "blocked" and message in (app.app_status.message or "")

    juju.wait(_blocked, timeout=timeout)


def _wait_for_workload_running(juju: jubilant.Juju, timeout: int = 900) -> dict[str, str]:
    """Wait until the gateway action reports workload-running=True."""
    deadline = time.monotonic() + timeout
    while True:
        result = juju.run(f"{APP_NAME}/0", "get-gateway-status")
        if result.status == "completed" and result.results.get("workload-running") == "True":
            return dict(result.results)
        if time.monotonic() > deadline:
            pytest.fail(f"gateway workload did not become running within {timeout}s")
        time.sleep(5)


def _deploy_gateway(juju: jubilant.Juju, charm_file: str, gateway_image: str) -> str:
    """Deploy the gateway charm, wire it up, and return the public gateway URL.

    The fixture deliberately does not wait for the gateway to become active:
    the gateway requires an ``lxd`` provider relation, and each provider-path
    module supplies its own. Callers that need an active gateway should invoke
    ``_wait_for_gateway_stack`` after relating their provider.
    """
    logger.info("Deploying OpenShell Gateway charm")
    juju.deploy(
        charm_file,
        app=APP_NAME,
        resources={"gateway-image": gateway_image},
        config={
            "oidc-admin-role": OIDC_ADMIN_ROLE,
            "oidc-user-role": OIDC_USER_ROLE,
            "oidc-audience": OIDC_AUDIENCE,
            "oidc-roles-claim": OIDC_ROLES_CLAIM,
        },
    )

    logger.info("Relating gateway to infrastructure")
    juju.integrate(f"{APP_NAME}:database", f"{DB_GATEWAY_APP}:database")
    juju.integrate(f"{APP_NAME}:certificates", f"{TLS_APP}:certificates")
    juju.integrate(f"{APP_NAME}:oauth", f"{HYDRA_APP}:oauth")
    juju.integrate(f"{APP_NAME}:ingress", f"{TRAEFIK_APP}:traefik-route")

    logger.info("Discovering Traefik LoadBalancer address for external hostname")
    lb_address = _get_traefik_lb_address(juju)
    external_hostname = lb_address
    logger.info("Using external hostname %s", external_hostname)

    # Traefik's external_hostname drives the OAuth2 issuer URL that Hydra
    # advertises. The gateway needs the same hostname for its TLS SAN and
    # SNI-based ingress route.
    juju.config(TRAEFIK_APP, {"external_hostname": external_hostname})
    juju.config(APP_NAME, {"external-hostname": external_hostname})

    return f"https://{external_hostname}:8443"


def _wait_for_gateway_stack(juju: jubilant.Juju, timeout: int = 1800) -> dict[str, str]:
    """Wait until the gateway is active, the workload is running, and the stack is idle."""
    juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=timeout)
    status = _wait_for_workload_running(juju)
    logger.info("Gateway readiness: %s", status)
    juju.wait(
        lambda s: (
            jubilant.all_active(s, *INFRA_APPS, APP_NAME)
            and jubilant.all_agents_idle(s, *INFRA_APPS, APP_NAME)
        ),
        timeout=timeout,
    )
    return status


K8S_CONTROLLER = os.environ.get("JUJU_CONTROLLER", "concierge-k8s")
LXD_CONTROLLER = os.environ.get("JUJU_LXD_CONTROLLER", "concierge-lxd")


@pytest.fixture(scope="module")
def juju(charm_file: str, gateway_image: str) -> jubilant.Juju:
    """Provide a Jubilant Juju handle with the gateway stack deployed.

    Infrastructure and the gateway charm are deployed, but no ``lxd`` provider
    is related. Each test module is responsible for supplying its own provider
    and waiting for the gateway to become active.

    If ``JUJU_MODEL`` is set the tests run in that existing model and the model
    is left in place. Otherwise a temporary model is created on the Kubernetes
    controller (``concierge-k8s`` by default, overridable via ``JUJU_CONTROLLER``)
    and destroyed at teardown.
    """
    existing_model = os.environ.get("JUJU_MODEL")

    def _deploy(juju: jubilant.Juju) -> None:
        _deploy_infrastructure(juju)
        gateway_url = _deploy_gateway(juju, charm_file, gateway_image)
        _gateway_urls[juju.model] = gateway_url

    if existing_model:
        juju = jubilant.Juju(model=existing_model)
        _deploy(juju)
        yield juju
        return

    with jubilant.temp_model(controller=K8S_CONTROLLER) as juju:
        _deploy(juju)
        yield juju


def _discover_gateway_url(juju: jubilant.Juju) -> str:
    """Re-discover the public gateway URL from the deployed model."""
    lb_address = _get_traefik_lb_address(juju)
    return f"https://{lb_address}:8443"


@pytest.fixture(scope="module")
def gateway_url(juju: jubilant.Juju) -> str:
    """Return the public gateway URL discovered during deployment."""
    url = _gateway_urls.get(juju.model)
    if not url:
        url = _discover_gateway_url(juju)
        _gateway_urls[juju.model] = url
    return url


def gateway_client_cert_fingerprint(juju: jubilant.Juju) -> str:
    """Return the SHA-256 fingerprint of the gateway's LXD client certificate.

    The ``get-lxd-client-cert`` action returns the client certificate PEM under
    the ``certificate`` key. ``certificate-fingerprint`` is the *provider's*
    server fingerprint and must not be used here.
    """
    result = juju.run(f"{APP_NAME}/0", "get-lxd-client-cert")
    assert result.status == "completed", result
    cert_pem = result.results.get("certificate")
    assert cert_pem, "get-lxd-client-cert did not return a client certificate"
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def lxc_trust_fingerprints(
    runner: Any,
) -> set[str]:
    """Return the set of certificate fingerprints from ``lxc config trust list``.

    ``runner`` is a callable that runs an ``lxc`` argv and returns either a
    ``subprocess.CompletedProcess`` or a ``jubilant.Task`` with a ``stdout``
    attribute.
    """
    result = runner("query", "/1.0/certificates?recursion=1")
    stdout = result.stdout if hasattr(result, "stdout") else str(result)
    certs = json.loads(stdout)
    return {cert["fingerprint"].lower() for cert in certs}


def assert_trust_registered(
    juju: jubilant.Juju,
    fingerprint_source: Any,
    *,
    timeout: int = 300,
) -> None:
    """Poll until the gateway's client certificate is trusted by the LXD."""
    expected = gateway_client_cert_fingerprint(juju)
    deadline = time.monotonic() + timeout
    while True:
        fingerprints = fingerprint_source()
        if expected in fingerprints:
            return
        if time.monotonic() > deadline:
            pytest.fail(f"gateway cert {expected} not registered in LXD trust store")
        time.sleep(5)


def assert_trust_withdrawn(
    juju: jubilant.Juju,
    fingerprint_source: Any,
    *,
    timeout: int = 300,
) -> None:
    """Poll until the gateway's client certificate is removed from the LXD trust store."""
    expected = gateway_client_cert_fingerprint(juju)
    deadline = time.monotonic() + timeout
    while True:
        fingerprints = fingerprint_source()
        if expected not in fingerprints:
            return
        if time.monotonic() > deadline:
            pytest.fail(f"gateway cert {expected} still present in LXD trust store")
        time.sleep(5)


def trust_self_signed_ca(juju: jubilant.Juju) -> str:
    """Install the self-signed CA into the host trust store.

    Returns the PEM so callers can also pass it via ``SSL_CERT_FILE``.
    """
    result = juju.run(f"{TLS_APP}/0", "get-ca-certificate")
    assert result.status == "completed", result
    ca_pem = result.results.get("ca-certificate")
    assert ca_pem, "get-ca-certificate did not return a certificate"

    cert_dir = Path.home() / ".local" / "share" / "openshell-gateway-integration"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_file = cert_dir / "ca.crt"
    cert_file.write_text(ca_pem)

    system_file = Path("/usr/local/share/ca-certificates") / "openshell-gateway-ca.crt"
    if os.geteuid() == 0:
        shutil.copy2(cert_file, system_file)
        _run("update-ca-certificates")
    else:
        install = _run("sudo", "cp", str(cert_file), str(system_file))
        if install.returncode == 0:
            _run("sudo", "update-ca-certificates")
        else:
            logger.warning(
                "Could not install CA system-wide (sudo failed); relying on SSL_CERT_FILE"
            )

    return ca_pem


def get_oidc_client_config(juju: jubilant.Juju) -> dict[str, str]:
    """Return OIDC client configuration advertised by the gateway charm."""
    result = juju.run(f"{APP_NAME}/0", "get-oidc-client-config")
    assert result.status == "completed", result
    return dict(result.results)


def create_hydra_m2m_client(juju: jubilant.Juju, *, audience: str) -> tuple[str, str]:
    """Create a Hydra OAuth2 client for the openshell snap M2M flow."""
    result = juju.run(
        f"{HYDRA_APP}/0",
        "create-oauth-client",
        params={
            "name": "openshell-cli-m2m",
            "grant-types": ["client_credentials"],
            "scope": [OIDC_ADMIN_ROLE],
            "audience": [audience],
            "token-endpoint-auth-method": "client_secret_post",
        },
    )
    assert result.status == "completed", result
    client_id = result.results.get("client-id")
    client_secret = result.results.get("client-secret") or result.results.get("secret")
    assert client_id and client_secret, f"missing client credentials: {result.results}"
    return client_id, client_secret


def prepare_openshell_client(juju: jubilant.Juju, gateway_url: str) -> dict[str, str]:
    """Prepare host CA trust and Hydra M2M credentials for the openshell snap.

    Returns a dict with ``gateway_url``, ``issuer_url``, ``client_id``,
    ``client_secret``, and ``audience``.
    """
    trust_self_signed_ca(juju)
    oidc = get_oidc_client_config(juju)
    audience = oidc.get("audience") or OIDC_AUDIENCE
    issuer_url = oidc["issuer"]
    client_id, client_secret = create_hydra_m2m_client(juju, audience=audience)
    return {
        "gateway_url": gateway_url,
        "issuer_url": issuer_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": audience,
    }


def driver_help_output(juju: jubilant.Juju) -> str:
    """Return ``openshell-driver-lxd --help`` output from the workload container.

    ``juju exec`` cannot target a workload container, so the probe goes through
    ``juju ssh --container``. A probe that produces no output at all means the
    driver could not be inspected, which fails the test rather than silently
    closing the capability gate.
    """
    try:
        return juju.ssh(
            f"{APP_NAME}/0",
            "openshell-driver-lxd",
            "--help",
            container=CONTAINER_NAME,
        )
    except jubilant.CLIError as exc:
        # Some CLIs print usage on stderr and exit non-zero; only treat the
        # probe itself as broken when it yielded no output whatsoever.
        output = f"{exc.stdout or ''}{exc.stderr or ''}"
        if not output.strip():
            pytest.fail(
                f"could not probe openshell-driver-lxd in container "
                f"{CONTAINER_NAME!r} of {APP_NAME}/0: {exc}"
            )
        return output


def sandbox_e2e_supported(juju: jubilant.Juju) -> bool:
    """Return True if the deployed driver exposes ``--gateway-endpoint``."""
    return "--gateway-endpoint" in driver_help_output(juju)


@pytest.fixture(scope="module")
def requires_sandbox_e2e(juju: jubilant.Juju) -> None:
    """Skip sandbox end-to-end tests until the upstream driver flag lands."""
    if not sandbox_e2e_supported(juju):
        pytest.skip(
            "openshell-driver-lxd does not expose --gateway-endpoint; skipping sandbox e2e"
        )


def managed_lxd_trust_fingerprints(
    machine_juju: jubilant.Juju,
    app: str = "lxd",
) -> set[str]:
    """Read the trust store of the LXD charm's managed LXD via ``juju exec``."""

    def runner(*args: str) -> Any:
        return machine_juju.exec("lxc", *args, unit=f"{app}/0")

    return lxc_trust_fingerprints(runner)


@pytest.fixture(scope="module")
def host_lxd_endpoint() -> HostLxdEndpoint:
    """Enable HTTPS on the concierge host LXD and mint the integrator's client identity."""
    if shutil.which("lxc") is None:
        pytest.skip("host 'lxc' binary not found; skipping tests that require host LXD")

    prior_address = read_lxd_config("core.https_address")
    try:
        endpoint = setup_host_lxd_endpoint()
    except RuntimeError as exc:
        pytest.skip(str(exc))

    yield endpoint

    teardown_host_lxd_endpoint(endpoint, prior_address)


@pytest.fixture(scope="module")
def _cleanup_host_lxd_gateway_trust(
    juju: jubilant.Juju, host_lxd_endpoint: HostLxdEndpoint
) -> None:
    """Remove the gateway's registered client certificate from the host LXD.

    This fixture is intentionally **not** autouse: only modules that exercise the
    host-LXD provider path request it explicitly. The cross-model offer path in
    ``test_lxd_offer.py`` does not depend on host ``lxc``.
    """
    yield
    try:
        fingerprint = gateway_client_cert_fingerprint(juju)
    except Exception:
        logger.exception("could not determine gateway client cert fingerprint for cleanup")
        return
    host_lxd_endpoint.host_runner("config", "trust", "remove", fingerprint)


def create_lxd_credentials_secret(
    juju: jubilant.Juju,
    host_lxd_endpoint: HostLxdEndpoint,
    app: str = INTEGRATOR_APP,
) -> str:
    """Create and grant a Juju secret carrying the integrator's LXD identity.

    The secret contains ``client-cert`` and ``client-key`` (the integrator's own
    mTLS identity) plus ``server-cert`` (the host LXD's server certificate).
    Granting it to *app* allows the integrator to read the secret once related.
    """
    secret_uri = juju.add_secret(
        "lxd-credentials",
        {
            "client-cert": host_lxd_endpoint.client_cert_pem,
            "client-key": host_lxd_endpoint.client_key_pem,
            "server-cert": host_lxd_endpoint.server_cert_pem,
        },
    )
    juju.grant_secret(secret_uri, app)
    return secret_uri


def deploy_integrator(
    juju: jubilant.Juju,
    host_lxd_endpoint: HostLxdEndpoint,
    app: str = INTEGRATOR_APP,
    charm_file: str | None = None,
) -> str:
    """Deploy ``lxd-integrator-k8s`` against the host LXD and return the secret URI."""
    deploy_args = {"app": app}
    if charm_file is None:
        deploy_args["channel"] = "latest/stable"
    juju.deploy(charm_file or app, **deploy_args)
    secret_uri = create_lxd_credentials_secret(juju, host_lxd_endpoint, app)
    try:
        # The integrator expects ``host:port`` endpoints, not a URL with scheme.
        endpoint_netloc = host_lxd_endpoint.address.removeprefix("https://").removeprefix(
            "http://"
        )
        juju.config(
            app,
            {
                "lxd-credentials": str(secret_uri),
                "lxd-endpoints": endpoint_netloc,
            },
        )
    except Exception:
        try:
            juju.cli("remove-secret", "lxd-credentials")
        except Exception:
            logger.exception("failed to clean up lxd-credentials secret")
        raise
    return secret_uri


def _openshell_gateway_remove(name: str) -> None:
    _run("openshell", "gateway", "remove", name)


def _openshell_sandbox_create(
    name: str, *, source: str | None = None, gateway_name: str | None = None
) -> None:
    """Create an OpenShell sandbox through the configured gateway."""
    args = ["openshell"]
    if gateway_name:
        args.extend(["-g", gateway_name])
    args.extend(["sandbox", "create", "--name", name])
    if source:
        args.extend(["--from", source])
    result = _run(*args)
    output = result.stdout + result.stderr
    print("openshell sandbox create output:\n", output)
    if result.returncode != 0:
        pytest.fail(f"openshell sandbox create failed ({result.returncode}):\n{output}")


def _openshell_sandbox_delete(name: str, *, gateway_name: str | None = None) -> None:
    """Delete an OpenShell sandbox."""
    args = ["openshell"]
    if gateway_name:
        args.extend(["-g", gateway_name])
    args.extend(["sandbox", "delete", name])
    result = _run(*args)
    output = result.stdout + result.stderr
    print("openshell sandbox delete output:\n", output)
    if result.returncode != 0:
        pytest.fail(f"openshell sandbox delete failed ({result.returncode}):\n{output}")


def _unique_marker(sandbox_name: str) -> str:
    """Return a sandbox-specific token that cannot be confused with stale output."""
    return f"{sandbox_name}-{uuid.uuid4().hex[:8]}"


def _openshell_sandbox_exec(name: str, marker: str, *, gateway_name: str | None = None) -> str:
    """Run a non-interactive command in a sandbox and return its stdout."""
    args = ["openshell"]
    if gateway_name:
        args.extend(["-g", gateway_name])
    args.extend(["sandbox", "exec", "-n", name, "--", "echo", marker])
    result = _run(*args)
    output = result.stdout + result.stderr
    print("openshell sandbox exec output:\n", output)
    if result.returncode != 0:
        pytest.fail(f"openshell sandbox exec failed ({result.returncode}):\n{output}")
    if marker not in result.stdout:
        pytest.fail(f"openshell sandbox exec output missing marker ({marker!r}):\n{output}")
    return result.stdout


def _openshell_sandbox_wait_running(
    name: str,
    *,
    timeout: int = 300,
    gateway_name: str | None = None,
) -> None:
    """Poll ``openshell sandbox list`` until the named sandbox reports running."""
    deadline = time.monotonic() + timeout
    while True:
        args = ["openshell"]
        if gateway_name:
            args.extend(["-g", gateway_name])
        args.extend(["sandbox", "list", "-o", "json"])
        result = _run(*args)
        output = result.stdout + result.stderr
        if result.returncode == 0 and _sandbox_is_running(name, result.stdout):
            return
        if time.monotonic() > deadline:
            pytest.fail(f"sandbox {name} did not reach running state within {timeout}s:\n{output}")
        time.sleep(5)


def _run_gated_sandbox_e2e(
    *,
    gateway_url: str,
    issuer_url: str,
    client_id: str,
    client_secret: str,
    audience: str,
    gateway_name: str,
    sandbox_name: str,
) -> None:
    """Add a gateway, launch a sandbox, verify shell access, and clean up.

    This helper is shared by the gated sandbox end-to-end tests in both
    provider-path modules. It removes any pre-existing gateway/sandbox, adds the
    gateway, verifies the CLI reports "Status: Connected", creates the sandbox,
    waits for it to report running, execs a marker command to verify shell
    access, and cleans up in a ``finally`` block.
    """
    _openshell_gateway_remove(gateway_name)
    _openshell_sandbox_delete(sandbox_name)
    _openshell_gateway_add(
        name=gateway_name,
        gateway_url=gateway_url,
        issuer_url=issuer_url,
        client_id=client_id,
        client_secret=client_secret,
        audience=audience,
    )

    status_output = _openshell_status(gateway_name)
    assert "Status: Connected" in status_output, status_output

    try:
        _openshell_sandbox_create(sandbox_name, gateway_name=gateway_name)
        _openshell_sandbox_wait_running(sandbox_name, gateway_name=gateway_name)
        marker = _unique_marker(sandbox_name)
        stdout = _openshell_sandbox_exec(sandbox_name, marker, gateway_name=gateway_name)
        assert marker in stdout, stdout
    finally:
        _openshell_sandbox_delete(sandbox_name, gateway_name=gateway_name)
        _openshell_gateway_remove(gateway_name)


def _sandbox_is_running(name: str, output: str) -> bool:
    """Return True when *output* indicates that the named sandbox is running.

    Prefer parsing the JSON list returned by ``openshell sandbox list``; fall
    back to plain-text matching if JSON parsing fails or the format differs.
    """
    try:
        data = json.loads(output)
    except Exception:
        normalized = output.lower()
        return name in normalized and "running" in normalized

    if isinstance(data, dict):
        entry = data.get(name)
        if isinstance(entry, dict):
            return entry.get("status", "").lower() == "running"
        normalized = output.lower()
        return name in normalized and "running" in normalized

    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and entry.get("name") == name:
                return entry.get("status", "").lower() == "running"

    normalized = output.lower()
    return name in normalized and "running" in normalized


def _openshell_gateway_add(
    *,
    name: str,
    gateway_url: str,
    issuer_url: str,
    client_id: str,
    client_secret: str,
    audience: str,
) -> None:
    env = os.environ.copy()
    env["OPENSHELL_OIDC_CLIENT_SECRET"] = client_secret
    # Do not set SSL_CERT_FILE to a user-home path: the confined openshell snap
    # cannot read arbitrary files there. The self-signed CA is installed into the
    # system trust store by trust_self_signed_ca(), which the snap honours.
    env.pop("SSL_CERT_FILE", None)

    result = _run(
        "openshell",
        "gateway",
        "add",
        gateway_url,
        "--name",
        name,
        "--oidc-issuer",
        issuer_url,
        "--oidc-client-id",
        client_id,
        "--oidc-audience",
        audience,
        "--oidc-scopes",
        OIDC_ADMIN_ROLE,
        env=env,
    )
    output = result.stdout + result.stderr
    print("openshell gateway add output:\n", output)
    if (
        result.returncode != 0
        or "added and set as active" not in output
        or "removed" in output.lower()
    ):
        pytest.fail(
            f"openshell gateway add failed ({result.returncode}):\n{result.stdout}\n{result.stderr}"
        )


def _openshell_status(gateway_name: str | None = None) -> str:
    args = ["openshell"]
    if gateway_name:
        args.extend(["-g", gateway_name])
    args.append("status")
    result = _run(*args)
    if result.returncode != 0:
        output = result.stdout + result.stderr
        pytest.fail(f"openshell status failed ({result.returncode}):\n{output}")
    # Strip ANSI colour codes so callers can do plain string assertions.
    return re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
