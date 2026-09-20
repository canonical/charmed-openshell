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
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jubilant
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .image_resolver import resolve_gateway_image
from .lxd_host import (
    HostLxdEndpoint,
    ensure_lxd_project,
    read_lxd_config,
    setup_host_lxd_endpoint,
    teardown_host_lxd_endpoint,
)
from .sandbox_state import sandbox_is_running as _sandbox_is_running

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

    The integrator charm lives in its own repository; it is not part of this
    tree. Resolution order:

    1. ``INTEGRATOR_CHARM_FILE`` — a prebuilt artifact. Use this to test against
       an integrator branch that is not merged yet.
    2. ``INTEGRATOR_CHARM_DIR`` — a local checkout to pack.
    3. A shallow clone of ``INTEGRATOR_CHARM_REPO`` (default
       ``canonical/lxd-integrator-k8s``) into the cache directory, then pack.

    Every failure is loud. The integrator is not optional to these tests: a
    skip here would quietly report a green run that never exercised the
    provider path at all.
    """
    env_path = os.environ.get("INTEGRATOR_CHARM_FILE")
    if env_path:
        source = Path(env_path)
        if not source.is_file():
            pytest.fail(f"INTEGRATOR_CHARM_FILE={env_path} does not exist")
        return str(_ensure_juju_readable(source))

    if shutil.which("charmcraft") is None:
        pytest.fail(
            "Cannot obtain the lxd-integrator-k8s charm: 'charmcraft' is not on PATH. "
            "Install charmcraft, or set INTEGRATOR_CHARM_FILE to a prebuilt .charm."
        )

    env_dir = os.environ.get("INTEGRATOR_CHARM_DIR")
    if env_dir:
        integrator_dir = Path(env_dir)
        if not (integrator_dir / "charmcraft.yaml").is_file():
            pytest.fail(f"INTEGRATOR_CHARM_DIR={env_dir} is not a charm source directory")
    else:
        integrator_dir = _clone_integrator()

    result = _run("charmcraft", "pack", cwd=str(integrator_dir))
    if result.returncode != 0:
        pytest.fail(
            f"charmcraft pack failed for lxd-integrator-k8s in {integrator_dir}:\n"
            f"{result.stdout}\n{result.stderr}"
        )
    charms = sorted(integrator_dir.glob("*.charm"))
    if not charms:
        pytest.fail(
            f"charmcraft pack reported success in {integrator_dir} but produced no .charm file"
        )

    return str(_ensure_juju_readable(charms[-1]))


def _clone_integrator() -> Path:
    """Shallow-clone the integrator repository into the cache directory."""
    repo = os.environ.get(
        "INTEGRATOR_CHARM_REPO", "https://github.com/canonical/lxd-integrator-k8s.git"
    )
    branch = os.environ.get("INTEGRATOR_CHARM_REF", "main")
    target = Path.home() / ".cache" / "openshell-gateway-integration" / "lxd-integrator-k8s"

    if (target / "charmcraft.yaml").is_file():
        logger.info("Reusing integrator checkout at %s", target)
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(target, ignore_errors=True)
    logger.info("Cloning %s (%s) into %s", repo, branch, target)
    result = _run("git", "clone", "--depth", "1", "--branch", branch, repo, str(target))
    if result.returncode != 0:
        pytest.fail(
            f"Failed to clone the lxd-integrator-k8s charm from {repo} ({branch}):\n"
            f"{result.stderr}\n"
            "Set INTEGRATOR_CHARM_FILE to a prebuilt .charm or INTEGRATOR_CHARM_DIR to a "
            "local checkout if this host has no access to the repository."
        )
    return target


@pytest.fixture(scope="module")
def gateway_image() -> str:
    """Return the OCI image ref for the gateway workload.

    Precedence:
      1. ``GATEWAY_IMAGE`` env var.
      2. Upstream source in ``charmcraft.yaml``.
      3. Fallback default: ``ghcr.io/canonical/openshell-gateway:latest``.
    """
    return resolve_gateway_image()


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


def kubectl_try(*args: str) -> subprocess.CompletedProcess:
    """Run ``kubectl`` and return the completed process without failing.

    For polling loops, where a command that has not succeeded *yet* must not
    end the test. ``kubectl()`` calls ``pytest.fail``, which raises a
    ``BaseException`` that a plain ``except Exception`` does not catch — a
    retry loop built around it never retries.
    """
    for prefix in (["kubectl"], ["microk8s", "kubectl"]):
        if shutil.which(prefix[0]) is None:
            continue
        return _run(*prefix, *args)
    pytest.fail("no kubectl binary found on PATH")


def kubectl(*args: str, allowed_returncodes: tuple[int, ...] = (0,)) -> str:
    """Run ``kubectl`` (or ``microk8s kubectl``) and return stdout.

    Fails the test rather than returning an empty string: a silent empty
    result here reads as "the assertion passed with nothing in it".

    *allowed_returncodes* widens what counts as success, for commands whose
    exit code carries meaning rather than failure — ``vault status`` exits 2
    when Vault is sealed, which is a state the caller wants to read, not an
    error.
    """
    for prefix in (["kubectl"], ["microk8s", "kubectl"]):
        if shutil.which(prefix[0]) is None:
            continue
        result = _run(*prefix, *args)
        if result.returncode in allowed_returncodes:
            return result.stdout
        pytest.fail(
            f"kubectl {' '.join(args)} failed ({result.returncode}):\n"
            f"{result.stdout}\n{result.stderr}"
        )
    pytest.fail("no kubectl binary found on PATH")


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
    """Return True if the deployed driver exposes ``--gateway-endpoint`` and e2e is enabled."""
    if not os.environ.get("OPENSHELL_ENABLE_SANDBOX_E2E"):
        return False
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
    project: str | None = None,
) -> str:
    """Deploy ``lxd-integrator-k8s`` against the host LXD and return the secret URI.

    *project* names the LXD project requirers are to operate in. Left None the
    integrator publishes none and requirers fall back to LXD's ``default``
    project, which is the other half of the placement matrix this suite covers.
    """
    deploy_args = {"app": app}
    if charm_file is None:
        deploy_args["channel"] = "latest/edge"
    juju.deploy(charm_file or app, **deploy_args)
    secret_uri = create_lxd_credentials_secret(juju, host_lxd_endpoint, app)
    try:
        # The integrator expects ``host:port`` endpoints, not a URL with scheme.
        endpoint_netloc = host_lxd_endpoint.address.removeprefix("https://").removeprefix(
            "http://"
        )
        config: dict[str, Any] = {
            "lxd-credentials": str(secret_uri),
            "lxd-endpoints": endpoint_netloc,
        }
        if project is not None:
            config["project"] = project
        juju.config(app, config)
    except Exception:
        try:
            juju.cli("remove-secret", "lxd-credentials")
        except Exception:
            logger.exception("failed to clean up lxd-credentials secret")
        raise
    return secret_uri


def _has_integrator_relation(juju: jubilant.Juju) -> bool:
    """Return True when the gateway is currently related to the integrator."""
    status = juju.status()
    app = status.apps.get(APP_NAME)
    if app is None:
        return False
    return any(relation.related_app == INTEGRATOR_APP for relation in app.relations.get("lxd", []))


def ensure_integrator_relation(juju: jubilant.Juju, timeout: int = 900) -> None:
    """Guarantee an established ``lxd`` relation between gateway and integrator.

    A no-op when the relation already exists. The trust-lifecycle tests
    deliberately leave the relation removed and the gateway blocked, so any
    test that needs an active stack declares that requirement through this
    helper instead of assuming the module left the relation in place.
    """
    if _has_integrator_relation(juju):
        return
    juju.integrate(f"{APP_NAME}:lxd", f"{INTEGRATOR_APP}:https")
    juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=timeout)


# The LXD project the custom-project half of the placement matrix uses. The
# driver reads placement from the project's ``default`` profile and never
# creates the project itself, so the ``it_project`` fixture provisions it on
# the host LXD before any test configures the integrator with it.
IT_PROJECT = os.environ.get("OPENSHELL_TEST_LXD_PROJECT", "openshell-it")


@pytest.fixture(scope="class")
def it_project(host_lxd_endpoint: HostLxdEndpoint) -> str:
    """Guarantee the custom LXD project exists on the host LXD, driver-ready.

    The project, its ``default`` profile devices, and the sandbox image alias
    are provisioned idempotently by :func:`ensure_lxd_project`. The project is
    left in place afterwards: the gateway's driver keeps running in it for the
    rest of the module, and a fresh run re-creates whatever it finds missing.
    """
    ensure_lxd_project(host_lxd_endpoint.host_runner, IT_PROJECT)
    return IT_PROJECT


def gateway_status(juju: jubilant.Juju) -> dict[str, str]:
    """Return the results of the gateway's ``get-gateway-status`` action."""
    result = juju.run(f"{APP_NAME}/0", "get-gateway-status")
    if result.status != "completed":
        pytest.fail(f"get-gateway-status did not complete: {result.status}")
    return dict(result.results)


def wait_for_lxd_project(juju: jubilant.Juju, expected: str, timeout: int = 300) -> dict[str, str]:
    """Wait until the gateway reports *expected* as its LXD project.

    An empty string means the provider named no project, so the driver uses
    LXD's own default. Config changes reach the gateway through the provider's
    databag, so this polls rather than assuming the next hook has already run.

    A blocked gateway unit fails the wait immediately with its blocked
    message: a blocked gateway cannot converge onto any project, and polling
    toward the timeout buries the diagnosis. An *active* gateway with no
    project published still reports ``lxd-project=''`` and the wait succeeds.
    """
    deadline = time.monotonic() + timeout
    last: dict[str, str] = {}
    while True:
        last = gateway_status(juju)
        app = juju.status().apps.get(APP_NAME)
        if app is not None and app.app_status.current == "blocked":
            pytest.fail(
                f"gateway blocked while waiting for lxd-project={expected!r}: "
                f"{app.app_status.message}"
            )
        if last.get("lxd-project", "") == expected:
            return last
        if time.monotonic() > deadline:
            pytest.fail(
                f"gateway still reports lxd-project={last.get('lxd-project')!r} "
                f"after {timeout}s, expected {expected!r}"
            )
        time.sleep(5)


def lxc_trust_entry(runner: Callable[..., Any], fingerprint: str) -> dict[str, Any]:
    """Return the LXD trust-store entry for *fingerprint*, or an empty dict.

    Read from LXD rather than from the integrator's action, because the point
    of the restriction is what LXD enforces, not what the charm believes.
    """
    result = runner("config", "trust", "list", "--format=json")
    if result.returncode != 0:
        pytest.fail(f"could not list the LXD trust store: {result.stderr}")
    for entry in json.loads(result.stdout or "[]"):
        if entry.get("fingerprint", "").lower() == fingerprint.lower():
            return entry
    return {}


def lxc_instance_projects(runner: Callable[..., Any], name_prefix: str) -> dict[str, str]:
    """Return ``{instance name: project}`` for instances whose name starts with *name_prefix*.

    Every project is searched, so a sandbox that landed in the wrong one is
    visible rather than merely absent from the one that was expected.
    """
    result = runner("project", "list", "--format=json")
    if result.returncode != 0:
        pytest.fail(f"could not list LXD projects: {result.stderr}")
    projects = [entry["name"] for entry in json.loads(result.stdout or "[]")]

    found: dict[str, str] = {}
    for project in projects:
        listed = runner("list", "--project", project, "--format=json")
        if listed.returncode != 0:
            continue
        for instance in json.loads(listed.stdout or "[]"):
            name = instance.get("name", "")
            if name.startswith(name_prefix):
                found[name] = project
    return found


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


def _openshell_sandbox_delete(
    name: str, *, gateway_name: str | None = None, check: bool = True
) -> None:
    """Delete an OpenShell sandbox."""
    args = ["openshell"]
    if gateway_name:
        args.extend(["-g", gateway_name])
    args.extend(["sandbox", "delete", name])
    result = _run(*args)
    output = result.stdout + result.stderr
    print("openshell sandbox delete output:\n", output)
    if check and result.returncode != 0:
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
    while_running: Callable[[], None] | None = None,
) -> None:
    """Add a gateway, launch a sandbox, verify shell access, and clean up.

    This helper is shared by the gated sandbox end-to-end tests in both
    provider-path modules. It removes any pre-existing gateway/sandbox, adds the
    gateway, verifies the CLI reports "Status: Connected", creates the sandbox,
    waits for it to report running, execs a marker command to verify shell
    access, and cleans up in a ``finally`` block.

    *while_running* is called once the sandbox reports running and before it is
    torn down, for assertions that need to observe the live instance.
    """
    _openshell_gateway_remove(gateway_name)
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
        if while_running is not None:
            while_running()
        marker = _unique_marker(sandbox_name)
        stdout = _openshell_sandbox_exec(sandbox_name, marker, gateway_name=gateway_name)
        assert marker in stdout, stdout
    finally:
        _openshell_sandbox_delete(sandbox_name, gateway_name=gateway_name, check=False)
        _openshell_gateway_remove(gateway_name)


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
