"""Integration tests for the OpenShell Gateway charm (Jubilant, live Juju).

Validates the full gateway deployment: PostgreSQL, Hydra, Traefik, self-signed
TLS and the gateway charm are wired together, the workload becomes healthy, and
the externally installed ``openshell`` snap can authenticate (OIDC M2M) and
connect to the gateway over gRPC through Traefik TLS-passthrough ingress.

Run with:  just integration-test-charm

Environment variables:
  CHARM_FILE    Path to a pre-built .charm artifact. If unset, the test shells
                out to a pre-installed ``charmcraft`` binary.
  GATEWAY_IMAGE OCI image ref for the gateway-image resource. If unset, the
                test imports a local gateway rock into the registry snap.
  ROCK_FILE     Path to a pre-built gateway rock. If unset, the test searches
                the repository or builds the rock with ``rockcraft``.
  LOCAL_REGISTRY  Registry endpoint for the rock import (default: localhost:5000).
  JUJU_MODEL    Deploy into an existing model instead of creating a temporary
                one. The model is *not* destroyed when the test finishes.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

import jubilant
import pytest

logger = logging.getLogger(__name__)

CHARM_DIR = Path(__file__).parent.parent.parent
REPO_ROOT = CHARM_DIR.parent.parent
APP_NAME = "openshell-gateway-k8s"
DB_GATEWAY_APP = "postgresql-gateway"
DB_HYDRA_APP = "postgresql-hydra"
HYDRA_APP = "hydra"
LOGIN_UI_APP = "login-ui"
TRAEFIK_APP = "traefik-k8s"
TLS_APP = "self-signed-certificates"

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
        timeout=1800,
    )


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
    """Deploy the gateway charm, wire it up, and return the public gateway URL."""
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

    logger.info("Waiting for gateway to become active")
    juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=1800)

    status = _wait_for_workload_running(juju)
    logger.info("Gateway readiness: %s", status)

    logger.info("Waiting for the full stack to settle")
    juju.wait(
        lambda s: (
            jubilant.all_active(s, *INFRA_APPS, APP_NAME)
            and jubilant.all_agents_idle(s, *INFRA_APPS, APP_NAME)
        ),
        timeout=1800,
    )

    return f"https://{external_hostname}:8443", f"https://{external_hostname}"


@pytest.fixture(scope="module")
def juju(charm_file: str, gateway_image: str) -> jubilant.Juju:
    """Provide a Jubilant Juju handle with a fully deployed gateway stack.

    If ``JUJU_MODEL`` is set the tests run in that existing model and the model
    is left in place. Otherwise a temporary model is created and destroyed.
    """
    existing_model = os.environ.get("JUJU_MODEL")

    def _deploy(juju: jubilant.Juju) -> None:
        _deploy_infrastructure(juju)
        gateway_url, _ = _deploy_gateway(juju, charm_file, gateway_image)
        juju._openshell_gateway_url = gateway_url  # type: ignore[attr-defined]

    if existing_model:
        juju = jubilant.Juju(model=existing_model)
        _deploy(juju)
        yield juju
        return

    with jubilant.temp_model() as juju:
        _deploy(juju)
        yield juju


class TestOpenShellGatewayFunctional:
    """End-to-end validation of the gateway charm and openshell snap."""

    def test_infrastructure_and_gateway_active(self, juju: jubilant.Juju) -> None:
        """All supporting applications and the gateway are active/idle."""
        status = juju.status()
        assert jubilant.all_active(status, *INFRA_APPS, APP_NAME)
        assert jubilant.all_agents_idle(status, *INFRA_APPS, APP_NAME)

    def test_gateway_workload_running(self, juju: jubilant.Juju) -> None:
        """The gateway action reports the pebble service as running."""
        result = juju.run(f"{APP_NAME}/0", "get-gateway-status")
        assert result.status == "completed"
        assert result.results.get("workload-running") == "True"

    def test_openshell_snap_connects(self, juju: jubilant.Juju, openshell_available: None) -> None:
        """The ``openshell`` snap authenticates and connects to the gateway."""
        gateway_url = juju._openshell_gateway_url  # type: ignore[attr-defined]

        self._trust_self_signed_ca(juju)
        oidc = self._get_oidc_client_config(juju)
        audience = oidc.get("audience") or OIDC_AUDIENCE
        issuer_url = oidc["issuer"]
        client_id, client_secret = self._create_hydra_m2m_client(juju, audience=audience)

        gateway_name = "integration-test-gateway"
        _openshell_gateway_remove(gateway_name)
        _openshell_gateway_add(
            name=gateway_name,
            gateway_url=gateway_url,
            issuer_url=issuer_url,
            client_id=client_id,
            client_secret=client_secret,
        )

        status_output = _openshell_status(gateway_name)
        assert "Status: Connected" in status_output, status_output

    def _trust_self_signed_ca(self, juju: jubilant.Juju) -> str:
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

    def _get_oidc_client_config(self, juju: jubilant.Juju) -> dict[str, str]:
        """Return OIDC client configuration advertised by the gateway charm."""
        result = juju.run(f"{APP_NAME}/0", "get-oidc-client-config")
        assert result.status == "completed", result
        return dict(result.results)

    def _create_hydra_m2m_client(self, juju: jubilant.Juju, *, audience: str) -> tuple[str, str]:
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

    def test_relation_resilience_database(self, juju: jubilant.Juju) -> None:
        """Removing and re-adding the database relation recovers automatically."""
        juju.cli("remove-relation", f"{APP_NAME}:database", f"{DB_GATEWAY_APP}:database")

        def _blocked(status: jubilant.Status) -> bool:
            app = status.apps.get(APP_NAME)
            if app is None:
                return False
            return (
                app.app_status.current == "blocked"
                and "database relation missing" in app.app_status.message
            )

        juju.wait(_blocked, timeout=300)
        juju.integrate(f"{APP_NAME}:database", f"{DB_GATEWAY_APP}:database")
        juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=900)
        _wait_for_workload_running(juju)

    def test_relation_resilience_oauth(
        self, juju: jubilant.Juju, openshell_available: None
    ) -> None:
        """Removing and re-adding the oauth relation recovers automatically."""
        juju.cli("remove-relation", f"{APP_NAME}:oauth", f"{HYDRA_APP}:oauth")

        def _blocked(status: jubilant.Status) -> bool:
            app = status.apps.get(APP_NAME)
            if app is None:
                return False
            return (
                app.app_status.current == "blocked"
                and "oauth relation missing" in app.app_status.message
            )

        juju.wait(_blocked, timeout=300)
        juju.integrate(f"{APP_NAME}:oauth", f"{HYDRA_APP}:oauth")
        juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=900)
        _wait_for_workload_running(juju)

        # Confirm the snap is still connected after the relation churn.
        status_output = _openshell_status("integration-test-gateway")
        assert "Status: Connected" in status_output, status_output


def _openshell_gateway_remove(name: str) -> None:
    _run("openshell", "gateway", "remove", name)


def _openshell_gateway_add(
    *,
    name: str,
    gateway_url: str,
    issuer_url: str,
    client_id: str,
    client_secret: str,
) -> None:
    env = os.environ.copy()
    env["OPENSHELL_OIDC_CLIENT_SECRET"] = client_secret
    # Do not set SSL_CERT_FILE to a user-home path: the confined openshell snap
    # cannot read arbitrary files there. The self-signed CA is installed into the
    # system trust store by _trust_self_signed_ca(), which the snap honours.
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
        OIDC_AUDIENCE,
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
    output = result.stdout + result.stderr
    if result.returncode != 0:
        pytest.fail(f"openshell status failed ({result.returncode}):\n{output}")
    # Strip ANSI colour codes so callers can do plain string assertions.
    return re.sub(r"\x1b\[[0-9;]*m", "", output)
