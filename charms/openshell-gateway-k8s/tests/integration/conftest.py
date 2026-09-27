"""Shared fixtures and configuration for OpenShell Gateway integration tests."""

from __future__ import annotations

import logging
import os
import shutil
from collections.abc import Generator
from pathlib import Path
from typing import Any

import jubilant
import pytest

from .helpers import (
    APP_NAME,
    INTEGRATOR_APP,
    IT_PROJECT,
    K8S_CONTROLLER,
    REPO_ROOT,
    clone_integrator,
    ensure_juju_readable,
    fail_on_app_error,
    gateway_client_cert_fingerprint,
    get_traefik_lb_address,
    is_transient_container_error,
    kubectl_try,
    openshell_gateway_add,
    openshell_gateway_remove,
    openshell_sandbox_create,
    openshell_sandbox_delete,
    openshell_sandbox_exec,
    openshell_sandbox_wait_running,
    openshell_status,
    resolve_charm_file,
    resolve_integrator_charm_file,
    run_cmd,
    run_gated_sandbox_e2e,
    sandbox_e2e_supported,
    unique_marker,
    wait_for_gateway_blocked,
    wait_for_gateway_stack,
    wait_for_workload_running,
)
from .helpers.stack import (
    deploy_gateway,
    deploy_infrastructure,
    deploy_integrator,
    ensure_integrator_relation,
    has_integrator_relation,
)
from .image_resolver import resolve_gateway_image
from .lxd_host import (
    HostLxdEndpoint,
    ensure_lxd_project,
    external_lxd_address,
    read_lxd_config,
    setup_host_lxd_endpoint,
    teardown_host_lxd_endpoint,
)

logger = logging.getLogger(__name__)

# Backward-compatible alias exports for underscore-prefixed legacy names
_run = run_cmd
_ensure_juju_readable = ensure_juju_readable
_clone_integrator = clone_integrator
_deploy_infrastructure = deploy_infrastructure
_is_transient_container_error = is_transient_container_error
_fail_on_app_error = fail_on_app_error
_get_traefik_lb_address = get_traefik_lb_address
_wait_for_gateway_blocked = wait_for_gateway_blocked
_wait_for_workload_running = wait_for_workload_running
_deploy_gateway = deploy_gateway
_wait_for_gateway_stack = wait_for_gateway_stack
_has_integrator_relation = has_integrator_relation
_openshell_gateway_remove = openshell_gateway_remove
_openshell_sandbox_create = openshell_sandbox_create
_openshell_sandbox_delete = openshell_sandbox_delete
_unique_marker = unique_marker
_openshell_sandbox_exec = openshell_sandbox_exec
_openshell_sandbox_wait_running = openshell_sandbox_wait_running
_run_gated_sandbox_e2e = run_gated_sandbox_e2e
_openshell_gateway_add = openshell_gateway_add
_openshell_status = openshell_status


@pytest.fixture(scope="session")
def charm_file() -> str:
    """Resolve a .charm artifact that the confined ``juju`` snap can read."""
    return resolve_charm_file()


@pytest.fixture(scope="session")
def integrator_charm_file() -> str:
    """Resolve a ``lxd-integrator-k8s`` .charm artifact the ``juju`` snap can read."""
    return resolve_integrator_charm_file()


@pytest.fixture(scope="session")
def gateway_image() -> str:
    """Return the OCI image ref for the gateway workload."""
    return resolve_gateway_image()


@pytest.fixture(scope="session")
def openshell_available() -> None:
    """Skip tests that require the externally installed ``openshell`` snap."""
    if shutil.which("openshell") is None:
        pytest.skip("openshell snap not found on PATH; skipping CLI connectivity tests")


@pytest.fixture(scope="session")
def host_lxd_endpoint() -> Generator[HostLxdEndpoint, None, None]:
    """Enable HTTPS on the concierge host LXD and mint the integrator's client identity."""
    if shutil.which("lxc") is None:
        pytest.skip("host 'lxc' binary not found; skipping tests that require host LXD")

    prior_address = read_lxd_config("core.https_address")
    endpoint: HostLxdEndpoint | None = None
    try:
        endpoint = setup_host_lxd_endpoint()
    except RuntimeError as exc:
        # An LXD named in the environment is one the run was set up to use,
        # so failing to reach it is an error, not a reason to skip every
        # test that depends on it.
        if external_lxd_address() is not None:
            raise
        pytest.skip(str(exc))

    assert endpoint is not None
    yield endpoint

    teardown_host_lxd_endpoint(endpoint, prior_address)


@pytest.fixture(scope="session")
def _cleanup_host_lxd_gateway_trust(
    juju: jubilant.Juju, host_lxd_endpoint: HostLxdEndpoint
) -> Generator[None, None, None]:
    """Remove the gateway's registered client certificate from the host LXD at session end."""
    yield
    try:
        fingerprint = gateway_client_cert_fingerprint(juju)
    except Exception:
        logger.exception("could not determine gateway client cert fingerprint for cleanup")
        return
    host_lxd_endpoint.host_runner("config", "trust", "remove", fingerprint)


@pytest.fixture(scope="session")
def juju(charm_file: str, gateway_image: str) -> Generator[jubilant.Juju, None, None]:
    """Provide a Jubilant Juju handle with the gateway stack deployed."""
    existing_model = os.environ.get("JUJU_MODEL")

    def _deploy(handle: jubilant.Juju) -> None:
        deploy_infrastructure(handle)
        deploy_gateway(handle, charm_file, gateway_image)

    if existing_model:
        handle = jubilant.Juju(model=existing_model)
        _deploy(handle)
        yield handle
        return

    with jubilant.temp_model(controller=K8S_CONTROLLER) as handle:
        _deploy(handle)
        yield handle


@pytest.fixture(scope="session")
def gateway_url(juju: jubilant.Juju) -> str:
    """Return the public gateway URL discovered from Traefik LoadBalancer."""
    lb_address = get_traefik_lb_address(juju)
    return f"https://{lb_address}:8443"


@pytest.fixture(scope="function")
def requires_sandbox_e2e(juju: jubilant.Juju) -> None:
    """Skip sandbox end-to-end tests when not supported by driver or opted out."""
    if not sandbox_e2e_supported(juju):
        pytest.skip("sandbox e2e is disabled or driver does not expose --gateway-endpoint")


@pytest.fixture(scope="session")
def integrator_provider(
    juju: jubilant.Juju,
    host_lxd_endpoint: HostLxdEndpoint,
    integrator_charm_file: str,
    _cleanup_host_lxd_gateway_trust: None,
) -> None:
    """Deploy ``lxd-integrator-k8s``, relate it to the gateway, and wait for stack."""
    deploy_integrator(juju, host_lxd_endpoint, charm_file=integrator_charm_file)
    juju.wait(lambda s: jubilant.all_active(s, INTEGRATOR_APP), timeout=900)
    juju.integrate(f"{APP_NAME}:lxd", f"{INTEGRATOR_APP}:https")
    wait_for_gateway_stack(juju)


@pytest.fixture(scope="class")
def it_project(host_lxd_endpoint: HostLxdEndpoint) -> str:
    """Guarantee the custom LXD project exists on the host LXD, driver-ready."""
    ensure_lxd_project(host_lxd_endpoint.host_runner, IT_PROJECT)
    return IT_PROJECT


@pytest.fixture
def restore_gateway_state(juju: jubilant.Juju) -> Generator[None, None, None]:
    """Teardown fixture to ensure the gateway stack is active and restored after test."""
    yield
    ensure_integrator_relation(juju)
    wait_for_gateway_stack(juju)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: Any) -> Generator[None, Any, None]:
    """Capture Juju and Kubernetes failure diagnostics on test failure."""
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed:
        juju_fixture: jubilant.Juju | None = item.funcargs.get("juju")  # type: ignore
        artifacts_dir = Path(REPO_ROOT) / "artifacts" / "diagnostics" / item.name
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        if juju_fixture is not None:
            try:
                status_yaml = juju_fixture.cli("status", "--format=yaml")
                (artifacts_dir / "juju-status.yaml").write_text(status_yaml)
            except Exception:
                logger.exception("Failed to capture juju status")
            try:
                debug_log = juju_fixture.cli("debug-log", "--replay", "--no-tail")
                (artifacts_dir / "juju-debug-log.txt").write_text(debug_log)
            except Exception:
                logger.exception("Failed to capture juju debug-log")
        try:
            cmd = ["-A", "describe", "pods"]
            if juju_fixture is not None and juju_fixture.model:
                model_name = juju_fixture.model.split(":")[-1]
                cmd = ["-n", model_name, "describe", "pods"]
            pod_desc = kubectl_try(*cmd)
            if pod_desc.stdout:
                (artifacts_dir / "kubectl-describe-pods.txt").write_text(pod_desc.stdout)
        except Exception:
            logger.exception("Failed to capture kubectl describe pods")
