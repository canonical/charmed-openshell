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
    IT_GROUP,
    IT_IDENTITY,
    IT_PROJECT,
    K8S_CONTROLLER,
    REPO_ROOT,
    get_traefik_lb_address,
    join_gateway_to_lxd,
    kubectl_try,
    remove_join_secret,
    resolve_charm_file,
    sandbox_e2e_supported,
    wait_for_gateway_stack,
)
from .helpers.stack import deploy_gateway, deploy_infrastructure
from .image_resolver import resolve_gateway_image
from .lxd_host import (
    HostLxdEndpoint,
    delete_group,
    delete_identity,
    ensure_join_group,
    ensure_lxd_project,
    external_lxd_address,
    read_lxd_config,
    setup_host_lxd_endpoint,
    teardown_host_lxd_endpoint,
)

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def charm_file() -> str:
    """Resolve a .charm artifact that the confined ``juju`` snap can read."""
    return resolve_charm_file()


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
    """Enable HTTPS on the concierge host LXD (or use the external one) for the gateway."""
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

    teardown_host_lxd_endpoint(prior_address)


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
def lxd_joined(
    juju: jubilant.Juju,
    host_lxd_endpoint: HostLxdEndpoint,
) -> Generator[None, None, None]:
    """Join the gateway to the host LXD with a project-scoped identity and wait for the stack.

    The identity sits in a group granted ``operator`` on IT_PROJECT only, so
    every sandbox lands there: the gateway cannot see any other project.
    """
    runner = host_lxd_endpoint.host_runner
    ensure_lxd_project(runner, IT_PROJECT)
    ensure_join_group(runner, IT_GROUP, IT_PROJECT)
    join_gateway_to_lxd(juju, runner)
    wait_for_gateway_stack(juju)

    yield

    delete_identity(runner, IT_IDENTITY)
    delete_group(runner, IT_GROUP)
    try:
        juju.config(APP_NAME, reset=["lxd-join-secret"])
        remove_join_secret(juju)
    except Exception:
        logger.exception("could not remove the lxd-join secret")


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
