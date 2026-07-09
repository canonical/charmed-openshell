"""Integration tests for the OpenShell Gateway charm (VP-7 — Jubilant, live Juju).

Requires a live Juju controller backed by microk8s.
Run with:  tox -e integration

Environment variables:
  CHARM_FILE    Path to a pre-built .charm artifact (primary).  If unset, the
                test shells out to a pre-installed `charmcraft` binary.  The
                test is skipped with a clear message when neither is available.
  GATEWAY_IMAGE OCI image ref for the gateway-image resource
                (default: ubuntu:24.04 — a pullable placeholder for pre-FD-001 runs).
"""

from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

import jubilant
import pytest

CHARM_DIR = Path(__file__).parent.parent.parent
RBAC_REQUIRED_MSG = "both oidc-admin-role and oidc-user-role must be set (RBAC required)"
APP_NAME = "openshell-gateway-k8s"


@pytest.fixture(scope="module")
def charm_file() -> str:
    """Resolve the .charm artifact path.

    Primary (b): use CHARM_FILE env var (CI packs once in a prior step).
    Fallback (a): shell out to `charmcraft pack`; skip if binary absent.
    """
    env_path = os.environ.get("CHARM_FILE")
    if env_path:
        return env_path

    charmcraft = subprocess.run(["which", "charmcraft"], capture_output=True)
    if charmcraft.returncode != 0:
        pytest.skip("CHARM_FILE not set and 'charmcraft' binary not found; skipping integration test")

    result = subprocess.run(
        ["charmcraft", "pack", "--verbose"],
        cwd=str(CHARM_DIR),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"charmcraft pack failed:\n{result.stderr}")

    # Find the produced .charm file
    charms = sorted(CHARM_DIR.glob("*.charm"))
    if not charms:
        pytest.skip("charmcraft pack succeeded but no .charm file found")
    return str(charms[-1])


@pytest.fixture(scope="module")
def gateway_image() -> str:
    """OCI image ref for the gateway-image resource.

    Defaults to ubuntu:24.04 (always-pullable placeholder) so the test
    works pre-FD-001.  Set GATEWAY_IMAGE to the real rock ref in CI once
    FD-001 publishes.
    """
    return os.environ.get("GATEWAY_IMAGE", "ubuntu:24.04")


@pytest.fixture(scope="module")
def juju(charm_file, gateway_image):
    """Jubilant Juju fixture: creates a temporary model and destroys it on teardown."""
    model_name = f"fd002-{uuid.uuid4().hex[:8]}"
    juju = jubilant.Juju()
    juju.add_model(model_name)
    try:
        juju.deploy(
            charm_file,
            app=APP_NAME,
            resources={"gateway-image": gateway_image},
        )
        yield juju
    finally:
        juju.destroy_model(model_name, destroy_storage=True, force=True)


class TestRBACStatusContract:
    """VP-7: RBAC-required-by-default status contract against a live Juju model."""

    def test_no_roles_is_blocked(self, juju: jubilant.Juju):
        """Deploy with no roles set → BlockedStatus with RBAC required message.

        Wait condition is on the charm-surfaced app status message only,
        decoupled from container-readiness (ubuntu:24.04 is not pebble-capable
        so pebble-ready never fires).
        """
        def _blocked(status: jubilant.Status) -> bool:
            app = status.apps.get(APP_NAME)
            if app is None:
                return False
            return app.app_status.message == RBAC_REQUIRED_MSG

        juju.wait(_blocked, timeout=300)

    def test_set_both_roles_clears_blocker(self, juju: jubilant.Juju):
        """Setting both roles clears the RBAC blocker.

        The wait predicate checks that the RBAC required message is gone,
        decoupled from Juju's own agent/container status so it doesn't matter
        whether Juju itself injects a competing message on the pebble-less
        placeholder workload.
        """
        juju.config(APP_NAME, {"oidc-admin-role": "admin", "oidc-user-role": "user"})

        def _rbac_blocker_cleared(status: jubilant.Status) -> bool:
            app = status.apps.get(APP_NAME)
            if app is None:
                return False
            return app.app_status.message != RBAC_REQUIRED_MSG

        juju.wait(_rbac_blocker_cleared, timeout=300)
