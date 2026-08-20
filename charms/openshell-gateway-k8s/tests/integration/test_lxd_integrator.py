"""Integration tests for the gateway's LXD provider via lxd-integrator-k8s.

Approach A: the test enables HTTPS on the concierge host LXD, mints an
integrator client identity, and relates ``lxd-integrator-k8s`` to the gateway in
the same Kubernetes model. It asserts the trust lifecycle on the host LXD.

Sandbox end-to-end assertions are gated by ``requires_sandbox_e2e`` and skip
until the upstream ``--gateway-endpoint`` driver flag lands.
"""

from __future__ import annotations

import logging

import jubilant
import pytest

from .conftest import (
    APP_NAME,
    INTEGRATOR_APP,
    _run_gated_sandbox_e2e,
    _wait_for_gateway_blocked,
    _wait_for_gateway_stack,
    assert_trust_registered,
    assert_trust_withdrawn,
    deploy_integrator,
    lxc_trust_fingerprints,
    prepare_openshell_client,
)
from .lxd_host import HostLxdEndpoint

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.integrator]


@pytest.fixture(scope="module", autouse=True)
def _lxd_integrator_provider(
    juju: jubilant.Juju,
    host_lxd_endpoint: HostLxdEndpoint,
    integrator_charm_file: str,
    _cleanup_host_lxd_gateway_trust: None,
) -> None:
    """Deploy the integrator, relate it to the gateway, and wait for the stack."""
    deploy_integrator(juju, host_lxd_endpoint, charm_file=integrator_charm_file)
    juju.wait(lambda s: jubilant.all_active(s, INTEGRATOR_APP), timeout=900)
    juju.integrate(f"{APP_NAME}:lxd", f"{INTEGRATOR_APP}:https")
    _wait_for_gateway_stack(juju)


def _has_integrator_relation(juju: jubilant.Juju) -> bool:
    """Return True when the gateway is currently related to the integrator."""
    status = juju.status()
    app = status.apps.get(APP_NAME)
    if app is None:
        return False
    return any(relation.related_app == INTEGRATOR_APP for relation in app.relations.get("lxd", []))


class TestLxdIntegratorProvider:
    """Trust lifecycle and sandbox e2e for the lxd-integrator-k8s provider path."""

    def test_integrator_relation_registers_trust(
        self,
        juju: jubilant.Juju,
        host_lxd_endpoint: HostLxdEndpoint,
    ) -> None:
        """Relating the integrator registers the gateway's client cert on the host LXD."""
        if _has_integrator_relation(juju):
            juju.cli("remove-relation", f"{APP_NAME}:lxd", f"{INTEGRATOR_APP}:https")
            _wait_for_gateway_blocked(juju)

        juju.integrate(f"{APP_NAME}:lxd", f"{INTEGRATOR_APP}:https")
        juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=900)

        assert_trust_registered(
            juju,
            lambda: lxc_trust_fingerprints(host_lxd_endpoint.host_runner),
        )

    def test_integrator_unrelate_withdraws_trust(
        self,
        juju: jubilant.Juju,
        host_lxd_endpoint: HostLxdEndpoint,
    ) -> None:
        """Removing the integrator relation withdraws the gateway's client cert."""
        juju.cli("remove-relation", f"{APP_NAME}:lxd", f"{INTEGRATOR_APP}:https")
        _wait_for_gateway_blocked(juju)

        assert_trust_withdrawn(
            juju,
            lambda: lxc_trust_fingerprints(host_lxd_endpoint.host_runner),
        )

    def test_sandbox_ops_via_integrator(
        self,
        juju: jubilant.Juju,
        gateway_url: str,
        host_lxd_endpoint: HostLxdEndpoint,
        requires_sandbox_e2e: None,
        openshell_available: None,
    ) -> None:
        """Gated: the openshell CLI connects to the gateway over the integrator path."""
        if not _has_integrator_relation(juju):
            juju.integrate(f"{APP_NAME}:lxd", f"{INTEGRATOR_APP}:https")
            juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=900)

        creds = prepare_openshell_client(juju, gateway_url)
        _run_gated_sandbox_e2e(
            gateway_url=creds["gateway_url"],
            issuer_url=creds["issuer_url"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            audience=creds["audience"],
            gateway_name="integration-test-gateway-integrator",
            sandbox_name="integration-test-sandbox-integrator",
        )
