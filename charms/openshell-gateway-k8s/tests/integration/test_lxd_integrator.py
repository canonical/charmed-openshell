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
    IT_PROJECT,
    _has_integrator_relation,
    _run_gated_sandbox_e2e,
    _wait_for_gateway_blocked,
    _wait_for_gateway_stack,
    assert_trust_registered,
    assert_trust_withdrawn,
    deploy_integrator,
    ensure_integrator_relation,
    gateway_client_cert_fingerprint,
    lxc_instance_projects,
    lxc_trust_entry,
    lxc_trust_fingerprints,
    prepare_openshell_client,
    wait_for_lxd_project,
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
        ensure_integrator_relation(juju)

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


class TestLxdProjectPlacement:
    """The LXD project comes from the integrator, not from gateway config.

    Both halves of the matrix are covered: the integrator naming no project, so
    the driver falls back to LXD's ``default``, and the integrator naming an
    isolated project, which is what a production deployment does.
    """

    @pytest.fixture(autouse=True)
    def _ensure_provider_related(self, juju: jubilant.Juju) -> None:
        """Guarantee a related integrator and a running stack before each test.

        The trust-lifecycle class before this one ends with the ``lxd``
        relation removed and the gateway blocked, and in CI nothing between
        the two classes re-establishes the relation. Each test here declares
        the state it needs instead of inheriting whatever ran before it; on an
        already-converged stack the fixture is a fast no-op.
        """
        ensure_integrator_relation(juju)
        _wait_for_gateway_stack(juju)

    def test_default_project_when_the_integrator_names_none(
        self,
        juju: jubilant.Juju,
    ) -> None:
        """With no project configured the gateway reports none and stays active."""
        juju.config(INTEGRATOR_APP, reset="project")
        status = wait_for_lxd_project(juju, "")
        assert status["workload-running"] == "True", status
        assert status["readiness-gaps"] == "none", status

    def test_project_from_the_integrator_reaches_the_gateway(
        self,
        juju: jubilant.Juju,
        host_lxd_endpoint: HostLxdEndpoint,
        it_project: str,
    ) -> None:
        """Configuring the integrator's project moves the gateway's driver into it."""
        juju.config(INTEGRATOR_APP, {"project": IT_PROJECT})
        status = wait_for_lxd_project(juju, IT_PROJECT)
        assert status["workload-running"] == "True", status
        assert status["readiness-gaps"] == "none", status

        # LXD restricts the gateway's trust entry to the same project, so the
        # isolation does not depend on the gateway behaving itself. Asserted
        # against LXD, because what LXD enforces is the thing that matters.
        fingerprint = gateway_client_cert_fingerprint(juju)
        entry = lxc_trust_entry(host_lxd_endpoint.host_runner, fingerprint)
        assert entry, f"the gateway's certificate {fingerprint} is not in the trust store"
        assert entry.get("restricted") is True, entry
        assert entry.get("projects") == [IT_PROJECT], entry

        # The integrator reports the same thing, so an operator can see it
        # without reaching for the LXD CLI.
        result = juju.run(f"{INTEGRATOR_APP}/0", "list-trusted-clients")
        assert result.status == "completed", result.status
        assert IT_PROJECT in str(result.results), result.results

    def test_sandbox_lands_in_the_project_the_integrator_named(
        self,
        juju: jubilant.Juju,
        gateway_url: str,
        host_lxd_endpoint: HostLxdEndpoint,
        requires_sandbox_e2e: None,
        openshell_available: None,
        it_project: str,
    ) -> None:
        """Gated: a sandbox created through the gateway appears in IT_PROJECT."""
        juju.config(INTEGRATOR_APP, {"project": IT_PROJECT})
        wait_for_lxd_project(juju, IT_PROJECT)

        creds = prepare_openshell_client(juju, gateway_url)
        sandbox_name = "integration-test-sandbox-project"
        observed: dict[str, str] = {}

        def _capture() -> None:
            observed.update(lxc_instance_projects(host_lxd_endpoint.host_runner, sandbox_name))

        _run_gated_sandbox_e2e(
            gateway_url=creds["gateway_url"],
            issuer_url=creds["issuer_url"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            audience=creds["audience"],
            gateway_name="integration-test-gateway-project",
            sandbox_name=sandbox_name,
            while_running=_capture,
        )

        assert observed, (
            f"no LXD instance named {sandbox_name}* was found in any project while "
            "the sandbox was running"
        )
        assert set(observed.values()) == {IT_PROJECT}, observed
