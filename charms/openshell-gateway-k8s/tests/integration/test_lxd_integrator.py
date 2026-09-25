"""Integration tests for the gateway's LXD provider via lxd-integrator-k8s.

Approach A: the test enables HTTPS on the concierge host LXD, mints an
integrator client identity, and relates ``lxd-integrator-k8s`` to the gateway in
the same Kubernetes model. It asserts the trust lifecycle on the host LXD.

Sandbox end-to-end assertions are gated by ``requires_sandbox_e2e`` and skip
until the upstream ``--gateway-endpoint`` driver flag lands.
"""

from __future__ import annotations

import logging
from collections.abc import Generator

import jubilant
import pytest

from .helpers import (
    APP_NAME,
    INTEGRATOR_APP,
    IT_PROJECT,
    assert_trust_registered,
    assert_trust_withdrawn,
    gateway_client_cert_fingerprint,
    lxc_instance_projects,
    lxc_trust_entry,
    lxc_trust_fingerprints,
    prepare_openshell_client,
    run_gated_sandbox_e2e,
    wait_for_gateway_blocked,
    wait_for_gateway_stack,
    wait_for_lxd_project,
)
from .helpers.stack import ensure_integrator_relation, has_integrator_relation
from .lxd_host import HostLxdEndpoint

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.integrator]


@pytest.fixture(scope="module", autouse=True)
def _lxd_integrator_provider(
    juju: jubilant.Juju,
    integrator_provider: None,
) -> Generator[None, None, None]:
    """Ensure the integrator is deployed and related, and restore state at module end."""
    yield
    ensure_integrator_relation(juju)
    juju.config(INTEGRATOR_APP, reset="project")
    wait_for_gateway_stack(juju)


class TestLxdIntegratorProvider:
    """Trust lifecycle and sandbox e2e for the lxd-integrator-k8s provider path."""

    def test_integrator_relation_registers_trust(
        self,
        juju: jubilant.Juju,
        host_lxd_endpoint: HostLxdEndpoint,
    ) -> None:
        """Relating the integrator registers the gateway's client cert on the host LXD."""
        if has_integrator_relation(juju):
            juju.cli("remove-relation", f"{APP_NAME}:lxd", f"{INTEGRATOR_APP}:https")
            wait_for_gateway_blocked(juju)

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
        wait_for_gateway_blocked(juju)

        assert_trust_withdrawn(
            juju,
            lambda: lxc_trust_fingerprints(host_lxd_endpoint.host_runner),
        )

    @pytest.mark.skip(
        reason="Sandboxes require OVN, so disabled until workflows deploy MicroCloud"
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
        run_gated_sandbox_e2e(
            gateway_url=creds["gateway_url"],
            issuer_url=creds["issuer_url"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            audience=creds["audience"],
            gateway_name="integration-test-gateway-integrator",
            sandbox_name="it-sbx-integ",
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
        wait_for_gateway_stack(juju)

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

    @pytest.mark.skip(
        reason="Sandboxes require OVN, so disabled until workflows deploy MicroCloud"
    )
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
        sandbox_name = "it-sbx-proj"
        observed: dict[str, str] = {}

        def _capture() -> None:
            observed.update(lxc_instance_projects(host_lxd_endpoint.host_runner, sandbox_name))

        run_gated_sandbox_e2e(
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
