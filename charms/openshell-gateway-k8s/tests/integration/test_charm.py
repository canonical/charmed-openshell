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
                test defaults to the upstream source defined in charmcraft.yaml.
  JUJU_MODEL    Deploy into an existing model instead of creating a temporary
                one. The model is *not* destroyed when the test finishes.
"""

from __future__ import annotations

from typing import Any

import jubilant
import pytest

from .conftest import (
    APP_NAME,
    DB_GATEWAY_APP,
    HYDRA_APP,
    INFRA_APPS,
    INTEGRATOR_APP,
    OIDC_AUDIENCE,
    _fail_on_app_error,
    _openshell_gateway_add,
    _openshell_gateway_remove,
    _openshell_status,
    _wait_for_gateway_stack,
    _wait_for_workload_running,
    create_hydra_m2m_client,
    deploy_integrator,
    get_oidc_client_config,
    trust_self_signed_ca,
)


@pytest.fixture(scope="module", autouse=True)
def _lxd_provider(
    juju: jubilant.Juju,
    host_lxd_endpoint: Any,
    integrator_charm_file: str,
    _cleanup_host_lxd_gateway_trust: None,
) -> None:
    """Deploy ``lxd-integrator-k8s`` so the gateway stack can become active."""
    deploy_integrator(juju, host_lxd_endpoint, charm_file=integrator_charm_file)
    juju.wait(lambda s: jubilant.all_active(s, INTEGRATOR_APP), timeout=900)
    juju.integrate(f"{APP_NAME}:lxd", f"{INTEGRATOR_APP}:https")
    _wait_for_gateway_stack(juju)


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

    def test_openshell_snap_connects(
        self, juju: jubilant.Juju, gateway_url: str, openshell_available: None
    ) -> None:
        """The ``openshell`` snap authenticates and connects to the gateway."""
        trust_self_signed_ca(juju)
        oidc = get_oidc_client_config(juju)
        audience = oidc.get("audience") or OIDC_AUDIENCE
        issuer_url = oidc["issuer"]
        client_id, client_secret = create_hydra_m2m_client(juju, audience=audience)

        gateway_name = "integration-test-gateway"
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

    def test_relation_resilience_database(self, juju: jubilant.Juju) -> None:
        """Removing and re-adding the database relation recovers automatically."""
        juju.cli("remove-relation", f"{APP_NAME}:database", f"{DB_GATEWAY_APP}:database")

        def _blocked(status: jubilant.Status) -> bool:
            app = status.apps.get(APP_NAME)
            if app is None:
                return False
            unit = app.units.get(f"{APP_NAME}/0")
            if unit is None:
                return False
            return unit.workload_status.current == "blocked" and "database relation missing" in (
                unit.workload_status.message or ""
            )

        juju.wait(_blocked, timeout=300)
        juju.integrate(f"{APP_NAME}:database", f"{DB_GATEWAY_APP}:database")
        juju.wait(
            lambda s: jubilant.all_active(s, APP_NAME),
            error=_fail_on_app_error(juju, APP_NAME),
            timeout=900,
        )
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
            unit = app.units.get(f"{APP_NAME}/0")
            if unit is None:
                return False
            return unit.workload_status.current == "blocked" and "oauth relation missing" in (
                unit.workload_status.message or ""
            )

        juju.wait(_blocked, timeout=300)
        juju.integrate(f"{APP_NAME}:oauth", f"{HYDRA_APP}:oauth")
        juju.wait(
            lambda s: jubilant.all_active(s, APP_NAME),
            error=_fail_on_app_error(juju, APP_NAME),
            timeout=900,
        )
        _wait_for_workload_running(juju)

        # Confirm the snap is still connected after the relation churn.
        status_output = _openshell_status("integration-test-gateway")
        assert "Status: Connected" in status_output, status_output
