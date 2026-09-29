"""Integration tests for mandatory relation resilience."""

from __future__ import annotations

import jubilant
import pytest

from .helpers import (
    APP_NAME,
    DB_GATEWAY_APP,
    HYDRA_APP,
    OIDC_AUDIENCE,
    create_hydra_m2m_client,
    fail_on_app_error,
    get_oidc_client_config,
    openshell_gateway_add,
    openshell_gateway_remove,
    openshell_status,
    trust_self_signed_ca,
    wait_for_workload_running,
)

pytestmark = [pytest.mark.lxd]


class TestRelationResilience:
    """Validate automatic recovery when mandatory relations are removed and restored."""

    def test_relation_resilience_database(
        self,
        juju: jubilant.Juju,
        lxd_joined: None,
    ) -> None:
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
            error=fail_on_app_error(juju, APP_NAME),
            timeout=900,
        )
        wait_for_workload_running(juju)

    def test_relation_resilience_oauth(
        self,
        juju: jubilant.Juju,
        gateway_url: str,
        lxd_joined: None,
        openshell_available: None,
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
            error=fail_on_app_error(juju, APP_NAME),
            timeout=900,
        )
        wait_for_workload_running(juju)

        trust_self_signed_ca(juju)
        oidc = get_oidc_client_config(juju)
        audience = oidc.get("audience") or OIDC_AUDIENCE
        issuer_url = oidc["issuer"]
        client_id, client_secret = create_hydra_m2m_client(juju, audience=audience)

        gateway_name = "integration-test-gateway-oauth"
        openshell_gateway_remove(gateway_name)
        try:
            openshell_gateway_add(
                name=gateway_name,
                gateway_url=gateway_url,
                issuer_url=issuer_url,
                client_id=client_id,
                client_secret=client_secret,
                audience=audience,
            )
            status_output = openshell_status(gateway_name)
            assert "Status: Connected" in status_output, status_output
        finally:
            openshell_gateway_remove(gateway_name)
