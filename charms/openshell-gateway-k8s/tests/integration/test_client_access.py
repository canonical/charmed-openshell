"""Integration tests for OpenShell client access and connectivity.

Validates that the externally installed ``openshell`` snap can authenticate
(OIDC M2M) and connect to the gateway over gRPC through Traefik TLS-passthrough ingress.
"""

from __future__ import annotations

import jubilant
import pytest

from .helpers import (
    OIDC_AUDIENCE,
    create_hydra_m2m_client,
    get_oidc_client_config,
    openshell_gateway_add,
    openshell_gateway_remove,
    openshell_status,
    trust_self_signed_ca,
)

pytestmark = [pytest.mark.integrator]


class TestClientAccess:
    """End-to-end validation of client connectivity to the gateway."""

    def test_openshell_snap_connects(
        self,
        juju: jubilant.Juju,
        gateway_url: str,
        integrator_provider: None,
        openshell_available: None,
    ) -> None:
        """The ``openshell`` snap authenticates and connects to the gateway."""
        trust_self_signed_ca(juju)
        oidc = get_oidc_client_config(juju)
        audience = oidc.get("audience") or OIDC_AUDIENCE
        issuer_url = oidc["issuer"]
        client_id, client_secret = create_hydra_m2m_client(juju, audience=audience)

        gateway_name = "integration-test-gateway-access"
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
