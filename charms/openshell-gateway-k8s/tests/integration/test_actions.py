"""Integration tests for charm operator actions."""

from __future__ import annotations

import jubilant
import pytest

from .helpers import (
    APP_NAME,
    gateway_status,
    wait_for_gateway_stack,
)

pytestmark = [pytest.mark.lxd]


class TestCharmActions:
    """Validate operator actions against an active gateway deployment."""

    def test_restart_action(
        self,
        juju: jubilant.Juju,
        lxd_joined: None,
    ) -> None:
        """The ``restart`` action coordinates a rolling restart of the workload."""
        result = juju.run(f"{APP_NAME}/0", "restart")
        assert result.status == "completed", result
        wait_for_gateway_stack(juju)
        status = gateway_status(juju)
        assert status["workload-running"] == "True", status

    def test_rotate_sandbox_client_identity_action(
        self,
        juju: jubilant.Juju,
        lxd_joined: None,
    ) -> None:
        """The ``rotate-sandbox-client-identity`` action rotates both CA and leaf."""
        result = juju.run(f"{APP_NAME}/0", "rotate-sandbox-client-identity")
        assert result.status == "completed", result
        assert result.results.get("ca-fingerprint"), result.results
        assert result.results.get("certificate-fingerprint"), result.results

        wait_for_gateway_stack(juju)
        status = gateway_status(juju)
        assert status["workload-running"] == "True", status
        assert status["sandbox-client-ca-configured"] == "True", status

    def test_rotate_jwt_signing_key_on_juju_secret_store(
        self,
        juju: jubilant.Juju,
        lxd_joined: None,
    ) -> None:
        """The ``rotate-jwt-signing-key`` action rotates the key in Juju secret store."""
        before = gateway_status(juju)
        assert before.get("jwt-store") == "juju-secret", before

        result = juju.run(f"{APP_NAME}/0", "rotate-jwt-signing-key")
        assert result.status == "completed", result
        assert result.results.get("store") == "juju-secret", result.results
        assert result.results.get("kid") != before.get("jwt-kid"), result.results

        wait_for_gateway_stack(juju)
        after = gateway_status(juju)
        assert after["jwt-kid"] == result.results["kid"], after
        assert after["workload-running"] == "True", after
