"""Integration tests for certificate transfer and CA distribution."""

from __future__ import annotations

import contextlib
import logging

import jubilant
import pytest

from .helpers import (
    APP_NAME,
    CONTAINER_NAME,
    gateway_status,
    wait_for_gateway_stack,
    wait_for_workload_running,
)

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.integrator]

EXTRA_CA_APP = "extra-ca-certificates"


class TestCaDistribution:
    """Validate receive-ca-cert relation and system CA bundle preservation."""

    def test_receive_ca_cert_preserves_public_roots(
        self,
        juju: jubilant.Juju,
        integrator_provider: None,
    ) -> None:
        """Adding a CA via receive-ca-cert updates the bundle without dropping roots."""
        logger.info("Deploying %s as extra CA provider", EXTRA_CA_APP)
        juju.deploy("self-signed-certificates", app=EXTRA_CA_APP, channel="1/stable")
        juju.wait(lambda s: jubilant.all_active(s, EXTRA_CA_APP), timeout=900)

        try:
            logger.info("Relating %s:receive-ca-cert to %s:send-ca-cert", APP_NAME, EXTRA_CA_APP)
            juju.integrate(f"{APP_NAME}:receive-ca-cert", f"{EXTRA_CA_APP}:send-ca-cert")
            juju.wait(
                lambda s: (
                    jubilant.all_active(s, APP_NAME, EXTRA_CA_APP)
                    and jubilant.all_agents_idle(s, APP_NAME, EXTRA_CA_APP)
                ),
                timeout=900,
            )
            wait_for_workload_running(juju)

            status = gateway_status(juju)
            assert int(status.get("received-ca-certificates", "0")) >= 1, status

            # Verify pristine bundle was preserved and system bundle updated
            pristine_check = juju.ssh(
                f"{APP_NAME}/0",
                "test",
                "-f",
                "/etc/openshell/tls/system-ca.crt",
                container=CONTAINER_NAME,
            )
            assert pristine_check == ""
        finally:
            logger.info("Cleaning up extra CA relation and app")
            with contextlib.suppress(Exception):
                juju.cli(
                    "remove-relation",
                    f"{APP_NAME}:receive-ca-cert",
                    f"{EXTRA_CA_APP}:send-ca-cert",
                )
            with contextlib.suppress(Exception):
                juju.cli("remove-application", EXTRA_CA_APP, "--force")
            wait_for_gateway_stack(juju)
