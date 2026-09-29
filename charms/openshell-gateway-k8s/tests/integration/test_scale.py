"""Integration tests for multi-unit scale and rolling operations."""

from __future__ import annotations

import logging

import jubilant
import pytest

from .helpers import (
    APP_NAME,
    fail_on_app_error,
    wait_for_gateway_stack,
    wait_for_workload_running,
)

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.lxd, pytest.mark.scale]


class TestScaleAndRollingOps:
    """Validate multi-unit deployment and rollingops coordination."""

    def test_rolling_restart_across_units(
        self,
        juju: jubilant.Juju,
        lxd_joined: None,
    ) -> None:
        """Adding a unit and triggering a rolling restart coordinates across units."""
        status = juju.status()
        app = status.apps.get(APP_NAME)
        assert app is not None

        logger.info("Scaling %s to 2 units", APP_NAME)
        juju.cli("add-unit", APP_NAME)
        try:
            juju.wait(
                lambda s: (
                    jubilant.all_active(s, APP_NAME)
                    and len(s.apps[APP_NAME].units) == 2
                    and jubilant.all_agents_idle(s, APP_NAME)
                ),
                error=fail_on_app_error(juju, APP_NAME),
                timeout=1200,
            )

            # Initiate rolling restart via action on leader
            logger.info("Triggering rolling restart across units")
            result = juju.run(f"{APP_NAME}/0", "restart")
            assert result.status == "completed", result

            juju.wait(
                lambda s: (
                    jubilant.all_active(s, APP_NAME) and jubilant.all_agents_idle(s, APP_NAME)
                ),
                error=fail_on_app_error(juju, APP_NAME),
                timeout=1200,
            )
            wait_for_workload_running(juju)
        finally:
            logger.info("Scaling %s back to 1 unit", APP_NAME)
            current_status = juju.status()
            current_app = current_status.apps.get(APP_NAME)
            if current_app and len(current_app.units) > 1:
                juju.cli("scale-application", APP_NAME, "1")
                juju.wait(
                    lambda s: (
                        jubilant.all_active(s, APP_NAME)
                        and len(s.apps[APP_NAME].units) == 1
                        and jubilant.all_agents_idle(s, APP_NAME)
                    ),
                    timeout=900,
                )
            wait_for_gateway_stack(juju)
