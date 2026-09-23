"""Juju status polling, error handling, and convergence helpers."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import NoReturn

import jubilant
import pytest

from .constants import APP_NAME, INFRA_APPS

logger = logging.getLogger(__name__)

_TRANSIENT_CONTAINER_PATTERNS = (
    "crash loop backoff",
    "restarting failed container",
    "crashloopbackoff",
)


def is_transient_container_error(message: str) -> bool:
    """Return True for Kubernetes container restart backoff messages."""
    lowered = message.lower()
    return any(pattern in lowered for pattern in _TRANSIENT_CONTAINER_PATTERNS)


def fail_on_app_error(
    juju: jubilant.Juju,
    *app_names: str,
    hook_retry_limit: int = 0,
    transient_grace_seconds: float = 120.0,
) -> Callable[[jubilant.Status], bool]:
    """Retry hook failures up to a limit, then fail with Juju logs."""
    hook_retries: dict[str, int] = {}
    retry_grace_deadlines: dict[str, float] = {}
    transient_grace_deadlines: dict[str, float] = {}

    def _capture_and_fail(app_name: str, message: str) -> NoReturn:
        try:
            log_output = juju.debug_log(limit=500)
        except (jubilant.CLIError, jubilant.TaskError):
            logger.exception("Failed to capture Juju debug logs")
        else:
            logger.error("Juju debug-log after %s entered error:\n%s", app_name, log_output)
        pytest.fail(f"{app_name} entered error: {message}")

    def _error(status: jubilant.Status) -> bool:
        for app_name in app_names:
            app = status.apps.get(app_name)
            if app is None or app.app_status.current != "error":
                transient_grace_deadlines.pop(app_name, None)
                continue
            message = app.app_status.message or ""
            if message.startswith("hook failed:"):
                for unit_name, unit in app.units.items():
                    if unit.workload_status.current != "error":
                        continue
                    retries = hook_retries.get(unit_name, 0)
                    if retries < hook_retry_limit:
                        logger.warning(
                            "%s entered error; retrying failed hook (%d/%d)",
                            unit_name,
                            retries + 1,
                            hook_retry_limit,
                        )
                        juju.cli("resolved", unit_name)
                        hook_retries[unit_name] = retries + 1
                        retry_grace_deadlines[unit_name] = time.monotonic() + 30
                        return False
                    if time.monotonic() < retry_grace_deadlines.get(unit_name, 0):
                        return False
                _capture_and_fail(app_name, message)
            if is_transient_container_error(message):
                deadline = transient_grace_deadlines.get(app_name)
                if deadline is None:
                    transient_grace_deadlines[app_name] = (
                        time.monotonic() + transient_grace_seconds
                    )
                    logger.warning(
                        "%s reports a transient container restart; waiting up to "
                        "%.0fs for it to clear: %s",
                        app_name,
                        transient_grace_seconds,
                        message,
                    )
                    return False
                if time.monotonic() < deadline:
                    return False
                _capture_and_fail(
                    app_name,
                    f"transient container restart did not clear within "
                    f"{transient_grace_seconds:.0f}s: {message}",
                )
            _capture_and_fail(app_name, message)
        return False

    return _error


def wait_for_gateway_blocked(
    juju: jubilant.Juju,
    message: str = "lxd relation missing",
    timeout: int = 300,
) -> None:
    """Wait until the gateway reports a blocked status containing *message*."""

    def _blocked(status: jubilant.Status) -> bool:
        app = status.apps.get(APP_NAME)
        if app is None:
            return False
        return app.app_status.current == "blocked" and message in (app.app_status.message or "")

    juju.wait(_blocked, timeout=timeout)


def wait_for_workload_running(juju: jubilant.Juju, timeout: int = 900) -> dict[str, str]:
    """Wait until the gateway action reports workload-running=True."""
    deadline = time.monotonic() + timeout
    while True:
        result = juju.run(f"{APP_NAME}/0", "get-gateway-status")
        if result.status == "completed" and result.results.get("workload-running") == "True":
            return dict(result.results)
        if time.monotonic() > deadline:
            pytest.fail(f"gateway workload did not become running within {timeout}s")
        time.sleep(5)


def wait_for_gateway_stack(juju: jubilant.Juju, timeout: int = 1800) -> dict[str, str]:
    """Wait until the gateway is active, the workload is running, and the stack is idle."""
    juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=timeout)
    status = wait_for_workload_running(juju)
    logger.info("Gateway readiness: %s", status)
    juju.wait(
        lambda s: (
            jubilant.all_active(s, *INFRA_APPS, APP_NAME)
            and jubilant.all_agents_idle(s, *INFRA_APPS, APP_NAME)
        ),
        timeout=timeout,
    )
    return status


def gateway_status(juju: jubilant.Juju) -> dict[str, str]:
    """Return the results of the gateway's ``get-gateway-status`` action."""
    result = juju.run(f"{APP_NAME}/0", "get-gateway-status")
    if result.status != "completed":
        pytest.fail(f"get-gateway-status did not complete: {result.status}")
    return dict(result.results)
