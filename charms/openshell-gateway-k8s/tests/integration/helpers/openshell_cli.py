"""OpenShell CLI execution and sandbox verification helpers."""

from __future__ import annotations

import os
import re
import time
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING

import jubilant
import pytest

from ..sandbox_state import sandbox_is_running as _sandbox_is_running
from .command import run_cmd
from .constants import APP_NAME, CONTAINER_NAME, OIDC_ADMIN_ROLE

if TYPE_CHECKING:
    import jubilant


def driver_help_output(juju: jubilant.Juju) -> str:
    """Return ``openshell-driver-lxd --help`` output from the workload container."""
    try:
        return juju.ssh(
            f"{APP_NAME}/0",
            "openshell-driver-lxd",
            "--help",
            container=CONTAINER_NAME,
        )
    except jubilant.CLIError as exc:
        output = f"{exc.stdout or ''}{exc.stderr or ''}"
        if not output.strip():
            pytest.fail(
                f"could not probe openshell-driver-lxd in container "
                f"{CONTAINER_NAME!r} of {APP_NAME}/0: {exc}"
            )
        return output


def sandbox_e2e_supported(juju: jubilant.Juju) -> bool:
    """Return True if the deployed driver exposes ``--gateway-endpoint`` and e2e is enabled.

    By default, checks whether the driver has ``--gateway-endpoint``.
    Allows explicit opt-out via ``OPENSHELL_DISABLE_SANDBOX_E2E``.
    """
    if os.environ.get("OPENSHELL_DISABLE_SANDBOX_E2E"):
        return False
    return "--gateway-endpoint" in driver_help_output(juju)


def openshell_gateway_remove(name: str) -> None:
    """Remove a registered gateway from the openshell CLI."""
    run_cmd("openshell", "gateway", "remove", name)


def openshell_gateway_add(
    *,
    name: str,
    gateway_url: str,
    issuer_url: str,
    client_id: str,
    client_secret: str,
    audience: str,
    scopes: str = OIDC_ADMIN_ROLE,
) -> None:
    """Register a gateway in the openshell CLI using OIDC credentials.

    *scopes* is what the CLI requests in the token exchange. The client has
    to be allowed every one of them, or the identity provider refuses the
    exchange before the gateway sees a token.
    """
    env = os.environ.copy()
    env["OPENSHELL_OIDC_CLIENT_SECRET"] = client_secret
    env.pop("SSL_CERT_FILE", None)

    result = run_cmd(
        "openshell",
        "gateway",
        "add",
        gateway_url,
        "--name",
        name,
        "--oidc-issuer",
        issuer_url,
        "--oidc-client-id",
        client_id,
        "--oidc-audience",
        audience,
        "--oidc-scopes",
        scopes,
        env=env,
    )
    output = result.stdout + result.stderr
    print("openshell gateway add output:\n", output)
    if (
        result.returncode != 0
        or "added and set as active" not in output
        or "removed" in output.lower()
    ):
        pytest.fail(
            f"openshell gateway add failed ({result.returncode}):\n{result.stdout}\n{result.stderr}"
        )


def openshell_status(gateway_name: str | None = None) -> str:
    """Run ``openshell status`` and return cleaned text output."""
    args = ["openshell"]
    if gateway_name:
        args.extend(["-g", gateway_name])
    args.append("status")
    result = run_cmd(*args)
    if result.returncode != 0:
        output = result.stdout + result.stderr
        pytest.fail(f"openshell status failed ({result.returncode}):\n{output}")
    return re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)


def openshell_sandbox_create(
    name: str, *, source: str | None = None, gateway_name: str | None = None
) -> None:
    """Create an OpenShell sandbox through the configured gateway."""
    args = ["openshell"]
    if gateway_name:
        args.extend(["-g", gateway_name])
    args.extend(["sandbox", "create", "--name", name])
    if source:
        args.extend(["--from", source])
    result = run_cmd(*args)
    output = result.stdout + result.stderr
    print("openshell sandbox create output:\n", output)
    if result.returncode != 0:
        pytest.fail(f"openshell sandbox create failed ({result.returncode}):\n{output}")


def openshell_sandbox_delete(
    name: str, *, gateway_name: str | None = None, check: bool = True
) -> None:
    """Delete an OpenShell sandbox."""
    args = ["openshell"]
    if gateway_name:
        args.extend(["-g", gateway_name])
    args.extend(["sandbox", "delete", name])
    result = run_cmd(*args)
    output = result.stdout + result.stderr
    print("openshell sandbox delete output:\n", output)
    if check and result.returncode != 0:
        pytest.fail(f"openshell sandbox delete failed ({result.returncode}):\n{output}")


def unique_marker(sandbox_name: str) -> str:
    """Return a sandbox-specific token that cannot be confused with stale output."""
    return f"{sandbox_name}-{uuid.uuid4().hex[:8]}"


def openshell_sandbox_exec(name: str, marker: str, *, gateway_name: str | None = None) -> str:
    """Run a non-interactive command in a sandbox and return its stdout."""
    args = ["openshell"]
    if gateway_name:
        args.extend(["-g", gateway_name])
    args.extend(["sandbox", "exec", "-n", name, "--", "echo", marker])
    result = run_cmd(*args)
    output = result.stdout + result.stderr
    print("openshell sandbox exec output:\n", output)
    if result.returncode != 0:
        pytest.fail(f"openshell sandbox exec failed ({result.returncode}):\n{output}")
    if marker not in result.stdout:
        pytest.fail(f"openshell sandbox exec output missing marker ({marker!r}):\n{output}")
    return result.stdout


def openshell_sandbox_wait_running(
    name: str,
    *,
    timeout: int = 300,
    gateway_name: str | None = None,
) -> None:
    """Poll ``openshell sandbox list`` until the named sandbox reports running."""
    deadline = time.monotonic() + timeout
    while True:
        args = ["openshell"]
        if gateway_name:
            args.extend(["-g", gateway_name])
        args.extend(["sandbox", "list", "-o", "json"])
        result = run_cmd(*args)
        output = result.stdout + result.stderr
        if result.returncode == 0 and _sandbox_is_running(name, result.stdout):
            return
        if time.monotonic() > deadline:
            pytest.fail(f"sandbox {name} did not reach running state within {timeout}s:\n{output}")
        time.sleep(5)


def run_gated_sandbox_e2e(
    *,
    gateway_url: str,
    issuer_url: str,
    client_id: str,
    client_secret: str,
    audience: str,
    gateway_name: str,
    sandbox_name: str,
    while_running: Callable[[], None] | None = None,
) -> None:
    """Add a gateway, launch a sandbox, verify shell access, and clean up."""
    openshell_gateway_remove(gateway_name)
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

    try:
        openshell_sandbox_create(sandbox_name, gateway_name=gateway_name)
        openshell_sandbox_wait_running(sandbox_name, gateway_name=gateway_name)
        if while_running is not None:
            while_running()
        marker = unique_marker(sandbox_name)
        stdout = openshell_sandbox_exec(sandbox_name, marker, gateway_name=gateway_name)
        assert marker in stdout, stdout
    finally:
        openshell_sandbox_delete(sandbox_name, gateway_name=gateway_name, check=False)
        openshell_gateway_remove(gateway_name)
