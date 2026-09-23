"""Kubernetes command execution and discovery helpers."""

from __future__ import annotations

import shutil
import subprocess
import time
from typing import TYPE_CHECKING

import pytest

from .command import run_cmd
from .constants import TRAEFIK_APP

if TYPE_CHECKING:
    import jubilant


def kubectl_try(*args: str) -> subprocess.CompletedProcess[str]:
    """Run ``kubectl`` and return the completed process without failing."""
    for prefix in (["kubectl"], ["microk8s", "kubectl"]):
        if shutil.which(prefix[0]) is None:
            continue
        return run_cmd(*prefix, *args)
    pytest.fail("no kubectl binary found on PATH")
    raise RuntimeError("unreachable")


def kubectl(*args: str, allowed_returncodes: tuple[int, ...] = (0,)) -> str:
    """Run ``kubectl`` (or ``microk8s kubectl``) and return stdout."""
    for prefix in (["kubectl"], ["microk8s", "kubectl"]):
        if shutil.which(prefix[0]) is None:
            continue
        result = run_cmd(*prefix, *args)
        if result.returncode in allowed_returncodes:
            return result.stdout
        pytest.fail(
            f"kubectl {' '.join(args)} failed ({result.returncode}):\n"
            f"{result.stdout}\n{result.stderr}"
        )
    pytest.fail("no kubectl binary found on PATH")
    raise RuntimeError("unreachable")


def get_traefik_lb_address(juju: jubilant.Juju, timeout: int = 300) -> str:
    """Discover the external LoadBalancer address assigned to Traefik."""
    model = juju.model.split(":")[-1]
    deadline = time.monotonic() + timeout

    while True:
        for cmd_prefix in (["kubectl"], ["microk8s", "kubectl"]):
            if shutil.which(cmd_prefix[0]) is None:
                continue
            cmd = [
                *cmd_prefix,
                "-n",
                model,
                "get",
                "svc",
                f"{TRAEFIK_APP}-lb",
                "-o",
                "jsonpath={.status.loadBalancer.ingress[0].ip}",
            ]
            result = run_cmd(*cmd)
            address = result.stdout.strip()
            if result.returncode == 0 and address:
                return address

            cmd[-1] = "jsonpath={.status.loadBalancer.ingress[0].hostname}"
            result = run_cmd(*cmd)
            address = result.stdout.strip()
            if result.returncode == 0 and address:
                return address

        if time.monotonic() > deadline:
            pytest.fail(
                f"Could not determine Traefik LoadBalancer address for service "
                f"{TRAEFIK_APP}-lb (is MetalLB configured and kubectl available?)"
            )
        time.sleep(5)
