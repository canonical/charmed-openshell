"""LXD trust store and project inspection helpers."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .constants import APP_NAME
from .juju_wait import gateway_status

if TYPE_CHECKING:
    import jubilant


def gateway_client_cert_fingerprint(juju: jubilant.Juju) -> str:
    """Return the SHA-256 fingerprint of the gateway's LXD client certificate."""
    result = juju.run(f"{APP_NAME}/0", "get-lxd-client-cert")
    assert result.status == "completed", result
    cert_pem = result.results.get("certificate")
    assert cert_pem, "get-lxd-client-cert did not return a client certificate"
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def lxc_trust_fingerprints(runner: Any) -> set[str]:
    """Return the set of certificate fingerprints from ``lxc config trust list``."""
    result = runner("query", "/1.0/certificates?recursion=1")
    stdout = result.stdout if hasattr(result, "stdout") else str(result)
    certs = json.loads(stdout)
    return {cert["fingerprint"].lower() for cert in certs}


def assert_trust_registered(
    juju: jubilant.Juju,
    fingerprint_source: Any,
    *,
    timeout: int = 300,
) -> None:
    """Poll until the gateway's client certificate is trusted by the LXD."""
    expected = gateway_client_cert_fingerprint(juju)
    deadline = time.monotonic() + timeout
    while True:
        fingerprints = fingerprint_source()
        if expected in fingerprints:
            return
        if time.monotonic() > deadline:
            pytest.fail(f"gateway cert {expected} not registered in LXD trust store")
        time.sleep(5)


def assert_trust_withdrawn(
    juju: jubilant.Juju,
    fingerprint_source: Any,
    *,
    timeout: int = 300,
) -> None:
    """Poll until the gateway's client certificate is removed from the LXD trust store."""
    expected = gateway_client_cert_fingerprint(juju)
    deadline = time.monotonic() + timeout
    while True:
        fingerprints = fingerprint_source()
        if expected not in fingerprints:
            return
        if time.monotonic() > deadline:
            pytest.fail(f"gateway cert {expected} still present in LXD trust store")
        time.sleep(5)


def managed_lxd_trust_fingerprints(
    machine_juju: jubilant.Juju,
    app: str = "lxd",
) -> set[str]:
    """Read the trust store of the LXD charm's managed LXD via ``juju exec``."""

    def runner(*args: str) -> Any:
        return machine_juju.exec("lxc", *args, unit=f"{app}/0")

    return lxc_trust_fingerprints(runner)


def wait_for_lxd_project(juju: jubilant.Juju, expected: str, timeout: int = 300) -> dict[str, str]:
    """Wait until the gateway reports *expected* as its LXD project."""
    deadline = time.monotonic() + timeout
    last: dict[str, str] = {}
    while True:
        last = gateway_status(juju)
        app = juju.status().apps.get(APP_NAME)
        if app is not None and app.app_status.current == "blocked":
            pytest.fail(
                f"gateway blocked while waiting for lxd-project={expected!r}: "
                f"{app.app_status.message}"
            )
        if last.get("lxd-project", "") == expected:
            return last
        if time.monotonic() > deadline:
            pytest.fail(
                f"gateway still reports lxd-project={last.get('lxd-project')!r} "
                f"after {timeout}s, expected {expected!r}"
            )
        time.sleep(5)


def lxc_trust_entry(runner: Callable[..., Any], fingerprint: str) -> dict[str, Any]:
    """Return the LXD trust-store entry for *fingerprint*, or an empty dict."""
    result = runner("config", "trust", "list", "--format=json")
    if result.returncode != 0:
        pytest.fail(f"could not list the LXD trust store: {result.stderr}")
    for entry in json.loads(result.stdout or "[]"):
        if entry.get("fingerprint", "").lower() == fingerprint.lower():
            return entry
    return {}


def lxc_instance_projects(runner: Callable[..., Any], name_prefix: str) -> dict[str, str]:
    """Return ``{instance name: project}`` for instances whose name starts with *name_prefix*."""
    result = runner("project", "list", "--format=json")
    if result.returncode != 0:
        pytest.fail(f"could not list LXD projects: {result.stderr}")
    projects = [entry["name"] for entry in json.loads(result.stdout or "[]")]

    found: dict[str, str] = {}
    for project in projects:
        listed = runner("list", "--project", project, "--format=json")
        if listed.returncode != 0:
            continue
        for instance in json.loads(listed.stdout or "[]"):
            name = instance.get("name", "")
            if name.startswith(name_prefix):
                found[name] = project
    return found
