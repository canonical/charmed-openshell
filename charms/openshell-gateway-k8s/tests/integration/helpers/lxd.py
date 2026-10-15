"""LXD identity, join-secret and project inspection helpers."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..lxd_host import create_pending_identity
from .constants import APP_NAME, IT_GROUP, IT_IDENTITY, IT_PROJECT, LXD_JOIN_SECRET
from .juju_wait import gateway_status

if TYPE_CHECKING:
    import jubilant

#: The label the charm gives the peer secret holding its LXD client identity.
LXD_CLIENT_IDENTITY_LABEL = "lxd-client-identity"


def gateway_client_cert_fingerprint(juju: jubilant.Juju) -> str:
    """Return the SHA-256 fingerprint of the gateway's LXD client certificate.

    Read from the charm's own secret, which an admin can reveal: the
    certificate is what LXD records as the identity's fingerprint once the
    token is redeemed.
    """
    matches = [s for s in juju.secrets() if s.label == LXD_CLIENT_IDENTITY_LABEL]
    assert matches, f"no secret labelled {LXD_CLIENT_IDENTITY_LABEL}"
    revealed = juju.show_secret(matches[0].uri, reveal=True)
    cert_pem = getattr(revealed, "content", {}).get("certificate")
    assert cert_pem, f"secret {LXD_CLIENT_IDENTITY_LABEL} carries no certificate"
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def put_join_secret(juju: jubilant.Juju, token: str) -> str:
    """Store *token* in the ``lxd-join`` user secret, grant it, and return its URI.

    A secret left from an earlier run against the same model gets a new
    revision instead of a second secret.
    """
    existing = [s for s in juju.secrets() if s.name == LXD_JOIN_SECRET]
    if existing:
        uri = str(existing[0].uri)
        juju.update_secret(uri, {"token": token})
    else:
        uri = str(juju.add_secret(LXD_JOIN_SECRET, {"token": token}))
    juju.grant_secret(uri, APP_NAME)
    return uri


def join_gateway_to_lxd(juju: jubilant.Juju, runner: Any) -> str:
    """Create a fresh pending identity, hand its token to the gateway, and return the URI.

    The secret is granted before the gateway's config names it: a grant fires
    no hook, while the config change that follows reads the granted secret.
    With the config already in place, the new secret revision fires
    secret-changed instead.
    """
    token = create_pending_identity(runner, IT_IDENTITY, IT_GROUP)
    uri = put_join_secret(juju, token)
    juju.config(APP_NAME, {"lxd-join-secret": uri, "lxd-project": IT_PROJECT})
    return uri


def remove_join_secret(juju: jubilant.Juju) -> None:
    """Remove the ``lxd-join`` user secret if it exists."""
    for secret in juju.secrets():
        if secret.name == LXD_JOIN_SECRET:
            juju.remove_secret(secret.uri)


def wait_for_gateway_message(
    juju: jubilant.Juju, message: str, *, status: str = "blocked", timeout: int = 600
) -> None:
    """Wait until the gateway's application status is *status* and names *message*."""

    def _reached(s: jubilant.Status) -> bool:
        app = s.apps.get(APP_NAME)
        if app is None:
            return False
        return app.app_status.current == status and message in (app.app_status.message or "")

    juju.wait(_reached, timeout=timeout)


def wait_for_identity_trusted(
    identity: Callable[[], dict[str, Any]], fingerprint: str, *, timeout: int = 600
) -> dict[str, Any]:
    """Poll until *identity* is redeemed by the certificate with *fingerprint*."""
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while True:
        last = identity()
        if last.get("type") == "Client certificate" and last.get("id") == fingerprint:
            return last
        if time.monotonic() > deadline:
            pytest.fail(f"identity was not redeemed by {fingerprint} within {timeout}s: {last}")
        time.sleep(5)


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
