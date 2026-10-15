"""Host-LXD helpers shared by integration test fixtures.

These helpers enable HTTPS on the concierge host LXD (or use an LXD that already
serves HTTPS, such as a MicroCloud, when ``OPENSHELL_TEST_LXD_ADDRESS`` names
it), read the server certificate/fingerprint, and create the group and pending
TLS identity whose trust token the gateway redeems.
They are intentionally free of pytest imports so they can be used from both
``conftest.py`` fixtures and the provider-path test modules.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import socket
import ssl
import subprocess
import time
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class HostLxdEndpoint:
    """Connection details for the host LXD the gateway joins."""

    address: str
    server_fingerprint: str
    server_cert_pem: str
    host_runner: Any


def host_lxc_runner(*args: str) -> Any:
    """Run an ``lxc`` command on the host and return the completed process.

    stdin is always ``/dev/null``: ``lxc auth identity create`` with no
    certificate path reads one from stdin whenever stdin is not a terminal,
    and would otherwise wait on it forever.
    """
    return subprocess.run(
        ["lxc", *args],
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def read_lxd_config(key: str) -> str:
    """Return the current value of an LXD server configuration key."""
    result = host_lxc_runner("config", "get", key)
    return result.stdout.strip()


def fetch_server_cert(address: str) -> tuple[str, str]:
    """Connect to the LXD HTTPS endpoint and return ``(cert_pem, fingerprint)``."""
    # Strip an optional scheme so callers can pass either ``host:port`` or a URL.
    netloc = address.removeprefix("https://").removeprefix("http://")
    host, _, port = netloc.rpartition(":")
    if not port:
        port = "8443"
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host or "localhost", int(port)), timeout=10) as sock,
        context.wrap_socket(sock) as ssock,
    ):
        der = ssock.getpeercert(binary_form=True)
    assert der, "could not retrieve LXD server certificate"
    cert = x509.load_der_x509_certificate(der)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    fingerprint = hashlib.sha256(der).hexdigest()
    return pem, fingerprint


def _host_reachable_ip() -> str:
    """Return an IP address the current host uses for outbound IPv4 traffic.

    Pods in the concierge Kubernetes cluster need this address to reach the
    host LXD; ``localhost`` resolves to the pod itself. The default route is
    read from the kernel routing table so the probe works in restricted CI
    environments without internet access.
    """
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0 and result.stdout:
        # ``default via <gateway> dev <dev> ...``
        parts = result.stdout.strip().split()
        if "via" in parts:
            gateway = parts[parts.index("via") + 1]
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2)
                    sock.connect((gateway, 1))
                    return sock.getsockname()[0]
            except OSError as exc:
                raise RuntimeError(f"could not determine host reachable IP: {exc}") from exc

    raise RuntimeError("could not determine host reachable IP: no default IPv4 route found")


def _query_profile(runner: Any, project: str) -> dict[str, Any]:
    """Return the ``default`` profile of *project* as JSON, or ``{}`` when absent.

    ``lxc query`` carries the project in the URL rather than a flag, and
    unlike ``lxc profile show`` it returns structured JSON.
    """
    result = runner("query", f"/1.0/profiles/default?project={project}")
    if result.returncode != 0:
        return {}
    return json.loads(result.stdout or "{}")


def _profile_devices(runner: Any, project: str) -> dict[str, Any]:
    """Return *project*'s ``default`` profile device map without the name keys.

    The API nests a ``name`` key inside every device; dropping it makes
    devices comparable to plain ``{type, ...config}`` maps.
    """
    devices = _query_profile(runner, project).get("devices") or {}
    return {
        name: {key: value for key, value in device.items() if key != "name"}
        for name, device in devices.items()
    }


def ensure_lxd_project(runner: Any = host_lxc_runner, project: str = "default") -> None:
    """Ensure *project* exists on the host LXD with the devices the driver needs.

    The OpenShell LXD driver reads placement from the *project's* ``default``
    profile but never creates the project or the profile's devices. This
    helper provisions what the driver reads, mirroring what LXD does for a
    project created with an explicit ``--network`` and ``--storage``:

    - the project itself, if absent, created with the same feature set any
      CLI-created project gets;
    - a ``default`` profile with one NIC on the default project's network
      (``eth0``) and one root disk on its storage pool (``root``), re-read
      from the default project's own profile on every call so the two stay
      in sync.

    Sandbox images are OCI references the driver pulls and converts itself,
    so the project needs no image of its own.

    Every level is idempotent: existing entities are left as they are.
    """
    if project == "default":
        # Nothing to provision: LXD ships the default project with a populated
        # profile.
        return

    default_devices = _profile_devices(runner, "default")
    network = (default_devices.get("eth0") or {}).get("network", "")
    storage_pool = (default_devices.get("root") or {}).get("pool", "")

    # Create the project. Features default the same way as a CLI-created
    # project, so the API fills in features.profiles/images/volumes/buckets
    # itself; the call fails with "already exists" when the project is there.
    result = runner("project", "create", project)
    if result.returncode != 0 and "already exists" not in (result.stderr or ""):
        raise RuntimeError(f"could not create LXD project {project}: {result.stderr}")

    # Ensure the project's default profile carries the NIC and root disk.
    profile_devices = _profile_devices(runner, project)

    wanted_devices: dict[str, dict[str, str]] = {}
    if network:
        wanted_devices["eth0"] = {"type": "nic", "network": network}
    if storage_pool:
        wanted_devices["root"] = {"type": "disk", "path": "/", "pool": storage_pool}

    for name, devices in wanted_devices.items():
        if profile_devices.get(name) == devices:
            continue
        dev_args = ["profile", "device", "add", "--project", project, "default", name]
        dev_args.append(devices.pop("type"))
        dev_args.extend(f"{key}={value}" for key, value in devices.items())
        result = runner(*dev_args)
        if result.returncode != 0:
            raise RuntimeError(
                f"could not add device {name} to the default profile of project "
                f"{project}: {result.stderr}"
            )


#: ``host:port`` of an LXD that already listens on HTTPS, such as a MicroCloud
#: the ``lxc`` client reaches as its default remote. When set, the fixtures
#: use it as it is instead of pointing the local LXD's listener at this host.
EXTERNAL_LXD_ADDRESS_ENV = "OPENSHELL_TEST_LXD_ADDRESS"


def external_lxd_address() -> str | None:
    """Return the externally managed LXD address from the environment, if any."""
    address = os.environ.get(EXTERNAL_LXD_ADDRESS_ENV, "").strip()
    return address or None


def setup_host_lxd_endpoint() -> HostLxdEndpoint:
    """Enable HTTPS on the host LXD and return its connection details.

    With ``OPENSHELL_TEST_LXD_ADDRESS`` set, the LXD is someone else's, for
    example a MicroCloud: its listener is left alone.
    """
    host_address = external_lxd_address()
    if host_address is None:
        host_address = f"{_host_reachable_ip()}:8443"
        result = host_lxc_runner("config", "set", "core.https_address", host_address)
        if result.returncode != 0:
            raise RuntimeError(f"could not enable host LXD HTTPS listener: {result.stderr}")

        # Allow the listener a moment to come up.
        time.sleep(2)

    address = f"https://{host_address}"
    server_cert_pem, server_fingerprint = fetch_server_cert(address)

    return HostLxdEndpoint(
        address=address,
        server_fingerprint=server_fingerprint,
        server_cert_pem=server_cert_pem,
        host_runner=host_lxc_runner,
    )


def teardown_host_lxd_endpoint(prior_address: str | None) -> None:
    """Restore the HTTPS listener setting, unless the LXD is an external one."""
    if external_lxd_address() is not None:
        # The listener was never touched.
        return
    if prior_address:
        host_lxc_runner("config", "set", "core.https_address", prior_address)
    else:
        host_lxc_runner("config", "unset", "core.https_address")


def ensure_join_group(runner: Any, group: str, project: str) -> None:
    """Ensure *group* grants ``operator`` on *project*, and sight of its shared network.

    ``ensure_lxd_project`` gives the project no networks of its own: its
    sandboxes use the ``default`` project's network, which the driver looks up
    before every create. LXD allows viewing that network only together with
    viewing the ``default`` project, which does not show its instances. A
    production project has its own network instead; see the deploy guide.
    """
    network = (_profile_devices(runner, "default").get("eth0") or {}).get("network", "")
    grants = [("project", project, "operator"), ("project", "default", "can_view")]
    if network:
        grants.append(("network", network, "can_view", "project=default"))

    result = runner("auth", "group", "create", group)
    if result.returncode != 0 and "already exists" not in (result.stderr or ""):
        raise RuntimeError(f"could not create LXD group {group}: {result.stderr}")
    for grant in grants:
        result = runner("auth", "group", "permission", "add", group, *grant)
        if result.returncode != 0 and "already" not in (result.stderr or ""):
            raise RuntimeError(f"could not grant {group} {' '.join(grant)}: {result.stderr}")


def create_pending_identity(runner: Any, name: str, group: str) -> str:
    """Create the pending TLS identity *name* in *group* and return its trust token.

    An identity left over from an earlier run is deleted first, whether it is
    still pending or was redeemed, so the token is always fresh.
    """
    delete_identity(runner, name)
    result = runner("auth", "identity", "create", f"tls/{name}", "--group", group)
    if result.returncode != 0:
        raise RuntimeError(f"could not create LXD identity {name}: {result.stderr}")
    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"lxc printed no trust token for identity {name}")
    return lines[-1]


def delete_identity(runner: Any, name: str) -> None:
    """Delete the TLS identity *name*, pending or not, if it exists."""
    runner("auth", "identity", "delete", f"tls/{name}")


def delete_group(runner: Any, group: str) -> None:
    """Delete the LXD group *group* if it exists."""
    runner("auth", "group", "delete", group)


def lxd_identity(runner: Any, name: str) -> dict[str, Any]:
    """Return the TLS identity called *name* from ``lxc auth identity list``, or ``{}``.

    A pending identity's ``type`` ends in ``(pending)`` and its ``id`` is a
    UUID; once redeemed, ``id`` is the SHA-256 fingerprint of the certificate
    that redeemed it.
    """
    result = runner("auth", "identity", "list", "--format=json")
    if result.returncode != 0:
        raise RuntimeError(f"could not list LXD identities: {result.stderr}")
    for entry in json.loads(result.stdout or "[]"):
        if entry.get("authentication_method") == "tls" and entry.get("name") == name:
            return entry
    return {}
