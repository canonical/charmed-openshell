"""LXD REST helpers for the composed-stack integration tests.

The stack CI runs its tests inside the Kubernetes VM, which has no ``lxc``
client: the MicroCloud LXD the gateway creates sandboxes on lives on the CI
runner and is reachable only over its HTTPS endpoint, with the administrative
client identity and server certificate the workflow pushes into the VM. These
helpers drive the REST API directly — standard library only, no pytest or
jubilant imports, in the same spirit as ``lxd_host.py`` — and provision what
the stack module's documented operator steps describe: the project and its
``default`` profile (mirrored from the default project's, the way LXD does
for a project created with an explicit network and storage), and the
gateway's pending TLS identity in a group limited to that project, whose
trust token the gateway redeems. Sandbox images are OCI references the driver
pulls itself, so no image is provisioned.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


@dataclasses.dataclass
class StackLxdConfig:
    """Connection details for the LXD endpoint the stack's sandboxes run on."""

    endpoint: str
    client_cert: Path
    client_key: Path
    server_cert: Path


class StackLxd:
    """Minimal LXD REST client authenticating with the pushed certificates."""

    def __init__(self, config: StackLxdConfig) -> None:
        self._base = config.endpoint.rstrip("/")
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # The MicroCloud LXD presents its self-signed server certificate; the
        # workflow pushes it into the VM so these tests can pin it.
        self._context.load_verify_locations(cafile=str(config.server_cert))
        self._context.check_hostname = False
        self._context.load_cert_chain(
            certfile=str(config.client_cert), keyfile=str(config.client_key)
        )

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        """Perform one REST call and return the response's ``metadata``, or None on 404.

        The metadata is an object for most calls and a list for collections.

        LXD wraps every result in an envelope (``type``, ``status``,
        ``metadata``, …); callers want the object inside it.
        """
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{self._base}{path}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, context=self._context, timeout=120) as response:
                envelope = json.loads(response.read() or b"null")
                return envelope.get("metadata") if isinstance(envelope, dict) else None
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"LXD {method} {path} failed: HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LXD {method} {path} failed: {exc.reason}") from exc

    def ensure_project(self, project: str) -> None:
        """Create *project*, tolerating an existing one, like ``lxc project create``."""
        try:
            self.request("POST", "/1.0/projects", {"name": project})
        except RuntimeError as exc:
            if "already exists" not in str(exc):
                raise

    @staticmethod
    def _bare_devices(devices: dict[str, Any]) -> dict[str, dict[str, str]]:
        """Drop the ``name`` key the API nests inside every device."""
        return {
            name: {key: value for key, value in device.items() if key != "name"}
            for name, device in devices.items()
        }

    def ensure_project_profile(self, project: str) -> str:
        """Give *project*'s ``default`` profile the default project's placement.

        The driver reads sandbox placement — the ``eth0`` network and the
        ``root`` pool — from the project's own ``default`` profile and never
        creates it. This mirrors both from the default project's profile on
        every call, leaving the project's other devices as they are, and
        returns the network's name.
        """
        default = self.request("GET", "/1.0/profiles/default?project=default")
        assert default is not None, "the default project has no default profile"
        default_devices = self._bare_devices(default.get("devices") or {})
        network = (default_devices.get("eth0") or {}).get("network", "")
        pool = (default_devices.get("root") or {}).get("pool", "")
        assert network and pool, f"the default profile has no eth0 network or root pool: {default}"

        current = self.request("GET", f"/1.0/profiles/default?project={project}")
        assert current is not None, f"project {project} has no default profile"
        devices = self._bare_devices(current.get("devices") or {})

        wanted: dict[str, dict[str, str]] = {}
        if network:
            wanted["eth0"] = {"type": "nic", "network": network}
        if pool:
            wanted["root"] = {"type": "disk", "path": "/", "pool": pool}
        if all(devices.get(name) == device for name, device in wanted.items()):
            return network

        for name, device in wanted.items():
            devices[name] = device
        body = {
            "config": current.get("config") or {},
            "description": current.get("description", ""),
            "devices": devices,
        }
        self.request("PUT", f"/1.0/profiles/default?project={project}", body)
        return network

    def ensure_project_group(self, group: str, project: str, shared_network: str) -> None:
        """Make *group* grant ``operator`` on *project*, and sight of *shared_network*.

        The project has no networks of its own: its sandboxes use
        *shared_network* from the ``default`` project, which the driver looks
        up before every create. LXD allows viewing that network only together
        with viewing the ``default`` project, which does not show its
        instances. A production project has its own network instead; see the
        deploy guide.
        """
        permissions = [
            {
                "entity_type": "project",
                "url": f"/1.0/projects/{project}",
                "entitlement": "operator",
            },
            {"entity_type": "project", "url": "/1.0/projects/default", "entitlement": "can_view"},
            {
                "entity_type": "network",
                "url": f"/1.0/networks/{shared_network}?project=default",
                "entitlement": "can_view",
            },
        ]
        if self.request("GET", f"/1.0/auth/groups/{group}") is None:
            self.request("POST", "/1.0/auth/groups", {"name": group, "permissions": permissions})
            return
        self.request(
            "PUT", f"/1.0/auth/groups/{group}", {"description": "", "permissions": permissions}
        )

    def delete_tls_identity(self, name: str) -> None:
        """Delete the TLS identity called *name*, pending or not, if it exists."""
        identities = self.request("GET", "/1.0/auth/identities/tls?recursion=1") or []
        for identity in identities:
            if identity.get("name") == name:
                self.request("DELETE", f"/1.0/auth/identities/tls/{identity['id']}")

    def create_pending_identity(self, name: str, group: str) -> str:
        """Create a pending TLS identity in *group* and return its trust token.

        The API answers with the token's fields; the token ``lxc auth
        identity create`` prints is that object, JSON-encoded and base64'd.
        """
        body = self.request(
            "POST",
            "/1.0/auth/identities/tls",
            {"name": name, "groups": [group], "token": True},
        )
        assert body and body.get("secret"), f"LXD returned no trust token: {body}"
        return base64.b64encode(json.dumps(body).encode()).decode()

    def delete_group(self, group: str) -> None:
        """Delete *group* if it exists."""
        if self.request("GET", f"/1.0/auth/groups/{group}") is not None:
            self.request("DELETE", f"/1.0/auth/groups/{group}")
