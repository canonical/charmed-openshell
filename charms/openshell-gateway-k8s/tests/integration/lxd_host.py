"""Host-LXD helpers shared by integration test fixtures.

These helpers enable HTTPS on the concierge host LXD, mint a self-signed client
identity for ``lxd-integrator-k8s``, and read the server certificate/fingerprint.
They are intentionally free of pytest imports so they can be used from both
``conftest.py`` fixtures and the provider-path test modules.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import io
import json
import logging
import os
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class HostLxdEndpoint:
    """Connection details for the concierge host LXD used by the integrator path."""

    address: str
    server_fingerprint: str
    server_cert_pem: str
    client_cert_pem: str
    client_key_pem: str
    host_runner: Any
    integrator_cert_fingerprint: str


def host_lxc_runner(*args: str) -> Any:
    """Run an ``lxc`` command on the host and return the completed process."""
    return subprocess.run(
        ["lxc", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def read_lxd_config(key: str) -> str:
    """Return the current value of an LXD server configuration key."""
    result = host_lxc_runner("config", "get", key)
    return result.stdout.strip()


def generate_integrator_client_credentials() -> tuple[str, str, str]:
    """Generate a self-signed client certificate for the integrator.

    Returns ``(cert_pem, key_pem, fingerprint)``.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "openshell-integrator")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return cert_pem, key_pem, fingerprint


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


DEFAULT_SANDBOX_IMAGE_ALIAS = "openshell-sandbox"


def ensure_sandbox_image(runner: Any = host_lxc_runner) -> None:
    """Ensure that the default sandbox image alias exists in LXD.

    The OpenShell LXD driver checks on startup that the configured default
    sandbox image alias exists in the LXD image store. If absent, alias an
    existing image or import a minimal dummy image so the driver can start.
    """
    aliases_res = runner("image", "alias", "list", "--format=json")
    if aliases_res.returncode == 0 and aliases_res.stdout:
        try:
            aliases = json.loads(aliases_res.stdout)
            if any(a.get("name") == DEFAULT_SANDBOX_IMAGE_ALIAS for a in aliases):
                return
        except json.JSONDecodeError:
            pass

    # Find an existing image to alias
    img_res = runner("image", "list", "--format=json")
    if img_res.returncode == 0 and img_res.stdout:
        try:
            images = json.loads(img_res.stdout)
            if images and "fingerprint" in images[0]:
                alias_res = runner(
                    "image",
                    "alias",
                    "create",
                    DEFAULT_SANDBOX_IMAGE_ALIAS,
                    images[0]["fingerprint"],
                )
                if alias_res.returncode == 0:
                    return
        except json.JSONDecodeError:
            pass

    # Fallback: import a minimal dummy container image
    meta = (
        b"architecture: x86_64\n"
        b"creation_date: 1600000000\n"
        b"properties:\n"
        b"  description: openshell sandbox dummy image\n"
        b"  os: ubuntu\n"
        b"  release: noble\n"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        meta_tar = Path(tmpdir) / "meta.tar.gz"
        rootfs_tar = Path(tmpdir) / "rootfs.tar.gz"
        with tarfile.open(meta_tar, "w:gz") as tar:
            info = tarfile.TarInfo("metadata.yaml")
            info.size = len(meta)
            tar.addfile(info, io.BytesIO(meta))
        with tarfile.open(rootfs_tar, "w:gz") as tar:
            pass
        runner(
            "image",
            "import",
            str(meta_tar),
            str(rootfs_tar),
            "--alias",
            DEFAULT_SANDBOX_IMAGE_ALIAS,
        )


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


def _alias_exists(runner: Any, project: str) -> bool:
    """Return True when the sandbox image alias already exists in *project*."""
    result = runner("image", "alias", "list", "--format=json", "--project", project)
    if result.returncode != 0 or not result.stdout:
        return False
    try:
        aliases = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    return any(a.get("name") == DEFAULT_SANDBOX_IMAGE_ALIAS for a in aliases)


def _image_exists_in_project(runner: Any, project: str, fingerprint: str) -> bool:
    """Return True when *fingerprint* is present in *project*'s image store."""
    result = runner("query", f"/1.0/images/{fingerprint}?project={project}")
    return result.returncode == 0


def _copy_image_to_project(runner: Any, fingerprint: str, project: str) -> None:
    """Copy an image from the default project into *project* by fingerprint."""
    result = runner("image", "copy", f"local:{fingerprint}", "local:", "--target-project", project)
    if result.returncode != 0:
        raise RuntimeError(
            f"could not copy sandbox image {fingerprint} into project {project}: {result.stderr}"
        )


def _ensure_project_sandbox_image_alias(runner: Any, project: str) -> None:
    """Ensure the sandbox image alias exists inside *project*.

    The project's image store is separate from the default project's, so the
    alias the driver validates at startup must be created there too. An
    existing image from the default project is copied in by fingerprint; a
    missing one falls back to importing a minimal dummy image directly into
    the project.
    """
    if _alias_exists(runner, project):
        return

    src_img_res = runner("image", "list", "--project", "default", "--format=json")
    if src_img_res.returncode == 0 and src_img_res.stdout:
        try:
            images = json.loads(src_img_res.stdout)
        except json.JSONDecodeError:
            images = []
        for image in images:
            fingerprint = image.get("fingerprint", "")
            if not fingerprint:
                continue
            if not _image_exists_in_project(runner, project, fingerprint):
                _copy_image_to_project(runner, fingerprint, project)
            result = runner(
                "image",
                "alias",
                "create",
                DEFAULT_SANDBOX_IMAGE_ALIAS,
                fingerprint,
                "--project",
                project,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"could not create sandbox image alias in project {project}: {result.stderr}"
                )
            return

    # No image available in the default project: import a minimal dummy image
    # directly into the project.
    meta = (
        b"architecture: x86_64\n"
        b"creation_date: 1600000000\n"
        b"properties:\n"
        b"  description: openshell sandbox dummy image\n"
        b"  os: ubuntu\n"
        b"  release: noble\n"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        meta_tar = Path(tmpdir) / "meta.tar.gz"
        rootfs_tar = Path(tmpdir) / "rootfs.tar.gz"
        with tarfile.open(meta_tar, "w:gz") as tar:
            info = tarfile.TarInfo("metadata.yaml")
            info.size = len(meta)
            tar.addfile(info, io.BytesIO(meta))
        with tarfile.open(rootfs_tar, "w:gz") as tar:
            pass
        result = runner(
            "image",
            "import",
            str(meta_tar),
            str(rootfs_tar),
            "--alias",
            DEFAULT_SANDBOX_IMAGE_ALIAS,
            "--project",
            project,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"could not import sandbox image into project {project}: {result.stderr}"
            )


def ensure_lxd_project(runner: Any = host_lxc_runner, project: str = "default") -> None:
    """Ensure *project* exists on the host LXD with the devices the driver needs.

    The OpenShell LXD driver reads placement from the *project's* ``default``
    profile and validates the sandbox image alias inside that project at
    startup, but it never creates any of them. This helper provisions what the
    driver reads, mirroring what LXD does for a project created with an
    explicit ``--network`` and ``--storage``:

    - the project itself, if absent, created with the same feature set any
      CLI-created project gets;
    - a ``default`` profile with one NIC on the default project's network
      (``eth0``) and one root disk on its storage pool (``root``), re-read
      from the default project's own profile on every call so the two stay
      in sync;
    - the sandbox image alias inside the project's own image store.

    Every level is idempotent: existing entities are left as they are.
    """
    if project == "default":
        # Nothing to provision: LXD ships the default project with a populated
        # profile, and ensure_sandbox_image() already covers its image store.
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

    _ensure_project_sandbox_image_alias(runner, project)


def setup_host_lxd_endpoint() -> HostLxdEndpoint:
    """Enable HTTPS on the host LXD, trust an integrator identity, and return details."""
    host_ip = _host_reachable_ip()
    result = host_lxc_runner("config", "set", "core.https_address", f"{host_ip}:8443")
    if result.returncode != 0:
        raise RuntimeError(f"could not enable host LXD HTTPS listener: {result.stderr}")

    # Allow the listener a moment to come up.
    time.sleep(2)

    ensure_sandbox_image(host_lxc_runner)

    client_cert_pem, client_key_pem, integrator_fingerprint = (
        generate_integrator_client_credentials()
    )

    cert_file = Path("/tmp") / f"openshell-integrator-{os.getpid()}.crt"
    cert_file.write_text(client_cert_pem)
    try:
        result = host_lxc_runner("config", "trust", "add", str(cert_file))
        if result.returncode != 0:
            raise RuntimeError(
                f"could not add integrator client cert to host LXD: {result.stderr}"
            )
    finally:
        cert_file.unlink(missing_ok=True)

    address = f"https://{host_ip}:8443"
    server_cert_pem, server_fingerprint = fetch_server_cert(address)

    return HostLxdEndpoint(
        address=address,
        server_fingerprint=server_fingerprint,
        server_cert_pem=server_cert_pem,
        client_cert_pem=client_cert_pem,
        client_key_pem=client_key_pem,
        host_runner=host_lxc_runner,
        integrator_cert_fingerprint=integrator_fingerprint,
    )


def teardown_host_lxd_endpoint(endpoint: HostLxdEndpoint, prior_address: str | None) -> None:
    """Remove the integrator identity and restore the HTTPS listener setting."""
    host_lxc_runner("config", "trust", "remove", endpoint.integrator_cert_fingerprint)
    if prior_address:
        host_lxc_runner("config", "set", "core.https_address", prior_address)
    else:
        host_lxc_runner("config", "unset", "core.https_address")
