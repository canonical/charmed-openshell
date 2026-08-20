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
import logging
import os
import socket
import ssl
import subprocess
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


def setup_host_lxd_endpoint() -> HostLxdEndpoint:
    """Enable HTTPS on the host LXD, trust an integrator identity, and return details."""
    host_ip = _host_reachable_ip()
    result = host_lxc_runner("config", "set", "core.https_address", f"{host_ip}:8443")
    if result.returncode != 0:
        raise RuntimeError(f"could not enable host LXD HTTPS listener: {result.stderr}")

    # Allow the listener a moment to come up.
    time.sleep(2)

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
