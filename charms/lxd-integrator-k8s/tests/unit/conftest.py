"""Shared test fixtures."""

from __future__ import annotations

import datetime
import json
from collections.abc import Iterable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@pytest.fixture
def cert_pair():
    """Generate a self-signed certificate and key for transport tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    return cert_pem, key_pem, cert_der


class FakeSocket:
    """Simulates the TLS socket returned by ``HTTPSConnection.sock``."""

    def __init__(self, peer_der: bytes):
        self.peer_der = peer_der

    def getpeercert(self, binary_form: bool = False):
        if binary_form:
            return self.peer_der
        return {}


class FakeResponse:
    """Simulates ``HTTPResponse`` returned by ``HTTPSConnection.getresponse``."""

    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body


class FakeConnection:
    """Simulates ``http.client.HTTPSConnection`` for Scenario tests."""

    def __init__(
        self,
        peer_der: bytes,
        responses: dict[tuple[str, str], tuple[int, bytes]] | None = None,
        raise_on_connect: bool = False,
    ):
        self.peer_der = peer_der
        self.responses = responses or {}
        self.raise_on_connect = raise_on_connect
        self.sock: FakeSocket | None = None
        self.requests: list[tuple[str, str, bytes | None]] = []
        self.connected = False
        self.closed = False

    def connect(self) -> None:
        if self.raise_on_connect:
            raise ConnectionRefusedError("connect failed")
        self.connected = True
        self.sock = FakeSocket(self.peer_der)

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.requests.append((method, path, body))

    def getresponse(self) -> FakeResponse:
        key = (self.requests[-1][0], self.requests[-1][1])
        status, body = self.responses.get(key, (200, b"{}"))
        return FakeResponse(status, body)

    def close(self) -> None:
        self.closed = True


class FakeTransport:
    """Factory and response registry for ``FakeConnection`` instances."""

    def __init__(self, peer_der: bytes):
        self.peer_der = peer_der
        self.responses: dict[tuple[str, str], tuple[int, bytes]] = {}
        self.raise_on_connect = False
        self.connections: list[FakeConnection] = []

    def add_response(self, method: str, path: str, status: int, body: object) -> None:
        """Register a JSON response for a given method/path."""
        self.responses[(method, path)] = (status, json.dumps({"metadata": body}).encode())

    def set_error(self, error: Exception) -> None:
        """Make every connection raise the given error on connect."""
        if isinstance(error, type):
            error = error()
        self._error = error
        self.raise_on_connect = True

    def __call__(self, _host: str, _port: int, _timeout: float = 30.0) -> FakeConnection:
        conn = FakeConnection(
            self.peer_der,
            responses=dict(self.responses),
            raise_on_connect=self.raise_on_connect,
        )
        self.connections.append(conn)
        return conn

    @property
    def requests(self) -> Iterable[tuple[str, str, bytes | None]]:
        for conn in self.connections:
            yield from conn.requests


@pytest.fixture
def transport(cert_pair):
    """Return a factory that creates ``FakeTransport`` instances."""
    _cert_pem, _key_pem, cert_der = cert_pair

    def factory():
        return FakeTransport(cert_der)

    return factory


@pytest.fixture
def requirer_cert(cert_pair):
    """Return a valid PEM certificate to stand in for a requirer's cert."""
    cert_pem, _key_pem, _cert_der = cert_pair
    return cert_pem + "\n"
