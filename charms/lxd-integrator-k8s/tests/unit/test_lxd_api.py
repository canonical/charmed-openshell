"""Unit tests for the http.client-based LXD API client."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import ssl
import tempfile
from unittest.mock import patch

import pytest

from lxd_api import LxdApiError, LxdClient, LxdConnectionError, VerificationError
from verification_mode import VerificationMode


class FakeResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body


class FakeSocket:
    def __init__(self, peer_der: bytes):
        self.peer_der = peer_der

    def getpeercert(self, binary_form: bool = False):
        if binary_form:
            return self.peer_der
        return {}


class FakeConnection:
    def __init__(
        self,
        peer_der: bytes,
        response_body: bytes = b"{}",
        status: int = 200,
        raise_on_connect: bool = False,
    ):
        self.peer_der = peer_der
        self.response_body = response_body
        self.status = status
        self.raise_on_connect = raise_on_connect
        self.requests: list[tuple[str, str, bytes | None, dict[str, str] | None]] = []
        self.connected = False
        self.closed = False
        self.sock = None

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
        self.requests.append((method, path, body, headers))

    def getresponse(self) -> FakeResponse:
        return FakeResponse(self.status, self.response_body)

    def close(self) -> None:
        self.closed = True


def test_client_construction():
    client = LxdClient(
        endpoints=(("localhost", 8443),),
        verification_mode=VerificationMode.FINGERPRINT,
        server_pin="aa:bb",
        client_cert="CERT",
        client_key="KEY",
    )
    assert client._endpoints == (("localhost", 8443),)


def test_default_factory_loads_cert_chain(cert_pair):
    cert_pem, key_pem, _ = cert_pair
    client = LxdClient(
        endpoints=(("localhost", 8443),),
        verification_mode=VerificationMode.FINGERPRINT,
        server_pin="aa",
        client_cert=cert_pem,
        client_key=key_pem,
    )

    captured_paths: list[str] = []
    original = tempfile.TemporaryDirectory
    cert_chain_calls: list[tuple[str, str | None]] = []
    original_load_cert_chain = ssl.SSLContext.load_cert_chain

    def patched_load_cert_chain(self, certfile, keyfile=None):
        cert_chain_calls.append((certfile, keyfile))
        original_load_cert_chain(self, certfile, keyfile)

    class PatchedTemporaryDirectory(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured_paths.append(self.name)

    with (
        patch("lxd_api.tempfile.TemporaryDirectory", PatchedTemporaryDirectory),
        patch("lxd_api.ssl.SSLContext.load_cert_chain", patched_load_cert_chain),
    ):
        conn = client._default_connection_factory("localhost", 8443)

    assert isinstance(conn, http.client.HTTPSConnection)
    assert len(captured_paths) == 1
    assert not os.path.exists(captured_paths[0])

    assert len(cert_chain_calls) == 1
    certfile, keyfile = cert_chain_calls[0]
    assert os.path.commonpath([certfile, captured_paths[0]]) == captured_paths[0]
    assert certfile.endswith("client.crt")
    assert keyfile is not None and keyfile.endswith("client.key")


def test_verification_match_and_mismatch(cert_pair):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()

    # Fingerprint match.
    conn_ok = FakeConnection(
        cert_der,
        json.dumps({"metadata": {"version": "1.0"}}).encode(),
    )
    client = LxdClient(
        endpoints=(("localhost", 8443),),
        verification_mode=VerificationMode.FINGERPRINT,
        server_pin=fingerprint,
        client_cert=cert_pem,
        client_key=key_pem,
        connection_factory=lambda _h, _p: conn_ok,
    )
    assert client.get_server_info() == {"version": "1.0"}
    assert conn_ok.requests

    # Fingerprint mismatch.
    conn_bad = FakeConnection(cert_der)
    client_bad = LxdClient(
        endpoints=(("localhost", 8443),),
        verification_mode=VerificationMode.FINGERPRINT,
        server_pin="00" * 32,
        client_cert=cert_pem,
        client_key=key_pem,
        connection_factory=lambda _h, _p: conn_bad,
    )
    with pytest.raises(VerificationError):
        client_bad.get_server_info()
    assert not conn_bad.requests
    assert conn_bad.closed

    # Certificate match.
    conn_cert_ok = FakeConnection(
        cert_der,
        json.dumps({"metadata": {"version": "1.0"}}).encode(),
    )
    client_cert = LxdClient(
        endpoints=(("localhost", 8443),),
        verification_mode=VerificationMode.CERTIFICATE,
        server_pin=cert_pem,
        client_cert=cert_pem,
        client_key=key_pem,
        connection_factory=lambda _h, _p: conn_cert_ok,
    )
    assert client_cert.get_server_info() == {"version": "1.0"}
    assert conn_cert_ok.requests

    # Certificate mismatch.
    conn_cert_bad = FakeConnection(b"\x00" * 64)
    client_cert_bad = LxdClient(
        endpoints=(("localhost", 8443),),
        verification_mode=VerificationMode.CERTIFICATE,
        server_pin=cert_pem,
        client_cert=cert_pem,
        client_key=key_pem,
        connection_factory=lambda _h, _p: conn_cert_bad,
    )
    with pytest.raises(VerificationError):
        client_cert_bad.get_server_info()
    assert not conn_cert_bad.requests
    assert conn_cert_bad.closed


def test_pem_pin_to_der(cert_pair):
    cert_pem, key_pem, cert_der = cert_pair
    conn = FakeConnection(cert_der, json.dumps({"metadata": {}}).encode())
    client = LxdClient(
        endpoints=(("localhost", 8443),),
        verification_mode=VerificationMode.CERTIFICATE,
        server_pin=cert_pem,
        client_cert=cert_pem,
        client_key=key_pem,
        connection_factory=lambda _h, _p: conn,
    )
    client.get_server_info()
    assert conn.requests


def test_endpoint_failover(cert_pair):
    cert_pem, key_pem, cert_der = cert_pair
    conn1 = FakeConnection(cert_der, raise_on_connect=True)
    conn2 = FakeConnection(cert_der, json.dumps({"metadata": {"ok": True}}).encode())
    connections = [conn1, conn2]

    client = LxdClient(
        endpoints=(("first", 8443), ("second", 8443)),
        verification_mode=VerificationMode.CERTIFICATE,
        server_pin=cert_pem,
        client_cert=cert_pem,
        client_key=key_pem,
        connection_factory=lambda _h, _p: connections.pop(0),
    )
    info = client.get_server_info()
    assert info == {"ok": True}
    assert conn1.closed
    assert conn2.requests


def test_response_parsing(cert_pair):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()

    def make_client(response_body: bytes, status: int = 200):
        conn = FakeConnection(cert_der, response_body, status=status)
        client = LxdClient(
            endpoints=(("localhost", 8443),),
            verification_mode=VerificationMode.FINGERPRINT,
            server_pin=fingerprint,
            client_cert=cert_pem,
            client_key=key_pem,
            connection_factory=lambda _h, _p: conn,
        )
        return client, conn

    client, conn = make_client(json.dumps({"metadata": {"version": "5.21"}}).encode())
    assert client.get_server_info() == {"version": "5.21"}

    client, conn = make_client(json.dumps({"metadata": [{"fingerprint": "fp1"}]}).encode())
    assert client.list_trusted_certificates() == [{"fingerprint": "fp1"}]

    client, conn = make_client(json.dumps({"metadata": {}}).encode(), status=409)
    client.add_trusted_certificate(cert_pem, "test")
    assert conn.requests
    assert conn.requests[0][0] == "POST"

    client, conn = make_client(json.dumps({"metadata": {}}).encode())
    client.remove_trusted_certificate("fp1")
    assert conn.requests
    assert conn.requests[0][0] == "DELETE"


def test_add_trusted_certificate_non_409_error(cert_pair):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    conn = FakeConnection(cert_der, b"conflict", status=400)
    client = LxdClient(
        endpoints=(("localhost", 8443),),
        verification_mode=VerificationMode.FINGERPRINT,
        server_pin=fingerprint,
        client_cert=cert_pem,
        client_key=key_pem,
        connection_factory=lambda _h, _p: conn,
    )
    with pytest.raises(LxdApiError) as exc_info:
        client.add_trusted_certificate(cert_pem, "test")
    assert exc_info.value.status == 400


def test_all_endpoints_exhausted(cert_pair):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    conn = FakeConnection(cert_der, raise_on_connect=True)
    client = LxdClient(
        endpoints=(("first", 8443), ("second", 8443)),
        verification_mode=VerificationMode.FINGERPRINT,
        server_pin=fingerprint,
        client_cert=cert_pem,
        client_key=key_pem,
        connection_factory=lambda _h, _p: conn,
    )
    with pytest.raises(LxdConnectionError):
        client.get_server_info()
