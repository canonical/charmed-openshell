"""Tests for lxd_join: decoding trust tokens and redeeming them against a fake LXD."""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.server
import json
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

import lxd_join
from lxd_join import JoinError, TokenError, decode_token, join


def _keypair(common_name: str) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA384())
    )
    return (
        cert.public_bytes(Encoding.PEM).decode(),
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(),
    )


def _fingerprint(cert_pem: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return cert.fingerprint(hashes.SHA256()).hex()


def _token(
    addresses: list[str],
    fingerprint: str,
    *,
    secret: str = "joinsecret",
    type_: str = "Client certificate",
    **extra: object,
) -> str:
    body = {
        "client_name": "openshell-gateway",
        "fingerprint": fingerprint,
        "addresses": addresses,
        "secret": secret,
        "expires_at": "2026-10-13T20:35:45Z",
        "type": type_,
        **extra,
    }
    return base64.b64encode(json.dumps(body).encode()).decode()


class TestDecodeToken:
    def test_a_pending_identity_token_decodes(self):
        raw = _token(["10.0.0.1:8443", "[fd42::1]:8443"], "AB:" * 31 + "AB")
        token = decode_token(raw + "\n")
        assert token.addresses == ("10.0.0.1:8443", "[fd42::1]:8443")
        assert token.fingerprint == "ab" * 32
        assert token.client_name == "openshell-gateway"
        assert token.raw == raw
        assert token.digest == hashlib.sha256(raw.encode()).hexdigest()

    def test_the_secret_stays_out_of_the_repr(self):
        token = decode_token(_token(["10.0.0.1:8443"], "a" * 64, secret="hunter2"))
        assert "hunter2" not in repr(token)
        assert token.raw not in repr(token)

    def test_addresses_the_command_line_cannot_carry_are_dropped(self):
        token = decode_token(_token(["10.0.0.1:8443 --evil", "10.0.0.2:8443"], "a" * 64))
        assert token.addresses == ("10.0.0.2:8443",)

    @pytest.mark.parametrize(
        ("raw", "message"),
        [
            ("not a token", "not base64-encoded JSON"),
            (base64.b64encode(b"[1, 2]").decode(), "not base64-encoded JSON"),
            # What `lxc config trust add` prints: no type, no group to put it in.
            (_token(["10.0.0.1:8443"], "a" * 64, type_=""), "not a TLS identity token"),
            (_token(["10.0.0.1:8443"], "not-hex"), "no usable server fingerprint"),
            (_token([], "a" * 64), "no usable server address"),
            (_token(["$(x):8443"], "a" * 64), "no usable server address"),
            (_token(["10.0.0.1:8443"], "a" * 64, secret=""), "no join secret"),
        ],
    )
    def test_unusable_tokens_are_refused(self, raw, message):
        with pytest.raises(TokenError, match=message):
            decode_token(raw)


@dataclass
class _FakeLxd:
    """A minimal stand-in for the two LXD endpoints a join uses."""

    address: str
    fingerprint: str
    pending_secret: str
    # Trusted client fingerprints, mapped to (identity name, fine-grained).
    trusted: dict[str, tuple[str, bool]] = field(default_factory=dict)
    posts: list[dict] = field(default_factory=list)
    refusal: str = "No pending identities found with given secret"


@pytest.fixture
def client() -> tuple[str, str]:
    return _keypair("openshell-gateway")


@pytest.fixture
def fake_lxd(tmp_path: Path, client: tuple[str, str]) -> Iterator[_FakeLxd]:
    cert_pem, key_pem = _keypair("lxd")
    (tmp_path / "server.crt").write_text(cert_pem)
    (tmp_path / "server.key").write_text(key_pem)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / "server.crt", tmp_path / "server.key")
    # LXD asks for a client certificate and accepts any self-signed one, then
    # decides trust itself. OpenSSL verifies what it is shown, so the fake has
    # to know the test client's certificate up front.
    context.verify_mode = ssl.CERT_OPTIONAL
    context.load_verify_locations(cadata=client[0])

    state: _FakeLxd

    class Handler(http.server.BaseHTTPRequestHandler):
        def _client(self) -> str:
            der = self.connection.getpeercert(binary_form=True)  # pyright: ignore[reportAttributeAccessIssue]
            return hashlib.sha256(der).hexdigest() if der else ""

        def _reply(self, status: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            client = self._client()
            if self.path == "/1.0/auth/identities/current":
                name, fine_grained = state.trusted[client]
                self._reply(
                    200,
                    {"type": "sync", "metadata": {"name": name, "fine_grained": fine_grained}},
                )
                return
            auth = "trusted" if client in state.trusted else "untrusted"
            self._reply(200, {"type": "sync", "metadata": {"auth": auth}})

        def do_POST(self) -> None:  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state.posts.append(body)
            client = self._client()
            if client in state.trusted:
                self._reply(403, {"type": "error", "error": "Forbidden", "error_code": 403})
                return
            secret = json.loads(base64.b64decode(body["trust_token"]))["secret"]
            if not client or secret != state.pending_secret:
                self._reply(
                    500,
                    {
                        "type": "error",
                        "error": state.refusal,
                        "error_code": 500,
                    },
                )
                return
            state.pending_secret = ""
            state.trusted[client] = ("openshell-gateway", True)
            self._reply(200, {"type": "sync", "metadata": {}})

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    state = _FakeLxd(
        address=f"127.0.0.1:{server.server_address[1]}",
        fingerprint=_fingerprint(cert_pem),
        pending_secret="joinsecret",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


def _closed_port_address() -> str:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{s.getsockname()[1]}"


class TestJoin:
    def test_the_token_is_redeemed_and_the_certificate_trusted(self, fake_lxd, client):
        token = decode_token(_token([fake_lxd.address], fake_lxd.fingerprint))
        assert join(token, *client) == fake_lxd.address
        assert set(fake_lxd.trusted) == {_fingerprint(client[0])}
        assert fake_lxd.posts == [{"trust_token": token.raw}]

    def test_unreachable_addresses_are_skipped(self, fake_lxd, client):
        dead = _closed_port_address()
        token = decode_token(_token([dead, fake_lxd.address], fake_lxd.fingerprint))
        assert join(token, *client, timeout=2) == fake_lxd.address

    def test_a_trusted_certificate_does_not_redeem_again(self, fake_lxd, client):
        fake_lxd.trusted[_fingerprint(client[0])] = ("openshell-gateway", True)
        token = decode_token(_token([fake_lxd.address], fake_lxd.fingerprint))
        assert join(token, *client) == fake_lxd.address
        assert fake_lxd.posts == []

    @pytest.mark.parametrize(
        "identity", [("openshell-gateway", False), ("someone-else", True)], ids=["legacy", "other"]
    )
    def test_trust_that_is_not_the_tokens_identity_is_refused(self, fake_lxd, client, identity):
        # A leftover `lxc config trust add` entry would otherwise count as
        # joined, with whatever that entry grants instead of the group.
        fake_lxd.trusted[_fingerprint(client[0])] = identity
        token = decode_token(_token([fake_lxd.address], fake_lxd.fingerprint))
        with pytest.raises(JoinError, match="already trusts this certificate"):
            join(token, *client)
        assert fake_lxd.posts == []

    def test_lxds_error_text_is_capped(self, fake_lxd, client):
        fake_lxd.refusal = "x" * 5000
        token = decode_token(_token([fake_lxd.address], fake_lxd.fingerprint, secret="spent"))
        with pytest.raises(JoinError) as raised:
            join(token, *client)
        assert len(str(raised.value)) < 300

    def test_a_server_that_never_answers_cannot_hold_the_hook(self, fake_lxd, client):
        # A listener that never completes the handshake stands in for a
        # blackholed address; the deadline covers every address together.
        with socket.socket() as silent:
            silent.bind(("127.0.0.1", 0))
            silent.listen()
            address = f"127.0.0.1:{silent.getsockname()[1]}"
            token = decode_token(_token([address, fake_lxd.address], fake_lxd.fingerprint))
            started = time.monotonic()
            with pytest.raises(JoinError, match="not tried, out of time"):
                join(token, *client, timeout=10, deadline=1)
        assert time.monotonic() - started < 5

    def test_a_spent_token_is_refused_with_lxds_reason(self, fake_lxd, client):
        token = decode_token(_token([fake_lxd.address], fake_lxd.fingerprint, secret="spent"))
        with pytest.raises(JoinError, match="LXD refused the token: No pending identities"):
            join(token, *client)

    def test_the_token_never_reaches_a_server_with_another_certificate(self, fake_lxd, client):
        token = decode_token(_token([fake_lxd.address], "0" * 64))
        with pytest.raises(JoinError, match="server certificate does not match the token"):
            join(token, *client)
        assert fake_lxd.posts == []

    def test_no_reachable_address_says_what_was_tried(self, client):
        dead = _closed_port_address()
        token = decode_token(_token([dead], "0" * 64))
        with pytest.raises(JoinError, match=f"cannot reach LXD: {dead}"):
            join(token, *client, timeout=2)


def test_the_module_does_not_import_ops():
    import inspect

    assert "import ops" not in inspect.getsource(lxd_join)
