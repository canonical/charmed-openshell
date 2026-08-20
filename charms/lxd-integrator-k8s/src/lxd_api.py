"""Minimal LXD REST client over ``http.client``.

No ``ops`` imports. Server identity is verified manually after the TLS handshake
and before any request bytes are written. There is no unverified mode.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import ssl
import tempfile
from collections.abc import Callable
from typing import Any, cast

from verification_mode import VerificationMode


class VerificationError(Exception):
    """Raised when the LXD server's TLS identity does not match the configured pin."""


class LxdApiError(Exception):
    """Raised when the LXD API returns a non-2xx response."""

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"LXD API returned {status}: {body}")


class LxdConnectionError(Exception):
    """Raised when every configured endpoint fails."""


ConnectionFactory = Callable[[str, int], http.client.HTTPSConnection]


def pem_fingerprint(cert_pem: str) -> str:
    """Return the lowercase SHA-256 hex digest of a PEM certificate's DER form.

    This matches the ``fingerprint`` field LXD stores in trust entries.
    """
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert_pem)).hexdigest()


class LxdClient:
    """Stateful LXD API client with connection-per-call semantics.

    Constructed from primitive values produced by
    ``IntegratorConfig.to_connection_params``. The optional
    ``connection_factory`` is the seam used by unit tests to inject fake
    transports.
    """

    def __init__(
        self,
        endpoints: tuple[tuple[str, int], ...],
        verification_mode: VerificationMode,
        server_pin: str,
        client_cert: str,
        client_key: str,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self._endpoints = endpoints
        self._verification_mode = verification_mode
        self._server_pin = server_pin
        self._client_cert = client_cert
        self._client_key = client_key
        self._connection_factory: ConnectionFactory = (
            connection_factory or self._default_connection_factory
        )

    def _default_connection_factory(self, host: str, port: int) -> http.client.HTTPSConnection:
        """Build a real HTTPS connection with mTLS and no host/chain verification."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "client.crt")
            key_path = os.path.join(tmpdir, "client.key")
            for path, data in ((cert_path, self._client_cert), (key_path, self._client_key)):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as file:
                    file.write(data)
            context.load_cert_chain(cert_path, key_path)

        return http.client.HTTPSConnection(host, port, context=context)

    def _verify(self, conn: http.client.HTTPSConnection) -> None:
        """Verify the server identity after the handshake and before any request.

        The peer certificate in DER form is compared against the configured pin:
        SHA-256 hex digest for fingerprint mode, DER equality for certificate
        mode. On mismatch the connection is torn down by the caller.
        """
        if conn.sock is None:
            raise VerificationError("connection has no socket")

        sock = cast(ssl.SSLSocket, conn.sock)
        der = sock.getpeercert(binary_form=True)
        if der is None:
            raise VerificationError("server did not present a certificate")

        if self._verification_mode == VerificationMode.FINGERPRINT:
            actual = hashlib.sha256(der).hexdigest()
            expected = self._server_pin.lower()
            if actual != expected:
                raise VerificationError(f"fingerprint mismatch: expected {expected}, got {actual}")
        else:
            expected_der = ssl.PEM_cert_to_DER_cert(self._server_pin)
            if der != expected_der:
                raise VerificationError("server certificate does not match pinned certificate")

    def _request(self, method: str, path: str, body: str | bytes | None = None) -> Any:
        """Issue a JSON request, walking endpoints in order.

        Returns the full decoded JSON body. Verification runs before any request
        bytes are written. On connect or other transport failure the client
        advances to the next endpoint; verification failures are raised
        immediately.
        """
        last_error: Exception | None = None
        for host, port in self._endpoints:
            conn: http.client.HTTPSConnection | None = None
            try:
                conn = self._connection_factory(host, port)
                conn.connect()
                self._verify(conn)
                headers = {"Content-Type": "application/json"}
                encoded_body = body.encode("utf-8") if isinstance(body, str) else body
                conn.request(method, path, body=encoded_body, headers=headers)
                response = conn.getresponse()
                response_body = response.read()
                if response.status >= 400:
                    raise LxdApiError(
                        response.status, response_body.decode("utf-8", errors="replace")
                    )
                return json.loads(response_body)
            except (VerificationError, LxdApiError):
                raise
            except (OSError, http.client.HTTPException) as exc:
                last_error = exc
                continue
            finally:
                if conn is not None:
                    conn.close()

        raise LxdConnectionError(f"all endpoints exhausted: {last_error}")

    def get_server_info(self) -> dict:
        """Return the ``metadata`` object from ``GET /1.0``."""
        response = self._request("GET", "/1.0")
        metadata = response.get("metadata", {})
        if not isinstance(metadata, dict):
            return {}
        return metadata

    def get_current_identity(self) -> dict:
        """Return the ``metadata`` object from ``GET /1.0/auth/identities/current``."""
        response = self._request("GET", "/1.0/auth/identities/current")
        metadata = response.get("metadata", {})
        if not isinstance(metadata, dict):
            return {}
        return metadata

    def list_trusted_certificates(self) -> list[dict]:
        """Return the trust list from ``GET /1.0/certificates``.

        LXD returns a list of certificate URLs by default; use recursion so the
        response contains the certificate objects (dicts) the caller expects.
        """
        response = self._request("GET", "/1.0/certificates?recursion=1")
        metadata = response.get("metadata", [])
        if not isinstance(metadata, list):
            return []
        return metadata

    def add_trusted_certificate(
        self,
        cert_pem: str,
        name: str,
        projects: list[str] | None = None,
        trust_token: str | None = None,
    ) -> None:
        """Add ``cert_pem`` to LXD's trust store via ``POST /1.0/certificates``.

        The LXD API expects the certificate as base64-encoded DER, not PEM.
        HTTP 409 (already trusted) is treated as idempotent success.
        """
        der = ssl.PEM_cert_to_DER_cert(cert_pem)
        data: dict[str, Any] = {
            "type": "client",
            "certificate": base64.b64encode(der).decode("ascii"),
            "name": name,
        }
        if projects is not None:
            data["projects"] = projects
            if projects:
                data["restricted"] = True
        if trust_token is not None:
            data["trust_token"] = trust_token

        try:
            self._request("POST", "/1.0/certificates", body=json.dumps(data))
        except LxdApiError as exc:
            if exc.status == 409:
                return
            raise

    def remove_trusted_certificate(self, fingerprint: str) -> None:
        """Remove a trusted certificate via ``DELETE /1.0/certificates/<fp>``."""
        self._request("DELETE", f"/1.0/certificates/{fingerprint}")
