"""Join an LXD server with the trust token of a pending TLS identity.

An LXD administrator creates the identity, in a group that grants access to
the sandbox project only, with ``lxc auth identity create tls/<name> --group
<group>``. That prints a single-use token carrying the server's addresses, its
certificate fingerprint and a join secret. Redeeming the token binds the
identity to whichever client certificate presents it.

Kept free of ``ops`` imports so it can be tested without Juju.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import os
import ssl
import tempfile
from dataclasses import dataclass, field

from config_model import _parse_lxd_address, _parse_lxd_fingerprint

# What LXD puts in ``type`` for a pending TLS identity. The tokens
# ``lxc config trust add`` prints leave it empty and are redeemed through a
# different endpoint that has no notion of groups, so they are refused.
IDENTITY_TOKEN_TYPE = "Client certificate"

DEFAULT_TIMEOUT_SECS = 10.0


class TokenError(ValueError):
    """The value is not a usable LXD identity trust token."""


class JoinError(Exception):
    """LXD could not be reached or refused the token."""


@dataclass(frozen=True)
class TrustToken:
    """A decoded LXD identity trust token."""

    raw: str = field(repr=False)
    client_name: str
    fingerprint: str
    addresses: tuple[str, ...]
    expires_at: str

    @property
    def digest(self) -> str:
        """Return a SHA-256 of the token, safe to record where the token is not."""
        return hashlib.sha256(self.raw.encode()).hexdigest()


def decode_token(raw: str) -> TrustToken:
    """Decode and validate an LXD identity trust token."""
    value = raw.strip()
    try:
        decoded = json.loads(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError) as e:
        raise TokenError("token is not base64-encoded JSON") from e
    if not isinstance(decoded, dict):
        raise TokenError("token is not base64-encoded JSON")

    if decoded.get("type") != IDENTITY_TOKEN_TYPE:
        raise TokenError(
            "token is not a TLS identity token; create one with lxc auth identity create"
        )

    fingerprint = _parse_lxd_fingerprint(str(decoded.get("fingerprint", "")))
    if fingerprint is None:
        raise TokenError("token carries no usable server fingerprint")

    raw_addresses = decoded.get("addresses")
    if not isinstance(raw_addresses, list):
        raise TokenError("token carries no server addresses")
    # Addresses end up on the driver's command line, so anything the sanitiser
    # rejects is dropped rather than passed on.
    addresses = tuple(
        a for a in (_parse_lxd_address(str(r)) for r in raw_addresses) if a is not None
    )
    if not addresses:
        raise TokenError("token carries no usable server address")

    if not decoded.get("secret"):
        raise TokenError("token carries no join secret")

    return TrustToken(
        raw=value,
        client_name=str(decoded.get("client_name", "")),
        fingerprint=fingerprint,
        addresses=addresses,
        expires_at=str(decoded.get("expires_at", "")),
    )


class _FingerprintMismatchError(Exception):
    pass


def _request(
    address: str,
    method: str,
    path: str,
    context: ssl.SSLContext,
    fingerprint: str,
    timeout: float,
    body: dict | None = None,
) -> tuple[int, dict]:
    """Send one request to LXD after checking the server's certificate fingerprint.

    LXD's certificate is self-signed and names only its hostname and loopback
    addresses, so it is pinned by fingerprint, as ``lxc remote add`` does. The
    check happens before the request is written: the body may carry the
    token's secret.
    """
    conn = http.client.HTTPSConnection(address, context=context, timeout=timeout)
    try:
        conn.connect()
        assert conn.sock is not None
        peer = conn.sock.getpeercert(binary_form=True)  # pyright: ignore[reportAttributeAccessIssue]
        if not peer or hashlib.sha256(peer).hexdigest() != fingerprint:
            raise _FingerprintMismatchError(address)
        payload = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            data = {}
        return response.status, data if isinstance(data, dict) else {}
    finally:
        conn.close()


def join(
    token: TrustToken,
    certificate_pem: str,
    private_key_pem: str,
    timeout: float = DEFAULT_TIMEOUT_SECS,
) -> str:
    """Make LXD trust *certificate_pem* and return the address it answered on.

    Tries the token's addresses in order; a server lists every address it
    listens on, and not all of them are reachable from here. A certificate
    LXD already trusts is not redeemed again: LXD answers a trusted client's
    redemption with 403, and the token is then left for the administrator to
    revoke.

    Raises ``JoinError`` when no address answers or LXD refuses the token.
    """
    with tempfile.TemporaryDirectory() as tmp:
        cert_path = os.path.join(tmp, "client.crt")
        key_path = os.path.join(tmp, "client.key")
        with open(cert_path, "w") as f:
            f.write(certificate_pem)
        with open(os.open(key_path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(private_key_pem)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(cert_path, key_path)

        failures: list[str] = []
        for address in token.addresses:
            try:
                _, server = _request(address, "GET", "/1.0", context, token.fingerprint, timeout)
                if (server.get("metadata") or {}).get("auth") == "trusted":
                    return address
                status, result = _request(
                    address,
                    "POST",
                    "/1.0/auth/identities/tls",
                    context,
                    token.fingerprint,
                    timeout,
                    {"trust_token": token.raw},
                )
            except _FingerprintMismatchError:
                failures.append(f"{address}: server certificate does not match the token")
                continue
            except (OSError, http.client.HTTPException) as e:
                failures.append(f"{address}: {e}")
                continue

            if 200 <= status < 300:
                return address
            # The server answered and refused: every address is the same
            # server, so asking again elsewhere gets the same answer.
            error = result.get("error") or f"HTTP {status}"
            raise JoinError(f"LXD refused the token: {error}")

    raise JoinError("cannot reach LXD: " + "; ".join(failures))
