"""Pure configuration model for the LXD Integrator charm.

No ``ops``, ``ssl``, or ``http.client`` imports — this module is testable with
plain pytest and zero Juju or TLS dependencies.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pydantic
from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from verification_mode import VerificationMode

DEFAULT_LXD_PORT: int = 8443


@dataclass(frozen=True)
class LxdConnectionParams:
    """Primitives passed to ``lxd_api.LxdClient``.

    ``server_pin`` is the lowercase hex fingerprint for fingerprint mode, or the
    PEM-encoded server certificate for certificate mode. ``LxdClient`` converts
    the PEM certificate to DER before comparing it to the peer certificate.
    """

    endpoints: tuple[tuple[str, int], ...]
    verification_mode: VerificationMode
    server_pin: str
    client_cert: str
    client_key: str


class IntegratorConfig(pydantic.BaseModel):
    """Validated, typed representation of the integrator charm's config surface.

    Build directly from ``dict(self.config)`` merged with resolved secret content
    in the charm; the kebab-case aliases match Juju's config key names.
    """

    model_config = ConfigDict(frozen=True, extra="ignore", populate_by_name=True)

    lxd_endpoints: str = Field(alias="lxd-endpoints")
    lxd_server_fingerprint: str | None = Field(default=None, alias="lxd-server-fingerprint")
    default_projects: str | None = Field(default=None, alias="default-projects")
    trust_name_prefix: str = Field(default="juju-relation", alias="trust-name-prefix")

    # Resolved from the lxd-credentials secret.
    client_cert: str | None = Field(default=None, alias="client-cert")
    client_key: str | None = Field(default=None, alias="client-key")
    server_cert: str | None = Field(default=None, alias="server-cert")
    trust_token: str | None = Field(default=None, alias="trust-token")

    @field_validator(
        "lxd_server_fingerprint",
        "default_projects",
        "client_cert",
        "client_key",
        "server_cert",
        "trust_token",
        mode="before",
    )
    @classmethod
    def _empty_string_to_none(cls, v: Any) -> Any:
        """Normalise Juju's empty-string representation of 'unset' to None."""
        if v == "":
            return None
        return v

    @field_validator("lxd_endpoints", mode="after")
    @classmethod
    def _endpoints_valid(cls, v: str) -> str:
        """Validate that the endpoint list is parseable.

        The parsed tuple is exposed by the ``endpoints`` property. Validating here
        ensures malformed endpoints surface through ``load_config`` as a clean,
        prefix-free error message.
        """
        parse_endpoints(v)
        return v

    @model_validator(mode="after")
    def _credentials_complete(self) -> IntegratorConfig:
        """Enforce credential completeness and an unambiguous server pin.

        Raises ``PydanticCustomError`` so ``load_config`` can return a clean,
        prefix-free message.
        """
        client_cert = self.client_cert
        client_key = self.client_key
        fingerprint = self.lxd_server_fingerprint
        server_cert = self.server_cert

        if (client_cert is None) != (client_key is None):
            raise PydanticCustomError(
                "client_cert_key_required_together",
                "client-cert and client-key must be set together",
            )

        if fingerprint is None and server_cert is None:
            raise PydanticCustomError(
                "server_pin_required",
                "exactly one of server-cert or lxd-server-fingerprint must be set",
            )

        if fingerprint is not None and server_cert is not None:
            raise PydanticCustomError(
                "server_pin_ambiguous",
                "only one of server-cert or lxd-server-fingerprint may be set",
            )

        return self

    @property
    def endpoints(self) -> tuple[tuple[str, int], ...]:
        """Preference-ordered endpoint list parsed from ``lxd-endpoints``."""
        return parse_endpoints(self.lxd_endpoints)

    @property
    def verification_mode(self) -> VerificationMode:
        """Derive the verification mode from the configured server pin."""
        if self.lxd_server_fingerprint is not None:
            return VerificationMode.FINGERPRINT
        return VerificationMode.CERTIFICATE

    def to_connection_params(self) -> LxdConnectionParams:
        """Return the primitives needed by ``lxd_api.LxdClient``."""
        if self.verification_mode == VerificationMode.FINGERPRINT:
            assert self.lxd_server_fingerprint is not None
            server_pin = self.lxd_server_fingerprint.lower()
        else:
            assert self.server_cert is not None
            server_pin = self.server_cert

        assert self.client_cert is not None
        assert self.client_key is not None

        return LxdConnectionParams(
            endpoints=self.endpoints,
            verification_mode=self.verification_mode,
            server_pin=server_pin,
            client_cert=self.client_cert,
            client_key=self.client_key,
        )


def parse_endpoints(raw: str) -> tuple[tuple[str, int], ...]:
    """Parse a comma-separated ``host:port`` list.

    IPv6 literals must be bracketed (``[::1]:8443``). The default LXD HTTPS port
    ``8443`` is applied when a port is omitted. Most-preferred endpoint first.
    """
    result: list[tuple[str, int]] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        host, port = _parse_endpoint(part)
        result.append((host, port))
    return tuple(result)


def _parse_endpoint(raw: str) -> tuple[str, int]:
    if raw.startswith("["):
        match = re.fullmatch(r"\[(?P<host>[^\]]+)\](?::(?P<port>\d+))?", raw)
        if not match:
            raise PydanticCustomError(
                "invalid_endpoint",
                "invalid endpoint: {raw}",
                {"raw": raw},
            )
        host = match.group("host")
        port_str = match.group("port")
    else:
        if ":" in raw:
            host, port_str = raw.rsplit(":", 1)
        else:
            host = raw
            port_str = None

        if not host:
            raise PydanticCustomError(
                "invalid_endpoint",
                "invalid endpoint: {raw}",
                {"raw": raw},
            )

    if port_str is None:
        port = DEFAULT_LXD_PORT
    else:
        try:
            port = int(port_str)
        except ValueError:
            raise PydanticCustomError(
                "invalid_endpoint_port",
                "invalid port in endpoint: {raw}",
                {"raw": raw},
            ) from None

    return host, port


def load_config(raw: Mapping[str, Any]) -> tuple[IntegratorConfig | None, str | None]:
    """Parse and validate charm config, returning (model, None) or (None, message).

    This is the single place ``pydantic.ValidationError`` is caught. All custom
    validators raise ``PydanticCustomError`` so the returned message is clean and
    prefix-free.
    """
    try:
        model = IntegratorConfig.model_validate(dict(raw))
        return model, None
    except pydantic.ValidationError as exc:
        messages = [e["msg"] for e in exc.errors()]
        return None, "; ".join(messages)
