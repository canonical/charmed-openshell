"""Pure configuration model for the OpenShell Gateway charm.

No ``ops`` imports — this module is testable with plain pytest and zero Juju.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pydantic
from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

# ---------------------------------------------------------------------------
# Fixed constants emitted by render_env
# ---------------------------------------------------------------------------

# BIND_ADDRESS is deliberately 0.0.0.0 — intentional sidecar workload posture.
# The gateway runs inside a Kubernetes pod; access is governed at the
# Kubernetes layer (NetworkPolicy / service exposure), not by the process's
# listen address.  Binding to all interfaces is correct and required for the
# container networking model.  No charm config option will ever be introduced
# to restrict the bind address — this constant is fixed and non-configurable
# by design (parallel to the no-disable-tls / no-allow-unauthenticated-users
# posture).
BIND_ADDRESS: str = "0.0.0.0"  # noqa: S104 — intentional; see comment above

GATEWAY_PORT: str = "8443"  # TLS-only listen port

# Default port for the workload's Prometheus endpoint. The gateway defaults
# it to 0 (disabled); this charm turns it on because an operator who relates
# a collector expects metrics, and a port nothing scrapes costs nothing.
# The listener is plain HTTP and unauthenticated, so it is deliberately never
# routed through ingress; see the metrics-port description in charmcraft.yaml
# and the observability section of the README.
DEFAULT_METRICS_PORT: int = 9090
METRICS_DISABLED: int = 0

# Image every sandbox is created from unless the request names another.
# openshell-driver-lxd resolves --default-image as an OCI reference and
# pulls it, so a bare LXD image alias (what this used to default to) fails
# on the first create. This mirrors the driver's own default.
DEFAULT_SANDBOX_IMAGE: str = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"

# Image the driver extracts the sandbox boundary binary from. Despite the
# driver's flag being --supervisor-image, what it pulls out is
# /openshell-sandbox. It must come from the same OpenShell release as the
# gateway: a mismatched pair fails to sync policy and the supervisor exits,
# which is why this is configurable rather than pinned to a floating tag.
DEFAULT_SUPERVISOR_IMAGE: str = "ghcr.io/nvidia/openshell/supervisor:latest"
DRIVERS: str = "lxd"
# Socket the driver gRPC server listens on (gateway connects here).
DRIVER_SOCKET: str = "/var/run/openshell/lxd.sock"

# ---------------------------------------------------------------------------
# Filesystem path constants (container layout)
# ---------------------------------------------------------------------------

CONFIG_PATH: str = "/etc/openshell/config.toml"
JWT_DIR: str = "/etc/openshell/jwt"
TLS_DIR: str = "/etc/openshell/tls"
LXD_DIR: str = "/etc/openshell/lxd"
LXD_CLIENT_CERT_PATH: str = f"{LXD_DIR}/client.crt"
LXD_CLIENT_KEY_PATH: str = f"{LXD_DIR}/client.key"
LXD_SERVER_CA_PATH: str = f"{LXD_DIR}/server.crt"

# The image's own CA bundle, and the charm's pristine copy of it.
# The charm adds its CA to the system bundle so the workload trusts the
# issuer whichever way it resolves roots, and keeps the untouched original
# beside it so that rewrite is idempotent rather than cumulative.
SYSTEM_CA_BUNDLE_PATH: str = "/etc/ssl/certs/ca-certificates.crt"
PRISTINE_CA_BUNDLE_PATH: str = f"{TLS_DIR}/system-ca.crt"

# Material every sandbox receives so its supervisor can reach the gateway
# over TLS.  The CA is the gateway's own issuer, so a sandbox verifies the
# certificate the gateway presents; the client certificate is a dedicated
# identity that is deliberately *not* the LXD client identity, which is an
# administrative credential and must never be copied into a sandbox.
SANDBOX_TLS_DIR: str = "/etc/openshell/sandbox-tls"
SANDBOX_TLS_CA_PATH: str = f"{SANDBOX_TLS_DIR}/ca.crt"
SANDBOX_TLS_CERT_PATH: str = f"{SANDBOX_TLS_DIR}/client.crt"
SANDBOX_TLS_KEY_PATH: str = f"{SANDBOX_TLS_DIR}/client.key"

# skopeo, which the driver shells out to for every image pull, reads its
# registry policy from this path.
REGISTRIES_CONF_PATH: str = "/etc/containers/registries.conf"

# Stable workload identity embedded in every minted JWT.  Must match the
# openshell-server binary's expected default; cross-reference when
# crates/openshell-server lands its config parser (FD-004).
GATEWAY_ID: str = "openshell-gateway"

# Default minted-token lifetime for shared Kubernetes deployments.
JWT_TTL_SECS: int = 3600

# Path to the key-id file delivered alongside the JWT signing/public key
# material.  The charm writes the kid here and the renderer emits the path.
JWT_KID_PATH: str = f"{JWT_DIR}/kid"


# ---------------------------------------------------------------------------
# Pydantic v2 config model
# ---------------------------------------------------------------------------


class GatewayConfig(pydantic.BaseModel):
    """Validated, typed representation of the charm's config surface.

    Build directly from ``dict(self.config)`` in the charm; the kebab-case
    aliases match Juju's config key names.
    """

    model_config = ConfigDict(frozen=True, extra="ignore", populate_by_name=True)

    external_hostname: str | None = Field(default=None, alias="external-hostname")
    oidc_audience: str = Field(default="openshell-cli", alias="oidc-audience")
    oidc_roles_claim: str = Field(default="groups", alias="oidc-roles-claim")
    oidc_admin_role: str | None = Field(default=None, alias="oidc-admin-role")
    oidc_user_role: str | None = Field(default=None, alias="oidc-user-role")
    log_level: Literal["debug", "info", "warn", "error"] = Field(default="info", alias="log-level")
    gateway_id: str = Field(default=GATEWAY_ID, alias="gateway-id", min_length=1)
    jwt_ttl_secs: int = Field(default=JWT_TTL_SECS, alias="jwt-ttl-secs", gt=0)
    metrics_port: int = Field(default=DEFAULT_METRICS_PORT, alias="metrics-port")
    lxd_sandbox_image: str = Field(default=DEFAULT_SANDBOX_IMAGE, alias="lxd-sandbox-image")
    supervisor_image: str = Field(default=DEFAULT_SUPERVISOR_IMAGE, alias="supervisor-image")
    insecure_registries: str | None = Field(default=None, alias="insecure-registries")
    lxd_operation_timeout_secs: int = Field(default=60, alias="lxd-operation-timeout-secs", gt=0)

    # ------------------------------------------------------------------
    # Field validators
    # ------------------------------------------------------------------

    @field_validator(
        "external_hostname",
        "oidc_admin_role",
        "oidc_user_role",
        "insecure_registries",
        mode="before",
    )
    @classmethod
    def _empty_string_to_none(cls, v: Any) -> Any:
        """Normalise Juju's empty-string representation of 'unset' to None.

        Only applied to optional string fields; the non-optional fields are
        deliberately excluded so an empty string there yields a meaningful
        type/Literal validation error.
        """
        if v == "":
            return None
        return v

    @field_validator(
        "external_hostname",
        "oidc_audience",
        "oidc_roles_claim",
        "oidc_admin_role",
        "oidc_user_role",
        "gateway_id",
        "lxd_sandbox_image",
        "supervisor_image",
        "insecure_registries",
        mode="after",
    )
    @classmethod
    def _no_control_chars(cls, v: str | None) -> str | None:
        """Reject C0 control characters and DEL (0x7F) in string config values.

        Guards the FD-002/FD-003 boundary: no downstream consumer (Pebble
        layer writer, env-file emitter) can receive a value with embedded
        control characters that could corrupt a spec or inject a newline.
        Runs *after* the empty-string normaliser so None values are safe.
        """
        if v is None:
            return v
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
            raise PydanticCustomError(
                "control_characters",
                "config value must not contain C0 control characters or DEL",
            )
        return v

    @field_validator("metrics_port", mode="after")
    @classmethod
    def _metrics_port_usable(cls, v: int) -> int:
        """Reject a metrics port the workload would refuse or that clashes.

        ``0`` disables the listener, which the workload supports. Anything else
        must be a real port, must not collide with the gateway's own TLS
        listener, and must be unprivileged: the workload runs as a non-root
        user and cannot bind below 1024.
        """
        if v == METRICS_DISABLED:
            return v
        if not 1024 <= v <= 65535:
            raise PydanticCustomError(
                "metrics_port_range",
                "metrics-port must be 0 (disabled) or between 1024 and 65535",
            )
        if v == int(GATEWAY_PORT):
            raise PydanticCustomError(
                "metrics_port_conflict",
                "metrics-port must differ from the gateway port ({port})",
                {"port": GATEWAY_PORT},
            )
        return v

    # ------------------------------------------------------------------
    # Cross-field (model-level) validator — RBAC required by default
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def _rbac_roles_required(self) -> GatewayConfig:
        """Enforce that both OIDC role fields are set together.

        Raises ``PydanticCustomError`` (not a bare ``ValueError``) so that
        Pydantic v2's automatic "Value error, " prefix is suppressed and
        ``exc.errors()[0]["msg"]`` returns the exact operator-facing string.
        """
        admin = self.oidc_admin_role
        user = self.oidc_user_role

        if admin is None and user is None:
            raise PydanticCustomError(
                "rbac_roles_required",
                "both oidc-admin-role and oidc-user-role must be set (RBAC required)",
            )

        if admin is None or user is None:
            set_key = "oidc-admin-role" if admin is not None else "oidc-user-role"
            raise PydanticCustomError(
                "rbac_roles_must_be_set_together",
                f"oidc-admin-role and oidc-user-role must be set together; got only {set_key}",
            )

        return self


# ---------------------------------------------------------------------------
# URI helpers — pure, side-effect-free
# ---------------------------------------------------------------------------


def append_sslmode(uri: str, *, have_ca: bool, tls_enabled: bool = True) -> str:
    """Return *uri* with exactly one authoritative ``sslmode`` parameter.

    Any existing ``sslmode`` value in the URI (e.g. an upstream
    ``sslmode=disable``) is stripped before the authoritative value is
    appended, so the result always carries a single ``sslmode`` and never
    silently disables TLS via a duplicate parameter.

    When *tls_enabled* is False (the database provider reports TLS is off),
    ``sslmode=disable`` is used so the connection is not rejected by a server
    that never negotiates TLS.
    """
    parts = urlsplit(uri)
    params = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "sslmode"]
    if not tls_enabled:
        sslmode = "disable"
    elif have_ca:
        sslmode = "verify-full"
    else:
        sslmode = "require"
    params.append(("sslmode", sslmode))
    return urlunsplit(parts._replace(query=urlencode(params)))


# ---------------------------------------------------------------------------
# Config-TOML renderer — pure, side-effect-free
# ---------------------------------------------------------------------------


def render_config_toml(
    cfg: GatewayConfig,
    *,
    db_uri: str,
    issuer_url: str,
    tls_cert_path: str,
    tls_key_path: str,
    jwt_signing_key_path: str,
    jwt_public_key_path: str,
    jwt_kid_path: str,
    redirect_uri: str,
    k8s_namespace: str = "openshell",
    k8s_service_account_name: str = "default",
) -> str:
    """Return the workload ``config.toml`` as a string.

    Pure function — no filesystem access, no ``ops`` imports.  All paths are
    passed in so the function is trivially unit-testable.

    The binary uses ``[openshell.gateway]``, ``[openshell.gateway.tls]``,
    ``[openshell.gateway.oidc]``, and ``[openshell.gateway.gateway_jwt]``
    sections.  The database URL is supplied via the ``OPENSHELL_DB_URL`` env
    var (handled by the Pebble layer), not here.  ``redirect_uri`` is kept as
    an argument for backwards compatibility but is not rendered in this
    version.
    """
    assert cfg.oidc_admin_role is not None
    assert cfg.oidc_user_role is not None

    def q(v: str) -> str:
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'

    lines = [
        "[openshell.gateway]",
        f"bind_address = {q(BIND_ADDRESS + ':' + GATEWAY_PORT)}",
        f"log_level = {q(cfg.log_level)}",
        "",
        "[openshell.gateway.tls]",
        f"cert_path = {q(tls_cert_path)}",
        f"key_path = {q(tls_key_path)}",
        "",
        "[openshell.gateway.oidc]",
        f"issuer = {q(issuer_url)}",
        f"audience = {q(cfg.oidc_audience)}",
        f"roles_claim = {q(cfg.oidc_roles_claim)}",
        f"admin_role = {q(cfg.oidc_admin_role)}",
        f"user_role = {q(cfg.oidc_user_role)}",
        "",
        "[openshell.gateway.gateway_jwt]",
        f"signing_key_path = {q(jwt_signing_key_path)}",
        f"public_key_path = {q(jwt_public_key_path)}",
        f"kid_path = {q(jwt_kid_path)}",
        f"gateway_id = {q(cfg.gateway_id)}",
        f"ttl_secs = {cfg.jwt_ttl_secs}",
        "",
        "[openshell.drivers.kubernetes]",
        f"namespace = {q(k8s_namespace)}",
        f"service_account_name = {q(k8s_service_account_name)}",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Env renderer — pure, config-only scope (FD-002)
# ---------------------------------------------------------------------------


def render_env(cfg: GatewayConfig) -> dict[str, str]:
    """Return the environment dict for the gateway workload.

    Covers only the vars FD-002 owns: config-derived vars and fixed constants.
    Deliberately absent:
    - ``OPENSHELL_DB_URL`` (relation-sourced, FD-003)
    - TLS certificate paths (FD-003)
    - OIDC issuer URL (FD-003)
    - ``gateway_jwt.*`` assembly (rendered into ``config.toml`` by FD-005)
    - ``OPENSHELL_ALLOW_UNAUTHENTICATED`` (option deliberately absent)
    - ``OPENSHELL_DISABLE_TLS`` (option deliberately absent)
    """
    # The validated model guarantees both role fields are non-None (the RBAC
    # model validator rejects any config where either is absent).
    assert cfg.oidc_admin_role is not None
    assert cfg.oidc_user_role is not None

    env: dict[str, str] = {
        # Fixed constants
        "OPENSHELL_BIND_ADDRESS": BIND_ADDRESS,
        "OPENSHELL_SERVER_PORT": GATEWAY_PORT,
        "OPENSHELL_DRIVERS": DRIVERS,
        "OPENSHELL_COMPUTE_DRIVER_SOCKET": DRIVER_SOCKET,
        # Config-derived
        "OPENSHELL_OIDC_AUDIENCE": cfg.oidc_audience,
        "OPENSHELL_OIDC_ROLES_CLAIM": cfg.oidc_roles_claim,
        "OPENSHELL_OIDC_ADMIN_ROLE": cfg.oidc_admin_role,
        "OPENSHELL_OIDC_USER_ROLE": cfg.oidc_user_role,
        "OPENSHELL_LOG_LEVEL": cfg.log_level,
        # Always emitted, including the disabling "0", so turning metrics
        # off changes the layer and actually restarts the workload rather
        # than leaving the previous listener up.
        "OPENSHELL_METRICS_PORT": str(cfg.metrics_port),
    }
    # Optional: only emitted when set
    if cfg.external_hostname is not None:
        env["OPENSHELL_EXTERNAL_HOSTNAME"] = cfg.external_hostname
    return env


# ---------------------------------------------------------------------------
# Parse helper — sole ValidationError catch site
# ---------------------------------------------------------------------------


def load_config(raw: Mapping[str, Any]) -> tuple[GatewayConfig | None, str | None]:
    """Parse and validate charm config, returning (model, None) or (None, message).

    This is the single place ``pydantic.ValidationError`` is caught.
    Returns a clean, prefix-free error message suitable for ``BlockedStatus``
    because all custom validators raise ``PydanticCustomError`` (which
    suppresses Pydantic v2's automatic "Value error, " prefix).

    ``charm.py.__init__`` calls::

        self._model, self._config_error = load_config(dict(self.config))

    and does no inline ``try/except`` of its own.
    """
    try:
        model = GatewayConfig.model_validate(dict(raw))
        return model, None
    except pydantic.ValidationError as exc:
        messages = [e["msg"] for e in exc.errors()]
        message = "; ".join(messages)
        return None, message


# ---------------------------------------------------------------------------
# Driver command renderer — pure, no ops imports
# ---------------------------------------------------------------------------


def render_driver_command(
    url: str,
    default_image: str,
    supervisor_image: str,
    operation_timeout_secs: int,
    log_level: str,
    gateway_endpoint: str,
    server_ca: str | None = None,
    server_fingerprint: str | None = None,
    project: str | None = None,
) -> str:
    """Return the full ``openshell-driver-lxd`` command line for remote HTTPS+mTLS.

    The local unix-socket path is intentionally absent; the driver is wired to
    a remote LXD over HTTPS using the provider's address and pinned CA or
    certificate fingerprint.

    Exactly one of ``server_ca`` or ``server_fingerprint`` must be supplied.

    ``gateway_endpoint`` is passed verbatim to the driver's ``--gateway-endpoint``
    flag and becomes each sandbox's ``OPENSHELL_ENDPOINT``. It must be a full URL
    (scheme + host + port) reachable by sandbox supervisors.

    ``supervisor_image`` is where the driver gets the sandbox boundary binary.
    It has to match the gateway's own OpenShell release; the driver's README
    warns that a mismatched pair fails to sync policy and exits.

    ``project`` is the LXD project the driver places every sandbox, image and
    operation in.  It comes from the provider over the ``lxd-https`` relation,
    never from charm config: which project a requirer may use is the LXD
    administrator's decision, and the integrator holds it.  Left unset, the
    driver falls back to its own default (the LXD ``default`` project).

    The sandbox TLS material is always passed.  The driver refuses to start
    without it unless plaintext is explicitly allowed, and this charm never
    allows plaintext: a sandbox supervisor reaches the gateway over TLS or not
    at all.
    """
    if (server_ca is None) == (server_fingerprint is None):
        raise ValueError("exactly one of server_ca or server_fingerprint must be set")

    trust_arg = (
        f" --lxd-server-ca {server_ca}"
        if server_ca is not None
        else f" --lxd-server-fingerprint {server_fingerprint}"
    )
    project_arg = f" --project {project}" if project is not None else ""

    return (
        f"/usr/bin/openshell-driver-lxd"
        f" --socket {DRIVER_SOCKET}"
        f" --lxd-url {url}"
        f" --lxd-client-cert {LXD_CLIENT_CERT_PATH}"
        f" --lxd-client-key {LXD_CLIENT_KEY_PATH}"
        f"{trust_arg}"
        f"{project_arg}"
        f" --default-image {default_image}"
        f" --supervisor-image {supervisor_image}"
        f" --operation-timeout-secs {operation_timeout_secs}"
        f" --log-level {log_level}"
        f" --gateway-endpoint {gateway_endpoint}"
        f" --guest-tls-ca {SANDBOX_TLS_CA_PATH}"
        f" --guest-tls-cert {SANDBOX_TLS_CERT_PATH}"
        f" --guest-tls-key {SANDBOX_TLS_KEY_PATH}"
    )


# ---------------------------------------------------------------------------
# LXD address sanitizer — pure, no ops imports
# ---------------------------------------------------------------------------


def _parse_lxd_address(raw: str) -> str | None:
    """Validate and return a cleaned ``host:port`` string, or None.

    Rejects whitespace, C0 control characters, DEL, and shell/path
    metacharacters. The result is intended for interpolation into the driver
    command line and must be a single ``host:port`` value.
    """
    # Reject embedded C0 control characters / DEL before stripping surrounding spaces.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        return None

    value = raw.strip()
    if not value:
        return None

    # Reject any remaining value containing whitespace or shell/path metacharacters.
    forbidden = set(" /\\;|&$`()<>\"'*?\t")
    if any(c in forbidden for c in value):
        return None

    # Host charset: A-Z, a-z, 0-9, dot, colon, underscore, hyphen, brackets.
    if not all(c.isascii() and (c.isalnum() or c in ".:_-[]") for c in value):
        return None

    # IPv6 literal form: [addr]:port
    if value.startswith("["):
        close = value.rfind("]")
        if close == -1 or close != value.index("]"):
            return None
        host_part = value[: close + 1]
        remainder = value[close + 1 :]
        if not remainder.startswith(":") or remainder == ":":
            return None
        port_part = remainder[1:]
        # Reject empty bracket content (e.g. "[]:8443").
        if close == 1:
            return None
    else:
        if ":" not in value:
            return None
        host_part, port_part = value.rsplit(":", 1)
        if not host_part:
            return None

    try:
        port = int(port_part)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None

    return f"{host_part}:{port}"


# ---------------------------------------------------------------------------
# LXD project sanitizer — pure, no ops imports
# ---------------------------------------------------------------------------


def _parse_lxd_project(raw: str) -> str | None:
    """Validate and return an LXD project name, or None.

    The value arrives over the ``lxd-https`` relation from the integrator and
    is interpolated into the driver's command line, so the accepted charset is
    deliberately narrow: letters, digits, dot, hyphen and underscore, up to the
    63 characters LXD allows. Anything else — whitespace, control characters,
    shell or path metacharacters, an over-long name — is rejected rather than
    sanitised, so a malformed value fails visibly instead of silently landing
    the driver in the wrong project.
    """
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        return None

    value = raw.strip()
    if not 1 <= len(value) <= 63:
        return None

    if not all(c.isascii() and (c.isalnum() or c in "._-") for c in value):
        return None

    return value


# ---------------------------------------------------------------------------
# Registry policy renderer — pure, no ops imports
# ---------------------------------------------------------------------------


def parse_insecure_registries(raw: str | None) -> list[str]:
    """Return the configured registry hosts, in order, without duplicates.

    Each entry is a ``host`` or ``host:port`` that skopeo will be told to reach
    over plain HTTP. Entries that could not be a registry location — whitespace,
    a scheme, a path, shell metacharacters — are dropped rather than written
    into a config file the workload parses.
    """
    if not raw:
        return []

    hosts: list[str] = []
    for part in raw.split(","):
        value = part.strip()
        if not value or "://" in value or "/" in value:
            continue
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            continue
        if not all(c.isascii() and (c.isalnum() or c in ".:_-[]") for c in value):
            continue
        if value not in hosts:
            hosts.append(value)
    return hosts


def render_registries_conf(insecure_registries: list[str]) -> str:
    """Return the contents of ``registries.conf`` for *insecure_registries*.

    skopeo verifies TLS against every registry by default, which is right. This
    exists for the deployments that pull the gateway's own companion images from
    a local registry serving plain HTTP, where the alternative is no images at
    all.
    """
    lines = [
        "# Managed by openshell-gateway-k8s. Written from the",
        "# insecure-registries config option; edits here are overwritten.",
    ]
    for host in insecure_registries:
        lines += ["", "[[registry]]", f'location = "{host}"', "insecure = true"]
    return "\n".join(lines) + "\n"
