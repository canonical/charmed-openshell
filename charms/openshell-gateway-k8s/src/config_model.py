"""Pure configuration model for the OpenShell Gateway charm.

No ``ops`` imports — this module is testable with plain pytest and zero Juju.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

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
DRIVERS: str = "lxd"
# Socket path created by the FD-001 rock on startup.
DRIVER_SOCKET: str = "/var/run/openshell/lxd.sock"


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

    # ------------------------------------------------------------------
    # Field validators
    # ------------------------------------------------------------------

    @field_validator("external_hostname", "oidc_admin_role", "oidc_user_role", mode="before")
    @classmethod
    def _empty_string_to_none(cls, v: Any) -> Any:
        """Normalise Juju's empty-string representation of 'unset' to None.

        Only applied to the three ``str | None`` fields; the non-optional
        fields are deliberately excluded so an empty string there yields a
        meaningful type/Literal validation error.
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
# Env renderer — pure, config-only scope (FD-002)
# ---------------------------------------------------------------------------


def render_env(cfg: GatewayConfig) -> dict[str, str]:
    """Return the environment dict for the gateway workload.

    Covers only the vars FD-002 owns: config-derived vars and fixed constants.
    Deliberately absent:
    - ``OPENSHELL_DB_URL`` (relation-sourced, FD-003)
    - TLS certificate paths (FD-003)
    - OIDC issuer URL (FD-003)
    - All ``config.toml`` / ``gateway_jwt.*`` assembly (FD-003/FD-006)
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
        "OPENSHELL_PORT": GATEWAY_PORT,
        "OPENSHELL_DRIVERS": DRIVERS,
        "OPENSHELL_LXD_SOCKET": DRIVER_SOCKET,
        # Config-derived
        "OPENSHELL_OIDC_AUDIENCE": cfg.oidc_audience,
        "OPENSHELL_OIDC_ROLES_CLAIM": cfg.oidc_roles_claim,
        "OPENSHELL_OIDC_ADMIN_ROLE": cfg.oidc_admin_role,
        "OPENSHELL_OIDC_USER_ROLE": cfg.oidc_user_role,
        "OPENSHELL_LOG_LEVEL": cfg.log_level,
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
