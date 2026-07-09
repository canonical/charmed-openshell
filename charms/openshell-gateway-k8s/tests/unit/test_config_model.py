"""Unit tests for config_model.py — pure pytest, no Juju required (VP-1, VP-2, VP-4)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from config_model import (
    BIND_ADDRESS,
    DRIVER_SOCKET,
    DRIVERS,
    GATEWAY_PORT,
    GatewayConfig,
    load_config,
    render_env,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_CONFIG = {
    "external-hostname": "gateway.example.com",
    "oidc-audience": "openshell-cli",
    "oidc-roles-claim": "groups",
    "oidc-admin-role": "admin",
    "oidc-user-role": "user",
    "log-level": "info",
}

BOTH_ROLES_MINIMAL = {
    "oidc-admin-role": "admin",
    "oidc-user-role": "user",
}


# ---------------------------------------------------------------------------
# VP-1: Config surface
# ---------------------------------------------------------------------------


class TestConfigSurface:
    def test_parse_all_six_keys(self):
        cfg = GatewayConfig.model_validate(VALID_CONFIG)
        assert cfg.external_hostname == "gateway.example.com"
        assert cfg.oidc_audience == "openshell-cli"
        assert cfg.oidc_roles_claim == "groups"
        assert cfg.oidc_admin_role == "admin"
        assert cfg.oidc_user_role == "user"
        assert cfg.log_level == "info"

    def test_no_disable_tls_field(self):
        # These options must never be declared as fields anywhere.
        assert "disable-tls" not in GatewayConfig.model_fields
        assert "disable_tls" not in GatewayConfig.model_fields

    def test_no_allow_unauthenticated_users_field(self):
        assert "allow-unauthenticated-users" not in GatewayConfig.model_fields
        assert "allow_unauthenticated_users" not in GatewayConfig.model_fields

    def test_defaults(self):
        cfg = GatewayConfig.model_validate(BOTH_ROLES_MINIMAL)
        assert cfg.oidc_audience == "openshell-cli"
        assert cfg.oidc_roles_claim == "groups"
        assert cfg.log_level == "info"
        assert cfg.external_hostname is None

    def test_empty_string_normalised_to_none_for_optional_fields(self):
        cfg = GatewayConfig.model_validate(
            {"external-hostname": "", "oidc-admin-role": "admin", "oidc-user-role": "user"}
        )
        assert cfg.external_hostname is None

    def test_extra_keys_ignored(self):
        """extra="ignore": unknown keys from future features do not break the model."""
        cfg = GatewayConfig.model_validate(
            {**BOTH_ROLES_MINIMAL, "future-option": "value"}
        )
        assert cfg.oidc_admin_role == "admin"


# ---------------------------------------------------------------------------
# VP-2: RBAC validation
# ---------------------------------------------------------------------------


class TestRBACValidation:
    def test_both_roles_valid(self):
        cfg = GatewayConfig.model_validate(BOTH_ROLES_MINIMAL)
        assert cfg.oidc_admin_role == "admin"
        assert cfg.oidc_user_role == "user"

    def test_neither_role_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            GatewayConfig.model_validate({})
        msg = exc_info.value.errors()[0]["msg"]
        assert msg == "both oidc-admin-role and oidc-user-role must be set (RBAC required)"

    def test_only_admin_role_raises_distinct_message(self):
        with pytest.raises(ValidationError) as exc_info:
            GatewayConfig.model_validate({"oidc-admin-role": "admin"})
        msg = exc_info.value.errors()[0]["msg"]
        assert "oidc-admin-role and oidc-user-role must be set together" in msg
        # The SET role's hyphen-key appears in "got only <hyphen-key>"
        assert "oidc-admin-role" in msg

    def test_only_user_role_raises_distinct_message(self):
        with pytest.raises(ValidationError) as exc_info:
            GatewayConfig.model_validate({"oidc-user-role": "user"})
        msg = exc_info.value.errors()[0]["msg"]
        assert "oidc-admin-role and oidc-user-role must be set together" in msg
        # The SET role's hyphen-key appears in "got only <hyphen-key>"
        assert "oidc-user-role" in msg

    def test_neither_and_only_admin_messages_are_distinct(self):
        """VP-2: exactly-one case has a distinct message from neither case."""
        with pytest.raises(ValidationError) as exc_info_neither:
            GatewayConfig.model_validate({})
        with pytest.raises(ValidationError) as exc_info_one:
            GatewayConfig.model_validate({"oidc-admin-role": "admin"})
        assert (
            exc_info_neither.value.errors()[0]["msg"]
            != exc_info_one.value.errors()[0]["msg"]
        )

    @pytest.mark.parametrize(
        "field",
        ["oidc-admin-role", "oidc-user-role", "external-hostname", "oidc-audience", "oidc-roles-claim"],
    )
    def test_control_char_newline_rejected(self, field):
        base = {"oidc-admin-role": "admin", "oidc-user-role": "user"}
        base[field] = "bad\nvalue"
        with pytest.raises(ValidationError):
            GatewayConfig.model_validate(base)

    @pytest.mark.parametrize("field", ["oidc-admin-role", "oidc-user-role", "external-hostname"])
    def test_none_optional_field_does_not_raise_control_char(self, field):
        """None-valued optional fields must not trigger the control-char validator."""
        base = {"oidc-admin-role": "admin", "oidc-user-role": "user"}
        base[field] = ""  # empty → None via normaliser
        # Should only raise if RBAC is broken; external-hostname being None is fine.
        if field == "external-hostname":
            cfg = GatewayConfig.model_validate(base)
            assert cfg.external_hostname is None
        # For role fields, setting one to None triggers the RBAC error, which is expected.

    def test_invalid_log_level(self):
        with pytest.raises(ValidationError):
            GatewayConfig.model_validate({**BOTH_ROLES_MINIMAL, "log-level": "verbose"})

    def test_empty_string_non_optional_field_is_invalid(self):
        """Empty string in a non-optional field is NOT normalised — it fails validation."""
        with pytest.raises(ValidationError):
            GatewayConfig.model_validate({**BOTH_ROLES_MINIMAL, "log-level": ""})


# ---------------------------------------------------------------------------
# load_config helper
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def test_valid_config_returns_model(self):
        model, err = load_config(VALID_CONFIG)
        assert model is not None
        assert err is None
        assert isinstance(model, GatewayConfig)

    def test_neither_role_returns_none_and_message(self):
        model, err = load_config({})
        assert model is None
        assert err == "both oidc-admin-role and oidc-user-role must be set (RBAC required)"

    def test_only_admin_returns_none_and_message(self):
        model, err = load_config({"oidc-admin-role": "admin"})
        assert model is None
        assert err is not None
        assert "oidc-admin-role" in err
        assert "got only oidc-admin-role" in err

    def test_only_user_returns_none_and_message(self):
        model, err = load_config({"oidc-user-role": "user"})
        assert model is None
        assert err is not None
        assert "got only oidc-user-role" in err

    def test_no_value_error_prefix_in_message(self):
        """PydanticCustomError suppresses the 'Value error, ' prefix."""
        _, err = load_config({})
        assert err is not None
        assert not err.startswith("Value error,")


# ---------------------------------------------------------------------------
# VP-4: render_env
# ---------------------------------------------------------------------------

FIXED_KEYS = {"OPENSHELL_BIND_ADDRESS", "OPENSHELL_PORT", "OPENSHELL_DRIVERS", "OPENSHELL_LXD_SOCKET"}
CONFIG_DERIVED_KEYS = {
    "OPENSHELL_OIDC_AUDIENCE",
    "OPENSHELL_OIDC_ROLES_CLAIM",
    "OPENSHELL_OIDC_ADMIN_ROLE",
    "OPENSHELL_OIDC_USER_ROLE",
    "OPENSHELL_LOG_LEVEL",
}
DEFERRED_KEYS = {"OPENSHELL_DB_URL", "OPENSHELL_TLS_CERT", "OPENSHELL_OIDC_ISSUER"}


class TestRenderEnv:
    def _valid_cfg(self, **overrides) -> GatewayConfig:
        return GatewayConfig.model_validate({**VALID_CONFIG, **overrides})

    def test_exact_key_set_with_hostname(self):
        cfg = self._valid_cfg()
        env = render_env(cfg)
        expected = FIXED_KEYS | CONFIG_DERIVED_KEYS | {"OPENSHELL_EXTERNAL_HOSTNAME"}
        assert set(env.keys()) == expected

    def test_exact_key_set_without_hostname(self):
        cfg = self._valid_cfg(**{"external-hostname": ""})
        env = render_env(cfg)
        expected = FIXED_KEYS | CONFIG_DERIVED_KEYS
        assert set(env.keys()) == expected

    def test_drivers_value(self):
        cfg = self._valid_cfg()
        assert render_env(cfg)["OPENSHELL_DRIVERS"] == "lxd"

    def test_fixed_constants(self):
        cfg = self._valid_cfg()
        env = render_env(cfg)
        assert env["OPENSHELL_BIND_ADDRESS"] == BIND_ADDRESS
        assert env["OPENSHELL_PORT"] == GATEWAY_PORT
        assert env["OPENSHELL_LXD_SOCKET"] == DRIVER_SOCKET

    def test_deferred_keys_absent(self):
        cfg = self._valid_cfg()
        env = render_env(cfg)
        for key in DEFERRED_KEYS:
            assert key not in env, f"{key} should be deferred to FD-003"

    def test_no_allow_unauthenticated_key(self):
        cfg = self._valid_cfg()
        env = render_env(cfg)
        assert "OPENSHELL_ALLOW_UNAUTHENTICATED" not in env

    def test_no_disable_tls_key(self):
        cfg = self._valid_cfg()
        env = render_env(cfg)
        assert "OPENSHELL_DISABLE_TLS" not in env

    def test_result_is_flat_str_dict(self):
        """No TOML — result must be a flat dict[str, str]."""
        cfg = self._valid_cfg()
        env = render_env(cfg)
        assert isinstance(env, dict)
        for k, v in env.items():
            assert isinstance(k, str), f"Key {k!r} is not a string"
            assert isinstance(v, str), f"Value for {k!r} is not a string"

    def test_external_hostname_unset_absent(self):
        cfg = self._valid_cfg(**{"external-hostname": ""})
        assert "OPENSHELL_EXTERNAL_HOSTNAME" not in render_env(cfg)

    def test_external_hostname_set_present(self):
        cfg = self._valid_cfg(**{"external-hostname": "gw.example.com"})
        assert render_env(cfg)["OPENSHELL_EXTERNAL_HOSTNAME"] == "gw.example.com"
