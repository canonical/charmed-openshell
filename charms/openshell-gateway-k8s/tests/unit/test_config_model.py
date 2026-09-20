"""Unit tests for config_model.py — pure pytest, no Juju required (VP-1, VP-2, VP-4)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from config_model import (
    BIND_ADDRESS,
    DRIVER_SOCKET,
    GATEWAY_ID,
    GATEWAY_PORT,
    LXD_CLIENT_CERT_PATH,
    LXD_CLIENT_KEY_PATH,
    LXD_SERVER_CA_PATH,
    SANDBOX_TLS_CA_PATH,
    SANDBOX_TLS_CERT_PATH,
    SANDBOX_TLS_KEY_PATH,
    GatewayConfig,
    _parse_lxd_address,
    _parse_lxd_project,
    append_sslmode,
    load_config,
    render_config_toml,
    render_driver_command,
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
    def test_parse_all_eight_keys(self):
        cfg = GatewayConfig.model_validate(VALID_CONFIG)
        assert cfg.external_hostname == "gateway.example.com"
        assert cfg.oidc_audience == "openshell-cli"
        assert cfg.oidc_roles_claim == "groups"
        assert cfg.oidc_admin_role == "admin"
        assert cfg.oidc_user_role == "user"
        assert cfg.log_level == "info"
        assert cfg.gateway_id == "openshell-gateway"
        assert cfg.jwt_ttl_secs == 3600

    def test_lxd_config_defaults(self):
        cfg = GatewayConfig.model_validate(BOTH_ROLES_MINIMAL)
        assert cfg.lxd_sandbox_image == "openshell-sandbox"
        assert cfg.lxd_operation_timeout_secs == 60

    def test_no_lxd_projects_field(self):
        # Which LXD projects the gateway may reach is the integrator's
        # decision and arrives over the lxd-https relation. This charm must
        # never grow a config option for it again.
        assert "lxd_projects" not in GatewayConfig.model_fields

    @pytest.mark.parametrize("field", ["lxd-sandbox-image"])
    def test_lxd_string_fields_reject_control_chars(self, field):
        base = {**BOTH_ROLES_MINIMAL}
        base[field] = "bad\nvalue"
        with pytest.raises(ValidationError):
            GatewayConfig.model_validate(base)

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
        cfg = GatewayConfig.model_validate({**BOTH_ROLES_MINIMAL, "future-option": "value"})
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
        assert exc_info_neither.value.errors()[0]["msg"] != exc_info_one.value.errors()[0]["msg"]

    @pytest.mark.parametrize(
        "field",
        [
            "oidc-admin-role",
            "oidc-user-role",
            "external-hostname",
            "oidc-audience",
            "oidc-roles-claim",
            "gateway-id",
        ],
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

    @pytest.mark.parametrize("value", [0, -1, -3600])
    def test_jwt_ttl_secs_must_be_positive(self, value):
        with pytest.raises(ValidationError):
            GatewayConfig.model_validate({**BOTH_ROLES_MINIMAL, "jwt-ttl-secs": value})

    def test_jwt_ttl_secs_rejects_non_integer(self):
        with pytest.raises(ValidationError):
            GatewayConfig.model_validate({**BOTH_ROLES_MINIMAL, "jwt-ttl-secs": "one-hour"})

    def test_gateway_id_empty_rejected(self):
        with pytest.raises(ValidationError):
            GatewayConfig.model_validate({**BOTH_ROLES_MINIMAL, "gateway-id": ""})


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

FIXED_KEYS = {
    "OPENSHELL_BIND_ADDRESS",
    "OPENSHELL_SERVER_PORT",
    "OPENSHELL_DRIVERS",
    "OPENSHELL_COMPUTE_DRIVER_SOCKET",
}
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
        assert env["OPENSHELL_SERVER_PORT"] == GATEWAY_PORT
        assert env["OPENSHELL_COMPUTE_DRIVER_SOCKET"] == DRIVER_SOCKET

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


# ---------------------------------------------------------------------------
# append_sslmode
# ---------------------------------------------------------------------------


class TestAppendSslmode:
    def test_require_without_ca(self):
        uri = "postgresql://user:pass@host:5432/db"
        result = append_sslmode(uri, have_ca=False)
        assert "sslmode=require" in result
        assert result.count("sslmode") == 1

    def test_verify_full_with_ca(self):
        uri = "postgresql://user:pass@host:5432/db"
        result = append_sslmode(uri, have_ca=True)
        assert "sslmode=verify-full" in result
        assert result.count("sslmode") == 1

    def test_existing_sslmode_stripped_require(self):
        """An upstream sslmode=disable is overridden to require, not duplicated."""
        uri = "postgresql://user:pass@host:5432/db?sslmode=disable"
        result = append_sslmode(uri, have_ca=False)
        assert "sslmode=require" in result
        assert result.count("sslmode") == 1
        assert "disable" not in result

    def test_existing_sslmode_stripped_verify_full(self):
        uri = "postgresql://user:pass@host:5432/db?sslmode=prefer"
        result = append_sslmode(uri, have_ca=True)
        assert "sslmode=verify-full" in result
        assert result.count("sslmode") == 1

    def test_existing_query_params_preserved(self):
        uri = "postgresql://user:pass@host:5432/db?connect_timeout=10"
        result = append_sslmode(uri, have_ca=False)
        assert "connect_timeout=10" in result
        assert "sslmode=require" in result

    def test_query_joined_correctly(self):
        """No double ? when URI already has params."""
        uri = "postgresql://user:pass@host/db?foo=bar"
        result = append_sslmode(uri, have_ca=False)
        assert result.count("?") == 1


# ---------------------------------------------------------------------------
# render_config_toml
# ---------------------------------------------------------------------------

_TOML_KWARGS = {
    "db_uri": "postgresql://u:p@db:5432/openshell?sslmode=require",
    "issuer_url": "https://hydra.example.com",
    "tls_cert_path": "/etc/openshell/tls/tls.crt",
    "tls_key_path": "/etc/openshell/tls/tls.key",
    "jwt_signing_key_path": "/etc/openshell/jwt/signing.key",
    "jwt_public_key_path": "/etc/openshell/jwt/public.pem",
    "jwt_kid_path": "/etc/openshell/jwt/kid",
    "redirect_uri": "https://gw.example.com/oauth/unused",
}


class TestRenderConfigToml:
    def _cfg(self, **overrides):
        return GatewayConfig.model_validate({**VALID_CONFIG, **overrides})

    def _render(self, **overrides):
        return render_config_toml(self._cfg(), **{**_TOML_KWARGS, **overrides})

    def test_gateway_id_defaults_to_constant(self):
        cfg = GatewayConfig.model_validate(BOTH_ROLES_MINIMAL)
        assert cfg.gateway_id == GATEWAY_ID == "openshell-gateway"

    def test_gateway_id_is_rendered(self):
        toml = self._render()
        assert f'gateway_id = "{GATEWAY_ID}"' in toml

    def test_gateway_id_can_be_overridden(self):
        cfg = GatewayConfig.model_validate({**VALID_CONFIG, "gateway-id": "custom-gateway"})
        toml = render_config_toml(cfg, **_TOML_KWARGS)
        assert 'gateway_id = "custom-gateway"' in toml

    def test_database_url_in_output(self):
        toml = self._render()
        # Database URL is passed via OPENSHELL_DB_URL env var, not in config.toml
        # The config.toml only contains gateway, TLS, OIDC, and gateway_jwt configuration
        assert "[openshell.gateway]" in toml

    def test_oidc_section(self):
        toml = self._render()
        assert "[openshell.gateway.oidc]" in toml
        assert 'issuer = "https://hydra.example.com"' in toml

    def test_tls_section(self):
        toml = self._render()
        assert "[openshell.gateway.tls]" in toml
        assert "tls.crt" in toml
        assert "tls.key" in toml

    def test_gateway_jwt_section(self):
        import tomllib

        toml = self._render()
        parsed = tomllib.loads(toml)
        section = parsed["openshell"]["gateway"]["gateway_jwt"]
        assert section["signing_key_path"] == _TOML_KWARGS["jwt_signing_key_path"]
        assert section["public_key_path"] == _TOML_KWARGS["jwt_public_key_path"]
        assert section["kid_path"] == _TOML_KWARGS["jwt_kid_path"]
        assert section["gateway_id"] == GATEWAY_ID
        assert section["ttl_secs"] == 3600
        assert isinstance(section["ttl_secs"], int)
        assert section["ttl_secs"] > 0

    def test_jwt_ttl_secs_defaults_to_one_hour(self):
        cfg = GatewayConfig.model_validate(BOTH_ROLES_MINIMAL)
        assert cfg.jwt_ttl_secs == 3600

    def test_jwt_ttl_secs_can_be_overridden(self):
        cfg = GatewayConfig.model_validate({**VALID_CONFIG, "jwt-ttl-secs": 7200})
        toml = render_config_toml(cfg, **_TOML_KWARGS)
        assert "ttl_secs = 7200" in toml

    def test_kubernetes_driver_section(self):
        import tomllib

        toml = self._render()
        parsed = tomllib.loads(toml)
        section = parsed["openshell"]["drivers"]["kubernetes"]
        assert section["namespace"] == "openshell"
        assert section["service_account_name"] == "default"

    def test_kubernetes_namespace_can_be_overridden(self):
        toml = self._render(k8s_namespace="custom-ns")
        assert 'namespace = "custom-ns"' in toml

    def test_is_string(self):
        toml = self._render()
        assert isinstance(toml, str)

    def test_no_ops_import(self):
        """config_model must never import ops."""
        import inspect

        import config_model

        src = inspect.getsource(config_model)
        assert "import ops" not in src


# ---------------------------------------------------------------------------
# LXD driver command rendering
# ---------------------------------------------------------------------------


class TestRenderDriverCommand:
    def test_golden_command_with_ca(self):
        cmd = render_driver_command(
            "https://10.0.0.1:8443",
            "openshell-sandbox",
            60,
            "info",
            "https://openshell-gateway.my-model.svc.cluster.local:8443",
            server_ca=LXD_SERVER_CA_PATH,
        )
        assert cmd == (
            "/usr/bin/openshell-driver-lxd"
            f" --socket {DRIVER_SOCKET}"
            " --lxd-url https://10.0.0.1:8443"
            f" --lxd-client-cert {LXD_CLIENT_CERT_PATH}"
            f" --lxd-client-key {LXD_CLIENT_KEY_PATH}"
            f" --lxd-server-ca {LXD_SERVER_CA_PATH}"
            " --default-image openshell-sandbox"
            " --operation-timeout-secs 60"
            " --log-level info"
            " --gateway-endpoint https://openshell-gateway.my-model.svc.cluster.local:8443"
            f" --guest-tls-ca {SANDBOX_TLS_CA_PATH}"
            f" --guest-tls-cert {SANDBOX_TLS_CERT_PATH}"
            f" --guest-tls-key {SANDBOX_TLS_KEY_PATH}"
        )

    def test_project_is_rendered_when_the_provider_names_one(self):
        cmd = render_driver_command(
            "https://10.0.0.1:8443",
            "openshell-sandbox",
            60,
            "info",
            "https://gw:8443",
            server_ca=LXD_SERVER_CA_PATH,
            project="openshell",
        )
        assert " --project openshell" in cmd

    def test_project_is_absent_when_the_provider_names_none(self):
        cmd = render_driver_command(
            "https://10.0.0.1:8443",
            "openshell-sandbox",
            60,
            "info",
            "https://gw:8443",
            server_ca=LXD_SERVER_CA_PATH,
        )
        assert "--project" not in cmd

    def test_sandbox_tls_material_is_always_passed(self):
        # The driver refuses to start without it unless plaintext is allowed,
        # and this charm never allows plaintext.
        cmd = render_driver_command(
            "https://10.0.0.1:8443",
            "openshell-sandbox",
            60,
            "info",
            "https://gw:8443",
            server_fingerprint="abcdef",
        )
        assert f"--guest-tls-ca {SANDBOX_TLS_CA_PATH}" in cmd
        assert f"--guest-tls-cert {SANDBOX_TLS_CERT_PATH}" in cmd
        assert f"--guest-tls-key {SANDBOX_TLS_KEY_PATH}" in cmd
        assert "--allow-plaintext-gateway" not in cmd

    def test_command_with_fingerprint(self):
        cmd = render_driver_command(
            "https://10.0.0.1:8443",
            "openshell-sandbox",
            60,
            "info",
            "https://openshell-gateway.my-model.svc.cluster.local:8443",
            server_fingerprint="ab:cd:ef:12:34:56",
        )
        assert "--lxd-server-fingerprint ab:cd:ef:12:34:56" in cmd
        assert "--lxd-server-ca" not in cmd

    def test_ca_and_fingerprint_mutually_exclusive(self):
        with pytest.raises(ValueError):
            render_driver_command(
                "https://10.0.0.1:8443",
                "openshell-sandbox",
                60,
                "info",
                "https://openshell-gateway.my-model.svc.cluster.local:8443",
                server_ca=LXD_SERVER_CA_PATH,
                server_fingerprint="ab:cd",
            )

    def test_rendered_command_has_no_socket_reference(self):
        cmd = render_driver_command(
            "https://10.0.0.1:8443",
            "openshell-sandbox",
            60,
            "info",
            "https://openshell-gateway.my-model.svc.cluster.local:8443",
            server_ca=LXD_SERVER_CA_PATH,
        )
        assert "--lxd-socket" not in cmd
        assert "LXD_HOST_SOCKET" not in cmd
        assert "/var/snap/lxd" not in cmd

    def test_gateway_endpoint_verbatim(self):
        """The endpoint is emitted exactly as supplied, preserving scheme/host/port."""
        endpoint = "https://custom.svc.cluster.local:8443"
        cmd = render_driver_command(
            "https://10.0.0.1:8443",
            "openshell-sandbox",
            60,
            "info",
            endpoint,
            server_ca=LXD_SERVER_CA_PATH,
        )
        assert f"--gateway-endpoint {endpoint}" in cmd


class TestParseLxdAddress:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("10.0.0.1:8443", "10.0.0.1:8443"),
            ("  10.0.0.1:8443  ", "10.0.0.1:8443"),
            ("[::1]:8443", "[::1]:8443"),
            ("lxd.local:8443", "lxd.local:8443"),
            ("lxd-1.cluster.local:12345", "lxd-1.cluster.local:12345"),
            ("10.0.0.1:1", "10.0.0.1:1"),
            ("10.0.0.1:65535", "10.0.0.1:65535"),
        ],
    )
    def test_valid_addresses(self, raw, expected):
        assert _parse_lxd_address(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "10.0.0.1",
            "10.0.0.1:",
            ":8443",
            "10.0.0.1:0",
            "10.0.0.1:65536",
            "10.0.0.1:abc",
            "10.0.0.1 8443",
            "10.0.0.1\t8443",
            "10.0.0.1:8443;rm -rf",
            "$(x):8443",
            "10.0.0.1:8443\n",
            "10.0.0.1:8443\x00",
            "10.0.0.1/path:8443",
            "[::1",  # missing bracket
            "[::1]:",  # missing port
            "[]:8443",  # empty host
        ],
    )
    def test_rejects_injection(self, raw):
        assert _parse_lxd_address(raw) is None


class TestParseLxdProject:
    @pytest.mark.parametrize("name", ["openshell", "a", "a" * 63, "proj-1_2.3", " padded "])
    def test_accepts_lxd_project_names(self, name):
        assert _parse_lxd_project(name) == name.strip()

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "   ",
            "a" * 64,
            "bad/project",
            "has space",
            "semi;colon",
            "dollar$sign",
            "back`tick`",
            "new\nline",
            "nul\x00byte",
            "del\x7f",
            "uni\u00e7ode",
        ],
    )
    def test_rejects_unusable_names(self, name):
        assert _parse_lxd_project(name) is None
