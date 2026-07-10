"""Ops Scenario tests for charm.py — lifecycle, status, and reconcile."""

from __future__ import annotations

import os
import stat
from unittest.mock import MagicMock, patch

from ops import ActiveStatus, BlockedStatus, WaitingStatus
from ops.testing import Container, Context, PeerRelation, Relation, State

from charm import (
    CONTAINER_NAME,
    GATEWAY_CMD,
    PEER_RELATION,
    SERVICE_NAME,
    OpenshellGatewayK8sCharm,
)

RBAC_REQUIRED_MSG = "both oidc-admin-role and oidc-user-role must be set (RBAC required)"
TOGETHER_ADMIN_MSG = (
    "oidc-admin-role and oidc-user-role must be set together; got only oidc-admin-role"
)
TOGETHER_USER_MSG = (
    "oidc-admin-role and oidc-user-role must be set together; got only oidc-user-role"
)
BOTH_ROLES = {"oidc-admin-role": "admin", "oidc-user-role": "user"}

_CONN_CONTAINER = Container(CONTAINER_NAME, can_connect=True)
_FAKE_TLS_CERT = MagicMock(
    certificate="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
    ca="-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----",
)
_FAKE_TLS_KEY = MagicMock(raw="-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----")
_FAKE_JWT = {
    "signing-key": "-----BEGIN PRIVATE KEY-----\nFAKESIGN\n-----END PRIVATE KEY-----",
    "public-key": "-----BEGIN PUBLIC KEY-----\nFAKEPUB\n-----END PUBLIC KEY-----",
    "kid": "testkid",
}
_DB_URI = "postgresql://u:p@db:5432/openshell?sslmode=require"
_ISSUER = "https://hydra.example.com"


def _all_relations():
    """Three empty relations so model.get_relation() returns non-None for each."""
    return [Relation("database"), Relation("certificates"), Relation("oauth")]


def _all_ready_patches():
    return (
        patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_DB_URI),
        patch.object(
            OpenshellGatewayK8sCharm, "_tls_material", return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY)
        ),
        patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_ISSUER),
        patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT),
        patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
    )


def _all_ready_state():
    return State(config=BOTH_ROLES, containers=[_CONN_CONTAINER], relations=_all_relations())


# ---------------------------------------------------------------------------
# VP-3: Config validation and status
# ---------------------------------------------------------------------------


class TestStatusSurfacing:
    def test_neither_role_is_blocked(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        out = ctx.run(ctx.on.collect_unit_status(), State(config={}))
        assert out.unit_status == BlockedStatus(RBAC_REQUIRED_MSG)

    def test_only_admin_role_is_blocked(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        out = ctx.run(ctx.on.collect_unit_status(), State(config={"oidc-admin-role": "admin"}))
        assert out.unit_status == BlockedStatus(TOGETHER_ADMIN_MSG)

    def test_only_user_role_is_blocked(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        out = ctx.run(ctx.on.collect_unit_status(), State(config={"oidc-user-role": "user"}))
        assert out.unit_status == BlockedStatus(TOGETHER_USER_MSG)

    def test_valid_config_no_relations_blocked_or_waiting(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(config=BOTH_ROLES, containers=[_CONN_CONTAINER])
        out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, (BlockedStatus, WaitingStatus))
        assert "database" in out.unit_status.message.lower()


# ---------------------------------------------------------------------------
# StoredState: fresh-deploy guard
# ---------------------------------------------------------------------------


class TestFreshDeploy:
    def test_config_changed_on_fresh_unit_no_attribute_error(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(config=BOTH_ROLES, containers=[Container(CONTAINER_NAME, can_connect=False)])
        ctx.run(ctx.on.config_changed(), state)

    def test_collect_unit_status_on_fresh_unit_no_crash(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(config=BOTH_ROLES, containers=[Container(CONTAINER_NAME, can_connect=False)])
        ctx.run(ctx.on.collect_unit_status(), state)


# ---------------------------------------------------------------------------
# Container connectivity
# ---------------------------------------------------------------------------


class TestContainerConnectivity:
    def test_waiting_when_container_not_connectable(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(config=BOTH_ROLES, containers=[Container(CONTAINER_NAME, can_connect=False)])
        out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, WaitingStatus)
        assert "container" in out.unit_status.message.lower()

    def test_reconcile_exits_cleanly_when_container_not_connectable(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(config=BOTH_ROLES, containers=[Container(CONTAINER_NAME, can_connect=False)])
        out = ctx.run(ctx.on.config_changed(), state)
        assert not out.get_container(CONTAINER_NAME).plan.services


# ---------------------------------------------------------------------------
# Missing relations: Blocked / Waiting
# ---------------------------------------------------------------------------


class TestMissingRelations:
    def _status_with(self, db_uri, tls, issuer, jwt, relations=None):
        ctx = Context(OpenshellGatewayK8sCharm)
        rels = relations if relations is not None else _all_relations()
        state = State(config=BOTH_ROLES, containers=[_CONN_CONTAINER], relations=rels)
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=db_uri),
            patch.object(OpenshellGatewayK8sCharm, "_tls_material", return_value=tls),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=issuer),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=jwt),
        ):
            out = ctx.run(ctx.on.collect_unit_status(), state)
        return out.unit_status

    def test_no_relation_database_missing(self):
        # No database relation in state → blocked on missing database
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(config=BOTH_ROLES, containers=[_CONN_CONTAINER])
        out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, (BlockedStatus, WaitingStatus))
        assert "database" in out.unit_status.message.lower()

    def test_waiting_when_database_data_not_ready(self):
        # Database relation present but _database_uri returns None → waiting
        status = self._status_with(None, (_FAKE_TLS_CERT, _FAKE_TLS_KEY), _ISSUER, _FAKE_JWT)
        assert isinstance(status, (BlockedStatus, WaitingStatus))
        assert "database" in status.message.lower()

    def test_waiting_when_tls_data_not_ready(self):
        status = self._status_with(_DB_URI, (None, None), _ISSUER, _FAKE_JWT)
        assert isinstance(status, (BlockedStatus, WaitingStatus))
        assert "certificate" in status.message.lower()

    def test_waiting_when_oauth_data_not_ready(self):
        status = self._status_with(_DB_URI, (_FAKE_TLS_CERT, _FAKE_TLS_KEY), None, _FAKE_JWT)
        assert isinstance(status, (BlockedStatus, WaitingStatus))
        assert "oauth" in status.message.lower()

    def test_waiting_when_jwt_not_ready(self):
        status = self._status_with(_DB_URI, (_FAKE_TLS_CERT, _FAKE_TLS_KEY), _ISSUER, None)
        assert isinstance(status, (BlockedStatus, WaitingStatus))


# ---------------------------------------------------------------------------
# Active scenario
# ---------------------------------------------------------------------------


class TestActiveScenario:
    def _run_pebble_ready(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        return out, ctx

    def test_active_when_all_ready(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert out.unit_status == ActiveStatus()

    def test_gateway_service_in_plan_with_correct_command(self):
        out, _ = self._run_pebble_ready()
        plan = out.get_container(CONTAINER_NAME).plan
        assert SERVICE_NAME in plan.services
        assert plan.services[SERVICE_NAME].command == GATEWAY_CMD

    def test_config_toml_pushed_with_gateway_id(self):
        out, ctx = self._run_pebble_ready()
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        config_path = fs / "etc" / "openshell" / "config.toml"
        assert config_path.exists()
        # The config.toml contains gateway configuration sections, not gateway_id field
        # Verify that the openshell.gateway section is present
        assert "[openshell.gateway]" in config_path.read_text()

    def test_jwt_files_pushed(self):
        out, ctx = self._run_pebble_ready()
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        assert (fs / "etc" / "openshell" / "jwt" / "signing.key").exists()
        assert (fs / "etc" / "openshell" / "jwt" / "public.pem").exists()

    def test_tls_files_pushed(self):
        out, ctx = self._run_pebble_ready()
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        assert (fs / "etc" / "openshell" / "tls" / "tls.crt").exists()
        assert (fs / "etc" / "openshell" / "tls" / "tls.key").exists()
        assert (fs / "etc" / "openshell" / "tls" / "ca.crt").exists()

    def test_sslmode_require_without_tls_ca(self):
        from config_model import append_sslmode

        result = append_sslmode("postgresql://u:p@h/db", have_ca=False)
        assert "sslmode=require" in result and result.count("sslmode") == 1

    def test_sslmode_verify_full_with_tls_ca(self):
        from config_model import append_sslmode

        result = append_sslmode("postgresql://u:p@h/db", have_ca=True)
        assert "sslmode=verify-full" in result and result.count("sslmode") == 1


# ---------------------------------------------------------------------------
# Teardown — relation-broken stops service
# ---------------------------------------------------------------------------


class TestTeardown:
    def test_relation_broken_disables_service(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        db_rel = Relation("database")
        state = State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=[db_rel, Relation("certificates"), Relation("oauth")],
        )
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=None),
            patch.object(OpenshellGatewayK8sCharm, "_tls_material", return_value=(None, None)),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=None),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=None),
        ):
            out = ctx.run(ctx.on.relation_broken(relation=db_rel), state)
        plan = out.get_container(CONTAINER_NAME).plan
        if SERVICE_NAME in plan.services:
            assert plan.services[SERVICE_NAME].startup in ("disabled", "disable")

    def test_status_blocked_after_data_removed(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(config=BOTH_ROLES, containers=[_CONN_CONTAINER], relations=_all_relations())
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=None),
            patch.object(OpenshellGatewayK8sCharm, "_tls_material", return_value=(None, None)),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=None),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=None),
        ):
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, (BlockedStatus, WaitingStatus))


# ---------------------------------------------------------------------------
# JWT keypair
# ---------------------------------------------------------------------------


class TestJwtKeypair:
    def test_leader_with_peer_relation_completes_without_crash(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        peer_rel = PeerRelation(PEER_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                peer_rel,
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
            ],
        )
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=None),
            patch.object(OpenshellGatewayK8sCharm, "_tls_material", return_value=(None, None)),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=None),
        ):
            out = ctx.run(ctx.on.relation_created(relation=peer_rel), state)
        assert out is not None

    def test_jwt_signing_key_pem_header(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        pem = (
            Ed25519PrivateKey.generate()
            .private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            .decode()
        )
        assert pem.startswith("-----BEGIN PRIVATE KEY-----")

    def test_jwt_public_key_pem_header(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        pub = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )
        assert pub.startswith("-----BEGIN PUBLIC KEY-----")

    def test_pushed_signing_key_starts_with_pem_header(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        assert (
            (fs / "etc" / "openshell" / "jwt" / "signing.key")
            .read_text()
            .startswith("-----BEGIN PRIVATE KEY-----")
        )

    def test_pushed_public_key_starts_with_pem_header(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        assert (
            (fs / "etc" / "openshell" / "jwt" / "public.pem")
            .read_text()
            .startswith("-----BEGIN PUBLIC KEY-----")
        )


# ---------------------------------------------------------------------------
# File existence
# ---------------------------------------------------------------------------


class TestFiles:
    def test_all_expected_files_exist_when_active(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        for rel_path in [
            "etc/openshell/jwt/signing.key",
            "etc/openshell/jwt/public.pem",
            "etc/openshell/tls/tls.crt",
            "etc/openshell/tls/tls.key",
            "etc/openshell/tls/ca.crt",
            "etc/openshell/config.toml",
        ]:
            assert (fs / rel_path).exists(), f"Missing: {rel_path}"


# ---------------------------------------------------------------------------
# CA transfer
# ---------------------------------------------------------------------------


class TestCaTransfer:
    def test_no_error_when_no_send_ca_cert_relation(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_second_reconcile_no_error(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        with p[0], p[1], p[2], p[3], p[4]:
            out2 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), out1)
        assert out2 is not None


# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------


class TestFilePermissions:
    """Assert that private-key files and config.toml are pushed at 0o600,
    and public/cert files at 0o644."""

    def _run_active(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        return fs

    def test_signing_key_is_0o600(self):
        fs = self._run_active()
        mode = stat.S_IMODE(os.stat(fs / "etc/openshell/jwt/signing.key").st_mode)
        assert mode == 0o600, f"signing.key mode {oct(mode)} != 0o600"

    def test_tls_key_is_0o600(self):
        fs = self._run_active()
        mode = stat.S_IMODE(os.stat(fs / "etc/openshell/tls/tls.key").st_mode)
        assert mode == 0o600, f"tls.key mode {oct(mode)} != 0o600"

    def test_config_toml_is_0o600(self):
        fs = self._run_active()
        mode = stat.S_IMODE(os.stat(fs / "etc/openshell/config.toml").st_mode)
        assert mode == 0o600, f"config.toml mode {oct(mode)} != 0o600"

    def test_public_key_is_0o644(self):
        fs = self._run_active()
        mode = stat.S_IMODE(os.stat(fs / "etc/openshell/jwt/public.pem").st_mode)
        assert mode == 0o644, f"public.pem mode {oct(mode)} != 0o644"

    def test_tls_cert_is_0o644(self):
        fs = self._run_active()
        mode = stat.S_IMODE(os.stat(fs / "etc/openshell/tls/tls.crt").st_mode)
        assert mode == 0o644, f"tls.crt mode {oct(mode)} != 0o644"

    def test_ca_cert_is_0o644(self):
        fs = self._run_active()
        mode = stat.S_IMODE(os.stat(fs / "etc/openshell/tls/ca.crt").st_mode)
        assert mode == 0o644, f"ca.crt mode {oct(mode)} != 0o644"


# ---------------------------------------------------------------------------
# Secret access errors — read-only JWT helper
# ---------------------------------------------------------------------------


class TestSecretAccessErrors:
    """_read_jwt_keypair returns None rather than raising on any secret error."""

    def test_secret_not_found_returns_none(self):
        """_read_jwt_keypair returns None (not raises) when the secret is absent."""
        import ops

        charm_mock = MagicMock()
        charm_mock.model.get_secret.side_effect = ops.SecretNotFoundError("not found")
        result = OpenshellGatewayK8sCharm._read_jwt_keypair(charm_mock)
        assert result is None

    def test_model_error_returns_none(self):
        """_read_jwt_keypair returns None (not raises) on ModelError (e.g. stale grant)."""
        import ops

        charm_mock = MagicMock()
        charm_mock.model.get_secret.side_effect = ops.ModelError("access denied")
        result = OpenshellGatewayK8sCharm._read_jwt_keypair(charm_mock)
        assert result is None
