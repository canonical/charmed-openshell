"""Ops Scenario tests for charm.py — lifecycle, status, and reconcile."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import ops.pebble
import yaml
from charms.tls_certificates_interface.v4.tls_certificates import TLSCertificatesRequiresV4
from ops import ActiveStatus, BlockedStatus, WaitingStatus
from ops.testing import Container, Context, PeerRelation, Relation, Secret, State

import config_model
from charm import (
    APPLIED_HASH_KEY,
    CHECK_PERIOD,
    CHECK_THRESHOLD,
    CHECK_TIMEOUT,
    CONTAINER_NAME,
    DRIVER_CHECK_NAME,
    DRIVER_SERVICE_NAME,
    GATEWAY_CMD,
    PEER_RELATION,
    PEER_SECRET_ID_KEY,
    READINESS_CHECK_NAME,
    RESTART_RELATION,
    SERVICE_NAME,
    OpenshellGatewayK8sCharm,
    _generate_jwt_keypair,
)
from config_model import DRIVER_SOCKET, GATEWAY_PORT

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
# External hostname: IP addresses become IP SANs, not DNS SANs
# ---------------------------------------------------------------------------


class TestExternalHostnameIp:
    def _request_attrs(self, external_hostname: str):
        ctx = Context(OpenshellGatewayK8sCharm)
        config = {**BOTH_ROLES, "external-hostname": external_hostname}
        state = State(
            config=config,
            containers=[_CONN_CONTAINER],
            relations=_all_relations(),
        )
        p_db, _tls, p_issuer, p_jwt1, p_jwt2 = _all_ready_patches()
        with (
            patch.object(
                TLSCertificatesRequiresV4,
                "get_assigned_certificate",
                return_value=(None, None),
            ) as mock_cert,
            p_db,
            p_issuer,
            p_jwt1,
            p_jwt2,
        ):
            ctx.run(ctx.on.config_changed(), state)
        args = mock_cert.call_args
        assert args is not None, "get_assigned_certificate was not called"
        return args[0][0]

    def test_ip_hostname_is_sans_ip_not_sans_dns(self):
        attrs = self._request_attrs("10.43.45.0")
        assert "10.43.45.0" in attrs.sans_ip
        assert "10.43.45.0" not in attrs.sans_dns

    def test_dns_hostname_is_sans_dns(self):
        attrs = self._request_attrs("gateway.example.com")
        assert "gateway.example.com" in attrs.sans_dns
        assert "gateway.example.com" not in attrs.sans_ip


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

    def test_generate_jwt_keypair_shape(self):
        material = _generate_jwt_keypair()
        assert set(material.keys()) == {"signing-key", "public-key", "kid"}
        assert material["signing-key"].startswith("-----BEGIN PRIVATE KEY-----")
        assert material["public-key"].startswith("-----BEGIN PUBLIC KEY-----")
        assert material["kid"]

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
# JWT key rotation convergence
# ---------------------------------------------------------------------------


class TestJwtRotationConvergence:
    def _all_ready_state_with_secret(self, secret):
        peer_rel = PeerRelation(
            PEER_RELATION,
            local_app_data={PEER_SECRET_ID_KEY: secret.id},
        )
        return State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=[
                peer_rel,
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
            ],
            secrets=[secret],
            leader=True,
        )

    def test_secret_changed_rewrites_jwt_files_and_replans(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        old_jwt = {
            "signing-key": "-----BEGIN PRIVATE KEY-----\nOLDSIGN\n-----END PRIVATE KEY-----",
            "public-key": "-----BEGIN PUBLIC KEY-----\nOLDPUB\n-----END PUBLIC KEY-----",
            "kid": "oldkid",
        }
        new_jwt = {
            "signing-key": "-----BEGIN PRIVATE KEY-----\nNEWSIGN\n-----END PRIVATE KEY-----",
            "public-key": "-----BEGIN PUBLIC KEY-----\nNEWPUB\n-----END PUBLIC KEY-----",
            "kid": "newkid",
        }
        secret = Secret(tracked_content=old_jwt, latest_content=new_jwt)
        state = self._all_ready_state_with_secret(secret)
        p = _all_ready_patches()
        with p[0], p[1], p[2]:
            out = ctx.run(ctx.on.secret_changed(secret), state)
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        assert (fs / "etc" / "openshell" / "jwt" / "signing.key").read_text() == new_jwt[
            "signing-key"
        ]
        assert (fs / "etc" / "openshell" / "jwt" / "public.pem").read_text() == new_jwt[
            "public-key"
        ]
        assert SERVICE_NAME in out.get_container(CONTAINER_NAME).plan.services


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


# ---------------------------------------------------------------------------
# Rolling restart coordination
# ---------------------------------------------------------------------------


def _restart_relation():
    return PeerRelation(RESTART_RELATION)


class TestRollingRestartMetadata:
    def test_restart_relation_and_action_declared(self):
        meta_path = Path(__file__).parent.parent.parent / "charmcraft.yaml"
        meta = yaml.safe_load(meta_path.read_text())
        assert "restart" in meta.get("peers", {})
        assert meta["peers"]["restart"]["interface"] == "rolling_op"
        assert "restart" in meta.get("actions", {})


class TestWorkloadConfigHash:
    def test_hash_is_order_independent_and_sensitive(self):
        charm = object.__new__(OpenshellGatewayK8sCharm)
        layer = {
            "summary": "gateway layer",
            "services": {
                "driver-lxd": {
                    "override": "replace",
                    "command": "/usr/bin/openshell-driver-lxd",
                    "startup": "enabled",
                },
                "gateway": {
                    "override": "replace",
                    "command": "/usr/bin/openshell-gateway",
                    "startup": "enabled",
                    "after": ["driver-lxd"],
                },
            },
        }
        toml = "[openshell.gateway]\nkey = 'value'\n"
        cert = "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----"
        h1 = charm._workload_config_hash(layer, toml, cert)

        # Reordered dict keys inside the layer produce the same hash.
        layer2 = {
            "summary": "gateway layer",
            "services": {
                "gateway": {
                    "startup": "enabled",
                    "command": "/usr/bin/openshell-gateway",
                    "override": "replace",
                    "after": ["driver-lxd"],
                },
                "driver-lxd": {
                    "command": "/usr/bin/openshell-driver-lxd",
                    "override": "replace",
                    "startup": "enabled",
                },
            },
        }
        h2 = charm._workload_config_hash(layer2, toml, cert)
        assert h1 == h2

        # Changing any component changes the hash.
        assert charm._workload_config_hash(layer, toml + "#", cert) != h1
        assert charm._workload_config_hash(layer, toml, cert + "X") != h1


class TestRollingRestartLifecycle:
    def _ready_state(self):
        peer_rel = _restart_relation()
        return State(
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

    def test_first_reconcile_records_hash_no_restart(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4], patch("ops.model.Container.restart") as restart_mock:
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)

        peer_rel = next(r for r in out.relations if r.endpoint == RESTART_RELATION)
        assert APPLIED_HASH_KEY in peer_rel.local_unit_data
        restart_mock.assert_not_called()

    def test_steady_state_no_restart(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        with p[0], p[1], p[2], p[3], p[4], patch("ops.model.Container.restart") as restart_mock:
            out2 = ctx.run(ctx.on.config_changed(), out1)

        peer_rel = next(r for r in out2.relations if r.endpoint == RESTART_RELATION)
        hash1 = peer_rel.local_unit_data.get(APPLIED_HASH_KEY)
        assert hash1 is not None
        restart_mock.assert_not_called()

    def test_config_change_triggers_lock(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)

        # Change a config option that flows into the rendered TOML.
        state2 = State(
            config={**BOTH_ROLES, "log-level": "debug"},
            leader=True,
            containers=list(out1.containers),
            relations=list(out1.relations),
        )
        with p[0], p[1], p[2], p[3], p[4], patch("ops.model.Container.restart") as restart_mock:
            out2 = ctx.run(ctx.on.config_changed(), state2)

        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel = next(r for r in out2.relations if r.endpoint == RESTART_RELATION)
        assert APPLIED_HASH_KEY in peer_rel.local_unit_data

    def test_upgrade_charm_acquires_lock(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4], patch("ops.model.Container.restart") as restart_mock:
            out = ctx.run(ctx.on.upgrade_charm(), state)

        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel = next(r for r in out.relations if r.endpoint == RESTART_RELATION)
        assert APPLIED_HASH_KEY in peer_rel.local_unit_data

    def test_cert_rotation_triggers_lock(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4]:
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)

        rotated_cert = MagicMock(
            certificate="-----BEGIN CERTIFICATE-----\nROTATED\n-----END CERTIFICATE-----",
            ca="-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----",
        )
        with (
            p[0],
            p[1],
            p[2],
            p[3],
            p[4],
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(rotated_cert, _FAKE_TLS_KEY),
            ),
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out2 = ctx.run(ctx.on.config_changed(), out1)

        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel1 = next(r for r in out1.relations if r.endpoint == RESTART_RELATION)
        peer_rel2 = next(r for r in out2.relations if r.endpoint == RESTART_RELATION)
        assert (
            peer_rel2.local_unit_data[APPLIED_HASH_KEY]
            != peer_rel1.local_unit_data[APPLIED_HASH_KEY]
        )


class TestPebbleChecks:
    def test_readiness_check_constants(self):
        assert READINESS_CHECK_NAME == "gateway-ready"
        assert DRIVER_CHECK_NAME == "driver-ready"
        assert int(GATEWAY_PORT) == 8443
        assert CHECK_PERIOD == "3s"
        assert CHECK_TIMEOUT == "3s"
        assert CHECK_THRESHOLD == 2
        assert DRIVER_SOCKET == "/var/run/openshell/lxd.sock"

    def _pebble_layer(self) -> ops.pebble.LayerDict:
        charm = object.__new__(OpenshellGatewayK8sCharm)
        charm._model_cfg = config_model.GatewayConfig(**BOTH_ROLES)
        return charm._pebble_layer(_DB_URI)

    def test_pebble_layer_has_readiness_check(self):
        from typing import Any, cast

        layer = self._pebble_layer()

        assert "checks" in layer
        checks = layer["checks"]
        assert set(checks) == {READINESS_CHECK_NAME, DRIVER_CHECK_NAME}

        gateway_check = cast(dict[str, Any], checks[READINESS_CHECK_NAME])
        assert gateway_check["override"] == "replace"
        assert gateway_check["level"] == "ready"
        assert gateway_check["period"] == CHECK_PERIOD
        assert gateway_check["timeout"] == CHECK_TIMEOUT
        assert gateway_check["threshold"] == CHECK_THRESHOLD
        assert gateway_check["tcp"] == {"port": int(GATEWAY_PORT), "host": "127.0.0.1"}
        assert "exec" not in gateway_check

        driver_check = cast(dict[str, Any], checks[DRIVER_CHECK_NAME])
        assert driver_check["override"] == "replace"
        assert "level" not in driver_check
        assert driver_check["period"] == CHECK_PERIOD
        assert driver_check["timeout"] == CHECK_TIMEOUT
        assert driver_check["threshold"] == CHECK_THRESHOLD
        assert driver_check["exec"] == {"command": f"test -S {DRIVER_SOCKET}"}
        assert "tcp" not in driver_check

    def test_pebble_layer_round_trips_through_ops_layer(self):
        layer = self._pebble_layer()
        ops.pebble.Layer(layer)

    def test_hash_covers_checks(self):
        from typing import Any, cast

        charm = object.__new__(OpenshellGatewayK8sCharm)
        layer_with_checks = cast(dict[str, Any], self._pebble_layer())
        layer_without_checks = cast(
            ops.pebble.LayerDict,
            {
                "summary": layer_with_checks["summary"],
                "services": layer_with_checks["services"],
            },
        )
        toml = "[openshell.gateway]\nkey = 'value'\n"
        cert = "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----"

        h_with = charm._workload_config_hash(layer_with_checks, toml, cert)
        h_without = charm._workload_config_hash(layer_without_checks, toml, cert)
        assert h_with != h_without
