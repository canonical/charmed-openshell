"""Ops Scenario tests for charm.py — lifecycle, status, and reconcile."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import re
import stat
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ops
import ops.pebble
import yaml
from charms.data_platform_libs.v0.data_interfaces import CachedSecret
from charms.tls_certificates_interface.v4.tls_certificates import TLSCertificatesRequiresV4
from ops import ActiveStatus, BlockedStatus, ModelError, SecretNotFoundError, WaitingStatus
from ops.testing import (
    Container,
    Context,
    Model,
    Mount,
    PeerRelation,
    Relation,
    Secret,
    State,
    TCPPort,
)

import config_model
from charm import (
    APPLIED_HASH_KEY,
    CHECK_PERIOD,
    CHECK_THRESHOLD,
    CHECK_TIMEOUT,
    CONTAINER_NAME,
    DASHBOARD_RELATION,
    DRIVER_CHECK_NAME,
    DRIVER_SERVICE_NAME,
    GATEWAY_CMD,
    LXD_INTERFACE_VERSION,
    LXD_RELATION,
    METRICS_RELATION,
    PEER_RELATION,
    PEER_SECRET_ID_KEY,
    READINESS_CHECK_NAME,
    RECEIVE_CA_RELATION,
    RESTART_RELATION,
    SERVICE_NAME,
    OpenshellGatewayK8sCharm,
    _generate_jwt_keypair,
    _LxdConnection,
)
from config_model import (
    CONFIG_PATH,
    DEFAULT_SANDBOX_IMAGE,
    DRIVER_SOCKET,
    GATEWAY_PORT,
    LXD_CLIENT_CERT_PATH,
    LXD_CLIENT_KEY_PATH,
    LXD_SERVER_CERT_PATH,
    SANDBOX_TLS_CA_PATH,
    SANDBOX_TLS_CERT_PATH,
    SANDBOX_TLS_KEY_PATH,
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


_FAKE_LXD_IDENTITY = {
    "certificate": "-----BEGIN CERTIFICATE-----\nLXDCERT\n-----END CERTIFICATE-----",
    "private-key": "-----BEGIN PRIVATE KEY-----\nLXDKEY\n-----END PRIVATE KEY-----",
}
_FAKE_SANDBOX_IDENTITY = {
    "certificate": "-----BEGIN CERTIFICATE-----\nSBXCERT\n-----END CERTIFICATE-----",
    "private-key": "-----BEGIN PRIVATE KEY-----\nSBXKEY\n-----END PRIVATE KEY-----",
}
_LXD_URL = "https://10.0.0.1:8443"
# Digests shaped the way the sanitizer requires: 64 hex characters.
_APP_FP = "a" * 64
_UNIT_FP = "b" * 64

_LXD_CONN = _LxdConnection(
    url=_LXD_URL,
    server_ca="-----BEGIN CERTIFICATE-----\nSERVERCA\n-----END CERTIFICATE-----",
    fingerprint="ab:cd:ef",
)


def _all_relations():
    """Mandatory relations so model.get_relation() returns non-None for each."""
    return [
        Relation("database"),
        Relation("certificates"),
        Relation("oauth"),
        Relation(LXD_RELATION),
    ]


@contextlib.contextmanager
def _all_ready(*, jwt: bool = True, lxd_connection: bool = True, extra: Sequence = ()):
    """Patch out everything a unit needs to be ready, by name rather than position.

    This used to be a tuple addressed as ``p[0], p[1], …`` at every call site,
    so adding a patch meant grouping it into an existing slot rather than
    appending — and one had already been grouped in twice by mistake. Keyword
    arguments name the variants the tests actually use: a unit whose LXD
    provider has published nothing (``lxd_connection=False``), and one whose
    JWT store is under test and must not be patched (``jwt=False``).
    """
    patches = [
        patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_DB_URI),
        patch.object(
            OpenshellGatewayK8sCharm, "_tls_material", return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY)
        ),
        patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_ISSUER),
        patch.object(
            OpenshellGatewayK8sCharm,
            "_ensure_lxd_client_identity",
            return_value=_FAKE_LXD_IDENTITY,
        ),
        patch.object(
            OpenshellGatewayK8sCharm,
            "_read_lxd_client_identity",
            return_value=_FAKE_LXD_IDENTITY,
        ),
        patch.object(
            OpenshellGatewayK8sCharm,
            "_ensure_sandbox_client_identity",
            return_value=_FAKE_SANDBOX_IDENTITY,
        ),
        patch.object(
            OpenshellGatewayK8sCharm,
            "_read_sandbox_client_identity",
            return_value=_FAKE_SANDBOX_IDENTITY,
        ),
    ]
    if jwt:
        patches += [
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
        ]
    if lxd_connection:
        patches.append(
            patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=_LXD_CONN)
        )

    with contextlib.ExitStack() as stack:
        for patcher in (*patches, *extra):
            stack.enter_context(patcher)
        yield


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
# Relation-data resilience during secret churn
# ---------------------------------------------------------------------------


class TestRelationDataResilience:
    def _ready_patches(self, stack: contextlib.ExitStack, **overrides):
        """Patch all readiness helpers via the supplied ExitStack."""
        defaults = {
            "_database_uri": _DB_URI,
            "_tls_material": (_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            "_oauth_issuer": _ISSUER,
            "_ensure_jwt_keypair": _FAKE_JWT,
            "_read_jwt_keypair": _FAKE_JWT,
            "_ensure_lxd_client_identity": _FAKE_LXD_IDENTITY,
            "_read_lxd_client_identity": _FAKE_LXD_IDENTITY,
            "_ensure_sandbox_client_identity": _FAKE_SANDBOX_IDENTITY,
            "_read_sandbox_client_identity": _FAKE_SANDBOX_IDENTITY,
            "_lxd_connection": _LXD_CONN,
        }
        defaults.update(overrides)
        for name, value in defaults.items():
            stack.enter_context(patch.object(OpenshellGatewayK8sCharm, name, return_value=value))

    def test_database_uri_swallows_secret_not_found(self):
        """Trans revoked database secrets are treated as not-ready, not fatal."""
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch(
                    "charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.fetch_relation_data",
                    side_effect=SecretNotFoundError("secret gone"),
                )
            )
            self._ready_patches(stack, _database_uri=None)
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, WaitingStatus)
        assert "database credentials" in out.unit_status.message.lower()

    def test_database_uri_swallows_model_error(self):
        """Transient model errors reading database secrets are treated as not-ready."""
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch(
                    "charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.fetch_relation_data",
                    side_effect=ModelError("model hiccup"),
                )
            )
            self._ready_patches(stack, _database_uri=None)
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, WaitingStatus)
        assert "database credentials" in out.unit_status.message.lower()

    def test_database_secret_registration_failure_is_transient(self):
        """An inaccessible provider secret during relation churn does not crash the hook.

        When a provider publishes a secret URI before the grant is propagated
        (e.g. immediately after ``juju integrate``), the data_interfaces
        library's secret registration can fail. The charm must survive that
        event and report ``waiting for database credentials`` until a later
        secret-changed/relation-changed event makes the secret readable.
        """
        ctx = Context(OpenshellGatewayK8sCharm)
        db_rel = Relation(
            "database",
            remote_app_data={"secret-user": "secret://model/uuid/user"},
        )
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                db_rel,
                Relation("certificates"),
                Relation("oauth"),
                Relation(LXD_RELATION),
            ],
        )

        def _raising_meta(_self):
            raise SecretNotFoundError("grant not yet propagated")

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    CachedSecret,
                    "meta",
                    property(_raising_meta),
                )
            )
            stack.enter_context(
                patch.object(
                    OpenshellGatewayK8sCharm,
                    "_tls_material",
                    return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
                )
            )
            stack.enter_context(
                patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_ISSUER)
            )
            stack.enter_context(
                patch.object(
                    OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT
                )
            )
            stack.enter_context(
                patch.object(
                    OpenshellGatewayK8sCharm,
                    "_ensure_lxd_client_identity",
                    return_value=_FAKE_LXD_IDENTITY,
                )
            )
            stack.enter_context(
                patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=_LXD_CONN)
            )
            out = ctx.run(ctx.on.relation_changed(relation=db_rel), state)
        assert isinstance(out.unit_status, WaitingStatus)
        assert "database credentials" in out.unit_status.message.lower()

    def test_oauth_issuer_swallows_secret_not_found(self):
        """Trans revoked oauth secrets are treated as not-ready, not fatal."""
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch(
                    "charms.hydra.v0.oauth.OAuthRequirer.get_provider_info",
                    side_effect=SecretNotFoundError("secret gone"),
                )
            )
            self._ready_patches(stack, _oauth_issuer=None)
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, WaitingStatus)
        assert "oauth provider info" in out.unit_status.message.lower()

    def test_oauth_issuer_swallows_model_error(self):
        """Transient model errors reading oauth secrets are treated as not-ready."""
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch(
                    "charms.hydra.v0.oauth.OAuthRequirer.get_provider_info",
                    side_effect=ModelError("model hiccup"),
                )
            )
            self._ready_patches(stack, _oauth_issuer=None)
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, WaitingStatus)
        assert "oauth provider info" in out.unit_status.message.lower()


# ---------------------------------------------------------------------------
# Active scenario
# ---------------------------------------------------------------------------


class TestActiveScenario:
    def _run_pebble_ready(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        return out, ctx

    def test_active_when_all_ready(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        with _all_ready():
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert out.unit_status == ActiveStatus()

    def test_gateway_service_in_plan_with_correct_command(self):
        out, _ = self._run_pebble_ready()
        plan = out.get_container(CONTAINER_NAME).plan
        assert SERVICE_NAME in plan.services
        assert plan.services[SERVICE_NAME].command == GATEWAY_CMD

    def test_config_toml_pushed_with_gateway_jwt(self):
        out, ctx = self._run_pebble_ready()
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        config_path = fs / "etc" / "openshell" / "config.toml"
        assert config_path.exists()
        text = config_path.read_text()
        assert "[openshell.gateway]" in text
        assert "[openshell.gateway.gateway_jwt]" in text
        assert 'gateway_id = "openshell-gateway"' in text
        assert "ttl_secs = 3600" in text

    def test_jwt_files_pushed(self):
        out, ctx = self._run_pebble_ready()
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        assert (fs / "etc" / "openshell" / "jwt" / "signing.key").exists()
        assert (fs / "etc" / "openshell" / "jwt" / "public.pem").exists()
        assert (fs / "etc" / "openshell" / "jwt" / "kid").exists()
        assert (fs / "etc" / "openshell" / "jwt" / "kid").read_text() == _FAKE_JWT["kid"]

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
        with (
            patch.object(
                TLSCertificatesRequiresV4,
                "get_assigned_certificate",
                return_value=(None, None),
            ) as mock_cert,
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_DB_URI),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_ISSUER),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
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


class TestGatewayEndpoint:
    def test_endpoint_host_is_cluster_service_dns_san(self):
        """The driver dial-back endpoint matches a SAN on the gateway TLS cert."""
        ctx = Context(OpenshellGatewayK8sCharm, app_name="osgw")
        state = State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=_all_relations(),
            model=Model(name="stg"),
        )
        with (
            patch.object(
                TLSCertificatesRequiresV4,
                "get_assigned_certificate",
                return_value=(None, None),
            ) as mock_cert,
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_DB_URI),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_ISSUER),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=_LXD_CONN),
        ):
            ctx.run(ctx.on.config_changed(), state)
        args = mock_cert.call_args
        assert args is not None, "get_assigned_certificate was not called"
        attrs = args[0][0]
        assert "osgw.stg.svc.cluster.local" in attrs.sans_dns

    def _driver_command(self, ctx: Context, config: dict, extra_relations: list) -> str:
        state = State(
            config=config,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                Relation(LXD_RELATION),
                *extra_relations,
            ],
            model=Model(name="prod"),
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        return out.get_container(CONTAINER_NAME).plan.services[DRIVER_SERVICE_NAME].command

    def test_uses_external_hostname_when_ingress_ready(self):
        """External LXD sandboxes get a dial-back address reachable from outside."""
        ctx = Context(OpenshellGatewayK8sCharm, app_name="my-gateway")
        cmd = self._driver_command(
            ctx,
            config={**BOTH_ROLES, "external-hostname": "gw.example.com"},
            extra_relations=[Relation("ingress")],
        )
        assert "--gateway-endpoint https://gw.example.com:8443" in cmd

    def test_falls_back_to_cluster_local_without_ingress(self):
        """Without an ingress relation the cluster-local SVC address is used."""
        ctx = Context(OpenshellGatewayK8sCharm, app_name="my-gateway")
        cmd = self._driver_command(
            ctx,
            config={**BOTH_ROLES, "external-hostname": "gw.example.com"},
            extra_relations=[],
        )
        assert "--gateway-endpoint https://my-gateway.prod.svc.cluster.local:8443" in cmd


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

    def test_relation_recovery_replans_when_workload_inputs_are_unchanged(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        restart_rel = PeerRelation(RESTART_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[restart_rel, *_all_relations()],
        )
        with (
            _all_ready(),
        ):
            running = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)

        restart_rel = next(r for r in running.relations if r.endpoint == RESTART_RELATION)
        original_hash = restart_rel.local_unit_data[APPLIED_HASH_KEY]

        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_DB_URI),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            ),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=None),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=_LXD_CONN),
        ):
            stopped = ctx.run(ctx.on.config_changed(), running)

        restart_rel = next(r for r in stopped.relations if r.endpoint == RESTART_RELATION)
        assert APPLIED_HASH_KEY not in restart_rel.local_unit_data
        with (
            _all_ready(),
            patch("ops.model.Container.replan") as replan_mock,
        ):
            recovered = ctx.run(ctx.on.config_changed(), stopped)

        replan_mock.assert_called_once_with()
        restart_rel = next(r for r in recovered.relations if r.endpoint == RESTART_RELATION)
        assert restart_rel.local_unit_data[APPLIED_HASH_KEY] == original_hash


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
        with _all_ready():
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
        with _all_ready():
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
        with _all_ready():
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
        with _all_ready():
            ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_second_reconcile_no_error(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _all_ready_state()
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        with _all_ready():
            out2 = ctx.run(ctx.on.pebble_ready(out1.get_container(CONTAINER_NAME)), out1)
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
                Relation(LXD_RELATION),
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
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_DB_URI),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            ),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_ISSUER),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=new_jwt),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=new_jwt),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=_LXD_CONN),
        ):
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
        with _all_ready():
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
    """The Juju-secret reader returns None rather than raising on any secret error."""

    def test_secret_not_found_returns_none(self):
        """Returns None (not raises) when the secret is absent."""
        import ops

        charm_mock = MagicMock()
        charm_mock.model.get_secret.side_effect = ops.SecretNotFoundError("not found")
        result = OpenshellGatewayK8sCharm._read_juju_jwt_keypair(charm_mock)
        assert result is None

    def test_model_error_returns_none(self):
        """Returns None (not raises) on ModelError (e.g. stale grant)."""
        import ops

        charm_mock = MagicMock()
        charm_mock.model.get_secret.side_effect = ops.ModelError("access denied")
        result = OpenshellGatewayK8sCharm._read_juju_jwt_keypair(charm_mock)
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

    def test_trust_transfer_is_limited_to_one_provider(self):
        # Every certificate transferred here becomes a trust anchor in the
        # workload; an unbounded number of applications able to add one is an
        # unbounded trust decision.
        meta_path = Path(__file__).parent.parent.parent / "charmcraft.yaml"
        meta = yaml.safe_load(meta_path.read_text())
        assert meta["requires"][RECEIVE_CA_RELATION]["limit"] == 1


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
        signing = "-----BEGIN PRIVATE KEY-----\nSIGN\n-----END PRIVATE KEY-----"
        public = "-----BEGIN PUBLIC KEY-----\nPUB\n-----END PUBLIC KEY-----"
        kid = "kid1"
        lxd_cert = "LXDCERT"
        lxd_key = "LXDKEY"
        lxd_ca = "SERVERCA"
        lxd_url = "https://10.0.0.1:8443"
        h1 = charm._workload_config_hash(
            layer, toml, cert, signing, public, kid, lxd_cert, lxd_key, lxd_ca, lxd_url
        )

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
        h2 = charm._workload_config_hash(
            layer2, toml, cert, signing, public, kid, lxd_cert, lxd_key, lxd_ca, lxd_url
        )
        assert h1 == h2

        # Changing any component changes the hash.
        assert (
            charm._workload_config_hash(
                layer, toml + "#", cert, signing, public, kid, lxd_cert, lxd_key, lxd_ca, lxd_url
            )
            != h1
        )
        assert (
            charm._workload_config_hash(
                layer, toml, cert + "X", signing, public, kid, lxd_cert, lxd_key, lxd_ca, lxd_url
            )
            != h1
        )
        assert (
            charm._workload_config_hash(
                layer, toml, cert, signing + "X", public, kid, lxd_cert, lxd_key, lxd_ca, lxd_url
            )
            != h1
        )
        assert (
            charm._workload_config_hash(
                layer, toml, cert, signing, public + "X", kid, lxd_cert, lxd_key, lxd_ca, lxd_url
            )
            != h1
        )
        assert (
            charm._workload_config_hash(
                layer, toml, cert, signing, public, kid + "X", lxd_cert, lxd_key, lxd_ca, lxd_url
            )
            != h1
        )


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
                Relation(LXD_RELATION),
            ],
        )

    def test_first_reconcile_records_hash_no_restart(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        with (
            _all_ready(),
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)

        peer_rel = next(r for r in out.relations if r.endpoint == RESTART_RELATION)
        assert APPLIED_HASH_KEY in peer_rel.local_unit_data
        restart_mock.assert_not_called()

    def test_steady_state_no_restart(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        with (
            _all_ready(),
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out2 = ctx.run(ctx.on.config_changed(), out1)

        peer_rel = next(r for r in out2.relations if r.endpoint == RESTART_RELATION)
        hash1 = peer_rel.local_unit_data.get(APPLIED_HASH_KEY)
        assert hash1 is not None
        restart_mock.assert_not_called()

    def test_config_change_triggers_lock(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)

        # Change a config option that flows into the rendered TOML.
        state2 = State(
            config={**BOTH_ROLES, "log-level": "debug"},
            leader=True,
            containers=list(out1.containers),
            relations=list(out1.relations),
        )
        with (
            _all_ready(),
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out2 = ctx.run(ctx.on.config_changed(), state2)

        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel = next(r for r in out2.relations if r.endpoint == RESTART_RELATION)
        assert APPLIED_HASH_KEY in peer_rel.local_unit_data

    def test_upgrade_charm_acquires_lock(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        with (
            _all_ready(),
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out = ctx.run(ctx.on.upgrade_charm(), state)

        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel = next(r for r in out.relations if r.endpoint == RESTART_RELATION)
        assert APPLIED_HASH_KEY in peer_rel.local_unit_data

    def test_cert_rotation_triggers_lock(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)

        rotated_cert = MagicMock(
            certificate="-----BEGIN CERTIFICATE-----\nROTATED\n-----END CERTIFICATE-----",
            ca="-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----",
        )
        with (
            _all_ready(),
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

    def test_jwt_rotation_triggers_lock(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)

        rotated_jwt = {
            "signing-key": "-----BEGIN PRIVATE KEY-----\nROTATED\n-----END PRIVATE KEY-----",
            "public-key": "-----BEGIN PUBLIC KEY-----\nROTATED\n-----END PUBLIC KEY-----",
            "kid": "rotatedkid",
        }
        with (
            _all_ready(),
            patch.object(
                OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=rotated_jwt
            ),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=rotated_jwt),
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

    def test_jwt_rotation_writes_kid_file(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state()
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)

        rotated_jwt = {
            "signing-key": "-----BEGIN PRIVATE KEY-----\nROTATED\n-----END PRIVATE KEY-----",
            "public-key": "-----BEGIN PUBLIC KEY-----\nROTATED\n-----END PUBLIC KEY-----",
            "kid": "rotatedkid",
        }
        with (
            _all_ready(),
            patch.object(
                OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=rotated_jwt
            ),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=rotated_jwt),
            patch("ops.model.Container.restart"),
        ):
            out2 = ctx.run(ctx.on.config_changed(), out1)

        fs = out2.get_container(CONTAINER_NAME).get_filesystem(ctx)
        assert (fs / "etc" / "openshell" / "jwt" / "kid").read_text() == rotated_jwt["kid"]
        assert (fs / "etc" / "openshell" / "jwt" / "public.pem").read_text() == rotated_jwt[
            "public-key"
        ]


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
        # _gateway_endpoint reads self.app/self.model; bypass it for this
        # structural test.
        charm._gateway_endpoint = lambda: "https://test.test.svc.cluster.local:8443"
        return charm._pebble_layer(_DB_URI, _LXD_CONN)

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
        # "ready" like the gateway's own check: the driver is the only way this
        # gateway creates a sandbox, so a unit whose driver is down is not
        # ready and Pebble's readiness has to say so.
        assert driver_check["level"] == "ready"
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

        signing = "-----BEGIN PRIVATE KEY-----\nSIGN\n-----END PRIVATE KEY-----"
        public = "-----BEGIN PUBLIC KEY-----\nPUB\n-----END PUBLIC KEY-----"
        kid = "kid1"
        lxd_cert = "LXDCERT"
        lxd_key = "LXDKEY"
        lxd_ca = "SERVERCA"
        lxd_url = "https://10.0.0.1:8443"
        h_with = charm._workload_config_hash(
            layer_with_checks, toml, cert, signing, public, kid, lxd_cert, lxd_key, lxd_ca, lxd_url
        )
        h_without = charm._workload_config_hash(
            layer_without_checks,
            toml,
            cert,
            signing,
            public,
            kid,
            lxd_cert,
            lxd_key,
            lxd_ca,
            lxd_url,
        )
        assert h_with != h_without


# ---------------------------------------------------------------------------
# LXD HTTPS requirer integration
# ---------------------------------------------------------------------------


class TestLxdIdentity:
    def test_lxd_identity_minted_once(self):
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
                Relation(LXD_RELATION),
            ],
        )
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_DB_URI),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            ),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_ISSUER),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=_LXD_CONN),
        ):
            out1 = ctx.run(ctx.on.relation_created(relation=peer_rel), state)

        # Exactly one LXD client identity secret should have been created.
        lxd_secrets = [s for s in out1.secrets if s.label == "lxd-client-identity"]
        assert len(lxd_secrets) == 1
        secret_id = lxd_secrets[0].id
        peer_rel_out = next(r for r in out1.relations if r.endpoint == PEER_RELATION)
        assert peer_rel_out.local_app_data.get("lxd-secret-id") == secret_id

        # Second reconcile should not mint a new secret.
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_DB_URI),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            ),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_ISSUER),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=_LXD_CONN),
        ):
            out2 = ctx.run(ctx.on.config_changed(), out1)

        lxd_secrets2 = [s for s in out2.secrets if s.label == "lxd-client-identity"]
        assert len(lxd_secrets2) == 1
        assert lxd_secrets2[0].id == secret_id


class TestLxdDatabag:
    def test_lxd_databag_published(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(LXD_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        lxd_rel_out = next(r for r in out.relations if r.endpoint == LXD_RELATION)
        assert lxd_rel_out.local_app_data["version"] == LXD_INTERFACE_VERSION
        assert lxd_rel_out.local_app_data["certificate"] == _FAKE_LXD_IDENTITY["certificate"]
        assert "projects" not in lxd_rel_out.local_app_data
        assert lxd_rel_out.local_unit_data["version"] == LXD_INTERFACE_VERSION
        assert lxd_rel_out.local_unit_data["certificate"] == _FAKE_LXD_IDENTITY["certificate"]
        assert "projects" not in lxd_rel_out.local_unit_data

    def test_lxd_databag_clears_a_legacy_projects_key(self):
        # An older revision published a config-derived "projects" restriction.
        # After upgrade the key is the integrator's to decide, so the charm
        # removes what it used to own instead of leaving it to rot.
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(
            LXD_RELATION,
            local_app_data={"projects": "default,project-a"},
            local_unit_data={"projects": "default,project-a"},
        )
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        lxd_rel_out = next(r for r in out.relations if r.endpoint == LXD_RELATION)
        assert "projects" not in lxd_rel_out.local_app_data
        assert "projects" not in lxd_rel_out.local_unit_data

    def test_lxd_databag_unit_data_published_when_not_leader(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(LXD_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=False,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        lxd_rel_out = next(r for r in out.relations if r.endpoint == LXD_RELATION)
        assert lxd_rel_out.local_app_data == {}
        assert lxd_rel_out.local_unit_data["version"] == LXD_INTERFACE_VERSION
        assert lxd_rel_out.local_unit_data["certificate"] == _FAKE_LXD_IDENTITY["certificate"]


class TestLxdConnection:
    def _make_relation(self, app_data=None, unit_data=None):
        rel = Relation(LXD_RELATION, remote_app_data=app_data or {})
        if unit_data:
            rel = Relation(
                LXD_RELATION,
                remote_app_data=app_data or {},
                remote_units_data={0: unit_data},
            )
        return rel

    def _run_action(self, rel):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=[rel],
        )
        with (
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
        ):
            ctx.run(ctx.on.action("get-lxd-client-cert"), state)
        return ctx.action_results

    def test_lxd_connection_prefers_app_bag(self):
        rel = self._make_relation(
            app_data={
                "version": "1.0",
                "certificate": "APPCA",
                "certificate_fingerprint": _APP_FP,
                "addresses": "10.0.0.1:8443",
            },
            unit_data={
                "certificate": "UNITCA",
                "certificate_fingerprint": _UNIT_FP,
                "addresses": "10.0.0.2:8443",
            },
        )
        results = self._run_action(rel)
        assert results["certificate-fingerprint"] == _APP_FP

    def test_lxd_connection_falls_back_to_unit_bag(self):
        rel = self._make_relation(
            app_data={},
            unit_data={
                "version": "1.0",
                "certificate": "UNITCA",
                "certificate_fingerprint": _UNIT_FP,
                "addresses": "10.0.0.2:8443",
            },
        )
        results = self._run_action(rel)
        assert results["certificate-fingerprint"] == _UNIT_FP

    def test_lxd_connection_reads_the_unit_bag_that_has_the_details(self):
        # A non-clustered provider publishes to its leader's unit bag only, and
        # the leader is not necessarily the first unit iteration yields.
        rel = Relation(
            LXD_RELATION,
            remote_app_data={},
            remote_units_data={
                0: {},
                1: {
                    "version": "1.0",
                    "certificate": "UNITCA",
                    "certificate_fingerprint": _UNIT_FP,
                    "addresses": "10.0.0.2:8443",
                },
            },
        )
        results = self._run_action(rel)
        assert results["certificate-fingerprint"] == _UNIT_FP

    def test_lxd_connection_rejects_an_unusable_fingerprint(self):
        # The fingerprint is interpolated into the driver's command line, which
        # Pebble splits on whitespace: a value carrying a space would otherwise
        # become extra arguments to the driver.
        for bad in (f"{_APP_FP} --sandbox-nesting", "ab", "z" * 64, f"{_APP_FP}x"):
            rel = self._make_relation(
                app_data={
                    "version": "1.0",
                    "certificate_fingerprint": bad,
                    "addresses": "10.0.0.1:8443",
                }
            )
            results = self._run_action(rel)
            assert results["certificate-fingerprint"] == "", bad

    def test_lxd_connection_normalises_a_colon_separated_fingerprint(self):
        colons = ":".join("ab" for _ in range(32))
        rel = self._make_relation(
            app_data={
                "version": "1.0",
                "certificate_fingerprint": colons,
                "addresses": "10.0.0.1:8443",
            }
        )
        results = self._run_action(rel)
        assert results["certificate-fingerprint"] == "ab" * 32

    def test_lxd_connection_none_when_incomplete(self):
        rel = self._make_relation(app_data={"certificate": "CA"})
        results = self._run_action(rel)
        assert results["certificate-fingerprint"] == ""

    def test_lxd_connection_url_scheme(self):
        rel = self._make_relation(
            app_data={
                "certificate": "CA",
                "addresses": "10.0.0.1:8443",
            }
        )
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                rel,
            ],
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        cmd = out.get_container(CONTAINER_NAME).plan.services[DRIVER_SERVICE_NAME].command
        assert "--lxd-url https://10.0.0.1:8443" in cmd

    def test_lxd_connection_accepts_json_list_addresses(self):
        rel = self._make_relation(
            app_data={
                "certificate": "CA",
                "addresses": '["10.0.0.1:8443", "10.0.0.2:8443"]',
            }
        )
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                rel,
            ],
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        cmd = out.get_container(CONTAINER_NAME).plan.services[DRIVER_SERVICE_NAME].command
        assert "--lxd-url https://10.0.0.1:8443" in cmd

    def test_lxd_connection_rejects_malformed_address(self):
        rel = self._make_relation(
            app_data={
                "certificate": "CA",
                "addresses": "10.0.0.1;rm -rf",
            }
        )
        results = self._run_action(rel)
        assert results["certificate-fingerprint"] == ""

    def test_lxd_connection_ipv6_comma_separated(self):
        rel = Relation(
            LXD_RELATION,
            remote_app_data={
                "certificate": "CA",
                "addresses": "[::1]:8443",
            },
        )
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                rel,
            ],
        )
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_DB_URI),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            ),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_ISSUER),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
        ):
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        cmd = out.get_container(CONTAINER_NAME).plan.services[DRIVER_SERVICE_NAME].command
        assert "--lxd-url https://[::1]:8443" in cmd


class TestLxdFilesAndLayer:
    def test_lxd_cert_files_written(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(LXD_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        assert (fs / "etc" / "openshell" / "lxd" / "client.crt").read_text() == _FAKE_LXD_IDENTITY[
            "certificate"
        ]
        assert (fs / "etc" / "openshell" / "lxd" / "client.key").read_text() == _FAKE_LXD_IDENTITY[
            "private-key"
        ]
        assert (fs / "etc" / "openshell" / "lxd" / "server.crt").read_text() == _LXD_CONN.server_ca
        mode_key = stat.S_IMODE(os.stat(fs / "etc/openshell/lxd/client.key").st_mode)
        assert mode_key == 0o600, f"client.key mode {oct(mode_key)} != 0o600"
        mode_cert = stat.S_IMODE(os.stat(fs / "etc/openshell/lxd/client.crt").st_mode)
        assert mode_cert == 0o644, f"client.crt mode {oct(mode_cert)} != 0o644"

    def test_driver_layer_uses_remote_args(self):
        ctx = Context(OpenshellGatewayK8sCharm, app_name="my-gateway")
        lxd_rel = Relation(LXD_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
            model=Model(name="prod"),
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        plan = out.get_container(CONTAINER_NAME).plan
        cmd = plan.services[DRIVER_SERVICE_NAME].command
        assert f"--lxd-url {_LXD_URL}" in cmd
        assert f"--lxd-client-cert {LXD_CLIENT_CERT_PATH}" in cmd
        assert f"--lxd-client-key {LXD_CLIENT_KEY_PATH}" in cmd
        assert f"--lxd-server-fingerprint {_LXD_CONN.fingerprint}" in cmd
        assert "--lxd-server-ca" not in cmd
        assert f"--default-image {DEFAULT_SANDBOX_IMAGE}" in cmd
        assert "--operation-timeout-secs 60" in cmd
        assert "--log-level info" in cmd
        assert "--gateway-endpoint https://my-gateway.prod.svc.cluster.local:8443" in cmd
        assert "--lxd-socket" not in cmd

    def test_sandbox_tls_files_written(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(LXD_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        sandbox_dir = fs / "etc" / "openshell" / "sandbox-tls"
        assert (sandbox_dir / "ca.crt").read_text() == str(_FAKE_TLS_CERT.ca)
        assert (sandbox_dir / "client.crt").read_text() == _FAKE_SANDBOX_IDENTITY["certificate"]
        assert (sandbox_dir / "client.key").read_text() == _FAKE_SANDBOX_IDENTITY["private-key"]
        mode_key = stat.S_IMODE(os.stat(sandbox_dir / "client.key").st_mode)
        assert mode_key == 0o600, f"sandbox client.key mode {oct(mode_key)} != 0o600"

    def test_lxd_client_identity_never_reaches_a_sandbox(self):
        # The LXD client certificate is an administrative credential. It must
        # stay in the gateway pod, never in the material copied into sandboxes.
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(LXD_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        sandbox_dir = fs / "etc" / "openshell" / "sandbox-tls"
        for name in ("client.crt", "client.key", "ca.crt"):
            content = (sandbox_dir / name).read_text()
            assert _FAKE_LXD_IDENTITY["certificate"] != content
            assert _FAKE_LXD_IDENTITY["private-key"] != content

    def test_driver_layer_passes_guest_tls_material(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(LXD_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        cmd = out.get_container(CONTAINER_NAME).plan.services[DRIVER_SERVICE_NAME].command
        assert f"--guest-tls-ca {SANDBOX_TLS_CA_PATH}" in cmd
        assert f"--guest-tls-cert {SANDBOX_TLS_CERT_PATH}" in cmd
        assert f"--guest-tls-key {SANDBOX_TLS_KEY_PATH}" in cmd
        assert "--allow-plaintext-gateway" not in cmd

    def test_driver_layer_uses_project_from_the_provider(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(
            LXD_RELATION,
            remote_app_data={
                "certificate_fingerprint": "cd" * 32,
                "addresses": "10.0.0.1:8443",
                "project": "openshell",
            },
        )
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with _all_ready(lxd_connection=False):
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        cmd = out.get_container(CONTAINER_NAME).plan.services[DRIVER_SERVICE_NAME].command
        assert "--project openshell" in cmd

    def test_driver_layer_omits_project_when_the_provider_names_none(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(
            LXD_RELATION,
            remote_app_data={
                "certificate_fingerprint": "cd" * 32,
                "addresses": "10.0.0.1:8443",
            },
        )
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with _all_ready(lxd_connection=False):
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        cmd = out.get_container(CONTAINER_NAME).plan.services[DRIVER_SERVICE_NAME].command
        assert "--project" not in cmd

    def test_unusable_project_blocks_instead_of_falling_back(self):
        # Silently dropping the project would place sandboxes in LXD's
        # "default" project, outside the isolation the operator asked for.
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(
            LXD_RELATION,
            remote_app_data={
                "certificate_fingerprint": "cd" * 32,
                "addresses": "10.0.0.1:8443",
                "project": "bad/project",
            },
        )
        state = State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with _all_ready(lxd_connection=False):
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, WaitingStatus)
        assert "lxd connection details" in out.unit_status.message

    def test_driver_layer_uses_fingerprint_when_ca_omitted(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(
            LXD_RELATION,
            remote_app_data={
                "certificate_fingerprint": "cd" * 32,
                "addresses": "10.0.0.1:8443",
            },
        )
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
            model=Model(name="prod"),
        )
        with (
            _all_ready(lxd_connection=False),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_lxd_connection",
                return_value=_LxdConnection(
                    url="https://10.0.0.1:8443",
                    server_ca=None,
                    fingerprint="abc:def",
                ),
            ),
        ):
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        plan = out.get_container(CONTAINER_NAME).plan
        cmd = plan.services[DRIVER_SERVICE_NAME].command
        assert "--lxd-server-fingerprint abc:def" in cmd
        assert "--lxd-server-ca" not in cmd

    def test_driver_layer_prefers_fingerprint_over_ca(self):
        """BG-021: a published fingerprint wins even when a certificate is present.

        LXD's self-signed server certificate carries only the hostname and the
        loopback addresses as SANs, so CA verification rejects the routable
        address the pod dials. Preferring the digest pin is what makes the
        connection work, and lxd-integrator-k8s always publishes both fields.
        """
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                Relation(LXD_RELATION),
            ],
            model=Model(name="prod"),
        )
        with (
            _all_ready(lxd_connection=False),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_lxd_connection",
                return_value=_LxdConnection(
                    url="https://10.0.0.1:8443",
                    server_ca="-----BEGIN CERTIFICATE-----\nSERVERCA\n-----END CERTIFICATE-----",
                    fingerprint="abc:def",
                ),
            ),
        ):
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        cmd = out.get_container(CONTAINER_NAME).plan.services[DRIVER_SERVICE_NAME].command
        assert "--lxd-server-fingerprint abc:def" in cmd
        assert "--lxd-server-ca" not in cmd

    def test_driver_layer_falls_back_to_ca_without_fingerprint(self):
        """A provider that publishes only a certificate still gets CA verification."""
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                Relation(LXD_RELATION),
            ],
            model=Model(name="prod"),
        )
        with (
            _all_ready(lxd_connection=False),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_lxd_connection",
                return_value=_LxdConnection(
                    url="https://10.0.0.1:8443",
                    server_ca="-----BEGIN CERTIFICATE-----\nSERVERCA\n-----END CERTIFICATE-----",
                    fingerprint="",
                ),
            ),
        ):
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        cmd = out.get_container(CONTAINER_NAME).plan.services[DRIVER_SERVICE_NAME].command
        assert f"--lxd-server-cert {LXD_SERVER_CERT_PATH}" in cmd
        assert "--lxd-server-fingerprint" not in cmd

    def test_driver_layer_socket_only_when_no_connection(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        lxd_rel = Relation(LXD_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                PeerRelation(PEER_RELATION),
                lxd_rel,
            ],
        )
        with (
            _all_ready(lxd_connection=False),
            patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=None),
        ):
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        plan = out.get_container(CONTAINER_NAME).plan
        cmd = plan.services[DRIVER_SERVICE_NAME].command
        assert cmd == f"/usr/bin/openshell-driver-lxd --socket {DRIVER_SOCKET}"
        assert "--lxd-url" not in cmd


class TestLxdReadinessGaps:
    def test_lxd_gap_blocked_no_relation(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=[Relation("database"), Relation("certificates"), Relation("oauth")],
        )
        with _all_ready():
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, BlockedStatus)
        assert "lxd relation missing" in out.unit_status.message

    def test_lxd_gap_waiting_no_identity(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                Relation(LXD_RELATION),
            ],
        )
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_DB_URI),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            ),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_ISSUER),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(OpenshellGatewayK8sCharm, "_read_lxd_client_identity", return_value=None),
        ):
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, WaitingStatus)
        assert "lxd client identity" in out.unit_status.message

    def test_gap_waiting_no_sandbox_identity(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                Relation(LXD_RELATION),
            ],
        )
        with (
            _all_ready(),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm, "_read_sandbox_client_identity", return_value=None
            ),
        ):
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, WaitingStatus)
        assert "sandbox client identity" in out.unit_status.message

    def test_lxd_gap_waiting_empty_databag(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                Relation(LXD_RELATION),
            ],
        )
        with (
            _all_ready(lxd_connection=False),
            patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=None),
        ):
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, WaitingStatus)
        assert "lxd connection details" in out.unit_status.message

    def test_lxd_gap_absent_when_ready(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=[
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                Relation(LXD_RELATION),
            ],
        )
        with _all_ready():
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert out.unit_status == ActiveStatus()


class TestLxdHash:
    def _ready_state_with_lxd(self):
        return State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                PeerRelation(RESTART_RELATION),
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                Relation(LXD_RELATION),
            ],
        )

    def test_hash_changes_on_lxd_rotation(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state_with_lxd()
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        peer_rel1 = next(r for r in out1.relations if r.endpoint == RESTART_RELATION)
        hash_before = peer_rel1.local_unit_data[APPLIED_HASH_KEY]

        rotated_identity = {
            "certificate": "-----BEGIN CERTIFICATE-----\nROTATED\n-----END CERTIFICATE-----",
            "private-key": "-----BEGIN PRIVATE KEY-----\nROTATED\n-----END PRIVATE KEY-----",
        }
        with (
            _all_ready(),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_lxd_client_identity",
                return_value=rotated_identity,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_lxd_client_identity",
                return_value=rotated_identity,
            ),
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out2 = ctx.run(ctx.on.config_changed(), out1)

        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel2 = next(r for r in out2.relations if r.endpoint == RESTART_RELATION)
        assert peer_rel2.local_unit_data[APPLIED_HASH_KEY] != hash_before

    def test_hash_changes_on_sandbox_identity_rotation(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state_with_lxd()
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        peer_rel1 = next(r for r in out1.relations if r.endpoint == RESTART_RELATION)
        hash_before = peer_rel1.local_unit_data[APPLIED_HASH_KEY]

        rotated = {
            "certificate": "-----BEGIN CERTIFICATE-----\nSBXROT\n-----END CERTIFICATE-----",
            "private-key": "-----BEGIN PRIVATE KEY-----\nSBXROT\n-----END PRIVATE KEY-----",
        }
        with (
            _all_ready(),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_sandbox_client_identity",
                return_value=rotated,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_sandbox_client_identity",
                return_value=rotated,
            ),
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out2 = ctx.run(ctx.on.config_changed(), out1)

        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel2 = next(r for r in out2.relations if r.endpoint == RESTART_RELATION)
        assert peer_rel2.local_unit_data[APPLIED_HASH_KEY] != hash_before

    def test_hash_changes_on_lxd_address_change(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state_with_lxd()
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        peer_rel1 = next(r for r in out1.relations if r.endpoint == RESTART_RELATION)
        hash_before = peer_rel1.local_unit_data[APPLIED_HASH_KEY]

        new_conn = _LxdConnection(
            url="https://10.0.0.2:8443",
            server_ca=_LXD_CONN.server_ca,
            fingerprint=_LXD_CONN.fingerprint,
        )
        with (
            _all_ready(lxd_connection=False),
            patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=new_conn),
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out2 = ctx.run(ctx.on.config_changed(), out1)

        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel2 = next(r for r in out2.relations if r.endpoint == RESTART_RELATION)
        assert peer_rel2.local_unit_data[APPLIED_HASH_KEY] != hash_before

    def test_hash_stable_when_lxd_unchanged(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = self._ready_state_with_lxd()
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        with (
            _all_ready(),
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out2 = ctx.run(ctx.on.config_changed(), out1)
        restart_mock.assert_not_called()
        peer_rel1 = next(r for r in out1.relations if r.endpoint == RESTART_RELATION)
        peer_rel2 = next(r for r in out2.relations if r.endpoint == RESTART_RELATION)
        assert (
            peer_rel2.local_unit_data[APPLIED_HASH_KEY]
            == peer_rel1.local_unit_data[APPLIED_HASH_KEY]
        )


class TestReplanResilience:
    """Regression tests for BG-022: replan failures must not lock out retries."""

    def test_failed_first_replan_does_not_record_hash_and_retries(self):
        """A transient ChangeError on first replan must not persist the hash.

        If ``_ensure_restart_state`` records the applied-config-hash even though
        ``container.replan()`` raised, every later reconcile sees the hash as
        matching and never retries the replan. In a fresh model this can leave
        the workload services out of the Pebble plan permanently while the
        charm reports no readiness gaps.
        """
        ctx = Context(OpenshellGatewayK8sCharm)
        restart_rel = PeerRelation(RESTART_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=[
                *(_all_relations()),
                PeerRelation(PEER_RELATION),
                restart_rel,
            ],
        )

        calls: list[object] = []

        def flaky_replan(*args: object, **kwargs: object) -> None:
            calls.append(None)
            if len(calls) == 1:
                raise ops.pebble.ChangeError("replan failed", change=None)

        with (
            _all_ready(),
            patch("ops.model.Container.replan", side_effect=flaky_replan),
        ):
            out1 = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)

        restart_data1 = out1.get_relation(restart_rel.id).local_unit_data
        assert APPLIED_HASH_KEY not in restart_data1
        assert len(calls) == 1

        with (
            _all_ready(),
            patch("ops.model.Container.replan", side_effect=flaky_replan),
        ):
            out2 = ctx.run(ctx.on.config_changed(), out1)

        restart_data2 = out2.get_relation(restart_rel.id).local_unit_data
        assert APPLIED_HASH_KEY in restart_data2
        assert len(calls) == 2
        plan = out2.get_container(CONTAINER_NAME).plan
        assert SERVICE_NAME in plan.services
        assert DRIVER_SERVICE_NAME in plan.services


class TestLxdAction:
    def test_get_lxd_client_cert_action(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            containers=[_CONN_CONTAINER],
            relations=[Relation(LXD_RELATION)],
        )
        with (
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_lxd_client_identity",
                return_value=_FAKE_LXD_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_read_sandbox_client_identity",
                return_value=_FAKE_SANDBOX_IDENTITY,
            ),
            patch.object(OpenshellGatewayK8sCharm, "_lxd_connection", return_value=_LXD_CONN),
        ):
            ctx.run(ctx.on.action("get-lxd-client-cert"), state)
        assert ctx.action_results["certificate"] == _FAKE_LXD_IDENTITY["certificate"]
        assert ctx.action_results["certificate-fingerprint"] == _LXD_CONN.fingerprint


class TestMetricsEndpoint:
    """The Prometheus scrape endpoint tracks the metrics-port config option."""

    def _state(self, **config):
        return State(
            config={**BOTH_ROLES, **config},
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=_all_relations() + [PeerRelation(PEER_RELATION)],
        )

    def test_provider_is_constructed_with_the_configured_port(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        with _all_ready():
            state = self._state(**{"metrics-port": 9464})
            with ctx(ctx.on.config_changed(), state) as manager:
                manager.run()
                charm = manager.charm
        assert charm.metrics_endpoint is not None
        jobs = charm.metrics_endpoint._jobs
        assert len(jobs) == 1
        assert jobs[0]["static_configs"] == [{"targets": ["*:9464"]}]
        assert jobs[0]["metrics_path"] == "/metrics"

    def test_provider_is_absent_when_metrics_are_disabled(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        with _all_ready():
            state = self._state(**{"metrics-port": 0})
            with ctx(ctx.on.config_changed(), state) as manager:
                manager.run()
                charm = manager.charm
        assert charm.metrics_endpoint is None

    def test_scrape_job_is_published_to_a_related_collector(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        metrics_rel = Relation(METRICS_RELATION, remote_app_name="opentelemetry-collector-k8s")
        state = State(
            config={**BOTH_ROLES, "metrics-port": 9464},
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=_all_relations() + [PeerRelation(PEER_RELATION), metrics_rel],
        )
        with _all_ready():
            out = ctx.run(ctx.on.relation_joined(metrics_rel), state)
        published = next(r for r in out.relations if r.endpoint == METRICS_RELATION)
        jobs = json.loads(published.local_app_data["scrape_jobs"])
        targets = [t for job in jobs for sc in job["static_configs"] for t in sc["targets"]]
        assert targets == ["*:9464"]

    def test_metrics_port_is_opened(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        with _all_ready():
            out = ctx.run(ctx.on.config_changed(), self._state(**{"metrics-port": 9464}))
        assert TCPPort(9464) in out.opened_ports

    def test_metrics_port_is_closed_when_disabled(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        with _all_ready():
            out1 = ctx.run(ctx.on.config_changed(), self._state(**{"metrics-port": 9464}))
        assert TCPPort(9464) in out1.opened_ports

        disabled = dataclasses.replace(out1, config={**BOTH_ROLES, "metrics-port": 0})
        with _all_ready():
            out2 = ctx.run(ctx.on.config_changed(), disabled)
        assert TCPPort(9464) not in out2.opened_ports
        # The gateway's own listener is untouched.
        assert TCPPort(int(GATEWAY_PORT)) in out2.opened_ports

    def test_env_carries_the_metrics_port(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        with _all_ready():
            out = ctx.run(
                ctx.on.pebble_ready(_CONN_CONTAINER), self._state(**{"metrics-port": 9464})
            )
        env = out.get_container(CONTAINER_NAME).plan.services[SERVICE_NAME].environment
        assert env["OPENSHELL_METRICS_PORT"] == "9464"

    def test_status_action_reports_metrics_state(self):
        # ops surfaces one ActiveStatus, so another component's note can mask
        # the metrics one. The action is the signal that always answers, and
        # the integration test asserts on it for exactly that reason.
        ctx = Context(OpenshellGatewayK8sCharm)
        metrics_rel = Relation(METRICS_RELATION, remote_app_name="opentelemetry-collector-k8s")
        state = State(
            config={**BOTH_ROLES, "metrics-port": 0},
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=_all_relations() + [PeerRelation(PEER_RELATION), metrics_rel],
        )
        with _all_ready():
            ctx.run(ctx.on.action("get-gateway-status"), state)
        assert ctx.action_results["metrics-port"] == "0"
        assert ctx.action_results["metrics-endpoint-related"] == "True"

    def test_status_action_reports_metrics_enabled(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        with _all_ready():
            ctx.run(ctx.on.action("get-gateway-status"), self._state(**{"metrics-port": 9464}))
        assert ctx.action_results["metrics-port"] == "9464"
        assert ctx.action_results["metrics-endpoint-related"] == "False"

    def test_related_collector_with_metrics_off_is_called_out(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        metrics_rel = Relation(METRICS_RELATION, remote_app_name="opentelemetry-collector-k8s")
        state = State(
            config={**BOTH_ROLES, "metrics-port": 0},
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=_all_relations() + [PeerRelation(PEER_RELATION), metrics_rel],
        )
        with _all_ready():
            out = ctx.run(ctx.on.collect_unit_status(), state)
        assert isinstance(out.unit_status, ActiveStatus)
        assert "metrics-port is 0" in out.unit_status.message


class TestSystemCaBundle:
    """The charm's CA is added to the image's bundle without displacing it."""

    _PUBLIC_ROOTS = (
        "-----BEGIN CERTIFICATE-----\nROOTA\n-----END CERTIFICATE-----\n"
        "-----BEGIN CERTIFICATE-----\nROOTB\n-----END CERTIFICATE-----\n"
    )

    def _state(self, container):
        return State(
            config=BOTH_ROLES,
            leader=True,
            containers=[container],
            relations=_all_relations() + [PeerRelation(PEER_RELATION)],
        )

    def test_public_roots_survive_the_charm_ca(self, tmp_path):
        # Running update-ca-certificates against the gateway rock replaces the
        # public roots with the charm CA alone, and the driver then cannot pull
        # a sandbox image from any public registry.
        ctx = Context(OpenshellGatewayK8sCharm)
        container = Container(
            CONTAINER_NAME,
            can_connect=True,
            mounts={"ssl": Mount(location="/etc/ssl/certs", source=tmp_path)},
        )
        (tmp_path / "ca-certificates.crt").write_text(self._PUBLIC_ROOTS)
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(container), self._state(container))

        bundle = (tmp_path / "ca-certificates.crt").read_text()
        assert "ROOTA" in bundle
        assert "ROOTB" in bundle
        assert str(_FAKE_TLS_CERT.ca) in bundle
        assert out.unit_status is not None

    def test_repeated_reconciles_do_not_accumulate(self, tmp_path):
        ctx = Context(OpenshellGatewayK8sCharm)
        container = Container(
            CONTAINER_NAME,
            can_connect=True,
            mounts={"ssl": Mount(location="/etc/ssl/certs", source=tmp_path)},
        )
        (tmp_path / "ca-certificates.crt").write_text(self._PUBLIC_ROOTS)
        with _all_ready():
            out1 = ctx.run(ctx.on.pebble_ready(container), self._state(container))
            ctx.run(ctx.on.config_changed(), out1)

        bundle = (tmp_path / "ca-certificates.crt").read_text()
        assert bundle.count(str(_FAKE_TLS_CERT.ca).strip().splitlines()[1]) == 1
        assert bundle.count("ROOTA") == 1


class TestGrafanaDashboard:
    """The charm ships a dashboard built on the metrics it actually exports."""

    _DASHBOARD = Path(__file__).parent.parent.parent / "src" / "grafana_dashboards"

    def test_dashboard_file_is_valid_json(self):
        files = sorted(self._DASHBOARD.glob("*.json"))
        assert files, "no dashboard shipped in src/grafana_dashboards"
        for path in files:
            json.loads(path.read_text())

    def test_dashboard_queries_only_metrics_the_gateway_exports(self):
        # A panel querying a metric the workload never emits renders an empty
        # graph and looks like an outage. These are the names registered in
        # OpenShell v0.0.116's openshell-server crate.
        exported = {
            "up",
            "openshell_server_grpc_requests_total",
            "openshell_server_grpc_request_duration_seconds",
            "openshell_server_http_requests_total",
            "openshell_server_readiness_database_healthy",
            "openshell_server_readiness_database_probe_duration_seconds",
        }
        pattern = re.compile(r"\b(openshell_[a-z0-9_]+|up)\b")
        for path in sorted(self._DASHBOARD.glob("*.json")):
            dashboard = json.loads(path.read_text())
            for panel in dashboard["panels"]:
                for target in panel.get("targets", []):
                    for name in pattern.findall(target["expr"]):
                        assert name in exported, f"{path.name}: unknown metric {name}"

    def test_durations_are_read_as_summaries_not_histograms(self):
        # OpenShell's exporter renders its `histogram!` metrics as Prometheus
        # *summaries*, with pre-computed quantile labels. There are no _bucket
        # series, so histogram_quantile() silently returns nothing and the
        # panel looks like an outage. Verified against a live gateway:
        # `# TYPE openshell_server_grpc_request_duration_seconds summary`.
        for path in sorted(self._DASHBOARD.glob("*.json")):
            dashboard = json.loads(path.read_text())
            for panel in dashboard["panels"]:
                for target in panel.get("targets", []):
                    expr = target["expr"]
                    assert "_bucket" not in expr, panel["title"]
                    assert "histogram_quantile" not in expr, panel["title"]
                    if "duration_seconds" in expr:
                        assert "quantile=" in expr, panel["title"]

    def test_every_panel_is_scoped_by_juju_topology(self):
        # Without the topology selectors one model's dashboard shows another
        # model's data.
        for path in sorted(self._DASHBOARD.glob("*.json")):
            dashboard = json.loads(path.read_text())
            names = {var["name"] for var in dashboard["templating"]["list"]}
            assert {"juju_model", "juju_model_uuid", "juju_application", "juju_unit"} <= names
            for panel in dashboard["panels"]:
                for target in panel.get("targets", []):
                    assert "juju_model=~" in target["expr"], panel["title"]
                    assert "juju_application=~" in target["expr"], panel["title"]

    def test_dashboard_is_published_to_a_related_grafana(self):
        # charm_root points at the real charm directory: the provider reads the
        # dashboards off disk relative to it, and Scenario's default root is an
        # empty temporary directory that has no src/grafana_dashboards.
        ctx = Context(OpenshellGatewayK8sCharm, charm_root=self._DASHBOARD.parent.parent)
        rel = Relation(DASHBOARD_RELATION, remote_app_name="grafana-k8s")
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=_all_relations() + [PeerRelation(PEER_RELATION), rel],
        )
        with _all_ready():
            # The library scans the dashboards directory on config-changed,
            # leader-elected and upgrade-charm, not on relation-joined.
            out = ctx.run(ctx.on.config_changed(), state)
        published = next(r for r in out.relations if r.endpoint == DASHBOARD_RELATION)
        assert published.local_app_data.get("dashboards"), published.local_app_data
        assert "openshell-gateway" in published.local_app_data["dashboards"]


class TestReceivedCaCertificates:
    """CAs transferred over receive-ca-cert join the workload's trust bundle."""

    _ROOTS = "-----BEGIN CERTIFICATE-----\nROOTA\n-----END CERTIFICATE-----\n"
    _IDENTITY_CA = "-----BEGIN CERTIFICATE-----\nIDENTITYCA\n-----END CERTIFICATE-----\n"

    def _container(self, tmp_path):
        (tmp_path / "ca-certificates.crt").write_text(self._ROOTS)
        return Container(
            CONTAINER_NAME,
            can_connect=True,
            mounts={"ssl": Mount(location="/etc/ssl/certs", source=tmp_path)},
        )

    def _state(self, container, relations):
        return State(
            config=BOTH_ROLES,
            leader=True,
            containers=[container],
            relations=_all_relations() + [PeerRelation(PEER_RELATION)] + relations,
        )

    def test_transferred_ca_is_added_to_the_bundle(self, tmp_path):
        # The identity provider's issuer is signed by a CA the workload image
        # does not know, and OIDC discovery fails to verify it without this.
        ctx = Context(OpenshellGatewayK8sCharm)
        container = self._container(tmp_path)
        rel = Relation(RECEIVE_CA_RELATION, remote_app_name="hydra")
        with (
            _all_ready(),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_received_ca_certificates",
                return_value={self._IDENTITY_CA},
            ),
        ):
            ctx.run(ctx.on.pebble_ready(container), self._state(container, [rel]))
        bundle = (tmp_path / "ca-certificates.crt").read_text()
        assert "ROOTA" in bundle
        assert "IDENTITYCA" in bundle
        assert str(_FAKE_TLS_CERT.ca) in bundle

    def test_no_relation_means_no_extra_cas(self, tmp_path):
        ctx = Context(OpenshellGatewayK8sCharm)
        container = self._container(tmp_path)
        with (
            _all_ready(),
            ctx(ctx.on.pebble_ready(container), self._state(container, [])) as manager,
        ):
            manager.run()
            assert manager.charm._received_ca_certificates() == set()

    def test_bundle_is_stable_across_reconciles(self, tmp_path):
        # An unstable ordering would change the workload config hash and
        # restart the gateway on every hook.
        ctx = Context(OpenshellGatewayK8sCharm)
        container = self._container(tmp_path)
        rel = Relation(RECEIVE_CA_RELATION, remote_app_name="hydra")
        second = "-----BEGIN CERTIFICATE-----\nOTHERCA\n-----END CERTIFICATE-----\n"
        with (
            _all_ready(),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_received_ca_certificates",
                return_value={self._IDENTITY_CA, second},
            ),
        ):
            out1 = ctx.run(ctx.on.pebble_ready(container), self._state(container, [rel]))
            first = (tmp_path / "ca-certificates.crt").read_text()
            ctx.run(ctx.on.config_changed(), out1)
        assert (tmp_path / "ca-certificates.crt").read_text() == first
        assert first.count("IDENTITYCA") == 1
        assert first.count("OTHERCA") == 1


class TestSandboxEgressRestriction:
    """The driver confines a sandbox only when the charm asks it to."""

    def _command(self, **config):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config={**BOTH_ROLES, **config},
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=_all_relations() + [PeerRelation(PEER_RELATION)],
        )
        with _all_ready():
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        return out.get_container(CONTAINER_NAME).plan.services[DRIVER_SERVICE_NAME].command

    def test_egress_is_restricted_by_default(self):
        # Sandboxes run untrusted agent workloads. Unrestricted, one reaches
        # the LAN it sits on, the LXD host and the LXD API itself.
        assert "--restrict-sandbox-egress" in self._command()

    def test_the_operator_can_turn_it_off_for_a_bridge(self):
        # LXD applies network ACLs to individual NICs only on OVN networks.
        assert "--restrict-sandbox-egress" not in self._command(
            **{"restrict-sandbox-egress": False}
        )


class TestWorkloadHealthInStatus:
    """A workload service that exits must not leave the unit reporting Active."""

    def _status(self, *, driver_up=True, gateway_up=True, checks=None, converged=True):
        ctx = Context(OpenshellGatewayK8sCharm)
        relations = _all_relations() + [PeerRelation(PEER_RELATION)]
        if converged:
            relations.append(
                PeerRelation(
                    RESTART_RELATION, local_unit_data={APPLIED_HASH_KEY: "converged-once"}
                )
            )
        else:
            relations.append(PeerRelation(RESTART_RELATION))
        state = State(
            config=BOTH_ROLES,
            leader=True,
            model=Model(name="my-model"),
            containers=[_CONN_CONTAINER],
            relations=relations,
        )

        def services(_self, *_args, **_kwargs):
            def info(up):
                return SimpleNamespace(is_running=lambda: up)

            return {
                SERVICE_NAME: info(gateway_up),
                DRIVER_SERVICE_NAME: info(driver_up),
            }

        with (
            _all_ready(),
            patch.object(ops.model.Container, "get_services", services),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_check_status",
                return_value=checks if checks is not None else {},
            ),
        ):
            out = ctx.run(ctx.on.collect_unit_status(), state)
        return out.unit_status

    def test_a_dead_driver_is_not_active(self):
        # Bad driver arguments, a missing LXD project or an unreachable
        # registry all look like this, and used to leave the unit Active with
        # an empty readiness-gaps until a sandbox create failed.
        status = self._status(driver_up=False)
        assert isinstance(status, WaitingStatus)
        assert "lxd driver service is not running" in status.message

    def test_a_dead_gateway_is_not_active(self):
        status = self._status(gateway_up=False)
        assert isinstance(status, WaitingStatus)
        assert "gateway service is not running" in status.message

    def test_a_failing_check_is_not_active(self):
        status = self._status(checks={DRIVER_CHECK_NAME: False, READINESS_CHECK_NAME: True})
        assert isinstance(status, WaitingStatus)
        assert DRIVER_CHECK_NAME in status.message

    def test_a_healthy_workload_is_active(self):
        status = self._status(
            checks={DRIVER_CHECK_NAME: True, READINESS_CHECK_NAME: True},
        )
        assert isinstance(status, ActiveStatus)

    def test_services_absent_before_the_first_convergence_are_not_a_gap(self):
        # Before the charm has converged once the services are absent by
        # design, and the relation gaps are the story.
        assert isinstance(self._status(driver_up=False, converged=False), ActiveStatus)


class TestTrustBundleRestartsTheWorkload:
    """Changing the workload's trust anchors has to reach the running process."""

    _IDENTITY_CA = "-----BEGIN CERTIFICATE-----\nIDENTITYCA\n-----END CERTIFICATE-----\n"

    def _hash(self, received):
        ctx = Context(OpenshellGatewayK8sCharm)
        restart_rel = PeerRelation(RESTART_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            # Fixed, because the gateway endpoint the driver command carries is
            # built from the model name and a random one would make the hash
            # differ for reasons that have nothing to do with trust.
            model=Model(name="my-model"),
            containers=[_CONN_CONTAINER],
            relations=_all_relations() + [PeerRelation(PEER_RELATION), restart_rel],
        )
        with (
            _all_ready(),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_received_ca_certificates",
                return_value=received,
            ),
        ):
            out = ctx.run(ctx.on.pebble_ready(_CONN_CONTAINER), state)
        rel = next(r for r in out.relations if r.endpoint == RESTART_RELATION)
        return rel.local_unit_data.get(APPLIED_HASH_KEY)

    def test_a_new_trust_anchor_changes_the_workload_hash(self):
        # Otherwise relating receive-ca-cert rewrites the trust store and the
        # workload keeps using the roots it loaded at start-up.
        assert self._hash(set()) != self._hash({self._IDENTITY_CA})

    def test_the_same_anchors_leave_the_hash_alone(self):
        assert self._hash({self._IDENTITY_CA}) == self._hash({self._IDENTITY_CA})


class TestPushOnlyWhatChanged:
    """_reconcile runs on every hook; rewriting every file each time is waste."""

    def test_an_unchanged_file_is_not_pushed_again(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=_all_relations() + [PeerRelation(PEER_RELATION)],
        )
        with (
            _all_ready(),
            ctx(ctx.on.pebble_ready(_CONN_CONTAINER), state) as manager,
        ):
            manager.run()
            charm = manager.charm
            container = charm.unit.get_container(CONTAINER_NAME)
            with patch("ops.model.Container.push") as push_mock:
                charm._push_if_changed(
                    container, CONFIG_PATH, container.pull(CONFIG_PATH).read(), 0o600
                )
                assert push_mock.call_count == 0
                charm._push_if_changed(container, CONFIG_PATH, "something else", 0o600)
                assert push_mock.call_count == 1
