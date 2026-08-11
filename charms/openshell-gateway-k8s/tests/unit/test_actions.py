"""Unit tests for charm actions: get-oidc-client-config and get-gateway-status."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from ops.testing import Container, Context, PeerRelation, Relation, State

from charm import (
    APPLIED_HASH_KEY,
    CONTAINER_NAME,
    DRIVER_SERVICE_NAME,
    RESTART_RELATION,
    SERVICE_NAME,
    OpenshellGatewayK8sCharm,
)

BOTH_ROLES = {"oidc-admin-role": "admin", "oidc-user-role": "user"}

_FAKE_TLS_CERT = MagicMock(
    certificate="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
    ca="-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----",
)
_FAKE_TLS_KEY = MagicMock(raw="-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----")

_FAKE_JWT = {
    "signing-key": "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----",
    "public-key": "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----",
    "kid": "testkid",
}


def _fake_provider_info():
    info = MagicMock()
    info.issuer_url = "https://hydra.example.com"
    info.authorization_endpoint = "https://hydra.example.com/oauth2/auth"
    info.token_endpoint = "https://hydra.example.com/oauth2/token"
    info.jwks_endpoint = "https://hydra.example.com/.well-known/jwks.json"
    return info


class TestGetOidcClientConfig:
    def test_returns_correct_fields_when_ready(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(config=BOTH_ROLES, containers=[Container(CONTAINER_NAME, can_connect=True)])
        with patch(
            "charms.hydra.v0.oauth.OAuthRequirer.get_provider_info",
            return_value=_fake_provider_info(),
        ):
            ctx.run(ctx.on.action("get-oidc-client-config"), state)
        results = ctx.action_results
        assert results["issuer"] == "https://hydra.example.com"
        assert results["audience"] == "openshell-cli"
        assert results["scopes"] == "openid profile email"
        assert "authorization-endpoint" in results

    def test_fails_when_oauth_not_ready(self):
        import pytest
        from ops._private.harness import ActionFailed

        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(config=BOTH_ROLES, containers=[Container(CONTAINER_NAME, can_connect=True)])
        with (
            patch(
                "charms.hydra.v0.oauth.OAuthRequirer.get_provider_info",
                return_value=None,
            ),
            pytest.raises(ActionFailed),
        ):
            ctx.run(ctx.on.action("get-oidc-client-config"), state)


class TestGetGatewayStatus:
    def test_returns_expected_keys_when_all_ready(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config=BOTH_ROLES,
            containers=[Container(CONTAINER_NAME, can_connect=True)],
        )
        with (
            patch.object(
                OpenshellGatewayK8sCharm,
                "_database_uri",
                return_value="postgresql://u:p@db/openshell?sslmode=require",
            ),
            patch.object(
                OpenshellGatewayK8sCharm, "_tls_material", return_value=(MagicMock(), MagicMock())
            ),
            patch.object(
                OpenshellGatewayK8sCharm, "_oauth_issuer", return_value="https://hydra.example.com"
            ),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=_FAKE_JWT),
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
        ):
            ctx.run(ctx.on.action("get-gateway-status"), state)
        results = ctx.action_results
        assert "workload-running" in results
        assert "jwt-kid" in results
        assert results["jwt-kid"] == "testkid"
        assert results["database-ready"] == "True"

    def test_returns_not_ready_when_missing(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(config=BOTH_ROLES, containers=[Container(CONTAINER_NAME, can_connect=False)])
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=None),
            patch.object(OpenshellGatewayK8sCharm, "_tls_material", return_value=(None, None)),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=None),
            patch.object(OpenshellGatewayK8sCharm, "_ensure_jwt_keypair", return_value=None),
        ):
            ctx.run(ctx.on.action("get-gateway-status"), state)
        results = ctx.action_results
        assert results["database-ready"] == "False"
        assert results["workload-running"] == "False"


class TestRestartAction:
    def test_restart_action_restarts_and_updates_hash(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        restart_rel = PeerRelation(RESTART_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[Container(CONTAINER_NAME, can_connect=True)],
            relations=[
                restart_rel,
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
            ],
        )
        with (
            patch.object(
                OpenshellGatewayK8sCharm,
                "_database_uri",
                return_value="******db/openshell?sslmode=require",
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_oauth_issuer",
                return_value="https://hydra.example.com",
            ),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_ensure_jwt_keypair",
                return_value=_FAKE_JWT,
            ),
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out = ctx.run(ctx.on.action("restart"), state)

        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel = next(r for r in out.relations if r.endpoint == RESTART_RELATION)
        assert APPLIED_HASH_KEY in peer_rel.local_unit_data
