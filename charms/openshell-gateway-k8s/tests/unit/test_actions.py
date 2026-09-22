"""Unit tests for charm actions: get-oidc-client-config and get-gateway-status."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import hashes
from ops.testing import Container, Context, PeerRelation, Relation, Secret, State

from charm import (
    APPLIED_HASH_KEY,
    CONTAINER_NAME,
    DRIVER_SERVICE_NAME,
    LXD_RELATION,
    PEER_RELATION,
    PEER_SANDBOX_SECRET_ID_KEY,
    PEER_SANDBOX_SECRET_LABEL,
    PEER_SECRET_ID_KEY,
    RESTART_RELATION,
    SERVICE_NAME,
    OpenshellGatewayK8sCharm,
    _LxdConnection,
)

BOTH_ROLES = {"oidc-admin-role": "admin", "oidc-user-role": "user"}

_FAKE_DB_URI = "postgresql://user:pass@db/openshell?sslmode=require"
_FAKE_OAUTH_ISSUER = "https://hydra.example.com"

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

_FAKE_LXD_IDENTITY = {
    "certificate": "-----BEGIN CERTIFICATE-----\nLXDCERT\n-----END CERTIFICATE-----",
    "private-key": "-----BEGIN PRIVATE KEY-----\nLXDKEY\n-----END PRIVATE KEY-----",
}
_FAKE_SANDBOX_IDENTITY = {
    "certificate": "-----BEGIN CERTIFICATE-----\nSBXCERT\n-----END CERTIFICATE-----",
    "private-key": "-----BEGIN PRIVATE KEY-----\nSBXKEY\n-----END PRIVATE KEY-----",
}
_LXD_CONN = _LxdConnection(
    url="https://10.0.0.1:8443",
    server_ca="-----BEGIN CERTIFICATE-----\nSERVERCA\n-----END CERTIFICATE-----",
    fingerprint="ab:cd:ef",
)


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
                Relation(LXD_RELATION),
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
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out = ctx.run(ctx.on.action("restart"), state)

        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel = next(r for r in out.relations if r.endpoint == RESTART_RELATION)
        assert APPLIED_HASH_KEY in peer_rel.local_unit_data


class TestRotateJwtSigningKey:
    _OLD_JWT = {
        "signing-key": "-----BEGIN PRIVATE KEY-----\nOLDSIGN\n-----END PRIVATE KEY-----",
        "public-key": "-----BEGIN PUBLIC KEY-----\nOLDPUB\n-----END PUBLIC KEY-----",
        "kid": "oldkid",
    }

    def _state_with_secret(self, secret, leader=False):
        peer_rel = PeerRelation(
            PEER_RELATION,
            local_app_data={PEER_SECRET_ID_KEY: secret.id},
        )
        return State(
            config=BOTH_ROLES,
            containers=[Container(CONTAINER_NAME, can_connect=True)],
            relations=[peer_rel],
            secrets=[secret],
            leader=leader,
        )

    def test_non_leader_fails(self):
        import pytest
        from ops._private.harness import ActionFailed

        ctx = Context(OpenshellGatewayK8sCharm)
        secret = Secret(tracked_content=self._OLD_JWT, owner="app")
        state = self._state_with_secret(secret, leader=False)
        with pytest.raises(ActionFailed) as exc_info:
            ctx.run(ctx.on.action("rotate-jwt-signing-key"), state)
        assert exc_info.value.message == "rotate-jwt-signing-key must run on the leader unit"
        assert secret.latest_content == self._OLD_JWT

    def test_uninitialised_secret_fails(self):
        import pytest
        from ops._private.harness import ActionFailed

        ctx = Context(OpenshellGatewayK8sCharm)
        peer_rel = PeerRelation(PEER_RELATION, local_app_data={})
        state = State(
            config=BOTH_ROLES,
            containers=[Container(CONTAINER_NAME, can_connect=True)],
            relations=[peer_rel],
            leader=True,
        )
        with pytest.raises(ActionFailed) as exc_info:
            ctx.run(ctx.on.action("rotate-jwt-signing-key"), state)
        assert (
            exc_info.value.message
            == "JWT signing-key secret not initialised yet; wait for the charm to become ready"
        )
        assert not ctx._output_state.secrets

    def test_leader_creates_revision_and_returns_new_kid(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        secret = Secret(tracked_content=self._OLD_JWT, owner="app")
        state = self._state_with_secret(secret, leader=True)
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=None),
            patch.object(OpenshellGatewayK8sCharm, "_tls_material", return_value=(None, None)),
            patch.object(OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=None),
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
            out = ctx.run(ctx.on.action("rotate-jwt-signing-key"), state)
        results = ctx.action_results
        assert results["kid"] != self._OLD_JWT["kid"]
        assert results["kid"]
        updated_secret = next(s for s in out.secrets if s.id == secret.id)
        assert updated_secret.latest_content["kid"] == results["kid"]

    def test_leader_rotation_replans_when_ready(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        secret = Secret(tracked_content=self._OLD_JWT, owner="app")
        state = self._state_with_secret(secret, leader=True)
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_FAKE_DB_URI),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            ),
            patch.object(
                OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_FAKE_OAUTH_ISSUER
            ),
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
            out = ctx.run(ctx.on.action("rotate-jwt-signing-key"), state)
        results = ctx.action_results
        updated_secret = next(s for s in out.secrets if s.id == secret.id)
        assert updated_secret.latest_content["kid"] == results["kid"]
        assert results["kid"] != self._OLD_JWT["kid"]
        fs = out.get_container(CONTAINER_NAME).get_filesystem(ctx)
        assert (
            fs / "etc" / "openshell" / "jwt" / "signing.key"
        ).read_text() == updated_secret.latest_content["signing-key"]
        assert (
            fs / "etc" / "openshell" / "jwt" / "public.pem"
        ).read_text() == updated_secret.latest_content["public-key"]
        assert SERVICE_NAME in out.get_container(CONTAINER_NAME).plan.services

    def test_leader_rotation_invalidates_hash_and_restarts_workload(self):
        """Running rotate-jwt-signing-key changes the workload hash and triggers a restart."""
        ctx = Context(OpenshellGatewayK8sCharm)
        secret = Secret(tracked_content=self._OLD_JWT, owner="app")
        peer_rel = PeerRelation(
            PEER_RELATION,
            local_app_data={PEER_SECRET_ID_KEY: secret.id},
        )
        restart_rel = PeerRelation(RESTART_RELATION)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[Container(CONTAINER_NAME, can_connect=True)],
            relations=[
                peer_rel,
                restart_rel,
                Relation("database"),
                Relation("certificates"),
                Relation("oauth"),
                Relation(LXD_RELATION),
            ],
            secrets=[secret],
        )
        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_FAKE_DB_URI),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            ),
            patch.object(
                OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_FAKE_OAUTH_ISSUER
            ),
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
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out1 = ctx.run(ctx.on.pebble_ready(Container(CONTAINER_NAME, can_connect=True)), state)

        peer_rel1 = next(r for r in out1.relations if r.endpoint == RESTART_RELATION)
        hash_before = peer_rel1.local_unit_data[APPLIED_HASH_KEY]

        with (
            patch.object(OpenshellGatewayK8sCharm, "_database_uri", return_value=_FAKE_DB_URI),
            patch.object(
                OpenshellGatewayK8sCharm,
                "_tls_material",
                return_value=(_FAKE_TLS_CERT, _FAKE_TLS_KEY),
            ),
            patch.object(
                OpenshellGatewayK8sCharm, "_oauth_issuer", return_value=_FAKE_OAUTH_ISSUER
            ),
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
            patch("ops.model.Container.restart") as restart_mock,
        ):
            out2 = ctx.run(ctx.on.action("rotate-jwt-signing-key"), out1)

        results = ctx.action_results
        assert results["kid"] != self._OLD_JWT["kid"]
        restart_mock.assert_called_once_with(SERVICE_NAME, DRIVER_SERVICE_NAME)
        peer_rel2 = next(r for r in out2.relations if r.endpoint == RESTART_RELATION)
        hash_after = peer_rel2.local_unit_data[APPLIED_HASH_KEY]
        assert hash_after != hash_before


class TestGatewayStatusReportsWhatStatusCannotSay:
    """ops surfaces one ActiveStatus, so the facts an operator needs live here."""

    def _results(self, **config):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = State(
            config={**BOTH_ROLES, **config},
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
            patch.object(OpenshellGatewayK8sCharm, "_read_jwt_keypair", return_value=_FAKE_JWT),
        ):
            ctx.run(ctx.on.action("get-gateway-status"), state)
        return ctx.action_results

    def test_the_driver_has_its_own_running_flag(self):
        # workload-running only ever spoke for the gateway service; a driver
        # that keeps exiting is what a broken deployment actually looks like.
        assert self._results()["driver-running"] == "False"

    def test_image_verification_being_off_is_reported(self):
        # An operator should not have to read `juju config` to find out that
        # the supervisor image is pulled without verifying TLS.
        results = self._results(**{"insecure-registries": "192.168.1.166:5000, reg.example"})
        assert results["insecure-registries"] == "192.168.1.166:5000, reg.example"
        assert self._results()["insecure-registries"] == "none"

    def test_the_sandbox_egress_restriction_is_reported(self):
        assert self._results()["sandbox-egress-restricted"] == "True"
        assert (
            self._results(**{"restrict-sandbox-egress": False})["sandbox-egress-restricted"]
            == "False"
        )

    def test_the_images_sandboxes_are_built_from_are_reported(self):
        results = self._results(
            **{"sandbox-image": "reg.example/base:1", "supervisor-image": "reg.example/sup:1"}
        )
        assert results["sandbox-image"] == "reg.example/base:1"
        assert results["supervisor-image"] == "reg.example/sup:1"

    def test_the_number_of_transferred_trust_anchors_is_reported(self):
        assert self._results()["received-ca-certificates"] == "0"


class TestRotateSandboxClientIdentity:
    """Rotating the sandbox identity has to rotate the CA, not just the leaf."""

    def _state(self, *, leader=True, with_secret=True):
        relations = [
            Relation("database"),
            Relation("certificates"),
            Relation("oauth"),
            Relation(LXD_RELATION),
        ]
        secrets = []
        if with_secret:
            secret = Secret(
                tracked_content={
                    "ca-certificate": "-----BEGIN CERTIFICATE-----\nOLDCA\n-----END CERTIFICATE-----",
                    "ca-private-key": "-----BEGIN PRIVATE KEY-----\nOLDCAKEY\n-----END PRIVATE KEY-----",
                    "certificate": "-----BEGIN CERTIFICATE-----\nOLDLEAF\n-----END CERTIFICATE-----",
                    "private-key": "-----BEGIN PRIVATE KEY-----\nOLDLEAFKEY\n-----END PRIVATE KEY-----",
                },
                label=PEER_SANDBOX_SECRET_LABEL,
                owner="app",
            )
            secrets.append(secret)
            relations.append(
                PeerRelation(PEER_RELATION, local_app_data={PEER_SANDBOX_SECRET_ID_KEY: secret.id})
            )
        else:
            relations.append(PeerRelation(PEER_RELATION))
        return State(
            config=BOTH_ROLES,
            leader=leader,
            containers=[Container(CONTAINER_NAME, can_connect=True)],
            relations=relations,
            secrets=secrets,
        )

    def test_it_mints_a_new_ca_and_a_leaf_issued_by_it(self):
        from cryptography import x509

        ctx = Context(OpenshellGatewayK8sCharm)
        out = ctx.run(ctx.on.action("rotate-sandbox-client-identity"), self._state())

        content = out.get_secret(label=PEER_SANDBOX_SECRET_LABEL).latest_content
        assert content is not None
        assert "OLDCA" not in content["ca-certificate"]
        assert "OLDLEAF" not in content["certificate"]

        ca = x509.load_pem_x509_certificate(content["ca-certificate"].encode())
        leaf = x509.load_pem_x509_certificate(content["certificate"].encode())
        assert leaf.issuer == ca.subject

        results = ctx.action_results
        assert results is not None
        assert results["ca-fingerprint"] == ca.fingerprint(hashes.SHA256()).hex()
        assert results["certificate-fingerprint"] == leaf.fingerprint(hashes.SHA256()).hex()
        # The disruption is the whole reason to say something here.
        assert "recreate" in results["note"]

    def test_a_follower_refuses(self):
        import pytest
        from ops._private.harness import ActionFailed

        ctx = Context(OpenshellGatewayK8sCharm)
        with pytest.raises(ActionFailed, match="leader"):
            ctx.run(
                ctx.on.action("rotate-sandbox-client-identity"),
                self._state(leader=False),
            )

    def test_it_refuses_before_the_identity_exists(self):
        import pytest
        from ops._private.harness import ActionFailed

        ctx = Context(OpenshellGatewayK8sCharm)
        with pytest.raises(ActionFailed, match="not initialised"):
            ctx.run(
                ctx.on.action("rotate-sandbox-client-identity"),
                self._state(with_secret=False),
            )
