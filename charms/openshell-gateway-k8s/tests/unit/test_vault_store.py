"""Unit tests for the optional Vault-backed JWT signing-key store."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from ops import WaitingStatus
from ops.testing import Context, PeerRelation, Relation, Secret, State

import vault_store
from charm import (
    PEER_RELATION,
    VAULT_RELATION,
    OpenshellGatewayK8sCharm,
)
from vault_store import VaultUnavailableError

from .test_charm import (
    _CONN_CONTAINER,
    _FAKE_JWT,
    BOTH_ROLES,
    _all_ready_patches,
    _all_relations,
)

VAULT_APP = "vault-k8s"
CREDENTIALS_SECRET_ID = "secret:0123456789abcdefghij"
_STORED = {
    "signing-key": "-----BEGIN PRIVATE KEY-----\nVAULTSIGN\n-----END PRIVATE KEY-----",
    "public-key": "-----BEGIN PUBLIC KEY-----\nVAULTPUB\n-----END PUBLIC KEY-----",
    "kid": "vaultkid",
}


def _vault_relation(*, ready: bool = True, nonce: str | None = None) -> Relation:
    """Return a vault-kv relation, optionally with everything a ready one has."""
    if not ready:
        return Relation(VAULT_RELATION, remote_app_name=VAULT_APP)
    unit_nonce = nonce or _expected_nonce()
    return Relation(
        VAULT_RELATION,
        remote_app_name=VAULT_APP,
        remote_app_data={
            "vault_url": "https://vault.example:8200",
            "ca_certificate": "-----BEGIN CERTIFICATE-----\nVAULTCA\n-----END CERTIFICATE-----",
            "mount": "charm-openshell-gateway-k8s-kv",
            "credentials": f'{{"{unit_nonce}": "{CREDENTIALS_SECRET_ID}"}}',
        },
        local_unit_data={"nonce": unit_nonce, "egress_subnet": "10.1.0.0/16"},
    )


def _expected_nonce() -> str:
    import hashlib

    return hashlib.sha256(b"openshell-gateway-k8s/0").hexdigest()[:32]


def _credentials_secret() -> Secret:
    return Secret(
        id=CREDENTIALS_SECRET_ID,
        tracked_content={"role-id": "role", "role-secret-id": "role-secret"},
    )


def _state(vault_rel: Relation | None, **kwargs) -> State:
    relations = _all_relations() + [PeerRelation(PEER_RELATION)]
    secrets = set()
    if vault_rel is not None:
        relations.append(vault_rel)
        secrets.add(_credentials_secret())
    return State(
        config=BOTH_ROLES,
        leader=kwargs.pop("leader", True),
        containers=[_CONN_CONTAINER],
        relations=relations,
        secrets=secrets,
        **kwargs,
    )


class _FakeVaultClient:
    """Stands in for hvac.Client, recording reads and writes."""

    def __init__(self, stored: dict[str, str] | None = None, fail: bool = False):
        self.stored = dict(stored) if stored else None
        self.fail = fail
        self.writes: list[dict[str, str]] = []
        self.secrets = MagicMock()
        self.secrets.kv.v2.read_secret.side_effect = self._read
        self.secrets.kv.v2.create_or_update_secret.side_effect = self._write

    def _read(self, path: str, mount_point: str):
        if self.fail:
            raise RuntimeError("vault is sealed")
        if self.stored is None:
            raise InvalidPathError("no such secret")
        return {"data": {"data": dict(self.stored)}}

    def _write(self, path: str, secret: dict, mount_point: str):
        if self.fail:
            raise RuntimeError("vault is sealed")
        self.writes.append(dict(secret))
        self.stored = dict(secret)


class InvalidPathError(Exception):
    """Stands in for hvac's InvalidPath, which vault_store matches by name."""


# vault_store identifies "no such secret" by the exception's class name, which
# upstream spells without an Error suffix. The stand-in reports that name so
# the test exercises the string the charm will actually see.
InvalidPathError.__name__ = "InvalidPath"


def _patch_client(client: _FakeVaultClient):
    return patch.object(
        vault_store.VaultJwtStore, "_connected_client", return_value=(client, "mount")
    )


class TestStoreSelection:
    def test_juju_secret_is_used_when_vault_is_not_related(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        p = _all_ready_patches()
        with (
            p[0],
            p[1],
            p[2],
            p[5],
            p[6],
            p[7],
            ctx(ctx.on.config_changed(), _state(None)) as manager,
        ):
            manager.run()
            charm = manager.charm
            assert charm.vault.is_related() is False
            with patch.object(
                OpenshellGatewayK8sCharm,
                "_read_juju_jwt_keypair",
                return_value=_FAKE_JWT,
            ):
                assert charm._read_jwt_keypair() == _FAKE_JWT

    def test_vault_is_authoritative_once_related_and_ready(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        client = _FakeVaultClient(stored=_STORED)
        p = _all_ready_patches()
        with (
            p[0],
            p[1],
            p[2],
            p[5],
            p[6],
            p[7],
            _patch_client(client),
            ctx(ctx.on.config_changed(), _state(_vault_relation())) as manager,
        ):
            manager.run()
            charm = manager.charm
            assert charm.vault.is_ready() is True
            assert charm._read_jwt_keypair() == _STORED

    def test_joined_but_not_ready_waits_instead_of_falling_back(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]:
            out = ctx.run(ctx.on.collect_unit_status(), _state(_vault_relation(ready=False)))
        assert isinstance(out.unit_status, WaitingStatus)
        assert "vault-kv" in out.unit_status.message


class TestMigration:
    def test_existing_juju_keypair_is_copied_into_an_empty_vault(self):
        # The key live sandbox tokens were signed with has to survive the move.
        ctx = Context(OpenshellGatewayK8sCharm)
        client = _FakeVaultClient(stored=None)
        p = _all_ready_patches()
        with (
            p[0],
            p[1],
            p[2],
            p[5],
            p[6],
            p[7],
            _patch_client(client),
            patch.object(
                OpenshellGatewayK8sCharm, "_read_juju_jwt_keypair", return_value=_FAKE_JWT
            ),
            ctx(ctx.on.config_changed(), _state(_vault_relation())) as manager,
        ):
            manager.run()
            charm = manager.charm
            assert charm._ensure_jwt_keypair() == _FAKE_JWT
        assert client.writes == [_FAKE_JWT]

    def test_vault_content_wins_over_the_juju_secret(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        client = _FakeVaultClient(stored=_STORED)
        p = _all_ready_patches()
        with (
            p[0],
            p[1],
            p[2],
            p[5],
            p[6],
            p[7],
            _patch_client(client),
            patch.object(
                OpenshellGatewayK8sCharm, "_read_juju_jwt_keypair", return_value=_FAKE_JWT
            ),
            ctx(ctx.on.config_changed(), _state(_vault_relation())) as manager,
        ):
            manager.run()
            charm = manager.charm
            assert charm._ensure_jwt_keypair() == _STORED
        assert client.writes == []

    def test_a_fresh_keypair_is_minted_when_neither_store_has_one(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        client = _FakeVaultClient(stored=None)
        p = _all_ready_patches()
        with (
            p[0],
            p[1],
            p[2],
            p[5],
            p[6],
            p[7],
            _patch_client(client),
            patch.object(OpenshellGatewayK8sCharm, "_read_juju_jwt_keypair", return_value=None),
            ctx(ctx.on.config_changed(), _state(_vault_relation())) as manager,
        ):
            manager.run()
            charm = manager.charm
            minted = charm._ensure_jwt_keypair()
        assert minted is not None
        assert set(minted) == {"signing-key", "public-key", "kid"}
        assert client.writes == [minted]

    def test_a_follower_never_seeds_vault(self):
        # Two units racing to seed would leave half the fleet signing with a
        # key the other half rejects.
        ctx = Context(OpenshellGatewayK8sCharm)
        client = _FakeVaultClient(stored=None)
        p = _all_ready_patches()
        with (
            p[0],
            p[1],
            p[2],
            p[5],
            p[6],
            p[7],
            _patch_client(client),
            patch.object(
                OpenshellGatewayK8sCharm, "_read_juju_jwt_keypair", return_value=_FAKE_JWT
            ),
        ):
            state = _state(_vault_relation(), leader=False)
            with ctx(ctx.on.config_changed(), state) as manager:
                manager.run()
                charm = manager.charm
                assert charm._ensure_jwt_keypair() is None
        assert client.writes == []

    def test_an_unreachable_vault_does_not_mint_a_second_keypair(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        client = _FakeVaultClient(stored=_STORED, fail=True)
        p = _all_ready_patches()
        with (
            p[0],
            p[1],
            p[2],
            p[5],
            p[6],
            p[7],
            _patch_client(client),
            patch.object(
                OpenshellGatewayK8sCharm, "_read_juju_jwt_keypair", return_value=_FAKE_JWT
            ),
            ctx(ctx.on.config_changed(), _state(_vault_relation())) as manager,
        ):
            manager.run()
            charm = manager.charm
            assert charm._ensure_jwt_keypair() is None
        assert client.writes == []


class TestRotation:
    def test_rotation_writes_to_vault_when_related(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        client = _FakeVaultClient(stored=_STORED)
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[5], p[6], p[7], _patch_client(client):
            ctx.run(ctx.on.action("rotate-jwt-signing-key"), _state(_vault_relation()))
        assert ctx.action_results is not None
        assert ctx.action_results["store"] == "vault"
        assert len(client.writes) == 1
        assert client.writes[0]["signing-key"] != _STORED["signing-key"]
        assert ctx.action_results["kid"] == client.writes[0]["kid"]

    def test_rotation_stays_leader_only(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        client = _FakeVaultClient(stored=_STORED)
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[5], p[6], p[7], _patch_client(client):
            state = _state(_vault_relation(), leader=False)
            with pytest.raises(Exception, match="leader"):
                ctx.run(ctx.on.action("rotate-jwt-signing-key"), state)
        assert client.writes == []

    def test_rotation_fails_loudly_when_vault_cannot_be_written(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        client = _FakeVaultClient(stored=_STORED, fail=True)
        p = _all_ready_patches()
        with (
            p[0],
            p[1],
            p[2],
            p[5],
            p[6],
            p[7],
            _patch_client(client),
            pytest.raises(Exception, match="Vault"),
        ):
            ctx.run(ctx.on.action("rotate-jwt-signing-key"), _state(_vault_relation()))


class TestStatusAndNonce:
    def test_status_action_names_the_active_store(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        client = _FakeVaultClient(stored=_STORED)
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[5], p[6], p[7], _patch_client(client):
            ctx.run(ctx.on.action("get-gateway-status"), _state(_vault_relation()))
        assert ctx.action_results["jwt-store"] == "vault"

    def test_status_action_names_the_juju_secret_store_by_default(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]:
            ctx.run(ctx.on.action("get-gateway-status"), _state(None))
        assert ctx.action_results["jwt-store"] == "juju-secret"

    def test_nonce_is_stable_across_hooks(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        nonces = []
        p = _all_ready_patches()
        for _ in range(2):
            with (
                p[0],
                p[1],
                p[2],
                p[3],
                p[4],
                p[5],
                p[6],
                p[7],
                ctx(ctx.on.config_changed(), _state(_vault_relation(ready=False))) as manager,
            ):
                manager.run()
                nonces.append(manager.charm.vault.nonce())
        assert nonces[0] == nonces[1]

    def test_credentials_are_requested_with_the_unit_egress_subnet(self):
        ctx = Context(OpenshellGatewayK8sCharm)
        vault_rel = Relation(VAULT_RELATION, remote_app_name=VAULT_APP)
        state = State(
            config=BOTH_ROLES,
            leader=True,
            containers=[_CONN_CONTAINER],
            relations=_all_relations() + [PeerRelation(PEER_RELATION), vault_rel],
        )
        p = _all_ready_patches()
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]:
            out = ctx.run(ctx.on.relation_joined(vault_rel), state)
        published = next(r for r in out.relations if r.endpoint == VAULT_RELATION)
        assert published.local_unit_data["nonce"]
        assert published.local_unit_data["egress_subnet"]


class TestVaultStoreUnit:
    def test_write_rejects_an_incomplete_keypair(self):
        store = object.__new__(vault_store.VaultJwtStore)
        with pytest.raises(ValueError, match="kid"):
            vault_store.VaultJwtStore.write(store, {"signing-key": "a", "public-key": "b"})

    def test_not_found_is_distinguished_from_an_outage(self):
        assert vault_store._is_not_found(InvalidPathError("gone")) is True
        assert vault_store._is_not_found(RuntimeError("sealed")) is False

    def test_unavailable_error_is_raised_for_an_outage(self):
        client = _FakeVaultClient(stored=_STORED, fail=True)
        store = object.__new__(vault_store.VaultJwtStore)
        with (
            patch.object(
                vault_store.VaultJwtStore, "_connected_client", return_value=(client, "mount")
            ),
            pytest.raises(VaultUnavailableError),
        ):
            vault_store.VaultJwtStore.read(store)


class TestClientErrors:
    def test_a_login_failure_becomes_unavailable_not_a_crash(self):
        # Vault sealed, a CIDR restriction that does not yet match this pod, a
        # certificate mid-rotation: none of these should fail the hook.
        store = object.__new__(vault_store.VaultJwtStore)
        with (
            patch.object(
                vault_store.VaultJwtStore,
                "_client",
                side_effect=RuntimeError("source address unauthorized"),
            ),
            pytest.raises(VaultUnavailableError, match="could not reach Vault"),
        ):
            vault_store.VaultJwtStore._connected_client(store)

    def test_egress_subnets_include_the_pod_interface(self):
        # On Kubernetes the binding's egress subnet is the service ClusterIP,
        # but the pod dials Vault from its own address.
        store = object.__new__(vault_store.VaultJwtStore)
        store._charm = MagicMock()
        store._relation_name = "vault-kv"
        binding = MagicMock()
        binding.network.egress_subnets = ["10.152.183.241/32"]
        interface = MagicMock()
        interface.subnet = "10.1.0.0/16"
        binding.network.interfaces = [interface]
        store._charm.model.get_binding.return_value = binding

        subnets = vault_store.VaultJwtStore._egress_subnets(store)
        assert subnets == ["10.152.183.241/32", "10.1.0.0/16"]
