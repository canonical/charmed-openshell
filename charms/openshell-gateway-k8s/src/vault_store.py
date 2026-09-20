"""Vault-backed store for the gateway's JWT signing keypair.

The charm keeps the Ed25519 keypair it mints sandbox tokens with in a Juju
application secret. That is the default and stays the default: a deployment
with no ``vault-kv`` relation behaves exactly as it always has. Relating
``vault-k8s`` moves the same material into Vault, so the key lives in a
purpose-built secrets store rather than in the controller's database.

Vault becomes authoritative on the first ``ready`` event, and the keypair the
charm already holds is copied across, so relating Vault to a running gateway
does not invalidate tokens that live sandboxes are still presenting.
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
from pathlib import Path
from typing import Any

import ops
from charms.vault_k8s.v0.vault_kv import VaultKvRequires

logger = logging.getLogger(__name__)

# Path inside the Vault KV mount the relation hands us. The mount is already
# scoped per relation by vault-k8s, so a single stable path is enough.
JWT_SECRET_PATH = "gateway-jwt"

# Keys of the keypair, identical to the Juju-secret representation so the two
# stores are interchangeable and migration is a straight copy.
KEYPAIR_KEYS = ("signing-key", "public-key", "kid")


class VaultUnavailableError(Exception):
    """Raised when Vault is related and ready but the call did not get through.

    Distinguishes "Vault says there is nothing stored" from "Vault could not be
    reached", so the charm waits instead of minting a second keypair and
    invalidating every token already in flight.
    """


class VaultJwtStore(ops.Object):
    """The ``vault-kv`` requirer side, exposing read/write of the keypair.

    The object is always constructed. With no relation it reports itself as not
    ready and the charm never consults it, which keeps Vault genuinely optional
    rather than optional-if-you-squint.
    """

    def __init__(self, charm: ops.CharmBase, relation_name: str = "vault-kv") -> None:
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self.requires = VaultKvRequires(charm, relation_name, mount_suffix="kv")

        self.framework.observe(self.requires.on.connected, self._on_connected)

    # ------------------------------------------------------------------
    # Relation state
    # ------------------------------------------------------------------

    @property
    def relation(self) -> ops.Relation | None:
        """Return the ``vault-kv`` relation, or None when there is none."""
        return self._charm.model.get_relation(self._relation_name)

    def is_related(self) -> bool:
        """Return True when a ``vault-kv`` relation exists."""
        return self.relation is not None

    def is_ready(self) -> bool:
        """Return True when Vault has published everything needed to talk to it.

        A joined-but-not-yet-ready relation reports False. The charm then waits
        rather than falling back to the Juju secret: writing to one store while
        the other is about to become authoritative is how key material gets
        lost.
        """
        return self._connection() is not None

    def nonce(self) -> str:
        """Return this unit's stable nonce.

        Vault ties credentials to (nonce, egress subnet), so the nonce has to
        survive hooks and restarts. It is an identifier, not a secret, so it is
        derived from the unit name rather than stored: a random nonce would
        need a secret of its own to be stable, which is a second store for the
        problem this module exists to solve.
        """
        digest = hashlib.sha256(self._charm.unit.name.encode()).hexdigest()
        return digest[:32]

    def _egress_subnets(self) -> list[str]:
        """Return the subnets Vault should scope this unit's AppRole to.

        The binding's ``egress_subnets`` is the application's address, which on
        Kubernetes is the service ClusterIP — not where the connection comes
        from. The pod dials Vault from its own address, so the interface subnet
        is included too. Without it Vault's CIDR restriction rejects the login
        with "source address ... unauthorized", which is the same shape of bug
        the upstream reference requirer works around the same way.
        """
        relation = self.relation
        if relation is None:
            return []
        binding = self._charm.model.get_binding(relation)
        if binding is None:
            return []

        subnets = [str(subnet) for subnet in binding.network.egress_subnets]
        interfaces = binding.network.interfaces
        if interfaces:
            interface_subnet = str(interfaces[0].subnet)
            if interface_subnet not in subnets:
                subnets.append(interface_subnet)
        return subnets

    def _on_connected(self, event: ops.EventBase) -> None:
        """Ask Vault for credentials as soon as the relation is usable."""
        self.request_credentials(getattr(event, "relation", None))

    def request_credentials(self, relation: ops.Relation | None = None) -> None:
        """Publish this unit's credential request.

        Also called from the charm's reconcile so a unit whose egress subnet
        changed underneath it — a reschedule Juju does not report as a relation
        event — asks for a role that matches where it now is.
        """
        relation = relation or self.relation
        if relation is None:
            return
        subnets = self._egress_subnets()
        if not subnets:
            logger.warning("vault-kv: no egress subnets yet; not requesting credentials")
            return
        self.requires.request_credentials(relation, subnets, self.nonce())

    # ------------------------------------------------------------------
    # Connection details
    # ------------------------------------------------------------------

    def _connection(self) -> tuple[str, str, str, str, str] | None:
        """Return ``(url, ca, mount, role_id, role_secret_id)``, or None."""
        relation = self.relation
        if relation is None or relation.app is None:
            return None

        url = self.requires.get_vault_url(relation)
        ca = self.requires.get_ca_certificate(relation)
        mount = self.requires.get_mount(relation)
        credentials_secret_id = self.requires.get_unit_credentials(relation)
        if not (url and ca and mount and credentials_secret_id):
            return None

        try:
            content = self._charm.model.get_secret(id=credentials_secret_id).get_content(
                refresh=True
            )
        except (ops.SecretNotFoundError, ops.ModelError):
            # The grant can lag the databag during relation churn; treat it as
            # not-ready rather than as an error.
            return None

        role_id = content.get("role-id")
        role_secret_id = content.get("role-secret-id")
        if not (role_id and role_secret_id):
            return None

        return url, ca, mount, role_id, role_secret_id

    # ------------------------------------------------------------------
    # Keypair read / write
    # ------------------------------------------------------------------

    def read(self) -> dict[str, str] | None:
        """Return the stored keypair, or None when Vault holds none yet.

        Raises ``VaultUnavailableError`` when Vault is ready but unreachable,
        so the caller can wait instead of treating an outage as an empty store.
        """
        client, mount = self._connected_client()
        try:
            response = client.secrets.kv.v2.read_secret(path=JWT_SECRET_PATH, mount_point=mount)
        except Exception as exc:  # hvac raises a family of errors
            if _is_not_found(exc):
                return None
            raise VaultUnavailableError(f"could not read the JWT keypair: {exc}") from exc

        data = response.get("data", {}).get("data", {})
        if not all(data.get(key) for key in KEYPAIR_KEYS):
            return None
        return {key: data[key] for key in KEYPAIR_KEYS}

    def write(self, keypair: dict[str, str]) -> None:
        """Store *keypair* in Vault, replacing whatever was there."""
        missing = [key for key in KEYPAIR_KEYS if not keypair.get(key)]
        if missing:
            raise ValueError(f"keypair is missing {', '.join(missing)}")

        client, mount = self._connected_client()
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=JWT_SECRET_PATH,
                secret={key: keypair[key] for key in KEYPAIR_KEYS},
                mount_point=mount,
            )
        except Exception as exc:
            raise VaultUnavailableError(f"could not write the JWT keypair: {exc}") from exc

    def _connected_client(self) -> tuple[Any, str]:
        """Return ``_client()``'s result, as ``VaultUnavailableError`` on failure.

        Logging in reaches the network and can fail for reasons the charm must
        survive — Vault sealed, the AppRole's CIDR restriction not yet matching
        this pod's address, a certificate that has just rotated. A crashed hook
        turns any of those into an error state an operator has to resolve by
        hand, so they surface as this error and the charm waits.
        """
        try:
            return self._client()
        except VaultUnavailableError:
            raise
        except Exception as exc:
            raise VaultUnavailableError(f"could not reach Vault: {exc}") from exc

    def _client(self) -> tuple[Any, str]:
        """Return an authenticated hvac client and the KV mount to use."""
        connection = self._connection()
        if connection is None:
            raise VaultUnavailableError("vault-kv relation is not ready")
        url, ca, mount, role_id, role_secret_id = connection

        # hvac verifies against a CA file, so the relation's PEM is written to
        # a temporary file for the lifetime of the hook. The charm container
        # has no persistent storage of its own and adding one for this would
        # change the pod spec for a value that arrives fresh on every hook.
        ca_file = Path(tempfile.mkdtemp(prefix="vault-ca-")) / "ca.pem"
        ca_file.write_text(ca)

        import hvac  # imported lazily: only a Vault-related charm needs it

        client = hvac.Client(url=url, verify=str(ca_file))
        login = client.auth.approle.login(
            role_id=role_id, secret_id=role_secret_id, use_token=False
        )
        client.token = login["auth"]["client_token"]
        return client, mount


def _is_not_found(exc: Exception) -> bool:
    """Return True when *exc* means "no such secret" rather than "no Vault"."""
    status = getattr(exc, "status_code", None)
    if status == 404:
        return True
    return type(exc).__name__ == "InvalidPath"
