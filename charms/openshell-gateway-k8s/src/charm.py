#!/usr/bin/env -S LD_LIBRARY_PATH=lib python3

"""OpenShell Gateway K8s charm."""

from __future__ import annotations

import base64
import contextlib
import datetime
import hashlib
import ipaddress
import json
import logging
from dataclasses import dataclass
from typing import Any

import ops
from charmlibs.rollingops import OperationResult, RollingOpsManager
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferProvides,
    CertificateTransferRequires,
)
from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.hydra.v0.oauth import ClientConfig, OAuthRequirer
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    TLSCertificatesRequiresV4,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import ExtendedKeyUsageOID
from ops import ActiveStatus, BlockedStatus, WaitingStatus

from config_model import (
    CONFIG_PATH,
    DRIVER_SOCKET,
    GATEWAY_PORT,
    JWT_DIR,
    LXD_CLIENT_CERT_PATH,
    LXD_CLIENT_KEY_PATH,
    LXD_SERVER_CERT_PATH,
    METRICS_DISABLED,
    PRISTINE_CA_BUNDLE_PATH,
    REGISTRIES_CONF_PATH,
    SANDBOX_CLIENT_CA_PATH,
    SANDBOX_TLS_CA_PATH,
    SANDBOX_TLS_CERT_PATH,
    SANDBOX_TLS_KEY_PATH,
    SYSTEM_CA_BUNDLE_PATH,
    TLS_DIR,
    GatewayConfig,
    _parse_lxd_address,
    _parse_lxd_fingerprint,
    _parse_lxd_project,
    load_config,
    parse_insecure_registries,
    render_config_toml,
    render_driver_command,
    render_env,
    render_registries_conf,
)
from ingress import GatewayIngress
from vault_store import VaultJwtStore, VaultUnavailableError

logger = logging.getLogger(__name__)

CONTAINER_NAME = "gateway"
SERVICE_NAME = "gateway"
DRIVER_SERVICE_NAME = "driver-lxd"
PEER_RELATION = "gateway-peers"
RESTART_RELATION = "restart"
APPLIED_HASH_KEY = "applied-config-hash"
PEER_SECRET_LABEL = "gateway-jwt"
PEER_SECRET_ID_KEY = "jwt-secret-id"  # app data key used to share secret ID with all units
PEER_LXD_SECRET_LABEL = "lxd-client-identity"
PEER_LXD_SECRET_ID_KEY = "lxd-secret-id"
PEER_SANDBOX_SECRET_LABEL = "sandbox-client-identity"
PEER_SANDBOX_SECRET_ID_KEY = "sandbox-secret-id"
LXD_INTERFACE_VERSION = "1.0"
LXD_RELATION = "lxd"
METRICS_RELATION = "metrics-endpoint"
DASHBOARD_RELATION = "grafana-dashboard"
RECEIVE_CA_RELATION = "receive-ca-cert"
VAULT_RELATION = "vault-kv"
STATIC_REDIRECT_URI = "https://openshell.invalid/unused"
DATABASE_NAME = "openshell"
GATEWAY_CMD = "/usr/bin/openshell-gateway --config /etc/openshell/config.toml"

READINESS_CHECK_NAME = "gateway-ready"
DRIVER_CHECK_NAME = "driver-ready"
CHECK_PERIOD = "3s"
CHECK_TIMEOUT = "3s"
CHECK_THRESHOLD = 2

# What a Pebble that is down or too slow to answer raises. ops converts a
# refused connection into pebble.ConnectionError but lets the socket's
# TimeoutError through unwrapped, from can_connect() as well.
_PEBBLE_UNREACHABLE = (ops.pebble.ConnectionError, TimeoutError)


def _can_connect(container: ops.Container) -> bool:
    """Return ``container.can_connect()``, counting a Pebble timeout as unreachable."""
    try:
        return container.can_connect()
    except TimeoutError:
        logger.warning("Pebble in the %s container did not answer in time", container.name)
        return False


@dataclass
class _LxdConnection:
    url: str
    fingerprint: str
    server_ca: str | None = None
    # LXD project the provider tells requirers to operate in. None means the
    # provider published none and the driver uses LXD's "default" project.
    project: str | None = None


def _generate_jwt_keypair() -> dict[str, str]:
    """Generate a fresh Ed25519 JWT signing keypair and return secret content.

    Returns a dict with exactly the keys used in the peer secret:
    ``signing-key`` (PKCS8 PEM), ``public-key`` (SubjectPublicKeyInfo PEM),
    and ``kid`` (base64url-unpadded SHA-256 of a canonical JWK).
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    signing_key_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()
    public_key_pem = public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()

    raw_pub = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = base64.urlsafe_b64encode(raw_pub).rstrip(b"=").decode()
    jwk_json = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": x},
        sort_keys=True,
        separators=(",", ":"),
    )
    kid = (
        base64.urlsafe_b64encode(hashlib.sha256(jwk_json.encode()).digest()).rstrip(b"=").decode()
    )

    return {"signing-key": signing_key_pem, "public-key": public_key_pem, "kid": kid}


def _certificate_fingerprint(certificate_pem: str) -> str:
    """Return a PEM certificate's lowercase SHA-256 fingerprint, as LXD spells it."""
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    return certificate.fingerprint(hashes.SHA256()).hex()


@dataclass
class _Gap:
    message: str
    kind: str  # "blocked" | "waiting"


class OpenshellGatewayK8sCharm(ops.CharmBase):
    """Sidecar ops charm for the OpenShell gateway on Kubernetes."""

    _stored = ops.StoredState()

    def __init__(self, framework: ops.Framework) -> None:
        super().__init__(framework)

        self._model_cfg: GatewayConfig | None = None
        self._config_error: str | None = None
        self._model_cfg, self._config_error = load_config(dict(self.config))

        # Per-hook memo for the JWT keypair. collect-unit-status runs on every
        # hook and reads the keypair, and with a vault-kv relation that read is
        # an AppRole login plus a KV read against Vault. Without this a plain
        # update-status costs two Vault round trips and a slow or sealed Vault
        # slows every unrelated event. The charm object does not outlive the
        # hook, so there is nothing to invalidate.
        self._jwt_keypair_read: dict | None = None
        self._jwt_keypair_read_done = False

        # Re-registration sentinels — must be set before any reconcile reads them.
        self._stored.set_default(last_cert_sans=[], last_redirect_uri="")

        self.database = DatabaseRequires(self, "database", database_name=DATABASE_NAME)
        self.certificates = TLSCertificatesRequiresV4(
            self,
            "certificates",
            certificate_requests=[self._cert_request_attributes()],
        )
        self.oauth = OAuthRequirer(
            self,
            client_config=self._oauth_client_config(),
            relation_name="oauth",
        )
        self.ca_transfer = CertificateTransferProvides(self, "send-ca-cert")
        self.ca_receiver = CertificateTransferRequires(self, RECEIVE_CA_RELATION)
        self.ingress = GatewayIngress(self)

        # Optional: with no vault-kv relation the JWT keypair stays in the
        # Juju application secret it has always lived in.
        self.vault = VaultJwtStore(self, VAULT_RELATION)

        # Constructed only when the workload actually has a metrics listener.
        # The library publishes a default job scraping port 80 when handed an
        # empty job list, so "disabled" has to mean "no provider", not "a
        # provider with nothing to say".
        # Always constructed, unlike the metrics provider: the dashboard is
        # static content and costs nothing to publish, and an operator who
        # relates Grafana before turning metrics on should still get the
        # dashboard rather than silence.
        self.grafana_dashboards = GrafanaDashboardProvider(self, relation_name=DASHBOARD_RELATION)

        self.metrics_endpoint: MetricsEndpointProvider | None = None
        metrics_port = self._metrics_port()
        if metrics_port:
            self.metrics_endpoint = MetricsEndpointProvider(
                self,
                relation_name=METRICS_RELATION,
                jobs=[{"static_configs": [{"targets": [f"*:{metrics_port}"]}]}],
                refresh_event=[self.on.config_changed],
            )

        # Rolling restart coordination using the maintained charmlibs
        # implementation. The manager wires its own relation and lock events;
        # the action and upgrade-charm events request an async lock.
        self.rollingops = RollingOpsManager(
            self,
            peer_relation_name=RESTART_RELATION,
            callback_targets={"restart": self._restart_workload},
        )
        self.framework.observe(self.on.restart_action, self._on_restart_action)
        self.framework.observe(self.on.upgrade_charm, self._on_upgrade_charm)

        # Every convergence trigger routes to _reconcile.
        for event in (
            self.on.config_changed,
            self.on[CONTAINER_NAME].pebble_ready,
            self.on.secret_changed,
            self.on.leader_elected,
            self.on.update_status,
            self.on[PEER_RELATION].relation_created,
            self.on[PEER_RELATION].relation_changed,
            self.database.on.database_created,
            self.database.on.endpoints_changed,
            self.certificates.on.certificate_available,
            self.oauth.on.oauth_info_changed,
            self.oauth.on.oauth_info_removed,
            self.on[LXD_RELATION].relation_changed,
            self.on[LXD_RELATION].relation_joined,
            self.on[RECEIVE_CA_RELATION].relation_changed,
            self.on[RECEIVE_CA_RELATION].relation_broken,
            self.vault.requires.on.ready,
            self.vault.requires.on.gone_away,
        ):
            self.framework.observe(event, self._reconcile)

        # Raw relation-broken events for mandatory relations (triggers teardown).
        self.framework.observe(self.on.database_relation_broken, self._reconcile)
        self.framework.observe(self.on.certificates_relation_broken, self._reconcile)
        self.framework.observe(self.on.oauth_relation_broken, self._reconcile)
        self.framework.observe(self.on.lxd_relation_broken, self._reconcile)

        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        self.framework.observe(
            self.on.get_oidc_client_config_action, self._on_get_oidc_client_config
        )
        self.framework.observe(self.on.get_lxd_client_cert_action, self._on_get_lxd_client_cert)
        self.framework.observe(self.on.get_gateway_status_action, self._on_get_gateway_status)
        self.framework.observe(
            self.on.rotate_jwt_signing_key_action, self._on_rotate_jwt_signing_key
        )
        self.framework.observe(
            self.on.rotate_sandbox_client_identity_action,
            self._on_rotate_sandbox_client_identity,
        )

    def _metrics_port(self) -> int:
        """Return the configured metrics port, or 0 when metrics are disabled.

        Falls back to 0 when config failed validation: without a valid model
        there is no port to trust, and a disabled listener is the safe read.
        """
        if self._model_cfg is None:
            return METRICS_DISABLED
        return self._model_cfg.metrics_port

    def _sync_metrics_port(self) -> None:
        """Open or close the metrics port to match config.

        ``open_port``/``close_port`` are additive and subtractive on their own
        port, so this leaves the gateway's 8443 (opened by the ingress
        component) alone.
        """
        port = self._metrics_port()
        if port:
            self.unit.open_port("tcp", port)
        for opened in self.unit.opened_ports():
            if opened.protocol != "tcp" or opened.port is None:
                continue
            if opened.port == int(GATEWAY_PORT):
                continue
            if opened.port != port:
                self.unit.close_port("tcp", opened.port)

    def _cert_request_attributes(self) -> CertificateRequestAttributes:
        sans_dns: list[str] = [
            f"{self.app.name}.{self.model.name}.svc.cluster.local",
            "localhost",
        ]
        sans_ip: list[str] = ["127.0.0.1"]
        if self._model_cfg and self._model_cfg.external_hostname:
            if self._is_ip_address(self._model_cfg.external_hostname):
                sans_ip.insert(0, self._model_cfg.external_hostname)
            else:
                sans_dns.insert(0, self._model_cfg.external_hostname)
        return CertificateRequestAttributes(
            common_name=f"{self.app.name}.{self.model.name}.svc.cluster.local",
            sans_dns=sans_dns,
            sans_ip=sans_ip,
        )

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        """Return True if *value* is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True

    def _redirect_uri(self) -> str:
        if self._model_cfg and self._model_cfg.external_hostname:
            return f"https://{self._model_cfg.external_hostname}/oauth/unused"
        return STATIC_REDIRECT_URI

    def _oauth_client_config(self) -> ClientConfig:
        return ClientConfig(
            redirect_uri=self._redirect_uri(),
            scope="openid profile email",
            grant_types=["authorization_code"],
        )

    def _database_uri(self) -> str | None:
        """Build the PostgreSQL URI from relation data, or None if not ready."""
        try:
            all_data = self.database.fetch_relation_data()
        except (ops.SecretNotFoundError, ops.ModelError):
            # Secrets may be revoked transiently during relation churn (e.g.
            # remove-relation followed by integrate). Treat that as not-ready
            # and wait for the provider to publish fresh credentials.
            return None
        if not all_data:
            return None
        # fetch_relation_data() returns Dict[relation_id, Dict[str, str]]
        row = next(iter(all_data.values()), {})
        endpoints = row.get("endpoints")
        username = row.get("username")
        password = row.get("password")
        if not (endpoints and username and password):
            return None
        host = endpoints.split(",")[0]
        # The data_interfaces library resolves the tls/tls-ca secret fields
        # and normalises hyphenated keys to underscores, giving us "tls" and
        # "tls_ca" directly.
        tls_enabled = row.get("tls", "False").strip().lower() == "true"
        have_ca = bool(row.get("tls_ca"))
        from config_model import append_sslmode

        base_uri = f"postgresql://{username}:{password}@{host}/{DATABASE_NAME}"
        return append_sslmode(base_uri, have_ca=have_ca, tls_enabled=tls_enabled)

    def _tls_material(self):
        """Return (ProviderCertificate | None, PrivateKey | None)."""
        return self.certificates.get_assigned_certificate(self._cert_request_attributes())

    def _oauth_issuer(self) -> str | None:
        """Return the OIDC issuer URL from the oauth relation, or None."""
        try:
            info = self.oauth.get_provider_info()
        except (ops.SecretNotFoundError, ops.ModelError):
            # Provider secrets can be revoked transiently during relation
            # churn; treat that as not-ready until fresh data is published.
            return None
        return info.issuer_url if info else None

    def _read_jwt_keypair(self) -> dict | None:
        """Read the JWT keypair from whichever store is authoritative.

        Vault is authoritative whenever a ``vault-kv`` relation exists. A
        relation that has joined but is not ready yet returns None rather than
        falling back to the Juju secret: serving the old key while Vault is
        about to take over would make the two stores disagree about which key
        is current.

        Memoised for the hook: see ``_jwt_keypair_read`` in ``__init__``.
        """
        if self._jwt_keypair_read_done:
            return self._jwt_keypair_read

        self._jwt_keypair_read = self._read_jwt_keypair_uncached()
        self._jwt_keypair_read_done = True
        return self._jwt_keypair_read

    def _read_jwt_keypair_uncached(self) -> dict | None:
        """Read the JWT keypair from the authoritative store, reaching Vault."""
        if self.vault.is_related():
            if not self.vault.is_ready():
                return None
            try:
                return self.vault.read()
            except VaultUnavailableError:
                logger.warning("vault-kv: could not read the JWT keypair", exc_info=True)
                return None
        return self._read_juju_jwt_keypair()

    def _read_juju_jwt_keypair(self) -> dict | None:
        """Read the JWT keypair secret using the ID stored in peer relation data.

        Falls back to label-based lookup for forward compat.  Returns the
        secret content dict, or None if absent or not yet accessible.
        """
        peer_rel = self.model.get_relation(PEER_RELATION)
        if peer_rel is None:
            return None
        secret_id = peer_rel.data[self.app].get(PEER_SECRET_ID_KEY)
        if secret_id:
            try:
                return self.model.get_secret(id=secret_id).get_content(refresh=True)
            except (ops.SecretNotFoundError, ops.ModelError):
                return None
        # Fallback: label lookup (may work in some Juju versions)
        try:
            return self.model.get_secret(label=PEER_SECRET_LABEL).get_content(refresh=True)
        except (ops.SecretNotFoundError, ops.ModelError):
            return None

    def _ensure_jwt_keypair(self) -> dict | None:
        """Mint or read the JWT keypair from whichever store is authoritative."""
        if self.vault.is_related():
            if not self.vault.is_ready():
                return None
            return self._ensure_jwt_keypair_in_vault()
        return self._ensure_juju_jwt_keypair()

    def _ensure_jwt_keypair_in_vault(self) -> dict | None:
        """Return the keypair Vault holds, seeding it on the first ready event.

        Seeding prefers the keypair the charm already has in its Juju secret,
        so relating Vault to a running gateway keeps the key that live sandbox
        tokens were signed with. Only the leader seeds; other units wait for it
        rather than racing to write a second keypair.
        """
        # Through the memo: collect-unit-status has almost always read this
        # already in the same hook, and each read is an AppRole login.
        existing = self._read_jwt_keypair()
        if existing is not None:
            return existing

        if not self.unit.is_leader():
            return None

        migrated = self._read_juju_jwt_keypair()
        keypair = migrated if migrated is not None else _generate_jwt_keypair()
        if migrated is not None:
            logger.info("vault-kv: migrating the existing JWT keypair into Vault")

        try:
            self.vault.write(keypair)
        except VaultUnavailableError:
            logger.warning("vault-kv: could not seed the JWT keypair", exc_info=True)
            return None
        self._forget_jwt_keypair()
        return keypair

    def _forget_jwt_keypair(self) -> None:
        """Drop the per-hook memo after writing new key material."""
        self._jwt_keypair_read = None
        self._jwt_keypair_read_done = False

    def _ensure_juju_jwt_keypair(self) -> dict | None:
        """Mint (leader, first call) or read the JWT keypair from the peer secret.

        Stores the secret ID in peer relation app data so all units can reach it
        via ``_read_juju_jwt_keypair`` using the stable ID rather than a label
        lookup. Only called from _reconcile (a regular event dispatch); status
        collection uses _read_jwt_keypair instead to stay side-effect-free.
        """
        peer_rel = self.model.get_relation(PEER_RELATION)
        if peer_rel is None:
            return None

        secret_id = peer_rel.data[self.app].get(PEER_SECRET_ID_KEY)

        if self.unit.is_leader() and not secret_id:
            # Try label lookup first — the secret may have been created in a
            # previous hook where the write succeeded but the ID was never
            # recorded in peer data (e.g. due to a subsequent grant failure).
            existing: ops.Secret | None = None
            with contextlib.suppress(ops.SecretNotFoundError):
                existing = self.model.get_secret(label=PEER_SECRET_LABEL)

            if existing is not None:
                secret_id = existing.id
            else:
                new_secret = self.app.add_secret(
                    _generate_jwt_keypair(),
                    label=PEER_SECRET_LABEL,
                )
                secret_id = new_secret.id

            # Publish the ID so non-leader units (and future hook invocations)
            # can reach the secret via get_secret(id=...) which is always stable.
            if secret_id is not None:
                peer_rel.data[self.app][PEER_SECRET_ID_KEY] = secret_id

        return self._read_juju_jwt_keypair()

    def _read_lxd_client_identity(self) -> dict | None:
        """Read the LXD client identity secret using the ID stored in peer relation data.

        Falls back to label-based lookup for forward compat. Returns the secret
        content dict (``certificate`` and ``private-key``), or None if absent.
        """
        peer_rel = self.model.get_relation(PEER_RELATION)
        if peer_rel is None:
            return None
        secret_id = peer_rel.data[self.app].get(PEER_LXD_SECRET_ID_KEY)
        if secret_id:
            try:
                return self.model.get_secret(id=secret_id).get_content(refresh=True)
            except (ops.SecretNotFoundError, ops.ModelError):
                return None
        try:
            return self.model.get_secret(label=PEER_LXD_SECRET_LABEL).get_content(refresh=True)
        except (ops.SecretNotFoundError, ops.ModelError):
            return None

    def _generate_lxd_client_identity(self) -> dict[str, str]:
        """Generate a self-signed EC P-384 client certificate for LXD mTLS.

        Returns a dict with ``certificate`` (PEM) and ``private-key`` (PEM).
        The CN is ``<app>-<model UUID>`` so the provider can identify the source
        application in the LXD trust store.
        """
        return self._generate_client_identity(f"{self.app.name}-{self.model.uuid}")

    def _generate_sandbox_client_identity(self) -> dict[str, str]:
        """Generate the client CA and the leaf certificate every sandbox gets.

        Deliberately separate from the LXD client identity: that one is an
        administrative credential for the LXD API and must never leave the
        gateway pod. This one only ever travels to sandboxes.

        The leaf is issued by a CA minted here rather than by the deployment's
        own CA, for two reasons. The ``certificates`` relation's library keeps
        one private key per relation, so asking it for a second certificate
        would hand every sandbox the gateway's *server* private key. And a
        purpose-built CA trusted for nothing else means "the gateway accepts
        this as a sandbox" rather than "the gateway accepts anything the
        deployment's CA ever signed".

        The CA private key stays in the peer secret. Only the CA certificate
        reaches the workload, and only the leaf and its key reach sandboxes.

        Returns ``ca-certificate``, ``ca-private-key``, ``certificate`` and
        ``private-key``, all PEM.
        """
        # The model UUID alone identifies the deployment; the application name
        # is left out so the common names stay inside X.509's 64-character
        # limit whatever the application is called.
        now = datetime.datetime.now(datetime.UTC)
        expiry = now + datetime.timedelta(days=3650)

        ca_key = ec.generate_private_key(ec.SECP384R1())
        ca_name = x509.Name(
            [
                x509.NameAttribute(
                    x509.NameOID.COMMON_NAME, f"openshell-sandbox-ca-{self.model.uuid}"
                )
            ]
        )
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(expiry)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
            )
            .sign(ca_key, hashes.SHA384())
        )

        leaf_key = ec.generate_private_key(ec.SECP384R1())
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            x509.NameOID.COMMON_NAME, f"openshell-sandbox-{self.model.uuid}"
                        )
                    ]
                )
            )
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(expiry)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # rustls accepts a client certificate that carries the clientAuth
            # usage or no usage extension at all. Saying it explicitly keeps
            # the certificate honest about what it is for.
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA384())
        )

        def pem_key(key: ec.EllipticCurvePrivateKey) -> str:
            return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()

        return {
            "ca-certificate": ca_cert.public_bytes(Encoding.PEM).decode(),
            "ca-private-key": pem_key(ca_key),
            "certificate": leaf_cert.public_bytes(Encoding.PEM).decode(),
            "private-key": pem_key(leaf_key),
        }

    def _generate_client_identity(self, common_name: str) -> dict[str, str]:
        """Generate a self-signed EC P-384 client certificate with *common_name*."""
        private_key = ec.generate_private_key(ec.SECP384R1())
        subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA384())
        )

        certificate_pem = cert.public_bytes(Encoding.PEM).decode()
        private_key_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()

        return {"certificate": certificate_pem, "private-key": private_key_pem}

    def _ensure_lxd_client_identity(self) -> dict | None:
        """Mint (leader, first call) or read the LXD client identity from the peer secret.

        Stores the secret ID in peer relation app data so all units can reach it
        via ``_read_lxd_client_identity``. Only called from `_reconcile`.
        """
        peer_rel = self.model.get_relation(PEER_RELATION)
        if peer_rel is None:
            return None

        secret_id = peer_rel.data[self.app].get(PEER_LXD_SECRET_ID_KEY)

        if self.unit.is_leader() and not secret_id:
            existing: ops.Secret | None = None
            with contextlib.suppress(ops.SecretNotFoundError):
                existing = self.model.get_secret(label=PEER_LXD_SECRET_LABEL)

            if existing is not None:
                secret_id = existing.id
            else:
                new_secret = self.app.add_secret(
                    self._generate_lxd_client_identity(),
                    label=PEER_LXD_SECRET_LABEL,
                )
                secret_id = new_secret.id

            if secret_id is not None:
                peer_rel.data[self.app][PEER_LXD_SECRET_ID_KEY] = secret_id

        return self._read_lxd_client_identity()

    def _read_sandbox_client_identity(self) -> dict | None:
        """Read the sandbox client identity secret, or None if not yet minted."""
        peer_rel = self.model.get_relation(PEER_RELATION)
        if peer_rel is None:
            return None
        secret_id = peer_rel.data[self.app].get(PEER_SANDBOX_SECRET_ID_KEY)
        if secret_id:
            try:
                return self.model.get_secret(id=secret_id).get_content(refresh=True)
            except (ops.SecretNotFoundError, ops.ModelError):
                return None
        try:
            return self.model.get_secret(label=PEER_SANDBOX_SECRET_LABEL).get_content(refresh=True)
        except (ops.SecretNotFoundError, ops.ModelError):
            return None

    def _ensure_sandbox_client_identity(self) -> dict | None:
        """Mint (leader, first call) or read the sandbox client identity.

        Mirrors ``_ensure_lxd_client_identity``: the leader mints once and
        publishes the secret ID in peer app data so every unit hands the same
        material to its driver, and a sandbox that migrates between units keeps
        working. Only called from ``_reconcile``.
        """
        peer_rel = self.model.get_relation(PEER_RELATION)
        if peer_rel is None:
            return None

        secret_id = peer_rel.data[self.app].get(PEER_SANDBOX_SECRET_ID_KEY)

        if self.unit.is_leader() and not secret_id:
            existing: ops.Secret | None = None
            with contextlib.suppress(ops.SecretNotFoundError):
                existing = self.model.get_secret(label=PEER_SANDBOX_SECRET_LABEL)

            if existing is not None:
                secret_id = existing.id
            else:
                new_secret = self.app.add_secret(
                    self._generate_sandbox_client_identity(),
                    label=PEER_SANDBOX_SECRET_LABEL,
                )
                secret_id = new_secret.id

            if secret_id is not None:
                peer_rel.data[self.app][PEER_SANDBOX_SECRET_ID_KEY] = secret_id

        identity = self._read_sandbox_client_identity()

        # Earlier revisions minted a self-signed leaf with no issuer anything
        # could verify, which is why the gateway was never given a client CA.
        # Such a secret is replaced with a CA and a leaf issued by it.
        if identity is not None and not identity.get("ca-certificate"):
            if not self.unit.is_leader():
                return None
            logger.info("re-issuing the sandbox client identity from a client CA")
            try:
                secret = self.model.get_secret(label=PEER_SANDBOX_SECRET_LABEL)
            except (ops.SecretNotFoundError, ops.ModelError):
                return None
            secret.set_content(self._generate_sandbox_client_identity())
            identity = self._read_sandbox_client_identity()

        return identity

    def _lxd_connection(self) -> _LxdConnection | None:
        """Consume the provider's lxd-https databag and return a validated connection.

        Prefers the app bag, then falls back to the unit bag. Returns None unless
        both ``addresses`` and ``certificate`` are published and the first address
        passes sanitisation.
        """
        rel = self.model.get_relation(LXD_RELATION)
        if rel is None:
            return None

        data = rel.data.get(rel.app, {}) or {}
        if not data.get("addresses"):
            # A non-clustered provider publishes to its *leader's* unit bag, so
            # every joined unit has to be tried: the leader is not necessarily
            # the first one iteration yields, and picking a follower's empty bag
            # would leave this charm waiting for details that are already there.
            for unit in rel.units:
                unit_data = rel.data.get(unit, {}) or {}
                if unit_data.get("addresses"):
                    data = unit_data
                    break

        addresses_raw = data.get("addresses", "")
        server_ca = data.get("certificate", "")
        fingerprint_raw = data.get("certificate_fingerprint", "")
        project_raw = data.get("project", "")

        if not addresses_raw or not (server_ca or fingerprint_raw):
            return None

        # The fingerprint is interpolated into the driver's command line, which
        # Pebble splits on whitespace, so a value carrying a space would become
        # extra arguments to the driver. An unusable one is a hard stop rather
        # than something to drop: silently falling back to CA verification
        # would change how the server is trusted without saying so.
        fingerprint = ""
        if fingerprint_raw:
            parsed_fingerprint = _parse_lxd_fingerprint(fingerprint_raw)
            if parsed_fingerprint is None:
                logger.warning(
                    "lxd: provider published an unusable certificate fingerprint %r; "
                    "refusing to build a driver command line from it",
                    fingerprint_raw,
                )
                return None
            fingerprint = parsed_fingerprint

        # A published-but-unusable project is a hard stop, not something to
        # silently drop: falling back to LXD's "default" project would place
        # sandboxes outside the isolation the operator asked for.
        project: str | None = None
        if project_raw:
            project = _parse_lxd_project(project_raw)
            if project is None:
                logger.warning(
                    "lxd: provider published an unusable project name %r; "
                    "refusing to fall back to the default project",
                    project_raw,
                )
                return None

        # addresses may be a comma-separated list or a JSON list. A single
        # bracketed IPv6 value such as "[::1]:8443" is not a JSON list, so on
        # decode failure we fall back to plain comma splitting.
        addresses = addresses_raw
        if addresses_raw.startswith("["):
            with contextlib.suppress(json.JSONDecodeError):
                addresses = ",".join(json.loads(addresses_raw))

        first = addresses.split(",")[0].strip()
        parsed = _parse_lxd_address(first)
        if parsed is None:
            return None

        return _LxdConnection(
            url=f"https://{parsed}",
            server_ca=server_ca or None,
            fingerprint=fingerprint,
            project=project,
        )

    def _publish_lxd_databag(self, identity: dict[str, str]) -> None:
        """Publish this requirer's certificate and version on the lxd relation.

        Writes to both the application databag (leader-only) and the unit
        databag. The unit-level copy is required for compatibility with the
        canonical ``lxd`` charm, which reads the requirer's certificate from
        the remote unit bag in non-clustered deployments.
        """
        rel = self.model.get_relation(LXD_RELATION)
        if rel is None:
            return

        bag: dict[str, str] = {
            "version": LXD_INTERFACE_VERSION,
            "certificate": identity["certificate"],
        }

        # Unit data can be written by every unit; it is needed by providers
        # that inspect the remote unit bag (e.g. the canonical lxd charm).
        rel.data[self.unit].update(bag)
        # Older revisions of this charm published a "projects" restriction
        # derived from charm config. Which projects a requirer may reach is the
        # LXD administrator's decision and now lives on the integrator, so an
        # upgraded unit clears the key it used to own.
        rel.data[self.unit].pop("projects", None)

        if not self.unit.is_leader():
            return

        rel.data[self.app].update(bag)
        rel.data[self.app].pop("projects", None)

    def _readiness_gaps(self) -> list[_Gap]:
        """Return the list of readiness gaps; empty means the unit can be Active.

        Checks container connectivity first, then each mandatory relation.
        Called independently from both _reconcile and _on_collect_unit_status
        so each dispatch sees live model/relation state.
        """
        container = self.unit.get_container(CONTAINER_NAME)
        if not _can_connect(container):
            return [_Gap("waiting for gateway container", "waiting")]

        gaps: list[_Gap] = []

        if not self.model.get_relation("database"):
            gaps.append(_Gap("database relation missing", "blocked"))
        elif self._database_uri() is None:
            gaps.append(_Gap("waiting for database credentials", "waiting"))

        if not self.model.get_relation("certificates"):
            gaps.append(_Gap("certificates relation missing", "blocked"))
        elif self._tls_material()[0] is None:
            gaps.append(_Gap("waiting for TLS certificate", "waiting"))

        if not self.model.get_relation("oauth"):
            gaps.append(_Gap("oauth relation missing", "blocked"))
        elif self._oauth_issuer() is None:
            gaps.append(_Gap("waiting for oauth provider info", "waiting"))

        if self.vault.is_related() and not self.vault.is_ready():
            gaps.append(_Gap("waiting for vault-kv credentials", "waiting"))
        elif self._read_jwt_keypair() is None:
            gaps.append(_Gap("waiting for JWT keypair", "waiting"))

        if self._read_sandbox_client_identity() is None:
            gaps.append(_Gap("waiting for sandbox client identity", "waiting"))

        if not self.model.get_relation(LXD_RELATION):
            gaps.append(_Gap("lxd relation missing", "blocked"))
        elif self._read_lxd_client_identity() is None:
            gaps.append(_Gap("waiting for lxd client identity", "waiting"))
        elif self._lxd_connection() is None:
            gaps.append(_Gap("waiting for lxd connection details", "waiting"))

        gaps.extend(self._workload_gaps(container))

        return gaps

    def _workload_gaps(self, container: ops.Container) -> list[_Gap]:
        """Return gaps for workload services that should be running and are not.

        Only meaningful once the charm has converged at least once: before
        that the services are absent by design and the relation gaps above are
        the story. After it, a service that keeps exiting — bad driver flags, a
        missing LXD project, an unreachable registry — used to leave the unit
        Active with nothing to say, and the first sign of trouble was a failing
        sandbox create.
        """
        if self._applied_hash() is None:
            return []

        gaps: list[_Gap] = []
        try:
            services = container.get_services()
        except (ops.pebble.APIError, *_PEBBLE_UNREACHABLE):
            return []

        for name, label in ((DRIVER_SERVICE_NAME, "lxd driver"), (SERVICE_NAME, "gateway")):
            info = services.get(name)
            if info is not None and not info.is_running():
                gaps.append(_Gap(f"{label} service is not running", "waiting"))

        failing = sorted(name for name, check in self._check_status().items() if not check)
        if failing:
            gaps.append(_Gap(f"workload checks failing: {', '.join(failing)}", "waiting"))

        return gaps

    def _check_status(self) -> dict[str, bool]:
        """Return each Pebble check's name mapped to whether it is passing."""
        container = self.unit.get_container(CONTAINER_NAME)
        if not _can_connect(container):
            return {}
        try:
            checks = container.get_checks()
        except (ops.pebble.APIError, *_PEBBLE_UNREACHABLE):
            return {}
        return {
            name: check.status == ops.pebble.CheckStatus.UP
            for name, check in checks.items()
            if name in (READINESS_CHECK_NAME, DRIVER_CHECK_NAME)
        }

    def _stop_workload(self, container: ops.Container) -> None:
        """Disable and stop the gateway and driver services idempotently."""
        if not _can_connect(container):
            return
        container.add_layer(
            CONTAINER_NAME,
            {
                "summary": "gateway teardown layer",
                "services": {
                    SERVICE_NAME: {
                        "override": "replace",
                        "command": GATEWAY_CMD,
                        "startup": "disabled",
                    },
                    DRIVER_SERVICE_NAME: {
                        "override": "replace",
                        "command": "/usr/bin/openshell-driver-lxd --socket " + DRIVER_SOCKET,
                        "startup": "disabled",
                    },
                },
            },
            combine=True,
        )
        services = container.get_services()
        if SERVICE_NAME in services and services[SERVICE_NAME].is_running():
            container.stop(SERVICE_NAME)
        if DRIVER_SERVICE_NAME in services and services[DRIVER_SERVICE_NAME].is_running():
            container.stop(DRIVER_SERVICE_NAME)

        # The disabled layer no longer matches the last running configuration.
        # Clear its hash so relation recovery replans even when provider data is unchanged.
        restart_rel = self.model.get_relation(RESTART_RELATION)
        if restart_rel is not None:
            restart_rel.data[self.unit].pop(APPLIED_HASH_KEY, None)

    def _gateway_endpoint(self) -> str:
        """Return the dial-back URL sandbox supervisors use to reach this gateway.

        When the operator has configured an external hostname and the ingress
        (traefik_route) relation is present, sandbox supervisors outside the
        cluster dial back via that hostname.  Otherwise fall back to the
        in-cluster Kubernetes service DNS name, which matches the SAN on the
        gateway's TLS certificate.
        """
        if (
            self._model_cfg is not None
            and self._model_cfg.external_hostname
            and self.ingress.is_ready()
        ):
            return f"https://{self._model_cfg.external_hostname}:8443"
        return f"https://{self.app.name}.{self.model.name}.svc.cluster.local:8443"

    def _pebble_layer(
        self, db_uri: str, lxd_connection: _LxdConnection | None
    ) -> ops.pebble.LayerDict:
        assert self._model_cfg is not None
        env = render_env(self._model_cfg)
        env["OPENSHELL_DB_URL"] = db_uri

        if lxd_connection is not None:
            # Prefer the fingerprint pin whenever the provider publishes one.
            # Falling back to the published certificate pins that certificate
            # (--lxd-server-cert), not a CA: LXD's self-signed certificate
            # lists only the hostname and the loopback addresses as SANs, so
            # chain-and-hostname verification rejects the routable address this
            # pod dials whichever of the two files it is handed.
            pin_fingerprint = bool(lxd_connection.fingerprint)
            driver_command = render_driver_command(
                url=lxd_connection.url,
                default_image=self._model_cfg.sandbox_image,
                supervisor_image=self._model_cfg.supervisor_image,
                operation_timeout_secs=self._model_cfg.lxd_operation_timeout_secs,
                log_level=self._model_cfg.log_level,
                gateway_endpoint=self._gateway_endpoint(),
                server_cert=(None if pin_fingerprint else LXD_SERVER_CERT_PATH),
                server_fingerprint=(lxd_connection.fingerprint if pin_fingerprint else None),
                project=lxd_connection.project,
                restrict_sandbox_egress=self._model_cfg.restrict_sandbox_egress,
            )
        else:
            # No connection yet: keep the service defined but unable to start,
            # so the readiness gap (not this layer) governs status.
            driver_command = f"/usr/bin/openshell-driver-lxd --socket {DRIVER_SOCKET}"

        return {
            "summary": "gateway layer",
            "services": {
                DRIVER_SERVICE_NAME: {
                    "override": "replace",
                    "command": driver_command,
                    "startup": "enabled",
                },
                SERVICE_NAME: {
                    "override": "replace",
                    "command": GATEWAY_CMD,
                    "startup": "enabled",
                    "after": [DRIVER_SERVICE_NAME],
                    "environment": env,
                },
            },
            "checks": {
                READINESS_CHECK_NAME: {
                    "override": "replace",
                    "level": "ready",
                    "period": CHECK_PERIOD,
                    "timeout": CHECK_TIMEOUT,
                    "threshold": CHECK_THRESHOLD,
                    "tcp": {"port": int(GATEWAY_PORT), "host": "127.0.0.1"},
                },
                DRIVER_CHECK_NAME: {
                    "override": "replace",
                    # "ready", like the gateway's own check: the driver is the
                    # only way this gateway creates a sandbox, so a unit whose
                    # driver is not up is not ready, and Pebble's readiness
                    # should say so rather than only this charm's status.
                    "level": "ready",
                    "period": CHECK_PERIOD,
                    "timeout": CHECK_TIMEOUT,
                    "threshold": CHECK_THRESHOLD,
                    "exec": {"command": f"test -S {DRIVER_SOCKET}"},
                },
            },
        }

    def _render_config_toml(
        self,
        db_uri: str,
        issuer_url: str,
        *,
        client_ca: bool = False,
    ) -> str:
        """Render gateway.toml from the current desired state."""
        assert self._model_cfg is not None
        k8s_namespace = self._read_pod_namespace()
        return render_config_toml(
            self._model_cfg,
            db_uri=db_uri,
            issuer_url=issuer_url,
            tls_cert_path=f"{TLS_DIR}/tls.crt",
            tls_key_path=f"{TLS_DIR}/tls.key",
            jwt_signing_key_path=f"{JWT_DIR}/signing.key",
            jwt_public_key_path=f"{JWT_DIR}/public.pem",
            jwt_kid_path=f"{JWT_DIR}/kid",
            redirect_uri=self._redirect_uri(),
            k8s_namespace=k8s_namespace,
            client_ca_path=SANDBOX_CLIENT_CA_PATH if client_ca else None,
        )

    def _read_pod_namespace(self) -> str:
        """Return the Kubernetes namespace the gateway pod runs in.

        Feeds the ``[openshell.drivers.kubernetes]`` section, which the gateway
        needs even with the LXD compute driver: issuing sandbox JWTs in-cluster
        bootstraps from a Kubernetes ServiceAccount, and the binary refuses to
        start without the section ("K8s ServiceAccount bootstrap requires
        [openshell.drivers.kubernetes] when sandbox JWT issuing is enabled
        in-cluster"). It is not dead configuration left over from the
        Kubernetes driver.

        Falls back to ``openshell`` when the downward-API namespace file is not
        readable, so the server can still start in non-Kubernetes test
        environments. A Pebble that does not answer is not such a case: the
        error propagates, so a slow container never gets a wrong namespace
        rendered into its configuration.
        """
        container = self.unit.get_container(CONTAINER_NAME)
        if not _can_connect(container):
            return "openshell"
        try:
            namespace = (
                container.pull("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
                .read()
                .strip()
            )
        except (ops.pebble.PathError, ops.pebble.APIError):
            return "openshell"
        return namespace if namespace else "openshell"

    def _push_if_changed(
        self,
        container: ops.Container,
        path: str,
        content: str,
        permissions: int,
    ) -> None:
        """Push *content* to *path* only when it differs from what is there.

        ``_reconcile`` runs on every hook, ``update-status`` included, and used
        to rewrite all eleven workload files each time. Reading first costs one
        Pebble round trip per file instead of one write, and leaves the file's
        mtime alone so anything watching it is not woken for nothing.

        Only the content is compared. Nothing but this charm writes these
        paths, so a file whose bytes are right but whose mode drifted is not a
        case worth a second round trip; a container restart re-pushes
        everything anyway.
        """
        try:
            if container.pull(path).read() == content:
                return
        except (ops.pebble.PathError, ops.pebble.APIError):
            pass
        container.push(path, content, make_dirs=True, permissions=permissions)

    def _write_container_files(
        self,
        container: ops.Container,
        db_uri: str,
        tls_cert_pem: str,
        tls_key_pem: str,
        tls_ca_pem: str,
        jwt_signing_key_pem: str,
        jwt_public_key_pem: str,
        jwt_kid: str,
        issuer_url: str,
        lxd_client_cert_pem: str,
        lxd_client_key_pem: str,
        lxd_server_ca_pem: str | None,
        sandbox_client_cert_pem: str,
        sandbox_client_key_pem: str,
        sandbox_client_ca_pem: str,
    ) -> str:
        """Push all rendered files to the container and return the rendered config TOML."""

        def push(path: str, content: str, mode: int) -> None:
            self._push_if_changed(container, path, content, mode)

        push(f"{JWT_DIR}/signing.key", jwt_signing_key_pem, 0o600)
        push(f"{JWT_DIR}/public.pem", jwt_public_key_pem, 0o644)
        # Key ID is delivered as a path-oriented file, matching how the other
        # JWT material is exposed to the workload.
        push(f"{JWT_DIR}/kid", jwt_kid, 0o644)
        push(f"{TLS_DIR}/tls.crt", tls_cert_pem, 0o644)
        push(f"{TLS_DIR}/tls.key", tls_key_pem, 0o600)
        push(f"{TLS_DIR}/ca.crt", tls_ca_pem, 0o644)
        # Add the CA to the system trust store so the binary's OIDC discovery
        # client can verify the issuer's TLS certificate (e.g. Hydra behind a
        # self-signed Traefik).
        self._install_ca_into_system_bundle(container, tls_ca_pem)

        # LXD mTLS material for the remote HTTPS driver.
        push(LXD_CLIENT_CERT_PATH, lxd_client_cert_pem, 0o644)
        push(LXD_CLIENT_KEY_PATH, lxd_client_key_pem, 0o600)
        if lxd_server_ca_pem is not None:
            push(LXD_SERVER_CERT_PATH, lxd_server_ca_pem, 0o644)

        # Sandbox TLS material. The CA is the gateway's own issuer, so a
        # sandbox supervisor can verify the certificate the gateway presents;
        # the client certificate is the dedicated sandbox identity, never the
        # LXD one. The driver reads all three on every create, so a rotated
        # certificate reaches new sandboxes without a restart.
        push(SANDBOX_TLS_CA_PATH, tls_ca_pem, 0o644)
        push(SANDBOX_TLS_CERT_PATH, sandbox_client_cert_pem, 0o644)
        push(SANDBOX_TLS_KEY_PATH, sandbox_client_key_pem, 0o600)

        # The issuer of that certificate, for the gateway to verify presented
        # client certificates against. Only the certificate: its private key
        # stays in the peer secret and never reaches this container.
        if sandbox_client_ca_pem:
            push(SANDBOX_CLIENT_CA_PATH, sandbox_client_ca_pem, 0o644)

        # Registry policy for skopeo, which the driver shells out to for the
        # sandbox and supervisor images. Rendered unconditionally so removing a
        # host from config takes effect rather than lingering in the file.
        push(
            REGISTRIES_CONF_PATH,
            render_registries_conf(
                parse_insecure_registries(
                    self._model_cfg.insecure_registries if self._model_cfg else None
                )
            ),
            0o644,
        )

        config_toml = self._render_config_toml(
            db_uri, issuer_url, client_ca=bool(sandbox_client_ca_pem)
        )
        push(CONFIG_PATH, config_toml, 0o600)
        return config_toml

    def _install_ca_into_system_bundle(self, container: ops.Container, ca_pem: str) -> None:
        """Append the charm's CA to the workload image's CA bundle.

        Deliberately does not run ``update-ca-certificates``. That command
        rebuilds the bundle from ``/etc/ca-certificates.conf``, and the gateway
        rock ships the 121 public roots as a prebuilt bundle without that conf
        file, so running it replaces every public root with the charm's single
        CA. The driver then cannot pull the sandbox or supervisor image from
        any public registry, and the failure surfaces much later as an opaque
        x509 error from skopeo.

        The image's original bundle is copied aside on first write and the
        system bundle is rebuilt from that copy every time, so repeated
        reconciles converge instead of appending the CA over and over.

        Which issuers end up in the bundle is part of the workload hash — see
        ``_transferred_trust`` — so a change of trust anchors restarts the
        workload rather than leaving it on the roots it loaded at start-up.
        """
        try:
            pristine = container.pull(PRISTINE_CA_BUNDLE_PATH).read()
        except (ops.pebble.PathError, ops.pebble.APIError):
            try:
                pristine = container.pull(SYSTEM_CA_BUNDLE_PATH).read()
            except (ops.pebble.PathError, ops.pebble.APIError):
                logger.warning(
                    "no CA bundle at %s; the workload image ships none",
                    SYSTEM_CA_BUNDLE_PATH,
                )
                pristine = ""
            container.push(PRISTINE_CA_BUNDLE_PATH, pristine, make_dirs=True, permissions=0o644)

        bundle = pristine
        if bundle and not bundle.endswith("\n"):
            bundle += "\n"

        # The charm's own issuer, plus anything transferred over
        # receive-ca-cert. Sorted so the bundle is byte-identical across
        # reconciles and the workload is not restarted for a reordering.
        for extra in [ca_pem, *sorted(self._received_ca_certificates())]:
            if extra and extra not in bundle:
                bundle += extra
                if not bundle.endswith("\n"):
                    bundle += "\n"

        container.push(SYSTEM_CA_BUNDLE_PATH, bundle, make_dirs=True, permissions=0o644)

    def _transferred_trust(self) -> str:
        """Return the ``receive-ca-cert`` anchors as one stable string.

        Derived from live relation state so the rolling-restart callback,
        which may run in a later hook than the reconcile that requested it,
        computes the same value.
        """
        return "".join(sorted(self._received_ca_certificates()))

    def _received_ca_certificates(self) -> set[str]:
        """Return CA certificates transferred over ``receive-ca-cert``.

        Used for issuers the workload image does not already trust: the
        Canonical Identity Platform signs its issuer certificate with its own
        CA, and the gateway's OIDC discovery fails to verify it otherwise.
        """
        if self.model.get_relation(RECEIVE_CA_RELATION) is None:
            return set()
        try:
            return set(self.ca_receiver.get_all_certificates())
        except Exception:
            logger.warning("receive-ca-cert: could not read transferred CAs", exc_info=True)
            return set()

    def _reconcile(self, event: ops.EventBase) -> None:
        """Re-derive desired state from scratch and converge.

        A Pebble that stops answering part-way through — a busy node, a
        workload restarting — is not a charm error. Failing the hook for it
        leaves the unit in error until someone runs ``juju resolved``, and
        with ``automatically-retry-hooks`` off that is forever. Every step of
        the convergence is idempotent and the applied hash is recorded only
        after a successful replan, so stopping here is safe: the next event,
        ``update-status`` at the latest, converges from where the model is.
        """
        try:
            self._converge(event)
        except _PEBBLE_UNREACHABLE:
            logger.warning(
                "Pebble in the %s container did not answer; the next event will converge",
                CONTAINER_NAME,
                exc_info=True,
            )

    def _converge(self, event: ops.EventBase) -> None:
        """Do the work of ``_reconcile``; Pebble errors propagate to it."""
        if self._config_error:
            return

        # Independent of the workload: a port stays open or shut according to
        # config even while the container is still coming up.
        self._sync_metrics_port()

        # A pod rescheduled onto another node changes egress subnet without a
        # relation event, and Vault scopes the unit's role to that subnet.
        if self.vault.is_related():
            self.vault.request_credentials()

        container = self.unit.get_container(CONTAINER_NAME)
        if not _can_connect(container):
            return

        # Re-register cert request when SANs have changed, and re-register the
        # oauth client when redirect_uri has changed. These must run *before*
        # the readiness gate below: a config change (e.g. external-hostname)
        # can invalidate the currently assigned certificate by changing its
        # desired SANs, which makes _tls_material() return None below. If
        # re-registration only ran after the gate, the charm would never
        # request a matching certificate again once tls_cert is None — a
        # permanent deadlock recoverable only by removing/re-adding the
        # certificates relation. Re-registering unconditionally up front
        # avoids that trap.
        new_attrs = self._cert_request_attributes()
        new_sans = sorted(list(new_attrs.sans_dns or []) + list(new_attrs.sans_ip or []))
        if new_sans != sorted(self._stored.last_cert_sans):
            self.certificates.certificate_requests = [new_attrs]
            # Merely reassigning certificate_requests does not send anything:
            # TLSCertificatesRequiresV4 only sends/cleans up CSRs from its
            # internal _configure(), which the library wires up to
            # relation-created/-changed, secret-expired/-remove, and any
            # explicit refresh_events (none are passed here). Since this
            # charm reconciles from arbitrary events (e.g. config-changed),
            # we must call sync() ourselves so a changed CSR is actually
            # transmitted instead of silently sitting unsent forever.
            self.certificates.sync()
            self._stored.last_cert_sans = new_sans

        new_redirect = self._redirect_uri()
        if new_redirect != self._stored.last_redirect_uri:
            self.oauth.update_client_config(self._oauth_client_config())
            self._stored.last_redirect_uri = new_redirect

        db_uri = self._database_uri()
        tls_cert, tls_key = self._tls_material()
        issuer = self._oauth_issuer()
        jwt = self._ensure_jwt_keypair()
        lxd_identity = self._ensure_lxd_client_identity()
        sandbox_identity = self._ensure_sandbox_client_identity()
        lxd_conn = self._lxd_connection()

        # Publish the requirer databag as soon as the identity exists and the
        # relation is present, even if the provider has not yet published its
        # connection details or other mandatory relations are still missing.
        if self._model_cfg is not None and lxd_identity is not None:
            self._publish_lxd_databag(lxd_identity)

        if (
            db_uri is None
            or tls_cert is None
            or tls_key is None
            or issuer is None
            or jwt is None
            or lxd_identity is None
            or sandbox_identity is None
            or lxd_conn is None
        ):
            self._stop_workload(container)
            return

        ca_pem = str(tls_cert.ca)
        config_toml = self._write_container_files(
            container,
            db_uri=db_uri,
            tls_cert_pem=str(tls_cert.certificate),
            tls_key_pem=tls_key.raw,
            tls_ca_pem=ca_pem,
            jwt_signing_key_pem=jwt["signing-key"],
            jwt_public_key_pem=jwt["public-key"],
            jwt_kid=jwt["kid"],
            issuer_url=issuer,
            lxd_client_cert_pem=lxd_identity["certificate"],
            lxd_client_key_pem=lxd_identity["private-key"],
            lxd_server_ca_pem=lxd_conn.server_ca,
            sandbox_client_cert_pem=sandbox_identity["certificate"],
            sandbox_client_key_pem=sandbox_identity["private-key"],
            sandbox_client_ca_pem=sandbox_identity.get("ca-certificate", ""),
        )
        layer = self._pebble_layer(db_uri, lxd_conn)
        container.add_layer(CONTAINER_NAME, layer, combine=True)

        desired_hash = self._workload_config_hash(
            layer,
            config_toml,
            str(tls_cert.certificate),
            jwt["signing-key"],
            jwt["public-key"],
            jwt["kid"],
            lxd_identity["certificate"],
            lxd_identity["private-key"],
            lxd_conn.server_ca or "",
            lxd_conn.url,
            sandbox_identity["certificate"],
            sandbox_identity["private-key"],
            self._transferred_trust(),
            sandbox_identity.get("ca-certificate", ""),
        )
        self._ensure_restart_state(event, desired_hash, container)

        # Re-publish CA to any joined send-ca-cert relations.
        for rel in self.model.relations.get("send-ca-cert", []):
            self.ca_transfer.add_certificates({ca_pem}, relation_id=rel.id)

    def _workload_config_hash(
        self,
        layer: ops.pebble.LayerDict,
        config_toml: str,
        tls_cert_pem: str,
        jwt_signing_key_pem: str,
        jwt_public_key_pem: str,
        jwt_kid: str,
        lxd_client_cert_pem: str,
        lxd_client_key_pem: str,
        lxd_server_ca_pem: str,
        lxd_url: str,
        sandbox_client_cert_pem: str = "",
        sandbox_client_key_pem: str = "",
        transferred_trust: str = "",
        sandbox_client_ca_pem: str = "",
    ) -> str:
        """Return a deterministic hex SHA-256 of the workload inputs.

        ``transferred_trust`` is what ``receive-ca-cert`` contributed to the
        workload's trust store. It belongs here because relating or removing a
        provider changes which issuers the workload trusts, and a workload that
        keeps running may keep using the roots it loaded at start-up. Sorted,
        so a reordering does not restart anything.
        """
        payload = (
            json.dumps(layer, sort_keys=True)
            + config_toml
            + tls_cert_pem
            + jwt_signing_key_pem
            + jwt_public_key_pem
            + jwt_kid
            + lxd_client_cert_pem
            + lxd_client_key_pem
            + lxd_server_ca_pem
            + lxd_url
            + sandbox_client_cert_pem
            + sandbox_client_key_pem
            + transferred_trust
            + sandbox_client_ca_pem
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _applied_hash(self) -> str | None:
        """Return the last applied workload hash, or None before first start."""
        rel = self.model.get_relation(RESTART_RELATION)
        if rel is None:
            return None
        return rel.data[self.unit].get(APPLIED_HASH_KEY)

    def _set_applied_hash(self, value: str) -> None:
        """Persist the applied workload hash in this unit's peer databag."""
        rel = self.model.get_relation(RESTART_RELATION)
        if rel is None:
            return
        rel.data[self.unit][APPLIED_HASH_KEY] = value

    def _ensure_restart_state(
        self,
        event: ops.EventBase,
        desired_hash: str,
        container: ops.Container,
    ) -> None:
        """Coordinate rolling restarts after convergence.

        First start replans and records the hash immediately (cold unit, no
        coordination needed). Subsequent reconciles request the rolling-ops
        lock only when the rendered workload configuration has changed, so the
        actual restart is serialized across units.
        """
        if self._applied_hash() is None:
            # First successful convergence: start the service now and record
            # the hash without taking the lock. Only record the hash once
            # replan has actually succeeded: if replan raises ChangeError the
            # layer may not have been applied, and recording the hash would
            # prevent future reconciles from ever retrying the replan.
            try:
                container.replan()
            except ops.pebble.ChangeError:
                # The workload can legitimately crash-loop for a while after a
                # config/relation change (e.g. it needs to re-resolve an OIDC
                # issuer that isn't reachable yet). Pebble's replan raises
                # ChangeError when the service exits quickly during the start
                # attempt it makes as part of replanning. Letting this
                # exception propagate would fail the hook (leaving the unit in
                # error state, needing a manual `juju resolved`) even though
                # nothing is actually wrong with the charm's reconciliation —
                # so log and continue instead of crashing. Because the hash is
                # not recorded, the next reconcile will retry the replan.
                logger.warning(
                    "workload service failed to start immediately after replan; "
                    "it will keep retrying via its own backoff",
                )
                return
            self._set_applied_hash(desired_hash)
            return

        if desired_hash != self._applied_hash():
            self.rollingops.request_async_lock(callback_id="restart")

    def _restart_workload(self, **kwargs: Any) -> OperationResult:
        """Rolling-ops lock callback: restart the workload and refresh the hash.

        A Pebble that does not answer releases the lock for a retry rather
        than failing the hook; see ``_reconcile``.
        """
        try:
            return self._restart_workload_now()
        except _PEBBLE_UNREACHABLE:
            logger.warning(
                "Pebble in the %s container did not answer; retrying the restart later",
                CONTAINER_NAME,
                exc_info=True,
            )
            return OperationResult.RETRY_RELEASE

    def _restart_workload_now(self) -> OperationResult:
        """Do the work of ``_restart_workload``; Pebble errors propagate to it."""
        container = self.unit.get_container(CONTAINER_NAME)
        if not _can_connect(container):
            return OperationResult.RETRY_RELEASE

        # Re-derive the desired hash from live state so this callback is safe
        # even when invoked in a later hook after the original reconcile.
        db_uri = self._database_uri()
        tls_cert, tls_key = self._tls_material()
        issuer = self._oauth_issuer()
        jwt = self._ensure_jwt_keypair()
        lxd_identity = self._ensure_lxd_client_identity()
        sandbox_identity = self._ensure_sandbox_client_identity()
        lxd_conn = self._lxd_connection()
        if (
            db_uri is None
            or tls_cert is None
            or tls_key is None
            or issuer is None
            or jwt is None
            or lxd_identity is None
            or sandbox_identity is None
            or lxd_conn is None
        ):
            return OperationResult.RETRY_RELEASE

        layer = self._pebble_layer(db_uri, lxd_conn)
        config_toml = self._render_config_toml(
            db_uri, issuer, client_ca=bool(sandbox_identity.get("ca-certificate"))
        )
        container.add_layer(CONTAINER_NAME, layer, combine=True)
        container.restart(SERVICE_NAME, DRIVER_SERVICE_NAME)
        self._set_applied_hash(
            self._workload_config_hash(
                layer,
                config_toml,
                str(tls_cert.certificate),
                jwt["signing-key"],
                jwt["public-key"],
                jwt["kid"],
                lxd_identity["certificate"],
                lxd_identity["private-key"],
                lxd_conn.server_ca or "",
                lxd_conn.url,
                sandbox_identity["certificate"],
                sandbox_identity["private-key"],
                self._transferred_trust(),
                sandbox_identity.get("ca-certificate", ""),
            )
        )
        return OperationResult.RELEASE

    def _on_restart_action(self, event: ops.ActionEvent) -> None:
        """Operator-initiated rolling restart."""
        self.rollingops.request_async_lock(callback_id="restart")

    def _on_upgrade_charm(self, event: ops.UpgradeCharmEvent) -> None:
        """Force a rolling restart on charm upgrade (image may have changed)."""
        self.rollingops.request_async_lock(callback_id="restart")

    def _on_collect_unit_status(self, event: ops.CollectStatusEvent) -> None:
        if self._config_error:
            event.add_status(BlockedStatus(self._config_error))
            return

        gaps = self._readiness_gaps()
        if not gaps:
            event.add_status(ActiveStatus(self._active_message()))
            return

        for gap in gaps:
            if gap.kind == "blocked":
                event.add_status(BlockedStatus(gap.message))
            else:
                event.add_status(WaitingStatus(gap.message))

    def _active_message(self) -> str:
        """Return the note to carry alongside ActiveStatus, or an empty string.

        A collector related to a gateway whose metrics listener is switched off
        will never scrape anything. That is a misconfiguration worth saying out
        loud, but not one that should take a working gateway out of service.
        """
        if self.model.get_relation(METRICS_RELATION) and not self._metrics_port():
            return "metrics-endpoint is related but metrics-port is 0 (metrics disabled)"
        return ""

    def _on_get_oidc_client_config(self, event: ops.ActionEvent) -> None:
        info = self.oauth.get_provider_info()
        if info is None:
            event.fail("oauth relation not ready")
            return
        cfg = self._model_cfg
        audience = cfg.oidc_audience if cfg else "openshell-cli"
        event.set_results(
            {
                "client-id": audience,
                "issuer": info.issuer_url,
                "audience": audience,
                "redirect-uri": self._redirect_uri(),
                "scopes": "openid profile email",
                "authorization-endpoint": info.authorization_endpoint,
                "token-endpoint": info.token_endpoint,
                "jwks-endpoint": info.jwks_endpoint,
            }
        )

    def _on_get_lxd_client_cert(self, event: ops.ActionEvent) -> None:
        identity = self._read_lxd_client_identity()
        if identity is None:
            event.fail("LXD client identity not initialised yet")
            return
        conn = self._lxd_connection()
        event.set_results(
            {
                "certificate": identity["certificate"],
                "certificate-fingerprint": conn.fingerprint if conn else "",
            }
        )

    def _on_get_gateway_status(self, event: ops.ActionEvent) -> None:
        gaps = self._readiness_gaps()
        container = self.unit.get_container(CONTAINER_NAME)
        services: dict[str, ops.pebble.ServiceInfo] = {}
        if _can_connect(container):
            with contextlib.suppress(*_PEBBLE_UNREACHABLE):
                services = dict(container.get_services())
        running = SERVICE_NAME in services and services[SERVICE_NAME].is_running()
        driver_running = (
            DRIVER_SERVICE_NAME in services and services[DRIVER_SERVICE_NAME].is_running()
        )
        jwt = self._read_jwt_keypair()
        lxd_conn = self._lxd_connection()
        cfg = self._model_cfg
        event.set_results(
            {
                "database-ready": str(self._database_uri() is not None),
                "tls-ready": str(self._tls_material()[0] is not None),
                "oauth-ready": str(self._oauth_issuer() is not None),
                "jwt-kid": jwt.get("kid", "") if jwt else "",
                "workload-running": str(running),
                "readiness-gaps": ", ".join(g.message for g in gaps) or "none",
                # The LXD project the provider named, empty when it named none
                # and the driver therefore uses LXD's own default.
                "lxd-project": (lxd_conn.project or "") if lxd_conn else "",
                # The address sandbox supervisors are told to dial back on.
                # Operators need to see this: it has to be reachable from the
                # sandbox network, which an in-cluster address rarely is.
                "gateway-endpoint": self._gateway_endpoint(),
                # Which store the signing key is served from, so an
                # operator can confirm a Vault migration actually took.
                "jwt-store": "vault" if self.vault.is_related() else "juju-secret",
                # Reported as well as surfaced in status: ops shows only one
                # ActiveStatus message, so another component's note (the
                # ingress wildcard warning, say) can mask the metrics one.
                # An operator needs a way to ask that always answers.
                "metrics-port": str(self._metrics_port()),
                "metrics-endpoint-related": str(
                    self.model.get_relation(METRICS_RELATION) is not None
                ),
                # Workload health. The relation gaps above say nothing about a
                # service that starts and exits, which is what bad driver
                # arguments, a missing LXD project or an unreachable registry
                # look like from here.
                "driver-running": str(driver_running),
                "workload-checks": (
                    ", ".join(
                        f"{name}={'up' if up else 'down'}"
                        for name, up in sorted(self._check_status().items())
                    )
                    or "none"
                ),
                # Security-relevant settings an operator should not have to
                # reconstruct from `juju config`.
                "sandbox-egress-restricted": str(bool(cfg and cfg.restrict_sandbox_egress)),
                "insecure-registries": ", ".join(
                    parse_insecure_registries(cfg.insecure_registries if cfg else None)
                )
                or "none",
                "received-ca-certificates": str(len(self._received_ca_certificates())),
                # Whether the gateway verifies the certificate sandboxes
                # present. It never demands one — the policy the gateway
                # derives is "require only without OIDC", and OIDC is always
                # configured here — so CLI users are unaffected either way.
                "sandbox-client-ca-configured": str(
                    bool((self._read_sandbox_client_identity() or {}).get("ca-certificate"))
                ),
                "sandbox-image": cfg.sandbox_image if cfg else "",
                "supervisor-image": cfg.supervisor_image if cfg else "",
            }
        )

    def _peer_secret(self, secret_id_key: str, label: str) -> ops.Secret | None:
        """Return a peer-owned secret by the ID in peer app data, or by label."""
        peer_rel = self.model.get_relation(PEER_RELATION)
        if peer_rel is None:
            return None
        secret_id = peer_rel.data[self.app].get(secret_id_key)
        if secret_id:
            try:
                return self.model.get_secret(id=secret_id)
            except (ops.SecretNotFoundError, ops.ModelError):
                pass
        try:
            return self.model.get_secret(label=label)
        except (ops.SecretNotFoundError, ops.ModelError):
            return None

    def _on_rotate_sandbox_client_identity(self, event: ops.ActionEvent) -> None:
        """Mint a new sandbox client CA and leaf, replacing the current pair.

        Deliberately rotates the CA as well as the certificate it signs.
        Rotating the leaf alone would leave the compromised one valid, because
        the gateway trusts the issuer, not the leaf — which makes the action
        useless for the reason anyone would run it.

        The cost is that certificates held by running sandboxes stop being
        accepted once the workload restarts with the new CA. Their supervisors
        cannot reconnect and the sandboxes have to be recreated.
        """
        if not self.unit.is_leader():
            event.fail("rotate-sandbox-client-identity must run on the leader unit")
            return

        secret = self._peer_secret(PEER_SANDBOX_SECRET_ID_KEY, PEER_SANDBOX_SECRET_LABEL)
        if secret is None:
            event.fail(
                "sandbox client identity not initialised yet; wait for the charm to become ready"
            )
            return

        new_material = self._generate_sandbox_client_identity()
        secret.set_content(new_material)
        self._reconcile(event)

        event.set_results(
            {
                "ca-fingerprint": _certificate_fingerprint(new_material["ca-certificate"]),
                "certificate-fingerprint": _certificate_fingerprint(new_material["certificate"]),
                "note": (
                    "running sandboxes keep the previous certificate and cannot reconnect "
                    "once the workload restarts; recreate them"
                ),
            }
        )

    def _on_rotate_jwt_signing_key(self, event: ops.ActionEvent) -> None:
        """Rotate the JWT signing keypair to a new revision of the peer secret."""
        if not self.unit.is_leader():
            event.fail("rotate-jwt-signing-key must run on the leader unit")
            return

        if self.vault.is_related():
            self._rotate_jwt_in_vault(event)
            return

        peer_rel = self.model.get_relation(PEER_RELATION)
        if peer_rel is None:
            event.fail(
                "JWT signing-key secret not initialised yet; wait for the charm to become ready"
            )
            return

        secret_id = peer_rel.data[self.app].get(PEER_SECRET_ID_KEY)
        secret: ops.Secret | None = None
        if secret_id:
            try:
                secret = self.model.get_secret(id=secret_id)
            except (ops.SecretNotFoundError, ops.ModelError):
                secret = None
        if secret is None:
            try:
                secret = self.model.get_secret(label=PEER_SECRET_LABEL)
            except (ops.SecretNotFoundError, ops.ModelError):
                secret = None

        if secret is None:
            event.fail(
                "JWT signing-key secret not initialised yet; wait for the charm to become ready"
            )
            return

        new_material = _generate_jwt_keypair()
        secret.set_content(new_material)
        self._forget_jwt_keypair()
        self._reconcile(event)
        event.set_results({"kid": new_material["kid"], "store": "juju-secret"})

    def _rotate_jwt_in_vault(self, event: ops.ActionEvent) -> None:
        """Rotate the keypair Vault holds. Leader-only; checked by the caller."""
        if not self.vault.is_ready():
            event.fail("vault-kv relation is not ready yet; wait for the charm to become ready")
            return

        new_material = _generate_jwt_keypair()
        try:
            self.vault.write(new_material)
        except VaultUnavailableError as exc:
            event.fail(f"could not write the new signing key to Vault: {exc}")
            return

        self._forget_jwt_keypair()
        self._reconcile(event)
        event.set_results({"kid": new_material["kid"], "store": "vault"})


if __name__ == "__main__":
    ops.main(OpenshellGatewayK8sCharm)
