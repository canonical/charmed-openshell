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
)
from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires
from charms.hydra.v0.oauth import ClientConfig, OAuthRequirer
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
from ops import ActiveStatus, BlockedStatus, WaitingStatus

from config_model import (
    CONFIG_PATH,
    DRIVER_SOCKET,
    GATEWAY_PORT,
    JWT_DIR,
    LXD_CLIENT_CERT_PATH,
    LXD_CLIENT_KEY_PATH,
    LXD_SERVER_CA_PATH,
    TLS_DIR,
    GatewayConfig,
    _parse_lxd_address,
    load_config,
    render_config_toml,
    render_driver_command,
    render_env,
)
from ingress import GatewayIngress

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
LXD_INTERFACE_VERSION = "1.0"
LXD_RELATION = "lxd"
STATIC_REDIRECT_URI = "https://openshell.invalid/unused"
DATABASE_NAME = "openshell"
GATEWAY_CMD = "/usr/bin/openshell-gateway --config /etc/openshell/config.toml"

READINESS_CHECK_NAME = "gateway-ready"
DRIVER_CHECK_NAME = "driver-ready"
CHECK_PERIOD = "3s"
CHECK_TIMEOUT = "3s"
CHECK_THRESHOLD = 2


@dataclass
class _LxdConnection:
    url: str
    fingerprint: str
    server_ca: str | None = None


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
        self.ingress = GatewayIngress(self)

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
        """Mint (leader, first call) or read the JWT keypair from the peer secret.

        Stores the secret ID in peer relation app data so all units can reach it
        via ``_read_jwt_keypair`` using the stable ID rather than a label lookup.
        Only called from _reconcile (a regular event dispatch); status collection
        uses _read_jwt_keypair instead to stay side-effect-free.
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

        return self._read_jwt_keypair()

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
        private_key = ec.generate_private_key(ec.SECP384R1())
        subject = issuer = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, f"{self.app.name}-{self.model.uuid}")]
        )
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
        if not data:
            unit = next(iter(rel.units), None)
            data = rel.data.get(unit, {}) if unit is not None else {}

        addresses_raw = data.get("addresses", "")
        server_ca = data.get("certificate", "")
        fingerprint = data.get("certificate_fingerprint", "")

        if not addresses_raw or not (server_ca or fingerprint):
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
        if self._model_cfg and self._model_cfg.lxd_projects:
            bag["projects"] = self._model_cfg.lxd_projects

        # Unit data can be written by every unit; it is needed by providers
        # that inspect the remote unit bag (e.g. the canonical lxd charm).
        rel.data[self.unit].update(bag)
        if "projects" not in bag:
            rel.data[self.unit].pop("projects", None)

        if not self.unit.is_leader():
            return

        rel.data[self.app].update(bag)
        if "projects" not in bag:
            rel.data[self.app].pop("projects", None)

    def _readiness_gaps(self) -> list[_Gap]:
        """Return the list of readiness gaps; empty means the unit can be Active.

        Checks container connectivity first, then each mandatory relation.
        Called independently from both _reconcile and _on_collect_unit_status
        so each dispatch sees live model/relation state.
        """
        container = self.unit.get_container(CONTAINER_NAME)
        if not container.can_connect():
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

        if self._read_jwt_keypair() is None:
            gaps.append(_Gap("waiting for JWT keypair", "waiting"))

        if not self.model.get_relation(LXD_RELATION):
            gaps.append(_Gap("lxd relation missing", "blocked"))
        elif self._read_lxd_client_identity() is None:
            gaps.append(_Gap("waiting for lxd client identity", "waiting"))
        elif self._lxd_connection() is None:
            gaps.append(_Gap("waiting for lxd connection details", "waiting"))

        return gaps

    def _stop_workload(self, container: ops.Container) -> None:
        """Disable and stop the gateway and driver services idempotently."""
        if not container.can_connect():
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
            # LXD's self-signed server certificate lists only the hostname and
            # the loopback addresses as SANs, so CA verification rejects the
            # routable address this pod dials. Pinning by digest skips the
            # hostname check and is the only mode that works for such an
            # endpoint; CA verification remains the fallback.
            pin_fingerprint = bool(lxd_connection.fingerprint)
            driver_command = render_driver_command(
                url=lxd_connection.url,
                default_image=self._model_cfg.lxd_sandbox_image,
                operation_timeout_secs=self._model_cfg.lxd_operation_timeout_secs,
                log_level=self._model_cfg.log_level,
                gateway_endpoint=self._gateway_endpoint(),
                server_ca=(None if pin_fingerprint else LXD_SERVER_CA_PATH),
                server_fingerprint=(lxd_connection.fingerprint if pin_fingerprint else None),
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
        )

    def _read_pod_namespace(self) -> str:
        """Return the Kubernetes namespace the gateway pod runs in.

        Falls back to ``openshell`` when the downward-API namespace file is not
        readable, so the server can still start in non-Kubernetes test
        environments.
        """
        container = self.unit.get_container(CONTAINER_NAME)
        if not container.can_connect():
            return "openshell"
        try:
            namespace = (
                container.pull("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
                .read()
                .strip()
            )
        except Exception:
            return "openshell"
        return namespace if namespace else "openshell"

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
    ) -> str:
        """Push all rendered files to the container and return the rendered config TOML."""
        container.push(
            f"{JWT_DIR}/signing.key", jwt_signing_key_pem, make_dirs=True, permissions=0o600
        )
        container.push(
            f"{JWT_DIR}/public.pem", jwt_public_key_pem, make_dirs=True, permissions=0o644
        )
        # Key ID is delivered as a path-oriented file, matching how the other
        # JWT material is exposed to the workload.
        container.push(f"{JWT_DIR}/kid", jwt_kid, make_dirs=True, permissions=0o644)
        container.push(f"{TLS_DIR}/tls.crt", tls_cert_pem, make_dirs=True, permissions=0o644)
        container.push(f"{TLS_DIR}/tls.key", tls_key_pem, make_dirs=True, permissions=0o600)
        container.push(f"{TLS_DIR}/ca.crt", tls_ca_pem, make_dirs=True, permissions=0o644)
        # Add the CA to the system trust store so the binary's OIDC discovery
        # client can verify the issuer's TLS certificate (e.g. Hydra behind a
        # self-signed Traefik).
        container.push(
            "/usr/local/share/ca-certificates/charm-ca.crt",
            tls_ca_pem,
            make_dirs=True,
            permissions=0o644,
        )
        try:
            proc = container.exec(["update-ca-certificates"], timeout=30)
            proc.wait_output()
        except Exception:
            pass  # best-effort; OIDC discovery will fail if this does

        # LXD mTLS material for the remote HTTPS driver.
        container.push(
            LXD_CLIENT_CERT_PATH, lxd_client_cert_pem, make_dirs=True, permissions=0o644
        )
        container.push(LXD_CLIENT_KEY_PATH, lxd_client_key_pem, make_dirs=True, permissions=0o600)
        if lxd_server_ca_pem is not None:
            container.push(
                LXD_SERVER_CA_PATH, lxd_server_ca_pem, make_dirs=True, permissions=0o644
            )

        config_toml = self._render_config_toml(db_uri, issuer_url)
        container.push(CONFIG_PATH, config_toml, make_dirs=True, permissions=0o600)
        return config_toml

    def _reconcile(self, event: ops.EventBase) -> None:
        """Re-derive desired state from scratch and converge."""
        if self._config_error:
            return

        container = self.unit.get_container(CONTAINER_NAME)
        if not container.can_connect():
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
    ) -> str:
        """Return a deterministic hex SHA-256 of the workload inputs."""
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
        """Rolling-ops lock callback: restart the workload and refresh the hash."""
        container = self.unit.get_container(CONTAINER_NAME)
        if not container.can_connect():
            return OperationResult.RETRY_RELEASE

        # Re-derive the desired hash from live state so this callback is safe
        # even when invoked in a later hook after the original reconcile.
        db_uri = self._database_uri()
        tls_cert, tls_key = self._tls_material()
        issuer = self._oauth_issuer()
        jwt = self._ensure_jwt_keypair()
        lxd_identity = self._ensure_lxd_client_identity()
        lxd_conn = self._lxd_connection()
        if (
            db_uri is None
            or tls_cert is None
            or tls_key is None
            or issuer is None
            or jwt is None
            or lxd_identity is None
            or lxd_conn is None
        ):
            return OperationResult.RETRY_RELEASE

        layer = self._pebble_layer(db_uri, lxd_conn)
        config_toml = self._render_config_toml(db_uri, issuer)
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
            event.add_status(ActiveStatus())
            return

        for gap in gaps:
            if gap.kind == "blocked":
                event.add_status(BlockedStatus(gap.message))
            else:
                event.add_status(WaitingStatus(gap.message))

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
        running = False
        if container.can_connect():
            services = container.get_services()
            running = SERVICE_NAME in services and services[SERVICE_NAME].is_running()
        jwt = self._read_jwt_keypair()
        event.set_results(
            {
                "database-ready": str(self._database_uri() is not None),
                "tls-ready": str(self._tls_material()[0] is not None),
                "oauth-ready": str(self._oauth_issuer() is not None),
                "jwt-kid": jwt.get("kid", "") if jwt else "",
                "workload-running": str(running),
                "readiness-gaps": ", ".join(g.message for g in gaps) or "none",
            }
        )

    def _on_rotate_jwt_signing_key(self, event: ops.ActionEvent) -> None:
        """Rotate the JWT signing keypair to a new revision of the peer secret."""
        if not self.unit.is_leader():
            event.fail("rotate-jwt-signing-key must run on the leader unit")
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
        self._reconcile(event)
        event.set_results({"kid": new_material["kid"]})


if __name__ == "__main__":
    ops.main(OpenshellGatewayK8sCharm)
