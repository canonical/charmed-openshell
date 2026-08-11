#!/usr/bin/env -S LD_LIBRARY_PATH=lib python3

"""OpenShell Gateway K8s charm."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import ipaddress
import json
import logging
from dataclasses import dataclass

import ops
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires
from charms.hydra.v0.oauth import ClientConfig, OAuthRequirer
from charms.rolling_ops.v0.rollingops import RollingOpsManager
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    TLSCertificatesRequiresV4,
)
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
    JWT_DIR,
    LXD_HOST_SOCKET,
    TLS_DIR,
    GatewayConfig,
    load_config,
    render_config_toml,
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
STATIC_REDIRECT_URI = "https://openshell.invalid/unused"
DATABASE_NAME = "openshell"
GATEWAY_CMD = "/usr/bin/openshell-gateway --config /etc/openshell/config.toml"


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

        # Rolling restart coordination. The manager wires its own relation and
        # lock events; the action and upgrade-charm events are handled locally
        # so we can emit the library's acquire_lock event.
        self.restart_manager = RollingOpsManager(
            self, relation=RESTART_RELATION, callback=self._restart_workload
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
        ):
            self.framework.observe(event, self._reconcile)

        # Raw relation-broken events for mandatory relations (triggers teardown).
        self.framework.observe(self.on.database_relation_broken, self._reconcile)
        self.framework.observe(self.on.certificates_relation_broken, self._reconcile)
        self.framework.observe(self.on.oauth_relation_broken, self._reconcile)

        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        self.framework.observe(
            self.on.get_oidc_client_config_action, self._on_get_oidc_client_config
        )
        self.framework.observe(self.on.get_gateway_status_action, self._on_get_gateway_status)

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
        all_data = self.database.fetch_relation_data()
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
        info = self.oauth.get_provider_info()
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
                    base64.urlsafe_b64encode(hashlib.sha256(jwk_json.encode()).digest())
                    .rstrip(b"=")
                    .decode()
                )

                new_secret = self.app.add_secret(
                    {"signing-key": signing_key_pem, "public-key": public_key_pem, "kid": kid},
                    label=PEER_SECRET_LABEL,
                )
                secret_id = new_secret.id

            # Publish the ID so non-leader units (and future hook invocations)
            # can reach the secret via get_secret(id=...) which is always stable.
            if secret_id is not None:
                peer_rel.data[self.app][PEER_SECRET_ID_KEY] = secret_id

        return self._read_jwt_keypair()

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
                        "command": "/usr/bin/openshell-driver-lxd",
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

    def _pebble_layer(self, db_uri: str) -> ops.pebble.LayerDict:
        assert self._model_cfg is not None
        env = render_env(self._model_cfg)
        env["OPENSHELL_DB_URL"] = db_uri
        return {
            "summary": "gateway layer",
            "services": {
                DRIVER_SERVICE_NAME: {
                    "override": "replace",
                    "command": (
                        f"/usr/bin/openshell-driver-lxd"
                        f" --socket {DRIVER_SOCKET}"
                        f" --lxd-socket {LXD_HOST_SOCKET}"
                    ),
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
        }

    def _render_config_toml(
        self,
        db_uri: str,
        issuer_url: str,
        jwt_kid: str,
    ) -> str:
        """Render gateway.toml from the current desired state."""
        assert self._model_cfg is not None
        return render_config_toml(
            self._model_cfg,
            db_uri=db_uri,
            issuer_url=issuer_url,
            tls_cert_path=f"{TLS_DIR}/tls.crt",
            tls_key_path=f"{TLS_DIR}/tls.key",
            jwt_signing_key_path=f"{JWT_DIR}/signing.key",
            jwt_public_key_path=f"{JWT_DIR}/public.pem",
            jwt_kid=jwt_kid,
            redirect_uri=self._redirect_uri(),
        )

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
    ) -> str:
        """Push all rendered files to the container and return the rendered config TOML."""
        container.push(
            f"{JWT_DIR}/signing.key", jwt_signing_key_pem, make_dirs=True, permissions=0o600
        )
        container.push(
            f"{JWT_DIR}/public.pem", jwt_public_key_pem, make_dirs=True, permissions=0o644
        )
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
        config_toml = self._render_config_toml(db_uri, issuer_url, jwt_kid)
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

        if db_uri is None or tls_cert is None or tls_key is None or issuer is None or jwt is None:
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
        )
        layer = self._pebble_layer(db_uri)
        container.add_layer(CONTAINER_NAME, layer, combine=True)
        try:
            container.replan()
        except ops.pebble.ChangeError:
            # The workload can legitimately crash-loop for a while after a
            # config/relation change (e.g. it needs to re-resolve an OIDC
            # issuer that isn't reachable yet). Pebble's replan raises
            # ChangeError when the service exits quickly during the start
            # attempt it makes as part of replanning, but the new layer/
            # config has already been applied and pebble will keep retrying
            # the service in the background on its own backoff schedule.
            # Letting this exception propagate would fail the hook (leaving
            # the unit in error state, needing a manual `juju resolved`) even
            # though nothing is actually wrong with the charm's reconciliation
            # — so log and continue instead of crashing.
            logger.warning(
                "workload service failed to start immediately after replan; "
                "it will keep retrying via its own backoff",
            )

        desired_hash = self._workload_config_hash(layer, config_toml, str(tls_cert.certificate))
        self._ensure_restart_state(event, desired_hash)

        # Re-publish CA to any joined send-ca-cert relations.
        for rel in self.model.relations.get("send-ca-cert", []):
            self.ca_transfer.add_certificates({ca_pem}, relation_id=rel.id)

    def _workload_config_hash(
        self,
        layer: ops.pebble.LayerDict,
        config_toml: str,
        tls_cert_pem: str,
    ) -> str:
        """Return a deterministic hex SHA-256 of the workload inputs."""
        payload = json.dumps(layer, sort_keys=True) + config_toml + tls_cert_pem
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

    def _ensure_restart_state(self, event: ops.EventBase, desired_hash: str) -> None:
        """Coordinate rolling restarts after convergence.

        First start records the hash immediately (cold unit, no coordination
        needed). Subsequent reconciles acquire the rolling-ops lock only when
        the rendered workload configuration has changed.
        """
        if self._applied_hash() is None:
            # First successful convergence: the service is already running via
            # replan(), so just record the hash without taking the lock.
            self._set_applied_hash(desired_hash)
            return

        if desired_hash != self._applied_hash():
            self.on[RESTART_RELATION].acquire_lock.emit()

    def _restart_workload(self, event: ops.EventBase) -> None:
        """Rolling-ops lock callback: restart the workload and refresh the hash."""
        container = self.unit.get_container(CONTAINER_NAME)
        if not container.can_connect():
            return

        # Re-derive the desired hash from live state so this callback is safe
        # even when invoked in a later hook after the original reconcile.
        db_uri = self._database_uri()
        tls_cert, tls_key = self._tls_material()
        issuer = self._oauth_issuer()
        jwt = self._ensure_jwt_keypair()
        if db_uri is None or tls_cert is None or tls_key is None or issuer is None or jwt is None:
            return

        layer = self._pebble_layer(db_uri)
        config_toml = self._render_config_toml(db_uri, issuer, jwt["kid"])
        container.restart(SERVICE_NAME, DRIVER_SERVICE_NAME)
        self._set_applied_hash(
            self._workload_config_hash(layer, config_toml, str(tls_cert.certificate))
        )

    def _on_restart_action(self, event: ops.ActionEvent) -> None:
        """Operator-initiated rolling restart."""
        self.on[RESTART_RELATION].acquire_lock.emit()

    def _on_upgrade_charm(self, event: ops.UpgradeCharmEvent) -> None:
        """Force a rolling restart on charm upgrade (image may have changed)."""
        self.on[RESTART_RELATION].acquire_lock.emit()

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


if __name__ == "__main__":
    ops.main(OpenshellGatewayK8sCharm)
