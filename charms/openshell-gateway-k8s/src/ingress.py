"""Dedicated ingress component for gRPC TLS-passthrough via traefik_route."""

from __future__ import annotations

import logging
import re
from typing import cast

import ops
from charms.traefik_k8s.v0.traefik_route import TraefikRouteRequirer

log = logging.getLogger(__name__)

# RFC 1123 hostname pattern (case-insensitive match; value is lowercased before use)
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](-*[a-z0-9])*)(\.[a-z0-9](-*[a-z0-9])*)*$",
    re.IGNORECASE,
)


def _valid_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.fullmatch(value))


class GatewayIngress(ops.Object):
    """Owns the traefik_route integration and submits SNI TCP TLS-passthrough config."""

    def __init__(self, charm: ops.CharmBase, relation_name: str = "ingress") -> None:
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name

        # Built once; _reconcile refreshes self._requirer._relation before every use
        # so the construction-time snapshot (potentially None) is never stale.
        self._requirer = TraefikRouteRequirer(
            charm,
            cast(ops.Relation, charm.model.get_relation(relation_name)),
            relation_name,
            raw=True,
        )

        for event in (
            charm.on[relation_name].relation_created,
            charm.on[relation_name].relation_joined,
            charm.on[relation_name].relation_changed,
            charm.on.leader_elected,
            charm.on.config_changed,
        ):
            self.framework.observe(event, self._reconcile)

        self.framework.observe(charm.on[relation_name].relation_broken, self._on_relation_broken)
        self.framework.observe(charm.on.collect_unit_status, self._on_collect_unit_status)

    # ------------------------------------------------------------------
    # Config assembly
    # ------------------------------------------------------------------

    def _static_config(self) -> dict:
        return {"entryPoints": {"openshell-grpc": {"address": ":8443"}}}

    def _dynamic_config(self, hostname: str | None) -> dict:
        rule = f"HostSNI(`{hostname}`)" if hostname else "HostSNI(`*`)"
        svc_addr = f"{self._charm.app.name}.{self._charm.model.name}.svc.cluster.local:8443"
        return {
            "tcp": {
                "routers": {
                    "openshell-grpc": {
                        "entryPoints": ["openshell-grpc"],
                        "rule": rule,
                        "tls": {"passthrough": True},
                        "service": "openshell-grpc",
                    }
                },
                "services": {
                    "openshell-grpc": {"loadBalancer": {"servers": [{"address": svc_addr}]}}
                },
            }
        }

    def _resolved_hostname(self) -> tuple[str | None, bool]:
        """Return (lowercased-hostname-or-None, is_valid).

        None means unset (wildcard fallback). is_valid=False means the raw
        value failed RFC 1123 validation and the route must not be submitted.
        """
        raw = str(self._charm.config.get("external-hostname") or "").strip()
        if not raw:
            return None, True
        if _valid_hostname(raw):
            return raw.lower(), True
        return raw, False

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _reconcile(self, _event: ops.EventBase) -> None:
        # Refresh the lib's cached relation reference on every dispatch.
        self._requirer._relation = cast(
            ops.Relation, self._charm.model.get_relation(self._relation_name)
        )

        # Open port 8443 unconditionally (additive — does not replace other ports).
        self._charm.unit.open_port("tcp", 8443)

        if not (self._requirer.is_ready() and self._charm.unit.is_leader()):
            return

        hostname, valid = self._resolved_hostname()
        if not valid:
            log.warning(
                "ingress: external-hostname %r is not a valid hostname — skipping submission",
                hostname,
            )
            return

        if hostname is None:
            log.warning(
                "ingress: wildcard SNI active (HostSNI(`*`)) — "
                "set external-hostname to scope routing to a single SNI"
            )

        self._requirer.submit_to_traefik(
            config=self._dynamic_config(hostname),
            static=self._static_config(),
        )

    def _on_relation_broken(self, _event: ops.EventBase) -> None:
        # Clear the cached relation so collect_unit_status sees no active ingress.
        self._requirer._relation = cast(ops.Relation, None)
        log.info(
            "ingress: traefik_route relation removed — external ingress is no longer provisioned"
        )

    def _on_collect_unit_status(self, event: ops.CollectStatusEvent) -> None:
        rel = self._charm.model.get_relation(self._relation_name)
        if rel is None:
            return

        hostname, valid = self._resolved_hostname()
        if not valid:
            event.add_status(
                ops.BlockedStatus(
                    f"ingress: external-hostname {hostname!r} is not a valid hostname"
                )
            )
        elif hostname is None:
            event.add_status(
                ops.ActiveStatus(
                    "ingress: wildcard SNI active — set external-hostname to scope routing"
                )
            )
