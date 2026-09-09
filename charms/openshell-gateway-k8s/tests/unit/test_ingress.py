"""Unit tests for the GatewayIngress ingress component."""

from __future__ import annotations

import yaml
from ops import ActiveStatus, BlockedStatus
from ops.testing import Container, Context, PeerRelation, Relation, State, TCPPort

from charm import CONTAINER_NAME, RESTART_RELATION, OpenshellGatewayK8sCharm
from ingress import GatewayIngress, _is_ip_address, _valid_hostname

# Minimal valid config so the charm's config validator doesn't block _reconcile.
_ROLES = {"oidc-admin-role": "admin", "oidc-user-role": "user"}

# Scenario requires the container to be declared in State even when can_connect=False.
_GATEWAY = Container(CONTAINER_NAME, can_connect=False)

# Traefik's app databag comes back empty; the unit writes into local_app_data.
_INGRESS_REL = Relation("ingress")
_PORT_8443 = TCPPort(8443)
_PORT_9090 = TCPPort(9090)


def _ctx() -> Context:
    return Context(OpenshellGatewayK8sCharm)


def _ingress_rel_from_out(out: State) -> Relation:
    rels = [r for r in out.relations if r.endpoint == "ingress"]
    assert rels, "expected ingress relation in output state"
    return rels[0]


# ---------------------------------------------------------------------------
# Pure-unit: config assembly helpers
# ---------------------------------------------------------------------------


class TestConfigAssembly:
    def test_static_config(self):
        ig = object.__new__(GatewayIngress)
        result = GatewayIngress._static_config(ig)
        assert result == {"entryPoints": {"openshell-grpc": {"address": ":8443"}}}

    def test_dynamic_config_wildcard(self):
        class _FakeCharm:
            class app:  # noqa: N801
                name = "openshell-gateway-k8s"

            class model:  # noqa: N801
                name = "test-model"

        ig = object.__new__(GatewayIngress)
        ig._charm = _FakeCharm()
        result = GatewayIngress._dynamic_config(ig, None)
        tcp = result["tcp"]
        assert tcp["routers"]["openshell-grpc"]["rule"] == "HostSNI(`*`)"
        assert tcp["routers"]["openshell-grpc"]["tls"] == {"passthrough": True}
        assert (
            tcp["services"]["openshell-grpc"]["loadBalancer"]["servers"][0]["address"]
            == "openshell-gateway-k8s.test-model.svc.cluster.local:8443"
        )

    def test_dynamic_config_hostname(self):
        class _FakeCharm:
            class app:  # noqa: N801
                name = "openshell-gateway-k8s"

            class model:  # noqa: N801
                name = "test-model"

        ig = object.__new__(GatewayIngress)
        ig._charm = _FakeCharm()
        result = GatewayIngress._dynamic_config(ig, "my.host.com")
        rule = result["tcp"]["routers"]["openshell-grpc"]["rule"]
        assert rule == "HostSNI(`my.host.com`)"

    def test_invalid_hostname_rejected(self):
        assert _valid_hostname("foo`)||(HostSNI(`*") is False
        assert _valid_hostname("my.host.com") is True
        assert _valid_hostname("") is False

    def test_ip_address_treated_as_valid_for_wildcard_sni(self):
        class _FakeCharm:
            class app:  # noqa: N801
                name = "openshell-gateway-k8s"

            class model:  # noqa: N801
                name = "test-model"

            config = {"external-hostname": "10.43.45.0"}

        ig = object.__new__(GatewayIngress)
        ig._charm = _FakeCharm()
        hostname, valid = GatewayIngress._resolved_hostname(ig)
        assert hostname is None
        assert valid is True

    def test_ip_helper(self):
        assert _is_ip_address("10.43.45.0") is True
        assert _is_ip_address("2001:db8::1") is True
        assert _is_ip_address("my.host.com") is False
        assert _is_ip_address("") is False


# ---------------------------------------------------------------------------
# Scenario: submit on relation-changed (VC 2 wildcard, VC 3 raw)
# ---------------------------------------------------------------------------


class TestSubmitOnRelationChanged:
    def test_submits_on_relation_changed(self):
        """Wildcard route submitted when ingress relation present, no hostname."""
        ctx = _ctx()
        out = ctx.run(
            ctx.on.relation_changed(relation=_INGRESS_REL),
            State(config=_ROLES, leader=True, relations=[_INGRESS_REL], containers=[_GATEWAY]),
        )
        rel = _ingress_rel_from_out(out)
        assert rel.local_app_data.get("raw") == "True"
        static = yaml.safe_load(rel.local_app_data["static"])
        assert static["entryPoints"]["openshell-grpc"]["address"] == ":8443"
        cfg = yaml.safe_load(rel.local_app_data["config"])
        router = cfg["tcp"]["routers"]["openshell-grpc"]
        assert router["rule"] == "HostSNI(`*`)"
        assert router["tls"] == {"passthrough": True}
        # Service backend contains the K8s service address
        svc_addr = cfg["tcp"]["services"]["openshell-grpc"]["loadBalancer"]["servers"][0][
            "address"
        ]
        assert ".svc.cluster.local:8443" in svc_addr


# ---------------------------------------------------------------------------
# Scenario: submit with explicit hostname (VC 1)
# ---------------------------------------------------------------------------


class TestSubmitWithHostname:
    def test_submits_with_hostname(self):
        """Hostname is validated and lowercased before embedding in the rule."""
        ctx = _ctx()
        out = ctx.run(
            ctx.on.relation_changed(relation=_INGRESS_REL),
            State(
                config={**_ROLES, "external-hostname": "My.Host.COM"},
                leader=True,
                relations=[_INGRESS_REL],
                containers=[_GATEWAY],
            ),
        )
        rel = _ingress_rel_from_out(out)
        cfg = yaml.safe_load(rel.local_app_data["config"])
        rule = cfg["tcp"]["routers"]["openshell-grpc"]["rule"]
        assert rule == "HostSNI(`my.host.com`)"
        # Original mixed-case value must not appear in the submitted config
        assert "My.Host.COM" not in rel.local_app_data["config"]

    def test_hostname_change_reconverges(self):
        """config_changed with a new hostname reconverges the databag (VC 9)."""
        ctx = _ctx()
        # First submission with hostname A
        out_a = ctx.run(
            ctx.on.relation_changed(relation=_INGRESS_REL),
            State(
                config={**_ROLES, "external-hostname": "host-a.example.com"},
                leader=True,
                relations=[_INGRESS_REL],
                containers=[_GATEWAY],
            ),
        )
        cfg_a = yaml.safe_load(_ingress_rel_from_out(out_a).local_app_data["config"])
        assert cfg_a["tcp"]["routers"]["openshell-grpc"]["rule"] == "HostSNI(`host-a.example.com`)"

        # Second trigger: hostname changes to B
        out_b = ctx.run(
            ctx.on.config_changed(),
            State(
                config={**_ROLES, "external-hostname": "host-b.example.com"},
                leader=True,
                relations=[_INGRESS_REL],
                containers=[_GATEWAY],
            ),
        )
        cfg_b = yaml.safe_load(_ingress_rel_from_out(out_b).local_app_data["config"])
        assert cfg_b["tcp"]["routers"]["openshell-grpc"]["rule"] == "HostSNI(`host-b.example.com`)"


# ---------------------------------------------------------------------------
# Scenario: invalid hostname rejected (VC 6)
# ---------------------------------------------------------------------------


class TestInvalidHostname:
    def test_invalid_hostname_no_submission(self):
        """Invalid external-hostname: route not submitted, status is blocked."""
        ctx = _ctx()
        out = ctx.run(
            ctx.on.collect_unit_status(),
            State(
                config={**_ROLES, "external-hostname": "foo`)||(HostSNI(`*"},
                leader=True,
                relations=[_INGRESS_REL],
                containers=[_GATEWAY],
            ),
        )
        assert isinstance(out.unit_status, BlockedStatus)
        assert "not a valid hostname" in out.unit_status.message

    def test_invalid_hostname_config_not_submitted(self):
        """Invalid hostname must never appear in the submitted config."""
        ctx = _ctx()
        out = ctx.run(
            ctx.on.relation_changed(relation=_INGRESS_REL),
            State(
                config={**_ROLES, "external-hostname": "foo`)||(HostSNI(`*"},
                leader=True,
                relations=[_INGRESS_REL],
                containers=[_GATEWAY],
            ),
        )
        rel = _ingress_rel_from_out(out)
        # No config written — the invalid value must never reach the databag
        assert "config" not in rel.local_app_data


# ---------------------------------------------------------------------------
# Scenario: wildcard status contributed via collect_unit_status (VC 2)
# ---------------------------------------------------------------------------


class TestWildcardStatus:
    def test_wildcard_sets_warning_status(self):
        """No hostname → wildcard ActiveStatus contributed via collect_unit_status."""
        from unittest.mock import patch

        ctx = _ctx()
        with patch.object(OpenshellGatewayK8sCharm, "_readiness_gaps", return_value=[]):
            out = ctx.run(
                ctx.on.collect_unit_status(),
                State(config=_ROLES, leader=True, relations=[_INGRESS_REL], containers=[_GATEWAY]),
            )
        assert isinstance(out.unit_status, ActiveStatus)
        assert "wildcard SNI active" in out.unit_status.message


# ---------------------------------------------------------------------------
# Scenario: status coexistence with workload (VC derived)
# ---------------------------------------------------------------------------


class TestStatusCoexistence:
    def test_invalid_hostname_blocks_over_workload_active(self):
        """Ingress BlockedStatus wins over workload ActiveStatus (higher severity)."""
        from unittest.mock import patch

        ctx = _ctx()
        with patch.object(OpenshellGatewayK8sCharm, "_readiness_gaps", return_value=[]):
            out = ctx.run(
                ctx.on.collect_unit_status(),
                State(
                    config={**_ROLES, "external-hostname": "bad val!"},
                    leader=True,
                    relations=[_INGRESS_REL],
                    containers=[_GATEWAY],
                ),
            )
        assert isinstance(out.unit_status, BlockedStatus)
        assert "not a valid hostname" in out.unit_status.message

    def test_workload_waiting_wins_over_ingress_active(self):
        """Workload WaitingStatus wins over ingress ActiveStatus."""
        ctx = _ctx()
        # No ingress hostname + no workload relations → workload Waiting wins
        out = ctx.run(
            ctx.on.collect_unit_status(),
            State(config=_ROLES, leader=True, relations=[_INGRESS_REL], containers=[_GATEWAY]),
        )
        # Workload is waiting (container not connectable) which is higher than ActiveStatus
        assert not isinstance(out.unit_status, ActiveStatus)


# ---------------------------------------------------------------------------
# Scenario: port opened unconditionally, additive (VC 4, VC 7)
# ---------------------------------------------------------------------------


class TestPortOpened:
    def test_port_opened_without_readiness(self):
        """Port 8443 opened even when workload readiness gate unmet; pre-existing port survives."""
        ctx = _ctx()
        out = ctx.run(
            ctx.on.relation_changed(relation=_INGRESS_REL),
            State(
                config=_ROLES,
                leader=True,
                relations=[_INGRESS_REL],
                opened_ports=[_PORT_9090],  # pre-existing unrelated port
                containers=[_GATEWAY],
            ),
        )
        ports = out.opened_ports
        assert _PORT_8443 in ports, "tcp/8443 must be opened"
        assert _PORT_9090 in ports, "pre-existing tcp/9090 must not be clobbered"

    def test_port_opened_on_follower(self):
        """Port 8443 opened even when unit is not the leader (VC 7)."""
        ctx = _ctx()
        out = ctx.run(
            ctx.on.relation_changed(relation=_INGRESS_REL),
            State(
                config=_ROLES,
                leader=False,
                relations=[_INGRESS_REL],
                containers=[_GATEWAY],
            ),
        )
        assert _PORT_8443 in out.opened_ports


# ---------------------------------------------------------------------------
# Scenario: no relation → no submit, port still opened (VC 5)
# ---------------------------------------------------------------------------


class TestNoRelation:
    def test_no_submit_without_relation(self):
        """No ingress relation: nothing submitted, no error, port still opened."""
        ctx = _ctx()
        out = ctx.run(
            ctx.on.config_changed(),
            State(config=_ROLES, leader=True, relations=[], containers=[_GATEWAY]),
        )
        # No ingress relation in output state
        assert not any(r.endpoint == "ingress" for r in out.relations)
        # Port still opened unconditionally
        assert _PORT_8443 in out.opened_ports


# ---------------------------------------------------------------------------
# Scenario: leader_elected re-submits (VC 3 re-submission path)
# ---------------------------------------------------------------------------


class TestLeaderElected:
    def test_resubmits_on_leader_elected(self):
        """Newly-elected leader re-submits the route immediately."""
        ctx = _ctx()
        out = ctx.run(
            ctx.on.leader_elected(),
            State(
                config=_ROLES,
                leader=True,
                relations=[_INGRESS_REL, PeerRelation(RESTART_RELATION)],
                containers=[_GATEWAY],
            ),
        )
        rel = _ingress_rel_from_out(out)
        assert rel.local_app_data.get("raw") == "True"
        assert "static" in rel.local_app_data
        assert "config" in rel.local_app_data
        cfg = yaml.safe_load(rel.local_app_data["config"])
        assert "tcp" in cfg


# ---------------------------------------------------------------------------
# Scenario: relation_broken — no submit, no error (VC 8)
# ---------------------------------------------------------------------------


class TestRelationBroken:
    def test_no_error_on_relation_broken(self):
        """relation_broken: charm settles without error, no fresh submission written."""
        ctx = _ctx()
        out = ctx.run(
            ctx.on.relation_broken(relation=_INGRESS_REL),
            State(config=_ROLES, leader=True, relations=[_INGRESS_REL], containers=[_GATEWAY]),
        )
        # Scenario keeps the departing relation in out.relations during the hook;
        # assert its local_app_data unconditionally so the check always executes.
        ingress_rels = [r for r in out.relations if r.endpoint == "ingress"]
        assert len(ingress_rels) == 1, "expected exactly one ingress relation in output state"
        assert "config" not in ingress_rels[0].local_app_data, (
            "no config should be submitted during relation_broken"
        )

    def test_no_active_ingress_status_after_relation_broken(self):
        """collect_unit_status after relation_broken: no wildcard-active ingress status."""
        ctx = _ctx()
        # After relation is removed, collect_unit_status should not emit ingress active msg
        out = ctx.run(
            ctx.on.collect_unit_status(),
            State(
                config=_ROLES, leader=True, relations=[], containers=[_GATEWAY]
            ),  # no ingress relation
        )
        msg = out.unit_status.message if out.unit_status else ""
        assert "wildcard SNI active" not in msg
