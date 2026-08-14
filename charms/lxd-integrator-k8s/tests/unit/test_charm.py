"""Unit tests for the integrator charm entrypoint."""

from __future__ import annotations

import hashlib
import json

import pytest
from ops.testing import Context, Relation, Secret, State

from charm import LxdIntegratorCharm
from lxd_api import pem_fingerprint


def _credentials_secret(client_cert: str, client_key: str) -> Secret:
    return Secret(
        id="secret:0123456789abcdef0123",
        tracked_content={"client-cert": client_cert, "client-key": client_key},
    )


def _state(
    client_cert: str,
    client_key: str,
    server_fingerprint: str,
    relations: set[Relation] | None = None,
    leader: bool = False,
    **config_overrides: object,
) -> State:
    config: dict[str, object] = {
        "lxd-endpoints": "localhost",
        "lxd-server-fingerprint": server_fingerprint,
        "lxd-credentials": "secret:0123456789abcdef0123",
    }
    config.update(config_overrides)
    secret = _credentials_secret(client_cert, client_key)
    return State(
        config=config,
        secrets={secret},
        relations=relations or set(),
        leader=leader,
    )


def _run_reconcile(
    ctx: Context,
    state: State,
    transport,
) -> State:
    with ctx._run(ctx.on.config_changed(), state) as ops:
        ops.charm._connection_factory = transport
        ops.run()
    return ops.state


@pytest.fixture
def base_state(cert_pair):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()

    def make(relations=None, leader=False, **overrides):
        return _state(
            cert_pem, key_pem, fingerprint, relations=relations, leader=leader, **overrides
        )

    return make


def test_charm_starts(cert_pair):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    ctx = Context(LxdIntegratorCharm)
    state = _state(cert_pem, key_pem, fingerprint)
    with ctx._run(ctx.on.start(), state) as ops:
        ops.run()
        charm = ops.charm

    assert charm._model is not None
    assert charm._config_error is None
    assert charm._model.client_cert == cert_pem
    assert charm._model.client_key == key_pem


def test_missing_secret_is_config_error():
    ctx = Context(LxdIntegratorCharm)
    state = State(config={"lxd-endpoints": "localhost"})
    with ctx._run(ctx.on.start(), state) as ops:
        ops.run()
        charm = ops.charm

    assert charm._model is None
    assert charm._config_error is not None
    assert not charm._config_error.startswith("Value error")


def test_publish_single_endpoint_to_unit_bag(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    relation = Relation(endpoint="https", remote_app_name="openshell-gateway")
    state = base_state(relations={relation}, leader=True)
    tr = transport()
    state_out = _run_reconcile(ctx, state, tr)

    rel_out = state_out.get_relation(relation.id)
    assert rel_out.local_unit_data["version"] == "1.0"
    assert "certificate_fingerprint" in rel_out.local_unit_data
    assert rel_out.local_unit_data["addresses"] == "localhost:8443"
    assert rel_out.local_app_data == {}


def test_publish_clustered_to_app_bag(cert_pair, transport):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    ctx = Context(LxdIntegratorCharm)
    relation = Relation(endpoint="https", remote_app_name="openshell-gateway")
    state = _state(
        cert_pem,
        key_pem,
        fingerprint,
        relations={relation},
        leader=True,
        **{"lxd-endpoints": "10.0.0.1:8443, 10.0.0.2:8443"},
    )
    tr = transport()
    state_out = _run_reconcile(ctx, state, tr)

    rel_out = state_out.get_relation(relation.id)
    assert rel_out.local_app_data["addresses"] == "10.0.0.1:8443,10.0.0.2:8443"
    assert "addresses" not in rel_out.local_unit_data


def test_publish_fingerprint_only_omits_certificate(cert_pair, transport):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    ctx = Context(LxdIntegratorCharm)
    relation = Relation(endpoint="https", remote_app_name="openshell-gateway")
    state = _state(cert_pem, key_pem, fingerprint, relations={relation}, leader=True)
    tr = transport()
    state_out = _run_reconcile(ctx, state, tr)

    rel_out = state_out.get_relation(relation.id)
    assert "certificate" not in rel_out.local_unit_data
    assert rel_out.local_unit_data["certificate_fingerprint"] == fingerprint


def test_register_requirer_certificate(base_state, transport, requirer_cert):
    ctx = Context(LxdIntegratorCharm)
    requirer_cert = requirer_cert.strip()
    relation = Relation(
        endpoint="https",
        remote_app_name="openshell-gateway",
        remote_app_data={"certificate": requirer_cert},
    )
    state = base_state(relations={relation}, leader=True)
    tr = transport()
    tr.add_response("GET", "/1.0/certificates", 200, [])
    tr.add_response("POST", "/1.0/certificates", 200, {})
    _run_reconcile(ctx, state, tr)

    post = [r for r in tr.requests if r[:2] == ("POST", "/1.0/certificates")]
    assert len(post) == 1
    body = json.loads(post[0][2] or b"{}")
    assert body["name"] == "juju-relation-openshell-gateway"


def test_register_idempotent_on_rerun(base_state, transport, requirer_cert):
    ctx = Context(LxdIntegratorCharm)
    requirer_cert = requirer_cert.strip()
    relation = Relation(
        endpoint="https",
        remote_app_name="openshell-gateway",
        remote_app_data={"certificate": requirer_cert},
    )
    state = base_state(relations={relation}, leader=True)

    tr = transport()
    tr.add_response("GET", "/1.0/certificates", 200, [])
    tr.add_response("POST", "/1.0/certificates", 200, {})
    state_out = _run_reconcile(ctx, state, tr)
    posts_1 = [r for r in tr.requests if r[:2] == ("POST", "/1.0/certificates")]
    assert len(posts_1) == 1

    tr2 = transport()
    tr2.add_response(
        "GET",
        "/1.0/certificates",
        200,
        [
            {
                "name": "juju-relation-openshell-gateway",
                "fingerprint": pem_fingerprint(requirer_cert),
            },
        ],
    )
    _run_reconcile(ctx, state_out, tr2)
    posts_2 = [r for r in tr2.requests if r[:2] == ("POST", "/1.0/certificates")]
    assert len(posts_2) == 0


def test_revoke_on_relation_broken(base_state, transport, requirer_cert):
    ctx = Context(LxdIntegratorCharm)
    requirer_cert = requirer_cert.strip()
    relation = Relation(
        endpoint="https",
        remote_app_name="openshell-gateway",
        remote_app_data={"certificate": requirer_cert},
    )
    state = base_state(relations={relation}, leader=True)

    tr = transport()
    tr.add_response("GET", "/1.0/certificates", 200, [])
    tr.add_response("POST", "/1.0/certificates", 200, {})
    state_out = _run_reconcile(ctx, state, tr)

    tr2 = transport()
    fp = pem_fingerprint(requirer_cert)
    tr2.add_response(
        "GET",
        "/1.0/certificates",
        200,
        [
            {"name": "juju-relation-openshell-gateway", "fingerprint": fp},
        ],
    )
    tr2.add_response("DELETE", f"/1.0/certificates/{fp}", 200, {})
    relation_out = state_out.get_relation(relation.id)
    with ctx._run(ctx.on.relation_broken(relation_out), state_out) as ops:
        ops.charm._connection_factory = tr2
        ops.run()

    deletes = [r for r in tr2.requests if r[0] == "DELETE"]
    assert len(deletes) == 1


def test_non_charm_owned_entry_not_revoked(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    relation = Relation(endpoint="https", remote_app_name="openshell-gateway")
    state = base_state(relations={relation}, leader=True)

    tr = transport()
    tr.add_response(
        "GET",
        "/1.0/certificates",
        200,
        [
            {"name": "manual-entry", "fingerprint": "aa" * 32},
        ],
    )
    _run_reconcile(ctx, state, tr)

    deletes = [r for r in tr.requests if r[0] == "DELETE"]
    assert len(deletes) == 0


def test_requirer_projects_override_default(cert_pair, transport):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    ctx = Context(LxdIntegratorCharm)
    requirer_cert = cert_pair[0]
    relation = Relation(
        endpoint="https",
        remote_app_name="openshell-gateway",
        remote_app_data={"certificate": requirer_cert, "projects": "project-a, project-b"},
    )
    state = _state(
        cert_pem,
        key_pem,
        fingerprint,
        relations={relation},
        leader=True,
        **{"default-projects": "default"},
    )
    tr = transport()
    tr.add_response("GET", "/1.0/certificates", 200, [])
    tr.add_response("POST", "/1.0/certificates", 200, {})
    _run_reconcile(ctx, state, tr)

    post = [r for r in tr.requests if r[:2] == ("POST", "/1.0/certificates")][0]
    body = json.loads(post[2] or b"{}")
    assert body["projects"] == ["project-a", "project-b"]
    assert body["restricted"] is True


def test_default_projects_parsed_and_restricted(base_state, transport, requirer_cert):
    ctx = Context(LxdIntegratorCharm)
    relation = Relation(
        endpoint="https",
        remote_app_name="openshell-gateway",
        remote_app_data={"certificate": requirer_cert.strip()},
    )
    state = base_state(
        relations={relation},
        leader=True,
        **{"default-projects": "project-a, project-b"},
    )
    tr = transport()
    tr.add_response("GET", "/1.0/certificates", 200, [])
    tr.add_response("POST", "/1.0/certificates", 200, {})
    _run_reconcile(ctx, state, tr)

    post = [r for r in tr.requests if r[:2] == ("POST", "/1.0/certificates")][0]
    body = json.loads(post[2] or b"{}")
    assert body["projects"] == ["project-a", "project-b"]
    assert body["restricted"] is True


def test_malformed_requirer_cert_skipped(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    relation = Relation(
        endpoint="https",
        remote_app_name="openshell-gateway",
        remote_app_data={"certificate": "not-valid-pem"},
    )
    state = base_state(relations={relation}, leader=True)
    tr = transport()
    tr.add_response("GET", "/1.0/certificates", 200, [])
    _run_reconcile(ctx, state, tr)

    posts = [r for r in tr.requests if r[:2] == ("POST", "/1.0/certificates")]
    assert len(posts) == 0


def test_incomplete_credentials_build_client_none():
    secret = Secret(
        id="secret:0123456789abcdef0123",
        tracked_content={"client-cert": "CLIENT_CERT", "server-cert": "SERVER_CERT"},
    )
    ctx = Context(LxdIntegratorCharm)
    state = State(
        config={
            "lxd-endpoints": "localhost",
            "lxd-credentials": secret.id,
            "lxd-server-fingerprint": "aa" * 32,
        },
        secrets={secret},
    )
    with ctx._run(ctx.on.start(), state) as ops:
        ops.run()
        charm = ops.charm

    assert charm._build_client() is None
    assert ops.state.unit_status.name == "blocked"


def test_databag_published_when_lxd_unreachable(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    relation = Relation(endpoint="https", remote_app_name="openshell-gateway")
    state = base_state(relations={relation}, leader=True)
    tr = transport()
    tr.raise_on_connect = True
    state_out = _run_reconcile(ctx, state, tr)

    rel_out = state_out.get_relation(relation.id)
    assert rel_out.local_unit_data["addresses"] == "localhost:8443"


def test_lxd_api_error_skips_convergence(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    requirer_cert = "REQUIRER_CERT"
    relation = Relation(
        endpoint="https",
        remote_app_name="openshell-gateway",
        remote_app_data={"certificate": requirer_cert},
    )
    state = base_state(relations={relation}, leader=True)
    tr = transport()
    tr.add_response("GET", "/1.0/certificates", 500, {})
    _run_reconcile(ctx, state, tr)

    posts = [r for r in tr.requests if r[:2] == ("POST", "/1.0/certificates")]
    assert len(posts) == 0


def test_get_connection_info_action_trusted(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True)
    tr = transport()
    tr.add_response("GET", "/1.0/auth/identities/current", 200, {"type": "Client certificate"})

    with ctx._run(ctx.on.action("get-connection-info"), state) as ops:
        ops.charm._connection_factory = tr
        ops.run()

    assert ctx.action_results["trusted"] == "true"
    assert ctx.action_results["addresses"] == "localhost:8443"
    assert "certificate-fingerprint" in ctx.action_results


def test_get_connection_info_action_untrusted(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True)
    tr = transport()
    tr.add_response("GET", "/1.0/auth/identities/current", 403, {})

    with ctx._run(ctx.on.action("get-connection-info"), state) as ops:
        ops.charm._connection_factory = tr
        ops.run()

    assert ctx.action_results["trusted"] == "false"


def test_get_connection_info_action_unreachable(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True)
    tr = transport()
    tr.raise_on_connect = True

    with (
        pytest.raises(Exception) as exc_info,
        ctx._run(ctx.on.action("get-connection-info"), state) as ops,
    ):
        ops.charm._connection_factory = tr
        ops.run()

    assert "LXD unreachable" in str(exc_info.value)


def test_list_trusted_clients_action(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True)
    tr = transport()
    tr.add_response(
        "GET",
        "/1.0/certificates",
        200,
        [
            {"name": "juju-relation-openshell-gateway", "fingerprint": "aa" * 32},
            {"name": "manual-entry", "fingerprint": "bb" * 32},
        ],
    )

    with ctx._run(ctx.on.action("list-trusted-clients"), state) as ops:
        ops.charm._connection_factory = tr
        ops.run()

    clients = ctx.action_results["clients"]
    assert len(clients) == 1
    assert clients[0]["name"] == "juju-relation-openshell-gateway"


def test_list_trusted_clients_action_unreachable(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True)
    tr = transport()
    tr.raise_on_connect = True

    with (
        pytest.raises(Exception) as exc_info,
        ctx._run(ctx.on.action("list-trusted-clients"), state) as ops,
    ):
        ops.charm._connection_factory = tr
        ops.run()

    assert "LXD unreachable" in str(exc_info.value)


def test_status_blocked_without_credentials():
    ctx = Context(LxdIntegratorCharm)
    state = State(config={"lxd-endpoints": "localhost"})
    state_out = ctx.run(ctx.on.start(), state)
    assert state_out.unit_status.name == "blocked"


def test_status_waiting_when_lxd_unreachable(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True)
    tr = transport()
    tr.raise_on_connect = True

    with ctx._run(ctx.on.update_status(), state) as ops:
        ops.charm._connection_factory = tr
        ops.run()

    assert ops.state.unit_status.name == "waiting"


def test_status_active_when_trusted(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True)
    tr = transport()
    tr.add_response("GET", "/1.0/auth/identities/current", 200, {"type": "Client certificate"})

    with ctx._run(ctx.on.update_status(), state) as ops:
        ops.charm._connection_factory = tr
        ops.run()

    assert ops.state.unit_status.name == "active"


def test_status_blocked_on_verification_error(base_state, transport):
    state = base_state(leader=True)
    tr = transport()
    # Use a mismatched server fingerprint to trigger VerificationError.
    ctx = Context(LxdIntegratorCharm)
    state2 = State(
        config={
            "lxd-endpoints": "localhost",
            "lxd-server-fingerprint": "00" * 32,
            "lxd-credentials": state.config["lxd-credentials"],
        },
        secrets=state.secrets,
        leader=True,
    )

    with ctx._run(ctx.on.update_status(), state2) as ops:
        ops.charm._connection_factory = tr
        ops.run()

    assert ops.state.unit_status.name == "blocked"


def test_status_blocked_on_api_error(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True)
    tr = transport()
    tr.add_response("GET", "/1.0/auth/identities/current", 500, {})

    with ctx._run(ctx.on.update_status(), state) as ops:
        ops.charm._connection_factory = tr
        ops.run()

    assert ops.state.unit_status.name == "blocked"


def test_get_connection_info_action_ipv6_endpoint_bracketed(cert_pair, transport):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    ctx = Context(LxdIntegratorCharm)
    state = _state(
        cert_pem,
        key_pem,
        fingerprint,
        leader=True,
        **{"lxd-endpoints": "[::1]:8443"},
    )
    tr = transport()
    tr.add_response("GET", "/1.0/auth/identities/current", 200, {"type": "Client certificate"})

    with ctx._run(ctx.on.action("get-connection-info"), state) as ops:
        ops.charm._connection_factory = tr
        ops.run()

    assert ctx.action_results["endpoint"] == "[::1]:8443"
    assert ctx.action_results["addresses"] == "[::1]:8443"


def test_get_connection_info_action_api_error(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True)
    tr = transport()
    tr.add_response("GET", "/1.0/auth/identities/current", 500, {})

    with (
        pytest.raises(Exception) as exc_info,
        ctx._run(ctx.on.action("get-connection-info"), state) as ops,
    ):
        ops.charm._connection_factory = tr
        ops.run()

    assert "LXD API error" in str(exc_info.value)


def test_get_connection_info_action_verification_error(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True, **{"lxd-server-fingerprint": "00" * 32})
    tr = transport()

    with (
        pytest.raises(Exception) as exc_info,
        ctx._run(ctx.on.action("get-connection-info"), state) as ops,
    ):
        ops.charm._connection_factory = tr
        ops.run()

    assert "server identity mismatch" in str(exc_info.value)


def test_list_trusted_clients_action_api_error(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True)
    tr = transport()
    tr.add_response("GET", "/1.0/certificates", 500, {})

    with (
        pytest.raises(Exception) as exc_info,
        ctx._run(ctx.on.action("list-trusted-clients"), state) as ops,
    ):
        ops.charm._connection_factory = tr
        ops.run()

    assert "LXD API error" in str(exc_info.value)


def test_list_trusted_clients_action_verification_error(base_state, transport):
    ctx = Context(LxdIntegratorCharm)
    state = base_state(leader=True, **{"lxd-server-fingerprint": "00" * 32})
    tr = transport()

    with (
        pytest.raises(Exception) as exc_info,
        ctx._run(ctx.on.action("list-trusted-clients"), state) as ops,
    ):
        ops.charm._connection_factory = tr
        ops.run()

    assert "server identity mismatch" in str(exc_info.value)


def test_reconcile_skips_on_verification_error(cert_pair, transport):
    cert_pem, key_pem, cert_der = cert_pair
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    ctx = Context(LxdIntegratorCharm)
    relation = Relation(endpoint="https", remote_app_name="openshell-gateway")
    state = _state(
        cert_pem,
        key_pem,
        fingerprint,
        relations={relation},
        leader=True,
        **{"lxd-server-fingerprint": "00" * 32},
    )
    tr = transport()

    state_out = _run_reconcile(ctx, state, tr)

    rel_out = state_out.get_relation(relation.id)
    assert rel_out.local_unit_data["addresses"] == "localhost:8443"
    assert len([r for r in tr.requests if r[:2] == ("GET", "/1.0/certificates")]) == 0
    assert len([r for r in tr.requests if r[:2] == ("POST", "/1.0/certificates")]) == 0
