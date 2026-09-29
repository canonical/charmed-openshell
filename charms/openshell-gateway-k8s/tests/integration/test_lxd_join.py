"""Integration tests for joining the gateway to LXD with a trust token.

The session fixture ``lxd_joined`` creates, on the host LXD, a group granted
``operator`` on IT_PROJECT only and a pending TLS identity in it, and hands
the identity's trust token to the gateway through a granted Juju secret. The
gateway's leader redeems it with the application's own LXD client
certificate. These tests assert what LXD records, what the gateway reports,
how it reports a token it cannot use, and that sandboxes land in the project.

Each test that breaks the join restores it before it returns, so the tests
do not depend on their order.
"""

from __future__ import annotations

import logging
from collections.abc import Generator

import jubilant
import pytest

from .helpers import (
    APP_NAME,
    IT_GROUP,
    IT_IDENTITY,
    IT_PROJECT,
    gateway_client_cert_fingerprint,
    gateway_status,
    join_gateway_to_lxd,
    lxc_instance_projects,
    prepare_openshell_client,
    put_join_secret,
    run_gated_sandbox_e2e,
    wait_for_gateway_message,
    wait_for_gateway_stack,
    wait_for_identity_trusted,
)
from .lxd_host import HostLxdEndpoint, create_pending_identity, delete_identity, lxd_identity

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.lxd]

#: A config option whose change fires config-changed without touching LXD.
_NUDGE_OPTION = "lxd-operation-timeout-secs"


def _nudge(juju: jubilant.Juju, value: int) -> None:
    """Fire config-changed, since granting or revoking a secret fires no hook."""
    juju.config(APP_NAME, {_NUDGE_OPTION: value})


def _join_secret_uri(juju: jubilant.Juju) -> str:
    return str(juju.config(APP_NAME)["lxd-join-secret"])


@pytest.fixture
def rejoin_afterwards(
    juju: jubilant.Juju, host_lxd_endpoint: HostLxdEndpoint
) -> Generator[None, None, None]:
    """Leave the gateway joined with a fresh identity and the stack converged."""
    yield
    join_gateway_to_lxd(juju, host_lxd_endpoint.host_runner)
    juju.config(APP_NAME, reset=[_NUDGE_OPTION])
    wait_for_gateway_stack(juju)


class TestLxdJoin:
    def test_the_leader_redeems_the_token_for_the_gateway_certificate(
        self,
        juju: jubilant.Juju,
        host_lxd_endpoint: HostLxdEndpoint,
        lxd_joined: None,
    ) -> None:
        """LXD binds the pending identity to the gateway's own client certificate."""
        entry = wait_for_identity_trusted(
            lambda: lxd_identity(host_lxd_endpoint.host_runner, IT_IDENTITY),
            gateway_client_cert_fingerprint(juju),
        )
        assert entry.get("groups") == [IT_GROUP], entry

    def test_status_reports_where_the_driver_reaches_lxd(
        self,
        juju: jubilant.Juju,
        host_lxd_endpoint: HostLxdEndpoint,
        lxd_joined: None,
    ) -> None:
        status = gateway_status(juju)
        assert status["lxd-project"] == IT_PROJECT, status
        assert status["lxd-url"].startswith("https://"), status
        assert status["readiness-gaps"] == "none", status
        assert status["workload-running"] == "True", status

    def test_an_unset_join_secret_blocks(
        self,
        juju: jubilant.Juju,
        lxd_joined: None,
    ) -> None:
        uri = _join_secret_uri(juju)
        juju.config(APP_NAME, reset=["lxd-join-secret"])
        try:
            wait_for_gateway_message(juju, "lxd-join-secret not set")
        finally:
            juju.config(APP_NAME, {"lxd-join-secret": uri})
            wait_for_gateway_stack(juju)

    def test_a_secret_not_granted_blocks(
        self,
        juju: jubilant.Juju,
        lxd_joined: None,
    ) -> None:
        uri = _join_secret_uri(juju)
        juju.cli("revoke-secret", uri, APP_NAME)
        try:
            _nudge(juju, 61)
            wait_for_gateway_message(
                juju, "cannot read lxd-join-secret; grant it to this application"
            )
        finally:
            juju.grant_secret(uri, APP_NAME)
            juju.config(APP_NAME, reset=[_NUDGE_OPTION])
            wait_for_gateway_stack(juju)

    def test_a_token_lxd_refuses_blocks_with_lxds_reason(
        self,
        juju: jubilant.Juju,
        host_lxd_endpoint: HostLxdEndpoint,
        lxd_joined: None,
        rejoin_afterwards: None,
    ) -> None:
        """A token LXD no longer knows is reported, not retried silently.

        A gateway LXD still trusts never redeems again, so the identity is
        deleted first; the replacement token is spent before the gateway sees
        it, by deleting the pending identity it belongs to.
        """
        runner = host_lxd_endpoint.host_runner
        delete_identity(runner, IT_IDENTITY)
        spent = create_pending_identity(runner, IT_IDENTITY, IT_GROUP)
        delete_identity(runner, IT_IDENTITY)

        put_join_secret(juju, spent)
        wait_for_gateway_message(juju, "cannot join LXD: LXD refused the token")

    def test_a_sandbox_lands_in_the_joined_project(
        self,
        juju: jubilant.Juju,
        gateway_url: str,
        host_lxd_endpoint: HostLxdEndpoint,
        lxd_joined: None,
        requires_sandbox_e2e: None,
        openshell_available: None,
    ) -> None:
        """Gated: a sandbox created through the gateway appears in IT_PROJECT only."""
        creds = prepare_openshell_client(juju, gateway_url)
        sandbox_name = "it-sbx-proj"
        observed: dict[str, str] = {}

        def _capture() -> None:
            observed.update(lxc_instance_projects(host_lxd_endpoint.host_runner, sandbox_name))

        run_gated_sandbox_e2e(
            gateway_url=creds["gateway_url"],
            issuer_url=creds["issuer_url"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            audience=creds["audience"],
            gateway_name="integration-test-gateway-project",
            sandbox_name=sandbox_name,
            while_running=_capture,
        )

        assert observed, (
            f"no LXD instance named {sandbox_name}* was found in any project while "
            "the sandbox was running"
        )
        assert set(observed.values()) == {IT_PROJECT}, observed
