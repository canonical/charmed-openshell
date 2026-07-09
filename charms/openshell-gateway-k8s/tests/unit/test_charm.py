"""Ops Scenario tests for charm.py — status surfacing (VP-3)."""

from __future__ import annotations

import pytest
from ops import ActiveStatus, BlockedStatus
from ops.testing import Context, State

from charm import OpenshellGatewayK8sCharm

RBAC_REQUIRED_MSG = "both oidc-admin-role and oidc-user-role must be set (RBAC required)"
TOGETHER_ADMIN_MSG = "oidc-admin-role and oidc-user-role must be set together; got only oidc-admin-role"
TOGETHER_USER_MSG = "oidc-admin-role and oidc-user-role must be set together; got only oidc-user-role"


def _state(**config_values) -> State:
    return State(config=config_values)


class TestStatusSurfacing:
    """VP-3: status is derived centrally in collect-unit-status (B1 pattern)."""

    def _assert_status(self, config: dict, expected_status):
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _state(**config)
        # Exercise config_changed path first (no status assertion here).
        ctx.run(ctx.on.config_changed(), state)
        # Assert status from collect_unit_status dispatch.
        out = ctx.run(ctx.on.collect_unit_status(), state)
        assert out.unit_status == expected_status

    def test_neither_role_is_blocked(self):
        self._assert_status({}, BlockedStatus(RBAC_REQUIRED_MSG))

    def test_only_admin_role_is_blocked(self):
        self._assert_status(
            {"oidc-admin-role": "admin"},
            BlockedStatus(TOGETHER_ADMIN_MSG),
        )

    def test_only_user_role_is_blocked(self):
        self._assert_status(
            {"oidc-user-role": "user"},
            BlockedStatus(TOGETHER_USER_MSG),
        )

    def test_both_roles_is_active(self):
        self._assert_status(
            {"oidc-admin-role": "admin", "oidc-user-role": "user"},
            ActiveStatus(),
        )

    def test_collect_unit_status_alone_sufficient(self):
        """Since parse is in __init__, collect_unit_status alone derives correct status."""
        ctx = Context(OpenshellGatewayK8sCharm)
        state = _state(**{"oidc-admin-role": "admin", "oidc-user-role": "user"})
        out = ctx.run(ctx.on.collect_unit_status(), state)
        assert out.unit_status == ActiveStatus()

    def test_both_roles_cleared_blocker(self):
        """Setting both roles after a blocked state clears the RBAC blocker."""
        ctx = Context(OpenshellGatewayK8sCharm)
        # First: neither role → blocked
        blocked_state = _state()
        out = ctx.run(ctx.on.collect_unit_status(), blocked_state)
        assert isinstance(out.unit_status, BlockedStatus)

        # Then: both roles → active (new dispatch, new state)
        active_state = _state(**{"oidc-admin-role": "admin", "oidc-user-role": "user"})
        out2 = ctx.run(ctx.on.collect_unit_status(), active_state)
        assert out2.unit_status == ActiveStatus()
