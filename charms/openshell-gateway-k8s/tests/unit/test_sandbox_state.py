"""Unit tests for the integration suite's sandbox-state parsing.

The helper is pure and its inputs come from a CLI whose output format has
already changed once, so it is worth testing without a cluster.
"""

from __future__ import annotations

import json

from tests.integration.sandbox_state import sandbox_is_running


def _listing(name: str, **fields) -> str:
    return json.dumps([{"name": name, **fields}])


def test_phase_ready_is_running():
    # openshell 0.0.116 reports phase, not status.
    assert sandbox_is_running("sb", _listing("sb", phase="Ready"))


def test_phase_pending_is_not_running():
    assert not sandbox_is_running("sb", _listing("sb", phase="Pending"))


def test_legacy_status_running_still_matches():
    assert sandbox_is_running("sb", _listing("sb", status="running"))


def test_absent_sandbox_is_not_running():
    assert not sandbox_is_running("sb", _listing("other", phase="Ready"))


def test_plain_text_fallback():
    assert sandbox_is_running("sb", "NAME  PHASE\nsb    Ready\n")
    assert not sandbox_is_running("sb", "NAME  PHASE\nsb    Pending\n")
