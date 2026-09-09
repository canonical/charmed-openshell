"""Shared test fixtures for the gateway charm unit tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _sync_rolling_ops():
    """Run rolling-ops callbacks synchronously in unit tests.

    The maintained ``charmlibs-rollingops`` library normally spawns a worker
    process to grant the lock and dispatch the callback. In Scenario-based
    unit tests that worker cannot run, so patch async lock requests to invoke
    the registered callback target directly. This keeps the charm's restart
    coordination logic testable without changing production behaviour.
    """

    def _request_async_lock(self, callback_id, kwargs=None, max_retry=None):
        callback = self._peer_backend.callback_targets[callback_id]
        callback(**(kwargs or {}))

    with patch(
        "charmlibs.rollingops.RollingOpsManager.request_async_lock",
        _request_async_lock,
    ):
        yield
