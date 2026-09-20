"""Parsing of ``openshell sandbox list`` output.

Deliberately free of ``jubilant`` and ``pytest`` imports so the pure parsing
can be unit-tested without a cluster, in the same spirit as ``lxd_host.py``.
The CLI's output format has already changed once — v0.0.116 reports ``phase``
where older builds reported ``status`` — which is exactly why this is worth
testing on its own.
"""

from __future__ import annotations

import json

# States ``openshell sandbox list`` reports for a sandbox that is up and
# usable. v0.0.116 spells it ``phase: "Ready"``; ``running`` is accepted too so
# a CLI that goes back to the older spelling still matches.
SANDBOX_READY_STATES = frozenset({"ready", "running"})


def sandbox_entry_is_ready(entry: dict) -> bool:
    """Return True when a ``sandbox list`` entry reports a usable sandbox."""
    for key in ("phase", "status", "state"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value.lower() in SANDBOX_READY_STATES
    return False


def sandbox_is_running(name: str, output: str) -> bool:
    """Return True when *output* indicates that the named sandbox is up.

    Prefer parsing the JSON list returned by ``openshell sandbox list``; fall
    back to plain-text matching if JSON parsing fails or the format differs.
    """

    def _text_fallback() -> bool:
        normalized = output.lower()
        return name.lower() in normalized and any(
            state in normalized for state in SANDBOX_READY_STATES
        )

    try:
        data = json.loads(output)
    except Exception:
        return _text_fallback()

    if isinstance(data, dict):
        entry = data.get(name)
        if isinstance(entry, dict):
            return sandbox_entry_is_ready(entry)
        return _text_fallback()

    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and entry.get("name") == name:
                return sandbox_entry_is_ready(entry)
        return False

    return _text_fallback()
