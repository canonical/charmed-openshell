"""Subprocess command execution helpers for integration tests."""

from __future__ import annotations

import subprocess
from typing import Any


def run_cmd(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run a subprocess, returning a CompletedProcess with captured text output."""
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        check=False,
        **kwargs,
    )
