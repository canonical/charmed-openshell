"""Charm artifact resolution and caching helpers."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from .constants import CHARM_DIR

logger = logging.getLogger(__name__)


def ensure_juju_readable(path: Path) -> Path:
    """Copy a charm file to a location the confined ``juju`` snap can read.

    The snap cannot access paths under ``/work`` in some CI environments, so
    charm files built there are copied under the user's home directory.
    """
    path = path.resolve()
    if str(path).startswith(str(Path.home())):
        return path

    cache_dir = Path.home() / ".cache" / "openshell-gateway-integration"
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = cache_dir / path.name
    shutil.copy2(path, dest)
    return dest


def resolve_charm_file() -> str:
    """Resolve a .charm artifact that the confined ``juju`` snap can read."""
    env_path = os.environ.get("CHARM_FILE")
    source = Path(env_path) if env_path else None

    if source is None:
        if shutil.which("charmcraft") is None:
            pytest.skip("CHARM_FILE not set and 'charmcraft' binary not found")
        result = subprocess.run(
            ["charmcraft", "pack"],
            cwd=str(CHARM_DIR),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip(f"charmcraft pack failed:\n{result.stderr}")
        charms = sorted(CHARM_DIR.glob("*.charm"))
        if not charms:
            pytest.skip("charmcraft pack succeeded but no .charm file found")
        source = charms[-1]

    accessible = ensure_juju_readable(source)
    return str(accessible)
