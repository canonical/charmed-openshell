"""Charm artifact resolution and caching helpers."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from .command import run_cmd
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


def clone_integrator() -> Path:
    """Shallow-clone the integrator repository into the cache directory."""
    repo = os.environ.get(
        "INTEGRATOR_CHARM_REPO", "https://github.com/canonical/lxd-integrator-k8s.git"
    )
    branch = os.environ.get("INTEGRATOR_CHARM_REF", "main")
    target = Path.home() / ".cache" / "openshell-gateway-integration" / "lxd-integrator-k8s"

    if (target / "charmcraft.yaml").is_file():
        logger.info("Reusing integrator checkout at %s", target)
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(target, ignore_errors=True)
    logger.info("Cloning %s (%s) into %s", repo, branch, target)
    result = run_cmd("git", "clone", "--depth", "1", "--branch", branch, repo, str(target))
    if result.returncode != 0:
        pytest.fail(
            f"Failed to clone the lxd-integrator-k8s charm from {repo} ({branch}):\n"
            f"{result.stderr}\n"
            "Set INTEGRATOR_CHARM_FILE to a prebuilt .charm or INTEGRATOR_CHARM_DIR to a "
            "local checkout if this host has no access to the repository."
        )
    return target


def resolve_integrator_charm_file() -> str:
    """Resolve a ``lxd-integrator-k8s`` .charm artifact the ``juju`` snap can read."""
    env_path = os.environ.get("INTEGRATOR_CHARM_FILE")
    if env_path:
        source = Path(env_path)
        if not source.is_file():
            pytest.fail(f"INTEGRATOR_CHARM_FILE={env_path} does not exist")
        return str(ensure_juju_readable(source))

    if shutil.which("charmcraft") is None:
        pytest.fail(
            "Cannot obtain the lxd-integrator-k8s charm: 'charmcraft' is not on PATH. "
            "Install charmcraft, or set INTEGRATOR_CHARM_FILE to a prebuilt .charm."
        )

    env_dir = os.environ.get("INTEGRATOR_CHARM_DIR")
    if env_dir:
        integrator_dir = Path(env_dir)
        if not (integrator_dir / "charmcraft.yaml").is_file():
            pytest.fail(f"INTEGRATOR_CHARM_DIR={env_dir} is not a charm source directory")
    else:
        integrator_dir = clone_integrator()

    result = run_cmd("charmcraft", "pack", cwd=str(integrator_dir))
    if result.returncode != 0:
        pytest.fail(
            f"charmcraft pack failed for lxd-integrator-k8s in {integrator_dir}:\n"
            f"{result.stdout}\n{result.stderr}"
        )
    charms = sorted(integrator_dir.glob("*.charm"))
    if not charms:
        pytest.fail(
            f"charmcraft pack reported success in {integrator_dir} but produced no .charm file"
        )

    return str(ensure_juju_readable(charms[-1]))
