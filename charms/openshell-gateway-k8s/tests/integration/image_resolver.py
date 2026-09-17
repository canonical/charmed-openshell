"""Helper function to resolve the gateway OCI image."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_GATEWAY_IMAGE = "ghcr.io/canonical/openshell-gateway:latest"
_CHARM_DIR = Path(__file__).resolve().parent.parent.parent


def resolve_gateway_image(
    charmcraft_path: Path | str | None = None,
) -> str:
    """Resolve the gateway OCI image ref.

    Precedence:
      1. ``GATEWAY_IMAGE`` environment variable.
      2. Upstream source from ``charmcraft.yaml`` (resources.gateway-image.upstream-source).
      3. Fallback default: ``ghcr.io/canonical/openshell-gateway:latest``.
    """
    image = os.environ.get("GATEWAY_IMAGE")
    if image:
        return image.strip()

    path = Path(charmcraft_path) if charmcraft_path is not None else _CHARM_DIR / "charmcraft.yaml"
    if path.is_file():
        try:
            with open(path, encoding="utf-8") as f:
                data: Any = yaml.safe_load(f)
            if isinstance(data, dict):
                upstream = (
                    data.get("resources", {}).get("gateway-image", {}).get("upstream-source")
                )
                if isinstance(upstream, str) and upstream.strip():
                    return upstream.strip()
        except Exception:
            pass

    return DEFAULT_GATEWAY_IMAGE
