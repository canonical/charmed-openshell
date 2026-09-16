"""Unit tests for the gateway OCI image resolver."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.integration.image_resolver import (
    DEFAULT_GATEWAY_IMAGE,
    resolve_gateway_image,
)


def test_resolve_gateway_image_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Env var GATEWAY_IMAGE takes precedence over charmcraft.yaml."""
    monkeypatch.setenv("GATEWAY_IMAGE", "custom-registry.example.com/openshell:v2")
    assert resolve_gateway_image() == "custom-registry.example.com/openshell:v2"


def test_resolve_gateway_image_from_charmcraft(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset GATEWAY_IMAGE resolves upstream-source from charmcraft.yaml."""
    monkeypatch.delenv("GATEWAY_IMAGE", raising=False)
    assert resolve_gateway_image() == "ghcr.io/canonical/openshell-gateway:latest"


def test_resolve_gateway_image_custom_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Unset GATEWAY_IMAGE with custom charmcraft_path resolves correctly."""
    monkeypatch.delenv("GATEWAY_IMAGE", raising=False)
    custom_yaml = tmp_path / "charmcraft.yaml"
    custom_yaml.write_text(
        "resources:\n  gateway-image:\n    upstream-source: my-repo/custom-image:1.0\n",
        encoding="utf-8",
    )
    assert resolve_gateway_image(charmcraft_path=custom_yaml) == "my-repo/custom-image:1.0"


def test_resolve_gateway_image_fallback_missing_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Missing charmcraft file returns DEFAULT_GATEWAY_IMAGE."""
    monkeypatch.delenv("GATEWAY_IMAGE", raising=False)
    non_existent = tmp_path / "non_existent.yaml"
    assert resolve_gateway_image(charmcraft_path=non_existent) == DEFAULT_GATEWAY_IMAGE


def test_resolve_gateway_image_fallback_invalid_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Invalid charmcraft file content falls back to DEFAULT_GATEWAY_IMAGE."""
    monkeypatch.delenv("GATEWAY_IMAGE", raising=False)
    invalid_yaml = tmp_path / "charmcraft.yaml"
    invalid_yaml.write_text("resources:\n  some-other-resource: {}\n", encoding="utf-8")
    assert resolve_gateway_image(charmcraft_path=invalid_yaml) == DEFAULT_GATEWAY_IMAGE
