"""Smoke tests for charm metadata declared in ``charmcraft.yaml``."""

from __future__ import annotations

import yaml


def test_no_workload_container():
    with open("charmcraft.yaml") as f:
        metadata = yaml.safe_load(f)

    assert "containers" not in metadata
    assert "resources" not in metadata


def test_config_options_declared():
    with open("charmcraft.yaml") as f:
        metadata = yaml.safe_load(f)

    options = metadata["config"]["options"]
    assert "lxd-endpoints" in options
    assert "lxd-credentials" in options
    assert "lxd-server-fingerprint" in options
    assert "default-projects" in options
    assert "trust-name-prefix" in options
    assert options["trust-name-prefix"]["default"] == "juju-relation"


def test_relations_declared():
    with open("charmcraft.yaml") as f:
        metadata = yaml.safe_load(f)

    assert metadata["provides"]["https"]["interface"] == "lxd-https"
    assert metadata["peers"]["integrator-peers"]["interface"] == "integrator_peers"


def test_actions_declared():
    with open("charmcraft.yaml") as f:
        metadata = yaml.safe_load(f)

    actions = metadata["actions"]
    assert "get-connection-info" in actions
    assert "list-trusted-clients" in actions
