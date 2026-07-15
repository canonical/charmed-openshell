set shell := ["bash", "-euo", "pipefail", "-c"]

# Build the rock
build-rock:
    cd rocks/openshell-gateway && rockcraft pack --verbose

# Test the rock (always build first)
test-rock: build-rock
    bash rocks/openshell-gateway/tests/smoke.sh

# Build the charm
build-charm:
    cd charms/openshell-gateway-k8s && charmcraft pack

# Test the charm (lint + unit by default)
test-charm: build-charm
    cd charms/openshell-gateway-k8s && tox

# Integration tests for the charm; accepts passthrough args
integration-test-charm *args: build-charm
    cd charms/openshell-gateway-k8s && tox -e integration -- {{args}}

# Run both test targets (does not include integration tests)
all: test-rock test-charm
