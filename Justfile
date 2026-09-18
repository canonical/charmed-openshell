set shell := ["bash", "-euo", "pipefail", "-c"]

build-charm:
    cd charms/openshell-gateway-k8s && charmcraft pack

test-charm: build-charm
    cd charms/openshell-gateway-k8s && tox

integration-test-charm *args:
    cd charms/openshell-gateway-k8s && tox -e integration -- {{args}}

all: test-charm
