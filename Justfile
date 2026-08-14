set shell := ["bash", "-euo", "pipefail", "-c"]

ROCK_REGISTRY := env_var_or_default("ROCK_REGISTRY", "localhost:5000")
ROCK_NAME := "openshell-gateway"

build-rock:
    cd rocks/openshell-gateway && rockcraft pack --verbose

push-rock: build-rock
    skopeo copy "oci-archive:$(ls -t rocks/openshell-gateway/*.rock | head -n1)" "docker://{{ROCK_REGISTRY}}/{{ROCK_NAME}}:latest" --dest-tls-verify=false

test-rock: build-rock
    bash rocks/openshell-gateway/tests/smoke.sh

build-charm:
    cd charms/openshell-gateway-k8s && charmcraft pack

build-integrator-charm:
    cd charms/lxd-integrator-k8s && charmcraft pack

test-charm: build-charm
    cd charms/openshell-gateway-k8s && tox

test-integrator-charm:
    cd charms/lxd-integrator-k8s && tox

integration-test-charm *args:
    cd charms/openshell-gateway-k8s && tox -e integration -- {{args}}

all: test-rock test-charm
