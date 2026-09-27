# Agent Instructions for charmed-openshell

## Project Overview

This repository is the Canonical-native Juju packaging for the NVIDIA OpenShell gateway on Kubernetes. It produces the `openshell-gateway-k8s` charm and supporting documentation/Terraform modules for deploying OpenShell in a production-grade, operator-native way. The gateway workload runs using the companion `openshell-gateway` rock, which is built and maintained externally.

The gateway provides the OpenShell control plane — API server, persistence, authentication/authorization, and sandbox orchestration — and is designed to integrate with PostgreSQL, Charmed Hydra (OIDC), Traefik ingress, and the Canonical Observability Stack.

## Maintaining This File

`AGENTS.md` is a living document. As you work in this repository and discover new conventions, patterns, tooling, or non-obvious project rules, update this file so future agents benefit from what you learned. Add sections or refine existing ones whenever:

- A new recurring pattern or architectural rule emerges.
- Tooling, build commands, or CI workflows change.
- You find a gotcha, implicit assumption, or undocumented dependency.
- A convention is clarified or contradicted by existing code.

Keep the guidance concise, accurate, and actionable.

## Repository Layout

| Path | Purpose |
|------|---------|
| `charms/openshell-gateway-k8s/` | Sidecar Kubernetes charm (ops framework) that operates the workload |
| `docs/spec/` | Feature specifications |
| `Justfile` | High-level build/test recipes |
| `concierge.yaml` | Local integration-test environment setup (Juju + K8s) |
| `.github/workflows/` | CI definitions for charm lint/unit/static/integration |

## Key Files Reference

| File | Purpose |
|------|---------|
| `charms/openshell-gateway-k8s/src/charm.py` | Main charm object, holistic `_reconcile()` implementation |
| `charms/openshell-gateway-k8s/src/config_model.py` | Pydantic v2 config model and TOML/env rendering (no ops imports) |
| `charms/openshell-gateway-k8s/src/ingress.py` | Traefik route / ingress helpers |
| `charms/openshell-gateway-k8s/src/vault_store.py` | Optional Vault-backed store for the JWT signing keypair |
| `charms/openshell-gateway-k8s/charmcraft.yaml` | Charm metadata, relations, resources, and build config |
| `charms/openshell-gateway-k8s/pyproject.toml` | Python tooling configuration (pytest, ruff, pyright, coverage) |
| `charms/openshell-gateway-k8s/tox.ini` | Local test environments |

## Development Setup

The project assumes an Ubuntu environment with Python 3.12, `tox`, `just`, and (for integration tests) `concierge`.

Typical workflows:

```bash
# Build the charm
just build-charm

# Run lint, unit, and static checks inside the charm directory
cd charms/openshell-gateway-k8s
tox -e lint
tox -e unit
tox -e static

# Fix formatting automatically
tox -e fmt

# Run integration tests (requires a bootstrapped Juju/K8s environment)
just integration-test-charm
```

For local integration testing, use `concierge` with the provided `concierge.yaml`:

```bash
sudo snap install --classic concierge
sudo concierge prepare -c concierge.yaml
```

## Coding Standards

### Language and Tooling

- Python 3.12.
- Format and lint with Ruff (`tox -e lint` / `tox -e fmt`).
- Line length is 99 characters.
- Static type checking with Pyright (`tox -e static`).
- Full type hints are required; prefer modern `x: int | None` over `Optional[int]`.
- Provide an explicit return type except for `__init__` and test functions.

### Import Style

Import modules, not objects (with `typing` and `collections.abc` as exceptions):

```python
# Good
import ops
from typing import Any

# Avoid
from ops import CharmBase, ActiveStatus
```

### Code Organisation

- Keep the configuration model in `config_model.py` free of `ops` imports so it can be tested without Juju.
- Put ingress/route logic in `ingress.py`.
- Keep the main charm file focused on lifecycle and reconciliation.

## Architecture Patterns

### Holistic Reconcile

The charm follows the **holistic reconcile** pattern:

- A single idempotent `_reconcile()` method handles all events.
- It re-derives desired state from scratch on every hook and converges the workload.
- Do **not** set status inside `_reconcile()`; status is declared separately in `collect-unit-status` handlers.
- `collect-unit-status` helpers must re-read live model state rather than relying on in-memory fields set by reconcile.

### Security-First Defaults

The charm enforces secure defaults by design:

- TLS is always enabled; there is no configuration option to disable it.
- Unauthenticated access is not expressible.
- Both `oidc-admin-role` and `oidc-user-role` must be configured before the charm becomes active.
- Bind address is fixed to `0.0.0.0` because network access is governed at the Kubernetes layer.

### Configuration Model

- Use Pydantic v2 for config validation.
- Normalise Juju empty-string values to `None` for optional fields.
- Render TOML and Pebble environment files from the validated model.

## Testing

### Unit Tests

Unit tests live in `charms/openshell-gateway-k8s/tests/unit/` and use `pytest` plus `ops[testing]` (Scenario/ Harness as appropriate). The config model is tested with plain pytest and zero Juju dependencies.

Run unit tests and coverage:

```bash
cd charms/openshell-gateway-k8s
tox -e unit
```

### Integration Tests

Integration tests live in `charms/openshell-gateway-k8s/tests/integration/` and use `jubilant`. They require a bootstrapped Juju controller with Kubernetes and the OpenShell client (`openshell` snap).

```bash
just integration-test-charm
```

## Vendored Library Patches

Libraries in `lib/` are vendored via `charmcraft fetch-libs`. When a vendored library crashes on a transient Juju condition that the charm itself already handles, it is acceptable to patch the vendored copy locally and cover the patch with a unit test.

Known patch:

- `lib/charms/data_platform_libs/v0/data_interfaces.py`: `_register_secrets_to_relation` catches `SecretNotFoundError` / `ModelError` when a provider publishes a secret URI before the grant has propagated (e.g. during `remove-relation` / `integrate` churn). Without this patch the library's `database-relation-changed` handler crashes before the charm's own `_database_uri()` resilience can run.

Document any such patch in the commit message and add a regression test that fails if the patch is removed.

`lib/charms/vault_k8s/v0/vault_kv.py` imports `interface_tester.schema_base` at module
scope, so `pytest-interface-tester` is a runtime dependency of the charm despite the
package's name. It is declared in the library's own `PYDEPS` and listed in
`requirements.txt` for that reason. `lib/charms/prometheus_k8s/v0/prometheus_scrape.py`
needs `cosl` the same way.

## Charm packaging compatibility

Charmcraft installs Python dependencies directly under `venv/`, while
`charmlibs-rollingops` 1.1.x looks for its asynchronous worker under the
conventional `venv/lib/pythonX.Y/site-packages/` path. The charm part applies
`patches/rollingops-flat-venv.patch` during packing so the worker supports both
layouts. Keep it until rollingops supports Charmcraft's flattened virtualenv.

## Documentation

- Feature specifications go in `docs/spec/`.
- There is no ADR convention in this repository. The `docs/adrs/` directory was
  removed in `48bb753` and the toctree entry in `37f3a83`; earlier ADR numbers
  survive only as references in code comments. Record a decision in the commit
  message that makes it and, when it is user-facing, in `docs/spec/` or the
  README — do not reintroduce `docs/adrs/` without agreeing the convention first.

When writing prose documentation:

- Use active voice.
- Be objective: avoid "simply", "easily", and "just".
- Use sentence case for headings.
- Spell out abbreviations and avoid Latin (for example, use "for example" not "e.g.").

## Gotchas Worth Knowing

### The LXD project is not charm config

Which LXD project sandboxes are created in is the LXD administrator's decision and
lives on `lxd-integrator-k8s` (`project`), arriving over the `lxd-https` relation as a
`project` key. The gateway charm renders it as the driver's `--project`. Do not add a
charm config option for it: `lxd-projects` existed once, only ever restricted the
integrator's trust entry, and was removed for this reason.

### The driver refuses to start without sandbox TLS material

`openshell-driver-lxd` validates at startup that sandboxes are either given
`--guest-tls-ca/-cert/-key` or that `--allow-plaintext-gateway` is set. This charm
never allows plaintext, so the three flags are always rendered. The client identity is
a dedicated self-signed keypair in a peer secret — never the LXD client identity,
which is an administrative credential for the LXD API.

### Never run `update-ca-certificates` in the workload container

The gateway rock ships the public roots as a prebuilt bundle but has no
`/etc/ca-certificates.conf` before `openshell-driver-lxd` commit `301529a`, which the
gateway rock is built from. Without that file `update-ca-certificates` rebuilds the
bundle from an empty list and replaces all 121 public roots with whatever the charm put
in `/usr/local/share/ca-certificates`; with it, the rebuild keeps the public roots but
still drops the charm's own CA, which lives outside that directory. Either way the
driver then cannot pull a sandbox or supervisor image from any registry, and the
failure surfaces much later as an opaque x509 error from skopeo. The charm appends its
CA to the image's bundle instead, keeping an untouched copy at
`/etc/openshell/tls/system-ca.crt` so the rewrite is idempotent.

### The dial-back endpoint must be reachable from the sandbox network

`--gateway-endpoint` becomes each sandbox's `OPENSHELL_ENDPOINT`. Sandboxes run on
LXD, not in Kubernetes, so a ClusterIP is useless to them. The charm derives the value
from `external-hostname` plus the ingress relation; that hostname has to be an address
the sandbox network can route to, such as a load-balancer address. `get-gateway-status`
reports the computed value.

### The `openshell` CLI must match the gateway build

The integration suite drives the `openshell` snap against the gateway in the
rock. A newer CLI fails to decode the gateway's responses outright — `latest/edge`
(0.0.117-dev) against a v0.0.116 gateway gives `failed to decode Protobuf message:
NetworkEndpoint.tls ... invalid wire type` from `sandbox list`, and a misleading
"sandbox not found" from `sandbox create`, on a sandbox that was created fine.
Track `latest/stable` unless the rock is pinned to something newer.

### `sandbox-image` is an OCI reference, not an LXD alias

The driver resolves `--default-image` as a registry reference and imports it on first
use. The Kubernetes node needs to reach whatever registry it names. The option was
called `lxd-sandbox-image` until it was renamed before first publish: the `lxd-`
prefix read as though the value were an LXD image alias, which is the mistake the
default value exists to prevent.

### `[openshell.drivers.kubernetes]` is required even with the LXD driver

`render_config_toml` always emits it, and `_read_pod_namespace` reads the downward-API
namespace file to fill it, although `OPENSHELL_DRIVERS` is `lxd`. That is not left-over
configuration: issuing sandbox JWTs in-cluster bootstraps from a Kubernetes
ServiceAccount, and without the section the binary exits with "K8s ServiceAccount
bootstrap requires [openshell.drivers.kubernetes] when sandbox JWT issuing is enabled
in-cluster".

### A slow Pebble raises a bare `TimeoutError`

ops turns a refused Pebble connection into `ops.pebble.ConnectionError` but lets a
read timeout through as the socket's `TimeoutError`, from `can_connect()` too. Use
`_can_connect()` and `_PEBBLE_UNREACHABLE` in `charm.py`: `_reconcile()` and the
rolling-restart callback catch it and let the next event converge. Do not reintroduce
a hook failure for it: the integration models run with `automatically-retry-hooks`
off, so one slow call leaves the unit in error for good.

### The sandbox client certificate gates connections; the JWT identifies sandboxes

Every sandbox gets the same client certificate, and the gateway verifies it —
`_render_config_toml` sets `client_ca_path` to a CA the charm mints for this one
purpose. Two things follow that are easy to get wrong:

- **It is not identity.** One certificate is shared by every sandbox, so it proves
  "a sandbox of this deployment", not *which* sandbox. What identifies a sandbox is
  its own gateway-minted JWT, pushed into the instance root-only before start.
- **It never locks out CLI users.** The gateway derives its policy:
  `require_client_auth: has_client_ca && !has_oidc` (upstream `cli.rs`). This charm
  always configures OIDC, so certificates are validated when presented and never
  demanded. Users come through Traefik in TLS passthrough and present none.

Two separate CAs, deliberately:

| File | Who trusts it | For what |
|---|---|---|
| `/etc/openshell/sandbox-tls/ca.crt` | the sandbox | verifying the gateway's certificate |
| `/etc/openshell/tls/sandbox-client-ca.crt` | the gateway | verifying the sandbox's certificate |

The client CA is minted by the charm rather than requested over the `certificates`
relation, because `TLSCertificatesRequiresV4` keeps **one private key per relation**:
a second request there would hand every sandbox the gateway's own server private key.
Its private key stays in the peer secret and never reaches the workload container.

A secret from before this existed holds a self-signed leaf with no `ca-certificate`
key; the leader re-issues it, and until it does no `client_ca_path` is rendered.

`rotate-sandbox-client-identity` replaces both. Rotating the leaf alone would be
pointless — the gateway trusts the issuer, so a leaked leaf stays valid until its CA
goes with it — and rotating both means running sandboxes cannot reconnect after the
workload restarts. The action says so in its results; there is no overlap window.

## Pull Request Guidelines

Follow conventional commit style in PR titles:

- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation changes
- `refactor:` — code refactoring
- `test:` — test additions or updates
- `chore:` — maintenance tasks
- `ci:` — CI/CD changes

### Before Submitting

1. Add or update unit tests for any changed behaviour.
2. Update `docs/spec/` and the README if the change affects architecture or user-facing behaviour.
3. Run `tox -e lint`, `tox -e unit`, and `tox -e static` in `charms/openshell-gateway-k8s`.
4. Run `tox -e fmt` if formatting is needed.
5. Verify the CI workflows in `.github/workflows/` still apply to the files you changed.
