# Agent Instructions for charmed-openshell

## Project Overview

This repository is the Canonical-native Juju packaging for the NVIDIA OpenShell gateway on Kubernetes. It produces the `openshell-gateway-k8s` charm, the companion `openshell-gateway` rock, and supporting documentation/Terraform modules for deploying OpenShell in a production-grade, operator-native way.

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
| `charms/openshell-gateway-k8s/` | Sidecar Kubernetes charm (ops framework) that operates the rock |
| `rocks/openshell-gateway/` | Pebble-based OCI image bundling `openshell-gateway` and `openshell-driver-lxd` |
| `docs/adrs/` | Architecture Decision Records (MADR-style) |
| `Justfile` | High-level build/test recipes |
| `concierge.yaml` | Local integration-test environment setup (Juju + K8s) |
| `.github/workflows/` | CI definitions for charm lint/unit/static/integration and rock builds |

## Key Files Reference

| File | Purpose |
|------|---------|
| `charms/openshell-gateway-k8s/src/charm.py` | Main charm object, holistic `_reconcile()` implementation |
| `charms/openshell-gateway-k8s/src/config_model.py` | Pydantic v2 config model and TOML/env rendering (no ops imports) |
| `charms/openshell-gateway-k8s/src/ingress.py` | Traefik route / ingress helpers |
| `charms/openshell-gateway-k8s/charmcraft.yaml` | Charm metadata, relations, resources, and build config |
| `charms/openshell-gateway-k8s/pyproject.toml` | Python tooling configuration (pytest, ruff, pyright, coverage) |
| `charms/openshell-gateway-k8s/tox.ini` | Local test environments |
| `rocks/openshell-gateway/rockcraft.yaml` | Rock build definition |

## Development Setup

The project assumes an Ubuntu environment with Python 3.12, `tox`, `just`, and (for integration tests) `concierge`.

Typical workflows:

```bash
# Build the rock
just build-rock

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

The charm follows the **holistic reconcile** pattern (ADR-0006):

- A single idempotent `_reconcile()` method handles all events.
- It re-derives desired state from scratch on every hook and converges the workload.
- Do **not** set status inside `_reconcile()`; status is declared separately in `collect-unit-status` handlers.
- `collect-unit-status` helpers must re-read live model state rather than relying on in-memory fields set by reconcile (ADR-0011).

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

### Rock Smoke Tests

Smoke tests for the rock are in `rocks/openshell-gateway/tests/smoke.sh` and run automatically in CI:

```bash
just test-rock
```

## Vendored Library Patches

Libraries in `lib/` are vendored via `charmcraft fetch-libs`. When a vendored library crashes on a transient Juju condition that the charm itself already handles, it is acceptable to patch the vendored copy locally and cover the patch with a unit test.

Known patch:

- `lib/charms/data_platform_libs/v0/data_interfaces.py`: `_register_secrets_to_relation` catches `SecretNotFoundError` / `ModelError` when a provider publishes a secret URI before the grant has propagated (e.g. during `remove-relation` / `integrate` churn). Without this patch the library's `database-relation-changed` handler crashes before the charm's own `_database_uri()` resilience can run.

Document any such patch in the commit message and add a regression test that fails if the patch is removed.

## Charm packaging compatibility

Charmcraft installs Python dependencies directly under `venv/`, while
`charmlibs-rollingops` 1.1.x looks for its asynchronous worker under the
conventional `venv/lib/pythonX.Y/site-packages/` path. The charm part applies
`patches/rollingops-flat-venv.patch` during packing so the worker supports both
layouts. Keep it until rollingops supports Charmcraft's flattened virtualenv.

## Documentation

- Feature specifications go in `docs/spec/`.
- Architecture decisions are recorded as ADRs in `docs/adrs/` using the MADR-style template (`docs/adrs/0000-template.md`).
- ADR file names use zero-padded, monotonically increasing numbers: `NNNN-short-title.md`.
- Once an ADR is `Accepted`, it is immutable; supersede it with a new ADR rather than editing history.

When writing prose documentation:

- Use active voice.
- Be objective: avoid "simply", "easily", and "just".
- Use sentence case for headings.
- Spell out abbreviations and avoid Latin (for example, use "for example" not "e.g.").

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
2. Update the spec or ADRs if the change affects architecture or user-facing behaviour.
3. Run `tox -e lint`, `tox -e unit`, and `tox -e static` in `charms/openshell-gateway-k8s`.
4. Run `tox -e fmt` if formatting is needed.
5. For rock changes, ensure `just test-rock` still passes.
6. Verify the CI workflows in `.github/workflows/` still apply to the files you changed.
