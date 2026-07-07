# Architecture Decision Records (ADRs)

This directory records significant architecture decisions for the openshell
charms, one decision per file, using a lightweight
[MADR](https://adr.github.io/madr/)-style format.

## Conventions

- Files are named `NNNN-short-title.md` with a zero-padded, monotonically
  increasing number.
- **Status** is one of: `Proposed`, `Accepted`, `Superseded by NNNN`,
  `Deprecated`.
- ADRs are immutable once `Accepted`; to change a decision, add a new ADR that
  supersedes the old one rather than editing history.
- Each ADR links back to the originating feature spec under `.gummi/state/`.

Use [`0000-template.md`](0000-template.md) as the starting point.

## Index

| ADR | Title | Status | Origin |
|-----|-------|--------|--------|
| [0001](0001-rbac-required-by-default.md) | RBAC required by default; omit unsafe options | Accepted | FD-002 |
| [0002](0002-pydantic-v2-config-model.md) | Pydantic v2 model for config validation and rendering | Accepted | FD-002 |
| [0003](0003-status-via-collect-unit-status.md) | Surface charm status via `collect-unit-status` | Accepted | FD-002 |
| [0004](0004-per-feature-interface-declaration.md) | Declare relation/action surface per-feature | Accepted | FD-002 |
| [0005](0005-fd002-config-only-env-rendering-scope.md) | FD-002 renders config-only, env-only subset | Proposed | FD-002 |
