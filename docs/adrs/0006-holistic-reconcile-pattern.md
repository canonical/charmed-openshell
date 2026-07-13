# 0006. Holistic reconcile pattern over event-driven handlers

- **Status:** Accepted
- **Date:** 2026-07-13
- **Deciders:** architect, implementer

## Context

The gateway charm must react to events from three mandatory relations (database,
certificates, oauth), a peer relation, config changes, Pebble readiness, and
Juju secrets.  Two coherent control-flow strategies were evaluated for wiring
these events to workload management.

## Decision

Every hook — `*-relation-changed/-joined/-broken`, `config-changed`,
`<container>-pebble-ready`, `secret-changed`, `leader-elected`, and
`update-status` — is observed by a single idempotent `_reconcile()` method that
re-derives desired state from scratch on each call and converges the workload
to match.  Status is never set inside reconcile; it is declared separately in
`collect-unit-status` handlers that read live model state independently.

## Alternatives considered

- **Approach A — holistic reconcile + collect-unit-status (chosen):** Single
  entrypoint, order-independent and self-healing regardless of which hook fires
  first.  Follows current ops-charm ecosystem conventions.  Easier to reason
  about and test holistically.  Tradeoff: reconcile re-reads all relations and
  re-renders config on every event, which requires `replan()` to be a no-op
  when nothing has changed (Pebble satisfies this).

- **Approach B — per-event handlers with inline status:** Discrete handlers
  mutate state and set status as they fire.  Less redundant computation per
  hook.  Rejected because correctness depends on event ordering; easy to leave
  the unit in a stale status when events interleave; status logic is scattered
  and prone to last-writer-wins bugs; harder to test holistically.

## Consequences

- All convergence logic lives in one place; adding a new relation or config
  field only requires updating the data-gather step and the readiness check.
- Testing a scenario means setting up model state and calling `_reconcile()`
  once, regardless of which event would have triggered it in production.
- `replan()` must be cheap when the layer is unchanged — Pebble guarantees
  this, so the redundant-computation tradeoff is acceptable.
- `collect-unit-status` runs in a separate hook dispatch from `_reconcile`;
  status helpers must re-read live state rather than consuming in-memory fields
  set by reconcile (see ADR-0011).
