# 0007. All-or-nothing mandatory relation gating with workload teardown

- **Status:** Accepted
- **Date:** 2026-07-13
- **Deciders:** architect, implementer

## Context

The gateway requires three integrations to operate: a PostgreSQL database, a
TLS certificate, and an OIDC issuer (Hydra oauth).  A decision was needed on
what the charm should do when one or more of these integrations is absent,
broken, or has not yet delivered data — and whether to support a degraded
partial-operation mode.

Additionally, RBAC roles (`oidc-admin-role`, `oidc-user-role`) must both be set
before the gateway can enforce access control.  An unset role would silently
authorize every valid token as admin.

## Decision

The workload is started only when **all** of the following are satisfied:
both RBAC roles set, database relation joined with credentials available,
certificates relation joined with a certificate assigned, and oauth relation
joined with issuer URL available.  When any mandatory piece is absent or
broken, the **same reconcile path** stops and disables the Pebble service
(see ADR-0009 for the teardown mechanism).  There is no partial-operation mode.

## Alternatives considered

- **All-or-nothing gate (chosen):** Cleanest security posture — the gateway
  never runs in an under-configured state.  Self-healing: relation-broken and
  relation-joined both funnel to the same reconcile, so recovery is automatic.
  Tradeoff: operators must satisfy all prerequisites before the unit becomes
  Active; there is no intermediate "degraded but serving" state.

- **Partial operation (rejected):** Allow the workload to start with, for
  example, a self-signed certificate or no database.  Rejected because any
  partially-configured state would silently weaken the security guarantees
  (unauthenticated access, plain-text DB connections, or untrusted TLS) that
  are core to the gateway's design contract.

## Consequences

- A freshly deployed unit stays Blocked/Waiting until all three relations are
  integrated and both RBAC roles are configured.  Operators must satisfy all
  prerequisites before the unit becomes Active.
- Removing any mandatory relation immediately stops the workload and returns
  the unit to Blocked.  Re-adding the relation restores Active automatically.
- The `collect-unit-status` handler reports a distinct Blocked or Waiting
  message per unmet prerequisite, giving operators actionable feedback.
- No dedicated `relation-broken` handler is needed; teardown is a natural
  branch of the shared reconcile path.
