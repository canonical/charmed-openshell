# 0011. Readiness gaps recomputed per dispatch; `StoredState` for sentinels only

- **Status:** Accepted
- **Date:** 2026-07-13
- **Deciders:** architect, implementer

## Context

Juju dispatches each hook in a fresh Python process.  A charm that writes
readiness state to a plain instance variable in one hook (`_reconcile`) cannot
read it back in a later hook (`collect-unit-status`) — the field is gone.
`ops.StoredState` persists across dispatches, but overusing it to cache derived
state introduces stale-data risks when model/relation state changes between
hooks without a StoredState update.

Two pieces of state genuinely need cross-dispatch persistence: the last-
registered TLS certificate SANs and the last-registered OAuth redirect URI,
used to decide when to re-register with the upstream operators.

## Decision

**Readiness gaps are never stored.**  The `_readiness_gaps() -> list[_Gap]`
helper re-reads live model and relation state on every call.  Both `_reconcile`
and `_on_collect_unit_status` call this helper independently in their own
dispatches, so each hook always reflects current state.

**`StoredState` is used only for re-registration sentinels:**
- `last_cert_sans: list[str]` — the sorted SAN list from the last cert CSR
  sent to `TLSCertificatesRequiresV4`.
- `last_redirect_uri: str` — the redirect URI last sent to `OAuthRequirer`.

Both are initialised with `set_default` in `__init__` before any reconcile
path reads them, preventing `AttributeError` on a fresh unit or after a charm
upgrade.

## Alternatives considered

- **Recompute readiness per dispatch (chosen):** Always accurate; no risk of
  the unit reporting Active while a relation is actually broken.  Acceptable
  cost — the helpers only read relation databags and container state, which are
  fast.

- **Store readiness gaps in `StoredState` (rejected):** Simpler `collect-unit-
  status` handler (just reads stored gaps).  Rejected because `StoredState`
  is only written by `_reconcile`; if a relation breaks between a `_reconcile`
  dispatch and a `collect-unit-status` dispatch, the stored gaps are stale and
  the unit would permanently report Active.  This was an explicit bug found
  during review.

- **Store readiness in a plain instance variable (rejected):** Would silently
  always show Active because each hook dispatch runs in a fresh process.  This
  was the original draft design; rejected before implementation.

## Consequences

- `collect-unit-status` always reflects live relation/container state, even if
  no `_reconcile` dispatch has fired recently.
- The `update-status` hook acts as a safety net: even if a transient event was
  missed, the next `update-status` fires `_reconcile`, which re-evaluates
  readiness and converges the workload.
- `StoredState` has a minimal, well-defined surface (two sentinel fields) that
  is easy to reason about and test.
- Any future cross-dispatch state that is not merely a re-registration sentinel
  should default to recomputation rather than storage.
