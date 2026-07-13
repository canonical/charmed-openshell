# 0008. Ed25519 JWT keypair minted once by leader into a peer secret

- **Status:** Accepted
- **Date:** 2026-07-13
- **Deciders:** architect, implementer

## Context

The gateway workload signs JWTs with an Ed25519 keypair.  In a multi-unit
deployment, all units must sign with the same key so that a token minted on one
unit validates on any other.  The keypair must be available before the workload
starts, must survive unit restarts, and must never appear in charm config or
relation data in plain text.

A `gateway_id` field is embedded in every minted JWT.  If this value differs
between units, token validation across units would silently fail.

The `rotate-jwt-signing-key` action is explicitly out of scope for this MVP
(deferred to FD-006).

## Decision

The leader unit generates the Ed25519 keypair **once** inside `_reconcile()`
when the peer secret is absent, serialises both keys as PEM (PKCS8 for the
private key, SubjectPublicKeyInfo for the public key), computes the `kid` as
the RFC 7638 JWK thumbprint of the OKP public key using SHA-256
(base64url-no-pad), and stores all three in an application-scoped Juju secret
labelled `gateway-jwt` on the `gateway-peers` peer relation.  The secret is
immediately granted to the peer relation so non-leader units can read it.  All
units (including the leader after minting) read the secret with
`get_content(refresh=True)` and write the key files to the container filesystem
under `JWT_DIR` with permissions `0o600` (private) and `0o644` (public).

The `GATEWAY_ID` constant (`"openshell-gateway"`) is the sole authoritative
source for the `gateway_id` field written into `config.toml`; it must match
the `openshell-server` binary's expected default.

## Alternatives considered

- **Leader-minted peer secret (chosen):** Keys are generated once and shared
  via Juju's secret mechanism — the only channel that encrypts at rest and in
  transit within the Juju model.  Minting lazily inside reconcile keeps keygen
  in the single convergence path rather than a separate `leader-elected`
  handler, so the key is available as soon as the peer relation exists.

- **Per-unit keypairs:** Each unit generates its own keypair.  Rejected because
  tokens minted on one unit would not validate on another — incompatible with
  horizontal scaling.

- **Static keypair in charm config or relation data:** Would expose the private
  signing key in plain text in Juju's model database and relation databags.
  Rejected on security grounds.

- **Key rotation in this MVP:** Deferred to FD-006 (HA/key-distribution work),
  which will introduce the `rotate-jwt-signing-key` action.

## Consequences

- A `gateway-peers` peer relation is required even on a single-unit deployment
  because the JWT secret lives on that relation.
- Non-leader units that reconcile before the leader has minted the secret
  receive `None` from `_ensure_jwt_keypair()`, record a "waiting for JWT
  keypair" gap, and retry on the next event — no crash.
- The private signing key never appears in charm config, relation databags, or
  Juju's audit log.
- Changing the keypair requires the `rotate-jwt-signing-key` action (FD-006);
  there is no in-place config-change path.
- `GATEWAY_ID = "openshell-gateway"` is a cross-component contract; the Rust
  binary must default to the same value (to be verified when FD-004 lands).
