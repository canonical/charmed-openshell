# 0012. LXD connectivity over `lxd-https`

- **Status:** Accepted
- **Date:** 2026-08-20
- **Origin:** FD-013 / FD-018
- **Deciders:** architect, implementer

## Context

The `openshell-gateway-k8s` charm ships `openshell-driver-lxd` beside the gateway in
a single rock, but the driver was configured for a local LXD unix socket that does not
exist inside a Kubernetes pod. This left the gateway without a working compute backend:
the driver started, the socket check passed, and every sandbox operation failed.

Two upstream changes made closing the gap possible. First, `canonical/openshell-driver-lxd`
gained an HTTPS + mTLS transport and a real sandbox lifecycle. Second, `canonical/charm-lxd`
provides an `lxd-https` relation interface whose provider registers a requirer's client
certificate in the LXD trust store and removes it when the relation goes away. Authenticating
to LXD therefore becomes a relation side effect rather than a manual `lxc config trust add`
operation.

## Decision

**Adopt the `lxd-https` relation interface as the gateway charm's LXD integration point.**
It is the interface the LXD team owns, it is what the `lxd` charm already provides, and
adopting it means one requirer implementation serves both charmed and unmanaged LXD.

**Create a new `lxd-integrator-k8s` charm instead of adopting
`canonical/lxd-integrator-operator`.** The existing charm speaks a bespoke `lxd` interface
incompatible with `lxd-https`, holds the client private key in plaintext charm config,
disables TLS hostname checking with no compensating pin, and is stale (20.04 bases,
`ops` 2.7, split metadata). A new charm in this repository shares this repo's conventions,
tests and CI, and is versioned alongside the gateway that consumes it.

## Alternatives considered

- **`lxd-https` rather than a bespoke interface (chosen):** One implementation covers both
  the `lxd` charm and `lxd-integrator-k8s`, and certificate trust lifecycle is handled by
  the interface contract rather than custom charm code.

- **A new `lxd-integrator-k8s` charm rather than adopting
  `canonical/lxd-integrator-operator` (chosen):** The existing operator's architecture and
  security posture do not match this repository's standards, and rewriting it would churn
  Anbox Cloud consumers. A new charm lets us keep the implementation, testing and release
  cadence aligned with the gateway.

## Consequences

- The gateway charm requires `lxd-https` exactly once and accepts any provider of that
  interface, whether the `lxd` charm reached through a cross-model offer or the new
  `lxd-integrator-k8s` charm.
- Client certificates and fingerprints are pinned, and hostname verification is disabled
  only because LXD's self-signed certificate makes it meaningless; pinning replaces it
  rather than weakening the posture.
- The deferred open issue **G-LXD** in `docs/spec/openshell-gateway-k8s.md` is superseded
  by this decision and the detailed design in `docs/spec/lxd-connectivity.md`.
