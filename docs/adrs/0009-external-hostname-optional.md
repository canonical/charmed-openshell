# 0009. `external-hostname` is optional and not part of the Active gate

- **Status:** Accepted
- **Date:** 2026-07-13
- **Deciders:** architect, implementer

## Context

The gateway's TLS certificate CSR and the OAuth redirect URI registered with
Hydra both benefit from knowing the public hostname of the gateway.  However,
operators may not know the final hostname at deploy time, or may be deploying
for in-cluster-only access where no external hostname exists.

The `oauth` interface requires a `redirect_uri` at registration time even
though the gateway is a pure resource server that never performs a redirect.

## Decision

`external-hostname` is an optional config option.  The charm reaches
**Active** without it by using fallbacks:

- **CSR SANs:** `<app>.<model>.svc.cluster.local`, `localhost`, `127.0.0.1`
  (no external hostname SAN).
- **OAuth redirect URI:** the static sentinel `https://openshell.invalid/unused`
  (never dereferenced by the resource server; exists solely to satisfy Hydra's
  registration requirement).

When `external-hostname` is later configured, `_reconcile()` detects the
change, re-requests the certificate with the real SAN included, and calls
`oauth.update_client_config()` with the real redirect URI
(`https://<hostname>/oauth/unused`).  Both re-registrations are triggered by
comparing the newly computed values against sentinels stored in `StoredState`.

## Alternatives considered

- **`external-hostname` optional with fallbacks (chosen):** Operators can bring
  up and test the gateway in a CI or staging cluster before a public hostname
  is assigned.  Reconcile handles the transition automatically when the
  hostname is later set.

- **`external-hostname` required for Active:** Simpler logic — no fallbacks,
  no re-registration path.  Rejected because it forces operators to know the
  final hostname before initial deploy, which is often impractical with
  Kubernetes load balancer provisioning.

## Consequences

- An initial deployment without `external-hostname` reaches Active with a
  certificate valid only for in-cluster DNS names; external TLS connections
  will fail until the hostname is set.  Operators must understand this
  tradeoff.
- Setting `external-hostname` after initial deploy triggers a certificate
  re-request; the unit may briefly return to Waiting until the new certificate
  is issued.
- The static `https://openshell.invalid/unused` redirect URI must be acceptable
  to Hydra as a registered value (a non-resolvable domain satisfies URI
  validation).
- `StoredState` carries `last_cert_sans` and `last_redirect_uri` as
  re-registration sentinels — the only two fields in `StoredState`
  (see ADR-0011).
