# 0010. Authoritative `sslmode` override on PostgreSQL URI

- **Status:** Accepted
- **Date:** 2026-07-13
- **Deciders:** architect, implementer

## Context

`DatabaseRequires` from `data_platform_libs` delivers a PostgreSQL URI in its
relation databag.  The `sslmode` query parameter in that URI controls whether
the database connection uses TLS, and the charm's security posture requires TLS
to always be on for database connections.

An upstream operator could supply any `sslmode` value — including `disable` or
`prefer` — either by accident or because the operator is running without TLS.
Simply appending `&sslmode=require` to the URI when an `sslmode` parameter is
already present produces a duplicate parameter whose interpretation is
driver-dependent and could silently disable TLS.

## Decision

The `append_sslmode(uri, *, have_ca)` helper in `config_model.py`:
1. Parses the URI with `urllib.parse.urlsplit`.
2. Parses the query string with `parse_qsl(keep_blank_values=True)`.
3. **Drops every existing `sslmode` key** from the parameter list.
4. Appends the single authoritative value: `verify-full` when the database
   relation data includes a `tls_ca` field, otherwise `require`.
5. Re-encodes with `urlencode` and `urlunsplit`.

The `tls_ca` check uses the CA from the *database* relation's fetched data
(the PostgreSQL server CA), not the gateway's own TLS CA.

## Alternatives considered

- **Parse, strip, and re-append (chosen):** Guarantees exactly one `sslmode`
  regardless of upstream value.  Correctly overrides `sslmode=disable` from
  a misconfigured or non-TLS PostgreSQL operator.

- **Append unconditionally (rejected):** Produces a duplicate `sslmode`
  parameter when the upstream already includes one.  Driver behaviour on
  duplicate parameters is undefined; the first or last value may win, making
  TLS enforcement unreliable.

- **Trust the upstream value (rejected):** Gives up the charm's ability to
  enforce its own TLS posture.  An operator deploying a non-TLS PostgreSQL
  would silently result in plain-text database connections.

## Consequences

- Database connections always use TLS regardless of what the PostgreSQL
  operator sends in the relation databag.
- When the PostgreSQL operator provides a CA (`tls_ca` in relation data),
  the connection uses full certificate verification (`verify-full`), which
  protects against MITM attacks.
- Without a CA, `require` enforces an encrypted channel without verifying
  the server certificate — acceptable as a baseline, though operators are
  encouraged to use a CA-capable PostgreSQL operator.
- `append_sslmode` is a pure function in `config_model.py`, testable without
  Juju, and the unit tests include a case where the upstream URI carries
  `sslmode=disable` to verify it is overridden.
