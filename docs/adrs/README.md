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
