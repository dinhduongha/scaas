> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Matrix homeservers for PqChat tests: Synapse and two backups (2026-11-27)

**Status:** background only, nothing built. The PqChat end-to-end tests run one Synapse in Docker
(`clients/pqchat-core/tests/e2e/matrix.rs`, image `matrixdotorg/synapse:v1.165.0`, `--memory 1g --cpus 1`, users made by
Synapse's own `register_new_matrix_user`, pqchat-core spec §13 O10 (a)). Synapse stays the reference: it is the most complete
implementation of the client-server API and the one matrix.org runs.

**Owner, 2026-11-27:** Tuwunel v2.1.0 and Continuwuity's latest release are recorded here as backups only, not added to the
tests. Use one only if Synapse cannot serve a test (memory on a busy machine, a Synapse-only behaviour to rule out).

## The two backups

Both are Rust forks of conduwuit (itself a fork of Conduit), Apache-2.0, started after conduwuit was archived; each calls
itself conduwuit's successor.

| | Tuwunel | Continuwuity |
|---|---|---|
| Repository | github.com/matrix-construct/tuwunel | github.com/continuwuity/continuwuity (mirror of forgejo.ellis.link/continuwuation/continuwuity) |
| Latest release (GitHub API, read 2026-11-27) | **v2.1.0**, published 2026-11-26 (v2.0.0-assets 2026-11-10, v1.9.4 2026-10-10) | **v26.9.4** (calendar versions); the mirror's release objects for v26.9.2 to v26.9.4 are all dated 2026-11-26, likely a mirror sync rather than the release day; tags `v26.11.0-alpha.1` / `-alpha.2` exist |
| Licence | Apache-2.0 | Apache-2.0 |
| Who | one main maintainer, an "enterprise successor" positioning | community volunteers; more contributors by forum accounts; backports Tuwunel changes |
| Test-relevant | shared-secret registration (named in the 1.9 line's Complement notes); opens an old Conduit database in place (from 1.8) | conduwuit data continues; differences document marked "may not be up to date" by its own authors |

Neither has an authoritative, current feature comparison; the two teams do not cooperate.

## If a backup is ever used

- Pin the image by digest, at a release at least 14 days old (the same caution the repo applies to new crate versions); read
  the changelog first for a major version (Tuwunel 2.x).
- Run the same test bodies against it; only the start-up and user-registration helper in `tests/e2e/matrix.rs` differs.
- Docker with `--memory`, as for Synapse; never matrix.org or any public homeserver (matrix.org's open password registration
  needs a verified email, and tests must not touch an outside service).

## Sources (read 2026-11-27)

- GitHub API `repos/matrix-construct/tuwunel/releases` and `repos/continuwuity/continuwuity/releases`, `/tags`
- https://github.com/matrix-construct/tuwunel
- https://forgejo.ellis.link/continuwuation/continuwuity/issues/1538 and /issues/849 (differences, comparison)
- https://forgejo.ellis.link/continuwuation/continuwuity/src/tag/v0.4.7/docs/differences.md
- https://matrix.org/blog/2026/08/07/this-week-in-matrix-2026-08-07/ (Continuwuity)
- https://matrix.org/blog/2025/01/06/authentication-changes/ and https://matrix.org/blog/2025/04/morg-now-running-mas/
  (matrix.org registration and MAS)
