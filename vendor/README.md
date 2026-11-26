# vendor

Third-party sources at an exact published version. A crate taken as published, unedited, sits in `<name>-<version>/` with a
`VENDORED.md`: the source URL, the package's sha256, the upstream repository and commit, the date, what uses it and its audit
status. `pqclean-falcon-seeded/` is re-created by its `vendor.sh` from pinned packages (symbols renamed; `seeded.c` is
PQClean's `pqclean.c` with the randomness passed in). Code here counts as audited only by a named audit round; until then
it is UNAUDITED.

| Directory | What | Used by |
|---|---|---|
| [`falcon-rs-0.3.1/`](falcon-rs-0.3.1/VENDORED.md) | falcon-rs 0.3.1 (MIT), the round-3 Falcon port | `clients/ua-rs` on wasm32: Falcon keys, signatures, verification ([CLI-UAL-66](../docs/clients/ua-libraries.md#CLI-UAL-66)) |
| [`pqclean-falcon-seeded/`](pqclean-falcon-seeded/vendor.sh) | PQClean Falcon-padded-512 / -1024 (clean, MIT) with the randomness passed in (`seeded.c`); `vendor.sh` re-creates it from the pinned crates | `clients/ua-rs` natively (`build.rs`, MD-8) |

Rules: a new version is a new directory from the published package (its checksum checked against the lockfile), never an edit
in place. `scripts/format.sh` leaves `vendor/` out; `docs_check.py paths` and the pre-push secret scan still read it.
