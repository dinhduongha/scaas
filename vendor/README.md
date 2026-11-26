# vendor

Third-party sources at an exact published version, **not in git** ([ARCH-POS-24](../docs/decisions.md#ARCH-POS-24), owner
2026-11-26). `scripts/vendor.sh install` fetches each package (from the cargo cache when it is there, else crates.io),
checks the archive's sha256 against its pin, unpacks it in a fresh temporary directory and writes `vendor/<name>/`;
`scripts/vendor.sh check` compares each installed directory with its pinned git tree id. CI runs both before every job that
builds `ua-rs` or a crate over it; a fresh clone or worktree runs them once (`cargo` refuses a missing `path` dependency
even behind a feature that is off).

```sh
scripts/vendor.sh install   # group core, the only group today
scripts/vendor.sh check
```

**Layout.** A directory `vendor/<name>/` is the package's alone and git-ignored (`/vendor/*/` in the root `.gitignore`);
`install` replaces it whole and never edits it. What SCaaS writes sits beside it and stays tracked: this file,
`<name>.VENDORED.md` (where the package comes from, its pins, what uses it, its audit status) and `<name>.local/` (our own
source built with the package; `!/vendor/*.local/`). The pins (archive sha256, tree id) live in `scripts/vendor.sh`. A tree id
is `git write-tree` over every file of the directory, so a committed copy and an installed one compare by the same number.

| Directory | What | Pins | Used by |
|---|---|---|---|
| `falcon-rs-0.3.1/` ([VENDORED](falcon-rs-0.3.1.VENDORED.md)) | falcon-rs 0.3.1 (MIT), the round-3 Falcon port, as published minus `.cargo-ok` / `.cargo_vcs_info.json` | crate sha256 `97afa6b3…`, tree `315fb462…` | `clients/ua-rs` on wasm32: Falcon keys, signatures, verification ([CLI-UAL-66](../docs/clients/ua-libraries.md#CLI-UAL-66)) |
| `pqclean-falcon-seeded/` ([VENDORED](pqclean-falcon-seeded.VENDORED.md)) | PQClean Falcon-padded-512 / -1024 (clean, MIT) and `fips202` from two pinned crates, symbols renamed | two crate sha256s, tree `ae0932f2…` | `clients/ua-rs` natively (`build.rs`, MD-8) |
| `pqclean-falcon-seeded.local/` (tracked) | `seeded.c`: PQClean's `pqclean.c` with the randomness passed in (ours; MIT as its origin) | — | the same native build |

Rules: a new version is a new directory and a new pin row from the published package, never an edit in place. Code here
counts as audited only by a named audit round; until then it is UNAUDITED. `scripts/format.sh` leaves `vendor/` out.
