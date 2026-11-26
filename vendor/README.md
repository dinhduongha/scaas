# vendor

Third-party sources at an exact published version, **not in git** ([ARCH-POS-24](../docs/decisions.md#ARCH-POS-24), owner
2026-11-26). `scripts/vendor.sh install` fetches each package (a crate from the cargo cache when it is there, else
crates.io, its archive's sha256 checked against its pin; a git package by its commit id alone), unpacks or checks it out in
a fresh temporary directory and writes `vendor/<name>/`; `scripts/vendor.sh check` compares each installed directory with
its pinned git tree id (a git package: its commit and sha256 too). CI runs both before every job that builds `ua-rs` or a
crate over it, or the contracts; a fresh clone or worktree runs them once (`cargo` refuses a missing `path` dependency even
behind a feature that is off; forge needs `smartcontracts/evm/lib`).

```sh
scripts/vendor.sh install                  # group core: what the builds need (the default)
scripts/vendor.sh check
scripts/vendor.sh install kat research     # the owner's machine: the KAT / cross-check and the parameter scripts
scripts/vendor.sh check kat research       # (CI: the pqz job fetches and checks them, nothing runs them)
```

**Groups.** `core`: the Falcon sources of `ua-rs` and the forge libraries of `smartcontracts/evm`; `install core` also
links `smartcontracts/evm/lib/openzeppelin-contracts` and `lib/forge-std` to them (relative links inside the tree, so
forge's remappings and every source unit name stay `lib/...`; `check` requires the links; a real directory there, the old
`scripts/evm_libs.sh` copy, is refused with `LINK_IS_A_DIRECTORY`). `kat`: upstream LaZer for the pqz-core KAT and
cross-check scripts. `research`: the lattice estimators of `pqz-core/pqzl/params` and `params/sets/make.sh`. Since TODO
8b-9 (4b) (2026-11-27) every third-party source the repository builds or runs is here; npm / cargo / Python packages and CI
tool binaries stay with their own lockfiles and pins.

**Worktrees** (owner 2026-11-27). `scripts/vendor.sh link <main checkout> [group...]` gives a worktree the main
checkout's packages without a second copy: each package whose directory in `<main checkout>/vendor/` passes this
checkout's pin (commit, sha256, tree id, computed as `check` does) becomes the link `vendor/<name>` -> that directory
(`LINKED`); a package whose pin differs there, or is missing (a branch that moves a pin), is installed here as a real
copy (`COPY`); then the `smartcontracts/evm/lib` links as `install` writes them. `check` reads through a link exactly as
through a directory, so a changed file in the linked copy fails it. `install` never writes through a link: one that
passes its check is left as it is, one that does not is refused (`SYMLINK_FAILS_CHECK`: run `link`, or remove the link).
`link` only reads the main checkout's `vendor/`; it refuses a missing one (`LINK_SOURCE_MISSING`) and this checkout
itself (`LINK_TO_SELF`).

```sh
scripts/vendor.sh link <main checkout> core kat research && scripts/vendor.sh check core kat research
```

**Layout.** A directory `vendor/<name>/` is the package's alone and git-ignored, as is a link in its place (`/vendor/*` in the root `.gitignore`, all but our files);
`install` replaces it whole and never edits it. What SCaaS writes sits beside it and stays tracked: this file,
`<name>.VENDORED.md` (where the package comes from, its pins, what uses it, its audit status) and `<name>.local/` (our own
source built with the package; `!/vendor/*.local/`). The pins (archive sha256, tree id) live in `scripts/vendor.sh`. A tree id
is `git write-tree` over every file of the directory, so a committed copy and an installed one compare by the same number.

| Directory | What | Pins | Used by |
|---|---|---|---|
| `falcon-rs-0.3.1/` ([VENDORED](falcon-rs-0.3.1.VENDORED.md)) | falcon-rs 0.3.1 (MIT), the round-3 Falcon port, as published minus `.cargo-ok` / `.cargo_vcs_info.json` | crate sha256 `97afa6b3…`, tree `315fb462…` | `clients/ua-rs` on wasm32: Falcon keys, signatures, verification ([CLI-UAL-66](../docs/clients/ua-libraries.md#CLI-UAL-66)) |
| `pqclean-falcon-seeded/` ([VENDORED](pqclean-falcon-seeded.VENDORED.md)) | PQClean Falcon-padded-512 / -1024 (clean, MIT) and `fips202` from two pinned crates, symbols renamed | two crate sha256s, tree `ae0932f2…` | `clients/ua-rs` natively (`build.rs`, MD-8) |
| `pqclean-falcon-seeded.local/` (tracked) | `seeded.c`: PQClean's `pqclean.c` with the randomness passed in (ours; MIT as its origin) | — | the same native build |
| `openzeppelin-contracts-fda6b85f/` ([VENDORED](openzeppelin-contracts-fda6b85f.VENDORED.md)) | OpenZeppelin Contracts at `fda6b85f` (MIT), git, no submodules | commit, sha256 `95afdb20…`, tree `ca37933c…` | `smartcontracts/evm` through `lib/openzeppelin-contracts` (CTR-GEN-01) |
| `forge-std-88c8a288/` ([VENDORED](forge-std-88c8a288.VENDORED.md)) | forge-std at `88c8a288` (MIT / Apache-2.0), git | commit, sha256 `8401226c…`, tree `92bb6f35…` | `smartcontracts/evm` tests and scripts through `lib/forge-std` |
| `lazer-3330e48/` ([VENDORED](lazer-3330e48.VENDORED.md)) | upstream LaZer at `3330e48` (MIT), git, no submodules | commit, sha256 `d84efa27…`, tree `930143bf…` | `pqzl/kat/build-lazer-dump.sh`, `artifact/reproduce.sh --upstream`, `research/upstream/`, `params/sets/make.sh` (group `kat`) |
| `leaky-LWE-Estimator-0a9caf8/` ([VENDORED](leaky-LWE-Estimator-0a9caf8.VENDORED.md)) | DDGR20's estimator at `0a9caf8`, git | commit, sha256 `200aa5fd…`, tree `ff8f143c…` | the hint scripts of `pqz-core/pqzl/params`, `make.sh` `e_s1` (group `research`) |
| `lattice-estimator-53da598/` ([VENDORED](lattice-estimator-53da598.VENDORED.md)) | lattice-estimator at `53da598` (LGPL-3.0+), git | commit, sha256 `6e44b984…`, tree `7cb765ba…` | every estimate of `pqz-core/pqzl/params`, `make.sh` `e_s1` (group `research`) |

Rules: a new version is a new directory and a new pin row from the published package, never an edit in place; a script
that builds a git package clones it and builds in the clone. Code here
counts as audited only by a named audit round; until then it is UNAUDITED. `scripts/format.sh` leaves `vendor/` out.
