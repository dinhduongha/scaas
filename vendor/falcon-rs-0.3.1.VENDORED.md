# falcon-rs 0.3.1, vendored

- Source: <https://static.crates.io/crates/falcon-rs/falcon-rs-0.3.1.crate> (crates.io package `falcon-rs` 0.3.1)
- Crate sha256: `97afa6b3e692aa0c332b883f18e3f999e99df06331ac93196b60805950b0f65f` (the `checksum` of falcon-rs 0.3.1 in
  `clients/ua-rs/Cargo.lock` before vendoring)
- Upstream: <https://github.com/lattice-safe/falcon-rs>, commit `59b2e673f714f9b7865cd28a0845329ae3231432` (its
  `.cargo_vcs_info.json`)
- License: MIT (`LICENSE`): Copyright (c) 2017-2019 Falcon Project (Thomas Pornin); Copyright (c) 2026 Rust port contributors
- Vendored: 2026-11-26 (owner: the audited code lives in the repository), the package as published; only `.cargo-ok` and
  `.cargo_vcs_info.json` dropped. Nothing else is edited.
- Installed, not committed (owner 2026-11-26, [ARCH-POS-24](../docs/decisions.md#ARCH-POS-24)): `scripts/vendor.sh install`
  writes `vendor/falcon-rs-0.3.1/` from the crate (its sha256 checked first); `scripts/vendor.sh check`, in CI, requires the
  directory's git tree id `315fb462132276c5cdf64dca2ee094f9652c5f85`. This file sat in that directory until then; the tree
  the audit names, `57a1aa39f980835a94100cf0b0d81bf8b221752e`, is that tree plus this file as it was at `5120ac3c5` (blob
  `c0866a60d826f57b50928e65231c55b57d47910e`), which `check` recomputes.
- Use: `ua-rs` on wasm32 only (feature `pq`, `default-features = false, features = ["fpemu"]`), the Falcon-padded-512 /
  -1024 key pairs, signatures and verification of `src/falcon/soft.rs` (CLI-UAL-66); native builds keep
  `vendor/pqclean-falcon-seeded` beside it ([its record](pqclean-falcon-seeded.VENDORED.md)).
- Status: **UNAUDITED.** A Fable audit read this tree (read-only, no build or timing run) and the `ua-rs` glue on
  2026-11-26, at commit `5120ac3c5cfc671217bb561f5e9834c15ec02dd3`, git tree id
  `57a1aa39f980835a94100cf0b0d81bf8b221752e`: approve with fixes, 0 P0, 0 P1, 3 P2, 9 P3. By reading, the round-3 code
  under `fpemu` is a faithful port of the C PQClean ships (no hardware float or `libm` on the signing path; integer tables
  equal; `rnd = nonce || sampler seed` as `seeded.c`). FR-3 (a re-check of this tree against the crate's sha256 in CI,
  P2) is fixed by `scripts/vendor.sh check` in CI at `f3ebb2da4`. The other fixes, in the glue, tests, CI and docs (this tree
  unedited), landed at `b9b5a4c24`: the wasm32 gate as CI job `ua-rs-fndsa-wasm` (FR-4), key-pair parity over 1,000 seeds per degree
  natively and in wasm32 (FR-5), the stated differences (signatures equal PQClean's except with probability about 2^-39 per
  signature, `fpr_expm_p63`; signed zero, FR-1, FR-2), the rule "never a secret message" (FR-7), the glue on
  `falcon::falcon::*` only with a test guard (FR-8), the keygen cap as a named error (FR-9), `zeroize` (FR-10), 624 encoding-edge
  rows and sign-side refusals (FR-11), verify after sign (FR-12). Open: FR-6, FR-7, FR-8, FR-9 upstream (the rejected padded
  candidate left unwiped, the variable-time hash-to-point, the debug-only preconditions, the sampler's panic), the timing
  measurement (written, not run) and the no-`f64` check of the wasm32 artefact. The record, with every finding and its state, is
  [`docs/audit/audited/vendor-falcon-rs.md`](../docs/audit/audited/vendor-falcon-rs.md) (owner 2026-11-26); it says what remains
  before this path is labelled `AI-AUDITED (Fable)`, and `UNAUDITED` again on any change.
