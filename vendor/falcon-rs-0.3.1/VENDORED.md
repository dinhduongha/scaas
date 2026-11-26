# falcon-rs 0.3.1, vendored

- Source: <https://static.crates.io/crates/falcon-rs/falcon-rs-0.3.1.crate> (crates.io package `falcon-rs` 0.3.1)
- Crate sha256: `97afa6b3e692aa0c332b883f18e3f999e99df06331ac93196b60805950b0f65f` (the `checksum` of falcon-rs 0.3.1 in
  `clients/ua-rs/Cargo.lock` before vendoring)
- Upstream: <https://github.com/lattice-safe/falcon-rs>, commit `59b2e673f714f9b7865cd28a0845329ae3231432` (its
  `.cargo_vcs_info.json`)
- License: MIT (`LICENSE`): Copyright (c) 2017-2019 Falcon Project (Thomas Pornin); Copyright (c) 2026 Rust port contributors
- Vendored: 2026-11-26 (owner: the audited code lives in the repository), the package as published; only `.cargo-ok` and
  `.cargo_vcs_info.json` dropped, this file added. Nothing else is edited.
- Use: `ua-rs` on wasm32 only (feature `pq`, `default-features = false, features = ["fpemu"]`), the Falcon-padded-512 /
  -1024 key pairs, signatures and verification of `src/falcon/soft.rs` (CLI-UAL-66); native builds keep
  `vendor/pqclean-falcon-seeded` beside it.
- Status: **UNAUDITED.** A Fable audit read this tree (read-only, no build or timing run) and the `ua-rs` glue on
  2026-11-26, at commit `5120ac3c5cfc671217bb561f5e9834c15ec02dd3`, git tree id
  `57a1aa39f980835a94100cf0b0d81bf8b221752e`: approve with fixes, 0 P0, 0 P1, 3 P2, 9 P3. By reading, the round-3 code
  under `fpemu` is a faithful port of the C PQClean ships (no hardware float or `libm` on the signing path; integer tables
  equal; `rnd = nonce || sampler seed` as `seeded.c`). Open before the label changes: a re-check of this tree against the
  crate's sha256 in CI (P2), the wasm32 gate as a CI job (P2), native / wasm32 key-generation parity over many seeds (P2),
  the P3 items (signatures equal PQClean's except with probability about 2^-39 per signature, from `fpr_expm_p63`; a
  rejected candidate left unwiped; variable-time hash-to-point, so never a secret message; `zeroize` in the glue; more
  edge refusal rows), and a timing test. The record, with every finding, is
  [`docs/audit/audited/vendor-falcon-rs.md`](../../docs/audit/audited/vendor-falcon-rs.md) (owner 2026-11-26). After those fixes this path is labelled `AI-AUDITED (Fable)`, and `UNAUDITED` again on any change.
