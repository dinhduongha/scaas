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
- Status: UNAUDITED until the Fable audit.
