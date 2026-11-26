# PQClean Falcon (seeded build), vendored

- Source: two crates.io packages, the ones `ua-rs` used before (MD-8, ua-rs-sign T3b):
  `pqcrypto-falcon` 0.4.1 (<https://static.crates.io/crates/pqcrypto-falcon/pqcrypto-falcon-0.4.1.crate>, sha256
  `01a0e72acca23e8bc9886f26396adbc1a2c71fc0b841723415ee245cdc5b395c`) for PQClean `crypto_sign/falcon-padded-512/clean` and
  `falcon-padded-1024/clean`; `pqcrypto-internals` 0.2.11
  (<https://static.crates.io/crates/pqcrypto-internals/pqcrypto-internals-0.2.11.crate>, sha256
  `b4a326caf27cbf2ac291ca7fd56300497ba9e76a8cc6a7d95b7a18b57f22b61d`) for `common/fips202.{c,h}`. Each sha256 is that
  crate's `checksum` in `clients/ua-rs/Cargo.lock` when it was a dependency.
- License: MIT (`LICENSE`, the falcon-padded-512 copy): Copyright (c) 2017-2019 Falcon Project (Thomas Pornin); fips202 is
  public domain.
- Edit: one mechanical rename, so this build links beside another PQClean copy without a duplicate symbol:
  `PQCLEAN_FALCONPADDED512_CLEAN_` -> `SCAAS_UA_FNDSA512_`, `PQCLEAN_FALCONPADDED1024_CLEAN_` -> `SCAAS_UA_FNDSA1024_`,
  fips202's `shake128*` `shake256*` `sha3_256*` `sha3_384*` `sha3_512*` -> `scaas_ua_*`. PQClean's `pqclean.c` is not taken.
- Installed, not committed (owner 2026-11-26, [ARCH-POS-24](../docs/decisions.md#ARCH-POS-24)): `scripts/vendor.sh install`
  writes `vendor/pqclean-falcon-seeded/` (the rename steps were this directory's `vendor.sh` until then);
  `scripts/vendor.sh check` requires its git tree id `ae0932f272cdf58f2eefa9188b121e86abf32547`, the tree committed
  before, minus `seeded.c` and `vendor.sh`.
- Ours beside it: `vendor/pqclean-falcon-seeded.local/seeded.c`, PQClean's `pqclean.c` with the randomness passed in (the
  48-byte keygen seed; the 40-byte nonce and 48-byte sampler seed of a signature), tracked; it moved there from this
  directory on 2026-11-26, unchanged.
- Use: `ua-rs` natively with feature `pq` (`build.rs`, `cfg(scaas_falcon)`); wasm32 uses
  [falcon-rs 0.3.1](falcon-rs-0.3.1.VENDORED.md) (CLI-UAL-66).
- Status: **UNAUDITED.**
