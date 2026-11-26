# forge-std 88c8a288, vendored

- Source: <https://github.com/foundry-rs/forge-std>, commit `88c8a2886f6f64c846ae57533a36361acb81683a` (2026-08-28);
  master after v1.16.2: the checkout every local test ran with (tests and scripts only, never in a deployed contract).
- License: MIT or Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
- Fetched (TODO 8b-9 (4b), [ARCH-POS-24](../docs/decisions.md#ARCH-POS-24); group `core`): `scripts/vendor.sh install
  core` runs `git fetch --depth 1` of that commit id alone (git checks every object against it) and checks it out in a
  fresh temporary directory, then moves it to `vendor/forge-std-88c8a288/`; the one-commit `.git` stays, so `git -C
  <dir> rev-parse HEAD` and a local `git clone` of the directory work. Nothing is edited.
- Pins (in `scripts/vendor.sh`; `install` and `check` require all three): the commit; sha256
  `8401226cdbba19d3640f90d1868c68fc1b9f91b0c79c598bdd7ad60903c62a35` over `sha256sum` of every file but `.git`, sorted
  by path; git tree id `92bb6f3538c130f4874f478d05d1c90b28e41997` (`git write-tree` over the same files).
- The tree id equals the commit's own tree (no submodule).
- Before the move (`scripts/evm_libs.sh`, CTR-GEN-01) the pin was the sha256 over `sha256sum` of `src/**/*.sol`,
  `290d0e46a0e4c0a3a0eaca67798b028dd57b9d2d75021f710a124a4827d9cb1a`; the installed directory gives the same value.
- Use: `smartcontracts/evm` tests and scripts (remapping `forge-std/` over `lib/forge-std`, a link to this directory).
- Status: **UNAUDITED** (third-party; no SCaaS audit round covers it).
