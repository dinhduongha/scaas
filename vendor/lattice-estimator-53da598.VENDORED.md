# lattice-estimator 53da598, vendored

- Source: <https://github.com/malb/lattice-estimator>, commit `53da5982597709ba0fdf94ea37a84d822310fd84` (2026-08-19);
  the cost model of every PQZ security estimate (`pqz-core/pqzl/params/README.md`, `RC.ADPS16`).
- License: LGPL-3.0-or-later (`README.rst`).
- Fetched (TODO 8b-9 (4b), [ARCH-POS-24](../docs/decisions.md#ARCH-POS-24); group `research`): `scripts/vendor.sh
  install research` runs `git fetch --depth 1` of that commit id alone (git checks every object against it) and checks
  it out in a fresh temporary directory, then moves it to `vendor/lattice-estimator-53da598/`; the one-commit `.git`
  stays, so `git -C <dir> rev-parse HEAD` and a local `git clone` of the directory work. Nothing is edited.
- Pins (in `scripts/vendor.sh`; `install` and `check` require all three): the commit; sha256
  `6e44b984b1d0470f73087ed62da650ad12d8f867871cce61feb5aa61fe263fd9` over `sha256sum` of every file but `.git`, sorted
  by path; git tree id `7cb765baf3bb401580c08f678dcee8c6f35e66d1` (`git write-tree` over the same files).
- The tree id equals the commit's own tree (no submodule) and the clone the parameter-set runs used (`PQZ_TOOLS/le`).
- Use: `pqz-core/pqzl/params` (`run.sh` E-S0, `run_e_s1.sh`, `anon/`, `aprime/`, `n-study/`, `p16k/`) and
  `params/sets/make.sh` (`e_s1`), in a pinned Sage container with no network; never by CI or the gate.
- Status: **UNAUDITED** (third-party; no SCaaS audit round covers it).
