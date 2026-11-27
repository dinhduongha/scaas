# OpenZeppelin Contracts fda6b85f, vendored

- Source: <https://github.com/OpenZeppelin/openzeppelin-contracts>, commit `fda6b85f2c65d146b86d513a604554d15abd6679`
  (2025-03-13); master after v5.2.0, before v5.3.0: the code uses `Math.saturatingAdd` / `Math.mul512` (not in v5.2.0);
  v5.3.0 changes P256. Every local build and SCaaS testnet deployment compiled against it.
- License: MIT (`LICENSE`).
- Fetched (TODO 8b-9 (4b), [ARCH-POS-24](../docs/decisions.md#ARCH-POS-24); group `core`): `scripts/vendor.sh install
  core` runs `git fetch --depth 1` of that commit id alone (git checks every object against it) and checks it out in a
  fresh temporary directory, then moves it to `vendor/openzeppelin-contracts-fda6b85f/`; the one-commit `.git` stays, so
  `git -C <dir> rev-parse HEAD` and a local `git clone` of the directory work. Nothing is edited.
- Pins (in `scripts/vendor.sh`; `install` and `check` require all three): the commit; sha256
  `95afdb2052758a3a3ca153d07a328747f732af516651b231f6154322b775085c` over `sha256sum` of every file but `.git`, sorted
  by path; git tree id `ca37933ccdf02f8d8d549e86deac97239ec7516f` (`git write-tree` over the same files).
- The commit's own tree is `c75944cbd6d6cd1c759f1bb6f6aff79574414a24`; it differs from the installed tree only by its
  three submodule links (`lib/erc4626-tests`, `lib/forge-std`, `lib/halmos-cheatcodes`), which are not fetched: forge
  reads only `contracts/` (`auto_detect_remappings = false`).
- Before the move (`scripts/evm_libs.sh`, CTR-GEN-01) the pin was the sha256 over `sha256sum` of `contracts/**/*.sol`,
  `2e19583b237d4ee4a0c083d9ed07033866e0b61c7f29c39fb9f0b6d7466582e1`; the installed directory gives the same value.
- Use: `smartcontracts/evm` (remapping `@openzeppelin/contracts/` and `openzeppelin-contracts/` over
  `lib/openzeppelin-contracts`, a link to this directory that `scripts/vendor.sh install` writes).
- Status: **UNAUDITED** (third-party; no SCaaS audit round covers it).
