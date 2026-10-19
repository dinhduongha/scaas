#!/bin/bash
# CTR-GEN-01: the forge libraries of smartcontracts/evm, pinned. `lib/` is not committed (source of others, fetched by
# commit); each pin is a commit plus the sha256 of the sources the remappings compile, so a local checkout, a symlink to
# one, or a CI `forge install --no-git` is checked the same way.
#   scripts/evm_libs.sh install   forge install --no-git each library at its commit (CI; a fresh clone)
#   scripts/evm_libs.sh check     sha256 of each library's sources against its pin; exit 1 on a mismatch or a missing one
set -euo pipefail
cd "$(dirname "$0")/../smartcontracts/evm"

# name | repository | commit | source dir (the remapping) | sha256 over `sha256sum` of its *.sol files, sorted by path
PINS=(
  # OpenZeppelin master after v5.2.0, before v5.3.0 (2025-03-13): the code uses Math.saturatingAdd / Math.mul512
  # (not in v5.2.0); v5.3.0 changes P256. Every local build and 7622 deployment compiled against it.
  "openzeppelin-contracts|OpenZeppelin/openzeppelin-contracts|fda6b85f2c65d146b86d513a604554d15abd6679|contracts|2e19583b237d4ee4a0c083d9ed07033866e0b61c7f29c39fb9f0b6d7466582e1"
  # forge-std master 2026-08-28 (after v1.16.2): the checkout every local test ran with (tests and scripts only).
  "forge-std|foundry-rs/forge-std|88c8a2886f6f64c846ae57533a36361acb81683a|src|290d0e46a0e4c0a3a0eaca67798b028dd57b9d2d75021f710a124a4827d9cb1a"
)

digest() { (cd "$1" && find . -name '*.sol' -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) | sha256sum | cut -d' ' -f1; }

case "${1:-}" in
  install)
    for p in "${PINS[@]}"; do
      IFS='|' read -r name repo commit _ _ <<<"$p"
      forge install --no-git "$repo@$commit"
      [[ -d "lib/$name" ]] || { echo "evm_libs: lib/$name missing after install" >&2; exit 1; }
    done
    ;;
  check)
    bad=0
    for p in "${PINS[@]}"; do
      IFS='|' read -r name _ commit dir sum <<<"$p"
      if [[ ! -d "lib/$name/$dir" ]]; then
        echo "evm_libs: lib/$name/$dir missing (scripts/evm_libs.sh install)" >&2; bad=1; continue
      fi
      got=$(digest "lib/$name/$dir")
      if [[ "$got" == "$sum" ]]; then echo "evm_libs: $name OK ($commit)"
      else echo "evm_libs: $name MISMATCH: sources $got, pin $sum ($commit)" >&2; bad=1; fi
    done
    exit "$bad"
    ;;
  *) echo "usage: $0 install|check" >&2; exit 2 ;;
esac
