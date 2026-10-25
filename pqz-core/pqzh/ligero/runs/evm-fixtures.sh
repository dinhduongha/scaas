#!/bin/sh
# The EVM Ligero fixtures (plan 5h Task 8d part 2; the set's PQZH id in each statement), run alone:
#   scripts/capped pqz-core/pqzh/ligero/runs/evm-fixtures.sh <tag>
# n2048-kmax1024 -> smartcontracts/evm/test/vectors/pqzh-ligero/ (committed: the Solidity LigeroVerifier test's fixtures,
# that port is n2048-kmax1024's field and layout), then tests/attacks.rs evm_fixtures at each PQZH set; at the other
# sets the test exports into the target's temp dir itself (nothing committed; owner 2026-10-25).
# Logs runs/<tag>-export-n2048-kmax1024.jsonl, runs/<tag>-evm-<set>.txt.
set -eu
cd "$(dirname "$0")/.."
tag=${1:-evm}
cargo run --release --offline --quiet -j2 --features set-n2048-kmax1024 --bin ligero_export -- \
  ../../../smartcontracts/evm/test/vectors/pqzh-ligero proven conj johnson > runs/$tag-export-n2048-kmax1024.jsonl
for s in n2048-kmax1024 n2304-kmax4096 n2560-kmax16384; do
  cargo test --release --offline -j2 --features set-$s --test attacks evm_fixtures > runs/$tag-evm-$s.txt 2>&1
  tail -3 runs/$tag-evm-$s.txt
done
