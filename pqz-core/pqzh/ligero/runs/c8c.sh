#!/bin/sh
# Plan 5h Task 8c part 2 (PQZH per parameter set through the generator): the crate rounds, no timing. Run under the
# machine lock, one round per capped job (per-set cargo targets, so rounds of different sets may run at once):
#   scripts/capped pqz-core/pqzh/ligero/runs/c8c.sh n2560 | v3 | a | fallback
# n2560: n2560-kmax16384 (n 32,756, k 817, t 122, MAX_PROOF_PQZH 327,680, owner 2026-10-23): tests, production lib, kat (every
# honest proof verifies), native = wasm32, sizes / soundness, constant-time check. v3: n2048-kmax1024 byte identity with
# the baseline runs/c8-base-kat.jsonl and the vectors replay, native = wasm32. a: n2304-kmax4096 preset B. fallback:
# n2304-kmax4096's feature fallback-retry tests.
set -u
cd "$(dirname "$0")/.."
case ${1:?round} in
  n2560) S=n2560-kmax16384
    runs/c8.sh c8c-n2560 $S && runs/c8-wasm.sh c8c-n2560 $S && target/$S/release/ligero_kat sizes > runs/c8c-n2560-sizes.jsonl &&
      runs/ct.sh c8c-n2560 4095 1 $S ;;
  v3) runs/c8.sh c8c-v3 n2048-kmax1024 && runs/c8-wasm.sh c8c-v3 n2048-kmax1024 ;;
  a) runs/c8.sh c8c-a n2304-kmax4096 && runs/c8-wasm.sh c8c-a n2304-kmax4096 ;;
  fallback) CARGO_TARGET_DIR=$(pwd)/target/n2304-kmax4096-fallback cargo test --release --offline --no-fail-fast \
      --features set-n2304-kmax4096,fallback-retry -- --test-threads 1 > runs/c8c-fallback-tests.txt 2>&1
    grep -E '^test result|FAILED|fallback_retry' runs/c8c-fallback-tests.txt; ! grep -q FAILED runs/c8c-fallback-tests.txt ;;
  *) echo "round: n2560 | v3 | a | fallback" >&2; exit 2 ;;
esac
