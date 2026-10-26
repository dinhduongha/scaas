#!/bin/sh
# t8d2b (plan 5h Task 8d part 2b, open item (a)): the C core's wasm32 arena peak at R_TXM M = 2 (auditor on and off) at
# the three sets whose set.toml [pqzl_c] wasm_max_legs = 2 is an estimate. A MEMORY measurement: pqz_arena_peak (the
# arena's high-water mark, step_arena_peak in pqz.wasm), with the production wasm32 arena (PQZ_ARENA_MB=512); one
# prove each; the timing lines run_wasm.mjs prints are not used. Every relation a wasm32 wallet can prove with this
# backend is loaded in pqz_bench's order (R_REG, R_TX, R_BURN, R_DS, R_DR, R_TX0, R_TXM1, R_TXM2, R_TXM1_0, R_TXM2_0;
# mask 3327; not M = 4 / 8, refused above wasm_max_legs), so R_TXM2_0, the last, peaks with all their keys in the
# arena (the worst case of a wallet; the first run, M = 2 alone, mask 2176, is kept as *-alone.jsonl). Run:
#   scripts/capped pqz-core/pqzl/runs/2026-10-26-t8d2b-cwasm-m2.sh   -> runs/2026-10-26-t8d2b-cwasm-m2-<set>.jsonl
set -eu
cd "$(dirname "$0")/.."
for s in n2048-kmax1024 n2304-kmax4096 n2560-kmax16384; do
  B=build/t8d2b-cwasm-$s PQZ_SET=$s ./build.sh wasm > /dev/null
  # rel bits: 63 = the six single forms, 1 << 6 / 7 = R_TXM1 / 2, 1 << 10 / 11 = R_TXM1_0 / 2_0
  PQZ_WASM_FILE=build/t8d2b-cwasm-$s/wasm/pqz.wasm PQZ_ARENA_MB=512 node test/run_wasm.mjs 1 0 3327 \
    > runs/2026-10-26-t8d2b-cwasm-m2-$s.jsonl || echo "rc $? at $s" >> runs/2026-10-26-t8d2b-cwasm-m2-$s.jsonl
done
