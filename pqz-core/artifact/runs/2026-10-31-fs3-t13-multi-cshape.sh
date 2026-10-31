#!/bin/sh
# usage: cshape.sh <t> <k list, e.g. "1 2 3">: commands k (1..6) of one shape of txm-bench.sh's loop (same body and
# NP/NV/NF/NPW/NVW defaults), one docker run, step c-shape-<t>-<k joined>
t=$1 K=$2
W=/home/ha/work/ainative/scaas/.claude/worktrees/fs3-t13-rollout
cd $W && GATE=1 scripts/capped pqz-core/artifact/runs/2026-10-31-fs3-t13-multi-step.sh c-shape-$t-$(echo $K | tr -d ' ') "cd pqzl && export PQZ_ARENA_MB=3072 B=build/ov OVERSIZE=1; R=/out/pqzl-txm NP=10 NV=30 NF=200 NPW=3 NVW=3 t=$t; m=\$((64 << t)); for k in $K; do case \$k in
  1) build/ov/native/pqz_bench \"\$NP\" \"\$NV\" \$m >> \"\$R-native-generic.jsonl\" || echo \"native generic \$t rc=\$?\" ;;
  2) PQZ_VERIFY=fast build/ov/native/pqz_bench 2 \"\$NF\" \$m >> \"\$R-native-fast.jsonl\" || echo \"native fast \$t rc=\$?\" ;;
  3) PQZ_VERIFY=fast build/ov/native-x86v3/pqz_bench 2 \"\$NF\" \$m >> \"\$R-x86v3-fast.jsonl\" || echo \"x86v3 fast \$t rc=\$?\" ;;
  4) PQZ_WASM_FILE=build/ov/wasm/pqz.wasm PQZ_VERIFY=fast node test/run_wasm.mjs 1 \$((NF / 2)) \$m >> \"\$R-wasm-fast.jsonl\" || echo \"wasm fast \$t rc=\$?\" ;;
  5) PQZ_WASM_FILE=build/ov/wasm/pqz.wasm node test/run_wasm.mjs \"\$NPW\" \"\$NVW\" \$m >> \"\$R-wasm-generic.jsonl\" || echo \"wasm generic \$t rc=\$?\" ;;
  6) PQZ_WASM_FILE=build/ov-nosv/wasm/pqz.wasm node test/run_wasm.mjs 1 0 \$m >> \"\$R-wasm-nosv.jsonl\" || echo \"wasm nosv \$t rc=\$?\" ;;
esac; done >> /out/pqzl-txm.txt 2>&1; echo shape \$t m \$m k $K done; grep -h '\"rel\"' \$R-native-generic.jsonl | tail -1 | cut -c1-60"
