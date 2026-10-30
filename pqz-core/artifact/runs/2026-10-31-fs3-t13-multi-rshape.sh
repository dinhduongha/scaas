#!/bin/sh
# usage: rshape.sh <t> <k list>: commands k (1..4) of one shape of reproduce.sh's Rust R_TXM loop, one docker run
t=$1 K=$2
W=/home/ha/work/ainative/scaas/.claude/worktrees/fs3-t13-rollout
cd $W && GATE=1 scripts/capped pqz-core/artifact/runs/2026-10-31-fs3-t13-multi-step.sh r-shape-$t-$(echo $K | tr -d ' ') "cd pqzl/rust && RO=target/oversize RW=wasm/target/oversize/wasm32-unknown-unknown/release/pqzl_wasm.wasm OUT=/out t=$t; m=\$((64 << t)); for k in $K; do case \$k in
  1) \$RO/release/bench 10 30 \$m >> \$OUT/rust-txm-native-generic.jsonl || echo \"native generic \$t rc=\$?\" ;;
  2) PQZ_VERIFY=fast \$RO/release/bench 2 200 \$m >> \$OUT/rust-txm-native-fast.jsonl || echo \"native fast \$t rc=\$?\" ;;
  3) PQZL_WASM_FILE=\$RW node wasm/run_wasm.mjs 3 3 \$m >> \$OUT/rust-txm-wasm-generic.jsonl || echo \"wasm generic \$t rc=\$?\" ;;
  4) PQZL_WASM_FILE=\$RW PQZ_VERIFY=fast node wasm/run_wasm.mjs 1 100 \$m >> \$OUT/rust-txm-wasm-fast.jsonl || echo \"wasm fast \$t rc=\$?\" ;;
esac; done >> /out/rust-txm.txt 2>&1; echo rust shape \$t m \$m k $K done"
