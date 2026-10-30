#!/bin/sh
# fs3 Task 13 phase B3 (2026-10-31): the sequence that produced runs/fs3-t13-docker-multi/ (reproduce.sh --multi-bench
# of pqz-core-artifact:fs3-t13, split into steps of 2026-10-31-fs3-t13-multi-step.sh; same commands, sample sizes and
# file names as reproduce.sh's multi branch). Resumable: done steps are skipped. Clean start: docker volume rm fs3t13-src.
set -u
cd "$(dirname "$0")/../../.."
P=pqz-core/artifact/runs/2026-10-31-fs3-t13-multi-step.sh
C='--release --locked --offline'
scripts/capped $P init 'echo multi > /out/mode.txt'
# PQZL (research/pqzl-measure/txm-bench.sh): its builds, then its loop one shape (t = 0..9, m = 64 << t) and command
# group at a time (2026-10-31-fs3-t13-multi-cshape.sh; per output file the shapes stay in t order), then its "all" runs
E='cd pqzl && export PQZ_ARENA_MB=3072 B=build/ov OVERSIZE=1 R=/out/pqzl-txm;'
scripts/capped $P c-build-1 "$E ./build.sh native > \$R-build.txt 2>&1 && ./build.sh native-x86v3 >> \$R-build.txt 2>&1"
scripts/capped $P c-build-2 "$E ./build.sh wasm >> \$R-build.txt 2>&1 && SV=0 B=build/ov-nosv ./build.sh wasm >> \$R-build.txt 2>&1 && wc -c build/ov/wasm/pqz.wasm build/ov-nosv/wasm/pqz.wasm >> \$R-build.txt && for f in native-generic native-fast x86v3-fast wasm-fast wasm-generic wasm-nosv; do : > \$R-\$f.jsonl; done"
CS=pqz-core/artifact/runs/2026-10-31-fs3-t13-multi-cshape.sh
sh $CS 0 "1 2 3 4 5 6"; sh $CS 1 "1 2 3 4 5 6"; sh $CS 2 "1 2 3 4 5 6"
sh $CS 3 "2 3 4 6"; sh $CS 3 5; sh $CS 3 1; sh $CS 4 "2 3 4 6"; sh $CS 4 "5 1"
for t in 5 6; do sh $CS $t "2 3 4 6 5"; sh $CS $t 1; done
sh $CS 7 "2 3 4 6"; sh $CS 7 5; sh $CS 7 1; sh $CS 8 "2 3"; sh $CS 8 "4 6"; sh $CS 8 5; sh $CS 8 1; sh $CS 9 "1 2 3 4 5 6"
E='cd pqzl && export PQZ_ARENA_MB=3072; R=/out/pqzl-txm ALL=$((63 + 64 * 255));'
GATE=1 scripts/capped $P c-all-native "$E { build/ov/native/pqz_bench 1 1 \$ALL > \"\$R-all-native-generic.jsonl\" || echo \"all native generic rc=\$?\"; PQZ_VERIFY=fast build/ov/native/pqz_bench 1 1 \$ALL > \"\$R-all-native-fast.jsonl\" || echo \"all native fast rc=\$?\"; } >> /out/pqzl-txm.txt 2>&1"
GATE=1 scripts/capped $P c-all-wasm "$E { PQZ_WASM_FILE=build/ov/wasm/pqz.wasm node test/run_wasm.mjs 1 1 \$ALL > \"\$R-all-wasm-generic.jsonl\" || echo \"all wasm rc=\$?\"; PQZ_WASM_FILE=build/ov/wasm/pqz.wasm PQZ_VERIFY=fast node test/run_wasm.mjs 1 1 \$ALL > \"\$R-all-wasm-fast.jsonl\" || echo \"all wasm fast rc=\$?\"; PQZ_WASM_FILE=build/ov-nosv/wasm/pqz.wasm node test/run_wasm.mjs 1 0 \$ALL > \"\$R-all-wasm-nosv.jsonl\" || echo \"all wasm nosv rc=\$?\"; grep -h -e proof_bytes -e timing -e fails -e arena_resident_end \$R-*.jsonl; } >> /out/pqzl-txm.txt 2>&1; echo rc=0 >> /out/pqzl-txm.txt"
# PQZH (steps 5-8 of pqzh/ligero/runs/txm.sh)
scripts/capped $P h-build "cd pqzh/ligero && { cargo build $C --bin ligero_bench; echo rc=\$?; } > /out/pqzh-txm-build.txt 2>&1"
scripts/capped $P h-build-ov "cd pqzh/ligero && { cargo build $C --features oversize --bin ligero_bench --target-dir target/oversize; echo rc=\$?; } > /out/pqzh-txm-oversize-build.txt 2>&1"
scripts/capped $P h-build-wasm "cd pqzh/ligero/wasm && { cargo build $C --target wasm32-unknown-unknown; echo rc=\$?; } > /out/pqzh-txm-wasm-build.txt 2>&1"
scripts/capped $P h-build-ov-wasm "cd pqzh/ligero/wasm && { cargo build $C --target wasm32-unknown-unknown --features oversize --target-dir target/oversize; echo rc=\$?; } > /out/pqzh-txm-oversize-wasm-build.txt 2>&1"
GATE=1 scripts/capped $P h-native "cd pqzh/ligero && { target/release/ligero_bench --rel txm --regime proven --r431 1 --np 10 --nv 1000 --nadv 80; echo rc=\$?; } > /out/pqzh-txm-native.jsonl 2>&1"
GATE=1 scripts/capped $P h-oversize "cd pqzh/ligero && { target/oversize/release/ligero_bench --rel txm --regime proven --r431 1 --np 3 --nv 100 --nadv 10; echo rc=\$?; } > /out/pqzh-txm-oversize.jsonl 2>&1"
GATE=1 scripts/capped $P h-wasm "cd pqzh/ligero && { node wasm/run_wasm.mjs 2 1000 4 1 1 txm; echo rc=\$?; } > /out/pqzh-txm-wasm.jsonl 2>&1"
GATE=1 scripts/capped $P h-oversize-wasm "cd pqzh/ligero && { env PQZH_WASM_FILE=wasm/target/oversize/wasm32-unknown-unknown/release/pqzh_ligero_wasm.wasm node wasm/run_wasm.mjs 2 100 4 1 1 txm; echo rc=\$?; } > /out/pqzh-txm-oversize-wasm.jsonl 2>&1"
# Rust core (port plan Task 12 step of reproduce.sh): builds, then one shape and command group at a time
scripts/capped $P r-build "cd pqzl/rust && RO=target/oversize && { sh -c \"cargo build $C --features bench,oversize --bin bench --target-dir \$RO && cd wasm && cargo build $C --target wasm32-unknown-unknown --features pqzl/oversize,pqzl/wasm-m8 --target-dir \$RO\"; echo rc=\$?; } > /out/rust-txm-build.txt 2>&1"
RS=pqz-core/artifact/runs/2026-10-31-fs3-t13-multi-rshape.sh
for t in 0 1 2; do sh $RS $t "2 4 3 1"; done; sh $RS 3 "2 4 3"; sh $RS 3 1
for t in 4 5 6; do sh $RS $t "2 4 3 1"; done; sh $RS 7 "2 4 3"; sh $RS 7 1; sh $RS 8 "2 4"; sh $RS 8 "3 1"; sh $RS 9 "2 4 3 1"
echo rc=0 >> pqz-core/artifact/runs/fs3-t13-docker-multi/rust-txm.txt
scripts/capped $P table 'python3 -I artifact/results.py multi /out | tee /out/summary.txt'
