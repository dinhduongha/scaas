#!/bin/sh
# Constant-time check of the PQZH prover under valgrind memcheck (ctgrind; review P-B, the method of PQZL fix E,
# pqzl/test/ct.sh). Run under scripts/capped from the repository root:
#   scripts/capped pqz-core/pqzh/ligero/runs/ct.sh <label> [rels] [nprove] [set]   -> runs/ct-<label>.txt
# rels: src/bin/ct.rs's bit mask (default 4095: the six forms and the six op 7 shapes); nprove: proofs per relation
# (default 1); set: the parameter set (cargo feature set-<set>; default none = v3). The crate is built with the
# test-only feature ctgrind (release profile, x86-64); src/bin/ct.rs marks the witness and rnd32 undefined (secret) and proves at THE preset; memcheck then reports every branch ("Conditional jump
# or move depends on uninitialised value(s)") or address ("Use of uninitialised value") that depends on them, after the
# declassification points (ct::public / ct::verdict: the root, w, q, h, the opened columns, the witness-valid and
# self-check verdicts, the samplers' accept bits; research/code-review-2026-10-19/O-pqzh-constant-time.md).
# Exit 0: no report and every proof verifies. Limits: only the paths the runs take, only the x86-64 code (not wasm32),
# only branches and addresses (not variable-latency instructions such as a division, and not a cmov, which memcheck
# propagates instead of reporting).
set -u
cd "$(dirname "$0")/.." # pqzh/ligero
L=${1:?label}
O=runs/ct-$L.txt
mkdir -p target/ct
VG="valgrind --tool=memcheck --error-limit=no --num-callers=12 --track-origins=no --max-stackframe=4000000"
count () { grep -c "Conditional jump or move depends\|Use of uninitialised value\|Syscall param" "$1"; }
# the tree: HEAD and a hash of the uncommitted diff of this directory (empty diff: e3b0c442...)
echo "# ct $L: HEAD $(git rev-parse HEAD), diff sha256 $(git diff HEAD -- . | sha256sum | cut -c1-16), $(valgrind --version), rels ${2:-4095}, nprove ${3:-1}, set ${4:-v3}" > "$O"
cargo build -j2 --release --offline --features ctgrind${4:+,set-$4} --bin ct >> "$O" 2>&1 || exit 1
rustc --version >> "$O" # rust-toolchain.toml's compiler
$VG --log-file=target/ct/rust.vg target/release/ct "${2:-4095}" "${3:-1}" >> "$O" 2>&1
rc=$?
cat target/ct/rust.vg >> "$O"
n=$(count target/ct/rust.vg)
echo "ct $L: rc=$rc secret-dependent reports=$n" | tee -a "$O"
[ $rc = 0 ] && [ "$n" = 0 ]
