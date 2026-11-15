#!/bin/sh
# Constant-time check of the prover under valgrind memcheck (ctgrind; review fix E), C core and Rust crate. Run under
# scripts/capped:
#   scripts/capped pqz-core/pqzl/test/ct.sh <label> [rels] [nprove] [keys]   -> test/runs/ct-<label>.txt
# rels: pqz_bench's bit mask (default 1 = R_REG; 63 = the six base relations, 64 << t = R_TXM shape t); keys: rounds
# of KeyGen / Enc / Dec with the seeds, the digits and s secret (default 1). CT_ONLY=c or
# CT_ONLY=rust runs one side only. The C library objects are built with -DPQZ_CTGRIND (PQZ_CT_PUBLIC =
# VALGRIND_MAKE_MEM_DEFINED) at the production -O2; the Rust crate with the test-only feature ctgrind (release
# profile, x86-64). test/pqz_ct.c / rust/src/bin/ct.rs mark the witness and rnd32 undefined (secret) and prove;
# memcheck then reports every branch ("Conditional jump or move depends on uninitialised value(s)") or address ("Use
# of uninitialised value") that depends on them, after the declassification points (PQZ_CT_PUBLIC / ct::public: the
# verdicts and proof fields that are public by design; research/code-review-2026-10-19/E-constant-time.md).
# Exit 0: no report on either side and every proof verifies. Limits: only the paths the runs take, only the x86-64
# code (not wasm32), only branches and addresses (not variable-latency instructions such as a division, and not a
# cmov, which memcheck propagates instead of reporting).
# PQZ_SET (default n2304-kmax4096) / PQZ_BUILD_TAG as build.sh: the C side builds against the set's headers in
# build[/<tag>]/, the Rust side with the set's feature in target/<set>/ (gate.sh step ct, review 3w u1-1).
set -u
cd "$(dirname "$0")/.." # pqzl
L=${1:?label}
O=test/runs/ct-$L.txt
PQZ_SET=${PQZ_SET:-n2304-kmax4096}
B=build${PQZ_BUILD_TAG:+/$PQZ_BUILD_TAG}
if [ "$PQZ_SET" = n2304-kmax4096 ]; then RF="--features ctgrind"; else RF="--no-default-features --features sv,set-$PQZ_SET,ctgrind"; fi
RT=target/$PQZ_SET
mkdir -p test/runs $B/ct
VG="valgrind --tool=memcheck --error-limit=no --num-callers=12 --track-origins=no --max-stackframe=4000000"
count () { grep -c "Conditional jump or move depends\|Use of uninitialised value\|Syscall param" "$1"; }
fail=0
# the tree: HEAD and a hash of the uncommitted diff of this directory (empty diff: e3b0c442...)
echo "# ct $L: HEAD $(git rev-parse HEAD), diff sha256 $(git diff HEAD -- . | sha256sum | cut -c1-16), $(valgrind --version), set $PQZ_SET, rels ${2:-1}, nprove ${3:-1}, keys ${4:-1}" > "$O"
if [ "${CT_ONLY:-}" != rust ]; then
  B=$B ./build.sh native > /dev/null || exit 1 # lazer.h and the set's headers in $B/include
  CC=${CC:-clang}
  # build.sh's library flags (CFLAGS_LIB, -fPIC -fstack-protector-strong) plus -g and the client requests
  F="-std=gnu11 -O2 -g -fno-builtin -fno-math-errno -ffp-contract=off -fPIC -fstack-protector-strong -ffunction-sections -fdata-sections -w -DPQZ_SV -DPQZ_CTGRIND"
  F="$F -I$B/include -Isrc -Ilazer -Iparams"
  $CC --version | head -1 >> "$O"
  $CC $F -o $B/ct/pqz_ct src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c src/pqz_sv.c src/pqz_keys.c \
    test/pqz_ct.c >> "$O" 2>&1 || exit 1
  $VG --log-file=$B/ct/c.vg $B/ct/pqz_ct "${2:-1}" "${3:-1}" "${4:-1}" >> "$O" 2>&1
  rc=$?
  cat $B/ct/c.vg >> "$O"
  n=$(count $B/ct/c.vg)
  echo "ct $L C ($($CC --version | head -1)): rc=$rc secret-dependent reports=$n" | tee -a "$O"
  { [ $rc = 0 ] && [ "$n" = 0 ]; } || fail=1
fi
if [ "${CT_ONLY:-}" != c ]; then
  (cd rust && CARGO_TARGET_DIR=$RT cargo build -j2 --release --offline $RF --bin ct) >> "$O" 2>&1 || exit 1
  (cd rust && rustc --version) >> "$O" # rust-toolchain.toml's compiler
  $VG --log-file=$B/ct/rust.vg rust/$RT/release/ct "${2:-1}" "${3:-1}" "${4:-1}" >> "$O" 2>&1
  rc=$?
  cat $B/ct/rust.vg >> "$O"
  n=$(count $B/ct/rust.vg)
  echo "ct $L Rust ($(cd rust && rustc --version)): rc=$rc secret-dependent reports=$n" | tee -a "$O"
  { [ $rc = 0 ] && [ "$n" = 0 ]; } || fail=1
fi
exit $fail
