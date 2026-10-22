#!/bin/sh
# One driver for every parameter set (owner 2026-10-21: one input file per set, one generic generator / driver):
#   pqz-core/params/sets/make.sh <set> <step> [step ...]     or     make.sh <set> all
# Steps (each runnable alone; `all` runs them in this order and stops at the first failing step, printing its name and
# log; a step the set does not have is printed as "skipped (reason)"):
#   specs   gen_set.py <set>: the 14 LaZer codegen specs, pqz_set.h, rust/set.rs, set.json, PqzSet.sol, the crates'
#           per-set feature lists                                                       (stdlib, seconds)
#   e_s1    lattice-estimator check of every spec (pqzl/params/n-study/e_s1_n.sage, pinned Sage image): MSIS beta,
#           hiding MLWE uSVP and dual_hybrid >= 450 -> <set>/e-s1.txt; then every spec's pqz_delta / kmlwe_min must
#           be set.toml's: if not (or missing), stop and print the values to put into set.toml   (heavy, capped)
#   codegen LaZer 3330e48 codegen of the 14 specs -> <set>/pqz_<rel>_params.h, <set>/codegen.txt; a set with
#           `frozen = true` (the v3 set) is regenerated into <set>/.codegen/ and compared byte for byte (capped)
#   rust    pqzl/params/to_rust.py <set>: the headers' Rust form <set>/rust/<rel>.rs and the crate's params/mod.rs
#   e_s0    e_s0_set.py: the set's budget checks, exactness of the norm proofs per relation, FS rounds -> <set>/e-s0.txt
#   kat     the upstream LaZer golden arithmetic KAT at the set's q (pqzl/kat/build-lazer-dump.sh, docker, x86-64-v3)
#           -> <set>/lazer-3330e48-kat.json (+ -build.txt), then pqz-core = upstream (pqzl/kat/check.py)
#   fixtures the cheating fixtures the Rust suite reads (pqzl/rust/tests/fixtures/cheating/export.sh -> <set>/)  (capped)
#   vectors pqz-ffi/vectors/run.sh write (PQZ_SET=<set>): smartcontracts/vectors/pqz[/<set>]   (not for core_only)
#   sol     <set>/PqzSet.sol -> smartcontracts/evm/src/pqz/PqzSet.sol, forge build of that file   (not for core_only)
#   gate    PQZ_SET=<set> pqz-core/gate.sh (run alone; label = the set, an interrupted gate resumes)
# Environment: PQZ_TOOLS = a directory with the pinned checkouts lk (leaky-LWE-Estimator 0a9caf8), le
# (lattice-estimator 53da598), lz (LaZer 3330e48) (e_s1, codegen); PQZ_WORK = a work directory for the KAT build
# (LaZer / HEXL clones, the static lazer_dump; never committed). Heavy steps run under scripts/capped (never wrap
# this script in timeout); docker containers carry their own --memory / --cpus. No timing is measured here.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
CORE=$(cd "$HERE/../.." && pwd)
REPO=$(cd "$CORE/.." && pwd)
CAP="$REPO/scripts/capped"
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
[ $# -ge 2 ] || { sed -n '2,24p' "$0"; exit 2; }
S=$1
shift
D=$HERE/$S
[ -f "$D/set.toml" ] || { echo "make.sh: no $D/set.toml" >&2; exit 2; }
RELS="reg tx tx0 burn ds dr txm2 txm20 txm4 txm40 txm8 txm80 txm16 txm160"
tomlget() { python3 -I -c "import tomllib, sys; t = tomllib.load(open(sys.argv[1], 'rb')); print(t.get(sys.argv[2], ''))" "$D/set.toml" "$1"; }
CORE_ONLY=$(tomlget core_only)
FROZEN=$(tomlget frozen)
tools() { [ -n "${PQZ_TOOLS:-}" ] && [ -d "$PQZ_TOOLS/$1" ] || { echo "PQZ_TOOLS must hold $1 (see the header)" >&2; return 1; }; }

step_specs() { python3 -I "$HERE/gen_set.py" "$S"; }

# e_s1: every spec through e_s1_n.sage, then the agreement with set.toml
step_e_s1() {
  tools lk && tools le && tools lz || return 1
  T=$(cd "$PQZ_TOOLS" && pwd)
  specs=$(for r in $RELS; do printf '/set/%s_params.sage ' "$r"; done)
  "$CAP" docker run --rm --network none --memory 5g --cpus 2 -e PYTHONPATH=/le -e LE_COMMIT=53da5982597709ba0fdf94ea37a84d822310fd84 \
    -e LK_COMMIT=0a9caf8bf0f80097724e0c6147194c52c6b90f86 -e PYTHONUNBUFFERED=1 -v "$T/le":/le:ro -v "$T/lz/third_party":/lz/third_party:ro \
    -v "$CORE/pqzl/params/n-study":/p:ro -v "$CORE/pqzl/params":/params:ro -v "$D":/set:ro --entrypoint /bin/sh "$IMG" -c \
    "mkdir -p /tmp/w && cp -r /params/codegen /tmp/w/ && ln -s /lz/third_party /tmp/w/third_party && cp /p/*.sage /tmp/w/ &&
     cd /tmp/w/codegen && sage /tmp/w/e_s1_n.sage $specs" > "$D/e-s1.txt" 2> "$D/.e-s1.err" || return 1
  rm -f "$D/.e-s1.err" # the estimator's stderr (kept only when the run fails)
  python3 -I - "$D" <<'EOF'
import os, re, sys, tomllib
d = sys.argv[1]
t = tomllib.load(open(os.path.join(d, "set.toml"), "rb"))
got = re.findall(r"^=> \S*?(\w+)_params\.sage: pqz_delta = ([\d.]+), kmlwe_min = (\d+)", open(os.path.join(d, "e-s1.txt")).read(), re.M)
deltas, kmlwes = {float(x[1]) for x in got}, {int(x[2]) for x in got}
if len(got) != 14:
    sys.exit(f"e_s1: {len(got)} of 14 specs have a result line (see e-s1.txt)")
want = (min(deltas), max(kmlwes))  # one set-wide value: the smallest pqz_delta and the largest rank any spec needs
if (t.get("pqz_delta"), t.get("kmlwe_min")) != want:
    sys.exit(f"e_s1: set.toml must say pqz_delta = {want[0]}, kmlwe_min = {want[1]} (per spec: {got}); "
             "edit set.toml, then rerun from specs")
print(f"e_s1: every spec meets beta >= 450 at set.toml's pqz_delta {want[0]}, kmlwe_min {want[1]}")
EOF
}

# codegen: LaZer's codegen per spec (as the earlier per-set regen.sh, now set-generic)
step_codegen() {
  tools lz || return 1
  LZ=$(cd "$PQZ_TOOLS/lz" && pwd)
  [ "$(git -C "$LZ" rev-parse HEAD)" = 3330e487228f633eceb322807b13a596b516770f ] || { echo "LaZer must be at 3330e48" >&2; return 1; }
  O=$D; [ "$FROZEN" = True ] && { O=$D/.codegen; mkdir -p "$O"; }
  rc=0
  { echo "LaZer $(git -C "$LZ" rev-parse HEAD); image $IMG; set $S"
    for r in $RELS; do
      "$CAP" docker run --rm --network none --memory 2g --cpus 1 -v "$LZ/third_party":/lz/third_party:ro \
        -v "$CORE/pqzl/params/codegen":/lz/codegen:ro -v "$D/${r}_params.sage":/lz/params.sage:ro --entrypoint /bin/sh "$IMG" -c \
        'mkdir -p /tmp/w && cp -r /lz/codegen /tmp/w/ && ln -s /lz/third_party /tmp/w/third_party && cd /tmp/w/codegen && sage lnp-tbox-codegen.sage /lz/params.sage' \
        > "$O/pqz_${r}_params.h" 2> "$O/$r.err" || rc=1
      echo "== $r: $(wc -c < "$O/pqz_${r}_params.h") B, sha256 $(sha256sum < "$O/pqz_${r}_params.h" | cut -c1-16)"
      sed -n -e '3,5p' -e '/^\/\/ Proof size/{n;p}' "$O/pqz_${r}_params.h" | sed 's/^/   /'
      grep -v 'rop: ' "$O/$r.err" | sed 's/^/   stderr: /' | head -20
      rm -f "$O/$r.err"
      if [ "$FROZEN" = True ]; then
        if cmp -s "$O/pqz_${r}_params.h" "$D/pqz_${r}_params.h"; then echo "   identical to the frozen header"; else echo "   DIFFERENT from the frozen header"; rc=1; fi
      fi
    done
    echo "codegen rc=$rc"
  } > "$O/codegen.txt" 2>&1
  [ "$FROZEN" = True ] && { cp "$O/codegen.txt" "$D/codegen-check.txt"; rm -rf "$O"; }
  return $rc
}

step_rust() { python3 -I "$CORE/pqzl/params/to_rust.py" "$S"; }

step_e_s0() { SET=$S "$CAP" "$HERE/run_e_s0_set.sh" > "$D/e-s0.txt" && grep -q "GATE .*: MET" "$D/e-s0.txt"; }

step_kat() {
  [ -n "${PQZ_WORK:-}" ] || { echo "PQZ_WORK: a work directory for the KAT build" >&2; return 1; }
  W=$PQZ_WORK/lazer-kat-$S
  PQZ_SET=$S "$CAP" "$CORE/pqzl/kat/build-lazer-dump.sh" "$W" v3 > "$W.log" 2>&1 || { echo "see $W.log" >&2; return 1; }
  "$W/lazer_dump-v3" > "$D/lazer-3330e48-kat.json" && cp "$W/build-info-v3.txt" "$D/lazer-3330e48-kat-build.txt" &&
    (cd "$CORE/pqzl" && PQZ_SET=$S "$CAP" sh -c './build.sh native && build/native/kat_dump > build/native/kat-pqz.json' &&
     python3 -I kat/check.py "$D/lazer-3330e48-kat.json" build/native/kat-pqz.json)
}

step_fixtures() { PQZ_SET=$S "$CAP" "$CORE/pqzl/rust/tests/fixtures/cheating/export.sh"; }

step_vectors() {
  [ "$CORE_ONLY" = True ] && { echo "skipped (core_only set: no pqz-stmt / precompile vectors)"; return 0; }
  PQZ_SET=$S "$CAP" "$CORE/ffi/vectors/run.sh" "$S-$(date -u +%Y%m%d)" write
}

step_sol() {
  [ "$CORE_ONLY" = True ] && { echo "skipped (core_only set: no contracts)"; return 0; }
  cp "$D/PqzSet.sol" "$REPO/smartcontracts/evm/src/pqz/PqzSet.sol" &&
    (cd "$REPO/smartcontracts/evm" && "$CAP" forge build --contracts src/pqz/PqzSet.sol)
}

step_gate() { PQZ_SET=$S "$CAP" "$CORE/gate.sh"; }

[ "$1" = all ] && set -- specs e_s1 codegen rust e_s0 kat fixtures vectors sol gate
for st in "$@"; do
  case $st in specs | e_s1 | codegen | rust | e_s0 | kat | fixtures | vectors | sol | gate) ;; *) echo "make.sh: unknown step $st" >&2; exit 2 ;; esac
  echo "== $S: $st"
  if ! "step_$st"; then
    echo "make.sh $S: step $st FAILED (logs: $D/, pqz-core/runs/gate/, pqz-core/ffi/vectors/runs/)"
    exit 1
  fi
done
echo "make.sh $S: $* done"
