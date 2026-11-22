#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# TODO 8g (4) cache proof (ARCH-POS-20): an incremental set lane builds the same bytecode as a clean one. Builds the lane
# of <set> (state A), changes src/common/MetaTxLib.sol in this work tree (MODE_FEE_SHIFT 4 -> 5, imported by 67 src
# files; restored byte-equal, sha256 checked, also on failure), builds the lane incrementally, keeps that out/, builds
# the lane again with --clean, then compares every artifact's init (bytecode) and runtime (deployedBytecode) byte for
# byte. Prints one summary row. Do not run anything else in this work tree meanwhile (it edits a source file).
#   sh smartcontracts/evm/runs/2026-11-23-set-lanes-cache-proof.sh <set>
set -eu
S=${1:?set}
EVM=$(cd "$(dirname "$0")/.." && pwd)
LANE=${LANES_DIR:-$EVM/../../scratchpad/lanes}/$S/smartcontracts/evm
F=$EVM/src/common/MetaTxLib.sol
T=$(mktemp -d)
cp -p "$F" "$T/orig.sol"
H=$(sha256sum <"$F")
trap 'cp -p "$T/orig.sol" "$F"; [ "$(sha256sum <"$F")" = "$H" ] || echo "cache-proof: RESTORE FAILED for $F" >&2; rm -rf "$T"' EXIT
trap 'exit 130' HUP INT TERM
LANES=$EVM/script/pqz/lanes.sh
echo "[cache-proof] $S: build A"
"$LANES" "$S" build >"$T/a.log" 2>&1 || {
    tail -n 20 "$T/a.log"
    exit 1
}
cp -a "$LANE/out" "$T/a"
sed -i 's/uint32 internal constant MODE_FEE_SHIFT = 4;/uint32 internal constant MODE_FEE_SHIFT = 5;/' "$F"
cmp -s "$F" "$T/orig.sol" && {
    echo "cache-proof: the edit did not apply" >&2
    exit 1
}
echo "[cache-proof] $S: incremental build after the edit"
"$LANES" "$S" build >"$T/inc.log" 2>&1 || {
    tail -n 20 "$T/inc.log"
    exit 1
}
cp -a "$LANE/out" "$T/inc"
echo "[cache-proof] $S: clean build (--clean)"
"$LANES" --clean "$S" build >"$T/clean.log" 2>&1 || {
    tail -n 20 "$T/clean.log"
    exit 1
}
python3 -I - "$T/a" "$T/inc" "$LANE/out" "$S" "$(git -C "$EVM" rev-parse --short=9 HEAD)" <<'EOF'
import json, os, sys

def arts(d):
    r = {}
    for top, dirs, files in os.walk(d):
        rel = os.path.relpath(top, d)
        if rel.split(os.sep)[0] in ("build-info", "t66b-legacy"):
            continue
        for f in files:
            if f.endswith(".json"):
                j = json.load(open(os.path.join(top, f)))
                if "bytecode" in j:
                    r[os.path.join(rel, f)] = (j["bytecode"]["object"], j["deployedBytecode"]["object"])
    return r

a, inc, clean = (arts(p) for p in sys.argv[1:4])
keys = sorted(set(inc) | set(clean))
init_eq = sum(1 for k in keys if k in inc and k in clean and inc[k][0] == clean[k][0])
run_eq = sum(1 for k in keys if k in inc and k in clean and inc[k][1] == clean[k][1])
one_side = sum(1 for k in keys if (k in inc) != (k in clean))
moved = sum(1 for k in keys if k in a and k in inc and a[k] != inc[k])
code = sum(1 for k in keys if k in clean and clean[k][0] not in ("", "0x"))
ok = init_eq == run_eq == len(keys) and one_side == 0 and moved > 0
print(f"cache-proof-{sys.argv[4]} | {sys.argv[5]} | {0 if ok else 1} | {len(keys)} artifacts ({code} with code): init {init_eq}/{len(keys)} "
      f"and runtime {run_eq}/{len(keys)} byte-identical incremental vs --clean, {one_side} on one side only; "
      f"the MetaTxLib edit moved {moved} artifacts' bytecode (A vs incremental)")
sys.exit(0 if ok else 1)
EOF
