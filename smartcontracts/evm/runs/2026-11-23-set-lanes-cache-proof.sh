#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# TODO 8g (4) cache proof (ARCH-POS-21): an incremental set lane builds the same bytecode as a clean one. In <set>'s lane,
# two compile sets: `src` (forge build src, out/) and `pqz` (src + test/pqz, the per-directory form of the scopes,
# out/t-pqz). Builds both (state A), changes src/common/MetaTxLib.sol in this work tree (MODE_FEE_SHIFT 4 -> 5, imported
# by 67 src files; restored byte-equal, sha256 checked, also on failure), builds both incrementally, keeps that out/,
# builds both again after --clean, then compares every artifact's init (bytecode) and runtime (deployedBytecode) byte for
# byte, incremental against clean. Prints one summary row per compile set. Run nothing else in this work tree meanwhile.
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
LN=$EVM/script/pqz/lanes.sh
# <log name> [--clean]: both compile sets
both() {
    n=$1
    shift
    echo "[cache-proof] $S: $n"
    if ! "$LN" "$@" "$S" build src >"$T/$n-src.log" 2>&1 ||
        ! FOUNDRY_TEST=test/pqz FOUNDRY_SCRIPT=test/pqz FOUNDRY_OUT=out/t-pqz FOUNDRY_CACHE_PATH=cache/t-pqz \
            "$LN" "$S" build >"$T/$n-pqz.log" 2>&1; then
        tail -n 20 "$T/$n-src.log" "$T/$n-pqz.log" 2>/dev/null
        exit 1
    fi
}
both a
cp -a "$LANE/out" "$T/a"
sed -i 's/uint32 internal constant MODE_FEE_SHIFT = 4;/uint32 internal constant MODE_FEE_SHIFT = 5;/' "$F"
cmp -s "$F" "$T/orig.sol" && {
    echo "cache-proof: the edit did not apply" >&2
    exit 1
}
both incremental
cp -a "$LANE/out" "$T/inc"
both clean --clean
python3 -I - "$T/a" "$T/inc" "$LANE/out" "$S" "$(git -C "$EVM" rev-parse --short=9 HEAD)" <<'EOF'
import json, os, sys

def arts(d):
    r = {}
    for top, dirs, files in os.walk(d):
        if top == d:
            dirs[:] = [x for x in dirs if not x.startswith("t-") and x not in ("build-info", "t66b-legacy")]
        dirs[:] = [x for x in dirs if x != "build-info"]
        for f in files:
            if f.endswith(".json"):
                j = json.load(open(os.path.join(top, f)))
                if "bytecode" in j:
                    r[os.path.relpath(os.path.join(top, f), d)] = (j["bytecode"]["object"], j["deployedBytecode"]["object"])
    return r

bad = 0
for unit, sub in (("src", ""), ("pqz", "t-pqz")):
    a, inc, clean = (arts(os.path.join(p, sub)) for p in sys.argv[1:4])
    keys = sorted(set(inc) | set(clean))
    init_eq = sum(1 for k in keys if k in inc and k in clean and inc[k][0] == clean[k][0])
    run_eq = sum(1 for k in keys if k in inc and k in clean and inc[k][1] == clean[k][1])
    one_side = sum(1 for k in keys if (k in inc) != (k in clean))
    moved = sum(1 for k in keys if k in a and k in inc and a[k] != inc[k])
    code = sum(1 for k in keys if k in clean and clean[k][1] not in ("", "0x"))
    ok = len(keys) > 0 and init_eq == run_eq == len(keys) and one_side == 0 and moved > 0
    bad |= not ok
    print(f"cache-proof-{sys.argv[4]}-{unit} | {sys.argv[5]} | {0 if ok else 1} | {len(keys)} artifacts ({code} with runtime "
          f"code): init {init_eq}/{len(keys)} and runtime {run_eq}/{len(keys)} byte-identical, incremental vs --clean; "
          f"{one_side} on one side only; the MetaTxLib edit moved {moved} artifacts (A vs incremental)")
sys.exit(bad)
EOF
