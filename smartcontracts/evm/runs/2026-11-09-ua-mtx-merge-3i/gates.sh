#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group 3i (service pull, plan T77-T79) gate steps, one at a time, from the repository root:
#   sh smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-3i/gates.sh <step> [<step> ...]
# Each step logs to smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-3i-<step>.log (git-ignored) and ends it with `rc=<n>`; a
# step whose log ends with `rc=0` is skipped (RERUN=1 runs it again). Heavy commands go through scripts/capped, foreground.
# The committed summary is summary.txt in this directory (`step | commit | rc | counts`).
set -u
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$ROOT"
EVM=smartcontracts/evm
export PATH="$HOME/.foundry/bin:$PATH" # at-set.sh calls `forge` by name
SETS="n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536"

step() {
  case $1 in
    t77-forge-metatx) scripts/capped sh $EVM/runs/2026-11-08-ua-mtx-merge-t66a/forge-dirs.sh 3i test/metatx ;;
    t77-forge-top) scripts/capped sh $EVM/runs/2026-11-08-ua-mtx-merge-t66a/forge-dirs.sh 3i top ;;
    t77-lint) # ExpectRevertLint scans every test's source (the new ones too); the other top-level files do not read them
      (cd $EVM && FOUNDRY_SPARSE_MODE=true FOUNDRY_OUT=out/sp3i-lint FOUNDRY_CACHE_PATH=cache/sp3i-lint \
        ../../scripts/capped ~/.foundry/bin/forge test -j 2 --match-path test/ExpectRevertLint.t.sol) ;;
    t77-kinds-*) # the kinds file at one PQZ set; at-set.sh restores src/pqz/PqzSet.sol (checked after)
      FOUNDRY_SPARSE_MODE=true scripts/capped $EVM/script/pqz/at-set.sh "${1#t77-kinds-}" test -j 2 \
        --match-path test/metatx/ServicePullKinds.t.sol; r=$?
      git diff --exit-code -- $EVM/src/pqz/PqzSet.sol || r=3
      return $r ;;
    t77-no-src-change) git diff --exit-code HEAD -- $EVM/src $EVM/size-baseline.json $EVM/test/v2/layout && git status --short -- $EVM/src ;;
    t78-gen-check) python3 -I smartcontracts/vectors/metatx/gen_servicepull.py --check &&
      python3 -I smartcontracts/vectors/metatx/gen_servicepull.py --check ;;
    t78-forge-vectors) (cd $EVM && FOUNDRY_SPARSE_MODE=true FOUNDRY_OUT=out/sp3i FOUNDRY_CACHE_PATH=cache/sp3i \
      ../../scripts/capped ~/.foundry/bin/forge test -j 2 --match-path test/metatx/ServicePullVectors.t.sol) ;;
    t78-tamper) # one byte of row 0's entryRef flipped in a copy: the cross-check must go red
      tf=smartcontracts/vectors/metatx/servicepull.tamper.json
      python3 -c "import json,sys;d=json.load(open(sys.argv[1]));r=d['rows'][0];e=r['entryRef'];r['entryRef']=e[:-1]+('0' if e[-1]!='0' else '1');json.dump(d,open(sys.argv[2],'w'))" \
        smartcontracts/vectors/metatx/servicepull.json $tf
      (cd $EVM && SERVICEPULL_FILE=../vectors/metatx/servicepull.tamper.json FOUNDRY_SPARSE_MODE=true FOUNDRY_OUT=out/sp3i \
        FOUNDRY_CACHE_PATH=cache/sp3i ../../scripts/capped ~/.foundry/bin/forge test -j 2 --match-path test/metatx/ServicePullVectors.t.sol)
      r=$?; rm -f $tf
      [ $r -ne 0 ] ;;
    t78-red-first) # the clientkeys builder before T78: HEAD's evm.js has no buildServicePull
      d=$(mktemp -d); git show HEAD:clients/clientkeys/src/evm.js > "$d/evm.js"; git show HEAD:clients/clientkeys/src/bytes.js > "$d/bytes.js"
      ln -s "$ROOT/clients/clientkeys/node_modules" "$d/node_modules"
      echo '{"type":"module"}' > "$d/package.json"
      node --input-type=module -e "import('$d/evm.js').then(m => { if (typeof m.buildServicePull === 'function') process.exit(0); console.log('red: no buildServicePull'); process.exit(1); })"
      r=$?; rm -rf "$d"; [ $r -ne 0 ] ;;
    t78-clientkeys) (cd clients/clientkeys && ../../scripts/capped npm test) ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

for s in "$@"; do
  log=$EVM/runs/2026-11-09-ua-mtx-merge-3i-$s.log
  if [ "${RERUN:-0}" != 1 ] && [ -f "$log" ] && tail -1 "$log" | grep -qx 'rc=0'; then echo "$s: done"; continue; fi
  { step "$s"; echo "rc=$?"; } > "$log" 2>&1
  echo "$s: $(tail -1 "$log")"
done
