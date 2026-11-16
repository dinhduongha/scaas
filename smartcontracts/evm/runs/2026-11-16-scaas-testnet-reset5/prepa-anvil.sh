#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Reset 5 prep A (owner 2026-11-15, NET-EVM-11 Change): deploy.sh evm's batches on a throwaway anvil, three cases, each on a
# fresh anvil: (good) the whole deploy in batches of 16, one send line per transaction, a batch line per batch; (fee)
# MAX_FEE_GWEI below the chain's fee: the named stop FEE_OVER_MAX before anything is sent (nonce 0); (stop) automine off
# after batch 1, receipt timeout 20 s, batch bound 60 s: batch 2 fails by name, no batch 3 sent; (sets) the two deploy sets
# (owner 2026-11-16): DEPLOY_SET refusals before any send, then mldsa-on and mldsa-off on one chain, the book holding both. From smartcontracts/evm, under scripts/capped:
#   ../../scripts/capped bash runs/2026-11-16-scaas-testnet-reset5/prepa-anvil.sh [good|fee|stop|sets ...]
# Output: short lines; each case's deploy.sh output in prepa-<case>.log beside this file (git-ignored).
set -u
command -v anvil > /dev/null || PATH=$HOME/.foundry/bin:$PATH
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-18651} RPC=http://127.0.0.1:${PORT:-18651}
D0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80  # anvil's well-known dev key 0
S=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
A=
trap '[ -z "$A" ] || kill "$A" 2> /dev/null' EXIT
up() {
  anvil --chain-id 31337 --hardfork amsterdam --gas-limit 200000000 --code-size-limit 131072 --port "$PORT" > /dev/null 2>&1 &
  A=$!
  for i in $(seq 60); do cast chain-id --rpc-url "$RPC" > /dev/null 2>&1 && return 0; sleep 1; done
  echo "[prepa] FAIL anvil did not start"; exit 1
}
down() { kill "$A" 2> /dev/null; wait "$A" 2> /dev/null; A=; }
dep() {  # the matrix's local deploy (matrix.sh), deploy.sh's lines to stdout
  env PRIVATE_KEY=$D0 DEPLOY_NAME=local-31337-testnet FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy \
    RELEASE_GAS_GATE=public CHAIN_CODE_LIMIT=131072 RELEASES_WRITE=true RELEASES_JSON=deployments/local-31337-testnet-releases.json \
    DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 DEPLOY_ZETHER=1 DEPLOY_PQCHAT=1 NOTICE_PERIOD=0 DEMO_SUPPLY=1000000000000 VERIFY_TARGET=local \
    DEPLOY_SALT="$(cast keccak scaas.deploy.prepa)" COMPLIANCE_ADMIN=0x0000000000000000000000004e59b44847b379578588920ca78fbf26c0b4956c \
    DEPLOY_LOG="$HERE/prepa-$1-forge.log" "${@:2}" ../scripts/deploy.sh evm "$RPC"
}
bad=0
for c in "${@:-good fee stop}"; do for c in $c; do
  up; L=$HERE/prepa-$c.log; : > "$L"
  case $c in
  good)
    dep good > "$L" 2>&1; rc=$?
    n=$(grep -c '^\[deploy\] send ' "$L"); b=$(grep -c '^\[deploy\] batch .* ok' "$L")
    t=$(sed -n 's/^\[deploy\] ok \([0-9]*\) txs.*/\1/p' "$L"); nn=$(cast nonce --rpc-url "$RPC" $S)
    p=$(python3 -I -c 'import json; print(len(json.load(open("broadcast/Deploy.s.sol/31337/dry-run/send-plan.json"))["to"]))')
    ok=$([ "$rc" = 0 ] && [ "$n" = "$p" ] && [ "$t" = "$p" ] && [ "$b" = $(((p + 15) / 16)) ] && [ "$nn" -ge "$p" ] && echo ok || echo FAIL)
    echo "[prepa] good $ok: rc $rc, plan $p, send lines $n, batches $b, ok line $t txs, deployer nonce $nn" ;;
  fee)
    dep fee MAX_FEE_GWEI=0.000000001 > "$L" 2>&1; rc=$?
    nn=$(cast nonce --rpc-url "$RPC" $S); f=$(grep -c 'FEE_OVER_MAX' "$L")
    ok=$([ "$rc" != 0 ] && [ "$f" -ge 1 ] && [ "$nn" = 0 ] && ! grep -q '^\[deploy\] send ' "$L" && echo ok || echo FAIL)
    echo "[prepa] fee $ok: rc $rc, FEE_OVER_MAX lines $f, deployer nonce $nn ($(grep -m1 FEE_OVER_MAX "$L" | cut -c1-120))" ;;
  stop)
    # automine off as soon as batch 1 is reported: batch 2's receipts never come, forge times out
    dep stop DEPLOY_TX_TIMEOUT=20 DEPLOY_BATCH_LIMIT=60 2>&1 | while IFS= read -r l; do
      printf '%s\n' "$l" >> "$L"
      case $l in "[deploy] batch 1/"*" ok"*) cast rpc --rpc-url "$RPC" evm_setAutomine false > /dev/null ;; esac
    done
    rc=$(grep -c '^\[deploy\] FAIL' "$L"); nn=$(cast nonce --rpc-url "$RPC" $S); np=$(cast nonce --block pending --rpc-url "$RPC" $S)
    b1=$(grep -c '^\[deploy\] batch 1/.* ok' "$L"); b2=$(grep -c '^\[deploy\] batch 2/.* ok' "$L"); s=$(grep -c '^\[deploy\] send ' "$L")
    ok=$([ "$rc" -ge 1 ] && [ "$b1" = 1 ] && [ "$b2" = 0 ] && [ "$s" = 16 ] && [ "$np" -le 32 ] && echo ok || echo FAIL)
    echo "[prepa] stop $ok: FAIL lines $rc ($(grep -m1 '^\[deploy\] FAIL' "$L" | cut -c1-140)), send lines $s, nonce $nn, pending $np" ;;
  sets)
    # deploy sets (owner 2026-11-16, "ok, option 2, one chain, two deploy sets"): two refusals before anything is sent,
    # then mldsa-on and mldsa-off on one chain, each its own salt and releases book; the book holds both, mldsa-off on top
    rm -f deployments/local-31337-testnet.json deployments/local-31337-testnet-releases.json deployments/local-31337-testnet-mldsa-on-releases.json
    dep sets-x DEPLOY_SET=mldsa-x > "$L" 2>&1; r1=$?
    dep sets-m DEPLOY_SET=mldsa-off >> "$L" 2>&1; r2=$?
    n0=$(cast nonce --rpc-url "$RPC" $S)
    dep sets-on DEPLOY_SET=mldsa-on MLDSA_PRECOMPILE=on DEPLOY_SALT="$(cast keccak scaas.deploy.prepa.on)" \
      RELEASES_JSON=deployments/local-31337-testnet-mldsa-on-releases.json >> "$L" 2>&1; r3=$?
    dep sets-off DEPLOY_SET=mldsa-off MLDSA_PRECOMPILE=off DEPLOY_SALT="$(cast keccak scaas.deploy.prepa.off)" >> "$L" 2>&1; r4=$?
    b=$(python3 -I -c 'import json
b = json.load(open("deployments/local-31337-testnet.json")); s = b["sets"]
ok = (sorted(s) == ["mldsa-off", "mldsa-on"] and b["default_set"] == "mldsa-off" and b["ua_registry"] == s["mldsa-off"]["ua_registry"]
      and s["mldsa-on"]["ua_registry"] != s["mldsa-off"]["ua_registry"] and s["mldsa-on"]["token_factory"] != s["mldsa-off"]["token_factory"]
      and s["mldsa-on"]["releases_json"].endswith("mldsa-on-releases.json") and s["mldsa-off"]["mldsa_precompile"] == "off")
print("book ok" if ok else "book BAD", s["mldsa-on"]["ua_registry"], s["mldsa-off"]["ua_registry"])' 2>&1)
    ok=$([ "$r1" != 0 ] && [ "$r2" != 0 ] && [ "$n0" = 0 ] && grep -q DEPLOY_SET_UNKNOWN "$L" && grep -q DEPLOY_SET_MISMATCH "$L" \
      && [ "$r3" = 0 ] && [ "$r4" = 0 ] && case $b in "book ok"*) true ;; *) false ;; esac && echo ok || echo FAIL)
    echo "[prepa] sets $ok: refusals rc $r1 / $r2 (nonce $n0), mldsa-on rc $r3, mldsa-off rc $r4, $b" ;;
  esac
  [ "$ok" = ok ] || bad=1
  down
done; done
exit $bad
