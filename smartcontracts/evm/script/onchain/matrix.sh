#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b Step 5b: the whole on-chain matrix, target by target; each target self-contained (nothing read from another
# target's run). From smartcontracts/evm, in the foreground, outside scripts/capped: a local target runs wholly under it;
# a remote one compiles under it, then broadcasts under a MATRIX_REMOTE_MEM (1G) scope (README.md has the commands):
#   matrix.sh <target> [<target> …]   each target in turn in its own process (its env, temp dir, anvil / copy, teardown);
#                                     one that fails does not stop the next; a summary table (target | group | result)
#                                     at the end, non-zero if any target failed
#   matrix.sh local           a fresh anvil (chain 31337, Amsterdam, 200 M gas, 128 KiB code) on $PORT, deploy.sh on it
#                             (DEPLOY_NAME=local-31337-testnet: its books deployments/local-31337-testnet*.json),
#                             every group, stopped after; the PQ groups on a fresh local Nethermind copy with the PQZ and
#                             ML-DSA precompiles: COPY=<git-ignored dir> (copy.sh init, genesis0, copygen.py, up; down
#                             after), or one already up at LOCAL_PQ_RPC; neither: listed as not run. Needs no other chain.
#   matrix.sh scaas-testnet   the SCaaS testnet RPC (RPC_7622), its Step 5 deploy deployments/scaas-testnet.json and
#                             scaas-testnet-t66b-releases.json
#   matrix.sh <name>          another testnet ([a-z0-9-]): ONCHAIN_RPC_<NAME> (upper case, - as _; ONCHAIN_RPC when it
#                             is the only named target); PRIVATE_KEY_<NAME> (its deployer) and ONCHAIN_K1_<NAME>..K3 (the
#                             plain names when it is the only named target), or else indices 0-3 of
#                             SCAAS_TESTNET_MNEMONIC_FILE; deploy.sh first if deployments/<key>.json is missing and
#                             MATRIX_DEPLOY=1
# Books by the chain's key (NET-EVM-13, script/deploybook.py: chain-uids.json by (chain id, genesis hash); a chain not in
# it needs DEPLOY_NAME), DEPLOY_JSON = deployments/<key>.json, RELEASES_JSON = deployments/<key>-releases.json; a book
# still named by chain id stops the target (BOOK_OLD_NAME: rename it).
# ONCHAIN_PQZ: precompile (the node answers OP_SELFTEST), offchain (only the OFFCHAIN group), off (no PQ group).
# MATRIX_GROUPS: the groups to run (default all). Outputs are named by target: records-<target>-<group>.jsonl,
# deployments/onchain-<target>-<group>.json. Stdout: one short line per event ([target] / [target/group] start, ok, FAIL,
# a heartbeat every 30 s; public ids only: chain id, addresses, tx hashes); every step's full output goes to the
# git-ignored runs/…/matrix-<target>.log. Never a key or a mnemonic.
set -eu
command -v anvil > /dev/null || PATH=$HOME/.foundry/bin:$PATH
if [ "${1:-}" != --one ]; then
  [ $# -ge 1 ] || { echo "usage: matrix.sh <local | scaas-testnet | name> [...]"; exit 2; }
  n=0
  for t; do case $t in local|scaas-testnet) ;; *) n=$((n + 1)) ;; esac; done
  MATRIX_SUMMARY=$(mktemp)
  export MATRIX_SUMMARY MATRIX_NAMED=$n
  trap 'rm -f "$MATRIX_SUMMARY"' EXIT INT TERM
  # local targets run wholly under scripts/capped; a remote one outside it (its compile under capped, its broadcasts
  # under a 1 G scope: owner 2026-11-10), so the driver itself runs outside capped (inside it, local targets still run)
  cg=$(cat "/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/memory.max" 2> /dev/null || echo max)
  rc=0
  for t; do
    if [ "$t" = local ]; then
      if [ "$cg" = max ]; then ../../scripts/capped sh "$0" --one "$t" || rc=1; else sh "$0" --one "$t" || rc=1; fi
    elif [ "$cg" != max ]; then
      echo "[$t] FAIL setup: a remote target runs outside scripts/capped (compile under capped, broadcasts under a 1 G scope): call matrix.sh directly"
      printf '%s | setup | fail\n' "$t" >> "$MATRIX_SUMMARY"
      rc=1
    else
      sh "$0" --one "$t" || rc=1
    fi
  done
  echo "## summary (exit $rc)"
  echo "target | group | result"
  cat "$MATRIX_SUMMARY"
  exit $rc
fi
tgt=${2:?target}
# this run's dir (MATRIX_OUT, default runs/<today>-matrix), never an earlier round's committed run note; every step
# writes there (run.sh, zether.sh, wraplimits.sh, pq.py, verifiers.py, coverage.py); the committed coverage list (coverage.py
# gen at the build) seeds it, and the run's table updates that copy
OUTD=${MATRIX_OUT:-runs/$(date +%Y-%m-%d)-matrix}
export MATRIX_OUT=$OUTD
mkdir -p "$OUTD"
[ -f "$OUTD/coverage.json" ] || cp runs/2026-11-10-ua-mtx-merge-t66b-step5b/coverage.json "$OUTD/coverage.json"
LOG=$OUTD/matrix-$tgt.log
GROUPS=${MATRIX_GROUPS:-tokens gov dex liquidity misc zether pq pqoff verifiers views wraplimits}
T=$(mktemp -d)
A= CP= P= STAGE=setup
CS=$(cd ../../pqz-core/nethermind/chain && pwd)
: > "$LOG"
say() { echo "[$tgt$1] $2"; }
row() { printf '%s | %s | %s\n' "$tgt" "$1" "$2" >> "${MATRIX_SUMMARY:-/dev/null}"; }
fail() { say "" "FAIL $STAGE: $1"; exit 1; }
trap 'r=$?; [ "$STAGE" = done ] || [ $r = 0 ] || row "$STAGE" fail; [ -z "$P" ] || kill "$P" 2> /dev/null
  if [ -n "$A" ]; then kill "$A" 2> /dev/null; say "" "anvil down"; fi
  if [ -n "$CP" ]; then sh "$CS/copy.sh" down >> "$LOG" 2>&1; say "" "copy down"; fi; rm -rf "$T"' EXIT
trap 'exit 1' INT TERM
# the transactions sent so far by the given accounts (their nonces): the heartbeat's count
ADDRS= PQ_ADDRS=
txs() { s=0; for a in $2; do s=$((s + $(cast nonce --rpc-url "$1" "$a" 2> /dev/null || echo 0))); done; echo $s; }
# step <label> <rpc> <accounts> <cmd…>: the command in the background, its output in $LOG, a heartbeat every 30 s;
# sets SECS and NTX (the accounts' transactions during the step)
step() {
  l=$1 sr=$2 sa=$3
  shift 3
  t0=$(date +%s) n0=$(txs "$sr" "$sa") i=0
  $SCOPE "$@" >> "$LOG" 2>&1 &
  P=$!
  while kill -0 "$P" 2> /dev/null; do
    sleep 1
    i=$((i + 1))
    [ $((i % 30)) != 0 ] || say "$l" "… ${sa:+$(($(txs "$sr" "$sa") - n0)) txs, }$(($(date +%s) - t0))s"
  done
  e=0
  wait "$P" || e=$?
  P=
  SECS=$(($(date +%s) - t0)) NTX=$(($(txs "$sr" "$sa") - n0))
  return $e
}
# a group's result from its records (txs status 1 / all, negatives refused as expected / all); on a failure the first
# failed entry and the last named error of the log
result() {
  python3 -I - "$OUTD" "$tgt" "$1" "$LOG" <<'PY'
import glob, json, os, re, sys
out, tgt, g, log = sys.argv[1:]
pat = f"records-{tgt}-{g}{'*' if g == 'zether' else ''}.jsonl"  # zether: its four scripts' records
r = [json.loads(x) for p in glob.glob(os.path.join(out, pat)) for x in open(p)]
t = [x for x in r if x.get("tx")]
n = [x for x in r if str(x.get("what", "")).startswith("negative")]
bad = [x for x in r if x.get("status") == 0]
c = [x for x in r if not x.get("tx") and x not in n]  # eth_calls (verifiers, views)
s = ", ".join(f"{k} {a}/{b}" for k, a, b in (("txs", sum(x["status"] == 1 for x in t), len(t)),
              ("calls", sum(x["status"] == 1 for x in c), len(c)), ("negatives", sum(x["status"] == 2 for x in n), len(n))) if b)
if bad or os.environ.get("MATRIX_FAILED"):
    err = [x.strip() for x in open(log, errors="replace") if re.search(r"Error|FAIL|BAD|revert", x)]
    s += f" | {bad[0].get('what', '')[:70] if bad else 'the step'}: {err[-1][:140] if err else 'no named error in the log'}"
print(s)
PY
}
# verify <after>: the verification step (verify.sh: every contract of the chain on its explorer, the completeness check)
# after a group of the SCaaS testnet, or as the group `verify`; one line per contract
verify() {
  if [ "$tgt" = local ]; then say "/verify" "local, not verified (no explorer)"; row "verify-$1" "local, not verified"; return 0; fi
  if [ "${VERIFY:-}" = none ]; then  # only an explicit VERIFY=none with its reason passes a remote target unverified
    say "/verify" "not verified: VERIFY=none (${VERIFY_REASON:?VERIFY=none needs VERIFY_REASON})"
    row "verify-$1" "not verified: VERIFY=none ($VERIFY_REASON)"
    return 0
  fi
  sc=$SCOPE SCOPE= n0=$(wc -l < "$LOG") ve=0
  step "/verify" "" "" env VERIFY_RPC="$RPC" sh script/onchain/verify.sh "$tgt" || ve=1
  SCOPE=$sc
  tail -n +$((n0 + 1)) "$LOG" | grep -E "^\[$tgt/verify\] " || true
  say "/verify" "after $1: $([ $ve = 0 ] && echo ok || echo FAIL) (${SECS}s)"
  row "verify-$1" "$([ $ve = 0 ] && echo ok || echo fail)"
  [ $ve = 0 ] || rc=1
}
# anvil's well-known dev keys (local only): 0 deploys, 1-3 sign
D0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
D1=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
D2=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
D3=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
case $tgt in
local)
  PORT=${PORT:-18620}
  anvil --chain-id 31337 --hardfork amsterdam --gas-limit 200000000 --code-size-limit 131072 --port "$PORT" \
    > "$T/anvil.log" 2>&1 &
  A=$!
  for i in $(seq 90); do
    cast chain-id --rpc-url "http://127.0.0.1:$PORT" > /dev/null 2>&1 && break
    [ "$i" -lt 90 ] || { cat "$T/anvil.log" >> "$LOG"; fail "anvil did not start"; }
    sleep 1
  done
  say "" "anvil up (chain 31337, port $PORT)"
  RPC=http://127.0.0.1:$PORT
  export ONCHAIN_K1=$D1 ONCHAIN_K2=$D2 ONCHAIN_K3=$D3 PRIVATE_KEY=$D0 DEPLOY_NAME=local-31337-testnet
  PQZ=${ONCHAIN_PQZ:-precompile}
  PQ_RPC=${LOCAL_PQ_RPC:-}
  if [ -z "$PQ_RPC" ] && [ -n "${COPY:-}" ] && [ "$PQZ" != off ]; then
    export COPY
    say "" "copy (Nethermind, PQZ and ML-DSA precompiles) …"
    { sh "$CS/copy.sh" init && sh "$CS/copy.sh" genesis0 "$CS/engine-pqz.json" && python3 -I script/onchain/copygen.py "$COPY" &&
      CP=1 && sh "$CS/copy.sh" up "${COPY_IMAGE:-scaas/nethermind-pqz:2.2.0-pqz7}" genesis.pqz0.json; } \
      >> "$LOG" 2>&1 || fail "the copy did not start (copy.sh, see the log)"
    PQ_RPC=http://10.76.22.10:8545  # the signer (docker-compose.copy.yml): no rate limit
    for i in $(seq 120); do
      [ "$(cast block-number --rpc-url "$PQ_RPC" 2> /dev/null || echo 0)" -ge 2 ] && break
      [ "$i" -lt 120 ] || fail "the copy produced no block"
      sleep 1
    done
    say "" "copy up (chain $(cast chain-id --rpc-url "$PQ_RPC"), $PQ_RPC)"
  fi
  MATRIX_DEPLOY=1 ;;
scaas-testnet)
  RPC=${RPC_7622:?the scaas-testnet target needs RPC_7622, named explicitly (no default)}
  # the genesis-funded test keys 0x…01-0x…03 (the PQ group's e2e takes them by number)
  ONCHAIN_K1=$(printf '0x%064x' 1) ONCHAIN_K2=$(printf '0x%064x' 2) ONCHAIN_K3=$(printf '0x%064x' 3)
  export ONCHAIN_K1 ONCHAIN_K2 ONCHAIN_K3 PRIVATE_KEY=$ONCHAIN_K1
  PQZ=${ONCHAIN_PQZ:-precompile}
  PQ_RPC=$RPC ;;
*)
  case $tgt in *[!a-z0-9-]*|'') fail "a target name is [a-z0-9-]" ;; esac
  N=$(echo "$tgt" | tr 'a-z-' 'A-Z_')
  only=$([ "${MATRIX_NAMED:-1}" = 1 ] && echo 1 || echo 0)
  eval "RPC=\${ONCHAIN_RPC_$N:-}"
  [ -n "$RPC" ] || [ "$only" = 0 ] || RPC=${ONCHAIN_RPC:-}
  [ -n "$RPC" ] || fail "no RPC (ONCHAIN_RPC_$N)"
  for v in PRIVATE_KEY ONCHAIN_K1 ONCHAIN_K2 ONCHAIN_K3; do  # the target's own keys; the plain ones only when alone
    eval "x=\${${v}_$N:-}"
    if [ -n "$x" ]; then eval "$v=\$x"; export "$v"; elif [ "$only" = 0 ]; then unset "$v"; fi
  done
  x=
  # keys not given: indices 0 (deployer) and 1-3 of the testnet-only mnemonic file (its `mnemonic:` line, or the whole
  # file), copied into the run's private temp dir for cast (the phrase never on a command line, never printed), each key
  # only in this process's environment
  if [ -z "${PRIVATE_KEY:-}" ] && [ -n "${SCAAS_TESTNET_MNEMONIC_FILE:-}" ]; then
    (umask 077; sed -n 's/^mnemonic:[[:space:]]*//p' "$SCAAS_TESTNET_MNEMONIC_FILE" > "$T/m")
    [ -s "$T/m" ] || (umask 077; grep -v '^#' "$SCAAS_TESTNET_MNEMONIC_FILE" > "$T/m")
    mk() { cast wallet private-key --mnemonic "$T/m" --mnemonic-index "$1"; }
    PRIVATE_KEY=$(mk 0) ONCHAIN_K1=$(mk 1) ONCHAIN_K2=$(mk 2) ONCHAIN_K3=$(mk 3)
    export PRIVATE_KEY ONCHAIN_K1 ONCHAIN_K2 ONCHAIN_K3
    rm -f "$T/m"
  fi
  [ -n "${PRIVATE_KEY:-}" ] && [ -n "${ONCHAIN_K1:-}" ] && [ -n "${ONCHAIN_K2:-}" ] && [ -n "${ONCHAIN_K3:-}" ] ||
    fail "no keys (PRIVATE_KEY_$N, ONCHAIN_K1_$N..K3, or SCAAS_TESTNET_MNEMONIC_FILE)"
  PQZ=${ONCHAIN_PQZ:-off}
  PQ_RPC=$RPC ;;
esac
CHAIN=$(cast chain-id --rpc-url "$RPC" 2>> "$LOG") || fail "the RPC does not answer"
G=$(cast block 0 --field hash --rpc-url "$RPC" 2>> "$LOG") || fail "the RPC gives no block 0"
# the target's books by its key (NET-EVM-13): DEPLOY_NAME_REQUIRED, BOOK_OLD_NAME, … stop it here
rs=-releases.json
[ "$tgt" != scaas-testnet ] || rs=-t66b-releases.json
DEPLOY_JSON=$(python3 -I script/deploybook.py path "$CHAIN" "$G" 2>&1) || fail "$DEPLOY_JSON"
RELEASES_JSON=$(python3 -I script/deploybook.py path "$CHAIN" "$G" "$rs" 2>&1) || fail "$RELEASES_JSON"
# a remote target: compile under scripts/capped first; then every broadcast step under a memory scope without a slot
# (MATRIX_REMOTE_MEM, default 1G, no swap), forge refusing any recompile there (run.sh, zether.sh: ONCHAIN_REMOTE)
SCOPE=
if [ "$tgt" != local ]; then
  SCOPE="systemd-run --user --scope --quiet -p MemoryMax=${MATRIX_REMOTE_MEM:-1G} -p MemorySwapMax=0 --"
  export ONCHAIN_REMOTE=1
fi
for k in "$PRIVATE_KEY" "$ONCHAIN_K1" "$ONCHAIN_K2" "$ONCHAIN_K3"; do ADDRS="$ADDRS $(cast wallet address --private-key "$k")"; done
ADDRS=$(printf '%s\n' $ADDRS | sort -u | tr '\n' ' ')  # the deployer may be a signer (the SCaaS testnet: key 1)
for k in 1 2 3; do PQ_ADDRS="$PQ_ADDRS $(cast wallet address --private-key "$(printf '0x%064x' "$k")")"; done
say "" "start (chain $CHAIN, PQZ $PQZ${PQ_RPC:+ on chain $(cast chain-id --rpc-url "$PQ_RPC" 2> /dev/null || echo '?')})"
say "" "deployer and signers:$ADDRS"
export ONCHAIN_RPC=$RPC DEPLOY_JSON RELEASES_JSON
if [ "${MATRIX_DEPLOY:-0}" = 1 ] && { [ "$tgt" = local ] || [ ! -f "$DEPLOY_JSON" ]; }; then
  STAGE=deploy
  if [ -n "$SCOPE" ]; then
    say "" "deploy: compile (scripts/capped) …"
    sc=$SCOPE SCOPE=
    step "" "" "" ../../scripts/capped env FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy forge build \
      script/Deploy.s.sol script/DeploySend.s.sol || fail "forge build of the deploy scripts"
    SCOPE=$sc
  fi
  say "" "deploy …"
  rm -f "$RELEASES_JSON"
  step "" "$RPC" "$ADDRS" env FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy RELEASE_GAS_GATE=public \
    CHAIN_CODE_LIMIT="${CHAIN_CODE_LIMIT:-131072}" RELEASES_WRITE=true \
    DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 DEPLOY_ZETHER=1 NOTICE_PERIOD=0 DEMO_SUPPLY=1000000000000 VERIFY_TARGET="$tgt" \
    DEPLOY_SALT="$(cast keccak "scaas.deploy.onchain.$tgt")" COMPLIANCE_ADMIN=0x0000000000000000000000004e59b44847b379578588920ca78fbf26c0b4956c \
    ../scripts/deploy.sh evm "$RPC" || fail "deploy.sh: $(grep -E 'Error|refus' "$LOG" | tail -1 | cut -c1-140)"
  say "" "deploy ok $NTX txs (${SECS}s): $DEPLOY_JSON"
fi
if [ "$tgt" = scaas-testnet ]; then NOTE=runs/2026-11-10-ua-mtx-merge-t66b-step5-7622.txt; export NOTE; fi
if [ -n "$SCOPE" ]; then
  STAGE=compile
  say "" "compile (scripts/capped) …"
  python3 -I script/onchain/zether_reg.py gen >> "$LOG" 2>&1
  sc=$SCOPE SCOPE=  # the compile steps run under capped, not under the scope
  for g in $GROUPS; do
    case $g in
    tokens|gov|dex|liquidity|misc)
      G=$(echo "$g" | sed 's/^./\U&/')
      step "/$g" "" "" ../../scripts/capped forge build "script/onchain/$G.s.sol" --out "out/onchain-$g" \
        --cache-path "cache/onchain-$g" || fail "forge build $G.s.sol"
      say "/$g" "compiled (${SECS}s)" ;;
    zether)
      step "/$g" "" "" ../../scripts/capped env FOUNDRY_OUT=out/onchain-zether FOUNDRY_CACHE_PATH=cache/onchain-zether \
        forge build script/ZetherE2E.s.sol script/onchain/ZetherMore.s.sol script/onchain/build/ZetherRegE2E.s.sol \
        script/onchain/build/ZetherRegMore.s.sol || fail "forge build of the Zether scripts"
      say "/$g" "compiled (${SECS}s)" ;;
    esac
  done
  SCOPE=$sc
  say "" "compile ok"
fi
python3 -I script/onchain/basebook.py "$tgt" >> "$LOG"
rc=0
STAGE=groups
for g in $GROUPS; do
  r=0 res=ok SECS=0 why=
  say "/$g" "start"
  case $g in
  tokens|gov|dex|liquidity|misc)
    G=$(echo "$g" | sed 's/^./\U&/')
    # forge's limit = its simulated gasUsed x m / 100 (README); tokens: x 2.00 (anvil undershot a CREATE by 19 % and a
    # kind-2 relay at x 1.30); misc: its SCaaSDex release and refund-heavy calls carry their own gas
    m=130 f=
    [ "$g" != tokens ] || { m=200; f=--ffi; }  # tokens: the ML-DSA-65 keys and signatures by node (vm.ffi)
    step "/$g" "$RPC" "$ADDRS" env ONCHAIN_GAS_MULTIPLIER="${ONCHAIN_GAS_MULTIPLIER:-$m}" \
      sh script/onchain/run.sh "$tgt" "$G" --tc "$G" $f || r=1 ;;
  zether)
    step "/$g" "$RPC" "$ADDRS" env NET="$tgt" RPC="$RPC" PRIVATE_KEY="$ONCHAIN_K1" sh script/onchain/zether.sh || r=1 ;;
  pq|pqoff)
    o=; [ $g = pq ] || o=--offchain
    if [ "$PQZ" = off ] || { [ "$PQZ" = offchain ] && [ $g = pq ]; } || [ -z "$PQ_RPC" ]; then
      res="not run"
    else
      # e2e.py's own book on the PQ node (NET-EVM-13): the local copy is its own chain, not the anvil
      dn=${DEPLOY_NAME:-}
      [ "$tgt" != local ] || dn=local-pq-testnet
      step "/$g" "$PQ_RPC" "$PQ_ADDRS" env EVM_OUT="${EVM_OUT:-out/t66b-e2e}" ${dn:+DEPLOY_NAME=$dn} \
        python3 -I script/onchain/pq.py --net "$tgt" --rpc "$PQ_RPC" $o || r=1
    fi ;;
  verify) verify verify; continue ;;
  verifiers) step "/$g" "$RPC" "" python3 -I script/onchain/verifiers.py "$tgt" "$RPC" || r=1 ;;
  views) step "/$g" "$RPC" "" python3 -I script/onchain/coverage.py views "$tgt" "$RPC" || r=1 ;;
  # last: it moves the chain's clock by two days (local only; its own outputs, wraplimits.sh)
  wraplimits)
    if [ "$tgt" != local ]; then
      res="not run" why="local only: the run moves the chain's clock"
    else
      step "/$g" "$RPC" "$ADDRS" env NET="$tgt" RPC="$RPC" sh script/onchain/wraplimits.sh || r=1
    fi ;;
  *) r=1; echo "unknown group $g" >> "$LOG" ;;
  esac
  if [ "$res" = "not run" ]; then
    say "/$g" "not run (${why:-ONCHAIN_PQZ=$PQZ$([ -n "$PQ_RPC" ] || echo ', no PQZ node for this target')})"
  elif [ $r = 0 ]; then
    say "/$g" "ok $(result "$g") (${SECS}s)"
  else
    res=fail rc=1
    say "/$g" "FAIL $(MATRIX_FAILED=1 result "$g") (${SECS}s)"
  fi
  row "$g" "$res"
  [ "$res" = "not run" ] || [ "$tgt" = local ] || [ "$g" = verify ] || verify "$g"
done
STAGE=table
# coverage.py refuses a target with no book and leaves coverage.json as it was; the table file is replaced only on success
if python3 -I script/onchain/coverage.py table --net "$tgt" > "$T/table.txt" 2>> "$LOG"; then
  mv "$T/table.txt" "$OUTD/table-$tgt.txt"
else
  rc=1
  say "" "FAIL table: $(tail -1 "$LOG")"
  row table fail
fi
STAGE=done
say "" "done: rc $rc (table $OUTD/table-$tgt.txt, log $LOG)"
exit $rc
