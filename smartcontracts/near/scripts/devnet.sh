#!/usr/bin/env bash
# near-sandbox for the scaas-node e2e (near-algorand Task 19, spec §7): RPC 32060, p2p 32061 (127.0.0.1 only).
#   devnet.sh up [home]    init (once) + start in the background, wait for the RPC; prints the RPC url
#   devnet.sh down [home]  stop it
# home: $NEAR_SANDBOX_HOME, default /tmp/scaas-near-sandbox. No docker: the binary near-workspaces downloaded for the
# contract tests (smartcontracts/near/target/*/build/near-sandbox-*/out/.near/near-sandbox-*/near-sandbox; run
# `smartcontracts/scripts/test.sh near` once), or $NEAR_SANDBOX_BIN_PATH. Run under scripts/capped with the e2e.
# Config: --fast blocks; max_gas_burnt_view 300 Tgas (the relayer's `*_check` views, a 13-passkey wrapper check burns
# ≈ 265 Tgas); every height kept (gc_num_epochs_to_keep: the indexer reads old blocks); a 600-block transaction validity
# (≈ 70 s at --fast; the e2e holds a signed transaction while another lane runs).
# NEAR_SANDBOX_WATCH_PID: the sandbox is stopped when that process exits (the e2e passes its own pid: no orphan).
# The funding account is test.near, its key in <home>/validator_key.json.
set -euo pipefail
NEAR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CMD="${1:?usage: $0 up|down [home]}"
H="${2:-${NEAR_SANDBOX_HOME:-/tmp/scaas-near-sandbox}}"
RPC=32060 NET=32061

bin() {
  if [ -n "${NEAR_SANDBOX_BIN_PATH:-}" ]; then echo "$NEAR_SANDBOX_BIN_PATH"; return; fi
  local b
  b="$(ls "$NEAR"/target/*/build/near-sandbox-*/out/.near/near-sandbox-*/near-sandbox 2>/dev/null | sort -V | tail -1)"
  [ -x "$b" ] || { echo "no near-sandbox binary: run smartcontracts/scripts/test.sh near once, or set NEAR_SANDBOX_BIN_PATH" >&2; exit 1; }
  echo "$b"
}

up() {
  local b; b="$(bin)"
  if [ -f "$H/pid" ] && kill -0 "$(cat "$H/pid")" 2>/dev/null; then echo "http://127.0.0.1:$RPC"; return; fi
  if [ ! -f "$H/config.json" ]; then
    mkdir -p "$H"
    "$b" --home "$H" init --fast --max-gas-burnt-view "300 Tgas" > "$H/init.log" 2>&1
    python3 -I - "$H" "$RPC" "$NET" <<'EOF'
import json, sys
h, rpc, net = sys.argv[1], sys.argv[2], sys.argv[3]
c = json.load(open(f"{h}/config.json"))
c["rpc"]["addr"], c["network"]["addr"] = f"127.0.0.1:{rpc}", f"127.0.0.1:{net}"
c["gc_num_epochs_to_keep"] = 100000
assert c["max_gas_burnt_view"] >= 300 * 10**12, c["max_gas_burnt_view"]
json.dump(c, open(f"{h}/config.json", "w"), indent=2)
g = json.load(open(f"{h}/genesis.json"))
g["transaction_validity_period"], g["epoch_length"] = 600, 1000  # nearcore: validity <= epoch length
json.dump(g, open(f"{h}/genesis.json", "w"), indent=2)
EOF
  fi
  nohup "$b" --home "$H" run < /dev/null > "$H/sandbox.log" 2>&1 &
  local pid=$!
  echo "$pid" > "$H/pid"
  if [ -n "${NEAR_SANDBOX_WATCH_PID:-}" ]; then
    ( while kill -0 "$NEAR_SANDBOX_WATCH_PID" 2>/dev/null && kill -0 "$pid" 2>/dev/null; do sleep 1; done
      kill "$pid" 2>/dev/null ) < /dev/null > /dev/null 2>&1 &
  fi
  for _ in $(seq 1 120); do
    if curl -sf -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"status","params":[]}' \
         "http://127.0.0.1:$RPC" > /dev/null 2>&1; then echo "http://127.0.0.1:$RPC"; return; fi
    kill -0 "$pid" 2>/dev/null || { tail -30 "$H/sandbox.log" >&2; exit 1; }
    sleep 0.5
  done
  tail -30 "$H/sandbox.log" >&2; echo "near-sandbox not ready" >&2; exit 1
}

down() {
  [ -f "$H/pid" ] || return 0
  local pid; pid="$(cat "$H/pid")"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 40); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$H/pid"
}

case "$CMD" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down [home]" >&2; exit 2 ;;
esac
