#!/usr/bin/env bash
# S12 local Solana validator (spec §9): RPC 32020, WS 32021, faucet 32022, gossip 32023, dynamic [32024, 32050)
# (Agave 4.3 refuses a dynamic range narrower than 26 ports — OQ4: the S12 block is 32020-32049).
# usage: devnet.sh up [extra solana-test-validator args…] | down | status
#   SOLANA_LEDGER (default $SP/solana-ledger or /tmp/s12-solana-ledger) — wiped on every `up` (--reset).
# Run it under the machine-wide `capped` wrapper together with the job that uses it, then `down`.
set -euo pipefail
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
LEDGER="${SOLANA_LEDGER:-${SP:-/tmp}/s12-solana-ledger}"
RPC=http://127.0.0.1:32020
PIDF="$LEDGER.pid"
case "${1:-}" in
  up)
    shift
    mkdir -p "$LEDGER"
    nohup solana-test-validator --reset --quiet --ledger "$LEDGER" --bind-address 127.0.0.1 \
      --rpc-port 32020 --faucet-port 32022 --gossip-port 32023 --dynamic-port-range 32024-32050 \
      "$@" > "$LEDGER.log" 2>&1 &
    echo $! > "$PIDF"
    for _ in $(seq 1 120); do
      if curl -s -m 2 "$RPC" -H 'content-type: application/json' \
           -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' | grep -q '"ok"'; then
        echo "validator up (pid $(cat "$PIDF")) at $RPC"; exit 0
      fi
      kill -0 "$(cat "$PIDF")" 2>/dev/null || { echo "validator died:"; tail -20 "$LEDGER.log"; exit 1; }
      sleep 1
    done
    echo "validator not healthy after 120 s"; tail -20 "$LEDGER.log"; exit 1 ;;
  down)
    [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null || true
    for _ in $(seq 1 30); do pgrep -f "solana-test-validator.*$LEDGER" >/dev/null || break; sleep 1; done
    pkill -9 -f "solana-test-validator.*$LEDGER" 2>/dev/null || true
    rm -f "$PIDF"; echo "validator down" ;;
  status)
    curl -s -m 2 "$RPC" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'; echo ;;
  *) echo "usage: $0 up|down|status"; exit 2 ;;
esac
