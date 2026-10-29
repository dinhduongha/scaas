#!/usr/bin/env bash
# Algorand localnet (devnet/docker-compose.yml): algod 127.0.0.1:4001 (kmd :4002, token "a"×64), indexer :8980.
# usage: devnet.sh up | down | status   — `up` waits until algod answers and its first block exists.
set -euo pipefail
D="$(cd "$(dirname "${BASH_SOURCE[0]}")/../devnet" && pwd)"
C=(docker compose -f "$D/docker-compose.yml")
TOK=$(printf 'a%.0s' {1..64})
case "${1:?usage: $0 up|down|status}" in
  up)
    "${C[@]}" up -d --quiet-pull
    for _ in $(seq 120); do
      curl -sf -H "X-Algo-API-Token: $TOK" http://127.0.0.1:4001/v2/status >/dev/null && { echo "algod up"; exit 0; }
      sleep 1
    done
    echo "algod did not answer in 120 s" >&2; "${C[@]}" logs --tail 50 algod >&2; exit 1 ;;
  down)   "${C[@]}" down -v ;;
  status) "${C[@]}" ps ;;
  *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
