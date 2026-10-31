#!/usr/bin/env bash
# The pinned local Stellar network at Protocol 30 (plan SOR-D4; spec S5, S17). One container at a time, `scaas-stellar`,
# memory-capped. usage: quickstart.sh up|down|wait|cli
#   up    start it (exit 3 when a `scaas-stellar` container already exists; any other failure removes what it created)
#   down  stop and remove it (no-op when absent)
#   wait  poll until protocolVersion == 30 and the testnet limits are applied (exit 1 after 10 min)
#   cli   print the pinned stellar-cli binary (exit 1 with the install command when missing)
set -euo pipefail

# stellar/quickstart tag `latest` as of 2026-10-28 (images.json: core v30.0.0, rpc v30.0.0, horizon v30.0.0, xdr v30.0.0;
# measured: `stellar-core version` v30.0.0 ledger protocol 30, `stellar-rpc version` 30.0.0 13e53516).
QS_IMAGE=stellar/quickstart@sha256:e05d68bb3b2629a829310dc3434fc0ee3f801854bdfa1a7c8c362d2f1c9060f8
# stellar-cli (SOR-D5): no release supports Protocol 30 yet (v28.1.0 is on stellar-xdr 28), so the pin is the main commit
# 90a3d42d (workspace version 30.0.0, stellar-xdr 30.0.0), installed into its own root.
STELLAR_CLI_REV=90a3d42d9327ccfaa0d301373766f45beae3e6d9
STELLAR_CLI_ROOT=${STELLAR_CLI_ROOT:-$HOME/.cache/scaas-tools/stellar-cli-30.0.0-90a3d42d}
NAME=scaas-stellar
PORT=${QS_PORT:-31980}
RPC_URL=http://127.0.0.1:$PORT/rpc

case "${1:-}" in
  up)
    if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
      echo "quickstart: container $NAME already exists (one quickstart at a time)" >&2; exit 3
    fi
    # a run that fails after creating the container (port taken, start error) removes what it created, by the id docker
    # wrote to the cidfile: never by name (another process may have created `scaas-stellar` since the check above)
    cid=$(mktemp -u "${TMPDIR:-/tmp}/scaas-stellar.XXXXXX.cid")
    docker run -d --rm --cidfile "$cid" --memory 3g --name "$NAME" -p "127.0.0.1:$PORT:8000" "$QS_IMAGE" \
      --local --protocol-version 30 --limits testnet --enable core,rpc,horizon >/dev/null \
      || { rc=$?; [ -s "$cid" ] && docker rm -f "$(cat "$cid")" >/dev/null 2>&1; rm -f "$cid"
           echo "quickstart: up failed (docker run exit $rc)" >&2; exit "$rc"; }
    rm -f "$cid"
    echo "quickstart: $NAME up ($QS_IMAGE), rpc $RPC_URL" ;;
  down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true ;;
  wait)
    for _ in $(seq 1 120); do
      v=$(curl -s -m 5 -X POST -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getNetwork"}' "$RPC_URL" 2>/dev/null \
        | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["result"]["protocolVersion"])' 2>/dev/null || true)
      # protocol 30 comes first; the `--limits testnet` config upgrade lands a few ledgers later (the image's /start
      # touches this file once it is applied), and only then are the network settings the ones to measure against
      if [ "$v" = 30 ] && docker exec "$NAME" test -f /opt/stellar/core/.upgrade-config-initialized 2>/dev/null; then
        echo "quickstart: protocolVersion 30, testnet limits applied"; exit 0
      fi
      sleep 5
    done
    echo "quickstart: no protocolVersion 30 with testnet limits after 10 min (last version: '${v:-none}')" >&2; exit 1 ;;
  cli)
    bin="$STELLAR_CLI_ROOT/bin/stellar"
    if [ -x "$bin" ]; then echo "$bin"; exit 0; fi
    echo "missing $bin; install: scripts/capped cargo +1.97.1 install --locked --git https://github.com/stellar/stellar-cli" \
      "--rev $STELLAR_CLI_REV stellar-cli --root $STELLAR_CLI_ROOT -j1" >&2; exit 1 ;;
  *) echo "usage: $0 up|down|wait|cli" >&2; exit 2 ;;
esac
