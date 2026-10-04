#!/usr/bin/env bash
# Localnet Aptos cho e2e của S11 (cổng 32010–32019, spec §9):
#   REST 32010 · faucet 32011 · ready 32012 · txn stream 32013 · postgres 32014 · Indexer API (Hasura) 32015
#   devnet.sh up        — `aptos node run-localnet --with-indexer-api` (Docker: postgres + hasura), chờ ready
#   devnet.sh publish   — tạo profile deployer (faucet), `deploy-object` package bamboo + một bản SAO, publish testfa
#   devnet.sh down      — dừng localnet và container của nó
# Thư mục trạng thái: $APTOS_LOCALNET_DIR (mặc định /tmp/bamboo-aptos-localnet). Địa chỉ ghi vào đó:
#   package.txt (bamboo), copy.txt (bản sao phát event giả — L2), deployer.txt (testfa = deployer).
# Chạy dưới `capped` cùng với e2e (một việc nặng mỗi lúc); `pgrep -f run-localnet` rỗng sau `down`.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${APTOS_LOCALNET_DIR:-/tmp/bamboo-aptos-localnet}"
REST=32010 FAUCET=32011 READY=32012 STREAM=32013 PG=32014 GQL=32015
CFG="$DIR/cli"   # thư mục .aptos/config.yaml của deployer

up() {
  mkdir -p "$DIR"
  if pgrep -f "run-localnet.*$DIR/node" >/dev/null; then echo "already up"; return; fi
  cat > "$DIR/override.yaml" <<EOF
api:
  address: 127.0.0.1:$REST
EOF
  nohup aptos node run-localnet --test-dir "$DIR/node" --force-restart --assume-yes \
    --test-config-override "$DIR/override.yaml" --faucet-port "$FAUCET" --ready-server-listen-port "$READY" \
    --txn-stream-port "$STREAM" --with-indexer-api --postgres-port "$PG" --indexer-api-port "$GQL" \
    > "$DIR/localnet.log" 2>&1 &
  echo $! > "$DIR/pid"
  for _ in $(seq 1 180); do
    if curl -sf "http://127.0.0.1:$READY/" >/dev/null 2>&1; then echo "localnet ready"; return; fi
    if ! kill -0 "$(cat "$DIR/pid")" 2>/dev/null; then tail -30 "$DIR/localnet.log"; exit 1; fi
    sleep 2
  done
  tail -30 "$DIR/localnet.log"; echo "localnet not ready"; exit 1
}

publish() {
  mkdir -p "$CFG"
  ( cd "$CFG" && aptos init --profile deployer --network custom --rest-url "http://127.0.0.1:$REST/v1" \
      --faucet-url "http://127.0.0.1:$FAUCET" --assume-yes < /dev/null > "$DIR/init.log" 2>&1 )
  local deployer
  deployer="0x$(cd "$CFG" && aptos config show-profiles --profile deployer | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["Result"]["deployer"]["account"])')"
  echo "$deployer" > "$DIR/deployer.txt"
  deploy() {
    ( cd "$CFG" && aptos move deploy-object --package-dir "$HERE" --address-name bamboo --profile deployer --included-artifacts none \
        --assume-yes --skip-fetch-latest-git-deps 2>&1 ) | tee -a "$DIR/deploy.log" \
      | python3 -c 'import re,sys; t=sys.stdin.read(); m=re.findall(r"Code was successfully deployed to object address (0x[0-9a-fA-F]+)", t); print(m[-1] if m else "")'
  }
  local pkg copy
  pkg="$(deploy)"; [ -n "$pkg" ] || { tail -40 "$DIR/deploy.log"; exit 1; }
  copy="$(deploy)"; [ -n "$copy" ] || { tail -40 "$DIR/deploy.log"; exit 1; }
  echo "$pkg" > "$DIR/package.txt"
  echo "$copy" > "$DIR/copy.txt"
  ( cd "$CFG" && aptos move publish --package-dir "$HERE/testfa" --named-addresses "testfa=$deployer" \
      --profile deployer --assume-yes --skip-fetch-latest-git-deps > "$DIR/testfa.log" 2>&1 ) \
    || { tail -40 "$DIR/testfa.log"; exit 1; }
  echo "bamboo $pkg, copy $copy, testfa $deployer"
}

down() {
  if [ -f "$DIR/pid" ]; then
    kill -INT "$(cat "$DIR/pid")" 2>/dev/null || true
    for _ in $(seq 1 30); do kill -0 "$(cat "$DIR/pid")" 2>/dev/null || break; sleep 1; done
    kill -KILL "$(cat "$DIR/pid")" 2>/dev/null || true
    rm -f "$DIR/pid"
  fi
  pkill -f "run-localnet.*$DIR/node" 2>/dev/null || true
  # Container của --with-indexer-api (tên do CLI đặt) — dừng nếu SIGINT chưa dọn.
  docker ps -aq --filter name=local-testnet | xargs -r docker rm -f >/dev/null
  echo "localnet down"
}

"${1:?up|publish|down}"
