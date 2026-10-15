#!/bin/sh
# P6f D10 (as adapted, see README §Copy): the throwaway copy of chain 7622 under $COPY (default <repo>/scratchpad/
# p6f-copy, git-ignored). The live directory /home/dockers/mba-chain-nethermind is never read here: the copy is a
# replica — the live chainspec's parameters (Nethermind.Pqz.Test/chainspecs/genesis-7622.json, the live params,
# engine and genesis header) with a throwaway signer key, whose history the stock image produces first.
#   copy.sh init                       fresh key, password, genesis.stock.json, configs; empty data dirs
#   copy.sh up <image> <genesis file>  start signer + follower + rpc (detached)
#   copy.sh down                       stop and remove the containers (data kept)
#   copy.sh patch <engine.json> <ts>   genesis.pqz.json = genesis.stock.json + engine.Pqz (first timestamp ts)
#   copy.sh genesis0 <engine.json>     genesis.pqz0.json: engine.Pqz from block 0 (a new chain, owner 2026-10-15)
#   copy.sh backup <label> | restore <label>   data dirs + chainspecs + configs, through alpine:3 (cp -a)
#   copy.sh wipe                       empty both data dirs (through alpine:3: the files belong to the container user)
#   copy.sh rpc <method> [params-json] JSON-RPC to the follower through nginx
#   copy.sh signer-rpc <method> [params-json]  JSON-RPC to the signer inside the network (curl container)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
COPY=${COPY:-$ROOT/scratchpad/p6f-copy}
export COPY
DC="docker compose -f $HERE/docker-compose.copy.yml"
A="docker run --rm --memory 256m -v $COPY:/c alpine:3"
cmd=${1:?command}; shift
case $cmd in
init)
  [ -z "$(docker ps -q --filter name=pqzcopy-)" ] || { echo "copy containers running: copy.sh down first"; exit 1; }
  mkdir -p "$COPY"
  [ -d "$COPY/data-signer" ] && $A sh -c 'rm -rf /c/data-signer /c/data-follower /c/keystore'
  mkdir -p "$COPY/data-signer" "$COPY/data-follower" "$COPY/keystore"
  PW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
  printf '%s' "$PW" > "$COPY/password.txt"
  cast wallet new --json > "$COPY/signer.json"
  PK=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["private_key"])' "$COPY/signer.json")
  ADDR=$(cast wallet address --private-key "$PK")
  cast wallet import signer --private-key "$PK" --keystore-dir "$COPY/keystore" --unsafe-password "$PW" > /dev/null
  LOW=$(echo "$ADDR" | tr 'A-F' 'a-f' | sed 's/^0x//')
  python3 -I - "$COPY/keystore/signer" "$COPY/keystore/UTC--2026-10-15T00-00-00.000000000Z--$LOW" "$LOW" <<'PY'
import json, sys, os
k = json.load(open(sys.argv[1])); k["address"] = sys.argv[3]
json.dump(k, open(sys.argv[2], "w")); os.remove(sys.argv[1])
PY
  PUB=$(cast wallet public-key --private-key "$PK" | sed 's/^0x//')
  python3 -I - "$HERE/../Nethermind.Pqz.Test/chainspecs/genesis-7622.json" "$COPY/genesis.stock.json" "$LOW" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))
g["genesis"]["extraData"] = "0x" + "00" * 32 + sys.argv[3] + "00" * 65
g["accounts"] = {"0x" + sys.argv[3]: {"balance": hex(10**30)}}
json.dump(g, open(sys.argv[2], "w"), indent=1)
PY
  sed "s/@SIGNER@/$ADDR/g" "$HERE/config.signer.json" > "$COPY/config.signer.json"
  sed "s/@ENODE@/$PUB/g" "$HERE/config.follower.json" > "$COPY/config.follower.json"
  echo "copy at $COPY: signer $ADDR (throwaway key, $COPY/signer.json), enode $PUB"
  ;;
up)
  IMAGE=$1 GENESIS=$2 $DC up -d
  ;;
down)
  IMAGE=x GENESIS=x $DC down --timeout 60
  ;;
patch)
  python3 -I "$HERE/patch-chainspec.py" "$COPY/genesis.stock.json" "$1" "$2" "$COPY/genesis.pqz.json"
  ;;
genesis0)
  python3 -I "$HERE/patch-chainspec.py" "$COPY/genesis.stock.json" "$1" 0 "$COPY/genesis.pqz0.json"
  ;;
backup)
  $A sh -c "rm -rf /c/bak-$1 && mkdir /c/bak-$1 && cp -a /c/data-signer /c/data-follower /c/genesis.*.json /c/config.*.json /c/bak-$1/ && du -s /c/data-signer /c/bak-$1/data-signer"
  ;;
restore)
  $A sh -c "test -d /c/bak-$1 && rm -rf /c/data-signer /c/data-follower && cp -a /c/bak-$1/data-signer /c/bak-$1/data-follower /c/ && du -s /c/data-signer"
  ;;
wipe)
  $A sh -c 'rm -rf /c/data-signer/* /c/data-follower/*'
  ;;
rpc)
  curl -s -H 'content-type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" http://127.0.0.1:18545; echo
  ;;
signer-rpc)
  docker run --rm --memory 64m --network pqzcopy_net curlimages/curl:8.21.0 -s -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" http://10.76.22.10:8545; echo
  ;;
*) echo "unknown command $cmd"; exit 2 ;;
esac
