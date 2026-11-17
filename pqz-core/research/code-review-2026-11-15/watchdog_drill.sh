#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# 3zh Fable F-7 (T-20): the node-fault exit path inside a real Nethermind, on a LOCAL throwaway copy only
# (chain/copy.sh: project pqzcopy, its own network, 127.0.0.1:18545; never the live stack or its RPC).
#   scripts/capped sh pqz-core/research/code-review-2026-11-15/watchdog_drill.sh <scratch dir> [image]
# 1. a drill build of the plugin from this tree: a scratch copy with ONE extra line in MlDsa.Verify (an ML-DSA-65 input
#    of PK + SIG + 1 bytes ending in 0xdd throws InvalidOperationException: the non-crypto exception path); never
#    committed, never in an image other than the local drill tag
# 2. image <image> (default the local scaas/nethermind-pqz:2.2.0-pqz9) + that dll = scaas/nethermind-pqz:drill-3zh
# 3. a fresh copy (copy.sh init, genesis0 on chain/engine-pqz-provisional-n2304.json, up), a transaction to MLDSA65 with
#    the drill input through the copy's RPC, then the signer's and the follower's exit codes, the fault line and the time
#    from the fault line to the container's end. Prints short lines; full logs under <scratch dir>.
set -eu
W=$(cd "$1" && pwd)
IMG=${2:-scaas/nethermind-pqz:2.2.0-pqz9}
REPO=$(git rev-parse --show-toplevel)
NM=$REPO/pqz-core/nethermind
SDK=mcr.microsoft.com/dotnet/sdk:10.0.402-resolute@sha256:6924c5c6564690089a67509f5a6ae85d7afa28d7f0f6466ec1b8a5439764ca92
echo "drill: start $(date -u +%FT%TZ), image $IMG, scratch $W"
[ -z "$(docker ps -q --filter name=pqzcopy-)" ] || { echo "drill: pqzcopy containers are running (another copy): stop"; exit 2; }

# 1. the drill plugin
rm -rf "$W/src" && mkdir -p "$W/src" && cp -r "$NM/Nethermind.Pqz" "$NM/Directory.Build.props" "$NM/Directory.Build.targets" "$W/src/"
rm -rf "$W/src/Nethermind.Pqz/bin" "$W/src/Nethermind.Pqz/obj"
python3 -I - "$W/src/Nethermind.Pqz/MlDsaPrecompile.cs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
a = "            if (input.Length < pk + sig) return output;\n"
assert s.count(a) == 1
s = s.replace(a, a + "            if (input.Length == pk + sig + 1 && input[^1] == 0xdd) throw new InvalidOperationException(\"drill\"); // DRILL ONLY\n")
open(p, "w").write(s)
PY
docker run --rm --memory 3g --cpus 2 -u "$(id -u):$(id -g)" -e HOME=/tmp -e DOTNET_CLI_HOME=/tmp -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
  -e DOTNET_NOLOGO=1 -e NUGET_PACKAGES="$HOME/.nuget/packages" -v "$HOME/.nuget/packages:$HOME/.nuget/packages" \
  -v "$W/src:/src" -v "$NM/ref:/src/ref:ro" -w /src "$SDK" \
  dotnet build Nethermind.Pqz/Nethermind.Pqz.csproj -c Release -p:UseSharedCompilation=false -p:PqzSet=n2304-kmax4096 \
  > "$W/build.log" 2>&1 || { echo "drill: plugin build FAILED (build.log)"; exit 1; }
DLL=$(find "$W/src/Nethermind.Pqz/bin/Release" -name Nethermind.Pqz.dll | head -1)
echo "drill: plugin built, sha256 $(sha256sum "$DLL" | cut -c1-16)…"

# 2. the drill image (local tag only)
mkdir -p "$W/img" && cp "$DLL" "$W/img/" && printf 'FROM %s\nCOPY Nethermind.Pqz.dll /nethermind/plugins/Nethermind.Pqz.dll\n' "$IMG" > "$W/img/Dockerfile"
docker build -q -t scaas/nethermind-pqz:drill-3zh "$W/img" > "$W/image.log" 2>&1 || { echo "drill: image build FAILED"; exit 1; }
echo "drill: image scaas/nethermind-pqz:drill-3zh $(cut -c1-19 "$W/image.log")"

# 3. the copy
export COPY="$W/copy"
CS="$NM/chain"
sh "$CS/copy.sh" init > "$W/copy-init.log" 2>&1
sh "$CS/copy.sh" genesis0 "$CS/engine-pqz-provisional-n2304.json" > "$W/copy-genesis.log" 2>&1
sh "$CS/copy.sh" up scaas/nethermind-pqz:drill-3zh genesis.pqz0.json > "$W/copy-up.log" 2>&1
echo "drill: copy up; waiting 45 s for blocks"
sleep 45
echo "drill: head $(sh "$CS/copy.sh" rpc eth_blockNumber)"
docker logs pqzcopy-signer 2>&1 | grep -E "PQZ-START|PQZ-REFUSE" | head -2 | cut -c1-200
PK=$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print((d["data"] if "data" in d else d)[0]["private_key"])' "$COPY/signer.json")
DATA=0x$(python3 -I -c 'print("00" * (1952 + 3309) + "dd")')
T0=$(date -u +%FT%T.%NZ)
cast send --async --private-key "$PK" --rpc-url http://127.0.0.1:18545 --gas-limit 300000 \
  0x000000000000000000000000000000005caa0013 "$DATA" > "$W/send.log" 2>&1 || true
echo "drill: transaction sent at $T0: $(cut -c1-66 "$W/send.log")"
echo "drill: waiting 60 s (the watchdog bound is 10 s)"
sleep 60
for c in pqzcopy-signer pqzcopy-follower; do
  st=$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} finished={{.State.FinishedAt}}' "$c")
  docker logs -t "$c" > "$W/$c.log" 2>&1 || true
  fault=$(grep -m1 "PQZ-NODE-FAULT" "$W/$c.log" | cut -c1-30 || true)
  wd=$(grep -c "exit watchdog" "$W/$c.log" || true)
  echo "drill: $c: $st; first PQZ-NODE-FAULT line at ${fault:-none}; watchdog lines $wd"
done
sh "$CS/copy.sh" down > "$W/copy-down.log" 2>&1 || true
docker rmi scaas/nethermind-pqz:drill-3zh > /dev/null 2>&1 || true
echo "drill: copy down, drill image removed, end $(date -u +%FT%TZ)"
