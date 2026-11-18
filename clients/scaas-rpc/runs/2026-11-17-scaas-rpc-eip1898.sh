#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# scaas-rpc plan T0 (F16): does a client answer EIP-1898 block objects `{blockHash, requireCanonical: true}`? Five reads
# (eth_call, eth_getCode, eth_getStorageAt, eth_getBalance, eth_getTransactionCount) at the canonical hash of the latest block
# must answer; at a made-up hash they must be an error answer. Run against a local Nethermind dev chain (a memory-capped
# container of the image the repository's local chain uses, on a free loopback port, removed on exit; never the live stack)
# and against anvil (through scripts/capped, killed on exit). Prints one line per read and one `RESULT <client> …` line each.
#   bash clients/scaas-rpc/runs/2026-11-17-scaas-rpc-eip1898.sh        (from the worktree root; docker and anvil needed)
set -uo pipefail
W=$(git rev-parse --show-toplevel)
IMAGE=${NETHERMIND_IMAGE:-nethermind/nethermind:2.2.0}
export PATH="$HOME/.foundry/bin:$PATH"
free_port() { python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
NAME=scaas-rpc-eip1898-$$
APID=
cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1
    [[ -n $APID ]] && kill "$APID" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

check() { # client url
    python3 -I - "$1" "$2" <<'EOF'
import json, sys, urllib.request
client, url = sys.argv[1], sys.argv[2]
def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())
head = rpc("eth_getBlockByNumber", ["latest", False])["result"]
print(f"{client}: latest block {int(head['number'], 16)} {head['hash']}")
acct = "0x" + "00" * 19 + "01"
def reads(block):
    return [("eth_call", [{"to": acct, "data": "0x"}, block]), ("eth_getCode", [acct, block]),
            ("eth_getStorageAt", [acct, "0x0", block]), ("eth_getBalance", [acct, block]),
            ("eth_getTransactionCount", [acct, block])]
ok = refused = 0
for label, block in (("canonical", {"blockHash": head["hash"], "requireCanonical": True}),
                     ("made-up", {"blockHash": "0x" + "11" * 32, "requireCanonical": True})):
    for method, params in reads(block):
        a = rpc(method, params)
        if label == "canonical":
            good = "result" in a and "error" not in a
            ok += good
        else:
            good = "error" in a
            refused += good
        what = a.get("result") if "result" in a else a.get("error")
        print(f"{client}: {method} {label}: {'ok' if good else 'WRONG'}: {json.dumps(what)[:160]}")
print(f"RESULT {client}: canonical answered {ok}/5, made-up refused {refused}/5: {'PASS' if ok == 5 and refused == 5 else 'FAIL'}")
sys.exit(0 if ok == 5 and refused == 5 else 1)
EOF
}

rc=0
P=$(free_port)
echo "[eip1898] nethermind $IMAGE on 127.0.0.1:$P (dev chain spaceneth, --memory 2g)"
docker run -d --rm --name "$NAME" --memory 2g -p "127.0.0.1:$P:8545" "$IMAGE" --config spaceneth \
    --JsonRpc.Enabled true --JsonRpc.Host 0.0.0.0 --JsonRpc.Port 8545 >/dev/null || exit 1
curl -s --retry 90 --retry-delay 1 --retry-connrefused --retry-all-errors -o /dev/null -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "http://127.0.0.1:$P" || {
    echo "[eip1898] nethermind did not answer"
    docker logs "$NAME" | tail -20
    exit 1
}
check nethermind "http://127.0.0.1:$P" || rc=1
docker rm -f "$NAME" >/dev/null

A=$(free_port)
echo "[eip1898] anvil on 127.0.0.1:$A ($(anvil --version | head -1))"
"$W/scripts/capped" anvil --port "$A" --silent &
APID=$!
curl -s --retry 60 --retry-delay 1 --retry-connrefused --retry-all-errors -o /dev/null -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "http://127.0.0.1:$A" || {
    echo "[eip1898] anvil did not answer"
    exit 1
}
# one mined block, so the latest hash is not block 0's
curl -s -o /dev/null -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"evm_mine","params":[]}' "http://127.0.0.1:$A"
check anvil "http://127.0.0.1:$A" || rc=1
echo "RESULT hedera-relay: not verified (no local relay)"
exit $rc
