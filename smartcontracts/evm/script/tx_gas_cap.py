#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The chain's per-transaction gas cap for a registry's `txGasCap` (spec 2026-11-19-registry-verify-only-kinds §9; owner X1,
P18; plan Task 13): `eth_call` of a cheap call at 2^24 and 2^24 + 1 through the node list under strict majority
(ARCH-POS-15), then a binary search up to the block gas limit where 2^24 + 1 is accepted. No cap found -> GEN_TX_CAP_UNKNOWN
unless the book holds an owner-set value; a book value other than the probe's -> GEN_TX_CAP_MISMATCH. No opcode exposes
EIP-7825's cap, so the probe is off chain. `probe` takes callables `accepts(gas) -> bool`; `rpc_node(url)` is one over JSON-RPC
(`eth_call` from and to the zero address, no data, at `latest`: accepted unless the node answers an error).
  python3 -I script/tx_gas_cap.py <rpc>[,<rpc>…] [--owner-set <gas>] [--rows-out <file>]
prints the cap; --owner-set is the book's owner-set value (TX_GAS_CAP), taken only where no cap is found and else checked
against the probe; --rows-out writes {tx_gas_cap, tx_gas_cap_probe_rows, tx_gas_cap_nodes} (client versions, never a URL:
an RPC URL may hold a key) for the book. UNAUDITED tooling."""

import json
import re
import sys
import urllib.request

EIP7825 = 1 << 24


class ProbeError(Exception):
    pass


def _ask(nodes, gas, rows):
    votes = [bool(n(gas)) for n in nodes]
    yes = sum(votes)
    if 2 * yes > len(votes):
        ok = True
    elif 2 * (len(votes) - yes) > len(votes):
        ok = False
    else:
        raise ProbeError(f"GEN_TX_CAP_NODES: no strict majority at gas {gas} ({yes} of {len(votes)} accept)")
    rows.append({"gas": gas, "accepted": ok, "votes": votes})
    return ok


def probe(nodes, block_gas_limit, book=None):
    """(cap, rows): the largest gas a transaction may carry, and every probe row (for the deploy book)."""
    if not nodes:
        raise ProbeError("GEN_TX_CAP_NODES: no node")
    rows = []
    first = min(EIP7825, block_gas_limit)  # a block below 2^24 bounds every transaction first (review P3-6)
    if not _ask(nodes, first, rows):
        raise ProbeError(f"GEN_TX_CAP_UNKNOWN: {first} refused (rows {rows})")
    cap = None
    if first < EIP7825:
        pass  # no cap below the block limit: the book's owner-set value, else GEN_TX_CAP_UNKNOWN
    elif not _ask(nodes, EIP7825 + 1, rows):
        cap = EIP7825
    elif not _ask(nodes, block_gas_limit, rows):
        lo, hi = EIP7825 + 1, block_gas_limit  # lo accepted, hi refused
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if _ask(nodes, mid, rows):
                lo = mid
            else:
                hi = mid
        cap = lo
    book = book or {}
    if cap is None:
        if book.get("txGasCapOwnerSet") and book.get("txGasCap"):
            return int(book["txGasCap"]), rows
        raise ProbeError(f"GEN_TX_CAP_UNKNOWN: every gas up to the block limit {block_gas_limit} accepted")
    if book.get("txGasCap") is not None and int(book["txGasCap"]) != cap:
        raise ProbeError(f"GEN_TX_CAP_MISMATCH: probe {cap}, book {book['txGasCap']}")
    return cap, rows


def _rpc(url, method, params):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except Exception as e:  # a node that does not answer is no vote: the probe stops by name
        raise ProbeError(f"GEN_TX_CAP_NODES: a node did not answer {method} ({type(e).__name__})") from None


# A node's refusal of a gas above its per-transaction cap (EIP-7825), as the clients word it (geth "transaction gas limit too
# high (cap: …)", Nethermind's gas-limit errors, others "exceeds … gas"): only such an answer is a refusal; any other error
# (a rate limit, a failed node, an unknown method) stops the probe by name, never lowers the cap (review P3-6)
CAP_REFUSAL = re.compile(r"gas.{0,40}(too high|exceed|above|over|cap|max)|(exceed|above|over).{0,40}gas", re.I | re.S)


def rpc_node(url, rpc=None):
    zero = "0x" + "00" * 20
    rpc = rpc or (lambda method, params: _rpc(url, method, params))

    def accepts(gas):
        r = rpc("eth_call", [{"from": zero, "to": zero, "gas": hex(gas)}, "latest"])
        if "error" not in r:
            return True
        e = r["error"]
        msg = str(e.get("message", "")) + " " + str(e.get("data", "")) if isinstance(e, dict) else str(e)
        if CAP_REFUSAL.search(msg):
            return False
        raise ProbeError(f"GEN_TX_CAP_RPC_ERROR: gas {gas}: the node answered an error that is no cap refusal: {msg.strip()[:200]}")

    return accepts


def main(argv):
    if not argv or argv[0].startswith("-"):
        sys.exit(__doc__)
    urls = [u for u in argv[0].split(",") if u]
    opts = dict(zip(argv[1::2], argv[2::2]))
    book = {"txGasCap": int(opts["--owner-set"]), "txGasCapOwnerSet": True} if "--owner-set" in opts else None
    limit = min(int(_rpc(u, "eth_getBlockByNumber", ["latest", False])["result"]["gasLimit"], 16) for u in urls)
    try:
        cap, rows = probe([rpc_node(u) for u in urls], limit, book)
    except ProbeError as e:
        print(f"[deploy] FAIL {e}", file=sys.stderr)
        return 1
    if "--rows-out" in opts:
        nodes = [_rpc(u, "web3_clientVersion", []).get("result", "unknown") for u in urls]
        with open(opts["--rows-out"], "w") as f:
            json.dump({"tx_gas_cap": cap, "tx_gas_cap_probe_rows": rows, "tx_gas_cap_nodes": nodes}, f, indent=2)
            f.write("\n")
    print(f"[deploy] tx-cap {cap} ({len(rows)} probe rows, {len(urls)} nodes)", file=sys.stderr)
    print(cap)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
