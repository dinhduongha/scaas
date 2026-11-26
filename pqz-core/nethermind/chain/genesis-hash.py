#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""genesis-hash.py <chainspec.json> | --check: the genesis block hash (= chainUid, NET-ALL-22, chain-uids.json) that
Nethermind gives a Clique chainspec of the SCaaS testnet's shape, without a node (owner 2026-11-26: the move to chain id
22779 records the new genesis hash before the reset). Python stdlib and eth.py (Keccak-256, RLP); run with python3 -I.

stateRoot: the Merkle Patricia trie over keccak256(address) -> RLP[nonce, balance, storageRoot, keccak256(code)], each
storageRoot the trie over keccak256(slot) -> RLP(value) of the non-zero slots. Header: the fifteen pre-London fields with
gasUsed 0 and the empty transaction / receipt tries, then baseFeePerGas (EIP-1559 from block 0), a zero hash in the
withdrawalsRoot slot (EIP-4844 active at genesis and EIP-4895 not: what Nethermind writes, docs/networks/evm.md
NET-EVM-02 traps), blobGasUsed 0 and excessBlobGas 0. Only that shape is validated (--check: reset 4's live genesis hash
reproduced); a chainspec with another set of header forks at its genesis timestamp (EIP-4895, EIP-4788, EIP-7685,
EIP-7928 active, EIP-1559 or EIP-4844 not) is refused with GENESIS_SHAPE_NOT_VALIDATED. The chain id is no header field:
only the header and the alloc move the hash (NET-ALL-25: a private chain's new genesis carries a unique extraData nonce).

--check: the committed scaas-testnet/genesis.json (chain id 22779) gives its pinned hash; with the extraData nonce
zeroed it gives 0x9ae9…5b13, the hash the SCaaS testnet's RPC reported after reset 4 (2026-11-15, the same header and
alloc) -- the positive control; one storage value changed gives another hash; a shape outside the validated one is
refused."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eth import keccak256, rlp  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
GENESIS = os.path.join(HERE, "scaas-testnet", "genesis.json")
PINNED = (
    "0x9693692c4ffc3bdca7d4181dbaab179ade3fe010975f8dd0b51ff7c3dff5be86"  # scaas-testnet/genesis.json, chain id 22779
)
RESET4 = (
    "0x9ae9048bfd6165d6b25290fa9295ad14e38c3e158371b80049d9a554341e5b13"  # chain-uids.json, eth_getBlockByNumber 0x0
)
EMPTY = keccak256(rlp(b""))


def _num(x):
    return int(str(x), 0)


def _bytes(x):
    s = str(x)
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def _nibbles(b):
    return [n for c in b for n in (c >> 4, c & 15)]


def _hp(n, leaf):
    f = 2 if leaf else 0
    if len(n) % 2:
        return bytes([(f + 1) << 4 | n[0]]) + bytes(n[i] << 4 | n[i + 1] for i in range(1, len(n), 2))
    return bytes([f << 4]) + bytes(n[i] << 4 | n[i + 1] for i in range(0, len(n), 2))


def _node(items):
    """items: sorted (nibble path, RLP value) pairs with distinct paths of one length."""
    if len(items) == 1:
        return [_hp(items[0][0], True), items[0][1]]
    p = 0
    while len({n[p] for n, _ in items}) == 1:
        p += 1
    if p:
        return [_hp(items[0][0][:p], False), _ref([(n[p:], v) for n, v in items])]
    return [
        _ref([(n[1:], v) for n, v in items if n[0] == i]) if any(n[0] == i for n, _ in items) else b""
        for i in range(16)
    ] + [b""]


def _ref(items):
    node = _node(items)
    return node if len(rlp(node)) < 32 else keccak256(rlp(node))


def trie_root(kv):
    """keccak256-keyed (secure) trie root of {key bytes: RLP value}."""
    if not kv:
        return EMPTY
    return keccak256(rlp(_node(sorted((_nibbles(keccak256(k)), v) for k, v in kv.items()))))


def genesis_hash(g):
    h, p = g["genesis"], g["params"]
    ts = _num(h["timestamp"])
    on = lambda k: k in p and _num(p[k]) <= ts  # noqa: E731
    if not (
        "eip1559Transition" in p
        and _num(p["eip1559Transition"]) == 0
        and on("eip4844TransitionTimestamp")
        and not any(on(f"eip{e}TransitionTimestamp") for e in (4895, 4788, 7685, 7928))
    ):
        sys.exit(
            "GENESIS_SHAPE_NOT_VALIDATED: only EIP-1559 and EIP-4844 (without EIP-4895 / 4788 / 7685 / 7928) at genesis"
        )
    acc = {}
    for a, v in g["accounts"].items():
        st = {_bytes(s).rjust(32, b"\0"): rlp(_num(x)) for s, x in v.get("storage", {}).items() if _num(x)}
        code = _bytes(v.get("code", "0x"))
        acc[_bytes(a)] = rlp([_num(v.get("nonce", 0)), _num(v.get("balance", 0)), trie_root(st), keccak256(code)])
    head = [
        _bytes(h["parentHash"]),
        keccak256(rlp([])),
        _bytes(h["coinbase"]),
        trie_root(acc),
        EMPTY,
        EMPTY,
        b"\0" * 256,
        _num(h["difficulty"]),
        _num(h["number"]),
        _num(h["gasLimit"]),
        _num(h["gasUsed"]),
        ts,
        _bytes(h["extraData"]),
        _bytes(h["mixHash"]),
        _bytes(h["nonce"]),
        _num(h.get("baseFeePerGas", 0)),
        b"\0" * 32,
        0,
        0,
    ]
    return "0x" + keccak256(rlp(head)).hex()


def check():
    g = json.load(open(GENESIS))
    got = genesis_hash(g)
    assert got == PINNED, f"{GENESIS}: {got}, pinned {PINNED}"
    print(f"  scaas-testnet/genesis.json (chain id {_num(g['params']['chainId'])}): {got} (pinned)")
    z = json.loads(json.dumps(g))
    z["genesis"]["extraData"] = "0x" + "00" * 32 + g["genesis"]["extraData"][66:]
    assert genesis_hash(z) == RESET4, genesis_hash(z)
    print(f"  extraData nonce zeroed: {RESET4} = reset 4's live genesis hash (positive control)")
    m = json.loads(json.dumps(z))
    a = next(k for k, v in m["accounts"].items() if v.get("storage"))
    s = next(iter(m["accounts"][a]["storage"]))
    m["accounts"][a]["storage"][s] = hex(_num(m["accounts"][a]["storage"][s]) ^ 1)
    assert genesis_hash(m) not in (RESET4, PINNED)
    print("  one storage value changed: another hash")
    m = json.loads(json.dumps(g))
    m["params"]["eip4895TransitionTimestamp"] = 0
    try:
        genesis_hash(m)
        raise AssertionError("eip4895 at genesis accepted")
    except SystemExit as e:
        assert str(e.code).startswith("GENESIS_SHAPE_NOT_VALIDATED"), e.code
        print(f"  refused (EIP-4895 at genesis): {e.code}")
    print("genesis-hash.py --check: ok")


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif len(sys.argv) == 2:
        print(genesis_hash(json.load(open(sys.argv[1]))))
    else:
        sys.exit(__doc__)
