#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""NET-EVM-13 (owner 2026-11-10): a chain's deployment books are named by its key: deployments/<key>.json its book (a
Hedera chain's from DeployHedera.s.sol, its only deploy), <key>-<what>.json a companion (-releases, -t66b-releases,
-zether-e2e, -pqz, …). The key comes from
chain-uids.json by (chainId, chain_uid); a chain not in the table needs DEPLOY_NAME (<name>-mainnet | <name>-testnet),
else DEPLOY_NAME_REQUIRED, never a chain-id fallback. Every book starts with key, name, chainId, chainUid, network; a
reader checks network against the key's suffix (a key without one, e.g. ethereum-hoodi: its table row's network), else
BOOK_NETWORK_MISMATCH. An old book by chain id with none by the key: BOOK_OLD_NAME (rename it). A book is written in
the form of json.dumps(…, indent=2), the header first. script/DeployBook.sol is the same rule for the forge scripts.
  python3 -I script/deploybook.py key <chainId> <chainUid>               the key
  python3 -I script/deploybook.py path <chainId> <chainUid> [<suffix>]   deployments/<key><suffix> (default .json)"""
import json
import os
import re
import sys

EVM = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
HEADER = ("key", "name", "chainId", "chainUid", "network")


class BookError(SystemExit):
    """A named fail (the message starts with its name); uncaught, it prints the message and exits 1."""


def rows():
    return json.load(open(os.path.join(EVM, "chain-uids.json")))["chains"]


def resolve(chain_id, chain_uid, env=os.environ):
    """(key, name, network) of the chain (chainId, chain_uid)."""
    cid, uid, dn = int(chain_id), chain_uid.lower(), env.get("DEPLOY_NAME", "")
    for r in rows():
        if r["chainId"] == cid and r["chainUid"].lower() == uid:
            if dn and dn != r["key"]:
                raise BookError(f"DEPLOY_NAME_MISMATCH: DEPLOY_NAME={dn}, but this chain is {r['key']} in chain-uids.json")
            return r["key"], r["name"], r["network"]
        if dn == r["key"]:
            raise BookError(f"DEPLOY_NAME_TAKEN: {dn} names another chain in chain-uids.json")
    if not dn:
        raise BookError(f"DEPLOY_NAME_REQUIRED: chain {cid} ({uid[:10]}…) is not in chain-uids.json; set "
                        "DEPLOY_NAME=<name>-testnet or <name>-mainnet (NET-EVM-13)")
    if not re.fullmatch(r"[a-z0-9-]+-(mainnet|testnet)", dn):
        raise BookError(f"DEPLOY_NAME_INVALID: {dn!r} is not <name>-mainnet or <name>-testnet ([a-z0-9-])")
    return dn, dn, dn.rsplit("-", 1)[1]


def network_of(key):
    """The network a key names: its suffix, else its chain-uids.json row's (a second testnet keeps its own name)."""
    m = re.fullmatch(r".+-(mainnet|testnet)", str(key))
    if m:
        return m.group(1)
    for r in rows():
        if r["key"] == key:
            return r["network"]
    raise BookError(f"BOOK_KEY_INVALID: {key!r} ends in neither -mainnet nor -testnet and is not in chain-uids.json")


def header(key, name, chain_id, chain_uid, network):
    """A book's first fields (a writer puts its own after them)."""
    return {"key": key, "name": name, "chainId": int(chain_id), "chainUid": chain_uid.lower(), "network": network}


def check(book, where):
    """A book as read: its header there, its network the key's."""
    miss = [f for f in HEADER if f not in book]
    if miss:
        raise BookError(f"BOOK_HEADER_MISSING: {where} has no {', '.join(miss)} (a book from before NET-EVM-13)")
    if book["network"] != network_of(book["key"]):
        raise BookError(f"BOOK_NETWORK_MISMATCH: {where}: network {book['network']!r}, key {book['key']} "
                        f"({network_of(book['key'])})")
    return book


def load(path):
    """The book at `path` (relative to smartcontracts/evm, or absolute), checked."""
    return check(json.load(open(os.path.join(EVM, path))), path)


def find(chain_id, chain_uid, suffix=".json", env=os.environ):
    """deployments/<key><suffix> of the chain; BOOK_OLD_NAME when only deployments/<chainId><suffix> is there (no
    silent fallback: the operator renames it)."""
    key = resolve(chain_id, chain_uid, env)[0]
    new, old = f"deployments/{key}{suffix}", f"deployments/{int(chain_id)}{suffix}"
    if not os.path.exists(os.path.join(EVM, new)) and os.path.exists(os.path.join(EVM, old)):
        raise BookError(f"BOOK_OLD_NAME: {old} is named by chain id; rename it to {new} and give it its header "
                        "(NET-EVM-13)")
    return new


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["key"] and len(a) == 3:
        print(resolve(a[1], a[2])[0])
    elif a[:1] == ["path"] and len(a) in (3, 4):
        print(find(a[1], a[2], *a[3:]))
    else:
        sys.exit(__doc__)
