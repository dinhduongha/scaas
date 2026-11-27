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
  python3 -I script/deploybook.py path <chainId> <chainUid> [<suffix>]   deployments/<key><suffix> (default .json)
NET-ALL-25: chain-uids.json as read refuses a second row of one (chainId, chainUid) pair (CHAIN_PAIR_TAKEN), a private
chain's genesis in another row or under another chain id (CHAIN_UID_PRIVATE), a row without `private` (CHAIN_ROW_PRIVATE);
a kind keeping or checking records bound to chain_uid without the chain id (`homeChainKinds`) on a genesis another row
shares: HOME_CHAIN_SHARED_GENESIS; a kind on neither that list nor `otherKinds`: KIND_UNKNOWN.
  python3 -I script/deploybook.py kind-check <kind> <chainId> <chainUid>   the kind may deploy on this chain
Deploy sets (owner 2026-11-16: option 2, one chain, two deploy sets; NET-EVM-11 Change): one chain may carry more
than one deploy of the same build, each with its own DEPLOY_SALT, named by a set label (SETS: `mldsa-off`, the deploy with
MLDSA_PRECOMPILE=off, the default set; `mldsa-on`, MLDSA_PRECOMPILE=on). The chain's one book then holds every set under
`sets.<label>` (the set's own entries, its `releases_json`), and its top level stays the default set's entries
(`default_set`), so a reader without a set reads the default set. An unknown label: DEPLOY_SET_UNKNOWN; a label the book
lacks: DEPLOY_SET_MISSING; a label that is not the deploy's MLDSA_PRECOMPILE: DEPLOY_SET_MISMATCH.
  python3 -I script/deploybook.py set-check <label> [<MLDSA_PRECOMPILE>]   the label known (and the deploy's mode its own)
  python3 -I script/deploybook.py set-merge <book> <previous book | -> <label> <releases json>   the new set into the book
  python3 -I script/deploybook.py set-book <book> <label> <out>   header + that set's entries in <out> (a reader's book)
  python3 -I script/deploybook.py add <book> <fields json>   the fields (e.g. tx_gas_cap.py --rows-out) into the book"""

import json
import os
import re
import sys

EVM = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
HEADER = ("key", "name", "chainId", "chainUid", "network")


class BookError(SystemExit):
    """A named fail (the message starts with its name); uncaught, it prints the message and exits 1."""


def table():
    """chain-uids.json, checked (NET-ALL-25): every row says `private` (true: a chain SCaaS runs), no two rows share the pair
    (chainId, chainUid), and a private chain's genesis is in no other row (public chains may share one)."""
    t = json.load(open(os.path.join(EVM, "chain-uids.json")))
    seen = {}
    for r in t["chains"]:
        if not isinstance(r.get("private"), bool):
            raise BookError(f"CHAIN_ROW_PRIVATE: {r.get('key')} in chain-uids.json has no private (true | false)")
        pair = (r["chainId"], r["chainUid"].lower())
        if pair in seen:
            raise BookError(
                f"CHAIN_PAIR_TAKEN: {r['key']} repeats the (chainId, chainUid) pair of {seen[pair]} (NET-ALL-25)"
            )
        seen[pair] = r["key"]
    for r in t["chains"]:
        other = [o["key"] for o in t["chains"] if o is not r and o["chainUid"].lower() == r["chainUid"].lower()]
        if r["private"] and other:
            raise BookError(
                f"CHAIN_UID_PRIVATE: the private chain {r['key']}'s genesis is also {', '.join(other)}'s (NET-ALL-25)"
            )
    return t


def rows():
    return table()["chains"]


def resolve(chain_id, chain_uid, env=os.environ):
    """(key, name, network) of the chain (chainId, chain_uid); a private chain's genesis under another chain id refused."""
    cid, uid, dn = int(chain_id), chain_uid.lower(), env.get("DEPLOY_NAME", "")
    rs = rows()
    for r in rs:
        if r["chainId"] == cid and r["chainUid"].lower() == uid:
            if dn and dn != r["key"]:
                raise BookError(
                    f"DEPLOY_NAME_MISMATCH: DEPLOY_NAME={dn}, but this chain is {r['key']} in chain-uids.json"
                )
            return r["key"], r["name"], r["network"]
        if dn == r["key"]:
            raise BookError(f"DEPLOY_NAME_TAKEN: {dn} names another chain in chain-uids.json")
    for r in rs:
        if r["private"] and r["chainUid"].lower() == uid:
            raise BookError(
                f"CHAIN_UID_PRIVATE: chain {cid} has the genesis of the private chain {r['key']} ({r['chainId']}); a chain we "
                "run that forks is a new chain with its own genesis (NET-ALL-25)"
            )
    if not dn:
        raise BookError(
            f"DEPLOY_NAME_REQUIRED: chain {cid} ({uid[:10]}…) is not in chain-uids.json; set "
            "DEPLOY_NAME=<name>-testnet or <name>-mainnet (NET-EVM-13)"
        )
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
        raise BookError(
            f"BOOK_NETWORK_MISMATCH: {where}: network {book['network']!r}, key {book['key']} "
            f"({network_of(book['key'])})"
        )
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
        raise BookError(
            f"BOOK_OLD_NAME: {old} is named by chain id; rename it to {new} and give it its header (NET-EVM-13)"
        )
    return new


def kind_check(kind, chain_id, chain_uid):
    """NET-ALL-25 (C18): a kind keeping or checking records bound to chain_uid without the chain id (chain-uids.json
    `homeChainKinds`: homeChain records, the registry's portable UAMsigUpdate and scoped keys) is refused on a chain whose
    chain_uid another row shares, until those records carry the chain id; any other kind passes."""
    t, cid, uid = table(), int(chain_id), chain_uid.lower()
    if kind not in t["homeChainKinds"] and kind not in t["otherKinds"]:
        raise BookError(f"KIND_UNKNOWN: {kind} is on neither homeChainKinds nor otherKinds of chain-uids.json")
    if kind in t["homeChainKinds"]:
        other = [r["key"] for r in t["chains"] if r["chainUid"].lower() == uid and r["chainId"] != cid]
        if other:
            raise BookError(
                f"HOME_CHAIN_SHARED_GENESIS: {kind} keeps records bound to chain_uid without the chain id; chain {cid} "
                f"shares its chain_uid with "
                f"{', '.join(other)} (NET-ALL-25)"
            )
    return kind


SETS = {"mldsa-off": "off", "mldsa-on": "on"}  # label -> the deploy's MLDSA_PRECOMPILE
DEFAULT_SET = "mldsa-off"


def set_label(label, mode=None):
    """A known set label; with `mode` (the deploy's MLDSA_PRECOMPILE, default on), the label's own mode."""
    if label not in SETS:
        raise BookError(f"DEPLOY_SET_UNKNOWN: {label!r} is not a deploy set ({', '.join(SETS)})")
    if mode is not None and (mode or "on") != SETS[label]:
        raise BookError(
            f"DEPLOY_SET_MISMATCH: set {label} is MLDSA_PRECOMPILE={SETS[label]}, the deploy's is {mode or 'on'}"
        )
    return label


def set_merge(new, prev, label, releases):
    """The book after a deploy of set `label`: `new` (forge's book of this deploy, flat) under `sets.<label>`, beside the
    sets of `prev` (the chain's book before it, or None); the top level the default set's entries (else this set's)."""
    set_label(label)
    check(new, "the new book")
    sets = {}
    if prev is not None:
        check(prev, "the previous book")
        if (prev["key"], prev["chainUid"]) != (new["key"], new["chainUid"]):
            raise BookError(
                f"BOOK_SET_CHAIN: the previous book is {prev['key']} {prev['chainUid'][:10]}…, the new "
                f"{new['key']} {new['chainUid'][:10]}…"
            )
        sets = dict(prev.get("sets") or {})
    body = {k: v for k, v in new.items() if k not in HEADER and k not in ("sets", "default_set")}
    sets[label] = dict(body, set=label, releases_json=releases)
    top = DEFAULT_SET if DEFAULT_SET in sets else label
    out = {k: new[k] for k in HEADER}
    out["default_set"] = top
    out.update({k: v for k, v in sets[top].items() if k not in ("set", "releases_json")})
    out["sets"] = sets
    return out


def set_book(book, label):
    """A reader's book of set `label`: the header and that set's entries."""
    set_label(label)
    check(book, "the book")
    if label not in (book.get("sets") or {}):
        raise BookError(
            f"DEPLOY_SET_MISSING: the book has no set {label} (sets: {', '.join(book.get('sets') or {}) or 'none'})"
        )
    out = {k: book[k] for k in HEADER}
    out.update(book["sets"][label])
    return out


# A later generation's book fields (spec 2026-11-19-registry-verify-only-kinds §9, F14; plan Task 13): DeployBase's later-generation
# mode writes the registry's own (address, generation, predecessor, code hash, libraries with their code hashes, tx_gas_cap,
# gen_pqz, verify_only); the deploy adds the tx-cap probe's rows (script/tx_gas_cap.py) and the owner overrides with reasons.
GEN_FIELDS = (
    "ua_registry",
    "ua_registry_generation",
    "ua_registry_predecessor",
    "ua_registry_codehash",
    "ua_registry_libraries",
    "tx_gas_cap",
    "tx_gas_cap_probe_rows",
    "gen_pqz",
    "verify_only",
    "owner_overrides",
)
VERIFY_ONLY_FIELDS = ("kind", "verifier", "cap", "keyForm", "precompile", "eip", "status", "probe_rows_hash")


def gen_fields(book, gen):
    """`book` with a generation's fields `gen` (each of GEN_FIELDS) set over it."""
    out = dict(book)
    out.update({k: gen[k] for k in GEN_FIELDS if k in gen})
    return out


def gen_check(book, where):
    """A later generation's book as read: every field of GEN_FIELDS and of each verify-only entry, else BOOK_GEN_FIELD."""
    miss = [k for k in GEN_FIELDS if k not in book]
    vo = book.get("verify_only") or {}  # keyed by the kind (forge's JSON writer keeps no array of objects)
    miss += [f"verify_only.{i}.{k}" for i, e in vo.items() for k in VERIFY_ONLY_FIELDS if k not in e]
    if miss:
        raise BookError(f"BOOK_GEN_FIELD: {where} has no {', '.join(miss)}")
    return True


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["key"] and len(a) == 3:
        print(resolve(a[1], a[2])[0])
    elif a[:1] == ["path"] and len(a) in (3, 4):
        print(find(a[1], a[2], *a[3:]))
    elif a[:1] == ["kind-check"] and len(a) == 4:
        print(kind_check(a[1], a[2], a[3]))
    elif a[:1] == ["set-check"] and len(a) in (2, 3):
        print(set_label(a[1], *a[2:]))
    elif a[:1] == ["set-merge"] and len(a) == 5:
        new = json.load(open(a[1]))
        prev = None if a[2] == "-" else json.load(open(a[2]))
        out = set_merge(new, prev, a[3], a[4])
        with open(a[1], "w") as f:
            json.dump(out, f, indent=2)
            f.write("\n")
    elif a[:1] == ["add"] and len(a) == 3:  # add <book> <fields json>: the fields at the book's top level
        out = check(json.load(open(a[1])), a[1])
        out.update(json.load(open(a[2])))
        with open(a[1], "w") as f:
            json.dump(out, f, indent=2)
            f.write("\n")
    elif a[:1] == ["set-book"] and len(a) == 4:
        out = set_book(json.load(open(a[1])), a[2])
        with open(a[3], "w") as f:
            json.dump(out, f, indent=2)
            f.write("\n")
    else:
        sys.exit(__doc__)
