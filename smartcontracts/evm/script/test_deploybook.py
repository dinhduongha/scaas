#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Offline checks of deploybook.py (NET-EVM-13; test/governance/DeployBook.t.sol is the forge twin) and of basebook.py
on a fixture book in the new format, in a temp dir (no chain, no live book):
  python3 -I script/test_deploybook.py      (from smartcontracts/evm)"""

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "onchain"))
import deploybook as d  # noqa: E402
import basebook  # noqa: E402

SCAAS = (7622, "0x9AE9048BFD6165D6B25290FA9295AD14E38C3E158371B80049D9A554341E5B13")  # case does not matter
HOODI = (560048, "0xbbe312868b376a3001692a646dd2d7d1e4406380dfd86b98aa8a34d1557c971b")
OTHER = "0x" + "01" * 32


def fails(name, f, *a, **k):
    try:
        f(*a, **k)
    except d.BookError as e:
        assert str(e).startswith(name + ":"), (name, str(e))
        return
    raise AssertionError(f"{name} expected")


# a known chain resolves; DEPLOY_NAME may only repeat its key
assert d.resolve(*SCAAS, env={}) == ("scaas-testnet", "SCaaS testnet", "testnet")
assert d.resolve(*SCAAS, env={"DEPLOY_NAME": "scaas-testnet"})[0] == "scaas-testnet"
fails("DEPLOY_NAME_MISMATCH", d.resolve, *SCAAS, env={"DEPLOY_NAME": "other-testnet"})
assert d.resolve(*HOODI, env={}) == ("ethereum-hoodi", "Ethereum Hoodi", "testnet")
# an unknown chain (a listed chain id with another genesis too) needs DEPLOY_NAME: no chain-id fallback
fails("DEPLOY_NAME_REQUIRED", d.resolve, 31337, OTHER, env={})
fails("DEPLOY_NAME_REQUIRED", d.resolve, 7622, OTHER, env={})
assert d.resolve(31337, OTHER, env={"DEPLOY_NAME": "local-testnet"}) == ("local-testnet", "local-testnet", "testnet")
assert d.resolve(31337, OTHER, env={"DEPLOY_NAME": "lab-mainnet"})[2] == "mainnet"
for bad in ("local", "Local-testnet", "local_testnet", "local-devnet"):
    fails("DEPLOY_NAME_INVALID", d.resolve, 31337, OTHER, env={"DEPLOY_NAME": bad})
fails("DEPLOY_NAME_TAKEN", d.resolve, 31337, OTHER, env={"DEPLOY_NAME": "polygon-testnet"})

# a book's header: the network against the key's suffix (or the table's), one change at a time
h = d.header("scaas-testnet", "SCaaS testnet", *SCAAS, "testnet")
assert list(h) == list(d.HEADER) and h["chainUid"] == SCAAS[1].lower()
d.check(dict(h, token_factory="0x" + "00" * 19 + "01"), "book")
fails("BOOK_NETWORK_MISMATCH", d.check, dict(h, network="mainnet"), "book")
d.check(dict(h, key="ethereum-hoodi"), "book")
fails("BOOK_NETWORK_MISMATCH", d.check, dict(h, key="ethereum-hoodi", network="mainnet"), "book")
fails("BOOK_KEY_INVALID", d.check, dict(h, key="local"), "book")
for f in d.HEADER:
    fails("BOOK_HEADER_MISSING", d.check, {k: v for k, v in h.items() if k != f}, "book")

# basebook.py on a fixture (its deploy plan, its release list, its book) in a temp dir; then a book without its header
with tempfile.TemporaryDirectory() as t:
    os.makedirs(os.path.join(t, "deployments"))
    a = lambda n: "0x" + f"{n:040x}"  # noqa: E731
    head = d.header("fixture-testnet", "fixture-testnet", 31337, OTHER, "testnet")
    book = dict(head, token_factory=a(1), ua_registry=a(2), chain_uid=OTHER)
    rel = dict(head, NormalToken={"address": a(3)}, NormalTokenP={"address": a(4)}, Unlisted={"address": a(5)})
    plan = {"transactions": [{"contractName": "GovernanceRouter", "contractAddress": a(6)}]}
    for n, v in (
        ("book.json", book),
        ("rel.json", rel),
        ("plan.json", plan),
    ):  # a book's form: the header first, indent 2
        json.dump(v, open(os.path.join(t, "deployments", n), "w"), indent=2)
    assert (
        open(os.path.join(t, "deployments/book.json")).read().startswith('{\n  "key": "fixture-testnet",\n  "name": ')
    )
    os.environ.update(
        DEPLOY_JSON=os.path.join(t, "deployments/book.json"),
        RELEASES_JSON=os.path.join(t, "deployments/rel.json"),
        PLAN=os.path.join(t, "deployments/plan.json"),
    )
    os.environ.pop("NOTE", None)
    basebook.EVM = t
    sys.argv = ["basebook.py", "fixture"]
    basebook.main()
    got = json.load(open(os.path.join(t, "deployments/onchain-fixture-base.json")))
    assert got == {
        a(6): "GovernanceRouter",
        a(3): "NormalToken",
        a(4): "NormalToken",
        a(1): "OpenFactory",
        a(2): "UARegistry",
    }, got
    json.dump(
        {k: v for k, v in book.items() if k != "network"}, open(os.path.join(t, "deployments/book.json"), "w"), indent=2
    )
    fails("BOOK_HEADER_MISSING", basebook.main)
    json.dump(dict(book, network="mainnet"), open(os.path.join(t, "deployments/book.json"), "w"), indent=2)
    fails("BOOK_NETWORK_MISMATCH", basebook.main)

    # find(): the new name, or BOOK_OLD_NAME when only the old book by chain id is there
    shutil.copy(os.path.join(d.EVM, "chain-uids.json"), t)
    d.EVM = t
    env = {"DEPLOY_NAME": "fixture-testnet"}
    assert d.find(31337, OTHER, env=env) == "deployments/fixture-testnet.json"
    open(os.path.join(t, "deployments/31337-releases.json"), "w").write("{}")
    fails("BOOK_OLD_NAME", d.find, 31337, OTHER, "-releases.json", env=env)
    open(os.path.join(t, "deployments/fixture-testnet-releases.json"), "w").write("{}")
    assert d.find(31337, OTHER, "-releases.json", env=env) == "deployments/fixture-testnet-releases.json"

# deploy sets (owner 2026-11-16, "ok, option 2, one chain, two deploy sets"): the labels, the merge, a reader's book
H = d.header("scaas-testnet", "SCaaS testnet", 7622, SCAAS[1], "testnet")
assert d.set_label("mldsa-off") == "mldsa-off" and d.set_label("mldsa-on", "on") == "mldsa-on"
assert d.set_label("mldsa-on", "") == "mldsa-on"  # MLDSA_PRECOMPILE unset: on (deploy.sh's default)
fails("DEPLOY_SET_UNKNOWN", d.set_label, "mldsa")
fails("DEPLOY_SET_UNKNOWN", d.set_label, "MLDSA-OFF")
fails("DEPLOY_SET_UNKNOWN", d.set_label, "")
fails("DEPLOY_SET_MISMATCH", d.set_label, "mldsa-off", "on")
fails("DEPLOY_SET_MISMATCH", d.set_label, "mldsa-off", "")
fails("DEPLOY_SET_MISMATCH", d.set_label, "mldsa-on", "off")
on = dict(H, ua_registry="0x" + "0a" * 20, mldsa_precompile="on")
off = dict(H, ua_registry="0x" + "0b" * 20, mldsa_precompile="off")
b1 = d.set_merge(on, None, "mldsa-on", "deployments/scaas-testnet-mldsa-on-t66b-releases.json")
assert b1["default_set"] == "mldsa-on" and b1["ua_registry"] == on["ua_registry"]  # no default set yet: this one on top
assert list(b1)[:5] == list(d.HEADER) and set(b1["sets"]) == {"mldsa-on"}
b2 = d.set_merge(off, b1, "mldsa-off", "deployments/scaas-testnet-t66b-releases.json")
assert b2["default_set"] == "mldsa-off" and b2["ua_registry"] == off["ua_registry"]  # the default set on top
assert b2["sets"]["mldsa-on"]["ua_registry"] == on["ua_registry"] and b2["sets"]["mldsa-off"]["set"] == "mldsa-off"
b3 = d.set_merge(
    dict(on, ua_registry="0x" + "0c" * 20), b2, "mldsa-on", "r.json"
)  # a set again: replaced, the default kept
assert b3["ua_registry"] == off["ua_registry"] and b3["sets"]["mldsa-on"]["ua_registry"] == "0x" + "0c" * 20
r = d.set_book(b2, "mldsa-on")
assert r["ua_registry"] == on["ua_registry"] and r["set"] == "mldsa-on" and "sets" not in r and d.check(r, "r")
fails("DEPLOY_SET_MISSING", d.set_book, b1, "mldsa-off")
fails("DEPLOY_SET_UNKNOWN", d.set_book, b2, "mldsa-x")
fails("DEPLOY_SET_UNKNOWN", d.set_merge, on, None, "mldsa-x", "r.json")
fails("BOOK_SET_CHAIN", d.set_merge, on, dict(b1, chainUid=OTHER), "mldsa-on", "r.json")

# plan 2026-11-19-registry-verify-only-kinds Task 13 (spec §9, F14): the later-generation book fields round-trip (red until
# deploybook.gen_fields / gen_check exist)
GEN = {
    "ua_registry": "0x" + "0d" * 20,
    "ua_registry_generation": 2,
    "ua_registry_predecessor": "0x" + "0a" * 20,
    "ua_registry_codehash": "0x" + "11" * 32,
    "ua_registry_libraries": {"UARegistryCoreLib": {"address": "0x" + "0e" * 20, "codehash": "0x" + "12" * 32}},
    "tx_gas_cap": 16777216,
    "tx_gas_cap_probe_rows": [{"gas": 16777216, "accepted": True}, {"gas": 16777217, "accepted": False}],
    "gen_pqz": True,
    "verify_only": {
        "0x0131": {
            "kind": "0x0131",
            "verifier": "0x" + "0f" * 20,
            "cap": 250000,
            "keyForm": 0,
            "precompile": "0x000000000000000000000000000000005caa0013",
            "eip": "EIP-8355",
            "status": "chain-own",
            "probe_rows_hash": "0x" + "13" * 32,
        }
    },
    "owner_overrides": [],
}


def book_fields_roundtrip():
    b = d.gen_fields(dict(H), GEN)
    assert d.gen_check(b, "gen") and {k: b[k] for k in GEN} == GEN
    fails("BOOK_GEN_FIELD", d.gen_check, {k: v for k, v in b.items() if k != "tx_gas_cap"}, "gen")


book_fields_roundtrip()

# NET-ALL-25 (the pair; C18): chain-uids.json as read refuses a second row of one (chainId, chainUid) pair and a private
# chain's genesis anywhere else; the resolver refuses a private chain's genesis under a new chain id; the deploy gate refuses
# a kind keeping homeChain records on a genesis another row shares. Each refusal beside its positive twin.
AVAX = "0x31ced5b9beb7f8782b014660da0cb18cc409f121f408186886e1ca3e8eeca96b"  # avalanche-mainnet 43114, avalanche-testnet 43113
EVM0 = d.EVM = os.path.abspath(os.path.join(HERE, ".."))  # the find() block above left d.EVM on its temp dir


def with_table(edit, f):
    """`f()` against a copy of chain-uids.json changed by `edit(table)`, in a temp dir."""
    t = json.load(open(os.path.join(EVM0, "chain-uids.json")))
    edit(t)
    with tempfile.TemporaryDirectory() as tmp:
        json.dump(t, open(os.path.join(tmp, "chain-uids.json"), "w"), indent=2)
        d.EVM = tmp
        try:
            return f()
        finally:
            d.EVM = EVM0


def row(key, chain_id, uid, private=False):
    return {
        "key": key,
        "name": key,
        "chainId": chain_id,
        "network": key.rsplit("-", 1)[1],
        "testnet": True,
        "chainUid": uid,
        "private": private,
    }


def avalanche_rows_resolve():
    assert d.resolve(43114, AVAX, env={}) == ("avalanche-mainnet", "Avalanche C-Chain", "mainnet")
    assert d.resolve(43113, AVAX, env={}) == ("avalanche-testnet", "Avalanche Fuji", "testnet")
    assert (
        d.resolve(1, "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", env={})[0]
        == "ethereum-mainnet"
    )
    assert (
        d.resolve(61, "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", env={})[0] == "etc-mainnet"
    )


def pair_taken_refused():
    dup = lambda t: t["chains"].append(row("avalanche-copy-testnet", 43113, AVAX))  # noqa: E731
    fails("CHAIN_PAIR_TAKEN", with_table, dup, lambda: d.resolve(43114, AVAX, env={}))
    # twin: the same genesis under a new chain id is a public chain's sharing, accepted
    ok = lambda t: t["chains"].append(row("avalanche-copy-testnet", 43112, AVAX))  # noqa: E731
    assert with_table(ok, lambda: d.resolve(43112, AVAX, env={}))[0] == "avalanche-copy-testnet"


def private_genesis_refused():
    assert [r["key"] for r in d.rows() if r["private"]] == ["scaas-testnet"]
    # the resolver: a private chain's genesis under a new chain id (a fork, a copy), even with DEPLOY_NAME
    fails("CHAIN_UID_PRIVATE", d.resolve, 7623, SCAAS[1], env={"DEPLOY_NAME": "fork-testnet"})
    fails("CHAIN_UID_PRIVATE", d.resolve, 7623, SCAAS[1], env={})
    assert d.resolve(7623, OTHER, env={"DEPLOY_NAME": "fork-testnet"})[0] == "fork-testnet"  # twin: its own genesis
    assert d.resolve(*SCAAS, env={})[0] == "scaas-testnet"  # twin: the private chain itself
    # a public chain's genesis under a new chain id: no private refusal (DEPLOY_NAME as for any unlisted chain)
    assert d.resolve(43112, AVAX, env={"DEPLOY_NAME": "avax-copy-testnet"})[0] == "avax-copy-testnet"
    # the table: a row repeating a private chain's genesis, under another chain id
    rep = lambda t: t["chains"].append(row("fork-testnet", 7623, SCAAS[1].lower()))  # noqa: E731
    fails("CHAIN_UID_PRIVATE", with_table, rep, d.rows)
    pub = lambda t: (rep(t), t["chains"][0].update(private=False))  # noqa: E731
    assert len(with_table(pub, d.rows)) == len(d.rows()) + 1  # twin: the same rows with the chain public
    # a private row whose genesis an earlier public row holds
    late = lambda t: t["chains"].append(row("avax-own-testnet", 7624, AVAX, private=True))  # noqa: E731
    fails("CHAIN_UID_PRIVATE", with_table, late, d.rows)
    # every row says private true | false
    fails("CHAIN_ROW_PRIVATE", with_table, lambda t: t["chains"][3].pop("private"), d.rows)
    fails("CHAIN_ROW_PRIVATE", with_table, lambda t: t["chains"][3].update(private="no"), d.rows)


def home_chain_kinds_refused():
    # UARegistry (review P1-2): UAMsigUpdate and UAPqzScopedKey(Record) bind chain_uid under the portable domain, no chain id
    kinds = ("PqChat", "OpenFactory", "PqVault", "UARegistry")
    assert d.table()["homeChainKinds"] == list(kinds)
    for cid in (43114, 43113):
        for kind in kinds:
            fails("HOME_CHAIN_SHARED_GENESIS", d.kind_check, kind, cid, AVAX)
        assert d.kind_check("PqChatStore", cid, AVAX) == "PqChatStore"  # twin: the store keeps no homeChain record
    for kind in kinds:  # twin: a genesis no other row shares
        assert d.kind_check(kind, *SCAAS) == kind
        assert (
            d.kind_check(kind, 11155111, "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9") == kind
        )
    # a kind name on neither list (a typo) is refused, never passed (review P3-1); a kind of the other list passes
    fails("KIND_UNKNOWN", d.kind_check, "PqChatt", *SCAAS)
    fails("KIND_UNKNOWN", d.kind_check, "uaregistry", 43113, AVAX)
    assert "PqChatStore" in d.table()["otherKinds"] and d.kind_check("RescueVault", 43113, AVAX) == "RescueVault"
    fails("HOME_CHAIN_SHARED_GENESIS", d.kind_check, "PqChat", 43112, AVAX)  # an unlisted chain on a listed genesis
    assert d.kind_check("PqChat", 43112, OTHER) == "PqChat"


for t in (avalanche_rows_resolve, pair_taken_refused, private_genesis_refused, home_chain_kinds_refused):
    try:
        t()
    except BaseException as e:  # noqa: BLE001  the test's name in the failing output (the mutants' `expect`)
        sys.exit(f"FAIL {t.__name__}: {type(e).__name__}: {e}")
print("test_deploybook: ok")
