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

SCAAS = (7622, "0xF1F491ABEC46EB7C1784B7FC75A0174171B41831530E510C46B7178C02D63164")  # case does not matter
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
    for n, v in (("book.json", book), ("rel.json", rel), ("plan.json", plan)):
        json.dump(v, open(os.path.join(t, "deployments", n), "w"))
    os.environ.update(DEPLOY_JSON=os.path.join(t, "deployments/book.json"), RELEASES_JSON=os.path.join(t, "deployments/rel.json"),
                      PLAN=os.path.join(t, "deployments/plan.json"))
    os.environ.pop("NOTE", None)
    basebook.EVM = t
    sys.argv = ["basebook.py", "fixture"]
    basebook.main()
    got = json.load(open(os.path.join(t, "deployments/onchain-fixture-base.json")))
    assert got == {a(6): "GovernanceRouter", a(3): "NormalToken", a(4): "NormalToken", a(1): "OpenFactory",
                   a(2): "UARegistry"}, got
    json.dump({k: v for k, v in book.items() if k != "network"}, open(os.path.join(t, "deployments/book.json"), "w"))
    fails("BOOK_HEADER_MISSING", basebook.main)
    json.dump(dict(book, network="mainnet"), open(os.path.join(t, "deployments/book.json"), "w"))
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

print("test_deploybook: ok")
