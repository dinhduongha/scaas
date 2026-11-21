#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Offline checks of deploy_pqchatstore.py (CTR-CHAT-22's deploy path, spec 2026-11-21-avax-polkadot-arweave §5.3, C23) on a
fake chain and synthetic artifacts (no anvil; the anvil run is the gate step `chatstore-cancun`). Books go to a temp dir,
never the real deployments/. `cast keccak` hashes.
  python3 -I script/test_deploy_pqchatstore.py [<test name>…]      (from smartcontracts/evm)
A failing test prints `FAIL <name>` and exits 1. UNAUDITED tooling."""

import json
import os
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import deploy_pqchatstore as d  # noqa: E402
import forkcheck as f  # noqa: E402
from test_forkcheck import STOP, art, write  # noqa: E402

ENV = {"DEPLOY_NAME": "local-testnet"}  # a chain outside chain-uids.json names itself (NET-EVM-13)
UID = "0x" + "ab" * 32
CANCUN = {"evmFork": "cancun", "codeSizeLimit": 24576, "initCodeSizeLimit": 49152}
SEL = {"storeMessage(uint8,bytes8,bytes)": "95660a78", "storedAt(bytes8,uint256)": "905a8035"}


def artifact(tag=0x01):
    """A scannable artifact (runtime PUSH1 <tag> STOP) with the store's selectors."""
    a = art([0x60, tag, STOP], 2, name="PqChatStore")
    a["methodIdentifiers"].update(SEL)
    return a


def release_of(a, **over):
    init, rt = a["bytecode"]["object"], a["deployedBytecode"]["object"]
    ih = d.keccak(init)
    r = {"initCodeHash": ih, "runtimeCodeHash": d.keccak(rt), "address": d.create2_address(ih), "precompiles": []}
    r.update(over)
    return r


class Chain:
    """A fake chain: the deterministic deployer's code (unless `deployer` is False or other code), `at` code already at the
    pinned address, `place` the code a deploy through the deployer leaves there, a store that keeps its payloads."""

    def __init__(self, addr, place, at=None, deployer=d.DEPLOYER_CODE, read_back=None, chain_id=31337, uid=UID):
        self.addr, self.place, self.read_back = addr.lower(), place, read_back
        self.chain_id, self.uid = chain_id, uid
        self.code = {d.DEPLOYER: deployer} if deployer else {}
        if at:
            self.code[self.addr] = at
        self.sent, self.receipts, self.stored = [], {}, []

    def __call__(self, method, params):
        if method == "eth_chainId":
            return {"result": hex(self.chain_id)}
        if method == "eth_getBlockByNumber":
            return {"result": {"hash": self.uid} if params[0] == "0x0" else {"gasLimit": hex(30_000_000)}}
        if method == "eth_getCode":
            return {"result": self.code.get(params[0].lower(), "0x")}
        if method == "eth_estimateGas":
            return {"result": hex(500_000)}
        if method == "eth_call":
            tx = params[0]
            if tx.get("to", "").lower() == self.addr and tx["data"].startswith("0x" + SEL["storedAt(bytes8,uint256)"]):
                i = int(tx["data"][10 + 64 :], 16)
                return {"result": "0x" + d.abi_bytes(self.read_back or self.stored[i]).hex()}
            return {"result": "0x"}
        if method == "eth_sendRawTransaction":
            tx = json.loads(bytes.fromhex(params[0][2:]))
            self.sent.append(tx)
            h = "0x%064x" % len(self.sent)
            logs = []
            if tx["to"].lower() == d.DEPLOYER:
                self.code[self.addr] = self.place
            elif tx["to"].lower() == self.addr:
                p = bytes.fromhex(tx["data"][10:])
                self.stored.append(p)
                logs = [
                    {
                        "address": self.addr,
                        "topics": [d.STORED_TOPIC, "0x" + p[32:40].hex() + "00" * 24],
                        "data": "0x" + d.word(len(self.stored) - 1).hex(),
                    }
                ]
            self.receipts[h] = {"status": "0x1", "gasUsed": hex(400_000), "blockNumber": "0x5", "logs": logs}
            return {"result": h}
        if method == "eth_getTransactionReceipt":
            return {"result": self.receipts.get(params[0])}
        return {"error": {"message": "unknown"}}


def sign(tx):
    return "0x" + json.dumps(tx).encode().hex()


def refused(name, fn, *a, **k):
    try:
        fn(*a, **k)
    except d.StoreError as e:
        assert str(e).startswith(name + ":"), (name, str(e))
        return str(e)
    raise AssertionError(f"{name} expected")


def setup(t, a, rel=None, profile=None):
    write(t, "out/PqChatStore.sol/PqChatStore.json", a)
    write(t, "release-data/PqChatStore.json", rel or release_of(a))
    if profile:
        write(t, "src/chains/local-testnet/profile.json", profile)
    return {
        "out": os.path.join(t, "out"),
        "release": os.path.join(t, "release-data/PqChatStore.json"),
        "books": t,
        "profiles": t,
        "env": ENV,
        "say": lambda s: None,
        "run4": lambda *x: 1,
    }


def run(chain, o, **k):
    return d.deploy([chain], sign, **dict(o, **k))


# ---- the release data


def release_pins_the_create2_address():
    a = artifact()
    r = release_of(a)
    assert d.release_data(r) == r
    refused("CHATSTORE_RELEASE", d.release_data, release_of(a, address="0x" + "11" * 20))  # not CREATE2 at salt 0
    refused("CHATSTORE_RELEASE", d.release_data, {k: v for k, v in r.items() if k != "runtimeCodeHash"})
    refused("CHATSTORE_RELEASE", d.release_data, {k: v for k, v in r.items() if k != "precompiles"})
    # the committed release data: its address is the deployer's CREATE2 of the pinned init-code hash with salt 0
    c = json.load(open(os.path.join(f.EVM, d.RELEASE)))
    assert d.release_data(c) == c and c["precompiles"] == []
    assert d.create2_address(c["initCodeHash"]) == c["address"].lower()


def salt_is_zero():
    assert d.SALT == "00" * 32
    a = artifact()
    with tempfile.TemporaryDirectory() as t:
        o = setup(t, a)
        ch = Chain(release_of(a)["address"], a["deployedBytecode"]["object"])
        run(ch, o)
        assert [x["to"].lower() for x in ch.sent] == [d.DEPLOYER]
        assert ch.sent[0]["data"] == "0x" + "00" * 32 + a["bytecode"]["object"][2:]
        assert ch.sent[0]["gas"] == 500_000  # the chain's estimate, checked by NET-EVM-18 (2)


# ---- the local build against the release data


def local_init_hash_differs_refused():
    a, b = artifact(), artifact()
    b["bytecode"]["object"] += "00"  # another init code (e.g. another compiler setting), the same runtime
    with tempfile.TemporaryDirectory() as t:
        o = setup(t, b, rel=release_of(a))
        ch = Chain(release_of(a)["address"], a["deployedBytecode"]["object"])
        refused("CHATSTORE_INIT_HASH", run, ch, o)
        assert not ch.sent
        o = setup(t, a)  # positive twin
        run(ch, o)
        assert len(ch.sent) == 1


def local_runtime_hash_differs_refused():
    a = artifact()
    rel = release_of(a, runtimeCodeHash=d.keccak(artifact(0x02)["deployedBytecode"]["object"]))
    with tempfile.TemporaryDirectory() as t:
        ch = Chain(rel["address"], a["deployedBytecode"]["object"])
        refused("CHATSTORE_RUNTIME_HASH", run, ch, setup(t, a, rel=rel))
        assert not ch.sent


# ---- the chain


def pinned_code_there_is_done():
    a = artifact()
    rt = a["deployedBytecode"]["object"]
    with tempfile.TemporaryDirectory() as t:
        o = setup(t, a)
        ch = Chain(release_of(a)["address"], None, at=rt)
        assert run(ch, o)["tx"] is None
        assert not ch.sent  # anyone may have deployed it first: no send
        ch = Chain(release_of(a)["address"], rt)  # positive twin: empty, so one send, then done on a second run
        assert run(ch, o)["tx"] and run(ch, o)["tx"] is None and len(ch.sent) == 1


def deployed_code_hash_differs_refused():
    a = artifact()
    addr, other = release_of(a)["address"], artifact(0x02)["deployedBytecode"]["object"]
    with tempfile.TemporaryDirectory() as t:
        o = setup(t, a)
        ch = Chain(addr, None, at=other)  # other code at the pinned address before the send
        refused("CHATSTORE_CODE_HASH", run, ch, o)
        assert not ch.sent
        ch = Chain(addr, other)  # the chain leaves other code after the send
        refused("CHATSTORE_CODE_HASH", run, ch, o)
        assert len(ch.sent) == 1


def deployer_missing_refused():
    a = artifact()
    with tempfile.TemporaryDirectory() as t:
        o = setup(t, a)
        for dep in (None, "0x00"):
            ch = Chain(release_of(a)["address"], a["deployedBytecode"]["object"], deployer=dep)
            refused("CHATSTORE_NO_DEPLOYER", run, ch, o)
            assert not ch.sent


def forkcheck_runs_before_the_send():
    a = artifact()
    with tempfile.TemporaryDirectory() as t:
        ran = []
        o = setup(t, a, profile=CANCUN)
        ch = Chain(release_of(a)["address"], a["deployedBytecode"]["object"])
        run(ch, o, run4=lambda *x: ran.append((x[0], len(ch.sent))) or 1)
        assert ran == [("cancun", 0)], ran  # check (4) at the profile's fork, nothing sent yet

        def red(*x):
            raise f.ForkError("FORKCHECK_EXEC: red")

        ch = Chain(release_of(a)["address"], a["deployedBytecode"]["object"])
        refused("CHATSTORE_FORKCHECK", run, ch, o, run4=red)
        assert not ch.sent


FUJI = (43113, "0x31ced5b9beb7f8782b014660da0cb18cc409f121f408186886e1ca3e8eeca96b")  # avalanche-testnet in chain-uids.json


def fuji_dry_run_needs_a_profile():
    """A Fuji deploy (its key from chain-uids.json) with no profile is refused by name before any send; with the committed
    profile (cancun) the five checks run, each its line, before the send (ARCH-POS-20, review P1-1)."""
    a = artifact()
    with tempfile.TemporaryDirectory() as t:
        o = setup(t, a)
        ch = Chain(release_of(a)["address"], a["deployedBytecode"]["object"], chain_id=FUJI[0], uid=FUJI[1])
        e = refused("CHATSTORE_FORKCHECK", run, ch, o, env={})
        assert "FORKCHECK_PROFILE: avalanche-testnet" in e and not ch.sent, e
        lines, ran = [], []
        run(ch, o, env={}, profiles=None, say=lines.append, run4=lambda *x: ran.append((x[0], x[2], len(ch.sent))) or 1)
        assert ran == [("cancun", 24576, 0)], ran
        for n in ("(1) runtime", "(3) cancun scan ok", "(4) 1 rows at cancun", "(5) 0 precompiles", "(2) gas"):
            assert any(n in s for s in lines), (n, lines)
        assert len(ch.sent) == 1 and os.path.exists(os.path.join(t, "deployments/avalanche-testnet.json"))


def book_entry_under_the_chain_key():
    a = artifact()
    rel = release_of(a)
    with tempfile.TemporaryDirectory() as t:
        o = setup(t, a)
        ch = Chain(rel["address"], a["deployedBytecode"]["object"])
        e = run(ch, o)
        b = json.load(open(os.path.join(t, "deployments/local-testnet.json")))
        assert [b[k] for k in ("key", "chainId", "chainUid", "network")] == ["local-testnet", 31337, UID, "testnet"]
        assert b["PqChatStore"] == e and e["address"] == rel["address"].lower() and e["salt"] == "0x" + "00" * 32
        assert e["runtimeCodeHash"] == rel["runtimeCodeHash"] and e["initCodeHash"] == rel["initCodeHash"]
        b["other"] = 1  # a second run keeps the book's other fields
        write(t, "deployments/local-testnet.json", b)
        run(ch, o)
        assert json.load(open(os.path.join(t, "deployments/local-testnet.json")))["other"] == 1
        refused("CHATSTORE_BOOK", run, ch, dict(o, env={}))  # a chain outside chain-uids.json without DEPLOY_NAME


# ---- the probes before a profile lists the store


def probes_write_and_read():
    a = artifact()
    rel = release_of(a)
    with tempfile.TemporaryDirectory() as t:
        o = setup(t, a)
        ch = Chain(rel["address"], a["deployedBytecode"]["object"])
        refused("CHATSTORE_CODE_HASH", d.probe, [ch], sign, **o)  # nothing deployed yet
        run(ch, o)
        p = d.probe([ch], sign, **o)
        assert ch.stored == [d.payload(1, d.PROBE_HINT, d.PROBE_ENV)] and p["index"] == 0
        assert json.load(open(os.path.join(t, "deployments/local-testnet.json")))["PqChatStore"]["probe"] == p
        ch.read_back = d.payload(1, d.PROBE_HINT, b"other")  # a chain whose SSTORE2 read gives other bytes
        refused("CHATSTORE_PROBE", d.probe, [ch], sign, **o)
        ch.read_back = None
        ch.code[d.DEPLOYER] = "0x"
        refused("CHATSTORE_NO_DEPLOYER", d.probe, [ch], sign, **o)


def abi_encoding():
    assert d.keccak("0x" + b"PqChatStored(bytes8,uint256)".hex()) == d.STORED_TOPIC
    assert d.keccak("0x" + b"scaas.pqchatstore.probe".hex())[:18] == "0x" + d.PROBE_HINT.hex()
    h = bytes.fromhex("0102030405060708")
    p = d.payload(1, h, bytes.fromhex("abcdef"))
    assert p.hex() == (
        "00" * 31 + "01" + "0102030405060708" + "00" * 24 + "00" * 31 + "60" + "00" * 31 + "03" + "abcdef" + "00" * 29
    )
    assert d.abi_bytes(b"\x01").hex() == "00" * 31 + "20" + "00" * 31 + "01" + "01" + "00" * 31
    assert d.abi_bytes_array([]).hex() == "00" * 31 + "20" + "00" * 32
    two = d.abi_bytes_array([b"\x01", b""]).hex()  # offset, count, the two offsets (past the count), then each element
    assert two[: 64 * 4] == "20".rjust(64, "0") + "2".rjust(64, "0") + "40".rjust(64, "0") + "80".rjust(64, "0")
    assert two[64 * 4 :] == "1".rjust(64, "0") + "01".ljust(64, "0") + "0" * 64


TESTS = [
    release_pins_the_create2_address,
    salt_is_zero,
    local_init_hash_differs_refused,
    local_runtime_hash_differs_refused,
    pinned_code_there_is_done,
    deployed_code_hash_differs_refused,
    deployer_missing_refused,
    forkcheck_runs_before_the_send,
    fuji_dry_run_needs_a_profile,
    book_entry_under_the_chain_key,
    probes_write_and_read,
    abi_encoding,
]


def main(names):
    tests = [t for t in TESTS if not names or t.__name__ in names]
    assert tests, f"no test named {names}"
    passed = 0
    for t in tests:
        try:
            t()
        except Exception:
            traceback.print_exc()
            print(f"FAIL {t.__name__}")
            continue
        passed += 1
        print(f"ok {t.__name__}")
    print(f"ok {passed}/{len(tests)}" if passed == len(tests) else f"FAILED {passed}/{len(tests)}")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
