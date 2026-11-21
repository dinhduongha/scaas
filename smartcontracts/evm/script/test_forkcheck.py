#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Offline checks of forkcheck.py (NET-EVM-18's five deploy checks) on synthetic forge artifacts and fake RPC nodes (no chain,
no forge, no anvil; the anvil run is the gate step `forkcheck`):
  python3 -I script/test_forkcheck.py [<test name>…]      (from smartcontracts/evm)
A failing test prints `FAIL <name>` and exits 1. UNAUDITED tooling."""

import json
import os
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import forkcheck as f  # noqa: E402

CBOR = bytes.fromhex("a164736f6c6343000825")  # {"solc": 0.8.37}, as bytecode_hash = "none" writes it
STOP, INVALID, PUSH1, CLZ, DUPN = 0x00, 0xFE, 0x60, 0x1E, 0xE6
CTOR = [0x60, 0x0A, 0x60, 0x00, 0xF3]  # PUSH1 PUSH1 RETURN: 3 instructions


def art(rt_code, n_rt, init_code=CTOR, n_init=3, rt_data=b"", init_data=b"", name="Fx", meta=CBOR):
    """A forge artifact: runtime = code ‖ INVALID ‖ data ‖ CBOR ‖ len; init = code ‖ INVALID ‖ runtime ‖ data; the source
    maps hold n entries (the compiler's instruction count)."""
    rt = bytes(rt_code) + bytes([INVALID]) + rt_data + meta + len(meta).to_bytes(2, "big")
    init = bytes(init_code) + bytes([INVALID]) + rt + init_data
    return {
        "_name": name,
        "bytecode": {"object": "0x" + init.hex(), "sourceMap": "0:1:0:-:0" + ";" * (n_init - 1)},
        "deployedBytecode": {
            "object": "0x" + rt.hex(),
            "sourceMap": "0:1:0:-:0" + ";" * (n_rt - 1),
            "immutableReferences": {},
        },
        "methodIdentifiers": {"f()": "26121ff0", "lz(uint256)": "aaaaaaaa"},
    }


def refused(name, fn, *a, **k):
    try:
        fn(*a, **k)
    except f.ForkError as e:
        assert str(e).startswith(name + ":"), (name, str(e))
        return str(e)
    raise AssertionError(f"{name} expected")


# ---- check (3): the allow-list scan


def scan_clz_refused_for_cancun():
    a = art([PUSH1, 0x01, CLZ, STOP], 3)
    refused("FORKCHECK_OPCODE", f.scan, a, "cancun")
    f.scan(a, "amsterdam")  # the compile target has it
    f.scan(art([PUSH1, 0x01, 0x15, STOP], 3), "cancun")  # positive twin: ISZERO instead of CLZ


def scan_clz_in_init_refused():
    refused("FORKCHECK_OPCODE", f.scan, art([STOP], 1, init_code=[PUSH1, 1, CLZ, *CTOR], n_init=5), "cancun")


def push_data_1e_passes():
    f.scan(art([PUSH1, CLZ, 0x7F, *([CLZ] * 32), STOP], 3), "cancun")  # PUSH1 0x1e, PUSH32 0x1e…1e, STOP


def unknown_immediate_refused():
    refused("FORKCHECK_UNPLACED", f.scan, art([DUPN, 0x01, STOP], 2), "amsterdam")
    refused("FORKCHECK_UNPLACED", f.scan, art([0x0C, STOP], 2), "amsterdam")  # no opcode at all
    refused("FORKCHECK_BOUNDARY", f.scan, art([0x61, 0x01], 1), "cancun")  # PUSH2's immediate runs past the code


def boundaries_from_the_compiler():
    # data between the code and the metadata (e.g. a sub-object) cannot be placed: refused, never walked or skipped
    refused("FORKCHECK_BOUNDARY", f.scan, art([STOP], 1, rt_data=bytes([CLZ])), "cancun")
    refused("FORKCHECK_BOUNDARY", f.scan, art([STOP], 1, init_data=b"\x00" * 32), "cancun")
    # a source map that counts more or fewer instructions than the code
    refused("FORKCHECK_BOUNDARY", f.scan, art([STOP, STOP], 3), "cancun")
    refused("FORKCHECK_BOUNDARY", f.scan, art([STOP, STOP], 1), "cancun")
    # no CBOR metadata at the end
    refused("FORKCHECK_BOUNDARY", f.scan, art([STOP], 1, meta=b"\x00\x01"), "cancun")
    # the CBOR (its bytes 0x64 PUSH5, 0x25 no opcode) and the constructor arguments are data, never scanned
    g = f.scan(art([STOP], 1), "cancun", args=bytes([CLZ, DUPN]))
    assert g["args"] == bytes([CLZ, DUPN])
    a = art([STOP], 1)
    a["deployedBytecode"]["sourceMap"] = ""
    refused("FORKCHECK_BOUNDARY", f.scan, a, "cancun")
    a = art([STOP], 1)
    a["bytecode"]["object"] += "__$abc$__"
    refused("FORKCHECK_ARTIFACT", f.scan, a, "cancun")
    refused("FORKCHECK_FORK_UNKNOWN", f.scan, art([STOP], 1), "frontier")


def asm(rt_data=(), init_data=(), subs=1):
    """A legacy assembly as solc writes it: data sections keyed by their hash, the runtime as sub-assembly 0."""
    rt = {".code": [], ".data": {k: v.hex() for k, v in rt_data}} if rt_data else {".code": []}
    out = {".code": [], ".data": {str(i): rt for i in range(subs)}}
    out[".data"].update({k: v.hex() for k, v in init_data})
    return out


K1, K2 = "0A" + "00" * 31, "F0" + "00" * 31  # two data keys; solc lays the sections out by key, ascending


def data_sections_from_the_assembly():
    """Data sections (the constant optimiser's, string data) are placed by the compiler's legacy assembly, never guessed."""
    d1, d2 = bytes([CLZ] * 32), bytes([DUPN, 0x0C])
    a = art([STOP], 1, rt_data=d1 + d2, init_data=d2)
    a["legacyAssembly"] = asm(rt_data=[(K2, d2), (K1, d1)], init_data=[(K1, d2)])
    f.scan(a, "cancun")  # 0x1e, 0xe6 and 0x0c inside data are never walked
    del a["legacyAssembly"]
    refused("FORKCHECK_BOUNDARY", f.scan, a, "cancun")  # the same bytes without the assembly: unplaced
    a["legacyAssembly"] = asm(rt_data=[(K1, d2), (K2, d1)], init_data=[(K1, d2)])
    refused("FORKCHECK_BOUNDARY", f.scan, a, "cancun")  # sections in another order than the assembly's
    a["legacyAssembly"] = asm(rt_data=[(K2, d2), (K1, d1)])
    refused("FORKCHECK_BOUNDARY", f.scan, a, "cancun")  # the init code's data not listed
    b = art([STOP], 1)
    b["legacyAssembly"] = asm(subs=2)
    refused("FORKCHECK_BOUNDARY", f.scan, b, "cancun")  # a second sub-assembly: code the walk does not reach
    b["legacyAssembly"] = asm()
    f.scan(b, "cancun")


# ---- check (1): the caps from the profile

AVAX = {"evmFork": "cancun", "codeSizeLimit": 24576, "initCodeSizeLimit": 49152}


def sized(rt_len, init_len, args=b""):
    code = [0x5B] * (rt_len - len(CBOR) - 3)  # JUMPDEST…, INVALID, CBOR, its length
    a = art(code, len(code))
    pad = init_len - len(CTOR) - 1 - rt_len
    a["bytecode"]["object"] = "0x" + bytes(CTOR + [INVALID]).hex() + a["deployedBytecode"]["object"][2:] + "00" * pad
    return {
        "_name": "Fx",
        "runtime": bytes.fromhex(a["deployedBytecode"]["object"][2:]),
        "init": bytes.fromhex(a["bytecode"]["object"][2:]),
        "args": args,
    }


def sizes_against_the_profile():
    f.check_sizes(sized(24576, 49152), AVAX)
    refused("FORKCHECK_SIZE", f.check_sizes, sized(24577, 30000), AVAX)
    refused("FORKCHECK_SIZE", f.check_sizes, sized(24576, 49153), AVAX)
    refused("FORKCHECK_SIZE", f.check_sizes, sized(24576, 49152, args=b"\x00"), AVAX)  # the arguments count
    f.check_sizes(sized(65536, 70000), dict(AVAX, codeSizeLimit=65536, initCodeSizeLimit=131072))


# ---- the profile and the set gate


def write(root, rel, obj):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        json.dump(obj, fh)


def profile_and_set_gate():
    with tempfile.TemporaryDirectory() as t:
        # no file: only the reset chain and a local anvil are amsterdam (ARCH-POS-20, review P1-1); any other key refused
        assert f.profile("scaas-testnet", t) == {"evmFork": "amsterdam"}
        f.set_gate("scaas-testnet", t)
        assert f.profile("local-31337-testnet", t) == f.profile("local-testnet", t) == {"evmFork": "amsterdam"}
        refused("FORKCHECK_PROFILE", f.profile, "avalanche-testnet", t)
        refused("FORKCHECK_PROFILE", f.set_gate, "ethereum-testnet", t)
        refused("FORKCHECK_PROFILE", f.profile, "local-mainnet", t)
        refused("FORKCHECK_PROFILE", f.profile, "scaas-testnet-2", t)
        write(t, "src/chains/avalanche-testnet/profile.json", AVAX)
        assert f.profile("avalanche-testnet", t)["codeSizeLimit"] == 24576
        refused("FORKCHECK_SET_FORK", f.set_gate, "avalanche-testnet", t)
        write(t, "src/chains/x-testnet/profile.json", {"evmFork": "cancun", "codeSizeLimit": 24576})
        refused("FORKCHECK_PROFILE", f.profile, "x-testnet", t)
        write(t, "src/chains/y-testnet/profile.json", {"evmFork": "byzantium"})
        refused("FORKCHECK_FORK_UNKNOWN", f.profile, "y-testnet", t)
        refused("FORKCHECK_PROFILE", f.profile, "../x", t)
        write(t, "src/chains/z-testnet/profile.json", dict(AVAX, txGasCap="16777216"))
        refused("FORKCHECK_PROFILE", f.profile, "z-testnet", t)
        write(t, "src/chains/z-testnet/profile.json", dict(AVAX, txGasCap=None))
        f.profile("z-testnet", t)


def real_tree_profiles():
    """The committed profiles: Avalanche at cancun with its caps; every chain-uids.json key has a profile or is refused by
    name (none falls back to amsterdam but the reset chain)."""
    for k in ("avalanche-mainnet", "avalanche-testnet"):
        pr = f.profile(k)
        assert (pr["evmFork"], pr["codeSizeLimit"], pr["initCodeSizeLimit"]) == ("cancun", 24576, 49152), (k, pr)
        assert pr["txGasCap"] is None and isinstance(pr["blockGasLimit"], int), (k, pr)
        refused("FORKCHECK_SET_FORK", f.set_gate, k)
    assert f.profile("scaas-testnet") == {"evmFork": "amsterdam"}
    keys = [r["key"] for r in json.load(open(os.path.join(f.EVM, "chain-uids.json")))["chains"]]
    for k in keys:
        if os.path.exists(os.path.join(f.EVM, "src", "chains", k, "profile.json")) or k == "scaas-testnet":
            f.profile(k)
        else:
            refused("FORKCHECK_PROFILE", f.profile, k)


# ---- checks (2) and (5) against fake nodes


def node(block=32_000_000, cap=None, estimate=1_000_000, pre=None, head=0x100, extra=0, fork=False):
    """A fake chain node: `cap` its per-transaction gas cap (None: none), `pre` its precompiles {address: {input: output}};
    `head` its latest block number, `extra` a value in the fields outside consensus (size, totalDifficulty), `fork` other
    block hashes."""
    pre = pre or {}

    def rpc(method, params):
        if method == "eth_blockNumber":
            return {"result": hex(head)}
        if method == "eth_getBlockByNumber":
            n = head if params[0] == "latest" else int(params[0], 16)
            if n > head:
                return {"result": None}
            h = "0x%064x" % (n + (1 << 255 if fork else 0))
            return {"result": {"number": hex(n), "hash": h, "gasLimit": hex(block), "size": hex(extra),
                               "totalDifficulty": hex(extra)}}  # fmt: skip
        if method == "eth_estimateGas":
            return {"result": hex(estimate)}
        if method == "eth_call":
            tx = params[0]
            if tx.get("to") in pre:
                return {"result": pre[tx["to"]].get(tx.get("data"), "0x")}
            if cap is not None and int(tx.get("gas", "0x0"), 16) > cap:
                return {"error": {"code": -32000, "message": f"transaction gas limit too high (cap: {cap})"}}
            return {"result": "0x"}
        return {"error": {"message": "unknown"}}

    return rpc


P256 = "0x0000000000000000000000000000000000000100"
KAT = {"address": P256, "name": "P-256", "input": "0x" + "11" * 160, "output": "0x" + "00" * 31 + "01"}


def gas_against_the_live_caps():
    assert f.check_gas([node()] * 3, "0x00") == (1_000_000, 32_000_000)
    refused("FORKCHECK_GAS", f.check_gas, [node(estimate=32_000_001)] * 3, "0x00")
    refused("FORKCHECK_GAS", f.check_gas, [node()], "0x00", gas_limit=40_000_000)
    refused("FORKCHECK_GAS", f.check_gas, [node(cap=1 << 24)], "0x00", gas_limit=(1 << 24) + 1)
    assert f.check_gas([node(cap=1 << 24)], "0x00", gas_limit=1 << 24)[0] == 1 << 24
    refused("FORKCHECK_NODES", f.check_gas, [node(), node(block=10)], "0x00")
    # the profile's per-transaction cap (txGasCap; null: none) beside the chain's
    refused("FORKCHECK_GAS", f.check_gas, [node()], "0x00", gas_limit=1_000_001, tx_cap=1_000_000)
    assert f.check_gas([node()], "0x00", gas_limit=1_000_000, tx_cap=1_000_000)[0] == 1_000_000


def precompile_known_answer():
    ok = node(pre={P256: {KAT["input"]: KAT["output"]}})
    assert f.check_precompiles([ok] * 3, [KAT]) == 1
    refused("FORKCHECK_PRECOMPILE", f.check_precompiles, [node()] * 3, [KAT])  # the chain lacks it: "0x"
    wrong = node(pre={P256: {KAT["input"]: "0x" + "00" * 32}})
    refused("FORKCHECK_PRECOMPILE", f.check_precompiles, [wrong], [KAT])
    assert f.precompiles({"precompiles": []}) == []
    refused("FORKCHECK_RELEASE_DATA", f.precompiles, {})
    refused("FORKCHECK_RELEASE_DATA", f.precompiles, {"precompiles": [{"address": P256}]})


def deploy_gate_runs_every_check():
    """The deploy path on a cancun profile: (1) (3) offline, (4) by its runner, (5) and (2) on the nodes; amsterdam: none."""
    with tempfile.TemporaryDirectory() as t:
        write(t, "src/chains/avalanche-testnet/profile.json", AVAX)
        write(t, "out/Fx.sol/Fx.json", art([STOP], 1))
        write(t, "release-data/Fx.json", {"precompiles": [KAT]})
        write(t, "cases.json", {"contracts": [{"artifact": "Fx.sol/Fx.json", "cases": [{"name": "f", "sig": "f()", "ok": True}]}]})
        ran, lines = [], []
        run4 = lambda *a: ran.append(a) or 3  # noqa: E731
        good = node(pre={P256: {KAT["input"]: KAT["output"]}})
        f.deploy_gate(
            "avalanche-testnet", "out/Fx.sol/Fx.json", [good], "cases.json", root=t, run4=run4, say=lines.append
        )
        assert ran and ran[0][0] == "cancun" and ran[0][2] == 24576, ran
        assert any("(5) 1 precompiles" in s for s in lines) and any("(2) gas" in s for s in lines), lines
        refused(
            "FORKCHECK_PRECOMPILE",
            f.deploy_gate,
            "avalanche-testnet",
            "out/Fx.sol/Fx.json",
            [node()],
            "cases.json",
            root=t,
            run4=run4,
            say=lines.append,
        )
        refused(
            "FORKCHECK_GAS",
            f.deploy_gate,
            "avalanche-testnet",
            "out/Fx.sol/Fx.json",
            [node(estimate=10**9, pre={P256: {KAT["input"]: KAT["output"]}})],
            "cases.json",
            root=t,
            run4=run4,
            say=lines.append,
        )
        refused(
            "FORKCHECK_CASES",
            f.deploy_gate,
            "avalanche-testnet",
            "out/Fx.sol/Fx.json",
            [good],
            None,
            root=t,
            run4=run4,
            say=lines.append,
        )
        write(t, "out/Clz.sol/Clz.json", art([PUSH1, 1, CLZ, STOP], 3, name="Clz"))
        refused(
            "FORKCHECK_OPCODE",
            f.deploy_gate,
            "avalanche-testnet",
            "out/Clz.sol/Clz.json",
            [good],
            "cases.json",
            root=t,
            run4=run4,
            say=lines.append,
        )
        write(t, "src/chains/capped-testnet/profile.json", dict(AVAX, txGasCap=999_999))  # the profile's tx cap applies
        refused("FORKCHECK_GAS", f.deploy_gate, "capped-testnet", "out/Fx.sol/Fx.json", [good], "cases.json", root=t,
                run4=run4, say=lines.append)  # fmt: skip
        os.remove(os.path.join(t, "release-data/Fx.json"))
        refused(
            "FORKCHECK_RELEASE_DATA",
            f.deploy_gate,
            "avalanche-testnet",
            "out/Fx.sol/Fx.json",
            [good],
            "cases.json",
            root=t,
            run4=run4,
            say=lines.append,
        )
        ran.clear()
        f.deploy_gate("scaas-testnet", "out/Clz.sol/Clz.json", [], root=t, run4=run4, say=lines.append)
        assert not ran  # amsterdam: nothing to check


def majority_on_the_used_fields():
    """Honest nodes differ in their head, in fields outside consensus and in their estimates: the vote is on the value used
    (a block's hash and gas limit at a number below the majority's head, the estimate a strict majority reaches), never
    the whole answer (review P2-2)."""
    honest = [node(head=0x100 + i, extra=i, estimate=1_000_000 + 10 * i) for i in range(3)]
    assert f.check_gas(honest, "0x00") == (1_000_010, 32_000_000)
    assert f.check_gas(honest[:1], "0x00") == (1_000_000, 32_000_000)
    # one node on another branch (other hashes) is outvoted; three different blocks: no strict majority
    assert f.check_gas(honest[:2] + [node(fork=True)], "0x00")[1] == 32_000_000
    refused("FORKCHECK_NODES", f.check_gas, [honest[0], node(fork=True), node(block=10)], "0x00")
    refused("FORKCHECK_NODES", f.check_gas, [honest[0], node(block=10, extra=5)], "0x00")
    # a number a strict majority reaches: the median; a hostile high or low answer moves nothing past an honest one
    est = [node(estimate=e) for e in (1_000_000, 1_000_005, 10**12)]
    assert f.majority_number(est, "eth_estimateGas", [{}]) == 1_000_005
    refused("FORKCHECK_NODES", f.majority_number, [node(), lambda m, p: {"error": {}}], "eth_estimateGas", [{}])
    # an answer the field cannot be read from is malformed, never a vote for a value
    bad = lambda m, p: {"result": {"gasLimit": 7}} if m == "eth_getBlockByNumber" else node()(m, p)  # noqa: E731
    refused("FORKCHECK_NODES", f.check_gas, [bad, bad, honest[0]], "0x00")
    assert f.check_gas([bad, honest[0], honest[0]], "0x00")[1] == 32_000_000


def cases_bound_to_the_contract():
    """Check (4) runs the cases of the contract under deploy: a cases file whose entries are another artifact's (by bytes), an
    empty file or an entry without a case is refused before anything runs (review P2-5)."""
    with tempfile.TemporaryDirectory() as t:
        write(t, "src/chains/avalanche-testnet/profile.json", AVAX)
        write(t, "out/Fx.sol/Fx.json", art([STOP], 1))
        write(t, "out/Foo.sol/Foo.json", art([PUSH1, 2, STOP], 2, name="Foo"))
        write(t, "out/Copy.sol/Fx.json", art([STOP], 1))  # the same bytes under another path: the same contract
        write(t, "release-data/Foo.json", {"precompiles": []})
        good = node()
        one = [{"name": "f", "sig": "f()", "ok": True}]
        ran = []

        def gate(cases):
            write(t, "cases.json", cases)
            ran.clear()
            f.deploy_gate("avalanche-testnet", "out/Foo.sol/Foo.json", [good], "cases.json", root=t,
                          run4=lambda *a: ran.append(a) or 1, say=lambda s: None)  # fmt: skip

        for bad in (
            {"contracts": [{"artifact": "Fx.sol/Fx.json", "cases": one}]},  # another contract's cases
            {"contracts": [{"artifact": "Foo.sol/Foo.json", "cases": one}, {"artifact": "Fx.sol/Fx.json", "cases": one}]},
            {"contracts": []},
            {"contracts": [{"artifact": "Foo.sol/Foo.json", "cases": []}]},
            {},
        ):
            refused("FORKCHECK_CASES", gate, bad)
            assert not ran
        gate({"contracts": [{"artifact": "Foo.sol/Foo.json", "cases": one}]})  # twin
        assert ran
        write(t, "release-data/Fx.json", {"precompiles": []})
        write(t, "cases.json", {"contracts": [{"artifact": "Copy.sol/Fx.json", "cases": one}]})
        f.deploy_gate("avalanche-testnet", "out/Fx.sol/Fx.json", [good], "cases.json", root=t, run4=lambda *a: 1,
                      say=lambda s: None)  # fmt: skip


# ---- check (4): the control must be red


def fake_evm(control_green, mode=None):
    """A fake anvil: deploys succeed; a call to the control (deployed first) succeeds only when `control_green`; the other
    contract's `f()` returns 1. `mode`: "nodeploy" the control's deploy reverts, "half" its call errors but its transaction
    succeeds, "transport" its call gets no answer."""
    st = {"n": 0, "receipts": {}}
    one = "0x" + "00" * 31 + "01"
    ctl = "0x" + f"{1:040x}"

    def outcome(tx, send=False):
        if "to" not in tx:
            st["n"] += 1
            return mode != "nodeploy" or st["n"] > 1, "0x", "0x" + f"{st['n']:040x}"
        if tx["to"] == ctl:
            return control_green or (send and mode == "half"), "0x" + "00" * 31 + "ff", None
        return True, one, None

    def rpc(method, params):
        if method == "eth_accounts":
            return {"result": ["0x" + "aa" * 20]}
        if method == "eth_getBlockByNumber":
            return {"result": {"gasLimit": hex(30_000_000)}}
        if method == "eth_getCode":
            return {"result": art([STOP], 1)["deployedBytecode"]["object"]}
        if method == "eth_call":
            if mode == "transport" and params[0].get("to") == ctl:
                return {"error": {"message": "no answer (URLError)", "transport": True}}
            ok, ret, _ = outcome(params[0]) if "to" in params[0] else (True, "0x", None)
            return {"result": ret} if ok else {"error": {"message": "invalid opcode"}}
        if method == "eth_sendTransaction":
            ok, _, addr = outcome(params[0], send=True)
            h = "0x%064x" % (len(st["receipts"]) + 1)
            st["receipts"][h] = {"status": "0x1" if ok else "0x0", "gasUsed": "0x5208", "contractAddress": addr}
            return {"result": h}
        if method == "eth_getTransactionReceipt":
            return {"result": st["receipts"].get(params[0])}
        return {"error": {"message": "unknown"}}

    return rpc


def control_green_voids_the_run():
    with tempfile.TemporaryDirectory() as t:
        write(t, "out/" + f.CONTROL["cancun"]["artifact"], art([STOP], 1, name="ForkcheckClz"))
        write(t, "out/Fx.sol/Fx.json", art([STOP], 1))
        cs = [
            {
                "artifact": "Fx.sol/Fx.json",
                "cases": [{"name": "f", "sig": "f()", "ok": True, "return": "0x" + "00" * 31 + "01"}],
            }
        ]
        lines = []
        assert f.execute(fake_evm(False), "cancun", cs, lines.append, t) == 3  # control red, deploy and f() green
        assert any(s.startswith("control: red at cancun") for s in lines), lines
        refused("FORKCHECK_CONTROL", f.execute, fake_evm(True), "cancun", cs, lines.append, t)
        bad = [dict(cs[0], cases=[dict(cs[0]["cases"][0], **{"return": "0x" + "00" * 32})])]
        refused("FORKCHECK_EXEC", f.execute, fake_evm(False), "cancun", bad, lines.append, t)
        refused("FORKCHECK_FORK_UNKNOWN", f.execute, fake_evm(False), "osaka", cs, lines.append, t)


def control_red_for_its_reason():
    """The control is red only for the missing opcode: its deploy green, its call an execution error and its receipt status
    0; a deploy that reverts, a call with no answer, or a call red with a transaction green is FORKCHECK_CONTROL, never a
    red control (review P2-6). The positive run: at the fork with the opcode the control is green with its amsterdam
    answer, and the same run under the cancun control's expectation is void."""
    with tempfile.TemporaryDirectory() as t:
        write(t, "out/" + f.CONTROL["cancun"]["artifact"], art([STOP], 1, name="ForkcheckClz"))
        write(t, "out/Fx.sol/Fx.json", art([STOP], 1))
        cs = [{"artifact": "Fx.sol/Fx.json", "cases": [{"name": "f", "sig": "f()", "ok": True}]}]
        for mode, why in (("nodeploy", "did not run"), ("transport", "did not run"), ("half", "is green")):
            e = refused("FORKCHECK_CONTROL", f.execute, fake_evm(False, mode), "cancun", cs, lambda s: None, t)
            assert why in e, (mode, e)
        assert f.execute(fake_evm(False), "cancun", cs, lambda s: None, t) == 3  # twin: red for its reason
        lines = []
        assert f.control_check(fake_evm(True), "cancun", lines.append, t) == 2
        assert any("green" in s for s in lines), lines
        e = refused("FORKCHECK_CONTROL", f.control_check, fake_evm(False), "cancun", lambda s: None, t)
        assert "not green" in e, e


def case_from_revert_logs():
    """A case's optional fields: `from` (an account index), `revert` (the revert data), `logs` (the receipt's logs, each the
    contract's own), each compared exactly, each with its positive twin."""
    at, top, one, two = "0x" + "cc" * 20, "0x" + "50" * 32, "0x" + "00" * 31 + "01", "0x" + "00" * 31 + "02"
    accts = ["0x" + "aa" * 20, "0x" + "bb" * 20]
    st = {"log_at": at}

    def rpc(method, params):
        tx = params[0] if params else {}
        sel = (tx.get("data") or "")[:10] if isinstance(tx, dict) else ""
        if method == "eth_getCode":
            return {"result": art([STOP], 1)["deployedBytecode"]["object"]}
        if method == "eth_call":
            if sel == "0x26121ff0":  # f(): returns 1 for the second account, else 2
                return {"result": one if tx["from"] == accts[1] else two}
            return {"error": {"code": 3, "message": "execution reverted", "data": "0x0c92e8bd"}}
        if method == "eth_sendTransaction":
            st["last"] = tx
            return {"result": "0x" + "11" * 32}
        if method == "eth_getTransactionReceipt":
            tx = st["last"]
            if "to" not in tx:
                return {"result": {"status": "0x1", "gasUsed": "0x1", "contractAddress": at, "logs": []}}
            ok = tx["data"][:10] == "0x26121ff0"
            logs = [{"address": st["log_at"], "topics": [top], "data": one}] if ok else []
            return {"result": {"status": "0x1" if ok else "0x0", "gasUsed": "0x2", "logs": logs}}
        return {"error": {"message": "unknown"}}

    a = art([STOP], 1)
    a["methodIdentifiers"]["g()"] = "e2179b8e"

    def passed(c):
        return [r[1] for r in f.run_contract(rpc, accts, 30_000_000, a, "0x", [c])] == [True, True]

    f_ = {"name": "f", "sig": "f()", "ok": True}
    assert passed(dict(f_, **{"from": 1, "return": one}))
    assert not passed(dict(f_, **{"return": one}))  # the first account: 2
    assert passed(dict(f_, **{"return": two}))
    g = {"name": "g", "sig": "g()", "ok": False}
    assert passed(dict(g, revert="0x0c92e8bd"))
    assert not passed(dict(g, revert="0x4e487b71"))
    assert passed(dict(f_, logs=[{"topics": [top], "data": one}]))
    assert not passed(dict(f_, logs=[{"topics": [top], "data": two}]))
    assert not passed(dict(f_, logs=[]))
    st["log_at"] = "0x" + "dd" * 20  # a log of another contract
    assert not passed(dict(f_, logs=[{"topics": [top], "data": one}]))


TESTS = [
    scan_clz_refused_for_cancun,
    scan_clz_in_init_refused,
    push_data_1e_passes,
    unknown_immediate_refused,
    boundaries_from_the_compiler,
    data_sections_from_the_assembly,
    sizes_against_the_profile,
    profile_and_set_gate,
    real_tree_profiles,
    gas_against_the_live_caps,
    precompile_known_answer,
    majority_on_the_used_fields,
    deploy_gate_runs_every_check,
    cases_bound_to_the_contract,
    control_green_voids_the_run,
    control_red_for_its_reason,
    case_from_revert_logs,
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
