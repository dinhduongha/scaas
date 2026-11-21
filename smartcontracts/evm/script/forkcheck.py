#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""NET-EVM-18 (owner 2026-11-21, ARCH-POS-19 Q1; the checks ARCH-POS-20 C5; spec 2026-11-21-avax-polkadot-arweave §4.5): on a
chain without the Amsterdam fork a contract deploys only when its `amsterdam` build fits that chain. NET-EVM-06 is unchanged
(one compile target); the deploy path runs five checks before it sends, each refusal named:
  (1) FORKCHECK_SIZE       runtime and init code (with the constructor arguments) within the profile's caps;
  (2) FORKCHECK_GAS        the deploy transaction's gas within the live block gas limit and accepted under the chain's
                           per-transaction cap (an eth_call at that gas, tx_gas_cap.py's refusal words);
  (3) FORKCHECK_OPCODE     every byte in code position is an opcode of the chain's fork (an allow-list, FORKS); the walk
      FORKCHECK_UNPLACED   takes each immediate's length from the compile target's table (AMSTERDAM: PUSH1-PUSH32); a byte
      FORKCHECK_BOUNDARY   that table cannot place is a refusal; the code ends where the compiler's source map says (its
                           instruction count), then the INVALID solc writes, then in the init code exactly the runtime, then
                           the data sections the compiler's legacy assembly lists (none without it), then in the runtime
                           exactly the CBOR metadata (its length the last two bytes); anything else is a refusal;
  (4) FORKCHECK_EXEC       the contract's cases run as real transactions on `anvil --hardfork <fork>` on the `amsterdam`
      FORKCHECK_CONTROL    artifact's bytes (never a recompile), beside the fork's control fixture, whose case must be red
                           (a green control voids the run); gas at that fork is printed as a record, never compared with the
                           Amsterdam pins;
  (5) FORKCHECK_PRECOMPILE every precompile the contract declares in its release data (release-data/<Contract>.json,
                           `precompiles`: [{address, name, input, output}]; a file without the list is FORKCHECK_RELEASE_DATA)
                           answers its known answer to an eth_call on the chain.
The profile states the fork: src/chains/<key>/profile.json {"evmFork", "codeSizeLimit", "initCodeSizeLimit", "txGasCap"?
(null: none), "blockGasLimit"? (a record; check (2) reads the live block)}; at `amsterdam` (NET-EVM-06) nothing here applies.
A key without the file is refused (FORKCHECK_PROFILE), except the reset chain `scaas-testnet` and a local anvil
(`local-…-testnet`), which are `amsterdam` (ARCH-POS-20, review P1-1). Chain reads ask every node of the list and take the
strict majority (ARCH-POS-15) on the value used (a block's hash and gas limit at a number below the head, a code, a call's
answer; a height, an estimate or a fee: the number a strict majority reaches), else FORKCHECK_NODES. One rule on every chain: no chain id is read here.
  python3 -I script/forkcheck.py set-gate <key>        exit 1 (FORKCHECK_SET_FORK) when the profile's fork is not amsterdam:
                                                       a whole SCaaS set waits for the chain's Amsterdam fork (deploy.sh)
  python3 -I script/forkcheck.py scan <fork> <artifact> [<args hex>]   check (3)
  scripts/capped python3 -I script/forkcheck.py exec <fork> <cases.json> [--out <dir>]   check (3) and (4) on a local anvil
                                                       (started and stopped here); prints `gas <contract> <case> <gasUsed>`
  scripts/capped python3 -I script/forkcheck.py control <fork> [--out <dir>]   the control's positive run: green on anvil
                                                       at the first fork with its opcode, and void under <fork>'s expectation
  scripts/capped python3 -I script/forkcheck.py deploy <key> <artifact> <rpc>[,<rpc>…] --cases <cases.json>
      [--args <hex>] [--gas-limit <gas>] [--release <release-data json>] [--out <dir>]   the five checks before a single
                                                       contract's deploy
cases.json: {"contracts": [{"artifact": "<F>.sol/<C>.json", "args": "0x…"?, "cases": [{"name", "sig": "f(uint256)",
"args": "0x…"?, "ok": true|false, "return": "0x…"?, "revert": "0x…"?, "logs": [{"topics", "data"}]?, "from": <account index>?}]}]}; artifacts in forge's out directory (--out, default out), built with
`--extra-output evm.legacyAssembly` so the scan places the compiler's data sections; other paths from smartcontracts/evm.
UNAUDITED tooling."""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

EVM = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tx_gas_cap import CAP_REFUSAL  # noqa: E402


class ForkError(Exception):
    """A named refusal: the message starts with its name."""


def _r(a, b):
    return set(range(a, b + 1))


# Cancun's opcodes, explicit (execution-specs, forks/cancun/vm/instructions): arithmetic 0x00-0x0b, comparison and bitwise
# 0x10-0x1d, KECCAK256, environment 0x30-0x3f, block 0x40-0x4a (BLOBHASH 0x49, BLOBBASEFEE 0x4a), stack, memory, storage and
# flow 0x50-0x5f (TLOAD, TSTORE, MCOPY, PUSH0), PUSH1-PUSH32, DUP1-16, SWAP1-16, LOG0-4, the system opcodes
CANCUN = frozenset(
    _r(0x00, 0x0B)
    | _r(0x10, 0x1D)
    | {0x20}
    | _r(0x30, 0x3F)
    | _r(0x40, 0x4A)
    | _r(0x50, 0x5F)
    | _r(0x60, 0x7F)
    | _r(0x80, 0x9F)
    | _r(0xA0, 0xA4)
    | _r(0xF0, 0xF5)
    | {0xFA, 0xFD, 0xFE, 0xFF}
)
# The compile target: Cancun, Prague (no opcode), Osaka's CLZ 0x1e (EIP-7939), Amsterdam's SLOTNUM 0x4b (EIP-7843); both
# without an immediate. Amsterdam's DUPN / SWAPN / EXCHANGE (0xe6-0xe8, EIP-8024) carry an immediate whose bytes the jump
# analysis does not skip, and solc 0.8.37 emits none (its binary names neither): they are left out, so the walk cannot place
# them and refuses (FORKCHECK_UNPLACED), as every byte outside this table.
AMSTERDAM = CANCUN | {0x1E, 0x4B}
FORKS = {"cancun": CANCUN, "amsterdam": AMSTERDAM}
TARGET = "amsterdam"
CLZ = 0x1E


def immediate(op):
    """The immediate length of an opcode of the compile target's table: PUSH1-PUSH32 carry 1-32 bytes, every other none."""
    return op - 0x5F if 0x60 <= op <= 0x7F else 0


def walk(code, count, fork, where):
    """The offset after `count` instructions of `code` (the compiler's source-map count), each byte in code position checked:
    placeable by the compile target's table, else FORKCHECK_UNPLACED; an opcode of `fork`, else FORKCHECK_OPCODE."""
    allowed, i = FORKS[fork], 0
    for _ in range(count):
        if i >= len(code):
            raise ForkError(f"FORKCHECK_BOUNDARY: {where}: the source map counts more instructions than the code holds")
        op = code[i]
        if op not in AMSTERDAM:
            raise ForkError(
                f"FORKCHECK_UNPLACED: {where}: byte 0x{op:02x} at {i} has no immediate length in the {TARGET} table"
            )
        if op not in allowed:
            raise ForkError(f"FORKCHECK_OPCODE: {where}: opcode 0x{op:02x} at {i} is not a {fork} opcode")
        i += 1 + immediate(op)
        if i > len(code):
            raise ForkError(f"FORKCHECK_UNPLACED: {where}: the immediate of 0x{op:02x} runs past the code")
    return i


def _hex(s, where):
    s = s[2:] if s.startswith("0x") else s
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", s):
        raise ForkError(f"FORKCHECK_ARTIFACT: {where} is not linked hex (a library placeholder or an odd length)")
    return bytes.fromhex(s)


def _count(source_map):
    return len(source_map.split(";")) if source_map else 0


def regions(artifact):
    """The init code and the runtime of a forge artifact with their instruction counts (the source maps) and where the
    runtime's CBOR metadata starts (its length the last two bytes)."""
    name = artifact.get("_name", "artifact")
    init = _hex(artifact["bytecode"]["object"], f"{name} bytecode")
    rt = _hex(artifact["deployedBytecode"]["object"], f"{name} deployedBytecode")
    if len(rt) < 2:
        raise ForkError(f"FORKCHECK_BOUNDARY: {name}: no runtime")
    meta = int.from_bytes(rt[-2:], "big")
    tail = len(rt) - 2 - meta  # where the CBOR metadata starts
    if tail < 1 or not 0xA0 <= rt[tail] <= 0xBF:
        raise ForkError(f"FORKCHECK_BOUNDARY: {name}: no CBOR metadata of length {meta} at the end of the runtime")
    n_rt, n_init = _count(artifact["deployedBytecode"].get("sourceMap")), _count(artifact["bytecode"].get("sourceMap"))
    if not n_rt or not n_init:
        raise ForkError(
            f"FORKCHECK_BOUNDARY: {name}: the artifact has no source map (the compiler's instruction count)"
        )
    return {"init": init, "init_n": n_init, "runtime": rt, "runtime_n": n_rt, "meta_at": tail, "_name": name}


def _sections(asm, where):
    """The sections solc appends after an assembly's code (its legacy assembly `.data`): the sub-assemblies by index, and
    the data bytes, in solc's order (its map of data keyed by their hash: ascending). No assembly: none."""
    subs, data = [], []
    for k, v in ((asm or {}).get(".data") or {}).items():
        if isinstance(v, dict) and k.isdigit():
            subs.append((int(k), v))
        elif isinstance(v, str) and re.fullmatch(r"[0-9A-Fa-f]{64}", k):
            data.append((int(k, 16), _hex(v, f"{where} data")))
        else:
            raise ForkError(f"FORKCHECK_BOUNDARY: {where}: an assembly section {k!r} the scan cannot place")
    return [v for _, v in sorted(subs)], b"".join(b for _, b in sorted(data))


def scan(artifact, fork, args=b""):
    """Check (3) on a forge artifact; returns the regions. `args`: the constructor arguments, data after the init code.
    After the code: solc's INVALID, then (init code) the runtime as its one sub-assembly, then the data sections the
    compiler's legacy assembly lists (`forge build --extra-output evm.legacyAssembly`; without it: none), then (runtime) the
    CBOR metadata. Anything else, a second sub-assembly (code the walk does not reach) included, is refused."""
    if fork not in FORKS:
        raise ForkError(f"FORKCHECK_FORK_UNKNOWN: {fork!r} (known: {', '.join(FORKS)})")
    g = regions(artifact)
    name, rt, init = g["_name"], g["runtime"], g["init"]
    asm = artifact.get("legacyAssembly")
    subs, init_data = _sections(asm, f"{name} init")
    rt_asm = subs[0] if subs else None
    if len(subs) > 1 or (asm and not subs):
        raise ForkError(f"FORKCHECK_BOUNDARY: {name} init: {len(subs)} sub-assemblies, not the runtime alone")
    rt_subs, rt_data = _sections(rt_asm, f"{name} runtime")
    if rt_subs:
        raise ForkError(
            f"FORKCHECK_BOUNDARY: {name} runtime: {len(rt_subs)} sub-assemblies (code the walk does not reach)"
        )
    end = walk(rt, g["runtime_n"], fork, f"{name} runtime")
    if rt[end:] != b"\xfe" + rt_data + rt[g["meta_at"] :]:
        how = (
            "the compiler's assembly"
            if asm
            else "no assembly in the artifact (build with --extra-output evm.legacyAssembly)"
        )
        raise ForkError(
            f"FORKCHECK_BOUNDARY: {name} runtime: the code ends at {end}, the metadata starts at {g['meta_at']}: the "
            f"{g['meta_at'] - end} bytes between them are not INVALID and the {len(rt_data)} data bytes of {how}"
        )
    end = walk(init, g["init_n"], fork, f"{name} init")
    if init[end:] != b"\xfe" + rt + init_data:
        raise ForkError(
            f"FORKCHECK_BOUNDARY: {name} init: the code ends at {end}; the {len(init) - end} bytes after it are not INVALID, "
            f"the runtime ({len(rt)} B) and the {len(init_data)} data bytes of the compiler's assembly"
        )
    g["args"] = args
    return g


def check_sizes(g, profile):
    """Check (1): the runtime and the init code with its arguments within the profile's caps (never a constant)."""
    rt, init = len(g["runtime"]), len(g["init"]) + len(g.get("args") or b"")
    if rt > profile["codeSizeLimit"]:
        raise ForkError(f"FORKCHECK_SIZE: {g['_name']} runtime {rt} B above the chain's {profile['codeSizeLimit']} B")
    if init > profile["initCodeSizeLimit"]:
        raise ForkError(
            f"FORKCHECK_SIZE: {g['_name']} init code {init} B above the chain's {profile['initCodeSizeLimit']} B"
        )
    return rt, init


# ---- the profile and the release data


# The keys that are amsterdam without a profile file: the reset chain and a local anvil (ARCH-POS-20, review P1-1)
NO_PROFILE_AMSTERDAM = re.compile(r"scaas-testnet|local(-[a-z0-9-]+)?-testnet")


def profile(key, root=EVM):
    """The profile's fork and caps: src/chains/<key>/profile.json; none: amsterdam for the reset chain and a local anvil,
    else FORKCHECK_PROFILE (fail closed: a chain without a profile never defaults to amsterdam)."""
    if not re.fullmatch(r"[a-z0-9-]+", key):
        raise ForkError(f"FORKCHECK_PROFILE: {key!r} is not a chain key")
    p = os.path.join(root, "src", "chains", key, "profile.json")
    if not os.path.exists(p):
        if NO_PROFILE_AMSTERDAM.fullmatch(key):
            return {"evmFork": TARGET}
        raise ForkError(
            f"FORKCHECK_PROFILE: {key} has no src/chains/{key}/profile.json (a chain states its fork; only the reset chain "
            "and a local anvil are amsterdam without one)"
        )
    pr = json.load(open(p))
    if pr.get("evmFork") not in FORKS:
        raise ForkError(f"FORKCHECK_FORK_UNKNOWN: {key}: evmFork {pr.get('evmFork')!r} (known: {', '.join(FORKS)})")
    if pr["evmFork"] != TARGET:
        for f in ("codeSizeLimit", "initCodeSizeLimit"):
            if not isinstance(pr.get(f), int) or pr[f] <= 0:
                raise ForkError(f"FORKCHECK_PROFILE: {key}: {f} missing (a chain without {TARGET} states its caps)")
    cap = pr.get("txGasCap")
    if cap is not None and (not isinstance(cap, int) or isinstance(cap, bool) or cap <= 0):
        raise ForkError(f"FORKCHECK_PROFILE: {key}: txGasCap {cap!r} is neither null nor a positive integer")
    return pr


def precompiles(release):
    """The precompiles a contract declares in its release data; a file without the list refuses (no silent none)."""
    if not isinstance(release, dict) or not isinstance(release.get("precompiles"), list):
        raise ForkError("FORKCHECK_RELEASE_DATA: the release data has no `precompiles` list")
    for e in release["precompiles"]:
        if not all(isinstance(e.get(k), str) for k in ("address", "input", "output")):
            raise ForkError(f"FORKCHECK_RELEASE_DATA: a precompile entry without address, input and output: {e}")
    return release["precompiles"]


# ---- chain reads through a node list (strict majority)


MAX_ANSWER = 4 << 20  # bytes of one answer read at most (a block is under 1 MiB, a 16-blob page under 1 MiB of hex; P3-3)


def _post(url, method, params, timeout=30):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(MAX_ANSWER + 1)
        if len(body) > MAX_ANSWER:
            return {"error": {"message": f"no answer (an answer above {MAX_ANSWER} B)", "transport": True}}
        a = json.loads(body)
        return a if isinstance(a, dict) else {"error": {"message": "no answer (not a JSON object)", "transport": True}}
    except Exception as e:  # never the URL: it may hold a key
        return {"error": {"message": f"no answer ({type(e).__name__})", "transport": True}}


def http_node(url):
    return lambda method, params: _post(url, method, params)


BAD_ANSWER = (ValueError, TypeError, KeyError, AttributeError, IndexError)


def qty(x):
    """A JSON-RPC quantity (a 0x-hex string) as an int; anything else raises ValueError (a malformed answer)."""
    if not isinstance(x, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,64}", x):
        raise ValueError("not a quantity")
    return int(x, 16)


def data(x):
    """JSON-RPC data (0x and whole bytes), lower case; anything else raises ValueError."""
    if not isinstance(x, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", x):
        raise ValueError("not data")
    return x.lower()


def agree(nodes, method, params, pick):
    """The strict majority on the value used: each answer reduced by `pick` to the fields that matter, normalized (never the
    whole object, whose fields outside consensus differ between honest nodes; review P2-2); returns {"result": picked} or
    {"error": …}. The error message is not compared, only its presence; an answer `pick` cannot read is malformed and is
    never a vote for a value."""
    if not nodes:
        raise ForkError("FORKCHECK_NODES: no node")
    answers, keys, vals = [n(method, params) for n in nodes], [], []
    for a in answers:
        if not isinstance(a, dict) or "error" in a or "result" not in a:
            keys.append("error")
            vals.append(None)
            continue
        try:
            v = pick(a["result"])
        except BAD_ANSWER:
            keys.append("malformed")
            vals.append(None)
            continue
        keys.append(json.dumps(v, sort_keys=True))
        vals.append(v)
    for k in set(keys):
        if k != "malformed" and 2 * keys.count(k) > len(keys):
            i = keys.index(k)
            return {"error": answers[i].get("error", {})} if k == "error" else {"result": vals[i]}
    raise ForkError(f"FORKCHECK_NODES: no strict majority on {method} ({len(nodes)} nodes)")


def majority_number(nodes, method, params):
    """A number a strict majority of the list reports at least (the descending list's middle: between two honest answers
    while a strict majority is honest): heads, estimates and fees differ between honest nodes, so they are never voted on
    exactly (review P2-2); fewer than a strict majority answering a number: FORKCHECK_NODES."""
    if not nodes:
        raise ForkError("FORKCHECK_NODES: no node")
    got = []
    for n in nodes:
        a = n(method, params)
        try:
            if "error" not in a:
                got.append(qty(a["result"]))
        except BAD_ANSWER:
            pass
    if 2 * len(got) <= len(nodes):
        raise ForkError(f"FORKCHECK_NODES: fewer than a strict majority of {len(nodes)} nodes answer {method} with a number")
    return sorted(got, reverse=True)[len(nodes) // 2]


BLOCK_MARGIN = 16  # the block check (2) reads: this far below the head a strict majority reaches


def pinned_block(nodes):
    """(number, hash, gas limit) of a block below the head a strict majority reaches, its hash and gas limit voted on."""
    n = max(0, majority_number(nodes, "eth_blockNumber", []) - BLOCK_MARGIN)
    b = agree(nodes, "eth_getBlockByNumber", [hex(n), False], lambda r: [data(r["hash"]), qty(r["gasLimit"])])
    if "error" in b:
        raise ForkError(f"FORKCHECK_GAS: no block {n}")
    return n, b["result"][0], b["result"][1]


def check_precompiles(nodes, entries):
    """Check (5): each declared precompile answers its known answer to an eth_call."""
    for e in entries:
        a = agree(nodes, "eth_call", [{"to": e["address"], "data": e["input"]}, "latest"], data)
        got = a.get("result")
        if "error" in a or not isinstance(got, str) or got.lower() != e["output"].lower():
            raise ForkError(
                f"FORKCHECK_PRECOMPILE: {e.get('name', '')} {e['address']}: the chain does not answer the known answer "
                f"({'an error' if 'error' in a else (got or '')[:20]})"
            )
    return len(entries)


def check_gas(nodes, code, gas_limit=None, sender=None, tx_cap=None):
    """Check (2): the deploy transaction's gas (the limit the deploy sends, else the chain's estimate) within the live block
    gas limit, the profile's per-transaction cap `tx_cap` (None: none) and accepted under the chain's per-transaction cap.
    Returns (gas, block gas limit)."""
    if gas_limit is None:
        tx = {"data": code} | ({"from": sender} if sender else {})
        gas_limit = majority_number(nodes, "eth_estimateGas", [tx])
    if tx_cap is not None and gas_limit > tx_cap:
        raise ForkError(f"FORKCHECK_GAS: the deploy needs {gas_limit} gas, the profile's txGasCap is {tx_cap}")
    block = pinned_block(nodes)[2]
    if gas_limit > block:
        raise ForkError(f"FORKCHECK_GAS: the deploy needs {gas_limit} gas, the live block gas limit is {block}")
    zero = "0x" + "00" * 20
    a = agree(nodes, "eth_call", [{"from": zero, "to": zero, "gas": hex(gas_limit)}, "latest"], data)
    if "error" in a:
        msg = json.dumps(a["error"])
        if CAP_REFUSAL.search(msg):
            raise ForkError(f"FORKCHECK_GAS: the chain's per-transaction cap refuses {gas_limit} gas")
        raise ForkError(f"FORKCHECK_GAS: the cap probe at {gas_limit} gas answered an error that is no cap refusal")
    return gas_limit, block


# ---- check (4): real transactions at the chain's fork


CONTROL = {  # per fork: a fixture whose amsterdam artifact uses an opcode the fork lacks, its case (red at the fork: the call
    # an execution error, the receipt status 0), its amsterdam answer (`green`) and the first anvil fork with the opcode
    "cancun": {
        "artifact": "ForkcheckClz.sol/ForkcheckClz.json",
        "cases": [{"name": "clz(1)", "sig": "lz(uint256)", "args": "0x" + "00" * 31 + "01", "ok": False}],
        "green": "0x" + "00" * 31 + "ff",
        "green_at": "osaka",
    }
}


def load_artifact(path, root=EVM):
    a = json.load(open(os.path.join(root, path)))
    a["_name"] = os.path.splitext(os.path.basename(path))[0]
    return a


def _calldata(artifact, case):
    ids = artifact.get("methodIdentifiers") or {}
    if case["sig"] not in ids:
        raise ForkError(f"FORKCHECK_EXEC: {artifact['_name']} has no function {case['sig']}")
    return "0x" + ids[case["sig"]] + (case.get("args") or "0x")[2:]


def _receipt(rpc, h):
    for _ in range(200):  # anvil mines at once; a bounded wait, never a loop without end
        r = rpc("eth_getTransactionReceipt", [h]).get("result")
        if r:
            return r
        time.sleep(0.05)
    raise ForkError(f"FORKCHECK_EXEC: no receipt for {h}")


def _send(rpc, frm, tx, gas):
    a = rpc("eth_sendTransaction", [dict(tx, **{"from": frm, "gas": hex(gas)})])
    if "error" in a:
        raise ForkError(f"FORKCHECK_EXEC: the node refused a transaction: {str(a['error'])[:200]}")
    return _receipt(rpc, a["result"])


def _logs(rec, at):
    """A receipt's logs as compared: the contract's own as {topics, data}, another's by its address."""
    return [
        {"topics": [t.lower() for t in x["topics"]], "data": x["data"].lower()}
        if x.get("address", "").lower() == at.lower()
        else {"address": x.get("address")}
        for x in rec.get("logs") or []
    ]


def run_contract(rpc, accts, gas, artifact, args, cases):
    """Deploys the artifact's init bytes (+ args) from the first account, runs each case (eth_call at the state before, then
    the same transaction sent, from the account `from` indexes, default the first); returns [(case name, passed, gasUsed,
    why)]. A case's `return`, `revert` (the revert data) and `logs` (the receipt's logs, each the contract's own) are
    compared exactly when given. A deploy that fails is one failed row."""
    init = artifact["bytecode"]["object"] + (args or "0x")[2:]
    r = _send(rpc, accts[0], {"data": init}, gas)
    if int(r["status"], 16) != 1 or not r.get("contractAddress"):
        return [("deploy", False, int(r["gasUsed"], 16), "the deploy reverted")]
    at, out = r["contractAddress"], [("deploy", True, int(r["gasUsed"], 16), "")]
    code = rpc("eth_getCode", [at, "latest"]).get("result", "")
    if (
        not artifact["deployedBytecode"].get("immutableReferences")
        and code.lower() != artifact["deployedBytecode"]["object"].lower()
    ):
        return out + [("code", False, 0, "the deployed code is not the artifact's runtime")]
    for c in cases:
        tx, frm = {"to": at, "data": _calldata(artifact, c)}, accts[c.get("from", 0)]
        call = rpc("eth_call", [dict(tx, **{"from": frm, "gas": hex(gas)}), "latest"])
        ok = "error" not in call
        rec = _send(rpc, frm, tx, gas)
        status = int(rec["status"], 16) == 1
        why = ""
        if isinstance(call.get("error"), dict) and call["error"].get("transport"):
            why = "no answer to the call (transport)"  # never an execution error
        elif ok != c["ok"] or status != c["ok"]:
            why = f"ok {ok} (call), {status} (receipt), expected {c['ok']}"
        elif c["ok"] and "return" in c and call["result"].lower() != c["return"].lower():
            why = f"returned {call['result'][:66]}, expected {c['return'][:66]}"
        elif not c["ok"] and "revert" in c and str(call["error"].get("data", "")).lower() != c["revert"].lower():
            why = f"reverted with {str(call['error'].get('data', ''))[:74]}, expected {c['revert'][:74]}"
        elif "logs" in c and _logs(rec, at) != _logs({"logs": [dict(x, address=at) for x in c["logs"]]}, at):
            why = f"logs {str(_logs(rec, at))[:200]}, expected {str(c['logs'])[:200]}"
        out.append((c["name"], not why, int(rec["gasUsed"], 16), why))
    return out


def _local_gas(rpc):
    try:
        return qty(rpc("eth_getBlockByNumber", ["latest", False])["result"]["gasLimit"])
    except BAD_ANSWER:
        raise ForkError("FORKCHECK_EXEC: the local node gave no latest block gas limit") from None


def execute(rpc, fork, contracts, say=print, root=EVM, out="out"):
    """Check (4) on a node at `fork` (rpc: a callable); returns the number of rows passed. Every contract's rows must pass and
    the fork's control must be red: a green control voids the run (FORKCHECK_CONTROL)."""
    if fork not in CONTROL:
        raise ForkError(f"FORKCHECK_FORK_UNKNOWN: no control fixture for {fork}")
    accts = rpc("eth_accounts", []).get("result") or []
    if not accts:
        raise ForkError("FORKCHECK_EXEC: the node has no unlocked account")
    gas = _local_gas(rpc)
    ctl = CONTROL[fork]
    rows = run_contract(rpc, accts, gas, load_artifact(os.path.join(out, ctl["artifact"]), root), "0x", ctl["cases"])
    for name, ok, g, why in rows:
        say(f"control {name}: {'as expected' if ok else 'NOT as expected'} gas {g}{' (' + why + ')' if why else ''}")
    # red for the missing opcode alone (review P2-6): the deploy green, each case red by both signals; else no evidence
    ran = rows[0][:2] == ("deploy", True) and [r[0] for r in rows[1:]] == [c["name"] for c in ctl["cases"]]
    if not ran or any(r[3].startswith("no answer") for r in rows):
        raise ForkError(f"FORKCHECK_CONTROL: the {fork} control did not run: {'; '.join(r[3] for r in rows if r[3])}")
    if not all(r[1] for r in rows):
        raise ForkError(f"FORKCHECK_CONTROL: the {fork} control is green (call or transaction): the run is void (it is not at {fork})")
    say(f"control: red at {fork} (the call an execution error, the receipt status 0)")
    passed, failed = 1, []  # the control's red counts as one expectation met
    for c in contracts:
        a = load_artifact(os.path.join(out, c["artifact"]), root)
        for name, ok, g, why in run_contract(rpc, accts, gas, a, c.get("args"), c["cases"]):
            say(f"gas {a['_name']} {name} {g} at {fork}" + ("" if ok else f" FAIL {why}"))
            if ok:
                passed += 1
            else:
                failed.append(f"{a['_name']} {name}: {why}")
    if failed:
        raise ForkError(f"FORKCHECK_EXEC: at {fork}: " + "; ".join(failed))
    return passed


def control_check(rpc, fork, say=print, root=EVM, out="out"):
    """The control's positive run on a node at the first fork with its opcode (review P2-6): green with its amsterdam answer,
    and the same node under `fork`'s expectation is void (FORKCHECK_CONTROL): a control that should fail but passes fails the
    step. Returns 2."""
    ctl = CONTROL[fork]
    accts = rpc("eth_accounts", []).get("result") or []
    if not accts:
        raise ForkError("FORKCHECK_EXEC: the node has no unlocked account")
    gas = _local_gas(rpc)
    green = [dict(c, ok=True, **{"return": ctl["green"]}) for c in ctl["cases"]]
    rows = run_contract(rpc, accts, gas, load_artifact(os.path.join(out, ctl["artifact"]), root), "0x", green)
    for name, ok, g, why in rows:
        say(f"control {name} at {ctl['green_at']}: {'green' if ok else 'NOT green'} gas {g}{' (' + why + ')' if why else ''}")
    if len(rows) != 1 + len(green) or not all(r[1] for r in rows):
        raise ForkError(f"FORKCHECK_CONTROL: the {fork} control is not green at {ctl['green_at']}: the fixture is wrong")
    try:
        execute(rpc, fork, [], lambda s: None, root, out)
    except ForkError as e:
        if not str(e).startswith("FORKCHECK_CONTROL"):
            raise
        say(f"control at {ctl['green_at']} under the {fork} expectation: void ({str(e)[:60]})")
        return 2
    raise ForkError(f"FORKCHECK_CONTROL: a green control did not void the {fork} run")


class Anvil:
    """`anvil --hardfork <fork>` on a free local port, stopped on exit (the caller runs under scripts/capped)."""

    def __init__(self, fork, code_size_limit=None):
        self.fork, self.limit = fork, code_size_limit

    def __enter__(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        exe = shutil.which("anvil") or os.path.expanduser("~/.foundry/bin/anvil")
        cmd = [exe, "--hardfork", self.fork, "--port", str(port), "--silent"]
        cmd += ["--code-size-limit", str(self.limit)] if self.limit else []
        self.p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        url = f"http://127.0.0.1:{port}"
        self.rpc = lambda m, p: _post(url, m, p, timeout=60)
        self.rpc.url = url
        for _ in range(300):  # up to 30 s for anvil to answer
            if "result" in self.rpc("eth_chainId", []):
                return self.rpc
            if self.p.poll() is not None:
                break
            time.sleep(0.1)
        self.__exit__()
        raise ForkError(f"FORKCHECK_EXEC: anvil --hardfork {self.fork} did not start")

    def __exit__(self, *_):
        self.p.terminate()
        try:
            self.p.wait(10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()


def exec_cases(fork, cases_path, code_size_limit=None, say=print, root=EVM, out="out"):
    """Check (3) on every contract of the cases file and the control (which must be refused), then check (4) on anvil."""
    if fork not in CONTROL:
        raise ForkError(f"FORKCHECK_FORK_UNKNOWN: no control fixture for {fork}")
    contracts = json.load(open(os.path.join(root, cases_path)))["contracts"]
    for c in contracts:
        scan(load_artifact(os.path.join(out, c["artifact"]), root), fork, _hex(c.get("args") or "0x", "args"))
        say(f"scan {c['artifact']}: {fork} ok")
    try:
        scan(load_artifact(os.path.join(out, CONTROL[fork]["artifact"]), root), fork)
    except ForkError as e:
        if not str(e).startswith("FORKCHECK_OPCODE"):
            raise
        say(f"scan control: refused ({str(e)[:80]})")
    else:
        raise ForkError(f"FORKCHECK_CONTROL: the scan passes the {fork} control: the scan is void")
    with Anvil(fork, code_size_limit) as rpc:
        return execute(rpc, fork, contracts, say, root, out) + 1  # + the control's scan refusal


def bound_cases(a, cases_path, root=EVM, out="out"):
    """Check (4)'s cases are the contract's under deploy (review P2-5): at least one entry, each entry's artifact the deployed
    one's bytes (init code and runtime; never another contract's) with at least one case; returns (cases, entries)."""
    try:
        contracts = json.load(open(os.path.join(root, cases_path)))["contracts"]
    except (OSError, ValueError, KeyError, TypeError):
        raise ForkError(f"FORKCHECK_CASES: {cases_path} is no cases file") from None
    if not isinstance(contracts, list) or not contracts:
        raise ForkError(f"FORKCHECK_CASES: {cases_path} lists no contract")
    mine, n = (a["bytecode"]["object"].lower(), a["deployedBytecode"]["object"].lower()), 0
    for c in contracts:
        b = load_artifact(os.path.join(out, c["artifact"]), root)
        if (b["bytecode"]["object"].lower(), b["deployedBytecode"]["object"].lower()) != mine:
            raise ForkError(f"FORKCHECK_CASES: {c['artifact']} is not {a['_name']}, the contract under deploy")
        if not isinstance(c.get("cases"), list) or not c["cases"]:
            raise ForkError(f"FORKCHECK_CASES: an entry of {a['_name']} has no case")
        n += len(c["cases"])
    return n, len(contracts)


def deploy_gate(
    key,
    artifact_path,
    nodes,
    cases_path=None,
    args="0x",
    gas_limit=None,
    release_path=None,
    say=print,
    root=EVM,
    run4=None,
    out="out",
    profiles=None,
):
    """The five checks before a single contract's deploy on profile `key`; amsterdam: nothing to check. `run4`: check (4)'s
    runner (default exec_cases on a local anvil); `profiles`: the root of src/chains/<key>/profile.json (default `root`)."""
    pr = profile(key, profiles or root)
    if pr["evmFork"] == TARGET:
        say(f"forkcheck {key}: {TARGET}, NET-EVM-06, nothing to check")
        return
    fork = pr["evmFork"]
    a = load_artifact(artifact_path, root)
    g = scan(a, fork, _hex(args, "args"))  # (3)
    rt, init = check_sizes(g, pr)  # (1)
    say(f"forkcheck {key}: (1) runtime {rt} B, init {init} B ok; (3) {fork} scan ok")
    rel = release_path or os.path.join("release-data", a["_name"] + ".json")
    if not os.path.exists(os.path.join(root, rel)):
        raise ForkError(f"FORKCHECK_RELEASE_DATA: {rel} missing (the contract's precompile list)")
    entries = precompiles(json.load(open(os.path.join(root, rel))))
    if not cases_path:
        raise ForkError(f"FORKCHECK_CASES: no cases for {a['_name']} at {fork}")
    n, m = bound_cases(a, cases_path, root, out)
    say(f"forkcheck {key}: (4) {n} cases of {a['_name']} in {m} entries")
    say(
        f"forkcheck {key}: (4) {(run4 or exec_cases)(fork, cases_path, pr['codeSizeLimit'], say, root, out)} rows at {fork} ok"
    )
    say(f"forkcheck {key}: (5) {check_precompiles(nodes, entries)} precompiles answer")  # (5)
    gas, block = check_gas(nodes, a["bytecode"]["object"] + args[2:], gas_limit, tx_cap=pr.get("txGasCap"))  # (2)
    say(f"forkcheck {key}: (2) gas {gas} within block {block} and the transaction cap")


def set_gate(key, root=EVM):
    pr = profile(key, root)
    if pr["evmFork"] != TARGET:
        raise ForkError(
            f"FORKCHECK_SET_FORK: {key} runs {pr['evmFork']}: a whole SCaaS set waits for the chain's {TARGET} fork "
            "(NET-EVM-06); a single contract deploys under NET-EVM-18 (forkcheck.py deploy)"
        )
    return pr


def main(argv):
    try:
        if argv[:1] == ["set-gate"] and len(argv) == 2:
            set_gate(argv[1])
        elif argv[:1] == ["scan"] and len(argv) in (3, 4):
            scan(load_artifact(argv[2]), argv[1], _hex(argv[3] if len(argv) == 4 else "0x", "args"))
            print(f"[forkcheck] scan {argv[2]}: {argv[1]} ok")
        elif argv[:1] == ["exec"] and len(argv) in (3, 5) and argv[3:4] in ([], ["--out"]):
            out = argv[4] if len(argv) == 5 else "out"
            n = exec_cases(argv[1], argv[2], say=lambda s: print(f"[forkcheck] {s}", flush=True), out=out)
            print(f"ok {n}/{n}")
        elif argv[:1] == ["control"] and len(argv) in (2, 4) and argv[2:3] in ([], ["--out"]):
            if argv[1] not in CONTROL:
                raise ForkError(f"FORKCHECK_FORK_UNKNOWN: no control fixture for {argv[1]}")
            with Anvil(CONTROL[argv[1]]["green_at"]) as rpc:
                say = lambda s: print(f"[forkcheck] {s}", flush=True)  # noqa: E731
                n = control_check(rpc, argv[1], say, out=argv[3] if len(argv) == 4 else "out")
            print(f"ok {n}/{n}")
        elif argv[:1] == ["deploy"] and len(argv) >= 4:
            o = dict(zip(argv[4::2], argv[5::2]))
            deploy_gate(
                argv[1],
                argv[2],
                [http_node(u) for u in argv[3].split(",") if u],
                o.get("--cases"),
                o.get("--args", "0x"),
                int(o["--gas-limit"]) if "--gas-limit" in o else None,
                o.get("--release"),
                out=o.get("--out", "out"),
                say=lambda s: print(f"[deploy] {s}", flush=True),
            )
        else:
            sys.exit(__doc__)
    except ForkError as e:
        print(f"[deploy] FAIL {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
