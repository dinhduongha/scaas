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
The profile states the fork: src/chains/<key>/profile.json {"evmFork", "codeSizeLimit", "initCodeSizeLimit"}; a profile
without the file is `amsterdam` (NET-EVM-06), where nothing here applies. Chain reads ask every node of the list and take the
strict majority (ARCH-POS-15), else FORKCHECK_NODES. One rule on every chain: no chain id is read here.
  python3 -I script/forkcheck.py set-gate <key>        exit 1 (FORKCHECK_SET_FORK) when the profile's fork is not amsterdam:
                                                       a whole SCaaS set waits for the chain's Amsterdam fork (deploy.sh)
  python3 -I script/forkcheck.py scan <fork> <artifact> [<args hex>]   check (3)
  scripts/capped python3 -I script/forkcheck.py exec <fork> <cases.json> [--out <dir>]   check (3) and (4) on a local anvil
                                                       (started and stopped here); prints `gas <contract> <case> <gasUsed>`
  scripts/capped python3 -I script/forkcheck.py deploy <key> <artifact> <rpc>[,<rpc>…] --cases <cases.json>
      [--args <hex>] [--gas-limit <gas>] [--release <release-data json>] [--out <dir>]   the five checks before a single
                                                       contract's deploy
cases.json: {"contracts": [{"artifact": "<F>.sol/<C>.json", "args": "0x…"?, "cases": [{"name", "sig": "f(uint256)",
"args": "0x…"?, "ok": true|false, "return": "0x…"?}]}]}; artifacts in forge's out directory (--out, default out), built with
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


def profile(key, root=EVM):
    """The profile's fork and caps: src/chains/<key>/profile.json; none: amsterdam (NET-EVM-06)."""
    if not re.fullmatch(r"[a-z0-9-]+", key):
        raise ForkError(f"FORKCHECK_PROFILE: {key!r} is not a chain key")
    p = os.path.join(root, "src", "chains", key, "profile.json")
    if not os.path.exists(p):
        return {"evmFork": TARGET}
    pr = json.load(open(p))
    if pr.get("evmFork") not in FORKS:
        raise ForkError(f"FORKCHECK_FORK_UNKNOWN: {key}: evmFork {pr.get('evmFork')!r} (known: {', '.join(FORKS)})")
    if pr["evmFork"] != TARGET:
        for f in ("codeSizeLimit", "initCodeSizeLimit"):
            if not isinstance(pr.get(f), int) or pr[f] <= 0:
                raise ForkError(f"FORKCHECK_PROFILE: {key}: {f} missing (a chain without {TARGET} states its caps)")
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


def _post(url, method, params, timeout=30):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception as e:  # never the URL: it may hold a key
        return {"error": {"message": f"no answer ({type(e).__name__})"}}


def http_node(url):
    return lambda method, params: _post(url, method, params)


def agree(nodes, method, params):
    """The strict majority's answer ({"result": …} or {"error": …}); the error message is not compared, only its presence."""
    if not nodes:
        raise ForkError("FORKCHECK_NODES: no node")
    answers = [n(method, params) for n in nodes]
    keys = [json.dumps(a["result"], sort_keys=True) if "error" not in a and "result" in a else "error" for a in answers]
    for k in set(keys):
        if 2 * keys.count(k) > len(keys):
            return answers[keys.index(k)]
    raise ForkError(f"FORKCHECK_NODES: no strict majority on {method} ({len(nodes)} nodes)")


def check_precompiles(nodes, entries):
    """Check (5): each declared precompile answers its known answer to an eth_call."""
    for e in entries:
        a = agree(nodes, "eth_call", [{"to": e["address"], "data": e["input"]}, "latest"])
        got = a.get("result")
        if "error" in a or not isinstance(got, str) or got.lower() != e["output"].lower():
            raise ForkError(
                f"FORKCHECK_PRECOMPILE: {e.get('name', '')} {e['address']}: the chain does not answer the known answer "
                f"({'an error' if 'error' in a else (got or '')[:20]})"
            )
    return len(entries)


def check_gas(nodes, data, gas_limit=None, sender=None):
    """Check (2): the deploy transaction's gas (the limit the deploy sends, else the chain's estimate) within the live block
    gas limit and accepted under the chain's per-transaction cap. Returns (gas, block gas limit)."""
    if gas_limit is None:
        tx = {"data": data} | ({"from": sender} if sender else {})
        a = agree(nodes, "eth_estimateGas", [tx])
        if "error" in a:
            raise ForkError("FORKCHECK_GAS: the chain does not estimate the deploy transaction")
        gas_limit = int(a["result"], 16)
    b = agree(nodes, "eth_getBlockByNumber", ["latest", False])
    if "error" in b or not b.get("result"):
        raise ForkError("FORKCHECK_GAS: no latest block")
    block = int(b["result"]["gasLimit"], 16)
    if gas_limit > block:
        raise ForkError(f"FORKCHECK_GAS: the deploy needs {gas_limit} gas, the live block gas limit is {block}")
    zero = "0x" + "00" * 20
    a = agree(nodes, "eth_call", [{"from": zero, "to": zero, "gas": hex(gas_limit)}, "latest"])
    if "error" in a:
        msg = json.dumps(a["error"])
        if CAP_REFUSAL.search(msg):
            raise ForkError(f"FORKCHECK_GAS: the chain's per-transaction cap refuses {gas_limit} gas")
        raise ForkError(f"FORKCHECK_GAS: the cap probe at {gas_limit} gas answered an error that is no cap refusal")
    return gas_limit, block


# ---- check (4): real transactions at the chain's fork


CONTROL = {  # per fork: a fixture whose amsterdam artifact uses an opcode the fork lacks, and its amsterdam answer
    "cancun": {
        "artifact": "ForkcheckClz.sol/ForkcheckClz.json",
        "cases": [
            {
                "name": "clz(1) = 255",
                "sig": "lz(uint256)",
                "args": "0x" + "00" * 31 + "01",
                "ok": True,
                "return": "0x" + "00" * 31 + "ff",
            }
        ],
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


def run_contract(rpc, frm, gas, artifact, args, cases):
    """Deploys the artifact's init bytes (+ args), runs each case (eth_call at the state before, then the same transaction
    sent); returns [(case name, passed, gasUsed, why)]. A deploy that fails is one failed row."""
    init = artifact["bytecode"]["object"] + (args or "0x")[2:]
    r = _send(rpc, frm, {"data": init}, gas)
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
        tx = {"to": at, "data": _calldata(artifact, c)}
        call = rpc("eth_call", [dict(tx, **{"from": frm, "gas": hex(gas)}), "latest"])
        ok = "error" not in call
        rec = _send(rpc, frm, tx, gas)
        status = int(rec["status"], 16) == 1
        why = ""
        if ok != c["ok"] or status != c["ok"]:
            why = f"ok {ok} (call), {status} (receipt), expected {c['ok']}"
        elif c["ok"] and "return" in c and call["result"].lower() != c["return"].lower():
            why = f"returned {call['result'][:66]}, expected {c['return'][:66]}"
        out.append((c["name"], not why, int(rec["gasUsed"], 16), why))
    return out


def execute(rpc, fork, contracts, say=print, root=EVM, out="out"):
    """Check (4) on a node at `fork` (rpc: a callable); returns the number of rows passed. Every contract's rows must pass and
    the fork's control must be red: a green control voids the run (FORKCHECK_CONTROL)."""
    if fork not in CONTROL:
        raise ForkError(f"FORKCHECK_FORK_UNKNOWN: no control fixture for {fork}")
    accts = rpc("eth_accounts", []).get("result") or []
    if not accts:
        raise ForkError("FORKCHECK_EXEC: the node has no unlocked account")
    frm = accts[0]
    gas = int(rpc("eth_getBlockByNumber", ["latest", False])["result"]["gasLimit"], 16)
    ctl = CONTROL[fork]
    rows = run_contract(rpc, frm, gas, load_artifact(os.path.join(out, ctl["artifact"]), root), "0x", ctl["cases"])
    red = [r for r in rows if not r[1]]
    for name, ok, g, why in rows:
        say(f"control {name}: {'green' if ok else 'red'} gas {g}{' (' + why + ')' if why else ''}")
    if not red:
        raise ForkError(f"FORKCHECK_CONTROL: the {fork} control is green: the run is void (it is not at {fork})")
    passed, failed = 1, []  # the control's red counts as one expectation met
    for c in contracts:
        a = load_artifact(os.path.join(out, c["artifact"]), root)
        for name, ok, g, why in run_contract(rpc, frm, gas, a, c.get("args"), c["cases"]):
            say(f"gas {a['_name']} {name} {g} at {fork}" + ("" if ok else f" FAIL {why}"))
            if ok:
                passed += 1
            else:
                failed.append(f"{a['_name']} {name}: {why}")
    if failed:
        raise ForkError(f"FORKCHECK_EXEC: at {fork}: " + "; ".join(failed))
    return passed


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
):
    """The five checks before a single contract's deploy on profile `key`; amsterdam: nothing to check. `run4`: check (4)'s
    runner (default exec_cases on a local anvil)."""
    pr = profile(key, root)
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
    say(
        f"forkcheck {key}: (4) {(run4 or exec_cases)(fork, cases_path, pr['codeSizeLimit'], say, root, out)} rows at {fork} ok"
    )
    say(f"forkcheck {key}: (5) {check_precompiles(nodes, entries)} precompiles answer")  # (5)
    gas, block = check_gas(nodes, a["bytecode"]["object"] + args[2:], gas_limit)  # (2)
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
