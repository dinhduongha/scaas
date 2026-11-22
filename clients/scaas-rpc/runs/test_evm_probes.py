# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Tests of the EVM probe runner (2026-11-22-evm-probes.py; NET-EVM-19 H1-H8 and the profile probes of SDK plan T40) against
in-process fake JSON-RPC nodes on 127.0.0.1:0. Each negative test has its positive control beside it.
  python3 -I clients/scaas-rpc/runs/test_evm_probes.py [name…]"""
import importlib.util
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probes", HERE / "2026-11-22-evm-probes.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

UID = "0x" + "d4" * 32
H = lambda n: "0x" + f"{n:064x}"  # noqa: E731 the canonical hash of block n
MINER = "0x" + "aa" * 20
G1 = P.G1_GEN


class Chain:
    """A fake EVM node: blocks 0..head with canonical hashes H(n), `finalized` at head - 64. Flags break one behaviour each."""

    def __init__(self, chain_id=1, head=1000, **flags):
        self.chain_id, self.head, self.f = chain_id, head, flags
        self.uid = flags.get("uid", UID)
        self.fin = flags.get("finalized", head - 64)
        self.calls = []

    def block(self, n, h=None):
        b = {"number": hex(n), "hash": h or (self.uid if n == 0 else H(n)), "timestamp": hex(1_700_000_000 + 12 * n),
             "gasLimit": hex(self.f.get("gas_limit", 60_000_000)), "miner": MINER}
        if not self.f.get("no_base_fee"):
            b["baseFeePerGas"] = "0x3b9aca00"
        for k in self.f.get("header", ()):
            b[k] = "0x" + "00" * 32
        return b

    def number(self, tag):
        if tag == "latest":
            return self.head
        if tag == "finalized":
            return None if self.f.get("no_finalized") else self.fin
        return int(tag, 16)

    def at_ok(self, blk):
        """A block parameter of a read: a tag, or {blockHash, requireCanonical}."""
        if isinstance(blk, dict):
            canon = any(blk["blockHash"] == H(n) for n in range(1, self.head + 1))
            return canon or self.f.get("ignores_hash")
        return True

    def rpc(self, method, params):
        self.calls.append(method)
        f = self.f
        if f.get("rate_limited") is not None and len(self.calls) > f["rate_limited"]:
            raise RpcErr(-32005, "Rate limit exceeded on public endpoints")
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            n = self.number(params[0])
            if n is None or (n == 0 and f.get("pruned")):
                return None
            return self.block(n)
        if method == "eth_getBlockByHash":
            h = params[0]
            for n in range(1, self.head + 1):
                if h == H(n):
                    return self.block(n)
            return self.block(self.head) if f.get("other_block") else None
        if method in ("eth_getStorageAt", "eth_getCode", "eth_getBalance", "eth_getTransactionCount"):
            if not self.at_ok(params[-1]):
                raise RpcErr(-32000, "header not found")
            if method == "eth_getCode":
                return "0x60" if params[0].lower() == P.GAS_PRICE_ORACLE and f.get("op_stack") else "0x"
            if method == "eth_getBalance":
                bal = f.get("balance", lambda blk: 7)(params[-1])
                return hex(bal)
            return "0x0"
        if method == "eth_call":
            tx, blk = params[0], params[1] if len(params) > 1 else "latest"
            if not self.at_ok(blk):
                raise RpcErr(-32000, "header not found")
            gas = int(tx.get("gas", "0x0"), 16)
            # a node that checks the sender's balance against gas x price when `from` is named (Polkadot Hub's eth-rpc)
            if "from" in tx and f.get("sender_funds") is not None and gas > f["sender_funds"]:
                raise RpcErr(-32000, "insufficient funds for gas * price + value")
            if f.get("tx_cap") and gas > f["tx_cap"]:
                raise RpcErr(-32000, "gas limit too high")
            to = (tx.get("to") or "").lower()
            data = tx.get("data", "0x")
            if to == P.BLS_G1ADD:
                return G1 if f.get("eip2537") else "0x"
            if to == P.ARB_GAS_INFO and f.get("arb_tx_limit"):
                return "0x" + f"{7_000_000:064x}" + f"{f['arb_tx_limit']:064x}" * 2
            if to == P.GAS_PRICE_ORACLE:
                return f.get("l1_answer", H(12345)) if f.get("op_stack") else "0x"
            if not to and data:
                return self.create(bytes.fromhex(data[2:]))
            return "0x"
        if method == "eth_estimateGas":
            return hex(f.get("estimate", 21000))
        if method == "linea_estimateGas":
            if not f.get("linea"):
                raise RpcErr(-32601, "the method linea_estimateGas does not exist")
            if f["linea"] == "gateway":
                raise RpcErr(-32601, "a gateway: linea_estimateGas is not served")
            if f["linea"] == "unfunded":
                raise RpcErr(-32000, "transaction up-front gas cost 0x23e38 exceeds transaction sender account balance 0x0")
            return {"gasLimit": "0x5208", "baseFeePerGas": "0x7", "priorityFeePerGas": "0x3b9aca00"}
        if method == "eth_getLogs":
            span = int(params[0]["toBlock"], 16) - int(params[0]["fromBlock"], 16) + 1
            if span > f.get("log_span", 10_000):
                raise RpcErr(-32005, "query exceeds max block range", f.get("http_status", 200))
            return []
        raise RpcErr(-32601, f"no such method {method}")

    def create(self, code):
        """An eth_call creation of the runner's init codes: the opcode tests and the `PUSH3 n PUSH1 0 RETURN` size tests."""
        f = self.f
        if len(code) > f.get("init_limit", 49152):
            raise RpcErr(-32000, "max initcode size exceeded")
        for name, (init, op) in P.OPCODE_TESTS.items():
            if code == init:
                if op in f.get("opcodes", (0x5F, 0x5C, 0x5E, 0x4A, 0x1E)):
                    return "0x" + "00" * 31 + "ff" if name == "osaka" else "0x" + "00" * 32
                raise RpcErr(-32000, "invalid opcode")
        if code[:5] == bytes.fromhex("60006000f3"):
            return "0x"
        if code[0] == 0x62:
            n = int.from_bytes(code[1:4], "big")
            if n > f.get("deposit_gas", 1 << 30):
                raise RpcErr(-32003, "out of gas: gas required exceeds: 50000000")
            if n > f.get("code_limit", 24576):
                raise RpcErr(-32000, "max code size exceeded")
            return "0x" + "00" * n
        raise RpcErr(-32000, "unexpected init code")


class RpcErr(Exception):
    def __init__(self, code, msg, status=200):
        super().__init__(msg)
        self.code, self.msg, self.status = code, msg, status


def serve(chain):
    class Hd(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            status = 200
            try:
                out = {"jsonrpc": "2.0", "id": req["id"], "result": chain.rpc(req["method"], req["params"])}
            except RpcErr as e:
                out = {"jsonrpc": "2.0", "id": req["id"], "error": {"code": e.code, "message": e.msg}}
                status = e.status
            b = json.dumps(out).encode() if status != 429 else b"slow down"
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    s = ThreadingHTTPServer(("127.0.0.1", 0), Hd)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    SERVERS.append(s)
    return f"http://127.0.0.1:{s.server_address[1]}/secret-path?key=k"


SERVERS = []
ROW = {"key": "x-mainnet", "chainId": 1, "chainUid": UID}


def go(probe, *chains, row=ROW, logdir=None):
    d = logdir or tempfile.mkdtemp()
    return P.run(probe, row, [serve(c) for c in chains], d), d


def facts_of(d, probe, key="x-mainnet"):
    return [json.loads(x) for x in open(os.path.join(d, f"2026-11-22-evm-probes-{key}-{probe}.log"))]


# ---- H1: block 0 and the chain id on every endpoint


def h1_block0_and_chain_id():
    (v, _), _ = go("H1", Chain(), Chain())
    assert v == "PASS", v
    # Ethereum and ETC share block 0: the chain id separates them (NET-ALL-25)
    (v, f), _ = go("H1", Chain(), Chain(chain_id=61))
    assert v == "FAIL" and f["endpoints"][1]["chain_id"] == 61, f
    (v, f), _ = go("H1", Chain(), Chain(uid="0x" + "11" * 32))
    assert v == "FAIL", f
    (v, f), _ = go("H1", Chain(), Chain(pruned=True))
    assert v == "FAIL" and f["endpoints"][1]["block0"] is None, f
    # one endpoint is not two providers
    (v, f), _ = go("H1", Chain())
    assert v == "FAIL" and "two" in f["why"], f


# ---- H2: EIP-1898 reads by a canonical hash answer, by a made-up hash are refused


def h2_eip1898():
    (v, f), _ = go("H2", Chain(), Chain())
    assert v == "PASS" and f["endpoints"][0] == {"canonical": 5, "made_up_refused": 5}, f
    (v, f), _ = go("H2", Chain(), Chain(ignores_hash=True))
    assert v == "FAIL" and f["endpoints"][1]["made_up_refused"] == 0, f


# ---- H3: latest sampled, compared later with the canonical chain


def h3_replaced_heads_counted():
    d = tempfile.mkdtemp()
    c = Chain(head=100)
    url = serve(c)
    P.run("H3", ROW, [url], d)
    c.head, c.fin = 300, 236
    # the sample of block 100 was H(100): canonical; a forged earlier sample of block 99 is a replaced head
    with open(os.path.join(d, "2026-11-22-evm-probes-x-mainnet-H3.log"), "a") as fh:
        fh.write(json.dumps({"t": "x", "verdict": "INFO", "facts": {"samples": [[0, 99, "0x" + "99" * 32]], "compared": []}})
                 + "\n")
    v, f = P.run("H3", ROW, [url], d)
    assert v == "INFO" and f["replaced"] == 1 and f["checked"] == 2, f


# ---- H4: a block asked by its hash


def h4_block_by_hash():
    (v, _), _ = go("H4", Chain(), Chain())
    assert v == "PASS"
    (v, f), _ = go("H4", Chain(), Chain(other_block=True))
    assert v == "FAIL" and f["endpoints"][1]["made_up"] == "another block", f


# ---- H5: the latest - finalized gap; p99 over the samples in the summary


def h5_gap():
    (v, f), d = go("H5", Chain(head=1000, finalized=900), Chain(head=1000, finalized=900))
    assert v == "INFO" and f["endpoints"][0] == {"blocks": 100, "secs": 1200}, f
    (v, f), _ = go("H5", Chain(no_finalized=True), Chain())
    assert v == "FAIL", f
    # one provider's `finalized` is its head, another's is final: the tag means two things on one chain
    (v, f), _ = go("H5", Chain(head=1000, finalized=1000), Chain(head=1000, finalized=600))
    assert v == "FAIL" and "differ" in f["why"], f
    (v, f), _ = go("H5", Chain(head=1000, finalized=1000), Chain(head=1000, finalized=1000))
    assert v == "INFO", "control: a chain final at its head on every endpoint"


# ---- H6: eth_getLogs range limits


def h6_log_span():
    (v, f), _ = go("H6", Chain(log_span=1000, head=200_000), Chain(log_span=100_000, head=200_000))
    assert v == "INFO" and f["endpoints"][0]["largest_span"] == 1000 and f["endpoints"][1]["largest_span"] == 100_000, f
    # a refusal on HTTP 400 with a JSON-RPC error is the endpoint's answer; HTTP 429 is no answer
    (v, f), _ = go("H6", Chain(log_span=100, head=200_000, http_status=400), Chain(head=200_000))
    assert v == "INFO" and f["endpoints"][0]["largest_span"] == 100, f
    (v, f), _ = go("H6", Chain(log_span=100, head=200_000, http_status=429), Chain(head=200_000))
    assert v == "UNREAD", f


# ---- H7: finalized served and never moving back


def h7_finalized_never_back():
    d = tempfile.mkdtemp()
    c = Chain(head=1000, finalized=900)
    url = serve(c)
    assert P.run("H7", ROW, [url], d)[0] == "PASS"
    c.fin = 950
    assert P.run("H7", ROW, [url], d)[0] == "PASS", "control: forward"
    c.fin = 940
    v, f = P.run("H7", ROW, [url], d)
    assert v == "FAIL" and "back" in f["endpoints"][0]["why"], f
    (v, f), _ = go("H7", Chain(no_finalized=True))
    assert v == "FAIL", f


# ---- H8: a read pinned by the newest head's hash, compared once final


def h8_pinned_head_read():
    d = tempfile.mkdtemp()
    state = {"v": 7}
    c = Chain(head=100, balance=lambda blk: state["v"])
    url = serve(c)
    assert P.run("H8", ROW, [url], d)[0] == "INFO"
    c.head, c.fin = 200, 136
    v, f = P.run("H8", ROW, [url], d)
    assert v == "PASS" and f["compared"] == 1 and f["mismatch"] == 0, f
    # the answer at the head was another state's: once final the same read differs
    c.head, c.fin = 300, 236
    state["v"] = 8
    v, f = P.run("H8", ROW, [url], d)
    assert v == "FAIL" and f["mismatch"] == 1, f


# ---- the profile probes of T40


def fork_level():
    (v, f), _ = go("fork", Chain(), Chain())
    assert f["fork"] == "osaka", f
    (v, f), _ = go("fork", Chain(header=["blockAccessListHash"]))
    assert f["fork"] == "amsterdam", f
    (v, f), _ = go("fork", Chain(opcodes=(0x5F, 0x5C, 0x5E, 0x4A)))
    assert f["fork"] == "cancun", f
    (v, f), _ = go("fork", Chain(opcodes=(0x5F, 0x5C, 0x5E, 0x4A), header=["requestsHash"]))
    assert f["fork"] == "prague", f
    (v, f), _ = go("fork", Chain(opcodes=(0x5F,)))
    assert f["fork"] == "shanghai", f
    (v, f), _ = go("fork", Chain(opcodes=()))
    assert f["fork"] == "before shanghai", f
    (v, f), _ = go("fork", Chain(), Chain(opcodes=()))
    assert v == "FAIL" and "differ" in f["why"], f


def eip2537_presence():
    (v, f), _ = go("eip2537", Chain(eip2537=True), Chain(eip2537=True))
    assert v == "INFO" and f["present"] is True, f
    (v, f), _ = go("eip2537", Chain(), Chain())
    assert f["present"] is False, f


def caps_and_pq_fit():
    (v, f), _ = go("caps", Chain(tx_cap=1 << 24, gas_limit=60_000_000), Chain(tx_cap=1 << 24, gas_limit=60_000_000))
    assert f["tx_gas_cap"] == 1 << 24 and f["block_gas_limit"] == 60_000_000, f
    assert all(r["fits"] for r in f["pq"].values()), f["pq"]
    (v, f), _ = go("caps", Chain(gas_limit=8_000_000), Chain(gas_limit=8_000_000))
    assert f["tx_gas_cap"] is None, f
    assert not f["pq"]["mldsa87"]["fits"] and f["pq"]["fndsa1024"]["fits"], f["pq"]
    # the regular part against the smaller of 2^24 and the chain's cap
    (v, f), _ = go("caps", Chain(tx_cap=10_000_000), Chain(tx_cap=10_000_000))
    assert f["tx_gas_cap"] == 10_000_000 and not f["pq"]["mldsa65"]["fits"] and f["pq"]["fndsa512"]["fits"], f["pq"]
    # a chain publishing its transaction limit (Arbitrum's ArbGasInfo) bounds the whole transaction, whatever its header says
    arb = dict(gas_limit=1 << 50, arb_tx_limit=32_000_000)
    (v, f), _ = go("caps", Chain(**arb), Chain(**arb))
    assert f["published_tx_limit"] == 32_000_000, f
    assert not f["pq"]["mldsa65"]["fits"] and f["pq"]["slhdsa128s"]["fits"], f["pq"]
    (v, f), _ = go("caps", Chain(gas_limit=1 << 50), Chain(gas_limit=1 << 50))
    assert f["published_tx_limit"] is None and f["pq"]["mldsa65"]["fits"], "control"
    # the sender's balance is never read as the chain's cap: the zero address funds 21,000 gas, the chain caps none
    (v, f), _ = go("caps", Chain(sender_funds=21_000), Chain(sender_funds=21_000))
    assert f["tx_gas_cap"] is None, f


def code_size_limits():
    (v, f), _ = go("codesize", Chain(), Chain())
    assert (f["code_limit"], f["initcode_limit"]) == (24576, 49152), f
    (v, f), _ = go("codesize", Chain(code_limit=32768), Chain(code_limit=32768))
    assert f["code_limit"] == 32768, f
    # a size the call's gas cannot deposit is untested, never a limit
    (v, f), _ = go("codesize", Chain(code_limit=1 << 20, deposit_gas=65_536), Chain(code_limit=1 << 20, deposit_gas=65_536))
    assert f["code_limit"] == ">=65536 (gas-bound)", f
    # a limit between two candidates is found exactly; an endpoint bound by its gas defers to one that measured
    (v, f), _ = go("codesize", Chain(code_limit=40_000, init_limit=100_000), Chain(code_limit=40_000, init_limit=100_000, deposit_gas=30_000))
    assert v == "INFO" and (f["code_limit"], f["initcode_limit"]) == (40_000, 100_000), f
    (v, f), _ = go("codesize", Chain(code_limit=40_000), Chain(code_limit=32_768))
    assert v == "FAIL", f


def base_fee_type():
    (v, f), _ = go("basefee", Chain(), Chain())
    assert f["tx_type"] == 2, f
    (v, f), _ = go("basefee", Chain(no_base_fee=True), Chain(no_base_fee=True))
    assert f["tx_type"] == 0, f


def l1_fee_model():
    (v, f), _ = go("l1fee", Chain(op_stack=True), Chain(op_stack=True))
    assert f["model"] == "op-stack" and f["endpoints"][0]["get_l1_fee"] == 12345, f
    (v, f), _ = go("l1fee", Chain(estimate=21500), Chain(estimate=21500))
    assert f["model"] == "in-estimate", f
    (v, f), _ = go("l1fee", Chain(linea=True), Chain(linea=True))
    assert f["model"] == "linea", f
    # the method served (a refusal for the sender's balance is not "no such method") by one provider and not the other
    (v, f), _ = go("l1fee", Chain(linea="unfunded"), Chain())
    assert v == "INFO" and f["model"] == "linea", f
    # a gateway naming the method as not served has no such method (Moonbeam, 2026-11-22)
    (v, f), _ = go("l1fee", Chain(linea="gateway"), Chain())
    assert f["model"] == "none", f
    (v, f), _ = go("l1fee", Chain(arb_tx_limit=32_000_000), Chain(arb_tx_limit=32_000_000))
    assert f["model"] == "in-estimate", "Arbitrum's ArbGasInfo, whatever its L1 price today"
    (v, f), _ = go("l1fee", Chain(), Chain())
    assert f["model"] == "none", f
    (v, f), _ = go("l1fee", Chain(op_stack=True, l1_answer="0x01"), Chain(op_stack=True))
    assert v == "FAIL", f


# ---- an endpoint that does not answer: UNREAD, never a verdict on the chain


def rate_limited_is_unread():
    (v, f), _ = go("H1", Chain(), Chain(rate_limited=1))
    assert v == "UNREAD" and "rate" in f["why"], f
    (v, f), _ = go("fork", Chain(), Chain(rate_limited=0))
    assert v == "UNREAD", f
    (v, f), _ = go("caps", Chain(), Chain(rate_limited=2))
    assert v == "UNREAD", f
    (v, f), _ = go("H1", Chain(), Chain(rate_limited=5))
    assert v == "PASS", "control"


# ---- the records: no URL path or query, a summary without paths


def logs_and_summary():
    (v, f), d = go("H1", Chain(), Chain())
    text = open(os.path.join(d, "2026-11-22-evm-probes-x-mainnet-H1.log")).read()
    assert "secret-path" not in text and "key=k" not in text, text
    go("H5", Chain(head=1000, finalized=900), Chain(head=1000, finalized=990), logdir=d)
    out = os.path.join(d, "summary.txt")
    P.summary(d, out)
    s = open(out).read()
    assert "x-mainnet | H1 | 1 | PASS" in s and "x-mainnet | H5 | 1 | INFO" in s, s
    assert "p99 100 blocks" in s, s
    assert "/" not in s.split("\n", 1)[1].replace("2^24", ""), s
    # another checkout's row (no log here) stays; a row of a key and probe logged here is replaced (control)
    with open(out, "a") as fh:
        fh.write("a-mainnet | H1 | 3 | PASS | elsewhere | t .. t\nx-mainnet | H5 | 9 | FAIL | stale | t .. t\n")
    P.summary(d, out)
    s = open(out).read()
    assert "a-mainnet | H1 | 3 | PASS | elsewhere" in s and "stale" not in s, s
    assert "x-mainnet | H5 | 1 | INFO" in s, s


TESTS = [h1_block0_and_chain_id, h2_eip1898, h3_replaced_heads_counted, h4_block_by_hash, h5_gap, h6_log_span,
         h7_finalized_never_back, h8_pinned_head_read, fork_level, eip2537_presence, caps_and_pq_fit, code_size_limits,
         base_fee_type, l1_fee_model, rate_limited_is_unread, logs_and_summary]

if __name__ == "__main__":
    want = set(sys.argv[1:])
    bad = 0
    P.QUIET = True
    for t in TESTS:
        if want and t.__name__ not in want:
            continue
        try:
            t()
            print(f"ok {t.__name__}")
        except Exception as e:  # noqa: BLE001 every failure is reported, then the exit code
            bad += 1
            print(f"not ok {t.__name__}: {type(e).__name__}: {str(e)[:300]}")
    for s in SERVERS:
        s.shutdown()
    print(f"{len(TESTS) - bad if not want else len(want) - bad} passed, {bad} failed")
    sys.exit(1 if bad else 0)
