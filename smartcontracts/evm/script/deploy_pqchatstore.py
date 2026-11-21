#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""CTR-CHAT-22's deploy path (spec 2026-11-21-avax-polkadot-arweave §5.3, C23; plan T6): `PqChatStore`, the `amsterdam`
build, through the deterministic deployer 0x4e59b448…956c with salt 0, so one address on every chain. The release data
(release-data/PqChatStore.json) pins the init-code hash, the runtime code hash, the CREATE2 address and the precompiles
(none). Each refusal is named CHATSTORE_*:
  CHATSTORE_RELEASE      the release data lacks a field, or its address is not the deployer's CREATE2 of the pinned init-code
                         hash with salt 0;
  CHATSTORE_INIT_HASH    the local build's init code is not the pinned one (another compiler setting gives another address
                         while the runtime hash still passes);
  CHATSTORE_RUNTIME_HASH the local build's runtime is not the pinned one;
  CHATSTORE_NO_DEPLOYER  the deployer's code is absent or not the deployer's (on Polkadot Hub it may be absent);
  CHATSTORE_CODE_HASH    the code at the pinned address is not the pinned runtime: before the send (someone deployed other
                         code there), after it, or at the probe; the pinned code already there is done, with no send;
  CHATSTORE_FORKCHECK    NET-EVM-18's five checks (forkcheck.py) refuse, before any send, on a profile without amsterdam;
  CHATSTORE_SEND         no strict majority on the chain id, nonce or fees; the signed bytes are not the transaction asked;
                         no node took them, the nodes answered other hashes, the receipt failed or never came;
  CHATSTORE_FEE          the majority's priority fee is above the max fee (FEE_FACTOR x the majority's gas price);
  CHATSTORE_PROBE        the SSTORE2 write and read of the probe gave other bytes;
  CHATSTORE_BOOK         the chain's key (deploybook.py: chain-uids.json by (chainId, chain_uid), else DEPLOY_NAME).
The chain's key names both its profile (src/chains/<key>/profile.json) and its book (deployments/<key>.json, the deploybook
header, the entry under `PqChatStore`). Reads take the strict majority of the node list; a write sends the same signed bytes
to every node (ARCH-POS-15). Signing is cast's (`cast mktx`, its wallet options after `--`, e.g. `--account <name>`), the
chain id, nonce and fees given explicitly from the majority's reads, the signed bytes decoded and compared before any send.
  python3 -I script/deploy_pqchatstore.py deploy <rpc>[,<rpc>…] --out <forge out> [-- <cast wallet options>]
  python3 -I script/deploy_pqchatstore.py probe <rpc>[,<rpc>…] --out <forge out> [-- <cast wallet options>]
      the probes before a profile lists the store: the deployer's code, eth_getCode equal to the pinned bytes, an SSTORE2
      write and read (one storeMessage under PROBE_HINT, read back by storedAt); recorded as the book entry's `probe`
  scripts/capped python3 -I script/deploy_pqchatstore.py local --out <forge out>
      the gate: a fresh `anvil --hardfork cancun --code-size-limit 24576` as a cancun profile `local-testnet`: deploy (sent),
      deploy again (done, no send), probe; books in a temp dir
  python3 -I script/deploy_pqchatstore.py cases     prints the cases NET-EVM-18 (4) runs at the chain's fork on the
      amsterdam artifact's bytes (generated here at each deploy, never a file edited by hand)
<forge out>: `forge build src/pqchat/PqChatStore.sol test/forkcheck --extra-output evm.legacyAssembly --out <dir>`.
UNAUDITED tooling."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deploybook  # noqa: E402
import forkcheck as f  # noqa: E402

EVM = f.EVM
DEPLOYER = "0x4e59b44847b379578588920ca78fbf26c0b4956c"  # the deterministic CREATE2 deployer (NET-EVM-05)
DEPLOYER_CODE = (  # its runtime: salt (32 B) ‖ init code in, the new address out
    "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f580151560"
    "39578182fd5b8082525050506014600cf3"
)
SALT = "00" * 32
NAME = "PqChatStore"
ARTIFACT = "PqChatStore.sol/PqChatStore.json"
RELEASE = "release-data/PqChatStore.json"
STORED_TOPIC = "0x50642adf71fc579730c87dc9ee28508e0192a61b3b170f9dad70ce3c2e54cbbe"  # PqChatStored(bytes8,uint256)
PROBE_HINT = bytes.fromhex("e8acd975480bd0a4")  # bytes8(keccak256("scaas.pqchatstore.probe"))
PROBE_ENV = b"scaas.pqchatstore.probe"
CAST = shutil.which("cast") or os.path.expanduser("~/.foundry/bin/cast")


class StoreError(Exception):
    """A named refusal: the message starts with its name."""


def keccak(hexdata):
    r = subprocess.run([CAST, "keccak"], input=hexdata, capture_output=True, text=True)
    if r.returncode:
        raise StoreError(f"CHATSTORE_RELEASE: cast keccak failed (rc {r.returncode})")
    return r.stdout.strip().lower()


def create2_address(init_hash):
    return "0x" + keccak("0xff" + DEPLOYER[2:] + SALT + init_hash[2:])[-40:]


# ---- ABI (the store's arguments and answers)


def word(n):
    return n.to_bytes(32, "big")


def _pad(b):
    return b + b"\0" * (-len(b) % 32)


def payload(v, hint, env):
    """abi.encode(uint8 v, bytes8 hint, bytes env): what storeMessage keeps, and its calldata after the selector."""
    return word(v) + hint.ljust(32, b"\0") + word(0x60) + word(len(env)) + _pad(env)


def abi_bytes(b):
    """A `bytes` return value."""
    return word(0x20) + word(len(b)) + _pad(b)


def abi_bytes_array(items):
    """A `bytes[]` return value."""
    heads, tails, at = b"", b"", 32 * len(items)
    for b in items:
        heads += word(at + len(tails))
        tails += word(len(b)) + _pad(b)
    return word(0x20) + word(len(items)) + heads + tails


# ---- the release data and the local build


def release_data(r):
    """The release data, its address the deployer's CREATE2 of its init-code hash at salt 0."""
    for k in ("initCodeHash", "runtimeCodeHash", "address"):
        if not isinstance(r.get(k), str) or not re.fullmatch(r"0x[0-9a-fA-F]+", r[k]):
            raise StoreError(f"CHATSTORE_RELEASE: no {k}")
    if not isinstance(r.get("precompiles"), list):
        raise StoreError("CHATSTORE_RELEASE: no precompiles list")
    if create2_address(r["initCodeHash"].lower()) != r["address"].lower():
        raise StoreError(
            f"CHATSTORE_RELEASE: {r['address']} is not the deployer's CREATE2 of the init-code hash, salt 0"
        )
    return r


def local_build(a, rel):
    if keccak(a["bytecode"]["object"]) != rel["initCodeHash"].lower():
        raise StoreError(f"CHATSTORE_INIT_HASH: the local build's init code is not {rel['initCodeHash'][:18]}…")
    if keccak(a["deployedBytecode"]["object"]) != rel["runtimeCodeHash"].lower():
        raise StoreError(f"CHATSTORE_RUNTIME_HASH: the local build's runtime is not {rel['runtimeCodeHash'][:18]}…")


# ---- the chain


def _read(nodes, method, params, pick):
    """The strict majority on `pick`'s value (forkcheck.agree)."""
    try:
        a = f.agree(nodes, method, params, pick)
    except f.ForkError as e:
        raise StoreError(f"CHATSTORE_SEND: {e}") from None
    if "error" in a:
        raise StoreError(f"CHATSTORE_SEND: {method} answered an error")
    return a["result"]


def chain_key(nodes, env):
    """The chain's key and book header (deploybook.py)."""
    cid = _read(nodes, "eth_chainId", [], f.qty)
    uid = _read(nodes, "eth_getBlockByNumber", ["0x0", False], lambda r: f.data(r["hash"]))
    try:
        key, name, net = deploybook.resolve(cid, uid, env)
    except deploybook.BookError as e:
        raise StoreError(f"CHATSTORE_BOOK: {e}") from None
    return key, deploybook.header(key, name, cid, uid, net)


def deployer_present(nodes):
    if _read(nodes, "eth_getCode", [DEPLOYER, "latest"], f.data) != DEPLOYER_CODE:
        raise StoreError(f"CHATSTORE_NO_DEPLOYER: no deterministic deployer code at {DEPLOYER} (NET-EVM-05)")


def code_hash(nodes, rel):
    """The keccak of the code at the pinned address, None when there is none."""
    code = _read(nodes, "eth_getCode", [rel["address"], "latest"], f.data)
    return None if code == "0x" else keccak(code)


FEE_FACTOR = 2  # the max fee per gas: this times the gas price a strict majority reports at least (review P2-1)
SIGNED = ("chainId", "nonce", "gas", "maxFeePerGas", "maxPriorityFeePerGas")


def _cast(args, url, what):
    r = subprocess.run([CAST] + args, capture_output=True, text=True, env=dict(os.environ, ETH_RPC_URL=url))
    if r.returncode:
        raise StoreError(f"CHATSTORE_SEND: cast {what} failed (rc {r.returncode}): {r.stderr.replace(url, '<rpc>')[:200]}")
    return r.stdout.strip()


def decoded(raw):
    """`cast decode-tx` of signed bytes (offline)."""
    try:
        return json.loads(_cast(["decode-tx", raw], "", "decode-tx"))
    except json.JSONDecodeError:
        raise StoreError("CHATSTORE_SEND: cast decode-tx gave no JSON") from None


def cast_signer(url, wallet):
    """Signs with cast (`cast mktx`, the wallet options `wallet`) the transaction asked: its chain id, nonce, gas and fees
    explicit, so cast consults no node for them (review P2-1); the signed bytes are decoded and compared with it, signer
    included. The node URL goes through ETH_RPC_URL, never argv (`--ethsign` signs on that node). `sign.address()` is the
    signer (`--from`, else `cast wallet address` of the wallet options, once)."""
    who = {}

    def address():
        if "a" not in who:
            who["a"] = (wallet[wallet.index("--from") + 1] if "--from" in wallet
                        else _cast(["wallet", "address"] + wallet, url, "wallet address")).lower()  # fmt: skip
        return who["a"]

    def sign(tx):
        args = ["mktx", tx["to"], tx["data"], "--gas-limit", str(tx["gas"]), "--chain", str(tx["chainId"])]
        args += ["--nonce", str(tx["nonce"]), "--gas-price", str(tx["maxFeePerGas"])]
        args += ["--priority-gas-price", str(tx["maxPriorityFeePerGas"])]
        raw = _cast(args + wallet, url, "mktx")
        got = decoded(raw)
        try:
            bad = [k for k in SIGNED if f.qty(got.get(k)) != tx[k]]
            want = (("to", tx["to"]), ("input", tx["data"]), ("signer", address()))
            bad += [k for k, v in want if f.data(got.get(k)) != v.lower()]
            bad += [] if got.get("type") == "0x2" else ["type"]
        except f.BAD_ANSWER:
            bad = ["a field"]
        if bad:
            raise StoreError(f"CHATSTORE_SEND: the signed transaction is not the one asked ({', '.join(bad)})")
        return raw

    sign.address = address
    return sign


def _number(nodes, method, params):
    try:
        return f.majority_number(nodes, method, params)
    except f.ForkError as e:
        raise StoreError(f"CHATSTORE_SEND: {e}") from None


def receipt_fields(r):
    """A receipt's consensus fields, as voted on (review P2-2); None: no receipt yet."""
    if r is None:
        return None
    logs = [{"address": f.data(x["address"]), "topics": [f.data(t) for t in x["topics"]], "data": f.data(x["data"])}
            for x in r.get("logs") or []]  # fmt: skip
    ca = r.get("contractAddress")
    return {
        "status": f.qty(r["status"]),
        "blockHash": f.data(r["blockHash"]),
        "blockNumber": f.qty(r["blockNumber"]),
        "gasUsed": f.qty(r["gasUsed"]),
        "contractAddress": f.data(ca) if ca else None,
        "logs": logs,
    }


def send(nodes, sign, to, data, gas=None, chain_id=None, wait=600):
    """Signs once (at `gas`, default the estimate a strict majority reaches) the transaction whose chain id and nonce a strict
    majority gives (the chain id the one the key was resolved by), its max fee FEE_FACTOR times the gas price a strict
    majority reports at least, its tip the priority fee a strict majority reports at least, refused above that max fee
    (CHATSTORE_FEE); sends the same bytes to every node; returns (hash, receipt)."""
    cid = _read(nodes, "eth_chainId", [], f.qty)
    if chain_id is not None and cid != chain_id:
        raise StoreError(f"CHATSTORE_SEND: the nodes now answer chain id {cid}, the chain resolved is {chain_id}")
    nonce = _read(nodes, "eth_getTransactionCount", [sign.address(), "latest"], f.qty)
    cap = FEE_FACTOR * _number(nodes, "eth_gasPrice", [])
    tip = _number(nodes, "eth_maxPriorityFeePerGas", [])
    if tip > cap:
        raise StoreError(
            f"CHATSTORE_FEE: the priority fee {tip} is above the max fee {cap} ({FEE_FACTOR} x the majority's gas price)"
        )
    gas = gas or _number(nodes, "eth_estimateGas", [{"to": to, "data": data}])
    tx = {"to": to, "data": data, "gas": gas, "chainId": cid, "nonce": nonce, "maxFeePerGas": cap}
    raw = sign(dict(tx, maxPriorityFeePerGas=tip))
    answers = [n("eth_sendRawTransaction", [raw]) for n in nodes]
    hashes = set()
    for a in answers:
        try:
            hashes |= {f.data(a["result"])} if "result" in a else set()
        except f.BAD_ANSWER:
            raise StoreError("CHATSTORE_SEND: a node answered eth_sendRawTransaction with no hash") from None
    if len(hashes) != 1:
        raise StoreError(f"CHATSTORE_SEND: {len(hashes)} distinct hashes from {len(nodes)} nodes")
    h = hashes.pop()
    for _ in range(wait):  # a bounded wait for the majority's receipt
        try:
            rec = f.agree(nodes, "eth_getTransactionReceipt", [h], receipt_fields).get("result")
        except f.ForkError:
            rec = None
        if rec:
            if rec["status"] != 1:
                raise StoreError(f"CHATSTORE_SEND: {h} failed (status 0)")
            return h, rec
        time.sleep(0.5)
    raise StoreError(f"CHATSTORE_SEND: no receipt for {h}")


def _book(books, key, header, update):
    """deployments/<key>.json under `books`: its header checked, the entry under NAME updated by `update`."""
    p = os.path.join(books, "deployments", f"{key}.json")
    try:
        b = deploybook.check(json.load(open(p)), p) if os.path.exists(p) else dict(header)
    except deploybook.BookError as e:
        raise StoreError(f"CHATSTORE_BOOK: {e}") from None
    b[NAME] = update(b.get(NAME) or {})
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        json.dump(b, fh, indent=2)
        fh.write("\n")
    return b[NAME]


def _load(out, release):
    rel = release_data(json.load(open(release)))
    a = f.load_artifact(os.path.join(out, ARTIFACT))
    return rel, a


def deploy(
    nodes,
    sign,
    out,
    release=os.path.join(EVM, RELEASE),
    books=EVM,
    profiles=None,
    env=os.environ,
    say=print,
    run4=None,
):
    """The deploy path; returns the book entry (`tx` None when the pinned code was there)."""
    rel, a = _load(out, release)
    local_build(a, rel)
    key, header = chain_key(nodes, env)
    deployer_present(nodes)
    addr, tx = rel["address"].lower(), None
    have = code_hash(nodes, rel)
    if have is None:
        data = "0x" + SALT + a["bytecode"]["object"][2:]
        gas = _number(nodes, "eth_estimateGas", [{"to": DEPLOYER, "data": data}])
        try:  # NET-EVM-18 on a profile without amsterdam, before any send; (4) runs the generated cases
            with tempfile.TemporaryDirectory() as t:
                cs = os.path.join(t, "cases.json")
                with open(cs, "w") as fh:
                    json.dump(cases(), fh)
                f.deploy_gate(
                    key, os.path.join(out, ARTIFACT), nodes, cs, "0x", gas, release, say, EVM, run4, out, profiles
                )
        except f.ForkError as e:
            raise StoreError(f"CHATSTORE_FORKCHECK: {e}") from None
        tx, rec = send(nodes, sign, DEPLOYER, data, gas, header["chainId"])
        say(f"{key}: sent {tx}, gas {rec['gasUsed']}")
        have = code_hash(nodes, rel)
    else:
        say(f"{key}: code already at {addr}, no send")
    if have != rel["runtimeCodeHash"].lower():
        raise StoreError(
            f"CHATSTORE_CODE_HASH: the code at {addr} is not the pinned runtime ({(have or 'none')[:18]}…)"
        )
    entry = {
        "address": addr,
        "deployer": DEPLOYER,
        "salt": "0x" + SALT,
        "initCodeHash": rel["initCodeHash"].lower(),
        "runtimeCodeHash": rel["runtimeCodeHash"].lower(),
        "tx": tx,
    }
    keep = lambda old: {**old, **entry, "tx": tx or old.get("tx")}  # noqa: E731  (a later run keeps the sending tx)
    _book(books, key, header, keep)
    return entry


def probe(nodes, sign, out, release=os.path.join(EVM, RELEASE), books=EVM, env=os.environ, say=print, **_):
    """The probes before a profile lists the store; returns the book entry's `probe`."""
    rel, a = _load(out, release)
    key, header = chain_key(nodes, env)
    deployer_present(nodes)
    addr = rel["address"].lower()
    if code_hash(nodes, rel) != rel["runtimeCodeHash"].lower():
        raise StoreError(f"CHATSTORE_CODE_HASH: eth_getCode at {addr} is not the pinned runtime")
    ids, want = a["methodIdentifiers"], payload(1, PROBE_HINT, PROBE_ENV)
    h, rec = send(nodes, sign, addr, "0x" + ids["storeMessage(uint8,bytes8,bytes)"] + want.hex(), None, header["chainId"])
    hint = "0x" + PROBE_HINT.hex() + "00" * 24
    logs = [x for x in rec["logs"] if x["address"] == addr and x["topics"] == [STORED_TOPIC, hint]]
    if len(logs) != 1:
        raise StoreError(f"CHATSTORE_PROBE: {len(logs)} PqChatStored events of the probe hint in {h}")
    try:
        index = f.qty(logs[0]["data"])
    except f.BAD_ANSWER:
        raise StoreError(f"CHATSTORE_PROBE: the probe event's data in {h} is no index") from None
    call = "0x" + ids["storedAt(bytes8,uint256)"] + PROBE_HINT.ljust(32, b"\0").hex() + word(index).hex()
    got = _read(nodes, "eth_call", [{"to": addr, "data": call}, "latest"], f.data)
    if got != "0x" + abi_bytes(want).hex():
        raise StoreError(f"CHATSTORE_PROBE: storedAt(probe hint, {index}) is not the bytes written")
    p = {"tx": h, "block": rec["blockNumber"], "index": index}
    say(f"{key}: probes ok (deployer, code hash, SSTORE2 write {h} and read at index {index})")
    _book(books, key, header, lambda old: dict(old or {"address": addr}, probe=p))
    return p


# ---- the gate: a local anvil at cancun


def local(out, say=print):
    cancun = {"evmFork": "cancun", "codeSizeLimit": 24576, "initCodeSizeLimit": 49152}
    with tempfile.TemporaryDirectory() as t, f.Anvil("cancun", cancun["codeSizeLimit"]) as rpc:
        os.makedirs(os.path.join(t, "src/chains/local-testnet"))
        with open(os.path.join(t, "src/chains/local-testnet/profile.json"), "w") as fh:
            json.dump(cancun, fh)
        frm = rpc("eth_accounts", [])["result"][0]
        sign = cast_signer(rpc.url, ["--ethsign", "--from", frm])
        o = {"out": out, "books": t, "profiles": t, "env": {"DEPLOY_NAME": "local-testnet"}, "say": say}
        first = deploy([rpc], sign, **o)
        if not first["tx"]:
            raise StoreError("CHATSTORE_SEND: a fresh chain had code at the pinned address")
        if deploy([rpc], sign, **o)["tx"] is not None:
            raise StoreError("CHATSTORE_SEND: a second deploy sent")
        say("deploy again: done, no send")
        probe([rpc], sign, **o)
        say(json.dumps(json.load(open(os.path.join(t, "deployments/local-testnet.json")))[NAME]))
    return 3


# ---- NET-EVM-18 (4)'s cases for PqChatStore


def cases():
    """The T5 cases, at the chain's fork on the amsterdam artifact's bytes; each `contracts` entry is a fresh deploy (its
    creation code alone, the deployed code compared with the artifact's runtime)."""
    H, H2, Z = bytes.fromhex("0102030405060708"), bytes.fromhex("1112131415161718"), b"\0" * 8
    max_ = 2**256 - 1
    shape = keccak("0x" + b"PqChatShape()".hex())[:10]
    panic32 = "0x4e487b71" + word(0x32).hex()
    sigs = ["storeMessage(uint8,bytes8,bytes)", "storedCount(bytes8)", "storedAt(bytes8,uint256)"]
    sigs.append("storedRange(bytes8,uint256,uint256)")
    store_id = 0
    for s in sigs:
        store_id ^= int(keccak("0x" + s.encode().hex())[2:10], 16)
    ipqchat_id = "a46bb0a4"  # type(IPqChat).interfaceId (its 53 selectors XORed, forge's artifact)

    def h32(b):
        return b.ljust(32, b"\0")

    def x(b):
        return "0x" + b.hex()

    def store(v, hint, env, index=None, ok=True, frm=None):
        c = {"name": f"storeMessage({v}, {hint.hex()}, {len(env)} B)", "sig": sigs[0], "args": x(payload(v, hint, env))}
        c["ok"] = ok
        if ok:
            c["return"] = x(word(index))
            c["logs"] = [{"topics": [STORED_TOPIC, x(h32(hint))], "data": x(word(index))}]
        else:
            c["revert"] = shape
        if frm is not None:
            c["from"] = frm
            c["name"] += f" from account {frm}"
        return c

    def count(hint, n):
        return {"name": f"storedCount({hint.hex()}) = {n}", "sig": sigs[1], "args": x(h32(hint)), "ok": True,
                "return": x(word(n))}  # fmt: skip

    def at(hint, i, want=None, frm=None):
        c = {"name": f"storedAt({hint.hex()}, {i})", "sig": sigs[2], "args": x(h32(hint) + word(i))}
        c.update({"ok": True, "return": x(abi_bytes(want))} if want is not None else {"ok": False, "revert": panic32})
        if frm is not None:
            c["from"] = frm
        return c

    def rng(hint, off, lim, items):
        return {"name": f"storedRange({hint.hex()}, {off}, {lim}) = {len(items)}", "sig": sigs[3],
                "args": x(h32(hint) + word(off) + word(lim)), "ok": True, "return": x(abi_bytes_array(items))}  # fmt: skip

    def iface(i, yes):
        return {"name": f"supportsInterface(0x{i}) = {yes}", "sig": "supportsInterface(bytes4)",
                "args": x(bytes.fromhex(i).ljust(32, b"\0")), "ok": True, "return": x(word(int(yes)))}  # fmt: skip

    e1, e0 = bytes.fromhex("abcdef"), b""
    one = [
        store(1, H, e1, 0),
        store(1, H, e0, 1),
        count(H, 2),
        at(H, 0, payload(1, H, e1)),
        at(H, 1, payload(1, H, e0)),
    ]
    lists = [store(1, H, b"\x01", 0), store(1, H2, b"\x02", 0), store(1, H, b"\x03", 1), count(H, 2), count(H2, 1)]
    lists += [count(Z, 0), at(H, 1, payload(1, H, b"\x03")), at(H2, 0, payload(1, H2, b"\x02"))]
    p18 = [payload(1, H, word(i)) for i in range(18)]
    eighteen = [store(1, H, word(i), i) for i in range(18)]
    eighteen += [rng(H, 0, 100, p18[0:16]), rng(H, 1, max_, p18[1:17]), rng(H, 16, 100, p18[16:18])]
    eighteen += [rng(H, 2, 3, p18[2:5])]
    eighteen += [{"name": "STORED_RANGE_MAX() = 16", "sig": "STORED_RANGE_MAX()", "ok": True, "return": x(word(16))}]
    p2 = [payload(1, H, b"\x0a"), payload(1, H, b"\x0b")]
    two = [
        store(1, H, b"\x0a", 0),
        store(1, H, b"\x0b", 1),
        rng(H, 1, 16, p2[1:]),
        rng(H, 2, 16, []),
        rng(H, 3, 16, []),
    ]
    two += [rng(H, max_, max_, []), rng(H2, 0, 16, []), rng(H, 0, 0, [])]
    shapes = [store(2, H, e1, ok=False), store(0, H, e1, ok=False), store(255, H, e1, ok=False), store(1, H, e1, 0)]
    big = [store(1, H, b"\x5a" * 24416, 0), store(1, H, b"\x5a" * 24417, ok=False), count(H, 1)]
    big += [store(1, H, b"\x5a" * 24416, 1)]  # T8's warm 24,416-B row
    # T8's Cancun rows beside the Amsterdam pins (test/pqchat/PqChatStoreGas.t.sol): 2,400 B and 5,100 B, new hint then warm
    gas = [
        store(1, H, bytes(2400), 0),
        store(1, H, bytes(2400), 1),
        store(1, H2, bytes(5100), 0),
        store(1, H2, bytes(5100), 1),
    ]
    ids = [iface("01ffc9a7", True), iface(f"{store_id:08x}", True), iface("ffffffff", False), iface(ipqchat_id, False)]

    def sender(frm):
        return [store(1, H, e1, 0, frm=frm), at(H, 0, payload(1, H, e1), frm=frm)]

    groups = [one, lists, [store(1, H, e1, 0), at(H, 1)], eighteen, two, shapes, big, ids, sender(0), sender(1), gas]
    return {
        "note": "PqChatStore's T5 cases (plan T6), "
        "run by forkcheck.py at the chain's fork on the amsterdam artifact's bytes: (1) append, event, count, storedAt; "
        "(2) per-hint lists; (3) an index past the end reverts Panic 0x32; (4) storedRange clamped to 16; (5) an offset "
        "past the end an empty page; (6) v != 1 refused; (7) env 24,416 B kept, 24,417 B refused; (8) ERC-165; (9) two "
        "senders, the same result; (10) T8's gas rows, 2,400 B and 5,100 B at a new hint, then warm; (11) each entry deploys from its creation code alone, its code the artifact's runtime.",
        "contracts": [{"artifact": ARTIFACT, "cases": g} for g in groups],
    }


def main(argv):
    try:
        if argv == ["cases"]:
            print(json.dumps(cases(), indent=1))
            return 0
        say = lambda s: print(f"[chatstore] {s}", flush=True)  # noqa: E731
        if argv[:1] == ["local"] and argv[1:2] == ["--out"] and len(argv) == 3:
            n = local(os.path.abspath(argv[2]), say)
            print(f"ok {n}/{n}")
            return 0
        if argv[:1] in (["deploy"], ["probe"]) and len(argv) >= 4 and argv[2] == "--out":
            urls = [u for u in argv[1].split(",") if u]
            wallet = argv[5:] if argv[4:5] == ["--"] else []
            if len(argv) > 4 and argv[4:5] != ["--"]:
                sys.exit(__doc__)
            nodes, sign = [f.http_node(u) for u in urls], cast_signer(urls[0], wallet)
            fn = deploy if argv[0] == "deploy" else probe
            print(json.dumps(fn(nodes, sign, os.path.abspath(argv[3]), say=say)))
            return 0
        sys.exit(__doc__)
    except StoreError as e:
        print(f"[chatstore] FAIL {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
