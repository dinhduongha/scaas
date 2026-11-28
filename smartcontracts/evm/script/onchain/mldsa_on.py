#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Deploy set `mldsa-on` (owner 2026-11-16, README-mldsa-on.md): the rows forge cannot run there, as real transactions.
Forge runs every call in its own EVM first, which has neither the ML-DSA nor the PQZ precompile, so a forge group with an
ML-DSA holder sends nothing on that set. These rows: e2e.py's helpers (imported through pq.py: ABI, Sender, ML-DSA by
mldsa.mjs over clientkeys, R_REG by pqz-ffi), every digest the contracts' own view, the set's contracts from the book.
  python3 -I script/onchain/mldsa_on.py --set mldsa-on --net scaas-testnet --rpc <url> [--groups mldsa,tokens,...]
Keys: ONCHAIN_K1..ONCHAIN_K3 from the environment (as matrix.sh), never printed. Records and log in MATRIX_OUT.
Test chains only. UNAUDITED."""

import argparse
import json
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pq as P  # noqa: E402  (imports e2e.py as P.E, with pq.py's recording patches)

E = P.E
EVM, VEC = P.EVM, os.path.abspath(os.path.join(P.EVM, "../vectors"))
SETS = {"mldsa-off": "off", "mldsa-on": "on"}  # label -> the deploy's MLDSA_PRECOMPILE (reset 5, deploybook.py SETS)
GROUPS = ("mldsa", "tokens", "pqchat", "pqzkeys", "pqzwallet")
CAP_7825 = 1 << 24  # EIP-7825: the chain caps a transaction's regular gas here
REC, SENDERS, NEGS = [], [], [0, 0]
DEP = {}  # the set's book entries
NET, GROUP, LOGF = "", "", None


class Stop(SystemExit):
    """A named stop: the message starts with its name; nothing more is sent."""


# ------------------------------------------------------------------ the set by name


def set_entries(book, label):
    """The entries of deploy set `label` in `book` (deployments/<key>.json): `sets.<label>` (reset 5's two-set book), or a
    flat book that is that set (one deploy); refused by name otherwise."""
    if label not in SETS:
        raise Stop(f"DEPLOY_SET_UNKNOWN: {label!r} is not a deploy set ({', '.join(SETS)})")
    if "sets" in book:
        if label not in book["sets"]:
            raise Stop(f"DEPLOY_SET_MISSING: the book has no set {label} (sets: {', '.join(book['sets']) or 'none'})")
        d = dict(book["sets"][label])
    else:
        d = dict(book)
    mode = d.get("mldsa_precompile")
    if mode != SETS[label]:
        raise Stop(
            f"DEPLOY_SET_MISMATCH: set {label} is MLDSA_PRECOMPILE={SETS[label]}, the book's entry says {mode!r}"
        )
    return d


def load_book(label, book_path=None):
    """The set's entries, the book found by the chain's key (NET-EVM-13) unless `book_path` names it."""
    chain = int(E.rpc("eth_chainId"), 16)
    g = E.rpc("eth_getBlockByNumber", ["0x0", False])["hash"]
    path = book_path or os.path.join(EVM, "deployments", E.deploybook.resolve(chain, g)[0] + ".json")
    if not os.path.exists(path):
        raise Stop(f"DEPLOY_BOOK_MISSING: {os.path.relpath(path, EVM)} (deploy the set first)")
    return set_entries(E.deploybook.check(json.load(open(path)), os.path.basename(path)), label)


# ------------------------------------------------------------------ sending, records, heartbeat


def say(s):
    print(f"[{NET}/{GROUP}] {s}", flush=True)


def gas_for(to, data, what, frm):
    """The node's estimate x 1.5 + 300 k (pq.py's margin), at most the block's gas limit; above it a named stop."""
    tx = {"from": frm, "data": "0x" + data.hex(), **({"to": to} if to else {})}
    est = int(E.rpc("eth_estimateGas", [tx]), 16)
    lim = int(E.rpc("eth_getBlockByNumber", ["latest", False])["gasLimit"], 16)
    if est > lim:
        raise Stop(f"GAS_OVER_BLOCK: {what}: estimate {est:,} > block gas limit {lim:,}")
    gas = min(lim, int(est * 1.5) + 300_000)
    if gas > CAP_7825:  # EIP-8037: regular + state; the chain caps the regular part at 2^24, which no RPC reports apart
        E.log(
            f"      {what}: asks {gas:,} > 2^24: relies on state gas (EIP-8037), the regular part capped by the chain"
        )
    return gas


def _send(self, to, data, what, gas=None):
    row = {
        "net": NET,
        "group": GROUP,
        "set": ARGS.set,
        "to": (to or "").lower(),
        "sel": data[:4].hex() if to else "create",
        "what": what,
    }
    try:
        gas = gas or gas_for(to, data, what, self.addr)
        row["asked"] = gas
        r = P._send0(self, to, data, what, gas)
    except Stop:
        raise
    except Exception as e:  # noqa: BLE001
        REC.append(row | {"tx": P.LAST.get("tx", ""), "gas": 0, "status": 0, "why": str(e)[:300]})
        raise
    REC.append(
        row
        | {
            "tx": r["transactionHash"],
            "gas": int(r["gasUsed"], 16),
            "status": int(r["status"], 16),
            "created": (r.get("contractAddress") or "").lower(),
        }
    )
    return r


E.Sender.send = _send


def neg(frm, to, data, want, what):
    """A negative by eth_call: refused with error data starting `want` (hex selector, or the whole revert data)."""
    try:
        E.rpc("eth_call", [{"from": frm, "to": to, "data": "0x" + data.hex(), "gas": hex(30_000_000)}, "latest"])
        got = "ran"
    except RuntimeError as e:
        got = str(e)
    ok = want.lower() in got.lower()
    NEGS[0] += 1
    NEGS[1] += ok
    E.check(ok, f"negative {what}: refused {want[:10]}" + ("" if ok else f" (got {got[:160]})"))
    REC.append(
        {
            "net": NET,
            "group": GROUP,
            "set": ARGS.set,
            "to": to.lower(),
            "sel": data[:4].hex(),
            "tx": "",
            "gas": 0,
            "status": 2 if ok else 0,
            "what": f"negative: {what}",
            "expected": want,
        }
    )
    return ok


def canon_env(env):
    """`MetaTxLib.canon` on an envelope [from, batch, nonce, validUntil, mode, relayer, fee, feeRecipient]: an unbound relayer
    or fee recipient (its mode bit 0x1 / 0x2 clear) is signed as zero, whatever the envelope carries."""
    e = list(env)
    if not e[4] & 0x1:
        e[5] = 0
    if not e[4] & 0x2:
        e[7] = 0
    return e


def named(tok, typ, args, env):
    """A named UA entry's digest (pq.py's `named`) over the canonical envelope."""
    return P.named(tok, typ, args, canon_env(env))


P.neg = neg  # pq.py's rows (ml_classical) record their negatives here


def control(frm, to, data, what):
    """The positive control of a negative: the same call with the good input answers."""
    try:
        E.rpc("eth_call", [{"from": frm, "to": to, "data": "0x" + data.hex(), "gas": hex(30_000_000)}, "latest"])
        return E.check(True, f"control {what}: answers")
    except RuntimeError as e:
        return E.check(False, f"control {what}: refused ({str(e)[:160]})")


def heartbeat(stop, t0):
    """Every 30 s: the senders' transactions on chain since the start (nonce deltas)."""
    base = {s.addr: int(E.rpc("eth_getTransactionCount", [s.addr, "latest"]), 16) for s in SENDERS}
    while not stop.wait(30):
        try:
            n = sum(int(E.rpc("eth_getTransactionCount", [a, "latest"]), 16) - b for a, b in base.items())
            say(f"… {n} tx on chain, {int(time.time() - t0)}s")
        except Exception:  # noqa: BLE001
            say(f"… {int(time.time() - t0)}s (RPC busy)")


# ------------------------------------------------------------------ helpers


def u(h, i=0):
    return int.from_bytes(E.words(h)[i], "big")


def ml_ua(pq, sd, name, kind, seed):
    """An ML-DSA UA of `seed`, registered with its portable PoP (e2e.py's `ml_ua`); on a cache path its expanded-key
    parts first (`cacheExpandedKey`, CTR-UA-39), on a precompile path none (the verifier refuses the cache)."""
    lvl = {E.MLDSA44: 44, E.MLDSA65: 65, 0x0134: 87}[kind]
    pk = pq.ml_pk(lvl, seed)
    reg = E.REG[0]
    ua = E.words(E.call(reg, E.cd("uaOf(uint16,bytes)", ["w", "b"], kind, pk)))[0]
    pop = pq.ml_sign(lvl, seed, E.kc(E.TAG[kind], E.portable("pop", kind=kind, ua=ua)))
    if cache_path(kind):
        for p in range(mldsa_parts(kind)):
            sd.send(
                reg,
                E.cd("cacheExpandedKey(uint16,bytes,uint256)", ["w", "b", "w"], kind, pk, p),
                f"cacheExpandedKey {name} part {p}",
            )
    sd.send(reg, E.register_cd(E.reg_args(kind, pk, pop=pop)["args"]), f"register {name} (mldsa{lvl})")
    E.check(u(E.call(reg, E.cd("kindOf(bytes32)", ["w"], ua))) == kind, f"{name} = {ua.hex()[:16]}… kindOf {kind:#06x}")
    return E.UA(name=name, kind=kind, seed=seed, pk=pk, ua=ua)


def mldsa_parts(kind):
    return {0x0130: 1, 0x0131: 2, 0x0134: 3}[kind]  # PqUA.mldsaParts


def cache_path(kind):
    """The registry's ML-DSA path of `kind` on this set: the verifier's `PRECOMPILE()` 0 is the cache."""
    v = DEP.get({0x0130: "mldsa44_verifier", 0x0131: "mldsa65_verifier", 0x0134: "mldsa87_verifier"}[kind])
    return not v or u(E.call(v, E.cd("PRECOMPILE()", []))) == 0


# ------------------------------------------------------------------ group mldsa: the registry's own path per ML-DSA kind


def g_mldsa(pq, sd, sr, s3):
    """MldsaAlt.s.sol `_kind`'s rows on the set's registry: per enabled ML-DSA kind the vector UA's `register`, a
    `requireAuthorized` transaction; by eth_call its control, the vector's wrong-purpose signature and one byte changed
    (`UAUnauthorized`), and on a precompile path `cacheExpandedKey`'s `UAKeyCache`."""
    reg = E.REG[0]
    pj = json.load(open(os.path.join(VEC, "ua/pq_signatures.json")))
    digest = E.hb(pj["digest"])
    for row in pj["kinds"]:
        kind, name = row["kind"], row["name"]
        if not name.startswith("mldsa"):
            continue
        if not u(E.call(reg, E.cd("kindEnabled(uint16)", ["w"], kind))):
            E.log(f"      {name}: not enabled on this registry (MD-1 / MD-5)")
            continue
        pk, ua = E.hb(row["keyData"]), E.hb(row["ua"])
        cache = cache_path(kind)
        E.log(f"   {name} on the {'cache' if cache else 'precompile'} path")
        if u(E.call(reg, E.cd("isRegistered(bytes32)", ["w"], ua))):
            E.log(f"      {name} vector UA {ua.hex()[:16]}… already registered: register skipped")
        else:
            if cache:
                for p in range(mldsa_parts(kind)):
                    sd.send(
                        reg,
                        E.cd("cacheExpandedKey(uint16,bytes,uint256)", ["w", "b", "w"], kind, pk, p),
                        f"cacheExpandedKey {name} part {p}",
                    )
            attrs = [b"", E.ZERO32, [0, b"", E.ZERO32], E.ZERO32]
            sd.send(
                reg,
                E.cd(E.REGISTER, E.REGISTER_T, kind, pk, attrs, E.hb(row["pop"]["sig"]), b""),
                f"register {name} (vector)",
            )
        E.check(u(E.call(reg, E.cd("kindOf(bytes32)", ["w"], ua))) == kind, f"{name} kindOf {kind:#06x}")
        s = row["sigs"][0]
        purpose = E.kc(f"scaas.ua.purpose.{s['purpose']}.v1")
        good = E.cd(E.REQ_AUTH, E.REQ_AUTH_T, ua, purpose, digest, [b"", E.hb(s["sig"]), []])
        control(sd.addr, reg, good, f"{name} requireAuthorized")
        sr.send(reg, good, f"requireAuthorized {name} ({s['purpose']}, vector signature)")
        wp = next(x for x in row["negatives"] if x["name"] == "wrong-purpose")
        other = E.kc("scaas.ua.purpose.member.v1")
        neg(
            sd.addr,
            reg,
            E.cd(E.REQ_AUTH, E.REQ_AUTH_T, ua, other, digest, [b"", E.hb(wp["sig"]), []]),
            P.sel_hex("UAUnauthorized(bytes32)"),
            f"{name} requireAuthorized: the metatx signature under purpose member",
        )
        bad = bytearray(E.hb(s["sig"]))
        bad[len(bad) // 2] ^= 1
        neg(
            sd.addr,
            reg,
            E.cd(E.REQ_AUTH, E.REQ_AUTH_T, ua, purpose, digest, [b"", bytes(bad), []]),
            P.sel_hex("UAUnauthorized(bytes32)"),
            f"{name} requireAuthorized: one signature byte changed",
        )
        if not cache:
            neg(
                sd.addr,
                reg,
                E.cd("cacheExpandedKey(uint16,bytes,uint256)", ["w", "b", "w"], kind, pk, 0),
                P.sel_hex("UAKeyCache(uint16)"),
                f"{name} cacheExpandedKey on the precompile path",
            )


# ------------------------------------------------------------------ group tokens: the ML-DSA-65 signer on every kind

CONF_ZETHER = [
    b"",
    1,
    1 << 40,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
]  # Tokens.s.sol / PqzKeys `_kindToken`: BLS12-381 v1, no auditor
TERMS = E.kc("onchain mldsa-on terms")


def pqz_conf(va):
    """PqzKeys.s.sol `_conf(true, false)`: OFFCHAIN, class 3 without the opening, the verifier `va` (transferable)."""
    return [b"", 10_000, 1 << 40, 0, 0, 0, 0, 1, va, 0, 0, 0, 3, 1, 0]


def kinds_on(fac):
    """The token kinds released (version 1) on the set's factory."""
    out = []
    for k in (0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 12, 13):
        if u(E.call(fac, E.cd("tokenKindEnabled(uint8)", ["w"], k))) and u(
            E.call(fac, E.cd("implementationOf(uint8,uint64)", ["w", "w"], k, 1))
        ):
            out.append(k)
    return out


def g_tokens(pq, sd, sr, s3):
    """Tokens.s.sol `_registerMl` + `_pq` (and PqzKeys' public-layer `_pq` on the PQZ kinds): an ML-DSA-65 UA alice on the
    set's registry, then on one token of each kind of the set's factory pq.py's `public` rows (the classical entries signed
    by alice and relayed by key 2, a relay fee through the set's RelayFeeRouter, a negative by eth_call)."""
    fac, router = DEP["token_factory"], DEP["relay_fee_router"]
    alice = ml_ua(pq, sd, "alice", E.MLDSA65, E.kc("mldsa-on alice", P.RUN))
    bob = ml_ua(pq, sd, "bob", E.MLDSA65, E.kc("mldsa-on bob", P.RUN))
    D = E.Deployer(sd)
    tusd = D.deploy(
        "MockERC20", E.encs(["b", "b", "w"], [b"mldsa-on USD", b"moUSD", 6]), src="Mocks", label="MockERC20"
    )
    sd.send(tusd, E.cd("mint(address,uint256)", ["w", "w"], sd.addr, 10**15), "tUSD mint")
    va = E.pad(E.address(sd.key))
    toks, ks = [], kinds_on(fac)
    for k in (0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 12, 13):
        if k not in ks:
            E.log(f"      kind {k}: no release on the set's factory: not run")
            continue
        wrapped = k in (1, 3, 5, 9, 11, 13)
        conf = CONF_ZETHER if k in (2, 3, 10, 11) else pqz_conf(va) if k in (4, 5, 12, 13) else None
        regp = [0, 0, 0, TERMS, 0] if k >= 8 else None
        feat = 1 | (0 if wrapped else 2 | 4)  # PAYABLE; MINTABLE | BURNABLE on a normal kind
        t = P.create_cfg(
            sd,
            fac,
            k,
            f"mldsa-on kind {k}",
            f"moK{k}",
            [[tusd, 1, 1]] if wrapped else [],
            feat,
            f"mldsa-on-k{k}".encode(),
            conf,
            regp,
        )
        toks.append((t, f"moK{k}"))
    P.public(pq, sd, sr, alice, bob, toks, tusd, router)


# ------------------------------------------------------------------ group pqchat: every signed write (PqChat.s.sol)


def abi_sig(x):
    t = x["type"]
    return "(" + ",".join(abi_sig(c) for c in x["components"]) + ")" + t[5:] if t.startswith("tuple") else t


def fsig(art, name, kind="function"):
    """`name`'s canonical signature from the artifact's ABI (out/<file>/<contract>.json); `kind` "error" for an error."""
    j = json.load(open(os.path.join(EVM, E.OUT_DIR, art + ".json")))
    f = next(x for x in j["abi"] if x.get("name") == name and x["type"] == kind)
    return f"{name}({','.join(abi_sig(i) for i in f['inputs'])})"


def cdx(sig, *vs):
    """Calldata of `sig` with its argument types read from the signature itself."""
    return E.cd(sig, E.abi_ts(sig[sig.index("(") + 1 : -1]), *vs)


def ret(frm, to, data):
    """What the transaction will return: the same call by eth_call at the latest state, just before it is sent."""
    return E.rpc("eth_call", [{"from": frm, "to": to, "data": "0x" + data.hex(), "gas": hex(30_000_000)}, "latest"])


class Digests:
    """PqChat.s.sol's `PqChatDigests` (the contracts' own `PqChatTypes` hashes): its runtime placed at an unused address by
    the eth_call's state override, never deployed."""

    AT = "0x" + "0d" * 20

    def __init__(self):
        j = json.load(open(os.path.join(EVM, E.OUT_DIR, "PqChat.s.sol/PqChatDigests.json")))
        self.code, self.abi = j["deployedBytecode"]["object"], j["abi"]

    def __call__(self, name, *vs):
        f = next(x for x in self.abi if x["name"] == name)
        sig = f"{name}({','.join(abi_sig(i) for i in f['inputs'])})"
        r = E.rpc(
            "eth_call", [{"to": self.AT, "data": "0x" + cdx(sig, *vs).hex()}, "latest", {self.AT: {"code": self.code}}]
        )
        return E.words(r)[0]


def g_pqchat(pq, sd, sr, s3):
    """PqChat.s.sol on the set's release and instance (`pqchat_implementation`, `pqchat_instance`) and a second instance:
    three ML-DSA-65 members with a KEM key at version 0, then sessions, rekeys, a replica, messages, leave / remove, the
    chain as a store, a topic, entries and votes, each signed by a member and sent by key 2; the views read back; the
    negatives by eth_call. Not here: `_rescue` (no signature, set mldsa-off's)."""
    if "pqchat_instance" not in DEP:
        raise Stop("PQCHAT_MISSING: the set has no pqchat_instance (deploy with DEPLOY_PQCHAT=1)")
    reg, fac, router = E.REG[0], DEP["token_factory"], DEP["relay_fee_router"]
    chat, A = DEP["pqchat_instance"], "IPqChat.sol/IPqChat"
    h, uid, rs = Digests(), E.CTX[1], P.RUN
    F = {
        n: fsig(A, n)
        for n in (
            "createSession",
            "addWraps",
            "rekey",
            "postMessage",
            "leave",
            "remove",
            "storeMessage",
            "createTopic",
            "updateTopic",
            "setTopicWriter",
            "postEntry",
            "editEntry",
            "voteEntry",
        )
    }
    rd = lambda sig, *vs, at=None: E.call(at or chat, cdx(sig, *vs))  # noqa: E731
    # the second instance (class 3, kind 0, release 1), owned by no UA
    rid = [3, 0, 1]
    ci = cdx(
        fsig("OpenFactory.sol/OpenFactory", "createInstance"),
        rid,
        E.kc("mldsa-on pqchat-2", rs),
        cdx("initialize(bytes32)", E.ZERO32),
    )
    c2 = "0x" + ret(sd.addr, fac, ci)[-40:]
    sd.send(fac, ci, "createInstance PqChat 2")
    E.check(u(rd("owner()", at=c2)) == 0, f"PqChat 2 at {c2}: owner 0")
    # three ML-DSA-65 members with their KEM key (register's attrs), sorted by id
    ms = []
    for i in range(3):
        seed = E.kc("mldsa-on pqchat", rs, bytes([i]))
        pk = pq.ml_pk(65, seed)
        ua = E.words(E.call(reg, E.cd("uaOf(uint16,bytes)", ["w", "b"], E.MLDSA65, pk)))[0]
        ek = b"".join(E.kc(seed, b"kem", bytes([j])) for j in range(49))
        kem = b"\x01" + ek + E.kc(seed, b"x25519")
        pop = pq.ml_sign(65, seed, E.kc(E.TAG[E.MLDSA65], E.portable("pop", kind=E.MLDSA65, ua=ua, kemPk=kem)))
        if cache_path(E.MLDSA65):
            for p in range(2):
                sd.send(
                    reg,
                    E.cd("cacheExpandedKey(uint16,bytes,uint256)", ["w", "b", "w"], E.MLDSA65, pk, p),
                    f"cacheExpandedKey member {i} part {p}",
                )
        g = E.reg_args(E.MLDSA65, pk, pop=pop, kemPk=kem)
        sd.send(reg, E.register_cd(g["args"]), f"register member {i} (mldsa65 + KEM v0)")
        if g["kemFill"]:
            f = g["kemFill"]
            sd.send(
                reg,
                E.cd(E.SET_KEM, E.SET_KEM_T, E.hb(f["ua"]), 0, E.kem_v(f["kem"]), E.sig_v(f["sig"])),
                f"setKemKey member {i} v0",
            )
        ms.append(E.UA(name=f"m{i}", kind=E.MLDSA65, seed=seed, pk=pk, ua=ua))
    ms.sort(key=lambda m: m.ua)
    uas = [m.ua for m in ms]
    P_CHAT = E.kc("scaas.ua.purpose.pqchat.v1")
    sig = lambda i, d: E.ml_sig(pq, ms[i], P_CHAT, d)  # noqa: E731
    # a kind-0 fee token of the set's factory, key 1 holding its supply (the relayed unsigned calls' fee)
    tok = P.create_cfg(sd, fac, 0, "mldsa-on pqchat", "moPC", [], 1 | 2, b"mldsa-on-pqchat-fee")
    sd.send(
        tok,
        E.cd("mint(address,uint256,bytes32)", ["w", "w", "w"], sd.addr, 10**12, E.chain_word(tok)),
        "fee token mint",
    )
    vu = int(time.time()) + 3600

    def relayed(target, data, what):
        """`RelayFeeRouter.relay` of the unsigned call: key 1's native id pays 1 on lane 31, key 3 sends."""
        fn = P.nonce(tok, E.pad(sd.addr), 31)
        payee = E.pad(router)
        typ = (
            "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,"
            "uint256 nonce,uint256 validUntil,address relayer)"
        )
        d = E.kc(
            b"\x19\x01",
            P.domain(tok),
            E.kc(
                E.kc(typ),
                E.pad(sd.addr),
                E.W(target),
                E.kc(data),
                payee,
                E.W(1),
                E.W(31),
                E.W(fn),
                E.W(vu),
                E.W(router),
            ),
        )
        s3.send(
            router,
            cdx(
                f"relay(address,bytes,address,bytes32,bytes32,uint256,uint256,uint256,uint256,{E.UASIG_S})",
                target,
                data,
                tok,
                E.pad(sd.addr),
                payee,
                1,
                31,
                fn,
                vu,
                [b"", E.ecdsa(sd.key, d), []],
            ),
            what,
        )
        E.check(P.nonce(tok, E.pad(sd.addr), 31) == fn + 1, f"{what}: the relay-fee lane moved")

    def wraps(idx, tag):
        w, hs = [], []
        for i in idx:
            ct = b"".join(E.kc(tag, uas[i], bytes([j])) for j in range(49))
            sk = E.kc(tag, uas[i], b"k") + E.kc(tag, b"s")[:16]
            x = [uas[i], 0, ct, E.kc(tag, uas[i], b"x"), sk]
            w.append(x)
            hs.append(h("wrap", x))
        return w, hs

    def session(creator, nonce, idx):
        w, hs = wraps(idx, E.kc(rs, b"session", nonce.to_bytes(8, "big")))
        return [
            uas[creator],
            nonce,
            uid,
            chat,
            [uas[creator]],
            [[uas[i], 0, E.ZERO32] for i in idx],
            hs,
            E.kc(rs, b"info", nonce.to_bytes(8, "big")),
        ], w

    def epoch(sid_, author, nonce, n, parent, admins, idx):
        w, hs = wraps(idx, E.kc(rs, b"epoch", sid_, n.to_bytes(8, "big"), nonce.to_bytes(8, "big")))
        return [sid_, uas[author], nonce, n, parent, admins, [[uas[i], 0, E.ZERO32] for i in idx], hs, b""], w

    def send_ret(data, what):
        r = ret(sr.addr, chat, data)
        sr.send(chat, data, what)
        return r

    def nneg(data, err, what, frm=None):
        neg(frm or sr.addr, chat, data, P.sel_hex(fsig(A, err, "error")), f"pqchat: {what}")

    sn = int.from_bytes(E.kc(rs, b"session-nonce")[:7], "big")
    # sessions: whole, in chunks, rekeys, a replica
    s, w = session(0, sn, [0, 1])
    sg = sig(0, h("session", s))
    sid = E.words(send_ret(cdx(F["createSession"], s, w, sg), "createSession A+B (whole)"))[0]
    E.check(sid == h("sessionId", s[0], s[1]) and u(rd("epochComplete(bytes32)", sid)) == 1, "session id, complete")
    E.check(
        u(rd("sessionCount(bytes32)", uas[1])) >= 1 and E.words(rd("latestEpoch(bytes32)", sid))[0] == sid,
        "recovery views at create",
    )
    nneg(cdx(F["createSession"], s, w, sg), "PqChatNonceUsed", "createSession with a used (creator, nonce)")
    s2, w2 = session(0, sn + 1, [0, 1])
    sg = sig(0, h("session", s2))
    sid2 = E.words(send_ret(cdx(F["createSession"], s2, w2[:1], sg), "createSession A+B (one wrap)"))[0]
    E.check(u(rd("epochComplete(bytes32)", sid2)) == 0, "incomplete after one wrap")
    relayed(chat, cdx(F["addWraps"], sid2, 1, w2[1:]), "addWraps relayed through RelayFeeRouter")
    E.check(u(rd("epochComplete(bytes32)", sid2)) == 1, "complete at the last wrap")
    admins = [uas[0]]
    e, ew = epoch(sid, 1, sn, 1, sid, admins, [0, 1])
    e1 = E.words(send_ret(cdx(F["rekey"], e, ew, sig(1, h("epoch", e))), "rekey by B (plain)"))[0]
    E.check(
        E.words(rd("childOf(bytes32)", sid))[0] == e1 and E.words(rd("latestEpoch(bytes32)", sid))[0] == e1,
        "home slot, latestEpoch",
    )
    e, ew = epoch(sid, 0, sn + 7, 1, sid, admins, [0])
    nneg(
        cdx(F["rekey"], e, ew, sig(0, h("epoch", e))),
        "PqChatEpochTaken",
        "a second child at home (the P9 removal attack)",
    )
    e, ew = epoch(sid, 0, sn + 1, 2, e1, admins, [0, 1, 2])
    e2 = E.words(send_ret(cdx(F["rekey"], e, ew, sig(0, h("epoch", e))), "rekey by A adding C"))[0]
    E.check(
        u(rd("epochCount(bytes32)", sid)) == 3 and u(rd("sessionCount(bytes32)", uas[2])) == 1,
        "epochCount, sessionCount",
    )
    s, w = session(0, sn, [0, 1])
    rep = ret(sr.addr, c2, cdx(F["createSession"], s, w, sig(0, h("session", s))))
    sr.send(c2, cdx(F["createSession"], s, w, sig(0, h("session", s))), "createSession on PqChat 2 (a replica)")
    E.check(
        E.words(rep)[0] == sid and E.words(rd("childOf(bytes32)", sid, at=c2))[0] == E.ZERO32,
        "replica session, no child",
    )
    # messages
    dv = (
        int.from_bytes(E.kc(rs, b"device")[:16], "big") & 0xFFFFFFFFFFFF0FFF3FFFFFFFFFFFFFFF
        | 0x00000000000070008000000000000000
    )
    dvw = dv.to_bytes(16, "big") + bytes(16)

    def msg(session_, eid, sender, counter):
        return [
            session_,
            eid,
            uas[sender],
            dvw,
            counter,
            [E.kc(rs, b"head")],
            E.kc(rs, b"ct", counter.to_bytes(8, "big")) + E.kc(dvw),
        ]

    m = msg(sid, e2, 0, 0)
    E.check(u(send_ret(cdx(F["postMessage"], m, sig(0, h("message", m))), "postMessage by A")) == 0, "message index 0")
    E.check(u(rd("messageCount(bytes32)", sid)) == 1, "messageCount")
    m = msg(sid2, sid2, 0, 0)
    sg = sig(0, h("message", m))
    sr.send(chat, cdx(F["postMessage"], m, sg), "postMessage in the chunked session")
    nneg(cdx(F["postMessage"], m, sg), "PqChatNonceUsed", "postMessage with a used counter")
    lv = [sid, e2, uas[1], 9]
    sr.send(chat, cdx(F["leave"], lv, sig(1, h("leave", lv))), "leave by B")
    E.check(u(rd("leftIn(bytes32,bytes32)", e2, uas[1])) == 1, "leftIn")
    r = [sid, e2, 3, [uas[2]], uas[0], sn + 20]
    sr.send(chat, cdx(F["remove"], r, sig(0, h("remove", r))), "remove C by A")
    E.check(
        u(rd("removedIn(bytes32,bytes32)", e2, uas[2])) == 1 and u(rd("removalCount(bytes32)", e2)) == 1,
        "removedIn, removalCount",
    )
    e3, w3 = epoch(sid, 0, sn + 21, 3, e2, admins, [0])
    id3 = E.words(send_ret(cdx(F["rekey"], e3, w3, sig(0, h("epoch", e3))), "rekey by A dropping B and C"))[0]
    E.check(E.words(rd("latestEpoch(bytes32)", sid))[0] == id3, "latestEpoch after the drop")
    m = msg(sid, id3, 0, 0)
    control(
        sr.addr,
        chat,
        cdx(F["postMessage"], m, sig(0, h("message", m))),
        "pqchat: postMessage by the member A in epoch 3",
    )
    m = msg(sid, id3, 1, 0)
    nneg(cdx(F["postMessage"], m, sig(1, h("message", m))), "PqChatNotMember", "postMessage by a non-member")
    m = msg(sid, e2, 0, 1)
    nneg(cdx(F["postMessage"], m, sig(0, h("message", m))), "PqChatEpochTaken", "postMessage under a superseded epoch")
    # the remove race (UA-7 P48)
    s, w = session(0, sn + 2, [0, 1, 2])
    s3_ = E.words(send_ret(cdx(F["createSession"], s, w, sig(0, h("session", s))), "createSession A+B+C"))[0]
    r = [s3_, s3_, 1, [uas[2]], uas[0], 1]
    sg = sig(0, h("remove", r))
    sr.send(chat, cdx(F["remove"], r, sg), "remove C from epoch 0")
    # E-3 (owner 2026-11-25): an exit checks membership before the nonce, so the byte-for-byte replay stops at C's
    # membership; the replay negative names B (still a member), signed by A at the first record's nonce
    again = [s3_, s3_, 1, [uas[1]], uas[0], 1]
    nneg(
        cdx(F["remove"], again, sig(0, h("remove", again))),
        "PqChatNonceUsed",
        "remove replayed (the admin's used nonce)",
    )
    e, ew = epoch(s3_, 2, 1, 1, s3_, s[4], [0, 1, 2])
    nneg(cdx(F["rekey"], e, ew, sig(2, h("epoch", e))), "PqChatNotMember", "the removed member's rekey")
    e, ew = epoch(s3_, 1, 1, 1, s3_, s[4], [0, 1, 2])
    nneg(cdx(F["rekey"], e, ew, sig(1, h("epoch", e))), "PqChatRemovedKept", "a child keeping a removed member")
    # the chain as a store
    hint = E.kc(rs, b"hint")[:8] + bytes(24)
    env = E.kc(b"envelope a") + E.kc(b"envelope b")
    s3.send(chat, cdx(F["storeMessage"], 1, hint, env), "storeMessage direct by key 3")
    relayed(chat, cdx(F["storeMessage"], 1, hint, env), "storeMessage relayed")
    E.check(u(rd("storedCount(bytes8)", hint)) == 2, "storedCount 2")
    nneg(cdx(F["storeMessage"], 2, hint, env), "PqChatShape", "storeMessage of a version other than 1", frm=s3.addr)
    # topics, entries, votes (PqChatTopics, through the instance)
    t = [uas[0], int.from_bytes(E.kc(rs, b"topic")[:7], "big"), uid, chat, b"onchain", b"matrix", 1]
    tid = E.words(send_ret(cdx(F["createTopic"], t, sig(0, h("topic", t))), "createTopic by A"))[0]
    up = [tid, 1, b"onchain 2", b"matrix 2", 1]
    sr.send(chat, cdx(F["updateTopic"], up, sig(0, h("topicUpdate", up))), "updateTopic")
    wr = [tid, uas[1], 1, 1]
    sr.send(chat, cdx(F["setTopicWriter"], wr, sig(0, h("topicWriter", wr))), "setTopicWriter B")
    E.check(u(rd("writerOf(bytes32,bytes32)", tid, uas[1])) == 1, "writerOf B")
    ref0 = [E.ZERO32, 0, E.ZERO32, E.ZERO32]
    pe = [tid, uas[1], 1, E.ZERO32, ref0, b"text/markdown", b"a post"]
    pid = E.words(send_ret(cdx(F["postEntry"], pe, sig(1, h("entry", pe))), "postEntry by B"))[0]
    q = [tid, uas[2], 1, pid, ref0, b"text/plain", b"a reply"]
    sr.send(chat, cdx(F["postEntry"], q, sig(2, h("entry", q))), "postEntry reply by C")
    d = [pid, uas[1], 2, 2, b"text/markdown", b"a post, edited"]
    sr.send(chat, cdx(F["editEntry"], d, sig(1, h("edit", d))), "editEntry by B")
    E.check(u(rd("replies(bytes32,uint256,uint256)", pid, 0, 0), 1) == 1, "replies 1")
    for v in ([pid, uas[0], 1, 1], [pid, uas[0], -1, 2]):
        sr.send(chat, cdx(F["voteEntry"], v, sig(0, h("vote", v))), f"voteEntry {v[2]:+d} by A")
    sc = E.words(rd("scoreOf(bytes32)", pid))
    E.check(int.from_bytes(sc[0], "big") == 0 and int.from_bytes(sc[1], "big") == 1, "scoreOf (0, 1): one count moved")
    v = [pid, uas[2], 1, 1]
    control(sr.addr, chat, cdx(F["voteEntry"], v, sig(2, h("vote", v))), "pqchat: a vote value of 1 by C")
    v = [pid, uas[2], 2, 1]
    nneg(cdx(F["voteEntry"], v, sig(2, h("vote", v))), "PqTopicVoteValue", "a vote value of 2")


# ------------------------------------------------------------------ main


def group_fn(name):
    """A group's rows: here, or the PQZ groups' in mldsa_on_pqz.py (which reads this module's helpers as `M`)."""
    if name in ("pqzkeys", "pqzwallet"):
        import mldsa_on_pqz as Q

        Q.M = sys.modules[__name__]
        return getattr(Q, f"g_{name}")
    return globals()[f"g_{name}"]


def run_group(name, pq, keys):
    global GROUP
    GROUP = P.GROUP = name
    t0 = time.time()
    n0, f0, g0 = len(REC), len(E.FAILS), NEGS[:]
    say("start")
    stop = threading.Event()
    hb = threading.Thread(target=heartbeat, args=(stop, t0), daemon=True)
    hb.start()
    try:
        group_fn(name)(pq, *keys)
    except Stop as e:
        E.check(False, str(e))
    except Exception as e:  # noqa: BLE001
        E.check(False, f"{name} aborted: {type(e).__name__}: {str(e)[:300]}")
    finally:
        stop.set()
    txs = [r for r in REC[n0:] if r["tx"]]
    ok = len(E.FAILS) == f0
    say(
        f"{'ok' if ok else 'FAIL ' + E.FAILS[f0][:160]} {sum(r['status'] == 1 for r in txs)}/{len(txs)} txs, "
        f"negatives {NEGS[1] - g0[1]}/{NEGS[0] - g0[0]} ({int(time.time() - t0)}s)"
    )
    return ok


def main():
    global NET, ARGS, DEP
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", required=True, help="the deploy set: " + ", ".join(SETS))
    ap.add_argument("--net", required=True)
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--groups", default=",".join(GROUPS))
    ap.add_argument("--book", help="the book's path (default: deployments/<chain key>.json)")
    ARGS = a = ap.parse_args()
    NET = P.NET = a.net
    gs = a.groups.split(",")
    bad = [g for g in gs if g not in GROUPS]
    if bad:
        raise Stop(f"GROUP_UNKNOWN: {', '.join(bad)} (groups: {', '.join(GROUPS)})")
    E.RPC = a.rpc
    chain = int(E.rpc("eth_chainId"), 16)
    E.CTX[:] = [chain, E.hb(E.rpc("eth_getBlockByNumber", ["0x0", False])["hash"])]
    DEP = load_book(a.set, a.book)
    E.REG[0] = DEP["ua_registry"]
    keys = []
    for v in ("ONCHAIN_K1", "ONCHAIN_K2", "ONCHAIN_K3"):
        if not os.environ.get(v):
            raise Stop(f"KEY_MISSING: {v} (the environment, as matrix.sh)")
        keys.append(E.Sender(int(os.environ[v], 16)))
    SENDERS[:] = keys
    os.makedirs(P.OUTD, exist_ok=True)
    print(
        f"[{NET}] start set {a.set} (chain {chain}, registry {E.REG[0]}, ML-DSA paths "
        f"{'/'.join(str(DEP.get(f'mldsa{n}_path', '?')) for n in (44, 65, 87))}); senders "
        f"{' '.join(s.addr for s in keys)}",
        flush=True,
    )
    pq = E.PQ()
    rc = 0
    try:
        for g in gs:
            rc |= 0 if run_group(g, pq, keys) else 1
    finally:
        with open(os.path.join(P.OUTD, f"mldsa-on-{NET}.log"), "w") as f:
            f.write("\n".join(E.LOG) + "\n")
        for g in gs:
            with open(os.path.join(P.OUTD, f"records-{NET}-{g}-on.jsonl"), "w") as f:
                for r in REC:
                    if r["group"] == g:
                        f.write(json.dumps(r) + "\n")
    print(f"[{NET}] {'ok' if not rc else 'FAIL'} {len(REC)} records, {len(E.FAILS)} failure(s)", flush=True)
    sys.exit(rc)


ARGS = None
if __name__ == "__main__":
    main()
