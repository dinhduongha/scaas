#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b Step 5b, group `pq`: the paths that need the node's PQZ and ML-DSA precompiles (the local copy, then the SCaaS
testnet), driven through script/pqz/e2e.py unchanged (imported; its own deploy: registry trio with the PQ kinds, factory,
releases 0, 4, 5, 12, 13, ML-DSA / PQZ / msig holders with real proofs). e2e.py's full run (sections 1-6c: the PQZ kinds 4
and 5 life cycles, relayed and named entries signed by EOAs, ML-DSA-65 and msig UAs, the wrapped kind, a key rotation)
runs as it is; its section 7 (the proof path, run in Step 5) is replaced by `extra`, unless PQ_SECTION7=1:
  - kinds 12 and 13 (no token of them on chain before): created on e2e's factory with a ComplianceRegistry; shield, op 1,
    op 7, rollover, burn, refresh, named relayed entries signed by an ML-DSA-65 UA, wrap-shield and unshield-unwrap (13);
    the deny list written and switched on, the allow list's refusals (round 3s, `lists`);
  - the classical entries of a kind-0 token (and kind 12's public layer) signed by an ML-DSA-65 UA (alice) and relayed:
    mtxTransfer (fee 0), mtxTransferWithFee, mtxPay (save true, false; paymentCount / paymentsOf), mtxExecuteTransfer,
    mtxBatchTransfer, mtxExecute, mtxBurn and mtxCancelNonce (named UA envelopes), mtxInvalidateNonces;
  - negatives by eth_call (a wrong ML-DSA signature, a transfer above the balance).
Every transaction is recorded (runs/…-step5b/records-<net>-pq.jsonl, book deployments/onchain-<net>-pq.json).
  python3 -I script/onchain/pq.py --net local --rpc http://<copy signer>:8545     (EVM_OUT: a build at the default set)
Test keys 0x…01-0x…03 and the e2e test seeds only. UNAUDITED."""
import argparse
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.abspath(os.path.join(HERE, "../.."))
sys.path.insert(0, os.path.join(EVM, "script/pqz"))
import e2e as E  # noqa: E402

OUTD = os.path.join(EVM, os.environ.get("MATRIX_OUT") or time.strftime("runs/%Y-%m-%d-matrix"))  # matrix.sh's run dir
REC, LAST, DEP = [], {}, []
RUN = str(time.time_ns()).encode()  # this run's salt part: a rerun on the same factory (--extra-only) creates fresh clones
LABEL_KIND = {0: "NormalToken", 4: "NormalPqzToken", 5: "WrappedPqzToken", 12: "NormalPqzRegulatedToken",
              13: "WrappedPqzRegulatedToken"}
UMT_S = "(bytes32,bytes32,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)"  # UAMetaTransfer
UMT_T = ("t", ["w"] * 11)
PAYMETA_S, PAYMETA_T = "(bytes32,bytes32,bool,uint16,bytes)", ("t", ["w", "w", "w", "w", "b"])


# ------------------------------------------------------------------ recording (e2e.py's Sender and Deployer, wrapped)

_rpc0 = E.rpc


def _rpc(method, params=()):
    r = _rpc0(method, params)
    if method == "eth_sendRawTransaction":
        LAST["tx"] = r
    return r


E.rpc = _rpc
_send0 = E.Sender.send


def _send(self, to, data, what, gas=None):
    LAST.pop("tx", None)
    row = {"net": NET, "to": (to or "").lower(), "sel": data[:4].hex() if to else "create", "what": what, "script": GROUP}
    if gas is None:
        # e2e's own limit (estimate x 1.15 + 50 k) left an ML-DSA-signed named mtxShield out of gas on the Amsterdam copy:
        # estimated 346 k at send time, it needed 453 k (reverted with no data; the same call at 30 M succeeds). The harness
        # asks estimate x 1.5 + 300 k, never above 60 M nor the block's limit.
        tx = {"from": self.addr, "data": "0x" + data.hex(), **({"to": to} if to else {})}
        try:
            est = int(_rpc0("eth_estimateGas", [tx]), 16)
            lim = int(_rpc0("eth_getBlockByNumber", ["latest", False])["gasLimit"], 16)
            gas = row["asked"] = min(lim, 60_000_000, int(est * 1.5) + 300_000)
        except RuntimeError:
            gas = None  # e2e's own path reports the refused estimate
    try:
        r = _send0(self, to, data, what, gas)
    except Exception:
        h = LAST.get("tx")
        x = _rpc0("eth_getTransactionReceipt", [h]) if h else None
        REC.append(row | {"tx": h or "", "gas": int(x["gasUsed"], 16) if x else 0, "status": 0})
        raise
    REC.append(row | {"tx": r["transactionHash"], "gas": int(r["gasUsed"], 16), "status": int(r["status"], 16),
                      "created": (r.get("contractAddress") or "").lower()})
    return r


E.Sender.send = _send
_dinit0 = E.Deployer.__init__


def _dinit(self, *a, **k):
    _dinit0(self, *a, **k)
    DEP.append(self)


E.Deployer.__init__ = _dinit


# ------------------------------------------------------------------ helpers

def W(x):
    return E.W(x)


def u(h, i=0):
    return int.from_bytes(E.words(h)[i], "big")


def domain(tok):
    """The token's EIP-712 domain separator from `eip712Domain()` (salted: SaltedEIP712)."""
    h = E.call(tok, E.cd("eip712Domain()", []))
    w = E.words(h)
    name, ver = E.dec_bytes(h, 1), E.dec_bytes(h, 2)
    if w[5] == bytes(32):
        return E.kc(E.kc("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    E.kc(name), E.kc(ver), w[3], w[4])
    return E.kc(E.kc("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
                E.kc(name), E.kc(ver), w[3], w[4], w[5])


def named(tok, typ, args, env):
    """A named UA entry's digest: struct `typ` = (from, args words, batch, nonce, validUntil, mode, relayer, fee,
    feeRecipient), relayer / fee recipient 0 unless bound (open mode here)."""
    return E.kc(b"\x19\x01", domain(tok), E.kc(E.kc(typ), W(env[0]), *[W(x) for x in args], *[W(x) for x in env[1:]]))


def nonce(tok, who, lane=0):
    return u(E.call(tok, E.cd("mtxNonce(bytes32,uint256)", ["w", "w"], who, lane)))


def bal_ua(tok, who):
    return u(E.call(tok, E.cd("balanceOfUA(bytes32)", ["w"], who)))


def neg(frm, to, data, want, what):
    """A negative by eth_call: refused with error selector `want` (hex)."""
    try:
        _rpc0("eth_call", [{"from": frm, "to": to, "data": "0x" + data.hex(), "gas": hex(50_000_000)}, "latest"])
        got = "ran"
    except RuntimeError as e:
        got = str(e)
    ok = want.lower() in got.lower()
    E.check(ok, f"negative {what}: refused with {want}" + ("" if ok else f" (got {got[:160]})"))
    REC.append({"net": NET, "to": to.lower(), "sel": data[:4].hex(), "tx": "", "gas": 0, "status": 2 if ok else 0,
                "what": f"negative: {what}", "expected": want, "script": GROUP})


def sel_hex(sig):
    return "0x" + E.sel(sig).hex()


# ------------------------------------------------------------------ the extra section (replaces e2e's section 7)

def extra(pq, sd, reg, create, U, aud, DEC, sk, tusd):
    if os.environ.get("PQ_SECTION7") == "1":
        _proof_path0(pq, sd, reg, create, U, aud, DEC, sk, tusd)
    D = DEP[-1]
    fac = next(v for k, v in D.addr.items() if k.startswith("OpenFactory"))
    mine(pq, sd, E.Sender(2), U, aud, DEC, tusd, fac, D)  # key 2: e2e's relayer key; its own Sender is done by now


def create_cfg(sd, fac, kind, name, sym, legs, feat, salt, conf=None, reg=None, issuer=0):
    """`createToken` on e2e's factory with e2e's `TokenConfig` encoding (its `create`), plus the regulated params."""
    c = [name, sym, 6, feat, 0, sd.addr, [sd.addr if feat & 2 else 0, 0, 0, issuer, 0], 0, 0, legs, [0, 0],
         conf or [b""] + [0] * 12, 0, 0, 0, reg or [0, 0, 0, 0, 0]]
    data = E.cd("createToken(uint8,uint64,bytes,bytes32)", ["w", "w", "b", "w"], kind, 1, E.encs([E.CFG], [c]), E.kc(salt, RUN))
    r = sd.send(fac, data, f"createToken {sym} (kind {kind})")
    lg = next(x for x in r["logs"] if x["address"].lower() == fac.lower())
    t = "0x" + lg["topics"][1][-40:]
    E.log(f"      {sym} at {t}")
    return t


def mine(pq, sd, sr, U, aud, DEC, tusd, fac, D):
    """Sections 8 and 9: the regulated PQZ kinds, then the public layer of every kind signed by an ML-DSA-65 UA."""
    alice, bob = U["alice"], U["bob"]
    if "pqUSD" in D.addr:  # round 3t (spec §13): the setter on a PRECOMPILE token
        neg(sd.addr, D.addr["pqUSD"], E.cd("setVerifierFee(uint64)", ["w"], 1), sel_hex("PqzVerifyConfigInvalid()"),
            "pqUSD (PRECOMPILE) setVerifierFee(1)")
    E.log("\n## 8. (T66b Step 5b) the regulated PQZ kinds 12 and 13 (KYC on a ComplianceRegistry, no account denied)")
    # round 3r: (bytes32 admin, address govRouter): the deployer contract's native id, no router; CTR-GOV-27: the chain word
    cr = D.deploy("ComplianceRegistry", E.encs(["w", "w", "w"], [E.CREATE2_DEPLOYER, 0, E.CTX[1]]), label="ComplianceRegistry")

    def create_reg(kind, name, sym, legs, dmode, amode, feat, salt):
        conf = [aud.ua if amode else b"", E.SCALE, E.MAXS, E.FEE, dmode, amode, E.MIN_DECOY, 0, 0, 0, 0, 0, 0]
        # RegulatedLib (round 3s): KYC (bit 28) needs a registry, a registry iff a mask (deniedFlags 1: no account has it),
        # KYC a terms bit (a termsHash)
        t = create_cfg(sd, fac, kind, name, sym, legs, feat | 1 << 28, salt, conf, [cr, 0, 1, E.kc("scaas.onchain.terms"), 0])
        D.addr[sym] = t
        return t

    # kind 12: BUNDLE, auditor OPTIONAL, PAYABLE | MINTABLE | BURNABLE
    t12 = create_reg(12, "PQZ regulated", "pqR12", [], 0, 2, 1 | 2 | 4, b"t66b-5b-k12")
    C = E.Client(t12, "pqR12")
    sd.send(t12, E.cd("mint(address,uint256)", ["w", "w"], sd.addr, 5_000 * E.SCALE), "pqR12 mint 5,000 public")
    for x, v in ((alice, 400), (bob, 100)):
        sd.send(t12, E.cd(E.API["shield"], ["w", "w"], x.ua, v), f"pqR12 mtxShield({x.name}, {v})")
        C.set_next(bal=[(x, v)], total=v)
        C.commit()
    E.transfer(pq, sd, C, alice, bob, E.ZERO32, 40, True, "pqR12 op 1 alice→bob 40, auditor on")
    E.rollover(sd, C, bob, 1, "pqR12 bob's credit")
    E.transfer_multi(pq, sd, C, alice, [(bob, 6), (DEC[0], 0)], E.ZERO32, False, "pqR12 op 7 M = 2 alice→[bob 6, decoy 0]")
    E.burn(pq, sd, C, alice, 10, sd.addr, "pqR12 unshield alice 10 → deployer")
    E.burn(pq, sd, C, bob, 0, None, "pqR12 refresh bob")
    sg = lambda who: E.Signed(t12, who, pq, sr, E.SCALE)  # noqa: E731
    sd.send(t12, E.cd("mintToUA(bytes32,uint256)", ["w", "w"], alice.ua, 20 * E.SCALE), "pqR12 mintToUA(alice, 20)")
    s = sg(alice)
    s.send("Shield", [alice.ua, 9], "pqR12 signed mtxShield(alice, 9), ML-DSA-65")
    C.set_next(bal=[(alice, 9)], total=9)
    C.commit()
    E.transfer(pq, sd, C, alice, bob, E.ZERO32, 5, True, "pqR12 named mtxConfidentialTransferSingle alice→bob 5, ML-DSA-65",
               signed=sg(alice))
    E.burn(pq, sd, C, alice, 3, sd.addr, "pqR12 named mtxUnshield alice 3, ML-DSA-65", signed=sg(alice))
    E.check_public(C, "pqR12 after its ops")
    E.restore(C, "pqR12")
    lists(sd, t12, "pqR12")

    # kind 13: COMPACT, auditor OPTIONAL, one 1:1 leg (tUSD)
    t13 = create_reg(13, "PQZ regulated wrapped", "pqR13", [[tusd, 1, 1]], 1, 2, 1, b"t66b-5b-k13")
    C13 = E.Client(t13, "pqR13")
    sd.send(tusd, E.cd("approve(address,uint256)", ["w", "w"], t13, 10**12), "tUSD approve pqR13")
    sd.send(t13, E.cd(E.API["wrapShield"], ["w", "w", "w"], tusd, 200 * E.SCALE, alice.ua), "pqR13 mtxWrapShield(tUSD 200, alice)")
    C13.set_next(bal=[(alice, 200)], total=200)
    C13.commit()
    E.transfer(pq, sd, C13, alice, bob, E.ZERO32, 30, False, "pqR13 op 1 (Compact) alice→bob 30")
    E.burn(pq, sd, C13, alice, 20, sd.addr, "pqR13 unshield-unwrap alice 20 → deployer in tUSD", unwrap=(tusd, 20 * E.SCALE))
    E.check_public(C13, "pqR13 after its ops")
    E.restore(C13, "pqR13")
    lists(sd, t13, "pqR13")

    D.addr["pqN0"] = create_cfg(sd, fac, 0, "PQ signer plain", "pqN0", [], 1 | 2 | 4, b"t66b-5b-k0")
    router = D.deploy("RelayFeeRouter", b"", label="RelayFeeRouter")
    toks = [(D.addr[x], x) for x in ("pqN0", "pqUSD", "pqW", "pqR12", "pqR13") if x in D.addr]
    public(pq, sd, sr, alice, bob, toks, tusd, router)


def lists(sd, t, nm):
    """Group 3s (spec 2026-11-10-token-lists.md §5.3, §6) on a regulated PQZ kind, its admin the deployer: its own deny-list
    holder (`grantRole(9)`, grantDelay 0: at once), an account denied, the deny list switched on; bit 8 is outside the
    masks of 10-13, so `setAllowed` is `MissingRole` (no holder can exist) and `enableFeature(8)` `FeatureInvalidForKind`."""
    d = [E.pad("0x" + "00" * 17 + "de41ed")]
    sd.send(t, E.cd("grantRole(uint8,bytes32)", ["w", "w"], 9, E.pad(sd.addr)), f"{nm} grantRole(DENYLIST, deployer)")
    sd.send(t, E.cd("setDenied(bytes32[],bool)", [("a", "w"), "w"], d, 1), f"{nm} setDenied([0xde41ed], true)")
    sd.send(t, E.cd("enableFeature(uint8)", ["w"], 9), f"{nm} enableFeature(DENYLIST), at once")
    neg(sd.addr, t, E.cd("setAllowed(bytes32[],bool)", [("a", "w"), "w"], d, 1), sel_hex("MissingRole(uint8,bytes32)"),
        f"{nm} setAllowed (bit 8 outside the mask: no holder)")
    neg(sd.addr, t, E.cd("enableFeature(uint8)", ["w"], 8), sel_hex("FeatureInvalidForKind(uint8)"), f"{nm} enableFeature(ALLOWLIST)")


def public(pq, sd, sr, alice, bob, toks, tusd, router):
    """The public layer of every kind of e2e's factory (0, 4, 5, 12, 13), signed by the ML-DSA-65 UA alice and relayed by
    key 2: the classical entries (ml_classical) and a relay fee through a RelayFeeRouter (its executor runs one relayed
    mtxTransfer, then the token's mtxRelayFee pays the caller)."""
    E.log("\n## 9. (T66b Step 5b) the public entries of kinds 0, 4, 5, 12, 13 signed by an ML-DSA-65 UA, and a relay fee on each")
    for tok, nm in toks:
        k = u(E.call(tok, E.cd("kind()", [])))
        if k in (1, 5, 13):  # a wrapped kind: wrapped units to alice's UA from tUSD
            sd.send(tusd, E.cd("approve(address,uint256)", ["w", "w"], tok, 10**12), f"tUSD approve {nm}")
            sd.send(tok, E.cd("wrapToUA(address,uint256,bytes32)", ["w", "w", "w"], tusd, 1_000, alice.ua),
                    f"{nm} wrapToUA(tUSD 1,000, alice)")
        else:
            sd.send(tok, E.cd("mintToUA(bytes32,uint256)", ["w", "w"], alice.ua, 1_000), f"{nm} mintToUA(alice, 1,000)")
        ml_classical(pq, sr, tok, nm, alice, bob, burn=k not in (1, 5, 13))
        relay_fee(pq, sr, tok, nm, alice, bob, router)


def relay_fee(pq, sr, tok, nm, alice, bob, router):
    vu = int(time.time()) + 3600
    n = nonce(tok, alice.ua)
    m = [alice.ua, bob.ua, 1, E.ZERO32, 0, n, vu, 0, 0, 0, 0]
    d = E.words(E.call(tok, E.cd(f"mtxTransferDigest({UMT_S})", [UMT_T], m)))[0]
    cdx = E.cd(f"mtxTransfer(bytes32,bytes32,uint256,uint256,uint256,uint256,uint32,address,{E.UASIG_S})",
               ["w"] * 8 + [E.UASIG_T], alice.ua, bob.ua, 1, 0, n, vu, 0, 0, E.ml_sig(pq, alice, E.P_METATX, d))
    fn = nonce(tok, alice.ua, 2)
    typ = "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)"
    payee = E.pad(router)
    dg = E.kc(b"\x19\x01", domain(tok), E.kc(E.kc(typ), W(alice.ua), W(tok), E.kc(cdx), payee, W(1), W(2), W(fn), W(vu), W(router)))
    b0 = u(E.call(tok, E.cd("balanceOf(address)", ["w"], sr.addr)))
    sr.send(router, E.cd(f"relay(address,bytes,address,bytes32,bytes32,uint256,uint256,uint256,uint256,{E.UASIG_S})",
                         ["w", "b", "w", "w", "w", "w", "w", "w", "w", E.UASIG_T], tok, cdx, tok, alice.ua, payee, 1, 2, fn, vu,
                         E.ml_sig(pq, alice, E.P_METATX, dg)),
            f"{nm} RelayFeeRouter.relay(mtxTransfer alice→bob 1) + mtxRelayFee 1, ML-DSA-65")
    E.check(u(E.call(tok, E.cd("balanceOf(address)", ["w"], sr.addr))) == b0 + 1, f"{nm} the relayer got the relay fee 1")


def ml_classical(pq, sr, tok, nm, alice, bob, burn=True):
    vu = int(time.time()) + 3600
    sig = lambda d: E.ml_sig(pq, alice, E.P_METATX, d)  # noqa: E731
    UAS = E.UASIG_S

    def umt(to, v, n, ref=E.ZERO32, mode=0, fee=0, fr=0):
        return [alice.ua, to, v, ref, 0, n, vu, mode, 0, fee, fr]

    def dg(m):
        return E.words(E.call(tok, E.cd(f"mtxTransferDigest({UMT_S})", [UMT_T], m)))[0]

    b0 = bal_ua(tok, bob.ua)
    n = nonce(tok, alice.ua)
    m = umt(bob.ua, 7, n)
    sr.send(tok, E.cd(f"mtxTransfer(bytes32,bytes32,uint256,uint256,uint256,uint256,uint32,address,{UAS})",
                      ["w"] * 8 + [E.UASIG_T], alice.ua, bob.ua, 7, 0, n, vu, 0, 0, sig(dg(m))),
            f"{nm} mtxTransfer alice→bob 7, fee 0, ML-DSA-65")
    n += 1
    # FIXED fee, its recipient bound (MODE_FEE_FIXED | MODE_RESTRICT_FEE_RECIPIENT, non-zero: MetaTokenBase's fee shape),
    # at most 1 % of the amount (FeePolicy: fee 1 needs an amount of 100)
    m = umt(bob.ua, 100, n, mode=0x22, fee=1, fr=sr.addr)
    sr.send(tok, E.cd(f"mtxTransferWithFee(bytes32,bytes32,uint256,uint256,uint256,uint256,uint32,address,uint256,address,{UAS})",
                      ["w"] * 10 + [E.UASIG_T], alice.ua, bob.ua, 100, 0, n, vu, 0x22, 0, 1, sr.addr, sig(dg(m))),
            f"{nm} mtxTransferWithFee alice→bob 100, fee 1 (FIXED, to the relayer), ML-DSA-65")
    n += 1
    for save in (True, False):
        payno = E.kc(f"t66b-5b {nm} payNo {save}")
        meta = [E.kc(f"t66b-5b {nm} salt {save} {time.time()}"), payno, int(save), 0, b""]
        pid = E.words(E.call(tok, E.cd(f"metaPayId({PAYMETA_S})", [PAYMETA_T], meta)))[0]
        lane = u(E.call(tok, E.cd("payLane(bytes32)", ["w"], pid)))
        pn = nonce(tok, alice.ua, lane)
        m = [alice.ua, bob.ua, 3, pid, lane, pn, vu, 0, 0, 0, 0]
        sr.send(tok, E.cd(f"mtxPay({UMT_S},{UAS},{PAYMETA_S})", [UMT_T, E.UASIG_T, PAYMETA_T], m, sig(dg(m)), meta),
                f"{nm} mtxPay alice→bob 3, save {save}, ML-DSA-65")
        cnt = u(E.call(tok, E.cd("paymentCount(bytes32)", ["w"], payno)))
        E.check(cnt == (1 if save else 0), f"{nm} paymentCount(payNo) = {cnt} after save {save}")
        if save:
            r = E.call(tok, E.cd("paymentsOf(bytes32,uint256,uint256)", ["w", "w", "w"], payno, 0, 10))
            E.check(u(r, 1) == 1, f"{nm} paymentsOf(payNo, 0, 10): 1 record")
    m = umt(bob.ua, 2, n)
    sr.send(tok, E.cd(f"mtxExecuteTransfer({UMT_S},{UAS})", [UMT_T, E.UASIG_T], m, sig(dg(m))),
            f"{nm} mtxExecuteTransfer alice→bob 2, ML-DSA-65")
    n += 1
    ms = [umt(bob.ua, 1, n), umt(bob.ua, 1, n + 1)]
    sr.send(tok, E.cd(f"mtxBatchTransfer({UMT_S}[],{UAS}[])", [("a", UMT_T), ("a", E.UASIG_T)], ms, [sig(dg(x)) for x in ms]),
            f"{nm} mtxBatchTransfer alice→bob 1 + 1, ML-DSA-65")
    n += 2
    # the generic entry's op: a derived signer's allow-list is burn (a normal kind) or an unwrap (a wrapped one), CTR-UA-26
    inner = (E.cd("burn(uint256)", ["w"], 4) if burn else
             E.cd("unwrap(uint256,address,uint256)", ["w", "w", "w"], 4, sr.addr, 0))
    mx = [alice.ua, inner, 0, n, vu, 0, 0, 0, 0]
    d = E.words(E.call(tok, E.cd(f"mtxDigest({E.UMTX_S})", [E.MTX], mx)))[0]
    sr.send(tok, E.cd(f"mtxExecute({E.UMTX_S},{UAS})", [E.MTX, E.UASIG_T], mx, sig(d)),
            f"{nm} mtxExecute({'burn 4' if burn else 'unwrap 4 to the relayer'}), ML-DSA-65")
    n += 1
    env = [alice.ua, 0, n, vu, 0, 0, 0, 0]
    d = None if not burn else named(tok, "UABurn(bytes32 from,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)", [6], env)
    if burn:
        sr.send(tok, E.cd(f"mtxBurn({E.UEVL_S},uint256,{UAS})", [E.EVL_T, "w", E.UASIG_T], env, 6, sig(d)),
                f"{nm} mtxBurn 6 (named UA envelope), ML-DSA-65")
        n += 1
    env = [alice.ua, 0, n, vu, 0, 0, 0, 0]
    d = named(tok, "UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)", [5], env)
    sr.send(tok, E.cd(f"mtxCancelNonce({E.UEVL_S},uint256,{UAS})", [E.EVL_T, "w", E.UASIG_T], env, 5, sig(d)),
            f"{nm} mtxCancelNonce(lane 5) (named UA envelope), ML-DSA-65")
    n += 1
    lane, nm_ = 7, 4
    d = E.words(E.call(tok, E.cd("invalidateNoncesDigest(bytes32,uint256,uint256)", ["w", "w", "w"], alice.ua, lane, nm_)))[0]
    # the order-nonce floor: purpose `trade` (ERC20MetaTx, a trade-order lane), not `metatx`
    sig_t = E.ml_sig(pq, alice, E.kc("scaas.ua.purpose.trade.v1"), d)
    sr.send(tok, E.cd(f"mtxInvalidateNonces(bytes32,uint256,uint256,{UAS})", ["w", "w", "w", E.UASIG_T], alice.ua, lane, nm_, sig_t),
            f"{nm} mtxInvalidateNonces(lane 7, min 4), ML-DSA-65")
    E.check(u(E.call(tok, E.cd("minNonce(bytes32,uint256)", ["w", "w"], alice.ua, lane))) == nm_, f"{nm} minNonce(alice, 7) = 4")
    got = bal_ua(tok, bob.ua) - b0
    E.check(got == 7 + 100 + 3 + 3 + 2 + 2, f"{nm} bob received {got} through the ML-DSA-signed entries")
    # negatives: an ML-DSA signature over another digest; a transfer above alice's balance
    m = umt(bob.ua, 1, n)
    bad = sig(dg(umt(bob.ua, 2, n)))
    # a derived signer: the registry refuses it by the UA's name (UAUnauthorized), not the native MetaTxBadSignature
    neg(sr.addr, tok, E.cd(f"mtxExecuteTransfer({UMT_S},{UAS})", [UMT_T, E.UASIG_T], m, bad), sel_hex("UAUnauthorized(bytes32)"),
        f"{nm} mtxExecuteTransfer with an ML-DSA signature over another digest")


# ------------------------------------------------------------------ group pqoff: the OFFCHAIN verify mode (group 3f)

def offchain(pq, sd, reg, create, U, aud, DEC, sk, tusd):
    """Section 10 (spec 2026-11-06-attested-verify, group 3f; e2e --zero-dep: the PQZ releases on deps = [0x0], every PQZ
    token OFFCHAIN, its verifier a native id whose key signs a `PqzVerdict` per proof after pqz-ffi verified it off chain):
    a FIXED verifier (kind 4) and TRANSFERABLE ones (e2e's pqUSD and pqW, kinds 4 and 5; kind 4 on a second factory with a
    30 s notice period): the main ops, the verifier change through the GovernanceRouter (propose, the notice, confirm),
    cancel, revoke (every proof refused) and re-assignment, the direct owner entries, setProofStore both ways, and the
    negatives (wrong verdict, missing verdict, a non-verifier's verdict, a revoked verifier, the five-argument disclosure,
    a fixed verifier's change, a confirm before the notice ends)."""
    D = DEP[-1]
    fac = next(v for k, v in D.addr.items() if k.startswith("OpenFactory"))
    router = D.addr["governance_router"]
    alice, bob = U["alice"], U["bob"]
    sr, s3 = E.Sender(2), E.Sender(3)
    E.log("\n## 10. (T66b Step 5b) the PQZ OFFCHAIN verify mode: fixed and transferable verifiers, the verifier change, negatives")

    def conf(fixed):
        return [aud.ua, E.SCALE, E.MAXS, E.FEE, 0, 2, E.MIN_DECOY, 1, E.pad(sd.addr), fixed, 0, 0, 0]

    def life(tok, nm, C, transfers=True):
        sd.send(tok, E.cd("mint(address,uint256)", ["w", "w"], sd.addr, 5_000 * E.SCALE), f"{nm} mint 5,000 public")
        for x, v in ((alice, 300), (bob, 100)):
            sd.send(tok, E.cd(E.API["shield"], ["w", "w"], x.ua, v), f"{nm} mtxShield({x.name}, {v})")
            C.set_next(bal=[(x, v)], total=v)
            C.commit()
        if transfers:
            E.transfer(pq, sd, C, alice, bob, E.ZERO32, 30, True, f"{nm} op 1 alice→bob 30, verdict signed")
            E.rollover(sd, C, bob, 1, f"{nm} bob's credit")
            E.transfer_multi(pq, sd, C, alice, [(bob, 4), (DEC[0], 0)], E.ZERO32, False, f"{nm} op 7 M = 2, verdict signed")
            E.burn(pq, sd, C, alice, 10, sd.addr, f"{nm} unshield alice 10, verdict signed")
            E.burn(pq, sd, C, bob, 0, None, f"{nm} refresh bob, verdict signed")

    def calldata_with(fake, C, what):
        """The calldata of an op 1 alice→bob 1 whose verdict is `fake(tok, stmt, proof)` (nothing sent)."""
        old = E.verdict
        E.verdict = fake
        try:
            return E.transfer(pq, sd, C, alice, bob, E.ZERO32, 1, True, what, send=False)[1]
        finally:
            E.verdict = old

    def signed_by(key, ua):
        """A verdict as the token wants it (its epoch, this statement and proof), signed by `key` over `ua`'s digest."""
        def f(tok, stmt, proof):
            c = E.words(E.call(tok, E.cd("pqzVerifyConfig()", [])), 4)
            v = [tok, E.CTX[0], E.hb(E.call(tok, E.cd("proofSystemId()", []))), E.keccak256(stmt), E.keccak256(proof),
                 int.from_bytes(c[3], "big"), int(time.time()) + E.VERDICT_LIFE]
            d = E.words(E.call(E.REG[0], E.cd("uaAuthDigest(bytes32,bytes32,bytes32)", ["w", "w", "w"], ua, E.P_VERDICT,
                                              E.verdict_hashes(v, E.CTX[1])[2])))[0]
            return [v, [b"", E.ecdsa(key, d), []]]
        return f

    def router_op(op, typ, args, ts, what, send=True):
        n = nonce(router, E.pad(sd.addr))
        env = [E.pad(sd.addr), 0, n, int(time.time()) + 3600, 0, 0, 0, 0]
        d = named(router, typ, args, env)
        data = E.cd(f"{op}({E.UEVL_S},{','.join(ts)},{E.UASIG_S})", [E.EVL_T] + ["w"] * len(ts) + [E.UASIG_T], env, *args,
                    [b"", E.ecdsa(sd.key, d), []])
        return sr.send(router, data, what) if send else data

    T_SET = "UAPqzSetVerifier(bytes32 from,address target,bytes32 next,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    T_CANCEL = "UAPqzCancelVerifier(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    T_REVOKE = "UAPqzRevokeVerifier(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    T_STORE = "UASetProofStore(bytes32 from,address target,uint8 next,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"

    # 1. a FIXED verifier, kind 4, bit 24 (PQZ_PROOF) held by the deployer: the life cycle, setProofStore both ways, negatives
    tf = create_cfg(sd, fac, 4, "PQZ offchain fixed", "pqOF", [], 1 | 2 | 4 | 1 << 24, b"t66b-5b-of", conf(1), issuer=sd.addr)
    D.addr["pqOF"] = tf
    CF = E.Client(tf, "pqOF")
    life(tf, "pqOF", CF)
    sd.send(tf, E.cd("setProofStore(uint8)", ["w"], 1), "pqOF setProofStore(LOG), direct")
    router_op("mtxSetProofStore", T_STORE, [tf, 0], ["address", "uint8"], "pqOF mtxSetProofStore(NONE) through the router")
    E.check(u(E.call(tf, E.cd("proofStore()", []))) == 0, "pqOF proofStore() = NONE after the router")
    mm = sel_hex("PqzVerdictMismatch(uint8)")
    neg(sd.addr, tf, calldata_with(lambda t, st, p: E.NO_VERDICT, CF, "missing verdict"), mm, "pqOF op 1 without a verdict")

    v0 = E.verdict  # e2e's own: `calldata_with` swaps E.verdict for the fake below

    def wrong(t, st, p):
        v = v0(t, st, p)
        v[0][3] = E.kc("another statement")
        return v
    neg(sd.addr, tf, calldata_with(wrong, CF, "wrong verdict"), mm, "pqOF op 1 with a verdict over another statement")
    neg(sd.addr, tf, calldata_with(signed_by(s3.key, E.pad(sd.addr)), CF, "non-verifier"), sel_hex("PqzVerdictRejected()"),
        "pqOF op 1 with a verdict signed by a non-verifier (key 3)")
    neg(sd.addr, tf, E.cd(E.API["verifyAmt"], ["w", "w", "w", "w", "w", "b"], E.kc("any entry"), 0, 1, 0, 0, b"\x00" * 32),
        sel_hex("PqzVerdictRequired()"), "pqOF the five-argument verifyTransferAmount on an OFFCHAIN token")
    neg(sd.addr, tf, E.cd("pqzSetVerifier(bytes32)", ["w"], E.pad(s3.addr)), sel_hex("PqzVerifierFixed()"),
        "pqOF pqzSetVerifier on a fixed verifier")
    E.check_public(CF, "pqOF")
    E.restore(CF, "pqOF")

    # 2. TRANSFERABLE on a notice-0 factory: e2e's pqW (kind 5: wrap-shield, op 1, unshield-unwrap) and pqUSD (direct owner
    #    entries: a change applies at once with notice 0, spec §4.2)
    t2, t1 = D.addr["pqW"], D.addr["pqUSD"]
    C2 = E.Client(t2, "pqW")
    sd.send(tusd, E.cd("approve(address,uint256)", ["w", "w"], t2, 10**12), "tUSD approve pqW")
    sd.send(t2, E.cd(E.API["wrapShield"], ["w", "w", "w"], tusd, 100 * E.SCALE, alice.ua), "pqW mtxWrapShield(tUSD 100, alice)")
    C2.set_next(bal=[(alice, 100)], total=100)
    C2.commit()
    E.transfer(pq, sd, C2, alice, bob, E.ZERO32, 20, False, "pqW op 1 alice→bob 20, verdict signed")
    E.burn(pq, sd, C2, alice, 10, sd.addr, "pqW unshield-unwrap alice 10 → deployer in tUSD, verdict signed", unwrap=(tusd, 10 * E.SCALE))
    E.restore(C2, "pqW")
    sd.send(t1, E.cd("pqzSetVerifier(bytes32)", ["w"], E.pad(s3.addr)), "pqUSD pqzSetVerifier(key 3), direct, notice 0: at once")
    E.check(E.words(E.call(t1, E.cd("pqzVerifyConfig()", [])), 4)[1] == E.pad(s3.addr), "pqUSD verifier = key 3")
    sd.send(t1, E.cd("pqzRevokeVerifier()", []), "pqUSD pqzRevokeVerifier(), direct")
    sd.send(t1, E.cd("pqzSetVerifier(bytes32)", ["w"], E.pad(sd.addr)), "pqUSD pqzSetVerifier(deployer), direct: re-assigned")

    # 3. TRANSFERABLE on a factory with a 30 s notice: kind 4's release there, a token, the router change
    N = 30
    fac2 = D.deploy("OpenFactory", E.encs(["w"], [sd.addr]), label="OpenFactory#notice")
    ref_b = int(_rpc0("eth_blockNumber", []), 16) - 1
    ref_h = E.hb(_rpc0("eth_getBlockByNumber", [hex(ref_b), False])["hash"])
    router_h = E.keccak256(E.hb(_rpc0("eth_getCode", [router, "latest"])))  # spec §13.3: the router's code hash
    sd.send(fac2, E.cd("configureChain(bytes32,uint64,address,bytes32,uint256,bytes32)", ["w"] * 6, E.CTX[1], N, router, router_h,
                       ref_b, ref_h),
            "factory 2 configureChain (notice 30 s)")
    code, libs = D.linked("NormalPqzToken")
    ms = []
    for src, mn in E.kind_modules(4):
        _, ml = D.linked(mn, src)
        libs += [x for x in ml if x not in libs]
        ms.append(D.deploy2(mn, E.encs(["w", "b"], [fac2, E.core_args(4)]), f"module {mn} (factory 2)", src=src))
    libs += ms
    hashes = [E.keccak256(E.hb(_rpc0("eth_getCode", [x, "latest"]))) for x in libs]
    sd.send(fac2, E.cd(f"publishTokenEnv(uint8,uint16,bytes32,{E.ENV_S})", ["w", "w", "w", E.ENV], 4, 1, E.CTX[1],
                       [reg, 0, 0, [0], [], libs, hashes]),
            "factory 2 publishTokenEnv(kind 4, 1), deps [0x0]")
    sd.send(fac2, E.cd("deployTokenImplementation(uint8,uint64,uint16,bytes,bytes,bytes32)", ["w", "w", "w", "b", "b", "w"], 4, 1,
                       1, code, E.impl_args(4, ms), E.CTX[1]), "factory 2 deployTokenImplementation(kind 4, 1)")
    sd.send(fac2, E.cd("setTokenKindEnabled(uint8,bool,bytes32)", ["w"] * 3, 4, 1, E.CTX[1]),
            "factory 2 setTokenKindEnabled(4, true)")
    # a release on a factory with a notice period is usable only after it (VersionNotYetUsable)
    t0 = int(_rpc0("eth_getBlockByNumber", ["latest", False])["timestamp"], 16)
    while int(_rpc0("eth_getBlockByNumber", ["latest", False])["timestamp"], 16) <= t0 + N + 1:
        E.wait_block(int(_rpc0("eth_blockNumber", []), 16) + 1)
    tt = create_cfg(sd, fac2, 4, "PQZ offchain transferable", "pqOT", [], 1 | 2 | 4, b"t66b-5b-ot", conf(0))
    D.addr["pqOT"] = tt
    CT = E.Client(tt, "pqOT")
    life(tt, "pqOT", CT, transfers=False)
    E.transfer(pq, sd, CT, alice, bob, E.ZERO32, 10, True, "pqOT op 1 alice→bob 10, verdict by the deployer")
    nxt = E.pad(s3.addr)
    r = router_op("mtxPqzSetVerifier", T_SET, [tt, nxt], ["address", "bytes32"], "pqOT mtxPqzSetVerifier(key 3): the proposal")
    neg(sr.addr, router, router_op("mtxPqzSetVerifier", T_SET, [tt, nxt], ["address", "bytes32"], "", send=False),
        sel_hex("PqzVerifierNotReady(uint64)"), "pqOT the confirm before the notice ends")
    wait_eta(r, N)
    router_op("mtxPqzSetVerifier", T_SET, [tt, nxt], ["address", "bytes32"], "pqOT mtxPqzSetVerifier(key 3): the confirm after 30 s")
    E.check(E.words(E.call(tt, E.cd("pqzVerifyConfig()", [])), 4)[1] == nxt, "pqOT verifier = key 3, epoch + 1")
    E.VERIFIER[0] = s3
    E.transfer(pq, sd, CT, alice, bob, E.ZERO32, 5, True, "pqOT op 1 alice→bob 5, verdict by the new verifier (key 3)")
    neg(sd.addr, tt, calldata_with(signed_by(sd.key, nxt), CT, "old verifier"), sel_hex("PqzVerdictRejected()"),
        "pqOT a verdict by the replaced verifier")
    router_op("mtxPqzSetVerifier", T_SET, [tt, E.pad(sd.addr)], ["address", "bytes32"], "pqOT propose the deployer again")
    router_op("mtxPqzCancelVerifier", T_CANCEL, [tt], ["address"], "pqOT mtxPqzCancelVerifier: the proposal dropped")
    sd.send(tt, E.cd("pqzSetVerifier(bytes32)", ["w"], E.pad(sd.addr)), "pqOT pqzSetVerifier(deployer), direct: a proposal")
    sd.send(tt, E.cd("pqzCancelVerifier()", []), "pqOT pqzCancelVerifier(), direct")
    router_op("mtxPqzRevokeVerifier", T_REVOKE, [tt], ["address"], "pqOT mtxPqzRevokeVerifier: frozen")
    neg(sd.addr, tt, calldata_with(lambda t, st, p: E.NO_VERDICT, CT, "revoked"), sel_hex("PqzVerifierRevoked()"),
        "pqOT op 1 after the revocation (every OFFCHAIN proof refused)")
    r = router_op("mtxPqzSetVerifier", T_SET, [tt, E.pad(sd.addr)], ["address", "bytes32"], "pqOT re-assign the deployer: proposal")
    wait_eta(r, N)
    router_op("mtxPqzSetVerifier", T_SET, [tt, E.pad(sd.addr)], ["address", "bytes32"], "pqOT re-assign the deployer: confirm")
    E.VERIFIER[0] = sd
    E.transfer(pq, sd, CT, alice, bob, E.ZERO32, 3, True, "pqOT op 1 alice→bob 3 after the re-assignment")
    E.restore(CT, "pqOT")
    verifier_fee(pq, sd, sr, s3, alice, bob, DEC, aud, tusd, fac, fac2, N, D, life, router_op, calldata_with)


def verifier_fee(pq, sd, sr, s3, alice, bob, DEC, aud, tusd, fac, fac2, N, D, life, router_op, calldata_with):
    """Section 10b (round 3t, CTR-PQZ-36, verifier fee spec §13): `OFFCHAIN` tokens with `verifierFee` VF and cap VMAX, the
    verifier key 3's EOA (its ERC-20 balance is its payout, read before and after each debit): kind 4 on the notice-0
    factory (op 1, op 7, unshield, refresh each pay VF; a decrease at once; an op built at the old fee refused `AuthRejected`;
    an increase at once with both events; the router op at fee 0 by a stranger relayer; the direct op 7 rebuilt with
    `d ∓ k` after `Δvf = M·k` refused, both signs, Fable P1-1), kind 4 on factory 2 (30 s notice: the proposal, a confirm
    before `eta` refused, the confirm, a cancel by the current value, the setter's refusals), kinds 5 and 12 (the setter: a
    decrease and an increase, at once on notice 0), and kind 13 (a frozen verifier
    halts the debit `FeeRecipientFrozen`, `setVerifierFee(0)` the relief, the fee restored halts it again, the unfreeze).
    The `PRECOMPILE` setter's refusal is group pq's (`mine`: no `PRECOMPILE` token on zero-dep releases)."""
    E.log("\n## 10b. (round 3t) the verifier fee: payouts per form, the setter, the router op, stale and split ops, a frozen verifier")
    VF, VMAX = 2, 6
    T_FEE = ("UASetVerifierFee(bytes32 from,address target,uint64 next,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,"
             "address relayer,uint256 fee,address feeRecipient)")
    EV = {e: "0x" + E.kc(e + sig).hex() for e, sig in (("VerifierFeeProposed", "(uint64,uint64,uint64)"),
                                                         ("VerifierFeeSet", "(uint64,uint64)"))}
    AUTH_REJ = sel_hex("AuthRejected()")
    E.VERIFIER[0] = s3

    def fconf(vf, dmode=0):
        return [aud.ua, E.SCALE, E.MAXS, E.FEE, dmode, 2, E.MIN_DECOY, 1, E.pad(s3.addr), 0, 0, vf, VMAX]

    def vcfg(t):
        """`pqzVerifyConfig()`'s round-3t words: verifierFee, verifierFeeMax, verifierFeePending, verifierFeeEta."""
        h = E.call(t, E.cd("pqzVerifyConfig()", []))
        return [u(h, i) for i in (7, 8, 9, 10)]

    def vbal(t):
        return u(E.call(t, E.cd("balanceOf(address)", ["w"], s3.addr)))

    def paid(t, C, vf, what, fn):
        b0 = vbal(t)
        r = fn()
        E.check(vbal(t) - b0 == vf * E.SCALE, f"{C.name} {what}: the verifier paid {vf} · scale ({vbal(t) - b0:,})")
        E.check_public(C, f"after {what}")
        return r

    def set_fee(t, nm, nxt, what, events, by=None):
        r = (by or sd).send(t, E.cd("setVerifierFee(uint64)", ["w"], nxt), f"{nm} setVerifierFee({nxt}): {what}")
        got = [x["topics"][0] for x in r["logs"] if x["address"].lower() == t.lower()]
        E.check(got == [EV[e] for e in events], f"{nm} setVerifierFee({nxt}) emitted {', '.join(events)}")
        return r

    # kind 4 on the notice-0 factory
    tf = create_cfg(sd, fac, 4, "PQZ verifier fee", "pqVF", [], 1 | 2 | 4, b"3t-vf4", fconf(VF))
    D.addr["pqVF"] = tf
    E.check(vcfg(tf) == [VF, VMAX, 0, 0], f"pqVF pqzVerifyConfig(): verifierFee {VF}, cap {VMAX}, nothing pending")
    C = E.Client(tf, "pqVF")
    life(tf, "pqVF", C, transfers=False)
    paid(tf, C, VF, "op 1", lambda: E.transfer(pq, sd, C, alice, bob, E.ZERO32, 30, True, "pqVF op 1 alice→bob 30, fee word vf"))
    paid(tf, C, VF, "op 7", lambda: E.transfer_multi(pq, sd, C, alice, [(bob, 4), (DEC[0], 0)], E.ZERO32, False,
                                                      "pqVF op 7 M = 2, fee word vf + 2d"))
    paid(tf, C, VF, "unshield", lambda: E.burn(pq, sd, C, alice, 10, sd.addr, "pqVF unshield alice 10, fee word vf"))
    paid(tf, C, VF, "refresh", lambda: E.burn(pq, sd, C, bob, 0, None, "pqVF refresh bob, fee word vf"))
    set_fee(tf, "pqVF", 1, "a decrease, at once", ["VerifierFeeSet"])
    E.check(vcfg(tf)[0] == 1, "pqVF verifierFee 1 at once")
    stale = E.transfer(pq, sd, C, alice, bob, E.ZERO32, 1, True, "pqVF op 1 built at fee 1", send=False)[1]
    set_fee(tf, "pqVF", 0, "a decrease to 0", ["VerifierFeeSet"])
    neg(sd.addr, tf, stale, AUTH_REJ, "pqVF op 1 built at the old fee, after the decrease")
    paid(tf, C, 0, "op 1 at fee 0", lambda: E.transfer(pq, sd, C, alice, bob, E.ZERO32, 1, True, "pqVF op 1 at fee 0, rebuilt"))
    set_fee(tf, "pqVF", VF, "an increase on notice 0: at once", ["VerifierFeeProposed", "VerifierFeeSet"])
    router_op("mtxSetVerifierFee", T_FEE, [tf, VF + 1], ["address", "uint64"],
              "pqVF mtxSetVerifierFee(vf + 1) through the router, fee 0, relayed by key 2")
    E.check(vcfg(tf)[0] == VF + 1, "pqVF verifierFee vf + 1 by the router op")
    set_fee(tf, "pqVF", VF, "back to vf", ["VerifierFeeSet"])
    # Fable P1-1: a direct op 7 (M = 2, d = DEC_FEE) built at vf, then Δvf = ±M·k met by d ∓ k (the same fee word): refused
    for k, nxt in ((1, VF + 2), (-1, VF - 2)):
        _, (pl, proof, auth, hint, sv), _, _ = E.transfer_multi(pq, sd, C, alice, [(bob, 2), (DEC[0], 0)], E.ZERO32, False,
                                                                f"pqVF op 7 built at vf {VF}, d {E.DEC_FEE}", send=False)
        set_fee(tf, "pqVF", nxt, f"Δvf = {2 * k:+}", ["VerifierFeeSet"] if nxt < VF else ["VerifierFeeProposed", "VerifierFeeSet"])
        pl = list(pl)
        pl[6] = E.DEC_FEE - k
        data = E.cd(E.API["transfer"], [E.MULTI_T] + E.AUTH_T + [E.SV_T], pl, proof, auth, hint, sv)
        neg(sd.addr, tf, data, AUTH_REJ, f"pqVF direct op 7 resubmitted with d {E.DEC_FEE - k} after Δvf = {2 * k:+}")
        set_fee(tf, "pqVF", VF, "back to vf", ["VerifierFeeSet"] if nxt > VF else ["VerifierFeeProposed", "VerifierFeeSet"])
    paid(tf, C, VF, "op 7 at the unchanged vf and d (the control)", lambda: E.transfer_multi(
        pq, sd, C, alice, [(bob, 2), (DEC[0], 0)], E.ZERO32, False, "pqVF op 7 at vf, d (control)"))
    E.restore(C, "pqVF")

    # kind 4 on factory 2: the 30 s notice
    tn = create_cfg(sd, fac2, 4, "PQZ verifier fee notice", "pqVFN", [], 1 | 2 | 4, b"3t-vfn", fconf(1))
    D.addr["pqVFN"] = tn
    r = set_fee(tn, "pqVFN", 3, "an increase: the proposal", ["VerifierFeeProposed"])
    c = vcfg(tn)
    E.check(c[:3] == [1, VMAX, 3] and c[3] > 0, f"pqVFN pending 3 at eta {c[3]}, the fee still 1")
    neg(sd.addr, tn, E.cd("setVerifierFee(uint64)", ["w"], 3), sel_hex("VerifierFeeNotReady(uint64)"), "pqVFN the confirm before eta")
    wait_eta(r, N)
    set_fee(tn, "pqVFN", 3, "the confirm after the notice", ["VerifierFeeSet"])
    E.check(vcfg(tn)[:3] == [3, VMAX, 0], "pqVFN verifierFee 3, nothing pending")
    set_fee(tn, "pqVFN", 5, "a second proposal", ["VerifierFeeProposed"])
    set_fee(tn, "pqVFN", 3, "the current value cancels it", ["VerifierFeeSet"])
    E.check(vcfg(tn)[:4] == [3, VMAX, 0, 0], "pqVFN the pending cancelled, the fee unmoved")
    for nxt, err, what in ((3, "VerifierFeeSame()", "the current value, nothing pending"),
                           (VMAX + 1, "VerifierFeeAboveMax(uint64,uint64)", "above the cap")):
        neg(sd.addr, tn, E.cd("setVerifierFee(uint64)", ["w"], nxt), sel_hex(err), f"pqVFN setVerifierFee({nxt}): {what}")
    neg(s3.addr, tn, E.cd("setVerifierFee(uint64)", ["w"], 0), sel_hex("NotAdmin(bytes32)"), "pqVFN setVerifierFee by a stranger")

    # the setter on kinds 5 and 12 (notice-0 factory): a decrease at once, an increase at once with both events
    for kind, nm, legs, feat, rg in ((5, "pqVF5", [[tusd, 1, 1]], 1, None),
                                     (12, "pqVF12", [], 1 | 2 | 4, [0, 0, 0, E.kc("scaas.onchain.terms"), 0])):
        t = create_cfg(sd, fac, kind, f"PQZ verifier fee kind {kind}", nm, legs, feat, nm.encode(), fconf(VF), rg)
        D.addr[nm] = t
        set_fee(t, nm, VF - 1, "a decrease, at once", ["VerifierFeeSet"])
        set_fee(t, nm, VF, "an increase on notice 0: at once", ["VerifierFeeProposed", "VerifierFeeSet"])
        E.check(vcfg(t) == [VF, VMAX, 0, 0], f"{nm} verifierFee {VF}, nothing pending")

    # kind 13 with vf: a frozen verifier halts every debit, fee 0 is the relief (Fable P2-1, T31)
    if 13 in E.SKIP_KINDS:
        E.log("      kind 13 skipped on this chain (--skip-kind 13)")
    else:
        # FREEZE (bit 5) is contract-only (RoleNotContract): the issuer seat is an OnchainForwarder of the deployer
        fw = D.deploy("OnchainForwarder", b"", label="OnchainForwarder (pqVF13 issuer)")
        t13 = create_cfg(sd, fac, 13, "PQZ regulated wrapped verifier fee", "pqVF13", [[tusd, 1, 1]], 1 | 1 << 5, b"3t-vf13",
                         fconf(VF, 1), [0, 0, 0, E.kc("scaas.onchain.terms"), 0], issuer=fw)
        D.addr["pqVF13"] = t13
        C13 = E.Client(t13, "pqVF13")
        sd.send(tusd, E.cd("approve(address,uint256)", ["w", "w"], t13, 10**12), "tUSD approve pqVF13")
        sd.send(t13, E.cd(E.API["wrapShield"], ["w", "w", "w"], tusd, 100 * E.SCALE, alice.ua), "pqVF13 mtxWrapShield(tUSD 100, alice)")
        C13.set_next(bal=[(alice, 100)], total=100)
        C13.commit()
        paid(t13, C13, VF, "unshield-unwrap", lambda: E.burn(pq, sd, C13, alice, 5, sd.addr, "pqVF13 unshield-unwrap alice 5",
                                                              unwrap=(tusd, 5 * E.SCALE)))
        vid, ref = E.pad(s3.addr), E.kc("scaas.onchain.3t-freeze")
        sd.send(fw, E.cd("forwardCall(address,bytes)", ["w", "b"], t13, E.cd("freeze(bytes32,bytes32,bytes32)", ["w", "w", "w"],
                                                                                  vid, ref, 0)), "pqVF13 freeze the verifier")
        op1 = lambda what: E.transfer(pq, sd, C13, alice, bob, E.ZERO32, 7, False, what, send=False)[1]  # noqa: E731
        frozen = sel_hex("FeeRecipientFrozen(bytes32)")
        neg(sd.addr, t13, op1("pqVF13 op 1 with a frozen verifier"), frozen, "pqVF13 op 1 while the verifier is frozen, vf set")
        set_fee(t13, "pqVF13", 0, "the relief, at once", ["VerifierFeeSet"])
        paid(t13, C13, 0, "op 1 at fee 0", lambda: E.transfer(pq, sd, C13, alice, bob, E.ZERO32, 7, False,
                                                              "pqVF13 op 1 at fee 0: lands, the frozen verifier unchecked"))
        set_fee(t13, "pqVF13", VF, "the fee restored (notice 0)", ["VerifierFeeProposed", "VerifierFeeSet"])
        neg(sd.addr, t13, op1("pqVF13 op 1 after the fee restored"), frozen, "pqVF13 op 1: the restored fee halts it again")
        sd.send(fw, E.cd("forwardCall(address,bytes)", ["w", "b"], t13, E.cd("unfreeze(bytes32,bytes32)", ["w", "w"], vid, ref)),
                "pqVF13 unfreeze the verifier")
        paid(t13, C13, VF, "op 1 after the unfreeze", lambda: E.transfer(pq, sd, C13, alice, bob, E.ZERO32, 7, False,
                                                                         "pqVF13 op 1 after the unfreeze"))
        E.restore(C13, "pqVF13")
    E.VERIFIER[0] = sd


def wait_eta(r, n):
    """Until the head is past the proposal's eta (its block's timestamp + the notice `n`): a confirm's estimate runs on
    the head's state, whose timestamp must reach eta (PqzVerifierNotReady before)."""
    eta = int(_rpc0("eth_getBlockByNumber", [r["blockNumber"], False])["timestamp"], 16) + n
    while int(_rpc0("eth_getBlockByNumber", ["latest", False])["timestamp"], 16) <= eta:
        E.wait_block(int(_rpc0("eth_blockNumber", []), 16) + 1)


def standalone(a):
    """Sections 8 and 9 alone, after a full run whose section 8 failed or was not run (e2e's state rebuilt: the holders from
    its test seeds, a UA id is the key's, registry-free; key version 0, which the full run leaves for these holders)."""
    E.RPC = a.rpc
    chain = int(_rpc0("eth_chainId"), 16)
    E.CTX[:] = [chain, E.hb(_rpc0("eth_getBlockByNumber", ["0x0", False])["hash"])]
    book = json.load(open(os.path.join(EVM, f"deployments/onchain-{NET}-{GROUP}.json")))
    by = {}
    for x, lab in book.items():
        by.setdefault(lab, []).append(x)
    reg = by["UARegistry"][-1]
    E.REG[0] = reg
    pq = E.PQ()
    sk = lambda tag: E.kc("p6g-e2e-7622/", tag)  # noqa: E731  e2e's test seeds
    U = {}
    for name in ("alice", "bob", "aud", "carol", "decoy0"):
        mls, pqs = sk("ml-" + name), sk("pqz-" + name)
        mlpk = pq.ml_pk(65, mls)
        pk, s_, e_, _ = E.K.keygen(pqs)
        ua = E.words(E.call(reg, E.cd("uaOf(uint16,bytes)", ["w", "b"], E.MLDSA65, mlpk)))[0]
        E.check(u(E.call(reg, E.cd("pqzKeyOf(bytes32)", ["w"], ua))) == 0, f"{name}: key version 0 current")
        U[name] = E.UA(name=name, kind=E.MLDSA65, seed=mls, pk=pk, s=s_, e=e_, ua=ua)
    sd, sr = E.Sender(1), E.Sender(2)
    D = E.Deployer(sd)
    fac = next(x for x in by["OpenFactory"] if len(_rpc0("eth_getCode", [x, "latest"])) > 1000)
    for lab, key in (("NormalPqzToken", "pqUSD"), ("WrappedPqzToken", "pqW")):  # e2e's first token of each PQZ kind
        cl = [x for x in by.get(lab, []) if len(_rpc0("eth_getCode", [x, "latest"])) < 1000]
        if cl:
            D.addr[key] = cl[0]
    old = [json.loads(x) for x in open(os.path.join(OUTD, f"records-{NET}-{GROUP}.jsonl"))]
    rc = 0
    try:
        mine(pq, sd, sr, U, U["aud"], [U["decoy0"]], by["MockERC20"][-1], fac, D)
    except Exception as e:  # noqa: BLE001
        import traceback
        E.check(False, f"aborted: {type(e).__name__}: {e}\n{traceback.format_exc()}")
    finally:
        write(old + REC, [D])
        with open(os.path.join(OUTD, f"pq-{NET}-extra.log"), "w") as f:
            f.write("\n".join(E.LOG) + f"\n\nresult: {len(E.FAILS)} failure(s)\n")
    bad = sum(1 for r in REC if r["status"] == 0) + len(E.FAILS)
    print(f"pq --extra-only: {len(REC)} records, {bad} failed")
    sys.exit(1 if bad else 0)


_rotation0 = E.rotation


def _rotation(pq, s, reg, C, *a):
    """e2e's section 6c sends its three op-1 transfers with the auditor leg off, on pqUSD, whose auditor mode is FULL: the
    token refuses them `AuditorRequired()` (PqzCore, as it must). The harness turns the leg on (argument 8) there."""
    t0 = E.transfer
    E.transfer = lambda pq_, s_, C_, frm, to, ben, v, aud_on, *r, **k: t0(pq_, s_, C_, frm, to, ben, v, True, *r, **k)
    try:
        return _rotation0(pq, s, reg, C, *a)
    finally:
        E.transfer = t0


E.rotation = _rotation
_proof_path0 = E.proof_path
E.proof_path = extra
NET = "local"
GROUP = "pq"  # pqoff with --offchain


GROUPS = json.load(open(os.path.join(HERE, "groups.json")))["groups"]
LABELS = {c["label"] for cs in GROUPS.values() for c in cs}
KINDS = sorted((c["label"] for c in GROUPS["tokens"]), key=len, reverse=True)


def label(k):
    """An e2e Deployer key as a groups.json label: "library X", "module X (factory 2)" -> X, "tUSD (MockERC20)" ->
    MockERC20, "UARegistry gen 1" -> UARegistry, "OpenFactory#notice" -> OpenFactory, "governance_router" ->
    GovernanceRouter; a body module (NormalPqzTokenP) under its kind's label, as basebook.py books it."""
    k = k.split("#")[0]
    m = re.fullmatch(r"(?:library|module) (\w+).*", k) or re.fullmatch(r".* \((\w+)\)", k)
    k = m[1] if m else {"governance_router": "GovernanceRouter"}.get(k, k.split(" ")[0])
    return next((x for x in KINDS if re.fullmatch(re.escape(x) + r"(P|T|A|W|R|Z|Q|S)", k)), k)


def write(recs, deps):
    """The book (e2e's names as groups.json labels, token clones by their kind) and the records; an earlier book's rows
    are kept."""
    bp = os.path.join(EVM, f"deployments/onchain-{NET}-{GROUP}.json")
    out = json.load(open(bp)) if os.path.exists(bp) else {}
    book = {}
    for d in deps:
        for k, v in {**d.addr, **d.libs}.items():
            book[v.lower()] = label(k)
    for r in recs:
        for x in (r["to"], r.get("created", "")):
            if x and x not in book and x not in out:
                book[x] = ""
    for a_, name in book.items():
        try:
            k = u(E.call(a_, E.cd("kind()", [])))
            lab = LABEL_KIND.get(k, name) if len(_rpc0("eth_getCode", [a_, "latest"])) < 1000 else name  # a clone: by kind
        except Exception:  # noqa: BLE001
            lab = name
        out[a_] = lab or out.get(a_, "")
    with open(bp, "w") as f:
        json.dump(out, f, indent=1)
    with open(os.path.join(OUTD, f"records-{NET}-{GROUP}.jsonl"), "w") as f:
        for r in recs:
            r["label"] = out.get(r["to"], "")
            f.write(json.dumps(r) + "\n")


def main():
    global NET, GROUP
    ap = argparse.ArgumentParser()
    ap.add_argument("--net", required=True)
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--extra-only", action="store_true",
                    help="sections 8 and 9 only, on e2e's deploy of an earlier run (its book deployments/onchain-<net>-pq.json)")
    ap.add_argument("--offchain", action="store_true",
                    help="group pqoff: the PQZ OFFCHAIN verify mode (e2e --zero-dep, sections 1-3, then section 10)")
    a = ap.parse_args()
    NET = a.net
    if a.offchain:
        GROUP = "pqoff"
        E.proof_path = offchain
    os.makedirs(OUTD, exist_ok=True)
    if a.extra_only:
        return standalone(a)
    sys.argv = ["e2e.py", "--rpc", a.rpc, "--split", "--keys", "1,2,3", "--log", os.path.join(OUTD, f"{GROUP}-{NET}.log")]
    if a.offchain:  # group 3f: e2e's deploy on deps = [0x0], its PQZ tokens OFFCHAIN; sections 1-3, then `offchain`
        sys.argv += ["--zero-dep", "--proof-path-only"]
    rc = 0
    try:
        E.main()
    except SystemExit as e:
        rc = e.code or 0
    write(REC, DEP)
    bad = sum(1 for r in REC if r["status"] == 0)
    print(f"pq: {len(REC)} records, {bad} failed; e2e rc {rc}")
    sys.exit(rc or (1 if bad else 0))


if __name__ == "__main__":
    main()
