# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Groups `pqzkeys` and `pqzwallet` of mldsa_on.py (README-mldsa-on.md): PqzKeys.s.sol's `PqzKeysSetup.setup()` (without
`_pqOn`, the `tokens` group's) and `PqzKeysRoll.roll()`, PqzWallet.s.sol's `setup()` and `roll()`, as real transactions on
the set's registry and factory. Owner D2: the PQZ tokens on the set's factory in OFFCHAIN mode (the verifier EOA from test
key 1, as forge's `_vInit`). Every scoped record and the registry key record of pqzkeys carry a REAL PQZ key and a real
R_REG proof (pqz_prove) over the message the registry checks (its own views); pqzwallet's keys are the wallet tool's (D3:
on a registry with a PqzKeyVerifier its records stay unproven, recorded as a gap). Ciphertexts and op proofs are forge's
filler bytes (an OFFCHAIN token checks the verifier's signed verdict, e2e's `verdict`). mldsa_on.py loads this module and
sets `M` to itself; its helpers are read as `M.<name>` at call time. Test keys and seeds only. UNAUDITED."""
import json
import os
import subprocess
import time
import types

M = None  # mldsa_on (set by its group_fn before a g_ function runs)
E = P = K = None
S = {}  # this process's state: pqzkeys' holders and tokens for its roll and for pqzwallet

VPROOF = bytes.fromhex("c0de")
WIN = 10_000  # validUntilBlock windows (forge's WIN)
ROLL_WAIT_S = 300  # the roll phase's bound on the wait for ROLL_AGE + 1 blocks
MLKEM_CT, SEALED_SEED, SEALED = 1568, 48, 2 + 40  # PqzCore
PAYABLE, PQZ_PROOF, BURNER = 0, 24, 30  # GovernanceBits
LANES = int("000000ffffffffff" * 4, 16)  # forge `_blob`: every 64-bit lane < 2^40 (canonical at every set)
ACCT = None
PQZ_KINDS = (4, 5, 12, 13)
PRE = "mldsa-on pqzkeys"
TOOL = os.environ.get("PQZ_WALLET_SIM") or "script/pqz/wallet/target/release/pqz-wallet-sim"


def _bind():
    global E, P, K, ACCT
    E, P, K = M.E, M.P, M.E.K
    ACCT = E.ACCT + ["rollSeq"]  # IPqzToken.AccountState (CTR-PQZ-41: rollSeq last)


# ------------------------------------------------------------------ the signatures (explicit where the ABI overloads)

def sigs():
    U = E.UASIG_S
    return types.SimpleNamespace(
        set_scoped=P.SET_SCOPED, store_scoped="storePqzScopedPop(bytes32,address,uint64,bytes)", rec=P.REC_S,
        scoped_digest="pqzScopedKeyDigest(bytes32,uint8,bytes32,address,uint64,bytes32)",
        ua_msg="uaMessage(uint16,bytes32,bytes32)", key_hash="keyHashOf(uint16,bytes)",
        scoped_at="pqzScopedKeyAt(bytes32,address,uint64)", latest="pqzScopedKeyLatest(bytes32,address)",
        open_kem="pqzOpenKemAt(bytes32,address,uint64)",
        shield="mtxShield(bytes32,uint256)", prep="mtxPrepareAcc(bytes32,uint64,uint256)", roll="mtxRollOver(bytes32,uint64,uint256)",
        roll_signed=f"mtxRollOverSigned(bytes32,uint64,uint64,uint64[],uint64,{U})",
        execute=f"mtxExecute({E.UMTX_S},{U})", mtx_digest=f"mtxDigest({E.UMTX_S})",
        exec_meta="executeMetaTransaction((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)",
        single_c=E.API["transferSingle"].replace("Single(", "SingleCompact("),
        multi_c=E.API["transfer"].replace("Transfer(", "TransferCompact(", 1),
        pending="pqzPending(bytes32,uint64,uint64)", skipped="pqzSkipped(bytes32,uint64,uint64)",
        account="pqzAccount(bytes32,uint64)", cfg="pqzVerifyConfig()")


# ------------------------------------------------------------------ small helpers

def W(x):
    return E.W(x)


def u(h, i=0):
    return int.from_bytes(E.words(h)[i], "big")


def view(to, sig, *vs):
    return E.call(to, M.cdx(sig, *vs))


def head():
    return int(E.rpc("eth_blockNumber"), 16)


def vub():
    return head() + WIN


def blob(seed, n):
    """forge `_blob(seed, n)`: n filler bytes, word i/32 = keccak256(abi.encode(seed, i)) with every 64-bit lane < 2^40."""
    return b"".join((int.from_bytes(E.kc(W(seed), W(i)), "big") & LANES).to_bytes(32, "big") for i in range(0, n, 32))[:n]


def salt32(seed):
    """`bytes16(keccak256(abi.encode(seed)))` as its ABI word (left-aligned)."""
    return E.kc(W(seed))[:16] + bytes(16)


def opening(seed):
    return [blob(seed, MLKEM_CT), E.kc(E.encs(["b", "w"], [b"eph", seed])), blob(seed + 1, SEALED_SEED)]


def acct(t, ua):
    return dict(zip(ACCT, (int.from_bytes(w, "big") for w in E.words(view(t, sigs().account, ua, 0), len(ACCT)))))


def cfg_word(t, i):
    return u(view(t, sigs().cfg), i)


def opens(t):
    return cfg_word(t, 12) == 1  # PqzVerifyConfig.pqzOpening


def own(t):
    return cfg_word(t, 11) == 1  # pqzOwnKey


def env(frm, lane, at, vu):
    """A `UAEnvelope` of id `frm` on lane `lane` of `at` (open mode, no fee)."""
    return [frm, lane, P.nonce(at, frm, lane), vu, 0, E.ZERO, 0, E.ZERO]


def binding(t, e):
    return E.hb(E.call(t, E.cd(f"envelopeBinding({E.UMTX_S})", [E.MTX], [e[0], b""] + e[1:])))


def native(key, d):
    return [b"", E.ecdsa(key, d), []]


def at_of(t):
    return (t, E.CTX[0], E.chain_word(t))


def err(art, name, *args):
    """Revert data `name(args)` (an error of `art`'s ABI): the selector alone without args, else the whole data."""
    s = M.fsig(art, name, "error")
    data = E.sel(s) + (E.encs(E.abi_ts(s[s.index("(") + 1:-1]), list(args)) if args else b"")
    return "0x" + data.hex()


IP, REGA = "IPqzToken.sol/IPqzToken", "UARegistry.sol/UARegistry"


# ------------------------------------------------------------------ clientkeys (the typed digests of the wallet side)

_JS = """
const ck = process.argv[1], E = await import(ck + '/src/evm.js'), O = await import(ck + '/src/pqzopen.js'), U = await import(ck + '/src/ua.js');
const B = await import(ck + '/src/bytes.js');
const a = JSON.parse((await import('node:fs')).readFileSync(0, 'utf8'));
let r;
if (a.fn === 'roll') {
  const eh = a.entriesHash ?? B.hex(O.pqzEntriesHash(a.entries.map((x) => O.pqzEntryHash(BigInt(x.index), x.slot, x.code))));
  r = E.hashTypedData(E.OP_BUILDERS.pqzRollOverTypedData({ ...a.at, message: { ...a.message, entriesHash: eh } }));
} else if (a.fn === 'meta') r = E.hashTypedData(E.metaTxTypedData(a.at));
else if (a.fn === 'membership') r = U.membershipMessage({ ua: B.fromHex(a.ua), member: B.fromHex(a.member) }).memberDigest;
console.log(typeof r === 'string' ? r : B.hex(r));
"""


def ck(fn, **a):
    out = subprocess.run(["node", "--input-type=module", "-e", _JS, "--", E.CK], input=json.dumps(E.js(dict(a, fn=fn))),
                         capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(f"clientkeys {fn}: {out.stderr.strip()[-400:]}")
    return E.hb(out.stdout.strip())


def domain_name(c):
    return E.dec_bytes(E.call(c, E.cd("eip712Domain()", [])), 1).decode()


# ------------------------------------------------------------------ registry: holders, the msig, records

def holders(pq, sd, tag):
    """forge `_registerMl` + `_holder(bob)`, `_holder(carol)`: ML-DSA-65 UAs on the set's registry (M.ml_ua)."""
    return {n: M.ml_ua(pq, sd, n, E.MLDSA65, E.kc(PRE, P.RUN, tag, n)) for n in ("uaM", "bob", "carol")}


def msig(pq, sd, bob, carol):
    """forge `_msig`: bob and carol, ids ascending, threshold 1; PoP bob's member signature over the registration digest
    (views), then bob's membership accepted (clientkeys `membershipMessage`)."""
    reg = E.REG[0]
    m0, m1 = sorted([bob.ua, carol.ua])
    slot = 0 if bob.ua == m0 else 1
    kd = E.hb(E._ck("msig", threshold=1, members=[dict(kind=E.MLDSA65, id=E.js(x), weight=1) for x in (m0, m1)]))
    mu = E.words(E.call(reg, E.cd("uaOf(uint16,bytes)", ["w", "b"], E.MSIG, kd)))[0]
    kh = E.words(view(reg, "kemRecordHash(bytes32,uint64,(uint8,bytes,bytes32))", mu, 0, [0, b"", E.ZERO32]))[0]
    rd = E.words(view(reg, "registrationDigest(bytes32,uint16,bytes32,bytes32,bytes32)", mu, E.MSIG, E.ZERO32, kh, E.ZERO32))[0]
    msg = E.words(view(reg, sigs().ua_msg, E.MSIG, E.kc("scaas.ua.purpose.pop.v2"), rd))[0]
    pop = [[slot, [], E.ml_sig(pq, bob, E.P_MEMBER, E.kc(mu, msg))[1]]]
    st = [1, [[E.MLDSA65, m0, 1], [E.MLDSA65, m1, 1]]]
    sd.send(reg, E.cd(E.REGISTER_MSIG, E.REGISTER_MSIG_T, st, [b"", E.ZERO32, [0, b"", E.ZERO32], E.ZERO32], pop, b""),
            "registerMsig mu (bob, carol; threshold 1)")
    E.check(u(E.call(reg, E.cd("kindOf(bytes32)", ["w"], mu))) == E.MSIG, f"mu = {mu.hex()[:16]}… kindOf 0x0120")
    md = ck("membership", ua=mu, member=bob.ua)
    sd.send(reg, M.cdx(M.fsig(REGA, "acceptMembership"), mu, [slot, [], E.ml_sig(pq, bob, E.P_MEMBER, md)[1]]),
            "acceptMembership mu (bob)")
    E.check(u(view(reg, "memberAccepted(bytes32,uint256)", mu, slot)) == 1, "mu memberAccepted(bob's slot)")
    return E.UA(name="mu", kind=E.MSIG, ua=mu, slot=slot)


def sig_by(pq, h, purpose, d):
    """A holder's `UASig`: its ML-DSA signature, or for mu bob's slot under `member` (forge `_msigSig`)."""
    if h.kind != E.MSIG:
        return E.ml_sig(pq, h, purpose, d)
    msg = E.words(view(E.REG[0], sigs().ua_msg, E.MSIG, purpose, d))[0]
    return [b"", b"", [[h.slot, [], E.ml_sig(pq, S["bob"], E.P_MEMBER, E.kc(h.ua, msg))[1]]]]


def kem_pk(k):
    return b"" if k == [0, b"", E.ZERO32] else bytes([k[0]]) + k[1] + k[2]


def rreg_on():
    """The set's registry checks R_REG (a PqzKeyVerifier in the book with code)."""
    v = M.DEP.get("pqz_key_verifier")
    return bool(v) and int(v, 16) != 0 and E.rpc("eth_getCode", [v, "latest"]) not in ("0x", None)


def rec_digest(h, scope, v, key, ph, kem, vb, uid, signed_scope=None):
    sc = scope if signed_scope is None else signed_scope
    kh = E.words(view(E.REG[0], sigs().key_hash, E.PQZ_MLWE, key))[0]
    kp = kem_pk(kem)
    return E.words(view(E.REG[0], sigs().rec, h.ua, 2 if int(sc, 16) == 0 else 3, uid, sc, v, kh, ph,
                        E.kc(kp) if kp else E.ZERO32, vb))[0], kh


def kem_of(h, scope, v):
    """forge `_record`'s opening KEM key (filler, as forge)."""
    x = E.encs(["w", "w", "w"], [h.ua, scope, v])
    return [1, blob(int.from_bytes(E.kc(x), "big"), 1568), E.kc(x)]


def scoped(pq, sd, h, scope, v, kem):
    """K3-3 (forge `_scoped`) with a REAL key: `h`'s record of `scope` at version `v` signed by its key, then the real R_REG
    over `uaMessage(0x0142, PURPOSE_PQZ_SCOPED_KEY, pqzScopedKeyDigest(...))` (the registry's views) by `storePqzScopedPop`;
    `proven` checked."""
    reg, uid = E.REG[0], E.CTX[1]
    pk, s_, e_, _ = K.keygen(E.kc(PRE, P.RUN, b"scoped", h.ua, E.hb(scope), W(v)))
    kh = E.words(view(reg, sigs().key_hash, E.PQZ_MLWE, pk))[0]
    cls = 2 if int(scope, 16) == 0 else 3
    m = E.words(view(reg, sigs().ua_msg, E.PQZ_MLWE, P.P_SCOPED, E.words(view(reg, sigs().scoped_digest, h.ua, cls, uid, scope, v, kh))[0]))[0]
    proof = pq.prove(3, K.build_register(m, pk), K.i8(s_) + K.i16(e_))
    ph = E.kc(proof)
    k = kem_of(h, scope, v) if kem else [0, b"", E.ZERO32]
    vb = vub()
    d, _ = rec_digest(h, scope, v, pk, ph, k, vb, uid)
    nm = f"{h.name} scope {scope[:10]}… v{v}"
    sd.send(reg, M.cdx(sigs().set_scoped, h.ua, scope, v, pk, ph, k, vb, sig_by(pq, h, P.P_SCOPED, d)), f"setPqzScopedKey {nm}")
    sd.send(reg, M.cdx(sigs().store_scoped, h.ua, scope, v, proof), f"storePqzScopedPop {nm} (R_REG {len(proof):,} B)")
    E.check(u(view(reg, sigs().scoped_at, h.ua, scope, v), 2) == int(rreg_on()), f"{nm}: proven = {int(rreg_on())}")


def filler_key(n=None):
    """forge `_record`'s key bytes (a negative's): PqzCt.PK bytes, bytes 13-15 0x5c and a counter (only the first 16 kept
    when resized)."""
    S["keySeed"] = S.get("keySeed", 0) + 1
    k = bytearray(K.PK_BYTES)
    k[13], k[14], k[15] = 0x5C, (S["keySeed"] >> 8) & 0xFF, S["keySeed"] & 0xFF
    return bytes(k) if n is None else bytes(k[:16]) + bytes(n - 16)


# ------------------------------------------------------------------ tokens (the set's factory, OFFCHAIN: forge `_conf`)

def conf(own_, open_, auditor=b"", amode=0):
    return [auditor, 10_000, 1 << 40, 0, 0, amode, 0, 1, S["vA"], 0, 0, 0, 3, int(own_), int(open_)]


def create(sd, kind, name, sym, feat, salt, cf, legs=(), supply=0, roles=None):
    """`createToken` on the set's factory (e2e's TokenConfig, pq.py's `create_cfg` with supply and roles)."""
    fac = M.DEP["token_factory"]
    reg = [0, 0, 0, E.kc("onchain pqzkeys terms"), 0] if kind >= 12 else [0, 0, 0, 0, 0]
    c = [name, sym, 6, feat, 0, sd.addr, roles or [0] * 6, supply, sd.addr if supply else 0, [list(x) for x in legs], [0, 0],
         cf, 0, 0, 0, 0, reg]
    data = E.cd("createToken(uint8,uint64,bytes,bytes32)", ["w", "w", "b", "w"], kind, 1, E.encs([E.CFG], [c]), E.kc(salt, P.RUN))
    r = sd.send(fac, data, f"createToken {sym} (kind {kind})")
    t = "0x" + next(x for x in r["logs"] if x["address"].lower() == fac.lower())["topics"][1][-40:]
    E.log(f"      {sym} at {t}")
    return t


def token(sd, kind, own_, open_, what):
    """forge `_token`: PAYABLE | PQZ_PROOF, class 3 (`own_`) or 2, the opening; a wrapped kind wraps 1e15 of the leg."""
    wrapped = kind in (5, 13)
    t = create(sd, kind, f"Onchain PQZ {what}", "oPQ", 1 << PAYABLE | 1 << PQZ_PROOF, f"pqzkeys-{what}", conf(own_, open_),
               legs=[(S["leg"], 1, 1)] if wrapped else (), supply=0 if wrapped else 10**15)
    if wrapped:
        sd.send(S["leg"], E.cd("approve(address,uint256)", ["w", "w"], t, 2**256 - 1), f"leg approve {what}")
        sd.send(t, E.cd("wrap(uint256)", ["w"], 10**15), f"wrap 1e15 on {what}")
    S["label"][t] = what
    return t


# ------------------------------------------------------------------ the confidential entries (filler, forge's)

def op1(t, frm, to, seed):
    a = [acct(t, frm.ua)["pendingCount"], vub(), 0, frm.ua, 0, to.ua, E.ZERO32, salt32(seed), E.ZERO32, blob(seed, K.PK_BYTES),
         blob(seed + 1, K.V_BYTES), blob(seed + 2, K.V_BYTES), b"", b"", b"", E.NO_OPENING, E.NO_OPENING]
    if opens(t):
        a[13], a[15] = blob(seed + 7, K.PK_BYTES), opening(seed)
    return a


def op7(t, frm, to, decoy, seed):
    return [acct(t, frm.ua)["pendingCount"], vub(), 0, frm.ua, 0, E.ZERO32, 0, salt32(seed), E.ZERO32, [blob(seed, K.PK_BYTES)],
            [[to.ua, blob(seed + 3, K.V_BYTES), b""], [decoy.ua, blob(seed + 4, K.V_BYTES), b""]], blob(seed + 2, K.V_BYTES), b""]


def burn_args(t, frm, seed):
    return [acct(t, frm.ua)["pendingCount"], vub(), 0, frm.ua, 0, E.ZERO32, E.ZERO32, blob(seed, K.PK_BYTES), blob(seed + 1, K.V_BYTES)]


def stmt(t, kind, a, bnd=None):
    b = bnd or E.ZERO32
    if kind == 1:
        return E.dec_bytes(E.call(t, E.cd(E.API["singleStmt"], [E.TRANSFER_T, "w"], a, b)))
    if kind == 7:
        return E.dec_bytes(E.call(t, E.cd(E.API["multiStmt"], [E.MULTI_T, "w"], a, b)))
    if kind == "unwrap":
        return E.dec_bytes(E.call(t, E.cd(E.API["unwrapStmt"], [E.BURN_T, E.UNWRAP, "w"], a[0], a[1], b)))
    return E.dec_bytes(E.call(t, E.cd(E.API["burnStmt"], [E.BURN_T, "w", "w", "w"], a[0], a[1], a[2], b)))


def auth(pq, h, op, st):
    return E.ml_sig(pq, h, E.P_ZAUTH, K.auth_digest(op, st))


def send1(pq, sr, t, frm, a, compact, what):
    if compact:
        a[14] = blob(int.from_bytes(E.kc(a[7]), "big"), SEALED)
    st = stmt(t, 1, a)
    sg = sigs().single_c if compact else E.API["transferSingle"]
    sr.send(t, E.cd(sg, [E.TRANSFER_T] + E.AUTH_T + [E.SV_T], a, VPROOF, auth(pq, frm, 1, st), b"", E.verdict(t, st, VPROOF)),
            f"{lab(t)} op 1{' compact' if compact else ''} {what}")


def send7(pq, sr, t, frm, a, compact, what):
    if compact:
        a[12] = blob(int.from_bytes(E.kc(a[7]), "big"), 2 + 40 * len(a[10]))
    st = stmt(t, 7, a)
    sg = sigs().multi_c if compact else E.API["transfer"]
    sr.send(t, E.cd(sg, [E.MULTI_T] + E.AUTH_T + [E.SV_T], a, VPROOF, auth(pq, frm, 7, st), b"", E.verdict(t, st, VPROOF)),
            f"{lab(t)} op 7{' compact' if compact else ''} {what}")


def unshield(pq, sr, t, frm, amount, rcp, seed):
    b = burn_args(t, frm, seed)
    st = stmt(t, 2, [b, amount, rcp])
    sr.send(t, E.cd(E.API["unshield"], [E.BURN_T, "w", "w"] + E.AUTH_T + [E.SV_T], b, amount, rcp, VPROOF, auth(pq, frm, 2, st),
                    b"", E.verdict(t, st, VPROOF)), f"{lab(t)} unshield {amount} by {frm.name}")


def unwrap_x(amount):
    return [S["leg"], E.pad(S["a3"]), amount, 0]


def unshield_unwrap(pq, sr, t, frm, amount, seed):
    b, x = burn_args(t, frm, seed), unwrap_x(amount)
    st = stmt(t, "unwrap", [b, x])
    sr.send(t, E.cd(E.API["unshieldUnwrap"], [E.BURN_T, E.UNWRAP] + E.AUTH_T + [E.SV_T], b, x, VPROOF, auth(pq, frm, 2, st), b"",
                    E.verdict(t, st, VPROOF)), f"{lab(t)} unshield-unwrap {amount} by {frm.name}")


def named(pq, sr, t, op, frm, build, what):
    """A named entry (forge `_named1` / `_named7` / `_namedUnshield` / `_namedUnwrap`): the holder's envelope on lane 20, the
    statement over its binding, `pqzAuth` and the envelope signed by the holder's ML-DSA key (clientkeys typed digest).
    `build()` gives (the op's parameters before the proof, the statement kind: 1, 7, 2 or "unwrap")."""
    e = env(frm.ua, 20, t, S["vu"])
    bnd = binding(t, e)
    p, kind = build()
    st = stmt(t, kind, p[0] if kind in (1, 7) else [p[0]] + p[1] if kind == 2 else p, bnd)
    pa = auth(pq, frm, kind if kind in (1, 7) else 2, st)
    pp = [p[0], VPROOF, pa, b""] if kind in (1, 7) else [p[0], p[1], VPROOF, pa, b""]
    d = E.typed_digest(op, at_of(t), e, pp)
    sr.send(t, E.named_cd(op, e, pp, E.ml_sig(pq, frm, E.P_METATX, d), E.verdict(t, st, VPROOF)), f"{lab(t)} named {op} {what}")


def shield(sd, t, h, amount):
    sd.send(t, M.cdx(sigs().shield, h.ua, amount), f"{lab(t)} shield {amount} to {h.name}")


def prepare(sd, t, h):
    for half in (0, 1):
        sd.send(t, M.cdx(sigs().prep, h.ua, 0, half), f"{lab(t)} mtxPrepareAcc({h.name}, {half})")


def acc_op(sd, sr, t, roll, h, x):
    """forge `_namedAccOp`: `mtxPrepareAcc` / `mtxRollOver` relayed, test key 1's native id signs (lane 21), key 2 sends."""
    op = "UARollOver" if roll else "UAPrepareAcc"
    e = env(E.pad(sd.addr), 21, t, S["vu"])
    p = [h.ua, 0, x]
    sr.send(t, E.named_cd(op, e, p, native(sd.key, E.typed_digest(op, at_of(t), e, p))), f"{lab(t)} named {op}({h.name}, {x})")


def lab(t):
    return S["label"].get(t, t[:10])


# ------------------------------------------------------------------ group pqzkeys, run 1 (PqzKeysSetup.setup)

def kinds_ok():
    fac = M.DEP["token_factory"]
    miss = [k for k in PQZ_KINDS if not (u(E.call(fac, E.cd("tokenKindEnabled(uint8)", ["w"], k))) and
                                         u(E.call(fac, E.cd("implementationOf(uint8,uint64)", ["w", "w"], k, 1))))]
    if miss:
        raise M.Stop(f"PQZ_KINDS_MISSING: kinds {miss} not released on the set's factory (deploy with DEPLOY_PQZ=1)")


def v_init(k1):
    """forge `_vInit`: the verifier EOA's key from test key 1 (it signs verdicts only, no funds)."""
    return int.from_bytes(E.kc(E.encs(["b", "w"], [b"scaas.onchain.pqzkeys.verifier", k1])), "big") % (2**128 - 1) + 1


def init(sd):
    vk = v_init(sd.key)
    E.VERIFIER[0] = types.SimpleNamespace(key=vk, addr=E.address(vk))
    S.update(vA=E.pad(E.VERIFIER[0].addr), vu=int(time.time()) + 86_400, label={}, a3=M.SENDERS[2].addr)


def g_pqzkeys(pq, sd, sr, s3):
    """PqzKeysSetup.setup() but `_pqOn` (the `tokens` group's), then after ROLL_AGE + 1 blocks PqzKeysRoll.roll()."""
    _bind()
    kinds_ok()
    init(sd)
    D = E.Deployer(sd)
    S["leg"] = D.deploy("MockERC20", E.encs(["b", "b", "w"], [b"Onchain PQZ leg", b"oPQL", 6]), src="Mocks", label="MockERC20")
    sd.send(S["leg"], E.cd("mint(address,uint256)", ["w", "w"], sd.addr, 10**18), "leg mint 1e18")
    S.update(holders(pq, sd, b"holder"))
    S["mu"] = msig(pq, sd, S["bob"], S["carol"])
    confidential(pq, sd, sr)
    registry_keys(pq, sd)
    for k in (4, 12):
        burner(pq, sd, sr, k)
    registry_negatives(pq, sd, sr)
    save()
    b0 = head()
    h = wait_roll(b0)
    M.say(f"roll wait over: block {h} ≥ {b0} + {E.ROLL_AGE + 1}")
    roll(pq, sd, sr, s3)
    save()


def confidential(pq, sd, sr):
    uaM, bob, carol, mu = S["uaM"], S["bob"], S["carol"], S["mu"]
    for nm, k, o, op in (("c2", 4, 0, 1), ("c3o", 4, 1, 1), ("c3", 4, 1, 0), ("t5", 5, 1, 0), ("t12", 12, 1, 0), ("t13", 13, 1, 0)):
        S[nm] = token(sd, k, o, op, nm)
    z = E.ZERO
    for h in (uaM, bob, carol):
        scoped(pq, sd, h, z, 0, True)  # class 2: the shared key with its opening KEM key
        scoped(pq, sd, h, S["c3o"], 0, True)
        for nm in ("c3", "t5", "t12", "t13"):
            scoped(pq, sd, h, S[nm], 0, False)
    reg = E.REG[0]
    E.check(u(view(reg, sigs().latest, bob.ua, S["c3o"])) == 0 and u(view(reg, "pqzScopedCount(address)", S["c3"])) == 3,
            "pqzScopedKeyLatest(bob, c3o) 0, pqzScopedCount(c3) 3")
    for i, nm in enumerate(("c2", "c3o", "c3", "t5", "t12", "t13")):
        life(pq, sd, sr, S[nm], i)
    scoped(pq, sd, mu, S["c3o"], 0, True)  # the msig's record with the opening KEM key, then a credit to it
    send1(pq, sr, S["c3o"], carol, op1(S["c3o"], carol, mu, 0x7F11), False, "carol → mu")
    for i, nm in enumerate(("c3", "t5", "t12", "t13")):
        named_life(pq, sd, sr, S[nm], 0x7A00 + 0x100 * i)
    for nm in ("t5", "t13"):
        wrap_shield(sd, sr, S[nm])
    rotation(pq, sd, sr)
    opening_kinds(pq, sd, sr)


def life(pq, sd, sr, t, i):
    """forge `_life`."""
    uaM, bob, carol = S["uaM"], S["bob"], S["carol"]
    s = 0x7C00 + 0x100 * i
    shield(sd, t, bob, 50)
    shield(sd, t, carol, 50)
    shield(sd, t, uaM, 100)
    send1(pq, sr, t, bob, op1(t, bob, uaM, s + 1), False, "bob → uaM")
    send1(pq, sr, t, carol, op1(t, carol, uaM, s + 11), False, "carol → uaM")
    send1(pq, sr, t, bob, op1(t, bob, uaM, s + 21), True, "bob → uaM")
    if opens(t):
        M.neg(sr.addr, t, E.cd(E.API["transfer"], [E.MULTI_T] + E.AUTH_T + [E.SV_T], op7(t, carol, bob, uaM, s + 41), VPROOF,
                               [b"", bytes(3309), []], b"", E.NO_VERDICT), err(IP, "OpUnsupported"), f"{lab(t)}: op 7 with the opening on")
    else:
        send7(pq, sr, t, carol, op7(t, carol, bob, uaM, s + 31), False, "carol → bob + uaM decoy")
        send7(pq, sr, t, carol, op7(t, carol, bob, uaM, s + 41), True, "carol → bob + uaM decoy")
    unshield(pq, sr, t, bob, 5, E.pad(S["a3"]), s + 51)
    unshield(pq, sr, t, bob, 0, E.ZERO32, s + 61)
    if lab(t) in ("t5", "t13"):
        unshield_unwrap(pq, sr, t, carol, 3, s + 71)
    if opens(t):  # bob's credit after his debits, then his TRIVIAL entry 2 (run 2's SkipTrivial negative)
        send1(pq, sr, t, carol, op1(t, carol, bob, s + 31), False, "carol → bob")
        shield(sd, t, bob, 10)
    prepare(sd, t, uaM)


def named_life(pq, sd, sr, t, s):
    """forge `_namedLife`: op 1 and compact, op 7 and compact, an unshield, an unshield-unwrap on a wrapped kind, a relayed
    shield and a relayed prepare."""
    uaM, bob, carol = S["uaM"], S["bob"], S["carol"]
    for compact, seed in ((False, s + 1), (True, s + 2)):
        def b1(compact=compact, seed=seed):
            a = op1(t, bob, uaM, seed)
            if compact:
                a[14] = blob(int.from_bytes(E.kc(a[7]), "big"), SEALED)
            return [a], 1
        named(pq, sr, t, "UAPqzTransferSingleCompact" if compact else "UAPqzTransferSingle", bob, b1, "bob → uaM")
    for compact, seed in ((False, s + 3), (True, s + 4)):
        def b7(compact=compact, seed=seed):
            a = op7(t, carol, bob, uaM, seed)
            if compact:
                a[12] = blob(int.from_bytes(E.kc(a[7]), "big"), 2 + 40 * len(a[10]))
            return [a], 7
        named(pq, sr, t, "UAPqzTransferCompact" if compact else "UAPqzTransfer", carol, b7, "carol → bob + uaM decoy")
    named(pq, sr, t, "UAPqzUnshield", bob, lambda: ([burn_args(t, bob, s + 5), [2, E.pad(S["a3"])]], 2), "bob 2 to key 3")
    if lab(t) in ("t5", "t13"):
        named(pq, sr, t, "UAPqzUnshieldUnwrap", carol, lambda: ([burn_args(t, carol, s + 6), unwrap_x(1)], "unwrap"), "carol 1")
    e = env(E.pad(sd.addr), 13, t, S["vu"])  # forge `_relayedShield`
    p = [bob.ua, 5]
    sr.send(t, E.named_cd("UAShield", e, p, native(sd.key, E.typed_digest("UAShield", at_of(t), e, p))), f"{lab(t)} named UAShield bob 5")
    acc_op(sd, sr, t, False, carol, 0)


def wrap_shield(sd, sr, t):
    """forge `_wrapShield`: direct, then relayed (the address envelope, lane 14)."""
    carol = S["carol"]
    sd.send(t, E.cd("mtxWrapShield(address,uint256,bytes32)", ["w", "w", "w"], S["leg"], 100_000, carol.ua), f"{lab(t)} mtxWrapShield direct")
    e = [sd.addr, 14, P.nonce(t, E.pad(sd.addr), 14), S["vu"], 0, E.ZERO, 0, E.ZERO]
    p = [S["leg"], 100_000, carol.ua]
    sr.send(t, E.named_cd("WrapShield", e, p, E.ecdsa(sd.key, E.typed_digest("WrapShield", at_of(t), e, p))), f"{lab(t)} mtxWrapShield relayed")


def rotation(pq, sd, sr):
    """forge `_rotation`: carol's scoped version 1 on c3, then her migration to herself from version 0 (op 1, KV-9)."""
    carol, c3 = S["carol"], S["c3"]
    scoped(pq, sd, carol, c3, 1, False)
    E.check(u(view(E.REG[0], sigs().latest, carol.ua, c3)) == 1, "pqzScopedKeyLatest(carol, c3) 1")
    send1(pq, sr, c3, carol, op1(c3, carol, carol, 0x7F01), False, "carol → carol (migration)")


def opening_kinds(pq, sd, sr):
    """forge `_openingKinds`: kinds 5, 12, 13 with the opening (class 3)."""
    uaM, bob = S["uaM"], S["bob"]
    for i, (nm, k) in enumerate((("o5", 5), ("o12", 12), ("o13", 13))):
        t = S[nm] = token(sd, k, 1, 1, nm)
        scoped(pq, sd, uaM, t, 0, True)
        scoped(pq, sd, bob, t, 0, True)
        shield(sd, t, bob, 50)
        shield(sd, t, uaM, 100)
        send1(pq, sr, t, bob, op1(t, bob, uaM, 0x7D01 + 0x10 * i), False, "bob → uaM")
        send1(pq, sr, t, bob, op1(t, bob, uaM, 0x7D02 + 0x10 * i), True, "bob → uaM")
        prepare(sd, t, uaM)


def registry_keys(pq, sd):
    """forge `_registryKeys` with a REAL key: carol's registry PQZ key at version 0 (`setPqzKey` over `pqzKeyRecordDigest`, then
    the real R_REG over `uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest(ua, h))` by `storePqzPop`, `proven` checked), bob's
    KEM key at version 1 (`setKemKey` over `kemRecordDigest`)."""
    reg, carol, bob = E.REG[0], S["carol"], S["bob"]
    pk, s_, e_, _ = K.keygen(E.kc(PRE, P.RUN, b"registry-key", carol.ua))
    kh = E.words(view(reg, sigs().key_hash, E.PQZ_MLWE, pk))[0]
    m = E.words(view(reg, sigs().ua_msg, E.PQZ_MLWE, E.kc("scaas.ua.purpose.pqz-key.v1"),
                     E.words(view(reg, "pqzKeyDigest(bytes32,bytes32)", carol.ua, kh))[0]))[0]
    proof = pq.prove(3, K.build_register(m, pk), K.i8(s_) + K.i16(e_))
    ph = E.kc(proof)
    rd = E.words(view(reg, "pqzKeyRecordDigest(bytes32,bytes32,bytes32)", carol.ua, kh, ph))[0]
    sd.send(reg, E.cd(E.SET_PQZ, E.SET_PQZ_T, carol.ua, 0, pk, ph, E.ml_sig(pq, carol, E.kc("scaas.ua.purpose.pqz-key.v1"), rd)),
            "setPqzKey carol v0")
    sd.send(reg, E.cd("storePqzPop(bytes32,uint64,bytes)", ["w", "w", "b"], carol.ua, 0, proof), f"storePqzPop carol v0 (R_REG {len(proof):,} B)")
    w = E.words(E.call(reg, E.cd("pqzKeyOf(bytes32)", ["w"], carol.ua)))
    E.check(w[2] == ph and int.from_bytes(w[3], "big") == int(rreg_on()), f"pqzKeyOf(carol): v0, proof hash, proven {int(rreg_on())}")
    k = [1, blob(0x4B45, 1568), E.kc("bob kem v1")]
    rd = E.words(view(reg, "kemRecordDigest(bytes32,uint64,(uint8,bytes,bytes32))", bob.ua, 1, k))[0]
    sd.send(reg, E.cd(E.SET_KEM, E.SET_KEM_T, bob.ua, 1, k, E.ml_sig(pq, bob, E.kc("scaas.ua.purpose.kem.v1"), rd)), "setKemKey bob v1")


def burner(pq, sd, sr, kind):
    """forge `_burnerPqz` (round 3zb): a BURNER token, class 2 with the opening; bob's unshield by key 2 is not gated, the
    seat's `burn(10)` lowers the supply; key 2's `burn` the negative `MissingRole(30, id)`."""
    bob = S["bob"]
    x = create(sd, kind, "Onchain PQZ burner", "oPQB", 1 << PAYABLE | 1 << BURNER, f"pqzkeys-burner{kind}", conf(0, 1),
               supply=10**15, roles=[0, 0, 0, 0, 0, E.pad(sd.addr)])
    S["label"][x] = f"burner{kind}"
    shield(sd, x, bob, 50)
    sd.send(x, E.cd("transfer(address,uint256)", ["w", "w"], sr.addr, 1000), f"burner{kind} transfer 1000 to key 2")
    ts = lambda: u(E.call(x, E.cd("totalSupply()", [])))  # noqa: E731
    s0 = ts()
    unshield(pq, sr, x, bob, 5, E.pad(S["a3"]), 0x7E00 + kind)
    E.check(ts() == s0 and u(E.call(x, E.cd("balanceOf(address)", ["w"], S["a3"]))) == 5 * 10_000,
            f"burner{kind}: the unshield not gated, supply kept, key 3 holds 50,000")
    data = E.cd("burn(uint256)", ["w"], 1)
    M.control(sd.addr, x, data, f"burner{kind} burn(1) by the seat")
    sd.send(x, E.cd("burn(uint256)", ["w"], 10), f"burner{kind} burn(10) by the seat")
    E.check(ts() == s0 - 10, f"burner{kind}: the seat's burn, supply -10")
    M.neg(sr.addr, x, data, err("IGovernance.sol/IGovernance", "MissingRole", BURNER, E.pad(sr.addr)),
          f"burn by a non-holder with a balance (kind {kind}, BURNER): MissingRole(30, id)")


def rec_call(pq, h, scope, signed_scope, kem, uid, vb, klen):
    """forge `_recCall` at `h`'s next version of `scope`: a filler key (a negative's), one thing changed by the caller."""
    v = u(view(E.REG[0], sigs().latest, h.ua, scope)) + 1
    key = filler_key(None if klen == K.PK_BYTES else klen)
    ph = E.kc(E.kc(E.encs(["w", "w", "w", "w"], [E.kc(P.RUN), h.ua, scope, v])))
    k = kem_of(h, scope, v) if kem else [0, b"", E.ZERO32]
    d, _ = rec_digest(h, scope, v, key, ph, k, vb, uid, signed_scope)
    return M.cdx(sigs().set_scoped, h.ua, scope, v, key, ph, k, vb, sig_by(pq, h, P.P_SCOPED, d))


def big_control(frm, to, data, what):
    """`M.control` at the block's gas limit: a record's two SSTORE2 writes (an 18 KB key and a 1.6 KB opening KEM key) cost
    ~30 M of EIP-8037 state gas, above `M.control`'s fixed 30 M (its CREATE runs out: `SSTORE2WriteFailed`)."""
    lim = int(E.rpc("eth_getBlockByNumber", ["latest", False])["gasLimit"], 16)
    try:
        E.rpc("eth_call", [{"from": frm, "to": to, "data": "0x" + data.hex(), "gas": hex(lim)}, "latest"])
        return E.check(True, f"control {what}: answers (gas {lim:,})")
    except RuntimeError as e:
        return E.check(False, f"control {what}: refused ({str(e)[:160]})")


def registry_negatives(pq, sd, sr):
    """forge `_registryNegatives`, each record negative beside its control (the same record with every field right)."""
    reg, uid, bob, mu, uaM = E.REG[0], E.CTX[1], S["bob"], S["mu"], S["uaM"]
    vb, pk, sib = vub(), K.PK_BYTES, E.kc("scaas.onchain.sibling-chain-word")
    z, c3o, c3, t5 = E.ZERO, S["c3o"], S["c3"], S["t5"]
    unauth = err(REGA, "UAUnauthorized", bob.ua)
    okem = lambda sc: err(REGA, "UAPqzOpenKem", sc)  # noqa: E731
    rows = [
        (bob, z, z, False, uid, vb, pk, okem(z), "class 2 record without openKem"),
        (bob, z, z, True, sib, vb, pk, unauth, "class 2 record signed for another chainUid"),
        (bob, z, z, True, uid, head() - 1, pk, err(REGA, "UAPqzRecordExpired", bob.ua), "class 2 record expired"),
        (bob, z, z, True, uid, vb, 16_384 if pk == 18_432 else 18_432, err(REGA, "UAKeyData", E.PQZ_MLWE),
         "class 2 version 1 of another key length"),
        (bob, c3o, c3o, False, uid, vb, pk, okem(c3o), "class 3 opening on: record without openKem"),
        (bob, c3o, c3o, True, sib, vb, pk, unauth, "class 3 opening on: another chainUid"),
        (bob, c3, c3, True, uid, vb, pk, okem(c3), "class 3 opening off: record with openKem"),
        (bob, c3, c3, False, sib, vb, pk, unauth, "class 3 opening off: another chainUid"),
        (bob, t5, c3, False, uid, vb, pk, unauth, "class 3: the record of another token"),
        (mu, z, z, True, uid, vb, pk, err(REGA, "UAPqzHolder", mu.ua), "class 2: an msig holds no shared key (ruling 9)"),
        (mu, c3o, c3o, False, uid, vb, pk, okem(c3o), "class 3 opening on: the msig's record without openKem"),
    ]
    done = set()
    for h, sc, ssc, kem, ud, v, kl, want, what in rows:
        if (h.name, sc) not in done and not (h is mu and sc == z):  # the control: this record with every field right
            big_control(sd.addr, reg, rec_call(pq, h, sc, sc, int(sc, 16) == 0 or sc == c3o, uid, vb, pk),
                        f"{h.name} record of {lab(sc) if sc != z else 'scope 0'}")
            done.add((h.name, sc))
        M.neg(sd.addr, reg, rec_call(pq, h, sc, ssc, kem, ud, v, kl), want, what)
    M.neg(sr.addr, S["c2"], M.cdx(sigs().roll, uaM.ua, 0, 1), err(IP, "RollOverSignedOnly"), "c2: the public rollover with the opening on")
    M.neg(sr.addr, c3o, M.cdx(sigs().roll, uaM.ua, 0, 1), err(IP, "RollOverSignedOnly"), "c3o: the public rollover with the opening on")
    M.neg(sr.addr, c3, M.cdx(sigs().roll_signed, uaM.ua, 0, 1, [], vb, [b"", bytes(3309), []]), err(IP, "OpUnsupported"),
          "c3: the signed rollover without the opening")
    ref = E.words(view(S["c2"], sigs().account, uaM.ua, 0))[8]  # any ref: the form is refused before the entry is read
    for form, nm in ((1, "RECEIVER_X"), (2, "AUDITOR")):
        M.neg(sr.addr, S["c2"], E.cd(E.API["discStmt"], ["w"] * 5, ref, 0, 1, form, 0), err(IP, "OpUnsupported"),
              f"c2: a {nm} disclosure with the opening on")


def save():
    d = {k: (v if isinstance(v, (str, int)) else "0x" + v.hex() if isinstance(v, bytes) else
             {"ua": "0x" + v.ua.hex(), **({"seed": "0x" + v.seed.hex()} if getattr(v, "seed", None) else {})})
         for k, v in S.items() if k != "label"}
    path = os.path.join(M.EVM, "deployments", f"mldsa-on-{M.NET}-state.json")
    with open(path, "w") as f:
        json.dump(d, f, indent=1)


# ------------------------------------------------------------------ the roll phase

def wait_roll(b0, n=None, limit=ROLL_WAIT_S, rpc=None, sleep=time.sleep, clock=time.monotonic):
    """Wait for ROLL_AGE + 1 new blocks after `b0` by polling eth_blockNumber, at most `limit` s (a named stop `ROLL_WAIT`);
    on chain 31337 (anvil) `evm_mine` them."""
    rpc = rpc or E.rpc
    want = b0 + (E.ROLL_AGE + 1 if n is None else n)
    if int(rpc("eth_chainId"), 16) == 31337:
        for _ in range(max(0, want - int(rpc("eth_blockNumber"), 16))):
            rpc("evm_mine")
    t0 = clock()
    while (h := int(rpc("eth_blockNumber"), 16)) < want:
        if clock() - t0 > limit:
            raise M.Stop(f"ROLL_WAIT: head {h} < {want} after {limit} s")
        sleep(1)
    return h


def roll_digest(t, h, n, skip, vb, entries_hash=None):
    """The holder's `PqzRollOver` digest (CTR-PQZ-41) by clientkeys: `rollSeq`, `rolled` from `pqzAccount`, `entriesHash` over
    the entries as read from the chain (`pqzEntryHash` of each slot and its blob's code)."""
    st = acct(t, h.ua)
    es = []
    for i in [st["rolled"] + k for k in range(n)] + list(skip):
        w = u(view(t, sigs().pending, h.ua, 0, i))
        code = E.rpc("eth_getCode", ["0x" + (w >> 96).to_bytes(20, "big").hex(), "latest"]) if (w >> 64) & 0xFFFF else "0x"
        es.append({"index": i, "slot": "0x" + w.to_bytes(32, "big").hex(), "code": code})
    uid = E.chain_word(t)
    at = {"name": domain_name(t), "contract": t, "chainId": E.CTX[0], "chainUid": uid}
    msg = {"ua": h.ua, "keyVersion": 0, "rollSeq": st["rollSeq"], "rolled": st["rolled"], "n": n, "skip": list(skip),
           "validUntilBlock": vb, "chainUid": uid}
    return ck("roll", at=at, message=msg, entries=es, **({"entriesHash": entries_hash} if entries_hash else {}))


def roll_sig(pq, t, h, n, skip, vb):
    return E.ml_sig(pq, h, E.P_ZAUTH, roll_digest(t, h, n, skip, vb))


def roll_cd(h, n, skip, vb, s):
    return M.cdx(sigs().roll_signed, h.ua, 0, n, list(skip), vb, s)


def skipped(t, h, i):
    return u(view(t, sigs().skipped, h.ua, 0, i)) == 1


def roll(pq, sd, sr, s3):
    """PqzKeysRoll.roll()."""
    uaM, bob = S["uaM"], S["bob"]
    for nm in ("c2", "c3o"):
        signed(pq, sd, sr, s3, S[nm])
    for nm in ("o5", "o12", "o13"):
        t, vb = S[nm], vub()
        sr.send(t, roll_cd(uaM, 3, [1], vb, roll_sig(pq, t, uaM, 3, [1], vb)), f"{nm} mtxRollOverSigned(uaM, 3, skip [1])")
    for nm in ("c3", "t5", "t12", "t13"):  # without the opening: one entry by the named form, the rest public
        t = S[nm]
        acc_op(sd, sr, t, True, uaM, 1)
        a = acct(t, uaM.ua)
        sr.send(t, M.cdx(sigs().roll, uaM.ua, 0, a["pendingCount"] - a["rolled"]), f"{nm} mtxRollOver(uaM, {a['pendingCount'] - a['rolled']})")
    send1(pq, sr, S["c2"], uaM, op1(S["c2"], uaM, bob, 0x7E01), False, "uaM → bob over the rolled acc")
    for nm, router in (("c3", False), ("t5", False), ("t12", False), ("t13", True)):
        owner_ops(sd, sr, S[nm], router)


def signed(pq, sd, sr, s3, t):
    """forge `_signed` + `_rollByAddress` + `_signedBob` on an opening token."""
    uaM, bob = S["uaM"], S["bob"]
    vb = vub()
    sr.send(t, roll_cd(uaM, 2, [2], vb, roll_sig(pq, t, uaM, 2, [2], vb)), f"{lab(t)} mtxRollOverSigned(uaM, 2, skip [2]) direct")
    E.check(skipped(t, uaM, 2) and not skipped(t, uaM, 1), f"{lab(t)}: uaM's entry 2 marked, 1 not")
    m = [E.pad(sd.addr), roll_cd(uaM, 1, [], vb, roll_sig(pq, t, uaM, 1, [], vb)), 15, P.nonce(t, E.pad(sd.addr), 15), S["vu"], 0, E.ZERO, 0, E.ZERO]
    d = E.words(E.call(t, E.cd(sigs().mtx_digest, [E.MTX], m)))[0]
    s3.send(t, E.cd(sigs().execute, [E.MTX, E.UASIG_T], m, native(sd.key, d)), f"{lab(t)} mtxExecute(mtxRollOverSigned(uaM, 1))")
    mt = [sd.addr, roll_cd(uaM, 1, [], vb, roll_sig(pq, t, uaM, 1, [], vb)), 16, P.nonce(t, E.pad(sd.addr), 16), S["vu"], 0, E.ZERO, 0, E.ZERO]
    d = ck("meta", at={"name": domain_name(t), "contract": t, "chainId": E.CTX[0], "chainUid": E.chain_word(t),
                       "message": dict(zip(["from", "data", "batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"], mt))})
    s3.send(t, E.cd(sigs().exec_meta, [E.MTX, "b"], mt, E.ecdsa(sd.key, d)), f"{lab(t)} executeMetaTransaction(mtxRollOverSigned(uaM, 1))")
    st = acct(t, uaM.ua)
    E.check(st["rolled"] == 4 == st["pendingCount"] and st["rollSeq"] == 3, f"{lab(t)}: uaM rolled 4 = pendingCount, rollSeq 3")
    # bob: mark only
    vb = vub()
    s = roll_sig(pq, t, bob, 0, [1], vb)
    r0 = acct(t, bob.ua)["rolled"]
    good = roll_cd(bob, 0, [1], vb, s)
    sr.send(t, good, f"{lab(t)} mtxRollOverSigned(bob, 0, skip [1]) mark only")
    E.check(skipped(t, bob, 1) and acct(t, bob.ua)["rolled"] == r0, f"{lab(t)}: bob's entry 1 marked, nothing rolled")
    M.neg(sr.addr, t, good, err(IP, "AuthRejected"), f"{lab(t)}: the mark-only call replayed (rollSeq moved)")
    # its control: the same mark signed over the state as it is now (rollSeq moved) answers
    M.control(sr.addr, t, roll_cd(bob, 0, [1], vb, roll_sig(pq, t, bob, 0, [1], vb)), f"{lab(t)}: bob's mark at the current rollSeq")
    stale = E.ml_sig(pq, bob, E.P_ZAUTH, roll_digest(t, bob, 0, [1], vb, entries_hash=E.kc("another entry")))
    M.neg(sr.addr, t, roll_cd(bob, 0, [1], vb, stale), err(IP, "AuthRejected"), f"{lab(t)}: a stale entriesHash")
    M.neg(sr.addr, t, roll_cd(bob, 0, [2], vb, roll_sig(pq, t, bob, 0, [2], vb)), err(IP, "SkipTrivial", 2),
          f"{lab(t)}: a mark on a TRIVIAL entry")


def owner_ops(sd, sr, t, router):
    """forge `_ownerOps`: bit 24 to the owner, then direct (or through the GovernanceRouter: key 1's native id signs, key 2
    sends) the verifier transfer proposed and cancelled, the proof store, the verifier fee, the revocation."""
    uid = E.chain_word(t)
    me = E.pad(sd.addr)
    sd.send(t, E.cd("grantRole(uint8,bytes32,bytes32)", ["w", "w", "w"], PQZ_PROOF, me, uid), f"{lab(t)} grantRole(PQZ_PROOF, owner)")
    a3 = E.pad(S["a3"])
    if not router:
        for sg, vs, what in (("pqzSetVerifier(bytes32,bytes32)", [a3], "pqzSetVerifier(key 3)"), ("pqzCancelVerifier(bytes32)", [], "pqzCancelVerifier"),
                             ("setProofStore(uint8,bytes32)", [1], "setProofStore(LOG)"), ("setProofStore(uint8,bytes32)", [0], "setProofStore(NONE)"),
                             ("setVerifierFee(uint64,bytes32)", [2], "setVerifierFee(2)"), ("setVerifierFee(uint64,bytes32)", [0], "setVerifierFee(0)"),
                             ("pqzRevokeVerifier(bytes32)", [], "pqzRevokeVerifier")):
            sd.send(t, M.cdx(sg, *vs, uid), f"{lab(t)} {what}")
    else:
        gr = M.DEP["governance_router"]
        ops = json.load(open(os.path.join(M.VEC, "typed/typed_ops.json")))["ops"]
        for op, vs in (("UAPqzSetVerifier", [a3]), ("UAPqzCancelVerifier", []), ("UASetProofStore", [1]), ("UASetVerifierFee", [2]),
                       ("UAPqzRevokeVerifier", [])):
            e = env(me, 0, gr, S["vu"])
            d = M.named(gr, ops[op]["typeString"], [t, *vs, uid], e)
            fn = "mtx" + op[2:]
            sr.send(gr, M.cdx(M.fsig("GovernanceRouter.sol/GovernanceRouter", fn), e, t, *vs, uid, native(sd.key, d)), f"{lab(t)} router {fn}")
    E.check(cfg_word(t, 1) == 0, f"{lab(t)}: the verifier revoked")
