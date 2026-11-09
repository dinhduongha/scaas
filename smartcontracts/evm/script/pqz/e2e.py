#!/usr/bin/env python3
"""P6g Tasks 7-8 (plan docs/superpowers/plans/2026-10-16-p6g-contracts.md, D7 / D15): deploy the PQZ contracts on
chain 7622 and run the e2e with REAL proofs. Python stdlib (python3 -I); P6f's eth.py (Keccak, RLP, secp256k1, legacy
EIP-155 transactions: calldata of 100-300 KB cannot pass cast's argv); pqz_kat.py (P6e) for KeyGen, Enc, Dec and the
witnesses; pqz-ffi's example `pqz_prove` (feature prove) for the proofs; `mldsa.mjs` (@noble/post-quantum 0.7.1) for the
ML-DSA signatures. Statements are always read from the token's own views, so the proofs cover exactly what the
contracts build.

Plan 5h Task 4a: the new token API (state redesign: pqzAccount views, accHint instead of acc / inline, proof-free shield,
rollover by count after mtxPrepareAcc, txFee / decoyFee to public balances, wallet restore from the views); the entry-point
names and signatures are the `API` table below (the shared `mtx*` interface of Task 3b).

typed-signing C8: `pqzAuth` is the typed `PqzAuth` of the statement (`K.auth_digest`, TS-D19) in a `UASig`; the signed forms are
the named entries (`NAMED`: `UAEnvelope` first, the op's explicit parameters, the entry's own typed struct from clientkeys,
sections 5b and 6b; ua-mtx-merge R1, R47: one merged `mtx<entry>` per op over the `UA` struct for every subject, an EOA by its
own key in `UASig.signature`, `WrapShield` alone on an address `Envelope`), the generic `mtxExecute(UAMetaTransaction, UASig)`
of section 5 stays as the path of an op without one (TS-D14); `UARegistryCoreLib` and `UARegistryAuxLib` are linked and deployed with the registry; one PQZ holder is an msig (`registerMsig`, `UASig.members`).
It needs the `PQZ` and ML-DSA precompiles, so a chain run waits for the next reset; `--self-test` is what runs without one.

Plan 5h Task 8d part 2: the parameter set is pqz_kat's (PQZ_SET, default n2304-kmax4096; the contracts must be built at
the same set, smartcontracts/evm/script/pqz/at-set.sh, and the node's library too): its vectors (self-test hash, the
R_REG probe), sizes and offsets. Stored ciphertexts are packed at PACK_BITS = ceil(log2 q) (P46): the op blobs
(`pqzEntryBlob`) and the hint (the packed `acc` stream) are compared in that form (`pack`).

Group 3f (PQZ verifier mode spec 2026-11-06-attested-verify.md §3, §5): every proof-carrying entry takes a `PqzSignedVerdict`
last (`verdict`: empty on a PRECOMPILE token, which ignores it); `--zero-dep` publishes the PQZ releases on `deps = [0x0]` (C6)
and creates the PQZ tokens OFFCHAIN with the deployer EOA as their transferable verifier, which signs a `PqzVerdict` per proof.

  e2e.py --rpc http://127.0.0.1:8545 --log runs/2026-10-16-p6g-7622.txt [--keys 1,2,3] [--zero-dep]
  (a redeploy writes a new log, e.g. runs/2026-10-17-ua-index-7622.txt; it also checks the registry's per-kind list)
  e2e.py --self-test  (no chain: portable messages, registry arguments and calldata against portable.json, every named entry
                       against typed_ops.json, the verdict digest against pqz/verdict.json, every signature and its encoder
                       against the built ABI in out/)

Deploying contracts and sending transactions only: the node is not touched. Gas price 2·baseFee + 1 gwei (baseFee +
tip). Test keys of the 7622 genesis (0x…01–0x…03). Exit 0 iff every check passed."""
import argparse
import ast
import json
import os
import re
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.abspath(os.path.join(HERE, "../.."))
ROOT = os.path.abspath(os.path.join(EVM, "../.."))
sys.path.insert(0, os.path.join(ROOT, "pqz-core/nethermind/chain"))
sys.path.insert(0, os.path.join(ROOT, "smartcontracts/vectors/pqz"))
from eth import _mul, address, keccak256, legacy_tx, sign  # noqa: E402
import pqz_kat as K  # noqa: E402

PQZ = "0x000000000000000000000000000000005caa0f01"
ML44 = "0x000000000000000000000000000000005caa0012"
ML65 = "0x000000000000000000000000000000005caa0013"
PQZL_ID = K.PQZL_ID
SCALE, MAXS, FEE = 10_000, 1 << 40, 3
MIN_DECOY, DEC_FEE = 1, 2  # the tokens' minDecoyFee (plan 5h fee ruling) and the decoyFee this run puts in op 7 payloads
ROLL_AGE = 5  # PqzCore.ROLL_AGE: an entry rolls up at block_i + ROLL_AGE
SHIELD_POOL = "0x" + keccak256(b"scaas.shield.pool.v1")[12:].hex()
MLDSA44, MLDSA65, PQZ_MLWE, SECP256K1, MSIG = 0x0130, 0x0131, 0x0142, 0x0108, 0x0120
# CAP_PQZ: the registry's verify cap for the PQZ key's R_REG proof; it must cover the precompile's register row + 3 per
# input word + the verifier (plan 5h Task 8d part 2b: PQZL 3.62-3.67 M at the four sets, 3,634,962 at n2304-kmax4096's
# provisional row 3,504,000, test PqzStatePinGasTest.test_gasTable_pqzl; 3,000,000 refused every PQZ key registration
# under those rows). PQZL only: a PQZH registry needs >= 5.1 M (its verifyPop 4.82-5.03 M)
CAP_ML, CAP_PQZ, BUDGET = 200_000, 4_500_000, 12_000_000
FAILS, LOG = [], []
RPC = None
SPLIT = False  # --split: force the register + storePqzPop path
ZERO_DEP = False  # --zero-dep: the PQZ releases on deps = [0x0], the PQZ tokens OFFCHAIN (group 3f, spec §3 C6)
PROOF_PATH_ONLY = False  # --proof-path-only: sections 1-3, then section 7 (group 3h T65)
SKIP_KINDS = set()  # --skip-kind 13: a release this chain cannot deploy (kind 13 above 64 KiB until T66b on a 100 M RPC gas cap)
PROOF_STORE = 0  # --proof-store log: the PQZ tokens created with proofStore LOG (group 3h T60, pqz-proof-path spec §4.1)
VERDICT_LIFE = 600  # a verdict's `validUntil`: now + this many seconds (the verifier's own short life, spec §5.1)
# DeployBase's deterministic CREATE2 deployer (forge-std CREATE2_FACTORY, NET-EVM-05) and salt (`DEPLOY_SALT` env, default
# keccak256("scaas.deploy.v1")): the GovernanceRouter goes the same way (governance spec §3.1)
CREATE2_DEPLOYER = "0x4e59b44847b379578588920ca78fbf26c0b4956c"
DEPLOY_SALT = bytes.fromhex(os.environ["DEPLOY_SALT"].removeprefix("0x")) if os.environ.get("DEPLOY_SALT") \
    else keccak256(b"scaas.deploy.v1")


def create2_address(deployer, salt, init):
    """EIP-1014: keccak256(0xff ‖ deployer ‖ salt ‖ keccak256(init))[12:]."""
    return "0x" + keccak256(b"\xff" + bytes.fromhex(deployer[2:]) + salt + keccak256(init))[12:].hex()


def pack(b):
    """P46 (owner 2026-10-21): 64-bit-lane PQZ bytes (be8 coefficients < q) as the token stores them, every coefficient
    in PACK_BITS = ceil(log2 q) bits, big-endian, four per PACK_BITS / 2 bytes"""
    bits = K.Q.bit_length()
    x, n = 0, len(b) // 8
    for i in range(n):
        x = x << bits | int.from_bytes(b[8 * i:8 * i + 8], "big")
    return x.to_bytes(n * bits // 8, "big")


def probe(n):
    """`out` of n bytes with every 64-bit lane 1: canonical and no zero u group (the views refuse a zero u, ZeroU), so a
    statement view called with it returns T, which does not depend on `out`."""
    return (bytes(7) + b"\1") * (n // 8)


def pqz_key(ua):
    """A holder's PQZ key as the token reads it (UA-8 UA8-D9, `PqzCore._keyPtr`): `pqzKeyOf(ua)` = (current version, SSTORE2
    pointer, proof hash, proven) (group 3g), a proven key only (`recordOf` lists unproven keys too); the key is the pointer's
    code after its leading 0x00. `keyOf` is the UA's signing key."""
    w = words(call(REG[0], cd("pqzKeyOf(bytes32)", ["w"], ua)))
    assert int.from_bytes(w[3], "big") == 1, f"pqz_key: {ua.hex()[:16]}… has no proven PQZ key"
    ptr = "0x" + w[1][12:].hex()
    k = bytes.fromhex(rpc("eth_getCode", [ptr, "latest"])[2:])[1:]
    assert len(k) == K.PK_BYTES, f"pqz_key: {len(k)} B at {ptr}, want {K.PK_BYTES} (a UA without a PQZ key?)"
    return k


def hb(s):
    return bytes.fromhex(s[2:])


def kc(*parts):
    return keccak256(b"".join(p if isinstance(p, bytes) else p.encode() for p in parts))


def pad(a):
    """A native id: the address zero-padded to `bytes32` (`MetaTxLib.pad`)."""
    return bytes(12) + bytes.fromhex(a[2:])


P_METATX, P_ZAUTH, P_MEMBER, P_VERDICT = (kc(f"scaas.ua.purpose.{n}.v1") for n in ("metatx", "zether-auth", "member", "pqz-verdict"))
MSG_TAG = kc("scaas.ua.msg.v1")
TAG = {MLDSA44: kc("scaas.ua.mldsa44.v1"), MLDSA65: kc("scaas.ua.mldsa65.v1"), SECP256K1: kc("scaas.ua.secp256k1.v1"), PQZ_MLWE: kc("scaas.ua.pqz-mlwe.v1"),
       MSIG: kc("scaas.ua.msig.v1")}


# ------------------------------------------------------------------ UA-8 registration (portable PoP, UAAttrs) on the
# registry's explicit ABI (typed-signing R1: KemKey, UAAttrs without a KEM version, UASig; the register KEM key is version 0)
KEM_S, KEM_T = "(uint8,bytes,bytes32)", ("t", ["w", "b", "w"])  # KemKey{scheme, mlkemEk, x25519}
MEMBER_S, MEMBER_T = "(uint16,(uint16,bytes)[],bytes)", ("t", ["w", ("a", ("t", ["w", "b"])), "b"])  # MemberSig{index, InnerSig[] members, sig}; this file signs flat, a typed_ops row may hold a list
UASIG_S, UASIG_T = f"(bytes,bytes,{MEMBER_S}[])", ("t", ["b", "b", ("a", MEMBER_T)])  # keyData, signature, MemberSig[]
ATTRS_S, ATTRS_T = f"(bytes,bytes32,{KEM_S},bytes32)", ("t", ["b", "w", KEM_T, "w"])  # UAAttrs{pqzKey, pqzPopHash, kem, kemPkHash}
REGISTER = f"register(uint16,bytes,{ATTRS_S},bytes,bytes)"
REGISTER_T = ["w", "b", ATTRS_T, "b", "b"]  # kind, keyData, attrs, pop, pqzPop
REGISTER_MSIG = f"registerMsig((uint16,(uint16,bytes32,uint16)[]),{ATTRS_S},{MEMBER_S}[],bytes)"
REGISTER_MSIG_T = [("t", ["w", ("a", ("t", ["w", "w", "w"]))]), ATTRS_T, ("a", MEMBER_T), "b"]  # MsigStructure, attrs, MemberSig[], pqzPop
SET_KEM, SET_KEM_T = f"setKemKey(bytes32,uint64,{KEM_S},{UASIG_S})", ["w", "w", KEM_T, UASIG_T]
SET_PQZ, SET_PQZ_T = f"setPqzKey(bytes32,uint64,bytes,bytes32,{UASIG_S})", ["w", "w", "b", "w", UASIG_T]  # group 3g: + version
REQ_AUTH, REQ_AUTH_T = f"requireAuthorized(bytes32,bytes32,bytes32,{UASIG_S})", ["w", "w", "w", UASIG_T]
# clientkeys (with its node_modules): this checkout's, else the main checkout's (as `PQ`)
CK = (os.path.join(ROOT, "clients/clientkeys") if os.path.isdir(os.path.join(ROOT, "clients/clientkeys/node_modules"))
      else os.path.join(ROOT, "../../../clients/clientkeys"))
# the arguments come on stdin (a proof is over argv's 128 KiB per-argument limit)
_PORTABLE_JS = """
const U = await import(process.argv[1] + '/src/ua.js'), B = await import(process.argv[1] + '/src/bytes.js'), E = await import(process.argv[1] + '/src/evm.js');
const a = JSON.parse((await import('node:fs')).readFileSync(0, 'utf8')), h = (k) => (a[k] === undefined ? undefined : B.fromHex(a[k]));
const o = { ua: h('ua'), pqzKey: h('pqzKey'), kemPk: h('kemPk') };
if (a.fn === 'args') {
  const r = U.registrationArgs({ kind: a.kind, keyData: h('keyData'), pqzKey: o.pqzKey, pqzPop: h('pqzPop'), kemPk: o.kemPk,
    pop: Array.isArray(a.pop) ? a.pop : h('pop'), kemCommit: a.kemCommit });
  console.log(JSON.stringify({ ...r, length: U.registryCalldataLength(r.entry, r.args) }));
} else console.log(B.hex(a.fn === 'typed' ? E.hashTypedData(E.OP_BUILDERS[(a.op === 'UARollOver' ? 'uaPqzRollOver' : a.op.replace(/^UA/, 'ua').replace(/^[A-Z]/, (c) => c.toLowerCase())) + 'TypedData'](a.at))
  : a.fn === 'msig' ? U.encodeMsig(a.threshold, a.members)
  : a.fn === 'reg' ? U.pqzRegMessage({ ...o, kind: a.kind })
  : a.fn === 'kem' ? U.kemRecordMessage(a.kind, { ua: o.ua, version: a.kemVersion, kemPk: o.kemPk })
  : a.fn === 'keyreg' ? U.uaMessage(0x0142, U.PQZ_KEY_TAG, U.pqzKeyDigest({ ua: o.ua, pqzKeyHash: U.keyHashOf(0x0142, o.pqzKey) }))
  : a.fn === 'keyrec' ? U.pqzKeyRecordMessage(a.kind, { ua: o.ua, pqzKey: o.pqzKey, pqzPopHash: h('pqzPopHash') }).message
  : a.fn === 'keyverreg' ? U.uaMessage(0x0142, U.PQZ_KEY_TAG, U.pqzKeyVersionDigest({ ua: o.ua, version: a.version, pqzKeyHash: U.keyHashOf(0x0142, o.pqzKey) }))
  : a.fn === 'keyverrec' ? U.uaMessage(a.kind, U.PQZ_KEY_TAG, U.pqzKeyVersionRecordDigest({ ua: o.ua, version: a.version,
    pqzKeyHash: U.keyHashOf(0x0142, o.pqzKey), pqzPopHash: h('pqzPopHash') }))
  : U.holderPopMessage(a.kind, { ...o, keyData: h('keyData'), pqzPopHash: h('pqzPopHash') })[a.fn === 'popmd' ? 'memberDigest' : 'message']));
"""


def _ck(fn, **a):
    a = {k: v.hex() if isinstance(v, bytes) else v for k, v in dict(a, fn=fn).items()}
    out = subprocess.run(["node", "--input-type=module", "-e", _PORTABLE_JS, "--", CK], input=json.dumps(a),
                         capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(f"clientkeys {fn}: {out.stderr.strip()[-600:]}")
    return out.stdout.strip()


def portable(fn, **a):
    """The portable message from clients/clientkeys (ua.js): fn 'pop' = `holderPopMessage(kind, ...).message` (what the
    UA's `pop` signs, UA-8 P1), fn 'reg' = `pqzRegMessage({ua, kind, pqzKey, kemPk})` (what R_REG proves over, `kind` the
    registering kind), fn 'kem' = `kemRecordMessage` (`setKemKey`'s sig), fn 'keyrec' = `pqzKeyRecordMessage(...).message`
    (`setPqzKey`'s sig), fn 'keyreg' = `uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest(ua, keyHash(0x0142, pqzKey)))` (what a
    later key's R_REG proves over), fn 'popmd' = the PoP's `memberDigest` (what an msig's members sign), fn 'msig' = `encodeMsig`
    (the structure's key data). bytes arguments go as hex."""
    return hb(_ck(fn, **a))


def reg_args(kind, keyData, **a):
    """clientkeys `registrationArgs` (typed-signing R1) + `length` (`registryCalldataLength`): `{entry, args, kemFill,
    length}`; the KEM key in full, or the hash commit + `kemFill` (`setKemKey(ua, 0, kem, UASig())`) when the full call is
    over one transaction's calldata (or `kemCommit=True`). `register` or, kind 0x0120, `registerMsig` with `pop` the member
    signatures `[{index, sig}]`: this script registers no WebAuthn / MuSig2 / FROST UA."""
    return json.loads(_ck("args", kind=kind, keyData=keyData, **a))


def kem_v(k):
    """A clientkeys `KemKey` JSON as ABI values."""
    return [k["scheme"], hb(k["mlkemEk"]), hb(k["x25519"])]


def kem_key(kem):
    """`KemKey{scheme, mlkemEk, x25519}` of the assembled `scheme ‖ ek ‖ x25519`."""
    return [kem[0], kem[1:-32], kem[-32:]]


def sig_v(s):
    """A clientkeys `UASig` JSON as ABI values."""
    return [hb(s["keyData"]), hb(s["signature"]), [[m["index"], [[x["index"], hb(x["sig"])] for x in m["members"]], hb(m["sig"])] for m in s["members"]]]


def attrs_v(t):
    """A clientkeys `UAAttrs` JSON as ABI values."""
    return [hb(t["pqzKey"]), hb(t["pqzPopHash"]), kem_v(t["kem"]), hb(t["kemPkHash"])]


def register_cd(a, pqzPop=None):
    """`register` calldata from `reg_args(...)["args"]`; `pqzPop=b""` for the split path (proof by `storePqzPop`)."""
    return cd(REGISTER, REGISTER_T, a["kind"], hb(a["keyData"]), attrs_v(a["attrs"]), hb(a["pop"]),
              hb(a["pqzPop"]) if pqzPop is None else pqzPop)


def register_msig_cd(a, pqzPop=None):
    """`registerMsig` calldata, the same split as `register_cd`."""
    s = a["structure"]
    return cd(REGISTER_MSIG, REGISTER_MSIG_T, [s["threshold"], [[m["kind"], hb(m["id"]), m["weight"]] for m in s["members"]]],
              attrs_v(a["attrs"]), [[m["index"], [], hb(m["sig"])] for m in a["pop"]],
              hb(a["pqzPop"]) if pqzPop is None else pqzPop)


def kem_of_ret(h):
    """`kemKeyOf` return data `(uint64 version, KemKey kem, bytes sig)` as (version, assembled key, sig); the empty key
    (scheme 0, no ek, x25519 0) as b""."""
    b = hb(h)
    u = lambda o: int.from_bytes(b[o:o + 32], "big")  # noqa: E731
    k = u(32)
    e = k + u(k + 32)
    kem = b[k + 31:k + 32] + b[e + 32:e + 32 + u(e)] + b[k + 64:k + 96]
    return u(0), b"" if kem == bytes(33) else kem, dec_bytes(h, 2)


def full_register_fits(to, data):
    """The chain decides: `eth_estimateGas` of the FULL register (proof in the call) against the latest block gas limit
    (no margin: Sender.send adds its own 15 % + 50 k to the estimate and caps the limit at the block's). The node refuses
    an estimate above its block gas limit / RPC gas cap, so an error also means: register without the proof."""
    try:
        est = int(rpc("eth_estimateGas", [{"to": to, "data": "0x" + data.hex()}]), 16)
    except RuntimeError:
        return False
    # 1023/1024: the next block's limit may step down by that much, and a block-sized tx would wait for it.
    return est <= int(rpc("eth_getBlockByNumber", ["latest", False])["gasLimit"], 16) * 1023 // 1024


# ------------------------------------------------------------------ the token API in one place (plan 5h Task 3b, spec
# §5.11; typed-signing C4: the explicit parameters of Appendix X.3, `(args, proof, pqzAuth, accHint)`). Checked against the built
# ABI (`abi_check`); the signed forms are `NAMED`.
# group 3g T52: `uint64 keyVersion` after `fromUA` in the three args structs; group 3h T59: `bytes32 ownTag` after `salt` (op 1,
# op 7) and after `beneficiaryUA` (the burn forms)
TRANSFER_S = "(uint64,uint256,uint256,bytes32,uint64,bytes32,bytes32,bytes16,bytes32,bytes,bytes,bytes,bytes,bytes)"  # IPqzToken.PqzTransferArgs
TRANSFER_T = ("t", ["w"] * 9 + ["b"] * 5)
MULTI_S = "(uint64,uint256,uint256,bytes32,uint64,bytes32,uint256,bytes16,bytes32,bytes[],(bytes32,bytes,bytes)[],bytes,bytes)"  # PqzMultiArgs, PqzLeg
MULTI_T = ("t", ["w"] * 9 + [("a", "b"), ("a", ("t", ["w", "b", "b"])), "b", "b"])
BURN_S = "(uint64,uint256,uint256,bytes32,uint64,bytes32,bytes32,bytes,bytes)"  # PqzBurnArgs
BURN_T = ("t", ["w"] * 7 + ["b", "b"])
AUTH_S, AUTH_T = f"bytes,{UASIG_S},bytes", ["b", UASIG_T, "b"]  # proof, pqzAuth, accHint: after the op's own parameters
# group 3f (spec §5.1, §5.3): `PqzSignedVerdict{PqzVerdict pqzVerdict; UASig sig}`, last on every proof-carrying entry (direct:
# after `accHint`; signed: after `auth`); PqzVerdict(token, chainId, proofSystemId, statementHash, proofHash, pqzVerifierEpoch,
# validUntil). The empty one (every field 0, an empty `UASig`) on a PRECOMPILE token, which never reads it.
SV_S = f"((address,uint256,bytes32,bytes32,bytes32,uint32,uint64),{UASIG_S})"
SV_T = ("t", [("t", ["w"] * 7), UASIG_T])
NO_VERDICT = [[0] * 7, [b"", b"", []]]
VERDICT_TYPEHASH = kc("PqzVerdict(address token,uint256 chainId,bytes32 proofSystemId,bytes32 statementHash,bytes32 proofHash,"
                      "uint32 pqzVerifierEpoch,uint64 validUntil)")
UNWRAP_S = "(address,bytes32,uint256,uint256)"  # IConfidentialWrappedToken.Unwrap(underlying, recipient, amount, minOut), a calldata struct
UNWRAP = ("t", ["w", "w", "w", "w"])
API = dict(
    shield="mtxShield(bytes32,uint256)",
    wrapShield="mtxWrapShield(address,uint256,bytes32)",
    transfer=f"mtxConfidentialTransfer({MULTI_S},{AUTH_S},{SV_S})",  # op 7 (M legs)
    transferSingle=f"mtxConfidentialTransferSingle({TRANSFER_S},{AUTH_S},{SV_S})",  # op 1
    unshield=f"mtxUnshield({BURN_S},uint256,bytes32,{AUTH_S},{SV_S})",  # amount, recipient id (zero-padded address = native)
    unshieldUnwrap=f"mtxUnshieldUnwrap({BURN_S},{UNWRAP_S},{AUTH_S},{SV_S})",
    rollOver="mtxRollOver(bytes32,uint64,uint256)",  # group 3g T52: (ua, keyVersion, n), (ua, keyVersion, half)
    prepareAcc="mtxPrepareAcc(bytes32,uint64,uint256)",
    # views (names kept by 3b); the recipient word of the burn statements is a bytes32 id since UA-5c (b)
    burnStmt=f"burnStatement({BURN_S},uint256,bytes32,bytes32)",
    unwrapStmt=f"unshieldUnwrapStatement({BURN_S},{UNWRAP_S},bytes32)",
    singleStmt=f"transferSingleStatement({TRANSFER_S},bytes32)",
    multiStmt=f"transferStatement({MULTI_S},bytes32)",
    discStmt="disclosureStatement(bytes32,uint256,uint256,uint8,uint64)",  # group 3g T53: + keyVersion
    verifyAmt="verifyTransferAmount(bytes32,uint256,uint256,uint8,uint64,bytes)",  # PRECOMPILE (OFFCHAIN: PqzVerdictRequired)
    verifyAmtV=f"verifyTransferAmount(bytes32,uint256,uint256,uint8,uint64,bytes,{SV_S})",  # group 3f, spec §5.4
    # events carrying the entry reference as topic 1 (as built, IConfidentialToken; only topic 0 is looked up here)
    ev_single=["ConfidentialTransfer(bytes32,bytes32,bytes32,bytes32,uint256,uint64,address)"],
    ev_multi=["ConfidentialTransferMulti(bytes32,bytes32,bytes32,uint256,uint64,bytes32[],uint8,address)"],
)
ACCT = ["pendingCount", "rolled", "floor", "cleared", "accBlob", "accUnits", "flags", "sendCounter", "accHash", "lastDebit"]  # pqzAccount (3h T58: lastDebit)

# The named signed entries (TS-D14, TS-D16, Appendix X.3): `mtx<entry>` / `ua<entry>`(Envelope, the op's parameters, sig). op (the
# struct, its twin "UA" + op) -> (entry, the parameters' ABI, their encoders, the struct's fields from the parameters). `pqzAuth`
# is a parameter and never in a struct: `args`, `proof`, `accHint` hash in (TS-D17).
EVL_S, UEVL_S = "(address,uint256,uint256,uint256,uint32,address,uint256,address)", "(bytes32,uint256,uint256,uint256,uint32,address,uint256,address)"
EVL_T = ("t", ["w"] * 8)
EVL_F = "from batch nonce validUntil mode relayer fee feeRecipient".split()
TRANSFER_F = "p validUntilBlock shieldIn fromUA keyVersion toUA beneficiaryUA salt ownTag u vTo vFrom vAuditor sealedMemo".split()
MULTI_F = "p validUntilBlock shieldIn fromUA keyVersion beneficiaryUA decoyFee salt ownTag u legs vFrom sealedMemo".split()
BURN_F = "p validUntilBlock shieldIn fromUA keyVersion beneficiaryUA ownTag u vFrom".split()
# group 3h T59 (pqz-proof-path spec §3.1): the holder's tag of its own debit; the contract checks no value, so this script sends
# the zero tag (ponytail: T65 computes each debit's from the holder's seed, `ownTag` of clients/clientkeys)
OWN_TAG = bytes(32)
# group 3h T65, another set (spec §11.4): the contracts as built by `at-set.sh <set> build` (EVM_OUT=out/at-set-<set>), the
# prover built at that set (PQZ_PROVE=<path>), PQZ_SET for pqz_kat
OUT_DIR = os.environ.get("EVM_OUT", "out")
PROVEN = []  # group 3h T65: (op, statement, proof) of every proof this run made, in order


def tail_of(blob):
    """Group 3h C5: an op blob's tail `ownTag(32) ‖ kv(8·n) ‖ u8(n)`, read from its last byte: (the bytes before it, ownTag, kv)."""
    n = blob[-1]
    kv = [int.from_bytes(blob[len(blob) - 1 - 8 * (n - i):len(blob) - 1 - 8 * (n - i - 1)], "big") for i in range(n)]
    return blob[:len(blob) - 33 - 8 * n], blob[len(blob) - 33 - 8 * n:len(blob) - 1 - 8 * n], kv
UNWRAP_F = "underlying recipient amount minOut".split()
ZERO = "0x" + "00" * 20
ZERO32 = bytes(32)


def struct(names, vals):
    """A positional args list as the typed struct: `salt` is a `bytes16` (its ABI word is left-aligned), a leg a `PqzLeg`."""
    d = dict(zip(names, vals))
    if "salt" in d:
        d["salt"] = d["salt"][:16]
    if "legs" in d:
        d["legs"] = [dict(zip(("ua", "v", "vAuditor"), x)) for x in d["legs"]]
    return d


def flat(*names):
    return lambda p: dict(zip(names, p))


def conf(names):
    return lambda p: dict(args=struct(names, p[0]), proof=p[1], accHint=p[3])


NAMED = dict(
    Shield=("Shield", "bytes32,uint256", ["w", "w"], flat("toUA", "amount")),
    WrapShield=("WrapShield", "address,uint256,bytes32", ["w", "w", "w"], flat("underlying", "amountIn", "toUA")),
    # group 3g T52 (KV-10): the PQZ rollover and prepare name the key version (typed_ops.json's `UAPqzRollOver` row)
    RollOver=("RollOver", "bytes32,uint64,uint256", ["w", "w", "w"], flat("ua", "keyVersion", "n")),
    PrepareAcc=("PrepareAcc", "bytes32,uint64,uint256", ["w", "w", "w"], flat("ua", "keyVersion", "half")),
    PqzTransferSingle=("ConfidentialTransferSingle", f"{TRANSFER_S},{AUTH_S}", [TRANSFER_T] + AUTH_T, conf(TRANSFER_F)),
    PqzTransferSingleCompact=("ConfidentialTransferSingleCompact", f"{TRANSFER_S},{AUTH_S}", [TRANSFER_T] + AUTH_T, conf(TRANSFER_F)),
    PqzTransfer=("ConfidentialTransfer", f"{MULTI_S},{AUTH_S}", [MULTI_T] + AUTH_T, conf(MULTI_F)),
    PqzTransferCompact=("ConfidentialTransferCompact", f"{MULTI_S},{AUTH_S}", [MULTI_T] + AUTH_T, conf(MULTI_F)),
    # `Payout` in the call (one `calldata` struct), `amount` and `recipient` flat in the signed struct
    PqzUnshield=("Unshield", f"{BURN_S},(uint256,bytes32),{AUTH_S}", [BURN_T, ("t", ["w", "w"])] + AUTH_T,
                 lambda p: dict(args=struct(BURN_F, p[0]), amount=p[1][0], recipient=p[1][1], proof=p[2], accHint=p[4])),
    PqzUnshieldUnwrap=("UnshieldUnwrap", f"{BURN_S},{UNWRAP_S},{AUTH_S}", [BURN_T, UNWRAP] + AUTH_T,
                       lambda p: dict(args=struct(BURN_F, p[0]), unwrap=struct(UNWRAP_F, p[1]), proof=p[2], accHint=p[4])),
)


# The ops this script signs (ua-mtx-merge R1): each `UA` struct, for every subject, and `WrapShield` (no twin, Q2a: an address
# `Envelope`, native only).
BUILT = ["UA" + op for op in NAMED if op != "WrapShield"] + ["WrapShield"]


def named_sig(op):
    """The merged entry of `op`: `mtx<entry>(UAEnvelope, the op's parameters, UASig auth)` (R47: `mtxShield` too), a
    proof-carrying one (`UAPqz*`) with `PqzSignedVerdict` after `auth` (group 3f), or for `WrapShield`
    `mtxWrapShield(Envelope, …, bytes sig)`."""
    name, s, _, _ = NAMED[op.removeprefix("UA")]
    if not op.startswith("UA"):
        return f"mtx{name}({EVL_S},{s},bytes)"
    return f"mtx{name}({UEVL_S},{s},{UASIG_S}{f',{SV_S}' if op.startswith('UAPqz') else ''})"


def named_cd(op, e, p, sig, sv=NO_VERDICT):
    """The calldata of the named entry of `op` (`named_sig`); `sig` a `UASig`, `bytes` for `WrapShield`; `sv` the
    `PqzSignedVerdict` of a proof-carrying entry."""
    ts, vs = [EVL_T] + NAMED[op.removeprefix("UA")][2] + [UASIG_T if op.startswith("UA") else "b"], [e, *p, sig]
    if op.startswith("UAPqz"):
        ts, vs = ts + [SV_T], vs + [sv]
    return cd(named_sig(op), ts, *vs)


def js(v):
    """ABI values as clientkeys JSON."""
    if isinstance(v, dict):
        return {k: js(x) for k, x in v.items()}
    if isinstance(v, list):
        return [js(x) for x in v]
    if isinstance(v, bytes):
        return "0x" + v.hex()
    return str(v) if isinstance(v, int) else v


def typed_digest(op, at, e, p):
    """The digest of the entry's struct from clientkeys (`<op>TypedData`, `hashTypedData`); `at` = (token, chainId, chainUid)."""
    return hb(_ck("typed", op=op, at=dict(name="SCaaS PqzToken", contract=at[0], chainId=at[1], chainUid=js(at[2]),
                                          message=js({**NAMED[op.removeprefix("UA")][3](p), **dict(zip(EVL_F, e))}))))


def log(s):
    print(s, flush=True)
    LOG.append(s)


def check(ok, what):
    log(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        FAILS.append(what)
    return ok


def rpc(method, params=()):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode()
    for attempt in range(30):  # a rate-limited RPC (an nginx in front, HTTP 429) or a refused connection (nothing sent): retry
        try:
            r = json.load(urllib.request.urlopen(urllib.request.Request(RPC, body, {"content-type": "application/json"}), timeout=300))
            break
        except urllib.error.HTTPError as e:
            if e.code != 429 or attempt == 29:
                raise
        except urllib.error.URLError as e:
            if not isinstance(e.reason, ConnectionRefusedError) or attempt == 29:
                raise
        time.sleep(0.2 * (attempt + 1))
    if "error" in r:
        raise RuntimeError(f"{method}: {json.dumps(r['error'])[:600]}")
    return r["result"]


# ------------------------------------------------------------------ ABI (enough for these contracts)

def W(x):
    if isinstance(x, bytes):
        assert len(x) == 32, len(x)
        return x
    if isinstance(x, str):
        return int(x, 16).to_bytes(32, "big")
    return (int(x) % 2**256).to_bytes(32, "big")


def dyn(t):
    return t == "b" or (isinstance(t, tuple) and (t[0] == "a" or any(dyn(x) for x in t[1])))


def ssize(t):
    return 32 if t == "w" else sum(ssize(x) for x in t[1])


def enc(t, v):
    if t == "w":
        return W(v)
    if t == "b":
        v = v.encode() if isinstance(v, str) else v
        return W(len(v)) + v + b"\0" * (-len(v) % 32)
    if t[0] == "t":
        return encs(t[1], v)
    return W(len(v)) + encs([t[1]] * len(v), v)


def encs(ts, vs):
    hl = sum(32 if dyn(t) else ssize(t) for t in ts)
    head, tail = b"", b""
    for t, v in zip(ts, vs):
        if dyn(t):
            head += W(hl + len(tail))
            tail += enc(t, v)
        else:
            head += enc(t, v)
    return head + tail


def sel(sig):
    return keccak256(sig.encode())[:4]


def cd(sig, ts, *vs):
    return sel(sig) + encs(ts, list(vs))


def words(h, n=None):
    b = bytes.fromhex(h[2:])
    return [b[i:i + 32] for i in range(0, len(b), 32)][:n]


def dec_bytes(h, i=0):
    """The `bytes` whose offset is head word `i` of the return data."""
    b = bytes.fromhex(h[2:])
    o = int.from_bytes(b[32 * i:32 * i + 32], "big")
    n = int.from_bytes(b[o:o + 32], "big")
    return b[o + 32:o + 32 + n]


MTX = ("t", ["w", "b", "w", "w", "w", "w", "w", "w", "w"])
UMTX_S = "(bytes32,bytes,uint256,uint256,uint256,uint32,address,uint256,address)"
# IFactoryToken.TokenConfig: name, symbol, decimals, features, lockedFeatures, owner, roles, initialSupply, initialHolder, legs,
# rate, conf, grantDelay, rescueTo, maxSupply, reg (T25: complianceRegistry, requiredFlags, deniedFlags, termsHash; pay-meta-tax
# T39: taxRecipient; empty on
# the PQZ kinds 4, 5); `owner` and the five `roles` are UA ids (bytes32, a native account's address padded: the same word as
# the address it was, CTR-GOV-01 Change)
# (group 3f: `conf` ends pqzVerifyMode, pqzVerifierUA, pqzVerifierFixed; group 3h T60: then proofStore)
CFG = ("t", ["b", "b", "w", "w", "w", "w", ("t", ["w"] * 5), "w", "w", ("a", ("t", ["w", "w", "w"])), ("t", ["w", "w"]),
             ("t", ["b"] + ["w"] * 10), "w", "w", "w", ("t", ["w"] * 5)])
# IFactoryToken.Env (plan 5g-Z2; chain-neutral releases, plan T71: the factory fills its own chainUid and router):
# registry, smartKeyAccountImpl, hedera, deps, params, libs, libCodeHashes
ENV = ("t", ["w", "w", "w", ("a", "w"), ("a", "w"), ("a", "w"), ("a", "w")])
ENV_S = "(address,address,bool,address[],bytes32[],address[],bytes32[])"


def ua_binding(tok, at, m):
    """CTR-PQZ-21, R36: the binding a relayed proof folds on the merged entries and `mtxExecute`, for every subject: tag
    `SCAAS-PQZ-UA-ENVELOPE-V1`, `at` = (chainId, chainUid), the token, then the `UAMetaTransaction` `m` but `data`, `from` a
    `bytes32` id (an EOA's address zero-padded), an unbound `relayer` / `feeRecipient` as 0 (`PqzLayer._uaEnvelopeBinding`)."""
    who, _, batch, nonce, until, mode, rel, fee, frec = m
    return keccak256(encs(["w"] * 12, [kc("SCAAS-PQZ-UA-ENVELOPE-V1"), at[0], at[1], tok, who, batch, nonce, until, mode,
                                       rel if mode & 1 else ZERO, fee, frec if mode & 2 else ZERO]))


# ------------------------------------------------------------------ release deploy gate (C5-1, NET-EVM-06)

def require_release_gas(name):
    """A release is one CREATE2 whose code deposit is EIP-8037 state gas, 1,530 per byte of runtime (size-baseline.json;
    a contract under the EIP-170 limit is priced at 24,576 B), on top of the regular gas that EIP-7825 caps at 2^24.
    Refuses before sending when the chain's actual block gas limit cannot hold it (as DeployBase._requireReleaseGas): the
    SCaaS testnet's gate (Q4 of CTR-MTX-30, R40). A public chain's gate (`RELEASE_GAS_GATE=public`) takes the release
    transaction's regular and EIP-8037 state gas apart, which `eth_estimateGas` does not give: it is DeployBase's (a forge
    script on the chain's fork), and this script refuses it by name."""
    gate = os.environ.get("RELEASE_GAS_GATE", "testnet")
    if gate != "testnet":
        raise SystemExit(f"RELEASE_GAS_GATE={gate}: e2e.py runs the testnet gate only; a public chain deploys through "
                         "DeployBase (deploy.sh evm with RELEASE_GAS_GATE=public)")
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "size-baseline.json")) as f:
        runtime = json.load(f).get(name, 24_576)
    need = runtime * 1530 + (1 << 24)
    limit = int(rpc("eth_getBlockByNumber", ["latest", False])["gasLimit"], 16)
    if limit < need:
        raise SystemExit(f"block gas limit {limit:,} < {need:,} needed to deploy the {name} release (NET-EVM-06)")


# ------------------------------------------------------------------ transactions

class Sender:
    def __init__(self, key):
        self.key = key
        self.addr = address(key)
        self.nonce = int(rpc("eth_getTransactionCount", [self.addr, "pending"]), 16)

    def send(self, to, data, what, gas=None):
        tx = {"from": self.addr, "data": "0x" + data.hex()}
        if to:
            tx["to"] = to
        head = rpc("eth_getBlockByNumber", ["latest", False])
        if gas is None:
            # Amsterdam (EIP-8037): the estimate is regular + state gas and may pass 2^24 (the chain caps the regular
            # part); the limit is bounded by the chain's block gas limit, read here, never assumed
            try:
                gas = min(int(head["gasLimit"], 16), int(int(rpc("eth_estimateGas", [tx]), 16) * 1.15) + 50_000)
            except RuntimeError as e:
                check(False, f"{what}: estimateGas {e}")
                raise
        fee = int(head["baseFeePerGas"], 16)
        raw = legacy_tx(self.key, self.nonce, 2 * fee + 10**9, gas, to, 0, data, 7622)
        self.nonce += 1
        h = rpc("eth_sendRawTransaction", ["0x" + raw.hex()])
        t0 = time.time()
        while True:
            r = rpc("eth_getTransactionReceipt", [h])
            if r:
                break
            if time.time() - t0 > 300:
                raise RuntimeError(f"no receipt for {h}")
            time.sleep(1)
        used = int(r["gasUsed"], 16)
        check(r["status"] == "0x1", f"tx {what}: {h} block {int(r['blockNumber'], 16)} gasUsed {used:,} "
                                    f"(calldata {len(data):,} B)")
        if r["status"] != "0x1":
            raise RuntimeError(what)
        return r


def call(to, data, frm=None):
    tx = {"to": to, "data": "0x" + data.hex(), "gas": hex(30_000_000)}
    if frm:
        tx["from"] = frm
    return rpc("eth_call", [tx, "latest"])


def gas_of(to, data):
    return int(rpc("eth_estimateGas", [{"to": to, "data": "0x" + data.hex()}]), 16)


def artifact(name, src=None):
    j = json.load(open(os.path.join(EVM, OUT_DIR, (src or name) + ".sol", name + ".json")))
    return j["bytecode"]["object"].removeprefix("0x"), j["bytecode"].get("linkReferences", {})


# The releases `run` publishes (kind, implementation), each version 1 on env 1; ua-mtx-merge T31: the regulated PQZ kinds.
RELEASES = ((0, "NormalToken"), (4, "NormalPqzToken"), (5, "WrappedPqzToken"), (12, "NormalPqzRegulatedToken"),
            (13, "WrappedPqzRegulatedToken"))


def registry_codehash():
    """The canonical `ComplianceRegistry` runtime's code hash (regulated-kinds spec §5, F-11), from out/."""
    j = json.load(open(os.path.join(EVM, OUT_DIR, "ComplianceRegistry.sol", "ComplianceRegistry.json")))
    return keccak256(bytes.fromhex(j["deployedBytecode"]["object"].removeprefix("0x")))


def core_args(kind):
    """A kind's own constructor arguments, which each of its body modules takes too (T66b M1): on 8-13
    `abi.encode(REGISTRY_CODEHASH)`, 32 bytes; else none."""
    return registry_codehash() if kind >= 8 else b""


def kind_modules(kind):
    """T66b §4.5: `kind`'s body modules as (source file, contract) in its `implArgs` order, from the generated
    script/KindModules.sol (`kindModuleNames`, the one list the tests' Catalogue and DeployBase read)."""
    src = open(os.path.join(EVM, "script/KindModules.sol")).read()
    m = re.search(r"if \(kind == %d\) \{(.*?)return n;" % kind, src, re.S)
    return re.findall(r'"(\w+)\.sol:(\w+)"', m.group(1)) if m else []


def impl_args(kind, modules):
    """A release's `implArgs` (T66b §4.5, one named struct): `abi.encode(ImplArgs(modules))` on 0-5,
    `abi.encode(RegulatedImplArgs(REGISTRY_CODEHASH, modules))` on 8-13."""
    if kind >= 8:
        return encs([("t", ["w", ("a", "w")])], [[registry_codehash(), modules]])
    return encs([("t", [("a", "w")])], [[modules]])


def link_names(name, src=None, seen=None):
    """The TRANSITIVE link closure of an artifact by library name, from out/ alone (no chain)."""
    seen = [] if seen is None else seen
    for ls in artifact(name, src)[1].values():
        for ln in ls:
            if ln not in seen:
                link_names(ln, None, seen)
                seen.append(ln)
    return seen


def release_closure(kind, name):
    """A release's closure (T66b §4.5, Fable P2-3): the implementation's link references, its body modules and each
    module's link references, recursively; as names."""
    out = link_names(name)
    for src, mn in kind_modules(kind):
        for x in link_names(mn, src) + [mn]:
            if x not in out:
                out.append(x)
    return out


class Deployer:
    def __init__(self, s):
        self.s = s
        self.libs = {}
        self.closure = {}  # name -> its transitive library addresses, leaf first
        self.addr = {}

    def lib(self, name):
        if name not in self.libs:
            self.libs[name] = self.deploy(name, b"", label=f"library {name}")
        return self.libs[name]

    def linked(self, name, src=None):
        """The init code without arguments, the libraries linked in, and their addresses: the TRANSITIVE link closure,
        each library's own libraries first (metatx-split §4: a release's env lists every library of the closure with its
        code hash, and `MtxPipelineLib` links `HederaLib`)."""
        code, links = artifact(name, src)
        libs = []
        for _, ls in links.items():
            for ln, pos in ls.items():
                a = self.lib(ln)  # deploys the library's own libraries first (deploy -> linked, recursively)
                for x in self.closure[ln] + [a]:
                    if x not in libs:
                        libs.append(x)
                for p in pos:
                    code = code[:2 * p["start"]] + a[2:] + code[2 * (p["start"] + p["length"]):]
        self.closure[name] = libs
        return bytes.fromhex(code), libs

    def deploy2(self, name, args, label, src=None):
        """As `DeployBase` deploys with `new X{salt}`: through `CREATE2_DEPLOYER` with `DEPLOY_SALT`, so the address
        depends on the init code (with its arguments) and the salt only; code already at it is reused."""
        if rpc("eth_getCode", [CREATE2_DEPLOYER, "latest"]) in ("0x", None):
            raise RuntimeError(f"no deterministic CREATE2 deployer at {CREATE2_DEPLOYER} (runbook NET-EVM-05)")
        code, _ = self.linked(name, src)
        init = code + args
        a = create2_address(CREATE2_DEPLOYER, DEPLOY_SALT, init)
        if rpc("eth_getCode", [a, "latest"]) == "0x":
            self.s.send(CREATE2_DEPLOYER, DEPLOY_SALT + init, f"deploy {name} (CREATE2)")
        check(rpc("eth_getCode", [a, "latest"]) != "0x", f"{name} at {a} (CREATE2, salt {DEPLOY_SALT.hex()[:8]}…)")
        self.addr[label] = a
        return a

    def deploy(self, name, args, src=None, label=None):
        code, _ = self.linked(name, src)
        r = self.s.send(None, code + args, label or f"deploy {name}")
        a = r["contractAddress"]
        log(f"      {name} at {a}")
        self.addr[label or name] = a
        return a


# ------------------------------------------------------------------ provers

class Proc:
    def __init__(self, argv):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def ask(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        r = self.p.stdout.readline().strip()
        if r.startswith("ERR"):
            raise RuntimeError(r)
        return r


class PQ:
    def __init__(self):
        self.prover = Proc([os.environ.get("PQZ_PROVE") or os.path.join(ROOT, "pqz-core/ffi/target/release/examples/pqz_prove")])
        self.ml = Proc(["node", os.path.join(HERE, "mldsa.mjs"), os.path.join(ROOT, "../../../clients/clientkeys")
                        if not os.path.isdir(os.path.join(ROOT, "clients/clientkeys/node_modules"))
                        else os.path.join(ROOT, "clients/clientkeys")])

    def prove(self, op, stmt, wit):
        rnd = os.urandom(32)
        t = time.time()
        p = bytes.fromhex(self.prover.ask(f"prove {op} {stmt.hex()} {wit.hex()} {rnd.hex()}"))
        dt = time.time() - t
        ok = self.prover.ask(f"verify {op} {stmt.hex()} {p.hex()}").endswith("01")
        PROVEN.append((op, stmt, p))
        check(ok, f"proof op {op}: {len(p):,} B, proved in {dt:.2f} s, pqz-ffi verify = 1 (stmt {len(stmt):,} B)")
        return p

    def ml_pk(self, lvl, seed):
        return bytes.fromhex(self.ml.ask(f"keygen {lvl} {seed.hex()}"))

    def ml_sign(self, lvl, seed, msg):
        return bytes.fromhex(self.ml.ask(f"sign {lvl} {seed.hex()} {msg.hex()}"))


# ------------------------------------------------------------------ the scenario

class UA:
    """An ML-DSA UA (`kind`, seed); a PQZ holder also has the PQZ key (pk, s, e)."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def ua_msg(kind, purpose, digest):
    return kc(MSG_TAG, TAG[kind], purpose, digest)


def ml_sig(pq, signer, purpose, digest):
    """`UASig{keyData: "", signature, members: []}` (a stored kind, CTR-UA-17), the ML-DSA signature over `pq_msg =
    keccak256(TAG ‖ ua_msg)` (CTR-UA-23): the registry's `requireAuthorized` form (typed-signing R1)."""
    m = ua_msg(signer.kind, purpose, digest)
    return [b"", pq.ml_sign(44 if signer.kind == MLDSA44 else 65, signer.seed, kc(TAG[signer.kind], m)), []]


def ua_sig(pq, signer, purpose, digest):
    """A holder's `UASig`: `ml_sig`, or for an msig the members' over `member_digest` under `member` (accounts.md §1.9), in
    index order, every member (2-of-2 here)."""
    if signer.kind != MSIG:
        return ml_sig(pq, signer, purpose, digest)
    md = kc(signer.ua, ua_msg(MSIG, purpose, digest))
    return [b"", b"", [[i, [], ml_sig(pq, m, P_MEMBER, md)[1]] for i, m in enumerate(signer.members)]]


def ecdsa(key, m):
    r, s_, rec = sign(key, m)
    return r.to_bytes(32, "big") + s_.to_bytes(32, "big") + bytes([27 + rec])


def verdict_hashes(v, uid):
    """(domain separator, struct hash, digest) of `PqzVerdict` `v` = [token, chainId, proofSystemId, statementHash, proofHash,
    pqzVerifierEpoch, validUntil] (spec §5.1) in the token's EIP-712 domain ("SCaaS PqzToken", "1", chainId, the token,
    salt = `uid`, the chain_uid)."""
    sep = kc(K.EIP712_DOMAIN_TYPEHASH, kc("SCaaS PqzToken"), kc("1"), W(v[1]), W(v[0]), uid)
    sh = kc(VERDICT_TYPEHASH, *map(W, v))
    return sep, sh, kc(b"\x19\x01", sep, sh)


def verdict(tok, stmt, proof):
    """The `PqzSignedVerdict` of `proof` over `stmt` (the bytes `tok`'s statement view returned for this op): the empty one
    on a PRECOMPILE token; on an OFFCHAIN token (`--zero-dep`) the `PqzVerdict` of spec §5.2 at the token's current
    `pqzVerifierEpoch`, valid `VERDICT_LIFE` s, signed by `VERIFIER` (the deployer EOA, a native id: its 65-byte low-s ECDSA
    over the registry's `uaAuthDigest(ua, PURPOSE_PQZ_VERDICT, digest)`, empty keyData and members)."""
    c = words(call(tok, cd("pqzVerifyConfig()", [])), 4)  # mode, verifier, fixed_, pqzVerifierEpoch, ...
    if int.from_bytes(c[0], "big") == 0:
        return NO_VERDICT
    ua = pad(VERIFIER[0].addr)
    assert c[1] == ua, f"verdict: {tok}'s verifier is 0x{c[1].hex()}, not the deployer"
    v = [tok, CTX[0], hb(call(tok, cd("proofSystemId()", []))), keccak256(stmt), keccak256(proof), int.from_bytes(c[3], "big"),
         int(time.time()) + VERDICT_LIFE]
    a = words(call(REG[0], cd("uaAuthDigest(bytes32,bytes32,bytes32)", ["w", "w", "w"], ua, P_VERDICT, verdict_hashes(v, CTX[1])[2])))[0]
    return [v, [b"", ecdsa(VERIFIER[0].key, a), []]]


def amount_cd(ref, leg, amount, kind, kv, proof, sv):
    """`verifyTransferAmount` calldata: the six-argument form with the empty verdict (a PRECOMPILE token), else the verdict
    form (spec §5.4: an OFFCHAIN token's six-argument form reverts `PqzVerdictRequired`)."""
    if sv == NO_VERDICT:
        return cd(API["verifyAmt"], ["w", "w", "w", "w", "w", "b"], ref, leg, amount, kind, kv, proof)
    return cd(API["verifyAmtV"], ["w", "w", "w", "w", "w", "b", SV_T], ref, leg, amount, kind, kv, proof, sv)


class Signed:
    """One signed envelope on `tok`, relayed by `relayer`: an EOA `Sender` (its own key in `UASig.signature`, no registry call:
    ua-mtx-merge R1, B) or a `UA` signs the merged entry's `UA` struct, `from` the id (an EOA's address zero-padded); the outer
    fee is FIXED (none at 0) and goes to the relayer. `binding` is what a proof folds (D15, R36: the UA binding for every
    subject), so build this before the proof; `send` signs the entry's own struct and submits it. One nonce space per id, so
    `WrapShield` (an address `Envelope`) reads it the same way. Each envelope takes one nonce, so one `Signed` per op."""
    spent = {}  # (token, signer id) -> outer fees

    def __init__(self, tok, signer, pq, relayer, fee):
        self.tok, self.signer, self.pq, self.relayer, self.ua = tok, signer, pq, relayer, isinstance(signer, UA)
        who = signer.ua if self.ua else pad(signer.addr)
        n = cd("mtxNonce(bytes32,uint256)", ["w", "w"], who, 0)
        self.e = [who, 0, int(call(tok, n), 16), int(time.time()) + 3600, 0x20 if fee else 0, ZERO, fee, ZERO]
        self.binding = hb(call(tok, cd(f"envelopeBinding({UMTX_S})", [MTX], [who, b""] + self.e[1:])))

    def send(self, base, p, what, sv=NO_VERDICT):
        """`sv`: the `PqzSignedVerdict` of a proof-carrying op (`verdict`), outside the signed struct (spec §5.3)."""
        op = base if base == "WrapShield" else "UA" + base
        e = [self.signer.addr] + self.e[1:] if op == "WrapShield" else self.e
        d = typed_digest(op, (self.tok, CTX[0], CTX[1]), e, p)
        if op == "WrapShield":
            sig = ecdsa(self.signer.key, d)
        else:
            sig = ua_sig(self.pq, self.signer, P_METATX, d) if self.ua else [b"", ecdsa(self.signer.key, d), []]
        r = self.relayer.send(self.tok, named_cd(op, e, p, sig, sv), what)
        k = (self.tok, self.e[0])
        Signed.spent[k] = Signed.spent.get(k, 0) + self.e[6]
        return r


class Client:
    """The wallet side of one PQZ token. It tracks, per UA, the decrypted shielded balance and (after a debit) the `acc`
    bytes it expects; the token's views are the truth (plan 5h D13): `restore()` rebuilds the balance from them alone
    and compares. Public side: `pub` (UA-ledger units paid by the pool, fees), `total` (totalShielded)."""

    def __init__(self, tok, name):
        self.tok, self.name = tok, name
        self.bal, self.acc, self.pub, self.uas, self.total = {}, {}, {}, {}, 0
        self._next = {}

    def state(self, ua, version=None):
        v = kv_of(ua) if version is None else version
        w = [int.from_bytes(x, "big") for x in words(call(self.tok, cd("pqzAccount(bytes32,uint64)", ["w", "w"], ua.ua, v)), len(ACCT))]
        return dict(zip(ACCT, w))

    def hint(self, ua):
        """The optional `accHint` (D5): the materialised `acc` packed (P46), used by the token only while its keccak is
        `accHash`."""
        return pack(dec_bytes(call(self.tok, cd("pqzAcc(bytes32,uint64)", ["w", "w"], ua.ua, kv_of(ua))))) if self.state(ua)["flags"] & 1 else b""

    def set_next(self, bal=(), pub=(), acc=None, total=0, accv=0):
        self._next = dict(bal=list(bal), pub=list(pub), acc=acc or {}, total=total, accv=accv)

    def commit(self):
        n = self._next
        for u, d in n["bal"]:
            self.uas[u.ua] = u
            self.bal[u.ua] = self.bal.get(u.ua, 0) + d
        for u, d in n["pub"]:
            self.pub[u.ua] = self.pub.get(u.ua, 0) + d
        self.total += n["total"]
        for u, acc in n["acc"].items():
            got = dec_bytes(call(self.tok, cd("pqzAcc(bytes32,uint64)", ["w", "w"], u, n.get("accv", 0))))  # the debited version
            check(got == acc, f"{self.name} pqzAcc({u.hex()[:8]}…) = the new u' ‖ v_f after the debit")
        self._next = {}


def pending_block(tok, ua, i):
    """The block of pending entry `i` (the low 64 bits of the raw slot, D2)."""
    return int(call(tok, cd("pqzPending(bytes32,uint64,uint64)", ["w", "w", "w"], ua.ua, kv_of(ua), i)), 16) & (2**64 - 1)


def wait_block(n):
    t0 = time.time()
    while int(rpc("eth_blockNumber"), 16) < n:
        if time.time() - t0 > 900:
            raise RuntimeError(f"head did not reach block {n}")
        time.sleep(1)


def rollover(s, C, ua, n, what, signed=None):
    """Plan 5h D8: `mtxPrepareAcc` for both halves (permissionless, idempotent, once per account), wait until the n-th
    entry is `ROLL_AGE` blocks old (D6), then `mtxRollOver(ua, n)` by count. `signed`: a function giving a new `Signed`, for
    the named entries; else direct from `s`."""
    st = C.state(ua)
    for half in (0, 1):
        if not st["flags"] & (2 << half):
            label = f"{C.name} mtxPrepareAcc({ua.name}, {half})"
            if signed:
                signed().send("PrepareAcc", [ua.ua, kv_of(ua), half], f"signed {label}")
            else:
                s.send(C.tok, cd(API["prepareAcc"], ["w", "w", "w"], ua.ua, kv_of(ua), half), label)
    wait_block(pending_block(C.tok, ua, st["rolled"] + n - 1) + ROLL_AGE)
    label = f"{C.name} mtxRollOver({ua.name}, {n}): {what}"
    if signed:
        signed().send("RollOver", [ua.ua, kv_of(ua), n], f"signed {label}")
    else:
        s.send(C.tok, cd(API["rollOver"], ["w", "w", "w"], ua.ua, kv_of(ua), n), label)
    st2 = C.state(ua)
    check(st2["rolled"] == st["rolled"] + n and st2["flags"] & 1 == 1 and st2["accUnits"] > st["accUnits"],
          f"{C.name} {ua.name} rolled {st['rolled']} → {st2['rolled']}, acc materialised, accUnits {st2['accUnits']}")


def restore(C, what):
    """Wallet restore from the views alone (plan 5h D13): `T = pqzAcc + Σ pqzPendingCt(i), i ∈ [rolled, pendingCount)`,
    decrypted with the UA's key, against the balance this script tracked; the raw slots (`pqzPending`) give kind and
    block of each entry."""
    log(f"wallet restore from the views ({what}):")
    for ua_id, tracked in C.bal.items():
        u = C.uas[ua_id]
        # group 3g (KV-6): the balance is the sum over the UA's versions, each with its own key
        got, kinds, st = 0, [], None
        for v in range(kv_of(u) + 1):
            st = C.state(u, v)
            T = dec_bytes(call(C.tok, cd("pqzAcc(bytes32,uint64)", ["w", "w"], ua_id, v)))
            for i in range(st["rolled"], st["pendingCount"]):
                T = K.ct_add(T, dec_bytes(call(C.tok, cd("pqzPendingCt(bytes32,uint64,uint64)", ["w", "w", "w"], ua_id, v, i))))
                w = int(call(C.tok, cd("pqzPending(bytes32,uint64,uint64)", ["w", "w", "w"], ua_id, v, i)), 16)
                kinds.append("T" if (w >> 64) & 0xFFFF == 0 else "C")  # TRIVIAL (vOff = 0) or a proven credit
            got += bal(key_at(u, v).s, T)
        check(got == tracked, f"restore {C.name} {u.name}: acc + pending over {kv_of(u) + 1} version(s) "
                              f"[{''.join(kinds)}] decrypt to {got}, tracked {tracked} (latest: rolled {st['rolled']}, "
                              f"pendingCount {st['pendingCount']}, floor {st['floor']}, flags {st['flags']})")


def check_public(C, what):
    """The pool holds exactly the shielded value (D19), the fee recipients their public units."""
    pool = int.from_bytes(words(call(C.tok, cd("balanceOf(address)", ["w"], SHIELD_POOL)))[0], "big")
    tot = int.from_bytes(words(call(C.tok, cd("totalShielded()", [])))[0], "big")
    check(tot == C.total and pool == tot * SCALE, f"{C.name} {what}: totalShielded {tot} (tracked {C.total}), SHIELD_POOL "
                                                  f"{pool:,} = totalShielded · scale")
    for ua_id, v in C.pub.items():
        got = int.from_bytes(words(call(C.tok, cd("balanceOfUA(bytes32)", ["w"], ua_id)))[0], "big")
        check(got == v * SCALE, f"{C.name} public UA balance of {ua_id.hex()[:8]}… = {got:,} (fees paid from the pool: {v} · scale)")


def bal(s_key, T):
    return K.dec(s_key, T)[2]


def abi_t(s):
    """An ABI type as this script's encoder notation."""
    if s.endswith("[]"):
        return ("a", abi_t(s[:-2]))
    if s.startswith("("):
        return ("t", abi_ts(s[1:-1]))
    return "b" if s in ("bytes", "string") else "w"


def abi_ts(s):
    out, depth, at = [], 0, 0
    for i, c in enumerate(s):
        depth += (c == "(") - (c == ")")
        if c == "," and depth == 0:
            out.append(abi_t(s[at:i]))
            at = i + 1
    return out + [abi_t(s[at:])] if s else []


def abi_methods():
    """The methods and events of the contracts this file calls, from the ABI in out/ (`forge build` first)."""
    methods, events = {}, set()
    for src, name in (("UARegistry", "UARegistry"), ("OpenFactory", "OpenFactory"), ("NormalPqzToken", "NormalPqzToken"),
                      ("WrappedPqzToken", "WrappedPqzToken"), ("Mocks", "MockERC20"), ("MlDsa", "UAMldsaVerifier"),
                      ("UAPqzVerifier", "UAPqzVerifier")):
        j = json.load(open(os.path.join(EVM, OUT_DIR, src + ".sol", name + ".json")))
        methods.update(j["methodIdentifiers"])
        events |= {f"{x['name']}({','.join(i['type'] for i in x['inputs'])})" for x in j["abi"] if x["type"] == "event"}
    # T66b: a token face declares only the events of its kept bodies; a log of a forwarded entry is declared by the body
    # module or the library that emits it, so the PQZ releases' closures (modules, libraries) count too
    for kind, name in ((4, "NormalPqzToken"), (5, "WrappedPqzToken")):
        for src, mn in kind_modules(kind):
            for n, sf in [(mn, src)] + [(x, None) for x in link_names(mn, src)]:
                j = json.load(open(os.path.join(EVM, OUT_DIR, (sf or n) + ".sol", n + ".json")))
                events |= {f"{x['name']}({','.join(i['type'] for i in x['inputs'])})" for x in j["abi"] if x["type"] == "event"}
    return methods, events


def sol_struct_t(name):
    """The ABI type of struct `name` from the Solidity source (`IFactoryToken.sol`, `GovernanceLib.sol`'s `Roles`): the
    shape `CFG` and `ENV` must follow (T25: a field added to `TokenConfig` turns the self-test red here)."""
    src = "".join(open(os.path.join(EVM, p), encoding="utf-8").read() for p in
                  ("src/factory/IFactoryToken.sol", "src/governance/GovernanceLib.sol"))
    src = re.sub(r"//[^\n]*", "", src)
    structs = {n: [f.split()[0] for f in body.split(";") if f.strip()] for n, body in re.findall(r"struct (\w+)\s*\{([^}]*)\}", src)}

    def t(x):
        if x.endswith("[]"):
            return t(x[:-2]) + "[]"
        x = x.split(".")[-1]
        return "(" + ",".join(t(f) for f in structs[x]) + ")" if x in structs else x
    return t(name)


def abi_check():
    """Every signature this file hands to `cd`, its encoders, and the events it looks up, against the ABI in out/. A
    signature built at run time is `named_cd`'s alone; `named_rows` checks that one."""
    methods, events = abi_methods()
    seen, late = set(), []
    for c in ast.walk(ast.parse(open(os.path.abspath(__file__), encoding="utf-8").read())):
        if isinstance(c, ast.Call) and getattr(c.func, "id", "") == "cd":
            try:
                sig, ts = (eval(compile(ast.Expression(x), "e2e", "eval"), globals()) for x in c.args[:2])  # noqa: S307
            except NameError as e:
                late.append(e.name)
                continue
            seen.add(sig)
            check(sig in methods, f"ABI: {sig[:70]}")
            check(abi_ts(sig[sig.index("(") + 1:-1]) == ts, f"encoders of {sig[:70]}")
    check(late == ["op"], f"ABI: {len(seen)} signatures; built at run time: {late}")
    check(all(x in events for k in ("ev_single", "ev_multi") for x in API[k]), "the transfer events are the built ones")


def pyv(t, v, types):
    """A `typed_ops.json` value of type `t` as this script's ABI value."""
    if t.endswith("[]"):
        return [pyv(t[:-2], x, types) for x in v]
    if t in types:
        return [pyv(f["type"], v[f["name"]], types) for f in types[t]]
    if t.startswith(("uint", "bool")):
        return int(v)
    if t == "address":
        return v
    return hb(v) + bytes(16) if t == "bytes16" else hb(v)


def row_call(op, r, d):
    """(envelope, parameters, sig) of a `typed_ops.json` row, in the shapes `run` hands the builders."""
    m, ts, base = r["message"], r["types"], op.removeprefix("UA")
    own = ts[op]
    e = [pyv(f["type"], m[f["name"]], ts) for f in own[:1] + own[-7:]]
    sig = hb(d["signature"])
    if op.startswith("UA"):
        sig = [b"", sig, []]
    if not base.startswith("Pqz"):
        return e, [pyv(f["type"], m[f["name"]], ts) for f in own[1:-7]], sig
    mid = [[int(m["amount"]), hb(m["recipient"])]] if base == "PqzUnshield" else [pyv("Unwrap", m["unwrap"], ts)] if base == "PqzUnshieldUnwrap" else []
    return e, [pyv(own[1]["type"], m["args"], ts)] + mid + [hb(m["proof"]), sig_v(d["extra"]["pqzAuth"]), hb(m["accHint"])], sig


def named_rows():
    """Every named entry this script can send against its `typed_ops.json` row: the merged `mtx<entry>` (ua-mtx-merge R1,
    R47: the `UA` struct for every subject, `UASig auth`; `WrapShield` keeps its address `Envelope`, no twin) is in the built
    ABI, its calldata is the row's byte for byte (T11 regenerated the rows under the merged names, `UAShield` with `UASig`),
    the digest of the struct `typed_digest` assembles from the same parameters, and the typed `PqzAuth`."""
    V = json.load(open(os.path.join(ROOT, "smartcontracts/vectors/typed/typed_ops.json")))
    methods, _ = abi_methods()
    # group 3g: the PQZ rollover's row is `UAPqzRollOver` (Zether keeps `UARollOver`)
    named = lambda op: "UARollOver" if op == "UAPqzRollOver" else op
    rows = {named(op): r for op, r in V["ops"].items() if named(op) in BUILT and "pqz" in r["domains"]}
    check(len(rows) == 10, f"typed_ops.json: {len(rows)} rows with a builder here, want 10")
    for op, r in rows.items():
        d = r["domains"]["pqz"]
        e, p, sig = row_call(op, r, d)
        c, head = named_cd(op, e, p, sig), named_sig(op)  # group 3f: a proof-carrying row with the empty verdict
        check(head in methods and c[:4] == sel(head), f"{op}: {head[:60]}… in the ABI")
        row = hb(d["calldata"])
        check(c == row, f"{op}: calldata {len(c):,} B = the row's (row {d['selector']})")
        check(typed_digest(op, (d["domain"]["verifyingContract"], d["domain"]["chainId"], hb(d["domain"]["salt"])), e, p) == hb(d["digest"]),
              f"{op}: typed digest = the row's")
    a = V["ops"]["PqzAuth"]
    m = a["message"]
    head = b"".join(W(pyv(f["type"], m[f["name"]], a["types"])) for f in a["types"]["PqzAuth"][1:-1])
    kec, K.kec = K.kec, lambda _: hb(m["bodyHash"])  # the row gives the body's hash, `K.auth_digest` hashes the body
    got = K.auth_digest(m["op"], head)
    K.kec = kec
    check(len(head) == 640 and K.PQZ_AUTH_TYPEHASH == hb(a["typehash"]) and got == hb(a["domains"]["pqz"]["digest"]), "PqzAuth: K.auth_digest = the row's")


def verdict_rows():
    """Group 3f (spec §5.1, §11.3): `verdict_hashes` against smartcontracts/vectors/pqz/verdict.json (the forge writer
    test/pqz/PqzVerdictVectors.t.sol): the typehash, `PURPOSE_PQZ_VERDICT`, the token's domain separator, every row's struct
    hash and digest, and `ecdsa` by the vector's EOA key over a row's `uaAuthDigest` = its signature. Skipped, with a note,
    while the file is not written."""
    path = os.path.join(ROOT, "smartcontracts/vectors/pqz/verdict.json")
    if not os.path.exists(path):
        log("note  smartcontracts/vectors/pqz/verdict.json not written yet (WRITE_VERDICT_VECTORS=true forge test "
            "--match-contract PqzVerdictVectorsTest): the verdict digest check skipped")
        return
    V = json.load(open(path))
    dom = V["domain"] if isinstance(V["domain"], dict) else json.loads(V["domain"])
    n = lambda x: int(str(x), 0)  # noqa: E731  (a JSON number or a numeric string)
    check(hb(V["typehash"]) == VERDICT_TYPEHASH and hb(V["purposeTag"]) == P_VERDICT, "verdict.json: PqzVerdict typehash, PURPOSE_PQZ_VERDICT")
    bad = []
    for i, r in enumerate(V["rows"]):
        v = [dom["verifyingContract"], n(dom["chainId"]), hb(V["proofSystemId"]), hb(r["statementHash"]), hb(r["proofHash"]),
             n(r["pqzVerifierEpoch"]), n(r["validUntil"])]
        sep, sh, dg = verdict_hashes(v, hb(dom["salt"]))
        if (sep, sh, dg) != (hb(dom["separator"]), hb(r["structHash"]), hb(r["digest"])) or (
                "signature" in r and ecdsa(n(V["verifierKey"]), hb(r["uaAuthDigest"])) != hb(r["signature"])):
            bad.append(i)
    check(V["rows"] and not bad, f"verdict.json ({V.get('set')}): {len(V['rows'])} rows, separator, struct hash, digest = "
                                 f"verdict_hashes, the EOA signature = ecdsa; failing rows {bad}")


def release_rows():
    """ua-mtx-merge T33 (regulated-kinds spec §6.1): the releases `run` publishes, the regulated PQZ kinds 12 and 13 among
    them: `RegulatedLib` linked in each regulated one's init code (so in its env's link closure) and in no base kind's, and
    each regulated release's `implArgs` the `ComplianceRegistry` runtime's code hash, the pin of test/as/Registry.t.sol."""
    check([k for k, _ in RELEASES] == [0, 4, 5, 12, 13], f"releases: kinds {[k for k, _ in RELEASES]}")
    pin = re.search(r"REGISTRY_CODEHASH = (0x[0-9a-f]{64});", open(os.path.join(EVM, "test/as/Registry.t.sol")).read())
    check(pin is not None and registry_codehash() == hb(pin.group(1)), "ComplianceRegistry runtime hash = Registry.t.sol's pin")
    for kind, name in RELEASES:
        mods = kind_modules(kind)
        closure = release_closure(kind, name)
        reg = "RegulatedLib" in closure
        check(len(mods) >= 3 and reg == (kind >= 8),
              f"{name} (kind {kind}): {len(mods)} modules, closure {len(closure)} contracts, RegulatedLib "
              f"{'in it' if reg else 'not in it'}")
        ms = ["0x" + f"{i + 1:040x}" for i in range(len(mods))]
        a = impl_args(kind, ms)
        head = 2 if kind >= 8 else 1  # struct offset, [registry hash,] array offset, length, the modules
        w = [a[i:i + 32] for i in range(0, len(a), 32)]
        check(len(core_args(kind)) == (32 if kind >= 8 else 0) and len(w) == 3 + head + len(ms) - 1
              and int.from_bytes(w[head + 1], "big") == len(ms) and [x.hex()[24:] for x in w[head + 2:]] == [m[2:] for m in ms]
              and (kind < 8 or w[1] == registry_codehash()), f"{name} (kind {kind}): implArgs {len(a)} B, the module list")


def self_test():
    """No chain (typed-signing P8, C8): the portable messages and the registry arguments this script builds, against
    portable.json's rows at pqz_kat's set — R_REG / PoP / KEM / PQZ-key messages from clientkeys, `registrationArgs`
    (full and hash-commit forms), the `register` / `registerMsig` / `setKemKey` / `setPqzKey` calldata (selector pins, length =
    clientkeys `registryCalldataLength`), the `kemKeyOf` decoder; `named_rows`; `abi_check`."""
    for dep, want in ((bytes(20).hex(), "4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38"),
                      ("deadbeef" + "00" * 16, "b928f69bb1d91cd65274e3c79d8986362984fda3")):  # EIP-1014 examples 0, 1
        check(create2_address("0x" + dep, bytes(32), b"\x00") == "0x" + want, f"create2_address: EIP-1014 row 0x{dep[:8]}… = 0x{want[:8]}…")
    P = json.load(open(os.path.join(ROOT, "smartcontracts/vectors/ua/portable.json")))
    r = next(x for x in P["registrations"] if x["name"] == f"mldsa65/{K.SET}")
    ua, at = hb(r["ua"]), {k: hb(v) for k, v in r["attrs"].items()}
    check(portable("reg", kind=MLDSA65, ua=ua, pqzKey=at["pqzKey"], kemPk=at["kemPk"]) == hb(r["pqzRegMessage"]),
          f"{r['name']}: R_REG message (pqzRegMessage, registering kind 0x0131)")
    check(portable("pop", kind=MLDSA65, ua=ua, **at) == hb(r["popMessage"]), f"{r['name']}: PoP message (holderPopMessage)")
    g = reg_args(MLDSA65, hb(r["keyData"]), pqzKey=at["pqzKey"], pqzPop=hb(r["pqzPop"]), kemPk=at["kemPk"], pop=hb(r["pop"]))
    check(g["entry"] == r["args"]["entry"] and dict(g["args"], entry=g["entry"]) == r["args"] and g["kemFill"] is None,
          f"{r['name']}: registrationArgs = the row's args (full KEM key)")
    full = register_cd(g["args"])
    check(full[:4].hex() == "4e229efb" and len(full) == g["length"],
          f"{r['name']}: register calldata {len(full):,} B = registryCalldataLength, selector 0x4e229efb")
    c = reg_args(MLDSA65, hb(r["keyData"]), pqzKey=at["pqzKey"], pqzPop=hb(r["pqzPop"]), kemPk=at["kemPk"], pop=hb(r["pop"]),
                 kemCommit=True)
    check(dict(c["args"], entry=c["entry"]) == r["kemCommit"]["register"] and c["kemFill"] == r["kemCommit"]["fill"]
          and len(register_cd(c["args"])) == c["length"], f"{r['name']}: hash-commit args + fill = the row's kemCommit")
    f = c["kemFill"]
    fill = cd(SET_KEM, SET_KEM_T, hb(f["ua"]), 0, kem_v(f["kem"]), sig_v(f["sig"]))
    check(fill[:4].hex() == "6a3318f9" and kem_key(at["kemPk"]) == kem_v(f["kem"]), "setKemKey fill calldata (selector 0x6a3318f9)")
    k = next(x for x in P["kemRecords"] if x["id"] == "mldsa65/v1")
    check(portable("kem", kind=k["kind"], ua=hb(k["ua"]), kemVersion=k["version"], kemPk=hb(k["kemPk"])) == hb(k["message"])
          and kem_key(hb(k["kemPk"])) == kem_v(k["args"]["kem"]), f"KEM record {k['id']}: message, KemKey")
    q = next(x for x in P["pqzKeyRecords"] if x["set"] == K.SET and x["kind"] != 0x0120)
    qa = dict(ua=hb(q["ua"]), pqzKey=hb(q["pqzKey"]))
    check(portable("keyrec", kind=q["kind"], pqzPopHash=hb(q["pqzPopHash"]), **qa) == hb(q["message"])
          and portable("keyreg", **qa) == hb(q["pqzRegMessage"]), f"PQZ key record {q['name']}: setPqzKey and R_REG messages")
    check(sel(SET_PQZ).hex() == "bd97b6a1" and sel(REQ_AUTH).hex() == "9600639d", "setPqzKey / requireAuthorized selectors")
    kem = at["kemPk"]
    ret = "0x" + encs(["w", KEM_T, "b"], [0, kem_key(kem), b"\x07"]).hex()
    none = "0x" + encs(["w", KEM_T, "b"], [0, [0, b"", bytes(32)], b""]).hex()
    check(kem_of_ret(ret) == (0, kem, b"\x07") and kem_of_ret(none) == (0, b"", b""), "kemKeyOf decoder (key, empty key)")
    m = next(x for x in P["registrations"] if x["name"] == f"msig-pq/{K.SET}")
    ma = {k: hb(v) for k, v in m["attrs"].items()}
    kd = hb(_ck("msig", threshold=m["threshold"], members=[{k: x[k] for k in ("kind", "id", "weight")} for x in m["members"]]))
    check(kd == hb(m["keyData"]), f"{m['name']}: encodeMsig = the row's key data")
    check(ua_msg(MSIG, kc("scaas.ua.purpose.pop.v2"), hb(m["registrationDigest"])) == hb(m["popMessage"])
          and _ck("popmd", kind=MSIG, ua=hb(m["ua"]), keyData=kd, pqzPopHash=kc(hb(m["pqzPop"])), **{k: ma[k] for k in ("pqzKey", "kemPk")}) == m["memberDigest"]
          and kc(hb(m["ua"]), hb(m["popMessage"])) == hb(m["memberDigest"]), f"{m['name']}: msig message, member digest")
    g = reg_args(MSIG, kd, pqzKey=ma["pqzKey"], pqzPop=hb(m["pqzPop"]), kemPk=ma["kemPk"], pop=m["args"]["pop"], kemCommit=False)
    check(dict(g["args"], entry=g["entry"]) == m["args"], f"{m['name']}: registrationArgs = the row's args")
    data = register_msig_cd(g["args"])
    check(data[:4].hex() == "61947129" and len(data) == g["length"], f"{m['name']}: registerMsig calldata {len(data):,} B = registryCalldataLength, selector 0x61947129")
    # ua-mtx-merge T10 (R36): the UA binding of an EOA's envelope (`from` its address zero-padded; the relayer bound, a non-zero
    # fee recipient unbound and so 0) = the word test/pqz/PqzRelay.t.sol `test_uaBindingOfAnEoaKat` pins from the token's view
    m = [pad("0x" + "11" * 20), b"\xc0\xde", 3, 4, 5, 0x21, "0x" + "22" * 20, 6, "0x" + "33" * 20]
    kat = (7622, hb("0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464"))
    check(ua_binding("0x" + "00" * 17 + "5caa01", kat, m) == hb("0x2bf9ed02f291a24e973d7013c788d50aae3bb9844c40c4c3ca5e9a37419abd33"),
          "ua_binding of an EOA's envelope = PqzRelay's KAT (SCAAS-PQZ-UA-ENVELOPE-V1, from padded, unbound fee recipient 0)")
    check(abi_t(sol_struct_t("TokenConfig")) == CFG and abi_t(sol_struct_t("Env")) == ENV
          and sol_struct_t("Env") == ENV_S, "CFG, ENV = IFactoryToken.TokenConfig, Env (the source's fields, `reg` included)")
    named_rows()
    verdict_rows()
    abi_check()
    release_rows()


def main():
    global RPC, SPLIT, ZERO_DEP, PROOF_STORE, PROOF_PATH_ONLY
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--log", default=os.path.join(EVM, "runs/2026-10-16-p6g-7622.txt"))
    ap.add_argument("--keys", default="1,2,3")
    ap.add_argument("--split", action="store_true", help="always register without the proof, then storePqzPop")
    ap.add_argument("--proof-store", choices=["none", "log"], default="none",
                    help="the PQZ tokens' proofStore at creation (group 3h): NONE (calldata only) or LOG (a PqzDebitProof event per debit)")
    ap.add_argument("--zero-dep", action="store_true",
                    help="PQZ releases on deps = [0x0], the PQZ tokens OFFCHAIN, the deployer EOA their verifier")
    ap.add_argument("--self-test", action="store_true", help="no chain: messages, registry args and calldata vs portable.json")
    ap.add_argument("--proof-path-only", action="store_true", help="deploy, UAs, tokens, then the proof path (section 7) alone")
    ap.add_argument("--skip-kind", type=int, action="append", default=[],
                    help="a token kind whose release is not deployed here (logged as skipped; this run creates no token of it)")
    a = ap.parse_args()
    if a.self_test:
        try:
            self_test()
        except Exception as e:  # noqa: BLE001
            check(False, f"self-test aborted: {type(e).__name__}: {e}")
        log(f"self-test: {len(FAILS)} failure(s)")
        sys.exit(1 if FAILS else 0)
    RPC, SPLIT, ZERO_DEP = a.rpc, a.split, a.zero_dep
    SKIP_KINDS.update(a.skip_kind)
    PROOF_PATH_ONLY = a.proof_path_only
    PROOF_STORE = 1 if a.proof_store == "log" else 0
    kd, kr, ke = (int(x) for x in a.keys.split(","))
    try:
        run(kd, kr, ke)
    except Exception as e:  # noqa: BLE001
        check(False, f"aborted: {type(e).__name__}: {e}\n{traceback.format_exc()}")
    finally:
        os.makedirs(os.path.dirname(a.log), exist_ok=True)
        with open(a.log, "w") as f:
            f.write("\n".join(LOG) + f"\n\nresult: {len(FAILS)} failure(s)\n")
        log(f"result: {len(FAILS)} failure(s); log {a.log}")
    sys.exit(1 if FAILS else 0)


def run(kd, kr, ke):
    t0 = time.time()
    chain = int(rpc("eth_chainId"), 16)
    g = rpc("eth_getBlockByNumber", ["0x0", False])
    uid = bytes.fromhex(g["hash"][2:])
    CTX[:] = [chain, uid]
    head = rpc("eth_getBlockByNumber", ["latest", False])
    log(f"# P6g e2e on chain {chain}, {time.strftime('%Y-%m-%d %H:%M:%S %z')}; genesis {g['hash']}; head "
        f"{int(head['number'], 16)}, gasLimit {int(head['gasLimit'], 16):,}, baseFee {int(head['baseFeePerGas'], 16)}")
    check(chain == 7622, "chain id 7622")
    sd, sr, se = Sender(kd), Sender(kr), Sender(ke)
    VERIFIER[0] = sd
    log(f"deployer {sd.addr} (key {kd}), relayer {sr.addr} (key {kr}), envelope signer {se.addr} (key {ke})")
    log("PQZ tokens: " + ("OFFCHAIN on zero-dep releases (deps = [0x0]), verifier UA the deployer EOA, transferable, a "
                          "signed PqzVerdict per proof" if ZERO_DEP else "PRECOMPILE, the empty verdict"))
    st = call(PQZ, bytes.fromhex("0600000000"))
    want = json.load(open(os.path.join(K.VEC_DIR, "selftest.json")))["hash"]
    check(st[2:] == want, f"PQZ OP_SELFTEST = {st[:18]}… (set {K.SET})")
    pq = PQ()
    D = Deployer(sd)

    # -------------------------------------------------------------- 1. verifiers, registry gen 1, factory, tokens
    log("\n## 1. deploy (P6g plan D15)")
    ext = json.load(open(os.path.join(ROOT, "smartcontracts/vectors/ua/pq_signatures.json")))
    mlv = {}
    for kind, at, lvl, pkl, sgl in ((MLDSA44, ML44, 44, 1312, 2420), (MLDSA65, ML65, 65, 1952, 3309)):
        k = next(x for x in ext["kinds"] if x["name"] == f"mldsa{lvl}")
        pk, sg = bytes.fromhex(k["keyData"][2:]), bytes.fromhex(k["pop"]["sig"][2:])
        valid = pk + sg + kc(TAG[kind], bytes.fromhex(k["pop"]["message"][2:]))
        bad = bytearray(valid)
        bad[pkl + 7] ^= 1
        v = D.deploy("UAMldsaVerifier", encs(["w", "w", "b", "b"], [kind, at, valid, bytes(bad)]), src="MlDsa",
                     label=f"UAMldsaVerifier {lvl}")
        got = words(call(v, cd("PRECOMPILE()", [])))[0][12:]
        check("0x" + got.hex() == at.lower(), f"UAMldsaVerifier({kind:#06x}).PRECOMPILE() = 0x{got.hex()} (probe passed)")
        mlv[kind] = v
    # the set's self-test R_REG vector (UAPqzVerifier's pinned probe, PqzSet.PROBE_PQZL; review 8d1 N1: per set).
    # --zero-dep KEEPS UAPqzVerifier and the registry's 0x0142 slot: only the releases' env drops it (deps = [0x0]). The
    # registry side of this run is unchanged (every holder registers with its R_REG proof, storePqzPop, the 0x0142 list
    # checks, `pqz_key`'s proven key), and that needs the verifier, so the run still needs the PQZ precompile chain; what
    # --zero-dep runs is the token side of a chain without one (an OFFCHAIN token never calls the precompile). On a chain
    # without the precompile UAPqzVerifier cannot pass its self-test: there the registry has no 0x0142 kind and the holders'
    # keys stay unproven (an OFFCHAIN token takes them, spec §6), a registration form this script does not build.
    reg_stmt = bytes.fromhex(json.load(open(os.path.join(K.VEC_DIR, "statement_register.json")))["rows"][0]["stmt"])
    reg_proof = bytes.fromhex(json.load(open(os.path.join(K.VEC_DIR, "proof_pqzl.json")))["rows"][4]["proof"])
    pqv = D.deploy("UAPqzVerifier", encs(["w", "w", "b", "w", "b"], [PQZ, PQZL_ID, reg_stmt[96:], reg_stmt[64:96], reg_proof]),
                   label="UAPqzVerifier PQZL")
    check(words(call(pqv, cd("isSupportedOnThisChain()", [])))[0][-1] == 1, "UAPqzVerifier.isSupportedOnThisChain()")
    secv = D.deploy("Secp256k1Verifier", b"", label="Secp256k1Verifier")
    kinds = [(MLDSA44, mlv[MLDSA44], CAP_ML), (MLDSA65, mlv[MLDSA65], CAP_ML), (PQZ_MLWE, pqv, CAP_PQZ),
             (SECP256K1, secv, 50_000)]
    require_release_gas("UARegistry")
    require_release_gas("UARegistryCoreLib")  # D.deploy links both (D.linked)
    require_release_gas("UARegistryAuxLib")
    reg = D.deploy("UARegistry", encs(["w", "w", "w", "w", "w", "w", ("a", ("t", ["w", "w", "w"]))],
                                      [uid, 0, 0, BUDGET, 0, 1, kinds]), label="UARegistry gen 1")
    REG[0] = reg
    # plan T11 (CTR-GOV-15 Change): a GovernanceRouter (chain_uid, registry, SmartKeyAccount implementation 0, Hedera false)
    # before every release, each env naming it as govRouter. By CREATE2 as DeployBase (governance spec §3.1); on this run's
    # own registry (it carries the pqz-mlwe kind, the deploy JSON's has none), so it is not the deploy JSON's router: the
    # node lists both in `governance_routers` (RUNBOOK); JSON key `governance_router` of deployments/7622-pqz.json
    router = D.deploy2("GovernanceRouter", encs(["w", "w", "w", "w"], [uid, reg, 0, 0]), label="governance_router")
    # plan 5g-Z2: the factory (notice period 0 here) deploys every release itself: env version 1 of each kind
    # (factory, chain_uid, registry, SmartKeyAccount implementation 0, Hedera false, deps, the linked libraries with
    # their code hashes, the GovernanceRouter above (the PQZ kinds link the four PqzStateLib / PqzTransferLib / PqzBurnLib / PqzViewLib, plan 5h D14,
    # each deployed once by D.lib; the PQZ kinds' one dependency is this run's UAPqzVerifier, CTR-ZTH-20), then the release
    # from the init code without arguments on env 1, named explicitly (owner 2026-10-20; the factory appends
    # envVersion, env, implArgs)
    # chain-neutral releases (plan T71): the registrar the only constructor argument, then this chain's values once
    # (configureChain: chain_uid, notice period 0, the router above, a reference block of this chain, Fable P1-1)
    fac = D.deploy("OpenFactory", encs(["w"], [sd.addr]))
    ref = int(rpc("eth_blockNumber", []), 16) - 1
    ref_hash = bytes.fromhex(rpc("eth_getBlockByNumber", [hex(ref), False])["hash"][2:])
    sd.send(fac, cd("configureChain(bytes32,uint64,address,uint256,bytes32)", ["w"] * 5, uid, 0, router, ref, ref_hash),
            "configureChain")
    # ua-mtx-merge T31 (regulated-kinds spec §6.1): the regulated PQZ kinds 12, 13 too, each on its base kind's env with
    # `RegulatedLib` in the link closure (D.linked finds it), `implArgs` = abi.encode(REGISTRY_CODEHASH), the canonical
    # `ComplianceRegistry` runtime's code hash (F-11); this run creates no regulated token (the regulated rows are the forge
    # suites test/as/confidential/Pqz*: a token naming a registry needs one deployed with COMPLIANCE_ADMIN, plan T33)
    for kind, name in RELEASES:
        if kind in SKIP_KINDS:
            log(f"SKIP  release of kind {kind} {name} (--skip-kind): no token of it in this run")
            continue
        require_release_gas(name)
        code, libs = D.linked(name)
        # T66b §4.5: the kind's body modules (CREATE2, the kind's own constructor arguments), each pinned in the env after
        # the libraries of the closure (theirs included), and named in the release's `implArgs`
        ms = []
        for src, mn in kind_modules(kind):
            require_release_gas(mn)
            _, ml = D.linked(mn, src)
            libs += [x for x in ml if x not in libs]
            ms.append(D.deploy2(mn, encs(["w", "b"], [fac, core_args(kind)]), f"module {mn}", src=src))
        libs += ms
        hashes = [keccak256(bytes.fromhex(rpc("eth_getCode", [a, "latest"])[2:])) for a in libs]
        # group 3f (spec §3 C6): --zero-dep publishes the PQZ kinds on deps = [0x0], where only an OFFCHAIN token can be
        # created (a PRECOMPILE one reverts SelfTestFailed(address(0)))
        env = [reg, 0, 0, ([0] if ZERO_DEP else [pqv]) if kind else [], [], libs, hashes]
        sd.send(fac, cd(f"publishEnv(uint8,uint16,{ENV_S})", ["w", "w", ENV], kind, 1, env), f"publishEnv(kind {kind}, 1)")
        r = sd.send(fac, cd("deployImplementation(uint8,uint64,uint16,bytes,bytes)", ["w", "w", "w", "b", "b"],
                               kind, 1, 1, code, impl_args(kind, ms)),
                    f"deployImplementation(kind {kind}, 1) {name}")
        lg = next(x for x in r["logs"] if x["address"].lower() == fac.lower() and len(x["topics"]) == 4)
        log(f"      {name} release at 0x{lg['topics'][3][-40:]} ({int(r['gasUsed'], 16):,} gas)")
    for kind in [k for k, _ in RELEASES if k and k not in SKIP_KINDS]:
        sd.send(fac, cd("setKindEnabled(uint8,bool)", ["w", "w"], kind, 1), f"setKindEnabled({kind}, true)")

    # -------------------------------------------------------------- 2. UAs
    log("\n## 2. UAs: ML-DSA UAs and PQZ holders (ML-DSA UA + pqz-mlwe key attribute, real R_REG proofs)")

    def ml_ua(name, kind, seed):
        lvl = 44 if kind == MLDSA44 else 65
        pk = pq.ml_pk(lvl, seed)
        ua = words(call(reg, cd("uaOf(uint16,bytes)", ["w", "b"], kind, pk)))[0]
        u = UA(name=name, kind=kind, seed=seed, pk=pk, ua=ua)
        pop = pq.ml_sign(lvl, seed, kc(TAG[kind], portable("pop", kind=kind, ua=ua)))
        sd.send(reg, register_cd(reg_args(kind, pk, pop=pop)["args"]),
                f"register {name} (mldsa{lvl}, seed {seed.hex()[:8]}…)")
        return u

    def pqz_ua(name, seed, mlseed):
        """A PQZ holder (UA-6, UA-8): an ML-DSA-65 UA with the pqz-mlwe key and KEM v0 as attributes; ONE register call, or
        `register` without the proof + `storePqzPop` when the full call does not fit the chain's block."""
        pk, s, e, _ = K.keygen(seed)
        mlpk = pq.ml_pk(65, mlseed)
        ua = words(call(reg, cd("uaOf(uint16,bytes)", ["w", "b"], MLDSA65, mlpk)))[0]
        kem = b"\x01" + (kc("kem", mlseed) * 50)[:1600]  # the register KEM key, version 0 (owner 2026-10-31; scheme byte 1 + any 1,600 bytes here)
        proof = pq.prove(3, K.build_register(portable("reg", kind=MLDSA65, ua=ua, pqzKey=pk, kemPk=kem), pk), K.i8(s) + K.i16(e))
        ph = kc(proof)
        pop = pq.ml_sign(65, mlseed, kc(TAG[MLDSA65], portable("pop", kind=MLDSA65, ua=ua, pqzKey=pk, pqzPopHash=ph,
                                                                  kemPk=kem)))
        # typed-signing R1: clientkeys `registrationArgs` (the KEM key in full, or its hash commit + the `setKemKey` v0 fill
        # when the full call is over one transaction's calldata); the same pop signs both forms
        register_holder(name, ua, reg_args(MLDSA65, mlpk, pqzKey=pk, pqzPop=proof, kemPk=kem, pop=pop), proof, kem, MLDSA65, register_cd)
        return UA(name=name, kind=MLDSA65, seed=mlseed, pk=pk, s=s, e=e, ua=ua)

    def register_holder(name, ua, g, proof, kem, kind, build):
        """ONE register call, or the entry without the proof + `storePqzPop` when the full call does not fit the chain's
        block; `build` = `register_cd` / `register_msig_cd`."""
        ph = kc(proof)
        check(hb(g["args"]["attrs"]["pqzPopHash"]) == ph, f"{name} registrationArgs: pqzPopHash = keccak256(proof)")
        full_cd = build(g["args"])
        full = not SPLIT and full_register_fits(reg, full_cd)
        sd.send(reg, full_cd if full else build(g["args"], b""),
                f"{g['entry']} {name} ({kind:#06x} + pqz-mlwe key{(' + KEM v0' + (' hash commit' if g['kemFill'] else '')) if kem else ''}, R_REG "
                f"{len(proof):,} B, {'one call' if full else 'proof by storePqzPop'})")
        if not full:
            sd.send(reg, cd("storePqzPop(bytes32,uint64,bytes)", ["w", "w", "b"], ua, 0, proof), f"storePqzPop {name}")
        if g["kemFill"]:
            f = g["kemFill"]
            sd.send(reg, cd(SET_KEM, SET_KEM_T, hb(f["ua"]), 0, kem_v(f["kem"]), sig_v(f["sig"])),
                    f"setKemKey {name} v0 (fills the hash commit, no signature)")
        rec = words(call(reg, cd("recordOf(bytes32)", ["w"], ua)))
        check(int.from_bytes(rec[-1], "big") != 0, f"{name} = {ua.hex()[:16]}… recordOf: PQZ key pointer set")
        pk_of = words(call(reg, cd("pqzKeyOf(bytes32)", ["w"], ua)))
        check(pk_of[2] == ph and int.from_bytes(pk_of[3], "big") == 1 and int.from_bytes(pk_of[0], "big") == 0,
              f"{name} pqzKeyOf: version 0 current, proof hash set, proven")
        check([int.from_bytes(w, "big") for w in words(call(reg, cd("checkedOf(bytes32)", ["w"], ua)))] == [1, 1, 1 if kem else 0],
              f"{name} checkedOf = (chain, chain, {'chain' if kem else 'none'})")
        check(kem_of_ret(call(reg, cd("kemKeyOf(bytes32)", ["w"], ua))) == (0, kem, b""), f"{name} kemKeyOf = (0, kem, \"\")")
        check(int.from_bytes(words(call(reg, cd("kindOf(bytes32)", ["w"], ua)))[0], "big") == kind, f"{name} kindOf {kind:#06x}")

    def msig_ua(name, seed):
        """A PQZ holder that is an msig (UA-8, TS-D10): 2-of-2 over two new ML-DSA-65 UAs, sorted by id, `registerMsig` with their
        PoP signatures; both sign its `UASig`s. No KEM key (CTR-UA-32, plan T66a: an msig holds none; a sender seals to each
        member's own key): the registry refuses one, `UAKemHolder`, checked here before the registration."""
        ms = sorted((ml_ua(f"{name}-m{i}", MLDSA65, sk(f"ml-{name}{i}")) for i in range(2)), key=lambda u: u.ua)
        keyData = hb(_ck("msig", threshold=2, members=[dict(kind=MLDSA65, id=js(m.ua), weight=1) for m in ms]))
        ua = words(call(reg, cd("uaOf(uint16,bytes)", ["w", "b"], MSIG, keyData)))[0]
        pk, s, e, _ = K.keygen(seed)
        proof = pq.prove(3, K.build_register(portable("reg", kind=MSIG, ua=ua, pqzKey=pk, kemPk=b""), pk), K.i8(s) + K.i16(e))
        md = hb(_ck("popmd", kind=MSIG, ua=ua, keyData=keyData, pqzKey=pk, pqzPopHash=kc(proof), kemPk=b""))
        pop = [dict(index=i, sig=js(ml_sig(pq, m, P_MEMBER, md)[1])) for i, m in enumerate(ms)]
        g = reg_args(MSIG, keyData, pqzKey=pk, pqzPop=proof, kemPk=b"", pop=pop)
        k = b"\x01" + (kc("kem", seed) * 50)[:1600]
        with_kem = dict(g["args"], attrs=dict(g["args"]["attrs"], kem={"scheme": 1, "mlkemEk": "0x" + k[1:-32].hex(), "x25519": "0x" + k[-32:].hex()}))
        try:
            call(reg, register_msig_cd(with_kem, b""))
            check(False, f"{name}: registerMsig with a KEM key is refused (UAKemHolder)")
        except RuntimeError:
            check(True, f"{name}: registerMsig with a KEM key is refused (UAKemHolder, CTR-UA-32)")
        register_holder(name, ua, g, proof, b"", MSIG, register_msig_cd)
        w = words(call(reg, cd("msigOf(bytes32)", ["w"], ua)))  # head offset, threshold, array offset, n, (kind, id, weight) ...
        check(int.from_bytes(w[1], "big") == 2 and [w[5], w[8]] == [m.ua for m in ms], f"{name} msigOf: 2-of-2, the members in index order")
        return UA(name=name, kind=MSIG, pk=pk, s=s, e=e, ua=ua, members=ms)

    sk = lambda tag: kc("p6g-e2e-7622/", tag)  # noqa: E731  (test seeds, in this log on purpose)
    log(f"test seeds: keccak256('p6g-e2e-7622/<name>')")
    ml44 = ml_ua("mldsa44-ua", MLDSA44, sk("ml44"))
    feeua = ml_ua("fee-ua", MLDSA65, sk("fee"))
    U = {n: pqz_ua(n, sk("pqz-" + n), sk("ml-" + n)) for n in ("alice", "bob", "aud", "carol")}
    alice, bob, aud, carol = U["alice"], U["bob"], U["aud"], U["carol"]
    # UA8-D5: a second KEM record, signed by the holder (real ML-DSA-65) over the portable KEM message
    kem2 = b"\x01" + (kc("kem2", alice.seed) * 50)[:1600]  # scheme 1
    ksig = pq.ml_sign(65, alice.seed, kc(TAG[MLDSA65], portable("kem", kind=MLDSA65, ua=alice.ua, kemVersion=2, kemPk=kem2)))
    sd.send(reg, cd(SET_KEM, SET_KEM_T, alice.ua, 2, kem_key(kem2), [b"", ksig, []]), "setKemKey v2 (alice, ML-DSA-65 sig)")
    check(kem_of_ret(call(reg, cd("kemKeyOf(bytes32)", ["w"], alice.ua))) == (2, kem2, ksig), "alice kemKeyOf: version 2, its key and sig")
    # ruling A1-I1 (review m2): a PQZ key added later to a UA registered without one — `setPqzKey` signed by the UA (real
    # ML-DSA-65) over `uaMessage(0x0131, PURPOSE_PQZ_KEY, pqzKeyRecordDigest(pqzKeyDigest(ua, h), ph))`, then a third
    # party's `storePqzPop` with the real R_REG over `uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest(ua, h))`
    dave = ml_ua("dave", MLDSA65, sk("ml-dave"))
    dpk, ds, de, _ = K.keygen(sk("pqz-dave"))
    dproof = pq.prove(3, K.build_register(portable("keyreg", ua=dave.ua, pqzKey=dpk), dpk), K.i8(ds) + K.i16(de))
    dph = kc(dproof)
    dsig = pq.ml_sign(65, dave.seed, kc(TAG[MLDSA65], portable("keyrec", kind=MLDSA65, ua=dave.ua, pqzKey=dpk, pqzPopHash=dph)))
    sd.send(reg, cd(SET_PQZ, SET_PQZ_T, dave.ua, 0, dpk, dph, [b"", dsig, []]),
            "setPqzKey dave (ML-DSA-65 sig over PURPOSE_PQZ_KEY)")
    w = words(call(reg, cd("pqzKeyOf(bytes32)", ["w"], dave.ua)))
    check(w[2] == dph and int.from_bytes(w[3], "big") == 0, "dave pqzKeyOf: the added key's proof hash, unproven")
    check(dec_bytes(call(reg, cd("pqzKeySigOf(bytes32,uint64)", ["w", "w"], dave.ua, 0))) == dsig,
          "dave pqzKeySigOf(0) = the setPqzKey signature")
    sd.send(reg, cd("storePqzPop(bytes32,uint64,bytes)", ["w", "w", "b"], dave.ua, 0, dproof),
            f"storePqzPop dave (R_REG {len(dproof):,} B over PURPOSE_PQZ_KEY)")
    w = words(call(reg, cd("pqzKeyOf(bytes32)", ["w"], dave.ua)))
    check(w[2] == dph and int.from_bytes(w[3], "big") == 1, "dave pqzKeyOf: proven")
    check([int.from_bytes(x, "big") for x in words(call(reg, cd("checkedOf(bytes32)", ["w"], dave.ua)))] == [1, 1, 0],
          "dave checkedOf = (chain, chain, none)")
    check(pqz_key(dave.ua) == dpk, "dave: the key a PQZ token reads (pqzKeyOf, proven) is the added key")
    dave.pk, dave.s, dave.e = dpk, ds, de  # version 0's key (group 3g: the rotation of §6c)
    # op 7 decoys (P6g op 7): five more PQZ holders
    DEC = [pqz_ua(f"decoy{i}", sk(f"pqz-decoy{i}"), sk(f"ml-decoy{i}")) for i in range(5)]

    # secp256k1 (ECDSA, 0x0108; CTR-UA-06, owner 2026-10-17): a secp256k1 key registers a derived id, separate from
    # its EOA address and the same on every chain
    seck = int.from_bytes(sk("secp256k1"), "big") % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    x, y = _mul(seck)
    secd = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    sec_ua = words(call(reg, cd("uaOf(uint16,bytes)", ["w", "b"], SECP256K1, secd)))[0]
    check(sec_ua == kc(TAG[SECP256K1], secd), "secp256k1 UA = keccak256(TAG ‖ x ‖ y)")
    sd.send(reg, register_cd(reg_args(SECP256K1, secd, pop=ecdsa(seck, portable("pop", kind=SECP256K1, ua=sec_ua)))["args"]),
            "register secp256k1 (ECDSA PoP)")
    kind = int.from_bytes(words(call(reg, cd("kindOf(bytes32)", ["w"], sec_ua)))[0], "big")
    check(kind == SECP256K1, f"secp256k1 UA {sec_ua.hex()[:16]}… kindOf 0x0108; the same key's EOA {address(seck)} is a "
                             f"separate native id")
    d = kc("p6g-gas")
    data = cd(REQ_AUTH, REQ_AUTH_T, sec_ua, P_METATX, d, [secd, ecdsa(seck, ua_msg(SECP256K1, P_METATX, d)), []])
    call(reg, data)
    log(f"      gas registry.requireAuthorized(secp256k1) = {gas_of(reg, data):,} (eth_estimateGas, incl. 21,000 "
        f"intrinsic and calldata)")
    bad = [secd, ecdsa(seck, ua_msg(SECP256K1, P_METATX, kc("other"))), []]
    try:
        call(reg, cd(REQ_AUTH, REQ_AUTH_T, sec_ua, P_METATX, d, bad))
        check(False, "secp256k1 signature over another digest is refused")
    except RuntimeError:
        check(True, "secp256k1 signature over another digest is refused (UAUnauthorized)")

    # the per-kind list (CTR-UA-29, owner 2026-10-17): every UA of a kind in registration order; dave (registered after
    # carol, before the decoys) joins the 0x0131 list at his ML-DSA-65 register and the 0x0142 list when storePqzPop
    # proves his key (setPqzKey alone lists nothing, UA8-D8; first real-node run 2026-10-31: fs3 Task 13)
    for kind, uas in ((PQZ_MLWE, [u.ua for u in list(U.values()) + [dave] + DEC]),
                      (MLDSA65, [u.ua for u in [feeua] + list(U.values()) + [dave] + DEC]),
                      (MLDSA44, [ml44.ua]), (SECP256K1, [sec_ua])):
        n = int.from_bytes(words(call(reg, cd("uaCount(uint16)", ["w"], kind)))[0], "big")
        at = [words(call(reg, cd("uaAt(uint16,uint256)", ["w", "w"], kind, i)))[0] for i in range(n)]
        # uaIndex is the UA's position in its own kind list; the 0x0142 list has no reverse index (spec U11)
        idx = list(range(n)) if kind == PQZ_MLWE else [int.from_bytes(words(call(reg, cd("uaIndex(bytes32)", ["w"], ua)))[0], "big") for ua in uas]
        page = call(reg, cd("uaPage(uint16,uint256,uint256)", ["w", "w", "w"], kind, 0, 100))
        check(n == len(uas) and at == uas and idx == list(range(n)) and (len(page) - 2) // 2 == 64 + 32 * n and words(page)[2:] == uas,
              f"registry list of kind {kind:#06x}: uaCount {n}, uaAt / uaIndex (kind lists) in registration order, uaPage {n} ids")

    # an msig PQZ holder (after the lists above: its two members join 0x0131, it joins 0x0120 and 0x0142)
    erin = msig_ua("erin", sk("pqz-erin"))
    check(words(call(reg, cd("uaAt(uint16,uint256)", ["w", "w"], MSIG, 0)))[0] == erin.ua, "registry list of kind 0x0120: erin")
    check(pqz_key(erin.ua) == erin.pk, "erin: the key a PQZ token reads is the msig's")

    # ML-DSA verify gas through the registry (both levels, precompile path)
    for u in (ml44, U["alice"]):
        d = kc("p6g-gas")
        data = cd(REQ_AUTH, REQ_AUTH_T, u.ua, P_METATX, d, ml_sig(pq, u, P_METATX, d))
        call(reg, data)
        log(f"      gas registry.requireAuthorized(mldsa{44 if u.kind == MLDSA44 else 65}) = {gas_of(reg, data):,} "
            f"(eth_estimateGas, incl. 21,000 intrinsic and calldata)")

    # -------------------------------------------------------------- 3. tokens
    log("\n## 3. tokens")

    def create(kind, name, sym, legs, dmode, amode, feat, supply=0, holder=0, conf=True, salt=b"p6g", issuer=0, store=None):
        aud_key = aud.ua if amode else b""
        # group 3f (AV-2): pqzVerifyMode, pqzVerifierUA, pqzVerifierFixed: PRECOMPILE (0, 0, false), or with --zero-dep
        # OFFCHAIN with the deployer EOA (a native id, its padded address) as a transferable verifier
        mode = [1, pad(sd.addr), 0] if ZERO_DEP else [0, 0, 0]
        mode += [PROOF_STORE if store is None else store]  # group 3h T60: proofStore, NONE unless --proof-store log
        c = [name, sym, 6, feat, 0, sd.addr, [sd.addr if feat & 2 else 0, 0, 0, issuer, 0], supply, holder, legs, [0, 0],
             [aud_key, SCALE, MAXS, FEE, dmode, amode, MIN_DECOY] + mode if conf else [b""] + [0] * 10, 0, 0, 0, [0, 0, 0, 0, 0]]
        # plan 5g-Z2: initArgs = abi.encode(TokenConfig), opaque to the factory; the verifier is the release's
        data = cd("createToken(uint8,uint64,bytes,bytes32)", ["w", "w", "b", "w"], kind, 1, encs([CFG], [c]), kc(salt))
        r = sd.send(fac, data, f"createToken {sym} (kind {kind})")
        lg = next(x for x in r["logs"] if x["address"].lower() == fac.lower())
        t = "0x" + lg["topics"][1][-40:]
        log(f"      {sym} at {t}")
        got = [int.from_bytes(x, "big") for x in words(call(t, cd("pqzVerifyConfig()", [])), 4)] if conf else []
        check(not conf or got == [mode[0], int.from_bytes(W(mode[1]), "big"), 0, 0],
              f"{sym} pqzVerifyConfig (mode, verifier, fixed_, epoch) = {[hex(x) for x in got]}")
        D.addr[sym] = t
        return t

    # the leg: a plain ERC-20 (SCaaS tokens give no allowance to an EOA, CTR-TOK-01); test/helpers/Mocks.sol
    tusd = D.deploy("MockERC20", encs(["b", "b", "w"], ["Test USD", "tUSD", 6]), src="Mocks", label="tUSD (MockERC20)")
    sd.send(tusd, cd("mint(address,uint256)", ["w", "w"], sd.addr, 10**12), "tUSD mint")
    t1 = create(4, "PQZ USD", "pqUSD", [], 0, 1, 1 | 2 | 4, salt=b"pq1")  # BUNDLE, FULL auditor, PAYABLE|MINTABLE|BURNABLE
    t2 = create(5, "PQZ wrapped tUSD", "pqW", [[tusd, 1, 1]], 1, 2, 1, salt=b"pq2")  # COMPACT, OPTIONAL
    if PROOF_PATH_ONLY:  # group 3h T65: sections 1-3, then the proof path alone
        proof_path(pq, sd, reg, create, U, aud, DEC, sk, tusd)
        log(f"elapsed {time.time() - t0:.0f} s")
        return

    # -------------------------------------------------------------- 4. the NORMAL_PQZ life cycle with real proofs
    log("\n## 4. NORMAL_PQZ (pqUSD: BUNDLE, auditor FULL): shield, transfer, rollover by count, hint, burn, refresh, disclosure")
    C1 = Client(t1, "pqUSD")
    sd.send(t1, cd("mint(address,uint256)", ["w", "w"], sd.addr, 5_000 * SCALE), "pqUSD mint 5,000 public")
    sd.send(t1, cd(API["shield"], ["w", "w"], alice.ua, 1_000), "mtxShield(alice, 1,000): no proof, free, into the pool")
    C1.set_next(bal=[(alice, 1_000)], total=1_000)
    C1.commit()
    st = C1.state(alice)
    w0 = int(call(t1, cd("pqzPending(bytes32,uint64,uint64)", ["w", "w", "w"], alice.ua, 0, 0)), 16)
    check(st["pendingCount"] == 1 and (w0 >> 64) & 0xFFFF == 0 and (w0 >> 96) & (2**64 - 1) == 1000,
          "alice pending[0] is a TRIVIAL entry of 1,000 (raw slot: vOff 0, amount in the blob field)")
    check_public(C1, "after the shield")

    xfer = lambda *a, **k: transfer(pq, sd, C1, *a, **k)  # noqa: E731
    r1, ref1, bundle1, enc1 = xfer(alice, bob, carol, 300, True, "mtxConfidentialTransferSingle alice→bob 300, txFee 3 to carol")
    rollover(sd, C1, bob, 1, "bob's first credit")
    xfer(bob, alice, b"\0" * 32, 100, True, "mtxConfidentialTransferSingle bob→alice 100 (no fee; accHint = the materialised acc)")
    xfer(alice, bob, b"\0" * 32, 50, True, "mtxConfidentialTransferSingle alice→bob 50, shieldIn 25, 1 inline entry (p ≥ rolled)",
         shield_in=25)
    burn(pq, sd, C1, alice, 200, sd.addr, "mtxUnshield alice burns 200 → deployer")
    burn(pq, sd, C1, alice, 0, None, "mtxUnshield refresh (amount 0)")
    pub = int.from_bytes(words(call(t1, cd("balanceOf(address)", ["w"], sd.addr)))[0], "big")
    check(pub == (5_000 - 1_000 - 25 + 200) * SCALE, f"deployer public pqUSD = {pub:,} (4,000 − 25 shieldIn + the 200 burnt back)")
    check_public(C1, "after the burns")
    restore(C1, "section 4")

    log("disclosure of the first transfer (view, verifyTransferAmount; the opening is the proof alone, R from the op blob):")
    for kind, op, wit in ((0, 4, K.i8(enc1[0]) + K.i16(enc1[1]) + K.i16(enc1[2][0])),
                          (1, 5, K.i8(bob.s) + K.i16(bob.e)), (2, 5, K.i8(aud.s) + K.i16(aud.e))):
        stmt = dec_bytes(call(t1, cd(API["discStmt"], ["w", "w", "w", "w", "w"], ref1, 0, 300, kind, 0)))
        proof = pq.prove(op, stmt, wit)
        sv = verdict(t1, stmt, proof)
        data = amount_cd(ref1, 0, 300, kind, 0, proof, sv)
        okw = int(call(t1, data), 16)
        bad = int(call(t1, amount_cd(ref1, 0, 301, kind, 0, proof, sv)), 16)
        check(okw == 1 and bad == 0, f"verifyTransferAmount kind {kind} (op {op}): 300 ⇒ true, 301 ⇒ false; "
                                     f"eth_estimateGas {gas_of(t1, data):,}")

    # -------------------------------------------------------------- 4b. op 7 on pqUSD (BUNDLE, auditor FULL)
    log("\n## 4b. op 7 multi-recipient transfer on pqUSD: M = 4 (one real leg, three decoys), txFee + decoyFee, disclosure by leg")
    legs4 = [(carol, 0), (bob, 40), (DEC[0], 0), (DEC[1], 0)]
    _, ref7, bundle7, enc7 = transfer_multi(pq, sd, C1, alice, legs4, carol, True,
                                            f"mtxConfidentialTransfer (op 7) alice→[carol 0, bob 40, decoy0 0, decoy1 0], "
                                            f"txFee 3 to carol, decoyFee {DEC_FEE} per leg")
    for kind, op, wit in ((0, 4, K.i8(enc7["rs"][0]) + K.i16(enc7["e1s"][0]) + K.i16(enc7["e2"][1])),
                          (1, 5, K.i8(bob.s) + K.i16(bob.e)), (2, 5, K.i8(aud.s) + K.i16(aud.e))):
        stmt = dec_bytes(call(t1, cd(API["discStmt"], ["w", "w", "w", "w", "w"], ref7, 1, 40, kind, 0)))
        proof = pq.prove(op, stmt, wit)
        sv = verdict(t1, stmt, proof)
        okw = int(call(t1, amount_cd(ref7, 1, 40, kind, 0, proof, sv)), 16)
        bad = int(call(t1, amount_cd(ref7, 1, 41, kind, 0, proof, sv)), 16)
        other = int(call(t1, amount_cd(ref7, 0, 40, kind, 0, proof, sv)), 16)
        check(okw == 1 and bad == 0 and other == 0, f"op 7 leg 1 verifyTransferAmount kind {kind} (op {op}): 40 ⇒ true, "
                                                    f"41 ⇒ false, leg 0 ⇒ false")
    check_public(C1, "after op 7 (txFee to carol, decoyFee to every leg)")
    n = C1.state(bob)["pendingCount"] - C1.state(bob)["rolled"]
    rollover(sd, C1, bob, n, f"{n} pending credits (op 1 credit(s) and the op 7 leg)")
    transfer_multi(pq, sd, C1, bob, [(alice, 15), (DEC[2], 0)], b"\0" * 32, True,
                   "mtxConfidentialTransfer (op 7) bob→[alice 15, decoy2 0], the op 7 credit spent")
    check_public(C1, "after the second op 7")
    restore(C1, "section 4b")

    # -------------------------------------------------------------- 5. relayed through the generic merged entry (R47)
    log("\n## 5. relayed transfers through mtxExecute(UAMetaTransaction, UASig): an EOA (its own key, a FIXED outer fee, no "
        "registry call) and an mldsa65 fee UA; the proof binds the envelope's UA binding (D15, R36)")
    sd.send(t1, cd("mint(address,uint256)", ["w", "w"], se.addr, 10 * SCALE), "pqUSD mint 10 public to the envelope signer")
    nonce = int.from_bytes(words(call(t1, cd("mtxNonce(bytes32,uint256)", ["w", "w"], pad(se.addr), 0)))[0], "big")
    m = [pad(se.addr), b"", 0, nonce, int(time.time()) + 3600, 0x20, 0, 5 * SCALE, 0]
    b1 = words(call(t1, cd(f"envelopeBinding({UMTX_S})", [MTX], m)))[0]
    check(b1 == ua_binding(t1, CTX, m), "envelopeBinding of the EOA's envelope = ua_binding (from zero-padded, R36)")
    _, data, _, _ = transfer(pq, sd, C1, bob, alice, b"\0" * 32, 20, True, "v1", binding=b1, send=False)
    m[1] = data
    dg = words(call(t1, cd(f"mtxDigest({UMTX_S})", [MTX], m)))[0]
    sr.send(t1, cd(f"mtxExecute({UMTX_S},{UASIG_S})", [MTX, UASIG_T], m, [b"", ecdsa(se.key, dg), []]),
            "mtxExecute(mtxConfidentialTransferSingle bob→alice 20), the EOA's UASig, relayer pays gas")
    C1.commit()
    fee_got = int.from_bytes(words(call(t1, cd("balanceOf(address)", ["w"], sr.addr)))[0], "big")
    check(fee_got == 5 * SCALE, f"relayer received the outer fee {fee_got:,}")

    sd.send(t1, cd("mintToUA(bytes32,uint256)", ["w", "w"], feeua.ua, 10 * SCALE), "pqUSD mintToUA(fee UA, 10)")
    un = int.from_bytes(words(call(t1, cd("mtxNonce(bytes32,uint256)", ["w", "w"], feeua.ua, 0)))[0], "big")
    m = [feeua.ua, b"", 0, un, int(time.time()) + 3600, 0x20, 0, 2 * SCALE, 0]
    b3 = words(call(t1, cd(f"envelopeBinding({UMTX_S})", [MTX], m)))[0]
    check(b3 == ua_binding(t1, CTX, m), "envelopeBinding of the fee UA's envelope = ua_binding")
    _, data, _, _ = transfer(pq, sd, C1, alice, bob, b"\0" * 32, 10, True, "v3", binding=b3, send=False)
    m[1] = data
    dg = words(call(t1, cd(f"mtxDigest({UMTX_S})", [MTX], m)))[0]
    sr.send(t1, cd(f"mtxExecute({UMTX_S},{UASIG_S})", [MTX, UASIG_T], m, ml_sig(pq, feeua, P_METATX, dg)),
            "mtxExecute(mtxConfidentialTransferSingle alice→bob 10), mldsa65 fee UA pays 2 outer")
    C1.commit()
    left = int.from_bytes(words(call(t1, cd("balanceOfUA(bytes32)", ["w"], feeua.ua)))[0], "big")
    check(left == 8 * SCALE, f"fee UA public balance {left:,} after the outer fee")
    for u in (alice, bob):
        log(f"      {u.name}: {C1.state(u)}")
    check_public(C1, "after the relayed transfers")
    restore(C1, "section 5")

    # -------------------------------------------------------------- 5b. the named signed entries (TS-D14)
    log("\n## 5b. named relayed entries on pqUSD (the merged mtx<entry>, R1): the entry's own UA struct, an EOA's UASig, ML-DSA-65 and msig UASigs, and pqzAuth")
    for ua_, what in ((feeua, "fee UA"), (erin, "erin")):
        sd.send(t1, cd("mintToUA(bytes32,uint256)", ["w", "w"], ua_.ua, 20 * SCALE), f"pqUSD mintToUA({what}, 20)")
    sd.send(t1, cd("mint(address,uint256)", ["w", "w"], se.addr, 50 * SCALE), "pqUSD mint 50 public to the envelope signer")  # 5 left from section 5: 30 shielded, about 8 outer fees
    se0, fee0 = (int.from_bytes(words(call(t1, c))[0], "big") for c in (cd("balanceOf(address)", ["w"], se.addr), cd("balanceOfUA(bytes32)", ["w"], feeua.ua)))
    ad, ud, md = (lambda who=who: Signed(t1, who, pq, sr, SCALE) for who in (se, feeua, erin))

    def signed_shield(C, sg, to, v, what):
        sg.send("Shield", [to.ua, v], what)
        C.set_next(bal=[(to, v)], total=v)
        C.commit()

    signed_shield(C1, ad(), alice, 30, "signed mtxShield(alice, 30), the EOA's UASig")
    signed_shield(C1, ud(), alice, 7, "signed mtxShield(alice, 7), UASig, ML-DSA-65 (R47)")
    for u, sg, who in ((carol, ad, "signed mtxPrepareAcc / mtxRollOver"), (DEC[0], ud, "uaPrepareAcc / uaRollOver")):
        n = C1.state(u)["pendingCount"] - C1.state(u)["rolled"]
        rollover(sd, C1, u, n, who, signed=sg)
    xfer(bob, alice, ZERO32, 9, True, "named mtxConfidentialTransferSingle bob→alice 9", signed=ad())
    xfer(alice, bob, ZERO32, 8, True, "named mtxConfidentialTransferSingle alice→bob 8, ML-DSA-65", signed=ud())
    transfer_multi(pq, sd, C1, alice, [(bob, 6), (DEC[3], 0)], ZERO32, True, "named mtxConfidentialTransfer alice→[bob 6, decoy3 0]", signed=ad())
    transfer_multi(pq, sd, C1, alice, [(bob, 5), (DEC[3], 0)], ZERO32, True, "named mtxConfidentialTransfer alice→[bob 5, decoy3 0], ML-DSA-65", signed=ud())
    burn(pq, sd, C1, alice, 11, sd.addr, "named mtxUnshield alice 11 → deployer", signed=ad())
    burn(pq, sd, C1, alice, 12, sd.addr, "named mtxUnshield alice 12 → deployer, ML-DSA-65", signed=ud())
    sd.send(t1, cd(API["shield"], ["w", "w"], erin.ua, 50), "mtxShield(erin, 50)")
    C1.set_next(bal=[(erin, 50)], total=50)
    C1.commit()
    xfer(erin, bob, ZERO32, 4, True, "mtxConfidentialTransferSingle erin→bob 4, pqzAuth by the members")
    transfer_multi(pq, sd, C1, erin, [(bob, 3), (DEC[4], 0)], ZERO32, True, "named mtxConfidentialTransfer erin→[bob 3, decoy4 0], msig envelope and pqzAuth", signed=md())
    se1, fee1 = (int.from_bytes(words(call(t1, c))[0], "big") for c in (cd("balanceOf(address)", ["w"], se.addr), cd("balanceOfUA(bytes32)", ["w"], feeua.ua)))
    check(se0 - se1 == Signed.spent[t1, pad(se.addr)] + 30 * SCALE, f"envelope signer paid {se0 - se1:,}: its outer fees and its shield")
    check(fee0 - fee1 == Signed.spent[t1, feeua.ua] + 7 * SCALE, f"fee UA paid {fee0 - fee1:,}: its outer fees and its shield")
    check_public(C1, "after the named entries")
    restore(C1, "section 5b")

    # -------------------------------------------------------------- 6. WRAPPED_PQZ (COMPACT, auditor OPTIONAL)
    log("\n## 6. WRAPPED_PQZ (pqW over tUSD: COMPACT, auditor OPTIONAL): wrap-shield, R_TX0 commit-reveal, unshield-unwrap")
    C2 = Client(t2, "pqW")
    sd.send(tusd, cd("approve(address,uint256)", ["w", "w"], t2, 10**12), "tUSD approve pqW")
    sd.send(t2, cd(API["wrapShield"], ["w", "w", "w"], tusd, 500 * SCALE, alice.ua), "mtxWrapShield(tUSD 500, alice)")
    C2.set_next(bal=[(alice, 500)], total=500)
    C2.commit()
    transfer(pq, sd, C2, alice, bob, b"\0" * 32, 120, False, "mtxConfidentialTransferSingle alice→bob 120, auditor off (R_TX0), commit-reveal")
    rollover(sd, C2, bob, 1, "bob's credit")
    legs8 = [(bob, 30)] + [(u, 0) for u in [carol, aud] + DEC]
    transfer_multi(pq, sd, C2, alice, legs8, b"\0" * 32, False,
                   "mtxConfidentialTransfer (op 7) alice→M = 8 (bob 30, seven decoys), auditor off, commit-reveal (two groups)")
    before = int.from_bytes(words(call(tusd, cd("balanceOf(address)", ["w"], sd.addr)))[0], "big")
    burn(pq, sd, C2, bob, 70, sd.addr, "mtxUnshieldUnwrap bob 70 → deployer in tUSD", unwrap=(tusd, 70 * SCALE))
    after = int.from_bytes(words(call(tusd, cd("balanceOf(address)", ["w"], sd.addr)))[0], "big")
    check(after - before == 70 * SCALE, f"deployer received {after - before:,} tUSD from the leg")
    check_public(C2, "after the unwrap")
    res = int.from_bytes(words(call(tusd, cd("balanceOf(address)", ["w"], t2)))[0], "big")
    check(res >= C2.total * SCALE, f"pqW reserve {res:,} ≥ totalShielded·scale {C2.total * SCALE:,}")
    restore(C2, "section 6")

    # -------------------------------------------------------------- 6b. the named entries of the wrapped kind, no outer fee
    log("\n## 6b. named relayed entries on pqW (commit-reveal forms): fee 0")
    sg = lambda who: Signed(t2, who, pq, sr, 0)  # noqa: E731
    sg(sd).send("WrapShield", [tusd, 40 * SCALE, alice.ua], "signed mtxWrapShield(tUSD 40, alice)")
    C2.set_next(bal=[(alice, 40)], total=40)
    C2.commit()
    transfer(pq, sd, C2, alice, bob, ZERO32, 9, False, "named mtxConfidentialTransferSingleCompact alice→bob 9", signed=sg(sd))
    transfer_multi(pq, sd, C2, alice, [(bob, 5), (carol, 0)], ZERO32, False, "named mtxConfidentialTransferCompact alice→[bob 5, carol 0]", signed=sg(feeua))
    burn(pq, sd, C2, bob, 6, sd.addr, "named mtxUnshieldUnwrap bob 6 → deployer in tUSD", unwrap=(tusd, 6 * SCALE), signed=sg(sd))
    burn(pq, sd, C2, bob, 7, sd.addr, "named mtxUnshieldUnwrap bob 7 → deployer in tUSD", unwrap=(tusd, 7 * SCALE), signed=sg(feeua))
    check_public(C2, "after the named entries")
    restore(C2, "section 6b")

    rotation(pq, sd, reg, C1, dave, alice, sk)
    proof_path(pq, sd, reg, create, U, aud, DEC, sk, tusd)
    log("\n## addresses")
    for k, v in {**D.libs, **D.addr}.items():
        log(f"      {k}: {v}")
    with open(os.path.join(EVM, "deployments/7622-pqz.json") if os.path.isdir(os.path.join(EVM, "deployments"))
              else os.devnull, "w") as f:
        json.dump({**D.libs, **D.addr, "chain_uid": "0x" + uid.hex()}, f, indent=2)
    log(f"elapsed {time.time() - t0:.0f} s")


# ------------------------------------------------------------------ group 3g: a PQZ key rotation (T53)

def rotation(pq, s, reg, C, dave, payer, sk):
    """Group 3g T53 (spec §3.4's runbook, single-key form): dave (an `mldsa65` holder, version 0 added by `setPqzKey`) adds
    version 1 (a fresh key, `setPqzKey(ua, 1, …)` signed over typed `UAPqzKeyVersionRecord`, `storePqzPop(ua, 1, R_REG over typed
    `UAPqzKeyVersion`)`); a credit after the rotation lands in (dave, 1); the migration (op 1 from (dave, 0) to dave, proved with
    s_0) moves the version-0 balance; the receiver disclosure of the migration checks version 1's key (`keyVersion` 1). Real
    proofs on the local chain; never the live testnet stack."""
    log("\n## 6c. a PQZ key rotation (group 3g): version 1, a credit to it, the migration, the disclosure by version")
    transfer(pq, s, C, payer, dave, ZERO32, 3, False, f"{payer.name}→dave 3 before the rotation (version 0)")
    pk1, s1, e1, _ = K.keygen(sk("pqz-dave-v1"))
    proof = pq.prove(3, K.build_register(portable("keyverreg", ua=dave.ua, pqzKey=pk1, version=1), pk1), K.i8(s1) + K.i16(e1))
    ph = kc(proof)
    sig = pq.ml_sign(65, dave.seed, kc(TAG[MLDSA65], portable("keyverrec", kind=MLDSA65, ua=dave.ua, pqzKey=pk1, pqzPopHash=ph, version=1)))
    s.send(reg, cd(SET_PQZ, SET_PQZ_T, dave.ua, 1, pk1, ph, [b"", sig, []]), "setPqzKey dave version 1")
    s.send(reg, cd("storePqzPop(bytes32,uint64,bytes)", ["w", "w", "b"], dave.ua, 1, proof), f"storePqzPop dave version 1 ({len(proof):,} B)")
    w = words(call(reg, cd("pqzKeyOf(bytes32)", ["w"], dave.ua)))
    check(int.from_bytes(w[0], "big") == 1 and int.from_bytes(w[3], "big") == 1, "dave pqzKeyOf: version 1 current, proven")
    dave1 = UA(**{**dave.__dict__, "pk": pk1, "s": s1, "e": e1, "kv": 1, "name": "dave/v1"})
    dave1.prior = {0: dave}
    C.uas[dave.ua] = dave1  # the restore reads both versions (KV-6)
    n0 = C.state(dave)["pendingCount"]
    transfer(pq, s, C, payer, dave1, ZERO32, 4, False, f"{payer.name}→dave 4 after the rotation (lands in version 1)")
    check(C.state(dave1)["pendingCount"] == 1 and C.state(dave)["pendingCount"] == n0, "the credit is in (dave, 1), (dave, 0) unchanged")
    _, ref, _, _ = transfer(pq, s, C, dave, dave1, ZERO32, 3, False, "the migration: op 1 from (dave, 0) to dave (version 1), 3")
    check(C.state(dave1)["pendingCount"] == 2, "the migration's credit is in (dave, 1)")
    stmt = dec_bytes(call(C.tok, cd(API["discStmt"], ["w", "w", "w", "w", "w"], ref, 0, 3, 1, 1)))
    dproof = pq.prove(5, stmt, K.i8(s1) + K.i16(e1))
    okw = int(call(C.tok, amount_cd(ref, 0, 3, 1, 1, dproof, verdict(C.tok, stmt, dproof))), 16)
    check(okw == 1, "verifyTransferAmount of the migration's leg, RECEIVER_X under version 1's key: true")


# ------------------------------------------------------------------ ops

def sent_ref(rc, tok, sigs):
    """The entry reference (topic 1) of the transfer event the token emitted."""
    tops = {"0x" + kc(x).hex() for x in sigs}
    lg = next(x for x in rc["logs"] if x["address"].lower() == tok.lower() and x["topics"][0] in tops)
    return bytes.fromhex(lg["topics"][1][2:])


def transfer(pq, s, C, frm, to, ben, v, aud_on, what, binding=ZERO32, send=True, shield_in=0, signed=None, at=None):
    """A transfer at `p = pendingCount` (the client rule), `shieldIn` taken from the sender's public balance (D5/D18),
    proved over the token's own statement (a `(payload, binding)` view, T read from state); returns (receipt, calldata,
    bundle, (r, e1, e2)). The relayed binding is the envelope's: the view folds the mode itself (D15). `signed`: the named
    relayed entry of that envelope (the Compact one on a COMPACT token)."""
    tok = C.tok
    binding = signed.binding if signed else binding
    stt = C.state(frm)
    p = stt["pendingCount"] if at is None else at  # group 3h T65: `at` below `rolled` is an un-roll
    compact = int(call(tok, cd("disclosureMode()", [])), 16) == 1
    salt = os.urandom(16)
    sealed = os.urandom(2 + 40 * 1) if compact else b""  # op 7's encoding, M = 1 (CTR-PQZ-23); ponytail: body random (stored unread);
    # the CTR-ZTH-50 HKDF memo is the client's (P6h)
    fee = FEE if ben != b"\0" * 32 else 0
    ben_ua = ben.ua if isinstance(ben, UA) else ben
    blen = K.CT_BYTES + K.V_BYTES * (2 if aud_on else 1)
    v3 = K.PK_BYTES + K.V_BYTES  # `out` = u ‖ v_t ‖ v_f ‖ [v_a]
    hdr = lambda out: [p, 10**9, shield_in, frm.ua, kv_of(frm), to.ua, ben_ua, salt + bytes(16), OWN_TAG, out[:K.PK_BYTES], out[K.PK_BYTES:v3],  # noqa: E731
                       out[v3:v3 + K.V_BYTES], out[v3 + K.V_BYTES:], sealed]
    view = lambda t: dec_bytes(call(tok, cd(API["singleStmt"], [TRANSFER_T, "w"], t, binding)))  # noqa: E731
    st0 = view(hdr(probe(blen)))
    tOff = K.HEADER_BYTES + K.PK_BYTES * (3 if aud_on else 2)
    T = st0[tOff:tOff + K.CT_BYTES]
    b = bal(frm.s, T)
    rest = b - v - fee
    assert rest >= 0, (b, v, fee)
    aud_pk = None
    if aud_on:
        a_ua = bytes.fromhex(call(tok, cd("auditorUA()", []))[2:])
        aud_pk = pqz_key(a_ua)
    pks = [to.pk, frm.pk] + ([aud_pk] if aud_on else [])
    vals = [v, rest] + ([v] if aud_on else [])
    r_, e1, e2, _ = K.enc_sample(os.urandom(32), len(pks))
    u, vs = K.encrypt(pks, [K.digits(x) for x in vals], r_, e1, e2)
    out = u + b"".join(vs)
    pl = hdr(out)
    stmt = view(pl)
    check(stmt[tOff:tOff + K.CT_BYTES] == T and stmt[-len(out):] == out, f"{C.name} statement of {what}: T and out as built")
    wit = K.i8(frm.s) + K.i16(frm.e) + K.i8(r_) + K.i16(e1) + b"".join(K.i16(x) for x in e2) + bytes(K.digits(v)) + bytes(K.digits(rest))
    proof = pq.prove(1, stmt, wit)
    auth = ua_sig(pq, frm, P_ZAUTH, K.auth_digest(1, stmt))
    hint = C.hint(frm)
    sv = verdict(tok, stmt, proof)  # also in `data` for mtxExecute (send=False): its inner call takes the verdict too
    data = cd(API["transferSingle"], [TRANSFER_T] + AUTH_T + [SV_T], pl, proof, auth, hint, sv)
    log(f"      {what}: balance {b} → {rest} (+{v} to {to.name}, fee {fee}, shieldIn {shield_in}), p {p}, rolled {stt['rolled']}, "
        f"hint {len(hint)} B, proof {len(proof):,} B")
    # the client's next state: the sender's acc is the new reference u ‖ v_f; the credit is the recipient's
    C.set_next(bal=[(frm, shield_in - v - fee), (to, v)], pub=[(ben, FEE)] if fee else [], acc={frm.ua: u + vs[1]},
               total=shield_in - fee, accv=kv_of(frm))
    bundle = salt + pack(u + vs[0]) + (pack(vs[2]) if aud_on else b"") + to.ua  # R as stored (P46)
    if not send:
        return None, data, bundle, (r_, e1, e2)
    rc = (signed.send("PqzTransferSingleCompact" if compact else "PqzTransferSingle", [pl, proof, auth, hint], f"{C.name} {what}", sv)
          if signed else s.send(tok, data, f"{C.name} {what}"))
    C.commit()
    ref = sent_ref(rc, tok, API["ev_single"])
    blob = dec_bytes(call(tok, cd("pqzEntryBlob(bytes32)", ["w"], ref)))
    head, tag, kv = tail_of(blob)
    check(head == bundle + pack(vs[1]) and tag == OWN_TAG and len(kv) == 1 + (1 if aud_on else 0),
          f"{C.name} pqzEntryBlob(ref) = R ‖ v_f ‖ ownTag ‖ kv {kv} ‖ n as built, packed ({len(blob):,} B)")
    return rc, ref, bundle, (r_, e1, e2)


def kv_of(u):
    """The key version a debit, rollover or view of `u` names (group 3g): its `kv` once rotated, else 0."""
    return getattr(u, "kv", 0) if u is not None else 0


def key_at(u, v):
    """The holder of version `v` of `u`: `u` itself at its own version, else the form it rotated from (`rotation`)."""
    return u if v == kv_of(u) else u.prior[v]


def multi_args(p, frm, ben, decoy, salt, uas, g, aud_on, out, sealed, kv=0):
    """`PqzMultiArgs` of `out` = u_0 … u_{G−1} ‖ v_0 … v_{M−1} ‖ v_f ‖ [v_{a,0} … v_{a,M−1}]; each leg its UA and parts."""
    pk, vb, m = K.PK_BYTES, K.V_BYTES, len(uas)
    us = [out[pk * i:pk * (i + 1)] for i in range(g)]
    o = pk * g
    legs = [[uas[j], out[o + vb * j:o + vb * (j + 1)], out[o + vb * (m + 1 + j):o + vb * (m + 2 + j)] if aud_on else b""] for j in range(m)]
    return [p, 10**9, 0, frm, kv, ben, decoy, salt + bytes(16), OWN_TAG, us, legs, out[o + vb * m:o + vb * (m + 1)], sealed]


def transfer_multi(pq, s, C, frm, legs, ben, aud_on, what, signed=None, at=None):
    """An op 7 transfer (CTR-PQZ-26) at `p = pendingCount`, legs [(UA, amount)] (decoys: amount 0), proved over the
    token's own statement; header fee word `txFee + M · decoyFee` (the proof binds the decoyFee); returns (receipt,
    entryRef, bundle, enc). `signed` as in `transfer`."""
    tok = C.tok
    binding = signed.binding if signed else ZERO32
    stt = C.state(frm)
    p = stt["pendingCount"] if at is None else at  # group 3h T65: `at` below `rolled` is an un-roll
    m, g = len(legs), K.groups(len(legs), aud_on)  # R0-1: S_AUD legs per group with the auditor, 4 without
    compact = int(call(tok, cd("disclosureMode()", [])), 16) == 1
    salt = os.urandom(16)
    sealed = os.urandom(2 + 40 * m) if compact else b""  # ponytail: memo body random, as transfer()
    mind = int(call(tok, cd("minDecoyFee()", [])), 16)
    assert DEC_FEE >= mind, (DEC_FEE, mind)
    fee = (FEE if ben != b"\0" * 32 else 0) + m * DEC_FEE
    ben_ua = ben.ua if isinstance(ben, UA) else ben
    olen = K.PK_BYTES * g + K.V_BYTES * (m + 1) + (K.V_BYTES * m if aud_on else 0)
    hdr = lambda out: multi_args(p, frm.ua, ben_ua, DEC_FEE, salt, [u.ua for u, _ in legs], g, aud_on, out, sealed, kv_of(frm))  # noqa: E731
    view = lambda t: dec_bytes(call(tok, cd(API["multiStmt"], [MULTI_T, "w"], t, binding)))  # noqa: E731
    tOff = K.HEADER_BYTES + K.PK_BYTES * (1 + m + (1 if aud_on else 0))
    T = view(hdr(probe(olen)))[tOff:tOff + K.CT_BYTES]
    b = bal(frm.s, T)
    rest = b - sum(a for _, a in legs) - fee
    assert rest >= 0, (b, legs, fee)
    aud_pk = None
    if aud_on:
        aud_pk = pqz_key(bytes.fromhex(call(tok, cd("auditorUA()", []))[2:]))
    e = K.enc_multi(frm.pk, K.digits(rest), [(u.pk, K.digits(a)) for u, a in legs], aud_pk, os.urandom(32))
    out = b"".join(e["us"]) + b"".join(e["vs"]) + e["v_f"] + (b"".join(e["v_as"]) if aud_on else b"")
    pl = hdr(out)
    stmt = view(pl)
    check(len(stmt) == K.multi_len(m, aud_on) and stmt[tOff:tOff + K.CT_BYTES] == T and stmt[-len(out):] == out,
          f"{C.name} op 7 statement of {what}: {len(stmt):,} B, T and out as built")
    wit = (K.i8(frm.s) + K.i16(frm.e) + b"".join(K.i8(r) + K.i16(x) for r, x in zip(e["rs"], e["e1s"]))
           + b"".join(K.i16(x) for x in e["e2"] + [e["e2_f"]] + e["e2_a"])
           + b"".join(bytes(K.digits(a)) for a in [a for _, a in legs] + [rest]))
    t0 = time.time()
    proof = pq.prove(7, stmt, wit)
    tp = time.time() - t0
    auth = ua_sig(pq, frm, P_ZAUTH, K.auth_digest(7, stmt))
    hint = C.hint(frm)
    sv = verdict(tok, stmt, proof)
    data = cd(API["transfer"], [MULTI_T] + AUTH_T + [SV_T], pl, proof, auth, hint, sv)
    log(f"      {what}: M {m}, balance {b} → {rest}, header fee {fee}, hint {len(hint)} B, proof {len(proof):,} B in {tp:.2f} s, "
        f"calldata {len(data):,} B")
    newacc = e["us"][0] + e["v_f"]
    C.set_next(bal=[(frm, -sum(a for _, a in legs) - fee)] + [(u, a) for u, a in legs],
               pub=([(ben, FEE)] if ben != b"\0" * 32 else []) + [(u, DEC_FEE) for u, _ in legs], acc={frm.ua: newacc},
               total=-fee)
    bundle = salt + b"".join(pack(x) for x in e["us"]) + b"".join(  # R as stored (P46)
        pack(e["vs"][j]) + (pack(e["v_as"][j]) if aud_on else b"") + u.ua for j, (u, _) in enumerate(legs))
    rc = (signed.send("PqzTransferCompact" if compact else "PqzTransfer", [pl, proof, auth, hint], f"{C.name} {what}", sv)
          if signed else s.send(tok, data, f"{C.name} {what}"))
    C.commit()
    ref = sent_ref(rc, tok, API["ev_multi"])
    blob = dec_bytes(call(tok, cd("pqzEntryBlob(bytes32)", ["w"], ref)))
    head, tag, kv = tail_of(blob)
    check(head == bundle + pack(e["v_f"]) and tag == OWN_TAG and len(kv) == len(legs) + (1 if aud_on else 0),
          f"{C.name} pqzEntryBlob(ref) = R ‖ v_f ‖ ownTag ‖ kv {kv} ‖ n as built, packed ({len(blob):,} B)")
    return rc, ref, bundle, e


def burn(pq, s, C, frm, amount, recipient, what, unwrap=None, signed=None, at=None):
    """Burn / refresh. The recipient is a 32-byte id (UA-5c b): a native address is its zero-padded word. `signed` as in
    `transfer`."""
    tok = C.tok
    binding = signed.binding if signed else ZERO32
    stt = C.state(frm)
    p = stt["pendingCount"] if at is None else at  # group 3h T65: `at` below `rolled` is an un-roll
    rcp = W(recipient) if recipient else b"\0" * 32
    hdr = lambda out: [p, 10**9, 0, frm.ua, kv_of(frm), b"\0" * 32, OWN_TAG, out[:K.PK_BYTES], out[K.PK_BYTES:]]  # noqa: E731
    if unwrap:
        x = [unwrap[0], rcp, amount, unwrap[1]]
        view = lambda t: dec_bytes(call(tok, cd(API["unwrapStmt"], [BURN_T, UNWRAP, "w"], t, x, binding)))  # noqa: E731
    else:
        view = lambda t: dec_bytes(call(tok, cd(API["burnStmt"], [BURN_T, "w", "w", "w"], t, amount, rcp, binding)))  # noqa: E731
    tOff = K.HEADER_BYTES + K.PK_BYTES
    T = view(hdr(probe(K.CT_BYTES)))[tOff:tOff + K.CT_BYTES]
    b = bal(frm.s, T)
    rest = b - amount
    r_, e1, e2, _ = K.enc_sample(os.urandom(32), 1)
    u, vs = K.encrypt([frm.pk], [K.digits(rest)], r_, e1, e2)
    pl = hdr(u + vs[0])
    stmt = view(pl)
    wit = K.i8(frm.s) + K.i16(frm.e) + K.i8(r_) + K.i16(e1) + K.i16(e2[0]) + bytes(K.digits(rest))
    proof = pq.prove(2, stmt, wit)
    auth = ua_sig(pq, frm, P_ZAUTH, K.auth_digest(2, stmt))
    hint = C.hint(frm)
    sv = verdict(tok, stmt, proof)
    log(f"      {what}: balance {b} → {rest}, p {p}, rolled {stt['rolled']}, hint {len(hint)} B, proof {len(proof):,} B")
    if signed:
        rc = signed.send("PqzUnshieldUnwrap" if unwrap else "PqzUnshield", [pl, x if unwrap else [amount, rcp], proof, auth, hint], f"{C.name} {what}", sv)
    elif unwrap:
        rc = s.send(tok, cd(API["unshieldUnwrap"], [BURN_T, UNWRAP] + AUTH_T + [SV_T], pl, x, proof, auth, hint, sv), f"{C.name} {what}")
    else:
        rc = s.send(tok, cd(API["unshield"], [BURN_T, "w", "w"] + AUTH_T + [SV_T], pl, amount, rcp, proof, auth, hint, sv), f"{C.name} {what}")
    C.set_next(bal=[(frm, -amount)], acc={frm.ua: u + vs[0]}, total=-amount)
    C.commit()
    return rc


# ------------------------------------------------------------------ group 3h T65: the proof path, rebuilt from the interface

PBITS = K.Q.bit_length()
EV_PROOF = "0x" + kc("PqzDebitProof(address,bytes32,uint64,bytes,bytes)").hex()


def psize(n):
    """The packed size (P46) of an object of `n` 64-bit-lane bytes."""
    return n // 8 * PBITS // 8


def unpack(b, n):
    """The inverse of `pack`: the first `psize(n)` bytes of `b` as `n` bytes of 64-bit lanes."""
    c = n // 8
    x = int.from_bytes(b[:psize(n)], "big")
    m = (1 << PBITS) - 1
    return b"".join(((x >> (PBITS * (c - 1 - i))) & m).to_bytes(8, "big") for i in range(c))


def _dyn(t):
    return t == "b" or (isinstance(t, tuple) and (t[0] == "a" or any(_dyn(x) for x in t[1])))


def _size(t):
    return 32 if t == "w" else sum(_size(x) for x in t[1])


def adec(t, d, o=0):
    """ABI-decode a value of type `t` (the encoder's descriptors: "w", "b", ("a", T), ("t", [...])) at `d[o:]`."""
    if t == "w":
        return d[o:o + 32]
    if t == "b":
        n = int.from_bytes(d[o:o + 32], "big")
        return d[o + 32:o + 32 + n]
    if t[0] == "a":
        n, e, base = int.from_bytes(d[o:o + 32], "big"), t[1], o + 32
        if _dyn(e):
            return [adec(e, d, base + int.from_bytes(d[base + 32 * i:base + 32 * i + 32], "big")) for i in range(n)]
        return [adec(e, d, base + _size(e) * i) for i in range(n)]
    out, h = [], o
    for x in t[1]:
        out.append(adec(x, d, o + int.from_bytes(d[h:h + 32], "big")) if _dyn(x) else adec(x, d, h))
        h += 32 if _dyn(x) else _size(x)
    return out


def arg(ts, d, i):
    """Parameter `i` of calldata `d` (no selector) whose parameter types are `ts`: only that one is decoded."""
    h = sum(32 if _dyn(x) else _size(x) for x in ts[:i])
    return adec(ts[i], d, int.from_bytes(d[h:h + 32], "big") if _dyn(ts[i]) else h)


def u_(w):
    return int.from_bytes(w, "big")


def debit_record(tok, ua, k):
    """`pqzDebitRecord(ua, k)` (spec §2.2, §9.1) as a dict."""
    w = words(call(tok, cd("pqzDebitRecord(bytes32,uint64)", ["w", "w"], ua, k)))
    names = ["prevBlob", "p", "deltaP", "proofStore", "shieldIn", "keyVersion", "prevCounter", "hasPrev"]
    r = dict(zip(names, (u_(x) for x in w)))
    r["prevBlob"] = "0x" + w[0][12:].hex()
    return r


def data_of(addr):
    """An SSTORE2 pointer's data: its code after the leading STOP."""
    return bytes.fromhex(rpc("eth_getCode", [addr, "latest"])[2:])[1:]


def key_code(ua, v):
    """The PQZ key of `(ua, v)` from the registry (`pqzKeyAt`, spec §9.4)."""
    return data_of("0x" + words(call(REG[0], cd("pqzKeyAt(bytes32,uint64)", ["w", "w"], ua, v)))[0][12:].hex())


def r_len(d):
    """`rOf`'s length of an op blob's data: before `P(v_f)` and the tail."""
    return len(d) - (33 + 8 * d[-1]) - psize(K.V_BYTES)


def acc_of(d):
    """`(u, v_f)` of an op blob (PqzCore's `_uv`): a burn's `R` is `P(u')`, a transfer's `salt ‖ u ‖ …`; `v_f` follows `R`."""
    r = r_len(d)
    return unpack(d[0 if r == psize(K.PK_BYTES) else 16:], K.PK_BYTES) + unpack(d[r:], K.V_BYTES)


def t_rebuild(tok, ua, r, shift=0, shield=None, version=None):
    """`T_k` from the one record and state (spec §2.3): `prevBlob`'s `(u, v_f)` + `Σ pending[p − Δp, p)` + `Trivial(shieldIn)`.
    The negatives move one input: `shift` the range's start, `shield` the plain term, `version` the pending entries' version."""
    c = acc_of(data_of(r["prevBlob"])) if r["hasPrev"] else bytes(K.CT_BYTES)
    v = r["keyVersion"] if version is None else version
    for i in range(r["p"] - r["deltaP"] + shift, r["p"]):
        c = K.ct_add(c, dec_bytes(call(tok, cd("pqzPendingCt(bytes32,uint64,uint64)", ["w", "w", "w"], ua, v, i))))
    sin = r["shieldIn"] if shield is None else shield
    return K.ct_add(c, K.trivial(K.digits(sin))) if sin else c


# the direct entries' parameters (API) and the position of `proof` among them
CALL_T = {"op1": [TRANSFER_T] + AUTH_T + [SV_T], "op7": [MULTI_T] + AUTH_T + [SV_T], "burn": [BURN_T, "w", "w"] + AUTH_T + [SV_T],
          "unwrap": [BURN_T, UNWRAP] + AUTH_T + [SV_T]}
PROOF_AT = {"op1": 1, "op7": 1, "burn": 3, "unwrap": 2}


def calldata(txh):
    return bytes.fromhex(rpc("eth_getTransactionByHash", [txh])["input"][10:])


def proof_of(tok, ua, k, r, txh, form, want_log=None):
    """P of debit `(ua, k)` (spec §9.5): under `LOG` its one `PqzDebitProof` (header, proof); under `NONE` the proof parameter of
    the transaction's calldata (no header). `want_log` forces the lookup the record does not name (a negative)."""
    if (r["proofStore"] == 1) if want_log is None else want_log:
        logs = rpc("eth_getLogs", [{"address": tok, "fromBlock": "0x0", "toBlock": "latest",
                                    "topics": [EV_PROOF, None, "0x" + ua.hex(), "0x" + k.to_bytes(32, "big").hex()]}])
        if len(logs) != 1:
            raise LookupError(f"{len(logs)} PqzDebitProof logs for ({ua.hex()[:8]}…, {k})")
        h, pr = adec(("t", ["b", "b"]), bytes.fromhex(logs[0]["data"][2:]))
        return h, pr
    return None, arg(CALL_T[form], calldata(txh), PROOF_AT[form])


def header_of(tok, ua, k, r, txh, form, aud, m):
    """The 640 header bytes of debit `(ua, k)` rebuilt from its calldata (history), its record and the token (spec §9.4): the
    parameters' words, `sendCounter` = k, the record's `p` and `shieldIn`, the token's psid, chain, registry, chainUid, fee;
    the direct call's binding (a transfer: `keccak256(TAG_DIRECT_MODE, TransferMode)`, W-A; an unwrap: `unwrapBinding(
    underlying, minOut)`, D12; a burn: 0); the memo empty (these tokens' memo mode 0: `memoHash = keccak256(ownTag)`)."""
    d = calldata(txh)
    x = arg(CALL_T[form], d, 0)
    fee = u_(words(call(tok, cd("confidentialFee()", [])))[0])
    if form in ("op1", "op7"):  # ZetherTypes.TransferMode: HASH (0) with a sealed memo or on a COMPACT token, else BUNDLE (1)
        compact = u_(words(call(tok, cd("disclosureMode()", [])))[0]) == 1
        mode = 0 if x[13 if form == "op1" else 12] or compact else 1
        binding = kc(kc("SCAAS-PQZ-DIRECT-MODE-V1"), K.word(mode))
    elif form == "unwrap":
        xu = arg(CALL_T[form], d, 1)  # Unwrap(underlying, recipient, amount, minOut)
        binding = kc(kc("SCAAS-PQZ-UNWRAP-V1"), xu[0], xu[3])
    else:
        binding = ZERO32
    f = dict(proofSystemId=words(call(tok, cd("proofSystemId()", [])))[0], chainId=CTX[0], token=bytes.fromhex(tok[2:]),
             registry=words(call(tok, cd("registry()", [])))[0][12:], fromUA=ua, sendCounter=k, p=r["p"],
             validUntilBlock=u_(x[1]), plainUsed=r["shieldIn"], chainUid=CTX[1], envelopeBinding=binding)
    if form == "op1":  # TRANSFER_F
        f.update(toUA=x[5], beneficiaryUA=x[6], fee=fee if u_(x[6]) else 0, auditorOn=int(aud), salt=x[7][:16], memoHash=kc(x[8]))
        return K.build_header("TRANSFER", f)
    if form == "op7":  # MULTI_F
        f.update(beneficiaryUA=x[5], fee=(fee if u_(x[5]) else 0) + m * u_(x[6]), salt=x[7][:16], memoHash=kc(x[8]),
                 recipientsHash=K.recipients_hash([leg[0] for leg in x[10]]), M=m, auditorOn=int(aud), opTag=K.OP_TAG["TRANSFER-MULTI"])
        return b"".join(K.word(f.get(n, 0)) for n in K.MULTI_HEADER)
    amount, rcp = (u_(arg(CALL_T[form], d, 1)), arg(CALL_T[form], d, 2)) if form == "burn" else (u_(arg(CALL_T[form], d, 1)[2]),
                                                                                                  arg(CALL_T[form], d, 1)[1])
    f.update(beneficiaryUA=x[5], amount=amount, recipient=rcp, memoHash=kc(x[6]))  # BURN_F
    return K.build_header("BURN" if amount else "REFRESH", f)


def other_version(v):
    return v + 1 if v == 0 else v - 1


def rebuild(tok, d, neg=None):
    """Debit `d` (`ua`, `k`, `tx`, `form`, `blob` data) rebuilt from the §9 interface alone and verified with pqz-ffi (the
    precompile's word); `neg` applies one negative of spec §11.4. Returns (statement, proof, verified, record, ownTag)."""
    ua, k, form = d["ua"], d["k"], d["form"]
    r = debit_record(tok, ua, k)
    hdr, proof = proof_of(tok, ua, k, r, d["tx"], form, (r["proofStore"] != 1) if neg == "mode-of-another-record" else None)
    if neg == "P-of-another-debit":
        proof = d["other_proof"]
    blob = d["blob"]
    _, tag, kv = tail_of(blob)
    rl = r_len(blob)
    vf = unpack(blob[rl:], K.V_BYTES)
    pk_f = key_code(ua, r["keyVersion"])
    if neg == "wrong-predecessor":
        r = dict(r, prevBlob=d["other_blob"], hasPrev=1)
    T = t_rebuild(tok, ua, r, shift=-1 if neg == "wrong-deltaP" else 0,
                  shield=r["shieldIn"] + 1 if neg == "wrong-shieldIn" else None,
                  version=other_version(r["keyVersion"]) if neg == "version-boundary" else None)
    aud_ua = words(call(tok, cd("auditorUA()", [])))[0]
    kvv = list(kv)
    if neg == "wrong-historical-key-version":
        kvv[0] = other_version(kvv[0])
    pv, pp = psize(K.V_BYTES), psize(K.PK_BYTES)
    if form == "op1":  # R = salt ‖ P(u ‖ v_t) ‖ [P(v_a)] ‖ toUA; kv = [receiver, (auditor)]
        aud, m = len(kv) == 2, 1
        u, vt = unpack(blob[16:], K.PK_BYTES), unpack(blob[16 + pp:], K.V_BYTES)
        va = unpack(blob[16 + pp + pv:], K.V_BYTES) if aud else b""
        av = other_version(kvv[1]) if aud and neg == "wrong-auditor-window" else (kvv[1] if aud else 0)
        pk_a = key_code(aud_ua, av) if aud else b""
        body = pk_f + key_code(blob[rl - 32:rl], kvv[0]) + pk_a + T + u + vt + vf + va
    elif form == "op7":  # R = salt ‖ P(u_0..u_{G-1}) ‖ M × (P(v_j) ‖ [P(v_{a,j})] ‖ UA_j); kv = [legs…, (auditor)]
        aud = m = None
        for a in (1, 0):
            mm = blob[-1] - a
            if mm > 0 and 16 + pp * K.groups(mm, bool(a)) + (32 + pv * (1 + a)) * mm == rl:
                aud, m = bool(a), mm
                break
        assert aud is not None, "op 7 blob: no (M, auditor) fits R"
        g, ls = K.groups(m, aud), 32 + pv * (1 + int(aud))
        us = [unpack(blob[16 + pp * i:], K.PK_BYTES) for i in range(g)]
        base = 16 + pp * g
        legs = [(blob[base + ls * j + ls - 32:base + ls * (j + 1)], unpack(blob[base + ls * j:], K.V_BYTES),
                 unpack(blob[base + ls * j + pv:], K.V_BYTES) if aud else b"", kvv[j]) for j in range(m)]
        if neg == "swapped-leg":
            legs[0], legs[1] = legs[1], legs[0]
        pk_a = key_code(aud_ua, kvv[m]) if aud else b""
        body = (pk_f + b"".join(key_code(lg[0], lg[3]) for lg in legs) + pk_a + T + b"".join(us) + b"".join(lg[1] for lg in legs)
                + vf + b"".join(lg[2] for lg in legs))
    else:  # burn, refresh, unwrap: R = P(u')
        aud, m = False, 0
        body = pk_f + T + unpack(blob, K.PK_BYTES) + vf
    if hdr is None:
        hdr = header_of(tok, ua, k, r, d["tx"], form, aud, m)
    stmt = hdr + body
    ok = PQ_REF[0].prover.ask(f"verify {OP_OF[form]} {stmt.hex()} {proof.hex()}").endswith("01")
    return stmt, proof, ok, r, tag, (aud, m)


OP_OF = {"op1": 1, "op7": 7, "burn": 2, "unwrap": 2}
PQ_REF = [None]


def proof_path(pq, sd, reg, create, U, aud, DEC, sk, tusd):
    """Group 3h T65 (spec §11.4): real proofs on this local chain under NONE, LOG and NONE again; then every debit's statement rebuilt
    from the §9 interface alone (record, pending, blob with kv, keys by version, P from the log or the calldata) and verified with
    pqz-ffi, equal to the statement proven (the positive control); then the negatives, one at a time, each must fail the verification
    or the lookup."""
    global OWN_TAG
    log("\n## 7. the proof path (group 3h T65): debits under NONE, LOG, NONE; each rebuilt from the interface and verified")
    PQ_REF[0] = pq
    alice, bob, carol = U["alice"], U["bob"], U["carol"]
    t3 = create(4, "PQZ proof path", "pqPP", [], 0, 2, 1 | 2 | 4 | (1 << 24), salt=b"pq3", issuer=sd.addr)  # OPTIONAL auditor, bit 24
    C = Client(t3, "pqPP")
    sd.send(t3, cd("mint(address,uint256)", ["w", "w"], sd.addr, 10_000 * SCALE), "pqPP mint 10,000 public")
    for u, v in ((alice, 600), (bob, 200), (carol, 100)):
        sd.send(t3, cd(API["shield"], ["w", "w"], u.ua, v), f"pqPP mtxShield({u.name}, {v})")
        C.set_next(bal=[(u, v)], total=v)
        C.commit()
    D_ = []

    def tag(label):
        global OWN_TAG
        OWN_TAG = kc("T65 ownTag " + label)  # ponytail: a distinct tag per debit; the contract checks no value (PP-3 is the client's)

    def note(form, frm, rc, label, ref=None, tok=None, Cx=None):
        tok = tok or t3
        D_.append(dict(label=label, form=form, ua=frm.ua, k=(Cx or C).state(frm, 0)["sendCounter"] - 1, tx=rc["transactionHash"],
                       tok=tok, tag=OWN_TAG, proven=PROVEN[-1],
                       blob=dec_bytes(call(tok, cd("pqzEntryBlob(bytes32)", ["w"], ref))) if ref else None))

    tag("d1")
    rc, ref, _, _ = transfer(pq, sd, C, alice, bob, ZERO32, 50, True, "NONE: op 1 alice→bob 50, auditor on")
    note("op1", alice, rc, "d1 op 1 auditor on, NONE", ref)
    rollover(sd, C, bob, 1, "bob's credit")
    tag("d2")
    rc, ref, _, _ = transfer(pq, sd, C, bob, carol, ZERO32, 20, False, "NONE: op 1 bob→carol 20, auditor off, after a rollover")
    note("op1", bob, rc, "d2 op 1 auditor off, NONE", ref)
    for v in (3, 4, 5):
        wait_block(int(rpc("eth_blockNumber"), 16) + 1)
        sd.send(t3, cd(API["shield"], ["w", "w"], alice.ua, v), f"pqPP mtxShield(alice, {v}), a block of its own")
        C.set_next(bal=[(alice, v)], total=v)
        C.commit()
    rollover(sd, C, alice, 2, "two of alice's three entries")
    carol1 = rotate(pq, sd, reg, C, carol, sk, "pqz-carol-v1")  # a receiver, a leg, then a sender (the migration)
    rotate(pq, sd, reg, C, aud, sk, "pqz-aud-v1")  # the auditor: every later auditor copy at version 1
    sd.send(t3, cd("setProofStore(uint8)", ["w"], 1), "pqPP setProofStore(LOG): the deployer holds bit 24")
    check(u_(words(call(t3, cd("proofStore()", [])))[0]) == 1, "pqPP proofStore() = LOG")
    tag("d3")
    st = C.state(alice)
    rc, ref, _, _ = transfer_multi(pq, sd, C, alice, [(carol1, 10), (bob, 5), (DEC[0], 0), (DEC[1], 0)], ZERO32, True,
                                   f"LOG: op 7 M = 4 alice→[carol/v1 10, bob 5, two decoys], auditor/v1 on, p = rolled − 1 = "
                                   f"{st['rolled'] - 1} (an un-roll)", at=st["rolled"] - 1)
    note("op7", alice, rc, "d3 op 7 M = 4 auditor on, rotated leg, un-roll, LOG", ref)
    tag("d4")
    rc = burn(pq, sd, C, alice, 20, sd.addr, "LOG: burn alice 20 → deployer")
    note("burn", alice, rc, "d4 burn 20, LOG")
    tag("d5")
    rc = burn(pq, sd, C, alice, 0, None, "LOG: refresh alice")
    note("burn", alice, rc, "d5 refresh, LOG")
    tag("d6")
    rc, ref, _, _ = transfer(pq, sd, C, alice, carol1, ZERO32, 7, True, "LOG: op 1 alice→carol/v1 7, auditor/v1 on")
    note("op1", alice, rc, "d6 op 1 to a rotated receiver, rotated auditor, LOG", ref)
    sd.send(t3, cd("setProofStore(uint8)", ["w"], 0), "pqPP setProofStore(NONE)")
    tag("d7")
    rc, ref, _, _ = transfer(pq, sd, C, carol, carol1, ZERO32, 30, False, "NONE: the migration, op 1 from (carol, 0) to carol/v1")
    note("op1", carol, rc, "d7 migration of a rotated sender, NONE", ref)
    t4 = create(5, "PQZ proof path wrapped", "pqPW", [[tusd, 1, 1]], 0, 2, 1, salt=b"pq4", store=1)  # kind 5, created under LOG
    C4 = Client(t4, "pqPW")
    sd.send(tusd, cd("approve(address,uint256)", ["w", "w"], t4, 10**12), "tUSD approve pqPW")
    sd.send(t4, cd(API["wrapShield"], ["w", "w", "w"], tusd, 100 * SCALE, alice.ua), "mtxWrapShield(tUSD 100, alice) into pqPW")
    C4.set_next(bal=[(alice, 100)], total=100)
    C4.commit()
    tag("d8")
    rc = burn(pq, sd, C4, alice, 30, sd.addr, "LOG: unshield-unwrap alice 30 → deployer in tUSD (kind 5)", unwrap=(tusd, 30 * SCALE))
    note("unwrap", alice, rc, "d8 unwrap 30, kind 5, LOG", tok=t4, Cx=C4)
    # a burn's op blob (spec §9.4): the next same-version debit's prevBlob, else the account's accBlob
    for i, d in enumerate(D_):
        if d["blob"] is None:
            nxt = next((e for e in D_[i + 1:] if e["ua"] == d["ua"] and e["tok"] == d["tok"]), None)
            ptr = debit_record(d["tok"], d["ua"], nxt["k"])["prevBlob"] if nxt else "0x" + words(call(d["tok"], cd(
                "pqzAccount(bytes32,uint64)", ["w", "w"], d["ua"], 0)))[ACCT.index("accBlob")][12:].hex()
            d["blob"] = data_of(ptr)
    log("\n   the reference rebuild (spec §9.4, §9.5), the positive control")
    for d in D_:
        try:
            stmt, proof, ok, r, tg, (a, m) = rebuild(d["tok"], d)
        except Exception as e:  # a harness error on one debit is a failed check, the others still run
            check(False, f"{d['label']}: the rebuild raised {type(e).__name__}: {str(e)[:120]}")
            continue
        _, pst, ppr = d["proven"]
        off = [K.HEADER[i] for i in range(20) if stmt[32 * i:32 * i + 32] != pst[32 * i:32 * i + 32]]
        check(stmt == pst and proof == ppr and ok and tg == d["tag"],
              f"{d['label']}: rebuilt = the proven statement ({len(stmt):,} B; header words off {off}; body "
              f"{'=' if stmt[640:] == pst[640:] else '≠'}), P from {'the log' if r['proofStore'] else 'the calldata'}, record "
              f"(p {r['p']}, Δp {r['deltaP']}, shieldIn {r['shieldIn']}, keyVersion {r['keyVersion']}, hasPrev {r['hasPrev']}), "
              f"pqz-ffi verify = {int(ok)}, ownTag in the blob")
        if r["proofStore"] == 1:
            check(header_of(d["tok"], d["ua"], d["k"], r, d["tx"], d["form"], a, m) == stmt[:640],
                  f"{d['label']}: the header rebuilt from the calldata = the logged header")
    log("\n   the negatives (spec §11.4), one at a time: each must fail the verification or the lookup")
    pick = {"wrong-historical-key-version": "d6", "swapped-leg": "d3", "wrong-auditor-window": "d6", "wrong-shieldIn": "d2",
            "wrong-predecessor": "d5", "wrong-deltaP": "d4", "version-boundary": "d7", "P-of-another-debit": "d1",
            "mode-of-another-record": "d1"}
    for neg, lab in pick.items():
        # P of d2 for "P of another debit"; d3's predecessor (d1's blob) in place of d5's (d4's) for "wrong predecessor"
        d = dict(next(e for e in D_ if e["label"].startswith(lab)), other_proof=D_[1]["proven"][2],
                 other_blob=debit_record(t3, alice.ua, D_[2]["k"])["prevBlob"])
        try:
            _, _, ok, _, _, _ = rebuild(d["tok"], d, neg)
            check(not ok, f"negative {neg} on {d['label']}: pqz-ffi verify = 0")
        except (LookupError, RuntimeError) as e:
            check(True, f"negative {neg} on {d['label']}: the lookup fails ({type(e).__name__}: {str(e)[:90]})")
        except Exception as e:  # a harness error is no negative result
            check(False, f"negative {neg} on {d['label']}: the rebuild raised {type(e).__name__}: {str(e)[:120]}")


def rotate(pq, s, reg, C, u, sk, label):
    """Version `kv + 1` of `u`, as `rotation` does for dave: a fresh key, `setPqzKey` signed over typed `UAPqzKeyVersionRecord`,
    `storePqzPop` with `R_REG` over typed `UAPqzKeyVersion`; the client reads the new version from then on."""
    v = kv_of(u) + 1
    pk1, s1, e1, _ = K.keygen(sk(label))
    proof = pq.prove(3, K.build_register(portable("keyverreg", ua=u.ua, pqzKey=pk1, version=v), pk1), K.i8(s1) + K.i16(e1))
    ph = kc(proof)
    sig = pq.ml_sign(65, u.seed, kc(TAG[MLDSA65], portable("keyverrec", kind=MLDSA65, ua=u.ua, pqzKey=pk1, pqzPopHash=ph, version=v)))
    s.send(reg, cd(SET_PQZ, SET_PQZ_T, u.ua, v, pk1, ph, [b"", sig, []]), f"setPqzKey {u.name} version {v}")
    s.send(reg, cd("storePqzPop(bytes32,uint64,bytes)", ["w", "w", "b"], u.ua, v, proof), f"storePqzPop {u.name} version {v}")
    check(u_(words(call(reg, cd("pqzKeyOf(bytes32)", ["w"], u.ua)))[0]) == v, f"{u.name} pqzKeyOf: version {v} current")
    u1 = UA(**{**u.__dict__, "pk": pk1, "s": s1, "e": e1, "kv": v, "name": f"{u.name}/v{v}"})
    u1.prior = {**getattr(u, "prior", {}), kv_of(u): u}
    C.uas[u.ua] = u1
    return u1


REG = [None]
CTX = [None, None]  # chainId, chainUid of this run
VERIFIER = [None]  # the `Sender` whose EOA is the OFFCHAIN tokens' verifier UA (--zero-dep): the deployer

if __name__ == "__main__":
    main()
