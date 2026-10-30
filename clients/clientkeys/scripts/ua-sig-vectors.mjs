// Generates smartcontracts/vectors/ua/signatures.json: UA-2a signatures (accounts.md §1.4, §1.8, §1.9) on deterministic
// keys — per derived kind a key, its PoP (UA-8: portable, the same in context A and B), signatures over ua_msg under metatx and member,
// and negatives a verifier must refuse; native EOA UAAuth signatures; an msig structure with member signature sets.
// Secrets: keccak256("scaas.ua.vectors.sig.<name>") mod (n − 1) + 1 (ed25519: the 32-byte keccak itself, RFC 8032 seed).
// Nonces: RFC 6979 (P-256, secp256k1 ECDSA), zero aux_rand (BIP-340), keccak256(secret ‖ message ‖ "scaas.ua.vectors.nonce")
// (scaas Schnorr), RFC 8032 (ed25519). test/ua-sig.test.js re-verifies every row with noble; clients/ua-rs
// (tests/signatures.rs) with p256 / k256 / arkworks / ed25519-dalek.
// Also writes metatx3.json (UA-4, accounts.md §1.16): the UA ledger's UAMetaTransaction and UAMetaTransfer on context A
// (typed data from src/evm.js, digest, the auth blob of the native key and of every derived kind above); Foundry
// (test/ua/UAMetaTx3Vectors.t.sol) recomputes each digest on a token and verifies each auth with the real verifiers.
// UA-5a (accounts.md CTR-UA-26/28, metatx.md CTR-MTX-05/06) appends the keys burn and unwrapToUA (UAMetaTransaction rows
// of the newly UA-allowlisted calls) and receiverFee (uaPayReceiverFee: the payer's UAMetaTransfer, the payee's
// ReceiverFee co-signature, a derived payee under the purpose receiver-fee); the existing keys stay byte-identical.
// UA-5b (dex.md CTR-DEX-25/26) writes uatrade_kat.json: UATradeOrder, the CancelOrder over its digest and
// UAInvalidateNonces under the purpose trade, for the native key and every derived kind, plus three mldsa65 orders (one
// taker, two makers) for the per-transaction caps; the other files stay byte-identical.
// Also writes ed25519_fuzz.json (UA-2b T-FUZZ, accounts.md §1.16): mutated / crafted ed25519 cases from a fixed seed, each
// with its strict verdict (ed25519-dalek verify_strict, re-checked by clients/ua-rs tests/ed25519_fuzz.rs).
// Also writes pq_signatures.json (P6c, accounts.md §1.16): the PQ kinds (src/pq.js, the keys of pq_kat.json) on context A —
// PoPs, metatx / member signatures and negatives, the msig treasury {mldsa65 ×3} t=2 and hybrid {mldsa65, p256} t=2
// with their member signature sets, and their metatx3 rows; test/pq-sig.test.js re-verifies them with noble,
// test/ua/UARegistryPq.t.sol and UAMetaTx3Pq.t.sol on chain.
//   node scripts/ua-sig-vectors.mjs [outDir]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { ed25519, ED25519_TORSION_SUBGROUP } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, abiEncode } from '../src/bytes.js';
import * as ua from '../src/ua.js';
import {
  hashStruct, hashTypedData, padId, payLane, uaMetaTxTypedData, uaMetaTransferTypedData, receiverFeeTypedData,
  unwrapToUACalldata, uaTradeOrderTypedData, uaInvalidateNoncesTypedData, orderCancelTypedData,
} from '../src/evm.js';
import { PQ_KINDS, pqMessage } from '../src/pq.js';
import { holderPopMessageV1 } from '../legacy/ua8/ua-pop-v1.js';
import {
  int, be, secretOf, SECP_N, BLS, secpHighS, withV, highS, CHROME_EXTRA, webauthnSign, webauthnHighS, blsG1enc, SCHEMES,
  ecdsa, nativeSk, nativeAddr, nativeUa, encodeMemberSigs, PQ_MNEMONIC, pqSignMsg, pqKey, pqzKeyOf, pqzPopOf,
} from './ua-signers.mjs';

const VECTORS = fileURLToPath(new URL('../../../smartcontracts/vectors/ua/', import.meta.url));
const OUT = process.argv[2] ?? VECTORS;
const { contexts } = JSON.parse(readFileSync(join(VECTORS, 'structures.json'), 'utf8'));

const flip = (b, i) => { const c = Uint8Array.from(b); c[i] ^= 1; return c; };
const tag = (p) => ua.purposeTag(p);
const DIGEST = keccak_256(utf8ToBytes('scaas.ua.vectors.sig.digest'));
const ZERO32 = new Uint8Array(32);

// --- schemes: keyData(sk) and sign(sk, msg32, { pop }) ---
// --- ed25519 (UA-2b): strict = ed25519-dalek verify_strict ---
const ED_L = ed25519.Point.Fn.ORDER;
const ED_P = ed25519.Point.Fp.ORDER;
const EdPoint = ed25519.Point;
const le = (v) => be(v, 32).reverse();
const leInt = (b) => int(Uint8Array.from(b).reverse());
const edK = (Rb, A, M) => leInt(sha512(concatBytes(Rb, A, M))) % ED_L;
const edNonce = (label, i) => int(keccak_256(concatBytes(utf8ToBytes(label), be(BigInt(i), 4)))) % ED_L;
const TORSION = ED25519_TORSION_SUBGROUP.map(fromHex); // [0] identity, [1] order 8
const ED_ID = TORSION[0];
const ED_T8 = TORSION[1];
const withSign = (b) => { const c = Uint8Array.from(b); c[31] |= 0x80; return c; };
/** Strict verdict: noble zip215:false (canonical A and R, S < L, A not small order, cofactored equation), plus R not small
 * order and the cofactorless equation [S]B == R + [k]A — the rules of ed25519-dalek verify_strict. */
function edStrict(pk, msg, sig) {
  try {
    if (!ed25519.verify(sig, msg, pk, { zip215: false })) return false;
    const R = EdPoint.fromBytes(sig.subarray(0, 32), false);
    if (R.isSmallOrder()) return false;
    const k = edK(sig.subarray(0, 32), pk, msg);
    return EdPoint.BASE.multiplyUnsafe(leInt(sig.subarray(32))).equals(R.add(EdPoint.fromBytes(pk, false).multiplyUnsafe(k)));
  } catch { return false; }
}
const edNoble = (pk, msg, sig) => { try { return ed25519.verify(sig, msg, pk, { zip215: false }); } catch { return false; } };
/** A signature with R replaced by `Rb` and S = k·a: the [k]A side alone, so it satisfies the cofactored equation when `Rb`
 * is small order, and the cofactorless one when `Rb` decodes to the identity. */
const edForgeR = (a, A, M, Rb) => concatBytes(Rb, le((edK(Rb, A, M) * a) % ED_L));
/** Signs `M` under key bytes `A` (scalar a, possibly plus torsion) with nonce point R = [r]B + T. */
const edSignRaw = (a, A, M, r, T = ED_ID) => {
  const Rb = EdPoint.BASE.multiply(r).add(EdPoint.fromBytes(T)).toBytes();
  return concatBytes(Rb, le((r + edK(Rb, A, M) * a) % ED_L));
};


// a sibling kind whose tag a "wrong-kind-tag" negative signs under (same curve where one exists)
const OTHER_KIND = { 0x0100: 0x0101, 0x0101: 0x0100, 0x0103: 0x0110, 0x0104: 0x0112, 0x0105: 0x0141, 0x0141: 0x0105, 0x0106: 0x0105, 0x0107: 0x0104, 0x0102: 0x0103, 0x0108: 0x0103 };

/** First point on y² = x³ + 4 (x = 1, 2, …) outside the BLS12-381 G1 subgroup. */
function blsG1OffSubgroup() {
  const { Fp } = BLS;
  for (let x = 1n; ; x++) {
    let y;
    try { y = Fp.sqrt(Fp.add(Fp.mul(Fp.sqr(x), x), 4n)); } catch { continue; }
    const P = bls12_381.G1.Point.fromAffine({ x, y });
    try { P.assertValidity(); } catch { return blsG1enc(P); }
  }
}

// --- derived rows ---
/** The portable PoP (UA-8 P1): one per UA and attributes, the same in every context (`holderPopMessage`). */
const popOf = (kind, uaId, attrs = {}) => ua.holderPopMessage(kind, { ua: uaId, ...attrs });
/** A PoP row: popDigest = portablePopDigest, message = uaMessage(kind, pop v2, registrationDigest); the context is a label. */
const popRow = (ctx, p, sig, extra = {}) => ({ context: ctx, ...extra, popDigest: hex(p.portablePopDigest),
  registrationDigest: hex(p.registrationDigest), message: hex(p.message), sig: hex(sig) });
/** The negatives a portable verifier refuses: a PoP over the chain-bound digest of context A, a PoP under the v1 purpose. */
const chainBoundPop = (kind, uaId) => holderPopMessageV1(kind, { ...contexts.A, ua: uaId }).message;
const popV1Purpose = (kind, uaId) => ua.uaMessage(kind, ua.POP_TAG, popOf(kind, uaId).registrationDigest);
const derivedRows = Object.entries(SCHEMES).map(([name, s]) => {
  const sk = s.seed ? int(keccak_256(utf8ToBytes(`scaas.ua.vectors.sig.${name}`))) : secretOf(name, s.n);
  const keyData = s.keyData(sk);
  const id = ua.deriveUA(s.kind, keyData);
  const sign = (m, o) => s.sign(sk, m, o);
  const pop = (ctx) => { const p = popOf(s.kind, id); return popRow(ctx, p, sign(p.message, { pop: true })); };
  const metatx = ua.uaMessage(s.kind, tag('metatx'), DIGEST);
  const member = ua.uaMessage(s.kind, tag('member'), DIGEST);
  const metatxSig = sign(metatx);
  const sigs = [
    { purpose: 'metatx', purposeTag: hex(tag('metatx')), digest: hex(DIGEST), message: hex(metatx), sig: hex(metatxSig) },
    { purpose: 'member', purposeTag: hex(tag('member')), digest: hex(DIGEST), message: hex(member), sig: hex(sign(member)) },
  ];
  const popA = popOf(s.kind, id).message;
  const neg = (n, verifyPop, message, sig) => ({ name: n, verifyPop, message: hex(message), sig: hex(sig) });
  const negatives = [
    neg('wrong-purpose', false, member, metatxSig),
    neg('wrong-kind-tag', false, metatx, sign(ua.uaMessage(OTHER_KIND[s.kind], tag('metatx'), DIGEST))),
    neg('chain-bound-pop', true, popA, sign(chainBoundPop(s.kind, id), { pop: true })), // UA-8: the pre-UA-8 PoP of context A
    neg('pop-v1-purpose', true, popA, sign(popV1Purpose(s.kind, id), { pop: true })),
    neg('pop-as-sig', false, metatx, sign(popA, { pop: true })),
  ];
  if (s.kind === 0x0100) {
    const wa = (o) => webauthnSign(sk, metatx, o);
    sigs.push({ ...sigs[0], variant: 'crossOrigin-false', sig: hex(wa({ tail: ',"crossOrigin":false' })) },
      { ...sigs[0], variant: 'crossOrigin-false-extra', sig: hex(wa({ tail: `,"crossOrigin":false${CHROME_EXTRA}` })) });
    negatives.push(neg('mutated', false, metatx, flip(metatxSig, 0x5f)), neg('high-s', false, metatx, webauthnHighS(metatxSig)),
      neg('no-uv', false, metatx, wa({ flags: 0x01 })), neg('no-up', false, metatx, wa({ flags: 0x04 })),
      neg('cross-origin-true', false, metatx, wa({ tail: ',"crossOrigin":true' })),
      neg('extra-without-cross-origin', false, metatx, wa({ tail: CHROME_EXTRA })),
      neg('wrong-rp-id', false, metatx, wa({ rpId: 'other.example' })), neg('type-create', false, metatx, wa({ type: 'webauthn.create' })));
  } else {
    // ed25519: flip S's low byte (its last byte would move S by 2^248, possibly past L)
    negatives.push(neg('mutated', false, metatx, flip(metatxSig, s.kind === 0x0102 ? 32 : s.kind === 0x0108 ? 63 : metatxSig.length - 1)));
  }
  if (s.kind === 0x0102) {
    const { scalar: a } = ed25519.utils.getExtendedPublicKey(be(sk, 32));
    const R = metatxSig.subarray(0, 32);
    const S = leInt(metatxSig.subarray(32));
    const withS = (v) => concatBytes(R, le(v));
    const forge = (Rb) => edForgeR(a, keyData, metatx, Rb);
    negatives.push(
      neg('s-plus-l', false, metatx, withS(S + ED_L)), // same point: malleability
      neg('s-ge-l', false, metatx, withS(S + ((1n << 256n) - 1n - S) / ED_L * ED_L)), // S + 15·L ≥ 2^255, same point
      neg('s-eq-l', false, metatx, withS(ED_L)),
      neg('r-identity', false, metatx, forge(ED_ID)), // the cofactorless equation holds: only the small-order R rule refuses
      neg('r-small-order', false, metatx, forge(ED_T8)), // the cofactored equation holds (noble zip215:false alone accepts)
      neg('r-noncanonical-y', false, metatx, forge(le(ED_P + 1n))), // the identity as y = p + 1
      neg('r-x0-signbit', false, metatx, forge(withSign(ED_ID))), // the identity with the sign bit set (x = 0)
      // R = [r]B + T8 and S = r + k·a: cofactored equation holds (noble zip215:false alone accepts), cofactorless does not
      neg('r-mixed-order', false, metatx, edSignRaw(a, keyData, metatx, edNonce('scaas.ua.vectors.sig.ed25519.r-mixed', 0), ED_T8)),
    );
  }
  if (s.kind === 0x0101) negatives.push(neg('high-s', false, metatx, highS(metatxSig)));
  if (s.kind === 0x0108) {
    negatives.push(neg('high-s', false, metatx, secpHighS(metatxSig)), neg('v-flipped', false, metatx, withV(metatxSig, 55 - metatxSig[64])),
      neg('v-raw-0', false, metatx, withV(metatxSig, metatxSig[64] - 27)), neg('v-29', false, metatx, withV(metatxSig, 29)),
      neg('short', false, metatx, metatxSig.subarray(0, 64)), neg('r-zero', false, metatx, concatBytes(new Uint8Array(32), metatxSig.subarray(32))));
  }
  if (s.kind === 0x0104 || s.kind === 0x0105) {
    const p = metatxSig.length - 32;
    const r = s.n;
    negatives.push(neg('z-not-reduced', false, metatx, concatBytes(metatxSig.subarray(0, p), be(int(metatxSig.subarray(p)) + r, 32))));
  }
  if (s.kind === 0x0106 || s.kind === 0x0107) {
    negatives.push(neg('sig-dst-as-pop', true, popA, sign(popA)), neg('pop-dst-as-sig', false, metatx, sign(metatx, { pop: true })),
      neg('identity', false, metatx, new Uint8Array(metatxSig.length)));
  }
  if (s.kind === 0x0106) negatives.push(neg('off-subgroup', false, metatx, blsG1OffSubgroup()));
  return { name, kind: s.kind, secret: hex(be(sk, 32)), keyData: hex(keyData), ua: hex(id), pop: pop('A'), popOther: pop('B'),
    sigs, negatives, ...(s.stored ? { stored: true } : {}) };
});

// --- native EOA: UAAuth under the registry domain ---
const domain = (ctx, generation) => ({ generation, ...contexts[ctx] });
const authDigest = (ctx, gen, id, p, d) => ua.uaAuthDigest(domain(ctx, gen), id, tag(p), d);
const nativeSigs = [['A', 1, 'metatx'], ['A', 1, 'member'], ['A', 2, 'metatx'], ['B', 1, 'metatx']].map(([context, generation, purpose]) => {
  const h = authDigest(context, generation, nativeUa, purpose, DIGEST);
  return { context, generation, purpose, digest: hex(DIGEST), uaAuthDigest: hex(h), sig: hex(ecdsa(nativeSk, h)) };
});
const goodA = fromHex(nativeSigs[0].sig);
const nativeHighS = concatBytes(goodA.subarray(0, 32), be(SECP_N - int(goodA.subarray(32, 64)), 32), Uint8Array.of(55 - goodA[64]));
const nativeNeg = (name, sig) => ({ name, context: 'A', generation: 1, purpose: 'metatx', digest: hex(DIGEST), sig: hex(sig) });
const nativeNegatives = [
  nativeNeg('raw-digest', ecdsa(nativeSk, DIGEST)),
  nativeNeg('other-generation', fromHex(nativeSigs[2].sig)),
  nativeNeg('other-registry', ecdsa(nativeSk, authDigest('D', 1, nativeUa, 'metatx', DIGEST))),
  nativeNeg('wrong-purpose', fromHex(nativeSigs[1].sig)),
  nativeNeg('high-s', nativeHighS),
];

// --- msig: native(1), p256(1), bls-bn254-minsig(1), schnorr-bn254(2); threshold 3 ---
const row = (name) => derivedRows.find((r) => r.name === name);
const cmp = (a, b) => { for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; };
const members = [
  { kind: 0x0001, name: 'native', id: nativeUa, weight: 1 },
  ...[['p256', 1], ['bls-bn254-minsig', 1], ['schnorr-bn254', 2]].map(([name, weight]) => ({ kind: SCHEMES[name].kind, name, id: fromHex(row(name).ua), weight })),
].sort((a, b) => cmp(a.id, b.id)).map((m, index) => ({ ...m, index }));
const THRESHOLD = 3;
const msigKey = ua.encodeMsig(THRESHOLD, members);
const msigUa = ua.deriveUA(0x0120, msigKey);
const msigPurpose = 'metatx';
const memberDigest = ua.memberDigest(msigUa, ua.uaMessage(0x0120, tag(msigPurpose), DIGEST));
const byName = Object.fromEntries(members.map((m) => [m.name, m]));
/** One MemberSig {index, keyData, sig}: native over UAAuth(id, member, member_digest) in context A gen 1, derived via its scheme. */
function memberSig(name, { raw = false, secretName } = {}) {
  const m = byName[name];
  if (m.kind === 0x0001) {
    return { index: m.index, keyData: new Uint8Array(0), sig: ecdsa(nativeSk, raw ? memberDigest : authDigest('A', 1, m.id, 'member', memberDigest)) };
  }
  const s = SCHEMES[name];
  const sk = secretOf(secretName ?? name, s.n);
  return { index: m.index, keyData: s.keyData(sk), sig: s.sign(sk, ua.uaMessage(m.kind, tag('member'), memberDigest)) };
}
const byIndex = (list) => [...list].sort((a, b) => a.index - b.index);
const set = (name, valid, list) => {
  const sig = encodeMemberSigs(list);
  return { name, valid, purpose: msigPurpose, digest: hex(DIGEST), memberDigest: hex(memberDigest), indices: list.map((s) => s.index),
    sig: hex(sig), auth: hex(abiEncode(['bytes', 'bytes'], [msigKey, sig])) };
};
const S = (n, o) => memberSig(n, o);
const sets = [
  set('at-threshold', true, byIndex([S('native'), S('schnorr-bn254')])),
  set('at-threshold-three', true, byIndex([S('native'), S('p256'), S('bls-bn254-minsig')])),
  set('extra-after-threshold', false, byIndex(members.map((m) => S(m.name)))),
  set('below-threshold', false, byIndex([S('native'), S('p256')])),
  set('unsorted', false, byIndex([S('native'), S('schnorr-bn254')]).reverse()),
  set('duplicate', false, byIndex([S('native'), S('native'), S('p256')])),
  set('wrong-member-key', false, byIndex([S('native'), S('p256', { secretName: 'p256-other' }), S('bls-bn254-minsig')])),
  set('native-raw-digest', false, byIndex([S('native', { raw: true }), S('schnorr-bn254')])),
  // R12: a native member's MemberSig carries no key data (here its address), even with a valid signature
  set('native-member-keydata', false, byIndex([{ ...S('native'), keyData: nativeAddr }, S('schnorr-bn254')])),
];

// --- BIP-340 official test vectors (bip-0340/test-vectors.csv), the 32-byte-message cases 0–14 ---
const BIP340_A = 'dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659';
const BIP340_M = '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89';
const bip340Official = [
  [0, 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9', '00'.repeat(32),
    'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0', true, ''],
  [1, BIP340_A, BIP340_M,
    '6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a', true, ''],
  [2, 'dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8', '7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c',
    '5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7', true, ''],
  [3, '25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517', 'ff'.repeat(32),
    '7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3', true, 'test fails if msg is reduced modulo p or n'],
  [4, 'd69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9', '4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703',
    '00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4', true, ''],
  [5, 'eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34', BIP340_M,
    '6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b', false, 'public key not on the curve'],
  [6, BIP340_A, BIP340_M,
    'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2', false, 'has_even_y(R) is false'],
  [7, BIP340_A, BIP340_M,
    '1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd', false, 'negated message'],
  [8, BIP340_A, BIP340_M,
    '6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6', false, 'negated s value'],
  [9, BIP340_A, BIP340_M,
    '0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051', false, 'sG - eP is infinite (x(inf) as 0)'],
  [10, BIP340_A, BIP340_M,
    '00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197', false, 'sG - eP is infinite (x(inf) as 1)'],
  [11, BIP340_A, BIP340_M,
    '4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b', false, 'sig[0:32] is not an X coordinate on the curve'],
  [12, BIP340_A, BIP340_M,
    'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b', false, 'sig[0:32] is equal to the field size'],
  [13, BIP340_A, BIP340_M,
    '6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', false, 'sig[32:64] is equal to the curve order'],
  [14, 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30', BIP340_M,
    '6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b', false, 'public key exceeds the field size'],
].map(([index, publicKey, message, signature, valid, comment]) => {
  let ok;
  try { ok = schnorr.verify(fromHex(signature), fromHex(message), fromHex(publicKey)); } catch { ok = false; }
  if (ok !== valid) throw new Error(`BIP-340 vector ${index}: noble says ${ok}`);
  return { index, publicKey: `0x${publicKey}`, message: `0x${message}`, sig: `0x${signature}`, valid, comment };
});

// --- ed25519 (UA-2b): RFC 8032 §7.1 test vectors (any message length: the verifier library's verifyRaw) and A-side cases ---
const RFC8032 = [
  ['TEST 1', '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    '',
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
  ['TEST 2', '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    '72',
    '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'],
  ['TEST 3', 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    'af82',
    '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'],
  ['TEST 1024', 'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5',
    '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',
    '08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0',
    '0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03'],
  ['TEST SHA(abc)', '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
    'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    'dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704'],
];
const edRow = derivedRows.find((r) => r.name === 'ed25519');
const edMsg = fromHex(edRow.sigs[0].message);
const edScalar = ed25519.utils.getExtendedPublicKey(fromHex(edRow.secret)).scalar;
/** R = [r_i]B (r_i = edNonce(label, i)), S = r_i + k·a under key bytes A, for the first i whose k = H(R ‖ A ‖ M) passes `want`. */
function edGrind(label, a, A, M, want) {
  for (let i = 0; ; i++) {
    const sig = edSignRaw(a, A, M, edNonce(label, i));
    if (want(edK(sig.subarray(0, 32), A, M))) return sig;
  }
}
const edMixedA = EdPoint.BASE.multiply(edScalar).add(EdPoint.fromBytes(ED_T8)).toBytes();
const ed25519Rfc8032 = [
  ...RFC8032.map(([name, secret, publicKey, message, signature]) => {
    const [sk, pk, m, sig] = [secret, publicKey, message, signature].map(fromHex);
    if (hex(ed25519.getPublicKey(sk)) !== hex(pk) || hex(ed25519.sign(m, sk)) !== hex(sig)) throw new Error(`RFC 8032 ${name}: noble differs`);
    if (name === 'TEST SHA(abc)' && hex(m) !== hex(sha512(utf8ToBytes('abc')))) throw new Error('TEST SHA(abc) message');
    return { name, publicKey: hex(pk), message: hex(m), sig: hex(sig), valid: true, comment: `RFC 8032 §7.1 ${name} (${m.length}-byte message)` };
  }),
  // A-side: each satisfies the cofactorless equation; only the A rules refuse (A = T8: k ≡ 0 mod 8; A = identity: any k)
  ...[
    ['small-order-a', ED_T8, (k) => k % 8n === 0n, 'A of order 8, k ≡ 0 mod 8, S = r: [S]B == R + [k]A'],
    ['a-identity', ED_ID, () => true, 'A = identity, S = r'],
    ['a-noncanonical-y', le(ED_P + 1n), () => true, 'A = the identity as y = p + 1 (non-canonical), S = r'],
    ['a-x0-signbit', withSign(ED_ID), () => true, 'A = the identity with the sign bit set (x = 0), S = r'],
  ].map(([name, A, want, comment]) => ({ name, publicKey: hex(A), message: hex(edMsg), sig: hex(edGrind(`scaas.ua.vectors.sig.ed25519.${name}`, 0n, A, edMsg, want)), valid: false, comment })),
  // A = [a]B + T8 (mixed order, not small order: key data accepts it): S = r + k·a holds cofactorless iff [k]T8 = O
  { name: 'a-mixed-order-k0', publicKey: hex(edMixedA), message: hex(edMsg), valid: true,
    sig: hex(edGrind('scaas.ua.vectors.sig.ed25519.a-mixed-order-k0', edScalar, edMixedA, edMsg, (k) => k % 8n === 0n)),
    comment: 'A = [a]B + T8, k ≡ 0 mod 8: the cofactorless equation holds (verify_strict accepts)' },
  { name: 'a-mixed-order', publicKey: hex(edMixedA), message: hex(edMsg), valid: false,
    sig: hex(edGrind('scaas.ua.vectors.sig.ed25519.a-mixed-order', edScalar, edMixedA, edMsg, (k) => k % 8n !== 0n)),
    comment: 'A = [a]B + T8, k ≢ 0 mod 8: only the cofactored equation holds (noble zip215:false alone accepts)' },
];
for (const t of ed25519Rfc8032) {
  if (edStrict(fromHex(t.publicKey), fromHex(t.message), fromHex(t.sig)) !== t.valid) throw new Error(`ed25519Rfc8032 ${t.name}: verdict`);
}

// --- ed25519_fuzz.json (T-FUZZ): cases from a fixed seed, verdict = strict (edStrict, = ed25519-dalek verify_strict) ---
const FUZZ_SEED = 'scaas.ua.vectors.ed25519.fuzz.v1';
let fuzzCtr = 0;
const rnd = () => keccak_256(concatBytes(utf8ToBytes(FUZZ_SEED), be(BigInt(fuzzCtr++), 4)));
const rint = (n) => Number(int(rnd()) % BigInt(n));
const pick = (list) => list[rint(list.length)];
const fuzzKeys = Array.from({ length: 16 }, (_, i) => {
  const seed = keccak_256(utf8ToBytes(`${FUZZ_SEED}.key.${i}`));
  const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(seed);
  return { seed, a: scalar, A: pointBytes };
});
/** Non-canonical encodings (y ≥ p, or x = 0 with the sign bit) of points on the curve, split by small order. */
const nonCanon = { small: [withSign(ED_ID), withSign(le(ED_P - 1n))], mixed: [] };
for (let y = 0n; y < 19n; y++) for (const b of [le(ED_P + y), withSign(le(ED_P + y))]) {
  let P;
  try { P = EdPoint.fromBytes(b, true); } catch { continue; }
  nonCanon[P.isSmallOrder() ? 'small' : 'mixed'].push(b);
}
const smallOrder = [...TORSION, ...nonCanon.small];
const T_NONZERO = TORSION.slice(1);
const torsionOrder = (T) => { let P = EdPoint.fromBytes(T); let n = 1; while (!P.is0()) { P = P.add(EdPoint.fromBytes(T)); n++; } return BigInt(n); };
const flipBit = (b) => { const c = Uint8Array.from(b); const i = rint(c.length * 8); c[i >> 3] ^= 1 << (i & 7); return c; };
const honest = () => { const key = pick(fuzzKeys); const msg = rnd(); return { key, pk: key.A, msg, sig: ed25519.sign(msg, key.seed) }; };
const setS = (sig, v) => concatBytes(sig.subarray(0, 32), le(v));
const getS = (sig) => leInt(sig.subarray(32));
const nonce = () => int(rnd()) % ED_L;
const FUZZ = [
  ['valid', 192, () => honest()],
  ['sig-bit', 416, () => { const c = honest(); return { ...c, sig: flipBit(c.sig) }; }],
  ['sig-byte', 128, () => { const c = honest(); const sig = Uint8Array.from(c.sig); const i = rint(64); sig[i] = (sig[i] + 1 + rint(255)) & 0xff; return { ...c, sig }; }],
  ['pk-bit', 192, () => { const c = honest(); return { ...c, pk: flipBit(c.pk) }; }],
  ['msg-bit', 192, () => { const c = honest(); return { ...c, msg: flipBit(c.msg) }; }],
  ['msg-random', 64, () => ({ ...honest(), msg: rnd() })],
  ['s-near-l', 128, () => { const c = honest(); return { ...c, sig: setS(c.sig, ED_L + BigInt(rint(33)) - 16n) }; }],
  ['s-plus-jl', 96, () => { const c = honest(); const S = getS(c.sig); return { ...c, sig: setS(c.sig, S + BigInt(1 + rint(Number(((1n << 256n) - 1n - S) / ED_L))) * ED_L) }; }],
  // R spliced with a small-order encoding; S = k·a (cofactored equation holds when canonical) or random
  ['r-small-order', 128, () => { const c = honest(); const Rb = pick(smallOrder);
    return { ...c, sig: rint(2) ? edForgeR(c.key.a, c.pk, c.msg, Rb) : concatBytes(Rb, le(nonce())) }; }],
  ['r-noncanonical', 96, () => { const c = honest(); const Rb = pick([...nonCanon.small, ...nonCanon.mixed]);
    return { ...c, sig: rint(2) ? edForgeR(c.key.a, c.pk, c.msg, Rb) : concatBytes(Rb, c.sig.subarray(32)) }; }],
  ['r-mixed-order', 96, () => { const c = honest(); return { ...c, sig: edSignRaw(c.key.a, c.pk, c.msg, nonce(), pick(T_NONZERO)) }; }],
  // A small order (canonical or not), R = [r]B, S = r; half ground so that [k]A = O (the cofactorless equation holds too)
  ['a-small-order', 96, () => { const A = pick(smallOrder); const msg = rnd(); const ground = rint(2);
    for (;;) { const r = nonce(); const sig = edSignRaw(0n, A, msg, r);
      if (!ground || (edK(sig.subarray(0, 32), A, msg) % 8n === 0n)) return { pk: A, msg, sig }; } }],
  ['a-noncanonical', 64, () => { const c = honest(); return { ...c, pk: pick(nonCanon.mixed) }; }],
  // A = [a]B + T: S = r + k·a; half ground so that [k]T = O (strict accepts), else as drawn
  ['a-mixed-order', 160, () => { const key = pick(fuzzKeys); const T = pick(T_NONZERO); const ord = torsionOrder(T);
    const A = EdPoint.BASE.multiply(key.a).add(EdPoint.fromBytes(T)).toBytes(); const msg = rnd(); const ground = rint(2);
    for (;;) { const sig = edSignRaw(key.a, A, msg, nonce());
      if (!ground || edK(sig.subarray(0, 32), A, msg) % ord === 0n) return { pk: A, msg, sig }; } }],
  ['random', 96, () => ({ pk: rnd(), msg: rnd(), sig: concatBytes(rnd(), le(nonce())) })],
];
const fuzzCases = [];
for (const [cls, n, make] of FUZZ) for (let i = 0; i < n; i++) {
  const { pk, msg, sig } = make();
  // keys in alphabetical order (forge's parseJson decodes objects into structs that way)
  fuzzCases.push({ class: cls, msg: hex(msg), noble: edNoble(pk, msg, sig), pk: hex(pk), sig: hex(sig), valid: edStrict(pk, msg, sig) });
}
const NOBLE_DIFFERS = ['r-small-order', 'r-mixed-order', 'a-mixed-order'];
for (const c of fuzzCases) if (c.noble !== c.valid && !NOBLE_DIFFERS.includes(c.class)) throw new Error(`noble differs outside the known classes: ${c.class}`);
const fuzzCounts = Object.fromEntries(FUZZ.map(([cls]) => {
  const cs = fuzzCases.filter((c) => c.class === cls);
  return [cls, { cases: cs.length, valid: cs.filter((c) => c.valid).length, nobleDiffers: cs.filter((c) => c.noble !== c.valid).length }];
}));
const fuzzNote = 'Generated by clients/clientkeys/scripts/ua-sig-vectors.mjs (@noble/curves 2.4.0); never edit by hand. UA-2b T-FUZZ '
  + '(accounts.md §1.16): ed25519 cases over 32-byte messages from a fixed seed. `valid` = strict RFC 8032 = ed25519-dalek '
  + 'verify_strict (canonical A and R, S < L, A and R not small order, cofactorless [S]B == R + [k]A); clients/ua-rs '
  + 'tests/ed25519_fuzz.rs requires dalek == valid on every case, the Solidity verifier must give `valid` too. `noble` = '
  + 'noble ed25519.verify with zip215:false alone (cofactored equation, small-order R allowed): it differs from `valid` only '
  + 'in the classes listed in nobleDiffers (R small order with S = k·a, R or A with a torsion component).';
const fuzzOut = { note: fuzzNote, version: 1, seed: FUZZ_SEED, nobleDiffers: NOBLE_DIFFERS, counts: fuzzCounts, cases: fuzzCases };

// --- metatx3.json (UA-4): the UA ledger's two structs on context A, one row per signer ---
const M3 = { name: 'SCaaS MetaToken', contract: '0x5ca00000000000000000000000000000000000a1', chainId: contexts.A.chainId,
  chainUid: contexts.A.chainUid };
const M3_UNDERLYING = '0x5ca00000000000000000000000000000000000b1';
const M3_RELAYER = '0x000000000000000000000000000000000000beef';
const M3_FEE_TO = '0x0000000000000000000000000000000000000fee';
const M3_PAYEE = '0x0000000000000000000000000000000000005409';
const M3_REF = keccak_256(utf8ToBytes('scaas.metatx3.entryRef'));
const M3_DATA = concatBytes(keccak_256(utf8ToBytes('unwrap(address,uint256,address,uint256)')).subarray(0, 4),
  abiEncode(['address', 'uint256', 'address', 'uint256'], [M3_UNDERLYING, 1000000n, M3_PAYEE, 990000n]));
const m3Call = (from) => uaMetaTxTypedData({ ...M3, message: { from, data: hex(M3_DATA), batch: 7, nonce: 0,
  validUntil: 1800000300, mode: 0x13, relayer: M3_RELAYER, fee: 5000, feeRecipient: M3_FEE_TO } });
const m3Transfer = (from) => uaMetaTransferTypedData({ ...M3, message: { from, to: padId(M3_PAYEE), value: 100000000,
  entryRef: hex(M3_REF), batch: payLane(M3_REF), nonce: 0, validUntil: 1800000300, mode: 0x23, relayer: M3_RELAYER,
  fee: 100000, feeRecipient: M3_FEE_TO } });
const m3Signers = [{ name: 'native', kind: 0x0001, id: nativeUa, keyData: null, sign: (d) => ecdsa(nativeSk, d) },
  ...derivedRows.map((r) => ({ name: r.name, kind: r.kind, id: fromHex(r.ua), keyData: fromHex(r.keyData),
    sign: (d) => SCHEMES[r.name].sign(int(fromHex(r.secret)), ua.uaMessage(r.kind, tag('metatx'), d)) }))]
  .map((x) => (x.name === 'zether-bls12381' ? { ...x, keyData: new Uint8Array(0) } : x)); // stored kind: empty keyData in the auth
/** Native: 65-byte ECDSA over the v3 digest itself; derived: abi.encode(keyData, sig over ua_msg(kind, metatx, digest)). */
const m3Rows = (build) => m3Signers.map((s) => {
  const typedData = build(s.id);
  const digest = hashTypedData(typedData);
  const sig = s.sign(digest);
  return { name: s.name, kind: s.kind, from: hex(s.id), typedData,
    structHash: hex(hashStruct(typedData.types, typedData.primaryType, typedData.message)), digest: hex(digest),
    auth: hex(s.keyData ? abiEncode(['bytes', 'bytes'], [s.keyData, sig]) : sig) };
});
// UA-5a: `burn` and `unwrapToUA` under a UA (lanes 8 and 9; the fee as `call`'s), and receiver-pays on the UA path
const m3CallOf = (data, batch) => (from) => uaMetaTxTypedData({ ...M3, message: { from, data: hex(data), batch, nonce: 0,
  validUntil: 1800000300, mode: 0x13, relayer: M3_RELAYER, fee: 5000, feeRecipient: M3_FEE_TO } });
const M3_UA_TO = fromHex(row('p256').ua); // the receiver of `unwrapToUA`: a registered SIGNING UA
const m3Burn = m3CallOf(concatBytes(keccak_256(utf8ToBytes('burn(uint256)')).subarray(0, 4),
  abiEncode(['uint256'], [1000000n])), 8);
const m3UnwrapToUA = m3CallOf(unwrapToUACalldata(M3_UNDERLYING, 1000000n, M3_UA_TO, 990000n), 9);
const M3_RF = { fee: 300000, feeRecipient: M3_FEE_TO, validUntil: 1800000060 };
/** The payment of receiver-pays: fee NONE, relayer bound (mode 0x01), its own pay lane, nonce 0 (CTR-MTX-06's shape). */
const m3Payment = (from, to, ref) => uaMetaTransferTypedData({ ...M3, message: { from, to, value: 100000000,
  entryRef: hex(ref), batch: payLane(ref), nonce: 0, validUntil: 1800000300, mode: 0x01, relayer: M3_RELAYER } });
/** Native: ECDSA over the digest itself, whatever the purpose; derived: abi.encode(keyData, sig over ua_msg(kind, purpose, digest)). */
const m3Auth = (s, purpose, d) => hex(s.keyData
  ? abiEncode(['bytes', 'bytes'], [s.keyData, SCHEMES[s.name].sign(int(fromHex(row(s.name).secret)), ua.uaMessage(s.kind, tag(purpose), d))])
  : ecdsa(nativeSk, d));
/** One receiver-pays row: `payerAuth` under `metatx` over the payment digest, `payeeAuth` under `receiver-fee` over the
 *  `ReceiverFee` digest; `sign(signer, purpose, digest)` makes either auth blob. */
const rfRow = (payer, payee, sign) => {
  const ref = keccak_256(utf8ToBytes(`scaas.metatx3.receiverFee.${payer.name}.${payee.name}`));
  const transfer = m3Payment(payer.id, payee.id, ref);
  const paymentDigest = hashTypedData(transfer);
  const receiverFee = receiverFeeTypedData({ ...M3, paymentDigest, ...M3_RF });
  const receiverFeeDigest = hashTypedData(receiverFee);
  return { payer: payer.name, payee: payee.name, transfer, paymentDigest: hex(paymentDigest), receiverFee,
    receiverFeeDigest: hex(receiverFeeDigest), payerAuth: sign(payer, 'metatx', paymentDigest),
    payeeAuth: sign(payee, 'receiver-fee', receiverFeeDigest) };
};
const m3Signer = (name) => m3Signers.find((s) => s.name === name);
const m3ReceiverFee = [...m3Signers.slice(1).map((p) => rfRow(m3Signers[0], p, m3Auth)),
  rfRow(m3Signer('p256'), m3Signer('bip340'), m3Auth)];
const m3Out = {
  note: 'Generated by clients/clientkeys/scripts/ua-sig-vectors.mjs (src/evm.js typed data, src/ua.js, @noble/curves 2.4.0); '
    + 'never edit by hand. accounts.md CTR-UA-19/26: domain ("SCaaS MetaToken", "1", chainId, token, salt = chain_uid) of '
    + 'context A; keys, PoPs and the registry are those of signatures.json (context A). Native auth = ECDSA over the digest '
    + '(CTR-UA-24); derived auth = abi.encode(bytes keyData, bytes sig) for requireAuthorized(from, metatx, digest, auth).',
  version: 1, context: 'A', chainId: M3.chainId, chainUid: M3.chainUid, registry: contexts.A.registry, token: M3.contract,
  typeHashes: {
    UAMetaTransaction: hex(keccak_256(utf8ToBytes('UAMetaTransaction(bytes32 from,bytes data,uint256 batch,uint256 nonce,'
      + 'uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)'))),
    UAMetaTransfer: hex(keccak_256(utf8ToBytes('UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,'
      + 'uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)'))),
  },
  domainSeparator: hex(hashStruct(m3Call(nativeUa).types, 'EIP712Domain', m3Call(nativeUa).domain)),
  call: m3Rows(m3Call),
  transfer: m3Rows(m3Transfer),
  noteUA5a: 'UA-5a (accounts.md CTR-UA-26/28, metatx.md CTR-MTX-05/06): burn and unwrapToUA are UAMetaTransaction rows '
    + 'as call (auth under metatx); receiverFee rows are uaPayReceiverFee(transfer, payerAuth, receiverFee.message.fee, '
    + 'feeRecipient, validUntil, payeeAuth): native payer x every derived payee, and p256 x bip340. A native payee signs '
    + 'receiverFeeDigest itself; a derived payee abi.encode(bytes keyData, bytes sig over ua_msg(kind, receiver-fee, '
    + 'receiverFeeDigest)).',
  burn: m3Rows(m3Burn),
  unwrapToUA: m3Rows(m3UnwrapToUA),
  receiverFee: m3ReceiverFee,
};

// --- pq_signatures.json (P6c): the PQ kinds on context A; stored kinds, so every auth carries an empty keyData ---
const PQ_OTHER = { mldsa44: 'mldsa65', mldsa65: 'mldsa44', fndsa512: 'slhdsa128s', slhdsa128s: 'fndsa512' };
// UA-6: a PQ signer registers its PQZ key in the same call; UA-8: its pop is over registrationDigest(portablePopDigest(ua, h, 0),
// pqzPopHash) with h = keyHash(0x0142, pqzKey) != 0 (the same key as ua-vectors.mjs) and the hash of the R_REG proof
// (portable.json's n2048-kmax1024 filler). `popPqz` rows: the digest and message move with h, so a pop for no key does not carry over.
const PQZ_SET = 'n2048-kmax1024';
const PQZ_KEY = pqzKeyOf(PQZ_SET);
const PQZ_POP = pqzPopOf(PQZ_SET);
const PQZ_ATTRS = { pqzKey: PQZ_KEY, pqzPop: PQZ_POP };
const PQZ_HOLDERS = new Set(['mldsa44', 'mldsa65', 'fndsa512']);
const pqAuth = (sig) => hex(abiEncode(['bytes', 'bytes'], [new Uint8Array(0), sig]));
const pqRows = Object.keys(PQ_KINDS).map((name) => {
  const { kind } = PQ_KINDS[name];
  const kp = pqKey(name, 0);
  const sign = (m) => pqSignMsg(name, kp.secretKey, m);
  const pop = (ctx, attrs) => {
    const p = popOf(kind, kp.ua, attrs);
    return popRow(ctx, p, sign(p.message), attrs ? { pqzKeyHash: hex(p.pqzKeyHash), pqzPopHash: hex(p.pqzPopHash) } : {});
  };
  const metatx = ua.uaMessage(kind, tag('metatx'), DIGEST);
  const member = ua.uaMessage(kind, tag('member'), DIGEST);
  const metatxSig = sign(metatx);
  const popA = popOf(kind, kp.ua).message;
  const neg = (n, verifyPop, message, sig) => ({ name: n, verifyPop, message: hex(message), sig: hex(sig) });
  const negatives = [
    neg('wrong-purpose', false, member, metatxSig),
    neg('wrong-kind-tag', false, metatx, sign(ua.uaMessage(PQ_KINDS[PQ_OTHER[name]].kind, tag('metatx'), DIGEST))),
    neg('chain-bound-pop', true, popA, sign(chainBoundPop(kind, kp.ua))), // UA-8: the pre-UA-8 PoP of context A
    neg('pop-v1-purpose', true, popA, sign(popV1Purpose(kind, kp.ua))),
    neg('pop-as-sig', false, metatx, sign(popA)),
    neg('mutated', false, metatx, flip(metatxSig, metatxSig.length >> 1)),
  ];
  if (PQ_KINDS[name].pq) { // the transitional context form CTR-UA-23 dropped
    negatives.push(neg('context-kind-tag', false, metatx,
      PQ_KINDS[name].alg.sign(pqMessage(name, metatx), kp.secretKey, { context: utf8ToBytes(PQ_KINDS[name].tag), extraEntropy: false })));
  }
  if (PQZ_HOLDERS.has(name)) {
    // the pop without the key does not verify as the holder's pop with it, and the reverse
    negatives.push(neg('pop-without-pqz-key', true, popOf(kind, kp.ua, PQZ_ATTRS).message, sign(popA)),
      neg('pop-with-pqz-key-as-plain', true, popA, sign(popOf(kind, kp.ua, PQZ_ATTRS).message)));
  }
  return { name, kind, keyData: hex(kp.publicKey), ua: hex(kp.ua), pop: pop('A'), popOther: pop('B'),
    ...(PQZ_HOLDERS.has(name) ? { pqzKey: hex(PQZ_KEY), popPqz: pop('A', PQZ_ATTRS) } : {}),
    sigs: [
      { purpose: 'metatx', purposeTag: hex(tag('metatx')), digest: hex(DIGEST), message: hex(metatx), sig: hex(metatxSig) },
      { purpose: 'member', purposeTag: hex(tag('member')), digest: hex(DIGEST), message: hex(member), sig: hex(sign(member)) },
    ],
    negatives };
});
// msig over PQ members (accounts.md §1.6 "Which kind for whom", CTR-PQZ-12): mldsa65 keys 0–2, the p256 key of signatures.json
const pqMembers = [0, 1, 2].map((i) => ({ i, kp: pqKey('mldsa65', i) }));
const pqExtra = pqMembers.slice(1).map(({ i, kp }) => {
  const p = popOf(0x0131, kp.ua);
  return { name: 'mldsa65', index: i, kind: 0x0131, keyData: hex(kp.publicKey), ua: hex(kp.ua),
    pop: popRow('A', p, pqSignMsg('mldsa65', kp.secretKey, p.message)) };
});
const p256Sk = secretOf('p256', SCHEMES.p256.n);
function pqMsig(name, list, threshold) {
  const ms = list.map((m) => ({ ...m })).sort((a, b) => cmp(a.id, b.id)).map((m, index) => ({ ...m, index }));
  const keyData = ua.encodeMsig(threshold, ms);
  const id = ua.deriveUA(0x0120, keyData);
  const md = ua.memberDigest(id, ua.uaMessage(0x0120, tag('metatx'), DIGEST));
  const sigOf = (m, mdv = md) => (m.kind === 0x0101
    ? { index: m.index, keyData: SCHEMES.p256.keyData(p256Sk), sig: SCHEMES.p256.sign(p256Sk, ua.uaMessage(0x0101, tag('member'), mdv)) }
    : { index: m.index, keyData: new Uint8Array(0), sig: pqSignMsg('mldsa65', m.sk, ua.uaMessage(0x0131, tag('member'), mdv)) });
  // UA-6 U5 / UA-8: a PQ-eligible msig registers with an m-of-n pop over the portable PoP (purpose pop v2, members under member)
  const hp = popOf(0x0120, id, { keyData, ...PQZ_ATTRS });
  const popMd = hp.memberDigest;
  const popList = ms.slice(0, threshold).map((m) => sigOf(m, popMd));
  const popBlob = encodeMemberSigs(popList);
  const set = (n, valid, picks) => {
    const list = picks.map((k) => sigOf(ms[k]));
    const sig = encodeMemberSigs(list);
    return { name: n, valid, indices: picks,
      memberSigs: list.map((x) => ({ index: x.index, keyData: hex(x.keyData), sig: hex(x.sig) })),
      sig: hex(sig), auth: hex(abiEncode(['bytes', 'bytes'], [keyData, sig])) };
  };
  const sets = threshold === 2 && ms.length === 3
    ? [set('members-0-1', true, [0, 1]), set('members-1-2', true, [1, 2]), set('below-threshold', false, [0])]
    : [set('both', true, [0, 1]), set('below-threshold', false, [0])];
  return { name, keyData: hex(keyData), ua: hex(id), threshold, purpose: 'metatx', digest: hex(DIGEST), memberDigest: hex(md),
    pqzEligible: ua.msigPqzEligible(keyData),
    popPqz: { context: 'A', pqzKey: hex(PQZ_KEY), pqzKeyHash: hex(hp.pqzKeyHash), pqzPopHash: hex(hp.pqzPopHash),
      popDigest: hex(hp.portablePopDigest), registrationDigest: hex(hp.registrationDigest), memberDigest: hex(popMd),
      pop: hex(popBlob), indices: ms.slice(0, threshold).map((m) => m.index) },
    members: ms.map((m) => ({ index: m.index, kind: m.kind, id: hex(m.id), weight: m.weight })), sets };
}
const pqTreasury = pqMsig('treasury', pqMembers.map(({ kp }) => ({ kind: 0x0131, id: kp.ua, weight: 1, sk: kp.secretKey })), 2);
const pqHybrid = pqMsig('hybrid', [{ kind: 0x0131, id: pqMembers[0].kp.ua, weight: 1, sk: pqMembers[0].kp.secretKey },
  { kind: 0x0101, id: fromHex(row('p256').ua), weight: 1 }], 2);
const pqM3Rows = (build) => pqRows.map((r) => {
  const typedData = build(fromHex(r.ua));
  const digest = hashTypedData(typedData);
  const sig = pqSignMsg(r.name, pqKey(r.name, 0).secretKey, ua.uaMessage(r.kind, tag('metatx'), digest));
  return { name: r.name, kind: r.kind, from: r.ua, typedData,
    structHash: hex(hashStruct(typedData.types, typedData.primaryType, typedData.message)), digest: hex(digest), auth: pqAuth(sig) };
});
// UA-5a: receiver-pays with an mldsa65 payer (index 0) and an mldsa65 payee (index 1, extraKeys[0]): two PQ verifies in
// one uaPayReceiverFee, the per-transaction cap case (metatx.md the uaPayReceiverFee paragraph)
const pqSigner = (index) => ({ name: `mldsa65#${index}`, kp: pqKey('mldsa65', index) });
const pqRfAuth = (s, purpose, d) => pqAuth(pqSignMsg('mldsa65', s.kp.secretKey, ua.uaMessage(0x0131, tag(purpose), d)));
const pqRf = [pqSigner(0), pqSigner(1)].map((s) => ({ ...s, id: s.kp.ua }));
const pqOut = {
  note: 'Generated by clients/clientkeys/scripts/ua-sig-vectors.mjs (src/pq.js on @noble/post-quantum 0.7.1, the keys of '
    + 'pq_kat.json: account 0, index 0; mldsa65 indexes 1 and 2 for the treasury); never edit by hand. Context A of '
    + 'signatures.json. PQ kinds are stored (CTR-UA-17): every auth is abi.encode(bytes(""), sig). ML-DSA and SLH-DSA sign '
    + 'pq_msg with the empty context, Falcon ua_msg (CTR-UA-23). Negatives: verifyPop = which registry entry point is asked. '
    + 'metatx3 rows: the domain, structs and fields of metatx3.json, one per PQ signer.',
  version: 1, context: 'A', contexts: { A: contexts.A, B: contexts.B, C: contexts.C, D: contexts.D }, digest: hex(DIGEST),
  mnemonic: PQ_MNEMONIC, kinds: pqRows, extraKeys: pqExtra, msig: { treasury: pqTreasury, hybrid: pqHybrid },
  metatx3: { token: M3.contract, call: pqM3Rows(m3Call), transfer: pqM3Rows(m3Transfer),
    receiverFee: [rfRow(pqRf[0], pqRf[1], pqRfAuth)] },
};

// --- write ---
// --- uatrade_kat.json (UA-5b): a UA's order, cancel and invalidate on context A, under the purpose trade ---
const UT = { name: 'SCaaS MetaToken', chainId: contexts.A.chainId, chainUid: contexts.A.chainUid };
const UT_A = '0x5ca00000000000000000000000000000000000c1'; // the sell token of the rows
const UT_B = '0x5ca00000000000000000000000000000000000c2';
const UT_DEX = '0x5ca00000000000000000000000000000000000d1';
const utOrder = (from, sell, receive, amount, receiveAmount, nonce) => uaTradeOrderTypedData({ ...UT, token: sell,
  order: { from, receiveToken: receive, amount, receiveAmount, fee: 3000, relayer: M3_RELAYER, dex: UT_DEX, batch: 1,
    nonce, validUntil: 1800000300 } });
/** One signer: its order (sells 1000 A for at least 2000 B), the cancel of that order and an invalidation to 5. */
const utRow = (s, sign) => {
  const order = utOrder(s.id, UT_A, UT_B, 1000, 2000, 1);
  const orderHash = hashTypedData(order);
  const cancel = orderCancelTypedData({ ...UT, contract: UT_A, orderHash: hex(orderHash) });
  const invalidate = uaInvalidateNoncesTypedData({ ...UT, contract: UT_A, from: s.id, batch: 1, minNonce: 5 });
  const cancelDigest = hashTypedData(cancel);
  const invalidateDigest = hashTypedData(invalidate);
  return { name: s.name, kind: s.kind, from: hex(s.id), order,
    structHash: hex(hashStruct(order.types, order.primaryType, order.message)), orderHash: hex(orderHash),
    auth: sign(s, 'trade', orderHash), cancelDigest: hex(cancelDigest), cancelAuth: sign(s, 'trade', cancelDigest),
    invalidate, invalidateDigest: hex(invalidateDigest), invalidateAuth: sign(s, 'trade', invalidateDigest) };
};
// the per-transaction caps (CTR-DEX-26): mldsa65 #0 sells 1000 A for 2000 B; #1 and #2 each sell 1000 B for 500 A
const utPq = [[0, UT_A, UT_B, 1000, 2000], [1, UT_B, UT_A, 1000, 500], [2, UT_B, UT_A, 1000, 500]].map(([i, sell, recv, a, r]) => {
  const s = { ...pqSigner(i), id: pqSigner(i).kp.ua };
  const order = utOrder(s.id, sell, recv, a, r, 1);
  const orderHash = hashTypedData(order);
  return { name: s.name, index: i, from: hex(s.id), sellToken: sell, order, orderHash: hex(orderHash),
    auth: pqRfAuth(s, 'trade', orderHash) };
});
const utNativeMaker = (() => { // the counterparty of every row: the native key sells 2000 B for 1000 A
  const order = utOrder(nativeUa, UT_B, UT_A, 2000, 1000, 2);
  const orderHash = hashTypedData(order);
  return { order, orderHash: hex(orderHash), auth: hex(ecdsa(nativeSk, orderHash)) };
})();
const utOut = {
  note: 'Generated by clients/clientkeys/scripts/ua-sig-vectors.mjs (src/evm.js typed data, src/ua.js, @noble/curves 2.4.0, '
    + '@noble/post-quantum 0.7.1); never edit by hand. dex.md CTR-DEX-25/26: UATradeOrder, CancelOrder over its digest and '
    + 'UAInvalidateNonces in the sell token\'s domain ("SCaaS MetaToken", "1", chainId, token, salt = chain_uid) of context A, '
    + 'under the UA purpose trade. Keys, PoPs and the registry are those of signatures.json and pq_signatures.json (context A). '
    + 'Native auth = ECDSA over the digest itself; derived auth = abi.encode(bytes keyData, bytes sig over ua_msg(kind, trade, '
    + 'digest)) (PQ kinds are stored: empty keyData). rows: every signer sells 1000 tokenA for at least 2000 tokenB; '
    + 'nativeMaker sells 2000 tokenB for 1000 tokenA (the counterparty); pq: mldsa65 #0 (taker) and #1, #2 (makers) for the '
    + 'per-transaction caps.',
  version: 1, context: 'A', chainId: UT.chainId, chainUid: UT.chainUid, registry: contexts.A.registry, tokenA: UT_A,
  tokenB: UT_B, dex: UT_DEX, purposeTag: hex(tag('trade')),
  typeHashes: {
    UATradeOrder: hex(keccak_256(utf8ToBytes('UATradeOrder(bytes32 from,address receiveToken,uint256 amount,uint256 '
      + 'receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,bytes32 destination,uint8 flags,uint256 batch,'
      + 'uint256 nonce,uint256 validUntil)'))),
    UAInvalidateNonces: hex(keccak_256(utf8ToBytes('UAInvalidateNonces(bytes32 from,uint256 batch,uint256 minNonce)'))),
    CancelOrder: hex(keccak_256(utf8ToBytes('CancelOrder(bytes32 orderHash)'))),
  },
  domainSeparatorA: hex(hashStruct(utNativeMaker.order.types, 'EIP712Domain', { ...utNativeMaker.order.domain, verifyingContract: UT_A })),
  rows: m3Signers.map((s) => utRow(s, m3Auth)),
  nativeMaker: utNativeMaker,
  pq: utPq,
};

const note = 'Generated by clients/clientkeys/scripts/ua-sig-vectors.mjs (src/ua.js on @noble/curves 2.4.0); never edit by hand. '
  + 'Every positive must verify and every negative must fail (verifyPop: which verifier entry point is asked). '
  + 'PoPs are portable (UA-8 P1): popDigest = portablePopDigest(ua, 0, 0), message = ua_msg(kind, pop v2, registrationDigest), '
  + 'the same in every context (popOther repeats pop under context B for its consumers); chain-bound-pop / pop-v1-purpose: the '
  + 'pre-UA-8 PoP and the v1 purpose are refused. '
  + 'The scaas Schnorr transcript and the bn254 mapToG1 have no independent second implementation: clients/ua-rs agreeing '
  + 'on them is self-consistency only (accounts.md §1.16). msig auth = abi.encode(bytes keyData, bytes sig) (§1.9).';
const out = {
  note, version: 1, context: 'A', contextOther: 'B', contexts: { A: contexts.A, B: contexts.B, C: contexts.C, D: contexts.D },
  digest: hex(DIGEST), derived: derivedRows, bip340Official,
  native: { secret: hex(be(nativeSk, 32)), address: hex(nativeAddr), ua: hex(nativeUa), sigs: nativeSigs, negatives: nativeNegatives },
  msig: { keyData: hex(msigKey), ua: hex(msigUa), threshold: THRESHOLD, context: 'A', generation: 1,
    members: members.map((m) => ({ index: m.index, kind: m.kind, name: m.name, id: hex(m.id), weight: m.weight, secretRef: m.name })),
    sets },
  ed25519Rfc8032,
};
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'signatures.json'), `${JSON.stringify(out, null, 2)}\n`);
// one case per line: the file stays near 0.6 MB and diffs by case
const fuzzJson = JSON.stringify({ ...fuzzOut, cases: [] }, null, 2)
  .replace('"cases": []', `"cases": [\n${fuzzCases.map((c) => `    ${JSON.stringify(c)}`).join(',\n')}\n  ]`);
writeFileSync(join(OUT, 'ed25519_fuzz.json'), `${fuzzJson}\n`);
writeFileSync(join(OUT, 'metatx3.json'), `${JSON.stringify(m3Out, null, 2)}\n`);
writeFileSync(join(OUT, 'pq_signatures.json'), `${JSON.stringify(pqOut, null, 2)}\n`);
writeFileSync(join(OUT, 'uatrade_kat.json'), `${JSON.stringify(utOut, null, 2)}\n`);
const fuzzValid = fuzzCases.filter((c) => c.valid).length;
const fuzzDiff = fuzzCases.filter((c) => c.noble !== c.valid).length;
const negs = derivedRows.reduce((n, r) => n + r.negatives.length, 0);
console.log(`signatures.json: ${derivedRows.length} derived kinds (${negs} negatives), native ${nativeSigs.length}+${nativeNegatives.length}, msig ${sets.length} sets, ${bip340Official.length} BIP-340 official, ${ed25519Rfc8032.length} ed25519Rfc8032; `
  + `ed25519_fuzz.json: ${fuzzCases.length} cases (${fuzzValid} valid, noble zip215:false alone differs on ${fuzzDiff}); `
  + `metatx3.json: ${m3Out.call.length} + ${m3Out.transfer.length} + ${m3Out.burn.length} + ${m3Out.unwrapToUA.length} + ${m3Out.receiverFee.length} rows; `
  + `pq_signatures.json: ${pqRows.length} kinds (${pqRows.reduce((n, r) => n + r.negatives.length, 0)} negatives), msig 2 structures, `
  + `metatx3 ${pqOut.metatx3.call.length} + ${pqOut.metatx3.transfer.length} + ${pqOut.metatx3.receiverFee.length}; `
  + `uatrade_kat.json: ${utOut.rows.length} rows + ${utOut.pq.length} mldsa65; written to ${OUT}`);
