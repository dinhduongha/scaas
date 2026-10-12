// Generates smartcontracts/vectors/ua/signatures.json: UA-2a signatures (accounts.md §1.4, §1.8, §1.9) on deterministic
// keys — per derived kind a key, its PoP in structures.json context A and B, signatures over ua_msg under metatx and member,
// and negatives a verifier must refuse; native EOA UAAuth signatures; an msig structure with member signature sets.
// Secrets: keccak256("scaas.ua.vectors.sig.<name>") mod (n − 1) + 1. Nonces: RFC 6979 (P-256, secp256k1 ECDSA), zero
// aux_rand (BIP-340), keccak256(secret ‖ message ‖ "scaas.ua.vectors.nonce") (scaas Schnorr). test/ua-sig.test.js
// re-verifies every row with noble; clients/scaas-ua (tests/signatures.rs) with p256 / k256 / arkworks.
//   node scripts/ua-sig-vectors.mjs [outDir]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, b64url, abiEncode, word } from '../src/bytes.js';
import * as ua from '../src/ua.js';

const VECTORS = fileURLToPath(new URL('../../../smartcontracts/vectors/ua/', import.meta.url));
const OUT = process.argv[2] ?? VECTORS;
const { contexts } = JSON.parse(readFileSync(join(VECTORS, 'structures.json'), 'utf8'));

const int = (b) => BigInt(hex(b));
const be = (v, len) => fromHex(v.toString(16).padStart(2 * len, '0'));
const secretOf = (name, n) => (int(keccak_256(utf8ToBytes(`scaas.ua.vectors.sig.${name}`))) % (n - 1n)) + 1n;
const flip = (b, i) => { const c = Uint8Array.from(b); c[i] ^= 1; return c; };
const tag = (p) => ua.purposeTag(p);
const DIGEST = keccak_256(utf8ToBytes('scaas.ua.vectors.sig.digest'));
const ZERO32 = new Uint8Array(32);

// --- schemes: keyData(sk) and sign(sk, msg32, { pop }) ---
const P256_N = p256.Point.Fn.ORDER;
const SECP_N = secp256k1.Point.Fn.ORDER;
const BN = bn254.fields;
const BLS = bls12_381.fields;

const p256Sign = (sk, h) => p256.sign(h, be(sk, 32), { prehash: false, lowS: true, format: 'compact' });
const highS = (sig) => concatBytes(sig.subarray(0, 32), be(P256_N - int(sig.subarray(32, 64)), 32));

const RP_ID = 'scaas.example';
const ORIGIN = 'https://scaas.example';
const CHROME_EXTRA = ',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"';
/** WebAuthn assertion as `abi.encode(bytes authenticatorData, string clientDataJSON, uint256 r, uint256 s)`. */
function webauthnSign(sk, msg, { flags = 0x05, rpId = RP_ID, type = 'webauthn.get', tail = '', counter = 1 } = {}) {
  const authData = concatBytes(sha256(utf8ToBytes(rpId)), Uint8Array.of(flags), be(BigInt(counter), 4));
  const cd = utf8ToBytes(`{"type":"${type}","challenge":"${b64url(msg)}","origin":"${ORIGIN}"${tail}}`);
  const sig = p256Sign(sk, sha256(concatBytes(authData, sha256(cd))));
  return abiEncode(['bytes', 'bytes', 'bytes32', 'bytes32'], [authData, cd, sig.subarray(0, 32), sig.subarray(32, 64)]);
}
const webauthnHighS = (blob) => { const c = Uint8Array.from(blob); c.set(be(P256_N - int(c.subarray(96, 128)), 32), 96); return c; };

const hashToScalar = (seed, r) => ((int(keccak_256(concatBytes(seed, Uint8Array.of(2)))) << 256n)
  + int(keccak_256(concatBytes(seed, Uint8Array.of(3))))) % r;
const SCHNORR_TAG = utf8ToBytes('scaas.ua.schnorr.v1');
const bnG1enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, 32), be(y, 32)); };
const blsG1enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, 64), be(y, 64)); };
/** scaas Schnorr (§1.9): R = kG, e = hashToScalar(keccak256(tag ‖ R ‖ Y ‖ m)), z = k + e·x. */
const schnorrScheme = (G, r, enc) => ({
  keyData: (sk) => enc(G.BASE.multiply(sk)),
  sign(sk, msg) {
    const k = (int(keccak_256(concatBytes(be(sk, 32), msg, utf8ToBytes('scaas.ua.vectors.nonce')))) % (r - 1n)) + 1n;
    const R = enc(G.BASE.multiply(k));
    const e = hashToScalar(keccak_256(concatBytes(SCHNORR_TAG, R, enc(G.BASE.multiply(sk)), msg)), r);
    if (e === 0n) throw new Error('e = 0');
    return concatBytes(R, be((k + e * sk) % r, 32));
  },
});

/** Port of ZetherCurves.sol `G1Bn254.mapToG1`: try-and-increment over keccak256(prefix ‖ uint32 ctr), even y. */
function mapToG1Bn254(prefix) {
  const { Fp } = BN;
  for (let ctr = 0; ; ctr++) {
    const x = int(keccak_256(concatBytes(prefix, be(BigInt(ctr), 4)))) % Fp.ORDER;
    const rhs = Fp.add(Fp.mul(Fp.sqr(x), x), 3n);
    let y = Fp.pow(rhs, (Fp.ORDER + 1n) / 4n);
    if (Fp.eql(Fp.sqr(y), rhs)) {
      if (y & 1n) y = Fp.ORDER - y;
      return bn254.G1.Point.fromAffine({ x, y });
    }
  }
}
const BN_LABEL = { sig: utf8ToBytes('SCAAS-UA-BLS-BN254-SIG-V1'), pop: utf8ToBytes('SCAAS-UA-BLS-BN254-POP-V1') };
const BLS_DST = { sig: 'SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_', pop: 'SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_' };
const bnG2enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c1, 32), be(x.c0, 32), be(y.c1, 32), be(y.c0, 32)); };
const blsG2enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c0, 64), be(x.c1, 64), be(y.c0, 64), be(y.c1, 64)); };

const SCHEMES = {
  'webauthn-p256': { kind: 0x0100, n: P256_N,
    keyData: (sk) => concatBytes(p256.getPublicKey(be(sk, 32), false).subarray(1), sha256(utf8ToBytes(RP_ID))),
    sign: (sk, m) => webauthnSign(sk, m) },
  p256: { kind: 0x0101, n: P256_N, keyData: (sk) => p256.getPublicKey(be(sk, 32), false).subarray(1),
    sign: (sk, m) => p256Sign(sk, sha256(m)) },
  bip340: { kind: 0x0103, n: SECP_N, keyData: (sk) => schnorr.getPublicKey(be(sk, 32)),
    sign: (sk, m) => schnorr.sign(m, be(sk, 32), ZERO32) },
  'schnorr-bn254': { kind: 0x0104, n: BN.Fr.ORDER, ...schnorrScheme(bn254.G1.Point, BN.Fr.ORDER, bnG1enc) },
  'schnorr-bls12381': { kind: 0x0105, n: BLS.Fr.ORDER, ...schnorrScheme(bls12_381.G1.Point, BLS.Fr.ORDER, blsG1enc) },
  'bls12381-minsig': { kind: 0x0106, n: BLS.Fr.ORDER, keyData: (sk) => blsG2enc(bls12_381.G2.Point.BASE.multiply(sk)),
    sign: (sk, m, { pop = false } = {}) => blsG1enc(bls12_381.G1.hashToCurve(m, { DST: pop ? BLS_DST.pop : BLS_DST.sig }).multiply(sk)) },
  'bls-bn254-minsig': { kind: 0x0107, n: BN.Fr.ORDER, keyData: (sk) => bnG2enc(bn254.G2.Point.BASE.multiply(sk)),
    sign: (sk, m, { pop = false } = {}) => bnG1enc(mapToG1Bn254(concatBytes(pop ? BN_LABEL.pop : BN_LABEL.sig, m)).multiply(sk)) },
};
// a sibling kind whose tag a "wrong-kind-tag" negative signs under (same curve where one exists)
const OTHER_KIND = { 0x0100: 0x0101, 0x0101: 0x0100, 0x0103: 0x0110, 0x0104: 0x0140, 0x0105: 0x0141, 0x0106: 0x0105, 0x0107: 0x0104 };

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
const popOf = (kind, uaId, ctx) => {
  const popDigest = ua.popDigest({ ...contexts[ctx], ua: uaId });
  return { popDigest, message: ua.uaMessage(kind, ua.POP_TAG, popDigest) };
};
const derivedRows = Object.entries(SCHEMES).map(([name, s]) => {
  const sk = secretOf(name, s.n);
  const keyData = s.keyData(sk);
  const id = ua.deriveUA(s.kind, keyData);
  const sign = (m, o) => s.sign(sk, m, o);
  const pop = (ctx) => { const p = popOf(s.kind, id, ctx); return { context: ctx, popDigest: hex(p.popDigest), message: hex(p.message), sig: hex(sign(p.message, { pop: true })) }; };
  const metatx = ua.uaMessage(s.kind, tag('metatx'), DIGEST);
  const member = ua.uaMessage(s.kind, tag('member'), DIGEST);
  const metatxSig = sign(metatx);
  const sigs = [
    { purpose: 'metatx', purposeTag: hex(tag('metatx')), digest: hex(DIGEST), message: hex(metatx), sig: hex(metatxSig) },
    { purpose: 'member', purposeTag: hex(tag('member')), digest: hex(DIGEST), message: hex(member), sig: hex(sign(member)) },
  ];
  const popA = popOf(s.kind, id, 'A').message;
  const popB = popOf(s.kind, id, 'B').message;
  const neg = (n, verifyPop, message, sig) => ({ name: n, verifyPop, message: hex(message), sig: hex(sig) });
  const negatives = [
    neg('wrong-purpose', false, member, metatxSig),
    neg('wrong-kind-tag', false, metatx, sign(ua.uaMessage(OTHER_KIND[s.kind], tag('metatx'), DIGEST))),
    neg('other-chain-uid', true, popB, sign(popOf(s.kind, id, 'C').message, { pop: true })), // B and C: both evm:7622
    neg('other-registry', true, popA, sign(popOf(s.kind, id, 'D').message, { pop: true })),
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
    negatives.push(neg('mutated', false, metatx, flip(metatxSig, metatxSig.length - 1)));
  }
  if (s.kind === 0x0101) negatives.push(neg('high-s', false, metatx, highS(metatxSig)));
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
    sigs, negatives };
});

// --- native EOA: UAAuth under the registry domain ---
const ecdsa = (sk, h) => {
  const rec = secp256k1.sign(h, be(sk, 32), { prehash: false, lowS: true, format: 'recovered' });
  return concatBytes(rec.subarray(1), Uint8Array.of(27 + rec[0]));
};
const nativeSk = secretOf('native', SECP_N);
const nativeAddr = keccak_256(secp256k1.getPublicKey(be(nativeSk, 32), false).subarray(1)).subarray(12);
const nativeUa = ua.nativeId(0x0001, nativeAddr);
const domain = (ctx, generation) => ({ generation, ...contexts[ctx] });
const authDigest = (ctx, gen, id, p, d) => ua.uaAuthDigest(domain(ctx, gen), id, tag(p), d);
const nativeSigs = [['A', 1, 'metatx'], ['A', 1, 'member'], ['A', 2, 'metatx'], ['B', 1, 'metatx']].map(([context, generation, purpose]) => {
  const h = authDigest(context, generation, nativeUa, purpose, DIGEST);
  return { context, generation, purpose, digest: hex(DIGEST), uaAuthDigest: hex(h), sig: hex(ecdsa(nativeSk, h)) };
});
const goodA = fromHex(nativeSigs[0].sig);
const nativeHighS = concatBytes(goodA.subarray(0, 32), be(SECP_N - int(goodA.subarray(32, 64)), 32), Uint8Array.of(goodA[64] ^ 1));
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
/** `abi.encode(MemberSig[])`, MemberSig = (uint16 index, bytes keyData, bytes sig). */
function encodeMemberSigs(list) {
  const tuples = list.map(({ index, keyData, sig }) => abiEncode(['uint16', 'bytes', 'bytes'], [index, keyData, sig]));
  const offsets = [];
  let o = 32 * list.length;
  for (const t of tuples) { offsets.push(word(o)); o += t.length; }
  return concatBytes(word(32), word(list.length), ...offsets, ...tuples);
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

// --- write ---
const note = 'Generated by clients/clientkeys/scripts/ua-sig-vectors.mjs (src/ua.js on @noble/curves 2.4.0); never edit by hand. '
  + 'Every positive must verify and every negative must fail (verifyPop: which verifier entry point is asked). '
  + 'The scaas Schnorr transcript and the bn254 mapToG1 have no independent second implementation: clients/scaas-ua agreeing '
  + 'on them is self-consistency only (accounts.md §1.16). msig auth = abi.encode(bytes keyData, bytes sig) (§1.9).';
const out = {
  note, version: 1, context: 'A', contextOther: 'B', contexts: { A: contexts.A, B: contexts.B, C: contexts.C, D: contexts.D },
  digest: hex(DIGEST), derived: derivedRows, bip340Official,
  native: { secret: hex(be(nativeSk, 32)), address: hex(nativeAddr), ua: hex(nativeUa), sigs: nativeSigs, negatives: nativeNegatives },
  msig: { keyData: hex(msigKey), ua: hex(msigUa), threshold: THRESHOLD, context: 'A', generation: 1,
    members: members.map((m) => ({ index: m.index, kind: m.kind, name: m.name, id: hex(m.id), weight: m.weight, secretRef: m.name })),
    sets },
};
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'signatures.json'), `${JSON.stringify(out, null, 2)}\n`);
const negs = derivedRows.reduce((n, r) => n + r.negatives.length, 0);
console.log(`signatures.json: ${derivedRows.length} derived kinds (${negs} negatives), native ${nativeSigs.length}+${nativeNegatives.length}, msig ${sets.length} sets, ${bip340Official.length} BIP-340 official; written to ${OUT}`);
