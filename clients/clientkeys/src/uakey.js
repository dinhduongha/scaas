// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// UNAUDITED. UA keys from the BIP-39 seed and their signers (ua-rs-sign spec §3–§5, signers-clientkeys §9, CLI-SGN-29/30): the
// UA tree m/7622'/0'/<account>'/<kindNo>'/<i>' (BIP-32 secp256k1, SLIP-10 nist256p1 and ed25519, all hardened), the EIP-2333 UA
// paths m/254/0/<account>/<kindNo> (salt SCAAS-UA-BN254-v1) and m/12381/0/<account>/<kindNo> (index 0 only), the PQ HKDF seeds
// (pq.js). A `UAKey` signs only `ua_msg` it builds itself (`signUA(purposeTag, digest)`, `signMember`): no raw digest, no key
// export. The scaas Schnorr nonce is k = hashToScalar(keccak256("scaas.ua.schnorr.nonce.v1" ‖ be32(sk) ‖ Y ‖ ua_msg ‖ aux)), the
// verifier's 512-bit map, aux from the platform RNG. The JS reference that writes smartcontracts/vectors/ua/{keys,sign}.json
// (scripts/ua-wallet-vectors.mjs); clients/ua-rs is held to its rows. Not loaded by the portal bundles.
import { p256 } from '@noble/curves/nist.js';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { HDKey } from '@scure/bip32';
import { keccak_256, concatBytes, utf8ToBytes, hex, fromHex, wipe, abiEncode } from './bytes.js';
import * as ua from './ua.js';
import { slip10 } from './seed.js';
import { eip2333 } from './zether.js';
import { PQ_KINDS, pqKeygen, pqMessage } from './pq.js';
import { hashToScalar, mapToG1Bn254, clientDataOk, webauthnOk, encodeMemberSigs, P256_N } from './ua-verify.js';

const fail = (code, reason) => { throw new ua.UAError(code, reason); };
const HARD = 2 ** 31;
const int = (b) => BigInt(hex(b));
const be = (v, n) => fromHex(v.toString(16).padStart(2 * n, '0'));
const PQ_NAME = Object.fromEntries(Object.entries(PQ_KINDS).map(([name, s]) => [s.kind, name]));

// UA-tree kinds: the derivation of each; the kindNo is the kind number itself (0x0101 → 257').
const TREE = { 0x0101: 'slip10-nist256p1', 0x0102: 'slip10-ed25519', 0x0103: 'bip32', 0x0108: 'bip32', 0x0110: 'bip32' };
const BN = { curve: 'bn254', r: bn254.fields.Fr.ORDER, salt: 'SCAAS-UA-BN254-v1', root: 254 };
const BLS = { curve: 'bls12381', r: bls12_381.fields.Fr.ORDER, salt: 'BLS-SIG-KEYGEN-SALT-', root: 12381 };
const EIP2333 = { 0x0104: BN, 0x0107: BN, 0x0112: BN, 0x0105: BLS, 0x0106: BLS };
const NOT_DERIVED = { 0x0100: 'a webauthn-p256 key is a platform credential', 0x0111: 'FROST shares come from the DKG, not the seed',
  0x0113: 'FROST shares come from the DKG, not the seed', 0x0120: 'an msig holds no key of its own',
  0x0141: 'a Zether key is deriveConfKey\'s (use 7), never a UA-tree key' };

const g1 = (n) => (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, n), be(y, n)); };
const bnG1 = g1(32);
const blsG1 = g1(64);
const bnG2 = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c1, 32), be(x.c0, 32), be(y.c1, 32), be(y.c0, 32)); };
const blsG2 = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c0, 64), be(x.c1, 64), be(y.c0, 64), be(y.c1, 64)); };
const BLS_DST = { sig: 'SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_', pop: 'SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_' };
const BN_LABEL = { sig: utf8ToBytes('SCAAS-UA-BLS-BN254-SIG-V1'), pop: utf8ToBytes('SCAAS-UA-BLS-BN254-POP-V1') };

const PUBLIC = {
  0x0101: (sk) => p256.getPublicKey(sk, false).subarray(1),
  0x0102: (sk) => ed25519.getPublicKey(sk),
  0x0103: (sk) => schnorr.getPublicKey(sk),
  0x0108: (sk) => secp256k1.getPublicKey(sk, false).subarray(1),
  0x0110: (sk) => secp256k1.getPublicKey(sk, true), // a MuSig2 participant: its BIP-327 individual key
  0x0104: (s) => bnG1(bn254.G1.Point.BASE.multiply(s)),
  0x0105: (s) => blsG1(bls12_381.G1.Point.BASE.multiply(s)),
  0x0106: (s) => blsG2(bls12_381.G2.Point.BASE.multiply(s)),
  0x0107: (s) => bnG2(bn254.G2.Point.BASE.multiply(s)),
  0x0112: (s) => bnG1(bn254.G1.Point.BASE.multiply(s)), // a musig2-bn254 participant
};
const PARTICIPANT = new Set([0x0110, 0x0112]);

const range = (v, what) => {
  if (!Number.isInteger(v) || v < 0 || v >= HARD) fail('Argument', `${what} must be an integer in [0, 2^31)`);
};

/** The path and derivation of a UA kind's key; refuses what is not derived from the seed and, for EIP-2333 kinds, `index ≠ 0`
 *  (their path has no index level: two indices would alias one key, spec §4, C-06). */
export function uaKeyPath(kind, account = 0, index = 0) {
  range(account, 'account');
  range(index, 'index');
  const info = ua.kindInfo(kind);
  if (TREE[kind]) return { derivation: TREE[kind], path: `m/7622'/0'/${account}'/${kind}'/${index}'` };
  if (EIP2333[kind]) {
    if (index !== 0) fail('Argument', `${info.name} has no index level: index 0 only (several keys: several accounts)`);
    const c = EIP2333[kind];
    return { derivation: `eip2333-${c.curve}`, path: `m/${c.root}/0/${account}/${kind}`, eip: [c.root, 0, account, kind] };
  }
  if (PQ_NAME[kind]) {
    return { derivation: 'hkdf-pq', path: `hkdf/scaas.ua.pq.v1/${PQ_KINDS[PQ_NAME[kind]].tag}/${account}/${index}` };
  }
  return fail('Argument', NOT_DERIVED[kind] ?? `${info.name} is a native kind: deriveKey`);
}

/** `pop` for the portable purposes the registry verifies with `verifyPop` (`pop` v2, `kem`, `pqz-key`; `_sigOk`), else
 *  `authorization` (spec §9.4). The BLS kinds sign under the DST of the role. */
export const sigRole = (purposeTag) =>
  ([ua.POP_V2_TAG, ua.KEM_TAG, ua.PQZ_KEY_TAG].some((t) => hex(t) === hex(purposeTag)) ? 'pop' : 'authorization');
const PURPOSE_TAGS = new Set([...ua.PURPOSES.map((p) => hex(ua.purposeTag(p))), hex(ua.POP_V2_TAG)]);
const purposeOf = (tag) => {
  if (!(tag instanceof Uint8Array) || tag.length !== 32 || !PURPOSE_TAGS.has(hex(tag))) fail('UAPurposeUnknown', 'not a purpose of PURPOSES');
  return tag;
};

/** scaas Schnorr nonce (spec §3, Q7): hashToScalar(keccak256("scaas.ua.schnorr.nonce.v1" ‖ be32(sk) ‖ Y ‖ ua_msg ‖ aux)). */
export function schnorrNonce(kind, sk, Y, uaMsg, aux) {
  const r = EIP2333[kind].r;
  return hashToScalar(keccak_256(concatBytes(utf8ToBytes('scaas.ua.schnorr.nonce.v1'), be(sk, 32), Y, uaMsg, aux)), r);
}

function scaasSchnorr(kind, s, Y, msg, rand) {
  const { r } = EIP2333[kind];
  const [G, enc] = kind === 0x0104 ? [bn254.G1.Point, bnG1] : [bls12_381.G1.Point, blsG1];
  let k = 0n;
  while (k === 0n) {
    k = schnorrNonce(kind, s, Y, msg, rand.aux());
    if (k === 0n && rand.fixed) fail('Argument', 'k = 0 for this aux');
  }
  const R = enc(G.BASE.multiply(k));
  const e = hashToScalar(keccak_256(concatBytes(utf8ToBytes('scaas.ua.schnorr.v1'), R, Y, msg)), r);
  if (e === 0n) fail('Argument', 'e = 0');
  return concatBytes(R, be((k + e * s) % r, 32));
}

const osRandom = Object.freeze({
  fixed: false,
  aux: () => crypto.getRandomValues(new Uint8Array(32)),
  pq: () => ({}), // noble's defaults: hedged ML-DSA, randomized SLH-DSA, Falcon from the platform RNG
});

/** The scheme's signature over `ua_msg` (spec §3 table). */
function signMsg(kind, secret, keyData, msg, role, rand) {
  if (PARTICIPANT.has(kind)) fail('Argument', 'a MuSig2 participant signs through its session, not signUA');
  switch (kind) {
    case 0x0101: return p256.sign(sha256(msg), secret, { prehash: false, lowS: true, extraEntropy: false, format: 'compact' });
    case 0x0102: return ed25519.sign(msg, secret);
    case 0x0103: return schnorr.sign(msg, secret, rand.aux());
    case 0x0104: case 0x0105: return scaasSchnorr(kind, secret, keyData, msg, rand);
    case 0x0106: return blsG1(bls12_381.G1.hashToCurve(msg, { DST: BLS_DST[role === 'pop' ? 'pop' : 'sig'] }).multiply(secret));
    case 0x0107: return bnG1(mapToG1Bn254(concatBytes(BN_LABEL[role === 'pop' ? 'pop' : 'sig'], msg)).multiply(secret));
    case 0x0108: {
      const rec = secp256k1.sign(msg, secret, { prehash: false, lowS: true, extraEntropy: false, format: 'recovered' });
      return concatBytes(rec.subarray(1), Uint8Array.of(27 + rec[0]));
    }
    default: {
      const name = PQ_NAME[kind];
      return PQ_KINDS[name].alg.sign(PQ_KINDS[name].pq ? pqMessage(name, msg) : msg, secret, rand.pq(name));
    }
  }
}

const SIGNERS = new WeakMap(); // UAKey → its signer (the secret stays in the closure)
const MEMBER = ua.purposeTag('member');

/** The UA key `kind` of `account` / `index` from the 64-byte BIP-39 seed (spec §4). `ua` is null for a MuSig2 participant
 *  (its group is the UA). */
export function deriveUAKey(seed, { kind, account = 0, index = 0 } = {}) {
  const k = Number(kind);
  const { derivation, path, eip } = uaKeyPath(k, account, index);
  if (!(seed instanceof Uint8Array) || seed.length !== 64) fail('Argument', 'seed must be the 64-byte BIP-39 seed');
  let secret;
  let keyData;
  if (PQ_NAME[k]) {
    const kp = pqKeygen(seed, PQ_NAME[k], account, index);
    [secret, keyData] = [kp.secretKey, kp.publicKey];
  } else {
    if (derivation === 'bip32') {
      const node = HDKey.fromMasterSeed(seed).derive(path);
      secret = node.privateKey.slice();
      node.wipePrivateData();
    } else if (derivation.startsWith('slip10-')) {
      const n = slip10(derivation === 'slip10-ed25519' ? 'ed25519' : 'nist256p1', seed, path);
      secret = n.privateKey;
      wipe(n.chainCode);
    } else {
      secret = eip2333(seed, eip, EIP2333[k]);
    }
    keyData = PUBLIC[k](secret);
  }
  const id = PARTICIPANT.has(k) ? null : ua.deriveUA(k, keyData);
  const sign = (msg, role, rand) => signMsg(k, secret, keyData, msg, role, rand);
  const key = Object.freeze({
    kind: k, name: ua.kindInfo(k).name, account, index, derivation, path, keyData, ua: id,
    /** Signs `ua_msg = uaMessage(kind, purposeTag, digest)`; `purposeTag` one of PURPOSES (and `pop` v2). */
    signUA: (purposeTag, digest) => sign(ua.uaMessage(k, purposeOf(purposeTag), digest), sigRole(purposeTag), osRandom),
    /** As an `msig` member: `uaMessage(kind, member, memberDigest(structureUa, structureUaMsg))`, role authorization. */
    signMember: (structureUa, structureUaMsg) =>
      sign(ua.uaMessage(k, MEMBER, ua.memberDigest(structureUa, structureUaMsg)), 'authorization', osRandom),
    wipe: () => { if (secret instanceof Uint8Array) wipe(secret); secret = 0n; },
  });
  SIGNERS.set(key, sign);
  return key;
}

/** Test vectors only: `signUA` with fixed randomness — `aux` (32 B: bip340, scaas Schnorr), `rnd` (32 B: ML-DSA; zero = the
 *  deterministic variant), `optRand` (16 B, or null for PK.seed: SLH-DSA), `falconSeed` (the sampler stream's seed). */
export function signUAVector(key, purposeTag, digest, fixed = {}) {
  const rand = {
    fixed: true,
    aux: () => fixed.aux ?? fail('Argument', 'aux required'),
    pq: (name) => (name.startsWith('fndsa') ? { random: (n) => shake256(fixed.falconSeed, { dkLen: n }) }
      : name.startsWith('slh') ? { extraEntropy: fixed.optRand ?? false } : { extraEntropy: fixed.rnd ?? false }),
  };
  return SIGNERS.get(key)(ua.uaMessage(key.kind, purposeOf(purposeTag), digest), sigRole(purposeTag), rand);
}

/** The authenticator's challenge for a `webauthn-p256` UA: `ua_msg` (spec §5.6). */
export const webauthnChallenge = (purposeTag, digest) => ua.uaMessage(0x0100, purposeOf(purposeTag), digest);

/** The `webauthn-p256` signature `abi.encode(authData, clientDataJSON, r, s)` from an assertion, against the challenge the
 *  caller asked for (spec §5.6, C-07): 0 < r, s < n first, s made low, clientDataJSON kept as signed and accepted only by the
 *  chains' rule (`clientDataOk`: type, challenge = expected, origin, then `}` or `,"crossOrigin":false`), then the whole
 *  encoding verified before it is returned. Any failure: `WebAuthnAssertion`. */
export function webauthnAssertion({ keyData, expectedChallenge, authData, clientDataJSON, r, s }) {
  const no = (why) => fail('WebAuthnAssertion', why);
  if (keyData?.length !== 96 || expectedChallenge?.length !== 32 || r?.length !== 32 || s?.length !== 32) no('lengths');
  const [R, S] = [int(r), int(s)];
  if (!(R > 0n && R < P256_N && S > 0n && S < P256_N)) no('r or s out of range');
  if (!clientDataOk(clientDataJSON, expectedChallenge)) no('clientDataJSON is not the chains\' form for the expected challenge');
  const blob = abiEncode(['bytes', 'bytes', 'bytes32', 'bytes32'], [authData, clientDataJSON, r, be(S > P256_N / 2n ? P256_N - S : S, 32)]);
  if (!webauthnOk(keyData, expectedChallenge, blob)) no('the assertion does not verify');
  return blob;
}

/** `abi.encode(MemberSig[])` of an `msig` UA `ua` (key data `keyData`) over `(purposeTag, digest)`: `slots` are
 *  `[{index, key}]` for a derived member and `[{index, members: [{index, key}]}]` for an `msig` member (`inner(id)` gives its key
 *  data). A set that is not minimal at both levels (or not strictly increasing) is `UAPoP`, the registry's verdict. */
export function msigMemberSigs({ ua: id, keyData, purposeTag, digest, slots, inner }) {
  const list = slots.map((s) => ({ index: s.index, members: s.members?.map((m) => ({ index: m.index })) }));
  if (!ua.msigSigMinimal(keyData, list, inner)) fail('UAPoP', 'the member set is not minimal');
  const all = ua.msigStructure(keyData).members;
  const md = ua.uaMessage(0x0120, purposeOf(purposeTag), digest);
  const own = (key, m, structure, msg) => {
    if (!key || key.kind !== m.kind || hex(key.ua) !== m.id) fail('Argument', 'the key is not the slot\'s member');
    return key.signMember(structure, msg);
  };
  return encodeMemberSigs(slots.map((s) => {
    const m = all[s.index];
    if (m.kind !== 0x0120) return { index: s.index, members: [], sig: own(s.key, m, id, md) };
    const innerMembers = ua.msigStructure(inner(m.id)).members;
    const msg = ua.uaMessage(0x0120, MEMBER, ua.memberDigest(id, md));
    return { index: s.index, sig: new Uint8Array(0),
      members: s.members.map((x) => ({ index: x.index, sig: own(x.key, innerMembers[x.index], fromHex(m.id), msg) })) };
  }));
}
