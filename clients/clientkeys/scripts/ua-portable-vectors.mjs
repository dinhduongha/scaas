// Generates smartcontracts/vectors/ua/portable.json (UA-8, spec P1, P2, P7, P10, P11): the portable registration of every
// kind clientkeys signs — the `register(kind, keyData, attrs, pop, pqzPop)` arguments with every digest between them (a KEM
// holder's register key at version 0, owner 2026-10-31) — the KEM key records (setKemKey versions 1-3) of the KEM holders, and the negatives a registry must refuse with their error. The records
// are typed EIP-712 structs under EIP712Domain(string name,string version) = ("SCaaS UA Portable", "1") (typed-signing
// TS-D1 … TS-D4); each row carries the typedData a wallet signs. No chain id, chain uid or registry anywhere: the same bytes
// register the UA on every chain and every family (P10), so every family's tests read this file (UAKinds / UARegistry
// forge tests, clients/ua-rs, the reproducers, Soroban).
// Keys: the fixed seeds of signatures.json (the derived kinds, the native EOA) and pq_kat.json (account 0, index 0;
// mldsa65 indexes 1 and 2 for the msig members); KEM keys: real ML-KEM-1024 ek ‖ X25519 pk from fixed labels (UA8-D15);
// PQZ keys and R_REG proofs: deterministic filler of the set's lengths, at every parameter set (UA8-D17, ruling C4).
// test/ua8.test.js rebuilds every digest by hand and re-verifies every signature.
//   node scripts/ua-portable-vectors.mjs [outDir]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hex, fromHex as B, keccak_256, utf8ToBytes, abiEncode, concatBytes } from '../src/bytes.js';
import { encodeInnerSigs } from '../src/ua-verify.js';
import * as ua from '../src/ua.js';
import { encodeType } from '../src/evm.js';
import { PQ_KINDS } from '../src/pq.js';
import { personalSignDigest } from '../legacy/typed-signing/ua-portable-raw.js';
import { SCHEMES, schemeSecret, ecdsa, nativeSk, nativeUa, encodeMemberSigs, portableMemberSigs, pqKey, pqSignMsg, PQZ_SETS, pqzKeyOf, pqzPopOf,
  kemPublicKey } from './ua-signers.mjs';

const OUT = fileURLToPath(new URL('../../../smartcontracts/vectors/ua/', import.meta.url));
const NONE = new Uint8Array(0);
const Z = new Uint8Array(32);
const SETS = Object.keys(PQZ_SETS);
const MEMBER = ua.purposeTag('member');
// only for the negative that frames a native member's portable signature as UAAuth (chain-bound) instead of the typed digest
const { contexts } = JSON.parse(readFileSync(join(OUT, 'structures.json'), 'utf8'));
// each UA's own filler PQZ key (one UA per proven PQZ key); mldsa65's at n2048-kmax1024 is kinds.json's `pqzKey`
const PQZ_LABEL = { mldsa65: '', 'msig-pq': ' msig-pq', fndsa512: ' fndsa512', 'msig-pq-native': ' msig-pq-native',
  'msig-nested-native': ' msig-nested-native' };

// --- signers: { name, kind, keyData, ua, sign(msg32, opts) } ---
const signer = (name, kind, keyData, sign) => ({ name, kind, keyData, ua: ua.deriveUA(kind, keyData), sign });
const classical = (name) => {
  const s = SCHEMES[name];
  const sk = schemeSecret(name);
  return signer(name, s.kind, s.keyData(sk), (m, o) => s.sign(sk, m, o));
};
const pq = (name, index = 0) => {
  const kp = pqKey(name, index);
  return signer(index ? `${name}#${index}` : name, PQ_KINDS[name].kind, kp.publicKey, (m) => pqSignMsg(name, kp.secretKey, m));
};
const native = { kind: 0x0001, ua: nativeUa };

/** An msig over `members` ({ kind, ua, sign? } with a weight): sorted by id; `signMembers(md, typedDigest, indices)` =
 *  abi.encode(MemberSig[]), derived members over uaMessage(kind, member, md) (a slot carries no key data, CTR-UA-33), a native
 *  member by ECDSA over the record's typed digest itself (TS-D4: eth_signTypedData_v4, chain-free, no UAAuth domain),
 *  an `msig` member by its own list over `innerDigest(id, md)`, its first `threshold` slots or `signers`, `sig` empty;
 *  `nativeSig(md)` replaces the native member's signature (the negatives); only a minimal slot set (owner 2026-10-31: every
 *  signature this file stores is a portable one). `memberList`: any set, unchecked. `inner`: an `msig` member's key data by id. */
function msig(name, threshold, members, signers) {
  const ms = members.map(([m, weight]) => ({ ...m, weight }))
    .sort((a, b) => (hex(a.ua) < hex(b.ua) ? -1 : 1)).map((m, index) => ({ ...m, index }));
  const keyData = ua.encodeMsig(threshold, ms.map((m) => ({ kind: m.kind, id: m.ua, weight: m.weight })));
  const inner = (id) => ms.find((m) => m.kind === 0x0120 && hex(m.ua) === id)?.keyData;
  const list = (md, typedDigest, indices, nativeSig = () => ecdsa(nativeSk, typedDigest)) => indices.map((i) => (ms[i].kind === 0x0120
    ? { index: i, members: ms[i].memberList(ua.innerDigest(ms[i].ua, md), typedDigest, ms[i].signers, nativeSig), sig: NONE }
    : { index: i, members: [], sig: ua.isNativeKind(ms[i].kind) ? nativeSig(md) : ms[i].sign(ua.uaMessage(ms[i].kind, MEMBER, md)) }));
  return { ...signer(name, 0x0120, keyData, null), threshold, members: ms, inner, signers: signers ?? ms.map((m) => m.index).slice(0, threshold),
    signMembers: (...a) => portableMemberSigs(keyData, list(...a), inner), memberList: list };
}

/** [v0 (the register key), v1, v2, v3]: each version its own key (a new key always goes to a new version). */
const kemKeys = (base) => [0, 1, 2, 3].map((v) => kemPublicKey(`${base} v${v}`));
const ml = pq('mldsa65');
const fn = pq('fndsa512');
const ml1 = pq('mldsa65', 1);
const ml2 = pq('mldsa65', 2);
const classicalMsig = (() => { // signatures.json's msig: native(1), p256(1), bls-bn254-minsig(1), schnorr-bn254(2); threshold 3
  const c = (n) => classical(n);
  return msig('msig-classical', 3, [[native, 1], [c('p256'), 1], [c('bls-bn254-minsig'), 1], [c('schnorr-bn254'), 2]]);
})();
const pqMsig = msig('msig-pq', 2, [[ml1, 1], [ml2, 1]]);
const nativeMsig = msig('msig-pq-native', 2, [[native, 1], [ml1, 1]]);
const KEM = { mldsa65: kemKeys('mldsa65'), fndsa512: kemKeys('fndsa512'), 'msig-pq': kemKeys('msig-pq') };

/** One registration: the `register` arguments, every digest between them, and the signer's pop over the portable PoP. */
function registration(s, { set = '', kem = false, raw = false, slots = 2, signers } = {}) {
  const pqzKey = set ? pqzKeyOf(set, PQZ_LABEL[s.name]) : NONE;
  const pqzPop = set ? pqzPopOf(set) : NONE;
  const kemPk = kem ? KEM[s.name][0] : NONE;
  const m = ua.holderPopMessage(s.kind, { ua: s.ua, keyData: s.keyData, pqzKey, pqzPop, kemPk, inner: s.inner });
  const isMsig = s.kind === 0x0120;
  const popSigners = isMsig && ua.msigPqzEligible(s.keyData, s.inner) ? signers ?? s.members.map((x) => x.index).slice(0, slots) : [];
  const popList = isMsig ? s.memberList(m.memberDigest, m.registrationDigest, popSigners) : null;
  const pop = isMsig ? (popSigners.length ? (raw ? encodeMemberSigs(popList) : portableMemberSigs(s.keyData, popList, s.inner)) : NONE) : s.sign(m.message, { pop: true });
  // typed-signing R1: the explicit registry arguments (register / registerMsig), and for a KEM row its hash-commit form
  const input = { kind: s.kind, keyData: s.keyData, pqzKey, pqzPopHash: m.pqzPopHash, pqzPop, kemPk, pop: popList ?? pop, inner: s.inner };
  // a raw row is not minimal, which `registrationArgs` refuses to build: its arguments are the row's own
  const full = ua.registrationArgs({ ...input, pop: raw ? [] : input.pop, kemCommit: false });
  if (raw) full.args.pop = ua.uaSig({ members: popList }).members;
  const commit = kem ? ua.registrationArgs({ ...input, kemCommit: true }) : null;
  return {
    name: set ? `${s.name}/${set}` : s.name, kind: s.kind, kindName: ua.kindInfo(s.kind).name, set, keyData: hex(s.keyData),
    ua: hex(s.ua), attrs: { pqzKey: hex(pqzKey), pqzPopHash: hex(m.pqzPopHash), kemPk: hex(kemPk) },
    pqzKeyHash: hex(m.pqzKeyHash), kemRecordHash: hex(m.kemRecordHash), portableRecordDigest: hex(m.portableRecordDigest),
    registrationDigest: hex(m.registrationDigest), popMessage: hex(m.message), pop: hex(pop), pqzPop: hex(pqzPop),
    pqzRegMessage: hex(set ? ua.pqzRegMessage({ ua: s.ua, kind: s.kind, pqzKey, kemPk }) : Z),
    ...(isMsig ? { threshold: s.threshold, members: s.members.map((x) => ({ index: x.index, kind: x.kind, id: hex(x.ua), weight: x.weight })),
      memberDigest: hex(m.memberDigest), popSigners } : {}),
    typedData: m.typedData,
    args: { entry: full.entry, ...full.args },
    ...(commit ? { kemCommit: { register: { entry: commit.entry, ...commit.args }, fill: commit.kemFill } } : {}),
  };
}

const registrations = [
  ...['webauthn-p256', 'p256', 'ed25519', 'bip340', 'secp256k1', 'schnorr-bn254', 'schnorr-bls12381', 'bls12381-minsig',
    'bls-bn254-minsig', 'zether-bls12381'].map((n) => registration(classical(n))),
  registration(pq('mldsa44')), registration(ml1), registration(ml2),
  ...SETS.map((set) => registration(ml, { set, kem: true })),
  registration(fn, { kem: true }), registration(pq('slhdsa128s')),
  registration(classicalMsig),
  ...SETS.map((set) => registration(pqMsig, { set, kem: true })),
  registration(nativeMsig),
];

// --- KEM records: setKemKey versions 1-3 of each KEM holder (version 0 is its register key), signed over uaMessage(kind, kem,
// kemRecordDigest) (an msig by members); structHash = hashStruct(UAKemRecord), digest = the typed UAKemRecord digest ---
const kemRecord = (s, name) => (kemPk, i) => {
  const version = i + 1;
  const record = { ua: s.ua, version, kemPk };
  const digest = ua.kemRecordDigest(record);
  const message = ua.kemRecordMessage(s.kind, record);
  const md = s.kind === 0x0120 ? ua.memberDigest(s.ua, message) : null;
  const list = md ? s.memberList(md, digest, [0, 1]) : null;
  const sig = md ? encodeMemberSigs(list) : s.sign(message);
  return { id: `${name}/v${version}`, name, ua: hex(s.ua), kind: s.kind, version, kemPk: hex(kemPk), structHash: hex(ua.kemRecordHash(record)),
    digest: hex(digest), message: hex(message), ...(md ? { memberDigest: hex(md) } : {}),
    sig: hex(sig), typedData: ua.portableTypedData('UAKemRecord', ua.kemRecordStruct(record)),
    args: { ua: hex(s.ua), version, kem: ua.kemKeyOf(kemPk), sig: ua.uaSig(list ? { members: list } : { signature: sig }) } };
};
const kemRecords = [[ml, 'mldsa65'], [fn, 'fndsa512'], [pqMsig, 'msig-pq']].flatMap(([s, name]) => KEM[name].slice(1).map(kemRecord(s, name)));

// --- PQZ key records (setPqzKey, ruling A1-I1): a holder registered without a PQZ key attaches one later, at every set ---
const pqzKeyRecord = (s, set, signerOf = s) => {
  const reg = { ua: hex(s.ua) };
  const pqzKey = pqzKeyOf(set, PQZ_LABEL[s.name]);
  const m = ua.pqzKeyRecordMessage(s.kind, { ua: s.ua, keyData: s.keyData, pqzKey, pqzPop: pqzPopOf(set), inner: s.inner });
  const list = s.kind === 0x0120 ? s.memberList(m.memberDigest, m.recordDigest, [0, 1]) : null;
  const sig = list ? encodeMemberSigs(list) : signerOf.sign(m.message);
  return { name: `${s.name}/${set}`, set, kind: s.kind, ua: reg.ua, pqzKey: hex(pqzKey), pqzKeyHash: hex(m.pqzKeyHash),
    pqzPopHash: hex(m.pqzPopHash), pqzKeyDigest: hex(m.pqzKeyDigest), recordDigest: hex(m.recordDigest), message: hex(m.message),
    ...(m.memberDigest ? { memberDigest: hex(m.memberDigest) } : {}), sig: hex(sig), pqzRegMessage: hex(m.pqzRegMessage),
    typedData: m.typedData,
    args: { ua: reg.ua, pqzKey: hex(pqzKey), pqzPopHash: hex(m.pqzPopHash), sig: ua.uaSig(list ? { members: list } : { signature: sig }) } };
};
const pqzKeyRecords = [fn, nativeMsig].flatMap((s) => SETS.map((set) => pqzKeyRecord(s, set)));
// --- acceptMembership(ua, MemberSig{index, [], sig}) (CTR-UA-37): each member of two structures; digest = typed(UAMembership{ua,
// member}), a native member over it, a derived member over uaMessage(memberKind, member, memberDigest) ---
const membership = (s, m) => {
  const r = ua.membershipMessage({ ua: s.ua, member: m.ua });
  const sig = ua.isNativeKind(m.kind) ? ecdsa(nativeSk, r.digest) : m.sign(ua.uaMessage(m.kind, MEMBER, r.memberDigest));
  return { name: `${s.name}/${m.index}`, msig: s.name, ua: hex(s.ua), index: m.index, member: hex(m.ua), memberKind: m.kind, digest: hex(r.digest),
    message: hex(r.message), memberDigest: hex(r.memberDigest), sig: hex(sig), typedData: r.typedData };
};
const memberships = [classicalMsig, nativeMsig].flatMap((s) => s.members.map((m) => membership(s, m)));
/** A valid signature of `s` over the PQZ key record (ua of s, the fndsa512 row's key and proof hash), for the setPqzKey negatives. */
const recordSigBy = (s, r) => s.sign(ua.uaMessage(s.kind, ua.PQZ_KEY_TAG,
  ua.pqzKeyRecordDigest({ ua: s.ua, pqzKeyHash: r.pqzKeyHash, pqzPopHash: r.pqzPopHash })));

// --- negatives: a row with fields replaced (`set`), refused with `error`; the row's table by entry point (see the note) ---
// Attribute errors (holder, PQZ key length, proof hash, KEM version, KEM key length) are checked before the PoP; a UAPoP row
// passes those checks and moves registrationDigest (or replaces the pop), so the pop no longer verifies; pqzPop "0x" keeps the
// proof check out of it.
const neg = (name, entry, row, set, error, extra = {}) => ({ name, entry, mutation: { row, ...extra, set }, error });
/** `pk` with its scheme byte replaced; the registry's error for a KEM key (UAKemScheme / UAKemKeyLength, as ua.kemRecordDigest). */
const withScheme = (scheme, pk) => concatBytes(Uint8Array.of(scheme), pk.subarray(1));
const kemErr = (pk) => { try { ua.kemRecordDigest({ ua: Z, version: 1, kemPk: pk }); } catch (e) { return e.code; } throw new Error('a valid KEM key'); };
const ml1Sig = (md) => ml1.sign(ua.uaMessage(ml1.kind, MEMBER, md));
const DIGEST = keccak_256(utf8ToBytes('scaas.ua.vectors.sig.digest')); // signatures.json's operation digest
const metatxMd = ua.memberDigest(nativeMsig.ua, ua.uaMessage(0x0120, ua.purposeTag('metatx'), DIGEST));
const nm = registrations.find((r) => r.name === 'msig-pq-native');
const uaAuthMd = (md) => ua.uaAuthDigest({ generation: 1, ...contexts.A }, nativeUa, MEMBER, md);
const negatives = [
  ...SETS.flatMap((set) => {
    const row = `mldsa65/${set}`;
    const fr = pqzKeyRecords.find((r) => r.name === `fndsa512/${set}`);
    return [
      neg(`swapped-pqz-key/${set}`, 'register', row, { 'attrs.pqzKey': hex(pqzKeyOf(set, ' other')), pqzPop: '0x' }, 'UAPoP'),
      neg(`stripped-pqz-key/${set}`, 'register', row, { 'attrs.pqzKey': '0x', 'attrs.pqzPopHash': hex(Z), pqzPop: '0x' }, 'UAPoP'),
      neg(`wrong-pqz-pop-hash/${set}`, 'register', row,
        { 'attrs.pqzPopHash': hex(keccak_256(pqzPopOf(set, ' other'))), pqzPop: '0x' }, 'UAPoP'),
      neg(`pqz-key-without-proof-hash/${set}`, 'register', row, { 'attrs.pqzPopHash': hex(Z), pqzPop: '0x' }, 'UAPqzPopHash'),
      neg(`register-pqz-pop-other-bytes/${set}`, 'register', row, { pqzPop: hex(pqzPopOf(set, ' other')) }, 'UAPqzPopHash'),
      neg(`pqz-key-wrong-length/${set}`, 'register', row, { 'attrs.pqzKey': hex(new Uint8Array(32).fill(0x42)), pqzPop: '0x' }, 'UAKeyData'),
      neg(`non-holder-with-pqz-key/${set}`, 'register', 'slhdsa128s',
        { 'attrs.pqzKey': hex(pqzKeyOf(set)), 'attrs.pqzPopHash': hex(keccak_256(pqzPopOf(set))) }, 'UAPqzHolder'),
      neg(`msig-swapped-kem-pk/${set}`, 'register', `msig-pq/${set}`, { 'attrs.kemPk': hex(KEM['msig-pq'][1]), pqzPop: '0x' }, 'UAPoP'),
      neg(`store-pqz-pop-other-bytes/${set}`, 'storePqzPop', row, { pqzPop: hex(pqzPopOf(set, ' other')) }, 'UAPqzPopHash',
        { registerWith: { pqzPop: '0x' } }),
      neg(`pqz-key-record-already-set/${set}`, 'setPqzKey', fr.name, { ua: hex(ml.ua), sig: hex(recordSigBy(ml, fr)) }, 'UAPqzKeySet'),
      neg(`pqz-key-record-wrong-holder/${set}`, 'setPqzKey', fr.name,
        { ua: hex(pq('slhdsa128s').ua), sig: hex(recordSigBy(pq('slhdsa128s'), fr)) }, 'UAPqzHolder'),
      neg(`pqz-key-record-signed-by-other-ua/${set}`, 'setPqzKey', fr.name, { sig: hex(ml1.sign(B(fr.message))) }, 'UAUnauthorized'),
    ];
  }),
  neg('stripped-kem-pk', 'register', 'fndsa512', { 'attrs.kemPk': '0x' }, 'UAPoP'),
  neg('swapped-kem-pk', 'register', 'fndsa512', { 'attrs.kemPk': hex(KEM.fndsa512[1]) }, 'UAPoP'),
  neg('kem-pk-1599', 'register', 'fndsa512', { 'attrs.kemPk': hex(KEM.fndsa512[0].subarray(0, 1599)) }, 'UAKemKeyLength'),
  // the KEM scheme byte (CTR-UA-32): the pre-scheme 1,600-byte key (no scheme byte: its first byte read as one), the
  // reserved scheme 2 (ML-KEM-1024 + HQC + X25519) and an unknown one are UAKemScheme, a scheme-1 key of 1,600 bytes UAKemKeyLength
  neg('kem-pk-without-scheme', 'register', 'fndsa512', { 'attrs.kemPk': hex(KEM.fndsa512[0].subarray(1)) },
    kemErr(KEM.fndsa512[0].subarray(1))),
  neg('kem-scheme-reserved', 'register', 'fndsa512', { 'attrs.kemPk': hex(withScheme(2, KEM.fndsa512[0])) }, 'UAKemScheme'),
  neg('kem-scheme-unknown', 'register', 'fndsa512', { 'attrs.kemPk': hex(withScheme(0, KEM.fndsa512[0])) }, 'UAKemScheme'),
  neg('kem-pk-1600', 'register', 'fndsa512', { 'attrs.kemPk': hex(KEM.fndsa512[0].subarray(0, 1600)) }, 'UAKemKeyLength'),
  neg('proof-hash-without-pqz-key', 'register', 'fndsa512', { 'attrs.pqzPopHash': hex(keccak_256(pqzPopOf(SETS[0]))) }, 'UAPqzPopHash'),
  // ruling A6-m: an empty proof is no proof; its hash is refused wherever a proof hash is signed
  neg('pqz-pop-hash-of-empty', 'register', `mldsa65/${SETS[0]}`, { 'attrs.pqzPopHash': hex(keccak_256(new Uint8Array(0))), pqzPop: '0x' },
    'UAPqzPopHash'),
  neg('pqz-key-record-hash-of-empty', 'setPqzKey', `fndsa512/${SETS[0]}`, { pqzPopHash: hex(keccak_256(new Uint8Array(0))) }, 'UAPqzPopHash'),
  neg('non-holder-with-kem', 'register', 'secp256k1', { 'attrs.kemPk': hex(KEM.fndsa512[0]) }, 'UAKemHolder'),
  neg('classical-msig-with-kem', 'register', 'msig-classical', { 'attrs.kemPk': hex(KEM.fndsa512[0]) },
    'UAKemHolder'),
  neg('kem-sig-of-other-version', 'setKemKey', 'mldsa65/v3', { sig: kemRecords.find((k) => k.id === 'mldsa65/v2').sig }, 'UAUnauthorized'),
  neg('kem-record-of-other-ua', 'setKemKey', 'fndsa512/v2', { ua: hex(ml.ua) }, 'UAUnauthorized'),
  // TS-D4 (C7, ruling A1-I2): a native member's portable signature framed as UAAuth is refused; personal_sign outside the
  // portable purposes is refused (UAAuth there, CTR-MTX-14)
  neg('native-uaauth-in-portable-pop', 'register', 'msig-pq-native',
    { pop: hex(nativeMsig.signMembers(B(nm.memberDigest), B(nm.registrationDigest), [0, 1], () => ecdsa(nativeSk, uaAuthMd(B(nm.memberDigest))))) },
    'UAPoP'),
  neg('native-personal-sign-under-metatx', 'requireAuthorized', 'msig-pq-native', { purposeTag: hex(ua.purposeTag('metatx')),
    digest: hex(DIGEST), auth: hex(abiEncode(['bytes', 'bytes'], [nativeMsig.keyData,
      nativeMsig.signMembers(metatxMd, Z, [0, 1], () => ecdsa(nativeSk, personalSignDigest(metatxMd)))])) },
  'UAUnauthorized'),
  // msig minimal form (owner 2026-10-31): not a mutation of a row; the full register arguments are in `registration`
  { name: 'msig-pop-not-minimal', entry: 'register', rule: 'msig-minimal',
    why: 'A stored msig signature (pop v2, KEM record, PQZ key record) is refused unless every slot is necessary: with T = '
      + 'the slots\' total weight and N the threshold, T >= N and T - weight(i) < N for every slot (owner 2026-10-31). This '
      + '2-of-(1, 2) msig over the registered mldsa65#1 and mldsa65#2 (the lower id weight 1) is signed by both slots: '
      + 'every member signature verifies and the old rule accepts it (1, then 3 >= 2), but the weight-2 slot alone reaches '
      + 'the threshold. Digest-only readers skip rule msig-minimal. lightestInMiddle: the same rule when the lightest slot is '
      + 'not the first: 5-of-(2, 1, 3) by index over mldsa65, #1 and #2, all three signed: T - weight(1) = 5, so the weight-1 '
      + 'slot is not necessary, while T - weight(0) = 4 would pass a check of the first slot alone.',
    registration: registration(msig('msig-pq-not-minimal', 2, [ml1, ml2].sort((a, b) => (hex(a.ua) < hex(b.ua) ? -1 : 1))
      .map((m, i) => [m, i + 1])), { raw: true }),
    lightestInMiddle: registration(msig('msig-pq-not-minimal-light', 5, [ml, ml1, ml2].sort((a, b) => (hex(a.ua) < hex(b.ua) ? -1 : 1))
      .map((m, i) => [m, [2, 1, 3][i]])), { raw: true, slots: 3 }),
    error: 'UAPoP' },
  // typed-signing (TS-D3 / TS-D4): the pre-round native form (EIP-191 personal_sign of memberDigest), a pop over the same UA
  // and attributes under another kind (only the record's kind differs), and the row's own initial KEM record's typed digest
  // signed under pop v2 (only the struct type differs)
  neg('native-member-personal-sign', 'register', 'msig-pq-native',
    { pop: hex(nativeMsig.signMembers(B(nm.memberDigest), B(nm.registrationDigest), [0, 1], () => ecdsa(nativeSk, personalSignDigest(B(nm.memberDigest))))) },
    'UAPoP'),
  neg('record-kind-mismatch', 'register', 'p256', { pop: hex(classical('p256').sign(ua.uaMessage(0x0101, ua.POP_V2_TAG,
    ua.registrationDigest({ ua: classical('p256').ua, kind: 0x0100 })))) }, 'UAPoP', { otherKind: 0x0100 }),
  neg('kem-record-as-registration', 'register', 'fndsa512', { pop: hex(fn.sign(ua.uaMessage(fn.kind, ua.POP_V2_TAG,
    B(kemRecords.find((k) => k.id === 'fndsa512/v1').digest)))) }, 'UAPoP'),
];

// --- nested.json: nested `msig` (spec 2026-11-02-msig-nested): its records in the order they register, in their own file because
// a family that has not taken the rule reads portable.json and refuses an `msig` member. Real verifiers: fndsa512, not the ML-DSA mock ---
const f0 = pq('fndsa512');
const f1 = pq('fndsa512', 1);
const f2 = pq('fndsa512', 2);
const p256 = classical('p256');
const ed = classical('ed25519');
const pqInner = msig('msig-inner-pq', 2, [[f0, 1], [f1, 1]]);
const nativeInner = msig('msig-inner-native', 2, [[native, 1], [f0, 1]]);
const nativeInner2 = msig('msig-inner-native-2', 2, [[native, 1], [f1, 1]]);
const classicalInner = msig('msig-inner-classical', 1, [[p256, 1], [ed, 1]]);
const nestedPq = msig('msig-nested-pq', 2, [[pqInner, 1], [f2, 1]]);
const nestedNative = msig('msig-nested-native', 2, [[nativeInner, 1], [f2, 1]]);
const nestedTwice = msig('msig-nested-twice', 2, [[nativeInner, 1], [nativeInner2, 1]]); // N5: one native signature serves both slots
const nestedClassical = msig('msig-nested-classical', 2, [[classicalInner, 2], [f2, 1]]); // a classical-dominant inner: an empty pop
// the minimal rule: T - weight(i) < N. `heavyInner` signed by both slots: its weight-2 slot alone reaches 2
const byId = (l) => [...l].sort((a, b) => (hex(a.ua) < hex(b.ua) ? -1 : 1));
const heavyInner = msig('msig-inner-heavy', 2, byId([f0, f1]).map((m, i) => [m, i + 1]), [1]);
const heavyInnerOuter = msig('msig-nested-heavy-inner', 2, [[heavyInner, 1], [f2, 1]]);
const heavyOuter = msig('msig-nested-heavy-outer', 2, [[pqInner, 2], [f2, 1]]);
const innerIndex = (s) => s.members.findIndex((m) => m.kind === 0x0120);
KEM['msig-nested-pq'] = kemKeys('msig-nested-pq');
const nestedRows = [
  registration(p256), registration(ed), registration(f0), registration(f1), registration(f2),
  registration(pqInner), registration(nativeInner), registration(nativeInner2), registration(classicalInner), registration(heavyInner, { signers: [1] }),
  registration(nestedPq, { kem: true }), registration(nestedNative), registration(nestedTwice), registration(nestedClassical),
  registration(heavyInnerOuter), registration(heavyOuter, { signers: [innerIndex(heavyOuter)] }),
];
// a `pop` with a slot of an inner that accepted by `acceptMembership`: registers after that acceptance, on a copy after its replay
const afterMsig = msig('msig-nested-after-acceptance', 2, [[classicalInner, 1], [f2, 1]]);
const afterAcceptance = [registration(afterMsig)];
const nestedKem = KEM['msig-nested-pq'].slice(1, 2).map(kemRecord(nestedPq, 'msig-nested-pq'));
const nestedPqzKey = SETS.map((set) => pqzKeyRecord(nestedNative, set));
/** An inner slot's acceptance: a threshold of its own accepted slots signs for it (spec §4); a leaf's as `membership`. */
const nestedMembership = (s, m) => {
  if (m.kind !== 0x0120) {
    const row = membership(s, m);
    return { ...row, members: [], stored: row.sig };
  }
  const r = ua.membershipMessage({ ua: s.ua, member: m.ua });
  const list = m.memberList(ua.innerDigest(m.ua, r.memberDigest), r.digest, m.signers);
  return { name: `${s.name}/${m.index}`, msig: s.name, ua: hex(s.ua), index: m.index, member: hex(m.ua), memberKind: m.kind, digest: hex(r.digest),
    message: hex(r.message), memberDigest: hex(r.memberDigest), sig: '0x', members: list.map((x) => ({ index: x.index, sig: hex(x.sig) })),
    stored: hex(encodeInnerSigs(list)), typedData: r.typedData };
};
// in the order they run: `msig-inner-classical` has an empty pop, so its signer accepts before it can accept its slot in the outer
const nestedMemberships = [
  ...classicalInner.members.map((m) => nestedMembership(classicalInner, m)),
  ...nestedClassical.members.map((m) => nestedMembership(nestedClassical, m)),
];
/** What `ua-rs` / clientkeys read to rebuild `md_I`: one row per `msig` slot of `s`, over the row's `memberDigest`. */
const innerDigests = (r, s) => s.members.filter((m) => m.kind === 0x0120).map((m) => ({ index: m.index, inner: hex(m.ua),
  memberDigest: hex(ua.innerDigest(m.ua, B(r.memberDigest))) }));
// requireAuthorized: chain-bound, a native leaf over UAAuth in its registry's domain (context A, gen 1), `metatx`, not portable
const authMd = ua.memberDigest(nestedNative.ua, ua.uaMessage(0x0120, ua.purposeTag('metatx'), DIGEST));
const leafAuth = (md) => ecdsa(nativeSk, uaAuthMd(md));
const authRow = (name, valid, list) => ({ name, valid, ua: hex(nestedNative.ua), purposeTag: hex(ua.purposeTag('metatx')), digest: hex(DIGEST),
  memberDigest: hex(authMd), sig: hex(encodeMemberSigs(list)), uaSig: ua.uaSig({ members: list }) });
const authGood = () => nestedNative.memberList(authMd, Z, [0, 1], leafAuth);
const withSlot = (list, i, f) => list.map((x, j) => (j === i ? f(x) : x));
const innerSlot = innerIndex(nestedNative);
const leafSlot = 1 - innerSlot;
const authorizations = [
  authRow('two-levels', true, authGood()),
  authRow('one-level-short', false, nestedNative.memberList(authMd, Z, [0, 1], leafAuth).map((x) => (x.members.length
    ? { ...x, members: nativeInner.memberList(authMd, Z, nativeInner.signers, leafAuth) } : x))),
  authRow('inner-below-threshold', false, withSlot(authGood(), innerSlot, (x) => ({ ...x, members: x.members.slice(0, 1) }))),
  authRow('sig-on-msig-slot', false, withSlot(authGood(), innerSlot, (x) => ({ ...x, sig: new Uint8Array(1).fill(1) }))),
  authRow('list-on-signing-slot', false, withSlot(authGood(), leafSlot, (x) => ({ ...x, members: [{ index: 0, sig: new Uint8Array(65) }] }))),
];
// --- the negatives: one change from a pop that registers; `error` the registry's, row by row a client's too ---
const raw = (s, indices, nativeSig) => {
  const r = nestedRows.find((x) => x.name === s.name);
  return { r, md: B(r.memberDigest), typed: B(r.registrationDigest), list: s.memberList(B(r.memberDigest), B(r.registrationDigest), indices, nativeSig) };
};
const nestedNeg = (name, s, list, error = 'UAPoP') => ({ name, row: s.name, error, pop: hex(encodeMemberSigs(list)), popTyped: ua.uaSig({ members: list }).members });
const good = (s) => raw(s, [0, 1]).list;
const nestedNegatives = [
  nestedNeg('list-on-signing-slot', nestedPq, withSlot(good(nestedPq), 1 - innerIndex(nestedPq), (x) => ({ ...x, members: [{ index: 0, sig: new Uint8Array(1).fill(1) }] }))),
  nestedNeg('sig-on-msig-slot', nestedPq, withSlot(good(nestedPq), innerIndex(nestedPq), (x) => ({ ...x, sig: new Uint8Array(1).fill(1) }))),
  nestedNeg('no-list-on-msig-slot', nestedPq, withSlot(good(nestedPq), innerIndex(nestedPq), (x) => ({ ...x, members: [], sig: new Uint8Array(666).fill(1) }))),
  nestedNeg('inner-below-threshold', nestedPq, withSlot(good(nestedPq), innerIndex(nestedPq), (x) => ({ ...x, members: x.members.slice(0, 1) }))),
  nestedNeg('inner-index-past-the-members', nestedPq, withSlot(good(nestedPq), innerIndex(nestedPq), (x) => ({ ...x, members: [x.members[0], { ...x.members[1], index: 2 }] }))),
  nestedNeg('inner-unsorted', nestedPq, withSlot(good(nestedPq), innerIndex(nestedPq), (x) => ({ ...x, members: [...x.members].reverse() }))),
  nestedNeg('inner-leaf-bad-signature', nestedPq, withSlot(good(nestedPq), innerIndex(nestedPq), (x) => ({ ...x, members: x.members.map((y, j) => (j === 0
    ? { ...y, sig: new Uint8Array(y.sig.length).fill(1) } : y)) }))),
  // one level short: the leaves signed the outer's member digest, not md_I
  nestedNeg('one-level-short', nestedPq, withSlot(good(nestedPq), innerIndex(nestedPq), (x) => {
    const { md, typed } = raw(nestedPq, []);
    return { ...x, members: pqInner.memberList(md, typed, pqInner.signers) };
  })),
  // the same inner, the list of another outer: md_I holds md_U
  nestedNeg('list-of-another-outer', nestedTwice, withSlot(good(nestedTwice), innerIndex(nestedTwice), (x) => {
    const { md, typed } = raw(nestedNative, []);
    return { ...x, members: nativeInner.memberList(ua.innerDigest(nativeInner.ua, md), typed, nativeInner.signers) };
  })),
  // TS-D4 at the inner level: a native leaf's portable signature is the typed digest, never UAAuth
  nestedNeg('native-leaf-uaauth', nestedNative, raw(nestedNative, [0, 1], leafAuth).list),
  // N6: a redundant signature at either level
  nestedNeg('inner-not-minimal', heavyInnerOuter, withSlot(good(heavyInnerOuter), innerIndex(heavyInnerOuter), (x) => {
    const { md, typed } = raw(heavyInnerOuter, []);
    return { ...x, members: heavyInner.memberList(ua.innerDigest(heavyInner.ua, md), typed, [0, 1]) };
  })),
  nestedNeg('outer-not-minimal', heavyOuter, good(heavyOuter)),
  // CTR-UA-37 one level down: afterAcceptance's own pop before the memberships rows run. A pop accepts the slots of its own record only, so the
  // slot of msig-inner-classical it uses is not accepted yet
  nestedNeg('inner-slot-not-accepted', afterMsig, afterMsig.memberList(B(afterAcceptance[0].memberDigest), B(afterAcceptance[0].registrationDigest),
    afterMsig.signers)),
];
/** A structure the registry refuses by its records: `registerMsig` reverts `UAMemberUnknown(member)`, no signature reached. */
const refused = (name, s, member) => ({ name, keyData: hex(s.keyData), ua: hex(s.ua), structure: ua.msigStructure(s.keyData), member: hex(member.ua), error: 'UAMemberUnknown' });
const unregistered = msig('msig-inner-unregistered', 1, [[f2, 1]]);
const structures = [
  refused('third-level', msig('msig-third-level', 1, [[nestedPq, 1]]), pqInner), // listing U names U's own `msig` member (N1)
  refused('inner-not-registered', msig('msig-outer-of-unregistered', 1, [[unregistered, 1]]), unregistered),
];
const inners = (...l) => Object.fromEntries(l.map((m) => [hex(m.ua), hex(m.keyData)]));
const eligibility = [
  ['a PQ-eligible inner counts as PQ', nestedPq, inners(pqInner), true],
  ['an inner with a native member, classical below its threshold, counts as PQ', nestedNative, inners(nativeInner), true],
  ['a classical-dominant inner counts its whole outer weight as classical', nestedClassical, inners(classicalInner), false],
].map(([reason, s, inner, eligible]) => ({ reason, keyData: hex(s.keyData), inner, eligible }));
const nestedNote = 'Generated by clients/clientkeys/scripts/ua-portable-vectors.mjs; never edit by hand. Nested msig (spec 2026-11-02-msig-nested, '
  + 'CTR-UA-09): every row the same shape as portable.json\'s. registrations: in the order they register, each record\'s member first. An msig slot is '
  + 'MemberSig{index, members: InnerSig{index, sig}[], sig: 0x}, a signing slot MemberSig{index, [], sig}. md_I = keccak256(I | ua_msg(0x0120, member, md_U)): '
  + 'innerDigests[j].memberDigest, for the row\'s memberDigest md_U; a derived leaf of I signs under member over md_I, a native leaf the row\'s typed digest '
  + 'in the portable purposes and UAAuth(id, member, md_I) elsewhere (context A of structures.json, gen 1). msig-nested-twice: one native signature serves both '
  + 'slots of that record (N5). kemRecords, pqzKeyRecords: as portable.json\'s. memberships: acceptMembership(ua, MemberSig{index, members, sig}) in the order '
  + 'they run, a member of msig kind by its accepted slots over innerDigest(member, memberDigest) (sig 0x); stored: what membershipSigOf(ua, index) then '
  + 'returns, sig, or abi.encode(InnerSig[]) for an msig member. afterAcceptance: a registration whose pop uses a slot accepted by a memberships row: on another '
  + 'registry the same bytes register once that row is replayed from stored, with no new signature (CTR-UA-37). authorizations: requireAuthorized(ua, purposeTag, '
  + 'digest, UASig{0x, 0x, members}), valid or refused UAUnauthorized, on the state after registrations (accepted: each msig row\'s popSigners). negatives: '
  + 'registerMsig of `row` (a registrations or afterAcceptance row) with `pop`, refused with `error`, every member signature otherwise as a registering one, '
  + 'on the state after the registrations rows up to msig-nested-pq; inner-slot-not-accepted: afterAcceptance\'s own pop, before the memberships rows accept '
  + 'the inner slot it uses (a pop accepts the slots of its own record only). structures: registerMsig refused UAMemberUnknown(member) by the records (a third level, an unregistered inner). eligibility: '
  + 'msig_pqz_eligible(keyData) with inner = id -> key data. All of it UNAUDITED.';
const nestedBuild = () => ({ note: nestedNote, version: 1, registrations: nestedRows.map((r) => {
  const s = [pqInner, nativeInner, nativeInner2, classicalInner, heavyInner, nestedPq, nestedNative, nestedTwice, nestedClassical, heavyInnerOuter, heavyOuter]
    .find((x) => x.name === r.name);
  return s && r.memberDigest ? { ...r, innerDigests: innerDigests(r, s) } : r;
}), kemRecords: nestedKem, pqzKeyRecords: nestedPqzKey, memberships: nestedMemberships, afterAcceptance, authorizations, negatives: nestedNegatives, structures, eligibility });

const tag = (t) => ({ tag: t, hash: hex(keccak_256(new TextEncoder().encode(t))) });
const note = [
  'Generated by clients/clientkeys/scripts/ua-portable-vectors.mjs (src/ua.js, @noble/curves 2.4.0, @noble/post-quantum 0.7.1); '
  + 'never edit by hand. UA-8 portable registrations as typed EIP-712 records (typed-signing TS-D1 ... TS-D4): domain '
  + 'EIP712Domain(string name,string version) = ("SCaaS UA Portable", "1"), no chain id, verifying contract or salt (typed.*); '
  + 'typed(s) = keccak256(0x1901 | typed.domainSeparator | hashStruct(s)); no chain and no registry anywhere.',
  'KEM keys (CTR-UA-32): kemPk = scheme byte | key; kemScheme 1 = ML-KEM-1024 + X25519, 0x01 | ek (1,568 B) | X25519 pk (32 B) = '
  + 'kemPkLength bytes; scheme 2 (ML-KEM-1024 + HQC + X25519) is reserved and refused (UAKemScheme), as is every other scheme byte; '
  + 'an empty key or a key of another length than its scheme\'s is UAKemKeyLength.',
  'Digests: pqzKeyHash = keccak256(PQZ_KEY_GROUP | pqzKey) (keyHash of scheme 0x0142, not a plain keccak; the key is of a set\'s '
  + 'length, else UAKeyData); pqzPopHash = keccak256(pqzPop); kemRecordHash = hashStruct(UAKemRecord{ua, version, scheme = '
  + 'kemPk[0], kemPkHash = keccak256(kemPk)}) of the register key, always version 0 (owner 2026-10-31: register takes no KEM '
  + 'version), the zero record UAKemRecord{ua, 0, 0, 0} '
  + 'when there is none (a present record has scheme != 0: version 0 with scheme 0 is UAKemScheme); portableRecordDigest = typed(UAPortableRecord{ua, kind, pqzKeyHash, kem}) (kind = the '
  + 'registering kind, uint16); registrationDigest = typed(UARegistration{record, pqzPopHash = attrs.pqzPopHash}); popMessage = '
  + 'ua_msg(kind, PURPOSE_POP_V2, registrationDigest); pqzRegMessage = ua_msg(0x0142, PURPOSE_POP_V2, portableRecordDigest) (the '
  + 'R_REG message); kemRecords: structHash = hashStruct(UAKemRecord), digest = typed(UAKemRecord), signed as ua_msg(kind, '
  + 'PURPOSE_KEM, digest); PQZ key record (setPqzKey): pqzKeyDigest = typed(UAPqzKey{ua, pqzKeyHash}) (its R_REG message: '
  + 'ua_msg(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest)), recordDigest = typed(UAPqzKeyRecord{UAPqzKey{ua, pqzKeyHash}, pqzPopHash}), '
  + 'signed as ua_msg(kind, PURPOSE_PQZ_KEY, recordDigest). typedData = the eth_signTypedData_v4 JSON of the signed record '
  + '(hashTypedData(typedData) = registrationDigest / digest / recordDigest). Absent attributes are empty / 0.',
  'PQZ key: set once per chain, by register or later by setPqzKey(ua, pqzKey, pqzPopHash, sig), which is accepted only while '
  + 'the registration has no PQZ key (UAPqzKeySet otherwise; holder rules as register). Client rule: one PQZ key per UA, '
  + 'ever (a UA that signs records for two PQZ keys can end with different keys on different chains).',
  'msig: a derived member signs memberDigest = keccak256(ua | message) of the portable message (popMessage, the KEM record '
  + 'message, the PQZ key record message) under member; a slot carries no key data. A code-less native EOA member '
  + '(its own key only) signs the record\'s typed digest itself, typedDigest = registrationDigest / digest / recordDigest (what '
  + 'eth_signTypedData_v4 of typedData returns), 65-byte r | s | v, low-s, v in {27, 28}; EIP-191 personal_sign '
  + 'is refused (native-member-personal-sign). Only for PURPOSE_POP_V2, PURPOSE_KEM and PURPOSE_PQZ_KEY; every other purpose '
  + 'stays UAAuth (chain-bound EIP-712: CTR-MTX-14). A contract member answers ERC-1271 isValidSignature(typedDigest, sig) on '
  + 'each chain: portable only where that wallet exists with the same behaviour.',
  'Acceptance (CTR-UA-37): memberships[i] = acceptMembership(ua, MemberSig{index, [], sig}) of the member at slot index of the msig '
  + 'row msig: digest = typed(UAMembership{ua, member}), message = ua_msg(0x0120, PURPOSE_MEMBERSHIP, digest), memberDigest = '
  + 'keccak256(ua | message); a native member signs digest itself (ECDSA, or ERC-1271 over it), a derived member signs '
  + 'ua_msg(memberKind, member, memberDigest) under member. The same signature on every registry; no nonce.',
  'Typed arguments (typed-signing R1, TS-D10 ... TS-D12; the byte fields above stay): registrations[i].args = the named '
  + 'arguments of register(kind, keyData, attrs, pop, pqzPop) (a single key) or registerMsig(structure, attrs, pop, pqzPop) (an msig: '
  + 'structure = {threshold, members: [{kind, id, weight}]} assembled by the registry to keyData, pop = [{index, members, sig}] stored '
  + 'as abi.encode(MemberSig[])), with attrs = {pqzKey, pqzPopHash, kem: KemKey{scheme, mlkemEk, x25519} (kemPk = scheme | mlkemEk | '
  + 'x25519, the empty key = none), kemPkHash}; registrations[i].kemCommit (KEM rows) = the same registration with the KEM record\'s '
  + 'hash only (kem = {scheme, 0x, 0}, kemPkHash = keccak256(kemPk); the same pop: the record words are equal) and its fill = '
  + 'setKemKey(ua, 0, kem, sig = UASig{0x, 0x, []}), open to anyone (owner 2026-10-31: only when the full key does not fit one '
  + 'transaction; every version write-once); kemRecords[i].args = setKemKey(ua, version, kem, sig) and pqzKeyRecords[i].args = '
  + 'setPqzKey(ua, pqzKey, pqzPopHash, sig) with sig = UASig{keyData, signature, members} (a single key: signature = sig; an msig: '
  + 'members, never keyData). attrs.kemVersion is gone (R1). typed-signing R1b (TS-D13): the webauthn-p256 row\'s args = '
  + 'registerWebAuthn(key = {x, y, rpIdHash}, attrs, pop, pqzPop), the registry assembling keyData = x | y | rpIdHash (register(0x0100, '
  + '...) is refused); MuSig2 / FROST keys register by registerMuSig2 / registerFrost(kind, key, attrs, pop, pqzPop) (clientkeys '
  + 'typedKey; no row here).',
  'Rows: registrations[i] = register(kind, keyData, attrs, pop, pqzPop); kemRecords[i] = setKemKey(ua, version, kemPk, sig) '
  + '(id = name/vN, versions 1-3, each its own key; version 0 is the registration\'s key, stored by register, never by setKemKey: '
  + 'UAKemVersion; every version is write-once); pqzKeyRecords[i] = setPqzKey(ua, pqzKey, pqzPopHash, sig) '
  + 'for a UA registered without a PQZ key (its proof bytes for storePqzPop: the set\'s filler, registrations '
  + '"mldsa65/<set>".pqzPop). pqzPop rows are filler of a real R_REG proof\'s length per set, not proofs.',
  'negatives: mutation.row names a row of registrations (entry register, storePqzPop, requireAuthorized), kemRecords by id '
  + '(setKemKey) or pqzKeyRecords (setPqzKey); mutation.set replaces fields (attrs.<field>, pqzPop, pop, ua, sig, pqzPopHash, '
  + 'purposeTag, digest, auth); mutation.registerWith gives the register call that precedes a storePqzPop row; mutation.otherKind '
  + '(record-kind-mismatch) is the kind the pop\'s record names instead of the row\'s. Attribute checks run '
  + 'before the PoP; error is the registry\'s. A proof hash of keccak256("") (an empty proof) is UAPqzPopHash wherever a proof hash is '
  + 'signed, and storePqzPop refuses empty proof bytes.',
].join(' ');
const typedSection = {
  domain: ua.PORTABLE_DOMAIN, domainType: encodeType(ua.PORTABLE_TYPES, 'EIP712Domain'), domainSeparator: hex(ua.portableDomainSeparator()),
  types: Object.fromEntries(Object.keys(ua.PORTABLE_TYPES).filter((t) => t !== 'EIP712Domain')
    .map((t) => [t, { type: encodeType(ua.PORTABLE_TYPES, t), typehash: hex(ua.PORTABLE_TYPEHASH[t]) }])),
};
const build = () => ({
  note, version: 2,
  typed: typedSection,
  tags: { PURPOSE_POP_V2: tag('scaas.ua.purpose.pop.v2'), PURPOSE_KEM: tag('scaas.ua.purpose.kem.v1'),
    PURPOSE_PQZ_KEY: tag('scaas.ua.purpose.pqz-key.v1'), PURPOSE_MEMBERSHIP: tag('scaas.ua.purpose.membership.v1'),
    PQZ_KEY_GROUP: tag('scaas.ua.group.pqz-mlwe.v1') },
  checked: ua.CHECKED, kemScheme: ua.KEM_SCHEME.mlkem1024X25519, kemPkLength: ua.KEM_PK_LENGTH, sets: PQZ_SETS, registrations, kemRecords, pqzKeyRecords, memberships, negatives,
});

/** portable.json's exact text. */
export const portableJson = () => `${JSON.stringify(build(), null, 2)}\n`;
/** nested.json's exact text. */
export const nestedJson = () => `${JSON.stringify(nestedBuild(), null, 2)}\n`;

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = process.argv[2] ?? OUT;
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'portable.json'), portableJson());
  writeFileSync(join(out, 'nested.json'), nestedJson());
  console.log(`portable.json: ${registrations.length} registrations, ${kemRecords.length} KEM records, ${pqzKeyRecords.length} PQZ key `
    + `records, ${memberships.length} memberships, ${negatives.length} negatives; written to ${out}`);
}
