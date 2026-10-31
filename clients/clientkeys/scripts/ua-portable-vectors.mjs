// Generates smartcontracts/vectors/ua/portable.json (UA-8, spec P1, P2, P7, P10, P11): the portable registration of every
// kind clientkeys signs — the `register(kind, keyData, attrs, pop, pqzPop)` arguments with every digest between them — the
// KEM key records (versions 1-3) of the KEM holders, and the negatives a registry must refuse with their error. The records
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
import * as ua from '../src/ua.js';
import { encodeType } from '../src/evm.js';
import { PQ_KINDS } from '../src/pq.js';
import { personalSignDigest } from '../legacy/typed-signing/ua-portable-raw.js';
import { SCHEMES, schemeSecret, ecdsa, nativeSk, nativeUa, encodeMemberSigs, pqKey, pqSignMsg, PQZ_SETS, pqzKeyOf, pqzPopOf,
  kemPublicKey } from './ua-signers.mjs';

const OUT = fileURLToPath(new URL('../../../smartcontracts/vectors/ua/', import.meta.url));
const NONE = new Uint8Array(0);
const Z = new Uint8Array(32);
const SETS = Object.keys(PQZ_SETS);
const MEMBER = ua.purposeTag('member');
// only for the negative that frames a native member's portable signature as UAAuth (chain-bound) instead of the typed digest
const { contexts } = JSON.parse(readFileSync(join(OUT, 'structures.json'), 'utf8'));
// each UA's own filler PQZ key (one UA per proven PQZ key); mldsa65's at n2048-kmax1024 is kinds.json's `pqzKey`
const PQZ_LABEL = { mldsa65: '', 'msig-pq': ' msig-pq', fndsa512: ' fndsa512', 'msig-pq-native': ' msig-pq-native' };

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

/** An msig over `members` ({ kind, ua, sign? } with a weight): sorted by id; `sign(md, typedDigest, indices)` =
 *  abi.encode(MemberSig[]), derived members over uaMessage(kind, member, md) with empty key data (stored kinds), a native
 *  member by ECDSA over the record's typed digest itself (TS-D4: eth_signTypedData_v4, chain-free, no UAAuth domain);
 *  `nativeSig` replaces the native member's signature (the negatives). */
function msig(name, threshold, members) {
  const ms = members.map(([m, weight]) => ({ ...m, weight }))
    .sort((a, b) => (hex(a.ua) < hex(b.ua) ? -1 : 1)).map((m, index) => ({ ...m, index }));
  const keyData = ua.encodeMsig(threshold, ms.map((m) => ({ kind: m.kind, id: m.ua, weight: m.weight })));
  const sign = (md, typedDigest, indices, nativeSig = () => ecdsa(nativeSk, typedDigest)) => encodeMemberSigs(indices.map((i) => ({
    index: i, keyData: NONE, sig: ua.isNativeKind(ms[i].kind) ? nativeSig() : ms[i].sign(ua.uaMessage(ms[i].kind, MEMBER, md)) })));
  return { ...signer(name, 0x0120, keyData, null), threshold, members: ms, signMembers: sign };
}

const kemKeys = (base) => [1, 2, 3].map((v) => kemPublicKey(`${base} v${v}`));
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
function registration(s, { set = '', kem = false } = {}) {
  const pqzKey = set ? pqzKeyOf(set, PQZ_LABEL[s.name]) : NONE;
  const pqzPop = set ? pqzPopOf(set) : NONE;
  const kemVersion = kem ? 1 : 0;
  const kemPk = kem ? KEM[s.name][0] : NONE;
  const m = ua.holderPopMessage(s.kind, { ua: s.ua, keyData: s.keyData, pqzKey, pqzPop, kemVersion, kemPk });
  const isMsig = s.kind === 0x0120;
  const popSigners = isMsig && ua.msigPqzEligible(s.keyData) ? s.members.map((x) => x.index).slice(0, 2) : [];
  const pop = isMsig ? (popSigners.length ? s.signMembers(m.memberDigest, m.registrationDigest, popSigners) : NONE)
    : s.sign(m.message, { pop: true });
  return {
    name: set ? `${s.name}/${set}` : s.name, kind: s.kind, kindName: ua.kindInfo(s.kind).name, set, keyData: hex(s.keyData),
    ua: hex(s.ua), attrs: { pqzKey: hex(pqzKey), pqzPopHash: hex(m.pqzPopHash), kemVersion, kemPk: hex(kemPk) },
    pqzKeyHash: hex(m.pqzKeyHash), kemRecordHash: hex(m.kemRecordHash), portableRecordDigest: hex(m.portableRecordDigest),
    registrationDigest: hex(m.registrationDigest), popMessage: hex(m.message), pop: hex(pop), pqzPop: hex(pqzPop),
    pqzRegMessage: hex(set ? ua.pqzRegMessage({ ua: s.ua, kind: s.kind, pqzKey, kemVersion, kemPk }) : Z),
    ...(isMsig ? { threshold: s.threshold, members: s.members.map((x) => ({ index: x.index, kind: x.kind, id: hex(x.ua), weight: x.weight })),
      memberDigest: hex(m.memberDigest), popSigners } : {}),
    typedData: m.typedData,
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

// --- KEM records: versions 1-3 of each KEM holder, signed over uaMessage(kind, kem, kemRecordDigest) (an msig by members);
// structHash = hashStruct(UAKemRecord) (v1's is the registration's kemRecordHash), digest = the typed UAKemRecord digest ---
const kemRecords = [[ml, 'mldsa65'], [fn, 'fndsa512'], [pqMsig, 'msig-pq']].flatMap(([s, name]) => KEM[name].map((kemPk, i) => {
  const version = i + 1;
  const record = { ua: s.ua, version, kemPk };
  const digest = ua.kemRecordDigest(record);
  const message = ua.kemRecordMessage(s.kind, record);
  const md = s.kind === 0x0120 ? ua.memberDigest(s.ua, message) : null;
  return { id: `${name}/v${version}`, name, ua: hex(s.ua), kind: s.kind, version, kemPk: hex(kemPk), structHash: hex(ua.kemRecordHash(record)),
    digest: hex(digest), message: hex(message), ...(md ? { memberDigest: hex(md) } : {}),
    sig: hex(md ? s.signMembers(md, digest, [0, 1]) : s.sign(message)), typedData: ua.portableTypedData('UAKemRecord', ua.kemRecordStruct(record)) };
}));

// --- PQZ key records (setPqzKey, ruling A1-I1): a holder registered without a PQZ key attaches one later, at every set ---
const pqzKeyRecord = (s, set, signerOf = s) => {
  const reg = registrations.find((r) => r.ua === hex(s.ua));
  const pqzKey = pqzKeyOf(set, PQZ_LABEL[s.name]);
  const m = ua.pqzKeyRecordMessage(s.kind, { ua: s.ua, keyData: s.keyData, pqzKey, pqzPop: pqzPopOf(set) });
  const sig = s.kind === 0x0120 ? s.signMembers(m.memberDigest, m.recordDigest, [0, 1]) : signerOf.sign(m.message);
  return { name: `${s.name}/${set}`, set, kind: s.kind, ua: reg.ua, pqzKey: hex(pqzKey), pqzKeyHash: hex(m.pqzKeyHash),
    pqzPopHash: hex(m.pqzPopHash), pqzKeyDigest: hex(m.pqzKeyDigest), recordDigest: hex(m.recordDigest), message: hex(m.message),
    ...(m.memberDigest ? { memberDigest: hex(m.memberDigest) } : {}), sig: hex(sig), pqzRegMessage: hex(m.pqzRegMessage),
    typedData: m.typedData };
};
const pqzKeyRecords = [fn, nativeMsig].flatMap((s) => SETS.map((set) => pqzKeyRecord(s, set)));
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
  neg('stripped-kem-pk', 'register', 'fndsa512', { 'attrs.kemVersion': 0, 'attrs.kemPk': '0x' }, 'UAPoP'),
  neg('swapped-kem-pk', 'register', 'fndsa512', { 'attrs.kemPk': hex(KEM.fndsa512[1]) }, 'UAPoP'),
  neg('other-kem-version', 'register', 'fndsa512', { 'attrs.kemVersion': 2 }, 'UAPoP'),
  neg('kem-pk-1599', 'register', 'fndsa512', { 'attrs.kemPk': hex(KEM.fndsa512[0].subarray(0, 1599)) }, 'UAKemKeyLength'),
  // the KEM scheme byte (CTR-UA-32): the pre-scheme 1,600-byte key (no scheme byte: its first byte read as one), the
  // reserved scheme 2 (ML-KEM-1024 + HQC + X25519) and an unknown one are UAKemScheme, a scheme-1 key of 1,600 bytes UAKemKeyLength
  neg('kem-pk-without-scheme', 'register', 'fndsa512', { 'attrs.kemPk': hex(KEM.fndsa512[0].subarray(1)) },
    kemErr(KEM.fndsa512[0].subarray(1))),
  neg('kem-scheme-reserved', 'register', 'fndsa512', { 'attrs.kemPk': hex(withScheme(2, KEM.fndsa512[0])) }, 'UAKemScheme'),
  neg('kem-scheme-unknown', 'register', 'fndsa512', { 'attrs.kemPk': hex(withScheme(0, KEM.fndsa512[0])) }, 'UAKemScheme'),
  neg('kem-pk-1600', 'register', 'fndsa512', { 'attrs.kemPk': hex(KEM.fndsa512[0].subarray(0, 1600)) }, 'UAKemKeyLength'),
  neg('kem-version-without-pk', 'register', 'fndsa512', { 'attrs.kemPk': '0x' }, 'UAKemKeyLength'),
  neg('kem-version-0', 'register', 'fndsa512', { 'attrs.kemVersion': 0 }, 'UAKemVersion'),
  neg('proof-hash-without-pqz-key', 'register', 'fndsa512', { 'attrs.pqzPopHash': hex(keccak_256(pqzPopOf(SETS[0]))) }, 'UAPqzPopHash'),
  // ruling A6-m: an empty proof is no proof; its hash is refused wherever a proof hash is signed
  neg('pqz-pop-hash-of-empty', 'register', `mldsa65/${SETS[0]}`, { 'attrs.pqzPopHash': hex(keccak_256(new Uint8Array(0))), pqzPop: '0x' },
    'UAPqzPopHash'),
  neg('pqz-key-record-hash-of-empty', 'setPqzKey', `fndsa512/${SETS[0]}`, { pqzPopHash: hex(keccak_256(new Uint8Array(0))) }, 'UAPqzPopHash'),
  neg('non-holder-with-kem', 'register', 'secp256k1', { 'attrs.kemVersion': 1, 'attrs.kemPk': hex(KEM.fndsa512[0]) }, 'UAKemHolder'),
  neg('classical-msig-with-kem', 'register', 'msig-classical', { 'attrs.kemVersion': 1, 'attrs.kemPk': hex(KEM.fndsa512[0]) },
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
  + 'kemPk[0], kemPkHash = keccak256(kemPk)}) of the initial record, the zero record UAKemRecord{ua, 0, 0, 0} when there is none '
  + '(version 0 is never a valid record); portableRecordDigest = typed(UAPortableRecord{ua, kind, pqzKeyHash, kem}) (kind = the '
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
  + 'message, the PQZ key record message) under member, with empty key data for stored kinds. A code-less native EOA member '
  + '(its own key only) signs the record\'s typed digest itself, typedDigest = registrationDigest / digest / recordDigest (what '
  + 'eth_signTypedData_v4 of typedData returns), 65-byte r | s | v, low-s, v in {27, 28}, empty key data; EIP-191 personal_sign '
  + 'is refused (native-member-personal-sign). Only for PURPOSE_POP_V2, PURPOSE_KEM and PURPOSE_PQZ_KEY; every other purpose '
  + 'stays UAAuth (chain-bound EIP-712: CTR-MTX-14). A contract member answers ERC-1271 isValidSignature(typedDigest, sig) on '
  + 'each chain: portable only where that wallet exists with the same behaviour.',
  'Rows: registrations[i] = register(kind, keyData, attrs, pop, pqzPop); kemRecords[i] = setKemKey(ua, version, kemPk, sig) '
  + '(id = name/vN; v1 is also the registration\'s initial record); pqzKeyRecords[i] = setPqzKey(ua, pqzKey, pqzPopHash, sig) '
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
    PURPOSE_PQZ_KEY: tag('scaas.ua.purpose.pqz-key.v1'), PQZ_KEY_GROUP: tag('scaas.ua.group.pqz-mlwe.v1') },
  checked: ua.CHECKED, kemScheme: ua.KEM_SCHEME.mlkem1024X25519, kemPkLength: ua.KEM_PK_LENGTH, sets: PQZ_SETS, registrations, kemRecords, pqzKeyRecords, negatives,
});

/** portable.json's exact text. */
export const portableJson = () => `${JSON.stringify(build(), null, 2)}\n`;

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = process.argv[2] ?? OUT;
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'portable.json'), portableJson());
  console.log(`portable.json: ${registrations.length} registrations, ${kemRecords.length} KEM records, ${pqzKeyRecords.length} PQZ key `
    + `records, ${negatives.length} negatives; written to ${out}`);
}
