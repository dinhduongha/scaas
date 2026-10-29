// Generates smartcontracts/vectors/ua/portable.json (UA-8, spec P1, P2, P7, P10, P11): the portable registration of every
// kind clientkeys signs — the `register(kind, keyData, attrs, pop, pqzPop)` arguments with every digest between them — the
// KEM key records (versions 1-3) of the KEM holders, and the negatives a registry must refuse with their error. No chain
// id, chain uid or registry anywhere: the same bytes register the UA on every chain and every family (P10), so every
// family's tests read this file (UAKinds / UARegistry forge tests, clients/ua-rs, the reproducers, Soroban).
// Keys: the fixed seeds of signatures.json (the derived kinds, the native EOA) and pq_kat.json (account 0, index 0;
// mldsa65 indexes 1 and 2 for the msig members); KEM keys: real ML-KEM-1024 ek ‖ X25519 pk from fixed labels (UA8-D15);
// PQZ keys and R_REG proofs: deterministic filler of the set's lengths, at every parameter set (UA8-D17, ruling C4).
// test/ua8.test.js rebuilds every digest by hand and re-verifies every signature.
//   node scripts/ua-portable-vectors.mjs [outDir]
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hex, keccak_256 } from '../src/bytes.js';
import * as ua from '../src/ua.js';
import { PQ_KINDS } from '../src/pq.js';
import { SCHEMES, schemeSecret, ecdsa, nativeSk, nativeUa, encodeMemberSigs, pqKey, pqSignMsg, PQZ_SETS, pqzKeyOf, pqzPopOf,
  kemPublicKey } from './ua-signers.mjs';

const OUT = fileURLToPath(new URL('../../../smartcontracts/vectors/ua/', import.meta.url));
const NONE = new Uint8Array(0);
const Z = new Uint8Array(32);
const SETS = Object.keys(PQZ_SETS);
const MEMBER = ua.purposeTag('member');

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

/** An msig over `members` ({ kind, ua, sign? } with a weight): sorted by id; `sign(md, indices)` = abi.encode(MemberSig[]),
 *  derived members over uaMessage(kind, member, md) with empty key data (stored kinds), a native member by EIP-191
 *  personal_sign of md (ruling C7: chain-free, no UAAuth domain). */
function msig(name, threshold, members) {
  const ms = members.map(([m, weight]) => ({ ...m, weight }))
    .sort((a, b) => (hex(a.ua) < hex(b.ua) ? -1 : 1)).map((m, index) => ({ ...m, index }));
  const keyData = ua.encodeMsig(threshold, ms.map((m) => ({ kind: m.kind, id: m.ua, weight: m.weight })));
  const sign = (md, indices) => encodeMemberSigs(indices.map((i) => ({ index: i, keyData: NONE,
    sig: ua.isNativeKind(ms[i].kind) ? ecdsa(nativeSk, ua.personalSignDigest(md)) : ms[i].sign(ua.uaMessage(ms[i].kind, MEMBER, md)) })));
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
  const pqzKey = set ? pqzKeyOf(set) : NONE;
  const pqzPop = set ? pqzPopOf(set) : NONE;
  const kemVersion = kem ? 1 : 0;
  const kemPk = kem ? KEM[s.name][0] : NONE;
  const m = ua.holderPopMessage(s.kind, { ua: s.ua, keyData: s.keyData, pqzKey, pqzPop, kemVersion, kemPk });
  const isMsig = s.kind === 0x0120;
  const popSigners = isMsig && ua.msigPqzEligible(s.keyData) ? s.members.map((x) => x.index).slice(0, 2) : [];
  const pop = isMsig ? (popSigners.length ? s.signMembers(m.memberDigest, popSigners) : NONE) : s.sign(m.message, { pop: true });
  return {
    name: set ? `${s.name}/${set}` : s.name, kind: s.kind, kindName: ua.kindInfo(s.kind).name, set, keyData: hex(s.keyData),
    ua: hex(s.ua), attrs: { pqzKey: hex(pqzKey), pqzPopHash: hex(m.pqzPopHash), kemVersion, kemPk: hex(kemPk) },
    pqzKeyHash: hex(m.pqzKeyHash), kemRecordHash: hex(m.kemRecordHash), portablePopDigest: hex(m.portablePopDigest),
    registrationDigest: hex(m.registrationDigest), popMessage: hex(m.message), pop: hex(pop), pqzPop: hex(pqzPop),
    pqzRegMessage: hex(set ? ua.pqzRegMessage({ ua: s.ua, pqzKey, kemVersion, kemPk }) : Z),
    ...(isMsig ? { threshold: s.threshold, members: s.members.map((x) => ({ index: x.index, kind: x.kind, id: hex(x.ua), weight: x.weight })),
      memberDigest: hex(m.memberDigest), popSigners } : {}),
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

// --- KEM records: versions 1-3 of each KEM holder, signed over uaMessage(kind, kem, kemRecordDigest) (an msig by members) ---
const kemRecords = [[ml, 'mldsa65'], [fn, 'fndsa512'], [pqMsig, 'msig-pq']].flatMap(([s, name]) => KEM[name].map((kemPk, i) => {
  const version = i + 1;
  const digest = ua.kemRecordDigest({ ua: s.ua, version, kemPk });
  const message = ua.kemRecordMessage(s.kind, { ua: s.ua, version, kemPk });
  const md = s.kind === 0x0120 ? ua.memberDigest(s.ua, message) : null;
  return { name, ua: hex(s.ua), kind: s.kind, version, kemPk: hex(kemPk), digest: hex(digest), message: hex(message),
    ...(md ? { memberDigest: hex(md) } : {}), sig: hex(md ? s.signMembers(md, [0, 1]) : s.sign(message)) };
}));

// --- negatives: a registration row with fields replaced (`set`: "attrs.<field>" or "pqzPop"), and the registry's error ---
// Attribute errors (holder, KEM version, KEM key length) are checked before the PoP; a UAPoP row passes those checks and
// moves registrationDigest, so the row's pop no longer verifies; pqzPop "0x" keeps the proof check out of it.
const neg = (name, entry, row, set, error) => ({ name, entry, mutation: { row, set }, error });
const negatives = [
  ...SETS.flatMap((set) => {
    const row = `mldsa65/${set}`;
    return [
      neg(`swapped-pqz-key/${set}`, 'register', row, { 'attrs.pqzKey': hex(pqzKeyOf(set, ' other')), pqzPop: '0x' }, 'UAPoP'),
      neg(`stripped-pqz-key/${set}`, 'register', row, { 'attrs.pqzKey': '0x', 'attrs.pqzPopHash': hex(Z), pqzPop: '0x' }, 'UAPoP'),
      neg(`wrong-pqz-pop-hash/${set}`, 'register', row,
        { 'attrs.pqzPopHash': hex(keccak_256(pqzPopOf(set, ' other'))), pqzPop: '0x' }, 'UAPoP'),
      neg(`non-holder-with-pqz-key/${set}`, 'register', 'slhdsa128s',
        { 'attrs.pqzKey': hex(pqzKeyOf(set)), 'attrs.pqzPopHash': hex(keccak_256(pqzPopOf(set))) }, 'UAPqzHolder'),
      neg(`store-pqz-pop-other-bytes/${set}`, 'storePqzPop', row, { pqzPop: hex(pqzPopOf(set, ' other')) }, 'UAPqzPopHash'),
    ];
  }),
  neg('stripped-kem-pk', 'register', 'fndsa512', { 'attrs.kemVersion': 0, 'attrs.kemPk': '0x' }, 'UAPoP'),
  neg('swapped-kem-pk', 'register', 'fndsa512', { 'attrs.kemPk': hex(KEM.fndsa512[1]) }, 'UAPoP'),
  neg('other-kem-version', 'register', 'fndsa512', { 'attrs.kemVersion': 2 }, 'UAPoP'),
  neg('kem-pk-1599', 'register', 'fndsa512', { 'attrs.kemPk': hex(KEM.fndsa512[0].subarray(0, 1599)) }, 'UAKemKeyLength'),
  neg('kem-version-0', 'register', 'fndsa512', { 'attrs.kemVersion': 0 }, 'UAKemVersion'),
  neg('non-holder-with-kem', 'register', 'secp256k1', { 'attrs.kemVersion': 1, 'attrs.kemPk': hex(KEM.fndsa512[0]) }, 'UAKemHolder'),
  neg('classical-msig-with-kem', 'register', 'msig-classical', { 'attrs.kemVersion': 1, 'attrs.kemPk': hex(KEM.fndsa512[0]) },
    'UAKemHolder'),
];

const tag = (t) => ({ tag: t, hash: hex(keccak_256(new TextEncoder().encode(t))) });
const note = 'Generated by clients/clientkeys/scripts/ua-portable-vectors.mjs (src/ua.js, @noble/curves 2.4.0, @noble/post-quantum '
  + '0.7.1); never edit by hand. UA-8 portable registrations: every digest is keccak256 of 32-byte words, no chain and no '
  + 'registry: portablePopDigest = keccak256(PURPOSE_POP_V2 | ua | pqzKeyHash | kemRecordHash), registrationDigest = '
  + 'keccak256(portablePopDigest | attrs.pqzPopHash), popMessage = ua_msg(kind, PURPOSE_POP_V2, registrationDigest) (an msig: '
  + 'members sign memberDigest = keccak256(ua | popMessage) under member, a native member by EIP-191 personal_sign), '
  + 'pqzRegMessage = ua_msg(0x0142, PURPOSE_POP_V2, portablePopDigest) (the R_REG message), kemRecordDigest = '
  + 'keccak256(KEM_RECORD_TAG | ua | uint256(version) | keccak256(kemPk)), a KEM record signed over ua_msg(kind, PURPOSE_KEM, '
  + 'kemRecordDigest). Absent attributes are empty / 0. pqzPop rows are filler of a real R_REG proof\'s length per set, not '
  + 'proofs. registrations[i] = register(kind, keyData, attrs, pop, pqzPop); negatives: the row\'s arguments with mutation.set '
  + 'applied, refused with error (attribute checks before the PoP).';
const build = () => ({
  note, version: 1,
  tags: { PURPOSE_POP_V2: tag('scaas.ua.purpose.pop.v2'), PURPOSE_KEM: tag('scaas.ua.purpose.kem.v1'),
    KEM_RECORD_TAG: tag('scaas.ua.kem-record.v1') },
  checked: ua.CHECKED, kemPkLength: ua.KEM_PK_LENGTH, sets: PQZ_SETS, registrations, kemRecords, negatives,
});

/** portable.json's exact text. */
export const portableJson = () => `${JSON.stringify(build(), null, 2)}\n`;

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = process.argv[2] ?? OUT;
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'portable.json'), portableJson());
  console.log(`portable.json: ${registrations.length} registrations, ${kemRecords.length} KEM records, ${negatives.length} negatives; written to ${out}`);
}
