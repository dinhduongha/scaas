// UNAUDITED. UA identity layer (accounts.md §1.3–§1.6; CTR-UA-02…05, 07, 09, 11, 12): the kind table, ids, keyHash, purpose tags,
// ua_msg, the portable records as typed EIP-712 structs under the name + version domain (typed-signing TS-D1 … TS-D4: the
// register PoP, R_REG, KEM and PQZ key records), the registry's UAAuth digest, member digests, canonical ids and key-data
// validation. The same rules live in Solidity (src/ua/UAKinds.sol), Rust (clients/ua-rs), Python (clients/ua-py),
// Go (clients/ua-go) and C# (clients/ua-cs); smartcontracts/vectors/ua/kinds.json, structures.json and portable.json, written
// by scripts/ua-vectors.mjs and scripts/ua-portable-vectors.mjs from this file, pin all six. No signing here (UAKey and the
// signers are UA F3). The chain-bound PoP before UA-8 is in legacy/ua8/ua-pop-v1.js, the raw portable digests before the
// typed records in legacy/typed-signing/ua-portable-raw.js.
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { keccak_256, concatBytes, utf8ToBytes, fromHex, hex, word } from './bytes.js';
import { encodeType } from './evm.js';

/** An error whose `code` every implementation and the vector files share. */
export class UAError extends Error {
  constructor(code, reason) {
    super(reason ? `${code}: ${reason}` : code);
    this.code = code;
    this.reason = reason;
  }
}
const fail = (code, reason) => { throw new UAError(code, reason); };
const need = (ok, reason) => { if (!ok) fail('UAKeyData', reason); };

const bytes = (v) => (v instanceof Uint8Array ? v : typeof v === 'string' ? fromHex(v) : fail('UAKeyData', 'type'));
const sized = (v, n, what) => {
  const b = bytes(v);
  if (b.length !== n) throw new Error(`${what} must be ${n} bytes`);
  return b;
};
const be = (b) => (b.length === 0 ? 0n : BigInt(hex(b)));
const u16 = (d, o) => (d[o] << 8) | d[o + 1];
const less = (a, b) => {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
};
const tagHash = (s) => keccak_256(utf8ToBytes(s));

// [number, name, key-data lengths (empty = variable), keyHash group (null = none)]
const DERIVED = [
  [0x0100, 'webauthn-p256', [96], 'p256'],
  [0x0101, 'p256', [64], 'p256'],
  [0x0102, 'ed25519', [32], 'ed25519'],
  [0x0103, 'bip340', [32], 'secp256k1'],
  [0x0104, 'schnorr-bn254', [64], 'bn254-g1'],
  [0x0105, 'schnorr-bls12381', [128], 'bls12381-g1'],
  [0x0106, 'bls12381-minsig', [256], 'bls12381-g2'],
  [0x0107, 'bls-bn254-minsig', [128], 'bn254-g2'],
  [0x0110, 'musig2-secp256k1', [], 'secp256k1'],
  [0x0111, 'frost-secp256k1', [], 'secp256k1'],
  [0x0112, 'musig2-bn254', [], 'bn254-g1'],
  [0x0113, 'frost-bn254', [], 'bn254-g1'],
  [0x0120, 'msig', [], null],
  [0x0130, 'mldsa44', [1312], 'mldsa44'],
  [0x0131, 'mldsa65', [1952], 'mldsa65'],
  [0x0132, 'fndsa512', [897], 'fndsa512'],
  [0x0133, 'slhdsa128s', [32], 'slhdsa128s'],
  [0x0141, 'zether-bls12381', [128], 'bls12381-g1'],
  [0x0108, 'secp256k1', [64], 'secp256k1'], // 2026-10-17, appended (rows keep their positions)
];
// [number, name, native id lengths]
const NATIVE = [
  [0x0001, 'evm-eoa', [20]], [0x0002, 'evm-contract', [20]], [0x0003, 'hedera-native', [20]],
  [0x0010, 'solana-ed25519', [32]], [0x0011, 'stellar-account', [32]], [0x0012, 'soroban-contract', [32]],
  [0x0013, 'aptos-account', [32]], [0x0014, 'sui-address', [32]], [0x0015, 'cosmos-account', [20, 32]],
  [0x0016, 'ton-wallet', [32]], [0x0017, 'near-account', [32]], [0x0018, 'algorand-address', [32]],
];
export const KINDS = Object.freeze([
  ...NATIVE.map(([kind, name, lengths]) => Object.freeze({ kind, name, native: true, lengths, group: null })),
  ...DERIVED.map(([kind, name, lengths, group]) => Object.freeze({ kind, name, native: false, lengths, group })),
]);
/** Schemes are not kinds (UA-6 U14): 0x0142 is the PQZ key attribute of a PQ holder; it keeps its tag and keyHash group. */
/** The PQZ key length of each parameter set (n2048-kmax1024, n2304-kmax4096, n2560-kmax16384, n2816-kmax65536; PqzSet.PK). */
export const PQZ_KEY_LENGTHS = Object.freeze([16384, 18432, 20480, 22528]);
export const SCHEMES = Object.freeze([Object.freeze({ kind: 0x0142, name: 'pqz-mlwe', lengths: PQZ_KEY_LENGTHS, group: 'pqz-mlwe' })]);
const BY_NUMBER = new Map(KINDS.map((k) => [k.kind, k]));
const SCHEME_BY_NUMBER = new Map(SCHEMES.map((k) => [k.kind, k]));
export const kindInfo = (kind) => BY_NUMBER.get(kind) ?? fail('UAKindUnknown', `0x${Number(kind).toString(16)}`);
const derived = (kind) => {
  if (SCHEME_BY_NUMBER.has(kind)) fail('UAKindNotDerived', SCHEME_BY_NUMBER.get(kind).name);
  const k = kindInfo(kind);
  if (k.native) fail('UAKindNotDerived', k.name);
  return k;
};
// tag / keyHash / message accept a kind or a scheme; id derivation and key-data validation accept kinds only
const tagged = (kind) => SCHEME_BY_NUMBER.get(kind) ?? derived(kind);

const singleSigning = (k) => (k >= 0x0100 && k <= 0x0108) || (k >= 0x0110 && k <= 0x0113) || (k >= 0x0130 && k <= 0x0133);
export const isNativeKind = (kind) => BY_NUMBER.get(kind)?.native === true;
export const isZetherKind = (kind) => kind === 0x0141;
export const isSigningKind = (kind) => kind === 0x0120 || kind === 0x0141 || singleSigning(kind);
/** Kinds that may hold a PQZ key attribute: mldsa44, mldsa65, fndsa512 (an `msig` per `msigPqzEligible`). */
export const isPqzHolder = (kind) => kind >= 0x0130 && kind <= 0x0132;
/** An `msig` whose members of kinds outside 0x0130–0x0133 weigh less than its threshold (CTR-PQZ-12). */
export function msigPqzEligible(keyData) {
  const d = bytes(keyData);
  need(d.length >= 4 && d.length === 4 + 36 * u16(d, 2), 'length');
  let classical = 0;
  for (let o = 4; o < d.length; o += 36) {
    const k = u16(d, o);
    if (k < 0x0130 || k > 0x0133) classical += u16(d, o + 34);
  }
  return classical < u16(d, 0);
}
export const isMemberKind = (kind, hederaNative = false) =>
  singleSigning(kind) || kind === 0x0001 || kind === 0x0002 || (hederaNative && kind === 0x0003);

export const kindTagString = (kind) => `scaas.ua.${tagged(kind).name}.v1`;
export const TAG = (kind) => tagHash(kindTagString(kind));
export const GROUPS = Object.freeze([...new Set([...DERIVED.map(([, , , g]) => g), ...SCHEMES.map((k) => k.group)].filter(Boolean))]);
export const groupTagString = (group) => {
  if (!GROUPS.includes(group)) throw new Error(`unknown keyHash group ${group}`);
  return `scaas.ua.group.${group}.v1`;
};
export const GROUP = (group) => tagHash(groupTagString(group));
export const MSG_TAG = tagHash('scaas.ua.msg.v1');
export const PURPOSES = Object.freeze(['pop', 'metatx', 'metatx-cancel', 'member', 'zether-auth', 'zether-owner',
  'keyop', 'receiver-fee', 'vp', 'vc-anchor', 'trade', 'kem', 'pqz-key']);
/** `keccak256("scaas.ua.purpose.<p>.v<version>")`; every purpose has v1, `pop` also v2 (the portable PoP, UA-8 P1). */
export const purposeTagString = (p, version = 1) => {
  if (!PURPOSES.includes(p) || !(version === 1 || (version === 2 && p === 'pop'))) fail('UAPurposeUnknown', `${p} v${version}`);
  return `scaas.ua.purpose.${p}.v${version}`;
};
export const purposeTag = (p, version = 1) => tagHash(purposeTagString(p, version));
/** The chain-bound PoP's purpose before UA-8 (legacy/ua8); the registry accepts only `POP_V2_TAG`. */
export const POP_TAG = purposeTag('pop');
export const POP_V2_TAG = purposeTag('pop', 2);
export const KEM_TAG = purposeTag('kem');
/** A PQZ key attached after `register` (`setPqzKey`, ruling A1-I1): its purpose. */
export const PQZ_KEY_TAG = purposeTag('pqz-key');
/** The KEM scheme byte, `kemPk[0]` (CTR-UA-32): 1 = ML-KEM-1024 + X25519 (X-Wing order), `kemPk = 0x01 ‖ ek (1,568 B) ‖
 *  X25519 pk (32 B)`; 2 = ML-KEM-1024 + HQC + X25519, reserved (after FIPS 207), refused today (`UAKemScheme`). */
export const KEM_SCHEME = Object.freeze({ mlkem1024X25519: 1, mlkem1024HqcX25519: 2 });
/** The length of a scheme-1 `kemPk`, its scheme byte included: the only KEM key the registry stores today (UA-8 P7). */
export const KEM_PK_LENGTH = 1601;
/** The `kemPk` length of an enabled scheme, 0 = unknown or reserved. */
export const kemPkLength = (scheme) => (scheme === KEM_SCHEME.mlkem1024X25519 ? KEM_PK_LENGTH : 0);
/** Who checked a part of a record (UA-8 P11.3); `relayer` comes with the relayer id. */
export const CHECKED = Object.freeze({ none: 0, chain: 1, relayer: 2 });
export const DOMAIN_TYPEHASH = tagHash('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)');
export const UAAUTH_TYPEHASH = tagHash('UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)');
export const NAME_HASH = tagHash('SCaaS UARegistry');

/** `keccak256(TAG(kind) ‖ keyData)`; no validation (use `deriveUA`). */
export const uaOf = (kind, keyData) => {
  derived(kind); // a scheme (0x0142) or a native kind has no derived id
  return keccak_256(concatBytes(TAG(kind), bytes(keyData)));
};
export const inNativeSpace = (id) => sized(id, 32, 'id').subarray(0, 12).every((b) => b === 0);

/** Validate, derive, refuse an id whose top 96 bits are zero (CTR-UA-03). */
export function deriveUA(kind, keyData, { hederaNative = false } = {}) {
  validateKeyData(kind, keyData, { hederaNative });
  const ua = uaOf(kind, keyData);
  if (inNativeSpace(ua)) fail('UAIdInNativeSpace', hex(ua));
  return ua;
}

/** A native id, left-padded to 32 bytes. */
export function nativeId(kind, raw) {
  const k = kindInfo(kind);
  if (!k.native) fail('UAKindNotNative', k.name);
  const b = bytes(raw);
  need(k.lengths.includes(b.length), 'length');
  return concatBytes(new Uint8Array(32 - b.length), b);
}

/** `keccak256(GROUP(g) ‖ canonical pubkey)`, null for structures. Call on validated key data. */
export function keyHashOf(kind, keyData) {
  const k = tagged(kind);
  if (!k.group) return null;
  const d = bytes(keyData);
  const [lo, hi] = { 0x0100: [0, 32], 0x0101: [0, 32], 0x0108: [0, 32], 0x0110: [1, 33], 0x0111: [1, 33], 0x0112: [0, 64], 0x0113: [0, 64] }[kind]
    ?? [0, d.length];
  need(d.length >= hi, 'length');
  return keccak_256(concatBytes(GROUP(k.group), d.subarray(lo, hi)));
}

export const uaMessage = (kind, purpose, digest) =>
  keccak_256(concatBytes(MSG_TAG, TAG(kind), sized(purpose, 32, 'purposeTag'), sized(digest, 32, 'digest')));
export const chainKeyHash = (chainId) => tagHash(`evm:${BigInt(chainId).toString(10)}`);
const addressWord = (a) => concatBytes(new Uint8Array(12), sized(a, 20, 'registry'));

const Z32 = new Uint8Array(32);
const present = (v) => v !== undefined && v !== null && bytes(v).length > 0;
const orEmpty = (v) => (v === undefined || v === null ? new Uint8Array(0) : bytes(v));

/** `keyHash(0x0142, pqzKey)`; a key of no parameter set's length is `UAKeyData`. */
function pqzKeyHashOf(pqzKey) {
  const k = orEmpty(pqzKey);
  if (!PQZ_KEY_LENGTHS.includes(k.length)) fail('UAKeyData', `PQZ key length ${k.length}`);
  return keyHashOf(0x0142, k);
}
const EMPTY_PROOF_HASH = hex(keccak_256(new Uint8Array(0)));
/** The proof hash from the proof bytes or the hash alone (absent = omitted, zero-length or all-zero); a hash of another
 *  length, both given and different, and `keccak256("")` (an empty proof is no proof: ruling A6-m) are `UAPqzPopHash`. */
function proofHashOf(pqzPop, pqzPopHash) {
  const proofHash = present(pqzPop) ? keccak_256(bytes(pqzPop)) : null;
  let givenHash = present(pqzPopHash) ? bytes(pqzPopHash) : null;
  if (givenHash && givenHash.length !== 32) fail('UAPqzPopHash', `pqzPopHash of ${givenHash.length} bytes`);
  if (givenHash && givenHash.every((b) => b === 0)) givenHash = null;
  if (proofHash && givenHash && hex(proofHash) !== hex(givenHash)) fail('UAPqzPopHash', 'pqzPop does not hash to pqzPopHash');
  const h = proofHash ?? givenHash ?? Z32;
  if (hex(h) === EMPTY_PROOF_HASH) fail('UAPqzPopHash', 'the hash of an empty proof');
  return h;
}

// --- the portable records, typed (typed-signing TS-D1 … TS-D4; owner 2026-10-31 decisions 2, 4, 8) ---

/** The portable EIP-712 domain: name and version only, no chainId / verifyingContract / salt (the records register a UA
 *  on every chain, CTR-UA-07). */
export const PORTABLE_DOMAIN = Object.freeze({ name: 'SCaaS UA Portable', version: '1' });
const field = (name, type) => Object.freeze({ name, type });
/** The portable structs (EIP-712 `types`); `kind` is `uint16` (the name is looked up in the kind table), no string field. */
export const PORTABLE_TYPES = Object.freeze({
  EIP712Domain: Object.freeze([field('name', 'string'), field('version', 'string')]),
  UAKemRecord: Object.freeze([field('ua', 'bytes32'), field('version', 'uint64'), field('scheme', 'uint8'), field('kemPkHash', 'bytes32')]),
  UAPortableRecord: Object.freeze([field('ua', 'bytes32'), field('kind', 'uint16'), field('pqzKeyHash', 'bytes32'), field('kem', 'UAKemRecord')]),
  UARegistration: Object.freeze([field('record', 'UAPortableRecord'), field('pqzPopHash', 'bytes32')]),
  UAPqzKey: Object.freeze([field('ua', 'bytes32'), field('pqzKeyHash', 'bytes32')]),
  UAPqzKeyRecord: Object.freeze([field('key', 'UAPqzKey'), field('pqzPopHash', 'bytes32')]),
});
/** `keccak256(encodeType(T))` per struct (primary type, then the referenced types sorted by name). */
export const PORTABLE_TYPEHASH = Object.freeze(Object.fromEntries(Object.keys(PORTABLE_TYPES)
  .map((t) => [t, tagHash(encodeType(PORTABLE_TYPES, t))])));
const TH = PORTABLE_TYPEHASH;
const DS_P = keccak_256(concatBytes(TH.EIP712Domain, tagHash(PORTABLE_DOMAIN.name), tagHash(PORTABLE_DOMAIN.version)));
/** `DS_P = 0x9a2c…4ca1`: `hashStruct(EIP712Domain{name: "SCaaS UA Portable", version: "1"})`. */
export const portableDomainSeparator = () => DS_P.slice();
/** `keccak256(0x1901 ‖ DS_P ‖ structHash)`: what `eth_signTypedData_v4` returns for a portable record. */
const typed = (structHash) => keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), DS_P, structHash));
const h32 = (v, what) => hex(sized(v, 32, what));
const u16w = (kind) => {
  const k = Number(kind);
  if (!Number.isInteger(k) || k < 0 || k > 0xffff) throw new Error('kind must be a uint16');
  return k;
};
const num = (v) => (v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v.toString(10));

/** The KEM record's struct (`UAKemRecord` message): `{ ua, version, scheme: kemPk[0], kemPkHash: keccak256(kemPk) }` over
 *  the whole scheme-1 key (UA-8 P7, CTR-UA-32: version 1 … 2^64 − 1; empty `UAKemKeyLength`, a scheme not enabled
 *  `UAKemScheme`, another length `UAKemKeyLength`). No record (version 0 / absent and no key) is the zero record
 *  `{ ua, 0, 0, 0 }` (TS-D2: version 0 is never a valid record). */
export function kemRecordStruct({ ua, version = 0, kemPk }) {
  const u = h32(ua, 'ua');
  if (!present(kemPk) && Number(version ?? 0) === 0) return { ua: u, version: 0, scheme: 0, kemPkHash: hex(Z32) };
  let v;
  try { v = BigInt(version); } catch { fail('UAKemVersion', String(version)); }
  if (v < 1n || v >= 1n << 64n) fail('UAKemVersion', String(version));
  const pk = orEmpty(kemPk);
  if (pk.length === 0) fail('UAKemKeyLength', '0');
  const n = kemPkLength(pk[0]);
  if (n === 0) fail('UAKemScheme', String(pk[0]));
  if (pk.length !== n) fail('UAKemKeyLength', String(pk.length));
  return { ua: u, version: num(v), scheme: pk[0], kemPkHash: hex(keccak_256(pk)) };
}
const kemHash = (k) => keccak_256(concatBytes(TH.UAKemRecord, fromHex(k.ua), word(k.version), word(k.scheme), fromHex(k.kemPkHash)));
/** `hashStruct(UAKemRecord)`: the `kem` word of a `UAPortableRecord`; the zero record when there is none. */
export const kemRecordHash = (record) => kemHash(kemRecordStruct(record));
/** The typed `UAKemRecord` digest `setKemKey` signs (a real record: version 0 is `UAKemVersion`). */
export function kemRecordDigest({ ua, version, kemPk }) {
  if (Number(version ?? 0) === 0) fail('UAKemVersion', String(version));
  return typed(kemRecordHash({ ua, version, kemPk }));
}
/** What the UA signs for a KEM record: `uaMessage(kind, PURPOSE_KEM, kemRecordDigest(ua, version, kemPk))`; an `msig`'s
 *  derived members sign `memberDigest(ua, ·)` of it under `member`, a native member the typed digest itself. */
export const kemRecordMessage = (kind, record) => uaMessage(kind, KEM_TAG, kemRecordDigest(record));

/** The `UAPortableRecord` message: `{ ua, kind, pqzKeyHash, kem }`, `kem` a `kemRecordStruct`. */
export const portableRecordStruct = ({ ua, kind, pqzKeyHash = Z32, kem }) =>
  ({ ua: h32(ua, 'ua'), kind: u16w(kind), pqzKeyHash: h32(pqzKeyHash, 'pqzKeyHash'), kem });
const recordHash = ({ ua, kind, pqzKeyHash = Z32, kemRecordHash: kh }) => keccak_256(concatBytes(TH.UAPortableRecord,
  sized(ua, 32, 'ua'), word(u16w(kind)), sized(pqzKeyHash, 32, 'pqzKeyHash'), kh === undefined ? kemRecordHash({ ua }) : sized(kh, 32, 'kemRecordHash')));
/** The typed `UAPortableRecord` digest over its words (`kemRecordHash` = `hashStruct(UAKemRecord)`, default the zero record):
 *  what R_REG proves over at `register` / the first `storePqzPop`. */
export const portableRecordDigest = (words) => typed(recordHash(words));
/** The typed `UARegistration{record, pqzPopHash}` digest: what the signer's `pop` signs under `uaMessage(kind, POP_V2, ·)`. */
export const registrationDigest = ({ pqzPopHash = Z32, ...words }) =>
  typed(keccak_256(concatBytes(TH.UARegistration, recordHash(words), sized(pqzPopHash, 32, 'pqzPopHash'))));
const pqzKeyHash_ = ({ ua, pqzKeyHash }) => keccak_256(concatBytes(TH.UAPqzKey, sized(ua, 32, 'ua'), sized(pqzKeyHash, 32, 'pqzKeyHash')));
/** The typed `UAPqzKey{ua, pqzKeyHash}` digest: what a later PQZ key's R_REG proves over (no proof hash: no cycle). */
export const pqzKeyDigest = (key) => typed(pqzKeyHash_(key));
/** The typed `UAPqzKeyRecord{UAPqzKey{ua, pqzKeyHash}, pqzPopHash}` digest: what `setPqzKey`'s signature signs. */
export const pqzKeyRecordDigest = ({ ua, pqzKeyHash, pqzPopHash }) =>
  typed(keccak_256(concatBytes(TH.UAPqzKeyRecord, pqzKeyHash_({ ua, pqzKeyHash }), sized(pqzPopHash, 32, 'pqzPopHash'))));

/** The exact JSON a wallet signs with `eth_signTypedData_v4` for a portable record: `{ domain: { name, version }, types:
 *  { EIP712Domain, <primaryType>, <referenced types> }, primaryType, message }`; its `hashTypedData` is the record's digest. */
export function portableTypedData(primaryType, message) {
  if (primaryType === 'EIP712Domain' || !PORTABLE_TYPES[primaryType]) throw new Error(`not a portable struct: ${primaryType}`);
  const types = { EIP712Domain: PORTABLE_TYPES.EIP712Domain.map((f) => ({ ...f })) };
  const walk = (t) => {
    types[t] = PORTABLE_TYPES[t].map((f) => ({ ...f }));
    for (const f of PORTABLE_TYPES[t]) if (PORTABLE_TYPES[f.type] && !types[f.type]) walk(f.type);
  };
  walk(primaryType);
  return { domain: { ...PORTABLE_DOMAIN }, types, primaryType, message };
}

/** A PQZ / KEM holder (UA-6 U3, UA-8 P7): mldsa44, mldsa65, fndsa512, or an `msig` whose `keyData` is PQ-eligible. */
const holds = (kind, keyData) => isPqzHolder(kind) || (kind === 0x0120 && present(keyData) && msigPqzEligible(keyData));

/**
 * The portable PoP of a registration (UA-8 P1, P2; typed-signing TS-D3): `{ pqzKeyHash, pqzPopHash, kemRecordHash,
 * portableRecordDigest, registrationDigest, message, typedData }`, `typedData` the `UARegistration{UAPortableRecord{ua, kind,
 * pqzKeyHash, kem}, pqzPopHash}` JSON (`eth_signTypedData_v4`), `registrationDigest = hashTypedData(typedData)`, `message =
 * uaMessage(kind, POP_V2, registrationDigest)` (every kind signs it; an `msig` also returns `memberDigest = memberDigest(ua,
 * message)`, what each derived member signs under `member`; a native member signs `registrationDigest` itself, TS-D4). The
 * attributes: `pqzKey` with its proof `pqzPop` (or only its hash `pqzPopHash`), and the initial KEM record (`kemVersion` ≥ 1,
 * `kemPk`); absent = omitted / empty / 0. Only holders may carry them (`UAPqzHolder`, `UAKemHolder`; an `msig` needs
 * `keyData` to show it is PQ-eligible); a PQZ key always comes with its proof hash and only with it (`UAPqzPopHash`).
 */
export function holderPopMessage(kind, { ua, keyData, pqzKey, pqzPop, pqzPopHash, kemVersion = 0, kemPk } = {}) {
  const hasPqz = present(pqzKey);
  const hasKem = Number(kemVersion) !== 0 || present(kemPk);
  const k = `0x${Number(kind).toString(16).padStart(4, '0')}`;
  if (hasPqz && !holds(kind, keyData)) fail('UAPqzHolder', `${k} may not hold a PQZ key`);
  if (hasKem && !holds(kind, keyData)) fail('UAKemHolder', `${k} may not hold a KEM key`);
  const popHash = proofHashOf(pqzPop, pqzPopHash);
  if (hasPqz !== (popHash !== Z32)) fail('UAPqzPopHash', hasPqz ? 'a PQZ key needs its proof hash' : 'a proof hash without a PQZ key');
  const pqzKeyHash = hasPqz ? pqzKeyHashOf(pqzKey) : Z32;
  const kem = kemRecordStruct({ ua, version: kemVersion, kemPk });
  const kh = kemHash(kem);
  const words = { ua, kind, pqzKeyHash, kemRecordHash: kh };
  const registration = registrationDigest({ ...words, pqzPopHash: popHash });
  const message = uaMessage(kind, POP_V2_TAG, registration);
  const typedData = portableTypedData('UARegistration',
    { record: portableRecordStruct({ ua, kind, pqzKeyHash, kem }), pqzPopHash: hex(popHash) });
  return { pqzKeyHash, pqzPopHash: popHash, kemRecordHash: kh, portableRecordDigest: portableRecordDigest(words),
    registrationDigest: registration, message, typedData, ...(kind === 0x0120 ? { memberDigest: memberDigest(ua, message) } : {}) };
}

/** The message `R_REG` proves over: `uaMessage(0x0142, POP_V2, portableRecordDigest(ua, kind, keyHash(0x0142, pqzKey),
 *  kemRecordHash))`, `kind` the registering kind (the record of the registration, TS-D3). */
export function pqzRegMessage({ ua, kind, pqzKey, kemVersion = 0, kemPk }) {
  if (kind === undefined || kind === null) throw new Error('pqzRegMessage needs the registering kind');
  return uaMessage(0x0142, POP_V2_TAG, portableRecordDigest({ ua, kind, pqzKeyHash: pqzKeyHashOf(pqzKey),
    kemRecordHash: kemRecordHash({ ua, version: kemVersion, kemPk }) }));
}

/**
 * The PQZ key record of `setPqzKey(ua, pqzKey, pqzPopHash, sig)` (ruling A1-I1): signed, portable, write-once, accepted only
 * by a registration without a PQZ key (a PQZ key is set once per chain; a client gives a UA one PQZ key, ever).
 * `{ pqzKeyHash, pqzPopHash, pqzKeyDigest, recordDigest, message, pqzRegMessage, typedData }` (+ `memberDigest` for an msig),
 * `recordDigest` = the typed `UAPqzKeyRecord` digest = `hashTypedData(typedData)`, `message = uaMessage(kind, PURPOSE_PQZ_KEY,
 * recordDigest)`, `pqzRegMessage = uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest)` (the typed `UAPqzKey`). The holder rules
 * of `holderPopMessage` (`UAPqzHolder`); the key and its proof hash are both required.
 */
export function pqzKeyRecordMessage(kind, { ua, keyData, pqzKey, pqzPop, pqzPopHash } = {}) {
  if (!holds(kind, keyData)) fail('UAPqzHolder', `0x${Number(kind).toString(16).padStart(4, '0')} may not hold a PQZ key`);
  const pqzKeyHash = pqzKeyHashOf(pqzKey);
  const popHash = proofHashOf(pqzPop, pqzPopHash);
  if (popHash === Z32) fail('UAPqzPopHash', 'a PQZ key needs its proof hash');
  const keyDigest = pqzKeyDigest({ ua, pqzKeyHash });
  const recordDigest = pqzKeyRecordDigest({ ua, pqzKeyHash, pqzPopHash: popHash });
  const message = uaMessage(kind, PQZ_KEY_TAG, recordDigest);
  const typedData = portableTypedData('UAPqzKeyRecord', { key: { ua: h32(ua, 'ua'), pqzKeyHash: hex(pqzKeyHash) }, pqzPopHash: hex(popHash) });
  return { pqzKeyHash, pqzPopHash: popHash, pqzKeyDigest: keyDigest, recordDigest, message,
    pqzRegMessage: uaMessage(0x0142, PQZ_KEY_TAG, keyDigest), typedData, ...(kind === 0x0120 ? { memberDigest: memberDigest(ua, message) } : {}) };
}

/** The portable purposes (POP_V2, KEM, PQZ_KEY): the only ones where a code-less native msig member signs the record's typed
 *  digest itself (`eth_signTypedData_v4`, 65-byte r ‖ s ‖ v, low-s, v 27 / 28; a contract member answers ERC-1271
 *  `isValidSignature(typedDigest, sig)`; TS-D4); every other purpose stays UAAuth (CTR-MTX-14). */
export const isPortablePurpose = (tag) => [POP_V2_TAG, KEM_TAG, PQZ_KEY_TAG].some((t) => hex(t) === hex(sized(tag, 32, 'purposeTag')));

export function uaAuthDomainSeparator({ generation, chainId, registry, chainUid }) {
  if (!Number.isInteger(generation) || generation < 1) throw new Error('generation must be a positive integer');
  return keccak_256(concatBytes(DOMAIN_TYPEHASH, NAME_HASH, tagHash(String(generation)), word(chainId), addressWord(registry),
    sized(chainUid, 32, 'chainUid')));
}

/** EIP-712 digest of `UAAuth(ua, purpose, digest)` under the registry's domain: what native signers sign. */
export function uaAuthDigest(domain, ua, purpose, digest) {
  const s = keccak_256(concatBytes(UAAUTH_TYPEHASH, sized(ua, 32, 'ua'), sized(purpose, 32, 'purposeTag'), sized(digest, 32, 'digest')));
  return keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), uaAuthDomainSeparator(domain), s));
}

export const memberDigest = (structureUa, uaMsg) =>
  keccak_256(concatBytes(sized(structureUa, 32, 'structureUa'), sized(uaMsg, 32, 'uaMsg')));

/** Lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id (CTR-UA-03). */
export function canonicalId(text) {
  const m = /^0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.exec(String(text));
  if (!m) fail('UAIdFormat', String(text));
  const h = m[1].toLowerCase();
  return h.length === 64 && h.startsWith('0'.repeat(24)) ? `0x${h.slice(24)}` : `0x${h}`;
}

export function encodeMsig(threshold, members) {
  const out = new Uint8Array(4 + 36 * members.length);
  const put16 = (o, v) => { out[o] = (v >> 8) & 0xff; out[o + 1] = v & 0xff; };
  put16(0, threshold);
  put16(2, members.length);
  members.forEach(({ kind, id, weight }, i) => {
    const o = 4 + 36 * i;
    put16(o, kind);
    out.set(sized(id, 32, 'member id'), o + 2);
    put16(o + 34, weight);
  });
  return out;
}

// --- key-data validation (§1.6 "Validation at registration") ---

const SECP_P = secp256k1.Point.Fp.ORDER;
const SECP_N = secp256k1.Point.Fn.ORDER;
const P256_P = p256.Point.Fp.ORDER;
const ED_P = 2n ** 255n - 19n;
const BN_P = bn254.fields.Fp.ORDER;
const BN_R = bn254.fields.Fr.ORDER;
const BLS_P = bls12_381.fields.Fp.ORDER;

/** Runs a noble constructor / validity check; any throw is "not a valid point". */
const point = (f) => {
  try {
    return f();
  } catch {
    return fail('UAKeyData', 'curve');
  }
};

function secpCompressed(b) {
  need(b[0] === 2 || b[0] === 3, 'prefix');
  need(be(b.subarray(1, 33)) < SECP_P, 'range');
  point(() => secp256k1.Point.fromBytes(b));
}

function secpPoint(xy) {
  need(be(xy.subarray(0, 32)) < SECP_P && be(xy.subarray(32, 64)) < SECP_P, 'range');
  point(() => secp256k1.Point.fromBytes(concatBytes(Uint8Array.of(4), xy)));
}

function p256Point(xy) {
  need(be(xy.subarray(0, 32)) < P256_P && be(xy.subarray(32, 64)) < P256_P, 'range');
  point(() => p256.Point.fromBytes(concatBytes(Uint8Array.of(4), xy)));
}

function ed25519Key(b) {
  need((be(Uint8Array.from(b).reverse()) & ((1n << 255n) - 1n)) < ED_P, 'range');
  const P = point(() => ed25519.Point.fromBytes(b, false));
  need(!(P.toAffine().x === 0n && (b[31] & 0x80)), 'sign');
  need(!P.isSmallOrder(), 'small-order');
}

function bnG1(b) {
  const x = be(b.subarray(0, 32));
  const y = be(b.subarray(32, 64));
  need(x < BN_P && y < BN_P, 'range');
  need(x !== 0n || y !== 0n, 'identity');
  point(() => bn254.G1.Point.fromAffine({ x, y }).assertValidity());
}

function bnG2(b) {
  const [xi, xr, yi, yr] = [0, 1, 2, 3].map((i) => be(b.subarray(32 * i, 32 * i + 32)));
  need([xi, xr, yi, yr].every((v) => v < BN_P), 'range');
  need([xi, xr, yi, yr].some((v) => v !== 0n), 'identity');
  // noble's assertValidity checks the twist equation and the prime-order subgroup
  point(() => bn254.G2.Point.fromAffine({ x: { c0: xr, c1: xi }, y: { c0: yr, c1: yi } }).assertValidity());
}

function blsFp(b) {
  need(b.subarray(0, 16).every((v) => v === 0), 'padding');
  const v = be(b.subarray(16, 64));
  need(v < BLS_P, 'range');
  return v;
}

function blsG1(b) {
  const x = blsFp(b.subarray(0, 64));
  const y = blsFp(b.subarray(64, 128));
  need(x !== 0n || y !== 0n, 'identity');
  point(() => bls12_381.G1.Point.fromAffine({ x, y }).assertValidity());
}

function blsG2(b) {
  const [x0, x1, y0, y1] = [0, 1, 2, 3].map((i) => blsFp(b.subarray(64 * i, 64 * i + 64)));
  need([x0, x1, y0, y1].some((v) => v !== 0n), 'identity');
  point(() => bls12_381.G2.Point.fromAffine({ x: { c0: x0, c1: x1 }, y: { c0: y0, c1: y1 } }).assertValidity());
}

/** `Q ‖ u16 n ‖ n × P_i`, 2 ≤ n ≤ 16, P_i strictly increasing. */
function musig2(d, check, size) {
  need(d.length >= size + 2, 'length');
  const n = u16(d, size);
  need(n >= 2 && n <= 16, 'n');
  need(d.length === size + 2 + n * size, 'length');
  check(d.subarray(0, size));
  for (let i = 0; i < n; i++) {
    const o = size + 2 + i * size;
    check(d.subarray(o, o + size));
    if (i > 0) need(less(d.subarray(o - size, o), d.subarray(o, o + size)), 'order');
  }
}

/** `Y ‖ u16 t ‖ u16 n ‖ n × (t × C_ik ‖ R_i ‖ μ_i)`, 2 ≤ t ≤ n ≤ 16, μ_i < order. */
function frost(d, check, size, order) {
  need(d.length >= size + 4, 'length');
  const t = u16(d, size);
  const n = u16(d, size + 2);
  need(t >= 2 && t <= n && n <= 16, 'threshold');
  const per = (t + 1) * size + 32;
  need(d.length === size + 4 + n * per, 'length');
  check(d.subarray(0, size));
  for (let i = 0; i < n; i++) {
    const o = size + 4 + i * per;
    for (let j = 0; j <= t; j++) check(d.subarray(o + j * size, o + (j + 1) * size)); // t commitments, then R_i
    need(be(d.subarray(o + (t + 1) * size, o + per)) < order, 'scalar');
  }
}

/** `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)` (CTR-UA-09; ruling U5). */
function msig(d, hederaNative) {
  need(d.length >= 4, 'length');
  const threshold = u16(d, 0);
  const count = u16(d, 2);
  need(count >= 1 && count <= 16, 'count');
  need(d.length === 4 + 36 * count, 'length');
  let total = 0;
  for (let i = 0; i < count; i++) {
    const o = 4 + 36 * i;
    const kind = u16(d, o);
    const id = d.subarray(o + 2, o + 34);
    const weight = u16(d, o + 34);
    need(isMemberKind(kind, hederaNative), 'member-kind');
    need(weight >= 1, 'weight');
    need(isNativeKind(kind) === id.subarray(0, 12).every((b) => b === 0), 'member-id');
    if (i > 0) need(less(d.subarray(o - 34, o - 2), id), 'order');
    total += weight;
  }
  need(threshold >= 1 && threshold <= total, 'threshold');
}

/** `0x09 ‖ 512 × 14-bit h_i`, big-endian bit packing, each h_i < q = 12289. */
function fndsa(d) {
  need(d[0] === 0x09, 'header');
  for (let i = 0; i < 512; i++) {
    let v = 0;
    for (let j = 0; j < 14; j++) {
      const k = i * 14 + j;
      v = (v << 1) | ((d[1 + (k >> 3)] >> (7 - (k & 7))) & 1);
    }
    need(v < 12289, 'coefficient');
  }
}

/** Throws `UAError('UAKeyData')` unless `keyData` is the unique canonical encoding of a valid key or structure. */
export function validateKeyData(kind, keyData, { hederaNative = false } = {}) {
  const k = derived(kind);
  const d = bytes(keyData);
  if (k.lengths.length) need(k.lengths.includes(d.length), 'length');
  switch (kind) {
    case 0x0100: return p256Point(d.subarray(0, 64));
    case 0x0101: return p256Point(d);
    case 0x0102: return ed25519Key(d);
    case 0x0103: return secpCompressed(concatBytes(Uint8Array.of(2), d));
    case 0x0104: return bnG1(d);
    case 0x0105: case 0x0141: return blsG1(d);
    case 0x0106: return blsG2(d);
    case 0x0107: return bnG2(d);
    case 0x0108: return secpPoint(d);
    case 0x0110: return musig2(d, secpCompressed, 33);
    case 0x0111: return frost(d, secpCompressed, 33, SECP_N);
    case 0x0112: return musig2(d, bnG1, 64);
    case 0x0113: return frost(d, bnG1, 64, BN_R);
    case 0x0120: return msig(d, hederaNative);
    case 0x0132: return fndsa(d);
    default: return undefined; // mldsa44/65, slhdsa128s: the length is the whole check (U7)
  }
}
