// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The PQZ three-key model on the client (spec 2026-11-13 pqz-three-keys; CLI-SGN-50, CLI-SGN-51, CTR-PQZ-38, CTR-PQZ-40):
// the key seeds of the classes `offchain-shared` and `offchain-token` (K3-2), the opening KEM key (K3-6b), the leg seed
// (K3-4), the opening coins and the sealed opening (K3-6), the `memoHash` that covers the openings. The holder check of K3-7
// re-encrypts from the leg seed with PQZ arithmetic this file does not carry: pqz-ffi runs it, natively or in the wallet
// module (src/pqzopenWasm.js, TODO 3zf); here the opening is sealed and opened, every failure the one outcome `null`. UNAUDITED.
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256, shake256 } from '@noble/hashes/sha3.js';
import { gcm } from '@noble/ciphers/aes.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { concatBytes, utf8ToBytes, fromHex } from './bytes.js';
import { encaps, combine, checkKemPk, kemKey } from './pqchat.js';
import { pqzOwnTag } from './evm.js';
import { uaMessage, portableDomainSeparator } from './ua.js';
import { isPqzWallet, pqzUnpack } from './pqzopenWasm.js';

// review 3w-delta U4h-3: a malformed value is refused, never changed (an odd nibble, a non-hex pair, an out-of-range integer).
const asBytes = (x, n, what) => {
  let b = x;
  if (typeof x === 'string') {
    try { b = fromHex(x); } catch { throw new Error(`${what}: not hex`); }
  }
  if (!(b instanceof Uint8Array) || (n !== undefined && b.length !== n)) throw new Error(`${what}: ${n ?? 'some'} bytes`);
  return b;
};
const u32 = (x, what) => {
  if (!Number.isInteger(x) || x < 0 || x > 0xffffffff) throw new Error(`${what} must be an integer in [0, 2^32)`);
  const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, x); return b;
};
const be64 = (v) => {
  const x = BigInt(v);
  if (x < 0n || x >= 1n << 64n) throw new Error('version must be a uint64');
  const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, x); return b;
};

/** K3-2: the PQZ key seed of class `offchain-shared` (`token` omitted) or `offchain-token` (`token` the token's address), 32 B:
 *  `HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info)`, `info` = `"scaas.ua.pqz-mlwe.offchain-shared.v1" ‖ u32 account ‖
 *  u32 index ‖ chainUid ‖ be64 v` or `"scaas.ua.pqz-mlwe.offchain-token.v1" ‖ … ‖ chainUid ‖ token ‖ be64 v` (the version always).
 *  Class `registry` stays `pqzKeySeed` (src/pq.js), byte for byte. An `msig` operator draws each class and version fresh. Module
 *  private (Fable P1-1 on CLI-SGN-51): a seed of a scope with the opening lives in a `pqzKeyHandle` only. */
function scopedKeySeed(seed, { account, index, chainUid, token, version }) {
  asBytes(seed, 64, 'seed');
  const label = token === undefined ? 'scaas.ua.pqz-mlwe.offchain-shared.v1' : 'scaas.ua.pqz-mlwe.offchain-token.v1';
  const info = concatBytes(utf8ToBytes(label), u32(account, 'account'), u32(index, 'index'), asBytes(chainUid, 32, 'chainUid'),
    token === undefined ? new Uint8Array(0) : asBytes(token, 20, 'token'), be64(version));
  return hkdf(sha256, seed, utf8ToBytes('scaas.ua.pq.v1'), info, 32);
}

/** K3-2, class `offchain-token` of a token WITHOUT the opening only: the accepted exposure of CTR-PQZ-37 (owner 2026-11-13: the
 *  wallet decrypts that token's credits as on `PRECOMPILE`). A token with the opening, and every `offchain-shared` key, go
 *  through `pqzKeyHandle`. */
export function pqzTokenKeySeedWithoutOpening(seed, { account, index, chainUid, token, version }) {
  return scopedKeySeed(seed, { account, index, chainUid, token: asBytes(token, 20, 'token'), version });
}

/** K3-6b: the opening KEM seed of a scoped record, 96 B: `HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.kem.v1", info, L = 96)`,
 *  `info` = `"scaas.kem.pqz-opening.1" ‖ ua ‖ chainUid ‖ be64 v` (offchain-shared) or `"scaas.kem.pqz-opening-token.1" ‖ ua ‖
 *  chainUid ‖ token ‖ be64 v` (offchain-token with the opening). Never given to chat code. */
export function openKemSeed(seed, { ua, chainUid, token, version }) {
  asBytes(seed, 64, 'seed');
  const label = token === undefined ? 'scaas.kem.pqz-opening.1' : 'scaas.kem.pqz-opening-token.1';
  const info = concatBytes(utf8ToBytes(label), asBytes(ua, 32, 'ua'), asBytes(chainUid, 32, 'chainUid'),
    token === undefined ? new Uint8Array(0) : asBytes(token, 20, 'token'), be64(version));
  return hkdf(sha256, seed, utf8ToBytes('scaas.ua.kem.v1'), info, 96);
}

/** The opening KEM key of a seed: `(ek, dk) = ML-KEM-1024.KeyGen_internal(d = s[0:32], z = s[32:64])`, `sk_X = s[64:96]`,
 *  `kemPk = 0x01 ‖ ek ‖ X25519(sk_X, 9)` (1,601 B, the scoped record's `openKem`). */
export function openKemKey(okSeed) {
  const s = asBytes(okSeed, 96, 'openKemSeed');
  const k = kemKey(s.subarray(0, 64), s.subarray(64));
  return { kemPk: k.kemPk, dk: k.dk, x25519Secret: s.slice(64) };
}

/** K3-4: `seed_leg = SHAKE256("SCAAS-PQZ-ENC-LEG-V1" ‖ seed_enc ‖ be4(0) ‖ toUA ‖ keccak256(pk_t))[0..32)`. */
export function legSeed(seedEnc, toUA, pkT) {
  return legSeedOfKeyHash(seedEnc, toUA, keccak_256(asBytes(pkT, undefined, 'pk_t')));
}

/** `legSeed` with `keccak256(pk_t)` given (the vectors carry the hash, a wallet the key). */
export function legSeedOfKeyHash(seedEnc, toUA, pkTHash) {
  return shake256(concatBytes(utf8ToBytes('SCAAS-PQZ-ENC-LEG-V1'), asBytes(seedEnc, 32, 'seed_enc'), u32(0, 'leg'),
    asBytes(toUA, 32, 'toUA'), asBytes(pkTHash, 32, 'keccak256(pk_t)')), { dkLen: 32 });
}

/** K3-6: `coins = SHAKE256("SCAAS-PQZ-OPEN-COINS-V1" ‖ seed_leg ‖ u8(role) ‖ keccak256(kemPk))[0..64)`, role 0 the recipient, 1
 *  the auditor. */
export function openingCoins(seedLeg, role, kemPk) {
  if (role !== 0 && role !== 1) throw new Error('role: 0 recipient, 1 auditor');
  return shake256(concatBytes(utf8ToBytes('SCAAS-PQZ-OPEN-COINS-V1'), asBytes(seedLeg, 32, 'seed_leg'), Uint8Array.of(role),
    keccak_256(asBytes(kemPk, 1601, 'kemPk'))), { dkLen: 64 });
}

const kek = (ss) => hkdf(sha256, ss, new Uint8Array(0), utf8ToBytes('PQZ/opening/kek/v1'), 32);
const NONCE = new Uint8Array(12);

/** K3-6: the sealed opening of `seed_leg` to a reader's `kemPk`, deterministic: `(mlkemCt, E, ss) = encaps(kemPk, m = coins[0..32),
 *  e = coins[32..64))`, `sealedSeed = AES-256-GCM(HKDF(ss, ∅, "PQZ/opening/kek/v1"), 0^96, seed_leg, aad)`. `aad` is the caller's:
 *  `chainUid ‖ token(20) ‖ ua ‖ be8(keyVersion) ‖ keccak256(…)` of the reader's leg as CTR-PQZ-40 states it. Returns the
 *  `PqzOpening` fields and its stored form `mlkemCt ‖ x25519Eph ‖ sealedSeed` (1,648 B). */
export function sealOpening({ seedLeg, role, kemPk, aad }) {
  const c = openingCoins(seedLeg, role, kemPk);
  const enc = encaps(kemPk, c.subarray(0, 32), c.subarray(32));
  const sealedSeed = gcm(kek(enc.ss), NONCE, asBytes(aad, undefined, 'aad')).encrypt(asBytes(seedLeg, 32, 'seed_leg'));
  return { mlkemCt: enc.ctM, x25519Eph: enc.E, sealedSeed, bytes: concatBytes(enc.ctM, enc.E, sealedSeed) };
}

/** The reader's side: decapsulates with its opening KEM secret and opens `seed_leg`; `null` for every failure (a wrong length,
 *  a low-order X25519 point, a tag that fails), one outcome, no detail (CLI-SGN-51). ML-KEM's implicit rejection gives a wrong
 *  `ss`, hence the same `null`. */
export function openOpening({ opening, kemPk, dk, x25519Secret, aad }) {
  try {
    const o = asBytes(opening, 1648, 'opening');
    const { pkX } = checkKemPk(kemPk);
    const ssM = ml_kem1024.decapsulate(o.subarray(0, 1568), asBytes(dk, undefined, 'dk'));
    const E = o.subarray(1568, 1600);
    const ssX = x25519.getSharedSecret(asBytes(x25519Secret, 32, 'x25519Secret'), E);
    if (ssX.every((b) => b === 0)) return null;
    return gcm(kek(combine(ssM, ssX, E, pkX)), NONCE, asBytes(aad, undefined, 'aad')).decrypt(o.subarray(1600));
  } catch {
    return null;
  }
}

/** CTR-PQZ-40 / CTR-PQZ-34's Change: an opening token's op 1 `memoHash = keccak256(memo ‖ ownTag ‖ keccak256(O_t ‖ [O_a]))`,
 *  `O` the stored form of each opening (recipient first). */
export function pqzOpeningMemoHash(memo, ownTag, openings) {
  const os = concatBytes(...openings.map((o) => asBytes(o, 1648, 'opening')));
  return keccak_256(concatBytes(asBytes(memo ?? '0x', undefined, 'memo'), asBytes(ownTag, 32, 'ownTag'), keccak_256(os)));
}

// ------------------------------------------------------------------ entries, the opening blob, scoped records (Fable P2-1, P2-2)

/** CTR-PQZ-41: the skip mark, bit 63 of a pending slot's `block` field. */
export const SKIP = 1n << 63n;
/** One stored opening `mlkemCt(1568) ‖ x25519Eph(32) ‖ sealedSeed(48)`. */
export const OPENING = 1648;
const slotOf = (slot) => (typeof slot === 'bigint' ? slot : BigInt(hexOf(asBytes(slot, 32, 'slot'))));
const hexOf = (b) => '0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const w256 = (v) => {
  let x = BigInt(v);
  if (x < 0n || x >= 1n << 256n) throw new Error('a uint256 word is in [0, 2^256)');
  const o = new Uint8Array(32); for (let i = 31; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; };
/** The pending slot `blob(160) ‖ offset(16) ‖ length(16) ‖ block(64)` (a bigint, or 32 bytes / hex) is skip-marked. */
export const pqzSlotMarked = (slot) => (slotOf(slot) & SKIP) !== 0n;
/** … is a TRIVIAL entry (length 0, no blob). */
export const pqzSlotTrivial = (slot) => ((slotOf(slot) >> 64n) & 0xffffn) === 0n;

/** CTR-PQZ-41 `h(i) = keccak256(abi.encode(i, slot with the mark cleared, keccak256(code) or 0 for a TRIVIAL entry))`, `code` the
 *  blob's code (`STOP ‖ data`) as the wallet read and checked it: the wallet hashes the bytes itself, never a node's code-hash
 *  answer (Fable P2-1). */
export function pqzEntryHash(index, slot, code) {
  const e = slotOf(slot);
  const c = pqzSlotTrivial(e) ? new Uint8Array(32) : keccak_256(asBytes(code, undefined, 'code'));
  return keccak_256(concatBytes(w256(index), w256(e & ~SKIP), c));
}
/** `entriesHash = keccak256(h(rolled) ‖ … ‖ h(rolled + n − 1) ‖ h(skip_0) ‖ …)`. */
export const pqzEntriesHash = (hs) => keccak_256(concatBytes(...hs.map((h) => asBytes(h, 32, 'h(i)'))));

/** A set's packed sizes (P46): `P(u)` = `n · b / 8` bytes, `P(v)` = `16 · b / 8`, `b` = `PACK_BITS`. */
export const pqzLayout = (n, packBits) => Object.freeze({ pkp: (n * packBits) / 8, vp: (16 * packBits) / 8 });

/** CTR-PQZ-40: an opening token's op 1 blob `salt(16) ‖ P(u) ‖ P(v_t) ‖ [P(v_a)] ‖ toUA ‖ P(u_f) ‖ P(v_f) ‖ O_t ‖ [O_a] ‖ ownTag ‖
 *  be64 kv[0..n) ‖ u8(n)` from its code (`STOP ‖ data`); `n` 1 or 2, `kv[0]` the recipient's key version, `kv[1]` the auditor's.
 *  Fields are subarrays; `at` their offsets in the data. Anything else is refused. */
export function pqzOpeningBlobOf(code, { pkp, vp }) {
  const c = asBytes(code, undefined, 'code');
  if (c[0] !== 0) refuse('the blob code starts with STOP');
  const d = c.subarray(1);
  const n = d.length ? d[d.length - 1] : 0;
  if ((n !== 1 && n !== 2) || d.length !== 16 + 2 * pkp + (n + 1) * vp + 32 + n * OPENING + 33 + 8 * n) {
    refuse('not an opening op 1 blob of this set');
  }
  let p = 0;
  const at = {};
  const take = (k, name) => { at[name] = p; const x = d.subarray(p, p + k); p += k; return x; };
  const f = { salt: take(16, 'salt'), pu: take(pkp, 'pu'), pvt: take(vp, 'pvt') };
  f.pva = n === 2 ? take(vp, 'pva') : null;
  Object.assign(f, { toUA: take(32, 'toUA'), puf: take(pkp, 'puf'), pvf: take(vp, 'pvf'), oT: take(OPENING, 'oT') });
  f.oA = n === 2 ? take(OPENING, 'oA') : null;
  f.ownTag = take(32, 'ownTag');
  const kvAt = take(8 * n, 'kv');
  f.kv = Array.from({ length: n }, (_, i) => new DataView(kvAt.buffer, kvAt.byteOffset + 8 * i, 8).getBigUint64(0));
  return { ...f, n, at };
}

/** CTR-PQZ-40: the sealed seed's `aad = chainUid ‖ token(20) ‖ ua ‖ be8(keyVersion) ‖ keccak256(P(u) ‖ P(v))`. */
export function pqzOpeningAad({ chainUid, token, ua, keyVersion, pu, pv }) {
  return concatBytes(asBytes(chainUid, 32, 'chainUid'), asBytes(token, 20, 'token'), asBytes(ua, 32, 'ua'), be64(keyVersion),
    keccak_256(concatBytes(asBytes(pu, undefined, 'P(u)'), asBytes(pv, undefined, 'P(v)'))));
}

/** K3-3 (CTR-UA-43): `keccak256("scaas.ua.purpose.pqz-scoped-key.v1")`. */
export const PURPOSE_PQZ_SCOPED_KEY = keccak_256(utf8ToBytes('scaas.ua.purpose.pqz-scoped-key.v1'));
const SCOPED_KEY_TYPE = 'UAPqzScopedKey(bytes32 ua,uint8 keyClass,bytes32 chainUid,address token,uint64 version,bytes32 pqzKeyHash)';
const SCOPED_KEY_RECORD_TYPE = 'UAPqzScopedKeyRecord(bytes32 ua,uint8 keyClass,bytes32 chainUid,address token,uint64 version,'
  + 'bytes32 pqzKeyHash,bytes32 pqzPopHash,bytes32 openKemHash,uint64 validUntilBlock)';
const portable = (structHash) => keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), portableDomainSeparator(), structHash));
const addrW = (a) => concatBytes(new Uint8Array(12), asBytes(a, 20, 'token'));
/** typed(`UAPqzScopedKey`): what a scoped key's `R_REG` proves over, as `uaMessage(0x0142, PURPOSE_PQZ_SCOPED_KEY, ·)`;
 *  `keyClass` 2 (`token` the zero address) or 3. */
export function pqzScopedKeyDigest({ ua, keyClass, chainUid, token, version, pqzKeyHash }) {
  return portable(keccak_256(concatBytes(keccak_256(utf8ToBytes(SCOPED_KEY_TYPE)), asBytes(ua, 32, 'ua'), w256(keyClass),
    asBytes(chainUid, 32, 'chainUid'), addrW(token), w256(version), asBytes(pqzKeyHash, 32, 'pqzKeyHash'))));
}
/** typed(`UAPqzScopedKeyRecord`): what `setPqzScopedKey`'s `sig` signs, as `uaMessage(kind, PURPOSE_PQZ_SCOPED_KEY, ·)`;
 *  `openKemHash = keccak256(kemPk)` of the opening KEM key, 0 without one. */
export function pqzScopedKeyRecordDigest({ ua, keyClass, chainUid, token, version, pqzKeyHash, pqzPopHash, openKemHash, validUntilBlock }) {
  return portable(keccak_256(concatBytes(keccak_256(utf8ToBytes(SCOPED_KEY_RECORD_TYPE)), asBytes(ua, 32, 'ua'), w256(keyClass),
    asBytes(chainUid, 32, 'chainUid'), addrW(token), w256(version), asBytes(pqzKeyHash, 32, 'pqzKeyHash'),
    asBytes(pqzPopHash, 32, 'pqzPopHash'), asBytes(openKemHash, 32, 'openKemHash'), w256(validUntilBlock))));
}
/** The two messages of a scoped record: `message = uaMessage(kind, PURPOSE_PQZ_SCOPED_KEY, recordDigest)` (what the UA signs) and
 *  `regMessage = uaMessage(0x0142, PURPOSE_PQZ_SCOPED_KEY, keyDigest)` (what the key's `R_REG` proves over). */
export function pqzScopedKeyMessages(kind, r) {
  const keyDigest = pqzScopedKeyDigest(r);
  const recordDigest = pqzScopedKeyRecordDigest(r);
  return { keyDigest, recordDigest, message: uaMessage(kind, PURPOSE_PQZ_SCOPED_KEY, recordDigest),
    regMessage: uaMessage(0x0142, PURPOSE_PQZ_SCOPED_KEY, keyDigest) };
}

// ------------------------------------------------------------------ the key handle (owner 2026-11-14; Fable P1-1)

const refuse = (why) => { throw new Error(`Refusing: ${why}.`); };
const ZERO20 = new Uint8Array(20);
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const ACCEPTED = new WeakMap(); // acceptance object -> { handle, index, content }: only a handle's check makes one

/** Owner ruling 2026-11-14 (CLI-SGN-51's Change: "no bare class-2 decrypt", enforced in the clients; spec §6, §14.1, §14.18;
 *  Fable P1-1): the wallet's handle of one PQZ key with the opening, `offchain-shared` (`token` omitted) or `offchain-token` of
 *  a token with the opening, at one key version. It derives and holds that key's PQZ seed and its opening KEM secret; no member
 *  returns either. The PQZ seed reaches a function only through three gated entries, each counted: `withSecretOwn(own, f)`
 *  after the holder's own `ownTag` verifies, `withSecretWindow(entries, f)` when every entry is skip-marked, TRIVIAL or accepted
 *  by this handle with the same bytes, and `withSecretKeygen(f)` (the public key and the `R_REG` proof of registration).
 *  `check(credit, verify)` runs K3-7 steps 2-4, 8 and the auditor's opening of step 9 here (the blob read, `aad`s built from the
 *  blob's own bytes, open `O_t`, `O_t` and `O_a` recomputed from `seed_leg`), then hands `seed_leg` to the binding's `verify`
 *  for the PQZ arithmetic of steps 5-7 and `v_a` (pqz-ffi `check_recipient`); `{ accepted, value }` or `{ skip }`, one outcome.
 *  `verify` may be a wallet of `loadPqzWallet` (src/pqzopenWasm.js; TODO 3zf): the handle then hands its opening KEM seed and
 *  the credit read from the blob (`u`, `v` unpacked, `credit.pk` the holder's own PQZ key of this version) to the module's
 *  `check_recipient`, which runs K3-7 steps 3-9 again; `value` = `{ digits, amount }`. The seed goes to no other `verify`.
 *  `credit = { token, index, slot, code, pk?, auditor?: { ua, pk, kemPk }, reads: { block, finalized, strictMajority } }`.
 *  UNAUDITED. */
export function pqzKeyHandle(seed, { account = 0, index = 0, chainUid, token, ua, version, layout }) {
  const kind = token === undefined ? 'offchain-shared' : 'offchain-token';
  const scope = token === undefined ? ZERO20 : asBytes(token, 20, 'token');
  const v = BigInt(version);
  const uaB = asBytes(ua, 32, 'ua');
  const cu = asBytes(chainUid, 32, 'chainUid');
  if (!layout || !layout.pkp || !layout.vp) refuse('the set layout (pqzLayout(n, packBits)) is needed');
  const id = keccak_256(concatBytes(utf8ToBytes('scaas.pqz3k.handle.v1'), cu, scope, uaB, be64(v)));
  let pqzSeed = scopedKeySeed(seed, { account, index, chainUid: cu, token: token === undefined ? undefined : scope, version: v });
  const okSeed = openKemSeed(seed, { ua: uaB, chainUid: cu, token: token === undefined ? undefined : scope, version: v });
  const k = openKemKey(okSeed);
  const kemPk = k.kemPk;
  const kem = { dk: k.dk, x25519Secret: k.x25519Secret };
  let loads = 0;
  let keygens = 0;
  const tokenOk = (t) => kind === 'offchain-shared' || eq(asBytes(t, 20, 'token'), scope);
  const live = () => { if (pqzSeed === null) refuse('this handle was wiped'); return pqzSeed; };

  function check(credit, verify) {
    live(); // review 3w-delta U4h-4: a wiped handle refuses, it never yields a (markable) skip
    const slot = slotOf(credit.slot);
    if (pqzSlotTrivial(slot)) refuse('a TRIVIAL entry is accepted without a check');
    const code = asBytes(credit.code, undefined, 'code');
    const b = pqzOpeningBlobOf(code, layout);
    const tok = asBytes(credit.token, 20, 'token');
    if (!tokenOk(tok) || !eq(b.toUA, uaB) || b.kv[0] !== v) refuse(`the credit is not this ${kind} handle's (token, recipient or key version)`);
    if (b.n === 2 && !credit.auditor) refuse('an audited leg without the auditor\'s keys (a read error, not a skip)');
    const wallet = isPqzWallet(verify);
    const lanes = (p) => pqzUnpack(p, layout.vp / 2);
    if (wallet && lanes(b.pu).length !== verify.pkBytes) refuse('the wallet module is of another parameter set than the layout');
    if (wallet && (!credit.pk || (b.n === 2 && !credit.auditor.pk))) refuse('the PQZ keys of the leg (credit.pk, auditor.pk) are needed');
    const aadT = pqzOpeningAad({ chainUid: cu, token: tok, ua: uaB, keyVersion: v, pu: b.pu, pv: b.pvt });
    const aadA = b.n === 2 ? pqzOpeningAad({ chainUid: cu, token: tok, ua: credit.auditor.ua, keyVersion: b.kv[1], pu: b.pu, pv: b.pva }) : null;
    const content = pqzEntryHash(credit.index, slot, code);
    const skip = () => ({ skip: { index: BigInt(credit.index), entryHash: hexOf(content), reads: { ...credit.reads } } });
    const seedLeg = openOpening({ opening: b.oT, kemPk, dk: kem.dk, x25519Secret: kem.x25519Secret, aad: aadT });
    if (seedLeg === null) return skip();
    if (!eq(sealOpening({ seedLeg, role: 0, kemPk, aad: aadT }).bytes, b.oT)) return skip(); // step 8
    if (b.n === 2) {
      let oA;
      try { oA = sealOpening({ seedLeg, role: 1, kemPk: credit.auditor.kemPk, aad: aadA }).bytes; } catch { return skip(); }
      if (!eq(oA, b.oA)) return skip(); // step 9, the auditor's opening
    }
    const value = wallet
      ? verify.checkRecipient(okSeed, { chainUid: cu, token: tok, u: lanes(b.pu),
        to: { ua: uaB, keyVersion: v, pk: credit.pk, kemPk, v: lanes(b.pvt), opening: b.oT },
        auditor: b.n === 2 ? { ua: credit.auditor.ua, keyVersion: b.kv[1], pk: credit.auditor.pk, kemPk: credit.auditor.kemPk,
          v: lanes(b.pva), opening: b.oA } : null })
      : verify(seedLeg, { blob: b, aadT, aadA, auditor: credit.auditor ?? null }) ?? null;
    if (value === null) return skip();
    const accepted = Object.freeze({ index: BigInt(credit.index), entryHash: hexOf(content) });
    ACCEPTED.set(accepted, { handle: id, index: BigInt(credit.index), content });
    return { accepted, value };
  }

  return Object.freeze({
    kind, scope: hexOf(scope), version: v, openKem: kemPk,
    check,
    /** How many times the PQZ seed reached `withSecretOwn` / `withSecretWindow`; `withSecretKeygen` apart. */
    get secretLoads() { return loads; },
    get keygens() { return keygens; },
    /** `keccak256(seed32)`: the KAT's view of the derivation, never the seed. */
    seedCommitment: () => hexOf(keccak_256(live())),
    withSecretOwn({ token: t, sendCounter, pu, pvf, ownTag }, f) {
      if (!tokenOk(t)) refuse(`the ciphertext is not this ${kind} handle's token`);
      const s = live();
      const { key, ownTag: want } = pqzOwnTag({ seed32: s, chainUid: cu, token: hexOf(asBytes(t, 20, 'token')), fromUA: uaB, sendCounter, pu, pvf });
      key.fill(0);
      if (want.toLowerCase() !== hexOf(asBytes(ownTag, 32, 'ownTag'))) refuse('the ownTag does not verify under this key');
      loads += 1;
      return f(s);
    },
    withSecretWindow(entries, f) {
      for (const e of entries) {
        const slot = slotOf(e.slot);
        if (pqzSlotMarked(slot) || pqzSlotTrivial(slot)) continue;
        const a = e.accepted && ACCEPTED.get(e.accepted);
        if (!a || !eq(a.handle, id) || a.index !== BigInt(e.index) || !e.code || !eq(a.content, pqzEntryHash(e.index, slot, e.code))) {
          refuse('a window entry is neither accepted by this handle, TRIVIAL nor skip-marked');
        }
      }
      const s = live();
      loads += 1;
      return f(s);
    },
    withSecretKeygen(f) {
      const s = live();
      keygens += 1;
      return f(s);
    },
    /** Wipes both secrets; the handle refuses every entry afterwards. */
    wipe() { if (pqzSeed) pqzSeed.fill(0); pqzSeed = null; kem.dk.fill(0); kem.x25519Secret.fill(0); okSeed.fill(0); },
  });
}

/** Fable P2-1: the skip marks a wallet may sign: every skip reproduced with reads at a finalized block from the node list in
 *  strict-majority mode (ARCH-POS-15), ascending and distinct; else refused, no mark. */
export function pqzMarks(skips) {
  if (skips.some((s) => !(s.reads?.finalized && s.reads?.strictMajority))) {
    refuse('a skip read at one node or an unfinalized block is not a reason to mark');
  }
  return [...new Set(skips.map((s) => BigInt(s.index)))].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
