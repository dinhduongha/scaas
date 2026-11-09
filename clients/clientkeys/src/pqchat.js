// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// PqChat (UA-7 spec v2 §4, §6, §7, §10; public topics spec §2; plan group 3c, 3C-D3 / 3C-D5 / 3C-D9): the typed records, ids,
// nonce scopes, signed-record blobs, the hybrid KEM wrap, the sender chains, padding, the message, envelope and payload bytes,
// sealedInfo and the call keys. The byte formats of smartcontracts/vectors/pqchat/. UNAUDITED.
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { gcm, gcmsiv } from '@noble/ciphers/aes.js';
import { keccak_256, sha256, concatBytes, utf8ToBytes, fromHex, abiEncode } from './bytes.js';
import { encodeType, hashStruct, intWord } from './evm.js';
import { uaMessage } from './ua.js';

const bytes = (v) => (v instanceof Uint8Array ? v : fromHex(v));
const tag = (s) => keccak_256(utf8ToBytes(s));
const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const be = (v, n) => {
  let x = BigInt(v);
  if (x < 0n || x >= 1n << BigInt(8 * n)) throw new Error(`not a uint${8 * n}: ${v}`);
  const out = new Uint8Array(n);
  for (let i = n - 1; i >= 0; i--, x >>= 8n) out[i] = Number(x & 0xffn);
  return out;
};
const u32be = (v) => be(v, 4);
const u64be = (v) => be(v, 8);

export class PqChatError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

// ------------------------------------------------------------------ records (spec §4.1, topics spec P35)

/** The type strings, exactly as the specs fix them; the field lists are parsed from them and `encodeType` must give them back. */
export const TYPE_STRINGS = Object.freeze({
  MemberKey: 'MemberKey(bytes32 ua,uint64 keyId,bytes32 via)',
  Wrap: 'Wrap(bytes32 member,uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey)',
  PqChatSession: 'PqChatSession(bytes32 creator,uint64 nonce,bytes32 homeChain,address homeContract,bytes32[] admins,'
    + 'MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)',
  PqChatEpoch: 'PqChatEpoch(bytes32 sessionId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins,'
    + 'MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)',
  PqChatLeave: 'PqChatLeave(bytes32 sessionId,bytes32 epochId,bytes32 member,uint64 nonce)',
  PqChatMessage: 'PqChatMessage(bytes32 sessionId,bytes32 epochId,bytes32 sender,bytes16 device,uint64 counter,bytes32[] parents,'
    + 'bytes ciphertext)',
  PqTopic: 'PqTopic(bytes32 owner,uint64 nonce,bytes32 homeChain,address homeContract,string name,bytes about,bool openReplies)',
  PqTopicUpdate: 'PqTopicUpdate(bytes32 topicId,uint64 seq,string name,bytes about,bool openReplies)',
  PqTopicWriter: 'PqTopicWriter(bytes32 topicId,bytes32 writer,bool granted,uint64 seq)',
  PqTopicEntry: 'PqTopicEntry(bytes32 topicId,bytes32 author,uint64 nonce,bytes32 parentId,EntryRef ref,string mediaType,bytes body)'
    + 'EntryRef(bytes32 chainUid,address pqchat,bytes32 entryId,bytes32 contentHash)',
  EntryRef: 'EntryRef(bytes32 chainUid,address pqchat,bytes32 entryId,bytes32 contentHash)',
  PqTopicEdit: 'PqTopicEdit(bytes32 entryId,bytes32 author,uint64 nonce,uint32 version,string mediaType,bytes body)',
  PqTopicVote: 'PqTopicVote(bytes32 entryId,bytes32 voter,int8 value,uint64 seq)',
});
export const SESSION_STRUCTS = ['MemberKey', 'Wrap', 'PqChatSession', 'PqChatEpoch', 'PqChatLeave', 'PqChatMessage'];
export const TOPIC_STRUCTS = ['PqTopic', 'PqTopicUpdate', 'PqTopicWriter', 'PqTopicEntry', 'EntryRef', 'PqTopicEdit', 'PqTopicVote'];

export const TYPES = Object.freeze(Object.fromEntries(Object.entries(TYPE_STRINGS).map(([name, s]) => {
  const [, primary, list] = s.match(/^(\w+)\(([^)]*)\)/);
  if (primary !== name) throw new Error(`type string of ${name} names ${primary}`);
  return [name, list.split(',').map((f) => { const [type, field] = f.split(' '); return { name: field, type }; })];
})));
for (const name of Object.keys(TYPES)) {
  if (encodeType(TYPES, name) !== TYPE_STRINGS[name]) throw new Error(`encodeType(${name}) differs from its type string`);
}
export const TYPEHASH = Object.freeze(Object.fromEntries(Object.entries(TYPE_STRINGS).map(([n, s]) => [n, tag(s)])));

/** `DS_C`: the portable domain, no chain id, no contract (P7). */
export const DOMAIN = Object.freeze({ name: 'SCaaS PqChat', version: '1', type: 'EIP712Domain(string name,string version)' });
export const DS_C = keccak_256(concatBytes(tag(DOMAIN.type), tag(DOMAIN.name), tag(DOMAIN.version)));
export const PURPOSE_TAG = 'scaas.ua.purpose.pqchat.v1';
export const PURPOSE_PQCHAT = tag(PURPOSE_TAG);

export const structHash = (name, s) => hashStruct(TYPES, name, s);
/** `typed(s) = keccak256(0x1901 ‖ DS_C ‖ hashStruct(s))`. */
export const typed = (name, s) => keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), DS_C, structHash(name, s)));
/** What the author signs: `uaMessage(kind, PURPOSE_PQCHAT, typed(s))`. */
export const signedDigest = (kind, name, s) => uaMessage(kind, PURPOSE_PQCHAT, typed(name, s));

// ------------------------------------------------------------------ ids and nonce scopes (§4.3, P36, 3C-D5)

export const TAG_STRINGS = Object.freeze(['session', 'epoch', 'topic', 'entry', 'scope/session', 'scope/epoch', 'scope/message',
  'scope/topic', 'scope/entry'].map((t) => `scaas/pqchat/v1/${t}`));
const TAG = Object.fromEntries(TAG_STRINGS.map((s) => [s.slice('scaas/pqchat/v1/'.length), tag(s)]));
const idOf = (t, types, values) => keccak_256(abiEncode(['bytes32', ...types], [TAG[t], ...values]));

export const sessionId = (creator, nonce) => idOf('session', ['bytes32', 'uint64'], [creator, nonce]);
export const epochId = (session, author, nonce) => idOf('epoch', ['bytes32', 'bytes32', 'uint64'], [session, author, nonce]);
export const leaveId = (l) => typed('PqChatLeave', l);
export const messageId = (m) => typed('PqChatMessage', m);
export const topicId = (owner, nonce) => idOf('topic', ['bytes32', 'uint64'], [owner, nonce]);
export const entryId = (topic, author, nonce) => idOf('entry', ['bytes32', 'bytes32', 'uint64'], [topic, author, nonce]);
export const scopeSession = (creator) => idOf('scope/session', ['bytes32'], [creator]);
/** Epochs and leaves. */
export const scopeEpoch = (session, author) => idOf('scope/epoch', ['bytes32', 'bytes32'], [session, author]);
/** Messages; the nonce is `counter`. */
export const scopeMessage = (epoch, sender, device) => idOf('scope/message', ['bytes32', 'bytes32', 'bytes16'], [epoch, sender, device]);
export const scopeTopic = (owner) => idOf('scope/topic', ['bytes32'], [owner]);
/** Entries and their edits (the original's `topicId`). */
export const scopeEntry = (topic, author) => idOf('scope/entry', ['bytes32', 'bytes32'], [topic, author]);

// ------------------------------------------------------------------ stored blobs (3C-D3)

/** A struct as an ABI tuple; `intN` goes as its sign-extended word (the same 32 bytes `abi.encode` writes). */
const abiTypeOf = (t) => {
  if (t.endsWith('[]')) return `${abiTypeOf(t.slice(0, -2))}[]`;
  if (TYPES[t]) return `(${TYPES[t].map((f) => abiTypeOf(f.type)).join(',')})`;
  return /^int\d+$/.test(t) ? 'bytes32' : t;
};
const abiValueOf = (t, v) => {
  if (t.endsWith('[]')) return v.map((x) => abiValueOf(t.slice(0, -2), x));
  if (TYPES[t]) return TYPES[t].map((f) => abiValueOf(f.type, v[f.name]));
  return /^int\d+$/.test(t) ? intWord(t, v) : v;
};
export const recordAbi = (name, s) => ({ type: abiTypeOf(name), value: abiValueOf(name, s) });

/** `UASig = (bytes keyData, bytes signature, (uint16 index, (uint16 index, bytes sig)[] members, bytes sig)[] members)`. */
export const UASIG_ABI = '(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])';
const uaSigValue = (s) => [s.keyData, s.signature, s.members.map((m) => [m.index, m.members.map((i) => [i.index, i.sig]), m.sig])];
/** `sigHash = keccak256(abi.encode(UASig))`. */
export const sigHash = (sig) => keccak_256(abiEncode([UASIG_ABI], [uaSigValue(sig)]));
/** `abi.encode(record, sigHash)`: a signed record's stored bytes. */
export function recordBlob(name, s, sig) {
  const r = recordAbi(name, s);
  return abiEncode([r.type, 'bytes32'], [r.value, sigHash(sig)]);
}
/** `abi.encode(PqChatMessage, UASig)`: what `postMessage` takes and what the envelope holds (P15). */
export function messageWithSig(m, sig) {
  const r = recordAbi('PqChatMessage', m);
  return abiEncode([r.type, UASIG_ABI], [r.value, uaSigValue(sig)]);
}

// ------------------------------------------------------------------ the hybrid KEM (P14, §6.1)

const Q = 3329;
/** P14: scheme byte 1, 1,601 B (so `ek` is 1,568 B), and FIPS 203 §7.2's modulus check: `ByteEncode12(ByteDecode12(ek[0:1536]))
 *  == ek[0:1536]`, which holds iff every 12-bit coefficient is below q. Returns `{ ek, pkX }`. */
export function checkKemPk(kemPk) {
  const pk = bytes(kemPk);
  if (pk[0] !== 1) throw new PqChatError('wrong scheme byte');
  if (pk.length !== 1601) throw new PqChatError('wrong length');
  for (let i = 1; i < 1 + 1536; i += 3) {
    if ((pk[i] | ((pk[i + 1] & 15) << 8)) >= Q || ((pk[i + 1] >> 4) | (pk[i + 2] << 4)) >= Q) throw new PqChatError('modulus check');
  }
  return { ek: pk.subarray(1, 1569), pkX: pk.subarray(1569) };
}

/** X25519 with the all-zero shared secret refused. noble refuses the low-order points (exactly those whose output is all zero
 *  for a clamped scalar) before the ladder, with this message; any other error passes through. */
function dh(secret, pub) {
  let s;
  try {
    s = x25519.getSharedSecret(secret, pub);
  } catch (e) {
    if (/invalid private or public key/.test(e.message)) throw new PqChatError('all-zero X25519');
    throw e;
  }
  if (s.every((b) => b === 0)) throw new PqChatError('all-zero X25519');
  return s;
}

/** §6.1: `ss = SHA3-256(ss_M ‖ ss_X ‖ E ‖ pk_X ‖ "scaas.kem.1")`. */
export const combine = (ssM, ssX, E, pkX) => sha3_256(concatBytes(ssM, ssX, E, pkX, utf8ToBytes('scaas.kem.1')));

/** Encapsulation to a checked `kemPk` with fixed randomness: ML-KEM `m` (32 B) and the X25519 ephemeral secret `e`. */
export function encaps(kemPk, m, e) {
  const { ek, pkX } = checkKemPk(kemPk);
  const ssX = dh(bytes(e), pkX);
  const { cipherText: ctM, sharedSecret: ssM } = ml_kem1024.encapsulate(ek, bytes(m));
  const E = x25519.getPublicKey(bytes(e));
  return { ctM, ssM, E, ssX, ss: combine(ssM, ssX, E, pkX) };
}

/** A member's KEM key from its ML-KEM keygen seed (64 B) and X25519 secret: `kemPk = 0x01 ‖ ek ‖ pkX`. */
export function kemKey(seed, x25519Secret) {
  const { publicKey: ek, secretKey: dk } = ml_kem1024.keygen(bytes(seed));
  const pkX = x25519.getPublicKey(bytes(x25519Secret));
  const kemPk = concatBytes(Uint8Array.of(1), ek, pkX);
  return { ek, dk, pkX, kemPk, kemPkHash: keccak_256(kemPk) };
}

// ------------------------------------------------------------------ wraps (§6.2)

const H = (ikm, info) => hkdf(sha256, ikm, new Uint8Array(0), info, 32);
const label = (s, ...parts) => concatBytes(utf8ToBytes(s), ...parts.map(bytes));
const ZERO_NONCE = new Uint8Array(12);

export const wrapKek = (ss, session, epoch, member, keyId, kemPk) =>
  H(ss, label('scaas/pqchat/v1/wrap', session, epoch, member, u64be(keyId), Uint8Array.of(1), keccak_256(bytes(kemPk))));
const wrapAad = (session, epoch, member, keyId) => concatBytes(bytes(session), bytes(epoch), bytes(member), u64be(keyId));

/** Seals `K` to one member: returns the encapsulation, `kek`, `sealedKey` (48 B) and the `Wrap` struct. */
export function wrapTo({ K, sessionId: s, epochId: e, member, keyId, kemPk, m, x25519Secret }) {
  const enc = encaps(kemPk, m, x25519Secret);
  const kek = wrapKek(enc.ss, s, e, member, keyId, kemPk);
  const sealedKey = gcm(kek, ZERO_NONCE, wrapAad(s, e, member, keyId)).encrypt(bytes(K));
  return { ...enc, kek, sealedKey, wrap: { member, keyId, mlkemCt: enc.ctM, x25519Eph: enc.E, sealedKey } };
}

/** The receiver: decapsulates with its ML-KEM `dk` and X25519 secret, opens `K`. */
export function openWrap({ wrap, sessionId: s, epochId: e, kemPk, dk, x25519Secret }) {
  const { pkX } = checkKemPk(kemPk);
  const ssM = ml_kem1024.decapsulate(bytes(wrap.mlkemCt), bytes(dk));
  const E = bytes(wrap.x25519Eph);
  const ss = combine(ssM, dh(bytes(x25519Secret), E), E, pkX);
  const kek = wrapKek(ss, s, e, wrap.member, wrap.keyId, kemPk);
  return gcm(kek, ZERO_NONCE, wrapAad(s, e, wrap.member, wrap.keyId)).decrypt(bytes(wrap.sealedKey));
}

// ------------------------------------------------------------------ sender chains, padding, messages (§6.3–§6.5)

/** §6.3: `ck_0`, then per step i `mk_i`, `n_i`, `ck_{i+1}`. A device id is a 16-byte UUID (RFC 9562), v7 or v4 at the client's
 *  choice, as `bytes16` (owner 2026-11-10): its 16 raw bytes here, in the call keys, the message scope and the aad; an input only,
 *  nothing checks its version or variant bits. */
export function chainKeys(K, session, epoch, sender, device, steps) {
  let ck = H(bytes(K), label('scaas/pqchat/v1/chain', session, epoch, sender, device));
  const ck0 = ck;
  const out = [];
  for (let i = 0; i < steps; i++) {
    const mk = hmac(sha256, ck, Uint8Array.of(1));
    const n = hmac(sha256, ck, Uint8Array.of(3)).subarray(0, 12);
    ck = hmac(sha256, ck, Uint8Array.of(2));
    out.push({ i, mk, n, ck });
  }
  return { ck0, steps: out };
}

const BUCKETS = [256, 1024, 4096, 16384];
/** §6.5, 3C-D9: `u32be(len) ‖ content ‖ zeros` to the smallest of 256, 1,024, 4,096, 16,384 B, then multiples of 16,384 B. */
export function pad(content) {
  const c = bytes(content);
  const need = 4 + c.length;
  const out = new Uint8Array(BUCKETS.find((b) => b >= need) ?? Math.ceil(need / 16384) * 16384);
  out.set(u32be(c.length));
  out.set(c, 4);
  return out;
}
/** The content of a padded plaintext; anything `pad` would not write is refused. */
export function unpad(pt) {
  const p = bytes(pt);
  const n = p.length >= 4 ? new DataView(p.buffer, p.byteOffset).getUint32(0) : -1;
  const c = n >= 0 && n <= p.length - 4 ? p.slice(4, 4 + n) : null;
  if (!c || !equal(pad(c), p)) throw new PqChatError('padding');
  return c;
}

/** Canonical JSON: object keys sorted (code units), no whitespace, `JSON.stringify` escapes. */
export const canonicalJson = (v) => JSON.stringify(v, (_, x) => (x && typeof x === 'object' && !Array.isArray(x)
  ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x));

/** §6.4: `abi.encode(sessionId, epochId, sender, bytes16 device, uint64 counter, keccak256(abi.encode(bytes32[] parents)))`. */
export const parentsHash = (parents) => keccak_256(abiEncode(['bytes32[]'], [parents]));
export const messageAad = (m) => abiEncode(['bytes32', 'bytes32', 'bytes32', 'bytes16', 'uint64', 'bytes32'],
  [m.sessionId, m.epochId, m.sender, m.device, m.counter, parentsHash(m.parents)]);

const messageKey = (K, m) => chainKeys(K, m.sessionId, m.epochId, m.sender, m.device, m.counter + 1).steps[m.counter];
/** `ciphertext = AES-256-GCM-SIV(mk_counter, n_counter, pt, aad)` for the header `m` (its `ciphertext` unused). */
export function encryptMessage(K, m, pt) {
  const { mk, n } = messageKey(K, m);
  return gcmsiv(mk, n, messageAad(m)).encrypt(bytes(pt));
}
export function decryptMessage(K, m) {
  const { mk, n } = messageKey(K, m);
  return gcmsiv(mk, n, messageAad(m)).decrypt(bytes(m.ciphertext));
}

// ------------------------------------------------------------------ envelope, payload, sealedInfo (P15, P25, P29, §4.2)

export const hint = (K) => hmac(sha256, bytes(K), utf8ToBytes('scaas/pqchat/v1/hint')).subarray(0, 8);
export const envKey = (K, session, epoch) => H(bytes(K), label('scaas/pqchat/v1/env', session, epoch));
export const infoKey = (K, session, epoch) => H(bytes(K), label('scaas/pqchat/v1/info', session, epoch));
const seal = (key, nonce, pt) => concatBytes(bytes(nonce), gcmsiv(key, bytes(nonce)).encrypt(pt));
const open = (key, blob) => { const b = bytes(blob); return gcmsiv(key, b.subarray(0, 12)).decrypt(b.subarray(12)); };

/** P15: `env = nonce ‖ AES-256-GCM-SIV(k_env, nonce, abi.encode(PqChatMessage, UASig))`, empty AAD. */
export function envelope(K, m, sig, nonce) {
  const kEnv = envKey(K, m.sessionId, m.epochId);
  const inner = messageWithSig(m, sig);
  return { hint: hint(K), kEnv, inner, env: seal(kEnv, nonce, inner) };
}
export const openEnvelope = (K, session, epoch, env) => open(envKey(K, session, epoch), env);
/** P25 / P29: the HCS and `storeMessage` payload `abi.encode(uint8 1, bytes8 hint, bytes env)`. */
export const payload = (h, env) => abiEncode(['uint8', 'bytes8', 'bytes'], [1, h, env]);

/** §4.2: `sealedInfo = nonce ‖ AES-256-GCM-SIV(HKDF(K, "scaas/pqchat/v1/info" ‖ sessionId ‖ epochId), nonce, pad(canonical JSON))`. */
export function sealInfo(K, session, epoch, info, nonce) {
  const json = canonicalJson(info);
  const pt = pad(utf8ToBytes(json));
  const kInfo = infoKey(K, session, epoch);
  return { json, pt, kInfo, sealedInfo: seal(kInfo, nonce, pt) };
}
export const openInfo = (K, session, epoch, sealed) =>
  JSON.parse(new TextDecoder().decode(unpad(open(infoKey(K, session, epoch), sealed))));

// ------------------------------------------------------------------ call keys (P22, 3C-D9; no SFrame KID: S is not stated)

/** `callBase = HKDF(K ‖ callSecret, "scaas/pqchat/v1/call" ‖ sessionId ‖ epochId ‖ callId ‖ u32be callEpoch)` (group), `HKDF(K, …)`
 *  (1:1, `callSecret` absent); `baseKey(sender, device) = HKDF(callBase, "scaas/pqchat/v1/sframe" ‖ sender ‖ device)`, the
 *  device's 16 bytes. */
export function callKeys({ K, callSecret, sessionId: s, epochId: e, callId, callEpoch }, senders) {
  const ikm = callSecret ? concatBytes(bytes(K), bytes(callSecret)) : bytes(K);
  const callBase = H(ikm, label('scaas/pqchat/v1/call', s, e, callId, u32be(callEpoch)));
  return { callBase, baseKeys: senders.map(({ sender, device }) => H(callBase, label('scaas/pqchat/v1/sframe', sender, device))) };
}
