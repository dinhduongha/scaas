// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// UNAUDITED. Seal / open to a UA KEM key and the sealed containers of backup and link (ua-rs-sign spec §6.3, C-03, C-11):
//   key        = HKDF-SHA256(ss, salt = empty, info = "scaas/seal/v1" ‖ u8 scheme ‖ be16 len(purpose) ‖ purpose ‖ keccak256(kemPk), 32)
//   ciphertext = AES-256-GCM(key, nonce = 0^96, pt, aad)       (every key encrypts once: m and e are fresh per seal)
// A seal authenticates no sender and gives no replay protection. A container carries the sender's `UASig` over
// keccak256(aad ‖ wire form) under the off-chain purpose scaas.ua.purpose.seal.v1 (MD-10; owner 2026-11-05: a full UASig, so an
// msig sender works), and `openContainer` accepts it only against what the opener expects (purpose, recipient, sender) and
// key data whose UA it recomputes, all before decapsulation. `openLink` adds the session window (10 minutes, one use); `restoreBackup` adds the payload's
// self-consistency and the backup generation. The JS reference of smartcontracts/vectors/ua/seal.json (T8, T9 in ua-rs).
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes, keccak_256, b64url, fromB64url, fromHex, hex, wipe } from './bytes.js';
import * as ua from './ua.js';
import { kemEncaps, kemEncapsVector, generateEphemeral, ephemeralVector } from './kem.js';
import { deriveUAKey, signContainer } from './uakey.js';
import { kindVerify, memberKeys } from './ua-verify.js';
import { seedFromEntropy } from './seed.js';

const fail = (code, reason) => { throw new ua.UAError(code, reason); };
export const PURPOSE = Object.freeze({ backup: 'scaas/backup/v1', link: 'scaas/link/v1' });
export const MAX_PT = 1 << 20;
/** A link container's `created` lies in [session start, start + LINK_WINDOW] (seconds; owner 2026-11-05: 10 minutes). */
export const LINK_WINDOW = 600;
const SEAL_INFO = utf8ToBytes('scaas/seal/v1');
const CT = 1568;
const ENTROPY = [16, 20, 24, 28, 32];

const bytesOf = (v, what) => (v instanceof Uint8Array ? v : typeof v === 'string' && v.startsWith('0x') ? fromHex(v)
  : fail('Argument', `${what}: bytes`));
const b32 = (v, what) => { const b = bytesOf(v, what); return b.length === 32 ? b : fail('Argument', `${what}: 32 bytes`); };
const be16 = (n) => Uint8Array.of(n >> 8, n & 255);
const be64 = (v, what) => {
  const n = typeof v === 'bigint' ? v : Number.isSafeInteger(v) ? BigInt(v) : -1n;
  if (n < 0n || n >= 1n << 64n) fail('Argument', `${what}: u64`);
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n);
  return b;
};
const purposeBytes = (p) => (typeof p === 'string' && /^[a-z0-9./-]{1,64}$/.test(p) ? utf8ToBytes(p)
  : fail('Argument', 'purpose: [a-z0-9./-], 1-64 bytes'));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function sealKey(ss, p, kemPk) {
  return hkdf(sha256, ss, new Uint8Array(0), concatBytes(SEAL_INFO, Uint8Array.of(1), be16(p.length), p, keccak_256(kemPk)), 32);
}

async function gcm(op, keyBytes, aad, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, [op]);
  const params = { name: 'AES-GCM', iv: new Uint8Array(12), additionalData: aad };
  return new Uint8Array(op === 'encrypt' ? await crypto.subtle.encrypt(params, key, data) : await crypto.subtle.decrypt(params, key, data));
}

async function sealWith(kemPk, purpose, aad, pt, encaps) {
  const p = purposeBytes(purpose);
  if (!(pt instanceof Uint8Array) || pt.length > MAX_PT) fail('Argument', 'pt: at most 1 MiB');
  if (!(aad instanceof Uint8Array)) fail('Argument', 'aad: bytes');
  const { mlkemCt, x25519Eph, ss } = encaps(kemPk);
  const key = sealKey(ss, p, kemPk);
  wipe(ss);
  try {
    return { version: 1, scheme: 1, mlkemCt, x25519Eph, ciphertext: await gcm('encrypt', key, aad, pt) };
  } finally {
    wipe(key);
  }
}

/** `Sealed { version: 1, scheme: 1, mlkemCt, x25519Eph, ciphertext }` of `pt` to `kemPk`; `m` and `e` from the platform RNG. */
export const seal = (kemPk, purpose, aad, pt) => sealWith(kemPk, purpose, aad, pt, kemEncaps);

/** Test vectors only: `seal` with the given `m` and `e`. */
export const sealVector = (kemPk, purpose, aad, pt, { m, e }) => sealWith(kemPk, purpose, aad, pt, (k) => kemEncapsVector(k, m, e));

/** The plaintext of `sealed` with the KEM key `kemKey` (kem.js): a version or scheme other than 1 is `SealVersion`, any other
 *  failure (decapsulation checks, tag) `SealOpen`. No replay protection: a valid seal may be opened again. */
export async function open(kemKey, purpose, aad, sealed) {
  if (sealed?.version !== 1 || sealed?.scheme !== 1) fail('SealVersion', 'version and scheme 1 only');
  const p = purposeBytes(purpose);
  let key;
  try {
    const ss = kemKey.decaps(sealed.mlkemCt, sealed.x25519Eph);
    key = sealKey(ss, p, kemKey.kemPk);
    wipe(ss);
    return await gcm('decrypt', key, aad, sealed.ciphertext);
  } catch {
    return fail('SealOpen', 'the seal does not open with this key, purpose and aad');
  } finally {
    if (key) wipe(key);
  }
}

/** Storage and transport form: `version ‖ scheme ‖ mlkemCt ‖ x25519Eph ‖ ciphertext`. */
export const wireForm = (s) => concatBytes(Uint8Array.of(s.version, s.scheme), s.mlkemCt, s.x25519Eph, s.ciphertext);

/** The named fields of a wire form (lengths checked; a version or scheme other than 1 is `SealVersion`). */
export function fromWire(w) {
  if (!(w instanceof Uint8Array) || w.length < 2 + CT + 32 + 16) fail('SealOpen', 'wire form too short');
  if (w[0] !== 1 || w[1] !== 1) fail('SealVersion', 'version and scheme 1 only');
  return { version: 1, scheme: 1, mlkemCt: w.slice(2, 2 + CT), x25519Eph: w.slice(2 + CT, 2 + CT + 32), ciphertext: w.slice(2 + CT + 32) };
}

// --- containers (backup and link) ---

/** `[recipientId (32), version]` of `{ ua, version }` or `{ kemPkHash }` (version 0 for an ephemeral key). */
function recipientParts(r) {
  if (r?.kemPkHash !== undefined && r?.ua === undefined) return { form: 'kem', id: b32(r.kemPkHash, 'kemPkHash'), version: 0n };
  if (r?.ua !== undefined && r?.kemPkHash === undefined) return { form: 'ua', id: b32(r.ua, 'recipient.ua'), version: BigInt(r.version ?? -1) };
  return fail('Argument', 'recipient: { ua, version } or { kemPkHash }');
}

/** The container's AEAD `aad`: `u8 v ‖ be16 len(purpose) ‖ purpose ‖ recipientId ‖ be64 version ‖ senderUa ‖ be64 created`,
 *  for `scaas/link/v1` followed by `sha256(shortCode)` (the code both screens show). */
export function containerAad({ purpose, recipient, senderUa, created, shortCode }) {
  const p = purposeBytes(purpose);
  const r = recipientParts(recipient);
  const parts = [Uint8Array.of(1), be16(p.length), p, r.id, be64(r.version, 'recipient.version'), b32(senderUa, 'sender.ua'), be64(created, 'created')];
  if (purpose === PURPOSE.link) {
    if (typeof shortCode !== 'string' || shortCode.length === 0) fail('Argument', 'a link container needs the short code');
    parts.push(sha256(utf8ToBytes(shortCode)));
  }
  return concatBytes(...parts);
}

const recipientJson = (r) => {
  const x = recipientParts(r);
  return x.form === 'kem' ? { kemPkHash: b64url(x.id) } : { ua: b64url(x.id), version: Number(x.version) };
};
const recipientOfJson = (j) => (j?.kemPkHash !== undefined ? { kemPkHash: fromB64url(j.kemPkHash) } : { ua: fromB64url(j?.ua ?? ''), version: j?.version });

const sigJson = (x) => ({ index: x.index, members: (x.members ?? []).map((y) => ({ index: y.index, sig: b64url(y.sig) })), sig: b64url(x.sig) });
const sigOfJson = (j, depth) => {
  if (!Number.isInteger(j?.index) || j.index < 0 || j.index > 0xffff || !Array.isArray(j.members ?? [])) throw new Error('member');
  if (depth === 2 && j.members?.length) throw new Error('a third level'); // two levels (CTR-UA-38)
  return { index: j.index, members: (j.members ?? []).map((x) => sigOfJson(x, depth + 1)), sig: fromB64url(j.sig) };
};

/** A container `{v: 1, purpose, recipient, sender: {ua, auth}, created, sealed}` (named fields, base64url) of `pt` to `kemPk`;
 *  `auth` the sender's `UASig {keyData, signature, members: [{index, members: [{index, sig}], sig}]}` (`signContainer`).
 *  `sender`: a UA key (uakey.js) or an `msig` `{ ua, keyData, slots, inner }` (the minimal set, as `msigMemberSigs`).
 *  `recipient`: `{ ua, version }` of a UA's KEM key or `{ kemPkHash }` of an ephemeral one (checked against `kemPk`).
 *  `fixed` (test vectors only): `{ m, e, sig }`, `sig` the signer's randomness. */
export async function sealContainer({ kemPk, purpose, recipient, sender, created, pt, shortCode }, fixed) {
  if (!sender?.ua) fail('Argument', 'the sender is a UA key or an msig with a UA id');
  const r = recipientParts(recipient);
  if (r.form === 'kem' && !eq(r.id, keccak_256(kemPk))) fail('Argument', 'recipient.kemPkHash is not keccak256(kemPk)');
  const aad = containerAad({ purpose, recipient, senderUa: sender.ua, created, shortCode });
  const sealed = fixed ? await sealVector(kemPk, purpose, aad, pt, fixed) : await seal(kemPk, purpose, aad, pt);
  const auth = signContainer(sender, keccak_256(concatBytes(aad, wireForm(sealed))), fixed?.sig);
  return { v: 1, purpose, recipient: recipientJson(recipient), created,
    sender: { ua: b64url(sender.ua), auth: { keyData: b64url(auth.keyData), signature: b64url(auth.signature), members: auth.members.map(sigJson) } },
    sealed: { mlkemCt: b64url(sealed.mlkemCt), x25519Eph: b64url(sealed.x25519Eph), ciphertext: b64url(sealed.ciphertext) } };
}

// The kinds whose key signs a container itself or as an msig member: the derived single keys clientkeys verifies. A native or
// group key, a Zether key, an msig as a leaf: none.
const SENDER_KINDS = [0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0130, 0x0131, 0x0132, 0x0133, 0x0134, 0x0135];
const MEMBER = ua.purposeTag('member');
const derives = (kind, keyData, id) => { try { return eq(ua.deriveUA(kind, keyData), id); } catch { return false; } };

/** A leaf member's signature over `uaMessage(kind, member, md)`; no list below it. */
const leafOk = (m, key, md, s) => SENDER_KINDS.includes(m.kind) && s.members.length === 0
  && kindVerify(m.kind, key, ua.uaMessage(m.kind, MEMBER, md), s.sig, false);

/** Member acceptance at one level (CTR-UA-37, owner 2026-11-05): the weight of the signing slots of `msig` `id` (hex) whose
 *  `accepted(id, index)` is `true` must reach the threshold, else `ContainerSender`; any other answer counts as not accepted. The
 *  set is minimal (every slot necessary), so this holds only when every signing member is accepted, and then the `msig`'s accepted
 *  weight reaches its threshold. */
function acceptedOk(id, d, slots, accepted) {
  const { threshold, members: all } = ua.msigStructure(d);
  const w = slots.reduce((t, s) => t + (accepted(id, s.index) === true ? all[s.index].weight : 0), 0);
  if (w < threshold) fail('ContainerSender', `msig ${id}: the accepted weight of its signers is below the threshold`);
}

/** An `msig` sender's `members` over its `ua_msg` `m0` (owner 2026-11-05): the minimal set at both levels (`msigSigMinimal`), each
 *  level's signers accepted (`acceptedOk`); a derived member over `memberDigest(senderUa, m0)`; an `msig` member with no `sig` of
 *  its own and its own non-empty list one level down over `innerDigest(member, memberDigest(senderUa, m0))`. Member key data from
 *  `members(id)`, never trusted (`memberKeys`). */
function msigOk(id, d, m0, slots, members, accepted) {
  const keys = memberKeys(d, members);
  if (!ua.msigSigMinimal(d, slots, (x) => members(x)?.keyData)) return false;
  const all = ua.msigStructure(d).members;
  acceptedOk(hex(id), d, slots, accepted);
  for (const s of slots) if (all[s.index].kind === 0x0120) acceptedOk(all[s.index].id, keys[s.index], s.members, accepted);
  const md = ua.memberDigest(id, m0);
  return slots.every((s) => {
    const m = all[s.index];
    if (m.kind !== 0x0120) return leafOk(m, keys[s.index], md, s);
    if (s.sig.length !== 0 || s.members.length === 0) return false;
    const leaves = ua.msigStructure(keys[s.index]).members;
    const inner = memberKeys(keys[s.index], members);
    const imd = ua.innerDigest(fromHex(m.id), md);
    return s.members.every((x) => leafOk(leaves[x.index], inner[x.index], imd, x));
  });
}

const decode = (f) => { try { return f(); } catch { return fail('SealOpen', 'container fields'); } };

/** The plaintext of a container, accepted only as `expect` says (spec §6.3, C-03), in order, each before decapsulation:
 *  the purpose; the recipient (the container's equals `expect.recipient`, and that is `kemKey`'s own); `sender.ua` is
 *  `expect.sender.ua` or in `expect.sender.set`; `sender.auth.keyData` derives `sender.ua`, as an `msig` or as exactly one
 *  single-key kind (`SENDER_KINDS`), recomputed here; then the `UASig` over the rebuilt aad and wire form (a single key: its
 *  `signature`, no members; an `msig`: no `signature`, `msigOk`), then the seal. A mismatch: `ContainerSender`; a bad
 *  signature, member set or tag: `SealOpen`. `members(id)` → `{ kind, keyData }`: an `msig` sender's member keys (re-derived;
 *  an unknown member: `ContainerSender`). `accepted(id, index)` → `memberAccepted(id, index)` of the chain's registry or an
 *  indexer (CTR-UA-37): an `msig` sender needs it (missing: `ContainerSender`) and opens only with its signers accepted at both
 *  levels (`acceptedOk`); a single key needs none. `shortCode`: a link container's. No replay protection here (openLink,
 *  restoreBackup). */
export async function openContainer(kemKey, c, expect, members, accepted, { shortCode } = {}) {
  if (c?.v !== 1) fail('SealVersion', 'container v 1 only');
  const no = (why) => fail('ContainerSender', why);
  if (c.purpose !== expect?.purpose) no('purpose not the expected one');
  const want = recipientParts(expect.recipient);
  const got = decode(() => recipientParts(recipientOfJson(c.recipient)));
  if (got.form !== want.form || !eq(got.id, want.id) || got.version !== want.version) no('recipient not the expected one');
  const own = recipientParts(kemKey.recipient);
  if (own.form !== want.form || !eq(own.id, want.id) || own.version !== want.version) no('the expected recipient is not this key');
  const senderUa = decode(() => b32(fromB64url(c.sender.ua), 'sender.ua'));
  const allowed = expect.sender?.ua !== undefined ? [expect.sender.ua] : expect.sender?.set ?? [];
  if (!allowed.some((u) => eq(b32(u, 'expect.sender'), senderUa))) no('sender not the expected one');
  const auth = decode(() => ({ keyData: fromB64url(c.sender.auth.keyData), signature: fromB64url(c.sender.auth.signature),
    members: (c.sender.auth.members ?? []).map((x) => sigOfJson(x, 1)) }));
  const kind = [0x0120, ...SENDER_KINDS].find((k) => derives(k, auth.keyData, senderUa));
  if (kind === undefined) no('auth.keyData does not derive sender.ua');
  const aad = containerAad({ purpose: c.purpose, recipient: recipientOfJson(c.recipient), senderUa, created: c.created, shortCode });
  const sealed = decode(() => ({ version: 1, scheme: 1, mlkemCt: fromB64url(c.sealed.mlkemCt), x25519Eph: fromB64url(c.sealed.x25519Eph),
    ciphertext: fromB64url(c.sealed.ciphertext) }));
  const m0 = ua.uaMessage(kind, ua.SEAL_TAG, keccak_256(concatBytes(aad, wireForm(sealed))));
  let ok;
  if (kind !== 0x0120) ok = auth.members.length === 0 && kindVerify(kind, auth.keyData, m0, auth.signature, false);
  else {
    if (typeof accepted !== 'function') no('an msig sender needs accepted(id, index)');
    try { ok = auth.signature.length === 0 && msigOk(senderUa, auth.keyData, m0, auth.members, members ?? (() => null), accepted); } catch (e) {
      no(e?.code === 'ContainerSender' ? e.reason : 'msig member keys');
    }
  }
  if (!ok) fail('SealOpen', 'sender signature');
  return open(kemKey, c.purpose, aad, sealed);
}

// --- link ---

/** A link session on the new device: an ephemeral KEM key, the short code both screens show, the window [start, start + 10 min];
 *  one use (`openLink` consumes it). */
export function linkSession(now = Math.floor(Date.now() / 1000)) {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 100_000_000;
  return newSession(generateEphemeral(), String(n).padStart(8, '0'), now);
}

/** Test vectors only: a session from 96 given bytes, a given short code and start. */
export const linkSessionVector = (bytes96, shortCode, start) => newSession(ephemeralVector(bytes96), shortCode, start);

const newSession = (kemKey, shortCode, start) => ({ kemKey, kemPk: kemKey.kemPk, recipient: kemKey.recipient, shortCode, start,
  end: start + LINK_WINDOW, used: false });

/** The plaintext of a link container to `session`: `created` in the window (else `ContainerReplay`), the acceptance of
 *  `openContainer`; on success the session is used up and its key wiped (a second call: `ContainerReplay`). */
export async function openLink(session, c, expect, members, accepted) {
  if (session.used) fail('ContainerReplay', 'the session is used up');
  if (expect?.purpose !== PURPOSE.link) fail('Argument', 'a link session opens scaas/link/v1 only');
  if (!Number.isSafeInteger(c?.created) || c.created < session.start || c.created > session.end) {
    fail('ContainerReplay', 'created outside the session window');
  }
  const pt = await openContainer(session.kemKey, c, expect, members, accepted, { shortCode: session.shortCode });
  session.used = true;
  session.kemKey.wipe();
  return pt;
}

// --- backup ---

/** `BackupPayload {v: 1, generation, entropy, secrets: [{label, bytes}], manifest}` as JSON (this key order, base64url bytes);
 *  `entropy` at its BIP-39 length; the BIP-39 passphrase is never in it. `manifest.entries`: `[{kind, account, index, ua}]`. */
export function encodeBackup({ generation, entropy, secrets = [], manifest }) {
  if (!Number.isSafeInteger(generation) || generation < 0) fail('Argument', 'generation');
  if (!(entropy instanceof Uint8Array) || !ENTROPY.includes(entropy.length)) fail('Argument', 'entropy: 16, 20, 24, 28 or 32 bytes');
  return utf8ToBytes(JSON.stringify({ v: 1, generation, entropy: b64url(entropy),
    secrets: secrets.map((s) => ({ label: s.label, bytes: b64url(s.bytes) })), manifest }));
}

export function decodeBackup(pt) {
  let j;
  try { j = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(pt)); } catch { fail('Argument', 'backup payload is not JSON'); }
  if (j?.v !== 1 || !Number.isSafeInteger(j.generation) || j.generation < 0 || !Array.isArray(j.manifest?.entries)) fail('Argument', 'backup payload');
  const entropy = fromB64url(j.entropy);
  if (!ENTROPY.includes(entropy.length)) fail('Argument', 'backup entropy: 16, 20, 24, 28 or 32 bytes');
  return { generation: j.generation, entropy, secrets: (j.secrets ?? []).map((s) => ({ label: s.label, bytes: fromB64url(s.bytes) })),
    manifest: j.manifest };
}

/** A backup container (purpose `scaas/backup/v1`) of `payload` (encodeBackup) to `kemPk`, signed by the wallet's identity key. */
export const sealBackup = ({ kemPk, recipient, sender, created, payload }, fixed) =>
  sealContainer({ kemPk, purpose: PURPOSE.backup, recipient, sender, created, pt: encodeBackup(payload) }, fixed);

/** A backup restored (spec §6.3, C-03, C-11): `openContainer`, then the payload must derive `sender.ua` from its own entropy at
 *  the manifest entry naming it (else `ContainerSender`); over a device that holds this wallet (`current = { ua, generation }`
 *  with `ua` = sender.ua) an older generation is `BackupRollback` unless `allowRollback`, an equal one changes nothing
 *  (`install: false`). Returns `{ install, payload }`. */
export async function restoreBackup(kemKey, c, expect, members, accepted, { current = null, allowRollback = false, bip39Passphrase = '' } = {}) {
  if (expect?.purpose !== PURPOSE.backup) fail('Argument', 'restore opens scaas/backup/v1 only');
  const pt = await openContainer(kemKey, c, expect, members, accepted);
  const payload = decodeBackup(pt);
  wipe(pt);
  const senderUa = hex(fromB64url(c.sender.ua));
  const entry = payload.manifest.entries.find((e) => e?.ua === senderUa);
  const seed = seedFromEntropy(payload.entropy, bip39Passphrase);
  let derived = null;
  try { if (entry) derived = hex(deriveUAKey(seed, { kind: entry.kind, account: entry.account, index: entry.index }).ua); } catch { derived = null; }
  wipe(seed);
  if (derived !== senderUa) fail('ContainerSender', 'the backup entropy does not derive sender.ua');
  if (current && hex(b32(current.ua, 'current.ua')) === senderUa) {
    if (payload.generation < current.generation && allowRollback !== true) fail('BackupRollback', `generation ${payload.generation} < ${current.generation}`);
    if (payload.generation === current.generation) return { install: false, payload };
  }
  return { install: true, payload };
}
