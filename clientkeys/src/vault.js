// Encrypted-at-rest secrets (R32, RS4-8). A random 32-byte data key (DEK) encrypts the secret with
// AES-256-GCM (WebCrypto, fresh 12-byte IV per encryption). The DEK is wrapped by:
//   - a passphrase via scrypt (N=2^17, r=8, p=1, 16-byte salt; ~0.5 s in Node 26) — ALWAYS present,
//     so a browser without the passkey PRF extension can still open the vault (review SEC-17). A new
//     passphrase needs 8+ characters and not only digits (review S4-M3); vaults sealed by older
//     clients (N=2^15, 6-digit PIN) still open and are re-wrapped on unlock (`rewrapPin`);
//   - optionally the passkey PRF output (HKDF-SHA256) — unlock without typing the PIN.
// No wrapping key and no plaintext is ever stored. The vault object is plain JSON (localStorage).
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes, b64url, fromB64url, wipe } from './bytes.js';

export const SCRYPT = Object.freeze({ N: 2 ** 17, r: 8, p: 1, dkLen: 32 });
const VERSION = 1;
const PRF_INFO = utf8ToBytes('bamboo-clientkeys-vault-v1/prf');

async function gcm(op, keyBytes, iv, data, aad) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, [op]);
  const params = { name: 'AES-GCM', iv, additionalData: utf8ToBytes(aad) };
  const out = op === 'encrypt' ? await crypto.subtle.encrypt(params, key, data) : await crypto.subtle.decrypt(params, key, data);
  return new Uint8Array(out);
}

/** AES-256-GCM box `{iv, ct}` (also the Zether balance-cache box, zether.js). */
export async function seal(keyBytes, data, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { iv: b64url(iv), ct: b64url(await gcm('encrypt', keyBytes, iv, data, aad)) };
}

export async function open(keyBytes, box, aad) {
  try {
    return await gcm('decrypt', keyBytes, fromB64url(box.iv), fromB64url(box.ct), aad);
  } catch {
    throw new Error('Wrong PIN or the vault was altered.');
  }
}

/** Policy for a NEW passphrase only; opening never checks it (old vaults keep working). */
export function checkPassphrase(pin) {
  const p = String(pin || '').normalize('NFKC');
  if ([...p].length < 8 || !/[^\d\s]/u.test(p)) {
    throw new Error('Choose a passphrase of at least 8 characters, not only digits.');
  }
}

async function pinKey(pin, salt, params = SCRYPT) {
  return scryptAsync(utf8ToBytes(String(pin ?? '').normalize('NFKC')), salt, params);
}

async function pinEnvelope(label, dek, pin, params = SCRYPT) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await pinKey(pin, salt, params);
  try {
    return { kdf: 'scrypt', N: params.N, r: params.r, p: params.p, salt: b64url(salt), ...(await seal(kek, dek, `${label}|pin`)) };
  } finally {
    wipe(kek);
  }
}

function prfKey(prfOutput) {
  return hkdf(sha256, prfOutput, undefined, PRF_INFO, 32);
}

/** `label` names what is inside ('seed', 'zether-conf:…') and is bound into every AAD. */
export async function createVault(secret, { label, pin, prf }) {
  checkPassphrase(pin);
  const dek = crypto.getRandomValues(new Uint8Array(32));
  try {
    const vault = { v: VERSION, label, data: await seal(dek, secret, `${label}|data`), pin: await pinEnvelope(label, dek, pin) };
    if (prf) await addPrfEnvelope(vault, dek, prf);
    return vault;
  } finally {
    wipe(dek);
  }
}

/** True when the passphrase envelope is weaker than today's scrypt parameters. */
export function needsRewrap(vault) {
  const p = vault.pin || {};
  return !(p.N >= SCRYPT.N && p.r >= SCRYPT.r && p.p >= SCRYPT.p);
}

/** New passphrase envelope (fresh salt, today's parameters) over the same DEK; data and PRF
 *  envelopes are untouched. Returns a new vault object; the caller stores it. `params`/`policy`
 *  exist for tests that build an old-format vault. */
export async function rewrapPin(vault, oldPin, newPin, params = SCRYPT, { policy = true } = {}) {
  if (policy) checkPassphrase(newPin);
  const dek = await dekFrom(vault, { pin: oldPin });
  try {
    return { ...structuredClone(vault), pin: await pinEnvelope(vault.label, dek, newPin, params) };
  } finally {
    wipe(dek);
  }
}

async function addPrfEnvelope(vault, dek, { output, credentialId, salt }) {
  const kek = prfKey(output);
  try {
    vault.prf = { credentialId, salt: b64url(salt), ...(await seal(kek, dek, `${vault.label}|prf`)) };
  } finally {
    wipe(kek);
  }
}

async function dekFrom(vault, { pin, prfOutput }) {
  if (vault.v !== VERSION) throw new Error('Unknown vault version.');
  if (prfOutput) {
    if (!vault.prf) throw new Error('This vault has no passkey unlock.');
    const kek = prfKey(prfOutput);
    try { return await open(kek, vault.prf, `${vault.label}|prf`); } finally { wipe(kek); }
  }
  const p = vault.pin;
  const kek = await pinKey(pin, fromB64url(p.salt), { N: p.N, r: p.r, p: p.p, dkLen: 32 });
  try { return await open(kek, p, `${vault.label}|pin`); } finally { wipe(kek); }
}

/** Returns the secret bytes; the caller wipes them as soon as it is done. */
export async function openVault(vault, unlock) {
  const dek = await dekFrom(vault, unlock);
  try { return await open(dek, vault.data, `${vault.label}|data`); } finally { wipe(dek); }
}

/** Add passkey-PRF unlock to an existing vault (needs the PIN once). */
export async function enablePrf(vault, pin, prf) {
  const dek = await dekFrom(vault, { pin });
  try { await addPrfEnvelope(vault, dek, prf); } finally { wipe(dek); }
  return vault;
}
