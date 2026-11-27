// Encrypted-at-rest secrets (R32, RS4-8). A random 32-byte data key (DEK) encrypts the secret with
// AES-256-GCM (WebCrypto, fresh 12-byte IV per encryption). The DEK is wrapped by:
//   - a passphrase via scrypt (N=2^17, r=8, p=1, 16-byte salt; ~0.5 s in Node 26) — ALWAYS present,
//     so a browser without the passkey PRF extension can still open the vault (review SEC-17). A new
//     passphrase needs 8+ characters and not only digits (review S4-M3); vaults sealed by older
//     clients (N=2^15, 6-digit PIN) still open and are re-wrapped on unlock (`rewrapPin`);
//   - optionally the passkey PRF output (HKDF-SHA256) — unlock without typing the PIN.
// No wrapping key and no plaintext is ever stored. The vault object is plain JSON (localStorage).
// Vault v2 (owner 2026-11-19, scaas-sdk T13b ruling 3): `{v: 2, id, label, data, pin, prf?}`, `id` a lower-case UUID v4 (a
// keystore seed's id, else a fresh one), and every AAD `<id>|<label>|<part>`, so a vault moved under another seed (another id)
// no longer opens. v 1 and the device-move tombstone `{v: 2, moved}` are `VaultVersion` (no migration: nothing is live).
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes, b64url, fromB64url, wipe } from "./bytes.js";

export const SCRYPT = Object.freeze({ N: 2 ** 17, r: 8, p: 1, dkLen: 32 });
const VERSION = 2;
/** A vault id: a lower-case UUID v4. */
export const VAULT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PIN_N = Object.freeze([2 ** 15, 2 ** 16, 2 ** 17]); // CLI-SGN-21: the only N an envelope may carry
const PRF_INFO = utf8ToBytes("scaas-clientkeys-vault-v1/prf");
/** An error with the status name every client shares (`VaultOpen`, `VaultParams`, `VaultVersion`, `VaultFormat`, `Argument`;
 *  ua-rs-sign §8.1). */
const refuse = (code, message) => {
  throw Object.assign(new Error(message), { code });
};
const SEED_LENGTHS = Object.freeze([16, 20, 24, 28, 32]); // BIP-39 entropy of 12, 15, 18, 21, 24 words
/** The key lock (user-profiles spec §7.4, CLI-UPR-24): an imported key under its own passphrase, a pin envelope only. */
const KEY_LOCKED = "native-import-locked:";
const keyLocked = (vault) => typeof vault.label === "string" && vault.label.startsWith(KEY_LOCKED);

async function gcm(op, keyBytes, iv, data, aad) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, [op]);
  const params = { name: "AES-GCM", iv, additionalData: utf8ToBytes(aad) };
  const out =
    op === "encrypt" ? await crypto.subtle.encrypt(params, key, data) : await crypto.subtle.decrypt(params, key, data);
  return new Uint8Array(out);
}

/** AES-256-GCM box `{iv, ct}` (also the Zether balance-cache box, zether.js). */
export async function seal(keyBytes, data, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { iv: b64url(iv), ct: b64url(await gcm("encrypt", keyBytes, iv, data, aad)) };
}

export async function open(keyBytes, box, aad) {
  try {
    return await gcm("decrypt", keyBytes, fromB64url(box.iv), fromB64url(box.ct), aad);
  } catch {
    refuse("VaultOpen", "Wrong PIN or the vault was altered.");
  }
}

/** Policy for a NEW passphrase only; opening never checks it (old vaults keep working). */
export function checkPassphrase(pin) {
  const p = String(pin || "").normalize("NFKC");
  if ([...p].length < 8 || !/[^\d\s]/u.test(p)) {
    throw new Error("Choose a passphrase of at least 8 characters, not only digits.");
  }
}

async function pinKey(pin, salt, params = SCRYPT) {
  return scryptAsync(utf8ToBytes(String(pin ?? "").normalize("NFKC")), salt, params);
}

/** A fresh vault id (UUID v4) from the platform RNG. */
export function vaultId() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Every AAD of a vault: `<id>|<label>|<part>` (the id first: a UUID, it holds no `|`). */
const aad = (vault, part) => `${vault.id}|${vault.label}|${part}`;

async function pinEnvelope(vault, dek, pin, params = SCRYPT) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await pinKey(pin, salt, params);
  try {
    return {
      kdf: "scrypt",
      N: params.N,
      r: params.r,
      p: params.p,
      salt: b64url(salt),
      ...(await seal(kek, dek, aad(vault, "pin"))),
    };
  } finally {
    wipe(kek);
  }
}

function prfKey(prfOutput) {
  return hkdf(sha256, prfOutput, undefined, PRF_INFO, 32);
}

/** `label` names what is inside ('seed', 'zether-conf:…'); `id` is the vault's (a keystore seed's id; a fresh UUID v4 by
 *  default). Both are bound into every AAD. */
export async function createVault(secret, { label, pin, prf, id }) {
  checkPassphrase(pin);
  const vid = id ?? vaultId();
  if (!VAULT_ID.test(vid)) refuse("Argument", "A vault id is a lower-case UUID v4.");
  const dek = crypto.getRandomValues(new Uint8Array(32));
  try {
    const head = { v: VERSION, id: vid, label };
    const vault = { ...head, data: await seal(dek, secret, aad(head, "data")), pin: await pinEnvelope(head, dek, pin) };
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
    return { ...structuredClone(vault), pin: await pinEnvelope(vault, dek, newPin, params) };
  } finally {
    wipe(dek);
  }
}

async function addPrfEnvelope(vault, dek, { output, credentialId, salt }) {
  if (keyLocked(vault)) refuse("Argument", "A key-locked vault takes no passkey or platform unlock.");
  const kek = prfKey(output);
  try {
    vault.prf = { credentialId, salt: b64url(salt), ...(await seal(kek, dek, aad(vault, "prf"))) };
  } finally {
    wipe(kek);
  }
}

async function dekFrom(vault, { pin, prfOutput }) {
  // v 1 and the tombstone `{v: 2, moved}` too: never a wrong passphrase
  if (vault.v !== VERSION || Object.hasOwn(vault, "moved")) refuse("VaultVersion", "Unknown vault version.");
  if (typeof vault.id !== "string" || !VAULT_ID.test(vault.id))
    refuse("Argument", "A vault id is a lower-case UUID v4.");
  // before any KDF: a key-locked vault opens by its own typed passphrase only (null is no envelope, as ua-rs reads it)
  if (keyLocked(vault) && vault.prf != null) refuse("VaultFormat", "A key-locked vault with a passkey envelope.");
  if (prfOutput) {
    if (!vault.prf) throw new Error("This vault has no passkey unlock.");
    const kek = prfKey(prfOutput);
    try {
      return await open(kek, vault.prf, aad(vault, "prf"));
    } finally {
      wipe(kek);
    }
  }
  const p = vault.pin;
  // CLI-SGN-21: refuse a stored envelope outside the known parameters before scrypt runs (a crafted N would exhaust memory).
  if (!PIN_N.includes(p?.N) || p.r !== 8 || p.p !== 1) refuse("VaultParams", "Unsupported vault parameters.");
  const kek = await pinKey(pin, fromB64url(p.salt), { N: p.N, r: p.r, p: p.p, dkLen: 32 });
  try {
    return await open(kek, p, aad(vault, "pin"));
  } finally {
    wipe(kek);
  }
}

/** Returns the secret bytes; the caller wipes them as soon as it is done. */
export async function openVault(vault, unlock) {
  const dek = await dekFrom(vault, unlock);
  try {
    return await open(dek, vault.data, aad(vault, "data"));
  } finally {
    wipe(dek);
  }
}

/** The seed vault (label `seed`): the BIP-39 entropy at its own length, 16, 20, 24, 28 or 32 bytes (spec §8.1, C-10); any other
 *  length is refused (`VaultOpen`) before a wallet is built, never padded or cut. Another label: `Argument`. */
export async function openSeedVault(vault, unlock) {
  // another v, or the tombstone: VaultVersion first
  if (vault?.v === VERSION && !Object.hasOwn(vault, "moved") && vault.label !== "seed")
    refuse("Argument", "Not a seed vault.");
  const entropy = await openVault(vault, unlock);
  if (!SEED_LENGTHS.includes(entropy.length)) {
    wipe(entropy);
    refuse("VaultOpen", "The seed vault does not hold BIP-39 entropy.");
  }
  return entropy;
}

/** The vault with `data` replaced by `secret` sealed under the vault's same DEK (a fresh IV); the pin and PRF envelopes are kept
 *  as they are, so a session opened by either can persist a changed secret (a manifest) and both still open it (scaas-sdk spec
 *  §6.10). Returns a new vault object; the caller stores it. */
export async function resealData(vault, unlock, secret) {
  const dek = await dekFrom(vault, unlock);
  try {
    return { ...structuredClone(vault), data: await seal(dek, secret, aad(vault, "data")) };
  } finally {
    wipe(dek);
  }
}

/** Add passkey-PRF unlock to an existing vault (needs the PIN once). */
export async function enablePrf(vault, pin, prf) {
  const dek = await dekFrom(vault, { pin });
  try {
    await addPrfEnvelope(vault, dek, prf);
  } finally {
    wipe(dek);
  }
  return vault;
}
