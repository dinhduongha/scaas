// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The scaas-sdk keystore's index MAC (scaas-sdk spec §6.2, CLI-SDK-03): a seed entry's public fields and its vault texts
// authenticated under a key of the seed's own BIP-39 entropy (owner 2026-11-19, T13b ruling 3: the MAC covers the vault texts):
//   k        = HKDF-SHA256(ikm = entropy, salt = "", info = "scaas.keystore.index.v2", 32)
//   indexMac = HMAC-SHA256(k, canonical), as 64 lower-case hex digits
//   canonical = JSON.stringify of exactly INDEX_FIELDS in that order (no white space; the accounts rows as given; `vaults` the
//               label → vault text object with its keys sorted)
// ua-rs `Wallet::index_mac` computes the same bytes. UNAUDITED.
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes, wipe } from './bytes.js';

const INFO = utf8ToBytes('scaas.keystore.index.v2');
export const INDEX_FIELDS = Object.freeze(['id', 'label', 'words', 'fingerprint', 'origin', 'class', 'warnings', 'backup', 'accounts', 'vaults']);

/** The MAC's input: the entry's fields of INDEX_FIELDS, in that order, every one present (an `Error` otherwise). */
export function indexCanonical(fields) {
  const o = {};
  for (const k of INDEX_FIELDS) {
    if (!Object.hasOwn(fields, k)) throw new Error(`index field missing: ${k}`);
    o[k] = k === 'vaults' ? Object.fromEntries(Object.keys(fields.vaults).sort().map((l) => [l, fields.vaults[l]])) : fields[k];
  }
  return JSON.stringify(o);
}

/** The index MAC of a seed entry (`entropy`: the seed vault's BIP-39 entropy, 16 to 32 bytes). */
export function indexMac(entropy, fields) {
  const k = hkdf(sha256, entropy, new Uint8Array(0), INFO, 32);
  try {
    return bytesToHex(hmac(sha256, k, utf8ToBytes(indexCanonical(fields))));
  } finally {
    wipe(k);
  }
}
