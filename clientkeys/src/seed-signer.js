// Lazy-loaded by the portal only when the payer picks "Recovery phrase wallet".
export { normalizeMnemonic, wordsToEntropy, seedFromEntropy, deriveKey, signDigest, NETWORKS } from './seed.js';
export { createVault, openVault, enablePrf, SCRYPT } from './vault.js';
export { SeedBackup } from './backup.js';
export { loadZetherProver, sealConfKey, openConfKey } from './zether.js';
export { hashTypedData, secpSubjectKey, accountSignature, merkleBatch } from './evm.js';
export { b64url, fromB64url, hex, fromHex, wipe } from './bytes.js';
