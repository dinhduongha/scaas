// Lazy-loaded by the portal only when the payer picks "Recovery phrase wallet".
export { normalizeMnemonic, wordsToEntropy, seedFromEntropy, deriveKey, signDigest, NETWORKS } from './seed.js';
export { createVault, openVault, enablePrf, needsRewrap, rewrapPin, checkPassphrase, SCRYPT } from './vault.js';
export { SeedBackup } from './backup.js';
export {
  hashTypedData, secpSubjectKey, passkeySubjectKey, accountSignature, merkleBatch, checkOwnerCall, checkPayment, keyProofMessage,
  checkCall, checkTradeOrder, metaTransferTypedData, tradeOrderTypedData, orderCancelTypedData,
} from './evm.js';
export { b64url, fromB64url, hex, fromHex, wipe } from './bytes.js';
