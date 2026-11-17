// Lazy-loaded by the portal only when the payer picks "Recovery phrase wallet".
export { normalizeMnemonic, wordsToEntropy, seedFromEntropy, deriveKey, signDigest, signTyped, signKeyProof, NETWORKS, NATIVE_NETWORKS, signMessage, MAX_RAW_MESSAGE,
  signNearTransaction, signSuiTransaction, signStellarTransaction, signHederaTransaction } from './seed.js';
export { polkadotKey, miniSecretFromEntropy, parsePolkadotPath, ss58 } from './substrate.js';
export { createVault, openVault, enablePrf, needsRewrap, rewrapPin, checkPassphrase, SCRYPT } from './vault.js';
export { SeedBackup } from './backup.js';
export {
  hashTypedData, secpSubjectKey, passkeySubjectKey, accountSignature, erc7739TypedData, erc7739Signature, merkleBatch, checkOwnerCall, checkPayment, keyProofMessage,
  checkCall, checkOp, checkTradeOrder, checkWrapOrder, checkUAWrapOrder, checkCancel, payLane, uaTradeOrderTypedData, tradeOrderTypedData, cancelUAOrderTypedData,
  cancelUAWrapOrderTypedData, invalidateNoncesTypedData, uaInvalidateNoncesTypedData,
  uaMetaTxTypedData, uaMetaTransferTypedData, padId,
  metaPayId, payMeta, payNoFromUuid, payNoToUuid, encodeMetaBody, decodeMetaBody, payMetaWarning, checkPayMeta, buildPay, buildPayWithPayeeFee,
  buildPayWithTax, percentTax, relayRef, mtxExecuteCalldata, mtxExecuteTransferCalldata, buildRelayFee,
} from './evm.js';
export { b64url, fromB64url, hex, fromHex, wipe } from './bytes.js';
