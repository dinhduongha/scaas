// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The receiver-fee names of src/evm.js as they stood at 202a05a9, before the payee-fee rename (owner 2026-11-12,
// CTR-MTX-86): the OPS row `UAReceiverFee` (entry `mtxPayReceiverFee`; now `UAPayeeFee` / `mtxPayWithPayeeFee`, the same
// fields), and the functions `uaReceiverFeeTypedData`, `uaReceiverFeeCalldata`, `checkReceiverFee`, `buildPayReceiverFee`
// (its `rfValidUntil`), now `uaPayeeFeeTypedData`, `uaPayeeFeeCalldata`, `checkPayeeFee`, `buildPayWithPayeeFee`
// (`pfValidUntil`), the same bodies; `checkReceiverFee` refused any `primaryType` but `UAReceiverFee`. src/ua.js and
// src/zether.js named the UA purpose `receiver-fee` (now `payee-fee`). Its vector row: smartcontracts/vectors/typed/legacy/
// ua-mtx-fix2-contracts/typed_ops.json. Reference only: its entry has no function now. Not imported by src/.
export const UA_RECEIVER_FEE_V1 = { name: 'UAReceiverFee', entry: 'mtxPayReceiverFee', fields: 'UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil', purpose: 'receiver-fee' };
export const RENAMED_V1 = Object.freeze({ uaReceiverFeeTypedData: 'uaPayeeFeeTypedData', uaReceiverFeeCalldata: 'uaPayeeFeeCalldata',
  checkReceiverFee: 'checkPayeeFee', buildPayReceiverFee: 'buildPayWithPayeeFee' });
