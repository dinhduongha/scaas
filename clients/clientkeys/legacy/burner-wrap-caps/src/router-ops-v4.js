// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The 25 router rows of src/evm.js's OPS table as they stood at 3fa153e4, before the Change of CTR-GOV-28 in round 3zb + 3zc
// (owner 2026-11-13, O5 / O6) added the target's chain word `bytes32 chainUid` as the last op field of every op of a role
// holder and of `UASetWrapLimits`. Their vector rows: smartcontracts/vectors/typed/legacy/burner-wrap-caps/typed_ops.json.
// Reference only: their entries have no function now. Not imported by src/.
const ON = ['GovernanceRouter'];
export const ROUTER_OPS_V4 = {
  UAMint: { fields: 'address target,address to,uint256 amount', on: ON },
  UAMintToUA: { fields: 'address target,bytes32 to,uint256 amount', on: ON },
  UADisableWrap: { fields: 'address target,address leg,bytes32 reason', on: ON },
  UAProposeRate: { fields: 'address target,address leg,uint96 num,uint96 den', on: ON },
  UACancelRate: { fields: 'address target', on: ON },
  UAExecuteRate: { fields: 'address target', on: ON },
  UASetMarket: { fields: 'address target,address base,address quote,bool listed', on: ON },
  UASetExchangeTarget: { fields: 'address target,address exchangeTarget,bool listed', on: ON },
  UASetListedOnly: { fields: 'address target,bool on', on: ON },
  UASetFeeSplit: { fields: 'address target,uint32 relayerSharePpm,address treasury', on: ON },
  UAFreeze: { fields: 'address target,bytes32 account,bytes32 ref,bytes32 recordId', on: ON },
  UAUnfreeze: { fields: 'address target,bytes32 account,bytes32 ref', on: ON },
  UAForceTransfer: { fields: 'address target,bytes32 recordId,uint256 amount', on: ON },
  UAPause: { fields: 'address target,bytes32 ref,uint64 until', on: ON },
  UAUnpause: { fields: 'address target,bytes32 ref', on: ON },
  UARecordOrder: { fields: 'address target,bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil', on: ON },
  UARevokeOrder: { fields: 'address target,bytes32 recordId,bytes32 reasonRef', on: ON },
  UASetTaxRate: { fields: 'address target,uint32 ratePpm', on: ON },
  UASetTaxRecipient: { fields: 'address target,bytes32 taxRecipient', on: ON },
  UASetProofStore: { fields: 'address target,uint8 next', on: ON },
  UAOperatorTransfer: { fields: 'address target,bytes32 account,bytes32 to,uint256 amount,bytes32 ref', on: ON },
  UASetWrapLimits: { fields: 'address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList', on: ON },
  UASetWrapMember: { fields: 'address target,bytes32 account,bool canWrap,bool canUnwrap', on: ON },
  UASetAllowed: { fields: 'address target,bytes32[] accounts,bool on', on: ON },
  UASetDenied: { fields: 'address target,bytes32[] accounts,bool on', on: ON },
};
