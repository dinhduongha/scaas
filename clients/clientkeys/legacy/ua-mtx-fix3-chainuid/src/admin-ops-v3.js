// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The rows of src/evm.js's OPS table as they stood at cac043bc, before CTR-GOV-28 (owner 2026-11-13) added the target's chain
// word `bytes32 chainUid` as the last op field of every admin op of a token, the DEX and a compliance registry.
// Their vector rows: smartcontracts/vectors/typed/legacy/ua-mtx-fix3-chainuid/typed_ops.json. Reference only: their entries
// have no function now. Not imported by src/.
const ON = ['GovernanceRouter'];
export const ADMIN_OPS_V3 = {
  UAGrantRole: { fields: 'address target,uint8 bit,bytes32 account', on: ON },
  UARevokeRole: { fields: 'address target,uint8 bit,bytes32 account', on: ON },
  UASetGrant: { fields: 'address target,uint8 bit,bytes32 holder,GrantTerms terms', on: ON },
  UACancelGrant: { fields: 'address target,uint8 bit,bytes32 account', on: ON },
  UADisableFeature: { fields: 'address target,uint8 bit', on: ON },
  UAEnableFeature: { fields: 'address target,uint8 bit', on: ON },
  UAPqzSetVerifier: { fields: 'address target,bytes32 next', on: ON },
  UAPqzCancelVerifier: { fields: 'address target', on: ON },
  UAPqzRevokeVerifier: { fields: 'address target', on: ON },
  UASetVerifierFee: { fields: 'address target,uint64 next', on: ON },
  UASetKycProvider: { fields: 'address target,bytes32 provider,bool enabled', on: ON },
  UASetCompliance: { fields: 'address target,bytes32[] accounts,uint64[] flags,uint64[] until', on: ON },
};
