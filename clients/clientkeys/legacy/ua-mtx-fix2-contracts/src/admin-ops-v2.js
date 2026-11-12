// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The rows of src/evm.js's OPS table as they stood at aeb1da09, before CTR-GOV-27 (the rest of Fable recheck-2 P3-1, owner
// 2026-11-12) added the target's chain word `bytes32 chainUid` to them and made `UASetChainEntries` one nested `ChainEntries`.
// Their vector rows: smartcontracts/vectors/typed/legacy/ua-mtx-fix2-contracts/typed_ops-a2.json. Reference only: their
// entries have no function now. Not imported by src/.
const ON = ['GovernanceRouter'];
export const ADMIN_OPS_V2 = {
  UATransferAdmin: { fields: 'address target,bytes32 newAdmin', on: ON },
  UAPublishTokenEnv: { fields: 'address target,uint8 kind,uint16 envVersion,Env env', on: ON },
  UAPublishDexEnv: { fields: 'address target,uint16 envVersion,Env env', on: ON },
  UAPublishClassEnv: { fields: 'address target,uint16 contractClass,uint16 kind,uint16 envVersion,Env env', on: ON },
  UARevokeApproval: { fields: 'address target,bytes32 key', on: ON },
  UASetChainEntries: { fields: 'address target,address relayFeeRouter,bytes32 relayFeeRouterCodeHash,bytes32 relayFeeExecutorCodeHash,'
    + 'address complianceRegistry,bytes32 complianceRegistryCodeHash,address smartKeyAccountFactory,bytes32 smartKeyAccountFactoryCodeHash,'
    + 'address zetherStatements,bytes32 zetherStatementsCodeHash', on: ON },
};
