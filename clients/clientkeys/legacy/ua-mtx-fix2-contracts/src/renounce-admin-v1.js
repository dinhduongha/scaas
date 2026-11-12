// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The `UARenounceAdmin` row of src/evm.js's OPS table as it stood at a18e9464, before Fable recheck-2 P3-1 (owner 2026-11-12,
// CTR-GOV-27) added `bytes32 chainUid` (the target's chain word). Its vector row: smartcontracts/vectors/typed/legacy/
// ua-mtx-fix2-contracts/typed_ops.json. Reference only: its entry has no function now. Not imported by src/.
export const UA_RENOUNCE_ADMIN_V1 = { fields: 'address target', on: ['GovernanceRouter'] };
