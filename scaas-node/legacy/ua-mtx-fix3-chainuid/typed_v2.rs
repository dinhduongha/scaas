// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The node's twelve router rows (`src/typed.rs` `TYPED`) as they stood at cac043bc, before CTR-GOV-28 (owner 2026-11-13)
//! added the target's chain word `bytes32 chainUid` as the last op field of every admin op of a token, the DEX and a
//! compliance registry (a job without it is now `BAD_PAYLOAD`, `args.chainUid: missing`). (`"GR"`: the table's router
//! domain.) Their vector rows: `smartcontracts/vectors/typed/legacy/ua-mtx-fix3-chainuid/typed_ops.json`. Reference only; not built.
pub const ROUTER_ROWS_V2: [(&str, &str, &str, &str, &str); 13] = [
    ("UAGrantRole", "mtxGrantRole", "GR", "bytes32 from,address target,uint8 bit,bytes32 account,E", ""),
    ("UARevokeRole", "mtxRevokeRole", "GR", "bytes32 from,address target,uint8 bit,bytes32 account,E", ""),
    ("UASetGrant", "mtxSetGrant", "GR", "bytes32 from,address target,uint8 bit,bytes32 holder,GrantTerms terms,E", ""),
    ("UACancelGrant", "mtxCancelGrant", "GR", "bytes32 from,address target,uint8 bit,bytes32 account,E", ""),
    ("UADisableFeature", "mtxDisableFeature", "GR", "bytes32 from,address target,uint8 bit,E", ""),
    ("UAPqzSetVerifier", "mtxPqzSetVerifier", "GR", "bytes32 from,address target,bytes32 next,E", ""),
    ("UAPqzCancelVerifier", "mtxPqzCancelVerifier", "GR", "bytes32 from,address target,E", ""),
    ("UAPqzRevokeVerifier", "mtxPqzRevokeVerifier", "GR", "bytes32 from,address target,E", ""),
    ("UASetVerifierFee", "mtxSetVerifierFee", "GR", "bytes32 from,address target,uint64 next,E", ""),
    ("UAEnableFeature", "mtxEnableFeature", "GR", "bytes32 from,address target,uint8 bit,E", ""),
    ("UASetKycProvider", "mtxSetKycProvider", "GR", "bytes32 from,address target,bytes32 provider,bool enabled,E", ""),
    ("UASetCompliance", "mtxSetCompliance", "GR", "bytes32 from,address target,bytes32[] accounts,uint64[] flags,uint64[] until,E", ""),
    // as it stood at baa42a33, before the owner's ruling of 2026-11-13 (renounceRole carries the chain word too)
    ("UARenounceRole", "mtxRenounceRole", "GR", "bytes32 from,address target,uint8 bit,E", ""),
];
