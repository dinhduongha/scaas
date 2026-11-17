// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The rows of `src/admin.rs`'s `ADMIN_OPS` as they stood at aeb1da09, before CTR-GOV-27 (the rest of Fable recheck-2 P3-1,
//! owner 2026-11-12) added the target's chain word `bytes32 chainUid` and made `UASetChainEntries` one nested `ChainEntries`.
//! Their vector rows: `smartcontracts/vectors/typed/legacy/ua-mtx-fix2-contracts/typed_ops-a2.json`. Reference only; not built.
pub const ADMIN_OPS_V2: [(&str, &str); 6] = [
    ("UATransferAdmin", "bytes32 newAdmin"),
    ("UAPublishTokenEnv", "uint8 kind,uint16 envVersion,Env env"),
    ("UAPublishDexEnv", "uint16 envVersion,Env env"),
    ("UAPublishClassEnv", "uint16 contractClass,uint16 kind,uint16 envVersion,Env env"),
    ("UARevokeApproval", "bytes32 key"),
    ("UASetChainEntries", "address relayFeeRouter,bytes32 relayFeeRouterCodeHash,bytes32 relayFeeExecutorCodeHash,address complianceRegistry,bytes32 complianceRegistryCodeHash,address smartKeyAccountFactory,bytes32 smartKeyAccountFactoryCodeHash,address zetherStatements,bytes32 zetherStatementsCodeHash"),
];
