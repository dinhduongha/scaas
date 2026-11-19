// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T8g: the `GovernanceRouter` rows (`gov_router`; spec 2026-11-02-governance §3.2): its closed table, every op naming its target
//! and (CTR-GOV-28) the target's chain word; the creations take a named config (`init!`) or the initializer call (`initcall!`),
//! whose keccak is the signed `initHash`. The ordered cancel `UACancelNonce` is in `token.rs`. A copy of
//! `scaas-node/src/typed.rs` `TYPED`, held equal by `tests/entries.rs`.
use super::Def;

const GR: &[&str] = &["gov_router"];

pub(super) const ROWS: &[Def] = &[
    ("UAGrantRole", "mtxGrantRole", GR, "bytes32 from,address target,uint8 bit,bytes32 account,bytes32 chainUid,E", ""),
    ("UARevokeRole", "mtxRevokeRole", GR, "bytes32 from,address target,uint8 bit,bytes32 account,bytes32 chainUid,E", ""),
    ("UASetGrant", "mtxSetGrant", GR, "bytes32 from,address target,uint8 bit,bytes32 holder,GrantTerms terms,bytes32 chainUid,E", ""),
    ("UACancelGrant", "mtxCancelGrant", GR, "bytes32 from,address target,uint8 bit,bytes32 account,bytes32 chainUid,E", ""),
    ("UADisableFeature", "mtxDisableFeature", GR, "bytes32 from,address target,uint8 bit,bytes32 chainUid,E", ""),
    ("UATransferAdmin", "mtxTransferAdmin", GR, "bytes32 from,address target,bytes32 newAdmin,bytes32 chainUid,E", ""),
    ("UAAcceptAdmin", "mtxAcceptAdmin", GR, "bytes32 from,address target,E", ""),
    ("UARenounceAdmin", "mtxRenounceAdmin", GR, "bytes32 from,address target,bytes32 chainUid,E", ""),
    ("UARenounceRole", "mtxRenounceRole", GR, "bytes32 from,address target,uint8 bit,bytes32 chainUid,E", ""),
    ("UAMint", "mtxMint", GR, "bytes32 from,address target,address to,uint256 amount,bytes32 chainUid,E", ""),
    ("UAMintToUA", "mtxMintToUA", GR, "bytes32 from,address target,bytes32 to,uint256 amount,bytes32 chainUid,E", ""),
    ("UADisableWrap", "mtxDisableWrap", GR, "bytes32 from,address target,address leg,bytes32 reason,bytes32 chainUid,E", ""),
    ("UAProposeRate", "mtxProposeRate", GR, "bytes32 from,address target,address leg,uint96 num,uint96 den,bytes32 chainUid,E", ""),
    ("UACancelRate", "mtxCancelRate", GR, "bytes32 from,address target,bytes32 chainUid,E", ""),
    ("UAExecuteRate", "mtxExecuteRate", GR, "bytes32 from,address target,bytes32 chainUid,E", ""),
    ("UASetMarket", "mtxSetMarket", GR, "bytes32 from,address target,address base,address quote,bool listed,bytes32 chainUid,E", ""),
    ("UASetExchangeTarget", "mtxSetExchangeTarget", GR, "bytes32 from,address target,address exchangeTarget,bool listed,bytes32 chainUid,E", ""),
    ("UASetListedOnly", "mtxSetListedOnly", GR, "bytes32 from,address target,bool on,bytes32 chainUid,E", ""),
    ("UASetFeeSplit", "mtxSetFeeSplit", GR, "bytes32 from,address target,uint32 relayerSharePpm,address treasury,bytes32 chainUid,E", ""),
    ("UAFreeze", "mtxFreeze", GR, "bytes32 from,address target,bytes32 account,bytes32 ref,bytes32 recordId,bytes32 chainUid,E", ""),
    ("UAUnfreeze", "mtxUnfreeze", GR, "bytes32 from,address target,bytes32 account,bytes32 ref,bytes32 chainUid,E", ""),
    ("UAForceTransfer", "mtxForceTransfer", GR, "bytes32 from,address target,bytes32 recordId,uint256 amount,bytes32 chainUid,E", ""),
    ("UAPause", "mtxPause", GR, "bytes32 from,address target,bytes32 ref,uint64 until,bytes32 chainUid,E", ""),
    ("UAUnpause", "mtxUnpause", GR, "bytes32 from,address target,bytes32 ref,bytes32 chainUid,E", ""),
    ("UARecordOrder", "mtxRecordOrder", GR, "bytes32 from,address target,bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil,bytes32 chainUid,E", ""),
    ("UARevokeOrder", "mtxRevokeOrder", GR, "bytes32 from,address target,bytes32 recordId,bytes32 reasonRef,bytes32 chainUid,E", ""),
    ("UAOperatorTransfer", "mtxOperatorTransfer", GR, "bytes32 from,address target,bytes32 account,bytes32 to,uint256 amount,bytes32 ref,bytes32 chainUid,E", ""),
    ("UASetTaxRate", "mtxSetTaxRate", GR, "bytes32 from,address target,uint32 ratePpm,bytes32 chainUid,E", ""),
    ("UASetTaxRecipient", "mtxSetTaxRecipient", GR, "bytes32 from,address target,bytes32 taxRecipient,bytes32 chainUid,E", ""),
    ("UAPqzSetVerifier", "mtxPqzSetVerifier", GR, "bytes32 from,address target,bytes32 next,bytes32 chainUid,E", ""),
    ("UAPqzCancelVerifier", "mtxPqzCancelVerifier", GR, "bytes32 from,address target,bytes32 chainUid,E", ""),
    ("UAPqzRevokeVerifier", "mtxPqzRevokeVerifier", GR, "bytes32 from,address target,bytes32 chainUid,E", ""),
    ("UASetProofStore", "mtxSetProofStore", GR, "bytes32 from,address target,uint8 next,bytes32 chainUid,E", ""),
    // set-auditor (CTR-GOV-31): the new auditor's consent rides unsigned beside the struct (`pop` bytes on Zether, `consent`
    // a `UASig` on PQZ)
    ("UASetAuditorKey", "mtxSetAuditorKey", GR, "bytes32 from,address target,bytes newKey,uint32 epoch,bytes32 chainUid,E",
        "E target newKey epoch pop:bytes chainUid @"),
    ("UASetAuditorUA", "mtxSetAuditorUA", GR, "bytes32 from,address target,bytes32 newAuditor,uint32 epoch,bytes32 chainUid,E",
        "E target newAuditor epoch consent:UASig chainUid @"),
    ("UASetVerifierFee", "mtxSetVerifierFee", GR, "bytes32 from,address target,uint64 next,bytes32 chainUid,E", ""),
    ("UASetWrapLimits", "mtxSetWrapLimits", GR, "bytes32 from,address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,bytes32 chainUid,E", ""),
    ("UASetWrapMember", "mtxSetWrapMember", GR, "bytes32 from,address target,bytes32 account,bool canWrap,bool canUnwrap,bytes32 chainUid,E", ""),
    ("UASetMaxSupply", "mtxSetMaxSupply", GR, "bytes32 from,address target,uint256 maxSupply,bytes32 chainUid,E", ""),
    ("UASetMaxWrapSupply", "mtxSetMaxWrapSupply", GR, "bytes32 from,address target,uint256 maxWrapSupply,bytes32 chainUid,E", ""),
    ("UASetAllowed", "mtxSetAllowed", GR, "bytes32 from,address target,bytes32[] accounts,bool on,bytes32 chainUid,E", ""),
    ("UASetDenied", "mtxSetDenied", GR, "bytes32 from,address target,bytes32[] accounts,bool on,bytes32 chainUid,E", ""),
    ("UAEnableFeature", "mtxEnableFeature", GR, "bytes32 from,address target,uint8 bit,bytes32 chainUid,E", ""),
    ("UAPublishTokenEnv", "mtxPublishTokenEnv", GR, "bytes32 from,address target,uint8 kind,uint16 envVersion,bytes32 chainUid,Env env,E", ""),
    ("UAPublishDexEnv", "mtxPublishDexEnv", GR, "bytes32 from,address target,uint16 envVersion,bytes32 chainUid,Env env,E", ""),
    ("UAPublishClassEnv", "mtxPublishClassEnv", GR, "bytes32 from,address target,uint16 contractClass,uint16 kind,uint16 envVersion,bytes32 chainUid,Env env,E", ""),
    ("UADeprecateToken", "mtxDeprecateToken", GR, "bytes32 from,address target,uint8 kind,uint64 version,bytes32 chainUid,string reason,E", ""),
    ("UADeprecateDex", "mtxDeprecateDex", GR, "bytes32 from,address target,uint64 version,bytes32 chainUid,string reason,E", ""),
    ("UADeprecateRelease", "mtxDeprecateRelease", GR, "bytes32 from,address target,uint16 contractClass,uint16 kind,uint64 version,bytes32 chainUid,string reason,E", ""),
    ("UASetTokenKindEnabled", "mtxSetTokenKindEnabled", GR, "bytes32 from,address target,uint8 kind,bool on,bytes32 chainUid,E", ""),
    ("UASetClassKindEnabled", "mtxSetClassKindEnabled", GR, "bytes32 from,address target,uint16 contractClass,uint16 kind,bool on,bytes32 chainUid,E", ""),
    ("UASetKycProvider", "mtxSetKycProvider", GR, "bytes32 from,address target,bytes32 provider,bool enabled,bytes32 chainUid,E", ""),
    ("UASetCompliance", "mtxSetCompliance", GR, "bytes32 from,address target,bytes32[] accounts,uint64[] flags,uint64[] until,bytes32 chainUid,E", ""),
    ("UACreateToken", "mtxCreateToken", GR, "bytes32 from,address target,uint8 kind,uint64 version,bytes32 initHash,bytes32 salt,E",
        "E target kind version init!config:TokenConfig salt @"),
    ("UACreateDex", "mtxCreateDex", GR, "bytes32 from,address target,uint64 version,bytes32 initHash,bytes32 salt,E",
        "E target version init!config:DexConfig salt @"),
    ("UACreateInstance", "mtxCreateInstance", GR, "bytes32 from,address target,uint16 contractClass,uint16 kind,uint64 version,bytes32 initHash,bytes32 salt,E",
        "E target contractClass kind version initcall! salt @"),
    ("UASetChainEntries", "mtxSetChainEntries", GR, "bytes32 from,address target,ChainEntries entries,bytes32 chainUid,E", ""),
];

/// Round 3r (spec §5.6, Q3): the release approvals and their revocation have no node row (release management is no node job,
/// owner 2026-11-10; the node's `testkit::NO_NODE_ROW`): calldata for self-relay, no job op. `mtxApproveRelease` takes the
/// release's words as one tuple (the factory's `GenericRelease`); the struct signs them flat.
pub(super) const NO_NODE_ROW: &[Def] = &[
    ("UAApproveTokenRelease", "mtxApproveTokenRelease", GR, "bytes32 from,address target,uint8 kind,uint64 version,uint16 envVersion,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until,E", ""),
    ("UAApproveDexRelease", "mtxApproveDexRelease", GR, "bytes32 from,address target,uint64 version,uint16 envVersion,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until,E", ""),
    ("UAApproveRelease", "mtxApproveRelease", GR, "bytes32 from,address target,uint16 contractClass,uint16 kind,uint64 version,uint16 envVersion,bytes4 initSelector,bytes4 interfaceId,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until,E", "E target (contractClass,kind,version,envVersion,initSelector,interfaceId,initcodeHash,implArgsHash,chainUid,factory,adminGeneration,until) @"),
    ("UARevokeApproval", "mtxRevokeApproval", GR, "bytes32 from,address target,bytes32 key,bytes32 chainUid,E", ""),
];
