// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T8b: the rows on the `zether` kind (with `pqz` where the node's row names both: the shields): the rollovers, the
//! confidential transfers and unshields, the owner statements. A copy of `scaas-node/src/typed.rs` `TYPED`, held equal by
//! `tests/entries.rs`.
use super::Def;

const ZP: &[&str] = &["zether", "pqz"];
const Z: &[&str] = &["zether"];
const OWNER_ROLL_PLAN: &str = "E ua expectedPendingSeq validUntilBlock ownerSig:UASig @";
const OWNER_MODE_PLAN: &str = "E ua rollOverMode validUntilBlock ownerSig:UASig @";

pub(super) const ROWS: &[Def] = &[
    (
        "UAShield",
        "mtxShield",
        ZP,
        "bytes32 from,bytes32 toUA,uint256 amount,E",
        "",
    ),
    (
        "WrapShield",
        "mtxWrapShield",
        ZP,
        "address from,address underlying,uint256 amountIn,bytes32 toUA,E",
        "",
    ),
    (
        "UARollOver",
        "mtxRollOver",
        Z,
        "bytes32 from,bytes32 ua,uint256 n,E",
        "",
    ),
    (
        "UAZetherTransferSingle",
        "mtxConfidentialTransferSingle",
        Z,
        "bytes32 from,ZetherSingle args,bytes proof,E",
        "",
    ),
    (
        "UAZetherTransfer",
        "mtxConfidentialTransfer",
        Z,
        "bytes32 from,ZetherMulti args,bytes proof,E",
        "",
    ),
    (
        "UAZetherTransferCompact",
        "mtxConfidentialTransferCompact",
        Z,
        "bytes32 from,ZetherMulti args,bytes proof,E",
        "",
    ),
    (
        "UAZetherUnshield",
        "mtxUnshield",
        Z,
        "bytes32 from,ZetherBurn args,uint256 amount,bytes32 recipient,bytes proof,E",
        "",
    ),
    (
        "UAZetherUnshieldUnwrap",
        "mtxUnshieldUnwrap",
        Z,
        "bytes32 from,ZetherBurn args,Unwrap unwrap,bytes proof,E",
        "",
    ),
    (
        "UARollOverSigned",
        "mtxRollOverSigned",
        Z,
        "bytes32 from,bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock,E",
        OWNER_ROLL_PLAN,
    ),
    (
        "UASetRollOverMode",
        "mtxSetRollOverMode",
        Z,
        "bytes32 from,bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock,E",
        OWNER_MODE_PLAN,
    ),
    (
        "UARollOverBatch",
        "mtxRollOverBatch",
        Z,
        "bytes32 from,bytes32[] uas,E",
        "",
    ),
    (
        "ZetherRollOver",
        "mtxRollOverSigned",
        Z,
        "bytes32 ua,uint64 accSeq,uint64 expectedPendingSeq,uint64 validUntilBlock",
        "ua expectedPendingSeq validUntilBlock @ua",
    ),
    (
        "ZetherSetRollOverMode",
        "mtxSetRollOverMode",
        Z,
        "bytes32 ua,uint8 mode,uint64 modeNonce,uint64 validUntilBlock",
        "ua mode validUntilBlock @ua",
    ),
    // set-auditor (spec §5.2): the new auditor's consent in a confidential token's domain, no entry (relayed beside the
    // holder's op, never built here)
    (
        "AuditorConsent",
        "",
        ZP,
        "address token,bytes32 auditor,uint32 epoch,bytes32 chainUid",
        "",
    ),
];
