// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T8e: the `SmartKeyAccount` rows (`account`): its own entries, signed with `AccountSig`; `mtxCancelNonce` takes `bytes`.
//! A copy of `scaas-node/src/typed.rs` `TYPED`, held equal by `tests/entries.rs`.
use super::Def;

use super::A;

pub(super) const ROWS: &[Def] = &[
    ("CancelNonce", "mtxCancelNonce", A, "address from,uint256 lane,E", "E lane @bytes"),
    ("AddKey", "mtxAddKey", A, "address from,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash,E", ""),
    ("RemoveKey", "mtxRemoveKey", A, "address from,uint256 index,E", ""),
    ("RotateKey", "mtxRotateKey", A, "address from,uint256 index,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash,E", ""),
    ("SetGuardian", "mtxSetGuardian", A, "address from,address guardian,E", ""),
    ("CancelRecovery", "mtxCancelRecovery", A, "address from,E", ""),
    ("Execute", "mtxExecute", A, "address from,address target,uint256 value,bytes data,E", ""),
];
