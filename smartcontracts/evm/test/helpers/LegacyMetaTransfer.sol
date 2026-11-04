// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// The address `MetaTransfer` as `MetaTxLib` held it before ua-mtx-merge T2 (R46; the source is in
/// legacy/ua-mtx-merge/src/common/MetaTxLib.sol). No token entry takes it any more: tests use it to sign the retired
/// form and show it is refused (invariant 3), and to keep its typehash pinned.
library LegacyMetaTransfer {
    struct MetaTransfer {
        address from;
        address to;
        uint256 value;
        bytes32 entryRef;
        uint256 batch;
        uint256 nonce;
        uint256 validUntil;
        uint32 mode;
        address relayer;
        uint256 fee;
        address feeRecipient;
    }

    bytes32 internal constant TYPEHASH = keccak256(
        "MetaTransfer(address from,address to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

    uint32 private constant MODE_RESTRICT_RELAYER = 1 << 0;
    uint32 private constant MODE_RESTRICT_FEE_RECIPIENT = 1 << 1;

    /// The struct hash, relayer and fee recipient hashed as 0 when their mode bit is off (as `MetaTxLib.canon` did).
    function hashStruct(MetaTransfer memory t) internal pure returns (bytes32) {
        address r = t.mode & MODE_RESTRICT_RELAYER != 0 ? t.relayer : address(0);
        address f = t.mode & MODE_RESTRICT_FEE_RECIPIENT != 0 ? t.feeRecipient : address(0);
        return keccak256(abi.encode(
            TYPEHASH, t.from, t.to, t.value, t.entryRef, t.batch, t.nonce, t.validUntil, t.mode, r, t.fee, f
        ));
    }
}
