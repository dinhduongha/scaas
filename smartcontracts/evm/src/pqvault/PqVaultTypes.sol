// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqVault} from "./IPqVault.sol";
import {IPqChat} from "../pqchat/IPqChat.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title The typed records of `PqVault` (spec §5.2, §5.3): the two domains, the typehashes, `hashStruct`, the ids and the
///        nonce scopes. Pinned against `smartcontracts/vectors/pqvault/` (`*TypehashIsPinned`). **UNAUDITED.**
library PqVaultTypes {
    /// @notice `keccak256("scaas.pqvault.v1")`: PqVault's id in the registry's open app namespace (CTR-UA-46).
    bytes32 internal constant APP_ID = keccak256("scaas.pqvault.v1");
    /// @notice `P_V = appPurpose(APP_ID)`, what every PqVault record is signed under.
    bytes32 internal constant P_V = keccak256(abi.encode(UAKinds.APP_PURPOSE_NS, APP_ID));

    bytes32 internal constant NAME_HASH = keccak256("SCaaS PqVault");
    bytes32 internal constant VERSION_HASH = keccak256("1");
    bytes32 internal constant DOMAIN_V_TYPEHASH = keccak256("EIP712Domain(string name,string version,bytes32 salt)");
    bytes32 internal constant DOMAIN_B_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    /// @notice Mode 0: no chain id, no address, `salt = APP_ID` (VC21).
    bytes32 internal constant DS_V = keccak256(abi.encode(DOMAIN_V_TYPEHASH, NAME_HASH, VERSION_HASH, APP_ID));

    bytes32 internal constant MEMBER_KEY_TYPEHASH = keccak256("MemberKey(bytes32 ua,uint64 keyId,bytes32 via)");
    bytes32 internal constant CREATE_TYPEHASH = keccak256(
        "PqVaultCreate(bytes32 creator,uint64 nonce,uint8 mode,bytes32 homeChain,address homeVaultContract,bytes32[] admins,"
        "MemberKey[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo,uint8 groupMode)"
        "MemberKey(bytes32 ua,uint64 keyId,bytes32 via)"
    );
    bytes32 internal constant EPOCH_TYPEHASH = keccak256(
        "PqVaultEpoch(bytes32 vaultId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins,"
        "MemberKey[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo)"
        "MemberKey(bytes32 ua,uint64 keyId,bytes32 via)"
    );
    bytes32 internal constant LEAVE_TYPEHASH =
        keccak256("PqVaultLeave(bytes32 vaultId,bytes32 epochId,bytes32 member,uint64 nonce)");
    bytes32 internal constant REMOVE_TYPEHASH = keccak256(
        "PqVaultRemove(bytes32 vaultId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,bytes32 admin,uint64 nonce)"
    );
    bytes32 internal constant ITEM_TYPEHASH =
        keccak256("PqVaultItem(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext)");
    bytes32 internal constant EDIT_TYPEHASH = keccak256(
        "PqVaultEdit(bytes32 itemId,bytes32 epochId,bytes32 author,uint64 nonce,uint32 version,bytes ciphertext)"
    );
    bytes32 internal constant BATCH_TYPEHASH = keccak256(
        "PqVaultBatch(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,PqVaultItem[] items)"
        "PqVaultItem(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext)"
    );

    /// @notice Id tags and nonce-scope tags (§5.3).
    bytes32 internal constant TAG_VAULT = keccak256("scaas/pqvault/v1/vault");
    bytes32 internal constant TAG_EPOCH = keccak256("scaas/pqvault/v1/epoch");
    bytes32 internal constant TAG_ITEM = keccak256("scaas/pqvault/v1/item");
    bytes32 internal constant TAG_BATCH = keccak256("scaas/pqvault/v1/batch");
    bytes32 internal constant SCOPE_VAULT = keccak256("scaas/pqvault/v1/scope/vault");
    bytes32 internal constant SCOPE_EPOCH = keccak256("scaas/pqvault/v1/scope/epoch");
    bytes32 internal constant SCOPE_ITEM = keccak256("scaas/pqvault/v1/scope/item");

    /// @notice Mode 1: `DS_B(c)`, this chain and the instance `c` (a clone: computed at run time).
    function dsB(address c) internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_B_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, c));
    }

    function typed(bytes32 ds, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", ds, structHash));
    }

    // ------------------------------------------------------------------ hashStruct

    function hashMembers(IPqChat.MemberKey[] calldata m) internal pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](m.length);
        for (uint256 i; i < m.length; ++i) {
            h[i] = keccak256(abi.encode(MEMBER_KEY_TYPEHASH, m[i].ua, m[i].keyId, m[i].via));
        }
        return keccak256(abi.encodePacked(h));
    }

    function hashCreate(IPqVault.PqVaultCreate calldata v) internal pure returns (bytes32) {
        return keccak256(
            bytes.concat(
                abi.encode(
                    CREATE_TYPEHASH,
                    v.creator,
                    v.nonce,
                    v.mode,
                    v.homeChain,
                    v.homeVaultContract,
                    keccak256(abi.encodePacked(v.admins)),
                    hashMembers(v.members)
                ),
                abi.encode(
                    keccak256(abi.encodePacked(v.wrapHashes)),
                    v.passKdf,
                    v.passSalt,
                    keccak256(v.sealedInfo),
                    v.groupMode
                )
            )
        );
    }

    function hashEpoch(IPqVault.PqVaultEpoch calldata e) internal pure returns (bytes32) {
        return keccak256(
            bytes.concat(
                abi.encode(
                    EPOCH_TYPEHASH,
                    e.vaultId,
                    e.author,
                    e.nonce,
                    e.epoch,
                    e.parentEpochId,
                    keccak256(abi.encodePacked(e.admins)),
                    hashMembers(e.members)
                ),
                abi.encode(keccak256(abi.encodePacked(e.wrapHashes)), e.passKdf, e.passSalt, keccak256(e.sealedInfo))
            )
        );
    }

    function hashLeave(IPqVault.PqVaultLeave calldata l) internal pure returns (bytes32) {
        return keccak256(abi.encode(LEAVE_TYPEHASH, l.vaultId, l.epochId, l.member, l.nonce));
    }

    function hashRemove(IPqVault.PqVaultRemove calldata r) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                REMOVE_TYPEHASH,
                r.vaultId,
                r.epochId,
                r.nextEpoch,
                keccak256(abi.encodePacked(r.members)),
                r.admin,
                r.nonce
            )
        );
    }

    function hashItem(IPqVault.PqVaultItem calldata it) internal pure returns (bytes32) {
        return
            keccak256(abi.encode(ITEM_TYPEHASH, it.vaultId, it.epochId, it.author, it.nonce, keccak256(it.ciphertext)));
    }

    function hashEdit(IPqVault.PqVaultEdit calldata d) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(EDIT_TYPEHASH, d.itemId, d.epochId, d.author, d.nonce, d.version, keccak256(d.ciphertext))
        );
    }

    function hashBatch(IPqVault.PqVaultBatch calldata b) internal pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](b.items.length);
        for (uint256 i; i < h.length; ++i) {
            h[i] = hashItem(b.items[i]);
        }
        return
            keccak256(
                abi.encode(BATCH_TYPEHASH, b.vaultId, b.epochId, b.author, b.nonce, keccak256(abi.encodePacked(h)))
            );
    }

    // ------------------------------------------------------------------ ids and scopes (§5.3)

    /// @notice Epoch 0's id too; binds the mode and the home (review r2 R5).
    function vaultId(bytes32 creator, uint64 nonce, uint8 mode, bytes32 homeChain, address homeVaultContract)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(TAG_VAULT, creator, nonce, mode, homeChain, homeVaultContract));
    }

    function epochId(bytes32 vaultId_, bytes32 author, uint64 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_EPOCH, vaultId_, author, nonce));
    }

    function itemId(bytes32 vaultId_, bytes32 author, uint64 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_ITEM, vaultId_, author, nonce));
    }

    function batchId(bytes32 vaultId_, bytes32 author, uint64 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_BATCH, vaultId_, author, nonce));
    }

    function scopeVault(bytes32 creator) internal pure returns (bytes32) {
        return keccak256(abi.encode(SCOPE_VAULT, creator));
    }

    /// @notice Rekeys, leaves and removals.
    function scopeEpoch(bytes32 vaultId_, bytes32 author) internal pure returns (bytes32) {
        return keccak256(abi.encode(SCOPE_EPOCH, vaultId_, author));
    }

    /// @notice Items, edits and batches.
    function scopeItem(bytes32 vaultId_, bytes32 author) internal pure returns (bytes32) {
        return keccak256(abi.encode(SCOPE_ITEM, vaultId_, author));
    }
}
