// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../ua/IUARegistry.sol";
import {IPqChat} from "../pqchat/IPqChat.sol";

/// @title `PqVault` (CTR-PQV-01): post-quantum encrypted notes and passwords in contract state, a factory kind (class 4, kind 0,
///        CTR-PQV-13).
/// @notice Spec `docs/superpowers/specs/2026-11-17-pqvault.md` §5; rules `docs/contracts/pqvault.md`. A vault is a key group
///         with PqChat's epochs and KEM wraps (one member or more), its items keep every version. Every record is a typed
///         EIP-712 struct in its vault's domain (mode 0: `DS_V`, portable; mode 1: `DS_B`, this instance), signed as a `UASig`
///         over `uaMessage(kind, P_V, typed(record))`, `P_V = appPurpose(keccak256("scaas.pqvault.v1"))`, and checked by the
///         registry's `requirePortableApp` (mode 0) or `requireAuthorized` (mode 1) (CTR-PQV-03, CTR-PQV-17). Anyone submits a
///         record; none carries a fee, a deadline or a submitter. The group types are PqChat's (`IPqChat.MemberKey`,
///         `IPqChat.Wrap`). **UNAUDITED.**
interface IPqVault {
    // ------------------------------------------------------------------ records (spec §5.2)

    /// @notice Epoch 0 (CTR-PQV-06): `mode` 0 portable, 1 chain-bound (then the home is this instance); `passKdf` 0 means no
    ///         passphrase and `passSalt` 0, else `passSalt` != 0.
    struct PqVaultCreate {
        bytes32 creator;
        uint64 nonce;
        uint8 mode;
        bytes32 homeChain;
        address homeVaultContract;
        bytes32[] admins;
        IPqChat.MemberKey[] members;
        bytes32[] wrapHashes;
        uint16 passKdf;
        bytes32 passSalt;
        bytes sealedInfo;
        /// @notice CTR-PQV-18 (controller call 2026-11-23, PqChat's CTR-CHAT-25): 0 flat wraps, fixed at creation, last; 0 only
        uint8 groupMode;
    }

    /// @notice An epoch >= 1, authored by an admin of its parent (CTR-PQV-13).
    struct PqVaultEpoch {
        bytes32 vaultId;
        bytes32 author;
        uint64 nonce;
        uint64 epoch;
        bytes32 parentEpochId;
        bytes32[] admins;
        IPqChat.MemberKey[] members;
        bytes32[] wrapHashes;
        uint16 passKdf;
        bytes32 passSalt;
        bytes sealedInfo;
    }

    struct PqVaultLeave {
        bytes32 vaultId;
        bytes32 epochId;
        bytes32 member;
        uint64 nonce;
    }

    struct PqVaultRemove {
        bytes32 vaultId;
        bytes32 epochId;
        uint64 nextEpoch;
        bytes32[] members;
        bytes32 admin;
        uint64 nonce;
    }

    struct PqVaultItem {
        bytes32 vaultId;
        bytes32 epochId;
        bytes32 author;
        uint64 nonce;
        bytes ciphertext;
    }

    struct PqVaultEdit {
        bytes32 itemId;
        bytes32 epochId;
        bytes32 author;
        uint64 nonce;
        uint32 version;
        bytes ciphertext;
    }

    struct PqVaultBatch {
        bytes32 vaultId;
        bytes32 epochId;
        bytes32 author;
        uint64 nonce;
        PqVaultItem[] items;
    }

    // ------------------------------------------------------------------ views (spec §5.9)

    struct ItemView {
        bytes32 vaultId;
        uint32 versionCount;
        bytes32 batchId; // 0 for a single create
    }

    struct VersionView {
        bytes32 epochId;
        bytes32 author;
        uint64 nonce;
        uint32 version;
        bytes ciphertext;
        bytes32 sigHash;
    }

    struct LatestView {
        bytes32 itemId;
        uint32 versionCount;
        bytes32 epochId;
        bytes32 author;
        bytes ciphertext;
    }

    // ------------------------------------------------------------------ events (spec §5.10): notify only, no ciphertext

    event PqVaultCreated(bytes32 indexed vaultId, bytes32 indexed creator, bytes32 homeChain);
    event PqVaultEpochAdded(
        bytes32 indexed vaultId, bytes32 indexed epochId, bytes32 indexed parentEpochId, uint64 epoch, bytes32 author
    );
    event PqVaultWraps(bytes32 indexed epochId, uint32 first, uint32 count);
    event PqVaultEpochComplete(bytes32 indexed epochId);
    event PqVaultLeft(bytes32 indexed vaultId, bytes32 indexed epochId, bytes32 indexed member);
    event PqVaultRemoved(bytes32 indexed vaultId, bytes32 indexed epochId, bytes32 indexed admin, bytes32[] members);
    /// @notice `sig` empty for a batch item (the batch event carries it).
    event PqVaultItemCreated(
        bytes32 indexed vaultId, bytes32 indexed itemId, bytes32 indexed author, bytes32 batchId, IUARegistry.UASig sig
    );
    event PqVaultItemEdited(bytes32 indexed itemId, uint32 version, bytes32 indexed author, IUARegistry.UASig sig);
    event PqVaultBatchCreated(
        bytes32 indexed vaultId, bytes32 indexed batchId, bytes32 indexed author, uint256 count, IUARegistry.UASig sig
    );

    // ------------------------------------------------------------------ errors (spec §5.11)

    /// @notice `validateEnv`: `chainUid` 0, registry 0, no code-size limit or one under 24,576 B; a constructor id other than
    ///         class 4, kind 0, version >= 1.
    error PqVaultEnv();
    error PqVaultNotFactory();
    error PqVaultInitialized();
    error PqVaultOwnerNotCreator(bytes32 ownerUA);
    /// @notice A shape the contract checks: lengths, order, counts, the passphrase flag, the mode and its home, a ciphertext
    ///         outside 32..16,416 B, a batch item naming another vault, epoch or author.
    error PqVaultShape();
    /// @notice CTR-PQV-18: a vault's `groupMode` this release does not run (it runs 0, flat wraps).
    error PqVaultModeUnsupported(uint8 groupMode);
    error PqVaultKemKey(bytes32 member, uint64 keyId);
    /// @notice No vault, epoch or item of that id here, or a record naming a vault other than its stored epoch's.
    error PqVaultUnknown(bytes32 id);
    error PqVaultIncomplete(bytes32 epochId);
    error PqVaultEpochNumber(uint64 expected, uint64 got);
    /// @notice C9 (Change 2026-11-24, E-3): an exit naming epoch number `named` lands at a head numbered `head`, more than
    ///         `EXIT_LAG_MAX` (16) above it.
    error PqVaultExitLag(uint64 named, uint64 head);
    error PqVaultEpochTaken(bytes32 parentEpochId, bytes32 child);
    error PqVaultNotMember(bytes32 ua);
    error PqVaultNotAdmin(bytes32 ua);
    error PqVaultNonceUsed(bytes32 scope, uint64 nonce);
    error PqVaultWrapHash(bytes32 epochId, uint256 index);
    error PqVaultWrapStored(bytes32 epochId, uint256 index);
    error PqVaultRemovedKept(bytes32 epochId, bytes32 ua);
    error PqVaultVersion(uint32 expected, uint32 got);

    // ------------------------------------------------------------------ the instance

    /// @notice Once, by the factory, on a clone with its env; `ownerUA` 0 or the creator; it has no power.
    function initialize(bytes32 ownerUA) external;
    function owner() external view returns (bytes32);

    // ------------------------------------------------------------------ vaults, epochs, wraps (spec §5.5)

    function createVault(PqVaultCreate calldata v, IPqChat.Wrap[] calldata wraps, IUARegistry.UASig calldata sig)
        external
        returns (bytes32 vaultId);
    function rekeyVault(PqVaultEpoch calldata e, IPqChat.Wrap[] calldata wraps, IUARegistry.UASig calldata sig)
        external
        returns (bytes32 epochId);
    /// @notice Anyone, no signature: `wraps[j]` must hash to `wrapHashes[first + j]`.
    function addVaultWraps(bytes32 epochId, uint32 first, IPqChat.Wrap[] calldata wraps) external;
    function leaveVault(PqVaultLeave calldata l, IUARegistry.UASig calldata sig) external;
    function removeVaultMembers(PqVaultRemove calldata r, IUARegistry.UASig calldata sig) external;

    // ------------------------------------------------------------------ items (spec §5.6-§5.8)

    function createItem(PqVaultItem calldata it, IUARegistry.UASig calldata sig) external returns (bytes32 itemId);
    function editItem(PqVaultEdit calldata d, IUARegistry.UASig calldata sig) external;
    function createItems(PqVaultBatch calldata b, IUARegistry.UASig calldata sig) external returns (bytes32 batchId);

    // ------------------------------------------------------------------ recovery from state alone (spec §5.9)

    /// @notice The vaults `ua` was listed in: one entry per member at `createVault` and per member a rekey adds; append-only.
    function vaultCount(bytes32 ua) external view returns (uint256);
    function vaultsOf(bytes32 ua, uint256 offset, uint256 limit) external view returns (bytes32[] memory);
    function vaultOf(bytes32 vaultId) external view returns (PqVaultCreate memory v, IUARegistry.UASig memory sig);
    /// @notice Epoch 0 (the vault id) once complete here, then each epoch >= 1 as it completed here.
    function epochCount(bytes32 vaultId) external view returns (uint256);
    function epochsOf(bytes32 vaultId, uint256 offset, uint256 limit) external view returns (bytes32[] memory);
    function latestEpoch(bytes32 vaultId) external view returns (bytes32);
    /// @notice An epoch >= 1 (epoch 0 is the vault: `vaultOf`).
    function epochOf(bytes32 epochId) external view returns (PqVaultEpoch memory e, IUARegistry.UASig memory sig);
    function epochComplete(bytes32 epochId) external view returns (bool);
    function childOf(bytes32 parentEpochId) external view returns (bytes32);
    function wrapAt(bytes32 epochId, uint256 i) external view returns (IPqChat.Wrap memory);
    function leftIn(bytes32 epochId, bytes32 member) external view returns (bool);
    function removedIn(bytes32 epochId, bytes32 member) external view returns (bool);
    function removalCount(bytes32 epochId) external view returns (uint256);
    function removalAt(bytes32 epochId, uint256 index)
        external
        view
        returns (PqVaultRemove memory r, IUARegistry.UASig memory sig);
    function nonceUsed(bytes32 scope, uint64 nonce) external view returns (bool);
    function itemCount(bytes32 vaultId) external view returns (uint256);
    function itemsOf(bytes32 vaultId, uint256 offset, uint256 limit) external view returns (bytes32[] memory);
    function itemOf(bytes32 itemId) external view returns (ItemView memory);
    /// @notice Version `version` (1 the original, 2.. the edits); `PqVaultVersion(count, version)` outside `1..count`.
    function versionAt(bytes32 itemId, uint32 version) external view returns (VersionView memory);
    /// @notice The latest version of items `[offset, min(offset + min(limit, LATEST_RANGE_MAX), count))` of the vault.
    function latestRange(bytes32 vaultId, uint256 offset, uint256 limit) external view returns (LatestView[] memory);
    function batchOf(bytes32 batchId)
        external
        view
        returns (
            bytes32 vaultId,
            bytes32 epochId,
            bytes32 author,
            uint64 nonce,
            bytes32[] memory itemIds,
            bytes32 sigHash
        );

    /// @notice At most this many members per `removeVaultMembers`.
    function REMOVE_MAX() external view returns (uint256);
    function VAULTS_RANGE_MAX() external view returns (uint256);
    function EPOCHS_RANGE_MAX() external view returns (uint256);
    function ITEMS_RANGE_MAX() external view returns (uint256);
    /// @notice 16 latest versions of at most 16,416 B each: about 270 KB per call on every chain.
    function LATEST_RANGE_MAX() external view returns (uint256);
}
