// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqVault} from "./IPqVault.sol";
import {PqVaultTypes} from "./PqVaultTypes.sol";
import {IPqChat} from "../pqchat/IPqChat.sol";
import {PqGroupBase} from "../pqgroup/PqGroupBase.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {RescueLib} from "../governance/RescueLib.sol";

/// @title `PqVault` (CTR-PQV-01, CTR-PQV-02, CTR-PQV-13: class 4, kind 0 on the factory's generic path): vaults as key groups
///        with PqChat's epochs, wraps in chunks, the home-instance slot, admins, leave and remove (over `PqGroupBase`), and items
///        whose every version stays in state.
/// @notice One release, many EIP-1167 clones; each clone reads its registry, `chain_uid` and code-size limit from its own code
///         (`ChainEnv`). State in the ERC-7201 namespace `scaas.pqvault`, no plain slot. Every record is an SSTORE2 blob (vault,
///         epoch and remove records with their full `UASig`; items with their `sigHash`), never only an event. A vault is
///         portable (mode 0: `DS_V`, `requirePortableApp`, replicas) or chain-bound (mode 1: `DS_B(this)`,
///         `requireAuthorized`, this instance its home), fixed at its creation (CTR-PQV-16, CTR-PQV-17). The contract runs no
///         KEM, KDF or cipher and never reads a ciphertext or `sealedInfo`. **UNAUDITED.**
contract PqVault is IPqVault, PqGroupBase {
    uint16 internal constant CLASS = 4;
    uint16 internal constant KIND = 0;
    uint256 public constant REMOVE_MAX = 16;
    uint256 public constant VAULTS_RANGE_MAX = 128;
    uint256 public constant EPOCHS_RANGE_MAX = 128;
    uint256 public constant ITEMS_RANGE_MAX = 128;
    uint256 public constant LATEST_RANGE_MAX = 16;
    /// @notice A ciphertext is `r` (16) ‖ AES-256-GCM-SIV of a padded plaintext of at most 16,384 B ‖ its tag (16) (VC9).
    uint256 internal constant CT_MIN = 32;
    uint256 internal constant CT_MAX = 16_416;
    /// @notice `sealedInfo` is at least a 12-B nonce and a 16-B tag, at most those around the 16,384-B bucket (Fable code review
    ///         F8; the client's padding policy is the client's, controller call 2026-11-21).
    uint256 internal constant INFO_MIN = 28;
    uint256 internal constant INFO_MAX = 16_412;
    /// @dev In a version-1 blob `abi.encode(item, sigHash, batchId)`: the item tuple's offset word, then `sigHash`, `batchId`
    ///      (+64), the tuple at +96 led by `vaultId`.
    uint256 internal constant ITEM_BATCH = 64;
    uint256 internal constant ITEM_VAULT = 96;

    address public immutable FACTORY;
    uint64 internal immutable VERSION;

    /// @custom:storage-location erc7201:scaas.pqvault
    struct V {
        bytes32 ownerUA; // +0
        bool initialized; // +1
        mapping(bytes32 => Epoch) epochs; // +2  PqGroupBase.Epoch, PqChat's layout
        mapping(bytes32 => bytes32) childOf; // +3  home only
        mapping(bytes32 => mapping(uint256 => uint256)) nonces; // +4
        mapping(bytes32 => bytes32[]) chain; // +5  per vault: epochs >= 1 in completion order
        mapping(bytes32 => address[]) removals; // +6  per epoch
        mapping(bytes32 => bytes32[]) vaults; // +7  per UA
        mapping(bytes32 => bytes32[]) items; // +8  per vault, creation order
        mapping(bytes32 => address) record; // +9  per item: its version-1 blob; 0 = unknown
        mapping(bytes32 => address[]) edits; // +10 per item: versions 2..
        mapping(bytes32 => address) batches; // +11 per batch: its header blob
        mapping(bytes32 => uint8) modes; // +12 per vault: 1 = chain-bound; 0 never written
    }

    /// @dev `keccak256(abi.encode(uint256(keccak256("scaas.pqvault")) - 1)) & ~bytes32(uint256(0xff))`.
    bytes32 internal constant SLOT = 0x5bab91edb5f7201959ccc400acb38a4632e4bb30c3ed3cf98f817b8f10b48800;

    function _v() internal pure returns (V storage s) {
        assembly ("memory-safe") {
            s.slot := SLOT
        }
    }

    /// @notice `(ReleaseId, factory_, implArgs)`; `implArgs` empty (no body module). The implementation is locked.
    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory implArgs) {
        if (
            id.contractClass != CLASS || id.kind != KIND || id.version == 0 || factory_ == address(0)
                || implArgs.length != 0
        ) revert PqVaultEnv();
        (FACTORY, VERSION) = (factory_, id.version);
        _v().initialized = true;
    }

    // ------------------------------------------------------------------ the instance (CTR-PQV-02)

    /// @notice The factory's only. `ownerUA` is 0 (no owner) or the creator (`IOpenFactory.creating()`); it has no power.
    function initialize(bytes32 ownerUA) external {
        if (msg.sender != FACTORY) revert PqVaultNotFactory();
        V storage s = _v();
        if (s.initialized) revert PqVaultInitialized();
        ChainEnvCode.requirePresent();
        if (ownerUA != 0 && ownerUA != IOpenFactory(FACTORY).creating()) revert PqVaultOwnerNotCreator(ownerUA);
        (s.initialized, s.ownerUA) = (true, ownerUA);
    }

    function owner() external view returns (bytes32) {
        return _v().ownerUA;
    }

    function factoryInfo() external view returns (IOpenFactory.FactoryInfo memory) {
        return IOpenFactory.FactoryInfo(FACTORY, ChainEnvCode.chainUid(), CLASS, KIND, VERSION, _v().initialized);
    }

    /// @notice CTR-GOV-26: anyone; this contract holds nothing by design, so the whole balance of `asset` goes to
    ///         `RescueLib.SCAAS_DEV_RESCUE`.
    function rescue(address asset) external {
        RescueLib.all(asset, RescueLib.SCAAS_DEV_RESCUE);
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x01ffc9a7 || id == type(IPqVault).interfaceId;
    }

    /// @notice A `chain_uid`, a registry and a code-size limit of at least 24,576 B.
    function validateEnv(IFactoryToken.ChainEnv calldata env) external pure {
        if (
            env.chainUid == 0 || env.registry == address(0) || env.params.length == 0
                || uint256(env.params[0]) < MIN_CODE_LIMIT
        ) revert PqVaultEnv();
    }

    function chainEnv() external view returns (IFactoryToken.ChainEnv memory) {
        return ChainEnvCode.decode();
    }

    /// @notice The body modules (CTR-TOK-30), as every release answers the factory: none.
    function modules() external pure returns (address[] memory) {}

    // ------------------------------------------------------------------ vaults, epochs, wraps (CTR-PQV-06, CTR-PQV-13)

    function createVault(PqVaultCreate calldata v, IPqChat.Wrap[] calldata wraps, IUARegistry.UASig calldata sig)
        external
        returns (bytes32 vid)
    {
        (IUARegistry reg, uint256 limit, bool home) = _checkCreate(v);
        _auth(reg, v.mode, v.creator, PqVaultTypes.hashCreate(v), sig);
        _useNonce(PqVaultTypes.scopeVault(v.creator), v.nonce);
        vid = PqVaultTypes.vaultId(v.creator, v.nonce, v.mode, v.homeChain, v.homeVaultContract);
        Epoch storage ep = _storeVault(vid, v, sig, home, limit);
        _landWraps(vid, ep, 0, wraps, v.members, v.wrapHashes, limit);
    }

    /// @dev Epoch 0's slots, the record with its full `UASig`, the mode, `vaultsOf` for every member.
    function _storeVault(
        bytes32 vid,
        PqVaultCreate calldata v,
        IUARegistry.UASig calldata sig,
        bool home,
        uint256 limit
    ) internal returns (Epoch storage ep) {
        V storage s = _v();
        ep = s.epochs[vid];
        ep.sessionId = vid;
        ep.record = _put(abi.encode(v, sig), limit);
        ep.wraps = uint32(v.members.length);
        ep.home = home;
        if (v.mode == 1) s.modes[vid] = 1;
        emit PqVaultCreated(vid, v.creator, v.homeChain);
        _indexAll(vid, v.members);
    }

    /// @dev The lists (at least one member), the creator an admin and a member, a home named, the mode 0 or 1 and in mode 1
    ///      this instance the home, the passphrase flag's shape. Returns whether this instance is the home.
    function _checkCreate(PqVaultCreate calldata v) internal view returns (IUARegistry reg, uint256 limit, bool home) {
        if (v.groupMode != 0) revert PqVaultModeUnsupported(v.groupMode); // CTR-PQV-18: flat wraps only
        bytes32 uid;
        (reg, limit, uid) = _env();
        IPqChat.MemberKey[] memory members = v.members;
        bytes32[] memory admins = v.admins;
        _checkLists(reg, admins, members, v.wrapHashes.length, 1);
        home = v.homeChain == uid && v.homeVaultContract == address(this);
        if (
            !_has(admins, v.creator) || _memberAt(members, v.creator) == type(uint256).max || v.homeChain == 0
                || v.homeVaultContract == address(0) || v.mode > 1 || (v.mode == 1 && !home)
                || (v.passKdf == 0) != (v.passSalt == 0) || v.sealedInfo.length < INFO_MIN
                || v.sealedInfo.length > INFO_MAX
        ) revert PqVaultShape();
    }

    /// @notice The parent stored and complete here, of the record's vault, `epoch == parent + 1`, the home slot free; the
    ///         author an admin of the parent not removed from it (CTR-PQV-13, every rekey); every member holds `keyId` here.
    function rekeyVault(PqVaultEpoch calldata e, IPqChat.Wrap[] calldata wraps, IUARegistry.UASig calldata sig)
        external
        returns (bytes32 eid)
    {
        (IUARegistry reg, uint256 limit, IPqChat.MemberKey[] memory members) = _checkRekey(e);
        _auth(reg, _v().modes[e.vaultId], e.author, PqVaultTypes.hashEpoch(e), sig);
        _useNonce(PqVaultTypes.scopeEpoch(e.vaultId, e.author), e.nonce);
        eid = PqVaultTypes.epochId(e.vaultId, e.author, e.nonce);
        Epoch storage ep = _v().epochs[eid];
        (ep.sessionId, ep.parent, ep.epoch) = (e.vaultId, e.parentEpochId, e.epoch);
        ep.record = _put(abi.encode(e, sig), limit);
        ep.wraps = uint32(members.length);
        emit PqVaultEpochAdded(e.vaultId, eid, e.parentEpochId, e.epoch, e.author);
        _landWraps(eid, ep, 0, wraps, members, e.wrapHashes, limit);
    }

    /// @dev The parent (`PqGroupBase._parentOf`: stored, of the record's vault, complete, the number, the home slot), the lists,
    ///      the passphrase flag's shape, the author an admin of the parent not removed from it; `vaultsOf` for added members.
    function _checkRekey(PqVaultEpoch calldata e)
        internal
        returns (IUARegistry reg, uint256 limit, IPqChat.MemberKey[] memory members)
    {
        (reg, limit,) = _env();
        Epoch storage pe = _parentOf(e.parentEpochId, e.vaultId, e.epoch);
        members = e.members;
        _checkLists(reg, e.admins, members, e.wrapHashes.length, 1);
        if ((e.passKdf == 0) != (e.passSalt == 0) || e.sealedInfo.length < INFO_MIN || e.sealedInfo.length > INFO_MAX) {
            revert PqVaultShape();
        }
        (bytes32[] memory pa, IPqChat.MemberKey[] memory pm,) = _lists(pe);
        if (!_liveAdmin(pe, pa, e.author)) revert PqVaultNotAdmin(e.author); // CTR-PQV-13; F7: not left either
        _indexAdded(e.vaultId, members, _uas(pm));
    }

    /// @dev `vaultsOf` gains `vid` once per UA of `m`, not per key (owner (M) 2026-11-23).
    function _indexAll(bytes32 vid, IPqChat.MemberKey[] memory m) internal {
        for (uint256 i; i < m.length; ++i) {
            if (!_sameUa(m, i)) _v().vaults[m[i].ua].push(vid);
        }
    }

    /// @dev `vaultsOf` gains the vault for each member the child adds to the parent (both sorted). Before the signature: a
    ///      refused record reverts it with the rest.
    function _indexAdded(bytes32 vid, IPqChat.MemberKey[] memory members, bytes32[] memory parent) internal {
        uint256 i;
        for (uint256 j; j < members.length; ++j) {
            if (_sameUa(members, j)) continue; // a UA's further key (owner (M))
            bytes32 ua = members[j].ua;
            while (i < parent.length && parent[i] < ua) ++i;
            if (i == parent.length || parent[i] != ua) _v().vaults[ua].push(vid);
        }
    }

    function addVaultWraps(bytes32 epochId, uint32 first, IPqChat.Wrap[] calldata wraps) external {
        if (wraps.length == 0) revert PqVaultShape(); // A-15 (as C40)
        (, uint256 limit,) = _env();
        Epoch storage ep = _known(epochId);
        _slotFree(ep, epochId);
        (, IPqChat.MemberKey[] memory members, bytes32[] memory hashes) = _lists(ep);
        _landWraps(epochId, ep, first, wraps, members, hashes, limit);
    }

    /// @dev `PqGroupBase._land` and its events.
    function _landWraps(
        bytes32 epochId,
        Epoch storage ep,
        uint256 first,
        IPqChat.Wrap[] calldata wraps,
        IPqChat.MemberKey[] memory members,
        bytes32[] memory hashes,
        uint256 limit
    ) internal {
        bool complete = _land(epochId, ep, first, wraps, members, hashes, limit);
        emit PqVaultWraps(epochId, uint32(first), uint32(wraps.length));
        if (complete) emit PqVaultEpochComplete(epochId);
    }

    /// @notice A member leaves: it writes no item under that epoch again (O3 (b)); an admin's rekey drops it. At home it names
    ///         the head or a complete ancestor within `EXIT_LAG_MAX` of which it is a member too (E-2) and applies at the head
    ///         (C9, E-3); a member already flagged at the head is refused (sc-E-5). In a replica it flags the epoch it names,
    ///         a repeat included (A-16).
    function leaveVault(PqVaultLeave calldata l, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg,,) = _env();
        (bytes32 at, Epoch storage ep,) = _exitAt(l.vaultId, l.epochId);
        (, IPqChat.MemberKey[] memory m,) = _lists(ep);
        bool home = _epochs()[l.vaultId].home;
        if (_memberAt(m, l.member) == type(uint256).max || (home && (ep.left[l.member] || ep.removedOf[l.member]))) {
            revert PqVaultNotMember(l.member);
        }
        if (at != l.epochId) {
            // E-2 (controller call 2026-11-25): a member of the epoch named too, where a replica checks it
            (, m,) = _lists(_known(l.epochId));
            if (_memberAt(m, l.member) == type(uint256).max) revert PqVaultNotMember(l.member);
        }
        _auth(reg, _v().modes[l.vaultId], l.member, PqVaultTypes.hashLeave(l), sig);
        _useNonce(PqVaultTypes.scopeEpoch(l.vaultId, l.member), l.nonce);
        ep.left[l.member] = true;
        emit PqVaultLeft(l.vaultId, at, l.member);
    }

    /// @notice An admin removes 1..REMOVE_MAX members, strictly sorted. At home it names the head or a complete ancestor within
    ///         `EXIT_LAG_MAX` and is checked and applied at the head (C9, E-3), the admin and each UA named also in the epoch
    ///         named's lists (E-2); a UA already removed at the head is refused (A-4). In a replica it flags the complete
    ///         epoch it names, a repeat included (A-16). The record and its full `UASig` in state.
    function removeVaultMembers(PqVaultRemove calldata r, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        (bytes32 at, Epoch storage ep, uint64 named) = _exitAt(r.vaultId, r.epochId);
        if (ep.landed != ep.wraps) revert PqVaultIncomplete(r.epochId); // a replica's epoch named
        if (r.nextEpoch != named + 1) revert PqVaultEpochNumber(named + 1, r.nextEpoch);
        uint256 n = r.members.length;
        if (n == 0 || n > REMOVE_MAX) revert PqVaultShape();
        (bytes32[] memory admins, IPqChat.MemberKey[] memory m,) = _lists(ep);
        if (!_liveAdmin(ep, admins, r.admin)) revert PqVaultNotAdmin(r.admin); // F2, F7
        bool home = _epochs()[r.vaultId].home;
        for (uint256 i; i < n; ++i) {
            if (i > 0 && r.members[i] <= r.members[i - 1]) revert PqVaultShape();
            if (!_removable(m, admins, r.members[i]) || (home && ep.removedOf[r.members[i]])) {
                revert PqVaultNotMember(r.members[i]); // F3, in the base; A-4 at home (A-16: a replica takes a repeat)
            }
        }
        if (at != r.epochId) _namedLists(r.epochId, r.admin, r.members); // E-2 (controller call 2026-11-25)
        _auth(reg, _v().modes[r.vaultId], r.admin, PqVaultTypes.hashRemove(r), sig);
        _useNonce(PqVaultTypes.scopeEpoch(r.vaultId, r.admin), r.nonce);
        ep.removed += _flagRemoved(ep, r.members);
        _v().removals[at].push(_put(abi.encode(r, sig), limit));
        emit PqVaultRemoved(r.vaultId, at, r.admin, r.members);
    }

    // ------------------------------------------------------------------ items (CTR-PQV-07, -08, -09, -14)

    function createItem(PqVaultItem calldata it, IUARegistry.UASig calldata sig) external returns (bytes32 iid) {
        (IUARegistry reg, uint256 limit,) = _env();
        _itemRights(it.epochId, it.vaultId, it.author);
        _ciphertext(it.ciphertext);
        _auth(reg, _v().modes[it.vaultId], it.author, PqVaultTypes.hashItem(it), sig);
        _useNonce(PqVaultTypes.scopeItem(it.vaultId, it.author), it.nonce);
        iid = PqVaultTypes.itemId(it.vaultId, it.author, it.nonce);
        V storage s = _v();
        s.record[iid] = _put(abi.encode(it, keccak256(abi.encode(sig)), bytes32(0)), limit);
        s.items[it.vaultId].push(iid);
        emit PqVaultItemCreated(it.vaultId, iid, it.author, 0, sig);
    }

    /// @notice Any member writes version `count + 1` (the first edit 2), under an epoch of the item's vault.
    function editItem(PqVaultEdit calldata d, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        V storage s = _v();
        address r = s.record[d.itemId];
        if (r == address(0)) revert PqVaultUnknown(d.itemId);
        bytes32 vid = _word(r, ITEM_VAULT);
        _itemRights(d.epochId, vid, d.author);
        uint32 next = uint32(s.edits[d.itemId].length) + 2;
        if (d.version != next) revert PqVaultVersion(next, d.version);
        _ciphertext(d.ciphertext);
        _auth(reg, s.modes[vid], d.author, PqVaultTypes.hashEdit(d), sig);
        _useNonce(PqVaultTypes.scopeItem(vid, d.author), d.nonce);
        s.edits[d.itemId].push(_put(abi.encode(d, keccak256(abi.encode(sig))), limit));
        emit PqVaultItemEdited(d.itemId, d.version, d.author, sig);
    }

    /// @notice One or more items of one vault, epoch and author under one signature; each item's nonce and the batch's in the
    ///         item scope; the header kept so the signed record is rebuilt from state.
    function createItems(PqVaultBatch calldata b, IUARegistry.UASig calldata sig) external returns (bytes32 bid) {
        (IUARegistry reg, uint256 limit,) = _env();
        uint256 n = b.items.length;
        if (n == 0) revert PqVaultShape();
        for (uint256 i; i < n; ++i) {
            PqVaultItem calldata it = b.items[i];
            if (it.vaultId != b.vaultId || it.epochId != b.epochId || it.author != b.author) revert PqVaultShape();
            _ciphertext(it.ciphertext);
        }
        _itemRights(b.epochId, b.vaultId, b.author);
        _auth(reg, _v().modes[b.vaultId], b.author, PqVaultTypes.hashBatch(b), sig);
        bid = _storeBatch(b, keccak256(abi.encode(sig)), limit);
        emit PqVaultBatchCreated(b.vaultId, bid, b.author, n, sig);
    }

    /// @dev The batch nonce, then per item its nonce, its version-1 blob `abi.encode(item, sigHash, batchId)` and its list
    ///      entry; the header blob.
    function _storeBatch(PqVaultBatch calldata b, bytes32 sh, uint256 limit) internal returns (bytes32 bid) {
        V storage s = _v();
        bytes32 scope = PqVaultTypes.scopeItem(b.vaultId, b.author);
        _useNonce(scope, b.nonce);
        bid = PqVaultTypes.batchId(b.vaultId, b.author, b.nonce);
        bytes32[] memory iids = new bytes32[](b.items.length);
        IUARegistry.UASig memory none;
        for (uint256 i; i < iids.length; ++i) {
            PqVaultItem calldata it = b.items[i];
            _useNonce(scope, it.nonce);
            bytes32 iid = PqVaultTypes.itemId(b.vaultId, b.author, it.nonce);
            iids[i] = iid;
            s.record[iid] = _put(abi.encode(it, sh, bid), limit);
            s.items[b.vaultId].push(iid);
            emit PqVaultItemCreated(b.vaultId, iid, b.author, bid, none);
        }
        s.batches[bid] = _put(abi.encode(b.vaultId, b.epochId, b.author, b.nonce, iids, sh), limit);
    }

    /// @dev CTR-PQV-07, CTR-PQV-14: the epoch stored here for `vid` (else `PqVaultUnknown`: a record naming another vault than
    ///      its epoch's, R11), complete, at home with no complete child; `author` a member of it, not removed from it, not left.
    function _itemRights(bytes32 epochId, bytes32 vid, bytes32 author) internal view {
        Epoch storage ep = _known(epochId);
        if (ep.sessionId != vid) revert PqVaultUnknown(epochId);
        if (ep.landed != ep.wraps) revert PqVaultIncomplete(epochId);
        bytes32 child = _v().childOf[epochId];
        if (child != 0) revert PqVaultEpochTaken(epochId, child);
        (, IPqChat.MemberKey[] memory m,) = _lists(ep);
        if (_memberAt(m, author) == type(uint256).max || ep.left[author] || ep.removedOf[author]) {
            revert PqVaultNotMember(author);
        }
    }

    /// @dev VC9: 32..16,416 B.
    function _ciphertext(bytes calldata c) internal pure {
        if (c.length < CT_MIN || c.length > CT_MAX) revert PqVaultShape();
    }

    // ------------------------------------------------------------------ recovery from state alone (CTR-PQV-10)

    function vaultCount(bytes32 ua) external view returns (uint256) {
        return _v().vaults[ua].length;
    }

    function vaultsOf(bytes32 ua, uint256 offset, uint256 limit) external view returns (bytes32[] memory) {
        return _page(_v().vaults[ua], offset, limit, VAULTS_RANGE_MAX);
    }

    function vaultOf(bytes32 vid) external view returns (PqVaultCreate memory, IUARegistry.UASig memory) {
        Epoch storage ep = _known(vid);
        if (ep.sessionId != vid) revert PqVaultUnknown(vid);
        _returnBlob(ep.record);
    }

    /// @dev Epoch 0 implied once the vault is complete here; then `chain`.
    function epochCount(bytes32 vid) public view returns (uint256) {
        Epoch storage ep = _v().epochs[vid];
        if (ep.sessionId != vid || vid == 0 || ep.landed != ep.wraps) return 0;
        return 1 + _v().chain[vid].length;
    }

    function epochsOf(bytes32 vid, uint256 offset, uint256 limit) external view returns (bytes32[] memory page) {
        uint256 n = epochCount(vid);
        if (offset >= n) return page;
        if (limit > EPOCHS_RANGE_MAX) limit = EPOCHS_RANGE_MAX;
        uint256 end = n - offset > limit ? offset + limit : n;
        page = new bytes32[](end - offset);
        bytes32[] storage c = _v().chain[vid];
        for (uint256 i; i < page.length; ++i) {
            page[i] = offset + i == 0 ? vid : c[offset + i - 1];
        }
    }

    function latestEpoch(bytes32 vid) external view returns (bytes32) {
        uint256 n = epochCount(vid);
        return n == 0 ? bytes32(0) : n == 1 ? vid : _v().chain[vid][n - 2];
    }

    function epochOf(bytes32 epochId) external view returns (PqVaultEpoch memory, IUARegistry.UASig memory) {
        Epoch storage ep = _known(epochId);
        if (ep.sessionId == epochId) revert PqVaultUnknown(epochId);
        _returnBlob(ep.record);
    }

    function epochComplete(bytes32 epochId) external view returns (bool) {
        Epoch storage ep = _v().epochs[epochId];
        return ep.sessionId != 0 && ep.landed == ep.wraps;
    }

    function childOf(bytes32 parentEpochId) external view returns (bytes32) {
        return _v().childOf[parentEpochId];
    }

    function wrapAt(bytes32 epochId, uint256 i) external view returns (IPqChat.Wrap memory) {
        return _wrapAt(epochId, i);
    }

    function leftIn(bytes32 epochId, bytes32 member) external view returns (bool) {
        return _v().epochs[epochId].left[member];
    }

    function removedIn(bytes32 epochId, bytes32 member) external view returns (bool) {
        return _v().epochs[epochId].removedOf[member];
    }

    function removalCount(bytes32 epochId) external view returns (uint256) {
        return _v().removals[epochId].length;
    }

    function removalAt(bytes32 epochId, uint256 index)
        external
        view
        returns (PqVaultRemove memory, IUARegistry.UASig memory)
    {
        address[] storage l = _v().removals[epochId];
        if (index >= l.length) revert PqVaultUnknown(epochId); // F15: as every unknown read, never a panic
        _returnBlob(l[index]);
    }

    /// @dev A group record's blob is `abi.encode(record, UASig)`, written by this contract: exactly the ABI encoding of the
    ///      view's `(record, UASig)`, so it is returned as stored (decoding a `UASig` from memory is past the legacy code
    ///      generator's stack).
    function _returnBlob(address head) internal view {
        bytes memory b = _get(head);
        assembly ("memory-safe") {
            return(add(b, 32), mload(b))
        }
    }

    function nonceUsed(bytes32 scope, uint64 nonce) external view returns (bool) {
        return _nonceUsed(scope, nonce);
    }

    function itemCount(bytes32 vid) external view returns (uint256) {
        return _v().items[vid].length;
    }

    function itemsOf(bytes32 vid, uint256 offset, uint256 limit) external view returns (bytes32[] memory) {
        return _page(_v().items[vid], offset, limit, ITEMS_RANGE_MAX);
    }

    function itemOf(bytes32 iid) external view returns (ItemView memory) {
        address r = _v().record[iid];
        if (r == address(0)) revert PqVaultUnknown(iid);
        return ItemView(_word(r, ITEM_VAULT), uint32(_v().edits[iid].length) + 1, _word(r, ITEM_BATCH));
    }

    function versionAt(bytes32 iid, uint32 version) public view returns (VersionView memory) {
        V storage s = _v();
        address r = s.record[iid];
        uint32 count = r == address(0) ? 0 : uint32(s.edits[iid].length) + 1;
        if (version == 0 || version > count) revert PqVaultVersion(count, version);
        if (version == 1) {
            (PqVaultItem memory it, bytes32 sh,) = abi.decode(_get(r), (PqVaultItem, bytes32, bytes32));
            return VersionView(it.epochId, it.author, it.nonce, 1, it.ciphertext, sh);
        }
        (PqVaultEdit memory d, bytes32 dh) = abi.decode(_get(s.edits[iid][version - 2]), (PqVaultEdit, bytes32));
        return VersionView(d.epochId, d.author, d.nonce, version, d.ciphertext, dh);
    }

    /// @notice The latest version of each item of the page, 16 at most: 16 x 16,416 B ciphertext, about 270 KB a call (VC9).
    function latestRange(bytes32 vid, uint256 offset, uint256 limit) external view returns (LatestView[] memory page) {
        bytes32[] memory iids = _page(_v().items[vid], offset, limit, LATEST_RANGE_MAX);
        page = new LatestView[](iids.length);
        for (uint256 i; i < iids.length; ++i) {
            uint32 c = uint32(_v().edits[iids[i]].length) + 1;
            VersionView memory w = versionAt(iids[i], c);
            page[i] = LatestView(iids[i], c, w.epochId, w.author, w.ciphertext);
        }
    }

    /// @notice The header blob `abi.encode(vaultId, epochId, author, nonce, itemIds, sigHash)` is exactly the return's encoding.
    function batchOf(bytes32 bid) external view returns (bytes32, bytes32, bytes32, uint64, bytes32[] memory, bytes32) {
        address r = _v().batches[bid];
        if (r == address(0)) revert PqVaultUnknown(bid);
        _returnBlob(r);
    }

    /// @dev `[offset, min(offset + min(limit, max), length))`; an offset past the end is empty, never a revert.
    function _page(bytes32[] storage l, uint256 offset, uint256 limit, uint256 max)
        internal
        view
        returns (bytes32[] memory page)
    {
        uint256 n = l.length;
        if (offset >= n) return page;
        if (limit > max) limit = max;
        uint256 end = n - offset > limit ? offset + limit : n;
        page = new bytes32[](end - offset);
        for (uint256 i; i < page.length; ++i) {
            page[i] = l[offset + i];
        }
    }

    // ------------------------------------------------------------------ internal: the signature (CTR-PQV-03, CTR-PQV-17)

    /// @dev The one place the mode picks the domain and the registry entry: mode 0 `requirePortableApp` over `typed(DS_V)`, mode
    ///      1 `requireAuthorized` under `P_V` over `typed(DS_B(this))`. `mode` comes from the record only at `createVault`; every
    ///      other write passes the stored mode of the vault its stored epoch (or item) names.
    function _auth(IUARegistry reg, uint8 mode, bytes32 signer, bytes32 structHash, IUARegistry.UASig calldata sig)
        internal
        view
    {
        if (mode == 0) {
            reg.requirePortableApp(signer, PqVaultTypes.APP_ID, PqVaultTypes.typed(PqVaultTypes.DS_V, structHash), sig);
        } else {
            reg.requireAuthorized(
                signer, PqVaultTypes.P_V, PqVaultTypes.typed(PqVaultTypes.dsB(address(this)), structHash), sig
            );
        }
    }

    // ------------------------------------------------------------------ the group hooks (PqGroupBase)

    function _epochs() internal view override returns (mapping(bytes32 => Epoch) storage) {
        return _v().epochs;
    }

    function _childOf() internal view override returns (mapping(bytes32 => bytes32) storage) {
        return _v().childOf;
    }

    function _nonces() internal view override returns (mapping(bytes32 => mapping(uint256 => uint256)) storage) {
        return _v().nonces;
    }

    function _chain() internal view override returns (mapping(bytes32 => bytes32[]) storage) {
        return _v().chain;
    }

    /// @dev The admins, members and wrap hashes of a stored epoch record (the vault's create record for epoch 0); the blob is
    ///      `abi.encode(record, UASig)` and only the record is decoded.
    function _lists(Epoch storage ep)
        internal
        view
        override
        returns (bytes32[] memory admins, IPqChat.MemberKey[] memory members, bytes32[] memory hashes)
    {
        bytes memory b = _get(ep.record);
        if (ep.epoch == 0) {
            PqVaultCreate memory v = abi.decode(b, (PqVaultCreate));
            return (v.admins, v.members, v.wrapHashes);
        }
        PqVaultEpoch memory e = abi.decode(b, (PqVaultEpoch));
        return (e.admins, e.members, e.wrapHashes);
    }

    /// @dev Every `PqGroupBase` code to its `PqVault` error.
    function _fail(uint8 code, uint256 a, uint256 b) internal pure override {
        if (code == F_SHAPE) revert PqVaultShape();
        if (code == F_KEM_KEY) revert PqVaultKemKey(bytes32(a), uint64(b));
        if (code == F_WRAP_HASH) revert PqVaultWrapHash(bytes32(a), b);
        if (code == F_WRAP_STORED) revert PqVaultWrapStored(bytes32(a), b);
        if (code == F_UNKNOWN) revert PqVaultUnknown(bytes32(a));
        if (code == F_INCOMPLETE) revert PqVaultIncomplete(bytes32(a));
        if (code == F_EPOCH_NUMBER) revert PqVaultEpochNumber(uint64(a), uint64(b));
        if (code == F_EPOCH_TAKEN) revert PqVaultEpochTaken(bytes32(a), bytes32(b));
        if (code == F_NOT_ADMIN) revert PqVaultNotAdmin(bytes32(a));
        if (code == F_NOT_MEMBER) revert PqVaultNotMember(bytes32(a));
        if (code == F_REMOVED_KEPT) revert PqVaultRemovedKept(bytes32(a), bytes32(b));
        if (code == F_EXIT_LAG) revert PqVaultExitLag(uint64(a), uint64(b));
        if (code == F_NONCE_USED) revert PqVaultNonceUsed(bytes32(a), uint64(b));
        revert PqVaultEnv();
    }
}
