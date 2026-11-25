// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "../pqchat/IPqChat.sol";
import {PqChatTypes} from "../pqchat/PqChatTypes.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title The key-group code `PqChat` and `PqVault` share (CTR-PQV-12, owner 2026-11-17 V3; pqvault spec §4.2): epochs in chunks,
///        their wraps, the home-instance slot, the list checks, the nonce bitmap, the SSTORE2 blobs and the clone's env read.
/// @notice No state of its own: each contract reaches its own ERC-7201 namespace through the storage hooks (`_epochs`, `_childOf`,
///         `_nonces`, `_chain`), decodes its own records (`_lists`) and raises its own named errors (`_fail`); its events are the
///         caller's (`_land` returns whether the epoch completed). The functions take ids and decoded lists, never a record type;
///         the signature check, the ids, the typehashes and every entry stay in each contract. The group types are `IPqChat.MemberKey` and `IPqChat.Wrap`.
///         **UNAUDITED.**
abstract contract PqGroupBase {
    /// @notice EIP-170's limit, the smallest of any EVM chain (3C-D1).
    uint256 internal constant MIN_CODE_LIMIT = 24_576;
    uint256 internal constant MLKEM_CT = 1568;
    uint256 internal constant SEALED_KEY = 48;
    /// @notice A packed wrap: member (32) ‖ keyId (8) ‖ mlkemCt (1,568) ‖ x25519Eph (32) ‖ sealedKey (48).
    uint256 internal constant WRAP_BYTES = 1688;
    /// @dev Owner (M) 2026-11-23: the KEM keys one UA may hold in one epoch (its seed key and device keys), a controller call
    ///      from the gas figures: 8 keys of each of 2 members are 16 wraps, about a 16-member epoch, still landed in chunks.
    uint256 internal constant KEYS_PER_UA_MAX = 8;
    /// @dev C9 (Change 2026-11-24, E-3): an exit names the head or an older complete epoch at most this many below it.
    uint64 internal constant EXIT_LAG_MAX = 16;

    /// @dev What `_fail` raises, each contract by its own named error: `a`, `b` its arguments as words.
    uint8 internal constant F_SHAPE = 0; // ()
    uint8 internal constant F_KEM_KEY = 1; // (member, keyId)
    uint8 internal constant F_WRAP_HASH = 2; // (epochId, index)
    uint8 internal constant F_WRAP_STORED = 3; // (epochId, index)
    uint8 internal constant F_UNKNOWN = 4; // (id)
    uint8 internal constant F_INCOMPLETE = 5; // (epochId)
    uint8 internal constant F_EPOCH_NUMBER = 6; // (expected, got)
    uint8 internal constant F_EPOCH_TAKEN = 7; // (parentEpochId, child)
    uint8 internal constant F_NOT_ADMIN = 8; // (author)
    uint8 internal constant F_NOT_MEMBER = 9; // (ua)
    uint8 internal constant F_REMOVED_KEPT = 10; // (epochId, ua)
    uint8 internal constant F_NONCE_USED = 11; // (scope, nonce)
    uint8 internal constant F_ENV = 12; // ()

    struct Epoch {
        bytes32 sessionId; // 0 = unknown
        address record; // head blob of abi.encode(record, sigHash)
        uint64 epoch;
        uint32 wraps;
        uint32 landed;
        bool home; // epoch 0 only: this instance is the session's home (P32)
        uint16 removed; // P48: how many members a `remove` took out of this epoch (0 on the 1:1 path)
        bytes32 parent;
        mapping(uint256 => uint256) wrapAt; // pointer | offset << 160
        mapping(bytes32 => bool) left;
        mapping(bytes32 => bool) removedOf; // P48
    }

    // ------------------------------------------------------------------ the hooks

    function _epochs() internal view virtual returns (mapping(bytes32 => Epoch) storage);
    function _childOf() internal view virtual returns (mapping(bytes32 => bytes32) storage);
    function _nonces() internal view virtual returns (mapping(bytes32 => mapping(uint256 => uint256)) storage);
    function _chain() internal view virtual returns (mapping(bytes32 => bytes32[]) storage);
    /// @dev The admins, members and wrap hashes of a stored epoch record (the group's first record for epoch 0).
    function _lists(Epoch storage ep)
        internal
        view
        virtual
        returns (bytes32[] memory admins, IPqChat.MemberKey[] memory members, bytes32[] memory hashes);
    /// @dev Reverts with the contract's named error for `code` (`F_*`); never returns.
    function _fail(uint8 code, uint256 a, uint256 b) internal pure virtual;

    // ------------------------------------------------------------------ env, nonces

    /// @dev The registry, the code-size limit and `chain_uid` of this clone (3C-D1); the implementation (no env) refuses.
    function _env() internal view returns (IUARegistry reg, uint256 limit, bytes32 uid) {
        IFactoryToken.ChainEnv memory e = ChainEnvCode.decode();
        limit = e.params.length == 0 ? 0 : uint256(e.params[0]);
        if (limit < MIN_CODE_LIMIT || e.registry == address(0)) _fail(F_ENV, 0, 0);
        (reg, uid) = (IUARegistry(e.registry), e.chainUid);
    }

    function _nonceUsed(bytes32 scope, uint64 nonce) internal view returns (bool) {
        return _nonces()[scope][nonce >> 8] & (1 << (nonce & 0xff)) != 0;
    }

    /// @dev A bitmap per scope, any order, never locked (§4.3); called after the signature.
    function _useNonce(bytes32 scope, uint64 nonce) internal {
        mapping(uint256 => uint256) storage b = _nonces()[scope];
        uint256 bit = 1 << (nonce & 0xff);
        uint256 word = b[nonce >> 8];
        if (word & bit != 0) _fail(F_NONCE_USED, uint256(scope), nonce);
        b[nonce >> 8] = word | bit;
    }

    // ------------------------------------------------------------------ blobs (3C-D3)

    /// @dev The largest runtime of one blob: the chain's limit, at most 65,535 B (`SSTORE2.write`'s PUSH2).
    function _codeCap(uint256 limit) internal pure returns (uint256) {
        return limit < 0xffff ? limit : 0xffff;
    }

    /// @dev `data` as one blob led by flag 0 when it fits the limit, else a chain: each blob led by flag 1 and the next
    ///      blob's address, the last by flag 0. Returns the head.
    function _put(bytes memory data, uint256 limit) internal returns (address head) {
        uint256 cap = _codeCap(limit) - 1; // the bytes of one blob, flag included
        if (data.length < cap) return SSTORE2.write(bytes.concat(bytes1(0), data));
        uint256 piece = cap - 21;
        for (uint256 i = (data.length + piece - 1) / piece; i > 0; --i) {
            uint256 o = (i - 1) * piece;
            uint256 len = data.length - o < piece ? data.length - o : piece;
            bytes memory part = new bytes(len);
            assembly ("memory-safe") {
                mcopy(add(part, 32), add(add(data, 32), o), len)
            }
            head = SSTORE2.write(
                head == address(0) ? bytes.concat(bytes1(0), part) : bytes.concat(bytes1(0x01), bytes20(head), part)
            );
        }
    }

    function _get(address head) internal view returns (bytes memory data) {
        for (address q = head; q != address(0);) {
            uint256 len = q.code.length - 1;
            bool more = SSTORE2.read(q, 0, 1)[0] != 0;
            uint256 skip = more ? 21 : 1;
            address next = more ? address(bytes20(SSTORE2.read(q, 1, 20))) : address(0);
            data = bytes.concat(data, SSTORE2.read(q, skip, len - skip));
            q = next;
        }
    }

    /// @dev The 32 bytes at `off` of a record's first piece.
    function _word(address head, uint256 off) internal view returns (bytes32) {
        return bytes32(SSTORE2.read(head, (SSTORE2.read(head, 0, 1)[0] != 0 ? 21 : 1) + off, 32));
    }

    // ------------------------------------------------------------------ epochs

    function _known(bytes32 epochId) internal view returns (Epoch storage ep) {
        ep = _epochs()[epochId];
        if (ep.sessionId == 0) _fail(F_UNKNOWN, uint256(epochId), 0);
    }

    /// @notice P9, P10: the parent `parentEpochId` stored and complete in this instance, of `sessionId`, `epoch == parent + 1`, the
    ///         home slot free.
    function _parentOf(bytes32 parentEpochId, bytes32 sessionId, uint64 epoch)
        internal
        view
        returns (Epoch storage pe)
    {
        pe = _known(parentEpochId);
        if (pe.sessionId != sessionId) _fail(F_UNKNOWN, uint256(parentEpochId), 0);
        if (pe.landed != pe.wraps) _fail(F_INCOMPLETE, uint256(parentEpochId), 0);
        if (epoch != pe.epoch + 1) _fail(F_EPOCH_NUMBER, pe.epoch + 1, epoch);
        if (_epochs()[sessionId].home) {
            bytes32 c = _childOf()[parentEpochId];
            if (c != 0) _fail(F_EPOCH_TAKEN, uint256(parentEpochId), uint256(c));
        }
    }

    /// @dev The rights of P10 (3C-D7) over lists: the parent's admins `pa` and members `pm`, the child's `admins` and `members`,
    ///      its `author`. A plain rekey (the child keeps the parent's admins and members, less those who left or were removed) by a
    ///      member of the parent who did not leave it, any other by an admin of it. Returns the parent's member ids.
    function _rights(
        Epoch storage pe,
        bytes32[] memory pa,
        IPqChat.MemberKey[] memory pm,
        bytes32[] memory admins,
        IPqChat.MemberKey[] memory members,
        bytes32 author
    ) internal view returns (bytes32[] memory pu) {
        pu = _uas(pm);
        if (pe.removed != 0 && pe.removedOf[author]) _fail(F_NOT_MEMBER, uint256(author), 0); // P48
        if (_keeps(pe, pa, admins) && _keeps(pe, pu, _uas(members))) {
            // Fable P1-2 (a): a member who left the parent authors no plain rekey of it (it would keep itself in)
            if (_memberAt(pm, author) == type(uint256).max || pe.left[author]) _fail(F_NOT_MEMBER, uint256(author), 0);
        } else if (!_liveAdmin(pe, pa, author)) {
            _fail(F_NOT_ADMIN, uint256(author), 0);
        }
    }

    /// @dev One rule for PqChat and PqVault (Fable code review of PqVault F2, F7; controller call 2026-11-21): an admin of `pe`
    ///      acts on it (a membership change, a removal; every PqVault rekey) only while it is in `pe`'s admin list, not removed
    ///      from `pe` and has not left it (as O3 (b) for item writes).
    function _liveAdmin(Epoch storage pe, bytes32[] memory admins, bytes32 ua) internal view returns (bool) {
        return _has(admins, ua) && !pe.removedOf[ua] && !pe.left[ua];
    }

    /// @dev Fable code review of PqVault F3 (controller call 2026-11-21, one rule for PqChat and PqVault): a `remove` takes a UA
    ///      that is a member or an admin of the epoch, so an admin that is no member (an `msig`, which holds no KEM key) is
    ///      removable.
    function _removable(IPqChat.MemberKey[] memory members, bytes32[] memory admins, bytes32 ua)
        internal
        pure
        returns (bool)
    {
        return _memberAt(members, ua) != type(uint256).max || _has(admins, ua);
    }

    /// @dev 3C-D7: `child` (sorted) is `parent` (sorted) minus entries that left the parent epoch.
    function _keeps(Epoch storage pe, bytes32[] memory parent, bytes32[] memory child) internal view returns (bool) {
        uint256 j;
        for (uint256 i; i < parent.length; ++i) {
            if (j < child.length && child[j] == parent[i]) ++j;
            else if (j < child.length && child[j] < parent[i]) return false; // added
            else if (!pe.left[parent[i]] && !pe.removedOf[parent[i]]) return false; // dropped without leaving or removal
        }
        return j == child.length;
    }

    /// @dev The distinct UAs of a member list (sorted by `(ua, keyId)`, owner (M) 2026-11-23: a UA's keys are adjacent), in
    ///      order: every rule but the wraps reads members per UA.
    function _uas(IPqChat.MemberKey[] memory m) internal pure returns (bytes32[] memory u) {
        u = new bytes32[](m.length);
        uint256 n;
        for (uint256 i; i < m.length; ++i) {
            if (!_sameUa(m, i)) u[n++] = m[i].ua;
        }
        assembly ("memory-safe") {
            mstore(u, n)
        }
    }

    /// @dev Entry `i` is a further key of the UA of entry `i - 1` (owner (M) 2026-11-23).
    function _sameUa(IPqChat.MemberKey[] memory m, uint256 i) internal pure returns (bool) {
        return i > 0 && m[i].ua == m[i - 1].ua;
    }

    /// @dev The author of a stored epoch record, its second field (`abi.encode(record, sigHash)`: the record's offset, the
    ///      trailer, the record's first field, then `author`); `PqChat` overrides it for the blobs that keep a signature
    ///      (CTR-CHAT-23).
    function _authorOf(Epoch storage ep) internal view virtual returns (bytes32) {
        return _word(ep.record, 96);
    }

    /// @dev P48: the completing child `ep` holds no UA a `remove` took out of its parent, in its members or its admins, and was
    ///      not authored by one (Fable code review of PqVault F1, controller call 2026-11-21: a child staged before its author's
    ///      removal must not complete after it).
    function _noneRemoved(Epoch storage ep) internal view {
        Epoch storage pe = _epochs()[ep.parent];
        bytes32 author = _authorOf(ep);
        if (pe.removedOf[author]) _fail(F_REMOVED_KEPT, uint256(ep.parent), uint256(author));
        (bytes32[] memory admins, IPqChat.MemberKey[] memory m,) = _lists(ep);
        for (uint256 i; i < m.length; ++i) {
            if (pe.removedOf[m[i].ua]) _fail(F_REMOVED_KEPT, uint256(ep.parent), uint256(m[i].ua));
        }
        for (uint256 i; i < admins.length; ++i) {
            if (pe.removedOf[admins[i]]) _fail(F_REMOVED_KEPT, uint256(ep.parent), uint256(admins[i]));
        }
    }

    /// @dev 3C-D6 as owner (M) of 2026-11-23 changed it: members strictly sorted by `(ua, keyId)`, one or more keys per UA
    ///      and at most `KEYS_PER_UA_MAX`, at least `min` distinct UAs, one hash per entry, each entry a KEM key its UA holds
    ///      here (P3); admins strictly sorted and registered (P8).
    function _checkLists(
        IUARegistry reg,
        bytes32[] memory admins,
        IPqChat.MemberKey[] memory members,
        uint256 nHashes,
        uint256 min
    ) internal view {
        uint256 n = members.length;
        if (nHashes != n) _fail(F_SHAPE, 0, 0);
        uint256 uas;
        uint256 keys;
        for (uint256 i; i < n; ++i) {
            if (_sameUa(members, i)) {
                if (members[i].keyId <= members[i - 1].keyId || ++keys > KEYS_PER_UA_MAX) _fail(F_SHAPE, 0, 0);
            } else {
                if (i > 0 && members[i].ua < members[i - 1].ua) _fail(F_SHAPE, 0, 0);
                (uas, keys) = (uas + 1, 1);
            }
            (IUARegistry.KemKey memory k,) = reg.kemKeyAt(members[i].ua, members[i].keyId);
            if (k.scheme == 0) _fail(F_KEM_KEY, uint256(members[i].ua), members[i].keyId);
        }
        if (uas < min) _fail(F_SHAPE, 0, 0);
        for (uint256 i; i < admins.length; ++i) {
            if ((i > 0 && admins[i] <= admins[i - 1]) || !reg.isRegistered(admins[i])) _fail(F_SHAPE, 0, 0);
        }
    }

    /// @dev P9: in the home instance, a child of a parent whose slot another child holds can no longer land.
    function _slotFree(Epoch storage ep, bytes32 epochId) internal view {
        if (ep.epoch == 0 || !_epochs()[ep.sessionId].home) return;
        bytes32 c = _childOf()[ep.parent];
        if (c != 0 && c != epochId) _fail(F_EPOCH_TAKEN, uint256(ep.parent), uint256(c));
    }

    // ------------------------------------------------------------------ wraps

    /// @dev P11: `_storeWraps`, then `landed` counts them; the epoch completes when its last wrap lands (`complete`,
    ///      `_complete`); the caller emits the events of both.
    function _land(
        bytes32 epochId,
        Epoch storage ep,
        uint256 first,
        IPqChat.Wrap[] calldata wraps,
        IPqChat.MemberKey[] memory members,
        bytes32[] memory hashes,
        uint256 limit
    ) internal returns (bool complete) {
        uint256 n = wraps.length;
        _storeWraps(epochId, ep, first, wraps, members, hashes, limit);
        uint32 landed = ep.landed + uint32(n);
        ep.landed = landed;
        if (landed == ep.wraps && n != 0) {
            _complete(epochId, ep);
            return true;
        }
    }

    /// @dev P11: `wraps` as indices `first..` of `epochId`, each against its signed hash, then its shape and its member's
    ///      `ua` / `keyId` (3C-D6), stored once; packed as many per blob as the limit holds, one slot each (pointer | offset
    ///      << 160). Counts nothing: the caller owns `landed` (a tree epoch counts its pieces, CTR-CHAT-27 C20).
    function _storeWraps(
        bytes32 epochId,
        Epoch storage ep,
        uint256 first,
        IPqChat.Wrap[] calldata wraps,
        IPqChat.MemberKey[] memory members,
        bytes32[] memory hashes,
        uint256 limit
    ) internal {
        uint256 n = wraps.length;
        if (first + n > members.length) _fail(F_SHAPE, 0, 0);
        uint256 per = (_codeCap(limit) - 1) / WRAP_BYTES;
        for (uint256 j; j < n; j += per) {
            _blob(epochId, ep, first, wraps, j, n - j < per ? n : j + per, members, hashes);
        }
    }

    /// @dev The completion of epoch `epochId` above 0 (epoch 0 has nothing to take): P48's check, the home slot (P9) and
    ///      `epochsOf` (owner 2026-11-10).
    function _complete(bytes32 epochId, Epoch storage ep) internal {
        if (ep.epoch == 0) return;
        if (_epochs()[ep.parent].removed != 0) _noneRemoved(ep); // P48: whoever authored it
        if (_epochs()[ep.sessionId].home) _childOf()[ep.parent] = epochId; // P9: the slot, home only
        _chain()[ep.sessionId].push(epochId); // owner 2026-11-10: `epochsOf`
    }

    /// @dev One blob of `wraps[from..to)`, indices `first + from..`.
    function _blob(
        bytes32 epochId,
        Epoch storage ep,
        uint256 first,
        IPqChat.Wrap[] calldata wraps,
        uint256 from,
        uint256 to,
        IPqChat.MemberKey[] memory members,
        bytes32[] memory hashes
    ) private {
        bytes memory buf = new bytes((to - from) * WRAP_BYTES);
        for (uint256 j = from; j < to; ++j) {
            uint256 i = first + j;
            IPqChat.Wrap calldata w = wraps[j];
            if (PqChatTypes.hashWrap(w) != hashes[i]) _fail(F_WRAP_HASH, uint256(epochId), i);
            if (
                w.mlkemCt.length != MLKEM_CT || w.sealedKey.length != SEALED_KEY || w.member != members[i].ua
                    || w.keyId != members[i].keyId
            ) _fail(F_SHAPE, 0, 0);
            if (ep.wrapAt[i] != 0) _fail(F_WRAP_STORED, uint256(epochId), i);
            _pack(buf, (j - from) * WRAP_BYTES, w);
        }
        uint256 ptr = uint160(SSTORE2.write(buf));
        for (uint256 j = from; j < to; ++j) {
            ep.wrapAt[first + j] = ptr | ((j - from) * WRAP_BYTES) << 160;
        }
    }

    /// @dev One wrap at `off`: member (32) ‖ keyId (8, big-endian) ‖ mlkemCt (1,568) ‖ x25519Eph (32) ‖ sealedKey (48).
    function _pack(bytes memory buf, uint256 off, IPqChat.Wrap calldata w) private pure {
        bytes calldata ct = w.mlkemCt;
        bytes calldata sk = w.sealedKey;
        (bytes32 m, uint64 kid, bytes32 x) = (w.member, w.keyId, w.x25519Eph);
        assembly ("memory-safe") {
            let q := add(add(buf, 32), off)
            mstore(q, m)
            mstore(add(q, 32), shl(192, kid))
            calldatacopy(add(q, 40), ct.offset, 1568)
            mstore(add(q, 1608), x)
            calldatacopy(add(q, 1640), sk.offset, 48)
        }
    }

    /// @dev Wrap `i` of `epochId` as stored (all zero when none).
    function _wrapAt(bytes32 epochId, uint256 i) internal view returns (IPqChat.Wrap memory w) {
        uint256 at = _epochs()[epochId].wrapAt[i];
        if (at == 0) return w;
        bytes memory b = SSTORE2.read(address(uint160(at)), at >> 160, WRAP_BYTES);
        (w.mlkemCt, w.sealedKey) = (new bytes(MLKEM_CT), new bytes(SEALED_KEY));
        bytes memory ct = w.mlkemCt;
        bytes memory sk = w.sealedKey;
        bytes32 m;
        bytes32 kid;
        bytes32 x;
        assembly ("memory-safe") {
            let q := add(b, 32)
            m := mload(q)
            kid := mload(add(q, 32))
            mcopy(add(ct, 32), add(q, 40), 1568)
            x := mload(add(q, 1608))
            mcopy(add(sk, 32), add(q, 1640), 48)
        }
        (w.member, w.keyId, w.x25519Eph) = (m, uint64(bytes8(kid)), x);
    }

    // ------------------------------------------------------------------ lists

    /// @dev ponytail: linear scans; a sorted list's binary search if groups grow past a few hundred.
    function _has(bytes32[] memory a, bytes32 x) internal pure returns (bool) {
        for (uint256 i; i < a.length; ++i) {
            if (a[i] == x) return true;
        }
        return false;
    }

    function _memberAt(IPqChat.MemberKey[] memory m, bytes32 ua) internal pure returns (uint256) {
        for (uint256 i; i < m.length; ++i) {
            if (m[i].ua == ua) return i;
        }
        return type(uint256).max;
    }
}
