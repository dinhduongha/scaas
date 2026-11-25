// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {PqChatTypes} from "./PqChatTypes.sol";
import {PqChatCore} from "./PqChatCore.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title `PqChatTreeMembers`: the body module of the exits, `treeLeave` and `treeRemove` of a tree session (spec §9, C9; owner
///        2026-11-24, the pre-approved split out of `PqChatTree`) and mode 0's `leave` and `remove` (CTR-CHAT-10, CTR-CHAT-20;
///        owner 2026-11-25, moved out of `PqChat` when E-3 took it over its size line).
/// @notice `PqChat` forwards the four entries here by `DELEGATECALL`, in the clone's context, so it reads and writes PqChat's state
///         and env through the same hooks as `PqChatTree`; called directly it has no env (`PqChatEnv`). No `this`,
///         `msg.sender` unused, no guard of its own, its return and revert data forwarded verbatim. An exit names a complete
///         epoch of the session within `EXIT_LAG_MAX` of the head and is checked and applied at the head (C9, Change
///         2026-11-24, E-3). **UNAUDITED.**
contract PqChatTreeMembers is PqChatCore {
    /// @notice The factory whose `PqChat` releases name this module (checked by the release's constructor).
    address public immutable FACTORY;

    constructor(address factory_) {
        FACTORY = factory_;
    }

    /// @dev C9 (Change 2026-11-24, E-3): `epochId` a complete epoch of the tree session `sid`, which is the head or an
    ///      ancestor of it (C4, C20: no walk), at most `EXIT_LAG_MAX` below the head (`PqChatExitLag`). Returns its number,
    ///      the head's id and the head.
    function _exitAt(Tree storage t, bytes32 sid, bytes32 epochId)
        internal
        view
        returns (uint64 named, bytes32 hid, Epoch storage head)
    {
        Epoch storage ep = _known(epochId);
        if (ep.sessionId != sid) revert IPqChat.PqChatUnknown(epochId);
        if (ep.landed != ep.wraps) revert IPqChat.PqChatIncomplete(epochId);
        named = ep.epoch;
        hid = t.head;
        head = _s().epochs[hid];
        if (head.epoch > named + EXIT_LAG_MAX) revert IPqChat.PqChatExitLag(named, head.epoch);
    }

    /// @notice C9, C21, C28, C38: a live member of the head leaves; it is `gone` (kind 1) from the head's number and its
    ///         leaves at the head are owed; the record is kept under the head. The record that closes a session is accepted.
    function treeLeave(IPqChat.PqChatTreeLeave calldata l, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        Tree storage t = _treeOf(l.sessionId);
        if (l.treeId != t.treeId) revert IPqChat.PqChatTreeHome();
        (, bytes32 hid, Epoch storage head) = _exitAt(t, l.sessionId, l.epochId);
        if (!_treeMember(t, l.member)) revert IPqChat.PqChatNotMember(l.member); // A-4: a gone UA too
        _auth(reg, l.member, PqChatTypes.hashTreeLeave(l), sig);
        _useNonce(PqChatTypes.scopeEpoch(l.sessionId, l.member), l.nonce);
        _treeGo(l.sessionId, l.member, 1, head.epoch);
        head.left[l.member] = true;
        _s().leaves[hid].push(_put(abi.encode(l, keccak256(abi.encode(sig)), sig), limit));
        emit IPqChat.PqChatLeft(l.sessionId, hid, l.member);
    }

    /// @notice C9, C21, C24, C28, C38: a live admin of the head removes members or admins (strictly sorted, its own UA
    ///         allowed), each a member of the head (a live leaf or in its `admins`) and not `gone` (A-4); they are `gone`
    ///         (kind 2) from the head's number and their leaves at the head are owed; `nextEpoch` is the named epoch's number
    ///         plus one; the record is kept under the head. An admin with a live leaf remains while any member keeps a leaf.
    ///         The record that closes a session is accepted.
    function treeRemove(IPqChat.PqChatTreeRemove calldata r, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        Tree storage t = _treeOf(r.sessionId);
        if (r.treeId != t.treeId) revert IPqChat.PqChatTreeHome();
        (uint64 named, bytes32 hid, Epoch storage head) = _exitAt(t, r.sessionId, r.epochId);
        if (r.nextEpoch != named + 1) revert IPqChat.PqChatEpochNumber(named + 1, r.nextEpoch);
        if (!_treeAdmin(t, r.admin)) revert IPqChat.PqChatNotAdmin(r.admin);
        uint256 n = r.members.length;
        if (n == 0) revert IPqChat.PqChatShape();
        for (uint256 i; i < n; ++i) {
            bytes32 u = r.members[i];
            if (i > 0 && u <= r.members[i - 1]) revert IPqChat.PqChatShape();
            if ((t.keysOf[u].live == 0 && !_in(t.admins, u)) || t.gone[u].kind != 0) {
                revert IPqChat.PqChatNotMember(u); // A-4: a UA already gone refuses the whole record
            }
        }
        _auth(reg, r.admin, PqChatTypes.hashTreeRemove(r), sig);
        _useNonce(PqChatTypes.scopeEpoch(r.sessionId, r.admin), r.nonce);
        bool leafy = _treeLeafyAdmin(t);
        uint64 at = head.epoch;
        for (uint256 i; i < n; ++i) {
            _treeGo(r.sessionId, r.members[i], 2, at);
            head.removedOf[r.members[i]] = true;
        }
        // C24 read with C38 (CTR-CHAT-27 Change 2026-11-24): refused only while a member that is not gone keeps a leaf
        if (leafy && !_treeLeafyAdmin(t) && _treeHasMember(t)) revert IPqChat.PqChatTreeAdmins();
        _s().removals[hid].push(_put(_blob(abi.encode(r), sig), limit));
        emit IPqChat.PqChatRemoved(r.sessionId, hid, r.admin, r.members);
    }

    // ------------------------------------------------------------------ mode 0 (owner 2026-11-25: moved here from `PqChat`)

    /// @dev `PqChat.REMOVE_MAX` (P48), which stays the public bound.
    uint256 internal constant REMOVE_MAX = 16;

    /// @notice P12, CTR-CHAT-10: a member leaves; the next epoch may drop it as a plain rekey (3C-D8). At home it names the
    ///         head or a complete ancestor within `EXIT_LAG_MAX` and applies at the head (C9, E-3); in a replica it flags the
    ///         epoch it names. A member already flagged there is refused (sc-E-5).
    function leave(IPqChat.PqChatLeave calldata l, IUARegistry.UASig calldata sig) external {
        if (_isTree(l.sessionId)) revert IPqChat.PqChatModeEntry(1); // C30: `treeLeave`
        (IUARegistry reg, uint256 limit,) = _env();
        (bytes32 at, Epoch storage ep,) = _exitAt(l.sessionId, l.epochId);
        (, IPqChat.MemberKey[] memory m,) = _lists(ep);
        if (_memberAt(m, l.member) == type(uint256).max || ep.left[l.member] || ep.removedOf[l.member]) {
            revert IPqChat.PqChatNotMember(l.member);
        }
        _auth(reg, l.member, PqChatTypes.hashLeave(l), sig);
        _useNonce(PqChatTypes.scopeEpoch(l.sessionId, l.member), l.nonce);
        ep.left[l.member] = true;
        if (_keep()) _s().leaves[at].push(_put(abi.encode(l, keccak256(abi.encode(sig)), sig), limit));
        emit IPqChat.PqChatLeft(l.sessionId, at, l.member);
    }

    /// @notice P48 (owner 2026-11-10), CTR-CHAT-20: an admin removes 1..REMOVE_MAX members, strictly sorted. At home it names
    ///         the head or a complete ancestor within `EXIT_LAG_MAX` and is checked and applied at the head (C9, E-3); in a
    ///         replica it flags the complete epoch it names. A UA already removed there is refused (A-4). The record and its
    ///         `sigHash` in state.
    function remove(IPqChat.PqChatRemove calldata r, IUARegistry.UASig calldata sig) external {
        if (_isTree(r.sessionId)) revert IPqChat.PqChatModeEntry(1); // C30: `treeRemove`
        (IUARegistry reg, uint256 limit,) = _env();
        (bytes32 at, Epoch storage ep, uint64 named) = _exitAt(r.sessionId, r.epochId);
        if (ep.landed != ep.wraps) revert IPqChat.PqChatIncomplete(r.epochId); // a replica's epoch named
        if (r.nextEpoch != named + 1) revert IPqChat.PqChatEpochNumber(named + 1, r.nextEpoch);
        uint256 n = r.members.length;
        if (n == 0 || n > REMOVE_MAX) revert IPqChat.PqChatShape();
        (bytes32[] memory admins, IPqChat.MemberKey[] memory m,) = _lists(ep);
        if (!_liveAdmin(ep, admins, r.admin)) revert IPqChat.PqChatNotAdmin(r.admin); // F2, F7 (controller call 2026-11-21)
        for (uint256 i; i < n; ++i) {
            if (i > 0 && r.members[i] <= r.members[i - 1]) revert IPqChat.PqChatShape();
            if (!_removable(m, admins, r.members[i]) || ep.removedOf[r.members[i]]) {
                revert IPqChat.PqChatNotMember(r.members[i]);
            }
        }
        _auth(reg, r.admin, PqChatTypes.hashRemove(r), sig);
        _useNonce(PqChatTypes.scopeEpoch(r.sessionId, r.admin), r.nonce);
        for (uint256 i; i < n; ++i) {
            ep.removedOf[r.members[i]] = true;
        }
        ep.removed += uint16(n);
        _s().removals[at].push(_put(_blob(abi.encode(r), sig), limit));
        emit IPqChat.PqChatRemoved(r.sessionId, at, r.admin, r.members);
    }

    function _fail(uint8 code, uint256 a, uint256 b) internal pure override {
        _chatFail(code, a, b);
    }
}
