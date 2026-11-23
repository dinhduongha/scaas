// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {PqChatTypes} from "./PqChatTypes.sol";
import {PqChatCore} from "./PqChatCore.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title `PqChatTree`: the body module of `PqChat`'s TreeKEM mode (`groupMode = 1`, CTR-CHAT-26, owner 2026-11-23: a new
///        DELEGATECALL body module), PqChat's entries over the shared tree of `PqGroupTree` (reached through `PqChatCore`).
/// @notice `PqChat` runs the mode-0 part of `createSession` (lists, keys, creator, signature, nonce, the record) and then
///         `treeCreate` here with its calldata; it forwards `addWraps` of a tree session. In the clone's context, so it reads
///         PqChat's state and env through the hooks; called directly it has no env (`PqChatEnv`). No `this`, `msg.sender`
///         unused, no guard of its own (`PqChat` holds none), its return and revert data forwarded verbatim. T3a of plan
///         2026-11-23-pqchat-treekem: the cold tree written with the wraps; `commit` and its pieces come in T3b. **UNAUDITED.**
contract PqChatTree is PqChatCore {
    /// @notice The factory whose `PqChat` releases name this module (checked by the release's constructor).
    address public immutable FACTORY;

    constructor(address factory_) {
        FACTORY = factory_;
    }

    /// @notice The creation step of a tree session (spec §8), after `PqChat.createSession` checked and stored the record
    ///         under the same arguments: an `sstore2` home (C1), this instance the home (C4), the caps (C10, C24); `treeId`,
    ///         `used`, `leaves` and the admin list written; the creator alone joins `sessionsOf` (C34); then the wraps.
    function treeCreate(IPqChat.PqChatSession calldata s, IPqChat.Wrap[] calldata wraps, IUARegistry.UASig calldata)
        external
        returns (bytes32 sid)
    {
        (IUARegistry reg, uint256 limit,) = _env();
        if (_s().sigStore != SIG_SSTORE2) revert IPqChat.PqChatTreeSigStore();
        sid = PqChatTypes.sessionId(s.creator, s.nonce);
        Epoch storage ep = _s().epochs[sid];
        if (!ep.home) revert IPqChat.PqChatTreeHome();
        if (s.sealedInfo.length > TREE_INFO_MAX) revert IPqChat.PqChatShape();
        _treeOpen(sid, PqChatTypes.hashSession(s), s.members.length, s.admins);
        _s().sessions[s.creator].push(sid);
        _treeListed(sid, s.creator);
        _landTree(reg, sid, ep, 0, wraps, s.members, s.wrapHashes, limit);
    }

    /// @notice `PqChat.addWraps` of a tree session: the wraps of epoch 0 with their leaves (C15).
    function addWraps(bytes32 epochId, uint32 first, IPqChat.Wrap[] calldata wraps) external {
        (IUARegistry reg, uint256 limit,) = _env();
        Epoch storage ep = _known(epochId);
        if (ep.epoch != 0) revert IPqChat.PqChatModeEntry(1); // a commit's Welcome wraps: T3b
        (, IPqChat.MemberKey[] memory members, bytes32[] memory hashes) = _lists(ep);
        _landTree(reg, epochId, ep, first, wraps, members, hashes, limit);
    }

    /// @dev Wraps `first..` of epoch 0 as mode 0's (`_land`); then leaf `i` = `members[i]` for each, its key admitted and not
    ///      live, and the UA in `sessionsOf` at its first key (C15, C34); at completion the genesis tree hash.
    function _landTree(
        IUARegistry reg,
        bytes32 sid,
        Epoch storage ep,
        uint256 first,
        IPqChat.Wrap[] calldata wraps,
        IPqChat.MemberKey[] memory members,
        bytes32[] memory hashes,
        uint256 limit
    ) internal {
        bool complete = _land(sid, ep, first, wraps, members, hashes, limit);
        for (uint256 j; j < wraps.length; ++j) {
            uint256 i = first + j;
            if (_treeSetLeaf(reg, sid, i, members[i].ua, members[i].keyId, 0, uint32(i))) {
                _s().sessions[members[i].ua].push(sid);
            }
        }
        emit IPqChat.PqChatWraps(sid, uint32(first), uint32(wraps.length));
        if (complete) {
            _treeGenesis(reg, sid, sid);
            emit IPqChat.PqChatEpochComplete(sid);
        }
    }

    function _fail(uint8 code, uint256 a, uint256 b) internal pure override {
        _chatFail(code, a, b);
    }
}
