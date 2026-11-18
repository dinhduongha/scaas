// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {PqChatTypes} from "./PqChatTypes.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {PqGroupBase} from "../pqgroup/PqGroupBase.sol";

/// @title What `PqChat` and its body module `PqChatTopics` share (CTR-TOK-30, plan 3c 3C-D2): the ERC-7201 namespace
///        `scaas.pqchat`, the clone's chain values (`ChainEnv`, 3C-D1), the signature check, the nonce bitmaps and the
///        SSTORE2 blobs (3C-D3). The module runs by `DELEGATECALL` in the clone's context, so both read one state and one
///        env. The group code (epochs, wraps, lists, nonces, blobs, the env read) is `PqGroupBase`'s (CTR-PQV-12), reached
///        through this namespace by the hooks below. **UNAUDITED.**
abstract contract PqChatCore is PqGroupBase {
    struct Topic {
        bytes32 admin; // 0 = unknown
        address record; // the create record's head blob
        uint64 seq;
        bool openReplies;
        address latest; // the latest update's head blob, 0 before one
    }

    struct Entry {
        address record; // the original's head blob; 0 = unknown
        uint32 depth;
    }

    struct Vote {
        int8 value;
        uint64 seq;
    }

    struct Writer {
        bool granted;
        uint64 seq;
    }

    struct Score {
        uint128 up;
        uint128 down;
    }

    /// @custom:storage-location erc7201:scaas.pqchat
    struct S {
        bytes32 ownerUA;
        bool initialized;
        mapping(bytes32 => Epoch) epochs;
        mapping(bytes32 => bytes32) childOf;
        mapping(bytes32 => mapping(uint256 => uint256)) nonces;
        mapping(bytes32 => address[]) messages;
        mapping(bytes8 => address[]) stored;
        mapping(bytes32 => Topic) topics;
        mapping(bytes32 => mapping(bytes32 => Writer)) writers;
        mapping(bytes32 => Entry) entries;
        mapping(bytes32 => address[]) versions;
        mapping(bytes32 => mapping(bytes32 => Vote)) votes;
        mapping(bytes32 => Score) scores;
        bytes32[] allTopics;
        mapping(bytes32 => bytes32[]) topicsByAdmin;
        mapping(bytes32 => bytes32[]) writersOf;
        mapping(bytes32 => bytes32[]) posts;
        mapping(bytes32 => bytes32[]) replies;
        mapping(bytes32 => bytes32[]) byAuthor;
        mapping(bytes32 => bytes32[]) sessions; // per UA (owner 2026-11-10)
        mapping(bytes32 => bytes32[]) chain; // per session: its epochs >= 1 in completion order (epoch 0 implied)
        mapping(bytes32 => address[]) removals; // P48: per epoch, its `remove` records
    }

    /// @dev `keccak256(abi.encode(uint256(keccak256("scaas.pqchat")) - 1)) & ~bytes32(uint256(0xff))`.
    bytes32 internal constant SLOT = 0xc7b36804b17476e9a19a6ebc690cd7b9326d322c515fd7dc91373f9bc6dc3000;

    function _s() internal pure returns (S storage s) {
        assembly ("memory-safe") {
            s.slot := SLOT
        }
    }

    // ------------------------------------------------------------------ the group hooks (PqGroupBase)

    function _epochs() internal view override returns (mapping(bytes32 => Epoch) storage) {
        return _s().epochs;
    }

    function _childOf() internal view override returns (mapping(bytes32 => bytes32) storage) {
        return _s().childOf;
    }

    function _nonces() internal view override returns (mapping(bytes32 => mapping(uint256 => uint256)) storage) {
        return _s().nonces;
    }

    function _chain() internal view override returns (mapping(bytes32 => bytes32[]) storage) {
        return _s().chain;
    }

    /// @dev The admins, members and wrap hashes of a stored epoch record (the session for epoch 0).
    function _lists(Epoch storage ep)
        internal
        view
        override
        returns (bytes32[] memory admins, IPqChat.MemberKey[] memory members, bytes32[] memory hashes)
    {
        bytes memory b = _get(ep.record);
        if (ep.epoch == 0) {
            (IPqChat.PqChatSession memory s,) = abi.decode(b, (IPqChat.PqChatSession, bytes32));
            return (s.admins, s.members, s.wrapHashes);
        }
        (IPqChat.PqChatEpoch memory e,) = abi.decode(b, (IPqChat.PqChatEpoch, bytes32));
        return (e.admins, e.members, e.wrapHashes);
    }

    /// @dev What the shared code here and in the body module raises (the env read, the nonce bitmap); `PqChat` maps every other
    ///      code (`_fail` there), so the module's ABI keeps its two errors.
    function _fail(uint8 code, uint256 a, uint256 b) internal pure virtual override {
        if (code == F_NONCE_USED) revert IPqChat.PqChatNonceUsed(bytes32(a), uint64(b));
        revert IPqChat.PqChatEnv();
    }

    // ------------------------------------------------------------------ internal: signatures

    /// @dev P7: `ua`'s portable signature over `typed(structHash)` under `PURPOSE_PQCHAT`.
    function _auth(IUARegistry reg, bytes32 ua, bytes32 structHash, IUARegistry.UASig calldata sig) internal view {
        reg.requirePortable(ua, UAKinds.PURPOSE_PQCHAT, PqChatTypes.typed(structHash), sig);
    }
}
