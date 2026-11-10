// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {PqChatTypes} from "./PqChatTypes.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title What `PqChat` and its body module `PqChatTopics` share (CTR-TOK-30, plan 3c 3C-D2): the ERC-7201 namespace
///        `scaas.pqchat`, the clone's chain values (`ChainEnv`, 3C-D1), the signature check, the nonce bitmaps and the
///        SSTORE2 blobs (3C-D3). The module runs by `DELEGATECALL` in the clone's context, so both read one state and one
///        env. **UNAUDITED.**
abstract contract PqChatCore {
    /// @notice EIP-170's limit, the smallest of any EVM chain (3C-D1).
    uint256 internal constant MIN_CODE_LIMIT = 24_576;

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

    struct Topic {
        bytes32 owner; // 0 = unknown
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
        mapping(bytes32 => bytes32[]) topicsByOwner;
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


    // ------------------------------------------------------------------ internal: env, signatures, nonces

    /// @dev The registry, the code-size limit and `chain_uid` of this clone (3C-D1); the implementation (no env) refuses.
    function _env() internal view returns (IUARegistry reg, uint256 limit, bytes32 uid) {
        IFactoryToken.ChainEnv memory e = ChainEnvCode.decode();
        limit = e.params.length == 0 ? 0 : uint256(e.params[0]);
        if (limit < MIN_CODE_LIMIT || e.registry == address(0)) revert IPqChat.PqChatEnv();
        (reg, uid) = (IUARegistry(e.registry), e.chainUid);
    }

    /// @dev P7: `ua`'s portable signature over `typed(structHash)` under `PURPOSE_PQCHAT`.
    function _auth(IUARegistry reg, bytes32 ua, bytes32 structHash, IUARegistry.UASig calldata sig) internal view {
        reg.requirePortable(ua, UAKinds.PURPOSE_PQCHAT, PqChatTypes.typed(structHash), sig);
    }

    function _nonceUsed(bytes32 scope, uint64 nonce) internal view returns (bool) {
        return _s().nonces[scope][nonce >> 8] & (1 << (nonce & 0xff)) != 0;
    }

    /// @dev A bitmap per scope, any order, never locked (§4.3); called after the signature.
    function _useNonce(bytes32 scope, uint64 nonce) internal {
        mapping(uint256 => uint256) storage b = _s().nonces[scope];
        uint256 bit = 1 << (nonce & 0xff);
        uint256 word = b[nonce >> 8];
        if (word & bit != 0) revert IPqChat.PqChatNonceUsed(scope, nonce);
        b[nonce >> 8] = word | bit;
    }

    // ------------------------------------------------------------------ internal: blobs (3C-D3)

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
            head = SSTORE2.write(head == address(0) ? bytes.concat(bytes1(0), part) : bytes.concat(bytes1(0x01), bytes20(head), part));
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
}
