// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "./IFactoryToken.sol";

/// @title An instance's chain environment in its own code (CTR-TOK-29, chain-neutral spec §2.1, option I): the one format
///        and the one decoder.
/// @notice The runtime code of every factory-made instance is the 45-byte EIP-1167 proxy followed by its `ChainEnv` (the
///         "ERC-1167 with immutable arguments" layout of Solady's `LibClone`; no dependency):
///
///             363d3d373d3d3d363d73 ‖ implementation (20) ‖ 5af43d82803e903d91602b57fd5bf3          45 B, never reaches below
///             ‖ chainUid (32) ‖ registry (20) ‖ govRouter (20) ‖ smartKeyAccountImpl (20) ‖ hedera (1)   head, 93 B
///             ‖ nDeps (1) ‖ deps (20 × nDeps) ‖ nParams (1) ‖ params (32 × nParams)                   counted tails
///
///         The proxy's only jump targets `0x2b`, so the bytes after it are data. Every reader copies from the code of
///         `address(this)`: under the clone's `DELEGATECALL` (and a library's or a body module's under it) that is the
///         clone. Whether the code is a clone is decided from the code itself, by the 45-byte proxy form, never by an
///         immutable of the implementation (library study §7, CN-1): anything else (the implementation, a contract that
///         is not a clone) reads an all-zero env. Written only by `OpenFactory` (`encode`, `initCode`); exposed typed by
///         each instance's `chainEnv()`.
library ChainEnvCode {
    uint256 internal constant PROXY = 45;
    uint256 internal constant HEAD = 93;
    uint256 internal constant MAX_DEPS = 4;
    uint256 internal constant MAX_PARAMS = 2;
    /// @dev Code offsets of the head's fields and of the deps count.
    uint256 internal constant OFF_CHAIN_UID = 45;
    uint256 internal constant OFF_REGISTRY = 77;
    uint256 internal constant OFF_GOV_ROUTER = 97;
    uint256 internal constant OFF_SKA = 117;
    uint256 internal constant OFF_HEDERA = 137;
    uint256 internal constant OFF_DEPS = 138;

    /// @dev The fixed-offset part, read by one copy of the code's first 138 bytes.
    struct Head {
        bytes32 chainUid;
        address registry;
        address govRouter;
        address smartKeyAccountImpl;
        bool hedera;
    }

    /// @notice The head, all zero unless this code is a clone (the EIP-1167 prefix and suffix around 20 bytes).
    function head() internal view returns (Head memory h) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            extcodecopy(address(), m, 0, 138)
            if and(eq(shr(176, mload(m)), 0x363d3d373d3d3d363d73),
                eq(shr(136, mload(add(m, 30))), 0x5af43d82803e903d91602b57fd5bf3)) {
                mstore(h, mload(add(m, 45)))
                mstore(add(h, 0x20), shr(96, mload(add(m, 77))))
                mstore(add(h, 0x40), shr(96, mload(add(m, 97))))
                mstore(add(h, 0x60), shr(96, mload(add(m, 117))))
                mstore(add(h, 0x80), byte(0, mload(add(m, 137))))
            }
        }
    }

    function isClone() internal view returns (bool ok) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            extcodecopy(address(), m, 0, 45)
            ok := and(eq(shr(176, mload(m)), 0x363d3d373d3d3d363d73),
                eq(shr(136, mload(add(m, 30))), 0x5af43d82803e903d91602b57fd5bf3))
        }
    }

    function chainUid() internal view returns (bytes32) { return head().chainUid; }

    function registry() internal view returns (address) { return head().registry; }

    function govRouter() internal view returns (address) { return head().govRouter; }

    function smartKeyAccountImpl() internal view returns (address) { return head().smartKeyAccountImpl; }

    function hedera() internal view returns (bool) { return head().hedera; }

    /// @notice Dependency `i` (`ENV_ZETHER_*`, `ENV_PQZ_VERIFIER`), 0 when absent or not a clone.
    function dep(uint256 i) internal view returns (address) {
        if (!isClone() || i >= _byte(OFF_DEPS)) return address(0);
        return address(bytes20(_word(OFF_DEPS + 1 + 20 * i)));
    }

    /// @notice The whole env, all zero (empty tails) unless this code is a clone.
    function decode() internal view returns (IFactoryToken.ChainEnv memory e) {
        Head memory h = head();
        (e.chainUid, e.registry, e.govRouter, e.smartKeyAccountImpl, e.hedera) =
            (h.chainUid, h.registry, h.govRouter, h.smartKeyAccountImpl, h.hedera);
        if (!isClone()) return e;
        uint256 n = _byte(OFF_DEPS);
        e.deps = new address[](n);
        for (uint256 i; i < n; ++i) e.deps[i] = address(bytes20(_word(OFF_DEPS + 1 + 20 * i)));
        uint256 off = OFF_DEPS + 1 + 20 * n;
        n = _byte(off);
        e.params = new bytes32[](n);
        for (uint256 i; i < n; ++i) e.params[i] = _word(off + 1 + 32 * i);
    }

    /// @notice `initialize`'s check (chain-neutral spec §2.1, Fable P3-4): this code is a clone whose length is exactly
    ///         45 + the env its counts give (at most 4 deps, 2 params) and whose `chainUid` is not 0, else `EnvMissing`.
    function requirePresent() internal view {
        if (head().chainUid == 0) revert IFactoryToken.EnvMissing();
        uint256 nd = _byte(OFF_DEPS);
        uint256 off = OFF_DEPS + 1 + 20 * nd;
        uint256 np = _byte(off);
        if (nd > MAX_DEPS || np > MAX_PARAMS || address(this).code.length != off + 1 + 32 * np) {
            revert IFactoryToken.EnvMissing();
        }
    }

    /// @notice The env bytes of `e` (the factory's composition; counts within the bounds, checked at `publishTokenEnv`).
    function encode(IFactoryToken.ChainEnv memory e) internal pure returns (bytes memory b) {
        b = abi.encodePacked(e.chainUid, e.registry, e.govRouter, e.smartKeyAccountImpl, e.hedera, uint8(e.deps.length));
        for (uint256 i; i < e.deps.length; ++i) b = bytes.concat(b, bytes20(e.deps[i]));
        b = bytes.concat(b, bytes1(uint8(e.params.length)));
        for (uint256 i; i < e.params.length; ++i) b = bytes.concat(b, e.params[i]);
    }

    /// @notice The init code of a clone of `implementation` with `env` appended: `PUSH2 n RETURNDATASIZE DUP2 PUSH1 10
    ///         RETURNDATASIZE CODECOPY RETURN` (10 B), then the runtime (`n = 45 + env.length`).
    function initCode(address implementation, bytes memory env) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"61", uint16(PROXY + env.length), hex"3d81600a3d39f3", hex"363d3d373d3d3d363d73",
            implementation, hex"5af43d82803e903d91602b57fd5bf3", env);
    }

    function _byte(uint256 off) private view returns (uint256 b) {
        assembly ("memory-safe") {
            mstore(0, 0)
            extcodecopy(address(), 0, off, 1)
            b := byte(0, mload(0))
        }
    }

    function _word(uint256 off) private view returns (bytes32 w) {
        assembly ("memory-safe") {
            extcodecopy(address(), 0, off, 32)
            w := mload(0)
        }
    }
}
