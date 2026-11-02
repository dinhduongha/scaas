// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "./IUARegistry.sol";
import {UAKinds} from "./UAKinds.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title SPIKE (registry size, scratch only): the registry's storage as one struct at slot 0, shared by `UARegistry` and
///        its linked libraries (which run by DELEGATECALL), plus the helpers more than one of them needs. The fields are
///        the baseline's mappings in the baseline's order, so every slot number is unchanged: `SaltedEIP712` has no
///        storage (immutables only), the first mapping was already at slot 0.
library UAStore {
    struct PqzKey {
        address ptr;
        bool proven;
        bool added;
    }

    struct KemCommit {
        bytes32 kemPkHash;
        uint8 scheme;
    }

    struct Layout {
        mapping(bytes32 ua => IUARegistry.Record) records; // 0
        mapping(bytes32 keyHash => bytes32) keyOwner; // 1
        mapping(bytes32 ua => PqzKey) pqzKey; // 2
        mapping(bytes32 ua => address[2]) ekPtr; // 3
        mapping(uint16 kind => uint256) uaCount; // 4
        mapping(uint16 kind => mapping(uint256 i => bytes32 ua)) uaAt; // 5
        mapping(bytes32 ua => address[]) reg; // 6
        mapping(bytes32 ua => bytes32) pqzPopHash; // 7
        mapping(bytes32 ua => address[]) pqzPop; // 8
        mapping(bytes32 ua => address[]) pqzKeySig; // 9
        mapping(bytes32 ua => mapping(uint64 version => address[])) kem; // 10
        mapping(bytes32 ua => uint64) kemMax; // 11
        mapping(bytes32 ua => KemCommit) kemCommit; // 12
        mapping(bytes32 ua => address) regPqzKey; // 13
        mapping(bytes32 ua => bytes32) regPqzPopHash; // 14
    }

    function layout() internal pure returns (Layout storage s) {
        assembly ("memory-safe") {
            s.slot := 0
        }
    }

    function word(bytes memory d, uint256 o) internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(d, 32), o))
        }
    }

    function u16(bytes memory d, uint256 o) internal pure returns (uint256) {
        return word(d, o) >> 240;
    }

    /// `n` bytes of `d` from `o`.
    function cut(bytes memory d, uint256 o, uint256 n) internal pure returns (bytes memory r) {
        r = new bytes(n);
        assembly ("memory-safe") {
            mcopy(add(r, 32), add(add(d, 32), o), n)
        }
    }

    function isPq(uint16 kind) internal pure returns (bool) {
        return kind >= UAKinds.MLDSA44 && kind <= UAKinds.SLHDSA128S;
    }

    function vkLength(uint16 kind) internal pure returns (uint256) {
        if (kind == UAKinds.MUSIG2_SECP256K1 || kind == UAKinds.FROST_SECP256K1) return 33;
        if (kind == UAKinds.MUSIG2_BN254 || kind == UAKinds.FROST_BN254) return 64;
        if (kind == UAKinds.ZETHER_BLS12381) return 128;
        if (kind == UAKinds.MLDSA44) return 1312;
        if (kind == UAKinds.MLDSA65) return 1952;
        if (kind == UAKinds.FNDSA512) return 897;
        if (kind == UAKinds.SLHDSA128S) return 32;
        return 0;
    }

    function checked(bool chain) internal pure returns (uint8) {
        return chain ? UAKinds.CHECKED_CHAIN : UAKinds.CHECKED_NONE;
    }

    /// The registration blob of a record held here: `keyData` (`keyPtr` prefix ‖ the rest), `pop`.
    function registration(bytes32 ua, address keyPtr) internal view returns (bytes memory keyData, bytes memory pop) {
        bytes memory rest;
        (rest, pop) = abi.decode(SSTORE2.readChunks(layout().reg[ua]), (bytes, bytes));
        keyData = bytes.concat(SSTORE2.read(keyPtr), rest);
    }

    /// The `keyRest` of a record held here, read alone (see the baseline's `_keyRest`).
    function keyRest(bytes32 ua) internal view returns (bytes memory) {
        address p = layout().reg[ua][0];
        return SSTORE2.read(p, 0x60, uint256(bytes32(SSTORE2.read(p, 0x40, 32))));
    }

    /// The stored KEM record of `(ua, version)` as its `KemKey` and `sig` (see the baseline's `_kemAt`).
    function kemAt(bytes32 ua, uint64 version) internal view returns (IUARegistry.KemKey memory kem, bytes memory sig) {
        bytes memory b = SSTORE2.readChunks(layout().kem[ua][version]);
        if (b.length == 0) return (kem, sig);
        uint256 n = UAKinds.KEM_PK_LENGTH;
        kem.scheme = uint8(b[0]);
        bytes memory ek = new bytes(n - 33);
        sig = new bytes(b.length - n);
        bytes32 x;
        assembly ("memory-safe") {
            mcopy(add(ek, 32), add(b, 33), mload(ek))
            x := mload(add(b, add(32, sub(n, 32))))
            mcopy(add(sig, 32), add(add(b, 32), n), mload(sig))
        }
        (kem.mlkemEk, kem.x25519) = (ek, x);
    }

    /// The part pointers of a complete ML-DSA cache (20 bytes each, in order), else empty.
    function expanded(bytes32 ua, uint16 kind) internal view returns (bytes memory) {
        if (kind != UAKinds.MLDSA44 && kind != UAKinds.MLDSA65) return "";
        address a = layout().ekPtr[ua][0];
        if (a == address(0)) return "";
        if (kind == UAKinds.MLDSA44) return abi.encodePacked(a);
        address b = layout().ekPtr[ua][1];
        return b == address(0) ? bytes("") : abi.encodePacked(a, b);
    }

    /// `staticcall` with exactly `cap` gas (see the baseline's `_capped`).
    function capped(address target, uint256 cap, bytes memory data, uint256 expect, bool hold)
        internal
        view
        returns (bool ok)
    {
        if (hold && gasleft() < cap + cap / 63 + SigCheck.GAS_MARGIN) revert UAKinds.UAVerifyGas();
        assembly ("memory-safe") {
            mstore(0, 0)
            let s := staticcall(cap, target, add(data, 0x20), mload(data), 0, 0x20)
            ok := and(and(s, eq(returndatasize(), 0x20)), eq(mload(0), expect))
        }
    }
}
