// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {UAKinds} from "./UAKinds.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title The registry's storage as one struct at slot 0, shared by `UARegistry` and `UARegistryLib` (which runs by
///        DELEGATECALL on it), and the helpers both need (typed-signing R2). `SaltedEIP712` has no storage (immutables
///        only), so `Layout` starts at slot 0 and every field keeps its slot number; pinned by `UARegistrySplit.t.sol`.
library UAStore {
    /// UA-6 / UA-8: the PQZ key's SSTORE2 pointer (0 = none; written once) and, in the same slot, whether the
    /// slot-0x0142 verifier checked its proof (UA8-D8, D9; `pqzKeyOf` costs a PQZ token's `_keyPtr` two SLOADs) and
    /// whether `setPqzKey` added it (ruling A1-I1: its `R_REG` message, and `registrationOf` leaves it out, A4-c3).
    struct PqzKey {
        address ptr;
        bool proven;
        bool added;
    }

    /// A `register` KEM key committed by hash (owner 2026-10-31): `kemPkHash` ≠ 0 and its scheme; version 0 stays empty
    /// until `setKemKey(ua, 0, …)` stores the key that hashes to it. Kept after the fill (`registrationOf`).
    struct KemCommit {
        bytes32 kemPkHash;
        uint8 scheme;
    }

    struct Layout {
        mapping(bytes32 ua => IUARegistry.Record) records; // 0
        mapping(bytes32 keyHash => bytes32) keyOwner; // 1
        mapping(bytes32 ua => PqzKey) pqzKey; // 2
        mapping(bytes32 ua => address[2]) ekPtr; // 3: ML-DSA expanded-key parts (SSTORE2), written once each
        mapping(uint16 kind => uint256) uaCount; // 4: per-kind list length (single-key kinds)
        mapping(uint16 kind => mapping(uint256 i => bytes32 ua)) uaAt; // 5
        /// 6. The registration blob (UA8-D7): `abi.encode(bytes keyRest, bytes pop)`, `keyRest` = the key data after the
        /// stored kinds' `keyPtr` prefix (all of it for the other kinds; an `msig`'s assembled CTR-UA-09 bytes), `pop` as
        /// `registrationOf` returns it (an `msig`: the 32 bytes of `keccak256(abi.encode(MemberSig[]))`, owner 2026-11-03, its slots
        /// in `UAMemberSig`; "" for none). `keyData` = `SSTORE2.read(keyPtr) ‖
        /// keyRest`: stored once. (Before typed-signing R1 a third word, the KEM version, always 0.)
        mapping(bytes32 ua => address[]) reg;
        mapping(bytes32 ua => bytes32) pqzPopHash; // 7: the PQZ key's proof hash (`attrs.pqzPopHash`)
        mapping(bytes32 ua => address[]) pqzPop; // 8: the R_REG proof bytes, written once
        mapping(bytes32 ua => address[]) pqzKeySig; // 9: `setPqzKey`'s signature, written once
        mapping(bytes32 ua => mapping(uint64 version => address[])) kem; // 10: `pk ‖ sig` (initial record: `sig` = "")
        mapping(bytes32 ua => uint64) kemMax; // 11: the highest stored KEM version (0: none, or the register key only)
        mapping(bytes32 ua => KemCommit) kemCommit; // 12
        /// 13, 14. Ruling R-cross-set: the `register` PQZ key (pointer) and proof hash a `setPqzKey` replaced (a key of
        /// another set's length, never provable here), kept so `registrationOf` still returns the `register` arguments.
        mapping(bytes32 ua => address) regPqzKey;
        mapping(bytes32 ua => bytes32) regPqzPopHash;
        /// 15. CTR-UA-37: an `msig`'s accepted slots, bit `i` = member slot `i`: the slots of its `pop`, written at
        /// registration, then `acceptMembership`. It lives with the record (gen 2 reads gen 1's).
        mapping(bytes32 ua => uint256) accepted;
        /// 16. CTR-UA-33 / CTR-UA-37 (owner 2026-11-03): `keccak256` of the signature object of an `msig`'s slot `index`, the slot's `sig` or
        /// an `msig` member's `abi.encode(InnerSig[])`, written once with its bit: at registration for each slot of the `pop`, by
        /// `acceptMembership` for a slot that accepts later. The bytes are in that slot's `UAMemberSig`.
        mapping(bytes32 ua => mapping(uint256 index => bytes32)) memberSigHash;
    }

    uint256 internal constant SMART_KEY_1271_GAS = 400_000;

    function layout() internal pure returns (Layout storage s) {
        assembly ("memory-safe") {
            s.slot := 0
        }
    }

    // ----- bytes helpers -----

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

    // ----- kinds -----

    /// PQ weight in an `msig` (CTR-PQZ-12): 0x0130–0x0134, `mldsa87` since owner 2026-11-04 (CTR-UA-39 Q3). Not the registry's
    /// config slot map (`UARegistry._slot`).
    function isPq(uint16 kind) internal pure returns (bool) {
        return kind >= UAKinds.MLDSA44 && kind <= UAKinds.MLDSA87;
    }

    /// Length of the stored `vk` of a stored kind (CTR-UA-17), 0 otherwise: `Q` / `Y` SEC1 compressed (secp256k1) or
    /// EIP-196 uncompressed (bn254), the first bytes of the key data; Zether `Y` (128) and the PQ `pk` (ML-DSA
    /// 1,312 / 1,952 / 2,592, FN-DSA 897, SLH-DSA 32), the whole key data. (The PQZ key has its own pointer, `pqzKey`.) The
    /// rest of the key data is in the registration blob (`reg`), so `keyData` is stored once (UA8-D7).
    function vkLength(uint16 kind) internal pure returns (uint256) {
        if (kind == UAKinds.MUSIG2_SECP256K1 || kind == UAKinds.FROST_SECP256K1) return 33;
        if (kind == UAKinds.MUSIG2_BN254 || kind == UAKinds.FROST_BN254) return 64;
        if (kind == UAKinds.ZETHER_BLS12381) return 128;
        if (kind == UAKinds.MLDSA44) return 1312;
        if (kind == UAKinds.MLDSA65) return 1952;
        if (kind == UAKinds.FNDSA512) return 897;
        if (kind == UAKinds.SLHDSA128S) return 32;
        if (kind == UAKinds.MLDSA87) return 2592;
        return 0;
    }

    function checked(bool chain) internal pure returns (uint8) {
        return chain ? UAKinds.CHECKED_CHAIN : UAKinds.CHECKED_NONE;
    }

    // ----- records held here -----

    /// The registration blob of a record held here: `keyData` (`keyPtr` prefix ‖ the rest), `pop`.
    function registration(bytes32 ua, address keyPtr) internal view returns (bytes memory keyData, bytes memory pop) {
        bytes memory rest;
        (rest, pop) = abi.decode(SSTORE2.readChunks(layout().reg[ua]), (bytes, bytes));
        keyData = bytes.concat(SSTORE2.read(keyPtr), rest);
    }

    /// The `keyRest` of a record held here, read alone (msig-pophash I1: never the blob's `pop`, whose length the
    /// member does not bound): the blob `abi.encode(keyRest, pop)` has `keyRest`'s length at 0x40 and its bytes from
    /// 0x60, in chunk 0 (key data of a non-stored kind: at most 256 B, an `msig` 580 B, a FROST rest at most 17,924 B;
    /// chunks 32,768 B).
    function keyRest(bytes32 ua) internal view returns (bytes memory) {
        address p = layout().reg[ua][0];
        return SSTORE2.read(p, 0x60, uint256(bytes32(SSTORE2.read(p, 0x40, 32))));
    }

    /// The stored record `scheme ‖ ek ‖ x25519 ‖ sig` of `(ua, version)` as its `KemKey` (scheme 1: the 1,601-byte key)
    /// and `sig`; (none, "") when not stored.
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

    // ----- signature checks -----

    /// `staticcall` with exactly `cap` gas; true iff it succeeds with exactly one 32-byte word equal to `expect`.
    /// `hold`: too little gas left to hand over the full cap ⇒ `UAVerifyGas` (63/64 starvation never turns into a
    /// verdict). Without `hold` (the group PoP, whose failure reverts `register` anyway) the call gets at most `cap`.
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

    /// The native rule (ruling D1; owner ruling 2026-10-30, "an EOA must really sign, no delegation"): an EOA (no code, or
    /// the EIP-7702 designator `0xef0100 ‖ delegate`) ⇒ ECDSA over `digest` by its own key only (65-byte r ‖ s ‖ v, low s, v
    /// 27 / 28: OZ `tryRecover`), never ERC-1271 through the delegate; other code ⇒ ERC-1271 `isValidSignature(digest, sig)`
    /// only, at 50 k, 400 k for a `SmartKeyAccount` clone (by its codehash `clone`, 0 = none). `digest` is `uaAuthDigest`
    /// for `_native`, or a portable record's typed digest for a native `msig` member (what `eth_signTypedData_v4` returns,
    /// no EIP-191, no chain context; typed-signing TS-D4, owner decision 4).
    function byCode(address a, bytes32 digest, bytes memory sig, bytes32 clone) internal view returns (bool) {
        if (!SigCheck.isContract(a)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            return err == ECDSA.RecoverError.NoError && rec == a;
        }
        uint256 cap = clone != 0 && a.codehash == clone ? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
        return capped(
            a,
            cap,
            abi.encodeCall(IERC1271.isValidSignature, (digest, sig)),
            uint256(bytes32(IERC1271.isValidSignature.selector)),
            true
        );
    }

    /// An inner `msig`'s signatures as the `MemberSig`s `_msig` checks: none carries a list, so nothing is checked below the inner level.
    function lift(IUARegistry.InnerSig[] memory inner) internal pure returns (IUARegistry.MemberSig[] memory s) {
        IUARegistry.InnerSig[] memory none;
        s = new IUARegistry.MemberSig[](inner.length);
        for (uint256 i; i < inner.length; ++i) {
            s[i] = IUARegistry.MemberSig(inner[i].index, none, inner[i].sig);
        }
    }

    /// `requireAuthorized` on `target` as a verdict. Records and kinds of gen 1 are checked by gen 1 (its verifiers, its
    /// `UAAuth` domain for native members of its structures); in `UARegistryLib` `target` is also the registry itself, for
    /// a derived `msig` member. Any revert there is a failed check, except starvation: a starved caller must see
    /// UAVerifyGas, never a verdict (T-AUTH-4): the target's own `UAVerifyGas` (at a hold) is re-raised, and so is the
    /// target running out of gas before its hold (W-M): no revert data and at most the 1/64 this frame kept (`g` = gasleft
    /// before the call); any other revert returns its unused gas and stays a verdict.
    function via(address target, bytes32 id, bytes32 purposeTag, bytes32 digest, IUARegistry.UASig memory auth)
        internal
        view
        returns (bool)
    {
        if (target == address(0)) return false;
        uint256 g = gasleft();
        try IUARegistry(target).requireAuthorized(id, purposeTag, digest, auth) {
            return true;
        } catch (bytes memory err) {
            if ((err.length == 4 && bytes4(err) == UAKinds.UAVerifyGas.selector) || (err.length == 0 && gasleft() < g / 63)) {
                revert UAKinds.UAVerifyGas();
            }
            return false;
        }
    }
}
