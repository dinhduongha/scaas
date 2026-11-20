// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {UAKinds} from "./UAKinds.sol";
import {PqUA} from "./PqUA.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {BlsMultiKeyData} from "./BlsMultiKeyData.sol";

/// @title The registry's storage as one struct at slot 0, shared by `UARegistry` and `UARegistryCoreLib` (which runs by
///        DELEGATECALL on it), and the helpers both need (typed-signing R2). `SaltedEIP712` has no storage (immutables
///        only), so `Layout` starts at slot 0 and every field keeps its slot number; pinned by `test/ua/UAStoreLayout.t.sol`
///        (group 3g, T51: the active pin; `UARegistrySplit.t.sol` is a legacy file).
library UAStore {
    /// UA-6 / UA-8, per version since group 3g: a PQZ key version's SSTORE2 pointer (0 = none; written once) and, in the
    /// same slot, whether the slot-0x0142 verifier checked its proof (UA8-D8, D9) and whether `setPqzKey` added it (ruling
    /// A1-I1: version 0's `R_REG` message, and `registrationOf` leaves it out, A4-c3; every version ≥ 1 is added).
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

    /// Group 3g (KV-3, §2.3): per UA, `latest` the highest version stored here, `current` the highest eligible one (0 when
    /// none is: version 0 as stored), non-decreasing, moved only where proof bytes are stored; `listed`: on the `0x0142`
    /// list (once per UA, at its first proven version, KV-2).
    struct PqzVersions {
        uint64 latest;
        uint64 current;
        bool listed;
    }

    struct Layout {
        mapping(bytes32 ua => IUARegistry.Record) records; // 0
        mapping(bytes32 keyHash => bytes32) keyOwner; // 1
        mapping(bytes32 ua => mapping(uint64 version => PqzKey)) pqzKey; // 2 (3g: per version)
        // 3: ML-DSA expanded-key parts (SSTORE2), written once each; `address[3]` since 3zh (mldsa87's third part at base + 2;
        // base + 0 and + 1 where they were, owner 2026-11-15)
        mapping(bytes32 ua => address[3]) ekPtr;
        mapping(uint16 kind => uint256) uaCount; // 4: per-kind list length (single-key kinds)
        mapping(uint16 kind => mapping(uint256 i => bytes32 ua)) uaAt; // 5
        /// 6. The registration blob (UA8-D7): `abi.encode(bytes keyRest, bytes pop)`, `keyRest` = the key data after the
        /// stored kinds' `keyPtr` prefix (all of it for the other kinds; an `msig`'s assembled CTR-UA-09 bytes), `pop` as
        /// `registrationOf` returns it (an `msig`: the 32 bytes of `keccak256(abi.encode(MemberSig[]))`, owner 2026-11-03, its slots
        /// in `UAMemberSig`; "" for none). `keyData` = `SSTORE2.read(keyPtr) ‖
        /// keyRest`: stored once. (Before typed-signing R1 a third word, the KEM version, always 0.)
        mapping(bytes32 ua => address[]) reg;
        mapping(bytes32 ua => mapping(uint64 version => bytes32)) pqzPopHash; // 7: a version's proof hash
        mapping(bytes32 ua => mapping(uint64 version => address[])) pqzPop; // 8: a version's R_REG proof bytes, written once
        mapping(bytes32 ua => mapping(uint64 version => address[])) pqzKeySig; // 9: `setPqzKey`'s signature, written once
        mapping(bytes32 ua => mapping(uint64 version => address[])) kem; // 10: `pk ‖ sig` (initial record: `sig` = "")
        mapping(bytes32 ua => uint64) kemMax; // 11: the highest stored KEM version (0: none, or the register key only)
        mapping(bytes32 ua => KemCommit) kemCommit; // 12
        /// 13, 14. Retired by R2 (owner 2026-11-06): ruling R-cross-set's kept `register` key; never written, placeholders so
        /// that 15 and 16 keep their numbers.
        mapping(bytes32 ua => address) retiredRegPqzKey;
        mapping(bytes32 ua => bytes32) retiredRegPqzPopHash;
        /// 15. CTR-UA-37: an `msig`'s accepted slots, bit `i` = member slot `i`: the slots of its `pop`, written at
        /// registration, then `acceptMembership`. It lives with the record (gen 2 reads gen 1's).
        mapping(bytes32 ua => uint256) accepted;
        /// 16. CTR-UA-33 / CTR-UA-37 (owner 2026-11-03): `keccak256` of the signature object of an `msig`'s slot `index`, the slot's `sig` or
        /// an `msig` member's `abi.encode(InnerSig[])`, written once with its bit: at registration for each slot of the `pop`, by
        /// `acceptMembership` for a slot that accepts later. The bytes are in that slot's `UAMemberSig`.
        mapping(bytes32 ua => mapping(uint256 index => bytes32)) memberSigHash;
        /// 17. Group 3g: `latest`, `current`, `listed` of the UA's PQZ key versions.
        mapping(bytes32 ua => PqzVersions) pqzVersions;
        /// 18. Group 3g (KV-1, Codex #1): some version of the UA stores this key (proven or not): no two versions of one UA
        /// hold the same key bytes, on any registry kind. Per UA, so nobody squats another UA's key with it.
        mapping(bytes32 ua => mapping(bytes32 pqzKeyHash => bool)) pqzKeyUsed;
        /// 19. CTR-UA-33 Change 2026-11-08 (plan T66a): an `msig`'s `pop` slots, bit `i` = member slot `i` signed its `pop`, written once
        /// at registration and never again (0: an empty `pop`, or any other kind). `accepted` (15) adds the later acceptances; their
        /// difference is what accepted later (`popSlotsOf`). It lives with the record (gen 2 forwards gen 1's).
        mapping(bytes32 ua => uint256) popSlots;
        /// 20–26. The PQZ three-key model (spec 2026-11-13-pqz-three-keys K3-3): the scoped PQZ key records `(ua, scope,
        /// version)`, `scope` 0 for class `offchain-shared`, the token for class `offchain-token`, beside the unchanged class-1
        /// records (2, 7, 8, 17); each written once. 20 the key (`ptr`, `proven`; `added` unused), 21 its proof hash, 22 its
        /// `R_REG` proof bytes, 23 its opening KEM key `kemPk` (SSTORE2, 0 = none), 24 `latest` / `current` / `listed` per
        /// `(ua, scope)`, 25 / 26 the per-scope holder list (a UA once per scope, at its first eligible version).
        mapping(bytes32 ua => mapping(address scope => mapping(uint64 version => PqzKey))) scopedKey;
        mapping(bytes32 ua => mapping(address scope => mapping(uint64 version => bytes32))) scopedPopHash;
        mapping(bytes32 ua => mapping(address scope => mapping(uint64 version => address[]))) scopedPop;
        mapping(bytes32 ua => mapping(address scope => mapping(uint64 version => address))) scopedOpenKem;
        mapping(bytes32 ua => mapping(address scope => PqzVersions)) scopedVersions;
        mapping(address scope => uint256) scopedCount;
        mapping(address scope => mapping(uint256 i => bytes32 ua)) scopedAt;
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

    /// PQ weight in an `msig` (CTR-PQZ-12): 0x0130–0x0135, `mldsa87` and `fndsa1024` since owner 2026-11-04 (CTR-UA-39 / -40 Q3).
    /// Not the registry's config slot map (`UARegistry._slot`).
    function isPq(uint16 kind) internal pure returns (bool) {
        return kind >= UAKinds.MLDSA44 && kind <= UAKinds.FNDSA1024;
    }

    /// Length of the stored `vk` of a stored kind (CTR-UA-17), 0 otherwise: `Q` / `Y` SEC1 compressed (secp256k1) or
    /// EIP-196 uncompressed (bn254), the first bytes of the key data; Zether `Y` (128) and the PQ `pk` (ML-DSA
    /// 1,312 / 1,952 / 2,592, FN-DSA 897 / 1,793, SLH-DSA 32), the whole key data. (The PQZ key has its own pointer, `pqzKey`.) The
    /// rest of the key data is in the registration blob (`reg`), so `keyData` is stored once (UA8-D7). `bls12381-multi` (spec
    /// 2026-11-19-bls12381-multi §2, owner ruling 2026-11-19): 228, the fixed part of its stored `p = ua ‖ s` (`ua ‖ c(apk) ‖ t ‖ n`), a
    /// flag that the kind is stored, not a cut length (`p` grows with n); its record takes its own branch before any use as a length.
    function vkLength(uint16 kind) internal pure returns (uint256) {
        if (kind == UAKinds.MUSIG2_SECP256K1 || kind == UAKinds.FROST_SECP256K1) return 33;
        if (kind == UAKinds.MUSIG2_BN254 || kind == UAKinds.FROST_BN254) return 64;
        if (kind == UAKinds.ZETHER_BLS12381) return 128;
        if (kind == UAKinds.MLDSA44) return 1312;
        if (kind == UAKinds.MLDSA65) return 1952;
        if (kind == UAKinds.FNDSA512) return 897;
        if (kind == UAKinds.SLHDSA128S) return 32;
        if (kind == UAKinds.MLDSA87) return 2592;
        if (kind == UAKinds.FNDSA1024) return 1793;
        if (kind == UAKinds.BLS12381_MULTI) return 228;
        return 0;
    }

    function checked(bool chain) internal pure returns (uint8) {
        return chain ? UAKinds.CHECKED_CHAIN : UAKinds.CHECKED_NONE;
    }

    // ----- records held here -----

    /// The registration blob of the record `r` held here: `keyData` (`keyPtr` prefix ‖ the rest), `pop`. A kind with no stored
    /// `vk` has no prefix: an `msig`'s `keyPtr` is its current structure's (CTR-UA-44 MM-10), never part of its key data.
    function registration(bytes32 ua, IUARegistry.Record memory r)
        internal
        view
        returns (bytes memory keyData, bytes memory pop)
    {
        bytes memory rest;
        (rest, pop) = abi.decode(SSTORE2.readChunks(layout().reg[ua]), (bytes, bytes));
        if (r.kind == UAKinds.BLS12381_MULTI) {
            // the pointer holds `ua ‖ s`, the blob no key bytes (spec 2026-11-19-bls12381-multi §2): `d` byte-identical
            bytes memory p = SSTORE2.read(r.keyPtr);
            return (BlsMultiKeyData.expand(cut(p, 32, p.length - 32)), pop);
        }
        keyData = bytes.concat(SSTORE2.read(vkLength(r.kind) == 0 ? address(0) : r.keyPtr), rest);
    }

    /// The `keyRest` of a record held here, read alone (msig-pophash I1: never the blob's `pop`, whose length the
    /// member does not bound): the blob `abi.encode(keyRest, pop)` has `keyRest`'s length at 0x40 and its bytes from
    /// 0x60, in chunk 0 (key data of a non-stored kind: at most 256 B, an `msig` 580 B, a FROST rest at most 17,924 B;
    /// chunks 32,768 B).
    function keyRest(bytes32 ua) internal view returns (bytes memory) {
        address p = layout().reg[ua][0];
        return SSTORE2.read(p, 0x60, uint256(bytes32(SSTORE2.read(p, 0x40, 32))));
    }

    // ----- an `msig`'s current structure (CTR-UA-44, MM-6 … MM-9) -----

    /// The current structure of the `msig` `ua` held here, `ptr` its record's `keyPtr` (MM-7): 0 = never updated, the
    /// registration's CTR-UA-09 bytes (every slot enabled, version 0); else the `updateMsig` blob `u16 threshold ‖ u16 count ‖
    /// count × (u16 kind ‖ id ‖ u16 weight) ‖ u256 enabled ‖ u64 version` (MM-6), whose first `4 + 36·count` bytes are the
    /// CTR-UA-09 form, so every reader that indexes `4 + 36·i` keeps its offsets.
    function msig(bytes32 ua, address ptr) internal view returns (bytes memory) {
        return ptr == address(0) ? keyRest(ua) : SSTORE2.read(ptr);
    }

    /// The enabled slots of the structure `d` (MM-9): its trailer's word, else (no trailer: never updated) every slot, in the
    /// 256-safe form (`1 << 256` is 0). `enabled` has no bit past the slots (`updateMsig` row 5), so no reader masks by count.
    function enabledOf(bytes memory d) internal pure returns (uint256) {
        uint256 n = u16(d, 2);
        if (d.length > 4 + 36 * n) return word(d, 4 + 36 * n);
        return n >= 256 ? type(uint256).max : (1 << n) - 1;
    }

    /// The version of the structure `d` (0: no trailer, never updated).
    function versionOf(bytes memory d) internal pure returns (uint64) {
        uint256 o = 4 + 36 * u16(d, 2) + 32;
        return d.length > o ? uint64(word(d, o) >> 192) : 0;
    }

    /// `enabled` and `version` of an updated `msig` from its blob's last 40 bytes, without its slots (`memberAccepted`,
    /// `msigStateOf`). `ptr` ≠ 0.
    function trailer(address ptr) internal view returns (uint256 enabled, uint64 version) {
        bytes memory t = SSTORE2.read(ptr, ptr.code.length - 41, 40);
        (enabled, version) = (word(t, 0), uint64(word(t, 32) >> 192));
    }

    /// The blob of the structure `s` with its trailer (MM-6), in one allocation for any count (P2-4: never `bytes.concat` in a
    /// loop): what `updateMsig` stores, and the form a gen-1 structure takes here (`msigOf` + `msigStateOf`).
    function blob(IUARegistry.MsigStructure memory s, uint256 enabled, uint64 version)
        internal
        pure
        returns (bytes memory d)
    {
        IUARegistry.MsigMember[] memory m = s.members;
        uint256 n = m.length;
        uint256 len = 44 + 36 * n;
        uint256 t = s.threshold;
        d = new bytes(len + 32); // room for the last 32-byte store; the length is set back below
        assembly ("memory-safe") {
            let p := add(d, 32)
            mstore(p, or(shl(240, t), shl(224, n)))
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let e := mload(add(add(m, 32), mul(32, i)))
                let q := add(p, add(4, mul(36, i)))
                mstore(q, shl(240, and(mload(e), 0xffff)))
                mstore(add(q, 2), mload(add(e, 32)))
                mstore(add(q, 34), shl(240, and(mload(add(e, 64)), 0xffff)))
            }
            let q := add(p, add(4, mul(36, n)))
            mstore(q, enabled)
            mstore(add(q, 32), shl(192, version))
            mstore(d, len)
        }
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

    /// The part pointers of a complete ML-DSA cache (20 bytes each, in order), else empty: `PqUA.mldsaParts(kind)` of them
    /// (none for another kind, whose id holds no cache).
    function expanded(bytes32 ua, uint16 kind) internal view returns (bytes memory ek) {
        // `PqUA.mldsaParts(kind)`, inline on this hot path (`mldsa65` first: the common holder; `UAStoreLayout.t.sol` pins that the
        // two agree for every kind)
        uint256 n;
        if (kind == UAKinds.MLDSA65) n = 2;
        else if (kind == UAKinds.MLDSA44) n = 1;
        else if (kind == UAKinds.MLDSA87) n = 3;
        else return ek;
        address[3] storage p = layout().ekPtr[ua];
        address a = p[0];
        if (a == address(0)) return ek; // no cache (or a precompile kind): one read, nothing allocated
        ek = new bytes(20 * n + 12); // each pointer written as a word: 12 bytes of room after the last
        for (uint256 i; i < n; ++i) {
            if (i != 0) a = p[i];
            if (a == address(0)) return "";
            assembly ("memory-safe") {
                mstore(add(add(ek, 32), mul(i, 20)), shl(96, a))
            }
        }
        assembly ("memory-safe") {
            mstore(ek, mul(n, 20))
        }
    }

    /// CTR-UA-23 (owner 2026-11-15): true iff the ML-DSA kind's verifier `v` reports no precompile (`MldsaVerifier.PRECOMPILE()`
    /// = 0): there the registry verifies on the complete expanded-key cache only (the caller checked the kind is ML-DSA). A
    /// verifier without that getter (a test stand-in) keeps its own verdict.
    function noPrecompile(address v) internal view returns (bool r) {
        assembly ("memory-safe") {
            mstore(0, 0x0709d0b1) // PRECOMPILE()
            let ok := staticcall(gas(), v, 28, 4, 0, 32)
            r := and(and(ok, eq(returndatasize(), 32)), iszero(mload(0)))
        }
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
    /// `UAAuth` domain for native members of its structures); in `UARegistryCoreLib` `target` is also the registry itself, for
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
            if (
                (err.length == 4 && bytes4(err) == UAKinds.UAVerifyGas.selector)
                    || (err.length == 0 && gasleft() < g / 63)
            ) {
                revert UAKinds.UAVerifyGas();
            }
            return false;
        }
    }
}
