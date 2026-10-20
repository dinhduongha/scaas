// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";

/// @title The UA registry (accounts.md §1.8): monotonic, admin-free records of derived UAs and the one entry point
///        `requireAuthorized` that tokens call for every UA signature.
/// @notice `eip712Domain()` (ERC-5267) comes from `IERC5267`: fields `0x1f`, name "SCaaS UARegistry", version = the
///         generation in decimal, salt = `chainUid`. The stored kinds add `keyOf`; the PQ kinds (P6c) the ML-DSA
///         expanded-key cache; UA-6 the PQZ key attribute of a PQ signing UA (`register`'s `pqzKey`, `recordOf`).
///         `requireZetherAuthorized` stays until UA-6 Task 4 (every Zether UA is "self" since UA-6: no `authRef`).
interface IUARegistry is IERC5267 {
    struct Record {
        uint16 kind;
        uint40 registeredAt;
        address keyPtr; // ≠ 0 only for stored kinds (UA-2c MuSig2/FROST, UA-3 Zether, P6c PQ)
        uint40 index; // the UA's position in its kind's list (`uaAt`)
    }

    /// `pqzKey`: the SSTORE2 pointer of the UA's PQZ key (UA-6), 0 = none.
    event UARegistered(bytes32 indexed ua, uint16 indexed kind, bytes keyData, address pqzKey);
    /// One part of an ML-DSA id's expanded key stored (P6c), at `ptr` (SSTORE2).
    event UAKeyCached(bytes32 indexed ua, uint16 indexed kind, uint256 part, address ptr);

    error UAKindDisabled(uint16 kind); // not enabled in this generation (incl. kinds a predecessor offers)
    error UAKeyData(uint16 kind); // non-canonical, curve, subgroup, identity, ordering, threshold, cap bound
    error UAIdInNativeSpace(bytes32 ua);
    error UAAlreadyRegistered(bytes32 ua);
    error UAKeyInUse(bytes32 keyHash, bytes32 owner); // layer 2
    error UAMemberUnknown(bytes32 member); // structure member not native/registered, or kind ∉ MEMBER
    error UAPqzHolder(bytes32 ua); // UA-6 U3: this UA's kind / structure may not hold a PQZ key
    error UAPoP();
    error UAUnauthorized(bytes32 ua); // also: ua is zether-bn254 or unregistered
    error UAKeyCache(uint16 kind); // not ML-DSA, disabled, part past the last, or the verifier uses a precompile
    error UAIndex(uint16 kind, uint256 i); // uaAt past the kind's count
    error UANotIndexed(bytes32 ua); // uaIndex of an unregistered id

    function generation() external view returns (uint8); // 1 or 2
    function predecessor() external view returns (address);
    function kindEnabled(uint16 kind) external view returns (bool);
    function verifyCap(uint16 kind) external view returns (uint64); // measured per chain
    function verifyBudget() external view returns (uint64); // UA_VERIFY_BUDGET of this chain
    function chainUid() external view returns (bytes32); // genesis hash, constructor immutable
    function chainKeyHash() external view returns (bytes32); // keccak256("evm:" ‖ decimal(chainid)), at deploy (CTR-UA-07)
    function hederaNative() external view returns (bool); // Hedera profile: 0x0003 ∈ MEMBER
    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32);
    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32); // 0 for structures
    /// `pqzKeyHash` = `keyHashOf(0x0142, pqzKey)`, 0 for a UA without a PQZ key (UA-6 U4).
    function popDigest(bytes32 ua, bytes32 pqzKeyHash) external view returns (bytes32);
    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32);
    /// EIP-712 digest of UAAuth(ua, purposeTag, digest) under this registry's domain: what native signers sign.
    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) external view returns (bytes32);

    /// `pqzKey`: the PQZ public key of a holder (`mldsa44`, `mldsa65`, `fndsa512`, a PQ-eligible `msig`; UA-6 U3), or
    /// empty; `pqzPop`: its `R_REG` proof over `uaMessage(0x0142, POP, popDigest(ua, h))`, empty iff `pqzKey` is.
    function register(uint16 kind, bytes calldata keyData, bytes calldata pop, bytes calldata pqzKey,
        bytes calldata pqzPop) external returns (bytes32 ua);

    /// `pqzKey`: the SSTORE2 pointer of the UA's PQZ key, 0 = none (gen 2 forwards gen-1 records).
    function recordOf(bytes32 ua) external view returns (Record memory r, address pqzKey);
    function kindOf(bytes32 ua) external view returns (uint16); // 0 = not registered (native ids too)
    function isRegistered(bytes32 ua) external view returns (bool);
    function keyOwner(bytes32 keyHash) external view returns (bytes32);
    /// The stored key of a stored kind (MuSig2 `Q`, FROST `Y`, Zether `Y`: zether.md CTR-ZTH-50; PQ `pk`), empty
    /// otherwise.
    function keyOf(bytes32 ua) external view returns (bytes memory);

    /// The per-kind list of registered UAs (owner 2026-10-17: decoy selection for PQZ and classical Zether, which
    /// wallets read as they choose; on chain because logs can be pruned). Every kind, msig included: each
    /// registration appends at `uaCount(kind)`, assigned by the registry. A kind this generation does not enable is
    /// answered by the predecessor (a single-key kind lives in exactly one generation; msig, enabled in both, has one
    /// list per generation).
    function uaCount(uint16 kind) external view returns (uint256);
    function uaAt(uint16 kind, uint256 i) external view returns (bytes32); // UAIndex if i >= uaCount(kind)
    /// Up to `n` ids from `start` (fewer at the end of the list; none if start >= uaCount(kind)).
    function uaPage(uint16 kind, uint256 start, uint256 n) external view returns (bytes32[] memory);
    function uaIndex(bytes32 ua) external view returns (uint256); // UANotIndexed if unregistered

    /// ML-DSA without a precompile (P6c): stores part `part` (ML-DSA-44: 0; ML-DSA-65: 0, 1; one transaction each) of
    /// the EIP-8051 expanded key the registry derives from `pk` under `uaOf(kind, pk)`; PoP and verify use it once
    /// every part is stored. Anyone may call it, before or after `register`; a stored part is never rewritten.
    function cacheExpandedKey(uint16 kind, bytes calldata pk, uint256 part) external returns (bytes32 ua);
    /// The stored part pointers (0 = not yet), this generation only.
    function expandedKeyOf(bytes32 ua) external view returns (address[2] memory);

    /// Reverts UAUnauthorized unless `auth` authorizes `digest` for `ua` under `purposeTag`.
    /// Native ids (ua >> 160 == 0): ECDSA low-s (EOA) or ERC-1271 (50 k cap; 400 k for SmartKeyAccount clones, by the
    ///   immutable clone codehash) over uaAuthDigest(ua, purposeTag, digest) — never over the raw digest.
    ///   Classified by code at call time: empty ⇒ ECDSA; 7702 designator ⇒ ECDSA, else 1271; other ⇒ 1271.
    /// Derived SIGNING: auth = abi.encode(bytes keyData, bytes sig); keyData empty for stored kinds (Zether
    ///   `zether-bls12381` included, UA-6 U8: a Schnorr by `x` on `Y`).
    ///   msig: sig = abi.encode(MemberSig[]), MemberSig{uint16 index; bytes keyData; bytes sig}.
    /// `zether-bn254` or unregistered: UAUnauthorized.
    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth) external view;

    /// Reverts UAUnauthorized unless `auth` authorizes `digest` for the Zether UA `ua` (accounts.md §1.7 Z-auth; removed
    /// in UA-6 Task 4). Every Zether UA is "self": zkCovered ⇒ `auth` empty (the proof is the authorization);
    /// !zkCovered ⇒ a Zether Schnorr by `x`, `auth = abi.encode(bytes(""), sig)`, over
    /// uaMessage(kind, PURPOSE_ZETHER_OWNER, digest), `Y` from `keyPtr`. Not a Zether UA, or unregistered: UAUnauthorized.
    function requireZetherAuthorized(bytes32 ua, bytes32 digest, bytes calldata auth, bool zkCovered) external view;
}
