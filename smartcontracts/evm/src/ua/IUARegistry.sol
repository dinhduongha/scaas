// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";

/// @title The UA-8 members `UARegistry` does not implement yet (spec 2026-10-25-ua8-portable-registrations, P4, P7, P9).
/// @notice UA-8 Task A5 folded the rest of the surface into `IUARegistry` (ruling C3), A6 `storePqzPop`, `setPqzKey` and
///         `pqzKeySigOf`; A7 (`setKemKey`) moves the rest there as it implements it.
interface IUARegistryUA8 {
    /// A KEM record stored; `keyHash = keccak256(kemPk)`. Checked on chain (`CHECKED_CHAIN`) on EVM.
    event UAKemKeySet(bytes32 indexed ua, uint64 indexed version, bytes32 keyHash);

    /// Anyone; `sig` in the `pop` format over `uaMessage(kind, PURPOSE_KEM, kemRecordDigest(ua, version, kemPk))`; each
    /// `(ua, version)` once, any order (UA8-D5).
    function setKemKey(bytes32 ua, uint64 version, bytes calldata kemPk, bytes calldata sig) external;
}

/// @title The UA registry (accounts.md §1.8): monotonic, admin-free records of derived UAs and the one entry point
///        `requireAuthorized` that tokens call for every UA signature.
/// @notice `eip712Domain()` (ERC-5267) comes from `IERC5267`: fields `0x1f`, name "SCaaS UARegistry", version = the
///         generation in decimal, salt = `chainUid`. The stored kinds add `keyOf`; the PQ kinds (P6c) the ML-DSA
///         expanded-key cache; UA-6 the PQZ key attribute of a PQ signing UA (`register`'s `pqzKey`, `recordOf`).
///         The Zether UA signs through `requireAuthorized` like any stored kind (UA-6 U8); `requireZetherAuthorized`
///         is in `legacy/ua6/` (U9). UA-8 (spec 2026-10-25-ua8-portable-registrations, P1–P11): one portable `register`
///         (no chain context in the PoP; digests `UAKinds`, UA8-D1; vectors `smartcontracts/vectors/ua/portable.json`), every
///         field stored; the chain-bound `popDigest` / `register` / `UARegistered` are in `legacy/ua8/`. `checked` (P11.3) is
///         derived on EVM, not stored (ruling C8): every stored part is checked on chain, except a PQZ proof not yet proven
///         (`CHECKED_NONE`).
interface IUARegistry is IERC5267 {
    struct Record {
        uint16 kind;
        uint40 registeredAt;
        address keyPtr; // ≠ 0 only for stored kinds (UA-2c MuSig2/FROST, UA-3 Zether, P6c PQ)
        uint40 index; // the UA's position in its kind's list (`uaAt`)
    }

    /// The registration attributes, exactly as `register` takes them; empty / 0 = absent. `kemVersion` ≥ 1 with a
    /// 1,600-byte `kemPk` is the initial KEM record (UA8-D3, D4); `pqzPopHash = keccak256(pqzPop)` whenever `pqzKey` is set.
    struct UAAttrs {
        bytes pqzKey;
        bytes32 pqzPopHash;
        uint64 kemVersion;
        bytes kemPk;
    }

    /// Every `register` argument (the record is copyable from the log) and the three `checkedOf` values at registration.
    event UARegistered(
        bytes32 indexed ua, uint16 indexed kind, bytes keyData, UAAttrs attrs, bytes pop, bytes pqzPop, uint8 checkedPop,
        uint8 checkedPqzPop, uint8 checkedKem
    );
    /// The PQZ proof stored (`register` with a `pqzPop`, or `storePqzPop`); `checkedPqzPop` = `CHECKED_CHAIN` iff the
    /// verifier checked it. `pqzPop`: the bytes `storePqzPop` wrote (spec P2: a later write's event carries its bytes);
    /// empty when `register` wrote them (its `UARegistered`, emitted next, carries them).
    event UAPqzPopStored(bytes32 indexed ua, uint8 checkedPqzPop, bytes pqzPop);
    /// A PQZ key added by `setPqzKey` (`pqzKeyHash = keyHashOf(0x0142, pqzKey)`), with the call's bytes (spec P2: the
    /// record is copyable from the log); unproven (`CHECKED_NONE`) until its proof is stored (`UAPqzPopStored`).
    event UAPqzKeyAdded(bytes32 indexed ua, bytes32 pqzKeyHash, bytes32 pqzPopHash, bytes pqzKey, bytes sig);
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
    error UAUnauthorized(bytes32 ua); // also: ua is unregistered
    error UAKeyCache(uint16 kind); // not ML-DSA, disabled, part past the last, or the verifier uses a precompile
    error UAIndex(uint16 kind, uint256 i); // uaAt past the kind's count
    error UANotIndexed(bytes32 ua); // uaIndex of an unregistered id
    error UAKemHolder(bytes32 ua); // kind / structure may not hold a KEM key (UA8-D12)
    error UAKemVersion(bytes32 ua, uint64 version); // 0 (with a key), or already stored
    error UAKemKeyLength(uint256 length); // ≠ 1,600
    /// A PQZ key without its proof hash or a proof hash without a key (`register`; a zero hash in `setPqzKey`), a proof
    /// hash of `keccak256("")` or empty proof bytes in `storePqzPop` (ruling A6-m), or proof bytes that do not hash to the
    /// (stored) `pqzPopHash`.
    error UAPqzPopHash(bytes32 ua);
    error UAPqzKeySet(bytes32 ua); // setPqzKey on a record that already has a PQZ key

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
    /// UA8-D1 (`UAKinds`): `pqzKeyHash = keyHashOf(0x0142, pqzKey)`, `kemRecordHash = kemRecordDigest(ua, kemVersion,
    /// kemPk)`, each 0 when absent.
    function portablePopDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 kemRecordHash) external pure returns (bytes32);
    function registrationDigest(bytes32 portable, bytes32 pqzPopHash) external pure returns (bytes32);
    function kemRecordDigest(bytes32 ua, uint64 version, bytes calldata kemPk) external pure returns (bytes32);
    function pqzKeyDigest(bytes32 ua, bytes32 pqzKeyHash) external pure returns (bytes32);
    function pqzKeyRecordDigest(bytes32 keyDigest, bytes32 pqzPopHash) external pure returns (bytes32);
    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32);
    /// EIP-712 digest of UAAuth(ua, purposeTag, digest) under this registry's domain: what native signers sign.
    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) external view returns (bytes32);

    /// `pop`: the kind's signature (an msig: `abi.encode(MemberSig[])` over `memberDigest`; a code-less native member by
    /// EIP-191 `personal_sign`, one with code by ERC-1271 over `memberDigest`) over `uaMessage(kind, PURPOSE_POP_V2,
    /// registrationDigest(portablePopDigest(ua, pqzKeyHash, kemRecordHash), attrs.pqzPopHash))`. `attrs`: only a holder
    /// (`mldsa44`, `mldsa65`, `fndsa512`, a PQ-eligible `msig`; UA-6 U3, UA8-D12) carries a PQZ key or a KEM record.
    /// `pqzPop`: the `R_REG` proof over `uaMessage(0x0142, PURPOSE_POP_V2, portablePopDigest(...))`, optional (empty: the
    /// key is stored unproven, `storePqzPop` later; also unproven where the `0x0142` slot is empty, UA8-D8). The attribute
    /// checks (holder, proof hash, PQZ key length, KEM version, KEM key length) come before the PoP (portable.json
    /// `negatives`). Anyone may submit; the same bytes register on every registry.
    function register(uint16 kind, bytes calldata keyData, UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua);

    /// Anyone (UA8-D8, P8): the `R_REG` proof of the UA's PQZ key, given later (or again) — `UAPqzPopHash` unless
    /// `keccak256(pqzPop)` is the stored `pqzPopHash` (so also for a UA without a PQZ key); a no-op (no event) once proof
    /// bytes are stored. Else the bytes are stored and, where slot `0x0142` has a verifier, checked over the key's `R_REG`
    /// message — `uaMessage(0x0142, PURPOSE_POP_V2, portablePopDigest(...))` for a key from `register`,
    /// `uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest(ua, pqzKeyHash))` for one from `setPqzKey` — (`UAPoP` on failure),
    /// then the key's owner (`UAKeyInUse`), `keyOwner`, the `0x0142` list, `proven`; `UAPqzPopStored` with the bytes.
    /// Empty `pqzPop`: `UAPqzPopHash` (ruling A6-m). `UAUnauthorized` for an id this registry does not hold (gen 2: a
    /// gen-1 record goes to gen 1, UA8-D11), except (ruling A6-I1) on a gen 2 that enables 0x0142 in front of a gen 1
    /// that does not: the PQZ attachment lives in the oldest generation with the verifier, so this gen 2 proves gen 1's
    /// key (pointer and hash read from gen 1) and keeps the proof, `proven`, owner and list entry itself.
    function storePqzPop(bytes32 ua, bytes calldata pqzPop) external;
    /// Anyone; adds the PQZ key to a record registered without one (ruling A1-I1: set once per chain, portable). `sig` in
    /// the `pop` format over `uaMessage(kind, PURPOSE_PQZ_KEY, pqzKeyRecordDigest(pqzKeyDigest(ua, pqzKeyHash), pqzPopHash))`;
    /// the key is stored unproven, and its `R_REG` (over `uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest(ua, pqzKeyHash))`)
    /// comes by `storePqzPop`. The key's bytes are stored once, at the SSTORE2 pointer `pqzKeyOf(ua).ptr` (as `recordOf`'s:
    /// `eth_getCode(ptr)` without its leading STOP byte), and carried by `UAPqzKeyAdded`. On a gen 2 that enables 0x0142
    /// in front of a gen 1 that does not, it takes gen-1 records too (ruling A6-I1, as `storePqzPop`); gen 1's key, if
    /// any, counts for `UAPqzKeySet`. Check order (ruling A4-c2): an id this registry does not hold (`UAUnauthorized`, as
    /// `storePqzPop`), a gen 2 whose gen 1 enables 0x0142 (`UAKindDisabled(0x0142)`, as `register`) → holder
    /// (`UAPqzHolder`, with the `msig` debit bound) → the record has a PQZ key (`UAPqzKeySet`) → the key's length
    /// (`UAKeyData(0x0142)`) / a zero or `keccak256("")` `pqzPopHash` (`UAPqzPopHash`) → signature (`UAUnauthorized`).
    /// `UAPoP` (`R_REG`) and `UAKeyInUse` (one UA per proven key) fire only where a proof is checked: `storePqzPop`,
    /// and `register` with a `pqzPop`. `UAPqzKeyAdded`.
    function setPqzKey(bytes32 ua, bytes calldata pqzKey, bytes32 pqzPopHash, bytes calldata sig) external;

    /// `pqzKey`: the SSTORE2 pointer of the UA's PQZ key, proven or not (UA8-D9: a directory), 0 = none (gen 2 forwards
    /// gen-1 records).
    function recordOf(bytes32 ua) external view returns (Record memory r, address pqzKey);
    /// Exactly the `register` arguments: a PQZ key added later by `setPqzKey` is not in `attrs` (read it, its proof and
    /// its signature with `pqzKeyOf`, `pqzPopOf`, `pqzKeySigOf`; ruling A4-c3). For a key from `register`, `pqzPop` is the
    /// stored proof (given in `register` or by `storePqzPop`; it hashes to `attrs.pqzPopHash`; ruling A5-c2).
    function registrationOf(bytes32 ua) external view returns (uint16 kind, bytes memory keyData, UAAttrs memory attrs,
        bytes memory pop, bytes memory pqzPop);
    function popOf(bytes32 ua) external view returns (bytes memory);
    function pqzPopOf(bytes32 ua) external view returns (bytes memory);
    /// `setPqzKey`'s signature; empty when the key came with `register` (its consent is the `pop`) or there is none.
    function pqzKeySigOf(bytes32 ua) external view returns (bytes memory);
    /// The PQZ key pointer (SSTORE2: the key is `eth_getCode(ptr)` without its leading STOP byte), its proof hash and
    /// whether the slot-0x0142 verifier checked the proof (UA8-D9). Gen 2: its own PQZ attachment of a gen-1 record if it
    /// holds one (ruling A6-I1), else gen 1's answer.
    function pqzKeyOf(bytes32 ua) external view returns (address ptr, bytes32 pqzPopHash, bool proven);
    /// The three parts (P11.3, ruling C8), `UAKinds.CHECKED_*`: `pop` = CHAIN; `pqzPop` = CHAIN iff proven, else NONE (no
    /// key, or not yet proven); `kem` = CHAIN once a KEM record is stored, else NONE; all NONE for an unregistered id.
    function checkedOf(bytes32 ua) external view returns (uint8 pop, uint8 pqzPop, uint8 kem);
    /// The highest stored version (0, "", "" without one); `sig` is "" for the initial record (UA8-D4).
    function kemKeyOf(bytes32 ua) external view returns (uint64 version, bytes memory pk, bytes memory sig);
    /// ("", "") for a version not stored.
    function kemKeyAt(bytes32 ua, uint64 version) external view returns (bytes memory pk, bytes memory sig);
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
    /// Unregistered: UAUnauthorized.
    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth) external view;
}
