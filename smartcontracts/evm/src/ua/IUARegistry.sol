// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";

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
        /// ≠ 0 for stored kinds (UA-2c MuSig2/FROST, UA-3 Zether, P6c PQ); an `msig` after its first `updateMsig` (CTR-UA-44
        /// MM-7): the pointer of its current structure blob, never key data (0: never updated)
        address keyPtr;
        uint40 index; // the UA's position in its kind's list (`uaAt`)
    }

    /// One signature of a member of an inner `msig`: its slot `index` there, its `sig`. No list of its own, so a third level has no
    /// form (owner 2026-11-02: verification goes two levels only).
    struct InnerSig {
        uint16 index;
        bytes sig;
    }

    /// One `msig` slot's signature (CTR-UA-33: a member's key is read from its record). A signing member: `sig`, `members` empty; an
    /// `msig` member: `members`, its own slots up to its own threshold, `sig` empty. `members` sits where `keyData` sat: an empty array
    /// encodes as empty bytes do, so a flat signature's bytes, every stored `pop`, did not change.
    struct MemberSig {
        uint16 index;
        InnerSig[] members;
        bytes sig;
    }

    /// A UA's signature, explicit (typed-signing TS-D12): a native id only `signature`; a derived single key `keyData`
    /// (empty for the stored kinds, CTR-UA-17) + `signature`; an `msig` only `members` (its structure is read from the
    /// record). A portable record's signature (`setKemKey`, `setPqzKey`) never carries `keyData`. Any other field set ⇒
    /// not authorized.
    struct UASig {
        bytes keyData;
        bytes signature;
        MemberSig[] members;
    }

    /// An `msig` member (CTR-UA-09): `kind`, id, weight (TS-D10).
    struct MsigMember {
        uint16 kind;
        bytes32 id;
        uint16 weight;
    }

    /// An `msig` structure (TS-D10); the registry assembles the CTR-UA-09 key data `u16 threshold ‖ u16 n ‖ n × (u16 kind
    /// ‖ id ‖ u16 weight)` from it, so the id and every digest are those of the packed bytes.
    struct MsigStructure {
        uint16 threshold;
        MsigMember[] members;
    }

    /// A `webauthn-p256` key (typed-signing TS-D13, Appendix X row 12): the P-256 point and the relying party's
    /// `rpIdHash`; the registry assembles the key data `x ‖ y ‖ rpIdHash` (96 B), so the id and every digest are the
    /// packed bytes'.
    struct WebAuthnKey {
        bytes32 x;
        bytes32 y;
        bytes32 rpIdHash;
    }

    /// A MuSig2 group key (TS-D13): `aggKey` and the n sorted member keys, each one point (`musig2-secp256k1`: 33 B
    /// compressed, `musig2-bn254`: 64 B); assembled `aggKey ‖ u16 n ‖ n × key`.
    struct MuSig2Key {
        bytes aggKey;
        bytes[] memberKeys;
    }

    /// One FROST member (TS-D13): its `threshold` Feldman commitments, the PoK nonce point `r` (R_i) and response `z`.
    struct FrostMember {
        bytes[] commitments;
        bytes r;
        bytes32 z;
    }

    /// A FROST group key (TS-D13): points of 33 B (`frost-secp256k1`) or 64 B (`frost-bn254`); assembled `groupKey ‖
    /// u16 threshold ‖ u16 n ‖ n × (threshold commitments ‖ r ‖ z)`.
    struct FrostKey {
        bytes groupKey;
        uint16 threshold;
        FrostMember[] members;
    }

    /// One `bls12381-multi` member (spec 2026-11-19-bls12381-multi §2): its G2 key (256 B, EIP-2537) and weight (≥ 1).
    struct BlsMultiMember {
        bytes key;
        uint16 weight;
    }

    /// A `bls12381-multi` key (0x0121): `aggKey` = apk (256 B, EIP-2537), `threshold`, the members strictly increasing by key;
    /// assembled `aggKey ‖ u16 threshold ‖ u16 n ‖ n × (key ‖ u16 weight)`.
    struct BlsMultiKey {
        bytes aggKey;
        uint16 threshold;
        BlsMultiMember[] members;
    }

    /// A KEM public key (TS-D11): scheme 1 = ML-KEM-1024 `mlkemEk` (1,568 B) + X25519 `x25519`. The registry assembles
    /// `kemPk = scheme ‖ mlkemEk ‖ x25519` (1,601 B) for storage and `kemPkHash = keccak256(kemPk)`. All zero / empty =
    /// no key.
    struct KemKey {
        uint8 scheme;
        bytes mlkemEk;
        bytes32 x25519;
    }

    /// The registration attributes, exactly as `register` takes them; empty / 0 = absent. `pqzPopHash = keccak256(pqzPop)`
    /// whenever `pqzKey` is set. The KEM key given here is always version 0 (owner 2026-10-31), in one of two forms:
    /// the full key — `kem` set, `kemPkHash` 0 — stored now; or the hash commit — `kemPkHash` ≠ 0 and `kem` carrying only
    /// its `scheme` (`mlkemEk` empty, `x25519` 0) — when the full key does not fit the registration transaction (owner
    /// 2026-10-31: PQZH `n2560-kmax16384` with a PQZ key). Either way the PoP signs `UAKemRecord{ua, 0, scheme,
    /// kemPkHash}`; a committed key is stored later by `setKemKey(ua, 0, key, UASig())`, open to anyone. No KEM key:
    /// `kem` all zero and `kemPkHash` 0.
    struct UAAttrs {
        bytes pqzKey;
        bytes32 pqzPopHash;
        KemKey kem;
        bytes32 kemPkHash;
    }

    /// Every `register` argument but `pop`, which comes as `popHash = keccak256(pop)` (`keccak256("")` for an empty
    /// `pop`; CTR-UA-33, owner 2026-10-30: one rule on every family, an `msig` PoP of ML-DSA members overflows Soroban's
    /// 16,384 B events limit), and the three `checkedOf` values at registration. `pop` itself is in state (`popOf`,
    /// `registrationOf`): the record is copyable from the log plus `popOf`.
    event UARegistered(
        bytes32 indexed ua,
        uint16 indexed kind,
        bytes keyData,
        UAAttrs attrs,
        bytes32 popHash,
        bytes pqzPop,
        uint8 checkedPop,
        uint8 checkedPqzPop,
        uint8 checkedKem
    );
    /// The PQZ proof of key version `version` stored (`register` with a `pqzPop`: version 0, or `storePqzPop`);
    /// `checkedPqzPop` = `CHECKED_CHAIN` iff the verifier checked it. `pqzPop`: the bytes `storePqzPop` wrote (spec P2: a
    /// later write's event carries its bytes); empty when `register` wrote them (its `UARegistered`, emitted next, carries them).
    event UAPqzPopStored(bytes32 indexed ua, uint64 indexed version, uint8 checkedPqzPop, bytes pqzPop);
    /// PQZ key version `version` added by `setPqzKey` (`pqzKeyHash = keyHashOf(0x0142, pqzKey)`), with the call's bytes
    /// (spec P2: the record is copyable from the log; `sig` as stored, `pqzKeySigOf`: the `signature`, or an msig's
    /// `abi.encode(members)`); unproven (`CHECKED_NONE`) until its proof is stored (`UAPqzPopStored`). `register` never
    /// emits it: its version 0 is in `UARegistered` (group 3g, F-10).
    event UAPqzKeyAdded(
        bytes32 indexed ua, uint64 indexed version, bytes32 pqzKeyHash, bytes32 pqzPopHash, bytes pqzKey, bytes sig
    );
    /// Group 3g (KV-3): version `version` became the UA's current PQZ key here (the highest eligible version: proven where
    /// slot 0x0142 has a verifier, else this build's set length with its proof bytes stored); version 0 included, also
    /// inside `register` with a `pqzPop`. Credits go to it from this log position on.
    event UAPqzKeyCurrent(bytes32 indexed ua, uint64 indexed version);
    /// A KEM record stored by `setKemKey` (`keyHash = keccak256(kemPk)` of the assembled key), with the call's key and
    /// its stored signature bytes (`kemKeyAt`'s `sig`) (spec P2, ruling A6-m m3: the record is copyable from the log);
    /// checked on chain (`CHECKED_CHAIN`) on EVM. The initial record comes in `UARegistered` (a hash-committed one is
    /// filled here, version 0, empty `sig`).
    event UAKemKeySet(bytes32 indexed ua, uint64 indexed version, bytes32 keyHash, KemKey kem, bytes sig);
    /// One part of an ML-DSA id's expanded key stored (P6c), at `ptr` (SSTORE2).
    event UAKeyCached(bytes32 indexed ua, uint16 indexed kind, uint256 part, address ptr);
    /// Slot `index` of the `msig` `ua`, member `member`, accepted by `acceptMembership` (CTR-UA-37), its signature in the `UAMemberSig`
    /// before it. Slots that signed the `pop` are accepted at registration, without this event: their `UAMemberSig` carry them.
    event UAMembershipAccepted(bytes32 indexed ua, uint16 index, bytes32 indexed member);
    /// One member signature of the `msig` `ua` (CTR-UA-33, CTR-UA-37, owner 2026-11-03): slot `index`, member `member`. `purpose`:
    /// `PURPOSE_POP_V2`, a slot of the registration's `pop` (one event per slot, in the `pop`'s order, before `UARegistered`), or
    /// `PURPOSE_MEMBERSHIP`, an acceptance. `sig`: the exact bytes whose `keccak256` `memberSigHashOf(ua, index)` returns, the slot's `sig`
    /// or an `msig` member's `abi.encode(InnerSig[])`. State keeps the hashes only: a copy rebuilds the `pop` from these events.
    event UAMemberSig(bytes32 indexed ua, bytes32 indexed member, uint16 index, bytes32 purpose, bytes sig);
    /// K3-3: scoped PQZ key version `version` of `(ua, scope)` added by `setPqzScopedKey`, with the call's bytes (the record is
    /// copyable from the log: key, opening KEM key or the empty one, `validUntilBlock`, `sig` as `setPqzKey` stores it).
    event UAPqzScopedKeyAdded(
        bytes32 indexed ua,
        address indexed scope,
        uint64 indexed version,
        bytes32 pqzKeyHash,
        bytes32 pqzPopHash,
        bytes pqzKey,
        KemKey openKem,
        uint64 validUntilBlock,
        bytes sig
    );
    /// K3-3: the `R_REG` proof of scoped version `version` stored (`storePqzScopedPop`), `checkedPqzPop` as `UAPqzPopStored`'s.
    event UAPqzScopedPopStored(
        bytes32 indexed ua, address indexed scope, uint64 indexed version, uint8 checkedPqzPop, bytes pqzPop
    );
    /// K3-3: version `version` became the current scoped key of `(ua, scope)` (CTR-UA-42's eligibility, per scope).
    event UAPqzScopedKeyCurrent(bytes32 indexed ua, address indexed scope, uint64 indexed version);

    /// CTR-UA-44: the `msig` `ua`'s structure on this registry is now version `version` (`count` slots, `enabled` the bitmap).
    /// Convenience only: state is complete without it (`msigOf`, `msigStateOf`).
    event UAMsigUpdated(bytes32 indexed ua, uint64 indexed version, uint16 threshold, uint16 count, uint256 enabled);

    error UAKindDisabled(uint16 kind); // not enabled in this generation (incl. kinds a predecessor offers)
    error UAKeyData(uint16 kind); // non-canonical, curve, subgroup, identity, ordering, threshold, cap bound
    error UAIdInNativeSpace(bytes32 ua);
    error UAAlreadyRegistered(bytes32 ua);
    error UAKeyInUse(bytes32 keyHash, bytes32 owner); // layer 2
    error UAMemberUnknown(bytes32 member); // structure member not native/registered, or kind ∉ MEMBER
    error UAPqzHolder(bytes32 ua); // UA-6 U3: this UA's kind / structure may not hold a PQZ key
    error UAPoP();
    error UAUnauthorized(bytes32 ua); // also: ua is unregistered
    error UAKeyCache(uint16 kind); // not ML-DSA, disabled, part past the last (`PqUA.mldsaParts`), or the verifier uses a precompile
    // ML-DSA without a precompile, a check (the registration's PoP, `requireAuthorized`) before every part of the id's cache is
    // stored: `cacheExpandedKey` each part first (CTR-UA-23, owner 2026-11-15)
    error UAKeyNotCached(bytes32 ua);
    error UAIndex(uint16 kind, uint256 i); // uaAt past the kind's count
    error UANotIndexed(bytes32 ua); // uaIndex of an unregistered id
    error UAKemHolder(bytes32 ua); // kind / structure may not hold a KEM key (UA8-D12)
    /// setKemKey: a version already stored (every version write-once, owner 2026-10-31), or version 0 not committed by
    /// hash at `register`
    error UAKemVersion(bytes32 ua, uint64 version);
    error UAKemKeyHash(bytes32 ua); // setKemKey version 0: the key does not hash to the `kemPkHash` committed at register
    error UAKemKeyLength(uint256 length); // empty, or ≠ 1,601 for scheme 1
    error UAKemScheme(uint8 scheme); // first byte of kemPk: not an enabled KEM scheme (1 only; 2 reserved)
    /// A PQZ key without its proof hash or a proof hash without a key (`register`; a zero hash in `setPqzKey`), a proof
    /// hash of `keccak256("")` or empty proof bytes in `storePqzPop` (ruling A6-m), or proof bytes that do not hash to the
    /// (stored) `pqzPopHash`.
    error UAPqzPopHash(bytes32 ua);
    /// `setPqzKey` of version 0 on a record that has a version 0 (here, or in gen 1 on a gen-2 host): every PQZ key record
    /// is write-once (group 3g, R2 retires ruling R-cross-set's replacement); another set's key gets a new version.
    error UAPqzKeySet(bytes32 ua);
    /// Group 3g (KV-1): `setPqzKey` of a version v ≥ 1 without version 0, or other than `latest + 1` (a gap, a stored
    /// version); on a gen-2 host `latest` is the larger of both generations'.
    error UAPqzKeyVersion(bytes32 ua, uint64 version);
    /// K3-3: a scoped record's opening KEM key against its scope: absent on a class-2 record (scope 0), present for a
    /// class-3 token whose `pqzOpening` is off or absent for one whose `pqzOpening` is on, or a scope that does not answer
    /// `pqzVerifyConfig()`.
    error UAPqzOpenKem(address scope);
    /// K3-3: `setPqzScopedKey` after the record's `validUntilBlock`.
    error UAPqzRecordExpired(bytes32 ua);
    /// CTR-GOV-28: a call's `chainUid_` is not this registry's chain word (`updateMsig`).
    error ChainUidMismatch(bytes32 expected, bytes32 got);
    /// CTR-UA-44: `updateMsig` after its `validUntilBlock`.
    error UAMsigExpired(bytes32 ua);
    /// CTR-UA-44: `updateMsig` of a version other than the stored one + 1 (`stored`: the stored version, 0 never updated).
    error UAMsigVersion(bytes32 ua, uint64 stored);
    /// CTR-UA-44: a target with fewer slots than stored, more than 256, an enabled bit past its slots, more than 16 enabled
    /// slots, or whose next update would not fit one transaction.
    error UAMsigSlots(uint256 count);
    /// CTR-UA-44: a stored slot's `kind` or `id` changed in the target.
    error UAMsigSlotChanged(uint16 index);
    /// CTR-UA-44: a target threshold of 0, or above the weight of its enabled and accepted slots.
    error UAMsigThreshold(bytes32 ua);

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
    /// typed-signing TS-D5 (owner 2026-10-31): the name of a kind id of the table (`UAKinds.name`; enabled or not, a name
    /// table, not an enablement view); an unknown id reverts `UAKindUnknown(kind)` (an app reads a revert as "unknown").
    function kindName(uint16 kind) external pure returns (string memory);
    /// The portable records as typed EIP-712 structs (typed-signing TS-D1 … TS-D3, TS-D6; `UAKinds`) under the domain
    /// `EIP712Domain(string name,string version)` = ("SCaaS UA Portable", "1"): `pqzKeyHash = keyHashOf(0x0142,
    /// pqzKey)`, `pqzPopHash = keccak256(pqzPop)`, each 0 when absent; `kemRecordHash = hashStruct(UAKemRecord{ua,
    /// version, scheme, keccak256(kemPk)})` of the assembled `kemPk = scheme ‖ mlkemEk ‖ x25519`, the zero record
    /// `UAKemRecord{ua, 0, 0, 0}` for an empty `KemKey` (no key).
    function portableDomainSeparator() external pure returns (bytes32);
    /// typed(`UAPortableRecord{ua, kind, pqzKeyHash, kem}`), `kind` the registering kind: what R_REG proves over.
    function portableRecordDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash)
        external
        pure
        returns (bytes32);
    function kemRecordHash(bytes32 ua, uint64 version, KemKey calldata kem) external pure returns (bytes32);
    /// typed(`UARegistration{record, pqzPopHash}`): what `register`'s `pop` signs.
    function registrationDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32);
    /// typed(`UAKemRecord`): what `setKemKey`'s `sig` signs.
    function kemRecordDigest(bytes32 ua, uint64 version, KemKey calldata kem) external pure returns (bytes32);
    /// typed(`UAPqzKey{ua, pqzKeyHash}`): what a later PQZ key's R_REG proves over.
    function pqzKeyDigest(bytes32 ua, bytes32 pqzKeyHash) external pure returns (bytes32);
    /// typed(`UAPqzKeyRecord{UAPqzKey{ua, pqzKeyHash}, pqzPopHash}`): what `setPqzKey`'s `sig` signs (version 0).
    function pqzKeyRecordDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 pqzPopHash) external pure returns (bytes32);
    /// Group 3g: typed(`UAPqzKeyVersion{ua, version, pqzKeyHash}`): what version v ≥ 1's R_REG proves over.
    function pqzKeyVersionDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash) external pure returns (bytes32);
    /// Group 3g: typed(`UAPqzKeyVersionRecord{UAPqzKeyVersion{ua, version, pqzKeyHash}, pqzPopHash}`): what `setPqzKey`'s
    /// `sig` signs for version v ≥ 1.
    function pqzKeyVersionRecordDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32);
    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32);
    /// EIP-712 digest of UAAuth(ua, purposeTag, digest) under this registry's domain: what native signers sign.
    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) external view returns (bytes32);

    /// A derived kind by its key data (every derived kind but `msig`, `registerMsig` only, `UAKeyData(kind)` here;
    /// `webauthn-p256`, MuSig2 and FROST also through `registerWebAuthn` / `registerMuSig2` / `registerFrost`). `pop`: the
    /// kind's signature over `uaMessage(kind, PURPOSE_POP_V2, registrationDigest(ua, kind, pqzKeyHash, kemRecordHash,
    /// attrs.pqzPopHash))`. `attrs`: only a holder carries a PQZ key (`mldsa44`, `mldsa65`, `fndsa512`, `mldsa87`, `fndsa1024`, a
    /// PQ-eligible `msig`; UA-6 U3, UA8-D12) or a KEM record (the same single kinds, never an `msig`: CTR-UA-32, plan T66a).
    /// `pqzPop`: the `R_REG` proof over `uaMessage(0x0142, PURPOSE_POP_V2, portableRecordDigest(...))`, optional (empty: the
    /// key is stored unproven, `storePqzPop` later; also unproven where the `0x0142` slot is empty, UA8-D8). The attribute
    /// checks (holder, proof hash, PQZ key length, KEM key length) come before the PoP (portable.json `negatives`). Anyone
    /// may submit; the same arguments register on every registry, and so does the hash-commit form of the same `pop`
    /// (PRV M1, owner 2026-11-01): a front-run yields the same record, its hash-commit form or a revert; after `register`
    /// or `UAAlreadyRegistered` a client reads `registrationOf`, and when `attrs.kemPkHash != 0` and `kemKeyAt(ua, 0)` is
    /// empty sends `setKemKey(ua, 0, key, UASig())`.
    function register(
        uint16 kind,
        bytes calldata keyData,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua);
    /// `register` for the structure `msig` (typed-signing TS-D10): the key data is assembled from `s` (CTR-UA-09), so the
    /// id and every digest are the packed form's (from `structure`). `pop`: empty unless the structure is PQ-eligible, then m-of-n member
    /// signatures over the registration (derived members sign `memberDigest` under `member`; a native member signs the
    /// typed `registrationDigest` itself (TS-D4, `eth_signTypedData_v4`): an EOA — code-less or an EIP-7702 designator —
    /// by ECDSA with its own key only, never ERC-1271 through the delegate; a contract by ERC-1271 over it). Owner 2026-11-03:
    /// stored as `keccak256(abi.encode(pop))` (`popOf`, `registrationOf`; "" for none) and each slot's hash (`memberSigHashOf`), each
    /// slot's bytes in its `UAMemberSig`.
    function registerMsig(
        MsigStructure calldata structure,
        UAAttrs calldata attrs,
        MemberSig[] calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua);
    /// `register` for `webauthn-p256` from its typed key (typed-signing TS-D13; `register(0x0100, …)` takes the packed
    /// form too, same id). The registry assembles `x ‖ y ‖ rpIdHash`; `pop` as `register`'s (one WebAuthn assertion).
    function registerWebAuthn(
        WebAuthnKey calldata key,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua);
    /// `register` for `kind` `musig2-secp256k1` (0x0110) or `musig2-bn254` (0x0112) from its typed key (TS-D13; another
    /// kind, or a point of the wrong length, `UAKeyData(kind)`; `register` takes the packed form too, same id).
    function registerMuSig2(
        uint16 kind,
        MuSig2Key calldata key,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua);
    /// `register` for `bls12381-multi` (0x0121) from its typed key (spec 2026-11-19-bls12381-multi §2; a point of the wrong length
    /// `UAKeyData(0x0121)`; `register` takes the packed form too, same id). `pop`: the members' aggregate proof of possession (§4).
    function registerBlsMulti(
        BlsMultiKey calldata key,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua);
    /// `register` for `kind` `frost-secp256k1` (0x0111) or `frost-bn254` (0x0113) from its typed key (TS-D13; another
    /// kind, a point of the wrong length or a member without `threshold` commitments, `UAKeyData(kind)`; `register` takes
    /// the packed form too, same id).
    function registerFrost(
        uint16 kind,
        FrostKey calldata key,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua);

    /// Anyone (UA8-D8, P8): the `R_REG` proof of the UA's PQZ key version `version`, given later (or again) —
    /// `UAPqzPopHash` unless `keccak256(pqzPop)` is that version's stored `pqzPopHash` (so also for a version not stored); a
    /// no-op (no event) once its proof bytes are stored. Else the bytes are stored and, where slot `0x0142` has a verifier,
    /// checked over the version's `R_REG` message — version 0: `uaMessage(0x0142, PURPOSE_POP_V2, portableRecordDigest(ua,
    /// kindOf(ua), ...))` for a key from `register`, `uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest(ua, pqzKeyHash))` for
    /// one from `setPqzKey`; v ≥ 1: `uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyVersionDigest(ua, version, pqzKeyHash))` —
    /// (`UAPoP` on failure), then the key's owner (`UAKeyInUse`: any UA, this one included), `keyOwner`, the `0x0142` list
    /// (once per UA), `proven`; `UAPqzPopStored` with the bytes; `UAPqzKeyCurrent` when the version becomes current (the
    /// highest eligible version: proven, or without the verifier this build's set length with its bytes stored).
    /// Empty `pqzPop`: `UAPqzPopHash` (ruling A6-m). `UAUnauthorized` for an id this registry does not hold (gen 2: a
    /// gen-1 record goes to gen 1, UA8-D11), except (ruling A6-I1) on a gen 2 that enables 0x0142 in front of a gen 1
    /// that does not: the PQZ attachment lives in the oldest generation with the verifier, so this gen 2 proves gen 1's
    /// version (pointer and hash read from gen 1; the bytes checked here, gen 1's stored bytes never taken as proven) and
    /// keeps the record, the proof, `proven`, owner and list entry itself; `current` is this generation's.
    function storePqzPop(bytes32 ua, uint64 version, bytes calldata pqzPop) external;
    /// Anyone (group 3g, CTR-UA-41 draft): PQZ key version `version` of the UA, each written once. Version 0 to a record
    /// registered without one (ruling A1-I1, portable); a second version 0 is `UAPqzKeySet` whatever its set (R2 retires
    /// ruling R-cross-set's replacement). A version v ≥ 1 only when version 0 is stored and `v == latest + 1`, else
    /// `UAPqzKeyVersion`; its key bytes differ from every stored version of the UA (`pqzKeyUsed`, else `UAKeyInUse(pqzKeyHash,
    /// ua)`, in every registry kind). `sig` in the `pop` format over `uaMessage(kind, PURPOSE_PQZ_KEY, rd)`, `rd` =
    /// `pqzKeyRecordDigest(ua, pqzKeyHash, pqzPopHash)` for version 0, `pqzKeyVersionRecordDigest(ua, version, pqzKeyHash,
    /// pqzPopHash)` for v ≥ 1; the key is stored unproven, never current here, and its `R_REG` comes by `storePqzPop`. The
    /// key's bytes are stored once, at the SSTORE2 pointer `pqzKeyAt(ua, version).ptr` (`eth_getCode(ptr)` without its
    /// leading STOP byte), and carried by `UAPqzKeyAdded`. On a gen 2 that enables 0x0142 in front of a gen 1 that does not,
    /// it takes gen-1 records too (ruling A6-I1, as `storePqzPop`): the sequence reads both generations' `latest`, a version
    /// stored in either is refused, and the key marker is read in both (host rule 1). `sig`: `signature` (single keys) or
    /// `members` (an msig), never `keyData`; stored (`pqzKeySigOf`) as `signature`, or `abi.encode(members)` for an msig.
    /// Check order: an id this registry does not hold (`UAUnauthorized`, as `storePqzPop`), a gen 2 whose gen 1 enables
    /// 0x0142 (`UAKindDisabled(0x0142)`, as `register`) → holder (`UAPqzHolder`, with the `msig` debit bound) → the version
    /// (`UAPqzKeySet` / `UAPqzKeyVersion`) → the key's length (`UAKeyData(0x0142)`) → the key repeated (`UAKeyInUse`) → a zero
    /// or `keccak256("")` `pqzPopHash` (`UAPqzPopHash`) → signature (`UAUnauthorized`). `UAPoP` (`R_REG`) and `UAKeyInUse`
    /// across UAs (one UA per proven key) fire only where a proof is checked: `storePqzPop`, and `register` with a `pqzPop`.
    function setPqzKey(bytes32 ua, uint64 version, bytes calldata pqzKey, bytes32 pqzPopHash, UASig calldata sig)
        external;
    /// Anyone (P4, UA8-D5): the UA's KEM record `(version, kem)`. Versions ≥ 1: `sig` (`signature`, or `members` for an
    /// msig, native members as in `registerMsig`'s `pop`; never `keyData`) over `uaMessage(kind, PURPOSE_KEM,
    /// kemRecordDigest(ua, version, kem))`. Version 0 (owner 2026-10-31): only the key `register` committed by hash
    /// (`attrs.kemPkHash`), with an empty `sig` (the PoP signed it), after `keccak256(kemPk) == kemPkHash`
    /// (`UAKemKeyHash`); open to anyone, as `storePqzPop`. Every version is write-once — a stored key is never
    /// overwritten, a new key goes to a new version (owner 2026-10-31) — in any order; no owner check (two UAs may list
    /// one key) and no revocation (P7). Stored `kemPk ‖ sig` (SSTORE2 chunks; `sig` = `signature`, or `abi.encode(members)`),
    /// `kemKeyOf` follows the highest version, `UAKemKeySet`. Check order: an id this registry does not hold
    /// (`UAUnauthorized`: an unregistered id, and on gen 2 a gen-1 record, which goes to gen 1, UA8-D11) → holder
    /// (`UAKemHolder`: `mldsa44`, `mldsa65`, `fndsa512`, `mldsa87`, `fndsa1024`; never an `msig`, CTR-UA-32) → a stored version, or version 0
    /// not committed (`UAKemVersion`) → the key: scheme 1 (`UAKemScheme`), 1,601 B assembled (`UAKemKeyLength`) →
    /// signature (`UAUnauthorized`; version 0: a non-empty `sig`) / version 0 the committed hash (`UAKemKeyHash`).
    function setKemKey(bytes32 ua, uint64 version, KemKey calldata kem, UASig calldata sig) external;
    /// Anyone, no fee (the PQZ three-key model, K3-3): scoped PQZ key version `version` of `(ua, scope)`, written once; `scope`
    /// 0 is class `offchain-shared` (one key per holder per chain), a token address class `offchain-token` (one key per holder
    /// and token). `sig` (`signature`, or `members` for an `msig`; never `keyData`) over `uaMessage(kind, PURPOSE_PQZ_SCOPED_KEY,
    /// pqzScopedKeyRecordDigest(ua, keyClass, chainUid(), scope, version, pqzKeyHash, pqzPopHash, openKemHash,
    /// validUntilBlock))`, `keyClass` 2 for scope 0 else 3, `openKemHash = keccak256(kemPk)` of `openKem` or 0 without one.
    /// The record space is apart from `setPqzKey`'s; the per-UA marker `pqzKeyUsed` and `keyOwner` span both. Check order:
    /// past `validUntilBlock` (`UAPqzRecordExpired`) → an id this registry does not hold (`UAUnauthorized`, as `setPqzKey`) →
    /// holder (`UAKindDisabled(0x0142)`, `UAPqzHolder` with the `msig` debit bound; an `msig` on scope 0: `UAPqzHolder`) →
    /// `version == pqzScopedKeyLatest(ua, scope) + 1`, the first 0 (`UAPqzKeyVersion`) → the key's length, a set's, and every
    /// version of a scope version 0's (`UAKeyData(0x0142)`) → the key repeated in any record space of the UA (`UAKeyInUse(h,
    /// ua)`) → a zero or `keccak256("")` `pqzPopHash` (`UAPqzPopHash`) → `openKem` present iff the scope's tokens have the
    /// opening on (scope 0 always; a token by one static call of its `pqzVerifyConfig()`, its `pqzOpening`) (`UAPqzOpenKem`),
    /// then scheme 1 and 1,601 B (`UAKemScheme`, `UAKemKeyLength`) → signature (`UAUnauthorized`; another chain's record
    /// fails here). The key is stored unproven; its `R_REG` comes by `storePqzScopedPop`. `UAPqzScopedKeyAdded`.
    function setPqzScopedKey(
        bytes32 ua,
        address scope,
        uint64 version,
        bytes calldata pqzKey,
        bytes32 pqzPopHash,
        KemKey calldata openKem,
        uint64 validUntilBlock,
        UASig calldata sig
    ) external;
    /// Anyone (K3-3, as `storePqzPop`): the `R_REG` proof of scoped version `version`; `UAPqzPopHash` for empty bytes or bytes
    /// that do not hash to the record's `pqzPopHash` (also no record); a no-op once stored. The bytes are stored (CTR-PQZ-30)
    /// and, where slot 0x0142 has a verifier, checked over `uaMessage(0x0142, PURPOSE_PQZ_SCOPED_KEY, pqzScopedKeyDigest(ua,
    /// keyClass, chainUid(), scope, version, pqzKeyHash))` (`UAPoP`), then one owner per proven key across every record space
    /// (`UAKeyInUse`), `keyOwner`, `proven`. Eligible as CTR-UA-42 (proven, or without the verifier this build's set length):
    /// the version becomes current when it is at or above `current` (`UAPqzScopedKeyCurrent`), and the UA joins the scope's
    /// holder list at its first eligible version. `UAPqzScopedPopStored`.
    function storePqzScopedPop(bytes32 ua, address scope, uint64 version, bytes calldata pqzPop) external;
    /// K3-3: the current scoped version of `(ua, scope)` (0 when none is eligible), its key pointer, proof hash and `proven`;
    /// what a class-2 (scope 0) or class-3 (scope = the token) PQZ token reads instead of `pqzKeyOf`. Gen 2 forwards a gen-1
    /// record unless it is the PQZ host (as `pqzKeyOf`).
    function pqzScopedKeyOf(bytes32 ua, address scope)
        external
        view
        returns (uint64 version, address ptr, bytes32 pqzPopHash, bool proven);
    /// Any stored scoped version (zero for none); `pqzKeyAt`'s shape.
    function pqzScopedKeyAt(bytes32 ua, address scope, uint64 version)
        external
        view
        returns (address ptr, bytes32 pqzPopHash, bool proven);
    /// The highest stored scoped version (clients sign `latest + 1`; 0 also when none: `pqzScopedKeyAt(ua, scope, 0)` tells).
    function pqzScopedKeyLatest(bytes32 ua, address scope) external view returns (uint64);
    /// Scoped version `version`'s stored `R_REG` proof bytes ("" none).
    function pqzScopedPopOf(bytes32 ua, address scope, uint64 version) external view returns (bytes memory);
    /// The opening KEM key of scoped version `version` (K3-3, K3-6b): the empty `KemKey` when the record has none.
    function pqzOpenKemAt(bytes32 ua, address scope, uint64 version) external view returns (KemKey memory);
    /// The per-scope holder list (as CTR-UA-29): the number of UAs with an eligible scoped key of `scope` in this
    /// generation, and the `i`-th (`UAIndex(0x0142, i)` past the end).
    function pqzScopedCount(address scope) external view returns (uint256);
    function pqzScopedAt(address scope, uint256 i) external view returns (bytes32);
    /// typed(`UAPqzScopedKey`): what a scoped key's `R_REG` proves over (K3-3).
    function pqzScopedKeyDigest(
        bytes32 ua,
        uint8 keyClass,
        bytes32 chainUid,
        address token,
        uint64 version,
        bytes32 pqzKeyHash
    ) external pure returns (bytes32);
    /// typed(`UAPqzScopedKeyRecord`): what `setPqzScopedKey`'s `sig` signs (K3-3).
    function pqzScopedKeyRecordDigest(
        bytes32 ua,
        uint8 keyClass,
        bytes32 chainUid,
        address token,
        uint64 version,
        bytes32 pqzKeyHash,
        bytes32 pqzPopHash,
        bytes32 openKemHash,
        uint64 validUntilBlock
    ) external pure returns (bytes32);
    /// CTR-UA-37. Anyone submits, the member signs: slot `memberSig.index` of the `msig` `ua` accepts its place. A native member
    /// signs the typed `UAMembership{ua, member}` itself (`eth_signTypedData_v4`) or answers ERC-1271 over it; a derived member signs
    /// `memberDigest(ua, uaMessage(MSIG, PURPOSE_MEMBERSHIP, typed))` under `member`; an `msig` member by a threshold of its own
    /// accepted slots, `memberSig.members`, each one level down, `sig` empty. Portable: no chain, no registry, so the same signature
    /// accepts on every registry (no nonce needed): its bytes are in `UAMemberSig` and its hash is kept (`memberSigHashOf`), so a copy
    /// replays it with no new signature (owner 2026-11-03). A slot already accepted is a no-op, no second event. `UAUnauthorized` for an id that is no `msig` on this
    /// registry (gen 2: a gen-1 record goes to gen 1, UA8-D11, as `setKemKey`), an index past the members or a bad signature. No
    /// revoke: an acceptance cannot be withdrawn.
    function acceptMembership(bytes32 ua, MemberSig calldata memberSig) external;

    /// `pqzKey`: the SSTORE2 pointer of the UA's current PQZ key version, proven or not (UA8-D9: a directory), 0 = none
    /// (gen 2 forwards gen-1 records; a gen-2 host answers its own current).
    function recordOf(bytes32 ua) external view returns (Record memory r, address pqzKey);
    /// Exactly the `register` arguments: a PQZ key added later by `setPqzKey` is not in `attrs` (read it, its proof and
    /// its signature with `pqzKeyAt`, `pqzPopOf`, `pqzKeySigOf`; ruling A4-c3). For a key from `register` (version 0), `pqzPop` is the
    /// stored proof (given in `register` or by `storePqzPop`; it hashes to `attrs.pqzPopHash`; ruling A5-c2). An `msig`:
    /// `keyData` the assembled CTR-UA-09 bytes, `pop` = the 32 bytes of `keccak256(abi.encode(MemberSig[]))` ("" for none; owner
    /// 2026-11-03: the slots are in `UAMemberSig`; `msigOf` for the typed structure). A hash-committed KEM key stays in its committed form (`kem` = scheme only, `kemPkHash`), filled or not.
    function registrationOf(bytes32 ua)
        external
        view
        returns (uint16 kind, bytes memory keyData, UAAttrs memory attrs, bytes memory pop, bytes memory pqzPop);
    /// The typed **current** structure of an `msig` (TS-D10; CTR-UA-44: every slot, disabled ones included, `msigStateOf` says
    /// which are enabled); empty (threshold 0, no members) for any other id. The id is the first structure's (`registrationOf`),
    /// never this one's after an update. Gen 2 forwards gen-1 records.
    function msigOf(bytes32 ua) external view returns (MsigStructure memory);
    /// Does member slot `index` of `ua` count at verify: **enabled and accepted** (CTR-UA-37: it signed the `pop` here, or
    /// `acceptMembership`; CTR-UA-44: and the slot is enabled)? Changed meaning (CTR-UA-44, was: accepted): a tool that copies
    /// acceptances to another registry reads `msigStateOf(ua).accepted` and `memberSigHashOf`, never this view. False for a
    /// slot only listed in `msigOf`, a disabled slot, any other id and past the members. Gen 2 forwards gen-1 records.
    function memberAccepted(bytes32 ua, uint256 index) external view returns (bool);
    /// CTR-UA-44: the raw words of the `msig` `ua` here: `version` (0 never updated), `enabled` (bit i = slot i), `accepted`
    /// (CTR-UA-37's bits, never cleared). Zeroes for any other id. Gen 2 forwards gen-1 records.
    function msigStateOf(bytes32 ua) external view returns (uint64 version, uint256 enabled, uint256 accepted);
    /// CTR-UA-44 (TODO 3ze, owner 2026-11-14): the `msig` `ua` on this registry becomes `structure` (every slot, disabled ones
    /// included: stored slots keep `kind` and `id`, new members are appended slots), `enabled` its bitmap, `version` the stored
    /// one + 1. Anyone submits (fee 0, a `call` job); `sigs` is a threshold of the **stored** structure's enabled and accepted
    /// slots, minimal, over typed(`UAMsigUpdate{ua, chainUid, registry = this, version, threshold, members, enabled,
    /// validUntilBlock}`) as `requirePortable`'s `msig` arm signs (native members the typed digest, derived members
    /// `memberDigest` under `member`, purpose `PURPOSE_MSIG_UPDATE`). The id never changes (the first structure's). Check
    /// order: `chainUid_` (`ChainUidMismatch`) → `validUntilBlock` (`UAMsigExpired`) → an `msig` held here (`UAUnauthorized`) →
    /// `version == stored + 1` (`UAMsigVersion`) → slot count, enabled bits, ≤ 16 enabled (`UAMsigSlots`) → stored slots
    /// unchanged (`UAMsigSlotChanged`) → weights, appended members, one slot per id, no self-slot (`UAKeyData(0x0120)`) →
    /// threshold ≤ enabled ∧ accepted weight (`UAMsigThreshold`) → signatures (`UAUnauthorized`) → appended or re-enabled
    /// members registered, an `msig` member flat (`UAMemberUnknown`) → the registration bound (`UAKeyData(0x0120)`) → the PQZ
    /// holder rule (`UAPqzHolder`) → the next update fits (`UAMsigSlots`). `UAMsigUpdated`.
    function updateMsig(
        bytes32 ua,
        uint64 version,
        MsigStructure calldata structure,
        uint256 enabled,
        uint64 validUntilBlock,
        MemberSig[] calldata sigs,
        bytes32 chainUid_
    ) external;
    /// `keccak256` of the signature object of the `msig` `ua`'s slot `index` (CTR-UA-33, CTR-UA-37, owner 2026-11-03): of `sig`, or of an
    /// `msig` member's `abi.encode(InnerSig[])`, the slot's kind says which (`msigOf`): a slot of the `pop` from registration, a slot that
    /// accepted later from `acceptMembership`. The bytes are in that slot's `UAMemberSig`; a copy checks them against this hash. Zero for a slot
    /// not accepted and any other id. Gen 2 forwards gen-1 records.
    function memberSigHashOf(bytes32 ua, uint256 index) external view returns (bytes32);
    /// CTR-UA-33 Change 2026-11-08 (owner; plan T66a): the slots that signed the `msig` `ua`'s `pop`, in index order, each with its
    /// `memberSigHashOf` hash: one word per `msig` written at registration, never by `acceptMembership`, so state alone tells which slots
    /// signed the `pop` and which accepted later (`memberAccepted`); a copy (CTR-UA-31) rebuilds the `pop` from these slots' `UAMemberSig`
    /// bytes (or the node keeper, NODE-IDX-08). `popOf` stays `keccak256(pop)`. Empty for an empty `pop` and any other id. Gen 2 forwards
    /// gen-1 records.
    function popSlotsOf(bytes32 ua) external view returns (uint16[] memory index, bytes32[] memory hash);
    /// The EIP-1167 codehash of this registry's `SmartKeyAccount` clones, 0 for none: gen 2 gives a clone the 400 k cap in a gen-1 structure by it.
    function smartKeyCloneHash() external view returns (bytes32);
    /// The typed key of a `webauthn-p256` / MuSig2 / FROST UA (TS-D13); empty for any other id (gen 2 forwards gen-1
    /// records).
    function webAuthnKeyOf(bytes32 ua) external view returns (WebAuthnKey memory);
    function muSig2KeyOf(bytes32 ua) external view returns (MuSig2Key memory);
    function frostKeyOf(bytes32 ua) external view returns (FrostKey memory);
    /// The typed key of a `bls12381-multi` UA (its key data `d`, from the stored form); empty for any other id (gen 2 forwards
    /// gen-1 records).
    function blsMultiKeyOf(bytes32 ua) external view returns (BlsMultiKey memory);
    /// The stored `pop` (CTR-UA-33): the `pop` bytes of a single key; of an `msig`, the 32 bytes of `keccak256(abi.encode(MemberSig[]))`
    /// (owner 2026-11-03; its slots are in `UAMemberSig`), "" for an empty `pop`. A reader tells which by the record's kind. "" for an id not
    /// registered (gen 2 forwards gen-1 records).
    function popOf(bytes32 ua) external view returns (bytes memory);
    /// Version `version`'s stored proof bytes ("" none). Gen 2 forwards a version it does not hold of a gen-1 record.
    function pqzPopOf(bytes32 ua, uint64 version) external view returns (bytes memory);
    /// `setPqzKey`'s signature of version `version`; empty when the key came with `register` (its consent is the `pop`) or
    /// there is none.
    function pqzKeySigOf(bytes32 ua, uint64 version) external view returns (bytes memory);
    /// Group 3g (KV-3, C3): the current version (the highest eligible one; 0 when none is, then version 0 as stored, its
    /// `proven` false), its key pointer (SSTORE2: the key is `eth_getCode(ptr)` without its leading STOP byte), its proof
    /// hash and whether the slot-0x0142 verifier checked its proof (UA8-D9). One current per UA and registry generation: a
    /// gen-2 host answers its own (its records first, gen 1's for a version it does not hold); any other gen 2 forwards a
    /// gen-1 record.
    function pqzKeyOf(bytes32 ua) external view returns (uint64 version, address ptr, bytes32 pqzPopHash, bool proven);
    /// Any stored version's key pointer, proof hash and `proven` (zero for none). Gen 2 (host rule 2): its own record of
    /// the version when it holds one, else gen 1's.
    function pqzKeyAt(bytes32 ua, uint64 version) external view returns (address ptr, bytes32 pqzPopHash, bool proven);
    /// The highest stored version (clients sign `latest + 1`; 0 also when none is stored: `pqzKeyAt(ua, 0)` tells). Gen 2:
    /// the larger of both generations'.
    function pqzKeyLatest(bytes32 ua) external view returns (uint64);
    /// Some version of `ua` stores this key, proven or not (KV-1's marker). Gen 2: in either generation.
    function pqzKeyUsed(bytes32 ua, bytes32 pqzKeyHash) external view returns (bool);
    /// The three parts (P11.3, ruling C8), `UAKinds.CHECKED_*`: `pop` = CHAIN; `pqzPop` = CHAIN iff the current PQZ key
    /// version is proven, else NONE (no key, or not yet proven); `kem` = CHAIN once a KEM record is stored, else NONE; all NONE for an unregistered id.
    function checkedOf(bytes32 ua) external view returns (uint8 pop, uint8 pqzPop, uint8 kem);
    /// The highest stored version: (0, none, "") without one — also a hash-committed `register` key not filled yet —,
    /// (0, kem, "") for the `register` key alone (version 0, empty `sig`: its consent is the pop, UA8-D4).
    function kemKeyOf(bytes32 ua) external view returns (uint64 version, KemKey memory kem, bytes memory sig);
    /// (none, "") for a version not stored.
    function kemKeyAt(bytes32 ua, uint64 version) external view returns (KemKey memory kem, bytes memory sig);
    function kindOf(bytes32 ua) external view returns (uint16); // 0 = not registered (native ids too)
    function isRegistered(bytes32 ua) external view returns (bool);
    function keyOwner(bytes32 keyHash) external view returns (bytes32);
    /// The stored key of a stored kind (MuSig2 `Q`, FROST `Y`, Zether `Y`: zether.md CTR-ZTH-50; PQ `pk`; `bls12381-multi`: its
    /// aggregate key `apk`, 256 B EIP-2537, never the stored `ua ‖ s`), empty otherwise.
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

    /// ML-DSA without a precompile (P6c): stores part `part` (ML-DSA-44: 0; ML-DSA-65: 0, 1; ML-DSA-87: 0, 1, 2; one
    /// transaction each) of the EIP-8051 expanded key the registry derives from `pk` under `uaOf(kind, pk)`; PoP and verify use it once
    /// every part is stored, and `register` needs it complete (`UAKeyNotCached`, CTR-UA-23, owner 2026-11-15). Anyone may
    /// call it; a stored part is never rewritten.
    function cacheExpandedKey(uint16 kind, bytes calldata pk, uint256 part) external returns (bytes32 ua);
    /// The stored part pointers (0 = not yet), this generation only; three since 3zh (ML-DSA-87's third part; the selector is
    /// the same, the return 96 bytes instead of 64: a caller decoding two words never sees part 2).
    function expandedKeyOf(bytes32 ua) external view returns (address[3] memory);

    /// UA-7 O1 (owner 2026-11-04; plan T66a): the portable check, chain-free. Reverts `UAUnauthorized(ua)` unless `auth` is the UA's
    /// portable signature over `uaMessage(kind, purposeTag, typedDigest)`, `typedDigest` a portable record's typed digest: a single key
    /// `signature` only, by the kind's verifier as `setKemKey` checks it; an `msig` `members` only, over two levels, minimal
    /// (T - min(weight) < N at each level), accepted slots only (CTR-UA-37), derived members over `memberDigest` under `member`,
    /// native members over `typedDigest` itself (TS-D4: an EOA by ECDSA with its own key, a contract by ERC-1271), never `UAAuth`.
    /// `purposeTag`: a portable purpose (`PURPOSE_KEM`, `PURPOSE_PQZ_KEY`, `PURPOSE_PQCHAT`); `PURPOSE_POP_V2` (the registration's own
    /// check) and every chain-bound purpose are `UAUnauthorized`, so are a native id (it signs chain-bound only) and an unregistered
    /// one. Gen 2 forwards a gen-1 record (UA8-D11). `UAVerifyGas` when too little gas is left for a verifier's cap.
    function requirePortable(bytes32 ua, bytes32 purposeTag, bytes32 typedDigest, UASig calldata auth) external view;

    /// CTR-UA-45 / CTR-UA-46 (owner 2026-11-17, N1): the open portable app namespace. `requirePortable`'s checks under
    /// `purpose = UAKinds.appPurpose(appId) = keccak256(abi.encode(keccak256("scaas.ua.purpose.app.v1"), appId))`, computed here, so
    /// an app never names a SCaaS purpose through it and `requirePortable` refuses every app purpose; `appId` 0 is
    /// `UAUnauthorized(ua)`. No write, no event, no new error. Gen 2 forwards a gen-1 record to gen 1's entry plainly (a gen 1
    /// without it reverts: a refusal). Single keys and derived `msig` members sign the purpose, so app X's signature is refused
    /// under app Y; a native `msig` member signs `typedDigest` itself, so its signature holds under every `appId` for the same
    /// digest. Hence three rules for every app contract on this entry: (a) it computes `typedDigest` itself, in its own EIP-712
    /// domain, from the record it checks, never from a caller's bytes; (b) every record names the signing UA in a field; (c) its
    /// portable domain (exactly `name, version, salt`, `salt = appId`) and its chain-bound domain (`requireAuthorized`) have
    /// different field sets. Residual: a dapp can phish a native member's signature over a valid record (one request per member,
    /// the quorum needed).
    function requirePortableApp(bytes32 ua, bytes32 appId, bytes32 typedDigest, UASig calldata auth) external view;

    /// Reverts UAUnauthorized unless `auth` authorizes `digest` for `ua` under `purposeTag` (typed-signing TS-D12).
    /// Native ids (ua >> 160 == 0): `auth.signature` only, ECDSA low-s (EOA) or ERC-1271 (50 k cap; 400 k for
    ///   SmartKeyAccount clones, by the immutable clone codehash) over uaAuthDigest(ua, purposeTag, digest) — never over
    ///   the raw digest. Classified by code at call time (owner ruling D1, 2026-10-30): empty or the 7702 designator (an
    ///   EOA) ⇒ ECDSA by its own key only, never 1271 through the delegate; other ⇒ 1271.
    /// Derived SIGNING: `auth.keyData` (empty for stored kinds: Zether `zether-bls12381` included, UA-6 U8: a Schnorr by
    ///   `x` on `Y`) + `auth.signature`. msig: `auth.members` only (the structure from the record).
    /// Unregistered: UAUnauthorized.
    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, UASig calldata auth) external view;
}
