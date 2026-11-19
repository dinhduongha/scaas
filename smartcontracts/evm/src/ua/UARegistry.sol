// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SaltedEIP712, SaltedEIP712Core} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {RescueLib} from "../governance/RescueLib.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {IUAKindVerifier, IUAVerifyOnlyVerifier} from "./IUAVerifier.sol";
import {UAKinds} from "./UAKinds.sol";
import {UAStore} from "./UAStore.sol";
import {UARegistryCoreLib} from "./UARegistryCoreLib.sol";
import {UARegistryAuxLib} from "./UARegistryAuxLib.sol";
import {UARegistryRegLib} from "./UARegistryRegLib.sol";
import {MldsaVerifier} from "./MlDsa.sol";
import {PqUA} from "./PqUA.sol";
import {BlsMultiKeyData} from "./BlsMultiKeyData.sol";

/// @title UA registry, UA-2a/2c/3, P6c and UA-6 scope (accounts.md §1.8): the single-key kinds 0x0100–0x0108, the
///        group kinds 0x0110–0x0113 (MuSig2/FROST, stored), the structure `msig`, the Zether kind 0x0141
///        (stored), the PQ signing kinds 0x0130–0x0135 (stored), the PQZ key attribute (scheme 0x0142) of PQ signing
///        UAs, native EVM ids, generations.
/// @notice Monotonic and admin-free (CTR-UA-15): no owner, no setter, no `payable`, a record never changes. `register`
///         derives every record field from `keyData` (CTR-UA-07), so anyone may relay it. Every verifier `staticcall` (group PoP: see below) is
///         capped at the kind's `verifyCap` and counts only exactly 32 bytes equal to 1; a caller that leaves too little
///         gas for the cap gets `UAVerifyGas`, never a pass (T-AUTH-4).
///
///         Kind table: one `uint256` immutable per kind this code can verify, `verifier | cap << 160` (0 = disabled):
///         read with no SLOAD and no EXTCODECOPY. Every kind of the table has its slot (P6c: the PQ kinds; slot 18 is
///         the PQZ key verifier 0x0142, `R_REG`, since UA-6); a kind without a verifier on a chain is disabled there.
///
///         Stored kinds (CTR-UA-17; UA-2c: MuSig2/FROST): `register` has the kind's verifier run the whole group check
///         in `verifyPop` (KeyAgg with hints / DKG PoKs, then one group signature; capped at `verifyBudget`, no hold:
///         a starved PoP is `UAPoP`, a revert like every PoP failure), then stores `vk` (`Q` / `Y`: 33 bytes on
///         secp256k1, 64 on bn254) with SSTORE2 as `keyPtr`. `requireAuthorized` takes `UASig{keyData, signature}`
///         (typed-signing TS-D12) with `keyData` empty (non-empty ⇒ `UAUnauthorized`) and verifies `signature` against `vk`
///         read from the record's `keyPtr`; an `msig` member of a stored kind is checked the same way through the member's
///         own record.
///         Every `msig` member signature (purpose `member`; CTR-UA-33, owner 2026-10-30) carries an empty `keyData`: a
///         classical member's key is read from its registration blob (`_reg`), a stored member's from its `keyPtr`.
///
///         Zether kinds (UA-3; CTR-UA-16, UA-6): the Zether key is the UA (no `authRef`); the PoP is a Zether Schnorr
///         by `x` over the portable registration message (UA-8); `Y` is stored with SSTORE2 like a group key, so
///         `keyOf` serves a sender's storage-only recovery (zether.md CTR-ZTH-50). `zether-bls12381` is in SIGNING
///         (UA-6 U8): `requireAuthorized` verifies its Schnorr on `Y` under any purpose (the token's owner ops under
///         `zether-owner`; spends are authorized by the proof alone, U9). `zether-bn254` (0x0140, slot 12) and `requireZetherAuthorized` are in
///         `legacy/ua6/` (U10).
///
///         PQ kinds (P6c; CTR-UA-17, CTR-UA-23): `pk` stored with SSTORE2 like a group key, `auth.keyData` empty. ML-DSA
///         without a precompile verifies on the EIP-8051 expanded key the registry derives itself — never one from a
///         caller — with `cacheExpandedKey(kind, pk, part)`: one part per transaction (ML-DSA-44 one, ML-DSA-65 and
///         ML-DSA-87 two), each `MldsaVerifier.expandedKeyPart(pk, part)` stored once with SSTORE2 under its id
///         (`uaOf(kind, pk)`); once every part is there, PoP and verify go through `verifyCached` with the part pointers,
///         and `register` needs them all first (`UAKeyNotCached`; CTR-UA-23, owner 2026-11-15: two paths only, the
///         precompile or the cache). Refused where the verifier uses a precompile (a cached Solidity path would exceed its cap).
///         KEM key (CTR-UA-32): the single PQ kinds only; an `msig` holds none (plan T66a), `UAKemHolder` at `register` and `setKemKey`.
///         PQZ key (UA-6, CTR-UA-30, CTR-PQZ-12/13): an attribute of a holder — `mldsa44`, `mldsa65`, `fndsa512`, `mldsa87`, `fndsa1024`, or an
///         `msig` whose members of kinds outside 0x0130–0x0135 weigh less than its threshold (PQ-eligible) — given in
///         its `register` (`attrs.pqzKey`, `attrs.pqzPopHash`) with the optional `R_REG` proof over the portable digest
///         (UA-8 P1, P8), checked by `PqzKeyVerifier` in slot 0x0142; stored with SSTORE2 (`recordOf`, `pqzKeyOf`),
///         immutable. Only a proven key (proof checked by that verifier) is one UA per key (`keyOwner(h)`) and appended
///         to the `0x0142` list (UA8-D8); a key without its proof, or where the slot is empty, is stored unproven; anyone
///         may add the proof later (`storePqzPop`), and PQZ tokens take proven keys only (`pqzKeyOf`, UA8-D9). A record
///         registered without a PQZ key may get one later, once, by the UA's signed portable record (`setPqzKey`,
///         ruling A1-I1). Group 3g (CTR-UA-41 draft): PQZ key versions, each written once, strictly sequential, signed
///         by the UA, distinct key bytes per UA, each with its own `R_REG`, `proven` and owner; `current` = the highest
///         eligible version (`pqzKeyOf`), moving only where proof bytes are stored (`UAPqzKeyCurrent`); R2 retires ruling
///         R-cross-set's replacement. A PQ-eligible `msig` always registers with an m-of-n PoP (U5).
///
///         UA-8 (portable registrations, spec 2026-10-25-ua8-portable-registrations): the PoP has no chain context, so
///         anyone may copy a registration to any registry; every `register` field is stored (UA8-D7): `keyData` once
///         (the stored kinds' `keyPtr` prefix, the rest in the registration blob), `pop` in the blob (an `msig`'s: its
///         32-byte `keccak256`, a hash per slot in `memberSigHash`, the bytes in `UAMemberSig`; owner 2026-11-03), `pqzPop` and each KEM
///         record (`pk ‖ sig`) as their own blobs, each in `SSTORE2.writeChunks` pieces. Later KEM records come by the UA's
///         signed portable record (`setKemKey`: once per version, any order, never overwritten).
///
///         typed-signing R1 (owner explicit-parameter rule; TS-D10 … TS-D12): every entry takes named typed parameters —
///         `registerMsig` the `MsigStructure` (the CTR-UA-09 bytes assembled here, ids unchanged) and `MemberSig[]`, the KEM
///         key as `KemKey`, signatures as `UASig`. The `register` KEM key is version 0 (owner 2026-10-31), in full or, only
///         when that does not fit one transaction, committed by hash (`UAAttrs.kemPkHash`) and stored later by
///         `setKemKey(ua, 0, key, UASig())`, open to anyone.
///
///         Gen 2 (`predecessor ≠ 0`) reads gen 1 for `UAAlreadyRegistered` / `UAKeyInUse` / `kindOf` / `keyOwner` /
///         `recordOf` and hands records it does not hold, and members whose kind it does not enable, to gen 1's
///         `requireAuthorized`. Its constructor refuses every single-key kind whose keyHash group gen 1 enables. A gen 2
///         that enables 0x0142 (so gen 1 does not) holds the PQZ attachment of gen-1 records — `setPqzKey`,
///         `storePqzPop`, `proven`, the owner and list entry of a proven key — and its PQZ reads prefer it (ruling A6-I1).
///
///         typed-signing R2 (owner 2026-11-01), T66b 3.1b (owner 2026-11-09, spec 2026-11-09-t66b-library-organisation.md
///         §11 (f); owner 2026-11-19, candidate (2)): the writers run by DELEGATECALL (`_lib`), on this contract's storage
///         (`UAStore.Layout`), in one of three libraries by domain: `UARegistryRegLib` the `register` forms;
///         `UARegistryCoreLib` the portable `msig` check, `acceptMembership`, `requirePortable`; `UARegistryAuxLib` the key
///         writes after registration (`setPqzKey`, `storePqzPop`, `setKemKey`, `cacheExpandedKey`, `updateMsig`). One
///         DELEGATECALL per operation from here; an auxiliary or registration writer runs another library's shared helpers by
///         one nested DELEGATECALL each (T66b 3.1c). The reads off the hot path run there too, inside the view (`_libView`):
///         `uaCount` in the core library; `registrationOf` (owner 2026-11-15, D1), `popOf`, `popSlotsOf`, `webAuthnKeyOf`, `pqzPopOf`, `pqzKeySigOf`,
///         `uaAt`, `uaPage`, `uaIndex` in the auxiliary library. The hot views (`requireAuthorized`, `kindOf`, `recordOf`,
///         `checkedOf`, the key and member readers), `uaAuthDigest` and the immutables' getters stay here; `muSig2KeyOf` and
///         `frostKeyOf` stay too (their typed return does not compile in a library: stack too deep). The three libraries'
///         addresses are in this contract's code, so they are part of the registry's CREATE2 address.
///
///         T66b R-1 (spec §5): the `pure` views whose code the core library holds (`uaOf`, `keyHashOf` and five digests) run
///         there too (`_libPure`), one copy of their code.
///
///         UA-7 O1 (plan T66a): `requirePortable`, the portable check view a `PqChat` record takes, runs `UARegistryCoreLib`'s
///         portable path by DELEGATECALL inside the view (`_libView`; the library entry writes nothing).
///
///         CTR-UA-37 (owner 2026-11-02): listing in an `msig` is no consent. A member accepts its slot (`acceptMembership`, a portable
///         `UAMembership`, in `UARegistryCoreLib`); `memberAccepted` reads it, the slots of the `pop` are accepted at registration, and
///         every verification but that `pop` counts accepted slots only: one read of one word, here and in `UARegistryCoreLib._msig`.
///
///         Open in UA-2a: HIP-632 (`hedera-native` members' 64-byte ed25519 signatures) needs a non-static CALL, which a
///         `view` `requireAuthorized` cannot make; such members verify as ECDSA/1271 only.
///         UNAUDITED.
contract UARegistry is IUARegistry, SaltedEIP712 {
    /// `verifyOnly` (spec 2026-11-19-registry-verify-only-kinds §2, CTR-UA-58): a single-key kind a predecessor enables, carried here
    /// for the consumer checks only, with its own verifier (bit 224 of the kind's word); `keyForm` (bit 225): the key form the registry
    /// hands that verifier, 0 the stored bytes, 1 the holder's ML-DSA cache, equal to the verifier's `KEY_FORM()`. Both 0 elsewhere.
    struct KindConfig {
        uint16 kind;
        address verifier;
        uint64 cap;
        bool verifyOnly;
        uint8 keyForm;
    }

    /// @notice A constructor argument is refused (kind outside this code's table, duplicate, verifier without code, cap
    ///         0 or above the budget, a keyHash group a predecessor enables, the verify-only rules of spec
    ///         2026-11-19-registry-verify-only-kinds §2, a predecessor line of another chain/profile, out of order, deeper
    ///         than `MAX_GENERATION` or without the views a successor reads), or one of its three libraries is not deployed.
    error UAConfig(uint16 kind);

    /// @notice `UARegistryRegLib` and `UARegistryAuxLib` write SSTORE2; solc lists only the errors a contract uses or declares, so this line keeps
    ///         it on the registry's ABI.
    error SSTORE2WriteFailed();

    /// @notice The depth cap of the line (owner R11): generations 1 … 16; a generation 17 is refused (`UAConfig(0)`).
    uint8 public constant MAX_GENERATION = 16;

    uint8 public immutable generation;
    address public immutable predecessor;
    bool public immutable hederaNative;
    uint64 public immutable verifyBudget;
    /// @notice The chain's per-transaction gas cap (owner X1): the bound of `msigBound` and of the PQZ debit.
    uint64 public immutable txGasCap;
    /// @notice `keccak256("evm:" ‖ decimal(block.chainid))`, computed at deploy (CTR-UA-07).
    bytes32 public immutable chainKeyHash;
    bytes32 private immutable _SMART_KEY_CLONE_CODEHASH;

    uint256 private immutable _CFG0; // 0x0100 webauthn-p256
    uint256 private immutable _CFG1; // 0x0101 p256
    uint256 private immutable _CFG2; // 0x0102 ed25519 (UA-2b)
    uint256 private immutable _CFG3; // 0x0103 bip340
    uint256 private immutable _CFG4; // 0x0104 schnorr-bn254
    uint256 private immutable _CFG5; // 0x0105 schnorr-bls12381
    uint256 private immutable _CFG6; // 0x0106 bls12381-minsig
    uint256 private immutable _CFG7; // 0x0107 bls-bn254-minsig
    uint256 private immutable _CFG8; // 0x0110 musig2-secp256k1 (UA-2c, stored)
    uint256 private immutable _CFG9; // 0x0111 frost-secp256k1 (UA-2c, stored)
    uint256 private immutable _CFG10; // 0x0112 musig2-bn254 (UA-2c, stored)
    uint256 private immutable _CFG11; // 0x0113 frost-bn254 (UA-2c, stored)
    uint256 private immutable _CFG12; // 0x0134 mldsa87 (CTR-UA-39, stored, precompile only; the slot of zether-bn254 before UA-6)
    uint256 private immutable _CFG13; // 0x0141 zether-bls12381 (UA-3, stored; SIGNING since UA-6)
    uint256 private immutable _CFG14; // 0x0130 mldsa44 (P6c, stored, expanded-key cache)
    uint256 private immutable _CFG15; // 0x0131 mldsa65 (P6c, stored, expanded-key cache)
    uint256 private immutable _CFG16; // 0x0132 fndsa512 (P6c, stored)
    uint256 private immutable _CFG17; // 0x0133 slhdsa128s (P6c, stored)
    uint256 private immutable _CFG18; // 0x0142 the PQZ key verifier (`R_REG`, UA-6; not a kind)
    uint256 private immutable _CFG19; // 0x0108 secp256k1 (ECDSA, 2026-10-17)
    uint256 private immutable _CFG20; // 0x0135 fndsa1024 (CTR-UA-40, stored)
    uint256 private immutable _CFG21; // 0x0121 bls12381-multi (spec 2026-11-19-bls12381-multi, stored `ua ‖ s`)
    uint256 private immutable _CFG_MSIG; // 0x0120: address(this) | verifyBudget << 160
    // a word: `verifier | cap << 160 | verifyOnly << 224 | keyForm << 225` (spec 2026-11-19-registry-verify-only-kinds §2); every
    // reader masks (N12): `UAStore._capOf`, `UAStore._registrable`

    UAStore.Layout private _s; // slot 0: the mappings, their slots and their comments in `UAStore.Layout`

    /// @param chainUid_ the chain's genesis hash (≠ 0, `SaltedEIP712.ChainUidZero`).
    /// @param predecessor_ 0 for generation 1, else the chain's latest generation n (this one is n + 1, at most `MAX_GENERATION`).
    /// @param txGasCap_ the chain's per-transaction gas cap from the deploy book (owner X1), at least `verifyBudget_`.
    /// @param smartKeyAccountImpl_ the chain's `SmartKeyAccount` implementation (0 = none): its EIP-1167 clones get the
    ///        400 k ERC-1271 cap.
    /// @param msig_ enables the structure kind `msig`.
    /// @param kinds_ the enabled single-key, group and Zether kinds with their verifier and measured verify cap.
    constructor(
        bytes32 chainUid_,
        address predecessor_,
        bool hederaNative_,
        uint64 verifyBudget_,
        uint64 txGasCap_,
        address smartKeyAccountImpl_,
        bool msig_,
        KindConfig[] memory kinds_
    ) SaltedEIP712Core("SCaaS UARegistry", _versionOf(predecessor_), chainUid_) {
        // owner P17: `verifyBudget ≤ txGasCap < 2^64` (the type bounds the top)
        if (
            verifyBudget_ == 0 || verifyBudget_ > txGasCap_
                || (smartKeyAccountImpl_ != address(0) && !SigCheck.isContract(smartKeyAccountImpl_))
        ) {
            revert UAConfig(0);
        }
        // `_lib`'s DELEGATECALL would "succeed" on an empty account, every write a silent no-op; the library has no way to
        // leave once it is there (no SELFDESTRUCT, `LinkClosure.test_libraryOpcodes`)
        if (
            address(UARegistryCoreLib).code.length == 0 || address(UARegistryAuxLib).code.length == 0
                || address(UARegistryRegLib).code.length == 0
        ) {
            revert UAConfig(0);
        }
        uint8 g = predecessor_ == address(0) ? 1 : _line(predecessor_, chainUid_, hederaNative_);
        uint256[22] memory k;
        for (uint256 i; i < kinds_.length; ++i) {
            KindConfig memory c = kinds_[i];
            uint256 slot = _slot(c.kind);
            if (
                slot > 21 || k[slot] != 0 || !SigCheck.isContract(c.verifier) || c.cap == 0 || c.cap > verifyBudget_
                    || c.keyForm > 1 || !_kindRule(predecessor_, c)
            ) revert UAConfig(c.kind);
            k[slot] = uint256(uint160(c.verifier)) | uint256(c.cap) << 160 | (c.verifyOnly ? 1 << 224 : 0)
                | uint256(c.keyForm) << 225;
        }
        // M10 (d) (owner P16): where `0x0142` is on the line, each verify-only kind's single-key fallback within the PQZ debit bound
        if (predecessor_ != address(0) && (k[18] != 0 || IUARegistry(predecessor_).kindHome(UAKinds.PQZ_MLWE) != address(0)))
        {
            _voDebit(predecessor_, kinds_, g, txGasCap_);
        }
        (_CFG0, _CFG1, _CFG2, _CFG3) = (k[0], k[1], k[2], k[3]);
        (_CFG4, _CFG5, _CFG6, _CFG7) = (k[4], k[5], k[6], k[7]);
        (_CFG8, _CFG9, _CFG10, _CFG11) = (k[8], k[9], k[10], k[11]);
        (_CFG12, _CFG13) = (k[12], k[13]);
        (_CFG14, _CFG15, _CFG16, _CFG17, _CFG18) = (k[14], k[15], k[16], k[17], k[18]);
        (_CFG19, _CFG20, _CFG21) = (k[19], k[20], k[21]);
        _CFG_MSIG = msig_ ? uint256(uint160(address(this))) | uint256(verifyBudget_) << 160 : 0;

        generation = g;
        predecessor = predecessor_;
        hederaNative = hederaNative_;
        verifyBudget = verifyBudget_;
        txGasCap = txGasCap_;
        chainKeyHash = UAKinds.chainKeyHash(block.chainid);
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0)
            ? bytes32(0)
            : keccak256(
                abi.encodePacked(hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3")
            );
    }

    // ----- views -----

    function kindEnabled(uint16 kind) external view returns (bool) {
        return uint160(_cfg(kind)) != 0;
    }

    function verifyCap(uint16 kind) public view returns (uint64) {
        return uint64(_cfg(kind) >> 160);
    }

    /// Spec 2026-11-19-registry-verify-only-kinds §3 (N4): this generation carries `kind` for the consumer checks only.
    function verifyOnly(uint16 kind) external view returns (bool) {
        return _cfg(kind) >> 224 & 1 != 0;
    }

    /// §11.1: this generation's verifier of `kind` (0 if none): the address of its word.
    function verifierOf(uint16 kind) external view returns (address) {
        return address(uint160(_cfg(kind)));
    }

    /// §11.1 (owner Y1, P5): the one walk, in `UARegistryCoreLib`; a native-space id without it.
    function holderOf(bytes32 ua) external view returns (address, uint16, address) {
        if (UAKinds.inNativeSpace(ua)) return (address(0), 0, address(0));
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.holderOf.selector, 0);
    }

    function lineReaches(address root) external view returns (bool) {
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.lineReaches.selector, 0);
    }

    function pqzHomeOf(bytes32 ua) external view returns (address) {
        if (UAKinds.inNativeSpace(ua)) return address(0);
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.pqzHomeOf.selector, 0);
    }

    /// §11.1 (owner Y1): the generation of the line where `kind` registers, 0 if none; the walk in `UARegistryCoreLib`.
    function kindHome(uint16 kind) external view returns (address) {
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.kindHome.selector, kind);
    }

    function chainUid() external view returns (bytes32) {
        return CHAIN_UID;
    }

    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32 ua) {
        _libPure(address(UARegistryCoreLib), UARegistryCoreLib.uaOf.selector);
    }

    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32 h) {
        _libPure(address(UARegistryCoreLib), UARegistryCoreLib.keyHashOf.selector);
    }

    /// TS-D5: the name of a kind id of the table (enabled or not); an unknown id reverts `UAKindUnknown(kind)`.
    function kindName(uint16 kind) external pure returns (string memory) {
        return UAKinds.name(kind);
    }

    function portableDomainSeparator() external pure returns (bytes32) {
        return UAKinds.PORTABLE_DOMAIN_SEPARATOR;
    }

    function portableRecordDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash_)
        external
        pure
        returns (bytes32 d)
    {
        _libPure(address(UARegistryAuxLib), UARegistryAuxLib.portableRecordDigest.selector);
    }

    function kemRecordHash(bytes32 ua, uint64 version, KemKey calldata kem) external pure returns (bytes32) {
        return UAKinds.kemRecordHash(ua, version, UAKinds.kemPk(kem));
    }

    function registrationDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash_, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32 d)
    {
        _libPure(address(UARegistryAuxLib), UARegistryAuxLib.registrationDigest.selector);
    }

    function kemRecordDigest(bytes32 ua, uint64 version, KemKey calldata kem) external pure returns (bytes32) {
        return UAKinds.kemRecordDigest(ua, version, UAKinds.kemPk(kem));
    }

    function pqzKeyDigest(bytes32 ua, bytes32 pqzKeyHash) external pure returns (bytes32) {
        return UAKinds.pqzKeyDigest(ua, pqzKeyHash);
    }

    function pqzKeyRecordDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 pqzPopHash) external pure returns (bytes32 d) {
        _libPure(address(UARegistryAuxLib), UARegistryAuxLib.pqzKeyRecordDigest.selector);
    }

    function pqzKeyVersionDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash) external pure returns (bytes32 d) {
        _libPure(address(UARegistryAuxLib), UARegistryAuxLib.pqzKeyVersionDigest.selector);
    }

    function pqzKeyVersionRecordDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32 d)
    {
        _libPure(address(UARegistryAuxLib), UARegistryAuxLib.pqzKeyVersionRecordDigest.selector);
    }

    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32) {
        return UAKinds.uaMessage(kind, purposeTag, digest);
    }

    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) public view returns (bytes32) {
        return UAKinds.uaAuthDigest(_domainSeparatorV4(), ua, purposeTag, digest);
    }

    /// `r.keyPtr ≠ 0` only for stored kinds and an updated `msig` (CTR-UA-44 MM-7: its structure blob, no key); `pqzKey ≠ 0` only for PQZ holders with a key (proven or not): the current
    /// version's (group 3g). A record held elsewhere: its PQZ home's answer (§11.2), or the holder's where it has none; here the
    /// home of a record held elsewhere: the holder's record with this generation's key.
    function recordOf(bytes32 ua) external view returns (Record memory r, address pqzKey) {
        (address t, address h) = _pqzWhere(ua);
        if (t != address(0)) return IUARegistry(t).recordOf(ua);
        r = _s.records[ua];
        if (h != address(0)) (r,) = IUARegistry(h).recordOf(ua);
        (, pqzKey,,) = pqzKeyOf(ua);
    }

    // ----- UA-8 reads (gen 2 forwards a record it does not hold, UA8-D11) -----

    /// N11 (spec 2026-11-19-registry-verify-only-kinds §11.1): the generation that holds a record this one does not, read at it
    /// directly; 0 when held here or nowhere (then this generation's empty answer is the line's). The predecessor's `holderOf`
    /// answers it (controller call (auto-run): for a record not held here it is this generation's own walk without the PQZ fill,
    /// one DELEGATECALL and one self-call fewer than `IUARegistry(address(this)).holderOf`, plan C8).
    function _away(bytes32 ua) private view returns (address h) {
        if (predecessor != address(0) && _s.records[ua].kind == 0) (h,,) = IUARegistry(predecessor).holderOf(ua);
    }

    /// Spec 2026-11-19-registry-verify-only-kinds §11.2 (owner P7; ruling A6-I1 for N generations): a UA's PQZ attachment (the
    /// versions, the proofs, `proven`, the owner of a proven key, the `0x0142` list entry, `current`) lives in its **PQZ home**,
    /// the oldest generation from its holder to the reader that enables 0x0142 (`holderOf`'s third word). From here: `t` the
    /// generation to forward a read to (its home, or its holder where it has none; 0: this one answers); `h` the holder of a
    /// record held elsewhere whose home this generation is (it reads each version from its own record when it has one, else the
    /// holder's: host rules 2 and 3), 0 otherwise.
    function _pqzWhere(bytes32 ua) private view returns (address t, address h) {
        if (predecessor == address(0) || _s.records[ua].kind != 0) return (t, h);
        address home;
        (h,, home) = IUARegistry(predecessor).holderOf(ua);
        if (home == address(0) && h != address(0) && uint160(_CFG18) != 0) return (t, h);
        (t, h) = (home != address(0) ? home : h, address(0));
    }

    /// Version `v` of `ua`: this generation's record, else the home's or the holder's (host rule 2).
    function _pqzAt(bytes32 ua, uint64 v) private view returns (address ptr, bytes32 pqzPopHash, bool proven) {
        UAStore.PqzKey memory k = _s.pqzKey[ua][v];
        if (k.ptr == address(0)) {
            (address t, address h) = _pqzWhere(ua);
            if (t != address(0) || h != address(0)) return IUARegistry(t != address(0) ? t : h).pqzKeyAt(ua, v);
        }
        return (k.ptr, _s.pqzPopHash[ua][v], k.proven);
    }

    function registrationOf(bytes32 ua)
        external
        view
        returns (uint16 kind, bytes memory keyData, UAAttrs memory attrs, bytes memory pop, bytes memory pqzPop)
    {
        _libView(address(UARegistryAuxLib), UARegistryAuxLib.registrationOf.selector, kind); // D1 (owner 2026-11-15)
    }

    function popOf(bytes32 ua) external view returns (bytes memory pop) {
        _libView(address(UARegistryAuxLib), UARegistryAuxLib.popOf.selector, 0);
    }

    function msigOf(bytes32 ua) external view returns (MsigStructure memory s) {
        address h = _away(ua);
        if (h != address(0)) return IUARegistry(h).msigOf(ua);
        Record memory r = _s.records[ua];
        if (r.kind != UAKinds.MSIG) return s;
        bytes memory d = UAStore.msig(ua, r.keyPtr); // CTR-UA-44: the current structure, every slot
        uint256 n = UAStore.u16(d, 2);
        s.threshold = uint16(UAStore.u16(d, 0));
        s.members = new MsigMember[](n);
        for (uint256 i; i < n; ++i) {
            uint256 o = 4 + 36 * i;
            s.members[i] =
                MsigMember(uint16(UAStore.u16(d, o)), bytes32(UAStore.word(d, o + 2)), uint16(UAStore.u16(d, o + 34)));
        }
    }

    function memberAccepted(bytes32 ua, uint256 index) external view returns (bool) {
        address h = _away(ua);
        if (h != address(0)) return IUARegistry(h).memberAccepted(ua, index);
        Record memory r = _s.records[ua];
        uint256 en = type(uint256).max; // never updated: every slot, and no accepted bit lies past them
        if (r.kind == UAKinds.MSIG && r.keyPtr != address(0)) (en,) = UAStore.trailer(r.keyPtr);
        return (_s.accepted[ua] & en) >> index & 1 != 0; // CTR-UA-44: enabled and accepted
    }

    function msigStateOf(bytes32 ua) external view returns (uint64 version, uint256 enabled, uint256 accepted) {
        _libView(address(UARegistryAuxLib), UARegistryAuxLib.msigStateOf.selector, 0);
    }

    function memberSigHashOf(bytes32 ua, uint256 index) external view returns (bytes32) {
        address h = _away(ua);
        if (h != address(0)) return IUARegistry(h).memberSigHashOf(ua, index);
        return _s.memberSigHash[ua][index];
    }

    function popSlotsOf(bytes32 ua) external view returns (uint16[] memory index, bytes32[] memory hash) {
        _libView(address(UARegistryAuxLib), UARegistryAuxLib.popSlotsOf.selector, 0);
    }

    function smartKeyCloneHash() external view returns (bytes32) {
        return _SMART_KEY_CLONE_CODEHASH;
    }

    /// TS-D13: the typed keys of `webauthn-p256` / MuSig2 / FROST records (empty for any other id).
    function webAuthnKeyOf(bytes32 ua) external view returns (WebAuthnKey memory k) {
        _libView(address(UARegistryAuxLib), UARegistryAuxLib.webAuthnKeyOf.selector, 0);
    }

    function muSig2KeyOf(bytes32 ua) external view returns (MuSig2Key memory k) {
        address h = _away(ua);
        if (h != address(0)) return IUARegistry(h).muSig2KeyOf(ua);
        Record memory r = _s.records[ua];
        if (r.kind != UAKinds.MUSIG2_SECP256K1 && r.kind != UAKinds.MUSIG2_BN254) return k;
        (uint256 size, bytes memory d) = (UAStore.vkLength(r.kind), UAStore.keyRest(ua)); // u16 n ‖ n × key
        k.aggKey = SSTORE2.read(r.keyPtr);
        k.memberKeys = new bytes[](UAStore.u16(d, 0));
        for (uint256 i; i < k.memberKeys.length; ++i) {
            k.memberKeys[i] = UAStore.cut(d, 2 + i * size, size);
        }
    }

    /// `bls12381-multi`'s typed key: its key data `d`, expanded from the stored `ua ‖ s` (spec 2026-11-19-bls12381-multi §2).
    function blsMultiKeyOf(bytes32 ua) external view returns (BlsMultiKey memory k) {
        _libView(address(UARegistryAuxLib), UARegistryAuxLib.blsMultiKeyOf.selector, 0);
    }

    function frostKeyOf(bytes32 ua) external view returns (FrostKey memory k) {
        address h = _away(ua);
        if (h != address(0)) return IUARegistry(h).frostKeyOf(ua);
        Record memory r = _s.records[ua];
        if (r.kind != UAKinds.FROST_SECP256K1 && r.kind != UAKinds.FROST_BN254) return k;
        (uint256 size, bytes memory d) = (UAStore.vkLength(r.kind), UAStore.keyRest(ua)); // u16 t ‖ u16 n ‖ n × member
        k.groupKey = SSTORE2.read(r.keyPtr);
        uint256 t = UAStore.u16(d, 0);
        k.threshold = uint16(t);
        k.members = new FrostMember[](UAStore.u16(d, 2));
        for (uint256 i; i < k.members.length; ++i) {
            uint256 o = 4 + i * ((t + 1) * size + 32);
            FrostMember memory m = k.members[i];
            m.commitments = new bytes[](t);
            for (uint256 j; j < t; ++j) {
                m.commitments[j] = UAStore.cut(d, o + j * size, size);
            }
            m.r = UAStore.cut(d, o + t * size, size);
            m.z = bytes32(UAStore.word(d, o + (t + 1) * size));
        }
    }

    function pqzPopOf(bytes32 ua, uint64 version) external view returns (bytes memory) {
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.pqzPopOf.selector, 0);
    }

    function pqzKeySigOf(bytes32 ua, uint64 version) external view returns (bytes memory) {
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.pqzKeySigOf.selector, 0);
    }

    /// Group 3g (KV-3): one current per UA at its PQZ home (§11.2); a generation that is not the home forwards.
    function pqzKeyOf(bytes32 ua) public view returns (uint64 version, address ptr, bytes32 pqzPopHash, bool proven) {
        (address t,) = _pqzWhere(ua);
        if (t != address(0)) return IUARegistry(t).pqzKeyOf(ua);
        version = _s.pqzVersions[ua].current;
        (ptr, pqzPopHash, proven) = _pqzAt(ua, version);
    }

    function pqzKeyAt(bytes32 ua, uint64 version) external view returns (address ptr, bytes32 pqzPopHash, bool proven) {
        return _pqzAt(ua, version);
    }

    function pqzKeyLatest(bytes32 ua) external view returns (uint64 latest) {
        (address t, address h) = _pqzWhere(ua);
        if (t != address(0)) return IUARegistry(t).pqzKeyLatest(ua);
        latest = _s.pqzVersions[ua].latest;
        if (h != address(0)) {
            uint64 g = IUARegistry(h).pqzKeyLatest(ua);
            if (g > latest) latest = g;
        }
    }

    function pqzKeyUsed(bytes32 ua, bytes32 pqzKeyHash) external view returns (bool) {
        (address t, address h) = _pqzWhere(ua);
        if (t != address(0)) return IUARegistry(t).pqzKeyUsed(ua, pqzKeyHash);
        return _s.pqzKeyUsed[ua][pqzKeyHash] || (h != address(0) && IUARegistry(h).pqzKeyUsed(ua, pqzKeyHash));
    }

    // ----- the PQZ three-key model: scoped PQZ key records (spec 2026-11-13-pqz-three-keys K3-3) -----

    /// What a class-2 / class-3 PQZ token reads (the hot path, here as `pqzKeyOf`): the current scoped version of `(ua, scope)`.
    function pqzScopedKeyOf(bytes32 ua, address scope)
        external
        view
        returns (uint64 version, address ptr, bytes32 pqzPopHash, bool proven)
    {
        (address t,) = _pqzWhere(ua);
        if (t != address(0)) return IUARegistry(t).pqzScopedKeyOf(ua, scope);
        version = _s.scopedVersions[ua][scope].current;
        UAStore.PqzKey memory k = _s.scopedKey[ua][scope][version];
        (ptr, pqzPopHash, proven) = (k.ptr, _s.scopedPopHash[ua][scope][version], k.proven);
    }

    function pqzScopedKeyAt(bytes32 ua, address scope, uint64 version)
        external
        view
        returns (address ptr, bytes32 pqzPopHash, bool proven)
    {
        (address t,) = _pqzWhere(ua);
        if (t != address(0)) return IUARegistry(t).pqzScopedKeyAt(ua, scope, version);
        UAStore.PqzKey memory k = _s.scopedKey[ua][scope][version];
        return (k.ptr, _s.scopedPopHash[ua][scope][version], k.proven);
    }

    function pqzScopedKeyLatest(bytes32 ua, address scope) external view returns (uint64) {
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.pqzScopedKeyLatest.selector, 0);
    }

    function pqzScopedPopOf(bytes32 ua, address scope, uint64 version) external view returns (bytes memory) {
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.pqzScopedPopOf.selector, 0);
    }

    function pqzOpenKemAt(bytes32 ua, address scope, uint64 version) external view returns (KemKey memory) {
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.pqzOpenKemAt.selector, 0);
    }

    function pqzScopedCount(address scope) external view returns (uint256) {
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.pqzScopedCount.selector, 0);
    }

    function pqzScopedAt(address scope, uint256 i) external view returns (bytes32) {
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.pqzScopedAt.selector, 0);
    }

    function pqzScopedKeyDigest(
        bytes32 ua,
        uint8 keyClass,
        bytes32 chainUid_,
        address token,
        uint64 version,
        bytes32 pqzKeyHash
    ) external pure returns (bytes32) {
        _libPure(address(UARegistryAuxLib), UARegistryAuxLib.pqzScopedKeyDigest.selector);
    }

    function pqzScopedKeyRecordDigest(
        bytes32 ua,
        uint8 keyClass,
        bytes32 chainUid_,
        address token,
        uint64 version,
        bytes32 pqzKeyHash,
        bytes32 pqzPopHash,
        bytes32 openKemHash,
        uint64 validUntilBlock
    ) external pure returns (bytes32) {
        _libPure(address(UARegistryAuxLib), UARegistryAuxLib.pqzScopedKeyRecordDigest.selector);
    }

    function setPqzScopedKey(
        bytes32 ua,
        address scope,
        uint64 version,
        bytes calldata pqzKey,
        bytes32 pqzPopHash,
        KemKey calldata openKem,
        uint64 validUntilBlock,
        UASig calldata sig
    ) external {
        _lib(address(UARegistryAuxLib), UARegistryAuxLib.setPqzScopedKey.selector, _s.records[ua].kind);
    }

    function storePqzScopedPop(bytes32 ua, address scope, uint64 version, bytes calldata pqzPop) external {
        _lib(address(UARegistryAuxLib), UARegistryAuxLib.storePqzScopedPop.selector, 0);
    }

    function checkedOf(bytes32 ua) external view returns (uint8 pop, uint8 pqzPop, uint8 kem) {
        bool proven;
        (address t, address h) = _pqzWhere(ua);
        if (t != address(0)) return IUARegistry(t).checkedOf(ua);
        if (h != address(0)) {
            (pop, pqzPop, kem) = IUARegistry(h).checkedOf(ua);
            (,,, proven) = pqzKeyOf(ua); // A6-I1: the home's current
            return (pop, UAStore.checked(proven), kem);
        }
        if (_s.records[ua].kind == 0) return (pop, pqzPop, kem);
        (,,, proven) = pqzKeyOf(ua);
        return (UAKinds.CHECKED_CHAIN, UAStore.checked(proven), UAStore.checked(_hasKem(ua)));
    }

    function kemKeyOf(bytes32 ua) external view returns (uint64 version, KemKey memory kem, bytes memory sig) {
        address h = _away(ua);
        if (h != address(0)) return IUARegistry(h).kemKeyOf(ua);
        version = _s.kemMax[ua];
        (kem, sig) = UAStore.kemAt(ua, version);
    }

    /// A KEM key stored here: the `register` key (version 0) or a `setKemKey` one (`_kemMax` ≥ 1).
    function _hasKem(bytes32 ua) private view returns (bool) {
        return _s.kemMax[ua] != 0 || _s.kem[ua][0].length != 0;
    }

    function kemKeyAt(bytes32 ua, uint64 version) external view returns (KemKey memory kem, bytes memory sig) {
        address h = _away(ua);
        if (h != address(0)) return IUARegistry(h).kemKeyAt(ua, version);
        return UAStore.kemAt(ua, version);
    }

    /// The stored key of a stored kind (MuSig2 `Q`, FROST `Y`, Zether `Y`, PQ `pk`), empty for every other id.
    function keyOf(bytes32 ua) external view returns (bytes memory) {
        address h = _away(ua);
        if (h != address(0)) return IUARegistry(h).keyOf(ua);
        Record memory r = _s.records[ua];
        if (r.kind == UAKinds.MSIG) return ""; // CTR-UA-44 MM-10: its `keyPtr` is a structure, never a key
        // `bls12381-multi` (N2): `apk` in EIP-2537 form, one point of the stored `ua ‖ c(apk) ‖ …`, never the pointer's bytes
        if (r.kind == UAKinds.BLS12381_MULTI) return BlsMultiKeyData.point(SSTORE2.read(r.keyPtr, 0, 224), 0);
        return SSTORE2.read(r.keyPtr);
    }

    // ----- the per-kind list (IUARegistry.uaCount) -----

    /// A kind this generation does not enable belongs to the predecessor's list; a kind both enable (msig) has one
    /// list per generation.
    function _listedHere(uint16 kind) private view returns (bool) {
        return predecessor == address(0) || UAStore._registrable(_cfg(kind));
    }

    function uaCount(uint16 kind) public view returns (uint256) {
        _libView(address(UARegistryCoreLib), UARegistryCoreLib.uaCount.selector, kind);
    }

    function uaAt(uint16 kind, uint256 i) external view returns (bytes32) {
        _libView(address(UARegistryAuxLib), UARegistryAuxLib.uaAt.selector, kind);
    }

    function uaPage(uint16 kind, uint256 start, uint256 n) external view returns (bytes32[] memory page) {
        _libView(address(UARegistryAuxLib), UARegistryAuxLib.uaPage.selector, kind);
    }

    function uaIndex(bytes32 ua) external view returns (uint256) {
        _libView(address(UARegistryAuxLib), UARegistryAuxLib.uaIndex.selector, 0);
    }

    /// P5: a native-space id without a walk; else the walk's kind (one call per generation).
    function kindOf(bytes32 ua) public view returns (uint16 kind) {
        if (UAKinds.inNativeSpace(ua)) return 0;
        kind = _s.records[ua].kind;
        if (kind == 0 && predecessor != address(0)) (, kind,) = IUARegistry(predecessor).holderOf(ua);
    }

    function isRegistered(bytes32 ua) external view returns (bool) {
        return kindOf(ua) != 0;
    }

    function keyOwner(bytes32 keyHash) public view returns (bytes32 owner) {
        owner = _s.keyOwner[keyHash];
        if (owner == 0 && predecessor != address(0)) owner = IUARegistry(predecessor).keyOwner(keyHash);
    }

    /// The ML-DSA expanded-key parts stored for `ua` (0 = not yet; ML-DSA-44 uses the first only, ML-DSA-65 two, ML-DSA-87
    /// three): the holding generation's cache (F12: a record held elsewhere forwards to its holder), else this generation's.
    function expandedKeyOf(bytes32 ua) external view returns (address[3] memory) {
        address h = _away(ua);
        if (h != address(0)) return IUARegistry(h).expandedKeyOf(ua);
        return _s.ekPtr[ua];
    }

    // ----- the writers and the reads off the hot path: in `UARegistryRegLib`, `UARegistryCoreLib` and `UARegistryAuxLib` -----

    /// Runs the library `lib`'s entry `sel` by DELEGATECALL (`UARegistryRegLib`, `UARegistryCoreLib` or `UARegistryAuxLib`, by the entry's domain): this call's arguments as they came, then four words the
    /// library cannot read for itself, `_cfg(kind)`, `_cfg(0x0142)`, the clone codehash (`kind` is the kind the entry knows), and
    /// (spec 2026-11-19-bls12381-multi §5.3, N1) `_cfg(0x0121)`, the verifier of a `0x0121` `msig` member on a stored path.
    /// They come from this contract's immutables only and sit past the caller's bytes; the library reads them from the end
    /// of its calldata. Its return data or revert data is this call's, byte for byte.
    function _lib(address lib, bytes4 sel, uint16 kind) private {
        (uint256 a, uint256 b, bytes32 c, uint256 m) = (_cfg(kind), _CFG18, _SMART_KEY_CLONE_CODEHASH, _CFG21);
        assembly {
            mstore(0, sel)
            calldatacopy(4, 4, sub(calldatasize(), 4))
            let e := calldatasize()
            mstore(e, a)
            mstore(add(e, 32), b)
            mstore(add(e, 64), c)
            mstore(add(e, 96), m)
            let ok := delegatecall(gas(), lib, 0, add(e, 128), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if ok { return(0, returndatasize()) }
            revert(0, returndatasize())
        }
    }

    function cacheExpandedKey(uint16 kind, bytes calldata pk, uint256 part) external returns (bytes32 ua) {
        _lib(address(UARegistryAuxLib), UARegistryAuxLib.cacheExpandedKey.selector, kind);
    }

    function register(
        uint16 kind,
        bytes calldata keyData,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua) {
        _lib(address(UARegistryRegLib), UARegistryRegLib.register.selector, kind);
    }

    function registerWebAuthn(
        WebAuthnKey calldata key,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua) {
        _lib(address(UARegistryRegLib), UARegistryRegLib.registerWebAuthn.selector, UAKinds.WEBAUTHN_P256);
    }

    function registerMuSig2(
        uint16 kind,
        MuSig2Key calldata key,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua) {
        _lib(address(UARegistryRegLib), UARegistryRegLib.registerMuSig2.selector, kind);
    }

    function registerFrost(
        uint16 kind,
        FrostKey calldata key,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua) {
        _lib(address(UARegistryRegLib), UARegistryRegLib.registerFrost.selector, kind);
    }

    function registerBlsMulti(
        BlsMultiKey calldata key,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua) {
        _lib(address(UARegistryRegLib), UARegistryRegLib.registerBlsMulti.selector, UAKinds.BLS12381_MULTI);
    }

    function registerMsig(
        MsigStructure calldata structure,
        UAAttrs calldata attrs,
        MemberSig[] calldata pop,
        bytes calldata pqzPop
    ) external returns (bytes32 ua) {
        _lib(address(UARegistryRegLib), UARegistryRegLib.registerMsig.selector, UAKinds.MSIG);
    }

    function storePqzPop(bytes32 ua, uint64 version, bytes calldata pqzPop) external {
        _lib(address(UARegistryAuxLib), UARegistryAuxLib.storePqzPop.selector, 0);
    }

    function setPqzKey(bytes32 ua, uint64 version, bytes calldata pqzKey, bytes32 pqzPopHash, UASig calldata sig)
        external
    {
        _lib(address(UARegistryAuxLib), UARegistryAuxLib.setPqzKey.selector, _s.records[ua].kind);
    }

    function setKemKey(bytes32 ua, uint64 version, KemKey calldata kem, UASig calldata sig) external {
        _lib(address(UARegistryAuxLib), UARegistryAuxLib.setKemKey.selector, _s.records[ua].kind);
    }

    function acceptMembership(bytes32 ua, MemberSig calldata memberSig) external {
        _lib(address(UARegistryCoreLib), UARegistryCoreLib.acceptMembership.selector, 0);
    }

    function updateMsig(
        bytes32 ua,
        uint64 version,
        MsigStructure calldata structure,
        uint256 enabled,
        uint64 validUntilBlock,
        MemberSig[] calldata sigs,
        bytes32 chainUid_
    ) external {
        _lib(address(UARegistryAuxLib), UARegistryAuxLib.updateMsig.selector, UAKinds.MSIG);
    }

    /// UA-7 O1 (plan T66a): a record held elsewhere of a kind not verify-only here goes to its holder directly (spec
    /// 2026-11-19-registry-verify-only-kinds §4, N3: its verdict, its revert as it is), else the library's check (`_portableAt`).
    function requirePortable(bytes32 ua, bytes32 purposeTag, bytes32 typedDigest, UASig calldata auth) external view {
        (address h, uint16 k) = _portableAt(ua);
        if (h != address(0)) IUARegistry(h).requirePortable(ua, purposeTag, typedDigest, auth);
        else _libView(address(UARegistryCoreLib), UARegistryCoreLib.requirePortable.selector, k);
    }

    /// §4: where a portable check of `ua` runs. Held here, or held elsewhere of a kind verify-only here: this generation's library (`k`
    /// the kind, so the library gets its word); held elsewhere of another kind: its holder `h`; held nowhere: the library, which refuses.
    function _portableAt(bytes32 ua) private view returns (address h, uint16 k) {
        k = _s.records[ua].kind;
        if (k == 0) {
            (h, k) = _holderKind(ua);
            if (_vo(k)) h = address(0);
        }
    }

    /// CTR-UA-46: as `requirePortable`, under the purpose the library derives from `appId`. Gen 2 forwards plainly: a predecessor
    /// without this entry reverts (empty data, no fallback), a refusal of a void view.
    function requirePortableApp(bytes32 ua, bytes32 appId, bytes32 typedDigest, UASig calldata auth) external view {
        (address h, uint16 k) = _portableAt(ua);
        if (h != address(0)) IUARegistry(h).requirePortableApp(ua, appId, typedDigest, auth);
        else _libView(address(UARegistryCoreLib), UARegistryCoreLib.requirePortableApp.selector, k);
    }

    /// `_lib` inside a view (`requirePortable`): the library entry writes nothing, so it runs in a STATICCALL frame too. Solidity
    /// types no DELEGATECALL as `view`; the function pointer is cast.
    function _libView(address lib, bytes4 sel, uint16 kind) private view {
        function(address, bytes4, uint16) f = _lib;
        function(address, bytes4, uint16) view v;
        assembly {
            v := f
        }
        v(lib, sel, kind);
    }

    /// T66b R-1 (spec 2026-11-09-t66b-library-organisation.md §5): a `pure` view whose code a registry library holds runs there
    /// (`lib`: the core for `uaOf` and `keyHashOf`, since 3.1d the Aux library for the five `*Digest` views), one copy of it in the pair: this call's
    /// calldata under the library entry `sel` (the same ABI), none of `_lib`'s four words
    /// appended (a pure body reads no configuration); its return or revert data is this call's, byte for byte. Only where the
    /// view's own bytes exceed this stub (≈ 45–80 B); `uaAuthDigest` stays (it reads this contract's EIP-712 immutables).
    function _libRaw(address lib, bytes4 sel) private {
        assembly {
            mstore(0, sel)
            calldatacopy(4, 4, sub(calldatasize(), 4))
            let ok := delegatecall(gas(), lib, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if ok { return(0, returndatasize()) }
            revert(0, returndatasize())
        }
    }

    /// `_libRaw` inside a `pure` view (R-1): the library entry is `pure`; the function pointer is cast, as `_libView`'s.
    function _libPure(address lib, bytes4 sel) private pure {
        function(address, bytes4) f = _libRaw;
        function(address, bytes4) pure v;
        assembly {
            v := f
        }
        v(lib, sel);
    }

    // ----- requireAuthorized -----

    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, UASig calldata auth) external view {
        if (!UAKinds.inNativeSpace(ua) && _s.records[ua].kind == 0) {
            // spec 2026-11-19-registry-verify-only-kinds §4 (CTR-UA-60, N3): a record held elsewhere, one walk. A kind verify-only here:
            // this generation's verifier in the library (`UAKeyNotCached` from the holder's cache under key form 1); any other: its
            // holder's check, handed to it directly (`via`: its starvation `UAVerifyGas`, any other refusal `UAUnauthorized`)
            (address h, uint16 k) = _holderKind(ua);
            if (_vo(k)) _libView(address(UARegistryCoreLib), UARegistryCoreLib.requireAuthorized.selector, k);
            else if (!UAStore.via(h, ua, purposeTag, digest, auth)) revert UAUnauthorized(ua); // held nowhere: h = 0, false
            return;
        }
        if (!_authorized(ua, purposeTag, digest, auth)) {
            // owner 2026-11-15, F-8: an ML-DSA record without its complete cache on a verifier without a precompile gets the named
            // refusal (CTR-UA-23), asked only after a refused check, so an accepted one pays nothing for it
            uint16 kind = _s.records[ua].kind;
            uint256 cfg = _cfg(kind);
            if (
                PqUA.mldsaParts(kind) != 0 && UAStore._registrable(cfg) && UAStore.expanded(ua, kind).length == 0
                    && UAStore.noPrecompile(address(uint160(cfg)))
            ) revert UAKeyNotCached(ua);
            revert UAUnauthorized(ua);
        }
    }

    /// TS-D12: native — `signature` only; `msig` — `members` only (the structure from the record); other derived ids —
    /// `keyData` + `signature`, no `members`.
    function _authorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, UASig calldata auth)
        private
        view
        returns (bool)
    {
        if (UAKinds.inNativeSpace(ua)) {
            return
                auth.keyData.length == 0 && auth.members.length == 0 && _native(ua, purposeTag, digest, auth.signature);
        }
        uint16 kind = _s.records[ua].kind; // held here (`requireAuthorized` took the rest)
        if (kind == UAKinds.MSIG) {
            // CTR-UA-44: the current structure (the record's slot is warm: its `keyPtr` costs a warm read, single keys pay nothing)
            return auth.keyData.length == 0 && auth.signature.length == 0
                && _msig(ua, purposeTag, digest, UAStore.msig(ua, _s.records[ua].keyPtr), auth.members);
        }
        return auth.members.length == 0 && _derived(ua, kind, purposeTag, digest, auth.keyData, auth.signature);
    }

    /// A derived id of `kind` (taken from the record, or from the structure for members): key data against the id
    /// (stored kinds, and every member signature — purpose `member`, CTR-UA-33: `keyData` empty, the key from the id's
    /// own record: `vk` at `keyPtr`, else the key data in the registration blob), then the kind's verifier, `msig`, or
    /// gen 1 for a kind this generation does not enable (handed on with the empty `keyData`: gen 1 reads its record).
    /// Never an `msig` (not a member kind; `_authorized` takes it).
    function _derived(
        bytes32 id,
        uint16 kind,
        bytes32 purposeTag,
        bytes32 digest,
        bytes memory keyData,
        bytes memory sig
    ) private view returns (bool) {
        uint256 cfg = _cfg(kind);
        if (!UAStore._registrable(cfg)) {
            // §4: a member held elsewhere, its kind `holderOf`'s (the listed one must match): verify-only here, this generation's
            // `requireAuthorized` of it (the library's verifier path); else its holder, directly, one hand-off (N3)
            (address h, uint16 k) = _holderKind(id);
            if (k != kind) return false;
            return UAStore.via(
                cfg >> 224 & 1 != 0 ? address(this) : h, id, purposeTag, digest, UASig(keyData, sig, new MemberSig[](0))
            );
        }
        uint256 vl = UAStore.vkLength(kind);
        if (vl != 0 || purposeTag == UAKinds.PURPOSE_MEMBER) {
            if (keyData.length != 0) return false; // CTR-UA-17 / CTR-UA-33: auth carries only the signature
            Record memory r = _s.records[id];
            if (r.kind != kind) return false;
            if (vl == 0) {
                keyData = UAStore.keyRest(id);
            } else {
                bytes memory ek = UAStore.expanded(id, kind);
                if (ek.length != 0) {
                    bytes32 m = UAKinds.uaMessage(kind, purposeTag, digest);
                    return _verifierCall(cfg, MldsaVerifier.verifyCached.selector, ek, m, sig);
                }
                keyData = SSTORE2.read(r.keyPtr);
            }
        } else if (UAKinds.uaOf(kind, keyData) != id) {
            return false;
        }
        return
            _verifierCall(
                cfg, IUAKindVerifier.verify.selector, keyData, UAKinds.uaMessage(kind, purposeTag, digest), sig
            );
    }

    /// §4: the holder of a record this generation does not hold and its kind, by the walk (the predecessor's `holderOf`, C8); (0, 0)
    /// for a record held nowhere, or at generation 1. A failed read is `UAVerifyGas` (F11).
    function _holderKind(bytes32 ua) private view returns (address h, uint16 k) {
        if (predecessor != address(0)) {
            (h, k,) = abi.decode(
                UAStore.read(predecessor, abi.encodeCall(IUARegistry.holderOf, (ua))), (address, uint16, address)
            );
        }
    }

    /// `kind` is verify-only here (bit 224 of its word, §2).
    function _vo(uint16 kind) private view returns (bool) {
        return _cfg(kind) >> 224 & 1 != 0;
    }

    /// accounts.md §1.9 `msig` row, a transaction authorization (the portable one: `UARegistryCoreLib._msig`): strictly increasing
    /// member indexes, stop at the threshold (a MemberSig after it fails, which keeps the registration bound sound),
    /// `member_digest = keccak256(ua ‖ ua_msg)`; native members sign `UAAuth` (CTR-UA-24, CTR-MTX-14), derived members
    /// sign `member_digest` under `member`. (The members come typed, TS-D12: no encoding to canonicalise.) Only an accepted
    /// slot counts (CTR-UA-37): a good signature of a slot that only is listed fails. An `msig` member is this same check one level
    /// down, under `member` over `md`, by `_memberOk`.
    function _msig(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory d, MemberSig[] memory sigs)
        private
        view
        returns (bool)
    {
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purposeTag, digest));
        (uint256 threshold, uint256 count) = (UAStore.u16(d, 0), UAStore.u16(d, 2));
        // CTR-UA-37: one slot, never `pop`; CTR-UA-44: a disabled slot signs nothing (its trailer word, or every slot)
        uint256 accepted = _s.accepted[ua] & UAStore.enabledOf(d);
        uint256 acc;
        uint256 next; // lowest index the next MemberSig may use
        for (uint256 i; i < sigs.length; ++i) {
            MemberSig memory s = sigs[i];
            if (acc >= threshold || s.index < next || s.index >= count || accepted >> s.index & 1 == 0) return false;
            next = uint256(s.index) + 1;
            if (!_memberOk(d, md, s)) return false;
            acc += UAStore.u16(d, 4 + 36 * uint256(s.index) + 34);
        }
        return acc >= threshold;
    }

    /// The signature `s` of member `s.index` of the structure `d` over `md` under `member`, without key data (native:
    /// none; registered: `_derived` reads the member's record, CTR-UA-33). An `msig` member: `s.members` by `_msig` over its own
    /// record, or its generation's; `lift` leaves them no list, so a level below has no signature and fails its threshold.
    function _memberOk(bytes memory d, bytes32 md, MemberSig memory s) private view returns (bool) {
        uint256 o = 4 + 36 * uint256(s.index);
        (uint16 kind, bytes32 id) = (uint16(UAStore.u16(d, o)), bytes32(UAStore.word(d, o + 2)));
        if (kind == UAKinds.MSIG) {
            if (s.sig.length != 0) return false;
            MemberSig[] memory inner = UAStore.lift(s.members);
            if (_s.records[id].kind == 0) {
                (address h,) = _holderKind(id); // §4: forwarded whole to its holder (R6), directly
                return UAStore.via(h, id, UAKinds.PURPOSE_MEMBER, md, UASig("", "", inner));
            }
            return _msig(id, UAKinds.PURPOSE_MEMBER, md, UAStore.msig(id, _s.records[id].keyPtr), inner);
        }
        if (s.members.length != 0) return false;
        if (!UAKinds.isNative(kind)) return _derived(id, kind, UAKinds.PURPOSE_MEMBER, md, "", s.sig);
        return _native(id, UAKinds.PURPOSE_MEMBER, md, s.sig);
    }

    /// CTR-UA-24 as amended by owner ruling D1 (2026-10-30, "an EOA must really sign, no delegation"): by code at call
    /// time. Empty or the 23-byte EIP-7702 designator (an EOA) ⇒ ECDSA by its own key only, never ERC-1271 through the
    /// delegate; other code ⇒ ERC-1271 only. Always over `uaAuthDigest`. OZ `tryRecover` refuses high s and a recovered
    /// `address(0)`, so neither id 0 nor a garbage signature ever matches.
    function _native(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory sig) private view returns (bool) {
        return UAStore.byCode(
            address(uint160(uint256(ua))), uaAuthDigest(ua, purposeTag, digest), sig, _SMART_KEY_CLONE_CODEHASH
        );
    }

    function _verifierCall(uint256 cfg, bytes4 selector, bytes memory keyData, bytes32 message, bytes memory sig)
        private
        view
        returns (bool)
    {
        return UAStore.capped(
            address(uint160(cfg)), UAStore._capOf(cfg), abi.encodeWithSelector(selector, keyData, message, sig), 1, true
        );
    }

    // ----- kind table -----

    function _cfg(uint16 kind) private view returns (uint256) {
        if (kind == UAKinds.MSIG) return _CFG_MSIG;
        uint256 s = _slot(kind);
        if (s > 20) return s == 21 ? _CFG21 : 0;
        if (s > 18) return s == 19 ? _CFG19 : _CFG20;
        if (s > 13) return s < 16 ? (s == 14 ? _CFG14 : _CFG15) : (s < 18 ? (s == 16 ? _CFG16 : _CFG17) : _CFG18);
        if (s > 11) return s == 12 ? _CFG12 : _CFG13;
        if (s > 7) return s < 10 ? (s == 8 ? _CFG8 : _CFG9) : (s == 10 ? _CFG10 : _CFG11);
        if (s < 4) return s < 2 ? (s == 0 ? _CFG0 : _CFG1) : (s == 2 ? _CFG2 : _CFG3);
        return s < 6 ? (s == 4 ? _CFG4 : _CFG5) : (s == 6 ? _CFG6 : _CFG7);
    }

    /// Kind-table slot: 0x0100–0x0107 → 0–7, 0x0110–0x0113 → 8–11, 0x0134 → 12, 0x0141 → 13, 0x0130–0x0133 → 14–17,
    /// 0x0142 (the PQZ key verifier) → 18, 0x0108 → 19, 0x0135 → 20, 0x0121 → 21, anything else 22 (not in this code's table). Slot 12 was
    /// `zether-bn254`'s (legacy/ua6/); 0x0134 and 0x0135 are mapped before `UAStore.isPq`, whose range now holds them
    /// (CTR-UA-39 / -40 Q3: `kind − 0x0130 + 14` would give them 18 and 19, the PQZ key verifier's and `secp256k1`'s slots).
    function _slot(uint16 kind) private pure returns (uint256) {
        if (kind >= 0x0100 && kind <= 0x0107) return kind - 0x0100;
        if (kind >= UAKinds.MUSIG2_SECP256K1 && kind <= UAKinds.FROST_BN254) return kind - 0x0110 + 8;
        if (kind == UAKinds.ZETHER_BLS12381) return 13;
        if (kind == UAKinds.MLDSA87) return 12;
        if (kind == UAKinds.FNDSA1024) return 20;
        if (UAStore.isPq(kind)) return kind - 0x0130 + 14;
        if (kind == UAKinds.PQZ_MLWE) return 18;
        if (kind == UAKinds.SECP256K1) return 19;
        if (kind == UAKinds.BLS12381_MULTI) return 21;
        return 22;
    }

    /// The line's rule (§1.8 "Generations"; spec 2026-11-19-registry-verify-only-kinds §2, §11.1): a single-key kind whose keyHash
    /// group a kind of any predecessor enables stays there (`kindHome(j) != 0` of the predecessor, which answers for the line).
    function _groupInPredecessor(address pred, uint16 kind) private view returns (bool) {
        bytes32 g = keccak256(bytes(UAKinds.groupName(kind)));
        for (uint16 j = 0x0100; j <= UAKinds.PQZ_MLWE; ++j) {
            if (
                j != UAKinds.MSIG && (UAKinds.isDerived(j) || j == UAKinds.PQZ_MLWE)
                    && keccak256(bytes(UAKinds.groupName(j))) == g && IUARegistry(pred).kindHome(j) != address(0)
            ) return true;
        }
        return false;
    }

    /// Spec 2026-11-19-registry-verify-only-kinds §2 (CTR-UA-58; N4, M6, R3, P1, N8, P11): `c` against the line below `pred`.
    /// `0x0142` (§11.2): never verify-only, re-enabled in full, exempt from the group rule. Every other kind of the table is
    /// verify-only exactly when a predecessor enables it (`kindHome`); unflagged, key form 0 and its group new on the line;
    /// flagged (never `bls12381-multi`, F16), a verifier whose probe found a precompile (`PRECOMPILE() ≠ 0`) and whose
    /// `KEY_FORM()` is the word's, key form 1 only where the **home's** verifier has none (an ML-DSA cache can exist there).
    /// (`msig` is never in `kinds_`: its slot is outside the table.)
    function _kindRule(address pred, KindConfig memory c) private view returns (bool) {
        if (c.kind == UAKinds.PQZ_MLWE) return !c.verifyOnly && c.keyForm == 0;
        address home = pred == address(0) ? address(0) : IUARegistry(pred).kindHome(c.kind);
        if (c.verifyOnly != (home != address(0))) return false;
        if (!c.verifyOnly) return c.keyForm == 0 && (pred == address(0) || !_groupInPredecessor(pred, c.kind));
        if (c.kind == UAKinds.BLS12381_MULTI) return false;
        (bool ok, uint256 pc) = _getter(c.verifier, IUAVerifyOnlyVerifier.PRECOMPILE.selector);
        (bool ok2, uint256 form) = _getter(c.verifier, IUAVerifyOnlyVerifier.KEY_FORM.selector);
        if (!ok || pc == 0 || !ok2 || form != c.keyForm) return false;
        return
            c.keyForm == 0
                || (PqUA.mldsaParts(c.kind) != 0 && UAStore.noPrecompile(IUARegistry(home).verifierOf(c.kind)));
    }

    /// M10 (d): `UARegistryRegLib.voDebitFits` per verify-only kind (its home's cap, the hops to it), else `UAConfig(kind)`.
    function _voDebit(address pred, KindConfig[] memory kinds_, uint8 g, uint64 cap) private view {
        for (uint256 i; i < kinds_.length; ++i) {
            KindConfig memory c = kinds_[i];
            if (!c.verifyOnly) continue;
            IUARegistry h = IUARegistry(IUARegistry(pred).kindHome(c.kind));
            if (!UARegistryRegLib.voDebitFits(c.kind, c.cap, h.verifyCap(c.kind), g - h.generation(), cap)) {
                revert UAConfig(c.kind);
            }
        }
    }

    /// A one-word getter `sel` of `v`: false unless it answers exactly 32 bytes.
    function _getter(address v, bytes4 sel) private view returns (bool ok, uint256 w) {
        bytes memory r;
        (ok, r) = v.staticcall(abi.encodeWithSelector(sel));
        ok = ok && r.length == 32;
        if (ok) w = uint256(bytes32(r));
    }

    /// §11.1 (owner R10, R11): the generation this registry is over the line ending in `p`, the walk of `p`'s predecessors down to
    /// generation 1, at most `MAX_GENERATION` steps: each a contract of this chain and profile, its generation one below the
    /// previous one, the last a generation 1 without predecessor; each probed for the views a successor reads (a predecessor's
    /// read then fails only by gas, F11). Anything else: `UAConfig(0)`. `p.generation()` at least `MAX_GENERATION`: no generation
    /// 17 (R11).
    function _line(address p, bytes32 uid, bool hedera) private view returns (uint8 g) {
        uint256 expect = MAX_GENERATION;
        for (uint256 i; i < MAX_GENERATION; ++i) {
            if (!SigCheck.isContract(p)) revert UAConfig(0); // D5 (owner ruling 2026-10-30): real code
            IUARegistry r = IUARegistry(p);
            uint8 pg = r.generation();
            if (i == 0) expect = pg;
            if (pg != expect || pg == 0 || pg >= MAX_GENERATION || r.chainUid() != uid || r.hederaNative() != hedera) {
                revert UAConfig(0);
            }
            if (i == 0) g = pg + 1;
            _probe(r);
            p = r.predecessor();
            if (pg == 1) {
                if (p != address(0)) revert UAConfig(0);
                return g;
            }
            --expect;
        }
        revert UAConfig(0);
    }

    /// The views a successor reads on a predecessor (§11.3, W3): each answers, or `UAConfig(0)`. Review n3: the UA-8 views
    /// (`checkedOf`); the `InnerSig` ABI of its hand-offs (`memberSigHashOf`); CTR-UA-44's current structure (`msigStateOf`).
    function _probe(IUARegistry p) private view {
        // §11.3 (W3): the line's views
        try p.holderOf(0) {}
        catch {
            revert UAConfig(0);
        }
        try p.kindHome(0) {}
        catch {
            revert UAConfig(0);
        }
        try p.verifierOf(0) {}
        catch {
            revert UAConfig(0);
        }
        try p.verifyOnly(0) {}
        catch {
            revert UAConfig(0);
        }
        try p.pqzHomeOf(0) {}
        catch {
            revert UAConfig(0);
        }
        try p.txGasCap() {}
        catch {
            revert UAConfig(0);
        }
        try p.expandedKeyOf(0) {}
        catch {
            revert UAConfig(0);
        }
        try p.checkedOf(0) {}
        catch {
            revert UAConfig(0);
        }
        try p.memberSigHashOf(0, 0) {}
        catch {
            revert UAConfig(0);
        }
        try p.msigStateOf(0) {}
        catch {
            revert UAConfig(0);
        }
    }

    /// The EIP-712 version (§11.1): the generation's decimal number, "1" for generation 1; "0" for a predecessor that does not
    /// answer a generation in `[1, MAX_GENERATION)` (the constructor's walk then refuses it).
    function _versionOf(address p) private view returns (string memory) {
        if (p == address(0)) return "1";
        (bool ok, uint256 g) = _getter(p, IUARegistry.generation.selector);
        return ok && g != 0 && g < MAX_GENERATION ? Strings.toString(g + 1) : "0";
    }

    // ------------------------------------------------------------------ rescue (CTR-GOV-26)

    /// @notice CTR-GOV-26 (owner 2026-11-12): anyone; the registry holds nothing by design (no owner, no setter, CTR-UA-15),
    ///         so the whole balance of `asset` (`address(0)`: the native coin) goes to `RescueLib.SCAAS_DEV_RESCUE`,
    ///         `IRescuable.Rescued`.
    function rescue(address asset) external {
        RescueLib.all(asset, RescueLib.SCAAS_DEV_RESCUE);
    }
}
