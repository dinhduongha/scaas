// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {IUAKindVerifier} from "./IUAVerifier.sol";
import {UAKinds} from "./UAKinds.sol";
import {UAStore} from "./UAStore.sol";
import {UARegistryLib} from "./UARegistryLib.sol";
import {UAMldsaVerifier} from "./MlDsa.sol";

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
///         caller — with `cacheExpandedKey(kind, pk, part)`: one part per transaction (ML-DSA-44 one, ML-DSA-65 two),
///         each `UAMldsaVerifier.expandedKeyPart(pk, part)` stored once with SSTORE2 under its id (`uaOf(kind, pk)`,
///         before or after `register`); once every part is there, PoP and verify go through `verifyCached` with the part
///         pointers. Refused where the verifier uses a precompile (a cached Solidity path would exceed its cap).
///         KEM key (CTR-UA-32): the single PQ kinds only; an `msig` holds none (plan T66a), `UAKemHolder` at `register` and `setKemKey`.
///         PQZ key (UA-6, CTR-UA-30, CTR-PQZ-12/13): an attribute of a holder — `mldsa44`, `mldsa65`, `fndsa512`, `mldsa87`, `fndsa1024`, or an
///         `msig` whose members of kinds outside 0x0130–0x0135 weigh less than its threshold (PQ-eligible) — given in
///         its `register` (`attrs.pqzKey`, `attrs.pqzPopHash`) with the optional `R_REG` proof over the portable digest
///         (UA-8 P1, P8), checked by `UAPqzVerifier` in slot 0x0142; stored with SSTORE2 (`recordOf`, `pqzKeyOf`),
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
///         typed-signing R2 (owner 2026-11-01): `cacheExpandedKey`, every `register*`, `storePqzPop`, `setPqzKey` and
///         `setKemKey` run in `UARegistryLib` by DELEGATECALL (`_lib`), on this contract's storage (`UAStore.Layout`); the
///         views and `requireAuthorized` stay here. The library's address is in this contract's code, so it is part of the
///         registry's CREATE2 address.
///
///         T66b R-1 (spec 2026-11-09-t66b-library-organisation.md §5): the `pure` views whose code the library holds
///         (`uaOf`, `keyHashOf` and five digests) run there too (`_libPure`), one copy of their code in the pair.
///
///         UA-7 O1 (plan T66a): `requirePortable`, the portable check view a `PqChat` record takes, runs `UARegistryLib`'s
///         portable path by DELEGATECALL inside the view (`_libView`; the library entry writes nothing).
///
///         CTR-UA-37 (owner 2026-11-02): listing in an `msig` is no consent. A member accepts its slot (`acceptMembership`, a portable
///         `UAMembership`, in `UARegistryLib`); `memberAccepted` reads it, the slots of the `pop` are accepted at registration, and
///         every verification but that `pop` counts accepted slots only: one read of one word, here and in `UARegistryLib._msig`.
///
///         Open in UA-2a: HIP-632 (`hedera-native` members' 64-byte ed25519 signatures) needs a non-static CALL, which a
///         `view` `requireAuthorized` cannot make; such members verify as ECDSA/1271 only.
///         UNAUDITED.
contract UARegistry is IUARegistry, SaltedEIP712 {
    struct KindConfig {
        uint16 kind;
        address verifier;
        uint64 cap;
    }

    /// @notice A constructor argument is refused (kind outside this code's table, duplicate, verifier without code, cap
    ///         0 or above the budget, a keyHash group the predecessor enables, a predecessor of another chain/profile or
    ///         without the UA-8 views), or `UARegistryLib` is not deployed.
    error UAConfig(uint16 kind);

    /// @notice `UARegistryLib` writes SSTORE2; solc lists only the errors a contract uses or declares, so this line keeps
    ///         it on the registry's ABI.
    error SSTORE2WriteFailed();

    uint8 public immutable generation;
    address public immutable predecessor;
    bool public immutable hederaNative;
    uint64 public immutable verifyBudget;
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
    uint256 private immutable _CFG_MSIG; // 0x0120: address(this) | verifyBudget << 160

    UAStore.Layout private _s; // slot 0: the mappings, their slots and their comments in `UAStore.Layout`

    /// @param chainUid_ the chain's genesis hash (≠ 0, `SaltedEIP712.ChainUidZero`).
    /// @param predecessor_ 0 for generation 1, else the chain's gen-1 registry.
    /// @param smartKeyAccountImpl_ the chain's `SmartKeyAccount` implementation (0 = none): its EIP-1167 clones get the
    ///        400 k ERC-1271 cap.
    /// @param msig_ enables the structure kind `msig`.
    /// @param kinds_ the enabled single-key, group and Zether kinds with their verifier and measured verify cap.
    constructor(
        bytes32 chainUid_,
        address predecessor_,
        bool hederaNative_,
        uint64 verifyBudget_,
        address smartKeyAccountImpl_,
        bool msig_,
        KindConfig[] memory kinds_
    ) SaltedEIP712("SCaaS UARegistry", predecessor_ == address(0) ? "1" : "2", chainUid_) {
        if (verifyBudget_ == 0 || (smartKeyAccountImpl_ != address(0) && !SigCheck.isContract(smartKeyAccountImpl_))) {
            revert UAConfig(0);
        }
        // `_lib`'s DELEGATECALL would "succeed" on an empty account, every write a silent no-op; the library has no way to
        // leave once it is there (no SELFDESTRUCT, `LinkClosure.test_libraryOpcodes`)
        if (address(UARegistryLib).code.length == 0) revert UAConfig(0);
        if (predecessor_ != address(0)) {
            IUARegistry p = IUARegistry(predecessor_);
            // D5 (owner ruling 2026-10-30): real code; a designator's delegate could change under gen 2
            if (
                !SigCheck.isContract(predecessor_) || p.generation() != 1 || p.chainUid() != chainUid_
                    || p.hederaNative() != hederaNative_
            ) {
                revert UAConfig(0);
            }
            // review n3: gen 1 speaks the UA-8 views gen 2 forwards to (`pqzKeyOf`, `registrationOf`, `checkedOf`)
            try p.checkedOf(0) {} catch { revert UAConfig(0); }
            // and the `InnerSig` ABI of its hand-offs: on an older gen 1 every one would read as a refused signature
            try p.memberSigHashOf(0, 0) {} catch { revert UAConfig(0); }
        }
        uint256[21] memory k;
        for (uint256 i; i < kinds_.length; ++i) {
            KindConfig memory c = kinds_[i];
            uint256 slot = _slot(c.kind);
            if (
                slot > 20 || k[slot] != 0 || !SigCheck.isContract(c.verifier) || c.cap == 0 || c.cap > verifyBudget_
                    || (predecessor_ != address(0) && _groupInPredecessor(predecessor_, c.kind))
            ) revert UAConfig(c.kind);
            k[slot] = uint256(uint160(c.verifier)) | uint256(c.cap) << 160;
        }
        (_CFG0, _CFG1, _CFG2, _CFG3) = (k[0], k[1], k[2], k[3]);
        (_CFG4, _CFG5, _CFG6, _CFG7) = (k[4], k[5], k[6], k[7]);
        (_CFG8, _CFG9, _CFG10, _CFG11) = (k[8], k[9], k[10], k[11]);
        (_CFG12, _CFG13) = (k[12], k[13]);
        (_CFG14, _CFG15, _CFG16, _CFG17, _CFG18) = (k[14], k[15], k[16], k[17], k[18]);
        (_CFG19, _CFG20) = (k[19], k[20]);
        _CFG_MSIG = msig_ ? uint256(uint160(address(this))) | uint256(verifyBudget_) << 160 : 0;

        generation = predecessor_ == address(0) ? 1 : 2;
        predecessor = predecessor_;
        hederaNative = hederaNative_;
        verifyBudget = verifyBudget_;
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

    function chainUid() external view returns (bytes32) {
        return CHAIN_UID;
    }

    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32 ua) {
        _libPure(UARegistryLib.uaOf.selector);
    }

    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32 h) {
        _libPure(UARegistryLib.keyHashOf.selector);
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
        _libPure(UARegistryLib.portableRecordDigest.selector);
    }

    function kemRecordHash(bytes32 ua, uint64 version, KemKey calldata kem) external pure returns (bytes32) {
        return UAKinds.kemRecordHash(ua, version, UAKinds.kemPk(kem));
    }

    function registrationDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash_, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32 d)
    {
        _libPure(UARegistryLib.registrationDigest.selector);
    }

    function kemRecordDigest(bytes32 ua, uint64 version, KemKey calldata kem) external pure returns (bytes32) {
        return UAKinds.kemRecordDigest(ua, version, UAKinds.kemPk(kem));
    }

    function pqzKeyDigest(bytes32 ua, bytes32 pqzKeyHash) external pure returns (bytes32) {
        return UAKinds.pqzKeyDigest(ua, pqzKeyHash);
    }

    function pqzKeyRecordDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 pqzPopHash) external pure returns (bytes32 d) {
        _libPure(UARegistryLib.pqzKeyRecordDigest.selector);
    }

    function pqzKeyVersionDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash) external pure returns (bytes32 d) {
        _libPure(UARegistryLib.pqzKeyVersionDigest.selector);
    }

    function pqzKeyVersionRecordDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32 d)
    {
        _libPure(UARegistryLib.pqzKeyVersionRecordDigest.selector);
    }

    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32) {
        return UAKinds.uaMessage(kind, purposeTag, digest);
    }

    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) public view returns (bytes32) {
        return UAKinds.uaAuthDigest(_domainSeparatorV4(), ua, purposeTag, digest);
    }

    /// `r.keyPtr ≠ 0` only for stored kinds; `pqzKey ≠ 0` only for PQZ holders with a key (proven or not): the current
    /// version's (group 3g). Gen 2: a gen-1 record with gen 1's key, or a host's own current (ruling A6-I1).
    function recordOf(bytes32 ua) external view returns (Record memory r, address pqzKey) {
        r = _s.records[ua];
        if (r.kind == 0 && predecessor != address(0)) {
            (r, pqzKey) = IUARegistry(predecessor).recordOf(ua);
            if (!_pqzHost()) return (r, pqzKey);
        }
        (, pqzKey,,) = pqzKeyOf(ua);
    }

    // ----- UA-8 reads (gen 2 forwards a record it does not hold, UA8-D11) -----

    /// A record gen 1 holds (this registry is gen 2 and has none of its own). Gen 1 reads no storage here.
    function _elsewhere(bytes32 ua) private view returns (bool) {
        return predecessor != address(0) && _s.records[ua].kind == 0;
    }

    /// Ruling A6-I1: a UA's PQZ attachment (the versions from `setPqzKey`, the proofs, `proven`, the owner of a proven key,
    /// the `0x0142` list entry, `current`) lives in the oldest generation that enables 0x0142; the record stays where it
    /// was registered. This gen 2 is such a host: it answers `current` itself and reads each version from its own record
    /// when it holds one, else gen 1's (group 3g, host rules 2 and 3).
    function _pqzHost() private view returns (bool) {
        return predecessor != address(0) && uint160(_CFG18) != 0;
    }

    /// Version `v` of `ua`: this generation's record, else gen 1's for a gen-1 record (host rule 2).
    function _pqzAt(bytes32 ua, uint64 v) private view returns (address ptr, bytes32 pqzPopHash, bool proven) {
        UAStore.PqzKey memory k = _s.pqzKey[ua][v];
        if (k.ptr == address(0) && _elsewhere(ua)) return IUARegistry(predecessor).pqzKeyAt(ua, v);
        return (k.ptr, _s.pqzPopHash[ua][v], k.proven);
    }

    function registrationOf(bytes32 ua)
        external
        view
        returns (uint16 kind, bytes memory keyData, UAAttrs memory attrs, bytes memory pop, bytes memory pqzPop)
    {
        if (_elsewhere(ua)) {
            (kind, keyData, attrs, pop, pqzPop) = IUARegistry(predecessor).registrationOf(ua);
            // A5-c2 / A6-I1: gen 1's `register` key (version 0) proven here, its proof stored here
            if (attrs.pqzKey.length != 0 && pqzPop.length == 0 && !_s.pqzKey[ua][0].added) {
                pqzPop = SSTORE2.readChunks(_s.pqzPop[ua][0]);
            }
            return (kind, keyData, attrs, pop, pqzPop);
        }
        Record memory r = _s.records[ua];
        kind = r.kind;
        if (kind == 0) return (kind, keyData, attrs, pop, pqzPop);
        (keyData, pop) = UAStore.registration(ua, r.keyPtr);
        UAStore.KemCommit memory c = _s.kemCommit[ua];
        if (c.kemPkHash != 0) (attrs.kem.scheme, attrs.kemPkHash) = (c.scheme, c.kemPkHash); // the committed form
        else (attrs.kem,) = UAStore.kemAt(ua, 0); // the register KEM key is version 0
        UAStore.PqzKey memory k = _s.pqzKey[ua][0];
        if (k.added) return (kind, keyData, attrs, pop, pqzPop); // A4-c3: an added key is no `register` argument
        (attrs.pqzKey, attrs.pqzPopHash) = (SSTORE2.read(k.ptr), _s.pqzPopHash[ua][0]);
        pqzPop = SSTORE2.readChunks(_s.pqzPop[ua][0]);
    }

    function popOf(bytes32 ua) external view returns (bytes memory pop) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).popOf(ua);
        if (_s.records[ua].kind == 0) return pop;
        (, pop) = abi.decode(SSTORE2.readChunks(_s.reg[ua]), (bytes, bytes));
    }

    function msigOf(bytes32 ua) external view returns (MsigStructure memory s) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).msigOf(ua);
        if (_s.records[ua].kind != UAKinds.MSIG) return s;
        bytes memory d = UAStore.keyRest(ua);
        uint256 n = UAStore.u16(d, 2);
        s.threshold = uint16(UAStore.u16(d, 0));
        s.members = new MsigMember[](n);
        for (uint256 i; i < n; ++i) {
            uint256 o = 4 + 36 * i;
            s.members[i] = MsigMember(uint16(UAStore.u16(d, o)), bytes32(UAStore.word(d, o + 2)), uint16(UAStore.u16(d, o + 34)));
        }
    }

    function memberAccepted(bytes32 ua, uint256 index) external view returns (bool) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).memberAccepted(ua, index);
        return _s.accepted[ua] >> index & 1 != 0;
    }

    function memberSigHashOf(bytes32 ua, uint256 index) external view returns (bytes32) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).memberSigHashOf(ua, index);
        return _s.memberSigHash[ua][index];
    }

    function popSlotsOf(bytes32 ua) external view returns (uint16[] memory index, bytes32[] memory hash) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).popSlotsOf(ua);
        uint256 bits = _s.popSlots[ua];
        uint256 n;
        for (uint256 b = bits; b != 0; b &= b - 1) ++n;
        (index, hash) = (new uint16[](n), new bytes32[](n));
        n = 0;
        for (uint256 i; bits >> i != 0; ++i) {
            if (bits >> i & 1 == 0) continue;
            (index[n], hash[n]) = (uint16(i), _s.memberSigHash[ua][i]);
            ++n;
        }
    }

    function smartKeyCloneHash() external view returns (bytes32) {
        return _SMART_KEY_CLONE_CODEHASH;
    }

    /// TS-D13: the typed keys of `webauthn-p256` / MuSig2 / FROST records (empty for any other id).
    function webAuthnKeyOf(bytes32 ua) external view returns (WebAuthnKey memory k) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).webAuthnKeyOf(ua);
        if (_s.records[ua].kind != UAKinds.WEBAUTHN_P256) return k;
        bytes memory d = UAStore.keyRest(ua);
        (k.x, k.y, k.rpIdHash) = (bytes32(UAStore.word(d, 0)), bytes32(UAStore.word(d, 32)), bytes32(UAStore.word(d, 64)));
    }

    function muSig2KeyOf(bytes32 ua) external view returns (MuSig2Key memory k) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).muSig2KeyOf(ua);
        Record memory r = _s.records[ua];
        if (r.kind != UAKinds.MUSIG2_SECP256K1 && r.kind != UAKinds.MUSIG2_BN254) return k;
        (uint256 size, bytes memory d) = (UAStore.vkLength(r.kind), UAStore.keyRest(ua)); // u16 n ‖ n × key
        k.aggKey = SSTORE2.read(r.keyPtr);
        k.memberKeys = new bytes[](UAStore.u16(d, 0));
        for (uint256 i; i < k.memberKeys.length; ++i) {
            k.memberKeys[i] = UAStore.cut(d, 2 + i * size, size);
        }
    }

    function frostKeyOf(bytes32 ua) external view returns (FrostKey memory k) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).frostKeyOf(ua);
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
        if (_s.pqzKey[ua][version].ptr == address(0) && _elsewhere(ua)) return IUARegistry(predecessor).pqzPopOf(ua, version);
        return SSTORE2.readChunks(_s.pqzPop[ua][version]);
    }

    function pqzKeySigOf(bytes32 ua, uint64 version) external view returns (bytes memory) {
        // gen 2 proving gen 1's `setPqzKey` key keeps no copy of the signature: gen 1 has it
        if (_s.pqzKeySig[ua][version].length == 0 && _elsewhere(ua)) {
            return IUARegistry(predecessor).pqzKeySigOf(ua, version);
        }
        return SSTORE2.readChunks(_s.pqzKeySig[ua][version]);
    }

    /// Group 3g (KV-3): one current per UA and registry generation; a gen 2 that is no PQZ host forwards a gen-1 record.
    function pqzKeyOf(bytes32 ua) public view returns (uint64 version, address ptr, bytes32 pqzPopHash, bool proven) {
        if (_elsewhere(ua) && !_pqzHost()) return IUARegistry(predecessor).pqzKeyOf(ua);
        version = _s.pqzVersions[ua].current;
        (ptr, pqzPopHash, proven) = _pqzAt(ua, version);
    }

    function pqzKeyAt(bytes32 ua, uint64 version) external view returns (address ptr, bytes32 pqzPopHash, bool proven) {
        return _pqzAt(ua, version);
    }

    function pqzKeyLatest(bytes32 ua) external view returns (uint64 latest) {
        latest = _s.pqzVersions[ua].latest;
        if (_elsewhere(ua)) {
            uint64 g = IUARegistry(predecessor).pqzKeyLatest(ua);
            if (g > latest) latest = g;
        }
    }

    function pqzKeyUsed(bytes32 ua, bytes32 pqzKeyHash) external view returns (bool) {
        return _s.pqzKeyUsed[ua][pqzKeyHash] || (_elsewhere(ua) && IUARegistry(predecessor).pqzKeyUsed(ua, pqzKeyHash));
    }

    function checkedOf(bytes32 ua) external view returns (uint8 pop, uint8 pqzPop, uint8 kem) {
        bool proven;
        if (_elsewhere(ua)) {
            (pop, pqzPop, kem) = IUARegistry(predecessor).checkedOf(ua);
            if (!_pqzHost()) return (pop, pqzPop, kem);
            (,,, proven) = pqzKeyOf(ua); // A6-I1: the host's current
            return (pop, UAStore.checked(proven), kem);
        }
        if (_s.records[ua].kind == 0) return (pop, pqzPop, kem);
        (,,, proven) = pqzKeyOf(ua);
        return (UAKinds.CHECKED_CHAIN, UAStore.checked(proven), UAStore.checked(_hasKem(ua)));
    }

    function kemKeyOf(bytes32 ua) external view returns (uint64 version, KemKey memory kem, bytes memory sig) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).kemKeyOf(ua);
        version = _s.kemMax[ua];
        (kem, sig) = UAStore.kemAt(ua, version);
    }

    /// A KEM key stored here: the `register` key (version 0) or a `setKemKey` one (`_kemMax` ≥ 1).
    function _hasKem(bytes32 ua) private view returns (bool) {
        return _s.kemMax[ua] != 0 || _s.kem[ua][0].length != 0;
    }

    function kemKeyAt(bytes32 ua, uint64 version) external view returns (KemKey memory kem, bytes memory sig) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).kemKeyAt(ua, version);
        return UAStore.kemAt(ua, version);
    }

    /// The stored key of a stored kind (MuSig2 `Q`, FROST `Y`, Zether `Y`, PQ `pk`), empty for every other id.
    function keyOf(bytes32 ua) external view returns (bytes memory) {
        Record memory r = _s.records[ua];
        if (r.kind == 0 && predecessor != address(0)) return IUARegistry(predecessor).keyOf(ua);
        return SSTORE2.read(r.keyPtr);
    }

    // ----- the per-kind list (IUARegistry.uaCount) -----

    /// A kind this generation does not enable belongs to the predecessor's list; a kind both enable (msig) has one
    /// list per generation.
    function _listedHere(uint16 kind) private view returns (bool) {
        return predecessor == address(0) || uint160(_cfg(kind)) != 0;
    }

    function uaCount(uint16 kind) public view returns (uint256) {
        if (!_listedHere(kind)) return IUARegistry(predecessor).uaCount(kind);
        return _s.uaCount[kind];
    }

    function uaAt(uint16 kind, uint256 i) external view returns (bytes32) {
        if (!_listedHere(kind)) return IUARegistry(predecessor).uaAt(kind, i);
        if (i >= _s.uaCount[kind]) revert UAIndex(kind, i);
        return _s.uaAt[kind][i];
    }

    function uaPage(uint16 kind, uint256 start, uint256 n) external view returns (bytes32[] memory page) {
        if (!_listedHere(kind)) return IUARegistry(predecessor).uaPage(kind, start, n);
        uint256 count = _s.uaCount[kind];
        if (start >= count) return page;
        if (n > count - start) n = count - start;
        page = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            page[i] = _s.uaAt[kind][start + i];
        }
    }

    function uaIndex(bytes32 ua) external view returns (uint256) {
        Record memory r = _s.records[ua];
        if (r.kind == 0 && predecessor != address(0)) return IUARegistry(predecessor).uaIndex(ua);
        if (r.kind == 0) revert UANotIndexed(ua);
        return r.index;
    }

    function kindOf(bytes32 ua) public view returns (uint16 kind) {
        kind = _s.records[ua].kind;
        if (kind == 0 && predecessor != address(0)) kind = IUARegistry(predecessor).kindOf(ua);
    }

    function isRegistered(bytes32 ua) external view returns (bool) {
        return kindOf(ua) != 0;
    }

    function keyOwner(bytes32 keyHash) public view returns (bytes32 owner) {
        owner = _s.keyOwner[keyHash];
        if (owner == 0 && predecessor != address(0)) owner = IUARegistry(predecessor).keyOwner(keyHash);
    }

    /// The ML-DSA expanded-key parts stored for `ua` (0 = not yet; ML-DSA-44 uses the first only). This generation's
    /// cache only.
    function expandedKeyOf(bytes32 ua) external view returns (address[2] memory) {
        return _s.ekPtr[ua];
    }

    // ----- ML-DSA expanded-key cache, registration, the PQZ attachment, KEM records: in `UARegistryLib` -----

    /// Runs `UARegistryLib`'s entry `sel` by DELEGATECALL: this call's arguments as they came, then three words the
    /// library cannot read for itself, `_cfg(kind)`, `_cfg(0x0142)`, the clone codehash (`kind` is the kind the entry knows).
    /// They come from this contract's immutables only and sit past the caller's bytes; the library reads them from the end
    /// of its calldata. Its return data or revert data is this call's, byte for byte.
    function _lib(bytes4 sel, uint16 kind) private {
        address lib = address(UARegistryLib);
        (uint256 a, uint256 b, bytes32 c) = (_cfg(kind), _CFG18, _SMART_KEY_CLONE_CODEHASH);
        assembly {
            mstore(0, sel)
            calldatacopy(4, 4, sub(calldatasize(), 4))
            let e := calldatasize()
            mstore(e, a)
            mstore(add(e, 32), b)
            mstore(add(e, 64), c)
            let ok := delegatecall(gas(), lib, 0, add(e, 96), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if ok { return(0, returndatasize()) }
            revert(0, returndatasize())
        }
    }

    function cacheExpandedKey(uint16 kind, bytes calldata pk, uint256 part) external returns (bytes32 ua) {
        _lib(UARegistryLib.cacheExpandedKey.selector, kind);
    }

    function register(uint16 kind, bytes calldata keyData, UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua)
    {
        _lib(UARegistryLib.register.selector, kind);
    }

    function registerWebAuthn(WebAuthnKey calldata key, UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua)
    {
        _lib(UARegistryLib.registerWebAuthn.selector, UAKinds.WEBAUTHN_P256);
    }

    function registerMuSig2(uint16 kind, MuSig2Key calldata key, UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua)
    {
        _lib(UARegistryLib.registerMuSig2.selector, kind);
    }

    function registerFrost(uint16 kind, FrostKey calldata key, UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua)
    {
        _lib(UARegistryLib.registerFrost.selector, kind);
    }

    function registerMsig(MsigStructure calldata structure, UAAttrs calldata attrs, MemberSig[] calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua)
    {
        _lib(UARegistryLib.registerMsig.selector, UAKinds.MSIG);
    }

    function storePqzPop(bytes32 ua, uint64 version, bytes calldata pqzPop) external {
        _lib(UARegistryLib.storePqzPop.selector, 0);
    }

    function setPqzKey(bytes32 ua, uint64 version, bytes calldata pqzKey, bytes32 pqzPopHash, UASig calldata sig) external {
        _lib(UARegistryLib.setPqzKey.selector, _s.records[ua].kind);
    }

    function setKemKey(bytes32 ua, uint64 version, KemKey calldata kem, UASig calldata sig) external {
        _lib(UARegistryLib.setKemKey.selector, _s.records[ua].kind);
    }

    function acceptMembership(bytes32 ua, MemberSig calldata memberSig) external {
        _lib(UARegistryLib.acceptMembership.selector, 0);
    }

    /// UA-7 O1 (plan T66a): gen 2 forwards a record it does not hold (UA8-D11: gen 1's verdict, its revert as it is), else the
    /// library's check on this record.
    function requirePortable(bytes32 ua, bytes32 purposeTag, bytes32 typedDigest, UASig calldata auth) external view {
        if (_elsewhere(ua)) IUARegistry(predecessor).requirePortable(ua, purposeTag, typedDigest, auth);
        else _libView(UARegistryLib.requirePortable.selector, _s.records[ua].kind);
    }

    /// `_lib` inside a view (`requirePortable`): the library entry writes nothing, so it runs in a STATICCALL frame too. Solidity
    /// types no DELEGATECALL as `view`; the function pointer is cast.
    function _libView(bytes4 sel, uint16 kind) private view {
        function(bytes4, uint16) f = _lib;
        function(bytes4, uint16) view v;
        assembly {
            v := f
        }
        v(sel, kind);
    }

    /// T66b R-1 (spec 2026-11-09-t66b-library-organisation.md §5): a `pure` view whose code `UARegistryLib` holds runs there, one
    /// copy of it in the pair: this call's calldata under the library entry `sel` (the same ABI), none of `_lib`'s three words
    /// appended (a pure body reads no configuration); its return or revert data is this call's, byte for byte. Only where the
    /// view's own bytes exceed this stub (≈ 45–80 B); `uaAuthDigest` stays (it reads this contract's EIP-712 immutables).
    function _libRaw(bytes4 sel) private {
        address lib = address(UARegistryLib);
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
    function _libPure(bytes4 sel) private pure {
        function(bytes4) f = _libRaw;
        function(bytes4) pure v;
        assembly {
            v := f
        }
        v(sel);
    }

    // ----- requireAuthorized -----

    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, UASig calldata auth) external view {
        if (!_authorized(ua, purposeTag, digest, auth)) revert UAUnauthorized(ua);
    }

    /// TS-D12: native — `signature` only; `msig` — `members` only (the structure from the record); other derived ids —
    /// `keyData` + `signature`, no `members`.
    function _authorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, UASig calldata auth)
        private
        view
        returns (bool)
    {
        if (UAKinds.inNativeSpace(ua)) {
            return auth.keyData.length == 0 && auth.members.length == 0 && _native(ua, purposeTag, digest, auth.signature);
        }
        uint16 kind = _s.records[ua].kind;
        if (kind == 0) return UAStore.via(predecessor, ua, purposeTag, digest, auth);
        if (kind == UAKinds.MSIG) {
            return auth.keyData.length == 0 && auth.signature.length == 0
                && _msig(ua, purposeTag, digest, UAStore.keyRest(ua), auth.members);
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
        uint256 vl = UAStore.vkLength(kind);
        if (vl != 0 || purposeTag == UAKinds.PURPOSE_MEMBER) {
            if (keyData.length != 0) return false; // CTR-UA-17 / CTR-UA-33: auth carries only the signature
            if (uint160(cfg) != 0) {
                Record memory r = _s.records[id];
                if (r.kind != kind) return false;
                if (vl == 0) {
                    keyData = UAStore.keyRest(id);
                } else {
                    bytes memory ek = UAStore.expanded(id, kind);
                    if (ek.length != 0) {
                        bytes32 m = UAKinds.uaMessage(kind, purposeTag, digest);
                        return _verifierCall(cfg, UAMldsaVerifier.verifyCached.selector, ek, m, sig);
                    }
                    keyData = SSTORE2.read(r.keyPtr);
                }
            }
        } else if (UAKinds.uaOf(kind, keyData) != id) {
            return false;
        }
        if (uint160(cfg) == 0) {
            return UAStore.via(predecessor, id, purposeTag, digest, UASig(keyData, sig, new MemberSig[](0)));
        }
        return _verifierCall(
            cfg, IUAKindVerifier.verify.selector, keyData, UAKinds.uaMessage(kind, purposeTag, digest), sig
        );
    }

    /// accounts.md §1.9 `msig` row, a transaction authorization (the portable one: `UARegistryLib._msig`): strictly increasing
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
        uint256 accepted = _s.accepted[ua]; // CTR-UA-37: one slot, never `pop`
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
            if (_s.records[id].kind == 0) return UAStore.via(predecessor, id, UAKinds.PURPOSE_MEMBER, md, UASig("", "", inner));
            return _msig(id, UAKinds.PURPOSE_MEMBER, md, UAStore.keyRest(id), inner);
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
            address(uint160(cfg)), cfg >> 160, abi.encodeWithSelector(selector, keyData, message, sig), 1, true
        );
    }

    // ----- kind table -----

    function _cfg(uint16 kind) private view returns (uint256) {
        if (kind == UAKinds.MSIG) return _CFG_MSIG;
        uint256 s = _slot(kind);
        if (s > 20) return 0;
        if (s > 18) return s == 19 ? _CFG19 : _CFG20;
        if (s > 13) return s < 16 ? (s == 14 ? _CFG14 : _CFG15) : (s < 18 ? (s == 16 ? _CFG16 : _CFG17) : _CFG18);
        if (s > 11) return s == 12 ? _CFG12 : _CFG13;
        if (s > 7) return s < 10 ? (s == 8 ? _CFG8 : _CFG9) : (s == 10 ? _CFG10 : _CFG11);
        if (s < 4) return s < 2 ? (s == 0 ? _CFG0 : _CFG1) : (s == 2 ? _CFG2 : _CFG3);
        return s < 6 ? (s == 4 ? _CFG4 : _CFG5) : (s == 6 ? _CFG6 : _CFG7);
    }

    /// Kind-table slot: 0x0100–0x0107 → 0–7, 0x0110–0x0113 → 8–11, 0x0134 → 12, 0x0141 → 13, 0x0130–0x0133 → 14–17,
    /// 0x0142 (the PQZ key verifier) → 18, 0x0108 → 19, 0x0135 → 20, anything else 21 (not in this code's table). Slot 12 was
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
        return 21;
    }

    /// Gen-2 rule (§1.8 "Generations"): a single-key kind (or the PQZ key verifier 0x0142) whose keyHash group any
    /// kind of gen 1 enables stays in gen 1.
    function _groupInPredecessor(address pred, uint16 kind) private view returns (bool) {
        bytes32 g = keccak256(bytes(UAKinds.groupName(kind)));
        for (uint16 j = 0x0100; j <= UAKinds.PQZ_MLWE; ++j) {
            if (
                j != UAKinds.MSIG && (UAKinds.isDerived(j) || j == UAKinds.PQZ_MLWE)
                    && keccak256(bytes(UAKinds.groupName(j))) == g
                    && IUARegistry(pred).kindEnabled(j)
            ) return true;
        }
        return false;
    }

}
