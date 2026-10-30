// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {IUAKindVerifier, IUAPopVerifier} from "./IUAVerifier.sol";
import {UAKinds} from "./UAKinds.sol";
import {PqzSet} from "../pqz/PqzSet.sol";
import {UAMldsaVerifier} from "./MlDsa.sol";

/// @title UA registry, UA-2a/2c/3, P6c and UA-6 scope (accounts.md §1.8): the single-key kinds 0x0100–0x0108, the
///        group kinds 0x0110–0x0113 (MuSig2/FROST, stored), the structure `msig`, the Zether kind 0x0141
///        (stored), the PQ signing kinds 0x0130–0x0133 (stored), the PQZ key attribute (scheme 0x0142) of PQ signing
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
///         secp256k1, 64 on bn254) with SSTORE2 as `keyPtr`. `requireAuthorized` takes `auth = abi.encode(bytes keyData,
///         bytes sig)` with `keyData` empty (non-empty ⇒ `UAUnauthorized`) and verifies `sig` against `vk` read from the
///         record's `keyPtr`; an `msig` member of a stored kind is checked the same way through the member's own record.
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
///         PQZ key (UA-6, CTR-UA-30, CTR-PQZ-12/13): an attribute of a holder — `mldsa44`, `mldsa65`, `fndsa512`, or an
///         `msig` whose members of kinds outside 0x0130–0x0133 weigh less than its threshold (PQ-eligible) — given in
///         its `register` (`attrs.pqzKey`, `attrs.pqzPopHash`) with the optional `R_REG` proof over the portable digest
///         (UA-8 P1, P8), checked by `UAPqzVerifier` in slot 0x0142; stored with SSTORE2 (`recordOf`, `pqzKeyOf`),
///         immutable. Only a proven key (proof checked by that verifier) is one UA per key (`keyOwner(h)`) and appended
///         to the `0x0142` list (UA8-D8); a key without its proof, or where the slot is empty, is stored unproven; anyone
///         may add the proof later (`storePqzPop`), and PQZ tokens take proven keys only (`pqzKeyOf`, UA8-D9). A record
///         registered without a PQZ key may get one later, once, by the UA's signed portable record (`setPqzKey`,
///         ruling A1-I1), or replace a key this chain can never prove (another parameter set's length where slot 0x0142 has a
///         verifier; ruling R-cross-set). A PQ-eligible `msig` always registers with an m-of-n PoP (U5).
///
///         UA-8 (portable registrations, spec 2026-10-25-ua8-portable-registrations): the PoP has no chain context, so
///         anyone may copy a registration to any registry; every `register` field is stored (UA8-D7): `keyData` once
///         (the stored kinds' `keyPtr` prefix, the rest in the registration blob), `pop` and the initial KEM version in
///         the blob, `pqzPop` and each KEM record (`pk ‖ sig`) as their own blobs, each in `SSTORE2.writeChunks` pieces.
///         Later KEM records come by the UA's signed portable record (`setKemKey`: once per version, any order).
///
///         Gen 2 (`predecessor ≠ 0`) reads gen 1 for `UAAlreadyRegistered` / `UAKeyInUse` / `kindOf` / `keyOwner` /
///         `recordOf` and hands records it does not hold, and members whose kind it does not enable, to gen 1's
///         `requireAuthorized`. Its constructor refuses every single-key kind whose keyHash group gen 1 enables. A gen 2
///         that enables 0x0142 (so gen 1 does not) holds the PQZ attachment of gen-1 records — `setPqzKey`,
///         `storePqzPop`, `proven`, the owner and list entry of a proven key — and its PQZ reads prefer it (ruling A6-I1).
///
///         Open in UA-2a: HIP-632 (`hedera-native` members' 64-byte ed25519 signatures) needs a non-static CALL, which a
///         `view` `requireAuthorized` cannot make; such members verify as ECDSA/1271 only.
///         UNAUDITED — NOT FOR PRODUCTION FUNDS.
contract UARegistry is IUARegistry, SaltedEIP712 {
    struct KindConfig {
        uint16 kind;
        address verifier;
        uint64 cap;
    }

    struct MemberSig {
        uint16 index;
        bytes keyData;
        bytes sig;
    }

    /// @notice A constructor argument is refused (kind outside this code's table, duplicate, verifier without code, cap
    ///         0 or above the budget, a keyHash group the predecessor enables, a predecessor of another chain/profile or
    ///         without the UA-8 views).
    error UAConfig(uint16 kind);

    uint256 internal constant SMART_KEY_1271_GAS = 400_000;
    /// @notice EIP-7825 per-transaction gas cap, the bound of a PQZ `msig` holder (`_attrs`).
    uint256 internal constant TX_GAS_CAP = 1 << 24;
    /// @notice Registration bound for `msig` (register step 4): gas per member beyond its cap — MemberSig decoding,
    ///         `uaOf`, `uaMessage`, the call or the gen-1 hand-off, cold accounts (measured worst, cold under
    ///         `--isolate`: 19,987 for a member handed to gen 1), plus what the caller must hold for the largest cap
    ///         (400 k / 63 + 5 k): 31,336, rounded up. Also added in `_membersWorst`: `(held - 400 k) / 63` for the
    ///         largest held member cap above 400 k, and for each member gen 2 hands to gen 1 the hold gen 2 keeps
    ///         around that call (the member counts `cap + cap / 63 + SigCheck.GAS_MARGIN`; gen 1 holds again
    ///         inside). `UAGas.t.sol` `test_T_GAS_msigAtBudget` authorizes msigs
    ///         registered exactly at `verifyBudget` within `verifyBudget`. `test_T_GAS_msigPqAtBudget` covers PQ signatures
    ///         (8 x `slhdsa128s`, 7,856 B each, + 1 clone, exactly at the bound 11,930,873; least frame gas 11,873,766, 57 k
    ///         spare): no per-kind size term (review2 C4-2).
    uint256 internal constant MSIG_MEMBER_GAS = 35_000;
    /// `keccak256("")`: the hash of an empty proof, refused as a `pqzPopHash` (ruling A6-m).
    bytes32 internal constant EMPTY_PROOF_HASH = keccak256("");

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
    uint256 private immutable _CFG13; // 0x0141 zether-bls12381 (UA-3, stored; SIGNING since UA-6)
    uint256 private immutable _CFG14; // 0x0130 mldsa44 (P6c, stored, expanded-key cache)
    uint256 private immutable _CFG15; // 0x0131 mldsa65 (P6c, stored, expanded-key cache)
    uint256 private immutable _CFG16; // 0x0132 fndsa512 (P6c, stored)
    uint256 private immutable _CFG17; // 0x0133 slhdsa128s (P6c, stored)
    uint256 private immutable _CFG18; // 0x0142 the PQZ key verifier (`R_REG`, UA-6; not a kind)
    uint256 private immutable _CFG19; // 0x0108 secp256k1 (ECDSA, 2026-10-17)
    uint256 private immutable _CFG_MSIG; // 0x0120: address(this) | verifyBudget << 160

    mapping(bytes32 ua => Record) private _records;
    mapping(bytes32 keyHash => bytes32) private _keyOwner;
    /// UA-6 / UA-8: the PQZ key's SSTORE2 pointer (0 = none; written once) and, in the same slot, whether the
    /// slot-0x0142 verifier checked its proof (UA8-D8, D9; `pqzKeyOf` costs a PQZ token's `_keyPtr` two SLOADs) and
    /// whether `setPqzKey` added it (ruling A1-I1: its `R_REG` message, and `registrationOf` leaves it out, A4-c3).
    struct PqzKey {
        address ptr;
        bool proven;
        bool added;
    }

    mapping(bytes32 ua => PqzKey) private _pqzKey;
    mapping(bytes32 ua => address[2]) private _ekPtr; // ML-DSA expanded-key parts (SSTORE2), written once each
    mapping(uint16 kind => uint256) private _uaCount; // per-kind list length (single-key kinds)
    mapping(uint16 kind => mapping(uint256 i => bytes32 ua)) private _uaAt;

    /// The registration blob (UA8-D7): `abi.encode(bytes keyRest, bytes pop, uint64 kemVersion)`, `keyRest` = the key
    /// data after the stored kinds' `keyPtr` prefix (all of it for the other kinds), `kemVersion` the initial KEM
    /// version (0 = none; ruling C2). `keyData` = `SSTORE2.read(keyPtr) ‖ keyRest`: stored once.
    mapping(bytes32 ua => address[]) private _reg;
    mapping(bytes32 ua => bytes32) private _pqzPopHash; // the PQZ key's proof hash (`attrs.pqzPopHash`)
    mapping(bytes32 ua => address[]) private _pqzPop; // the R_REG proof bytes, written once
    mapping(bytes32 ua => address[]) private _pqzKeySig; // `setPqzKey`'s signature, written once
    mapping(bytes32 ua => mapping(uint64 version => address[])) private _kem; // `pk ‖ sig` (initial record: `sig` = "")
    mapping(bytes32 ua => uint64) private _kemMax; // the highest stored KEM version, 0 = none
    /// Ruling R-cross-set: the `register` PQZ key (pointer) and proof hash a `setPqzKey` replaced (a key of another
    /// set's length, never provable here), kept so `registrationOf` still returns the `register` arguments.
    mapping(bytes32 ua => address) private _regPqzKey;
    mapping(bytes32 ua => bytes32) private _regPqzPopHash;

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
        }
        uint256[20] memory k;
        for (uint256 i; i < kinds_.length; ++i) {
            KindConfig memory c = kinds_[i];
            uint256 slot = _slot(c.kind);
            if (
                slot > 19 || k[slot] != 0 || !SigCheck.isContract(c.verifier) || c.cap == 0 || c.cap > verifyBudget_
                    || (predecessor_ != address(0) && _groupInPredecessor(predecessor_, c.kind))
            ) revert UAConfig(c.kind);
            k[slot] = uint256(uint160(c.verifier)) | uint256(c.cap) << 160;
        }
        (_CFG0, _CFG1, _CFG2, _CFG3) = (k[0], k[1], k[2], k[3]);
        (_CFG4, _CFG5, _CFG6, _CFG7) = (k[4], k[5], k[6], k[7]);
        (_CFG8, _CFG9, _CFG10, _CFG11) = (k[8], k[9], k[10], k[11]);
        _CFG13 = k[13];
        (_CFG14, _CFG15, _CFG16, _CFG17, _CFG18) = (k[14], k[15], k[16], k[17], k[18]);
        _CFG19 = k[19];
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

    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.uaOf(kind, keyData);
    }

    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.keyHashOf(kind, keyData);
    }

    function portablePopDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 kemRecordHash) external pure returns (bytes32) {
        return UAKinds.portablePopDigest(ua, pqzKeyHash, kemRecordHash);
    }

    function registrationDigest(bytes32 portable, bytes32 pqzPopHash) external pure returns (bytes32) {
        return UAKinds.registrationDigest(portable, pqzPopHash);
    }

    function kemRecordDigest(bytes32 ua, uint64 version, bytes calldata kemPk) external pure returns (bytes32) {
        return UAKinds.kemRecordDigest(ua, version, kemPk);
    }

    function pqzKeyDigest(bytes32 ua, bytes32 pqzKeyHash) external pure returns (bytes32) {
        return UAKinds.pqzKeyDigest(ua, pqzKeyHash);
    }

    function pqzKeyRecordDigest(bytes32 keyDigest, bytes32 pqzPopHash) external pure returns (bytes32) {
        return UAKinds.pqzKeyRecordDigest(keyDigest, pqzPopHash);
    }

    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32) {
        return UAKinds.uaMessage(kind, purposeTag, digest);
    }

    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) public view returns (bytes32) {
        return UAKinds.uaAuthDigest(_domainSeparatorV4(), ua, purposeTag, digest);
    }

    /// `r.keyPtr ≠ 0` only for stored kinds; `pqzKey ≠ 0` only for PQZ holders with a key (proven or not). Gen 2: a
    /// gen-1 record with this generation's PQZ attachment, if any (ruling A6-I1).
    function recordOf(bytes32 ua) external view returns (Record memory r, address pqzKey) {
        r = _records[ua];
        pqzKey = _pqzKey[ua].ptr;
        if (r.kind == 0 && predecessor != address(0)) {
            (Record memory g, address p) = IUARegistry(predecessor).recordOf(ua);
            return (g, pqzKey != address(0) ? pqzKey : p);
        }
    }

    // ----- UA-8 reads (gen 2 forwards a record it does not hold, UA8-D11) -----

    /// A record gen 1 holds (this registry is gen 2 and has none of its own). Gen 1 reads no storage here.
    function _elsewhere(bytes32 ua) private view returns (bool) {
        return predecessor != address(0) && _records[ua].kind == 0;
    }

    /// Ruling A6-I1: a UA's PQZ attachment (the key from `setPqzKey`, the proof, `proven`, the owner of a proven key, the
    /// `0x0142` list entry) lives in the oldest generation that enables 0x0142; the record stays where it was
    /// registered. The PQZ reads of a gen-1 record on gen 2 take gen 2's own attachment (its `_pqzKey` slot, written
    /// only by this generation) when there is one, else gen 1's.
    function _pqzElsewhere(bytes32 ua) private view returns (bool) {
        return _pqzKey[ua].ptr == address(0) && _elsewhere(ua);
    }

    function registrationOf(bytes32 ua)
        external
        view
        returns (uint16 kind, bytes memory keyData, UAAttrs memory attrs, bytes memory pop, bytes memory pqzPop)
    {
        if (_elsewhere(ua)) {
            (kind, keyData, attrs, pop, pqzPop) = IUARegistry(predecessor).registrationOf(ua);
            // A5-c2 / A6-I1: gen 1's key proven here, its proof stored here (not a key this gen 2 added in its place,
            // R-cross-set)
            if (attrs.pqzKey.length != 0 && pqzPop.length == 0 && !_pqzKey[ua].added) {
                pqzPop = SSTORE2.readChunks(_pqzPop[ua]);
            }
            return (kind, keyData, attrs, pop, pqzPop);
        }
        Record memory r = _records[ua];
        kind = r.kind;
        if (kind == 0) return (kind, keyData, attrs, pop, pqzPop);
        uint64 v;
        (keyData, pop, v) = _registration(ua, r.keyPtr);
        (attrs.kemPk,) = _kemAt(ua, v);
        attrs.kemVersion = v;
        PqzKey memory k = _pqzKey[ua];
        if (k.added) {
            // A4-c3: an added key is not a `register` argument; R-cross-set: the `register` key it replaced is (its
            // proof was never stored: this chain refuses it)
            (attrs.pqzKey, attrs.pqzPopHash) = (SSTORE2.read(_regPqzKey[ua]), _regPqzPopHash[ua]);
            return (kind, keyData, attrs, pop, pqzPop);
        }
        (attrs.pqzKey, attrs.pqzPopHash) = (SSTORE2.read(k.ptr), _pqzPopHash[ua]);
        pqzPop = SSTORE2.readChunks(_pqzPop[ua]);
    }

    /// The registration blob of a record held here: `keyData` (`keyPtr` prefix ‖ the rest), `pop`, the initial KEM
    /// version.
    function _registration(bytes32 ua, address keyPtr) private view returns (bytes memory keyData, bytes memory pop,
        uint64 v)
    {
        bytes memory rest;
        (rest, pop, v) = abi.decode(SSTORE2.readChunks(_reg[ua]), (bytes, bytes, uint64));
        keyData = bytes.concat(SSTORE2.read(keyPtr), rest);
    }

    function popOf(bytes32 ua) external view returns (bytes memory pop) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).popOf(ua);
        if (_records[ua].kind == 0) return pop;
        (, pop,) = abi.decode(SSTORE2.readChunks(_reg[ua]), (bytes, bytes, uint64));
    }

    function pqzPopOf(bytes32 ua) external view returns (bytes memory) {
        if (_pqzElsewhere(ua)) return IUARegistry(predecessor).pqzPopOf(ua);
        return SSTORE2.readChunks(_pqzPop[ua]);
    }

    function pqzKeySigOf(bytes32 ua) external view returns (bytes memory) {
        // gen 2 proving gen 1's `setPqzKey` key keeps no copy of the signature: gen 1 has it
        if (_pqzKeySig[ua].length == 0 && _elsewhere(ua)) return IUARegistry(predecessor).pqzKeySigOf(ua);
        return SSTORE2.readChunks(_pqzKeySig[ua]);
    }

    function pqzKeyOf(bytes32 ua) external view returns (address ptr, bytes32 pqzPopHash, bool proven) {
        PqzKey memory k = _pqzKey[ua];
        if (k.ptr == address(0) && _elsewhere(ua)) return IUARegistry(predecessor).pqzKeyOf(ua);
        return (k.ptr, _pqzPopHash[ua], k.proven);
    }

    function checkedOf(bytes32 ua) external view returns (uint8 pop, uint8 pqzPop, uint8 kem) {
        if (_elsewhere(ua)) {
            (pop, pqzPop, kem) = IUARegistry(predecessor).checkedOf(ua);
            if (_pqzKey[ua].proven) pqzPop = UAKinds.CHECKED_CHAIN; // A6-I1: proven here
            return (pop, pqzPop, kem);
        }
        if (_records[ua].kind == 0) return (pop, pqzPop, kem);
        return (UAKinds.CHECKED_CHAIN, _checked(_pqzKey[ua].proven), _checked(_kemMax[ua] != 0));
    }

    function kemKeyOf(bytes32 ua) external view returns (uint64 version, bytes memory pk, bytes memory sig) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).kemKeyOf(ua);
        version = _kemMax[ua];
        (pk, sig) = _kemAt(ua, version);
    }

    function kemKeyAt(bytes32 ua, uint64 version) external view returns (bytes memory pk, bytes memory sig) {
        if (_elsewhere(ua)) return IUARegistry(predecessor).kemKeyAt(ua, version);
        return _kemAt(ua, version);
    }

    /// The stored record `pk ‖ sig` of `(ua, version)` split at the 1,600-byte key; ("", "") when not stored.
    function _kemAt(bytes32 ua, uint64 version) private view returns (bytes memory pk, bytes memory sig) {
        bytes memory b = SSTORE2.readChunks(_kem[ua][version]);
        if (b.length == 0) return (pk, sig);
        uint256 n = UAKinds.KEM_PK_LENGTH;
        pk = new bytes(n);
        sig = new bytes(b.length - n);
        assembly ("memory-safe") {
            mcopy(add(pk, 32), add(b, 32), n)
            mcopy(add(sig, 32), add(add(b, 32), n), mload(sig))
        }
    }

    function _checked(bool chain) private pure returns (uint8) {
        return chain ? UAKinds.CHECKED_CHAIN : UAKinds.CHECKED_NONE;
    }

    /// The stored key of a stored kind (MuSig2 `Q`, FROST `Y`, Zether `Y`, PQ `pk`), empty for every other id.
    function keyOf(bytes32 ua) external view returns (bytes memory) {
        Record memory r = _records[ua];
        if (r.kind == 0 && predecessor != address(0)) return IUARegistry(predecessor).keyOf(ua);
        return SSTORE2.read(r.keyPtr);
    }

    // ----- the per-kind list (IUARegistry.uaCount) -----

    /// Appends `ua` to its kind's list (every kind, msig included) and returns its index.
    function _list(uint16 kind, bytes32 ua) private returns (uint40) {
        uint256 n = _uaCount[kind];
        _uaAt[kind][n] = ua;
        _uaCount[kind] = n + 1;
        return uint40(n);
    }

    /// A kind this generation does not enable belongs to the predecessor's list; a kind both enable (msig) has one
    /// list per generation.
    function _listedHere(uint16 kind) private view returns (bool) {
        return predecessor == address(0) || uint160(_cfg(kind)) != 0;
    }

    function uaCount(uint16 kind) public view returns (uint256) {
        if (!_listedHere(kind)) return IUARegistry(predecessor).uaCount(kind);
        return _uaCount[kind];
    }

    function uaAt(uint16 kind, uint256 i) external view returns (bytes32) {
        if (!_listedHere(kind)) return IUARegistry(predecessor).uaAt(kind, i);
        if (i >= _uaCount[kind]) revert UAIndex(kind, i);
        return _uaAt[kind][i];
    }

    function uaPage(uint16 kind, uint256 start, uint256 n) external view returns (bytes32[] memory page) {
        if (!_listedHere(kind)) return IUARegistry(predecessor).uaPage(kind, start, n);
        uint256 count = _uaCount[kind];
        if (start >= count) return page;
        if (n > count - start) n = count - start;
        page = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            page[i] = _uaAt[kind][start + i];
        }
    }

    function uaIndex(bytes32 ua) external view returns (uint256) {
        Record memory r = _records[ua];
        if (r.kind == 0 && predecessor != address(0)) return IUARegistry(predecessor).uaIndex(ua);
        if (r.kind == 0) revert UANotIndexed(ua);
        return r.index;
    }

    function kindOf(bytes32 ua) public view returns (uint16 kind) {
        kind = _records[ua].kind;
        if (kind == 0 && predecessor != address(0)) kind = IUARegistry(predecessor).kindOf(ua);
    }

    function isRegistered(bytes32 ua) external view returns (bool) {
        return kindOf(ua) != 0;
    }

    function keyOwner(bytes32 keyHash) public view returns (bytes32 owner) {
        owner = _keyOwner[keyHash];
        if (owner == 0 && predecessor != address(0)) owner = IUARegistry(predecessor).keyOwner(keyHash);
    }

    /// The ML-DSA expanded-key parts stored for `ua` (0 = not yet; ML-DSA-44 uses the first only). This generation's
    /// cache only.
    function expandedKeyOf(bytes32 ua) external view returns (address[2] memory) {
        return _ekPtr[ua];
    }

    // ----- ML-DSA expanded-key cache (P6c; owner 2026-10-12) -----

    /// Stores part `part` of the expanded key of `pk` under `uaOf(kind, pk)`, computed by the kind's verifier
    /// (`expandedKeyPart`) from the authenticated `pk` — never accepted from a caller (a caller-supplied expanded key
    /// allows universal forgery). Anyone may call it, before or after `register`; a part already stored is left as it
    /// is (a front-runner stored the same bytes). Each part is one transaction (ML-DSA-65 part 1: ≈ 13.4 M gas).
    /// Reverts `UAKeyCache(kind)` for a kind other than ML-DSA, a disabled kind, a part past the last, or a verifier
    /// that uses a precompile; `UAKeyData` for a key of the wrong length.
    function cacheExpandedKey(uint16 kind, bytes calldata pk, uint256 part) external returns (bytes32 ua) {
        address v = address(uint160(_cfg(kind)));
        if (
            (kind != UAKinds.MLDSA44 && kind != UAKinds.MLDSA65) || v == address(0) || part >= _ekParts(kind)
                || UAMldsaVerifier(v).PRECOMPILE() != address(0)
        ) revert UAKeyCache(kind);
        bytes memory d = pk;
        UAKinds.validateKeyData(kind, d, false);
        ua = UAKinds.uaOf(kind, d);
        if (_ekPtr[ua][part] != address(0)) return ua;
        address ptr = SSTORE2.write(UAMldsaVerifier(v).expandedKeyPart(pk, part));
        _ekPtr[ua][part] = ptr;
        emit UAKeyCached(ua, kind, part, ptr);
    }

    /// The part pointers of a complete ML-DSA cache (20 bytes each, in order), else empty.
    function _expanded(bytes32 ua, uint16 kind) private view returns (bytes memory) {
        if (kind != UAKinds.MLDSA44 && kind != UAKinds.MLDSA65) return "";
        address a = _ekPtr[ua][0];
        if (a == address(0)) return "";
        if (kind == UAKinds.MLDSA44) return abi.encodePacked(a);
        address b = _ekPtr[ua][1];
        return b == address(0) ? bytes("") : abi.encodePacked(a, b);
    }

    function _ekParts(uint16 kind) private pure returns (uint256) {
        return kind == UAKinds.MLDSA44 ? 1 : 2;
    }

    // ----- register (accounts.md §1.8 steps 1–8, UA-8) -----

    /// Registers `keyData` of `kind` with its attributes (accounts.md §1.8, UA-8 P2). `UAPoP` when the PoP fails, except
    /// one case: the `pop` of a PQ-eligible `msig` that does not decode as `MemberSig[]` reverts with empty data (the ABI
    /// decoder), not `UAPoP`.
    function register(uint16 kind, bytes calldata keyData, UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua)
    {
        bytes memory d;
        bytes32 kh;
        (ua, d, kh) = _identify(kind, keyData); // 1–4
        _consent(kind, d, ua, attrs, pop, pqzPop); // 5–7
        _record(ua, kind, keyData, kh, attrs, pop); // 8
        _registered(ua, kind, keyData, attrs, pop, pqzPop);
    }

    /// Steps 5–7: the attributes, the PoP over the registration digest (`UAPoP`), the PQZ key (and its proof).
    function _consent(
        uint16 kind,
        bytes memory d,
        bytes32 ua,
        UAAttrs calldata attrs,
        bytes calldata pop,
        bytes calldata pqzPop
    ) private {
        (bytes32 portable, bytes32 h) = _attrs(kind, d, ua, attrs, pqzPop); // 5
        bytes32 rd = UAKinds.registrationDigest(portable, attrs.pqzPopHash);
        if (!_sigOk(kind, d, ua, UAKinds.PURPOSE_POP_V2, rd, pop)) revert UAPoP(); // 6
        _pqzAttach(ua, attrs, pqzPop, h, portable); // 7
    }

    /// Step 8: the record, `keyPtr` (stored kinds), the keyHash (single keys), the kind's list, the initial KEM record
    /// (UA8-D4), the registration blob (UA8-D7).
    function _record(bytes32 ua, uint16 kind, bytes calldata keyData, bytes32 kh, UAAttrs calldata attrs,
        bytes calldata pop) private
    {
        uint256 vl = _vkLength(kind);
        address ptr = vl == 0 ? address(0) : SSTORE2.write(keyData[0:vl]);
        _records[ua] = Record(kind, uint40(block.timestamp), ptr, _list(kind, ua));
        if (kh != 0) _keyOwner[kh] = ua; // msig: none
        uint64 v = attrs.kemVersion;
        if (v != 0) {
            _kem[ua][v] = SSTORE2.writeChunks(attrs.kemPk);
            _kemMax[ua] = v;
        }
        _reg[ua] = SSTORE2.writeChunks(abi.encode(keyData[vl:], pop, v));
    }

    /// Step 8, the event: every argument and the three `checkedOf` values (read back from storage: `register`'s stack
    /// has no room for them).
    function _registered(bytes32 ua, uint16 kind, bytes calldata keyData, UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) private
    {
        (uint8 q, uint8 k) = (_checked(_pqzKey[ua].proven), _checked(_kemMax[ua] != 0));
        emit UARegistered(ua, kind, keyData, attrs, pop, pqzPop, UAKinds.CHECKED_CHAIN, q, k);
    }

    /// Steps 1–4: kind enabled, key data canonical, the id (not native-space, not registered here or in gen 1), the
    /// keyHash (single keys) or the members (msig).
    function _identify(uint16 kind, bytes calldata keyData)
        private
        view
        returns (bytes32 ua, bytes memory d, bytes32 kh)
    {
        if (uint160(_cfg(kind)) == 0) revert UAKindDisabled(kind); // 1
        bool structure = kind == UAKinds.MSIG;
        d = keyData;
        // 2. msig: the layout with the widest member set; the profile's MEMBER set is step 4 (UAMemberUnknown).
        UAKinds.validateKeyData(kind, d, structure || hederaNative);
        ua = UAKinds.uaOf(kind, d); // 3
        if (UAKinds.inNativeSpace(ua)) revert UAIdInNativeSpace(ua);
        if (kindOf(ua) != 0) revert UAAlreadyRegistered(ua);
        kh = _claim(kind, d, structure); // 4
    }

    /// Step 4: single-key kinds claim their keyHash (`UAKeyInUse`); structures check their members (no keyHash).
    function _claim(uint16 kind, bytes memory d, bool structure) private view returns (bytes32 kh) {
        if (structure) {
            _membersWorst(d);
            return 0;
        }
        kh = UAKinds.keyHashOf(kind, d);
        bytes32 owner = keyOwner(kh);
        if (owner != 0) revert UAKeyInUse(kh, owner);
    }

    /// Step 5 (UA-6 U3, UA-8 P2 / P7 / P8): the attributes, checked before the PoP in portable.json's order. Returns the
    /// portable PoP digest and the PQZ keyHash `h` (group `pqz-mlwe`, 0 without a key). `UAPqzHolder` / `UAKemHolder` for
    /// a kind (or an `msig` that is not PQ-eligible) that may not hold the key, and `UAPqzHolder` for an `msig` PQZ holder
    /// whose worst-case authorization, with a gen-2 registry's forwarding hold, + `PqzSet.PQZ_DEBIT_MIN_GAS` exceeds
    /// 2^24; `UAPqzPopHash` unless a PQZ key comes with a proof hash and only with it, and given proof bytes hash to it;
    /// `UAKeyData(0x0142)` for a PQZ key of no parameter set's length; `UAKemVersion` for version 0 with a key,
    /// `UAKemKeyLength` for a KEM key other than 1,600 B; `UAKindDisabled(0x0142)` for a PQZ key on a gen 2 whose gen 1
    /// enables 0x0142 (ruling A5-I1). The PQZ key's owner (`UAKeyInUse`) is step 7, for a proven key.
    function _attrs(uint16 kind, bytes memory d, bytes32 ua, UAAttrs calldata attrs, bytes calldata pqzPop)
        private
        view
        returns (bytes32 portable, bytes32 h)
    {
        bool pqz = attrs.pqzKey.length != 0;
        uint64 v = attrs.kemVersion;
        bool kem = v != 0 || attrs.kemPk.length != 0;
        if (pqz) _pqzHolder(kind, d, ua);
        if (kem && !_holder(kind, d)) revert UAKemHolder(ua);
        if (pqz != (attrs.pqzPopHash != 0) || attrs.pqzPopHash == EMPTY_PROOF_HASH) revert UAPqzPopHash(ua);
        if (pqzPop.length != 0 && keccak256(pqzPop) != attrs.pqzPopHash) revert UAPqzPopHash(ua);
        if (pqz) h = _pqzKeyHash(attrs.pqzKey);
        bytes32 kemHash;
        if (kem) {
            if (v == 0) revert UAKemVersion(ua, 0);
            if (attrs.kemPk.length != UAKinds.KEM_PK_LENGTH) revert UAKemKeyLength(attrs.kemPk.length);
            kemHash = UAKinds.kemRecordDigest(ua, v, attrs.kemPk);
        }
        portable = UAKinds.portablePopDigest(ua, h, kemHash);
    }

    /// A PQZ / KEM holder (UA-6 U3, UA8-D12): `mldsa44`, `mldsa65`, `fndsa512`, a PQ-eligible `msig`.
    function _holder(uint16 kind, bytes memory d) private pure returns (bool) {
        return kind == UAKinds.MLDSA44 || kind == UAKinds.MLDSA65 || kind == UAKinds.FNDSA512
            || (kind == UAKinds.MSIG && _pqEligible(d));
    }

    /// May `ua` (`kind`, key data `d`) hold a PQZ key here (`register`, `setPqzKey`)? `UAKindDisabled(0x0142)` on a gen 2
    /// whose gen 1 enables 0x0142, `UAPqzHolder` for a non-holder or an `msig` over the debit bound.
    function _pqzHolder(uint16 kind, bytes memory d, bytes32 ua) private view {
        // ruling A5-I1: 0x0142 lives in one generation; a gen 2 in front of a gen 1 that holds it refuses a PQZ key (the
        // portable PoP lets anyone choose the registry: a key placed here could never be proven on this chain)
        if (predecessor != address(0) && IUARegistry(predecessor).kindEnabled(UAKinds.PQZ_MLWE)) {
            revert UAKindDisabled(UAKinds.PQZ_MLWE);
        }
        if (!_holder(kind, d)) revert UAPqzHolder(ua);
        // CTR-PQZ-12 (review2 C0-5, controller proposal, owner may override): an `msig` holder's worst-case
        // authorization plus the set's cheapest PQZL debit (its full relayed transaction, fee signer included) must fit
        // one transaction at the EIP-7825 cap 2^24, else every credit to it could be locked. Not the chain's own limit.
        // UA8-D12: the PQZ key only, not the KEM record.
        if (kind == UAKinds.MSIG) {
            // a gen-2 registry in front forwards the whole authorization to the one that holds the record
            // (`_viaPredecessor`) and holds 1/63 of it again plus the margin: counted here
            uint256 w = _membersWorst(d);
            if (w + w / 63 + SigCheck.GAS_MARGIN + PqzSet.PQZ_DEBIT_MIN_GAS > TX_GAS_CAP) revert UAPqzHolder(ua);
        }
    }

    /// The PQZ keyHash (group `pqz-mlwe`); `UAKeyData(0x0142)` for a key of no parameter set's length.
    function _pqzKeyHash(bytes memory pqzKey) private pure returns (bytes32) {
        uint256 n = pqzKey.length; // PqzSet.PK of the four sets: 2,048 B per 256 of n, n 2,048 … 2,816
        if (n < 16_384 || n > 22_528 || n % 2_048 != 0) revert UAKeyData(UAKinds.PQZ_MLWE);
        return UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqzKey);
    }

    /// An `msig` whose members of kinds outside 0x0130–0x0133 weigh less than its threshold (CTR-PQZ-12): it may hold
    /// a PQZ key and registers with an m-of-n PoP (U5).
    function _pqEligible(bytes memory d) private pure returns (bool) {
        (uint256 threshold, uint256 count) = (_u16(d, 0), _u16(d, 2));
        uint256 classical;
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            if (!_isPq(uint16(_u16(d, o)))) classical += _u16(d, o + 34);
        }
        return classical < threshold;
    }

    /// Step 7, the PQZ key (UA8-D8): the key (SSTORE2) and its proof hash; with `pqzPop`, the proof bytes, and where
    /// slot 0x0142 has a verifier `R_REG` over `uaMessage(0x0142, PURPOSE_POP_V2, portable)` (it refuses a key of
    /// another set's length or with a coefficient `≥ q`; `UAPoP`), capped with the hold, then the proven key's owner
    /// (`UAKeyInUse`, either generation), `keyOwner(h)`, the `0x0142` list.
    function _pqzAttach(bytes32 ua, UAAttrs calldata attrs, bytes calldata pqzPop, bytes32 h, bytes32 portable) private {
        if (h == 0) return;
        _pqzKey[ua].ptr = SSTORE2.write(attrs.pqzKey);
        _pqzPopHash[ua] = attrs.pqzPopHash;
        if (pqzPop.length == 0) return;
        _pqzProof(ua, attrs.pqzKey, pqzPop, h, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, portable), pqzPop[0:0]);
    }

    /// The proof bytes stored; proven where slot 0x0142 has a verifier and it accepts `pqzPop` over `message`.
    function _pqzProof(bytes32 ua, bytes memory pqzKey, bytes calldata pqzPop, bytes32 h, bytes32 message,
        bytes calldata logged) private returns (bool proven)
    {
        _pqzPop[ua] = SSTORE2.writeChunks(pqzPop);
        uint256 cfg = _cfg(UAKinds.PQZ_MLWE);
        if (uint160(cfg) != 0) {
            bytes memory data = abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, pqzKey, message, pqzPop);
            if (!_capped(address(uint160(cfg)), cfg >> 160, data, 1, true)) revert UAPoP();
            bytes32 owner = keyOwner(h);
            if (owner != 0) revert UAKeyInUse(h, owner);
            _keyOwner[h] = ua;
            _list(UAKinds.PQZ_MLWE, ua);
            _pqzKey[ua].proven = proven = true;
        }
        emit UAPqzPopStored(ua, _checked(proven), logged);
    }

    // ----- the PQZ proof later (UA8-D8, P8) and the PQZ key later (ruling A1-I1) -----

    function storePqzPop(bytes32 ua, bytes calldata pqzPop) external {
        bool host = _host(ua);
        if (pqzPop.length == 0) revert UAPqzPopHash(ua); // an empty proof is no proof (ruling A6-m)
        PqzKey memory k = _pqzKey[ua];
        bytes32 ph = _pqzPopHash[ua];
        if (host && k.ptr == address(0)) {
            // gen 1's key (from its `register` or `setPqzKey`), proven in this generation (ruling A6-I1)
            (k.ptr, ph,) = IUARegistry(predecessor).pqzKeyOf(ua);
            k.added = IUARegistry(predecessor).pqzKeySigOf(ua).length != 0;
        }
        if (keccak256(pqzPop) != ph) revert UAPqzPopHash(ua); // no PQZ key: the hash is 0
        if (_pqzPop[ua].length != 0) return; // stored: proven, or never provable here (no verifier)
        bytes memory key = SSTORE2.read(k.ptr);
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key);
        bytes32 message = k.added
            ? UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyDigest(ua, h))
            : UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, UAKinds.portablePopDigest(ua, h, _kemHash(ua, host)));
        if (host) {
            _pqzKey[ua] = k;
            _pqzPopHash[ua] = ph;
        }
        _pqzProof(ua, key, pqzPop, h, message, pqzPop);
    }

    /// The initial KEM record's digest (0 = none) that `register`'s PoP signed: from the blob, or gen 1's record.
    function _kemHash(bytes32 ua, bool host) private view returns (bytes32) {
        uint64 v;
        bytes memory kemPk;
        if (host) {
            (,, UAAttrs memory a,,) = IUARegistry(predecessor).registrationOf(ua);
            (v, kemPk) = (a.kemVersion, a.kemPk);
        } else {
            (,, v) = abi.decode(SSTORE2.readChunks(_reg[ua]), (bytes, bytes, uint64));
            (kemPk,) = _kemAt(ua, v);
        }
        return v == 0 ? bytes32(0) : UAKinds.kemRecordDigest(ua, v, kemPk);
    }

    /// Where `storePqzPop` / `setPqzKey` write (ruling A6-I1): false = the record is here; true = gen 1 holds it and this
    /// gen 2 enables 0x0142 (its constructor refuses 0x0142 when gen 1 enables it, so this is the oldest generation
    /// with the verifier); else `UAUnauthorized` (unregistered, or a gen-1 record on a gen 2 without 0x0142: UA8-D11).
    function _host(bytes32 ua) private view returns (bool) {
        if (_records[ua].kind != 0) return false;
        if (predecessor != address(0) && uint160(_cfg(UAKinds.PQZ_MLWE)) != 0 && kindOf(ua) != 0) return true;
        revert UAUnauthorized(ua);
    }

    function setPqzKey(bytes32 ua, bytes calldata pqzKey, bytes32 pqzPopHash, bytes calldata sig) external {
        bool host = _host(ua);
        uint16 kind;
        bytes memory d;
        if (host) {
            (kind, d,,,) = IUARegistry(predecessor).registrationOf(ua);
        } else {
            Record memory r = _records[ua];
            kind = r.kind;
            (d,,) = _registration(ua, r.keyPtr);
        }
        _pqzHolder(kind, d, ua);
        _pqzKeyFree(ua, host);
        bytes32 h = _pqzKeyHash(pqzKey);
        if (pqzPopHash == 0 || pqzPopHash == EMPTY_PROOF_HASH) revert UAPqzPopHash(ua);
        bytes32 rd = UAKinds.pqzKeyRecordDigest(UAKinds.pqzKeyDigest(ua, h), pqzPopHash);
        if (!_sigOk(kind, d, ua, UAKinds.PURPOSE_PQZ_KEY, rd, sig)) revert UAUnauthorized(ua);
        _pqzKey[ua] = PqzKey(SSTORE2.write(pqzKey), false, true);
        _pqzPopHash[ua] = pqzPopHash;
        _pqzKeySig[ua] = SSTORE2.writeChunks(sig);
        emit UAPqzKeyAdded(ua, h, pqzPopHash, pqzKey, sig);
    }

    /// `setPqzKey`'s `UAPqzKeySet` (ruling R-cross-set): the UA has a PQZ key here (gen 2 host: in either generation), and
    /// it stays (write-once) unless this chain can never prove it: slot 0x0142 has a verifier and the key, unproven, is
    /// not of this build's set length (`PqzSet.PK`, the verifier's own length check). Without the verifier nothing is
    /// replaced (nothing can be proven here either way). A replaced `register` key is kept for `registrationOf`.
    function _pqzKeyFree(bytes32 ua, bool host) private {
        PqzKey memory old = _pqzKey[ua];
        address pk = old.ptr;
        if (host && pk == address(0)) (pk,,) = IUARegistry(predecessor).pqzKeyOf(ua); // gen 1's key counts
        if (pk == address(0)) return;
        if (old.proven || uint160(_cfg(UAKinds.PQZ_MLWE)) == 0 || pk.code.length - 1 == PqzSet.PK) revert UAPqzKeySet(ua);
        if (!host && !old.added) (_regPqzKey[ua], _regPqzPopHash[ua]) = (pk, _pqzPopHash[ua]);
    }

    // ----- KEM records (P4, P5, P7; UA8-D3–D5, D11, D12) -----

    function setKemKey(bytes32 ua, uint64 version, bytes calldata kemPk, bytes calldata sig) external {
        Record memory r = _records[ua];
        // UA8-D11 before `_sigOk`: its gen-1 fallback would verify a gen-1 holder's record here (A6 re-review)
        if (r.kind == 0) revert UAUnauthorized(ua);
        (bytes memory d,,) = _registration(ua, r.keyPtr);
        if (!_holder(r.kind, d)) revert UAKemHolder(ua);
        if (version == 0 || _kem[ua][version].length != 0) revert UAKemVersion(ua, version);
        if (kemPk.length != UAKinds.KEM_PK_LENGTH) revert UAKemKeyLength(kemPk.length);
        bytes32 rd = UAKinds.kemRecordDigest(ua, version, kemPk);
        if (!_sigOk(r.kind, d, ua, UAKinds.PURPOSE_KEM, rd, sig)) revert UAUnauthorized(ua);
        _kem[ua][version] = SSTORE2.writeChunks(bytes.concat(kemPk, sig));
        if (version > _kemMax[ua]) _kemMax[ua] = version;
        emit UAKemKeySet(ua, version, keccak256(kemPk), kemPk, sig);
    }

    function _isPq(uint16 kind) private pure returns (bool) {
        return kind >= UAKinds.MLDSA44 && kind <= UAKinds.SLHDSA128S;
    }

    /// Step 6 (and `setKemKey`, `setPqzKey`): a portable record's signature `sig` over `uaMessage(kind, purpose, digest)`.
    /// `msig`: `sig` empty unless PQ-eligible, then the m-of-n `MemberSig[]` (members under `member`, U5; a native member
    /// by `personal_sign` or ERC-1271, `_msig`'s `portable`); single keys: the kind's verifier (`verifyPop`). Only the
    /// portable purposes (POP_V2, KEM, PQZ_KEY; rulings A1-f1, A5-m3) reach this chain-free path; any other purpose
    /// reverts `UAUnauthorized` (writes stay on `requireAuthorized`, UAAuth for native members).
    function _sigOk(uint16 kind, bytes memory d, bytes32 ua, bytes32 purpose, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (bool)
    {
        if (purpose != UAKinds.PURPOSE_POP_V2 && purpose != UAKinds.PURPOSE_KEM && purpose != UAKinds.PURPOSE_PQZ_KEY) {
            revert UAUnauthorized(ua);
        }
        if (kind == UAKinds.MSIG) {
            if (!_pqEligible(d)) return sig.length == 0;
            return sig.length != 0 && _msig(ua, purpose, digest, d, sig, true);
        }
        uint256 cfg = _cfg(kind);
        // A6-I1: a gen-1 holder's PQZ key record on gen 2 (the PQ holder kinds are stored: no key data in `auth`); the
        // PQ verifiers' `verify` is their `verifyPop`
        if (uint160(cfg) == 0) return _viaPredecessor(ua, purpose, digest, abi.encode(bytes(""), sig));
        bytes32 message = UAKinds.uaMessage(kind, purpose, digest);
        bytes memory ek = _expanded(ua, kind); // ML-DSA: a complete cache is the key the PoP verifies on
        bytes memory data = ek.length != 0
            ? abi.encodeWithSelector(UAMldsaVerifier.verifyCached.selector, ek, message, sig)
            : abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, d, message, sig);
        // group kinds: the whole group check runs here, bounded by verifyBudget (§1.8 step 6), without the hold
        if (kind >= UAKinds.MUSIG2_SECP256K1 && kind <= UAKinds.FROST_BN254) {
            return _capped(address(uint160(cfg)), verifyBudget, data, 1, false);
        }
        return _capped(address(uint160(cfg)), cfg >> 160, data, 1, true);
    }

    /// Step 4 for `msig`: every member ∈ MEMBER of this profile and native or registered under its stated kind; the
    /// worst case of a minimal authorizing set (the `c` largest caps + `c` × `MSIG_MEMBER_GAS`, + the caller's hold for
    /// the largest of this generation's caps beyond the 400 k that `MSIG_MEMBER_GAS` covers) fits `verifyBudget`.
    function _membersWorst(bytes memory d) private view returns (uint256 worst) {
        (uint256 threshold, uint256 count) = (_u16(d, 0), _u16(d, 2));
        uint256[] memory weights = new uint256[](count);
        uint256[] memory caps = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            uint16 kind = uint16(_u16(d, o));
            bytes32 id = bytes32(_word(d, o + 2));
            if (!UAKinds.isMember(kind, hederaNative)) revert UAMemberUnknown(id);
            if (UAKinds.isNative(kind)) {
                caps[i] = _nativeCap();
            } else {
                if (kindOf(id) != kind) revert UAMemberUnknown(id);
                uint256 cfg = _cfg(kind);
                if (uint160(cfg) != 0) {
                    caps[i] = cfg >> 160;
                } else {
                    // handed to gen 1, which holds cap / 63 + GAS_MARGIN again inside the 63/64 gen 2 gives it; gen 2 holds for it too
                    uint256 cap = IUARegistry(predecessor).verifyCap(kind);
                    caps[i] = cap + cap / 63 + SigCheck.GAS_MARGIN;
                }
            }
            weights[i] = _u16(d, o + 34);
        }
        _sort(weights);
        _sort(caps);
        uint256 c;
        for (uint256 acc; acc < threshold; ++c) {
            acc += weights[c];
        }
        worst = c * MSIG_MEMBER_GAS;
        for (uint256 i; i < c; ++i) {
            worst += caps[count - 1 - i];
        }
        uint256 held = c == 0 ? 0 : caps[count - 1]; // the largest cap among the c (P6c: PQ caps exceed 400 k)
        if (held > SMART_KEY_1271_GAS) worst += (held - SMART_KEY_1271_GAS) / 63;
        if (worst > verifyBudget) revert UAKeyData(UAKinds.MSIG);
    }

    /// A native member may be (or later become, counterfactually) a `SmartKeyAccount` clone: the bound takes its cap.
    function _nativeCap() private view returns (uint256) {
        return _SMART_KEY_CLONE_CODEHASH != 0 ? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
    }

    // ----- requireAuthorized -----

    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth) external view {
        if (!_authorized(ua, purposeTag, digest, auth)) revert UAUnauthorized(ua);
    }

    function _authorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth)
        private
        view
        returns (bool)
    {
        if (UAKinds.inNativeSpace(ua)) return _native(ua, purposeTag, digest, auth);
        uint16 kind = _records[ua].kind;
        if (kind == 0) return _viaPredecessor(ua, purposeTag, digest, auth);
        (bytes memory keyData, bytes memory sig) = abi.decode(auth, (bytes, bytes));
        return _derived(ua, kind, purposeTag, digest, keyData, sig);
    }

    /// A derived id of `kind` (taken from the record, or from the structure for members): key data against the id
    /// (stored kinds: `keyData` empty, `vk` from the id's own record), then the kind's verifier, `msig`, or gen 1 for
    /// a kind this generation does not enable.
    function _derived(
        bytes32 id,
        uint16 kind,
        bytes32 purposeTag,
        bytes32 digest,
        bytes memory keyData,
        bytes memory sig
    ) private view returns (bool) {
        uint256 cfg = _cfg(kind);
        if (_vkLength(kind) != 0) {
            if (keyData.length != 0) return false; // CTR-UA-17: auth carries only the signature
            if (uint160(cfg) != 0) {
                Record memory r = _records[id];
                if (r.kind != kind) return false;
                bytes memory ek = _expanded(id, kind);
                if (ek.length != 0) {
                    bytes32 m = UAKinds.uaMessage(kind, purposeTag, digest);
                    return _verifierCall(cfg, UAMldsaVerifier.verifyCached.selector, ek, m, sig);
                }
                keyData = SSTORE2.read(r.keyPtr);
            }
        } else if (UAKinds.uaOf(kind, keyData) != id) {
            return false;
        }
        if (kind == UAKinds.MSIG) return _msig(id, purposeTag, digest, keyData, sig, false);
        if (uint160(cfg) == 0) return _viaPredecessor(id, purposeTag, digest, abi.encode(keyData, sig));
        return _verifierCall(
            cfg, IUAKindVerifier.verify.selector, keyData, UAKinds.uaMessage(kind, purposeTag, digest), sig
        );
    }

    /// accounts.md §1.9 `msig` row: strictly increasing member indexes, stop at the threshold (a MemberSig after it
    /// fails, which keeps the registration bound sound), `member_digest = keccak256(ua ‖ ua_msg)`. `portable` (a portable
    /// record's signature, `_sigOk` only — never `requireAuthorized`; rulings C7 / A1-I2 / A1-f1, owner 2026-10-30): `blob`
    /// must be the canonical `abi.encode(MemberSig[])` (review m3), and a native member signs `member_digest` by EIP-191
    /// `personal_sign` (an EOA: code-less or an EIP-7702 designator, its own key only) or, a contract, answers ERC-1271
    /// over `member_digest` (`_nativePortable`); otherwise native members sign `UAAuth` (CTR-UA-24, CTR-MTX-14).
    function _msig(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory d, bytes memory blob, bool portable)
        private
        view
        returns (bool)
    {
        MemberSig[] memory sigs = abi.decode(blob, (MemberSig[]));
        // review m3: a stored portable signature is the canonical encoding (the decoder ignores trailing bytes)
        if (portable && keccak256(abi.encode(sigs)) != keccak256(blob)) return false;
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purposeTag, digest));
        (uint256 threshold, uint256 count) = (_u16(d, 0), _u16(d, 2));
        uint256 acc;
        uint256 next; // lowest index the next MemberSig may use
        for (uint256 i; i < sigs.length; ++i) {
            MemberSig memory s = sigs[i];
            if (acc >= threshold || s.index < next || s.index >= count) return false;
            next = uint256(s.index) + 1;
            uint256 o = 4 + 36 * uint256(s.index);
            if (!_memberOk(uint16(_u16(d, o)), bytes32(_word(d, o + 2)), md, s, portable)) return false;
            acc += _u16(d, o + 34);
        }
        return acc >= threshold;
    }

    /// One `msig` member's signature over `md` under `member` (a native one without key data; `portable`: `_msig`).
    function _memberOk(uint16 kind, bytes32 id, bytes32 md, MemberSig memory s, bool portable)
        private
        view
        returns (bool)
    {
        if (!UAKinds.isNative(kind)) return _derived(id, kind, UAKinds.PURPOSE_MEMBER, md, s.keyData, s.sig);
        if (s.keyData.length != 0) return false;
        if (portable) return _nativePortable(address(uint160(uint256(id))), md, s.sig);
        return _native(id, UAKinds.PURPOSE_MEMBER, md, s.sig);
    }

    /// CTR-UA-24 as amended by owner ruling D1 (2026-10-30, "an EOA must really sign, no delegation"): by code at call
    /// time. Empty or the 23-byte EIP-7702 designator (an EOA) ⇒ ECDSA by its own key only, never ERC-1271 through the
    /// delegate; other code ⇒ ERC-1271 only. Always over `uaAuthDigest`. OZ `tryRecover` refuses high s and a recovered
    /// `address(0)`, so neither id 0 nor a garbage signature ever matches.
    function _native(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory sig) private view returns (bool) {
        bytes32 h = uaAuthDigest(ua, purposeTag, digest);
        return _byCode(address(uint160(uint256(ua))), h, h, sig);
    }

    /// The native rule (ruling D1): an EOA (no code, or the EIP-7702 designator `0xef0100 ‖ delegate`) ⇒ ECDSA over `e`
    /// by its own key only; a contract ⇒ ERC-1271 over `h` only.
    function _byCode(address a, bytes32 e, bytes32 h, bytes memory sig) private view returns (bool) {
        if (!SigCheck.isContract(a)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(e, sig);
            return err == ECDSA.RecoverError.NoError && rec == a;
        }
        return _1271(a, h, sig);
    }

    /// ERC-1271 at 50 k, 400 k for a `SmartKeyAccount` clone (by its immutable codehash).
    function _1271(address a, bytes32 h, bytes memory sig) private view returns (bool) {
        uint256 cap = _SMART_KEY_CLONE_CODEHASH != 0 && a.codehash == _SMART_KEY_CLONE_CODEHASH
            ? SMART_KEY_1271_GAS
            : SigCheck.ERC1271_GAS;
        return _capped(
            a,
            cap,
            abi.encodeCall(IERC1271.isValidSignature, (h, sig)),
            uint256(bytes32(IERC1271.isValidSignature.selector)),
            true
        );
    }

    /// A native `msig` member of a portable record (no chain context; owner ruling 2026-10-30, "an EOA must really sign,
    /// no delegation"): code-less or an EIP-7702 designator (an EOA) ⇒ ECDSA by its own key only (65-byte r ‖ s ‖ v, low
    /// s, v 27 / 28: OZ `tryRecover`) over the EIP-191 `personal_sign` hash of `md`, never ERC-1271 through the delegate;
    /// other code (a contract wallet) ⇒ ERC-1271 `isValidSignature(md, sig)` only, at the same caps as `_native`.
    function _nativePortable(address a, bytes32 md, bytes memory sig) private view returns (bool) {
        return _byCode(a, MessageHashUtils.toEthSignedMessageHash(md), md, sig);
    }

    function _verifierCall(uint256 cfg, bytes4 selector, bytes memory keyData, bytes32 message, bytes memory sig)
        private
        view
        returns (bool)
    {
        return
            _capped(address(uint160(cfg)), cfg >> 160, abi.encodeWithSelector(selector, keyData, message, sig), 1, true);
    }

    /// `staticcall` with exactly `cap` gas; true iff it succeeds with exactly one 32-byte word equal to `expect`.
    /// `hold`: too little gas left to hand over the full cap ⇒ `UAVerifyGas` (63/64 starvation never turns into a
    /// verdict). Without `hold` (the group PoP, whose failure reverts `register` anyway) the call gets at most `cap`.
    function _capped(address target, uint256 cap, bytes memory data, uint256 expect, bool hold)
        private
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

    /// Records and kinds of gen 1 are checked by gen 1 (its verifiers, its `UAAuth` domain for native members of its
    /// structures). Any revert there is a failed check, except starvation (`_starved`).
    function _viaPredecessor(bytes32 id, bytes32 purposeTag, bytes32 digest, bytes memory auth)
        private
        view
        returns (bool)
    {
        if (predecessor == address(0)) return false;
        uint256 g = gasleft();
        try IUARegistry(predecessor).requireAuthorized(id, purposeTag, digest, auth) {
            return true;
        } catch (bytes memory err) {
            _starved(err, g);
            return false;
        }
    }

    /// A starved caller must see UAVerifyGas, never a verdict (T-AUTH-4): gen 1's own `UAVerifyGas` (at a hold) is
    /// re-raised, and so is gen 1 running out of gas before its hold (W-M): no revert data and at most the 1/64 this
    /// frame kept (`g` = gasleft before the call); any other revert of gen 1 returns its unused gas and stays a verdict.
    function _starved(bytes memory err, uint256 g) private view {
        if ((err.length == 4 && bytes4(err) == UAKinds.UAVerifyGas.selector) || (err.length == 0 && gasleft() < g / 63)) {
            revert UAKinds.UAVerifyGas();
        }
    }

    // ----- kind table -----

    function _cfg(uint16 kind) private view returns (uint256) {
        if (kind == UAKinds.MSIG) return _CFG_MSIG;
        uint256 s = _slot(kind);
        if (s > 19) return 0;
        if (s == 19) return _CFG19;
        if (s > 13) return s < 16 ? (s == 14 ? _CFG14 : _CFG15) : (s < 18 ? (s == 16 ? _CFG16 : _CFG17) : _CFG18);
        if (s > 11) return _CFG13; // slot 12 (zether-bn254) is in legacy/ua6/: `_slot` never returns it
        if (s > 7) return s < 10 ? (s == 8 ? _CFG8 : _CFG9) : (s == 10 ? _CFG10 : _CFG11);
        if (s < 4) return s < 2 ? (s == 0 ? _CFG0 : _CFG1) : (s == 2 ? _CFG2 : _CFG3);
        return s < 6 ? (s == 4 ? _CFG4 : _CFG5) : (s == 6 ? _CFG6 : _CFG7);
    }

    /// Kind-table slot: 0x0100–0x0107 → 0–7, 0x0110–0x0113 → 8–11, 0x0141 → 13, 0x0130–0x0133 → 14–17,
    /// 0x0142 (the PQZ key verifier) → 18, 0x0108 → 19, anything else 20 (not in this code's table).
    function _slot(uint16 kind) private pure returns (uint256) {
        if (kind >= 0x0100 && kind <= 0x0107) return kind - 0x0100;
        if (kind >= UAKinds.MUSIG2_SECP256K1 && kind <= UAKinds.FROST_BN254) return kind - 0x0110 + 8;
        if (kind == UAKinds.ZETHER_BLS12381) return 13;
        if (_isPq(kind)) return kind - 0x0130 + 14;
        if (kind == UAKinds.PQZ_MLWE) return 18;
        if (kind == UAKinds.SECP256K1) return 19;
        return 20;
    }

    /// Length of the stored `vk` of a stored kind (CTR-UA-17), 0 otherwise: `Q` / `Y` SEC1 compressed (secp256k1) or
    /// EIP-196 uncompressed (bn254), the first bytes of the key data; Zether `Y` (128) and the PQ `pk` (ML-DSA
    /// 1,312 / 1,952, FN-DSA 897, SLH-DSA 32), the whole key data. (The PQZ key has its own pointer, `_pqzKey`.) The
    /// rest of the key data is in the registration blob (`_reg`), so `keyData` is stored once (UA8-D7).
    function _vkLength(uint16 kind) private pure returns (uint256) {
        if (kind == UAKinds.MUSIG2_SECP256K1 || kind == UAKinds.FROST_SECP256K1) return 33;
        if (kind == UAKinds.MUSIG2_BN254 || kind == UAKinds.FROST_BN254) return 64;
        if (kind == UAKinds.ZETHER_BLS12381) return 128;
        if (kind == UAKinds.MLDSA44) return 1312;
        if (kind == UAKinds.MLDSA65) return 1952;
        if (kind == UAKinds.FNDSA512) return 897;
        if (kind == UAKinds.SLHDSA128S) return 32;
        return 0;
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

    // ----- bytes helpers -----

    function _word(bytes memory d, uint256 o) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(d, 32), o))
        }
    }

    function _u16(bytes memory d, uint256 o) private pure returns (uint256) {
        return _word(d, o) >> 240;
    }

    /// Insertion sort, ascending (count ≤ 16).
    function _sort(uint256[] memory a) private pure {
        for (uint256 i = 1; i < a.length; ++i) {
            uint256 v = a[i];
            uint256 j = i;
            for (; j > 0 && a[j - 1] > v; --j) {
                a[j] = a[j - 1];
            }
            a[j] = v;
        }
    }
}
