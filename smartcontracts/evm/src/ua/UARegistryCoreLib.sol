// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SigCheck} from "../common/SigCheck.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {IUAPopVerifier} from "./IUAVerifier.sol";
import {UAKinds} from "./UAKinds.sol";
import {UAStore} from "./UAStore.sol";
import {PqzSet} from "../pqz/PqzSet.sol";
import {UAMldsaVerifier} from "./MlDsa.sol";

/// @title `UARegistry`'s core library (typed-signing R2, owner 2026-11-01; T66b 3.1b, owner 2026-11-09, spec
///        2026-11-09-t66b-library-organisation.md §11 (f)): the `register` forms, the `msig`, `acceptMembership`,
///        `requirePortable`, the pure digests; the key writes after registration and the reads off the hot path are
///        `UARegistryAuxLib`'s, which runs this library's shared helpers by a nested DELEGATECALL (T66b 3.1c: `portableOk`,
///        `pqzHolder`, `pqzProof`, `keyUa`) and compiles in only its small `internal` ones. Run by DELEGATECALL from a
///        thin entry per function, so `address(this)` is the registry and the storage is its `UAStore.Layout`. Same check order, same stored bytes, same events and errors as when this
///        code was in the registry (`legacy/typed-signing/UARegistryPreSplit.sol`; `test/ua/UARegistrySplit.t.sol`).
/// @notice What a library cannot read, the registry's immutables, reaches it two ways (no new selector):
///         - 3 words the entry appends after the forwarded calldata: `_cfg(kind)` of the kind the entry knows (its
///           parameter, or the record's), `_cfg(0x0142)`, the clone codehash. They are read from the end of the calldata,
///           so nothing a caller sends can stand in their place, however long its calldata; a nested ABI offset may point
///           into them, which only reads public values as that caller's own argument.
///         - everything with a getter is called back on `address(this)`: `predecessor`, `hederaNative`, `verifyBudget`,
///           `verifyCap` (an `msig` member's cap and whether its kind is enabled), `kindOf`, `keyOwner`.
///         A derived `msig` member's signature goes through `requireAuthorized` on `address(this)` under `member`: the
///         same `_derived`, its kind was checked against its record at registration (`_membersWorst`); the verifier call
///         stays in the one place, and this library needs no member's verifier address.
///         Called directly every writer reverts: solc's library call protection covers each one, none is `view`; the seven
///         `pure` views of T66b R-1 answer a direct call with their pure result.
///         `acceptMembership` (CTR-UA-37) runs here too; its member check is `_memberOk`, as a stored record's.
///         UNAUDITED.
library UARegistryCoreLib {
    /// @notice EIP-7825 per-transaction gas cap, the bound of a PQZ `msig` holder (`_attrs`).
    uint256 internal constant TX_GAS_CAP = 1 << 24;
    /// @notice Registration bound for `msig` (register step 4): gas per member beyond its cap — MemberSig decoding,
    ///         `uaOf`, `uaMessage`, the member's key read from its record (CTR-UA-33: the key bytes only, never the
    ///         member's `pop`, so the figure does not depend on how the member registered), the call or the gen-1
    ///         hand-off, cold accounts (measured worst, cold under `--isolate`: 28,544 for a member handed to gen 1,
    ///         21,224 for a derived member here), plus what the caller must hold for the largest cap (400 k / 63 + 5 k):
    ///         39,893, rounded up (35,000 before CTR-UA-33: 19,987 + 11,349 = 31,336). Also added in `_membersWorst`:
    ///         `(held - 400 k) / 63` for the largest held member cap above 400 k, and for each member gen 2 hands to gen 1 the hold gen 2 keeps
    ///         around that call (the member counts `cap + cap / 63 + SigCheck.GAS_MARGIN`; gen 1 holds again
    ///         inside). `UAGas.t.sol` `test_T_GAS_msigAtBudget` authorizes msigs
    ///         registered exactly at `verifyBudget` within `verifyBudget`. `test_T_GAS_msigPqAtBudget` covers PQ signatures
    ///         (8 x `slhdsa128s`, 7,856 B each, + 1 clone, exactly at the bound 12,020,873; least frame gas 11,875,412,
    ///         145 k spare): no per-kind size term (review2 C4-2).
    uint256 internal constant MSIG_MEMBER_GAS = 45_000;
    /// CTR-UA-37: the accepted bits' cold read, once per authorization and not per member, so a term of `_membersWorst` of its own:
    /// measured +2,236 (`requireAuthorized`, `msig` 2-of-2, 49,634 -> 51,870, `UARegistrySplit.t.sol` `test_gasHotPath`), rounded up.
    /// Without it a member of 400 k handed to gen 1, at the bound, starves (`test_T_GAS_msigAtBudget`).
    uint256 internal constant MSIG_ACCEPTED_GAS = 2_500;
    /// `keccak256("")`: the hash of an empty proof, refused as a `pqzPopHash` (ruling A6-m).
    bytes32 internal constant EMPTY_PROOF_HASH = keccak256("");

    // ----- the registry's `pure` views (T66b R-1, spec 2026-11-09-t66b-library-organisation.md §5) -----

    /// One copy of their code in the registry pair: `UARegistry` runs these by DELEGATECALL (`_libPure`, nothing appended), the
    /// same ABI and answers as when they were compiled into the registry. `pure`, so solc's call protection does not cover them:
    /// a direct call answers the same pure result, and reads and writes nothing.
    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.uaOf(kind, keyData);
    }

    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.keyHashOf(kind, keyData);
    }

    function portableRecordDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash_)
        external
        pure
        returns (bytes32)
    {
        return UAKinds.portableRecordDigest(ua, kind, pqzKeyHash, kemRecordHash_);
    }

    function registrationDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash_, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32)
    {
        return UAKinds.registrationDigest(ua, kind, pqzKeyHash, kemRecordHash_, pqzPopHash);
    }

    function pqzKeyRecordDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 pqzPopHash) external pure returns (bytes32) {
        return UAKinds.pqzKeyRecordDigest(ua, pqzKeyHash, pqzPopHash);
    }

    function pqzKeyVersionDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash) external pure returns (bytes32) {
        return UAKinds.pqzKeyVersionDigest(ua, version, pqzKeyHash);
    }

    function pqzKeyVersionRecordDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32)
    {
        return UAKinds.pqzKeyVersionRecordDigest(ua, version, pqzKeyHash, pqzPopHash);
    }

    // ----- the appended words -----

    function _cfgKind() internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := calldataload(sub(calldatasize(), 96))
        }
    }

    function _cfgPqz() internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := calldataload(sub(calldatasize(), 64))
        }
    }

    function _cloneHash() internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := calldataload(sub(calldatasize(), 32))
        }
    }

    // ----- the getters, on the registry -----

    function _pred() internal view returns (address) {
        return IUARegistry(address(this)).predecessor();
    }

    function _kindOf(bytes32 ua) internal view returns (uint16) {
        return IUARegistry(address(this)).kindOf(ua);
    }

    function _keyOwner(bytes32 h) internal view returns (bytes32) {
        return IUARegistry(address(this)).keyOwner(h);
    }

    /// A record gen 1 holds (this registry is gen 2 and has none of its own), as `UARegistry._elsewhere`.
    function _elsewhere(bytes32 ua) internal view returns (bool) {
        return UAStore.layout().records[ua].kind == 0 && _pred() != address(0);
    }

    /// A kind this generation lists itself (`UARegistry._listedHere`): `_cfgKind()` is the kind's word the entry appended.
    function _listedHere() internal view returns (bool) {
        return _pred() == address(0) || uint160(_cfgKind()) != 0;
    }

    // ----- register (accounts.md §1.8 steps 1–8, UA-8) -----

    /// Registers `keyData` of a single-key `kind` with its attributes (accounts.md §1.8, UA-8 P2); `UAPoP` when the PoP
    /// fails. The structure `msig` registers through `registerMsig` only (`UAKeyData(kind)` here: its PoP is a
    /// `MemberSig[]`); `webauthn-p256` / MuSig2 / FROST also through their packed key data, next to `registerWebAuthn` /
    /// `registerMuSig2` / `registerFrost` (owner 2026-10-31; TS-D13): same bytes, same id, same record.
    function register(uint16 kind, bytes calldata keyData, IUARegistry.UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua)
    {
        if (kind == UAKinds.MSIG) revert IUARegistry.UAKeyData(kind);
        return _register(kind, keyData, attrs, pop, new IUARegistry.MemberSig[](0), pqzPop);
    }

    /// TS-D13: `register` of a `webauthn-p256` key from its fields (`x ‖ y ‖ rpIdHash` assembled here).
    function registerWebAuthn(IUARegistry.WebAuthnKey calldata key, IUARegistry.UAAttrs calldata attrs,
        bytes calldata pop, bytes calldata pqzPop) external returns (bytes32 ua)
    {
        return _register(UAKinds.WEBAUTHN_P256, abi.encodePacked(key.x, key.y, key.rpIdHash), attrs, pop,
            new IUARegistry.MemberSig[](0), pqzPop);
    }

    /// TS-D13: `register` of a MuSig2 group key from its points (`aggKey ‖ u16 n ‖ n × key` assembled here).
    function registerMuSig2(uint16 kind, IUARegistry.MuSig2Key calldata key, IUARegistry.UAAttrs calldata attrs,
        bytes calldata pop, bytes calldata pqzPop) external returns (bytes32 ua)
    {
        if (kind != UAKinds.MUSIG2_SECP256K1 && kind != UAKinds.MUSIG2_BN254) revert IUARegistry.UAKeyData(kind);
        if (uint160(_cfgKind()) == 0) revert IUARegistry.UAKindDisabled(kind); // step 1 before the key's fields (step 2)
        uint256 size = UAStore.vkLength(kind);
        bytes[] calldata m = key.memberKeys;
        bytes memory d = abi.encodePacked(_point(kind, key.aggKey, size), uint16(m.length));
        for (uint256 i; i < m.length; ++i) {
            d = bytes.concat(d, _point(kind, m[i], size));
        }
        return _register(kind, d, attrs, pop, new IUARegistry.MemberSig[](0), pqzPop);
    }

    /// TS-D13: `register` of a FROST group key from its fields (`groupKey ‖ u16 t ‖ u16 n ‖ n × (t commitments ‖ r ‖ z)`
    /// assembled here; each member has exactly `threshold` commitments).
    function registerFrost(uint16 kind, IUARegistry.FrostKey calldata key, IUARegistry.UAAttrs calldata attrs,
        bytes calldata pop, bytes calldata pqzPop) external returns (bytes32 ua)
    {
        if (kind != UAKinds.FROST_SECP256K1 && kind != UAKinds.FROST_BN254) revert IUARegistry.UAKeyData(kind);
        if (uint160(_cfgKind()) == 0) revert IUARegistry.UAKindDisabled(kind); // step 1 before the key's fields (step 2)
        IUARegistry.FrostMember[] calldata m = key.members;
        bytes memory d =
            abi.encodePacked(_point(kind, key.groupKey, UAStore.vkLength(kind)), key.threshold, uint16(m.length));
        for (uint256 i; i < m.length; ++i) {
            d = bytes.concat(d, _frostMember(kind, m[i], key.threshold));
        }
        return _register(kind, d, attrs, pop, new IUARegistry.MemberSig[](0), pqzPop);
    }

    /// One FROST member's bytes `t commitments ‖ r ‖ z` (exactly `t` commitments).
    function _frostMember(uint16 kind, IUARegistry.FrostMember calldata m, uint256 t) internal pure returns (bytes memory d) {
        uint256 size = UAStore.vkLength(kind);
        if (m.commitments.length != t) revert IUARegistry.UAKeyData(kind);
        for (uint256 j; j < t; ++j) {
            d = bytes.concat(d, _point(kind, m.commitments[j], size));
        }
        d = bytes.concat(d, _point(kind, m.r, size), m.z);
    }

    /// One point of a typed key: exactly `size` bytes (its validity is `validateKeyData`'s, on the assembled bytes).
    function _point(uint16 kind, bytes calldata p, uint256 size) internal pure returns (bytes calldata) {
        if (p.length != size) revert IUARegistry.UAKeyData(kind);
        return p;
    }

    /// TS-D10: `register` of an `msig` from its typed structure (the CTR-UA-09 bytes assembled here) and its typed
    /// member signatures (stored as `abi.encode(pop)`, "" for none).
    function registerMsig(IUARegistry.MsigStructure calldata structure, IUARegistry.UAAttrs calldata attrs,
        IUARegistry.MemberSig[] calldata pop, bytes calldata pqzPop) external returns (bytes32 ua)
    {
        IUARegistry.MsigMember[] calldata m = structure.members;
        bytes memory d = abi.encodePacked(structure.threshold, uint16(m.length));
        for (uint256 i; i < m.length; ++i) {
            d = bytes.concat(d, abi.encodePacked(m[i].kind, m[i].id, m[i].weight));
        }
        return _register(UAKinds.MSIG, d, attrs, "", pop, pqzPop);
    }

    /// The CTR-UA-09 bytes of a structure read from a record. Not shared with `registerMsig`: a `memory` parameter there copies the
    /// whole structure out of calldata first, which every flat `msig` would pay.
    function _packed(IUARegistry.MsigStructure memory s) internal pure returns (bytes memory d) {
        IUARegistry.MsigMember[] memory m = s.members;
        d = abi.encodePacked(s.threshold, uint16(m.length));
        for (uint256 i; i < m.length; ++i) {
            d = bytes.concat(d, abi.encodePacked(m[i].kind, m[i].id, m[i].weight));
        }
    }

    /// The structure of the `msig` member `id`, here or in gen 1 (`msigOf`: the key bytes only, never its `pop`).
    function _msigBytes(bytes32 id) internal view returns (bytes memory) {
        return _packed(IUARegistry(address(this)).msigOf(id));
    }

    /// Steps 1–8. `sig` (single keys) or `members` (an msig) is the PoP; the stored `pop` is `sig`, or
    /// `abi.encode(members)` ("" for none).
    function _register(uint16 kind, bytes memory d, IUARegistry.UAAttrs calldata attrs, bytes memory sig,
        IUARegistry.MemberSig[] memory members, bytes calldata pqzPop) internal returns (bytes32 ua)
    {
        UAStore.Layout storage s = UAStore.layout();
        bytes32 kh;
        (ua, kh) = _identify(kind, d); // 1–4
        _consent(kind, d, ua, attrs, sig, members, pqzPop); // 5–7
        bytes memory pop = members.length != 0 ? abi.encode(members) : sig;
        // owner 2026-11-03: an `msig` keeps `keccak256(pop)`, not its bytes; each slot's bytes go in `UAMemberSig`, its hash in state
        _record(ua, kind, d, kh, attrs, members.length != 0 ? abi.encodePacked(keccak256(pop)) : pop); // 8
        // CTR-UA-37: a slot that signed the `pop` agreed; an empty `pop` writes nothing
        if (members.length != 0) {
            uint256 bits;
            for (uint256 i; i < members.length; ++i) {
                IUARegistry.MemberSig memory m = members[i];
                bits |= 1 << m.index;
                _memberSig(ua, d, m.index, UAKinds.PURPOSE_POP_V2, m.members.length == 0 ? m.sig : abi.encode(m.members));
            }
            s.accepted[ua] = bits;
            s.popSlots[ua] = bits; // CTR-UA-33 Change 2026-11-08: the `pop`'s own slots, never moved by `acceptMembership`
        }
        (uint8 q, uint8 k) = (UAStore.checked(s.pqzKey[ua][0].proven), UAStore.checked(s.kem[ua][0].length != 0));
        emit IUARegistry.UARegistered(ua, kind, d, attrs, keccak256(pop), pqzPop, UAKinds.CHECKED_CHAIN, q, k);
    }

    /// The signature object `b` of the `msig` `ua`'s slot `index` (owner 2026-11-03): its hash kept, written once with the slot's bit, its
    /// bytes in `UAMemberSig`, under `purpose` (`PURPOSE_POP_V2` or `PURPOSE_MEMBERSHIP`). `d`: the `msig`'s key data.
    function _memberSig(bytes32 ua, bytes memory d, uint16 index, bytes32 purpose, bytes memory b) internal {
        UAStore.layout().memberSigHash[ua][index] = keccak256(b);
        emit IUARegistry.UAMemberSig(ua, bytes32(UAStore.word(d, 4 + 36 * uint256(index) + 2)), index, purpose, b);
    }

    /// Steps 5–7: the attributes, the PoP over the registration digest (`UAPoP`), the PQZ key (and its proof).
    function _consent(
        uint16 kind,
        bytes memory d,
        bytes32 ua,
        IUARegistry.UAAttrs calldata attrs,
        bytes memory sig,
        IUARegistry.MemberSig[] memory members,
        bytes calldata pqzPop
    ) internal {
        (bytes32 record, bytes32 h) = _attrs(kind, d, ua, attrs, pqzPop); // 5
        bytes32 rd = UAKinds.portableDigest(UAKinds.registrationHash(record, attrs.pqzPopHash));
        if (!_sigOk(_cfgKind(), kind, d, ua, UAKinds.PURPOSE_POP_V2, rd, sig, members)) revert IUARegistry.UAPoP(); // 6
        _pqzAttach(ua, attrs, pqzPop, h, UAKinds.portableDigest(record)); // 7
    }

    /// Step 8: the record, `keyPtr` (stored kinds), the keyHash (single keys), the kind's list, the initial KEM record
    /// at version 0 (UA8-D4; owner 2026-10-31: `kemMax` stays 0) — the key, or its committed hash —, the registration
    /// blob (UA8-D7).
    function _record(bytes32 ua, uint16 kind, bytes memory d, bytes32 kh, IUARegistry.UAAttrs calldata attrs, bytes memory pop)
        private
    {
        UAStore.Layout storage s = UAStore.layout();
        uint256 vl = UAStore.vkLength(kind);
        address ptr = vl == 0 ? address(0) : SSTORE2.write(UAStore.cut(d, 0, vl));
        s.records[ua] = IUARegistry.Record(kind, uint40(block.timestamp), ptr, _list(kind, ua));
        if (kh != 0) s.keyOwner[kh] = ua; // msig: none
        if (attrs.kemPkHash != 0) s.kemCommit[ua] = UAStore.KemCommit(attrs.kemPkHash, attrs.kem.scheme);
        else if (attrs.kem.scheme != 0) s.kem[ua][0] = SSTORE2.writeChunks(UAKinds.kemPk(attrs.kem));
        s.reg[ua] = SSTORE2.writeChunks(abi.encode(UAStore.cut(d, vl, d.length - vl), pop));
    }

    /// Appends `ua` to its kind's list (every kind, msig included) and returns its index.
    function _list(uint16 kind, bytes32 ua) internal returns (uint40) {
        UAStore.Layout storage s = UAStore.layout();
        uint256 n = s.uaCount[kind];
        s.uaAt[kind][n] = ua;
        s.uaCount[kind] = n + 1;
        return uint40(n);
    }

    /// Steps 1–4: kind enabled, key data canonical, the id (not native-space, not registered here or in gen 1), the
    /// keyHash (single keys) or the members (msig).
    function _identify(uint16 kind, bytes memory d) internal view returns (bytes32 ua, bytes32 kh) {
        if (uint160(_cfgKind()) == 0) revert IUARegistry.UAKindDisabled(kind); // 1
        bool structure = kind == UAKinds.MSIG;
        // 2. msig: the layout with the widest member set; the profile's MEMBER set is step 4 (UAMemberUnknown).
        UAKinds.validateKeyData(kind, d, structure || IUARegistry(address(this)).hederaNative());
        ua = UAKinds.uaOf(kind, d); // 3
        if (UAKinds.inNativeSpace(ua)) revert IUARegistry.UAIdInNativeSpace(ua);
        if (_kindOf(ua) != 0) revert IUARegistry.UAAlreadyRegistered(ua);
        kh = _claim(kind, d, structure); // 4
    }

    /// Step 4: single-key kinds claim their keyHash (`UAKeyInUse`); structures check their members (no keyHash).
    function _claim(uint16 kind, bytes memory d, bool structure) internal view returns (bytes32 kh) {
        if (structure) {
            _membersWorst(d, _nativeCap());
            return 0;
        }
        kh = UAKinds.keyHashOf(kind, d);
        bytes32 owner = _keyOwner(kh);
        if (owner != 0) revert IUARegistry.UAKeyInUse(kh, owner);
    }

    /// Step 5 (UA-6 U3, UA-8 P2 / P7 / P8): the attributes, checked before the PoP in portable.json's order. Returns the
    /// `UAPortableRecord` struct hash (typed-signing TS-D1; the zero KEM record without one, TS-D2) and the PQZ keyHash `h` (group `pqz-mlwe`, 0 without a key). `UAPqzHolder` / `UAKemHolder` for
    /// a kind (or an `msig` that is not PQ-eligible) that may not hold the key, and `UAPqzHolder` for an `msig` PQZ holder
    /// whose worst-case authorization, with a gen-2 registry's forwarding hold, + `PqzSet.PQZ_DEBIT_MIN_GAS` exceeds
    /// 2^24; `UAPqzPopHash` unless a PQZ key comes with a proof hash and only with it, and given proof bytes hash to it;
    /// `UAKeyData(0x0142)` for a PQZ key of no parameter set's length; the KEM key (version 0, owner 2026-10-31):
    /// `UAKemKeyLength` for an assembled key other than the scheme-1 length (1,601 B) — for the hash commit
    /// (`kemPkHash` ≠ 0), any key bytes next to the scheme —, `UAKemScheme` for a scheme id not enabled;
    /// `UAKindDisabled(0x0142)` for a PQZ key on a gen 2 whose gen 1 enables 0x0142 (ruling A5-I1). The PQZ key's owner
    /// (`UAKeyInUse`) is step 7, for a proven key.
    function _attrs(uint16 kind, bytes memory d, bytes32 ua, IUARegistry.UAAttrs calldata attrs, bytes calldata pqzPop)
        private
        view
        returns (bytes32 record, bytes32 h)
    {
        bool pqz = attrs.pqzKey.length != 0;
        bytes memory kemPk = UAKinds.kemPk(attrs.kem);
        bool commit = attrs.kemPkHash != 0;
        if (pqz) _pqzHolder(kind, d, ua, false);
        if ((commit || kemPk.length != 0) && !_kemHolder(kind)) revert IUARegistry.UAKemHolder(ua);
        if (pqz != (attrs.pqzPopHash != 0) || attrs.pqzPopHash == EMPTY_PROOF_HASH) revert IUARegistry.UAPqzPopHash(ua);
        if (pqzPop.length != 0 && keccak256(pqzPop) != attrs.pqzPopHash) revert IUARegistry.UAPqzPopHash(ua);
        if (pqz) h = _pqzKeyHash(attrs.pqzKey);
        bytes32 kh;
        if (commit) {
            if (attrs.kem.mlkemEk.length != 0 || attrs.kem.x25519 != 0) revert IUARegistry.UAKemKeyLength(kemPk.length);
            _checkKemScheme(attrs.kem.scheme);
            kh = UAKinds.kemRecordHash(ua, 0, attrs.kem.scheme, attrs.kemPkHash);
        } else {
            if (kemPk.length != 0) _checkKemPk(kemPk);
            kh = UAKinds.kemRecordHash(ua, 0, kemPk);
        }
        record = UAKinds.portableRecordHash(ua, kind, h, kh);
    }

    /// A PQZ key holder (UA-6 U3, UA8-D12): a KEM holder, or a PQ-eligible `msig`.
    function _holder(uint16 kind, bytes memory d) internal view returns (bool) {
        return _kemHolder(kind) || (kind == UAKinds.MSIG && _pqEligible(d));
    }

    /// A KEM key holder (CTR-UA-32; owner 2026-11-05, confirmed 2026-11-07; plan T66a): `mldsa44`, `mldsa65`, `fndsa512`, `mldsa87`
    /// (CTR-UA-39 Q2), `fndsa1024` (CTR-UA-40 Q2). Never an `msig`, PQ-eligible or not: a sender seals to each accepted member's own key.
    function _kemHolder(uint16 kind) internal pure returns (bool) {
        return kind == UAKinds.MLDSA44 || kind == UAKinds.MLDSA65 || kind == UAKinds.FNDSA512 || kind == UAKinds.MLDSA87
            || kind == UAKinds.FNDSA1024;
    }

    /// May `ua` (`kind`, key data `d`) hold a PQZ key here (`register`, `setPqzKey`)? `UAKindDisabled(0x0142)` on a gen 2
    /// whose gen 1 enables 0x0142, `UAPqzHolder` for a non-holder or an `msig` over the debit bound. `gen1`: a record gen 1 holds
    /// (`setPqzKey` on a gen-2 host); gen 1 verifies its native slots with its own clone hash, so they count 400 k, as `_slotCap`
    /// counts a gen-1 inner's.
    function _pqzHolder(uint16 kind, bytes memory d, bytes32 ua, bool gen1) internal view {
        // ruling A5-I1: 0x0142 lives in one generation; a gen 2 in front of a gen 1 that holds it refuses a PQZ key (the
        // portable PoP lets anyone choose the registry: a key placed here could never be proven on this chain)
        address g1 = _pred();
        if (g1 != address(0) && IUARegistry(g1).kindEnabled(UAKinds.PQZ_MLWE)) {
            revert IUARegistry.UAKindDisabled(UAKinds.PQZ_MLWE);
        }
        if (!_holder(kind, d)) revert IUARegistry.UAPqzHolder(ua);
        // CTR-PQZ-12 (review2 C0-5, controller proposal, owner may override): an `msig` holder's worst-case
        // authorization plus the set's cheapest PQZL debit (its full relayed transaction, fee signer included) must fit
        // one transaction at the EIP-7825 cap 2^24, else every credit to it could be locked. Not the chain's own limit.
        // UA8-D12: the PQZ key only, not the KEM record. The authorization's own calldata counts too, 16 gas a byte and the EIP-7976 floor of
        // 64: `PQZ_DEBIT_MIN_GAS` holds one holder signature, which is counted again here, on the safe side.
        if (kind == UAKinds.MSIG) {
            // a gen-2 registry in front forwards the whole authorization to the one that holds the record
            // (`UAStore.via`) and holds 1/63 of it again plus the margin: counted here
            uint256 w = _membersWorst(d, gen1 ? UAStore.SMART_KEY_1271_GAS : _nativeCap());
            uint256 a = _authBytes(d, 192);
            uint256 debit = PqzSet.PQZ_DEBIT_MIN_GAS;
            if (w + w / 63 + SigCheck.GAS_MARGIN + debit + 16 * a > TX_GAS_CAP || debit + 64 * a > TX_GAS_CAP) revert IUARegistry.UAPqzHolder(ua);
        }
    }

    /// The PQZ keyHash (group `pqz-mlwe`); `UAKeyData(0x0142)` for a key of no parameter set's length.
    function _pqzKeyHash(bytes memory pqzKey) internal pure returns (bytes32) {
        uint256 n = pqzKey.length; // PqzSet.PK of the four sets: 2,048 B per 256 of n, n 2,048 … 2,816
        if (n < 16_384 || n > 22_528 || n % 2_048 != 0) revert IUARegistry.UAKeyData(UAKinds.PQZ_MLWE);
        return UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqzKey);
    }

    /// An `msig` whose members of kinds outside 0x0130–0x0135 weigh less than its threshold (CTR-PQZ-12): it may hold
    /// a PQZ key and registers with an m-of-n PoP (U5). An `msig` member counts as PQ iff it is PQ-eligible itself: a forger of every
    /// classical key cannot reach its threshold.
    function _pqEligible(bytes memory d) internal view returns (bool) {
        (uint256 threshold, uint256 count) = (UAStore.u16(d, 0), UAStore.u16(d, 2));
        uint256 classical;
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            uint16 kind = uint16(UAStore.u16(d, o));
            if (UAStore.isPq(kind) || (kind == UAKinds.MSIG && _pqEligible(_msigBytes(bytes32(UAStore.word(d, o + 2)))))) continue;
            classical += UAStore.u16(d, o + 34);
        }
        return classical < threshold;
    }

    /// Step 7, the PQZ key (UA8-D8) as version 0 (group 3g): the key (SSTORE2), its proof hash, the per-UA key marker; with
    /// `pqzPop`, the proof bytes, and where slot 0x0142 has a verifier `R_REG` over `uaMessage(0x0142, PURPOSE_POP_V2,
    /// portable)` (`portable` = typed `UAPortableRecord`) (it refuses a key of another set's length or with a coefficient
    /// `≥ q`; `UAPoP`), capped with the hold, then the proven key's owner (`UAKeyInUse`, either generation), `keyOwner(h)`,
    /// the `0x0142` list; `UAPqzKeyCurrent(ua, 0)` when eligible. No `UAPqzKeyAdded` (F-10: `UARegistered` carries it).
    function _pqzAttach(bytes32 ua, IUARegistry.UAAttrs calldata attrs, bytes calldata pqzPop, bytes32 h, bytes32 portable)
        private
    {
        UAStore.Layout storage s = UAStore.layout();
        if (h == 0) return;
        s.pqzKey[ua][0].ptr = SSTORE2.write(attrs.pqzKey);
        s.pqzPopHash[ua][0] = attrs.pqzPopHash;
        s.pqzKeyUsed[ua][h] = true;
        if (pqzPop.length == 0) return;
        _pqzProof(ua, 0, attrs.pqzKey, pqzPop, h, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, portable),
            pqzPop[0:0]);
    }

    /// Version `v`'s proof bytes stored; where slot 0x0142 has a verifier and it accepts `pqzPop` over `message`, proven
    /// (`_pqzOwn`). Eligible (KV-3): proven, or without the verifier this build's set length (C2, F-1: its bytes are stored
    /// here); an eligible version may become current (`_pqzCurrent`).
    function _pqzProof(bytes32 ua, uint64 v, bytes memory pqzKey, bytes calldata pqzPop, bytes32 h, bytes32 message,
        bytes calldata logged) internal
    {
        UAStore.layout().pqzPop[ua][v] = SSTORE2.writeChunks(pqzPop);
        uint256 cfg = _cfgPqz();
        bool proven = uint160(cfg) != 0;
        if (proven) {
            bytes memory data = abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, pqzKey, message, pqzPop);
            if (!UAStore.capped(address(uint160(cfg)), cfg >> 160, data, 1, true)) revert IUARegistry.UAPoP();
            _pqzOwn(ua, v, h);
        }
        emit IUARegistry.UAPqzPopStored(ua, v, UAStore.checked(proven), logged);
        if (proven || pqzKey.length == PqzSet.PK) _pqzCurrent(ua, v);
    }

    /// A proven version: its owner (`UAKeyInUse` for a hash any UA owns, this one included: KV-2), `keyOwner`, the `0x0142`
    /// list once per UA (decoys are drawn per UA, never per version), `proven`.
    function _pqzOwn(bytes32 ua, uint64 v, bytes32 h) internal {
        UAStore.Layout storage s = UAStore.layout();
        bytes32 owner = _keyOwner(h);
        if (owner != 0) revert IUARegistry.UAKeyInUse(h, owner);
        s.keyOwner[h] = ua;
        UAStore.PqzVersions storage vs = s.pqzVersions[ua];
        if (!vs.listed) {
            _list(UAKinds.PQZ_MLWE, ua);
            vs.listed = true;
        }
        s.pqzKey[ua][v].proven = true;
    }

    /// An eligible version at or above `current` becomes current (KV-3: `current` never goes down; equal only for version
    /// 0, whose proof is stored once), `UAPqzKeyCurrent`.
    function _pqzCurrent(bytes32 ua, uint64 v) internal {
        UAStore.PqzVersions storage vs = UAStore.layout().pqzVersions[ua];
        if (v < vs.current) return;
        vs.current = v;
        emit IUARegistry.UAPqzKeyCurrent(ua, v);
    }

    /// A portable record's `UASig` (`setPqzKey`, `setKemKey` ≥ 1): never `keyData`; `signature` or `members` (`_sigOk`).
    function _portableOk(uint16 kind, bytes memory d, bytes32 ua, bytes32 purpose, bytes32 digest,
        IUARegistry.UASig calldata sig) internal view returns (bool)
    {
        return sig.keyData.length == 0 && _sigOk(_cfgKind(), kind, d, ua, purpose, digest, sig.signature, sig.members);
    }

    // ----- the helpers `UARegistryAuxLib` calls (T66b 3.1c, owner 2026-11-09, spec 2026-11-09-t66b-library-organisation.md §11 (f)) -----

    /// One copy of the shared code in the pair: `UARegistryAuxLib` runs these by a nested DELEGATECALL (its `_core`), this
    /// call's arguments followed by the three words the registry appended to the Aux entry, so `address(this)`, the storage
    /// and `_cfgKind` / `_cfgPqz` / `_cloneHash` are the registry's, as when the Aux library compiled this code in. Each is its
    /// `internal` twin and nothing else. None is `view` or `pure`: solc's library call protection covers each, a direct call
    /// reverts.
    function portableOk(uint16 kind, bytes memory d, bytes32 ua, bytes32 purpose, bytes32 digest,
        IUARegistry.UASig calldata sig) external returns (bool)
    {
        return _portableOk(kind, d, ua, purpose, digest, sig);
    }

    function pqzHolder(uint16 kind, bytes memory d, bytes32 ua, bool gen1) external {
        _pqzHolder(kind, d, ua, gen1);
    }

    /// `_pqzProof` with the proof bytes logged (`storePqzPop`).
    function pqzProof(bytes32 ua, uint64 v, bytes memory pqzKey, bytes calldata pqzPop, bytes32 h, bytes32 message) external {
        _pqzProof(ua, v, pqzKey, pqzPop, h, message, pqzPop);
    }

    /// `kind`'s validated key data (`UAKinds.validateKeyData`, not Hedera-native) and its id (`cacheExpandedKey`).
    function keyUa(uint16 kind, bytes memory keyData) external returns (bytes32) {
        UAKinds.validateKeyData(kind, keyData, false);
        return UAKinds.uaOf(kind, keyData);
    }

    // ----- the portable check (UA-7 O1, owner 2026-11-04; plan T66a) -----

    /// `IUARegistry.requirePortable` on a record held here (the registry forwards a gen-1 record to gen 1 first): a single key by
    /// `_portableOk`, the path `setKemKey` and `setPqzKey` take; an `msig` by `_msig` over its accepted slots, minimal, whatever its PQ
    /// weight (`_sigOk`'s empty `pop` of a classical-dominant `msig` is the registration's rule, never a signature). No write: the registry
    /// runs it inside its view.
    function requirePortable(bytes32 ua, bytes32 purposeTag, bytes32 typedDigest, IUARegistry.UASig calldata auth) external {
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        // the registration's `pop` is `register`'s own check (its slots need no acceptance): never a view's
        if (r.kind == 0 || purposeTag == UAKinds.PURPOSE_POP_V2) revert IUARegistry.UAUnauthorized(ua);
        (bytes memory d,) = UAStore.registration(ua, r.keyPtr);
        bool ok;
        if (r.kind != UAKinds.MSIG) {
            ok = _portableOk(r.kind, d, ua, purposeTag, typedDigest, auth);
        } else {
            _portablePurpose(ua, purposeTag);
            bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purposeTag, typedDigest));
            ok = auth.keyData.length == 0 && auth.signature.length == 0 && _msig(ua, md, typedDigest, false, d, auth.members);
        }
        if (!ok) revert IUARegistry.UAUnauthorized(ua);
    }

    // ----- acceptance (CTR-UA-37) -----

    /// Slot `memberSig.index` of the `msig` `ua` accepts its place (`IUARegistry.acceptMembership`): the check of a stored
    /// record's member (`_memberOk`) over typed(`UAMembership{ua, member}`), no threshold, no minimal form: one slot speaks
    /// for itself. A gen-1 record on gen 2 is refused here as in `setKemKey` (UA8-D11): the bits live with the record, gen 1.
    function acceptMembership(bytes32 ua, IUARegistry.MemberSig calldata memberSig) external {
        UAStore.Layout storage s = UAStore.layout();
        if (s.records[ua].kind != UAKinds.MSIG) revert IUARegistry.UAUnauthorized(ua);
        bytes memory d = UAStore.keyRest(ua);
        uint16 index = memberSig.index;
        if (index >= UAStore.u16(d, 2)) revert IUARegistry.UAUnauthorized(ua);
        uint256 bits = s.accepted[ua];
        if (bits >> index & 1 != 0) return;
        bytes32 member = bytes32(UAStore.word(d, 4 + 36 * uint256(index) + 2));
        bytes32 typed = UAKinds.membershipDigest(ua, member);
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBERSHIP, typed));
        if (!_memberOk(d, md, typed, memberSig, true)) revert IUARegistry.UAUnauthorized(ua);
        s.accepted[ua] = bits | 1 << index;
        // owner 2026-11-03: the hash kept, written once as the bit it goes with, the bytes in `UAMemberSig`: a copy checks them against
        // `memberSigHashOf` and replays them
        _memberSig(ua, d, index, UAKinds.PURPOSE_MEMBERSHIP, memberSig.members.length == 0 ? memberSig.sig : abi.encode(memberSig.members));
        emit IUARegistry.UAMembershipAccepted(ua, index, member);
    }

    /// Empty -> `UAKemKeyLength`; scheme id (first byte) not enabled -> `UAKemScheme`; other length -> `UAKemKeyLength`.
    function _checkKemPk(bytes memory pk) internal pure {
        if (pk.length == 0) revert IUARegistry.UAKemKeyLength(0);
        _checkKemScheme(uint8(pk[0]));
        if (pk.length != UAKinds.KEM_PK_LENGTH) revert IUARegistry.UAKemKeyLength(pk.length);
    }

    function _checkKemScheme(uint8 scheme) internal pure {
        if (scheme != UAKinds.KEM_SCHEME_MLKEM1024_X25519) revert IUARegistry.UAKemScheme(scheme);
    }

    // ----- the portable signature -----

    /// Step 6 (and `setKemKey`, `setPqzKey`): a portable record's signature over `uaMessage(kind, purpose, digest)`.
    /// `msig`: no signature unless PQ-eligible, then the m-of-n `members` (under `member`, U5; a native member over the
    /// typed `digest` itself, by ECDSA or ERC-1271), `sig` empty; single keys: `sig` by the kind's
    /// verifier (`verifyPop`), no `members`. Only the portable purposes reach this chain-free path (`_portablePurpose`).
    /// `cfg`: the registry's `_cfg(kind)`. `internal` for `SigOkHarness` (ruling A5-m3).
    function _sigOk(
        uint256 cfg,
        uint16 kind,
        bytes memory d,
        bytes32 ua,
        bytes32 purpose,
        bytes32 digest,
        bytes memory sig,
        IUARegistry.MemberSig[] memory members
    ) internal view returns (bool) {
        _portablePurpose(ua, purpose);
        if (kind == UAKinds.MSIG) {
            if (sig.length != 0) return false;
            if (!_pqEligible(d)) return members.length == 0;
            bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purpose, digest));
            return members.length != 0 && _msig(ua, md, digest, purpose == UAKinds.PURPOSE_POP_V2, d, members);
        }
        if (members.length != 0) return false;
        // A6-I1: a gen-1 holder's PQZ key record on gen 2 (the PQ holder kinds are stored: no key data in `auth`); the
        // PQ verifiers' `verify` is their `verifyPop`
        if (uint160(cfg) == 0) return UAStore.via(_pred(), ua, purpose, digest, IUARegistry.UASig("", sig, members));
        bytes32 message = UAKinds.uaMessage(kind, purpose, digest);
        bytes memory ek = UAStore.expanded(ua, kind); // ML-DSA: a complete cache is the key the PoP verifies on
        bytes memory data = ek.length != 0
            ? abi.encodeWithSelector(UAMldsaVerifier.verifyCached.selector, ek, message, sig)
            : abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, d, message, sig);
        // group kinds: the whole group check runs here, bounded by verifyBudget (§1.8 step 6), without the hold
        if (kind >= UAKinds.MUSIG2_SECP256K1 && kind <= UAKinds.FROST_BN254) {
            return UAStore.capped(address(uint160(cfg)), IUARegistry(address(this)).verifyBudget(), data, 1, false);
        }
        return UAStore.capped(address(uint160(cfg)), cfg >> 160, data, 1, true);
    }

    /// The portable purposes (POP_V2, KEM, PQZ_KEY; rulings A1-f1, A5-m3; PQCHAT, UA-7 O1): any other purpose reverts `UAUnauthorized`
    /// (writes stay on `requireAuthorized`, UAAuth for native members).
    function _portablePurpose(bytes32 ua, bytes32 purpose) internal pure {
        if (
            purpose != UAKinds.PURPOSE_POP_V2 && purpose != UAKinds.PURPOSE_KEM && purpose != UAKinds.PURPOSE_PQZ_KEY
                && purpose != UAKinds.PURPOSE_PQCHAT
        ) revert IUARegistry.UAUnauthorized(ua);
    }

    /// accounts.md §1.9 `msig` row, a portable record's signature (`_sigOk` and `requirePortable` only — never `requireAuthorized`; rulings C7 /
    /// A1-I2 / A1-f1, owner 2026-10-30): strictly increasing member indexes, stop at the threshold (a MemberSig after it
    /// fails, which keeps the registration bound sound), `member_digest = keccak256(ua ‖ ua_msg)`. A native member signs
    /// the record's typed digest `digest` itself (typed-signing TS-D4, owner decision 4: `eth_signTypedData_v4`; an EOA:
    /// code-less or an EIP-7702 designator, its own key only) or, a contract, answers ERC-1271 over `digest`. Derived members
    /// sign `member_digest` under `member`. (The members come typed, TS-D12: no encoding to canonicalise.) A stored signature
    /// is minimal too (owner 2026-10-31, U8S-D1): with T the slots' total weight and N the threshold, T >= N and
    /// T - weight(i) < N for every slot, i.e. T - min(weight) < N.
    /// Only an accepted slot counts (CTR-UA-37), except in the registration's own `pop` (`pop`), which is what accepts its signers.
    /// An `msig` member is this same check one level down: its members sign under `member`, its native members `typed` still, its
    /// slots are minimal too and count only if accepted in it, a `pop` above exempting no slot of it (spec 2026-11-02-msig-nested).
    /// `md`: this structure's `member_digest`; `typed`: the record's typed digest, the same at both levels.
    function _msig(bytes32 ua, bytes32 md, bytes32 typed, bool pop, bytes memory d, IUARegistry.MemberSig[] memory sigs)
        private
        view
        returns (bool)
    {
        uint256 threshold = UAStore.u16(d, 0);
        uint256 acc;
        // the slots that may sign: past the members is none of them
        uint256 yes = (pop ? type(uint256).max : _accepted(ua, sigs)) & ((1 << UAStore.u16(d, 2)) - 1);
        bool here = pop || UAStore.layout().records[ua].kind != 0;
        uint256 wMin = type(uint256).max; // the smallest slot weight
        uint256 next; // lowest index the next MemberSig may use
        for (uint256 i; i < sigs.length; ++i) {
            IUARegistry.MemberSig memory s = sigs[i];
            if (acc >= threshold || s.index < next || yes >> s.index & 1 == 0) return false;
            next = uint256(s.index) + 1;
            if (!_memberOk(d, md, typed, s, here)) return false;
            uint256 w = UAStore.u16(d, 4 + 36 * uint256(s.index) + 34);
            acc += w;
            if (w < wMin) wMin = w;
        }
        return acc >= threshold && acc - wMin < threshold;
    }

    /// The accepted bits `sigs` are checked against: one read for a record held here. The bits live with the record, so a gen 2
    /// hosting a gen-1 record (`setPqzKey`) asks gen 1 slot by slot, that word having no getter; gen 1's view cannot revert but out of
    /// gas, and a starved caller sees `UAVerifyGas`, never a verdict.
    function _accepted(bytes32 ua, IUARegistry.MemberSig[] memory sigs) internal view returns (uint256 bits) {
        UAStore.Layout storage s = UAStore.layout();
        if (s.records[ua].kind != 0) return s.accepted[ua];
        IUARegistry g1 = IUARegistry(_pred());
        for (uint256 i; i < sigs.length; ++i) {
            uint256 index = sigs[i].index;
            try g1.memberAccepted(ua, index) returns (bool yes) {
                if (yes) bits |= 1 << index;
            } catch {
                revert UAKinds.UAVerifyGas();
            }
        }
    }

    /// The signature `s` of member `s.index` of the structure `d`: a registered member over `md` under `member`, without key
    /// data (the registry reads the member's record, CTR-UA-33); a native member over the typed digest `typed`; an `msig` member by
    /// `_msig`, under `member` over `md`. `here`: this registry holds the structure, else gen 1 does and a clone is one of gen 1's, with the 400 k
    /// cap `_slotCap` counted for it.
    function _memberOk(bytes memory d, bytes32 md, bytes32 typed, IUARegistry.MemberSig memory s, bool here) internal view returns (bool) {
        uint256 o = 4 + 36 * uint256(s.index);
        (uint16 kind, bytes32 id) = (uint16(UAStore.u16(d, o)), bytes32(UAStore.word(d, o + 2)));
        if (kind == UAKinds.MSIG) {
            bytes32 inner = UAKinds.memberDigest(id, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBER, md));
            return s.sig.length == 0 && _msig(id, inner, typed, false, _msigBytes(id), UAStore.lift(s.members));
        }
        if (s.members.length != 0) return false;
        if (!UAKinds.isNative(kind)) {
            return UAStore.via(address(this), id, UAKinds.PURPOSE_MEMBER, md,
                IUARegistry.UASig("", s.sig, new IUARegistry.MemberSig[](0)));
        }
        return UAStore.byCode(address(uint160(uint256(id))), typed, s.sig, here ? _cloneHash() : IUARegistry(_pred()).smartKeyCloneHash());
    }

    // ----- the msig bound -----

    /// Step 4 for `msig`: every member ∈ MEMBER of this profile and native or registered under its stated kind; the
    /// worst case of a minimal authorizing set (the `c` largest caps + `c` × `MSIG_MEMBER_GAS` + `MSIG_ACCEPTED_GAS`, + the caller's
    /// hold for the largest single cap, at either level, beyond the 400 k that `MSIG_MEMBER_GAS` covers) fits `verifyBudget`;
    /// `nativeCap` what one native slot of `d` may spend in the generation that verifies it.
    function _membersWorst(bytes memory d, uint256 nativeCap) internal view returns (uint256 worst) {
        IUARegistry self = IUARegistry(address(this));
        uint256 held;
        (worst, held) = _worst(d, false, nativeCap, self.hederaNative());
        if (held > UAStore.SMART_KEY_1271_GAS) worst += (held - UAStore.SMART_KEY_1271_GAS) / 63;
        if (worst > self.verifyBudget()) revert IUARegistry.UAKeyData(UAKinds.MSIG);
    }

    /// One level of the bound: the worst of `d` without the caller's hold, and the largest single cap in it (`held`). An `msig` member
    /// counts its own worst as its cap, so the total is every signature across both levels, plain members and inner thresholds
    /// together; `inner`: this is that member, and it may hold no `msig` (`UAMemberUnknown`: two levels only).
    function _worst(bytes memory d, bool inner, uint256 nativeCap, bool hedera) internal view returns (uint256 worst, uint256 held) {
        (uint256 threshold, uint256 count) = (UAStore.u16(d, 0), UAStore.u16(d, 2));
        uint256[] memory weights = new uint256[](count);
        uint256[] memory caps = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            uint256 h;
            (caps[i], h) = _slotCap(uint16(UAStore.u16(d, o)), bytes32(UAStore.word(d, o + 2)), inner, nativeCap, hedera);
            if (h > held) held = h;
            weights[i] = UAStore.u16(d, o + 34);
        }
        _sort(caps);
        uint256 c = _quorum(weights, threshold);
        worst = c * MSIG_MEMBER_GAS + MSIG_ACCEPTED_GAS;
        for (uint256 i; i < c; ++i) {
            worst += caps[count - 1 - i];
        }
    }

    /// How many of the lightest slots reach `threshold`: no quorum has more (a minimal one, or one that stops at the threshold).
    function _quorum(uint256[] memory weights, uint256 threshold) internal pure returns (uint256 c) {
        _sort(weights);
        for (uint256 acc; acc < threshold; ++c) {
            acc += weights[c];
        }
    }

    /// The bytes of the largest `MemberSig[]` a quorum of `d` signs (spec 2026-11-02-msig-nested §2): a signing slot `head + ⌈sig / 32⌉ × 32`,
    /// `head` 192, 128 for a leaf of an inner list; an `msig` slot 192 and its own largest list.
    function _authBytes(bytes memory d, uint256 head) internal view returns (uint256 n) {
        (uint256 threshold, uint256 count) = (UAStore.u16(d, 0), UAStore.u16(d, 2));
        uint256[] memory weights = new uint256[](count);
        uint256[] memory sizes = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            weights[i] = UAStore.u16(d, o + 34);
            sizes[i] = head + _slotBytes(uint16(UAStore.u16(d, o)), bytes32(UAStore.word(d, o + 2)));
        }
        _sort(sizes);
        uint256 c = _quorum(weights, threshold);
        for (uint256 i; i < c; ++i) {
            n += sizes[count - 1 - i];
        }
    }

    function _slotBytes(uint16 kind, bytes32 id) internal view returns (uint256) {
        return kind == UAKinds.MSIG ? _authBytes(_msigBytes(id), 128) : (_sigBytes(kind) + 31) / 32 * 32;
    }

    /// A signature's bytes. ponytail: one figure for every classical kind and native member, 1,024 B over a WebAuthn assertion and over a wallet's usual
    /// ERC-1271 bytes; a wallet with a longer signature is its own limit, per-kind sizes if a holder ever sits near the edge on classical slots.
    function _sigBytes(uint16 kind) internal pure returns (uint256) {
        if (kind == UAKinds.MLDSA44) return 2_420;
        if (kind == UAKinds.MLDSA65) return 3_309;
        if (kind == UAKinds.FNDSA512) return 666;
        if (kind == UAKinds.SLHDSA128S) return 7_856;
        if (kind == UAKinds.MLDSA87) return 4_627;
        if (kind == UAKinds.FNDSA1024) return 1_280;
        return 1_024;
    }

    /// What one slot may spend (`cap`) and the largest single cap in it (`held`): a native member's, a registered kind's, or an `msig`
    /// member's own worst. A record gen 1 holds is one more call level: `cap / 63 + GAS_MARGIN`, as a member of a kind gen 1 alone
    /// enables; gen 1's natives may be clones of its own, so they count 400 k there.
    function _slotCap(uint16 kind, bytes32 id, bool inner, uint256 nativeCap, bool hedera)
        private view returns (uint256 cap, uint256 held)
    {
        IUARegistry self = IUARegistry(address(this));
        if (!UAKinds.isMember(kind, hedera)) revert IUARegistry.UAMemberUnknown(id);
        if (UAKinds.isNative(kind)) return (nativeCap, nativeCap);
        if (self.kindOf(id) != kind) revert IUARegistry.UAMemberUnknown(id);
        if (kind == UAKinds.MSIG) {
            if (inner) revert IUARegistry.UAMemberUnknown(id);
            bool here = UAStore.layout().records[id].kind != 0;
            (cap, held) = _worst(_msigBytes(id), true, here ? nativeCap : UAStore.SMART_KEY_1271_GAS, hedera);
            if (!here) cap += cap / 63 + SigCheck.GAS_MARGIN;
            return (cap, held);
        }
        cap = self.verifyCap(kind); // 0: this generation does not enable the kind (an enabled cap is ≠ 0)
        if (cap == 0) {
            // handed to gen 1, which holds cap / 63 + GAS_MARGIN again inside the 63/64 gen 2 gives it; gen 2 holds for it too
            cap = IUARegistry(self.predecessor()).verifyCap(kind);
            cap = cap + cap / 63 + SigCheck.GAS_MARGIN;
        }
        return (cap, cap);
    }

    /// A native member may be (or later become, counterfactually) a `SmartKeyAccount` clone: the bound takes its cap.
    function _nativeCap() internal view returns (uint256) {
        return _cloneHash() != 0 ? UAStore.SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
    }

    /// Insertion sort, ascending (count ≤ 16).
    function _sort(uint256[] memory a) internal pure {
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
