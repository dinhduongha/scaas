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

/// @title `UARegistry`'s write paths (typed-signing R2, owner 2026-11-01): registration, the PQZ attachment, KEM records and
///        the ML-DSA cache, run by DELEGATECALL from a thin entry per function, so `address(this)` is the registry and
///        the storage is its `UAStore.Layout`. Same check order, same stored bytes, same events and errors as when this
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
///         Called directly every entry reverts: solc's library call protection covers each one, none is `view` or `pure`.
///         `acceptMembership` (CTR-UA-37) runs here too; its member check is `_memberOk`, as a stored record's.
///         UNAUDITED.
library UARegistryLib {
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

    // ----- the appended words -----

    function _cfgKind() private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := calldataload(sub(calldatasize(), 96))
        }
    }

    function _cfgPqz() private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := calldataload(sub(calldatasize(), 64))
        }
    }

    function _cloneHash() private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := calldataload(sub(calldatasize(), 32))
        }
    }

    // ----- the getters, on the registry -----

    function _pred() private view returns (address) {
        return IUARegistry(address(this)).predecessor();
    }

    function _kindOf(bytes32 ua) private view returns (uint16) {
        return IUARegistry(address(this)).kindOf(ua);
    }

    function _keyOwner(bytes32 h) private view returns (bytes32) {
        return IUARegistry(address(this)).keyOwner(h);
    }

    // ----- ML-DSA expanded-key cache (P6c; owner 2026-10-12) -----

    /// Stores part `part` of the expanded key of `pk` under `uaOf(kind, pk)`, computed by the kind's verifier
    /// (`expandedKeyPart`) from the authenticated `pk` — never accepted from a caller (a caller-supplied expanded key
    /// allows universal forgery). Anyone may call it, before or after `register`; a part already stored is left as it
    /// is (a front-runner stored the same bytes). Each part is one transaction (ML-DSA-65 part 1: ≈ 13.4 M gas).
    /// Reverts `UAKeyCache(kind)` for a kind other than ML-DSA, a disabled kind, a part past the last, or a verifier
    /// that uses a precompile; `UAKeyData` for a key of the wrong length.
    function cacheExpandedKey(uint16 kind, bytes calldata pk, uint256 part) external returns (bytes32 ua) {
        UAStore.Layout storage s = UAStore.layout();
        address v = address(uint160(_cfgKind()));
        if (
            (kind != UAKinds.MLDSA44 && kind != UAKinds.MLDSA65) || v == address(0) || part >= _ekParts(kind)
                || UAMldsaVerifier(v).PRECOMPILE() != address(0)
        ) revert IUARegistry.UAKeyCache(kind);
        bytes memory d = pk;
        UAKinds.validateKeyData(kind, d, false);
        ua = UAKinds.uaOf(kind, d);
        if (s.ekPtr[ua][part] != address(0)) return ua;
        address ptr = SSTORE2.write(UAMldsaVerifier(v).expandedKeyPart(pk, part));
        s.ekPtr[ua][part] = ptr;
        emit IUARegistry.UAKeyCached(ua, kind, part, ptr);
    }

    function _ekParts(uint16 kind) private pure returns (uint256) {
        return kind == UAKinds.MLDSA44 ? 1 : 2;
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
    function _frostMember(uint16 kind, IUARegistry.FrostMember calldata m, uint256 t) private pure returns (bytes memory d) {
        uint256 size = UAStore.vkLength(kind);
        if (m.commitments.length != t) revert IUARegistry.UAKeyData(kind);
        for (uint256 j; j < t; ++j) {
            d = bytes.concat(d, _point(kind, m.commitments[j], size));
        }
        d = bytes.concat(d, _point(kind, m.r, size), m.z);
    }

    /// One point of a typed key: exactly `size` bytes (its validity is `validateKeyData`'s, on the assembled bytes).
    function _point(uint16 kind, bytes calldata p, uint256 size) private pure returns (bytes calldata) {
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

    /// Steps 1–8. `sig` (single keys) or `members` (an msig) is the PoP; the stored `pop` is `sig`, or
    /// `abi.encode(members)` ("" for none).
    function _register(uint16 kind, bytes memory d, IUARegistry.UAAttrs calldata attrs, bytes memory sig,
        IUARegistry.MemberSig[] memory members, bytes calldata pqzPop) private returns (bytes32 ua)
    {
        UAStore.Layout storage s = UAStore.layout();
        bytes32 kh;
        (ua, kh) = _identify(kind, d); // 1–4
        _consent(kind, d, ua, attrs, sig, members, pqzPop); // 5–7
        bytes memory pop = members.length != 0 ? abi.encode(members) : sig;
        _record(ua, kind, d, kh, attrs, pop); // 8
        // CTR-UA-37: a slot that signed the `pop` agreed; an empty `pop` writes nothing
        if (members.length != 0) {
            uint256 bits;
            for (uint256 i; i < members.length; ++i) {
                bits |= 1 << members[i].index;
            }
            s.accepted[ua] = bits;
        }
        (uint8 q, uint8 k) = (UAStore.checked(s.pqzKey[ua].proven), UAStore.checked(s.kem[ua][0].length != 0));
        emit IUARegistry.UARegistered(ua, kind, d, attrs, keccak256(pop), pqzPop, UAKinds.CHECKED_CHAIN, q, k);
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
    ) private {
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
    function _list(uint16 kind, bytes32 ua) private returns (uint40) {
        UAStore.Layout storage s = UAStore.layout();
        uint256 n = s.uaCount[kind];
        s.uaAt[kind][n] = ua;
        s.uaCount[kind] = n + 1;
        return uint40(n);
    }

    /// Steps 1–4: kind enabled, key data canonical, the id (not native-space, not registered here or in gen 1), the
    /// keyHash (single keys) or the members (msig).
    function _identify(uint16 kind, bytes memory d) private view returns (bytes32 ua, bytes32 kh) {
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
    function _claim(uint16 kind, bytes memory d, bool structure) private view returns (bytes32 kh) {
        if (structure) {
            _membersWorst(d);
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
        if (pqz) _pqzHolder(kind, d, ua);
        if ((commit || kemPk.length != 0) && !_holder(kind, d)) revert IUARegistry.UAKemHolder(ua);
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
        address g1 = _pred();
        if (g1 != address(0) && IUARegistry(g1).kindEnabled(UAKinds.PQZ_MLWE)) {
            revert IUARegistry.UAKindDisabled(UAKinds.PQZ_MLWE);
        }
        if (!_holder(kind, d)) revert IUARegistry.UAPqzHolder(ua);
        // CTR-PQZ-12 (review2 C0-5, controller proposal, owner may override): an `msig` holder's worst-case
        // authorization plus the set's cheapest PQZL debit (its full relayed transaction, fee signer included) must fit
        // one transaction at the EIP-7825 cap 2^24, else every credit to it could be locked. Not the chain's own limit.
        // UA8-D12: the PQZ key only, not the KEM record.
        if (kind == UAKinds.MSIG) {
            // a gen-2 registry in front forwards the whole authorization to the one that holds the record
            // (`UAStore.via`) and holds 1/63 of it again plus the margin: counted here
            uint256 w = _membersWorst(d);
            if (w + w / 63 + SigCheck.GAS_MARGIN + PqzSet.PQZ_DEBIT_MIN_GAS > TX_GAS_CAP) revert IUARegistry.UAPqzHolder(ua);
        }
    }

    /// The PQZ keyHash (group `pqz-mlwe`); `UAKeyData(0x0142)` for a key of no parameter set's length.
    function _pqzKeyHash(bytes memory pqzKey) private pure returns (bytes32) {
        uint256 n = pqzKey.length; // PqzSet.PK of the four sets: 2,048 B per 256 of n, n 2,048 … 2,816
        if (n < 16_384 || n > 22_528 || n % 2_048 != 0) revert IUARegistry.UAKeyData(UAKinds.PQZ_MLWE);
        return UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqzKey);
    }

    /// An `msig` whose members of kinds outside 0x0130–0x0133 weigh less than its threshold (CTR-PQZ-12): it may hold
    /// a PQZ key and registers with an m-of-n PoP (U5).
    function _pqEligible(bytes memory d) private pure returns (bool) {
        (uint256 threshold, uint256 count) = (UAStore.u16(d, 0), UAStore.u16(d, 2));
        uint256 classical;
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            if (!UAStore.isPq(uint16(UAStore.u16(d, o)))) classical += UAStore.u16(d, o + 34);
        }
        return classical < threshold;
    }

    /// Step 7, the PQZ key (UA8-D8): the key (SSTORE2) and its proof hash; with `pqzPop`, the proof bytes, and where
    /// slot 0x0142 has a verifier `R_REG` over `uaMessage(0x0142, PURPOSE_POP_V2, portable)` (`portable` = typed
    /// `UAPortableRecord`) (it refuses a key of
    /// another set's length or with a coefficient `≥ q`; `UAPoP`), capped with the hold, then the proven key's owner
    /// (`UAKeyInUse`, either generation), `keyOwner(h)`, the `0x0142` list.
    function _pqzAttach(bytes32 ua, IUARegistry.UAAttrs calldata attrs, bytes calldata pqzPop, bytes32 h, bytes32 portable)
        private
    {
        UAStore.Layout storage s = UAStore.layout();
        if (h == 0) return;
        s.pqzKey[ua].ptr = SSTORE2.write(attrs.pqzKey);
        s.pqzPopHash[ua] = attrs.pqzPopHash;
        if (pqzPop.length == 0) return;
        _pqzProof(ua, attrs.pqzKey, pqzPop, h, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, portable), pqzPop[0:0]);
    }

    /// The proof bytes stored; proven where slot 0x0142 has a verifier and it accepts `pqzPop` over `message`.
    function _pqzProof(bytes32 ua, bytes memory pqzKey, bytes calldata pqzPop, bytes32 h, bytes32 message,
        bytes calldata logged) private returns (bool proven)
    {
        UAStore.Layout storage s = UAStore.layout();
        s.pqzPop[ua] = SSTORE2.writeChunks(pqzPop);
        uint256 cfg = _cfgPqz();
        if (uint160(cfg) != 0) {
            bytes memory data = abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, pqzKey, message, pqzPop);
            if (!UAStore.capped(address(uint160(cfg)), cfg >> 160, data, 1, true)) revert IUARegistry.UAPoP();
            bytes32 owner = _keyOwner(h);
            if (owner != 0) revert IUARegistry.UAKeyInUse(h, owner);
            s.keyOwner[h] = ua;
            _list(UAKinds.PQZ_MLWE, ua);
            s.pqzKey[ua].proven = proven = true;
        }
        emit IUARegistry.UAPqzPopStored(ua, UAStore.checked(proven), logged);
    }

    // ----- the PQZ proof later (UA8-D8, P8) and the PQZ key later (ruling A1-I1) -----

    function storePqzPop(bytes32 ua, bytes calldata pqzPop) external {
        UAStore.Layout storage s = UAStore.layout();
        bool host = _host(ua);
        if (pqzPop.length == 0) revert IUARegistry.UAPqzPopHash(ua); // an empty proof is no proof (ruling A6-m)
        UAStore.PqzKey memory k = s.pqzKey[ua];
        bytes32 ph = s.pqzPopHash[ua];
        if (host && k.ptr == address(0)) {
            // gen 1's key (from its `register` or `setPqzKey`), proven in this generation (ruling A6-I1)
            address g1 = _pred();
            (k.ptr, ph,) = IUARegistry(g1).pqzKeyOf(ua);
            k.added = IUARegistry(g1).pqzKeySigOf(ua).length != 0;
        }
        if (keccak256(pqzPop) != ph) revert IUARegistry.UAPqzPopHash(ua); // no PQZ key: the hash is 0
        if (s.pqzPop[ua].length != 0) return; // stored: proven, or never provable here (no verifier)
        bytes memory key = SSTORE2.read(k.ptr);
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key);
        bytes32 message = k.added
            ? UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyDigest(ua, h))
            : _registerKeyMessage(ua, h, host);
        if (host) {
            s.pqzKey[ua] = k;
            s.pqzPopHash[ua] = ph;
        }
        _pqzProof(ua, key, pqzPop, h, message, pqzPop);
    }

    /// The R_REG message of a `register` key: `uaMessage(0x0142, PURPOSE_POP_V2, typed(UAPortableRecord))` with the
    /// registering kind from either generation (a gen-1 record on its gen-2 host: `kindOf` reads gen 1).
    function _registerKeyMessage(bytes32 ua, bytes32 h, bool host) private view returns (bytes32) {
        bytes32 d = UAKinds.portableRecordDigest(ua, _kindOf(ua), h, _kemHash(ua, host));
        return UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, d);
    }

    /// The initial KEM record's struct hash (the zero record = none) that `register`'s PoP signed: version 0 — the key,
    /// or its committed hash, filled or not (owner 2026-10-31) —, of the `register` arguments here or gen 1's.
    function _kemHash(bytes32 ua, bool host) private view returns (bytes32) {
        UAStore.Layout storage s = UAStore.layout();
        IUARegistry.KemKey memory kem;
        bytes32 committed;
        if (host) {
            (,, IUARegistry.UAAttrs memory a,,) = IUARegistry(_pred()).registrationOf(ua);
            (kem, committed) = (a.kem, a.kemPkHash);
        } else {
            UAStore.KemCommit memory c = s.kemCommit[ua];
            if (c.kemPkHash != 0) return UAKinds.kemRecordHash(ua, 0, c.scheme, c.kemPkHash);
            (kem,) = UAStore.kemAt(ua, 0);
        }
        if (committed != 0) return UAKinds.kemRecordHash(ua, 0, kem.scheme, committed);
        return UAKinds.kemRecordHash(ua, 0, UAKinds.kemPk(kem));
    }

    /// Where `storePqzPop` / `setPqzKey` write (ruling A6-I1): false = the record is here; true = gen 1 holds it and this
    /// gen 2 enables 0x0142 (its constructor refuses 0x0142 when gen 1 enables it, so this is the oldest generation
    /// with the verifier); else `UAUnauthorized` (unregistered, or a gen-1 record on a gen 2 without 0x0142: UA8-D11).
    function _host(bytes32 ua) private view returns (bool) {
        UAStore.Layout storage s = UAStore.layout();
        if (s.records[ua].kind != 0) return false;
        if (_pred() != address(0) && uint160(_cfgPqz()) != 0 && _kindOf(ua) != 0) return true;
        revert IUARegistry.UAUnauthorized(ua);
    }

    function setPqzKey(bytes32 ua, bytes calldata pqzKey, bytes32 pqzPopHash, IUARegistry.UASig calldata sig) external {
        UAStore.Layout storage s = UAStore.layout();
        bool host = _host(ua);
        uint16 kind;
        bytes memory d;
        if (host) {
            (kind, d,,,) = IUARegistry(_pred()).registrationOf(ua);
        } else {
            IUARegistry.Record memory r = s.records[ua];
            kind = r.kind;
            (d,) = UAStore.registration(ua, r.keyPtr);
        }
        _pqzHolder(kind, d, ua);
        _pqzKeyFree(ua, host);
        bytes32 h = _pqzKeyHash(pqzKey);
        if (pqzPopHash == 0 || pqzPopHash == EMPTY_PROOF_HASH) revert IUARegistry.UAPqzPopHash(ua);
        bytes32 rd = UAKinds.pqzKeyRecordDigest(ua, h, pqzPopHash);
        if (!_portableOk(kind, d, ua, UAKinds.PURPOSE_PQZ_KEY, rd, sig)) revert IUARegistry.UAUnauthorized(ua);
        bytes memory stored = _portableBytes(sig);
        s.pqzKey[ua] = UAStore.PqzKey(SSTORE2.write(pqzKey), false, true);
        s.pqzPopHash[ua] = pqzPopHash;
        s.pqzKeySig[ua] = SSTORE2.writeChunks(stored);
        emit IUARegistry.UAPqzKeyAdded(ua, h, pqzPopHash, pqzKey, stored);
    }

    /// A portable record's `UASig` (`setPqzKey`, `setKemKey` ≥ 1): never `keyData`; `signature` or `members` (`_sigOk`).
    function _portableOk(uint16 kind, bytes memory d, bytes32 ua, bytes32 purpose, bytes32 digest,
        IUARegistry.UASig calldata sig) private view returns (bool)
    {
        return sig.keyData.length == 0 && _sigOk(_cfgKind(), kind, d, ua, purpose, digest, sig.signature, sig.members);
    }

    /// The stored bytes of a portable `UASig`: `signature`, or an msig's `abi.encode(members)` (the pre-R1 form).
    function _portableBytes(IUARegistry.UASig calldata sig) private pure returns (bytes memory) {
        return sig.members.length != 0 ? abi.encode(sig.members) : sig.signature;
    }

    /// `setPqzKey`'s `UAPqzKeySet` (ruling R-cross-set): the UA has a PQZ key here (gen 2 host: in either generation), and
    /// it stays (write-once) unless this chain can never prove it: slot 0x0142 has a verifier and the key, unproven, is
    /// not of this build's set length (`PqzSet.PK`, the verifier's own length check). Without the verifier nothing is
    /// replaced (nothing can be proven here either way). A replaced `register` key is kept for `registrationOf`.
    function _pqzKeyFree(bytes32 ua, bool host) private {
        UAStore.Layout storage s = UAStore.layout();
        UAStore.PqzKey memory old = s.pqzKey[ua];
        address pk = old.ptr;
        if (host && pk == address(0)) (pk,,) = IUARegistry(_pred()).pqzKeyOf(ua); // gen 1's key counts
        if (pk == address(0)) return;
        if (old.proven || uint160(_cfgPqz()) == 0 || pk.code.length - 1 == PqzSet.PK) revert IUARegistry.UAPqzKeySet(ua);
        if (!host && !old.added) (s.regPqzKey[ua], s.regPqzPopHash[ua]) = (pk, s.pqzPopHash[ua]);
    }

    // ----- KEM records (P4, P5, P7; UA8-D3–D5, D11, D12) -----

    function setKemKey(bytes32 ua, uint64 version, IUARegistry.KemKey calldata kem, IUARegistry.UASig calldata sig) external {
        UAStore.Layout storage s = UAStore.layout();
        IUARegistry.Record memory r = s.records[ua];
        // UA8-D11 before `_sigOk`: its gen-1 fallback would verify a gen-1 holder's record here (A6 re-review)
        if (r.kind == 0) revert IUARegistry.UAUnauthorized(ua);
        (bytes memory d,) = UAStore.registration(ua, r.keyPtr);
        if (!_holder(r.kind, d)) revert IUARegistry.UAKemHolder(ua);
        // owner 2026-10-31: never overwrite (every version write-once); version 0 only to fill the `register` commit
        if (s.kem[ua][version].length != 0) revert IUARegistry.UAKemVersion(ua, version);
        bytes32 committed = version == 0 ? s.kemCommit[ua].kemPkHash : bytes32(0);
        if (version == 0 && committed == 0) revert IUARegistry.UAKemVersion(ua, 0);
        bytes memory kemPk = UAKinds.kemPk(kem);
        _checkKemPk(kemPk);
        bytes memory stored;
        if (version == 0) {
            // the PoP signed the committed record: no signature of its own, anyone may fill it (as `storePqzPop`)
            if (sig.keyData.length != 0 || sig.signature.length != 0 || sig.members.length != 0) {
                revert IUARegistry.UAUnauthorized(ua);
            }
            if (keccak256(kemPk) != committed) revert IUARegistry.UAKemKeyHash(ua);
        } else {
            bytes32 rd = UAKinds.kemRecordDigest(ua, version, kemPk);
            if (!_portableOk(r.kind, d, ua, UAKinds.PURPOSE_KEM, rd, sig)) revert IUARegistry.UAUnauthorized(ua);
            stored = _portableBytes(sig);
            if (version > s.kemMax[ua]) s.kemMax[ua] = version;
        }
        s.kem[ua][version] = SSTORE2.writeChunks(bytes.concat(kemPk, stored));
        emit IUARegistry.UAKemKeySet(ua, version, keccak256(kemPk), kem, stored);
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
        if (!_memberOk(d, md, typed, memberSig)) revert IUARegistry.UAUnauthorized(ua);
        s.accepted[ua] = bits | 1 << index;
        emit IUARegistry.UAMembershipAccepted(ua, index, member);
    }

    /// Empty -> `UAKemKeyLength`; scheme id (first byte) not enabled -> `UAKemScheme`; other length -> `UAKemKeyLength`.
    function _checkKemPk(bytes memory pk) private pure {
        if (pk.length == 0) revert IUARegistry.UAKemKeyLength(0);
        _checkKemScheme(uint8(pk[0]));
        if (pk.length != UAKinds.KEM_PK_LENGTH) revert IUARegistry.UAKemKeyLength(pk.length);
    }

    function _checkKemScheme(uint8 scheme) private pure {
        if (scheme != UAKinds.KEM_SCHEME_MLKEM1024_X25519) revert IUARegistry.UAKemScheme(scheme);
    }

    // ----- the portable signature -----

    /// Step 6 (and `setKemKey`, `setPqzKey`): a portable record's signature over `uaMessage(kind, purpose, digest)`.
    /// `msig`: no signature unless PQ-eligible, then the m-of-n `members` (under `member`, U5; a native member over the
    /// typed `digest` itself, by ECDSA or ERC-1271), `sig` empty; single keys: `sig` by the kind's
    /// verifier (`verifyPop`), no `members`. Only the portable purposes (POP_V2, KEM, PQZ_KEY; rulings A1-f1, A5-m3)
    /// reach this chain-free path; any other purpose reverts `UAUnauthorized` (writes stay on `requireAuthorized`, UAAuth
    /// for native members). `cfg`: the registry's `_cfg(kind)`. `internal` for `SigOkHarness` (ruling A5-m3).
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
        if (purpose != UAKinds.PURPOSE_POP_V2 && purpose != UAKinds.PURPOSE_KEM && purpose != UAKinds.PURPOSE_PQZ_KEY) {
            revert IUARegistry.UAUnauthorized(ua);
        }
        if (kind == UAKinds.MSIG) {
            if (sig.length != 0) return false;
            if (!_pqEligible(d)) return members.length == 0;
            return members.length != 0 && _msig(ua, purpose, digest, d, members);
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

    /// accounts.md §1.9 `msig` row, a portable record's signature (`_sigOk` only — never `requireAuthorized`; rulings C7 /
    /// A1-I2 / A1-f1, owner 2026-10-30): strictly increasing member indexes, stop at the threshold (a MemberSig after it
    /// fails, which keeps the registration bound sound), `member_digest = keccak256(ua ‖ ua_msg)`. A native member signs
    /// the record's typed digest `digest` itself (typed-signing TS-D4, owner decision 4: `eth_signTypedData_v4`; an EOA:
    /// code-less or an EIP-7702 designator, its own key only) or, a contract, answers ERC-1271 over `digest`. Derived members
    /// sign `member_digest` under `member`. (The members come typed, TS-D12: no encoding to canonicalise.) A stored signature
    /// is minimal too (owner 2026-10-31, U8S-D1): with T the slots' total weight and N the threshold, T >= N and
    /// T - weight(i) < N for every slot, i.e. T - min(weight) < N.
    /// Only an accepted slot counts (CTR-UA-37), except in the registration's own `pop`, which is what accepts its signers.
    function _msig(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory d, IUARegistry.MemberSig[] memory sigs)
        private
        view
        returns (bool)
    {
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purposeTag, digest));
        (uint256 threshold, uint256 count) = (UAStore.u16(d, 0), UAStore.u16(d, 2));
        uint256 acc;
        uint256 yes = purposeTag == UAKinds.PURPOSE_POP_V2 ? type(uint256).max : _accepted(ua, sigs);
        uint256 wMin = type(uint256).max; // the smallest slot weight
        uint256 next; // lowest index the next MemberSig may use
        for (uint256 i; i < sigs.length; ++i) {
            IUARegistry.MemberSig memory s = sigs[i];
            if (acc >= threshold || s.index < next || s.index >= count || yes >> s.index & 1 == 0) return false;
            next = uint256(s.index) + 1;
            if (!_memberOk(d, md, digest, s)) return false;
            uint256 w = UAStore.u16(d, 4 + 36 * uint256(s.index) + 34);
            acc += w;
            if (w < wMin) wMin = w;
        }
        return acc >= threshold && acc - wMin < threshold;
    }

    /// The accepted bits `sigs` are checked against: one read for a record held here. The bits live with the record, so a gen 2
    /// hosting a gen-1 record (`setPqzKey`) asks gen 1 slot by slot, that word having no getter; gen 1's view cannot revert but out of
    /// gas, and a starved caller sees `UAVerifyGas`, never a verdict.
    function _accepted(bytes32 ua, IUARegistry.MemberSig[] memory sigs) private view returns (uint256 bits) {
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
    /// data (the registry reads the member's record, CTR-UA-33); a native member over the typed digest `typed`.
    function _memberOk(bytes memory d, bytes32 md, bytes32 typed, IUARegistry.MemberSig memory s) private view returns (bool) {
        uint256 o = 4 + 36 * uint256(s.index);
        (uint16 kind, bytes32 id) = (uint16(UAStore.u16(d, o)), bytes32(UAStore.word(d, o + 2)));
        if (!UAKinds.isNative(kind)) {
            return UAStore.via(address(this), id, UAKinds.PURPOSE_MEMBER, md,
                IUARegistry.UASig(s.keyData, s.sig, new IUARegistry.MemberSig[](0)));
        }
        if (s.keyData.length != 0) return false;
        return UAStore.byCode(address(uint160(uint256(id))), typed, s.sig, _cloneHash());
    }

    // ----- the msig bound -----

    /// Step 4 for `msig`: every member ∈ MEMBER of this profile and native or registered under its stated kind; the
    /// worst case of a minimal authorizing set (the `c` largest caps + `c` × `MSIG_MEMBER_GAS` + `MSIG_ACCEPTED_GAS`, + the caller's
    /// hold for the largest of this generation's caps beyond the 400 k that `MSIG_MEMBER_GAS` covers) fits `verifyBudget`.
    function _membersWorst(bytes memory d) private view returns (uint256 worst) {
        IUARegistry self = IUARegistry(address(this));
        (uint256 threshold, uint256 count) = (UAStore.u16(d, 0), UAStore.u16(d, 2));
        uint256[] memory weights = new uint256[](count);
        uint256[] memory caps = new uint256[](count);
        (bool hedera, address g1) = (self.hederaNative(), self.predecessor());
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            uint16 kind = uint16(UAStore.u16(d, o));
            bytes32 id = bytes32(UAStore.word(d, o + 2));
            if (!UAKinds.isMember(kind, hedera)) revert IUARegistry.UAMemberUnknown(id);
            if (UAKinds.isNative(kind)) {
                caps[i] = _nativeCap();
            } else {
                if (self.kindOf(id) != kind) revert IUARegistry.UAMemberUnknown(id);
                uint256 cap = self.verifyCap(kind); // 0: this generation does not enable the kind (an enabled cap is ≠ 0)
                if (cap == 0) {
                    // handed to gen 1, which holds cap / 63 + GAS_MARGIN again inside the 63/64 gen 2 gives it; gen 2 holds for it too
                    cap = IUARegistry(g1).verifyCap(kind);
                    cap = cap + cap / 63 + SigCheck.GAS_MARGIN;
                }
                caps[i] = cap;
            }
            weights[i] = UAStore.u16(d, o + 34);
        }
        _sort(weights);
        _sort(caps);
        uint256 c;
        for (uint256 acc; acc < threshold; ++c) {
            acc += weights[c];
        }
        worst = c * MSIG_MEMBER_GAS + MSIG_ACCEPTED_GAS;
        for (uint256 i; i < c; ++i) {
            worst += caps[count - 1 - i];
        }
        uint256 held = c == 0 ? 0 : caps[count - 1]; // the largest cap among the c (P6c: PQ caps exceed 400 k)
        if (held > UAStore.SMART_KEY_1271_GAS) worst += (held - UAStore.SMART_KEY_1271_GAS) / 63;
        if (worst > self.verifyBudget()) revert IUARegistry.UAKeyData(UAKinds.MSIG);
    }

    /// A native member may be (or later become, counterfactually) a `SmartKeyAccount` clone: the bound takes its cap.
    function _nativeCap() private view returns (uint256) {
        return _cloneHash() != 0 ? UAStore.SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
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
