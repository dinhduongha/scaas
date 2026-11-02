// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {IUAPopVerifier} from "./IUAVerifier.sol";
import {UAKinds} from "./UAKinds.sol";
import {UAStore} from "./UAStore.sol";
import {PqzSet} from "../pqz/PqzSet.sol";
import {UAMldsaVerifier} from "./MlDsa.sol";

/// @title SPIKE lever R2: registration, the PQZ attachment, KEM records and the ML-DSA cache, run by DELEGATECALL from a
///        thin entry per function. Same check order, same storage, same events as the baseline's code in `UARegistry`.
/// @notice Immutables a library cannot read reach it two ways (no new selector):
///         - 3 words appended by the entry after the forwarded calldata: `_cfg(kind)` of the kind the entry knows (its
///           parameter, or the record's), `_cfg(0x0142)`, the clone codehash. Fixed at the very end of the calldata, so
///           a caller cannot move them; ABI offsets may point into them, which only reads public values.
///         - everything with a getter calls back on `address(this)`: `predecessor`, `hederaNative`, `verifyBudget`,
///           `verifyCap` (an `msig` member's cap and whether its kind is enabled), `kindOf`, `keyOwner`.
///         A derived `msig` member's signature goes through `requireAuthorized` on `address(this)` under `member`: the
///         same `_derived` as the baseline (the member's kind was checked against its record at registration); the
///         verifier call stays in the one place, and this library needs no member's verifier address.
library UARegisterLib {
    uint256 internal constant SMART_KEY_1271_GAS = 400_000;
    uint256 internal constant TX_GAS_CAP = 1 << 24;
    uint256 internal constant MSIG_MEMBER_GAS = 45_000;
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

    function _pred() private view returns (address) {
        return IUARegistry(address(this)).predecessor();
    }

    function _kindOf(bytes32 ua) private view returns (uint16) {
        return IUARegistry(address(this)).kindOf(ua);
    }

    function _keyOwner(bytes32 h) private view returns (bytes32) {
        return IUARegistry(address(this)).keyOwner(h);
    }

    // ----- ML-DSA expanded-key cache -----

    function cacheExpandedKey(uint16 kind, bytes calldata pk, uint256 part) external returns (bytes32 ua) {
        UAStore.Layout storage s = UAStore.layout();
        address v = address(uint160(_cfgKind()));
        if (
            (kind != UAKinds.MLDSA44 && kind != UAKinds.MLDSA65) || v == address(0)
                || part >= (kind == UAKinds.MLDSA44 ? 1 : 2) || UAMldsaVerifier(v).PRECOMPILE() != address(0)
        ) revert IUARegistry.UAKeyCache(kind);
        bytes memory d = pk;
        UAKinds.validateKeyData(kind, d, false);
        ua = UAKinds.uaOf(kind, d);
        if (s.ekPtr[ua][part] != address(0)) return ua;
        address ptr = SSTORE2.write(UAMldsaVerifier(v).expandedKeyPart(pk, part));
        s.ekPtr[ua][part] = ptr;
        emit IUARegistry.UAKeyCached(ua, kind, part, ptr);
    }

    // ----- register -----

    function register(uint16 kind, bytes calldata keyData, IUARegistry.UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua)
    {
        if (kind == UAKinds.MSIG) revert IUARegistry.UAKeyData(kind);
        return _register(kind, keyData, attrs, pop, new IUARegistry.MemberSig[](0), pqzPop);
    }

    function registerWebAuthn(IUARegistry.WebAuthnKey calldata key, IUARegistry.UAAttrs calldata attrs, bytes calldata pop,
        bytes calldata pqzPop) external returns (bytes32 ua)
    {
        return _register(UAKinds.WEBAUTHN_P256, abi.encodePacked(key.x, key.y, key.rpIdHash), attrs, pop,
            new IUARegistry.MemberSig[](0), pqzPop);
    }

    function registerMuSig2(uint16 kind, IUARegistry.MuSig2Key calldata key, IUARegistry.UAAttrs calldata attrs,
        bytes calldata pop, bytes calldata pqzPop) external returns (bytes32 ua)
    {
        if (kind != UAKinds.MUSIG2_SECP256K1 && kind != UAKinds.MUSIG2_BN254) revert IUARegistry.UAKeyData(kind);
        if (uint160(_cfgKind()) == 0) revert IUARegistry.UAKindDisabled(kind);
        uint256 size = UAStore.vkLength(kind);
        bytes[] calldata m = key.memberKeys;
        bytes memory d = abi.encodePacked(_point(kind, key.aggKey, size), uint16(m.length));
        for (uint256 i; i < m.length; ++i) {
            d = bytes.concat(d, _point(kind, m[i], size));
        }
        return _register(kind, d, attrs, pop, new IUARegistry.MemberSig[](0), pqzPop);
    }

    function registerFrost(uint16 kind, IUARegistry.FrostKey calldata key, IUARegistry.UAAttrs calldata attrs,
        bytes calldata pop, bytes calldata pqzPop) external returns (bytes32 ua)
    {
        if (kind != UAKinds.FROST_SECP256K1 && kind != UAKinds.FROST_BN254) revert IUARegistry.UAKeyData(kind);
        if (uint160(_cfgKind()) == 0) revert IUARegistry.UAKindDisabled(kind);
        IUARegistry.FrostMember[] calldata m = key.members;
        bytes memory d =
            abi.encodePacked(_point(kind, key.groupKey, UAStore.vkLength(kind)), key.threshold, uint16(m.length));
        for (uint256 i; i < m.length; ++i) {
            d = bytes.concat(d, _frostMember(kind, m[i], key.threshold));
        }
        return _register(kind, d, attrs, pop, new IUARegistry.MemberSig[](0), pqzPop);
    }

    function _frostMember(uint16 kind, IUARegistry.FrostMember calldata m, uint256 t) private pure returns (bytes memory d) {
        uint256 size = UAStore.vkLength(kind);
        if (m.commitments.length != t) revert IUARegistry.UAKeyData(kind);
        for (uint256 j; j < t; ++j) {
            d = bytes.concat(d, _point(kind, m.commitments[j], size));
        }
        d = bytes.concat(d, _point(kind, m.r, size), m.z);
    }

    function _point(uint16 kind, bytes calldata p, uint256 size) private pure returns (bytes calldata) {
        if (p.length != size) revert IUARegistry.UAKeyData(kind);
        return p;
    }

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

    function _register(uint16 kind, bytes memory d, IUARegistry.UAAttrs calldata attrs, bytes memory sig,
        IUARegistry.MemberSig[] memory members, bytes calldata pqzPop) private returns (bytes32 ua)
    {
        UAStore.Layout storage s = UAStore.layout();
        bytes32 kh;
        (ua, kh) = _identify(kind, d); // 1–4
        _consent(kind, d, ua, attrs, sig, members, pqzPop); // 5–7
        bytes memory pop = members.length != 0 ? abi.encode(members) : sig;
        _record(ua, kind, d, kh, attrs, pop); // 8
        (uint8 q, uint8 k) = (UAStore.checked(s.pqzKey[ua].proven), UAStore.checked(s.kem[ua][0].length != 0));
        emit IUARegistry.UARegistered(ua, kind, d, attrs, keccak256(pop), pqzPop, UAKinds.CHECKED_CHAIN, q, k);
    }

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

    function _list(uint16 kind, bytes32 ua) private returns (uint40) {
        UAStore.Layout storage s = UAStore.layout();
        uint256 n = s.uaCount[kind];
        s.uaAt[kind][n] = ua;
        s.uaCount[kind] = n + 1;
        return uint40(n);
    }

    function _identify(uint16 kind, bytes memory d) private view returns (bytes32 ua, bytes32 kh) {
        if (uint160(_cfgKind()) == 0) revert IUARegistry.UAKindDisabled(kind); // 1
        bool structure = kind == UAKinds.MSIG;
        UAKinds.validateKeyData(kind, d, structure || IUARegistry(address(this)).hederaNative()); // 2
        ua = UAKinds.uaOf(kind, d); // 3
        if (UAKinds.inNativeSpace(ua)) revert IUARegistry.UAIdInNativeSpace(ua);
        if (_kindOf(ua) != 0) revert IUARegistry.UAAlreadyRegistered(ua);
        kh = _claim(kind, d, structure); // 4
    }

    function _claim(uint16 kind, bytes memory d, bool structure) private view returns (bytes32 kh) {
        if (structure) {
            _membersWorst(d);
            return 0;
        }
        kh = UAKinds.keyHashOf(kind, d);
        bytes32 owner = _keyOwner(kh);
        if (owner != 0) revert IUARegistry.UAKeyInUse(kh, owner);
    }

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

    function _checkKemPk(bytes memory pk) private pure {
        if (pk.length == 0) revert IUARegistry.UAKemKeyLength(0);
        _checkKemScheme(uint8(pk[0]));
        if (pk.length != UAKinds.KEM_PK_LENGTH) revert IUARegistry.UAKemKeyLength(pk.length);
    }

    function _checkKemScheme(uint8 scheme) private pure {
        if (scheme != UAKinds.KEM_SCHEME_MLKEM1024_X25519) revert IUARegistry.UAKemScheme(scheme);
    }

    function _holder(uint16 kind, bytes memory d) private pure returns (bool) {
        return kind == UAKinds.MLDSA44 || kind == UAKinds.MLDSA65 || kind == UAKinds.FNDSA512
            || (kind == UAKinds.MSIG && _pqEligible(d));
    }

    function _pqzHolder(uint16 kind, bytes memory d, bytes32 ua) private view {
        address g1 = _pred();
        if (g1 != address(0) && IUARegistry(g1).kindEnabled(UAKinds.PQZ_MLWE)) {
            revert IUARegistry.UAKindDisabled(UAKinds.PQZ_MLWE);
        }
        if (!_holder(kind, d)) revert IUARegistry.UAPqzHolder(ua);
        if (kind == UAKinds.MSIG) {
            uint256 w = _membersWorst(d);
            if (w + w / 63 + SigCheck.GAS_MARGIN + PqzSet.PQZ_DEBIT_MIN_GAS > TX_GAS_CAP) revert IUARegistry.UAPqzHolder(ua);
        }
    }

    function _pqzKeyHash(bytes memory pqzKey) private pure returns (bytes32) {
        uint256 n = pqzKey.length;
        if (n < 16_384 || n > 22_528 || n % 2_048 != 0) revert IUARegistry.UAKeyData(UAKinds.PQZ_MLWE);
        return UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqzKey);
    }

    function _pqEligible(bytes memory d) private pure returns (bool) {
        (uint256 threshold, uint256 count) = (UAStore.u16(d, 0), UAStore.u16(d, 2));
        uint256 classical;
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            if (!UAStore.isPq(uint16(UAStore.u16(d, o)))) classical += UAStore.u16(d, o + 34);
        }
        return classical < threshold;
    }

    function _pqzAttach(bytes32 ua, IUARegistry.UAAttrs calldata attrs, bytes calldata pqzPop, bytes32 h, bytes32 portable)
        private
    {
        if (h == 0) return;
        UAStore.Layout storage s = UAStore.layout();
        s.pqzKey[ua].ptr = SSTORE2.write(attrs.pqzKey);
        s.pqzPopHash[ua] = attrs.pqzPopHash;
        if (pqzPop.length == 0) return;
        _pqzProof(ua, attrs.pqzKey, pqzPop, h, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, portable), pqzPop[0:0]);
    }

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

    // ----- the PQZ proof later, the PQZ key later -----

    function storePqzPop(bytes32 ua, bytes calldata pqzPop) external {
        bool host = _host(ua);
        if (pqzPop.length == 0) revert IUARegistry.UAPqzPopHash(ua);
        UAStore.PqzKey memory k = UAStore.layout().pqzKey[ua];
        bytes32 ph = UAStore.layout().pqzPopHash[ua];
        if (host && k.ptr == address(0)) {
            (k.ptr, ph,) = IUARegistry(_pred()).pqzKeyOf(ua);
            k.added = IUARegistry(_pred()).pqzKeySigOf(ua).length != 0;
        }
        if (keccak256(pqzPop) != ph) revert IUARegistry.UAPqzPopHash(ua);
        if (UAStore.layout().pqzPop[ua].length != 0) return;
        bytes memory key = SSTORE2.read(k.ptr);
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key);
        bytes32 message = k.added
            ? UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyDigest(ua, h))
            : _registerKeyMessage(ua, h, host);
        if (host) {
            UAStore.layout().pqzKey[ua] = k;
            UAStore.layout().pqzPopHash[ua] = ph;
        }
        _pqzProof(ua, key, pqzPop, h, message, pqzPop);
    }

    function _registerKeyMessage(bytes32 ua, bytes32 h, bool host) private view returns (bytes32) {
        bytes32 d = UAKinds.portableRecordDigest(ua, _kindOf(ua), h, _kemHash(ua, host));
        return UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, d);
    }

    function _kemHash(bytes32 ua, bool host) private view returns (bytes32) {
        IUARegistry.KemKey memory kem;
        bytes32 committed;
        if (host) {
            (,, IUARegistry.UAAttrs memory a,,) = IUARegistry(_pred()).registrationOf(ua);
            (kem, committed) = (a.kem, a.kemPkHash);
        } else {
            UAStore.KemCommit memory c = UAStore.layout().kemCommit[ua];
            if (c.kemPkHash != 0) return UAKinds.kemRecordHash(ua, 0, c.scheme, c.kemPkHash);
            (kem,) = UAStore.kemAt(ua, 0);
        }
        if (committed != 0) return UAKinds.kemRecordHash(ua, 0, kem.scheme, committed);
        return UAKinds.kemRecordHash(ua, 0, UAKinds.kemPk(kem));
    }

    function _host(bytes32 ua) private view returns (bool) {
        if (UAStore.layout().records[ua].kind != 0) return false;
        if (_pred() != address(0) && uint160(_cfgPqz()) != 0 && _kindOf(ua) != 0) return true;
        revert IUARegistry.UAUnauthorized(ua);
    }

    function setPqzKey(bytes32 ua, bytes calldata pqzKey, bytes32 pqzPopHash, IUARegistry.UASig calldata sig) external {
        bool host = _host(ua);
        (uint16 kind, bytes memory d) = _keyDataOf(ua, host);
        _pqzHolder(kind, d, ua);
        _pqzKeyFree(ua, host);
        bytes32 h = _pqzKeyHash(pqzKey);
        if (pqzPopHash == 0 || pqzPopHash == EMPTY_PROOF_HASH) revert IUARegistry.UAPqzPopHash(ua);
        bytes32 rd = UAKinds.pqzKeyRecordDigest(ua, h, pqzPopHash);
        if (!_portableOk(kind, d, ua, UAKinds.PURPOSE_PQZ_KEY, rd, sig)) revert IUARegistry.UAUnauthorized(ua);
        bytes memory stored = _portableBytes(sig);
        UAStore.layout().pqzKey[ua] = UAStore.PqzKey(SSTORE2.write(pqzKey), false, true);
        UAStore.layout().pqzPopHash[ua] = pqzPopHash;
        UAStore.layout().pqzKeySig[ua] = SSTORE2.writeChunks(stored);
        emit IUARegistry.UAPqzKeyAdded(ua, h, pqzPopHash, pqzKey, stored);
    }

    function _keyDataOf(bytes32 ua, bool host) private view returns (uint16 kind, bytes memory d) {
        if (host) {
            (kind, d,,,) = IUARegistry(_pred()).registrationOf(ua);
        } else {
            IUARegistry.Record memory r = UAStore.layout().records[ua];
            kind = r.kind;
            (d,) = UAStore.registration(ua, r.keyPtr);
        }
    }

    function _portableOk(uint16 kind, bytes memory d, bytes32 ua, bytes32 purpose, bytes32 digest,
        IUARegistry.UASig calldata sig) private view returns (bool)
    {
        return sig.keyData.length == 0 && _sigOk(_cfgKind(), kind, d, ua, purpose, digest, sig.signature, sig.members);
    }

    function _portableBytes(IUARegistry.UASig calldata sig) private pure returns (bytes memory) {
        return sig.members.length != 0 ? abi.encode(sig.members) : sig.signature;
    }

    function _pqzKeyFree(bytes32 ua, bool host) private {
        UAStore.Layout storage s = UAStore.layout();
        UAStore.PqzKey memory old = s.pqzKey[ua];
        address pk = old.ptr;
        if (host && pk == address(0)) (pk,,) = IUARegistry(_pred()).pqzKeyOf(ua);
        if (pk == address(0)) return;
        if (old.proven || uint160(_cfgPqz()) == 0 || pk.code.length - 1 == PqzSet.PK) revert IUARegistry.UAPqzKeySet(ua);
        if (!host && !old.added) (s.regPqzKey[ua], s.regPqzPopHash[ua]) = (pk, s.pqzPopHash[ua]);
    }

    // ----- KEM records -----

    function setKemKey(bytes32 ua, uint64 version, IUARegistry.KemKey calldata kem, IUARegistry.UASig calldata sig) external {
        UAStore.Layout storage s = UAStore.layout();
        IUARegistry.Record memory r = s.records[ua];
        if (r.kind == 0) revert IUARegistry.UAUnauthorized(ua);
        (bytes memory d,) = UAStore.registration(ua, r.keyPtr);
        if (!_holder(r.kind, d)) revert IUARegistry.UAKemHolder(ua);
        if (s.kem[ua][version].length != 0) revert IUARegistry.UAKemVersion(ua, version);
        bytes32 committed = version == 0 ? s.kemCommit[ua].kemPkHash : bytes32(0);
        if (version == 0 && committed == 0) revert IUARegistry.UAKemVersion(ua, 0);
        bytes memory kemPk = UAKinds.kemPk(kem);
        _checkKemPk(kemPk);
        bytes memory stored;
        if (version == 0) {
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

    // ----- the portable signature (the baseline's `_sigOk` and its `portable` path of `_msig`) -----

    /// `internal` for the test harness only (`SigOkHarness`, ruling A5-m3); `cfg` is `_cfg(kind)`.
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
        if (uint160(cfg) == 0) return _via(_pred(), ua, purpose, digest, IUARegistry.UASig("", sig, members));
        bytes32 message = UAKinds.uaMessage(kind, purpose, digest);
        bytes memory ek = UAStore.expanded(ua, kind);
        bytes memory data = ek.length != 0
            ? abi.encodeWithSelector(UAMldsaVerifier.verifyCached.selector, ek, message, sig)
            : abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, d, message, sig);
        if (kind >= UAKinds.MUSIG2_SECP256K1 && kind <= UAKinds.FROST_BN254) {
            return UAStore.capped(address(uint160(cfg)), IUARegistry(address(this)).verifyBudget(), data, 1, false);
        }
        return UAStore.capped(address(uint160(cfg)), cfg >> 160, data, 1, true);
    }

    function _msig(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory d, IUARegistry.MemberSig[] memory sigs)
        private
        view
        returns (bool)
    {
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purposeTag, digest));
        (uint256 threshold, uint256 count) = (UAStore.u16(d, 0), UAStore.u16(d, 2));
        uint256 acc;
        uint256 next;
        for (uint256 i; i < sigs.length; ++i) {
            IUARegistry.MemberSig memory s = sigs[i];
            if (acc >= threshold || s.index < next || s.index >= count) return false;
            next = uint256(s.index) + 1;
            if (!_memberOk(d, md, digest, s)) return false;
            acc += UAStore.u16(d, 4 + 36 * uint256(s.index) + 34);
        }
        return acc >= threshold;
    }

    function _memberOk(bytes memory d, bytes32 md, bytes32 typed, IUARegistry.MemberSig memory s) private view returns (bool) {
        uint256 o = 4 + 36 * uint256(s.index);
        (uint16 kind, bytes32 id) = (uint16(UAStore.u16(d, o)), bytes32(UAStore.word(d, o + 2)));
        if (!UAKinds.isNative(kind)) {
            return _via(address(this), id, UAKinds.PURPOSE_MEMBER, md,
                IUARegistry.UASig(s.keyData, s.sig, new IUARegistry.MemberSig[](0)));
        }
        if (s.keyData.length != 0) return false;
        return _byCode(address(uint160(uint256(id))), typed, s.sig);
    }

    function _byCode(address a, bytes32 digest, bytes memory sig) private view returns (bool) {
        if (!SigCheck.isContract(a)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            return err == ECDSA.RecoverError.NoError && rec == a;
        }
        bytes32 clone = _cloneHash();
        uint256 cap = clone != 0 && a.codehash == clone ? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
        return UAStore.capped(a, cap, abi.encodeCall(IERC1271.isValidSignature, (digest, sig)),
            uint256(bytes32(IERC1271.isValidSignature.selector)), true);
    }

    /// `requireAuthorized` on `target` as a verdict (the baseline's `_viaPredecessor` + `_starved`): `target` is gen 1, or
    /// this registry itself for a derived member. Any revert is a failed check, except starvation.
    function _via(address target, bytes32 id, bytes32 purposeTag, bytes32 digest, IUARegistry.UASig memory auth)
        private
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

    // ----- the msig bound -----

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
                caps[i] = _cloneHash() != 0 ? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
            } else {
                if (self.kindOf(id) != kind) revert IUARegistry.UAMemberUnknown(id);
                uint256 cap = self.verifyCap(kind);
                if (cap == 0) {
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
        worst = c * MSIG_MEMBER_GAS;
        for (uint256 i; i < c; ++i) {
            worst += caps[count - 1 - i];
        }
        uint256 held = c == 0 ? 0 : caps[count - 1];
        if (held > SMART_KEY_1271_GAS) worst += (held - SMART_KEY_1271_GAS) / 63;
        if (worst > self.verifyBudget()) revert IUARegistry.UAKeyData(UAKinds.MSIG);
    }

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
