// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "./IUARegistry.sol";
import {UAKinds} from "./UAKinds.sol";
import {UAStore} from "./UAStore.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title SPIKE lever R1′: the registry's off-chain views, run by DELEGATECALL from a stub per view. A function here with
///        value-typed parameters has the registry function's selector, so the stub forwards its calldata as it is; the two
///        with a struct parameter (`kemRecordHash`, `kemRecordDigest`) have a library selector, patched in by the stub.
/// @notice A library cannot read the registry's immutables: the views call back the existing getters on `address(this)`
///         (`predecessor`, `kindEnabled`). No new selector.
library UAViewLib {
    function _pred() private view returns (address) {
        return IUARegistry(address(this)).predecessor();
    }

    function _elsewhere(bytes32 ua) private view returns (address) {
        return UAStore.layout().records[ua].kind == 0 ? _pred() : address(0);
    }

    function _listedHere(uint16 kind) private view returns (address) {
        address p = _pred();
        return p == address(0) || IUARegistry(address(this)).kindEnabled(kind) ? address(0) : p;
    }

    // ----- pure -----

    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.uaOf(kind, keyData);
    }

    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.keyHashOf(kind, keyData);
    }

    function kindName(uint16 kind) external pure returns (string memory) {
        return UAKinds.name(kind);
    }

    function portableRecordDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash_)
        external
        pure
        returns (bytes32)
    {
        return UAKinds.portableRecordDigest(ua, kind, pqzKeyHash, kemRecordHash_);
    }

    function kemRecordHash(bytes32 ua, uint64 version, IUARegistry.KemKey calldata kem) external pure returns (bytes32) {
        return UAKinds.kemRecordHash(ua, version, UAKinds.kemPk(kem));
    }

    function registrationDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash_, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32)
    {
        return UAKinds.registrationDigest(ua, kind, pqzKeyHash, kemRecordHash_, pqzPopHash);
    }

    function kemRecordDigest(bytes32 ua, uint64 version, IUARegistry.KemKey calldata kem) external pure returns (bytes32) {
        return UAKinds.kemRecordDigest(ua, version, UAKinds.kemPk(kem));
    }

    function pqzKeyDigest(bytes32 ua, bytes32 pqzKeyHash) external pure returns (bytes32) {
        return UAKinds.pqzKeyDigest(ua, pqzKeyHash);
    }

    function pqzKeyRecordDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 pqzPopHash) external pure returns (bytes32) {
        return UAKinds.pqzKeyRecordDigest(ua, pqzKeyHash, pqzPopHash);
    }

    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32) {
        return UAKinds.uaMessage(kind, purposeTag, digest);
    }

    // ----- state -----

    function recordOf(bytes32 ua) external view returns (IUARegistry.Record memory r, address pqzKey) {
        UAStore.Layout storage s = UAStore.layout();
        r = s.records[ua];
        pqzKey = s.pqzKey[ua].ptr;
        address g1 = r.kind == 0 ? _pred() : address(0);
        if (g1 != address(0)) {
            (IUARegistry.Record memory g, address p) = IUARegistry(g1).recordOf(ua);
            return (g, pqzKey != address(0) ? pqzKey : p);
        }
    }

    function registrationOf(bytes32 ua)
        external
        view
        returns (uint16 kind, bytes memory keyData, IUARegistry.UAAttrs memory attrs, bytes memory pop, bytes memory pqzPop)
    {
        UAStore.Layout storage s = UAStore.layout();
        address g1 = _elsewhere(ua);
        if (g1 != address(0)) {
            (kind, keyData, attrs, pop, pqzPop) = IUARegistry(g1).registrationOf(ua);
            if (attrs.pqzKey.length != 0 && pqzPop.length == 0 && !s.pqzKey[ua].added) {
                pqzPop = SSTORE2.readChunks(s.pqzPop[ua]);
            }
            return (kind, keyData, attrs, pop, pqzPop);
        }
        IUARegistry.Record memory r = s.records[ua];
        kind = r.kind;
        if (kind == 0) return (kind, keyData, attrs, pop, pqzPop);
        (keyData, pop) = UAStore.registration(ua, r.keyPtr);
        UAStore.KemCommit memory c = s.kemCommit[ua];
        if (c.kemPkHash != 0) (attrs.kem.scheme, attrs.kemPkHash) = (c.scheme, c.kemPkHash);
        else (attrs.kem,) = UAStore.kemAt(ua, 0);
        UAStore.PqzKey memory k = s.pqzKey[ua];
        if (k.added) {
            (attrs.pqzKey, attrs.pqzPopHash) = (SSTORE2.read(s.regPqzKey[ua]), s.regPqzPopHash[ua]);
            return (kind, keyData, attrs, pop, pqzPop);
        }
        (attrs.pqzKey, attrs.pqzPopHash) = (SSTORE2.read(k.ptr), s.pqzPopHash[ua]);
        pqzPop = SSTORE2.readChunks(s.pqzPop[ua]);
    }

    function popOf(bytes32 ua) external view returns (bytes memory pop) {
        UAStore.Layout storage s = UAStore.layout();
        address g1 = _elsewhere(ua);
        if (g1 != address(0)) return IUARegistry(g1).popOf(ua);
        if (s.records[ua].kind == 0) return pop;
        (, pop) = abi.decode(SSTORE2.readChunks(s.reg[ua]), (bytes, bytes));
    }

    function msigOf(bytes32 ua) external view returns (IUARegistry.MsigStructure memory s) {
        address g1 = _elsewhere(ua);
        if (g1 != address(0)) return IUARegistry(g1).msigOf(ua);
        if (UAStore.layout().records[ua].kind != UAKinds.MSIG) return s;
        bytes memory d = UAStore.keyRest(ua);
        uint256 n = UAStore.u16(d, 2);
        s.threshold = uint16(UAStore.u16(d, 0));
        s.members = new IUARegistry.MsigMember[](n);
        for (uint256 i; i < n; ++i) {
            uint256 o = 4 + 36 * i;
            s.members[i] =
                IUARegistry.MsigMember(uint16(UAStore.u16(d, o)), bytes32(UAStore.word(d, o + 2)), uint16(UAStore.u16(d, o + 34)));
        }
    }

    function webAuthnKeyOf(bytes32 ua) external view returns (IUARegistry.WebAuthnKey memory k) {
        address g1 = _elsewhere(ua);
        if (g1 != address(0)) return IUARegistry(g1).webAuthnKeyOf(ua);
        if (UAStore.layout().records[ua].kind != UAKinds.WEBAUTHN_P256) return k;
        bytes memory d = UAStore.keyRest(ua);
        (k.x, k.y, k.rpIdHash) = (bytes32(UAStore.word(d, 0)), bytes32(UAStore.word(d, 32)), bytes32(UAStore.word(d, 64)));
    }

    function muSig2KeyOf(bytes32 ua) external view returns (IUARegistry.MuSig2Key memory k) {
        address g1 = _elsewhere(ua);
        if (g1 != address(0)) return IUARegistry(g1).muSig2KeyOf(ua);
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        if (r.kind != UAKinds.MUSIG2_SECP256K1 && r.kind != UAKinds.MUSIG2_BN254) return k;
        (uint256 size, bytes memory d) = (UAStore.vkLength(r.kind), UAStore.keyRest(ua));
        k.aggKey = SSTORE2.read(r.keyPtr);
        k.memberKeys = new bytes[](UAStore.u16(d, 0));
        for (uint256 i; i < k.memberKeys.length; ++i) {
            k.memberKeys[i] = UAStore.cut(d, 2 + i * size, size);
        }
    }

    function frostKeyOf(bytes32 ua) external view returns (IUARegistry.FrostKey memory k) {
        address g1 = _elsewhere(ua);
        if (g1 != address(0)) return IUARegistry(g1).frostKeyOf(ua);
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        if (r.kind != UAKinds.FROST_SECP256K1 && r.kind != UAKinds.FROST_BN254) return k;
        (uint256 size, bytes memory d) = (UAStore.vkLength(r.kind), UAStore.keyRest(ua));
        k.groupKey = SSTORE2.read(r.keyPtr);
        uint256 t = UAStore.u16(d, 0);
        k.threshold = uint16(t);
        k.members = new IUARegistry.FrostMember[](UAStore.u16(d, 2));
        for (uint256 i; i < k.members.length; ++i) {
            uint256 o = 4 + i * ((t + 1) * size + 32);
            IUARegistry.FrostMember memory m = k.members[i];
            m.commitments = new bytes[](t);
            for (uint256 j; j < t; ++j) {
                m.commitments[j] = UAStore.cut(d, o + j * size, size);
            }
            m.r = UAStore.cut(d, o + t * size, size);
            m.z = bytes32(UAStore.word(d, o + (t + 1) * size));
        }
    }

    function pqzPopOf(bytes32 ua) external view returns (bytes memory) {
        UAStore.Layout storage s = UAStore.layout();
        if (s.pqzKey[ua].ptr == address(0)) {
            address g1 = _elsewhere(ua);
            if (g1 != address(0)) return IUARegistry(g1).pqzPopOf(ua);
        }
        return SSTORE2.readChunks(s.pqzPop[ua]);
    }

    function pqzKeySigOf(bytes32 ua) external view returns (bytes memory) {
        UAStore.Layout storage s = UAStore.layout();
        if (s.pqzKeySig[ua].length == 0) {
            address g1 = _elsewhere(ua);
            if (g1 != address(0)) return IUARegistry(g1).pqzKeySigOf(ua);
        }
        return SSTORE2.readChunks(s.pqzKeySig[ua]);
    }

    function checkedOf(bytes32 ua) external view returns (uint8 pop, uint8 pqzPop, uint8 kem) {
        UAStore.Layout storage s = UAStore.layout();
        address g1 = _elsewhere(ua);
        if (g1 != address(0)) {
            (pop, pqzPop, kem) = IUARegistry(g1).checkedOf(ua);
            if (s.pqzKey[ua].proven) pqzPop = UAKinds.CHECKED_CHAIN;
            return (pop, pqzPop, kem);
        }
        if (s.records[ua].kind == 0) return (pop, pqzPop, kem);
        return (UAKinds.CHECKED_CHAIN, UAStore.checked(s.pqzKey[ua].proven),
            UAStore.checked(s.kemMax[ua] != 0 || s.kem[ua][0].length != 0));
    }

    function kemKeyOf(bytes32 ua) external view returns (uint64 version, IUARegistry.KemKey memory kem, bytes memory sig) {
        address g1 = _elsewhere(ua);
        if (g1 != address(0)) return IUARegistry(g1).kemKeyOf(ua);
        version = UAStore.layout().kemMax[ua];
        (kem, sig) = UAStore.kemAt(ua, version);
    }

    function kemKeyAt(bytes32 ua, uint64 version) external view returns (IUARegistry.KemKey memory kem, bytes memory sig) {
        address g1 = _elsewhere(ua);
        if (g1 != address(0)) return IUARegistry(g1).kemKeyAt(ua, version);
        return UAStore.kemAt(ua, version);
    }

    function keyOf(bytes32 ua) external view returns (bytes memory) {
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        address g1 = r.kind == 0 ? _pred() : address(0);
        if (g1 != address(0)) return IUARegistry(g1).keyOf(ua);
        return SSTORE2.read(r.keyPtr);
    }

    function uaCount(uint16 kind) external view returns (uint256) {
        address g1 = _listedHere(kind);
        if (g1 != address(0)) return IUARegistry(g1).uaCount(kind);
        return UAStore.layout().uaCount[kind];
    }

    function uaAt(uint16 kind, uint256 i) external view returns (bytes32) {
        address g1 = _listedHere(kind);
        if (g1 != address(0)) return IUARegistry(g1).uaAt(kind, i);
        UAStore.Layout storage s = UAStore.layout();
        if (i >= s.uaCount[kind]) revert IUARegistry.UAIndex(kind, i);
        return s.uaAt[kind][i];
    }

    function uaPage(uint16 kind, uint256 start, uint256 n) external view returns (bytes32[] memory page) {
        address g1 = _listedHere(kind);
        if (g1 != address(0)) return IUARegistry(g1).uaPage(kind, start, n);
        UAStore.Layout storage s = UAStore.layout();
        uint256 count = s.uaCount[kind];
        if (start >= count) return page;
        if (n > count - start) n = count - start;
        page = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            page[i] = s.uaAt[kind][start + i];
        }
    }

    function uaIndex(bytes32 ua) external view returns (uint256) {
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        if (r.kind != 0) return r.index;
        address g1 = _pred();
        if (g1 != address(0)) return IUARegistry(g1).uaIndex(ua);
        revert IUARegistry.UANotIndexed(ua);
    }

    function expandedKeyOf(bytes32 ua) external view returns (address[2] memory) {
        return UAStore.layout().ekPtr[ua];
    }
}
