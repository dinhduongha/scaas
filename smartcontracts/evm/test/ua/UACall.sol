// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// typed-signing R1 test helpers: the registry's explicit arguments (TS-D10 … TS-D12) built from the byte forms the
/// vectors and the older tests carry (`kemPk` = scheme ‖ ek ‖ x25519, CTR-UA-09 `msig` key data, `abi.encode(MemberSig[])`
/// pops, `abi.encode(keyData, sig)` auths). Pure conversions: no external call, so `vm.expectRevert` still meets the
/// registry call.
library UACall {
    /// `kemPk` split into its `KemKey` (scheme byte, ek, the last 32 bytes); "" is the empty key. Any length of 33 B or
    /// more round-trips through `kemPk` (a wrong length stays wrong, for the length negatives).
    function kem(bytes memory pk) internal pure returns (IUARegistry.KemKey memory k) {
        if (pk.length == 0) return k;
        require(pk.length >= 33, "UACall.kem: shorter than scheme + x25519");
        k.scheme = uint8(pk[0]);
        k.mlkemEk = new bytes(pk.length - 33);
        bytes memory ek = k.mlkemEk;
        bytes32 x;
        assembly ("memory-safe") {
            mcopy(add(ek, 32), add(pk, 33), mload(ek))
            x := mload(add(add(pk, 32), sub(mload(pk), 32)))
        }
        k.x25519 = x;
    }

    /// `scheme ‖ mlkemEk ‖ x25519`, "" for the empty key.
    function kemPk(IUARegistry.KemKey memory k) internal pure returns (bytes memory) {
        if (k.scheme == 0 && k.mlkemEk.length == 0 && k.x25519 == 0) return "";
        return abi.encodePacked(k.scheme, k.mlkemEk, k.x25519);
    }

    /// Attributes with the full KEM key (or none).
    function attrs(bytes memory pqzKey, bytes32 pqzPopHash, bytes memory kemPk_)
        internal
        pure
        returns (IUARegistry.UAAttrs memory a)
    {
        a.pqzKey = pqzKey;
        a.pqzPopHash = pqzPopHash;
        a.kem = kem(kemPk_);
    }

    function none() internal pure returns (IUARegistry.UAAttrs memory a) {}

    /// The hash-commit form of `a`'s full KEM key: `kem` = its scheme only, `kemPkHash = keccak256(kemPk)`.
    function commit(IUARegistry.UAAttrs memory a) internal pure returns (IUARegistry.UAAttrs memory c) {
        c.pqzKey = a.pqzKey;
        c.pqzPopHash = a.pqzPopHash;
        c.kem.scheme = a.kem.scheme;
        c.kemPkHash = keccak256(kemPk(a.kem));
    }

    /// CTR-UA-09 key data `u16 t ‖ u16 n ‖ n × (u16 kind ‖ id ‖ u16 weight)` as its structure (no validation).
    function structure(bytes memory d) internal pure returns (IUARegistry.MsigStructure memory s) {
        s.threshold = uint16(_u16(d, 0));
        uint256 n = _u16(d, 2);
        s.members = new IUARegistry.MsigMember[](n);
        for (uint256 i; i < n; ++i) {
            uint256 o = 4 + 36 * i;
            bytes32 id;
            assembly ("memory-safe") {
                id := mload(add(add(d, 34), o))
            }
            s.members[i] = IUARegistry.MsigMember(uint16(_u16(d, o)), id, uint16(_u16(d, o + 34)));
        }
    }

    function keyData(IUARegistry.MsigStructure memory s) internal pure returns (bytes memory d) {
        d = abi.encodePacked(s.threshold, uint16(s.members.length));
        for (uint256 i; i < s.members.length; ++i) {
            d = bytes.concat(d, abi.encodePacked(s.members[i].kind, s.members[i].id, s.members[i].weight));
        }
    }

    /// `abi.encode(MemberSig[])` decoded; "" is no member signature. Test-only: any other non-empty bytes (the older
    /// tests' junk pops, e.g. `hex"01"`) become one junk member signature (index 0, `sig` = the bytes), so a "pop given"
    /// case stays one.
    function members(bytes memory pop) internal pure returns (IUARegistry.MemberSig[] memory m) {
        if (pop.length == 0) return m;
        if (pop.length < 64 || uint256(bytes32(pop)) != 0x20) {
            m = new IUARegistry.MemberSig[](1);
            m[0].sig = pop;
            return m;
        }
        m = abi.decode(pop, (IUARegistry.MemberSig[]));
    }

    /// `register`, or the typed entry of kind `msig` / `webauthn-p256` / MuSig2 / FROST (key data and pop in their byte
    /// forms; typed-signing R1 / R1b). Key data the typed form cannot express (a wrong length) goes to `register`, whose
    /// `validateKeyData` refuses it (`UAKeyData(kind)`), as the typed entry refuses the layout.
    function register(
        IUARegistry r,
        uint16 kind,
        bytes memory keyData_,
        IUARegistry.UAAttrs memory a,
        bytes memory pop,
        bytes memory pqzPop
    ) internal returns (bytes32) {
        if (kind == UAKinds.MSIG) return r.registerMsig(structure(keyData_), a, members(pop), pqzPop);
        if (kind == UAKinds.WEBAUTHN_P256 && keyData_.length == 96) {
            return r.registerWebAuthn(webAuthnKey(keyData_), a, pop, pqzPop);
        }
        uint256 size = pointSize(kind);
        if ((kind == UAKinds.MUSIG2_SECP256K1 || kind == UAKinds.MUSIG2_BN254) && muSig2Layout(keyData_, size)) {
            return r.registerMuSig2(kind, muSig2Key(keyData_, size), a, pop, pqzPop);
        }
        if ((kind == UAKinds.FROST_SECP256K1 || kind == UAKinds.FROST_BN254) && frostLayout(keyData_, size)) {
            return r.registerFrost(kind, frostKey(keyData_, size), a, pop, pqzPop);
        }
        return r.register(kind, keyData_, a, pop, pqzPop);
    }

    /// The calldata of the call `register` makes.
    function registerCall(
        uint16 kind,
        bytes memory keyData_,
        IUARegistry.UAAttrs memory a,
        bytes memory pop,
        bytes memory pqzPop
    ) internal pure returns (bytes memory) {
        if (kind == UAKinds.MSIG) {
            return abi.encodeCall(IUARegistry.registerMsig, (structure(keyData_), a, members(pop), pqzPop));
        }
        if (kind == UAKinds.WEBAUTHN_P256 && keyData_.length == 96) {
            return abi.encodeCall(IUARegistry.registerWebAuthn, (webAuthnKey(keyData_), a, pop, pqzPop));
        }
        uint256 size = pointSize(kind);
        if ((kind == UAKinds.MUSIG2_SECP256K1 || kind == UAKinds.MUSIG2_BN254) && muSig2Layout(keyData_, size)) {
            return abi.encodeCall(IUARegistry.registerMuSig2, (kind, muSig2Key(keyData_, size), a, pop, pqzPop));
        }
        if ((kind == UAKinds.FROST_SECP256K1 || kind == UAKinds.FROST_BN254) && frostLayout(keyData_, size)) {
            return abi.encodeCall(IUARegistry.registerFrost, (kind, frostKey(keyData_, size), a, pop, pqzPop));
        }
        return abi.encodeCall(IUARegistry.register, (kind, keyData_, a, pop, pqzPop));
    }

    // ----- typed-signing R1b (TS-D13): the typed single keys, from and to their packed key data (no validation) -----

    /// The point length of a MuSig2 / FROST kind: 33 B (secp256k1 compressed) or 64 B (bn254).
    function pointSize(uint16 kind) internal pure returns (uint256) {
        return kind == UAKinds.MUSIG2_BN254 || kind == UAKinds.FROST_BN254 ? 64 : 33;
    }

    function webAuthnKey(bytes memory d) internal pure returns (IUARegistry.WebAuthnKey memory k) {
        (k.x, k.y, k.rpIdHash) = (_w(d, 0), _w(d, 32), _w(d, 64));
    }

    function keyData(IUARegistry.WebAuthnKey memory k) internal pure returns (bytes memory) {
        return abi.encodePacked(k.x, k.y, k.rpIdHash);
    }

    /// `aggKey ‖ u16 n ‖ n × key` with whole points.
    function muSig2Layout(bytes memory d, uint256 size) internal pure returns (bool) {
        return d.length >= size + 2 && d.length == size + 2 + _u16(d, size) * size;
    }

    function muSig2Key(bytes memory d, uint256 size) internal pure returns (IUARegistry.MuSig2Key memory k) {
        k.aggKey = _slice(d, 0, size);
        k.memberKeys = new bytes[](_u16(d, size));
        for (uint256 i; i < k.memberKeys.length; ++i) {
            k.memberKeys[i] = _slice(d, size + 2 + i * size, size);
        }
    }

    function keyData(IUARegistry.MuSig2Key memory k) internal pure returns (bytes memory d) {
        d = abi.encodePacked(k.aggKey, uint16(k.memberKeys.length));
        for (uint256 i; i < k.memberKeys.length; ++i) {
            d = bytes.concat(d, k.memberKeys[i]);
        }
    }

    /// `groupKey ‖ u16 t ‖ u16 n ‖ n × (t commitments ‖ R_i ‖ z_i)` with whole points.
    function frostLayout(bytes memory d, uint256 size) internal pure returns (bool) {
        if (d.length < size + 4) return false;
        return d.length == size + 4 + _u16(d, size + 2) * ((_u16(d, size) + 1) * size + 32);
    }

    function frostKey(bytes memory d, uint256 size) internal pure returns (IUARegistry.FrostKey memory k) {
        k.groupKey = _slice(d, 0, size);
        uint256 t = _u16(d, size);
        k.threshold = uint16(t);
        k.members = new IUARegistry.FrostMember[](_u16(d, size + 2));
        for (uint256 i; i < k.members.length; ++i) {
            uint256 o = size + 4 + i * ((t + 1) * size + 32);
            IUARegistry.FrostMember memory m = k.members[i];
            m.commitments = new bytes[](t);
            for (uint256 j; j < t; ++j) {
                m.commitments[j] = _slice(d, o + j * size, size);
            }
            m.r = _slice(d, o + t * size, size);
            m.z = _w(d, o + (t + 1) * size);
        }
    }

    function keyData(IUARegistry.FrostKey memory k) internal pure returns (bytes memory d) {
        d = abi.encodePacked(k.groupKey, k.threshold, uint16(k.members.length));
        for (uint256 i; i < k.members.length; ++i) {
            IUARegistry.FrostMember memory m = k.members[i];
            for (uint256 j; j < m.commitments.length; ++j) {
                d = bytes.concat(d, m.commitments[j]);
            }
            d = bytes.concat(d, m.r, m.z);
        }
    }

    function _w(bytes memory d, uint256 o) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(add(add(d, 32), o))
        }
    }

    function _slice(bytes memory d, uint256 o, uint256 n) private pure returns (bytes memory r) {
        r = new bytes(n);
        assembly ("memory-safe") {
            mcopy(add(r, 32), add(add(d, 32), o), n)
        }
    }

    /// A portable record's signature (`setKemKey`, `setPqzKey`) from its stored byte form: an `msig`'s
    /// `abi.encode(MemberSig[])` (first word 0x20) as `members`, anything else as `signature`. Test-only heuristic: no
    /// vector signature of a single key starts with the word 0x20.
    function sig(bytes memory s) internal pure returns (IUARegistry.UASig memory u) {
        if (s.length >= 64 && uint256(bytes32(s)) == 0x20) u.members = abi.decode(s, (IUARegistry.MemberSig[]));
        else u.signature = s;
    }

    /// The `UASig` of a pre-R1 `bytes auth` (the tokens' conversion, `UAKinds.uaSig`). Test-only: bytes that are no
    /// `abi.encode(keyData, sig)` (the older tests' junk and empty auths) travel as `signature`, so they stay junk.
    function auth(bytes32 ua, bytes memory a) internal pure returns (IUARegistry.UASig memory s) {
        if (!UAKinds.inNativeSpace(ua) && (a.length < 96 || uint256(bytes32(a)) != 0x40)) {
            s.signature = a;
            return s;
        }
        return UAKinds.uaSig(ua, a);
    }

    /// `auth` of each transfer of a batch.
    function auths(MetaTxLib.UAMetaTransfer[] memory ts, bytes[] memory as_)
        internal pure returns (IUARegistry.UASig[] memory s)
    {
        s = new IUARegistry.UASig[](as_.length);
        for (uint256 i; i < as_.length; ++i) s[i] = auth(ts[i].from, as_[i]);
    }

    function _u16(bytes memory d, uint256 o) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := shr(240, mload(add(add(d, 32), o)))
        }
    }
}
