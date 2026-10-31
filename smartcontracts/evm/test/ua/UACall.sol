// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

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

    /// `register`, or `registerMsig` for kind `msig` (key data and pop in their byte forms).
    function register(
        IUARegistry r,
        uint16 kind,
        bytes memory keyData_,
        IUARegistry.UAAttrs memory a,
        bytes memory pop,
        bytes memory pqzPop
    ) internal returns (bytes32) {
        if (kind == UAKinds.MSIG) return r.registerMsig(structure(keyData_), a, members(pop), pqzPop);
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
        return abi.encodeCall(IUARegistry.register, (kind, keyData_, a, pop, pqzPop));
    }

    /// A portable record's signature (`setKemKey`, `setPqzKey`) from its stored byte form: an `msig`'s
    /// `abi.encode(MemberSig[])` (first word 0x20) as `members`, anything else as `signature`. Test-only heuristic: no
    /// vector signature of a single key starts with the word 0x20.
    function sig(bytes memory s) internal pure returns (IUARegistry.UASig memory u) {
        if (s.length >= 64 && uint256(bytes32(s)) == 0x20) u.members = abi.decode(s, (IUARegistry.MemberSig[]));
        else u.signature = s;
    }

    /// The `requireAuthorized` argument of a pre-R1 `bytes auth` (the tokens' conversion, `UAKinds.uaSig`).
    function auth(bytes32 ua, bytes memory a) internal pure returns (IUARegistry.UASig memory) {
        return UAKinds.uaSig(ua, a);
    }

    function _u16(bytes memory d, uint256 o) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := shr(240, mload(add(add(d, 32), o)))
        }
    }
}
