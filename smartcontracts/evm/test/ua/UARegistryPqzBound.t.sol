// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UARegistryBase} from "./UARegistryBase.sol";

/// Review2 T2 (C0-5): an `msig` PQZ holder is admitted only if its worst-case authorization (register step 4's bound)
/// plus `PqzSet.PQZ_DEBIT_MIN_GAS` (the cheapest PQZL debit, full relayed transaction) fits 2^24 (EIP-7825); else
/// `UAPqzHolder`. Stand-in verifiers with the caps of the kinds (gen-1 `DeployBase`: fndsa512 2.5 M, slhdsa128s 1.4 M).
contract UARegistryPqzBoundTest is UARegistryBase {
    uint256 internal constant LIM = 1 << 24; // EIP-7825
    uint256 internal n;

    function _regs(address where, uint16[3] memory kinds, uint64[3] memory caps) internal returns (UARegistry r) {
        UARegistry.KindConfig[] memory base = _cfgs(address(mock));
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](base.length + 4);
        for (uint256 i; i < base.length; ++i) c[i] = base[i];
        for (uint256 i; i < 3; ++i) c[base.length + i] = UARegistry.KindConfig(kinds[i], address(mock), caps[i]);
        c[base.length + 3] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(mock), 1_000_000);
        r = _deploy(where, chainUidA, address(0), false, BUDGET, address(0), true, c);
    }

    function _pk(uint16 kind, uint256 salt) internal pure returns (bytes memory pk) {
        uint256 len = kind == 0x0131 ? 1952 : kind == 0x0132 ? 897 : kind == 0x0133 ? 32 : 16384;
        pk = new bytes(len);
        for (uint256 i; i < len; i += 32) {
            bytes32 w = keccak256(abi.encode(kind, salt, i));
            for (uint256 j; j < 32 && i + j < len; ++j) pk[i + j] = w[j];
        }
        if (kind == 0x0132) {
            pk[0] = 0x09;
            for (uint256 i = 1; i < len; ++i) pk[i] = 0;
            pk[3] = bytes1(uint8(salt % 16)); // distinct keys, every h_i < q
        }
    }

    /// `count` members of `kind` (keys `salt…`), weight 1, plus (if `slh`) one `slhdsa128s`; threshold `t`.
    function _members(UARegistry r, uint16 kind, uint256 count, bool slh, uint16 t)
        internal
        returns (bytes memory d, bytes32 ua, bytes[] memory keys, uint16[] memory ks)
    {
        uint256 m = count + (slh ? 1 : 0);
        Member[] memory ms = new Member[](m);
        keys = new bytes[](m);
        ks = new uint16[](m);
        for (uint256 i; i < m; ++i) {
            ks[i] = i < count ? kind : 0x0133;
            keys[i] = _pk(ks[i], ++n);
            ms[i] = Member(ks[i], _register(r, ks[i], keys[i]), 1);
        }
        d = _msigKey(t, ms);
        ua = r.uaOf(UAKinds.MSIG, d);
    }

    /// The m-of-n PoP (every member signs, stored kinds: no key data) and the `R_REG` stand-in, then `register`. UA-8:
    /// R_REG over the portable digest, the members over the registration digest (it covers the proof hash).
    function _holder(UARegistry r, bytes memory d, bytes32 ua, bytes[] memory keys, uint16[] memory ks) internal {
        bytes memory pqz = _pk(0x0142, ++n);
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqz);
        bytes memory rReg = _sig(pqz, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, UAKinds.portablePopDigest(ua, h, 0)));
        IUARegistry.UAAttrs memory a = IUARegistry.UAAttrs(pqz, keccak256(rReg), 0, "");
        r.register(UAKinds.MSIG, d, a, _memberSigs(d, ua, a, keys, ks), rReg);
        assertEq(r.uaCount(UAKinds.PQZ_MLWE), 1);
    }

    function _memberSigs(bytes memory d, bytes32 ua, IUARegistry.UAAttrs memory a, bytes[] memory keys, uint16[] memory ks)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, a));
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](ks.length);
        for (uint256 i; i < ks.length; ++i) {
            bytes32 id = UAKinds.uaOf(ks[i], keys[i]);
            s[i] = UARegistry.MemberSig(_indexOf(d, id), "", _sig(keys[i], UAKinds.uaMessage(ks[i], UAKinds.PURPOSE_MEMBER, md)));
        }
        for (uint256 i = 1; i < s.length; ++i) {
            for (uint256 j = i; j > 0 && s[j - 1].index > s[j].index; --j) (s[j - 1], s[j]) = (s[j], s[j - 1]);
        }
        return abi.encode(s);
    }

    /// `{fndsa512 x 4, slhdsa128s}, t = 5` (worst case about 11.6 M, over the 12 M budget minus nothing: it registers
    /// without a key) and `{fndsa512 x 4}, t = 4` (10.2 M): with 6.8 M+ of debit neither fits 2^24.
    function test_register_msigHolderOverBound() public {
        UARegistry r = _regs(address(0x5CA7001), [uint16(0x0131), 0x0132, 0x0133], [uint64(200_000), 2_500_000, 1_400_000]);
        (bytes memory d, bytes32 ua,,) = _members(r, 0x0132, 4, true, 5);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        r.register(UAKinds.MSIG, d, _pqzOnly(_pk(0x0142, 900)), hex"01", hex"01");
        (d, ua,,) = _members(r, 0x0132, 4, false, 4);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        r.register(UAKinds.MSIG, d, _pqzOnly(_pk(0x0142, 901)), hex"01", hex"01");
    }

    /// 2-of-2 `mldsa65` registers at PQZL with a PQZ key.
    function test_register_msigHolderWithinBound() public {
        UARegistry r = _regs(address(0x5CA7002), [uint16(0x0131), 0x0132, 0x0133], [uint64(200_000), 2_500_000, 1_400_000]);
        (bytes memory d, bytes32 ua, bytes[] memory keys, uint16[] memory ks) = _members(r, 0x0131, 2, false, 2);
        _holder(r, d, ua, keys, ks);
    }

    /// A PQZ key with the proof hash of the filler proof `0x01` (the holder check comes before the PoP).
    function _pqzOnly(bytes memory pqz) internal pure returns (IUARegistry.UAAttrs memory) {
        return IUARegistry.UAAttrs(pqz, keccak256(hex"01"), 0, "");
    }

    /// 2-of-2 worst case at cap `c`, the gen-2 forwarding hold (w / 63 + margin) and the cheapest debit.
    function _bound(uint256 c) internal pure returns (uint256) {
        uint256 w = 2 * (c + 35_000) + (c - 400_000) / 63;
        return w + w / 63 + SigCheck.GAS_MARGIN + PqzSet.PQZ_DEBIT_MIN_GAS;
    }

    /// The exact boundary: 2-of-2 `mldsa65` with cap `C` (worst case `2 (C + 35 k) + (C - 400 k) / 63`); the largest
    /// `C` with worst case (+ the gen-2 hold) + `PQZ_DEBIT_MIN_GAS` <= 2^24 registers, `C + 1` does not.
    function test_register_msigHolderBoundary() public {
        uint256 lo = 400_000;
        uint256 hi = 8_000_000;
        while (hi - lo > 1) {
            uint256 mid = (lo + hi) / 2;
            if (_bound(mid) <= LIM) lo = mid;
            else hi = mid;
        }
        UARegistry r = _regs(address(0x5CA7003), [uint16(0x0131), 0x0132, 0x0133], [uint64(lo), 2_500_000, 1_400_000]);
        (bytes memory d, bytes32 ua, bytes[] memory keys, uint16[] memory ks) = _members(r, 0x0131, 2, false, 2);
        _holder(r, d, ua, keys, ks);
        UARegistry r2 = _regs(address(0x5CA7004), [uint16(0x0131), 0x0132, 0x0133], [uint64(lo + 1), 2_500_000, 1_400_000]);
        (d, ua, keys, ks) = _members(r2, 0x0131, 2, false, 2);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        r2.register(UAKinds.MSIG, d, _pqzOnly(_pk(0x0142, 902)), hex"01", hex"01");
    }
}
