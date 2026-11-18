// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {UACall} from "./UACall.sol";

/// Review2 T2 (C0-5): an `msig` PQZ holder is admitted only if its worst-case authorization (register step 4's bound)
/// plus `PqzSet.PQZ_DEBIT_MIN_GAS` (the cheapest PQZL debit, full relayed transaction) and the authorization's own calldata fit 2^24 (EIP-7825);
/// else `UAPqzHolder`. Stand-in verifiers with the caps of the kinds (gen-1 `DeployBase`: fndsa512 2.5 M, slhdsa128s 1.4 M).
contract UARegistryPqzBoundTest is UARegistryBase {
    uint256 internal constant LIM = 1 << 24; // EIP-7825
    uint256 internal constant AUTH_2_ML65 = 2 * (192 + 3_328); // two ML-DSA-65 slots, each signature padded to 3,328 B
    uint256 internal n;

    function _regs(address where, uint16[3] memory kinds, uint64[3] memory caps) internal returns (UARegistry r) {
        UARegistry.KindConfig[] memory base = _cfgs(address(mock));
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](base.length + 4);
        for (uint256 i; i < base.length; ++i) {
            c[i] = base[i];
        }
        for (uint256 i; i < 3; ++i) {
            c[base.length + i] = UARegistry.KindConfig(kinds[i], address(mock), caps[i]);
        }
        c[base.length + 3] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(mock), 1_000_000);
        r = _deploy(where, chainUidA, address(0), false, BUDGET, address(0), true, c);
    }

    function _pk(uint16 kind, uint256 salt) internal pure returns (bytes memory pk) {
        uint256 len = kind == 0x0130
            ? 1312
            : kind == 0x0131
                ? 1952
                : kind == 0x0132 ? 897 : kind == 0x0133 ? 32 : kind == 0x0134 ? 2592 : kind == 0x0135 ? 1793 : 16384;
        pk = new bytes(len);
        for (uint256 i; i < len; i += 32) {
            bytes32 w = keccak256(abi.encode(kind, salt, i));
            for (uint256 j; j < 32 && i + j < len; ++j) {
                pk[i + j] = w[j];
            }
        }
        if (kind == 0x0132 || kind == 0x0135) {
            pk[0] = kind == 0x0132 ? bytes1(0x09) : bytes1(0x0a);
            for (uint256 i = 1; i < len; ++i) {
                pk[i] = 0;
            }
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
        bytes memory rReg = _sig(
            pqz,
            UAKinds.uaMessage(
                UAKinds.PQZ_MLWE,
                UAKinds.PURPOSE_POP_V2,
                UAKinds.portableRecordDigest(ua, UAKinds.MSIG, h, UAKinds.kemRecordHash(ua, 0, ""))
            )
        );
        IUARegistry.UAAttrs memory a = UACall.attrs(pqz, keccak256(rReg), "");
        UACall.register(r, UAKinds.MSIG, d, a, _memberSigs(d, ua, a, keys, ks), rReg);
        assertEq(r.uaCount(UAKinds.PQZ_MLWE), 1);
    }

    function _memberSigs(
        bytes memory d,
        bytes32 ua,
        IUARegistry.UAAttrs memory a,
        bytes[] memory keys,
        uint16[] memory ks
    ) internal pure returns (bytes memory) {
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG, a));
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](ks.length);
        for (uint256 i; i < ks.length; ++i) {
            bytes32 id = UAKinds.uaOf(ks[i], keys[i]);
            s[i] = IUARegistry.MemberSig(
                _indexOf(d, id),
                new IUARegistry.InnerSig[](0),
                _sig(keys[i], UAKinds.uaMessage(ks[i], UAKinds.PURPOSE_MEMBER, md))
            );
        }
        for (uint256 i = 1; i < s.length; ++i) {
            for (uint256 j = i; j > 0 && s[j - 1].index > s[j].index; --j) {
                (s[j - 1], s[j]) = (s[j], s[j - 1]);
            }
        }
        return abi.encode(s);
    }

    /// Over the bound at EVERY set (owner 2026-11-15, 3zh-core group 2: the fixture moved when `{fndsa512 x 4}, t = 4` began to
    /// fit at `n2304-kmax4096`): `{fndsa512 x 4, slhdsa128s}, t = 5` (worst case about 11.6 M, inside the 12 M budget: it
    /// registers without a key) and 2-of-2 `fndsa1024` at `DeployBase`'s cap 5,250,000 (about 10.67 M; bound 16.97 M at the
    /// set with the least debit, `n2304-kmax4096`): neither fits 2^24 with a PQZ key.
    function test_register_msigHolderOverBound() public {
        UARegistry r =
            _regs(address(0x5CA7001), [uint16(0x0131), 0x0132, 0x0133], [uint64(200_000), 2_500_000, 1_400_000]);
        (bytes memory d, bytes32 ua,,) = _members(r, 0x0132, 4, true, 5);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        UACall.register(r, UAKinds.MSIG, d, _pqzOnly(_pk(0x0142, 900)), hex"01", hex"01");
        uint256 b = _bound(5_250_000, 2 * (192 + 1_280));
        emit log_named_uint(string.concat("MD-13 ", PqzSet.NAME, ": 2-of-2 fndsa1024 at 5,250,000, bound"), b);
        assertGt(b, LIM, "over 2^24 at this set");
        UARegistry r2 =
            _regs(address(0x5CA700B), [uint16(0x0135), 0x0132, 0x0133], [uint64(5_250_000), 2_500_000, 1_400_000]);
        (d, ua,,) = _members(r2, 0x0135, 2, false, 2);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        UACall.register(r2, UAKinds.MSIG, d, _pqzOnly(_pk(0x0142, 901)), hex"01", hex"01");
    }

    /// The per-set boundary of `{fndsa512 x 4}, t = 4` (about 10.2 M; owner 2026-11-15, 3zh-core group 2): a PQZ holder at
    /// `n2304-kmax4096` (`PQZ_DEBIT_MIN_GAS` 6,074,000 with its calibrated rows leaves about 10.70 M), `UAPqzHolder` at the
    /// three other sets (7.36 / 7.79 / 8.03 M of debit).
    function test_register_msigHolder_fndsa512x4_perSet() public {
        UARegistry r =
            _regs(address(0x5CA700C), [uint16(0x0131), 0x0132, 0x0133], [uint64(200_000), 2_500_000, 1_400_000]);
        (bytes memory d, bytes32 ua, bytes[] memory keys, uint16[] memory ks) = _members(r, 0x0132, 4, false, 4);
        if (keccak256(bytes(PqzSet.NAME)) == keccak256("n2304-kmax4096")) {
            _holder(r, d, ua, keys, ks);
        } else {
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
            UACall.register(r, UAKinds.MSIG, d, _pqzOnly(_pk(0x0142, 906)), hex"01", hex"01");
        }
    }

    /// 2-of-2 `mldsa65` registers at PQZL with a PQZ key.
    function test_register_msigHolderWithinBound() public {
        UARegistry r =
            _regs(address(0x5CA7002), [uint16(0x0131), 0x0132, 0x0133], [uint64(200_000), 2_500_000, 1_400_000]);
        (bytes memory d, bytes32 ua, bytes[] memory keys, uint16[] memory ks) = _members(r, 0x0131, 2, false, 2);
        _holder(r, d, ua, keys, ks);
    }

    /// A PQZ key with the proof hash of the filler proof `0x01` (the holder check comes before the PoP).
    function _pqzOnly(bytes memory pqz) internal pure returns (IUARegistry.UAAttrs memory) {
        return UACall.attrs(pqz, keccak256(hex"01"), "");
    }

    /// 2-of-2 worst case at cap `c`, the gen-2 forwarding hold (w / 63 + margin) and the cheapest debit.
    function _bound(uint256 c) internal pure returns (uint256) {
        return _bound(c, AUTH_2_ML65);
    }

    function _bound(uint256 c, uint256 auth) internal pure returns (uint256) {
        uint256 w = 2 * (c + 45_000) + (c - 400_000) / 63 + 3_500; // MSIG_ACCEPTED_GAS (3ze: 2,500 -> 3,500)
        return w + w / 63 + SigCheck.GAS_MARGIN + PqzSet.PQZ_DEBIT_MIN_GAS + 16 * auth;
    }

    /// CTR-UA-39 (owner Q2 / Q3): 2-of-2 `mldsa87` is PQ-eligible and its bound counts each signature at 4,627 B (padded 4,640):
    /// the largest cap that fits registers with a PQZ key, one more gas does not.
    function test_register_msigHolderBoundary_mldsa87() public {
        uint256 auth = 2 * (192 + 4_640);
        uint256 lo = 400_000;
        uint256 hi = 8_000_000;
        while (hi - lo > 1) {
            uint256 mid = (lo + hi) / 2;
            if (_bound(mid, auth) <= LIM) lo = mid;
            else hi = mid;
        }
        UARegistry r = _regs(address(0x5CA7005), [uint16(0x0134), 0x0132, 0x0133], [uint64(lo), 2_500_000, 1_400_000]);
        (bytes memory d, bytes32 ua, bytes[] memory keys, uint16[] memory ks) = _members(r, 0x0134, 2, false, 2);
        _holder(r, d, ua, keys, ks);
        UARegistry r2 =
            _regs(address(0x5CA7006), [uint16(0x0134), 0x0132, 0x0133], [uint64(lo + 1), 2_500_000, 1_400_000]);
        (d, ua, keys, ks) = _members(r2, 0x0134, 2, false, 2);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        UACall.register(r2, UAKinds.MSIG, d, _pqzOnly(_pk(0x0142, 903)), hex"01", hex"01");
    }

    /// CTR-UA-40 (owner Q2 / Q3): 2-of-2 `fndsa1024` is PQ-eligible and its bound counts each signature at 1,280 B (a whole number
    /// of words): the largest cap that fits registers with a PQZ key, one more gas does not.
    function test_register_msigHolderBoundary_fndsa1024() public {
        uint256 auth = 2 * (192 + 1_280);
        uint256 lo = 400_000;
        uint256 hi = 8_000_000;
        while (hi - lo > 1) {
            uint256 mid = (lo + hi) / 2;
            if (_bound(mid, auth) <= LIM) lo = mid;
            else hi = mid;
        }
        UARegistry r = _regs(address(0x5CA7007), [uint16(0x0135), 0x0132, 0x0133], [uint64(lo), 2_500_000, 1_400_000]);
        (bytes memory d, bytes32 ua, bytes[] memory keys, uint16[] memory ks) = _members(r, 0x0135, 2, false, 2);
        _holder(r, d, ua, keys, ks);
        UARegistry r2 =
            _regs(address(0x5CA7008), [uint16(0x0135), 0x0132, 0x0133], [uint64(lo + 1), 2_500_000, 1_400_000]);
        (d, ua, keys, ks) = _members(r2, 0x0135, 2, false, 2);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        UACall.register(r2, UAKinds.MSIG, d, _pqzOnly(_pk(0x0142, 903)), hex"01", hex"01");
    }

    /// The exact boundary: 2-of-2 `mldsa65` with cap `C` (worst case `2 (C + 35 k) + (C - 400 k) / 63`); the largest
    /// `C` with worst case (+ the gen-2 hold) + `PQZ_DEBIT_MIN_GAS` + 16 per byte of the signatures' calldata <= 2^24 registers, `C + 1` does not.
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
        UARegistry r2 =
            _regs(address(0x5CA7004), [uint16(0x0131), 0x0132, 0x0133], [uint64(lo + 1), 2_500_000, 1_400_000]);
        (d, ua, keys, ks) = _members(r2, 0x0131, 2, false, 2);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        UACall.register(r2, UAKinds.MSIG, d, _pqzOnly(_pk(0x0142, 902)), hex"01", hex"01");
    }

    // ----- MD-13 (owner 2026-11-15, F-1): the debit bound for every holder kind -----

    /// A single-key PQZ holder of `kind` on `r` with its R_REG stand-in; reverts as the registry does.
    function _singleHolder(UARegistry r, uint16 kind) internal returns (bytes32 ua) {
        bytes memory pk = _pk(kind, ++n);
        ua = r.uaOf(kind, pk);
        bytes memory pqz = _pk(0x0142, ++n);
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqz);
        bytes memory rReg = _sig(
            pqz,
            UAKinds.uaMessage(
                UAKinds.PQZ_MLWE,
                UAKinds.PURPOSE_POP_V2,
                UAKinds.portableRecordDigest(ua, kind, h, UAKinds.kemRecordHash(ua, 0, ""))
            )
        );
        IUARegistry.UAAttrs memory a = UACall.attrs(pqz, keccak256(rReg), "");
        bytes memory pop = _sig(pk, UAKinds.uaMessage(kind, UAKinds.PURPOSE_POP_V2, _regDigest(ua, kind, a)));
        assertEq(UACall.register(r, kind, pk, a, pop, rReg), ua);
    }

    /// The single-key bound: the kind's cap `c` with the verifier call's hold (`c / 63 + margin`), the set's cheapest debit and the
    /// signature's calldata (192 + the signature padded to words, as an `msig` slot counts it).
    function _singleBound(uint256 c, uint256 sigBytes) internal pure returns (uint256) {
        return c + c / 63 + SigCheck.GAS_MARGIN + PqzSet.PQZ_DEBIT_MIN_GAS + 16 * (192 + (sigBytes + 31) / 32 * 32);
    }

    /// MD-13: a single `mldsa87` holder registers with a PQZ key at the largest cap the bound admits on this set, one gas more is
    /// `UAPqzHolder` (before MD-13 a single key had no bound: the `msig` holders only).
    function test_register_singleHolderBoundary_mldsa87() public {
        uint256 lo = 400_000;
        uint256 hi = 16_000_000;
        while (hi - lo > 1) {
            uint256 mid = (lo + hi) / 2;
            if (_singleBound(mid, 4_627) <= LIM) lo = mid;
            else hi = mid;
        }
        UARegistry r = _regs(address(0x5CA7009), [uint16(0x0134), 0x0132, 0x0133], [uint64(lo), 2_500_000, 1_400_000]);
        _singleHolder(r, 0x0134);
        UARegistry r2 =
            _regs(address(0x5CA700A), [uint16(0x0134), 0x0132, 0x0133], [uint64(lo + 1), 2_500_000, 1_400_000]);
        bytes memory pk = _pk(0x0134, ++n);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, r2.uaOf(0x0134, pk)));
        UACall.register(r2, 0x0134, pk, _pqzOnly(_pk(0x0142, 904)), hex"01", hex"01");
        emit log_named_uint(string.concat("MD-13 ", PqzSet.NAME, ": the largest single mldsa87 holder cap"), lo);
    }

    /// MD-13 at `DeployBase`'s cached `mldsa87` cap 8,850,000: a PQZ holder only where the bound fits this set (arithmetic,
    /// 2026-11-15: n2048-kmax1024 and n2304-kmax4096 fit, n2560-kmax16384 and n2816-kmax65536 do not: there the cached `mldsa87` is
    /// a signing kind but not a PQZ holder, CTR-UA-16 / CTR-PQZ-12); the 65 / 44 cached caps fit every set. Same rule for a KEM
    /// record (a KEM key alone needs no debit: registers either way).
    function test_register_cachedHolders_thisSet() public {
        uint64[3] memory caps = [uint64(4_250_000), 5_950_000, 8_850_000];
        uint16[3] memory ks = [uint16(0x0130), 0x0131, 0x0134];
        uint256[3] memory sigs = [uint256(2_420), 3_309, 4_627];
        for (uint256 i; i < 3; ++i) {
            UARegistry r =
                _regs(address(uint160(0x5CA7010 + i)), [ks[i], 0x0132, 0x0133], [caps[i], 2_500_000, 1_400_000]);
            uint256 b = _singleBound(caps[i], sigs[i]);
            emit log_named_uint(
                string.concat("MD-13 ", PqzSet.NAME, " bound kind ", vm.toString(abi.encodePacked(ks[i]))), b
            );
            if (b <= LIM) {
                _singleHolder(r, ks[i]);
            } else {
                bytes memory pk = _pk(ks[i], ++n);
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, r.uaOf(ks[i], pk)));
                UACall.register(r, ks[i], pk, _pqzOnly(_pk(0x0142, 905 + i)), hex"01", hex"01");
            }
        }
        bool big = keccak256(bytes(PqzSet.NAME)) == keccak256("n2560-kmax16384")
            || keccak256(bytes(PqzSet.NAME)) == keccak256("n2816-kmax65536");
        assertEq(_singleBound(8_850_000, 4_627) > LIM, big, "the cached mldsa87 holds a PQZ key at n2048 / n2304 only");
        assertLe(_singleBound(5_950_000, 3_309), LIM, "the cached mldsa65 holds one at every set");
    }
}
