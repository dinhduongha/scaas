// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {BlsMinSigBn254Verifier} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {UARegistryBase, MockWallet} from "./UARegistryBase.sol";

/// T-GAS (accounts.md §1.15/§1.16) for the UA-2a registry: the `msig` per-member overhead behind `MSIG_MEMBER_GAS`,
/// the structure bound, the native paths, and the gas a `register` of the heaviest kind needs. Per-kind verifier
/// gas with the real verifiers: `UARegistryVectors.t.sol` (`-vv`). Numbers are logged with `-vv`.
contract UAGasTest is UARegistryBase {
    uint256 internal constant SMART_KEY_1271_GAS = 400_000;

    /// Per-member gas of `msig` beyond the member's own verifier, for derived members verified here, derived members
    /// handed to gen 1, and native ECDSA members (mock verifiers: their own ~1–2 k is included, so it over-counts).
    /// `MSIG_MEMBER_GAS` must cover the worst of them plus what the caller must hold for the largest cap.
    function test_T_GAS_msigMemberOverhead() public {
        uint256 local = _derivedOverhead(reg, reg, 1);
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry gen2 = _deploy(address(0x5ca2), chainUidA, address(reg), false, BUDGET, address(0), true, none);
        uint256 handed = _derivedOverhead(gen2, reg, 2); // other weights: other ids than gen 1's
        uint256 native = _nativeOverhead();
        emit log_named_uint("msig per derived member", local);
        emit log_named_uint("msig per gen-1 member (gen 2)", handed);
        emit log_named_uint("msig per native ECDSA member", native);
        uint256 worst = local > handed ? local : handed;
        worst = worst > native ? worst : native;
        // + two cold accounts (the member's verifier, gen 1) + what the caller holds for the largest cap
        assertLe(worst + 2 * 2_600 + SMART_KEY_1271_GAS / 63 + 5_000, 35_000, "MSIG_MEMBER_GAS");
    }

    /// msig over the 7 single-key kinds (weights 1); (gas with 7 member sigs − gas with 1) / 6.
    function _derivedOverhead(UARegistry r, UARegistry home, uint16 w) internal returns (uint256) {
        Member[] memory m = new Member[](7);
        for (uint256 i; i < 7; ++i) {
            bytes memory k = _key(KINDS[i]);
            bytes32 id = UAKinds.uaOf(KINDS[i], k);
            if (!home.isRegistered(id)) _register(home, KINDS[i], k);
            m[i] = Member(KINDS[i], id, w);
        }
        uint256[2] memory used;
        uint16[2] memory t = [uint16(1), uint16(7)];
        for (uint256 x; x < 2; ++x) {
            Member[] memory mm = new Member[](7);
            for (uint256 i; i < 7; ++i) {
                mm[i] = m[i];
            }
            bytes memory d = _msigKey(t[x] * w, mm);
            bytes32 ua = r.register(UAKinds.MSIG, d, "", 0, "");
            bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
            UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](t[x]);
            for (uint16 j; j < t[x]; ++j) {
                (uint16 kind, bytes memory k) = _memberAt(d, j);
                s[j] = UARegistry.MemberSig(j, k, _sig(k, UAKinds.uaMessage(kind, UAKinds.PURPOSE_MEMBER, md)));
            }
            bytes memory auth = _msigAuth(d, s);
            uint256 g = gasleft();
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
            used[x] = g - gasleft();
        }
        return (used[1] - used[0]) / 6;
    }

    function _memberAt(bytes memory d, uint16 j) internal view returns (uint16 kind, bytes memory k) {
        uint256 o = 4 + 36 * uint256(j);
        kind = uint16(bytes2(abi.encodePacked(d[o], d[o + 1])));
        k = _key(kind);
    }

    /// msig over 16 EOAs; (gas with 16 − gas with 1) / 15.
    function _nativeOverhead() internal returns (uint256) {
        uint256[2] memory used;
        uint16[2] memory t = [uint16(1), uint16(16)];
        for (uint256 x; x < 2; ++x) {
            Member[] memory m = new Member[](16);
            for (uint256 i; i < 16; ++i) {
                m[i] = Member(UAKinds.EVM_EOA, _pad(vm.addr(1000 + i)), 1);
            }
            bytes memory d = _msigKey(t[x], m);
            bytes32 ua = reg.register(UAKinds.MSIG, d, "", 0, "");
            bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
            UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](t[x]);
            for (uint16 j; j < t[x]; ++j) {
                bytes32 id;
                assembly ("memory-safe") {
                    id := mload(add(add(d, 38), mul(36, j)))
                }
                uint256 pk = _pkOf(address(uint160(uint256(id))));
                s[j] = UARegistry.MemberSig(j, "", _nativeSig(reg, pk, UAKinds.PURPOSE_MEMBER, md));
            }
            bytes memory auth = _msigAuth(d, s);
            uint256 g = gasleft();
            reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
            used[x] = g - gasleft();
        }
        return (used[1] - used[0]) / 15;
    }

    function _pkOf(address a) internal pure returns (uint256) {
        for (uint256 pk = 1000; pk < 1016; ++pk) {
            if (vm.addr(pk) == a) return pk;
        }
        revert("pk");
    }

    /// Register step 4: Σ of the c largest caps + c × MSIG_MEMBER_GAS ≤ verifyBudget (here 1,145,000 + 105,000).
    function test_T_GAS_structureOverBudgetRefused() public {
        Member[] memory m = new Member[](3);
        uint16[3] memory kinds = [uint16(0x0100), uint16(0x0101), uint16(0x0107)];
        UARegistry tight =
            _deploy(address(0x5cc1), chainUidA, address(0), false, 1_200_000, address(0), true, _cfgs(address(mock)));
        UARegistry roomy =
            _deploy(address(0x5cc2), chainUidA, address(0), false, 1_250_000, address(0), true, _cfgs(address(mock)));
        for (uint256 i; i < 3; ++i) {
            bytes memory k = _key(kinds[i]);
            m[i] = Member(kinds[i], _register(tight, kinds[i], k), 1);
            _register(roomy, kinds[i], k);
        }
        bytes memory d = _msigKey(3, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        tight.register(UAKinds.MSIG, d, "", 0, "");
        roomy.register(UAKinds.MSIG, d, "", 0, ""); // exactly at the budget
        // threshold 2 of the same three: c = 2, the two largest caps
        d = _msigKey(2, m);
        tight.register(UAKinds.MSIG, d, "", 0, "");
        // 16 native members on a chain with SmartKeyAccount clones: 16 × 435 k = 6.96 M ≤ 12 M
        UARegistry ska = _deploy(
            address(0x5cc3),
            chainUidA,
            address(0),
            false,
            BUDGET,
            address(new MockWallet(address(0), 0, 0, address(0))),
            true,
            _cfgs(address(mock))
        );
        Member[] memory n = new Member[](16);
        for (uint256 i; i < 16; ++i) {
            n[i] = Member(UAKinds.EVM_EOA, _pad(vm.addr(1000 + i)), 1);
        }
        uint256 g = gasleft();
        ska.register(UAKinds.MSIG, _msigKey(16, n), "", 0, "");
        emit log_named_uint("register msig 16 natives", g - gasleft());
        UARegistry small = _deploy(
            address(0x5cc4),
            chainUidA,
            address(0),
            false,
            6_000_000,
            address(new MockWallet(address(0), 0, 0, address(0))),
            true,
            _cfgs(address(mock))
        );
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        small.register(UAKinds.MSIG, _msigKey(16, n), "", 0, "");
    }

    /// Caps of the gen-1 default config: ≤ verifyBudget and ≤ 50 % of it (public-chain rule, CTR-UA-23).
    function test_T_GAS_capsWithinBudget() public view {
        for (uint256 i; i < KINDS.length; ++i) {
            assertLe(reg.verifyCap(KINDS[i]), BUDGET / 2);
        }
    }

    /// Native paths: ECDSA, ERC-1271 (an ECDSA wallet), the 7702 base key.
    function test_T_GAS_native() public {
        uint256 pk = 0xA11CE;
        bytes32 ua = _pad(vm.addr(pk));
        bytes memory sig = _nativeSig(reg, pk, UAKinds.PURPOSE_METATX, DIGEST);
        uint256 g = gasleft();
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        emit log_named_uint("requireAuthorized native ECDSA (registry warm)", g - gasleft());
        MockWallet w = new MockWallet(vm.addr(pk), 0, 0, address(0));
        bytes32 wua = _pad(address(w));
        sig = _ecdsa(pk, reg.uaAuthDigest(wua, UAKinds.PURPOSE_METATX, DIGEST));
        g = gasleft();
        reg.requireAuthorized(wua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        emit log_named_uint("requireAuthorized native ERC-1271 (ECDSA wallet)", g - gasleft());
    }

    /// Addendum (b): `register(bls-bn254-minsig)` runs the G2 pairing check of `UAKinds` (needs ≥ 165,508 gas left at
    /// that point) and then the PoP under the 345 k cap (needs ≥ 355,476 left): the smallest call gas that registers.
    function test_T_GAS_registerHeadroomBlsBn254() public {
        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0107, address(new BlsMinSigBn254Verifier()), 345_000);
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), false, c);
        bytes memory call = abi.encodeCall(
            r.register,
            (0x0107, vm.parseJsonBytes(sj, ".derived[6].keyData"), vm.parseJsonBytes(sj, ".derived[6].pop.sig"), 0, "")
        );
        uint256 lo = 100_000;
        uint256 hi = 1_000_000;
        while (hi - lo > 500) {
            uint256 mid = (lo + hi) / 2;
            uint256 snap = vm.snapshotState();
            (bool ok,) = address(r).call{gas: mid}(call);
            vm.revertToState(snap);
            if (ok) hi = mid;
            else lo = mid;
        }
        emit log_named_uint("register bls-bn254-minsig: least call gas", hi);
        uint256 g = gasleft();
        (bool ok2,) = address(r).call(call);
        assertTrue(ok2);
        emit log_named_uint("register bls-bn254-minsig: gas used", g - gasleft());
        assertLt(hi, 500_000);
    }
}
