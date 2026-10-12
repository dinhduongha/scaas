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
/// Accepts every signature: real-size signature blobs without a real verifier.
contract AcceptAll {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }

    function verifyPop(bytes calldata, bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }
}

contract UAGasTest is UARegistryBase {
    uint256 internal constant SMART_KEY_1271_GAS = 400_000;

    /// Per-member gas of `msig` beyond the member's own verifier, measured in the worst state: every touched account and
    /// storage slot cold (`vm.cool`), signatures of the largest real size in signatures.json, derived members verified
    /// here, derived members handed to gen 1, and native members as EOA, EIP-7702 designator and ERC-1271 wallet. The
    /// verifier/1271 execution itself (the cap covers it) is ~0 for the accept-all verifier, a few k for the wallet
    /// (which over-counts). `MSIG_MEMBER_GAS` must cover the worst plus what the caller must hold for the largest cap.
    function test_T_GAS_msigMemberOverhead() public {
        bytes memory big = _bigSig();
        AcceptAll v = new AcceptAll();
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](7);
        for (uint256 i; i < 7; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], address(v), _cap(KINDS[i]));
        }
        UARegistry home = _deploy(address(0x5ca1), chainUidA, address(0), false, BUDGET, address(0), true, c);
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry gen2 = _deploy(address(0x5ca2), chainUidA, address(home), false, BUDGET, address(0), true, none);
        uint256 local = _derivedOverhead(home, home, big, address(v), 1);
        uint256 handed = _derivedOverhead(gen2, home, big, address(v), 2); // other weights: other ids; gen 2 reads its record, then gen 1's
        uint256 eoa = _nativeOverhead(0);
        uint256 designator = _nativeOverhead(1);
        uint256 wallet = _nativeOverhead(2);
        emit log_named_uint("sig bytes (largest real)", big.length);
        emit log_named_uint("msig per derived member (cold)", local);
        emit log_named_uint("msig per gen-1 member via gen 2 (cold)", handed);
        emit log_named_uint("msig per native EOA member (cold)", eoa);
        emit log_named_uint("msig per native 7702-designator member (cold)", designator);
        emit log_named_uint("msig per native ERC-1271 wallet member (cold, incl. wallet exec)", wallet);
        uint256 worst = local > handed ? local : handed;
        worst = worst > eoa ? worst : eoa;
        worst = worst > designator ? worst : designator;
        worst = worst > wallet ? worst : wallet;
        // + what the caller holds for the largest cap (400 k / 63) + the call margin
        uint256 total = worst + SMART_KEY_1271_GAS / 63 + 5_000;
        emit log_named_uint("msig member bound needed", total);
        assertLe(total, 35_000, "MSIG_MEMBER_GAS");
    }

    /// The largest `sig` in signatures.json (derived rows and negatives), as zero-padded-length stand-in bytes.
    function _bigSig() internal view returns (bytes memory) {
        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        uint256 max;
        uint256 rows;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            for (uint256 k; k < 2; ++k) {
                string memory arr = k == 0 ? "sigs" : "negatives";
                for (
                    uint256 s;
                    vm.keyExistsJson(
                        sj, string.concat(".derived[", vm.toString(i), "].", arr, "[", vm.toString(s), "]")
                    );
                    ++s
                ) {
                    uint256 n = vm.parseJsonBytes(
                        sj, string.concat(".derived[", vm.toString(i), "].", arr, "[", vm.toString(s), "].sig")
                    ).length;
                    if (n > max) max = n;
                    ++rows;
                }
            }
        }
        assertEq(rows, 16 + 59, "signature rows scanned");
        assertGe(max, 256, "largest real signature");
        return new bytes(max);
    }

    function _cool(address[] memory a) internal {
        for (uint256 i; i < a.length; ++i) {
            vm.cool(a[i]);
        }
    }

    /// msig over the 7 single-key kinds (weights 1); (gas with 7 member sigs - gas with 1) / 6, all cold.
    function _derivedOverhead(UARegistry r, UARegistry home, bytes memory big, address verifier, uint16 w)
        internal
        returns (uint256)
    {
        Member[] memory m = new Member[](7);
        for (uint256 i; i < 7; ++i) {
            bytes memory k = _key(KINDS[i]);
            bytes32 id = UAKinds.uaOf(KINDS[i], k);
            if (!home.isRegistered(id)) home.register(KINDS[i], k, big, 0, "");
            m[i] = Member(KINDS[i], id, w);
        }
        uint256[2] memory used;
        uint16[2] memory t = [uint16(1), uint16(7)];
        for (uint256 x; x < 2; ++x) {
            bytes memory d = _msigKey(t[x] * w, m);
            bytes32 ua = r.register(UAKinds.MSIG, d, "", 0, "");
            UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](t[x]);
            for (uint16 j; j < t[x]; ++j) {
                (, bytes memory k) = _memberAt(d, j);
                s[j] = UARegistry.MemberSig(j, k, big);
            }
            bytes memory auth = _msigAuth(d, s);
            vm.cool(address(r));
            vm.cool(address(home));
            vm.cool(verifier);
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

    /// msig over 16 native members of one flavor (0 EOA, 1 EIP-7702 designator, 2 ERC-1271 wallet); (gas with 16 - gas
    /// with 1) / 15, all cold.
    function _nativeOverhead(uint8 flavor) internal returns (uint256) {
        UARegistry r = _deploy(
            address(uint160(0x5cd0 + flavor)),
            chainUidA,
            address(0),
            false,
            BUDGET,
            address(0),
            true,
            _cfgs(address(mock))
        );
        Member[] memory m = new Member[](16);
        bytes32[] memory ids = new bytes32[](16);
        address[] memory accounts = new address[](16);
        for (uint256 i; i < 16; ++i) {
            address a = vm.addr(1000 + i);
            if (flavor == 1) {
                vm.etch(a, abi.encodePacked(hex"ef0100", address(0xdE1e6A7e)));
            } else if (flavor == 2) {
                a = address(new MockWallet(a, 0, 0, address(0)));
            }
            accounts[i] = a;
            ids[i] = _pad(a);
            m[i] = Member(UAKinds.EVM_EOA, ids[i], 1);
        }
        uint256[2] memory used;
        uint16[2] memory t = [uint16(1), uint16(16)];
        for (uint256 x; x < 2; ++x) {
            bytes memory d = _msigKey(t[x], m);
            bytes32 ua = r.register(UAKinds.MSIG, d, "", 0, "");
            bytes memory auth = _nativeAuth(r, d, ua, t[x], ids);
            vm.cool(address(r));
            _cool(accounts);
            uint256 g = gasleft();
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
            used[x] = g - gasleft();
        }
        return (used[1] - used[0]) / 15;
    }

    function _nativeAuth(UARegistry r, bytes memory d, bytes32 ua, uint16 n, bytes32[] memory ids)
        internal
        view
        returns (bytes memory)
    {
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](n);
        for (uint16 j; j < n; ++j) {
            bytes32 id;
            assembly ("memory-safe") {
                id := mload(add(add(d, 38), mul(36, j)))
            }
            s[j] = UARegistry.MemberSig(j, "", _ecdsa(_pkOf(id, ids), r.uaAuthDigest(id, UAKinds.PURPOSE_MEMBER, md)));
        }
        return _msigAuth(d, s);
    }

    function _pkOf(bytes32 id, bytes32[] memory ids) internal pure returns (uint256) {
        for (uint256 i; i < ids.length; ++i) {
            if (ids[i] == id) return 1000 + i;
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
