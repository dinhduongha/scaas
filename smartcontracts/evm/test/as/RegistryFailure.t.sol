// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Vm} from "forge-std/Vm.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {RevertingRegistry, GasBurningRegistry, ShortReturnRegistry, TwoReturningRegistry, LongReturnRegistry,
    GasProbeRegistry} from "./RegistryStubs.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IComplianceRegistry} from "../../src/regulated/IComplianceRegistry.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {nid} from "../helpers/Ids.sol";

/// Makes a call with a fixed gas limit from inside one transaction (the top-level call keeps the test's gas).
contract GasCaller {
    function go(address t, bytes calldata cd, uint256 g) external returns (bool ok, bytes memory ret) {
        (ok, ret) = t.call{gas: g}(cd);
    }

    function need(address r, bytes calldata cd, uint256 g) external view returns (bool ok) {
        bytes memory ret;
        (ok, ret) = r.staticcall{gas: g}(cd);
        ok = ok && ret.length == 32;
    }
}

/// Plan T29 (regulated-kinds spec §5 the bounded call, §9; Codex 4, F-11): a failure never means eligible. Each stub over the
/// canonical address (reverting, gas-burning, short, 2-returning, long): transfer, mint (wrap on 9), a fee leg and
/// `canReceive` fail `RegistryUnavailable(registry)`; burn and unwrap pass (no receiver). A starved call reverts
/// `RegistryGasStarved(REGISTRY_GAS, left)`; at the starvation line the callee gets its whole cap; the cap bounds a
/// gas-burning registry; `REGISTRY_GAS` is pinned at 50,000, at least twice the canonical `hasFlags` measured cold.
contract RegistryFailureTest is RegFixture {
    uint256 internal constant REGISTRY_GAS = 50_000; // the pin (spec §5): moves only old -> new in the commit
    uint64 internal constant MAX = type(uint64).max;
    address internal feeTo = address(0xFEE);
    GasCaller internal gc;

    function setUp() public override {
        super.setUp();
        gc = new GasCaller();
    }

    function _stubs() internal returns (bytes[5] memory c) {
        c = [address(new RevertingRegistry()).code, address(new GasBurningRegistry()).code,
            address(new ShortReturnRegistry()).code, address(new TwoReturningRegistry()).code,
            address(new LongReturnRegistry()).code];
    }

    /// `cd` as `who` with 3 M gas (a gas-burning registry without the cap would take all of it).
    function _as(address who, address t, bytes memory cd) internal returns (bool ok, bytes memory ret) {
        vm.prank(who);
        (ok, ret) = t.call{gas: 3_000_000}(cd);
    }

    function _unavailable(address who, address t, bytes memory cd, string memory what) internal {
        (bool ok, bytes memory ret) = _as(who, t, cd);
        assertFalse(ok, what);
        assertEq(ret, abi.encodeWithSelector(IRegulatedToken.RegistryUnavailable.selector, address(creg)), what);
    }

    function test_registryFailureNeverEligible() public {
        bytes[5] memory stubs = _stubs();
        bytes memory canonical = address(creg).code;
        for (uint256 i; i < 2; ++i) {
            for (uint256 j; j < stubs.length; ++j) {
                address t = _listed(i, 1, 1 << 16, keccak256(abi.encode(i, j)));
                _attest(nid(bob), 1, MAX);
                _attest(nid(feeTo), 1, MAX);
                bytes memory tr = abi.encodeCall(IERC20.transfer, (bob, 1));
                bytes memory pay = abi.encodeCall(NormalToken.payWithFee, (bob, 100, FeeMode.FIXED, 1, feeTo, PayMetaKit.ref(keccak256("r")), PayMetaKit.meta(keccak256("r"))));
                (bool ok,) = _as(alice, t, tr);
                assertTrue(ok, "control");
                vm.etch(address(creg), stubs[j]);
                _unavailable(alice, t, tr, "transfer");
                _unavailable(alice, t, pay, "fee leg");
                if (i == 0) {
                    _unavailable(address(this), t, abi.encodeCall(NormalToken.mint, (bob, 1)), "mint");
                    vm.prank(alice);
                    NormalToken(t).burn(1);
                } else {
                    usd.mint(alice, 5);
                    vm.prank(alice);
                    usd.approve(t, 5);
                    _unavailable(alice, t, abi.encodeWithSignature("wrap(uint256)", 5), "wrap (a mint)");
                    vm.prank(alice);
                    WrappedToken(payable(t)).unwrap(1, alice);
                }
                vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.RegistryUnavailable.selector, address(creg)));
                IRegulatedToken(t).canReceive(nid(bob));
                vm.etch(address(creg), canonical);
            }
        }
    }

    /// The cap bounds a registry that spends all it is given: the refused transfer costs about `REGISTRY_GAS`, not the 3 M
    /// the transaction carried.
    function test_registryGasCapBounds() public {
        bytes memory canonical = address(creg).code;
        for (uint256 i; i < 2; ++i) {
            address t = _listed(i, 1, 0, bytes32(i));
            vm.etch(address(creg), address(new GasBurningRegistry()).code);
            vm.prank(alice);
            (bool ok, bytes memory ret) = t.call{gas: 3_000_000}(abi.encodeCall(IERC20.transfer, (bob, 1)));
            Vm.Gas memory g = vm.lastCallGas();
            assertFalse(ok);
            assertEq(bytes4(ret), IRegulatedToken.RegistryUnavailable.selector);
            assertLt(g.gasTotalUsed, 200_000, "bounded by the cap");
            assertGt(g.gasTotalUsed, REGISTRY_GAS, "the registry got its cap");
            vm.etch(address(creg), canonical);
        }
    }

    function _starvedAt(address t, uint256 g) internal returns (bool starved, bool ok, bytes memory ret) {
        (ok, ret) = gc.go(t, abi.encodeCall(IERC20.transfer, (bob, 1)), g);
        starved = !ok && ret.length >= 4 && bytes4(ret) == IRegulatedToken.RegistryGasStarved.selector;
    }

    /// Spec §5: with less than `REGISTRY_GAS x 64/63 + margin` left, the call is not made: `RegistryGasStarved(cap, left)`,
    /// never a failure read from a starved registry. The control: the same transfer with ample gas.
    function test_registryStarvedReverts() public {
        for (uint256 i; i < 2; ++i) {
            address t = _listed(i, 1, 0, bytes32(i));
            _attest(nid(bob), 1, MAX);
            _attest(nid(address(gc)), 1, MAX);
            vm.prank(alice);
            IERC20(t).transfer(address(gc), 100);
            (bool starved, bool ok, bytes memory ret) = _starvedAt(t, 45_000);
            assertTrue(starved, "starved");
            (bytes4 sel, uint256 cap, uint256 left) = _decodeStarved(ret);
            assertEq(sel, IRegulatedToken.RegistryGasStarved.selector);
            assertEq(cap, REGISTRY_GAS, "the cap");
            assertLt(left, REGISTRY_GAS * 64 / 63 + 10_000, "left");
            (starved, ok,) = _starvedAt(t, 1_000_000);
            assertTrue(ok && !starved, "control");
        }
    }

    function _decodeStarved(bytes memory ret) internal pure returns (bytes4 sel, uint256 cap, uint256 left) {
        sel = bytes4(ret);
        assembly {
            cap := mload(add(ret, 36))
            left := mload(add(ret, 68))
        }
    }

    /// At the first gas limit the starvation check lets through, the registry was given its whole cap: a probe that
    /// refuses with less than `REGISTRY_GAS - 1,000` never reports `RegistryUnavailable` there (so the margin covers the
    /// call's own cost); one gas below, the call is still starved.
    function test_registryStarvedBoundary() public {
        address t = _listed(0, 1, 0, "b");
        _attest(nid(bob), 1, MAX);
        _attest(nid(address(gc)), 1, MAX);
        vm.prank(alice);
        IERC20(t).transfer(address(gc), 1_000);
        vm.etch(address(creg), address(new GasProbeRegistry()).code);
        uint256 lo = 45_000;
        uint256 hi = 1_000_000;
        (bool s,,) = _starvedAt(t, lo);
        assertTrue(s, "low end starved");
        (bool s2, bool ok2,) = _starvedAt(t, hi);
        assertTrue(!s2 && ok2, "high end passes");
        while (hi - lo > 1) {
            uint256 mid = (lo + hi) / 2;
            (bool sm,,) = _starvedAt(t, mid);
            if (sm) lo = mid;
            else hi = mid;
        }
        (, bool ok, bytes memory ret) = _starvedAt(t, hi);
        emit log_named_uint("first gas limit not starved", hi);
        assertTrue(ok || ret.length < 4 || bytes4(ret) != IRegulatedToken.RegistryUnavailable.selector,
            "the registry got its whole cap at the line");
    }

    /// `REGISTRY_GAS` = 50,000 (the starved error's `cap`), at least twice the canonical `hasFlags` measured cold on its
    /// costliest path (an attester's attestation: the record and the attester's enabled bit, both cold).
    function test_registryGasPinned() public {
        bytes32 a = nid(bob);
        _attest(a, 1 | (1 << 16), MAX);
        bytes memory cd = abi.encodeCall(IComplianceRegistry.hasFlags, (a, 1, 1 << 16));
        uint256 lo = 0;
        uint256 hi = REGISTRY_GAS;
        assertTrue(gc.need(address(creg), cd, hi), "the cap is enough");
        while (hi - lo > 1) {
            uint256 mid = (lo + hi) / 2;
            if (gc.need(address(creg), cd, mid)) hi = mid;
            else lo = mid;
        }
        emit log_named_uint("canonical hasFlags, cold, gas needed", hi);
        assertGe(REGISTRY_GAS, 2 * hi, "REGISTRY_GAS >= 2 x the cold need");

        address t = _listed(0, 1, 0, "p");
        _attest(nid(address(gc)), 1, MAX);
        vm.prank(alice);
        IERC20(t).transfer(address(gc), 10);
        (, , bytes memory ret) = _starvedAt(t, 45_000);
        (, uint256 cap,) = _decodeStarved(ret);
        assertEq(cap, REGISTRY_GAS, "the token's cap");
    }
}
