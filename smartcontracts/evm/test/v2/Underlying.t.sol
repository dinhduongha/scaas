// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {stdJson} from "forge-std/StdJson.sol";
import {V2Fixture, Rate, underlyingInit} from "./helpers/V2Fixture.sol";
import {RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";

/// Kind `UNDERLYING` on `AdminLib` (CTR-TOK-22): flags valid for the kind, the rate role and the guardian as roles,
/// `disableFeature(RATE_ADJUSTABLE)` cancels a pending change, the single-asset ABI rule, init vs the factory's
/// `underlyings`, and `UnderlyingLib` writing only its own namespace.
contract UnderlyingTest is V2Fixture {
    using stdJson for string;

    uint8 constant RATE = 3;
    uint8 constant GUARD = 4;
    bytes32 constant NS_UNDERLYING = 0x38d6f7edefffa65376a58a6aced8a2c86698d3a0b5d15a785f69ed89d0cd1000;
    bytes32 constant NS_TOKEN = 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00;

    MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
    MockERC20 usdt = new MockERC20("Tether", "USDT", 6);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function initExt(address[] memory us, bytes memory d) external returns (address) {
        return _clone(_underlyingImpl(), address(this), us, d);
    }

    function _two() internal view returns (address[] memory us, uint256[] memory one) {
        us = new address[](2);
        (us[0], us[1]) = (address(usdc), address(usdt));
        one = new uint256[](2);
        (one[0], one[1]) = (1, 1);
    }

    function _wrap(UnderlyingToken t, MockERC20 u, address who, uint256 v) internal {
        u.mint(who, v);
        vm.startPrank(who);
        u.approve(address(t), v);
        t.wrap(address(u), v);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ flags and init

    function test_validFlags_underlyingKind() public {
        (address[] memory us, uint256[] memory one) = _two();
        Rate memory fixedRate;
        IUnderlyingToken.UnderlyingInit memory c = underlyingInit(us, one, one, 6, fixedRate, address(0), address(0));
        c.features |= 1 << AdminLib.MINTABLE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.MINTABLE));
        this.initExt(us, abi.encode(c));
        c = underlyingInit(us, one, one, 6, fixedRate, address(0), address(0));
        c.roles.rateAdmin = address(new RateAdminForwarder());
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleWithoutFeature.selector, RATE));
        this.initExt(us, abi.encode(c));
        c = underlyingInit(us, one, one, 6, _adjustable(bob), address(0), address(0));
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleNotContract.selector, RATE, bob));
        this.initExt(us, abi.encode(c));
        // adjustable without an initial rate admin is valid: the owner grants the role later
        c = underlyingInit(us, one, one, 6, _adjustable(address(0)), address(0), wrapperOwner);
        UnderlyingToken t = UnderlyingToken(this.initExt(us, abi.encode(c)));
        assertTrue(t.rateAdjustable());
        assertEq(t.kind(), AdminLib.KIND_UNDERLYING);
        assertEq(t.features(), (1 << AdminLib.PAYABLE) | (1 << RATE));
    }

    function test_init_legsMustMatchTheFactoryUnderlyings() public {
        (address[] memory us, uint256[] memory one) = _two();
        Rate memory fixedRate;
        bytes memory d = abi.encode(underlyingInit(us, one, one, 6, fixedRate, address(0), address(0)));
        address[] memory swapped = new address[](2);
        (swapped[0], swapped[1]) = (us[1], us[0]);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnknownUnderlying.selector, address(usdt)));
        this.initExt(swapped, d);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 2));
        this.initExt(_one(address(usdc)), d);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 0));
        this.initExt(new address[](0), d);
        address[] memory nine = new address[](9);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 9));
        this.initExt(nine, d);
    }

    // ------------------------------------------------------------------ rate role (RATE_ADJUSTABLE)

    function test_rateRole_grantRevokeRenounce_leaveTheRate() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _adjustable(address(0)));
        vm.expectRevert(IUnderlyingToken.NotRateAdmin.selector);
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(usdc), 101, 100)));
        vm.prank(wrapperOwner);
        t.grantRole(RATE, address(adm));
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(usdc), 101, 100)));
        vm.prank(wrapperOwner);
        t.revokeRole(RATE, address(adm));
        vm.expectRevert(IUnderlyingToken.NotRateAdmin.selector);
        adm.exec(address(t), abi.encodeCall(t.cancelRate, ()));
        // revoking leaves the pending change and the rate as they are
        (address u,,, uint64 eta) = t.pendingRate();
        assertEq(u, address(usdc));
        assertGt(eta, 0);
        assertTrue(t.rateAdjustable());
        vm.prank(wrapperOwner);
        t.grantRole(RATE, address(adm));
        adm.exec(address(t), abi.encodeCall(t.renounceRole, (RATE)));
        assertFalse(t.hasRole(RATE, address(adm)));
        assertTrue(t.rateAdjustable());
    }

    function test_disableRateAdjustable_cancelsThePendingChange_andFixesTheRate() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _adjustable(address(adm)));
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(usdc), 101, 100)));
        usdc.mint(alice, 10);
        vm.prank(alice);
        usdc.approve(address(t), 10);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapPausedForRateChange.selector, address(usdc)));
        t.wrap(10);
        vm.expectEmit(address(t));
        emit ITokenAdmin.FeatureDisabled(RATE, wrapperOwner);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.RateChangeCancelled(address(usdc));
        vm.prank(wrapperOwner);
        t.disableFeature(RATE);
        (address u, uint96 n, uint96 d, uint64 eta) = t.pendingRate();
        assertEq(abi.encode(u, n, d, eta), abi.encode(address(0), uint96(0), uint96(0), uint64(0)));
        assertFalse(t.rateAdjustable());
        vm.prank(alice);
        t.wrap(10);
        vm.expectRevert(IUnderlyingToken.RateFixed.selector);
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(usdc), 101, 100)));
        vm.expectRevert(IUnderlyingToken.RateFixed.selector);
        adm.exec(address(t), abi.encodeCall(t.executeRate, ()));
    }

    function test_disableRateAdjustable_withNothingPending_emitsNoCancel() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _adjustable(address(adm)));
        vm.recordLogs();
        vm.prank(wrapperOwner);
        t.disableFeature(RATE);
        assertEq(vm.getRecordedLogs().length, 1); // FeatureDisabled only
    }

    // ------------------------------------------------------------------ guardian (WRAP_DISABLEABLE)

    function test_guardianRole_disableWrap_oneWay_andFlagGates() public {
        (address[] memory us, uint256[] memory one) = _two();
        UnderlyingToken t = _multi(us, one, one, _fixedRate(), bob); // an EOA guardian is allowed
        vm.prank(alice);
        vm.expectRevert(IUnderlyingToken.NotGuardian.selector);
        t.disableWrap(address(usdt), "x");
        vm.expectEmit(address(t));
        emit IUnderlyingToken.WrapDisabled(address(usdt), bob, "depeg");
        vm.prank(bob);
        t.disableWrap(address(usdt), "depeg");
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapDisabledFor.selector, address(usdt)));
        t.disableWrap(address(usdt), "again");
        // a disabled flag stops the role: the guardian keeps the role but has no power
        vm.prank(wrapperOwner);
        t.disableFeature(GUARD);
        assertTrue(t.hasRole(GUARD, bob));
        vm.prank(bob);
        vm.expectRevert(IUnderlyingToken.NotGuardian.selector);
        t.disableWrap(address(usdc), "late");
    }

    function test_guardianRenounces() public {
        (address[] memory us, uint256[] memory one) = _two();
        UnderlyingToken t = _multi(us, one, one, _fixedRate(), bob);
        vm.prank(bob);
        t.renounceRole(GUARD);
        vm.prank(bob);
        vm.expectRevert(IUnderlyingToken.NotGuardian.selector);
        t.disableWrap(address(usdt), "x");
    }

    // ------------------------------------------------------------------ single-asset ABI (CTR-TOK-07)

    function test_singleAssetAbi_onlyWithExactlyOneLeg() public {
        (address[] memory us, uint256[] memory one) = _two();
        UnderlyingToken m = _multi(us, one, one, _fixedRate(), address(0));
        _wrap(m, usdc, alice, 100);
        vm.startPrank(alice);
        vm.expectRevert(IUnderlyingToken.UnderlyingRequired.selector);
        m.wrap(1);
        vm.expectRevert(IUnderlyingToken.UnderlyingRequired.selector);
        m.unwrap(1, alice);
        vm.expectRevert(IUnderlyingToken.UnderlyingRequired.selector);
        m.unwrap(1, alice, 0);
        vm.stopPrank();
        assertEq(m.underlying(), address(0));
        assertEq(m.underlyings().length, 2);

        UnderlyingToken s = _single(address(usdc), 6, 1, 1, _fixedRate());
        assertEq(s.underlying(), address(usdc));
        // the per-leg ABI works on one leg too
        _wrap(s, usdc, alice, 50);
        vm.prank(alice);
        (uint256 out, uint256 burned) = s.unwrap(address(usdc), 20, bob, 20);
        assertEq(out, 20);
        assertEq(burned, 20);
        assertEq(usdc.balanceOf(bob), 20);
    }

    // ------------------------------------------------------------------ storage (CTR-TOK-24)

    /// `UnderlyingLib` keeps the legs in `scaas.underlying`: leg i at `keccak256(i ‖ NS)` (+1 rate, +2 reserve);
    /// a wrap and a rate proposal write nothing in `scaas.token`.
    function test_underlyingStateLivesInItsNamespace() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken t = _single(address(usdc), 6, 3, 7, _adjustable(address(adm)));
        bytes32[12] memory tokBefore;
        for (uint256 i; i < 12; ++i) tokBefore[i] = vm.load(address(t), bytes32(uint256(NS_TOKEN) + i));
        usdc.mint(address(this), 1_000);
        usdc.approve(address(t), 1_000);
        t.wrap(1_000);
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(usdc), 3, 7)));
        for (uint256 i; i < 12; ++i) assertEq(vm.load(address(t), bytes32(uint256(NS_TOKEN) + i)), tokBefore[i]);
        bytes32 leg0 = keccak256(abi.encode(uint256(0), NS_UNDERLYING));
        assertEq(address(uint160(uint256(vm.load(address(t), leg0)))), address(usdc));
        uint256 rate = uint256(vm.load(address(t), bytes32(uint256(leg0) + 1)));
        assertEq(rate & type(uint96).max, 3);
        assertEq(rate >> 96, 7);
        assertEq(uint256(vm.load(address(t), bytes32(uint256(leg0) + 2))), 1_000);
        // nothing below slot 6 except the ERC-20 state: no `_legCount` in the linear layout
        for (uint256 s = 3; s < 8; ++s) assertEq(vm.load(address(t), bytes32(s)), bytes32(0));
    }

    /// Errors raised inside the external `UnderlyingLib` (OpenZeppelin's `FailedCall`, `SafeERC20FailedOperation`,
    /// `InsufficientBalance`) are in the token ABI only if `IUnderlyingToken` declares them.
    function test_libraryErrorsAreInTheTokenAbi() public view {
        string memory lib = vm.readFile("./out/UnderlyingLib.sol/UnderlyingLib.json");
        string memory tok = vm.readFile("./out/UnderlyingToken.sol/UnderlyingToken.json");
        bytes4[] memory have = _errorSelectors(tok);
        bytes4[] memory want = _errorSelectors(lib);
        assertGt(want.length, 0);
        for (uint256 i; i < want.length; ++i) {
            bool found;
            for (uint256 j; j < have.length; ++j) found = found || have[j] == want[i];
            assertTrue(found, vm.toString(want[i]));
        }
    }

    function _errorSelectors(string memory art) internal view returns (bytes4[] memory out) {
        uint256 n;
        while (vm.keyExistsJson(art, _at(".abi[", n, "]"))) ++n;
        bytes4[] memory tmp = new bytes4[](n);
        uint256 k;
        for (uint256 i; i < n; ++i) {
            if (!_eq(art.readString(_at(".abi[", i, "].type")), "error")) continue;
            string memory sig = string.concat(art.readString(_at(".abi[", i, "].name")), "(");
            for (uint256 j; vm.keyExistsJson(art, _at(".abi[", i, string.concat("].inputs[", vm.toString(j), "]"))); ++j) {
                sig = string.concat(sig, j == 0 ? "" : ",", art.readString(
                    _at(".abi[", i, string.concat("].inputs[", vm.toString(j), "].type"))));
            }
            tmp[k++] = bytes4(keccak256(bytes(string.concat(sig, ")"))));
        }
        out = new bytes4[](k);
        for (uint256 i; i < k; ++i) out[i] = tmp[i];
    }

    function _at(string memory a, uint256 i, string memory b) internal pure returns (string memory) {
        return string.concat(a, vm.toString(i), b);
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
