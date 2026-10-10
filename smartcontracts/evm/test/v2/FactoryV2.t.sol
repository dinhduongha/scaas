// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactoryV2} from "../../src/factory/OpenFactoryV2.sol";
import {IOpenFactoryV2} from "../../src/common/IOpenFactoryV2.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {MetaToken} from "../../src/metatx/MetaToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UID_, noneInit, underlyingInit, Rate} from "./helpers/V2Fixture.sol";

/// T4: factory v2 (TW2 §9, R130).
contract FactoryV2Test is Test {
    OpenFactoryV2 f;
    address registrar = address(0xF00D);
    NoUnderlyingToken noneImpl;
    UnderlyingToken underlyingImpl;
    MockERC20 usdc;
    MockERC20 usdt;
    MockERC20 dai;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    IOpenFactoryV2.TokenKind constant META = IOpenFactoryV2.TokenKind.META;
    IOpenFactoryV2.TokenKind constant ZETHER = IOpenFactoryV2.TokenKind.ZETHER;
    IOpenFactoryV2.TokenKind constant NONE = IOpenFactoryV2.TokenKind.META_NONE;
    IOpenFactoryV2.TokenKind constant SINGLE = IOpenFactoryV2.TokenKind.META_SINGLE;
    IOpenFactoryV2.TokenKind constant MULTI = IOpenFactoryV2.TokenKind.META_MULTI;

    function setUp() public {
        f = new OpenFactoryV2(registrar);
        noneImpl = new NoUnderlyingToken(address(f), address(0), UID_, false);
        underlyingImpl = new UnderlyingToken(address(f), address(0), UID_, false);
        vm.startPrank(registrar);
        f.registerImplementation(NONE, 1, address(noneImpl));
        f.registerImplementation(SINGLE, 1, address(underlyingImpl));
        vm.stopPrank();
        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdt = new MockERC20("Tether", "USDT", 6);
        dai = new MockERC20("Dai", "DAI", 18);
    }

    function _us(uint256 n) internal returns (address[] memory us) {
        us = new address[](n);
        address[3] memory pool = [address(usdc), address(usdt), address(dai)];
        for (uint256 i; i < n; ++i) us[i] = i < 3 ? pool[i] : address(new MockERC20("X", "X", 6));
    }

    /// 1000 to `holder` (the creator; before P1c the token minted to `creator`), no minter.
    function _noneInit(address holder) internal pure returns (bytes memory) {
        return abi.encode(noneInit("Points", "PTS", 0, 1000, holder, address(0)));
    }

    /// `UnderlyingInit` for legs `us` at 1:1, rates fixed, no guardian, no owner.
    function _init(address[] memory us) internal pure returns (bytes memory) {
        Rate memory c;
        uint256[] memory nums = new uint256[](us.length);
        for (uint256 i; i < us.length; ++i) nums[i] = 1;
        return abi.encode(underlyingInit(us, nums, nums, 6, c, address(0), address(0)));
    }

    function test_createsEachTierWithProvenance() public {
        vm.prank(alice);
        address a = f.createTiered(NONE, 1, new address[](0), _noneInit(alice), "s");
        assertEq(NoUnderlyingToken(a).balanceOf(alice), 1000);
        assertEq(NoUnderlyingToken(a).version(), 1);
        assertEq(NoUnderlyingToken(a).factory(), address(f));
        vm.prank(alice);
        address b = f.createTiered(SINGLE, 1, _us(1), _init(_us(1)), "s2");
        vm.prank(alice);
        address c = f.createTiered(SINGLE, 1, _us(3), _init(_us(3)), "s3"); // D9: SINGLE takes 1–8 legs
        assertTrue(f.isDeployedHere(c));
        assertEq(f.creatorOf(c), alice);
        (IOpenFactoryV2.TokenKind k, uint64 v) = f.versionOf(c);
        assertEq(uint8(k), uint8(SINGLE));
        assertEq(v, 1);
        // every underlying of a wrapper is indexed; tier 1 is not a wrapper of anything
        assertEq(f.getWrapper(alice, address(usdc)), b);
        assertEq(f.getWrapperCount(alice, address(usdc)), 2);
        assertEq(f.getWrapperAt(alice, address(usdc), 1), c);
        assertEq(f.getWrapper(alice, address(dai)), c);
        assertEq(f.deployCountFor(address(usdt)), 1);
        assertEq(f.deployedFor(address(usdt), 0), c);
        assertEq(f.deployCountFor(address(0)), 0);
    }

    function test_kindImpliesUnderlyingCount() public {
        bytes4 e = OpenFactoryV2.UnderlyingCountInvalid.selector;
        vm.expectRevert(abi.encodeWithSelector(e, 1));
        f.createTiered(NONE, 1, _us(1), _noneInit(alice), "a");
        vm.expectRevert(abi.encodeWithSelector(e, 0));
        f.createTiered(SINGLE, 1, _us(0), _init(_us(0)), "a");
        // D9: SINGLE takes 1–8 legs; nothing implements MULTI any more
        address two = f.createTiered(SINGLE, 1, _us(2), _init(_us(2)), "a");
        assertEq(UnderlyingToken(two).underlyings().length, 2);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV2.VersionUnknown.selector, MULTI, 1));
        f.createTiered(MULTI, 1, _us(2), _init(_us(2)), "b");
        address[] memory nine = _us(9);
        vm.expectRevert(abi.encodeWithSelector(e, 9));
        f.createTiered(SINGLE, 1, nine, _init(nine), "b");
        address[] memory eight = new address[](8);
        for (uint256 i; i < 8; ++i) eight[i] = nine[i];
        f.createTiered(SINGLE, 1, eight, _init(eight), "b");
    }

    function test_entryPointsMatchTheirKinds() public {
        bytes4 e = IOpenFactoryV2.VersionKindMismatch.selector;
        vm.expectRevert(abi.encodeWithSelector(e, META, SINGLE));
        f.createUnregistered(SINGLE, address(underlyingImpl), address(usdc), address(0), _init(_us(1)), "a");
        vm.expectRevert(abi.encodeWithSelector(e, NONE, META));
        f.createTiered(META, 1, new address[](0), "", "a");
        vm.expectRevert(abi.encodeWithSelector(e, NONE, ZETHER));
        f.createTieredUnregistered(ZETHER, address(underlyingImpl), new address[](0), "", "a");
    }

    function test_registrationChecksKindAndFactory() public {
        bytes4 e = IOpenFactoryV2.VersionKindMismatch.selector;
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(e, SINGLE, NONE));
        f.registerImplementation(SINGLE, 2, address(noneImpl));
        // D9: `UnderlyingToken` reports META_SINGLE for every leg count
        vm.expectRevert(abi.encodeWithSelector(e, MULTI, SINGLE));
        f.registerImplementation(MULTI, 1, address(underlyingImpl));
        // no answer (a v1 MetaToken has no tokenKind())
        MetaToken v1 = new MetaToken(address(f), address(0));
        vm.expectRevert(abi.encodeWithSelector(e, NONE, META));
        f.registerImplementation(NONE, 2, address(v1));
        NoUnderlyingToken foreign = new NoUnderlyingToken(address(0xBAD), address(0), UID_, false);
        vm.expectRevert(abi.encodeWithSelector(OpenFactoryV2.ImplementationFactoryMismatch.selector, address(foreign)));
        f.registerImplementation(NONE, 2, address(foreign));
        // append-only, version 0 reserved
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV2.VersionAlreadyRegistered.selector,
            NONE, 1, address(noneImpl)));
        f.registerImplementation(NONE, 1, address(noneImpl));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV2.VersionUnknown.selector, NONE, 0));
        f.registerImplementation(NONE, 0, address(noneImpl));
        // v1 kinds register without tokenKind(), as in v1
        f.registerImplementation(META, 1, address(v1));
        vm.stopPrank();
        vm.expectRevert(OpenFactoryV2.NotRegistrar.selector);
        f.registerImplementation(NONE, 3, address(noneImpl));
        assertEq(f.latestVersion(NONE), 1);
        assertEq(f.implementationOf(SINGLE, 1), address(underlyingImpl));
    }

    function test_v1PathStillWorksInFactoryV2() public {
        MetaToken v1 = new MetaToken(address(f), address(0));
        vm.prank(registrar);
        f.registerImplementation(META, 1, address(v1));
        vm.prank(alice);
        address t = f.createMetaToken(1, address(0), abi.encode("V1", "V1", uint8(6), uint256(5), address(0)), "v1");
        assertEq(MetaToken(t).balanceOf(alice), 5);
        (IOpenFactoryV2.TokenKind k,) = f.versionOf(t);
        assertEq(uint8(k), uint8(META));
    }

    function test_unregisteredTieredIsVersionZeroAndChecked() public {
        UnderlyingToken own = new UnderlyingToken(address(f), address(0), UID_, false);
        vm.prank(bob);
        address t = f.createTieredUnregistered(SINGLE, address(own), _us(1), _init(_us(1)), "u");
        (, uint64 v) = f.versionOf(t);
        assertEq(v, 0);
        assertEq(UnderlyingToken(t).version(), 0);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV2.ImplementationNotAContract.selector, address(0xDEAD)));
        f.createTieredUnregistered(SINGLE, address(0xDEAD), _us(1), _init(_us(1)), "u");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV2.VersionKindMismatch.selector, MULTI, SINGLE));
        f.createTieredUnregistered(MULTI, address(own), _us(2), _init(_us(2)), "u");
    }

    function test_saltIsScopedByCreator() public {
        vm.prank(alice);
        address a = f.createTiered(NONE, 1, new address[](0), _noneInit(alice), "same");
        vm.prank(bob);
        address b = f.createTiered(NONE, 1, new address[](0), _noneInit(bob), "same");
        assertTrue(a != b);
        assertEq(a, f.predictAddress(address(noneImpl), alice, "same"));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV2.SaltAlreadyUsed.selector, a));
        f.createTiered(NONE, 1, new address[](0), _noneInit(alice), "same");
    }

    function test_exactlyOneTieredTokenDeployedEvent() public {
        address[] memory us = _us(2);
        vm.recordLogs();
        vm.prank(alice);
        address t = f.createTiered(SINGLE, 1, us, _init(us), "e");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 tiered;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(f)) continue;
            assertEq(logs[i].topics[0], IOpenFactoryV2.TieredTokenDeployed.selector);
            ++tiered;
            assertEq(address(uint160(uint256(logs[i].topics[1]))), t);
            assertEq(address(uint160(uint256(logs[i].topics[2]))), alice);
            (IOpenFactoryV2.TokenKind k, uint64 v, address impl, address[] memory got) =
                abi.decode(logs[i].data, (IOpenFactoryV2.TokenKind, uint64, address, address[]));
            assertEq(uint8(k), uint8(SINGLE));
            assertEq(v, 1);
            assertEq(impl, address(underlyingImpl));
            assertEq(got.length, 2);
            assertEq(got[1], us[1]);
        }
        assertEq(tiered, 1);
    }

    function test_implementationSizes() public view {
        assertLe(address(noneImpl).code.length, 20_480); // CTR-TOK-24 (measured 20,038)
        assertLe(address(f).code.length, 24_576);
        // Transitional (P1d, D2): over EIP-170 until the size work; measured 25,408
        assertLe(address(underlyingImpl).code.length, 26_624);
    }
}
