// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactoryV2} from "../../src/factory/OpenFactoryV2.sol";
import {IOpenFactoryV2} from "../../src/common/IOpenFactoryV2.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {SingleUnderlyingToken} from "../../src/metatx/SingleUnderlyingToken.sol";
import {MultiUnderlyingToken} from "../../src/metatx/MultiUnderlyingToken.sol";
import {MetaToken} from "../../src/metatx/MetaToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";

/// T4: factory v2 (TW2 §9, R130).
contract FactoryV2Test is Test {
    OpenFactoryV2 f;
    address registrar = address(0xF00D);
    NoUnderlyingToken noneImpl;
    SingleUnderlyingToken singleImpl;
    MultiUnderlyingToken multiImpl;
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
        noneImpl = new NoUnderlyingToken(address(f), address(0));
        singleImpl = new SingleUnderlyingToken(address(f), address(0));
        multiImpl = new MultiUnderlyingToken(address(f), address(0));
        vm.startPrank(registrar);
        f.registerImplementation(NONE, 1, address(noneImpl));
        f.registerImplementation(SINGLE, 1, address(singleImpl));
        f.registerImplementation(MULTI, 1, address(multiImpl));
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

    function _noneInit() internal pure returns (bytes memory) {
        return abi.encode("Points", "PTS", uint8(0), uint256(1000), address(0));
    }

    function _singleInit() internal pure returns (bytes memory) {
        SingleUnderlyingToken.RateConfig memory c;
        return abi.encode("Wrapped USDC", "wUSDC", uint8(6), uint256(1), uint256(1), c);
    }

    function _multiInit(uint256 n) internal pure returns (bytes memory) {
        SingleUnderlyingToken.RateConfig memory c;
        uint256[] memory nums = new uint256[](n);
        for (uint256 i; i < n; ++i) nums[i] = 1;
        return abi.encode("Any USD", "aUSD", uint8(18), nums, nums, c, address(0));
    }

    function test_createsEachTierWithProvenance() public {
        vm.prank(alice);
        address a = f.createTiered(NONE, 1, new address[](0), _noneInit(), "s");
        assertEq(NoUnderlyingToken(a).balanceOf(alice), 1000);
        assertEq(NoUnderlyingToken(a).version(), 1);
        assertEq(NoUnderlyingToken(a).factory(), address(f));
        vm.prank(alice);
        address b = f.createTiered(SINGLE, 1, _us(1), _singleInit(), "s2");
        vm.prank(alice);
        address c = f.createTiered(MULTI, 1, _us(3), _multiInit(3), "s3");
        assertTrue(f.isDeployedHere(c));
        assertEq(f.creatorOf(c), alice);
        (IOpenFactoryV2.TokenKind k, uint64 v) = f.versionOf(c);
        assertEq(uint8(k), uint8(MULTI));
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
        f.createTiered(NONE, 1, _us(1), _noneInit(), "a");
        vm.expectRevert(abi.encodeWithSelector(e, 0));
        f.createTiered(SINGLE, 1, _us(0), _singleInit(), "a");
        vm.expectRevert(abi.encodeWithSelector(e, 2));
        f.createTiered(SINGLE, 1, _us(2), _singleInit(), "a");
        vm.expectRevert(abi.encodeWithSelector(e, 1));
        f.createTiered(MULTI, 1, _us(1), _multiInit(1), "a");
        address[] memory nine = _us(9);
        vm.expectRevert(abi.encodeWithSelector(e, 9));
        f.createTiered(MULTI, 1, nine, _multiInit(9), "a");
        address[] memory eight = new address[](8);
        for (uint256 i; i < 8; ++i) eight[i] = nine[i];
        f.createTiered(MULTI, 1, eight, _multiInit(8), "a");
    }

    function test_entryPointsMatchTheirKinds() public {
        bytes4 e = IOpenFactoryV2.VersionKindMismatch.selector;
        vm.expectRevert(abi.encodeWithSelector(e, META, SINGLE));
        f.createUnregistered(SINGLE, address(singleImpl), address(usdc), address(0), _singleInit(), "a");
        vm.expectRevert(abi.encodeWithSelector(e, NONE, META));
        f.createTiered(META, 1, new address[](0), "", "a");
        vm.expectRevert(abi.encodeWithSelector(e, NONE, ZETHER));
        f.createTieredUnregistered(ZETHER, address(singleImpl), new address[](0), "", "a");
    }

    function test_registrationChecksKindAndFactory() public {
        bytes4 e = IOpenFactoryV2.VersionKindMismatch.selector;
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(e, SINGLE, NONE));
        f.registerImplementation(SINGLE, 2, address(noneImpl));
        // no answer (a v1 MetaToken has no tokenKind())
        MetaToken v1 = new MetaToken(address(f), address(0));
        vm.expectRevert(abi.encodeWithSelector(e, NONE, META));
        f.registerImplementation(NONE, 2, address(v1));
        NoUnderlyingToken foreign = new NoUnderlyingToken(address(0xBAD), address(0));
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
        assertEq(f.implementationOf(SINGLE, 1), address(singleImpl));
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
        SingleUnderlyingToken own = new SingleUnderlyingToken(address(f), address(0));
        vm.prank(bob);
        address t = f.createTieredUnregistered(SINGLE, address(own), _us(1), _singleInit(), "u");
        (, uint64 v) = f.versionOf(t);
        assertEq(v, 0);
        assertEq(SingleUnderlyingToken(t).version(), 0);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV2.ImplementationNotAContract.selector, address(0xDEAD)));
        f.createTieredUnregistered(SINGLE, address(0xDEAD), _us(1), _singleInit(), "u");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV2.VersionKindMismatch.selector, MULTI, SINGLE));
        f.createTieredUnregistered(MULTI, address(own), _us(2), _multiInit(2), "u");
    }

    function test_saltIsScopedByCreator() public {
        vm.prank(alice);
        address a = f.createTiered(NONE, 1, new address[](0), _noneInit(), "same");
        vm.prank(bob);
        address b = f.createTiered(NONE, 1, new address[](0), _noneInit(), "same");
        assertTrue(a != b);
        assertEq(a, f.predictAddress(address(noneImpl), alice, "same"));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV2.SaltAlreadyUsed.selector, a));
        f.createTiered(NONE, 1, new address[](0), _noneInit(), "same");
    }

    function test_exactlyOneTieredTokenDeployedEvent() public {
        address[] memory us = _us(2);
        vm.recordLogs();
        vm.prank(alice);
        address t = f.createTiered(MULTI, 1, us, _multiInit(2), "e");
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
            assertEq(uint8(k), uint8(MULTI));
            assertEq(v, 1);
            assertEq(impl, address(multiImpl));
            assertEq(got.length, 2);
            assertEq(got[1], us[1]);
        }
        assertEq(tiered, 1);
    }

    function test_implementationSizesFitEip170() public view {
        assertLe(address(noneImpl).code.length, 24_576);
        assertLe(address(singleImpl).code.length, 24_576);
        assertLe(address(multiImpl).code.length, 24_576);
        assertLe(address(f).code.length, 24_576);
    }
}
