// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UID_, noneInit, underlyingInit, Rate} from "./helpers/V2Fixture.sol";

/// Answers `kind()` only.
contract KindOnly {
    function kind() external pure returns (uint8) { return 0; }
}

/// Unregistered implementation whose `initialize` self-destructs the clone (same transaction as its creation: post-Cancun
/// SELFDESTRUCT still deletes the account then). Answers what `createTokenUnregistered` and `TokenCreated` read.
contract SelfDestructImpl {
    address immutable F;
    bytes32 immutable U;

    constructor(address f_, bytes32 u_) { F = f_; U = u_; }

    function kind() external pure returns (uint8) { return 0; }
    function factory() external view returns (address) { return F; }
    function chainUid() external view returns (bytes32) { return U; }
    function lockedFeatures() external pure returns (uint256) { return 0; }

    function initialize(address, uint64, IFactoryToken.TokenConfig calldata) external {
        selfdestruct(payable(address(0)));
    }
}

/// `OpenFactory` (CTR-TOK-03, CTR-TOK-25): catalogue checks, `createToken`/`createTokenUnregistered` with
/// `TokenConfig`, one `TokenCreated`, provenance, salt scoped by the creator; the token validates flags and fields.
contract FactoryTest is Test {
    OpenFactory f;
    address registrar = address(0xF00D);
    NoUnderlyingToken noneImpl;
    UnderlyingToken underlyingImpl;
    MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
    MockERC20 usdt = new MockERC20("Tether", "USDT", 6);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    IOpenFactory.TokenKind constant NONE = IOpenFactory.TokenKind.NONE;
    IOpenFactory.TokenKind constant UNDERLYING = IOpenFactory.TokenKind.UNDERLYING;

    function setUp() public {
        f = new OpenFactory(registrar, UID_);
        noneImpl = new NoUnderlyingToken(address(f), address(0), UID_, address(0), false);
        underlyingImpl = new UnderlyingToken(address(f), address(0), UID_, address(0), false);
        vm.startPrank(registrar);
        f.registerImplementation(NONE, 1, address(noneImpl));
        f.registerImplementation(UNDERLYING, 1, address(underlyingImpl));
        vm.stopPrank();
    }

    function _none(address holder) internal pure returns (IFactoryToken.TokenConfig memory) {
        return noneInit("Points", "PTS", 0, 1000, holder, address(0));
    }

    /// Legs `us` at 1:1, rates fixed, no guardian, no owner.
    function _wrapper(address[] memory us) internal pure returns (IFactoryToken.TokenConfig memory) {
        Rate memory c;
        uint256[] memory one = new uint256[](us.length);
        for (uint256 i; i < us.length; ++i) one[i] = 1;
        return underlyingInit(us, one, one, 6, c, address(0), address(0));
    }

    function _two() internal view returns (address[] memory us) {
        us = new address[](2);
        (us[0], us[1]) = (address(usdc), address(usdt));
    }

    // ------------------------------------------------------------------ catalogue

    function test_constructor_refusesZeroChainUid() public {
        vm.expectRevert(IOpenFactory.ChainUidZero.selector);
        new OpenFactory(registrar, bytes32(0));
        assertEq(f.chainUid(), UID_);
        assertEq(f.registrar(), registrar);
    }

    function test_register_checksKindFactoryAndChainUid() public {
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionKindMismatch.selector, UNDERLYING, 0));
        f.registerImplementation(UNDERLYING, 2, address(noneImpl));
        address otherFactory = address(new NoUnderlyingToken(address(0xFAC), address(0), UID_, address(0), false));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationFactoryMismatch.selector, otherFactory));
        f.registerImplementation(NONE, 2, otherFactory);
        bytes32 otherUid = keccak256("other chain");
        address otherChain = address(new NoUnderlyingToken(address(f), address(0), otherUid, address(0), false));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, otherUid));
        f.registerImplementation(NONE, 2, otherChain);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationNotAContract.selector, address(0xDEAD)));
        f.registerImplementation(NONE, 2, address(0xDEAD));
        address mute = address(new MockERC20("M", "M", 6)); // no kind()
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionKindMismatch.selector, NONE, type(uint256).max));
        f.registerImplementation(NONE, 2, mute);
        address kindOnly = address(new KindOnly()); // no factory()
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationFactoryMismatch.selector, kindOnly));
        f.registerImplementation(NONE, 2, kindOnly);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindReserved.selector, IOpenFactory.TokenKind.NONE_ZETHER_PQZ));
        f.registerImplementation(IOpenFactory.TokenKind.NONE_ZETHER_PQZ, 1, address(noneImpl)); // P6g built 4, 5
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, NONE, 0));
        f.registerImplementation(NONE, 0, address(noneImpl));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionAlreadyRegistered.selector, NONE, 1,
            address(noneImpl)));
        f.registerImplementation(NONE, 1, address(noneImpl));
        vm.stopPrank();
        vm.prank(alice);
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.registerImplementation(NONE, 3, address(noneImpl));
        assertEq(f.latestVersion(NONE), 1);
        assertEq(f.implementationOf(UNDERLYING, 1), address(underlyingImpl));
    }

    function test_deprecateOnlyMarks() public {
        vm.prank(alice);
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.deprecate(NONE, 1, "x");
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, NONE, 9));
        f.deprecate(NONE, 9, "x");
        vm.prank(registrar);
        f.deprecate(NONE, 1, "bug");
        assertTrue(f.isDeprecated(NONE, 1));
        vm.prank(alice);
        f.createToken(NONE, 1, _none(alice), "still"); // deprecation is advisory
    }

    // ------------------------------------------------------------------ create

    function test_createToken_none_emitsOneEventWithProvenance() public {
        address predicted = f.predictAddress(address(noneImpl), alice, "s");
        vm.recordLogs();
        vm.prank(alice);
        address t = f.createToken(NONE, 1, _none(alice), "s");
        assertEq(t, predicted);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 created;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(f)) {
                ++created;
                assertEq(logs[i].topics[0], IOpenFactory.TokenCreated.selector);
                assertEq(address(uint160(uint256(logs[i].topics[1]))), t);
                assertEq(address(uint160(uint256(logs[i].topics[2]))), alice);
                assertEq(uint256(logs[i].topics[3]), uint256(NONE));
                (uint64 v, address impl, uint256 feat, uint256 locked, address owner, address[] memory us) =
                    abi.decode(logs[i].data, (uint64, address, uint256, uint256, address, address[]));
                assertEq(abi.encode(v, impl, feat, locked, owner, us.length),
                    abi.encode(uint64(1), address(noneImpl), uint256(7), uint256(5), address(0), uint256(0)));
                // not `cfg.lockedFeatures` (0): the token stores `locked | (features & ALWAYS_LOCKED)`
                assertEq(locked, NoUnderlyingToken(t).lockedFeatures());
            }
        }
        assertEq(created, 1);
        assertEq(NoUnderlyingToken(t).balanceOf(alice), 1000);
        assertEq(NoUnderlyingToken(t).version(), 1);
        assertEq(NoUnderlyingToken(t).creator(), alice);
        assertTrue(f.isToken(t));
        assertEq(f.creatorOf(t), alice);
        (IOpenFactory.TokenKind k, uint64 ver) = f.versionOf(t);
        assertEq(uint8(k), uint8(NONE));
        assertEq(ver, 1);
        assertFalse(f.isToken(address(noneImpl)));
    }

    function test_createToken_underlying_indexesEveryLeg_includingNative() public {
        address[] memory us = new address[](3);
        (us[0], us[1], us[2]) = (address(usdc), address(usdt), address(0));
        vm.prank(alice);
        address t = f.createToken(UNDERLYING, 1, _wrapper(us), "w");
        assertEq(UnderlyingToken(t).underlyings().length, 3);
        assertEq(f.getWrapper(alice, address(usdc)), t);
        assertEq(f.getWrapper(alice, address(0)), t);
        assertEq(f.getWrapperCount(alice, address(usdt)), 1);
        assertEq(f.getWrapperAt(alice, address(usdt), 0), t);
        assertEq(f.deployCountFor(address(0)), 1);
        assertEq(f.deployedFor(address(usdc), 0), t);
        assertEq(f.getWrapper(bob, address(usdc)), address(0));
    }

    function test_createToken_legCountByKind() public {
        IFactoryToken.TokenConfig memory c = _none(alice);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usdc), 1, 1);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.UnderlyingCountInvalid.selector, 1));
        f.createToken(NONE, 1, c, "a");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.UnderlyingCountInvalid.selector, 0));
        f.createToken(UNDERLYING, 1, _wrapper(new address[](0)), "a");
        address[] memory nine = new address[](9);
        for (uint256 i; i < 9; ++i) nine[i] = address(new MockERC20("X", "X", 6));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.UnderlyingCountInvalid.selector, 9));
        f.createToken(UNDERLYING, 1, _wrapper(nine), "a");
        address[] memory eight = new address[](8);
        for (uint256 i; i < 8; ++i) eight[i] = nine[i];
        f.createToken(UNDERLYING, 1, _wrapper(eight), "a");
    }

    function test_createToken_unknownVersion() public {
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, NONE, 2));
        f.createToken(NONE, 2, _none(alice), "a");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector,
            IOpenFactory.TokenKind.NONE_ZETHER, 1));
        f.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, _none(alice), "a");
    }

    function test_saltIsScopedByCreator_andCannotBeReused() public {
        vm.prank(alice);
        address a = f.createToken(NONE, 1, _none(alice), "same");
        vm.prank(bob);
        address b = f.createToken(NONE, 1, _none(bob), "same");
        assertTrue(a != b);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, a));
        f.createToken(NONE, 1, _none(alice), "same");
    }

    function test_unregisteredImplementationThatSelfDestructs_cannotReuseTheSalt() public {
        SelfDestructImpl bad = new SelfDestructImpl(address(f), UID_);
        address predicted = f.predictAddress(address(bad), alice, "x");
        vm.prank(alice);
        address t = f.createTokenUnregistered(NONE, address(bad), _none(alice), "x");
        assertEq(t, predicted);
        assertTrue(f.isToken(t));
        // the clone's code is gone at the end of its creating transaction: a test is one transaction, so apply it
        assertGt(t.code.length, 0, "still there within the creating tx");
        vm.etch(t, "");
        assertEq(t.code.length, 0);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, t));
        f.createTokenUnregistered(NONE, address(bad), _none(alice), "x");
    }

    function test_createTokenUnregistered_isCheckedAndRecordedAsVersion0() public {
        NoUnderlyingToken mine = new NoUnderlyingToken(address(f), address(0), UID_, address(0), false);
        vm.prank(alice);
        address t = f.createTokenUnregistered(NONE, address(mine), _none(alice), "u");
        (, uint64 v) = f.versionOf(t);
        assertEq(v, 0);
        assertEq(NoUnderlyingToken(t).version(), 0);
        NoUnderlyingToken other = new NoUnderlyingToken(address(f), address(0), keccak256("x"), address(0), false);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, keccak256("x")));
        f.createTokenUnregistered(NONE, address(other), _none(alice), "u2");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionKindMismatch.selector, UNDERLYING, 0));
        f.createTokenUnregistered(UNDERLYING, address(mine), _wrapper(_two()), "u3");
    }

    // ------------------------------------------------------------------ the token validates

    function test_factoryOnlyForwards_theTokenValidatesFlagsAndFields() public {
        IFactoryToken.TokenConfig memory c = _none(alice);
        c.features |= 1 << 3; // RATE_ADJUSTABLE on NONE
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, 3));
        f.createToken(NONE, 1, c, "a");
        c = _none(alice);
        c.rate.rateDelay = 7 days;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 3));
        f.createToken(NONE, 1, c, "a");
        c = _none(alice);
        c.conf.shieldScale = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        f.createToken(NONE, 1, c, "a");
        c = _wrapper(_two());
        c.initialSupply = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 1));
        f.createToken(UNDERLYING, 1, c, "a");
        c = _wrapper(_two());
        c.initialHolder = alice;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 1));
        f.createToken(UNDERLYING, 1, c, "a");
        c = _wrapper(_two());
        c.conf.auditorKey = hex"01";
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        f.createToken(UNDERLYING, 1, c, "a");
    }

    function test_onlyTheFactoryInitializes_andOnlyOnce() public {
        vm.prank(alice);
        address t = f.createToken(NONE, 1, _none(alice), "s");
        vm.expectRevert(MetaTokenBase.NotFactory.selector);
        NoUnderlyingToken(t).initialize(alice, 1, _none(alice));
        vm.prank(address(f));
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        NoUnderlyingToken(t).initialize(alice, 1, _none(alice));
        vm.prank(address(f));
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        noneImpl.initialize(alice, 1, _none(alice)); // the implementation locked itself
    }

    function test_kindIsAConstantOfTheImplementation() public view {
        assertEq(noneImpl.kind(), uint8(NONE));
        assertEq(underlyingImpl.kind(), uint8(UNDERLYING));
    }

    function test_sizes() public view {
        // owner: size later (Glamsterdam); budget 20,480 (P2a ruling); +8.7 KB for the UA ledger (UA-4); +1.2 / +2.5 KB
        // for the UA-5a receivers; +2.3 / +3.4 KB for UA-5b (UATradeOrder, uaWrap); +1.6 KB for the guard on every entry
        // (review W-Q, CTR-MTX-18) (size-baseline.json holds the exact ratchet)
        assertLe(address(noneImpl).code.length, 38_912);
        assertLe(address(f).code.length, 24_576);
        // Transitional (P1d D2): over EIP-170 until the size work
        assertLe(address(underlyingImpl).code.length, 49_152);
    }
}
