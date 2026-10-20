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
import {plainEnv, Catalogue} from "../helpers/Catalogue.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";

/// Answers nothing the factory asks.
contract Muted {}

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
    function features() external pure returns (uint256) { return 0; }
    function lockedFeatures() external pure returns (uint256) { return 0; }
    function owner() external pure returns (address) { return address(0); }
    function underlyings() external pure returns (address[] memory) {}

    function initialize(address, uint64, bytes calldata) external {
        selfdestruct(payable(address(0)));
    }
}

/// A release answering `kind()` 0 and `factory()` (its deployer), on another chain: `ChainUidMismatch`.
contract OtherChainImpl {
    address immutable F = msg.sender;

    function kind() external pure returns (uint8) { return 0; }
    function factory() external view returns (address) { return F; }
    function chainUid() external pure returns (bytes32) { return keccak256("other chain"); }
}

/// A constructor that reverts with a known error (bubbled by `deployImplementation`).
contract BadConstructor {
    constructor() { revert IOpenFactory.EnvInvalid(); }
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
        f = new OpenFactory(registrar, UID_, 0);
        noneImpl = NoUnderlyingToken(Catalogue.plain(f, NONE, 1, type(NoUnderlyingToken).creationCode, address(0),
            address(0), false));
        underlyingImpl = UnderlyingToken(Catalogue.plain(f, UNDERLYING, 1, type(UnderlyingToken).creationCode,
            address(0), address(0), false));
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
        new OpenFactory(registrar, bytes32(0), 0);
        assertEq(f.chainUid(), UID_);
        assertEq(f.registrar(), registrar);
    }

    /// Plan 5g-Z2: envs are published per kind, versioned, never changed; the factory's own and well-formed.
    function test_publishEnv() public {
        IFactoryToken.Env memory e = plainEnv(address(f), address(0), UID_, address(0), false);
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.publishEnv(NONE, 2, e);
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.EnvAlreadyPublished.selector, 0, 1));
        f.publishEnv(NONE, 1, e);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.EnvUnknown.selector, 0, 0));
        f.publishEnv(NONE, 0, e);
        IFactoryToken.Env memory bad = plainEnv(address(0xFAC), address(0), UID_, address(0), false);
        vm.expectRevert(IOpenFactory.EnvInvalid.selector);
        f.publishEnv(NONE, 2, bad);
        bad = plainEnv(address(f), address(0), keccak256("other chain"), address(0), false);
        vm.expectRevert(IOpenFactory.EnvInvalid.selector);
        f.publishEnv(NONE, 2, bad);
        bad = plainEnv(address(f), address(0), UID_, address(0), false);
        bad.libs = new address[](1);
        vm.expectRevert(IOpenFactory.EnvInvalid.selector);
        f.publishEnv(NONE, 2, bad);
        // a pin that pins nothing (review 5g-Z2 P2-1): 0 (no account) or keccak256("") (no code)
        (bad.libs[0], bad.libCodeHashes) = (address(AdminLib), new bytes32[](1));
        vm.expectRevert(IOpenFactory.EnvInvalid.selector);
        f.publishEnv(NONE, 2, bad);
        bad.libCodeHashes[0] = keccak256("");
        vm.expectRevert(IOpenFactory.EnvInvalid.selector);
        f.publishEnv(NONE, 2, bad);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindReserved.selector, IOpenFactory.TokenKind.NONE_ZETHER_PQZ));
        f.publishEnv(IOpenFactory.TokenKind.NONE_ZETHER_PQZ, 1, e);
        e.registry = address(0x1234);
        vm.expectEmit(true, true, false, true, address(f));
        emit IOpenFactory.EnvPublished(0, 5, keccak256(abi.encode(e)));
        f.publishEnv(NONE, 5, e); // gaps allowed; the latest is the highest
        vm.stopPrank();
        assertEq(f.latestEnvVersion(NONE), 5);
        assertEq(f.envOf(NONE, 5).registry, address(0x1234));
        assertEq(f.latestEnvVersion(IOpenFactory.TokenKind.NONE_PQZ), 0);
        // a release names a published env of its kind (owner 2026-10-20: explicit, never implied by the latest)
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.EnvUnknown.selector, 4, 1));
        f.deployImplementation(IOpenFactory.TokenKind.NONE_PQZ, 1, 1, type(NoUnderlyingToken).creationCode, "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.EnvUnknown.selector, 0, 3)); // a gap
        f.deployImplementation(NONE, 2, 3, type(NoUnderlyingToken).creationCode, "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.EnvUnknown.selector, 0, 0));
        f.deployImplementation(NONE, 2, 0, type(NoUnderlyingToken).creationCode, "");
        // an older env stays usable for a new release: the registrar's choice, recorded in the release
        address v2 = f.deployImplementation(NONE, 2, 1, type(NoUnderlyingToken).creationCode, "");
        vm.stopPrank();
        assertEq(f.releaseOf(NONE, 2).envVersion, 1);
        assertEq(f.releaseOf(NONE, 2).envHash, keccak256(abi.encode(f.envOf(NONE, 1))));
        assertEq(NoUnderlyingToken(v2).registry(), address(0), "env 1's registry, not env 5's");
    }

    /// The linked libraries of the env are checked by code hash at every release deployment (plan 5g-Z2).
    function test_deployImplementation_checksLibraryCodeHashes() public {
        IFactoryToken.Env memory e = plainEnv(address(f), address(0), UID_, address(0), false);
        e.libs = new address[](2);
        e.libCodeHashes = new bytes32[](2);
        (e.libs[0], e.libCodeHashes[0]) = (address(AdminLib), address(AdminLib).codehash);
        (e.libs[1], e.libCodeHashes[1]) = (address(usdc), keccak256("not the code"));
        uint16 ev = Catalogue.env(f, NONE, e);
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.LibraryCodeHashMismatch.selector, address(usdc),
            keccak256("not the code"), address(usdc).codehash));
        f.deployImplementation(NONE, 2, ev, type(NoUnderlyingToken).creationCode, "");
        e.libCodeHashes[1] = address(usdc).codehash;
        address v2 = Catalogue.release(f, NONE, 2, e, type(NoUnderlyingToken).creationCode);
        assertEq(f.releaseOf(NONE, 2).envVersion, 3);
        assertEq(f.releaseOf(NONE, 2).implementation, v2);
    }

    /// The catalogue is code the factory deploys itself (plan 5g-Z2): registrar only, append-only, version 0 and the
    /// reserved kinds refused, then the `kind()` / `factory()` / `chainUid()` checks on what it deployed; a constructor's
    /// revert is bubbled, an empty failure is `DeployFailed`; the release hashes in the event; the same init code again as
    /// a later version on a newer env.
    function test_deployImplementation_checksKindFactoryAndChainUid() public {
        bytes memory code = type(NoUnderlyingToken).creationCode;
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionKindMismatch.selector, UNDERLYING, 0));
        f.deployImplementation(UNDERLYING, 2, 1, code, "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionKindMismatch.selector, NONE, type(uint256).max));
        f.deployImplementation(NONE, 2, 1, type(Muted).creationCode, ""); // no kind()
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationFactoryMismatch.selector,
            Catalogue.predict(f, NONE, 2, type(KindOnly).creationCode)));
        f.deployImplementation(NONE, 2, 1, type(KindOnly).creationCode, "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, keccak256("other chain")));
        f.deployImplementation(NONE, 2, 1, type(OtherChainImpl).creationCode, "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationNotAContract.selector,
            Catalogue.predict(f, NONE, 2, "")));
        f.deployImplementation(NONE, 2, 1, "", ""); // an empty init code makes an account without code
        vm.expectRevert(IOpenFactory.DeployFailed.selector);
        f.deployImplementation(NONE, 2, 1, hex"fe", ""); // INVALID: no revert data
        vm.expectRevert(IOpenFactory.EnvInvalid.selector); // a constructor's error is bubbled
        f.deployImplementation(NONE, 2, 1, type(BadConstructor).creationCode, "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindReserved.selector, IOpenFactory.TokenKind.NONE_ZETHER_PQZ));
        f.deployImplementation(IOpenFactory.TokenKind.NONE_ZETHER_PQZ, 1, 1, code, "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, NONE, 0));
        f.deployImplementation(NONE, 0, 1, code, "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionAlreadyRegistered.selector, NONE, 1, address(noneImpl)));
        f.deployImplementation(NONE, 1, 1, code, "");
        vm.stopPrank();
        vm.prank(alice);
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.deployImplementation(NONE, 3, 1, code, "");
        assertEq(f.latestVersion(NONE), 1);
        assertEq(f.implementationOf(UNDERLYING, 1), address(underlyingImpl));
        // the same init code on a newer env as version 2 (no recompile): a new address, the hashes in the event
        IFactoryToken.Env memory e2 = plainEnv(address(f), address(0), UID_, address(0x1234), false);
        uint16 ev = Catalogue.env(f, NONE, e2);
        address predicted = Catalogue.predict(f, NONE, 2, code);
        vm.recordLogs();
        vm.prank(registrar);
        address v2 = f.deployImplementation(NONE, 2, ev, code, "");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        Vm.Log memory l = logs[logs.length - 1];
        assertEq(l.topics[0], IOpenFactory.ImplementationDeployed.selector);
        (uint16 envVersion, bytes32 envHash, bytes32 initcodeHash, bytes32 codeHash, uint64 usableFrom) =
            abi.decode(l.data, (uint16, bytes32, bytes32, bytes32, uint64));
        assertEq(v2, predicted);
        assertEq(envVersion, ev);
        assertEq(envHash, keccak256(abi.encode(e2)));
        assertEq(initcodeHash, keccak256(code), "the registrar's init code, without the appended arguments");
        assertEq(codeHash, v2.codehash);
        assertEq(usableFrom, block.timestamp);
        assertEq(NoUnderlyingToken(v2).registry(), address(0x1234), "the env's registry, an immutable");
        assertEq(address(noneImpl).codehash == v2.codehash, false, "other immutables, other code");
        assertEq(f.latestVersion(NONE), 2);
    }

    /// Plan 5g-Z2: a release is usable `noticePeriod` seconds after its deployment (7622: minutes, 22776: days).
    function test_noticePeriod() public {
        // the period is immutable, capped at 30 days (review 5g-Z2 P2-4: near 2^64 `usableFrom` would overflow)
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.NoticePeriodTooLong.selector, 30 days + 1));
        new OpenFactory(registrar, UID_, 30 days + 1);
        assertEq(new OpenFactory(registrar, UID_, 30 days).noticePeriod(), f.MAX_NOTICE_PERIOD());
        OpenFactory g = new OpenFactory(registrar, UID_, 10 minutes);
        assertEq(g.noticePeriod(), 10 minutes);
        Catalogue.plain(g, NONE, 1, type(NoUnderlyingToken).creationCode, address(0), address(0), false);
        uint64 from = uint64(block.timestamp + 10 minutes);
        assertEq(g.releaseOf(NONE, 1).usableFrom, from);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionNotYetUsable.selector, NONE, 1, from));
        g.createToken(NONE, 1, abi.encode(_none(alice)), "early");
        vm.warp(from);
        assertTrue(g.isRegisteredToken(g.createToken(NONE, 1, abi.encode(_none(alice)), "on time")));
    }

    /// The factory's generic gate (plan 5g-Z2): the plain kinds start on, the confidential ones off; registrar only.
    function test_kindEnabled() public {
        assertTrue(f.kindEnabled(NONE));
        assertTrue(f.kindEnabled(UNDERLYING));
        for (uint8 k = 2; k <= 5; ++k) assertFalse(f.kindEnabled(IOpenFactory.TokenKind(k)));
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.setKindEnabled(NONE, false);
        vm.prank(registrar);
        vm.expectEmit(true, false, false, true, address(f));
        emit IOpenFactory.KindEnabled(NONE, false);
        f.setKindEnabled(NONE, false);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindDisabled.selector, NONE));
        f.createToken(NONE, 1, abi.encode(_none(alice)), "off");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindDisabled.selector, NONE));
        f.createTokenUnregistered(NONE, address(noneImpl), abi.encode(_none(alice)), "off");
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindReserved.selector, IOpenFactory.TokenKind.NONE_ZETHER_PQZ));
        f.setKindEnabled(IOpenFactory.TokenKind.NONE_ZETHER_PQZ, true);
    }

    /// `deprecate` is immediate and refuses new tokens of that version (owner 2026-10-20); tokens already made keep
    /// working and the other versions stay creatable.
    function test_deprecate_refusesNewTokensOfThatVersion() public {
        vm.prank(alice);
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.deprecate(NONE, 1, "x");
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, NONE, 9));
        f.deprecate(NONE, 9, "x");
        vm.prank(alice);
        address before = f.createToken(NONE, 1, abi.encode(_none(alice)), "before");
        vm.prank(registrar);
        f.deprecate(NONE, 1, "bug");
        assertTrue(f.isDeprecated(NONE, 1));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionDeprecated.selector, NONE, 1));
        f.createToken(NONE, 1, abi.encode(_none(alice)), "after");
        assertTrue(f.isRegisteredToken(before), "an existing token is untouched");
        assertEq(NoUnderlyingToken(before).balanceOf(alice), 1000);
        vm.prank(alice);
        f.createToken(UNDERLYING, 1, abi.encode(_wrapper(_two())), "other version");
    }

    // ------------------------------------------------------------------ create

    function test_createToken_none_emitsOneEventWithProvenance() public {
        address predicted = f.predictAddress(address(noneImpl), alice, "s");
        vm.recordLogs();
        vm.prank(alice);
        address t = f.createToken(NONE, 1, abi.encode(_none(alice)), "s");
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
        address t = f.createToken(UNDERLYING, 1, abi.encode(_wrapper(us)), "w");
        assertEq(UnderlyingToken(t).underlyings().length, 3);
        assertEq(f.getWrapper(alice, address(usdc)), t);
        assertEq(f.getWrapper(alice, address(0)), t);
        assertEq(f.getWrapperCount(alice, address(usdt)), 1);
        assertEq(f.getWrapperAt(alice, address(usdt), 0), t);
        assertEq(f.deployCountFor(address(0)), 1);
        assertEq(f.deployedFor(address(usdc), 0), t);
        assertEq(f.getWrapper(bob, address(usdc)), address(0));
    }

    /// The leg count is the implementation's (plan 5g-Z2): `NONE` refuses legs as another kind's field, `UNDERLYING` takes
    /// 1–8.
    function test_createToken_legCountByKind() public {
        IFactoryToken.TokenConfig memory c = _none(alice);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usdc), 1, 1);
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 2));
        f.createToken(NONE, 1, abi.encode(c), "a");
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 0));
        f.createToken(UNDERLYING, 1, abi.encode(_wrapper(new address[](0))), "a");
        address[] memory nine = new address[](9);
        for (uint256 i; i < 9; ++i) nine[i] = address(new MockERC20("X", "X", 6));
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 9));
        f.createToken(UNDERLYING, 1, abi.encode(_wrapper(nine)), "a");
        address[] memory eight = new address[](8);
        for (uint256 i; i < 8; ++i) eight[i] = nine[i];
        f.createToken(UNDERLYING, 1, abi.encode(_wrapper(eight)), "a");
    }

    function test_createToken_unknownVersion() public {
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, NONE, 2));
        f.createToken(NONE, 2, abi.encode(_none(alice)), "a");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector,
            IOpenFactory.TokenKind.NONE_ZETHER, 1));
        f.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(_none(alice)), "a");
    }

    function test_saltIsScopedByCreator_andCannotBeReused() public {
        vm.prank(alice);
        address a = f.createToken(NONE, 1, abi.encode(_none(alice)), "same");
        vm.prank(bob);
        address b = f.createToken(NONE, 1, abi.encode(_none(bob)), "same");
        assertTrue(a != b);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, a));
        f.createToken(NONE, 1, abi.encode(_none(alice)), "same");
    }

    function test_unregisteredImplementationThatSelfDestructs_cannotReuseTheSalt() public {
        SelfDestructImpl bad = new SelfDestructImpl(address(f), UID_);
        address predicted = f.predictAddress(address(bad), alice, "x");
        vm.prank(alice);
        address t = f.createTokenUnregistered(NONE, address(bad), abi.encode(_none(alice)), "x");
        assertEq(t, predicted);
        assertTrue(f.isToken(t));
        // the clone's code is gone at the end of its creating transaction: a test is one transaction, so apply it
        assertGt(t.code.length, 0, "still there within the creating tx");
        vm.etch(t, "");
        assertEq(t.code.length, 0);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, t));
        f.createTokenUnregistered(NONE, address(bad), abi.encode(_none(alice)), "x");
    }

    /// Plain kinds only (owner 2026-10-19): recorded as version 0 and not a registered token, so clients and the gateway
    /// treat it as unvetted; every confidential kind (2–7) is refused before any check.
    function test_createTokenUnregistered_isCheckedAndRecordedAsVersion0() public {
        NoUnderlyingToken mine = new NoUnderlyingToken(1, plainEnv(address(f), address(0), UID_, address(0), false), "");
        vm.prank(alice);
        address t = f.createTokenUnregistered(NONE, address(mine), abi.encode(_none(alice)), "u");
        (, uint64 v) = f.versionOf(t);
        assertEq(v, 0);
        assertEq(NoUnderlyingToken(t).version(), 0);
        assertTrue(f.isToken(t));
        assertFalse(f.isRegisteredToken(t), "version 0: unvetted");
        assertTrue(f.isRegisteredToken(f.createToken(NONE, 1, abi.encode(_none(alice)), "r")));
        assertFalse(f.isRegisteredToken(address(mine)));
        for (uint8 k = 2; k <= 7; ++k) {
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.UnregisteredConfidentialKind.selector, k));
            f.createTokenUnregistered(IOpenFactory.TokenKind(k), address(mine), abi.encode(_none(alice)), "c");
        }
        NoUnderlyingToken other = new NoUnderlyingToken(1, plainEnv(address(f), address(0), keccak256("x"), address(0), false), "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, keccak256("x")));
        f.createTokenUnregistered(NONE, address(other), abi.encode(_none(alice)), "u2");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionKindMismatch.selector, UNDERLYING, 0));
        f.createTokenUnregistered(UNDERLYING, address(mine), abi.encode(_wrapper(_two())), "u3");
    }

    // ------------------------------------------------------------------ the token validates

    function test_factoryOnlyForwards_theTokenValidatesFlagsAndFields() public {
        IFactoryToken.TokenConfig memory c = _none(alice);
        c.features |= 1 << 3; // RATE_ADJUSTABLE on NONE
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, 3));
        f.createToken(NONE, 1, abi.encode(c), "a");
        c = _none(alice);
        c.rate.rateDelay = 7 days;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 3));
        f.createToken(NONE, 1, abi.encode(c), "a");
        c = _none(alice);
        c.conf.shieldScale = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        f.createToken(NONE, 1, abi.encode(c), "a");
        c = _wrapper(_two());
        c.initialSupply = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 1));
        f.createToken(UNDERLYING, 1, abi.encode(c), "a");
        c = _wrapper(_two());
        c.initialHolder = alice;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 1));
        f.createToken(UNDERLYING, 1, abi.encode(c), "a");
        c = _wrapper(_two());
        c.conf.auditorKey = hex"01";
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        f.createToken(UNDERLYING, 1, abi.encode(c), "a");
    }

    function test_onlyTheFactoryInitializes_andOnlyOnce() public {
        vm.prank(alice);
        address t = f.createToken(NONE, 1, abi.encode(_none(alice)), "s");
        vm.expectRevert(MetaTokenBase.NotFactory.selector);
        NoUnderlyingToken(t).initialize(alice, 1, abi.encode(_none(alice)));
        vm.prank(address(f));
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        NoUnderlyingToken(t).initialize(alice, 1, abi.encode(_none(alice)));
        vm.prank(address(f));
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        noneImpl.initialize(alice, 1, abi.encode(_none(alice))); // the implementation locked itself
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
