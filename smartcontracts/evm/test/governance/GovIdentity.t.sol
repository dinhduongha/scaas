// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs, dexArgs} from "../../script/KindModules.sol";

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBase} from "../../src/governance/GovernanceBase.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// A stand-in for the chain's `GovernanceRouter` (plan task T11 builds the real one): it authenticates nobody, it only
/// holds the subject of the call it makes. `subject` is a plain slot here, so a test can also leave it set outside a call.
contract MockGovRouter {
    bytes32 public subject;

    function set(bytes32 s) external {
        subject = s;
    }

    /// The router's flow without the signature: write the subject, call the target, clear the subject.
    function run(bytes32 s, address target, bytes calldata data) external returns (bytes memory r) {
        subject = s;
        bool ok;
        (ok, r) = target.call(data);
        subject = 0;
        if (!ok) assembly ("memory-safe") { revert(add(r, 32), mload(r)) }
    }
}

/// @notice Identity by UA (owner 2026-11-04; CTR-GOV-01 Change; spec `2026-11-04-governance-ua-identity.md` §1, §2, §4; plan
///         T10b). Every governance identity is a `bytes32`; `_govSubject()` is the native id of a direct caller, or, from the
///         release's `GOV_ROUTER`, the UA the router names for that call. `NORMAL`, `WRAPPED` (the test plays the factory) and
///         the DEX (a clone of its implementation, the test as its factory).
contract GovIdentityTest is Test {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint8 constant MINT = GovernanceBits.MINTABLE;
    uint8 constant RATE = GovernanceBits.RATE_ADJUSTABLE;
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    /// A derived UA (a PQ key, an `msig`): its top 96 bits are not 0, so no address is its native id.
    bytes32 constant ISSUER = keccak256("a derived UA: an issuer's PQ msig");
    bytes32 constant MINTER = keccak256("a derived UA: a minter");

    MockGovRouter internal router = new MockGovRouter();
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);
    address internal normalImpl;
    address internal wrappedImpl;

    /// The test plays the factory: it registered no token, so every leg is outside to the leg check.
    function isRegisteredToken(address) external pure returns (bool) { return false; }

    /// The clones' env (chain-neutral spec §2.1): this chain, no registry, the router.
    function _cenv() internal view returns (IFactoryToken.ChainEnv memory) {
        return EnvKit.env(UID, address(0), address(0), false, address(router));
    }

    function _normal(bytes32 owner_, bytes32 minter) internal returns (NormalToken t) {
        if (normalImpl == address(0)) normalImpl = address(new NormalToken(address(this), kindArgs(0, address(this), "")));
        t = NormalToken(EnvKit.clone(normalImpl, _cenv()));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.admin) = ("I", "I", 6, 1 | (uint256(1) << MINT), owner_);
        c.roles.minter = minter;
        t.initialize(nid(address(this)), 1, abi.encode(c));
    }

    function _wrappedCfg(bytes32 owner_) internal view returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.features, c.admin) = ("W", "W", 6, 1 | (uint256(1) << RATE), owner_);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
    }

    function _wrapped(IFactoryToken.TokenConfig memory c) internal returns (WrappedToken w) {
        if (wrappedImpl == address(0)) wrappedImpl = address(new WrappedToken(address(this), kindArgs(1, address(this), "")));
        w = WrappedToken(payable(EnvKit.clone(wrappedImpl, _cenv())));
        w.initialize(nid(address(this)), 1, abi.encode(c));
    }

    function _dex(bytes32 owner_) internal returns (SCaaSDex d) {
        d = SCaaSDex(EnvKit.clone(address(new SCaaSDex(address(this), dexArgs(address(this)))), _cenv()));
        d.initialize(nid(address(this)), 1, abi.encode(ISCaaSDex.DexConfig(owner_, 0, address(0xAA), false, 0, address(0))));
    }

    function _open() internal pure returns (IGovernance.GrantTerms memory g) {
        g.max = type(uint128).max;
    }

    /// The chain's router is every clone's `GOV_ROUTER`, from the env in its code (chain-neutral spec §2.1: the factory's
    /// one-time value); the release carries none.
    function test_govRouterIsTheReleases() public {
        assertEq(GovernanceBase(address(_normal(ISSUER, 0))).GOV_ROUTER(), address(router));
        assertEq(GovernanceBase(address(_dex(ISSUER))).GOV_ROUTER(), address(router));
        assertEq(GovernanceBase(normalImpl).GOV_ROUTER(), address(0), "the release carries no env");
        NormalToken none = NormalToken(EnvKit.clone(normalImpl, EnvKit.env(UID, address(0), address(0), false)));
        assertEq(none.GOV_ROUTER(), address(0), "no router on this chain");
    }

    /// A derived UA owns a token and acts only through the router: grant, revoke, set a grant, transfer ownership, accept.
    function test_derivedUAOwnsAndGrantsThroughTheRouter() public {
        NormalToken t = _normal(ISSUER, 0);
        assertEq(t.admin(), ISSUER);
        vm.expectEmit(address(t));
        emit IGovernance.RoleGranted(MINT, MINTER, ISSUER);
        router.run(ISSUER, address(t), abi.encodeCall(IGovernance.grantRole, (MINT, MINTER)));
        assertTrue(t.hasRole(MINT, MINTER));
        router.run(ISSUER, address(t), abi.encodeCall(IGovernance.setGrant, (MINT, MINTER, _limited(5))));
        assertEq(t.grantOf(MINT, MINTER).total, 5);
        assertEq(t.grantOf(MINT, MINTER).grantor, bytes32(0), "the owner's grant is a root");
        router.run(ISSUER, address(t), abi.encodeCall(IGovernance.revokeRole, (MINT, MINTER)));
        assertFalse(t.hasRole(MINT, MINTER));
        // ownership moves to a native account, then back to another derived UA
        bytes32 alice = bytes32(uint256(uint160(ALICE)));
        router.run(ISSUER, address(t), abi.encodeCall(IGovernance.transferAdmin, (alice)));
        assertEq(t.pendingAdmin(), alice);
        vm.prank(ALICE);
        t.acceptAdmin();
        assertEq(t.admin(), alice);
        vm.prank(ALICE);
        t.transferAdmin(MINTER);
        router.run(MINTER, address(t), abi.encodeCall(IGovernance.acceptAdmin, ()));
        assertEq(t.admin(), MINTER);
        // nobody reaches the derived owner's power directly: no address is its id
        vm.prank(address(uint160(uint256(MINTER))));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotAdmin.selector, bytes32(uint256(uint160(uint256(MINTER))))));
        t.grantRole(MINT, ISSUER);
    }

    function _limited(uint128 total) internal pure returns (IGovernance.GrantTerms memory g) {
        g = _open();
        g.total = total;
    }

    /// A power's own entry takes the same subject: a derived minter mints through the router, and only there.
    function test_derivedUAMintsThroughTheRouter() public {
        NormalToken t = _normal(ISSUER, MINTER);
        router.run(MINTER, address(t), abi.encodeCall(NormalToken.mint, (BOB, 7)));
        assertEq(t.balanceOf(BOB), 7);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, ISSUER));
        router.run(ISSUER, address(t), abi.encodeCall(NormalToken.mint, (BOB, 1)));
    }

    /// The DEX's owner is a derived UA: it holds both bits from creation and uses `LISTING` through the router.
    function test_dexOwnedByADerivedUA() public {
        SCaaSDex d = _dex(ISSUER);
        assertEq(d.admin(), ISSUER);
        assertTrue(d.hasRole(GovernanceBits.LISTING, ISSUER) && d.hasRole(GovernanceBits.FEE_ROUTING, ISSUER));
        router.run(ISSUER, address(d), abi.encodeCall(SCaaSDex.setListedOnly, (true)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, GovernanceBits.LISTING, MINTER));
        router.run(MINTER, address(d), abi.encodeCall(SCaaSDex.setListedOnly, (false)));
    }

    /// A direct caller's id is its address padded to 32 bytes, from `msg.sender` (not `tx.origin`): `vm.prank` leaves the
    /// origin at the test's default sender.
    function test_nativeCallerIsItsPaddedAddress() public {
        NormalToken t = _normal(bytes32(uint256(uint160(ALICE))), 0);
        vm.prank(ALICE);
        t.grantRole(MINT, bytes32(uint256(uint160(BOB))));
        assertTrue(t.hasRole(MINT, bytes32(uint256(uint160(BOB)))));
        vm.prank(BOB);
        t.mint(BOB, 1);
        assertEq(t.balanceOf(BOB), 1);
        // the same low 160 bits under other top bits is another identity
        bytes32 shadow = bytes32(uint256(uint160(ALICE)) | (uint256(1) << 200));
        vm.prank(ALICE);
        t.transferAdmin(shadow);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotPendingAdmin.selector, bytes32(uint256(uint160(ALICE)))));
        t.acceptAdmin();
        // the transaction's origin is nobody's subject
        vm.prank(BOB, ALICE);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotAdmin.selector, bytes32(uint256(uint160(BOB)))));
        t.grantRole(MINT, bytes32(uint256(uint160(BOB))));
    }

    /// The router's subject is read only on a call from the router: another caller with a subject set in the router is
    /// itself, on every entry and on a power.
    function test_routerSubjectReadOnlyFromTheRouter() public {
        NormalToken t = _normal(ISSUER, MINTER);
        router.set(ISSUER); // left set, as a router outside a live call never would be
        bytes32 alice = bytes32(uint256(uint160(ALICE)));
        vm.startPrank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotAdmin.selector, alice));
        t.grantRole(MINT, alice);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotAdmin.selector, alice));
        t.transferAdmin(alice);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotAdmin.selector, alice));
        t.disableFeature(MINT);
        router.set(MINTER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, alice));
        t.mint(ALICE, 1);
        vm.stopPrank();
        assertEq(t.admin(), ISSUER);
    }

    /// The router outside a live call names 0: every entry refuses it, as the owner, as a pending owner, as a holder.
    function test_routerSubjectZeroRefused() public {
        NormalToken t = _normal(ISSUER, MINTER);
        router.set(0);
        vm.startPrank(address(router));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotAdmin.selector, bytes32(0)));
        t.grantRole(MINT, ISSUER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotAdmin.selector, bytes32(0)));
        t.revokeRole(MINT, MINTER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotAdmin.selector, bytes32(0)));
        t.setGrant(MINT, ISSUER, _limited(1));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotAdmin.selector, bytes32(0)));
        t.transferAdmin(ISSUER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotPendingAdmin.selector, bytes32(0)));
        t.acceptAdmin();
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, bytes32(0)));
        t.renounceRole(MINT);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, bytes32(0)));
        t.mint(BOB, 1);
        vm.stopPrank();
    }

    /// A contract-only bit (`RATE_ADJUSTABLE`) is held only by a native id with code: a derived UA is refused even when its
    /// low 160 bits are a contract's address, at `init` and at `grantRole`.
    function test_contractOnlyBitToADerivedUARefused() public {
        bytes32 derived = bytes32(uint256(uint160(address(this))) | (uint256(0xd1) << 160));
        IFactoryToken.TokenConfig memory c = _wrappedCfg(ISSUER);
        c.roles.rateAdmin = derived;
        if (wrappedImpl == address(0)) wrappedImpl = address(new WrappedToken(address(this), kindArgs(1, address(this), "")));
        WrappedToken w = WrappedToken(payable(EnvKit.clone(wrappedImpl, _cenv())));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, RATE, derived));
        w.initialize(nid(address(this)), 1, abi.encode(c));
        w = _wrapped(_wrappedCfg(ISSUER));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, RATE, derived));
        router.run(ISSUER, address(w), abi.encodeCall(IGovernance.grantRole, (RATE, derived)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, RATE, ISSUER));
        router.run(ISSUER, address(w), abi.encodeCall(IGovernance.grantRole, (RATE, ISSUER)));
        bytes32 self = bytes32(uint256(uint160(address(this))));
        router.run(ISSUER, address(w), abi.encodeCall(IGovernance.grantRole, (RATE, self)));
        assertTrue(w.hasRole(RATE, self), "a native id with code holds it");
    }

    /// `UA_POOL`, `SHIELD_POOL` and 0 are never owner and never holder, as native ids.
    function test_poolsAndZeroRefusedAsOwnerAndHolder() public {
        bytes32[2] memory pools = [MetaTxLib.pad(MetaTxLib.UA_POOL), MetaTxLib.pad(MetaTxLib.SHIELD_POOL)];
        for (uint256 i; i < 2; ++i) {
            if (normalImpl == address(0)) normalImpl = address(new NormalToken(address(this), kindArgs(0, address(this), "")));
            NormalToken n = NormalToken(EnvKit.clone(normalImpl, _cenv()));
            IFactoryToken.TokenConfig memory c;
            (c.name, c.symbol, c.decimals, c.features, c.admin) = ("I", "I", 6, 1 | (uint256(1) << MINT), pools[i]);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminAccountPool.selector, pools[i]));
            n.initialize(nid(address(this)), 1, abi.encode(c));
            c.admin = ISSUER;
            c.roles.minter = pools[i];
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountPool.selector, MINT, pools[i]));
            n.initialize(nid(address(this)), 1, abi.encode(c));
            NormalToken t = _normal(ISSUER, 0);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminAccountPool.selector, pools[i]));
            router.run(ISSUER, address(t), abi.encodeCall(IGovernance.transferAdmin, (pools[i])));
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountPool.selector, MINT, pools[i]));
            router.run(ISSUER, address(t), abi.encodeCall(IGovernance.grantRole, (MINT, pools[i])));
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountPool.selector, MINT, pools[i]));
            router.run(ISSUER, address(t), abi.encodeCall(IGovernance.setGrant, (MINT, pools[i], _limited(1))));
        }
        NormalToken z = _normal(ISSUER, 0);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountZero.selector, MINT));
        router.run(ISSUER, address(z), abi.encodeCall(IGovernance.grantRole, (MINT, bytes32(0))));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountZero.selector, MINT));
        router.run(ISSUER, address(z), abi.encodeCall(IGovernance.setGrant, (MINT, bytes32(0), _limited(1))));
    }
}
