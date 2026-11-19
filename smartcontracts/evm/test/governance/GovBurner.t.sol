// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {UACall} from "../ua/UACall.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// Round 3zb (spec 2026-11-13-burner-wrap-caps.md §1, §2, §6; CTR-GOV-29): bit 30 `BURNER` on a `NORMAL` token (kind 0, the
/// body every Normal kind shares, `NormalTokenCore._burnBody`). Only a holder burns, only its own balance (`_subject()`),
/// within its grant, on `burn`, `mtxBurn` (native and derived UA) and the generic `mtxExecute`; exclusive with `BURNABLE` at
/// creation; never enabled later; the admin's `disableFeature(30)` stops every burn. The other Normal kinds:
/// `GovBurnerKinds.t.sol`. UNAUDITED.
contract GovBurnerTest is UALedgerBase {
    uint8 internal constant BURNER = GovernanceBits.BURNER;
    uint8 internal constant BURNABLE = GovernanceBits.BURNABLE;
    bytes32 internal constant UA_BURN = keccak256(
        "UABurn(bytes32 from,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

    NormalToken internal bt; // BURNER, admin = this, seat = alice
    uint256 internal salt;

    function setUp() public override {
        super.setUp();
        bt = _make(
            _cfg((1 << GovernanceBits.PAYABLE) | (1 << GovernanceBits.MINTABLE) | (uint256(1) << BURNER), nid(alice))
        );
        _mintTo(bt, alice, 1_000_000);
        _mintTo(bt, bob, 1_000_000);
        _mintUA(bt, uaP, 500_000);
        _mintUA(bt, uaB, 500_000);
    }

    // ------------------------------------------------------------------ fixtures

    function _cfg(uint256 features, bytes32 burner) internal view returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.features, c.admin) = ("Burn", "BRN", 6, features, nid(address(this)));
        c.roles.minter = nid(address(this));
        c.roles.burner = burner;
        c;
    }

    function _clone() internal returns (NormalToken) {
        return NormalToken(
            EnvKit.clone(
                address(new NormalToken(address(this), kindArgs(0, address(this), ""))),
                EnvKit.env(chainUidA, REG_L, address(0), false)
            )
        );
    }

    function _make(IFactoryToken.TokenConfig memory c) internal returns (NormalToken t) {
        t = _clone();
        t.initialize(nid(address(this)), 1, abi.encode(c));
    }

    function _makeRev(IFactoryToken.TokenConfig memory c, bytes memory err) internal {
        NormalToken t = _clone();
        vm.expectRevert(err);
        t.initialize(nid(address(this)), 1, abi.encode(c));
    }

    function _uid(NormalToken t) internal view returns (bytes32) {
        return EnvKit.codeUidOf(address(t));
    }

    function _mintTo(NormalToken t, address to, uint256 a) internal {
        t.mint(to, a, _uid(t));
    }

    function _mintUA(NormalToken t, bytes32 to, uint256 a) internal {
        t.mintToUA(to, a, _uid(t));
    }

    function _missing(bytes32 who) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IGovernance.MissingRole.selector, BURNER, who);
    }

    function _env(NormalToken t, bytes32 from) internal view returns (MetaTxLib.UAEnvelope memory e) {
        e = MetaTxLib.UAEnvelope(from, 1, t.mtxNonce(from, 1), block.timestamp + 300, 0, address(0), 0, address(0));
    }

    /// `mtxBurn(amount)` signed by `from` (native: its own key; derived: through the registry), relayed by `RELAYER`.
    function _mtxBurnCall(NormalToken t, bytes32 from, uint256 amount) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _env(t, from);
        bytes32 sh = keccak256(
            abi.encode(UA_BURN, e.from, amount, e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))
        );
        IUARegistry.UASig memory s = UACall.auth(from, _authFor(from, MtxDigest.typed(address(t), sh)));
        return abi.encodeCall(NormalToken.mtxBurn, (e, amount, s));
    }

    /// The generic `mtxExecute` of `burn(amount)` signed by `from`.
    function _genericCall(NormalToken t, bytes32 from, uint256 amount) internal view returns (bytes memory) {
        MetaTxLib.UAMetaTransaction memory m = _m(address(t), from, abi.encodeCall(NormalToken.burn, (amount)));
        return abi.encodeCall(NormalToken.mtxExecute, (m, UACall.auth(from, _authM(address(t), m))));
    }

    function _relay(NormalToken t, bytes memory cd) internal returns (bool ok, bytes memory ret) {
        vm.prank(RELAYER);
        (ok, ret) = address(t).call(cd);
    }

    function _relayOk(NormalToken t, bytes memory cd) internal {
        (bool ok, bytes memory ret) = _relay(t, cd);
        if (!ok) {
            assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
        }
    }

    function _relayRev(NormalToken t, bytes memory cd, bytes memory err) internal {
        (bool ok, bytes memory ret) = _relay(t, cd);
        assertFalse(ok, "refused");
        assertEq(ret, err, "refused by name");
    }

    function _limited(bytes32 who, IGovernance.GrantTerms memory g) internal {
        bt.setGrant(BURNER, who, g, _uid(bt));
    }

    function _terms(uint128 max) internal pure returns (IGovernance.GrantTerms memory g) {
        g.max = max;
    }

    // ------------------------------------------------------------------ positive controls: the seat burns, three paths

    function test_seatBurnsDirect() public {
        uint256 s0 = bt.totalSupply();
        vm.prank(alice);
        bt.burn(400);
        assertEq(bt.balanceOf(alice), 1_000_000 - 400);
        assertEq(bt.totalSupply(), s0 - 400, "supply falls by amount");
    }

    function test_seatBurnsByMtxBurn() public {
        uint256 s0 = bt.totalSupply();
        _relayOk(bt, _mtxBurnCall(bt, nid(alice), 300));
        assertEq(bt.balanceOf(alice), 1_000_000 - 300);
        assertEq(bt.totalSupply(), s0 - 300);
        assertEq(bt.mtxNonce(nid(alice), 1), 1, "nonce used");
    }

    /// A derived UA holder burns its UA-ledger balance by `mtxBurn` (the named control of the `_govSubject()` mutant: for a
    /// derived signer `_subject()` is the UA, the self-call's caller is the token).
    function test_derivedHolderBurnsByMtxBurn() public {
        bt.grantRole(BURNER, uaP, _uid(bt));
        uint256 s0 = bt.totalSupply();
        _relayOk(bt, _mtxBurnCall(bt, uaP, 200));
        assertEq(IUALedger(address(bt)).balanceOfUA(uaP), 500_000 - 200, "its own UA balance");
        assertEq(IUALedger(address(bt)).balanceOfUA(uaB), 500_000, "no other UA's");
        assertEq(bt.balanceOf(alice), 1_000_000, "no other account's");
        assertEq(bt.totalSupply(), s0 - 200);
    }

    function test_derivedHolderBurnsByGenericExecute() public {
        bt.grantRole(BURNER, uaP, _uid(bt));
        uint256 s0 = bt.totalSupply();
        _relayOk(bt, _genericCall(bt, uaP, 150));
        assertEq(IUALedger(address(bt)).balanceOfUA(uaP), 500_000 - 150);
        assertEq(bt.totalSupply(), s0 - 150);
    }

    function test_nativeSeatBurnsByGenericExecute() public {
        uint256 s0 = bt.totalSupply();
        _relayOk(bt, _genericCall(bt, nid(alice), 10));
        assertEq(bt.totalSupply(), s0 - 10);
    }

    // ------------------------------------------------------------------ negatives: a non-holder with a balance, three paths

    function test_nonHolderRefusedDirect() public {
        vm.expectRevert(_missing(nid(bob)));
        vm.prank(bob);
        bt.burn(1);
    }

    function test_nonHolderRefusedByMtxBurn() public {
        _relayRev(bt, _mtxBurnCall(bt, nid(bob), 1), _missing(nid(bob)));
        _relayRev(bt, _mtxBurnCall(bt, uaB, 1), _missing(uaB));
        assertEq(bt.mtxNonce(uaB, 1), 0, "nonce unused");
        assertEq(IUALedger(address(bt)).balanceOfUA(uaB), 500_000);
    }

    function test_nonHolderRefusedByGenericExecute() public {
        (bool ok, bytes memory ret) = _relay(bt, _genericCall(bt, uaB, 1));
        assertFalse(ok, "the whole call reverts");
        assertEq(bytes4(ret), IGovernance.MissingRole.selector);
        assertEq(IUALedger(address(bt)).balanceOfUA(uaB), 500_000);
        assertEq(bt.mtxNonce(uaB, 1), 0);
    }

    /// A holder whose signed call is for another subject does not burn that subject's units: the role is read on the
    /// signer, the balance debited is the signer's.
    function test_ownBalanceOnly() public {
        bt.grantRole(BURNER, uaP, _uid(bt));
        _relayRev(bt, _mtxBurnCall(bt, uaB, 5), _missing(uaB)); // uaB signs: no role, though uaP holds one
        _relayOk(bt, _mtxBurnCall(bt, uaP, 5));
        assertEq(IUALedger(address(bt)).balanceOfUA(uaB), 500_000);
        assertEq(IUALedger(address(bt)).balanceOfUA(uaP), 500_000 - 5);
    }

    // ------------------------------------------------------------------ a LIMITED holder, each word

    function test_limitedMax() public {
        _limited(nid(bob), _terms(100));
        vm.prank(bob);
        bt.burn(100);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(1)));
        vm.prank(bob);
        bt.burn(101);
    }

    function test_limitedMin() public {
        IGovernance.GrantTerms memory g = _terms(100);
        g.min = 10;
        _limited(nid(bob), g);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(0)));
        vm.prank(bob);
        bt.burn(9);
        vm.prank(bob);
        bt.burn(10);
    }

    function test_limitedTotal() public {
        IGovernance.GrantTerms memory g = _terms(100);
        g.total = 150;
        _limited(nid(bob), g);
        vm.prank(bob);
        bt.burn(100);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(2)));
        vm.prank(bob);
        bt.burn(51);
        vm.prank(bob);
        bt.burn(50);
        assertEq(bt.grantOf(BURNER, nid(bob)).spentTotal, 150, "debited by amount (the scalar)");
    }

    function test_limitedPerWindow() public {
        IGovernance.GrantTerms memory g = _terms(100);
        (g.perWindow, g.window) = (120, 1 days);
        _limited(nid(bob), g);
        vm.prank(bob);
        bt.burn(100);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(3)));
        vm.prank(bob);
        bt.burn(21);
        vm.warp(block.timestamp + 1 days);
        vm.prank(bob);
        bt.burn(100); // the next window lifts it
    }

    function test_limitedMaxUses() public {
        IGovernance.GrantTerms memory g = _terms(100);
        g.maxUses = 2;
        _limited(nid(bob), g);
        vm.startPrank(bob);
        bt.burn(1);
        bt.burn(1);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(5)));
        bt.burn(1);
        vm.stopPrank();
    }

    function test_limitedValidUntil() public {
        IGovernance.GrantTerms memory g = _terms(100);
        g.validUntil = uint64(block.timestamp + 1 hours);
        _limited(nid(bob), g);
        vm.prank(bob);
        bt.burn(1);
        vm.warp(block.timestamp + 1 hours + 1);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExpired.selector, BURNER, nid(bob)));
        vm.prank(bob);
        bt.burn(1);
    }

    /// A limited `mtxBurn` by a derived UA is debited too (`GrantUsed(30, ua, amount)`).
    function test_limitedDerivedByMtxBurn() public {
        IGovernance.GrantTerms memory g = _terms(100);
        g.total = 100;
        _limited(uaP, g);
        _relayOk(bt, _mtxBurnCall(bt, uaP, 60));
        assertEq(bt.grantOf(BURNER, uaP).spentTotal, 60);
        _relayRev(bt, _mtxBurnCall(bt, uaP, 41), abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(2)));
    }

    /// A leaf debits its parent too.
    function test_leafDebitsParent() public {
        IGovernance.GrantTerms memory root = _terms(100);
        (root.total, root.delegable) = (100, true);
        _limited(nid(bob), root);
        IGovernance.GrantTerms memory leaf = _terms(100);
        leaf.total = 80;
        address carol = address(0xCA201);
        _mintTo(bt, carol, 1_000);
        vm.prank(bob);
        bt.setGrant(BURNER, nid(carol), leaf, _uid(bt));
        vm.prank(carol);
        bt.burn(70);
        assertEq(bt.grantOf(BURNER, nid(carol)).spentTotal, 70, "the leaf");
        assertEq(bt.grantOf(BURNER, nid(bob)).spentTotal, 70, "its parent");
    }

    // ------------------------------------------------------------------ revoke, disable, modes

    function test_revokeStopsTheHolder() public {
        bt.revokeRole(BURNER, nid(alice), _uid(bt));
        vm.expectRevert(_missing(nid(alice)));
        vm.prank(alice);
        bt.burn(1);
    }

    /// `disableFeature(30)` stops every burn; the error is `FeatureNotSet(2)` (the token has no `BURNABLE` either, S-17).
    function test_disableStopsEveryBurn() public {
        bt.disableFeature(BURNER, _uid(bt));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, BURNABLE));
        vm.prank(alice);
        bt.burn(1);
        _relayRev(
            bt, _mtxBurnCall(bt, nid(alice), 1), abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, BURNABLE)
        );
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, BURNER));
        bt.grantRole(BURNER, nid(bob), _uid(bt));
    }

    /// `BURNABLE` mode unchanged: any holder burns its own balance; off: `FeatureNotSet(2)`.
    function test_burnableAndOffUnchanged() public {
        NormalToken b = _make(_cfg((1 << GovernanceBits.MINTABLE) | (uint256(1) << BURNABLE), 0));
        _mintTo(b, bob, 10);
        vm.prank(bob);
        b.burn(10);
        assertEq(b.totalSupply(), 0);
        NormalToken off = _make(_cfg(1 << GovernanceBits.MINTABLE, 0));
        _mintTo(off, bob, 10);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, BURNABLE));
        vm.prank(bob);
        off.burn(10);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, BURNER));
        b.grantRole(BURNER, nid(bob), _uid(b));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, BURNER));
        off.setGrant(BURNER, nid(bob), _terms(1), _uid(off));
    }

    // ------------------------------------------------------------------ creation

    function test_initExclusive() public {
        _makeRev(
            _cfg((uint256(1) << BURNABLE) | (uint256(1) << BURNER), 0),
            abi.encodeWithSelector(IGovernance.FeatureConflict.selector, BURNER, BURNABLE)
        );
    }

    function test_initSeatWithoutBit() public {
        _makeRev(
            _cfg(1 << GovernanceBits.MINTABLE, nid(alice)),
            abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, BURNER)
        );
    }

    function test_initBit31OnNormal() public {
        _makeRev(
            _cfg(uint256(1) << GovernanceBits.SUPPLY_CAP_ADJUSTABLE, 0),
            abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, GovernanceBits.SUPPLY_CAP_ADJUSTABLE)
        );
    }

    function test_initMaxWrapSupplyOnNormal() public {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << BURNER, 0);
        c.maxWrapSupply = 1;
        _makeRev(c, abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, uint8(5)));
    }

    /// `admin == 0` with a seat: bit 30 unlocked has a live root (`AdminHasHolders(30)`); locked, the token is created and the
    /// seat burns.
    function test_initNoAdminSeat() public {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << BURNER, nid(alice));
        (c.admin, c.roles.minter) = (0, 0);
        _makeRev(c, abi.encodeWithSelector(IGovernance.AdminHasHolders.selector, BURNER));
        (c.lockedFeatures, c.initialSupply, c.initialHolder) = (uint256(1) << BURNER, 100, alice);
        NormalToken t = _make(c);
        vm.prank(alice);
        t.burn(100);
        assertEq(t.totalSupply(), 0);
    }

    /// Bit 30 on a wrapped kind is `FeatureInvalidForKind`; a burner seat there is `NoSuchRole(30)`.
    function test_initWrappedRefuses() public {
        address[] memory us = new address[](1);
        us[0] = address(und);
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = ("W", "W", 6, nid(address(this)));
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(und), 1, 1);
        c.features = uint256(1) << BURNER;
        WrappedToken w = WrappedToken(
            EnvKit.clone(
                address(new WrappedToken(address(this), kindArgs(1, address(this), ""))),
                EnvKit.env(chainUidA, REG_L, address(0), false)
            )
        );
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, BURNER));
        w.initialize(nid(address(this)), 1, abi.encode(c));
        (c.features, c.roles.burner) = (0, nid(alice));
        w = WrappedToken(
            EnvKit.clone(
                address(new WrappedToken(address(this), kindArgs(1, address(this), ""))),
                EnvKit.env(chainUidA, REG_L, address(0), false)
            )
        );
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, BURNER));
        w.initialize(nid(address(this)), 1, abi.encode(c));
        us;
    }

    /// The masks (the mutants "add 30 to `ENABLEABLE` / `ALWAYS_LOCKED`", "drop 30 from `TOKEN_SCALAR`"): 30 is lockable,
    /// not always locked, never enableable, a scalar power.
    function test_bitMasks() public pure {
        assertEq(GovernanceBits.ENABLEABLE & (uint256(1) << BURNER), 0, "never enabled later");
        assertEq(GovernanceBits.ALWAYS_LOCKED & (uint256(1) << BURNER), 0, "not always locked");
        assertTrue(GovernanceBits.TOKEN_SCALAR & (uint256(1) << BURNER) != 0, "a scalar power");
        assertTrue(GovernanceBits.NORMAL_ROLES & (uint256(1) << BURNER) != 0);
        assertEq(GovernanceBits.WRAPPED_ROLES & (uint256(1) << BURNER), 0);
        assertTrue(GovernanceBits.WRAPPED_BITS & (uint256(1) << GovernanceBits.SUPPLY_CAP_ADJUSTABLE) != 0);
        assertEq(GovernanceBits.NORMAL_BITS & (uint256(1) << GovernanceBits.SUPPLY_CAP_ADJUSTABLE), 0);
    }

    /// The bit is not always locked: with it unlocked the admin can disable it (the control of `test_disableStopsEveryBurn`);
    /// locked at creation, `disableFeature(30)` is `FeatureLocked(30)`.
    function test_lockedBurnerCannotBeDisabled() public {
        IFactoryToken.TokenConfig memory c = _cfg((1 << GovernanceBits.MINTABLE) | (uint256(1) << BURNER), nid(alice));
        c.lockedFeatures = uint256(1) << BURNER;
        NormalToken t = _make(c);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureLocked.selector, BURNER));
        t.disableFeature(BURNER, _uid(t));
    }

    /// A limited grant works only because 30 is a scalar bit (`TOKEN_SCALAR`): with it dropped, `setGrant` with a `max`
    /// would be `GrantWordRefused`.
    function test_limitedGrantAccepted() public {
        _limited(nid(bob), _terms(5));
        assertTrue(bt.hasRole(BURNER, nid(bob)));
    }
}
