// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {noVerdict} from "../pqz/helpers/PqzVerdicts.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {plainEnv, Catalogue} from "../helpers/Catalogue.sol";
import {UACall} from "../ua/UACall.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// @notice Hybrid underlying (spec §5; CTR-GOV-12, CTR-TOK-05; C1, C2): a wrapped token with `maxSupply != 0`, whose issuer
///         mints under the cap. One cap on every path that raises `totalSupply()`; redemption until the reserve is empty,
///         first come; no backing claim, so a rate falls with no `addReserve`; `RateDecreaseWithDisabledLeg` stays; a
///         non-hybrid wrap reads no new slot. `WRAPPED` here (the fixture plays the factory, ledger on `REG_L`); the
///         confidential kinds below, Zether and PQZ apart.
contract GovHybridTest is UALedgerBase {
    address constant OWNER = address(0x0A);
    address constant MINTER = address(0x313);
    address constant MINTER2 = address(0x314);
    address constant GUARD = address(0x6A);
    uint8 constant MINT = GovernanceBits.MINTABLE;
    uint256 constant RATE = uint256(1) << GovernanceBits.RATE_ADJUSTABLE;
    uint256 constant DISABLE = uint256(1) << GovernanceBits.WRAP_DISABLEABLE;
    uint256 constant CAP = 1000;
    bytes32 constant NS = 0x38d6f7edefffa65376a58a6aced8a2c86698d3a0b5d15a785f69ed89d0cd1000; // scaas.underlying

    address internal impl;

    function _legs(address a) internal pure returns (address[] memory l) {
        l = new address[](1);
        l[0] = a;
    }

    /// `PAYABLE` plus `extra`, owner `OWNER`; a hybrid (`MINTABLE`, minter `MINTER`) iff `cap != 0`; the test is the rate admin
    /// (a contract), `GUARD` the guardian.
    function _cfg(address[] memory legs, uint256 cap, uint256 extra) internal pure returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.owner, c.maxSupply) = ("H", "H", 6, nid(OWNER), cap);
        c.features = 1 | extra | (cap != 0 ? uint256(1) << MINT : 0);
        if (cap != 0) c.roles.minter = nid(MINTER);
        if (extra & RATE != 0) (c.roles.rateAdmin, c.rate) = (nid(address(1)), IFactoryToken.RateConfig(2 days, 1000)); // _make: this
        if (extra & DISABLE != 0) c.roles.guardian = nid(GUARD);
        c.legs = new IFactoryToken.Leg[](legs.length);
        for (uint256 i; i < legs.length; ++i) c.legs[i] = IFactoryToken.Leg(legs[i], 1, 1);
    }

    function _clone() internal returns (WrappedToken) {
        if (impl == address(0)) impl = address(new WrappedToken(address(this), kindArgs(1, address(this), "")));
        return WrappedToken(payable(EnvKit.clone(impl, EnvKit.env(chainUidA, REG_L, address(0), false))));
    }

    function _make(IFactoryToken.TokenConfig memory c) internal returns (WrappedToken w) {
        if (c.roles.rateAdmin != 0) c.roles.rateAdmin = nid(address(this));
        w = _clone();
        w.initialize(nid(address(this)), 1, abi.encode(c));
    }

    function _hybrid(address leg, uint256 cap) internal returns (WrappedToken) {
        return _make(_cfg(_legs(leg), cap, 0));
    }

    function _give(WrappedToken w, address who, uint256 amount) internal {
        und.mint(who, amount);
        vm.prank(who);
        und.approve(address(w), type(uint256).max);
    }

    function _wrapUnd(WrappedToken w, address who, uint256 amount) internal {
        _give(w, who, amount);
        vm.prank(who);
        w.wrap(address(und), amount);
    }

    function _over(uint256 supply) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IWrappedToken.MaxSupplyExceeded.selector, supply, CAP);
    }

    function _reserve(WrappedToken w, address leg) internal view returns (uint256 r) {
        (,, r,,) = w.legOf(leg);
    }

    // ------------------------------------------------------------------ creation

    function test_mintableWithoutMaxSupplyRefused() public {
        IFactoryToken.TokenConfig memory c = _cfg(_legs(address(und)), CAP, 0);
        c.maxSupply = 0;
        WrappedToken w = _clone();
        vm.expectRevert(IWrappedToken.MaxSupplyInvalid.selector);
        w.initialize(nid(address(this)), 1, abi.encode(c));
        assertEq(_hybrid(address(und), CAP).maxSupply(), CAP); // positive control: both
    }

    function test_maxSupplyWithoutMintableRefused() public {
        IFactoryToken.TokenConfig memory c = _cfg(_legs(address(und)), 0, 0);
        c.maxSupply = CAP;
        WrappedToken w = _clone();
        vm.expectRevert(IWrappedToken.MaxSupplyInvalid.selector);
        w.initialize(nid(address(this)), 1, abi.encode(c));
        assertEq(_make(_cfg(_legs(address(und)), 0, 0)).maxSupply(), 0); // positive control: neither, fully backed
    }

    // ------------------------------------------------------------------ one cap, every path (spec §5.2)

    function test_capHolds_wrap() public {
        WrappedToken w = _hybrid(address(und), CAP);
        _wrapUnd(w, bob, CAP);
        assertEq(w.totalSupply(), CAP);
        _give(w, bob, 1);
        vm.expectRevert(_over(CAP + 1));
        vm.prank(bob);
        w.wrap(address(und), 1);
    }

    function test_capHolds_wrapToUA() public {
        WrappedToken w = _hybrid(address(und), CAP);
        _give(w, bob, CAP + 1);
        vm.prank(bob);
        w.wrapToUA(address(und), CAP, uaP);
        assertEq(w.balanceOfUA(uaP), CAP);
        vm.expectRevert(_over(CAP + 1));
        vm.prank(bob);
        w.wrapToUA(address(und), 1, uaP);
    }

    function _uaWrapOrder(WrappedToken w, uint256 amount, uint256 nonce) internal view returns (ITradeToken.UAWrapOrder memory o) {
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill) = (_pad(alice), address(w), amount, amount, amount);
        (o.relayer, o.batch, o.nonce, o.validUntil) = (RELAYER, 1, nonce, block.timestamp + 300);
    }

    /// The merged `mtxWrapOrder` (R39: `UAWrapOrder` + `UASig`; the address `WrapOrder` entry is in legacy/ua-mtx-merge/).
    function test_capHolds_mtxWrapOrder() public {
        WrappedToken w = _hybrid(address(tok), CAP);
        ITradeToken.UAWrapOrder memory o = _uaWrapOrder(w, CAP, 1);
        bytes memory sig = _ecdsa(ALICE_PK, tok.tradeOrderDigest(DexLegs.asTrade(o)));
        vm.prank(RELAYER);
        w.mtxWrapOrder(address(tok), o, UACall.auth(o.from, sig));
        assertEq(w.totalSupply(), CAP);
        o = _uaWrapOrder(w, 1, 2);
        sig = _ecdsa(ALICE_PK, tok.tradeOrderDigest(DexLegs.asTrade(o)));
        vm.expectRevert(_over(CAP + 1));
        vm.prank(RELAYER);
        w.mtxWrapOrder(address(tok), o, UACall.auth(o.from, sig));
    }

    function test_capHolds_mint() public {
        WrappedToken w = _hybrid(address(und), CAP);
        vm.prank(MINTER);
        w.mint(alice, CAP);
        assertEq(w.balanceOf(alice), CAP);
        assertEq(_reserve(w, address(und)), 0, "a mint adds no reserve");
        vm.expectRevert(_over(CAP + 1));
        vm.prank(MINTER);
        w.mint(alice, 1);
    }

    function test_capHolds_mintToUA() public {
        WrappedToken w = _hybrid(address(und), CAP);
        vm.prank(MINTER);
        w.mintToUA(uaP, CAP);
        assertEq(w.balanceOfUA(uaP), CAP);
        vm.expectRevert(_over(CAP + 1));
        vm.prank(MINTER);
        w.mintToUA(uaP, 1);
    }

    /// Minted to the cap, deposits stop (spec §5.4: an issuer can shut them first); an unwrap makes room again.
    function test_mintToTheCapStopsWraps() public {
        WrappedToken w = _hybrid(address(und), CAP);
        _wrapUnd(w, bob, 500);
        vm.prank(MINTER);
        w.mint(alice, 500);
        _give(w, bob, 100);
        vm.expectRevert(_over(CAP + 1));
        vm.prank(bob);
        w.wrap(address(und), 1);
        vm.prank(bob);
        w.unwrap(address(und), 100, bob, 0);
        vm.prank(bob);
        w.wrap(address(und), 100); // room again
        assertEq(w.totalSupply(), CAP);
    }

    // ------------------------------------------------------------------ redemption until empty (spec §5.4)

    function _drained() internal returns (WrappedToken w) {
        w = _hybrid(address(und), 2 * CAP);
        _wrapUnd(w, bob, 500);
        vm.prank(MINTER);
        w.mint(alice, CAP);
        vm.prank(alice); // the issuer's own units drain the reserve: first come
        w.unwrap(address(und), 500, alice, 0);
        assertEq(und.balanceOf(alice), 500);
        assertEq(_reserve(w, address(und)), 0);
    }

    function test_unwrapToEmptyThenInsufficientReserve() public {
        WrappedToken w = _drained();
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.InsufficientReserve.selector, address(und), 1, 0));
        vm.prank(bob);
        w.unwrap(address(und), 1, bob, 0);
    }

    function test_unitsTransferAfterTheReserveIsEmpty() public {
        WrappedToken w = _drained();
        vm.prank(bob);
        w.transfer(alice, 500);
        assertEq(w.balanceOf(alice), CAP);
        assertEq(w.balanceOf(bob), 0);
        assertLt(w.collateralValue(), w.totalSupply(), "no backing claim on a hybrid");
    }

    // ------------------------------------------------------------------ rates (spec §5.3, C1)

    function _execute(WrappedToken w, address leg, uint96 num, uint96 den) internal {
        w.proposeRate(leg, num, den);
        vm.warp(block.timestamp + 2 days);
        w.executeRate();
    }

    function test_executeRateOnAHybridShortOfSupply() public {
        WrappedToken w = _make(_cfg(_legs(address(und)), 10 * CAP, RATE));
        _wrapUnd(w, bob, 100);
        vm.prank(MINTER);
        w.mint(alice, 900);
        _execute(w, address(und), 101, 100); // collateral 101 against a supply of 1000
        (uint96 num,,,,) = w.legOf(address(und));
        assertEq(num, 101);
    }

    function test_rateFallOnAHybridNeedsNoAddReserve() public {
        WrappedToken w = _make(_cfg(_legs(address(und)), 10 * CAP, RATE));
        _wrapUnd(w, bob, CAP);
        _execute(w, address(und), 99, 100);
        assertEq(w.collateralValue(), 990);
        assertEq(w.totalSupply(), CAP);
    }

    function test_executeRateNonHybridStillChecksSupply() public {
        WrappedToken w = _make(_cfg(_legs(address(und)), 0, RATE));
        _wrapUnd(w, bob, CAP);
        w.proposeRate(address(und), 99, 100);
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.RateChangeUndercollateralized.selector, 990, CAP));
        w.executeRate();
        _give(w, address(this), 11);
        w.addReserve(address(und), 11); // positive control: ⌊1011·0.99⌋ = 1000
        w.executeRate();
    }

    function test_rateFallWithDisabledLegStillRefusedOnAHybrid() public {
        MockERC20 und2 = new MockERC20("U2", "U2", 6);
        address[] memory two = new address[](2);
        (two[0], two[1]) = (address(und), address(und2));
        WrappedToken w = _make(_cfg(two, 10 * CAP, RATE | DISABLE));
        _wrapUnd(w, bob, CAP);
        vm.prank(GUARD);
        w.disableWrap(address(und2), "depeg");
        w.proposeRate(address(und), 99, 100);
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(IWrappedToken.RateDecreaseWithDisabledLeg.selector);
        w.executeRate();
        w.cancelRate();
        _execute(w, address(und), 101, 100); // positive control: a rise
    }

    // ------------------------------------------------------------------ the hybrid stays one (spec §5.2, §5.4)

    function test_disableMintableLeavesAHybrid() public {
        WrappedToken w = _hybrid(address(und), CAP);
        vm.prank(OWNER);
        w.disableFeature(MINT);
        assertEq(w.features() & (uint256(1) << MINT), 0);
        assertEq(w.maxSupply(), CAP);
        bytes32 slotA = keccak256(abi.encode(uint256(0), NS));
        assertEq((uint256(vm.load(address(w), slotA)) >> (8 * 23)) & 0xff, 1, "leg 0 keeps capped");
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, MINT));
        vm.prank(MINTER);
        w.mint(alice, 1);
        _wrapUnd(w, bob, CAP); // the cap binds wraps still
        _give(w, bob, 1);
        vm.expectRevert(_over(CAP + 1));
        vm.prank(bob);
        w.wrap(address(und), 1);
    }

    function test_addReserveRefusedOnADisabledLegOfAHybrid() public {
        WrappedToken w = _make(_cfg(_legs(address(und)), CAP, DISABLE));
        _give(w, address(this), 2);
        w.addReserve(address(und), 1); // positive control
        vm.prank(GUARD);
        w.disableWrap(address(und), "closed");
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapDisabledFor.selector, address(und)));
        w.addReserve(address(und), 1);
    }

    /// Spec §5.6: the whole `Grant` binds the minter of a wrapped kind beside `maxSupply`.
    function test_limitedMinterBindsOnAWrappedKind() public {
        WrappedToken w = _hybrid(address(und), 10 * CAP);
        IGovernance.GrantTerms memory g;
        (g.max, g.total, g.perWindow, g.window) = (type(uint128).max, 100, 50, 1 days);
        vm.prank(OWNER);
        w.setGrant(MINT, nid(MINTER2), g);
        vm.prank(MINTER2);
        w.mint(alice, 50);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(3)));
        vm.prank(MINTER2);
        w.mint(alice, 1);
        vm.warp(block.timestamp + 1 days);
        vm.prank(MINTER2);
        w.mint(alice, 50);
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(2)));
        vm.prank(MINTER2);
        w.mint(alice, 1);
    }

    // ------------------------------------------------------------------ no new slot off the hybrid (C2)

    function _wrapReads(WrappedToken w) internal returns (bytes32[] memory reads) {
        _give(w, bob, 100);
        vm.record();
        vm.prank(bob);
        w.wrap(address(und), 100);
        (reads,) = vm.accesses(address(w));
    }

    function _has(bytes32[] memory a, bytes32 x) internal pure returns (bool) {
        for (uint256 i; i < a.length; ++i) if (a[i] == x) return true;
        return false;
    }

    /// The slots a fixed-rate wrap reads: a hybrid's are a non-hybrid's plus `maxSupply`, and a non-hybrid's hold no
    /// `maxSupply` (the `capped` copy sits in slot a, read anyway; `totalSupply()` is read by `_mint` anyway).
    function test_nonHybridWrapReadsNoNewSlot() public {
        bytes32 maxSlot = bytes32(uint256(NS) + 4);
        bytes32[] memory plain = _wrapReads(_make(_cfg(_legs(address(und)), 0, 0)));
        bytes32[] memory capped = _wrapReads(_hybrid(address(und), CAP));
        assertFalse(_has(plain, maxSlot), "a non-hybrid wrap reads maxSupply");
        assertTrue(_has(capped, maxSlot), "control: a hybrid wrap reads it");
        for (uint256 i; i < plain.length; ++i) assertTrue(_has(capped, plain[i]), "a slot only the plain wrap reads");
        for (uint256 i; i < capped.length; ++i) {
            assertTrue(capped[i] == maxSlot || _has(plain, capped[i]), "a slot only the hybrid wrap reads, not maxSupply");
        }
    }
}

/// `WRAPPED_ZETHER`: `mtxWrapShield` under the cap; `mtxUnshieldUnwrap` quotes the leg before the proof; the minter never
/// reaches a shielded balance.
contract GovHybridZetherTest is ZetherFixture {
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
        _users();
    }

    /// One USD leg 1:1; a hybrid (the fixture the minter, `MINTABLE` locked, no owner) iff `cap != 0`.
    function _token(uint256 cap, bytes32 salt) internal returns (WrappedZetherToken) {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        c.features = 1 | (cap != 0 ? uint256(1) << GovernanceBits.MINTABLE : 0);
        if (cap == 0) (c.lockedFeatures, c.roles.minter) = (0, 0);
        c.maxSupply = cap;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        return WrappedZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), salt)));
    }

    function test_capHolds_mtxWrapShieldZether() public {
        WrappedZetherToken w = _token(30 * SCALE, "h");
        usd.mint(address(this), 31 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.mtxWrapShield(address(usd), 30 * SCALE, ZetherTypes.UA.unwrap(alice.ua));
        assertEq(w.totalShielded(), 30);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.MaxSupplyExceeded.selector, 31 * SCALE, 30 * SCALE));
        w.mtxWrapShield(address(usd), SCALE, ZetherTypes.UA.unwrap(alice.ua));
    }

    function _unshieldUnwrap(WrappedZetherToken w) internal returns (bool ok, bytes memory ret) {
        IZetherToken.ZetherBurn memory b; // no proof behind it: whatever runs the proof refuses it
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), bytes32(uint256(uint160(address(0xD00D)))), 10, 0);
        try w.mtxUnshieldUnwrap(b, x, "") {
            ok = true;
        } catch (bytes memory e) {
            ret = e;
        }
    }

    /// Spec §5.4, Claude M-9: on a hybrid an empty reserve is ordinary, so the leg's quote runs before the proof. A call with no
    /// proof behind it gets `InsufficientReserve` on an empty leg, and the proof's refusal once the leg holds enough.
    function test_unshieldUnwrapShortReserveRevertsBeforeTheProofZether() public {
        WrappedZetherToken w = _token(1000 * SCALE, "h");
        w.mint(address(this), 100 * SCALE);
        (bool ok, bytes memory ret) = _unshieldUnwrap(w);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IWrappedToken.InsufficientReserve.selector, address(usd), 10 * SCALE, 0));
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.wrap(address(usd), 100 * SCALE); // positive control: the leg holds enough, the proof stage refuses
        (ok, ret) = _unshieldUnwrap(w);
        assertFalse(ok);
        assertTrue(bytes4(ret) != IWrappedToken.InsufficientReserve.selector, "the quote, not the proof");
    }

    function test_minterNeverMintsIntoAShieldedBalance() public {
        WrappedZetherToken w = _token(1000 * SCALE, "h");
        vm.expectRevert(IUALedger.ShieldPoolNotPayable.selector);
        w.mint(SHIELD_POOL_, SCALE);
        bytes32 pool = MetaTxLib.pad(SHIELD_POOL_);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, pool));
        w.mintToUA(pool, SCALE);
        w.mint(alice.evm, SCALE); // positive control: a public balance
        assertEq(w.balanceOf(alice.evm), SCALE);
        assertEq(w.totalShielded(), 0);
        assertEq(w.balanceOf(SHIELD_POOL_), 0);
    }
}

/// `WRAPPED_PQZ`, apart from Zether: the same three rows.
contract GovHybridPqzTest is PqzFixture {
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);
    address internal constant POOL_ = MetaTxLib.SHIELD_POOL;

    function setUp() public {
        _stack();
        _releaseWrapped();
    }

    function _token(uint256 cap, bytes32 salt) internal returns (WrappedPqzToken) {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = 1 | (cap != 0 ? uint256(1) << GovernanceBits.MINTABLE : 0);
        if (cap == 0) (c.lockedFeatures, c.roles.minter) = (0, 0);
        c.maxSupply = cap;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        return WrappedPqzToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), salt)));
    }

    function test_capHolds_mtxWrapShieldPqz() public {
        WrappedPqzToken w = _token(30 * SCALE, "h");
        usd.mint(address(this), 31 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.mtxWrapShield(address(usd), 30 * SCALE, alice);
        assertEq(w.totalShielded(), 30);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.MaxSupplyExceeded.selector, 31 * SCALE, 30 * SCALE));
        w.mtxWrapShield(address(usd), SCALE, alice);
    }

    function _unshieldUnwrap(WrappedPqzToken w) internal returns (bool ok, bytes memory ret) {
        // an unregistered `fromUA`: whatever runs the burn refuses it
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), bytes32(uint256(0xBAD)), bytes32(0)),
            _blob(21, PqzCt.CT));
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), bytes32(uint256(uint160(address(0xD00D)))), 10, 0);
        try w.mtxUnshieldUnwrap(_bs(pl), x, hex"c0de", _pqAuth(), "", noVerdict()) {
            ok = true;
        } catch (bytes memory e) {
            ret = e;
        }
    }

    function test_unshieldUnwrapShortReserveRevertsBeforeTheProofPqz() public {
        WrappedPqzToken w = _token(1000 * SCALE, "h");
        w.mint(address(this), 100 * SCALE);
        (bool ok, bytes memory ret) = _unshieldUnwrap(w);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IWrappedToken.InsufficientReserve.selector, address(usd), 10 * SCALE, 0));
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.wrap(address(usd), 100 * SCALE); // positive control: the leg holds enough, the burn stage refuses
        (ok, ret) = _unshieldUnwrap(w);
        assertFalse(ok);
        assertTrue(bytes4(ret) != IWrappedToken.InsufficientReserve.selector, "the quote, not the burn");
    }

    function test_minterNeverMintsIntoAShieldedBalance() public {
        WrappedPqzToken w = _token(1000 * SCALE, "h");
        vm.expectRevert(IUALedger.ShieldPoolNotPayable.selector);
        w.mint(POOL_, SCALE);
        bytes32 pool = MetaTxLib.pad(POOL_);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, pool));
        w.mintToUA(pool, SCALE);
        w.mint(address(0xA11CE), SCALE); // positive control: a public balance
        assertEq(w.balanceOf(address(0xA11CE)), SCALE);
        assertEq(w.totalShielded(), 0);
        assertEq(w.balanceOf(POOL_), 0);
    }
}
