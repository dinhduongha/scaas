// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode, FeePolicy} from "../../src/common/FeePolicy.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {normalInit, wrappedInit, Rate} from "../v2/helpers/V2Fixture.sol";
import {UALedgerBase} from "./UALedgerBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// Exposes `_uaMint` (accounts.md CTR-UA-28).
contract UAMintHarness is NormalToken {
    constructor(bytes32 uid, address reg) NormalToken(1, plainEnv(msg.sender, address(0), uid, reg, false), "") {}

    function mintUA(bytes32 to, uint256 v) external {
        _uaMint(to, v);
    }
}

/// A leg that answers `IUALedger` by ERC-165 but lies: mode 0 moves one unit less than asked, mode 1 re-enters `target`,
/// mode 2 moves one unit more.
contract LyingLedgerLeg is MockERC20 {
    uint8 public mode;
    address public target;

    constructor() MockERC20("Lie", "LIE", 6) {}

    function arm(uint8 m, address t) external {
        (mode, target) = (m, t);
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == type(IERC165).interfaceId || id == type(IUALedger).interfaceId;
    }

    function transferToUA(bytes32, uint256 v) external returns (bool) {
        if (mode == 1) WrappedToken(target).unwrapToUA(address(this), 1, bytes32(0), 0);
        _transfer(msg.sender, address(0xdead), mode == 2 ? v + 1 : v - 1);
        return true;
    }
}

/// accounts.md CTR-UA-28: a native caller credits a derived UA in one call; a mint into a UA is a UA-ledger move from 0.
contract UAReceiversTest is UALedgerBase {
    bytes32 internal constant REF = keccak256("scaas.ua5a.ref");

    UAMintHarness internal hm;

    function setUp() public override {
        super.setUp();
        hm = _harness(REG_L);
    }

    function _harness(address registry_) internal returns (UAMintHarness h) {
        h = UAMintHarness(Clones.clone(address(new UAMintHarness(chainUidA, registry_))));
        h.initialize(address(this), 1, abi.encode(normalInit("H", "H", 6, 0, address(0), address(this))));
    }

    // ----- _uaMint -----

    function test_uaMint_eventsAndTotals() public {
        vm.expectEmit(address(hm));
        emit IERC20.Transfer(address(0), POOL, 700);
        vm.expectEmit(address(hm));
        emit IUALedger.UATransfer(bytes32(0), uaP, 700);
        hm.mintUA(uaP, 700);
        assertEq(hm.totalSupply(), 700);
        assertEq(hm.balanceOf(POOL), 700);
        assertEq(hm.balanceOfUA(uaP), 700);
    }

    /// UA-6 U8: the Zether UA receives (a SIGNING UA).
    function test_uaMint_refusesNativeUnregistered_zetherReceives() public {
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, _pad(bob)));
        hm.mintUA(_pad(bob), 1);
        bytes32 unknown = keccak256("unregistered");
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, unknown));
        hm.mintUA(unknown, 1);
        hm.mintUA(uaZ, 1);
        assertEq(hm.balanceOfUA(uaZ), 1);
        assertEq(hm.totalSupply(), 1);
    }

    function test_uaMint_ledgerOff() public {
        UAMintHarness off = _harness(address(0));
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.mintUA(uaP, 1);
    }

    // ----- helpers -----

    /// An address-path `MetaTransaction` of alice on `token`, signed.
    function _mtx(address token, bytes memory data, uint32 mode, uint256 fee, address feeTo)
        internal view returns (MetaTxLib.MetaTransaction memory m, bytes memory sig)
    {
        m = MetaTxLib.MetaTransaction({from: alice, data: data, batch: 3, nonce: MetaTokenBase(token).mtxNonce(alice, 3),
            validUntil: block.timestamp + 300, mode: mode, relayer: RELAYER, fee: fee, feeRecipient: feeTo});
        sig = _ecdsa(ALICE_PK, MetaTokenBase(token).mtxDigest(m));
    }

    function _relay(address token, bytes memory data, uint32 mode, uint256 fee, address feeTo, bytes memory err) internal {
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) = _mtx(token, data, mode, fee, feeTo);
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(RELAYER);
        MetaTokenBase(token).mtxExecute(m, sig);
    }

    function _reserve(WrappedToken w, address leg) internal view returns (uint256 r) {
        (,, r,,) = w.legOf(leg);
    }

    /// A NORMAL clone on `REG_L` with `features` and no minter.
    function _normal(uint256 features) internal returns (NormalToken t) {
        t = NormalToken(Clones.clone(address(new NormalToken(1, plainEnv(address(this), address(0), chainUidA, REG_L, false), ""))));
        IFactoryToken.TokenConfig memory c = normalInit("N", "N", 6, 1_000, alice, address(0));
        c.features = features;
        t.initialize(address(this), 1, abi.encode(c));
    }

    // ----- wrapToUA -----

    function test_wrapToUA_erc20Leg() public {
        und.mint(alice, 1_000);
        vm.prank(alice);
        und.approve(address(wrp), 1_000);
        vm.expectEmit(address(wrp));
        emit IERC20.Transfer(address(0), POOL, 1_000);
        vm.expectEmit(address(wrp));
        emit IUALedger.UATransfer(bytes32(0), uaP, 1_000);
        vm.expectEmit(address(wrp));
        emit IWrappedToken.Wrapped(alice, address(und), 1_000, 1_000);
        vm.prank(alice);
        assertEq(wrp.wrapToUA(address(und), 1_000, uaP), 1_000);
        assertEq(wrp.balanceOfUA(uaP), 1_000);
        assertEq(wrp.balanceOf(alice), 0);
        assertEq(wrp.balanceOf(POOL), 1_000);
        assertEq(wrp.totalSupply(), 1_000);
        assertEq(_reserve(wrp, address(und)), 1_000);
        assertEq(und.balanceOf(address(wrp)), 1_000);
    }

    /// UA-6 U8: the Zether UA is a SIGNING UA, so `wrapToUA` credits it.
    function test_UA6_wrapToUA_zetherReceives() public {
        und.mint(alice, 100);
        vm.startPrank(alice);
        und.approve(address(wrp), 100);
        assertEq(wrp.wrapToUA(address(und), 100, uaZ), 100);
        vm.stopPrank();
        assertEq(wrp.balanceOfUA(uaZ), 100);
    }

    function test_wrapToUA_nativeLeg_direct() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        wrpN.wrapToUA{value: 5_000}(address(0), 5_000, uaB);
        assertEq(wrpN.balanceOfUA(uaB), 5_000);
        assertEq(address(wrpN).balance, 5_000);
        assertEq(_reserve(wrpN, address(0)), 5_000);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.NativeValueMismatch.selector, 4_999, 5_000));
        vm.prank(alice);
        wrpN.wrapToUA{value: 4_999}(address(0), 5_000, uaB);
        // an ERC-20 leg takes no coin
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.NativeValueMismatch.selector, 1, 0));
        vm.prank(alice);
        wrp.wrapToUA{value: 1}(address(und), 5_000, uaB);
    }

    /// Relayed (`ABSOLUTE`): the fee comes after the call from the signer's own native balance of this token; a signer
    /// without one signs fee `NONE`; `PERCENT` is refused at step 3.
    function test_wrapToUA_relayed_absoluteFeeFromNativeBalance() public {
        _wrapFor(alice, 5);
        und.mint(alice, 2_000);
        vm.prank(alice);
        und.approve(address(wrp), 2_000);
        bytes memory data = abi.encodeCall(WrappedToken.wrapToUA, (address(und), 1_000, uaP));
        _relay(address(wrp), data, RR | RF | FIX, 5, FEE_TO, "");
        assertEq(wrp.balanceOfUA(uaP), 1_000);
        assertEq(wrp.balanceOf(alice), 0);
        assertEq(wrp.balanceOf(FEE_TO), 5);
        _relay(address(wrp), data, RR, 0, address(0), "");
        assertEq(wrp.balanceOfUA(uaP), 2_000);
        _relay(address(wrp), data, RR | RF | PCT, 1, FEE_TO,
            abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, WrappedToken.wrapToUA.selector, RR | RF | PCT));
    }

    function test_wrapToUA_nativeLeg_relayedRefused() public {
        _relay(address(wrpN), abi.encodeCall(WrappedToken.wrapToUA, (address(0), 1_000, uaP)), RR, 0, address(0),
            abi.encodeWithSelector(IWrappedToken.NativeValueMismatch.selector, 0, 1_000));
    }

    /// The receiver is checked before any pull; the leg's own refusals are `wrap`'s.
    function test_wrapToUA_refusals() public {
        MockERC20 und2 = new MockERC20("U2", "U2", 6);
        address[] memory us = new address[](2);
        (us[0], us[1]) = (address(und), address(und2));
        uint256[] memory one = new uint256[](2);
        (one[0], one[1]) = (1, 1);
        Rate memory adj = Rate(true, address(this), 2 days, 1_000);
        WrappedToken w =
            WrappedToken(Clones.clone(address(new WrappedToken(1, plainEnv(address(this), address(0), chainUidA, REG_L, false), ""))));
        w.initialize(address(this), 1, abi.encode(wrappedInit(us, one, one, 6, adj, address(this), address(0))));
        und.mint(alice, 1_000);
        und2.mint(alice, 1_000);
        vm.startPrank(alice);
        und.approve(address(w), 1_000);
        und2.approve(address(w), 1_000);
        bytes32 unknown = keccak256("unregistered");
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, _pad(bob)));
        w.wrapToUA(address(und), 100, _pad(bob));
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, unknown));
        w.wrapToUA(address(und), 100, unknown);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnknownUnderlying.selector, address(tok)));
        w.wrapToUA(address(tok), 100, uaP);
        // `bytes32(0)` is `_wrap`'s mint-to-caller sentinel: `wrapToUA` refuses it as a native id first
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, bytes32(0)));
        w.wrapToUA(address(und), 100, bytes32(0));
        assertEq(und.allowance(alice, address(w)), 1_000, "nothing pulled");
        w.wrapToUA(address(und), 100, uaP);
        vm.stopPrank();
        deal(address(und), address(w), 99);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.ReserveShortfall.selector, address(und), 99, 100));
        vm.prank(alice);
        w.wrapToUA(address(und), 100, uaP);
        deal(address(und), address(w), 100);
        w.disableWrap(address(und2), "depeg");
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapDisabledFor.selector, address(und2)));
        vm.prank(alice);
        w.wrapToUA(address(und2), 100, uaP);
        w.proposeRate(address(und), 101, 100);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapPausedForRateChange.selector, address(und)));
        vm.prank(alice);
        w.wrapToUA(address(und), 100, uaP);
        WrappedToken off = _offWrapper(address(und));
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        vm.prank(alice);
        off.wrapToUA(address(und), 100, uaP);
    }

    /// A one-leg 1:1 wrapper of `leg` with the ledger off (registry 0).
    function _offWrapper(address leg) internal returns (WrappedToken w) {
        w = WrappedToken(Clones.clone(address(new WrappedToken(1, plainEnv(address(this), address(0), chainUidA, address(0), false), ""))));
        address[] memory us = new address[](1);
        uint256[] memory one = new uint256[](1);
        (us[0], one[0]) = (leg, 1);
        Rate memory fixedRate;
        w.initialize(address(this), 1, abi.encode(wrappedInit(us, one, one, 6, fixedRate, address(0), address(0))));
    }

    // ----- unwrapToUA -----

    function test_unwrapToUA_direct() public {
        _wrapL(alice, 10_000);
        vm.expectEmit(address(wrpL));
        emit IERC20.Transfer(alice, address(0), 4_000);
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(address(wrpL), POOL, 4_000);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(_pad(address(wrpL)), uaB, 4_000);
        vm.expectEmit(address(wrpL));
        emit IWrappedToken.UnwrappedToUA(alice, address(tok), uaB, 4_000, 4_000);
        vm.prank(alice);
        (uint256 out, uint256 burned) = wrpL.unwrapToUA(address(tok), 4_000, uaB, 4_000);
        assertEq(out, 4_000);
        assertEq(burned, 4_000);
        assertEq(wrpL.balanceOf(alice), 6_000);
        assertEq(wrpL.totalSupply(), 6_000);
        assertEq(tok.balanceOf(address(wrpL)), 6_000);
        assertEq(_reserve(wrpL, address(tok)), 6_000);
        assertEq(tok.balanceOfUA(uaB), 4_000);
        assertEq(tok.balanceOf(POOL), 4_000);
    }

    /// A leg that is not a SCaaS ledger token: an outside ERC-20, the native coin, a SCaaS token with the ledger off.
    function test_unwrapToUA_notLedgerLeg() public {
        _wrapFor(alice, 100);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(und)));
        vm.prank(alice);
        wrp.unwrapToUA(address(und), 100, uaP, 0);
        vm.deal(alice, 100);
        vm.startPrank(alice);
        wrpN.wrap{value: 100}(address(0), 100);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(0)));
        wrpN.unwrapToUA(address(0), 100, uaP, 0);
        vm.stopPrank();
        NormalToken off =
            NormalToken(Clones.clone(address(new NormalToken(1, plainEnv(address(this), address(0), chainUidA, address(0), false), ""))));
        off.initialize(address(this), 1, abi.encode(normalInit("Off", "OFF", 6, 0, address(0), address(this))));
        WrappedToken w = _wrapper(address(off));
        off.mint(address(this), 100);
        off.approve(address(w), 100);
        w.wrap(100);
        w.transfer(alice, 100);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(off)));
        vm.prank(alice);
        w.unwrapToUA(address(off), 100, uaP, 0);
        assertEq(w.balanceOf(alice), 100);
    }

    /// `to` is checked by the leg's own `transferToUA`.
    function test_unwrapToUA_nativeOrBadTo() public {
        _wrapL(alice, 100);
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, _pad(bob)));
        wrpL.unwrapToUA(address(tok), 10, _pad(bob), 0);
        wrpL.unwrapToUA(address(tok), 10, uaZ, 0); // UA-6 U8: the Zether UA receives
        assertEq(tok.balanceOfUA(uaZ), 10);
        bytes32 unknown = keccak256("unregistered");
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, unknown));
        wrpL.unwrapToUA(address(tok), 10, unknown, 0);
        vm.stopPrank();
    }

    function test_unwrapToUA_minOutAndReserve() public {
        _wrapL(alice, 100);
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnwrapBelowMin.selector, 10, 11));
        wrpL.unwrapToUA(address(tok), 10, uaP, 11);
        vm.expectRevert(IWrappedToken.UnwrapTooSmall.selector);
        wrpL.unwrapToUA(address(tok), 0, uaP, 0);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnknownUnderlying.selector, address(und)));
        wrpL.unwrapToUA(address(und), 10, uaP, 0);
        vm.stopPrank();
        // two legs: units wrapped on `und`, unwrapped from `tok`, whose reserve is 0
        address[] memory us = new address[](2);
        (us[0], us[1]) = (address(und), address(tok));
        uint256[] memory one = new uint256[](2);
        (one[0], one[1]) = (1, 1);
        Rate memory fixedRate;
        WrappedToken w =
            WrappedToken(Clones.clone(address(new WrappedToken(1, plainEnv(address(this), address(0), chainUidA, REG_L, false), ""))));
        w.initialize(address(this), 1, abi.encode(wrappedInit(us, one, one, 6, fixedRate, address(0), address(0))));
        und.mint(alice, 50);
        vm.startPrank(alice);
        und.approve(address(w), 50);
        w.wrap(address(und), 50);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.InsufficientReserve.selector, address(tok), 50, 0));
        w.unwrapToUA(address(tok), 50, uaP, 0);
        vm.stopPrank();
    }

    /// The exact-delta check protects the reserve from a leg that lies about `IUALedger`; a re-entry from the leg into
    /// the wrapper hits its guard.
    function test_unwrapToUA_lyingLeg() public {
        LyingLedgerLeg leg = new LyingLedgerLeg();
        WrappedToken w = _wrapper(address(leg));
        leg.mint(alice, 100);
        vm.startPrank(alice);
        leg.approve(address(w), 100);
        w.wrap(100);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnderlyingTransferMismatch.selector, address(leg), 40, 39));
        w.unwrapToUA(address(leg), 40, uaP, 0);
        vm.stopPrank();
        leg.arm(1, address(w));
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        vm.prank(alice);
        w.unwrapToUA(address(leg), 40, uaP, 0);
        // over-pay: the check is exact (`!=`), not a floor
        leg.arm(2, address(w));
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnderlyingTransferMismatch.selector, address(leg), 40, 41));
        vm.prank(alice);
        w.unwrapToUA(address(leg), 40, uaP, 0);
        assertEq(_reserve(w, address(leg)), 100);
    }

    /// Relayed through `mtxExecute`: `AMOUNT(1)`, a fee of 1 % of `wrapped` from the signer's balance after the call.
    function test_unwrapToUA_relayedNative() public {
        _wrapL(alice, 10_000);
        _relay(address(wrpL), abi.encodeCall(WrappedToken.unwrapToUA, (address(tok), 4_000, uaP, 4_000)),
            RR | RF | PCT, 10_000, FEE_TO, "");
        assertEq(tok.balanceOfUA(uaP), 4_000);
        assertEq(wrpL.balanceOf(alice), 10_000 - 4_000 - 40);
        assertEq(wrpL.balanceOf(FEE_TO), 40);
        _relay(address(wrpL), abi.encodeCall(WrappedToken.unwrapToUA, (address(tok), 1_000, uaP, 0)), RR | RF | FIX,
            11, FEE_TO, abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 11, 10));
    }

    /// C5a-15: a wrapper with its ledger off pays a UA of a ledger-on leg; the credit lives in the leg's ledger (only the
    /// UA-subject path, `uaExecute`, needs the wrapper's own ledger).
    function test_unwrapToUA_ledgerOffWrapper_ledgerOnLeg() public {
        WrappedToken off = _offWrapper(address(tok));
        _wrapLOn(off, alice, 100);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(_pad(address(off)), uaP, 100);
        vm.expectEmit(address(off));
        emit IWrappedToken.UnwrappedToUA(alice, address(tok), uaP, 100, 100);
        vm.prank(alice);
        off.unwrapToUA(address(tok), 100, uaP, 100);
        assertEq(tok.balanceOfUA(uaP), 100);
        assertEq(off.balanceOf(alice), 0);
        assertEq(off.totalSupply(), 0);
        assertEq(_reserve(off, address(tok)), 0);
    }

    // ----- a non-unit rate (3/2): minted, burned, out and the reserve each distinct -----

    /// `wrapToUA` of 1001 at 3/2 mints ⌊1001·3/2⌋ = 1501 into the UA; the reserve takes the 1001 received.
    function test_wrapToUA_rate32_direct() public {
        WrappedToken w = _wrapperAt(address(und), 3, 2);
        und.mint(alice, 1_001);
        vm.prank(alice);
        und.approve(address(w), 1_001);
        vm.expectEmit(address(w));
        emit IERC20.Transfer(address(0), POOL, 1_501);
        vm.expectEmit(address(w));
        emit IUALedger.UATransfer(bytes32(0), uaP, 1_501);
        vm.expectEmit(address(w));
        emit IWrappedToken.Wrapped(alice, address(und), 1_001, 1_501);
        vm.prank(alice);
        assertEq(w.wrapToUA(address(und), 1_001, uaP), 1_501);
        assertEq(w.balanceOfUA(uaP), 1_501);
        assertEq(w.balanceOf(POOL), 1_501);
        assertEq(w.balanceOf(alice), 0);
        assertEq(w.totalSupply(), 1_501);
        assertEq(_reserve(w, address(und)), 1_001);
        assertEq(und.balanceOf(address(w)), 1_001);
    }

    /// The same relayed (`mtxExecute`, the signer alice).
    function test_wrapToUA_rate32_relayed() public {
        WrappedToken w = _wrapperAt(address(und), 3, 2);
        und.mint(alice, 1_001);
        vm.prank(alice);
        und.approve(address(w), 1_001);
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) =
            _mtx(address(w), abi.encodeCall(WrappedToken.wrapToUA, (address(und), 1_001, uaP)), RR, 0, address(0));
        vm.expectEmit(address(w));
        emit IUALedger.UATransfer(bytes32(0), uaP, 1_501);
        vm.expectEmit(address(w));
        emit IWrappedToken.Wrapped(alice, address(und), 1_001, 1_501);
        vm.prank(RELAYER);
        w.mtxExecute(m, sig);
        assertEq(w.balanceOfUA(uaP), 1_501);
        assertEq(w.totalSupply(), 1_501);
        assertEq(_reserve(w, address(und)), 1_001);
    }

    /// `unwrapToUA` of 1000 at 3/2: out ⌊1000·2/3⌋ = 666 into the UA in `tok`, burned ⌈666·3/2⌉ = 999 (not 1000).
    function test_unwrapToUA_rate32_direct() public {
        WrappedToken w = _wrapperAt(address(tok), 3, 2);
        assertEq(_wrapLOn(w, alice, 1_001), 1_501);
        vm.expectEmit(address(w));
        emit IERC20.Transfer(alice, address(0), 999);
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(address(w), POOL, 666);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(_pad(address(w)), uaB, 666);
        vm.expectEmit(address(w));
        emit IWrappedToken.UnwrappedToUA(alice, address(tok), uaB, 999, 666);
        vm.prank(alice);
        (uint256 out, uint256 burned) = w.unwrapToUA(address(tok), 1_000, uaB, 666);
        assertEq(out, 666);
        assertEq(burned, 999);
        assertEq(w.balanceOf(alice), 1_501 - 999);
        assertEq(w.totalSupply(), 1_501 - 999);
        assertEq(_reserve(w, address(tok)), 1_001 - 666);
        assertEq(tok.balanceOf(address(w)), 1_001 - 666);
        assertEq(tok.balanceOfUA(uaB), 666);
    }

    // ----- mintToUA -----

    function test_mintToUA() public {
        uint256 supply = tok.totalSupply();
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(address(0), POOL, 500);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(bytes32(0), uaP, 500);
        tok.mintToUA(uaP, 500);
        assertEq(tok.balanceOfUA(uaP), 500);
        assertEq(tok.totalSupply(), supply + 500);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.MissingRole.selector, AdminLib.MINTABLE, alice));
        vm.prank(alice);
        tok.mintToUA(uaP, 1);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, _pad(bob)));
        tok.mintToUA(_pad(bob), 1);
        NormalToken noMint = _normal(1 << AdminLib.PAYABLE);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, AdminLib.MINTABLE));
        noMint.mintToUA(uaP, 1);
        _relay(address(tok), abi.encodeCall(NormalToken.mintToUA, (uaP, 1)), RR, 0, address(0),
            abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, NormalToken.mintToUA.selector));
    }

    // ----- payWithFeeToUA -----

    function test_payWithFeeToUA() public {
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(alice, FEE_TO, 10);
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(alice, POOL, 1_000);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(_pad(alice), uaP, 1_000);
        vm.expectEmit(address(tok));
        emit IUALedger.UAPaymentSettled(_pad(alice), uaP, 1_000, 10, FEE_TO, REF);
        vm.prank(alice);
        assertTrue(tok.payWithFeeToUA(uaP, 1_000, FeeMode.FIXED, 10, FEE_TO, REF));
        assertEq(tok.balanceOfUA(uaP), 1_000);
        assertEq(tok.balanceOf(FEE_TO), 10);
        assertEq(tok.balanceOf(alice), 1_000_000 - 1_010);
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, _pad(bob)));
        tok.payWithFeeToUA(_pad(bob), 1, FeeMode.NONE, 0, address(0), REF);
        tok.payWithFeeToUA(uaZ, 1, FeeMode.NONE, 0, address(0), REF); // UA-6 U8: the Zether UA receives
        assertEq(tok.balanceOfUA(uaZ), 1);
        vm.expectRevert(abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 10_001, 10_000));
        tok.payWithFeeToUA(uaP, 1_000, FeeMode.PERCENT, 10_001, FEE_TO, REF);
        vm.stopPrank();
        NormalToken notPayable = _normal(1 << AdminLib.BURNABLE);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, AdminLib.PAYABLE));
        vm.prank(alice);
        notPayable.payWithFeeToUA(uaP, 1, FeeMode.NONE, 0, address(0), REF);
        _relay(address(tok), abi.encodeCall(MetaTokenBase.payWithFeeToUA, (uaP, 1, FeeMode.NONE, 0, address(0), REF)), RR,
            0, address(0), abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, MetaTokenBase.payWithFeeToUA.selector));
    }

    function test_payWithFeeToUA_poolFeeRecipientRefused() public {
        vm.startPrank(alice);
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        tok.payWithFeeToUA(uaP, 1_000, FeeMode.FIXED, 1, POOL, REF);
        vm.expectRevert(IERC20MetaTx.TransferToSelf.selector);
        tok.payWithFeeToUA(uaP, 1_000, FeeMode.FIXED, 1, address(tok), REF);
        vm.stopPrank();
        assertEq(tok.balanceOf(POOL), 0);
    }

    // ----- gas, logged (R5a-13) -----

    /// Gas of one call from `who` measured from a state snapshot, which `revertToState` restores with every account and
    /// slot cold again: each pair below runs from the same state, as two separate transactions would (no intrinsic gas).
    function _gasOf(address who, address target, uint256 value, bytes memory data) internal returns (uint256 g) {
        uint256 snap = vm.snapshotState();
        vm.prank(who);
        g = gasleft();
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        g -= gasleft();
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        vm.revertToState(snap);
    }

    /// The method's own check: the same call twice from one snapshot costs the same (cold both times); a third call
    /// after it, without the revert, is warm and cheaper.
    function test_gas_snapshotRestoresColdAccess() public {
        und.mint(alice, 3_000);
        vm.prank(alice);
        und.approve(address(wrp), 3_000);
        bytes memory data = abi.encodeWithSignature("wrap(address,uint256)", address(und), 1_000);
        uint256 a = _gasOf(alice, address(wrp), 0, data);
        uint256 b = _gasOf(alice, address(wrp), 0, data);
        assertApproxEqAbs(a, b, 10);
        vm.prank(alice);
        wrp.wrap(address(und), 1_000);
        assertLt(_gasOf(alice, address(wrp), 0, data), a - 20_000);
    }

    function _logPair(string memory a, uint256 ga, string memory b, uint256 gb) internal {
        emit log_named_uint(a, ga);
        emit log_named_uint(b, gb);
    }

    /// Each receiver against its address twin from the same state: the receiver slot empty, the payer's balance set.
    function test_gas_receiversVsAddressTwins() public {
        und.mint(alice, 1_000);
        vm.prank(alice);
        und.approve(address(wrp), 1_000);
        vm.deal(alice, 1_000);
        _wrapL(alice, 1_000);
        _logPair("wrap(u, v) ERC-20 leg", _gasOf(alice, address(wrp), 0, abi.encodeWithSignature(
            "wrap(address,uint256)", address(und), 1_000)),
            "wrapToUA ERC-20 leg", _gasOf(alice, address(wrp), 0, abi.encodeCall(WrappedToken.wrapToUA, (address(und), 1_000, uaP))));
        _logPair("wrap(u, v) native leg", _gasOf(alice, address(wrpN), 1_000, abi.encodeWithSignature(
            "wrap(address,uint256)", address(0), 1_000)),
            "wrapToUA native leg", _gasOf(alice, address(wrpN), 1_000, abi.encodeCall(WrappedToken.wrapToUA, (address(0), 1_000, uaP))));
        _logPair("unwrap(u, ...) ledger leg", _gasOf(alice, address(wrpL), 0, abi.encodeWithSignature(
            "unwrap(address,uint256,address,uint256)", address(tok), 1_000, bob, 0)),
            "unwrapToUA ledger leg", _gasOf(alice, address(wrpL), 0, abi.encodeCall(WrappedToken.unwrapToUA, (address(tok), 1_000, uaB, 0))));
        _logPair("payWithFee", _gasOf(alice, address(tok), 0, abi.encodeCall(MetaTokenBase.payWithFee, (bob, 1_000, FeeMode.FIXED, 10, FEE_TO, REF))),
            "payWithFeeToUA", _gasOf(alice, address(tok), 0, abi.encodeCall(MetaTokenBase.payWithFeeToUA, (uaB, 1_000, FeeMode.FIXED, 10, FEE_TO, REF))));
        _logPair("mint", _gasOf(address(this), address(tok), 0, abi.encodeCall(NormalToken.mint, (bob, 1_000))),
            "mintToUA", _gasOf(address(this), address(tok), 0, abi.encodeCall(NormalToken.mintToUA, (uaB, 1_000))));
    }
}
