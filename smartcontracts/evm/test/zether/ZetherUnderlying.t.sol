// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

/// A leg that calls back into the token when the token pays it out or pulls it (an ERC-777-style hook).
contract HookLeg is MockERC20 {
    address public target;
    bytes public payload;

    constructor() MockERC20("Hook", "HOOK", 6) {}

    function arm(address t, bytes calldata p) external {
        target = t;
        payload = p;
    }

    function _update(address from, address to, uint256 v) internal override {
        super._update(from, to, v);
        if (target != address(0) && (from == target || to == target)) {
            (bool ok, bytes memory ret) = target.call(payload);
            if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
        }
    }
}

/// @notice Kind `UNDERLYING_ZETHER` (CTR-ZTH-44/45): the legs' underlying straight into a shielded balance and back,
///         nothing minted either way; the reserve invariant counts the shielded value; `mtxWrap`, the native leg, the
///         direct unshield-unwrap binding its leg and `minOut`, relaying, re-entry.
/// A native-leg recipient: re-enters the token from `receive()`, or refuses the coin.
contract NativeRecipient {
    address t;
    bytes p;
    bool refuse;

    function arm(address t_, bytes memory p_, bool refuse_) external {
        (t, p, refuse) = (t_, p_, refuse_);
    }

    receive() external payable {
        require(!refuse, "refused");
        if (t != address(0)) {
            (bool ok, bytes memory ret) = t.call(p);
            if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        }
    }
}

contract ZetherUnderlyingTest is ZetherFixture {
    UnderlyingZetherToken internal undImpl;
    UnderlyingZetherToken internal w;
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);
    MockERC20 internal eur = new MockERC20("EUR", "EUR", 6);
    uint256 constant PAYER_PK = 0x9A7E5;
    address payer = vm.addr(PAYER_PK);
    bytes32 internal signer; // a SIGNING UA, receiver of `wrapToUA`

    function setUp() public {
        _stack(false);
        undImpl = new UnderlyingZetherToken(address(factory), address(0), ZUID, address(reg), dis);
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, address(undImpl));
        address[] memory legs = new address[](2);
        (legs[0], legs[1]) = (address(usd), address(eur));
        uint256[] memory nums = new uint256[](2);
        (nums[0], nums[1]) = (1, 2); // 1 EUR raw = 2 public units
        w = _wrapper(legs, nums, _ones(2), "zw", true);
        tok = ZetherLayer(address(w));
        _users();
    }

    function _ones(uint256 n) internal pure returns (uint256[] memory o) {
        o = new uint256[](n);
        for (uint256 i; i < n; ++i) o[i] = 1;
    }

    /// `PAYABLE | RATE_ADJUSTABLE | WRAP_DISABLEABLE`; the test is owner, rate admin (a contract) and guardian.
    function _wrapper(address[] memory legs, uint256[] memory nums, uint256[] memory dens, bytes32 salt, bool auditor)
        internal returns (UnderlyingZetherToken)
    {
        IFactoryToken.TokenConfig memory c;
        c.name = "Zether wrapped";
        c.symbol = "zW";
        c.decimals = 6;
        c.features = (1 << AdminLib.PAYABLE) | (1 << AdminLib.RATE_ADJUSTABLE) | (1 << AdminLib.WRAP_DISABLEABLE);
        c.owner = address(this);
        c.roles.rateAdmin = address(this);
        c.roles.guardian = address(this);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        c.legs = new IFactoryToken.Leg[](legs.length);
        for (uint256 i; i < legs.length; ++i) c.legs[i] = IFactoryToken.Leg(legs[i], nums[i], dens[i]);
        c.conf = IFactoryToken.ConfidentialConfig(
            address(ver), auditor ? ZetherKeys.pub(X_AUD, false) : bytes(""), SCALE, uint256(1) << 40, FEE, dMode,
            auditor ? aMode : 0
        );
        return UnderlyingZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, salt)));
    }

    /// Public units by a 1:1 USD wrap.
    function _public(ZetherLayer t, address to, uint256 units) internal override {
        usd.mint(address(this), units);
        usd.approve(address(t), units);
        UnderlyingToken(payable(address(t))).wrap(address(usd), units);
        if (to != address(this)) t.transfer(to, units);
        minted[address(t)] += units;
    }

    /// The reserve invariant (CTR-ZTH-44) and Σ plaintext == totalShielded.
    function _assertConservation(ZetherLayer t, uint256 max) internal view override {
        User[3] memory us = [alice, bob, carol];
        uint256 sum;
        for (uint256 i; i < 3; ++i) {
            (uint256 a, uint256 p) = _balances(t, us[i], max);
            sum += a + p;
        }
        assertEq(sum, t.totalShielded(), "sum of plaintext balances == totalShielded");
        UnderlyingToken u = UnderlyingToken(payable(address(t)));
        assertGe(u.collateralValue(), t.totalSupply() + t.totalShielded() * SCALE, "reserve invariant");
    }

    function _wrapShield(MockERC20 leg, uint256 amountIn, User memory to) internal {
        leg.mint(address(this), amountIn);
        leg.approve(address(w), amountIn);
        w.zetherWrapShield(address(leg), amountIn, to.ua);
    }

    function _reserve(address leg) internal view returns (uint256 r) {
        (,, r,,) = w.legOf(leg);
    }

    // ------------------------------------------------------------------ wrap-shield

    function test_wrapShield_creditsShieldedUnits_mintsNothing() public {
        usd.mint(address(this), 30 * SCALE);
        usd.approve(address(w), 30 * SCALE);
        vm.expectEmit(true, false, false, true, address(w));
        emit IZetherToken.ZetherShielded(alice.ua, 30);
        w.zetherWrapShield(address(usd), 30 * SCALE, alice.ua);
        assertEq(w.totalSupply(), 0, "nothing minted");
        assertEq(w.totalShielded(), 30);
        assertEq(_reserve(address(usd)), 30 * SCALE);
        assertTrue(_holds(tok, alice, 30, false));
        // the EUR leg at 2 public units per raw unit: 5·SCALE EUR = 10 shielded units
        _wrapShield(eur, 5 * SCALE, bob);
        assertTrue(_holds(tok, bob, 10, false));
        assertEq(w.totalShielded(), 40);
        assertEq(w.collateralValue(), 40 * SCALE);
        _assertConservation(tok, 100);
    }

    function test_wrapShield_refusals() public {
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), 100 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountNotScaled.selector, 30 * SCALE + 1, SCALE));
        w.zetherWrapShield(address(usd), 30 * SCALE + 1, alice.ua);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnknownUnderlying.selector, address(0xDEAD)));
        w.zetherWrapShield(address(0xDEAD), SCALE, alice.ua);
        ZetherTypes.UA ghost = ZetherTypes.toUA(ZetherKeys.pub(0x6057, false));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ghost));
        w.zetherWrapShield(address(usd), SCALE, ghost);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 1, 0));
        w.zetherWrapShield{value: 1}(address(usd), SCALE, alice.ua);
        // a disabled leg (guardian, one-way) and a pending rate change pause the inflow
        w.disableWrap(address(eur), "depeg");
        eur.mint(address(this), SCALE);
        eur.approve(address(w), SCALE);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapDisabledFor.selector, address(eur)));
        w.zetherWrapShield(address(eur), SCALE, alice.ua);
        w.proposeRate(address(usd), 11, 10);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapPausedForRateChange.selector, address(usd)));
        w.zetherWrapShield(address(usd), SCALE, alice.ua);
        w.cancelRate();
        // the cap
        UnderlyingZetherToken small = _small();
        usd.mint(address(this), 101 * SCALE);
        usd.approve(address(small), 101 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 101, 100));
        small.zetherWrapShield(address(usd), 101 * SCALE, alice.ua);
    }

    /// One USD leg 1:1, cap 100.
    function _small() internal returns (UnderlyingZetherToken z) {
        IFactoryToken.TokenConfig memory c;
        c.name = "S";
        c.symbol = "S";
        c.decimals = 6;
        c.features = (1 << AdminLib.PAYABLE) | (1 << AdminLib.RATE_ADJUSTABLE);
        c.roles.rateAdmin = address(this);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, 100, FEE, 0, 0);
        z = UnderlyingZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "small")));
    }

    // ------------------------------------------------------------------ unshield-unwrap

    function _shielded(uint256 usdUnits, uint256 eurRaw) internal {
        if (usdUnits != 0) _wrapShield(usd, usdUnits * SCALE, alice);
        if (eurRaw != 0) _wrapShield(eur, eurRaw, alice);
        tok.zetherRollOver(alice.ua);
    }

    function _unwrapProof(uint256 amount, uint256 b, address recipient, address u, uint256 minOut, bytes32 envB)
        internal view returns (bytes memory pl, bytes memory pr)
    {
        pl = _unshieldPayload(tok, alice);
        bytes memory st = stm.unshieldUnwrapStatement(address(w), pl, amount, recipient, _none(), u, minOut, envB);
        pr = _proveU(alice, st, amount, b, _none(), tok);
    }

    function test_unshieldUnwrap_paysTheLeg_mintsNothing() public {
        _shielded(60, 40 * SCALE); // 60 + 80 shielded
        (bytes memory pl, bytes memory pr) = _unwrapProof(40, 140, address(0xD00D), address(eur), 20 * SCALE, 0);
        vm.expectEmit(true, false, false, true, address(w));
        emit IZetherToken.ZetherUnshielded(alice.ua, 40, address(0xD00D));
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(eur), address(0xD00D), 40, 20 * SCALE);
        assertEq(eur.balanceOf(address(0xD00D)), 20 * SCALE, "40 units at 2 per raw EUR");
        assertEq(_reserve(address(eur)), 20 * SCALE);
        assertEq(w.totalSupply(), 0, "nothing minted");
        assertEq(w.totalShielded(), 100);
        assertTrue(_holds(tok, alice, 100, true));
        // the USD leg, 1:1
        (pl, pr) = _unwrapProof(60, 100, address(0xD00D), address(usd), 0, 0);
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(0xD00D), 60, 0);
        assertEq(usd.balanceOf(address(0xD00D)), 60 * SCALE);
        _assertConservation(tok, 200);
    }

    function test_unshieldUnwrap_refusals() public {
        _shielded(10, 0);
        // more than the leg's reserve: EUR holds nothing
        (bytes memory pl, bytes memory pr) = _unwrapProof(10, 10, address(0xD00D), address(eur), 0, 0);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.InsufficientReserve.selector, address(eur), 5 * SCALE, 0));
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(eur), address(0xD00D), 10, 0);
        // minOut above what the leg pays
        (pl, pr) = _unwrapProof(10, 10, address(0xD00D), address(usd), 10 * SCALE + 1, 0);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnwrapBelowMin.selector, 10 * SCALE, 10 * SCALE + 1));
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(0xD00D), 10, 10 * SCALE + 1);
        // the token itself as recipient
        (pl, pr) = _unwrapProof(10, 10, address(w), address(usd), 0, 0);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnwrapRecipientInvalid.selector, address(w)));
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(w), 10, 0);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnknownUnderlying.selector, address(0xDEAD)));
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(0xDEAD), address(w), 10, 0);
    }

    /// A direct proof binds the leg and `minOut` (controller ruling, pending the owner): copied from a pending call it
    /// cannot pick another leg, drop `minOut`, or go through `zetherUnshield`; a plain unshield proof does not fit here.
    function test_unshieldUnwrap_directProofBindsLegAndMinOut() public {
        _shielded(30, 30 * SCALE);
        (bytes memory pl, bytes memory pr) = _unwrapProof(10, 90, address(0xD00D), address(usd), 10 * SCALE, 0);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(eur), address(0xD00D), 10, 5 * SCALE); // other leg
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(0xD00D), 10, 0); // minOut dropped
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        w.zetherUnshield(pl, pr, "", _none(), address(0xD00D), 10); // into public units instead
        (bytes memory pl2, bytes memory pr2) = _proveUnshield(tok, alice, 10, 90, address(0xD00D), _none(), 0);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        w.zetherUnshieldUnwrap(pl2, pr2, "", _none(), address(usd), address(0xD00D), 10, 0);
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(0xD00D), 10, 10 * SCALE);
        assertEq(stm.unwrapBinding(address(usd), 10 * SCALE),
            keccak256(abi.encode(keccak256("SCAAS-ZETHER-UNWRAP-V1"), address(usd), 10 * SCALE)));
    }

    /// Relayed: the envelope binding; the signer's signature covers the leg and `minOut` (they are in `data`).
    function test_unshieldUnwrap_relayed() public {
        _shielded(30, 0);
        _public(tok, payer, 100);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: payer, data: "", batch: 1, nonce: 0, validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED, relayer: relayer, fee: 9,
            feeRecipient: address(0)
        });
        (bytes memory pl, bytes memory pr) = _unwrapProof(10, 30, address(0xB0C), address(usd), 0, w.envelopeBinding(m));
        m.data = abi.encodeCall(UnderlyingZetherToken.zetherUnshieldUnwrap,
            (pl, pr, bytes(""), _none(), address(usd), address(0xB0C), 10, 0));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, w.mtxDigest(m));
        bytes memory sig = abi.encodePacked(r, s, v);
        vm.expectRevert(IZetherToken.ProofRejected.selector); // lifted out: the direct binding differs
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(0xB0C), 10, 0);
        vm.prank(relayer);
        w.mtxExecute(m, sig);
        assertEq(usd.balanceOf(address(0xB0C)), 10 * SCALE);
        assertEq(w.balanceOf(relayer), 9);
        assertTrue(_holds(tok, alice, 20, true));
    }

    // ------------------------------------------------------------------ disclosure carried over (CTR-ZTH-40/43)

    /// The disclosure reads (`disclosure()`, `transferEntry`, `auditorKey()`, `verifier()`, `chainUid()`) work on kind 3
    /// as on kind 2: every opening of a transfer opens through the canonical `ZetherDisclosure`.
    function test_disclosureOnTheUnderlyingKind() public {
        _shielded(50, 0);
        Tx memory t = _proveTransfer(tok, alice, bob, 21, 50, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        assertEq(address(w.disclosure()), address(dis));
        assertEq(w.auditorKey(), ZetherKeys.pub(X_AUD, false));
        assertEq(w.transferEntry(ref).length, 16 + 4 * 64, "the single format stores R = salt, then B");
        (bytes memory ct,) = dis.transferCiphertext(address(w), ref, 0, "");
        bytes memory dOut = new bytes(64);
        for (uint256 i; i < 64; ++i) dOut[i] = ct[64 + i];
        assertTrue(_vta(tok, ref, 0, 21, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), ""));
        assertTrue(_vta(tok, ref, 0, 21, ITransferDisclosure.OpeningKind.RECEIVER_X,
            _cpOpening(tok, bob.x, ref, 0, 21, ITransferDisclosure.OpeningKind.RECEIVER_X, dOut), ""));
        assertTrue(_vta(tok, ref, 0, 21, ITransferDisclosure.OpeningKind.AUDITOR,
            _cpOpening(tok, X_AUD, ref, 0, 21, ITransferDisclosure.OpeningKind.AUDITOR, dOut), ""));
        assertTrue(_vta(tok, ref, 0, 21, ITransferDisclosure.OpeningKind.SENDER_CP,
            _cpOpening(tok, t.s, ref, 0, 21, ITransferDisclosure.OpeningKind.SENDER_CP, bob.y), ""));
        assertFalse(_vta(tok, ref, 0, 22, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), ""));
    }

    // ------------------------------------------------------------------ reserve invariant (CTR-ZTH-44)

    /// A rate decrease that the public supply alone would allow, but the shielded value would not.
    function test_executeRate_countsTheShieldedValue() public {
        UnderlyingZetherToken z = _small();
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(z), 100 * SCALE);
        z.zetherWrapShield(address(usd), 100 * SCALE, alice.ua);
        assertEq(z.totalSupply(), 0);
        z.proposeRate(address(usd), 9, 10);
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.RateChangeUndercollateralized.selector, 90 * SCALE,
            100 * SCALE));
        z.executeRate();
    }

    /// The kind's own flag rules (CTR-ZTH-47) and `disableFeature(RATE_ADJUSTABLE)` cancelling a pending change
    /// (CTR-TOK-06), restated on this kind.
    function test_kindFlags_andDisableFeatureCancelsAPendingRate() public {
        w.proposeRate(address(usd), 11, 10);
        (address pu,,,) = w.pendingRate();
        assertEq(pu, address(usd));
        w.disableFeature(AdminLib.RATE_ADJUSTABLE);
        (pu,,,) = w.pendingRate();
        assertEq(pu, address(0), "the pending change is gone");
        assertFalse(w.rateAdjustable());
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("F", "F", 6, 1 << AdminLib.FREEZE);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, 100, FEE, 0, 0);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.FREEZE));
        factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "freeze");
        c.features = 1 << AdminLib.MINTABLE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.MINTABLE));
        factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "mint");
        // `initialSupply` / `initialHolder` are the `NONE*` kinds' (CTR-TOK-25): refused, never silently ignored
        c.features = 0;
        c.initialSupply = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 1));
        factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "supply");
        (c.initialSupply, c.initialHolder) = (0, address(this));
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 1));
        factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "holder");
    }

    // ------------------------------------------------------------------ mtxWrap and shield, gasless (CTR-TOK-20, MT-3)

    /// An EOA holding a SCaaS underlying cannot approve (CTR-TOK-01): it wraps by signature (`mtxWrap`, inherited) and
    /// shields through `mtxExecute`, paying no gas.
    function test_mtxWrapThenRelayedShield_noApproveAnywhere() public {
        NoUnderlyingToken pImpl = new NoUnderlyingToken(address(factory), address(0), ZUID, address(0), false);
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.NONE, 1, address(pImpl));
        IFactoryToken.TokenConfig memory pc;
        (pc.name, pc.symbol, pc.decimals, pc.features) = ("Points", "PTS", 6, 1 << AdminLib.PAYABLE);
        (pc.initialSupply, pc.initialHolder) = (50 * SCALE, payer);
        NoUnderlyingToken pts = NoUnderlyingToken(factory.createToken(IOpenFactory.TokenKind.NONE, 1, pc, "pts"));
        address[] memory legs = new address[](1);
        legs[0] = address(pts);
        UnderlyingZetherToken z = _wrapper(legs, _ones(1), _ones(1), "zpts", false);
        ITradeToken.TradeOrder memory o;
        (o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.dex) =
            (payer, address(z), 20 * SCALE, 20 * SCALE, 20 * SCALE, address(z));
        (o.batch, o.nonce, o.validUntil) = (7, 1, block.timestamp + 300);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, pts.tradeOrderDigest(o));
        bytes memory sig = abi.encodePacked(r, s, v);
        vm.prank(relayer);
        z.mtxWrap(address(pts), o, sig);
        assertEq(z.balanceOf(payer), 20 * SCALE);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: payer, data: abi.encodeCall(ZetherLayer.zetherShield, (bob.y, 20)), batch: 2, nonce: 0,
            validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: relayer, fee: 0,
            feeRecipient: address(0)
        });
        (v, r, s) = vm.sign(PAYER_PK, z.mtxDigest(m));
        sig = abi.encodePacked(r, s, v);
        vm.prank(relayer);
        z.mtxExecute(m, sig);
        assertEq(z.balanceOf(payer), 0);
        assertEq(z.totalShielded(), 20);
        assertEq(pts.allowance(payer, address(z)), 0);
    }

    // ------------------------------------------------------------------ the native leg (CTR-TOK-26)

    function test_nativeLeg_wrapShieldPayable_notGasless() public {
        address[] memory legs = new address[](1);
        uint256[] memory dens = new uint256[](1);
        dens[0] = 1e12; // 1e12 wei = 1 public unit
        UnderlyingZetherToken z = _wrapper(legs, _ones(1), dens, "native", false);
        vm.deal(address(this), 1 ether);
        z.zetherWrapShield{value: 3e16}(address(0), 3e16, alice.ua);
        assertEq(z.totalShielded(), 3);
        assertEq(address(z).balance, 3e16);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 0, 3e16));
        z.zetherWrapShield(address(0), 3e16, alice.ua);
    }

    /// The native leg's unshield-unwrap payout (review T5 m3): a recipient re-entering from `receive()` hits the guard,
    /// a refusing one reverts the whole call with nothing debited, an accepting one is paid exactly.
    function test_nativeLeg_unshieldUnwrapPayout() public {
        address[] memory legs = new address[](1);
        uint256[] memory dens = new uint256[](1);
        dens[0] = 1e12;
        UnderlyingZetherToken z = _wrapper(legs, _ones(1), dens, "native2", false);
        ZetherLayer zt = ZetherLayer(address(z));
        vm.deal(address(this), 1 ether);
        z.zetherWrapShield{value: 3e16}(address(0), 3e16, alice.ua); // 1 shielded unit = SCALE·1e12 wei
        zt.zetherRollOver(alice.ua);
        NativeRecipient rc = new NativeRecipient();
        bytes memory pl = _unshieldPayload(zt, alice);
        bytes memory st = stm.unshieldUnwrapStatement(address(z), pl, 2, address(rc), _none(), address(0), 0, 0);
        bytes memory pr = _proveU(alice, st, 2, 3, _none(), zt);
        rc.arm(address(z), abi.encodeCall(ZetherLayer.zetherRollOver, (bob.ua)), false);
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        z.zetherUnshieldUnwrap(pl, pr, "", _none(), address(0), address(rc), 2, 0);
        rc.arm(address(0), "", true);
        vm.expectRevert();
        z.zetherUnshieldUnwrap(pl, pr, "", _none(), address(0), address(rc), 2, 0);
        assertEq(z.totalShielded(), 3, "nothing debited");
        rc.arm(address(0), "", false);
        z.zetherUnshieldUnwrap(pl, pr, "", _none(), address(0), address(rc), 2, 0);
        assertEq(address(rc).balance, 2e16);
        assertEq(address(z).balance, 1e16);
        (,, uint256 res,,) = z.legOf(address(0));
        assertEq(res, 1e16);
        assertEq(z.totalShielded(), 1);
    }

    // ------------------------------------------------------------------ re-entry and the allowlist

    /// A hook leg that calls the token back mid-payout or mid-pull hits the contract-wide guard.
    function test_reentryThroughAHookLegRefused() public {
        HookLeg hook = new HookLeg();
        address[] memory legs = new address[](1);
        legs[0] = address(hook);
        UnderlyingZetherToken z = _wrapper(legs, _ones(1), _ones(1), "hook", false);
        hook.mint(address(this), 50 * SCALE);
        hook.approve(address(z), 50 * SCALE);
        z.zetherWrapShield(address(hook), 30 * SCALE, alice.ua);
        z.zetherRollOver(alice.ua);
        hook.arm(address(z), abi.encodeCall(ZetherLayer.zetherRollOver, (bob.ua)));
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        z.zetherWrapShield(address(hook), SCALE, alice.ua);
        bytes memory pl = _unshieldPayload(ZetherLayer(address(z)), alice);
        bytes memory st = stm.unshieldUnwrapStatement(address(z), pl, 10, address(0xD00D), _none(), address(hook), 0, 0);
        bytes memory pr = _proveU(alice, st, 10, 30, _none(), ZetherLayer(address(z)));
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        z.zetherUnshieldUnwrap(pl, pr, "", _none(), address(hook), address(0xD00D), 10, 0);
        hook.arm(address(0), "");
        z.zetherUnshieldUnwrap(pl, pr, "", _none(), address(hook), address(0xD00D), 10, 0);
        assertEq(hook.balanceOf(address(0xD00D)), 10 * SCALE);
    }

    function test_allowlistPinned_underlyingZether() public {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = w.mtxSelectors();
        assertEq(s.length, 16);
        assertEq(s[12], UnderlyingZetherToken.zetherWrapShield.selector);
        assertEq(s[13], UnderlyingZetherToken.zetherUnshieldUnwrap.selector);
        assertEq(s[14], UnderlyingToken.wrapToUA.selector);
        assertEq(s[15], UnderlyingToken.unwrapToUA.selector);
        assertEq(c[14], 1, "wrapToUA ABSOLUTE");
        assertEq(a[14], 0);
        assertEq(c[15], 2, "unwrapToUA AMOUNT(1)");
        assertEq(a[15], 1);
        assertEq(s[6], ZetherLayer.zetherShield.selector);
        assertEq(s[7], ZetherLayer.zetherTransfer.selector);
        assertEq(s[8], ZetherLayer.zetherTransferCompact.selector);
        assertEq(s[9], ZetherLayer.zetherTransferNoBundle.selector);
        assertEq(s[10], ZetherLayer.zetherTransferSingle.selector);
        assertEq(s[11], ZetherLayer.zetherUnshield.selector);
        for (uint256 i = 6; i < 14; ++i) {
            assertEq(c[i], 1, "ABSOLUTE");
            assertEq(a[i], 0);
        }
        assertEq(c[4], 2);
        assertEq(a[4], 1, "unwrap(address,uint256,address,uint256) AMOUNT(1) as on UNDERLYING");
        // the static shape of wrap-shield is pinned: a longer `data` is refused at step 3
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: payer, data: bytes.concat(abi.encodeCall(UnderlyingZetherToken.zetherWrapShield,
                (address(usd), SCALE, alice.ua)), hex"00"), batch: 1, nonce: 0, validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(PAYER_PK, w.mtxDigest(m));
        bytes memory sig = abi.encodePacked(r, sg, v);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, UnderlyingZetherToken.zetherWrapShield.selector));
        w.mtxExecute(m, sig);
        assertEq(w.kind(), AdminLib.KIND_UNDERLYING_ZETHER);
        (, string memory n,,,,,) = w.eip712Domain();
        assertEq(n, "SCaaS ZetherToken");
    }

    /// Relay `data` on lane `batch`; `err` non-empty: expect that revert.
    function _relay(bytes memory data, uint256 batch, bytes memory err) internal {
        MetaTxLib.MetaTransaction memory m = _envOf(batch);
        m.data = data;
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(PAYER_PK, w.mtxDigest(m));
        vm.prank(relayer);
        if (err.length != 0) vm.expectRevert(err);
        w.mtxExecute(m, abi.encodePacked(r, sg, v));
    }

    /// K6 and CTR-MTX-19 on kind 3 (review T5 m2): `_mtxRule` refuses these inside `mtxExecute`, not only the view.
    function test_allowlistRefusals_underlyingZether() public {
        bytes[9] memory refused = [
            abi.encodeWithSignature("unwrap(uint256,address)", 1, payer),
            abi.encodeWithSignature("proposeRate(address,uint96,uint96)", address(usd), 1, 1),
            abi.encodeWithSignature("cancelRate()"),
            abi.encodeWithSignature("executeRate()"),
            abi.encodeWithSignature("disableWrap(address,bytes32)", address(usd), bytes32(0)),
            abi.encodeCall(ZetherLayer.zetherRollOver, (alice.ua)),
            abi.encodeCall(ZetherLayer.zetherRollOverSigned, (alice.ua, 1, 1, bytes(""))),
            abi.encodeCall(ZetherLayer.zetherSetRollOverMode, (alice.ua, ZetherTypes.RollOverMode.PUBLIC, 1, bytes(""))),
            abi.encodeWithSelector(IUnderlyingToken.mtxWrap.selector)
        ];
        for (uint256 i; i < refused.length; ++i) {
            _relay(refused[i], 100 + i, abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(refused[i])));
        }
    }

    /// A registered SIGNING UA (`schnorr-bn254`) for `wrapToUA` (CTR-UA-28).
    function _signingUA() internal returns (bytes32 ua) {
        bytes memory y = ZetherKeys.pub(0xA07, false);
        ua = UAKinds.uaOf(UAKinds.SCHNORR_BN254, y);
        bytes32 m = reg.uaMessage(UAKinds.SCHNORR_BN254, UAKinds.PURPOSE_POP, reg.popDigest(ua, 0));
        reg.register(UAKinds.SCHNORR_BN254, y, ZetherKeys.sign("scaas.ua.schnorr.v1", 0xA07, m, false), 0, "");
    }

    /// Every selector kind 3 publishes runs relayed once (review T4 I1). On this two-leg token the two single-asset
    /// entries reach the call and revert `UnderlyingRequired`, and `unwrapToUA` reverts `UALegNotLedger` (its legs are
    /// outside tokens): the rule let them through.
    function test_everyListedSelectorRuns_underlyingZether() public {
        _shielded(70, 0);
        _public(tok, payer, 100 * SCALE);
        usd.mint(payer, 100 * SCALE);
        vm.prank(payer);
        usd.approve(address(w), type(uint256).max);
        (bytes4[] memory s,,) = w.mtxSelectors();
        assertEq(s.length, 16);
        signer = _signingUA();
        uint256 bal = 70;
        for (uint256 i; i < s.length; ++i) {
            bytes memory data = _k3Call(s[i], bal, w.envelopeBinding(_envOf(300 + i)));
            uint256 sc = w.accountState(alice.ua).sendCounter;
            bool single = s[i] == bytes4(keccak256("wrap(uint256)")) || s[i] == bytes4(keccak256("unwrap(uint256,address,uint256)"));
            bytes memory err = single ? abi.encodeWithSelector(IUnderlyingToken.UnderlyingRequired.selector) : bytes("");
            if (s[i] == UnderlyingToken.unwrapToUA.selector) {
                err = abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(usd));
            }
            _relay(data, 300 + i, err);
            if (w.accountState(alice.ua).sendCounter != sc) bal -= 10;
        }
        assertEq(w.balanceOfUA(signer), SCALE, "wrapToUA");
        assertEq(bal, 10, "four transfers, an unshield, an unshield-unwrap");
        assertTrue(_holds(tok, alice, 10, true));
        assertTrue(_holds(tok, bob, 3 + 4 * 10 + 1, false), "shield; transfers; wrap-shield");
        assertEq(w.mtxNonce(payer, 55), 1, "cancelNonce");
        assertEq(w.balanceOf(payer), (100 + 10 - 5 - 3) * SCALE, "wrap; unwrap; shield");
        assertEq(usd.balanceOf(payer), (100 - 10 + 5 - 1 - 1 - 1) * SCALE, "wrap; unwrap; wrap-shield; addReserve; wrapToUA");
        assertEq(w.balanceOf(address(0xB0C)), 10 * SCALE, "unshield");
        assertEq(usd.balanceOf(address(0xB0C)), 10 * SCALE, "unshield-unwrap");
    }

    /// The envelope `_relay` signs on lane `batch`, without `data` (which the binding leaves out).
    function _envOf(uint256 batch) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m = MetaTxLib.MetaTransaction({
            from: payer, data: "", batch: batch, nonce: 0, validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
    }

    function _k3Call(bytes4 sel, uint256 bal, bytes32 b) internal view returns (bytes memory) {
        if (sel == IMetaTx.cancelNonce.selector) return abi.encodeCall(IMetaTx.cancelNonce, (55));
        if (sel == bytes4(keccak256("wrap(uint256)"))) return abi.encodeWithSignature("wrap(uint256)", SCALE);
        if (sel == bytes4(keccak256("unwrap(uint256,address,uint256)"))) {
            return abi.encodeWithSignature("unwrap(uint256,address,uint256)", SCALE, payer, SCALE);
        }
        if (sel == bytes4(keccak256("wrap(address,uint256)"))) {
            return abi.encodeWithSignature("wrap(address,uint256)", address(usd), 10 * SCALE);
        }
        if (sel == bytes4(keccak256("unwrap(address,uint256,address,uint256)"))) {
            return abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(usd), 5 * SCALE, payer, 0);
        }
        if (sel == bytes4(keccak256("addReserve(address,uint256)"))) {
            return abi.encodeWithSignature("addReserve(address,uint256)", address(usd), SCALE);
        }
        if (sel == UnderlyingToken.wrapToUA.selector) return abi.encodeCall(UnderlyingToken.wrapToUA, (address(usd), SCALE, signer));
        if (sel == UnderlyingToken.unwrapToUA.selector) {
            return abi.encodeCall(UnderlyingToken.unwrapToUA, (address(usd), SCALE, signer, 0));
        }
        if (sel == UnderlyingZetherToken.zetherWrapShield.selector) {
            return abi.encodeCall(UnderlyingZetherToken.zetherWrapShield, (address(usd), SCALE, bob.ua));
        }
        if (sel == UnderlyingZetherToken.zetherUnshieldUnwrap.selector) {
            (bytes memory pl, bytes memory pr) = _unwrapProof(10, bal, address(0xB0C), address(usd), 0, b);
            return abi.encodeCall(UnderlyingZetherToken.zetherUnshieldUnwrap,
                (pl, pr, bytes(""), _none(), address(usd), address(0xB0C), 10, 0));
        }
        return _zetherOpCall(sel, bal, b);
    }
}
