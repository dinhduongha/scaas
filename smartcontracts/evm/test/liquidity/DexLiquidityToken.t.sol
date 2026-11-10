// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ITradeToken, ILiquidityPullToken} from "../../src/trade/ITradeToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {nid} from "../helpers/Ids.sol";
import {LiquidityBase} from "./LiquidityBase.sol";
import {MockOldDex, MockWrongDex} from "./LiquidityMocks.sol";

/// The token side, `mtxLiquidityPull` (spec 2026-11-10-dex-liquidity.md §5, T1-T10), called by contracts that are not the
/// DEX: the capability check T7 refuses each, and the checks before it name their own error.
contract DexLiquidityTokenTest is LiquidityBase {
    MockWrongDex internal wd;

    function setUp() public override {
        super.setUp();
        wd = new MockWrongDex();
    }

    /// Alice gives up to 1 000 `a`; carol receives `b` (the token reads only its own input).
    function _o() internal view returns (ITradeToken.LiquidityOrder memory o) {
        o = _base();
        o.inputs = _one(_t(address(a), 1_000));
        o.outputs = _one(_t(address(b), 1));
    }

    /// `wd` answers T7 rightly for `o`; alice signs `o` for `wd`.
    function _armed(ITradeToken.LiquidityOrder memory o) internal returns (IUARegistry.UASig memory) {
        wd.set(3, _digestFor(o, address(wd)));
        return _sigFor(o, ALICE_PK, address(wd));
    }

    function _pull(ITradeToken.LiquidityOrder memory o, IUARegistry.UASig memory s, uint256 amount) internal {
        vm.prank(relayer);
        wd.pull(address(a), o, s, amount);
    }

    /// Positive control: a contract answering T7 rightly pulls exactly `amount`, once, into itself.
    function test_T_positive() public {
        ITradeToken.LiquidityOrder memory o = _o();
        IUARegistry.UASig memory s = _armed(o);
        bytes32 h = _digestFor(o, address(wd));
        vm.expectEmit(address(a));
        emit ITradeToken.LiquidityPulled(h, nid(alice), address(wd), 700);
        _pull(o, s, 700);
        assertEq(a.balanceOf(address(wd)), 700);
        assertEq(a.pulled(h), 700);
    }

    function test_T1_caller() public {
        ITradeToken.LiquidityOrder memory o = _o();
        IUARegistry.UASig memory s = _armed(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.DexNotContract.selector, attacker));
        vm.prank(attacker);
        ILiquidityPullToken(address(a)).mtxLiquidityPull(o, s, 1, relayer);
        o.from = nid(address(a));
        s = _armed(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.SelfOrder.selector, _digestFor(o, address(wd))));
        _pull(o, s, 1);
    }

    function test_T2_relayer() public {
        ITradeToken.LiquidityOrder memory o = _o();
        IUARegistry.UASig memory s = _armed(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.WrongRelayer.selector, _digestFor(o, address(wd)), attacker));
        vm.prank(attacker);
        wd.pull(address(a), o, s, 1);
    }

    function test_T3_expiry() public {
        ITradeToken.LiquidityOrder memory o = _o();
        IUARegistry.UASig memory s = _armed(o);
        vm.warp(o.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.OrderExpired.selector, _digestFor(o, address(wd))));
        _pull(o, s, 1);
    }

    /// The token's own order lane (a native signer through the UA form).
    function test_T4_lane() public {
        ITradeToken.LiquidityOrder memory o = _o();
        IUARegistry.UASig memory s = _armed(o);
        IUARegistry.UASig memory inv;
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(ALICE_PK, a.invalidateNoncesDigest(nid(alice), 7, 1));
        inv.signature = abi.encodePacked(r, ss, v);
        a.mtxInvalidateNonces(nid(alice), 7, 1, inv);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NonceInvalidated.selector, _digestFor(o, address(wd))));
        _pull(o, s, 1);
        o.nonce = 2 ** 128;
        s = _armed(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NonceAboveCap.selector, _digestFor(o, address(wd))));
        _pull(o, s, 1);
    }

    function test_T5_oneInput() public {
        ITradeToken.LiquidityOrder memory o = _o();
        o.inputs = _one(_t(address(b), 1_000)); // not an input
        IUARegistry.UASig memory s = _armed(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.LiquidityShape.selector, 6));
        _pull(o, s, 1);
        o.inputs = _two(_t(address(a), 1_000), _t(address(a), 1_000)); // twice
        s = _armed(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.LiquidityShape.selector, 6));
        _pull(o, s, 1);
    }

    function test_T6_amount() public {
        ITradeToken.LiquidityOrder memory o = _o();
        IUARegistry.UASig memory s = _armed(o);
        bytes32 h = _digestFor(o, address(wd));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.ZeroFill.selector, h));
        _pull(o, s, 0);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.Overfill.selector, h));
        _pull(o, s, 1_001);
    }

    /// A DEX release before the spec (no `liquidityOrderDigest`) runs an interaction-style pull of an order signed for it,
    /// then would move the tokens to the attacker: T7 refuses (review P1-2).
    function test_T7_oldDex() public {
        MockOldDex old = new MockOldDex();
        ITradeToken.LiquidityOrder memory o = _o();
        IUARegistry.UASig memory s = _sigFor(o, ALICE_PK, address(old));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotLiquidityDex.selector, address(old)));
        vm.prank(relayer);
        old.run(address(a), o, s, 1_000, attacker);
        assertEq(a.balanceOf(attacker), 0);
    }

    function test_T7_wrongAnswers() public {
        ITradeToken.LiquidityOrder memory o = _o();
        IUARegistry.UASig memory s = _sigFor(o, ALICE_PK, address(wd));
        for (uint8 m = 1; m <= 2; ++m) {
            wd.set(m, 0); // another word; a short return
            vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotLiquidityDex.selector, address(wd)));
            _pull(o, s, 1);
        }
    }

    /// The signature over the token's own `h`: one signed for the real DEX does not serve `wd` (another verifyingContract).
    function test_T8_signatureOwnDigest() public {
        ITradeToken.LiquidityOrder memory o = _o();
        _armed(o);
        IUARegistry.UASig memory forDex = _sig(o, ALICE_PK);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _pull(o, forDex, 1);
    }

    function test_T9_oneShot() public {
        ITradeToken.LiquidityOrder memory o = _o();
        IUARegistry.UASig memory s = _armed(o);
        _pull(o, s, 1);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.OrderClosed.selector, _digestFor(o, address(wd))));
        _pull(o, s, 1);
    }

    /// No transient pull counter: `restorePulled` from the same caller after a liquidity pull restores nothing.
    function test_T10_noRestore() public {
        ITradeToken.LiquidityOrder memory o = _o();
        IUARegistry.UASig memory s = _armed(o);
        _pull(o, s, 700);
        ITradeToken.UATradeOrder memory t;
        t.from = nid(alice);
        t.dex = address(wd);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.RestoreExceedsPull.selector, a.tradeOrderDigest(t)));
        vm.prank(address(wd));
        a.restorePulled(t, 1);
    }

    /// `mtxLiquidityPull` is on no allowlist (`mtxSelectors`), so `mtxExecute` cannot self-call it.
    function test_T_notAllowlisted() public view {
        (bytes4[] memory sels,,) = a.mtxSelectors();
        for (uint256 i; i < sels.length; ++i) assertTrue(sels[i] != ILiquidityPullToken.mtxLiquidityPull.selector);
        assertTrue(UAKinds.inNativeSpace(nid(alice)));
    }
}
