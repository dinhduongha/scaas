// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken, ILiquidityPullToken} from "../../src/trade/ITradeToken.sol";
import {SCaaSDexLiquidityModule} from "../../src/dex/SCaaSDexLiquidityModule.sol";
import {V4PositionReader} from "../../src/dex/V4PositionReader.sol";
import {FeeOnTransferERC20, MockERC20} from "../helpers/Mocks.sol";
import {nid} from "../helpers/Ids.sol";
import {LiquidityBase} from "./LiquidityBase.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MockV2LiquidityPair, MockPositionManagerV4, MockDistributor, MockShortReader, MockStickyPositions,
    MockReenter, MockFixedReader, MockSwap, MockDigestProbe} from "./LiquidityMocks.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";

/// `mtxLiquidity` (CTR-DEX-30, -31; spec 2026-11-10-dex-liquidity.md §6, §7, §14): the positive controls of §7.2 and the
/// negatives L1-L37, each one change from a positive control.
contract DexLiquidityTest is LiquidityBase {
    // ------------------------------------------------------------------ positive controls

    /// v2-style add, two SCaaS inputs, a native EOA, fee 0.3 % split 20 / 80, LP to carol.
    function test_v2Add() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        bytes32 h = dex.liquidityOrderDigest(p.order);
        uint256 fee = (LP_FIRST * 3_000 + 999_999) / 1_000_000; // 297
        vm.expectEmit(address(dex));
        emit ISCaaSDex.LiquiditySettled("liq", h, nid(alice), nid(carol), _u2(ADD, ADD), _u2(0, 0), _u(LP_FIRST - fee),
            _u(fee), 0, 0);
        _run(p, _addXs(ADD, ADD, address(dex)));
        assertEq(pair.balanceOf(carol), LP_FIRST - fee);
        assertEq(pair.balanceOf(relayer), fee * 200_000 / 1_000_000);
        assertEq(pair.balanceOf(treasury), fee - fee * 200_000 / 1_000_000);
        assertEq(pair.balanceOf(address(dex)), 0);
        assertEq(a.balanceOf(address(dex)) + b.balanceOf(address(dex)), 0);
        assertEq(dex.pulled(h), 1);
        assertEq(a.pulled(h), ADD);
        assertEq(b.pulled(h), ADD);
    }

    /// A leftover goes back to alice, fee-free; `fee = 0` stays valid and relayable (no fee shares).
    /// Owner 2026-11-12 (supersedes Fable D P3-4's live read, now in `legacy/ua-mtx-fix2-dex/`): the DEX never reads a
    /// release's deprecation. A SCaaS-only plan is verified by its tokens, deprecated or not: a bad signature fails at the
    /// token (`MetaTxBadSignature`) after `a`'s release is deprecated as before, and the good signature still settles.
    function test_deprecatedRelease_tokenStillVerifies() public {
        ITradeToken.LiquidityOrder memory o = _addOrder(98_000);
        ISCaaSDex.LiquidityPlan memory bad = _plan(o, 0xBAD, _u2(ADD, ADD));
        bytes32 h = dex.liquidityOrderDigest(o);
        f.deprecateToken(IOpenFactory.TokenKind.NORMAL, 1, f.chainUid(), "its liquidity pull");
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector); // the token's own check, not the DEX's
        _run(bad, _addXs(ADD, ADD, address(dex)));
        _run(_plan(o, ALICE_PK, _u2(ADD, ADD)), _addXs(ADD, ADD, address(dex))); // the control
        assertEq(dex.pulled(h), 1);
    }

    function test_v2AddRefundFeeZero() public {
        ITradeToken.LiquidityOrder memory o = _addOrder(90_000);
        o.fee = 0;
        uint256 before = a.balanceOf(alice);
        _run(_plan(o, ALICE_PK, _u2(ADD, ADD)), _addXs(90_000, ADD, address(dex)));
        assertEq(a.balanceOf(alice), before - 90_000);
        assertEq(pair.balanceOf(relayer) + pair.balanceOf(treasury), 0);
        assertGt(pair.balanceOf(carol), 90_000);
    }

    /// Create the pair as the first interaction, then deposit (§8.1).
    function test_createPairFirst() public {
        MockERC20 c = new MockERC20("C", "C", 18);
        c.mint(alice, 1e9);
        vm.prank(alice);
        c.approve(puller, type(uint256).max);
        address next = vm.computeCreateAddress(address(v2f), vm.getNonce(address(v2f)));
        ITradeToken.LiquidityOrder memory o = _base();
        o.inputs = _two(_t(address(a), ADD), _t(address(c), ADD));
        o.outputs = _one(_t(next, 98_000));
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](4);
        xs[0] = _ix(address(v2f), abi.encodeCall(v2f.createPair, (address(a), address(c))));
        xs[1] = _ix(address(a), abi.encodeCall(IERC20.transfer, (next, ADD)));
        xs[2] = _ix(address(c), abi.encodeCall(IERC20.transfer, (next, ADD)));
        xs[3] = _ix(next, abi.encodeCall(MockV2LiquidityPair.mint, (address(dex))));
        _run(_plan(o, ALICE_PK, _u2(ADD, ADD)), xs);
        assertGt(IERC20(next).balanceOf(carol), 98_000);
    }

    /// One SCaaS and one outside input (the puller; the DEX verifies the signature itself).
    function test_scaasAndOutside() public {
        MockV2LiquidityPair p2 = MockV2LiquidityPair(v2f.createPair(address(a), address(usdc)));
        ITradeToken.LiquidityOrder memory o = _base();
        o.inputs = _two(_t(address(a), ADD), _t(address(usdc), ADD));
        o.outputs = _one(_t(address(p2), 98_000));
        ISCaaSDex.Interaction[] memory xs = _xs3(_ix(address(a), abi.encodeCall(IERC20.transfer, (address(p2), ADD))),
            _ix(address(usdc), abi.encodeCall(IERC20.transfer, (address(p2), ADD))),
            _ix(address(p2), abi.encodeCall(MockV2LiquidityPair.mint, (address(dex)))));
        _run(_plan(o, ALICE_PK, _u2(ADD, ADD)), xs);
        assertGt(p2.balanceOf(carol), 98_000);
    }

    /// Withdraw: carol gives her LP (the puller) for both tokens.
    function test_v2Withdraw() public {
        _run(_addPlan(98_000), _addXs(ADD, ADD, address(dex)));
        uint256 lp = pair.balanceOf(carol);
        vm.prank(carol);
        pair.approve(puller, lp);
        ITradeToken.LiquidityOrder memory o = _base();
        o.from = nid(carol);
        o.recipient = 0;
        o.inputs = _one(_t(address(pair), lp));
        o.outputs = _two(_t(address(a), 90_000), _t(address(b), 90_000));
        o.nonce = 1;
        uint256 a0 = a.balanceOf(carol);
        _run(_plan(o, CAROL_PK, _u(lp)), _xs2(_ix(address(pair), abi.encodeCall(IERC20.transfer, (address(pair), lp))),
            _ix(address(pair), abi.encodeCall(MockV2LiquidityPair.burn, (address(dex))))));
        assertEq(pair.balanceOf(carol), 0);
        assertGt(a.balanceOf(carol) - a0, 90_000);
    }

    /// v4-style mint: the reader binds pool, range and liquidity; the NFT goes to carol; leftovers back to alice.
    function test_v4Mint() public {
        uint256 id = posm.nextId();
        uint256 a0 = a.balanceOf(alice);
        ISCaaSDex.LiquidityPlan memory p = _plan(_mintOrder(40_000), ALICE_PK, _u2(50_000, 50_000));
        p.positionId = id;
        _run(p, _mintXs(40_000, address(dex)));
        assertEq(posm.ownerOf(id), carol);
        assertEq(posm.getPositionLiquidity(id), 40_000);
        assertEq(a.balanceOf(alice), a0 - 40_000);
        assertEq(posm.balanceOf(address(dex)), 0);
    }

    /// A partial withdraw signed as the received position (same id, at least what must remain: review P0-1).
    function test_v4PartialWithdraw() public {
        uint256 id = _carolPosition();
        ISCaaSDex.LiquidityPlan memory p = _returnOrder(id, 30_000, 9_000);
        uint256 a0 = a.balanceOf(carol);
        _run(p, _xs(_ix(address(posm), abi.encodeCall(MockPositionManagerV4.decrease, (id, 10_000, address(dex))))));
        assertEq(posm.ownerOf(id), carol);
        assertEq(posm.getPositionLiquidity(id), 30_000);
        assertEq(a.balanceOf(carol) - a0, 10_000 - 30); // the fee ⌈10 000 · 0.3 %⌉
    }

    /// A whole withdraw that burns: no position received, the given one spent whole; `ownerOf` reverts (burnt), settles.
    function test_v4WholeWithdrawBurns() public {
        uint256 id = _carolPosition();
        ISCaaSDex.LiquidityPlan memory p = _returnOrder(id, 0, 39_000);
        p.order.positionReader = address(0);
        (p.order.positionPool, p.order.tickLower, p.order.tickUpper) = (0, 0, 0);
        p.positionId = 0;
        p.auth = _sig(p.order, CAROL_PK);
        _run(p, _xs2(_ix(address(posm), abi.encodeCall(MockPositionManagerV4.decrease, (id, 40_000, address(dex)))),
            _ix(address(posm), abi.encodeCall(MockPositionManagerV4.burn, (id)))));
        vm.expectRevert();
        posm.ownerOf(id);
    }

    /// A whole withdraw that leaves an empty NFT: the DEX still owns it and returns it to `from` (housekeeping).
    function test_v4WholeWithdrawReturnsEmpty() public {
        uint256 id = _carolPosition();
        ISCaaSDex.LiquidityPlan memory p = _returnOrder(id, 0, 39_000);
        p.order.positionReader = address(0);
        (p.order.positionPool, p.order.tickLower, p.order.tickUpper) = (0, 0, 0);
        p.positionId = 0;
        p.auth = _sig(p.order, CAROL_PK);
        _run(p, _xs(_ix(address(posm), abi.encodeCall(MockPositionManagerV4.decrease, (id, 40_000, address(dex))))));
        assertEq(posm.ownerOf(id), carol);
        assertEq(posm.getPositionLiquidity(id), 0);
    }

    /// v4's auto-collect on a top-up returns more A than was pulled: the excess is refunded to `from` (review P2-2).
    function test_v4TopUpRefundAbovePull() public {
        uint256 id = _carolPosition();
        vm.prank(carol);
        a.transfer(address(posm), 20_000);
        posm.accrue(id, 20_000, 0);
        ITradeToken.LiquidityOrder memory o = _returnOrder(id, 50_000, 0).order;
        o.inputs = _two(_t(address(a), 10_000), _t(address(b), 10_000));
        o.outputs = new ITradeToken.LiquidityToken[](0);
        ISCaaSDex.LiquidityPlan memory p = _plan(o, CAROL_PK, _u2(10_000, 10_000));
        p.positionId = id;
        uint256 a0 = a.balanceOf(carol);
        _run(p, _xs3(_ix(address(a), abi.encodeCall(IERC20.transfer, (address(posm), 10_000))),
            _ix(address(b), abi.encodeCall(IERC20.transfer, (address(posm), 10_000))),
            _ix(address(posm), abi.encodeCall(MockPositionManagerV4.increase, (id, 10_000, address(dex))))));
        assertEq(a.balanceOf(carol), a0 + 10_000); // pulled 10 000, refunded 20 000
        assertEq(posm.getPositionLiquidity(id), 50_000);
        assertEq(posm.ownerOf(id), carol);
    }

    /// Through a router-style target: `approve` then a pull by the router; the allowance is reset to 0 (L20).
    function test_approveReset() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](4);
        xs[0] = _ix(address(a), abi.encodeCall(IERC20.approve, (address(pair), 5))); // a contract spender (CTR-TOK-01)
        (xs[1], xs[2], xs[3]) = (_addXs(ADD, ADD, address(dex))[0], _addXs(ADD, ADD, address(dex))[1],
            _addXs(ADD, ADD, address(dex))[2]);
        _run(p, xs);
        assertEq(a.allowance(address(dex), address(pair)), 0);
    }

    // ------------------------------------------------------------------ L1-L5 shape

    function _shape(ISCaaSDex.LiquidityPlan memory p, uint8 code) internal {
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.LiquidityShape.selector, code));
        _run(p, _addXs(ADD, ADD, address(dex)));
    }

    function test_L1_noInputNoOutput() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        p.order.outputs = new ITradeToken.LiquidityToken[](0);
        _shape(p, 1);
        p = _addPlan(98_000);
        p.order.inputs = new ITradeToken.LiquidityToken[](0);
        p.pull = new uint256[](0);
        _shape(p, 1);
    }

    function test_L2_atMostEight() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        p.extraTokens = new address[](9);
        for (uint256 i; i < 9; ++i) p.extraTokens[i] = address(uint160(0x1000 + i));
        _shape(p, 2);
        p = _addPlan(98_000);
        p.order.outputs = new ITradeToken.LiquidityToken[](9);
        for (uint256 i; i < 9; ++i) p.order.outputs[i] = _t(address(uint160(0x2000 + i)), 1);
        _shape(p, 2);
    }

    function test_L3_distinctNonZero() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        p.order.inputs[1].token = address(a); // twice in one list
        _shape(p, 3);
        p = _addPlan(98_000);
        p.order.outputs[0].token = address(b); // in inputs and outputs
        _shape(p, 3);
        p = _addPlan(98_000);
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(pair); // an output again
        _shape(p, 3);
        p = _addPlan(98_000);
        p.order.inputs[1].amount = 0; // a zero maximum
        _shape(p, 3);
        p = _addPlan(98_000);
        p.order.positionManager = address(b); // the manager is an input
        _shape(p, 3);
    }

    function test_L4_positionFields() public {
        ISCaaSDex.LiquidityPlan memory p = _plan(_mintOrder(40_000), ALICE_PK, _u2(50_000, 50_000));
        p.positionId = 0; // received, no id
        _shape(p, 4);
        p.positionId = 1;
        p.order.minLiquidity = 0;
        _shape(p, 4);
        p.order.minLiquidity = 1;
        (p.order.tickLower, p.order.tickUpper) = (HI, LO);
        _shape(p, 4);
        p = _addPlan(98_000);
        p.positionId = 1; // an id with none received
        _shape(p, 4);
        p = _addPlan(98_000);
        p.order.positionReader = address(reader); // a reader without a manager
        _shape(p, 4);
    }

    function test_L5_recipient() public {
        bytes32[5] memory bad = [nid(address(dex)), nid(puller), nid(address(a)), nid(address(pair)), nid(address(posm))];
        for (uint256 i; i < bad.length; ++i) {
            ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
            if (i == 4) (p.order.positionManager, p.order.positionIn) = (address(posm), 1);
            p.order.recipient = bad[i];
            _shape(p, 5);
        }
    }

    // ------------------------------------------------------------------ L6-L13 order checks

    function test_L6_relayer() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.WrongRelayer.selector, attacker));
        vm.prank(attacker);
        dex.mtxLiquidity(p, _addXs(ADD, ADD, address(dex)));
    }

    function test_L7_expiry() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        vm.warp(p.order.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.OrderExpired.selector, dex.liquidityOrderDigest(p.order)));
        _run(p, _addXs(ADD, ADD, address(dex)));
    }

    function test_L8_nonceCap() public {
        ITradeToken.LiquidityOrder memory o = _addOrder(98_000);
        o.nonce = 2 ** 128;
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(ADD, ADD));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.NonceAboveCap.selector, dex.liquidityOrderDigest(o)));
        _run(p, _addXs(ADD, ADD, address(dex)));
    }

    function test_L9_dexLane() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, dex.invalidateNoncesDigest(alice, 7, 1));
        dex.mtxInvalidateNonces(alice, 7, 1, abi.encodePacked(r, s, v));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.NonceInvalidated.selector, dex.liquidityOrderDigest(p.order)));
        _run(p, _addXs(ADD, ADD, address(dex)));
    }

    function test_L10_flags() public {
        for (uint8 fl = 1; fl <= 2; ++fl) {
            ITradeToken.LiquidityOrder memory o = _addOrder(98_000);
            o.flags = fl;
            ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(ADD, ADD));
            vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.BadFlags.selector, dex.liquidityOrderDigest(o)));
            _run(p, _addXs(ADD, ADD, address(dex)));
        }
    }

    function test_L11_feeCap() public {
        ITradeToken.LiquidityOrder memory o = _addOrder(98_000);
        o.fee = 10_001;
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(ADD, ADD));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.FeeAboveCap.selector, dex.liquidityOrderDigest(o)));
        _run(p, _addXs(ADD, ADD, address(dex)));
    }

    function test_L12_oneShot() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        _run(p, _addXs(ADD, ADD, address(dex)));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.OrderClosed.selector, dex.liquidityOrderDigest(p.order)));
        _run(p, _addXs(ADD, ADD, address(dex)));
    }

    /// One-shot on the DEX itself: an order with an outside input only (no token keeps `pulled[h]` for it).
    function test_L12_oneShotOutsideOnly() public {
        _run(_addPlan(98_000), _addXs(ADD, ADD, address(dex)));
        uint256 lp = pair.balanceOf(carol);
        vm.prank(carol);
        pair.approve(puller, type(uint256).max);
        ITradeToken.LiquidityOrder memory o = _base();
        (o.from, o.recipient, o.nonce) = (nid(carol), 0, 1);
        o.inputs = _one(_t(address(pair), lp));
        o.outputs = _two(_t(address(a), 1), _t(address(b), 1));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, CAROL_PK, _u(lp / 2));
        ISCaaSDex.Interaction[] memory xs = _xs2(_ix(address(pair), abi.encodeCall(IERC20.transfer, (address(pair), lp / 2))),
            _ix(address(pair), abi.encodeCall(MockV2LiquidityPair.burn, (address(dex)))));
        _run(p, xs);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.OrderClosed.selector, dex.liquidityOrderDigest(o)));
        _run(p, xs);
    }

    function test_L13_pullBounds() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        bytes32 h = dex.liquidityOrderDigest(p.order);
        p.pull = _u(ADD);
        vm.expectRevert(ISCaaSDex.LengthMismatch.selector);
        _run(p, _addXs(ADD, ADD, address(dex)));
        p.pull = _u2(ADD, 0);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.ZeroFill.selector, h));
        _run(p, _addXs(ADD, ADD, address(dex)));
        p.pull = _u2(ADD, ADD + 1);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.Overfill.selector, h));
        _run(p, _addXs(ADD, ADD, address(dex)));
    }

    // ------------------------------------------------------------------ L16-L18 verify and arrival

    function test_L16_dexVerify() public {
        MockV2LiquidityPair p2 = MockV2LiquidityPair(v2f.createPair(address(a), address(usdc)));
        ITradeToken.LiquidityOrder memory o = _base();
        o.inputs = _two(_t(address(a), ADD), _t(address(usdc), ADD));
        o.outputs = _one(_t(address(p2), 98_000));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, CAROL_PK, _u2(ADD, ADD)); // signed by another key
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, dex.liquidityOrderDigest(o)));
        _run(p, new ISCaaSDex.Interaction[](0));
        // a position given with a bad signature
        uint256 id = _carolPosition();
        p = _returnOrder(id, 30_000, 9_000);
        p.auth = _sig(p.order, ALICE_PK);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, dex.liquidityOrderDigest(p.order)));
        _run(p, new ISCaaSDex.Interaction[](0));
    }

    function test_L17_arrival() public {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        fot.mint(alice, 1e9);
        vm.prank(alice);
        fot.approve(puller, type(uint256).max);
        MockV2LiquidityPair p2 = MockV2LiquidityPair(v2f.createPair(address(a), address(fot)));
        ITradeToken.LiquidityOrder memory o = _base();
        o.inputs = _two(_t(address(a), ADD), _t(address(fot), ADD));
        o.outputs = _one(_t(address(p2), 1));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(ADD, ADD));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(fot)));
        _run(p, new ISCaaSDex.Interaction[](0));
    }

    function test_L18_positionGivenArrived() public {
        MockStickyPositions sticky = new MockStickyPositions();
        sticky.mint(alice, 5);
        ITradeToken.LiquidityOrder memory o = _base();
        o.outputs = _one(_t(address(a), 0));
        o.positionManager = address(sticky);
        o.positionIn = 5;
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, new uint256[](0));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionNotReceived.selector, 5));
        _run(p, new ISCaaSDex.Interaction[](0));
    }

    // ------------------------------------------------------------------ L19 interactions

    function _forbidden(ISCaaSDex.Interaction memory x, bytes memory err) internal {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        vm.expectRevert(err);
        _run(p, _xs(x));
    }

    function test_L19_interactions() public {
        _forbidden(_ix(address(dex), hex"00000000"), abi.encodeWithSelector(ISCaaSDex.ForbiddenTarget.selector, address(dex)));
        _forbidden(_ix(puller, hex"00000000"), abi.encodeWithSelector(ISCaaSDex.ForbiddenTarget.selector, puller));
        bytes4[7] memory sels = [ITradeToken.mtxTrade.selector, ILiquidityPullToken.mtxLiquidityPull.selector,
            bytes4(0x58c18f87), bytes4(0x8c4a5df6), bytes4(0x39509351), bytes4(0x87517c45), bytes4(0xa22cb465)];
        for (uint256 i; i < sels.length; ++i) {
            _forbidden(_ix(address(a), abi.encodePacked(sels[i], bytes32(0))),
                abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(a), sels[i]));
        }
    }

    /// `approve` aimed at the position manager: the module's own loop (ERC-721 `approve` shares ERC-20's selector).
    function test_L19_approveOnManager() public {
        ISCaaSDex.LiquidityPlan memory p = _plan(_mintOrder(40_000), ALICE_PK, _u2(50_000, 50_000));
        p.positionId = posm.nextId();
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(posm),
            IERC20.approve.selector));
        _run(p, _xs(_ix(address(posm), abi.encodeCall(IERC20.approve, (attacker, 0)))));
    }

    function test_L19_listed() public {
        ITradeToken.LiquidityOrder memory o = _addOrder(98_000);
        o.flags = 4; // LISTED_POOLS
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(ADD, ADD));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.TargetNotListed.selector, address(a)));
        _run(p, _addXs(ADD, ADD, address(dex)));
        vm.prank(admin);
        dex.setListedOnly(true);
        p = _addPlan(98_000);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.TargetNotListed.selector, address(a)));
        _run(p, _addXs(ADD, ADD, address(dex)));
    }

    // ------------------------------------------------------------------ L21-L25 positions

    function test_L21_receivedOwned() public {
        ISCaaSDex.LiquidityPlan memory p = _plan(_mintOrder(40_000), ALICE_PK, _u2(50_000, 50_000));
        p.positionId = posm.nextId();
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionNotReceived.selector, p.positionId));
        _run(p, _mintXs(40_000, attacker)); // minted elsewhere
    }

    function test_L22_readerListed() public {
        V4PositionReader other = new V4PositionReader(address(posm));
        ITradeToken.LiquidityOrder memory o = _mintOrder(40_000);
        o.positionReader = address(other); // not listed
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(50_000, 50_000));
        p.positionId = posm.nextId();
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionReaderNotListed.selector, address(other)));
        _run(p, _mintXs(40_000, address(dex)));
        V4PositionReader wrong = new V4PositionReader(address(0x1234)); // listed, another manager
        vm.prank(admin);
        dex.setExchangeTarget(address(wrong), true);
        o.positionReader = address(wrong);
        p = _plan(o, ALICE_PK, _u2(50_000, 50_000));
        p.positionId = posm.nextId();
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionReaderNotListed.selector, address(wrong)));
        _run(p, _mintXs(40_000, address(dex)));
    }

    function test_L23_poolRangeEncumbered() public {
        ITradeToken.LiquidityOrder memory o = _mintOrder(40_000);
        o.positionPool = keccak256("another pool");
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(50_000, 50_000));
        uint256 id = posm.nextId();
        p.positionId = id;
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionMismatch.selector, id));
        _run(p, _mintXs(40_000, address(dex)));
        o = _mintOrder(40_000);
        o.tickLower = -660; // another range
        p = _plan(o, ALICE_PK, _u2(50_000, 50_000));
        p.positionId = id;
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionMismatch.selector, id));
        _run(p, _mintXs(40_000, address(dex)));
        // a subscriber set mid-plan
        p = _plan(_mintOrder(40_000), ALICE_PK, _u2(50_000, 50_000));
        p.positionId = id;
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](4);
        (xs[0], xs[1], xs[2]) = (_mintXs(40_000, address(dex))[0], _mintXs(40_000, address(dex))[1],
            _mintXs(40_000, address(dex))[2]);
        xs[3] = _ix(address(posm), abi.encodeCall(MockPositionManagerV4.setSubscriber, (id, true)));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionMismatch.selector, id));
        _run(p, xs);
    }

    function test_L23_unreadable() public {
        MockShortReader short = new MockShortReader(address(posm));
        vm.prank(admin);
        dex.setExchangeTarget(address(short), true);
        ITradeToken.LiquidityOrder memory o = _mintOrder(40_000);
        o.positionReader = address(short);
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(50_000, 50_000));
        p.positionId = posm.nextId();
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionUnreadable.selector, address(short)));
        _run(p, _mintXs(40_000, address(dex)));
    }

    function test_L24_minLiquidity() public {
        ISCaaSDex.LiquidityPlan memory p = _plan(_mintOrder(40_000), ALICE_PK, _u2(50_000, 50_000));
        p.positionId = posm.nextId();
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionBelowMin.selector, p.positionId, uint128(1)));
        _run(p, _mintXs(1, address(dex))); // a dust position
    }

    // ------------------------------------------------------------------ L26-L31 outputs, fee, refunds, positions, conservation

    function test_L26_outputAtDexNet() public {
        uint256 fee = (LP_FIRST * 3_000 + 999_999) / 1_000_000;
        // one unit short at the DEX after the fee
        ISCaaSDex.LiquidityPlan memory p = _addPlan(LP_FIRST - fee + 1);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.InsufficientOutput.selector, address(pair)));
        _run(p, _addXs(ADD, ADD, address(dex)));
        // a route paying the recipient directly: got = 0 at the DEX
        p = _addPlan(98_000);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.InsufficientOutput.selector, address(pair)));
        _run(p, _addXs(ADD, ADD, carol));
    }

    /// A third-party credit to the recipient (`claim(recipient)`) while the plan's LP goes to the submitter (review P1-1).
    function test_L26_claimDoesNotCount() public {
        _run(_addPlan(98_000), _addXs(ADD, ADD, address(dex))); // the pool exists; carol holds LP
        MockDistributor dist = new MockDistributor();
        vm.prank(carol);
        pair.transfer(address(dist), 50_000);
        ITradeToken.LiquidityOrder memory o = _addOrder(40_000);
        o.nonce = 1;
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](4);
        (xs[0], xs[1], xs[2]) = (_addXs(ADD, ADD, relayer)[0], _addXs(ADD, ADD, relayer)[1], _addXs(ADD, ADD, relayer)[2]);
        xs[3] = _ix(address(dist), abi.encodeCall(MockDistributor.claim, (address(pair), carol, 50_000)));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(ADD, ADD));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.InsufficientOutput.selector, address(pair)));
        _run(p, xs);
    }

    /// The recipient backstop: a fee-on-transfer LP on the last hop, and the recipient being the treasury (its fee share
    /// must not count: the backstop is measured before the shares).
    function test_L26_recipientBackstop() public {
        FeeOnTransferERC20 lp = new FeeOnTransferERC20();
        lp.mint(address(this), 1e9);
        MockDistributor dist = new MockDistributor();
        lp.transfer(address(dist), 1e8);
        ITradeToken.LiquidityOrder memory o = _base();
        o.inputs = _one(_t(address(a), 1_000));
        o.outputs = _one(_t(address(lp), 98_011));
        o.recipient = nid(treasury);
        o.fee = 10_000; // 1 %
        // the DEX gets 100 001 (1 % of 101 011 burnt), keeps ⌈1 000.01⌉ = 1 001 and pays 99 000 to the treasury, which
        // receives 98 010 (< 98 011); its own fee share (800, 792 after the burn) would cover the gap if it counted
        ISCaaSDex.Interaction[] memory xs = _xs2(_ix(address(dist), abi.encodeCall(MockDistributor.claim,
            (address(lp), address(dex), 101_011))), _ix(address(a), abi.encodeCall(IERC20.transfer, (attacker, 1_000))));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u(1_000));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.InsufficientOutput.selector, address(lp)));
        _run(p, xs);
    }

    /// The fee `⌈got · fee / 10⁶⌉` on a dust fill pays 1 (L27).
    function test_L27_feeCeil() public {
        _run(_addPlan(98_000), _addXs(ADD, ADD, address(dex)));
        ITradeToken.LiquidityOrder memory o = _addOrder(1);
        o.nonce = 1;
        (o.inputs[0].amount, o.inputs[1].amount) = (100, 100);
        uint256 t0 = pair.balanceOf(treasury) + pair.balanceOf(relayer);
        _run(_plan(o, ALICE_PK, _u2(100, 100)), _addXs(100, 100, address(dex)));
        assertEq(pair.balanceOf(treasury) + pair.balanceOf(relayer) - t0, 1);
    }

    /// A route that leaves an input below its snapshot (it spent more than was pulled: a stray of the DEX).
    function test_L28_inputBelowSnapshot() public {
        vm.prank(alice);
        a.transfer(address(dex), 7); // a stray in a plan token
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(a)));
        _run(p, _addXs(ADD + 7, ADD, address(dex)));
    }

    /// A partial withdraw where the submitter removes more to itself (review P0-1).
    function test_L29_returnedPositionBound() public {
        uint256 id = _carolPosition();
        ISCaaSDex.LiquidityPlan memory p = _returnOrder(id, 30_000, 9_000);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionBelowMin.selector, id, uint128(20_000)));
        _run(p, _xs2(_ix(address(posm), abi.encodeCall(MockPositionManagerV4.decrease, (id, 10_000, address(dex)))),
            _ix(address(posm), abi.encodeCall(MockPositionManagerV4.decrease, (id, 10_000, attacker)))));
    }

    /// A fee collect where the submitter also removes principal.
    function test_L29_feeCollectBound() public {
        uint256 id = _carolPosition();
        vm.prank(carol);
        a.transfer(address(posm), 500);
        vm.prank(carol);
        b.transfer(address(posm), 500);
        posm.accrue(id, 500, 500);
        ISCaaSDex.LiquidityPlan memory p = _returnOrder(id, 40_000, 400);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionBelowMin.selector, id, uint128(39_000)));
        _run(p, _xs2(_ix(address(posm), abi.encodeCall(MockPositionManagerV4.collect, (id, address(dex)))),
            _ix(address(posm), abi.encodeCall(MockPositionManagerV4.decrease, (id, 1_000, attacker)))));
    }

    /// An interaction moves the given NFT away: the minima bound it, the plan settles (spent whole).
    function test_L30_givenMovedAway() public {
        uint256 id = _carolPosition();
        ISCaaSDex.LiquidityPlan memory p = _returnOrder(id, 0, 0);
        p.order.outputs = _one(_t(address(a), 0));
        p.order.positionReader = address(0);
        (p.order.positionPool, p.order.tickLower, p.order.tickUpper) = (0, 0, 0);
        p.positionId = 0;
        p.auth = _sig(p.order, CAROL_PK);
        _run(p, _xs(_ix(address(posm), abi.encodeCall(IERC721.transferFrom, (address(dex), attacker, id)))));
        assertEq(posm.ownerOf(id), attacker);
    }

    function test_L31_conservation() public {
        MockERC20 hop = new MockERC20("H", "H", 18);
        hop.mint(address(this), 10);
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(hop);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](4);
        (xs[0], xs[1], xs[2]) = (_addXs(ADD, ADD, address(dex))[0], _addXs(ADD, ADD, address(dex))[1],
            _addXs(ADD, ADD, address(dex))[2]);
        MockDistributor dist = new MockDistributor();
        hop.transfer(address(dist), 10);
        xs[3] = _ix(address(dist), abi.encodeCall(MockDistributor.claim, (address(hop), address(dex), 10)));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(hop)));
        _run(p, xs);
    }

    /// A position left in the DEX (minted to it, never received) fails conservation of the manager's balance.
    function test_L31_positionLeft() public {
        ITradeToken.LiquidityOrder memory o = _base();
        o.inputs = _two(_t(address(a), 50_000), _t(address(b), 50_000));
        o.outputs = _one(_t(address(usdc), 0));
        o.positionManager = address(posm);
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(50_000, 50_000));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(posm)));
        _run(p, _mintXs(40_000, address(dex)));
    }

    // ------------------------------------------------------------------ L32-L37 module, wiring, guard, invariants

    function test_L32_moduleDirect() public {
        address m = dex.modules()[1];
        assertEq(SCaaSDexLiquidityModule(m).moduleGroup(), 11);
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        vm.expectRevert(SCaaSDexLiquidityModule.NotDelegated.selector);
        SCaaSDexLiquidityModule(m).mtxLiquidity(p, new ISCaaSDex.Interaction[](0));
        vm.expectRevert(SCaaSDexLiquidityModule.NotDelegated.selector);
        SCaaSDexLiquidityModule(m).liquidityOrderDigest(p.order);
    }

    /// A target re-enters `mtxLiquidity` (the same order) and `mtxExchange`: the stub's guard (L34).
    function test_L34_guard() public {
        MockReenter re = new MockReenter();
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        ISCaaSDex.Interaction[] memory none = new ISCaaSDex.Interaction[](0);
        re.set(address(dex), abi.encodeCall(dex.mtxLiquidity, (p, none)));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.InteractionFailed.selector, 0, address(re),
            abi.encodeWithSelector(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector)));
        _run(p, _xs(_ix(address(re), abi.encodeCall(MockReenter.go, ()))));
        ISCaaSDex.ExchangePlan memory e;
        re.set(address(dex), abi.encodeCall(dex.mtxExchange, (e, none)));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.InteractionFailed.selector, 0, address(re),
            abi.encodeWithSelector(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector)));
        _run(p, _xs(_ix(address(re), abi.encodeCall(MockReenter.go, ()))));
    }

    /// The DEX holds no key and implements no ERC-1271 (L36).
    function test_L36_noErc1271() public {
        vm.expectRevert();
        IERC1271(address(dex)).isValidSignature(bytes32(0), "");
    }

    /// `supportsInterface(ILiquidityPullToken)` (L35's positive side; review P2-6).
    function test_L35_interface() public view {
        assertTrue(a.supportsInterface(type(ILiquidityPullToken).interfaceId));
        assertEq(type(ILiquidityPullToken).interfaceId, ILiquidityPullToken.mtxLiquidityPull.selector);
    }

    // ------------------------------------------------------------------ owner 2026-11-10: the remaining cases

    /// T7's read through the stub: the DEX's `liquidityOrderDigest` answers a STATICCALL, also while a plan holds the guard.
    function test_T7_digestUnderStaticcall() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        bytes32 h = dex.liquidityOrderDigest(p.order);
        MockDigestProbe probe = new MockDigestProbe();
        probe.probe(address(dex), p.order, h);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](4);
        xs[0] = _ix(address(probe), abi.encodeCall(MockDigestProbe.probe, (address(dex), p.order, h)));
        (xs[1], xs[2], xs[3]) = (_addXs(ADD, ADD, address(dex))[0], _addXs(ADD, ADD, address(dex))[1],
            _addXs(ADD, ADD, address(dex))[2]);
        _run(p, xs);
        assertEq(dex.pulled(h), 1);
    }

    /// L25: a manager whose `transferFrom` keeps the received position.
    function test_L25_delivered() public {
        MockStickyPositions sticky = new MockStickyPositions();
        MockFixedReader fr = new MockFixedReader(address(sticky), keccak256("pool"), LO, HI, 5);
        vm.prank(admin);
        dex.setExchangeTarget(address(fr), true);
        ITradeToken.LiquidityOrder memory o = _base();
        o.inputs = _one(_t(address(a), 1_000));
        (o.positionManager, o.positionReader, o.positionPool) = (address(sticky), address(fr), keccak256("pool"));
        (o.tickLower, o.tickUpper, o.minLiquidity) = (LO, HI, 5);
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u(1_000));
        p.positionId = 7;
        ISCaaSDex.Interaction[] memory xs = _xs(_ix(address(sticky), abi.encodeCall(MockStickyPositions.mint, (address(dex), 7))));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.PositionNotDelivered.selector, 7));
        _run(p, xs);
    }

    /// L35: a token of an earlier release (no `mtxLiquidityPull`; simulated by an empty revert of that selector) as a SCaaS
    /// input: the plan reverts with empty data and nothing moves.
    function test_L35_earlierRelease() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        vm.mockCallRevert(address(b), abi.encodeWithSelector(ILiquidityPullToken.mtxLiquidityPull.selector), "");
        uint256 a0 = a.balanceOf(alice);
        vm.expectRevert(bytes(""));
        _run(p, _addXs(ADD, ADD, address(dex)));
        assertEq(a.balanceOf(alice), a0);
        assertEq(dex.pulled(dex.liquidityOrderDigest(p.order)), 0);
    }

    /// A zap: one token in, half swapped for the other inside the plan (`extraTokens` for the hop), LP out.
    function test_zap() public {
        MockSwap sw = new MockSwap();
        vm.prank(carol);
        b.transfer(address(sw), ADD);
        ITradeToken.LiquidityOrder memory o = _base();
        o.inputs = _one(_t(address(a), 2 * ADD));
        o.outputs = _one(_t(address(pair), 98_000));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u(2 * ADD));
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(b);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](5);
        xs[0] = _ix(address(a), abi.encodeCall(IERC20.transfer, (address(sw), ADD)));
        xs[1] = _ix(address(sw), abi.encodeCall(MockSwap.swap, (address(b), ADD, address(dex))));
        (xs[2], xs[3], xs[4]) = (_addXs(ADD, ADD, address(dex))[0], _addXs(ADD, ADD, address(dex))[1],
            _addXs(ADD, ADD, address(dex))[2]);
        _run(p, xs);
        assertGt(pair.balanceOf(carol), 98_000);
        assertEq(b.balanceOf(address(dex)), 0);
    }

    /// An ERC-1271 signer: each SCaaS input token verifies the wallet's signature over `h` (CTR-DEX-08's cap).
    function test_erc1271Signer() public {
        Mock1271Wallet w = new Mock1271Wallet(alice);
        vm.startPrank(alice);
        a.transfer(address(w), ADD);
        b.transfer(address(w), ADD);
        vm.stopPrank();
        ITradeToken.LiquidityOrder memory o = _addOrder(98_000);
        o.from = nid(address(w));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(ADD, ADD));
        _run(p, _addXs(ADD, ADD, address(dex)));
        assertEq(a.balanceOf(address(w)), 0);
        assertGt(pair.balanceOf(carol), 98_000);
    }

    /// Carol's LP-only withdraw order (an outside input: no token checks it, the DEX alone does), after a v2 add.
    function _lpOnly() internal returns (ITradeToken.LiquidityOrder memory o, uint256 lp) {
        _run(_addPlan(98_000), _addXs(ADD, ADD, address(dex)));
        lp = pair.balanceOf(carol);
        vm.prank(carol);
        pair.approve(puller, type(uint256).max);
        o = _base();
        (o.from, o.recipient, o.nonce) = (nid(carol), 0, 1);
        o.inputs = _one(_t(address(pair), lp));
        o.outputs = _two(_t(address(a), 1), _t(address(b), 1));
    }

    /// L7, L8, L13 on the DEX alone (the tokens repeat them with the same errors on a SCaaS input).
    function test_L7_L8_L13_dexAlone() public {
        (ITradeToken.LiquidityOrder memory o, uint256 lp) = _lpOnly();
        ISCaaSDex.Interaction[] memory xs = _xs2(_ix(address(pair), abi.encodeCall(IERC20.transfer, (address(pair), lp))),
            _ix(address(pair), abi.encodeCall(MockV2LiquidityPair.burn, (address(dex)))));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, CAROL_PK, _u(lp));
        p.pull = _u(lp + 1);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.Overfill.selector, dex.liquidityOrderDigest(o)));
        _run(p, xs);
        o.nonce = 2 ** 128;
        p = _plan(o, CAROL_PK, _u(lp));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.NonceAboveCap.selector, dex.liquidityOrderDigest(o)));
        _run(p, xs);
        o.nonce = 1;
        p = _plan(o, CAROL_PK, _u(lp));
        bytes32 h = dex.liquidityOrderDigest(o);
        vm.warp(o.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.OrderExpired.selector, h));
        _run(p, xs);
    }
}
