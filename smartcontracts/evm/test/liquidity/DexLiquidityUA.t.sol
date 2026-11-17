// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {nid} from "../helpers/Ids.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "../ua/UACall.sol";
import {UADexBase} from "../ua/UADex.t.sol";
import {MockV2Factory, MockV2LiquidityPair} from "./LiquidityMocks.sol";

/// A derived signer (`p256`) gives SCaaS inputs from its UA ledger, a native recipient receives the LP (CTR-UA-27,
/// spec 2026-11-10-dex-liquidity.md §6 step 1, L14, L15); each input token verifies `h` through the registry.
contract DexLiquidityUATest is UADexBase {
    address internal constant RECV = address(0xC0FFEE);
    MockV2LiquidityPair internal pair;

    function setUp() public override {
        super.setUp();
        pair = MockV2LiquidityPair(new MockV2Factory().createPair(address(A), address(B)));
        vm.prank(bob);
        B.transferToUA(uaP, 100_000);
    }

    function _order(address lp) internal view returns (ITradeToken.LiquidityOrder memory o) {
        o.from = uaP;
        o.inputs = new ITradeToken.LiquidityToken[](2);
        o.inputs[0] = ITradeToken.LiquidityToken(address(A), 50_000);
        o.inputs[1] = ITradeToken.LiquidityToken(address(B), 50_000);
        o.outputs = new ITradeToken.LiquidityToken[](1);
        o.outputs[0] = ITradeToken.LiquidityToken(lp, 48_000);
        o.recipient = bytes32(uint256(uint160(RECV)));
        o.relayer = RELAYER;
        o.batch = 3;
        o.validUntil = block.timestamp + 300;
    }

    function _plan(ITradeToken.LiquidityOrder memory o) internal view returns (ISCaaSDex.LiquidityPlan memory p) {
        bytes32 h = dex.liquidityOrderDigest(o);
        p.order = o;
        p.auth = UACall.auth(uaP, _auth(lreg, lreg.kindOf(uaP), _key(UAKinds.P256), UAKinds.PURPOSE_TRADE, h));
        p.pull = new uint256[](o.inputs.length);
        for (uint256 i; i < o.inputs.length; ++i) p.pull[i] = o.inputs[i].amount;
    }

    function _xs() internal view returns (ISCaaSDex.Interaction[] memory xs) {
        xs = new ISCaaSDex.Interaction[](3);
        xs[0] = ISCaaSDex.Interaction(address(A), abi.encodeCall(IERC20.transfer, (address(pair), 50_000)));
        xs[1] = ISCaaSDex.Interaction(address(B), abi.encodeCall(IERC20.transfer, (address(pair), 50_000)));
        xs[2] = ISCaaSDex.Interaction(address(pair), abi.encodeCall(MockV2LiquidityPair.mint, (address(dex))));
    }

    function _run(ISCaaSDex.LiquidityPlan memory p) internal {
        vm.prank(RELAYER);
        dex.mtxLiquidity(p, _xs());
    }

    function test_derivedSignerNativeRecipient() public {
        uint256 a0 = A.balanceOfUA(uaP);
        _run(_plan(_order(address(pair))));
        assertEq(A.balanceOfUA(uaP), a0 - 50_000);
        assertGt(pair.balanceOf(RECV), 48_000);
    }

    /// fix2-dex (CTR-DEX-32): on a DEX that never listed `A` / `B` the kind is the factory's at use, so a derived signer's
    /// SCaaS inputs are verified by the tokens (the DEX cannot verify a derived signer itself).
    function test_derivedSigner_unlistedScaasInputs() public {
        dex = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(address(this)), 200_000, TREASURY, false, 0,
            address(0), 0, 0)), "fresh"));
        assertEq(dex.tokenKind(address(A)), 0);
        _run(_plan(_order(address(pair))));
        assertGt(pair.balanceOf(RECV), 48_000);
    }

    /// L14: a derived signer gives an outside input, a ledger-off SCaaS input, or a position.
    function test_L14_derivedFrom() public {
        ITradeToken.LiquidityOrder memory o = _order(address(pair));
        o.inputs[1].token = address(usdc);
        ISCaaSDex.LiquidityPlan memory p = _plan(o);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.UALegNotLedger.selector, address(usdc)));
        _run(p);
        o.inputs[1].token = address(C);
        p = _plan(o);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.UALegNotLedger.selector, address(C)));
        _run(p);
        o = _order(address(pair));
        (o.positionManager, o.positionIn) = (address(0x1234), 1);
        p = _plan(o);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.UALegNotLedger.selector, address(0x1234)));
        _run(p);
    }

    /// L15: a derived recipient of an outside output, or of a position.
    function test_L15_derivedRecipient() public {
        ITradeToken.LiquidityOrder memory o = _order(address(pair));
        o.recipient = uaB;
        ISCaaSDex.LiquidityPlan memory p = _plan(o);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.UAReceiveNotLedger.selector, address(pair)));
        _run(p);
    }
}
