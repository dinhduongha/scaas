// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {noneInit, underlyingInit, Rate} from "./helpers/V2Fixture.sol";
import {FeePolicy} from "../../src/common/FeePolicy.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";

/// Underlying whose `transferFrom` re-enters the wrapper while the self-call is live.
contract ReenteringERC20 is MockERC20 {
    address public target;
    constructor() MockERC20("Re", "RE", 6) {}
    function arm(address t) external { target = t; }
    function transferFrom(address from, address to, uint256 v) public override returns (bool) {
        if (target != address(0)) UnderlyingToken(target).wrap(1);
        return super.transferFrom(from, to, v);
    }
}

/// CTR-MTX-19 per kind: the published allowlist is pinned, every listed selector runs through `mtxExecute` and
/// the alias (so it is `nonReentrant` — `_selfCall` fails closed otherwise), everything else is refused at step 3.
contract AllowlistTest is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant PK = 0xA11CE;
    address internal alice = vm.addr(PK);
    address internal relayer = address(0xBEEF);
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint32 internal constant FIX = MetaTxLib.MODE_FEE_FIXED;
    uint32 internal constant PCT = MetaTxLib.MODE_FEE_PERCENT;

    NoUnderlyingToken internal none;
    UnderlyingToken internal single;
    UnderlyingToken internal multi;
    MockERC20 internal u;
    MockERC20 internal u2;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        u = new MockERC20("U", "U", 6);
        u2 = new MockERC20("U2", "U2", 6);
        none = NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(address(this), address(0), UID, false))));
        none.initialize(address(this), new address[](0), 1,
            abi.encode(noneInit("P", "P", 6, 0, address(this), address(this))));
        single = UnderlyingToken(
            Clones.clone(address(new UnderlyingToken(address(this), address(0), UID, false))));
        Rate memory cfg;
        address[] memory one = new address[](1);
        one[0] = address(u);
        uint256[] memory r1 = new uint256[](1);
        r1[0] = 1;
        single.initialize(address(this), one, 1,
            abi.encode(underlyingInit(one, r1, r1, 6, cfg, address(0), address(0))));
        multi = UnderlyingToken(
            Clones.clone(address(new UnderlyingToken(address(this), address(0), UID, false))));
        address[] memory two = new address[](2);
        (two[0], two[1]) = (address(u), address(u2));
        uint256[] memory r = new uint256[](2);
        (r[0], r[1]) = (1, 1);
        multi.initialize(address(this), two, 1, abi.encode(underlyingInit(two, r, r, 6, cfg, address(0), address(0))));
        none.mint(alice, 1_000e6);
        u.mint(alice, 1_000e6);
        u2.mint(alice, 1_000e6);
        vm.startPrank(alice);
        u.approve(address(single), type(uint256).max);
        u.approve(address(multi), type(uint256).max);
        u2.approve(address(multi), type(uint256).max);
        vm.stopPrank();
    }

    uint256 internal lane;

    function _m(address t, bytes memory data, uint32 mode, uint256 fee)
        internal returns (MetaTxLib.MetaTransaction memory m, bytes memory sig)
    {
        m = MetaTxLib.MetaTransaction({from: alice, data: data, batch: ++lane, nonce: 0,
            validUntil: block.timestamp + 300, mode: mode, relayer: relayer, fee: fee, feeRecipient: address(0)});
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, MetaTokenBase(t).mtxDigest(m));
        sig = abi.encodePacked(r, s, v);
    }

    function _run(address t, bytes memory data) internal {
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) = _m(t, data, RR, 0);
        vm.prank(relayer);
        MetaTokenBase(t).mtxExecute(m, sig);
        (m, sig) = _m(t, data, RR, 0);
        vm.prank(relayer);
        assertTrue(MetaTokenBase(t).executeMetaTransaction(m, sig));
    }

    function _refused(address t, bytes memory data) internal {
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) = _m(t, data, RR, 0);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(data)));
        MetaTokenBase(t).mtxExecute(m, sig);
    }

    function _pin(address t, bytes4[] memory es, uint8[] memory ec, uint8[] memory ea) internal view {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = MetaTokenBase(t).mtxSelectors();
        assertEq(s.length, es.length);
        for (uint256 i; i < s.length; ++i) {
            assertEq(s[i], es[i]);
            assertEq(c[i], ec[i]);
            assertEq(a[i], ea[i]);
        }
    }

    // ------------------------------------------------------------------ pins

    function test_none_allowlistPinned() public view {
        bytes4[] memory s = new bytes4[](2);
        uint8[] memory c = new uint8[](2);
        (s[0], c[0]) = (IMetaTx.cancelNonce.selector, 1);
        (s[1], c[1]) = (NoUnderlyingToken.burn.selector, 2);
        _pin(address(none), s, c, new uint8[](2));
    }

    /// P1d: one implementation for 1–8 legs, so one list (the single-asset ABI and the per-leg ABI).
    function _pinUnderlying(address t) internal view {
        bytes4[] memory s = new bytes4[](6);
        uint8[] memory c = new uint8[](6);
        uint8[] memory a = new uint8[](6);
        (s[0], c[0]) = (IMetaTx.cancelNonce.selector, 1);
        (s[1], c[1]) = (bytes4(keccak256("wrap(uint256)")), 1);
        (s[2], c[2]) = (bytes4(keccak256("unwrap(uint256,address,uint256)")), 2);
        (s[3], c[3]) = (bytes4(keccak256("wrap(address,uint256)")), 1);
        (s[4], c[4], a[4]) = (bytes4(keccak256("unwrap(address,uint256,address,uint256)")), 2, 1);
        (s[5], c[5]) = (bytes4(keccak256("addReserve(address,uint256)")), 1);
        _pin(t, s, c, a);
    }

    function test_single_allowlistPinned() public view {
        _pinUnderlying(address(single));
    }

    function test_multi_allowlistPinned() public view {
        _pinUnderlying(address(multi));
    }

    // ------------------------------------------------------------------ every listed selector runs

    function test_none_everyListedSelectorRuns() public {
        _run(address(none), abi.encodeCall(IMetaTx.cancelNonce, (99)));
        _run(address(none), abi.encodeCall(NoUnderlyingToken.burn, (1e6)));
        assertEq(none.balanceOf(alice), 998e6);
    }

    function test_single_everyListedSelectorRuns() public {
        _run(address(single), abi.encodeCall(IMetaTx.cancelNonce, (99)));
        _run(address(single), abi.encodeWithSignature("wrap(uint256)", 10e6));
        _run(address(single), abi.encodeWithSignature("unwrap(uint256,address,uint256)", 1e6, alice, 1e6));
        _run(address(single), abi.encodeWithSignature("wrap(address,uint256)", address(u), 10e6));
        _run(address(single), abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(u), 1e6, alice, 0));
        _run(address(single), abi.encodeWithSignature("addReserve(address,uint256)", address(u), 1e6));
        assertEq(single.balanceOf(alice), 36e6);
        assertEq(u.balanceOf(address(single)), 38e6);       // 40 wrapped − 4 unwrapped + 2 by addReserve
    }

    /// The single-asset entries are listed but revert `UnderlyingRequired` with two legs.
    function test_multi_everyListedSelectorRuns() public {
        _run(address(multi), abi.encodeCall(IMetaTx.cancelNonce, (99)));
        _run(address(multi), abi.encodeWithSignature("wrap(address,uint256)", address(u2), 10e6));
        _run(address(multi), abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(u2), 1e6, alice, 0));
        _run(address(multi), abi.encodeWithSignature("addReserve(address,uint256)", address(u), 1e6));
        assertEq(multi.balanceOf(alice), 18e6);
        assertEq(u.balanceOf(address(multi)), 2e6);         // addReserve(u) twice
        assertEq(u2.balanceOf(address(multi)), 18e6);
    }

    // ------------------------------------------------------------------ published list vs enforced rule

    /// For each listed selector, the class and basis argument `mtxSelectors()` publishes are the ones `_mtxRule`
    /// enforces: ABSOLUTE refuses `PERCENT` at step 3; AMOUNT caps a `FIXED` fee at 1 % of the named argument, so
    /// `basis/100 + 1` trips `FeeExceedsCap(basis/100 + 1, basis/100)` (the basis is passed here independently).
    function _crossCheck(address t, bytes[] memory calls, uint256[] memory basis) internal {
        (bytes4[] memory s, uint8[] memory c,) = MetaTokenBase(t).mtxSelectors();
        assertEq(calls.length, s.length);
        for (uint256 i; i < s.length; ++i) {
            assertEq(bytes4(calls[i]), s[i]);
            MetaTxLib.MetaTransaction memory m;
            bytes memory sig;
            if (c[i] == 1) {
                (m, sig) = _m(t, calls[i], RR | PCT, 1);
                vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, s[i], RR | PCT));
            } else {
                assertEq(c[i], 2);
                (m, sig) = _m(t, calls[i], RR | FIX, basis[i] / 100 + 1);
                vm.expectRevert(abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, basis[i] / 100 + 1, basis[i] / 100));
            }
            vm.prank(relayer);
            MetaTokenBase(t).mtxExecute(m, sig);
        }
    }

    function test_none_classAndBasisMatchTheRule() public {
        bytes[] memory k = new bytes[](2);
        uint256[] memory b = new uint256[](2);
        k[0] = abi.encodeCall(IMetaTx.cancelNonce, (99));
        (k[1], b[1]) = (abi.encodeCall(NoUnderlyingToken.burn, (3e6)), 3e6);
        _crossCheck(address(none), k, b);
    }

    /// P1d: one implementation, so one rule for every leg count; all six entries need a one-leg token (with more
    /// legs the single-asset rows revert `UnderlyingRequired` before the AMOUNT cap is checked).
    function test_underlying_classAndBasisMatchTheRule() public {
        vm.prank(alice);
        single.wrap(10e6);
        bytes[] memory k = new bytes[](6);
        uint256[] memory b = new uint256[](6);
        k[0] = abi.encodeCall(IMetaTx.cancelNonce, (99));
        k[1] = abi.encodeWithSignature("wrap(uint256)", 10e6);
        (k[2], b[2]) = (abi.encodeWithSignature("unwrap(uint256,address,uint256)", 3e6, alice, 1e6), 3e6);
        k[3] = abi.encodeWithSignature("wrap(address,uint256)", address(u), 10e6);
        // basis = arg 1 (`wrapped`), not arg 0 (an address) or arg 3 (`minOut`)
        (k[4], b[4]) = (abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(u), 3e6, alice, 1e6), 3e6);
        k[5] = abi.encodeWithSignature("addReserve(address,uint256)", address(u), 1e6);
        _crossCheck(address(single), k, b);
    }

    // ------------------------------------------------------------------ never allowlisted

    function test_refusedEverywhere() public {
        address[3] memory ts = [address(none), address(single), address(multi)];
        for (uint256 i; i < 3; ++i) {
            address t = ts[i];
            _refused(t, abi.encodeWithSignature("transfer(address,uint256)", address(1), 1));
            _refused(t, abi.encodeWithSignature("transferFrom(address,address,uint256)", alice, address(1), 1));
            _refused(t, abi.encodeWithSignature("approve(address,uint256)", address(this), 1));
            _refused(t, abi.encodeWithSignature("payWithFee(address,uint256,uint8,uint256,address,bytes32)",
                address(1), 1, 0, 0, address(0), bytes32(0)));
            _refused(t, abi.encodeWithSignature("initialize(address,address[],uint64,bytes)",
                alice, new address[](0), 1, ""));
            _refused(t, abi.encodeWithSelector(IMetaTx.mtxExecute.selector));
            _refused(t, abi.encodeWithSelector(IMetaTx.executeMetaTransaction.selector));
            _refused(t, abi.encodeWithSelector(IMetaTx.mtxBatch.selector));
            _refused(t, abi.encodeWithSelector(MetaTokenBase.mtxTransfer.selector));
            _refused(t, abi.encodeWithSelector(MetaTokenBase.mtxTransferWithFee.selector));
            _refused(t, abi.encodeWithSelector(MetaTokenBase.mtxPay.selector));
            _refused(t, abi.encodeWithSelector(MetaTokenBase.mtxExecuteWithFee.selector));
            _refused(t, abi.encodeWithSelector(IERC20MetaTx.mtxExecuteTransfer.selector));
            _refused(t, abi.encodeWithSelector(IERC20MetaTx.mtxBatchTransfer.selector));
            _refused(t, abi.encodeWithSelector(MetaTokenBase.mtxPayReceiverFee.selector));
        }
        _refused(address(none), abi.encodeCall(NoUnderlyingToken.mint, (alice, 1)));
        _refused(address(none), abi.encodeCall(ITokenAdmin.renounceRole, (1)));
        _refused(address(single), abi.encodeWithSignature("unwrap(uint256,address)", 1, alice));
        _refused(address(single), abi.encodeWithSignature("proposeRate(address,uint96,uint96)", address(u), 1, 1));
        _refused(address(single), abi.encodeWithSignature("cancelRate()"));
        _refused(address(single), abi.encodeWithSignature("executeRate()"));
        _refused(address(single), abi.encodeCall(ITokenAdmin.renounceRole, (3)));
        _refused(address(multi), abi.encodeWithSignature("unwrap(uint256,address)", 1, alice));
        _refused(address(multi), abi.encodeWithSignature("proposeRate(address,uint96,uint96)", address(u), 1, 1));
        _refused(address(multi), abi.encodeWithSignature("cancelRate()"));
        _refused(address(multi), abi.encodeWithSignature("executeRate()"));
        _refused(address(multi), abi.encodeCall(ITokenAdmin.renounceRole, (3)));
        _refused(address(multi), abi.encodeWithSignature("disableWrap(address,bytes32)", address(u), bytes32(0)));
        _refused(address(multi), abi.encodeCall(ITokenAdmin.renounceRole, (4)));
    }

    function test_wrongStaticLength_refused() public {
        bytes memory data = abi.encodePacked(abi.encodeWithSignature("wrap(uint256)", 1), uint8(0));
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) = _m(address(single), data, RR, 0);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(keccak256("wrap(uint256)"))));
        single.mtxExecute(m, sig);
    }

    // ------------------------------------------------------------------ all or nothing, re-entry

    function test_wrapPaysItsAbsoluteFeeFromMintedUnits() public {
        assertEq(single.balanceOf(alice), 0);
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) =
            _m(address(single), abi.encodeWithSignature("wrap(uint256)", 10e6), RR | FIX, 3e6); // 30 %: uncapped
        vm.prank(relayer);
        single.mtxExecute(m, sig);
        assertEq(single.balanceOf(alice), 7e6);
        assertEq(single.balanceOf(relayer), 3e6);
        assertEq(u.balanceOf(alice), 990e6);                 // pulled from the signer, not the relayer
    }

    function test_innerRevertBubbles_laneUntouched() public {
        _run(address(single), abi.encodeWithSignature("wrap(uint256)", 10e6));
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) =
            _m(address(single), abi.encodeWithSignature("unwrap(uint256,address,uint256)", 1e6, alice, 2e6), RR, 0);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnwrapBelowMin.selector, 1e6, 2e6));
        single.mtxExecute(m, sig);
        assertEq(single.mtxNonce(alice, m.batch), 0);
    }

    function test_reentryFromUnderlyingHook_reverts() public {
        ReenteringERC20 bad = new ReenteringERC20();
        UnderlyingToken w = UnderlyingToken(
            Clones.clone(address(new UnderlyingToken(address(this), address(0), UID, false))));
        Rate memory cfg;
        address[] memory one = new address[](1);
        one[0] = address(bad);
        uint256[] memory r1 = new uint256[](1);
        r1[0] = 1;
        w.initialize(address(this), one, 1, abi.encode(underlyingInit(one, r1, r1, 6, cfg, address(0), address(0))));
        bad.mint(alice, 10e6);
        vm.prank(alice);
        bad.approve(address(w), 10e6);
        bad.arm(address(w));
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) =
            _m(address(w), abi.encodeWithSignature("wrap(uint256)", 1e6), RR, 0);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        w.mtxExecute(m, sig);
    }
}
