// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {MtxFixture} from "../helpers/MtxFixture.sol";
import {Puller} from "../helpers/WalletMocks.sol";
import {ERC20MetaTxHarness} from "./helpers/ERC20MetaTxHarness.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeePolicy} from "../../src/common/FeePolicy.sol";

/// `ERC20MetaTx` (CTR-MTX-07, -08, -13, -20, -23, -24; CTR-TOK-01) on a minimal harness.
contract ERC20MetaTxTest is MtxFixture {
    ERC20MetaTxHarness internal t;
    address internal shop = address(0x5409);
    address internal feeTaker = address(0xFEE);
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint32 internal constant RF = MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    uint32 internal constant PCT = MetaTxLib.MODE_FEE_PERCENT;
    uint32 internal constant FIX = MetaTxLib.MODE_FEE_FIXED;

    function setUp() public override {
        super.setUp();
        t = new ERC20MetaTxHarness(UID);
        t.mint(alice, 1_000e6);
    }

    // ------------------------------------------------------------------ helpers

    function _t(address to, uint256 value, bytes32 ref, uint256 batch, uint32 mode, uint256 fee, address feeTo)
        internal view returns (MetaTxLib.MetaTransfer memory)
    {
        return MetaTxLib.MetaTransfer({
            from: alice, to: to, value: value, entryRef: ref, batch: batch, nonce: t.mtxNonce(alice, batch),
            validUntil: block.timestamp + 300, mode: mode, relayer: relayer, fee: fee, feeRecipient: feeTo
        });
    }

    function _signT(MetaTxLib.MetaTransfer memory x) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, t.mtxTransferDigest(x));
        return abi.encodePacked(r, s, v);
    }

    function _call(bytes memory data, uint256 batch, uint32 mode, uint256 fee)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = _m(alice, data, batch, t.mtxNonce(alice, batch));
        m.mode = mode;
        m.relayer = relayer;
        m.fee = fee;
    }

    function _signM(MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, t.mtxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function _xfer(MetaTxLib.MetaTransfer memory x) internal {
        bytes memory s = _signT(x);
        vm.prank(relayer);
        t.mtxExecuteTransfer(x, s);
    }

    function _xferRevert(MetaTxLib.MetaTransfer memory x, bytes memory err) internal {
        bytes memory s = _signT(x);
        vm.prank(relayer);
        vm.expectRevert(err);
        t.mtxExecuteTransfer(x, s);
    }

    function _exec(MetaTxLib.MetaTransaction memory m) internal {
        bytes memory s = _signM(m);
        vm.prank(relayer);
        t.mtxExecute(m, s);
    }

    function _execRevert(MetaTxLib.MetaTransaction memory m, bytes memory err) internal {
        bytes memory s = _signM(m);
        vm.prank(relayer);
        vm.expectRevert(err);
        t.mtxExecute(m, s);
    }

    // ------------------------------------------------------------------ domain, modes

    function test_domainAndModes() public view {
        (bytes1 f, string memory n, string memory v, uint256 cid, address vc, bytes32 salt,) = t.eip712Domain();
        assertEq(f, hex"1f");
        assertEq(n, "SCaaS MetaToken");
        assertEq(v, "1");
        assertEq(cid, 7622);
        assertEq(vc, address(t));
        assertEq(salt, UID);
        assertEq(t.supportedModes(), 0xF3);
        assertEq(t.chainUid(), UID);
    }

    // ------------------------------------------------------------------ typed path

    function test_transfer_movesValueBumpsLaneEmits() public {
        MetaTxLib.MetaTransfer memory x = _t(shop, 100e6, 0, 7, RR, 0, address(0));
        bytes32 d = t.mtxTransferDigest(x);
        vm.expectEmit(address(t));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 7, 0, d, relayer, 0);
        _xfer(x);
        assertEq(t.balanceOf(shop), 100e6);
        assertEq(t.mtxNonce(alice, 7), 1);
        _xferRevert(x, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
    }

    function test_payment_emitsPaymentSettledWithTheRealFee() public {
        bytes32 ref = keccak256("invoice-1");
        MetaTxLib.MetaTransfer memory x = _t(shop, 200e6, ref, 9, RR | PCT, 5_000, address(0)); // 0.5 %
        vm.expectEmit(address(t));
        emit IERC20Payment.PaymentSettled(alice, shop, 200e6, 1e6, relayer, ref);
        _xfer(x);
        assertEq(t.balanceOf(shop), 200e6);
        assertEq(t.balanceOf(relayer), 1e6);
        assertEq(t.balanceOf(alice), 799e6);
    }

    function test_fixedFee_cappedAtOnePercentOfValue() public {
        _xferRevert(_t(shop, 100e6, 0, 1, FIX | RF, 1e6 + 1, feeTaker),
            abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 1e6 + 1, 1e6));
        _xfer(_t(shop, 100e6, 0, 1, FIX | RF, 1e6, feeTaker));
        assertEq(t.balanceOf(feeTaker), 1e6);
    }

    function test_step3Refusals() public {
        _xferRevert(_t(address(0), 1, 0, 1, 0, 0, address(0)), abi.encodeWithSelector(IERC20MetaTx.PayToZero.selector));
        _xferRevert(_t(address(t), 1, 0, 1, 0, 0, address(0)),
            abi.encodeWithSelector(IERC20MetaTx.TransferToSelf.selector));
        // the payee self-relays with a fee (recipient defaults to msg.sender == to)
        MetaTxLib.MetaTransfer memory x = _t(relayer, 100e6, 0, 1, FIX, 1e5, address(0));
        _xferRevert(x, abi.encodeWithSelector(IERC20MetaTx.FeeRecipientIsPayee.selector));
        _xferRevert(_t(shop, 1_000e6, 0, 1, FIX | RF, 1, feeTaker),
            abi.encodeWithSelector(IERC20MetaTx.MetaTxInsufficientForFee.selector, 1_000e6 + 1, 1_000e6));
        assertEq(t.mtxNonce(alice, 1), 0); // nothing consumed
    }

    function test_feeToTheTokenRefused_typedPath() public {
        _xferRevert(_t(shop, 100e6, 0, 1, FIX | RF, 1e5, address(t)),
            abi.encodeWithSelector(IERC20MetaTx.TransferToSelf.selector));
        assertEq(t.mtxNonce(alice, 1), 0);
    }

    function test_restrictedRelayer_otherCallerRefused() public {
        MetaTxLib.MetaTransfer memory x = _t(shop, 1, 0, 1, RR, 0, address(0));
        bytes memory s = _signT(x);
        vm.prank(address(0xCAFE));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, relayer, address(0xCAFE)));
        t.mtxExecuteTransfer(x, s);
    }

    function test_oneLaneForBothStructs() public {
        _xfer(_t(shop, 1e6, 0, 5, RR, 0, address(0)));              // lane 5: nonce 0 → 1
        MetaTxLib.MetaTransaction memory m = _call(abi.encodeCall(ERC20MetaTxHarness.touch, ()), 5, RR, 0);
        assertEq(m.nonce, 1);
        _exec(m);                                                   // lane 5: nonce 1 → 2
        MetaTxLib.MetaTransfer memory stale = _t(shop, 1e6, 0, 5, RR, 0, address(0));
        stale.nonce = 1;
        _xferRevert(stale, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 2, 1));
    }

    function test_batchTransfer_atomic() public {
        MetaTxLib.MetaTransfer[] memory xs = new MetaTxLib.MetaTransfer[](2);
        bytes[] memory ss = new bytes[](2);
        xs[0] = _t(shop, 1e6, 0, 1, RR, 0, address(0));
        xs[1] = _t(feeTaker, 2e6, 0, 2, RR, 0, address(0));
        ss[0] = _signT(xs[0]);
        ss[1] = _signT(xs[1]);
        vm.prank(relayer);
        t.mtxBatchTransfer(xs, ss);
        assertEq(t.balanceOf(shop), 1e6);
        assertEq(t.balanceOf(feeTaker), 2e6);

        xs[0] = _t(shop, 1e6, 0, 3, RR, 0, address(0));
        xs[1] = _t(address(0), 1, 0, 4, RR, 0, address(0));         // second item fails
        ss[0] = _signT(xs[0]);
        ss[1] = _signT(xs[1]);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.PayToZero.selector));
        t.mtxBatchTransfer(xs, ss);
        assertEq(t.mtxNonce(alice, 3), 0);                          // first item rolled back

        vm.expectRevert(IMetaTx.MtxBatchEmpty.selector);
        t.mtxBatchTransfer(new MetaTxLib.MetaTransfer[](0), new bytes[](0));
        vm.expectRevert(IMetaTx.MtxBatchLengthMismatch.selector);
        t.mtxBatchTransfer(xs, new bytes[](1));
    }

    // ------------------------------------------------------------------ fee of a self-call (CTR-MTX-20)

    function test_amountClass_percentOnTheBasis_afterTheCall() public {
        MetaTxLib.MetaTransaction memory m =
            _call(abi.encodeCall(ERC20MetaTxHarness.burn, (100e6)), 1, RR | PCT, 10_000); // 1 % of 100e6
        bytes32 d = t.mtxDigest(m);
        vm.expectEmit(address(t));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 1, 0, d, relayer, 1e6);
        _exec(m);
        assertEq(t.balanceOf(alice), 1_000e6 - 100e6 - 1e6);
        assertEq(t.balanceOf(relayer), 1e6);
    }

    function test_amountClass_fixedCapped() public {
        _execRevert(_call(abi.encodeCall(ERC20MetaTxHarness.burn, (100e6)), 1, RR | FIX, 1e6 + 1),
            abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 1e6 + 1, 1e6));
    }

    function test_absoluteClass_fixedUncapped_percentRefused() public {
        _exec(_call(abi.encodeCall(ERC20MetaTxHarness.touch, ()), 1, RR | FIX | RF, 50e6)
            .withFeeRecipient(feeTaker));
        assertEq(t.balanceOf(feeTaker), 50e6);
        bytes4 sel = ERC20MetaTxHarness.touch.selector;
        _execRevert(_call(abi.encodeCall(ERC20MetaTxHarness.touch, ()), 2, RR | PCT, 1),
            abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, sel, RR | PCT));
    }

    function test_feeToTheTokenRefused_genericPath() public {
        _execRevert(_call(abi.encodeCall(ERC20MetaTxHarness.touch, ()), 1, RR | FIX | RF, 1e6)
            .withFeeRecipient(address(t)), abi.encodeWithSelector(IERC20MetaTx.TransferToSelf.selector));
        assertEq(t.balanceOf(alice), 1_000e6);
        assertEq(t.mtxNonce(alice, 1), 0);
    }

    function test_feeFailureAfterTheCall_revertsTheCall() public {
        // burn everything, then the fee has nothing to come from: the burn is undone, the lane untouched
        _execRevert(_call(abi.encodeCall(ERC20MetaTxHarness.burn, (1_000e6)), 1, RR | PCT, 100),
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, alice, 0, 1e5));
        assertEq(t.balanceOf(alice), 1_000e6);
        assertEq(t.mtxNonce(alice, 1), 0);
    }

    function test_selfCallRunsAsTheSigner() public {
        vm.expectEmit(address(t));
        emit ERC20MetaTxHarness.Touched(alice);
        _exec(_call(abi.encodeCall(ERC20MetaTxHarness.touch, ()), 1, RR, 0));
    }

    function test_transferAndApproveNotAllowlisted() public {
        bytes memory data = abi.encodeCall(t.transfer, (shop, 1));
        _execRevert(_call(data, 1, RR, 0), abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, t.transfer.selector));
        data = abi.encodeCall(t.approve, (address(this), 1));
        _execRevert(_call(data, 1, RR, 0), abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, t.approve.selector));
    }

    // ------------------------------------------------------------------ allowance (CTR-TOK-01)

    function test_approve_callerAndSpenderMustBeContracts() public {
        Puller p = new Puller();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, alice));
        t.approve(address(p), 1);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, alice));
        p.approveOn(address(t), alice, 1);
        t.mint(address(p), 10);
        assertTrue(p.approveOn(address(t), address(this), 10));
        assertEq(t.allowance(address(p), address(this)), 10);
    }

    function test_transferFrom_onlyByAContract() public {
        Puller p = new Puller();
        Puller q = new Puller();
        t.mint(address(q), 10);
        q.approveOn(address(t), address(p), 10);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, alice));
        t.transferFrom(address(q), alice, 1);
        assertTrue(p.pull(address(t), address(q), shop, 10));
        assertEq(t.balanceOf(shop), 10);
    }

    function test_noTokensAtTheTokensAddress() public {
        vm.expectRevert(IERC20MetaTx.TransferToSelf.selector);
        t.mint(address(t), 1);
        vm.prank(alice);
        vm.expectRevert(IERC20MetaTx.TransferToSelf.selector);
        t.transfer(address(t), 1);
    }

    function test_fromTheTokenItselfRefused() public {
        MetaTxLib.MetaTransfer memory x = _t(shop, 1, 0, 1, RR, 0, address(0));
        x.from = address(t);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.SelfSender.selector);
        t.mtxExecuteTransfer(x, new bytes(65));
    }
}

using {withFeeRecipient} for MetaTxLib.MetaTransaction;

function withFeeRecipient(MetaTxLib.MetaTransaction memory m, address r) pure returns (MetaTxLib.MetaTransaction memory) {
    m.feeRecipient = r;
    return m;
}
