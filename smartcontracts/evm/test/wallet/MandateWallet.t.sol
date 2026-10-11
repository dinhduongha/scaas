// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {V2Fixture, UID_, noneInit} from "../v2/helpers/V2Fixture.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {HederaMandateWallet} from "../../src/hedera/HederaMandateWallet.sol";
import {MockHederaAccountService} from "../hedera/HederaMocks.sol";

/// A "token" whose `payWithFee` answers false without moving anything.
contract FalsePayToken {
    function payWithFee(address, uint256, FeeMode, uint256, address, bytes32) external pure returns (bool) {
        return false;
    }
}

/// A `MandateWallet` of `owner` holding 10 000 of a kind-NONE token, a mandate for `delegate` (1 000 per payment,
/// 2 500 per day, 30 days) and one approved payee; chain 7622 with its real `chain_uid`.
abstract contract MandateFixture is V2Fixture {
    uint256 internal constant OWNER_PK = 0x0A11CE;
    uint256 internal constant DELEGATE_PK = 0xDE1E;
    address internal owner = vm.addr(OWNER_PK);
    address internal delegate = vm.addr(DELEGATE_PK);
    address internal npp = address(0x4EE);
    address internal stranger = address(0x5745);
    NoUnderlyingToken internal t;
    MandateWallet internal w;

    function setUp() public virtual {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        t = _none(address(this), 0, address(this));
        w = new MandateWallet(owner, UID_);
        t.mint(address(w), 10_000);
        vm.startPrank(owner);
        w.setMandate(address(t), delegate, 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));
        w.setPayee(address(t), npp, true);
        vm.stopPrank();
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// The `MetaTransaction` `mtxPayUnderMandate` builds.
    function _payM(address payee, uint256 amount, bytes32 ref) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m.from = delegate;
        m.data = abi.encodeCall(MandateWallet.payUnderMandate, (address(t), payee, amount, ref));
        m.batch = w.mandatePayLane(ref);
        m.validUntil = block.timestamp + 300;
    }

    function _pay(address payee, uint256 amount, bytes32 ref) internal {
        _payExpect(payee, amount, ref, "");
    }

    /// Signed by the delegate, submitted through the named entry by a relayer.
    function _payExpect(address payee, uint256 amount, bytes32 ref, bytes memory err) internal {
        MetaTxLib.MetaTransaction memory m = _payM(payee, amount, ref);
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(relayer);
        w.mtxPayUnderMandate(address(t), payee, amount, ref, m.validUntil, sig);
    }

    function _owner(bytes memory data) internal {
        uint256 n = w.mtxNonce(owner, 0);
        uint256 vu = block.timestamp + 300;
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.nonce, m.validUntil) = (owner, data, n, vu);
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.prank(relayer);
        w.mtxExecuteAsOwner(data, n, vu, sig);
    }

}

/// CTR-ACC-06, CTR-ACC-07 on `MetaTxBase` (CTR-MTX-22): every limit of a delegated payment, the epoch-bound signed
/// revoke, the owner's calls, the named builders and their lanes, the allowlist; ported from the built tests
/// (`legacy/p4/test/MandateWallet.t.sol`) onto a token of the new tree.
contract MandateWalletTest is MandateFixture {
    // ------------------------------------------------------------------ the delegate's payment

    function test_pays_within_mandate_and_settles_like_a_manual_payment() public {
        vm.expectEmit(true, true, true, true, address(t));
        emit IERC20Payment.PaymentSettled(address(w), npp, 700, 0, address(0), keccak256("inv-1"));
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.PaidUnderMandate(address(t), npp, 700, keccak256("inv-1"));
        _pay(npp, 700, keccak256("inv-1"));
        assertEq(t.balanceOf(npp), 700);
        assertEq(t.balanceOf(address(w)), 9_300);
        assertTrue(w.refUsed(keccak256("inv-1")));
        assertEq(w.mtxNonce(delegate, w.mandatePayLane(keccak256("inv-1"))), 1);
    }

    /// One signature, one digest: the named entry and `mtxExecute` run the same struct on the same lane.
    function test_named_entry_is_mtxExecute() public {
        MetaTxLib.MetaTransaction memory m = _payM(npp, 10, keccak256("same"));
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.prank(relayer);
        w.mtxExecute(m, sig);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxPayUnderMandate(address(t), npp, 10, keccak256("same"), m.validUntil, sig);
    }

    function test_per_payment_cap_and_zero() public {
        _payExpect(npp, 1_001, keccak256("big"), abi.encodeWithSelector(MandateWallet.OverPaymentCap.selector, 1_001, 1_000));
        _payExpect(npp, 0, keccak256("zero"), abi.encodeWithSelector(MandateWallet.OverPaymentCap.selector, 0, 1_000));
        _pay(npp, 1_000, keccak256("exact"));
    }

    function test_per_period_cap_and_rollover() public {
        _pay(npp, 1_000, keccak256("a"));
        _pay(npp, 1_000, keccak256("b"));
        _payExpect(npp, 600, keccak256("c"), abi.encodeWithSelector(MandateWallet.OverPeriodCap.selector, 2_600, 2_500));
        _pay(npp, 500, keccak256("d"));                       // exactly the cap
        vm.warp(block.timestamp + 1 days - 1);
        _payExpect(npp, 1, keccak256("e"), abi.encodeWithSelector(MandateWallet.OverPeriodCap.selector, 2_501, 2_500));
        vm.warp(block.timestamp + 1);                        // the period ends at periodStart + periodSeconds
        _pay(npp, 600, keccak256("c"));
        (,,, uint64 start,,, uint128 spent) = w.mandates(address(t));
        assertEq(start, block.timestamp);
        assertEq(spent, 600);
        assertEq(t.balanceOf(npp), 3_100);
    }

    function test_payee_not_allowed_and_removed() public {
        _payExpect(stranger, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.PayeeNotAllowed.selector, stranger));
        _owner(abi.encodeCall(MandateWallet.setPayee, (address(t), npp, false)));
        _payExpect(npp, 10, keccak256("y"), abi.encodeWithSelector(MandateWallet.PayeeNotAllowed.selector, npp));
    }

    function test_payee_is_per_token() public {
        NoUnderlyingToken t2 = _none(address(this), 0, address(this));
        t2.mint(address(w), 100);
        vm.prank(owner);
        w.setMandate(address(t2), delegate, 10, 10, 1 days, uint64(block.timestamp + 1 days));
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.batch, m.validUntil) = (delegate, w.mandatePayLane("t2"), block.timestamp + 300);
        m.data = abi.encodeCall(MandateWallet.payUnderMandate, (address(t2), npp, 5, bytes32("t2")));
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.PayeeNotAllowed.selector, npp));
        w.mtxExecute(m, sig);
    }

    function test_expired_mandate() public {
        vm.warp(block.timestamp + 30 days);                  // at the expiry: still live
        _pay(npp, 10, keccak256("last"));
        vm.warp(block.timestamp + 1);
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.MandateExpired.selector));
    }

    function test_expired_delegate_signature() public {
        MetaTxLib.MetaTransaction memory m = _payM(npp, 10, keccak256("x"));
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.warp(m.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, m.validUntil, m.validUntil + 1));
        w.mtxPayUnderMandate(address(t), npp, 10, keccak256("x"), m.validUntil, sig);
    }

    /// `entryRef` pays once per wallet, also on another lane through `mtxExecute`.
    function test_entry_ref_pays_once() public {
        _pay(npp, 10, keccak256("once"));
        _payExpect(npp, 10, keccak256("once"), abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        MetaTxLib.MetaTransaction memory m = _payM(npp, 10, keccak256("once"));
        m.batch = 77;
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.RefAlreadyPaid.selector, keccak256("once")));
        w.mtxExecute(m, sig);
    }

    function test_signer_must_be_the_delegate() public {
        // the owner signing a delegate's payment: a valid signature of the wrong party
        MetaTxLib.MetaTransaction memory m = _payM(npp, 10, keccak256("x"));
        m.from = owner;
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.mtxExecute(m, sig);
        // a stranger's signature under the delegate's name
        sig = _sig(0xBAD, w.mtxDigest(_payM(npp, 10, keccak256("x"))));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(address(t), npp, 10, keccak256("x"), block.timestamp + 300, sig);
        // and the delegate calling directly is the delegate (it pays its own gas)
        vm.prank(delegate);
        w.payUnderMandate(address(t), npp, 10, keccak256("direct"));
        vm.prank(stranger);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.payUnderMandate(address(t), npp, 10, keccak256("direct2"));
    }

    function test_signature_binds_amount_payee_ref_and_token() public {
        uint256 vu = block.timestamp + 300;
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(_payM(npp, 10, keccak256("x"))));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(address(t), npp, 999, keccak256("x"), vu, sig);
        vm.prank(owner);
        w.setPayee(address(t), stranger, true);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(address(t), stranger, 10, keccak256("x"), vu, sig);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);  // another ref: another lane and another digest
        w.mtxPayUnderMandate(address(t), npp, 10, keccak256("y"), vu, sig);
    }

    /// A new delegate voids what the old one signed (the struct's `from` is the current delegate).
    function test_new_delegate_voids_old_signatures() public {
        MetaTxLib.MetaTransaction memory m = _payM(npp, 10, keccak256("old"));
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.prank(owner);
        w.setMandate(address(t), stranger, 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(address(t), npp, 10, keccak256("old"), m.validUntil, sig);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.mtxExecute(m, sig);
    }

    // ------------------------------------------------------------------ revocation (CTR-ACC-07)

    function _revokeSig(uint64 e) internal view returns (MetaTxLib.MetaTransaction memory m, bytes memory sig) {
        m.from = delegate;
        m.data = abi.encodeWithSignature("revoke(address,uint64)", address(t), e);
        m.batch = w.mandateRevokeLane(address(t), e);
        m.validUntil = block.timestamp + 300;
        sig = _sig(DELEGATE_PK, w.mtxDigest(m));
    }

    function test_owner_revoke_kills_it_and_bumps_the_epoch() public {
        assertEq(w.epoch(address(t)), 1);
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.MandateRevoked(address(t), owner);
        vm.prank(owner);
        w.revoke(address(t));
        assertEq(w.epoch(address(t)), 2);
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.NoMandate.selector));
        vm.prank(delegate);
        vm.expectRevert(MandateWallet.NoMandate.selector);
        w.payUnderMandate(address(t), npp, 10, keccak256("x"));
    }

    /// A token that answers false moved nothing: the payment reverts, so `entryRef` and the period stay unspent.
    function test_pay_failed_reverts_everything() public {
        FalsePayToken f = new FalsePayToken();
        vm.startPrank(owner);
        w.setMandate(address(f), delegate, 10, 10, 1 days, uint64(block.timestamp + 1 days));
        w.setPayee(address(f), npp, true);
        vm.stopPrank();
        vm.prank(delegate);
        vm.expectRevert(MandateWallet.PayFailed.selector);
        w.payUnderMandate(address(f), npp, 10, keccak256("f"));
        assertFalse(w.refUsed(keccak256("f")));
    }

    function test_delegate_signed_revoke_kills_it() public {
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) = _revokeSig(1);
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.MandateRevoked(address(t), delegate);
        vm.prank(relayer);
        w.mtxRevoke(address(t), 1, m.validUntil, sig);
        assertEq(w.epoch(address(t)), 2);
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.NoMandate.selector));
        vm.expectRevert(MandateWallet.NoMandate.selector);
        w.mtxRevoke(address(t), 1, m.validUntil, sig);
    }

    /// The replay CTR-ACC-07 closes: a public revoke signature cannot delete a mandate the owner re-established.
    function test_revoke_signature_is_bound_to_its_epoch() public {
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) = _revokeSig(1);
        vm.startPrank(owner);
        w.revoke(address(t));                                                     // epoch 2
        w.setMandate(address(t), delegate, 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));  // epoch 3
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxRevoke(address(t), 1, m.validUntil, sig);
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxExecute(m, sig);
        _pay(npp, 10, keccak256("alive"));
        // a current-epoch revoke works; its replay is the used lane
        (m, sig) = _revokeSig(3);
        w.mtxRevoke(address(t), 3, m.validUntil, sig);
        vm.prank(owner);
        w.setMandate(address(t), delegate, 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));  // epoch 5
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxRevoke(address(t), 3, m.validUntil, sig);
    }

    function test_only_the_delegate_revokes_by_signature() public {
        vm.prank(stranger);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.revoke(address(t), 1);
        vm.prank(owner);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.revoke(address(t), 1);
        bytes memory bad = _sig(0xBAD, w.mtxDigest(_revokeSigM(1)));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxRevoke(address(t), 1, block.timestamp + 300, bad);
    }

    function _revokeSigM(uint64 e) internal view returns (MetaTxLib.MetaTransaction memory m) {
        (m,) = _revokeSig(e);
    }

    // ------------------------------------------------------------------ the owner

    function test_mandate_parameters_are_validated() public {
        vm.startPrank(owner);
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), delegate, 1_000, 2_500, 0, uint64(block.timestamp + 1 days));
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), delegate, 3_000, 2_500, 1 days, uint64(block.timestamp + 1 days));
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), address(0), 1_000, 2_500, 1 days, uint64(block.timestamp + 1 days));
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), delegate, 0, 2_500, 1 days, uint64(block.timestamp + 1 days));
        w.setMandate(address(t), delegate, 2_500, 2_500, 1 days, uint64(block.timestamp + 1 days));
        vm.stopPrank();
        assertEq(w.epoch(address(t)), 2);
        vm.expectRevert(MandateWallet.ZeroOwner.selector);
        new MandateWallet(address(0), UID_);
    }

    function test_owner_only_functions() public {
        vm.startPrank(delegate);
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.setPayee(address(t), stranger, true);
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.setMandate(address(t), delegate, 1, 1, 1, 1);
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.revoke(address(t));
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.execute(address(t), 0, "");
        vm.stopPrank();
        // the delegate's own signature does not make it the owner
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.validUntil) = (delegate, abi.encodeCall(MandateWallet.setPayee, (address(t), stranger, true)),
            block.timestamp + 300);
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.mtxExecute(m, sig);
    }

    function test_owner_configures_gasless() public {
        bytes memory data = abi.encodeCall(MandateWallet.setPayee, (address(t), stranger, true));
        uint256 vu = block.timestamp + 300;
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.validUntil) = (owner, data, vu);
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.prank(relayer);
        w.mtxExecuteAsOwner(data, 0, vu, sig);
        assertTrue(w.payeeAllowed(address(t), stranger));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxExecuteAsOwner(data, 0, vu, sig);
        bytes memory foreign = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxExecuteAsOwner(data, 0, vu, foreign);
        m.nonce = 1;
        foreign = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxExecuteAsOwner(data, 1, vu, foreign);
    }

    function test_owner_executes_and_cannot_reenter() public {
        _owner(abi.encodeCall(MandateWallet.execute, (address(t), 0, abi.encodeCall(t.transfer, (owner, 100)))));
        assertEq(t.balanceOf(owner), 100);
        bytes memory inner = abi.encodeCall(MandateWallet.setPayee, (address(t), stranger, true));
        uint256 vu = block.timestamp + 300;
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.nonce, m.validUntil) =
            (owner, abi.encodeCall(MandateWallet.execute, (address(w), 0, inner)), 1, vu);
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.CallFailed.selector,
            abi.encodeWithSelector(IMetaTx.Reentrancy.selector)));
        w.mtxExecuteAsOwner(m.data, 1, vu, sig);
    }

    /// The owner still pays by hand from the wallet: a `MetaTransfer` with `from = wallet`, ERC-1271 by the owner.
    function test_owner_still_pays_manually_through_meta_tx() public {
        bytes32 ref = keccak256("manual");
        MetaTxLib.MetaTransfer memory x = _tr(address(w), npp, 50, ref, t.payLane(ref), RR);
        bytes memory sig = _sig(OWNER_PK, t.mtxTransferDigest(x));
        vm.prank(relayer);
        t.mtxExecuteTransfer(x, sig);
        assertEq(t.balanceOf(npp), 50);
        x = _tr(address(w), npp, 50, keccak256("d"), 1, RR);
        sig = _sig(DELEGATE_PK, t.mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxExecuteTransfer(x, sig);
    }

    /// The delegated path never uses an allowance: no `approve` / `transferFrom` / `permit` / `increaseAllowance`
    /// selector anywhere in the wallet's bytecode.
    function test_bytecode_has_no_allowance_selectors() public view {
        bytes memory code = address(w).code;
        bytes4[4] memory banned = [bytes4(0x095ea7b3), 0x23b872dd, 0xd505accf, 0x39509351];
        for (uint256 b = 0; b < banned.length; b++) {
            for (uint256 i = 0; i + 4 <= code.length; i++) {
                bool hit = code[i] == banned[b][0] && code[i + 1] == banned[b][1]
                    && code[i + 2] == banned[b][2] && code[i + 3] == banned[b][3];
                assertFalse(hit, "allowance selector in MandateWallet bytecode");
            }
        }
    }

    // ------------------------------------------------------------------ the base (CTR-MTX-19/21/22, MT-4)

    function test_allowlistPinned() public view {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = w.mtxSelectors();
        bytes4[7] memory want = [IMetaTx.cancelNonce.selector,
            bytes4(keccak256("payUnderMandate(address,address,uint256,bytes32)")),
            bytes4(keccak256("revoke(address,uint64)")),
            bytes4(keccak256("setMandate(address,address,uint128,uint128,uint64,uint64)")),
            bytes4(keccak256("setPayee(address,address,bool)")),
            bytes4(keccak256("revoke(address)")),
            bytes4(keccak256("execute(address,uint256,bytes)"))];
        assertEq(s.length, 7);
        for (uint256 i; i < 7; ++i) {
            assertEq(s[i], want[i]);
            assertEq(c[i], 1);
            assertEq(a[i], 0);
        }
        assertEq(w.supportedModes(), 0x03);
    }

    function _signedFails(bytes memory data, bytes memory err) internal {
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.batch, m.validUntil) = (owner, data, 5, block.timestamp + 300);
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(err);
        w.mtxExecute(m, sig);
    }

    function test_unlistedSelectorsAndShapes() public {
        bytes[4] memory calls = [
            abi.encodeCall(MandateWallet.mtxExecuteAsOwner, ("", 0, 0, "")),
            abi.encodeCall(MandateWallet.mtxPayUnderMandate, (address(t), npp, 1, 0, 0, "")),
            abi.encodeCall(MandateWallet.mtxRevoke, (address(t), 1, 0, "")),
            abi.encodeCall(MandateWallet.isValidSignature, (bytes32(0), ""))
        ];
        for (uint256 i; i < calls.length; ++i) {
            _signedFails(calls[i], abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(calls[i])));
        }
        bytes memory sp = abi.encodeCall(MandateWallet.setPayee, (address(t), stranger, true));
        assertEq(sp.length, 100);
        _signedFails(abi.encodePacked(sp, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(sp)));
        bytes memory pu = abi.encodeCall(MandateWallet.payUnderMandate, (address(t), npp, 1, 0));
        assertEq(pu.length, 132);
        _signedFails(abi.encodePacked(pu, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(pu)));
        bytes memory sm = abi.encodeCall(MandateWallet.setMandate, (address(t), delegate, 1, 1, 1, 1));
        assertEq(sm.length, 196);
        _signedFails(abi.encodePacked(sm, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(sm)));
        bytes memory r2 = abi.encodeWithSignature("revoke(address,uint64)", address(t), uint64(1));
        _signedFails(abi.encodePacked(r2, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(r2)));
        bytes memory r1 = abi.encodeWithSignature("revoke(address)", address(t));
        _signedFails(abi.encodePacked(r1, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(r1)));
    }

    function test_feeModesAndSelfSender() public {
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.validUntil, m.mode) =
            (owner, abi.encodeCall(IMetaTx.cancelNonce, (1)), block.timestamp + 300, MetaTxLib.MODE_FEE_PERCENT);
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, IMetaTx.cancelNonce.selector, m.mode));
        w.mtxExecute(m, sig);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, m.mode));
        w.mtxExecute(m, sig);
        // the wallet is not a self-signer: `from = wallet` is refused at step 1 even with the owner's 1271 signature
        m.mode = 0;
        m.from = address(w);
        sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(IMetaTx.SelfSender.selector);
        w.mtxExecute(m, sig);
    }

    function test_domainAndLanes() public view {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt_,) = w.eip712Domain();
        assertEq(name, "SCaaS MandateWallet");
        assertEq(version, "1");
        assertEq(chainId, 7622);
        assertEq(vc, address(w));
        assertEq(salt_, UID_);
        assertEq(w.chainUid(), UID_);
        assertEq(w.mandatePayLane(keccak256("r")), uint256(keccak256(abi.encodePacked("scaas.mandate.pay", keccak256("r")))));
        assertEq(w.mandateRevokeLane(address(t), 3),
            uint256(keccak256(abi.encodePacked("scaas.mandate.revoke", address(t), uint64(3)))));
        assertEq(w.mandateRevokeLane(address(t), 3), uint256(keccak256(bytes.concat(
            bytes("scaas.mandate.revoke"), bytes20(address(t)), bytes8(uint64(3))))));
    }

    function test_noMandateOnTheNamedEntries() public {
        vm.prank(owner);
        w.revoke(address(t));
        vm.expectRevert(MandateWallet.NoMandate.selector);
        w.mtxPayUnderMandate(address(t), npp, 1, 0, block.timestamp, "");
        vm.expectRevert(MandateWallet.NoMandate.selector);
        w.mtxRevoke(address(t), 2, block.timestamp, "");
    }

    function test_gas() public {
        MetaTxLib.MetaTransaction memory m = _payM(npp, 700, keccak256("g"));
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.prank(relayer);
        uint256 g = gasleft();
        w.mtxPayUnderMandate(address(t), npp, 700, keccak256("g"), m.validUntil, sig);
        emit log_named_uint("mtxPayUnderMandate (first payment of the period)", g - gasleft());
    }
}

/// NET-HED-03: an ED25519 owner (no code, 64-byte signature) through HIP-632 over the same `MetaTransaction` digest
/// and lane; the delegate stays ECDSA; ERC-1271 for the owner stays ECDSA.
contract HederaMandateWalletTest is MandateFixture {
    address constant HAS = address(0x16a);
    uint256 constant ED_KEY = 0x0E1;
    address edOwner;
    HederaMandateWallet hw;

    function setUp() public override {
        super.setUp();
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        edOwner = address(uint160(2_000_001));
        MockHederaAccountService(HAS).setEdKey(edOwner, vm.addr(ED_KEY));
        hw = new HederaMandateWallet(edOwner, UID_);
        t.mint(address(hw), 1_000);
    }

    function _ed(bytes32 d) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 vs) = vm.signCompact(ED_KEY, d);
        return abi.encodePacked(r, vs);
    }

    function _edOwnerCall(bytes memory data, uint256 nonce) internal returns (MetaTxLib.MetaTransaction memory m) {
        (m.from, m.data, m.nonce, m.validUntil) = (edOwner, data, nonce, block.timestamp + 300);
    }

    function test_ed25519OwnerSetsMandateAndPaysByHand() public {
        MetaTxLib.MetaTransaction memory m = _edOwnerCall(abi.encodeCall(MandateWallet.setMandate,
            (address(t), delegate, 100, 300, 1 days, uint64(block.timestamp + 30 days))), 0);
        bytes memory sig = _ed(hw.mtxDigest(m));
        vm.prank(relayer);
        hw.mtxExecuteAsOwnerRaw(m.data, 0, m.validUntil, sig);
        (address d,,,,,,) = hw.mandates(address(t));
        assertEq(d, delegate);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        hw.mtxExecuteAsOwnerRaw(m.data, 0, m.validUntil, sig);
        // pays by hand: an owner call `execute(token, payWithFee…)`, on the same lane as `mtxExecuteAsOwner`
        bytes memory pay = abi.encodeCall(IERC20Payment.payWithFee, (npp, 40, FeeMode.NONE, 0, address(0), keccak256("hand")));
        m = _edOwnerCall(abi.encodeCall(MandateWallet.execute, (address(t), 0, pay)), 1);
        sig = _ed(hw.mtxDigest(m));
        hw.mtxExecuteAsOwner(m.data, 1, m.validUntil, sig);
        assertEq(t.balanceOf(npp), 40);
    }

    function test_ed25519OwnerRefusals() public {
        MetaTxLib.MetaTransaction memory m = _edOwnerCall(abi.encodeCall(MandateWallet.setPayee, (address(t), npp, true)), 0);
        (bytes32 r, bytes32 vs) = vm.signCompact(DELEGATE_PK, hw.mtxDigest(m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        hw.mtxExecuteAsOwnerRaw(m.data, 0, m.validUntil, abi.encodePacked(r, vs));
        bytes memory sig = _ed(hw.mtxDigest(m));
        vm.warp(m.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, m.validUntil, m.validUntil + 1));
        hw.mtxExecuteAsOwnerRaw(m.data, 0, m.validUntil, sig);
    }

    /// ERC-1271 runs under STATICCALL, where HIP-632 halts: a `MetaTransfer` with `from = wallet` and the ED25519
    /// owner's signature fails, as specified.
    function test_ed25519OwnerCannotSignAs1271() public {
        MetaTxLib.MetaTransfer memory x = _tr(address(hw), npp, 5, keccak256("1271"), 3, RR);
        bytes memory sig = _ed(t.mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxExecuteTransfer(x, sig);
    }

    function test_delegatePaysUnderMandateSetByEd25519Owner() public {
        MetaTxLib.MetaTransaction memory m = _edOwnerCall(abi.encodeCall(MandateWallet.setMandate,
            (address(t), delegate, 100, 300, 1 days, uint64(block.timestamp + 30 days))), 0);
        hw.mtxExecuteAsOwnerRaw(m.data, 0, m.validUntil, _ed(hw.mtxDigest(m)));
        m = _edOwnerCall(abi.encodeCall(MandateWallet.setPayee, (address(t), npp, true)), 1);
        hw.mtxExecuteAsOwnerRaw(m.data, 1, m.validUntil, _ed(hw.mtxDigest(m)));
        MetaTxLib.MetaTransaction memory p;
        (p.from, p.batch, p.validUntil) = (delegate, hw.mandatePayLane(bytes32(uint256(7))), block.timestamp + 300);
        p.data = abi.encodeCall(MandateWallet.payUnderMandate, (address(t), npp, 50, bytes32(uint256(7))));
        bytes memory sig = _sig(DELEGATE_PK, hw.mtxDigest(p));
        hw.mtxPayUnderMandate(address(t), npp, 50, bytes32(uint256(7)), p.validUntil, sig);
        assertEq(t.balanceOf(npp), 50);
    }
}
