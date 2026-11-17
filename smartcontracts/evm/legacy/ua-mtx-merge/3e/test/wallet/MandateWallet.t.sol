// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {V2Fixture, UID_, normalInit} from "../v2/helpers/V2Fixture.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {HederaMandateWallet} from "../../src/hedera/HederaMandateWallet.sol";
import {MockHederaAccountService} from "../hedera/HederaMocks.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {uaDigest, UA_PAY_UNDER_MANDATE, UA_DELEGATE_REVOKE} from "./MandateWalletMerged.t.sol";

/// A "token" whose `payWithFee` answers false without moving anything.
contract FalsePayToken {
    function payWithFee(address, uint256, FeeMode, uint256, address, bytes32) external pure returns (bool) {
        return false;
    }
}

/// A `MandateWallet` of `owner` holding 10 000 of a kind-NORMAL token, a mandate for `delegate` (1 000 per payment,
/// 2 500 per day, 30 days) and one approved payee; chain 7622 with its real `chain_uid`, no registry (every party native).
/// ua-mtx-merge T3b: ids `bytes32` (the EOAs zero-padded), signed entries on `UAEnvelope` + `UASig` (Q6).
abstract contract MandateFixture is V2Fixture {
    uint256 internal constant OWNER_PK = 0x0A11CE;
    uint256 internal constant DELEGATE_PK = 0xDE1E;
    address internal owner = vm.addr(OWNER_PK);
    address internal delegate = vm.addr(DELEGATE_PK);
    address internal npp = address(0x4EE);
    address internal stranger = address(0x5745);
    NormalToken internal t;
    MandateWallet internal w;

    function setUp() public virtual {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        t = _normal(address(this), 0, address(this));
        w = new MandateWallet(_id(owner), UID_, address(0), false);
        t.mint(address(w), 10_000);
        vm.startPrank(owner);
        w.setMandate(address(t), _id(delegate), 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));
        w.setPayee(address(t), _id(npp), true);
        vm.stopPrank();
    }

    function _id(address a) internal pure returns (bytes32) {
        return MetaTxLib.pad(a);
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// A native id's `UASig`: its own signature only.
    function _ua(uint256 pk, bytes32 digest) internal pure returns (IUARegistry.UASig memory a) {
        a.signature = _sig(pk, digest);
    }

    /// The current epoch of `t`: what the delegate's pay names.
    function _e() internal view returns (uint64) {
        return w.epoch(address(t));
    }

    /// The delegate's pay envelope: its mandate lane, nonce 0.
    function _payEnv(bytes32 ref) internal view returns (MetaTxLib.UAEnvelope memory e) {
        e.from = _id(delegate);
        e.batch = w.mandatePayLane(ref);
        e.validUntil = block.timestamp + 300;
    }

    function _payDigest(MandateWallet c, MetaTxLib.UAEnvelope memory e, address token, address payee, uint256 amount,
        bytes32 ref, uint64 ep) internal view returns (bytes32)
    {
        return uaDigest(address(c), UA_PAY_UNDER_MANDATE, e, abi.encode(token, _id(payee), amount, ref, ep));
    }

    /// The generic `UAMetaTransaction` of the delegate's pay on its pay lane (the same op as the named entry).
    function _payM(address payee, uint256 amount, bytes32 ref) internal view returns (MetaTxLib.UAMetaTransaction memory m) {
        m = _gen(_id(delegate), abi.encodeCall(MandateWallet.payUnderMandate, (address(t), _id(payee), amount, ref, _e())),
            w.mandatePayLane(ref), 0);
    }

    function _gen(bytes32 from, bytes memory data, uint256 batch, uint256 nonce)
        internal view returns (MetaTxLib.UAMetaTransaction memory m)
    {
        (m.from, m.data, m.batch, m.nonce, m.validUntil) = (from, data, batch, nonce, block.timestamp + 300);
    }

    function _pay(address payee, uint256 amount, bytes32 ref) internal {
        _payExpect(payee, amount, ref, "");
    }

    /// Signed by the delegate, submitted through the named entry by a relayer.
    function _payExpect(address payee, uint256 amount, bytes32 ref, bytes memory err) internal {
        MetaTxLib.UAEnvelope memory e = _payEnv(ref);
        uint64 ep = _e();
        IUARegistry.UASig memory a = _ua(DELEGATE_PK, _payDigest(w, e, address(t), payee, amount, ref, ep));
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(relayer);
        w.mtxPayUnderMandate(e, address(t), _id(payee), amount, ref, ep, a);
    }

    /// The owner's call through the generic entry, lane 0, relayed.
    function _owner(bytes memory data) internal {
        MetaTxLib.UAMetaTransaction memory m = _gen(_id(owner), data, 0, w.mtxNonce(_id(owner), 0));
        IUARegistry.UASig memory a = _ua(OWNER_PK, w.mtxDigest(m));
        vm.prank(relayer);
        w.mtxExecute(m, a);
    }
}

/// CTR-ACC-06, CTR-ACC-07 on `UAMetaTxBase` (ua-mtx-merge Q6): every limit of a delegated payment, the epoch-bound signed
/// revoke, the owner's calls, the named entries and their lanes, the allowlist; ported from the built tests
/// (`legacy/p4/test/MandateWallet.t.sol`, then `legacy/ua-mtx-merge/test/wallet/MandateWallet.t.sol`).
contract MandateWalletTest is MandateFixture {
    // ------------------------------------------------------------------ the delegate's payment

    function test_pays_within_mandate_and_settles_like_a_manual_payment() public {
        vm.expectEmit(true, true, true, true, address(t));
        emit IERC20Payment.PaymentSettled(address(w), npp, 700, 0, address(0), keccak256("inv-1"));
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.PaidUnderMandate(address(t), _id(npp), 700, keccak256("inv-1"));
        _pay(npp, 700, keccak256("inv-1"));
        assertEq(t.balanceOf(npp), 700);
        assertEq(t.balanceOf(address(w)), 9_300);
        assertTrue(w.refUsed(keccak256("inv-1")));
        assertEq(w.mtxNonce(_id(delegate), w.mandatePayLane(keccak256("inv-1"))), 1);
    }

    /// The named entry and the generic `mtxExecute` share the `(from, batch)` lane; neither signature runs on the other
    /// (two structs, two digests).
    function test_named_entry_and_mtxExecute_share_the_lane() public {
        MetaTxLib.UAMetaTransaction memory m = _payM(npp, 10, keccak256("same"));
        IUARegistry.UASig memory generic = _ua(DELEGATE_PK, w.mtxDigest(m));
        MetaTxLib.UAEnvelope memory e = _payEnv(keccak256("same"));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(e, address(t), _id(npp), 10, keccak256("same"), 1, generic);
        vm.prank(relayer);
        w.mtxExecute(m, generic);
        IUARegistry.UASig memory named = _ua(DELEGATE_PK, _payDigest(w, e, address(t), npp, 10, keccak256("same"), 1));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxPayUnderMandate(e, address(t), _id(npp), 10, keccak256("same"), 1, named);
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
        _payExpect(stranger, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.PayeeNotAllowed.selector, _id(stranger)));
        _owner(abi.encodeCall(MandateWallet.setPayee, (address(t), _id(npp), false)));
        _payExpect(npp, 10, keccak256("y"), abi.encodeWithSelector(MandateWallet.PayeeNotAllowed.selector, _id(npp)));
    }

    function test_payee_is_per_token() public {
        NormalToken t2 = _normal(address(this), 0, address(this));
        t2.mint(address(w), 100);
        vm.prank(owner);
        w.setMandate(address(t2), _id(delegate), 10, 10, 1 days, uint64(block.timestamp + 1 days));
        MetaTxLib.UAMetaTransaction memory m = _gen(_id(delegate),
            abi.encodeCall(MandateWallet.payUnderMandate, (address(t2), _id(npp), 5, bytes32("t2"), 1)), w.mandatePayLane("t2"), 0);
        IUARegistry.UASig memory a = _ua(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.PayeeNotAllowed.selector, _id(npp)));
        w.mtxExecute(m, a);
    }

    function test_expired_mandate() public {
        vm.warp(block.timestamp + 30 days);                  // at the expiry: still live
        _pay(npp, 10, keccak256("last"));
        vm.warp(block.timestamp + 1);
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.MandateExpired.selector));
    }

    function test_expired_delegate_signature() public {
        MetaTxLib.UAEnvelope memory e = _payEnv(keccak256("x"));
        IUARegistry.UASig memory a = _ua(DELEGATE_PK, _payDigest(w, e, address(t), npp, 10, keccak256("x"), 1));
        vm.warp(e.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, e.validUntil, e.validUntil + 1));
        w.mtxPayUnderMandate(e, address(t), _id(npp), 10, keccak256("x"), 1, a);
    }

    /// `entryRef` pays once per wallet, also on another lane through `mtxExecute`.
    function test_entry_ref_pays_once() public {
        _pay(npp, 10, keccak256("once"));
        _payExpect(npp, 10, keccak256("once"), abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        MetaTxLib.UAMetaTransaction memory m = _payM(npp, 10, keccak256("once"));
        m.batch = 77;
        IUARegistry.UASig memory a = _ua(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.RefAlreadyPaid.selector, keccak256("once")));
        w.mtxExecute(m, a);
    }

    function test_signer_must_be_the_delegate() public {
        // the owner signing a delegate's payment: a valid signature of the wrong party
        MetaTxLib.UAMetaTransaction memory m = _payM(npp, 10, keccak256("x"));
        m.from = _id(owner);
        IUARegistry.UASig memory a = _ua(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.mtxExecute(m, a);
        // a stranger's signature under the delegate's name
        MetaTxLib.UAEnvelope memory e = _payEnv(keccak256("x"));
        a = _ua(0xBAD, _payDigest(w, e, address(t), npp, 10, keccak256("x"), 1));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(e, address(t), _id(npp), 10, keccak256("x"), 1, a);
        // and the delegate calling directly is the delegate (it pays its own gas)
        vm.prank(delegate);
        w.payUnderMandate(address(t), _id(npp), 10, keccak256("direct"), 1);
        vm.prank(stranger);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.payUnderMandate(address(t), _id(npp), 10, keccak256("direct2"), 1);
    }

    function test_signature_binds_amount_payee_ref_and_token() public {
        MetaTxLib.UAEnvelope memory e = _payEnv(keccak256("x"));
        IUARegistry.UASig memory a = _ua(DELEGATE_PK, _payDigest(w, e, address(t), npp, 10, keccak256("x"), 1));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(e, address(t), _id(npp), 999, keccak256("x"), 1, a);
        vm.prank(owner);
        w.setPayee(address(t), _id(stranger), true);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(e, address(t), _id(stranger), 10, keccak256("x"), 1, a);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);  // another ref: another digest
        w.mtxPayUnderMandate(e, address(t), _id(npp), 10, keccak256("y"), 1, a);
        NormalToken t2 = _normal(address(this), 0, address(this));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(e, address(t2), _id(npp), 10, keccak256("x"), 1, a);
    }

    /// A new delegate voids what the old one signed (the op checks the current delegate).
    function test_new_delegate_voids_old_signatures() public {
        MetaTxLib.UAEnvelope memory e = _payEnv(keccak256("old"));
        IUARegistry.UASig memory a = _ua(DELEGATE_PK, _payDigest(w, e, address(t), npp, 10, keccak256("old"), 1));
        vm.prank(owner);
        w.setMandate(address(t), _id(stranger), 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(e, address(t), _id(npp), 10, keccak256("old"), 2, a);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.mtxPayUnderMandate(e, address(t), _id(npp), 10, keccak256("old"), 1, a);
    }

    // ------------------------------------------------------------------ revocation (CTR-ACC-07)

    function _revokeSig(uint64 ep) internal view returns (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) {
        e.from = _id(delegate);
        e.batch = w.mandateRevokeLane(address(t), ep);
        e.validUntil = block.timestamp + 300;
        a = _ua(DELEGATE_PK, uaDigest(address(w), UA_DELEGATE_REVOKE, e, abi.encode(address(t), ep)));
    }

    /// The generic `revoke(token, epoch)` of the delegate on the revoke lane.
    function _revokeM(uint64 ep) internal view returns (MetaTxLib.UAMetaTransaction memory m, IUARegistry.UASig memory a) {
        m = _gen(_id(delegate), abi.encodeWithSignature("revoke(address,uint64)", address(t), ep),
            w.mandateRevokeLane(address(t), ep), 0);
        a = _ua(DELEGATE_PK, w.mtxDigest(m));
    }

    function test_owner_revoke_kills_it_and_bumps_the_epoch() public {
        assertEq(w.epoch(address(t)), 1);
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.MandateRevoked(address(t), _id(owner));
        vm.prank(owner);
        w.revoke(address(t));
        assertEq(w.epoch(address(t)), 2);
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.NoMandate.selector));
        vm.prank(delegate);
        vm.expectRevert(MandateWallet.NoMandate.selector);
        w.payUnderMandate(address(t), _id(npp), 10, keccak256("x"), 2);
    }

    /// A token that answers false moved nothing: the payment reverts, so `entryRef` and the period stay unspent.
    function test_pay_failed_reverts_everything() public {
        FalsePayToken f = new FalsePayToken();
        vm.startPrank(owner);
        w.setMandate(address(f), _id(delegate), 10, 10, 1 days, uint64(block.timestamp + 1 days));
        w.setPayee(address(f), _id(npp), true);
        vm.stopPrank();
        vm.prank(delegate);
        vm.expectRevert(MandateWallet.PayFailed.selector);
        w.payUnderMandate(address(f), _id(npp), 10, keccak256("f"), 1);
        assertFalse(w.refUsed(keccak256("f")));
    }

    function test_delegate_signed_revoke_kills_it() public {
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) = _revokeSig(1);
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.MandateRevoked(address(t), _id(delegate));
        vm.prank(relayer);
        w.mtxDelegateRevoke(e, address(t), 1, a);
        assertEq(w.epoch(address(t)), 2);
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.NoMandate.selector));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0)); // its replay: the used lane
        w.mtxDelegateRevoke(e, address(t), 1, a);
    }

    /// The replay CTR-ACC-07 closes: a public revoke signature cannot delete a mandate the owner re-established.
    function test_revoke_signature_is_bound_to_its_epoch() public {
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) = _revokeSig(1);
        (MetaTxLib.UAMetaTransaction memory m, IUARegistry.UASig memory ga) = _revokeM(1);
        vm.startPrank(owner);
        w.revoke(address(t));                                                     // epoch 2
        w.setMandate(address(t), _id(delegate), 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));  // epoch 3
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxDelegateRevoke(e, address(t), 1, a);
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxExecute(m, ga);
        _pay(npp, 10, keccak256("alive"));
        // a current-epoch revoke works; its replay is the used lane
        (e, a) = _revokeSig(3);
        w.mtxDelegateRevoke(e, address(t), 3, a);
        vm.prank(owner);
        w.setMandate(address(t), _id(delegate), 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));  // epoch 5
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxDelegateRevoke(e, address(t), 3, a);
    }

    /// A revoke kills every pay signed before it, also when the owner sets the same delegate again (the pay names the
    /// epoch); a pay signed under the new epoch works.
    function test_pay_signature_is_bound_to_its_epoch() public {
        MetaTxLib.UAEnvelope memory e = _payEnv(keccak256("pending"));
        IUARegistry.UASig memory a = _ua(DELEGATE_PK, _payDigest(w, e, address(t), npp, 900, keccak256("pending"), 1));
        MetaTxLib.UAMetaTransaction memory m = _payM(npp, 900, keccak256("pending"));
        IUARegistry.UASig memory ga = _ua(DELEGATE_PK, w.mtxDigest(m));
        vm.startPrank(owner);
        w.revoke(address(t));                                                     // epoch 2
        w.setMandate(address(t), _id(delegate), 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));  // epoch 3
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxPayUnderMandate(e, address(t), _id(npp), 900, keccak256("pending"), 1, a);
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxExecute(m, ga);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);                    // the relayer cannot restamp it
        w.mtxPayUnderMandate(e, address(t), _id(npp), 900, keccak256("pending"), 3, a);
        vm.prank(delegate);
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 2));
        w.payUnderMandate(address(t), _id(npp), 900, keccak256("pending"), 2);
        _pay(npp, 900, keccak256("pending"));                                     // re-signed under epoch 3
        assertEq(t.balanceOf(npp), 900);
    }

    // ------------------------------------------------------------------ setMandate and the running period

    /// Same delegate and period length: an edit keeps the period's start and spend, so it grants no fresh budget.
    /// W-L: periods stay on the grid of the mandate's start. After an idle stretch the first payment opens the window
    /// that holds `now` (not a window starting at `now`), so the delegate cannot choose where a boundary falls.
    function test_period_windows_stay_on_the_grid() public {
        (uint64 p0,) = _period();
        vm.warp(p0 + 2 days + 12 hours);                     // idle for two and a half periods
        _pay(npp, 1_000, keccak256("a"));
        (uint64 ps, uint128 spent) = _period();
        assertEq(ps, p0 + 2 days);
        assertEq(spent, 1_000);
        _pay(npp, 1_000, keccak256("b"));
        _pay(npp, 500, keccak256("c"));
        vm.warp(p0 + 3 days - 1);
        _payExpect(npp, 1, keccak256("d"), abi.encodeWithSelector(MandateWallet.OverPeriodCap.selector, 2_501, 2_500));
        vm.warp(p0 + 3 days);                                // the grid boundary (a window opened on demand at
        _pay(npp, 1, keccak256("d"));                        // p0 + 2.5 days would still be full here)
        (ps, spent) = _period();
        assertEq(ps, p0 + 3 days);
        assertEq(spent, 1);
    }

    function test_setMandate_keeps_the_period_budget() public {
        _pay(npp, 1_000, keccak256("a"));
        _pay(npp, 1_000, keccak256("b"));
        uint64 start = uint64(block.timestamp);
        vm.warp(block.timestamp + 1 hours);
        vm.prank(owner);                                                          // a later expiry, higher caps
        w.setMandate(address(t), _id(delegate), 1_000, 3_000, 1 days, uint64(block.timestamp + 60 days));
        (uint64 ps, uint128 spent) = _period();
        assertEq(ps, start);
        assertEq(spent, 2_000);
        _pay(npp, 1_000, keccak256("c"));
        _payExpect(npp, 1, keccak256("d"), abi.encodeWithSelector(MandateWallet.OverPeriodCap.selector, 3_001, 3_000));
        vm.warp(start + 1 days);                                                  // the period still ends on time
        _pay(npp, 1_000, keccak256("d"));
        assertEq(t.balanceOf(npp), 4_000);
    }

    /// A new delegate, a new period length, or a revoke first: the period restarts empty.
    function test_setMandate_resets_on_new_delegate_or_period() public {
        _pay(npp, 1_000, keccak256("a"));
        vm.warp(block.timestamp + 1 hours);
        vm.prank(owner);
        w.setMandate(address(t), _id(stranger), 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));
        (uint64 ps, uint128 spent) = _period();
        assertEq(ps, block.timestamp);
        assertEq(spent, 0);
        vm.prank(owner);
        w.setMandate(address(t), _id(delegate), 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));
        _pay(npp, 1_000, keccak256("b"));
        vm.warp(block.timestamp + 1 hours);
        vm.prank(owner);
        w.setMandate(address(t), _id(delegate), 1_000, 2_500, 2 days, uint64(block.timestamp + 30 days));
        (ps, spent) = _period();
        assertEq(ps, block.timestamp);
        assertEq(spent, 0);
        _pay(npp, 1_000, keccak256("c"));
        vm.warp(block.timestamp + 1 hours);
        vm.startPrank(owner);
        w.revoke(address(t));
        w.setMandate(address(t), _id(delegate), 1_000, 2_500, 2 days, uint64(block.timestamp + 30 days));
        vm.stopPrank();
        (ps, spent) = _period();
        assertEq(ps, block.timestamp);
        assertEq(spent, 0);
    }

    function _period() internal view returns (uint64 start, uint128 spent) {
        (,,, start,,, spent) = w.mandates(address(t));
    }

    function test_only_the_delegate_revokes_by_signature() public {
        vm.prank(stranger);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.revoke(address(t), 1);
        vm.prank(owner);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.revoke(address(t), 1);
        (MetaTxLib.UAEnvelope memory e,) = _revokeSig(1);
        IUARegistry.UASig memory bad = _ua(0xBAD, uaDigest(address(w), UA_DELEGATE_REVOKE, e, abi.encode(address(t), uint64(1))));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxDelegateRevoke(e, address(t), 1, bad);
    }

    // ------------------------------------------------------------------ the owner

    function test_mandate_parameters_are_validated() public {
        vm.startPrank(owner);
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), _id(delegate), 1_000, 2_500, 0, uint64(block.timestamp + 1 days));
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), _id(delegate), 3_000, 2_500, 1 days, uint64(block.timestamp + 1 days));
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), bytes32(0), 1_000, 2_500, 1 days, uint64(block.timestamp + 1 days));
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), _id(delegate), 0, 2_500, 1 days, uint64(block.timestamp + 1 days));
        w.setMandate(address(t), _id(delegate), 2_500, 2_500, 1 days, uint64(block.timestamp + 1 days));
        vm.stopPrank();
        assertEq(w.epoch(address(t)), 2);
        vm.expectRevert(MandateWallet.ZeroOwner.selector);
        new MandateWallet(bytes32(0), UID_, address(0), false);
    }

    function test_owner_only_functions() public {
        vm.startPrank(delegate);
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.setPayee(address(t), _id(stranger), true);
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.setMandate(address(t), _id(delegate), 1, 1, 1, 1);
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.revoke(address(t));
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.execute(address(t), 0, "");
        vm.stopPrank();
        // the delegate's own signature does not make it the owner
        MetaTxLib.UAMetaTransaction memory m =
            _gen(_id(delegate), abi.encodeCall(MandateWallet.setPayee, (address(t), _id(stranger), true)), 0, 0);
        IUARegistry.UASig memory a = _ua(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.mtxExecute(m, a);
    }

    function test_owner_configures_gasless() public {
        bytes memory data = abi.encodeCall(MandateWallet.setPayee, (address(t), _id(stranger), true));
        MetaTxLib.UAMetaTransaction memory m = _gen(_id(owner), data, 0, 0);
        IUARegistry.UASig memory a = _ua(OWNER_PK, w.mtxDigest(m));
        vm.prank(relayer);
        w.mtxExecute(m, a);
        assertTrue(w.payeeAllowed(address(t), _id(stranger)));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxExecute(m, a);
        IUARegistry.UASig memory foreign = _ua(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxExecute(m, foreign);
        m.nonce = 1;
        foreign = _ua(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxExecute(m, foreign);
    }

    function test_owner_executes_and_cannot_reenter() public {
        _owner(abi.encodeCall(MandateWallet.execute, (address(t), 0, abi.encodeCall(t.transfer, (owner, 100)))));
        assertEq(t.balanceOf(owner), 100);
        bytes memory inner = abi.encodeCall(MandateWallet.setPayee, (address(t), _id(stranger), true));
        MetaTxLib.UAMetaTransaction memory m =
            _gen(_id(owner), abi.encodeCall(MandateWallet.execute, (address(w), 0, inner)), 0, 1);
        IUARegistry.UASig memory a = _ua(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.CallFailed.selector,
            abi.encodeWithSelector(IMetaTx.Reentrancy.selector)));
        w.mtxExecute(m, a);
    }

    /// The owner still pays by hand from the wallet: a `UAMetaTransfer` with `from = pad(wallet)` (ua-mtx-merge T2: the
    /// token's one typed struct), ERC-1271 by the owner.
    function test_owner_still_pays_manually_through_meta_tx() public {
        bytes32 ref = keccak256("manual");
        MetaTxLib.UAMetaTransfer memory x = _tr(address(w), npp, 50, ref, t.payLane(ref), RR);
        bytes memory sig = _sig(OWNER_PK, t.mtxTransferDigest(x));
        vm.prank(relayer);
        t.mtxExecuteTransfer(x, _nativeSig(sig));
        assertEq(t.balanceOf(npp), 50);
        x = _tr(address(w), npp, 50, keccak256("d"), 1, RR);
        sig = _sig(DELEGATE_PK, t.mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxExecuteTransfer(x, _nativeSig(sig));
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
            bytes4(keccak256("payUnderMandate(address,bytes32,uint256,bytes32,uint64)")),
            bytes4(keccak256("revoke(address,uint64)")),
            bytes4(keccak256("setMandate(address,bytes32,uint128,uint128,uint64,uint64)")),
            bytes4(keccak256("setPayee(address,bytes32,bool)")),
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
        MetaTxLib.UAMetaTransaction memory m = _gen(_id(owner), data, 5, 0);
        IUARegistry.UASig memory a = _ua(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(err);
        w.mtxExecute(m, a);
    }

    function test_unlistedSelectorsAndShapes() public {
        MetaTxLib.UAEnvelope memory e;
        IUARegistry.UASig memory none;
        bytes[4] memory calls = [
            abi.encodeCall(MandateWallet.mtxSetPayee, (e, address(t), _id(npp), true, none)),
            abi.encodeCall(MandateWallet.mtxPayUnderMandate, (e, address(t), _id(npp), 1, 0, 0, none)),
            abi.encodeCall(MandateWallet.mtxDelegateRevoke, (e, address(t), 1, none)),
            abi.encodeCall(MandateWallet.isValidSignature, (bytes32(0), ""))
        ];
        for (uint256 i; i < calls.length; ++i) {
            _signedFails(calls[i], abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(calls[i])));
        }
        bytes memory sp = abi.encodeCall(MandateWallet.setPayee, (address(t), _id(stranger), true));
        assertEq(sp.length, 100);
        _signedFails(abi.encodePacked(sp, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(sp)));
        bytes memory pu = abi.encodeCall(MandateWallet.payUnderMandate, (address(t), _id(npp), 1, 0, 1));
        assertEq(pu.length, 164);
        _signedFails(abi.encodePacked(pu, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(pu)));
        bytes memory sm = abi.encodeCall(MandateWallet.setMandate, (address(t), _id(delegate), 1, 1, 1, 1));
        assertEq(sm.length, 196);
        _signedFails(abi.encodePacked(sm, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(sm)));
        bytes memory r2 = abi.encodeWithSignature("revoke(address,uint64)", address(t), uint64(1));
        _signedFails(abi.encodePacked(r2, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(r2)));
        bytes memory r1 = abi.encodeWithSignature("revoke(address)", address(t));
        _signedFails(abi.encodePacked(r1, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(r1)));
    }

    function test_feeModesAndSelfSender() public {
        MetaTxLib.UAMetaTransaction memory m = _gen(_id(owner), abi.encodeCall(IMetaTx.cancelNonce, (1)), 0, 0);
        m.mode = MetaTxLib.MODE_FEE_PERCENT;
        IUARegistry.UASig memory a = _ua(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, IMetaTx.cancelNonce.selector, m.mode));
        w.mtxExecute(m, a);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        a = _ua(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, m.mode));
        w.mtxExecute(m, a);
        // the wallet is not a self-signer: `from = wallet` is refused at step 1 even with the owner's 1271 signature
        m.mode = 0;
        m.from = _id(address(w));
        a = _ua(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(IMetaTx.SelfSender.selector);
        w.mtxExecute(m, a);
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

    /// After a revoke, a validly signed pay or delegate revoke reaches the op and finds no mandate.
    function test_noMandateOnTheNamedEntries() public {
        vm.prank(owner);
        w.revoke(address(t));
        _payExpect(npp, 1, keccak256("n"), abi.encodeWithSelector(MandateWallet.NoMandate.selector));
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) = _revokeSig(2);
        vm.expectRevert(MandateWallet.NoMandate.selector);
        w.mtxDelegateRevoke(e, address(t), 2, a);
    }

    function test_gas() public {
        MetaTxLib.UAEnvelope memory e = _payEnv(keccak256("g"));
        IUARegistry.UASig memory a = _ua(DELEGATE_PK, _payDigest(w, e, address(t), npp, 700, keccak256("g"), 1));
        vm.prank(relayer);
        uint256 g = gasleft();
        w.mtxPayUnderMandate(e, address(t), _id(npp), 700, keccak256("g"), 1, a);
        emit log_named_uint("mtxPayUnderMandate (first payment of the period)", g - gasleft());
    }
}

/// NET-HED-03 through `IS_HEDERA` (ua-mtx-merge T3b): any native signer without code and a 64-byte signature (an
/// ED25519 owner or delegate) goes through HIP-632 over the entry's digest and lane, on every entry; the delegate may be
/// ECDSA or ED25519; a signer with code never takes HIP-632; ERC-1271 for the owner stays ECDSA.
contract HederaMandateWalletTest is MandateFixture {
    address constant HAS = address(0x16a);
    uint256 constant ED_KEY = 0x0E1;
    uint256 constant ED_DEL = 0x0E2;
    address edOwner;
    address edDel = address(uint160(2_000_002));
    HederaMandateWallet hw;

    function setUp() public override {
        super.setUp();
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        edOwner = address(uint160(2_000_001));
        MockHederaAccountService(HAS).setEdKey(edOwner, vm.addr(ED_KEY));
        MockHederaAccountService(HAS).setEdKey(edDel, vm.addr(ED_DEL));
        hw = new HederaMandateWallet(_id(edOwner), UID_, address(0));
        t.mint(address(hw), 1_000);
    }

    function _edAs(uint256 k, bytes32 d) internal pure returns (IUARegistry.UASig memory a) {
        (bytes32 r, bytes32 vs) = vm.signCompact(k, d);
        a.signature = abi.encodePacked(r, vs);
    }

    function _edOwnerCall(bytes memory data, uint256 nonce) internal view returns (MetaTxLib.UAMetaTransaction memory) {
        return _gen(_id(edOwner), data, 0, nonce);
    }

    function _ownerRaw(bytes memory data, uint256 n) internal {
        MetaTxLib.UAMetaTransaction memory m = _edOwnerCall(data, n);
        hw.mtxExecute(m, _edAs(ED_KEY, hw.mtxDigest(m)));
    }

    function test_ed25519OwnerSetsMandateAndPaysByHand() public {
        MetaTxLib.UAMetaTransaction memory m = _edOwnerCall(abi.encodeCall(MandateWallet.setMandate,
            (address(t), _id(delegate), 100, 300, 1 days, uint64(block.timestamp + 30 days))), 0);
        IUARegistry.UASig memory a = _edAs(ED_KEY, hw.mtxDigest(m));
        vm.prank(relayer);
        hw.mtxExecute(m, a);
        (bytes32 d,,,,,,) = hw.mandates(address(t));
        assertEq(d, _id(delegate));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        hw.mtxExecute(m, a);
        // pays by hand: an owner call `execute(token, payWithFee…)`, on the same lane
        bytes memory pay = abi.encodeCall(IERC20Payment.payWithFee, (npp, 40, FeeMode.NONE, 0, address(0), keccak256("hand")));
        _ownerRaw(abi.encodeCall(MandateWallet.execute, (address(t), 0, pay)), 1);
        assertEq(t.balanceOf(npp), 40);
    }

    function test_ed25519OwnerRefusals() public {
        MetaTxLib.UAMetaTransaction memory m =
            _edOwnerCall(abi.encodeCall(MandateWallet.setPayee, (address(t), _id(npp), true)), 0);
        IUARegistry.UASig memory a = _edAs(DELEGATE_PK, hw.mtxDigest(m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        hw.mtxExecute(m, a);
        a = _edAs(ED_KEY, hw.mtxDigest(m));
        vm.warp(m.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, m.validUntil, m.validUntil + 1));
        hw.mtxExecute(m, a);
    }

    /// ERC-1271 runs under STATICCALL, where HIP-632 halts: a `UAMetaTransfer` with `from = pad(wallet)` and the ED25519
    /// owner's signature fails, as specified.
    function test_ed25519OwnerCannotSignAs1271() public {
        MetaTxLib.UAMetaTransfer memory x = _tr(address(hw), npp, 5, keccak256("1271"), 3, RR);
        IUARegistry.UASig memory a = _edAs(ED_KEY, t.mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxExecuteTransfer(x, a);
    }

    function test_delegatePaysUnderMandateSetByEd25519Owner() public {
        _ownerRaw(abi.encodeCall(MandateWallet.setMandate,
            (address(t), _id(delegate), 100, 300, 1 days, uint64(block.timestamp + 30 days))), 0);
        _ownerRaw(abi.encodeCall(MandateWallet.setPayee, (address(t), _id(npp), true)), 1);
        bytes32 ref = bytes32(uint256(7));
        MetaTxLib.UAEnvelope memory e = _payEnv(ref);
        e.batch = hw.mandatePayLane(ref);
        IUARegistry.UASig memory a = _ua(DELEGATE_PK, _payDigest(hw, e, address(t), npp, 50, ref, 1));
        hw.mtxPayUnderMandate(e, address(t), _id(npp), 50, ref, 1, a);
        assertEq(t.balanceOf(npp), 50);
    }

    /// A mandate on `t` for `d` (100 per payment, 300 per day) with `npp` approved, set by the ED25519 owner.
    function _mandateFor(address d) internal {
        _ownerRaw(abi.encodeCall(MandateWallet.setMandate, (address(t), _id(d), 100, 300, 1 days,
            uint64(block.timestamp + 1 days))), 0);
        _ownerRaw(abi.encodeCall(MandateWallet.setPayee, (address(t), _id(npp), true)), 1);
    }

    function _edPayEnv(address from, bytes32 ref) internal view returns (MetaTxLib.UAEnvelope memory e) {
        (e.from, e.batch, e.validUntil) = (_id(from), hw.mandatePayLane(ref), block.timestamp + 300);
    }

    /// An ED25519 delegate pays and revokes through the named entries; its pay is bound to the epoch too.
    function test_ed25519DelegatePaysAndRevokes() public {
        _mandateFor(edDel);
        MetaTxLib.UAEnvelope memory p = _edPayEnv(edDel, "e");
        IUARegistry.UASig memory a = _edAs(ED_DEL, _payDigest(hw, p, address(t), npp, 50, "e", 1));
        hw.mtxPayUnderMandate(p, address(t), _id(npp), 50, "e", 1, a);
        assertEq(t.balanceOf(npp), 50);
        MetaTxLib.UAMetaTransaction memory late = _gen(_id(edDel),
            abi.encodeCall(MandateWallet.payUnderMandate, (address(t), _id(npp), 50, bytes32("late"), 1)), hw.mandatePayLane("late"), 0);
        IUARegistry.UASig memory lateSig = _edAs(ED_DEL, hw.mtxDigest(late));
        MetaTxLib.UAEnvelope memory r = _edPayEnv(edDel, "r");
        r.batch = hw.mandateRevokeLane(address(t), 1);
        a = _edAs(ED_DEL, uaDigest(address(hw), UA_DELEGATE_REVOKE, r, abi.encode(address(t), uint64(1))));
        hw.mtxDelegateRevoke(r, address(t), 1, a);
        (bytes32 d,,,,,,) = hw.mandates(address(t));
        assertEq(d, bytes32(0));
        _ownerRaw(abi.encodeCall(MandateWallet.setMandate, (address(t), _id(edDel), 100, 300, 1 days,
            uint64(block.timestamp + 1 days))), 2);                                // same delegate, epoch 3
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        hw.mtxExecute(late, lateSig);
    }

    /// A `from` with code never takes HIP-632, even when the account service would vouch for its 64-byte signature.
    function test_contractSignerNeverTakesHip632() public {
        Mock1271Wallet cw = new Mock1271Wallet(delegate);
        MockHederaAccountService(HAS).setEdKey(address(cw), vm.addr(ED_DEL));
        _mandateFor(address(cw));
        MetaTxLib.UAEnvelope memory p = _edPayEnv(address(cw), "c");
        IUARegistry.UASig memory a = _edAs(ED_DEL, _payDigest(hw, p, address(t), npp, 50, "c", 1));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        hw.mtxPayUnderMandate(p, address(t), _id(npp), 50, "c", 1, a);
    }

    /// The ED25519 owner through `mtxBatch`; the EIP-1776 alias refuses every call on a wallet (MD-11 (b)); an ECDSA
    /// EOA's 64-byte (compact) signature is not taken for an ED25519 one.
    function test_ed25519OwnerThroughBatchAndAliasRefused() public {
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](1);
        IUARegistry.UASig[] memory ss = new IUARegistry.UASig[](1);
        ms[0] = _gen(_id(edOwner), abi.encodeCall(MandateWallet.setPayee, (address(t), _id(npp), true)), 9, 0);
        ss[0] = _edAs(ED_KEY, hw.mtxDigest(ms[0]));
        hw.mtxBatch(ms, ss);
        assertTrue(hw.payeeAllowed(address(t), _id(npp)));
        MetaTxLib.MetaTransaction memory old;
        (old.from, old.data, old.batch, old.nonce, old.validUntil) =
            (edOwner, abi.encodeCall(MandateWallet.setPayee, (address(t), _id(npp), false)), 9, 1, block.timestamp + 300);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, MandateWallet.setPayee.selector));
        hw.executeMetaTransaction(old, "");
        MetaTxLib.UAMetaTransaction memory m = _gen(_id(owner), abi.encodeCall(IMetaTx.cancelNonce, (1)), 0, 0);
        IUARegistry.UASig memory sg = _edAs(OWNER_PK, hw.mtxDigest(m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        hw.mtxExecute(m, sg);
    }
}
