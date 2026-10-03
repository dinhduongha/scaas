// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {IERC20Payment} from "../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {MandateWallet} from "../src/wallet/MandateWallet.sol";

contract MandateWalletTest is Fixtures {
    MetaToken internal t;
    MandateWallet internal w;
    uint256 internal ownerPk = 0x0A11CE;
    uint256 internal delegatePk = 0xDE1E;
    address internal delegate;
    address internal npp = address(0x4EE);
    address internal stranger = address(0x5745);

    function setUp() public {
        vm.warp(1_800_000_000);
        _deployFactory();
        t = _standalone(address(this), "ZVND", 0, 0, address(this));
        delegate = vm.addr(delegatePk);
        w = new MandateWallet(vm.addr(ownerPk));
        t.mint(address(w), 10_000);
        vm.startPrank(vm.addr(ownerPk));
        w.setMandate(address(t), delegate, 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));
        w.setPayee(address(t), npp, true);
        vm.stopPrank();
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _pay(address payee, uint256 amount, bytes32 ref) internal {
        _payExpect(payee, amount, ref, "");
    }

    /// `expectRevert` phải đứng ngay trước lời gọi thật, sau mọi lời gọi view (payDigest).
    function _payExpect(address payee, uint256 amount, bytes32 ref, bytes memory err) internal {
        uint256 vu = block.timestamp + 300;
        bytes memory sig = _sig(delegatePk, w.payDigest(address(t), payee, amount, ref, vu));
        if (err.length != 0) vm.expectRevert(err);
        w.payUnderMandate(address(t), payee, amount, ref, vu, sig);
    }

    function test_pays_within_mandate_and_settles_like_a_manual_payment() public {
        vm.expectEmit(true, true, true, true, address(t));
        emit IERC20Payment.PaymentSettled(address(w), npp, 700, 0, address(0), keccak256("inv-1"));
        _pay(npp, 700, keccak256("inv-1"));
        assertEq(t.balanceOf(npp), 700);
    }

    function test_per_payment_cap() public {
        _payExpect(npp, 1_001, keccak256("big"), abi.encodeWithSelector(MandateWallet.OverPaymentCap.selector, 1_001, 1_000));
    }

    function test_per_period_cap_and_rollover() public {
        _pay(npp, 1_000, keccak256("a"));
        _pay(npp, 1_000, keccak256("b"));
        _payExpect(npp, 600, keccak256("c"), abi.encodeWithSelector(MandateWallet.OverPeriodCap.selector, 2_600, 2_500));
        vm.warp(block.timestamp + 1 days);
        _pay(npp, 600, keccak256("c"));
        assertEq(t.balanceOf(npp), 2_600);
    }

    function test_payee_not_allowed() public {
        _payExpect(stranger, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.PayeeNotAllowed.selector, stranger));
    }

    function test_expired_mandate() public {
        vm.warp(block.timestamp + 31 days);
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.MandateExpired.selector));
    }

    function test_expired_delegate_signature() public {
        uint256 vu = block.timestamp + 300;
        bytes memory sig = _sig(delegatePk, w.payDigest(address(t), npp, 10, keccak256("x"), vu));
        vm.warp(vu + 1);
        vm.expectRevert(MandateWallet.SignatureExpired.selector);
        w.payUnderMandate(address(t), npp, 10, keccak256("x"), vu, sig);
    }

    function test_entry_ref_pays_once() public {
        _pay(npp, 10, keccak256("once"));
        _payExpect(npp, 10, keccak256("once"), abi.encodeWithSelector(MandateWallet.RefAlreadyPaid.selector, keccak256("once")));
    }

    function test_signature_must_be_the_delegates() public {
        uint256 vu = block.timestamp + 300;
        bytes memory sig = _sig(ownerPk, w.payDigest(address(t), npp, 10, keccak256("x"), vu));
        vm.expectRevert(MandateWallet.BadSignature.selector);
        w.payUnderMandate(address(t), npp, 10, keccak256("x"), vu, sig);
    }

    function test_signature_binds_amount_and_payee() public {
        uint256 vu = block.timestamp + 300;
        bytes memory sig = _sig(delegatePk, w.payDigest(address(t), npp, 10, keccak256("x"), vu));
        vm.expectRevert(MandateWallet.BadSignature.selector);
        w.payUnderMandate(address(t), npp, 999, keccak256("x"), vu, sig);
    }

    function test_owner_revoke_kills_it() public {
        vm.prank(vm.addr(ownerPk));
        w.revoke(address(t));
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.NoMandate.selector));
    }

    function test_delegate_revoke_with_sig_kills_it() public {
        uint256 vu = block.timestamp + 300;
        w.revokeWithSig(address(t), vu, _sig(delegatePk, w.revokeDigest(address(t), vu)));
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.NoMandate.selector));
    }

    function test_stranger_cannot_revoke_or_configure() public {
        uint256 vu = block.timestamp + 300;
        bytes memory bad = _sig(0xBAD, w.revokeDigest(address(t), vu));
        vm.expectRevert(MandateWallet.BadSignature.selector);
        w.revokeWithSig(address(t), vu, bad);
        vm.prank(delegate);
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.setPayee(address(t), stranger, true);
    }

    function test_owner_configures_gasless() public {
        bytes memory data = abi.encodeCall(MandateWallet.setPayee, (address(t), stranger, true));
        uint256 vu = block.timestamp + 300;
        bytes memory sig = _sig(ownerPk, w.ownerCallDigest(data, 0, vu));
        vm.prank(relayer);
        w.executeAsOwner(data, 0, vu, sig);
        assertTrue(w.payeeAllowed(address(t), stranger));
        vm.expectRevert(MandateWallet.BadNonce.selector);
        w.executeAsOwner(data, 0, vu, sig);
    }

    function test_owner_still_pays_manually_through_meta_tx() public {
        bytes32 ref = keccak256("manual");
        MetaTxLib.MetaTransaction memory m =
            _mt(address(w), npp, 50, _payData(ref), uint256(ref), MetaTxLib.MODE_RESTRICT_RELAYER);
        bytes memory sig = _sign(ownerPk, t, m);
        vm.prank(relayer);
        t.executeMetaTransaction(m, sig);
        assertEq(t.balanceOf(npp), 50);
    }

    /// Đường delegated/auto-pay không bao giờ dùng allowance: không selector nào của
    /// approve / transferFrom / permit / increaseAllowance có trong bytecode của ví.
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
}
