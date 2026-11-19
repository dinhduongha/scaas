// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {GovRouterFixture} from "../governance/GovRouter.t.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {SdkGasOps} from "./SdkGasOps.sol";

/// The `wallet` domain kind's base rows on `MandateWallet` (variant `mandate`): the owner's `mtxSetMandate`, `mtxSetPayee`,
/// `mtxRevokeMandate`, `mtxExecute` and the ordered `mtxCancelNonce` on the owner's wallet `w`; the delegate's
/// `mtxPayUnderMandate` and `mtxDelegateRevoke` on `wd`, whose mandate on `tok` names the signer. The signer (a native key)
/// is the owner of `w` and the delegate of `wd`. `mtxExecute` calls an account without code with no value: the wallet's
/// own cost, the target's never in a row; its `data` has the per-byte coefficient (ruling B's treatment), as
/// `mtxPayUnderMandate`'s `PayMeta` body has.
contract SdkGasWalletTest is SdkGasOps, UALedgerBase {
    MandateWallet internal w;
    MandateWallet internal wd;

    function setUp() public override {
        super.setUp();
        sgPk = ALICE_PK;
        w = new MandateWallet(MetaTxLib.pad(alice), chainUidA, address(0), false);
        vm.prank(alice);
        w.setMandate(address(tok), MetaTxLib.pad(bob), 1_000, 1_000, 1 days, uint64(block.timestamp + 1 days));
        wd = new MandateWallet(MetaTxLib.pad(bob), chainUidA, address(0), false);
        vm.startPrank(bob);
        wd.setMandate(address(tok), MetaTxLib.pad(alice), 1_000, 1_000, 1 days, uint64(block.timestamp + 1 days));
        wd.setPayee(address(tok), MetaTxLib.pad(SG_PAYEE), true);
        vm.stopPrank();
        vm.prank(alice);
        tok.transfer(address(wd), 1_000);
    }

    /// A new mandate on a token the wallet has none on (its first write).
    function _setMandate(address c, uint256 nonce) internal view returns (bytes memory) {
        (address t, bytes32 d, uint64 exp) = (address(und), MetaTxLib.pad(bob), uint64(block.timestamp + 1 days));
        bytes32 h = _sgNamed(
            c,
            "UASetMandate(bytes32 from,address token,bytes32 delegate,uint128 maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry,",
            abi.encode(t, d, uint128(1_000), uint128(1_000), uint64(1 days), exp),
            nonce
        );
        return abi.encodeCall(
            MandateWallet.mtxSetMandate,
            (_sgE(nonce), t, d, uint128(1_000), uint128(1_000), uint64(1 days), exp, _sgUaSig(h))
        );
    }

    function _setPayee(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 p = MetaTxLib.pad(SG_PAYEE);
        bytes32 h = _sgNamed(
            c, "UASetPayee(bytes32 from,address token,bytes32 payee,bool allowed,", abi.encode(tok, p, true), nonce
        );
        return abi.encodeCall(MandateWallet.mtxSetPayee, (_sgE(nonce), address(tok), p, true, _sgUaSig(h)));
    }

    function _revokeMandate(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 h = _sgNamed(c, "UARevokeMandate(bytes32 from,address token,", abi.encode(tok), nonce);
        return abi.encodeCall(MandateWallet.mtxRevokeMandate, (_sgE(nonce), address(tok), _sgUaSig(h)));
    }

    function _execute(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes memory data = new bytes(sgBody);
        for (uint256 i; i < data.length; ++i) {
            data[i] = 0xab;
        }
        bytes32 h = _sgNamed(
            c,
            "UAExecute(bytes32 from,address target,uint256 value,bytes data,",
            abi.encode(SG_PAYEE, uint256(0), keccak256(data)),
            nonce
        );
        return abi.encodeCall(MandateWallet.mtxExecute, (_sgE(nonce), SG_PAYEE, 0, data, _sgUaSig(h)));
    }

    function _payUnderMandate(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.PayMeta memory m = _sgMeta();
        (bytes32 p, bytes32 r, uint64 ep) =
            (MetaTxLib.pad(SG_PAYEE), PayMetaKit.id(m), MandateWallet(payable(c)).epoch(address(tok)));
        bytes32 h = _sgNamed(
            c,
            "UAPayUnderMandate(bytes32 from,address token,bytes32 payee,uint256 amount,bytes32 entryRef,uint64 epoch,",
            abi.encode(tok, p, uint256(1), r, ep),
            nonce
        );
        return
            abi.encodeCall(MandateWallet.mtxPayUnderMandate, (_sgE(nonce), address(tok), p, 1, r, ep, _sgUaSig(h), m));
    }

    function _delegateRevoke(address c, uint256 nonce) internal view returns (bytes memory) {
        uint64 ep = MandateWallet(payable(c)).epoch(address(tok));
        bytes32 h = _sgNamed(c, "UADelegateRevoke(bytes32 from,address token,uint64 epoch,", abi.encode(tok, ep), nonce);
        return abi.encodeCall(MandateWallet.mtxDelegateRevoke, (_sgE(nonce), address(tok), ep, _sgUaSig(h)));
    }

    function test_sdkGas_wallet() public {
        bytes32 from = _sgFrom();
        _both("wallet", "mtxSetMandate", "mandate", address(w), from, _setMandate);
        _both("wallet", "mtxSetPayee", "mandate", address(w), from, _setPayee);
        _both("wallet", "mtxRevokeMandate", "mandate", address(w), from, _revokeMandate);
        _both("wallet", "mtxExecute", "mandate", address(w), from, _execute);
        _both("wallet", "mtxCancelNonce", "mandate", address(w), from, _cancel);
        _both("wallet", "mtxPayUnderMandate", "mandate", address(wd), from, _payUnderMandate);
        _both("wallet", "mtxDelegateRevoke", "mandate", address(wd), from, _delegateRevoke);
    }

    function test_sdkGas_wallet_body() public {
        _bodyRows("wallet", "mtxPayUnderMandate", "mandate", address(wd), _payUnderMandate);
        // `data` at 32 and 160 bytes: from about 250, the calldata floor binds this small call's total
        uint256 s = vm.snapshotState();
        sgBody = 32;
        uint256 lo = _measure("wallet_mtxExecute_body32_mandate", address(w), _execute(address(w), 0));
        vm.revertToState(s);
        sgBody = 160;
        uint256 hi = _measure("wallet_mtxExecute_body160_mandate", address(w), _execute(address(w), 0));
        vm.revertToState(s);
        _perByte("wallet_mtxExecute_per_byte_mandate", lo, hi, 128);
    }
}

/// The `gov_router` domain kind's `mtxCancelNonce` (variant `router`): the ordered cancel on the router, by a native key.
contract SdkGasRouterTest is SdkGasOps, GovRouterFixture {
    function setUp() public override {
        super.setUp();
        sgPk = 0xA11CE;
    }

    function test_sdkGas_router() public {
        _both("gov_router", "mtxCancelNonce", "router", address(router), _sgFrom(), _cancel);
    }
}
