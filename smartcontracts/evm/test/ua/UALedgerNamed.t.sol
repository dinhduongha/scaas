// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {UALedgerBase} from "./UALedgerBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// T-V3-1: the named `ua*` functions build their struct and run its pipeline (CTR-UA-26 mirroring CTR-MTX-09) —
/// same digest, same events, one lane consumed once — and enforce only their mode shape.
contract UALedgerNamedTest is UALedgerBase {
    function setUp() public override {
        super.setUp();
        _fund(uaP, 100_000);
    }

    /// `uaTransfer(f,t,a,b,n,v,mode,r,s) ≡ uaExecuteTransfer({f,t,a,0,b,n,v,mode,r,0,0}, s)`: one signature, either
    /// entry, once.
    function test_T_V3_1_uaTransfer() public {
        MetaTxLib.UAMetaTransfer memory t = _t(uaP, uaB, 10);
        bytes memory a = _authT(address(tok), t);
        vm.expectEmit(address(tok));
        emit IUALedger.UAMetaTransactionExecuted(uaP, RELAYER, 1, 0, tok.uaTransferDigest(t), RELAYER, 0);
        vm.prank(RELAYER);
        tok.uaTransfer(uaP, uaB, 10, 1, 0, t.validUntil, RR, RELAYER, a);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, a);
        t = _t(uaP, uaB, 10);
        a = _authT(address(tok), t);
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, a);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 2, 1));
        vm.prank(RELAYER);
        tok.uaTransfer(uaP, uaB, 10, 1, 1, t.validUntil, RR, RELAYER, a);
        assertEq(tok.balanceOfUA(uaB), 20);
    }

    function test_T_V3_1_uaTransferWithFee() public {
        MetaTxLib.UAMetaTransfer memory t = _t(uaP, _pad(bob), 1_000);
        (t.mode, t.fee, t.feeRecipient) = (RR | RF | PCT, 5_000, FEE_TO);
        bytes memory a = _authT(address(tok), t);
        vm.prank(RELAYER);
        tok.uaTransferWithFee(uaP, _pad(bob), 1_000, 1, 0, t.validUntil, t.mode, RELAYER, 5_000, FEE_TO, a);
        assertEq(tok.balanceOf(FEE_TO), 5);
        assertEq(tok.balanceOf(bob), 1_000);
        // the fee shape: a fee mode and a bound, non-zero recipient
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.MtxModeShape.selector, RR | PCT));
        tok.uaTransferWithFee(uaP, _pad(bob), 1, 1, 1, t.validUntil, RR | PCT, RELAYER, 1, FEE_TO, a);
    }

    /// `uaPay(f,t,a,p,v,mode,r,x,R,s) ≡ uaExecuteTransfer({f,t,a,p,payLane(p),0,v,mode,r,x,R}, s)`: the payment is
    /// payable once through either entry.
    function test_T_V3_1_uaPay() public {
        bytes32 payId = keccak256("request-7");
        MetaTxLib.UAMetaTransfer memory t = _t(uaP, uaB, 300);
        (t.entryRef, t.batch, t.nonce) = (payId, tok.payLane(payId), 0);
        bytes memory a = _authT(address(tok), t);
        vm.expectEmit(address(tok));
        emit IUALedger.UAPaymentSettled(uaP, uaB, 300, 0, RELAYER, payId);
        vm.prank(RELAYER);
        tok.uaPay(uaP, uaB, 300, payId, t.validUntil, RR, RELAYER, 0, address(0), a);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, a);
    }

    /// `uaPay` is pay: it needs `PAYABLE`, like `mtxPay`; a `UAMetaTransfer` with `entryRef` set is never gated.
    function test_uaPay_needsPayable() public {
        IFactoryToken.TokenConfig memory c = normalInit("NoPay", "NP", 6, 0, address(0), address(this));
        c.features = 1 << AdminLib.MINTABLE;
        NormalToken np = NormalToken(Clones.clone(address(new NormalToken(1, plainEnv(address(this), address(0), chainUidA, REG_L, false), ""))));
        np.initialize(address(this), 1, abi.encode(c));
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, AdminLib.PAYABLE));
        np.uaPay(uaP, uaB, 1, keccak256("p"), block.timestamp + 1, RR, RELAYER, 0, address(0), "");
        // a UAMetaTransfer with `entryRef` set is not gated
        np.mint(alice, 10);
        bytes32 ref = keccak256("p");
        MetaTxLib.UAMetaTransfer memory t = _t(_pad(alice), _pad(bob), 7);
        (t.entryRef, t.batch, t.nonce) = (ref, np.payLane(ref), 0);
        bytes memory auth = _authFor(t.from, np.uaTransferDigest(t));
        vm.prank(RELAYER);
        np.uaExecuteTransfer(t, auth);
        assertEq(np.balanceOf(bob), 7);
    }

    /// `uaUnwrap(f,u,w,r,min,b,n,v,mode,rel,s) ≡ uaExecute({f, unwrap(u,w,r,min), b,n,v,mode,rel,0,0}, s)`.
    function test_T_V3_1_uaUnwrap() public {
        _wrapFor(alice, 1_000);
        vm.prank(alice);
        wrp.transferToUA(uaP, 1_000);
        bytes memory data = abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(und), 250, bob, 250);
        MetaTxLib.UAMetaTransaction memory m = _m(address(wrp), uaP, data);
        bytes memory a = _authM(address(wrp), m);
        vm.prank(RELAYER);
        bytes memory ret = wrp.uaUnwrap(uaP, address(und), 250, bob, 250, 1, 0, m.validUntil, RR, RELAYER, a);
        (uint256 out, uint256 burned) = abi.decode(ret, (uint256, uint256));
        assertEq(out, 250);
        assertEq(burned, 250);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        vm.prank(RELAYER);
        wrp.uaExecute(m, a);
        assertEq(und.balanceOf(bob), 250);
        assertEq(wrp.balanceOfUA(uaP), 750);
    }

    /// No fee in the named form; on the NORMAL kind no `unwrap` is on the UA allowlist.
    function test_uaUnwrap_refusals() public {
        uint256 until = block.timestamp + 300;
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.MtxModeShape.selector, RR | FIX));
        wrp.uaUnwrap(uaP, address(und), 1, bob, 0, 1, 0, until, RR | FIX, RELAYER, "");
        bytes memory data = abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(und), 1, bob, 0);
        bytes memory a = _authM(address(tok), _m(address(tok), uaP, data));
        vm.expectRevert(abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, bytes4(data)));
        vm.prank(RELAYER);
        tok.uaUnwrap(uaP, address(und), 1, bob, 0, 1, 0, until, RR, RELAYER, a);
    }

    /// M2: `UA_POOL` holds every derived balance; an unwrap never pays out to it.
    function test_uaUnwrap_poolRecipientRefused() public {
        _wrapFor(alice, 1_000);
        vm.prank(alice);
        wrp.transferToUA(uaP, 1_000);
        bytes memory data = abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(und), 10, POOL, 0);
        MetaTxLib.UAMetaTransaction memory m = _m(address(wrp), uaP, data);
        bytes memory a = _authM(address(wrp), m);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnwrapRecipientInvalid.selector, POOL));
        vm.prank(RELAYER);
        wrp.uaExecute(m, a);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnwrapRecipientInvalid.selector, POOL));
        vm.prank(RELAYER);
        wrp.uaUnwrap(uaP, address(und), 10, POOL, 0, 1, 0, m.validUntil, RR, RELAYER, a);
    }

    /// C5-4: `SHIELD_POOL` is no unwrap recipient either (the plain unwrap would pay the underlying to a keyless address).
    function test_C5_4_shieldPoolRecipientRefused() public {
        _wrapFor(alice, 1_000);
        vm.prank(alice);
        wrp.transferToUA(uaP, 1_000);
        bytes memory data = abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(und), 10,
            MetaTxLib.SHIELD_POOL, 0);
        MetaTxLib.UAMetaTransaction memory m = _m(address(wrp), uaP, data);
        bytes memory a = _authM(address(wrp), m);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnwrapRecipientInvalid.selector, MetaTxLib.SHIELD_POOL));
        vm.prank(RELAYER);
        wrp.uaExecute(m, a);
    }

    function test_uaTransfer_modeShape() public {
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.MtxModeShape.selector, RR | RF));
        tok.uaTransfer(uaP, uaB, 1, 1, 0, block.timestamp + 1, RR | RF, RELAYER, "");
    }
}
