// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";
import {MockWallet} from "./UARegistryBase.sol";
import {UALedgerBase} from "./UALedgerBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// accounts.md CTR-UA-18 (the ledger, `UA_POOL`, events), CTR-UA-19 (structs, domain, `initialize` check), CTR-UA-24
/// (the native path), CTR-UA-26 (pipelines, receivers, allowlist, one nonce map, `uaCancelNonce`); T-V3-1 (the shared
/// nonce map), T-V3-3, T-V3-3b.
contract UALedgerTest is UALedgerBase {
    bytes32 internal constant TRANSFER_SIG = keccak256("Transfer(address,address,uint256)");
    bytes32 internal constant UATRANSFER_SIG = keccak256("UATransfer(bytes32,bytes32,uint256)");

    // ----- CTR-UA-18: transferToUA, the pool, events -----

    function test_transferToUA() public {
        uint256 supply = tok.totalSupply();
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(alice, POOL, 400);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(_pad(alice), uaP, 400);
        _fund(uaP, 400);
        assertEq(tok.balanceOfUA(uaP), 400);
        assertEq(tok.balanceOf(POOL), 400);
        assertEq(tok.balanceOf(alice), 1_000_000 - 400);
        assertEq(tok.balanceOfUA(_pad(alice)), 1_000_000 - 400);
        assertEq(tok.totalSupply(), supply);
    }

    function test_transferToUA_refusesNonSigningReceivers() public {
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, _pad(bob)));
        tok.transferToUA(_pad(bob), 1);
        bytes32 unknown = keccak256("unregistered");
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, unknown));
        tok.transferToUA(unknown, 1);
        vm.stopPrank();
    }

    /// UA → UA: `UATransfer` only, the pool's slot and every native balance unchanged.
    function test_uaToUA_emitsNoTransfer() public {
        _fund(uaP, 500);
        MetaTxLib.UAMetaTransfer memory t = _t(uaP, uaB, 200);
        vm.recordLogs();
        _xfer(t);
        (uint256 transfers, uint256 uaTransfers) = _count(vm.getRecordedLogs());
        assertEq(transfers, 0);
        assertEq(uaTransfers, 1);
        assertEq(tok.balanceOfUA(uaP), 300);
        assertEq(tok.balanceOfUA(uaB), 200);
        assertEq(tok.balanceOf(POOL), 500);
        assertEq(tok.uaNonce(uaP, 1), 1);
    }

    /// UA → native with a bound fee: `Transfer(UA_POOL, feeRecipient)` and `Transfer(UA_POOL, to)`, each with its
    /// `UATransfer`; then the executed event.
    function test_uaToNative_withFee() public {
        _fund(uaP, 1_000);
        MetaTxLib.UAMetaTransfer memory t = _t(uaP, _pad(bob), 500);
        (t.mode, t.fee, t.feeRecipient) = (RR | RF | FIX, 5, FEE_TO);
        bytes32 digest = tok.uaTransferDigest(t);
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(POOL, FEE_TO, 5);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(uaP, _pad(FEE_TO), 5);
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(POOL, bob, 500);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(uaP, _pad(bob), 500);
        vm.expectEmit(address(tok));
        emit IUALedger.UAMetaTransactionExecuted(uaP, RELAYER, 1, 0, digest, FEE_TO, 5);
        _xfer(t);
        assertEq(tok.balanceOfUA(uaP), 495);
        assertEq(tok.balanceOf(bob), 500);
        assertEq(tok.balanceOf(FEE_TO), 5);
        assertEq(tok.balanceOf(POOL), 495);
    }

    /// Native → native through the UA path: plain `Transfer`s, no `UATransfer`; the signature is ECDSA over the v3
    /// digest (never the `UAAuth` wrapper), a payment emits `UAPaymentSettled`.
    function test_nativePath() public {
        MetaTxLib.UAMetaTransfer memory t = _t(_pad(alice), _pad(bob), 70);
        t.entryRef = keccak256("invoice-1");
        vm.recordLogs();
        _xfer(t);
        (uint256 transfers, uint256 uaTransfers) = _count(vm.getRecordedLogs());
        assertEq(transfers, 1);
        assertEq(uaTransfers, 0);
        assertEq(tok.balanceOf(bob), 70);
        t = _t(_pad(alice), uaP, 30);
        bytes memory wrapped = _ecdsa(ALICE_PK, lreg.uaAuthDigest(_pad(alice), UAKinds.PURPOSE_METATX, tok.uaTransferDigest(t)));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, wrapped);
        vm.expectEmit(address(tok));
        emit IUALedger.UAPaymentSettled(_pad(alice), uaP, 30, 0, RELAYER, keccak256("invoice-2"));
        t.entryRef = keccak256("invoice-2");
        _xfer(t);
    }

    /// A derived `from` is authorized by the registry under `metatx` only.
    function test_derivedFrom_registryDecides() public {
        _fund(uaP, 100);
        MetaTxLib.UAMetaTransfer memory t = _t(uaP, _pad(bob), 10);
        bytes memory wrongPurpose =
            _auth(lreg, UAKinds.P256, _key(UAKinds.P256), UAKinds.PURPOSE_MEMBER, tok.uaTransferDigest(t));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, wrongPurpose);
        bytes32 stranger = keccak256("not registered");
        t = _t(stranger, _pad(bob), 0);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, stranger));
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, abi.encode(bytes(""), bytes("")));
    }

    // ----- T-V3-1: one nonce map for both paths -----

    function test_T_V3_1_sharedNonceMap() public {
        MetaTxLib.MetaTransfer memory v2 = MetaTxLib.MetaTransfer({
            from: alice, to: bob, value: 1, entryRef: 0, batch: 1, nonce: 0, validUntil: block.timestamp + 300,
            mode: RR, relayer: RELAYER, fee: 0, feeRecipient: address(0)
        });
        MetaTxLib.UAMetaTransfer memory v3 = _t(_pad(alice), _pad(bob), 1);
        bytes memory a3 = _authT(address(tok), v3);
        bytes memory a2 = _ecdsa(ALICE_PK, tok.mtxTransferDigest(v2));
        vm.prank(RELAYER);
        tok.mtxExecuteTransfer(v2, a2);
        assertEq(tok.uaNonce(_pad(alice), 1), 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(v3, a3);
        v3.nonce = 1;
        _xfer(v3);
        assertEq(tok.mtxNonce(alice, 1), 2);
        vm.prank(alice);
        tok.cancelNonce(1);
        assertEq(tok.uaNonce(_pad(alice), 1), 3);
    }

    // ----- T-V3-3: receivers, allowlist, fee recipient -----

    function test_T_V3_3_unregisteredReceiver() public {
        _fund(uaP, 10);
        bytes32 unknown = keccak256("unregistered");
        _xferReverts(_t(uaP, unknown, 1), abi.encodeWithSelector(IUALedger.UANotRegistered.selector, unknown));
        _xferReverts(_t(uaP, bytes32(0), 1), abi.encodeWithSelector(IERC20MetaTx.PayToZero.selector));
        _xferReverts(_t(uaP, _pad(address(tok)), 1), abi.encodeWithSelector(IERC20MetaTx.TransferToSelf.selector));
    }

    /// `approve` and `trade` are refused in every `ua*` function, for a native `from` too (natives use the address
    /// path); so is any selector off the UA allowlist.
    function test_T_V3_3_approveAndTradeRefused() public {
        _fund(uaP, 10);
        bytes[3] memory calls = [
            abi.encodeCall(IERC20.approve, (address(this), 1)),
            abi.encodeWithSelector(ITradeToken.mtxTrade.selector),
            abi.encodeCall(IERC20.transfer, (bob, 1))
        ];
        bytes32[2] memory froms = [_pad(alice), uaP];
        for (uint256 f; f < 2; ++f) {
            for (uint256 i; i < 3; ++i) {
                MetaTxLib.UAMetaTransaction memory m = _m(address(tok), froms[f], calls[i]);
                bytes memory a = _authM(address(tok), m);
                vm.expectRevert(abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, bytes4(calls[i])));
                vm.prank(RELAYER);
                tok.uaExecute(m, a);
            }
        }
    }

    /// `FeeRecipientIsPayee` compares the padded `feeRecipient` with `to`; a fee to `UA_POOL` is refused.
    function test_T_V3_3_feeRecipientIsPayee() public {
        _fund(uaP, 1_000);
        MetaTxLib.UAMetaTransfer memory t = _t(uaP, _pad(bob), 100);
        (t.mode, t.fee, t.feeRecipient) = (RR | RF | FIX, 1, bob);
        _xferReverts(t, abi.encodeWithSelector(IERC20MetaTx.FeeRecipientIsPayee.selector));
        t.feeRecipient = POOL;
        _xferReverts(t, abi.encodeWithSelector(IUALedger.UAPoolNotPayable.selector));
        t = _t(uaP, _pad(bob), 100);
        t.relayer = bob; // unbound fee recipient = the relayer: a payee relaying its own payment with a fee
        (t.mode, t.fee) = (RR | FIX, 1);
        bytes memory a = _authT(address(tok), t);
        vm.expectRevert(IERC20MetaTx.FeeRecipientIsPayee.selector);
        vm.prank(bob);
        tok.uaExecuteTransfer(t, a);
    }

    /// D19: no UA-ledger fee reaches `SHIELD_POOL`: the transfer fee, and the self-call fee of `uaExecute` (`_uaMove`
    /// itself refuses the pool; it bypasses the `_update` guard).
    function test_D19_feeToShieldPoolRefused() public {
        address sp = MetaTxLib.SHIELD_POOL;
        _fund(uaP, 1_000);
        MetaTxLib.UAMetaTransfer memory t = _t(uaP, _pad(bob), 100);
        (t.mode, t.fee, t.feeRecipient) = (RR | RF | FIX, 1, sp);
        _xferReverts(t, abi.encodeWithSelector(IUALedger.ShieldPoolNotPayable.selector));
        _wrapFor(alice, 10_000);
        vm.prank(alice);
        wrp.transferToUA(uaP, 5_000);
        MetaTxLib.UAMetaTransaction memory m = _m(address(wrp), uaP,
            abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(und), 100, bob, 100));
        (m.mode, m.fee, m.feeRecipient) = (RR | RF | FIX, 1, sp);
        bytes memory a = _authM(address(wrp), m);
        vm.expectRevert(IUALedger.ShieldPoolNotPayable.selector);
        vm.prank(RELAYER);
        wrp.uaExecute(m, a);
        assertEq(wrp.balanceOf(sp), 0, "nothing reached the pool");
    }

    /// CTR-MTX-18: a `uaExecute` fee to the token's own address is refused (derived and native `from`).
    function test_T_V3_3_feeToTokenRefused() public {
        _wrapFor(alice, 10_000);
        vm.prank(alice);
        wrp.transferToUA(uaP, 5_000);
        bytes32[2] memory froms = [uaP, _pad(alice)];
        for (uint256 i; i < 2; ++i) {
            bytes memory data = froms[i] == uaP
                ? abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(und), 100, bob, 100)
                : abi.encodeWithSignature("unwrap(uint256,address,uint256)", 100, bob, 100);
            MetaTxLib.UAMetaTransaction memory m = _m(address(wrp), froms[i], data);
            (m.mode, m.fee, m.feeRecipient) = (RR | RF | FIX, 1, address(wrp));
            bytes memory a = _authM(address(wrp), m);
            vm.expectRevert(IERC20MetaTx.TransferToSelf.selector);
            vm.prank(RELAYER);
            wrp.uaExecute(m, a);
        }
    }

    // ----- T-V3-3b: Zether receivers, UA_POOL, native cancel -----

    /// UA-6 U8 (CTR-UA-30 (2)): the Zether UA (`zether-bls12381`) is a SIGNING UA: it receives by `transferToUA` and
    /// by a UA transfer, and signs its own `UAMetaTransfer` (Schnorr by `x` on `Y`, `auth.keyData` empty).
    function test_UA6_zetherReceivesAndSigns() public {
        _fund(uaZ, 50);
        assertEq(tok.balanceOfUA(uaZ), 50);
        _fund(uaP, 10);
        _xfer(_t(uaP, uaZ, 7));
        assertEq(tok.balanceOfUA(uaZ), 57);
        _xfer(_t(uaZ, uaB, 20));
        assertEq(tok.balanceOfUA(uaZ), 37);
        assertEq(tok.balanceOfUA(uaB), 20);
    }

    function test_T_V3_3b_poolNotPayable() public {
        _fund(uaP, 10);
        _xferReverts(_t(uaP, _pad(POOL), 1), abi.encodeWithSelector(IUALedger.UAPoolNotPayable.selector));
        vm.startPrank(alice);
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        tok.transfer(POOL, 1);
        vm.stopPrank();
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        tok.mint(POOL, 1);
        // the pool's balance is never spent outside a UA self-call, nor signed for
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        vm.prank(POOL);
        tok.transfer(bob, 1);
        MetaTxLib.UAMetaTransfer memory t = _t(_pad(POOL), _pad(bob), 1);
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, new bytes(65));
    }

    function test_T_V3_3b_cancelNative_refused() public {
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UAKindNotAccepted.selector, _pad(alice), uint16(0)));
        tok.uaCancelNonce(_pad(alice), 1, block.timestamp + 60, "");
    }

    // ----- uaCancelNonce -----

    function test_uaCancelNonce() public {
        uint256 until = block.timestamp + 60;
        bytes32 d = tok.uaCancelDigest(uaP, 9, until);
        assertEq(d, keccak256(abi.encode(UAKinds.PURPOSE_METATX_CANCEL, block.chainid, chainUidA, address(tok), uaP, uint256(9), until)));
        bytes memory a = _auth(lreg, UAKinds.P256, _key(UAKinds.P256), UAKinds.PURPOSE_METATX_CANCEL, d);
        vm.expectEmit(address(tok));
        emit IUALedger.UANonceCancelled(uaP, 9, 1);
        tok.uaCancelNonce(uaP, 9, until, a);
        assertEq(tok.uaNonce(uaP, 9), 1);
        vm.expectRevert(IUALedger.UACancelUsed.selector); // one signature, one cancel
        tok.uaCancelNonce(uaP, 9, until, a);
        bytes memory asMetatx = _auth(lreg, UAKinds.P256, _key(UAKinds.P256), UAKinds.PURPOSE_METATX, d);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        tok.uaCancelNonce(uaP, 9, until + 1, asMetatx);
        vm.warp(until + 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, until, until + 1));
        tok.uaCancelNonce(uaP, 9, until, a);
    }

    // ----- uaExecute: the UA allowlist (`unwrap`), a derived signer spends its own UA balance -----

    function test_uaExecute_unwrapUnderUA() public {
        _wrapFor(alice, 10_000);
        vm.prank(alice);
        wrp.transferToUA(uaP, 10_000);
        bytes memory data = abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(und), 4_000, bob, 4_000);
        MetaTxLib.UAMetaTransaction memory m = _m(address(wrp), uaP, data);
        (m.mode, m.fee, m.feeRecipient) = (RR | RF | PCT, 10_000, FEE_TO); // 1 % of the wrapped amount, after the call
        bytes memory a = _authM(address(wrp), m);
        vm.expectEmit(address(wrp));
        emit IUALedger.UATransfer(uaP, bytes32(0), 4_000);
        vm.expectEmit(address(wrp));
        emit IERC20.Transfer(POOL, address(0), 4_000);
        vm.prank(RELAYER);
        wrp.uaExecute(m, a);
        assertEq(und.balanceOf(bob), 4_000);
        assertEq(wrp.balanceOfUA(uaP), 10_000 - 4_000 - 40);
        assertEq(wrp.balanceOf(FEE_TO), 40);
        assertEq(wrp.balanceOf(POOL), 10_000 - 4_040);
        assertEq(wrp.totalSupply(), 10_000 - 4_000);
        // more than the UA holds: the burn through the pool refuses
        data = abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(und), 6_000, bob, 0);
        m = _m(address(wrp), uaP, data);
        a = _authM(address(wrp), m);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UAInsufficientBalance.selector, uaP, 5_960, 6_000));
        vm.prank(RELAYER);
        wrp.uaExecute(m, a);
    }

    /// The same allowlisted call under a native `from` is `mtxExecute` on the ids path.
    function test_uaExecute_unwrapNative() public {
        _wrapFor(alice, 500);
        bytes memory data = abi.encodeWithSignature("unwrap(uint256,address,uint256)", 200, bob, 200);
        MetaTxLib.UAMetaTransaction memory m = _m(address(wrp), _pad(alice), data);
        bytes memory a = _authM(address(wrp), m);
        vm.prank(RELAYER);
        wrp.uaExecute(m, a);
        assertEq(und.balanceOf(bob), 200);
        assertEq(wrp.balanceOf(alice), 300);
        // no `unwrap` on the NONE kind's UA allowlist
        m = _m(address(tok), _pad(alice), data);
        a = _authM(address(tok), m);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, bytes4(data)));
        vm.prank(RELAYER);
        tok.uaExecute(m, a);
    }

    // ----- batches -----

    function test_uaBatchTransfer_atomic() public {
        _fund(uaP, 100);
        MetaTxLib.UAMetaTransfer[] memory ts = new MetaTxLib.UAMetaTransfer[](2);
        bytes[] memory as_ = new bytes[](2);
        ts[0] = _t(uaP, uaB, 60);
        ts[1] = _t(uaP, _pad(bob), 60);
        ts[1].nonce = 1;
        (as_[0], as_[1]) = (_authT(address(tok), ts[0]), _authT(address(tok), ts[1]));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.MetaTxInsufficientForFee.selector, 60, 40));
        vm.prank(RELAYER);
        tok.uaBatchTransfer(ts, as_);
        ts[1].value = 40;
        as_[1] = _authT(address(tok), ts[1]);
        vm.prank(RELAYER);
        tok.uaBatchTransfer(ts, as_);
        assertEq(tok.balanceOfUA(uaB), 60);
        assertEq(tok.balanceOf(bob), 40);
        vm.expectRevert(IMetaTx.MtxBatchEmpty.selector);
        tok.uaBatchTransfer(new MetaTxLib.UAMetaTransfer[](0), new bytes[](0));
        vm.expectRevert(IMetaTx.MtxBatchLengthMismatch.selector);
        tok.uaBatch(new MetaTxLib.UAMetaTransaction[](1), new bytes[](0));
    }

    // ----- CTR-UA-24: an EIP-7702 delegated native `from` -----

    /// Owner ruling 2026-10-30 (D1, superseding 2026-10-28): the base key's ECDSA passes; a delegate's ERC-1271 is
    /// refused on the UA path and on the address path.
    function test_7702_nativeFrom() public {
        MockWallet delegate = new MockWallet(bob, 0, 0, address(0)); // ERC-1271: ECDSA by bob over the hash
        vm.signAndAttachDelegation(address(delegate), ALICE_PK);
        MetaTxLib.UAMetaTransfer memory t = _t(_pad(alice), uaP, 5);
        _xfer(t); // alice's own key
        t = _t(_pad(alice), uaP, 5);
        bytes memory bySession = _ecdsa(BOB_PK, tok.uaTransferDigest(t));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector); // the delegate's isValidSignature is never asked (D1)
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, bySession);
        assertEq(tok.balanceOfUA(uaP), 5);
        MetaTxLib.MetaTransfer memory v2 = MetaTxLib.MetaTransfer({
            from: alice, to: bob, value: 1, entryRef: 0, batch: 1, nonce: 1, validUntil: block.timestamp + 300,
            mode: RR, relayer: RELAYER, fee: 0, feeRecipient: address(0)
        });
        bytes memory v2Session = _ecdsa(BOB_PK, tok.mtxTransferDigest(v2));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector); // nor on the address path
        vm.prank(RELAYER);
        tok.mtxExecuteTransfer(v2, v2Session);
        v2Session = _ecdsa(ALICE_PK, tok.mtxTransferDigest(v2));
        uint256 before = tok.balanceOf(bob);
        vm.prank(RELAYER);
        tok.mtxExecuteTransfer(v2, v2Session); // alice's own key on the address path
        assertEq(tok.balanceOf(bob), before + 1);
    }

    // ----- registry binding (CTR-UA-19) -----

    function test_registryOff() public {
        NoUnderlyingToken off = NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(1, plainEnv(address(this), address(0), chainUidA, address(0), false), ""))));
        off.initialize(address(this), 1, abi.encode(noneInit("Off", "OFF", 6, 100, alice, address(this))));
        assertEq(off.registry(), address(0));
        assertFalse(off.supportsInterface(type(IUALedger).interfaceId));
        assertTrue(tok.supportsInterface(type(IUALedger).interfaceId));
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        vm.prank(alice);
        off.transferToUA(uaP, 1);
        MetaTxLib.UAMetaTransfer memory t = _t(_pad(alice), _pad(bob), 1);
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.uaExecuteTransfer(t, "");
    }

    function test_initialize_registryChainUid() public {
        bytes32 other = keccak256("other genesis");
        address impl = address(new NoUnderlyingToken(1, plainEnv(address(this), address(0), other, REG_L, false), ""));
        NoUnderlyingToken c = NoUnderlyingToken(Clones.clone(impl));
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UARegistryChainUid.selector, chainUidA, other));
        c.initialize(address(this), 1, abi.encode(noneInit("X", "X", 6, 0, address(0), address(this))));
    }

    function test_uaDigest_domainAndTypehash() public view {
        MetaTxLib.UAMetaTransfer memory t = _t(uaP, uaB, 1);
        bytes32 domain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), block.chainid, address(tok), chainUidA));
        assertEq(tok.uaTransferDigest(t), keccak256(abi.encodePacked(hex"1901", domain, MetaTxLib.hashStruct(t))));
        MetaTxLib.UAMetaTransaction memory m = _m(address(tok), uaP, hex"01020304");
        assertEq(tok.uaDigest(m), keccak256(abi.encodePacked(hex"1901", domain, MetaTxLib.hashStruct(m))));
    }

    // ----- helpers -----

    function _count(Vm.Log[] memory logs) internal view returns (uint256 transfers, uint256 uaTransfers) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(tok)) continue;
            if (logs[i].topics[0] == TRANSFER_SIG) ++transfers;
            if (logs[i].topics[0] == UATRANSFER_SIG) ++uaTransfers;
        }
    }
}
