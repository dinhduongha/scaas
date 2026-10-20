// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";
import {MockWallet} from "./UARegistryBase.sol";
import {UALedgerBase} from "./UALedgerBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// Receiver-pays on the UA path (metatx.md CTR-MTX-05/06, the `uaPayReceiverFee` paragraph): the payer's
/// `UAMetaTransfer` runs untouched through the typed UA pipeline, then the payee — a native id signing the token's
/// `ReceiverFee` itself, or a derived UA through `requireAuthorized` under `receiver-fee` — pays `fee` out of what it
/// received, in the same transaction. Payers: native (alice), `p256`, `bip340`; payees: native (bob), `ed25519`,
/// `webauthn-p256` (distinct ids, so no payment is a self-payment).
contract UAReceiverFeeTest is UALedgerBase {
    uint256 internal constant N = 100_000;
    bytes32 internal uaE; // ed25519 (0x0102)
    bytes32 internal uaW; // webauthn-p256 (0x0100)
    uint256 internal refs;

    function setUp() public override {
        super.setUp();
        uaE = _register(lreg, UAKinds.ED25519, _key(UAKinds.ED25519));
        uaW = _register(lreg, UAKinds.WEBAUTHN_P256, _key(UAKinds.WEBAUTHN_P256));
    }

    function _pay(bytes32 from, bytes32 to, uint256 value) internal returns (MetaTxLib.UAMetaTransfer memory t) {
        bytes32 ref = keccak256(abi.encode("scaas.ua5a.rf", ++refs));
        t = MetaTxLib.UAMetaTransfer({
            from: from, to: to, value: value, entryRef: ref, batch: tok.payLane(ref), nonce: 0,
            validUntil: block.timestamp + 300, mode: RR, relayer: RELAYER, fee: 0, feeRecipient: address(0)
        });
    }

    /// The payer's `metatx` auth (`_authFor`) or the payee's co-signature: a native signs `digest` itself, a derived UA
    /// `ua_msg(kind, purpose, digest)` through the registry.
    function _sign(bytes32 id, bytes32 purpose, bytes32 digest) internal view returns (bytes memory) {
        if (id == _pad(alice)) return _ecdsa(ALICE_PK, digest);
        if (id == _pad(bob)) return _ecdsa(BOB_PK, digest);
        uint16 kind = lreg.kindOf(id);
        return _auth(lreg, kind, _key(kind), purpose, digest);
    }

    function _fundId(bytes32 id, uint256 amount) internal {
        if (id == _pad(alice)) return; // alice holds the initial supply
        _fund(id, amount);
    }

    function _call(NoUnderlyingToken t_, MetaTxLib.UAMetaTransfer memory t, uint256 fee, address feeTo, uint256 rfUntil,
        bytes memory err) internal returns (uint256 gas)
    {
        bytes32 d = t_.uaTransferDigest(t);
        bytes memory payerAuth = _sign(t.from, UAKinds.PURPOSE_METATX, d);
        bytes memory payeeAuth = _sign(t.to, UAKinds.PURPOSE_RECEIVER_FEE, t_.receiverFeeDigest(d, fee, feeTo, rfUntil));
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(RELAYER);
        gas = gasleft();
        t_.uaPayReceiverFee(t, payerAuth, fee, feeTo, rfUntil, payeeAuth);
        gas -= gasleft();
    }

    function _run(MetaTxLib.UAMetaTransfer memory t, uint256 fee) internal returns (uint256) {
        return _call(tok, t, fee, FEE_TO, block.timestamp + 60, "");
    }

    function _runRevert(MetaTxLib.UAMetaTransfer memory t, uint256 fee, address feeTo, uint256 rfUntil, bytes memory err)
        internal
    {
        _call(tok, t, fee, feeTo, rfUntil, err);
    }

    // ----- events and balances -----

    function test_uaPayReceiverFee_eventsAndBalances() public {
        _fund(uaP, N);
        MetaTxLib.UAMetaTransfer memory t = _pay(uaP, uaE, N);
        bytes32 d = tok.uaTransferDigest(t);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(uaP, uaE, N);
        vm.expectEmit(address(tok));
        emit IUALedger.UAPaymentSettled(uaP, uaE, N, 0, RELAYER, t.entryRef);
        vm.expectEmit(address(tok));
        emit IUALedger.UAMetaTransactionExecuted(uaP, RELAYER, t.batch, 0, d, RELAYER, 0);
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(POOL, FEE_TO, 3_000);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(uaE, _pad(FEE_TO), 3_000);
        vm.expectEmit(address(tok));
        emit IMetaTokenV2.UAReceiverFeePaid(d, uaE, FEE_TO, 3_000);
        _run(t, 3_000);
        assertEq(tok.balanceOfUA(uaP), 0);                   // RP1: payer −N
        assertEq(tok.balanceOfUA(uaE), N - 3_000);           // payee N − fee
        assertEq(tok.balanceOf(FEE_TO), 3_000);
        assertEq(tok.balanceOf(POOL), N - 3_000);
    }

    /// Every payer × payee: native, and two derived kinds each.
    function test_uaPayReceiverFee_matrix() public {
        bytes32[3] memory payers = [_pad(alice), uaP, uaB];
        bytes32[3] memory payees = [_pad(bob), uaE, uaW];
        for (uint256 i; i < 3; ++i) {
            for (uint256 j; j < 3; ++j) {
                _fundId(payers[i], N);
                uint256 payerBefore = tok.balanceOfUA(payers[i]);
                uint256 payeeBefore = tok.balanceOfUA(payees[j]);
                uint256 feeBefore = tok.balanceOf(FEE_TO);
                _run(_pay(payers[i], payees[j], N), 1_000 + j);
                assertEq(tok.balanceOfUA(payers[i]), payerBefore - N);
                assertEq(tok.balanceOfUA(payees[j]), payeeBefore + N - 1_000 - j);
                assertEq(tok.balanceOf(FEE_TO), feeBefore + 1_000 + j);
            }
        }
        assertEq(tok.balanceOf(POOL), tok.balanceOfUA(uaP) + tok.balanceOfUA(uaB) + tok.balanceOfUA(uaE) + tok.balanceOfUA(uaW));
    }

    /// Gas per payer × payee kind (R5a-13, logged): each call from the same state snapshot, so every account and slot
    /// is cold as in its own transaction (the stand-in verifier: the registry's overhead, not a real verify); and the
    /// address path's `mtxPayReceiverFee` (native × native) for comparison.
    function test_gas_uaPayReceiverFee() public {
        bytes32[3] memory payers = [_pad(alice), uaP, uaB];
        bytes32[3] memory payees = [_pad(bob), uaE, uaW];
        string[3] memory pn = ["native", "p256", "bip340"];
        string[3] memory qn = ["native", "ed25519", "webauthn-p256"];
        for (uint256 i; i < 3; ++i) _fundId(payers[i], N);
        for (uint256 i; i < 3; ++i) {
            for (uint256 j; j < 3; ++j) {
                uint256 snap = vm.snapshotState();
                uint256 g = _run(_pay(payers[i], payees[j], N), 1_000);
                emit log_named_uint(string.concat("uaPayReceiverFee payer ", pn[i], ", payee ", qn[j]), g);
                vm.revertToState(snap);
            }
        }
        MetaTxLib.MetaTransfer memory x = MetaTxLib.MetaTransfer({
            from: alice, to: bob, value: N, entryRef: keccak256("addr"), batch: tok.payLane(keccak256("addr")), nonce: 0,
            validUntil: block.timestamp + 300, mode: RR, relayer: RELAYER, fee: 0, feeRecipient: address(0)
        });
        bytes32 d = tok.mtxTransferDigest(x);
        bytes memory ps = _ecdsa(ALICE_PK, d);
        bytes memory rs = _ecdsa(BOB_PK, tok.receiverFeeDigest(d, 1_000, FEE_TO, block.timestamp));
        vm.prank(RELAYER);
        uint256 g0 = gasleft();
        tok.mtxPayReceiverFee(x, ps, 1_000, FEE_TO, block.timestamp, rs);
        emit log_named_uint("mtxPayReceiverFee payer native, payee native", g0 - gasleft());
    }

    // ----- shape, expiry, amount, feature -----

    function test_uaPayReceiverFee_shapeErrors() public {
        _fund(uaP, N);
        bytes memory shape = abi.encodeWithSelector(IMetaTokenV2.ReceiverFeeShape.selector);
        uint256 until = block.timestamp;
        MetaTxLib.UAMetaTransfer memory t = _pay(uaP, uaE, 10);
        t.entryRef = 0;
        _runRevert(t, 1, FEE_TO, until, shape);
        t = _pay(uaP, uaE, 10);
        t.mode = RR | FIX;
        _runRevert(t, 1, FEE_TO, until, shape);
        t = _pay(uaP, uaE, 10);
        t.fee = 1;
        _runRevert(t, 1, FEE_TO, until, shape);
        t = _pay(uaP, uaE, 10);
        t.mode = 0;                                          // payer relayer unbound
        _runRevert(t, 1, FEE_TO, until, shape);
        t = _pay(uaP, uaE, 10);
        t.batch = 1;                                         // not payLane(entryRef)
        _runRevert(t, 1, FEE_TO, until, shape);
        t = _pay(uaP, uaE, 10);
        t.nonce = 1;
        _runRevert(t, 1, FEE_TO, until, shape);
        _runRevert(_pay(uaP, uaE, 10), 1, address(0), until, shape);
        t = _pay(uaP, uaE, 10);
        _runRevert(t, 1, FEE_TO, until - 1,
            abi.encodeWithSelector(IMetaTokenV2.ReceiverFeeExpired.selector, until - 1, until));
        _runRevert(t, 0, FEE_TO, until, abi.encodeWithSelector(IMetaTokenV2.ReceiverFeeAmount.selector, 0, 10));
        _runRevert(t, 11, FEE_TO, until, abi.encodeWithSelector(IMetaTokenV2.ReceiverFeeAmount.selector, 11, 10));
        // `PAYABLE` off
        NoUnderlyingToken np =
            NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(1, plainEnv(address(this), address(0), chainUidA, REG_L, false), ""))));
        IFactoryToken.TokenConfig memory c = noneInit("NP", "NP", 6, 0, address(0), address(this));
        c.features = (1 << AdminLib.MINTABLE) | (1 << AdminLib.BURNABLE);
        np.initialize(address(this), 1, abi.encode(c));
        np.mintToUA(uaP, 10);
        t = _pay(uaP, uaE, 10);
        t.batch = np.payLane(t.entryRef);
        _call(np, t, 1, FEE_TO, until, abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, AdminLib.PAYABLE));
        assertEq(tok.balanceOfUA(uaP), N);
    }

    /// `pad(feeRecipient) == t.to` and the token itself are refused before anything moves.
    function test_uaPayReceiverFee_feeRecipientChecks() public {
        _fund(uaP, N);
        _runRevert(_pay(uaP, _pad(bob), 10), 1, bob, block.timestamp,
            abi.encodeWithSelector(IERC20MetaTx.FeeRecipientIsPayee.selector));
        _runRevert(_pay(uaP, uaE, 10), 1, address(tok), block.timestamp,
            abi.encodeWithSelector(IERC20MetaTx.TransferToSelf.selector));
    }

    /// A `UA_POOL` fee recipient is refused before any move: `_uaMove(payee, pad(UA_POOL), fee)` would debit a derived
    /// payee and leave the pool's slot unchanged (`balanceOf(UA_POOL)` above Σ of the UA balances).
    function test_uaPayReceiverFee_poolFeeRecipientRefused() public {
        _fund(uaP, N);
        _runRevert(_pay(uaP, uaE, 10), 1, POOL, block.timestamp,
            abi.encodeWithSelector(IUALedger.UAPoolNotPayable.selector));
        _runRevert(_pay(uaP, _pad(bob), 10), 1, POOL, block.timestamp,
            abi.encodeWithSelector(IUALedger.UAPoolNotPayable.selector));
        assertEq(tok.balanceOf(POOL), N);
    }

    /// D19: a `SHIELD_POOL` fee recipient is refused (`_uaMove` bypasses the `_update` guard).
    function test_uaPayReceiverFee_shieldPoolFeeRecipientRefused() public {
        _fund(uaP, N);
        _runRevert(_pay(uaP, uaE, 10), 1, MetaTxLib.SHIELD_POOL, block.timestamp,
            abi.encodeWithSelector(IUALedger.ShieldPoolNotPayable.selector));
        assertEq(tok.balanceOf(MetaTxLib.SHIELD_POOL), 0);
    }

    // ----- the co-signature binds one payment -----

    /// A derived payee signs under `receiver-fee` only: its `metatx` signature over the receiver-fee digest fails, and
    /// so does a `receiver-fee` signature over the payer's digest.
    function test_uaPayReceiverFee_purposeSeparation() public {
        _fund(uaP, N);
        MetaTxLib.UAMetaTransfer memory t = _pay(uaP, uaE, 10);
        bytes32 d = tok.uaTransferDigest(t);
        bytes32 rf = tok.receiverFeeDigest(d, 1, FEE_TO, block.timestamp);
        bytes memory payerAuth = _sign(uaP, UAKinds.PURPOSE_METATX, d);
        bytes[2] memory wrong = [_sign(uaE, UAKinds.PURPOSE_METATX, rf), _sign(uaE, UAKinds.PURPOSE_RECEIVER_FEE, d)];
        for (uint256 i; i < 2; ++i) {
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaE));
            vm.prank(RELAYER);
            tok.uaPayReceiverFee(t, payerAuth, 1, FEE_TO, block.timestamp, wrong[i]);
        }
        // and the payer's `receiver-fee` signature does not authorize its payment
        bytes memory payerAsRf = _sign(uaP, UAKinds.PURPOSE_RECEIVER_FEE, d);
        bytes memory payeeAuth = _sign(uaE, UAKinds.PURPOSE_RECEIVER_FEE, rf);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        vm.prank(RELAYER);
        tok.uaPayReceiverFee(t, payerAsRf, 1, FEE_TO, block.timestamp, payeeAuth);
    }

    function test_uaPayReceiverFee_coSignatureOverAnotherDigest_refused() public {
        _fund(uaP, N);
        bytes32[2] memory payees = [_pad(bob), uaE];
        for (uint256 i; i < 2; ++i) {
            MetaTxLib.UAMetaTransfer memory t = _pay(uaP, payees[i], 10);
            MetaTxLib.UAMetaTransfer memory other = _pay(uaP, payees[i], 11);
            bytes memory payerAuth = _sign(uaP, UAKinds.PURPOSE_METATX, tok.uaTransferDigest(t));
            bytes memory payeeAuth = _sign(payees[i], UAKinds.PURPOSE_RECEIVER_FEE,
                tok.receiverFeeDigest(tok.uaTransferDigest(other), 1, FEE_TO, block.timestamp));
            vm.expectRevert(i == 0 ? abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector)
                : abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaE));
            vm.prank(RELAYER);
            tok.uaPayReceiverFee(t, payerAuth, 1, FEE_TO, block.timestamp, payeeAuth);
        }
        assertEq(tok.balanceOfUA(uaP), N);                   // RP4: no fee without the payment, and vice versa
    }

    function test_uaPayReceiverFee_payerIntentLandedElsewhere_coSignatureDead() public {
        _fund(uaP, N);
        MetaTxLib.UAMetaTransfer memory t = _pay(uaP, uaE, 10);
        bytes32 d = tok.uaTransferDigest(t);
        bytes memory payerAuth = _sign(uaP, UAKinds.PURPOSE_METATX, d);
        bytes memory payeeAuth = _sign(uaE, UAKinds.PURPOSE_RECEIVER_FEE, tok.receiverFeeDigest(d, 1, FEE_TO, block.timestamp));
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, payerAuth);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        vm.prank(RELAYER);
        tok.uaPayReceiverFee(t, payerAuth, 1, FEE_TO, block.timestamp, payeeAuth);
        assertEq(tok.balanceOf(FEE_TO), 0);
    }

    // ----- native payees: ERC-1271, EIP-7702 -----

    /// A contract payee co-signs by ERC-1271 with the token's budget: a `SmartKeyAccount` clone (here an EIP-1167 clone
    /// of the token's `SMART_KEY_ACCOUNT_IMPL`) gets 400 k, any other wallet 50 k.
    function test_uaPayReceiverFee_erc1271Payee() public {
        MockWallet impl = new MockWallet(bob, 0, 100_000, address(0)); // ECDSA by bob after burning 100 k gas
        address payee = Clones.clone(address(impl));
        NoUnderlyingToken t400 =
            NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(1, plainEnv(address(this), address(impl), chainUidA, REG_L, false), ""))));
        t400.initialize(address(this), 1, abi.encode(noneInit("S", "S", 6, 0, address(0), address(this))));
        t400.mintToUA(uaP, 2 * N);
        NoUnderlyingToken[2] memory ts = [tok, t400];
        _fund(uaP, N);
        for (uint256 i; i < 2; ++i) {
            MetaTxLib.UAMetaTransfer memory t = _pay(uaP, _pad(payee), N);
            t.batch = ts[i].payLane(t.entryRef);
            bytes32 d = ts[i].uaTransferDigest(t);
            bytes memory payerAuth = _sign(uaP, UAKinds.PURPOSE_METATX, d);
            bytes memory payeeSig = _ecdsa(BOB_PK, ts[i].receiverFeeDigest(d, 2_000, FEE_TO, block.timestamp));
            if (i == 0) vm.expectRevert(IMetaTx.MetaTxBadSignature.selector); // 50 k: not enough for this wallet
            vm.prank(RELAYER);
            ts[i].uaPayReceiverFee(t, payerAuth, 2_000, FEE_TO, block.timestamp, payeeSig);
        }
        assertEq(t400.balanceOf(payee), N - 2_000);
        assertEq(t400.balanceOf(FEE_TO), 2_000);
    }

    /// An EIP-7702 delegated payee (CTR-UA-24): its own key, or the delegate's ERC-1271.
    function test_uaPayReceiverFee_7702Payee() public {
        address carol = vm.addr(0xCA401);
        MockWallet delegate = new MockWallet(bob, 0, 0, address(0));
        vm.signAndAttachDelegation(address(delegate), 0xCA401);
        _fund(uaP, 2 * N);
        for (uint256 i; i < 2; ++i) {
            MetaTxLib.UAMetaTransfer memory t = _pay(uaP, _pad(carol), N);
            bytes32 d = tok.uaTransferDigest(t);
            bytes32 rf = tok.receiverFeeDigest(d, 500, FEE_TO, block.timestamp);
            bytes memory payeeSig = i == 0 ? _ecdsa(0xCA401, rf) : _ecdsa(BOB_PK, rf);
            bytes memory payerAuth = _sign(uaP, UAKinds.PURPOSE_METATX, d);
            vm.prank(RELAYER);
            tok.uaPayReceiverFee(t, payerAuth, 500, FEE_TO, block.timestamp, payeeSig);
        }
        assertEq(tok.balanceOf(carol), 2 * (N - 500));
    }

    /// RP1 under fuzz: payee nets `N − fee ≥ 0`, payer `−N`, fee recipient `+fee`.
    function testFuzz_uaPayReceiverFee_rp1(uint256 n, uint256 fee) public {
        n = bound(n, 1, 1_000_000);
        fee = bound(fee, 1, n);
        _fund(uaB, n);
        _run(_pay(uaB, uaW, n), fee);
        assertEq(tok.balanceOfUA(uaB), 0);
        assertEq(tok.balanceOfUA(uaW), n - fee);
        assertEq(tok.balanceOf(FEE_TO), fee);
        assertEq(tok.balanceOf(POOL), n - fee);
    }
}
