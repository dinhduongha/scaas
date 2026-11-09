// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {UACall} from "../ua/UACall.sol";
import {RegFixture} from "../as/helpers/RegFixture.sol";
import {MockHederaAccountService} from "../hedera/HederaMocks.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {RefServiceEscrow, RefServiceEscrowFailAfter, NoopPullToken, ReenterPullToken, NakedPuller}
    from "./helpers/RefServiceEscrow.sol";
import {spDepositRef, spNoteRef, spPull, spRelayFeeDigest} from "./helpers/ServicePullKit.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {SmartKeyAccount, SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";

/// @notice Service pull (spec 2026-11-09-service-pull §3, §11; proposed CTR-MTX-32; plan T77), on a `NORMAL` token with the
///         UA ledger on (`UALedgerBase`): the reference service `RefServiceEscrow` (test only), its positive controls for
///         every payer class (a native EOA, a derived single-key UA, an `msig` UA, a `SmartKeyAccount` by ERC-1271, a
///         Hedera 64-byte payer), relayed directly and through `RelayFeeRouter` (the fee in the pulled token on one lane,
///         `n` then `n + 1`, and in another token), and the negatives N1-N13, N15-N20, one change at a time from the
///         control, each with its named error. The regulated negatives N14, N14b are `ServicePullRegTest`; every kind
///         is `ServicePullKinds.t.sol`; the invariants are `ServicePullInvariant.t.sol`. UNAUDITED.
contract ServicePullTest is UALedgerBase {
    address internal constant REL = address(0x7E1A); // a lane: any account
    uint256 internal constant LANE = 7;
    uint256 internal constant AMT = 1_000;
    uint256 internal constant FEE = 25;
    address internal constant HAS = address(0x16a);

    RefServiceEscrow internal s;
    RelayFeeRouter internal router;

    function setUp() public override {
        super.setUp();
        s = new RefServiceEscrow(address(tok));
        router = new RelayFeeRouter();
        _fund(uaP, 100_000);
    }

    // ------------------------------------------------------------------ helpers

    function _dep(bytes32 payer, bytes32 salt) internal view returns (RefServiceEscrow.Deposit memory) {
        return RefServiceEscrow.Deposit(payer, AMT, uint64(block.timestamp + 1 hours), salt);
    }

    /// The pull of `op` for `svc` on `token`, at the payer's next nonce on `LANE`.
    function _pullOf(address token, address svc, RefServiceEscrow.Deposit memory op)
        internal view returns (MetaTxLib.UAMetaTransfer memory)
    {
        return spPull(op.payer, svc, op.amount, spDepositRef(svc, block.chainid, op), LANE,
            NormalToken(token).mtxNonce(op.payer, LANE), block.timestamp + 300);
    }

    function _pull(RefServiceEscrow.Deposit memory op) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        return _pullOf(address(tok), address(s), op);
    }

    /// The payer's own signature of `t` in `token`'s domain (`UALedgerBase._authFor`: alice, bob, `uaP`, `uaB`, `uaZ`).
    function _sigOn(address token, MetaTxLib.UAMetaTransfer memory t) internal view returns (IUARegistry.UASig memory) {
        return UACall.auth(t.from, _authT(token, t));
    }

    function _sig(MetaTxLib.UAMetaTransfer memory t) internal view returns (IUARegistry.UASig memory) {
        return _sigOn(address(tok), t);
    }

    function _deposit(RefServiceEscrow svc, RefServiceEscrow.Deposit memory op, MetaTxLib.UAMetaTransfer memory t) internal {
        IUARegistry.UASig memory a = _sigOn(svc.TOKEN(), t);
        vm.prank(REL);
        svc.deposit(op, t, a);
    }

    function _refused(RefServiceEscrow svc, RefServiceEscrow.Deposit memory op, MetaTxLib.UAMetaTransfer memory t,
        bytes memory err) internal
    {
        IUARegistry.UASig memory a = _sigOn(svc.TOKEN(), t);
        vm.prank(REL);
        vm.expectRevert(err);
        svc.deposit(op, t, a);
    }

    function _shape(uint8 code) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(RefServiceEscrow.ServicePullShape.selector, code);
    }

    function _custody(RefServiceEscrow svc, bytes32 ref) internal view returns (bytes32 payer, uint256 amount) {
        (payer, amount,) = svc.custody(ref);
    }

    /// The control: `op` of alice lands, nothing else changes. Snapshot-reverted by the negatives that use it.
    function _control(RefServiceEscrow.Deposit memory op) internal {
        uint256 snap = vm.snapshotState();
        _deposit(s, op, _pull(op));
        assertEq(tok.balanceOf(address(s)), AMT, "control");
        vm.revertToState(snap);
    }

    // ------------------------------------------------------------------ positive controls

    /// A native EOA: the pull, its events (`UAPaymentSettled` payer -> S with the operation digest, then
    /// `UAMetaTransactionExecuted` with `relayer` = S), the custody, the refusal before `releaseAfter`, the permissionless
    /// release after it.
    function test_positive_nativeEoa() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "eoa");
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        bytes32 ref = t.entryRef;
        assertEq(ref, s.depositRef(op), "the service's digest is the test's");
        uint256 a0 = tok.balanceOf(alice);
        IUARegistry.UASig memory a = _sig(t);
        vm.expectEmit(address(tok));
        emit IUALedger.UAPaymentSettled(_pad(alice), _pad(address(s)), AMT, 0, address(s), ref);
        vm.expectEmit(address(tok));
        emit IUALedger.UAMetaTransactionExecuted(_pad(alice), address(s), LANE, 0, tok.mtxTransferDigest(t), address(s), 0);
        vm.expectEmit(address(s));
        emit RefServiceEscrow.Deposited(ref, _pad(alice), AMT, op.releaseAfter, op.salt);
        vm.prank(REL);
        s.deposit(op, t, a);
        assertEq(tok.balanceOf(alice), a0 - AMT);
        assertEq(tok.balanceOf(address(s)), AMT);
        (bytes32 p, uint256 v) = _custody(s, ref);
        assertEq(p, _pad(alice));
        assertEq(v, AMT);
        assertTrue(s.used(ref));
        assertEq(s.owed(), AMT);
        assertEq(tok.mtxNonce(_pad(alice), LANE), 1);
        vm.expectRevert(abi.encodeWithSelector(RefServiceEscrow.NotReleasable.selector, ref));
        s.release(ref);
        vm.warp(op.releaseAfter);
        vm.prank(address(0xD00D)); // anyone
        s.release(ref);
        assertEq(tok.balanceOf(alice), a0);
        assertEq(s.owed(), 0);
        (, v) = _custody(s, ref);
        assertEq(v, 0);
        vm.expectRevert(abi.encodeWithSelector(RefServiceEscrow.NotReleasable.selector, ref));
        s.release(ref);
    }

    /// A derived single-key UA (`p256`): its UA-ledger balance pulled, released by `transferToUA`.
    function test_positive_derivedUA() public {
        RefServiceEscrow.Deposit memory op = _dep(uaP, "ua");
        uint256 b0 = tok.balanceOfUA(uaP);
        bytes32 ref = _pull(op).entryRef;
        _deposit(s, op, _pull(op));
        assertEq(tok.balanceOfUA(uaP), b0 - AMT);
        assertEq(tok.balanceOf(address(s)), AMT);
        vm.warp(op.releaseAfter);
        s.release(ref);
        assertEq(tok.balanceOfUA(uaP), b0);
    }

    /// An `msig` UA of two EOAs (2 of 2, both slots accepted): `members` at the threshold.
    function test_positive_msigUA() public {
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(alice), 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(bob), 1);
        bytes memory d = _msigKey(2, m);
        bytes32 ua = UACall.register(lreg, UAKinds.MSIG, d, _none(), "", "");
        lreg.acceptMembership(ua, _acceptEoaSig(d, ALICE_PK));
        lreg.acceptMembership(ua, _acceptEoaSig(d, BOB_PK));
        tok.mintToUA(ua, 10_000);
        RefServiceEscrow.Deposit memory op = _dep(ua, "msig");
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, tok.mtxTransferDigest(t));
        uint16 ia = _indexOf(d, _pad(alice));
        IUARegistry.UASig memory a;
        a.members = new IUARegistry.MemberSig[](2);
        a.members[ia] = IUARegistry.MemberSig(ia, new IUARegistry.InnerSig[](0), _nativeSig(lreg, ALICE_PK, UAKinds.PURPOSE_MEMBER, md));
        a.members[1 - ia] = IUARegistry.MemberSig(1 - ia, new IUARegistry.InnerSig[](0), _nativeSig(lreg, BOB_PK, UAKinds.PURPOSE_MEMBER, md));
        vm.prank(REL);
        s.deposit(op, t, a);
        assertEq(tok.balanceOfUA(ua), 10_000 - AMT);
        vm.warp(op.releaseAfter);
        s.release(t.entryRef);
        assertEq(tok.balanceOfUA(ua), 10_000);
    }

    /// A `SmartKeyAccount` (ERC-1271, its secp256k1 key alice's): `abi.encode(keyIndex, proof, signature)`.
    function test_positive_smartKeyAccount() public {
        SmartKeyAccount acct = SmartKeyAccount(payable(new SmartKeyAccountFactory(chainUidA).deploy(
            SubjectKey(KeyKind.SECP256K1, _pad(alice), 0, 0, 0), address(0xD00D))));
        tok.mint(address(acct), 5_000);
        RefServiceEscrow.Deposit memory op = _dep(_pad(address(acct)), "ska");
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        IUARegistry.UASig memory a;
        a.signature = abi.encode(uint256(0), new bytes32[](0), _ecdsa(ALICE_PK, tok.mtxTransferDigest(t)));
        vm.prank(REL);
        s.deposit(op, t, a);
        assertEq(tok.balanceOf(address(acct)), 5_000 - AMT);
        vm.warp(op.releaseAfter);
        s.release(t.entryRef);
        assertEq(tok.balanceOf(address(acct)), 5_000);
    }

    /// Hedera: a long-zero ED25519 account (HIP-632, 64 bytes; the precompile mocked as `test/hedera`) on a `NORMAL` clone
    /// whose env says Hedera; the service is the same code.
    function test_positive_hedera64() public {
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        address ha = address(uint160(1_234_567));
        MockHederaAccountService(HAS).setEdKey(ha, vm.addr(0xA11CE5));
        NormalToken h = NormalToken(EnvKit.clone(address(new NormalToken(address(this), "")), EnvKit.env(chainUidA, address(0), address(0), true)));
        h.initialize(nid(address(this)), 1, abi.encode(normalInit("Points", "PTS", 6, 5_000, ha, address(this))));
        RefServiceEscrow sh = new RefServiceEscrow(address(h));
        RefServiceEscrow.Deposit memory op = _dep(_pad(ha), "hedera");
        MetaTxLib.UAMetaTransfer memory t = _pullOf(address(h), address(sh), op);
        (bytes32 r, bytes32 vs) = vm.signCompact(0xA11CE5, h.mtxTransferDigest(t));
        IUARegistry.UASig memory a;
        a.signature = abi.encodePacked(r, vs);
        assertEq(a.signature.length, 64);
        vm.prank(REL);
        sh.deposit(op, t, a);
        assertEq(h.balanceOf(ha), 5_000 - AMT);
        vm.warp(op.releaseAfter);
        sh.release(t.entryRef);
        assertEq(h.balanceOf(ha), 5_000);
    }

    /// `note`: the dynamic fields (`string`, `bytes`) hashed as `keccak256(value)` in the digest, passed raw in the ABI.
    function test_positive_note() public {
        RefServiceEscrow.Note memory op = RefServiceEscrow.Note(_pad(alice), AMT, "invoice 42: deposit", hex"c0ffee00", "n1");
        bytes32 ref = spNoteRef(address(s), block.chainid, op);
        assertEq(ref, s.noteRef(op));
        MetaTxLib.UAMetaTransfer memory t = spPull(_pad(alice), address(s), AMT, ref, LANE, 0, block.timestamp + 300);
        IUARegistry.UASig memory a = _sig(t);
        vm.expectEmit(address(s));
        emit RefServiceEscrow.Noted(ref, _pad(alice), AMT, op.memo, op.commitment, op.salt);
        vm.prank(REL);
        s.note(op, t, a);
        s.release(ref);
        assertEq(tok.balanceOf(address(s)), 0);
        op.memo = "invoice 43: deposit"; // one byte of the string: another digest
        assertTrue(spNoteRef(address(s), block.chainid, op) != ref);
        op.memo = "invoice 42: deposit";
        op.commitment = hex"c0ffee01";
        assertTrue(spNoteRef(address(s), block.chainid, op) != ref);
    }

    /// `servicePullEntries()` and ERC-5267: the two entries, their `encodeType`, the fixed token; the domain the test hashes.
    function test_discovery() public view {
        (bytes4[] memory sel, string[] memory ty, address[] memory tk) = s.servicePullEntries();
        assertEq(sel.length, 2);
        assertEq(sel[0], RefServiceEscrow.deposit.selector);
        assertEq(sel[1], RefServiceEscrow.note.selector);
        assertEq(ty[0], "Deposit(bytes32 payer,uint256 amount,uint64 releaseAfter,bytes32 salt)");
        assertEq(ty[1], "Note(bytes32 payer,uint256 amount,string memo,bytes commitment,bytes32 salt)");
        assertEq(tk[0], address(tok));
        assertEq(tk[1], address(tok));
        (bytes1 f, string memory n, string memory v, uint256 cid, address vc,,) = s.eip712Domain();
        assertEq(f, bytes1(0x0f));
        assertEq(n, "SCaaS RefServiceEscrow");
        assertEq(v, "1");
        assertEq(cid, block.chainid);
        assertEq(vc, address(s));
        assertEq(s.REGULATED(), false);
    }

    // ------------------------------------------------------------------ relay fee (§2.4 (b))

    function _relayFee(address feeToken, bytes memory cd, uint256 batch, uint256 nonce) internal view returns (bytes memory) {
        return _ecdsa(ALICE_PK, spRelayFeeDigest(feeToken, _pad(alice), address(s), cd, _pad(address(router)), FEE, batch, nonce,
            block.timestamp + 300, address(router)));
    }

    function _relay(address feeToken, bytes memory cd, uint256 batch, uint256 nonce, bytes memory sig) internal {
        IUARegistry.UASig memory fa;
        fa.signature = sig;
        vm.prank(REL);
        router.relay(address(s), cd, feeToken, _pad(alice), _pad(address(router)), FEE, batch, nonce, block.timestamp + 300, fa);
    }

    /// F = T on one lane: the pull takes `n`, the fee `n + 1` (the router runs the target first); open mode pays the lane.
    function test_positive_relayFeeSameTokenOneLane() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "rf-T");
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        uint256 n = t.nonce;
        bytes memory cd = abi.encodeCall(RefServiceEscrow.deposit, (op, t, _sig(t)));
        uint256 a0 = tok.balanceOf(alice);
        _relay(address(tok), cd, LANE, n + 1, _relayFee(address(tok), cd, LANE, n + 1));
        assertEq(tok.balanceOf(address(s)), AMT);
        assertEq(tok.balanceOf(REL), FEE);
        assertEq(tok.balanceOf(alice), a0 - AMT - FEE);
        assertEq(tok.mtxNonce(_pad(alice), LANE), n + 2);
    }

    /// The fee in another SCaaS token (`wrp`), on its own lane.
    function test_positive_relayFeeOtherToken() public {
        _wrapFor(alice, 1_000);
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "rf-F");
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        bytes memory cd = abi.encodeCall(RefServiceEscrow.deposit, (op, t, _sig(t)));
        _relay(address(wrp), cd, 2, 0, _relayFee(address(wrp), cd, 2, 0));
        assertEq(tok.balanceOf(address(s)), AMT);
        assertEq(wrp.balanceOf(REL), FEE);
        assertEq(wrp.balanceOf(alice), 1_000 - FEE);
    }

    /// N13: the wrapped service operation reverts (an `op` field changed after signing): no fee, nothing moved.
    function test_N13_relayFeeServiceRevertsNoFee() public {
        _wrapFor(alice, 1_000);
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "rf-13");
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        op.salt = "rf-13'";
        bytes memory cd = abi.encodeCall(RefServiceEscrow.deposit, (op, t, _sig(t)));
        bytes memory fs = _relayFee(address(wrp), cd, 2, 0);
        IUARegistry.UASig memory fa;
        fa.signature = fs;
        vm.prank(REL);
        vm.expectRevert(_shape(3));
        router.relay(address(s), cd, address(wrp), _pad(alice), _pad(address(router)), FEE, 2, 0, block.timestamp + 300, fa);
        assertEq(wrp.balanceOf(REL), 0);
        assertEq(wrp.balanceOf(alice), 1_000);
        assertEq(tok.balanceOf(address(s)), 0);
    }

    /// N19: F = T, the fee signed at the pull's own nonce: the pull runs first and takes it, the fee then fails
    /// `MetaTxBadNonce(n + 1, n)`, the whole relay reverts, no fee (proves §2.4's order).
    function test_N19_relayFeeAtPullNonce() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "rf-19");
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        uint256 n = t.nonce;
        bytes memory cd = abi.encodeCall(RefServiceEscrow.deposit, (op, t, _sig(t)));
        bytes memory fs = _relayFee(address(tok), cd, LANE, n);
        IUARegistry.UASig memory fa;
        fa.signature = fs;
        uint256 a0 = tok.balanceOf(alice);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, n + 1, n));
        router.relay(address(s), cd, address(tok), _pad(alice), _pad(address(router)), FEE, LANE, n, block.timestamp + 300, fa);
        assertEq(tok.balanceOf(alice), a0);
        assertEq(tok.balanceOf(REL), 0);
        assertEq(tok.mtxNonce(_pad(alice), LANE), n);
    }

    // ------------------------------------------------------------------ negatives (§11), one change from the control

    /// N1: `t.to` another id (bob; the token itself).
    function test_N1_toNotService() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n1");
        _control(op);
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        t.to = _pad(bob);
        _refused(s, op, t, _shape(1));
        t.to = _pad(address(tok));
        _refused(s, op, t, _shape(1));
    }

    /// N2: the relayer bit off; `relayer` another address; fee mode `PERCENT` / `FIXED`; the fee-recipient bit on.
    function test_N2_modeAndRelayer() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n2");
        _control(op);
        uint32[4] memory modes = [uint32(0), RR | PCT, RR | FIX, RR | RF];
        for (uint256 i; i < 4; ++i) {
            MetaTxLib.UAMetaTransfer memory t = _pull(op);
            t.mode = modes[i];
            _refused(s, op, t, _shape(2));
        }
        MetaTxLib.UAMetaTransfer memory u = _pull(op);
        u.relayer = REL;
        _refused(s, op, u, _shape(2));
    }

    /// N3: each `op` field changed after signing; `entryRef` from another service or another chain.
    function test_N3_entryRefNotTheOperation() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n3");
        _control(op);
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        for (uint256 i; i < 4; ++i) {
            RefServiceEscrow.Deposit memory o = _dep(_pad(alice), "n3");
            if (i == 0) o.payer = _pad(bob);
            if (i == 1) o.amount += 1;
            if (i == 2) o.releaseAfter += 1;
            if (i == 3) o.salt = "n3'";
            _refused(s, o, t, _shape(3));
        }
        RefServiceEscrow other = new RefServiceEscrow(address(tok));
        t.entryRef = spDepositRef(address(other), block.chainid, op);
        _refused(s, op, t, _shape(3));
        t.entryRef = spDepositRef(address(s), 1, op);
        _refused(s, op, t, _shape(3));
    }

    /// N4: `t.from` (bob, who signs) is not `op.payer` (alice); `entryRef` is `op`'s.
    function test_N4_fromNotPayer() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n4");
        _control(op);
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        t.from = _pad(bob);
        _refused(s, op, t, _shape(4));
    }

    /// N5: `value` not the operation's amount; `value = 0` (with `op.amount = 0`).
    function test_N5_value() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n5");
        _control(op);
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        t.value = AMT + 1;
        _refused(s, op, t, _shape(5));
        t.value = AMT - 1;
        _refused(s, op, t, _shape(5));
        op.amount = 0;
        t = _pull(op);
        _refused(s, op, t, _shape(5));
    }

    /// N6: expired.
    function test_N6_expired() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n6");
        _control(op);
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        vm.warp(t.validUntil + 1);
        _refused(s, op, t, abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, t.validUntil, t.validUntil + 1));
    }

    /// N7: the lane cancelled by `mtxCancelNonce` first: `MetaTxBadNonce`. The same `(op, t, auth)` submitted twice meets
    /// step 6 first (§3.3: the seen `entryRef` before the token's nonce): `ServicePullReplayed`.
    function test_N7_cancelledAndResubmitted() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n7");
        _control(op);
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(_pad(alice), 9, 0, block.timestamp + 300, 0, address(0), 0, address(0));
        bytes32 h = keccak256(bytes.concat(abi.encode(MetaTxLib.UA_CANCEL_NONCE_TYPEHASH, e.from), abi.encode(LANE),
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        IUARegistry.UASig memory ca;
        ca.signature = _ecdsa(ALICE_PK, MtxDigest.typed(address(tok), h));
        tok.mtxCancelNonce(e, LANE, ca);
        _refused(s, op, t, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        t = _pull(op);
        _deposit(s, op, t);
        _refused(s, op, t, abi.encodeWithSelector(RefServiceEscrow.ServicePullReplayed.selector, t.entryRef));
    }

    /// N8: a third party lands `t` on the token directly: `mtxExecuteTransfer`, `mtxBatchTransfer` (the relayer binding);
    /// `mtxPay`, `mtxPayReceiverFee` (`PAYABLE` on: the pay reference first).
    function test_N8_tokenDirect() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n8");
        _control(op);
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        IUARegistry.UASig memory a = _sig(t);
        bytes memory rel = abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, address(s), REL);
        vm.prank(REL);
        vm.expectRevert(rel);
        tok.mtxExecuteTransfer(t, a);
        MetaTxLib.UAMetaTransfer[] memory ts = new MetaTxLib.UAMetaTransfer[](1);
        IUARegistry.UASig[] memory as_ = new IUARegistry.UASig[](1);
        (ts[0], as_[0]) = (t, a);
        vm.prank(REL);
        vm.expectRevert(rel);
        tok.mtxBatchTransfer(ts, as_);
        MetaTxLib.PayMeta memory m = PayMetaKit.meta("n8");
        bytes memory mis = abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, t.entryRef, PayMetaKit.id(m));
        vm.prank(REL);
        vm.expectRevert(mis);
        tok.mtxPay(t, a, m);
        vm.prank(REL);
        vm.expectRevert(mis);
        tok.mtxPayReceiverFee(t, a, 0, address(0), block.timestamp + 300, a, m);
        assertEq(tok.balanceOf(address(s)), 0);
    }

    /// N9: a second escrow (same code, another address): `t` as signed is not for it (check 1); `t.to` rewritten to it,
    /// the relayer is still S (check 2); a contract with no checks of its own meets the token's relayer binding.
    function test_N9_otherService() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n9");
        _control(op);
        RefServiceEscrow s2 = new RefServiceEscrow(address(tok));
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        _refused(s2, op, t, _shape(1));
        MetaTxLib.UAMetaTransfer memory u = _pull(op);
        u.to = _pad(address(s2));
        _refused(s2, op, u, _shape(2));
        NakedPuller naked = new NakedPuller();
        IUARegistry.UASig memory a = _sig(t);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, address(s), address(naked)));
        naked.pull(address(tok), t, a);
    }

    /// N10: `t` signed in another token's domain; in this token's domain on another chain.
    function test_N10_otherDomain() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n10");
        _control(op);
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        IUARegistry.UASig memory a;
        a.signature = _ecdsa(ALICE_PK, wrp.mtxTransferDigest(t));
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        s.deposit(op, t, a);
        uint256 cid = block.chainid;
        vm.chainId(1);
        a.signature = _ecdsa(ALICE_PK, tok.mtxTransferDigest(t));
        vm.chainId(cid);
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        s.deposit(op, t, a);
    }

    /// N11: a token that answers `true` and moves nothing: the delta check (C5).
    function test_N11_noopToken() public {
        NoopPullToken nt = new NoopPullToken();
        RefServiceEscrow sn = new RefServiceEscrow(address(nt));
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n11");
        MetaTxLib.UAMetaTransfer memory t = spPull(op.payer, address(sn), AMT, spDepositRef(address(sn), block.chainid, op), LANE, 0,
            block.timestamp + 300);
        IUARegistry.UASig memory a;
        vm.expectRevert(abi.encodeWithSelector(RefServiceEscrow.ServicePullNotReceived.selector, AMT, 0));
        sn.deposit(op, t, a);
    }

    /// N12: the service's logic reverts after the pull: the payer's balance and lane nonce unchanged.
    function test_N12_logicRevertsAfterPull() public {
        RefServiceEscrowFailAfter sf = new RefServiceEscrowFailAfter(address(tok));
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n12");
        MetaTxLib.UAMetaTransfer memory t = _pullOf(address(tok), address(sf), op);
        uint256 a0 = tok.balanceOf(alice);
        _refused(sf, op, t, abi.encodeWithSelector(RefServiceEscrowFailAfter.LogicFailed.selector, t.entryRef));
        assertEq(tok.balanceOf(alice), a0);
        assertEq(tok.mtxNonce(_pad(alice), LANE), 0);
        assertEq(tok.balanceOf(address(sf)), 0);
        assertFalse(sf.used(t.entryRef));
    }

    /// N15: a derived payer on a token with the UA ledger off.
    function test_N15_derivedLedgerOff() public {
        NormalToken off = NormalToken(EnvKit.clone(address(new NormalToken(address(this), "")), EnvKit.env(chainUidA, address(0), address(0), false)));
        off.initialize(nid(address(this)), 1, abi.encode(normalInit("Off", "OFF", 6, 1_000_000, alice, address(this))));
        RefServiceEscrow so = new RefServiceEscrow(address(off));
        RefServiceEscrow.Deposit memory c = _dep(_pad(alice), "n15c");
        _deposit(so, c, _pullOf(address(off), address(so), c)); // the control: a native payer runs
        RefServiceEscrow.Deposit memory op = _dep(uaP, "n15");
        MetaTxLib.UAMetaTransfer memory t = _pullOf(address(off), address(so), op);
        IUARegistry.UASig memory a = UACall.auth(uaP, _authFor(uaP, off.mtxTransferDigest(t)));
        vm.prank(REL);
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        so.deposit(op, t, a);
    }

    /// N16: an EIP-7702 designator account (delegated to the service's code) as the bound executor.
    function test_N16_delegatedExecutor() public {
        address e = vm.addr(0xE7702);
        vm.etch(e, abi.encodePacked(hex"ef0100", address(s)));
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n16");
        MetaTxLib.UAMetaTransfer memory t = _pullOf(address(tok), e, op);
        _refused(RefServiceEscrow(e), op, t, abi.encodeWithSelector(SigCheck.CallerDelegated.selector, e));
        _control(op);
    }

    /// N17: the same `op` signed twice, on two nonces: the second is refused (Q4).
    function test_N17_operationTwice() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n17");
        _deposit(s, op, _pull(op));
        MetaTxLib.UAMetaTransfer memory t2 = _pull(op);
        assertEq(t2.nonce, 1);
        _refused(s, op, t2, abi.encodeWithSelector(RefServiceEscrow.ServicePullReplayed.selector, t2.entryRef));
        assertEq(tok.balanceOf(address(s)), AMT);
    }

    /// N18: `t.fee != 0` or `t.feeRecipient != 0` at fee `NONE` (the token would accept both: unbound, uncharged).
    function test_N18_feePins() public {
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n18");
        _control(op);
        MetaTxLib.UAMetaTransfer memory t = _pull(op);
        t.fee = 1;
        _refused(s, op, t, _shape(2));
        t = _pull(op);
        t.feeRecipient = bob;
        _refused(s, op, t, _shape(2));
        // what the pin closes: through a contract with no checks, both land (nothing charged; `feeRecipient` in the events)
        NakedPuller naked = new NakedPuller();
        RefServiceEscrow.Deposit memory o2 = _dep(_pad(alice), "n18-naked");
        MetaTxLib.UAMetaTransfer memory u = spPull(o2.payer, address(naked), AMT, bytes32(uint256(1)), LANE, 0, block.timestamp + 300);
        (u.fee, u.feeRecipient) = (1, bob);
        IUARegistry.UASig memory a = _sig(u);
        vm.expectEmit(address(tok));
        emit IUALedger.UAPaymentSettled(_pad(alice), _pad(address(naked)), AMT, 0, bob, u.entryRef);
        naked.pull(address(tok), u, a);
        assertEq(tok.balanceOf(bob), 0, "nothing charged at fee NONE");
    }

    /// N20: a token that re-enters `deposit` during `mtxExecuteTransfer`: the service's transient guard. Unarmed, the same
    /// stand-in lands the deposit (its positive control).
    function test_N20_reentrantToken() public {
        ReenterPullToken rt = new ReenterPullToken();
        RefServiceEscrow sr = new RefServiceEscrow(address(rt));
        RefServiceEscrow.Deposit memory op = _dep(_pad(alice), "n20");
        RefServiceEscrow.Deposit memory op2 = _dep(_pad(alice), "n20'");
        MetaTxLib.UAMetaTransfer memory t = spPull(op.payer, address(sr), AMT, spDepositRef(address(sr), block.chainid, op), LANE, 0,
            block.timestamp + 300);
        MetaTxLib.UAMetaTransfer memory t2 = spPull(op.payer, address(sr), AMT, spDepositRef(address(sr), block.chainid, op2), LANE,
            1, block.timestamp + 300);
        IUARegistry.UASig memory a;
        uint256 snap = vm.snapshotState();
        sr.deposit(op, t, a);
        assertEq(rt.balanceOf(address(sr)), AMT, "control");
        vm.revertToState(snap);
        rt.arm(address(sr), abi.encodeCall(RefServiceEscrow.deposit, (op2, t2, a)));
        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        sr.deposit(op, t, a);
    }
}

/// @notice The regulated negatives N14, N14b (spec §6, §3.4, Q5) and the forced move on kinds 8 and 9 (`RegFixture`, lists
///         off unless named): S not eligible under `ALLOWLIST`, then eligible by `ELIGIBLE_CONTRACT`; the payer frozen; the
///         token paused; S frozen at release; `operatorTransfer` from S; a pull while S is frozen; the payee ineligible at
///         release, custody intact, the retry after re-eligibility; a `forceTransfer` on S: the shortfall falls on the last
///         claimant, the payout fails closed. Each with its positive control. UNAUDITED.
contract ServicePullRegTest is RegFixture {
    address internal constant REL = address(0x7E1A);
    uint256 internal constant LANE = 7;
    uint256 internal constant AMT = 1_000;
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;

    function _dep(address payer, bytes32 salt) internal view returns (RefServiceEscrow.Deposit memory) {
        return RefServiceEscrow.Deposit(nid(payer), AMT, uint64(block.timestamp), salt);
    }

    function _pullOf(address t, RefServiceEscrow svc, RefServiceEscrow.Deposit memory op)
        internal view returns (MetaTxLib.UAMetaTransfer memory)
    {
        return spPull(op.payer, address(svc), op.amount, spDepositRef(address(svc), block.chainid, op), LANE,
            MetaTokenBase(t).mtxNonce(op.payer, LANE), block.timestamp + 300);
    }

    function _sigOf(uint256 pk, address t, MetaTxLib.UAMetaTransfer memory x) internal view returns (IUARegistry.UASig memory a) {
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, MetaTokenBase(t).mtxTransferDigest(x));
        a.signature = abi.encodePacked(r, ss, v);
    }

    function _deposit(uint256 pk, RefServiceEscrow svc, RefServiceEscrow.Deposit memory op) internal returns (bytes32) {
        MetaTxLib.UAMetaTransfer memory x = _pullOf(svc.TOKEN(), svc, op);
        IUARegistry.UASig memory a = _sigOf(pk, svc.TOKEN(), x);
        vm.prank(REL);
        svc.deposit(op, x, a);
        return x.entryRef;
    }

    function _refused(uint256 pk, RefServiceEscrow svc, RefServiceEscrow.Deposit memory op, bytes memory err) internal {
        MetaTxLib.UAMetaTransfer memory x = _pullOf(svc.TOKEN(), svc, op);
        IUARegistry.UASig memory a = _sigOf(pk, svc.TOKEN(), x);
        vm.prank(REL);
        vm.expectRevert(err);
        svc.deposit(op, x, a);
    }

    /// The positive control on both kinds: deposit and release, `REGULATED` read from the token.
    function test_reg_positive() public {
        for (uint256 i; i < 2; ++i) {
            RefServiceEscrow svc = new RefServiceEscrow(_ks()[i]);
            assertTrue(svc.REGULATED());
            bytes32 ref = _deposit(ALICE_PK, svc, _dep(alice, "p"));
            assertEq(IERC20(_ks()[i]).balanceOf(address(svc)), AMT);
            svc.release(ref);
            assertEq(IERC20(_ks()[i]).balanceOf(alice), SUPPLY);
        }
    }

    /// N14 (a): `ALLOWLIST` on: S not eligible (`R(S)` in the move); with `ELIGIBLE_CONTRACT` it is.
    function test_N14_serviceNotEligible() public {
        address t = _listed(0, KYC, 0, "sp-l");
        RefServiceEscrow svc = new RefServiceEscrow(t);
        _refused(ALICE_PK, svc, _dep(alice, "a"), abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(address(svc)), 0));
        _attestAs(cadmin, nid(address(svc)), ELIGIBLE, type(uint64).max);
        bytes32 ref = _deposit(ALICE_PK, svc, _dep(alice, "a"));
        svc.release(ref);
        assertEq(IERC20(t).balanceOf(alice), SUPPLY);
    }

    /// N14 (b) the payer frozen; (c) the token paused.
    function test_N14_payerFrozenAndPaused() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            RefServiceEscrow svc = new RefServiceEscrow(t);
            uint256 snap = vm.snapshotState();
            _deposit(ALICE_PK, svc, _dep(alice, "b"));
            vm.revertToState(snap);
            _freeze(t, nid(alice));
            _refused(ALICE_PK, svc, _dep(alice, "b"), abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(alice)));
            _unfreeze(t, nid(alice));
            uint64 until = _now() + 1 days;
            _pause(t, until);
            _refused(ALICE_PK, svc, _dep(alice, "c"), abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until));
        }
    }

    /// N14 (d) S frozen at release: refused, custody intact, paid after the unfreeze; (f) a pull while S is frozen.
    function test_N14_serviceFrozen() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            RefServiceEscrow svc = new RefServiceEscrow(t);
            bytes32 ref = _deposit(ALICE_PK, svc, _dep(alice, "d"));
            _freeze(t, nid(address(svc)));
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(address(svc))));
            svc.release(ref);
            (, uint256 v,) = svc.custody(ref);
            assertEq(v, AMT, "custody intact");
            _refused(ALICE_PK, svc, _dep(alice, "f"), abi.encodeWithSelector(RefServiceEscrow.ServicePullFrozen.selector));
            _unfreeze(t, nid(address(svc)));
            svc.release(ref);
            assertEq(IERC20(t).balanceOf(alice), SUPPLY);
        }
    }

    /// N14 (e) `operatorTransfer` from S (a `from` with code) is refused; from alice it runs (the control).
    function test_N14_operatorFromService() public {
        IFactoryToken.TokenConfig memory c = _cfg8();
        c.features |= uint256(1) << GovernanceBits.OPERATOR_TRANSFER;
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "sp-op");
        address clerk = address(0xC1E2);
        vm.prank(ownerA);
        MetaTokenBase(t).grantRole(GovernanceBits.OPERATOR_TRANSFER, nid(clerk));
        vm.warp(block.timestamp + GD);
        vm.prank(ownerA);
        MetaTokenBase(t).grantRole(GovernanceBits.OPERATOR_TRANSFER, nid(clerk));
        RefServiceEscrow svc = new RefServiceEscrow(t);
        _deposit(ALICE_PK, svc, _dep(alice, "e"));
        vm.prank(clerk);
        _r(t).operatorTransfer(nid(alice), nid(bob), 1, REF);
        assertEq(IERC20(t).balanceOf(bob), 1);
        vm.prank(clerk);
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OperatorTargetRefused.selector, nid(address(svc))));
        _r(t).operatorTransfer(nid(address(svc)), nid(bob), 1, REF);
        assertEq(IERC20(t).balanceOf(address(svc)), AMT);
    }

    /// N14b: the payee (the payer) is no longer eligible at release: `NotEligible`, custody intact; re-attested, the retry
    /// succeeds. The payout is never redirected.
    function test_N14b_payeeIneligibleAtRelease() public {
        address t = _listed(0, KYC, 0, "sp-14b");
        RefServiceEscrow svc = new RefServiceEscrow(t);
        _attestAs(cadmin, nid(address(svc)), ELIGIBLE, type(uint64).max);
        bytes32 ref = _deposit(ALICE_PK, svc, _dep(alice, "14b"));
        _attestAs(cadmin, nid(alice), 0, 0);
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(alice), 0));
        svc.release(ref);
        (bytes32 p, uint256 v,) = svc.custody(ref);
        assertEq(p, nid(alice));
        assertEq(v, AMT);
        assertEq(svc.owed(), AMT);
        _attest(nid(alice), KYC, type(uint64).max);
        svc.release(ref);
        assertEq(IERC20(t).balanceOf(alice), SUPPLY);
    }

    /// Q5 (b): a recorded `forceTransfer` on a frozen S moves its pooled balance; the shortfall equals the forced amount and
    /// falls on the last claimant, whose payout fails closed (in full or not at all); the first is paid.
    function test_reg_forcedMoveShortfall() public {
        RefServiceEscrow svc = new RefServiceEscrow(t8);
        vm.prank(alice);
        IERC20(t8).transfer(bob, 10_000);
        bytes32 r1 = _deposit(ALICE_PK, svc, _dep(alice, "f1"));
        bytes32 r2 = _deposit(BOB_PK, svc, _dep(bob, "f2"));
        bytes32 rid = _order(t8, "sp-force", nid(address(svc)), nid(address(0xBE)), 600, _now() + 30 days);
        _freezeRecord(t8, nid(address(svc)), rid);
        vm.prank(issuer);
        _r(t8).forceTransfer(rid, 600);
        _unfreeze(t8, nid(address(svc)));
        assertEq(svc.owed() - IERC20(t8).balanceOf(address(svc)), 600, "shortfall = forced");
        svc.release(r1);
        assertEq(IERC20(t8).balanceOf(alice), SUPPLY - 10_000);
        vm.expectRevert(); // ERC20InsufficientBalance: in full or not at all
        svc.release(r2);
        (, uint256 v,) = svc.custody(r2);
        assertEq(v, AMT, "the last claimant's custody stays owed");
    }
}
