// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Hashes} from "@openzeppelin/contracts/utils/cryptography/Hashes.sol";
import {UID_} from "../v2/helpers/V2Fixture.sol";
import {MandateFixture} from "./MandateWallet.t.sol";
import {WebAuthnSoft} from "../account/SmartKeyAccount.t.sol";
import {VM, a, n, h, walletDigest} from "../metatx/NamedEntry.t.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {HederaMandateWallet} from "../../src/hedera/HederaMandateWallet.sol";
import {SmartKeyAccount, SubjectKey, KeyKind, AccountSig} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {MockHederaAccountService} from "../hedera/HederaMocks.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";

// The fields of each struct before `E`, for the JSON a wallet is handed.
string constant F_FROM = '{"name":"from","type":"address"}';
string constant F_UA_FROM = '{"name":"from","type":"bytes32"}';
string constant F_TOKEN = '{"name":"token","type":"address"}';
string constant F_EPOCH = '{"name":"epoch","type":"uint64"}';
string constant SET_PAYEE = string.concat(F_UA_FROM, ",", F_TOKEN, ',{"name":"payee","type":"bytes32"},{"name":"allowed","type":"bool"}');
string constant REVOKE_MANDATE = string.concat(F_UA_FROM, ",", F_TOKEN);
string constant PAY = string.concat(F_UA_FROM, ",", F_TOKEN, ',{"name":"payee","type":"bytes32"},{"name":"amount","type":"uint256"},'
    '{"name":"entryRef","type":"bytes32"},', F_EPOCH);
string constant DELEGATE_REVOKE = string.concat(F_UA_FROM, ",", F_TOKEN, ",", F_EPOCH);
string constant EXECUTE = string.concat(F_FROM, ',{"name":"target","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"}');
string constant UA_EXECUTE_FIELDS = string.concat(F_UA_FROM, ',{"name":"target","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"}');
string constant KEY = '{"name":"kind","type":"uint8"},{"name":"x","type":"bytes32"},{"name":"y","type":"bytes32"},'
    '{"name":"rpIdHash","type":"bytes32"},{"name":"originHash","type":"bytes32"}';
string constant ADD_KEY = string.concat(F_FROM, ",", KEY);
string constant ROTATE_KEY = string.concat(F_FROM, ',{"name":"index","type":"uint256"},', KEY);
string constant REMOVE_KEY = string.concat(F_FROM, ',{"name":"index","type":"uint256"}');
string constant SET_GUARDIAN = string.concat(F_FROM, ',{"name":"guardian","type":"address"}');

uint256 constant LANE = 3;

function env(address from, uint256 nonce, uint256 validUntil) pure returns (MetaTxLib.Envelope memory) {
    return MetaTxLib.Envelope(from, LANE, nonce, validUntil, 0, address(0), 0, address(0));
}

/// The mandate wallet's envelope (ua-mtx-merge Q6): `from` an id.
function uaEnv(address from, uint256 nonce, uint256 validUntil) pure returns (MetaTxLib.UAEnvelope memory) {
    return MetaTxLib.UAEnvelope(MetaTxLib.pad(from), LANE, nonce, validUntil, 0, address(0), 0, address(0));
}

/// `E` as signed: an unbound relayer is the canonical zero.
function tail(MetaTxLib.Envelope memory e) pure returns (string memory) {
    return tail(e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee);
}

function tail(MetaTxLib.UAEnvelope memory e) pure returns (string memory) {
    return tail(e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee);
}

function tail(uint256 batch, uint256 nonce, uint256 validUntil, uint32 mode, address relayer, uint256 fee)
    pure returns (string memory)
{
    address r = mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 ? relayer : address(0);
    return string.concat('"batch":', n(batch), ',"nonce":', n(nonce), ',"validUntil":', n(validUntil), ',"mode":', n(mode),
        ',"relayer":', a(r), ',"fee":', n(fee), ',"feeRecipient":', a(address(0)));
}

function setPayeeDigest(address w, MetaTxLib.UAEnvelope memory e, address token, address payee, bool allowed) view returns (bytes32) {
    string memory m = string.concat('"from":', h(e.from), ',"token":', a(token), ',"payee":', h(MetaTxLib.pad(payee)));
    m = string.concat(m, ',"allowed":', allowed ? "true" : "false", ",", tail(e));
    return walletDigest(w, "UASetPayee", SET_PAYEE, m);
}

function revokeMandateDigest(address w, MetaTxLib.UAEnvelope memory e, address token) view returns (bytes32) {
    string memory m = string.concat('"from":', h(e.from), ',"token":', a(token), ",", tail(e));
    return walletDigest(w, "UARevokeMandate", REVOKE_MANDATE, m);
}

function payDigest(address w, MetaTxLib.UAEnvelope memory e, address token, address payee, uint256 amount, bytes32 ref, uint64 ep)
    view returns (bytes32)
{
    string memory m = string.concat('"from":', h(e.from), ',"token":', a(token), ',"payee":', h(MetaTxLib.pad(payee)));
    m = string.concat(m, ',"amount":', n(amount), ',"entryRef":', h(ref));
    m = string.concat(m, ',"epoch":', n(ep), ",", tail(e));
    return walletDigest(w, "UAPayUnderMandate", PAY, m);
}

function delegateRevokeDigest(address w, MetaTxLib.UAEnvelope memory e, address token, uint64 ep) view returns (bytes32) {
    string memory m = string.concat('"from":', h(e.from), ',"token":', a(token), ',"epoch":', n(ep), ",", tail(e));
    return walletDigest(w, "UADelegateRevoke", DELEGATE_REVOKE, m);
}

/// The account's `Execute` (`SmartKeyAccount`, unchanged).
function executeDigest(address w, MetaTxLib.Envelope memory e, address target, uint256 value, bytes memory data) view returns (bytes32) {
    string memory m = string.concat('"from":', a(e.from), ',"target":', a(target), ',"value":', n(value));
    m = string.concat(m, ',"data":"', VM.toString(data), '",', tail(e));
    return walletDigest(w, "Execute", EXECUTE, m);
}

/// The mandate wallet's `UAExecute`.
function uaExecuteDigest(address w, MetaTxLib.UAEnvelope memory e, address target, uint256 value, bytes memory data)
    view returns (bytes32)
{
    string memory m = string.concat('"from":', h(e.from), ',"target":', a(target), ',"value":', n(value));
    m = string.concat(m, ',"data":"', VM.toString(data), '",', tail(e));
    return walletDigest(w, "UAExecute", UA_EXECUTE_FIELDS, m);
}

/// typed-signing C5 (TS-D14), ua-mtx-merge T3b (Q6): the one signed entry per operation of `MandateWallet`, over its
/// `UA<Op>` struct, on the digest a wallet computes from the JSON it is handed (`from`, `payee` as `bytes32`); the rows
/// of `typed_ops.json` run in `TypedOps.t.sol` (T11, MD-7: the six `UA<Op>` rows; the retired address rows have no wallet entry).
contract NamedMandateEntriesTest is MandateFixture {
    function _env(address from, uint256 nonce) internal view returns (MetaTxLib.UAEnvelope memory) {
        return uaEnv(from, nonce, block.timestamp + 300);
    }

    function _paySig(MetaTxLib.UAEnvelope memory e, uint256 amount, bytes32 ref, uint64 ep)
        internal view returns (IUARegistry.UASig memory)
    {
        return _ua(DELEGATE_PK, payDigest(address(w), e, address(t), npp, amount, ref, ep));
    }

    function _delegateRevokeSig(MetaTxLib.UAEnvelope memory e, uint64 ep) internal view returns (IUARegistry.UASig memory) {
        return _ua(DELEGATE_PK, delegateRevokeDigest(address(w), e, address(t), ep));
    }

    function _bumpEpochTwice() internal {
        vm.startPrank(owner);
        w.revoke(address(t));
        w.setMandate(address(t), _id(delegate), 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));
        vm.stopPrank();
    }

    function test_setPayeeTyped() public {
        MetaTxLib.UAEnvelope memory e = _env(owner, 0);
        IUARegistry.UASig memory sig = _ua(OWNER_PK, setPayeeDigest(address(w), e, address(t), stranger, true));
        vm.prank(relayer);
        w.mtxSetPayee(e, address(t), _id(stranger), true, sig);
        assertTrue(w.payeeAllowed(address(t), _id(stranger)));
        assertEq(w.mtxNonce(_id(owner), LANE), 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxSetPayee(e, address(t), _id(stranger), true, sig);

        e.nonce = 1;
        sig = _ua(OWNER_PK, setPayeeDigest(address(w), e, address(t), stranger, true));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector); // `allowed` is signed
        w.mtxSetPayee(e, address(t), _id(stranger), false, sig);

        // a valid signature of somebody else: the op reads the signer
        e = _env(delegate, 0);
        sig = _ua(DELEGATE_PK, setPayeeDigest(address(w), e, address(t), stranger, false));
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.mtxSetPayee(e, address(t), _id(stranger), false, sig);
    }

    function test_revokeMandateTyped() public {
        MetaTxLib.UAEnvelope memory e = _env(delegate, 0);
        IUARegistry.UASig memory sig = _ua(DELEGATE_PK, revokeMandateDigest(address(w), e, address(t)));
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.mtxRevokeMandate(e, address(t), sig);

        e = _env(owner, 0);
        sig = _ua(OWNER_PK, revokeMandateDigest(address(w), e, address(t)));
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.MandateRevoked(address(t), _id(owner));
        vm.prank(relayer);
        w.mtxRevokeMandate(e, address(t), sig);
        assertEq(w.epoch(address(t)), 2);
        (bytes32 d,,,,,,) = w.mandates(address(t));
        assertEq(d, bytes32(0));
    }

    function test_payUnderMandateTyped() public {
        MetaTxLib.UAEnvelope memory e = _env(delegate, 0);
        IUARegistry.UASig memory sig = _paySig(e, 700, "inv", 1);
        vm.prank(relayer);
        w.mtxPayUnderMandate(e, address(t), _id(npp), 700, "inv", 1, sig);
        assertEq(t.balanceOf(npp), 700);
        assertTrue(w.refUsed("inv"));
        assertEq(w.mtxNonce(_id(delegate), LANE), 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxPayUnderMandate(e, address(t), _id(npp), 700, "inv", 1, sig);

        e.nonce = 1;
        sig = _paySig(e, 10, "b", 1);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(e, address(t), _id(npp), 11, "b", 1, sig);
        e = _env(owner, 0); // a valid signature of the wrong party
        sig = _ua(OWNER_PK, payDigest(address(w), e, address(t), npp, 10, "b", 1));
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.mtxPayUnderMandate(e, address(t), _id(npp), 10, "b", 1, sig);
    }

    function test_delegateRevokeTyped() public {
        MetaTxLib.UAEnvelope memory e = _env(owner, 0);
        IUARegistry.UASig memory sig = _ua(OWNER_PK, delegateRevokeDigest(address(w), e, address(t), 1));
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.mtxDelegateRevoke(e, address(t), 1, sig);

        e = _env(delegate, 0);
        sig = _delegateRevokeSig(e, 1);
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.MandateRevoked(address(t), _id(delegate));
        vm.prank(relayer);
        w.mtxDelegateRevoke(e, address(t), 1, sig);
        assertEq(w.epoch(address(t)), 2);
    }

    /// CTR-ACC-07: a delegate's signature names the epoch, and no relayer can restamp it.
    function test_mandateEpochBound() public {
        MetaTxLib.UAEnvelope memory p = _env(delegate, 0);
        IUARegistry.UASig memory pay = _paySig(p, 10, "old", 1);
        MetaTxLib.UAEnvelope memory r = _env(delegate, 0);
        r.batch = LANE + 1;
        IUARegistry.UASig memory rev = _delegateRevokeSig(r, 1);
        _bumpEpochTwice();
        assertEq(w.epoch(address(t)), 3);

        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxPayUnderMandate(p, address(t), _id(npp), 10, "old", 1, pay);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(p, address(t), _id(npp), 10, "old", 3, pay);
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxDelegateRevoke(r, address(t), 1, rev);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxDelegateRevoke(r, address(t), 3, rev);
        IUARegistry.UASig memory ahead = _paySig(p, 10, "old", 4);
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 4));
        w.mtxPayUnderMandate(p, address(t), _id(npp), 10, "old", 4, ahead);

        pay = _paySig(p, 10, "old", 3);
        w.mtxPayUnderMandate(p, address(t), _id(npp), 10, "old", 3, pay);
        assertEq(t.balanceOf(npp), 10);
        (bytes32 d,,,,,,) = w.mandates(address(t));
        assertEq(d, _id(delegate), "no old revoke took it");
    }

    /// The named entries' lanes float: the signer picks `batch`, and a signature cannot move lanes since `batch` is signed.
    /// `refUsed` and `epoch` stop a new signature by the delegate for the same payment or revoke, here or on the generic path.
    function test_mandateLanesFloatRefAndEpochGuard() public {
        MetaTxLib.UAEnvelope memory e = _env(delegate, 0);
        w.mtxPayUnderMandate(e, address(t), _id(npp), 10, "once", 1, _paySig(e, 10, "once", 1));
        e.batch = 99;
        IUARegistry.UASig memory again = _paySig(e, 10, "once", 1);
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.RefAlreadyPaid.selector, bytes32("once")));
        w.mtxPayUnderMandate(e, address(t), _id(npp), 10, "once", 1, again);
        MetaTxLib.UAMetaTransaction memory m = _payM(npp, 10, "once"); // the pay lane, on the generic path
        IUARegistry.UASig memory generic = _ua(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.RefAlreadyPaid.selector, bytes32("once")));
        w.mtxExecute(m, generic);
        assertEq(t.balanceOf(npp), 10);

        e = _env(delegate, 1);
        w.mtxDelegateRevoke(e, address(t), 1, _delegateRevokeSig(e, 1));
        vm.prank(owner);
        w.setMandate(address(t), _id(delegate), 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days)); // the same delegate, epoch 3
        e = _env(delegate, 2);
        IUARegistry.UASig memory other = _delegateRevokeSig(e, 1); // a fresh lane position, the old epoch
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxDelegateRevoke(e, address(t), 1, other);
    }

    function test_executeTyped() public {
        bytes memory data = abi.encodeCall(t.transfer, (owner, 100));
        MetaTxLib.UAEnvelope memory e = _env(owner, 0);
        IUARegistry.UASig memory sig = _ua(OWNER_PK, uaExecuteDigest(address(w), e, address(t), 0, data));

        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector); // the inner `data`, `target` and `value` are all signed
        w.mtxExecute(e, address(t), 0, abi.encodeCall(t.transfer, (stranger, 100)), sig);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxExecute(e, stranger, 0, data, sig);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxExecute(e, address(t), 1, data, sig);

        vm.prank(relayer);
        w.mtxExecute(e, address(t), 0, data, sig);
        assertEq(t.balanceOf(owner), 100);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxExecute(e, address(t), 0, data, sig);

        vm.deal(address(w), 5);
        e = _env(owner, 1);
        w.mtxExecute(e, stranger, 5, "", _ua(OWNER_PK, uaExecuteDigest(address(w), e, stranger, 5, "")));
        assertEq(stranger.balance, 5);

        // a delegate signing it: a valid signature, not the owner
        e = _env(delegate, 0);
        sig = _ua(DELEGATE_PK, uaExecuteDigest(address(w), e, address(t), 0, data));
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.mtxExecute(e, address(t), 0, data, sig);
    }

    function test_executeTypedFailureAndReentry() public {
        bytes memory inner = abi.encodeCall(MandateWallet.setPayee, (address(t), _id(stranger), true));
        MetaTxLib.UAEnvelope memory e = _env(owner, 0);
        IUARegistry.UASig memory sig = _ua(OWNER_PK, uaExecuteDigest(address(w), e, address(w), 0, inner));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.CallFailed.selector, abi.encodeWithSelector(IMetaTx.Reentrancy.selector)));
        w.mtxExecute(e, address(w), 0, inner, sig);
        assertEq(w.mtxNonce(_id(owner), LANE), 0, "a failed op burns no nonce");
    }

    /// Step 7: the event the node's indexer decodes, carrying the digest the wallet signed (ua-mtx-merge T3b, R18: the
    /// UA event of the merged path).
    function test_executeTypedEmitsExecuted() public {
        MetaTxLib.UAEnvelope memory e = _env(owner, 0);
        bytes32 d = uaExecuteDigest(address(w), e, stranger, 0, "");
        IUARegistry.UASig memory sig = _ua(OWNER_PK, d);
        vm.expectEmit(true, true, true, true, address(w));
        emit IUALedger.UAMetaTransactionExecuted(_id(owner), relayer, LANE, 0, d, relayer, 0);
        vm.prank(relayer);
        w.mtxExecute(e, stranger, 0, "", sig);
    }

    /// The domain binds the wallet and the chain; a bound relayer and `validUntil` hold on `mtxExecute`.
    function test_executeTypedReplayAndEnvelope() public {
        MandateWallet other = new MandateWallet(_id(owner), UID_, address(0), false);
        MetaTxLib.UAEnvelope memory e = _env(owner, 0);
        IUARegistry.UASig memory sig = _ua(OWNER_PK, uaExecuteDigest(address(w), e, stranger, 0, ""));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        other.mtxExecute(e, stranger, 0, "", sig);
        vm.chainId(7623);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxExecute(e, stranger, 0, "", sig);
        vm.chainId(7622);

        e.mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        e.relayer = relayer;
        sig = _ua(OWNER_PK, uaExecuteDigest(address(w), e, stranger, 0, ""));
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, relayer, stranger));
        w.mtxExecute(e, stranger, 0, "", sig);
        vm.warp(e.validUntil + 1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, e.validUntil, e.validUntil + 1));
        w.mtxExecute(e, stranger, 0, "", sig);
        vm.warp(e.validUntil);
        vm.prank(relayer);
        w.mtxExecute(e, stranger, 0, "", sig);
        assertEq(w.mtxNonce(_id(owner), LANE), 1);
    }

    /// The same `(from, batch)` lane as the generic path; neither signature runs on the other entry.
    function test_executeTypedAndGenericShareTheLane() public {
        bytes memory data = abi.encodeCall(t.transfer, (owner, 1));
        MetaTxLib.UAEnvelope memory e = _env(owner, 0);
        IUARegistry.UASig memory typed = _ua(OWNER_PK, uaExecuteDigest(address(w), e, address(t), 0, data));
        MetaTxLib.UAMetaTransaction memory m =
            _gen(_id(owner), abi.encodeCall(MandateWallet.execute, (address(t), 0, data)), LANE, 0);
        m.validUntil = e.validUntil;
        IUARegistry.UASig memory generic = _ua(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxExecute(m, typed);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxExecute(e, address(t), 0, data, generic);
        w.mtxExecute(m, generic);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxExecute(e, address(t), 0, data, typed);
    }

    /// A wallet takes fee mode `NONE` only (CTR-MTX-22), and is no signer of its own.
    function test_namedModesAndSelfSender() public {
        MetaTxLib.UAEnvelope memory e = _env(owner, 0);
        e.mode = MetaTxLib.MODE_FEE_FIXED;
        IUARegistry.UASig memory sig = _ua(OWNER_PK, uaExecuteDigest(address(w), e, stranger, 0, ""));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, e.mode));
        w.mtxExecute(e, stranger, 0, "", sig);
        e.mode = MetaTxLib.MODE_FEE_PERCENT;
        sig = _ua(OWNER_PK, uaExecuteDigest(address(w), e, stranger, 0, ""));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, MandateWallet.execute.selector, e.mode));
        w.mtxExecute(e, stranger, 0, "", sig);
        e = _env(address(w), 0);
        sig = _ua(OWNER_PK, uaExecuteDigest(address(w), e, stranger, 0, ""));
        vm.expectRevert(IMetaTx.SelfSender.selector);
        w.mtxExecute(e, stranger, 0, "", sig);
    }

    /// A named entry is no self-call target.
    function test_namedEntriesNotAllowlisted() public {
        MetaTxLib.UAEnvelope memory e;
        IUARegistry.UASig memory none;
        bytes[6] memory calls = [
            abi.encodeCall(MandateWallet.mtxSetPayee, (e, address(t), _id(npp), true, none)),
            abi.encodeCall(MandateWallet.mtxRevokeMandate, (e, address(t), none)),
            abi.encodeCall(MandateWallet.mtxDelegateRevoke, (e, address(t), 1, none)),
            abi.encodeCall(MandateWallet.mtxPayUnderMandate, (e, address(t), _id(npp), 1, 0, 1, none)),
            abi.encodeCall(MandateWallet.mtxSetMandate, (e, address(t), _id(npp), 1, 1, 1, 1, none)),
            abi.encodeWithSelector(bytes4(keccak256("mtxExecute((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),address,uint256,bytes,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))")),
                e, npp, uint256(0), bytes(""), none)
        ];
        for (uint256 i; i < calls.length; ++i) {
            MetaTxLib.UAMetaTransaction memory m = _gen(_id(owner), calls[i], 5, 0);
            IUARegistry.UASig memory sig = _ua(OWNER_PK, w.mtxDigest(m));
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(calls[i])));
            w.mtxExecute(m, sig);
        }
    }
}

/// NET-HED-03 on the named entries through `IS_HEDERA`: a 64-byte signature from an address without code goes through
/// HIP-632 over the entry's own digest.
contract NamedHederaMandateTest is MandateFixture {
    address constant HAS = address(0x16a);
    uint256 constant ED_KEY = 0x0E1;
    uint256 constant ED_DEL = 0x0E2;
    address edOwner = address(uint160(2_000_001));
    address edDel = address(uint160(2_000_002));
    HederaMandateWallet hw;

    function setUp() public override {
        super.setUp();
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        MockHederaAccountService(HAS).setEdKey(edOwner, vm.addr(ED_KEY));
        MockHederaAccountService(HAS).setEdKey(edDel, vm.addr(ED_DEL));
        hw = new HederaMandateWallet(_id(edOwner), UID_, address(0));
        t.mint(address(hw), 1_000);
    }

    function _ed(uint256 k, bytes32 d) internal pure returns (IUARegistry.UASig memory s) {
        (bytes32 r, bytes32 vs) = vm.signCompact(k, d);
        s.signature = abi.encodePacked(r, vs);
    }

    function _env(address from, uint256 nonce) internal view returns (MetaTxLib.UAEnvelope memory) {
        return uaEnv(from, nonce, block.timestamp + 300);
    }

    function _setPayee(uint256 nonce) internal {
        MetaTxLib.UAEnvelope memory e = _env(edOwner, nonce);
        hw.mtxSetPayee(e, address(t), _id(npp), true, _ed(ED_KEY, setPayeeDigest(address(hw), e, address(t), npp, true)));
    }

    function test_ed25519OwnerNamedEntries() public {
        _setPayee(0);
        assertTrue(hw.payeeAllowed(address(t), _id(npp)));

        // pays by hand through `UAExecute`, the owner's only way (`isValidSignature` stays ECDSA)
        bytes memory data = abi.encodeCall(t.transfer, (npp, 40));
        MetaTxLib.UAEnvelope memory e = _env(edOwner, 1);
        IUARegistry.UASig memory sig = _ed(ED_KEY, uaExecuteDigest(address(hw), e, address(t), 0, data));
        hw.mtxExecute(e, address(t), 0, data, sig);
        assertEq(t.balanceOf(npp), 40);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 2, 1));
        hw.mtxExecute(e, address(t), 0, data, sig);

        e = _env(edOwner, 2);
        sig = _ed(ED_DEL, revokeMandateDigest(address(hw), e, address(t))); // another account's key
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        hw.mtxRevokeMandate(e, address(t), sig);
        hw.mtxRevokeMandate(e, address(t), _ed(ED_KEY, revokeMandateDigest(address(hw), e, address(t))));
        assertEq(hw.epoch(address(t)), 1);
    }

    function test_ed25519DelegateNamedEntries() public {
        _setPayee(0);
        vm.prank(edOwner);
        hw.setMandate(address(t), _id(edDel), 100, 300, 1 days, uint64(block.timestamp + 1 days));
        MetaTxLib.UAEnvelope memory e = _env(edDel, 0);
        IUARegistry.UASig memory sig = _ed(ED_DEL, payDigest(address(hw), e, address(t), npp, 50, "e", 1));
        hw.mtxPayUnderMandate(e, address(t), _id(npp), 50, "e", 1, sig);
        assertEq(t.balanceOf(npp), 50);
        e = _env(edDel, 1);
        hw.mtxDelegateRevoke(e, address(t), 1, _ed(ED_DEL, delegateRevokeDigest(address(hw), e, address(t), 1)));
        (bytes32 d,,,,,,) = hw.mandates(address(t));
        assertEq(d, bytes32(0));
    }

    /// A `from` with code never takes HIP-632, even when the account service would vouch for its 64-byte signature.
    function test_contractSignerNeverTakesHip632() public {
        Mock1271Wallet cw = new Mock1271Wallet(delegate);
        MockHederaAccountService(HAS).setEdKey(address(cw), vm.addr(ED_DEL));
        vm.prank(edOwner);
        hw.setMandate(address(t), _id(address(cw)), 100, 300, 1 days, uint64(block.timestamp + 1 days));
        _setPayee(0);
        MetaTxLib.UAEnvelope memory e = _env(address(cw), 0);
        IUARegistry.UASig memory sig = _ed(ED_DEL, payDigest(address(hw), e, address(t), npp, 50, "c", 1));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        hw.mtxPayUnderMandate(e, address(t), _id(npp), 50, "c", 1, sig);
    }
}

contract VouchesForAll {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// typed-signing C5 (TS-D14, CTR-ACC-10): the account's own entries take `AccountSig`, on the digest a wallet computes.
contract NamedAccountTest is WebAuthnSoft {
    uint256 internal constant PASSKEY = 0xC0FFEE1234567890;
    uint256 internal constant SEED = 0x5EED;
    uint256 internal constant SEED2 = 0x5EED2;
    address internal constant GUARDIAN = address(0x6A2D);
    SmartKeyAccountFactory internal fac;
    SmartKeyAccount internal acct;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        fac = new SmartKeyAccountFactory(UID_);
        acct = SmartKeyAccount(payable(fac.deploy(_seedKey(SEED), GUARDIAN)));
    }

    function _env(uint256 nonce) internal view returns (MetaTxLib.Envelope memory) {
        return env(address(acct), nonce, block.timestamp + 300);
    }

    function _keyJson(uint8 kind, SubjectKey memory k) internal pure returns (string memory) {
        return string.concat('"kind":', n(kind), ',"x":', h(k.x), ',"y":', h(k.y), ',"rpIdHash":', h(k.rpIdHash),
            ',"originHash":', h(k.originHash));
    }

    function _addKeyDigest(MetaTxLib.Envelope memory e, uint8 kind, SubjectKey memory k) internal view returns (bytes32) {
        return walletDigest(address(acct), "AddKey", ADD_KEY, string.concat('"from":', a(e.from), ",", _keyJson(kind, k), ",", tail(e)));
    }

    function _addKeyDigest(MetaTxLib.Envelope memory e, SubjectKey memory k) internal view returns (bytes32) {
        return _addKeyDigest(e, uint8(k.kind), k);
    }

    function _removeKeyDigest(MetaTxLib.Envelope memory e, uint256 index) internal view returns (bytes32) {
        return walletDigest(address(acct), "RemoveKey", REMOVE_KEY, string.concat('"from":', a(e.from), ',"index":', n(index), ",", tail(e)));
    }

    function _rotateKeyDigest(MetaTxLib.Envelope memory e, uint256 index, SubjectKey memory k) internal view returns (bytes32) {
        return walletDigest(address(acct), "RotateKey", ROTATE_KEY,
            string.concat('"from":', a(e.from), ',"index":', n(index), ",", _keyJson(uint8(k.kind), k), ",", tail(e)));
    }

    function _setGuardianDigest(MetaTxLib.Envelope memory e, address g) internal view returns (bytes32) {
        return walletDigest(address(acct), "SetGuardian", SET_GUARDIAN, string.concat('"from":', a(e.from), ',"guardian":', a(g), ",", tail(e)));
    }

    function _cancelRecoveryDigest(MetaTxLib.Envelope memory e) internal view returns (bytes32) {
        return walletDigest(address(acct), "CancelRecovery", F_FROM, string.concat('"from":', a(e.from), ",", tail(e)));
    }

    function _raw(uint256 pk, bytes32 message) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, message);
        return abi.encodePacked(r, s, v);
    }

    function _seedSig(uint256 index, uint256 pk, bytes32 digest) internal pure returns (AccountSig memory) {
        return AccountSig(index, new bytes32[](0), _raw(pk, digest));
    }

    function _addKey(MetaTxLib.Envelope memory e, SubjectKey memory k, AccountSig memory s) internal {
        acct.mtxAddKey(e, uint8(k.kind), k.x, k.y, k.rpIdHash, k.originHash, s);
    }

    function _add(SubjectKey memory k, uint256 nonce) internal {
        MetaTxLib.Envelope memory e = _env(nonce);
        AccountSig memory s = _seedSig(0, SEED, _addKeyDigest(e, k));
        vm.prank(relayer);
        _addKey(e, k, s);
    }

    function test_addKeyTyped() public {
        SubjectKey memory k = _passkey(PASSKEY);
        _add(k, 0);
        assertEq(acct.keyCount(), 2);
        assertTrue(acct.hasKey(keccak256(abi.encode(k))));
        assertEq(acct.mtxNonce(address(acct), LANE), 1);

        MetaTxLib.Envelope memory e = _env(0);
        AccountSig memory s = _seedSig(0, SEED, _addKeyDigest(e, k));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _addKey(e, k, s);
        e = _env(1);
        SubjectKey memory seed2 = _seedKey(SEED2);
        s = _seedSig(0, SEED, _addKeyDigest(e, seed2));
        seed2.originHash = keccak256("not signed"); // every key field is signed
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _addKey(e, seed2, s);
    }

    function test_removeKeyTyped() public {
        _add(_seedKey(SEED2), 0);
        MetaTxLib.Envelope memory e = _env(1);
        vm.prank(relayer);
        acct.mtxRemoveKey(e, 1, _seedSig(0, SEED, _removeKeyDigest(e, 1)));
        assertEq(acct.keyCount(), 1);
        e = _env(2);
        AccountSig memory s = _seedSig(0, SEED, _removeKeyDigest(e, 0));
        vm.expectRevert(SmartKeyAccount.LastKey.selector);
        acct.mtxRemoveKey(e, 0, s);
    }

    function test_rotateKeyTyped() public {
        SubjectKey memory k = _seedKey(SEED2);
        MetaTxLib.Envelope memory e = _env(0);
        AccountSig memory s = _seedSig(0, SEED, _rotateKeyDigest(e, 0, k));
        acct.mtxRotateKey(e, 0, uint8(k.kind), k.x, k.y, k.rpIdHash, k.originHash, s);
        assertEq(acct.keyCount(), 1);
        assertEq(acct.keyAt(1).x, k.x);
        // the old key is gone; the new one signs
        e = _env(1);
        s = _seedSig(0, SEED, _setGuardianDigest(e, address(0)));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        acct.mtxSetGuardian(e, address(0), s);
        acct.mtxSetGuardian(e, address(0), _seedSig(1, SEED2, _setGuardianDigest(e, address(0))));
        assertEq(acct.guardian(), address(0));
    }

    function test_setGuardianAndCancelRecoveryTyped() public {
        SubjectKey memory k = _seedKey(SEED2);
        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        MetaTxLib.Envelope memory e = _env(0);
        vm.prank(relayer);
        acct.mtxCancelRecovery(e, _seedSig(0, SEED, _cancelRecoveryDigest(e)));
        assertEq(acct.pendingRecovery(), bytes32(0));
        e = _env(1);
        AccountSig memory s = _seedSig(0, SEED, _cancelRecoveryDigest(e));
        vm.expectRevert(SmartKeyAccount.NoRecovery.selector);
        acct.mtxCancelRecovery(e, s);

        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        vm.prank(relayer);
        acct.mtxSetGuardian(e, address(0xA), _seedSig(0, SEED, _setGuardianDigest(e, address(0xA))));
        assertEq(acct.guardian(), address(0xA));
        assertEq(acct.pendingRecovery(), bytes32(0), "a new guardian cancels the old one's recovery");
    }

    function test_executeTyped() public {
        vm.deal(address(acct), 9);
        MetaTxLib.Envelope memory e = _env(0);
        bytes memory data = hex"c0ffee";
        AccountSig memory s = _seedSig(0, SEED, executeDigest(address(acct), e, GUARDIAN, 9, data));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        acct.mtxExecute(e, GUARDIAN, 9, hex"c0ffef", s);
        vm.prank(relayer);
        acct.mtxExecute(e, GUARDIAN, 9, data, s);
        assertEq(GUARDIAN.balance, 9);

        bytes memory inner = abi.encodeCall(SmartKeyAccount.cancelRecovery, ());
        e = _env(1);
        s = _seedSig(0, SEED, executeDigest(address(acct), e, address(acct), 0, inner));
        vm.expectRevert(abi.encodeWithSelector(SmartKeyAccount.CallFailed.selector, abi.encodeWithSelector(IMetaTx.Reentrancy.selector)));
        acct.mtxExecute(e, address(acct), 0, inner, s);
    }

    /// A batch of typed digests under one signature (CTR-ACC-02): each leaf is `batchLeaf` of the entry's own digest.
    function test_skaMerkleBatchLeafIsTypedDigest() public {
        SubjectKey memory k = _seedKey(SEED2);
        MetaTxLib.Envelope memory e0 = _env(0);
        MetaTxLib.Envelope memory e1 = _env(1);
        bytes32 d0 = _addKeyDigest(e0, k);
        bytes32 d1 = _setGuardianDigest(e1, address(0xA));
        bytes memory sig = _raw(SEED, Hashes.commutativeKeccak256(acct.batchLeaf(d0), acct.batchLeaf(d1)));
        bytes32[] memory p0 = new bytes32[](1);
        bytes32[] memory p1 = new bytes32[](1);
        p0[0] = acct.batchLeaf(d1);
        p1[0] = acct.batchLeaf(d0);

        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector); // the other leaf's proof
        _addKey(e0, k, AccountSig(0, p1, sig));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector); // no proof: the digest itself, which nobody signed
        _addKey(e0, k, AccountSig(0, new bytes32[](0), sig));

        // the same fields as a generic `MetaTransaction`: another digest, so no leaf of this root
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.batch, m.validUntil) = (address(acct), abi.encodeCall(SmartKeyAccount.addKey, (k)), LANE, e0.validUntil);
        bytes memory blob = abi.encode(uint256(0), p0, sig);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        acct.mtxExecute(m, blob);

        _addKey(e0, k, AccountSig(0, p0, sig));
        acct.mtxSetGuardian(e1, address(0xA), AccountSig(0, p1, sig));
        assertEq(acct.keyCount(), 2);
        assertEq(acct.guardian(), address(0xA));
    }

    /// A passkey signs the typed digest as the WebAuthn challenge (CTR-ACC-08): base64url of the 32 bytes.
    function test_skaPasskeyChallengeTypedDigest() public {
        acct = SmartKeyAccount(payable(fac.deploy(_passkey(PASSKEY), GUARDIAN)));
        SubjectKey memory k = _seedKey(SEED2);
        MetaTxLib.Envelope memory e = _env(0);
        bytes32 d = _addKeyDigest(e, k);
        AccountSig memory wrong = AccountSig(0, new bytes32[](0), _enc(_assertion(PASSKEY, keccak256("another op"))));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _addKey(e, k, wrong);

        // the same fields as a generic `MetaTransaction`: another digest, another challenge
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.batch, m.validUntil) = (address(acct), abi.encodeCall(SmartKeyAccount.addKey, (k)), LANE, e.validUntil);
        wrong = AccountSig(0, new bytes32[](0), _enc(_assertion(PASSKEY, acct.mtxDigest(m))));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _addKey(e, k, wrong);

        AccountSig memory right = AccountSig(0, new bytes32[](0), _enc(_assertion(PASSKEY, d)));
        vm.prank(relayer);
        _addKey(e, k, right);
        assertEq(acct.keyCount(), 2);
    }

    /// The offset of the `AccountSig` tuple in `mtxCancelRecovery(e, sig)`: the eight envelope words and that offset.
    uint256 internal constant TUPLE_AT = 0x120;

    /// `mtxCancelRecovery(e, sig)` with the tuple's offset and the bytes behind the head set by hand.
    function _rawCancel(MetaTxLib.Envelope memory e, uint256 tupleAt, bytes memory tuple) internal pure returns (bytes memory) {
        return abi.encodePacked(SmartKeyAccount.mtxCancelRecovery.selector, abi.encode(e), tupleAt, tuple);
    }

    function _refused(bytes memory call, bytes memory err) internal {
        (bool ok, bytes memory ret) = address(acct).call(call);
        assertFalse(ok);
        assertEq(ret, err);
        assertEq(acct.mtxNonce(address(acct), LANE), 0, "no nonce burnt");
    }

    /// `_blob` takes the calldata from the tuple's offset: whatever layout a relayer sends is decoded as a signature, and
    /// refused unless it is one. The last call is the control: the same hand-made layout, well formed, runs.
    function test_accountSigMalformedLayout() public {
        vm.prank(GUARDIAN);
        acct.initiateRecovery(_seedKey(SEED2));
        MetaTxLib.Envelope memory e = _env(0);
        bytes memory raw = _raw(SEED, _cancelRecoveryDigest(e));
        bytes memory bad = abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector);

        // tuple offset 0: the tuple overlaps the envelope, `from` as the key index and `batch` as an offset
        _refused(_rawCancel(e, 0, abi.encode(uint256(0), new bytes32[](0), raw)), bad);
        // offsets past the end: the entry's own decoder
        _refused(_rawCancel(e, TUPLE_AT, ""), "");
        _refused(_rawCancel(e, TUPLE_AT, abi.encode(uint256(0), uint256(0x60))), "");
        _refused(_rawCancel(e, 1 << 64, abi.encode(uint256(0), new bytes32[](0), raw)), "");
        _refused(_rawCancel(e, type(uint256).max, abi.encode(uint256(0), new bytes32[](0), raw)), "");
        // inner offsets and lengths past the end: `_isValid`'s decode, inside the static call
        _refused(_rawCancel(e, TUPLE_AT, abi.encode(uint256(0), uint256(1) << 40, uint256(0x60))), bad);
        _refused(_rawCancel(e, TUPLE_AT, abi.encode(uint256(0), uint256(0x60), uint256(1) << 40, uint256(0))), bad);
        _refused(_rawCancel(e, TUPLE_AT, abi.encode(uint256(0), uint256(0x60), uint256(0x80), uint256(0), uint256(1) << 40)), bad);

        (bool ok, bytes memory ret) = address(acct).call(_rawCancel(e, TUPLE_AT, abi.encode(uint256(0), new bytes32[](0), raw)));
        assertTrue(ok, string(ret));
        assertEq(acct.pendingRecovery(), bytes32(0));
    }

    /// `kind` reaches the op as signed: 0 and 3 are the op's refusals, past the signature, and the nonce stays.
    function test_addKeyKindRefused() public {
        SubjectKey memory k = _seedKey(SEED2);
        MetaTxLib.Envelope memory e = _env(0);
        AccountSig memory s = _seedSig(0, SEED, _addKeyDigest(e, 0, k));
        _refused(abi.encodeCall(SmartKeyAccount.mtxAddKey, (e, 0, k.x, k.y, k.rpIdHash, k.originHash, s)),
            abi.encodeWithSelector(SmartKeyAccount.BadKey.selector));
        s = _seedSig(0, SEED, _addKeyDigest(e, 3, k));
        _refused(abi.encodeCall(SmartKeyAccount.mtxAddKey, (e, 3, k.x, k.y, k.rpIdHash, k.originHash, s)), "");
        assertEq(acct.keyCount(), 1);
    }

    function test_rotateKeyToPasskeyTyped() public {
        SubjectKey memory k = _passkey(PASSKEY);
        MetaTxLib.Envelope memory e = _env(0);
        AccountSig memory s = _seedSig(0, SEED, _rotateKeyDigest(e, 0, k));
        acct.mtxRotateKey(e, 0, uint8(k.kind), k.x, k.y, k.rpIdHash, k.originHash, s);
        assertEq(uint8(acct.keyAt(1).kind), uint8(KeyKind.P256_WEBAUTHN));
        assertEq(acct.keyCount(), 1);

        e = _env(1);
        bytes32 d = _setGuardianDigest(e, address(0xA));
        s = _seedSig(0, SEED, d);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector); // the seed key is gone
        acct.mtxSetGuardian(e, address(0xA), s);
        acct.mtxSetGuardian(e, address(0xA), AccountSig(1, new bytes32[](0), _enc(_assertion(PASSKEY, d))));
        assertEq(acct.guardian(), address(0xA));
    }

    function test_executeTypedEmitsExecuted() public {
        MetaTxLib.Envelope memory e = _env(0);
        bytes32 d = executeDigest(address(acct), e, GUARDIAN, 0, "");
        AccountSig memory s = _seedSig(0, SEED, d);
        vm.expectEmit(true, true, true, true, address(acct));
        emit IMetaTx.MetaTransactionExecuted(address(acct), relayer, LANE, 0, d, relayer, 0);
        vm.prank(relayer);
        acct.mtxExecute(e, GUARDIAN, 0, "", s);
    }

    /// The domain binds the clone and the chain, for the same key; a bound relayer and `validUntil` hold on `mtxExecute`.
    function test_executeTypedReplayAndEnvelope() public {
        SmartKeyAccount other = SmartKeyAccount(payable(fac.deploy(_seedKey(SEED), address(0xFEED))));
        MetaTxLib.Envelope memory e = _env(0);
        AccountSig memory s = _seedSig(0, SEED, executeDigest(address(acct), e, GUARDIAN, 0, ""));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector); // `from` still this clone: not `other`'s own key set
        other.mtxExecute(e, GUARDIAN, 0, "", s);
        MetaTxLib.Envelope memory theirs = env(address(other), 0, e.validUntil);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        other.mtxExecute(theirs, GUARDIAN, 0, "", s);
        vm.chainId(7623);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        acct.mtxExecute(e, GUARDIAN, 0, "", s);
        vm.chainId(7622);

        e.mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        e.relayer = relayer;
        s = _seedSig(0, SEED, executeDigest(address(acct), e, GUARDIAN, 0, ""));
        address stranger = address(0x5745);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, relayer, stranger));
        acct.mtxExecute(e, GUARDIAN, 0, "", s);
        vm.warp(e.validUntil + 1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, e.validUntil, e.validUntil + 1));
        acct.mtxExecute(e, GUARDIAN, 0, "", s);
        vm.warp(e.validUntil);
        vm.prank(relayer);
        acct.mtxExecute(e, GUARDIAN, 0, "", s);
        assertEq(acct.mtxNonce(address(acct), LANE), 1);
    }

    /// `AccountSig`: a key index without a key, and a `from` other than the account.
    function test_accountSigRefusals() public {
        MetaTxLib.Envelope memory e = _env(0);
        AccountSig memory s = _seedSig(1, SEED, _setGuardianDigest(e, address(0xA)));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        acct.mtxSetGuardian(e, address(0xA), s);

        // an EOA's signature is 65 bytes, an `AccountSig` is not that: refused before `onlySelf`
        address eoa = vm.addr(SEED);
        e = env(eoa, 0, block.timestamp + 300);
        s = _seedSig(0, SEED, _setGuardianDigest(e, address(0xA)));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        acct.mtxSetGuardian(e, address(0xA), s);

        // a contract that vouches for anything passes the signature, and is still not the account
        e = env(address(new VouchesForAll()), 0, block.timestamp + 300);
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.mtxSetGuardian(e, address(0xA), s);
        assertEq(acct.guardian(), GUARDIAN);
    }

    function test_namedFeeModeRefused() public {
        MetaTxLib.Envelope memory e = _env(0);
        e.mode = MetaTxLib.MODE_FEE_FIXED;
        AccountSig memory s = _seedSig(0, SEED, _cancelRecoveryDigest(e));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, e.mode));
        acct.mtxCancelRecovery(e, s);
    }

    function test_namedEntriesNotAllowlisted() public {
        MetaTxLib.Envelope memory e;
        AccountSig memory none;
        bytes[6] memory calls = [
            abi.encodeCall(SmartKeyAccount.mtxAddKey, (e, 2, 0, 0, 0, 0, none)),
            abi.encodeCall(SmartKeyAccount.mtxRemoveKey, (e, 0, none)),
            abi.encodeCall(SmartKeyAccount.mtxRotateKey, (e, 0, 2, 0, 0, 0, 0, none)),
            abi.encodeCall(SmartKeyAccount.mtxSetGuardian, (e, address(0), none)),
            abi.encodeCall(SmartKeyAccount.mtxCancelRecovery, (e, none)),
            abi.encodeWithSelector(bytes4(keccak256("mtxExecute((address,uint256,uint256,uint256,uint32,address,uint256,address),address,uint256,bytes,(uint256,bytes32[],bytes))")),
                e, address(0), uint256(0), bytes(""), none)
        ];
        for (uint256 i; i < calls.length; ++i) {
            MetaTxLib.MetaTransaction memory m;
            (m.from, m.data, m.batch, m.validUntil) = (address(acct), calls[i], 5, block.timestamp + 300);
            bytes memory sig = _ecdsa(0, SEED, acct.mtxDigest(m));
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(calls[i])));
            acct.mtxExecute(m, sig);
        }
    }
}
