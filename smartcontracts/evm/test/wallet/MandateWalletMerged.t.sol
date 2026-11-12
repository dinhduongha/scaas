// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MtxHash} from "../helpers/MtxHash.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {Erc7739Kit} from "../helpers/Erc7739Kit.sol";
import {ERC7739Lib} from "../../src/common/ERC7739Lib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MergeBase} from "../merge/MergedEntry.t.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {GasBurner1271} from "../v2/helpers/V2Fixture.sol";
import {MockHederaAccountService} from "../hedera/HederaMocks.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";

/// The mandate wallets in the merged form (ua-mtx-merge T3b, spec §2.7, Q6, MD-11), called by selector: this file
/// compiles on the address-form wallets too, so each test is red there on its own (plan T3b step 3).
interface IMandateMerged {
    function owner() external view returns (bytes32);
    function supportedModes() external view returns (uint32);
    function registry() external view returns (address);
    function mandates(address token) external view returns (bytes32 delegate, uint64 expiry, uint64 periodSeconds,
        uint64 periodStart, uint128 maxPerPayment, uint128 maxPerPeriod, uint128 spentInPeriod);
    function payeeAllowed(address token, bytes32 payee) external view returns (bool);
    function epoch(address token) external view returns (uint64);
    function refUsed(bytes32 entryRef) external view returns (bool);
    function mtxNonce(bytes32 from, uint256 batch) external view returns (uint256);
    function mandatePayLane(bytes32 entryRef) external pure returns (uint256);
    function mandateRevokeLane(address token, uint64 epoch_) external pure returns (uint256);
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4);
    function setMandate(address token, bytes32 delegate, uint128 maxPerPayment, uint128 maxPerPeriod, uint64 periodSeconds,
        uint64 expiry) external;
    function setPayee(address token, bytes32 payee, bool allowed) external;
    function revoke(address token) external;
    function execute(address target, uint256 value, bytes calldata data) external returns (bytes memory);
    function payUnderMandate(address token, bytes32 payee, uint256 amount, bytes32 entryRef, uint64 epoch_,
        MetaTxLib.PayMeta calldata meta) external;
    function mtxSetMandate(MetaTxLib.UAEnvelope calldata e, address token, bytes32 delegate, uint128 maxPerPayment,
        uint128 maxPerPeriod, uint64 periodSeconds, uint64 expiry, IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxSetPayee(MetaTxLib.UAEnvelope calldata e, address token, bytes32 payee, bool allowed,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxRevokeMandate(MetaTxLib.UAEnvelope calldata e, address token, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxPayUnderMandate(MetaTxLib.UAEnvelope calldata e, address token, bytes32 payee, uint256 amount,
        bytes32 entryRef, uint64 epoch_, IUARegistry.UASig calldata auth, MetaTxLib.PayMeta calldata meta)
        external returns (bytes memory);
    function mtxDelegateRevoke(MetaTxLib.UAEnvelope calldata e, address token, uint64 epoch_, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxExecute(MetaTxLib.UAEnvelope calldata e, address target, uint256 value, bytes calldata data,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxExecute(MetaTxLib.UAMetaTransaction calldata m, IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxBatch(MetaTxLib.UAMetaTransaction[] calldata ms, IUARegistry.UASig[] calldata auths) external returns (bool);
    function mtxCancelNonce(MetaTxLib.UAEnvelope calldata e, uint256 lane, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bool);
}

// The six wallet structs (spec §2.7), `E` the envelope tail.
string constant E_TAIL = "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
string constant UA_SET_MANDATE = string.concat("UASetMandate(bytes32 from,address token,bytes32 delegate,uint128 maxPerPayment,"
    "uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry,", E_TAIL);
string constant UA_SET_PAYEE = string.concat("UASetPayee(bytes32 from,address token,bytes32 payee,bool allowed,", E_TAIL);
string constant UA_REVOKE_MANDATE = string.concat("UARevokeMandate(bytes32 from,address token,", E_TAIL);
string constant UA_PAY_UNDER_MANDATE = string.concat("UAPayUnderMandate(bytes32 from,address token,bytes32 payee,"
    "uint256 amount,bytes32 entryRef,uint64 epoch,", E_TAIL);
string constant UA_DELEGATE_REVOKE = string.concat("UADelegateRevoke(bytes32 from,address token,uint64 epoch,", E_TAIL);
string constant UA_EXECUTE = string.concat("UAExecute(bytes32 from,address target,uint256 value,bytes data,", E_TAIL);

/// The digest of `UA<Op>(bytes32 from, <args>, E)` from its type string, in `w`'s salted domain (ERC-5267), relayer and
/// fee recipient canonical (0 when unbound): computed here, not read from the wallet.
function uaDigest(address w, string memory typeString, MetaTxLib.UAEnvelope memory e, bytes memory args)
    view returns (bytes32)
{
    return keccak256(abi.encodePacked(hex"1901", saltedDomain(w), keccak256(bytes.concat(
        abi.encode(keccak256(bytes(typeString)), e.from), args, envTail(e)))));
}

/// `E` as signed: relayer / fee recipient canonical (0 when unbound).
function envTail(MetaTxLib.UAEnvelope memory e) pure returns (bytes memory) {
    return abi.encode(e.batch, e.nonce, e.validUntil, e.mode,
        e.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 ? e.relayer : address(0), e.fee,
        e.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT != 0 ? e.feeRecipient : address(0));
}

/// The domain separator from `w`'s ERC-5267 fields.
function saltedDomain(address w) view returns (bytes32) {
    (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = IERC5267(w).eip712Domain();
    return keccak256(abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
        keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
}

/// ua-mtx-merge T3b (plan step 2): every test with its positive control first. Native ids: `alice` (owner), `bob`
/// (delegate), `NPP` (payee); derived: `uaP`, `uaB` of the fixture's registry `REG_L`. `tok` has the ledger on
/// (`REG_L`), `tok0` has none.
contract MandateWalletMergedTest is MergeBase {
    address internal constant NPP = address(0x4EE);
    address internal constant HAS = address(0x16a);
    uint256 internal constant ED_KEY = 0x0E1;
    uint64 internal constant EXPIRY = 1_900_000_000;

    // ------------------------------------------------------------------ helpers

    function _wallet(bytes32 owner_, address reg) internal returns (IMandateMerged w) {
        w = IMandateMerged(deployCode("MandateWallet.sol:MandateWallet", abi.encode(owner_, chainUidA, reg, false)));
    }

    function _hwallet(bytes32 owner_, address reg) internal returns (IMandateMerged) {
        return IMandateMerged(deployCode("HederaMandateWallet.sol:HederaMandateWallet", abi.encode(owner_, chainUidA, reg)));
    }

    function _named(address w, string memory typeString, MetaTxLib.UAEnvelope memory e, bytes memory args)
        internal view returns (bytes32)
    {
        return uaDigest(w, typeString, e, args);
    }

    function _setMandateCd(IMandateMerged w, MetaTxLib.UAEnvelope memory e, address token, bytes32 d)
        internal view returns (bytes memory)
    {
        bytes32 dig = _named(address(w), UA_SET_MANDATE, e,
            abi.encode(token, d, uint128(1_000), uint128(2_500), uint64(1 days), EXPIRY));
        return abi.encodeCall(IMandateMerged.mtxSetMandate, (e, token, d, 1_000, 2_500, 1 days, EXPIRY, _authOf(e.from, dig)));
    }

    function _setPayeeCd(IMandateMerged w, MetaTxLib.UAEnvelope memory e, address token, bytes32 payee)
        internal view returns (bytes memory)
    {
        bytes32 dig = _named(address(w), UA_SET_PAYEE, e, abi.encode(token, payee, true));
        return abi.encodeCall(IMandateMerged.mtxSetPayee, (e, token, payee, true, _authOf(e.from, dig)));
    }

    /// The delegate's pay on its mandate lane, nonce 0, at the wallet's current epoch.
    function _payEnv(IMandateMerged w, bytes32 d, bytes32 ref) internal view returns (MetaTxLib.UAEnvelope memory) {
        return _env(d, w.mandatePayLane(ref), 0);
    }

    function _payDigest(IMandateMerged w, MetaTxLib.UAEnvelope memory e, address token, bytes32 payee, uint256 amount,
        bytes32 ref, uint64 ep) internal view returns (bytes32)
    {
        return _named(address(w), UA_PAY_UNDER_MANDATE, e, abi.encode(token, payee, amount, PayMetaKit.ref(ref), ep));
    }

    struct Pay { address token; bytes32 payee; uint256 amount; bytes32 ref; uint64 ep; }

    function _payCd(IMandateMerged w, bytes32 d, address token, bytes32 payee, uint256 amount, bytes32 ref)
        internal view returns (bytes memory)
    {
        return _payCd(w, _payEnv(w, d, ref), Pay(token, payee, amount, ref, w.epoch(token)));
    }

    function _payCd(IMandateMerged w, MetaTxLib.UAEnvelope memory e, Pay memory p) internal view returns (bytes memory) {
        IUARegistry.UASig memory a = _authOf(e.from, _payDigest(w, e, p.token, p.payee, p.amount, p.ref, p.ep));
        return abi.encodeCall(IMandateMerged.mtxPayUnderMandate, (e, p.token, p.payee, p.amount, PayMetaKit.ref(p.ref), p.ep, a, PayMetaKit.meta(p.ref)));
    }

    function _executeCd(IMandateMerged w, MetaTxLib.UAEnvelope memory e, address target, uint256 value, bytes memory data)
        internal view returns (bytes memory)
    {
        bytes32 dig = _named(address(w), UA_EXECUTE, e, abi.encode(target, value, keccak256(data)));
        return abi.encodeWithSignature(
            "mtxExecute((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),address,uint256,bytes,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))",
            e, target, value, data, _authOf(e.from, dig));
    }

    /// The generic entry on the wallet: `data` signed by `from`.
    function _genericCd(IMandateMerged w, bytes32 from, bytes memory data, uint256 batch, uint256 nonce)
        internal view returns (bytes memory)
    {
        MetaTxLib.UAMetaTransaction memory m = _call(from, data, batch, nonce);
        return _execCd(m, _authOf(from, _callDigest(address(w), m)));
    }

    function _ok(address w, bytes memory cd, string memory what) internal {
        (bool ok, bytes memory ret) = _relay(w, cd);
        if (!ok) emit log_named_bytes(what, ret);
        assertTrue(ok, what);
    }

    function _refused(address w, bytes memory cd, bytes memory err, string memory what) internal {
        (bool ok, bytes memory ret) = _relay(w, cd);
        assertFalse(ok, what);
        assertEq(ret, err, what);
    }

    function _fund(address w, address tk, uint256 v) internal {
        vm.prank(alice);
        (bool ok,) = tk.call(abi.encodeWithSignature("transfer(address,uint256)", w, v));
        require(ok, "fund");
    }

    /// A wallet of the native owner `alice` holding 10 000 of `tk`, a mandate on `tk` for `d` and `payee` approved, set
    /// by direct calls.
    function _mandate(address reg, address tk, bytes32 d, bytes32 payee) internal returns (IMandateMerged w) {
        w = _wallet(_pad(alice), reg);
        _fund(address(w), tk, 10_000);
        vm.startPrank(alice);
        w.setMandate(tk, d, 1_000, 2_500, 1 days, EXPIRY);
        w.setPayee(tk, payee, true);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ B and C: a registry only for a derived side

    function test_nativeOwnerSetMandateNoRegistry() public {
        IMandateMerged w0 = _wallet(_pad(alice), address(0));
        _ok(address(w0), _setMandateCd(w0, _env(_pad(alice), 1, 0), address(tok0), _pad(bob)), "registry 0");
        (bytes32 d,,,,,,) = w0.mandates(address(tok0));
        assertEq(d, _pad(bob));
        IMandateMerged w = _wallet(_pad(alice), REG_L);
        bytes memory cd = _setMandateCd(w, _env(_pad(alice), 1, 0), address(tok), _pad(bob));
        vm.expectCall(REG_L, bytes(""), 0);
        _ok(address(w), cd, "a registry, not called");
        assertEq(w.epoch(address(tok)), 1);
    }

    function test_nativeDelegatePaysNoRegistry() public {
        IMandateMerged w0 = _mandate(address(0), address(tok0), _pad(bob), _pad(NPP));
        _ok(address(w0), _payCd(w0, _pad(bob), address(tok0), _pad(NPP), 700, "r0"), "registry 0");
        assertEq(tok0.balanceOf(NPP), 700);
        IMandateMerged w = _mandate(REG_L, address(tok), _pad(bob), _pad(NPP));
        bytes memory cd = _payCd(w, _pad(bob), address(tok), _pad(NPP), 700, "r1");
        vm.expectCall(REG_L, bytes(""), 0);
        _ok(address(w), cd, "a registry, not called");
        assertEq(tok.balanceOf(NPP), 700);
        assertTrue(w.refUsed(PayMetaKit.ref("r1")));
        assertEq(w.mtxNonce(_pad(bob), w.mandatePayLane("r1")), 1);
    }

    /// A contract owner signs with its own code (ERC-1271), at the 50 k cap of every contract signer (MD-11 (c)).
    function test_erc1271OwnerSignsWithItsCode() public {
        Mock1271Wallet cw = new Mock1271Wallet(alice);
        IMandateMerged w = _wallet(_pad(address(cw)), REG_L);
        MetaTxLib.UAEnvelope memory e = _env(_pad(address(cw)), 1, 0);
        bytes32 dig = _named(address(w), UA_SET_PAYEE, e, abi.encode(address(tok), _pad(NPP), true));
        vm.expectCall(REG_L, bytes(""), 0);
        _ok(address(w), abi.encodeCall(IMandateMerged.mtxSetPayee, (e, address(tok), _pad(NPP), true, _sig(ALICE_PK, dig))),
            "ERC-1271 owner");
        assertTrue(w.payeeAllowed(address(tok), _pad(NPP)));
        GasBurner1271 gb = new GasBurner1271();
        IMandateMerged wg = _wallet(_pad(address(gb)), REG_L);
        e.from = _pad(address(gb));
        dig = _named(address(wg), UA_SET_PAYEE, e, abi.encode(address(tok), _pad(NPP), true));
        _refused(address(wg), abi.encodeCall(IMandateMerged.mtxSetPayee, (e, address(tok), _pad(NPP), true, _sig(ALICE_PK, dig))),
            abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "100 k of ERC-1271 over the 50 k cap");
    }

    function test_derivedOwnerSetMandateViaRegistry() public {
        IMandateMerged w = _wallet(uaP, REG_L);
        bytes memory cd = _setMandateCd(w, _env(uaP, 1, 0), address(tok), _pad(bob));
        vm.expectCall(REG_L, abi.encodeWithSelector(IUARegistry.requireAuthorized.selector));
        _ok(address(w), cd, "derived owner");
        (bytes32 d,,,,,,) = w.mandates(address(tok));
        assertEq(d, _pad(bob));
        // another derived id's valid authorization is not the owner's
        _refused(address(w), _setMandateCd(w, _env(uaB, 1, 0), address(tok), _pad(bob)),
            abi.encodeWithSelector(NOT_OWNER), "uaB is not the owner");
        // forgery: uaB's authorization presented for the owner's id
        MetaTxLib.UAEnvelope memory e = _env(uaP, 1, 1);
        bytes32 dig = _named(address(w), UA_SET_PAYEE, e, abi.encode(address(tok), _pad(NPP), true));
        (bool ok,) = _relay(address(w), abi.encodeCall(IMandateMerged.mtxSetPayee,
            (e, address(tok), _pad(NPP), true, _authOf(uaB, dig))));
        assertFalse(ok, "a forged derived authorization");
        assertFalse(w.payeeAllowed(address(tok), _pad(NPP)));
    }

    bytes4 internal constant NOT_OWNER = bytes4(keccak256("NotOwner()"));
    bytes4 internal constant NOT_DELEGATE = bytes4(keccak256("NotDelegate()"));

    function test_derivedDelegatePaysViaRegistry() public {
        IMandateMerged w = _mandate(REG_L, address(tok), uaB, _pad(NPP));
        bytes memory cd = _payCd(w, uaB, address(tok), _pad(NPP), 300, "d");
        vm.expectCall(REG_L, abi.encodeWithSelector(IUARegistry.requireAuthorized.selector), 1);
        _ok(address(w), cd, "derived delegate");
        assertEq(tok.balanceOf(NPP), 300);
        assertEq(w.mtxNonce(uaB, w.mandatePayLane("d")), 1);
    }

    function test_derivedPayeePaidByPayWithFeeToUA() public {
        IMandateMerged w = _mandate(REG_L, address(tok), _pad(bob), uaP);
        vm.prank(alice);
        w.setPayee(address(tok), _pad(NPP), true);
        _ok(address(w), _payCd(w, _pad(bob), address(tok), _pad(NPP), 10, "native"), "positive control: native payee");
        assertEq(tok.balanceOf(NPP), 10);
        uint256 before = tok.balanceOfUA(uaP);
        vm.expectCall(address(tok), abi.encodeWithSignature(
            "payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32,(bytes32,bytes32,bool,uint16,bytes))", uaP, 400, 0, 0,
            address(0), PayMetaKit.ref("ua"), PayMetaKit.meta("ua")));
        _ok(address(w), _payCd(w, _pad(bob), address(tok), uaP, 400, "ua"), "derived payee");
        assertEq(tok.balanceOfUA(uaP), before + 400);
        assertEq(tok.balanceOf(address(w)), 10_000 - 410);
    }

    function test_derivedSideAtRegistryZeroIsLedgerOffByName() public {
        IMandateMerged w0 = _wallet(_pad(alice), address(0));
        _ok(address(w0), _setMandateCd(w0, _env(_pad(alice), 1, 0), address(tok0), uaB), "positive control: native at 0");
        _refused(address(w0), _payCd(w0, uaB, address(tok0), _pad(NPP), 1, "x"),
            abi.encodeWithSelector(IUALedger.UALedgerOff.selector), "derived delegate at 0");
        IMandateMerged d0 = _wallet(uaP, address(0));
        _refused(address(d0), _setMandateCd(d0, _env(uaP, 1, 0), address(tok0), _pad(bob)),
            abi.encodeWithSelector(IUALedger.UALedgerOff.selector), "derived owner at 0");
    }

    // ------------------------------------------------------------------ R17

    function test_nativeUASigWithKeyDataRefused() public {
        _r17(true);
    }

    function test_nativeUASigWithMembersRefused() public {
        _r17(false);
    }

    function _r17(bool keyData) internal {
        IMandateMerged w = _wallet(_pad(alice), REG_L);
        MetaTxLib.UAEnvelope memory e = _env(_pad(alice), 1, 0);
        bytes32 dig = _named(address(w), UA_SET_PAYEE, e, abi.encode(address(tok), _pad(NPP), true));
        IUARegistry.UASig memory a = _sig(ALICE_PK, dig);
        _ok(address(w), abi.encodeCall(IMandateMerged.mtxSetPayee, (e, address(tok), _pad(NPP), true, a)),
            "positive control: named");
        e.nonce = 1;
        a = _sig(ALICE_PK, _named(address(w), UA_SET_PAYEE, e, abi.encode(address(tok), _pad(NPP), true)));
        if (keyData) a.keyData = hex"01";
        else a.members = _r17Members();
        _refused(address(w), abi.encodeCall(IMandateMerged.mtxSetPayee, (e, address(tok), _pad(NPP), true, a)),
            abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "named");
        bytes memory data = abi.encodeCall(IMandateMerged.setPayee, (address(tok), _pad(NPP), false));
        MetaTxLib.UAMetaTransaction memory m = _call(_pad(alice), data, 2, 0);
        a = _sig(ALICE_PK, _callDigest(address(w), m));
        IUARegistry.UASig memory clean = a;
        if (keyData) a.keyData = hex"01";
        else a.members = _r17Members();
        _refused(address(w), _execCd(m, a), abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "generic");
        a.keyData = "";
        delete a.members;
        _ok(address(w), _execCd(m, clean), "positive control: generic");
    }

    function _r17Members() internal pure returns (IUARegistry.MemberSig[] memory ms) {
        ms = new IUARegistry.MemberSig[](1);
        ms[0].sig = hex"01";
    }

    // ------------------------------------------------------------------ invariant 4: fee 0, any relayer

    /// The six named entries, the generic entry, the batch and the cancel, each relayed by `RELAYER` (no party) at fee
    /// mode `NONE`, native signers on a wallet with a registry.
    function test_everyEntryRelayableAtFeeZero() public {
        _everyEntry();
    }

    function _everyEntry() internal {
        IMandateMerged w = _wallet(_pad(alice), REG_L);
        _fund(address(w), address(tok), 10_000);
        bytes32 me = _pad(alice);
        _ok(address(w), _setMandateCd(w, _env(me, 1, 0), address(tok), _pad(bob)), "mtxSetMandate");
        _ok(address(w), _setPayeeCd(w, _env(me, 1, 1), address(tok), _pad(NPP)), "mtxSetPayee");
        _ok(address(w), _payCd(w, _pad(bob), address(tok), _pad(NPP), 5, "p"), "mtxPayUnderMandate");
        MetaTxLib.UAEnvelope memory e = _env(_pad(bob), w.mandateRevokeLane(address(tok), 1), 0);
        bytes32 dig = _named(address(w), UA_DELEGATE_REVOKE, e, abi.encode(address(tok), uint64(1)));
        _ok(address(w), abi.encodeCall(IMandateMerged.mtxDelegateRevoke, (e, address(tok), 1, _authOf(e.from, dig))),
            "mtxDelegateRevoke");
        _ok(address(w), _genericCd(w, me, abi.encodeCall(IMandateMerged.setMandate,
            (address(tok), _pad(bob), 1, 1, 1 days, EXPIRY)), 1, 2), "generic mtxExecute");
        e = _env(me, 1, 3);
        dig = _named(address(w), UA_REVOKE_MANDATE, e, abi.encode(address(tok)));
        _ok(address(w), abi.encodeCall(IMandateMerged.mtxRevokeMandate, (e, address(tok), _authOf(me, dig))), "mtxRevokeMandate");
        _ok(address(w), _executeCd(w, _env(me, 1, 4), address(tok), 0, abi.encodeWithSignature(
            "transfer(address,uint256)", NPP, 1)), "named mtxExecute");
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](1);
        IUARegistry.UASig[] memory as_ = new IUARegistry.UASig[](1);
        ms[0] = _call(me, abi.encodeCall(IMandateMerged.setPayee, (address(tok), _pad(NPP), false)), 1, 5);
        as_[0] = _authOf(me, _callDigest(address(w), ms[0]));
        _ok(address(w), abi.encodeCall(IMandateMerged.mtxBatch, (ms, as_)), "mtxBatch");
        e = _env(me, 1, 6);
        _ok(address(w), _cancelCd(e, 9, _authOf(me, _cancelDigest(address(w), e, 9))), "mtxCancelNonce");
        assertEq(w.mtxNonce(me, 1), 7);
        assertEq(w.mtxNonce(me, 9), 1);
        assertEq(tok.balanceOf(NPP), 6);
        assertFalse(w.payeeAllowed(address(tok), _pad(NPP)));
    }

    function test_feeNonZeroRefused() public {
        IMandateMerged w = _wallet(_pad(alice), REG_L);
        MetaTxLib.UAEnvelope memory e = _env(_pad(alice), 1, 0);
        _ok(address(w), _setPayeeCd(w, e, address(tok), _pad(NPP)), "positive control: fee 0");
        e.nonce = 1;
        (e.mode, e.fee) = (MetaTxLib.MODE_FEE_FIXED, 1);
        _refused(address(w), _setPayeeCd(w, e, address(tok), _pad(NPP)),
            abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, e.mode), "named, fixed fee");
        MetaTxLib.UAMetaTransaction memory m = _call(_pad(alice), abi.encodeCall(IMandateMerged.setPayee,
            (address(tok), _pad(NPP), false)), 1, 1);
        (m.mode, m.fee) = (MetaTxLib.MODE_FEE_FIXED, 1);
        _refused(address(w), _execCd(m, _authOf(m.from, _callDigest(address(w), m))),
            abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, m.mode), "generic, fixed fee");
        assertEq(w.mtxNonce(_pad(alice), 1), 1);
        assertEq(w.supportedModes(), 0x03);
    }

    // ------------------------------------------------------------------ Q2: the cancel is ordered

    function test_cancelIsNonceOrdered_native() public {
        _ordered(_pad(alice));
    }

    function test_cancelIsNonceOrdered_derived() public {
        _ordered(uaP);
    }

    /// A cancel signed at nonce 0 of lane 3, withheld; a newer op consumes 0; the cancel cannot land.
    function _ordered(bytes32 who) internal {
        IMandateMerged w = _wallet(who, REG_L);
        MetaTxLib.UAEnvelope memory e = _env(who, 3, 0);
        bytes memory withheld = _cancelCd(e, 9, _authOf(who, _cancelDigest(address(w), e, 9)));
        _ok(address(w), _genericCd(w, who, abi.encodeCall(IMandateMerged.setPayee, (address(tok), _pad(NPP), true)), 3, 0),
            "the newer op");
        _refused(address(w), withheld, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0), "withheld cancel");
        assertEq(w.mtxNonce(who, 9), 0, "lane 9 untouched");
        e.nonce = 1;
        _ok(address(w), _cancelCd(e, 9, _authOf(who, _cancelDigest(address(w), e, 9))), "positive control: in order");
        assertEq(w.mtxNonce(who, 9), 1);
    }

    // ------------------------------------------------------------------ invariant 2: what is signed

    function test_payeeIsSigned() public {
        IMandateMerged w = _mandate(REG_L, address(tok), _pad(bob), _pad(NPP));
        vm.prank(alice);
        w.setPayee(address(tok), _pad(address(0x5745)), true);
        MetaTxLib.UAEnvelope memory e = _payEnv(w, _pad(bob), "s");
        IUARegistry.UASig memory a = _sig(BOB_PK, _payDigest(w, e, address(tok), _pad(NPP), 10, "s", 1));
        _refused(address(w), abi.encodeCall(IMandateMerged.mtxPayUnderMandate,
            (e, address(tok), _pad(address(0x5745)), 10, PayMetaKit.ref("s"), 1, a, PayMetaKit.meta("s"))),
            abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "another approved payee");
        _ok(address(w), abi.encodeCall(IMandateMerged.mtxPayUnderMandate, (e, address(tok), _pad(NPP), 10, PayMetaKit.ref("s"), 1, a, PayMetaKit.meta("s"))),
            "the signed payee");
        assertEq(tok.balanceOf(NPP), 10);
    }

    function test_executeTargetIsSigned() public {
        IMandateMerged w = _wallet(_pad(alice), REG_L);
        _fund(address(w), address(tok), 100);
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", NPP, 1);
        MetaTxLib.UAEnvelope memory e = _env(_pad(alice), 1, 0);
        bytes32 dig = _named(address(w), UA_EXECUTE, e, abi.encode(address(tok), 0, keccak256(data)));
        bytes memory cd = abi.encodeWithSignature(
            "mtxExecute((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),address,uint256,bytes,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))",
            e, address(tok0), 0, data, _sig(ALICE_PK, dig));
        _refused(address(w), cd, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "another target");
        _ok(address(w), _executeCd(w, e, address(tok), 0, data), "the signed target");
        assertEq(tok.balanceOf(NPP), 1);
    }

    // ------------------------------------------------------------------ B: a derived subject, `UA_POOL` in the self-call

    function test_derivedSubjectReadsUAAllowedOnly() public {
        IMandateMerged w = _wallet(uaP, REG_L);
        _ok(address(w), _genericCd(w, uaP, abi.encodeCall(IMandateMerged.setPayee, (address(tok), _pad(NPP), true)), 1, 0),
            "positive control: a wallet op");
        _refused(address(w), _genericCd(w, uaP, abi.encodeCall(IMetaTx.cancelNonce, (4)), 1, 1),
            abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, IMetaTx.cancelNonce.selector), "cancelNonce: _mtxRule only");
        bytes memory iv = abi.encodeCall(IMandateMerged.isValidSignature, (bytes32(0), ""));
        _refused(address(w), _genericCd(w, uaP, iv, 1, 1),
            abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, bytes4(iv)), "on no list");
        IMandateMerged n = _wallet(_pad(alice), REG_L);
        _ok(address(n), _genericCd(n, _pad(alice), abi.encodeCall(IMetaTx.cancelNonce, (4)), 1, 0),
            "a native id keeps _mtxRule: cancelNonce");
        assertEq(n.mtxNonce(_pad(alice), 4), 1);
    }

    /// Every check compares `_subject()` with the stored id; `_msgSender()` is `UA_POOL` for every derived subject.
    function test_checksReadSubjectNotMsgSender() public {
        IMandateMerged w = _mandate(REG_L, address(tok), uaB, _pad(NPP));
        _ok(address(w), _payCd(w, uaB, address(tok), _pad(NPP), 10, "b"), "the derived delegate by its id");
        _refused(address(w), _payCd(w, uaP, address(tok), _pad(NPP), 10, "p"), abi.encodeWithSelector(NOT_DELEGATE),
            "another derived id, the same UA_POOL");
        // a mandate naming the pool itself: no derived subject is it
        vm.prank(alice);
        w.setMandate(address(tok), _pad(POOL), 1_000, 2_500, 1 days, EXPIRY);
        _refused(address(w), _payCd(w, uaP, address(tok), _pad(NPP), 10, "q"), abi.encodeWithSelector(NOT_DELEGATE),
            "UA_POOL as delegate");
        assertEq(tok.balanceOf(NPP), 10);
    }

    /// CTR-ACC-12: a derived owner has no ERC-1271 answer, even for a key whose address is its low 160 bits. CTR-ACC-02
    /// (B P3-2, ERC-7739 only): a native owner's answer is over the `PersonalSign` / `TypedDataSign` message naming this
    /// wallet, never the raw `h`; `isValidSignature(0x7739…7739, "")` is `0x77390001` for a native owner only.
    function test_derivedOwnerHasNoErc1271Answer() public {
        bytes32 h = keccak256("anything");
        IMandateMerged n = _wallet(_pad(alice), REG_L);
        bytes memory sig = _ecdsa(ALICE_PK, Erc7739Kit.personal(address(n), h));
        assertEq(n.isValidSignature(h, sig), bytes4(0x1626ba7e), "positive control: a native owner's ECDSA, PersonalSign");
        assertEq(n.isValidSignature(h, _ecdsa(BOB_PK, Erc7739Kit.personal(address(n), h))), bytes4(0xffffffff), "another key");
        assertEq(n.isValidSignature(h, _ecdsa(ALICE_PK, h)), bytes4(0xffffffff), "the raw hash");
        assertEq(n.isValidSignature(ERC7739Lib.DETECT, ""), bytes4(0x77390001), "support detection");
        assertEq(_wallet(_pad(alice), REG_L).isValidSignature(h, sig), bytes4(0xffffffff), "same owner, other wallet");
        bytes32 shadow = _pad(alice) | bytes32(uint256(1) << 200);
        IMandateMerged d = _wallet(shadow, REG_L);
        assertEq(d.isValidSignature(h, _ecdsa(ALICE_PK, Erc7739Kit.personal(address(d), h))), bytes4(0xffffffff),
            "derived owner, its low 160 bits' key");
        IMandateMerged d2 = _wallet(uaP, REG_L);
        assertEq(d2.isValidSignature(h, _ecdsa(ALICE_PK, Erc7739Kit.personal(address(d2), h))), bytes4(0xffffffff),
            "derived owner");
        assertEq(d2.isValidSignature(ERC7739Lib.DETECT, ""), bytes4(0xffffffff), "derived owner: no detection answer");
    }

    /// CTR-ACC-02: a native owner's `TypedDataSign` answers for its own wallet only.
    function test_nativeOwnerTypedDataSignBoundToTheWallet() public {
        IMandateMerged n = _wallet(_pad(alice), REG_L);
        bytes32 app = keccak256("app");
        bytes32 c = keccak256("contents");
        bytes32 ah = keccak256(abi.encodePacked(hex"1901", app, c));
        bytes memory td = Erc7739Kit.wrap(_ecdsa(ALICE_PK, Erc7739Kit.nested(address(n), app, "Mail", "Mail(address to)", c)),
            app, c, "Mail(address to)");
        assertEq(n.isValidSignature(ah, td), bytes4(0x1626ba7e), "positive control: TypedDataSign");
        assertEq(_wallet(_pad(alice), REG_L).isValidSignature(ah, td), bytes4(0xffffffff), "same owner, other wallet");
        assertEq(n.isValidSignature(keccak256("other"), td), bytes4(0xffffffff), "the hash is not app || contents");
        // a suffix length past the signature falls back to PersonalSign (no underflow), which this ECDSA does not match
        assertEq(n.isValidSignature(ah, abi.encodePacked(_ecdsa(ALICE_PK, ah), bytes2(0xffff))), bytes4(0xffffffff), "length");
    }

    // ------------------------------------------------------------------ invariant 3: the retired forms

    function test_executeMetaTransactionRefused() public {
        IMandateMerged w = _wallet(_pad(alice), REG_L);
        bytes memory data = abi.encodeCall(IMandateMerged.setPayee, (address(tok), _pad(NPP), true));
        _ok(address(w), _genericCd(w, _pad(alice), data, 1, 0), "positive control: the merged generic entry");
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({from: alice, data: data, batch: 1, nonce: 1,
            validUntil: block.timestamp + 600, mode: 0, relayer: address(0), fee: 0, feeRecipient: address(0)});
        bytes memory sig = _sig(ALICE_PK, _dig(address(w), MtxHash.hashStruct(m))).signature;
        _refused(address(w), abi.encodeCall(IMandateMerged.executeMetaTransaction, (m, sig)),
            abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(data)), "EIP-1776 alias");
        assertEq(w.mtxNonce(_pad(alice), 1), 1);
    }

    /// The flat builders (MD-11 (a)) and the address generic entries have no function.
    function test_flatBuildersHaveNoEntry() public {
        IMandateMerged w = _mandate(REG_L, address(tok), _pad(bob), _pad(NPP));
        _ok(address(w), _payCd(w, _pad(bob), address(tok), _pad(NPP), 1, "ctl"), "positive control: the named pay");
        bytes[7] memory old = [
            abi.encodeWithSignature("mtxPayUnderMandate(address,address,uint256,bytes32,uint64,uint256,bytes)",
                address(tok), NPP, uint256(1), bytes32("f"), uint64(1), block.timestamp + 600, hex"00"),
            abi.encodeWithSignature("mtxRevoke(address,uint64,uint256,bytes)", address(tok), uint64(1), block.timestamp, hex"00"),
            abi.encodeWithSignature("mtxExecuteAsOwner(bytes,uint256,uint256,bytes)", hex"", uint256(0), block.timestamp, hex"00"),
            abi.encodeWithSignature("mtxExecuteAsOwnerRaw(bytes,uint256,uint256,bytes)", hex"", uint256(0), block.timestamp, hex"00"),
            abi.encodeWithSignature("mtxNonce(address,uint256)", bob, uint256(0)),
            abi.encodeWithSignature("mtxCancelNonce((address,uint256,uint256,uint256,uint32,address,uint256,address),uint256,bytes)",
                MetaTxLib.Envelope(alice, 1, 0, block.timestamp, 0, address(0), 0, address(0)), uint256(9), hex"00"),
            abi.encodeWithSignature("mtxBatch((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address)[],bytes[])",
                new MetaTxLib.MetaTransaction[](0), new bytes[](0))
        ];
        for (uint256 i; i < old.length; ++i) _refused(address(w), old[i], "", vm.toString(i));
    }

    /// A signature of the old address forms (`PayUnderMandate`, `MetaTransaction`) has no entry, and does not verify on
    /// the new one.
    function test_oldAddressWalletSignatureRefused() public {
        IMandateMerged w = _mandate(REG_L, address(tok), _pad(bob), _pad(NPP));
        MetaTxLib.Envelope memory oe = MetaTxLib.Envelope(bob, 7, 0, block.timestamp + 600, 0, address(0), 0, address(0));
        bytes32 oldD = _dig(address(w), keccak256(abi.encode(keccak256(
            "PayUnderMandate(address from,address token,address payee,uint256 amount,bytes32 entryRef,uint64 epoch,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
            bob, address(tok), NPP, 10, bytes32("o"), uint64(1), 7, 0, oe.validUntil, 0, address(0), 0, address(0))));
        bytes memory oldSig = _sig(BOB_PK, oldD).signature;
        _refused(address(w), abi.encodeWithSignature(
            "mtxPayUnderMandate((address,uint256,uint256,uint256,uint32,address,uint256,address),address,address,uint256,bytes32,uint64,bytes)",
            oe, address(tok), NPP, uint256(10), bytes32("o"), uint64(1), oldSig), "", "the old named entry");
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({from: bob, data: abi.encodeWithSignature(
            "payUnderMandate(address,address,uint256,bytes32,uint64)", address(tok), NPP, 10, bytes32("o"), uint64(1)),
            batch: 7, nonce: 0, validUntil: oe.validUntil, mode: 0, relayer: address(0), fee: 0, feeRecipient: address(0)});
        bytes memory mSig = _sig(BOB_PK, _dig(address(w), MtxHash.hashStruct(m))).signature;
        _refused(address(w), abi.encodeWithSignature(
            "mtxExecute((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)", m, mSig), "",
            "the old generic entry");
        MetaTxLib.UAEnvelope memory e = _env(_pad(bob), 7, 0);
        e.validUntil = oe.validUntil;
        IUARegistry.UASig memory a;
        a.signature = oldSig;
        _refused(address(w), abi.encodeCall(IMandateMerged.mtxPayUnderMandate, (e, address(tok), _pad(NPP), 10, PayMetaKit.ref("o"), 1, a, PayMetaKit.meta("o"))),
            abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "the old struct's signature on the new entry");
        a = _sig(BOB_PK, _payDigest(w, e, address(tok), _pad(NPP), 10, "o", 1));
        _ok(address(w), abi.encodeCall(IMandateMerged.mtxPayUnderMandate, (e, address(tok), _pad(NPP), 10, PayMetaKit.ref("o"), 1, a, PayMetaKit.meta("o"))),
            "positive control");
    }

    // ------------------------------------------------------------------ Hedera (NET-HED-03 through IS_HEDERA)

    function _ed(uint256 k, bytes32 d) internal pure returns (IUARegistry.UASig memory a) {
        (bytes32 r, bytes32 vs) = vm.signCompact(k, d);
        a.signature = abi.encodePacked(r, vs);
    }

    function test_hederaEd25519OwnerSignsHip632() public {
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        address edOwner = address(uint160(2_000_001));
        MockHederaAccountService(HAS).setEdKey(edOwner, vm.addr(ED_KEY));
        IMandateMerged hw = _hwallet(_pad(edOwner), REG_L);
        MetaTxLib.UAEnvelope memory e = _env(_pad(edOwner), 1, 0);
        bytes32 dig = _named(address(hw), UA_SET_PAYEE, e, abi.encode(address(tok), _pad(NPP), true));
        _refused(address(hw), abi.encodeCall(IMandateMerged.mtxSetPayee, (e, address(tok), _pad(NPP), true, _ed(BOB_PK, dig))),
            abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "another key");
        vm.expectCall(REG_L, bytes(""), 0);
        _ok(address(hw), abi.encodeCall(IMandateMerged.mtxSetPayee, (e, address(tok), _pad(NPP), true, _ed(ED_KEY, dig))),
            "HIP-632");
        assertTrue(hw.payeeAllowed(address(tok), _pad(NPP)));
        // the plain wallet takes no HIP-632 path
        IMandateMerged w = _wallet(_pad(edOwner), REG_L);
        dig = _named(address(w), UA_SET_PAYEE, e, abi.encode(address(tok), _pad(NPP), true));
        _refused(address(w), abi.encodeCall(IMandateMerged.mtxSetPayee, (e, address(tok), _pad(NPP), true, _ed(ED_KEY, dig))),
            abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "not Hedera");
    }

    function test_hip632RefusedForAContract() public {
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        Mock1271Wallet cw = new Mock1271Wallet(alice);
        MockHederaAccountService(HAS).setEdKey(address(cw), vm.addr(ED_KEY));
        IMandateMerged hw = _hwallet(_pad(address(cw)), REG_L);
        MetaTxLib.UAEnvelope memory e = _env(_pad(address(cw)), 1, 0);
        bytes32 dig = _named(address(hw), UA_SET_PAYEE, e, abi.encode(address(tok), _pad(NPP), true));
        _refused(address(hw), abi.encodeCall(IMandateMerged.mtxSetPayee, (e, address(tok), _pad(NPP), true, _ed(ED_KEY, dig))),
            abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "a contract never takes HIP-632");
        _ok(address(hw), abi.encodeCall(IMandateMerged.mtxSetPayee, (e, address(tok), _pad(NPP), true, _sig(ALICE_PK, dig))),
            "positive control: its ERC-1271");
    }

    // ------------------------------------------------------------------ pins

    /// The six wallet structs and the cancel, verbatim with their hashes (`cast keccak`), and each entry run over a digest
    /// built from its string (`_everyEntry`), so the wallet's typehashes are these.
    function test_walletUATypehashesArePinned() public {
        assertEq(keccak256(bytes(UA_SET_MANDATE)), 0x77cac4912d9b5ea899e4894cd527290f239809543c0a3604b89ef74796d88492);
        assertEq(keccak256(bytes(UA_SET_PAYEE)), 0xf0fb362dece88eadf659a55ed5c2606877293dbd69f9bb7eba806da921a77dc4);
        assertEq(keccak256(bytes(UA_REVOKE_MANDATE)), 0x8ec86d41c994f21c46c1517876704534ac3d564d82e844ec73b07d6f4b07b8bc);
        assertEq(keccak256(bytes(UA_PAY_UNDER_MANDATE)), 0xadbc54026c0db2f3af4387e08d6db8d717cb74af436468a089f09d377d6f0119);
        assertEq(keccak256(bytes(UA_DELEGATE_REVOKE)), 0x774892773810b24a4c22164980cf38c17d181e11c99acc17c7229238a11035e0);
        assertEq(keccak256(bytes(UA_EXECUTE)), 0x0d4d513cf9b5169c6422cb757a9af6c10be34ccd883caa3a1d18d165cf9ea413);
        assertEq(MetaTxLib.UA_CANCEL_NONCE_TYPEHASH, 0xcd17c2129240241748e841a7f0572558b9c5a900a47bc540170a8c258d291c54);
        _everyEntry();
    }

    /// `SmartKeyAccount` keeps its address surface (Q6): its code without the CBOR tail, as at `ref/pre-ua-mtx-merge`.
    /// T66b (controller 2026-11-09): the `<X>Core` + flat-face split of `UAMetaTxBase` / `MetaTxBase` moved it, 21,003 -> 21,085 B:
    /// 0xd201866a…5876 -> 0xbede204d…3962; its ABI and behaviour unchanged. B P3-2 (ua-mtx-fix2-contracts): ERC-1271 over
    /// `erc1271Digest(hash)`, the self-call through `isValidOwnDigest`: 0xbede204d…3962 -> 0x4d73f626…33e1; ERC-7739 only
    /// (owner 2026-11-12; `erc1271Digest` to legacy): -> this.
    function test_smartKeyAccountByteIdentical() public {
        address at = address(0xA002);
        deployCodeTo("SmartKeyAccount.sol:SmartKeyAccount", abi.encode(keccak256("wallet-uid")), at);
        bytes memory c = at.code;
        uint256 meta = (uint256(uint8(c[c.length - 2])) << 8 | uint8(c[c.length - 1])) + 2;
        assembly ("memory-safe") { mstore(c, sub(mload(c), meta)) }
        assertEq(keccak256(c), 0xfb57bbfbdc8f91765feef8ff715e18a0a6284274f74de4f469ef6cb8b0b842da);
    }
}
