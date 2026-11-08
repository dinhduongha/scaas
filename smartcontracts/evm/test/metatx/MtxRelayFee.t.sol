// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {UACall} from "../ua/UACall.sol";
import {console2, Vm} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {MtxRelayFee, MtxRelayExecutor} from "../../src/metatx/MtxRelayFee.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UAMldsaVerifier} from "../../src/ua/MlDsa.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {MtxRegistryMock} from "../helpers/MtxRegistryMock.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {PqzRegistryBase, PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {GasBurner} from "../pqz/PqzStateGas.t.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {TYPED_OPS, TYPED_OPS_LEGACY, checkRow, onChain, domainField, msgField, domainJson, domainOf, h, n, a as a_} from "./NamedEntry.t.sol";
import {find} from "./TypedOps.t.sol";

/// A token stand-in whose `mtxRelayFee` calls back into the router (the router does not check the token).
contract ReenterToken {
    address internal router;
    bytes internal data;

    function arm(address r, bytes calldata d) external {
        (router, data) = (r, d);
    }

    function mtxRelayFee(bytes32, address, bytes32, bytes32, uint256, uint256, uint256, uint256, IUARegistry.UASig calldata)
        external
    {
        (bool ok, bytes memory ret) = router.call(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }
}

/// @notice CTR-MTX-27 (metatx split T9, spec §7.1, R14; TS-D19): `MtxRelayFee` runs a fee-less call through its executor,
///         then the payer's `UARelayFee` (`relayer` = router; `entryRef = relayRef(target, callData)`, lane `payLane(ref)`,
///         nonce 0, fee `NONE`, all built by the token), atomically. Token: a `NORMAL` clone on a gen-1 `UARegistry` with `mldsa65` (the precompile
///         mocked, filler signatures, `PqzRegistryBase`); target: a `MetaTxBase` contract (`MtxRegistryMock`, fee `NONE`)
///         whose `mtxExecute` carries bob's own signature. Payers: alice (ECDSA, a native id) and an `mldsa65` UA.
///         ua-mtx-merge T2 (R28): one `relay` on ids (today's `uaRelay`), one `UARelayFee`; the address `relay`,
///         `RelayFee` and this file as it stood are in legacy/ua-mtx-merge/.
contract MtxRelayFeeTest is PqzRegistryBase {
    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant BOB_PK = 0xB0B;
    address internal constant REL = address(0xBEEF);
    address internal constant PAYEE = address(0xB0B5);
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint256 internal constant FEE = 25;
    /// pay-meta-tax T38 (spec §4, O4): `batch` and `nonce`, the payer's own lane; the struct without them is in
    /// legacy/ua-mtx-merge/3e/.
    bytes32 internal constant UA_RELAY_FEE = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)");
    bytes32 internal constant UA_RELAY_FEE_OLD = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 validUntil,address relayer)");
    /// The lane the tests' payer dedicates to relay fees (O4: "for example lane 2").
    uint256 internal constant RF_LANE = 2;

    MtxRelayFee internal router;
    address internal exec;
    NormalToken internal tok;
    MtxRegistryMock internal target;
    address internal alice = vm.addr(ALICE_PK);
    address internal bob = vm.addr(BOB_PK);
    bytes32 internal ml; // the mldsa65 payer UA

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        (bytes memory valid, bytes memory invalid) = _mockMlDsa();
        mlv = new UAMldsaVerifier(UAKinds.MLDSA65, ML65, valid, invalid);
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(UAKinds.MLDSA65, address(mlv), 100_000);
        reg = new UARegistry(PQZ_UID, address(0), false, 12_000_000, address(0), true, k);
        tok = NormalToken(Clones.clone(address(new NormalToken(1,
            plainEnv(address(this), address(0), PQZ_UID, address(reg), false), ""))));
        tok.initialize(address(this), 1, abi.encode(normalInit("Points", "PTS", 6, 1_000_000, alice, address(this))));
        ml = _mldsaUA(7);
        tok.mintToUA(ml, 1_000);
        target = new MtxRegistryMock("SCaaS TestRegistry", PQZ_UID);
        router = new MtxRelayFee();
        exec = router.EXECUTOR();
    }

    // ------------------------------------------------------------------ helpers

    function _ecdsa(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    /// bob's signed `bump(1)` on `target` at nonce `n`, relayer open (or bound to `rel` when non-zero), as `mtxExecute`.
    function _call(uint256 n, address rel) internal view returns (bytes memory) {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(bob, abi.encodeCall(MtxRegistryMock.bump, (1)), 0,
            n, block.timestamp + 300, rel == address(0) ? 0 : RR, rel, 0, address(0));
        return abi.encodeCall(IMetaTx.executeMetaTransaction, (m, _ecdsa(BOB_PK, target.mtxDigest(m))));
    }

    function _ref(address t, bytes memory cd) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.relayfee", block.chainid, t, keccak256(cd)));
    }

    /// What a relay's payer signs, on either path (`from`, `to` as ids).
    struct Pay {
        bytes32 from;
        bytes32 to;
        uint256 value;
        uint256 validUntil;
        address tgt;
        bytes32 cdh;
        uint256 batch;
        uint256 nonce;
    }

    function _upay(bytes32 from, bytes32 to, address t, bytes memory cd, uint256 value) internal view returns (Pay memory) {
        return Pay(from, to, value, block.timestamp + 300, t, keccak256(cd), RF_LANE, tok.mtxNonce(from, RF_LANE));
    }

    /// alice's `RelayFee` of `value` to `to` for the call `cd` on `t`.
    function _pay(address to, address t, bytes memory cd, uint256 value) internal view returns (Pay memory) {
        return _upay(MetaTxLib.pad(alice), MetaTxLib.pad(to), t, cd, value);
    }

    function _digest(address token, bytes32 typehash, Pay memory p, address rel) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainOf(token), keccak256(abi.encode(
            typehash, p.from, p.tgt, p.cdh, p.to, p.value, p.batch, p.nonce, p.validUntil, rel))));
    }

    /// The digest of alice's `UARelayFee`, relayer = the router (ua-mtx-merge T2: the one relay-fee struct).
    function _d(Pay memory p) internal view returns (bytes32) {
        return _digest(address(tok), UA_RELAY_FEE, p, address(router));
    }

    /// A native id's `UASig`: its own signature only (R17).
    function _n(bytes memory sig) internal pure returns (IUARegistry.UASig memory u) {
        u.signature = sig;
    }

    function _sig(Pay memory p) internal view returns (bytes memory) {
        return _ecdsa(ALICE_PK, _d(p));
    }

    function _send(Pay memory p, bytes memory cd, address token, bytes memory s) internal {
        router.relay(p.tgt, cd, token, p.from, p.to, p.value, p.batch, p.nonce, p.validUntil, _n(s));
    }

    function _usend(Pay memory u, bytes memory cd, bytes memory auth) internal {
        router.relay(u.tgt, cd, address(tok), u.from, u.to, u.value, u.batch, u.nonce, u.validUntil, UACall.auth(u.from, auth));
    }

    function _relay(bytes memory cd, Pay memory t) internal {
        bytes memory s = _sig(t);
        vm.prank(REL);
        _send(t, cd, address(tok), s);
    }

    // ------------------------------------------------------------------ the call hash

    function test_relayRef_formula() public {
        bytes memory cd = _call(0, address(0));
        bytes32 r = router.relayRef(address(target), cd);
        assertEq(r, _ref(address(target), cd));
        vm.chainId(1);
        assertTrue(router.relayRef(address(target), cd) != r, "the chain id is in ref");
    }

    /// `../vectors/metatx/relayref.json` (`[{name, chainId, target, callData, callHash, ref, payLane}]`): written with
    /// `RELAYREF_WRITE=1`, else checked against the router and the token; `clientkeys`, `ua-rs` and `ua-qt` read it
    /// (metatx split T18). `cancel_nonce_7` is the call `paymeta.json`'s `bound_call` (schema 3) commits to.
    function test_relayRefVectors() public {
        string memory file = "../vectors/metatx/relayref.json";
        if (vm.envOr("RELAYREF_WRITE", false)) {
            bytes memory long = new bytes(300);
            for (uint256 i; i < 300; ++i) long[i] = bytes1(uint8(uint256(keccak256(abi.encode("relayref", i / 32))) >> (8 * (i % 32))));
            string memory j = string.concat("[\n", _refRow("cancel_nonce_7", 7622, address(0xC0FFEE),
                abi.encodeCall(IMetaTx.cancelNonce, (7))), ",\n");
            j = string.concat(j, _refRow("empty_call", 22776, address(0x5CAA5), ""), ",\n");
            vm.writeFile(file, string.concat(j, _refRow("long_call_anvil", 31337, address(0xBEEFCAFE), long), "\n]\n"));
        }
        string memory f = vm.readFile(file);
        uint256 rows;
        while (vm.keyExistsJson(f, string.concat("[", vm.toString(rows), "]"))) ++rows;
        assertEq(rows, 3, "rows");
        for (uint256 i; i < rows; ++i) {
            string memory p = string.concat("[", vm.toString(i), "]");
            vm.chainId(vm.parseJsonUint(f, string.concat(p, ".chainId")));
            bytes memory cd = vm.parseJsonBytes(f, string.concat(p, ".callData"));
            bytes32 r = vm.parseJsonBytes32(f, string.concat(p, ".ref"));
            assertEq(keccak256(cd), vm.parseJsonBytes32(f, string.concat(p, ".callHash")), "callHash");
            assertEq(router.relayRef(vm.parseJsonAddress(f, string.concat(p, ".target")), cd), r, "ref");
            assertEq(bytes32(tok.payLane(r)), vm.parseJsonBytes32(f, string.concat(p, ".payLane")), "payLane");
        }
    }

    function _refRow(string memory name, uint256 chainId, address t, bytes memory cd) internal returns (string memory) {
        vm.chainId(chainId);
        bytes32 r = router.relayRef(t, cd);
        string memory head = string.concat('  {"name":"', name, '","chainId":', vm.toString(chainId), ',"target":"',
            vm.toString(t), '","callData":"', vm.toString(cd), '","callHash":"', vm.toString(keccak256(cd)));
        return string.concat(head, '","ref":"', vm.toString(r), '","payLane":"', vm.toString(bytes32(tok.payLane(r))), '"}');
    }

    // ------------------------------------------------------------------ CTR-MTX-27 conformance

    /// (1) a payment signed for another target, other call bytes or another chain is refused: the token builds `RelayFee`
    ///     from what the router passes. Repeatable views as the call, so only the payment can refuse.
    function test_relay_boundToCall() public {
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        Pay memory t = _pay(address(router), address(target), cd, FEE);
        bytes memory s = _sig(t);
        MtxRegistryMock other = new MtxRegistryMock("SCaaS TestRegistry", PQZ_UID);
        Pay memory x = _pay(address(router), address(other), cd, FEE);
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _send(x, cd, address(tok), s); // another target
        bytes memory cd1 = abi.encodeWithSignature("count(address)", bob);
        x = _pay(address(router), address(target), cd1, FEE);
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _send(x, cd1, address(tok), s); // other call bytes
        vm.chainId(1);
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _send(t, cd, address(tok), s); // another chain
        vm.chainId(7622);
        _relay(cd, t);
        assertEq(tok.balanceOf(REL), FEE);
    }

    /// (2) Review Focus 3: a `UARelayFee` signature settles nothing else: as the `UAMetaTransfer` of the same terms, on
    ///     every typed entry of the token, it does not verify. The positive control is `test_relayFeeTyped`.
    function test_routerBoundPayment_refusedOutsideRouter() public {
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        Pay memory p = _pay(address(router), address(target), cd, FEE);
        bytes memory s = _sig(p);
        MetaTxLib.UAMetaTransfer memory t = MetaTxLib.UAMetaTransfer(p.from, p.to, FEE, ref, p.batch, 0, p.validUntil, RR,
            REL, 0, address(0));
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxExecuteTransfer(t, _n(s));
        MetaTxLib.UAMetaTransfer[] memory ts = new MetaTxLib.UAMetaTransfer[](1);
        IUARegistry.UASig[] memory ss = new IUARegistry.UASig[](1);
        (ts[0], ss[0]) = (t, _n(s));
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxBatchTransfer(ts, ss);
        // pay-meta-tax T37, meaning: `mtxPay` checks `PayMeta` first, and `ref` (a call's hash) is no `PayMeta`
        // commitment: refused by name before the signature (was `MetaTxBadSignature`)
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, ref, PayMetaKit.ref(0)));
        tok.mtxPay(t, _n(s), PayMetaKit.meta(0));
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), p.batch), 0);
    }

    /// (3) a `callData` that executes another router-bound payment through the executor fails: the token reads the
    ///     executor as `relayer`, which the payer did not sign.
    function test_relay_callDataIsAnotherRouterPayment() public {
        bytes memory c0 = _call(0, address(0));
        Pay memory inner = _pay(REL, address(target), c0, 500);
        bytes memory cd = abi.encodeCall(IERC20MetaTx.mtxRelayFee,
            (inner.from, address(target), inner.cdh, inner.to, 500, inner.batch, inner.nonce, inner.validUntil, _n(_sig(inner))));
        Pay memory t = _pay(address(router), address(tok), cd, FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _send(t, cd, address(tok), s);
    }

    /// (4) a target revert leaves no payment: the inner revert data bubbles, nothing moved, the pay lane unused.
    function test_relay_innerRevertBubbles() public {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(bob, abi.encodeCall(MtxRegistryMock.bump, (0)), 0,
            0, block.timestamp + 300, 0, address(0), 0, address(0));
        bytes memory cd = abi.encodeCall(IMetaTx.executeMetaTransaction, (m, _ecdsa(BOB_PK, target.mtxDigest(m))));
        Pay memory t = _pay(address(router), address(target), cd, FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(MtxRegistryMock.ZeroBump.selector);
        _send(t, cd, address(tok), s);
        assertEq(tok.balanceOf(alice), 1_000_000);
        assertEq(tok.balanceOf(REL), 0);
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), t.batch), 0);
    }

    /// (5) a second `relay` with the same `ref` fails at the pay lane (a repeatable call: an unguarded view).
    function test_relay_payOnce() public {
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        Pay memory t = _pay(address(router), address(target), cd, FEE);
        _relay(cd, t);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _send(t, cd, address(tok), s);
        assertEq(tok.balanceOf(REL), FEE);
    }

    /// (6a) open mode (`t.to == router`): the router forwards `t.value` to `msg.sender`.
    function test_relay_openModePaysCaller() public {
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        Pay memory t = _pay(address(router), address(target), cd, FEE);
        bytes memory s = _sig(t);
        vm.expectEmit(address(tok));
        // ua-mtx-merge T2 (R18, R20), meaning: `UAPaymentSettled` with padded ids (fee 0: feeTo = the relayer)
        emit IUALedger.UAPaymentSettled(MetaTxLib.pad(alice), MetaTxLib.pad(address(router)), FEE, 0, address(router), ref);
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), MetaTxLib.pad(alice), MetaTxLib.pad(REL), FEE);
        vm.prank(REL);
        _send(t, cd, address(tok), s);
        assertEq(target.count(bob), 1, "the call ran");
        assertEq(tok.balanceOf(REL), FEE);
        assertEq(tok.balanceOf(alice), 1_000_000 - FEE);
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), t.batch), 1);
    }

    /// (6b) a bound payee is paid directly; the submitting relayer gets nothing, the router forwards nothing.
    function test_relay_boundPayee() public {
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        Pay memory t = _pay(PAYEE, address(target), cd, FEE);
        bytes memory s = _sig(t);
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), MetaTxLib.pad(alice), MetaTxLib.pad(PAYEE), FEE);
        vm.prank(REL);
        _send(t, cd, address(tok), s);
        assertEq(tok.balanceOf(PAYEE), FEE);
        assertEq(tok.balanceOf(REL), 0);
        assertEq(tok.balanceOf(address(router)), 0);
    }

    /// (7) a UA payer works through `relay`: an `mldsa65` UA (open mode: its ledger to the relayer's public balance;
    ///     a bound native payee; a bound derived payee, the event `payee` its id) and a native id (ECDSA).
    function test_uaRelay_mldsa65Payer() public {
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        Pay memory u = _upay(ml, MetaTxLib.pad(address(router)), address(target), cd, FEE);
        vm.expectEmit(address(tok));
        emit IUALedger.UAPaymentSettled(ml, u.to, FEE, 0, address(router), ref);
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), ml, MetaTxLib.pad(REL), FEE);
        vm.prank(REL);
        _usend(u, cd, _mlAuth());
        assertEq(tok.balanceOfUA(ml), 1_000 - FEE);
        assertEq(tok.balanceOf(REL), FEE);
        assertEq(target.count(bob), 1);

        cd = _call(1, address(0));
        ref = _ref(address(target), cd);
        u = _upay(ml, MetaTxLib.pad(PAYEE), address(target), cd, FEE);
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), ml, MetaTxLib.pad(PAYEE), FEE);
        vm.prank(REL);
        _usend(u, cd, _mlAuth());
        assertEq(tok.balanceOf(PAYEE), FEE);

        bytes32 ml2 = _mldsaUA(8);
        cd = _call(2, address(0));
        ref = _ref(address(target), cd);
        u = _upay(ml, ml2, address(target), cd, FEE);
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), ml, ml2, FEE);
        vm.prank(REL);
        _usend(u, cd, _mlAuth());
        assertEq(tok.balanceOfUA(ml2), FEE);

        cd = _call(3, address(0));
        ref = _ref(address(target), cd);
        u = _upay(MetaTxLib.pad(alice), MetaTxLib.pad(address(router)), address(target), cd, FEE);
        bytes memory a = _ecdsa(ALICE_PK, _digest(address(tok), UA_RELAY_FEE, u, address(router)));
        vm.prank(REL);
        _usend(u, cd, a);
        assertEq(tok.balanceOf(REL), 2 * FEE);
        assertEq(tok.balanceOfUA(ml), 1_000 - 3 * FEE);
        assertEq(target.count(bob), 4);
    }

    /// (8) re-entry into the router is refused: from the target call (the executor calls `relay`) and from a token.
    function test_relay_reentryRefused() public {
        bytes4 reentry = bytes4(keccak256("ReentrancyGuardReentrantCall()"));
        bytes memory cd0 = _call(0, address(0));
        Pay memory ti = _pay(address(router), address(target), cd0, FEE);
        bytes memory re = abi.encodeCall(MtxRelayFee.relay,
            (address(target), cd0, address(tok), ti.from, ti.to, FEE, ti.batch, ti.nonce, ti.validUntil, _n(_sig(ti))));
        Pay memory t = _pay(address(router), address(router), re, FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(reentry);
        _send(t, re, address(tok), s);

        ReenterToken rt = new ReenterToken();
        rt.arm(address(router), re);
        bytes memory cd1 = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        Pay memory t1 = _pay(address(router), address(target), cd1, FEE);
        vm.prank(REL);
        vm.expectRevert(reentry);
        _send(t1, cd1, address(rt), "");
    }

    // ------------------------------------------------------------------ extra (spec §7.1)

    /// The fields the old shape check held are the signed struct's now (TS-D19): each changed from a passing call fails
    /// the signature, `validUntil` past its time is `MetaTxExpired`; the unchanged call then passes.
    function test_relayFeeFieldsBound() public {
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        Pay memory t = _pay(address(router), address(target), cd, FEE);
        bytes memory s = _sig(t);
        Pay memory x = _pay(PAYEE, address(target), cd, FEE);
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _send(x, cd, address(tok), s); // another payee
        x = _pay(address(router), address(target), cd, FEE + 1);
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _send(x, cd, address(tok), s); // another value
        x = _pay(address(router), address(target), cd, FEE);
        x.validUntil += 1;
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _send(x, cd, address(tok), s); // another validUntil
        vm.warp(t.validUntil + 1);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, t.validUntil, block.timestamp));
        _send(t, cd, address(tok), s);
        vm.warp(t.validUntil);
        vm.prank(REL);
        _send(t, cd, address(tok), s);
        assertEq(tok.balanceOf(REL), FEE);
    }

    /// Conformance item 9 (controller call 2026-10-27): the target must have code at relay time. A counterfactual
    /// target (CREATE2, not yet deployed) is refused, so the payment cannot be spent on an empty call; after the deploy
    /// the same `t, sig` settles. An EOA and a precompile are refused too.
    function test_relay_targetNoCode_counterfactual() public {
        bytes32 salt = keccak256("t9.counterfactual");
        address pred = vm.computeCreate2Address(salt, keccak256(abi.encodePacked(type(MtxRegistryMock).creationCode,
            abi.encode("SCaaS TestRegistry", PQZ_UID))), address(this));
        assertEq(pred.code.length, 0);
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        Pay memory t = _pay(address(router), pred, cd, FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(MtxRelayFee.RelayTargetNoCode.selector, pred));
        _send(t, cd, address(tok), s);
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), t.batch), 0, "the lane is not burnt");
        assertEq(address(new MtxRegistryMock{salt: salt}("SCaaS TestRegistry", PQZ_UID)), pred);
        vm.prank(REL);
        _send(t, cd, address(tok), s);
        assertEq(tok.balanceOf(REL), FEE);
        address[2] memory empty = [address(0xE0A), address(1)]; // an EOA, the ecrecover precompile
        for (uint256 i; i < 2; ++i) {
            t = _pay(address(router), empty[i], cd, FEE);
            vm.prank(REL);
            vm.expectRevert(abi.encodeWithSelector(MtxRelayFee.RelayTargetNoCode.selector, empty[i]));
            _send(t, cd, address(tok), "");
        }
    }

    /// Owner ruling 2026-10-30 (D4): an EIP-7702 designator target is an EOA, refused like one: one to a contract (the
    /// delegate's code must not run as the target) and one to a code-less address (the call would succeed empty and the
    /// payer pay for nothing). Nothing is paid, the lane is not burnt.
    function test_relay_targetDesignatorRefused() public {
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        address[2] memory to = [address(target), address(0xE0A)];
        for (uint256 i; i < 2; ++i) {
            address d = address(uint160(0xD7702 + i));
            vm.etch(d, abi.encodePacked(hex"ef0100", to[i]));
            Pay memory t = _pay(address(router), d, cd, FEE);
            bytes memory s = _sig(t);
            vm.prank(REL);
            vm.expectRevert(abi.encodeWithSelector(MtxRelayFee.RelayTargetNoCode.selector, d));
            _send(t, cd, address(tok), s);
            assertEq(tok.mtxNonce(MetaTxLib.pad(alice), t.batch), 0, "the lane is not burnt");
        }
    }

    /// `test_relayFeeExecutorPayeeRefused`: never pay the executor (controller call 2026-10-27; the token's `mtxRelayFee`
    /// does not know it): `payee == executor` (UA: `pad(executor)`) is `RelayFeeShape` with a valid signature for it; the
    /// same call with another payee runs.
    function test_relayFeeExecutorPayeeRefused() public {
        bytes memory cd = _call(0, address(0));
        Pay memory t = _pay(exec, address(target), cd, FEE);
        bytes memory s = _sig(t);
        vm.expectRevert(MtxRelayFee.RelayFeeShape.selector);
        vm.prank(REL);
        _send(t, cd, address(tok), s);
        Pay memory u = _upay(MetaTxLib.pad(alice), MetaTxLib.pad(exec), address(target), cd, FEE);
        bytes memory a = _ecdsa(ALICE_PK, _digest(address(tok), UA_RELAY_FEE, u, address(router)));
        vm.expectRevert(MtxRelayFee.RelayFeeShape.selector);
        vm.prank(REL);
        _usend(u, cd, a);
        assertEq(target.count(bob), 0);
        _relay(cd, _pay(PAYEE, address(target), cd, FEE));
        assertEq(tok.balanceOf(PAYEE), FEE);
    }

    /// `test_relayFeeDirectCallRefused`: `msg.sender != relayer`. Signed for the router, sent straight to the token by any
    /// other caller, the token hashes that caller as `relayer` and the signature fails; from the router the same words pass.
    /// ua-mtx-merge T2: the native half is the one entry on ids (was the address `mtxRelayFee`).
    function test_relayFeeDirectCallRefused() public {
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        Pay memory t = _pay(PAYEE, address(target), cd, FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxRelayFee(t.from, t.tgt, t.cdh, t.to, FEE, t.batch, t.nonce, t.validUntil, _n(s));
        Pay memory u = _upay(MetaTxLib.pad(alice), MetaTxLib.pad(PAYEE), address(target), cd, FEE);
        IUARegistry.UASig memory a;
        a.signature = _ecdsa(ALICE_PK, _digest(address(tok), UA_RELAY_FEE, u, address(router)));
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxRelayFee(u.from, u.tgt, u.cdh, u.to, FEE, u.batch, u.nonce, u.validUntil, a);
        assertEq(tok.balanceOf(PAYEE), 0);
        vm.prank(address(router));
        tok.mtxRelayFee(t.from, t.tgt, t.cdh, t.to, FEE, t.batch, t.nonce, t.validUntil, _n(s));
        assertEq(tok.balanceOf(PAYEE), FEE);
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), t.batch), 1);
        // the UA half's control: another call bytes, so another lane (`pad(alice)` shares the one spent above); from the router it passes
        u = _upay(MetaTxLib.pad(alice), MetaTxLib.pad(PAYEE), address(target), bytes.concat(cd, hex"00"), FEE);
        a.signature = _ecdsa(ALICE_PK, _digest(address(tok), UA_RELAY_FEE, u, address(router)));
        vm.prank(address(router));
        tok.mtxRelayFee(u.from, u.tgt, u.cdh, u.to, FEE, u.batch, u.nonce, u.validUntil, a);
        assertEq(tok.balanceOf(PAYEE), 2 * FEE);
    }

    /// `test_relayFeeTyped`: the wallet's JSON digest settles through the router in open mode (+UA): lane `payLane(ref)`,
    /// nonce 0, relayer = the router; the lane is spent, the events carry `ref`.
    function test_relayFeeTyped() public {
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        Pay memory t = _pay(address(router), address(target), cd, FEE);
        // ua-mtx-merge T2 (R28): the wallet shows `UARelayFee`, `from` and `payee` as ids
        string memory m = string.concat('"from":', h(t.from), ',"target":', a_(address(target)), ',"callDataHash":', h(t.cdh),
            ',"payee":', h(t.to), ',"value":', n(FEE), ',"batch":', n(t.batch), ',"nonce":', n(t.nonce), ',"validUntil":',
            n(t.validUntil), ',"relayer":', a_(address(router)));
        bytes32 wallet = vm.eip712HashTypedData(string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},',
            '{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"},{"name":"salt","type":"bytes32"}],',
            '"UARelayFee":[{"name":"from","type":"bytes32"},{"name":"target","type":"address"},{"name":"callDataHash","type":"bytes32"},',
            '{"name":"payee","type":"bytes32"},{"name":"value","type":"uint256"},{"name":"batch","type":"uint256"},',
            '{"name":"nonce","type":"uint256"},{"name":"validUntil","type":"uint256"},',
            '{"name":"relayer","type":"address"}]},"primaryType":"UARelayFee","domain":', domainJson(address(tok)), ',"message":{', m, '}}'));
        assertEq(wallet, _d(t), "the wallet's digest");
        assertEq(t.batch, RF_LANE); // pay-meta-tax T38 (O4): the payer's own lane, no `payLane(ref)`
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), t.batch), 0);
        vm.expectEmit(address(tok));
        emit IUALedger.UAMetaTransactionExecuted(MetaTxLib.pad(alice), address(router), t.batch, 0, wallet, address(router), 0);
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), MetaTxLib.pad(alice), MetaTxLib.pad(REL), FEE);
        _relay(cd, t);
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), t.batch), 1, "nonce 0 of the lane");
        assertEq(tok.balanceOf(REL), FEE);
        assertEq(tok.balanceOf(address(router)), 0);

        bytes memory cd2 = _call(1, address(0));
        Pay memory u = _upay(MetaTxLib.pad(alice), MetaTxLib.pad(address(router)), address(target), cd2, FEE);
        bytes memory au = _ecdsa(ALICE_PK, _digest(address(tok), UA_RELAY_FEE, u, address(router)));
        vm.prank(REL);
        _usend(u, cd2, au);
        assertEq(tok.mtxNonce(u.from, u.batch), 2, "the same lane, its next nonce");
        assertEq(tok.balanceOf(REL), 2 * FEE);
    }

    /// The router's calldata of the rows of `typed_ops.json` run at the rows' addresses: router, target, the payer funded.
    /// ua-mtx-merge T2, meaning: the `RelayFee` row's address `relay` has no entry left; the `UARelayFee` row's call is
    /// `relay` on ids. T11 (MD-7): the `UARelayFee` row names `relay` itself and runs verbatim; the retired `RelayFee` row is
    /// read from `TYPED_OPS_LEGACY`.
    function test_relayFeeRows() public {
        // pay-meta-tax T41: the `UARelayFee` row signs the struct with `batch` / `nonce` (the payer's own lane) and its router
        // call is the ten-argument `relay`; it runs verbatim, the signature re-made under `tok`'s domain
        string memory j = vm.readFile(TYPED_OPS);
        address at = vm.parseJsonAddress(j, domainField("UARelayFee", "token", "router"));
        deployCodeTo("MtxRelayFee.sol:MtxRelayFee", at);
        address tgt = vm.parseJsonAddress(j, msgField("UARelayFee", "target"));
        vm.etch(tgt, hex"00");
        address payer = vm.parseJsonAddress(j, ".key.address");
        tok.mint(payer, 1_000);
        _relayFeeRowHasNoEntry(vm.readFile(TYPED_OPS_LEGACY), at);
        string memory op = "UARelayFee";
        checkRow(j, op, "token");
        bytes memory cd = vm.parseJsonBytes(j, domainField(op, "token", "routerCalldata"));
        assertEq(bytes4(cd), MtxRelayFee.relay.selector, "the row names the router's relay on ids");
        bytes memory rowSig = vm.parseJsonBytes(j, domainField(op, "token", "signature"));
        assertEq(keccak256(vm.parseJsonBytes(j, domainField(op, "token", "relayedCall"))), vm.parseJsonBytes32(j, msgField(op, "callDataHash")));
        bytes memory sig = onChain(j, op, address(tok));
        uint256 w = find(cd, rowSig);
        for (uint256 k; k < 65; ++k) cd[w + k] = sig[k];
        // the row's token is its own address: the call goes to `tok`
        bytes memory tokWord = abi.encode(vm.parseJsonAddress(j, domainField(op, "token", "domain.verifyingContract")));
        w = find(cd, tokWord);
        bytes memory real = abi.encode(address(tok));
        for (uint256 k; k < 32; ++k) cd[w + k] = real[k];
        vm.prank(REL);
        (bool ok, bytes memory ret) = at.call(cd);
        assertTrue(ok, vm.toString(ret));
        assertEq(tok.balanceOf(REL), FEE, "open mode");
    }

    function _relayFeeRowHasNoEntry(string memory j, address at) internal {
        checkRow(j, "RelayFee", "token");
        vm.prank(REL);
        (bool ok, bytes memory ret) = at.call(vm.parseJsonBytes(j, domainField("RelayFee", "token", "routerCalldata")));
        assertFalse(ok, "the address relay has no entry");
        assertEq(ret.length, 0);
    }

    /// A payment that fails after a successful target call rolls the call back (a wrong signature: the counter stays
    /// 0); the same signature against a second real token fails (another domain) and moves nothing there.
    function test_relay_paymentFailureRollsBackCall() public {
        bytes memory cd = _call(0, address(0));
        Pay memory t = _pay(address(router), address(target), cd, FEE);
        bytes memory bad = _ecdsa(BOB_PK, _d(t));
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _send(t, cd, address(tok), bad);
        assertEq(target.count(bob), 0, "the call rolled back");
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), t.batch), 0);

        NormalToken tok2 = NormalToken(Clones.clone(address(new NormalToken(1,
            plainEnv(address(this), address(0), PQZ_UID, address(reg), false), ""))));
        tok2.initialize(address(this), 1, abi.encode(normalInit("Other", "OTH", 6, 1_000_000, alice, address(this))));
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _send(t, cd, address(tok2), s);
        assertEq(tok2.balanceOf(alice), 1_000_000);
        assertEq(target.count(bob), 0);
    }

    /// The executor: created by the router (CREATE, nonce 1), names it, refuses every other caller.
    function test_executor_onlyRouter() public {
        assertEq(exec, vm.computeCreateAddress(address(router), 1));
        assertEq(MtxRelayExecutor(exec).ROUTER(), address(router));
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        vm.prank(REL);
        vm.expectRevert(MtxRelayExecutor.NotRouter.selector);
        MtxRelayExecutor(exec).exec(address(target), cd);
        vm.expectRevert(MtxRelayExecutor.NotRouter.selector);
        MtxRelayExecutor(exec).exec(address(target), cd);
        vm.prank(address(router));
        MtxRelayExecutor(exec).exec(address(target), cd);
    }

    /// After an open-mode `relay` (a native payer, then a derived one) neither the router nor the executor holds anything.
    function test_router_holdsNothingAfterOpenMode() public {
        bytes memory cd = _call(0, address(0));
        _relay(cd, _pay(address(router), address(target), cd, FEE));
        cd = _call(1, address(0));
        Pay memory u = _upay(ml, MetaTxLib.pad(address(router)), address(target), cd, FEE);
        vm.prank(REL);
        _usend(u, cd, _mlAuth());
        assertEq(tok.balanceOf(address(router)), 0);
        assertEq(tok.balanceOf(exec), 0);
        assertEq(tok.balanceOfUA(MetaTxLib.pad(address(router))), 0);
        assertEq(address(router).balance, 0);
        assertEq(exec.balance, 0);
        assertEq(tok.balanceOf(REL), 2 * FEE);
    }

    /// A target that is a SCaaS entry with its own envelope works when the envelope binds its relayer to the executor
    /// (the open case is every other test); bound to the router it fails: the target sees the executor.
    function test_relay_targetEnvelopeBoundToExecutor() public {
        bytes memory cd = _call(0, exec);
        _relay(cd, _pay(address(router), address(target), cd, FEE));
        assertEq(target.count(bob), 1);
        cd = _call(1, address(router));
        Pay memory t = _pay(address(router), address(target), cd, FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, address(router), exec));
        _send(t, cd, address(tok), s);
    }

    /// Relay gas, logged (spec §7.1; CTR-MTX-27's estimate ≈ +200–230 k on Amsterdam with an ECDSA payer): the bare
    /// call (`mtxExecute` by the relayer), `relay` with an ECDSA payer (open mode, bound payee) and `relay` with an
    /// `mldsa65` payer (the precompile at its EIP-8051 price, 68,006, as `MtxSplitOverhead.t.sol`), each from the same
    /// state (snapshots), each its own transaction (`isolate`): regular / state (EIP-8037) gas.
    function test_relayGas_ecdsaAndMldsa65() public {
        vm.clearMockedCalls();
        vm.etch(ML65, address(new GasBurner(68_006 - 2_900)).code);
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        uint256 snap = vm.snapshotState();
        vm.prank(REL);
        (bool ok,) = address(target).call(cd);
        assertTrue(ok);
        (uint256 bare, uint256 bareSt) = _last("bare call (mtxExecute, bump)");
        vm.revertToState(snap);
        uint256 eo = _gasRelay(cd, _pay(address(router), address(target), cd, FEE), "relay, ECDSA payer, open mode");
        vm.revertToState(snap);
        uint256 eb = _gasRelay(cd, _pay(PAYEE, address(target), cd, FEE), "relay, ECDSA payer, bound payee");
        vm.revertToState(snap);
        Pay memory u = _upay(ml, MetaTxLib.pad(address(router)), address(target), cd, FEE);
        bytes memory au = _mlAuth();
        vm.prank(REL);
        _usend(u, cd, au);
        (uint256 mo,) = _last("relay, mldsa65 payer, open mode");
        console2.log("overhead over the bare call (regular): ECDSA open / ECDSA bound / mldsa65 open", eo - bare,
            eb - bare, mo - bare);
        console2.log("bare call state gas", bareSt);
        assertGt(mo, eo, "a PQ payer costs more");
    }

    function _gasRelay(bytes memory cd, Pay memory t, string memory what)
        internal returns (uint256 g)
    {
        bytes memory s = _sig(t);
        vm.prank(REL);
        _send(t, cd, address(tok), s);
        (g,) = _last(what);
    }

    function _last(string memory what) internal view returns (uint256 reg_, uint256 st) {
        Vm.Gas memory g = vm.lastCallGas();
        reg_ = g.gasTotalUsed;
        st = uint256(int256(g.gasStateUsed));
        console2.log(string.concat(what, " gas: regular / state / total"), reg_, st, reg_ + st);
    }

    /// `DeployBase` deploys the router by CREATE2 (`mtx_relay_fee`) and records its executor (`mtx_relay_executor`).
    function test_deployBase_relayFee() public {
        vm.chainId(31337);
        bytes32 uid = keccak256("scaas.t9.deploy");
        DeployHarness h = new DeployHarness();
        (, string memory json) = h.deploy(uid, false, new SmartKeyAccountFactory(uid).IMPLEMENTATION());
        address r = vm.parseJsonAddress(json, ".mtx_relay_fee");
        address e = vm.parseJsonAddress(json, ".mtx_relay_executor");
        assertEq(r, vm.computeCreate2Address(keccak256("scaas.deploy.v1"), keccak256(type(MtxRelayFee).creationCode),
            address(h)));
        assertEq(MtxRelayFee(r).EXECUTOR(), e);
        assertEq(MtxRelayExecutor(e).ROUTER(), r);
        assertGt(e.code.length, 0);
    }

    // ------------------------------------------------------------------ pay-meta-tax T38 (spec §4, O4): free lanes

    /// The typehash, old -> new: `batch` and `nonce` after `value`.
    function test_UARelayFeeTypehashIsPinned() public pure {
        assertEq(UA_RELAY_FEE_OLD, 0x77fa32c7a04e129e629d66b3803094553841c76b1ba094fa75566d16cd3eb54d, "old");
        assertEq(UA_RELAY_FEE, 0x220269b9987739caf1274adfea8055b107d8e0a4b237683de5b13ae493e43ea5, "new");
    }

    /// A signature on a nonce the lane has passed (or not reached) is refused by the nonce; the current one pays.
    function test_relayFee_staleNonce() public {
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        Pay memory t = _pay(address(router), address(target), cd, FEE);
        Pay memory ahead = _pay(address(router), address(target), cd, FEE); // a copy: memory structs alias
        ahead.nonce = t.nonce + 1;
        bytes memory sa = _sig(ahead);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, t.nonce, ahead.nonce));
        _send(ahead, cd, address(tok), sa);
        _relay(cd, t);
        bytes memory st = _sig(t);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, t.nonce + 1, t.nonce));
        _send(t, cd, address(tok), st); // stale: the lane moved on
        assertEq(tok.balanceOf(REL), FEE);
    }

    /// A signature over the old struct (no `batch`, no `nonce`) does not verify.
    function test_relayFee_oldTypehashRefused() public {
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        Pay memory t = _pay(address(router), address(target), cd, FEE);
        bytes memory old = _ecdsa(ALICE_PK, keccak256(abi.encodePacked(hex"1901", domainOf(address(tok)), keccak256(
            abi.encode(UA_RELAY_FEE_OLD, t.from, t.tgt, t.cdh, t.to, t.value, t.validUntil, address(router))))));
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _send(t, cd, address(tok), old);
        _relay(cd, t); // control
        assertEq(tok.balanceOf(REL), FEE);
    }

    /// The payer dedicates lane `RF_LANE` to relay fees: two calls paid on it in order, its other lanes untouched.
    function test_relayFee_dedicatedLane() public {
        _relay(abi.encodeCall(MtxRegistryMock.whoAmI, ()),
            _pay(address(router), address(target), abi.encodeCall(MtxRegistryMock.whoAmI, ()), FEE));
        bytes memory cd2 = abi.encodeWithSignature("count(address)", bob);
        _relay(cd2, _pay(address(router), address(target), cd2, FEE));
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), RF_LANE), 2);
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), 0), 0);
        assertEq(tok.balanceOf(REL), 2 * FEE);
    }

    /// O4: the contract does not stop paying twice for one call: two signatures (nonces 0 and 1) for a repeatable call
    /// both pay; the same `ref`.
    function test_relayFee_twoSignaturesReplayableTargetPaysTwice() public {
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        _relay(cd, _pay(address(router), address(target), cd, FEE));
        _relay(cd, _pay(address(router), address(target), cd, FEE));
        assertEq(tok.balanceOf(REL), 2 * FEE);
    }

    /// A target with its own nonce: the second signature for the same call reverts in the target, and pays nothing.
    function test_relayFee_guardedTargetSecondReverts() public {
        bytes memory cd = _call(0, address(0)); // bob's signed `bump(1)` at his nonce 0
        _relay(cd, _pay(address(router), address(target), cd, FEE));
        Pay memory again = _pay(address(router), address(target), cd, FEE);
        bytes memory s = _sig(again);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0)); // bob's nonce, in the target
        _send(again, cd, address(tok), s);
        assertEq(tok.balanceOf(REL), FEE);
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), RF_LANE), 1);
    }

}
