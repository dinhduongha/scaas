// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

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

/// A token stand-in whose `mtxExecuteTransfer` calls back into the router (the router does not check the token).
contract ReenterToken {
    address internal router;
    bytes internal data;

    function arm(address r, bytes calldata d) external {
        (router, data) = (r, d);
    }

    function mtxExecuteTransfer(MetaTxLib.MetaTransfer calldata, bytes calldata) external returns (bool) {
        (bool ok, bytes memory ret) = router.call(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        return true;
    }
}

/// @notice CTR-MTX-27 (metatx split T9, spec §7.1, R14): `MtxRelayFee` runs a fee-less call through its executor, then the
///         payer's router-bound payment (`entryRef = relayRef(target, callData)`, lane `payLane(ref)`, nonce 0, relayer =
///         router, fee `NONE`), atomically. Token: a `NORMAL` clone on a gen-1 `UARegistry` with `mldsa65` (the precompile
///         mocked, filler signatures, `PqzRegistryBase`); target: a `MetaTxBase` contract (`MtxRegistryMock`, fee `NONE`)
///         whose `mtxExecute` carries bob's own signature. Payers: alice (ECDSA, address path) and an `mldsa65` UA.
contract MtxRelayFeeTest is PqzRegistryBase {
    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant BOB_PK = 0xB0B;
    address internal constant REL = address(0xBEEF);
    address internal constant PAYEE = address(0xB0B5);
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint256 internal constant FEE = 25;

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
        return abi.encodeCall(IMetaTx.mtxExecute, (m, _ecdsa(BOB_PK, target.mtxDigest(m))));
    }

    function _ref(address t, bytes memory cd) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.relayfee", block.chainid, t, keccak256(cd)));
    }

    /// alice's router-bound payment of `value` to `to` for `ref`.
    function _pay(address to, bytes32 ref, uint256 value) internal view returns (MetaTxLib.MetaTransfer memory) {
        return MetaTxLib.MetaTransfer(alice, to, value, ref, tok.payLane(ref), 0, block.timestamp + 300, RR,
            address(router), 0, address(0));
    }

    function _sig(MetaTxLib.MetaTransfer memory t) internal view returns (bytes memory) {
        return _ecdsa(ALICE_PK, tok.mtxTransferDigest(t));
    }

    function _upay(bytes32 from, bytes32 to, bytes32 ref, uint256 value)
        internal view returns (MetaTxLib.UAMetaTransfer memory)
    {
        return MetaTxLib.UAMetaTransfer(from, to, value, ref, tok.payLane(ref), 0, block.timestamp + 300, RR,
            address(router), 0, address(0));
    }

    function _relay(bytes memory cd, MetaTxLib.MetaTransfer memory t) internal {
        bytes memory s = _sig(t);
        vm.prank(REL);
        router.relay(address(target), cd, address(tok), t, s);
    }

    function _shape(MetaTxLib.MetaTransfer memory t, bytes memory cd) internal {
        vm.expectRevert(MtxRelayFee.RelayFeeShape.selector);
        vm.prank(REL);
        router.relay(address(target), cd, address(tok), t, "");
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

    /// (1) a payment bound to another target, other call bytes or another chain is refused.
    function test_relay_boundToCall() public {
        bytes memory cd = _call(0, address(0));
        MetaTxLib.MetaTransfer memory t = _pay(address(router), _ref(address(target), cd), FEE);
        bytes memory s = _sig(t);
        MtxRegistryMock other = new MtxRegistryMock("SCaaS TestRegistry", PQZ_UID);
        vm.prank(REL);
        vm.expectRevert(MtxRelayFee.RelayFeeShape.selector);
        router.relay(address(other), cd, address(tok), t, s); // another target
        bytes memory cd1 = _call(1, address(0));
        vm.prank(REL);
        vm.expectRevert(MtxRelayFee.RelayFeeShape.selector);
        router.relay(address(target), cd1, address(tok), t, s); // other call bytes
        vm.chainId(1);
        vm.prank(REL);
        vm.expectRevert(MtxRelayFee.RelayFeeShape.selector);
        router.relay(address(target), cd, address(tok), t, s); // another chain
        vm.chainId(7622);
        _relay(cd, t);
        assertEq(target.count(bob), 1);
    }

    /// (2) Review Focus 3: a router-bound payment never settles any other way: the same `t, sig` (and the UA twin)
    ///     straight to every typed entry of the token is refused by the relayer binding.
    function test_routerBoundPayment_refusedOutsideRouter() public {
        bytes32 ref = _ref(address(target), _call(0, address(0)));
        MetaTxLib.MetaTransfer memory t = _pay(address(router), ref, FEE);
        bytes memory s = _sig(t);
        bytes memory bad = abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, address(router), REL);
        vm.prank(REL);
        vm.expectRevert(bad);
        tok.mtxExecuteTransfer(t, s);
        MetaTxLib.MetaTransfer[] memory ts = new MetaTxLib.MetaTransfer[](1);
        bytes[] memory ss = new bytes[](1);
        (ts[0], ss[0]) = (t, s);
        vm.prank(REL);
        vm.expectRevert(bad);
        tok.mtxBatchTransfer(ts, ss);
        vm.prank(REL);
        vm.expectRevert(bad);
        tok.mtxPay(alice, address(router), FEE, ref, t.validUntil, RR, address(router), 0, address(0), s);
        MetaTxLib.UAMetaTransfer memory u = _upay(ml, MetaTxLib.pad(address(router)), ref, FEE);
        vm.prank(REL);
        vm.expectRevert(bad);
        tok.uaExecuteTransfer(u, _mlAuth());
        vm.prank(REL);
        vm.expectRevert(bad);
        tok.uaPay(ml, u.to, FEE, ref, u.validUntil, RR, address(router), 0, address(0), _mlAuth());
        assertEq(tok.mtxNonce(alice, t.batch), 0);
    }

    /// (3) a `callData` that executes another router-bound payment through the executor fails: the token sees the
    ///     executor, not its bound relayer.
    function test_relay_callDataIsAnotherRouterPayment() public {
        MetaTxLib.MetaTransfer memory inner = _pay(REL, _ref(address(target), _call(0, address(0))), 500);
        bytes memory cd = abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (inner, _sig(inner)));
        MetaTxLib.MetaTransfer memory t = _pay(address(router), _ref(address(tok), cd), FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, address(router), exec));
        router.relay(address(tok), cd, address(tok), t, s);
    }

    /// (4) a target revert leaves no payment: the inner revert data bubbles, nothing moved, the pay lane unused.
    function test_relay_innerRevertBubbles() public {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(bob, abi.encodeCall(MtxRegistryMock.bump, (0)), 0,
            0, block.timestamp + 300, 0, address(0), 0, address(0));
        bytes memory cd = abi.encodeCall(IMetaTx.mtxExecute, (m, _ecdsa(BOB_PK, target.mtxDigest(m))));
        MetaTxLib.MetaTransfer memory t = _pay(address(router), _ref(address(target), cd), FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(MtxRegistryMock.ZeroBump.selector);
        router.relay(address(target), cd, address(tok), t, s);
        assertEq(tok.balanceOf(alice), 1_000_000);
        assertEq(tok.balanceOf(REL), 0);
        assertEq(tok.mtxNonce(alice, t.batch), 0);
    }

    /// (5) a second `relay` with the same `ref` fails at the pay lane (a repeatable call: an unguarded view).
    function test_relay_payOnce() public {
        bytes memory cd = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        MetaTxLib.MetaTransfer memory t = _pay(address(router), _ref(address(target), cd), FEE);
        _relay(cd, t);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        router.relay(address(target), cd, address(tok), t, s);
        assertEq(tok.balanceOf(REL), FEE);
    }

    /// (6a) open mode (`t.to == router`): the router forwards `t.value` to `msg.sender`.
    function test_relay_openModePaysCaller() public {
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        MetaTxLib.MetaTransfer memory t = _pay(address(router), ref, FEE);
        bytes memory s = _sig(t);
        vm.expectEmit(address(tok));
        emit IERC20Payment.PaymentSettled(alice, address(router), FEE, 0, address(router), ref); // fee 0: feeTo = the relayer
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), MetaTxLib.pad(alice), MetaTxLib.pad(REL), FEE);
        vm.prank(REL);
        router.relay(address(target), cd, address(tok), t, s);
        assertEq(target.count(bob), 1, "the call ran");
        assertEq(tok.balanceOf(REL), FEE);
        assertEq(tok.balanceOf(alice), 1_000_000 - FEE);
        assertEq(tok.mtxNonce(alice, t.batch), 1);
    }

    /// (6b) a bound payee is paid directly; the submitting relayer gets nothing, the router forwards nothing.
    function test_relay_boundPayee() public {
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        MetaTxLib.MetaTransfer memory t = _pay(PAYEE, ref, FEE);
        bytes memory s = _sig(t);
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), MetaTxLib.pad(alice), MetaTxLib.pad(PAYEE), FEE);
        vm.prank(REL);
        router.relay(address(target), cd, address(tok), t, s);
        assertEq(tok.balanceOf(PAYEE), FEE);
        assertEq(tok.balanceOf(REL), 0);
        assertEq(tok.balanceOf(address(router)), 0);
    }

    /// (7) a UA payer works through `uaRelay`: an `mldsa65` UA (open mode: its ledger to the relayer's public balance;
    ///     a bound native payee; a bound derived payee, the event `payee` its id) and a native id (ECDSA).
    function test_uaRelay_mldsa65Payer() public {
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        MetaTxLib.UAMetaTransfer memory u = _upay(ml, MetaTxLib.pad(address(router)), ref, FEE);
        vm.expectEmit(address(tok));
        emit IUALedger.UAPaymentSettled(ml, u.to, FEE, 0, address(router), ref);
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), ml, MetaTxLib.pad(REL), FEE);
        vm.prank(REL);
        router.uaRelay(address(target), cd, address(tok), u, _mlAuth());
        assertEq(tok.balanceOfUA(ml), 1_000 - FEE);
        assertEq(tok.balanceOf(REL), FEE);
        assertEq(target.count(bob), 1);

        cd = _call(1, address(0));
        ref = _ref(address(target), cd);
        u = _upay(ml, MetaTxLib.pad(PAYEE), ref, FEE);
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), ml, MetaTxLib.pad(PAYEE), FEE);
        vm.prank(REL);
        router.uaRelay(address(target), cd, address(tok), u, _mlAuth());
        assertEq(tok.balanceOf(PAYEE), FEE);

        bytes32 ml2 = _mldsaUA(8);
        cd = _call(2, address(0));
        ref = _ref(address(target), cd);
        u = _upay(ml, ml2, ref, FEE);
        vm.expectEmit(address(router));
        emit MtxRelayFee.RelayFeePaid(ref, address(target), address(tok), ml, ml2, FEE);
        vm.prank(REL);
        router.uaRelay(address(target), cd, address(tok), u, _mlAuth());
        assertEq(tok.balanceOfUA(ml2), FEE);

        cd = _call(3, address(0));
        ref = _ref(address(target), cd);
        u = _upay(MetaTxLib.pad(alice), MetaTxLib.pad(address(router)), ref, FEE);
        bytes memory a = _ecdsa(ALICE_PK, tok.uaTransferDigest(u));
        vm.prank(REL);
        router.uaRelay(address(target), cd, address(tok), u, a);
        assertEq(tok.balanceOf(REL), 2 * FEE);
        assertEq(tok.balanceOfUA(ml), 1_000 - 3 * FEE);
        assertEq(target.count(bob), 4);
    }

    /// (8) re-entry into the router is refused: from the target call (the executor calls `relay`) and from a token.
    function test_relay_reentryRefused() public {
        bytes4 reentry = bytes4(keccak256("ReentrancyGuardReentrantCall()"));
        bytes memory cd0 = _call(0, address(0));
        MetaTxLib.MetaTransfer memory ti = _pay(address(router), _ref(address(target), cd0), FEE);
        bytes memory cd = abi.encodeCall(MtxRelayFee.relay, (address(target), cd0, address(tok), ti, _sig(ti)));
        MetaTxLib.MetaTransfer memory t = _pay(address(router), _ref(address(router), cd), FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(reentry);
        router.relay(address(router), cd, address(tok), t, s);

        ReenterToken rt = new ReenterToken();
        rt.arm(address(router), abi.encodeCall(MtxRelayFee.relay, (address(target), cd0, address(tok), ti, _sig(ti))));
        bytes memory cd1 = abi.encodeCall(MtxRegistryMock.whoAmI, ());
        MetaTxLib.MetaTransfer memory t1 = _pay(address(router), _ref(address(target), cd1), FEE);
        vm.prank(REL);
        vm.expectRevert(reentry);
        router.relay(address(target), cd1, address(rt), t1, "");
    }

    // ------------------------------------------------------------------ extra (spec §7.1)

    /// Every shape outside CTR-MTX-27 step 2 is refused before any call.
    function test_relay_shapeRefused() public {
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        MetaTxLib.MetaTransfer memory t = _pay(address(router), ref, FEE);
        t.entryRef = bytes32(uint256(ref) ^ 1);
        _shape(t, cd); // wrong entryRef (its own lane)
        t = _pay(address(router), ref, FEE);
        t.batch += 1;
        _shape(t, cd); // batch != payLane(ref)
        t = _pay(address(router), ref, FEE);
        t.nonce = 1;
        _shape(t, cd);
        t = _pay(address(router), ref, FEE);
        t.mode = 0;
        _shape(t, cd); // relayer not bound
        t = _pay(address(router), ref, FEE);
        t.relayer = REL;
        _shape(t, cd); // bound, not the router
        t.relayer = exec;
        _shape(t, cd); // bound to the executor
        t = _pay(address(router), ref, FEE);
        t.mode = RR | MetaTxLib.MODE_FEE_FIXED;
        t.fee = 1;
        _shape(t, cd); // fee mode not NONE
        t.fee = 0;
        _shape(t, cd);
        t = _pay(address(router), ref, FEE);
        t.fee = 1;
        _shape(t, cd); // fee != 0
        MetaTxLib.UAMetaTransfer memory u = _upay(ml, MetaTxLib.pad(address(router)), ref, FEE);
        u.nonce = 1;
        vm.expectRevert(MtxRelayFee.RelayFeeShape.selector);
        vm.prank(REL);
        router.uaRelay(address(target), cd, address(tok), u, "");
        u = _upay(ml, MetaTxLib.pad(address(router)), ref, FEE);
        u.relayer = REL;
        vm.expectRevert(MtxRelayFee.RelayFeeShape.selector);
        vm.prank(REL);
        router.uaRelay(address(target), cd, address(tok), u, "");
        assertEq(target.count(bob), 0);
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
        MetaTxLib.MetaTransfer memory t = _pay(address(router), _ref(pred, cd), FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(MtxRelayFee.RelayTargetNoCode.selector, pred));
        router.relay(pred, cd, address(tok), t, s);
        assertEq(tok.mtxNonce(alice, t.batch), 0, "the lane is not burnt");
        assertEq(address(new MtxRegistryMock{salt: salt}("SCaaS TestRegistry", PQZ_UID)), pred);
        vm.prank(REL);
        router.relay(pred, cd, address(tok), t, s);
        assertEq(tok.balanceOf(REL), FEE);
        address[2] memory empty = [address(0xE0A), address(1)]; // an EOA, the ecrecover precompile
        for (uint256 i; i < 2; ++i) {
            t = _pay(address(router), _ref(empty[i], cd), FEE);
            vm.prank(REL);
            vm.expectRevert(abi.encodeWithSelector(MtxRelayFee.RelayTargetNoCode.selector, empty[i]));
            router.relay(empty[i], cd, address(tok), t, "");
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
            MetaTxLib.MetaTransfer memory t = _pay(address(router), _ref(d, cd), FEE);
            bytes memory s = _sig(t);
            vm.prank(REL);
            vm.expectRevert(abi.encodeWithSelector(MtxRelayFee.RelayTargetNoCode.selector, d));
            router.relay(d, cd, address(tok), t, s);
            assertEq(tok.mtxNonce(alice, t.batch), 0, "the lane is not burnt");
        }
    }

    /// Never pay the executor (controller call 2026-10-27): `t.to == executor` (UA: `pad(executor)`) is refused.
    function test_relay_payeeExecutorRefused() public {
        bytes memory cd = _call(0, address(0));
        bytes32 ref = _ref(address(target), cd);
        _shape(_pay(exec, ref, FEE), cd);
        MetaTxLib.UAMetaTransfer memory u = _upay(ml, MetaTxLib.pad(exec), ref, FEE);
        vm.expectRevert(MtxRelayFee.RelayFeeShape.selector);
        vm.prank(REL);
        router.uaRelay(address(target), cd, address(tok), u, "");
    }

    /// A payment that fails after a successful target call rolls the call back (a wrong signature: the counter stays
    /// 0); the same `t, sig` against a second real token fails (another domain) and moves nothing there.
    function test_relay_paymentFailureRollsBackCall() public {
        bytes memory cd = _call(0, address(0));
        MetaTxLib.MetaTransfer memory t = _pay(address(router), _ref(address(target), cd), FEE);
        bytes memory bad = _ecdsa(BOB_PK, tok.mtxTransferDigest(t));
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        router.relay(address(target), cd, address(tok), t, bad);
        assertEq(target.count(bob), 0, "the call rolled back");
        assertEq(tok.mtxNonce(alice, t.batch), 0);

        NormalToken tok2 = NormalToken(Clones.clone(address(new NormalToken(1,
            plainEnv(address(this), address(0), PQZ_UID, address(reg), false), ""))));
        tok2.initialize(address(this), 1, abi.encode(normalInit("Other", "OTH", 6, 1_000_000, alice, address(this))));
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        router.relay(address(target), cd, address(tok2), t, s);
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

    /// After an open-mode `relay` / `uaRelay` neither the router nor the executor holds anything.
    function test_router_holdsNothingAfterOpenMode() public {
        bytes memory cd = _call(0, address(0));
        _relay(cd, _pay(address(router), _ref(address(target), cd), FEE));
        cd = _call(1, address(0));
        MetaTxLib.UAMetaTransfer memory u = _upay(ml, MetaTxLib.pad(address(router)), _ref(address(target), cd), FEE);
        vm.prank(REL);
        router.uaRelay(address(target), cd, address(tok), u, _mlAuth());
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
        _relay(cd, _pay(address(router), _ref(address(target), cd), FEE));
        assertEq(target.count(bob), 1);
        cd = _call(1, address(router));
        MetaTxLib.MetaTransfer memory t = _pay(address(router), _ref(address(target), cd), FEE);
        bytes memory s = _sig(t);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, address(router), exec));
        router.relay(address(target), cd, address(tok), t, s);
    }

    /// Relay gas, logged (spec §7.1; CTR-MTX-27's estimate ≈ +200–230 k on Amsterdam with an ECDSA payer): the bare
    /// call (`mtxExecute` by the relayer), `relay` with an ECDSA payer (open mode, bound payee) and `uaRelay` with an
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
        uint256 eo = _gasRelay(cd, _pay(address(router), ref, FEE), "relay, ECDSA payer, open mode");
        vm.revertToState(snap);
        uint256 eb = _gasRelay(cd, _pay(PAYEE, ref, FEE), "relay, ECDSA payer, bound payee");
        vm.revertToState(snap);
        MetaTxLib.UAMetaTransfer memory u = _upay(ml, MetaTxLib.pad(address(router)), ref, FEE);
        bytes memory au = _mlAuth();
        vm.prank(REL);
        router.uaRelay(address(target), cd, address(tok), u, au);
        (uint256 mo,) = _last("uaRelay, mldsa65 payer, open mode");
        console2.log("overhead over the bare call (regular): ECDSA open / ECDSA bound / mldsa65 open", eo - bare,
            eb - bare, mo - bare);
        console2.log("bare call state gas", bareSt);
        assertGt(mo, eo, "a PQ payer costs more");
    }

    function _gasRelay(bytes memory cd, MetaTxLib.MetaTransfer memory t, string memory what)
        internal returns (uint256 g)
    {
        bytes memory s = _sig(t);
        vm.prank(REL);
        router.relay(address(target), cd, address(tok), t, s);
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
}
