// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {Test, Vm} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {normalInit, wrappedInit, Rate} from "../v2/helpers/V2Fixture.sol";
import {IRig, KindRig, PlainRig, PqzRig, ZetherRig, Tk} from "../metatx/helpers/KindRigs.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// The merged entries of ua-mtx-merge T2 (spec §2.1, R1, R4, R20, R21, R27, R28), called by selector: this file compiles on
/// the tree before T2 too, so each test is red there on its own (plan T2 step 3).
interface IMergedT2 {
    function mtxTransfer(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, IUARegistry.UASig calldata auth) external returns (bool);
    function mtxTransferWithFee(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce,
        uint256 validUntil, uint32 mode, address relayer, uint256 fee, address feeRecipient,
        IUARegistry.UASig calldata auth) external returns (bool);
    // pay-meta-tax T37: the pay entries in their struct form with `PayMeta` last (`mtxPayMeta` in legacy/)
    function mtxPay(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth, MetaTxLib.PayMeta calldata meta)
        external returns (bool);
    function mtxPayReceiverFee(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata payerAuth, uint256 fee,
        address feeRecipient, uint256 rfValidUntil, IUARegistry.UASig calldata payeeAuth, MetaTxLib.PayMeta calldata meta)
        external returns (bool);
    function mtxExecuteTransfer(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth)
        external returns (bool);
    function mtxBatchTransfer(MetaTxLib.UAMetaTransfer[] calldata ts, IUARegistry.UASig[] calldata auths)
        external returns (bool);
    function mtxTransferDigest(MetaTxLib.UAMetaTransfer calldata t) external view returns (bytes32);
    function receiverFeeDigest(MetaTxLib.UAMetaTransfer calldata t, uint256 fee, address feeRecipient,
        uint256 validUntil) external view returns (bytes32);
}

/// `RelayFeeRouter.relay` on ids (R28: today's `uaRelay` under the name `relay`).
interface IRelayT2 {
    function relay(address target, bytes calldata callData, address token, bytes32 from, bytes32 payee, uint256 value,
        uint256 batch, uint256 nonce, uint256 validUntil, IUARegistry.UASig calldata auth) external;
}

/// The address `MetaTransfer` (R46: in legacy/ua-mtx-merge/ after T2), kept here to sign and encode the retired forms.
struct OldMetaTransfer {
    address from;
    address to;
    uint256 value;
    bytes32 entryRef;
    uint256 batch;
    uint256 nonce;
    uint256 validUntil;
    uint32 mode;
    address relayer;
    uint256 fee;
    address feeRecipient;
}

/// The retired address entries (invariant 3): after T2 no token or router serves these selectors.
interface IOldT2 {
    function mtxExecuteTransfer(OldMetaTransfer calldata t, bytes calldata signature) external returns (bool);
    function mtxBatchTransfer(OldMetaTransfer[] calldata ts, bytes[] calldata signatures) external returns (bool);
    function mtxTransfer(address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, bytes calldata signature) external returns (bool);
    function mtxPay(address from, address to, uint256 amount, bytes32 payId, uint256 validUntil, uint32 mode,
        address relayer, uint256 fee, address feeRecipient, bytes calldata signature) external returns (bool);
    function mtxPayReceiverFee(OldMetaTransfer calldata t, bytes calldata payerSig, uint256 fee, address feeRecipient,
        uint256 rfValidUntil, bytes calldata payeeSig) external returns (bool);
    function mtxRelayFee(address from, address target, bytes32 callDataHash, address payee, uint256 value,
        uint256 validUntil, bytes calldata sig) external;
    function relay(address target, bytes calldata callData, address token, address from, address payee, uint256 value,
        uint256 validUntil, bytes calldata sig) external;
    function uaRelay(address target, bytes calldata callData, address token, bytes32 from, bytes32 payee, uint256 value,
        uint256 validUntil, IUARegistry.UASig calldata auth) external;
}

/// A relay target that records what the payee held while it ran: the call runs before its fee (invariant 5).
contract RelayProbe {
    uint256 public seen;
    bool public ran;

    function poke(address token, address who) external {
        seen = IERC20(token).balanceOf(who);
        ran = true;
    }
}

/// A `NORMAL` kind with a stand-in regulated hook in `_update` only (CTR-GOV-17 is SPECIFIED, not built).
contract HookedNormal is NormalToken {
    uint256 public hits;

    constructor(address f) NormalToken(f, "") {}

    function _update(address from, address to, uint256 value) internal override {
        ++hits;
        super._update(from, to, value);
    }
}

/// T2: the transfer group (`mtxTransfer`, `mtxTransferWithFee`, `mtxExecuteTransfer`, `mtxBatchTransfer`), payments
/// (`mtxPay`, `mtxPayMeta`), receiver-pays (`mtxPayReceiverFee`) and the relay fee (`mtxRelayFee`, `RelayFeeRouter.relay`)
/// in today's `ua*` form under the `mtx*` name, on the six kinds of the parity rigs plus `NORMAL` and `WRAPPED` with no
/// registry. The signer of every rig is `0xA11CE`, an EOA that signs the `UA…` structs with its own key (B).
contract TransferGroupTest is Test {
    uint256 internal constant PK = 0xA11CE;
    uint256 internal constant PAYEE_PK = 0xC0FFEE; // holds nothing on any token: receiver-pays pays out of what it got
    address internal constant REL = address(0x7E1A);
    address internal constant FEE_TO = address(0xFEE5);
    bytes32 internal constant OLD_METATRANSFER_TYPEHASH = keccak256(
        "MetaTransfer(address from,address to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant OLD_RECEIVER_FEE_TYPEHASH = keccak256(
        "ReceiverFee(MetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)MetaTransfer(address from,address to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_RECEIVER_FEE_TYPEHASH = keccak256(
        "UAReceiverFee(UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant OLD_RELAY_FEE_TYPEHASH = keccak256(
        "RelayFee(address from,address target,bytes32 callDataHash,address payee,uint256 value,uint256 validUntil,address relayer)");
    // pay-meta-tax T38 (spec §4): `batch` and `nonce`, the payer's own lane
    bytes32 internal constant UA_RELAY_FEE_TYPEHASH = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)");
    uint256 internal constant RF_LANE = 31;

    address internal signer = vm.addr(PK);
    address internal payee = vm.addr(PAYEE_PK);
    bytes32 internal from;
    bytes32 internal to;
    Tk[] internal ks; // the seven rig tokens, then `WRAPPED` with no registry
    RelayFeeRouter internal router;
    RelayProbe internal probe;
    mapping(address => bool) internal _noCallSet; // registries already under `expectCall(…, 0)` (once per test)

    /// One `RelayFeeRouter.relay` call; a struct so the call's eight arguments come from memory, not the stack.
    struct RelayArgs {
        address t;
        bytes cd;
        bytes32 payee;
        uint256 value;
        uint256 batch;
        uint256 nonce;
        uint256 validUntil;
        IUARegistry.UASig auth;
    }

    /// The test plays the factory of its own clones: no token is registered, every leg is an outside leg.
    function isRegisteredToken(address) external pure returns (bool) { return false; }

    function setUp() public {
        IRig[3] memory rigs;
        PlainRig plain = new PlainRig();
        plain.init();
        rigs[0] = IRig(address(plain));
        PqzRig pqz = new PqzRig();
        pqz.init();
        rigs[1] = IRig(address(pqz));
        ZetherRig zeth = new ZetherRig();
        zeth.init();
        rigs[2] = IRig(address(zeth));
        for (uint256 r; r < 3; ++r) {
            (, address[] memory t,) = rigs[r].setup();
            for (uint256 i; i < t.length; ++i) ks.push(KindRig(address(rigs[r])).tkAt(i));
        }
        Tk memory off;
        off.kind = "WRAPPED_LEDGEROFF";
        off.t = _wrappedOff();
        off.pk = PK;
        off.signer = signer;
        off.style = 1;
        ks.push(off);
        assertEq(ks.length, 8, "six kinds, NORMAL and WRAPPED with no registry");
        for (uint256 i; i < ks.length; ++i) assertEq(ks[i].signer, signer, ks[i].kind);
        (from, to) = (MetaTxLib.pad(signer), MetaTxLib.pad(payee));
        router = new RelayFeeRouter();
        probe = new RelayProbe();
    }

    function _wrappedOff() internal returns (address w) {
        MockERC20 u = new MockERC20("U", "U", 6);
        w = EnvKit.clone(address(new WrappedToken(address(this), "")), EnvKit.env(bytes32(uint256(7)), address(0), address(0), false));
        address[] memory us = new address[](1);
        uint256[] memory one = new uint256[](1);
        (us[0], one[0]) = (address(u), 1);
        Rate memory r;
        WrappedToken(payable(w)).initialize(nid(address(this)), 1, abi.encode(wrappedInit(us, one, one, 6, r, address(0), address(0))));
        u.mint(signer, 10_000_000);
        vm.startPrank(signer);
        u.approve(w, 10_000_000);
        WrappedToken(payable(w)).wrap(10_000_000);
        vm.stopPrank();
        assertEq(MetaTokenBase(w).registry(), address(0));
    }

    // ------------------------------------------------------------------ helpers

    function _sig(uint256 pk, bytes32 d) internal pure returns (IUARegistry.UASig memory a) {
        a.signature = _raw(pk, d);
    }

    function _raw(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    /// A transfer at fee mode `NONE`, any relayer, on lane `lane` at its next nonce.
    function _x(address t, bytes32 f, bytes32 dst, uint256 v, uint256 lane)
        internal view returns (MetaTxLib.UAMetaTransfer memory x)
    {
        x.from = f;
        x.to = dst;
        x.value = v;
        x.batch = lane;
        x.nonce = MetaTokenBase(t).mtxNonce(f, lane);
        x.validUntil = block.timestamp + 600;
    }

    /// The signer's `UAMetaTransfer` digest in `t`'s domain, from the type string (not read from the token).
    function _d(address t, MetaTxLib.UAMetaTransfer memory x) internal view returns (bytes32) {
        return MtxDigest.typed(t, MetaTxLib.hashStruct(x));
    }

    /// The signer's `UASig` over `x`. Read before a cheatcode that targets the next call: the domain is an external
    /// read (`eip712Domain()`).
    function _s(address t, MetaTxLib.UAMetaTransfer memory x) internal view returns (IUARegistry.UASig memory) {
        return _sig(PK, _d(t, x));
    }

    /// The same transfer as the retired address `MetaTransfer` (the native ids unpadded).
    function _old(MetaTxLib.UAMetaTransfer memory x) internal pure returns (OldMetaTransfer memory o) {
        o.from = address(uint160(uint256(x.from)));
        o.to = address(uint160(uint256(x.to)));
        o.value = x.value;
        o.entryRef = x.entryRef;
        o.batch = x.batch;
        o.nonce = x.nonce;
        o.validUntil = x.validUntil;
        o.mode = x.mode;
        o.relayer = x.relayer;
        o.fee = x.fee;
        o.feeRecipient = x.feeRecipient;
    }

    function _oldHash(OldMetaTransfer memory o) internal pure returns (bytes32) {
        bytes memory head = abi.encode(OLD_METATRANSFER_TYPEHASH, o.from, o.to, o.value, o.entryRef, o.batch, o.nonce);
        return keccak256(bytes.concat(head, abi.encode(o.validUntil, o.mode,
            o.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 ? o.relayer : address(0), o.fee,
            o.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT != 0 ? o.feeRecipient : address(0))));
    }

    /// The signer's signature of the address `MetaTransfer` of `x`.
    function _oldSig(address t, MetaTxLib.UAMetaTransfer memory x) internal view returns (bytes memory) {
        return _raw(PK, MtxDigest.typed(t, _oldHash(_old(x))));
    }

    /// pay-meta-tax T37: a payment's `entryRef` is the commitment of `PayMetaKit.meta(seed)`; `seedOf` finds the seed.
    mapping(bytes32 entryRef => bytes32 seed) internal seedOf;

    function _payId(uint256 i) internal returns (bytes32 ref) {
        bytes32 seed = keccak256(abi.encode("t2.pay", i));
        ref = PayMetaKit.ref(seed);
        seedOf[ref] = seed;
    }

    /// The payment `mtxPay` builds: lane `payLane(payId)`, nonce 0, relayer `REL`.
    function _payX(address t, bytes32 payId, uint256 v, uint32 mode) internal view returns (MetaTxLib.UAMetaTransfer memory x) {
        x.from = from;
        x.to = to;
        x.value = v;
        x.entryRef = payId;
        x.batch = MetaTokenBase(t).payLane(payId);
        x.validUntil = block.timestamp + 600;
        x.mode = mode;
        x.relayer = REL;
    }

    function _transfer(address t, MetaTxLib.UAMetaTransfer memory x, IUARegistry.UASig memory s) internal returns (bool) {
        vm.prank(REL);
        return IMergedT2(t).mtxTransfer(x.from, x.to, x.value, x.batch, x.nonce, x.validUntil, x.mode, x.relayer, s);
    }

    function _transferWithFee(address t, MetaTxLib.UAMetaTransfer memory x, IUARegistry.UASig memory s)
        internal returns (bool)
    {
        vm.prank(REL);
        return IMergedT2(t).mtxTransferWithFee(x.from, x.to, x.value, x.batch, x.nonce, x.validUntil, x.mode, x.relayer,
            x.fee, x.feeRecipient, s);
    }

    function _pay(address t, MetaTxLib.UAMetaTransfer memory x) internal returns (bool) {
        return _payWith(t, x, _s(t, x));
    }

    function _payWith(address t, MetaTxLib.UAMetaTransfer memory x, IUARegistry.UASig memory s) internal returns (bool) {
        vm.prank(REL);
        return IMergedT2(t).mtxPay(x, s, PayMetaKit.meta(seedOf[x.entryRef]));
    }

    function _relayArgs(address t, uint256 v, bytes32 p) internal view returns (RelayArgs memory r) {
        r.t = t;
        r.cd = abi.encodeCall(RelayProbe.poke, (t, payee));
        r.payee = p;
        r.value = v;
        r.validUntil = block.timestamp + 600;
        (r.batch, r.nonce) = (RF_LANE, MetaTokenBase(t).mtxNonce(from, RF_LANE));
        r.auth = _sig(PK, MtxDigest.typed(t, _relayHash(UA_RELAY_FEE_TYPEHASH, from, r)));
    }

    /// `UARelayFee` (or the old `RelayFee`, ids padded) with the router as `relayer`.
    function _relayHash(bytes32 typehash, bytes32 f, RelayArgs memory r) internal view returns (bytes32) {
        if (typehash != UA_RELAY_FEE_TYPEHASH) {
            return keccak256(abi.encode(typehash, f, address(probe), keccak256(r.cd), r.payee, r.value, r.validUntil,
                address(router)));
        }
        return keccak256(abi.encode(typehash, f, address(probe), keccak256(r.cd), r.payee, r.value, r.batch, r.nonce,
            r.validUntil, address(router)));
    }

    function _relayWith(RelayArgs memory r) internal {
        vm.prank(REL);
        IRelayT2(address(router)).relay(address(probe), r.cd, r.t, from, r.payee, r.value, r.batch, r.nonce, r.validUntil,
            r.auth);
    }

    function _relay(address t, uint256 v, bytes32 p) internal {
        _relayWith(_relayArgs(t, v, p));
    }

    /// `pay`'s receiver-pays leg: `t.to = pad(payee)`, mode `RESTRICT_RELAYER` (fee `NONE`), lane `payLane`, nonce 0.
    function _rfLeg(address t, uint256 i, uint256 v) internal returns (MetaTxLib.UAMetaTransfer memory) {
        return _payX(t, _payId(1000 + i), v, MetaTxLib.MODE_RESTRICT_RELAYER);
    }

    /// The payee's `UASig` over `UAReceiverFee` nesting `x`, fee `fee` to `FEE_TO`.
    function _rfSig(address t, MetaTxLib.UAMetaTransfer memory x, uint256 fee, uint256 vu)
        internal view returns (IUARegistry.UASig memory)
    {
        return _sig(PAYEE_PK, MtxDigest.typed(t,
            keccak256(abi.encode(UA_RECEIVER_FEE_TYPEHASH, MetaTxLib.hashStruct(x), fee, FEE_TO, vu))));
    }

    function _receiverFeeWith(address t, MetaTxLib.UAMetaTransfer memory x, IUARegistry.UASig memory a, uint256 fee,
        IUARegistry.UASig memory b) internal returns (bool)
    {
        vm.prank(REL);
        return IMergedT2(t).mtxPayReceiverFee(x, a, fee, FEE_TO, block.timestamp + 600, b,
            PayMetaKit.meta(seedOf[x.entryRef]));
    }

    function _receiverFee(address t, MetaTxLib.UAMetaTransfer memory x, uint256 fee) internal returns (bool) {
        IUARegistry.UASig memory a = _s(t, x);
        IUARegistry.UASig memory b = _rfSig(t, x, fee, block.timestamp + 600);
        return _receiverFeeWith(t, x, a, fee, b);
    }

    function _noEntry(address t, bytes memory cd, string memory kind) internal {
        vm.prank(REL);
        (bool ok, bytes memory ret) = t.call(cd);
        assertFalse(ok, string.concat(kind, ": a retired selector runs"));
        assertEq(ret.length, 0, string.concat(kind, ": no entry, so no named refusal"));
    }

    // ------------------------------------------------------------------ EOA to EOA, EOA to UA (B, C)

    /// One relayed `mtxTransfer` by the EOA signer to an EOA: the ERC-20 `Transfer`, the nonce, and no registry call.
    function _eoaToEoa(Tk memory k) internal {
        address t = k.t;
        MetaTxLib.UAMetaTransfer memory x = _x(t, from, to, 7, 11);
        uint256 b0 = IERC20(t).balanceOf(payee);
        address reg = MetaTokenBase(t).registry();
        IUARegistry.UASig memory s = _s(t, x);
        if (reg != address(0) && !_noCallSet[reg]) {
            vm.expectCall(reg, bytes(""), 0); // no call to this registry for the rest of the test
            _noCallSet[reg] = true;
        }
        vm.expectEmit(true, true, false, true, t);
        emit IERC20.Transfer(signer, payee, 7);
        assertTrue(_transfer(t, x, s), k.kind);
        assertEq(IERC20(t).balanceOf(payee), b0 + 7, k.kind);
        assertEq(MetaTokenBase(t).mtxNonce(from, 11), x.nonce + 1, k.kind);
    }

    function test_mtxTransfer_eoaToEoa_registry() public {
        uint256 n;
        for (uint256 i; i < ks.length; ++i) {
            if (MetaTokenBase(ks[i].t).registry() == address(0)) continue;
            _eoaToEoa(ks[i]);
            ++n;
        }
        assertEq(n, 6, "every kind with a registry");
    }

    /// C: with no registry at all an EOA still relays (`NORMAL`, `WRAPPED`).
    function test_mtxTransfer_eoaToEoa_registry0() public {
        uint256 n;
        for (uint256 i; i < ks.length; ++i) {
            if (MetaTokenBase(ks[i].t).registry() != address(0)) continue;
            _eoaToEoa(ks[i]);
            ++n;
        }
        assertEq(n, 2, "NORMAL and WRAPPED with no registry");
    }

    /// An EOA pays a registered SIGNING derived UA of the token's registry (new on the address side, risk 6).
    function test_mtxTransfer_eoaToUA() public {
        uint256 n;
        for (uint256 i; i < ks.length; ++i) {
            if (ks[i].uaD == 0) continue;
            _eoaToUA(ks[i].t, ks[i].uaD, ks[i].kind);
            ++n;
        }
        assertEq(n, 6, "every kind with a registry");
    }

    function _eoaToUA(address t, bytes32 ua, string memory kind) internal {
        MetaTxLib.UAMetaTransfer memory x = _x(t, from, ua, 9, 12);
        uint256 u0 = MetaTokenBase(t).balanceOfUA(ua);
        IUARegistry.UASig memory s = _s(t, x);
        vm.expectEmit(true, true, false, true, t);
        emit IUALedger.UATransfer(from, ua, 9);
        _transfer(t, x, s);
        assertEq(MetaTokenBase(t).balanceOfUA(ua), u0 + 9, kind);
    }

    /// C on the receiver: with no registry a derived `to` is `UALedgerOff` by name, not an empty revert.
    function test_mtxTransfer_derivedReceiverNoRegistryIsLedgerOff() public {
        address t = ks[7].t;
        MetaTxLib.UAMetaTransfer memory x = _x(t, from, bytes32(uint256(1) << 200), 1, 13);
        IUARegistry.UASig memory s = _s(t, x);
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        _transfer(t, x, s);
    }

    // ------------------------------------------------------------------ fee 0 (invariant 4)

    /// Every merged entry of the group runs at fee mode `NONE` on every kind, with and without a registry.
    function test_mtxTransfer_feeZero() public {
        for (uint256 i; i < ks.length; ++i) _feeZero(ks[i].t, i, ks[i].kind);
    }

    function _feeZero(address t, uint256 i, string memory kind) internal {
        uint256 b0 = IERC20(t).balanceOf(payee);
        MetaTxLib.UAMetaTransfer memory x = _x(t, from, to, 1, 21);
        IUARegistry.UASig memory s = _s(t, x);
        vm.prank(REL);
        assertTrue(IMergedT2(t).mtxExecuteTransfer(x, s), string.concat(kind, ": mtxExecuteTransfer"));
        _batchTwo(t, kind);
        assertTrue(_pay(t, _payX(t, _payId(i), 4, MetaTxLib.MODE_RESTRICT_RELAYER)), string.concat(kind, ": mtxPay"));
        _payMetaZero(t, i, kind);
        _relay(t, 6, to); // mtxRelayFee through the router: the relayed payment is built at NONE
        assertEq(IERC20(t).balanceOf(payee), b0 + 1 + 2 + 3 + 4 + 5 + 6, kind);
    }

    /// `mtxBatchTransfer`, two items on one lane.
    function _batchTwo(address t, string memory kind) internal {
        MetaTxLib.UAMetaTransfer[] memory xs = new MetaTxLib.UAMetaTransfer[](2);
        IUARegistry.UASig[] memory as_ = new IUARegistry.UASig[](2);
        xs[0] = _x(t, from, to, 2, 22);
        xs[1] = _x(t, from, to, 3, 22);
        xs[1].nonce = xs[0].nonce + 1;
        as_[0] = _s(t, xs[0]);
        as_[1] = _s(t, xs[1]);
        vm.prank(REL);
        assertTrue(IMergedT2(t).mtxBatchTransfer(xs, as_), string.concat(kind, ": mtxBatchTransfer"));
    }

    /// `mtxPay` at `NONE` on a free lane (pay-meta-tax T37, meaning: was `mtxPayMeta`, now in legacy/).
    function _payMetaZero(address t, uint256 i, string memory kind) internal {
        MetaTxLib.UAMetaTransfer memory x = _payX(t, _payId(500 + i), 5, 0);
        x.batch = 23;
        IUARegistry.UASig memory s = _s(t, x);
        assertTrue(_payWith(t, x, s), string.concat(kind, ": mtxPay at NONE"));
    }

    // ------------------------------------------------------------------ the fee entries (listed by invariant 4)

    /// `mtxTransferWithFee` is the fee form: `NONE` is refused (`mtxTransfer` is the form at 0); a bound FIXED fee runs.
    function test_mtxTransferWithFee_needsFee() public {
        for (uint256 i; i < ks.length; ++i) _withFee(ks[i].t, ks[i].kind);
    }

    function _withFee(address t, string memory kind) internal {
        MetaTxLib.UAMetaTransfer memory x = _x(t, from, to, 1_000, 31);
        IUARegistry.UASig memory s = _s(t, x);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.MtxModeShape.selector, uint32(0)));
        _transferWithFee(t, x, s);
        x.mode = MetaTxLib.MODE_FEE_FIXED | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
        x.fee = 3;
        x.feeRecipient = FEE_TO;
        uint256 f0 = IERC20(t).balanceOf(FEE_TO);
        s = _s(t, x);
        assertTrue(_transferWithFee(t, x, s), kind);
        assertEq(IERC20(t).balanceOf(FEE_TO), f0 + 3, kind);
    }

    /// Receiver-pays: the payer's leg is `NONE`; the payee (an EOA holding nothing before) co-signs `UAReceiverFee` and
    /// pays the fee out of what it received. A payer leg with a fee mode is the wrong shape.
    function test_mtxPayReceiverFee_payerLegNone() public {
        for (uint256 i; i < ks.length; ++i) _payerLegNone(ks[i].t, i, ks[i].kind);
    }

    function _payerLegNone(address t, uint256 i, string memory kind) internal {
        assertEq(IERC20(t).balanceOf(payee), 0, kind);
        assertTrue(_receiverFee(t, _rfLeg(t, i, 100), 4), kind);
        assertEq(IERC20(t).balanceOf(payee), 96, kind);
        assertEq(IERC20(t).balanceOf(FEE_TO), 4, kind);
        MetaTxLib.UAMetaTransfer memory y = _rfLeg(t, i + 100, 100);
        y.mode = MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED;
        y.fee = 1;
        IUARegistry.UASig memory a = _s(t, y);
        IUARegistry.UASig memory b = _rfSig(t, y, 4, block.timestamp + 600);
        vm.expectRevert(IMetaTokenV2.ReceiverFeeShape.selector);
        _receiverFeeWith(t, y, a, 4, b);
    }

    /// The router's `relay` takes the payer's id and `UASig` (R28); the target runs before the fee (invariant 5).
    function test_relayFeeRouter_relayTakesUASig() public {
        for (uint256 i; i < ks.length; ++i) _relayCase(ks[i].t, ks[i].kind);
    }

    function _relayCase(address t, string memory kind) internal {
        uint256 p0 = IERC20(t).balanceOf(payee);
        RelayArgs memory r = _relayArgs(t, 8, to);
        bytes32 ref = router.relayRef(address(probe), r.cd);
        vm.expectEmit(true, true, true, true, address(router));
        emit RelayFeeRouter.RelayFeePaid(ref, address(probe), t, from, to, 8);
        _relayWith(r);
        assertTrue(probe.ran(), kind);
        assertEq(probe.seen(), p0, string.concat(kind, ": the call ran before its fee"));
        assertEq(IERC20(t).balanceOf(payee), p0 + 8, kind);
    }

    /// Open mode: `payee == pad(router)`, the fee goes on to the submitter.
    function test_relayFeeRouter_openModePaysSubmitter() public {
        address t = ks[0].t;
        uint256 r0 = IERC20(t).balanceOf(REL);
        _relay(t, 8, MetaTxLib.pad(address(router)));
        assertEq(IERC20(t).balanceOf(REL), r0 + 8);
        assertEq(IERC20(t).balanceOf(address(router)), 0);
    }

    // ------------------------------------------------------------------ receivers and the batch shape (mutants)

    function test_mtxPay_receiverChecked() public {
        address t = ks[0].t;
        MetaTxLib.UAMetaTransfer memory x = _payX(t, _payId(51), 1, MetaTxLib.MODE_RESTRICT_RELAYER);
        x.to = bytes32(uint256(1) << 200); // derived, not registered
        IUARegistry.UASig memory s = _s(t, x);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, x.to));
        _payWith(t, x, s);
        x.to = MetaTxLib.pad(t);
        s = _s(t, x);
        vm.expectRevert(IERC20MetaTx.TransferToSelf.selector);
        _payWith(t, x, s);
        x.to = bytes32(0);
        s = _s(t, x);
        vm.expectRevert(IERC20MetaTx.PayToZero.selector);
        _payWith(t, x, s);
    }

    function test_mtxBatchTransfer_shape() public {
        address t = ks[0].t;
        MetaTxLib.UAMetaTransfer[] memory xs = new MetaTxLib.UAMetaTransfer[](2);
        xs[0] = _x(t, from, to, 1, 52);
        xs[1] = _x(t, from, to, 1, 53);
        IUARegistry.UASig[] memory one = new IUARegistry.UASig[](1);
        one[0] = _s(t, xs[0]);
        vm.expectRevert(IMetaTx.MtxBatchLengthMismatch.selector);
        vm.prank(REL);
        IMergedT2(t).mtxBatchTransfer(xs, one);
        vm.expectRevert(IMetaTx.MtxBatchEmpty.selector);
        vm.prank(REL);
        IMergedT2(t).mtxBatchTransfer(new MetaTxLib.UAMetaTransfer[](0), new IUARegistry.UASig[](0));
    }

    // ------------------------------------------------------------------ the retired forms (invariant 3)

    /// Positive control first: the `UAMetaTransfer` signature runs. The same transfer signed as the address
    /// `MetaTransfer` verifies on no merged entry, and the address selectors have no entry on any kind.
    function test_oldMetaTransferSignatureRefusedOnEveryEntry() public {
        for (uint256 i; i < ks.length; ++i) _oldRefused(ks[i].t, i, ks[i].kind);
    }

    function _oldRefused(address t, uint256 i, string memory kind) internal {
        MetaTxLib.UAMetaTransfer memory x = _x(t, from, to, 2, 61);
        IUARegistry.UASig memory s = _s(t, x);
        vm.prank(REL);
        assertTrue(IMergedT2(t).mtxExecuteTransfer(x, s), string.concat(kind, ": positive control"));
        x = _x(t, from, to, 2, 61);
        _oldOnMerged(t, x);
        _oldPayOnMerged(t, _payX(t, _payId(2000 + i), 2, MetaTxLib.MODE_RESTRICT_RELAYER));
        _oldSelectors(t, x, kind);
        _oldPaySelector(t, _payX(t, _payId(2000 + i), 2, MetaTxLib.MODE_RESTRICT_RELAYER), kind);
        assertEq(MetaTokenBase(t).mtxNonce(from, 61), x.nonce, string.concat(kind, ": nothing ran"));
    }

    /// The address signature of the same transfer in a `UASig`, on the three transfer entries.
    function _oldOnMerged(address t, MetaTxLib.UAMetaTransfer memory x) internal {
        IUARegistry.UASig memory a;
        a.signature = _oldSig(t, x);
        MetaTxLib.UAMetaTransfer[] memory xs = new MetaTxLib.UAMetaTransfer[](1);
        IUARegistry.UASig[] memory as_ = new IUARegistry.UASig[](1);
        xs[0] = x;
        as_[0] = a;
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        vm.prank(REL);
        IMergedT2(t).mtxExecuteTransfer(x, a);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _transfer(t, x, a);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        vm.prank(REL);
        IMergedT2(t).mtxBatchTransfer(xs, as_);
    }

    /// The address signature of a payment, on `mtxPay`.
    function _oldPayOnMerged(address t, MetaTxLib.UAMetaTransfer memory p) internal {
        IUARegistry.UASig memory a;
        a.signature = _oldSig(t, p);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _payWith(t, p, a);
    }

    /// The address transfer entries: no selector left on the token.
    function _oldSelectors(address t, MetaTxLib.UAMetaTransfer memory x, string memory kind) internal {
        OldMetaTransfer memory o = _old(x);
        bytes memory oldSig = _oldSig(t, x);
        OldMetaTransfer[] memory os = new OldMetaTransfer[](1);
        bytes[] memory ss = new bytes[](1);
        os[0] = o;
        ss[0] = oldSig;
        _noEntry(t, abi.encodeCall(IOldT2.mtxExecuteTransfer, (o, oldSig)), kind);
        _noEntry(t, abi.encodeCall(IOldT2.mtxBatchTransfer, (os, ss)), kind);
        _noEntry(t, _oldTransferCd(o, oldSig), kind);
    }

    function _oldTransferCd(OldMetaTransfer memory o, bytes memory sig) internal pure returns (bytes memory) {
        return abi.encodeCall(IOldT2.mtxTransfer, (o.from, o.to, o.value, o.batch, o.nonce, o.validUntil, o.mode,
            o.relayer, sig));
    }

    function _oldPaySelector(address t, MetaTxLib.UAMetaTransfer memory p, string memory kind) internal {
        OldMetaTransfer memory o = _old(p);
        bytes memory sig = _oldSig(t, p);
        _noEntry(t, abi.encodeCall(IOldT2.mtxPay, (o.from, o.to, o.value, o.entryRef, o.validUntil, o.mode, o.relayer,
            o.fee, o.feeRecipient, sig)), kind);
    }

    /// The address `ReceiverFee` and `RelayFee` have no entry (token and router), and a payee or payer that signs them
    /// is refused by the merged entries; positive controls in the tests above.
    function test_oldReceiverFeeAndRelayFeeHaveNoEntry() public {
        for (uint256 i; i < ks.length; ++i) {
            _oldReceiverFee(ks[i].t, i, ks[i].kind);
            _oldRelayFee(ks[i].t, ks[i].kind);
        }
    }

    function _oldReceiverFee(address t, uint256 i, string memory kind) internal {
        MetaTxLib.UAMetaTransfer memory x = _rfLeg(t, i, 100);
        OldMetaTransfer memory o = _old(x);
        IUARegistry.UASig memory b;
        b.signature = _raw(PAYEE_PK, MtxDigest.typed(t,
            keccak256(abi.encode(OLD_RECEIVER_FEE_TYPEHASH, _oldHash(o), 4, FEE_TO, block.timestamp + 600))));
        _noEntry(t, abi.encodeCall(IOldT2.mtxPayReceiverFee, (o, _oldSig(t, x), 4, FEE_TO, block.timestamp + 600,
            b.signature)), kind);
        IUARegistry.UASig memory a = _s(t, x);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _receiverFeeWith(t, x, a, 4, b);
    }

    /// The token's address entry and the router's two old entries; the old struct signed is refused by `relay`.
    function _oldRelayFee(address t, string memory kind) internal {
        RelayArgs memory r = _relayArgs(t, 8, to);
        r.auth.signature = _raw(PK, MtxDigest.typed(t, _relayHash(OLD_RELAY_FEE_TYPEHASH, from, r)));
        _noEntry(t, abi.encodeCall(IOldT2.mtxRelayFee, (signer, address(probe), keccak256(r.cd), payee, 8, r.validUntil,
            r.auth.signature)), kind);
        _noEntry(address(router), _oldRelayCd(r), kind);
        _noEntry(address(router), abi.encodeCall(IOldT2.uaRelay, (address(probe), r.cd, t, from, to, 8, r.validUntil,
            r.auth)), kind);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _relayWith(r);
    }

    function _oldRelayCd(RelayArgs memory r) internal view returns (bytes memory) {
        return abi.encodeCall(IOldT2.relay, (address(probe), r.cd, r.t, signer, payee, r.value, r.validUntil,
            r.auth.signature));
    }

    // ------------------------------------------------------------------ events (R18, R20)

    /// A merged path emits the `UA…` events only, a native subject included: no `MetaTransactionExecuted`,
    /// `PaymentSettled` or `ReceiverFeePaid`; a native ledger move still emits the ERC-20 `Transfer`.
    function test_mergedPathEmitsUAEventsOnly() public {
        for (uint256 i; i < ks.length; ++i) {
            address t = ks[i].t;
            MetaTxLib.UAMetaTransfer memory x = _x(t, from, to, 3, 71);
            IUARegistry.UASig memory s = _s(t, x);
            vm.recordLogs();
            vm.prank(REL);
            IMergedT2(t).mtxExecuteTransfer(x, s);
            _pay(t, _payX(t, _payId(3000 + i), 3, MetaTxLib.MODE_RESTRICT_RELAYER));
            _receiverFee(t, _rfLeg(t, i, 50), 2);
            _relay(t, 1, to);
            _uaEventsOnly(vm.getRecordedLogs(), t, ks[i].kind);
        }
    }

    function _uaEventsOnly(Vm.Log[] memory logs, address t, string memory kind) internal pure {
        bytes32 oldRf = keccak256("ReceiverFeePaid(bytes32,address,address,uint256)");
        uint256 ua;
        uint256 erc;
        for (uint256 j; j < logs.length; ++j) {
            if (logs[j].emitter != t) continue;
            bytes32 t0 = logs[j].topics[0];
            assertTrue(t0 != IMetaTx.MetaTransactionExecuted.selector, string.concat(kind, ": address executed"));
            assertTrue(t0 != IERC20Payment.PaymentSettled.selector, string.concat(kind, ": PaymentSettled"));
            assertTrue(t0 != oldRf, string.concat(kind, ": ReceiverFeePaid"));
            if (t0 == IUALedger.UAMetaTransactionExecuted.selector) {
                assertEq(logs[j].topics[1], MetaTxLib.pad(vm.addr(PK)), kind);
                ++ua;
            }
            if (t0 == IERC20.Transfer.selector) ++erc;
        }
        assertEq(ua, 4, string.concat(kind, ": one UAMetaTransactionExecuted per payment"));
        assertGt(erc, 0, string.concat(kind, ": the native moves emit Transfer"));
    }

    /// A `pay_ref` lookup reads `UAPaymentSettled` for an EOA (R20): `entryRef` = the pay id, ids padded.
    function test_payRefReadsUAPaymentSettled() public {
        for (uint256 i; i < ks.length; ++i) {
            address t = ks[i].t;
            MetaTxLib.UAMetaTransfer memory x = _payX(t, _payId(4000 + i), 11, MetaTxLib.MODE_RESTRICT_RELAYER);
            IUARegistry.UASig memory s = _s(t, x);
            vm.expectEmit(true, true, true, true, t);
            emit IUALedger.UAPaymentSettled(from, to, 11, 0, REL, x.entryRef);
            _payWith(t, x, s);
        }
    }

    // ------------------------------------------------------------------ interface ids (pins, old -> new)

    /// The typed path left `IUALedger` for `IERC20MetaTx` (it runs with the ledger off for a native id, C, R9); the named
    /// entries of `IMetaTokenV2` are the merged ones; `IERC20Payment` (`payWithFee`) is unchanged. Old -> new (the old
    /// ids XOR-ed from the T1 interfaces' selectors): IERC20MetaTx 0x24cb820a -> 0x05c4a9ef, IMetaTokenV2 0x72c81896 ->
    /// 0xfa5f874a, IERC20Payment 0xcc624078 (unchanged), IUALedger 0x1060e254 -> 0xac15edc6. pay-meta-tax T37 (`PayMeta`
    /// last on every pay entry, `mtxPay` in its struct form, `mtxPayMeta` and `metaPayId(bytes32,bytes)` to legacy):
    /// IMetaTokenV2 0xfa5f874a -> 0xcd9d6940, IERC20Payment 0xcc624078 -> 0xced674ba. Plan T83 (`PayMeta` v3 in every pay
    /// entry's tuple; `paymentCount`, `paymentsOf`): IMetaTokenV2 0xcd9d6940 -> 0x62cce053, IERC20Payment 0xced674ba ->
    /// 0x6a4938cb.
    function test_typedPathInterfaceIdsArePinned() public pure {
        // pay-meta-tax T38 (`mtxRelayFee` with `batch`, `nonce`): IERC20MetaTx 0x05c4a9ef -> 0x7513beba
        assertEq(type(IERC20MetaTx).interfaceId, bytes4(0x7513beba), "IERC20MetaTx");
        assertEq(type(IMetaTokenV2).interfaceId, bytes4(0x62cce053), "IMetaTokenV2");
        assertEq(type(IERC20Payment).interfaceId, bytes4(0x6a4938cb), "IERC20Payment");
        assertEq(type(IUALedger).interfaceId, bytes4(0xac15edc6), "IUALedger");
    }

    // ------------------------------------------------------------------ the regulated hook's seat (spec §8 risk 2)

    /// A hook in `_update` alone sees a direct transfer and misses a relayed one: every signed transfer moves through
    /// `_uaMove`, which calls `ERC20._update` directly. The stated risk, pinned: CTR-GOV-17 must hook `_uaMove` too.
    function test_regulatedHookSeatIsUaMove() public {
        address h = EnvKit.clone(address(new HookedNormal(address(this))), EnvKit.env(bytes32(uint256(7)), address(0), address(0), false));
        HookedNormal(h).initialize(nid(address(this)), 1, abi.encode(normalInit("Hooked", "HK", 6, 1_000, signer, address(this))));
        uint256 h0 = HookedNormal(h).hits();
        vm.prank(signer);
        IERC20(h).transfer(payee, 1);
        assertEq(HookedNormal(h).hits(), h0 + 1, "a direct transfer passes the hook");
        MetaTxLib.UAMetaTransfer memory x = _x(h, from, to, 1, 81);
        _transfer(h, x, _s(h, x));
        assertEq(IERC20(h).balanceOf(payee), 2);
        assertEq(HookedNormal(h).hits(), h0 + 1, "a relayed transfer does not pass a hook in _update");
    }
}
