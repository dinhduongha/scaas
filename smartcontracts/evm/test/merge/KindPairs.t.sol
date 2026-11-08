// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {UACall} from "../ua/UACall.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {normalInit, wrappedInit, Rate} from "../v2/helpers/V2Fixture.sol";

/// The merged entries of ua-mtx-merge T3 (R23, R39), called by selector: this file compiles on the tree before T3 too,
/// so each test is red there on its own (plan T3 step 3).
interface IMergedT3 {
    function mtxBurn(MetaTxLib.UAEnvelope calldata e, uint256 amount, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxUnwrap(MetaTxLib.UAEnvelope calldata e, uint256 wrapped, address recipient, uint256 minOut,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxUnwrapLeg(MetaTxLib.UAEnvelope calldata e, address u, uint256 wrapped, address recipient,
        uint256 minOut, IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxUnwrapToUA(MetaTxLib.UAEnvelope calldata e, address u, uint256 wrapped, bytes32 to, uint256 minOut,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxWrapOrder(address u, ITradeToken.UAWrapOrder calldata o, IUARegistry.UASig calldata auth)
        external returns (uint256);
}

/// The address `WrapOrder` (R39: in legacy/ua-mtx-merge/ after T3), kept here to encode the retired entry.
struct OldWrapOrder {
    address from;
    address wrappedToken;
    uint256 amount;
    uint256 minMinted;
    uint256 minFill;
    uint256 fee;
    address relayer;
    address destination;
    uint8 flags;
    uint256 batch;
    uint256 nonce;
    uint256 validUntil;
}

/// The retired address entries and the `ua*` names (invariant 3): after T3 no token serves these selectors.
interface IOldT3 {
    function mtxBurn(MetaTxLib.Envelope calldata e, uint256 amount, bytes calldata sig) external returns (bytes memory);
    function mtxUnwrap(MetaTxLib.Envelope calldata e, uint256 wrapped, address recipient, uint256 minOut,
        bytes calldata sig) external returns (bytes memory);
    function mtxUnwrapLeg(MetaTxLib.Envelope calldata e, address u, uint256 wrapped, address recipient, uint256 minOut,
        bytes calldata sig) external returns (bytes memory);
    function mtxUnwrapToUA(MetaTxLib.Envelope calldata e, address u, uint256 wrapped, bytes32 to, uint256 minOut,
        bytes calldata sig) external returns (bytes memory);
    function mtxWrapOrder(address u, OldWrapOrder calldata o, bytes calldata sig) external returns (uint256);
    function uaBurn(MetaTxLib.UAEnvelope calldata e, uint256 amount, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function uaUnwrap(MetaTxLib.UAEnvelope calldata e, uint256 wrapped, address recipient, uint256 minOut,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function uaUnwrapLeg(MetaTxLib.UAEnvelope calldata e, address u, uint256 wrapped, address recipient,
        uint256 minOut, IUARegistry.UASig calldata auth) external returns (bytes memory);
    function uaUnwrapToUA(MetaTxLib.UAEnvelope calldata e, address u, uint256 wrapped, bytes32 to, uint256 minOut,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function uaWrapOrder(address u, ITradeToken.UAWrapOrder calldata o, IUARegistry.UASig calldata auth)
        external returns (uint256);
}

/// The no-twin wrap entries moved onto `UAEnvelope` (what must NOT exist, spec §2.1).
interface INoTwinOnUA {
    function mtxWrap(MetaTxLib.UAEnvelope calldata e, uint256 amount, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxWrapLeg(MetaTxLib.UAEnvelope calldata e, address u, uint256 amount, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxWrapToUA(MetaTxLib.UAEnvelope calldata e, address u, uint256 amount, bytes32 to,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxAddReserve(MetaTxLib.UAEnvelope calldata e, address u, uint256 amount, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
}

/// T3: the token kinds' own pairs (`mtxBurn`, `mtxUnwrap`, `mtxUnwrapLeg`, `mtxUnwrapToUA`, `mtxWrapOrder`) in today's
/// `ua*` form under the `mtx*` name, for native and derived ids (R23, R39); the four no-twin wraps unchanged (spec §2.1).
/// `tok` / `wrp` / `wrpL` have the registry `lreg`; `off` / `wOff` / `wOffL` none (C). Every relayed call is at fee mode
/// `NONE` by a relayer the signer did not bind (invariant 4).
contract KindPairsTest is UALedgerBase {
    string internal constant E_TAIL =
        "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant H_BURN = "UABurn(bytes32 from,uint256 amount,";
    string internal constant H_UNWRAP = "UAUnwrap(bytes32 from,uint256 wrapped,address recipient,uint256 minOut,";
    string internal constant H_UNWRAP_LEG =
        "UAUnwrapLeg(bytes32 from,address underlying,uint256 wrapped,address recipient,uint256 minOut,";
    string internal constant H_UNWRAP_TO_UA =
        "UAUnwrapToUA(bytes32 from,address underlying,uint256 wrapped,bytes32 to,uint256 minOut,";
    string internal constant ENV = "(address,uint256,uint256,uint256,uint32,address,uint256,address)";
    string internal constant UA_ENV = "(bytes32,uint256,uint256,uint256,uint32,address,uint256,address)";
    address internal constant ANY = address(0xA9E); // a relayer nobody bound
    uint256 internal constant LANE = 5;
    uint256 internal constant CAP = 1000;

    NormalToken internal off; // NORMAL, no registry
    WrappedToken internal wOff; // WRAPPED of `und`, no registry
    WrappedToken internal wOffL; // WRAPPED of `off` (a SCaaS token with no registry), no registry

    function setUp() public override {
        super.setUp();
        off = NormalToken(Clones.clone(address(new NormalToken(1, plainEnv(address(this), address(0), chainUidA, address(0), false), ""))));
        off.initialize(address(this), 1, abi.encode(normalInit("Off", "OFF", 6, 1_000_000, alice, address(this))));
        wOff = _wrapperOff(address(und));
        wOffL = _wrapperOff(address(off));
        _wrapFor(alice, 10_000);
        und.mint(alice, 10_000);
        vm.startPrank(alice);
        und.approve(address(wOff), 10_000);
        wOff.wrap(10_000);
        wrp.transferToUA(uaP, 2_000);
        vm.stopPrank();
        _wrapL(alice, 5_000);
        assertEq(off.registry(), address(0));
        assertEq(wOff.registry(), address(0));
    }

    function _wrapperOff(address leg) internal returns (WrappedToken w) {
        w = WrappedToken(Clones.clone(address(new WrappedToken(1, plainEnv(address(this), address(0), chainUidA, address(0), false), ""))));
        address[] memory us = new address[](1);
        uint256[] memory one = new uint256[](1);
        (us[0], one[0]) = (leg, 1);
        Rate memory fixedRate;
        w.initialize(address(this), 1, abi.encode(wrappedInit(us, one, one, 6, fixedRate, address(0), address(0))));
    }

    // ------------------------------------------------------------------ helpers

    /// Fee mode `NONE`, relayer and fee recipient unbound, lane `LANE` at `from`'s next nonce on `t`.
    function _e(address t, bytes32 from) internal view returns (MetaTxLib.UAEnvelope memory e) {
        e.from = from;
        e.batch = LANE;
        e.nonce = MetaTokenBase(t).mtxNonce(from, LANE);
        e.validUntil = block.timestamp + 300;
    }

    /// The digest of `<head><E>` over `(from, args…, E)` in `t`'s domain, from the type string (not read from the token).
    function _digest(address t, string memory head, bytes memory args, MetaTxLib.UAEnvelope memory e)
        internal view returns (bytes32)
    {
        bytes32 structHash = keccak256(bytes.concat(abi.encode(keccak256(bytes(string.concat(head, E_TAIL))), e.from),
            args, abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        return MtxDigest.typed(t, structHash);
    }

    /// The signer's `UASig`: a native id its own ECDSA signature only (R17), a derived one through `lreg` (`metatx`).
    function _sigFor(address t, string memory head, bytes memory args, MetaTxLib.UAEnvelope memory e)
        internal view returns (IUARegistry.UASig memory)
    {
        return UACall.auth(e.from, _authFor(e.from, _digest(t, head, args, e)));
    }

    function _noEntry(address t, bytes memory cd, string memory what) internal {
        vm.prank(ANY);
        (bool ok, bytes memory ret) = t.call(cd);
        assertFalse(ok, string.concat(what, ": a retired selector runs"));
        assertEq(ret.length, 0, string.concat(what, ": no entry, so no named refusal"));
    }

    function _burn(NormalToken t, bytes32 from, uint256 amount) internal {
        MetaTxLib.UAEnvelope memory e = _e(address(t), from);
        IUARegistry.UASig memory s = _sigFor(address(t), H_BURN, abi.encode(amount), e);
        vm.prank(ANY);
        IMergedT3(address(t)).mtxBurn(e, amount, s);
    }

    function _unwrap(WrappedToken w, bytes32 from, uint256 wrapped) internal {
        MetaTxLib.UAEnvelope memory e = _e(address(w), from);
        IUARegistry.UASig memory s = _sigFor(address(w), H_UNWRAP, abi.encode(wrapped, bob, uint256(0)), e);
        vm.prank(ANY);
        IMergedT3(address(w)).mtxUnwrap(e, wrapped, bob, 0, s);
    }

    function _unwrapLeg(WrappedToken w, address u, bytes32 from, uint256 wrapped) internal {
        MetaTxLib.UAEnvelope memory e = _e(address(w), from);
        IUARegistry.UASig memory s = _sigFor(address(w), H_UNWRAP_LEG, abi.encode(u, wrapped, bob, uint256(0)), e);
        vm.prank(ANY);
        IMergedT3(address(w)).mtxUnwrapLeg(e, u, wrapped, bob, 0, s);
    }

    function _unwrapToUA(bytes32 from, bytes32 to, uint256 wrapped) internal {
        MetaTxLib.UAEnvelope memory e = _e(address(wrpL), from);
        IUARegistry.UASig memory s =
            _sigFor(address(wrpL), H_UNWRAP_TO_UA, abi.encode(address(tok), wrapped, to, uint256(0)), e);
        vm.prank(ANY);
        IMergedT3(address(wrpL)).mtxUnwrapToUA(e, address(tok), wrapped, to, 0, s);
    }

    /// A `UAWrapOrder` of `amount` at 1:1, no fee, relayer `ANY` (the order's own field), lane 1 at `nonce`.
    function _o(WrappedToken w, bytes32 from, uint256 amount, uint256 nonce)
        internal view returns (ITradeToken.UAWrapOrder memory o)
    {
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill) = (from, address(w), amount, amount, amount);
        (o.relayer, o.batch, o.nonce, o.validUntil) = (ANY, 1, nonce, block.timestamp + 300);
    }

    /// The holder's `UASig` over the order in the underlying `u`'s domain: a native id signs it itself.
    function _oSig(address u, ITradeToken.UAWrapOrder memory o) internal view returns (IUARegistry.UASig memory a) {
        a.signature = _ecdsa(ALICE_PK, NormalToken(u).tradeOrderDigest(DexLegs.asTrade(o)));
    }

    function _wrapOrder(WrappedToken w, address u, ITradeToken.UAWrapOrder memory o) internal returns (uint256) {
        IUARegistry.UASig memory a = _oSig(u, o);
        vm.prank(ANY);
        return IMergedT3(address(w)).mtxWrapOrder(u, o, a);
    }

    // ------------------------------------------------------------------ burn (NORMAL)

    /// C: an EOA burns by `mtxBurn` on a `NORMAL` token with no registry at all; with a registry, no registry call (B).
    function test_mtxBurn_native_registry0() public {
        uint256 b0 = off.balanceOf(alice);
        _burn(off, _pad(alice), 100);
        assertEq(off.balanceOf(alice), b0 - 100);
        assertEq(off.mtxNonce(_pad(alice), LANE), 1);
        b0 = tok.balanceOf(alice);
        vm.expectCall(address(lreg), bytes(""), 0);
        _burn(tok, _pad(alice), 100);
        assertEq(tok.balanceOf(alice), b0 - 100);
    }

    /// A derived signer burns its UA balance through the same entry (registry `metatx`).
    function test_mtxBurn_derived() public {
        _fund(uaP, 500);
        _burn(tok, uaP, 200);
        assertEq(tok.balanceOfUA(uaP), 300);
    }

    // ------------------------------------------------------------------ unwraps (WRAPPED)

    /// R23: an EOA unwraps by `mtxUnwrap` / `mtxUnwrapLeg` with no registry, and with one at no registry call.
    function test_mtxUnwrap_native() public {
        uint256 u0 = und.balanceOf(bob);
        _unwrap(wOff, _pad(alice), 100);
        _unwrapLeg(wOff, address(und), _pad(alice), 50);
        assertEq(und.balanceOf(bob), u0 + 150);
        assertEq(wOff.balanceOf(alice), 10_000 - 150);
        vm.expectCall(address(lreg), bytes(""), 0);
        _unwrap(wrp, _pad(alice), 100);
        _unwrapLeg(wrp, address(und), _pad(alice), 50);
        assertEq(und.balanceOf(bob), u0 + 300);
    }

    /// R23: a derived UA unwraps its UA balance by the same entries.
    function test_mtxUnwrap_derived() public {
        uint256 u0 = und.balanceOf(bob);
        _unwrap(wrp, uaP, 100);
        _unwrapLeg(wrp, address(und), uaP, 50);
        assertEq(und.balanceOf(bob), u0 + 150);
        assertEq(wrp.balanceOfUA(uaP), 2_000 - 150);
    }

    /// `mtxUnwrapToUA` pays into a derived UA of the leg's ledger, for a native and a derived signer; a native receiver is
    /// refused by name (`UANotRegistered`): the address twin pays it (`unwrap`).
    function test_mtxUnwrapToUA_nativeAndDerived() public {
        _unwrapToUA(_pad(alice), uaB, 100);
        assertEq(tok.balanceOfUA(uaB), 100);
        assertEq(wrpL.balanceOf(alice), 5_000 - 100);
        vm.prank(alice);
        wrpL.transferToUA(uaP, 1_000);
        _unwrapToUA(uaP, uaB, 200);
        assertEq(tok.balanceOfUA(uaB), 300);
        assertEq(wrpL.balanceOfUA(uaP), 800);
        MetaTxLib.UAEnvelope memory e = _e(address(wrpL), _pad(alice));
        IUARegistry.UASig memory s =
            _sigFor(address(wrpL), H_UNWRAP_TO_UA, abi.encode(address(tok), uint256(1), _pad(bob), uint256(0)), e);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, _pad(bob)));
        vm.prank(ANY);
        IMergedT3(address(wrpL)).mtxUnwrapToUA(e, address(tok), 1, _pad(bob), 0, s);
    }

    // ------------------------------------------------------------------ the wrap order (R39)

    /// C: an EOA wraps a SCaaS underlying with no registry into a wrapper with no registry: no ledger is asked of the leg
    /// for a native holder. Positive control: a derived holder over a leg that is no ledger is refused by name.
    function test_mtxWrapOrder_eoaLegNoRegistry() public {
        ITradeToken.UAWrapOrder memory o = _o(wOffL, _pad(alice), 1_000, 1);
        vm.expectEmit(address(wOffL));
        emit IWrappedToken.UAWrapped(_pad(alice), address(off), 1_000, 1_000);
        assertEq(_wrapOrder(wOffL, address(off), o), 1_000);
        assertEq(wOffL.balanceOf(alice), 1_000);
        assertEq(off.balanceOf(address(wOffL)), 1_000);
        o = _o(wrp, uaP, 100, 1);
        IUARegistry.UASig memory a;
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(und)));
        vm.prank(ANY);
        IMergedT3(address(wrp)).mtxWrapOrder(address(und), o, a);
    }

    /// CTR-GOV-12: the hybrid's one cap holds on the merged entry.
    function test_wrapOrderCapStillHolds() public {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.owner, c.maxSupply) = ("H", "H", 6, nid(address(0x0A)), CAP);
        c.features = 1 | (uint256(1) << GovernanceBits.MINTABLE);
        c.roles.minter = nid(address(0x313));
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(tok), 1, 1);
        WrappedToken w = WrappedToken(payable(Clones.clone(address(
            new WrappedToken(1, plainEnv(address(this), address(0), chainUidA, REG_L, false), "")))));
        w.initialize(address(this), 1, abi.encode(c));
        _wrapOrder(w, address(tok), _o(w, _pad(alice), CAP, 1));
        assertEq(w.totalSupply(), CAP);
        ITradeToken.UAWrapOrder memory o = _o(w, _pad(alice), 1, 2);
        IUARegistry.UASig memory a = _oSig(address(tok), o);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.MaxSupplyExceeded.selector, CAP + 1, CAP));
        vm.prank(ANY);
        IMergedT3(address(w)).mtxWrapOrder(address(tok), o, a);
    }

    // ------------------------------------------------------------------ fee 0 (invariant 4)

    /// Every merged entry of T3 runs at fee mode `NONE` by an unbound relayer, with no registry for a native subject.
    function test_feeZero_everyMergedEntry() public {
        _burn(off, _pad(alice), 1);
        _unwrap(wOff, _pad(alice), 1);
        _unwrapLeg(wOff, address(und), _pad(alice), 1);
        _unwrapToUA(_pad(alice), uaB, 1);
        _wrapOrder(wOffL, address(off), _o(wOffL, _pad(alice), 1, 1));
        assertEq(off.balanceOf(ANY) + wOff.balanceOf(ANY) + wrpL.balanceOf(ANY) + wOffL.balanceOf(ANY), 0, "no fee taken");
        assertEq(off.mtxNonce(_pad(alice), LANE) + wOff.mtxNonce(_pad(alice), LANE), 3);
    }

    // ------------------------------------------------------------------ what does not move

    /// Spec §2.1: `mtxWrap`, `mtxWrapLeg`, `mtxWrapToUA`, `mtxAddReserve` stay on `Envelope` + `bytes sig` with `address
    /// from` (their selectors pinned by signature); no `UAEnvelope` twin exists. Positive control: a signed `mtxWrap`.
    function test_noTwinWrapsStayAddress() public {
        assertEq(IWrappedToken.mtxWrap.selector, bytes4(keccak256(bytes(string.concat("mtxWrap(", ENV, ",uint256,bytes)")))));
        assertEq(IWrappedToken.mtxWrapLeg.selector,
            bytes4(keccak256(bytes(string.concat("mtxWrapLeg(", ENV, ",address,uint256,bytes)")))));
        assertEq(IWrappedToken.mtxWrapToUA.selector,
            bytes4(keccak256(bytes(string.concat("mtxWrapToUA(", ENV, ",address,uint256,bytes32,bytes)")))));
        assertEq(IWrappedToken.mtxAddReserve.selector,
            bytes4(keccak256(bytes(string.concat("mtxAddReserve(", ENV, ",address,uint256,bytes)")))));
        IUARegistry.UASig memory none;
        MetaTxLib.UAEnvelope memory ue = _e(address(wOff), _pad(alice));
        _noEntry(address(wOff), abi.encodeCall(INoTwinOnUA.mtxWrap, (ue, 1, none)), "mtxWrap on UAEnvelope");
        _noEntry(address(wOff), abi.encodeCall(INoTwinOnUA.mtxWrapLeg, (ue, address(und), 1, none)), "mtxWrapLeg on UAEnvelope");
        _noEntry(address(wOff), abi.encodeCall(INoTwinOnUA.mtxWrapToUA, (ue, address(und), 1, uaP, none)), "mtxWrapToUA on UAEnvelope");
        _noEntry(address(wOff), abi.encodeCall(INoTwinOnUA.mtxAddReserve, (ue, address(und), 1, none)), "mtxAddReserve on UAEnvelope");
        // positive control: the address `Wrap` struct, signed by the EOA, wraps with no registry
        MetaTxLib.Envelope memory e = MetaTxLib.Envelope(alice, 9, 0, block.timestamp + 300, 0, address(0), 0, address(0));
        bytes32 h = keccak256(abi.encode(keccak256(bytes(string.concat("Wrap(address from,uint256 amount,", E_TAIL))),
            alice, uint256(10), e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0)));
        und.mint(alice, 10);
        vm.prank(alice);
        und.approve(address(wOff), 10);
        uint256 w0 = wOff.balanceOf(alice);
        bytes memory sig = _ecdsa(ALICE_PK, MtxDigest.typed(address(wOff), h));
        vm.prank(ANY); // by its signature, so the file compiles whatever form the token's interface declares
        (bool ok, bytes memory ret) = address(wOff).call(abi.encodeWithSignature(
            string.concat("mtxWrap(", ENV, ",uint256,bytes)"), e, uint256(10), sig));
        assertTrue(ok, string(ret));
        assertEq(wOff.balanceOf(alice), w0 + 10);
    }

    /// Invariant 3: the address bodies and the `ua*` names of T3's pairs have no entry. Positive control first: the merged
    /// `mtxBurn` of the same burn runs.
    function test_oldAddressFormsAndUaNamesHaveNoEntry() public {
        _burn(off, _pad(alice), 1);
        MetaTxLib.Envelope memory e = MetaTxLib.Envelope(alice, LANE, 1, block.timestamp + 300, 0, address(0), 0, address(0));
        MetaTxLib.UAEnvelope memory ue = _e(address(wrpL), _pad(alice));
        IUARegistry.UASig memory none;
        OldWrapOrder memory ow;
        _noEntry(address(off), abi.encodeCall(IOldT3.mtxBurn, (e, 1, "")), "mtxBurn(Envelope)");
        _noEntry(address(off), abi.encodeCall(IOldT3.uaBurn, (ue, 1, none)), "uaBurn");
        _noEntry(address(wrpL), abi.encodeCall(IOldT3.mtxUnwrap, (e, 1, bob, 0, "")), "mtxUnwrap(Envelope)");
        _noEntry(address(wrpL), abi.encodeCall(IOldT3.mtxUnwrapLeg, (e, address(tok), 1, bob, 0, "")), "mtxUnwrapLeg(Envelope)");
        _noEntry(address(wrpL), abi.encodeCall(IOldT3.mtxUnwrapToUA, (e, address(tok), 1, uaB, 0, "")), "mtxUnwrapToUA(Envelope)");
        _noEntry(address(wrpL), abi.encodeCall(IOldT3.mtxWrapOrder, (address(tok), ow, "")), "mtxWrapOrder(WrapOrder)");
        _noEntry(address(wrpL), abi.encodeCall(IOldT3.uaUnwrap, (ue, 1, bob, 0, none)), "uaUnwrap");
        _noEntry(address(wrpL), abi.encodeCall(IOldT3.uaUnwrapLeg, (ue, address(tok), 1, bob, 0, none)), "uaUnwrapLeg");
        _noEntry(address(wrpL), abi.encodeCall(IOldT3.uaUnwrapToUA, (ue, address(tok), 1, uaB, 0, none)), "uaUnwrapToUA");
        _noEntry(address(wrpL), abi.encodeCall(IOldT3.uaWrapOrder, (address(tok), _o(wrpL, uaP, 1, 1), none)), "uaWrapOrder");
    }

    // ------------------------------------------------------------------ interface ids (pins, old -> new)

    /// `IWrappedToken` loses the address bodies and the `ua*` names of its pairs, its merged entries take the `mtx*` names;
    /// `ITradeToken` loses only the `WrapOrder` struct (no function names it), so its id does not move. Old -> new (red
    /// first at 0, then measured; the ITradeToken id XOR-ed from its 17 selectors): IWrappedToken 0xd69c2cd0 -> 0xa84f2937,
    /// ITradeToken 0x0b4d9a5c (unchanged). ua-mtx-merge T6 (R12, R38): ITradeToken 0x0b4d9a5c -> 0xe393854e, its 9
    /// selectors (the address `TradeOrder` entries and views out, the `ua*` ones under the `mtx` / plain names).
    function test_kindPairInterfaceIdsArePinned() public pure {
        assertEq(type(IWrappedToken).interfaceId, bytes4(0xa84f2937), "IWrappedToken");
        assertEq(type(ITradeToken).interfaceId, bytes4(0xe393854e), "ITradeToken");
    }
}
