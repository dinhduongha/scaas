// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {underlyingInit, Rate} from "../v2/helpers/V2Fixture.sol";
import {UALedgerBase} from "./UALedgerBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// token-wrappers.md CTR-TOK-20 `uaWrap` (UA-5b): a holder (derived, or a native id) of a SCaaS ledger underlying wraps
/// by a `UATradeOrder` pulled by the underlying's `uaTrade`; `minted − fee` goes to `o.destination` (0 ⇒ `o.from`), a
/// derived id through the UA ledger, a native one as ERC-20; the fee to the submitter. `wrpL` wraps `tok` 1:1.
contract UAWrapTest is UALedgerBase {
    function setUp() public override {
        super.setUp();
        _fund(uaP, 10_000);
    }

    function _o(UnderlyingToken w, bytes32 from, uint256 amount, uint256 receiveAmount, uint256 fee)
        internal view returns (ITradeToken.UATradeOrder memory o)
    {
        o.from = from;
        o.receiveToken = address(w);
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.minFill = amount;
        o.fee = fee;
        o.relayer = RELAYER;
        o.dex = address(w);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _a(ITradeToken.UATradeOrder memory o) internal view returns (bytes memory) {
        bytes32 h = tok.uaTradeOrderDigest(o);
        if (o.from == _pad(alice)) return _ecdsa(ALICE_PK, h);
        uint16 kind = lreg.kindOf(o.from);
        return _auth(lreg, kind, _key(kind), UAKinds.PURPOSE_TRADE, h);
    }

    function _wrap(UnderlyingToken w, ITradeToken.UATradeOrder memory o) internal returns (uint256 minted) {
        bytes memory auth = _a(o);
        vm.prank(RELAYER);
        minted = w.uaWrap(address(tok), o, auth);
    }

    function _wrapReverts(UnderlyingToken w, address u, ITradeToken.UATradeOrder memory o, bytes memory err) internal {
        bytes memory auth = _a(o);
        vm.expectRevert(err);
        vm.prank(RELAYER);
        w.uaWrap(u, o, auth);
    }

    function test_derivedHolder_intoItself_feeToTheSubmitter() public {
        ITradeToken.UATradeOrder memory o = _o(wrpL, uaP, 1000, 1000, 3_000); // fee ⌈1000 · 0.3 %⌉ = 3
        uint256 pool = wrpL.balanceOf(POOL);
        vm.expectEmit(address(wrpL));
        emit IUnderlyingToken.UAWrapped(uaP, address(tok), 1000, 997); // net of the fee (W-Q)
        assertEq(_wrap(wrpL, o), 1000);
        assertEq(wrpL.balanceOfUA(uaP), 997);
        assertEq(wrpL.balanceOf(POOL), pool + 997);
        assertEq(wrpL.balanceOf(RELAYER), 3);
        assertEq(wrpL.totalSupply(), 1000);
        assertEq(tok.balanceOfUA(uaP), 9_000);
        assertEq(tok.balanceOf(address(wrpL)), 1000);
        (,, uint256 reserve,,) = wrpL.legOf(address(tok));
        assertEq(reserve, 1000);
        // the order is closed: a replay pulls nothing
        _wrapReverts(wrpL, address(tok), o,
            abi.encodeWithSelector(ITradeToken.OrderClosed.selector, tok.uaTradeOrderDigest(o)));
    }

    function test_rate_and_destinations() public {
        UnderlyingToken w = _wrapperAt(address(tok), 3, 2);
        ITradeToken.UATradeOrder memory o = _o(w, uaP, 1000, 1500, 0);
        o.destination = _pad(bob); // a native destination: ERC-20 units
        assertEq(_wrap(w, o), 1500);
        assertEq(w.balanceOf(bob), 1500);
        assertEq(w.balanceOf(POOL), 0);
        o = _o(w, _pad(alice), 1000, 1500, 0); // a native holder wraps straight into a UA
        o.destination = uaB;
        uint256 a = tok.balanceOf(alice);
        vm.expectEmit(address(w));
        emit IUnderlyingToken.UAWrapped(uaB, address(tok), 1000, 1500); // the credited id (W-Q)
        _wrap(w, o);
        assertEq(tok.balanceOf(alice), a - 1000);
        assertEq(w.balanceOfUA(uaB), 1500);
        assertEq(w.balanceOf(POOL), 1500);
    }

    function test_receiverChecks() public {
        ITradeToken.UATradeOrder memory o = _o(wrpL, uaP, 1000, 1000, 0);
        o.destination = bytes32(uint256(keccak256("unregistered")));
        _wrapReverts(wrpL, address(tok), o, abi.encodeWithSelector(IUALedger.UANotRegistered.selector, o.destination));
        o.destination = uaZ;
        _wrapReverts(wrpL, address(tok), o,
            abi.encodeWithSelector(IUALedger.UAKindNotAccepted.selector, uaZ, UAKinds.ZETHER_BN254));
        o.destination = _pad(POOL);
        _wrapReverts(wrpL, address(tok), o, abi.encodeWithSelector(IUALedger.UAPoolNotPayable.selector));
    }

    function test_legAndOrderChecks() public {
        // an outside leg (`wrp` wraps the mock `und`): not a ledger token
        ITradeToken.UATradeOrder memory o = _o(wrp, uaP, 1000, 1000, 0);
        _wrapReverts(wrp, address(und), o, abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(und)));
        // the native leg is never gasless
        o = _o(wrpN, uaP, 1000, 1000, 0);
        _wrapReverts(wrpN, address(0), o, abi.encodeWithSelector(IUnderlyingToken.NativeNotGasless.selector));
        // the order must buy this wrapper
        o = _o(wrpL, uaP, 1000, 1000, 0);
        o.receiveToken = address(wrp);
        _wrapReverts(wrpL, address(tok), o, abi.encodeWithSelector(IUnderlyingToken.WrapOrderInvalid.selector, address(wrp)));
        // the underlying's checks: the signed minimum, the purpose
        o = _o(wrpL, uaP, 1000, 1001, 0);
        _wrapReverts(wrpL, address(tok), o,
            abi.encodeWithSelector(ITradeToken.PriceLimit.selector, tok.uaTradeOrderDigest(o)));
        o = _o(wrpL, uaP, 1000, 1000, 0);
        bytes memory meta = _auth(lreg, UAKinds.P256, _key(UAKinds.P256), UAKinds.PURPOSE_METATX, tok.uaTradeOrderDigest(o));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        vm.prank(RELAYER);
        wrpL.uaWrap(address(tok), o, meta);
        o.relayer = address(0xBAD);
        _wrapReverts(wrpL, address(tok), o,
            abi.encodeWithSelector(ITradeToken.WrongRelayer.selector, tok.uaTradeOrderDigest(o), RELAYER));
    }

    /// A wrapper whose own ledger is off mints to a native destination, and refuses a derived one (`UALedgerOff`).
    function test_ledgerOffWrapper() public {
        UnderlyingToken w = UnderlyingToken(Clones.clone(address(
            new UnderlyingToken(1, plainEnv(address(this), address(0), chainUidA, address(0), false), ""))));
        address[] memory us = new address[](1);
        uint256[] memory one = new uint256[](1);
        (us[0], one[0]) = (address(tok), 1);
        Rate memory fixedRate;
        w.initialize(address(this), 1, abi.encode(underlyingInit(us, one, one, 6, fixedRate, address(0), address(0))));
        ITradeToken.UATradeOrder memory o = _o(w, uaP, 1000, 1000, 0);
        _wrapReverts(w, address(tok), o, abi.encodeWithSelector(IUALedger.UALedgerOff.selector));
        o.destination = _pad(bob);
        _wrap(w, o);
        assertEq(w.balanceOf(bob), 1000);
    }
}
