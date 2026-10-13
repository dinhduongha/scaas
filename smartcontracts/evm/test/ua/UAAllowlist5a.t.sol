// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";
import {UALedgerBase} from "./UALedgerBase.sol";

/// accounts.md CTR-UA-26 as grown by UA-5a (CTR-UA-27 "allowlist or dedicated function"): `burn` (`NONE*`) and
/// `unwrapToUA` (the wrappers) run under `uaExecute` / `uaBatch`; under a derived ticket each debits exactly the subject
/// through `UA_POOL`, and the fee (`AMOUNT(i)`) comes from the signer's UA balance after the call. The dedicated
/// functions (`wrapToUA`, `mintToUA`, `payWithFeeToUA`), `addReserve`, `approve` and `mtxTrade` stay off it.
contract UAAllowlist5aTest is UALedgerBase {
    function _exec(address token, MetaTxLib.UAMetaTransaction memory m, bytes memory err) internal {
        bytes memory a = _authM(token, m);
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(RELAYER);
        MetaTokenBase(token).uaExecute(m, a);
    }

    function _withFee(MetaTxLib.UAMetaTransaction memory m, uint256 fee)
        internal pure returns (MetaTxLib.UAMetaTransaction memory)
    {
        (m.mode, m.fee, m.feeRecipient) = (RR | RF | FIX, fee, FEE_TO);
        return m;
    }

    // ----- burn -----

    function test_uaExecute_burnUnderUA() public {
        _fund(uaP, 1_000);
        uint256 supply = tok.totalSupply();
        MetaTxLib.UAMetaTransaction memory m = _withFee(_m(address(tok), uaP, abi.encodeCall(NoUnderlyingToken.burn, (400))), 4);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(uaP, bytes32(0), 400);
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(POOL, address(0), 400);
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(POOL, FEE_TO, 4);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(uaP, _pad(FEE_TO), 4);
        _exec(address(tok), m, "");
        assertEq(tok.balanceOfUA(uaP), 596);
        assertEq(tok.balanceOf(POOL), 596);
        assertEq(tok.balanceOf(FEE_TO), 4);
        assertEq(tok.totalSupply(), supply - 400);
        // more than the UA holds: the burn through the pool refuses; the fee cap is `AMOUNT(0)`'s 1 %
        _exec(address(tok), _m(address(tok), uaP, abi.encodeCall(NoUnderlyingToken.burn, (597))),
            abi.encodeWithSelector(IUALedger.UAInsufficientBalance.selector, uaP, 596, 597));
        // `BURNABLE` off: the feature error of `burn`
        NoUnderlyingToken nb =
            NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(address(this), address(0), chainUidA, REG_L, false))));
        IFactoryToken.TokenConfig memory c = noneInit("NB", "NB", 6, 0, address(0), address(this));
        c.features = (1 << AdminLib.PAYABLE) | (1 << AdminLib.MINTABLE);
        nb.initialize(address(this), 1, c);
        nb.mintToUA(uaP, 10);
        _exec(address(nb), _m(address(nb), uaP, abi.encodeCall(NoUnderlyingToken.burn, (1))),
            abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, AdminLib.BURNABLE));
    }

    /// A native signer burns its own address balance (`mtxExecute` on the ids path).
    function test_uaExecute_burnNative() public {
        uint256 supply = tok.totalSupply();
        _exec(address(tok), _m(address(tok), _pad(alice), abi.encodeCall(NoUnderlyingToken.burn, (100))), "");
        assertEq(tok.balanceOf(alice), 1_000_000 - 100);
        assertEq(tok.totalSupply(), supply - 100);
    }

    // ----- unwrapToUA -----

    /// A UA unwraps `wrpL` into another UA: its burn through the pool, the leg's `transferToUA`, the fee after.
    function test_uaExecute_unwrapToUAUnderUA() public {
        _wrapL(alice, 10_000);
        vm.prank(alice);
        wrpL.transferToUA(uaP, 10_000);
        bytes memory data = abi.encodeCall(UnderlyingToken.unwrapToUA, (address(tok), 4_000, uaB, 4_000));
        MetaTxLib.UAMetaTransaction memory m = _m(address(wrpL), uaP, data);
        (m.mode, m.fee, m.feeRecipient) = (RR | RF | PCT, 10_000, FEE_TO); // 1 % of `wrapped`
        vm.expectEmit(address(wrpL));
        emit IUALedger.UATransfer(uaP, bytes32(0), 4_000);
        vm.expectEmit(address(wrpL));
        emit IERC20.Transfer(POOL, address(0), 4_000);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(_pad(address(wrpL)), uaB, 4_000);
        vm.expectEmit(address(wrpL));
        emit IUnderlyingToken.UnwrappedToUA(POOL, address(tok), uaB, 4_000, 4_000);
        _exec(address(wrpL), m, "");
        assertEq(wrpL.balanceOfUA(uaP), 10_000 - 4_000 - 40);
        assertEq(wrpL.balanceOf(FEE_TO), 40);
        assertEq(wrpL.totalSupply(), 6_000);
        assertEq(tok.balanceOfUA(uaB), 4_000);
        assertEq(tok.balanceOf(address(wrpL)), 6_000);
        (,, uint256 reserve,,) = wrpL.legOf(address(tok));
        assertEq(reserve, 6_000);
    }

    /// At 3/2 under `uaExecute`: `unwrapToUA(1000)` burns ⌈666·3/2⌉ = 999 from the UA, pays out 666 in `tok`; the
    /// `AMOUNT(1)` fee (1 % of `wrapped` = 10) comes after.
    function test_uaExecute_unwrapToUA_rate32() public {
        UnderlyingToken w = _wrapperAt(address(tok), 3, 2);
        _wrapLOn(w, alice, 1_001);
        vm.prank(alice);
        w.transferToUA(uaP, 1_501);
        MetaTxLib.UAMetaTransaction memory m =
            _m(address(w), uaP, abi.encodeCall(UnderlyingToken.unwrapToUA, (address(tok), 1_000, uaB, 666)));
        (m.mode, m.fee, m.feeRecipient) = (RR | RF | PCT, 10_000, FEE_TO);
        vm.expectEmit(address(w));
        emit IUALedger.UATransfer(uaP, bytes32(0), 999);
        vm.expectEmit(address(w));
        emit IERC20.Transfer(POOL, address(0), 999);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(_pad(address(w)), uaB, 666);
        vm.expectEmit(address(w));
        emit IUnderlyingToken.UnwrappedToUA(POOL, address(tok), uaB, 999, 666);
        vm.expectEmit(address(w));
        emit IERC20.Transfer(POOL, FEE_TO, 10);
        _exec(address(w), m, "");
        assertEq(w.balanceOfUA(uaP), 1_501 - 999 - 10);
        assertEq(w.balanceOf(FEE_TO), 10);
        assertEq(w.totalSupply(), 1_501 - 999);
        assertEq(tok.balanceOfUA(uaB), 666);
        assertEq(tok.balanceOf(address(w)), 1_001 - 666);
        (,, uint256 reserve,,) = w.legOf(address(tok));
        assertEq(reserve, 1_001 - 666);
    }

    function test_uaExecute_unwrapToUA_nativeToRefused() public {
        _wrapL(alice, 100);
        vm.prank(alice);
        wrpL.transferToUA(uaP, 100);
        _exec(address(wrpL), _m(address(wrpL), uaP, abi.encodeCall(UnderlyingToken.unwrapToUA, (address(tok), 10, _pad(bob), 0))),
            abi.encodeWithSelector(IUALedger.UANotRegistered.selector, _pad(bob)));
        assertEq(wrpL.balanceOfUA(uaP), 100);
    }

    // ----- refusals -----

    /// The dedicated functions, `addReserve`, `approve` and `mtxTrade` are off the UA allowlist, for a derived and a
    /// native `from`.
    function test_uaAllowlist_refusals() public {
        _fund(uaP, 10);
        address[6] memory on = [address(wrp), address(tok), address(tok), address(wrp), address(tok), address(tok)];
        bytes[6] memory calls = [
            abi.encodeCall(UnderlyingToken.wrapToUA, (address(und), 1, uaB)),
            abi.encodeCall(NoUnderlyingToken.mintToUA, (uaB, 1)),
            abi.encodeCall(MetaTokenBase.payWithFeeToUA, (uaB, 1, FeeMode.NONE, 0, address(0), bytes32("ref"))),
            abi.encodeWithSignature("addReserve(address,uint256)", address(und), 1),
            abi.encodeCall(IERC20.approve, (address(this), 1)),
            abi.encodeWithSelector(ITradeToken.mtxTrade.selector)
        ];
        bytes32[2] memory froms = [uaP, _pad(alice)];
        for (uint256 f; f < 2; ++f) {
            for (uint256 i; i < calls.length; ++i) {
                _exec(on[i], _m(on[i], froms[f], calls[i]),
                    abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, bytes4(calls[i])));
            }
        }
    }

    // ----- batches -----

    /// One atomic batch, a fresh ticket per item: one failing item reverts every item.
    function test_uaBatch_burnAndUnwrapToUA() public {
        _fund(uaP, 100);
        _wrapL(alice, 100);
        vm.prank(alice);
        wrpL.transferToUA(uaP, 100);
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](2);
        bytes[] memory as_ = new bytes[](2);
        ms[0] = _m(address(wrpL), uaP, abi.encodeCall(UnderlyingToken.unwrapToUA, (address(tok), 60, uaB, 0)));
        ms[1] = _m(address(wrpL), uaP, abi.encodeCall(UnderlyingToken.unwrapToUA, (address(tok), 60, uaB, 0)));
        ms[1].nonce = 1;
        (as_[0], as_[1]) = (_authM(address(wrpL), ms[0]), _authM(address(wrpL), ms[1]));
        // the second item asks for more than is left (the reserve, 1:1 with the supply, is checked first)
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.InsufficientReserve.selector, address(tok), 60, 40));
        vm.prank(RELAYER);
        wrpL.uaBatch(ms, as_);
        assertEq(wrpL.balanceOfUA(uaP), 100);
        ms[1] = _m(address(wrpL), uaP, abi.encodeCall(UnderlyingToken.unwrapToUA, (address(tok), 40, uaB, 0)));
        ms[1].nonce = 1;
        as_[1] = _authM(address(wrpL), ms[1]);
        vm.prank(RELAYER);
        wrpL.uaBatch(ms, as_);
        assertEq(wrpL.balanceOfUA(uaP), 0);
        assertEq(tok.balanceOfUA(uaB), 100);
        ms[0] = _m(address(tok), uaP, abi.encodeCall(NoUnderlyingToken.burn, (30)));
        ms[1] = _m(address(tok), uaP, abi.encodeCall(NoUnderlyingToken.burn, (70)));
        ms[1].nonce = 1;
        (as_[0], as_[1]) = (_authM(address(tok), ms[0]), _authM(address(tok), ms[1]));
        vm.prank(RELAYER);
        tok.uaBatch(ms, as_);
        assertEq(tok.balanceOfUA(uaP), 0);
        assertEq(tok.balanceOf(POOL), 100); // uaB's
    }
}
