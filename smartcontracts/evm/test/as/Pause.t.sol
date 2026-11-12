// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../../src/metatx/ERC20MetaTx.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// A contract caller for `approve` (an EOA neither grants nor holds an allowance).
contract Approver {
    function approve(address t, address spender) external {
        IERC20(t).approve(spender, 1);
    }
}

/// Plan T28 (regulated-kinds spec §3.2, §3.4, CTR-AS-06, RK-7, I4): `pause` / `unpause` and their bounds; while paused the
/// ledger rows refuse `TokenPaused(pausedUntil)` but the holder's burn and unwrap; the pause-open set by the inner selector
/// on the named, generic and address paths at fee mode `NONE`, each refused with a fee; `cancelNonce` refused.
contract PauseTest is RegFixture {
    string constant E = "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    uint32 constant FIX = MetaTxLib.MODE_FEE_FIXED;
    uint64 until;

    function setUp() public override {
        super.setUp();
        until = _now() + 7 days;
    }

    /// `ref != 0`; `now < until <= now + 7 d` (`PauseTooLong(now + 7 d)`); the cooldown `until + 7 d` refuses a pause while
    /// paused and until 7 d after its end; `Paused`; expiry is passive.
    function test_pauseBounds() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            vm.startPrank(issuer);
            vm.expectRevert(IRegulatedToken.RefRequired.selector);
            _r(t).pause(0, until);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.PauseTooLong.selector, until));
            _r(t).pause(REF, until + 1);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.PauseTooLong.selector, until));
            _r(t).pause(REF, _now());
            vm.expectEmit(t);
            emit IRegulatedToken.Paused(REF, until);
            _r(t).pause(REF, until);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.PauseCooldown.selector, until + 7 days));
            _r(t).pause(REF, _now() + 1);
            vm.stopPrank();
            IRegulatedToken.RegulatedConfig memory c = _r(t).regulatedConfig();
            assertEq(c.pausedUntil, until);
            assertEq(c.pauseCooldownUntil, until + 7 days);
            vm.warp(until);
            vm.prank(alice);
            IERC20(t).transfer(bob, 1); // passive expiry
            vm.warp(until + 7 days - 1);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.PauseCooldown.selector, until + 7 days));
            _r(t).pause(REF, _now() + 1);
            vm.warp(until + 7 days);
            _pause(t, _now() + 1); // the control
            vm.warp(1_800_000_000);
        }
    }

    /// `unpause`: paused (`NotPaused` otherwise); `pausedUntil = now`, the cooldown from now; `Unpaused`.
    function test_unpause() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            vm.prank(issuer);
            vm.expectRevert(IRegulatedToken.NotPaused.selector);
            _r(t).unpause(REF);
            _pause(t, until);
            vm.warp(_now() + 1 days);
            vm.expectEmit(t);
            emit IRegulatedToken.Unpaused(REF);
            vm.prank(issuer);
            _r(t).unpause(REF);
            IRegulatedToken.RegulatedConfig memory c = _r(t).regulatedConfig();
            assertEq(c.pausedUntil, _now());
            assertEq(c.pauseCooldownUntil, _now() + 7 days);
            vm.prank(alice);
            IERC20(t).transfer(bob, 1);
            vm.warp(1_800_000_000);
        }
    }

    /// While paused: a transfer (refused before the move, by the real `pausedUntil`), a mint, a contract's `approve`, a
    /// `transferToUA`; the holder's burn (8) and unwrap (9) pass, since a burn is never paused (spec §3.2).
    function test_ledgerRowsUnderPause() public {
        Approver ap = new Approver();
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            vm.prank(alice);
            IERC20(t).transfer(address(ap), 10);
            _pause(t, until);
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until));
            IERC20(t).transfer(bob, 1);
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until));
            NormalToken(t).transferToUA(UA_X, 1);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until));
            ap.approve(t, address(f));
            if (t == t8) {
                vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until));
                NormalToken(t).mint(bob, 1);
                vm.prank(alice);
                NormalToken(t).burn(10);
            } else {
                vm.prank(alice);
                WrappedToken(payable(t)).unwrap(5, alice);
                vm.prank(alice);
                WrappedToken(payable(t)).unwrap(address(usd), 5, alice, 5);
                assertEq(usd.balanceOf(alice), 10);
            }
            assertEq(IERC20(t).balanceOf(alice), SUPPLY - 20);
        }
    }

    /// `P` needs a live issuer root of bit 7 (spec §3.2).
    function test_pauseNeedsALiveRoot() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            _pause(t, until);
            vm.prank(ownerA);
            NormalToken(t).revokeRole(7, nid(issuer), EnvKit.codeUidOf(address(NormalToken(t))));
            vm.warp(_now() + GD);
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until));
            IERC20(t).transfer(bob, 1); // proposed only: still paused
            vm.prank(ownerA);
            NormalToken(t).revokeRole(7, nid(issuer), EnvKit.codeUidOf(address(NormalToken(t))));
            vm.prank(alice);
            IERC20(t).transfer(bob, 1);
            vm.warp(1_800_000_000);
        }
    }

    // ------------------------------------------------------------------ the pause-open set (RK-7, Codex 5, Q6)

    /// Kind 8, `burn(uint256)` at fee `NONE`, under `P`: the named `mtxBurn`, the generic `mtxExecute`, the address
    /// `executeMetaTransaction` each burn.
    function test_pauseOpenBurn_8() public {
        _pause(t8, until);
        MetaTxLib.UAEnvelope memory e = _env(alice, 0, 0);
        IUARegistry.UASig memory s = _namedSig(ALICE_PK, t8, string.concat("UABurn(bytes32 from,uint256 amount,", E), e,
            abi.encode(uint256(3)));
        vm.prank(relayer);
        NormalToken(t8).mtxBurn(e, 3, s);
        MetaTxLib.UAMetaTransaction memory m = _uaTx(alice, abi.encodeWithSignature("burn(uint256)", 4), 0, 0);
        IUARegistry.UASig memory ms = _uaSig(ALICE_PK, t8, m);
        vm.prank(relayer);
        UAMetaTxBase(t8).mtxExecute(m, ms);
        MetaTxLib.MetaTransaction memory am = _addrTx(alice, abi.encodeWithSignature("burn(uint256)", 5), 0, 0);
        bytes memory as_ = _addrSig(ALICE_PK, t8, am);
        vm.prank(relayer);
        IMetaTx(t8).executeMetaTransaction(am, as_);
        assertEq(IERC20(t8).balanceOf(alice), SUPPLY - 12);
    }

    /// Kind 9, `unwrap(uint256,address,uint256)` and `unwrap(address,uint256,address,uint256)` at fee `NONE`, under `P`:
    /// named, generic and address paths each pay out; `unwrapToUA`'s named entry passes the pre row (its garbage signature
    /// fails in the pipeline, not `TokenPaused`).
    function test_pauseOpenUnwrap_9() public {
        _pause(t9, until);
        MetaTxLib.UAEnvelope memory e = _env(alice, 0, 0);
        IUARegistry.UASig memory s = _namedSig(ALICE_PK, t9, string.concat(
            "UAUnwrap(bytes32 from,uint256 wrapped,address recipient,uint256 minOut,", E), e, abi.encode(uint256(3), bob, uint256(3)));
        vm.prank(relayer);
        WrappedToken(payable(t9)).mtxUnwrap(e, 3, bob, 3, s);
        e.nonce = 1;
        s = _namedSig(ALICE_PK, t9, string.concat(
            "UAUnwrapLeg(bytes32 from,address underlying,uint256 wrapped,address recipient,uint256 minOut,", E), e,
            abi.encode(address(usd), uint256(4), bob, uint256(4)));
        vm.prank(relayer);
        WrappedToken(payable(t9)).mtxUnwrapLeg(e, address(usd), 4, bob, 4, s);
        MetaTxLib.UAMetaTransaction memory m =
            _uaTx(alice, abi.encodeWithSignature("unwrap(uint256,address,uint256)", 5, bob, 5), 0, 0);
        IUARegistry.UASig memory ms = _uaSig(ALICE_PK, t9, m);
        vm.prank(relayer);
        UAMetaTxBase(t9).mtxExecute(m, ms);
        MetaTxLib.MetaTransaction memory am =
            _addrTx(alice, abi.encodeWithSignature("unwrap(uint256,address,uint256)", 6, bob, 6), 0, 0);
        bytes memory as_ = _addrSig(ALICE_PK, t9, am);
        vm.prank(relayer);
        IMetaTx(t9).executeMetaTransaction(am, as_);
        assertEq(usd.balanceOf(bob), 18);
        e.nonce = 2;
        bytes4 err = _try(t9, abi.encodeCall(WrappedToken.mtxUnwrapToUA, (e, address(usd), 1, UA_X, 1, _bad())));
        assertTrue(err != 0 && err != IRegulatedToken.TokenPaused.selector, "unwrapToUA passes the pre row");
    }

    /// Each pause-open op with a fee (fee-bearing: a `FIXED` mode, here fee 1) is refused `TokenPaused` before the
    /// signature, on every path; at fee `NONE` the same garbage-signed calls fail in the pipeline instead (the control).
    function test_pauseOpenRefusedWithAFee() public {
        _pause(t8, until);
        _pause(t9, until);
        for (uint256 fee; fee < 2; ++fee) {
            uint32 mode = fee == 0 ? 0 : FIX;
            bytes[] memory c = new bytes[](8);
            MetaTxLib.UAEnvelope memory e = _env(alice, mode, fee);
            c[0] = abi.encodeCall(NormalToken.mtxBurn, (e, 1, _bad()));
            c[1] = abi.encodeCall(UAMetaTxBase.mtxExecute, (_uaTx(alice, abi.encodeWithSignature("burn(uint256)", 1), mode, fee), _bad()));
            c[2] = abi.encodeCall(IMetaTx.executeMetaTransaction, (_addrTx(alice, abi.encodeWithSignature("burn(uint256)", 1), mode, fee), new bytes(65)));
            c[3] = abi.encodeCall(WrappedToken.mtxUnwrap, (e, 1, bob, 0, _bad()));
            c[4] = abi.encodeCall(WrappedToken.mtxUnwrapLeg, (e, address(usd), 1, bob, 0, _bad()));
            c[5] = abi.encodeCall(WrappedToken.mtxUnwrapToUA, (e, address(usd), 1, UA_X, 0, _bad()));
            bytes memory un = abi.encodeWithSignature("unwrap(uint256,address,uint256)", 1, bob, 0);
            c[6] = abi.encodeCall(UAMetaTxBase.mtxExecute, (_uaTx(alice, un, mode, fee), _bad()));
            c[7] = abi.encodeCall(IMetaTx.executeMetaTransaction, (_addrTx(alice, un, mode, fee), new bytes(65)));
            for (uint256 k; k < 8; ++k) {
                bytes4 err = _try(k < 3 ? t8 : t9, c[k]);
                if (fee == 0) assertTrue(err != 0 && err != IRegulatedToken.TokenPaused.selector, "fee NONE: open");
                else assertEq(err, IRegulatedToken.TokenPaused.selector, "with a fee: paused");
            }
        }
    }

    /// The set is matched on the inner selector, never the outer entry: a paused transfer inside `mtxExecute`, and
    /// `cancelNonce` (not in the set, RK-8), are refused at fee `NONE`.
    function test_pauseClosedOnOtherSelectors() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            _pause(t, until);
            bytes memory tr = abi.encodeWithSignature("transfer(address,uint256)", bob, 1);
            assertEq(_try(t, abi.encodeCall(UAMetaTxBase.mtxExecute, (_uaTx(alice, tr, 0, 0), _bad()))),
                IRegulatedToken.TokenPaused.selector);
            assertEq(_try(t, abi.encodeCall(UAMetaTxBase.mtxCancelNonce, (_env(alice, 0, 0), 9, _bad()))),
                IRegulatedToken.TokenPaused.selector, "cancelNonce is not pause-open");
            MetaTxLib.UAMetaTransfer memory x;
            (x.from, x.to, x.value, x.batch, x.validUntil) = (nid(alice), nid(bob), 1, 1, block.timestamp + 60);
            assertEq(_try(t, abi.encodeCall(NormalToken.mtxExecuteTransfer, (x, _bad()))),
                IRegulatedToken.TokenPaused.selector, "a typed transfer (sel 0)");
        }
    }
}
