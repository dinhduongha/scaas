// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzOffchainBase} from "../helpers/PqzOffchainBase.sol";
import {PqzFeeHandler} from "./PqzFeeHandler.t.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {OpenFactory} from "../../../src/factory/OpenFactory.sol";
import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../../src/pqz/WrappedPqzToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {Catalogue, pqzEnv} from "../../helpers/Catalogue.sol";
import {EnvKit} from "../../helpers/EnvKit.sol";
import {nid} from "../../helpers/Ids.sol";
import {PQZ_UID} from "../helpers/PqzRegistryBase.sol";
import {MockERC20} from "../../helpers/Mocks.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";

/// Round 3t (verifier fee spec §15 (8), controller A1-A3): F1 `balanceOf(SHIELD_POOL) == totalShielded · shieldScale`; F2
/// `totalShielded ==` Σ ghost hidden balances; F3 Σ public payouts `== Σ (fee + amount) · s` and `Σ shields + Σ shieldIn −
/// Σ (fee + amount) == totalShielded`; F4 `totalSupply` moves only by wraps, mints and unwraps (a payout of `vf` to the zero id,
/// a burn, would move it: I-V3); F5 no debit landed with `T < v + fee`, and no honest one refused; F6 every fee word is `txFee
/// + vf_now (+ M·d)` and no held op lands after a fee change, `d` shifted included; I-V1 `verifierFeeMax` never moves; I-V2 a
/// `PRECOMPILE` token's fee stays 0. Over `PqzFeeHandler` on a `PRECOMPILE` and an `OFFCHAIN` kind 4 token and an `OFFCHAIN`
/// kind 5 token (fee 3, cap 9, notice 1 day). Mocked proofs under the honest model. UNAUDITED.
/// forge-config: default.invariant.runs = 64
/// forge-config: default.invariant.depth = 128
contract PqzFeeInvariantsTest is PqzOffchainBase {
    uint64 internal constant FEE0 = 3;
    uint64 internal constant CAP = 9;
    PqzFeeHandler internal h;
    OpenFactory internal fN;

    function _cfg(uint256 m) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = super._cfg(m);
        c.admin = nid(address(h));
    }

    function setUp() public {
        _offStack();
        aMode = 0; // no auditor: the handler's ops carry no auditor copies
        h = new PqzFeeHandler(reg, alice, bob, carol, _mldsaUA(9));
        fN = new OpenFactory(nid(registrar));
        EnvKit.configure(fN, PQZ_UID, 1 days, address(0));
        Catalogue.release(fN, IOpenFactory.TokenKind.NORMAL_PQZ, 1, pqzEnv(address(fN), PQZ_UID, address(reg), address(pqv)),
            type(NormalPqzToken).creationCode);
        Catalogue.release(fN, IOpenFactory.TokenKind.WRAPPED_PQZ, 1, pqzEnv(address(fN), PQZ_UID, address(reg), address(pqv)),
            type(WrappedPqzToken).creationCode);
        vm.startPrank(registrar);
        fN.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true);
        fN.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ, true);
        vm.stopPrank();
        vm.warp(block.timestamp + 1 days); // the releases usable
        NormalPqzToken pre = NormalPqzToken(fN.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1,
            abi.encode(_cfg(uint256(1) << 40)), "fee-pre"));
        (vMode, vUA, vFixed, vFee, vFeeMax) = (PqzCore.OFFCHAIN, vA, false, FEE0, CAP);
        NormalPqzToken off = NormalPqzToken(fN.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1,
            abi.encode(_cfg(uint256(1) << 40)), "fee-off"));
        IFactoryToken.TokenConfig memory cw = _cfg(uint256(1) << 40);
        (vMode, vUA, vFixed, vFee, vFeeMax) = (0, bytes32(0), false, 0, 0);
        _factory = fN;
        WrappedPqzToken offW = _wrappedOn(cw);
        _public(pre, address(h), 1_000_000 * SCALE);
        _public(off, address(h), 1_000_000 * SCALE);
        h.setTokens(pre, off, offW);
        for (uint256 t; t < 3; ++t) for (uint256 j; j < 3; ++j) h.shield(t, j, 500);
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](8);
        (sel[0], sel[1], sel[2], sel[3]) = (h.shield.selector, h.debit.selector, h.feeDecrease.selector, h.feePropose.selector);
        (sel[4], sel[5], sel[6], sel[7]) = (h.feeConfirm.selector, h.warp.selector, h.hold.selector, h.replay.selector);
        targetSelector(FuzzSelector(address(h), sel));
    }

    OpenFactory internal _factory;

    /// A `WRAPPED_PQZ` token of `cw` on `fN` with one 1:1 `MockERC20` leg (the fixture's `_newWrapped`, on this factory).
    function _wrappedOn(IFactoryToken.TokenConfig memory c) internal returns (WrappedPqzToken) {
        c.features = 1 << GovernanceBits.PAYABLE;
        c.lockedFeatures = 0;
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
        return WrappedPqzToken(payable(_factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), "fee-offw")));
    }

    function _all(function(uint256) view f) internal view {
        for (uint256 t; t < 3; ++t) f(t);
    }

    function _f1(uint256 t) internal view {
        NormalPqzToken k = h.toks(t);
        assertEq(k.balanceOf(MetaTxLib.SHIELD_POOL), k.totalShielded() * SCALE, "F1: pool = totalShielded * scale");
    }

    function _f2(uint256 t) internal view {
        assertEq(h.toks(t).totalShielded(), h.hidden(t), "F2: totalShielded = the ghost hidden balances");
    }

    function _f3(uint256 t) internal view {
        assertEq(h.paidPublic(t), h.outs(t) * SCALE, "F3: the payouts = (fee + amount) * s");
        assertEq(h.shields(t) + h.shieldIns(t) - h.outs(t), h.toks(t).totalShielded(), "F3: shields + shieldIn - out");
    }

    function _f4(uint256 t) internal view {
        assertEq(h.toks(t).totalSupply(), h.supplyWant(t), "F4 / I-V3: totalSupply by wraps, mints and unwraps only");
    }

    function invariant_F1_pool() public view { _all(_f1); }
    function invariant_F2_hidden() public view { _all(_f2); }
    function invariant_F3_payouts() public view { _all(_f3); }
    function invariant_F4_supply() public view { _all(_f4); }

    function invariant_F5_honest() public view {
        assertEq(h.landedShort(), 0, "F5: a debit landed with T < v + fee");
        assertEq(h.refusedHonest(), 0, "F5: an honest debit refused");
    }

    function invariant_F6_feeWord() public view {
        assertEq(h.badWord(), 0, "F6: a fee word not txFee + vf (+ M d)");
        assertEq(h.replayLanded(), 0, "F6: a held op landed after a fee change");
    }

    function invariant_IV1_IV2() public view {
        assertEq(h.toks(1).pqzVerifyConfig().verifierFeeMax, CAP, "I-V1");
        assertEq(h.toks(2).pqzVerifyConfig().verifierFeeMax, CAP, "I-V1");
        assertEq(h.toks(0).pqzVerifyConfig().verifierFee, 0, "I-V2");
        assertEq(h.toks(0).pqzVerifyConfig().verifierFeeMax, 0, "I-V2");
    }

    /// The control: a fixed sequence lands debits of every kind on the three tokens, a fee decrease, a proposal confirmed
    /// after the notice, a held op 7 refused after the change (and with `d` shifted); every ghost still 0.
    function test_handler_acts() public {
        for (uint256 k; k < 5; ++k) h.debit(2, 0, k, 7 + k * 1000);
        h.debit(0, 1, 0, 11);
        h.debit(1, 2, 1, 13 << 16);
        h.hold(0, 0, 1);
        h.feeDecrease(0, 1);
        h.replay();
        h.feePropose(1, 0);
        h.warp(1 days);
        h.feeConfirm(1);
        h.debit(2, 1, 2, 5);
        assertGe(h.debits(), 8, "debits landed");
        assertEq(h.feeMoves(), 2, "a decrease and a confirmed increase");
        assertEq(h.landedShort() + h.refusedHonest() + h.badWord() + h.replayLanded(), 0, "every ghost 0");
        invariant_F1_pool();
        invariant_F2_hidden();
        invariant_F3_payouts();
        invariant_F4_supply();
    }
}
