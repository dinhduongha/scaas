// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture, Holder} from "./helpers/RegFixture.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {StubUARegistry} from "../helpers/Mocks.sol";
import {nid} from "../helpers/Ids.sol";

/// Plan T32 (owner 2026-11-05, CTR-GOV-20; regulated-kinds spec §3.1, §3.4; CTR-GOV-08's refusals, CTR-GOV-13): bit 22
/// `OPERATOR_TRANSFER` on kinds 8 and 9. Any holder (here an EOA clerk), `WHOLE` or `LIMITED` with a daily `perWindow`; the
/// move is `_uaMove`, hooked, so `P`, `F(from)` and `R(to)` apply; the refusals: 0, `from == to`, 0 / pools / the token on
/// either side, a native `from` with code, an unregistered or non-SIGNING derived `to`, `ref` 0. Bit 21 `MODERATE` has no
/// body; the plain kinds have no entry. Each refusal has its positive control.
contract OperatorTransferTest is RegFixture {
    uint8 internal constant OP = GovernanceBits.OPERATOR_TRANSFER;
    uint128 internal constant NONE = type(uint128).max;
    address internal clerk = address(0xC1E2); // an EOA: no code
    address internal carol = address(0xCA201);
    address[2] internal ts;
    bytes32 internal a;
    bytes32 internal b;

    function setUp() public override {
        super.setUp();
        (a, b) = (nid(alice), nid(bob));
        ts[0] = _opToken(0, 0, "o8");
        ts[1] = _opToken(1, 0, "o9");
        for (uint256 i; i < 2; ++i) _grant(ts[i], nid(clerk));
    }

    /// Kind 8 (`i == 0`) or 9 as the fixture's, with bit 22 and, when `denied != 0`, `DENYLIST` on `creg`.
    function _opToken(uint256 i, uint64 denied, bytes32 salt) internal returns (address t) {
        IFactoryToken.TokenConfig memory c = i == 0 ? _cfg8() : _cfg9();
        c.features |= uint256(1) << OP;
        if (denied != 0) {
            c.features |= uint256(1) << GovernanceBits.DENYLIST;
            (c.reg.complianceRegistry, c.reg.deniedFlags) = (address(creg), denied);
        }
        t = f.createToken(i == 0 ? IOpenFactory.TokenKind.NORMAL_REGULATED : IOpenFactory.TokenKind.WRAPPED_REGULATED, 1,
            abi.encode(c), salt);
        if (i == 1) _wrapFor(t, alice, SUPPLY);
    }

    /// `WHOLE` for `who`: a widening, so proposed, then confirmed after `grantDelay`.
    function _grant(address t, bytes32 who) internal {
        vm.prank(ownerA);
        MetaTokenBase(t).grantRole(OP, who);
        vm.warp(block.timestamp + GD);
        vm.prank(ownerA);
        MetaTokenBase(t).grantRole(OP, who);
        assertTrue(MetaTokenBase(t).hasRole(OP, who));
    }

    function _op(address t, bytes32 from, bytes32 to, uint256 amount) internal {
        vm.prank(clerk);
        _r(t).operatorTransfer(from, to, amount, REF);
    }

    function _refused(address t, bytes32 from, bytes32 to, uint256 amount, bytes32 ref, bytes memory err) internal {
        vm.prank(clerk);
        vm.expectRevert(err);
        _r(t).operatorTransfer(from, to, amount, ref);
    }

    /// The move and its event, native to native, native to derived, derived to derived (the UA ledger), derived to native.
    function test_operatorTransferMoves() public {
        bytes32 ux = UA_X;
        bytes32 uy = bytes32(uint256(UA_X) + 1);
        for (uint256 i; i < 2; ++i) {
            address t = ts[i];
            vm.expectEmit(t);
            emit IRegulatedToken.OperatorTransfer(a, b, 100, REF);
            _op(t, a, b, 100);
            assertEq(IERC20(t).balanceOf(alice), SUPPLY - 100);
            assertEq(IERC20(t).balanceOf(bob), 100);
            _op(t, a, ux, 50);
            assertEq(MetaTokenBase(t).balanceOfUA(ux), 50);
            _op(t, ux, uy, 20);
            assertEq(MetaTokenBase(t).balanceOfUA(ux), 30);
            assertEq(MetaTokenBase(t).balanceOfUA(uy), 20);
            _op(t, uy, b, 20);
            assertEq(IERC20(t).balanceOf(bob), 120);
            assertEq(IERC20(t).totalSupply(), SUPPLY, "a move, no mint or burn");
        }
    }

    /// `LIMITED` (CTR-GOV-20, the point-of-sale case): 100 a day over a 1-day window; 60 + 40, then 1 refused
    /// `GrantExhausted(3)` (the window), the next day 100 again.
    function test_limitedDailyWindow() public {
        address pos = address(0x9050);
        IGovernance.GrantTerms memory g;
        (g.max, g.perWindow, g.window) = (NONE, 100, 1 days);
        for (uint256 i; i < 2; ++i) {
            address t = ts[i];
            vm.prank(ownerA);
            MetaTokenBase(t).setGrant(OP, nid(pos), g);
            vm.warp(block.timestamp + GD);
            vm.prank(ownerA);
            MetaTokenBase(t).setGrant(OP, nid(pos), g);
            uint256 day = block.timestamp - block.timestamp % 1 days;
            vm.warp(day + 1 hours);
            vm.startPrank(pos);
            _r(t).operatorTransfer(a, b, 60, REF);
            _r(t).operatorTransfer(a, b, 40, REF);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(3)));
            _r(t).operatorTransfer(a, b, 1, REF);
            vm.warp(day + 1 days);
            _r(t).operatorTransfer(a, b, 100, REF);
            vm.stopPrank();
            assertEq(IERC20(t).balanceOf(bob), 200);
        }
    }

    /// The refusals of CTR-GOV-08 and `ref`, each next to a call that passes.
    function test_refusals() public {
        for (uint256 i; i < 2; ++i) {
            address t = ts[i];
            _refused(t, a, b, 0, REF, abi.encodeWithSelector(IRegulatedToken.AmountZero.selector));
            _refused(t, a, b, 1, 0, abi.encodeWithSelector(IRegulatedToken.RefRequired.selector));
            _refused(t, a, a, 1, REF, abi.encodeWithSelector(IRegulatedToken.OperatorTargetRefused.selector, a));
            bytes32[4] memory bad = [bytes32(0), MetaTxLib.pad(MetaTxLib.UA_POOL), MetaTxLib.pad(MetaTxLib.SHIELD_POOL),
                nid(t)];
            for (uint256 k; k < 4; ++k) {
                _refused(t, bad[k], b, 1, REF,
                    abi.encodeWithSelector(IRegulatedToken.OperatorTargetRefused.selector, bad[k]));
                _refused(t, a, bad[k], 1, REF,
                    abi.encodeWithSelector(IRegulatedToken.OperatorTargetRefused.selector, bad[k]));
            }
            _op(t, a, b, 1); // the control
        }
    }

    /// A native `from` with code (a Safe-held balance, a pool contract) is refused; an EOA `from` passes.
    function test_nativeFromWithCodeRefused() public {
        address safe = address(new Holder());
        for (uint256 i; i < 2; ++i) {
            address t = ts[i];
            vm.prank(alice);
            IERC20(t).transfer(safe, 10);
            _refused(t, nid(safe), b, 1, REF, abi.encodeWithSelector(IRegulatedToken.OperatorTargetRefused.selector, nid(safe)));
            vm.prank(alice);
            IERC20(t).transfer(bob, 10);
            _op(t, b, a, 1); // the control: an EOA
        }
    }

    /// A derived `to` must be a registered SIGNING UA (`_checkTo`): unregistered and non-SIGNING refused; a SIGNING one passes.
    function test_derivedToMustBeSigning() public {
        bytes32 uy = bytes32(uint256(UA_X) + 7);
        bytes32 uz = bytes32(uint256(UA_X) + 8);
        vm.mockCall(address(ureg), abi.encodeCall(StubUARegistry.kindOf, (uy)), abi.encode(uint16(0)));
        vm.mockCall(address(ureg), abi.encodeCall(StubUARegistry.kindOf, (uz)), abi.encode(uint16(0x0001)));
        for (uint256 i; i < 2; ++i) {
            address t = ts[i];
            _refused(t, a, uy, 1, REF, abi.encodeWithSelector(IUALedger.UANotRegistered.selector, uy));
            _refused(t, a, uz, 1, REF, abi.encodeWithSelector(IUALedger.UAKindNotAccepted.selector, uz, uint16(0x0001)));
            _op(t, a, UA_X, 1);
        }
    }

    /// The hooks of `_uaMove` (spec §3.2's row): a frozen `from` is refused (it cannot be moved past `F`), a frozen `to` still
    /// receives (credits are never refused for a freeze), a paused token refuses.
    function test_freezeAndPauseApply() public {
        for (uint256 i; i < 2; ++i) {
            address t = ts[i];
            _freeze(t, a);
            _refused(t, a, b, 1, REF, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, a));
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, a));
            IERC20(t).transfer(bob, 1); // as the holder's own send
            _unfreeze(t, a);
            _freeze(t, b);
            _op(t, a, b, 1); // a frozen receiver receives
            _unfreeze(t, b);
            _pause(t, _now() + 1 days);
            _refused(t, a, b, 1, REF,
                abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, _now() + 1 days));
            vm.warp(block.timestamp + 1 days);
            _op(t, a, b, 1); // the pause lapsed
        }
    }

    /// `R(to)` (CTR-GOV-18) with `DENYLIST`: a denied receiver is refused, an unlisted one passes; a denied `from` still sends.
    function test_receiverCheckApplies() public {
        for (uint256 i; i < 2; ++i) {
            address t = _opToken(i, SANCTIONED, bytes32(uint256(100 + i)));
            _grant(t, nid(clerk));
            _attest(nid(bob), SANCTIONED, type(uint64).max);
            _refused(t, a, b, 1, REF, abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, b, uint8(0)));
            _op(t, a, nid(carol), 2);
            _attest(nid(carol), SANCTIONED, type(uint64).max);
            _op(t, nid(carol), a, 1);
            _clearBob();
            _attestAs(cadmin, nid(carol), 0, 0);
        }
    }

    /// The role: a stranger is refused `MissingRole(22)`; a token without bit 22 refuses `FeatureNotSet(22)`.
    function test_roleAndFeature() public {
        address stranger = address(0x5742);
        for (uint256 i; i < 2; ++i) {
            vm.prank(stranger);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, OP, nid(stranger)));
            _r(ts[i]).operatorTransfer(a, b, 1, REF);
            vm.prank(clerk);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, OP));
            _r(_ks()[i]).operatorTransfer(a, b, 1, REF); // the fixture's tokens carry no bit 22
        }
    }

    /// Bit 21 `MODERATE` keeps its name and its contract-only rule and has no body (owner 2026-11-05): a contract holding
    /// bit 21 moves nothing through `operatorTransfer` (bit 22's), and no `moderatedTransfer` entry exists.
    function test_moderateHasNoBody() public {
        address mod = address(new Holder());
        for (uint256 i; i < 2; ++i) {
            IFactoryToken.TokenConfig memory c = i == 0 ? _cfg8() : _cfg9();
            c.features |= (uint256(1) << GovernanceBits.MODERATE) | (uint256(1) << OP);
            address t = f.createToken(i == 0 ? IOpenFactory.TokenKind.NORMAL_REGULATED
                : IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, abi.encode(c), bytes32(uint256(200 + i)));
            if (i == 1) _wrapFor(t, alice, SUPPLY);
            vm.prank(ownerA);
            MetaTokenBase(t).grantRole(GovernanceBits.MODERATE, nid(mod));
            vm.warp(block.timestamp + GD);
            vm.prank(ownerA);
            MetaTokenBase(t).grantRole(GovernanceBits.MODERATE, nid(mod));
            assertTrue(MetaTokenBase(t).hasRole(GovernanceBits.MODERATE, nid(mod)), "bit 21 held");
            vm.prank(mod);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, OP, nid(mod)));
            _r(t).operatorTransfer(a, b, 1, REF);
            (bool ok, bytes memory ret) = t.call(abi.encodeWithSignature("moderatedTransfer(bytes32,bytes32,uint256,bytes32)",
                a, b, uint256(1), REF));
            assertFalse(ok, "no moderatedTransfer entry");
            assertEq(ret.length, 0, "an unknown selector");
            _grant(t, nid(mod)); // the control: the same contract with bit 22 moves
            vm.prank(mod);
            _r(t).operatorTransfer(a, b, 1, REF);
        }
    }

    /// The plain kinds 0 and 1 have no `operatorTransfer` entry (bit 22 is outside their masks: `GovRegulatedBits`).
    function test_plainKindsHaveNoEntry() public {
        IOpenFactory.TokenKind[2] memory plain = [IOpenFactory.TokenKind.NORMAL, IOpenFactory.TokenKind.WRAPPED];
        for (uint256 i; i < 2; ++i) {
            (bool ok, bytes memory ret) = f.implementationOf(plain[i], 1).call(
                abi.encodeCall(IRegulatedToken.operatorTransfer, (a, b, 1, REF)));
            assertFalse(ok);
            assertEq(ret.length, 0);
            (ok, ret) = f.implementationOf(IOpenFactory.TokenKind.NORMAL_REGULATED, 1).call(
                abi.encodeCall(IRegulatedToken.operatorTransfer, (a, b, 1, REF)));
            assertFalse(ok);
            assertGt(ret.length, 0, "the control: the regulated release has the entry (a named refusal)");
        }
    }
}
