// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalToken} from "../../src/metatx/NormalToken.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// Plan T28 (regulated-kinds spec §3.3 "forceTransfer", CTR-AS-04, F-08): the issuer moves a frozen subject's public
/// balance to the record's beneficiary on `_poolMove`, within `maxAmount`, while `RECORD` is active; kinds 8 and 9.
contract ForceTest is RegFixture {
    bytes32 a;
    bytes32 b;

    function setUp() public override {
        super.setUp();
        (a, b) = (nid(alice), nid(bob));
    }

    function _seized(address t, uint256 maxAmount) internal returns (bytes32 r) {
        r = _order(t, "o1", a, b, maxAmount, _now() + 90 days);
        _freezeRecord(t, a, r);
    }

    /// The move, `ForcedTransfer`, `executed` accumulated, then `OrderExceeded(remaining)`; the frozen subject's own send
    /// stays refused.
    function test_forceTransfer() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _seized(t, 100);
            vm.expectEmit(t);
            emit IRegulatedToken.ForcedTransfer(r, a, b, 60);
            vm.prank(issuer);
            _r(t).forceTransfer(r, 60);
            assertEq(IERC20(t).balanceOf(bob), 60);
            assertEq(IERC20(t).balanceOf(alice), SUPPLY - 60);
            assertEq(_r(t).order(r).executed, 60);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderExceeded.selector, 40));
            _r(t).forceTransfer(r, 41);
            vm.prank(issuer);
            _r(t).forceTransfer(r, 40);
            assertEq(_r(t).order(r).executed, 100);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderExceeded.selector, 0));
            _r(t).forceTransfer(r, 1);
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, a));
            IERC20(t).transfer(bob, 1);
        }
    }

    /// F-08: an amount of 0 is refused; 1 passes (the control).
    function test_forceZeroRefused() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _seized(t, 100);
            vm.prank(issuer);
            vm.expectRevert(IRegulatedToken.AmountZero.selector);
            _r(t).forceTransfer(r, 0);
            vm.prank(issuer);
            _r(t).forceTransfer(r, 1);
        }
    }

    /// The subject must be frozen when the move runs (`SubjectNotFrozen`): after the freeze expires, and after `unfreeze`.
    function test_subjectNotFrozenRefused() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _order(t, "o1", a, b, 100, _now() + 90 days);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.SubjectNotFrozen.selector, a));
            _r(t).forceTransfer(r, 1);
            _freeze(t, a); // issuer-only counts too: F(subject)
            vm.prank(issuer);
            _r(t).forceTransfer(r, 1);
            _unfreeze(t, a);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.SubjectNotFrozen.selector, a));
            _r(t).forceTransfer(r, 1);
        }
    }

    /// `!F(beneficiary)`: a frozen beneficiary is refused `Frozen(beneficiary)`.
    function test_frozenBeneficiaryRefused() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _seized(t, 100);
            _freeze(t, b);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, b));
            _r(t).forceTransfer(r, 1);
            _unfreeze(t, b);
            vm.prank(issuer);
            _r(t).forceTransfer(r, 1);
        }
    }

    /// `RECORD` active needs a live compliance root (spec §3.3): once the only compliance holder renounces (bit 10 is not
    /// delayed), `FORCE` stops; the record itself is unchanged.
    function test_recordRootRequired() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _seized(t, 100);
            vm.prank(issuer);
            _r(t).forceTransfer(r, 1);
            vm.prank(compliance);
            NormalToken(t).renounceRole(10, EnvKit.codeUidOf(t));
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderInactive.selector, r));
            _r(t).forceTransfer(r, 1);
        }
    }

    /// A revoked record and an unknown one are refused; the role is `FORCE`'s (compliance does not hold it).
    function test_recordLiveAndRole() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _seized(t, 100);
            vm.prank(compliance);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, uint8(6), nid(compliance)));
            _r(t).forceTransfer(r, 1);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderUnknown.selector, bytes32("nope")));
            _r(t).forceTransfer("nope", 1);
            vm.prank(compliance);
            _r(t).revokeOrder(r, "why"); // also ends the record-backed freeze; the record check comes first
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderInactive.selector, r));
            _r(t).forceTransfer(r, 1);
        }
    }

    /// A derived subject's UA-ledger balance moves to a derived beneficiary (registered SIGNING); public balances only.
    function test_derivedSubjectAndBeneficiary() public {
        bytes32 ux = UA_X;
        bytes32 uy = bytes32(uint256(UA_X) + 1);
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            vm.prank(alice);
            NormalToken(t).transferToUA(ux, 500);
            bytes32 r = _order(t, "o1", ux, uy, 100, _now() + 90 days);
            _freezeRecord(t, ux, r);
            vm.prank(issuer);
            _r(t).forceTransfer(r, 100);
            assertEq(NormalToken(t).balanceOfUA(ux), 400);
            assertEq(NormalToken(t).balanceOfUA(uy), 100);
        }
    }
}
