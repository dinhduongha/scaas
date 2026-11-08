// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {nid} from "../helpers/Ids.sol";

/// Plan T28 (regulated-kinds spec §3.1, §3.3 T4, T6, T8; RK-4, RK-5, F-02, F-17): `recordOrder`, the record-backed freeze,
/// `revokeOrder`, and `RECORD` disabled, on kinds 8 and 9.
contract RecordTest is RegFixture {
    bytes32 a;
    bytes32 b;

    function setUp() public override {
        super.setUp();
        (a, b) = (nid(alice), nid(bob));
    }

    /// `recordId = keccak256(abi.encode(orderId, subject, beneficiary))`, the record as written, `OrderRecorded`; the same
    /// order twice `OrderExists`.
    function test_recordOrder() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 id = keccak256(abi.encode(bytes32("o1"), a, b));
            vm.expectEmit(t);
            emit IRegulatedToken.OrderRecorded(id, "o1", a, b, 100, _now() + 90 days, keccak256("document"));
            assertEq(_order(t, "o1", a, b, 100, _now() + 90 days), id);
            IRegulatedToken.OrderRecord memory o = _r(t).order(id);
            (bytes32 s, bytes32 be, uint64 fu, bool rv, uint256 mx, uint256 ex) =
                (o.subject, o.beneficiary, o.freezeUntil, o.revoked, o.maxAmount, o.executed);
            assertEq(s, a);
            assertEq(be, b);
            assertEq(fu, _now() + 90 days);
            assertFalse(rv);
            assertEq(mx, 100);
            assertEq(ex, 0);
            vm.prank(compliance);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderExists.selector, id));
            _r(t).recordOrder("o1", keccak256("other document"), a, b, 1, 0);
        }
    }

    /// The rules of `recordOrder` (spec §3.3): both refs, two distinct ids neither 0 nor a pool nor the token, an amount or
    /// a future freeze, the compliance role; a freeze-only order (`maxAmount` 0, `freezeUntil > now`) is the control.
    function test_recordOrderRefusals() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            vm.startPrank(compliance);
            vm.expectRevert(IRegulatedToken.RefRequired.selector);
            _r(t).recordOrder(0, "doc", a, b, 1, 0);
            vm.expectRevert(IRegulatedToken.RefRequired.selector);
            _r(t).recordOrder("o", 0, a, b, 1, 0);
            bytes32[4] memory bad = [bytes32(0), nid(MetaTxLib.UA_POOL), nid(MetaTxLib.SHIELD_POOL), nid(t)];
            for (uint256 k; k < 4; ++k) {
                vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.ForceTargetRefused.selector, bad[k]));
                _r(t).recordOrder("o", "doc", bad[k], b, 1, 0);
                vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.ForceTargetRefused.selector, bad[k]));
                _r(t).recordOrder("o", "doc", a, bad[k], 1, 0);
            }
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.ForceTargetRefused.selector, a));
            _r(t).recordOrder("o", "doc", a, a, 1, 0);
            bytes32 id = keccak256(abi.encode(bytes32("o"), a, b));
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderInactive.selector, id));
            _r(t).recordOrder("o", "doc", a, b, 0, _now());
            _r(t).recordOrder("o", "doc", a, b, 0, _now() + 1); // freeze-only
            vm.stopPrank();
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, uint8(10), nid(issuer)));
            _r(t).recordOrder("o2", "doc", a, b, 1, 0);
        }
    }

    /// T4 on an account not frozen: `until = freezeUntil`, record-backed, `recordId`; `type(uint64).max` is open-ended.
    function test_T4_recordFreeze() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _order(t, "o1", a, b, 100, type(uint64).max);
            vm.expectEmit(t);
            emit IRegulatedToken.AccountFrozen(a, REF, r, type(uint64).max);
            _freezeRecord(t, a, r);
            IRegulatedToken.FreezeState memory s = _r(t).freezeOf(a);
            assertEq(s.until, type(uint64).max);
            assertTrue(s.recordBacked);
            assertEq(s.recordId, r);
            vm.warp(block.timestamp + 3650 days);
            assertTrue(_r(t).isFrozen(a), "open-ended");
            vm.warp(1_800_000_000);
        }
    }

    /// T4's preconditions, each with the control: an unknown record, another subject, a revoked one, `freezeUntil <= now`,
    /// and, on an issuer-frozen account, a `freezeUntil` before `until` (`RecordFreezeShorter(until)`); `freezeUntil >= until`
    /// extends it.
    function test_T4_refusals() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderUnknown.selector, bytes32("nope")));
            _r(t).freeze(a, REF, "nope");
            bytes32 rb = _order(t, "ob", b, a, 100, _now() + 90 days);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderInactive.selector, rb));
            _r(t).freeze(a, REF, rb); // names bob
            bytes32 rr = _order(t, "or", a, b, 100, _now() + 90 days);
            vm.prank(compliance);
            _r(t).revokeOrder(rr, REF);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderInactive.selector, rr));
            _r(t).freeze(a, REF, rr);
            bytes32 rs = _order(t, "os", a, b, 100, _now() + 10 days);
            vm.warp(_now() + 10 days);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderInactive.selector, rs));
            _r(t).freeze(a, REF, rs); // freezeUntil == now
            _freeze(t, a); // issuer-only, until = now + 30 d
            uint64 until = _now() + 30 days;
            bytes32 short = _order(t, "oshort", a, b, 100, until - 1);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.RecordFreezeShorter.selector, until));
            _r(t).freeze(a, REF, short);
            bytes32 same = _order(t, "osame", a, b, 100, until);
            _freezeRecord(t, a, same);
            assertEq(_r(t).freezeOf(a).until, until, "freezeUntil == until is accepted");
            assertTrue(_r(t).freezeOf(a).recordBacked);
            vm.warp(1_800_000_000);
        }
    }

    /// T6, M-08, F-17: revoking the record that backs a freeze ends it, `OrderRevoked` then `AccountUnfrozen(subject,
    /// reasonRef)`, the issuer cooldown starts; revoking it again `OrderInactive`; an unknown record `OrderUnknown`.
    function test_revokeOrderEmitsAccountUnfrozen() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _order(t, "o1", a, b, 100, _now() + 90 days);
            _freezeRecord(t, a, r);
            vm.expectEmit(t);
            emit IRegulatedToken.OrderRevoked(r, "why");
            vm.expectEmit(t);
            emit IRegulatedToken.AccountUnfrozen(a, "why");
            vm.prank(compliance);
            _r(t).revokeOrder(r, "why");
            assertFalse(_r(t).isFrozen(a));
            IRegulatedToken.FreezeState memory s = _r(t).freezeOf(a);
            assertEq(s.until, _now());
            assertEq(s.recordId, 0);
            assertFalse(s.recordBacked);
            assertEq(s.issuerCooldownUntil, _now() + 30 days);
            assertTrue(_r(t).order(r).revoked);
            vm.prank(compliance);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderInactive.selector, r));
            _r(t).revokeOrder(r, "why");
            vm.prank(compliance);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderUnknown.selector, bytes32("nope")));
            _r(t).revokeOrder("nope", "why");
            vm.prank(compliance);
            vm.expectRevert(IRegulatedToken.RefRequired.selector);
            _r(t).revokeOrder(r, 0);
        }
    }

    /// T5 then T6: `unfreeze` cleared `recordId`, so revoking the old record changes no freeze: a later issuer-only freeze
    /// stands.
    function test_unfreezeClearsRecordId() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _order(t, "o1", a, b, 100, _now() + 90 days);
            _freezeRecord(t, a, r);
            _unfreeze(t, a);
            assertEq(_r(t).freezeOf(a).recordId, 0);
            vm.warp(_now() + 30 days);
            _freeze(t, a);
            vm.prank(compliance);
            _r(t).revokeOrder(r, "why");
            assertTrue(_r(t).isFrozen(a), "the issuer-only freeze stands");
            vm.warp(1_800_000_000);
        }
    }

    /// T8, RK-5: `disableFeature(RECORD)` (one call: bit 10 is not delayed) ends every record-backed freeze at once and
    /// `FORCE`; an issuer-only freeze stands; no record is live (a record-backed `freeze` refused).
    function test_recordDisabledEndsBackedFreezesStopsForce() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _order(t, "o1", a, b, 100, _now() + 90 days);
            _freezeRecord(t, a, r);
            _freeze(t, nid(address(0xCAFE)));
            vm.prank(issuer);
            _r(t).forceTransfer(r, 10); // the control
            _disable(t, 10);
            assertEq(_r(t).regulatedConfig().controls & (1 << 5), 0, "mirror bit 10 cleared at once");
            assertFalse(_r(t).isFrozen(a), "the record-backed freeze stopped");
            assertTrue(_r(t).isFrozen(nid(address(0xCAFE))), "an issuer-only freeze stands");
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderInactive.selector, r));
            _r(t).forceTransfer(r, 10);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.OrderInactive.selector, r));
            _r(t).freeze(b, REF, r);
            vm.prank(alice);
            IERC20(t).transfer(bob, 1);
            _freeze(t, a); // T1 replaces a value that no longer counts
            assertTrue(_r(t).isFrozen(a));
        }
    }

    /// T8, F-02: with `RECORD` disabled `revokeOrder` runs on the role alone (no `use`, which would refuse `FeatureNotSet`);
    /// another id still needs the role.
    function test_revokeOrderRunsWithRecordDisabled() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _order(t, "o1", a, b, 100, _now() + 90 days);
            _disable(t, 10);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, uint8(10), nid(issuer)));
            _r(t).revokeOrder(r, "why");
            vm.expectEmit(t);
            emit IRegulatedToken.OrderRevoked(r, "why");
            vm.prank(compliance);
            _r(t).revokeOrder(r, "why");
            assertTrue(_r(t).order(r).revoked);
            vm.prank(compliance);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, uint8(10)));
            _r(t).recordOrder("o2", "doc", a, b, 1, 0);
        }
    }
}
