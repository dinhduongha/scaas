// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Vm} from "forge-std/Vm.sol";
import {ListFixture, IListOps} from "./helpers/ListFixture.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {nid} from "../helpers/Ids.sol";

/// Round 3s, spec 2026-11-10-token-lists.md §5.2 cell by cell, §3's init rows, §5.5's predicate, §6's ops and holders, the
/// review's rows (9)-(12) (§13 (3), (4), (5), (9)-(12)); kinds 8 and 9, each refusal with its positive control.
contract ListGovernanceTest is ListFixture {
    uint256 salt;

    function _c(uint256 i) internal view returns (IFactoryToken.TokenConfig memory) {
        return _cfg(i, 0, 0);
    }

    function _new(uint256 i, IFactoryToken.TokenConfig memory c) internal returns (address) {
        return _create(i, c, bytes32(++salt));
    }

    function _refused(uint256 i, IFactoryToken.TokenConfig memory c, bytes memory err) internal {
        vm.expectRevert(err);
        _create(i, c, bytes32(++salt));
    }

    function _bit(uint8 bit) internal pure returns (uint256) {
        return uint256(1) << bit;
    }

    function _try1(address t, address who, bytes memory cd) internal returns (bytes4) {
        vm.prank(who);
        return _try(t, cd);
    }

    function _enableCd(uint8 bit) internal pure returns (bytes memory) {
        return abi.encodeCall(IListOps.enableFeature, (bit));
    }

    function _disableCd(uint8 bit) internal pure returns (bytes memory) {
        return abi.encodeCall(IGovernance.disableFeature, (bit));
    }

    function _controls(address t) internal view returns (uint8) {
        return _r(t).regulatedConfig().controls;
    }

    /// A config of kind `i` with no regulated control and no holder seat: the bare base for the init rows.
    function _bare(uint256 i) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _c(i);
        c.features &= ~REG_FEATURES;
        (c.roles.issuer, c.roles.compliance) = (0, 0);
    }

    // ------------------------------------------------------------------ §5.2: enableFeature, disableFeature, the locks

    /// `enableFeature(8 | 9)` at once by the admin: `FeatureEnabled`, the bit in `features()` and in the mirror (I12); a
    /// second call `FeatureAlreadySet`.
    function test_enable_listsAtOnce() public {
        for (uint256 i; i < 2; ++i) {
            for (uint8 bit = ALLOW; bit <= DENY; ++bit) {
                address t = _lt(i, 0, 0, bytes32(++salt));
                assertEq(NormalToken(t).features() & _bit(bit), 0);
                vm.recordLogs();
                _enable(t, bit);
                Vm.Log[] memory l = vm.getRecordedLogs();
                assertEq(l.length, 1);
                assertEq(l[0].topics[0], FEATURE_ENABLED);
                assertEq(uint256(l[0].topics[1]), bit);
                assertEq(l[0].topics[2], nid(ownerA));
                assertEq(NormalToken(t).features() & _bit(bit), _bit(bit));
                assertEq(_controls(t), uint8(REG_FEATURES >> 5) | uint8(1 << (bit - 5)), "I12");
                assertEq(_try1(t, ownerA, _enableCd(bit)), ALREADY_SET);
            }
        }
    }

    /// `enableFeature(28)` with a registry set at creation (masks and registry, `KYC` off): at once, mirror bit 6; without a
    /// registry `ComplianceRegistryNotSet` (M18).
    function test_enable_kyc() public {
        for (uint256 i; i < 2; ++i) {
            address none = _lt(i, 0, 0, bytes32(++salt));
            assertEq(_try1(none, ownerA, _enableCd(KYC_BIT)), REGISTRY_NOT_SET);
            assertEq(NormalToken(none).features() & _bit(KYC_BIT), 0, "the whole call reverted");
            IFactoryToken.TokenConfig memory c = _c(i);
            (c.reg.complianceRegistry, c.reg.deniedFlags) = (address(creg), SANCTIONED);
            address t = _new(i, c);
            assertEq(_controls(t), uint8(REG_FEATURES >> 5), "KYC off at creation");
            _enable(t, KYC_BIT);
            assertEq(_controls(t), uint8(REG_FEATURES >> 5) | 64);
            if (i == 1) _wrapFor(t, alice, SUPPLY);
            _attest(nid(bob), SANCTIONED, type(uint64).max);
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(bob), uint8(0)));
            IERC20(t).transfer(bob, 1);
            _attest(nid(bob), 0, type(uint64).max);
        }
    }

    /// Every other bit `FeatureNotEnableable` (M16); a stranger `NotAdmin`.
    function test_enable_otherBitsAndStranger() public {
        address t = _lt(0, 0, 0, "o");
        uint8[10] memory bits = [0, 1, 2, 5, 6, 7, 10, 21, 23, 29];
        for (uint256 k; k < bits.length; ++k) {
            assertEq(_try1(t, ownerA, _enableCd(bits[k])), NOT_ENABLEABLE, "not enableable");
        }
        assertEq(_try1(t, bob, _enableCd(ALLOW)), IAdmin.NotAdmin.selector);
        assertEq(_try1(t, issuer, _enableCd(ALLOW)), IAdmin.NotAdmin.selector);
        _enable(t, ALLOW); // the control
    }

    /// Locked on and locked off (M17): both entries `FeatureLocked`, for 8, 9 and 28.
    function test_locks_onAndOff() public {
        uint8[3] memory bits = [ALLOW, DENY, KYC_BIT];
        for (uint256 i; i < 2; ++i) {
            for (uint256 k; k < 3; ++k) {
                uint8 bit = bits[k];
                for (uint256 on; on < 2; ++on) {
                    IFactoryToken.TokenConfig memory c = _c(i);
                    if (on == 1) c.features |= _bit(bit);
                    c.lockedFeatures = _bit(bit);
                    (c.reg.complianceRegistry, c.reg.deniedFlags) = (address(creg), SANCTIONED);
                    address t = _new(i, c);
                    assertEq(NormalToken(t).lockedFeatures() & _bit(bit), _bit(bit));
                    bytes memory e = abi.encodeWithSelector(IGovernance.FeatureLocked.selector, bit);
                    vm.prank(ownerA);
                    (bool ok, bytes memory ret) = t.call(_enableCd(bit));
                    assertFalse(ok);
                    assertEq(ret, e, "enable");
                    vm.prank(ownerA);
                    (ok, ret) = t.call(_disableCd(bit));
                    assertFalse(ok);
                    assertEq(ret, e, "disable");
                    assertEq(NormalToken(t).features() & _bit(bit), on == 1 ? _bit(bit) : 0);
                }
            }
        }
    }

    /// `disableFeature(8 | 9)` refused `FeatureNotDisableable` (M19), on or off.
    function test_disable_listsRefused() public {
        for (uint256 i; i < 2; ++i) {
            address on = _lt(i, _bit(ALLOW) | _bit(DENY), 0, bytes32(++salt));
            address off = _lt(i, 0, 0, bytes32(++salt));
            for (uint8 bit = ALLOW; bit <= DENY; ++bit) {
                bytes memory e = abi.encodeWithSelector(NOT_DISABLEABLE, bit);
                vm.prank(ownerA);
                (bool ok, bytes memory ret) = on.call(_disableCd(bit));
                assertFalse(ok);
                assertEq(ret, e);
                vm.prank(ownerA);
                (ok, ret) = off.call(_disableCd(bit));
                assertEq(ret, e);
                assertEq(NormalToken(on).features() & _bit(bit), _bit(bit));
            }
            _disable(on, 5); // the control: bit 5 still disables (delayed: the proposal)
        }
    }

    /// `disableFeature(28)` (M20): two calls with `grantDelay` (the mirror keeps bit 6 until the confirm, RK-3), at once
    /// with `grantDelay` 0; then `enableFeature(28)` again.
    function test_disable_kycDelayedThenEnabledAgain() public {
        for (uint256 i; i < 2; ++i) {
            for (uint256 d; d < 2; ++d) {
                IFactoryToken.TokenConfig memory c = _c(i);
                c.features |= _bit(KYC_BIT);
                (c.reg.complianceRegistry, c.reg.deniedFlags) = (address(creg), SANCTIONED);
                if (d == 1) c.grantDelay = 0;
                address t = _new(i, c);
                assertEq(_controls(t) & 64, 64);
                _disable(t, KYC_BIT);
                if (d == 0) {
                    assertEq(_controls(t) & 64, 64, "proposed only");
                    assertEq(NormalToken(t).features() & _bit(KYC_BIT), _bit(KYC_BIT));
                    vm.warp(block.timestamp + GD);
                    _disable(t, KYC_BIT);
                }
                assertEq(_controls(t) & 64, 0, "applied");
                assertEq(NormalToken(t).features() & _bit(KYC_BIT), 0);
                _enable(t, KYC_BIT);
                assertEq(_controls(t) & 64, 64, "enabled again");
                vm.warp(1_800_000_000);
            }
        }
    }

    // ------------------------------------------------------------------ §3, §5.5: init rows and the predicate

    /// `KYC ⇒ registry`; `registry ⇔ masks`; a registry and masks with `KYC` off create (enable later).
    function test_init_kycRows() public {
        bytes memory bad = abi.encodeWithSelector(IRegulatedToken.RegulatedConfigInvalid.selector);
        _attest(nid(alice), KYC, type(uint64).max); // the initial supply's receiver under `KYC` with a required mask
        for (uint256 i; i < 2; ++i) {
            IFactoryToken.TokenConfig memory c = _c(i);
            c.features |= _bit(KYC_BIT);
            _refused(i, c, bad); // KYC without a registry
            c.reg.requiredFlags = KYC;
            _refused(i, c, bad); // masks without a registry
            c = _c(i);
            c.reg.complianceRegistry = address(creg);
            _refused(i, c, bad); // a registry without a mask
            c.reg.requiredFlags = KYC;
            address t = _new(i, c); // registry and mask, KYC off: the control
            assertEq(_r(t).regulatedConfig().complianceRegistry, address(creg));
            c.features |= _bit(KYC_BIT);
            _new(i, c);
        }
    }

    /// The lock-off rule (M22): 8, 9, 28 may be locked off; 5 locked while off `LockedNotSubset`.
    function test_init_lockOff() public {
        for (uint256 i; i < 2; ++i) {
            IFactoryToken.TokenConfig memory c = _c(i);
            c.lockedFeatures = _bit(ALLOW) | _bit(DENY) | _bit(KYC_BIT);
            address t = _new(i, c);
            assertEq(NormalToken(t).lockedFeatures() & c.lockedFeatures, c.lockedFeatures);
            assertEq(NormalToken(t).features() & c.lockedFeatures, 0, "locked off");
            c = _bare(i);
            c.lockedFeatures = _bit(5);
            _refused(i, c, abi.encodeWithSelector(IGovernance.LockedNotSubset.selector));
        }
    }

    /// §5.5's predicate drives `termsHash` (M26, M33): each term alone — a list bit not locked off, a registry for 28, an
    /// admin — makes the terms required; with none of them, terms are refused.
    function test_init_termsPredicate() public {
        bytes memory bad = abi.encodeWithSelector(IRegulatedToken.RegulatedConfigInvalid.selector);
        uint256 lists = _bit(ALLOW) | _bit(DENY);
        for (uint256 i; i < 2; ++i) {
            IFactoryToken.TokenConfig memory c = _bare(i);
            c.reg.termsHash = 0;
            _refused(i, c, bad); // 8, 9 enableable: terms required
            c.lockedFeatures = _bit(ALLOW);
            _refused(i, c, bad); // 9 alone still enableable
            c.lockedFeatures = _bit(DENY);
            _refused(i, c, bad); // 8 alone still enableable
            c.lockedFeatures = lists;
            _new(i, c); // nothing enableable: no terms (the control)
            c.reg.termsHash = TERMS;
            _refused(i, c, bad); // terms with nothing to disclose
            c.reg.termsHash = 0;
            (c.reg.complianceRegistry, c.reg.deniedFlags) = (address(creg), SANCTIONED);
            _refused(i, c, bad); // 28 enableable once a registry exists
            c.lockedFeatures = lists | _bit(KYC_BIT);
            _new(i, c);
            c = _bare(i);
            (c.reg.termsHash, c.admin, c.roles.minter) = (bytes32(0), bytes32(0), bytes32(0));
            (c.reg.complianceRegistry, c.reg.deniedFlags) = (address(creg), SANCTIONED);
            _new(i, c); // admin 0: nothing can ever be enabled
            c.reg.termsHash = TERMS;
            _refused(i, c, bad);
        }
    }

    /// Fable P1-2, M31: `ALLOWLIST` set (and locked) on a fixed-supply kind 8 lists `initialHolder` before the mint
    /// (`AllowedSet(pad(alice), 0, true)` before `Transfer`); with the bit off, or no supply, no row.
    function test_init_listsInitialHolder() public {
        IFactoryToken.TokenConfig memory c = _c(0);
        c.features = (c.features & ~_bit(GovernanceBits.MINTABLE)) | _bit(ALLOW);
        c.roles.minter = 0;
        c.lockedFeatures = _bit(ALLOW);
        vm.recordLogs();
        address t = _new(0, c);
        Vm.Log[] memory l = vm.getRecordedLogs();
        uint256 at = type(uint256).max;
        uint256 mintAt;
        for (uint256 k; k < l.length; ++k) {
            if (l[k].emitter != t) continue;
            if (l[k].topics[0] == ALLOWED_SET) {
                (at, mintAt) = (k, type(uint256).max);
                assertEq(l[k].topics[1], nid(alice));
                assertEq(l[k].topics[2], bytes32(0));
                assertEq(abi.decode(l[k].data, (bool)), true);
            }
            if (l[k].topics[0] == keccak256("Transfer(address,address,uint256)") && at != type(uint256).max) mintAt = k;
        }
        assertTrue(at != type(uint256).max && mintAt != type(uint256).max, "AllowedSet before the mint");
        assertEq(IERC20(t).balanceOf(alice), SUPPLY);
        assertEq(_flags(t, nid(alice)), ALLOWED);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(NOT_ALLOWED, nid(bob)));
        IERC20(t).transfer(bob, 1);
        // the bit off: no row
        assertEq(_flags(_lt(0, 0, 0, "off"), nid(alice)), 0);
        // no supply: no row
        c = _c(0);
        c.features |= _bit(ALLOW);
        (c.initialSupply, c.initialHolder) = (0, address(0));
        t = _new(0, c);
        assertEq(_flags(t, nid(alice)) | _flags(t, bytes32(0)), 0);
    }

    // ------------------------------------------------------------------ §6: the ops and who holds them

    /// The batch bounds (M12, M13): 256 pass with one event each; 257 and 0 `ListBatchInvalid`; account 0 `ListAccountZero`.
    function test_ops_bounds() public {
        address t = _lt(0, 0, 0, "b");
        bytes32[] memory as_ = new bytes32[](257);
        for (uint256 k; k < 257; ++k) as_[k] = bytes32(k + 1);
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(BATCH_INVALID, uint256(257)));
        IListOps(t).setDenied(as_, true);
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(BATCH_INVALID, uint256(0)));
        IListOps(t).setAllowed(new bytes32[](0), true);
        bytes32[] memory z = new bytes32[](2);
        z[0] = bytes32(uint256(7));
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(ACCOUNT_ZERO));
        IListOps(t).setAllowed(z, true);
        assembly ("memory-safe") { mstore(as_, 256) }
        vm.recordLogs();
        vm.prank(issuer);
        IListOps(t).setDenied(as_, true);
        assertEq(vm.getRecordedLogs().length, 256, "one event per account");
        assertEq(_flags(t, bytes32(uint256(256))), DENIED);
    }

    /// One event per account, `by` the subject; duplicates idempotent; the other flag never touched (M10).
    function test_ops_eventsAndOtherFlag() public {
        address t = _lt(1, 0, 0, "e");
        bytes32[] memory as_ = new bytes32[](3);
        (as_[0], as_[1], as_[2]) = (nid(bob), nid(bob), nid(alice));
        vm.recordLogs();
        vm.prank(issuer);
        IListOps(t).setAllowed(as_, true);
        Vm.Log[] memory l = vm.getRecordedLogs();
        assertEq(l.length, 3);
        for (uint256 k; k < 3; ++k) {
            assertEq(l[k].topics[0], ALLOWED_SET);
            assertEq(l[k].topics[1], as_[k]);
            assertEq(l[k].topics[2], nid(issuer));
        }
        _setList(t, DENY, nid(bob), true);
        assertEq(_flags(t, nid(bob)), ALLOWED | DENIED);
        _setList(t, ALLOW, nid(bob), false);
        assertEq(_flags(t, nid(bob)), DENIED, "the deny flag untouched");
        _setList(t, DENY, nid(alice), true);
        _setList(t, DENY, nid(alice), false);
        assertEq(_flags(t, nid(alice)), ALLOWED, "the allow flag untouched");
    }

    /// A stranger `MissingRole` (M11); a holder edits while the bit is off, and the list holds at `enableFeature` (M11).
    function test_ops_strangerAndEditWhileOff() public {
        for (uint256 i; i < 2; ++i) {
            address t = _lt(i, 0, 0, bytes32(++salt));
            vm.prank(bob);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, DENY, nid(bob)));
            IListOps(t).setDenied(_one(nid(bob)), true);
            vm.prank(bob);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, ALLOW, nid(bob)));
            IListOps(t).setAllowed(_one(nid(bob)), true);
            _setList(t, DENY, nid(bob), true); // off: the row is written, nothing is checked
            vm.prank(alice);
            IERC20(t).transfer(bob, 2);
            vm.prank(bob);
            IERC20(t).transfer(alice, 1);
            _enable(t, DENY);
            vm.prank(bob);
            vm.expectRevert(abi.encodeWithSelector(DENIED_ERR, nid(bob)));
            IERC20(t).transfer(alice, 1);
        }
    }

    /// A role on 8 granted while the bit is off and unlocked (M23); refused `RoleWithoutFeature` when locked off; a list
    /// holder's revoke is at once (M21: no `RelaxProposed`, even with a `grantDelay`).
    function test_holders_grantWhileOff_revokeAtOnce() public {
        for (uint256 i; i < 2; ++i) {
            IFactoryToken.TokenConfig memory c = _c(i);
            c.grantDelay = 0;
            address t = _new(i, c);
            vm.prank(ownerA);
            NormalToken(t).grantRole(ALLOW, nid(bob));
            vm.prank(bob);
            IListOps(t).setAllowed(_one(nid(bob)), true);
            c.lockedFeatures = _bit(ALLOW);
            t = _new(i, c);
            vm.prank(ownerA);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, ALLOW));
            NormalToken(t).grantRole(ALLOW, nid(bob));
            vm.prank(ownerA);
            NormalToken(t).grantRole(DENY, nid(bob)); // 9 unlocked: the control
            // with grantDelay one day: the revoke of a list holder at once
            t = _lt(i, _bit(DENY), 0, bytes32(++salt));
            vm.recordLogs();
            vm.prank(ownerA);
            NormalToken(t).revokeRole(DENY, nid(issuer));
            Vm.Log[] memory l = vm.getRecordedLogs();
            assertEq(l.length, 1);
            assertEq(l[0].topics[0], IGovernance.RoleRevoked.selector);
            assertFalse(NormalToken(t).hasRole(DENY, nid(issuer)));
        }
    }

    /// Fable P1-1, M29, M30: the issuer seat holds every list bit valid and not locked off, set or not; not a locked-off one,
    /// nor any with admin 0 (R-7). `enableFeature(8 | 9)` with no holder root `ListHolderMissing`, then passes once granted.
    function test_holders_issuerSeatAndHolderMissing() public {
        for (uint256 i; i < 2; ++i) {
            address t = _lt(i, 0, _bit(ALLOW), bytes32(++salt));
            assertFalse(NormalToken(t).hasRole(ALLOW, nid(issuer)), "locked off: no seat");
            assertTrue(NormalToken(t).hasRole(DENY, nid(issuer)), "off, unlocked: the seat");
            IFactoryToken.TokenConfig memory c = _bare(i);
            c.roles.issuer = nid(bob); // an EOA: 8 and 9 take any holder; a seat with list bits only
            c.grantDelay = 0;
            t = _new(i, c);
            assertTrue(NormalToken(t).hasRole(ALLOW, nid(bob)) && NormalToken(t).hasRole(DENY, nid(bob)));
            c.roles.issuer = 0;
            t = _new(i, c);
            for (uint8 bit = ALLOW; bit <= DENY; ++bit) {
                assertEq(_try1(t, ownerA, _enableCd(bit)), HOLDER_MISSING);
                assertEq(NormalToken(t).features() & _bit(bit), 0, "the whole call reverted");
                vm.prank(ownerA);
                NormalToken(t).grantRole(bit, nid(bob));
                _enable(t, bit);
            }
            c = _bare(i);
            (c.admin, c.roles.minter, c.reg.termsHash) = (0, 0, 0);
            c.roles.issuer = nid(bob);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(GovernanceBits.FREEZE)));
            _create(i, c, bytes32(++salt)); // admin 0: the seat holds no list bit, so nothing
        }
    }

    /// Fable P2-3: with the deny list on, revoke its holders and renounce: the list is final (a denied account stays
    /// denied); an off allow list with holders does not block the renounce, and nothing can switch it on afterwards.
    function test_renounce_listFinal() public {
        IFactoryToken.TokenConfig memory c = _bare(0);
        c.features |= _bit(DENY);
        c.roles.issuer = nid(issuer);
        c.grantDelay = 0;
        address t = _new(0, c);
        _setList(t, DENY, nid(bob), true);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(DENIED_ERR, nid(bob)));
        IERC20(t).transfer(bob, 1);
        vm.startPrank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminHasHolders.selector, uint8(1)));
        NormalToken(t).renounceAdmin();
        NormalToken(t).revokeRole(1, nid(address(this)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminHasHolders.selector, DENY));
        NormalToken(t).renounceAdmin();
        NormalToken(t).revokeRole(DENY, nid(issuer));
        NormalToken(t).renounceAdmin();
        vm.stopPrank();
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, DENY, nid(issuer)));
        IListOps(t).setDenied(_one(nid(bob)), false);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(DENIED_ERR, nid(bob)));
        IERC20(t).transfer(bob, 1);
        _setList(t, ALLOW, nid(bob), true); // the dormant allow list: its holder still edits it
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(ownerA)));
        IListOps(t).enableFeature(ALLOW);
    }
}
