// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture, Holder} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IComplianceRegistry} from "../../src/regulated/IComplianceRegistry.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {RegulatedBase} from "../../src/regulated/RegulatedBase.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {Catalogue, plainEnv} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";

/// Plan T29 (regulated-kinds spec §2.4, §5; CTR-AS-07, CTR-AS-16, CTR-GOV-18): the canonical `ComplianceRegistry` (admin
/// written once, attesters by id, `ELIGIBLE_CONTRACT` admin only), the `R` truth table on the registry and through kinds 8
/// and 9, and the code pin (`REGISTRY_CODEHASH` from the release's `implArgs`, `RegistryCodeMismatch` at init). Each
/// refusal after its control.
contract RegistryTest is RegFixture {
    /// The canonical registry runtime's code hash (a pin: it moves with the registry's source, its interface or the
    /// compiler settings, old -> new in the commit).
    bytes32 internal constant REGISTRY_CODEHASH = 0x8e2d42b6304131a9159832ae910e4e39f609cd9fdbffbd6c91a090cec2f43f0c;
    uint64 internal constant ACCR = 2;
    uint64 internal constant MAX = type(uint64).max;
    bytes32 internal constant ACC = bytes32(uint256(0xACC));

    function _has(bytes32 a, uint64 req, uint64 den) internal view returns (bool) {
        return creg.hasFlags(a, req, den);
    }

    // ------------------------------------------------------------------ the registry

    /// CTR-AS-07: the admin is a contract, set by the constructor and never written again (no writer exists).
    function test_adminWrittenOnceAContract() public {
        assertEq(creg.admin(), cadmin);
        vm.expectRevert(abi.encodeWithSelector(IComplianceRegistry.AdminNotContract.selector, bob));
        new ComplianceRegistry(bob);
        assertEq(new ComplianceRegistry(address(new Holder())).admin() != address(0), true);
    }

    /// Attester ids: assigned at the first enabling from 1, never reused; a disable keeps the id; id 0 is the admin, always
    /// enabled; `setAttester` is the admin's.
    function test_attesterIds() public {
        assertEq(creg.attesterId(attester), 1);
        assertTrue(creg.attesterEnabled(0), "admin");
        assertTrue(creg.attesterEnabled(1));
        assertFalse(creg.attesterEnabled(2), "not assigned");
        vm.prank(cadmin);
        creg.setAttester(attester, false);
        assertEq(creg.attesterId(attester), 1);
        assertFalse(creg.attesterEnabled(1));
        vm.prank(cadmin);
        creg.setAttester(bob, true);
        assertEq(creg.attesterId(bob), 2, "the next id");
        vm.prank(cadmin);
        creg.setAttester(attester, true);
        assertEq(creg.attesterId(attester), 1, "never reused, never reassigned");
        vm.expectRevert(IComplianceRegistry.NotAdmin.selector);
        vm.prank(attester);
        creg.setAttester(alice, true);
        vm.expectRevert(IComplianceRegistry.NotAttester.selector);
        vm.prank(cadmin);
        creg.setAttester(alice, false); // never enabled: nothing to disable
    }

    /// `attest`: an enabled attester (its id) or the admin (id 0); anyone else `NotAttester`, a disabled attester too;
    /// lengths checked; flags 0 revoke.
    function test_attest() public {
        _attest(ACC, KYC, MAX);
        (uint64 fl, uint64 vu, uint32 id) = creg.attestationOf(ACC);
        assertEq(fl, KYC);
        assertEq(vu, MAX);
        assertEq(id, 1);
        _attestAs(cadmin, ACC, ACCR, 5);
        (fl, vu, id) = creg.attestationOf(ACC);
        assertEq(fl, ACCR);
        assertEq(vu, 5);
        assertEq(id, 0, "the admin's id");
        vm.expectRevert(IComplianceRegistry.NotAttester.selector);
        _attestAs(bob, ACC, KYC, MAX);
        vm.prank(cadmin);
        creg.setAttester(attester, false);
        vm.expectRevert(IComplianceRegistry.NotAttester.selector);
        _attest(ACC, KYC, MAX);
        vm.expectRevert(IComplianceRegistry.LengthMismatch.selector);
        vm.prank(cadmin);
        creg.attest(new bytes32[](2), new uint64[](1), new uint64[](2));
        _attestAs(cadmin, ACC, 0, MAX); // revoke
        assertFalse(_has(ACC, KYC, 0));
    }

    /// Owner 2026-11-06: a row the admin wrote (stored `attesterId == 0 && flags != 0`) only the admin overwrites or
    /// revokes; an attester gets `AdminWrittenSlot(account)`, in a batch too (nothing written). An empty slot is open; an
    /// admin row of flags 0 (a revoke) is open, nothing left to protect. Attesters overwrite their own and each other's
    /// rows. Each refusal after its control.
    function test_adminWrittenSlotOnlyAdmin() public {
        bytes32 b = bytes32(uint256(0xB0B));
        bytes memory locked = abi.encodeWithSelector(IComplianceRegistry.AdminWrittenSlot.selector, ACC);
        vm.prank(cadmin);
        creg.setAttester(bob, true); // attester id 2
        _attest(ACC, KYC, MAX); // the control: an empty slot is open to an attester
        _attest(ACC, ACCR, 7); // its own row
        _attestAs(bob, ACC, KYC, MAX); // another attester's row
        _attest(ACC, SANCTIONED, MAX); // and back
        _attestAs(cadmin, ACC, KYC, MAX); // the admin over an attester's row
        vm.expectRevert(locked);
        _attest(ACC, ACCR, MAX); // overwrite an admin row
        vm.expectRevert(locked);
        _attest(ACC, 0, MAX); // revoke an admin row
        vm.expectRevert(locked);
        _attestAs(bob, ACC, 0, 0); // another attester, the same
        (uint64 fl, uint64 vu, uint32 id) = creg.attestationOf(ACC);
        assertEq(fl, KYC);
        assertEq(vu, MAX);
        assertEq(id, 0, "the admin's row stands");
        // a batch with an admin row in it writes nothing
        bytes32[] memory as_ = new bytes32[](2);
        uint64[] memory f2 = new uint64[](2);
        uint64[] memory v2 = new uint64[](2);
        (as_[0], as_[1], f2[0], f2[1], v2[0], v2[1]) = (b, ACC, KYC, KYC, MAX, MAX);
        vm.prank(attester);
        vm.expectRevert(locked);
        creg.attest(as_, f2, v2);
        (fl,,) = creg.attestationOf(b);
        assertEq(fl, 0, "the batch's first row reverted with it");
        // the admin still overwrites and revokes its own row
        _attestAs(cadmin, ACC, ACCR, 9);
        (fl, vu, id) = creg.attestationOf(ACC);
        assertEq(fl, ACCR);
        assertEq(vu, 9);
        assertEq(id, 0);
        _attestAs(cadmin, ACC, 0, MAX); // the admin's revoke: flags 0, nothing left to protect
        _attest(ACC, KYC, MAX); // open again to an attester
        (fl,, id) = creg.attestationOf(ACC);
        assertEq(fl, KYC);
        assertEq(id, 1);
        // ELIGIBLE_CONTRACT rows are admin rows too
        _attestAs(cadmin, ACC, ELIGIBLE, MAX);
        vm.expectRevert(locked);
        _attest(ACC, KYC, MAX);
    }

    /// CTR-AS-16: `ELIGIBLE_CONTRACT` only by the admin and only with `validUntil == type(uint64).max`.
    function test_eligibleContractAdminOnly() public {
        _attestAs(cadmin, ACC, ELIGIBLE, MAX); // the control
        assertTrue(_has(ACC, KYC, 0));
        vm.expectRevert(IComplianceRegistry.EligibleContractAdminOnly.selector);
        _attest(ACC, ELIGIBLE | KYC, MAX);
        vm.expectRevert(IComplianceRegistry.EligibleContractAdminOnly.selector);
        _attestAs(cadmin, ACC, ELIGIBLE, MAX - 1);
    }

    /// The `R` truth table (CTR-GOV-18, spec §5), on `hasFlags`: both off; required (missing, present, partial,
    /// `ELIGIBLE_CONTRACT`, lapsed, `validUntil == now`, a disabled attester); denied (unattested, active, lapsed, disabled,
    /// `ELIGIBLE_CONTRACT` never passing it); both.
    function test_truthTable() public {
        uint64 nowT = uint64(block.timestamp);
        assertTrue(_has(ACC, 0, 0), "both off");
        assertFalse(_has(ACC, KYC, 0), "required, unattested");
        assertTrue(_has(ACC, 0, SANCTIONED), "denied, unattested");
        _attest(ACC, KYC, MAX);
        assertTrue(_has(ACC, KYC, 0), "required, present");
        assertFalse(_has(ACC, KYC | ACCR, 0), "required, partial");
        _attest(ACC, KYC, nowT);
        assertTrue(_has(ACC, KYC, 0), "validUntil == now passes");
        _attest(ACC, KYC, nowT - 1);
        assertFalse(_has(ACC, KYC, 0), "lapsed");
        _attest(ACC, KYC | SANCTIONED, MAX);
        assertFalse(_has(ACC, 0, SANCTIONED), "denied, active");
        assertFalse(_has(ACC, KYC, SANCTIONED), "both: known and denied");
        _attest(ACC, KYC, MAX);
        assertTrue(_has(ACC, KYC, SANCTIONED), "both: known, not denied");
        _attest(ACC, SANCTIONED, nowT - 1);
        assertTrue(_has(ACC, 0, SANCTIONED), "denied, lapsed: not active");
        _attest(ACC, SANCTIONED, MAX);
        vm.prank(cadmin);
        creg.setAttester(attester, false);
        assertTrue(_has(ACC, 0, SANCTIONED), "denied, attester disabled: not active");
        _attestAs(cadmin, ACC, ELIGIBLE, MAX);
        assertTrue(_has(ACC, KYC | ACCR, 0), "ELIGIBLE_CONTRACT satisfies required");
        assertTrue(_has(ACC, KYC, SANCTIONED), "ELIGIBLE_CONTRACT, not denied");
        _attestAs(cadmin, ACC, ELIGIBLE | SANCTIONED, MAX);
        assertFalse(_has(ACC, KYC, SANCTIONED), "ELIGIBLE_CONTRACT never passes denied");
        assertFalse(_has(ACC, 0, ELIGIBLE), "ELIGIBLE_CONTRACT as a denied flag denies");
    }

    /// Disabling an attester voids its attestations at once, on the registry and through a token; enabling it again
    /// restores them (nothing was erased); the admin's (id 0) never lapse by it.
    function test_attesterDisableVoids() public {
        for (uint256 i; i < 2; ++i) {
            _clearBob();
            address t = _listed(i, KYC, 0, bytes32(i));
            _attest(nid(bob), KYC, MAX);
            vm.prank(alice);
            IERC20(t).transfer(bob, 1); // the control
            vm.prank(cadmin);
            creg.setAttester(attester, false);
            assertFalse(_has(nid(bob), KYC, 0));
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(bob), uint8(0)));
            IERC20(t).transfer(bob, 1);
            vm.prank(cadmin);
            creg.setAttester(attester, true);
            vm.prank(alice);
            IERC20(t).transfer(bob, 1);
        }
    }

    // ------------------------------------------------------------------ R through the token (kinds 8, 9)

    /// `ALLOWLIST` and `DENYLIST` on the receiver of a transfer (spec §3.2): unattested refused `NotEligible(to, 0)`;
    /// attested passes; lapsed refused; `validUntil == now` passes; denied refused; `ELIGIBLE_CONTRACT` passes required,
    /// never denied. A denied or lapsed holder still sends (only receivers are checked).
    function test_receiverTruthTableThroughToken() public {
        for (uint256 i; i < 2; ++i) {
            _clearBob();
            address t = _listed(i, KYC, SANCTIONED, bytes32(i));
            bytes memory ne = abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(bob), uint8(0));
            vm.prank(alice);
            vm.expectRevert(ne);
            IERC20(t).transfer(bob, 1);
            _attest(nid(bob), KYC, uint64(block.timestamp));
            vm.prank(alice);
            IERC20(t).transfer(bob, 2); // validUntil == now
            _attest(nid(bob), KYC, uint64(block.timestamp) - 1);
            vm.prank(alice);
            vm.expectRevert(ne);
            IERC20(t).transfer(bob, 1);
            _attest(nid(bob), KYC | SANCTIONED, MAX);
            vm.prank(alice);
            vm.expectRevert(ne);
            IERC20(t).transfer(bob, 1);
            _attestAs(cadmin, nid(bob), ELIGIBLE, MAX);
            vm.prank(alice);
            IERC20(t).transfer(bob, 1);
            _attestAs(cadmin, nid(bob), ELIGIBLE | SANCTIONED, MAX);
            vm.prank(alice);
            vm.expectRevert(ne);
            IERC20(t).transfer(bob, 1);
            vm.prank(bob); // denied: still sends to an eligible party
            IERC20(t).transfer(alice, 3);
            assertEq(IERC20(t).balanceOf(bob), 0);
        }
    }

    /// One list at a time: `DENYLIST` alone lets an unattested receiver through; `ALLOWLIST` alone ignores denied flags.
    function test_eachListAlone() public {
        for (uint256 i; i < 2; ++i) {
            _clearBob();
            address d = _listed(i, 0, SANCTIONED, bytes32(i));
            address a = _listed(i, KYC, 0, bytes32(i + 10));
            vm.prank(alice);
            IERC20(d).transfer(bob, 1);
            _attest(nid(bob), KYC | SANCTIONED, MAX);
            vm.prank(alice);
            IERC20(a).transfer(bob, 1);
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(bob), uint8(0)));
            IERC20(d).transfer(bob, 1);
        }
    }

    /// A disabled list stops its check (the mirror, Codex 3): after `disableFeature(ALLOWLIST)` an unattested receiver
    /// passes (its `requiredFlags` are no longer read) and `DENYLIST` still refuses; after `(DENYLIST)` (one call each: not
    /// delayed bits) the token makes no registry call.
    function test_disabledListStopsChecking() public {
        for (uint256 i; i < 2; ++i) {
            _clearBob();
            address t = _listed(i, KYC, SANCTIONED, bytes32(i));
            bytes memory ne = abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(bob), uint8(0));
            vm.prank(alice);
            vm.expectRevert(ne);
            IERC20(t).transfer(bob, 1); // the control: unattested, refused by ALLOWLIST
            _disable(t, GovernanceBits.ALLOWLIST);
            vm.prank(alice);
            IERC20(t).transfer(bob, 1); // ALLOWLIST off: requiredFlags no longer read
            _attest(nid(bob), SANCTIONED, MAX);
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(bob), uint8(0)));
            IERC20(t).transfer(bob, 1);
            _disable(t, GovernanceBits.DENYLIST);
            _countStart();
            vm.prank(alice);
            IERC20(t).transfer(bob, 1);
            assertEq(_countEnd(0), 0, "no registry call");
        }
    }

    /// The initial-supply recipient passes `R` (spec §2.4's last row, the mint's own row): kind 8 to an unattested
    /// holder is refused `NotEligible`.
    function test_initialSupplyRecipientChecked() public {
        IFactoryToken.TokenConfig memory c = _cfg8();
        c.features |= 1 << GovernanceBits.ALLOWLIST;
        (c.reg.complianceRegistry, c.reg.requiredFlags) = (address(creg), KYC);
        c.initialHolder = bob;
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(bob), uint8(0)));
        f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "ib");
        _attest(nid(bob), KYC, MAX);
        f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "ib");
    }

    // ------------------------------------------------------------------ the code pin (F-11)

    /// Every registry has one runtime (admin in storage): the deployed code hash is the pinned one, whatever the admin, and
    /// the release carries it (`REGISTRY_CODEHASH`, from `implArgs`).
    function test_registryRuntimeHashPinned() public {
        assertEq(keccak256(type(ComplianceRegistry).runtimeCode), REGISTRY_CODEHASH, "runtime pin");
        assertEq(address(creg).codehash, REGISTRY_CODEHASH, "deployed");
        assertEq(address(new ComplianceRegistry(address(new Holder()))).codehash, REGISTRY_CODEHASH, "another admin");
        for (uint256 i; i < 2; ++i) {
            address impl = f.implementationOf(i == 0 ? IOpenFactory.TokenKind.NORMAL_REGULATED
                : IOpenFactory.TokenKind.WRAPPED_REGULATED, 1);
            assertEq(NormalRegulatedToken(payable(impl)).REGISTRY_CODEHASH(), REGISTRY_CODEHASH, "release");
            assertEq(NormalRegulatedToken(payable(_ks()[i])).REGISTRY_CODEHASH(), REGISTRY_CODEHASH, "token");
        }
    }

    /// Spec §2.4: a registry of another code is refused at init, `RegistryCodeMismatch(registry, codehash)`: a contract of
    /// other code, an EOA, an empty address; the canonical one creates (the control) and is written in slot +0.
    function test_registryCodehashPinned() public {
        for (uint256 i; i < 2; ++i) {
            IOpenFactory.TokenKind k = i == 0 ? IOpenFactory.TokenKind.NORMAL_REGULATED : IOpenFactory.TokenKind.WRAPPED_REGULATED;
            IFactoryToken.TokenConfig memory c = i == 0 ? _cfg8() : _cfg9();
            c.features |= 1 << GovernanceBits.DENYLIST;
            c.reg.deniedFlags = SANCTIONED;
            address other = address(new Holder());
            address[3] memory bad = [other, bob, address(0xDEAD0)];
            for (uint256 j; j < 3; ++j) {
                c.reg.complianceRegistry = bad[j];
                vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.RegistryCodeMismatch.selector, bad[j], bad[j].codehash));
                f.createToken(k, 1, abi.encode(c), bytes32(j));
            }
            c.reg.complianceRegistry = address(creg);
            address t = f.createToken(k, 1, abi.encode(c), "ok");
            IRegulatedToken.RegulatedConfig memory rc = IRegulatedToken(t).regulatedConfig();
            assertEq(rc.complianceRegistry, address(creg));
            assertEq(rc.deniedFlags, SANCTIONED);
            assertEq(rc.controls & 0x18, 0x10, "DENYLIST in the mirror");
        }
    }

    /// A regulated release must carry the hash: `implArgs` empty (or not one word) refuses the release at deploy.
    function test_releaseWithoutCodehashRefused() public {
        IFactoryToken.Env memory e = plainEnv(address(f), address(0), f.chainUid(), address(ureg), false);
        vm.expectRevert();
        this.releaseWith(e, "");
        vm.expectRevert();
        this.releaseWith(e, abi.encode(bytes32(0)));
        this.releaseWith(e, abi.encode(REGISTRY_CODEHASH)); // the control
    }

    function releaseWith(IFactoryToken.Env memory e, bytes memory implArgs) external returns (address) {
        return Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_REGULATED, 2, e, type(NormalRegulatedToken).creationCode,
            implArgs);
    }
}
