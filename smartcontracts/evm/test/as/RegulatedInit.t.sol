// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {nid} from "../helpers/Ids.sol";

/// Plan T28 (regulated-kinds spec §2.4, M-10): kind 8 and kind 9 creation and the init checks, each refusal against the
/// fixture's config that creates (the control); ERC-165 answers `IRegulatedToken` on 8 and 9 only.
contract RegulatedInitTest is RegFixture {
    IOpenFactory.TokenKind constant K8 = IOpenFactory.TokenKind.NORMAL_REGULATED;
    IOpenFactory.TokenKind constant K9 = IOpenFactory.TokenKind.WRAPPED_REGULATED;
    uint256 salt;

    function _create(IOpenFactory.TokenKind k, IFactoryToken.TokenConfig memory c) internal returns (address) {
        return f.createToken(k, 1, abi.encode(c), bytes32(++salt));
    }

    function _refused(IOpenFactory.TokenKind k, IFactoryToken.TokenConfig memory c, bytes memory err) internal {
        vm.expectRevert(err);
        f.createToken(k, 1, abi.encode(c), bytes32(++salt));
    }

    function _cfg(uint256 i) internal view returns (IFactoryToken.TokenConfig memory) {
        return i == 0 ? _cfg8() : _cfg9();
    }

    /// The fixture's tokens: kind 8 and 9, `controls` and `termsHash` written, kind 8's initial supply minted through the
    /// mint row (`R` with both lists off: no call).
    function test_createsKinds8And9() public view {
        assertEq(MetaTokenBase(t8).kind(), 8);
        assertEq(MetaTokenBase(t9).kind(), 9);
        assertEq(IERC20(t8).balanceOf(alice), SUPPLY);
        for (uint256 i; i < 2; ++i) {
            IRegulatedToken.RegulatedConfig memory c = _r(_ks()[i]).regulatedConfig();
            assertEq(c.controls, uint8(REG_FEATURES >> 5));
            assertEq(c.termsHash, TERMS);
            assertEq(c.complianceRegistry, address(0));
            assertEq(c.requiredFlags | c.deniedFlags | c.pausedUntil | c.pauseCooldownUntil, 0);
        }
    }

    /// Spec §2.4: `FORCE ⇒ FREEZE ∧ RECORD`, `RECORD ⇒ FREEZE`, `termsHash ≠ 0 ⇔` any of 5-10, 21, the flags and the
    /// registry with their bits; each `RegulatedConfigInvalid`. `MODERATE` alone (with terms) creates.
    function test_regulatedConfigInvalid() public {
        bytes memory bad = abi.encodeWithSelector(IRegulatedToken.RegulatedConfigInvalid.selector);
        for (uint256 i; i < 2; ++i) {
            IOpenFactory.TokenKind k = i == 0 ? K8 : K9;
            IFactoryToken.TokenConfig memory c = _cfg(i);
            c.features &= ~uint256(1 << 10); // FORCE without RECORD
            c.roles.compliance = 0;
            _refused(k, c, bad);
            c = _cfg(i);
            c.features &= ~uint256(1 << 5); // RECORD (and FORCE) without FREEZE
            _refused(k, c, bad);
            c = _cfg(i);
            c.reg.termsHash = 0;
            _refused(k, c, bad);
            c = _cfg(i);
            c.features &= ~REG_FEATURES; // no regulated bit, terms set
            (c.roles.issuer, c.roles.compliance) = (0, 0);
            _refused(k, c, bad);
            c.reg.termsHash = 0;
            _create(k, c); // the control: a regulated kind with no control
            c.reg.requiredFlags = 1; // flags without ALLOWLIST
            _refused(k, c, bad);
            c.reg.requiredFlags = 0;
            c.reg.deniedFlags = 1;
            _refused(k, c, bad);
            c.reg.deniedFlags = 0;
            c.reg.complianceRegistry = address(0xC0FFEE); // a registry with neither list
            _refused(k, c, bad);
            c = _cfg(i);
            c.features |= 1 << 8; // ALLOWLIST without requiredFlags
            _refused(k, c, bad);
            c = _cfg(i);
            c.features |= 1 << 21; // MODERATE with the other controls: allowed
            _create(k, c);
            c.features = (c.features & ~(REG_FEATURES)) | (1 << 21); // MODERATE alone
            (c.roles.issuer, c.roles.compliance) = (0, 0);
            _create(k, c);
        }
    }

    /// A list on with its flags and a registry that is not the canonical code: refused `RegistryCodeMismatch` (plan T29;
    /// T28 refused it `RegulatedNotBuilt`). The canonical registry: `Registry.t.sol`.
    function test_registryOfOtherCodeRefused() public {
        for (uint256 i; i < 2; ++i) {
            IFactoryToken.TokenConfig memory c = _cfg(i);
            c.features |= 1 << 9;
            (c.reg.deniedFlags, c.reg.complianceRegistry) = (4, address(0xC0FFEE));
            _refused(i == 0 ? K8 : K9, c,
                abi.encodeWithSelector(IRegulatedToken.RegistryCodeMismatch.selector, address(0xC0FFEE), bytes32(0)));
        }
    }

    /// A bit outside the kind's mask first, as `GovernanceLib.init` names it (`FeatureInvalidForKind`).
    function test_bitOutsideTheMask() public {
        for (uint256 i; i < 2; ++i) {
            IFactoryToken.TokenConfig memory c = _cfg(i);
            c.features |= 1 << 11; // LISTING: the DEX's
            _refused(i == 0 ? K8 : K9, c, abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(11)));
        }
    }

    /// The holders (spec §2.4, RK-1, CTR-AS-03): `roles.issuer` / `roles.compliance` contracts (an EOA `RoleNotContract`),
    /// never one id for `FORCE` and `RECORD` (`RoleConflict`); with no owner and the role bits unlocked, `OwnerHasHolders`.
    function test_holderRules() public {
        for (uint256 i; i < 2; ++i) {
            IOpenFactory.TokenKind k = i == 0 ? K8 : K9;
            IFactoryToken.TokenConfig memory c = _cfg(i);
            c.roles.issuer = nid(bob);
            _refused(k, c, abi.encodeWithSelector(IGovernance.RoleNotContract.selector, uint8(5), nid(bob)));
            c = _cfg(i);
            c.roles.compliance = nid(bob);
            _refused(k, c, abi.encodeWithSelector(IGovernance.RoleNotContract.selector, uint8(10), nid(bob)));
            c = _cfg(i);
            c.roles.compliance = nid(issuer);
            _refused(k, c, abi.encodeWithSelector(IGovernance.RoleConflict.selector, uint8(10), nid(issuer)));
            c = _cfg(i);
            c.owner = 0;
            if (i == 0) c.roles.minter = 0;
            _refused(k, c, abi.encodeWithSelector(IGovernance.OwnerHasHolders.selector, uint8(5)));
            c.lockedFeatures = c.features & ~uint256(1); // locked: the holders survive (the control)
            _create(k, c);
        }
    }

    /// M-10: `IRegulatedToken` on kinds 8 and 9 (the base kinds 0 and 1 do not answer it; 0-5 in `RegConfig.t.sol`).
    function test_supportsIRegulatedToken_8() public {
        _supports(t8, IOpenFactory.TokenKind.NORMAL, abi.encode(_cfg8Plain()));
    }

    function test_supportsIRegulatedToken_9() public {
        IFactoryToken.TokenConfig memory c = _cfg9();
        c.features = 1;
        (c.roles.issuer, c.roles.compliance, c.reg.termsHash) = (0, 0, 0);
        _supports(t9, IOpenFactory.TokenKind.WRAPPED, abi.encode(c));
    }

    function _cfg8Plain() internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg8();
        c.features = 7;
        (c.roles.issuer, c.roles.compliance, c.reg.termsHash) = (0, 0, 0);
    }

    function _supports(address reg, IOpenFactory.TokenKind base, bytes memory cfg) internal {
        address plain = f.createToken(base, 1, cfg, "plain");
        bytes4 id = type(IRegulatedToken).interfaceId;
        assertTrue(IERC165(reg).supportsInterface(id), "regulated");
        assertFalse(IERC165(plain).supportsInterface(id), "base kind");
        assertTrue(IERC165(reg).supportsInterface(type(IERC165).interfaceId));
        assertTrue(IERC165(reg).supportsInterface(type(IERC20).interfaceId));
    }
}
