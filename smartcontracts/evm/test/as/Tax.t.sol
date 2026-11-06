// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture, Holder} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {Catalogue, plainEnv, regArgs} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";

/// @notice Pay-meta-tax spec §6 (T39; PT-5, PT-6, O9, O10, Q4, Q5): bit 23 `TAX` on kinds 8 and 9 (the six regulated
///         kinds share `RegulatedBase` and `RegulatedLib`; 10-13 in `test/as/confidential/TaxConfidential.t.sol`), the one
///         PERCENT rate (a decrease at once, an increase after the factory's `noticePeriod()`), the recipient (not 0, a pool,
///         the token, an unregistered UA, a frozen or unattested id; a padded native address is valid), the issuer seat, the
///         immediate relaxations. **UNAUDITED.**
contract TaxTest is RegFixture {
    uint64 internal constant NOTICE = 3 days;
    address internal taxTo = address(0x7A0);
    address internal clerk = address(0xC1E2);
    address internal t8t; // kind 8 with `TAX`, notice 0 (the fixture's factory)
    OpenFactory internal fN; // a factory with `NOTICE`
    address internal t8n; // kind 8 with `TAX` on `fN`

    function setUp() public override {
        super.setUp();
        t8t = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(_taxCfg8(nid(taxTo))), "tax8");
        fN = new OpenFactory(address(this), UID, NOTICE);
        Catalogue.release(fN, IOpenFactory.TokenKind.NORMAL_REGULATED, 1, plainEnv(address(fN), address(0), UID,
            address(ureg), false), type(NormalRegulatedToken).creationCode, regArgs());
        fN.setKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED, true);
        vm.warp(block.timestamp + NOTICE); // the release is usable after the factory's notice period
        t8n = fN.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(_taxCfg8(nid(taxTo))), "tax8n");
    }

    function _taxCfg8(bytes32 r) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg8();
        c.features |= 1 << GovernanceBits.TAX;
        c.reg.taxRecipient = r;
    }

    function _rate(address t, uint32 ppm) internal {
        vm.prank(issuer);
        IRegulatedToken(t).setTaxRate(ppm);
    }

    function _cfgOf(address t) internal view returns (IRegulatedToken.TaxConfig memory) {
        return IRegulatedToken(t).taxConfig();
    }

    // ------------------------------------------------------------------ the bit (spec §6.1)

    function test_taxBit_validOn_8_9() public view {
        assertEq(IGovernance(t8).validBits() & (1 << 23), 1 << 23, "8");
        assertEq(IGovernance(t9).validBits() & (1 << 23), 1 << 23, "9");
    }

    /// `init` grants the issuer seat bit 23 (F-19); an EOA holder beside a contract issuer by `grantRole` after creation
    /// (A-1); `TAX` is never contract-only (O9).
    function test_taxBit_eoaHolderGrantedAfterCreation() public {
        IFactoryToken.TokenConfig memory c = _taxCfg8(nid(taxTo));
        c.grantDelay = 0;
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "eoa");
        assertTrue(IGovernance(t).hasRole(GovernanceBits.TAX, nid(issuer)), "the issuer seat");
        vm.prank(ownerA);
        IGovernance(t).grantRole(GovernanceBits.TAX, nid(clerk));
        vm.prank(clerk);
        IRegulatedToken(t).setTaxRate(1_000);
        assertEq(_cfgOf(t).effectivePpm, 1_000);
    }

    /// An issuer that holds only bit 23 (an EOA) passes `init` (F-19).
    function test_taxBit_issuerOnlyBit23Init() public {
        IFactoryToken.TokenConfig memory c = _cfg8();
        c.features = (1 << GovernanceBits.PAYABLE) | (1 << GovernanceBits.TAX);
        c.reg.termsHash = 0;
        c.reg.taxRecipient = nid(taxTo);
        (c.roles.issuer, c.roles.compliance, c.roles.minter) = (nid(clerk), 0, 0);
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "only23");
        assertTrue(IGovernance(t).hasRole(GovernanceBits.TAX, nid(clerk)));
        vm.prank(clerk);
        IRegulatedToken(t).setTaxRecipient(nid(address(0x7A1)));
        assertEq(_cfgOf(t).taxRecipient, nid(address(0x7A1)));
    }

    /// `taxRecipient != 0` iff bit 23 (B-5): set without the bit, and the bit without a recipient, are refused.
    function test_taxRecipientZeroInitRefused_8() public {
        IFactoryToken.TokenConfig memory c = _taxCfg8(0);
        vm.expectRevert(IRegulatedToken.RegulatedConfigInvalid.selector);
        f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "z");
        c = _cfg8();
        c.reg.taxRecipient = nid(taxTo);
        vm.expectRevert(IRegulatedToken.RegulatedConfigInvalid.selector);
        f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "z2");
    }

    /// `RoleRevoked(23)` and `disableFeature(23)` apply at once (Q5): never delay-relaxed.
    function test_taxBit_revokeAndDisableImmediate() public {
        vm.prank(ownerA);
        IGovernance(t8t).revokeRole(GovernanceBits.TAX, nid(issuer));
        assertFalse(IGovernance(t8t).hasRole(GovernanceBits.TAX, nid(issuer)), "revoked at once");
        vm.prank(ownerA);
        IGovernance(t8t).disableFeature(GovernanceBits.TAX);
        assertFalse(_cfgOf(t8t).enabled, "disabled at once");
    }

    // ------------------------------------------------------------------ the rate (spec §6.2, PT-5)

    function test_setTaxRate_decreaseImmediate() public {
        _rate(t8n, 100_000);
        vm.warp(block.timestamp + NOTICE);
        assertEq(_cfgOf(t8n).effectivePpm, 100_000);
        vm.expectEmit(t8n);
        emit IRegulatedToken.TaxRateSet(50_000, uint64(block.timestamp));
        _rate(t8n, 50_000);
        assertEq(_cfgOf(t8n).effectivePpm, 50_000);
    }

    function test_setTaxRate_increaseNotBeforeEta() public {
        uint64 eta = uint64(block.timestamp) + NOTICE;
        vm.expectEmit(t8n);
        emit IRegulatedToken.TaxRateSet(100_000, eta);
        _rate(t8n, 100_000);
        IRegulatedToken.TaxConfig memory c = _cfgOf(t8n);
        assertEq(c.ratePpm, 0);
        assertEq(c.pendingPpm, 100_000);
        assertEq(c.eta, eta);
        assertEq(c.noticePeriod, NOTICE);
        vm.warp(eta - 1);
        assertEq(_cfgOf(t8n).effectivePpm, 0, "not before eta");
    }

    function test_setTaxRate_increaseAtEta() public {
        _rate(t8n, 100_000);
        vm.warp(block.timestamp + NOTICE);
        assertEq(_cfgOf(t8n).effectivePpm, 100_000, "at eta");
    }

    function test_setTaxRate_decreaseCancelsPending() public {
        _rate(t8n, 100_000);
        _rate(t8n, 0);
        vm.warp(block.timestamp + NOTICE);
        IRegulatedToken.TaxConfig memory c = _cfgOf(t8n);
        assertEq(c.effectivePpm, 0);
        assertEq(c.pendingPpm, 0);
        assertEq(c.eta, 0);
    }

    function test_setTaxRate_noticeZeroImmediate() public {
        _rate(t8t, 100_000);
        assertEq(_cfgOf(t8t).effectivePpm, 100_000);
    }

    function test_setTaxRate_boundAndHolder() public {
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.TaxRateInvalid.selector, uint32(1_000_001)));
        IRegulatedToken(t8t).setTaxRate(1_000_001);
        _rate(t8t, 1_000_000);
        vm.prank(clerk);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, GovernanceBits.TAX, nid(clerk)));
        IRegulatedToken(t8t).setTaxRate(1);
    }

    // ------------------------------------------------------------------ the recipient (spec §6.2, F-15, F-21)

    function _recipientRefused(bytes32 r, bytes memory err) internal {
        vm.prank(issuer);
        vm.expectRevert(err);
        IRegulatedToken(t8t).setTaxRecipient(r);
    }

    function test_setTaxRecipient_poolRefused() public {
        bytes4 e = IRegulatedToken.TaxRecipientInvalid.selector;
        _recipientRefused(nid(MetaTxLib.UA_POOL), abi.encodeWithSelector(e, nid(MetaTxLib.UA_POOL)));
        _recipientRefused(nid(MetaTxLib.SHIELD_POOL), abi.encodeWithSelector(e, nid(MetaTxLib.SHIELD_POOL)));
        _recipientRefused(0, abi.encodeWithSelector(e, bytes32(0)));
    }

    function test_setTaxRecipient_tokenRefused() public {
        _recipientRefused(nid(t8t), abi.encodeWithSelector(IRegulatedToken.TaxRecipientInvalid.selector, nid(t8t)));
    }

    function test_setTaxRecipient_unregisteredRefused() public {
        bytes32 ua = bytes32(uint256(0xBAD) << 160);
        // the fixture's stub registry answers SIGNING for every id; this one is not registered
        vm.mockCall(address(ureg), abi.encodeWithSelector(IUARegistry.kindOf.selector, ua), abi.encode(uint16(0)));
        _recipientRefused(ua, abi.encodeWithSelector(IUALedger.UANotRegistered.selector, ua));
    }

    function test_setTaxRecipient_frozenRefused() public {
        bytes32 r = nid(address(0x7A2));
        _freeze(t8t, r);
        _recipientRefused(r, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, r));
    }

    function test_setTaxRecipient_unattestedRefused() public {
        _attest(nid(alice), KYC, type(uint64).max);
        IFactoryToken.TokenConfig memory c = _taxCfg8(nid(taxTo));
        (c.features, c.reg.complianceRegistry, c.reg.requiredFlags) =
            (c.features | (1 << GovernanceBits.ALLOWLIST), address(creg), KYC);
        _attest(nid(taxTo), KYC, type(uint64).max);
        c.reg.taxRecipient = nid(taxTo);
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "tl2");
        bytes32 r = nid(address(0x7A3));
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, r, uint8(0)));
        IRegulatedToken(t).setTaxRecipient(r);
        _attest(r, KYC, type(uint64).max); // control
        vm.prank(issuer);
        IRegulatedToken(t).setTaxRecipient(r);
    }

    function test_setTaxRecipient_paddedNativeAccepted() public {
        bytes32 r = nid(address(0x7A4));
        vm.expectEmit(t8t);
        emit IRegulatedToken.TaxRecipientSet(r);
        vm.prank(issuer);
        IRegulatedToken(t8t).setTaxRecipient(r);
        assertEq(_cfgOf(t8t).taxRecipient, r);
    }
}
