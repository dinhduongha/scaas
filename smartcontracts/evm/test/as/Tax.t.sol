// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture, Holder} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {Catalogue, plainEnv, regArgs} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

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
        fN = EnvKit.factory(address(this), UID, NOTICE);
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


    // ------------------------------------------------------------------ T40: mtxPayWithTax, payWithTax (spec §5)

    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    bytes32 internal constant UA_PAY_WITH_TAX = keccak256(
        "UAPayWithTax(UAMetaTransfer payment,uint8 taxMode,uint256 tax)UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    uint256 internal constant V = 1_000;

    /// alice -> bob `v` on lane 5, relayer bound, `PayMetaKit.meta(seed)`.
    function _tx(address t, bytes32 seed, uint256 v) internal view returns (MetaTxLib.UAMetaTransfer memory x) {
        x = MetaTxLib.UAMetaTransfer(nid(alice), nid(bob), v, PayMetaKit.ref(seed), 5,
            NormalToken(t).mtxNonce(nid(alice), 5), block.timestamp + 300, RR, relayer, 0, address(0));
    }

    function _taxDigest(address t, MetaTxLib.UAMetaTransfer memory x, uint8 mode, uint256 tax) internal view returns (bytes32) {
        return MtxDigest.typed(t, keccak256(abi.encode(UA_PAY_WITH_TAX, MetaTxLib.hashStruct(x), mode, tax)));
    }

    function _taxSig(address t, MetaTxLib.UAMetaTransfer memory x, uint8 mode, uint256 tax)
        internal view returns (IUARegistry.UASig memory s)
    {
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(ALICE_PK, _taxDigest(t, x, mode, tax));
        s.signature = abi.encodePacked(r, ss, v);
    }

    function _payTax(address t, bytes32 seed, uint256 v, uint8 mode, uint256 tax, bytes memory err) internal {
        MetaTxLib.UAMetaTransfer memory x = _tx(t, seed, v);
        IUARegistry.UASig memory s = _taxSig(t, x, mode, tax);
        vm.prank(relayer);
        if (err.length != 0) vm.expectRevert(err);
        IRegulatedToken(t).mtxPayWithTax(x, mode, tax, s, PayMetaKit.meta(seed));
    }

    function _set10pct(address t) internal {
        _rate(t, 100_000);
    }

    function _mismatch(uint256 e, uint256 g) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IRegulatedToken.TaxMismatch.selector, e, g);
    }

    function test_payWithTax_percentExact() public {
        _set10pct(t8t);
        uint256 a0 = IERC20(t8t).balanceOf(alice);
        _payTax(t8t, "p1", V, 1, 100, "");
        assertEq(IERC20(t8t).balanceOf(bob), 900);
        assertEq(IERC20(t8t).balanceOf(taxTo), 100);
        assertEq(IERC20(t8t).balanceOf(alice), a0 - V);
        _payTax(t8t, "p1b", 1_005, 1, 101, _mismatch(100, 101)); // 100.5: the floor, never rounded up (PT-6)
        _payTax(t8t, "p1c", 1_009, 1, 100, "");
        assertEq(IERC20(t8t).balanceOf(taxTo), 200);
    }

    function test_payWithTax_percentOffByOne_up() public {
        _set10pct(t8t);
        _payTax(t8t, "p2", V, 1, 101, _mismatch(100, 101));
    }

    function test_payWithTax_percentOffByOne_down() public {
        _set10pct(t8t);
        _payTax(t8t, "p3", V, 1, 99, _mismatch(100, 99));
    }

    function test_payWithTax_amountAsSigned() public {
        _set10pct(t8t);
        _payTax(t8t, "p4", V, 2, 37, "");
        assertEq(IERC20(t8t).balanceOf(taxTo), 37);
        assertEq(IERC20(t8t).balanceOf(bob), V - 37);
    }

    function test_payWithTax_taxAboveAmount() public {
        _payTax(t8t, "p5", V, 2, V + 1, abi.encodeWithSelector(IRegulatedToken.TaxExceedsAmount.selector, V + 1, V));
        _payTax(t8t, "p5", V, 2, V, ""); // control: the whole amount
    }

    function test_payWithTax_mode0() public {
        _payTax(t8t, "p6", V, 0, 0, abi.encodeWithSelector(IRegulatedToken.TaxModeInvalid.selector, uint8(0)));
    }

    function test_payWithTax_mode3() public {
        _payTax(t8t, "p7", V, 3, 0, abi.encodeWithSelector(IRegulatedToken.TaxModeInvalid.selector, uint8(3)));
    }

    function test_payWithTax_taxOff() public {
        _payTax(t8, "p8", V, 2, 0, abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, GovernanceBits.TAX));
    }

    function test_payWithTax_recipientIsPayee() public {
        MetaTxLib.UAMetaTransfer memory x = _tx(t8t, "p9", V);
        x.to = nid(taxTo);
        IUARegistry.UASig memory s = _taxSig(t8t, x, 2, 1);
        vm.prank(relayer);
        vm.expectRevert(IRegulatedToken.TaxRecipientIsPayee.selector);
        IRegulatedToken(t8t).mtxPayWithTax(x, 2, 1, s, PayMetaKit.meta("p9"));
    }

    function test_payWithTax_recipientFrozen() public {
        _freeze(t8t, nid(taxTo));
        _payTax(t8t, "pa", V, 2, 1, abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, nid(taxTo)));
        _payTax(t8t, "pb", V, 2, 0, ""); // a zero tax leg reads no recipient seat
    }

    /// RK-6 at the tax leg: a recipient no longer eligible (`!R(r)`) is refused `NotEligible` before effects; a zero tax
    ///         reads no recipient seat.
    function test_payWithTax_recipientUnattested() public {
        _attest(nid(alice), KYC, type(uint64).max);
        _attest(nid(bob), KYC, type(uint64).max);
        _attest(nid(taxTo), KYC, type(uint64).max);
        IFactoryToken.TokenConfig memory c = _taxCfg8(nid(taxTo));
        (c.features, c.reg.complianceRegistry, c.reg.requiredFlags) =
            (c.features | (1 << GovernanceBits.ALLOWLIST), address(creg), KYC);
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "tl3");
        _payTax(t, "pu", V, 2, 1, ""); // control: attested
        _attest(nid(taxTo), 0, type(uint64).max);
        _payTax(t, "pv", V, 2, 1, abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(taxTo), uint8(0)));
        _payTax(t, "pw", V, 2, 0, "");
    }

    function test_payWithTax_frozenPayeePasses() public {
        _freeze(t8t, nid(bob));
        _payTax(t8t, "pc", V, 2, 10, "");
        assertEq(IERC20(t8t).balanceOf(bob), V - 10);
    }

    /// J3 with coinciding roles: the fee recipient is the tax recipient; the deltas add.
    function test_payWithTax_books() public {
        MetaTxLib.UAMetaTransfer memory x = _tx(t8t, "pd", V);
        (x.mode, x.fee, x.feeRecipient) = (RR | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT | MetaTxLib.MODE_FEE_FIXED, 3, taxTo);
        IUARegistry.UASig memory s = _taxSig(t8t, x, 2, 40);
        uint256 a0 = IERC20(t8t).balanceOf(alice);
        uint256 s0 = IERC20(t8t).totalSupply();
        vm.prank(relayer);
        IRegulatedToken(t8t).mtxPayWithTax(x, 2, 40, s, PayMetaKit.meta("pd"));
        assertEq(IERC20(t8t).balanceOf(alice), a0 - V - 3, "payer -(value + fee)");
        assertEq(IERC20(t8t).balanceOf(bob), V - 40, "payee +(value - tax)");
        assertEq(IERC20(t8t).balanceOf(taxTo), 40 + 3, "recipient +tax, fee recipient +fee");
        assertEq(IERC20(t8t).totalSupply(), s0);
    }

    function test_payWithTax_zeroTaxEmits() public {
        MetaTxLib.UAMetaTransfer memory x = _tx(t8t, "pe", V);
        IUARegistry.UASig memory s = _taxSig(t8t, x, 2, 0);
        vm.expectEmit(t8t);
        emit IRegulatedToken.PaymentTaxed(x.entryRef, x.to, nid(taxTo), x.from, 2, 0, _taxDigest(t8t, x, 2, 0));
        vm.prank(relayer);
        IRegulatedToken(t8t).mtxPayWithTax(x, 2, 0, s, PayMetaKit.meta("pe"));
    }

    /// C7: signed at 10 %, the rate lowered to 5 %, lands: `TaxMismatch`; the node re-signs.
    function test_payWithTax_inFlightRateLowered() public {
        _set10pct(t8t);
        MetaTxLib.UAMetaTransfer memory x = _tx(t8t, "pf", V);
        IUARegistry.UASig memory s = _taxSig(t8t, x, 1, 100);
        _rate(t8t, 50_000);
        vm.prank(relayer);
        vm.expectRevert(_mismatch(50, 100));
        IRegulatedToken(t8t).mtxPayWithTax(x, 1, 100, s, PayMetaKit.meta("pf"));
    }

    /// C7: signed at 10 %, an increase to 20 % matured at `eta`, lands: `TaxMismatch`.
    function test_payWithTax_inFlightIncreaseMatured() public {
        _set10pct(t8n);
        vm.warp(block.timestamp + NOTICE);
        MetaTxLib.UAMetaTransfer memory x = _tx(t8n, "pg", V);
        IUARegistry.UASig memory s = _taxSig(t8n, x, 1, 100);
        _rate(t8n, 200_000);
        vm.warp(block.timestamp + NOTICE);
        vm.prank(relayer);
        vm.expectRevert(_mismatch(200, 100));
        IRegulatedToken(t8n).mtxPayWithTax(x, 1, 100, s, PayMetaKit.meta("pg"));
    }

    /// The canonical digest: an unbound `relayer` / `feeRecipient` is zeroed in the nested struct (`MetaTxLib.canon`).
    function test_payWithTax_digestZeroesUnboundFields() public {
        MetaTxLib.UAMetaTransfer memory x = _tx(t8t, "ph", V);
        x.mode = 0;
        (x.relayer, x.feeRecipient) = (address(0xDEAD), address(0xBEEF));
        MetaTxLib.UAMetaTransfer memory z = x;
        (z.relayer, z.feeRecipient) = (address(0), address(0));
        bytes32 raw = keccak256(abi.encode(MetaTxLib.UAMETATRANSFER_TYPEHASH, x.from, x.to, x.value, x.entryRef, x.batch,
            x.nonce, x.validUntil, x.mode, address(0), x.fee, address(0)));
        assertEq(MetaTxLib.hashStruct(x), raw, "zeroed");
        IUARegistry.UASig memory s = _taxSig(t8t, z, 2, 1); // signed over the zeroed form
        vm.prank(address(0xF00));
        IRegulatedToken(t8t).mtxPayWithTax(x, 2, 1, s, PayMetaKit.meta("ph"));
    }

    // ---- the direct twin (spec §5.6)

    function test_directPayWithTax_eoaCaller() public {
        _set10pct(t8t);
        vm.expectEmit(t8t);
        emit IUALedger.UAPaymentSettled(nid(alice), nid(bob), V, 0, address(0), PayMetaKit.ref("q1"));
        vm.expectEmit(t8t);
        emit IRegulatedToken.PaymentTaxed(PayMetaKit.ref("q1"), nid(bob), nid(taxTo), nid(alice), 1, 100, 0);
        vm.prank(alice);
        IRegulatedToken(t8t).payWithTax(nid(bob), V, 1, 100, PayMetaKit.ref("q1"), PayMetaKit.meta("q1"));
        assertEq(IERC20(t8t).balanceOf(bob), 900);
        assertEq(IERC20(t8t).balanceOf(taxTo), 100);
    }

    function test_directPayWithTax_contractCaller() public {
        Holder payer = new Holder();
        vm.prank(alice);
        IERC20(t8t).transfer(address(payer), V);
        vm.prank(address(payer));
        IRegulatedToken(t8t).payWithTax(nid(bob), V, 2, 30, PayMetaKit.ref("q2"), PayMetaKit.meta("q2"));
        assertEq(IERC20(t8t).balanceOf(address(payer)), 0);
        assertEq(IERC20(t8t).balanceOf(bob), V - 30);
    }

    function test_directPayWithTax_frozenCaller() public {
        _freeze(t8t, nid(alice));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(alice)));
        IRegulatedToken(t8t).payWithTax(nid(bob), V, 2, 1, PayMetaKit.ref("q3"), PayMetaKit.meta("q3"));
    }

    function test_directPayWithTax_mismatchedMeta() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, PayMetaKit.ref("q4"),
            PayMetaKit.ref("other")));
        IRegulatedToken(t8t).payWithTax(nid(bob), V, 2, 1, PayMetaKit.ref("q4"), PayMetaKit.meta("other"));
    }

    /// Spec §14 on the direct twin: each refusal by name, one change at a time against a control that lands.
    function test_directPayWithTax_refusals() public {
        _set10pct(t8t);
        _direct(t8t, nid(bob), V, 1, 101, "r1", _mismatch(100, 101));
        _direct(t8t, nid(bob), V, 1, 99, "r2", _mismatch(100, 99));
        _direct(t8t, nid(bob), V, 2, V + 1, "r3", abi.encodeWithSelector(IRegulatedToken.TaxExceedsAmount.selector, V + 1, V));
        _direct(t8t, nid(taxTo), V, 2, 1, "r4", abi.encodeWithSelector(IRegulatedToken.TaxRecipientIsPayee.selector));
        _direct(t8, nid(bob), V, 2, 1, "r5", abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, GovernanceBits.TAX));
        _freeze(t8t, nid(taxTo));
        _direct(t8t, nid(bob), V, 2, 1, "r6", abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, nid(taxTo)));
        _unfreeze(t8t, nid(taxTo));
        _direct(t8t, nid(bob), V, 1, 100, "r7", ""); // control
        assertEq(IERC20(t8t).balanceOf(taxTo), 100);
    }

    // ---- plan T83: the pay records of the two tax forms (owner 2026-11-09)

    /// `mtxPayWithTax` and `payWithTax` with `save`: the record is what the payee received, `value - tax`; `save` off writes
    /// nothing.
    function test_payWithTax_recordsNet() public {
        _set10pct(t8t);
        bytes32 no = bytes32(uint256(0x019a6e3c5f007a3b8c4d5e6f708192a3));
        MetaTxLib.PayMeta memory m = PayMetaKit.saved("rec1", no);
        MetaTxLib.UAMetaTransfer memory x = _tx(t8t, "rec1", V);
        x.entryRef = PayMetaKit.id(m);
        IUARegistry.UASig memory s = _taxSig(t8t, x, 1, 100);
        vm.roll(300);
        vm.prank(relayer);
        IRegulatedToken(t8t).mtxPayWithTax(x, 1, 100, s, m);
        MetaTxLib.PayMeta memory d = PayMetaKit.saved("rec2", no);
        vm.roll(301);
        vm.prank(alice);
        IRegulatedToken(t8t).payWithTax(nid(bob), V, 2, 30, PayMetaKit.id(d), d);
        MetaTxLib.PayRecord[] memory r = NormalToken(t8t).paymentsOf(no, 0, 5);
        assertEq(r.length, 2);
        assertEq(r[0].to, nid(bob));
        assertEq(r[0].amount, V - 100);
        assertEq(r[0].blockNumber, 300);
        assertEq(r[1].to, nid(bob));
        assertEq(r[1].amount, V - 30);
        assertEq(r[1].blockNumber, 301);
        assertEq(IERC20(t8t).balanceOf(bob), 2 * V - 130);
        _payTax(t8t, "rec3", V, 1, 100, ""); // `PayMetaKit.meta`: `save` off
        _direct(t8t, nid(bob), V, 2, 1, "rec4", "");
        assertEq(NormalToken(t8t).paymentCount(no), 2);
        assertEq(NormalToken(t8t).paymentCount(0), 0);
    }

    function _direct(address t, bytes32 to, uint256 v, uint8 mode, uint256 tax, bytes32 seed, bytes memory err) internal {
        vm.prank(alice);
        if (err.length != 0) vm.expectRevert(err);
        IRegulatedToken(t).payWithTax(to, v, mode, tax, PayMetaKit.ref(seed), PayMetaKit.meta(seed));
    }

    function test_directPayWithTax_notInMtxSelectors() public view {
        (bytes4[] memory s,,) = IMetaTx(t8t).mtxSelectors();
        for (uint256 i; i < s.length; ++i) {
            assertTrue(s[i] != IRegulatedToken.payWithTax.selector, "payWithTax allow-listed");
            assertTrue(s[i] != IRegulatedToken.mtxPayWithTax.selector, "mtxPayWithTax allow-listed");
        }
    }

    // ---- paytax.json (spec §7, PT-6, F-27, F-06): written with PAYTAX_WRITE=1, else checked

    string internal constant PAYTAX = "../vectors/metatx/paytax.json";

    struct TaxRow {
        string name;
        uint8 mode;
        uint32 ratePpm;
        uint256 amount;
        uint256 tax;
        string refused; // "" or the error's name
    }

    function _taxRows() internal pure returns (TaxRow[] memory r) {
        uint32[4] memory rates = [uint32(0), 1, 100_000, 1_000_000];
        uint256[4] memory amts = [uint256(0), 1, 999_999, uint256(1) << 255];
        r = new TaxRow[](24);
        uint256 n;
        for (uint256 i; i < 4; ++i) {
            for (uint256 j; j < 4; ++j) {
                r[n++] = TaxRow(string.concat("percent_", vm.toString(rates[i]), "_", vm.toString(amts[j])), 1, rates[i],
                    amts[j], Math.mulDiv(amts[j], rates[i], 1_000_000), "");
            }
        }
        r[n++] = TaxRow("percent_floor_not_half_up", 1, 100_000, 1_005, 100, ""); // 100.5: half-up 101
        r[n++] = TaxRow("percent_floor_below_one", 1, 100_000, 9, 0, ""); // 0.9
        r[n++] = TaxRow("percent_floor_edge", 1, 333_333, 1_000_000, 333_333, "");
        r[n++] = TaxRow("amount_whole", 2, 100_000, 1_000, 1_000, "");
        r[n++] = TaxRow("amount_zero", 2, 100_000, 1_000, 0, "");
        r[n++] = TaxRow("amount_above_refused", 2, 100_000, 1_000, 1_001, "TaxExceedsAmount");
        r[n++] = TaxRow("percent_mismatch_refused", 1, 100_000, 1_000, 101, "TaxMismatch");
        r[n++] = TaxRow("mode_invalid_refused", 3, 100_000, 1_000, 0, "TaxModeInvalid");
    }

    function _taxRowJson(TaxRow memory r) internal pure returns (string memory) {
        return string.concat('  {"name":"', r.name, '","taxMode":', vm.toString(r.mode), ',"ratePpm":', vm.toString(r.ratePpm),
            ',"amount":"', vm.toString(r.amount), '","tax":"', vm.toString(r.tax), '","refused":"', r.refused, '"}');
    }

    /// The `UAPayWithTax` digest row: non-zero `relayer` / `feeRecipient` in the input, unbound (mode 0), so zeroed.
    function _digestRowJson(MetaTxLib.UAMetaTransfer memory x, uint8 mode, uint256 tax) internal view returns (string memory) {
        bytes32 sh = keccak256(abi.encode(UA_PAY_WITH_TAX, MetaTxLib.hashStruct(x), mode, tax));
        string memory d = string.concat(',"typehash":"', vm.toString(UA_PAY_WITH_TAX), '","paymentHash":"',
            vm.toString(MetaTxLib.hashStruct(x)), '","structHash":"', vm.toString(sh), '","digest":"',
            vm.toString(_vecDigest(sh)), '"}');
        return string.concat('  {"name":"digest_unbound_relayer_fee_recipient",', _payJson(x), ',"taxMode":',
            vm.toString(mode), ',"tax":"', vm.toString(tax), '",', _domainJson(), d);
    }

    function _payJson(MetaTxLib.UAMetaTransfer memory x) internal pure returns (string memory) {
        string memory a = string.concat('"from":"', vm.toString(x.from), '","to":"', vm.toString(x.to), '","value":"',
            vm.toString(x.value), '","entryRef":"', vm.toString(x.entryRef), '","batch":"', vm.toString(x.batch));
        return string.concat(a, '","nonce":"', vm.toString(x.nonce), '","validUntil":"', vm.toString(x.validUntil),
            '","mode":', vm.toString(x.mode), ',"relayer":"', vm.toString(x.relayer), '","fee":"', vm.toString(x.fee),
            '","feeRecipient":"', vm.toString(x.feeRecipient), '"');
    }

    /// The vector's fixed domain (a token's shape: name, version, chainId, verifyingContract, salt), so the row does not move
    /// with a deployment address; the tests above sign the same struct hash in a live token's domain and land.
    string internal constant VEC_NAME = "SCaaS MetaToken";
    uint256 internal constant VEC_CHAIN = 7622;
    address internal constant VEC_TOKEN = address(0x7A7a7A7a7a7a7a7A7a7a7a7A7a7A7A7A7A7A7a7A);
    bytes32 internal constant VEC_SALT = keccak256("scaas.paytax.vector");

    function _vecDigest(bytes32 sh) internal pure returns (bytes32) {
        bytes32 ds = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(VEC_NAME)), keccak256("1"), VEC_CHAIN, VEC_TOKEN, VEC_SALT));
        return keccak256(abi.encodePacked(hex"1901", ds, sh));
    }

    function _domainJson() internal pure returns (string memory) {
        return string.concat('"domain":{"name":"', VEC_NAME, '","version":"1","chainId":', vm.toString(VEC_CHAIN),
            ',"verifyingContract":"', vm.toString(VEC_TOKEN), '","salt":"', vm.toString(VEC_SALT), '"}');
    }

    function _digestInput() internal view returns (MetaTxLib.UAMetaTransfer memory x) {
        x = MetaTxLib.UAMetaTransfer(nid(alice), nid(bob), 1_000, PayMetaKit.ref("vec"), 7, 3, 1_900_000_000, 0,
            address(0xDEAD), 0, address(0xBEEF));
    }

    function test_payTaxVectors() public {
        TaxRow[] memory rows = _taxRows();
        if (vm.envOr("PAYTAX_WRITE", false)) {
            string memory j = "[\n";
            for (uint256 i; i < rows.length; ++i) j = string.concat(j, i == 0 ? "" : ",\n", _taxRowJson(rows[i]));
            j = string.concat(j, ",\n", _digestRowJson(_digestInput(), 2, 50));
            vm.writeFile(PAYTAX, string.concat(j, "\n]\n"));
        }
        string memory f = vm.readFile(PAYTAX);
        uint256 n;
        while (vm.keyExistsJson(f, string.concat("[", vm.toString(n), "]"))) ++n;
        assertEq(n, rows.length + 1, "rows");
        for (uint256 i; i < rows.length; ++i) {
            string memory p = string.concat("[", vm.toString(i), "]");
            uint256 amount = vm.parseUint(vm.parseJsonString(f, string.concat(p, ".amount")));
            uint256 tax = vm.parseUint(vm.parseJsonString(f, string.concat(p, ".tax")));
            uint8 mode = uint8(vm.parseJsonUint(f, string.concat(p, ".taxMode")));
            uint32 rate = uint32(vm.parseJsonUint(f, string.concat(p, ".ratePpm")));
            assertEq(amount, rows[i].amount, rows[i].name);
            assertEq(tax, rows[i].tax, rows[i].name);
            bool refused = bytes(vm.parseJsonString(f, string.concat(p, ".refused"))).length != 0;
            if (mode == 1 && !refused) assertEq(tax, Math.mulDiv(amount, rate, 1_000_000), "PERCENT floor");
            if (amount > 1_000_000 || amount == 0) continue; // the contract rows run what alice holds
            // the row on the token: the rate set, the pay landed or refused by name
            uint256 snap = vm.snapshotState();
            _rate(t8t, rate);
            bytes memory err;
            if (refused) {
                err = mode != 1 && mode != 2 ? abi.encodeWithSelector(IRegulatedToken.TaxModeInvalid.selector, mode)
                    : tax > amount ? abi.encodeWithSelector(IRegulatedToken.TaxExceedsAmount.selector, tax, amount)
                    : _mismatch(Math.mulDiv(amount, rate, 1_000_000), tax);
            }
            _payTax(t8t, keccak256(bytes(rows[i].name)), amount, mode, tax, err);
            vm.revertToState(snap);
        }
        string memory q = string.concat("[", vm.toString(rows.length), "]");
        MetaTxLib.UAMetaTransfer memory x = _digestInput();
        bytes32 sh = keccak256(abi.encode(UA_PAY_WITH_TAX, MetaTxLib.hashStruct(x), uint8(2), uint256(50)));
        assertEq(vm.parseJsonBytes32(f, string.concat(q, ".structHash")), sh, "UAPayWithTax struct hash");
        assertEq(vm.parseJsonBytes32(f, string.concat(q, ".digest")), _vecDigest(sh), "UAPayWithTax digest");
        assertEq(vm.parseJsonBytes32(f, string.concat(q, ".paymentHash")), MetaTxLib.hashStruct(x), "canonical payment");
    }

    // ---- typed_ops.json's `UAPayWithTax` row (clientkeys, pay-meta-tax T41)

    function _rowPayment(string memory j, string memory p) internal pure returns (MetaTxLib.UAMetaTransfer memory x) {
        x.from = vm.parseJsonBytes32(j, string.concat(p, "from"));
        x.to = vm.parseJsonBytes32(j, string.concat(p, "to"));
        x.value = vm.parseJsonUint(j, string.concat(p, "value"));
        x.entryRef = vm.parseJsonBytes32(j, string.concat(p, "entryRef"));
        x.batch = vm.parseJsonUint(j, string.concat(p, "batch"));
        x.nonce = vm.parseJsonUint(j, string.concat(p, "nonce"));
        x.validUntil = vm.parseJsonUint(j, string.concat(p, "validUntil"));
        x.mode = uint32(vm.parseJsonUint(j, string.concat(p, "mode")));
        x.relayer = vm.parseJsonAddress(j, string.concat(p, "relayer"));
        x.fee = vm.parseJsonUint(j, string.concat(p, "fee"));
        x.feeRecipient = vm.parseJsonAddress(j, string.concat(p, "feeRecipient"));
    }

    function _rowMeta(string memory j, string memory p) internal pure returns (MetaTxLib.PayMeta memory m) {
        m.salt = vm.parseJsonBytes32(j, string.concat(p, "salt"));
        m.payNo = vm.parseJsonBytes32(j, string.concat(p, "payNo"));
        m.save = vm.parseJsonBool(j, string.concat(p, "save"));
        m.schema = uint16(vm.parseJsonUint(j, string.concat(p, "schema")));
        m.body = vm.parseJsonBytes(j, string.concat(p, "body"));
    }

    /// The row's struct hash is the contract's formula, its calldata the entry's with the row's `PayMeta`; re-signed by the
    /// row's key under this kind-8 token's domain, it lands: payee `+(value - tax)`, recipient `+tax`.
    function test_payWithTax_typedOpsRow() public {
        string memory j = vm.readFile("../vectors/typed/typed_ops.json");
        MetaTxLib.UAMetaTransfer memory x = _rowPayment(j, ".ops.UAPayWithTax.message.payment.");
        uint8 mode = uint8(vm.parseJsonUint(j, ".ops.UAPayWithTax.message.taxMode"));
        uint256 tax = vm.parseJsonUint(j, ".ops.UAPayWithTax.message.tax");
        assertEq(keccak256(abi.encode(UA_PAY_WITH_TAX, MetaTxLib.hashStruct(x), mode, tax)),
            vm.parseJsonBytes32(j, ".ops.UAPayWithTax.structHash"), "struct hash");
        assertEq(vm.parseJsonBytes32(j, ".ops.UAPayWithTax.typehash"), keccak256(bytes(vm.parseJsonString(j, ".ops.UAPayWithTax.typeString"))));
        assertEq(vm.parseJsonBytes32(j, ".ops.UAPayWithTax.typehash"), UA_PAY_WITH_TAX, "UAPayWithTax typehash");
        MetaTxLib.PayMeta memory m = _rowMeta(j, ".ops.UAPayWithTax.domains.token.extra.meta.");
        assertEq(PayMetaKit.id(m), x.entryRef, "the row's entryRef commits to its PayMeta");
        IUARegistry.UASig memory rowSig;
        rowSig.signature = vm.parseJsonBytes(j, ".ops.UAPayWithTax.domains.token.signature");
        assertEq(keccak256(abi.encodeCall(IRegulatedToken.mtxPayWithTax, (x, mode, tax, rowSig, m))),
            keccak256(vm.parseJsonBytes(j, ".ops.UAPayWithTax.domains.token.calldata")), "the row's calldata");
        uint256 pk = vm.parseJsonUint(j, ".key.private");
        assertEq(x.from, nid(vm.addr(pk)));
        NormalToken(t8t).mint(vm.addr(pk), x.value); // this test is the kind-8 token's minter
        vm.warp(x.validUntil - 300);
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, _taxDigest(t8t, x, mode, tax));
        IUARegistry.UASig memory s;
        s.signature = abi.encodePacked(r, ss, v);
        vm.prank(x.relayer);
        IRegulatedToken(t8t).mtxPayWithTax(x, mode, tax, s, m);
        assertEq(IERC20(t8t).balanceOf(address(uint160(uint256(x.to)))), x.value - tax);
        assertEq(IERC20(t8t).balanceOf(taxTo), tax);
    }
}
