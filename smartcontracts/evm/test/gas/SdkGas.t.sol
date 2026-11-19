// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {SdkGasRegFix} from "./SdkGasFixtures.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {SdkGasLedger} from "./SdkGasLedger.sol";

/// The `token` domain kind's base rows on `NormalToken` and `WrappedToken` (the generator stores the worst over these and
/// the regulated variants, `SdkGasRegulatedTest`); the wrap family on Wrapped only, the burn on Normal only. A1 (owner
/// 2026-11-19): the derived reference signer (`SdkGasLedger`) holds 1,000 units of the token in the ledger in its run, as the
/// native signer holds them.
contract SdkGasTokenTest is SdkGasLedger {
    function setUp() public override {
        super.setUp();
        _sgVerifiers();
        sgPk = ALICE_PK;
        _wrapFor(alice, 2_000);
        _wrapL(alice, 2_000);
        (sgLeg, sgLedgerLeg, sgUaTo) = (address(und), address(tok), uaP);
        _sgUaSigner();
    }

    /// A1: the derived signer's 1,000 units of the token `c` (`tok`, `wrp`, `wrpL`), from the native signer, in its run only.
    function _sgUaPrep(address c) internal override {
        vm.prank(alice);
        WrappedToken(payable(c)).transferToUA(UAKinds.uaOf(sgUaKind, sgUaKey), 1_000);
    }

    function test_sdkGas_token() public {
        _commonRows("token", "normal", address(tok));
        _commonRows("token", "wrapped", address(wrp));
        _both("token", "mtxBurn", "normal", address(tok), _sgFrom(), _burn);
        _unwrapRows("token", "wrapped", address(wrp), address(wrpL));
        // the wrap-in entries on a wrapper the signer holds nothing of (its first units: a first write)
        WrappedToken w = _wrapper(address(und));
        und.mint(alice, 1_000);
        vm.prank(alice);
        und.approve(address(w), 1_000);
        _wrapInRows("token", "wrapped", address(w));
    }

    /// Ruling B: the `PayMeta` body's per-byte cost on the pay entries.
    function test_sdkGas_token_body() public {
        _bodyRows("token", "mtxPay", "normal", address(tok), _pay);
        _bodyRows("token", "mtxPay", "wrapped", address(wrp), _pay);
        _bodyRows("token", "mtxPayWithPayeeFee", "normal", address(tok), _payeeFee);
        _bodyRows("token", "mtxPayWithPayeeFee", "wrapped", address(wrp), _payeeFee);
    }
}

/// The same rows on the regulated variants (owner 2026-11-19, ruling A: they count toward the worst case): kinds 8 and 9
/// with every control the fixture enables, the registry check (`KYC`, every party attested) and `TAX` at 10 %, where
/// `mtxPayWithTax` lives; the UA a `…ToUA` entry credits a P-256 UA registered on the fixture's registry (G4: a real one).
contract SdkGasRegulatedTest is SdkGasRegFix {
    address internal constant SG_TAX_TO = address(0x7A0);
    uint256 internal constant SG_TO_SK = 0xC0FFEE;
    address internal t8k;
    address internal t9k;

    function _cfg(IFactoryToken.TokenConfig memory c) internal view returns (IFactoryToken.TokenConfig memory) {
        c.features |= (1 << GovernanceBits.KYC) | (1 << GovernanceBits.TAX);
        (c.reg.complianceRegistry, c.reg.requiredFlags, c.reg.taxRecipient) = (address(creg), KYC, nid(SG_TAX_TO));
        return c;
    }

    function _reg(bool wrapped, IFactoryToken.TokenConfig memory c, bytes32 salt) internal returns (address t) {
        IOpenFactory.TokenKind k =
            wrapped ? IOpenFactory.TokenKind.WRAPPED_REGULATED : IOpenFactory.TokenKind.NORMAL_REGULATED;
        t = f.createToken(k, 1, abi.encode(_cfg(c)), salt);
        vm.prank(issuer);
        IRegulatedToken(t).setTaxRate(100_000, EnvKit.codeUidOf(t));
    }

    function setUp() public override {
        super.setUp();
        sgPk = ALICE_PK;
        address[6] memory parties = [alice, SG_PAYEE, vm.addr(SG_PAYEE_PK), SG_FEE_TO, SG_TAX_TO, SG_RELAYER];
        for (uint256 i; i < parties.length; ++i) {
            _attest(nid(parties[i]), KYC, type(uint64).max);
        }
        (bytes32 to,) = _sgRegisterOn(address(ureg), UAKinds.P256, SG_TO_SK); // the UA a `…ToUA` entry credits (G4)
        _attest(to, KYC, type(uint64).max);
        t8k = _reg(false, _cfg8(), "sg8");
        t9k = _reg(true, _cfg9(), "sg9");
        _wrapFor(t9k, alice, SUPPLY);
        (sgLeg, sgUaTo) = (address(usd), to);
    }

    function test_sdkGas_tokenRegulated() public {
        _commonRows("token", "normal_reg", t8k);
        _commonRows("token", "wrapped_reg", t9k);
        _both("token", "mtxBurn", "normal_reg", t8k, _sgFrom(), _burn);
        _both("token", "mtxPayWithTax", "normal_reg", t8k, _sgFrom(), _payWithTax);
        _both("token", "mtxPayWithTax", "wrapped_reg", t9k, _sgFrom(), _payWithTax);
        // a wrapper of a ledger leg for `mtxUnwrapToUA`, the signer holding its units (a factory `NORMAL` token: a leg with
        // `FORCE` or `MODERATE`, as the regulated kinds have, is refused)
        IFactoryToken.TokenConfig memory n;
        (n.name, n.symbol, n.features, n.admin, n.grantDelay) =
        ("Leg", "LEG", 1 << GovernanceBits.PAYABLE, nid(ownerA), GD);
        (n.initialSupply, n.initialHolder) = (SUPPLY, address(this));
        sgLedgerLeg = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(n), "sgleg");
        IFactoryToken.TokenConfig memory c = _cfg9();
        c.legs[0] = IFactoryToken.Leg(sgLedgerLeg, 1, 1);
        address t9l = _reg(true, c, "sg9l");
        _attest(nid(address(this)), KYC, type(uint64).max);
        WrappedToken(payable(sgLedgerLeg)).approve(t9l, 1_000); // a SCaaS token's allowance: a contract's only
        WrappedToken(payable(t9l)).wrap(1_000);
        WrappedToken(payable(t9l)).transfer(alice, 1_000);
        _unwrapRows("token", "wrapped_reg", t9k, t9l);
        // the wrap-in entries on a wrapper the signer holds nothing of
        address t9w = _reg(true, _cfg9(), "sg9w");
        usd.mint(alice, 1_000);
        vm.prank(alice);
        usd.approve(t9w, 1_000);
        _wrapInRows("token", "wrapped_reg", t9w);
    }

    function test_sdkGas_tokenRegulated_body() public {
        _bodyRows("token", "mtxPay", "normal_reg", t8k, _pay);
        _bodyRows("token", "mtxPay", "wrapped_reg", t9k, _pay);
        _bodyRows("token", "mtxPayWithPayeeFee", "normal_reg", t8k, _payeeFee);
        _bodyRows("token", "mtxPayWithPayeeFee", "wrapped_reg", t9k, _payeeFee);
        _bodyRows("token", "mtxPayWithTax", "normal_reg", t8k, _payWithTax);
        _bodyRows("token", "mtxPayWithTax", "wrapped_reg", t9k, _payWithTax);
    }
}
