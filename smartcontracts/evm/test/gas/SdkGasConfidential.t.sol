// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {SdkGasZetherFix, SdkGasPqzFix} from "./SdkGasFixtures.sol";
import {SdkGasOps} from "./SdkGasOps.sol";

/// The `zether` and `pqz` domain kinds' base rows (owner 2026-11-19: the token kinds' entry set; ruling A: the regulated
/// variants count): each entry on the kind's Normal, Wrapped and regulated Normal / Wrapped tokens, public balances, the
/// reference signer a native key. A regulated token has the registry check (`KYC` with the deny mask, every party read
/// there, none denied) and `TAX` at 10 %.
abstract contract SdkGasKindBase is SdkGasOps {
    address internal constant SG_TAX_TO = address(0x7A0);
    uint64 internal constant SG_KYC = 1;
    uint64 internal constant SG_DENIED = 1 << 16;
    MockERC20 internal sgUnd;

    function _sgKind() internal pure virtual returns (string memory);
    /// The kind's config: the fixture's regulated one when `reg`, else its plain one; this contract the minter of a Normal.
    function _sgCfg(bool reg) internal view virtual returns (IFactoryToken.TokenConfig memory);
    function _sgKindOf(bool wrapped, bool reg) internal pure virtual returns (IOpenFactory.TokenKind);
    function _sgFactory() internal view virtual returns (IOpenFactory);
    function _sgReg() internal view virtual returns (ComplianceRegistry creg, address attester, address issuer);

    function _sgCreate(bool wrapped, bool reg, address leg, bytes32 salt) internal returns (address t) {
        IFactoryToken.TokenConfig memory c = _sgCfg(reg);
        if (wrapped) {
            c.features = (1 << GovernanceBits.PAYABLE) | (reg ? c.features & ~uint256(0x1F) : 0);
            (c.lockedFeatures, c.roles.minter) = (0, 0);
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(leg, 1, 1);
        }
        (ComplianceRegistry creg,, address issuer) = _sgReg();
        if (reg) {
            c.features |= (1 << GovernanceBits.KYC) | (1 << GovernanceBits.TAX);
            // kinds 10-13 take no required mask (a shielded receiver cannot be checked): the deny mask
            (c.reg.complianceRegistry, c.reg.requiredFlags, c.reg.deniedFlags) = (address(creg), 0, SG_DENIED);
            c.reg.taxRecipient = nid(SG_TAX_TO);
        }
        t = _sgFactory().createToken(_sgKindOf(wrapped, reg), 1, abi.encode(c), salt);
        if (reg) {
            vm.prank(issuer);
            IRegulatedToken(t).setTaxRate(100_000, EnvKit.codeUidOf(t));
        }
    }

    function _sgAttest(bytes32 a) internal {
        (ComplianceRegistry creg, address attester,) = _sgReg();
        bytes32[] memory as_ = new bytes32[](1);
        uint64[] memory fl = new uint64[](1);
        uint64[] memory vu = new uint64[](1);
        (as_[0], fl[0], vu[0]) = (a, SG_KYC, type(uint64).max);
        vm.prank(attester);
        creg.setCompliance(as_, fl, vu, EnvKit.regUidOf(address(creg)));
    }

    /// Every row of one variant pair (`reg`: the regulated Normal and Wrapped).
    function _sgRows(bool reg) internal {
        string memory k = _sgKind();
        (string memory vn, string memory vw) = reg ? ("normal_reg", "wrapped_reg") : ("normal", "wrapped");
        address alice_ = vm.addr(sgPk);
        if (reg) {
            address[7] memory parties =
                [alice_, SG_PAYEE, vm.addr(SG_PAYEE_PK), SG_FEE_TO, SG_TAX_TO, SG_RELAYER, address(this)];
            for (uint256 i; i < parties.length; ++i) {
                _sgAttest(nid(parties[i]));
            }
            _sgAttest(sgUaTo);
        }
        address tn = _sgCreate(false, reg, address(0), reg ? bytes32("sgnr") : bytes32("sgn"));
        NormalToken(tn).mint(alice_, 1_000_000, EnvKit.codeUidOf(tn));
        _commonRows(k, vn, tn);
        _both(k, "mtxBurn", vn, tn, _sgFrom(), _burn);
        sgUnd = new MockERC20("Und", "UND", 6);
        sgLeg = address(sgUnd);
        address tw = _sgCreate(true, reg, sgLeg, reg ? bytes32("sgwr") : bytes32("sgw"));
        _sgFund(tw, alice_, 1_000_000);
        _commonRows(k, vw, tw);
        if (reg) {
            _both(k, "mtxPayWithTax", vn, tn, _sgFrom(), _payWithTax);
            _both(k, "mtxPayWithTax", vw, tw, _sgFrom(), _payWithTax);
        }
        // `mtxUnwrapToUA`: a wrapper of a plain Normal of the kind (a ledger leg), the signer holding its units
        sgLedgerLeg = _sgCreate(false, false, address(0), reg ? bytes32("sglr") : bytes32("sgl"));
        address tl = _sgCreate(true, reg, sgLedgerLeg, reg ? bytes32("sgwlr") : bytes32("sgwl"));
        NormalToken(sgLedgerLeg).mint(address(this), 1_000, EnvKit.codeUidOf(sgLedgerLeg));
        NormalToken(sgLedgerLeg).approve(tl, 1_000); // a SCaaS token's allowance: a contract's only
        WrappedToken(payable(tl)).wrap(sgLedgerLeg, 1_000);
        WrappedToken(payable(tl)).transfer(alice_, 1_000);
        _unwrapRows(k, vw, tw, tl);
        // the wrap-in entries on a wrapper the signer holds nothing of
        address t2 = _sgCreate(true, reg, sgLeg, reg ? bytes32("sgw2r") : bytes32("sgw2"));
        sgUnd.mint(alice_, 1_000);
        vm.prank(alice_);
        sgUnd.approve(t2, 1_000);
        _wrapInRows(k, vw, t2);
    }

    /// Ruling B on the kind's pay entries.
    function _sgBody(bool reg) internal {
        string memory k = _sgKind();
        (string memory vn, string memory vw) = reg ? ("normal_reg", "wrapped_reg") : ("normal", "wrapped");
        address alice_ = vm.addr(sgPk);
        if (reg) {
            address[5] memory parties = [alice_, SG_PAYEE, vm.addr(SG_PAYEE_PK), SG_FEE_TO, SG_TAX_TO];
            for (uint256 i; i < parties.length; ++i) {
                _sgAttest(nid(parties[i]));
            }
        }
        address tn = _sgCreate(false, reg, address(0), "sgbn");
        NormalToken(tn).mint(alice_, 1_000_000, EnvKit.codeUidOf(tn));
        sgUnd = new MockERC20("Und", "UND", 6);
        address tw = _sgCreate(true, reg, address(sgUnd), "sgbw");
        _sgFund(tw, alice_, 1_000_000);
        _bodyRows(k, "mtxPay", vn, tn, _pay);
        _bodyRows(k, "mtxPay", vw, tw, _pay);
        _bodyRows(k, "mtxPayWithPayeeFee", vn, tn, _payeeFee);
        _bodyRows(k, "mtxPayWithPayeeFee", vw, tw, _payeeFee);
        if (reg) {
            _bodyRows(k, "mtxPayWithTax", vn, tn, _payWithTax);
            _bodyRows(k, "mtxPayWithTax", vw, tw, _payWithTax);
        }
    }

    /// `amount` units of the wrapper `t` of `sgUnd` to `to`, wrapped by this contract.
    function _sgFund(address t, address to, uint256 amount) internal {
        sgUnd.mint(address(this), amount);
        sgUnd.approve(t, amount);
        WrappedToken(payable(t)).wrap(address(sgUnd), amount);
        WrappedToken(payable(t)).transfer(to, amount);
    }
}

/// The base rows' runs of a kind (`inputs.json` `runs`).
abstract contract SdkGasKind is SdkGasKindBase {
    function test_sdkGas_kind() public {
        _sgRows(false);
    }

    function test_sdkGas_kindRegulated() public {
        _sgRows(true);
    }

    function test_sdkGas_kind_body() public {
        _sgBody(false);
    }

    function test_sdkGas_kindRegulated_body() public {
        _sgBody(true);
    }
}

/// The `zether` kind's fixture: `ZetherRegFixture` with the `WRAPPED_ZETHER` release.
abstract contract SdkGasZetherBase is SdkGasKindBase, SdkGasZetherFix {
    function _isWrapped() internal pure override returns (bool) {
        return false;
    }

    function setUp() public virtual override {
        super.setUp();
        Catalogue.release(
            factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode
        );
        (sgPk, sgUaTo) = (0xA11CE5EED, ZetherTypes.UA.unwrap(bob.ua));
    }

    function _sgKind() internal pure override returns (string memory) {
        return "zether";
    }

    function _sgCfg(bool reg) internal view override returns (IFactoryToken.TokenConfig memory) {
        return reg ? _regCfg(false, uint256(1) << 40) : _cfg(false, uint256(1) << 40);
    }

    function _sgKindOf(bool wrapped, bool reg) internal pure override returns (IOpenFactory.TokenKind) {
        if (reg) {
            return
                wrapped
                    ? IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED
                    : IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED;
        }
        return wrapped ? IOpenFactory.TokenKind.WRAPPED_ZETHER : IOpenFactory.TokenKind.NORMAL_ZETHER;
    }

    function _sgFactory() internal view override returns (IOpenFactory) {
        return IOpenFactory(address(factory));
    }

    function _sgReg() internal view override returns (ComplianceRegistry, address, address) {
        return (creg, attester, issuer);
    }
}

contract SdkGasZetherTest is SdkGasKind, SdkGasZetherBase {}

/// The `pqz` kind's fixture: `PqzRegFixture` with the `WRAPPED_PQZ` release.
abstract contract SdkGasPqzBase is SdkGasKindBase, SdkGasPqzFix {
    function _isWrapped() internal pure override returns (bool) {
        return false;
    }

    function setUp() public virtual override {
        super.setUp();
        _releaseWrapped();
        (sgPk, sgUaTo) = (0xA11CE5EED, more[2]);
    }

    function _sgKind() internal pure override returns (string memory) {
        return "pqz";
    }

    function _sgCfg(bool reg) internal view override returns (IFactoryToken.TokenConfig memory) {
        return reg ? _regCfg() : _cfg(uint256(1) << 40);
    }

    function _sgKindOf(bool wrapped, bool reg) internal pure override returns (IOpenFactory.TokenKind) {
        if (reg) {
            return wrapped ? IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED : IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED;
        }
        return wrapped ? IOpenFactory.TokenKind.WRAPPED_PQZ : IOpenFactory.TokenKind.NORMAL_PQZ;
    }

    function _sgFactory() internal view override returns (IOpenFactory) {
        return IOpenFactory(address(factory));
    }

    function _sgReg() internal view override returns (ComplianceRegistry, address, address) {
        return (creg, attester, issuer);
    }
}

contract SdkGasPqzTest is SdkGasKind, SdkGasPqzBase {}
