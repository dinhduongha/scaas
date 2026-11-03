// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";

/// @notice What lands now for the regulated round (spec §1.2, §4.2; CTR-GOV-03, -17, -18; GD-19): bits 5-9 refused on every
///         kind of this release, with each kind's error (`FeatureNotBuilt` on `NORMAL` and `WRAPPED`, `FeatureInvalidForKind`
///         on the four confidential kinds), and none of them in `validBits()`, so a wallet reads the truth.
abstract contract GovRegulatedRows is Test {
    uint256 internal constant REGULATED = (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9);

    /// A config of the kind under test with `features` (PAYABLE plus whatever the caller adds).
    function _rCfg(bool wrapped, uint256 features) internal virtual returns (IFactoryToken.TokenConfig memory);

    function _rCreate(bool wrapped, IFactoryToken.TokenConfig memory c, bytes32 salt) internal virtual returns (address);

    /// Each of 5-9 alone, then all five together (the lowest named), each refused with `err`; PAYABLE alone creates.
    function _refusesEach(bool wrapped, bytes4 err) internal {
        _rCreate(wrapped, _rCfg(wrapped, 1), "ok"); // control
        IFactoryToken.TokenConfig memory c;
        for (uint8 b = 5; b <= 9; ++b) {
            c = _rCfg(wrapped, 1 | (uint256(1) << b)); // before the expectation: a wrapped config deploys its leg
            vm.expectRevert(abi.encodeWithSelector(err, b));
            _rCreate(wrapped, c, bytes32(uint256(b)));
        }
        c = _rCfg(wrapped, 1 | REGULATED);
        vm.expectRevert(abi.encodeWithSelector(err, uint8(5)));
        _rCreate(wrapped, c, "all");
    }

    function _noRegulatedValid(bool wrapped) internal {
        address t = _rCreate(wrapped, _rCfg(wrapped, 1), "v");
        uint256 v = IGovernance(t).validBits();
        assertEq(v & REGULATED, 0, "validBits() holds a bit of 5-9");
        assertEq(v & 1, 1, "control: PAYABLE is valid");
    }
}

/// `NORMAL` and `WRAPPED` on one factory.
contract GovRegulatedBitsTest is GovRegulatedRows {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    address constant OWNER = address(0x0A);
    OpenFactory f;

    function setUp() public {
        f = new OpenFactory(address(this), UID, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), false);
    }

    function _rCfg(bool wrapped, uint256 features) internal override returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.features, c.owner) = ("R", "R", 18, features, OWNER);
        if (wrapped) {
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
        }
    }

    function _rCreate(bool wrapped, IFactoryToken.TokenConfig memory c, bytes32 salt) internal override returns (address) {
        return f.createToken(wrapped ? IOpenFactory.TokenKind.WRAPPED : IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), salt);
    }

    function test_regulatedBitsRefusedOnPlainKinds() public {
        _refusesEach(false, IGovernance.FeatureNotBuilt.selector);
        _refusesEach(true, IGovernance.FeatureNotBuilt.selector);
    }

    function test_validBitsHoldsNoRegulatedBit() public {
        _noRegulatedValid(false);
        _noRegulatedValid(true);
    }

    /// `Roles.compliance` maps bit 10 `RECORD` (spec §1.2): bits 8 and 9 have no holder. `Roles.issuer` stays bit 5.
    function test_complianceWordIsBitTen() public {
        for (uint256 w; w < 2; ++w) {
            IFactoryToken.TokenConfig memory c = _rCfg(w == 1, 1);
            c.roles.compliance = address(0xC0);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(10)));
            _rCreate(w == 1, c, "c");
            c.roles.compliance = address(0);
            c.roles.issuer = address(0x15);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(5)));
            _rCreate(w == 1, c, "i");
        }
    }

    /// The masks are the kind's (spec §1.2): bit 3 is no role on a `NORMAL*` kind, a role without its feature on `WRAPPED*`.
    function test_normalKindHasNoRateRole() public {
        address holder = address(new MockERC20("H", "H", 6)); // has code: bit 3 is contract-only on a wrapped kind
        NormalToken n = NormalToken(_rCreate(false, _rCfg(false, 1), "n"));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, uint8(3)));
        n.grantRole(3, holder);
        WrappedToken w = WrappedToken(payable(_rCreate(true, _rCfg(true, 1), "w")));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(3)));
        w.grantRole(3, holder);
    }
}

/// `NORMAL_ZETHER` and `WRAPPED_ZETHER`.
contract GovRegulatedBitsZetherTest is GovRegulatedRows, ZetherFixture {
    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
    }

    function _rCfg(bool wrapped, uint256 features) internal override returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(false, uint256(1) << 40);
        c.features = features;
        c.roles.minter = address(0);
        if (wrapped) {
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
        }
    }

    function _rCreate(bool wrapped, IFactoryToken.TokenConfig memory c, bytes32 s) internal override returns (address) {
        IOpenFactory.TokenKind k = wrapped ? IOpenFactory.TokenKind.WRAPPED_ZETHER : IOpenFactory.TokenKind.NORMAL_ZETHER;
        return factory.createToken(k, 1, abi.encode(c), s);
    }

    function test_regulatedBitsInvalidOnConfidentialKinds() public {
        _refusesEach(false, IGovernance.FeatureInvalidForKind.selector);
        _refusesEach(true, IGovernance.FeatureInvalidForKind.selector);
    }

    function test_validBitsHoldsNoRegulatedBit() public {
        _noRegulatedValid(false);
        _noRegulatedValid(true);
    }
}

/// `NORMAL_PQZ` and `WRAPPED_PQZ`.
contract GovRegulatedBitsPqzTest is GovRegulatedRows, PqzFixture {
    function setUp() public {
        _stack();
        _releaseWrapped();
    }

    function _rCfg(bool wrapped, uint256 features) internal override returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(uint256(1) << 40);
        c.features = features;
        c.roles.minter = address(0);
        if (wrapped) {
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
        }
    }

    function _rCreate(bool wrapped, IFactoryToken.TokenConfig memory c, bytes32 s) internal override returns (address) {
        IOpenFactory.TokenKind k = wrapped ? IOpenFactory.TokenKind.WRAPPED_PQZ : IOpenFactory.TokenKind.NORMAL_PQZ;
        return factory.createToken(k, 1, abi.encode(c), s);
    }

    function test_regulatedBitsInvalidOnConfidentialKinds() public {
        _refusesEach(false, IGovernance.FeatureInvalidForKind.selector);
        _refusesEach(true, IGovernance.FeatureInvalidForKind.selector);
    }

    function test_validBitsHoldsNoRegulatedBit() public {
        _noRegulatedValid(false);
        _noRegulatedValid(true);
    }
}
