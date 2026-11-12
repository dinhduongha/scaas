// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IRescuable} from "../../src/governance/IRescuable.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {plainEnv, pinned, withModules} from "../helpers/Catalogue.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {NormalTokenP, NormalTokenT, NormalTokenA} from "../../src/metatx/NormalTokenModules.sol";
import {probeModules} from "../helpers/ProbeModules.sol";

/// @notice What lands now for the regulated round (spec §1.2, §4.2; CTR-GOV-03, -17, -18; GD-19): bits 5-9 refused on every
///         plain kind, `FeatureInvalidForKind` on all six (ua-mtx-merge T24, regulated-kinds spec Q3: `NORMAL` and `WRAPPED`
///         refused them `FeatureNotBuilt` before), and none of them in `validBits()`, so a wallet reads the truth.
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

    /// GD-3: `maxSupply` is another kind's field on a `NORMAL*` kind (`ConfigFieldForOtherKind(5)`) and, without `MINTABLE`, no
    /// hybrid on a `WRAPPED*` one (`MaxSupplyInvalid`, spec §5.2); `rescueTo` without `RESCUABLE` is refused on both (spec §6.2).
    function _configFailsClosed(bool wrapped) internal {
        IFactoryToken.TokenConfig memory c = _rCfg(wrapped, 1);
        c.maxSupply = 1;
        vm.expectRevert(wrapped ? abi.encodeWithSelector(IWrappedToken.MaxSupplyInvalid.selector)
            : abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, uint8(5)));
        _rCreate(wrapped, c, "c");
        c.maxSupply = 0;
        c.rescueTo = address(0xBEEF);
        vm.expectRevert(IRescuable.RescueConfigInvalid.selector);
        _rCreate(wrapped, c, "c");
        c.rescueTo = address(0); // positive control
        _rCreate(wrapped, c, "c");
    }

    /// pay-meta-tax T39 (spec §5.1, O8): bit 23 `TAX` is valid on 8-13 only; each plain kind refuses it at creation.
    function test_taxBit_plainKindRefuses() public {
        for (uint256 w; w < 2; ++w) {
            IFactoryToken.TokenConfig memory c = _rCfg(w == 1, 1 | (1 << 23));
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(23)));
            _rCreate(w == 1, c, "tax");
            assertEq(IGovernance(_rCreate(w == 1, _rCfg(w == 1, 1), "ok23")).validBits() & (1 << 23), 0, "validBits");
        }
    }

    function _noRegulatedValid(bool wrapped) internal {
        address t = _rCreate(wrapped, _rCfg(wrapped, 1), "v");
        uint256 v = IGovernance(t).validBits();
        assertEq(v & REGULATED, 0, "validBits() holds a bit of 5-9");
        assertEq(v & 1, 1, "control: PAYABLE is valid");
    }
}

/// The shape of what a regulated release decodes beside `IFactoryToken.TokenConfig` (spec §4.2, §4.4). Test only: nothing of it lands now.
struct MockRegulatedParams {
    address complianceRegistry;
    uint256 requiredFlags;
    uint256 deniedFlags;
}

/// A mock implementation of kind 8 `NORMAL_REGULATED`: its own encoding, `abi.encode(IFactoryToken.TokenConfig, MockRegulatedParams)`, read
/// in its own `_initRaw`. The factory passes `initArgs` opaque, so nothing in it changes.
contract MockNormalRegulated is NormalToken {
    MockRegulatedParams public params;

    constructor(address f_, bytes memory a) NormalToken(f_, a) {}

    function kind() public pure override returns (uint8) { return 8; }

    function _initRaw(bytes calldata initArgs) internal override {
        (IFactoryToken.TokenConfig memory cfg, MockRegulatedParams memory p) = abi.decode(initArgs, (IFactoryToken.TokenConfig, MockRegulatedParams));
        params = p;
        _init(cfg);
    }
}

/// `MockNormalRegulated`'s overrides in its kind's module P (T66b: the bodies run there; `probeArgs`, test/helpers/ProbeModules.sol).
contract MockNormalRegulatedP is NormalTokenP {
    constructor(address f_, bytes memory a) NormalTokenP(f_, a) {}

    MockRegulatedParams public params;

    function _initRaw(bytes calldata initArgs) internal override {
        (IFactoryToken.TokenConfig memory cfg, MockRegulatedParams memory p) = abi.decode(initArgs, (IFactoryToken.TokenConfig, MockRegulatedParams));
        params = p;
        _init(cfg);
    }
}

/// `MockNormalRegulated`'s overrides in its kind's module T (T66b: the bodies run there; `probeArgs`, test/helpers/ProbeModules.sol).
contract MockNormalRegulatedT is NormalTokenT {
    constructor(address f_, bytes memory a) NormalTokenT(f_, a) {}

    MockRegulatedParams public params;

    function _initRaw(bytes calldata initArgs) internal override {
        (IFactoryToken.TokenConfig memory cfg, MockRegulatedParams memory p) = abi.decode(initArgs, (IFactoryToken.TokenConfig, MockRegulatedParams));
        params = p;
        _init(cfg);
    }
}

/// `MockNormalRegulated`'s overrides in its kind's module A (T66b: the bodies run there; `probeArgs`, test/helpers/ProbeModules.sol).
contract MockNormalRegulatedA is NormalTokenA {
    constructor(address f_, bytes memory a) NormalTokenA(f_, a) {}

    MockRegulatedParams public params;

    function _initRaw(bytes calldata initArgs) internal override {
        (IFactoryToken.TokenConfig memory cfg, MockRegulatedParams memory p) = abi.decode(initArgs, (IFactoryToken.TokenConfig, MockRegulatedParams));
        params = p;
        _init(cfg);
    }
}

/// `NORMAL` and `WRAPPED` on one factory.
contract GovRegulatedBitsTest is GovRegulatedRows {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    address constant OWNER = address(0x0A);
    OpenFactory f;

    function setUp() public {
        f = EnvKit.factory(address(this), UID, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), false);
    }

    function _rCfg(bool wrapped, uint256 features) internal override returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.features, c.admin) = ("R", "R", 18, features, nid(OWNER));
        if (wrapped) {
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
        }
    }

    function _rCreate(bool wrapped, IFactoryToken.TokenConfig memory c, bytes32 salt) internal override returns (address) {
        return f.createToken(wrapped ? IOpenFactory.TokenKind.WRAPPED : IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), salt);
    }

    /// ua-mtx-merge T24 (Q3): was `test_regulatedBitsRefusedOnPlainKinds`, expecting `FeatureNotBuilt`.
    function test_plainKindsRefuseRegulatedAsInvalid() public {
        _refusesEach(false, IGovernance.FeatureInvalidForKind.selector);
        _refusesEach(true, IGovernance.FeatureInvalidForKind.selector);
    }

    /// CTR-GOV-20 (owner 2026-11-05): bit 22 `OPERATOR_TRANSFER` is on the regulated kinds only; each plain kind refuses it.
    function test_plainKindsRefuseOperatorTransfer() public {
        for (uint256 w; w < 2; ++w) {
            IFactoryToken.TokenConfig memory c = _rCfg(w == 1, 1 | (1 << 22));
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(22)));
            _rCreate(w == 1, c, "op");
            _rCreate(w == 1, _rCfg(w == 1, 1), "ok"); // positive control
        }
    }

    function test_validBitsHoldsNoRegulatedBit() public {
        _noRegulatedValid(false);
        _noRegulatedValid(true);
    }

    /// `Roles.compliance` maps bit 10 `RECORD` (spec §1.2): bits 8 and 9 have no holder. `Roles.issuer` stays bit 5.
    function test_complianceWordIsBitTen() public {
        for (uint256 w; w < 2; ++w) {
            IFactoryToken.TokenConfig memory c = _rCfg(w == 1, 1);
            c.roles.compliance = nid(address(0xC0));
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(10)));
            _rCreate(w == 1, c, "c");
            c.roles.compliance = 0;
            c.roles.issuer = nid(address(0x15));
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(5)));
            _rCreate(w == 1, c, "i");
        }
    }

    /// CTR-GOV-16, spec §4.2: a regulated kind publishes, enables and creates on the same factory with no factory change; its
    /// token is registered and `KIND_SCAAS` to the DEX.
    function test_regulatedKindPublishesOnTheSameFactory() public {
        IOpenFactory.TokenKind k8 = IOpenFactory.TokenKind.NORMAL_REGULATED;
        bytes memory args = abi.encode(_rCfg(false, 1), MockRegulatedParams(address(0xC0), 3, 4));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, k8, 1));
        f.createToken(k8, 1, args, "r");
        // T66b: the stand-in's bodies run in kind 0's modules (the face checks them against kind 0), its hook there too
        (address[] memory ms, bytes memory implArgs) = probeModules("GovRegulatedBits.t.sol:MockNormalRegulated", 0, address(f), "");
        uint16 ev = Catalogue.env(f, k8, withModules(pinned(plainEnv(address(f), address(0), UID, address(0), false), k8), ms));
        vm.prank(address(uint160(uint256(f.admin()))));
        f.deployTokenImplementation(k8, 1, ev, type(MockNormalRegulated).creationCode, implArgs);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindDisabled.selector, k8));
        f.createToken(k8, 1, args, "r");
        f.setTokenKindEnabled(k8, true, EnvKit.uidOf(address(f)));
        address t = f.createToken(k8, 1, args, "r");
        assertTrue(f.isRegisteredToken(t));
        assertEq(NormalToken(t).kind(), 8);
        (address reg, uint256 req, uint256 den) = MockNormalRegulated(t).params();
        assertEq(reg, address(0xC0));
        assertEq(req, 3);
        assertEq(den, 4);
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, address(0), 0, 0)), "d"));
        address n = _rCreate(false, _rCfg(false, 1), "n");
        vm.prank(OWNER);
        d.setMarket(t, n, true);
        assertEq(d.tokenKind(t), 1, "KIND_SCAAS");
        assertEq(d.tokenKind(n), 1, "control: a NORMAL token");
    }

    /// The masks are the kind's (spec §1.2): bit 3 is no role on a `NORMAL*` kind, a role without its feature on `WRAPPED*`.
    function test_normalKindHasNoRateRole() public {
        address holder = address(new MockERC20("H", "H", 6)); // has code: bit 3 is contract-only on a wrapped kind
        NormalToken n = NormalToken(_rCreate(false, _rCfg(false, 1), "n"));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, uint8(3)));
        n.grantRole(3, nid(holder));
        WrappedToken w = WrappedToken(payable(_rCreate(true, _rCfg(true, 1), "w")));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(3)));
        w.grantRole(3, nid(holder));
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
        c.lockedFeatures = 0; // the fixture locks MINTABLE for its minter (B-06); this token has neither
        c.roles.minter = 0;
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

    function test_configFieldsFailClosedUntilBuilt() public {
        _configFailsClosed(false);
        _configFailsClosed(true);
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
        c.lockedFeatures = 0; // the fixture locks MINTABLE for its minter (B-06); this token has neither
        c.roles.minter = 0;
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

    function test_configFieldsFailClosedUntilBuilt() public {
        _configFailsClosed(false);
        _configFailsClosed(true);
    }
}
