// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {UnderlyingLib} from "../../src/metatx/UnderlyingLib.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UID_, noneInit} from "./helpers/V2Fixture.sol";
import {plainEnv, Catalogue} from "../helpers/Catalogue.sol";

/// Kind 2 stand-in: the public `NONE` kind under the confidential id and domain name, accepting `conf` (the factory's
/// side only; the Zether layer, its verifiers and its chain gate are tested in `test/zether`).
contract MockNoneZether is NoUnderlyingToken {
    constructor(uint16 v, Env memory env, bytes memory a) NoUnderlyingToken(v, env, a) {}

    function kind() public pure override returns (uint8) { return AdminLib.KIND_NONE_ZETHER; }

    function _domainName() internal pure override returns (string memory) { return "SCaaS ZetherToken"; }

    function _init(TokenConfig memory cfg) internal override {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        AdminLib.init(AdminLib.KIND_NONE_ZETHER, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
    }
}

/// Kind 3 stand-in: the public `UNDERLYING` kind under the confidential id, its flags validated for kind 3.
contract MockUnderlyingZether is UnderlyingToken {
    constructor(uint16 v, Env memory env, bytes memory a) UnderlyingToken(v, env, a) {}

    function kind() public pure override returns (uint8) { return AdminLib.KIND_UNDERLYING_ZETHER; }

    function _init(TokenConfig memory cfg) internal override {
        _requireUnused(cfg, true, false, false, false);
        UnderlyingLib.initToken(cfg, IS_HEDERA, AdminLib.KIND_UNDERLYING_ZETHER);
    }
}

/// The confidential kinds behind the factory's generic gate (plan 5g-Z2, CTR-TOK-03): off by default, registrar only;
/// the chain and verifier gates are the implementation's (`test/zether`, `test/pqz`); the `conf` fields are the
/// confidential kinds' only (CTR-TOK-25); the domain name hook.
contract FactoryZetherTest is Test {
    OpenFactory f;
    address registrar = address(0xF00D);
    MockNoneZether noneZ;
    MockUnderlyingZether undZ;
    MockERC20 usd = new MockERC20("USD", "USD", 6);

    IOpenFactory.TokenKind constant NZ = IOpenFactory.TokenKind.NONE_ZETHER;
    IOpenFactory.TokenKind constant UZ = IOpenFactory.TokenKind.UNDERLYING_ZETHER;

    function setUp() public {
        f = new OpenFactory(registrar, UID_, 0);
        noneZ = MockNoneZether(Catalogue.plain(f, NZ, 1, type(MockNoneZether).creationCode, address(0), address(0), false));
        undZ = MockUnderlyingZether(Catalogue.plain(f, UZ, 1, type(MockUnderlyingZether).creationCode, address(0),
            address(0), false));
    }

    function _conf() internal pure returns (IFactoryToken.TokenConfig memory c) {
        c = noneInit("Zether", "Z", 6, 0, address(0), address(0));
        c.conf.shieldScale = 1;
    }

    function _underlying() internal view returns (IFactoryToken.TokenConfig memory c) {
        c.name = "Zether wrapped";
        c.symbol = "ZW";
        c.decimals = 6;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
    }

    function _enable() internal {
        vm.startPrank(registrar);
        f.setKindEnabled(NZ, true);
        f.setKindEnabled(UZ, true);
        vm.stopPrank();
    }

    function test_confidentialKinds_offByDefault_registrarOnly() public {
        assertFalse(f.kindEnabled(NZ));
        assertFalse(f.kindEnabled(UZ));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindDisabled.selector, NZ));
        f.createToken(NZ, 1, abi.encode(_conf()), "a");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindDisabled.selector, UZ));
        f.createToken(UZ, 1, abi.encode(_underlying()), "a");
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.setKindEnabled(NZ, true);
        vm.recordLogs();
        _enable();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2);
        assertEq(logs[0].topics[0], IOpenFactory.KindEnabled.selector);
        assertEq(abi.decode(logs[0].data, (bool)), true);
        address t = f.createToken(NZ, 1, abi.encode(_conf()), "on");
        assertTrue(f.isRegisteredToken(t));
        address w = f.createToken(UZ, 1, abi.encode(_underlying()), "on");
        assertEq(f.getWrapper(address(this), address(usd)), w, "the index reads underlyings() after initialize");
        vm.prank(registrar);
        f.setKindEnabled(NZ, false);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindDisabled.selector, NZ));
        f.createToken(NZ, 1, abi.encode(_conf()), "off again");
    }

    /// The flags of kind 3 are validated for kind 3: the regulated flags are invalid there (CTR-ZTH-47), not "not built".
    function test_underlyingZether_flagsValidatedForItsKind() public {
        _enable();
        IFactoryToken.TokenConfig memory c = _underlying();
        c.features = 1 << AdminLib.FREEZE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.FREEZE));
        f.createToken(UZ, 1, abi.encode(c), "a");
        c.features = 1 << AdminLib.MINTABLE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.MINTABLE));
        f.createToken(UZ, 1, abi.encode(c), "a");
    }

    /// A public kind refuses every `conf` field, the two modes included.
    function test_publicKinds_refuseEveryConfField() public {
        OpenFactory g = new OpenFactory(registrar, UID_, 0);
        Catalogue.plain(g, IOpenFactory.TokenKind.NONE, 1, type(NoUnderlyingToken).creationCode, address(0), address(0),
            false);
        IFactoryToken.TokenConfig memory c = noneInit("P", "P", 0, 0, address(0), address(0));
        c.conf.maxShielded = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, abi.encode(c), "a");
        c.conf.maxShielded = 0;
        c.conf.confidentialFee = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, abi.encode(c), "a");
        c.conf.confidentialFee = 0;
        c.conf.auditorKey = hex"01";
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, abi.encode(c), "a");
        c.conf.auditorKey = "";
        c.conf.disclosureMode = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, abi.encode(c), "a");
        c.conf.disclosureMode = 0;
        c.conf.auditorMode = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, abi.encode(c), "a");
    }

    /// CTR-MTX-02: the confidential kinds sign under "SCaaS ZetherToken", the public ones under "SCaaS MetaToken".
    function test_domainNameHook() public view {
        (, string memory n,,,, bytes32 salt,) = noneZ.eip712Domain();
        assertEq(n, "SCaaS ZetherToken");
        assertEq(salt, UID_);
        (, n,,,,,) = undZ.eip712Domain();
        assertEq(n, "SCaaS MetaToken", "a kind that does not override keeps the base name");
    }
}
