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
import {ZetherSafety} from "../../src/zether/ZetherSafety.sol";
import {MockERC20, SupportedVerifier, UnsupportedVerifier} from "../helpers/Mocks.sol";
import {UID_, noneInit} from "./helpers/V2Fixture.sol";
import {noVerifiers, zetherCanon} from "../helpers/Canon.sol";

/// Kind 2 stand-in: the public `NONE` kind under the confidential id and domain name, accepting `conf` (the factory's
/// side only; the Zether layer is tested in `test/zether`). `verifier()`, `burnVerifier()`, `disclosure()` answer the
/// raw words given (CTR-ZTH-20: the factory reads them at registration; a word wider than an address is refused).
contract MockNoneZether is NoUnderlyingToken {
    uint256 internal immutable _V;
    uint256 internal immutable _B;
    uint256 internal immutable _D;

    constructor(address f, uint256 v, uint256 b, uint256 d) NoUnderlyingToken(f, address(0), UID_, address(0), false) {
        (_V, _B, _D) = (v, b, d);
    }

    function verifier() external view returns (uint256) { return _V; }
    function burnVerifier() external view returns (uint256) { return _B; }
    function disclosure() external view returns (uint256) { return _D; }

    function kind() public pure override returns (uint8) { return AdminLib.KIND_NONE_ZETHER; }

    function _domainName() internal pure override returns (string memory) { return "SCaaS ZetherToken"; }

    function _init(TokenConfig calldata cfg) internal override {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        AdminLib.init(AdminLib.KIND_NONE_ZETHER, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
    }
}

/// Kind 3 stand-in: the public `UNDERLYING` kind under the confidential id, its flags validated for kind 3.
contract MockUnderlyingZether is UnderlyingToken {
    address public immutable verifier;
    address public immutable burnVerifier;
    address public immutable disclosure;

    constructor(address f, address v, address b, address d) UnderlyingToken(f, address(0), UID_, address(0), false) {
        (verifier, burnVerifier, disclosure) = (v, b, d);
    }

    function kind() public pure override returns (uint8) { return AdminLib.KIND_UNDERLYING_ZETHER; }

    function _init(TokenConfig calldata cfg) internal override {
        _requireUnused(cfg, true, false, false, false);
        UnderlyingLib.initToken(cfg, IS_HEDERA, AdminLib.KIND_UNDERLYING_ZETHER);
    }
}

/// The Zether gate of `OpenFactory` (CTR-ZTH-02, CTR-TOK-03): off by default, registrar only, dev chains only, the
/// verifier checked at creation; the `conf` fields are the confidential kinds' only (CTR-TOK-25); the domain name hook.
/// Answers every call, returning nothing.
contract PermissiveFallback {
    fallback() external {}
}

contract FactoryZetherTest is Test {
    OpenFactory f;
    address registrar = address(0xF00D);
    MockNoneZether noneZ;
    MockUnderlyingZether undZ;
    MockERC20 usd = new MockERC20("USD", "USD", 6);
    SupportedVerifier okVer = new SupportedVerifier();
    SupportedVerifier okBurn = new SupportedVerifier();
    address okDis = address(new SupportedVerifier()); // any contract: the factory compares addresses
    UnsupportedVerifier badVer = new UnsupportedVerifier();

    IOpenFactory.TokenKind constant NZ = IOpenFactory.TokenKind.NONE_ZETHER;
    IOpenFactory.TokenKind constant UZ = IOpenFactory.TokenKind.UNDERLYING_ZETHER;

    function setUp() public {
        f = new OpenFactory(registrar, UID_, zetherCanon(0, address(okVer), address(okBurn), okDis));
        noneZ = new MockNoneZether(address(f), uint160(address(okVer)), uint160(address(okBurn)), uint160(okDis));
        undZ = new MockUnderlyingZether(address(f), address(okVer), address(okBurn), okDis);
        vm.startPrank(registrar);
        f.registerImplementation(NZ, 1, address(noneZ));
        f.registerImplementation(UZ, 1, address(undZ));
        vm.stopPrank();
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
        vm.prank(registrar);
        f.setZetherEnabled(true);
    }

    function test_zetherGate_offByDefault_registrarOnly_devChainsOnly() public {
        assertFalse(f.zetherEnabled());
        vm.expectRevert(IOpenFactory.ZetherDisabled.selector);
        f.createToken(NZ, 1, _conf(), "a");
        vm.expectRevert(IOpenFactory.ZetherDisabled.selector);
        f.createToken(UZ, 1, _underlying(), "a");
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.setZetherEnabled(true);
        uint256[4] memory prod = [uint256(1), 100, 42220, 7622];
        for (uint256 i; i < prod.length; ++i) {
            vm.chainId(prod[i]);
            vm.prank(registrar);
            vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, prod[i]));
            f.setZetherEnabled(true);
            vm.prank(registrar);
            f.setZetherEnabled(false); // switching off always works
        }
        vm.chainId(1337);
        vm.recordLogs();
        _enable();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], IOpenFactory.ZetherEnabled.selector);
        assertEq(abi.decode(logs[0].data, (bool)), true);
        assertTrue(f.zetherEnabled());
        f.createToken(NZ, 1, _conf(), "on 1337");
        // the flag set on a dev chain does not survive a chain id change (a fork)
        vm.chainId(100);
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 100));
        f.createToken(NZ, 1, _conf(), "fork");
        vm.chainId(31337);
        vm.recordLogs();
        vm.prank(registrar);
        f.setZetherEnabled(false);
        logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], IOpenFactory.ZetherEnabled.selector);
        assertEq(abi.decode(logs[0].data, (bool)), false, "the disable event says false");
        vm.expectRevert(IOpenFactory.ZetherDisabled.selector);
        f.createToken(NZ, 1, _conf(), "off again");
    }

    /// CTR-ZTH-20: a release registers only when its `(verifier(), burnVerifier(), disclosure())` is one of the canonical
    /// sets fixed in the factory's constructor; no admin can add one; the creator names none.
    function test_zetherRelease_canonicalVerifiersOnly() public {
        uint256 v = uint160(address(okVer));
        uint256 b = uint160(address(okBurn));
        uint256 d = uint160(okDis);
        // one part off, zero, swapped, or wider than an address
        uint256[3][7] memory bad = [[uint256(0), b, d], [v, 0, d], [v, b, 0], [uint256(0x99), b, d], [b, v, d],
            [v | 1 << 200, b, d], [v, b, d | 1 << 160]];
        for (uint256 i; i < bad.length; ++i) {
            MockNoneZether m = new MockNoneZether(address(f), bad[i][0], bad[i][1], bad[i][2]);
            vm.prank(registrar);
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.NotCanonicalVerifiers.selector, address(m)));
            f.registerImplementation(NZ, 2, address(m));
        }
        MockUnderlyingZether u = new MockUnderlyingZether(address(f), address(okVer), address(0x99), okDis);
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.NotCanonicalVerifiers.selector, address(u)));
        f.registerImplementation(UZ, 2, address(u));
        // curve 1 is empty on this factory: nothing matches it
        (address tv, address bv, address dv) = f.zetherVerifiers(1);
        assertEq(tv, address(0));
        assertEq(bv, address(0));
        assertEq(dv, address(0));
        (tv, bv, dv) = f.zetherVerifiers(0);
        assertEq(tv, address(okVer));
        assertEq(bv, address(okBurn));
        assertEq(dv, okDis);
        // the canonical release creates, registered
        _enable();
        address t = f.createToken(NZ, 1, _conf(), "ok");
        assertTrue(f.isRegisteredToken(t));
        assertEq(f.getWrapper(address(this), address(usd)), address(0));
        address w = f.createToken(UZ, 1, _underlying(), "ok");
        assertEq(f.getWrapper(address(this), address(usd)), w);
    }

    /// A canonical verifier this chain cannot run is still refused at creation (CTR-TOK-18): typed, with the curve name.
    function test_zetherGate_canonicalVerifierUnsupported() public {
        address perm = address(new PermissiveFallback()); // answers every call with empty data (review T1 M2)
        address mute = address(usd); // has code, answers neither function
        address[3] memory vs = [address(badVer), perm, mute];
        string[3] memory curves = ["bls12-381", "", ""];
        for (uint256 i; i < vs.length; ++i) {
            OpenFactory g = new OpenFactory(registrar, UID_, zetherCanon(1, vs[i], address(okBurn), okDis));
            MockNoneZether m = new MockNoneZether(address(g), uint160(vs[i]), uint160(address(okBurn)), uint160(okDis));
            vm.startPrank(registrar);
            g.registerImplementation(NZ, 1, address(m));
            g.setZetherEnabled(true);
            vm.stopPrank();
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VerifierUnsupportedOnThisChain.selector, vs[i], curves[i]));
            g.createToken(NZ, 1, _conf(), "a");
        }
        // the public kinds never pass through the gate (no flag, no verifier)
        NoUnderlyingToken none = new NoUnderlyingToken(address(f), address(0), UID_, address(0), false);
        vm.prank(registrar);
        f.registerImplementation(IOpenFactory.TokenKind.NONE, 1, address(none));
        f.createToken(IOpenFactory.TokenKind.NONE, 1, noneInit("P", "P", 0, 0, address(0), address(0)), "public");
    }

    /// The flags of kind 3 are validated for kind 3: the regulated flags are invalid there (CTR-ZTH-47), not "not built".
    function test_underlyingZether_flagsValidatedForItsKind() public {
        _enable();
        IFactoryToken.TokenConfig memory c = _underlying();
        c.features = 1 << AdminLib.FREEZE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.FREEZE));
        f.createToken(UZ, 1, c, "a");
        c.features = 1 << AdminLib.MINTABLE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.MINTABLE));
        f.createToken(UZ, 1, c, "a");
    }

    /// A public kind refuses every `conf` field, the two modes included.
    function test_publicKinds_refuseEveryConfField() public {
        OpenFactory g = new OpenFactory(registrar, UID_, noVerifiers());
        NoUnderlyingToken none = new NoUnderlyingToken(address(g), address(0), UID_, address(0), false);
        vm.prank(registrar);
        g.registerImplementation(IOpenFactory.TokenKind.NONE, 1, address(none));
        IFactoryToken.TokenConfig memory c = noneInit("P", "P", 0, 0, address(0), address(0));
        c.conf.maxShielded = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, c, "a");
        c.conf.maxShielded = 0;
        c.conf.confidentialFee = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, c, "a");
        c.conf.confidentialFee = 0;
        c.conf.verifier = address(okVer);
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, c, "a");
        c.conf.verifier = address(0);
        c.conf.disclosureMode = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, c, "a");
        c.conf.disclosureMode = 0;
        c.conf.auditorMode = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, c, "a");
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
