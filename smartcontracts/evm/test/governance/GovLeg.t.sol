// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {plainEnv, Catalogue} from "../helpers/Catalogue.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {ChainEnvCode} from "../../src/factory/ChainEnvCode.sol";

/// A token whose `features()` is whatever its creator asked (test only): published as kind 8, it stands for a registered
/// regulated token with `FORCE` or `MODERATE`, which no kind of this release can set; published elsewhere, or with
/// `createTokenUnregistered`, it is an outside token that may lie.
contract FlagLeg {
    address public immutable factory;
    uint8 private immutable _kind;
    uint256 public features;

    /// Chain-neutral (plan T72): the factory and `implArgs`; `chain_uid` from the clone's env.
    constructor(address f, bytes memory a) {
        factory = f;
        _kind = a.length == 0 ? 8 : abi.decode(a, (uint8));
    }

    function chainUid() external view returns (bytes32) { return ChainEnvCode.chainUid(); }
    function validateEnv(IFactoryToken.ChainEnv calldata) external pure {}
    function kind() external view returns (uint8) { return _kind; }
    function modules() external pure returns (address[] memory) {} // T66b: no body module
    function initialize(bytes32, uint64, bytes calldata a) external { features = abi.decode(a, (uint256)); }
    function underlyings() external pure returns (address[] memory) {}
    function lockedFeatures() external view returns (uint256) { return features; }
    function admin() external pure returns (address) {}
    function decimals() external pure returns (uint8) { return 6; }
}

/// @notice D5, the leg check (spec §6.1; CTR-GOV-05 and its Change; B-15): `_addLeg` of every wrapped kind refuses a leg that
///         the factory creating the token registered and whose `features()` holds `FORCE` (6) or `MODERATE` (21),
///         `UnderlyingInvalid(leg)`. `isRegisteredToken`, never `isToken`; an unregistered leg and a second factory's token are
///         outside legs, never read. Bits 5, 7, 8, 9 stay allowed. `msg.sender` is the factory, through the token's DELEGATECALL
///         to `WrappedLib` and, on the confidential kinds, a second one through their own library (GD-20).
abstract contract GovLegRows is Test {
    uint256 internal constant PLAIN = 1;
    uint256 internal constant FORCE = uint256(1) << GovernanceBits.FORCE;
    uint256 internal constant MODERATE = uint256(1) << GovernanceBits.MODERATE;

    function _fac() internal view virtual returns (OpenFactory);
    function _wKind() internal pure virtual returns (IOpenFactory.TokenKind);
    /// A config of the kind under test, PAYABLE only, over `legs`.
    function _wCfg(address[] memory legs) internal virtual returns (IFactoryToken.TokenConfig memory);

    /// A registered kind-8 `FlagLeg` of `f` with `features`; the release is published and enabled on first use.
    function _flagLeg(OpenFactory f, uint256 features, bytes32 salt) internal returns (address) {
        IOpenFactory.TokenKind k8 = IOpenFactory.TokenKind.NORMAL_REGULATED;
        if (f.implementationOf(k8, 1) == address(0)) {
            // T66b: a mock release with no body module (`Catalogue.release` would deploy kind 8's)
            uint16 v = Catalogue.env(f, k8, plainEnv(address(f), address(0), f.chainUid(), address(0), false));
            vm.prank(address(uint160(uint256(f.admin()))));
            f.deployTokenImplementation(k8, 1, v, type(FlagLeg).creationCode, "");
            vm.prank(address(uint160(uint256(f.admin()))));
            f.setKindEnabled(k8, true);
        }
        return f.createToken(k8, 1, abi.encode(features), salt);
    }

    function _one(address leg) internal pure returns (address[] memory l) {
        l = new address[](1);
        l[0] = leg;
    }

    function _wrapped(address[] memory legs, bytes32 salt) internal returns (address) {
        return _fac().createToken(_wKind(), 1, abi.encode(_wCfg(legs)), salt);
    }

    function _refused(address[] memory legs, address bad, bytes32 salt) internal {
        IFactoryToken.TokenConfig memory c = _wCfg(legs);
        OpenFactory f = _fac();
        IOpenFactory.TokenKind k = _wKind();
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnderlyingInvalid.selector, bad));
        f.createToken(k, 1, abi.encode(c), salt);
    }

    /// `FORCE` refused, `MODERATE` refused, each also as the second leg; a plain registered leg accepted, its `features()`
    /// read once and `isRegisteredToken` asked of the factory once.
    function _legCheck() internal {
        OpenFactory f = _fac();
        address plain = _flagLeg(f, PLAIN, "plain");
        address force = _flagLeg(f, PLAIN | FORCE, "force");
        address moderate = _flagLeg(f, PLAIN | MODERATE, "moderate");
        _refused(_one(force), force, "w1");
        _refused(_one(moderate), moderate, "w2");
        address[] memory two = new address[](2);
        (two[0], two[1]) = (plain, force);
        _refused(two, force, "w3");
        vm.expectCall(address(f), abi.encodeCall(IOpenFactory.isRegisteredToken, (plain)), 1);
        vm.expectCall(plain, abi.encodeCall(IGovernance.features, ()), 1);
        address w = _wrapped(_one(plain), "w4"); // positive control
        assertEq(IWrappedToken(w).underlyings()[0], plain);
    }

    function test_legCheckRunsOnEveryWrappedKind() public {
        _legCheck();
    }
}

/// `WRAPPED`, on one factory with `NORMAL`.
contract GovLegTest is GovLegRows {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    OpenFactory f;

    function setUp() public {
        f = EnvKit.factory(address(this), UID, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), false);
    }

    function _fac() internal view override returns (OpenFactory) { return f; }
    function _wKind() internal pure override returns (IOpenFactory.TokenKind) { return IOpenFactory.TokenKind.WRAPPED; }

    function _wCfg(address[] memory legs) internal pure override returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.features) = ("W", "W", 18, PLAIN);
        c.legs = new IFactoryToken.Leg[](legs.length);
        for (uint256 i; i < legs.length; ++i) c.legs[i] = IFactoryToken.Leg(legs[i], 1, 1);
    }

    function test_registeredForceLegRefused() public {
        address force = _flagLeg(f, PLAIN | FORCE, "force");
        assertTrue(f.isRegisteredToken(force));
        _refused(_one(force), force, "w");
        _wrapped(_one(_flagLeg(f, PLAIN, "plain")), "w"); // positive control, the same salt
    }

    function test_registeredModerateLegRefused() public {
        address moderate = _flagLeg(f, PLAIN | MODERATE, "moderate");
        _refused(_one(moderate), moderate, "w");
        address both = _flagLeg(f, PLAIN | FORCE | MODERATE, "both");
        _refused(_one(both), both, "w");
        _wrapped(_one(_flagLeg(f, PLAIN, "plain")), "w"); // positive control
    }

    /// `createTokenUnregistered` makes `isToken` true for anyone's code: a leg that says `FORCE | MODERATE` is an outside leg,
    /// accepted and never asked for its features.
    function test_unregisteredLegIsOutside() public {
        address impl = address(new FlagLeg(address(f), abi.encode(uint8(0))));
        address leg = f.createTokenUnregistered(IOpenFactory.TokenKind.NORMAL, impl, abi.encode(PLAIN | FORCE | MODERATE), "u");
        assertTrue(f.isToken(leg));
        assertFalse(f.isRegisteredToken(leg));
        vm.expectCall(leg, abi.encodeCall(IGovernance.features, ()), 0);
        address w = _wrapped(_one(leg), "w");
        assertEq(IWrappedToken(w).underlyings()[0], leg);
    }

    /// A second factory's registered `FORCE` token is outside to the first: accepted there, refused on its own factory.
    function test_secondFactoryLegIsOutside() public {
        OpenFactory f2 = EnvKit.factory(address(this), UID, 0);
        Catalogue.plain(f2, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), false);
        address force = _flagLeg(f2, PLAIN | FORCE, "force");
        assertTrue(f2.isRegisteredToken(force));
        assertFalse(f.isRegisteredToken(force));
        _wrapped(_one(force), "w");
        IFactoryToken.TokenConfig memory c = _wCfg(_one(force));
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnderlyingInvalid.selector, force)); // control: its own factory
        f2.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), "w");
    }

    function test_registeredPlainLegAccepted() public {
        IFactoryToken.TokenConfig memory n;
        (n.name, n.symbol, n.decimals, n.features) = ("N", "N", 6, PLAIN);
        address leg = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(n), "n");
        assertTrue(f.isRegisteredToken(leg));
        vm.expectCall(leg, abi.encodeCall(IGovernance.features, ()), 1);
        address w = _wrapped(_one(leg), "w");
        assertEq(IWrappedToken(w).underlyings()[0], leg);
    }

    /// Bits 5, 7, 8, 9 stay allowed on a leg (spec §6.1, B-34), each alone and together; 6 beside them is still refused.
    function test_pauseAndFreezeLegsStayAllowed() public {
        uint8[4] memory bits = [GovernanceBits.FREEZE, GovernanceBits.PAUSE, GovernanceBits.ALLOWLIST, GovernanceBits.DENYLIST];
        uint256 all;
        for (uint256 i; i < 4; ++i) {
            uint256 b = uint256(1) << bits[i];
            all |= b;
            _wrapped(_one(_flagLeg(f, PLAIN | b, bytes32(i + 1))), bytes32(i + 1));
        }
        _wrapped(_one(_flagLeg(f, PLAIN | all, "all")), "all");
        address bad = _flagLeg(f, PLAIN | all | FORCE, "bad"); // control
        _refused(_one(bad), bad, "bad");
    }
}

/// `WRAPPED_ZETHER`: the factory → token → `ZetherWrappedLib.init` → `WrappedLib.initToken`, two DELEGATECALLs.
contract GovLegZetherTest is GovLegRows, ZetherFixture {
    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
    }

    function _fac() internal view override returns (OpenFactory) { return factory; }
    function _wKind() internal pure override returns (IOpenFactory.TokenKind) {
        return IOpenFactory.TokenKind.WRAPPED_ZETHER;
    }

    function _wCfg(address[] memory legs) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(false, uint256(1) << 40);
        (c.features, c.lockedFeatures, c.roles.minter) = (PLAIN, 0, 0);
        c.legs = new IFactoryToken.Leg[](legs.length);
        for (uint256 i; i < legs.length; ++i) c.legs[i] = IFactoryToken.Leg(legs[i], 1, 1);
    }
}

/// `WRAPPED_PQZ`: the factory → token → `PqzWrappedLib.init` → `WrappedLib.initToken`, two DELEGATECALLs.
contract GovLegPqzTest is GovLegRows, PqzFixture {
    function setUp() public {
        _stack();
        _releaseWrapped();
    }

    function _fac() internal view override returns (OpenFactory) { return factory; }
    function _wKind() internal pure override returns (IOpenFactory.TokenKind) { return IOpenFactory.TokenKind.WRAPPED_PQZ; }

    function _wCfg(address[] memory legs) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(uint256(1) << 40);
        (c.features, c.lockedFeatures, c.roles.minter) = (PLAIN, 0, 0);
        c.legs = new IFactoryToken.Leg[](legs.length);
        for (uint256 i; i < legs.length; ++i) c.legs[i] = IFactoryToken.Leg(legs[i], 1, 1);
    }
}
