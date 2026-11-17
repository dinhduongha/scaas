// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {nid} from "../helpers/Ids.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";
import {UID_, normalInit} from "../v2/helpers/V2Fixture.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {instanceEnv} from "../helpers/Catalogue.sol";
import {WrappedZetherTokenA} from "../../src/zether/WrappedZetherTokenModules.sol";
import {NormalZetherTokenA} from "../../src/zether/NormalZetherTokenModules.sol";
import {WrappedPqzTokenA} from "../../src/pqz/WrappedPqzTokenModules.sol";

// Plan T25 (regulated-kinds spec §2.4): `TokenConfig.reg` on the plain kinds 0-5, each refusing any non-zero field of it with
// `ConfigFieldForOtherKind(6)` through the factory (the same config with `reg` empty is the positive control); the wrapped
// Zether and PQZ kinds' raw init decoders take the kind id and the masks from the token, not the fixed `WRAPPED_*`.

/// The five fields of `reg`, each alone non-zero (`taxRecipient`: Fable A-3).
abstract contract RegRows is Test {
    bytes32 internal constant TOKEN_SLOT = 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00; // scaas.token

    function _regs() internal pure returns (IFactoryToken.RegulatedParams[5] memory r) {
        r[0].complianceRegistry = address(0xC0FFEE);
        r[1].requiredFlags = 1;
        r[2].deniedFlags = 1 << 63;
        r[3].termsHash = bytes32(uint256(1));
        r[4].taxRecipient = bytes32(uint256(0x7A));
    }

    /// Each field of `reg` alone refuses `ConfigFieldForOtherKind(6)`; `reg` empty creates the token of `kind`.
    function _refusesReg(OpenFactory f, IOpenFactory.TokenKind kind, IFactoryToken.TokenConfig memory c) internal {
        IFactoryToken.RegulatedParams[5] memory r = _regs();
        for (uint256 i; i < 5; ++i) {
            c.reg = r[i];
            vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, uint8(6)));
            f.createToken(kind, 1, abi.encode(c), bytes32(i));
        }
        IFactoryToken.RegulatedParams memory none;
        c.reg = none;
        address t = f.createToken(kind, 1, abi.encode(c), "ok");
        assertEq(NormalToken(t).kind(), uint8(kind));
        // plan T28 (M-10): a plain kind 0-5 does not answer `IRegulatedToken`
        assertFalse(NormalToken(t).supportsInterface(type(IRegulatedToken).interfaceId), "IRegulatedToken on a plain kind");
    }

    /// The kind byte `init` wrote in `scaas.token` (creator 20 B, version 8 B, then kind).
    function _storedKind(address t) internal view returns (uint8) {
        return uint8(uint256(vm.load(t, TOKEN_SLOT)) >> 224);
    }

    /// The env the factory would append to a clone (chain-neutral spec §2.1); each test contract names its chain's.
    function _cloneEnv() internal view virtual returns (IFactoryToken.ChainEnv memory) {}

    /// A clone of `impl` initialized as the factory `fac` would.
    function _init(address impl, address fac, IFactoryToken.TokenConfig memory c) internal returns (address t) {
        t = EnvKit.clone(impl, _cloneEnv());
        vm.prank(fac);
        NormalToken(t).initialize(nid(address(this)), 1, abi.encode(c));
    }

    /// `_init` expecting `err`.
    function _initRefused(address impl, address fac, IFactoryToken.TokenConfig memory c, bytes memory err) internal {
        address t = EnvKit.clone(impl, _cloneEnv());
        vm.prank(fac);
        vm.expectRevert(err);
        NormalToken(t).initialize(nid(address(this)), 1, abi.encode(c));
    }

    /// The three refusals and the stored kind that only the token's own kind id and masks give (`Masked*` below), each
    /// against the real kind first (the positive control: the same config passes there).
    function _takesKindMasks(address real, address masked, address fac, IFactoryToken.TokenConfig memory c, uint8 kindId)
        internal
    {
        assertEq(_storedKind(_init(real, fac, c)), NormalToken(real).kind());
        assertEq(_storedKind(_init(masked, fac, c)), kindId);
        IFactoryToken.TokenConfig memory x = c; // the same memory: `c` is not read after this line
        x.features = 1 << GovernanceBits.PAYABLE; // outside the masked kind's valid bits
        _init(real, fac, x);
        _initRefused(masked, fac, x,
            abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, GovernanceBits.PAYABLE));
        x.features = 1 << GovernanceBits.WRAP_DISABLEABLE; // not a role of the masked kind
        x.lockedFeatures = x.features;
        x.roles.guardian = nid(address(0x6A2D));
        _init(real, fac, x);
        _initRefused(masked, fac, x, abi.encodeWithSelector(IGovernance.NoSuchRole.selector, GovernanceBits.WRAP_DISABLEABLE));
        x.roles.guardian = 0;
        x.features = 1 << GovernanceBits.MINTABLE; // contract-only on the masked kind: an EOA minter is refused
        x.lockedFeatures = x.features;
        x.maxSupply = 1e30;
        x.roles.minter = nid(address(0xA11CE));
        _init(real, fac, x);
        _initRefused(masked, fac, x, abi.encodeWithSelector(IGovernance.RoleNotContract.selector, GovernanceBits.MINTABLE,
            nid(address(0xA11CE))));
    }
}

/// The masks a regulated wrapped kind passes differ from `WRAPPED_*`: here `PAYABLE` is not valid, `WRAP_DISABLEABLE` is
/// no role, `MINTABLE` is contract-only, the kind id is 11. T66b: `initialize` runs in the kind's module A, so the stand-in
/// is A's twin: a clone of it runs the init body under this kind id and these masks (`onlyDelegated` holds in a clone).
contract MaskedWrappedZether is WrappedZetherTokenA {
    constructor(address f_, bytes memory a) WrappedZetherTokenA(f_, a) {}

    function kind() public pure override returns (uint8) { return TokenStore.KIND_WRAPPED_ZETHER_REGULATED; }
    function _validBits() internal pure override returns (uint256) {
        return GovernanceBits.WRAPPED_BITS & ~(uint256(1) << GovernanceBits.PAYABLE);
    }
    function _roleBits() internal pure override returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES & ~(uint256(1) << GovernanceBits.WRAP_DISABLEABLE);
    }
    function _contractOnlyBits() internal pure override returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY | (uint256(1) << GovernanceBits.MINTABLE);
    }
}

/// `MaskedWrappedZether`'s masks on `WrappedPqzToken`, kind id 13.
contract MaskedWrappedPqz is WrappedPqzTokenA {
    constructor(address f_, bytes memory a) WrappedPqzTokenA(f_, a) {}

    function kind() public pure override returns (uint8) { return TokenStore.KIND_WRAPPED_PQZ_REGULATED; }
    function _validBits() internal pure override returns (uint256) {
        return GovernanceBits.WRAPPED_BITS & ~(uint256(1) << GovernanceBits.PAYABLE);
    }
    function _roleBits() internal pure override returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES & ~(uint256(1) << GovernanceBits.WRAP_DISABLEABLE);
    }
    function _contractOnlyBits() internal pure override returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY | (uint256(1) << GovernanceBits.MINTABLE);
    }
}

/// `NormalZetherToken` under kind id 10: its raw decoder (`ZetherLib.initNormal`) writes the token's kind, not a fixed one.
contract KindNormalZether is NormalZetherTokenA {
    constructor(address f_, bytes memory a) NormalZetherTokenA(f_, a) {}

    function kind() public pure override returns (uint8) { return TokenStore.KIND_NORMAL_ZETHER_REGULATED; }
}

contract RegConfigPlainTest is RegRows {
    OpenFactory f;
    MockERC20 usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        f = EnvKit.factory(address(0xF00D), UID_, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), false);
    }

    function test_plainKindRefusesReg_0() public {
        _refusesReg(f, IOpenFactory.TokenKind.NORMAL, normalInit("N", "N", 6, 1, address(this), address(0)));
    }

    function test_plainKindRefusesReg_1() public {
        IFactoryToken.TokenConfig memory c;
        c.name = "W";
        c.symbol = "W";
        c.decimals = 6;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        _refusesReg(f, IOpenFactory.TokenKind.WRAPPED, c);
    }

    /// The regulated ids are the factory's enum members 8-13 (CTR-GOV-16).
    function test_regulatedKindIds() public pure {
        assertEq(TokenStore.KIND_NORMAL_REGULATED, uint8(IOpenFactory.TokenKind.NORMAL_REGULATED));
        assertEq(TokenStore.KIND_WRAPPED_REGULATED, uint8(IOpenFactory.TokenKind.WRAPPED_REGULATED));
        assertEq(TokenStore.KIND_NORMAL_ZETHER_REGULATED, uint8(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED));
        assertEq(TokenStore.KIND_WRAPPED_ZETHER_REGULATED, uint8(IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED));
        assertEq(TokenStore.KIND_NORMAL_PQZ_REGULATED, uint8(IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED));
        assertEq(TokenStore.KIND_WRAPPED_PQZ_REGULATED, uint8(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED));
        assertEq(TokenStore.KIND_NORMAL_REGULATED, 8);
        assertEq(TokenStore.KIND_WRAPPED_PQZ_REGULATED, 13);
    }
}

contract RegConfigZetherTest is ZetherFixture, RegRows {
    function _cloneEnv() internal view override returns (IFactoryToken.ChainEnv memory) {
        return instanceEnv(_zenv(), factory.chainUid(), address(0));
    }

    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
    }

    function _wrapped() internal returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(false, uint256(1) << 40);
        c.features = 0;
        c.lockedFeatures = 0;
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
    }

    function test_plainKindRefusesReg_2() public {
        _refusesReg(factory, IOpenFactory.TokenKind.NORMAL_ZETHER, _cfg(false, uint256(1) << 40));
    }

    function test_plainKindRefusesReg_3() public {
        _refusesReg(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, _wrapped());
    }

    function test_wrappedZetherInitTakesKindMasks() public {
        address real = address(new WrappedZetherToken(address(factory), kindArgs(3, address(factory), "")));
        address masked = address(new MaskedWrappedZether(address(factory), ""));
        _takesKindMasks(real, masked, address(factory), _wrapped(), TokenStore.KIND_WRAPPED_ZETHER_REGULATED);
    }

    function test_normalZetherInitTakesKind() public {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        assertEq(_storedKind(_init(address(normalImpl), address(factory), c)), TokenStore.KIND_NORMAL_ZETHER);
        address k = address(new KindNormalZether(address(factory), ""));
        assertEq(_storedKind(_init(k, address(factory), c)), TokenStore.KIND_NORMAL_ZETHER_REGULATED);
    }
}

contract RegConfigPqzTest is PqzFixture, RegRows {
    function _cloneEnv() internal view override returns (IFactoryToken.ChainEnv memory) {
        return instanceEnv(pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), PQZ_UID, address(0));
    }

    function setUp() public {
        _stack();
        _releaseWrapped();
    }

    function _wrapped() internal returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(uint256(1) << 40);
        c.features = 0;
        c.lockedFeatures = 0;
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
    }

    function test_plainKindRefusesReg_4() public {
        _refusesReg(factory, IOpenFactory.TokenKind.NORMAL_PQZ, _cfg(uint256(1) << 40));
    }

    function test_plainKindRefusesReg_5() public {
        _refusesReg(factory, IOpenFactory.TokenKind.WRAPPED_PQZ, _wrapped());
    }

    function test_wrappedPqzInitTakesKindMasks() public {
        address real = address(new WrappedPqzToken(address(factory), kindArgs(5, address(factory), "")));
        address masked = address(new MaskedWrappedPqz(address(factory), ""));
        _takesKindMasks(real, masked, address(factory), _wrapped(), TokenStore.KIND_WRAPPED_PQZ_REGULATED);
    }
}
