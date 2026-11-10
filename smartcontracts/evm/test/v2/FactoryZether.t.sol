// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {SaltedEIP712Core} from "../../src/common/SaltedEIP712.sol";

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {NormalTokenP, NormalTokenT, NormalTokenA} from "../../src/metatx/NormalTokenModules.sol";
import {WrappedTokenP, WrappedTokenT, WrappedTokenA, WrappedTokenW} from "../../src/metatx/WrappedTokenModules.sol";
import {ImplArgs} from "../../src/metatx/ITokenModule.sol";
import {WrappedLib} from "../../src/metatx/WrappedLib.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UID_, normalInit} from "./helpers/V2Fixture.sol";
import {plainEnv, pinned, withModules, Catalogue} from "../helpers/Catalogue.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {SaltedEIP712} from "../../src/common/SaltedEIP712.sol";

/// Kind 2 stand-in: the public `NORMAL` kind under the confidential id and domain name, accepting `conf` (the factory's
/// side only; the Zether layer, its verifiers and its chain gate are tested in `test/zether`). T66b: the bodies run in the
/// modules, kind 0's (the face checks them against kind 0), so the hooks are overridden there.
contract MockNormalZether is NormalToken {
    constructor(address f_, bytes memory a) NormalToken(f_, a) {}

    function kind() public pure override returns (uint8) { return TokenStore.KIND_NORMAL_ZETHER; }

    function _domainName() internal pure override returns (string memory) { return "SCaaS ZetherToken"; }
}

contract MockNormalZetherP is NormalTokenP {
    constructor(address f_, bytes memory a) NormalTokenP(f_, a) {}

    function _domainName() internal pure override returns (string memory) { return "SCaaS ZetherToken"; }
}

contract MockNormalZetherT is NormalTokenT {
    constructor(address f_, bytes memory a) NormalTokenT(f_, a) {}

    function _domainName() internal pure override returns (string memory) { return "SCaaS ZetherToken"; }
}

contract MockNormalZetherA is NormalTokenA {
    constructor(address f_, bytes memory a) NormalTokenA(f_, a) {}

    function _domainName() internal pure override returns (string memory) { return "SCaaS ZetherToken"; }

    function _init(IFactoryToken.TokenConfig memory cfg) internal override {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        GovernanceLib.init(cfg.features, cfg.lockedFeatures, cfg.admin, cfg.grantDelay, cfg.rescueTo, cfg.roles, _validBits(),
            _roleBits(), _contractOnlyBits(), address(0));
    }
}

/// Kind 3 stand-in: the public `WRAPPED` kind under the confidential id, its flags validated for kind 3.
contract MockWrappedZether is WrappedToken {
    constructor(address f_, bytes memory a) WrappedToken(f_, a) {}

    function kind() public pure override returns (uint8) { return TokenStore.KIND_WRAPPED_ZETHER; }
}

contract MockWrappedZetherA is WrappedTokenA {
    constructor(address f_, bytes memory a) WrappedTokenA(f_, a) {}

    function _init(IFactoryToken.TokenConfig memory cfg) internal override {
        _requireUnused(cfg, true, false, false, false);
        WrappedLib.initToken(cfg, _hedera(), TokenStore.KIND_WRAPPED_ZETHER, GovernanceBits.WRAPPED_BITS, _roleBits(),
            _contractOnlyBits(), address(0));
    }
}

/// The confidential kinds behind the factory's generic gate (plan 5g-Z2, CTR-TOK-03): off by default, registrar only;
/// the chain and verifier gates are the implementation's (`test/zether`, `test/pqz`); the `conf` fields are the
/// confidential kinds' only (CTR-TOK-25); the domain name hook.
contract FactoryZetherTest is Test {
    OpenFactory f;
    address registrar = address(0xF00D);
    MockNormalZether normalZ;
    MockWrappedZether undZ;
    MockERC20 usd = new MockERC20("USD", "USD", 6);

    IOpenFactory.TokenKind constant NZ = IOpenFactory.TokenKind.NORMAL_ZETHER;
    IOpenFactory.TokenKind constant UZ = IOpenFactory.TokenKind.WRAPPED_ZETHER;

    function setUp() public {
        f = EnvKit.factory(registrar, UID_, 0);
        address[] memory ms = new address[](3);
        ms[0] = address(new MockNormalZetherP(address(f), ""));
        ms[1] = address(new MockNormalZetherT(address(f), ""));
        ms[2] = address(new MockNormalZetherA(address(f), ""));
        normalZ = MockNormalZether(_release(NZ, type(MockNormalZether).creationCode, ms));
        ms = new address[](4);
        ms[0] = address(new WrappedTokenP(address(f), ""));
        ms[1] = address(new WrappedTokenT(address(f), ""));
        ms[2] = address(new MockWrappedZetherA(address(f), ""));
        ms[3] = address(new WrappedTokenW(address(f), ""));
        undZ = MockWrappedZether(payable(_release(UZ, type(MockWrappedZether).creationCode, ms)));
    }

    /// Release 1 of `k` from `code` on its mock modules `ms`, pinned in a plain env beside the kind's link closure (T66b).
    function _release(IOpenFactory.TokenKind k, bytes memory code, address[] memory ms) internal returns (address) {
        uint16 v = Catalogue.env(f, k, withModules(pinned(plainEnv(address(f), address(0), UID_, address(0), false), k), ms));
        vm.prank(registrar);
        return f.deployTokenImplementation(k, 1, v, code, abi.encode(ImplArgs(ms)));
    }

    function _conf() internal pure returns (IFactoryToken.TokenConfig memory c) {
        c = normalInit("Zether", "Z", 6, 0, address(0), address(0));
        c.conf.shieldScale = 1;
    }

    function _wrapped() internal view returns (IFactoryToken.TokenConfig memory c) {
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
        f.createToken(UZ, 1, abi.encode(_wrapped()), "a");
        vm.expectPartialRevert(IAdmin.NotAdmin.selector);
        f.setKindEnabled(NZ, true);
        vm.recordLogs();
        _enable();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2);
        assertEq(logs[0].topics[0], IOpenFactory.KindEnabled.selector);
        assertEq(abi.decode(logs[0].data, (bool)), true);
        address t = f.createToken(NZ, 1, abi.encode(_conf()), "on");
        assertTrue(f.isRegisteredToken(t));
        address w = f.createToken(UZ, 1, abi.encode(_wrapped()), "on");
        assertEq(f.getWrapper(nid(address(this)), address(usd)), w, "the index reads underlyings() after initialize");
        vm.prank(registrar);
        f.setKindEnabled(NZ, false);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindDisabled.selector, NZ));
        f.createToken(NZ, 1, abi.encode(_conf()), "off again");
    }

    /// The flags of kind 3 are validated for kind 3: the regulated flags are invalid there (CTR-ZTH-47), not "not built".
    function test_wrappedZether_flagsValidatedForItsKind() public {
        _enable();
        IFactoryToken.TokenConfig memory c = _wrapped();
        c.features = 1 << GovernanceBits.FREEZE;
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, GovernanceBits.FREEZE));
        f.createToken(UZ, 1, abi.encode(c), "a");
        c.features = 1 << GovernanceBits.MINTABLE; // a hybrid's bit (spec §5.2, governance T9): only with `maxSupply`
        vm.expectRevert(IWrappedToken.MaxSupplyInvalid.selector);
        f.createToken(UZ, 1, abi.encode(c), "a");
    }

    /// A public kind refuses every `conf` field, the two modes included.
    function test_publicKinds_refuseEveryConfField() public {
        OpenFactory g = EnvKit.factory(registrar, UID_, 0);
        Catalogue.plain(g, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0),
            false);
        IFactoryToken.TokenConfig memory c = normalInit("P", "P", 0, 0, address(0), address(0));
        c.conf.maxShielded = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "a");
        c.conf.maxShielded = 0;
        c.conf.confidentialFee = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "a");
        c.conf.confidentialFee = 0;
        c.conf.auditorKey = hex"01";
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "a");
        c.conf.auditorKey = "";
        c.conf.disclosureMode = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "a");
        c.conf.disclosureMode = 0;
        c.conf.auditorMode = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "a");
    }

    /// CTR-MTX-02: the confidential kinds sign under "SCaaS ZetherToken", the public ones under "SCaaS MetaToken".
    /// Chain-neutral releases (plan T72): on the clones (a release carries no env and builds no domain).
    function test_domainNameHook() public {
        vm.startPrank(registrar);
        f.setKindEnabled(NZ, true);
        f.setKindEnabled(UZ, true);
        vm.stopPrank();
        address t = f.createToken(NZ, 1, abi.encode(_conf()), "dom");
        address w = f.createToken(UZ, 1, abi.encode(_wrapped()), "dom");
        (, string memory n,,,, bytes32 salt,) = MockNormalZether(t).eip712Domain();
        assertEq(n, "SCaaS ZetherToken");
        assertEq(salt, UID_);
        (, n,,,,,) = MockWrappedZether(payable(w)).eip712Domain();
        assertEq(n, "SCaaS MetaToken", "a kind that does not override keeps the base name");
        vm.expectRevert(SaltedEIP712Core.ChainUidZero.selector);
        normalZ.eip712Domain();
    }
}
