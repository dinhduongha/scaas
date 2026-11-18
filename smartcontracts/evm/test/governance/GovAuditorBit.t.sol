// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {PqzOffchainBase} from "../pqz/helpers/PqzOffchainBase.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {NormalPqzRegulatedToken} from "../../src/regulated/NormalPqzRegulatedToken.sol";
import {WrappedPqzRegulatedToken} from "../../src/regulated/WrappedPqzRegulatedToken.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {WrappedRegulatedToken} from "../../src/regulated/WrappedRegulatedToken.sol";
import {NormalZetherRegulatedToken} from "../../src/regulated/NormalZetherRegulatedToken.sol";
import {WrappedZetherRegulatedToken} from "../../src/regulated/WrappedZetherRegulatedToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue, pqzEnv, plainEnv, regArgs} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {Holder} from "../as/helpers/RegFixture.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {nid} from "../helpers/Ids.sol";

/// Test only: the masks `GovernanceLib` receives from each kind (bit 32 on 2, 3, 4, 5, 10, 11, 12, 13).
contract AudMasks2 is NormalZetherToken {
    constructor(address f_, bytes memory a) NormalZetherToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

contract AudMasks3 is WrappedZetherToken {
    constructor(address f_, bytes memory a) WrappedZetherToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

contract AudMasks4 is NormalPqzToken {
    constructor(address f_, bytes memory a) NormalPqzToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

contract AudMasks5 is WrappedPqzToken {
    constructor(address f_, bytes memory a) WrappedPqzToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

contract AudMasks10 is NormalZetherRegulatedToken {
    constructor(address f_, bytes memory a) NormalZetherRegulatedToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

contract AudMasks11 is WrappedZetherRegulatedToken {
    constructor(address f_, bytes memory a) WrappedZetherRegulatedToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

contract AudMasks12 is NormalPqzRegulatedToken {
    constructor(address f_, bytes memory a) NormalPqzRegulatedToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

contract AudMasks13 is WrappedPqzRegulatedToken {
    constructor(address f_, bytes memory a) WrappedPqzRegulatedToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

/// The setAuditor round A1 (spec 2026-11-17-set-auditor.md §3, §13 "Bits and masks"; CTR-GOV-31): bit 32 `AUDITOR`, a power
/// of the confidential kinds 2, 3, 4, 5, 10, 11, 12, 13 only; any holder (a native EOA, a single-key UA, an `msig`, a
/// contract), never contract-only, never delay-relaxed, never delegable (`DelegableRefused(32)`); not enableable, not in
/// `REGULATED_ROLES` (kinds 8 and 9 refuse it as `NoSuchRole(32)`, never `RoleWithoutFeature(32)`); refused at `init` on a
/// token without an auditor (`BadAuditorMode(0)`) or without an admin (`FeatureNeedsAdmin(32)`). The PQZ precompile is mocked.
/// UNAUDITED.
contract GovAuditorBitTest is PqzOffchainBase {
    uint8 internal constant BIT = 32;
    uint256 internal constant M = uint256(1) << 32;

    OpenFactory internal f;
    bytes32 internal owner_;

    function setUp() public {
        _offStack();
        owner_ = nid(address(this));
        f = new OpenFactory(nid(registrar));
        EnvKit.configure(f, PQZ_UID, 0, address(0));
        IFactoryToken.Env memory e = pqzEnv(address(f), PQZ_UID, address(reg), address(pqv));
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_PQZ, 1, e, type(NormalPqzToken).creationCode);
        Catalogue.release(f, IOpenFactory.TokenKind.WRAPPED_PQZ, 1, e, type(WrappedPqzToken).creationCode);
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, 1, e, type(NormalPqzRegulatedToken).creationCode,
            regArgs());
        Catalogue.release(f, IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, 1, e, type(WrappedPqzRegulatedToken).creationCode,
            regArgs());
        vm.startPrank(registrar);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, EnvKit.uidOf(address(f)));
        f.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ, true, EnvKit.uidOf(address(f)));
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, true, EnvKit.uidOf(address(f)));
        f.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, true, EnvKit.uidOf(address(f)));
        vm.stopPrank();
    }

    /// The config of PQZ kind `k` (4, 5, 12, 13) with bit 32 set (unless `withBit` is false), the test its admin (`admin`
    /// false: 0), `delay` its grant delay.
    function _cfg32(uint8 k, bool withBit, bool admin, uint64 delay) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(uint256(1) << 40);
        // admin 0: the minter's bit 1 locked, so the seat survives creation (B-06), as the fixture's own tokens
        (c.admin, c.grantDelay, c.lockedFeatures) = (admin ? owner_ : bytes32(0), delay, admin ? 0 : c.lockedFeatures);
        if (k == 5 || k == 13) {
            c.features = 1 << GovernanceBits.PAYABLE;
            c.roles.minter = 0;
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(0xD011A5), 1, 1);
        }
        if (withBit) c.features |= M;
        if (k >= 12) c.lockedFeatures |= uint256(1) << GovernanceBits.DENYLIST;
    }

    function _create(uint8 k, IFactoryToken.TokenConfig memory c, bytes32 salt) internal returns (IGovernance) {
        if (k == 5 || k == 13) c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
        return IGovernance(f.createToken(IOpenFactory.TokenKind(k), 1, abi.encode(c), salt));
    }

    function _tok32(uint8 k, uint64 delay) internal returns (IGovernance) {
        return _create(k, _cfg32(k, true, true, delay), keccak256(abi.encode("bit 32", k, delay)));
    }

    function _uid(IGovernance t) internal view returns (bytes32) {
        return EnvKit.codeUidOf(address(t));
    }

    // ------------------------------------------------------------------ the kinds

    function _masks(uint8 k) internal returns (uint256 v, uint256 r, uint256 c, uint256 d) {
        if (k == 2) return new AudMasks2(address(f), kindArgs(2, address(f), "")).masks();
        if (k == 3) return new AudMasks3(address(f), kindArgs(3, address(f), "")).masks();
        if (k == 4) return new AudMasks4(address(f), kindArgs(4, address(f), "")).masks();
        if (k == 5) return new AudMasks5(address(f), kindArgs(5, address(f), "")).masks();
        if (k == 10) return new AudMasks10(address(f), kindArgs(10, address(f), regArgs())).masks();
        if (k == 11) return new AudMasks11(address(f), kindArgs(11, address(f), regArgs())).masks();
        if (k == 12) return new AudMasks12(address(f), kindArgs(12, address(f), regArgs())).masks();
        return new AudMasks13(address(f), kindArgs(13, address(f), regArgs())).masks();
    }

    /// Each confidential kind: valid, a role bit (a power), never contract-only, never delay-relaxed.
    function test_bit32_masks_confidentialKinds() public {
        uint8[8] memory ks = [2, 3, 4, 5, 10, 11, 12, 13];
        for (uint256 i; i < 8; ++i) {
            (uint256 v, uint256 r, uint256 c, uint256 d) = _masks(ks[i]);
            string memory k = vm.toString(ks[i]);
            assertTrue(v & M != 0, string.concat("valid on ", k));
            assertTrue(r & M != 0, string.concat("a power on ", k));
            assertEq(c & M, 0, string.concat("never contract-only on ", k));
            assertEq(d & M, 0, string.concat("never delay-relaxed on ", k));
        }
        assertEq(GovernanceBits.AUDITOR, 32);
        assertEq(GovernanceBits.ENABLEABLE & M, 0, "set at creation only");
        assertEq(GovernanceBits.REGULATED_ROLES & M, 0, "not a regulated role (kinds 8 and 9 refuse it)");
        assertEq(GovernanceBits.ISSUER_BITS & M, 0, "no Roles seat: the admin grants it");
        assertEq(GovernanceBits.ALWAYS_LOCKED & M, 0);
    }

    /// Kinds 0, 1, 8, 9 have bit 32 outside their valid and role masks; a creation of kind 0 with it is
    /// `FeatureInvalidForKind(32)`.
    function test_bit32_otherKindsRefused() public {
        address[4] memory impls = [address(new NormalToken(address(f), kindArgs(0, address(f), ""))),
            address(new WrappedToken(address(f), kindArgs(1, address(f), ""))),
            address(new NormalRegulatedToken(address(f), kindArgs(8, address(f), regArgs()))),
            address(new WrappedRegulatedToken(address(f), kindArgs(9, address(f), regArgs())))];
        for (uint256 i; i < 4; ++i) assertEq(IGovernance(impls[i]).validBits() & M, 0, vm.toString(i));
        _tok32(4, 0); // the control: a confidential kind takes it
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (c.admin, c.lockedFeatures) = (owner_, 0);
        c.features |= M;
        c.conf = IFactoryToken.ConfidentialConfig("", 0, 0, 0, 0, 0, 0, 0, bytes32(0), false, 0, 0, 0, false, false);
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL, 1,
            plainEnv(address(factory), address(0), PQZ_UID, address(reg), false), type(NormalToken).creationCode);
        vm.prank(registrar);
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL, true, EnvKit.uidOf(address(factory)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, BIT));
        factory.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "plain-32");
    }

    /// A token of every PQZ kind takes the bit with an auditor and an admin; `features()` holds it, nobody holds it yet.
    function test_bit32_init_pqzKinds() public {
        uint8[4] memory ks = [4, 5, 12, 13];
        for (uint256 i; i < 4; ++i) {
            IGovernance t = _tok32(ks[i], 0);
            assertTrue(t.features() & M != 0, vm.toString(ks[i]));
            assertTrue(t.validBits() & M != 0);
            assertEq(t.holderCount(BIT), 0, "no seat: no holder at creation");
        }
    }

    /// `init` refuses bit 32 on a token without an auditor (`BadAuditorMode(0)`) and with admin 0 (`FeatureNeedsAdmin(32)`),
    /// each next to its control (the same config with the auditor and the admin).
    function test_bit32_init_refusals() public {
        IFactoryToken.TokenConfig memory c = _cfg32(4, true, true, 0);
        _create(4, c, "control");
        uint8 keep = aMode;
        aMode = uint8(ZetherTypes.AuditorMode.NONE);
        c = _cfg32(4, true, true, 0);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadAuditorMode.selector, uint8(0)));
        f.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "none");
        c = _cfg32(4, false, true, 0); // without the bit a NONE token is created as before
        _create(4, c, "none without the bit");
        aMode = keep;
        c = _cfg32(12, true, false, 0);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNeedsAdmin.selector, BIT));
        f.createToken(IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, 1, abi.encode(c), "no admin");
        c = _cfg32(12, false, false, 0);
        _create(12, c, "no admin without the bit");
    }

    // ------------------------------------------------------------------ the holders (owner ruling 4: any UA)

    function _granted(IGovernance t, bytes32 h) internal {
        t.grantRole(BIT, h, _uid(t));
        assertTrue(t.hasRole(BIT, h));
    }

    function test_bit32_anyHolder() public {
        _granted(_tok32(4, 0), nid(vm.addr(0xE0A))); // a native EOA
        _granted(_tok32(5, 0), _mldsaUA(32)); // a derived single-key UA
        _granted(_tok32(12, 0), keccak256("bit 32 msig")); // an msig id (no registry read: bit 32 is not contract-only)
        _granted(_tok32(13, 0), nid(address(new Holder()))); // a contract
    }

    /// Kinds 8 and 9 refuse a grant of 32 as `NoSuchRole(32)` (their role masks), never `RoleWithoutFeature(32)`; a confidential
    /// kind without the bit set refuses it as `RoleWithoutFeature(32)` (the control of the two checks' order).
    function test_bit32_grantOnKind8_noSuchRole() public {
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_REGULATED, 1, plainEnv(address(f), address(0), PQZ_UID, address(reg), false),
            type(NormalRegulatedToken).creationCode, regArgs());
        vm.prank(registrar);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED, true, EnvKit.uidOf(address(f)));
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (c.admin, c.lockedFeatures) = (owner_, (uint256(1) << GovernanceBits.DENYLIST) | (uint256(1) << GovernanceBits.ALLOWLIST));
        c.conf = IFactoryToken.ConfidentialConfig("", 0, 0, 0, 0, 0, 0, 0, bytes32(0), false, 0, 0, 0, false, false);
        IGovernance r8 = IGovernance(f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "kind 8"));
        bytes32 h = nid(vm.addr(0xE0B));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, BIT));
        r8.grantRole(BIT, h, _uid(r8));
        IGovernance off = _create(4, _cfg32(4, false, true, 0), "kind 4 without the bit");
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, BIT));
        off.grantRole(BIT, h, _uid(off));
        _granted(_tok32(4, 0), h); // the control: a confidential kind with the bit
    }

    /// No delegation on bit 32: `delegable` terms refused (`DelegableRefused(32)`); the same terms not delegable pass.
    function test_bit32_delegableRefused() public {
        IGovernance t = _tok32(4, 0); // kind 4 has bit 1 set: the control below
        bytes32 h = nid(vm.addr(0xE0C));
        IGovernance.GrantTerms memory g;
        (g.max, g.maxUses, g.delegable) = (type(uint128).max, 4, true);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.DelegableRefused.selector, BIT));
        t.setGrant(BIT, h, g, _uid(t));
        g.delegable = false;
        t.setGrant(BIT, h, g, _uid(t));
        assertTrue(t.hasRole(BIT, h));
        // the control on another bit of the same token: delegable is accepted there (bit 1, a scalar bit, with a budget)
        (g.max, g.total, g.delegable) = (10, 10, true);
        t.setGrant(GovernanceBits.MINTABLE, h, g, _uid(t));
        assertTrue(t.hasRole(GovernanceBits.MINTABLE, h));
    }

    /// With a grant delay, the admin's revoke and `disableFeature(32)`, and the holder's renounce, act in one call.
    function test_bit32_stopsAtOnce() public {
        uint8[2] memory ks = [4, 12];
        for (uint256 i; i < 2; ++i) {
            IGovernance t = _tok32(ks[i], 1 days);
            bytes32 a = nid(vm.addr(0xA1));
            bytes32 b = nid(vm.addr(0xB1));
            t.grantRole(BIT, a, _uid(t)); // proposes (grantDelay)
            t.grantRole(BIT, b, _uid(t));
            vm.warp(block.timestamp + 1 days);
            t.grantRole(BIT, a, _uid(t));
            t.grantRole(BIT, b, _uid(t));
            assertTrue(t.hasRole(BIT, a) && t.hasRole(BIT, b));
            t.revokeRole(BIT, a, _uid(t));
            assertFalse(t.hasRole(BIT, a), "revoked at once");
            vm.prank(vm.addr(0xB1));
            t.renounceRole(BIT, _uid(t));
            assertFalse(t.hasRole(BIT, b), "renounced at once");
            t.disableFeature(BIT, _uid(t));
            assertEq(t.features() & M, 0, "disabled at once");
        }
    }
}

/// The Zether side of A1: kind 2's `init` takes bit 32 with an auditor and an admin and refuses it without either.
contract GovAuditorBitZetherTest is ZetherFixture {
    uint256 internal constant M = uint256(1) << 32;
    bool internal withBit;
    bool internal withAdmin;

    function setUp() public {
        _stack();
        _users();
    }

    function _c32(bool auditor) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(auditor, uint256(1) << 40);
        if (withBit) c.features |= M;
        if (withAdmin) (c.admin, c.lockedFeatures) = (nid(address(this)), 0);
    }

    function test_bit32_init_zether() public {
        (withBit, withAdmin) = (true, true);
        address t = factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(_c32(true)), "control");
        assertTrue(IGovernance(t).features() & M != 0);
        IFactoryToken.TokenConfig memory c = _c32(false);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, uint8(0)));
        factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "none");
        withAdmin = false;
        c = _c32(true);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNeedsAdmin.selector, uint8(32)));
        factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "no admin");
        withBit = false;
        factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(_c32(true)), "no bit, no admin"); // as before
    }
}
