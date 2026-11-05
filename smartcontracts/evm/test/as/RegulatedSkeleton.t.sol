// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../../src/metatx/ERC20MetaTx.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {RegulatedNotBuilt} from "../../src/regulated/RegulatedLib.sol";
import {WrappedRegulatedToken} from "../../src/regulated/WrappedRegulatedToken.sol";
import {WrappedPqzRegulatedToken} from "../../src/regulated/WrappedPqzRegulatedToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue, plainEnv, pqzEnv} from "../helpers/Catalogue.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";

/// Test only: the five masks of a regulated kind, as `GovernanceLib` receives them.
contract WrappedRegulatedMasks is WrappedRegulatedToken {
    constructor(uint16 v, Env memory env, bytes memory a) WrappedRegulatedToken(v, env, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _scalarBits(), _delayedRelaxBits());
    }
}

contract WrappedPqzRegulatedMasks is WrappedPqzRegulatedToken {
    constructor(uint16 v, Env memory env, bytes memory a) WrappedPqzRegulatedToken(v, env, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _scalarBits(), _delayedRelaxBits());
    }
}

/// Plan T27 (regulated-kinds spec §2.1, §2.2, §3.1, §3.2, §4.2; F-19): the skeleton of kinds 9 and 13, measured first. The
/// releases pass the factory's `kind()` check; the masks are the base kind's plus the regulated bits (bit 8 not on 13, bit 22
/// never contract-only); ERC-165 answers `IRegulatedToken` on 9 and 13 only; the init path reaches `RegulatedLib.init` before
/// the kind's own init, so creation fails closed (`RegulatedNotBuilt`) until T28; the eight stubs and the five views revert
/// the placeholder; every hook seat reaches `RegulatedBase` (the public pre row at any fee, the confidential one only
/// fee-bearing). Each row has its plain-kind positive control.
contract RegulatedSkeletonTest is PqzFixture {
    WrappedRegulatedToken internal r9;
    WrappedPqzRegulatedToken internal r13;
    WrappedToken internal w1;
    WrappedPqzToken internal w5;
    IFactoryToken.Env internal plain;
    IFactoryToken.Env internal pqz;

    uint256 constant REG_ROLES = (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10) | (1 << 21) | (1 << 22);
    uint256 constant REG_CONTRACT_ONLY = (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10) | (1 << 21);

    function setUp() public {
        _stack();
        plain = plainEnv(address(factory), address(0), PQZ_UID, address(reg), false);
        pqz = pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv));
        r9 = WrappedRegulatedToken(payable(Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, plain,
            type(WrappedRegulatedToken).creationCode)));
        r13 = WrappedPqzRegulatedToken(payable(Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, 1, pqz,
            type(WrappedPqzRegulatedToken).creationCode)));
        w1 = WrappedToken(payable(Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED, 1, plain,
            type(WrappedToken).creationCode)));
        w5 = WrappedPqzToken(payable(Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_PQZ, 1, pqz,
            type(WrappedPqzToken).creationCode)));
        vm.startPrank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.WRAPPED, true);
        factory.setKindEnabled(IOpenFactory.TokenKind.WRAPPED_REGULATED, true);
        factory.setKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, true);
        vm.stopPrank();
    }

    /// The factory's `_checkImplementation` read `kind()` 9 and 13 (`VersionKindMismatch` otherwise).
    function test_releasesOfKinds9And13() public view {
        assertEq(r9.kind(), 9);
        assertEq(r13.kind(), 13);
        assertEq(factory.implementationOf(IOpenFactory.TokenKind.WRAPPED_REGULATED, 1), address(r9));
        assertEq(factory.implementationOf(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, 1), address(r13));
    }

    /// Spec §2.1 and bit 22 (CTR-GOV-20): base | 5-10, 21, 22 (9) or base | 5-7, 9, 10, 21, 22 (13); roles | 5, 6, 7, 10, 21,
    /// 22; contract-only | 5, 6, 7, 10, 21 (never 22); scalar 1 | 6, 21, 22; delayed relax 5, 6, 7.
    function test_masks() public {
        (uint256 v, uint256 r, uint256 c, uint256 s, uint256 d) = new WrappedRegulatedMasks(1, plain, "").masks();
        uint256 reg = (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 21) | (1 << 22);
        assertEq(v, GovernanceBits.WRAPPED_BITS | reg, "9 valid");
        assertEq(r, GovernanceBits.WRAPPED_ROLES | REG_ROLES, "9 roles");
        assertEq(c, GovernanceBits.WRAPPED_CONTRACT_ONLY | REG_CONTRACT_ONLY, "9 contract-only");
        assertEq(s, (1 << 1) | (1 << 6) | (1 << 21) | (1 << 22), "9 scalar");
        assertEq(d, (1 << 5) | (1 << 6) | (1 << 7), "9 delayed relax");
        assertEq(r9.validBits(), v, "9 validBits()");

        (v, r, c, s, d) = new WrappedPqzRegulatedMasks(1, pqz, "").masks();
        assertEq(v, GovernanceBits.WRAPPED_BITS | (reg & ~uint256(1 << 8)), "13 valid: no ALLOWLIST");
        assertEq(r, GovernanceBits.WRAPPED_ROLES | REG_ROLES, "13 roles");
        assertEq(c, GovernanceBits.WRAPPED_CONTRACT_ONLY | REG_CONTRACT_ONLY, "13 contract-only");
        assertEq(s, (1 << 1) | (1 << 6) | (1 << 21) | (1 << 22), "13 scalar");
        assertEq(d, (1 << 5) | (1 << 6) | (1 << 7), "13 delayed relax");
        assertEq(r13.validBits(), v, "13 validBits()");
    }

    /// M-10: `IRegulatedToken` on 9 and 13, not on their base kinds; the base kinds' answers unchanged.
    function test_supportsIRegulatedToken() public view {
        bytes4 id = type(IRegulatedToken).interfaceId;
        assertTrue(r9.supportsInterface(id), "9");
        assertTrue(r13.supportsInterface(id), "13");
        assertFalse(w1.supportsInterface(id), "1");
        assertFalse(w5.supportsInterface(id), "5");
        assertTrue(r9.supportsInterface(type(IERC165).interfaceId), "9 IERC165");
        assertTrue(r13.supportsInterface(type(IERC165).interfaceId), "13 IERC165");
        assertFalse(r13.supportsInterface(0xffffffff), "13 0xffffffff");
    }

    function _wrappedCfg() internal returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(uint256(1) << 40);
        c.features = 1 << GovernanceBits.PAYABLE;
        (c.lockedFeatures, c.roles.minter) = (0, 0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
    }

    /// The init path reaches `RegulatedLib.init` first (spec §2.4, before any mint): creation fails closed until T28. The
    /// same config creates the base kind (the control).
    function test_createRefusedUntilBuilt() public {
        IFactoryToken.TokenConfig memory c = _wrappedCfg();
        IFactoryToken.ConfidentialConfig memory none;
        c.conf = none;
        vm.expectRevert(RegulatedNotBuilt.selector);
        factory.createToken(IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, abi.encode(c), "r9");
        assertEq(MetaTokenBase(factory.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), "w1")).kind(), 1);

        c = _wrappedCfg();
        vm.expectRevert(RegulatedNotBuilt.selector);
        factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, 1, abi.encode(c), "r13");
        assertEq(MetaTokenBase(factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), "w5")).kind(), 5);
    }

    /// The eight controls and the five views (spec §3.1), at their final arity, revert the placeholder on both kinds.
    function test_stubsAndViewsNotBuilt() public {
        address[2] memory ks = [address(r9), address(r13)];
        for (uint256 i; i < 2; ++i) {
            IRegulatedToken t = IRegulatedToken(ks[i]);
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.freeze(bytes32(uint256(1)), bytes32(uint256(2)), 0);
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.unfreeze(bytes32(uint256(1)), bytes32(uint256(2)));
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.forceTransfer(bytes32(uint256(3)), 1);
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.pause(bytes32(uint256(2)), uint64(block.timestamp + 1));
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.unpause(bytes32(uint256(2)));
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.recordOrder(bytes32(uint256(4)), bytes32(uint256(5)), bytes32(uint256(1)), bytes32(uint256(6)), 1, 0);
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.revokeOrder(bytes32(uint256(3)), bytes32(uint256(2)));
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.operatorTransfer(bytes32(uint256(1)), bytes32(uint256(6)), 1, bytes32(uint256(2)));
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.regulatedConfig();
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.freezeOf(bytes32(uint256(1)));
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.isFrozen(bytes32(uint256(1)));
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.canReceive(bytes32(uint256(1)));
            vm.expectRevert(RegulatedNotBuilt.selector);
            t.order(bytes32(uint256(3)));
        }
    }

    function _call(address t, bytes memory cd) internal returns (bool ok, bytes4 err) {
        bytes memory ret;
        (ok, ret) = t.call(cd);
        if (ret.length >= 4) err = bytes4(ret);
    }

    function _transfer(uint32 mode) internal view returns (bytes memory) {
        MetaTxLib.UAMetaTransfer memory t;
        (t.from, t.to, t.value, t.batch, t.validUntil, t.mode) = (alice, bob, 1, 1, block.timestamp + 60, mode);
        IUARegistry.UASig memory none;
        return abi.encodeCall(ERC20MetaTx.mtxExecuteTransfer, (t, none));
    }

    /// The ledger, payer and pre seats reach `RegulatedBase` on both kinds; on the base kinds the same calls never revert
    /// the placeholder (`transfer(0)` and `approve` pass). The pre row: kind 9 at any fee mode, before any signature check;
    /// kind 13 only when fee-bearing (U4: at fee `NONE` nothing is read, the call fails later in the pipeline).
    function test_hookSeatsWired() public {
        address[4] memory ks = [address(r9), address(r13), address(w1), address(w5)];
        for (uint256 i; i < 4; ++i) {
            bool reg = i < 2;
            (bool ok, bytes4 err) = _call(ks[i], abi.encodeCall(IERC20.transfer, (address(0xB0B), 0))); // _regMove
            assertTrue(reg ? !ok && err == RegulatedNotBuilt.selector : ok, "transfer");
            (ok, err) = _call(ks[i], abi.encodeCall(IERC20.approve, (address(factory), 1))); // _regPayer
            assertTrue(reg ? !ok && err == RegulatedNotBuilt.selector : ok, "approve");
            (ok, err) = _call(ks[i], _transfer(MetaTxLib.MODE_FEE_FIXED)); // _regPre, fee-bearing
            assertTrue(!ok && (err == RegulatedNotBuilt.selector) == reg, "pre, fee-bearing");
            (ok, err) = _call(ks[i], _transfer(0)); // _regPre, fee NONE
            assertTrue(!ok && (err == RegulatedNotBuilt.selector) == (ks[i] == address(r9)), "pre, fee NONE");
        }
        // the PQZ payer seat (mtxShield, direct): 13 reaches it, 5 fails elsewhere
        (bool ok13, bytes4 e13) = _call(address(r13), abi.encodeWithSignature("mtxShield(bytes32,uint256)", alice, 1));
        (bool ok5, bytes4 e5) = _call(address(w5), abi.encodeWithSignature("mtxShield(bytes32,uint256)", alice, 1));
        assertTrue(!ok13 && e13 == RegulatedNotBuilt.selector, "13 shield payer");
        assertTrue(!ok5 && e5 != RegulatedNotBuilt.selector, "5 shield");
    }
}
