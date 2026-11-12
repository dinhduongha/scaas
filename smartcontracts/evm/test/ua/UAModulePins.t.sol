// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {deployKindModules, deployDexModules} from "../../script/KindModules.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {plainEnv, pinned, withModules} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";

/// A release that answers `kind()`, `factory()` and `validateEnv` but no `modules()` (T66b §4.5: refused, fail closed).
contract NoModulesRelease {
    address public immutable factory;

    constructor(address f, bytes memory) { factory = f; }

    function kind() external pure returns (uint8) { return 0; }

    function validateEnv(IFactoryToken.ChainEnv calldata) external pure {}
}

/// T66b (spec 2026-11-09-t66b-library-organisation.md §4.5, §10): `OpenFactory` refuses a release whose `modules()` names an
/// address outside the env's `libs` (`ModuleNotPinned`), on both release paths and on `createTokenUnregistered`, and a release
/// that does not answer `modules()` (`ModulesUnreadable`). Each refusal has its positive control.
contract UAModulePinsTest is Test {
    bytes32 internal constant UID = keccak256("t66b.module-pins");
    IOpenFactory.TokenKind internal constant NORMAL = IOpenFactory.TokenKind.NORMAL;
    OpenFactory internal f;

    function setUp() public {
        f = EnvKit.factory(address(this), UID, 0);
    }

    function _env(address[] memory ms) internal view returns (IFactoryToken.Env memory) {
        return withModules(pinned(plainEnv(address(f), address(0), UID, address(0), false), NORMAL), ms);
    }

    function _first(address[] memory ms, uint256 n) internal pure returns (address[] memory out) {
        out = new address[](n);
        for (uint256 i; i < n; ++i) out[i] = ms[i];
    }

    function _dexEnv(address[] memory ms) internal view returns (IFactoryToken.Env memory e) {
        e = plainEnv(address(f), address(0), UID, address(0), false);
        e.libs = new address[](2);
        (e.libs[0], e.libs[1]) = (address(GovernanceLib), address(TradeLib));
        e.libCodeHashes = new bytes32[](2);
        (e.libCodeHashes[0], e.libCodeHashes[1]) = (address(GovernanceLib).codehash, address(TradeLib).codehash);
        e = withModules(e, ms);
    }

    /// `deployTokenImplementation`: env 1 pins two of NormalToken's three modules, env 2 all three (the control).
    function test_m_releaseModuleNotPinned() public {
        (address[] memory ms, bytes memory args) = deployKindModules(0, address(f), "");
        assertEq(ms.length, 3);
        f.publishTokenEnv(NORMAL, 1, _env(_first(ms, 2)));
        f.publishTokenEnv(NORMAL, 2, _env(ms));
        bytes memory code = type(NormalToken).creationCode;
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ModuleNotPinned.selector, ms[2]));
        f.deployTokenImplementation(NORMAL, 1, 1, code, args, EnvKit.uidOf(address(f)));
        address impl = f.deployTokenImplementation(NORMAL, 1, 2, code, args, EnvKit.uidOf(address(f))); // control
        assertEq(NormalToken(impl).modules(), ms);
    }

    /// `createTokenUnregistered` checks the kind's latest env: one without the third module refuses, one with it creates.
    function test_m_unregisteredModuleNotPinned() public {
        (address[] memory ms, bytes memory args) = deployKindModules(0, address(f), "");
        f.publishTokenEnv(NORMAL, 1, _env(ms));
        address impl = f.deployTokenImplementation(NORMAL, 1, 1, type(NormalToken).creationCode, args, EnvKit.uidOf(address(f)));
        f.publishTokenEnv(NORMAL, 2, _env(_first(ms, 2)));
        bytes memory init = abi.encode(normalInit("U", "U", 0, 1, address(this), address(0)));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ModuleNotPinned.selector, ms[2]));
        f.createTokenUnregistered(NORMAL, impl, init, "u");
        f.publishTokenEnv(NORMAL, 3, _env(ms));
        assertTrue(f.createTokenUnregistered(NORMAL, impl, init, "u").code.length != 0); // control
    }

    /// `deployDexImplementation`: a DEX env without D refuses the release, one with D deploys it.
    function test_m_dexModuleNotPinned() public {
        (address[] memory ms, bytes memory args) = deployDexModules(address(f));
        f.publishDexEnv(1, _dexEnv(new address[](0)));
        f.publishDexEnv(2, _dexEnv(ms));
        bytes memory code = type(SCaaSDex).creationCode;
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ModuleNotPinned.selector, ms[0]));
        f.deployDexImplementation(1, 1, code, args, EnvKit.uidOf(address(f)));
        address impl = f.deployDexImplementation(1, 2, code, args, EnvKit.uidOf(address(f))); // control
        assertEq(SCaaSDex(impl).modules(), ms);
    }

    /// A release without `modules()` is refused; the same env takes NormalToken (the control above, env 2's form).
    function test_m_modulesUnreadable() public {
        f.publishTokenEnv(NORMAL, 1, _env(new address[](0)));
        bytes memory code = type(NoModulesRelease).creationCode;
        address at = vm.computeCreate2Address(keccak256(abi.encode(NORMAL, uint64(1))),
            keccak256(bytes.concat(code, abi.encode(address(f), bytes("")))), address(f));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ModulesUnreadable.selector, at));
        f.deployTokenImplementation(NORMAL, 1, 1, code, "", EnvKit.uidOf(address(f)));
    }
}
