// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {deployDexModules} from "../../script/KindModules.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {SCaaSDexGovernanceModule} from "../../src/dex/SCaaSDexAdmin.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {ImplArgs, ITokenModule} from "../../src/metatx/ITokenModule.sol";
import {nid} from "../helpers/Ids.sol";
import {UADexBase} from "./UADex.t.sol";

/// T66b (spec 2026-11-09-t66b-library-organisation.md §4.2, owner 2026-11-09 ruling (a)): the DEX's 22 governance entries run
/// in its admin module D by DELEGATECALL from the DEX's stubs; D refuses a direct call (M2); the DEX's constructor checks D
/// (code, group, factory; §4.5).
contract UADexAdminTest is UADexBase {
    function _one(address m) internal pure returns (bytes memory) {
        address[] memory ms = new address[](1);
        ms[0] = m;
        return abi.encode(ImplArgs(ms));
    }

    function _two(address m0, address m1) internal pure returns (bytes memory) {
        address[] memory ms = new address[](2);
        (ms[0], ms[1]) = (m0, m1);
        return abi.encode(ImplArgs(ms));
    }

    /// The DEX's governance views and writes run in D (one DELEGATECALL each), with the DEX's state.
    function test_d_governanceRunsInD() public {
        address d = dex.modules()[0];
        assertEq(dex.modules().length, 2);
        assertEq(ITokenModule(d).moduleGroup(), 10);
        assertEq(ITokenModule(d).factory(), address(f));
        vm.expectCall(d, abi.encodeCall(IGovernance.owner, ()));
        assertEq(dex.owner(), nid(address(this)));
        assertEq(dex.validBits(), GovernanceBits.DEX_BITS);
        assertTrue(dex.hasRole(GovernanceBits.LISTING, nid(address(this))));
        vm.expectCall(d, abi.encodeCall(IGovernance.transferOwnership, (nid(dave))));
        dex.transferOwnership(nid(dave));
        assertEq(dex.pendingOwner(), nid(dave));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, nid(dave)));
        vm.prank(dave);
        dex.renounceOwnership(); // D's revert data, verbatim through the stub
    }

    /// M2: D's entries answer only under DELEGATECALL; `validBits` is `pure` and reads nothing.
    function test_d_directCallRefused() public {
        SCaaSDexGovernanceModule d = SCaaSDexGovernanceModule(dex.modules()[0]);
        vm.expectRevert(SCaaSDexGovernanceModule.NotDelegated.selector);
        d.owner();
        vm.expectRevert(SCaaSDexGovernanceModule.NotDelegated.selector);
        d.features();
        vm.expectRevert(SCaaSDexGovernanceModule.NotDelegated.selector);
        d.transferOwnership(nid(dave));
        vm.expectRevert(SCaaSDexGovernanceModule.NotDelegated.selector);
        d.grantRole(GovernanceBits.LISTING, nid(dave));
        assertEq(d.validBits(), GovernanceBits.DEX_BITS);
    }

    /// §4.5 and the liquidity spec §9.1 (L33): the DEX's constructor takes exactly two modules with code, the governance
    /// module (group 10) then the liquidity module (group 11), each for its own factory.
    function test_d_constructorChecksD() public {
        (address d, address l) = (dex.modules()[0], dex.modules()[1]);
        assertEq(ITokenModule(l).moduleGroup(), 11);
        new SCaaSDex(address(f), _two(d, l)); // control
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMissing.selector, 0));
        new SCaaSDex(address(f), abi.encode(ImplArgs(new address[](0))));
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMissing.selector, 1));
        new SCaaSDex(address(f), _one(d)); // one module
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMismatch.selector, 1));
        new SCaaSDex(address(f), _two(d, d)); // the second of group 10
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMissing.selector, 1));
        new SCaaSDex(address(f), _two(d, address(0xD0D0)));
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMissing.selector, 0));
        new SCaaSDex(address(f), _two(address(0xD0D0), l));
        address p = A.modules()[0]; // a token's module P: another group
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMismatch.selector, 0));
        new SCaaSDex(address(f), _two(p, l));
        (address[] memory other,) = deployDexModules(address(0xF00)); // modules of another factory
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMismatch.selector, 0));
        new SCaaSDex(address(f), _two(other[0], l));
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMismatch.selector, 1));
        new SCaaSDex(address(f), _two(d, other[1]));
    }
}
