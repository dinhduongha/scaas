// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {deployDexModules} from "../../script/KindModules.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {SCaaSDexD} from "../../src/dex/SCaaSDexAdmin.sol";
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

    /// The DEX's governance views and writes run in D (one DELEGATECALL each), with the DEX's state.
    function test_d_governanceRunsInD() public {
        address d = dex.modules()[0];
        assertEq(dex.modules().length, 1);
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
        SCaaSDexD d = SCaaSDexD(dex.modules()[0]);
        vm.expectRevert(SCaaSDexD.NotDelegated.selector);
        d.owner();
        vm.expectRevert(SCaaSDexD.NotDelegated.selector);
        d.features();
        vm.expectRevert(SCaaSDexD.NotDelegated.selector);
        d.transferOwnership(nid(dave));
        vm.expectRevert(SCaaSDexD.NotDelegated.selector);
        d.grantRole(GovernanceBits.LISTING, nid(dave));
        assertEq(d.validBits(), GovernanceBits.DEX_BITS);
    }

    /// §4.5: the DEX's constructor takes exactly one module with code, of group D, for its own factory.
    function test_d_constructorChecksD() public {
        address d = dex.modules()[0];
        new SCaaSDex(address(f), _one(d)); // control
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMissing.selector, 0));
        new SCaaSDex(address(f), abi.encode(ImplArgs(new address[](0))));
        address[] memory two = new address[](2);
        (two[0], two[1]) = (d, d);
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMissing.selector, 2));
        new SCaaSDex(address(f), abi.encode(ImplArgs(two)));
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMissing.selector, 0));
        new SCaaSDex(address(f), _one(address(0xD0D0)));
        bytes memory p = _one(A.modules()[0]); // a token's module P: another group
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMismatch.selector, 0));
        new SCaaSDex(address(f), p);
        (address[] memory other,) = deployDexModules(address(0xF00)); // a D of another factory
        p = _one(other[0]);
        vm.expectRevert(abi.encodeWithSelector(SCaaSDex.ModuleMismatch.selector, 0));
        new SCaaSDex(address(f), p);
    }
}
