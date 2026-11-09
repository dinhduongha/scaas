// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {V2Fixture} from "../v2/helpers/V2Fixture.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";

/// Calls one token twice in one transaction.
contract Twice {
    function burnTwice(NormalToken t) external {
        t.burn(1);
        t.burn(1);
    }
}

/// T66b §10, §8 path tests: the guard of a forwarded entry is released before it returns (two calls into one token in one
/// transaction); a relayed op through P runs an entry of module A by the self-call ticket; a payable entry takes value
/// through its stub into W (M4); `implementation()` on the implementation, a clone and a module.
contract PathsTest is V2Fixture {
    uint256 internal constant PK = 0xA11CE;
    address internal holder;
    NormalToken internal n;

    function setUp() public {
        holder = vm.addr(PK);
        n = _normal(holder, 1e18, address(0));
    }

    function test_p_twoCallsAfterAForwardedEntry() public {
        Twice c = new Twice();
        vm.prank(holder);
        n.transfer(address(c), 10);
        vm.expectCall(n.modules()[2], abi.encodeCall(n.burn, (1)), 2); // `burn` runs in A (kinds 0-5)
        c.burnTwice(n);
        assertEq(n.balanceOf(address(c)), 8);
    }

    function test_p_relayedOpIntoModuleA() public {
        bytes memory op = abi.encodeCall(n.burn, (5));
        vm.expectCall(n.modules()[0], abi.encodeWithSelector(n.executeMetaTransaction.selector)); // the pipeline in P
        vm.expectCall(n.modules()[2], op); // the op in A, by the self-call
        assertTrue(_execCall(PK, address(n), _call(holder, op, 1, RR)));
        assertEq(n.balanceOf(holder), 1e18 - 5);
    }

    function test_p_payableEntryTakesValue() public {
        WrappedToken w = _single(address(0), 18, 1, 1, _fixedRate()); // a native leg
        vm.deal(holder, 3 ether);
        // under DELEGATECALL the module sees the stub's `msg.value`: a non-payable module entry would revert on it (M4)
        vm.expectCall(w.modules()[3], abi.encodeWithSignature("wrap(address,uint256)", address(0), 1 ether));
        vm.prank(holder);
        w.wrap{value: 1 ether}(address(0), 1 ether);
        vm.prank(holder);
        w.wrap{value: 2 ether}(2 ether); // the single-leg form
        assertEq(w.balanceOf(holder), 3 ether);
        assertEq(address(w).balance, 3 ether);
    }

    function test_p_implementationEverywhere() public view {
        address impl = normalImpl;
        assertEq(n.implementation(), impl, "a clone");
        assertEq(NormalToken(impl).implementation(), impl, "the implementation");
        address a = n.modules()[2];
        assertEq(NormalToken(a).implementation(), a, "a module answers its own address (M8: no body reads it)");
    }
}
