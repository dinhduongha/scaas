// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";
import {UALedgerBase} from "./UALedgerBase.sol";

/// Exposes `_uaMint` (accounts.md CTR-UA-28).
contract UAMintHarness is NoUnderlyingToken {
    constructor(bytes32 uid, address reg) NoUnderlyingToken(msg.sender, address(0), uid, reg, false) {}

    function mintUA(bytes32 to, uint256 v) external {
        _uaMint(to, v);
    }
}

/// accounts.md CTR-UA-28: a native caller credits a derived UA in one call; a mint into a UA is a UA-ledger move from 0.
contract UAReceiversTest is UALedgerBase {
    UAMintHarness internal hm;

    function setUp() public override {
        super.setUp();
        hm = _harness(REG_L);
    }

    function _harness(address registry_) internal returns (UAMintHarness h) {
        h = UAMintHarness(Clones.clone(address(new UAMintHarness(chainUidA, registry_))));
        h.initialize(address(this), 1, noneInit("H", "H", 6, 0, address(0), address(this)));
    }

    // ----- _uaMint -----

    function test_uaMint_eventsAndTotals() public {
        vm.expectEmit(address(hm));
        emit IERC20.Transfer(address(0), POOL, 700);
        vm.expectEmit(address(hm));
        emit IUALedger.UATransfer(bytes32(0), uaP, 700);
        hm.mintUA(uaP, 700);
        assertEq(hm.totalSupply(), 700);
        assertEq(hm.balanceOf(POOL), 700);
        assertEq(hm.balanceOfUA(uaP), 700);
    }

    function test_uaMint_refusesNativeUnregisteredZether() public {
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, _pad(bob)));
        hm.mintUA(_pad(bob), 1);
        bytes32 unknown = keccak256("unregistered");
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, unknown));
        hm.mintUA(unknown, 1);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UAKindNotAccepted.selector, uaZ, UAKinds.ZETHER_BN254));
        hm.mintUA(uaZ, 1);
        assertEq(hm.totalSupply(), 0);
    }

    function test_uaMint_ledgerOff() public {
        UAMintHarness off = _harness(address(0));
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.mintUA(uaP, 1);
    }
}
