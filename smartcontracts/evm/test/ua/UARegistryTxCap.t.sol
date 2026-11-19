// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";

/// Owner X1 (spec 2026-11-19-registry-verify-only-kinds §2, §9): the registry takes the chain's per-transaction gas cap as an
/// immutable constructor argument, `verifyBudget ≤ txGasCap` (owner P17), and the deploy reads it from `TX_GAS_CAP`, required.
/// The bounds that read it: `UARegistryMsigUpdate.t.sol` `test_msigBound_readsTxGasCap`, `UARegistryPqzBound.t.sol`
/// `test_msigDebit_readsTxGasCap`.
contract UARegistryTxCapTest is UARegistryBase {
    function _at(address where, uint64 budget, uint64 cap) internal returns (UARegistry) {
        txCap = cap;
        return _deploy(where, chainUidA, address(0), false, budget, address(0), true, _cfgs(address(mock)));
    }

    function test_txGasCap_view() public {
        assertEq(_at(address(0x7c01), BUDGET, 1 << 24).txGasCap(), 1 << 24);
        assertEq(_at(address(0x7c02), BUDGET, 30_000_000).txGasCap(), 30_000_000);
        assertEq(_at(address(0x7c03), BUDGET, BUDGET).txGasCap(), BUDGET, "equal to the budget: accepted");
    }

    /// P17: `verifyBudget` 12 M against a `txGasCap` of 11 M is `UAConfig(0)`; one gas below the budget too.
    function test_txGasCap_belowBudget_UAConfig0() public {
        UARegistry.KindConfig[] memory c = _cfgs(address(mock));
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(chainUidA, address(0), false, 12_000_000, 11_000_000, address(0), true, c);
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(chainUidA, address(0), false, 12_000_000, 12_000_000 - 1, address(0), true, c);
        new UARegistry(chainUidA, address(0), false, 12_000_000, 12_000_000, address(0), true, c); // the control
    }

    /// `TX_GAS_CAP` is required, no default: unset, the deploy's read reverts (the process env carries none in tests).
    function test_deploy_txGasCapRequired() public {
        DeployHarness h = new DeployHarness();
        vm.expectRevert();
        h.txGasCapEnv();
    }

    /// `_deployUARegistry` refuses a cap of 0 by name (a script that skipped `_setup`).
    function test_deploy_txGasCapZero_refused() public {
        DeployHarness h = new DeployHarness();
        h.setTxGasCap(0);
        vm.expectRevert(bytes("TX_GAS_CAP: the chain's per-transaction gas cap from the deploy book (owner X1)"));
        h.deploy(chainUidA, false, address(0), false);
    }
}
