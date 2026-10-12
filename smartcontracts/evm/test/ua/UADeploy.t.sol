// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {UAPrecompileProbe} from "../../script/UAPrecompileProbe.sol";
import {Bls12381} from "../../src/common/Bls12381.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";

/// @notice `DeployBase` deploys UA registry generation 1 on every chain (CTR-UA-22) with the per-chain kind set of
///         accounts.md §1.9: the precompile probe (`UAPrecompileProbe`: the kinds.json points outside the subgroup,
///         the registry's caps) gates the EIP-2537 kinds and `bls-bn254-minsig`; the Zether kinds stay on the dev chains.
contract UADeployTest is Test {
    bytes32 constant UID = keccak256("scaas.ua3.deploy");
    uint16[12] internal EVERYWHERE = [0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0110, 0x0111, 0x0112, 0x0113, 0x0120, 0, 0];
    address ska = new SmartKeyAccountFactory(UID).IMPLEMENTATION();

    function _registry(uint256 chainId, bool hedera) internal returns (IUARegistry reg) {
        vm.chainId(chainId);
        DeployHarness h = new DeployHarness();
        (, string memory json) = h.deploy(UID, false, ska, hedera);
        reg = IUARegistry(vm.parseJsonAddress(json, ".ua_registry"));
    }

    function _kinds(IUARegistry reg, uint16[5] memory optional) internal view returns (bool[5] memory on) {
        for (uint256 i; i < 10; ++i) {
            assertTrue(reg.kindEnabled(EVERYWHERE[i]), "a kind every chain enables");
        }
        for (uint256 i; i < 5; ++i) {
            on[i] = reg.kindEnabled(optional[i]);
        }
    }

    /// Osaka has EIP-2537 and EIP-197: the probe passes both; under an EVM without EIP-2537 (`FOUNDRY_EVM_VERSION=cancun`)
    /// it reports `bls12381 = false`, as the registry's `Bls12381.isSupported` does. Its points are kinds.json's.
    function test_probe() public {
        (bool bls, bool bn) = abi.decode(address(new UAPrecompileProbe()).code, (bool, bool));
        assertEq(bls, Bls12381.isSupported());
        assertTrue(bn);
        string memory code = vm.toString(type(UAPrecompileProbe).creationCode);
        string memory j = vm.readFile("../vectors/ua/kinds.json");
        uint256[3] memory rows = [uint256(88), 94, 99];
        for (uint256 i; i < 3; ++i) {
            string memory row = string.concat(".invalid[", vm.toString(rows[i]), "]");
            assertEq(vm.parseJsonString(j, string.concat(row, ".reason")), "outside the subgroup");
            string memory kd = vm.toString(vm.parseJsonBytes(j, string.concat(row, ".keyData")));
            assertTrue(vm.indexOf(code, vm.replace(kd, "0x", "")) != type(uint256).max, "probe carries the row");
        }
    }

    /// Dev chain 31337: every kind this registry code has, the Zether ones included; budget 12 M; msig on.
    function test_devChain() public {
        IUARegistry reg = _registry(31337, false);
        bool[5] memory on = _kinds(reg, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        for (uint256 i; i < 5; ++i) assertTrue(on[i]);
        assertEq(reg.verifyBudget(), 12_000_000);
        assertEq(reg.chainUid(), UID);
        assertEq(reg.generation(), 1);
        assertEq(reg.verifyCap(UAKinds.ED25519), 210_000);
        assertEq(reg.verifyCap(UAKinds.ZETHER_BLS12381), 70_000);
        assertFalse(reg.kindEnabled(UAKinds.PQZ_MLWE));
    }

    /// Chain 7622 (private, not dev): no Zether kind; `bls-bn254-minsig` stays. Another chain (the e2e's 31901): no
    /// `bls-bn254-minsig` either. Hedera 298: `hederaNative`, budget 10.5 M.
    function test_otherChains() public {
        bool[5] memory on = _kinds(_registry(7622, false), [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(on[0] && on[1] && on[2] && !on[3] && !on[4]);
        on = _kinds(_registry(31901, false), [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(on[0] && on[1] && !on[2] && !on[3] && !on[4]);
        IUARegistry h = _registry(298, true);
        assertTrue(h.hederaNative());
        assertEq(h.verifyBudget(), 10_500_000);
    }

    /// A chain whose precompiles fail the probe gets none of the kinds that need them (never registrable but unusable).
    function test_probeFailureDisables() public {
        vm.chainId(31337);
        DeployHarness h = new DeployHarness();
        h.force(false, false);
        (, string memory json) = h.deploy(UID, true, ska, false);
        IUARegistry reg = IUARegistry(vm.parseJsonAddress(json, ".ua_registry"));
        bool[5] memory on = _kinds(reg, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(!on[0] && !on[1] && !on[2] && on[3] && !on[4], "only zether-bn254 of these");
    }
}
