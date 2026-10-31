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
///         the registry's caps) gates the EIP-2537 kinds (`zether-bls12381` among them, on every chain: owner ruling 2026-10-31)
///         and `bls-bn254-minsig`.
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
        uint256[3] memory rows = [uint256(79), 85, 90];
        for (uint256 i; i < 3; ++i) {
            string memory row = string.concat(".invalid[", vm.toString(rows[i]), "]");
            assertEq(vm.parseJsonString(j, string.concat(row, ".reason")), "outside the subgroup");
            string memory kd = vm.toString(vm.parseJsonBytes(j, string.concat(row, ".keyData")));
            assertTrue(vm.indexOf(code, vm.replace(kd, "0x", "")) != type(uint256).max, "probe carries the row");
        }
    }

    /// Dev chain 31337: every kind this registry code has, `zether-bls12381` included (`zether-bn254` is in
    /// `legacy/ua6/`, UA-6 U10); budget 12 M; msig on.
    function test_devChain() public {
        IUARegistry reg = _registry(31337, false);
        bool[5] memory on = _kinds(reg, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(on[0] && on[1] && on[2] && !on[3] && on[4]);
        assertEq(reg.verifyBudget(), 12_000_000);
        assertEq(reg.chainUid(), UID);
        assertEq(reg.generation(), 1);
        assertEq(reg.verifyCap(UAKinds.ED25519), 210_000);
        assertEq(reg.verifyCap(UAKinds.ZETHER_BLS12381), 70_000);
        assertFalse(reg.kindEnabled(UAKinds.PQZ_MLWE));
        _pq(reg, true);
    }

    /// P6c: the PQ signing kinds with the gen-1 caps (each ≤ 50 % of the budget) on the private chains, none elsewhere;
    /// the ML-DSA verifiers in Solidity (the registry's expanded-key cache).
    function _pq(IUARegistry reg, bool on) internal view {
        uint64[4] memory caps = [uint64(4_250_000), 5_950_000, 2_500_000, 1_400_000];
        for (uint16 k = UAKinds.MLDSA44; k <= UAKinds.SLHDSA128S; ++k) {
            assertEq(reg.kindEnabled(k), on);
            assertEq(reg.verifyCap(k), on ? caps[k - UAKinds.MLDSA44] : 0);
            assertLe(reg.verifyCap(k), reg.verifyBudget() / 2);
        }
    }

    /// Chain 7622 (private, not dev): `zether-bls12381` (owner ruling 2026-10-31), `bls-bn254-minsig` and the PQ kinds.
    /// Another chain (the e2e's 31901): `zether-bls12381`, no `bls-bn254-minsig`, no PQ kind. Hedera 298: `hederaNative`,
    /// budget 10.5 M, no PQ kind.
    function test_otherChains() public {
        IUARegistry r7622 = _registry(7622, false);
        bool[5] memory on = _kinds(r7622, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(on[0] && on[1] && on[2] && !on[3] && on[4]);
        _pq(r7622, true);
        assertFalse(r7622.kindEnabled(UAKinds.PQZ_MLWE));
        IUARegistry r31901 = _registry(31901, false);
        on = _kinds(r31901, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(on[0] && on[1] && !on[2] && !on[3] && on[4]);
        _pq(r31901, false);
        IUARegistry h = _registry(298, true);
        assertTrue(h.hederaNative());
        assertEq(h.verifyBudget(), 10_500_000);
        _pq(h, false);
    }

    /// A chain whose precompiles fail the probe gets none of the kinds that need them (never registrable but unusable).
    function test_probeFailureDisables() public {
        vm.chainId(31337);
        DeployHarness h = new DeployHarness();
        h.force(false, false);
        (, string memory json) = h.deploy(UID, true, ska, false);
        IUARegistry reg = IUARegistry(vm.parseJsonAddress(json, ".ua_registry"));
        bool[5] memory on = _kinds(reg, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(!on[0] && !on[1] && !on[2] && !on[3] && !on[4], "none of these");
    }

    /// C5-1 (NET-EVM-06): a release deploys only where the chain's block gas limit covers its state gas (1,530 per byte
    /// of runtime, size-baseline.json) plus the 2^24 regular-gas cap; the deploy refuses before sending otherwise.
    function test_C5_1_releaseNeedsABlockGasLimit() public {
        DeployHarness h = new DeployHarness();
        string memory base = vm.readFile("./size-baseline.json");
        uint256 plain = vm.parseJsonUint(base, ".NormalToken") * 1530 + 16_777_216;
        uint256 conf = vm.parseJsonUint(base, ".WrappedPqzToken") * 1530 + 16_777_216;
        assertEq(h.gasNeed("NormalToken"), plain);
        assertEq(h.gasNeed("WrappedPqzToken"), conf);
        assertLt(plain, 80_000_000, "plain kinds: about 75 M");
        assertGt(conf, 100_000_000, "confidential kinds: about 110 M");
        assertLt(conf, 120_000_000);
        // a contract over the EIP-170 limit is priced at its baseline size (SCaaSDex since the DEX round)
        assertEq(h.gasNeed("SCaaSDex"), vm.parseJsonUint(base, ".SCaaSDex") * 1530 + 16_777_216);
        // a contract under the EIP-170 limit is not in the baseline: priced at 24,576 B
        assertFalse(vm.keyExistsJson(base, ".UniswapExecutor"));
        assertEq(h.gasNeed("UniswapExecutor"), uint256(24_576) * 1530 + 16_777_216);
        // an Ethereum-like 60 M block cannot hold any confidential release
        vm.expectRevert(bytes(string.concat("block gas limit 60000000 < ", vm.toString(conf),
            " needed to deploy the WrappedPqzToken release (NET-EVM-06)")));
        h.checkGas("WrappedPqzToken", 60_000_000);
        h.checkGas("WrappedPqzToken", conf);
        // the gate reads the chain's block gas limit
        if (block.gaslimit < conf) vm.expectRevert();
        h.requireGas("WrappedPqzToken");
    }
}
