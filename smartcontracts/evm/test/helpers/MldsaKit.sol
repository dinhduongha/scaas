// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {MldsaVerifier} from "../../src/ua/MlDsa.sol";

/// Round 3zh (owner 2026-11-15, F-6): an `MldsaVerifier` on a precompile as `script/pq_verifiers.py` builds it on a chain — by
/// CREATE2 through the deterministic deployer with the deploy salt, `pq_kat.json`'s EIP-8355 probe, the candidate answering
/// it (mocked here: forge's EVM has no ML-DSA precompile) — the only form `DeployBase` takes by `MLDSA<x>_VERIFIER`.
library MldsaKit {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// Kind `i` (0, 1, 2 = 44, 65, 87) on precompile `pc` with `salt` (`DEPLOY_SALT`).
    function onChain(uint256 i, address pc, bytes32 salt) internal returns (address v) {
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        string memory k = string.concat(".kinds.mldsa", ["44", "65", "87"][i]);
        bytes memory valid = vm.parseJsonBytes(kat, string.concat(k, ".eip8355_probe_valid"));
        bytes memory invalid = vm.parseJsonBytes(kat, string.concat(k, ".eip8355_probe_invalid"));
        vm.mockCall(pc, valid, abi.encode(uint256(1)));
        vm.mockCall(pc, invalid, abi.encode(uint256(0)));
        bytes memory init = abi.encodePacked(type(MldsaVerifier).creationCode,
            abi.encode([uint16(0x0130), 0x0131, 0x0134][i], pc, valid, invalid));
        v = vm.computeCreate2Address(salt, keccak256(init), DEPLOYER);
        if (v.code.length == 0) {
            (bool ok,) = DEPLOYER.call(bytes.concat(salt, init));
            require(ok && v.code.length != 0, "MldsaKit: CREATE2");
        }
        vm.clearMockedCalls();
        require(MldsaVerifier(v).PRECOMPILE() == pc, "MldsaKit: the probe did not pass");
    }
}
