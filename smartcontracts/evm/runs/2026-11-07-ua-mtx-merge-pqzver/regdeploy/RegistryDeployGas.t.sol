// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {UARegistry} from "../../../src/ua/UARegistry.sol";
import {UARegistryLib} from "../../../src/ua/UARegistryLib.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";

/// A verifier stand-in: code, nothing else (the constructor checks only that a verifier has code).
contract VerifierStandIn {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bool) {
        return false;
    }
}

contract RegCreate2Probe {
    function deploy(bytes calldata code, bytes32 salt) external returns (address a) {
        bytes memory c = code;
        assembly ("memory-safe") { a := create2(0, add(c, 32), mload(c), salt) }
    }
}

/// @notice ua-mtx-merge T51 (group 3g, spec §6.2): the deploy gas of `UARegistryLib` and `UARegistry` by T10's public-gate
///         formula, each its own CREATE2 transaction through a probe: regular = `lastCallGas.gasTotalUsed` x 64/63, state =
///         EIP-8037's, asked = (regular + state) x 1.05, against 57 M / 60 M and regular x 1.05 < 2^24. `UARegistry` with
///         DeployBase's gen-1 kind list on an Amsterdam chain without an ML-DSA-87 precompile (19 kinds, verifier stand-ins,
///         budget 12 M). Run by `measure.sh` (FOUNDRY_TEST = this directory); the same file on the old and the new tree.
contract RegistryDeployGasTest is Test {
    function _line(string memory name, bytes memory code, address a, Vm.Gas memory g) internal {
        uint256 regular = g.gasTotalUsed * 64 / 63;
        uint256 state = uint256(int256(g.gasStateUsed));
        uint256 asked = (regular + state) * 105 / 100;
        emit log(string.concat("REGDEPLOY | ", name, " | runtime ", vm.toString(a.code.length), " | init ",
            vm.toString(code.length), " | regular ", vm.toString(regular), " | state ", vm.toString(state), " | asked ",
            vm.toString(asked), " | 57M ", asked <= 57_000_000 ? "fits" : "NO", " | 60M ", asked <= 60_000_000 ? "fits" : "NO",
            " | reg105<2^24 ", regular * 105 / 100 < 1 << 24 ? "yes" : "NO"));
    }

    function test_registryDeployGas() public {
        RegCreate2Probe probe = new RegCreate2Probe();
        bytes memory lib = type(UARegistryLib).creationCode;
        address l = probe.deploy(lib, bytes32(uint256(1)));
        Vm.Gas memory g = vm.lastCallGas();
        assertTrue(l != address(0));
        _line("UARegistryLib", lib, l, g);
        address v = address(new VerifierStandIn());
        uint16[19] memory kinds = [UAKinds.WEBAUTHN_P256, UAKinds.P256, UAKinds.ED25519, UAKinds.BIP340, UAKinds.SECP256K1,
            UAKinds.SCHNORR_BN254, UAKinds.SCHNORR_BLS12381, UAKinds.BLS12381_MINSIG, UAKinds.BLS_BN254_MINSIG,
            UAKinds.MUSIG2_SECP256K1, UAKinds.FROST_SECP256K1, UAKinds.MUSIG2_BN254, UAKinds.FROST_BN254,
            UAKinds.ZETHER_BLS12381, UAKinds.MLDSA44, UAKinds.MLDSA65, UAKinds.FNDSA512, UAKinds.SLHDSA128S, UAKinds.FNDSA1024];
        uint64[19] memory caps = [uint64(400_000), 400_000, 210_000, 50_000, 50_000, 50_000, 70_000, 200_000, 345_000, 50_000,
            50_000, 50_000, 50_000, 70_000, 4_250_000, 5_950_000, 2_500_000, 1_400_000, 5_250_000];
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](19);
        for (uint256 i; i < 19; ++i) k[i] = UARegistry.KindConfig(kinds[i], v, caps[i]);
        bytes memory init = abi.encodePacked(type(UARegistry).creationCode,
            abi.encode(keccak256("scaas-testnet"), address(0), false, uint64(12_000_000), address(0), true, k));
        address r = probe.deploy(init, bytes32(uint256(2)));
        g = vm.lastCallGas();
        assertTrue(r != address(0));
        _line("UARegistry", init, r, g);
    }
}
