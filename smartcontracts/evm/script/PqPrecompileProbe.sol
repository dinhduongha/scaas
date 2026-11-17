// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzSafety} from "../src/pqz/PqzSafety.sol";
import {PqUA} from "../src/ua/PqUA.sol";

/// @title Deploy-time probe of the chain's PQ precompiles the gen-1 registry's `pqz-mlwe` 0x0142 and ML-DSA kinds 0x0130 /
///        0x0131 / 0x0134 need (owner 2026-11-15, the gen-1 kind gate of `DeployBase._checkGen1Kinds` and `_mldsaVerifier`).
/// @notice Runs in its constructor and returns `abi.encode(bool pqz, bool mldsa44, bool mldsa65, bool mldsa87)` as its code, so
///         `DeployBase` asks the **chain's own** precompiles through an `eth_call` with no `to`, as `UAPrecompileProbe`:
///         `pqz` = the `PQZ` precompile's self-test (`PqzSafety.selfTest`, the set's `OP_SELFTEST` hash); `mldsa<x>` = an
///         ML-DSA precompile answers that level's KAT probe exactly (`PqUA.probe`: valid ⇒ the word 1, flipped ⇒ 0) at its
///         EIP-8355 address (`0x12` / `0x13` / `0x14`) or at the SCaaS testnet's `0x…5caa0012` / `…0013` / `…0014`
///         (`DeployBase._mldsaCandidates`). UNAUDITED.
contract PqPrecompileProbe {
    constructor(bytes memory v44, bytes memory i44, bytes memory v65, bytes memory i65, bytes memory v87, bytes memory i87) {
        bytes memory out = abi.encode(PqzSafety.selfTest(PqzSafety.PQZ), _ml(0, v44, i44), _ml(1, v65, i65), _ml(2, v87, i87));
        assembly ("memory-safe") {
            return(add(out, 32), mload(out))
        }
    }

    function _ml(uint256 i, bytes memory valid, bytes memory invalid) private view returns (bool) {
        return PqUA.probe(address(uint160(0x12 + i)), valid, invalid)
            || PqUA.probe(address(uint160(0x5caa0012 + i)), valid, invalid);
    }
}
