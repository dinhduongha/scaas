// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzSafety} from "../src/pqz/PqzSafety.sol";
import {PqUA} from "../src/ua/PqUA.sol";

/// @title Deploy-time probe of the chain's PQ precompiles the gen-1 registry's `pqz-mlwe` 0x0142 and `mldsa87` 0x0134 need
///        (owner 2026-11-15, the gen-1 kind gate of `DeployBase._checkGen1Kinds`).
/// @notice Runs in its constructor and returns `abi.encode(bool pqz, bool mldsa87)` as its code, so `DeployBase` asks the
///         **chain's own** precompiles through an `eth_call` with no `to`, as `UAPrecompileProbe`: `pqz` = the `PQZ`
///         precompile's self-test (`PqzSafety.selfTest`, the set's `OP_SELFTEST` hash); `mldsa87` = an ML-DSA-87
///         precompile answers the KAT probe exactly (`PqUA.probe`: valid ⇒ the word 1, flipped ⇒ 0) at `0x14` (EIP-8355)
///         or at the SCaaS testnet's `0x…5caa0014` (`DeployBase._mldsa87Precompile`'s candidates). UNAUDITED.
contract PqPrecompileProbe {
    constructor(bytes memory valid87, bytes memory invalid87) {
        bool ml87 = PqUA.probe(address(0x14), valid87, invalid87)
            || PqUA.probe(0x000000000000000000000000000000005caA0014, valid87, invalid87);
        bytes memory out = abi.encode(PqzSafety.selfTest(PqzSafety.PQZ), ml87);
        assembly ("memory-safe") {
            return(add(out, 32), mload(out))
        }
    }
}
