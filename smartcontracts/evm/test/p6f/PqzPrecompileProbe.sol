// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @notice P6f (plan R5): test-only probe for the PQZ / ML-DSA precompiles on the copy and on 7622 — never in src/.
/// `call` measures one STATICCALL with all gas: `gasUsed` = gasleft() before − after (the call's own cost, 100 warm,
/// plus the precompile's gas, plus a constant few gas of stack work that `probe.sh` measures on the identity
/// precompile), `rlen` = returndatasize, `word` = the 32-byte answer, or type(uint256).max if the call failed.
contract PqzPrecompileProbe {
    event Probed(address indexed target, bytes32 inputHash, uint256 word, uint256 gasUsed, uint256 rlen);

    function call(address target, bytes calldata input) public view returns (uint256 word, uint256 gasUsed, uint256 rlen) {
        bytes memory m = input;
        assembly ("memory-safe") {
            let p := add(m, 32)
            let n := mload(m)
            let g0 := gas()
            let ok := staticcall(gas(), target, p, n, 0, 0)
            let g1 := gas()
            gasUsed := sub(g0, g1)
            rlen := returndatasize()
            word := not(0)
            if ok {
                word := 0
                if iszero(lt(rlen, 32)) {
                    returndatacopy(0, 0, 32)
                    word := mload(0)
                }
            }
        }
    }

    /// The same as a transaction: the result goes into the event (e2e).
    function check(address target, bytes calldata input) external returns (uint256 word, uint256 gasUsed, uint256 rlen) {
        (word, gasUsed, rlen) = call(target, input);
        emit Probed(target, keccak256(input), word, gasUsed, rlen);
    }
}
