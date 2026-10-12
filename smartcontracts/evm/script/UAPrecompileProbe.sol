// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Bls12381} from "../src/common/Bls12381.sol";
import {CurveSigs} from "../src/common/CurveSigs.sol";
import {UAKinds} from "../src/ua/UAKinds.sol";
import {G1Bn254, G1Bls12381} from "../src/zether/ZetherCurves.sol";

/// @title Deploy-time probe of the BLS12-381 / bn254 precompiles the UA registry's curve kinds need (accounts.md §1.9 per-chain
///        enablement; the UA-2 carry-overs: 0x0c / 0x0e / 0x08 refuse the points outside the subgroup, prices fit).
/// @notice Runs in its constructor and returns `abi.encode(bool bls12381, bool bn254G2)` as its code, so `DeployBase`
///         asks the **chain's own** precompiles through an `eth_call` with no `to` (a forge script runs precompiles in
///         its local EVM) and a test reads `address(new UAPrecompileProbe()).code`. Every call is capped: success under
///         the cap proves the price fits; a failing precompile burns only the cap; an absent precompile (an empty
///         account: success, no data) fails the returndata comparison.
///         - `bls12381` (EIP-2537; kinds 0x0105, 0x0106, 0x0141): G1MSM / G2MSM with k = 1 return the point under the
///           registry's key-check caps (`UAKinds.G1MSM_GAS` / `G2MSM_GAS`) and refuse kinds.json's points outside the
///           subgroup; a k = 2 PAIRING_CHECK returns 1 within its EIP-2537 price (102,900), the price the verifier caps
///           were measured at; G1ADD (0x0b, g1 + O = g1, 375) and MAP_FP_TO_G1 (0x10, 128 bytes for 0, 5,500), which
///           `bls12381-minsig` uses besides MSM / pairing, answer within their EIP-2537 prices.
///         - `bn254G2` (0x08; kind 0x0107): the registry's G2 check (the G1 generator and the key, `UAKinds.PAIRING_GAS`)
///           answers 32 bytes for the G2 generator and refuses kinds.json's G2 point outside the subgroup; a k = 2
///           pairing returns 1 within its EIP-1108 price (113,000).
contract UAPrecompileProbe {
    /// kinds.json `invalid`, kind 0x0141 "outside the subgroup" (G1, 128 bytes).
    bytes internal constant G1_OUTSIDE =
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000000000000000000000000000000000004"
        hex"000000000000000000000000000000000a989badd40d6212b33cffc3f3763e9b"
        hex"c760f988c9926b26da9dd85e928483446346b8ed00e1de5d5ea93e354abe706c";
    /// kinds.json `invalid`, kind 0x0106 "outside the subgroup" (G2, 256 bytes).
    bytes internal constant G2_OUTSIDE =
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000000000000000000000000000000000002"
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000018c6b864ae17dc9da64203ffefb96630"
        hex"6425a7bc6aeb7c75247438372716284a4173830420cd476ba1a365b95bfcec38"
        hex"00000000000000000000000000000000172e93db764a8400a7d5071b6b6f5de0"
        hex"da2f0f4a063119abca014006b7c40a2cfe291a1924e65db0d6d0fcfbf3bf3d5c";
    /// kinds.json `invalid`, kind 0x0107 "outside the subgroup" (bn254 G2, 128 bytes, EIP-197 order).
    bytes internal constant BN_G2_OUTSIDE =
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000000000000000000000000000000000001"
        hex"2351dcdda257b62181cbd745dfee16d5fdf4eb185bbcf33c20a0fe6eaa9cb4a3"
        hex"07fb3d558dafafb6bf6dd326a5fefe0beca3f9ac3bd999a390d504fad34b0b8c";

    uint256 internal constant BLS_PAIRING_2_GAS = 37_700 + 2 * 32_600; // EIP-2537
    uint256 internal constant BN_PAIRING_2_GAS = 45_000 + 2 * 34_000; // EIP-1108

    constructor() {
        bytes memory out = abi.encode(bls12381(), bn254G2());
        assembly ("memory-safe") {
            return(add(out, 32), mload(out))
        }
    }

    function bls12381() internal view returns (bool) {
        bytes memory g1 = G1Bls12381.generator();
        bytes memory g2 = Bls12381.NEG_G2_GENERATOR;
        return _returns(address(0x0c), abi.encodePacked(g1, uint256(1)), UAKinds.G1MSM_GAS, g1)
            && !_answers(address(0x0c), abi.encodePacked(G1_OUTSIDE, uint256(1)), UAKinds.G1MSM_GAS, 128)
            && _returns(address(0x0e), abi.encodePacked(g2, uint256(1)), UAKinds.G2MSM_GAS, g2)
            && !_answers(address(0x0e), abi.encodePacked(G2_OUTSIDE, uint256(1)), UAKinds.G2MSM_GAS, 256)
            && _returns(
                address(0x0f), bytes.concat(g1, g2, G1Bls12381.neg(g1), g2), BLS_PAIRING_2_GAS, abi.encode(uint256(1))
            ) && _returns(address(0x0b), bytes.concat(g1, new bytes(128)), 375, g1) // G1ADD: g1 + O = g1 (EIP-2537 price)
            && _answers(address(0x10), new bytes(64), 5_500, 128); // MAP_FP_TO_G1(0) (EIP-2537 price)
    }

    function bn254G2() internal view returns (bool) {
        bytes memory g1 = G1Bn254.generator();
        bytes memory g2 = CurveSigs.BN254_G2;
        return _answers(address(0x08), bytes.concat(g1, g2), UAKinds.PAIRING_GAS, 32)
            && !_answers(address(0x08), bytes.concat(g1, BN_G2_OUTSIDE), UAKinds.PAIRING_GAS, 32)
            && _returns(address(0x08), bytes.concat(g1, g2, G1Bn254.neg(g1), g2), BN_PAIRING_2_GAS, abi.encode(uint256(1)));
    }

    /// Succeeds within `cap` and returns exactly `want`.
    function _returns(address p, bytes memory input, uint256 cap, bytes memory want) private view returns (bool) {
        (bool ok, bytes memory out) = p.staticcall{gas: cap}(input);
        return ok && keccak256(out) == keccak256(want);
    }

    /// Succeeds within `cap` with `len` bytes of output (the registry's own acceptance rule).
    function _answers(address p, bytes memory input, uint256 cap, uint256 len) private view returns (bool) {
        (bool ok, bytes memory out) = p.staticcall{gas: cap}(input);
        return ok && out.length == len;
    }
}
