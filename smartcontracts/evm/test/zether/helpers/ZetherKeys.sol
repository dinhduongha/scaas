// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {G1Bn254, G1Bls12381} from "../../../src/zether/ZetherCurves.sol";
import {ZetherTranscript} from "../../../src/zether/ZetherTranscript.sol";

/// @notice Ký Schnorr §11.1 phía test (nonce tất định từ `x‖m` — chỉ test). `schnorr` under the Zether tag (Zether
///         UAs, accounts.md §1.9), `sign` under any tag (`"scaas.ua.schnorr.v1"`: a `schnorr-*` UA).
library ZetherKeys {
    function pub(uint256 x, bool bls) internal view returns (bytes memory) {
        return bls ? G1Bls12381.mulBase(x) : G1Bn254.mulBase(x);
    }

    function schnorr(uint256 x, bytes32 m, bool bls) internal view returns (bytes memory) {
        return sign("SCAAS-ZETHER-SCHNORR-V1", x, m, bls);
    }

    function sign(bytes memory tag, uint256 x, bytes32 m, bool bls) internal view returns (bytes memory) {
        uint256 r = bls ? G1Bls12381.R : G1Bn254.R;
        uint256 k = ZetherTranscript.hashToScalar(keccak256(abi.encode("test-nonce", x, m)), r);
        bytes memory y = pub(x, bls);
        bytes memory rPt = pub(k, bls);
        uint256 e = ZetherTranscript.hashToScalar(
            keccak256(abi.encodePacked(tag, rPt, y, m)), r
        );
        return abi.encodePacked(rPt, addmod(k, mulmod(e, x, r), r));
    }
}
