// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../ua/IUAVerifier.sol";
import {PqzSafety} from "./PqzSafety.sol";
import {PqzCt} from "./PqzCt.sol";

/// @title `pqz-mlwe` (0x0142) UA verifier (CTR-PQZ-13, pq-zero-knowledge.md §7.2 step 6; P6g plan D3): the PoP is an `R_REG`
///        proof through the `PQZ` precompile, op 3, on `opTag(REGISTER) ‖ PROOF_SYSTEM_ID ‖ message ‖ pk` (16,480 B).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Stateless; the precompile and the proof system are immutables. The
///         constructor runs only on an allowed chain (`PqzSafety`), after the precompile's self-test and an `R_REG`
///         probe through this contract's own `verify` (a valid vector ⇒ true, the same proof with one bit flipped ⇒
///         false), so a deployed instance has watched the precompile accept and refuse. The same contract is the
///         `verifier` of a PQZ token's `ConfidentialConfig` (P6g plan D9): the token takes `PRECOMPILE` and
///         `PROOF_SYSTEM_ID` from it. `verify` (the registry never calls it for this kind: a PQZ UA authorizes nothing,
///         CTR-PQZ-12) is the same check as `verifyPop`.
contract UAPqzVerifier is IUAPopVerifier {
    /// @notice `keccak256("SCAAS-PQZ-OP-REGISTER-V1")` (pq-zero-knowledge.md §8.1).
    bytes32 internal constant OP_TAG_REGISTER = 0x69562a9cd615eb3d906cb1934ad56c788c30228d2faf7c517e33d65b4a03c088;
    uint8 internal constant OP_REGISTER = 3;
    uint32 internal constant STMT_REGISTER = 16_480;

    address public immutable PRECOMPILE;
    bytes32 public immutable PROOF_SYSTEM_ID;

    /// @notice The constructor's `R_REG` probe failed (valid not accepted, or the flipped proof accepted).
    error UAPqzProbe();

    constructor(address pqz, bytes32 psid, bytes memory probePk, bytes32 probeMessage, bytes memory probeProof) {
        PqzSafety.requireAllowedChain();
        PqzSafety.requireSelfTest(pqz);
        bool valid = probeProof.length != 0 && _call(pqz, psid, probePk, probeMessage, probeProof);
        if (probeProof.length != 0) probeProof[probeProof.length / 2] ^= 0x01;
        if (!valid || _call(pqz, psid, probePk, probeMessage, probeProof)) revert UAPqzProbe();
        PRECOMPILE = pqz;
        PROOF_SYSTEM_ID = psid;
    }

    /// @notice The `R_REG` proof `sig` for `pk` (16,384 bytes, every coefficient `< q`) over `message`.
    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != PqzCt.PK || !PqzCt.isCanonical(keyData)) return false;
        return _call(PRECOMPILE, PROOF_SYSTEM_ID, keyData, message, sig);
    }

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verifyPop(keyData, message, sig);
    }

    /// @notice An allowed chain and the precompile's self-test now (`OpenFactory`'s PQZ gate, P6g plan D2).
    function isSupportedOnThisChain() external view returns (bool) {
        return PqzSafety.isAllowedChain() && PqzSafety.selfTest(PRECOMPILE);
    }

    /// @dev `u8(3) ‖ be32(16,480) ‖ opTag ‖ psid ‖ message ‖ pk ‖ proof`; true only on exactly the word 1.
    function _call(address pqz, bytes32 psid, bytes memory pk, bytes32 message, bytes memory proof)
        private view returns (bool ok)
    {
        bytes memory input = abi.encodePacked(OP_REGISTER, STMT_REGISTER, OP_TAG_REGISTER, psid, message, pk, proof);
        assembly ("memory-safe") {
            mstore(0, 0)
            let s := staticcall(gas(), pqz, add(input, 32), mload(input), 0, 0x20)
            ok := and(and(s, eq(returndatasize(), 0x20)), eq(mload(0), 1))
        }
    }
}
