// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../ua/IUAVerifier.sol";
import {PqzSafety} from "./PqzSafety.sol";
import {PqzCt} from "./PqzCt.sol";
import {PqzSet} from "./PqzSet.sol";

/// @title PQZ key PoK verifier of slot 0x0142 (UA-6 U10; CTR-PQZ-13, pq-zero-knowledge.md §7.2 step 6; P6g plan D3): the PoP is an `R_REG`
///        proof through the `PQZ` precompile, op 3, on `opTag(REGISTER) ‖ PROOF_SYSTEM_ID ‖ message ‖ pk` (`96 + PK` bytes at
///        the build's parameter set, `PqzSet`; plan 5h Task 8d part 2: the set's ids, probe and sizes).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Stateless; the precompile and the proof system are immutables. The
///         constructor runs only on an allowed chain (`PqzSafety`), for exactly the `PQZ` precompile and one of the set's
///         proof systems (PQZL; PQZH where the set has it), after the precompile's self-test and an `R_REG` probe through this contract's own `verify`
///         (the pinned vector of that proof system ⇒ true, the same proof with one bit flipped ⇒ false), so a deployed
///         instance has watched the precompile accept and refuse (review W-B, 2026-10-19). The same contract is the
///         `verifier` of a PQZ token's `ConfidentialConfig` (P6g plan D9): the token takes `PRECOMPILE` and
///         `PROOF_SYSTEM_ID` from it. `verify` (the registry never calls it: a PQZ key is an attribute of a PQ signing
///         UA, which authorizes with its own signature, CTR-PQZ-12; `register` calls `verifyPop` over the key, UA-6 U3) is the same check as `verifyPop`.
contract UAPqzVerifier is IUAPopVerifier {
    /// @notice `keccak256("SCAAS-PQZ-OP-REGISTER-V1")` (pq-zero-knowledge.md §8.1).
    bytes32 internal constant OP_TAG_REGISTER = 0x69562a9cd615eb3d906cb1934ad56c788c30228d2faf7c517e33d65b4a03c088;
    uint8 internal constant OP_REGISTER = 3;
    uint32 internal constant STMT_REGISTER = uint32(PqzSet.STMT_REGISTER);
    /// @notice `SELFTEST_VECTOR_HASH` per proof system (pq-zero-knowledge.md §10, self-test): `keccak256(psid ‖ message
    ///         ‖ pk ‖ proof)` of the set's self-test `R_REG` vector (`statement_register.json` row 0, `proof_pqzl.json` /
    ///         `proof_pqzh.json` row 4 REGISTER), generated into `PqzSet` from the set's vectors.
    bytes32 internal constant PROBE_PQZL = PqzSet.PROBE_PQZL;
    bytes32 internal constant PROBE_PQZH = PqzSet.PROBE_PQZH;

    address public immutable PRECOMPILE;
    bytes32 public immutable PROOF_SYSTEM_ID;

    /// @notice The constructor's `R_REG` probe failed (not the pinned vector, valid not accepted, or the flipped proof
    ///         accepted).
    error UAPqzProbe();

    constructor(address pqz, bytes32 psid, bytes memory probePk, bytes32 probeMessage, bytes memory probeProof) {
        PqzSafety.requirePqz(pqz, psid);
        bytes32 h = keccak256(abi.encodePacked(psid, probeMessage, probePk, probeProof));
        if (h != (psid == PqzSafety.PQZL_ID ? PROBE_PQZL : PROBE_PQZH)) revert UAPqzProbe();
        bool valid = _call(pqz, psid, probePk, probeMessage, probeProof);
        probeProof[probeProof.length / 2] ^= 0x01;
        if (!valid || _call(pqz, psid, probePk, probeMessage, probeProof)) revert UAPqzProbe();
        PRECOMPILE = pqz;
        PROOF_SYSTEM_ID = psid;
    }

    /// @notice The `R_REG` proof `sig` for `pk` (`PK` bytes, every coefficient `< q`) over `message`.
    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != PqzCt.PK || !PqzCt.isCanonical(keyData)) return false;
        return _call(PRECOMPILE, PROOF_SYSTEM_ID, keyData, message, sig);
    }

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verifyPop(keyData, message, sig);
    }

    /// @notice The precompile's self-test now, on any chain id (a view for off-chain callers; the on-chain gate is
    ///         `PqzStateLib.init`: `requirePqz`; `OpenFactory.setKindEnabled` has no chain gate since 5g-Z2, P6g plan D2;
    ///         no chain allowlist since the owner ruling of 2026-10-31).
    function isSupportedOnThisChain() external view returns (bool) {
        return PqzSafety.selfTest(PRECOMPILE);
    }

    /// @dev `u8(3) ‖ be32(STMT_REGISTER) ‖ opTag ‖ psid ‖ message ‖ pk ‖ proof`; true only on exactly the word 1.
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
