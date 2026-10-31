// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzSet} from "./PqzSet.sol";

/// @title The PQZ chain gate (CTR-PQZ-01, CTR-PQZ-10; P6g plan D2): the precompile self-test, nothing else.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** No chain-id allowlist (owner ruling 2026-10-31: PQZ is open on every
///         chain that meets the requirements). A chain id alone proves nothing (a missing chainspec key looks exactly
///         like an enabled one), so every deploy asks the precompile for its frozen self-test hash: a chain without the
///         `PQZ` precompile, or with one built for another set, is refused by that, whatever its id.
library PqzSafety {
    /// @notice The `PQZ` precompile (CTR-PQZ-10; the 32-bit form `0x…5caa0f01` of plan 5h Task 8d, spec §12 item 9), the
    ///         same address on every chain.
    address internal constant PQZ = 0x000000000000000000000000000000005caa0f01;
    /// @notice `OP_SELFTEST` (P6e D13, the set's `selftest.json`): the precompile's answer to the input `06 00000000` at
    ///         the build's parameter set (`PqzSet`: a precompile built for another set answers another hash).
    bytes32 internal constant SELFTEST = PqzSet.SELFTEST;
    /// @notice The proof systems the precompile verifies at the build's set (CTR-PQZ-09 / CTR-PQZ-10, one id per set and
    ///         system): PQZL, and PQZH where the set has it (`PqzSet.HAS_PQZH`; the zero word elsewhere, never accepted).
    ///         Every other id — the retired PQZL v2 / v3 and PQZH v1, another set's — is refused.
    bytes32 internal constant PQZL_ID = PqzSet.PQZL_ID;
    bytes32 internal constant PQZH_ID = PqzSet.PQZH_ID;

    error SelfTestFailed(address pqz);
    /// @notice Not the `PQZ` precompile, or a proof system it does not verify (review W-B, 2026-10-19).
    error NotPqz(address pqz, bytes32 psid);

    /// @notice True iff `pqz` answers exactly `06 00000000` with exactly the 32-byte frozen hash. An empty account, a
    ///         revert, another length or another word is false.
    function selfTest(address pqz) internal view returns (bool ok) {
        bytes32 want = SELFTEST;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, shl(248, 6)) // 06 00 00 00 00
            mstore(0, 0)
            let s := staticcall(gas(), pqz, m, 5, 0, 0x20)
            ok := and(and(s, eq(returndatasize(), 0x20)), eq(mload(0), want))
        }
    }

    /// @notice `psid` is the set's PQZL id, or its PQZH id where the set has PQZH.
    function isPsid(bytes32 psid) internal pure returns (bool) {
        return psid == PQZL_ID || (PqzSet.HAS_PQZH && psid == PQZH_ID);
    }

    function requireSelfTest(address pqz) internal view {
        if (!selfTest(pqz)) revert SelfTestFailed(pqz);
    }

    /// @notice What a token or a `UAPqzVerifier` may be bound to (review W-B): exactly `PQZ`, one of the set's proof
    ///         systems, and its self-test now. A creator-chosen precompile could answer every proof with 1.
    function requirePqz(address pqz, bytes32 psid) internal view {
        if (pqz != PQZ || !isPsid(psid)) revert NotPqz(pqz, psid);
        requireSelfTest(pqz);
    }
}
