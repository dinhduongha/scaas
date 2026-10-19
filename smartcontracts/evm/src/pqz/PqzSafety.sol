// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The PQZ chain gate (CTR-PQZ-01, CTR-PQZ-10; P6g plan D2): a hard-coded allowlist and the precompile self-test.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** The allowlist is code, not a parameter: adding a chain is a reviewed
///         change and a new deploy (as `ZetherSafety`). A chain id alone proves nothing (a missing chainspec key looks
///         exactly like an enabled one), so every deploy also asks the precompile for its frozen self-test hash.
library PqzSafety {
    /// @notice The `PQZ` precompile on chain 7622 (CTR-PQZ-10), the same address on the dev chains.
    address internal constant PQZ = 0x5caA500000000000000000000000000000000F01;
    /// @notice `OP_SELFTEST` (P6e D13, `selftest.json`): the precompile's answer to the input `06 00000000`.
    bytes32 internal constant SELFTEST = 0xed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205;
    /// @notice The proof systems the precompile verifies (CTR-PQZ-10): PQZL v3 (lazer#28 fix; v2 retired) and PQZH.
    bytes32 internal constant PQZL_ID = 0x8079d65b5e5c15e330f7e65c875776dfc1b0f6c93ced90c045e83865d116baef;
    bytes32 internal constant PQZH_ID = 0x0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4;

    error NotAllowedChain(uint256 chainId);
    error SelfTestFailed(address pqz);
    /// @notice Not the `PQZ` precompile, or a proof system it does not verify (review W-B, 2026-10-19).
    error NotPqz(address pqz, bytes32 psid);

    /// @notice 31337 (anvil), 1337 (geth --dev), 7622 (the SCaaS testnet with the PQZ precompile).
    function isAllowedChain() internal view returns (bool) {
        return block.chainid == 31337 || block.chainid == 1337 || block.chainid == 7622;
    }

    function requireAllowedChain() internal view {
        if (!isAllowedChain()) revert NotAllowedChain(block.chainid);
    }

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

    function requireSelfTest(address pqz) internal view {
        if (!selfTest(pqz)) revert SelfTestFailed(pqz);
    }

    /// @notice What a token or a `UAPqzVerifier` may be bound to (review W-B): exactly `PQZ`, one of its two proof
    ///         systems, and its self-test now. A creator-chosen precompile could answer every proof with 1.
    function requirePqz(address pqz, bytes32 psid) internal view {
        if (pqz != PQZ || (psid != PQZL_ID && psid != PQZH_ID)) revert NotPqz(pqz, psid);
        requireSelfTest(pqz);
    }
}
