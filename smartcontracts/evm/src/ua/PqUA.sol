// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

/// @title PQ signing kinds: tags, the PQ message and the precompile probe (accounts.md CTR-UA-23).
/// @notice ML-DSA and SLH-DSA sign `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` with the empty FIPS 204 / FIPS 205
///         context, so the signed message is `M' = 0x00 ‖ 0x00 ‖ pq_msg`; FN-DSA (Falcon) signs `ua_msg` itself,
///         the 32-byte message of EIP-8052. A precompile is used only when it answers a known vector exactly:
///         a valid input ⇒ 32 bytes equal to 1, a one-bit-flipped input ⇒ 32 bytes equal to 0 (EIP-8355
///         "Security Considerations"); an empty account, another precompile at a contested address (EIP-7932 and
///         EIP-8051 also claim 0x12) or a different message convention fails the probe.
library PqUA {
    uint16 internal constant MLDSA44 = 0x0130;
    uint16 internal constant MLDSA65 = 0x0131;
    uint16 internal constant FNDSA512 = 0x0132;
    uint16 internal constant SLHDSA128S = 0x0133;

    bytes32 internal constant MSG_TAG = keccak256("scaas.ua.msg.v1");

    error PqUAUnknownKind(uint16 kind);

    /// `TAG(kind) = keccak256(kind_tag)`, `kind_tag = "scaas.ua.<name>.v1"` (accounts.md §1.6).
    function tag(uint16 kind) internal pure returns (bytes32) {
        if (kind == MLDSA44) return keccak256("scaas.ua.mldsa44.v1");
        if (kind == MLDSA65) return keccak256("scaas.ua.mldsa65.v1");
        if (kind == FNDSA512) return keccak256("scaas.ua.fndsa512.v1");
        if (kind == SLHDSA128S) return keccak256("scaas.ua.slhdsa128s.v1");
        revert PqUAUnknownKind(kind);
    }

    /// `ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)` (CTR-UA-12).
    function uaMessage(bytes32 kindTag, bytes32 purposeTag, bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(MSG_TAG, kindTag, purposeTag, digest));
    }

    /// `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` (CTR-UA-23).
    function pqMessage(bytes32 kindTag, bytes32 uaMsg) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(kindTag, uaMsg));
    }

    /// FIPS 204 / FIPS 205 pure signing with the empty context: `M' = 0x00 ‖ 0x00 ‖ pq_msg`.
    function emptyContext(bytes32 pqMsg) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes2(0), pqMsg);
    }

    /// True iff `target` answers `valid` with exactly the 32-byte word 1 and `invalid` with exactly the word 0.
    function probe(address target, bytes memory valid, bytes memory invalid) internal view returns (bool) {
        if (target == address(0)) return false;
        return _answer(target, valid) == 1 && _answer(target, invalid) == 0;
    }

    /// The 32-byte answer of `target`, or 2 (neither 0 nor 1) on a failed call or any other returndata length.
    function _answer(address target, bytes memory input) private view returns (uint256 w) {
        assembly ("memory-safe") {
            mstore(0, 2)
            let ok := staticcall(gas(), target, add(input, 0x20), mload(input), 0, 0x20)
            w := mload(0)
            if iszero(and(ok, eq(returndatasize(), 0x20))) { w := 2 }
        }
    }

    /// One precompile call on the verify path: true only on exactly 32 bytes equal to 1 (EIP-8355 output rule).
    function callBool(address target, bytes memory input) internal view returns (bool ok) {
        assembly ("memory-safe") {
            mstore(0, 0)
            let s := staticcall(gas(), target, add(input, 0x20), mload(input), 0, 0x20)
            ok := and(and(s, eq(returndatasize(), 0x20)), eq(mload(0), 1))
        }
    }
}
