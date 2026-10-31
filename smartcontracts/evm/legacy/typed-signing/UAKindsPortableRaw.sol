// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// legacy/typed-signing: NOT COMPILED. The raw UA-8 portable digests and their record tags as they stood in
// src/ua/UAKinds.sol before typed-signing P3 (typed EIP-712 portable records, TS-D1 … TS-D4), and the registry's
// `personal_sign` path for a native `msig` member of a portable record (UARegistry `_nativePortable`, replaced by
// ECDSA over the typed digest, TS-D4). Reference only.

library UAKindsPortableRaw {
    bytes32 internal constant PURPOSE_POP_V2 = keccak256("scaas.ua.purpose.pop.v2");
    bytes32 internal constant KEM_RECORD_TAG = keccak256("scaas.ua.kem-record.v1");
    bytes32 internal constant PQZ_KEY_RECORD_TAG = keccak256("scaas.ua.pqz-key-record.v1");

    /// `keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)`; `pqzKeyHash = keyHashOf(0x0142, pqzKey)`,
    /// `kemRecordHash = kemRecordDigest` of the initial KEM record. R_REG proves over `uaMessage(0x0142, PURPOSE_POP_V2, ·)`.
    function portablePopDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 kemRecordHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(PURPOSE_POP_V2, ua, pqzKeyHash, kemRecordHash));
    }

    /// `keccak256(portablePopDigest ‖ pqzPopHash)`, `pqzPopHash = keccak256(pqzPop)`: the `pop` (an msig's members through
    /// `memberDigest`) signs `uaMessage(kind, PURPOSE_POP_V2, ·)` of it.
    function registrationDigest(bytes32 portable, bytes32 pqzPopHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(portable, pqzPopHash));
    }

    /// `keccak256(KEM_RECORD_TAG ‖ ua ‖ uint256(version) ‖ keccak256(kemPk))`, signed as `uaMessage(kind, PURPOSE_KEM, ·)`.
    function kemRecordDigest(bytes32 ua, uint64 version, bytes memory kemPk) internal pure returns (bytes32) {
        return keccak256(abi.encode(KEM_RECORD_TAG, ua, uint256(version), keccak256(kemPk)));
    }

    /// `keccak256(PQZ_KEY_RECORD_TAG ‖ ua ‖ pqzKeyHash)`: a later PQZ key's R_REG proves over
    /// `uaMessage(0x0142, PURPOSE_PQZ_KEY, ·)` (no proof hash: no cycle).
    function pqzKeyDigest(bytes32 ua, bytes32 pqzKeyHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(PQZ_KEY_RECORD_TAG, ua, pqzKeyHash));
    }

    /// `keccak256(pqzKeyDigest ‖ pqzPopHash)`: `setPqzKey`'s signature signs `uaMessage(kind, PURPOSE_PQZ_KEY, ·)`.
    function pqzKeyRecordDigest(bytes32 keyDigest, bytes32 pqzPopHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(keyDigest, pqzPopHash));
    }

    // UARegistry (before typed-signing P3):
    //
    // /// A native `msig` member of a portable record (no chain context; owner ruling 2026-10-30, "an EOA must really
    // /// sign, no delegation"): code-less or an EIP-7702 designator (an EOA) ⇒ ECDSA by its own key only (65-byte
    // /// r ‖ s ‖ v, low s, v 27 / 28: OZ `tryRecover`) over the EIP-191 `personal_sign` hash of `md`, never ERC-1271
    // /// through the delegate; other code (a contract wallet) ⇒ ERC-1271 `isValidSignature(md, sig)` only, at the same
    // /// caps as `_native`.
    // function _nativePortable(address a, bytes32 md, bytes memory sig) private view returns (bool) {
    //     return _byCode(a, MessageHashUtils.toEthSignedMessageHash(md), md, sig);
    // }
}
