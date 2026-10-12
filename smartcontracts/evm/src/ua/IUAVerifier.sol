// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

/// @title Per-kind UA verifier (accounts.md CTR-UA-17 "Verifiers").
/// @notice Stateless. The registry has matched `keyData` against the id (or read the stored key from `keyPtr`);
///         `message` is the 32-byte `ua_msg` (CTR-UA-12). A malformed input returns false, never true.
interface IUAKindVerifier {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
}

/// @title Per-kind UA verifier with the proof of possession (accounts.md §1.4, CTR-UA-07).
/// @notice `message` is `uaMessage(kind, PURPOSE_POP, popDigest(...))`. A kind whose PoP needs its own domain (the BLS
///         min-sig kinds: `DST_POP` / the POP label) checks it here; the group kinds (MuSig2/FROST, accounts.md §1.6.1)
///         take the full key data and run the whole group check (KeyAgg with hints / DKG PoKs) before the group
///         signature, while their `verify` takes the stored `vk`; for every other kind `verifyPop == verify`.
///         Malformed input returns false and never reverts.
interface IUAPopVerifier is IUAKindVerifier {
    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
}
