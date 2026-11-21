// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title Per-kind UA verifier (accounts.md CTR-UA-17 "Verifiers").
/// @notice Stateless. The registry has matched `keyData` against the id (or read the stored key from `keyPtr`);
///         `message` is the 32-byte `ua_msg` (CTR-UA-12). A malformed input returns false, never true.
interface IUAKindVerifier {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
}

/// @title Per-kind UA verifier with the proof of possession (accounts.md §1.4, CTR-UA-07).
/// @notice `message` is the portable `uaMessage(kind, PURPOSE_POP_V2, registrationDigest(...))` (UA-8). A kind whose PoP needs its own domain (the BLS
///         min-sig kinds: `DST_POP` / the POP label) checks it here; the group kinds (MuSig2/FROST, accounts.md §1.6.1, and
///         `bls12381-multi`, which is both: its PoP is the members' distinct-message aggregate under `DST_MULTI_POP` over the full
///         key data, spec 2026-11-19-bls12381-multi §4)
///         take the full key data and run the whole group check (KeyAgg with hints / DKG PoKs) before the group
///         signature, while their `verify` takes the stored `vk`; for every other kind `verifyPop == verify`.
///         Malformed input returns false and never reverts.
interface IUAPopVerifier is IUAKindVerifier {
    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
}

/// @title The stored form (CTR-UA-07, spec 2026-11-19-bls12381-multi §5.3): `verify` and every signer necessary.
/// @notice Only kinds whose signatures have a surplus form implement it (`UAKinds.hasSurplusForm`, today `0x0121`); the registry
///         calls it on the stored paths for those kinds, `verify` on the others. Malformed input returns false and never reverts.
interface IUAMinimalVerifier is IUAPopVerifier {
    function verifyMinimal(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
}

/// A verify-only verifier (spec 2026-11-19-registry-verify-only-kinds §2, §5): the precompile its constructor probe found (0 =
/// none: such a verifier is refused by the registry constructor, P11) and the key form it takes (0 the stored bytes, 1 the
/// holder's ML-DSA cache). A successor reads both (frozen, §11.3 M8).
interface IUAVerifyOnlyVerifier {
    function PRECOMPILE() external view returns (address);
    function KEY_FORM() external view returns (uint8);
}
