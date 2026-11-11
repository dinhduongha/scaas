// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The contract surface the verifier reads, in its ABI form (`IPqzToken.sol`, `IUARegistry.sol`): the operation's named
//! argument structs (the request's `op.args`, decoded with unknown fields refused), the token's statement views and
//! verifier configuration, the registry's PQZ key records and digests, and the signed `PqzVerdict` (3f spec §5.1).

alloy::sol! {
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PqzTransferArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        uint64 keyVersion;
        bytes32 toUA;
        bytes32 beneficiaryUA;
        bytes16 salt;
        bytes u;
        bytes vTo;
        bytes vFrom;
        bytes vAuditor;
        bytes sealedMemo;
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PqzLeg {
        bytes32 ua;
        bytes v;
        bytes vAuditor;
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PqzMultiArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        uint64 keyVersion;
        bytes32 beneficiaryUA;
        uint256 decoyFee;
        bytes16 salt;
        bytes[] u;
        PqzLeg[] legs;
        bytes vFrom;
        bytes sealedMemo;
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PqzBurnArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        uint64 keyVersion;
        bytes32 beneficiaryUA;
        bytes u;
        bytes vFrom;
    }


    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Unwrap {
        address underlying;
        bytes32 recipient;
        uint256 amount;
        uint256 minOut;
    }

    #[derive(Debug, PartialEq, serde::Serialize)]
    struct PqzVerdict {
        address token;
        uint256 chainId;
        bytes32 proofSystemId;
        bytes32 statementHash;
        bytes32 proofHash;
        uint32 pqzVerifierEpoch;
        uint64 validUntil;
    }

    /// `UAKinds.UAAUTH_TYPEHASH`'s struct: what a native EOA UA signs, in the registry's domain. Built here from configured
    /// values only; the registry's `uaAuthDigest` view is never read (a hash an RPC returns is never signed).
    #[derive(Debug)]
    struct UAAuth {
        bytes32 ua;
        bytes32 purpose;
        bytes32 digest;
    }

    #[derive(Debug)]
    struct PqzVerifyConfig {
        uint8 pqzVerifyMode;
        bytes32 verifier;
        bool fixed_;
        uint32 pqzVerifierEpoch;
        bytes32 pending;
        uint64 eta;
        uint64 noticePeriod;
        // round 3t (CTR-PQZ-36): the verifier fee, its cap, a live pending increase and its `eta`
        uint64 verifierFee;
        uint64 verifierFeeMax;
        uint64 verifierFeePending;
        uint64 verifierFeeEta;
    }

    #[derive(Debug)]
    struct KemKey {
        uint8 scheme;
        bytes mlkemEk;
        bytes32 x25519;
    }

    #[derive(Debug)]
    struct UAAttrs {
        bytes pqzKey;
        bytes32 pqzPopHash;
        KemKey kem;
        bytes32 kemPkHash;
    }

    interface IPqzToken {
        function transferStatement(PqzMultiArgs t, bytes32 binding) external view returns (bytes);
        function transferSingleStatement(PqzTransferArgs t, bytes32 binding) external view returns (bytes);
        function burnStatement(PqzBurnArgs b, uint256 amount, bytes32 recipient, bytes32 binding) external view returns (bytes);
        function unshieldUnwrapStatement(PqzBurnArgs b, Unwrap x, bytes32 binding) external view returns (bytes);
        function disclosureStatement(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind, uint64 keyVersion)
            external view returns (bytes);
        function proofSystemId() external view returns (bytes32);
        function auditorUA() external view returns (bytes32);
        function pqzVerifyConfig() external view returns (PqzVerifyConfig);
        function pqzEntryBlob(bytes32 entryRef) external view returns (bytes);
    }

    interface IUARegistry {
        function pqzKeyOf(bytes32 ua) external view returns (uint64 version, address ptr, bytes32 pqzPopHash, bool proven);
        function pqzKeyAt(bytes32 ua, uint64 version) external view returns (address ptr, bytes32 pqzPopHash, bool proven);
        function pqzPopOf(bytes32 ua, uint64 version) external view returns (bytes);
        function pqzKeySigOf(bytes32 ua, uint64 version) external view returns (bytes);
        function keyOwner(bytes32 keyHash) external view returns (bytes32);
        function kindOf(bytes32 ua) external view returns (uint16);
        function registrationOf(bytes32 ua) external view
            returns (uint16 kind, bytes keyData, UAAttrs attrs, bytes pop, bytes pqzPop);
        function portableRecordDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash)
            external pure returns (bytes32);
        function kemRecordHash(bytes32 ua, uint64 version, KemKey kem) external pure returns (bytes32);
        function pqzKeyDigest(bytes32 ua, bytes32 pqzKeyHash) external pure returns (bytes32);
        function pqzKeyVersionDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash) external pure returns (bytes32);
        function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32);
    }
}
