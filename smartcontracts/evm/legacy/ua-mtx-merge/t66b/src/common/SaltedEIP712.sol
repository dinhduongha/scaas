// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ShortString, ShortStrings} from "@openzeppelin/contracts/utils/ShortStrings.sol";

/// @title EIP-712 domain with `salt = chain_uid` (CTR-GEN-05) — OpenZeppelin `EIP712` has no salt.
/// @notice Domain `(name, version, chainId, verifyingContract = address(this), salt = chain_uid)`;
///         `eip712Domain()` (ERC-5267) reports fields `0x1f`. Name, version and (for every contract the factory does not
///         make) `chain_uid` are immutables of the implementation, so an EIP-1167 clone (which runs this code by
///         `DELEGATECALL`) uses the same ones with no storage, and the separator is rebuilt whenever `address(this)` or
///         `block.chainid` differs from the cached one. Name and version must fit 31 bytes (`ShortStrings`; longer
///         reverts at deploy): a storage fallback would read the clone's empty storage. A factory-made contract
///         (CTR-TOK-29, chain-neutral spec §2.2: `_chainUidInCode()`) passes 0 and overrides `eip712Domain`,
///         `_domainSeparatorV4` and `_chainUidRaw` with its clone's code (`_eip712DomainUnder`, `_separator`, `_chainUid`,
///         which reverts `ChainUidZero` on 0: the implementation builds no domain, Fable P2-1); the code of every other
///         contract is unchanged by the hook (`SmartKeyAccount` byte for byte).
abstract contract SaltedEIP712 is IERC5267 {
    using ShortStrings for ShortString;

    /// @notice NET-ALL-22: `chain_uid` is a non-zero bytes32.
    error ChainUidZero();

    bytes32 private constant TYPE_HASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
    );

    /// @notice The chain's genesis block hash (NET-ALL-22), fixed by the implementation's constructor.
    bytes32 internal immutable CHAIN_UID;

    ShortString private immutable _name;
    ShortString private immutable _version;
    bytes32 private immutable _hashedName;
    bytes32 private immutable _hashedVersion;
    bytes32 private immutable _cachedDomainSeparator;
    uint256 private immutable _cachedChainId;
    address private immutable _cachedThis;

    /// @param chainUid_ the chain's genesis hash; 0 only on a factory-made contract (`_chainUidInCode()`).
    constructor(string memory name_, string memory version_, bytes32 chainUid_) {
        if (chainUid_ == bytes32(0) && !_chainUidInCode()) revert ChainUidZero();
        _name = ShortStrings.toShortString(name_);
        _version = ShortStrings.toShortString(version_);
        _hashedName = keccak256(bytes(name_));
        _hashedVersion = keccak256(bytes(version_));
        CHAIN_UID = chainUid_;
        _cachedChainId = block.chainid;
        _cachedThis = address(this);
        _cachedDomainSeparator = _buildDomainSeparator();
    }

    function eip712Domain()
        public view virtual returns (
            bytes1 fields, string memory name, string memory version, uint256 chainId,
            address verifyingContract, bytes32 salt, uint256[] memory extensions
        )
    {
        return (hex"1f", _name.toString(), _version.toString(), block.chainid, address(this), CHAIN_UID,
            new uint256[](0));
    }

    function _domainSeparatorV4() internal view virtual returns (bytes32) {
        if (address(this) == _cachedThis && block.chainid == _cachedChainId) return _cachedDomainSeparator;
        return _buildDomainSeparator();
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this), CHAIN_UID));
    }

    // ------------------------------------------------------------------ the factory-made hook (CTR-TOK-29)

    /// @dev True on a factory-made contract: its `chain_uid` is in its clone's code, the constructor's is 0.
    function _chainUidInCode() internal pure virtual returns (bool) { return false; }

    /// @dev The chain's `chain_uid` as stored (0 on a factory-made implementation).
    function _chainUidRaw() internal view virtual returns (bytes32) { return CHAIN_UID; }

    /// @dev `_chainUidRaw()`, never 0: a factory-made contract's domains and chain-bound digests.
    function _chainUid() internal view returns (bytes32 u) {
        u = _chainUidRaw();
        if (u == bytes32(0)) revert ChainUidZero();
    }

    /// @dev The separator under `uid` (the caller's, non-zero).
    function _separator(bytes32 uid) internal view returns (bytes32) {
        return keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this), uid));
    }

    /// @dev `eip712Domain()` under `salt` (a factory-made contract's override).
    function _eip712DomainUnder(bytes32 salt)
        internal view returns (
            bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory
        )
    {
        return (hex"1f", _name.toString(), _version.toString(), block.chainid, address(this), salt, new uint256[](0));
    }
}
