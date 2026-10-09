// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ShortString, ShortStrings} from "@openzeppelin/contracts/utils/ShortStrings.sol";

/// @title EIP-712 domain with `salt = chain_uid` (CTR-GEN-05) — OpenZeppelin `EIP712` has no salt.
/// @notice Domain `(name, version, chainId, verifyingContract = address(this), salt = chain_uid)`;
///         `eip712Domain()` (ERC-5267) reports fields `0x1f`. Everything is an immutable of the implementation, so
///         an EIP-1167 clone (which runs this code by `DELEGATECALL`) uses the same name, version and `chain_uid`
///         with no storage, and the separator is rebuilt whenever `address(this)` or `block.chainid` differs from
///         the cached one. Name and version must fit 31 bytes (`ShortStrings`; longer reverts at deploy):
///         a storage fallback would read the clone's empty storage.
abstract contract SaltedEIP712 is IERC5267 {
    using ShortStrings for ShortString;

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

    constructor(string memory name_, string memory version_, bytes32 chainUid_) {
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

    function _domainSeparatorV4() internal view returns (bytes32) {
        if (address(this) == _cachedThis && block.chainid == _cachedChainId) return _cachedDomainSeparator;
        return _buildDomainSeparator();
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this), CHAIN_UID));
    }
}
