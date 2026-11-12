// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title The dev rescue destination (CTR-GOV-25): one owner, one CREATE2 address on every EVM chain.
/// @notice `withdraw`: anyone; the owner's call pays `to`, anyone else's pays the owner. `rotate`: the owner's chain-neutral
///         EIP-712 signature with `seq == seq() + 1`, submitted by anyone, replayable on this vault on every chain.
///         No admin, no upgrade, no delegatecall, no arbitrary call, no chain value. Spec 2026-11-12-rescue-vault.md.
/// @dev This file is in the vault's metadata hash, so in its address (`RescueLib.SCAAS_DEV_RESCUE`): never edit it.
contract RescueVault {
    using SafeERC20 for IERC20;

    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,address verifyingContract)");
    bytes32 public constant ROTATE_TYPEHASH = keccak256("Rotate(uint64 seq,address newOwner)");

    address public owner;
    uint64 public seq;

    event Withdrawn(address indexed token, address indexed to, uint256 amount, address by);
    event Rotated(uint64 indexed seq, address previousOwner, address newOwner);

    error OwnerInvalid();
    error ToInvalid(address to);
    error CallerDelegated(address caller);
    error SeqInvalid(uint64 expected, uint64 got);
    error SignatureInvalid();

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert OwnerInvalid();
        owner = initialOwner;
    }

    receive() external payable {}

    /// @param token the ERC-20, or 0 for the native coin
    /// @param amount the amount, in the token's units
    /// @param to the destination when the owner calls; 0, or any caller but the owner, pays the owner (`to` ignored)
    function withdraw(address token, uint256 amount, address to) external {
        address dest = owner;
        if (msg.sender == dest && to != address(0)) {
            if (_isDesignator(msg.sender)) revert CallerDelegated(msg.sender);
            dest = to;
        }
        emit Withdrawn(token, dest, amount, msg.sender);
        if (token == address(0)) {
            if (_isDesignator(dest)) revert ToInvalid(dest);
            Address.sendValue(payable(dest), amount);
        } else {
            IERC20(token).safeTransfer(dest, amount);
        }
    }

    function rotate(uint64 seq_, address newOwner, bytes calldata sig) external {
        if (seq_ != seq + 1) revert SeqInvalid(seq + 1, seq_);
        if (newOwner == address(0)) revert OwnerInvalid();
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(rotateDigest(seq_, newOwner), sig);
        address previous = owner;
        if (err != ECDSA.RecoverError.NoError || signer != previous) revert SignatureInvalid();
        owner = newOwner;
        seq = seq_;
        emit Rotated(seq_, previous, newOwner);
    }

    function rotateDigest(uint64 seq_, address newOwner) public view returns (bytes32) {
        bytes32 domain = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("SCaaS RescueVault"), keccak256("1"), address(this)));
        return keccak256(abi.encodePacked(hex"1901", domain, keccak256(abi.encode(ROTATE_TYPEHASH, seq_, newOwner))));
    }

    /// @notice ERC-5267: name, version, verifyingContract (fields 0x0d); no chainId, no salt.
    function eip712Domain() external view returns (
            bytes1 fields, string memory name, string memory version, uint256 chainId,
            address verifyingContract, bytes32 salt, uint256[] memory extensions
        )
    {
        return (hex"0d", "SCaaS RescueVault", "1", 0, address(this), bytes32(0), new uint256[](0));
    }

    /// @dev `SigCheck.isDesignator`, copied: an import would put SigCheck's text in this vault's address.
    function _isDesignator(address a) private view returns (bool d) {
        assembly ("memory-safe") {
            if eq(extcodesize(a), 23) {
                extcodecopy(a, 0, 0, 3)
                d := eq(shr(232, mload(0)), 0xef0100)
            }
        }
    }
}
