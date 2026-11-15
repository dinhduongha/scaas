// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title The dev rescue destination (CTR-GOV-25): one CREATE2 address on every EVM chain, two roles.
/// @notice `rescuer` (an address) receives: `withdraw` by anyone; the rescuer's call pays `to`, every other call pays the
///         rescuer. `admin` (a native UA) only administers, never receives: `setRescuer` and `rotateAdmin`, each the admin's
///         chain-neutral EIP-712 signature with one shared `seq == seq() + 1`, submitted by anyone, replayable on this vault on
///         every chain. No upgrade, no delegatecall, no arbitrary call, no chain value. Spec 2026-11-12-rescue-vault.md.
/// @dev This file is in the vault's metadata hash, so in its address (`RescueLib.SCAAS_DEV_RESCUE`): never edit it.
contract RescueVault {
    using SafeERC20 for IERC20;

    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,address verifyingContract)");
    bytes32 public constant SET_RESCUER_TYPEHASH = keccak256("SetRescuer(uint64 seq,address newRescuer)");
    bytes32 public constant ROTATE_ADMIN_TYPEHASH = keccak256("RotateAdmin(uint64 seq,bytes32 newAdmin)");

    /// @notice A native UA: an EOA address in the low 160 bits, the high 96 bits 0. Signs by `ecrecover` (low s) only.
    bytes32 public admin;
    address public rescuer;
    /// @notice The number of admin operations applied, both kinds counted together.
    uint64 public seq;

    event Withdrawn(address indexed token, address indexed to, uint256 amount, address by);
    event RescuerSet(uint64 indexed seq, address previousRescuer, address newRescuer);
    event AdminRotated(uint64 indexed seq, bytes32 previousAdmin, bytes32 newAdmin);

    error AdminInvalid(bytes32 admin);
    error RescuerInvalid();
    error ToInvalid(address to);
    error CallerDelegated(address caller);
    error SeqInvalid(uint64 expected, uint64 got);
    error SignatureInvalid();

    constructor(bytes32 initialAdmin, address initialRescuer) {
        _checkAdmin(initialAdmin);
        if (initialRescuer == address(0)) revert RescuerInvalid();
        admin = initialAdmin;
        rescuer = initialRescuer;
    }

    receive() external payable {}

    /// @param token the ERC-20, or 0 for the native coin
    /// @param amount the amount, in the token's units
    /// @param to the destination when the rescuer calls; 0, or any caller but the rescuer, pays the rescuer (`to` ignored)
    function withdraw(address token, uint256 amount, address to) external {
        address dest = rescuer;
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

    function setRescuer(uint64 seq_, address newRescuer, bytes calldata sig) external {
        if (newRescuer == address(0)) revert RescuerInvalid();
        _advance(seq_, setRescuerDigest(seq_, newRescuer), sig);
        emit RescuerSet(seq_, rescuer, newRescuer);
        rescuer = newRescuer;
    }

    function rotateAdmin(uint64 seq_, bytes32 newAdmin, bytes calldata sig) external {
        _checkAdmin(newAdmin);
        _advance(seq_, rotateAdminDigest(seq_, newAdmin), sig);
        emit AdminRotated(seq_, admin, newAdmin);
        admin = newAdmin;
    }

    function setRescuerDigest(uint64 seq_, address newRescuer) public view returns (bytes32) {
        return _digest(keccak256(abi.encode(SET_RESCUER_TYPEHASH, seq_, newRescuer)));
    }

    function rotateAdminDigest(uint64 seq_, bytes32 newAdmin) public view returns (bytes32) {
        return _digest(keccak256(abi.encode(ROTATE_ADMIN_TYPEHASH, seq_, newAdmin)));
    }

    /// @notice ERC-5267: name, version, verifyingContract (fields 0x0b); no chainId, no salt.
    function eip712Domain() external view returns (
            bytes1 fields, string memory name, string memory version, uint256 chainId,
            address verifyingContract, bytes32 salt, uint256[] memory extensions
        )
    {
        return (hex"0b", "SCaaS RescueVault", "1", 0, address(this), bytes32(0), new uint256[](0));
    }

    /// @dev `seq_` must be the next one, and `sig` the current admin's 65-byte low-s ECDSA over `digest`.
    function _advance(uint64 seq_, bytes32 digest, bytes calldata sig) private {
        if (seq_ != seq + 1) revert SeqInvalid(seq + 1, seq_);
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
        if (err != ECDSA.RecoverError.NoError || signer != address(uint160(uint256(admin)))) revert SignatureInvalid();
        seq = seq_;
    }

    function _digest(bytes32 structHash) private view returns (bytes32) {
        bytes32 domain = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("SCaaS RescueVault"), keccak256("1"), address(this)));
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    /// @dev A native UA only (`UAKinds.inNativeSpace`, not 0): a derived or PQ UA needs the chain's UARegistry, whose
    ///      address differs per chain, which this chain-neutral vault cannot trust.
    function _checkAdmin(bytes32 a) private pure {
        if (a == bytes32(0) || uint256(a) >> 160 != 0) revert AdminInvalid(a);
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
