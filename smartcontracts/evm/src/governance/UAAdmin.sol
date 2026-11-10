// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IAdmin} from "./IAdmin.sol";
import {IGovernanceRouter} from "./IGovernanceRouter.sol";
import {SigCheck} from "../common/SigCheck.sol";

/// @title One UA admin for a contract outside the governed kinds (CTR-GOV-23; spec 2026-11-10-admin-not-owner.md §5.1):
///        `OpenFactory` and `ComplianceRegistry`. The admin is a UA id (`bytes32`): a native id acts directly
///        (`pad(msg.sender)`, never an EIP-7702 designator, D2), a derived one (`msig`, a PQ key) through the contract's
///        router, whose `subject()` names it. The semantics are `GovernanceLib`'s: a two-step transfer with acceptance,
///        `adminGeneration` moved at every accept and renounce, a renounce one-way and clearing the pending. Storage in the
///        ERC-7201 namespace `scaas.admin`, so no sequential slot of the inheriting contract moves. **UNAUDITED.**
abstract contract UAAdmin is IAdmin {
    /// @custom:storage-location erc7201:scaas.admin
    struct AdminStorage {
        bytes32 admin;           // +0
        bytes32 pendingAdmin;    // +1
        uint32 adminGeneration;  // +2, completed changes of admin
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.admin")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _ADMIN_STORAGE = 0x18d5f0472d6a800e9364a1440766c2bdb7c41a41a2aba8a58d289cc3c593bb00;

    function _adminStorage() internal pure returns (AdminStorage storage s) {
        assembly ("memory-safe") { s.slot := _ADMIN_STORAGE }
    }

    /// @dev The one router whose `subject()` this contract asks (0 = none): the factory's `govRouter`, the registry's own.
    function _adminRouter() internal view virtual returns (address);

    /// @dev The subject of every admin check (`GovernanceBase._govSubject`): from the router, the UA it authenticated for
    ///      this call (0 outside a live call, which every check refuses); from any other caller, its native id, refused
    ///      when it is a 7702 designator (D2). No signature is verified here.
    function _adminSubject() internal view returns (bytes32) {
        address r = _adminRouter();
        if (r != address(0) && msg.sender == r) return IGovernanceRouter(r).subject();
        SigCheck.requireNotDelegated(msg.sender);
        return bytes32(uint256(uint160(msg.sender)));
    }

    modifier onlyAdmin() {
        _requireAdmin();
        _;
    }

    function _requireAdmin() internal view {
        bytes32 c = _adminSubject();
        if (c == 0 || c != _adminStorage().admin) revert NotAdmin(c);
    }

    /// @dev The first admin, at construction: `AdminTransferred(0, admin_)`.
    function _initAdmin(bytes32 admin_) internal {
        _adminStorage().admin = admin_;
        emit AdminTransferred(bytes32(0), admin_);
    }

    function admin() public view returns (bytes32) {
        return _adminStorage().admin;
    }

    function pendingAdmin() public view returns (bytes32) {
        return _adminStorage().pendingAdmin;
    }

    /// @notice The admin names its successor (0 cancels a pending); the successor's `acceptAdmin` completes it.
    function transferAdmin(bytes32 newAdmin) public virtual onlyAdmin {
        AdminStorage storage s = _adminStorage();
        s.pendingAdmin = newAdmin;
        emit AdminTransferStarted(s.admin, newAdmin);
    }

    /// @notice The pending admin, as its own subject (directly or through the router), becomes the admin.
    function acceptAdmin() public virtual {
        bytes32 c = _adminSubject();
        AdminStorage storage s = _adminStorage();
        if (c == 0 || c != s.pendingAdmin) revert NotPendingAdmin(c);
        emit AdminTransferred(s.admin, c);
        (s.admin, s.pendingAdmin) = (c, bytes32(0));
        ++s.adminGeneration;
    }

    /// @dev The admin becomes 0 for good, the pending with it.
    function _renounceAdmin() internal onlyAdmin {
        AdminStorage storage s = _adminStorage();
        emit AdminTransferred(s.admin, bytes32(0));
        (s.admin, s.pendingAdmin) = (bytes32(0), bytes32(0));
        ++s.adminGeneration;
    }
}
