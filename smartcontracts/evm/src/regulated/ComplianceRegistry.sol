// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IComplianceRegistry} from "./IComplianceRegistry.sol";
import {UAAdmin} from "../governance/UAAdmin.sol";

/// @title The canonical compliance registry (CTR-AS-07, CTR-AS-16, regulated-kinds spec §5): one per issuer policy, deployed
///        by anyone, not a release and not a clone. Round 3r (spec 2026-11-10-admin-not-owner.md §5.3, §5.3.1): its admin
///        is a UA (`UAAdmin`: direct as the native id, or the router's `subject()`), transferred in two steps, never
///        renounced (owner, Q2: only the admin disables a compromised KYC provider or writes an `ELIGIBLE_CONTRACT` row);
///        each KYC provider is a UA id too and the subject of its own `setCompliance`.
/// @notice **UNAUDITED.** The code is pinned (F-11): the admin (the `scaas.admin` namespace) and `govRouter` live in
///         storage, written by the constructor (`chainUid` too, CTR-GOV-27); no immutable, so every deployment has one runtime and one `extcodehash`,
///         the `COMPLIANCE_REGISTRY_CODEHASH` a regulated release carries (`type(ComplianceRegistry).runtimeCode` is the
///         deployed code). The code hash pins the code, not the router: a regulated token also checks `govRouter()`
///         (spec §5.3, Fable P1-1). No `SELFDESTRUCT`, no upgrade path, no personal data.
contract ComplianceRegistry is IComplianceRegistry, UAAdmin {
    /// @dev Satisfies any `required`, never `denied` (CTR-AS-16).
    uint64 internal constant ELIGIBLE_CONTRACT = 8;
    /// @dev The node's decode bound of `UASetCompliance` (spec §5.3.1, §5.4).
    uint256 internal constant MAX_ROWS = 256;

    /// @dev One slot per account.
    struct ComplianceRow {
        uint64 flags;
        uint64 validUntil;
        uint32 providerId;
    }

    address public govRouter;
    uint32 internal _lastId;
    /// @notice The chain word `transferAdmin` checks (CTR-GOV-27), written once by the constructor.
    bytes32 public chainUid;
    mapping(bytes32 provider => uint32) public kycProviderId;
    mapping(uint32 id => bool) internal _enabled;
    mapping(bytes32 account => ComplianceRow) internal _rows;

    /// @notice `admin_` any UA but 0; a derived one only with a router (its one path), and a router has code; `chainUid_`
    ///         this chain's word, not 0 (CTR-GOV-27).
    constructor(bytes32 admin_, address govRouter_, bytes32 chainUid_) {
        if (admin_ == bytes32(0)) revert AdminZero();
        if (chainUid_ == bytes32(0)) revert ChainUidZero();
        if (govRouter_ == address(0)) {
            if (uint256(admin_) >> 160 != 0) revert AdminUnreachable(admin_);
        } else if (govRouter_.code.length == 0) {
            revert RouterNotContract(govRouter_);
        }
        (govRouter, chainUid) = (govRouter_, chainUid_);
        _initAdmin(admin_);
    }

    function _adminRouter() internal view override returns (address) {
        return govRouter;
    }

    function _requireChainWord(bytes32 chainUid_) internal view override {
        if (chainUid_ != chainUid) revert ChainUidMismatch(chainUid, chainUid_);
    }

    function setKycProvider(bytes32 provider, bool enabled) external onlyAdmin {
        if (provider == bytes32(0)) revert KycProviderZero();
        uint32 id = kycProviderId[provider];
        if (id == 0) {
            if (!enabled) revert NotKycProvider();
            kycProviderId[provider] = id = ++_lastId;
        }
        _enabled[id] = enabled;
        emit KycProviderSet(provider, id, enabled);
    }

    function kycProviderEnabled(uint32 id) public view returns (bool) {
        return id == 0 || _enabled[id];
    }

    function setCompliance(bytes32[] calldata accounts, uint64[] calldata flags, uint64[] calldata until) external {
        bytes32 c = _adminSubject();
        uint32 id;
        if (c != _adminStorage().admin) {
            id = kycProviderId[c];
            if (id == 0 || !_enabled[id]) revert NotKycProvider();
        }
        if (flags.length != accounts.length || until.length != accounts.length) revert LengthMismatch();
        if (accounts.length > MAX_ROWS) revert TooManyRows(accounts.length);
        for (uint256 i; i < accounts.length; ++i) {
            if (flags[i] & ELIGIBLE_CONTRACT != 0 && (id != 0 || until[i] != type(uint64).max)) {
                revert EligibleContractAdminOnly();
            }
            ComplianceRow storage s = _rows[accounts[i]];
            // Owner 2026-11-06: an admin row (id 0, flags != 0) is the admin's alone; an empty slot also reads id 0, and
            // an admin row of flags 0 is a revoke, both open.
            if (id != 0 && s.providerId == 0 && s.flags != 0) revert AdminWrittenSlot(accounts[i]);
            (s.flags, s.validUntil, s.providerId) = (flags[i], until[i], id);
            emit ComplianceSet(accounts[i], flags[i], until[i], id);
        }
    }

    function complianceOf(bytes32 account) external view returns (uint64, uint64, uint32) {
        ComplianceRow memory a = _rows[account];
        return (a.flags, a.validUntil, a.providerId);
    }

    function hasFlags(bytes32 account, uint64 required, uint64 denied) external view returns (bool) {
        ComplianceRow memory a = _rows[account];
        bool active = a.validUntil >= block.timestamp && kycProviderEnabled(a.providerId);
        return (required == 0 || (active && ((a.flags & required) == required || a.flags & ELIGIBLE_CONTRACT != 0)))
            && !(active && a.flags & denied != 0);
    }
}
