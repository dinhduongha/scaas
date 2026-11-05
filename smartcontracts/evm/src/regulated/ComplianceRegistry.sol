// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IComplianceRegistry} from "./IComplianceRegistry.sol";

/// @title The canonical compliance registry (CTR-AS-07, CTR-AS-16, regulated-kinds spec §5): one per issuer policy, deployed
///        by anyone, not a release and not a clone.
/// @notice **UNAUDITED.** The code is pinned (F-11): `admin` lives in storage, written once by the constructor, and nothing
///         writes it after, so every deployment has one runtime and one `extcodehash`, the `REGISTRY_CODEHASH` a regulated
///         release carries. No immutable (so `type(ComplianceRegistry).runtimeCode` is the deployed code), no
///         `SELFDESTRUCT`, no upgrade path, no personal data.
contract ComplianceRegistry is IComplianceRegistry {
    /// @dev Satisfies any `required`, never `denied` (CTR-AS-16).
    uint64 internal constant ELIGIBLE_CONTRACT = 8;

    /// @dev One slot per account.
    struct Attestation {
        uint64 flags;
        uint64 validUntil;
        uint32 attesterId;
    }

    address public admin;
    uint32 internal _lastId;
    mapping(address attester => uint32) public attesterId;
    mapping(uint32 id => bool) internal _enabled;
    mapping(bytes32 account => Attestation) internal _attestations;

    constructor(address admin_) {
        if (admin_.code.length == 0) revert AdminNotContract(admin_);
        admin = admin_;
    }

    function setAttester(address attester, bool enabled) external {
        if (msg.sender != admin) revert NotAdmin();
        uint32 id = attesterId[attester];
        if (id == 0) {
            if (!enabled) revert NotAttester();
            attesterId[attester] = id = ++_lastId;
        }
        _enabled[id] = enabled;
        emit AttesterSet(attester, id, enabled);
    }

    function attesterEnabled(uint32 id) public view returns (bool) {
        return id == 0 || _enabled[id];
    }

    function attest(bytes32[] calldata accounts, uint64[] calldata flags, uint64[] calldata validUntil) external {
        uint32 id;
        if (msg.sender != admin) {
            id = attesterId[msg.sender];
            if (id == 0 || !_enabled[id]) revert NotAttester();
        }
        if (flags.length != accounts.length || validUntil.length != accounts.length) revert LengthMismatch();
        for (uint256 i; i < accounts.length; ++i) {
            if (flags[i] & ELIGIBLE_CONTRACT != 0 && (id != 0 || validUntil[i] != type(uint64).max)) {
                revert EligibleContractAdminOnly();
            }
            _attestations[accounts[i]] = Attestation(flags[i], validUntil[i], id);
            emit Attested(accounts[i], flags[i], validUntil[i], id);
        }
    }

    function attestationOf(bytes32 account) external view returns (uint64, uint64, uint32) {
        Attestation memory a = _attestations[account];
        return (a.flags, a.validUntil, a.attesterId);
    }

    function hasFlags(bytes32 account, uint64 required, uint64 denied) external view returns (bool) {
        Attestation memory a = _attestations[account];
        bool active = a.validUntil >= block.timestamp && attesterEnabled(a.attesterId);
        return (required == 0 || (active && ((a.flags & required) == required || a.flags & ELIGIBLE_CONTRACT != 0)))
            && !(active && a.flags & denied != 0);
    }
}
