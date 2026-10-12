// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SigCheck} from "../common/SigCheck.sol";
import {ITokenAdmin} from "./ITokenAdmin.sol";

/// @title Features, owner and roles of every SCaaS token (CTR-TOK-22), in the ERC-7201 namespace `scaas.token`.
/// @notice External library: the token keeps one-line wrappers, the logic is linked at deploy (CTR-TOK-24).
///         `features`/`lockedFeatures` are written once by `init`; a flag can later only be cleared, once, by the
///         owner and only when not locked. One `owner` (0 = no administration ever) grants and revokes the role of a
///         set flag, disables disableable flags, transfers (two-step) or renounces ownership. Role holders keep their
///         roles after the owner renounces; a holder may renounce its own role.
library AdminLib {
    // ------------------------------------------------------------------ flags (bit numbers, CTR-TOK-22)
    uint8 internal constant PAYABLE = 0;
    uint8 internal constant MINTABLE = 1;
    uint8 internal constant BURNABLE = 2;
    uint8 internal constant RATE_ADJUSTABLE = 3;
    uint8 internal constant WRAP_DISABLEABLE = 4;
    uint8 internal constant FREEZE = 5;
    uint8 internal constant FORCE = 6;
    uint8 internal constant PAUSE = 7;
    uint8 internal constant ALLOWLIST = 8;

    // ------------------------------------------------------------------ kinds (CTR-TOK-21, fresh enum)
    uint8 internal constant KIND_NONE = 0;
    uint8 internal constant KIND_UNDERLYING = 1;
    uint8 internal constant KIND_NONE_ZETHER = 2;
    uint8 internal constant KIND_UNDERLYING_ZETHER = 3;

    /// @dev Flags 5–8 (regulated controls, CTR-AS-17): valid on non-confidential kinds, not built yet (asset suite).
    uint256 internal constant REGULATED = (1 << FREEZE) | (1 << FORCE) | (1 << PAUSE) | (1 << ALLOWLIST);
    /// @dev Flags with a role. PAYABLE and BURNABLE have none and are always locked.
    uint256 internal constant ROLE_BITS = (1 << MINTABLE) | (1 << RATE_ADJUSTABLE) | (1 << WRAP_DISABLEABLE);
    uint256 internal constant ALWAYS_LOCKED = (1 << PAYABLE) | (1 << BURNABLE);

    /// @notice Initial role holders (CTR-TOK-25 `Roles`); each only for a set flag, 0 = none.
    struct Roles {
        address minter;      // MINTABLE
        address rateAdmin;   // RATE_ADJUSTABLE, contract only
        address guardian;    // WRAP_DISABLEABLE
        address issuer;      // FREEZE / FORCE / PAUSE (not built)
        address compliance;  // FORCE / ALLOWLIST (not built)
    }

    /// @custom:storage-location erc7201:scaas.token
    struct TokenStorage {
        uint256 features;
        uint256 lockedFeatures;
        address owner;
        address pendingOwner;
        address creator;
        uint64 version;
        uint8 kind;
        uint8 decimals;
        bool initialized;
        string name;
        string symbol;
        mapping(uint256 bit => mapping(address account => bool)) roles;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.token")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00;



    function $() internal pure returns (TokenStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init (CTR-TOK-22 "Validation in the token")

    /// @notice Validates the flags for `kind` and writes features, owner and initial roles. Called once by the
    ///         token's `initialize` (the factory only forwards; anyone may bring an implementation).
    function init(uint8 kind, uint256 features, uint256 locked, address owner, Roles memory roles) public {
        uint256 bad = features & ~_validFor(kind);
        if (bad != 0) revert ITokenAdmin.FeatureInvalidForKind(_lowest(bad));
        if (features & REGULATED != 0) revert ITokenAdmin.FeatureNotBuilt(_lowest(features & REGULATED));
        if (locked & ~features != 0) revert ITokenAdmin.LockedNotSubset();
        TokenStorage storage s = $();
        s.kind = kind;
        s.features = features;
        s.lockedFeatures = locked | (features & ALWAYS_LOCKED);
        if (roles.issuer != address(0)) revert ITokenAdmin.RoleWithoutFeature(FREEZE);
        if (roles.compliance != address(0)) revert ITokenAdmin.RoleWithoutFeature(ALLOWLIST);
        if (roles.minter != address(0)) _grant(s, MINTABLE, roles.minter, address(0));
        if (roles.rateAdmin != address(0)) _grant(s, RATE_ADJUSTABLE, roles.rateAdmin, address(0));
        if (roles.guardian != address(0)) _grant(s, WRAP_DISABLEABLE, roles.guardian, address(0));
        if (owner != address(0)) {
            s.owner = owner;
            emit ITokenAdmin.OwnershipTransferred(address(0), owner);
        }
    }

    // ------------------------------------------------------------------ owner

    function grantRole(uint8 bit, address account, address caller) public {
        TokenStorage storage s = _onlyOwner(caller);
        _grant(s, bit, account, caller);
    }

    function revokeRole(uint8 bit, address account, address caller) public {
        TokenStorage storage s = _onlyOwner(caller);
        if (s.roles[bit][account]) {
            s.roles[bit][account] = false;
            emit ITokenAdmin.RoleRevoked(bit, account, caller);
        }
    }

    /// @notice A holder gives up its own role (replaces `renounceMinter`/`renounceRateAdmin`/`renounceGuardian`).
    function renounceRole(uint8 bit, address caller) public {
        TokenStorage storage s = $();
        if (!s.roles[bit][caller]) revert ITokenAdmin.MissingRole(bit, caller);
        s.roles[bit][caller] = false;
        emit ITokenAdmin.RoleRevoked(bit, caller, caller);
    }

    /// @notice One-way: clears a set, unlocked flag (replaces `disableControls`).
    function disableFeature(uint8 bit, address caller) public {
        TokenStorage storage s = _onlyOwner(caller);
        uint256 m = _bit(bit);
        if ((s.lockedFeatures | ALWAYS_LOCKED) & m != 0) revert ITokenAdmin.FeatureLocked(bit);
        if (s.features & m == 0) revert ITokenAdmin.FeatureNotSet(bit);
        s.features &= ~m;
        emit ITokenAdmin.FeatureDisabled(bit, caller);
    }

    function transferOwnership(address newOwner, address caller) public {
        TokenStorage storage s = _onlyOwner(caller);
        s.pendingOwner = newOwner;
        emit ITokenAdmin.OwnershipTransferStarted(caller, newOwner);
    }

    function acceptOwnership(address caller) public {
        TokenStorage storage s = $();
        if (caller != s.pendingOwner || caller == address(0)) revert ITokenAdmin.NotPendingOwner(caller);
        address previous = s.owner;
        s.owner = caller;
        s.pendingOwner = address(0);
        emit ITokenAdmin.OwnershipTransferred(previous, caller);
    }

    /// @notice The owner becomes 0 forever; role holders keep their roles (to freeze everything, revoke first).
    function renounceOwnership(address caller) public {
        TokenStorage storage s = _onlyOwner(caller);
        s.owner = address(0);
        s.pendingOwner = address(0);
        emit ITokenAdmin.OwnershipTransferred(caller, address(0));
    }

    // ------------------------------------------------------------------ checks used inline by the token

    function hasFeature(uint8 bit) internal view returns (bool) {
        return $().features & _bit(bit) != 0;
    }

    function hasRole(uint8 bit, address account) internal view returns (bool) {
        return $().roles[bit][account];
    }

    /// @dev The flag is set and `account` holds its role.
    function requireRole(uint8 bit, address account) internal view {
        TokenStorage storage s = $();
        if (s.features & _bit(bit) == 0) revert ITokenAdmin.FeatureNotSet(bit);
        if (!s.roles[bit][account]) revert ITokenAdmin.MissingRole(bit, account);
    }

    function requireFeature(uint8 bit) internal view {
        if ($().features & _bit(bit) == 0) revert ITokenAdmin.FeatureNotSet(bit);
    }

    // ------------------------------------------------------------------ internals

    function _grant(TokenStorage storage s, uint8 bit, address account, address caller) private {
        if (account == address(0)) revert ITokenAdmin.RoleAccountZero(bit);
        if (ROLE_BITS & _bit(bit) == 0) revert ITokenAdmin.NoSuchRole(bit);
        if (s.features & _bit(bit) == 0) revert ITokenAdmin.RoleWithoutFeature(bit);
        if (bit == RATE_ADJUSTABLE && !SigCheck.isContract(account)) revert ITokenAdmin.RoleNotContract(bit, account);
        if (s.roles[bit][account]) return;
        s.roles[bit][account] = true;
        emit ITokenAdmin.RoleGranted(bit, account, caller);
    }

    function _onlyOwner(address caller) private view returns (TokenStorage storage s) {
        s = $();
        if (caller != s.owner || caller == address(0)) revert ITokenAdmin.NotOwner(caller);
    }

    /// @dev Valid flags per kind (CTR-TOK-22 table): NONE* mint/burn, UNDERLYING* rate/wrap, regulated only on
    ///      non-confidential kinds (CTR-AS-17), PAYABLE everywhere. An unknown kind has no valid flag.
    function _validFor(uint8 kind) private pure returns (uint256) {
        uint256 none = (1 << PAYABLE) | (1 << MINTABLE) | (1 << BURNABLE);
        uint256 und = (1 << PAYABLE) | (1 << RATE_ADJUSTABLE) | (1 << WRAP_DISABLEABLE);
        if (kind == KIND_NONE) return none | REGULATED;
        if (kind == KIND_UNDERLYING) return und | REGULATED;
        if (kind == KIND_NONE_ZETHER) return none;
        if (kind == KIND_UNDERLYING_ZETHER) return und;
        return 0;
    }

    function _bit(uint8 bit) private pure returns (uint256) {
        return uint256(1) << bit;
    }

    function _lowest(uint256 x) private pure returns (uint8 i) {
        while (x & 1 == 0) { x >>= 1; ++i; }
    }
}
