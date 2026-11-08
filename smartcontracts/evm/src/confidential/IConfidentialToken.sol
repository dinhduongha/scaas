// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The confidential-token interface both layers implement: the classical Zether (`NORMAL_ZETHER`,
///        `WRAPPED_ZETHER`) and the post-quantum PQZ (`NORMAL_PQZ`, `WRAPPED_PQZ`) (plan 5h D20, CTR-ZTH-45).
/// @notice **UNAUDITED.** One selector per function across both layers, no layer argument; ids are `bytes32` UAs. The
///         proof-taking entry points take kind-specific explicit parameters (typed-signing Appendix X.3), so they are in
///         `IZetherToken` / `IPqzToken`, with every other layer-only function. Events carry the fields of both layers; a
///         field one layer lacks is 0 there (Zether: `blob`, `accUnits`, `accHash`).
interface IConfidentialToken {
    /// @notice A shield: `amount` shielded units from `from`'s public units (or a leg's underlying) to `toUA`; `index`
    ///         the PQZ pending entry, Zether's `pendingSeq` after the credit. `from` is `_msgSender()`: `UA_POOL` for a
    ///         UA signer.
    event Shielded(bytes32 indexed toUA, address indexed from, uint256 amount, uint64 index);
    /// @notice A single-recipient transfer; `fee` the proven fee word, `sendCounter` the sender's before the debit,
    ///         `blob` the PQZ op blob (`R ‖ v_f`), 0 on Zether.
    event ConfidentialTransfer(
        bytes32 indexed entryRef,
        bytes32 indexed fromUA,
        bytes32 indexed toUA,
        bytes32 beneficiary,
        uint256 fee,
        uint64 sendCounter,
        address blob
    );
    /// @notice `M` recipients (decoys included), one proof; `mode` the stored form (`ZetherTypes.TransferMode`).
    event ConfidentialTransferMulti(
        bytes32 indexed entryRef,
        bytes32 indexed fromUA,
        bytes32 indexed beneficiary,
        uint256 fee,
        uint64 sendCounter,
        bytes32[] recipients,
        uint8 mode,
        address blob
    );
    /// @notice An unshield (`amount > 0`) to `recipient` (a padded address or a derived UA), or a PQZ refresh
    ///         (`amount = 0`, `recipient = 0`); `blob` the PQZ `u' ‖ v_f`, 0 on Zether.
    event Unshielded(bytes32 indexed ua, uint256 amount, bytes32 indexed recipient, address blob);
    /// @notice A rollover; Zether: `rolled` = `accSeq`, `accUnits` and `accHash` 0.
    event RolledOver(bytes32 indexed ua, uint64 rolled, uint32 accUnits, bytes32 accHash);

    /// @notice Moves `amount · shieldScale` public units of the signer (a derived UA signer: its UA-ledger balance) to
    ///         `SHIELD_POOL` and credits `amount` to `toUA`; no proof. (Group 3g: the rollovers take each layer's parameters,
    ///         `IZetherToken.mtxRollOver(ua, n)`, `IPqzToken.mtxRollOver(ua, keyVersion, n)`; the PQZ layer emits
    ///         `PqzRolledOver`, `RolledOver` stays Zether's.)
    function mtxShield(bytes32 toUA, uint256 amount) external;
}

/// @title The wrapper kinds `WRAPPED_ZETHER` and `WRAPPED_PQZ`: `mtxWrapShield`, one selector, and the leg of an
///        unshield-unwrap; `mtxUnshieldUnwrap` itself takes the kind's parameters (`IZetherWrappedToken`, `IPqzWrappedToken`).
interface IConfidentialWrappedToken {
    /// @notice The leg of an unshield-unwrap: `amount` shielded units paid from leg `underlying`, at least `minOut` of it,
    ///         to `recipient` (a padded address or a derived UA). One calldata struct keeps the signatures within the
    ///         legacy code generator's stack.
    struct Unwrap {
        address underlying;
        bytes32 recipient;
        uint256 amount;
        uint256 minOut;
    }

    /// @notice Pulls `amountIn` of leg `underlying` (native: `msg.value`) and credits its public-equivalent, a multiple of
    ///         `shieldScale`, to `toUA` (minted to `SHIELD_POOL`).
    function mtxWrapShield(address underlying, uint256 amountIn, bytes32 toUA) external payable;
}
