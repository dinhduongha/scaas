// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The confidential-token interface both layers implement: the classical Zether (`NONE_ZETHER`,
///        `UNDERLYING_ZETHER`) and the post-quantum PQZ (`NONE_PQZ`, `UNDERLYING_PQZ`) (plan 5h D20, CTR-ZTH-45).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** One selector per function across both layers, no layer argument.
///         Ids are `bytes32` UAs. Every proof-taking entry point takes `(payload, proof, auth, beneficiary, accHint[,
///         …])`: PQZ — `auth` the signing UA's own signature over the statement digest, `beneficiary` equal to the
///         payload's (`BeneficiaryMismatch`), `accHint` the optional materialised `acc`; Zether — the proof alone
///         authorises (UA-6), so `auth` and `accHint` must be empty (`AuthNotEmpty`, `AccHintNotEmpty`). Layer-only
///         functions are in `IZetherToken` / `IPqzToken`. Events carry the fields of both layers; a field one layer
///         lacks is 0 there (Zether: `blob`, `accUnits`, `accHash`).
interface IConfidentialToken {
    /// @notice A shield: `amount` shielded units from `from`'s public units (or a leg's underlying) to `toUA`; `index` the
    ///         PQZ pending entry, Zether's `pendingSeq` after the credit. `from` is `_msgSender()`: `UA_POOL` for a UA signer.
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
    ///         `SHIELD_POOL` and credits `amount` to `toUA`; no proof.
    function mtxShield(bytes32 toUA, uint256 amount) external;
    /// @notice Multi-recipient, in the token's default storage mode.
    function mtxConfidentialTransfer(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint
    ) external returns (bytes32 entryRef);
    /// @notice Multi-recipient, commit-reveal on every token.
    function mtxConfidentialTransferCompact(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint
    ) external returns (bytes32 entryRef);
    /// @notice Single-recipient, in the token's default storage mode.
    function mtxConfidentialTransferSingle(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint
    ) external returns (bytes32 entryRef);
    /// @notice `amount` shielded units out as `amount · shieldScale` public units from `SHIELD_POOL` to `recipient`: a
    ///         native address as its zero-padded id, or a registered SIGNING UA (credited on the UA ledger); the pools
    ///         are refused. PQZ: `amount = 0` with `recipient = 0` is a refresh.
    function mtxUnshield(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint,
        uint256 amount,
        bytes32 recipient
    ) external;
    /// @notice Pending into `acc`: PQZ the next `n` entries (`1 ≤ n ≤ ROLL_MAX`), Zether its one aggregated pending for
    ///         any `n ≥ 1`.
    function mtxRollOver(bytes32 ua, uint256 n) external;
}

/// @title The two leg paths of the wrapper kinds `UNDERLYING_ZETHER` and `UNDERLYING_PQZ`, one selector each.
interface IConfidentialUnderlyingToken {
    /// @notice The leg of an unshield-unwrap: `amount` shielded units paid from leg `underlying`, at least `minOut` of it,
    ///         to `recipient` (a padded address or a derived UA). One calldata struct keeps the shared signature within
    ///         the legacy code generator's stack.
    struct Unwrap {
        address underlying;
        bytes32 recipient;
        uint256 amount;
        uint256 minOut;
    }

    /// @notice Pulls `amountIn` of leg `underlying` (native: `msg.value`) and credits its public-equivalent, a multiple of
    ///         `shieldScale`, to `toUA` (minted to `SHIELD_POOL`).
    function mtxWrapShield(address underlying, uint256 amountIn, bytes32 toUA) external payable;
    /// @notice `mtxUnshield`'s debit of `x.amount`, then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥ minOut`
    ///         to `x.recipient`: a native address, or a derived UA in the leg's own UA ledger (`transferToUA`;
    ///         `UALegNotLedger` otherwise).
    function mtxUnshieldUnwrap(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint,
        Unwrap calldata x
    ) external;
}
