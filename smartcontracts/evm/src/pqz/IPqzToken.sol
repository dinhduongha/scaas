// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IConfidentialToken, IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title Events, errors, the account view and the PQZ-only entry points of the PQZ layer (pq-zero-knowledge.md §7.1,
///        §7.8, §9.4); the shared entry points and events are `IConfidentialToken`'s (plan 5h D20).
/// @notice **UNAUDITED.** `bytes32` ids are signing UAs holding a PQZ key (UA-6 U7). The debits take explicit parameters
///         (TS-D17); `pqzAuth` is the holder's own signature over the typed `PqzAuth` of the statement (TS-D19), and the
///         signed overloads and `ua*` twins are `PqzLayer`'s (TS-D14, TS-D16).
interface IPqzToken is IConfidentialToken {
    /// @notice The explicit parameters of op 1 (Appendix X.2): each `u`, `v` a ciphertext part of `PK` or `V` bytes in
    ///         64-bit lanes. `vAuditor` empty: auditor off. `sealedMemo` the memo after its clear salt, 41 bytes on
    ///         commit-reveal (the memo is `salt ‖ sealedMemo`), else empty.
    struct PqzTransferArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        bytes32 toUA;
        bytes32 beneficiaryUA;
        bytes16 salt;
        bytes u;
        bytes vTo;
        bytes vFrom;
        bytes vAuditor;
        bytes sealedMemo;
    }

    /// @notice An op 7 leg: its UA with its parts. `vAuditor` empty on every leg (auditor off) or on none.
    struct PqzLeg {
        bytes32 ua;
        bytes v;
        bytes vAuditor;
    }

    /// @notice Op 7; `M` is `legs.length`. `u`: `G` randomness groups, `⌈M / S_AUD⌉` with the auditor, `⌈M / 4⌉` without.
    ///         `sealedMemo` `2 + 40·M` bytes on commit-reveal, else empty.
    struct PqzMultiArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        bytes32 beneficiaryUA;
        uint256 decoyFee;
        bytes16 salt;
        bytes[] u;
        PqzLeg[] legs;
        bytes vFrom;
        bytes sealedMemo;
    }

    /// @notice A burn, refresh or unshield-unwrap: the amount and the recipient are the entry's.
    struct PqzBurnArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        bytes32 beneficiaryUA;
        bytes u;
        bytes vFrom;
    }

    /// @notice `amount` and `recipient` of the signed `mtxUnshield` and `uaUnshield`: one calldata struct keeps those two
    ///         within the legacy code generator's stack (evm-size-levers.md §7); the signed struct keeps both fields flat.
    struct Payout {
        uint256 amount;
        bytes32 recipient;
    }

    /// @notice `pqzAccount` (pq-zero-knowledge.md §9.4; plan 5h D2 / D3, D13): the counters, the `acc` reference (`accBlob`,
    ///         0 for `Trivial(0)`; ignored while `flags & 1`, the materialised `acc`), `flags` (1 MATERIALISED, 2 / 4 the
    ///         prepared halves), `accHash` (the keccak of the materialised `acc`'s
    ///         packed stream, P46: `PqzCt.CTP` bytes; stale once a debit clears flag 1).
    struct AccountState {
        uint64 pendingCount;
        uint64 rolled;
        uint64 floor;
        uint64 cleared;
        address accBlob;
        uint32 accUnits;
        uint8 flags;
        uint64 sendCounter;
        bytes32 accHash;
    }

    /// @notice Proven credit `index` of `ua`; its bytes `u ‖ v_t` are in state (`pqzPendingCt`, the op blob of
    ///         `entryRef`; plan 5h D1 / D2).
    event Credited(bytes32 indexed ua, uint64 indexed index, bytes32 entryRef);
    /// @notice Every debit (D12, review N4): `rolled = floor = p`, `acc` now references `blob` (the op blob).
    event Debited(bytes32 indexed ua, uint64 rolled, uint64 floor, address blob);

    error BadInit();
    /// @notice `init` with the PQZH proof system at a set without PQZH value tokens (`PqzSet.PQZH_VALUE`): no debit of
    ///         such a token fits one transaction (C2-1; owner 2026-10-27, C0-2).
    error PqzhValueUnsupported();
    /// @notice A PQZH value token refuses a holder that is not a single-key `mldsa44` / `mldsa65` / `fndsa512` UA on
    ///         every entry that creates its pending entry (shield, op 1 and op 7 legs; owner 2026-10-27, C0-2).
    error PqzhHolderKind(bytes32 ua, uint16 kind);
    error BadDisclosureMode(uint8 mode);
    error BadAuditorMode(uint8 mode);
    error AccountNotRegistered(bytes32 ua);
    error AmountOutOfRange(uint256 amount, uint256 max);
    error AmountNotScaled(uint256 minted, uint256 shieldScale);
    /// @notice A part of the wrong length for the op, the form or the auditor copies (`length`, its length).
    error BadPayload(uint256 length);
    error NonCanonical();
    error Expired(uint256 validUntilBlock);
    error SelfTransfer();
    error BadRecipientCount(uint256 legs);
    error DuplicateRecipient(bytes32 ua);
    error ZeroRecipient();
    error RefreshRecipient(bytes32 recipient);
    error PendingRange(uint256 p, uint256 floor, uint256 pendingCount);
    error InlineTooFar(uint256 n);
    error UnitsInvariant();
    error AuditorRequired();
    error AuditorForbidden();
    /// F-4: with the auditor copies on, the auditor UA is neither the sender nor a recipient (op 1, op 7)
    error AuditorAsParty(bytes32 ua);
    error TransferEntryDisabled(uint8 disclosureMode);
    error AuthRejected();
    error ProofRejected();
    error RollOverRange(uint256 n);
    /// @notice `acc` holds `K_MAX − 1` units: refresh (plan 5h D8).
    error CapReached(bytes32 ua);
    /// @notice Entry `index` is younger than `ROLL_AGE` blocks (D6).
    error RollTooYoung(uint256 index);
    /// @notice A rollover before `mtxPrepareAcc` wrote both halves of the account's `acc` words (D8).
    error AccNotPrepared(bytes32 ua);
    /// @notice A shared `u` (any `u_g`, a burn's `u'`) all zero (D24, Codex T2 CHAIN-01).
    error ZeroU();
    error UnknownEntry(bytes32 entryRef);
    /// @notice An op 7 `decoyFee` below the token's `minDecoyFee`, or `≥ 2^64` (owner 2026-10-20).
    error DecoyFeeOutOfRange(uint256 decoyFee, uint256 minDecoyFee);

    /// @notice Multi-recipient, in the token's default storage mode.
    function mtxConfidentialTransfer(PqzMultiArgs calldata t, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint) external returns (bytes32 entryRef);
    /// @notice Multi-recipient, commit-reveal on every token.
    function mtxConfidentialTransferCompact(PqzMultiArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint) external returns (bytes32 entryRef);
    /// @notice Single-recipient, in the token's default storage mode.
    function mtxConfidentialTransferSingle(PqzTransferArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint) external returns (bytes32 entryRef);
    /// @notice Single-recipient, commit-reveal on every token.
    function mtxConfidentialTransferSingleCompact(PqzTransferArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint) external returns (bytes32 entryRef);
    /// @notice `amount` shielded units out as `amount · shieldScale` public units from `SHIELD_POOL` to `recipient`: a
    ///         native address as its zero-padded id, or a registered SIGNING UA (credited on the UA ledger); the pools
    ///         are refused. PQZ: `amount = 0` with `recipient = 0` is a refresh.
    function mtxUnshield(PqzBurnArgs calldata b, uint256 amount, bytes32 recipient, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint) external;
    /// @notice The account (pq-zero-knowledge.md §9.4): counters, the `acc` reference, `accUnits`, flags, `sendCounter`, `accHash`.
    function pqzAccount(bytes32 ua) external view returns (AccountState memory);
    /// @notice Pending slot `i`: `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)`; 0 once deleted.
    function pqzPending(bytes32 ua, uint64 i) external view returns (uint256);
    /// @notice The `acc` ciphertext from state.
    function pqzAcc(bytes32 ua) external view returns (bytes memory);
    /// @notice Entry `i` as a ciphertext from state.
    function pqzPendingCt(bytes32 ua, uint64 i) external view returns (bytes memory);
    /// @notice The op blob of a transfer as stored (empty if unknown).
    function pqzEntryBlob(bytes32 entryRef) external view returns (bytes memory);
    /// @notice Anyone, once per account and half (0, 1) before its first rollover (idempotent; plan 5h D8).
    function mtxPrepareAcc(bytes32 ua, uint256 half) external;
}

/// @title `mtxUnshieldUnwrap` of `WRAPPED_PQZ`, its explicit form (typed-signing Appendix X.3).
interface IPqzWrappedToken is IConfidentialWrappedToken {
    /// @notice `mtxUnshield`'s debit of `x.amount`, then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥ minOut`
    ///         to `x.recipient`: a native address, or a derived UA in the leg's own UA ledger (`transferToUA`;
    ///         `UALegNotLedger` otherwise).
    function mtxUnshieldUnwrap(IPqzToken.PqzBurnArgs calldata b, Unwrap calldata x, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint) external;
}
