// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IConfidentialToken, IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @notice Group 3f (PQZ verifier mode spec §4.3): the owner revoked a transferable verifier at once (`previous` the old
///         one, `pqzVerifierEpoch` the new epoch). At file level because the error of the same name, every proof-carrying
///         op's refusal after it, is `IPqzToken`'s (one name for both, spec §4.3).
event PqzVerifierRevoked(bytes32 previous, uint32 pqzVerifierEpoch);

/// @title Events, errors, the account view and the PQZ-only entry points of the PQZ layer (pq-zero-knowledge.md §7.1,
///        §7.8, §9.4); the shared entry points and events are `IConfidentialToken`'s (plan 5h D20).
/// @notice **UNAUDITED.** `bytes32` ids are signing UAs holding a PQZ key (UA-6 U7). The debits take explicit parameters
///         (TS-D17); `pqzAuth` is the holder's own signature over the typed `PqzAuth` of the statement (TS-D19), and the
///         signed overloads (`UAEnvelope`, `UASig`; R36) are `PqzLayer`'s (TS-D14, TS-D16).
interface IPqzToken is IConfidentialToken {
    /// @notice The explicit parameters of op 1 (Appendix X.2): each `u`, `v` a ciphertext part of `PK` or `V` bytes in
    ///         64-bit lanes. `vAuditor` empty: auditor off. `sealedMemo` the memo after its clear salt, 41 bytes on
    ///         commit-reveal (the memo is `salt ‖ sealedMemo`), else empty. `ownTag` (group 3h, pqz-proof-path spec §3,
    ///         PP-3): the holder's tag of its own `(u, v_f)`, computed by its client, stored in the op blob's tail and bound
    ///         by `memoHash = keccak256(memo ‖ ownTag)`; the contract checks no value.
    struct PqzTransferArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        uint64 keyVersion; // group 3g (KV-8): the debited key version of `fromUA`
        bytes32 toUA;
        bytes32 beneficiaryUA;
        bytes16 salt;
        bytes32 ownTag;
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
        uint64 keyVersion;
        bytes32 beneficiaryUA;
        uint256 decoyFee;
        bytes16 salt;
        bytes32 ownTag; // group 3h (PP-3), as `PqzTransferArgs.ownTag`
        bytes[] u;
        PqzLeg[] legs;
        bytes vFrom;
        bytes sealedMemo;
    }

    /// @notice A burn, refresh or unshield-unwrap: the amount and the recipient are the entry's. `ownTag` (group 3h, PP-3):
    ///         as `PqzTransferArgs.ownTag`, over `(u', v_f)`.
    struct PqzBurnArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        uint64 keyVersion;
        bytes32 beneficiaryUA;
        bytes32 ownTag;
        bytes u;
        bytes vFrom;
    }

    /// @notice Group 3f (PQZ verifier mode spec §5.1, AV-5): what the token's verifier UA signs, typed EIP-712 in the token's
    ///         own domain under `PURPOSE_PQZ_VERDICT`: the statement the token built (`statementHash = keccak256` of the
    ///         bytes its statement views return) and the exact proof (`proofHash = keccak256(proof)`), the token, the chain,
    ///         the release's `proofSystemId`, the verifier epoch (a signature dies at every verifier change, A -> B -> A
    ///         included) and `validUntil` (unix seconds, the verifier's own life). Empty (every field 0, an empty `UASig`)
    ///         on a `PRECOMPILE` token, which never reads it.
    struct PqzVerdict {
        address token;
        uint256 chainId;
        bytes32 proofSystemId;
        bytes32 statementHash;
        bytes32 proofHash;
        uint32 pqzVerifierEpoch;
        uint64 validUntil;
    }

    /// @notice The verdict and the verifier's signature over it, last on every proof-carrying entry and the verdict form of
    ///         `verifyTransferAmount` (spec §5.3: one named struct, the legacy code generator's stack; still explicit).
    struct PqzSignedVerdict {
        PqzVerdict pqzVerdict;
        IUARegistry.UASig sig;
    }

    /// @notice `pqzVerifyConfig()` (spec §4.4), for wallets and the node: the mode, the verifier (0: revoked, or a
    ///         `PRECOMPILE` token), fixed or transferable, the epoch, a pending transfer and its `eta`, the notice period
    ///         stored at init (the factory's `noticePeriod()`).
    struct PqzVerifyConfig {
        uint8 pqzVerifyMode;
        bytes32 verifier;
        bool fixed_;
        uint32 pqzVerifierEpoch;
        bytes32 pending;
        uint64 eta;
        uint64 noticePeriod;
    }

    /// @notice `amount` and `recipient` of the signed `mtxUnshield`: one calldata struct keeps those two
    ///         within the legacy code generator's stack (evm-size-levers.md §7); the signed struct keeps both fields flat.
    struct Payout {
        uint256 amount;
        bytes32 recipient;
    }

    /// @notice `pqzAccount` (pq-zero-knowledge.md §9.4; plan 5h D2 / D3, D13; per key version since group 3g, `sendCounter`
    ///         the UA's, one for every version): the counters, the `acc` reference (`accBlob`,
    ///         0 for `Trivial(0)`; ignored while `flags & 1`, the materialised `acc`), `flags` (1 MATERIALISED, 2 / 4 the
    ///         prepared halves), `accHash` (the keccak of the materialised `acc`'s
    ///         packed stream, P46: `PqzCt.CTP` bytes; stale once a debit clears flag 1), `lastDebit` (group 3h, PP-2: the
    ///         counter + 1 of this account's last debit, 0 = none; `accBlob` is that debit's blob).
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
        uint64 lastDebit;
    }

    /// @notice `pqzDebitRecord` (group 3h, pqz-proof-path spec §2.2, PP-2): the debit of `(ua, counter)` as recorded:
    ///         `prevBlob` the same `(ua, keyVersion)` account's previous debit's blob (0 for its first), `p`, `deltaP = p −
    ///         p_prev` (`p_prev` that debit's `p`, 0 for the first), the `proofStore` in force, `shieldIn`, the debited
    ///         `keyVersion`, `prevCounter` the counter of that previous debit (`hasPrev` false: none, `prevCounter` 0).
    ///         `T` of the debit is `prevBlob`'s `(u, v_f)` + `pending[ua][keyVersion][p − deltaP, p)` +
    ///         `Trivial(digits(shieldIn))` (spec §2.3).
    struct DebitRecordView {
        address prevBlob;
        uint64 p;
        uint16 deltaP;
        uint8 proofStore;
        uint64 shieldIn;
        uint64 keyVersion;
        uint64 prevCounter;
        bool hasPrev;
    }

    /// @notice Proven credit `index` of `(ua, keyVersion)` (group 3g: the receiver's current version); its bytes `u ‖ v_t`
    ///         are in state (`pqzPendingCt`, the op blob of `entryRef`; plan 5h D1 / D2).
    event Credited(bytes32 indexed ua, uint64 indexed index, uint64 keyVersion, bytes32 entryRef);
    /// @notice Every debit (D12, review N4) of `(ua, keyVersion)`: `rolled = floor = p`, `acc` now references `blob` (the op
    ///         blob).
    event Debited(bytes32 indexed ua, uint64 keyVersion, uint64 rolled, uint64 floor, address blob);
    /// @notice A rollover of `(ua, keyVersion)` (group 3g, in place of the shared `RolledOver`).
    event PqzRolledOver(bytes32 indexed ua, uint64 indexed keyVersion, uint64 rolled, uint32 accUnits, bytes32 accHash);

    error BadInit();
    /// @notice `init` with the PQZH proof system at a set without PQZH value tokens (`PqzSet.PQZH_VALUE`): no debit of
    ///         such a token fits one transaction (C2-1; owner 2026-10-27, C0-2).
    error PqzhValueUnsupported();
    /// @notice A PQZH value token refuses a holder that is not a single-key `mldsa44` / `mldsa65` / `fndsa512` / `mldsa87` /
    ///         `fndsa1024` UA on every entry that creates its pending entry (shield, op 1 and op 7 legs; owner 2026-10-27, C0-2).
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
    /// @notice Group 3g (KV-9): two keys a statement names are equal (`ua` the owner of the later one).
    error KeyReused(bytes32 ua);
    /// @notice Group 3g (KV-8): a debit of a stale version other than the migration (op 1 to itself) or a refresh.
    error StaleKeyVersion(bytes32 ua, uint64 keyVersion, uint64 current);
    /// @notice Group 3g (KV-8, KV-11): a key version above current (a debit), or not stored (a disclosure).
    error KeyVersionUnknown(bytes32 ua, uint64 keyVersion);
    /// @notice Group 3h (PP-2): no debit of `ua` with this counter (`counter ≥ sendCounter`).
    error DebitRecordUnknown(bytes32 ua, uint64 counter);
    /// @notice Group 3h (PP-4): a `proofStore` other than 0 `NONE` and 1 `LOG`.
    error ProofStoreInvalid(uint8 proofStore);
    /// @notice Group 3h (spec §4.2, PP-4, C7): under `proofStore` `LOG`, each debit's verified statement header (its first 640
    ///         bytes) and the calldata proof, `blob` the debit's op blob, `sendCounter` its counter (the record's key).
    event PqzDebitProof(address indexed blob, bytes32 indexed ua, uint64 indexed sendCounter, bytes header, bytes proof);

    // ---- group 3f, PQZ verifier mode (spec §3-§5; CTR-PQZ-27..29 drafts)
    /// @notice An accepted proof in `OFFCHAIN` mode: the verifier's verdict over `statementHash` and `proofHash` at its epoch.
    event PqzVerified(bytes32 statementHash, bytes32 proofHash, bytes32 verifier, uint32 pqzVerifierEpoch);
    /// @notice A transfer of the verifier proposed by the owner; confirmable by its proposer in `[eta, eta + noticePeriod]`.
    event PqzVerifierProposed(bytes32 current, bytes32 next, uint64 eta);
    /// @notice The verifier, its shape and its epoch written (a confirmed transfer, or at once with a notice period 0).
    event PqzVerifierSet(bytes32 previous, bytes32 next, uint32 pqzVerifierEpoch);
    /// @notice A live pending transfer deleted by the owner.
    event PqzVerifierCancelled(bytes32 next);

    /// @notice `ConfidentialConfig.pqzVerifyMode` neither 0 `PRECOMPILE` nor 1 `OFFCHAIN`.
    error PqzVerifyModeInvalid(uint8 mode);
    /// @notice A verifier field set against the mode (`PRECOMPILE` with a verifier or fixed, `OFFCHAIN` without one), or a
    ///         verifier op on a `PRECOMPILE` token.
    error PqzVerifyConfigInvalid();
    /// @notice A derived verifier not registered on this chain's registry (`kindOf = 0`).
    error PqzVerifierUnregistered(bytes32 ua);
    /// @notice A verifier (or an `msig` verifier's member) of a kind outside spec §4.1's table: `mldsa87`, the EIP-2537 and
    ///         bn254 kinds, `zether-bls12381`, a native id with code (`EVM_CONTRACT`), a nested `msig`, ...
    error PqzVerifierKind(uint16 kind);
    /// @notice A fixed verifier: no transfer, no revocation (owner 2026-11-06, Q1).
    error PqzVerifierFixed();
    /// @notice A transfer to the current verifier.
    error PqzVerifierSame();
    /// @notice The verifier's shape (a native id's code, an `msig`'s structure, accepted slots, native members' code) is not
    ///         the one frozen at its assignment: every `OFFCHAIN` proof refuses until a transfer re-assigns.
    error PqzVerifierChanged();
    /// @notice The verifier was revoked: every proof-carrying op refuses until a transfer sets a new one.
    error PqzVerifierRevoked();
    /// @notice The confirm of a transfer before its `eta`.
    error PqzVerifierNotReady(uint64 eta);
    /// @notice Another verifier proposed while `pending` is live.
    error PqzVerifierPending(bytes32 pending);
    /// @notice The five-argument disclosure (`verifyTransferAmount` without a verdict) on an `OFFCHAIN` token: cannot verify.
    error PqzVerdictRequired();
    /// @notice The verifier's signature over the verdict refused by the registry.
    error PqzVerdictRejected();
    /// @notice A verdict field not the token's: `field` its index in `PqzVerdict` (0 token, 1 chainId, 2 proofSystemId,
    ///         3 statementHash, 4 proofHash, 5 pqzVerifierEpoch, 6 validUntil: below the block's timestamp).
    error PqzVerdictMismatch(uint8 field);

    /// @notice Multi-recipient, in the token's default storage mode. Every proof-carrying entry takes the verdict pair last
    ///         (group 3f, spec §5.3): empty and never read on a `PRECOMPILE` token, required on an `OFFCHAIN` one.
    function mtxConfidentialTransfer(PqzMultiArgs calldata t, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, PqzSignedVerdict calldata pqzVerdict) external returns (bytes32 entryRef);
    /// @notice Multi-recipient, commit-reveal on every token.
    function mtxConfidentialTransferCompact(PqzMultiArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, PqzSignedVerdict calldata pqzVerdict) external returns (bytes32 entryRef);
    /// @notice Single-recipient, in the token's default storage mode.
    function mtxConfidentialTransferSingle(PqzTransferArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, PqzSignedVerdict calldata pqzVerdict) external returns (bytes32 entryRef);
    /// @notice Single-recipient, commit-reveal on every token.
    function mtxConfidentialTransferSingleCompact(PqzTransferArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, PqzSignedVerdict calldata pqzVerdict) external returns (bytes32 entryRef);
    /// @notice `amount` shielded units out as `amount · shieldScale` public units from `SHIELD_POOL` to `recipient`: a
    ///         native address as its zero-padded id, or a registered SIGNING UA (credited on the UA ledger); the pools
    ///         are refused. PQZ: `amount = 0` with `recipient = 0` is a refresh.
    function mtxUnshield(PqzBurnArgs calldata b, uint256 amount, bytes32 recipient, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, PqzSignedVerdict calldata pqzVerdict) external;
    /// @notice The account of `(ua, keyVersion)` (pq-zero-knowledge.md §9.4): counters, the `acc` reference, `accUnits`, flags,
    ///         the UA's `sendCounter`, `accHash`, `lastDebit` (group 3h).
    function pqzAccount(bytes32 ua, uint64 keyVersion) external view returns (AccountState memory);
    /// @notice Group 3h (PP-2): the record of `ua`'s debit with counter `counter` (`DebitRecordUnknown` without one).
    function pqzDebitRecord(bytes32 ua, uint64 counter) external view returns (DebitRecordView memory);
    /// @notice Group 3h (PP-4): the `proofStore` the next debit runs under, 0 `NONE` or 1 `LOG` (absent before 3h: the release
    ///         probe, C9).
    function proofStore() external view returns (uint8);
    /// @notice Pending slot `i` of `(ua, keyVersion)`: `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)`, for every `i <
    ///         pendingCount` (group 3h PP-1: kept for good); 0 for an unwritten index.
    function pqzPending(bytes32 ua, uint64 keyVersion, uint64 i) external view returns (uint256);
    /// @notice The `acc` ciphertext of `(ua, keyVersion)` from state.
    function pqzAcc(bytes32 ua, uint64 keyVersion) external view returns (bytes memory);
    /// @notice Entry `i` of `(ua, keyVersion)` as a ciphertext from state.
    function pqzPendingCt(bytes32 ua, uint64 keyVersion, uint64 i) external view returns (bytes memory);
    /// @notice The op blob of a transfer as stored (empty if unknown).
    function pqzEntryBlob(bytes32 entryRef) external view returns (bytes memory);
    /// @notice Anyone: the next `n` entries (`1 ≤ n ≤ ROLL_MAX`) of `(ua, keyVersion)` into its `acc` (group 3g, KV-10;
    ///         `IConfidentialToken`'s two-argument form is Zether's only).
    function mtxRollOver(bytes32 ua, uint64 keyVersion, uint256 n) external;
    /// @notice Anyone, once per account and half (0, 1) before its first rollover (idempotent; plan 5h D8), per key version.
    function mtxPrepareAcc(bytes32 ua, uint64 keyVersion, uint256 half) external;
    /// @notice Group 3f (spec §4.2-§4.4): the owner's verifier transfer (propose, confirm after the notice), its cancel,
    ///         the immediate revocation; the verifier's configuration.
    function pqzSetVerifier(bytes32 next) external;
    function pqzCancelVerifier() external;
    function pqzRevokeVerifier() external;
    function pqzVerifyConfig() external view returns (PqzVerifyConfig memory);
}

/// @title `mtxUnshieldUnwrap` of `WRAPPED_PQZ`, its explicit form (typed-signing Appendix X.3).
interface IPqzWrappedToken is IConfidentialWrappedToken {
    /// @notice `mtxUnshield`'s debit of `x.amount`, then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥ minOut`
    ///         to `x.recipient`: a native address, or a derived UA in the leg's own UA ledger (`transferToUA`;
    ///         `UALegNotLedger` otherwise).
    function mtxUnshieldUnwrap(IPqzToken.PqzBurnArgs calldata b, Unwrap calldata x, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) external;
}
