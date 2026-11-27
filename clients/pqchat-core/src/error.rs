// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `PqChatError` (spec §8): `code()` is the variant's name, stable and appended only. No variant carries anything of its own: no
//! input, key, handle, ciphertext, room id or Matrix id (CLI-PQC-03). The SDK's codes pass through by their own names. An error
//! comes back only for the user's own action; a received record that fails is a drop reason, never an error (CLI-PQC-07).
use scaas_sdk::SdkError;
use std::fmt;

macro_rules! codes {
    ($($(#[$m:meta])* $v:ident,)*) => {
        /// A `pqchat-core` error. `Display` and `Debug` are the code.
        #[non_exhaustive]
        pub enum PqChatError {
            $($(#[$m])* $v,)*
            /// An SDK error, by its own code.
            Sdk(SdkError),
        }

        /// The crate's own codes, in declaration order (appended only).
        pub const CODES: &[&str] = &[$(stringify!($v),)*];

        impl PqChatError {
            /// The stable code: the variant's name, or the SDK's code.
            pub fn code(&self) -> &'static str {
                match self {
                    $(PqChatError::$v => stringify!($v),)*
                    PqChatError::Sdk(e) => e.code(),
                }
            }
            /// Every own variant, for the tests of the names.
            pub fn own_variants() -> Vec<PqChatError> {
                vec![$(PqChatError::$v,)*]
            }
        }
    };
}

codes! {
    /// a `PqChat` address the chain's factory does not list as class 3 with version ≠ 0
    InstanceUnlisted,
    /// no such session at a listed, reachable home
    SessionUnknown,
    /// an action on a session the user has not accepted
    SessionPending,
    /// the account is not a member of the latest epoch (or left, or was removed)
    NotMember,
    /// a membership change without admin rights at the parent
    NotAdmin,
    /// a member without a usable KEM key (none, or `checkedOf.kem` `NONE`)
    KemKeyMissing,
    /// P14 refused the key
    KemKeyInvalid,
    /// a KEM version below the highest seen
    KemVersionLowered,
    /// fewer than 2 members, a duplicate, a non-holder kind, an `msig` seat with no KEM leaf
    MembersInvalid,
    /// a record whose author is an `msig` (CLI-PQC-02)
    MsigAuthorPlanned,
    /// no message store, duplicates, more than one Matrix entry
    StoreListInvalid,
    /// a listed store kind this build does not implement
    StoreUnsupported,
    /// a store changed by a rekey and not yet confirmed (CLI-PQC-06)
    StoreUnconfirmed,
    /// a chain store without the session's spend consent
    ChainCostUnconfirmed,
    /// no Matrix client attached
    MatrixDetached,
    /// the room cannot be created, joined or written, or is not bound to the session
    MatrixRoom,
    /// an invite or removal of an id not bound to its UA
    MatrixIdUnbound,
    /// the home already holds a complete child of the parent
    EpochTaken,
    /// the parent is not complete
    EpochIncomplete,
    /// a send held while a child is complete but not final
    EpochNotFinal,
    /// a content out of P49's bounds or out of scope
    ContentInvalid,
    /// above 16,000 B of text, or above the 1,024-B bucket on chain without the cost confirmation
    ContentTooLarge,
    /// an own chain at `2^64 − 1`
    CounterExhausted,
    /// the app's storage interface failed
    StoreIo,
    /// the item changed under the crate three times
    StoreConflict,
    /// no better name; carries nothing
    Internal,
    /// a contact card that does not count for its UA (UA-7 §14 O7, CLI-PQC-05)
    CardRefused,
    /// CLI-PQC-15: under `require_signed_records`, a home that keeps no signatures (`sigStore` `none`)
    HomeUnsigned,
    /// a leave or removal naming an epoch more than 16 below the home's head (C9, the contract's `PqChatExitLag`; D2-4)
    ExitLag,
    /// a tree call whose reads did not settle within its bound of read rounds (CLI-PQC-17)
    TreeReads,
    /// a tree creation over the chain's one-transaction cap, or a commit whose required piece does not fit (spec §13)
    TreeTooLarge,
    /// a tree session on a home that keeps no signatures (C1, the contract's `PqChatTreeSigStore`)
    TreeHomeNone,
    /// a commit whose pieces another sender landed out of order, so that the piece left cannot pay the completion: void,
    /// rebuilt with a new nonce (C37, codex-r3-12)
    TreeVoid,
    /// a changed session info whose head a strict majority of at least 3 named endpoints did not confirm (R13)
    TreeInfoUnconfirmed,
    /// an admin's new info after a gap, sealed without the admin's review of it (codex-r3-7)
    TreeInfoReview,
    /// a tree creation that did not complete and whose prepared record this store does not hold: it cannot be finished
    /// (codex-r3-5)
    TreeCreationIncomplete,
    /// a tree commit on a state whose head moved since (C33: replay first)
    TreeStale,
    /// a send under a tree epoch whose info in force the device does not hold (after a gap, or taken flagged: C33)
    TreeInfoMissing,
    /// a path commit while leaves are under review (a compromise warning or an author that did not hold the epoch names
    /// them), not acknowledged by the caller: nothing signed (the path-less delta §6.2, F-3)
    TreeLeavesUnderReview,
    /// a relayed write on a port or chain with no gateway to relay it (CLI-PQC-18 F3: the payer's own transaction is the
    /// option)
    RelayUnavailable,
}

impl fmt::Display for PqChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl fmt::Debug for PqChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for PqChatError {}

impl From<SdkError> for PqChatError {
    /// The SDK's code, except a KEM key that P14's checks refuse (`KemCheck`): `KemKeyInvalid`.
    fn from(e: SdkError) -> Self {
        if e.code() == "KemCheck" {
            return PqChatError::KemKeyInvalid;
        }
        PqChatError::Sdk(e)
    }
}

impl From<pqchat_transport::TransportError> for PqChatError {
    /// A transport call that failed: a room that cannot be created, joined or written (no room id or Matrix id in it).
    fn from(_: pqchat_transport::TransportError) -> Self {
        PqChatError::MatrixRoom
    }
}
