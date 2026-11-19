// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `SdkError` (spec §15, CLI-SDK-13): `code()` is the variant's name, stable and appended only. The SDK's own variants carry
//! nothing; the layers below pass through by their own codes (`Ua`, `Rpc`). `BroadcastRejected` is not an error (an outcome of
//! `scaas-rpc`'s send, shown in an operation's state), so no variant has that name.

macro_rules! own_codes {
    ($($(#[$m:meta])* $v:ident,)*) => {
        /// An SDK error. `Display` is the code; no variant carries an input, a URL, a body, a key or a ciphertext.
        #[derive(Debug)]
        #[non_exhaustive]
        pub enum SdkError {
            $($(#[$m])* $v,)*
            /// A `scaas-ua` wallet error, by its own code.
            Ua(scaas_ua::wallet::Error),
            /// A `scaas-rpc` error, by its own code (its text redacted by `scaas-rpc`, CLI-RPC-11).
            Rpc(scaas_rpc::RpcError),
        }

        /// The SDK's own codes, in declaration order.
        pub const OWN_CODES: &[&str] = &[$(stringify!($v),)*];

        impl SdkError {
            /// The stable code: the variant's name, or the lower layer's code.
            pub fn code(&self) -> &'static str {
                match self {
                    $(SdkError::$v => stringify!($v),)*
                    SdkError::Ua(e) => e.code(),
                    SdkError::Rpc(e) => e.code(),
                }
            }
            /// Every own variant, for the tests of the names.
            pub fn own_variants() -> Vec<SdkError> {
                vec![$(SdkError::$v,)*]
            }
        }
    };
}

own_codes! {
    /// A malformed input or configuration (the meaning `scaas-ua` and `scaas-rpc` give the same name).
    Argument,
    /// The keystore's `format` or `v` is not `scaas.keystore` / 1 (the meaning of `scaas-ua`'s vault `VaultVersion`).
    VaultVersion,
    VaultFormat,
    VaultIo,
    StoreConflict,
    KeystoreMismatch,
    KeystoreRollback,
    AccountUnverified,
    SeedUnknown,
    SeedExists,
    LabelTaken,
    ConfirmationMissing,
    MnemonicInvalid,
    VaultPassphraseWeak,
    DerivationPassphraseShort,
    OriginSignature,
    AuthenticatorRefused,
    ChainUnknown,
    ProfileMismatch,
    FeatureMissing,
    PreparedStale,
    PreparedUnknown,
    OpaqueCallRefused,
    FeeAboveCap,
    GasAboveTxCap,
    PayerDelegated,
    SubmitPathNone,
    VerdictRefused,
    TxTypeRefused,
    RawDigestRefused,
    AppDomainRefused,
    AppPurposeRefused,
    AppSaltMismatch,
    AppHandleForeign,
    AppLabelRefused,
    AppKeyUsage,
    AppArenaFull,
    KemKeyGone,
    ReceiverUnregistered,
    RegistrationUaMismatch,
    RegistrationKindDisabled,
    RegistrationPopInvalid,
    RegistrationKemMissing,
    AbiMismatch,
    /// No better name (a failed task included); carries nothing.
    Internal,
    /// An account row whose key (the same UA, native key or watched id) the seed lists already (owner 2026-11-18, Q1).
    AccountExists,
    /// A relayed operation's quote found no row of the gas table for its key (entry, domain kind, signer kind, fresh lane;
    /// owner 2026-11-18, ruling 1; owner 2026-11-19, ruling B).
    GasUnquoted,
    /// An operation's `validUntil` already past on the SDK's clock, or further ahead than the chain's window (owner 2026-11-19,
    /// T13b ruling 1).
    ValidUntilRefused,
    /// A gas table's verify row without `sig_bytes` (owner 2026-11-19, A4): every verify row states its signature's length.
    GasSigBytesMissing,
    /// A self-relay whose gas, recomputed after signing from the signed calldata (the real signature's length; owner
    /// 2026-11-19, G3), exceeds `Limits::max_gas`: nothing written or sent.
    SignedGasAboveCap,
    /// A gas table's row with `per_item` but no `item`, or the reverse (owner 2026-11-19, I1).
    GasItemUnpaired,
    /// A gas table's row whose `item` names no count the SDK reads (owner 2026-11-19, I1).
    GasItemUnknown,
    /// An operation whose gas row grows with a count (`per_item`) that the SDK cannot read from the operation, or above
    /// 65,536 (owner 2026-11-19, I1): refused, never quoted without it.
    GasCountUnknown,
    /// A gas table with a key outside the format, at the top, on a row or inside a row's part (PR A review, finding 1): an
    /// unknown part is refused, never dropped from a quote.
    GasFieldUnknown,
}

/// Own codes that are also a lower layer's code, with the same meaning (the test holds every other own code apart from theirs).
pub const SHARED_CODES: &[&str] = &["Argument", "VaultVersion"];

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SdkError {}

impl From<scaas_ua::wallet::Error> for SdkError {
    fn from(e: scaas_ua::wallet::Error) -> Self {
        SdkError::Ua(e)
    }
}

impl From<scaas_rpc::RpcError> for SdkError {
    fn from(e: scaas_rpc::RpcError) -> Self {
        SdkError::Rpc(e)
    }
}
