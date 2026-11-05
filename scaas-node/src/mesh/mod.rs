//! Mesh relayer vòng 4 (`docs/history/specs/2026-10-05-relayer-mesh-design.md`). S3: thư viện thuần —
//! envelope `scaas-intent/1.2`, giải mã theo họ, chữ ký hub, nhận/từ chối (L0–L3) và bộ lọc xuất. Không mạng,
//! không store (store nằm sau trait `accept::Seen`).
use serde::{Deserialize, Serialize};

pub mod accept;
pub mod digest;
pub mod envelope;
pub mod export;
pub mod hubsig;

/// Mã kết quả ingest (spec §5.3). `Duplicate` không phải từ chối: no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    UnsupportedSpec,
    BadEnvelope,
    FamilyNotSupported,
    UnknownChain,
    Expired,
    ValidTooLong,
    HopLimit,
    DigestMismatch,
    BadSignature,
    RelayerBoundZero,
    BadHubSig,
    PrivateFromOpenPeer,
    Unsupported,
    /// R45: an address body (`meta_tx`) for an entry no contract has any more: an address `MetaTransfer`, or any address
    /// body on a registered token (CTR-MTX-30; the job API's name, R43).
    OpKindMismatch,
    /// MD-10: a derived `from` in a UA body; no peer check of a derived `UASig` is ruled yet.
    DerivedFromUnsupported,
    Duplicate,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedSpec => "UNSUPPORTED_SPEC",
            Self::BadEnvelope => "BAD_ENVELOPE",
            Self::FamilyNotSupported => "FAMILY_NOT_SUPPORTED",
            Self::UnknownChain => "UNKNOWN_CHAIN",
            Self::Expired => "EXPIRED",
            Self::ValidTooLong => "VALID_TOO_LONG",
            Self::HopLimit => "HOP_LIMIT",
            Self::DigestMismatch => "DIGEST_MISMATCH",
            Self::BadSignature => "BAD_SIGNATURE",
            Self::RelayerBoundZero => "RELAYER_BOUND_ZERO",
            Self::BadHubSig => "BAD_HUB_SIG",
            Self::PrivateFromOpenPeer => "PRIVATE_FROM_OPEN_PEER",
            Self::Unsupported => "UNSUPPORTED",
            Self::OpKindMismatch => "OP_KIND_MISMATCH",
            Self::DerivedFromUnsupported => "DERIVED_FROM_UNSUPPORTED",
            Self::Duplicate => "DUPLICATE",
        }
    }
}

/// `open < private < none`: `max` là "chặt nhất" (§9). Số lưu store: 0, 1, 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Open,
    Private,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerClass {
    Open,
    Private,
}
