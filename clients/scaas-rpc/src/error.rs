// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Errors (docs/clients/scaas-rpc.md §8; spec §8): named, stable codes; `code()` is the variant's name, the same names the app's
//! endpoint lists use. An error never carries a URL, a body, a key or a ciphertext (CLI-RPC-11): every text an endpoint sent back
//! goes through [`endpoint_text`] (URLs redacted, control characters removed, at most 256 bytes).

use crate::endpoint::redact_urls;

/// The most bytes of an endpoint's own text an error or a log line keeps (CLI-RPC-11, F21).
pub const TEXT_MAX: usize = 256;

/// `s` as it may appear in an error or a log line: each `scheme://…` token `<url>`, control characters removed, cut to
/// [`TEXT_MAX`] bytes at a character boundary.
pub fn endpoint_text(s: &str) -> String {
    let mut out: String = redact_urls(s).chars().filter(|c| !c.is_control()).collect();
    if out.len() > TEXT_MAX {
        let mut cut = TEXT_MAX;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
    }
    out
}

/// Why one endpoint did not answer a read (inside [`RpcError::EndpointAllFailed`] and [`RpcError::EndpointNoMajority`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Transport,
    Timeout,
    Http,
    AnswerTooLarge,
    AnswerTooDeep,
    AnswerMalformed,
    WrongChain,
    IdentityUnread,
    /// it serves no block 0 and its entry names no checkpoint it matches: refused (T13 S16), never trusted on a pin alone
    ChainIdentityUnreadable,
    BehindHead,
    BlockChanged,
    /// a revert from an endpoint after the first used: no verdict (CLI-RPC-04); its data is kept
    FailoverRevert,
    /// the answer failed the caller's check (an Arweave object whose SHA-256 is not `ctSha256`, CLI-RPC-13:
    /// `EndpointAnswerRefused`): that endpoint's failure, so failover moves on
    AnswerRefused,
}

/// One endpoint's failure: its index and label, the kind, a short redacted text; a failover endpoint's revert keeps its data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointFailure {
    pub endpoint: usize,
    pub label: Option<String>,
    pub kind: FailureKind,
    text: String,
    pub revert_data: Option<Vec<u8>>,
}

impl EndpointFailure {
    pub fn new(endpoint: usize, kind: FailureKind, text: &str) -> Self {
        Self {
            endpoint,
            label: None,
            kind,
            text: endpoint_text(text),
            revert_data: None,
        }
    }
    pub fn with_label(mut self, label: Option<&str>) -> Self {
        self.label = label.map(str::to_string);
        self
    }
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Display for EndpointFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "endpoint {}", self.endpoint)?;
        if let Some(l) = &self.label {
            write!(f, " ({l})")?;
        }
        write!(f, ": {:?}: {}", self.kind, self.text)
    }
}

/// The crate's errors, by code (docs/clients/scaas-rpc.md §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// a URL that is not `http` or `https`
    EndpointScheme,
    /// a list with no endpoint
    EndpointListEmpty,
    /// failover: no endpoint answered the whole read; the last failure, and a later endpoint's revert data if one reverted
    EndpointAllFailed {
        last: Option<EndpointFailure>,
        failover_revert: Option<Vec<u8>>,
    },
    /// strict majority: no `need` equal complete answers at one block after the fallback round
    EndpointNoMajority {
        n: usize,
        need: usize,
        largest: usize,
        failures: Vec<EndpointFailure>,
    },
    /// a read that feeds a decryption with no `named` or `default` endpoint to serve it
    NoTrustedEndpoint,
    /// the same under strict majority with a `discovered` endpoint and `n < 3`
    AgreementNeedsThree,
    /// a pinned read on a chain whose pinned reads are not trusted (the profile's `pinnedReads` false)
    PinnedReadsUntrusted,
    /// the first endpoint's revert (failover) or the agreed revert (strict majority), its data as bytes
    Revert {
        endpoint: usize,
        data: Vec<u8>,
        reason: String,
    },
    /// a scaas-node's error contract (NODE-GW-06)
    NodeRefused {
        status: u16,
        code: String,
        detail: Option<String>,
        revert_data: Option<String>,
    },
    /// a node's `api` this client does not speak
    NodeApiVersion { api: String },
    /// a request above the route's body cap, refused before sending
    BodyTooLarge { len: usize, cap: usize },
    /// a malformed input or configuration
    Argument(String),
}

impl RpcError {
    /// The stable code: the variant's name.
    pub fn code(&self) -> &'static str {
        match self {
            RpcError::EndpointScheme => "EndpointScheme",
            RpcError::EndpointListEmpty => "EndpointListEmpty",
            RpcError::EndpointAllFailed { .. } => "EndpointAllFailed",
            RpcError::EndpointNoMajority { .. } => "EndpointNoMajority",
            RpcError::NoTrustedEndpoint => "NoTrustedEndpoint",
            RpcError::AgreementNeedsThree => "AgreementNeedsThree",
            RpcError::PinnedReadsUntrusted => "PinnedReadsUntrusted",
            RpcError::Revert { .. } => "Revert",
            RpcError::NodeRefused { .. } => "NodeRefused",
            RpcError::NodeApiVersion { .. } => "NodeApiVersion",
            RpcError::BodyTooLarge { .. } => "BodyTooLarge",
            RpcError::Argument(_) => "Argument",
        }
    }

    /// `Argument` with `why` (redacted and capped like an endpoint's text: a configuration error may quote a URL).
    pub fn argument(why: &str) -> Self {
        RpcError::Argument(endpoint_text(why))
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = self.code();
        match self {
            RpcError::EndpointAllFailed {
                last,
                failover_revert,
            } => {
                write!(f, "{code}")?;
                if let Some(l) = last {
                    write!(f, ": last {l}")?;
                }
                if failover_revert.is_some() {
                    write!(f, "; reverted on a failover endpoint, no verdict")?;
                }
                Ok(())
            }
            RpcError::EndpointNoMajority {
                n, need, largest, ..
            } => write!(f, "{code}: n {n}, need {need}, largest group {largest}"),
            RpcError::Revert {
                endpoint, reason, ..
            } => write!(f, "{code} (endpoint {endpoint}): {reason}"),
            RpcError::NodeRefused {
                status,
                code: c,
                detail,
                ..
            } => {
                write!(f, "{code}: HTTP {status} {c}")?;
                detail.as_ref().map_or(Ok(()), |d| write!(f, ": {d}"))
            }
            RpcError::NodeApiVersion { api } => write!(f, "{code}: api {api}"),
            RpcError::BodyTooLarge { len, cap } => write!(f, "{code}: {len} bytes, cap {cap}"),
            RpcError::Argument(why) => write!(f, "{code}: {why}"),
            _ => write!(f, "{code}"),
        }
    }
}

impl std::error::Error for RpcError {}
impl std::error::Error for EndpointFailure {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app's names (app-core contract §6: 17, 18, 19) are the codes.
    #[test]
    fn codes_are_the_app_names() {
        assert_eq!(RpcError::EndpointScheme.code(), "EndpointScheme");
        assert_eq!(
            RpcError::EndpointAllFailed {
                last: None,
                failover_revert: None
            }
            .code(),
            "EndpointAllFailed"
        );
        assert_eq!(
            RpcError::EndpointNoMajority {
                n: 3,
                need: 2,
                largest: 1,
                failures: vec![]
            }
            .code(),
            "EndpointNoMajority"
        );
        assert_eq!(RpcError::EndpointListEmpty.code(), "EndpointListEmpty");
        assert_eq!(RpcError::NoTrustedEndpoint.code(), "NoTrustedEndpoint");
        assert_eq!(
            RpcError::PinnedReadsUntrusted.code(),
            "PinnedReadsUntrusted"
        );
        assert_eq!(RpcError::AgreementNeedsThree.code(), "AgreementNeedsThree");
        assert!(RpcError::argument("x")
            .to_string()
            .starts_with("Argument: "));
    }

    /// An endpoint's text is cut to 256 bytes at a character boundary, control characters removed, URLs redacted; a short clean
    /// text is kept as it is (the control).
    #[test]
    fn endpoint_text_is_capped() {
        assert_eq!(endpoint_text("nonce too low"), "nonce too low", "control");
        let long = "é".repeat(300);
        let t = endpoint_text(&long);
        assert!(
            t.len() <= TEXT_MAX && t.len() >= TEXT_MAX - 1 && t.chars().all(|c| c == 'é'),
            "{}",
            t.len()
        );
        assert_eq!(endpoint_text("a\nb\u{1b}[31mc\u{7f}"), "ab[31mc");
        assert_eq!(
            endpoint_text("at https://h.example/v3/KEY now"),
            "at <url> now"
        );
        let f =
            EndpointFailure::new(2, FailureKind::Http, &"x".repeat(1_000)).with_label(Some("own"));
        assert_eq!(f.text().len(), TEXT_MAX);
        assert!(f.to_string().starts_with("endpoint 2 (own): Http: "));
    }
}
