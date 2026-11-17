// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The endpoint list (CLI-RPC-02, spec §4.1): `{url, class, label, auth}` in the order given, the list's read policy and its
//! timeouts. A URL and a credential never appear in a `Debug` or `Display` output, an error or a log line (CLI-RPC-11): an
//! endpoint is named by its index and label.

use crate::error::RpcError;
use serde::Deserialize;
use zeroize::Zeroizing;

/// Where an endpoint comes from (ARCH-POS-15): the operator's or holder's (`named`), the release's reviewed list (`default`), or
/// found at run time by the caller (`discovered`; the crate discovers nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Named,
    Default,
    Discovered,
}

/// A credential: zeroized on drop, never printed.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(Zeroizing::new(s.into()))
    }
    /// The secret's text, for the one request header it goes into.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<secret>")
    }
}

/// An endpoint's own credential, sent to that endpoint only (F8): `Authorization: Bearer`, a gateway's HMAC secret (NODE-GW-02),
/// or a provider's API key header.
#[derive(Clone, Debug)]
pub enum EndpointAuth {
    Bearer(Secret),
    Hmac(Secret),
    Header { name: String, value: Secret },
}

/// At most 64 bytes, control characters removed (F21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label(String);

impl Label {
    pub const MAX: usize = 64;
    pub fn new(s: &str) -> Self {
        let mut out: String = s.chars().filter(|c| !c.is_control()).collect();
        let mut cut = out.len().min(Self::MAX);
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        Label(out)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One endpoint. Its URL is private and never printed.
#[derive(Clone)]
pub struct Endpoint {
    url: url::Url,
    pub class: Class,
    pub label: Option<Label>,
    auth: Option<EndpointAuth>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("class", &self.class)
            .field("label", &self.label)
            .field("auth", &self.auth.as_ref().map(|_| "<secret>"))
            .finish()
    }
}

impl Endpoint {
    /// An `http` or `https` URL (`EndpointScheme` otherwise; `Argument` when it does not parse).
    pub fn new(
        url: &str,
        class: Class,
        label: Option<&str>,
        auth: Option<EndpointAuth>,
    ) -> Result<Self, RpcError> {
        let url = url::Url::parse(url)
            .map_err(|_| RpcError::argument("an endpoint URL that does not parse"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(RpcError::EndpointScheme);
        }
        if url.host_str().is_none() {
            return Err(RpcError::argument("an endpoint URL without a host"));
        }
        if let Some(EndpointAuth::Header { name, .. }) = &auth {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            {
                return Err(RpcError::argument(
                    "an API key header name that is not a header name",
                ));
            }
        }
        Ok(Self {
            url,
            class,
            label: label.map(Label::new),
            auth,
        })
    }
    /// A `named` endpoint without a credential.
    pub fn named(url: &str) -> Result<Self, RpcError> {
        Self::new(url, Class::Named, None, None)
    }
    /// The URL, for the transport only.
    pub fn url(&self) -> &url::Url {
        &self.url
    }
    pub fn auth(&self) -> Option<&EndpointAuth> {
        self.auth.as_ref()
    }
    pub fn label_str(&self) -> Option<&str> {
        self.label.as_ref().map(Label::as_str)
    }
    /// Scheme, host, port and path: two endpoints equal in these are one (F22).
    fn identity(&self) -> (&str, Option<&str>, Option<u16>, &str) {
        (
            self.url.scheme(),
            self.url.host_str(),
            self.url.port_or_known_default(),
            self.url.path(),
        )
    }
}

/// The list's read policy (CLI-RPC-04, CLI-RPC-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    #[default]
    Failover,
    StrictMajority,
}

/// What a read is for: a read whose bytes enter a decryption is marked by its caller (CLI-RPC-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Plain,
    FeedsDecryption,
}

/// The endpoints a send goes to (CLI-RPC-08): the first, or every one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fanout {
    First,
    All,
}

/// Defaults: the node's `rpc_timeout_ms`, `rpc_simulate_timeout_ms`, and one whole agreement read (spec §4.6).
pub const TIMEOUT_MS: u64 = 30_000;
pub const SLOW_TIMEOUT_MS: u64 = 120_000;
pub const READ_TIMEOUT_MS: u64 = 60_000;
/// An agreed read's freshness (T13 S1): an endpoint counts at block `b` only when `b` is at most this many blocks below the
/// block it named itself. 4: honest endpoints of one chain stand a block or two apart (propagation, a head polled a moment
/// earlier), the fallback round reads one named number lower, and a margin of one more; an older block is refused by the
/// honest endpoints themselves, so no endpoint below `need` honest names can choose an old state. A list of a slow-block or
/// fast-block chain may set its own (`NodeList::with_max_lag`).
pub const MAX_LAG: u64 = 4;

/// An ordered endpoint list with its policy and timeouts (CLI-RPC-02).
#[derive(Clone, Debug)]
pub struct NodeList {
    endpoints: Vec<Endpoint>,
    pub policy: Policy,
    pub timeout_ms: u64,
    pub slow_timeout_ms: u64,
    pub read_timeout_ms: u64,
    /// [`MAX_LAG`] unless set (strict majority only)
    pub max_lag: u64,
}

impl NodeList {
    /// Refuses: no endpoint (`EndpointListEmpty`); two endpoints equal in scheme, host, port and path, a zero timeout, or
    /// `strict_majority` with one endpoint (`Argument`). The scheme is checked when each [`Endpoint`] is built.
    pub fn new(
        endpoints: Vec<Endpoint>,
        policy: Policy,
        timeout_ms: u64,
        slow_timeout_ms: u64,
        read_timeout_ms: u64,
    ) -> Result<Self, RpcError> {
        if endpoints.is_empty() {
            return Err(RpcError::EndpointListEmpty);
        }
        if timeout_ms == 0 || slow_timeout_ms == 0 || read_timeout_ms == 0 {
            return Err(RpcError::argument("a zero timeout"));
        }
        for (i, a) in endpoints.iter().enumerate() {
            if endpoints[..i].iter().any(|b| b.identity() == a.identity()) {
                return Err(RpcError::argument(&format!(
                    "endpoint {i} is an earlier endpoint again (scheme, host, port and path)"
                )));
            }
        }
        if policy == Policy::StrictMajority && endpoints.len() < 2 {
            return Err(RpcError::argument(
                "strict_majority needs two endpoints or more",
            ));
        }
        Ok(Self {
            endpoints,
            policy,
            timeout_ms,
            slow_timeout_ms,
            read_timeout_ms,
            max_lag: MAX_LAG,
        })
    }

    /// The list with another agreed-read freshness ([`MAX_LAG`]).
    pub fn with_max_lag(mut self, max_lag: u64) -> Self {
        self.max_lag = max_lag;
        self
    }

    /// A plain list of URL strings (the node's and the verifier's `rpc_urls`): `named`, in order, without credentials, failover,
    /// the default timeouts.
    pub fn from_urls(urls: &[String]) -> Result<Self, RpcError> {
        let e = urls
            .iter()
            .map(|u| Endpoint::named(u))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            e,
            Policy::Failover,
            TIMEOUT_MS,
            SLOW_TIMEOUT_MS,
            READ_TIMEOUT_MS,
        )
    }

    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

/// One entry of the app's form (spec §4.1): `{url, class, label, api_key_env | api_key_file, api_key_header, auth}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryConfig {
    pub url: String,
    #[serde(default = "named")]
    pub class: Class,
    pub label: Option<String>,
    /// the credential's environment variable, or its file
    pub api_key_env: Option<String>,
    pub api_key_file: Option<String>,
    /// the header it goes in; absent: `auth` decides
    pub api_key_header: Option<String>,
    /// `bearer` (the default without a header) or `hmac`
    pub auth: Option<String>,
}

fn named() -> Class {
    Class::Named
}

/// The list's configuration, the same shape in TOML and JSON (spec §4.1): `rpc_urls` (strings, `named`, no credentials) or `rpc`
/// (entries), `rpc_policy`, `rpc_timeout_ms`, `rpc_simulate_timeout_ms`, `rpc_read_timeout_ms`. A list-wide credential
/// (`api_key_env`, `api_key_file`, `api_key_header`, `auth` beside the list) is refused when the list is built (F8).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListConfig {
    pub rpc_urls: Option<Vec<String>>,
    pub rpc: Option<Vec<EntryConfig>>,
    #[serde(default)]
    pub rpc_policy: Policy,
    pub rpc_timeout_ms: Option<u64>,
    pub rpc_simulate_timeout_ms: Option<u64>,
    pub rpc_read_timeout_ms: Option<u64>,
    api_key_env: Option<serde::de::IgnoredAny>,
    api_key_file: Option<serde::de::IgnoredAny>,
    api_key_header: Option<serde::de::IgnoredAny>,
    auth: Option<serde::de::IgnoredAny>,
}

impl ListConfig {
    /// The list; `env` reads an environment variable (the caller's: `std::env::var` in a process, a map in a test).
    pub fn build(&self, env: impl Fn(&str) -> Option<String>) -> Result<NodeList, RpcError> {
        if self.api_key_env.is_some()
            || self.api_key_file.is_some()
            || self.api_key_header.is_some()
            || self.auth.is_some()
        {
            return Err(RpcError::argument(
                "a list-wide credential: a credential belongs to one endpoint",
            ));
        }
        let endpoints = match (&self.rpc_urls, &self.rpc) {
            (Some(_), Some(_)) => return Err(RpcError::argument("both rpc_urls and rpc")),
            (Some(urls), None) => urls
                .iter()
                .map(|u| Endpoint::named(u))
                .collect::<Result<Vec<_>, _>>()?,
            (None, Some(es)) => es
                .iter()
                .map(|e| entry(e, &env))
                .collect::<Result<Vec<_>, _>>()?,
            (None, None) => vec![],
        };
        NodeList::new(
            endpoints,
            self.rpc_policy,
            self.rpc_timeout_ms.unwrap_or(TIMEOUT_MS),
            self.rpc_simulate_timeout_ms.unwrap_or(SLOW_TIMEOUT_MS),
            self.rpc_read_timeout_ms.unwrap_or(READ_TIMEOUT_MS),
        )
    }
}

fn entry(e: &EntryConfig, env: &impl Fn(&str) -> Option<String>) -> Result<Endpoint, RpcError> {
    let secret = match (&e.api_key_env, &e.api_key_file) {
        (Some(_), Some(_)) => return Err(RpcError::argument("both api_key_env and api_key_file")),
        (Some(v), None) => {
            Some(Secret::new(env(v).ok_or_else(|| {
                RpcError::argument("api_key_env names an unset variable")
            })?))
        }
        (None, Some(p)) => Some(Secret::new(
            std::fs::read_to_string(p)
                .map_err(|_| RpcError::argument("api_key_file unreadable"))?
                .trim()
                .to_string(),
        )),
        (None, None) => None,
    };
    let auth = match (secret, e.api_key_header.as_deref(), e.auth.as_deref()) {
        (None, None, None) => None,
        (None, _, _) => {
            return Err(RpcError::argument(
                "an auth kind or header without a credential",
            ))
        }
        (Some(s), Some(h), None | Some("header")) => Some(EndpointAuth::Header {
            name: h.to_string(),
            value: s,
        }),
        (Some(s), None, None | Some("bearer")) => Some(EndpointAuth::Bearer(s)),
        (Some(s), None, Some("hmac")) => Some(EndpointAuth::Hmac(s)),
        _ => {
            return Err(RpcError::argument(
                "auth is header (with api_key_header), bearer or hmac",
            ))
        }
    };
    Endpoint::new(&e.url, e.class, e.label.as_deref(), auth)
}

/// Fable E N-8 (moved from the node): an endpoint URL (an RPC's, a verifier's: an internal host, a key in a path) never reaches an
/// error or a reply: each `scheme://…` up to a blank, a quote or a bracket becomes `<url>` (never ending at `,` or `;`: a key after
/// one in a path or query is part of the URL; Fable recheck R-7).
pub fn redact_urls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = ["http://", "https://", "ws://", "wss://"]
        .iter()
        .filter_map(|p| rest.find(p))
        .min()
    {
        out.push_str(&rest[..i]);
        out.push_str("<url>");
        let tail = &rest[i..];
        rest = &tail[tail
            .find(|c: char| c.is_whitespace() || "()<>\"'".contains(c))
            .unwrap_or(tail.len())..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(urls: &[&str]) -> Result<NodeList, RpcError> {
        NodeList::from_urls(&urls.iter().map(|u| u.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn a_scheme_other_than_http_is_refused() {
        for u in ["ws://a.example", "file:///etc/passwd", "ftp://a.example/x"] {
            assert_eq!(
                Endpoint::named(u).unwrap_err(),
                RpcError::EndpointScheme,
                "{u}"
            );
            assert_eq!(
                list(&["https://ok.example", u]).unwrap_err(),
                RpcError::EndpointScheme,
                "{u} in a list"
            );
        }
        for u in ["http://a.example", "https://a.example:8545/v1"] {
            assert!(Endpoint::named(u).is_ok(), "control: {u}");
        }
    }

    #[test]
    fn an_empty_list_is_refused() {
        assert_eq!(list(&[]).unwrap_err(), RpcError::EndpointListEmpty);
        assert_eq!(
            ListConfig::default().build(|_| None).unwrap_err(),
            RpcError::EndpointListEmpty
        );
        assert!(list(&["http://a.example"]).is_ok(), "control");
    }

    #[test]
    fn equal_parsed_urls_are_refused() {
        let e = list(&["https://a.example:443/x", "https://A.example/x"]).unwrap_err();
        assert_eq!(e.code(), "Argument", "{e}");
        let e = list(&["https://a.example/x?key=1", "https://a.example/x?key=2"]).unwrap_err();
        assert_eq!(
            e.code(),
            "Argument",
            "the query is not part of an endpoint's identity: {e}"
        );
        assert!(
            list(&["https://a.example:443/x", "https://A.example/y"]).is_ok(),
            "control: another path"
        );
        assert!(
            list(&["https://a.example/x", "http://a.example/x"]).is_ok(),
            "control: another scheme"
        );
    }

    #[test]
    fn url_strings_are_named_in_order_without_credentials() {
        let l = list(&["https://b.example", "https://a.example"]).unwrap();
        assert_eq!(
            l.endpoints()
                .iter()
                .map(|e| e.url().host_str().unwrap())
                .collect::<Vec<_>>(),
            ["b.example", "a.example"]
        );
        assert!(l
            .endpoints()
            .iter()
            .all(|e| e.class == Class::Named && e.auth().is_none() && e.label.is_none()));
        assert_eq!(
            (l.policy, l.timeout_ms, l.slow_timeout_ms, l.read_timeout_ms),
            (Policy::Failover, 30_000, 120_000, 60_000)
        );
    }

    #[test]
    fn the_app_shape_parses() {
        let toml_text = r#"
rpc = [{ url = "https://rpc-a.example", class = "named", label = "own", api_key_env = "RPC_A_KEY", api_key_header = "X-API-Key" },
       { url = "https://rpc-b.example", class = "default" },
       { url = "https://rpc-c.example", class = "discovered" }]
rpc_policy = "strict_majority"
rpc_timeout_ms = 30000
rpc_simulate_timeout_ms = 120000
rpc_read_timeout_ms = 60000
"#;
        let json_text = r#"{"rpc": [{"url": "https://rpc-a.example", "class": "named", "label": "own", "api_key_env": "RPC_A_KEY",
            "api_key_header": "X-API-Key"}, {"url": "https://rpc-b.example", "class": "default"},
            {"url": "https://rpc-c.example", "class": "discovered"}],
            "rpc_policy": "strict_majority", "rpc_timeout_ms": 30000, "rpc_simulate_timeout_ms": 120000, "rpc_read_timeout_ms": 60000}"#;
        let env = |k: &str| (k == "RPC_A_KEY").then(|| "k-123".to_string());
        for c in [
            toml::from_str::<ListConfig>(toml_text).unwrap(),
            serde_json::from_str::<ListConfig>(json_text).unwrap(),
        ] {
            let l = c.build(env).unwrap();
            assert_eq!(
                l.endpoints().iter().map(|e| e.class).collect::<Vec<_>>(),
                [Class::Named, Class::Default, Class::Discovered]
            );
            assert_eq!(l.policy, Policy::StrictMajority);
            assert_eq!(l.endpoints()[0].label_str(), Some("own"));
            match l.endpoints()[0].auth() {
                Some(EndpointAuth::Header { name, value }) => {
                    assert_eq!((name.as_str(), value.expose()), ("X-API-Key", "k-123"))
                }
                a => panic!("{a:?}"),
            }
            assert!(
                l.endpoints()[1].auth().is_none() && l.endpoints()[2].auth().is_none(),
                "the key is the first entry's only"
            );
        }
        assert!(
            toml::from_str::<ListConfig>(
                r#"rpc = [{ url = "https://a.example", class = "Named" }]"#
            )
            .is_err(),
            "class names exact"
        );
        assert!(toml::from_str::<ListConfig>(
            r#"rpc = [{ url = "https://a.example", class = "trusted" }]"#
        )
        .is_err());
        let unset = toml::from_str::<ListConfig>(
            r#"rpc = [{ url = "https://a.example", api_key_env = "NOPE" }]"#,
        )
        .unwrap();
        assert_eq!(
            unset.build(|_| None).unwrap_err().code(),
            "Argument",
            "an unset variable"
        );
    }

    #[test]
    fn a_list_wide_credential_is_refused() {
        for extra in [
            r#"api_key_env = "K""#,
            r#"api_key_header = "X-API-Key""#,
            r#"auth = "bearer""#,
            r#"api_key_file = "k""#,
        ] {
            let c: ListConfig =
                toml::from_str(&format!("rpc_urls = [\"https://a.example\"]\n{extra}")).unwrap();
            assert_eq!(
                c.build(|_| Some("v".into())).unwrap_err().code(),
                "Argument",
                "{extra}"
            );
        }
        let c: ListConfig = toml::from_str("rpc_urls = [\"https://a.example\"]").unwrap();
        assert!(c.build(|_| None).is_ok(), "control");
    }

    #[test]
    fn strict_majority_with_one_endpoint_is_refused() {
        let one = vec![Endpoint::named("https://a.example").unwrap()];
        assert_eq!(
            NodeList::new(one, Policy::StrictMajority, 1, 1, 1)
                .unwrap_err()
                .code(),
            "Argument"
        );
        let two = vec![
            Endpoint::named("https://a.example").unwrap(),
            Endpoint::named("https://b.example").unwrap(),
        ];
        assert!(
            NodeList::new(two, Policy::StrictMajority, 1, 1, 1).is_ok(),
            "control: two"
        );
    }

    #[test]
    fn a_zero_timeout_is_refused() {
        let e = || vec![Endpoint::named("https://a.example").unwrap()];
        for (a, b, c) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
            assert_eq!(
                NodeList::new(e(), Policy::Failover, a, b, c)
                    .unwrap_err()
                    .code(),
                "Argument",
                "{a} {b} {c}"
            );
        }
        assert!(
            NodeList::new(e(), Policy::Failover, 1, 1, 1).is_ok(),
            "control"
        );
    }

    #[test]
    fn a_label_is_capped_and_stripped() {
        assert_eq!(Label::new("own node").as_str(), "own node", "control");
        assert_eq!(Label::new("a\nb\tc\u{0}").as_str(), "abc");
        let l = Label::new(&"ü".repeat(100));
        assert!(
            l.as_str().len() <= 64 && l.as_str().len() >= 63,
            "{}",
            l.as_str().len()
        );
        let e = Endpoint::new(
            "https://a.example",
            Class::Named,
            Some(&"x".repeat(80)),
            None,
        )
        .unwrap();
        assert_eq!(e.label_str().unwrap().len(), 64);
    }

    #[test]
    fn debug_and_display_carry_no_url_or_secret() {
        let url = "https://rpc.example/v3/PATHKEY123?apikey=QUERYKEY456";
        let bearer = EndpointAuth::Bearer(Secret::new("BEARERSECRET789"));
        let e = Endpoint::new(url, Class::Named, Some("own"), Some(bearer)).unwrap();
        let hdr = Endpoint::new(
            "https://b.example/HDRPATH",
            Class::Default,
            None,
            Some(EndpointAuth::Header {
                name: "X-API-Key".into(),
                value: Secret::new("HEADERSECRET"),
            }),
        )
        .unwrap();
        let l = NodeList::new(vec![e.clone(), hdr], Policy::Failover, 1, 1, 1).unwrap();
        let errs = [
            Endpoint::named("ftp://rpc.example/v3/PATHKEY123").unwrap_err(),
            NodeList::new(vec![e.clone(), e.clone()], Policy::Failover, 1, 1, 1).unwrap_err(),
            RpcError::argument(&format!("failed {url}")),
            RpcError::EndpointAllFailed {
                last: Some(crate::error::EndpointFailure::new(
                    0,
                    crate::error::FailureKind::Transport,
                    &format!("error sending request for url ({url})"),
                )),
                failover_revert: None,
            },
        ];
        let mut texts = vec![format!("{e:?}"), format!("{l:?}")];
        for x in &errs {
            texts.push(format!("{x:?}"));
            texts.push(x.to_string());
        }
        for t in &texts {
            for secret in [
                "PATHKEY123",
                "QUERYKEY456",
                "BEARERSECRET789",
                "HEADERSECRET",
                "HDRPATH",
                "rpc.example",
            ] {
                assert!(!t.contains(secret), "{secret} in {t}");
            }
        }
        assert!(
            format!("{e:?}").contains("own"),
            "control: the label is printed"
        );
    }

    /// The node's redaction tests (scaas-node `submit.rs::a_job_error_carries_no_endpoint_url`), kept with their name.
    #[test]
    fn a_job_error_carries_no_endpoint_url() {
        assert_eq!(redact_urls("rpc: error sending request for url (https://rpc.example/v3/KEY) after http://10.0.0.7:8545/ x"),
            "rpc: error sending request for url (<url>) after <url> x");
        assert_eq!(redact_urls("no url; wss://h:1/p,ws://q"), "no url; <url>");
        assert_eq!(
            redact_urls("x http://h/p?a=1;key=SECRET,b=2 y"),
            "x <url> y",
            "recheck R-7: a key after ; or ,"
        );
    }
}
