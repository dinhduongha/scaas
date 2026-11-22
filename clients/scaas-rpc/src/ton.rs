// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! TON Center v3 (spec §5.3 ton row, plan T22) on the family client: a GET with its query and a JSON POST under `/api/v3/`,
//! an answer other than 2xx as `FamilyError::Status` with its text, and the head (`masterchainInfo`'s last seqno) for the
//! failover's floor. TON Center names no network: endpoint 0 is this network by the profile constant (NET-ALL-22, CLI-RPC-03),
//! and a later endpoint is when its masterchain block at the last seqno endpoint 0 showed has endpoint 0's root hash (T24.6,
//! owner 2026-11-18). Get-method stacks, BOCs and transactions are the caller's to read. Reads pinned to one masterchain seqno
//! (rpc T24.ton-seqno): [`Ton::run_get_at`] and [`Ton::account_at`] on TON Center's `/api/v2/` paths of the same endpoints
//! (v3's `runGetMethod` and `walletInformation` take no seqno), each answer naming that block; the stack's cells through the
//! bounded [`crate::boc`] reader.
use crate::family::{Client, FamilyError, ANSWER_MAX};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::{json, Value};
use web_time::Instant;

/// The family client of one TON network's TON Center v3 endpoints.
pub struct Ton {
    pub client: Client,
    /// endpoint 0's last masterchain block seen: (seqno, root hash), a later endpoint's identity reference (T24.6)
    seen: std::sync::Mutex<Option<(u64, String)>>,
}

impl Ton {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            seen: Default::default(),
        }
    }

    /// Endpoint 0's masterchain block `seqno`, of root hash `root_hash` (its polled head): the failover reads' floor and a later
    /// endpoint's identity reference (T24.6). Only a higher seqno replaces the reference.
    pub fn saw(&self, seqno: u64, root_hash: &str) {
        self.client.pool().saw_block(seqno);
        let mut s = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if s.as_ref().is_none_or(|(n, _)| seqno > *n) {
            *s = Some((seqno, root_hash.to_string()));
        }
    }

    /// GET `/api/v3/{path}` with `query` on endpoint `i`.
    pub async fn get(
        &self,
        i: usize,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Value, FamilyError> {
        let mut p = format!("/api/v3/{path}");
        if !query.is_empty() {
            let q: String = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())))
                .finish();
            p = format!("{p}?{q}");
        }
        self.request(i, reqwest::Method::GET, &p, None).await
    }

    /// POST `body` (JSON) to `/api/v3/{path}` on endpoint `i`.
    pub async fn post(&self, i: usize, path: &str, body: &Value) -> Result<Value, FamilyError> {
        let b = serde_json::to_vec(body).map_err(|e| {
            FamilyError::Failure(EndpointFailure::new(
                i,
                FailureKind::Transport,
                &e.to_string(),
            ))
        })?;
        self.request(
            i,
            reqwest::Method::POST,
            &format!("/api/v3/{path}"),
            Some(b),
        )
        .await
    }

    async fn request(
        &self,
        i: usize,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Value, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        self.fetch(i, method, path, body).await
    }

    /// [`Ton::request`] without the identity check (the probe's own reads).
    async fn fetch(
        &self,
        i: usize,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Value, FamilyError> {
        let (status, b) = self
            .client
            .raw_at(i, method, path, body, "application/json", ANSWER_MAX)
            .await?;
        if !(200..300).contains(&status) {
            return Err(FamilyError::Status {
                status,
                message: crate::error::endpoint_text(&String::from_utf8_lossy(&b)),
            });
        }
        crate::http::decode(&b, ANSWER_MAX)
            .map_err(|k| FamilyError::Failure(EndpointFailure::new(i, k, "the answer")))
    }

    /// `masterchainInfo`'s last block on endpoint `i`.
    pub async fn masterchain_last(&self, i: usize) -> Result<Value, FamilyError> {
        let v = self.get(i, "masterchainInfo", &[]).await?;
        v.get("last").cloned().ok_or_else(|| {
            FamilyError::Failure(EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                "masterchainInfo without last",
            ))
        })
    }
}

impl Probe for Ton {
    type Hash = String;
    /// Endpoint 0: the profile constant (NET-ALL-22: TON Center exposes no network id, the configured list names the network).
    /// A later endpoint: its masterchain block at endpoint 0's last seen seqno has endpoint 0's root hash (T24.6); none seen
    /// yet, or its block unreadable: unread (skipped, asked again); another hash: another network (dropped).
    async fn same_chain(&self, i: usize, d: Option<Instant>) -> Result<bool, EndpointFailure> {
        if i == 0 {
            return Ok(true);
        }
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some((seqno, want)) = seen else {
            return Err(EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                "no masterchain block of endpoint 0 seen yet",
            ));
        };
        Ok(self.header(i, seqno, d).await? == want)
    }
    /// `masterchainInfo`'s last seqno.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        let last = self.masterchain_last(i).await.map_err(|e| unread(i, e))?;
        last.get("seqno").and_then(Value::as_u64).ok_or_else(|| {
            EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                "masterchainInfo.last.seqno",
            )
        })
    }
    async fn named(
        &self,
        i: usize,
        _: BlockChoice,
        d: Option<Instant>,
    ) -> Result<u64, EndpointFailure> {
        self.head(i, d).await
    }
    async fn header(
        &self,
        i: usize,
        n: u64,
        _: Option<Instant>,
    ) -> Result<String, EndpointFailure> {
        let path = format!("/api/v3/blocks?workchain=-1&shard=8000000000000000&seqno={n}");
        let v = self
            .fetch(i, reqwest::Method::GET, &path, None)
            .await
            .map_err(|e| unread(i, e))?;
        v.pointer("/blocks/0/root_hash")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                EndpointFailure::new(i, FailureKind::AnswerMalformed, "no masterchain block")
            })
    }
}

/// A family error as the pool's endpoint failure.
fn unread(i: usize, e: FamilyError) -> EndpointFailure {
    match e {
        FamilyError::Failure(f) => f,
        e => EndpointFailure::new(i, FailureKind::Transport, &e.to_string()),
    }
}

// ------------------------------------------------------------ reads pinned to a masterchain seqno (rpc T24.ton-seqno)

/// A get-method argument, in TON Center v2's `[type, value]` stack form: a number (decimal or `0x` hex) or a slice (a BoC).
pub enum StackArg {
    Num(String),
    Slice(Vec<u8>),
}

/// An entry of a v2 get-method answer's stack: a number as the endpoint wrote it (`0x` hex of at most 65 digits, 257 bits, an
/// optional `-`), or a cell or slice as its BoC bytes (read with [`crate::boc::parse`]). Any other entry is malformed.
#[derive(Debug, Clone, PartialEq)]
pub enum StackEntry {
    Num(String),
    Cell(Vec<u8>),
}

impl StackEntry {
    /// A number that is not negative and fits 128 bits (a jetton balance: `Coins`, at most 120 bits).
    pub fn as_u128(&self) -> Option<u128> {
        match self {
            StackEntry::Num(s) => u128::from_str_radix(s.strip_prefix("0x")?, 16).ok(),
            StackEntry::Cell(_) => None,
        }
    }
}

/// A get-method's answer at the asked seqno: TVM's exit code (0 and 1 are success; the caller reads it) and the stack.
#[derive(Debug, Clone, PartialEq)]
pub struct GetAt {
    pub exit_code: i64,
    pub stack: Vec<StackEntry>,
}

/// An account at the asked seqno: its balance (nanoton, a decimal string of at most 78 digits) and its state as the endpoint
/// names it (`active`, `uninitialized`, `frozen`).
#[derive(Debug, Clone, PartialEq)]
pub struct AccountAt {
    pub balance: String,
    pub state: String,
}

/// A raw `wc:hex` address: workchain 0 or -1 and 64 hex digits (any case), else none.
pub fn raw_address(s: &str) -> Option<(i8, [u8; 32])> {
    let (wc, h) = s.split_once(':')?;
    let wc = match wc {
        "0" => 0,
        "-1" => -1,
        _ => return None,
    };
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (k, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&h[2 * k..2 * k + 2], 16).ok()?;
    }
    Some((wc, out))
}

/// The raw form `wc:hex`, lowercase.
pub fn format_raw((wc, h): (i8, [u8; 32])) -> String {
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    format!("{wc}:{hex}")
}

fn bad(i: usize, why: &str) -> FamilyError {
    FamilyError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
}

/// A v2 answer's `result`, which must name masterchain block `seqno` (`block_id`).
fn result_at(i: usize, mut v: Value, seqno: u64) -> Result<Value, FamilyError> {
    if v.get("ok") != Some(&Value::Bool(true)) {
        return Err(bad(i, "a v2 answer that is not ok"));
    }
    let r = v.get_mut("result").map(Value::take).unwrap_or_default();
    let b = r.get("block_id");
    if b.and_then(|b| b.get("workchain")).and_then(Value::as_i64) != Some(-1)
        || b.and_then(|b| b.get("seqno")).and_then(Value::as_u64) != Some(seqno)
    {
        return Err(bad(
            i,
            &format!("an answer not at masterchain block {seqno}"),
        ));
    }
    Ok(r)
}

/// One entry of a v2 answer's stack.
fn entry(i: usize, e: &Value) -> Result<StackEntry, FamilyError> {
    use base64::Engine as _;
    match (e.get(0).and_then(Value::as_str), e.get(1)) {
        (Some("num"), Some(Value::String(s))) => {
            let h = s.strip_prefix('-').unwrap_or(s).strip_prefix("0x");
            match h {
                Some(h)
                    if (1..=65).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit()) =>
                {
                    Ok(StackEntry::Num(s.clone()))
                }
                _ => Err(bad(
                    i,
                    "a stack number that is not 0x hex of at most 257 bits",
                )),
            }
        }
        (Some("cell"), Some(c)) => c
            .get("bytes")
            .and_then(Value::as_str)
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .map(StackEntry::Cell)
            .ok_or_else(|| bad(i, "a stack cell that is not a base64 BoC")),
        _ => Err(bad(i, "a stack entry that is neither a number nor a cell")),
    }
}

impl Ton {
    /// POST `body` to `/api/v2/{path}` on endpoint `i` (its identity checked first).
    async fn post_v2(&self, i: usize, path: &str, body: &Value) -> Result<Value, FamilyError> {
        let b = serde_json::to_vec(body).map_err(|e| bad(i, &e.to_string()))?;
        self.request(
            i,
            reqwest::Method::POST,
            &format!("/api/v2/{path}"),
            Some(b),
        )
        .await
    }

    /// Get-method `method` of `address` run on the state at masterchain block `seqno`, endpoint `i`: TON Center's
    /// `/api/v2/runGetMethod` with `seqno` (v3's takes none); the answer must name that block, its stack is read entry by entry.
    pub async fn run_get_at(
        &self,
        i: usize,
        address: &str,
        method: &str,
        stack: &[StackArg],
        seqno: u64,
    ) -> Result<GetAt, FamilyError> {
        use base64::Engine as _;
        let args: Vec<Value> = stack
            .iter()
            .map(|a| match a {
                StackArg::Num(n) => json!(["num", n]),
                StackArg::Slice(b) => {
                    json!([
                        "tvm.Slice",
                        base64::engine::general_purpose::STANDARD.encode(b)
                    ])
                }
            })
            .collect();
        let body = json!({"address": address, "method": method, "stack": args, "seqno": seqno});
        let r = result_at(i, self.post_v2(i, "runGetMethod", &body).await?, seqno)?;
        let exit_code = r
            .get("exit_code")
            .and_then(Value::as_i64)
            .ok_or_else(|| bad(i, "an exit code that is not a number"))?;
        let stack = r
            .get("stack")
            .and_then(Value::as_array)
            .ok_or_else(|| bad(i, "a stack that is not a list"))?
            .iter()
            .map(|e| entry(i, e))
            .collect::<Result<_, _>>()?;
        Ok(GetAt { exit_code, stack })
    }

    /// The account `address` at masterchain block `seqno`, endpoint `i`: TON Center's `/api/v2/getAddressInformation` with
    /// `seqno`; the answer must name that block.
    pub async fn account_at(
        &self,
        i: usize,
        address: &str,
        seqno: u64,
    ) -> Result<AccountAt, FamilyError> {
        let q: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("address", address)
            .append_pair("seqno", &seqno.to_string())
            .finish();
        let v = self
            .request(
                i,
                reqwest::Method::GET,
                &format!("/api/v2/getAddressInformation?{q}"),
                None,
            )
            .await?;
        let r = result_at(i, v, seqno)?;
        let balance = r
            .get("balance")
            .and_then(Value::as_str)
            .filter(|s| (1..=78).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| {
                bad(
                    i,
                    "a balance that is not a decimal string of at most 78 digits",
                )
            })?;
        let state = r
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| bad(i, "an account without its state"))?;
        Ok(AccountAt {
            balance: balance.to_string(),
            state: state.to_string(),
        })
    }
}
