// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Soroban RPC (spec §5.3 soroban row, plan T15) on the family client: the JSON-RPC calls, the ledger reads (`getLatestLedger`,
//! `getLedgers`), the network identity (`getNetwork`'s passphrase) and the head for the failover's floor. The XDR inside the
//! answers (account entries, results) is the caller's to decode.
use crate::family::{Client, FamilyError};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::{json, Value};
use web_time::Instant;

/// A ledger: its sequence and its hash (`0x` + lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    pub sequence: u64,
    pub hash: String,
}

/// The family client of one Soroban network, named by its passphrase (the identity every endpoint must answer).
pub struct Soroban {
    pub client: Client,
    passphrase: String,
}

impl Soroban {
    pub fn new(client: Client, passphrase: &str) -> Self {
        Self {
            client,
            passphrase: passphrase.into(),
        }
    }

    /// One JSON-RPC call to endpoint `i`.
    pub async fn call(&self, i: usize, method: &str, params: Value) -> Result<Value, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        self.client.rpc_at(i, method, params).await
    }

    /// `getLedgers` of ledger `seq` on endpoint `i`: its hash (an endpoint without it is an error).
    pub async fn ledger_hash(&self, i: usize, seq: u64) -> Result<String, FamilyError> {
        let r = self
            .call(
                i,
                "getLedgers",
                json!({"startLedger": seq, "pagination": {"limit": 1}}),
            )
            .await?;
        let l = &r["ledgers"][0];
        let bad = |why: &str| {
            FamilyError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
        };
        if l["sequence"].as_u64() != Some(seq) {
            return Err(bad(&format!("ledger {seq} not available")));
        }
        let h = l["hash"]
            .as_str()
            .ok_or_else(|| bad(&format!("ledger {seq} without hash")))?;
        Ok(format!("0x{}", h.to_lowercase()))
    }

    /// `getLatestLedger` on endpoint `i`.
    pub async fn latest_ledger(&self, i: usize) -> Result<Ledger, FamilyError> {
        let r = self.call(i, "getLatestLedger", json!({})).await?;
        let bad = |why: &str| {
            FamilyError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
        };
        let sequence = r["sequence"]
            .as_u64()
            .ok_or_else(|| bad("getLatestLedger without sequence"))?;
        let id = r["id"]
            .as_str()
            .ok_or_else(|| bad("getLatestLedger without id"))?;
        Ok(Ledger {
            sequence,
            hash: format!("0x{}", id.to_lowercase()),
        })
    }

    /// Endpoint 0's latest ledger and how many endpoints, endpoint 0 included, give the same hash at its sequence (the node's
    /// head quorum; an endpoint that fails counts as not agreeing).
    pub async fn head_agreement(&self) -> Result<(Ledger, usize), FamilyError> {
        let head = self.latest_ledger(0).await?;
        let mut agree = 1;
        for i in 1..self.client.len() {
            if self.ledger_hash(i, head.sequence).await.ok().as_deref() == Some(head.hash.as_str())
            {
                agree += 1;
            }
        }
        Ok((head, agree))
    }
}

impl Probe for Soroban {
    type Hash = String;
    /// `getNetwork`'s passphrase against the configured one.
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        let r = self
            .client
            .rpc_at(i, "getNetwork", json!({}))
            .await
            .map_err(|e| unread(i, e))?;
        match r["passphrase"].as_str() {
            Some(p) => Ok(p == self.passphrase),
            None => Err(EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                "getNetwork without passphrase",
            )),
        }
    }
    /// `getLatestLedger`'s sequence.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.latest_ledger(i)
            .await
            .map(|l| l.sequence)
            .map_err(|e| unread(i, e))
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
        self.ledger_hash(i, n).await.map_err(|e| unread(i, e))
    }
}

/// A family error as the pool's endpoint failure.
fn unread(i: usize, e: FamilyError) -> EndpointFailure {
    match e {
        FamilyError::Failure(f) => f,
        e => EndpointFailure::new(i, FailureKind::Transport, &e.to_string()),
    }
}

// ---------------------------------------------------------------- plan T30.soroban / T41.soroban: the quote's reads, the send

/// The longest `SorobanTransactionData` or auth entry read, and the deepest `ScVal` in it (the family client's depth).
pub const XDR_MAX: usize = 256 << 10;
pub const XDR_DEPTH: u32 = 64;
/// The most ledger keys of one footprint list, auth entries of one simulation, signatures of one envelope.
pub const MAX_ITEMS: usize = 256;

/// A transaction's resources as a simulation gave them (`SorobanTransactionData`): each footprint `LedgerKey` its own XDR, sliced
/// by the bounded reader below; the fee as given (the caller adds its margin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxData {
    pub read_only: Vec<Vec<u8>>,
    pub read_write: Vec<Vec<u8>>,
    pub instructions: u32,
    pub disk_read_bytes: u32,
    pub write_bytes: u32,
    pub resource_fee: i64,
    pub archived: Vec<u32>,
}

/// A bounded XDR reader: every length within what is left, every opaque padded with zeros, `ScVal`s at most [`XDR_DEPTH`] deep.
struct Xdr<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Xdr<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn opaque(&mut self, max: usize) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return None;
        }
        let v = self.take(n)?;
        self.take((4 - n % 4) % 4)?
            .iter()
            .all(|z| *z == 0)
            .then_some(v)
    }
    fn count(&mut self) -> Option<usize> {
        let n = self.u32()? as usize;
        (n <= MAX_ITEMS).then_some(n)
    }
    fn account_id(&mut self) -> Option<()> {
        (self.u32()? == 0).then_some(())?; // PUBLIC_KEY_TYPE_ED25519
        self.take(32).map(drop)
    }
    fn sc_address(&mut self) -> Option<()> {
        match self.u32()? {
            0 => self.account_id(),
            1 | 4 => self.take(32).map(drop),
            2 => self.take(40).map(drop),
            3 => {
                (self.u32()? == 0).then_some(())?;
                self.take(32).map(drop)
            }
            _ => None,
        }
    }
    fn sc_map(&mut self, depth: u32) -> Option<()> {
        for _ in 0..self.count()? {
            self.sc_val(depth)?;
            self.sc_val(depth)?;
        }
        Some(())
    }
    fn sc_val(&mut self, depth: u32) -> Option<()> {
        let depth = depth.checked_sub(1)?;
        match self.u32()? {
            0 => (self.u32()? <= 1).then_some(()),
            1 | 20 => Some(()),
            2 => self.take(8).map(drop), // SCError: its type and its code
            3 | 4 => self.take(4).map(drop),
            5..=8 | 21 => self.take(8).map(drop),
            9 | 10 => self.take(16).map(drop),
            11 | 12 => self.take(32).map(drop),
            13 | 14 => self.opaque(XDR_MAX).map(drop),
            15 => self.opaque(32).map(drop),
            16 => match self.u32()? {
                0 => Some(()),
                1 => (0..self.count()?).try_for_each(|_| self.sc_val(depth)),
                _ => None,
            },
            17 => match self.u32()? {
                0 => Some(()),
                1 => self.sc_map(depth),
                _ => None,
            },
            18 => self.sc_address(),
            19 => {
                match self.u32()? {
                    0 => self.take(32).map(drop)?,
                    1 => {}
                    _ => return None,
                }
                match self.u32()? {
                    0 => Some(()),
                    1 => self.sc_map(depth),
                    _ => None,
                }
            }
            _ => None,
        }
    }
    /// One `LedgerKey`, its bytes.
    fn ledger_key(&mut self) -> Option<Vec<u8>> {
        let start = self.at;
        match self.u32()? {
            0 => self.account_id()?,
            1 => {
                self.account_id()?;
                match self.u32()? {
                    0 => {}
                    1 => {
                        self.take(4)?;
                        self.account_id()?
                    }
                    2 => {
                        self.take(12)?;
                        self.account_id()?
                    }
                    3 => self.take(32).map(drop)?,
                    _ => return None,
                }
            }
            2 => {
                self.account_id()?;
                self.take(8)?;
            }
            3 => {
                self.account_id()?;
                self.opaque(64)?;
            }
            4 => {
                (self.u32()? == 0).then_some(())?;
                self.take(32)?;
            }
            5 | 7 | 9 => self.take(32).map(drop)?,
            6 => {
                self.sc_address()?;
                self.sc_val(XDR_DEPTH)?;
                (self.u32()? <= 1).then_some(())?;
            }
            8 => self.take(4).map(drop)?,
            _ => return None,
        }
        Some(self.b.get(start..self.at)?.to_vec())
    }
    fn keys(&mut self) -> Option<Vec<Vec<u8>>> {
        (0..self.count()?).map(|_| self.ledger_key()).collect()
    }
}

/// The `SorobanTransactionData` XDR `b`, exactly (nothing after it); `None` above [`XDR_MAX`], past [`XDR_DEPTH`], a list above
/// [`MAX_ITEMS`] or any other form.
pub fn tx_data(b: &[u8]) -> Option<TxData> {
    if b.len() > XDR_MAX {
        return None;
    }
    let mut r = Xdr { b, at: 0 };
    let archived = match r.u32()? {
        0 => vec![],
        1 => (0..r.count()?).map(|_| r.u32()).collect::<Option<_>>()?,
        _ => return None,
    };
    let d = TxData {
        read_only: r.keys()?,
        read_write: r.keys()?,
        instructions: r.u32()?,
        disk_read_bytes: r.u32()?,
        write_bytes: r.u32()?,
        resource_fee: r.i64()?,
        archived,
    };
    (r.at == b.len() && d.resource_fee >= 0).then_some(d)
}

/// A `SorobanAuthorizationEntry`'s credentials, read by [`auth_credential`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCredential<'a> {
    /// Address credentials: the entry's first 44 bytes, `SOROBAN_CREDENTIALS_ADDRESS ‖ ScAddress` (the signer)
    Address(&'a [u8]),
    /// the transaction's source account's own authorization (owner 2026-11-22: accepted when the source is the op's subject)
    SourceAccount,
}

/// The credentials of the `SorobanAuthorizationEntry` XDR `b`, after a bounded read of the whole entry (nothing after it);
/// `None` for any other form.
pub fn auth_credential(b: &[u8]) -> Option<AuthCredential<'_>> {
    if b.len() > XDR_MAX {
        return None;
    }
    let mut r = Xdr { b, at: 0 };
    let cred = match r.u32()? {
        0 => None,
        1 => {
            r.sc_address()?;
            let signer_end = r.at;
            r.take(12)?; // nonce, signature expiration ledger
            r.sc_val(XDR_DEPTH)?;
            Some(signer_end)
        }
        _ => return None,
    };
    fn invocation(r: &mut Xdr<'_>, depth: u32) -> Option<()> {
        let depth = depth.checked_sub(1)?;
        (r.u32()? == 0).then_some(())?; // a contract function
        r.sc_address()?;
        r.opaque(32)?;
        (0..r.count()?).try_for_each(|_| r.sc_val(XDR_DEPTH))?;
        (0..r.count()?).try_for_each(|_| invocation(r, depth))
    }
    invocation(&mut r, XDR_DEPTH)?;
    if r.at != b.len() {
        return None;
    }
    Some(match cred {
        None => AuthCredential::SourceAccount,
        Some(end) => AuthCredential::Address(b.get(..end)?),
    })
}

/// The signer of an Address-credentials entry ([`auth_credential`]'s `Address`); `None` for source-account credentials or any
/// other form.
pub fn auth_signer(b: &[u8]) -> Option<&[u8]> {
    match auth_credential(b)? {
        AuthCredential::Address(s) => Some(s),
        AuthCredential::SourceAccount => None,
    }
}

/// A simulation's answer, read (spec §27.5 (d)): the host refused the call (its error, capped), it needs archived entries restored,
/// or its transaction data, its minimum resource fee and the auth entries it recorded (raw XDR, each read by [`auth_credential`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Simulation {
    Refused {
        reason: String,
    },
    Restore,
    Ok {
        data: TxData,
        min_resource_fee: u64,
        auth: Vec<Vec<u8>>,
    },
}

/// `sendTransaction`'s status of a well-formed answer, as CLI-RPC-08 merges it.
pub use crate::family::SendOutcome;

/// The merge of a send (CLI-RPC-08): never a final verdict on the transaction ([`Soroban::transaction_at`] decides).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Broadcast {
    Sent {
        id: [u8; 32],
        accepted: Vec<usize>,
        others: Vec<(usize, SendOutcome)>,
    },
    Rejected {
        id: [u8; 32],
        outcomes: Vec<(usize, SendOutcome)>,
    },
}

impl Broadcast {
    pub fn id(&self) -> [u8; 32] {
        match self {
            Broadcast::Sent { id, .. } | Broadcast::Rejected { id, .. } => *id,
        }
    }
}

/// `getTransaction`'s answer: in a ledger (`SUCCESS` or `FAILED`, billed either way) or not found at the endpoint's latest ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    Success { ledger: u64 },
    Failed { ledger: u64 },
    NotFound { latest: u64 },
}

/// One ledger entry an endpoint answered: its `LedgerEntryData` XDR and its TTL (`liveUntilLedgerSeq`) where it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub xdr: Vec<u8>,
    pub live_until: Option<u64>,
}

fn b64d(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    // a base64 text at most 4/3 of the bound
    (s.len() <= XDR_MAX / 3 * 4 + 4).then_some(())?;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}
fn b64e(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn lower_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A decimal string of at most 20 digits (a `u64` the RPC writes as text).
fn dec_u64(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    (!s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// The id of `tx` on network `network_id`: `sha256(network_id ‖ ENVELOPE_TYPE_TX ‖ tx)`, computed before any request.
pub fn tx_id(network_id: &[u8; 32], tx: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(network_id);
    h.update(2u32.to_be_bytes());
    h.update(tx);
    h.finalize().into()
}

impl Soroban {
    fn bad(i: usize, why: &str) -> FamilyError {
        FamilyError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
    }

    /// `simulateTransaction` of the envelope XDR `envelope` (unsigned) on endpoint `i`: the endpoint's latest ledger and the
    /// simulation, read within [`XDR_MAX`], [`XDR_DEPTH`] and [`MAX_ITEMS`] (anything else is its `AnswerMalformed`).
    pub async fn simulate_at(
        &self,
        i: usize,
        envelope: &[u8],
    ) -> Result<(u64, Simulation), FamilyError> {
        let r = self
            .call(
                i,
                "simulateTransaction",
                json!({"transaction": b64e(envelope)}),
            )
            .await?;
        let ledger = r["latestLedger"]
            .as_u64()
            .ok_or_else(|| Self::bad(i, "a simulation without latestLedger"))?;
        if let Some(e) = r.get("error").filter(|e| !e.is_null()) {
            let reason = crate::error::endpoint_text(e.as_str().unwrap_or("a simulation error"));
            return Ok((ledger, Simulation::Refused { reason }));
        }
        if r.get("restorePreamble").is_some_and(|p| !p.is_null()) {
            return Ok((ledger, Simulation::Restore));
        }
        let data = r["transactionData"]
            .as_str()
            .and_then(b64d)
            .and_then(|b| tx_data(&b))
            .ok_or_else(|| Self::bad(i, "transactionData out of its form"))?;
        let min_resource_fee = dec_u64(&r["minResourceFee"])
            .ok_or_else(|| Self::bad(i, "minResourceFee out of its form"))?;
        let auth = match r["results"].as_array().map(Vec::as_slice) {
            Some([one]) => match &one["auth"] {
                Value::Null => vec![],
                Value::Array(a) if a.len() <= MAX_ITEMS => a
                    .iter()
                    .map(|x| {
                        x.as_str()
                            .and_then(b64d)
                            .filter(|b| auth_credential(b).is_some())
                    })
                    .collect::<Option<_>>()
                    .ok_or_else(|| Self::bad(i, "an auth entry out of its form"))?,
                _ => return Err(Self::bad(i, "auth that is no list")),
            },
            _ => return Err(Self::bad(i, "a simulation without its one result")),
        };
        Ok((
            ledger,
            Simulation::Ok {
                data,
                min_resource_fee,
                auth,
            },
        ))
    }

    /// `getLedgerEntries` of `keys` (`LedgerKey` XDR) on endpoint `i`: its latest ledger and each key's entry, `None` where it
    /// has none; an entry answered twice or not asked is its `AnswerMalformed`.
    pub async fn entries_at(
        &self,
        i: usize,
        keys: &[Vec<u8>],
    ) -> Result<(u64, Vec<Option<Entry>>), FamilyError> {
        let text: Vec<String> = keys.iter().map(|k| b64e(k)).collect();
        let r = self
            .call(i, "getLedgerEntries", json!({"keys": text}))
            .await?;
        let ledger = r["latestLedger"]
            .as_u64()
            .ok_or_else(|| Self::bad(i, "getLedgerEntries without latestLedger"))?;
        let mut out: Vec<Option<Entry>> = vec![None; keys.len()];
        let list = match &r["entries"] {
            Value::Null => &[][..],
            Value::Array(a) => a.as_slice(),
            _ => return Err(Self::bad(i, "entries that are not a list")),
        };
        for e in list {
            let n = text
                .iter()
                .position(|t| Some(t.as_str()) == e["key"].as_str())
                .filter(|n| out.get(*n).is_some_and(Option::is_none))
                .ok_or_else(|| Self::bad(i, "an entry not asked, or twice"))?;
            let xdr = e["xdr"]
                .as_str()
                .and_then(b64d)
                .ok_or_else(|| Self::bad(i, "an entry without its xdr"))?;
            out[n] = Some(Entry {
                xdr,
                live_until: e["liveUntilLedgerSeq"].as_u64(),
            });
        }
        Ok((ledger, out))
    }

    /// `getFeeStats` on endpoint `i`: the 90th percentile of the inclusion fee per operation of Soroban transactions and of the
    /// others (stroops).
    pub async fn fee_stats_at(&self, i: usize) -> Result<(u64, u64), FamilyError> {
        let r = self.call(i, "getFeeStats", json!({})).await?;
        let p90 = |k: &str| {
            dec_u64(&r[k]["p90"]).ok_or_else(|| Self::bad(i, "a fee statistic out of its form"))
        };
        Ok((p90("sorobanInclusionFee")?, p90("inclusionFee")?))
    }

    /// `getTransaction` of the id `hash` on endpoint `i`.
    pub async fn transaction_at(&self, i: usize, hash: &[u8; 32]) -> Result<TxStatus, FamilyError> {
        let r = self
            .call(i, "getTransaction", json!({"hash": lower_hex(hash)}))
            .await?;
        let latest = r["latestLedger"]
            .as_u64()
            .ok_or_else(|| Self::bad(i, "getTransaction without latestLedger"))?;
        let ledger = || {
            r["ledger"]
                .as_u64()
                .ok_or_else(|| Self::bad(i, "a transaction without its ledger"))
        };
        match r["status"].as_str() {
            Some("SUCCESS") => Ok(TxStatus::Success { ledger: ledger()? }),
            Some("FAILED") => Ok(TxStatus::Failed { ledger: ledger()? }),
            Some("NOT_FOUND") => Ok(TxStatus::NotFound { latest }),
            _ => Err(Self::bad(i, "a transaction status out of its form")),
        }
    }

    /// CLI-RPC-08: the envelope of `tx` (its XDR) with `signatures` (each the key's hint and its 64 bytes) built once, the same
    /// bytes to the first endpoint or to all, concurrently; the id [`tx_id`] computed before any request. `PENDING` or
    /// `DUPLICATE` with that id accepts; another id, `ERROR` and `TRY_AGAIN_LATER` refuse (the reason capped); a failure is
    /// unreachable. `Sent` when one accepted, else `Rejected`; neither is final.
    pub async fn send(
        &self,
        network_id: &[u8; 32],
        tx: &[u8],
        signatures: &[([u8; 4], [u8; 64])],
        fanout: crate::endpoint::Fanout,
    ) -> Result<Broadcast, crate::RpcError> {
        if signatures.is_empty() || signatures.len() > 20 || tx.len() > XDR_MAX {
            return Err(crate::RpcError::argument(
                "an envelope of 1 to 20 signatures within the bound",
            ));
        }
        let id = tx_id(network_id, tx);
        let mut env = 2u32.to_be_bytes().to_vec();
        env.extend_from_slice(tx);
        env.extend_from_slice(&(signatures.len() as u32).to_be_bytes());
        for (hint, sig) in signatures {
            env.extend_from_slice(hint);
            env.extend_from_slice(&64u32.to_be_bytes());
            env.extend_from_slice(sig);
        }
        let text = b64e(&env);
        let want = lower_hex(&id);
        let to: Vec<usize> = match fanout {
            crate::endpoint::Fanout::First => vec![0],
            crate::endpoint::Fanout::All => (0..self.client.len()).collect(),
        };
        let outcomes = futures::future::join_all(to.iter().map(|&i| {
            let (text, want) = (text.clone(), want.clone());
            async move {
                let o = match self
                    .call(i, "sendTransaction", json!({"transaction": text}))
                    .await
                {
                    Err(FamilyError::Failure(failure)) => SendOutcome::Unreachable { failure },
                    Err(e) => SendOutcome::Refused {
                        reason: crate::error::endpoint_text(&e.to_string()),
                    },
                    Ok(r) => match (r["status"].as_str(), r["hash"].as_str()) {
                        (_, Some(h)) if !h.eq_ignore_ascii_case(&want) => SendOutcome::Refused {
                            reason: "another transaction id".into(),
                        },
                        (Some("PENDING" | "DUPLICATE"), Some(_)) => SendOutcome::Accepted,
                        (Some(s @ ("ERROR" | "TRY_AGAIN_LATER")), _) => SendOutcome::Refused {
                            reason: crate::error::endpoint_text(&format!(
                                "{s} {}",
                                r["errorResultXdr"].as_str().unwrap_or_default()
                            )),
                        },
                        _ => SendOutcome::Unreachable {
                            failure: EndpointFailure::new(
                                i,
                                FailureKind::AnswerMalformed,
                                "a sendTransaction answer out of its form",
                            ),
                        },
                    },
                };
                (i, o)
            }
        }))
        .await;
        let accepted: Vec<usize> = outcomes
            .iter()
            .filter(|(_, o)| *o == SendOutcome::Accepted)
            .map(|(i, _)| *i)
            .collect();
        Ok(if accepted.is_empty() {
            Broadcast::Rejected { id, outcomes }
        } else {
            Broadcast::Sent {
                id,
                accepted,
                others: outcomes
                    .into_iter()
                    .filter(|(_, o)| *o != SendOutcome::Accepted)
                    .collect(),
            }
        })
    }
}
