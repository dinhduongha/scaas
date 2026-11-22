// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Arweave as a store of ciphertext (CLI-RPC-13, CLI-RPC-14; feature `arweave`; chains-arweave plan T19): [`Gateways`] reads an
//! object by `GET /raw/{id}` within its exact length (failover, or a strict majority by SHA-256), each answer accepted only when
//! the caller's check passes; `status` and `settled` read GraphQL `transactions(ids:)` and `/info`. [`Bundlers`] posts one signed
//! data item (`POST /tx`) to the first or every bundler, a receipt counting only when its id is the id computed locally. Every
//! list is CLI-RPC-02's (ARCH-POS-15), each gateway naming its operator; the crate discovers nothing, follows no redirect, holds
//! no key and pays nothing (`x-paid-by` is the caller's, sent to one bundler only). Logs carry ids and sizes only (CLI-RPC-11).
//! Compiles for wasm32. UNAUDITED.
use crate::endpoint::{Class, NodeList, Policy, Purpose};
use crate::error::{EndpointFailure, FailureKind, RpcError};
use crate::http::{decode, Http};
use crate::pool::{BlockChoice, Pool, Probe, ReadError};
use scaas_ua::arweave::{b64url, id_bytes, DataItem};
use serde_json::{json, Value};
use std::sync::Arc;
use web_time::Instant;

/// The largest object a read takes: the platform's in-memory cap plus the GCM tag (CLI-RPC-13).
pub const READ_MAX: u64 = scaas_ua::file::CAP + scaas_ua::file::TAG;
/// A `/info`, GraphQL or receipt answer's cap and the depth of its JSON.
pub const ANSWER_MAX: usize = 64 << 10;
/// The settlement depth by default (CLI-RPC-13: Arweave blocks come about every 2 minutes).
pub const DEPTH: u64 = 50;
/// The most bytes of a bundler's own text an outcome keeps.
const RECEIPT_MAX: usize = 4096;

fn failure(i: usize, kind: FailureKind, text: &str) -> EndpointFailure {
    EndpointFailure::new(i, kind, text)
}

/// The id of a 43-character base64url string, before any request (`Argument`).
fn id_of(id: &str) -> Result<[u8; 32], RpcError> {
    id_bytes(id).map_err(|_| {
        RpcError::argument("an Arweave id that is not 43 canonical base64url characters")
    })
}

/// The gateways of one Arweave network (`network`, e.g. `arweave.N.1`), each with the operator it belongs to.
pub struct Gateways {
    list: Arc<NodeList>,
    operators: Vec<String>,
    network: String,
    http: Http,
    pool: Pool,
}

/// One gateway's view of an item: the block it is in (none while pending), the tip it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemStatus {
    pub endpoint: usize,
    pub block: Option<u64>,
    pub tip: u64,
}

impl Gateways {
    /// `operators[i]` is gateway `i`'s operator (one per endpoint, none empty: `Argument`).
    pub fn new(list: NodeList, operators: Vec<String>, network: &str) -> Result<Self, RpcError> {
        if operators.len() != list.len()
            || operators.iter().any(String::is_empty)
            || network.is_empty()
        {
            return Err(RpcError::argument(
                "one non-empty operator per gateway, and the network",
            ));
        }
        Ok(Self {
            http: Http::new(list.timeout_ms)?,
            // the network is pinned by its `/info` name, which a read that feeds a decryption requires (CLI-RPC-06)
            pool: Pool::new(&list, true),
            list: Arc::new(list),
            operators,
            network: network.to_string(),
        })
    }

    pub fn list(&self) -> &NodeList {
        &self.list
    }

    async fn info(&self, i: usize, deadline: Option<Instant>) -> Result<Value, EndpointFailure> {
        self.http
            .get_json(&self.list, i, "/info", ANSWER_MAX, deadline)
            .await
    }

    /// `GET /raw/{id}` of gateway `i`: exactly `len` bytes, then `check` (else `AnswerRefused`).
    async fn raw_at(
        &self,
        i: usize,
        id: &str,
        len: usize,
        check: &(dyn Fn(&[u8]) -> bool + Sync),
        deadline: Option<Instant>,
    ) -> Result<(Vec<u8>, [u8; 32]), EndpointFailure> {
        let (b, h) = self
            .http
            .get_exact(&self.list, i, &format!("/raw/{id}"), len, deadline)
            .await?;
        if !check(&b) {
            tracing::warn!(
                endpoint = i,
                id,
                len,
                "arweave: an object that fails the check; next gateway"
            );
            return Err(failure(
                i,
                FailureKind::AnswerRefused,
                "the object fails the caller's check",
            ));
        }
        Ok((b, h))
    }

    /// The object `id` of exactly `len` bytes whose `check` passes (CLI-RPC-13): `id` and `len` checked before any request;
    /// failover by default (a body that fails `check` is that gateway's failure), or a strict majority of ⌊n/2⌋ + 1 gateways
    /// returning bytes with one SHA-256 that pass `check`. `purpose` `FeedsDecryption` (every attachment read): discovered
    /// gateways skipped under failover; under agreement `n ≥ 3` and a named or default member.
    pub async fn data(
        &self,
        id: &str,
        len: u64,
        purpose: Purpose,
        check: &(dyn Fn(&[u8]) -> bool + Sync),
    ) -> Result<Vec<u8>, RpcError> {
        id_of(id)?;
        if len > READ_MAX {
            return Err(RpcError::argument("an object above the platform's cap"));
        }
        let len = usize::try_from(len)
            .map_err(|_| RpcError::argument("an object above the platform's cap"))?;
        tracing::debug!(id, len, "arweave: data read");
        if self.list.policy == Policy::Failover {
            let a = self
                .pool
                .failover(self, purpose, |i| async move {
                    self.raw_at(i, id, len, check, None)
                        .await
                        .map(|(b, _)| b)
                        .map_err(ReadError::Failure)
                })
                .await?;
            return Ok(a.value);
        }
        // strict majority by SHA-256 (no block: the id fixes the content)
        let n = self.list.len();
        let need = n / 2 + 1;
        let trusted = |i: usize| self.list.endpoints()[i].class != Class::Discovered;
        if purpose == Purpose::FeedsDecryption {
            if !(0..n).any(trusted) {
                return Err(RpcError::NoTrustedEndpoint);
            }
            if n < 3 && !(0..n).all(trusted) {
                return Err(RpcError::AgreementNeedsThree);
            }
        }
        let deadline = Some(self.pool.deadline());
        let answers = futures::future::join_all((0..n).map(|i| async move {
            self.pool.admit(self, i, deadline).await?;
            self.raw_at(i, id, len, check, deadline).await
        }))
        .await;
        let mut failures = vec![];
        let mut groups: Vec<([u8; 32], Vec<usize>, Vec<u8>)> = vec![];
        for (i, a) in answers.into_iter().enumerate() {
            match a {
                Ok((b, h)) => match groups.iter_mut().find(|g| g.0 == h) {
                    Some(g) => g.1.push(i),
                    None => groups.push((h, vec![i], b)),
                },
                Err(e) => failures.push(e),
            }
        }
        let largest = groups.iter().map(|g| g.1.len()).max().unwrap_or(0);
        match groups.into_iter().find(|g| {
            g.1.len() >= need && (purpose == Purpose::Plain || g.1.iter().any(|&m| trusted(m)))
        }) {
            Some((_, _, b)) => Ok(b),
            None => Err(RpcError::EndpointNoMajority {
                n,
                need,
                largest,
                failures,
            }),
        }
    }

    /// Gateway `i`'s view of item `id`: GraphQL `transactions(ids: [id])`'s block height (absent while pending) and the tip of
    /// its `/info`, each answer capped at 64 KiB and depth 64.
    pub async fn status_at(&self, i: usize, id: &str) -> Result<ItemStatus, RpcError> {
        id_of(id)?;
        let fail = |e: EndpointFailure| RpcError::EndpointAllFailed {
            last: Some(e),
            failover_revert: None,
        };
        self.pool.admit(self, i, None).await.map_err(fail)?;
        let q = json!({
            "query": "query($ids: [ID!]) { transactions(ids: $ids) { edges { node { id block { height } } } } }",
            "variables": {"ids": [id]},
        });
        let v = self
            .http
            .post_json(&self.list, i, Some("/graphql"), &q, ANSWER_MAX, None)
            .await
            .map_err(fail)?;
        let edges = v["data"]["transactions"]["edges"]
            .as_array()
            .filter(|e| e.len() <= 1)
            .ok_or_else(|| {
                fail(failure(
                    i,
                    FailureKind::AnswerMalformed,
                    "transactions without edges",
                ))
            })?;
        let block = match edges.first() {
            None => None,
            Some(e) => {
                if e["node"]["id"].as_str() != Some(id) {
                    return Err(fail(failure(
                        i,
                        FailureKind::AnswerMalformed,
                        "another item's status",
                    )));
                }
                match &e["node"]["block"] {
                    Value::Null => None,
                    b => Some(b["height"].as_u64().ok_or_else(|| {
                        fail(failure(
                            i,
                            FailureKind::AnswerMalformed,
                            "a block without a height",
                        ))
                    })?),
                }
            }
        };
        let tip = self.info(i, None).await.map_err(fail)?["height"]
            .as_u64()
            .ok_or_else(|| {
                fail(failure(
                    i,
                    FailureKind::AnswerMalformed,
                    "/info without a height",
                ))
            })?;
        Ok(ItemStatus {
            endpoint: i,
            block,
            tip,
        })
    }

    /// Whether item `id` is settled (CLI-RPC-13, C16): (a) a strict majority of the named and default gateways, at least two of
    /// them run by different operators, report it in one block; (b) that block is at least `depth` below the tip each of them
    /// reports; (c) one `data` read of `len` bytes returns bytes whose SHA-256 is `object_sha256`. Discovered gateways never
    /// count; with fewer than two operators nothing is ever settled.
    pub async fn settled(
        &self,
        id: &str,
        len: u64,
        depth: u64,
        object_sha256: &[u8; 32],
    ) -> Result<bool, RpcError> {
        id_of(id)?;
        let counted: Vec<usize> = (0..self.list.len())
            .filter(|&i| self.list.endpoints()[i].class != Class::Discovered)
            .collect();
        let need = counted.len() / 2 + 1;
        let views = futures::future::join_all(counted.iter().map(|&i| self.status_at(i, id))).await;
        let mut by_block: Vec<(u64, Vec<ItemStatus>)> = vec![];
        for s in views.into_iter().flatten() {
            if let Some(b) = s.block {
                match by_block.iter_mut().find(|g| g.0 == b) {
                    Some(g) => g.1.push(s),
                    None => by_block.push((b, vec![s])),
                }
            }
        }
        let Some((block, group)) = by_block.into_iter().find(|g| g.1.len() >= need) else {
            return Ok(false);
        };
        let mut ops: Vec<&str> = group
            .iter()
            .map(|s| self.operators[s.endpoint].as_str())
            .collect();
        ops.sort_unstable();
        ops.dedup();
        if group.len() < 2 || ops.len() < 2 {
            return Ok(false);
        }
        if group.iter().any(|s| s.tip < block.saturating_add(depth)) {
            return Ok(false);
        }
        let want = *object_sha256;
        let check = move |b: &[u8]| {
            use sha2::Digest as _;
            <[u8; 32]>::from(sha2::Sha256::digest(b)) == want
        };
        Ok(self.data(id, len, Purpose::Plain, &check).await.is_ok())
    }
}

impl Gateways {
    /// [`Gateways::settled`] of a kept item: its id, its object's length and SHA-256.
    pub async fn settled_item(&self, item: &DataItem, depth: u64) -> Result<bool, RpcError> {
        use sha2::Digest as _;
        let h: [u8; 32] = sha2::Sha256::digest(item.data()).into();
        self.settled(&item.id_b64(), item.data().len() as u64, depth, &h)
            .await
    }
}

/// The normalized address of an item's owner, base64url of SHA-256 of its public key, as an upload address in a payer
/// request (NODE-SPN-05; the form per type is the T18 probe's to confirm).
pub fn owner_address(item: &DataItem) -> String {
    use sha2::Digest as _;
    b64url(&sha2::Sha256::digest(item.owner()))
}

impl Probe for Gateways {
    type Hash = u64;
    /// `GET /info`'s `network` against the configured one (CLI-RPC-03).
    async fn same_chain(&self, i: usize, d: Option<Instant>) -> Result<bool, EndpointFailure> {
        let v = self.info(i, d).await?;
        let net = v["network"]
            .as_str()
            .ok_or_else(|| failure(i, FailureKind::AnswerMalformed, "/info without a network"))?;
        Ok(net == self.network)
    }
    async fn head(&self, i: usize, d: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.info(i, d).await?["height"]
            .as_u64()
            .ok_or_else(|| failure(i, FailureKind::AnswerMalformed, "/info without a height"))
    }
    async fn named(
        &self,
        i: usize,
        _: BlockChoice,
        d: Option<Instant>,
    ) -> Result<u64, EndpointFailure> {
        self.head(i, d).await
    }
    /// Arweave reads pin no block (the id fixes the content): a block is named by its height.
    async fn header(&self, _: usize, n: u64, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        Ok(n)
    }
}

// ---------------------------------------------------------------- bundlers (CLI-RPC-14)

/// One bundler's answer to an upload.
#[derive(Debug, Clone, PartialEq)]
pub enum BundlerOutcome {
    /// a 2xx receipt whose `id` is the item's (kept, capped)
    Accepted { receipt: Value },
    /// a refusal: HTTP 402 is `payment_required`; a receipt for another id is refused too
    Refused {
        status: u16,
        payment_required: bool,
        reason: String,
    },
    /// transport, timeout, a 3xx (never followed), a 5xx, an answer past its bounds
    Unreachable(EndpointFailure),
}

/// The merge of one upload to several bundlers (CLI-RPC-08): neither arm is final; settlement is read later (CLI-RPC-13).
#[derive(Debug, Clone, PartialEq)]
pub enum Upload {
    /// at least one bundler accepted it
    Sent {
        id: String,
        outcomes: Vec<(usize, BundlerOutcome)>,
    },
    /// none did
    Rejected {
        id: String,
        outcomes: Vec<(usize, BundlerOutcome)>,
    },
}

impl Upload {
    /// Some bundler refused for payment (HTTP 402): `PaymentRequired`.
    pub fn payment_required(&self) -> bool {
        let (Upload::Sent { outcomes, .. } | Upload::Rejected { outcomes, .. }) = self;
        outcomes.iter().any(|(_, o)| {
            matches!(
                o,
                BundlerOutcome::Refused {
                    payment_required: true,
                    ..
                }
            )
        })
    }
}

/// The bundlers of a release (`default` Turbo), with the largest single-request object.
pub struct Bundlers {
    list: Arc<NodeList>,
    http: Http,
    max_object: u64,
}

impl Bundlers {
    /// `max_object`: the bundler profile's largest single request (the body cap is it plus 1,024 B).
    pub fn new(list: NodeList, max_object: u64) -> Result<Self, RpcError> {
        Ok(Self {
            http: Http::new(list.timeout_ms)?,
            list: Arc::new(list),
            max_object,
        })
    }

    pub fn list(&self) -> &NodeList {
        &self.list
    }

    /// Posts the same bytes of `item` (`POST /tx`, `application/octet-stream`) to the first or every bundler; `paid_by` =
    /// `(bundler, payer)` sends `x-paid-by: payer` to that bundler only. The item is parsed and verified first (types 2, 3, 4)
    /// and its id computed locally; above the body cap nothing is sent (`BodyTooLarge`). The crate re-sends nothing.
    pub async fn upload(
        &self,
        item: &[u8],
        fanout: crate::Fanout,
        paid_by: Option<(usize, &str)>,
    ) -> Result<Upload, RpcError> {
        let cap = usize::try_from(self.max_object.saturating_add(1024)).unwrap_or(usize::MAX);
        if item.len() > cap {
            return Err(RpcError::BodyTooLarge {
                len: item.len(),
                cap,
            });
        }
        let it = DataItem::parse(item.to_vec())
            .map_err(|e| RpcError::argument(&format!("a data item refused: {e}")))?;
        let id = b64url(&it.id());
        if let Some((_, p)) = paid_by {
            if p.is_empty()
                || p.len() > 128
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            {
                return Err(RpcError::argument(
                    "x-paid-by is an address of base64url or hex characters",
                ));
            }
        }
        let targets: Vec<usize> = match fanout {
            crate::Fanout::First => vec![0],
            crate::Fanout::All => (0..self.list.len()).collect(),
        };
        let outs = futures::future::join_all(targets.iter().map(|&i| {
            let header = paid_by
                .filter(|(b, _)| *b == i)
                .map(|(_, p)| ("x-paid-by", p));
            let (item, id) = (item, id.as_str());
            async move { (i, self.post_at(i, item, id, header).await) }
        }))
        .await;
        tracing::info!(
            id = id.as_str(),
            len = item.len(),
            sent_to = targets.len(),
            "arweave: upload"
        );
        let ok = outs
            .iter()
            .any(|(_, o)| matches!(o, BundlerOutcome::Accepted { .. }));
        Ok(if ok {
            Upload::Sent { id, outcomes: outs }
        } else {
            Upload::Rejected { id, outcomes: outs }
        })
    }

    async fn post_at(
        &self,
        i: usize,
        item: &[u8],
        id: &str,
        header: Option<(&str, &str)>,
    ) -> BundlerOutcome {
        let r = self
            .http
            .raw_any(
                &self.list,
                i,
                reqwest::Method::POST,
                "/tx",
                Some(item.to_vec()),
                "application/octet-stream",
                ANSWER_MAX,
                None,
                header,
            )
            .await;
        let (status, b) = match r {
            Ok(x) => x,
            Err(e) => return BundlerOutcome::Unreachable(e),
        };
        if status >= 500 {
            return BundlerOutcome::Unreachable(failure(
                i,
                FailureKind::Http,
                &format!("HTTP {status}"),
            ));
        }
        let text = || {
            crate::error::endpoint_text(&String::from_utf8_lossy(
                b.get(..RECEIPT_MAX.min(b.len())).unwrap_or(&[]),
            ))
        };
        if !(200..300).contains(&status) {
            return BundlerOutcome::Refused {
                status,
                payment_required: status == 402,
                reason: text(),
            };
        }
        match decode(&b, ANSWER_MAX) {
            Ok(v) if v["id"].as_str() == Some(id) => BundlerOutcome::Accepted { receipt: v },
            Ok(_) => BundlerOutcome::Refused {
                status,
                payment_required: false,
                reason: "a receipt for another id".into(),
            },
            Err(k) => BundlerOutcome::Unreachable(failure(i, k, "the receipt")),
        }
    }
}
