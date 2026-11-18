// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The read rules over endpoint indices, without a transport (spec §4.3–§4.5): failover (CLI-RPC-04), strict majority
//! (CLI-RPC-05) and the decryption rule (CLI-RPC-06). The transport is the caller's [`Probe`] and read closures; the pool keeps the
//! classes, each endpoint's identity, the highest block seen from the first endpoint, the highest block agreed, and the failover
//! counters. It never sleeps or arms a timer: a whole read's deadline is computed from one clock (`web-time`) and handed to every
//! request, whose transport bounds it (F18).

use crate::endpoint::{Class, NodeList, Policy, Purpose};
use crate::error::{EndpointFailure, FailureKind, RpcError};
use futures::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use web_time::{Duration, Instant};

/// `Send` on native, nothing on wasm32 (F18).
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}
/// `Sync` on native, nothing on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

/// Which block an endpoint names for an agreed read (CLI-RPC-05 step 1): its head minus a depth (the default `Depth(1)`, F6),
/// its head, or its `finalized` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockChoice {
    Depth(u64),
    Latest,
    Finalized,
}

impl Default for BlockChoice {
    fn default() -> Self {
        BlockChoice::Depth(1)
    }
}

/// What the pool needs of an endpoint besides the read itself: its identity, its head, the block it names, a header's hash.
pub trait Probe: MaybeSync {
    type Hash: Clone + PartialEq + std::fmt::Debug + MaybeSend + MaybeSync;
    /// `Ok(true)`: endpoint `i` is the configured chain; `Ok(false)`: another one (dropped for good); `Err`: unread (asked again).
    fn same_chain(
        &self,
        i: usize,
        deadline: Option<Instant>,
    ) -> impl Future<Output = Result<bool, EndpointFailure>> + MaybeSend;
    /// Endpoint `i`'s head number.
    fn head(
        &self,
        i: usize,
        deadline: Option<Instant>,
    ) -> impl Future<Output = Result<u64, EndpointFailure>> + MaybeSend;
    /// The number endpoint `i` names for `choice`.
    fn named(
        &self,
        i: usize,
        choice: BlockChoice,
        deadline: Option<Instant>,
    ) -> impl Future<Output = Result<u64, EndpointFailure>> + MaybeSend;
    /// Endpoint `i`'s header hash at `number` (a header that answers another number is the endpoint's failure).
    fn header(
        &self,
        i: usize,
        number: u64,
        deadline: Option<Instant>,
    ) -> impl Future<Output = Result<Self::Hash, EndpointFailure>> + MaybeSend;
}

/// How one endpoint's read ended other than with a value: a revert (the contract's answer, its data as bytes) or a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    Revert { data: Vec<u8>, reason: String },
    Failure(EndpointFailure),
}

impl From<EndpointFailure> for ReadError {
    fn from(f: EndpointFailure) -> Self {
        ReadError::Failure(f)
    }
}

/// A failover answer: the value and the index of the endpoint that gave it (CLI-RPC-04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer<T> {
    pub value: T,
    pub endpoint: usize,
}

/// Where an agreed (or pinned) read runs: one endpoint, at block `number` whose hash is `hash`, within `deadline`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAt<H> {
    pub endpoint: usize,
    pub number: u64,
    pub hash: H,
    pub deadline: Option<Instant>,
}

/// An agreed read (CLI-RPC-05): the value, the block, the endpoints that agreed, and the highest number any endpoint named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agreed<T, H> {
    pub value: T,
    pub number: u64,
    pub hash: H,
    pub members: Vec<usize>,
    pub highest_named: u64,
}

/// The pool of one endpoint list (spec §4.3–§4.5).
pub struct Pool {
    classes: Vec<Class>,
    labels: Vec<Option<String>>,
    policy: Policy,
    read_timeout: Duration,
    /// an agreed read's freshness ([`crate::endpoint::MAX_LAG`], T13 S1)
    max_lag: u64,
    /// a `chain_uid` is pinned: required by strict majority and by a read that feeds a decryption (CLI-RPC-03)
    pinned: bool,
    identity: Arc<Vec<OnceLock<bool>>>,
    /// set beside a `false` identity when the endpoint was refused by name (T13 S16)
    refused: Vec<OnceLock<()>>,
    head: Arc<AtomicU64>,
    /// per block choice, the highest block an agreed read of it stood at (F12; T13 S2)
    floor: std::sync::Mutex<std::collections::HashMap<BlockChoice, u64>>,
    failover: AtomicU64,
    failover_total: Arc<AtomicU64>,
}

impl Pool {
    pub fn new(list: &NodeList, pinned: bool) -> Self {
        Self::shared(list, pinned, Default::default(), Default::default())
    }

    /// A pool of endpoints known by their classes only (T13 S11: a caller with its own transport, the PQZ verifier), with the
    /// read deadline `read_timeout_ms` and [`crate::endpoint::MAX_LAG`]; `strict_majority` needs two or more (`Argument`).
    pub fn of_classes(
        classes: &[Class],
        policy: Policy,
        read_timeout_ms: u64,
        pinned: bool,
    ) -> Result<Self, RpcError> {
        if classes.is_empty() {
            return Err(RpcError::EndpointListEmpty);
        }
        if read_timeout_ms == 0 || (policy == Policy::StrictMajority && classes.len() < 2) {
            return Err(RpcError::argument(
                "a zero read deadline, or strict_majority with one endpoint",
            ));
        }
        Ok(Self {
            classes: classes.to_vec(),
            labels: vec![None; classes.len()],
            policy,
            read_timeout: Duration::from_millis(read_timeout_ms),
            max_lag: crate::endpoint::MAX_LAG,
            pinned,
            identity: Arc::new(classes.iter().map(|_| OnceLock::new()).collect()),
            refused: classes.iter().map(|_| OnceLock::new()).collect(),
            head: Default::default(),
            floor: Default::default(),
            failover: AtomicU64::new(0),
            failover_total: Default::default(),
        })
    }

    /// With the highest-seen head and the total failover counter shared by several pools of one chain (the node's table).
    pub fn shared(
        list: &NodeList,
        pinned: bool,
        head: Arc<AtomicU64>,
        failover_total: Arc<AtomicU64>,
    ) -> Self {
        Self {
            classes: list.endpoints().iter().map(|e| e.class).collect(),
            labels: list
                .endpoints()
                .iter()
                .map(|e| e.label_str().map(str::to_string))
                .collect(),
            policy: list.policy,
            read_timeout: Duration::from_millis(list.read_timeout_ms),
            max_lag: list.max_lag,
            pinned,
            identity: Arc::new(list.endpoints().iter().map(|_| OnceLock::new()).collect()),
            refused: list.endpoints().iter().map(|_| OnceLock::new()).collect(),
            head,
            floor: Default::default(),
            failover: AtomicU64::new(0),
            failover_total,
        }
    }

    pub fn len(&self) -> usize {
        self.classes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
    pub fn policy(&self) -> Policy {
        self.policy
    }
    pub fn class(&self, i: usize) -> Class {
        self.classes[i]
    }
    /// Every endpoint's identity cell, shared (the node's `Chain` keeps them for its tests and health).
    pub fn identity_cells(&self) -> Arc<Vec<OnceLock<bool>>> {
        self.identity.clone()
    }
    /// The endpoint's cached identity: `Some(false)` dropped, `None` not read yet.
    pub fn identity_of(&self, i: usize) -> Option<bool> {
        self.identity[i].get().copied()
    }

    /// A block of this chain from the first endpoint (its head, a receipt): later endpoints below it answer no failover read.
    /// Nothing lowers it, and a later endpoint's own answer never raises it.
    pub fn saw_block(&self, n: u64) {
        self.head.fetch_max(n, Relaxed);
    }
    pub fn seen_head(&self) -> u64 {
        self.head.load(Relaxed)
    }
    /// How many reads an endpoint after the first used answered (a value, never a verdict).
    pub fn failover_answers(&self) -> u64 {
        self.failover.load(Relaxed)
    }
    pub fn failover_total(&self) -> u64 {
        self.failover_total.load(Relaxed)
    }
    /// The highest block an agreed read of `choice` stood at (T13 S2: one floor per choice; a `Finalized` read is far below
    /// the head and never held back by a read there).
    pub fn agreed_floor(&self, choice: BlockChoice) -> u64 {
        self.floor
            .lock()
            .map(|f| f.get(&choice).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    fn label(&self, f: EndpointFailure) -> EndpointFailure {
        let l = self.labels[f.endpoint].clone();
        f.with_label(l.as_deref())
    }

    /// The endpoints a read of `purpose` may use, in order: every one, or for a read that feeds a decryption the ones that are
    /// not `discovered` (none: `NoTrustedEndpoint`).
    pub fn usable(&self, purpose: Purpose) -> Result<Vec<usize>, RpcError> {
        let all = 0..self.len();
        let v: Vec<usize> = match purpose {
            Purpose::Plain => all.collect(),
            Purpose::FeedsDecryption => {
                if !self.pinned {
                    return Err(RpcError::argument(
                        "a read that feeds a decryption needs a pinned chain_uid",
                    ));
                }
                all.filter(|&i| self.classes[i] != Class::Discovered)
                    .collect()
            }
        };
        if v.is_empty() {
            return Err(RpcError::NoTrustedEndpoint);
        }
        Ok(v)
    }

    /// Endpoint `i` may be asked anything at all (T13 S3): it passes identity (every endpoint, the first included: T13 point 6).
    /// Every read and send outside the pool's own rules (the first-endpoint reads, a broadcast, the strict-majority fee) goes
    /// through this, so a dropped endpoint is never asked again.
    pub async fn admit<P: Probe>(
        &self,
        probe: &P,
        i: usize,
        deadline: Option<Instant>,
    ) -> Result<(), EndpointFailure> {
        self.identity_ok(probe, i, deadline).await
    }

    /// Endpoint `i` passes identity (cached once read; unread is asked again next time).
    async fn identity_ok<P: Probe>(
        &self,
        probe: &P,
        i: usize,
        deadline: Option<Instant>,
    ) -> Result<(), EndpointFailure> {
        let same = match self.identity[i].get() {
            Some(s) => *s,
            None => {
                let s = match probe.same_chain(i, deadline).await {
                    Ok(s) => s,
                    // T13 S16: refused by name, for good
                    Err(e) if e.kind == FailureKind::ChainIdentityUnreadable => {
                        let _ = self.identity[i].set(false);
                        let _ = self.refused[i].set(());
                        return Err(e);
                    }
                    Err(e) => {
                        return Err(EndpointFailure::new(
                            i,
                            FailureKind::IdentityUnread,
                            e.text(),
                        ))
                    }
                };
                if !s {
                    tracing::warn!(
                        endpoint = i,
                        label = self.labels[i].as_deref(),
                        "endpoint is another chain (chain id or block 0); dropped"
                    );
                }
                *self.identity[i].get_or_init(|| s)
            }
        };
        if same {
            Ok(())
        } else if self.refused[i].get().is_some() {
            Err(EndpointFailure::new(
                i,
                FailureKind::ChainIdentityUnreadable,
                "it serves no block 0 and names no checkpoint it matches",
            ))
        } else {
            Err(EndpointFailure::new(
                i,
                FailureKind::WrongChain,
                "another chain",
            ))
        }
    }

    /// CLI-RPC-04: one endpoint answers the whole read, in list order. The next starts from scratch when the current fails,
    /// is another chain, or (after the first used) is below the highest block seen; a revert is final from the first endpoint
    /// used only (a later one's is kept and moves on). One pass, no retry.
    ///
    /// `a_read_without_a_purpose_cannot_feed_a_decryption` (CLI-RPC-06): every read names its [`Purpose`]; one without does not
    /// compile (the control beside it does):
    ///
    /// ```compile_fail
    /// # use scaas_rpc::pool::{Pool, Probe, ReadError};
    /// # async fn f(p: &Pool, probe: &impl Probe) {
    /// let _ = p.failover(probe, |_i: usize| async { Ok::<u8, ReadError>(1) }).await;
    /// # }
    /// ```
    ///
    /// ```no_run
    /// # use scaas_rpc::pool::{Pool, Probe, ReadError};
    /// # async fn f(p: &Pool, probe: &impl Probe) {
    /// let _ = p.failover(probe, scaas_rpc::Purpose::FeedsDecryption, |_i: usize| async { Ok::<u8, ReadError>(1) }).await;
    /// # }
    /// ```
    pub async fn failover<T, P, F, Fut>(
        &self,
        probe: &P,
        purpose: Purpose,
        f: F,
    ) -> Result<Answer<T>, RpcError>
    where
        P: Probe,
        F: Fn(usize) -> Fut,
        Fut: Future<Output = Result<T, ReadError>>,
    {
        let order = self.usable(purpose)?;
        let first = order[0];
        let (mut last, mut failover_revert) = (None, None);
        for &i in &order {
            let fresh = async {
                self.identity_ok(probe, i, None).await?;
                if i != first {
                    let floor = self.head.load(Relaxed);
                    let n = probe.head(i, None).await?;
                    if n < floor {
                        return Err(EndpointFailure::new(
                            i,
                            FailureKind::BehindHead,
                            &format!("at block {n}, behind {floor}"),
                        ));
                    }
                }
                Ok(())
            };
            if let Err(e) = fresh.await {
                tracing::warn!(endpoint = i, label = self.labels[i].as_deref(), kind = ?e.kind, error = e.text(), "read: endpoint not used; next");
                last = Some(self.label(e));
                continue;
            }
            match f(i).await {
                Ok(value) => {
                    if i != first {
                        self.failover.fetch_add(1, Relaxed);
                        self.failover_total.fetch_add(1, Relaxed);
                    }
                    return Ok(Answer { value, endpoint: i });
                }
                Err(ReadError::Revert { data, reason }) if i == first => {
                    return Err(RpcError::Revert {
                        endpoint: i,
                        data,
                        reason,
                    })
                }
                Err(ReadError::Revert { data, reason }) => {
                    tracing::warn!(
                        endpoint = i,
                        "read: a failover endpoint's revert is no verdict; next"
                    );
                    let mut e = EndpointFailure::new(
                        i,
                        FailureKind::FailoverRevert,
                        &format!(
                            "endpoint {i} reverted (a failover endpoint decides nothing): {reason}"
                        ),
                    );
                    e.revert_data = Some(data.clone());
                    failover_revert = Some(data);
                    last = Some(self.label(e));
                }
                Err(ReadError::Failure(e)) => {
                    tracing::warn!(endpoint = i, kind = ?e.kind, error = e.text(), "read failed; next endpoint");
                    last = Some(self.label(e));
                }
            }
        }
        Err(RpcError::EndpointAllFailed {
            last,
            failover_revert,
        })
    }

    /// The deadline of one whole agreed read.
    pub fn deadline(&self) -> Instant {
        Instant::now() + self.read_timeout
    }

    /// CLI-RPC-05: the same complete answer at the same block from ⌊n/2⌋ + 1 endpoints of the list (spec §4.4). `f` runs on every
    /// endpoint, concurrently, pinned to `ReadAt`; a revert is a value compared by its data. Decides as soon as `need` equal
    /// answers have passed the re-check (the rest dropped); one fallback round at the next lower named number; one deadline.
    /// CLI-RPC-06 under strict majority: a `discovered` endpoint serves a decryption read only when `n ≥ 3`, and the agreeing
    /// group holds a `named` or `default` member (owner, Q6 (b)).
    pub async fn agree<T, P, F, Fut>(
        &self,
        probe: &P,
        choice: BlockChoice,
        purpose: Purpose,
        f: F,
    ) -> Result<Agreed<T, P::Hash>, RpcError>
    where
        T: Clone + PartialEq,
        P: Probe,
        F: Fn(ReadAt<P::Hash>) -> Fut,
        Fut: Future<Output = Result<T, ReadError>>,
    {
        let n = self.len();
        if n < 2 {
            return Err(RpcError::argument(
                "strict_majority needs two endpoints or more",
            ));
        }
        if !self.pinned {
            return Err(RpcError::argument(
                "strict_majority needs a pinned chain_uid",
            ));
        }
        let need = n / 2 + 1;
        let trusted = |i: usize| self.classes[i] != Class::Discovered;
        if purpose == Purpose::FeedsDecryption {
            if !(0..n).any(trusted) {
                return Err(RpcError::NoTrustedEndpoint);
            }
            if n < 3 && !(0..n).all(trusted) {
                return Err(RpcError::AgreementNeedsThree);
            }
        }
        let deadline = Some(self.deadline());
        let mut failures: Vec<EndpointFailure> = vec![];

        // (1) identity and the block each endpoint names, concurrently; every name is waited for (each one request, under its
        // timeout and the deadline): the need-th highest needs them all
        let names: Vec<Option<u64>> = futures::future::join_all((0..n).map(|i| async move {
            self.identity_ok(probe, i, deadline).await?;
            probe.named(i, choice, deadline).await
        }))
        .await
        .into_iter()
        .map(|r| r.map_err(|e| failures.push(self.label(e))).ok())
        .collect();
        let mut sorted: Vec<u64> = names.iter().flatten().copied().collect();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        let highest_named = sorted.first().copied().unwrap_or(0);
        let no = |largest: usize, failures: Vec<EndpointFailure>| RpcError::EndpointNoMajority {
            n,
            need,
            largest,
            failures,
        };
        if sorted.len() < need {
            return Err(no(0, failures));
        }
        // (2) the need-th highest, never below the floor
        let floor = self.agreed_floor(choice);
        let b = sorted[need - 1];
        if b < floor {
            failures.extend(
                (0..n)
                    .filter(|&i| names[i].is_some_and(|x| x < floor))
                    .map(|i| {
                        self.label(EndpointFailure::new(
                            i,
                            FailureKind::BehindHead,
                            &format!("names a block below the agreed {floor}"),
                        ))
                    }),
            );
            return Err(no(0, failures));
        }
        // ponytail: one fallback, the next lower *named* number (T13 S13, liveness only): at n = 5 two liars within the
        // tolerance can name numbers between the honest heads, so both rounds miss the block three honest endpoints share and
        // the read is EndpointNoMajority (fail closed, asked again). Upgrade: try each named number down to the floor.
        let fallback = sorted.iter().copied().find(|&x| x < b && x >= floor);
        let mut largest = 0;
        for number in std::iter::once(b).chain(fallback) {
            match self
                .round(probe, number, &names, deadline, need, purpose, &f)
                .await
            {
                Ok((value, hash, members)) => {
                    if let Ok(mut f) = self.floor.lock() {
                        let e = f.entry(choice).or_insert(0);
                        *e = (*e).max(number);
                    }
                    return match value {
                        Ok(value) => Ok(Agreed {
                            value,
                            number,
                            hash,
                            members,
                            highest_named,
                        }),
                        Err((data, reason)) => Err(RpcError::Revert {
                            endpoint: members[0],
                            data,
                            reason,
                        }),
                    };
                }
                Err((l, mut fs)) => {
                    largest = largest.max(l);
                    failures.append(&mut fs);
                }
            }
        }
        Err(no(largest, failures))
    }

    /// One round at block `number`: (3) each endpoint's header there, (4) the read pinned to it, (5) answers grouped whole, (6)
    /// a group of `need` re-reads its header and decides; the rest are dropped. `Err`: the largest group's size and the failures.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    async fn round<T, P, F, Fut>(
        &self,
        probe: &P,
        number: u64,
        names: &[Option<u64>],
        deadline: Option<Instant>,
        need: usize,
        purpose: Purpose,
        f: &F,
    ) -> Result<(Result<T, (Vec<u8>, String)>, P::Hash, Vec<usize>), (usize, Vec<EndpointFailure>)>
    where
        T: Clone + PartialEq,
        P: Probe,
        F: Fn(ReadAt<P::Hash>) -> Fut,
        Fut: Future<Output = Result<T, ReadError>>,
    {
        let n = self.len();
        // T13 S1: an endpoint counts at `number` only when it named a block and `number` is within `max_lag` of it, so a
        // group always holds members that call `number` fresh themselves
        let fresh = |i: usize| names[i].is_some_and(|x| number.saturating_add(self.max_lag) >= x);
        let mut failures = vec![];
        for i in (0..n).filter(|&i| names[i].is_some() && !fresh(i)) {
            failures.push(self.label(EndpointFailure::new(
                i,
                FailureKind::BehindHead,
                &format!("block {number} is more than {} below its own", self.max_lag),
            )));
        }
        let mut pending: FuturesUnordered<_> = (0..n)
            .filter(|&i| fresh(i))
            .map(|i| async move {
                let r = async {
                    self.identity_ok(probe, i, deadline).await?;
                    let hash = probe.header(i, number, deadline).await?;
                    let v = match f(ReadAt {
                        endpoint: i,
                        number,
                        hash: hash.clone(),
                        deadline,
                    })
                    .await
                    {
                        Ok(v) => Ok(v),
                        Err(ReadError::Revert { data, reason }) => Err((data, reason)),
                        Err(ReadError::Failure(e)) => return Err(e),
                    };
                    Ok((v, hash))
                }
                .await;
                (i, r)
            })
            .collect();
        // groups of equal (answer, hash): members, and which of them passed the re-check
        let mut groups: Vec<(
            Result<T, (Vec<u8>, String)>,
            P::Hash,
            Vec<usize>,
            Vec<usize>,
        )> = vec![];
        let same = |a: &Result<T, (Vec<u8>, String)>, b: &Result<T, (Vec<u8>, String)>| match (a, b)
        {
            (Ok(x), Ok(y)) => x == y,
            // a revert compares by its data; one without data by its reason too (T13 S17: two node-side errors without data are
            // no agreed revert)
            (Err((x, rx)), Err((y, ry))) => x == y && (!x.is_empty() || rx == ry),
            _ => false,
        };
        while let Some((i, r)) = pending.next().await {
            let (v, hash) = match r {
                Ok(x) => x,
                Err(e) => {
                    failures.push(self.label(e));
                    continue;
                }
            };
            let g = match groups.iter().position(|g| g.1 == hash && same(&g.0, &v)) {
                Some(g) => g,
                None => {
                    groups.push((v, hash, vec![], vec![]));
                    groups.len() - 1
                }
            };
            groups[g].2.push(i);
            if groups[g].2.len() < need {
                continue;
            }
            // (6) the re-check: each member not yet re-checked reads the header at `number` again; a moved hash leaves
            let (hash, members, checked) = (
                groups[g].1.clone(),
                groups[g].2.clone(),
                groups[g].3.clone(),
            );
            let todo: Vec<usize> = members
                .iter()
                .copied()
                .filter(|m| !checked.contains(m))
                .collect();
            let again =
                futures::future::join_all(todo.iter().map(|&m| probe.header(m, number, deadline)))
                    .await;
            for (&m, h) in todo.iter().zip(again) {
                match h {
                    Ok(h) if h == hash => groups[g].3.push(m),
                    Ok(_) => {
                        groups[g].2.retain(|x| *x != m);
                        failures.push(self.label(EndpointFailure::new(
                            m,
                            FailureKind::BlockChanged,
                            &format!("block {number} changed"),
                        )));
                    }
                    Err(e) => {
                        groups[g].2.retain(|x| *x != m);
                        failures.push(self.label(e));
                    }
                }
            }
            let ok = &groups[g].3;
            let trusted_member = purpose == Purpose::Plain
                || ok.iter().any(|&m| self.classes[m] != Class::Discovered);
            if ok.len() >= need && trusted_member {
                let mut members = ok.clone();
                members.sort_unstable();
                let (v, h) = (groups[g].0.clone(), groups[g].1.clone());
                return Ok((v, h, members));
            }
        }
        Err((
            groups.iter().map(|g| g.2.len()).max().unwrap_or(0),
            failures,
        ))
    }
}

/// The indexers' event-set quorum (NODE-IDX-01, moved from the node's `finality.rs`): the first endpoint always counts; `others`
/// are the remaining independent endpoints.
pub fn quorum_ok<H: PartialEq>(primary: H, others: &[Option<H>], quorum: usize) -> bool {
    1 + others
        .iter()
        .filter(|h| h.as_ref() == Some(&primary))
        .count()
        >= quorum
}
