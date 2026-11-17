// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T3: failover (CLI-RPC-04), agreement (CLI-RPC-05) and the decryption rule (CLI-RPC-06) over fake endpoints given by
//! index: no network. Time is real and short (a pool deadline is `web-time`'s clock, which a paused tokio clock does not move).
//! Each refusal has its positive control beside it.
use scaas_rpc::pool::{Agreed, BlockChoice, Pool, Probe, ReadAt, ReadError};
use scaas_rpc::{Class, Endpoint, EndpointFailure, FailureKind, NodeList, Policy, Purpose, RpcError};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use web_time::{Duration, Instant};

/// One fake endpoint.
#[derive(Clone)]
struct Ep {
    /// `None`: the identity is unreadable
    same: Option<bool>,
    head: Option<u64>,
    /// the number it names for an agreed read; `None`: it fails
    name: Option<u64>,
    /// it holds headers up to here (a header above is its failure)
    tip: u64,
    /// its header hash at `n` is `(fork, n)`
    fork: u8,
    /// after this many header reads its hash moves (a reorg)
    reorg_after: Option<usize>,
    /// each request takes this long (bounded by the read's deadline, as the transport bounds it)
    delay_ms: u64,
}

fn ep(head: u64) -> Ep {
    Ep { same: Some(true), head: Some(head), name: Some(head), tip: head, fork: 0, reorg_after: None, delay_ms: 0 }
}

struct Fake {
    eps: Vec<Ep>,
    /// every probe request and every read, per endpoint
    reqs: Vec<AtomicUsize>,
    identity: Vec<AtomicUsize>,
    headers: Vec<AtomicUsize>,
}

impl Fake {
    fn new(eps: Vec<Ep>) -> Arc<Self> {
        let z = |n: usize| (0..n).map(|_| AtomicUsize::new(0)).collect();
        Arc::new(Self { reqs: z(eps.len()), identity: z(eps.len()), headers: z(eps.len()), eps })
    }
    fn total(&self) -> usize {
        (0..self.eps.len()).map(|i| self.reqs[i].load(SeqCst)).sum()
    }
    async fn wait(&self, i: usize, deadline: Option<Instant>) -> Result<(), EndpointFailure> {
        self.reqs[i].fetch_add(1, SeqCst);
        let d = Duration::from_millis(self.eps[i].delay_ms);
        let left = deadline.map(|x| x.saturating_duration_since(Instant::now()));
        if let Some(l) = left.filter(|l| *l < d) {
            tokio::time::sleep(std::time::Duration::from_millis(l.as_millis() as u64)).await;
            return Err(EndpointFailure::new(i, FailureKind::Timeout, "deadline"));
        }
        if !d.is_zero() {
            tokio::time::sleep(std::time::Duration::from_millis(self.eps[i].delay_ms)).await;
        }
        Ok(())
    }
}

fn fail(i: usize) -> EndpointFailure {
    EndpointFailure::new(i, FailureKind::Transport, "down")
}

impl Probe for Fake {
    type Hash = (u8, u64);
    async fn same_chain(&self, i: usize, d: Option<Instant>) -> Result<bool, EndpointFailure> {
        self.identity[i].fetch_add(1, SeqCst);
        self.wait(i, d).await?;
        self.eps[i].same.ok_or_else(|| fail(i))
    }
    async fn head(&self, i: usize, d: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.wait(i, d).await?;
        self.eps[i].head.ok_or_else(|| fail(i))
    }
    async fn named(&self, i: usize, _c: BlockChoice, d: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.wait(i, d).await?;
        self.eps[i].name.ok_or_else(|| fail(i))
    }
    async fn header(&self, i: usize, n: u64, d: Option<Instant>) -> Result<(u8, u64), EndpointFailure> {
        self.wait(i, d).await?;
        let k = self.headers[i].fetch_add(1, SeqCst);
        let e = &self.eps[i];
        if n > e.tip {
            return Err(EndpointFailure::new(i, FailureKind::Transport, "header not found"));
        }
        let moved = e.reorg_after.is_some_and(|r| k >= r);
        Ok((if moved { e.fork + 100 } else { e.fork }, n))
    }
}

fn list_of(classes: &[Class], policy: Policy, read_timeout_ms: u64) -> NodeList {
    let e = classes.iter().enumerate().map(|(i, c)| Endpoint::new(&format!("http://e{i}.example"), *c, None, None).unwrap()).collect();
    NodeList::new(e, policy, 5_000, 5_000, read_timeout_ms).unwrap()
}
fn named(n: usize, policy: Policy) -> Pool {
    Pool::new(&list_of(&vec![Class::Named; n], policy, 5_000), true)
}

/// One fake read's future.
type ReadFut = std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, ReadError>> + Send>>;

/// A read whose answer is `answers[i]` (a value, a revert with data `[i]`, or a failure), counted as a request.
#[derive(Clone, Copy, Debug)]
enum A {
    V(u64),
    Rev,
    Down,
    /// never answers
    Hung,
}

fn read(fake: &Arc<Fake>, answers: Vec<A>) -> impl Fn(usize) -> ReadFut {
    let fake = fake.clone();
    move |i| {
        let (fake, a) = (fake.clone(), answers[i]);
        Box::pin(async move {
            fake.reqs[i].fetch_add(1, SeqCst);
            match a {
                A::V(v) => Ok(v),
                A::Rev => Err(ReadError::Revert { data: vec![i as u8], reason: "reverted".into() }),
                A::Down => Err(ReadError::Failure(fail(i))),
                A::Hung => futures::future::pending().await,
            }
        })
    }
}

/// A pinned read for `agree`: endpoint `i` answers `answers[i]` at every block (`V(x)` reads as `x * 1000 + number` when
/// `by_block`), after its delay.
fn at(fake: &Arc<Fake>, answers: Vec<A>, by_block: bool)
    -> impl Fn(ReadAt<(u8, u64)>) -> ReadFut {
    let fake = fake.clone();
    move |p: ReadAt<(u8, u64)>| {
        let (fake, a) = (fake.clone(), answers[p.endpoint]);
        Box::pin(async move {
            fake.wait(p.endpoint, p.deadline).await?;
            match a {
                A::V(v) => Ok(if by_block { v * 1000 + p.number } else { v }),
                A::Rev => Err(ReadError::Revert { data: vec![7], reason: "reverted".into() }),
                A::Down => Err(ReadError::Failure(fail(p.endpoint))),
                A::Hung => futures::future::pending().await,
            }
        })
    }
}

// ---------------------------------------------------------------- failover

#[tokio::test]
async fn the_first_answer_wins() {
    let f = Fake::new(vec![ep(10), ep(10), ep(10)]);
    let a = named(3, Policy::Failover).failover(&*f, Purpose::Plain, read(&f, vec![A::V(1), A::V(2), A::V(3)])).await.unwrap();
    assert_eq!((a.value, a.endpoint), (1, 0));
    assert_eq!((f.reqs[1].load(SeqCst), f.reqs[2].load(SeqCst)), (0, 0), "the others are never asked");
}

#[tokio::test]
async fn a_transport_failure_moves_on() {
    let f = Fake::new(vec![ep(10), ep(10)]);
    let a = named(2, Policy::Failover).failover(&*f, Purpose::Plain, read(&f, vec![A::Down, A::V(2)])).await.unwrap();
    assert_eq!((a.value, a.endpoint), (2, 1));
}

#[tokio::test]
async fn a_revert_from_the_first_is_final() {
    let f = Fake::new(vec![ep(10), ep(10)]);
    let e = named(2, Policy::Failover).failover(&*f, Purpose::Plain, read(&f, vec![A::Rev, A::V(2)])).await.unwrap_err();
    assert_eq!(e, RpcError::Revert { endpoint: 0, data: vec![0], reason: "reverted".into() });
    assert_eq!(f.reqs[1].load(SeqCst), 0, "the next endpoint is never asked after a revert");
}

#[tokio::test]
async fn a_revert_from_a_later_endpoint_moves_on_and_keeps_its_data() {
    let f = Fake::new(vec![ep(10), ep(10), ep(10)]);
    let p = named(3, Policy::Failover);
    let a = p.failover(&*f, Purpose::Plain, read(&f, vec![A::Down, A::Rev, A::V(3)])).await.unwrap();
    assert_eq!((a.value, a.endpoint), (3, 2), "the revert of endpoint 1 decides nothing");
    let e = p.failover(&*f, Purpose::Plain, read(&f, vec![A::Down, A::Rev, A::Down])).await.unwrap_err();
    match e {
        RpcError::EndpointAllFailed { last, failover_revert } => {
            assert_eq!(failover_revert, Some(vec![1]), "its data is kept");
            assert_eq!(last.unwrap().endpoint, 2);
        }
        e => panic!("{e:?}"),
    }
}

#[tokio::test]
async fn a_later_endpoint_behind_the_head_is_skipped() {
    let f = Fake::new(vec![ep(100), ep(90), ep(100), ep(200)]);
    let p = named(4, Policy::Failover);
    p.saw_block(100);
    let a = p.failover(&*f, Purpose::Plain, read(&f, vec![A::Down, A::V(2), A::V(3), A::V(4)])).await.unwrap();
    assert_eq!(a.endpoint, 2, "endpoint 1 at 90 is behind 100");
    assert_eq!(f.reqs[1].load(SeqCst), 2, "its identity and head only, no read");
    let a = p.failover(&*f, Purpose::Plain, read(&f, vec![A::Down, A::Down, A::Down, A::V(4)])).await.unwrap();
    assert_eq!(a.endpoint, 3, "control: at or above the head");
    assert_eq!(p.seen_head(), 100, "a later endpoint's head raises nothing");
    let g = Fake::new(vec![ep(100), ep(100)]);
    assert_eq!(p.failover(&*g, Purpose::Plain, read(&g, vec![A::Down, A::V(2), A::V(0), A::V(0)])).await.unwrap().endpoint, 1,
        "control: at the head");
}

#[tokio::test]
async fn a_wrong_chain_endpoint_is_dropped_for_good() {
    let mut other = ep(10);
    other.same = Some(false);
    let f = Fake::new(vec![ep(10), other, ep(10)]);
    let p = named(3, Policy::Failover);
    for _ in 0..3 {
        assert_eq!(p.failover(&*f, Purpose::Plain, read(&f, vec![A::Down, A::V(2), A::V(3)])).await.unwrap().endpoint, 2);
    }
    assert_eq!(f.identity[1].load(SeqCst), 1, "checked once");
    assert_eq!(f.reqs[1].load(SeqCst), 1, "never read");
    assert_eq!(p.identity_of(1), Some(false));
}

#[tokio::test]
async fn the_first_endpoint_is_identity_checked_too() {
    let mut other = ep(10);
    other.same = Some(false);
    let f = Fake::new(vec![other, ep(10)]);
    let a = named(2, Policy::Failover).failover(&*f, Purpose::Plain, read(&f, vec![A::V(1), A::V(2)])).await.unwrap();
    assert_eq!(a.endpoint, 1, "endpoint 0 is another chain");
    let g = Fake::new(vec![ep(10), ep(10)]);
    assert_eq!(named(2, Policy::Failover).failover(&*g, Purpose::Plain, read(&g, vec![A::V(1), A::V(2)])).await.unwrap().endpoint, 0,
        "control");
    assert_eq!(g.identity[0].load(SeqCst), 1, "and it was checked");
}

#[tokio::test]
async fn an_unreadable_identity_is_asked_again() {
    let mut mute = ep(10);
    mute.same = None;
    let f = Fake::new(vec![ep(10), mute, ep(10)]);
    let p = named(3, Policy::Failover);
    for _ in 0..2 {
        assert_eq!(p.failover(&*f, Purpose::Plain, read(&f, vec![A::Down, A::V(2), A::V(3)])).await.unwrap().endpoint, 2);
    }
    assert_eq!(f.identity[1].load(SeqCst), 2, "asked again, not kept");
    assert_eq!(p.identity_of(1), None);
}

#[tokio::test]
async fn failover_answers_are_counted() {
    let total = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let l = list_of(&[Class::Named, Class::Named], Policy::Failover, 5_000);
    let (p, q) = (Pool::shared(&l, true, Default::default(), total.clone()), Pool::shared(&l, true, Default::default(), total.clone()));
    let f = Fake::new(vec![ep(10), ep(10)]);
    p.failover(&*f, Purpose::Plain, read(&f, vec![A::V(1), A::V(2)])).await.unwrap();
    assert_eq!(p.failover_answers(), 0, "control: the first endpoint's answer is not counted");
    p.failover(&*f, Purpose::Plain, read(&f, vec![A::Down, A::V(2)])).await.unwrap();
    assert_eq!((p.failover_answers(), q.failover_answers(), total.load(SeqCst)), (1, 0, 1), "per pool, and in the shared total");
}

#[tokio::test]
async fn all_failing_is_all_failed_with_the_last() {
    let mut behind = ep(5);
    behind.head = Some(5);
    let f = Fake::new(vec![ep(10), ep(10), behind]);
    let p = named(3, Policy::Failover);
    p.saw_block(10);
    match p.failover(&*f, Purpose::Plain, read(&f, vec![A::Down, A::Down, A::V(3)])).await.unwrap_err() {
        RpcError::EndpointAllFailed { last: Some(l), failover_revert: None } => assert_eq!((l.endpoint, l.kind), (2, FailureKind::BehindHead)),
        e => panic!("{e:?}"),
    }
}

#[tokio::test]
async fn answers_are_never_mixed() {
    // a read of two requests: endpoint 0 answers the first and fails the second; the whole read runs again on endpoint 1
    let f = Fake::new(vec![ep(10), ep(10)]);
    let parts = |i: usize| async move {
        let first = 10 * (i as u64 + 1);
        if i == 0 {
            return Err(ReadError::Failure(fail(0)));
        }
        Ok((first, first + 1))
    };
    let a = named(2, Policy::Failover).failover(&*f, Purpose::Plain, parts).await.unwrap();
    assert_eq!((a.value, a.endpoint), ((20, 21), 1), "both parts from endpoint 1");
}

// ---------------------------------------------------------------- agreement

async fn agree(p: &Pool, f: &Arc<Fake>, answers: Vec<A>) -> Result<Agreed<u64, (u8, u64)>, RpcError> {
    p.agree(&**f, BlockChoice::Depth(1), Purpose::Plain, at(f, answers, false)).await
}

#[tokio::test]
async fn three_honest_agree() {
    let f = Fake::new(vec![ep(100); 3]);
    let a = agree(&named(3, Policy::StrictMajority), &f, vec![A::V(5); 3]).await.unwrap();
    assert_eq!((a.value, a.number, a.hash, a.highest_named), (5, 100, (0, 100), 100));
    assert!(a.members.len() >= 2);
}

#[tokio::test]
async fn one_liar_is_outvoted() {
    let f = Fake::new(vec![ep(100); 3]);
    let a = agree(&named(3, Policy::StrictMajority), &f, vec![A::V(5), A::V(6), A::V(5)]).await.unwrap();
    assert_eq!((a.value, a.members), (5, vec![0, 2]));
}

#[tokio::test]
async fn two_lie_on_different_words_is_no_majority() {
    // answers are whole values: (word 1, word 2); a field-by-field majority would make (1, 1)
    let f = Fake::new(vec![ep(100); 3]);
    let words = [(1u64, 1u64), (9, 1), (1, 9)];
    let r = named(3, Policy::StrictMajority).agree(&*f, BlockChoice::Depth(1), Purpose::Plain, |p: ReadAt<(u8, u64)>| async move {
        Ok::<_, ReadError>(words[p.endpoint])
    }).await;
    assert!(matches!(r, Err(RpcError::EndpointNoMajority { n: 3, need: 2, largest: 1, .. })), "{r:?}");
    let ok = named(3, Policy::StrictMajority).agree(&*f, BlockChoice::Depth(1), Purpose::Plain, |p: ReadAt<(u8, u64)>| async move {
        Ok::<_, ReadError>([(1u64, 1u64), (9, 1), (1, 1)][p.endpoint])
    }).await.unwrap();
    assert_eq!(ok.value, (1, 1), "control: two whole answers equal");
}

#[tokio::test]
async fn four_two_agree_two_fail_is_no_majority() {
    let f = Fake::new(vec![ep(100); 4]);
    let r = agree(&named(4, Policy::StrictMajority), &f, vec![A::V(5), A::V(5), A::Down, A::Down]).await;
    assert!(matches!(r, Err(RpcError::EndpointNoMajority { n: 4, need: 3, largest: 2, .. })), "{r:?}");
    // the two fail already when naming their block: they still count in n
    let mut mute = ep(100);
    mute.name = None;
    let f = Fake::new(vec![ep(100), ep(100), mute.clone(), mute]);
    let r = agree(&named(4, Policy::StrictMajority), &f, vec![A::V(5); 4]).await;
    assert!(matches!(r, Err(RpcError::EndpointNoMajority { n: 4, need: 3, .. })), "{r:?}");
    let f = Fake::new(vec![ep(100); 4]);
    assert!(agree(&named(4, Policy::StrictMajority), &f, vec![A::V(5), A::V(5), A::V(5), A::Down]).await.is_ok(), "control: three");
}

#[tokio::test]
async fn need_is_a_strict_majority_of_the_list() {
    let f = Fake::new(vec![ep(100); 2]);
    assert!(agree(&named(2, Policy::StrictMajority), &f, vec![A::V(5), A::Down]).await.is_err(), "n = 2 needs both");
    let f = Fake::new(vec![ep(100); 2]);
    assert!(agree(&named(2, Policy::StrictMajority), &f, vec![A::V(5), A::V(5)]).await.is_ok(), "control");
    let f = Fake::new(vec![ep(100); 5]);
    assert!(agree(&named(5, Policy::StrictMajority), &f, vec![A::V(5), A::V(5), A::V(6), A::Down, A::Down]).await.is_err(), "5 needs 3");
    let f = Fake::new(vec![ep(100); 5]);
    assert!(agree(&named(5, Policy::StrictMajority), &f, vec![A::V(5), A::V(5), A::V(5), A::Down, A::Down]).await.is_ok());
}

#[tokio::test]
async fn the_block_is_the_need_th_highest_named() {
    // one endpoint names block 1, where the state differs: the read is at the 2nd highest, 100
    let mut old = ep(100);
    old.name = Some(1);
    let f = Fake::new(vec![ep(100), old, ep(100)]);
    let a = named(3, Policy::StrictMajority).agree(&*f, BlockChoice::Depth(1), Purpose::Plain, at(&f, vec![A::V(5); 3], true)).await.unwrap();
    assert_eq!((a.number, a.value), (100, 5_100));
}

#[tokio::test]
async fn a_far_future_liar_at_n_3_agrees_in_the_fallback_round() {
    // F6: honest heads 100 and 99, a liar names 10^9: b = 100, which only one honest endpoint holds; the fallback at 99 agrees
    let mut liar = ep(1_000_000_000);
    liar.fork = 9;
    let f = Fake::new(vec![ep(100), ep(99), liar]);
    let a = named(3, Policy::StrictMajority).agree(&*f, BlockChoice::Depth(1), Purpose::Plain, at(&f, vec![A::V(5), A::V(5), A::V(6)], true))
        .await.unwrap();
    assert_eq!((a.number, a.members.clone(), a.value, a.highest_named), (99, vec![0, 1], 5_099, 1_000_000_000));
}

#[tokio::test]
async fn a_far_future_liar_at_n_5_agrees_in_the_fallback_round() {
    let mut liar = ep(1_000_000_000);
    liar.fork = 9;
    let f = Fake::new(vec![ep(100), ep(100), ep(99), ep(99), liar]);
    let a = named(5, Policy::StrictMajority).agree(&*f, BlockChoice::Depth(1), Purpose::Plain, at(&f, vec![A::V(5), A::V(5), A::V(5), A::V(5), A::V(6)], true))
        .await.unwrap();
    assert_eq!(a.number, 99);
    assert!(a.members.len() >= 3 && !a.members.contains(&4), "{:?}", a.members);
}

#[tokio::test]
async fn two_fast_equal_and_one_hung_decide_before_the_timeout() {
    // F7: endpoint 2 names its block and hangs on the read; the two fast equal answers decide, the hung read is dropped
    let f = Fake::new(vec![ep(100); 3]);
    let p = Pool::new(&list_of(&[Class::Named; 3], Policy::StrictMajority, 10_000), true);
    let t = Instant::now();
    let a = tokio::time::timeout(std::time::Duration::from_secs(5), agree(&p, &f, vec![A::V(5), A::V(5), A::Hung])).await
        .expect("decided without the hung endpoint").unwrap();
    assert_eq!(a.members, vec![0, 1]);
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
}

#[tokio::test]
async fn a_slow_endpoint_is_bounded_by_the_read_deadline() {
    // F7: endpoints 0 and 1 disagree; endpoint 2 answers every request after 400 ms (named, header, read, re-check: 1.6 s), equal
    // to endpoint 0; the read's deadline of 1 s ends it
    let mut slow = ep(100);
    slow.delay_ms = 400;
    let f = Fake::new(vec![ep(100), ep(100), slow]);
    let p = Pool::new(&list_of(&[Class::Named; 3], Policy::StrictMajority, 1_000), true);
    let t = Instant::now();
    let r = agree(&p, &f, vec![A::V(5), A::V(6), A::V(5)]).await;
    assert!(matches!(r, Err(RpcError::EndpointNoMajority { .. })), "{r:?}");
    assert!(t.elapsed() < Duration::from_millis(1_400), "within the read's deadline: {:?}", t.elapsed());
    let p = Pool::new(&list_of(&[Class::Named; 3], Policy::StrictMajority, 5_000), true);
    let f = Fake::new(vec![ep(100), ep(100), { let mut s = ep(100); s.delay_ms = 400; s }]);
    assert_eq!(agree(&p, &f, vec![A::V(5), A::V(6), A::V(5)]).await.unwrap().members, vec![0, 2], "control: a longer deadline");
}

#[tokio::test]
async fn an_agreement_below_the_last_agreed_block_is_refused() {
    let p = named(3, Policy::StrictMajority);
    let f = Fake::new(vec![ep(100); 3]);
    assert_eq!(agree(&p, &f, vec![A::V(5); 3]).await.unwrap().number, 100);
    assert_eq!(p.agreed_floor(), 100);
    let mut lag = ep(100);
    lag.name = Some(90);
    let g = Fake::new(vec![lag.clone(), lag, ep(100)]);
    match agree(&p, &g, vec![A::V(5); 3]).await {
        Err(RpcError::EndpointNoMajority { failures, .. }) => assert!(failures.iter().any(|f| f.kind == FailureKind::BehindHead), "{failures:?}"),
        r => panic!("{r:?}"),
    }
    assert_eq!(g.headers.iter().map(|h| h.load(SeqCst)).sum::<usize>(), 0, "no read at 90");
    assert!(agree(&p, &Fake::new(vec![ep(100); 3]), vec![A::V(5); 3]).await.is_ok(), "control: at the floor");
}

#[tokio::test]
async fn strict_majority_without_a_pinned_chain_uid_is_argument() {
    let l = list_of(&[Class::Named; 3], Policy::StrictMajority, 5_000);
    let f = Fake::new(vec![ep(100); 3]);
    let e = agree(&Pool::new(&l, false), &f, vec![A::V(5); 3]).await.unwrap_err();
    assert_eq!(e.code(), "Argument");
    assert_eq!(f.total(), 0, "before any request");
    assert!(agree(&Pool::new(&l, true), &f, vec![A::V(5); 3]).await.is_ok(), "control: pinned");
}

#[tokio::test]
async fn equal_answers_with_an_extra_field_agree() {
    // I1: the read projects an answer to the fields it defines; an honest client's extra `blockTimestamp` is not compared
    let f = Fake::new(vec![ep(100); 3]);
    let raw = [serde_json::json!({"data": "0x01", "blockTimestamp": "0x5"}), serde_json::json!({"data": "0x01"}),
        serde_json::json!({"data": "0x02"})];
    let a = named(3, Policy::StrictMajority).agree(&*f, BlockChoice::Depth(1), Purpose::Plain, |p: ReadAt<(u8, u64)>| {
        let v = raw[p.endpoint].clone();
        async move { Ok::<_, ReadError>(v["data"].as_str().unwrap().to_string()) }
    }).await.unwrap();
    assert_eq!((a.value.as_str(), a.members), ("0x01", vec![0, 1]));
}

#[tokio::test]
async fn a_member_whose_block_hash_differs_is_outside_the_group() {
    let mut forked = ep(100);
    forked.fork = 1;
    let f = Fake::new(vec![ep(100), forked, ep(100)]);
    let a = agree(&named(3, Policy::StrictMajority), &f, vec![A::V(5); 3]).await.unwrap();
    assert_eq!(a.members, vec![0, 2], "the same value at another block hash is another answer");
    // the forked one answers first: the honest two still group by their own hash
    let slow = |d: u64| { let mut x = ep(100); x.delay_ms = d; x };
    let mut fast_fork = ep(100);
    fast_fork.fork = 1;
    let f = Fake::new(vec![slow(60), fast_fork, slow(60)]);
    assert_eq!(agree(&named(3, Policy::StrictMajority), &f, vec![A::V(5); 3]).await.unwrap().members, vec![0, 2]);
    let f = Fake::new(vec![ep(100), { let mut x = ep(100); x.fork = 1; x }, { let mut x = ep(100); x.fork = 2; x }]);
    assert!(agree(&named(3, Policy::StrictMajority), &f, vec![A::V(5); 3]).await.is_err(), "three hashes: no majority");
}

#[tokio::test]
async fn a_reorg_during_the_read_is_block_changed() {
    // endpoint 1's header moves after its first read: it leaves at the re-check; 0 and 2 still agree
    let mut reorg = ep(100);
    reorg.reorg_after = Some(1);
    let f = Fake::new(vec![ep(100), reorg.clone(), ep(100)]);
    let a = agree(&named(3, Policy::StrictMajority), &f, vec![A::V(5); 3]).await.unwrap();
    assert_eq!(a.members, vec![0, 2]);
    // with endpoint 2 lying: no majority (the reorged member does not count)
    let f = Fake::new(vec![ep(100), reorg, ep(100)]);
    match agree(&named(3, Policy::StrictMajority), &f, vec![A::V(5), A::V(5), A::V(6)]).await {
        Err(RpcError::EndpointNoMajority { failures, .. }) => assert!(failures.iter().any(|f| f.kind == FailureKind::BlockChanged)),
        r => panic!("{r:?}"),
    }
}

#[tokio::test]
async fn an_agreed_revert_is_the_revert() {
    let f = Fake::new(vec![ep(100); 3]);
    let e = agree(&named(3, Policy::StrictMajority), &f, vec![A::Rev, A::Rev, A::V(5)]).await.unwrap_err();
    assert!(matches!(e, RpcError::Revert { ref data, .. } if data == &vec![7]), "{e:?}");
}

#[tokio::test]
async fn one_endpoint_cannot_agree() {
    let mut l = list_of(&[Class::Named; 2], Policy::StrictMajority, 5_000);
    l = NodeList::new(vec![l.endpoints()[0].clone()], Policy::Failover, 1, 1, 1).unwrap();
    let f = Fake::new(vec![ep(100)]);
    assert_eq!(agree(&Pool::new(&l, true), &f, vec![A::V(5)]).await.unwrap_err().code(), "Argument");
}

// ---------------------------------------------------------------- decryption reads

#[tokio::test]
async fn discovered_is_skipped_under_failover() {
    let f = Fake::new(vec![ep(10), ep(10)]);
    let p = Pool::new(&list_of(&[Class::Discovered, Class::Named], Policy::Failover, 5_000), true);
    let a = p.failover(&*f, Purpose::FeedsDecryption, read(&f, vec![A::V(1), A::V(2)])).await.unwrap();
    assert_eq!(a.endpoint, 1);
    assert_eq!(f.reqs[0].load(SeqCst), 0, "the discovered endpoint is never asked");
    assert_eq!(p.failover(&*f, Purpose::Plain, read(&f, vec![A::V(1), A::V(2)])).await.unwrap().endpoint, 0, "control: a plain read");
}

#[tokio::test]
async fn only_discovered_is_no_trusted_endpoint() {
    let f = Fake::new(vec![ep(10), ep(10)]);
    let p = Pool::new(&list_of(&[Class::Discovered, Class::Discovered], Policy::Failover, 5_000), true);
    assert_eq!(p.failover(&*f, Purpose::FeedsDecryption, read(&f, vec![A::V(1), A::V(2)])).await.unwrap_err(), RpcError::NoTrustedEndpoint);
    assert_eq!(f.total(), 0);
    let q = Pool::new(&list_of(&[Class::Discovered, Class::Default], Policy::Failover, 5_000), true);
    assert_eq!(q.failover(&*f, Purpose::FeedsDecryption, read(&f, vec![A::V(1), A::V(2)])).await.unwrap().endpoint, 1, "control: default");
}

#[tokio::test]
async fn a_discovered_first_endpoint_moves_the_revert_rule_to_the_first_used() {
    let f = Fake::new(vec![ep(10), ep(10), ep(10)]);
    let p = Pool::new(&list_of(&[Class::Discovered, Class::Named, Class::Named], Policy::Failover, 5_000), true);
    let e = p.failover(&*f, Purpose::FeedsDecryption, read(&f, vec![A::V(1), A::Rev, A::V(3)])).await.unwrap_err();
    assert_eq!(e, RpcError::Revert { endpoint: 1, data: vec![1], reason: "reverted".into() }, "endpoint 1 is the first used");
    let a = p.failover(&*f, Purpose::Plain, read(&f, vec![A::Down, A::Rev, A::V(3)])).await.unwrap();
    assert_eq!(a.endpoint, 2, "control: a plain read, endpoint 1 is a later endpoint");
}

#[tokio::test]
async fn discovered_with_n_2_under_agreement_is_refused_before_any_request() {
    let f = Fake::new(vec![ep(100); 2]);
    let p = Pool::new(&list_of(&[Class::Named, Class::Discovered], Policy::StrictMajority, 5_000), true);
    let r = p.agree(&*f, BlockChoice::Depth(1), Purpose::FeedsDecryption, at(&f, vec![A::V(5); 2], false)).await;
    assert_eq!(r.unwrap_err(), RpcError::AgreementNeedsThree);
    assert_eq!(f.total(), 0);
    assert!(p.agree(&*f, BlockChoice::Depth(1), Purpose::Plain, at(&f, vec![A::V(5); 2], false)).await.is_ok(), "control: a plain read");
}

#[tokio::test]
async fn discovered_with_n_3_and_a_named_member_agreeing_is_served() {
    let f = Fake::new(vec![ep(100); 3]);
    let p = Pool::new(&list_of(&[Class::Named, Class::Discovered, Class::Discovered], Policy::StrictMajority, 5_000), true);
    let a = p.agree(&*f, BlockChoice::Depth(1), Purpose::FeedsDecryption, at(&f, vec![A::V(5), A::V(5), A::V(6)], false)).await.unwrap();
    assert_eq!(a.members, vec![0, 1]);
}

#[tokio::test]
async fn all_discovered_under_agreement_is_no_trusted_endpoint() {
    let f = Fake::new(vec![ep(100); 3]);
    let p = Pool::new(&list_of(&[Class::Discovered; 3], Policy::StrictMajority, 5_000), true);
    let r = p.agree(&*f, BlockChoice::Depth(1), Purpose::FeedsDecryption, at(&f, vec![A::V(5); 3], false)).await;
    assert_eq!(r.unwrap_err(), RpcError::NoTrustedEndpoint);
    assert_eq!(f.total(), 0, "before any request");
    assert!(p.agree(&*f, BlockChoice::Depth(1), Purpose::Plain, at(&f, vec![A::V(5); 3], false)).await.is_ok(), "control: a plain read");
}

#[tokio::test]
async fn a_discovered_majority_against_the_named_member_is_no_majority() {
    let f = Fake::new(vec![ep(100); 3]);
    let p = Pool::new(&list_of(&[Class::Named, Class::Discovered, Class::Discovered], Policy::StrictMajority, 5_000), true);
    let r = p.agree(&*f, BlockChoice::Depth(1), Purpose::FeedsDecryption, at(&f, vec![A::V(5), A::V(6), A::V(6)], false)).await;
    assert!(matches!(r, Err(RpcError::EndpointNoMajority { largest: 2, .. })), "{r:?}");
    let a = p.agree(&*f, BlockChoice::Depth(1), Purpose::Plain, at(&f, vec![A::V(5), A::V(6), A::V(6)], false)).await.unwrap();
    assert_eq!(a.members, vec![1, 2], "control: a plain read stands on them");
}

#[tokio::test]
async fn discovered_agreeing_first_waits_for_the_named_member() {
    let mut slow = ep(100);
    slow.delay_ms = 150;
    let f = Fake::new(vec![slow, ep(100), ep(100)]);
    let p = Pool::new(&list_of(&[Class::Named, Class::Discovered, Class::Discovered], Policy::StrictMajority, 5_000), true);
    let t = Instant::now();
    let a = p.agree(&*f, BlockChoice::Depth(1), Purpose::FeedsDecryption, at(&f, vec![A::V(5); 3], false)).await.unwrap();
    assert!(a.members.contains(&0), "decided on the named member's answer: {:?}", a.members);
    assert!(t.elapsed() >= Duration::from_millis(450), "after its answer: {:?}", t.elapsed());
}
