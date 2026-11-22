// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The e2e's world (plan T11): the local chain of `common::chain` (the deploy and the ML-DSA registration on an anvil
//! without the cap, then every write under `--enable-tx-gas-limit` after its positive control), the UAs A (`fndsa512`), B
//! (`mldsa65`, the registry's cached expanded key) and C (`fndsa512`), each with a KEM key; the home H and the replicas R1,
//! R2 listed through the factory; U, the home's code at an address the factory never made (`anvil_setCode`: unlisted); the
//! SDK's port with every read and prepared write recorded, and a read rewritten when a fixture asks (a named endpoint
//! serving another answer, mutants 10 and 11). Two more profiles of the same chain: [`FINAL`] reads two blocks below the
//! latest (mutant 13's reorg), [`DISC`] lists a discovered endpoint first, a JSON-RPC [`Proxy`] that serves `kemKeyAt` of
//! B as C's (mutant 15), the named anvil second.
use crate::common::chain::*;
use async_trait::async_trait;
use pqchat_core::net::{Net, SdkNet};
use pqchat_core::reads::SessionRef;
use pqchat_core::session::{Built, Me, StoreEntry};
use pqchat_core::stores::Delivery;
use pqchat_core::{MemoryStore, PqChat, PqChatError};
use scaas_sdk::app_core::{AppCall, AppCore};
use scaas_sdk::op::KeyRef;
use scaas_sdk::OpState;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The profile whose final block is two below the latest (mutant 13).
pub const FINAL: &str = "anvil-final";
/// The depth of [`FINAL`]'s final block.
pub const DEPTH: u64 = 2;
/// The profile whose first endpoint is a discovered one, the [`Proxy`] (mutant 15).
pub const DISC: &str = "anvil-disc";

/// A discovered endpoint in front of the anvil: every JSON-RPC request forwarded, an `eth_call` whose calldata starts with
/// `swap.0` sent as `swap.1` instead (the substituted answer), counted.
pub struct Proxy {
    pub url: String,
    target: Arc<Mutex<String>>,
    pub swap: Arc<Mutex<Option<(String, String)>>>,
    pub swapped: Arc<AtomicU64>,
}

fn rewrite(v: &mut Value, swap: &Option<(String, String)>, n: &AtomicU64) {
    if let Value::Array(a) = v {
        a.iter_mut().for_each(|x| rewrite(x, swap, n));
        return;
    }
    let Some((from, to)) = swap else { return };
    if v["method"] != "eth_call" {
        return;
    }
    for k in ["data", "input"] {
        if let Some(d) = v["params"][0][k].as_str() {
            if d.to_ascii_lowercase().starts_with(from.as_str()) {
                v["params"][0][k] = Value::String(to.clone());
                n.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

async fn serve(
    mut s: tokio::net::TcpStream,
    target: Arc<Mutex<String>>,
    swap: Arc<Mutex<Option<(String, String)>>>,
    n: Arc<AtomicU64>,
) {
    let mut buf = vec![];
    let mut chunk = [0u8; 8192];
    let (head, len) = loop {
        let Ok(k) = s.read(&mut chunk).await else {
            return;
        };
        if k == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..k]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|x| x.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (i + 4, len);
        }
    };
    while buf.len() < head + len {
        let Ok(k) = s.read(&mut chunk).await else {
            return;
        };
        if k == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..k]);
    }
    let Ok(mut v) = serde_json::from_slice::<Value>(&buf[head..head + len]) else {
        return;
    };
    rewrite(&mut v, &swap.lock().unwrap().clone(), &n);
    let url = target.lock().unwrap().clone();
    let Ok(r) = reqwest::Client::new().post(url).json(&v).send().await else {
        return;
    };
    let body = r.bytes().await.unwrap_or_default();
    let h = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(h.as_bytes()).await;
    let _ = s.write_all(&body).await;
}

impl Proxy {
    /// Listening on `127.0.0.1:0`; its target set later (the anvil's URL is known once it runs).
    pub async fn start() -> Proxy {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let p = Proxy {
            url,
            target: Arc::new(Mutex::new(String::new())),
            swap: Arc::new(Mutex::new(None)),
            swapped: Arc::new(AtomicU64::new(0)),
        };
        let (t, sw, n) = (p.target.clone(), p.swap.clone(), p.swapped.clone());
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                tokio::spawn(serve(s, t.clone(), sw.clone(), n.clone()));
            }
        });
        p
    }
}

/// A read's answer rewritten: `(item, answer) -> answer`.
pub type Tamper = Box<dyn Fn(&str, Value) -> Value + Send + Sync>;

/// The SDK's port, recorded.
pub struct Rec {
    pub inner: SdkNet,
    pub reads: Mutex<Vec<&'static str>>,
    pub prepared: Mutex<Vec<(String, &'static str)>>,
    pub tamper: Mutex<Option<Tamper>>,
}

#[async_trait]
impl Net for Rec {
    async fn read(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        self.reads.lock().unwrap().push(item);
        let v = self.inner.read(chain, contract, item, args).await?;
        Ok(match &*self.tamper.lock().unwrap() {
            Some(t) => t(item, v),
            None => v,
        })
    }
    async fn prepare(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        self.prepared
            .lock()
            .unwrap()
            .push((contract.to_ascii_lowercase(), item));
        self.inner.prepare(chain, contract, item, args, payer).await
    }
    async fn submit(&self, call: AppCall) -> Result<String, PqChatError> {
        self.inner.submit(call).await
    }
}

impl Rec {
    pub fn read_items(&self) -> Vec<&'static str> {
        self.reads.lock().unwrap().clone()
    }
    pub fn clear(&self) {
        self.reads.lock().unwrap().clear();
        self.prepared.lock().unwrap().clear();
    }
    pub fn writes(&self) -> usize {
        self.prepared.lock().unwrap().len()
    }
}

pub struct World {
    pub l: Local,
    pub proxy: Proxy,
    pub a: Me,
    pub b: Me,
    pub c: Me,
    pub r1: String,
    pub r2: String,
    pub u: String,
    pub app: Arc<AppCore>,
    pub net: Arc<Rec>,
    /// the transactions the run landed (the summary row's count)
    pub txs: Mutex<Vec<String>>,
}

/// An address no factory made: the home's code set there (its env names the same registry, its storage is empty).
const U: &str = "0x00000000000000000000000000000000000e2e00";

pub async fn world() -> World {
    let proxy = Proxy::start().await;
    let (purl, ptarget) = (proxy.url.clone(), proxy.target.clone());
    let extra = move |rpc: &str, uid: &str, reg: &str, fac: &str| {
        *ptarget.lock().unwrap() = rpc.to_string();
        use scaas_rpc::Class::{Discovered, Named};
        vec![
            profile_of(
                FINAL,
                &[(rpc, Named)],
                uid,
                reg,
                fac,
                scaas_sdk::Finality::Depth(DEPTH),
            ),
            profile_of(
                DISC,
                &[(&purl, Discovered), (rpc, Named)],
                uid,
                reg,
                fac,
                scaas_sdk::Finality::Depth(0),
            ),
        ]
    };
    let (l, m, more) = local_with_extra(
        &[(0, true, FNDSA512), (1, true, KIND), (2, true, FNDSA512)],
        2,
        &extra,
    )
    .await;
    let code = cast(&["code", "--rpc-url", &l.rpc, &l.home]);
    cast(&["rpc", "--rpc-url", &l.rpc, "anvil_setCode", U, &code]);
    let app = pqchat_core::scope(&l.sdk).unwrap();
    let net = Arc::new(Rec {
        inner: SdkNet {
            sdk: l.sdk.clone(),
            app: app.clone(),
        },
        reads: Mutex::new(vec![]),
        prepared: Mutex::new(vec![]),
        tamper: Mutex::new(None),
    });
    println!(
        "[e2e] A {} (fndsa512), B {} (mldsa65), C {} (fndsa512); H {}, R1 {}, R2 {}, U {U} (unlisted)",
        m[0].ua, m[1].ua, m[2].ua, l.home, more[0], more[1]
    );
    World {
        a: m[0].clone(),
        b: m[1].clone(),
        c: m[2].clone(),
        r1: more[0].clone(),
        r2: more[1].clone(),
        u: U.into(),
        l,
        proxy,
        app,
        net,
        txs: Mutex::new(vec![]),
    }
}

impl World {
    /// A device: a fresh store over the recorded port.
    pub fn device(&self) -> Arc<PqChat> {
        self.device_with(Arc::new(MemoryStore::new()))
    }

    /// A device over `store`.
    pub fn device_with(&self, store: Arc<MemoryStore>) -> Arc<PqChat> {
        PqChat::with_net(self.app.clone(), self.net.clone(), store, self.l.conf())
    }

    /// A device over a fresh store serving only the profile `chain` of the same chain (its contracts the same).
    pub fn device_on(&self, chain: &str) -> Arc<PqChat> {
        let mut conf = self.l.conf();
        conf.chains[0].chain = chain.into();
        PqChat::with_net(
            self.app.clone(),
            self.net.clone(),
            Arc::new(MemoryStore::new()),
            conf,
        )
    }

    pub fn sref(&self, sid: &str) -> SessionRef {
        SessionRef {
            chain: CHAIN.into(),
            home: self.l.home.clone(),
            session_id: sid.into(),
        }
    }

    pub fn chain_store(&self, contract: &str) -> StoreEntry {
        StoreEntry::Chain {
            chain_id: "31337".into(),
            chain_uid: self.l.uid.clone(),
            contract: contract.into(),
        }
    }

    /// `op` followed to `Landed`, its hash kept.
    pub async fn follow_landed(&self, op: String) {
        let s = follow(&self.l.sdk, op).await;
        match s {
            OpState::Landed { hash, .. } => self.txs.lock().unwrap().push(hash),
            s => panic!("{s:?}"),
        }
    }

    /// `call` landed (nothing above 2^24 gas is sent).
    pub async fn land(&self, call: AppCall) {
        let gas = call.quote.quote.gas_limit;
        assert!(
            gas <= TX_CAP,
            "the harness sends nothing above 2^24 gas ({gas})"
        );
        let op = self
            .l
            .sdk
            .wallet()
            .submit_native_send(call.quote)
            .await
            .unwrap();
        self.follow_landed(op).await;
    }

    pub async fn delivered(&self, d: &Delivery) {
        let Delivery::Sent(op) = d else {
            panic!("not sent: {d:?}")
        };
        self.follow_landed(op.clone()).await;
    }

    /// `b` landed with every `addWraps` the quote sizes.
    pub async fn land_all(&self, pq: &Arc<PqChat>, b: Built) -> Built {
        self.land_all_calls(pq, b).await.0
    }

    /// [`World::land_all`], with the writes it landed in their order (a replica's copy sends the same calldata).
    pub async fn land_all_calls(&self, pq: &Arc<PqChat>, mut b: Built) -> (Built, Vec<AppCall>) {
        self.land(b.call.clone()).await;
        let mut calls = vec![b.call.clone()];
        let s = self.sref(&b.session_id);
        while let Some(c) = pq.next_wraps(&s, &mut b, &self.l.payer).await.unwrap() {
            self.land(c.clone()).await;
            calls.push(c);
        }
        (b, calls)
    }

    /// Raw calldata `data` sent to `to` by anvil's funded deployer (the hostile harness and the replicas' copies): its
    /// transaction hash, or the revert data's selector.
    pub fn raw(&self, to: &str, data: &str) -> Result<String, String> {
        let o = cast_out(&[
            "send",
            "--rpc-url",
            &self.l.rpc,
            "--private-key",
            DEPLOYER,
            "--gas-limit",
            &TX_CAP.to_string(),
            to,
            data,
            "--json",
        ]);
        let out = String::from_utf8_lossy(&o.stdout).to_string();
        if o.status.success() {
            let v: Value = serde_json::from_str(&out).unwrap();
            if v["status"] == "0x1" {
                let h = v["transactionHash"].as_str().unwrap().to_string();
                self.txs.lock().unwrap().push(h.clone());
                return Ok(h);
            }
        }
        // the refusal's selector, by the same call simulated
        let o = cast_out(&[
            "call",
            "--rpc-url",
            &self.l.rpc,
            "--from",
            DEPLOYER_ADDRESS,
            to,
            data,
        ]);
        let err = String::from_utf8_lossy(&o.stderr).to_string();
        let sel = err
            .split("data: \"")
            .nth(1)
            .or_else(|| err.split("custom error ").nth(1))
            .map(|x| x.chars().take(10).collect::<String>());
        Err(sel.unwrap_or(err))
    }
}

/// An error's selector (`cast sig`).
pub fn selector(sig: &str) -> String {
    cast(&["sig", sig])
}
