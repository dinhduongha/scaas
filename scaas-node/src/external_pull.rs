//! `/json/2` — đường duy nhất vào ExternalPull (ruling R6). Một client cho mỗi API key.
use alloy::primitives::Address;
use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::ExternalPullCfg;

#[derive(Clone)]
pub struct ExternalPull {
    http: reqwest::Client,
    base: String,
    db: String,
    key: String,
    /// Plan T28: the node's own queue beside the pull path, on one family chain's lanes (`with_queue`).
    queue: Option<std::sync::Arc<OwnQueue>>,
}

/// Plan T28 (gateway.md `POST /v1/ops`): the namespace of the jobs the gateway accepts (door A, G2 durable).
pub const GATEWAY_NAMESPACE: &str = "~gateway";

/// Plan T28: a family chain's own queue, the `~gateway` rows of the node store, read and moved by the same lane calls as the
/// pull path (`relay_poll_ref`, `relay_claim`, `relay_report`, `node_config_ref`'s `inflight`). A row's job id on the lane is
/// `-uid`: the pull path's ids are positive, so one id names one source. ponytail: one id space split by sign; the node's
/// queue alone (NODE-JOB-21) drops the split when the pull path goes.
pub struct OwnQueue {
    pub store: crate::store::Store,
    pub chain_key: String,
    /// a lane's worker name (`node#lane`) → its store label (the lane row a lease names)
    pub labels: std::collections::HashMap<String, String>,
}

impl OwnQueue {
    /// The lane's `Job` of a stored row: `{"id": -uid, "kind": "signed_op", "op": <the stored op>}`.
    fn job(r: &crate::store::JobRow) -> Result<Job> {
        let op: Value = serde_json::from_slice(r.payload.as_deref().unwrap_or_default())
            .with_context(|| format!("~gateway job {}: payload", r.uid))?;
        Ok(serde_json::from_value(
            json!({"id": -r.uid, "kind": r.kind, "op": op}),
        )?)
    }

    fn serves(&self, chain: &Value) -> bool {
        chain.as_str() == Some(self.chain_key.as_str())
    }

    async fn poll(&self, limit: u32) -> Result<Vec<Job>> {
        let rows = self
            .store
            .queued_jobs(GATEWAY_NAMESPACE, &self.chain_key, limit.into())
            .await?;
        rows.iter().map(Self::job).collect()
    }

    /// `queued → leased` by the lane `worker` names; a row another lane took (`Moved`) or an unread outcome is not ours.
    async fn claim(&self, uid: i64, worker: &str) -> Result<bool> {
        use crate::store::{Fields, State, Transition};
        let Some(label) = self.labels.get(worker) else {
            return Ok(false);
        };
        let f = Fields {
            lane_label: Some(label.clone()),
            ..Fields::default()
        };
        let t = self
            .store
            .transition(
                uid,
                State::Queued,
                State::Leased,
                &f,
                crate::store::now_ms(),
            )
            .await?;
        Ok(matches!(t, Transition::Ok { .. }))
    }

    /// A lane's report on row `uid`: the move from the row's state to `chain_state`, the store's table deciding (a report it
    /// refuses is an error the caller logs, never a silent change).
    async fn report(&self, uid: i64, r: &Report) -> Result<()> {
        use crate::store::{Fields, State, Transition};
        let row = self
            .store
            .job(uid)
            .await?
            .ok_or_else(|| anyhow!("~gateway job {uid}: no row"))?;
        let to = State::try_from(r.chain_state.clone()).map_err(|e| anyhow!(e))?;
        let f = Fields {
            outer_nonce: match to {
                State::Signed => r.outer_nonce.map(i64::try_from).transpose()?,
                _ => None,
            },
            tx_hash: r
                .tx_hash
                .clone()
                .filter(|_| matches!(to, State::Signed | State::Broadcast)),
            error: r.error.as_deref().map(crate::chain::redact_urls),
            ..Fields::default()
        };
        match self
            .store
            .transition(uid, row.state, to, &f, crate::store::now_ms())
            .await?
        {
            Transition::Ok { .. } => Ok(()),
            t => Err(anyhow!(
                "~gateway job {uid}: {} -> {}: {t:?}",
                row.state.as_str(),
                to.as_str()
            )),
        }
    }

    /// The rows lane `worker` holds (`leased`, `signed`, `broadcast`), as the pull path's `inflight`.
    async fn inflight(&self, worker: &str) -> Result<Vec<InflightJob>> {
        let Some(label) = self.labels.get(worker) else {
            return Ok(vec![]);
        };
        let rows = self
            .store
            .lane_live(GATEWAY_NAMESPACE, &self.chain_key, label)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(InflightJob {
                    job_id: -r.uid,
                    nonce: r.outer_nonce.and_then(|n| u64::try_from(n).ok()),
                    state: r.state.as_str().into(),
                    tx_hash: r.tx_hash.clone(),
                    payload: Self::job(r)?,
                })
            })
            .collect()
    }
}

pub use crate::config::TokenCfg;

#[derive(Debug, Clone, Deserialize)]
pub struct InflightJob {
    pub job_id: i64,
    pub nonce: Option<u64>,
    pub state: String,
    pub tx_hash: Option<String>,
    pub payload: Job,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// Số EIP-155 (EVM/Hedera) hoặc khoá `family:network` — không ai đọc, chỉ để log.
    #[serde(default)]
    pub evm_chain_number: Value,
    /// `active` | `paused` (R53: paused = indexing continues, nothing new is submitted).
    #[serde(default)]
    pub state: Option<String>,
    pub finality_mode: String,
    pub finality_depth: u64,
    pub finality_quorum: usize,
    pub indexed_block: u64,
    pub tokens: Vec<TokenCfg>,
    pub journal_max_nonce: Option<u64>,
    #[serde(default)]
    pub inflight: Vec<InflightJob>,
    /// Ví nhận đã duyệt (drift R56). Chuỗi theo dạng chuẩn của họ mạng — EVM tự parse.
    #[serde(default)]
    pub receiving_addresses: Vec<Receiving>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Receiving {
    pub token: String,
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BalanceReport {
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub mismatch: u64,
}

impl NodeConfig {
    /// Token list the open gateway may accept: none while the chain is paused (R53).
    pub fn submittable_tokens(&self) -> Vec<Address> {
        if self.state.as_deref().unwrap_or("active") == "active" {
            self.tokens.iter().filter_map(TokenCfg::evm).collect()
        } else {
            Vec::new()
        }
    }
}

/// One outbox job. EVM (job-api.md): `op`, one named entry as explicit JSON; `kind` = `metatx`, `ua_metatx` (a `ua*` entry)
/// or `call` (a plain entry: the registry, the account factory, the DEX). A plain transfer or payment keeps its explicit
/// struct: `kind = "metatx"` with `token`, `signature`, `metatx` (`MetaTransfer`), `kind = "ua_metatx"` with `token`, `auth`,
/// `m` (`UAMetaTransfer`). Hex `data` / `calldata` is refused on every kind (`submit::work_from_job`).
#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub id: i64,
    #[serde(default)]
    pub token: Option<Address>,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default, rename = "struct")]
    pub struct_: Option<String>,
    #[serde(default)]
    pub metatx: Option<Value>,
    /// The refused hex fields (typed-signing N1), read only to name the refusal: `call: {target, calldata, validUntil}`, a
    /// top-level `calldata` or `data`.
    #[serde(default)]
    pub call: Option<Value>,
    #[serde(default)]
    pub calldata: Option<Value>,
    #[serde(default)]
    pub data: Option<Value>,
    /// The contract kind of a `metatx` / `ua_metatx` struct job (`token`, `zether`, `pqz`; absent = `token`): its typed digest's
    /// domain name. An `op` names its own.
    #[serde(default)]
    pub contract: Option<String>,
    /// Payee fee (job-api.md): not built in the node, so a job carrying it is refused (`work_from_job`), never
    /// relayed as a plain transfer that drops the payee's fee authorization (review T2 m5).
    #[serde(default)]
    pub payee_fee: Option<Value>,
    /// The name of `payee_fee` before the payee-fee rename (owner 2026-11-12, CTR-MTX-86), read only to refuse it by name
    /// (`RECEIVER_FEE_REFUSED`), never relayed and never silently `dead`.
    #[serde(default)]
    pub receiver_fee: Option<Value>,
    /// A pay-meta `metatx` job (CTR-MTX-26, `struct = transfer`): `salt` (bytes32) and `meta` (hex) the payment id
    /// commits to; relayed as `mtxPayMeta`, or as the plain `mtxExecuteTransfer` with `meta_offchain = true`.
    #[serde(default)]
    pub salt: Option<String>,
    #[serde(default)]
    pub meta: Option<String>,
    #[serde(default)]
    pub meta_offchain: Option<bool>,
    /// A `ua_metatx` struct job (job-api.md): `m` = `WireUAMetaTransfer`, `auth` the `UASig` object; never `metatx` / `signature`.
    #[serde(default)]
    pub m: Option<Value>,
    #[serde(default)]
    pub auth: Option<Value>,
    /// `metatx` | `call` | `signed_op` (họ không phải EVM: payload ký + chữ ký + khoá công khai, adapter tự đọc).
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub op: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub job_id: i64,
    pub chain_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outer_nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngestResult {
    pub indexed_block: u64,
    pub created: u64,
}

impl ExternalPull {
    pub fn new(cfg: &ExternalPullCfg, key_env: &str) -> Result<Self> {
        let key = std::env::var(key_env).with_context(|| format!("env {key_env} not set"))?;
        Self::with_key(cfg, key)
    }

    pub fn with_key(cfg: &ExternalPullCfg, key: String) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            base: cfg.url.trim_end_matches('/').to_string(),
            db: cfg.database.clone(),
            key,
            queue: None,
        })
    }

    /// Plan T28: this client's lanes also take the jobs of `queue` (a family chain's `~gateway` rows).
    pub fn with_queue(mut self, queue: OwnQueue) -> Self {
        self.queue = Some(std::sync::Arc::new(queue));
        self
    }

    pub async fn call<T: DeserializeOwned>(
        &self,
        model: &str,
        method: &str,
        body: Value,
    ) -> Result<T> {
        let res = self
            .http
            .post(format!("{}/json/2/{model}/{method}", self.base))
            .bearer_auth(&self.key)
            .header("X-Odoo-Database", &self.db)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("{model}.{method}: transport"))?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            // Cắt ngắn: lỗi ExternalPull có thể kèm traceback dài.
            let head: String = text.chars().take(300).collect();
            return Err(anyhow!("{model}.{method}: HTTP {status}: {head}"));
        }
        serde_json::from_str(&text).with_context(|| format!("{model}.{method}: decode"))
    }

    pub async fn node_config(&self, chain: u64, relayer: Option<Address>) -> Result<NodeConfig> {
        self.node_config_ref(json!(chain), relayer.map(|r| format!("{r:#x}")), None)
            .await
    }

    /// `chain` = số EIP-155 (EVM) hoặc khoá `family:network` (R61). `worker` lọc job đã claim mà
    /// chưa ký về đúng lane đã claim (nhiều lane cùng chain).
    pub async fn node_config_ref(
        &self,
        chain: Value,
        relayer: Option<String>,
        worker: Option<String>,
    ) -> Result<NodeConfig> {
        let mut body = json!({"evm_chain_number": chain});
        if let Some(r) = relayer {
            body["relayer_address"] = json!(r);
        }
        if let Some(w) = &worker {
            body["worker"] = json!(w);
        }
        let mut nc: NodeConfig = self.call("blockchain.chain", "node_config", body).await?;
        if let (Some(q), Some(w)) = (&self.queue, &worker) {
            if q.serves(&chain) {
                nc.inflight.extend(q.inflight(w).await?);
            }
        }
        Ok(nc)
    }

    pub async fn relay_poll(&self, chain: u64, limit: u32) -> Result<Vec<Job>> {
        self.relay_poll_ref(json!(chain), limit).await
    }

    /// The jobs to claim: the own queue's first (plan T28), then the pull path's; a pull path that fails while the own queue has
    /// work still hands that work out.
    pub async fn relay_poll_ref(&self, chain: Value, limit: u32) -> Result<Vec<Job>> {
        let mut own = match &self.queue {
            Some(q) if q.serves(&chain) => q.poll(limit).await?,
            _ => vec![],
        };
        let pulled: Result<Vec<Job>> = self
            .call(
                "blockchain.relay.job",
                "relay_poll",
                json!({"evm_chain_number": chain, "limit": limit}),
            )
            .await;
        match pulled {
            Ok(p) => own.extend(p),
            Err(e) if own.is_empty() => return Err(e),
            Err(e) => tracing::warn!("relay_poll: {e:#}; the own queue's jobs go on"),
        }
        Ok(own)
    }

    pub async fn relay_claim(&self, ids: &[i64], worker: &str) -> Result<Vec<i64>> {
        let (own, pulled): (Vec<i64>, Vec<i64>) = ids.iter().partition(|&&i| i < 0);
        let mut won = vec![];
        if let Some(q) = &self.queue {
            for id in own {
                if q.claim(-id, worker).await? {
                    won.push(id);
                }
            }
        }
        if !pulled.is_empty() {
            let p: Vec<i64> = self
                .call(
                    "blockchain.relay.job",
                    "relay_claim",
                    json!({"job_ids": pulled, "worker": worker}),
                )
                .await?;
            won.extend(p);
        }
        Ok(won)
    }

    pub async fn relay_report(&self, r: &Report) -> Result<()> {
        if r.job_id < 0 {
            let q = self
                .queue
                .as_ref()
                .ok_or_else(|| anyhow!("job {}: no own queue", r.job_id))?;
            return q.report(-r.job_id, r).await;
        }
        let mut v = serde_json::to_value(r)?;
        // Fable E N-8: no endpoint URL in a job's error (the one sink of every runner's report)
        if let Some(e) = r.error.as_deref() {
            v["error"] = json!(crate::chain::redact_urls(e));
        }
        let _: Value = self.call("blockchain.relay.job", "relay_report", v).await?;
        Ok(())
    }

    /// Drift C (R56): số dư ví nhận tại `height` (= cursor đã index). `stale` = cursor đã đi tiếp, đọc lại.
    pub async fn balance_report(
        &self,
        chain_key: &str,
        height: u64,
        balances: &[Value],
    ) -> Result<BalanceReport> {
        self.call(
            "blockchain.chain",
            "balance_report",
            json!({"chain_key": chain_key, "height": height, "balances": balances}),
        )
        .await
    }

    pub async fn ingest(
        &self,
        chain: u64,
        from: u64,
        to: u64,
        hash: &str,
        events: &[Value],
    ) -> Result<IngestResult> {
        self.ingest_ref(json!(chain), from, to, hash, events).await
    }

    pub async fn ingest_ref(
        &self,
        chain: Value,
        from: u64,
        to: u64,
        hash: &str,
        events: &[Value],
    ) -> Result<IngestResult> {
        self.call(
            "blockchain.chain.event",
            "chain_event_ingest",
            json!({
                "evm_chain_number": chain, "from_block": from, "to_block": to,
                "to_block_hash": hash, "events": events,
            }),
        )
        .await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy::sol_types::SolCall;

    /// Plan T28: a node store of its own (a temp file) knowing one family chain `key` and its lane `label`.
    pub(crate) async fn own_store(key: &str, family: &str, label: &str) -> crate::store::Store {
        let dir = std::env::temp_dir().join(format!(
            "scaas-own-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let st = crate::store::create(
            &format!("sqlite://{}", dir.join("node.db").display()),
            "test",
        )
        .await
        .unwrap();
        let chain = crate::store::ChainRow {
            chain_key: key.into(),
            family: family.into(),
            state: "active".into(),
            profile: "private".into(),
            finality_mode: "instant".into(),
            finality_depth: 0,
            finality_quorum: 1,
            fee_recipient: None,
            poll_ms: 1000,
            stuck_after_secs: 60,
            max_gas_per_tx: 3_000_000,
            max_fee_cap_gwei: 500,
            max_index_lag: 100,
            breaker: "{}".into(),
            dex: None,
            gossip: false,
            exclusive_ms: 7000,
        };
        let set = crate::store::ConfigSet {
            chains: vec![chain],
            lanes: vec![crate::store::LaneRow {
                chain_key: key.into(),
                label: label.into(),
                account_index: 0,
                journal_max: None,
            }],
            ..Default::default()
        };
        crate::store::bootstrap(st.as_ref(), &set, 1).await.unwrap();
        st
    }

    /// Plan T28: a `~gateway` `signed_op` row as the gateway writes it (origin key = digest).
    pub(crate) async fn own_job(st: &crate::store::Store, key: &str, digest: u8, op: Value) -> i64 {
        let payload = serde_json::to_vec(&op).unwrap();
        let j = crate::store::NewJob {
            namespace: GATEWAY_NAMESPACE.into(),
            origin: crate::store::Origin {
                scope: "gateway".into(),
                producer: "gateway".into(),
                key: format!("0x{}", alloy::hex::encode([digest; 32])),
                generation: 0,
            },
            client_ref: None,
            chain_key: key.into(),
            kind: "signed_op".into(),
            digest: Some([digest; 32]),
            payload_hash: alloy::primitives::keccak256(&payload).0,
            payload,
            valid_until: 4_000_000_000,
            lane_hint: None,
            bus_scope: "restricted".into(),
            private_window_secs: 0,
        };
        match st.accept(&j, crate::store::now_ms()).await.unwrap() {
            crate::store::Accept::Created(r) => r.uid,
            a => panic!("{a:?}"),
        }
    }

    /// Plan T28: the own queue's rows go out as `-uid`, a lease names the worker's lane (a worker without a lane claims
    /// nothing: the control), a report moves the row by the store's table and one it refuses is an error, and the lane's rows
    /// come back as `inflight`.
    #[tokio::test]
    async fn the_own_queue_hands_out_claims_and_moves_gateway_rows() {
        use crate::store::State;
        let st = own_store("cosmos:t", "cosmos", "pk:aa").await;
        let uid = own_job(
            &st,
            "cosmos:t",
            7,
            json!({"family": "cosmos", "valid_until": 4_000_000_000u64}),
        )
        .await;
        let q = OwnQueue {
            store: st.clone(),
            chain_key: "cosmos:t".into(),
            labels: [("n#0".to_string(), "pk:aa".to_string())].into(),
        };
        assert!(
            !q.serves(&json!("cosmos:other")),
            "another chain's lanes never see it"
        );
        let jobs = q.poll(5).await.unwrap();
        assert_eq!(
            (jobs.len(), jobs[0].id, jobs[0].kind.as_deref()),
            (1, -uid, Some("signed_op"))
        );
        assert!(
            !q.claim(uid, "n#9").await.unwrap(),
            "a worker without a lane leases nothing"
        );
        assert!(q.claim(uid, "n#0").await.unwrap());
        assert!(!q.claim(uid, "n#0").await.unwrap(), "leased once");
        assert!(
            q.poll(5).await.unwrap().is_empty(),
            "a leased row is not handed out"
        );
        let inflight = q.inflight("n#0").await.unwrap();
        assert_eq!(
            (inflight[0].job_id, inflight[0].tx_hash.as_deref()),
            (-uid, None)
        );
        let rep = |state: &str| Report {
            job_id: -uid,
            chain_state: state.into(),
            tx_hash: Some("0x01".into()),
            outer_nonce: Some(3),
            ..Default::default()
        };
        q.report(uid, &rep("signed")).await.unwrap();
        let row = st.job(uid).await.unwrap().unwrap();
        assert_eq!(
            (row.state, row.outer_nonce, row.tx_hash.as_deref()),
            (State::Signed, Some(3), Some("0x01"))
        );
        assert!(
            q.report(uid, &rep("leased")).await.is_err(),
            "signed -> leased is no move of the table"
        );
        q.report(uid, &rep("mined")).await.unwrap();
        assert_eq!(st.job(uid).await.unwrap().unwrap().state, State::Mined);
        assert!(
            q.inflight("n#0").await.unwrap().is_empty(),
            "a mined row is no longer the lane's"
        );
    }

    #[test]
    fn job_payload_from_external_pull_decodes() {
        let raw = r#"{"id": 3, "token": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "digest": "0x33", "signature": "0x44", "struct": "transfer",
            "metatx": {"from": "0xabababababababababababababababababababab",
                       "to": "0x0101010101010101010101010101010101010101", "value": "100",
                       "entryRef": "0x0000000000000000000000000000000000000000000000000000000000000042",
                       "batch": "7", "nonce": "0", "validUntil": "1800000300",
                       "mode": 1, "relayer": "0x0202020202020202020202020202020202020202",
                       "fee": "0", "feeRecipient": "0x0000000000000000000000000000000000000000"}}"#;
        let job: Job = serde_json::from_str(raw).unwrap();
        assert_eq!(job.id, 3);
        let m = crate::metatx::Mtx::from_wire(job.struct_.as_deref(), job.metatx.as_ref().unwrap())
            .unwrap();
        assert_eq!(m.batch(), alloy::primitives::U256::from(7));
    }

    /// The plain entry that replaced the hex `call` job: named JSON in, the row's bytes out.
    #[test]
    fn call_job_payload_decodes() {
        let raw = r#"{"id": 9, "kind": "call", "op": {"entry": "storePqzPop", "token": "0xbabababababababababababababababababababa",
            "validUntil": "1800000300", "args": {"pqzPop": "0xdeadbeef", "version": "1",
            "ua": "0x0000000000000000000000000000000000000000000000000000000000000042"}}}"#;
        let job: Job = serde_json::from_str(raw).unwrap();
        assert!(job.metatx.is_none());
        let w = crate::submit::work_from_job(&job, None).unwrap();
        assert_eq!(
            w.data[..4],
            crate::abi::IUARegistry::storePqzPopCall::SELECTOR
        );
        // group 3g: the version a named field, word 2 of the rebuilt call
        let c =
            <crate::abi::IUARegistry::storePqzPopCall as alloy::sol_types::SolCall>::abi_decode(
                &w.data,
            )
            .unwrap();
        assert_eq!(
            (c.version, c.pqzPop.to_vec()),
            (1, vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(w.valid_until, 1_800_000_300);
    }

    /// CTR-UA-37: a member's acceptance as a job, the member's own signature in named fields: a relayer carries it, the member
    /// holds no gas.
    #[test]
    fn accept_membership_job_decodes() {
        let raw = r#"{"id": 9, "kind": "call", "op": {"entry": "acceptMembership", "token": "0xbabababababababababababababababababababa",
            "validUntil": "1800000300", "args": {"memberSig": {"index": 3, "members": [], "sig": "0xdeadbeef"},
            "ua": "0x0000000000000000000000000000000000000000000000000000000000000042"}}}"#;
        let job: Job = serde_json::from_str(raw).unwrap();
        let w = crate::submit::work_from_job(&job, None).unwrap();
        use alloy::sol_types::SolCall;
        let call = crate::abi::IUARegistry::acceptMembershipCall::abi_decode(&w.data).unwrap();
        assert_eq!(
            (call.memberSig.index, call.memberSig.sig.to_vec()),
            (3, vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(call.ua, alloy::primitives::B256::with_last_byte(0x42));
        assert!(call.memberSig.members.is_empty());
    }

    #[test]
    fn paused_chain_serves_no_tokens_to_the_gateway() {
        let mk = |state: &str| -> NodeConfig {
            serde_json::from_value(json!({"evm_chain_number": 1, "state": state, "finality_mode": "depth",
                "finality_depth": 1, "finality_quorum": 1, "indexed_block": 0, "journal_max_nonce": null,
                "tokens": [{"address": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "decimals": 6}]}))
            .unwrap()
        };
        assert_eq!(mk("active").submittable_tokens().len(), 1);
        assert!(mk("paused").submittable_tokens().is_empty());
    }

    /// Review H1: ExternalPull gửi địa chỉ token dạng chuẩn của HỌ (`wasm1…`, `0.0.x`, …); chỉ đường EVM đọc thành `Address`.
    #[test]
    fn non_evm_token_addresses_decode() {
        let nc: NodeConfig = serde_json::from_value(json!({"evm_chain_number": "cosmos:scaas-1", "finality_mode": "instant",
            "finality_depth": 0, "finality_quorum": 1, "indexed_block": 0, "journal_max_nonce": null,
            "tokens": [{"address": "wasm1g3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqn0lflt", "decimals": 6}]}))
        .unwrap();
        assert_eq!(
            nc.tokens[0].address,
            "wasm1g3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqn0lflt"
        );
        assert!(nc.submittable_tokens().is_empty(), "never an EVM address");
    }

    #[test]
    fn report_omits_absent_fields() {
        let r = Report {
            job_id: 1,
            chain_state: "dead".into(),
            error: Some("x".into()),
            ..Default::default()
        };
        let v = serde_json::to_value(r).unwrap();
        assert!(v.get("tx_hash").is_none());
        assert_eq!(v["error"], "x");
    }
}
