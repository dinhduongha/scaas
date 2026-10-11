//! scaas-node --config node.toml            chạy các mô-đun bật trong config
//! scaas-node addresses --config node.toml  in địa chỉ lane dẫn xuất rồi thoát
//! scaas-node store init --config node.toml      tạo store MỚI cho một node mới (node không bao giờ tự tạo store)
//! scaas-node store restored --config node.toml  bắt buộc sau mỗi lần restore store: restore_epoch + 1 (R110)
//! scaas-node keystore new --kind <mnemonic|secp256k1|ed25519> --out <dir> --name <file>
//!     (bí mật đọc từ stdin, passphrase từ $SCAAS_KEYSTORE_PASSPHRASE)
//!
//! Một binary, mô-đun bật bằng config (`_USER-DECISIONS` §23.3). Mỗi chain EVM: một `submit` mỗi lane
//! (R62), một `indexer`, và (tuỳ chọn) gateway HTTP chung. Họ khác và Hedera (R6-1): `lane_runner` mỗi lane + `index_runner`.
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use scaas_node::adapter::{index_runner, lane_runner};
use scaas_node::signer::Signer;
use scaas_node::admin::{ChainProbe, LaneProbe};
use scaas_node::breaker::Breaker;
use scaas_node::{admin, adapters, chain, config, dex, gateway, gwauth, indexer, keys, odoo, store, submit};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

// legacy(R104): every module still runs on the Odoo pull path until P3/P4. `relay` picks the API key.
fn legacy(cfg: &config::Config, relay: bool) -> Result<odoo::Odoo> {
    let o = cfg.odoo.as_ref().context("[odoo] is required on the legacy path (R104)")?;
    odoo::Odoo::new(o, if relay { &o.relay_api_key_env } else { &o.indexer_api_key_env })
}

fn cli_uid() -> String {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map(|m| m.uid().to_string()).unwrap_or_else(|_| "unknown".into())
}

/// `store init`: một store mới (file 0600). Store đã có ⇒ lỗi; khởi động thường không bao giờ tạo store (F5).
async fn store_init(cfg: &config::Config) -> Result<()> {
    let st = store::create(&cfg.store.url, &format!("cli:{}", cli_uid())).await.context("store init")?;
    println!("store {} created", st.identity().store_id);
    Ok(())
}

/// `store restored`: chạy khi node DỪNG (lấy owner lock), ghi audit `cli:<uid>`.
async fn store_restored(cfg: &config::Config) -> Result<()> {
    let uid = cli_uid();
    let st = store::open(&cfg.store.url, &format!("cli:{uid}")).await.context("open the store (stop the node first)")?;
    let e = store::AuditEntry {
        actor_kind: "cli".into(),
        sub: Some(uid),
        method: "CLI".into(),
        route: "store restored".into(),
        request_id: format!("cli-{}", std::process::id()),
        ..Default::default()
    };
    let n = st.mark_restored(&e, store::now_ms()).await?;
    println!("store {}: restore_epoch = {n}", st.identity().store_id);
    Ok(())
}

fn lane_label(cc: &config::ChainCfg, s: &scaas_node::signer::LocalSigner) -> String {
    match cc.family.as_str() {
        "evm" | "hedera" => s.address_hex(),
        _ => format!("pk:{}", alloy::hex::encode(s.public_key())),
    }
}

fn keystore_new(args: &[String]) -> Result<()> {
    let kind = arg(args, "--kind").ok_or_else(|| anyhow!("--kind mnemonic|secp256k1|ed25519"))?;
    let out = PathBuf::from(arg(args, "--out").ok_or_else(|| anyhow!("--out <dir>"))?);
    let name = arg(args, "--name").ok_or_else(|| anyhow!("--name <file>"))?;
    let mut secret = zeroize::Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut secret)?;
    let pass = zeroize::Zeroizing::new(std::env::var("SCAAS_KEYSTORE_PASSPHRASE").context("SCAAS_KEYSTORE_PASSPHRASE")?);
    let bytes: zeroize::Zeroizing<Vec<u8>> = match kind.as_str() {
        "mnemonic" => {
            keys::Seed::from_phrase(secret.trim().as_bytes(), None)?; // checksum + 24 words before writing
            zeroize::Zeroizing::new(secret.trim().as_bytes().to_vec())
        }
        "secp256k1" | "ed25519" => zeroize::Zeroizing::new(secret.trim().as_bytes().to_vec()),
        other => bail!("unknown kind {other}"),
    };
    if kind != "mnemonic" {
        keys::parse_raw_key(&bytes)?;
    }
    keys::write_keystore(&out, &name, &bytes, pass.as_bytes())?;
    println!("wrote {}", out.join(&name).display());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("keystore") && args.get(2).map(String::as_str) == Some("new") {
        return keystore_new(&args);
    }
    let path = PathBuf::from(arg(&args, "--config")
        .ok_or_else(|| anyhow!("usage: scaas-node [addresses | store init | store restored] --config node.toml"))?);
    let cfg = config::Config::load(&path)?;
    if args.get(1).map(String::as_str) == Some("store") {
        return match args.get(2).map(String::as_str) {
            Some("init") => store_init(&cfg).await,
            Some("restored") => store_restored(&cfg).await,
            other => bail!("unknown store command {other:?}: init | restored"),
        };
    }
    // Chỉ địa chỉ được in, không bao giờ bí mật (R60).
    let mut lane_signers = Vec::new();
    for cc in &cfg.chains {
        let signers = cfg.lane_signers(cc).with_context(|| format!("keys of {}", cc.chain_key()))?;
        for (s, i) in signers.iter().zip(&cc.lanes) {
            info!(chain = %cc.chain_key(), lane = i, address = %lane_label(cc, s), "relayer lane");
            if args.get(1).map(String::as_str) == Some("addresses") {
                println!("{}\tlane {i}\t{}", cc.chain_key(), lane_label(cc, s));
            }
        }
        lane_signers.push(signers);
    }
    if args.get(1).map(String::as_str) == Some("addresses") {
        return Ok(());
    }
    if cfg.modules.gateway && !cfg.modules.submit {
        bail!("gateway needs the submit module");
    }
    let node_id = std::env::var("SCAAS_NODE_ID").unwrap_or_else(|_| "scaas-node".into());
    // Store v2 (R88): owner lock + fencing epoch, then the R95 bootstrap of the toml lists. A second process on
    // the same store refuses to start here.
    let st = store::open(&cfg.store.url, &format!("{node_id}:{}", std::process::id())).await.context("open the store")?;
    let id = st.identity().clone();
    info!(store_id = %id.store_id, incarnation = %id.incarnation, epoch = id.epoch, restore_epoch = id.restore_epoch, "store open");
    let labels: Vec<Vec<String>> = cfg.chains.iter().zip(&lane_signers)
        .map(|(cc, ss)| ss.iter().map(|s| lane_label(cc, s)).collect())
        .collect();
    let boot = store::bootstrap(st.as_ref(), &cfg.boot_set(&labels), store::now_ms()).await.context("store bootstrap")?;
    for k in &boot.imported {
        info!(entry = %k, "bootstrap: imported from node.toml");
    }
    // Until runtime reads the store (P3), every consumer still reads node.toml: say so, or an operator who
    // edits toml is told the store wins while toml actually does, and later the edit silently stops applying.
    for k in &boot.drift {
        warn!(entry = %k, "node.toml differs from the store; toml is used for now, the store value takes effect \
                            when runtime reads the store (P3)");
    }
    admin::TOML_DRIFT.store(boot.drift.len() as u64, std::sync::atomic::Ordering::Relaxed);
    match store::verify_audit(&st.audit_log().await?) {
        Ok(head) => info!(head = %alloy::hex::encode(head), "audit chain head"),
        Err(seq) => error!(seq, "audit chain broken (R110)"),
    }
    let mut gw_chains = HashMap::new();
    let mut probes = Vec::new();
    let mut set: JoinSet<Result<()>> = JoinSet::new();
    // ≤ 10 y each (validated), so the casts are exact.
    let (janitor, job_ret, feed_ret) = (st.clone(), cfg.store.job_retention_secs as i64, cfg.store.feed_retention_secs as i64);
    set.spawn(async move {
        // Fenced out or lock lost ⇒ Err ⇒ the process exits (A1.1); the legacy paths stop with it.
        store::janitor(janitor, Duration::from_secs(2), Duration::from_secs(60), job_ret, feed_ret).await
            .context("store ownership lost")?;
        Err(anyhow!("store janitor ended"))
    });

    for (cc, signers) in cfg.chains.iter().zip(lane_signers) {
        let poll = Duration::from_millis(cc.poll_ms);
        let tokens = Arc::new(RwLock::new(Vec::new()));
        let mut probe_lanes = Vec::new();
        // G2 (§8.4): MỘT tập digest in-flight mỗi chain, chung cho mọi lane.
        let digests = submit::InflightSet::default();
        if cc.uses_adapter() {
            let adapter = adapters::build(cc, &signers)?;
            if cfg.modules.submit {
                let relay = legacy(&cfg, true)?;
                for lane in 0..signers.len() {
                    let (a, o, w) = (adapter.clone(), relay.clone(), format!("{node_id}#{}", cc.lanes[lane]));
                    let d = digests.clone();
                    let k = Arc::new(Mutex::new(Breaker::new(cc.breaker.clone())));
                    probe_lanes.push(LaneProbe { lane: adapter.lanes()[lane].address.clone(), breaker: k.clone() });
                    set.spawn(async move {
                        lane_runner(a, o, lane, w, poll, k, d).await;
                        Err(anyhow!("lane loop ended"))
                    });
                }
            }
            probes.push(ChainProbe { key: cc.chain_key(), adapter: adapter.clone(), max_lag: cc.max_index_lag, lanes: probe_lanes });
            if cfg.modules.indexer {
                let idx = legacy(&cfg, false)?;
                let a = adapter.clone();
                set.spawn(async move {
                    index_runner(a, idx, poll).await;
                    Err(anyhow!("indexer loop ended"))
                });
            }
            continue;
        }
        let num = cc.evm_chain_number;
        let mut lanes = chain::Chain::connect_lanes(cc, &signers)?;
        let shared = Arc::new(lanes.remove(0));
        let (mut first_tx, mut first_breaker) = (None, None);
        if cfg.modules.submit {
            let relay = legacy(&cfg, true)?;
            // Danh sách token NẠP TRƯỚC khi gateway mở (review P15), rồi làm mới mỗi 30 s.
            let nc = relay.node_config(num, None).await?;
            if let Ok(mut w) = tokens.write() {
                *w = nc.submittable_tokens();
            }
            let all = std::iter::once(chain::Chain::connect_lanes(cc, &signers[..1])?.remove(0)).chain(lanes);
            for (lane, c) in all.enumerate() {
                let (tx, rx) = mpsc::channel::<submit::Work>(256);
                if first_tx.is_none() {
                    first_tx = Some(tx);
                }
                let worker = format!("{node_id}#{}", cc.lanes[lane]);
                let s = submit::Submitter::start(c, relay.clone(), cc.clone(), worker, digests.clone()).await?;
                probe_lanes.push(LaneProbe { lane: format!("{:#x}", s.address()), breaker: s.breaker() });
                if first_breaker.is_none() {
                    first_breaker = Some(s.breaker());
                }
                set.spawn(async move {
                    submit::run(s, rx, poll).await;
                    Err(anyhow!("submit loop ended"))
                });
            }
            let (t, n) = (tokens.clone(), relay);
            set.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    match n.node_config(num, None).await {
                        Ok(nc) => {
                            if let Ok(mut w) = t.write() {
                                *w = nc.submittable_tokens();
                            }
                        }
                        Err(e) => warn!(chain = num, "token refresh: {e:#}"),
                    }
                }
            });
        }
        if cfg.modules.indexer {
            let idx = legacy(&cfg, false)?;
            let (c, key) = (shared.clone(), cc.chain_key());
            set.spawn(async move {
                indexer::run(c, idx, poll, key).await;
                Err(anyhow!("indexer loop ended"))
            });
        }
        let probe_chain = chain::Chain::connect_lanes(cc, &signers[..1])?;
        let probe = adapters::evm::EvmAdapter::new(cc, probe_chain, tokens.clone())?;
        probes.push(ChainProbe { key: cc.chain_key(), adapter: Arc::new(probe), max_lag: cc.max_index_lag, lanes: probe_lanes });
        if let Some(tx) = first_tx {
            // DEX (R35): sổ lệnh bền ở Odoo + watcher riêng; settle qua outbox. Lệnh khoá `relayer` =
            // ví lane 0 (RS5-9) mà job outbox chưa ghim được lane (RS5-11) ⇒ DEX chỉ chạy một lane.
            let venue = match cc.dex {
                Some(addr) if cfg.modules.gateway => {
                    if cc.lanes.len() > 1 {
                        bail!("chain {num}: the DEX needs a single relayer lane (RS5-11)");
                    }
                    let relay = legacy(&cfg, true)?;
                    let idx = match cfg.modules.indexer {
                        true => Some(legacy(&cfg, false)?),
                        false => None,
                    };
                    let v = dex::venue::Venue::start(shared.clone(), relay, idx, addr).await?;
                    let lv = v.clone();
                    set.spawn(async move {
                        lv.run_loops(poll).await;
                        Err(anyhow!("dex loop ended"))
                    });
                    Some(v)
                }
                _ => None,
            };
            let guard = Arc::new(scaas_node::guard::Guard::new(cc, tokens.clone()));
            gw_chains.insert(num, gateway::GwChain { chain: shared, tx, tokens, dex: venue, breaker: first_breaker, fee_recipient: cc.fee_recipient, guard });
        }
    }
    if cfg.modules.gateway {
        let secret = match &cfg.modules.gateway_secret_env {
            Some(v) => Some(std::env::var(v).with_context(|| format!("environment variable {v} is not set"))?.into_bytes()),
            None => None,
        };
        let auth = gwauth::Auth::from_mode(&cfg.modules.gateway_auth, secret)?;
        let app = gwauth::wrap(gateway::router(gateway::AppState { chains: Arc::new(gw_chains) }), auth);
        let listener = tokio::net::TcpListener::bind(&cfg.modules.gateway_bind).await?;
        info!(bind = %cfg.modules.gateway_bind, "gateway listening");
        set.spawn(async move {
            axum::serve(listener, app).await?;
            Err(anyhow!("gateway stopped"))
        });
    }
    if !cfg.modules.admin_bind.is_empty() {
        let o = legacy(&cfg, !cfg.modules.indexer)?;
        let snap = Arc::new(RwLock::new(admin::Snapshot::default()));
        let listener = tokio::net::TcpListener::bind(&cfg.modules.admin_bind).await?;
        info!(bind = %cfg.modules.admin_bind, "admin listening (/healthz /readyz /metrics)");
        let app = admin::router(snap.clone());
        set.spawn(async move {
            admin::refresh_loop(probes, o, snap).await;
            Err(anyhow!("admin refresh ended"))
        });
        set.spawn(async move {
            axum::serve(listener, app).await?;
            Err(anyhow!("admin server stopped"))
        });
    }
    // Bất kỳ task nào dừng là một sự cố: báo và thoát để supervisor khởi động lại (review P8).
    let err = match set.join_next().await {
        None => return Ok(()), // no module enabled
        Some(Ok(Ok(()))) => anyhow!("a module exited"),
        Some(Ok(Err(e))) => e,
        Some(Err(e)) => anyhow!("a module panicked: {e}"),
    };
    error!("{err:#}");
    Err(err)
}
