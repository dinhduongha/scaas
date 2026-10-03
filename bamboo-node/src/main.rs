//! bamboo-node --config node.toml
//!
//! Một binary, mô-đun bật bằng config (`_USER-DECISIONS` §23.3). Mỗi chain: một task `submit`
//! sở hữu nonce vỏ, một task `indexer`, và (tuỳ chọn) gateway HTTP chung.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use bamboo_node::{chain, config, dex, gateway, indexer, odoo, submit};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args: Vec<String> = std::env::args().collect();
    let path = match args.iter().position(|a| a == "--config") {
        Some(i) if i + 1 < args.len() => PathBuf::from(&args[i + 1]),
        _ => bail!("usage: bamboo-node --config node.toml"),
    };
    let cfg = config::Config::load(&path)?;
    if cfg.modules.gateway && !cfg.modules.submit {
        bail!("gateway needs the submit module");
    }
    let node_id = std::env::var("BAMBOO_NODE_ID").unwrap_or_else(|_| "bamboo-node".into());
    let mut gw_chains = HashMap::new();
    let mut set: JoinSet<Result<()>> = JoinSet::new();

    for cc in &cfg.chains {
        let poll = Duration::from_millis(cc.poll_ms);
        let (tx, rx) = mpsc::channel::<submit::Work>(256);
        let tokens = Arc::new(RwLock::new(Vec::new()));
        let shared = Arc::new(chain::Chain::connect(cc)?);
        if cfg.modules.submit {
            let relay = odoo::Odoo::new(&cfg.odoo, &cfg.odoo.relay_api_key_env)?;
            // Danh sách token NẠP TRƯỚC khi gateway mở (review P15), rồi làm mới mỗi 30 s.
            let nc = relay.node_config(cc.evm_chain_number, None).await?;
            if let Ok(mut w) = tokens.write() {
                *w = nc.submittable_tokens();
            }
            let s = submit::Submitter::start(chain::Chain::connect(cc)?, relay.clone(), cc.clone(), node_id.clone())
                .await?;
            set.spawn(async move {
                submit::run(s, rx, poll).await;
                Err(anyhow!("submit loop ended"))
            });
            let (t, n, num) = (tokens.clone(), relay, cc.evm_chain_number);
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
            let idx = odoo::Odoo::new(&cfg.odoo, &cfg.odoo.indexer_api_key_env)?;
            let c = shared.clone();
            set.spawn(async move {
                indexer::run(c, idx, poll).await;
                Err(anyhow!("indexer loop ended"))
            });
        }
        gw_chains.insert(
            cc.evm_chain_number,
            gateway::GwChain { chain: shared, tx, tokens, dex: cc.dex, book: Arc::new(Mutex::new(dex::Book::default())) },
        );
    }
    if cfg.modules.gateway {
        let app = gateway::router(gateway::AppState { chains: Arc::new(gw_chains) });
        let listener = tokio::net::TcpListener::bind(&cfg.modules.gateway_bind).await?;
        info!(bind = %cfg.modules.gateway_bind, "gateway listening");
        set.spawn(async move {
            axum::serve(listener, app).await?;
            Err(anyhow!("gateway stopped"))
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
