// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas-pqz-verifier [config.toml]` (default `pqz-verifier.toml`): the reference PQZ verifier (off-chain). UNAUDITED.

use std::net::SocketAddr;
use std::sync::Arc;

use alloy::signers::local::PrivateKeySigner;
use anyhow::Context;
use scaas_pqz_verifier::{chain::Rpc, http, Config, Service};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let path = std::env::args().nth(1).unwrap_or_else(|| "pqz-verifier.toml".into());
    let cfg = Config::parse(&std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?)?;
    let password = std::env::var(&cfg.keystore_password_env)
        .with_context(|| format!("the keystore password: env {}", cfg.keystore_password_env))?;
    let signer = PrivateKeySigner::decrypt_keystore(&cfg.keystore, password).context("the keystore")?;
    let rpc = Rpc::connect(&cfg.rpc_url)?;
    let chain_id = rpc.chain_id().await.context("the RPC's chain id")?;
    anyhow::ensure!(chain_id == cfg.chain_id, "the RPC answers chain {chain_id}, the config pins {}", cfg.chain_id);
    let svc = Arc::new(Service::new(Arc::new(rpc), Arc::new(pqz_ffi::precompile), signer, &cfg));
    tracing::info!(verifier = %svc.ua(), set = pqz_ffi::stmt::SET, chain_id, registry = %cfg.registry, bind = %cfg.bind,
        "scaas-pqz-verifier");

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    axum::serve(listener, http::router(svc, &cfg).into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
