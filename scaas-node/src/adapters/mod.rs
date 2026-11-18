//! Một file mỗi họ mạng. `evm` dùng chung cho Hedera (HSCS qua JSON-RPC relay — R63).
use std::sync::Arc;

use anyhow::{bail, Result};

use crate::adapter::ChainAdapter;
use crate::config::ChainCfg;
use crate::signer::LocalSigner;

pub mod algorand;
pub mod aptos;
pub mod cosmos;
pub mod evm;
pub mod hedera;
pub mod near;
pub mod solana;
pub mod soroban;
pub mod sui;
pub mod ton;

/// scaas-rpc T24.10 (spec §5.3, owner 2026-11-18): a family's API key per endpoint, named by env var only. `params.<param>` is a
/// string (endpoint 0's key) or a list of env var names, one per `rpc_urls` entry (`""`: none). A later endpoint gets no key
/// unless one is configured for it. A named variable that is unset is an error when `required`, else no key (TON's, as before).
pub(crate) fn endpoint_keys(
    cfg: &ChainCfg,
    param: &str,
    required: bool,
) -> Result<Vec<Option<String>>> {
    let n = cfg.rpc_urls.len();
    let names: Vec<String> = match cfg.params.get(param) {
        None => vec![],
        Some(toml::Value::String(s)) => vec![s.clone()],
        Some(toml::Value::Array(a)) if a.len() == n => a
            .iter()
            .map(|v| v.as_str().map(str::to_string).ok_or_else(|| anyhow::anyhow!("params.{param}: an env var name is not a string")))
            .collect::<Result<_>>()?,
        Some(_) => bail!("chain {}: params.{param} must be an env var name or a list of {n} (one per rpc_urls entry)", cfg.chain_key()),
    };
    (0..n)
        .map(|i| match names.get(i).filter(|v| !v.is_empty()) {
            None => Ok(None),
            Some(v) => match std::env::var(v) {
                Ok(k) => Ok(Some(k)),
                Err(_) if !required => Ok(None),
                Err(_) => bail!("chain {}: params.{param}: {v} is not set", cfg.chain_key()),
            },
        })
        .collect()
}

/// Adapter giữ signer của nó; `LocalSigner` không `Clone` nên chép khoá bên trong.
fn own(s: &LocalSigner) -> LocalSigner {
    match s {
        LocalSigner::Secp(k) => LocalSigner::Secp(k.clone()),
        LocalSigner::Ed(k) => LocalSigner::Ed(k.clone()),
    }
}

/// Adapter cho một chain KHÔNG chạy runner EVM riêng. Mỗi luồng mạng thêm một nhánh ở đây.
pub fn build(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Arc<dyn ChainAdapter>> {
    match cfg.family.as_str() {
        "cosmos" => Ok(Arc::new(cosmos::CosmosAdapter::new(
            cfg,
            signers.iter().map(own).collect(),
        )?)),
        "hedera" => Ok(Arc::new(hedera::HederaAdapter::from_cfg(cfg, signers)?)),
        "soroban" => Ok(Arc::new(soroban::SorobanAdapter::new(cfg, signers)?)),
        "ton" => Ok(Arc::new(ton::TonAdapter::new(cfg, signers)?)),
        "sui" => Ok(Arc::new(sui::SuiAdapter::new(cfg, signers)?)),
        "solana" => Ok(Arc::new(solana::SolanaAdapter::new(cfg, signers)?)),
        "aptos" => Ok(Arc::new(aptos::AptosAdapter::new(cfg, signers)?)),
        "near" => Ok(Arc::new(near::NearAdapter::new(cfg, signers)?)),
        "algorand" => Ok(Arc::new(algorand::AlgorandAdapter::new(cfg, signers)?)),
        other => bail!(
            "chain {}: no adapter for family {other} in this build",
            cfg.chain_key()
        ),
    }
}

/// Test endpoints shared by the families' adapter tests.
#[cfg(test)]
pub(crate) mod testkit {
    use axum::response::IntoResponse;
    use serde_json::Value;

    /// scaas-rpc T24.3: an endpoint in front of the fake at `upstream` that passes the requests `pass` names (its identity
    /// read: path, JSON body) and answers every other one `status` with `body` (a rate limit, an unavailable gateway). Its URL
    /// keeps `upstream`'s path.
    pub(crate) async fn refusing(
        upstream: &str,
        pass: fn(&str, &Value) -> bool,
        status: u16,
        body: Value,
    ) -> String {
        let u = reqwest::Url::parse(upstream).unwrap();
        let origin = u.origin().ascii_serialization();
        let app = axum::Router::new().fallback(
            move |m: axum::http::Method,
                  uri: axum::http::Uri,
                  h: axum::http::HeaderMap,
                  b: axum::body::Bytes| {
                let (origin, body) = (origin.clone(), body.clone());
                async move {
                    let j = serde_json::from_slice(&b).unwrap_or(Value::Null);
                    if !pass(uri.path(), &j) {
                        return (
                            axum::http::StatusCode::from_u16(status).unwrap(),
                            axum::Json(body),
                        )
                            .into_response();
                    }
                    let pq = uri.path_and_query().map_or("", |p| p.as_str());
                    let mut r = reqwest::Client::new()
                        .request(m, format!("{origin}{pq}"))
                        .body(b.to_vec());
                    if let Some(c) = h.get("content-type") {
                        r = r.header("content-type", c);
                    }
                    let r = r.send().await.unwrap();
                    (
                        axum::http::StatusCode::from_u16(r.status().as_u16()).unwrap(),
                        r.bytes().await.unwrap().to_vec(),
                    )
                        .into_response()
                }
            },
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}{}",
            l.local_addr().unwrap(),
            u.path().trim_end_matches('/')
        );
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    /// scaas-rpc T24.2: a scripted endpoint: `answer(path, JSON body)` is its 200 answer (a JSON-RPC family's `result`, wrapped,
    /// when `rpc`); `None` is a 503 (the endpoint down for that read).
    pub(crate) async fn scripted(rpc: bool, answer: fn(&str, &Value) -> Option<Value>) -> String {
        let app = axum::Router::new().fallback(
            move |uri: axum::http::Uri, b: axum::body::Bytes| async move {
                let j: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
                let key = if rpc {
                    j["method"].as_str().unwrap_or_default().to_string()
                } else {
                    uri.path().to_string()
                };
                match answer(&key, &j) {
                    Some(r) if rpc => axum::Json(
                        serde_json::json!({"jsonrpc": "2.0", "id": j["id"], "result": r}),
                    )
                    .into_response(),
                    Some(r) => axum::Json(r).into_response(),
                    None => axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
                }
            },
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::config::Config;
    use crate::keys::{lane_secret, Seed};
    use crate::signer::LocalSigner;

    /// Merge TODO f: `node.example.toml` has a working `[[chains]]` for every family — it parses, validates, and
    /// every adapter builds from it (only the Sui/Aptos package ids, the Solana program id and the Sui journal directory
    /// are swapped for real ones).
    #[test]
    fn example_config_builds_every_family() {
        let mut cfg: Config = toml::from_str(include_str!("../../node.example.toml")).unwrap();
        cfg.validate().unwrap();
        // review P5 m3: the EVM example pins the recorded block 0 of chain 7622
        let uids: serde_json::Value =
            serde_json::from_str(include_str!("../../../smartcontracts/evm/chain-uids.json"))
                .unwrap();
        let want = uids["chains"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["chainId"] == 7622)
            .unwrap()["chainUid"]
            .as_str()
            .unwrap();
        assert_eq!(
            cfg.chains
                .iter()
                .find(|c| c.family == "evm")
                .unwrap()
                .chain_uid,
            Some(want.parse().unwrap())
        );
        let families: BTreeSet<&str> = cfg.chains.iter().map(|c| c.family.as_str()).collect();
        assert_eq!(
            families,
            BTreeSet::from([
                "algorand", "aptos", "cosmos", "evm", "hedera", "near", "solana", "soroban", "sui",
                "ton"
            ])
        );
        let words = format!("{}art", "abandon ".repeat(23));
        let seed = Seed::from_words(&words, None).unwrap();
        let dir = std::env::temp_dir().join(format!("example-journal-{}", std::process::id()));
        for c in cfg.chains.iter_mut().filter(|c| c.uses_adapter()) {
            if c.family == "aptos" {
                c.params.insert("package".into(), "0xb0b".into());
            }
            if c.family == "solana" {
                c.params.insert(
                    "program_id".into(),
                    "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx".into(),
                );
            }
            if c.family == "sui" {
                c.params.insert("package".into(), "0x2".into());
                c.params.insert(
                    "lane_journal".into(),
                    dir.to_string_lossy().to_string().into(),
                );
            }
            let signers: Vec<LocalSigner> = c
                .lanes
                .iter()
                .map(|&i| {
                    let (curve, k) = lane_secret(&seed, &c.family, i).unwrap();
                    LocalSigner::new(curve, &k).unwrap()
                })
                .collect();
            if let Err(e) = super::build(c, &signers) {
                panic!("{}: {e:#}", c.family);
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
