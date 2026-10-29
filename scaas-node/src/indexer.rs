//! Mô-đun `indexer`: chỉ gửi vùng đã final, chỉ khi đủ quorum (spec §3.3).
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::abi::{IMtxRelayFee, IToken, IUALedger};
use crate::chain::Chain;
use crate::finality::{next_range, quorum_ok, safe_head, Mode};
use crate::odoo::Odoo;

const MAX_SPAN: u64 = 1000;

/// An id in row field `k` as the client's ingest takes it (20-byte addresses only, review C1): a native id (top 96 bits
/// zero) is its address; a derived UA is `UA_POOL`, the holder ERC-20 observers see for every UA move, with the id
/// itself in `<k>_ua`.
fn put_id(v: &mut Value, k: &str, w: B256) {
    match crate::metatx::native(&w) {
        Some(a) => v[k] = json!(format!("{a:#x}")),
        None => {
            v[k] = json!(format!("{:#x}", crate::metatx::ua_pool()));
            v[format!("{k}_ua")] = json!(format!("{w:#x}"));
        }
    }
}

/// The id of row field `k`: `<k>_ua` for a derived UA, else the address (joins compare ids, never `UA_POOL`).
fn who(v: &Value, k: &str) -> Option<String> {
    v[format!("{k}_ua")].as_str().or_else(|| v[k].as_str()).map(str::to_string)
}

/// Log đã giải mã theo đúng khoá Odoo đọc (`dms_blockchain` `_decode`). None = không phải
/// event ta theo dõi, hoặc log thiếu vị trí (log pending) — loại.
pub fn encode_event(log: &Log) -> Option<Value> {
    let mut v = json!({
        "contract": format!("{:#x}", log.address()),
        "block_number": log.block_number?,
        "block_hash": format!("{:#x}", log.block_hash?),
        "tx_hash": format!("{:#x}", log.transaction_hash?),
        "log_index": log.log_index?,
    });
    let topic0 = *log.topic0()?;
    if topic0 == IToken::PaymentSettled::SIGNATURE_HASH {
        let e = log.log_decode::<IToken::PaymentSettled>().ok()?.inner.data;
        v["event"] = json!("PaymentSettled");
        v["from"] = json!(format!("{:#x}", e.from));
        v["to"] = json!(format!("{:#x}", e.to));
        v["amount"] = json!(e.amount.to_string());
        v["fee"] = json!(e.feeAmount.to_string());
        v["fee_recipient"] = json!(format!("{:#x}", e.feeRecipient));
        v["entry_ref"] = json!(format!("{:#x}", e.entryRef));
    } else if topic0 == IToken::Transfer::SIGNATURE_HASH {
        let e = log.log_decode::<IToken::Transfer>().ok()?.inner.data;
        v["event"] = json!("Transfer");
        v["from"] = json!(format!("{:#x}", e.from));
        v["to"] = json!(format!("{:#x}", e.to));
        v["amount"] = json!(e.value.to_string());
    } else if topic0 == IToken::PaymentMeta::SIGNATURE_HASH {
        // joined to its PaymentSettled, never sent alone (`join_pay_events`)
        let e = log.log_decode::<IToken::PaymentMeta>().ok()?.inner.data;
        v["event"] = json!("PaymentMeta");
        v["entry_ref"] = json!(format!("{:#x}", e.payId));
        v["meta"] = json!(format!("0x{}", alloy::hex::encode(&e.meta)));
    } else if topic0 == IUALedger::UAPaymentSettled::SIGNATURE_HASH {
        // the UA ledger's payment is a `PaymentSettled` row with ids, as on NEAR and Algorand
        let e = log.log_decode::<IUALedger::UAPaymentSettled>().ok()?.inner.data;
        v["event"] = json!("PaymentSettled");
        put_id(&mut v, "from", e.from);
        put_id(&mut v, "to", e.to);
        v["amount"] = json!(e.amount.to_string());
        v["fee"] = json!(e.feeAmount.to_string());
        v["fee_recipient"] = json!(format!("{:#x}", e.feeRecipient));
        v["entry_ref"] = json!(format!("{:#x}", e.entryRef));
    } else if topic0 == IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH {
        let e = log.log_decode::<IUALedger::UAMetaTransactionExecuted>().ok()?.inner.data;
        v["event"] = json!("MetaTransactionExecuted");
        put_id(&mut v, "from", e.from);
        v["relayer"] = json!(format!("{:#x}", e.relayer));
        v["batch"] = json!(e.batch.to_string());
        v["nonce"] = json!(e.nonce.to_string());
        v["digest"] = json!(format!("{:#x}", e.digest));
        v["fee_recipient"] = json!(format!("{:#x}", e.feeRecipient));
        v["fee"] = json!(e.fee.to_string());
    } else if topic0 == IMtxRelayFee::RelayFeePaid::SIGNATURE_HASH {
        let e = log.log_decode::<IMtxRelayFee::RelayFeePaid>().ok()?.inner.data;
        v["event"] = json!("RelayFeePaid");
        v["entry_ref"] = json!(format!("{:#x}", e.r#ref));
        v["target"] = json!(format!("{:#x}", e.target));
        v["token"] = json!(format!("{:#x}", e.token));
        put_id(&mut v, "from", e.payer);
        put_id(&mut v, "to", e.payee);
        v["amount"] = json!(e.amount.to_string());
    } else if topic0 == IToken::MetaTransactionExecuted::SIGNATURE_HASH {
        let e = log.log_decode::<IToken::MetaTransactionExecuted>().ok()?.inner.data;
        v["event"] = json!("MetaTransactionExecuted");
        v["from"] = json!(format!("{:#x}", e.from));
        v["relayer"] = json!(format!("{:#x}", e.relayer));
        v["batch"] = json!(e.batch.to_string());
        v["nonce"] = json!(e.nonce.to_string());
        v["digest"] = json!(format!("{:#x}", e.digest));
        v["fee_recipient"] = json!(format!("{:#x}", e.feeRecipient));
        v["fee"] = json!(e.fee.to_string());
    } else {
        return None;
    }
    Some(v)
}

/// CTR-MTX-26 / -27 indexer join, one rule for every family (T17, controller ruling 2026-10-28, owner may override).
/// Each family's decoder emits, next to `PaymentSettled`, `PaymentMeta` (`contract` = the token, `entry_ref` = the
/// payId, `meta` hex, `from` when the event names it) and `RelayFeePaid` (`contract` = the router, `entry_ref` = `ref`,
/// `token`, `from` = the payer, `to` = the payee, `amount`, `target`). Only the expected token's `PaymentSettled`
/// proves a payment, and nothing joins by `entry_ref` alone (a 0-amount or fake-token event with the same id joins
/// nothing):
/// - a `PaymentMeta` gives its `meta` to the first later `PaymentSettled` of the same token in the same transaction
///   with the same `entry_ref` (and `from`, when the meta event has one);
/// - a `RelayFeePaid` gives `relay_target` / `relay_payee` to the `PaymentSettled` of its `token` in the same
///   transaction with the same `(from, entry_ref)` and `amount`, paid to the payee or to the router (open mode).
///
/// A `PaymentMeta` or `RelayFeePaid` without its `PaymentSettled` proves nothing (not paid) and neither is ever sent
/// as a row of its own: Odoo's `chain_event_ingest` knows `PaymentSettled`, `MetaTransactionExecuted`, `Transfer`, and
/// reads the new fields only as fields.
pub fn join_pay_events(mut events: Vec<Value>) -> Vec<Value> {
    let key = |v: &Value, k: &str| v[k].as_str().map(str::to_string);
    let at = |v: &Value| v["log_index"].as_u64().unwrap_or(0);
    let of = |events: &[Value], e: &str| events.iter().enumerate().filter(|(_, v)| v["event"] == e).map(|(i, _)| i).collect::<Vec<_>>();
    let (settled, metas, fees) = (of(&events, "PaymentSettled"), of(&events, "PaymentMeta"), of(&events, "RelayFeePaid"));
    let mut taken = vec![false; events.len()];
    for i in metas {
        let m = events[i].clone();
        let j = settled.iter().copied().filter(|&j| {
            let p = &events[j];
            !taken[j] && key(p, "tx_hash") == key(&m, "tx_hash") && key(p, "contract") == key(&m, "contract")
                && key(p, "entry_ref") == key(&m, "entry_ref") && at(p) > at(&m)
                && (m["from"].is_null() || who(p, "from") == who(&m, "from"))
        }).min_by_key(|&j| at(&events[j]));
        if let Some(j) = j {
            taken[j] = true;
            events[j]["meta"] = m["meta"].clone();
        }
    }
    for i in fees {
        let f = events[i].clone();
        if let Some(&j) = settled.iter().find(|&&j| {
            let p = &events[j];
            p["relay_payee"].is_null() && key(p, "tx_hash") == key(&f, "tx_hash") && key(p, "contract") == key(&f, "token")
                && key(p, "entry_ref") == key(&f, "entry_ref") && who(p, "from") == who(&f, "from")
                && key(p, "amount") == key(&f, "amount") && (who(p, "to") == who(&f, "to") || who(p, "to") == key(&f, "contract"))
        }) {
            events[j]["relay_target"] = f["target"].clone();
            events[j]["relay_payee"] = f["to"].clone();
            if !f["to_ua"].is_null() {
                events[j]["relay_payee_ua"] = f["to_ua"].clone();
            }
        }
    }
    events.retain(|v| v["event"] != "PaymentMeta" && v["event"] != "RelayFeePaid");
    events
}

/// The token events the indexer reads (the UA ledger's `UAPaymentSettled` / `UAMetaTransactionExecuted` too; with a
/// router, its `RelayFeePaid`), decoded and joined.
pub fn pay_filter(from: u64, to: u64, mut addrs: Vec<Address>, router: Option<Address>) -> Filter {
    addrs.extend(router);
    Filter::new().from_block(from).to_block(to).address(addrs).event_signature(vec![
        IToken::PaymentSettled::SIGNATURE_HASH,
        IToken::MetaTransactionExecuted::SIGNATURE_HASH,
        IToken::PaymentMeta::SIGNATURE_HASH,
        IMtxRelayFee::RelayFeePaid::SIGNATURE_HASH,
        IUALedger::UAPaymentSettled::SIGNATURE_HASH,
        IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH,
    ])
}

/// `pay_filter`'s logs ⇒ Odoo's events: a `RelayFeePaid` only from the router, a token event only from a token.
pub fn pay_events(logs: &[Log], router: Option<Address>) -> Vec<Value> {
    let rf = IMtxRelayFee::RelayFeePaid::SIGNATURE_HASH;
    let ours = |l: &&Log| (l.topic0() == Some(&rf)) == (Some(l.address()) == router);
    join_pay_events(logs.iter().filter(ours).filter_map(encode_event).collect())
}

/// Cặp (token, ví nhận) đã duyệt; Odoo gửi dạng chuẩn, cặp nào không parse được thì bỏ.
pub fn receiving_pairs(nc: &crate::odoo::NodeConfig) -> Vec<(Address, Address)> {
    nc.receiving_addresses
        .iter()
        .filter_map(|r| Some((r.token.parse().ok()?, r.address.parse().ok()?)))
        .collect()
}

/// Drift A (R56): chỉ giữ `Transfer` của đúng token tới đúng ví nhận của token đó.
pub fn inbound(events: Vec<Value>, pairs: &[(Address, Address)]) -> Vec<Value> {
    let key = |v: &Value, k: &str| v[k].as_str().and_then(|s| s.parse::<Address>().ok());
    events
        .into_iter()
        .filter(|v| v["event"] == "Transfer")
        .filter(|v| matches!((key(v, "contract"), key(v, "to")), (Some(c), Some(t)) if pairs.contains(&(c, t))))
        .collect()
}

const DRIFT_ERR_BACKOFF: Duration = Duration::from_secs(300);

/// Vòng indexer. Drift C chạy TRONG vòng này, giữa hai bước ingest: cursor đứng yên trong lúc đọc số dư nên
/// `height == indexed_block` luôn đúng (review S1-2: task riêng đua với indexer và có thể không bao giờ ghi được).
pub async fn run(chain: Arc<Chain>, odoo: Odoo, poll: Duration, chain_key: String, router: Option<Address>) {
    let mut drift_due = std::time::Instant::now();
    loop {
        match step(&chain, &odoo, router).await {
            Ok(true) => continue, // còn tồn đọng: đi tiếp ngay
            Ok(false) => {}
            Err(e) => warn!(chain = chain.number, "indexer: {e:#}"),
        }
        if std::time::Instant::now() >= drift_due {
            match crate::drift::step(&chain, &odoo, &chain_key).await {
                Ok(true) => drift_due = std::time::Instant::now() + crate::drift::EVERY,
                Ok(false) => warn!(chain = chain.number, "drift: cursor moved under the balance read; retrying"),
                Err(e) => {
                    warn!(chain = chain.number, "drift: {e:#}");
                    drift_due = std::time::Instant::now() + DRIFT_ERR_BACKOFF; // không dội RPC/Odoo mỗi vòng poll
                }
            }
        }
        tokio::time::sleep(poll).await;
    }
}

/// Một vòng: đọc cursor + token từ Odoo, tính vùng final, kiểm quorum, gửi. `true` = đã tiến.
pub async fn step(chain: &Chain, odoo: &Odoo, router: Option<Address>) -> anyhow::Result<bool> {
    let nc = odoo.node_config(chain.number, None).await?;
    // Không token nào đăng ký: không ai lọc được vùng này ⇒ giữ con trỏ (recipe M1), đọc lại khi có token.
    let addrs: Vec<Address> = nc.tokens.iter().filter_map(crate::odoo::TokenCfg::evm).collect();
    if addrs.is_empty() {
        return Ok(false);
    }
    let mode = if nc.finality_mode == "tag" { Mode::Tag } else { Mode::Depth(nc.finality_depth) };
    let latest = chain.primary().get_block_number().await?;
    let finalized = if mode == Mode::Tag { chain.finalized_number().await? } else { None };
    let Some(safe) = safe_head(&mode, latest, finalized) else { return Ok(false) };
    let Some((from, to)) = next_range(nc.indexed_block, safe, MAX_SPAN) else { return Ok(false) };
    let Some(hash) = Chain::block_hash(chain.primary(), to).await else { return Ok(false) };
    let mut others = Vec::new();
    for p in chain.others() {
        others.push(Chain::block_hash(p, to).await);
    }
    if !quorum_ok(hash, &others, nc.finality_quorum) {
        warn!(chain = chain.number, block = to, "quorum not reached; not advancing");
        return Ok(false);
    }
    let mut events = pay_events(&chain.primary().get_logs(&pay_filter(from, to, addrs, router)).await?, router);
    let pairs = receiving_pairs(&nc);
    if !pairs.is_empty() {
        let tokens: Vec<Address> = pairs.iter().map(|p| p.0).collect();
        let wallets: Vec<B256> = pairs.iter().map(|p| p.1.into_word()).collect();
        let f = Filter::new()
            .from_block(from)
            .to_block(to)
            .address(tokens)
            .event_signature(IToken::Transfer::SIGNATURE_HASH)
            .topic2(wallets);
        let logs = chain.primary().get_logs(&f).await?;
        events.extend(inbound(logs.iter().filter_map(encode_event).collect(), &pairs));
    }
    let r = odoo.ingest(chain.number, from, to, &format!("{hash:#x}"), &events).await?;
    info!(chain = chain.number, from, to, created = r.created, "ingested");
    Ok(r.indexed_block >= to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, LogData, B256, U256};

    fn log_of(data: LogData) -> Log {
        Log {
            inner: alloy::primitives::Log { address: Address::repeat_byte(9), data },
            block_hash: Some(B256::repeat_byte(0xb)),
            block_number: Some(5),
            transaction_hash: Some(B256::repeat_byte(0xe)),
            log_index: Some(2),
            ..Default::default()
        }
    }

    #[test]
    fn payment_settled_is_encoded_for_odoo() {
        let ev = IToken::PaymentSettled {
            from: Address::repeat_byte(1),
            to: Address::repeat_byte(2),
            amount: U256::from(250u64),
            feeAmount: U256::ZERO,
            feeRecipient: Address::repeat_byte(3),
            entryRef: B256::repeat_byte(4),
        };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!(v["event"], "PaymentSettled");
        assert_eq!(v["amount"], "250");
        assert_eq!(v["entry_ref"], format!("{:#x}", B256::repeat_byte(4)));
        assert_eq!(v["log_index"], 2);
        assert_eq!(v["contract"], format!("{:#x}", Address::repeat_byte(9)));
    }

    #[test]
    fn executed_carries_the_digest() {
        let ev = IToken::MetaTransactionExecuted {
            from: Address::repeat_byte(1),
            relayer: Address::repeat_byte(2),
            batch: U256::from(7u64),
            nonce: U256::ZERO,
            digest: B256::repeat_byte(5),
            feeRecipient: Address::repeat_byte(2),
            fee: U256::ZERO,
        };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!(v["event"], "MetaTransactionExecuted");
        assert_eq!(v["digest"], format!("{:#x}", B256::repeat_byte(5)));
        assert_eq!(v["batch"], "7");
    }

    #[test]
    fn transfers_are_kept_only_to_the_receiving_wallet_of_that_token() {
        let (token, shop) = (Address::repeat_byte(9), Address::repeat_byte(0x5a));
        let ev = |to: Address| {
            let t = IToken::Transfer { from: Address::repeat_byte(7), to, value: U256::from(5u64) };
            encode_event(&log_of(t.encode_log_data())).unwrap()
        };
        let v = ev(shop);
        assert_eq!((v["event"].as_str(), v["amount"].as_str()), (Some("Transfer"), Some("5")));
        assert_eq!(v["to"], format!("{shop:#x}"));
        let kept = inbound(vec![ev(shop), ev(Address::repeat_byte(1))], &[(token, shop)]);
        assert_eq!(kept.len(), 1);
        assert!(inbound(vec![ev(shop)], &[(Address::repeat_byte(8), shop)]).is_empty(), "other token's wallet");
        let nc: crate::odoo::NodeConfig = serde_json::from_value(json!({
            "finality_mode": "depth", "finality_depth": 1, "finality_quorum": 1, "indexed_block": 0,
            "journal_max_nonce": null, "tokens": [],
            "receiving_addresses": [{"token": format!("{token:#x}"), "address": format!("{shop:#x}")},
                                    {"token": "CABC", "address": "GXYZ"}]})).unwrap();
        assert_eq!(receiving_pairs(&nc), vec![(token, shop)], "non-EVM forms are skipped, not fatal");
    }

    #[test]
    fn pending_or_foreign_logs_are_dropped() {
        let ev = IToken::PaymentSettled {
            from: Address::ZERO,
            to: Address::ZERO,
            amount: U256::ZERO,
            feeAmount: U256::ZERO,
            feeRecipient: Address::ZERO,
            entryRef: B256::ZERO,
        };
        let mut pending = log_of(ev.encode_log_data());
        pending.block_number = None;
        assert!(encode_event(&pending).is_none());
        let foreign = log_of(LogData::new_unchecked(vec![B256::repeat_byte(7)], Default::default()));
        assert!(encode_event(&foreign).is_none());
    }

    fn log_at(address: Address, tx: u8, log_index: u64, data: LogData) -> Log {
        Log { inner: alloy::primitives::Log { address, data }, transaction_hash: Some(B256::repeat_byte(tx)), log_index: Some(log_index),
              ..log_of(LogData::new_unchecked(vec![], Default::default())) }
    }

    /// T17 (G): `PaymentMeta` joins its `PaymentSettled` (same token, transaction and payId, the next one), a
    /// `RelayFeePaid` of the router joins the expected token's `PaymentSettled` by `(from, ref)`, amount and payee; no
    /// join by id alone, an unjoined one proves nothing, and neither reaches Odoo as a row.
    #[test]
    fn indexer_joins_payment_meta() {
        let (token, fake, router) = (Address::repeat_byte(9), Address::repeat_byte(0x66), Address::repeat_byte(0x7f));
        let (alice, shop, mallory) = (Address::repeat_byte(1), Address::repeat_byte(2), Address::repeat_byte(3));
        let (p, r) = (B256::repeat_byte(4), B256::repeat_byte(5));
        let settled = |from: Address, to: Address, amount: u64, entry_ref: B256| IToken::PaymentSettled { from, to,
            amount: U256::from(amount), feeAmount: U256::ZERO, feeRecipient: Address::ZERO, entryRef: entry_ref }.encode_log_data();
        let meta = IToken::PaymentMeta { payId: p, meta: vec![0xab, 0xcd].into() }.encode_log_data();
        let fee_by = |token: Address, payer: Address, amount: u64| IMtxRelayFee::RelayFeePaid { r#ref: r, target: shop, token,
            payer: payer.into_word(), payee: Address::repeat_byte(0x1a).into_word(), amount: U256::from(amount) }.encode_log_data();
        let fee = |token: Address, amount: u64| fee_by(token, alice, amount);
        let logs = vec![
            // tx 1: a 0-amount spoof with the same id before the meta, then the meta and its payment
            log_at(token, 1, 0, settled(mallory, shop, 0, p)),
            log_at(token, 1, 1, meta.clone()),
            log_at(token, 1, 2, settled(alice, shop, 100, p)),
            // tx 2: a meta whose payment never settled; a payment of the same id in another tx
            log_at(token, 2, 0, meta.clone()),
            log_at(token, 3, 0, settled(alice, shop, 100, p)),
            // tx 4: an open-mode relay fee (paid to the router, forwarded), and the router's event
            log_at(token, 4, 0, settled(alice, router, 5, r)),
            log_at(router, 4, 1, fee(token, 5)),
            // tx 5: a fake token's relay fee (no payment of a registered token), and one whose amount differs
            log_at(router, 5, 0, fee(fake, 5)),
            log_at(token, 6, 0, settled(alice, router, 4, r)),
            log_at(router, 6, 1, fee(token, 5)),
            // tx 7: a RelayFeePaid from a contract that is not the router
            log_at(token, 7, 0, settled(alice, router, 5, r)),
            log_at(fake, 7, 1, fee(token, 5)),
            // tx 8 / 9: the registered token's payment in the same tx, the router's event naming another token / payer
            log_at(token, 8, 0, settled(alice, router, 5, r)),
            log_at(router, 8, 1, fee_by(fake, alice, 5)),
            log_at(token, 9, 0, settled(alice, router, 5, r)),
            log_at(router, 9, 1, fee_by(token, mallory, 5)),
        ];
        let out = pay_events(&logs, Some(router));
        assert!(out.iter().all(client_ingest_accepts));
        let names: Vec<&str> = out.iter().map(|v| v["event"].as_str().unwrap()).collect();
        assert_eq!(names, ["PaymentSettled"; 8], "PaymentMeta / RelayFeePaid never reach Odoo as rows");
        let with_meta: Vec<(&str, u64)> = out.iter().filter(|v| !v["meta"].is_null())
            .map(|v| (v["tx_hash"].as_str().unwrap(), v["log_index"].as_u64().unwrap())).collect();
        assert_eq!(with_meta, [(format!("{:#x}", B256::repeat_byte(1)).as_str(), 2)], "only the payment right after its meta");
        assert_eq!(out[1]["meta"], "0xabcd");
        assert_eq!(out[1]["from"], format!("{alice:#x}"));
        let relayed: Vec<&str> = out.iter().filter(|v| !v["relay_payee"].is_null()).map(|v| v["tx_hash"].as_str().unwrap()).collect();
        assert_eq!(relayed, [format!("{:#x}", B256::repeat_byte(4))], "the expected token's payment, same (from, ref), amount and payee or router");
        let j = out.iter().find(|v| !v["relay_payee"].is_null()).unwrap();
        assert_eq!((j["relay_target"].as_str(), j["relay_payee"].as_str()),
            (Some(format!("{shop:#x}").as_str()), Some(format!("{:#x}", Address::repeat_byte(0x1a)).as_str())));
        assert!(pay_events(&logs, None).iter().all(|v| v["relay_payee"].is_null()), "no router: no relay fee joins");
    }

    /// The client's ingest (`dms_blockchain` `chain_event_ingest` `_decode`, bamboo-dms 81cea08): on an EVM chain
    /// `contract`, `from`, `to`, `fee_recipient` and `relayer` must each be `0x` + 40 hex, or the whole range is refused
    /// (review C1). Every row the indexer sends must pass it.
    pub(crate) fn client_ingest_accepts(row: &Value) -> bool {
        let addr = |v: &Value| v.as_str().is_some_and(|s| s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit()));
        ["contract", "from", "to", "fee_recipient", "relayer"].iter().all(|k| row[*k].is_null() || addr(&row[*k]))
    }

    /// The UA ledger's payment (`UAPaymentSettled`) and execution (`UAMetaTransactionExecuted`) are the same rows as the
    /// address path's; a native id is its address, a derived UA is `UA_POOL` (the holder ERC-20 observers see for every
    /// UA move) with the id in `from_ua` / `to_ua` (fix 1, review C1: the client's ingest takes 20-byte addresses only).
    /// A UA payer's `PaymentMeta` and `RelayFeePaid` join them by `(from, entry_ref)` on the id, like any payment.
    #[test]
    fn ua_payments_are_payment_rows_and_join_their_meta_and_relay_fee() {
        use crate::abi::IUALedger;
        let (token, router, lane) = (Address::repeat_byte(9), Address::repeat_byte(0x7f), Address::repeat_byte(0x1a));
        let (ua, shop, other) = (B256::repeat_byte(0xaa), B256::repeat_byte(0xbb), B256::repeat_byte(0xcc));
        let (p, r) = (B256::repeat_byte(4), B256::repeat_byte(5));
        let pool = format!("{:#x}", crate::metatx::ua_pool());
        assert_eq!(crate::metatx::ua_pool(), Address::from_word(alloy::primitives::keccak256("scaas.ua.pool.v1")), "MetaTxLib.UA_POOL");
        let settled = |from: B256, to: B256, amount: u64, entry_ref: B256| IUALedger::UAPaymentSettled { from, to,
            amount: U256::from(amount), feeAmount: U256::from(1u64), feeRecipient: lane, entryRef: entry_ref }.encode_log_data();
        let meta = IToken::PaymentMeta { payId: p, meta: vec![0xab].into() }.encode_log_data();
        let fee = |payer: B256, payee: B256| IMtxRelayFee::RelayFeePaid { r#ref: r, target: token, token, payer, payee,
            amount: U256::from(5u64) }.encode_log_data();
        let exec = IUALedger::UAMetaTransactionExecuted { from: ua, relayer: lane, batch: U256::from(7u64), nonce: U256::ZERO,
            digest: B256::repeat_byte(0xd1), feeRecipient: lane, fee: U256::from(1u64) }.encode_log_data();
        let logs = vec![
            log_at(token, 1, 0, meta.clone()),
            log_at(token, 1, 1, settled(ua, shop, 100, p)),
            log_at(token, 1, 2, exec),
            // a UA payer's open-mode relay fee: paid to pad(router), forwarded to the lane
            log_at(token, 2, 0, settled(ua, router.into_word(), 5, r)),
            log_at(router, 2, 1, fee(ua, lane.into_word())),
            // another payer's RelayFeePaid joins nothing, though both rows say UA_POOL
            log_at(token, 3, 0, settled(ua, router.into_word(), 5, r)),
            log_at(router, 3, 1, fee(other, lane.into_word())),
            // a bound derived payee
            log_at(token, 4, 0, settled(ua, shop, 5, r)),
            log_at(router, 4, 1, fee(ua, shop)),
        ];
        assert!(pay_filter(0, 1, vec![token], Some(router)).topics[0].matches(&IUALedger::UAPaymentSettled::SIGNATURE_HASH));
        assert!(pay_filter(0, 1, vec![token], None).topics[0].matches(&IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH));
        let out = pay_events(&logs, Some(router));
        assert!(out.iter().all(client_ingest_accepts), "every row passes the client's ingest: {out:?}");
        let names: Vec<&str> = out.iter().map(|v| v["event"].as_str().unwrap()).collect();
        assert_eq!(names, ["PaymentSettled", "MetaTransactionExecuted", "PaymentSettled", "PaymentSettled", "PaymentSettled"]);
        let id = |b: B256| format!("{b:#x}");
        assert_eq!((out[0]["from"].as_str(), out[0]["to"].as_str()), (Some(pool.as_str()), Some(pool.as_str())));
        assert_eq!((out[0]["from_ua"].as_str(), out[0]["to_ua"].as_str()), (Some(id(ua).as_str()), Some(id(shop).as_str())));
        assert_eq!((out[0]["amount"].as_str(), out[0]["fee"].as_str(), out[0]["meta"].as_str()), (Some("100"), Some("1"), Some("0xab")));
        assert_eq!((out[1]["from"].as_str(), out[1]["from_ua"].as_str(), out[1]["digest"].as_str()),
            (Some(pool.as_str()), Some(id(ua).as_str()), Some(id(B256::repeat_byte(0xd1)).as_str())));
        assert_eq!(out[2]["to"], format!("{router:#x}"), "a native id is its address");
        assert!(out[2]["to_ua"].is_null(), "and carries no id key");
        assert_eq!(out[2]["relay_payee"], format!("{lane:#x}"), "the UA payer's relay fee joins");
        assert!(out[3]["relay_payee"].is_null(), "by (from, ref) on the id, never by ref or UA_POOL alone");
        assert_eq!((out[4]["relay_payee"].as_str(), out[4]["relay_payee_ua"].as_str()), (Some(pool.as_str()), Some(id(shop).as_str())));
    }

    /// Merge TODO a (recipe M1 on the EVM indexer): no registered token ⇒ nobody can filter this range, so the
    /// cursor stays put (a token activated later still gets its events) and no RPC is spent.
    #[tokio::test]
    async fn no_tokens_holds_the_cursor() {
        use crate::adapter::tests::{fake_odoo, Fake};
        let (odoo, o) = fake_odoo(Fake { tokens: json!([]), ..Default::default() }).await;
        let cfg = crate::config::ChainCfg { evm_chain_number: 7, rpc_urls: vec!["http://127.0.0.1:9".into()], ..Default::default() };
        let chain = Chain::with_signer(&cfg, alloy::signers::local::PrivateKeySigner::random()).unwrap();
        assert!(!step(&chain, &odoo, None).await.unwrap());
        assert_eq!(o.lock().unwrap().ingests, 0, "cursor not advanced");
    }
}
