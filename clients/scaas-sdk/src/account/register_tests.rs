// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T13 `pq_registration_split`: a PQ registration carrying its PQZ key's `pqzPop` (the `ua/portable.json` row
//! `mldsa65/n2304-kmax4096`, a real one) on the fake chain whose estimate grows with the calldata, driven here as both entries
//! drive it (`tests/account_ops.rs` `sponsored_pq_blob_split` drives it through a blob).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)]
// the fake chain of the integration tests, as `op::tests` takes it too (a test-only copy per module)
#[allow(clippy::duplicate_mod)]
#[path = "../../tests/common/fake_chain.rs"]
mod fake_chain;

use super::*;
use crate::vault::{ImportWords, MemoryStore};
use crate::{ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, SdkConfig};
use fake_chain::{fake, keccak_hex, serve, CHAIN_ID};
use scaas_ua::wallet::SecretBytes;
use zeroize::Zeroizing;

const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000a1";

fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}

/// The estimate: 400 gas per calldata byte (the input is hex, two characters a byte).
fn by_size(input: &str) -> u64 {
    input.len() as u64 * 200
}

#[tokio::test(flavor = "multi_thread")]
async fn pq_registration_split() {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../smartcontracts/vectors/ua/portable.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let row = v["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "mldsa65/n2304-kmax4096")
        .unwrap()
        .clone();
    let ua: [u8; 32] = unhex(row["ua"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let chain = fake();
    {
        let mut c = chain.lock().unwrap();
        c.gas_of = Some(by_size);
        let sel = keccak_hex(b"isRegistered(bytes32)")[..10].to_string();
        c.answers
            .push((REGISTRY.into(), sel, format!("0x{}", "00".repeat(32))));
        // `address[3]`: the ML-DSA key's expanded-key cache complete (plan T13, owner 2026-11-19 T1)
        let sel = keccak_hex(b"expandedKeyOf(bytes32)")[..10].to_string();
        c.answers
            .push((REGISTRY.into(), sel, format!("0x{}", "11".repeat(96))));
    }
    let url = serve(chain.clone()).await;
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: chain.lock().unwrap().genesis.clone(),
        rpc: vec![EndpointConfig {
            url,
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(REGISTRY.into()),
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        tokens: vec![],
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
    };
    let sdk = crate::Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO),
            vault_passphrase: sec("river-otter-7 ünï"),
        })
        .await
        .unwrap()
        .id;
    let payer = KeyRef::Native {
        seed,
        network: "evm".into(),
        index: 0,
    };
    let args = &row["args"];
    // the full call (~54 KB of calldata: ~22 M gas) is above the cap; without `pqzPop` (~24 KB: ~10 M) it fits: the registration without `pqzPop`, then `storePqzPop`
    let ws = writes(&sdk, "local", &payer, ua, args, None).await.unwrap();
    let entries: Vec<String> = ws.iter().map(|w| w.entry()).collect();
    assert_eq!(entries, ["register", "storePqzPop"]);
    let mut first = args.clone();
    first["pqzPop"] = json!("0x");
    assert_eq!(ws[0].calldata, registry_call("register", &first).unwrap());
    let store = json!({"ua": hex(&ua), "version": 0, "pqzPop": args["pqzPop"]});
    assert_eq!(
        ws[1].calldata,
        registry_call("storePqzPop", &store).unwrap()
    );
    assert_eq!(ws[1].landed, Landed::PqzPop(0));
    // a part still above the cap: `GasAboveTxCap`
    chain.lock().unwrap().gas_of = Some(|_| 20_000_000);
    assert!(matches!(
        writes(&sdk, "local", &payer, ua, args, None).await,
        Err(SdkError::GasAboveTxCap)
    ));
    // the control: a full call within the cap goes whole
    chain.lock().unwrap().gas_of = Some(|_| 1_000_000);
    let ws = writes(&sdk, "local", &payer, ua, args, None).await.unwrap();
    assert_eq!(ws.len(), 1);
    assert_eq!(ws[0].calldata, registry_call("register", args).unwrap());

    // M1 (review 2026-11-20): the first part landed, the app restarted, the key proved again (a hedged proof: other bytes,
    // another hash). The registry committed to the first proof's hash; the split kept that proof, so the second part is
    // prepared with it, never with the new one
    let pop = args["pqzPop"].as_str().unwrap();
    let committed = scaas_ua::keccak256(&unhex(pop).unwrap());
    {
        let mut c = chain.lock().unwrap();
        let reg = keccak_hex(b"isRegistered(bytes32)")[..10].to_string();
        c.answers.retain(|(_, d, _)| *d != reg);
        c.answers
            .push((REGISTRY.into(), reg, format!("0x{}01", "00".repeat(31))));
        let at = keccak_hex(b"pqzKeyAt(bytes32,uint64)")[..10].to_string();
        c.answers.push((
            REGISTRY.into(),
            at,
            format!(
                "0x{}{}{}",
                "00".repeat(32),
                &hex(&committed)[2..],
                "00".repeat(32)
            ),
        ));
        let of = keccak_hex(b"pqzPopOf(bytes32,uint64)")[..10].to_string();
        c.answers
            .push((REGISTRY.into(), of, format!("0x{}{}", word(0x20), word(0))));
    }
    let mut again = args.clone();
    let mut other = unhex(pop).unwrap();
    other[100] ^= 1;
    again["pqzPop"] = json!(hex(&other));
    let store = |p: &str| {
        registry_call(
            "storePqzPop",
            &json!({"ua": hex(&ua), "version": 0, "pqzPop": p}),
        )
        .unwrap()
    };
    let ws = writes(&sdk, "local", &payer, ua, &again, None)
        .await
        .unwrap();
    let entries: Vec<String> = ws.iter().map(|w| w.entry()).collect();
    assert_eq!(entries, ["storePqzPop"]);
    assert_eq!(
        ws[0].calldata,
        store(pop),
        "the kept proof, the one committed"
    );
    // nothing kept (another device): the new proof hashes otherwise, refused by name; the committed one itself is taken
    crate::op::state::keep_pop(&sdk, &hex(&ua), None)
        .await
        .unwrap();
    assert!(matches!(
        writes(&sdk, "local", &payer, ua, &again, None).await,
        Err(SdkError::RegistrationPopInvalid)
    ));
    let ws = writes(&sdk, "local", &payer, ua, args, None).await.unwrap();
    assert_eq!(ws[0].calldata, store(pop));
}

/// A 32-byte word of `n` (hex, no prefix).
fn word(n: u64) -> String {
    format!("{n:064x}")
}

/// M5 (review 2026-11-20), F24: offsets from an RPC answer near `usize::MAX` are refused, never wrap or panic; the controls
/// read well-formed answers.
#[test]
fn record_offsets_added_checked() {
    let w = |n: u64| {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&n.to_be_bytes());
        b.to_vec()
    };
    // `bytes`: offset, length, one word
    let ok = [w(0x20), w(1), vec![0xaa; 32]].concat();
    assert_eq!(record_holds(Landed::PqzPop(0), &ok), Some(true));
    let near = [w(u64::MAX - 8), w(1), vec![0xaa; 32]].concat();
    assert_eq!(record_holds(Landed::PqzPop(0), &near), None);
    let len_near = [w(0x20), w(u64::MAX - 8), vec![0xaa; 32]].concat();
    assert_eq!(record_holds(Landed::PqzPop(0), &len_near), None);
    // `(KemKey, bytes)`: the tuple's offset, its first word the scheme
    let kem = [w(0x20), w(1)].concat();
    assert_eq!(record_holds(Landed::Kem(0), &kem), Some(true));
    let kem_near = [w(u64::MAX - 8), w(1)].concat();
    assert_eq!(record_holds(Landed::Kem(0), &kem_near), None);
}

// ------------------------------------------------------------------ the registry writes' gas rows (owner 2026-11-20)

/// A chain row `(entry, kind)` at a fresh lane: `gas` whole, `regular` its regular part.
fn row(entry: &str, kind: &str, gas: u64, regular: u64) -> crate::GasBase {
    crate::GasBase {
        entry: entry.into(),
        kind: kind.into(),
        fresh: true,
        gas,
        per_byte: None,
        save: None,
        fee_extra: None,
        ua_extra: None,
        per_item: None,
        regular: Some(regular),
    }
}

/// The SDK's figure of rows summing to `g` for a calldata of `len` bytes: the intrinsic cost, 64 gas a byte, the margin.
fn fig(g: u64, len: usize) -> u64 {
    let x = g + 21_000 + 64 * len as u64;
    x + x / 2
}

/// The rows of an ML-DSA-65 registration with its KEM key and PQZ key: the kind's, the KEM key's, the PQZ key's (with its
/// proof, or without: the first step), `storePqzPop`'s; `pqz_key_regular` the first step's PQZ part.
fn reg_rows(pqz_key_regular: u64, store_regular: u64) -> Vec<crate::GasBase> {
    vec![
        row("register", "ua-0x0131", 5_000_000, 1_000_000),
        row("register", "kem", 1_000_000, 10_000),
        row("register", "pqz-pop", 40_000_000, 2_000_000),
        row("register", "pqz-key", 20_000_000, pqz_key_regular),
        row("storePqzPop", "pqz", 30_000_000, store_regular),
    ]
}

/// The estimate of a registration by its input: the full call (its proof in: ~56 KB) 90 M, `storePqzPop` (~30 KB) 10 M,
/// the call without the proof (~26 KB) 40 M.
fn by_form(input: &str) -> u64 {
    match input.len() {
        n if n > 100_000 => 90_000_000,
        n if n > 56_000 => 10_000_000,
        _ => 40_000_000,
    }
}

struct Reg {
    sdk: Arc<crate::Sdk>,
    chain: fake_chain::Fake,
    payer: KeyRef,
    ua: [u8; 32],
    args: Value,
}

/// The portable row `name` unregistered on a fake chain of block gas limit `block`, whose chain rows are `rows`, under
/// `tx_gas_cap` 2^24 and an SDK whose own gas cap is above any block here.
async fn reg_setup(name: &str, block: u64, rows: Vec<crate::GasBase>) -> Reg {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../smartcontracts/vectors/ua/portable.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let r = v["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap()
        .clone();
    let ua: [u8; 32] = unhex(r["ua"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let chain = fake();
    {
        let mut c = chain.lock().unwrap();
        c.block_gas_limit = block;
        c.gas_of = Some(by_form);
        let sel = keccak_hex(b"isRegistered(bytes32)")[..10].to_string();
        c.answers
            .push((REGISTRY.into(), sel, format!("0x{}", "00".repeat(32))));
        let sel = keccak_hex(b"expandedKeyOf(bytes32)")[..10].to_string();
        c.answers
            .push((REGISTRY.into(), sel, format!("0x{}", "11".repeat(96))));
    }
    let url = serve(chain.clone()).await;
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: chain.lock().unwrap().genesis.clone(),
        rpc: vec![EndpointConfig {
            url,
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(REGISTRY.into()),
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        tokens: vec![],
        gas: crate::GasRows {
            base: rows,
            verify: vec![],
        },
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
    };
    let sdk = crate::Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits {
            max_gas: 1 << 30,
            ..Limits::default()
        },
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO),
            vault_passphrase: sec("river-otter-7 ünï"),
        })
        .await
        .unwrap()
        .id;
    let payer = KeyRef::Native {
        seed,
        network: "evm".into(),
        index: 0,
    };
    let args = r["args"].clone();
    Reg {
        sdk,
        chain,
        payer,
        ua,
        args,
    }
}

const PQ: &str = "mldsa65/n2304-kmax4096";

/// (a) An ML-DSA-65 registration with its PQZ key whose whole gas (the node's 90 M) is above 2^24 and whose regular gas (the
/// table's) fits it, within half the block (200 M): one transaction, quoted at the estimate's whole and the table's regular,
/// not refused, and sent (the fake chain enforces EIP-7825 on the regular gas at the send).
#[tokio::test(flavor = "multi_thread")]
async fn pq_registration_one_transaction_above_2_24() {
    let t = reg_setup(PQ, 200_000_000, reg_rows(300_000, 2_000_000)).await;
    t.chain.lock().unwrap().regular_of = Some(|_| 9_000_000);
    let ws = writes(&t.sdk, "local", &t.payer, t.ua, &t.args, None)
        .await
        .unwrap();
    assert_eq!(ws.len(), 1, "one transaction");
    assert_eq!(ws[0].calldata, registry_call("register", &t.args).unwrap());
    let len = ws[0].calldata.len();
    let regular = fig(1_000_000 + 10_000 + 2_000_000, len);
    assert!(regular <= 1 << 24 && fig(46_000_000, len) < 90_000_000);
    let plan = ws[0].registration_gas().expect("the registration's plan");
    assert_eq!(plan.transactions, 1);
    assert_eq!(
        plan.steps,
        [StepGas {
            entry: "register".into(),
            gas: Some(90_000_000),
            regular_gas: Some(regular),
        }]
    );
    assert_eq!(plan.total_gas, Some(90_000_000));
    let q = t
        .sdk
        .account()
        .quote_registry_write(ws[0].clone())
        .await
        .unwrap();
    assert_eq!((q.gas_limit, q.regular_gas), (90_000_000, regular));
    assert_eq!(
        q.gas_from.as_ref().map(|f| f.base.clone()),
        Some(crate::op::GasFrom::Chain),
        "the table's rows"
    );
    t.sdk
        .account()
        .submit_registry_write(ws[0].clone(), q)
        .await
        .unwrap();
    for _ in 0..50 {
        if !t.chain.lock().unwrap().sent.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        t.chain.lock().unwrap().sent.len(),
        1,
        "sent, and the chain took it"
    );
}

/// (b) The same registration on a block of 150 M: its whole 90 M is above half: two steps, `register` without the proof
/// (estimate 40 M against the table's) then `storePqzPop` (the table's alone: it is not estimated before the first landed),
/// each quoted, the plan stating both and the total.
#[tokio::test(flavor = "multi_thread")]
async fn pq_registration_two_steps_above_half_the_block() {
    let t = reg_setup(PQ, 150_000_000, reg_rows(300_000, 2_000_000)).await;
    let ws = writes(&t.sdk, "local", &t.payer, t.ua, &t.args, None)
        .await
        .unwrap();
    let entries: Vec<String> = ws.iter().map(|w| w.entry()).collect();
    assert_eq!(entries, ["register", "storePqzPop"]);
    let (l1, l2) = (ws[0].calldata.len(), ws[1].calldata.len());
    let s1 = StepGas {
        entry: "register".into(),
        gas: Some(fig(26_000_000, l1).max(40_000_000)),
        regular_gas: Some(fig(1_310_000, l1)),
    };
    let s2 = StepGas {
        entry: "storePqzPop".into(),
        gas: Some(fig(30_000_000, l2)),
        regular_gas: Some(fig(2_000_000, l2)),
    };
    let total = s1.gas.unwrap() + s2.gas.unwrap();
    let plan = RegistrationGas {
        transactions: 2,
        steps: vec![s1, s2],
        total_gas: Some(total),
    };
    assert_eq!(ws[0].registration_gas(), Some(plan.clone()));
    assert_eq!(ws[1].registration_gas(), Some(plan), "both steps state it");
    let q = t
        .sdk
        .account()
        .quote_registry_write(ws[0].clone())
        .await
        .unwrap();
    assert_eq!(
        (q.gas_limit, q.regular_gas),
        (fig(26_000_000, l1).max(40_000_000), fig(1_310_000, l1))
    );
}

/// (c) A step that alone does not fit: the first above half the block (70 M: 41.5 M > 35 M) is `GasAboveBlockShare`; the
/// second's regular gas above 2^24 is `GasAboveTxCap`; nothing kept, nothing sent. The control: the same within both.
#[tokio::test(flavor = "multi_thread")]
async fn pq_registration_step_that_does_not_fit_refused() {
    let t = reg_setup(PQ, 70_000_000, reg_rows(300_000, 2_000_000)).await;
    assert_eq!(
        writes(&t.sdk, "local", &t.payer, t.ua, &t.args, None)
            .await
            .unwrap_err()
            .code(),
        "GasAboveBlockShare"
    );
    let t = reg_setup(PQ, 150_000_000, reg_rows(300_000, 12_000_000)).await;
    assert_eq!(
        writes(&t.sdk, "local", &t.payer, t.ua, &t.args, None)
            .await
            .unwrap_err()
            .code(),
        "GasAboveTxCap"
    );
    assert!(
        t.sdk.registry_writes.lock().unwrap().is_empty(),
        "nothing kept"
    );
    assert!(t.chain.lock().unwrap().sent.is_empty(), "nothing sent");
    let t = reg_setup(PQ, 150_000_000, reg_rows(300_000, 2_000_000)).await;
    assert_eq!(
        writes(&t.sdk, "local", &t.payer, t.ua, &t.args, None)
            .await
            .unwrap()
            .len(),
        2,
        "the control"
    );
}

/// (d) A restart between the two steps: the registration landed, its proof not stored, `pqzKeyAt(ua, 0).pqzPopHash` its
/// commit (F22, M1): `storePqzPop` alone is prepared from the stored state, stated as the second of two, quoted from its
/// row (the regular the table's, the whole max(estimate, table)).
#[tokio::test(flavor = "multi_thread")]
async fn pq_registration_resumes_the_second_step() {
    let t = reg_setup(PQ, 150_000_000, reg_rows(300_000, 2_000_000)).await;
    let pop = t.args["pqzPop"].as_str().unwrap().to_string();
    let committed = scaas_ua::keccak256(&unhex(&pop).unwrap());
    {
        let mut c = t.chain.lock().unwrap();
        let reg = keccak_hex(b"isRegistered(bytes32)")[..10].to_string();
        c.answers.retain(|(_, d, _)| *d != reg);
        c.answers
            .push((REGISTRY.into(), reg, format!("0x{}01", "00".repeat(31))));
        let at = keccak_hex(b"pqzKeyAt(bytes32,uint64)")[..10].to_string();
        c.answers.push((
            REGISTRY.into(),
            at,
            format!(
                "0x{}{}{}",
                "00".repeat(32),
                &hex(&committed)[2..],
                "00".repeat(32)
            ),
        ));
        let of = keccak_hex(b"pqzPopOf(bytes32,uint64)")[..10].to_string();
        c.answers
            .push((REGISTRY.into(), of, format!("0x{}{}", word(0x20), word(0))));
    }
    let ws = writes(&t.sdk, "local", &t.payer, t.ua, &t.args, None)
        .await
        .unwrap();
    let entries: Vec<String> = ws.iter().map(|w| w.entry()).collect();
    assert_eq!(entries, ["storePqzPop"]);
    let l2 = ws[0].calldata.len();
    let s2 = StepGas {
        entry: "storePqzPop".into(),
        gas: Some(fig(30_000_000, l2).max(10_000_000)),
        regular_gas: Some(fig(2_000_000, l2)),
    };
    assert_eq!(
        ws[0].registration_gas(),
        Some(RegistrationGas {
            transactions: 2,
            steps: vec![s2.clone()],
            total_gas: s2.gas,
        })
    );
    let q = t
        .sdk
        .account()
        .quote_registry_write(ws[0].clone())
        .await
        .unwrap();
    assert_eq!(
        (Some(q.gas_limit), Some(q.regular_gas)),
        (s2.gas, s2.regular_gas)
    );
}

/// (e) A registration whose regular gas (the table's) is above the cap is refused at its quote, `GasAboveTxCap`, although the
/// node's estimate (40 M whole, all of it read as regular before) would not tell; the control quotes it at the table's.
#[tokio::test(flavor = "multi_thread")]
async fn registration_regular_above_the_cap_refused() {
    let mut rows = reg_rows(300_000, 2_000_000);
    rows[0] = row("register", "ua-0x0131", 15_000_000, 12_000_000);
    let t = reg_setup("mldsa65#1", 150_000_000, rows).await;
    t.chain.lock().unwrap().gas_of = Some(|_| 1_000_000);
    let ws = writes(&t.sdk, "local", &t.payer, t.ua, &t.args, None)
        .await
        .unwrap();
    assert_eq!(ws.len(), 1);
    assert!(ws[0].registration_gas().is_none(), "no PQZ proof: no plan");
    assert_eq!(
        t.sdk
            .account()
            .quote_registry_write(ws[0].clone())
            .await
            .unwrap_err()
            .code(),
        "GasAboveTxCap"
    );
    let t = reg_setup("mldsa65#1", 150_000_000, reg_rows(300_000, 2_000_000)).await;
    t.chain.lock().unwrap().gas_of = Some(|_| 1_000_000);
    let ws = writes(&t.sdk, "local", &t.payer, t.ua, &t.args, None)
        .await
        .unwrap();
    let len = ws[0].calldata.len();
    let q = t
        .sdk
        .account()
        .quote_registry_write(ws[0].clone())
        .await
        .unwrap();
    assert_eq!(
        (q.gas_limit, q.regular_gas),
        (fig(5_000_000, len), fig(1_000_000, len))
    );
}

/// Controller call (owner auto-run 2026-11-19): every registry write form the SDK builds has its rows in the reference table,
/// so its regular gas is the table's, never the estimate's: `register` of each signing kind (a KEM key and a PQZ key, with
/// or without its proof, added), `registerWebAuthn`, `cacheExpandedKey` of ML-DSA-44 / -65, `setKemKey`, `storePqzPop`, and
/// the `msig` writes up to 16 members with EOA and derived slots; above the counts measured `GasCountUnknown`; a kind without
/// a row (`musig2`) and a slot of a kind without a verify row (a nested `msig`) give no figure.
#[test]
fn reference_rows_cover_every_registry_write() {
    let t = crate::GasTable::parse(crate::op::gas::REFERENCE_FILE).unwrap();
    let opt = [crate::op::gas::REFERENCE.to_string()];
    let none = crate::GasRows::default();
    let fig = |rows: &[(&str, &str)], members: u64, signers: &[u16]| {
        let rows: Vec<(String, String)> = rows
            .iter()
            .map(|(e, k)| (e.to_string(), k.to_string()))
            .collect();
        crate::op::gas::registry_gas(
            &none,
            &opt,
            std::slice::from_ref(&t),
            &rows,
            members,
            signers,
        )
    };
    let kinds = (0x0101..=0x0108).chain(0x0130..=0x0135).chain([0x0141]);
    for k in kinds {
        let base = format!("ua-{k:#06x}");
        let (g, r, from) = fig(&[("register", &base)], 0, &[]).unwrap().unwrap();
        assert!(r > 0 && r < g, "{base}: a regular part");
        assert_eq!(from.base, crate::op::GasFrom::Reference);
        for extra in ["kem", "pqz-key", "pqz-pop"] {
            let (g2, r2, _) = fig(&[("register", &base), ("register", extra)], 0, &[])
                .unwrap()
                .unwrap();
            assert!(g2 > g && r2 > r, "{base} + {extra}: added");
        }
    }
    for rows in [
        [("registerWebAuthn", "ua-0x0100")],
        [("cacheExpandedKey", "ua-0x0130")],
        [("cacheExpandedKey", "ua-0x0131")],
        [("setKemKey", "kem")],
        [("storePqzPop", "pqz")],
    ] {
        assert!(fig(&rows, 0, &[]).unwrap().is_some(), "{rows:?}");
    }
    for e in ["registerMsig", "acceptMembership", "updateMsig"] {
        let (g2, _, _) = fig(&[(e, "msig")], 2, &[0, 0]).unwrap().unwrap();
        let (g16, _, _) = fig(&[(e, "msig")], 16, &[0, 0]).unwrap().unwrap();
        assert!(g16 > g2, "{e}: counted by members");
        let (gd, _, from) = fig(&[(e, "msig")], 2, &[0, 0x0131]).unwrap().unwrap();
        assert!(gd > g2, "{e}: a derived slot adds its verify row");
        assert_eq!(from.verify, crate::op::GasFrom::Reference);
        assert_eq!(
            fig(&[(e, "msig")], 17, &[0]).map_err(|e| e.code()),
            Err("GasCountUnknown"),
            "{e}: above the counts measured"
        );
        assert!(
            fig(&[(e, "msig")], 2, &[0x0120]).unwrap().is_none(),
            "{e}: a nested msig slot"
        );
    }
    assert!(
        fig(&[("register", "ua-0x0110")], 0, &[]).unwrap().is_none(),
        "musig2: no row"
    );
}

/// The rows a write's arguments name (`shape_of`): a PQ registration's kind, its KEM key (full or committed) and its PQZ
/// key with or without the proof; an `msig` registration's members and its `pop` slots' signers by the structure's kinds
/// (an EOA the native reference).
#[test]
fn registry_write_shapes() {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../smartcontracts/vectors/ua/portable.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let args = |name: &str| {
        v["registrations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap()["args"]
            .clone()
    };
    let rows = |s: GasShape| {
        s.rows
            .into_iter()
            .map(|(e, k)| format!("{e}:{k}"))
            .collect::<Vec<_>>()
    };
    let mut a = args(PQ);
    assert_eq!(
        rows(shape_of("register", &a)),
        ["register:ua-0x0131", "register:kem", "register:pqz-pop"]
    );
    a["pqzPop"] = json!("0x");
    a["attrs"]["kem"]["scheme"] = json!(0);
    assert_eq!(
        rows(shape_of("register", &a)),
        ["register:ua-0x0131", "register:pqz-key"]
    );
    a["attrs"]["kemPkHash"] = json!(format!("0x{}", "01".repeat(32)));
    assert_eq!(
        rows(shape_of("register", &a)),
        ["register:ua-0x0131", "register:kem", "register:pqz-key"]
    );
    assert_eq!(
        rows(shape_of("register", &args("mldsa65#1"))),
        ["register:ua-0x0131"]
    );
    assert_eq!(
        rows(shape_of("registerWebAuthn", &args("webauthn-p256"))),
        ["registerWebAuthn:ua-0x0100"]
    );
    let m = shape_of("registerMsig", &args("msig-pq/n2304-kmax4096"));
    assert_eq!((m.members, m.signers.clone()), (2, vec![0x0131, 0x0131]));
    let mut n = args("msig-pq-native");
    let slots = n["pop"].as_array().unwrap().len();
    n["structure"]["members"][0]["kind"] = json!(1);
    n["pop"][0]["index"] = json!(0);
    assert_eq!(
        shape_of("registerMsig", &n).signers[0],
        0,
        "an EOA slot: the native reference"
    );
    assert_eq!(shape_of("registerMsig", &n).signers.len(), slots);
    assert!(
        shape_of("mtxPay", &a).rows.is_empty(),
        "not a registry write"
    );
}
