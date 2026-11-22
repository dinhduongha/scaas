// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T40: the EVM profiles of `smartcontracts/evm/chain-uids.json` (Ethereum, OP Mainnet, Arbitrum One, Linea; mainnet and
//! testnet each; Ethereum Classic dropped by the owner 2026-11-22, decisions CLI-SDK-32; and the chains-arweave plan's T2 and
//! T11: Avalanche C-Chain and Fuji, the two Polkadot Hub profiles (Westend dropped by the owner 2026-11-22), Moonbeam and Moonbase Alpha) as release data: the row's chain id
//! and `chain_uid`, the `profile.json` finality, per-transaction cap, transaction type, L1 fee model and disabled kinds. Each
//! profile loads; a native send's type follows the chain's base fee; a kind the profile disables is `KindDisabled` before
//! anything is signed (owner 2026-11-22: OP and Arbitrum), against the fake chain of `tests/common/fake_chain.rs` answering
//! the profile's own identity.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, serve};
use scaas_sdk::account::{Register, RegisterAttrs};
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::wallet::NativeSend;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, L1Fee, Limits, RuntimeChoice, Sdk, SdkConfig,
    SdkError,
};
use scaas_ua::wallet::SecretBytes;
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

const KEYS: [&str; 14] = [
    "ethereum-mainnet",
    "ethereum-testnet",
    "op-mainnet",
    "op-testnet",
    "arbitrum-mainnet",
    "arbitrum-testnet",
    "linea-mainnet",
    "linea-testnet",
    // chains-arweave T2 and T11: draft profiles; Fuji disables the kinds above its block (owner 2026-11-22)
    "avalanche-mainnet",
    "avalanche-testnet",
    "polkadot-hub-mainnet",
    "polkadot-hub-testnet",
    "moonbeam-mainnet",
    "moonbeam-testnet",
];
const ORACLE: &str = "0x420000000000000000000000000000000000000f";
const EVM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/evm");
const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

fn json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_else(|_| panic!("{path}")))
        .unwrap()
}

/// The profile of `key` on endpoint `rpc`, with the finality its profile.json states (`None` when it states none), its
/// transaction type and its chain id.
fn profile(key: &str, rpc: &str) -> (ChainProfile, Finality, u8) {
    let rows = json(&format!("{EVM}/chain-uids.json"));
    let row = rows["chains"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == key)
        .unwrap()
        .clone();
    let p = json(&format!("{EVM}/src/chains/{key}/profile.json"));
    // a profile states its finality: the tag or a depth; none is no profile (fail closed)
    let finality = match &p["finality"] {
        Value::String(t) if t == "tag" => Finality::Finalized,
        Value::Object(o) => Finality::Depth(o["depth"].as_u64().unwrap()),
        f => panic!("{key}: finality {f}"),
    };

    let c = ChainProfile {
        key: key.into(),
        family: Family::Evm,
        chain_id: row["chainId"].as_u64(),
        chain_uid: row["chainUid"].as_str().unwrap().into(),
        rpc: vec![EndpointConfig {
            url: rpc.into(),
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: None,
        factory: None,
        router: None,
        finality,
        tx_gas_cap: p["txGasCap"].as_u64(),
        tokens: vec![],
        gas: Default::default(),
        gas_opt_in: vec![],
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        dexes: vec![],
        wrappers: vec![],
        l1_fee: (p["l1Fee"] == "op-stack").then_some(L1Fee::OpStack),
        pinned_reads: p["pinnedReads"].as_bool().unwrap_or(true),
        disabled_kinds: p["disabledKinds"]
            .as_array()
            .map(|a| a.iter().map(|k| k.as_str().unwrap().to_string()).collect())
            .unwrap_or_default(),
        family_params: None,
    };
    (c, finality, p["txType"].as_u64().unwrap() as u8)
}

async fn open(p: ChainProfile) -> (Arc<Sdk>, String) {
    let s = Sdk::open(SdkConfig {
        profiles: vec![p],
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
    let sec = |t: &str| {
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(t.as_bytes().to_vec())).unwrap())
    };
    let seed = s
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    (s, seed)
}

fn send(seed: &str, chain: &str, tx_type: Option<u8>) -> NativeSend {
    NativeSend {
        key: KeyRef::Native {
            seed: seed.into(),
            network: "evm".into(),
            index: 0,
        },
        chain: chain.into(),
        to: "0x00000000000000000000000000000000000000aa".into(),
        value: "1000".into(),
        data: None,
        tx_type,
    }
}

/// Every profile loads with its own chain id and `chain_uid` and the tag (each chain serves `finalized`); Ethereum shares
/// block 0 with ETC (chain id 61) and differs by chain id; an endpoint answering the other chain of the pair is never used
/// (control: its own chain's endpoint).
#[tokio::test(flavor = "multi_thread")]
async fn each_profile_loads() {
    for key in KEYS {
        let c = fake();
        let (p, finality, _) = profile(key, "http://127.0.0.1:9");
        {
            let mut f = c.lock().unwrap();
            f.chain_id = p.chain_id.unwrap();
            f.genesis = p.chain_uid.clone();
            f.native_balance = 10u64.pow(18);
            // GasPriceOracle.getL1Fee on an OP Stack profile (plan T38)
            f.answers
                .push((ORACLE.into(), "0x49948e0e".into(), format!("0x{:064x}", 7)));
        }
        let url = serve(c.clone()).await;
        let (p, _, _) = profile(key, &url);
        assert_eq!(finality, Finality::Finalized, "{key}: the tag");
        let (s, seed) = open(p.clone()).await;
        s.wallet()
            .prepare_native_send(send(&seed, key, None))
            .await
            .unwrap_or_else(|e| panic!("{key}: {e:?}"));
        // the other chain of the pair: the ETC id over Ethereum's block 0 and back, Fuji's over C-Chain's and back, else the
        // id + 1
        let other = match p.chain_id.unwrap() {
            1 => 61,
            61 => 1,
            43114 => 43113,
            43113 => 43114,
            id => id + 1,
        };
        c.lock().unwrap().chain_id = other;
        let (s, seed) = open(p).await;
        assert!(
            s.wallet()
                .prepare_native_send(send(&seed, key, None))
                .await
                .is_err(),
            "{key}: an endpoint of chain {other} is not this profile's"
        );
    }
}

/// A native send's type is the profile's (2: every profile's head carries a base fee); the same profile on a head without a
/// base fee quotes type 0 and refuses an asked type 2 (`TxTypeRefused`).
#[tokio::test(flavor = "multi_thread")]
async fn a_native_send_type_follows_the_base_fee() {
    for key in KEYS {
        for no_base_fee in [false, true] {
            let c = fake();
            let (p, _, ty) = profile(key, "http://127.0.0.1:9");
            {
                let mut f = c.lock().unwrap();
                f.chain_id = p.chain_id.unwrap();
                f.genesis = p.chain_uid.clone();
                f.native_balance = 10u64.pow(18);
                f.answers
                    .push((ORACLE.into(), "0x49948e0e".into(), format!("0x{:064x}", 7)));
                f.no_base_fee = no_base_fee;
            }
            let url = serve(c.clone()).await;
            let (s, seed) = open(profile(key, &url).0).await;
            let q = s
                .wallet()
                .prepare_native_send(send(&seed, key, None))
                .await
                .unwrap();
            let two = s
                .wallet()
                .prepare_native_send(send(&seed, key, Some(2)))
                .await;
            if no_base_fee {
                assert_eq!(q.quote.tx_type, 0, "{key}: no base fee: legacy");
                assert!(
                    matches!(two, Err(SdkError::TxTypeRefused)),
                    "{key}: type 2 without a base fee"
                );
            } else {
                assert_eq!((ty, q.quote.tx_type), (2, 2), "{key}: the profile's type");
                assert_eq!(two.unwrap().quote.tx_type, 2, "{key}: control");
            }
        }
    }
}

/// Owner 2026-11-22 (decisions ARCH-POS-20 (2), wired into the SDK the same day): Moonbeam's and Moonbase's `pinnedReads` false
/// reaches the pool, so a pinned read (a balance at one block) is `PinnedReadsUntrusted` by name while a plain read (a native
/// send's quote) works; the twin with `pinned_reads` true on the same profile reads the balance; every other profile states
/// none and is trusted.
#[tokio::test(flavor = "multi_thread")]
async fn pinned_reads_follow_the_profile() {
    let mut untrusted = 0;
    for key in KEYS {
        let (p, _, _) = profile(key, "http://127.0.0.1:9");
        assert_eq!(
            !p.pinned_reads,
            key.starts_with("moonbeam-"),
            "{key}: pinnedReads"
        );
        for trusted in [p.pinned_reads, true] {
            let c = fake();
            {
                let mut f = c.lock().unwrap();
                f.chain_id = p.chain_id.unwrap();
                f.genesis = p.chain_uid.clone();
                f.native_balance = 10u64.pow(18);
                f.answers
                    .push((ORACLE.into(), "0x49948e0e".into(), format!("0x{:064x}", 7)));
            }
            let url = serve(c.clone()).await;
            let mut q = profile(key, &url).0;
            q.pinned_reads = trusted;
            let (s, seed) = open(q).await;
            let who = "0x00000000000000000000000000000000000000aa".to_string();
            let b = s.wallet().balances(who, key.into()).await;
            let plain = s.wallet().prepare_native_send(send(&seed, key, None)).await;
            assert!(
                plain.is_ok(),
                "{key}: a plain read works ({:?})",
                plain.err()
            );
            if trusted {
                assert!(b.is_ok(), "{key}: trusted: the pinned read ({:?})", b.err());
            } else {
                assert_eq!(
                    b.err().map(|e| e.code()),
                    Some("PinnedReadsUntrusted"),
                    "{key}"
                );
                untrusted += 1;
            }
        }
    }
    assert_eq!(untrusted, 2, "control: Moonbeam and Moonbase were read");
}

/// The owner's ruling of 2026-11-22 (decisions CLI-SDK-32): on OP and Arbitrum the kinds whose largest transaction is above the
/// chain's limit are disabled in the profile (`mldsa44`, `mldsa65`, `mldsa87`, `pqz`) and every other profile disables none; a
/// registration of a disabled kind is `KindDisabled` before anything is read or signed. Twins: a kind that fits on the same
/// profile (`fndsa512`), and the disabled kind on a profile where it fits (Ethereum), pass the check to the next step (no
/// registry in these profiles: `Argument`).
#[tokio::test(flavor = "multi_thread")]
async fn a_disabled_kind_is_refused_before_signing() {
    for key in KEYS {
        let (p, _, _) = profile(key, "http://127.0.0.1:9");
        // owner 2026-11-22: OP and Arbitrum (decisions CLI-SDK-32); Avalanche Fuji's 32 M block (ARCH-POS-20)
        let off =
            key.starts_with("op-") || key.starts_with("arbitrum-") || key == "avalanche-testnet";
        let want: Vec<String> = if off {
            ["mldsa44", "mldsa65", "mldsa87", "pqz"]
                .map(String::from)
                .to_vec()
        } else {
            vec![]
        };
        assert_eq!(p.disabled_kinds, want, "{key}");
    }
    // the same rule on Base and Celo (owner 2026-11-22, (2b)): Base Sepolia's 120 M block fits every kind
    for (key, off) in [
        ("base-mainnet", true),
        ("base-testnet", false),
        ("celo-mainnet", true),
        ("celo-testnet", true),
    ] {
        let n = profile(key, "http://127.0.0.1:9").0.disabled_kinds.len();
        assert_eq!(n, if off { 4 } else { 0 }, "{key}");
    }
    let register = |seed: &str, chain: &str, kind: u16| Register {
        key: KeyRef::Ua {
            seed: seed.into(),
            kind,
            account: 0,
            index: 0,
        },
        chain: chain.into(),
        attrs: RegisterAttrs {
            pqz_key: false,
            kem: false,
        },
        payer: KeyRef::Native {
            seed: seed.into(),
            network: "evm".into(),
            index: 0,
        },
    };
    // a name the SDK does not know is no profile (`Argument` at `Sdk::open`); control: the known names
    for (names, ok) in [
        (vec!["mldsa65".to_string(), "pqz".into()], true),
        (vec!["nope".to_string()], false),
    ] {
        let mut p = profile("op-mainnet", "http://127.0.0.1:9").0;
        p.disabled_kinds = names;
        let r = Sdk::open(SdkConfig {
            profiles: vec![p],
            store: MemoryStore::new(),
            authenticator: None,
            rp_id: None,
            runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
            limits: Limits::default(),
            clock: None,
            gas_tables: vec![],
        })
        .await;
        assert_eq!(r.is_ok(), ok, "{:?}", r.err());
    }
    const MLDSA65: u16 = 0x0131;
    const FNDSA512: u16 = 0x0132;
    for (key, kind, disabled) in [
        ("op-mainnet", MLDSA65, true),
        ("arbitrum-mainnet", MLDSA65, true),
        ("op-mainnet", FNDSA512, false),
        ("arbitrum-mainnet", FNDSA512, false),
        ("ethereum-mainnet", MLDSA65, false),
    ] {
        let c = fake();
        let (p, _, _) = profile(key, "http://127.0.0.1:9");
        {
            let mut f = c.lock().unwrap();
            f.chain_id = p.chain_id.unwrap();
            f.genesis = p.chain_uid.clone();
        }
        let url = serve(c.clone()).await;
        let (s, seed) = open(profile(key, &url).0).await;
        let r = s
            .account()
            .prepare_register(register(&seed, key, kind))
            .await;
        match (disabled, r) {
            (true, Err(SdkError::KindDisabled)) | (false, Err(SdkError::Argument)) => {}
            (_, r) => panic!("{key} {kind:#06x}: {:?}", r.map(|w| w.len())),
        }
    }
}

/// Plan T38's profile data: the profiles with the OP Stack L1 data fee are exactly Base, Celo and OP (mainnet and testnet), and
/// the SDK's profile of each carries `L1Fee::OpStack`.
#[test]
fn the_op_stack_profiles_are_base_celo_and_op() {
    let mut op = vec![];
    for e in std::fs::read_dir(format!("{EVM}/src/chains")).unwrap() {
        let k = e.unwrap().file_name().into_string().unwrap();
        let f = format!("{EVM}/src/chains/{k}/profile.json");
        if std::path::Path::new(&f).exists() && json(&f)["l1Fee"] == "op-stack" {
            op.push(k);
        }
    }
    op.sort();
    assert_eq!(
        op,
        [
            "base-mainnet",
            "base-testnet",
            "celo-mainnet",
            "celo-testnet",
            "op-mainnet",
            "op-testnet"
        ]
    );
    for k in &op {
        let (p, _, _) = profile(k, "http://127.0.0.1:9");
        assert_eq!(p.l1_fee, Some(L1Fee::OpStack), "{k}");
    }
    assert_eq!(
        profile("arbitrum-mainnet", "http://127.0.0.1:9").0.l1_fee,
        None,
        "control"
    );
}
