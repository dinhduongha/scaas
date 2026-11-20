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
