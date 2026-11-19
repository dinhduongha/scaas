// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T13 `msig` (spec §7) on the fake chain whose registry answers the views of `msig` records (`registrationOf`, `msigOf`,
//! `msigStateOf`): `msig_minimal_sets` over `ua/nested.json`'s nested records, `update_msig_current` over `ua/portable.json`'s
//! `msigUpdates` / `msigUpdated`, and the three registry writes landed by the record. Each signature is checked by `scaas-ua`'s
//! own verifiers (`check_authorization_current`, `check_membership_current`, `check_registration`).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)]
#[allow(clippy::duplicate_mod)]
#[path = "../../tests/common/fake_chain.rs"]
mod fake_chain;

use super::*;
use crate::op::{MsigLeaf, OpState};
use crate::vault::{ImportWords, MemoryStore};
use crate::{ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, SdkConfig};
use fake_chain::{fake, keccak_hex, serve, Fake, CHAIN_ID};
use scaas_ua::ua_portable::{
    check_authorization_current, check_membership_current, check_registration, decode_member_sigs,
    MemberSig,
};
use scaas_ua::wallet::entries::registry_call;
use scaas_ua::wallet::{SecretBytes, Wallet};
use zeroize::Zeroizing;

const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000a1";
const FNDSA512: u16 = 0x0132;
const MLDSA65: u16 = 0x0131;

fn load(p: &str) -> Value {
    let path = format!(
        "{}/../../smartcontracts/vectors/ua/{p}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn b(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap()).unwrap()
}

fn b32(v: &Value) -> [u8; 32] {
    b(v).try_into().unwrap()
}

fn w(n: u64) -> String {
    format!("{n:064x}")
}

fn sel(sig: &str) -> String {
    keccak_hex(sig.as_bytes())[..10].to_string()
}

fn word32(n: u64) -> Vec<u8> {
    U256::from(n).to_be_bytes::<32>().to_vec()
}

struct T {
    sdk: Arc<Sdk>,
    chain: Fake,
    seed: String,
}

async fn setup(registry: &str, genesis: Option<&str>) -> T {
    setup_auth(registry, genesis, None).await
}

async fn setup_auth(
    registry: &str,
    genesis: Option<&str>,
    authenticator: Option<Arc<dyn crate::platform::Authenticator>>,
) -> T {
    let chain = fake();
    if let Some(g) = genesis {
        chain.lock().unwrap().genesis = g.into();
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
        registry: Some(registry.into()),
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
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: MemoryStore::new(),
        authenticator,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let sec = |s: &str| {
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
    };
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
    T { sdk, chain, seed }
}

/// The fake registry's answer to the call prefix `call` (one answer per prefix).
fn answer(t: &T, registry: &str, call: String, out: String) {
    let mut c = t.chain.lock().unwrap();
    c.answers.retain(|(r, d, _)| !(r == registry && *d == call));
    c.answers.push((registry.into(), call, out));
}

/// The registry's `msig` record `first` (registered), its current structure `now`, `version`, `enabled` and `accepted` bits.
fn record(
    t: &T,
    registry: &str,
    first: &[u8],
    now: &[u8],
    version: u64,
    enabled: u64,
    accepted: u64,
) {
    let ua = hex(&scaas_ua::derive_ua(MSIG, first, false).unwrap());
    let ua = &ua[2..];
    let mut kd = alloy::hex::encode(first);
    while !kd.len().is_multiple_of(64) {
        kd.push('0');
    }
    let reg = format!("0x{}{}{}{kd}", w(0x120), w(0x40), w(first.len() as u64));
    answer(
        t,
        registry,
        format!("{}{ua}", sel("registrationOf(bytes32)")),
        reg,
    );
    let s = MsigStructure::from_key_data(now).unwrap();
    let mut o = format!(
        "0x{}{}{}{}",
        w(0x20),
        w(u64::from(s.threshold)),
        w(0x40),
        w(s.members.len() as u64)
    );
    for m in &s.members {
        o += &format!(
            "{}{}{}",
            w(u64::from(m.kind)),
            alloy::hex::encode(m.id),
            w(u64::from(m.weight))
        );
    }
    answer(t, registry, format!("{}{ua}", sel("msigOf(bytes32)")), o);
    answer(
        t,
        registry,
        format!("{}{ua}", sel("msigStateOf(bytes32)")),
        format!("0x{}{}{}", w(version), w(enabled), w(accepted)),
    );
    answer(
        t,
        registry,
        format!("{}{ua}", sel("isRegistered(bytes32)")),
        format!("0x{}", w(1)),
    );
    answer(
        t,
        registry,
        format!("{}{ua}", sel("memberSigHashOf(bytes32,uint256)")),
        format!("0x{}", "ab".repeat(32)),
    );
}

fn ua_ref(t: &T, kind: u16, index: u32) -> KeyRef {
    KeyRef::Ua {
        seed: t.seed.clone(),
        kind,
        account: 0,
        index,
    }
}

fn member(t: &T, index: u16, kind: u16, key: u32) -> MsigSlot {
    MsigSlot::Member {
        index,
        key: ua_ref(t, kind, key),
    }
}

/// The verifier's lookup: the wallet's fndsa512 and mldsa65 keys (indices 0-2) and the `msig` records given.
fn members(msigs: &[Vec<u8>]) -> impl Fn([u8; 32]) -> Option<(u16, Vec<u8>)> {
    let wallet = Wallet::from_mnemonic(REPO, "").unwrap();
    let mut m: HashMap<[u8; 32], (u16, Vec<u8>)> = HashMap::new();
    for kind in [FNDSA512, MLDSA65] {
        for i in 0..3 {
            let k = wallet.ua_key(kind, 0, i).unwrap();
            m.insert(k.ua().unwrap(), (kind, k.key_data()));
        }
    }
    for kd in msigs {
        m.insert(
            scaas_ua::derive_ua(MSIG, kd, false).unwrap(),
            (MSIG, kd.clone()),
        );
    }
    move |id| m.get(&id).cloned()
}

fn domain() -> scaas_ua::Domain {
    scaas_ua::Domain {
        generation: 1,
        chain_id: CHAIN_ID,
        registry: [0x5c; 20],
        chain_uid: [1; 32],
    }
}

fn code<X>(r: Result<X, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn all(_: [u8; 32], _: u16) -> bool {
    true
}

/// The dynamic argument `i` of a call's calldata up to argument `next` (or the end), as `abi.encode` of that one value.
fn tail(calldata: &[u8], i: usize, next: Option<usize>) -> Vec<u8> {
    let off = |k: usize| {
        usize::try_from(U256::from_be_slice(&calldata[4 + 32 * k..4 + 32 * k + 32])).unwrap()
    };
    let end = next.map_or(calldata.len(), |n| 4 + off(n));
    [word32(32), calldata[4 + off(i)..end].to_vec()].concat()
}

/// Plan T13 `msig_minimal_sets` (`ua/nested.json`, CTR-UA-07 at both levels): signing as `msig-inner-heavy` (fndsa512 #0 w1,
/// #1 w2, threshold 2) and `msig-nested-heavy-outer` (`msig-inner-pq` w2 over fndsa512 #0, #1; fndsa512 #2 w1; threshold 2), each
/// structure read from the registry: a minimal set signs and verifies; a set with a slot more, or an inner list short of its
/// threshold, is `UAPoP` (`scaas-ua`'s refusal before anything is signed); a slot or leaf not accepted on this registry is
/// `Argument` (CTR-UA-37), its control signing.
#[tokio::test(flavor = "multi_thread")]
async fn msig_minimal_sets() {
    let n = load("nested.json");
    let row = |name: &str| {
        n["registrations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap()
            .clone()
    };
    let t = setup(REGISTRY, None).await;
    let wallet = Wallet::from_mnemonic(REPO, "").unwrap();
    for (i, name) in ["fndsa512", "fndsa512#1", "fndsa512#2"].iter().enumerate() {
        assert_eq!(
            wallet.ua_key(FNDSA512, 0, i as u32).unwrap().ua().unwrap(),
            b32(&row(name)["ua"])
        );
    }
    let (inner_pq, heavy, outer) = (
        b(&row("msig-inner-pq")["keyData"]),
        b(&row("msig-inner-heavy")["keyData"]),
        b(&row("msig-nested-heavy-outer")["keyData"]),
    );
    for kd in [&inner_pq, &heavy, &outer] {
        record(&t, REGISTRY, kd, kd, 0, 0b11, 0b11);
    }
    let lookup = members(&[inner_pq.clone(), heavy.clone(), outer.clone()]);
    let (purpose, digest) = (scaas_ua::purpose_tag("metatx").unwrap(), [7u8; 32]);
    let sign = |kd: &[u8], slots: Vec<MsigSlot>| {
        let (sdk, ua) = (t.sdk.clone(), scaas_ua::derive_ua(MSIG, kd, false).unwrap());
        async move { uasig(&sdk, "local", &ua, &slots, &purpose, &digest).await }
    };
    let verify = |kd: &[u8], s: &UASig| {
        let ua = scaas_ua::derive_ua(MSIG, kd, false).unwrap();
        check_authorization_current(
            kd,
            &ua,
            &purpose,
            &digest,
            &s.members,
            &domain(),
            &lookup,
            &|_| None,
            Some(&all),
        )
    };
    let leaves = |l: &[u16]| MsigSlot::Msig {
        index: 0,
        members: l
            .iter()
            .map(|i| MsigLeaf {
                index: *i,
                key: ua_ref(&t, FNDSA512, u32::from(*i)),
            })
            .collect(),
    };
    // msig-inner-heavy: {1} alone reaches 2; {0, 1} has a slot more
    let s = sign(&heavy, vec![member(&t, 1, FNDSA512, 1)])
        .await
        .unwrap();
    assert_eq!(verify(&heavy, &s), Ok(()));
    let both = vec![member(&t, 0, FNDSA512, 0), member(&t, 1, FNDSA512, 1)];
    assert_eq!(code(sign(&heavy, both).await), "UAPoP");
    // msig-nested-heavy-outer: the inner slot (w2) by inner-pq's {0, 1} alone
    let s = sign(&outer, vec![leaves(&[0, 1])]).await.unwrap();
    assert_eq!(verify(&outer, &s), Ok(()));
    assert_eq!((s.members.len(), s.members[0].members.len()), (1, 2));
    assert_eq!(
        code(sign(&outer, vec![leaves(&[0, 1]), member(&t, 1, FNDSA512, 2)]).await),
        "UAPoP"
    );
    assert_eq!(
        code(sign(&outer, vec![leaves(&[0])]).await),
        "UAPoP",
        "an inner list short of its threshold"
    );
    // not accepted here: an outer slot, then an inner leaf (CTR-UA-37; their own code, M2)
    record(&t, REGISTRY, &heavy, &heavy, 0, 0b11, 0b01);
    assert_eq!(
        code(sign(&heavy, vec![member(&t, 1, FNDSA512, 1)]).await),
        "MsigSlotInactive"
    );
    record(&t, REGISTRY, &inner_pq, &inner_pq, 0, 0b11, 0b01);
    assert_eq!(
        code(sign(&outer, vec![leaves(&[0, 1])]).await),
        "MsigSlotInactive"
    );
    record(&t, REGISTRY, &inner_pq, &inner_pq, 0, 0b11, 0b11);
    assert!(
        sign(&outer, vec![leaves(&[0, 1])]).await.is_ok(),
        "the control: accepted again"
    );
}

/// Plan T13 `update_msig_current` (CTR-UA-44; `ua/portable.json` `msigUpdates` row `disable-append`, `msigUpdated`): the
/// SDK's `updateMsig` of the stored structure (native, mldsa65 #1, mldsa65 #2; threshold 2) to the row's target (fndsa512 #0
/// appended, slot 2 disabled) is the row's call but for the signatures, signed by mldsa65 #1 and #2 over the row's digest
/// (version = stored + 1, this registry and chain); landed when the registry's version reaches 1. Then, on the updated record
/// (`msigUpdated`), an operation signs by the current structure: the appended slot 3 with slot 1 verifies against the current
/// structure; the disabled slot 2 is refused; the next update is version 2.
#[tokio::test(flavor = "multi_thread")]
async fn update_msig_current() {
    let p = load("portable.json");
    let row = p["msigUpdates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "disable-append")
        .unwrap()
        .clone();
    let registry = row["registry"].as_str().unwrap().to_ascii_lowercase();
    let t = setup(&registry, Some(row["chainUid"].as_str().unwrap())).await;
    let first = b(&row["stored"]);
    let ua = b32(&row["ua"]);
    assert_eq!(scaas_ua::derive_ua(MSIG, &first, false).unwrap(), ua);
    record(&t, &registry, &first, &first, 0, 0b111, 0b111);
    let target = MsigStructureArgs {
        threshold: row["threshold"].as_u64().unwrap() as u16,
        members: row["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| MsigMemberArgs {
                kind: m["kind"].as_u64().unwrap() as u16,
                id: m["id"].as_str().unwrap().into(),
                weight: m["weight"].as_u64().unwrap() as u16,
            })
            .collect(),
    };
    let payer = KeyRef::Native {
        seed: t.seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let update = |slots: Vec<MsigSlot>| UpdateMsig {
        chain: "local".into(),
        ua: hex(&ua),
        structure: target.clone(),
        enabled: vec![0, 1, 3], // "11"
        valid_until_block: row["validUntilBlock"].as_u64().unwrap(),
        slots,
        payer: payer.clone(),
        verifier: false,
        family_without_update: false,
    };
    let quorum = || vec![member(&t, 1, MLDSA65, 1), member(&t, 2, MLDSA65, 2)];
    let acc = t.sdk.account();
    // M4: `pqzKeyAt(ua, 0)` read; no key: no rotation warning for the disabled slot, a key: the warning
    let key_at = format!(
        "{}{}{}",
        sel("pqzKeyAt(bytes32,uint64)"),
        &hex(&ua)[2..],
        w(0)
    );
    answer(
        &t,
        &registry,
        key_at.clone(),
        format!("0x{}{}{}", w(0), w(0), w(0)),
    );
    let plan = acc.prepare_update_msig(update(quorum())).await.unwrap();
    assert!(
        !plan.warnings.iter().any(|w| w == "RotatePqzKey"),
        "{:?}",
        plan.warnings
    );
    answer(
        &t,
        &registry,
        key_at.clone(),
        format!("0x{}{}{}", w(0x5ca), w(0), w(1)),
    );
    let keyed = acc.prepare_update_msig(update(quorum())).await.unwrap();
    assert!(
        keyed.warnings.iter().any(|w| w == "RotatePqzKey"),
        "{:?}",
        keyed.warnings
    );
    answer(&t, &registry, key_at, format!("0x{}{}{}", w(0), w(0), w(0)));
    let wr = &plan.write;
    let updated = b(&p["msigUpdated"]["current"]);
    let want = Landed::MsigUpdate(1, scaas_ua::keccak256(&updated));
    assert_eq!((wr.entry(), wr.landed), ("updateMsig".to_string(), want));
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.starts_with("SlotsLeft(252)")),
        "{:?}",
        plan.warnings
    );
    // the signatures: argument 5 (`sigs`) to the end; every other byte the row's call
    let sigs = decode_member_sigs(&tail(&wr.calldata, 5, None)).unwrap();
    assert_eq!(sigs.iter().map(|s| s.index).collect::<Vec<_>>(), [1, 2]);
    let mut args = row["args"].clone();
    args["sigs"] = members_json(&UASig {
        members: sigs.clone(),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(wr.calldata, registry_call("updateMsig", &args).unwrap());
    let lookup = members(std::slice::from_ref(&first));
    let tag = scaas_ua::purpose_tag("msig-update").unwrap();
    let ok = check_authorization_current(
        &first,
        &ua,
        &tag,
        &b32(&row["digest"]),
        &sigs,
        &domain(),
        &lookup,
        &|_| None,
        Some(&all),
    );
    assert_eq!(
        ok,
        Ok(()),
        "a quorum of the stored structure over the row's digest"
    );
    // an update signed by a slot of the stored structure not accepted here: refused before signing
    record(&t, &registry, &first, &first, 0, 0b111, 0b011);
    assert_eq!(
        code(acc.prepare_update_msig(update(quorum())).await),
        "MsigSlotInactive"
    );
    // the updated record: four slots, enabled 0, 1, 3, version 1, every slot accepted
    let now = b(&p["msigUpdated"]["current"]);
    // M3: version 1 reached by another structure (a competing quorum's update) is not this update; this structure is
    let (_, _, pool) = crate::op::evm(&t.sdk, "local").unwrap();
    let reg: Address = registry.parse().unwrap();
    record(&t, &registry, &first, &first, 1, 0b111, 0b111);
    assert!(
        !super::super::register::read_record(&pool, reg, want, &ua)
            .await
            .unwrap(),
        "another structure at version 1"
    );
    record(&t, &registry, &first, &now, 1, 0b1011, 0b1111);
    assert!(
        super::super::register::read_record(&pool, reg, want, &ua)
            .await
            .unwrap(),
        "this update's structure"
    );
    let (purpose, digest) = (scaas_ua::purpose_tag("metatx").unwrap(), [9u8; 32]);
    let by_current = [member(&t, 1, MLDSA65, 1), member(&t, 3, FNDSA512, 0)];
    let s = uasig(&t.sdk, "local", &ua, &by_current, &purpose, &digest)
        .await
        .unwrap();
    let en: [u8; 32] = U256::from(0b1011).to_be_bytes();
    let current = |id: [u8; 32]| (id == ua).then(|| (now.clone(), en));
    let ok = check_authorization_current(
        &first,
        &ua,
        &purpose,
        &digest,
        &s.members,
        &domain(),
        &lookup,
        &current,
        Some(&all),
    );
    assert_eq!(ok, Ok(()), "signed by the current structure");
    // an operation's check runs before any member signs: `Expect::Any` is refused by `sign_scaas` itself
    let td = TypedData::from_json(row["typedData"].to_string().as_bytes()).unwrap();
    let any = Expect::Any(scaas_ua::wallet::AllowAnyTypedData);
    assert_eq!(
        code(sign_typed(&t.sdk, "local", &hex(&ua), &by_current, &td, &any).await),
        "Argument"
    );
    assert_eq!(
        code(uasig(&t.sdk, "local", &ua, &quorum(), &purpose, &digest).await),
        "MsigSlotInactive",
        "a disabled slot"
    );
    let next = acc
        .prepare_update_msig(UpdateMsig {
            structure: MsigStructureArgs::of(&MsigStructure::from_key_data(&now).unwrap()),
            ..update(by_current.to_vec())
        })
        .await
        .unwrap();
    assert_eq!(
        next.write.landed,
        Landed::MsigUpdate(2, scaas_ua::keccak256(&now)),
        "version = stored + 1"
    );
}

/// The three registry writes on the fake chain (spec §7, CTR-UA-37): `registerMsig` of a 2-of-3 over fndsa512 #0-#2 with an
/// empty `pop` (the call `registry_call` builds from the named arguments) and with the `pop` of two slots (verified by
/// `check_registration`), landed by `isRegistered`; `acceptMembership` of the third slot, verified by
/// `check_membership_current`, landed by its accepted bit, not by the payer's receipt; nothing to accept once the bit is set;
/// `msig_state` shows listed and accepted apart.
#[tokio::test(flavor = "multi_thread")]
async fn msig_writes_landed_by_record() {
    let t = setup(REGISTRY, None).await;
    let wallet = Wallet::from_mnemonic(REPO, "").unwrap();
    let id_of = |i: u32| hex(&wallet.ua_key(FNDSA512, 0, i).unwrap().ua().unwrap());
    let ids: Vec<MsigMemberArgs> = (0..3)
        .map(|i| MsigMemberArgs {
            kind: FNDSA512,
            id: id_of(i),
            weight: 1,
        })
        .collect();
    let s = msig_structure(ids.clone(), 2).unwrap();
    assert_eq!(
        code(msig_structure(vec![ids[0].clone(), ids[0].clone()], 1)),
        "Argument",
        "one id twice"
    );
    assert_eq!(
        code(msig_structure(ids.clone(), 4)),
        "Argument",
        "a threshold above the weight"
    );
    let kd = s.typed().unwrap().key_data();
    let ua = scaas_ua::derive_ua(MSIG, &kd, false).unwrap();
    assert_eq!(s.ua().unwrap(), hex(&ua));
    let slot_of = |i: u32| s.members.iter().position(|m| m.id == id_of(i)).unwrap() as u16;
    answer(
        &t,
        REGISTRY,
        format!("{}{}", sel("isRegistered(bytes32)"), &hex(&ua)[2..]),
        format!("0x{}", w(0)),
    );
    let payer = KeyRef::Native {
        seed: t.seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let acc = t.sdk.account();
    let reg = |slots: Vec<MsigSlot>| MsigRegister {
        chain: "local".into(),
        structure: s.clone(),
        slots,
        payer: payer.clone(),
    };
    let ws = acc.prepare_msig_register(reg(vec![])).await.unwrap();
    assert_eq!(
        (ws.len(), ws[0].entry(), ws[0].landed),
        (1, "registerMsig".to_string(), Landed::Registered)
    );
    let listed: Vec<Value> = s
        .members
        .iter()
        .map(|m| json!({"kind": m.kind, "id": m.id, "weight": m.weight}))
        .collect();
    let z = hex(&[0; 32]);
    let want = json!({"structure": {"threshold": 2, "members": listed}, "attrs": {"pqzKey": "0x", "pqzPopHash": z,
        "kem": {"scheme": 0, "mlkemEk": "0x", "x25519": z}, "kemPkHash": z}, "pop": [], "pqzPop": "0x"});
    assert_eq!(
        ws[0].calldata,
        registry_call("registerMsig", &want).unwrap()
    );
    // with a `pop` by two slots, strictly increasing
    let mut two = [(slot_of(0), 0), (slot_of(1), 1)];
    two.sort_unstable();
    let ws = acc
        .prepare_msig_register(reg(two
            .iter()
            .map(|(i, k)| member(&t, *i, FNDSA512, *k))
            .collect()))
        .await
        .unwrap();
    let pop = tail(&ws[0].calldata, 2, Some(3));
    let lookup = members(&[]);
    assert_eq!(
        check_registration(MSIG, &kd, &Default::default(), &pop, &[], &lookup),
        Ok(())
    );
    // submitted, followed: landed by `isRegistered`
    let q = acc.quote_registry_write(ws[0].clone()).await.unwrap();
    let op = acc.submit_registry_write(ws[0].clone(), q).await.unwrap();
    for _ in 0..50 {
        if !t.chain.lock().unwrap().sent.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    record(&t, REGISTRY, &kd, &kd, 0, 0b111, 0b000);
    assert!(matches!(
        t.sdk.op().state(op).await.unwrap(),
        OpState::Landed { .. }
    ));
    // `acceptMembership` of the third key's slot
    let i2 = slot_of(2);
    let accept = || AcceptMembership {
        chain: "local".into(),
        ua: hex(&ua),
        slot: member(&t, i2, FNDSA512, 2),
        payer: payer.clone(),
    };
    let st = acc.msig_state("local".into(), hex(&ua)).await.unwrap();
    assert!(
        !st.active && st.slots.iter().all(|x| x.enabled && !x.accepted),
        "{st:?}"
    );
    let a = acc
        .prepare_accept_membership(accept())
        .await
        .unwrap()
        .expect("not accepted yet");
    assert_eq!(
        (a.entry(), a.landed),
        ("acceptMembership".to_string(), Landed::Accepted(i2))
    );
    // the one `MemberSig` tuple (argument 1) read as a list of one
    let one = tail(&a.calldata, 1, None);
    let ms = decode_member_sigs(&[word32(32), word32(1), word32(32), one[32..].to_vec()].concat())
        .unwrap();
    let m: &MemberSig = &ms[0];
    assert_eq!(m.index, i2);
    assert_eq!(
        check_membership_current(&kd, &ua, m, &lookup, &|_| None, Some(&all)),
        Ok(())
    );
    let q = acc.quote_registry_write(a.clone()).await.unwrap();
    let sent = t.chain.lock().unwrap().sent.len();
    let op = acc.submit_registry_write(a, q).await.unwrap();
    for _ in 0..50 {
        if t.chain.lock().unwrap().sent.len() > sent {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // the payer's transaction final and successful, the bit not set: not landed
    {
        let mut c = t.chain.lock().unwrap();
        let raw = c.sent.last().unwrap().clone();
        let id = keccak_hex(&alloy::hex::decode(raw.trim_start_matches("0x")).unwrap());
        c.receipts.insert(id, true);
    }
    let s1 = t.sdk.op().state(op.clone()).await.unwrap();
    assert!(
        !matches!(s1, OpState::Landed { .. }),
        "a receipt alone lands nothing: {s1:?}"
    );
    record(&t, REGISTRY, &kd, &kd, 0, 0b111, 1 << i2);
    assert!(
        matches!(t.sdk.op().state(op).await.unwrap(), OpState::Landed { .. }),
        "the accepted bit lands it"
    );
    assert!(
        acc.prepare_accept_membership(accept())
            .await
            .unwrap()
            .is_none(),
        "accepted already"
    );
    let st = acc.msig_state("local".into(), hex(&ua)).await.unwrap();
    assert_eq!((st.active_weight, st.active), (1, false));
    let x = &st.slots[usize::from(i2)];
    assert!(
        x.accepted && x.sig_hash == format!("0x{}", "ab".repeat(32)),
        "{x:?}"
    );
}

/// A secure element holding one P-256 key (MESSAGE mode: ECDSA over SHA-256 of the 32 bytes given); asked `n` times.
#[derive(Default)]
struct Se {
    n: std::sync::atomic::AtomicUsize,
}

fn se_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&scaas_ua::sha256(b"scaas-sdk.m5.se")).unwrap()
}

#[async_trait::async_trait]
impl crate::platform::Authenticator for Se {
    async fn create_passkey(
        &self,
        _: String,
        _: String,
        _: Vec<Vec<u8>>,
    ) -> Result<crate::platform::PasskeyCreated, crate::platform::AuthError> {
        Err(crate::platform::AuthError::Unavailable)
    }
    async fn get_assertion(
        &self,
        _: crate::platform::AssertionRequest,
        _: Arc<SecretBytes>,
    ) -> Result<crate::platform::Assertion, crate::platform::AuthError> {
        Err(crate::platform::AuthError::Unavailable)
    }
    async fn platform_secret(
        &self,
        _: String,
        _: Vec<u8>,
        _: String,
        _: Option<crate::platform::KeyPolicy>,
        _: Arc<SecretBytes>,
    ) -> Result<(), crate::platform::AuthError> {
        Err(crate::platform::AuthError::Unavailable)
    }
    async fn p256_generate(
        &self,
        _: crate::platform::KeyPolicy,
    ) -> Result<crate::platform::SePublic, crate::platform::AuthError> {
        Ok(crate::platform::SePublic {
            handle: "se-m5".into(),
            key_data: se_key().verifying_key().to_sec1_point(false).as_bytes()[1..].to_vec(),
        })
    }
    async fn p256_sign(
        &self,
        _: String,
        ua_msg: Vec<u8>,
        _: String,
    ) -> Result<Vec<u8>, crate::platform::AuthError> {
        use p256::ecdsa::signature::Signer as _;
        self.n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let sig: p256::ecdsa::Signature = se_key().sign(&ua_msg);
        Ok(sig.to_bytes().to_vec())
    }
}

/// M1 and M5 (owner 2026-11-19, "approved M1–M5 as proposed"): a 2-of-2 over fndsa512 #0 and a secure-element row. The
/// fndsa512 slot signed apart (what `member_sign` returns on its device) comes back as `MsigSlot::Signed`; the secure-element
/// slot signs through the external flow (one device request after a dry run); `msig_combine` puts them in index order and the
/// set verifies. A `Signed` slot naming another index, and the same slot twice, are refused; an inactive slot is
/// `MsigSlotInactive` (M2) with no device asked.
#[tokio::test(flavor = "multi_thread")]
async fn msig_members_apart() {
    let se = Arc::new(Se::default());
    let t = setup_auth(REGISTRY, None, Some(se.clone())).await;
    let policy = crate::platform::KeyPolicy {
        biometry_current_set: true,
        invalidated_by_enrollment: true,
    };
    let row = t
        .sdk
        .account()
        .create_se_key(crate::account::CreateSeKey {
            seed: t.seed.clone(),
            name: "element".into(),
            policy,
        })
        .await
        .unwrap();
    let se_kd = se_key().verifying_key().to_sec1_point(false).as_bytes()[1..].to_vec();
    let se_ua = scaas_ua::derive_ua(0x0101, &se_kd, false).unwrap();
    let wallet = Wallet::from_mnemonic(REPO, "").unwrap();
    let f = wallet.ua_key(FNDSA512, 0, 0).unwrap();
    let mut ms = vec![
        MsigMember {
            kind: FNDSA512,
            id: f.ua().unwrap(),
            weight: 1,
        },
        MsigMember {
            kind: 0x0101,
            id: se_ua,
            weight: 1,
        },
    ];
    ms.sort_by_key(|m| m.id);
    let kd = MsigStructure {
        threshold: 2,
        members: ms.clone(),
    }
    .key_data();
    let ua = scaas_ua::derive_ua(MSIG, &kd, false).unwrap();
    record(&t, REGISTRY, &kd, &kd, 0, 0b11, 0b11);
    let (fi, si) = (
        ms.iter().position(|m| m.kind == FNDSA512).unwrap() as u16,
        ms.iter().position(|m| m.kind == 0x0101).unwrap() as u16,
    );
    let (purpose, digest) = (scaas_ua::purpose_tag("metatx").unwrap(), [5u8; 32]);
    // the fndsa512 slot on its own device
    let (_, _, pool) = crate::op::evm(&t.sdk, "local").unwrap();
    let reg: Address = REGISTRY.parse().unwrap();
    let vs = views(&pool, reg, &[ua]).await.unwrap();
    let m = slot_sig(
        &t.sdk,
        &vs,
        &kd,
        &ua,
        &member(&t, fi, FNDSA512, 0),
        &purpose,
        &digest,
        None,
        None,
    )
    .await
    .unwrap();
    let j = serde_json::to_string(
        &members_json(&UASig {
            members: vec![m],
            ..Default::default()
        })
        .unwrap()[0],
    )
    .unwrap();
    let slots = vec![
        MsigSlot::Member {
            index: si,
            key: row.clone(),
        },
        MsigSlot::Signed {
            index: fi,
            member: j.clone(),
        },
    ];
    let s = uasig(&t.sdk, "local", &ua, &slots, &purpose, &digest)
        .await
        .unwrap();
    assert_eq!(
        se.n.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the device asked once"
    );
    assert_eq!(
        s.members.iter().map(|m| m.index).collect::<Vec<_>>(),
        [fi.min(si), fi.max(si)],
        "index order"
    );
    let lookup = |id: [u8; 32]| {
        (id == se_ua)
            .then(|| (0x0101, se_kd.clone()))
            .or_else(|| (id == f.ua().unwrap()).then(|| (FNDSA512, f.key_data())))
    };
    let ok = check_authorization_current(
        &kd,
        &ua,
        &purpose,
        &digest,
        &s.members,
        &domain(),
        &lookup,
        &|_| None,
        Some(&all),
    );
    assert_eq!(ok, Ok(()), "the combined set verifies");
    // a `Signed` slot under another index; the same slot twice
    let wrong = vec![
        MsigSlot::Member {
            index: si,
            key: row.clone(),
        },
        MsigSlot::Signed {
            index: si,
            member: j.clone(),
        },
    ];
    assert_eq!(
        code(uasig(&t.sdk, "local", &ua, &wrong, &purpose, &digest).await),
        "Argument"
    );
    let twice = vec![
        MsigSlot::Signed {
            index: fi,
            member: j.clone(),
        },
        MsigSlot::Signed {
            index: fi,
            member: j.clone(),
        },
    ];
    assert_eq!(
        code(uasig(&t.sdk, "local", &ua, &twice, &purpose, &digest).await),
        "Argument"
    );
    // the secure-element slot not accepted: its own code, no device asked
    record(&t, REGISTRY, &kd, &kd, 0, 0b11, 1 << fi);
    let n = se.n.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        code(uasig(&t.sdk, "local", &ua, &slots, &purpose, &digest).await),
        "MsigSlotInactive"
    );
    assert_eq!(
        se.n.load(std::sync::atomic::Ordering::SeqCst),
        n,
        "no device asked"
    );
}
