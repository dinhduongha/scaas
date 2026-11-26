// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The SDK on the SDK's own fake chain (its `tests/common/fake_chain.rs`, local only): the repository mnemonic imported,
//! three UAs of it (alice, bob, carol: kind 0x0131, accounts 0, 1, 2) registered on the fake registry with their own keys,
//! the crate over its scope and a recording fake of its chain port. Real keys, real signatures, real ciphertexts.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#[path = "../../../scaas-sdk/tests/common/fake_chain.rs"]
pub mod fake_chain;

use super::net::FakeNet;
use fake_chain::{fake, keccak_hex, serve, Fake};
use pqchat_core::model::{hex, Epoch, Member, ZERO32};
use pqchat_core::{ChainConf, MemoryStore, PqChat, PqChatConfig};
use scaas_sdk::app_core::{AppCore, AppKey};
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_keys::PqMessageHeader;
use scaas_sdk::vault::{ImportWords, MemoryStore as Vaults};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig,
    SecretBytes,
};
use scaas_ua::wallet::{Signer, Wallet};
use serde_json::{json, Value};
use std::sync::Arc;
use zeroize::Zeroizing;

pub const PASS: &str = "river-otter-7 ünï";
pub const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
pub const REGISTRY: &str = "0x5ca00000000000000000000000000000000000a1";
pub const FACTORY: &str = "0x5ca00000000000000000000000000000000000f1";
pub const HOME: &str = "0x5ca00000000000000000000000000000000000c1";
pub const REPLICA: &str = "0x5ca00000000000000000000000000000000000c2";
pub const UNLISTED: &str = "0x5ca00000000000000000000000000000000000c3";
pub const CHAIN: &str = "local";
pub const KIND: u16 = 0x0131;
/// One live scope declares PqChat's prefix at a time (the SDK refuses overlapping live prefixes): every test holds this.
pub static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}

pub fn profile(rpc: Vec<EndpointConfig>, genesis: String) -> ChainProfile {
    ChainProfile {
        key: CHAIN.into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: genesis,
        rpc,
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(REGISTRY.into()),
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: None,
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: vec![],
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: vec![],
        family_params: None,
    }
}

pub fn named(url: String) -> EndpointConfig {
    EndpointConfig {
        url,
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    }
}

pub fn discovered(url: String) -> EndpointConfig {
    EndpointConfig {
        url,
        class: scaas_rpc::Class::Discovered,
        label: None,
        auth: None,
    }
}

/// The SDK over `rpc` (the fake chains' URLs), the repository mnemonic imported; its seed id.
pub async fn sdk_on(rpc: Vec<EndpointConfig>, genesis: String) -> (Arc<Sdk>, String) {
    let s = Sdk::open(SdkConfig {
        profiles: vec![profile(rpc, genesis)],
        store: Vaults::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
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

pub fn w(n: u64) -> String {
    format!("{n:064x}")
}
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn pad(b: &[u8]) -> String {
    let mut s = hexs(b);
    while !s.len().is_multiple_of(64) {
        s.push('0');
    }
    s
}
pub fn sel(sig: &str) -> String {
    keccak_hex(sig.as_bytes())[..10].to_string()
}
/// An `eth_call` answer of the fake: `sig` with `arg` (the calldata after the selector) on `to`.
pub fn answer(c: &Fake, to: &str, sig: &str, arg: &[u8], out: String) {
    let mut c = c.lock().unwrap();
    let prefix = format!("{}{}", sel(sig), hexs(arg));
    c.answers.retain(|(t, d, _)| !(t == to && *d == prefix));
    c.answers.push((to.into(), prefix, format!("0x{out}")));
}
fn word(n: u64) -> Vec<u8> {
    let mut v = [0u8; 32];
    v[24..].copy_from_slice(&n.to_be_bytes());
    v.to_vec()
}
/// The KemKey tuple's encoding at a head offset of `head` words (as the registry's `kemKeyAt` / `kemKeyOf` return it).
fn kem_tail(kem_pk: &[u8], head: u64) -> String {
    let (ek, x) = (&kem_pk[1..1 + 1568], &kem_pk[1 + 1568..]);
    let sig_at = head * 32 + 0x60 + 0x20 + pad(ek).len() as u64 / 2;
    format!(
        "{}{}{}{}{}{}{}",
        w(sig_at),
        w(1),
        w(0x60),
        hexs(x),
        w(ek.len() as u64),
        pad(ek),
        w(0)
    )
}
/// `kemKeyAt(id, v)` answers `kem_pk`.
pub fn kem_at(c: &Fake, id: &[u8; 32], v: u64, kem_pk: &[u8]) {
    answer(
        c,
        REGISTRY,
        "kemKeyAt(bytes32,uint64)",
        &[id.to_vec(), word(v)].concat(),
        format!("{}{}", w(0x40), kem_tail(kem_pk, 2)),
    );
}
/// `kemKeyOf(id)` answers version `v` and `kem_pk`.
pub fn kem_of(c: &Fake, id: &[u8; 32], v: u64, kem_pk: &[u8]) {
    answer(
        c,
        REGISTRY,
        "kemKeyOf(bytes32)",
        id,
        format!("{}{}{}", w(v), w(0x60), kem_tail(kem_pk, 3)),
    );
}
/// `registrationOf(id)` answers `(kind, keyData)`.
pub fn reg(c: &Fake, id: &[u8; 32], kind: u16, kd: &[u8]) {
    let out = format!(
        "{}{}{}{}{}{}{}",
        w(u64::from(kind)),
        w(0xa0),
        w(0),
        w(0),
        w(0),
        w(kd.len() as u64),
        pad(kd)
    );
    answer(c, REGISTRY, "registrationOf(bytes32)", id, out);
}

/// A UA of the repository seed.
#[derive(Clone)]
pub struct Acc {
    pub ua: String,
    pub id: [u8; 32],
    pub key: KeyRef,
    pub kem_pk: Vec<u8>,
}

pub fn acc(seed: &str, account: u32) -> Acc {
    let wl = Wallet::from_mnemonic(REPO, "").unwrap();
    let k = wl.ua_key(KIND, account, 0).unwrap();
    let id = k.ua().unwrap();
    Acc {
        ua: hex(&id),
        id,
        key: KeyRef::Ua {
            seed: seed.into(),
            kind: KIND,
            account,
            index: 0,
        },
        kem_pk: k.kem_key(1).unwrap().kem_pk(),
    }
}

/// `a` registered on the fake registry with its own key data (`with` another UA's: a signature of another key).
pub fn register(c: &Fake, a: &Acc, with: &Acc) {
    let wl = Wallet::from_mnemonic(REPO, "").unwrap();
    let KeyRef::Ua { account, .. } = with.key else {
        panic!()
    };
    let k = wl.ua_key(KIND, account, 0).unwrap();
    let scaas_ua::wallet::KeyRef::Ua { kind, key_data, .. } = k.key_ref() else {
        panic!()
    };
    reg(c, &a.id, kind, &key_data);
}

/// The world of a test: the SDK on a fake chain, the crate on a recording port, three UAs, one epoch key.
pub struct World {
    pub sdk: Arc<Sdk>,
    pub seed: String,
    pub chain: Fake,
    pub app: Arc<AppCore>,
    pub net: Arc<FakeNet>,
    pub store: Arc<MemoryStore>,
    pub pq: Arc<PqChat>,
    pub alice: Acc,
    pub bob: Acc,
    pub carol: Acc,
}

pub fn conf() -> PqChatConfig {
    PqChatConfig {
        chains: vec![ChainConf {
            chain: CHAIN.into(),
            chain_uid: hex(&[7; 32]),
            registry: REGISTRY.into(),
            factory: FACTORY.into(),
            tree_gas: None,
        }],
        ..PqChatConfig::default()
    }
}

pub async fn world() -> World {
    let chain = fake();
    let url = serve(chain.clone()).await;
    let genesis = chain.lock().unwrap().genesis.clone();
    let (sdk, seed) = sdk_on(vec![named(url)], genesis).await;
    let app = pqchat_core::scope(&sdk).unwrap();
    let net = Arc::new(FakeNet::new());
    let store = Arc::new(MemoryStore::new());
    let pq = PqChat::with_net(app.clone(), net.clone(), store.clone(), conf());
    let (alice, bob, carol) = (acc(&seed, 0), acc(&seed, 1), acc(&seed, 2));
    for a in [&alice, &bob, &carol] {
        register(&chain, a, a);
        not_msig(&net, &a.ua);
    }
    World {
        sdk,
        seed,
        chain,
        app,
        net,
        store,
        pq,
        alice,
        bob,
        carol,
    }
}

pub fn member(a: &Acc) -> Member {
    Member {
        ua: a.ua.clone(),
        key_id: 1,
        via: ZERO32.into(),
    }
}

/// A session record (epoch 0) of `creator` with `members` (sorted here), `admins` the creator; wrap hashes placeholders.
pub fn session(creator: &Acc, members: &[&Acc]) -> Epoch {
    let mut ms: Vec<Member> = members.iter().map(|a| member(a)).collect();
    ms.sort_by(|a, b| a.ua.cmp(&b.ua));
    let id = hex(&[0x51; 32]);
    Epoch {
        id: id.clone(),
        session_id: id,
        author: creator.ua.clone(),
        nonce: 1,
        epoch: 0,
        parent: ZERO32.into(),
        admins: vec![creator.ua.clone()],
        wrap_hashes: ms.iter().map(|_| hex(&[0xaa; 32])).collect(),
        members: ms,
        sealed_info: vec![],
        sig_hash: hex(&[0x5e; 32]),
    }
}

pub const DEVICE: &str = "0x0102030405060708090a0b0c0d0e0f10";

/// `from`'s message of `content` at `counter` under `e` and `k` (S5 through the crate's scope).
pub async fn sealed(
    w: &World,
    from: &Acc,
    e: &Epoch,
    k: &Arc<AppKey>,
    counter: u64,
    content: &str,
) -> scaas_sdk::pqchat_keys::PqSealedMessage {
    let p0 = w
        .app
        .pqchat_chain(
            k.clone(),
            e.session_id.clone(),
            e.id.clone(),
            from.ua.clone(),
            DEVICE.into(),
        )
        .unwrap();
    let p = if counter == 0 {
        p0
    } else {
        w.app.pqchat_advance(p0, counter).unwrap()
    };
    w.app
        .pqchat_seal_message(
            from.key.clone(),
            k.clone(),
            p,
            PqMessageHeader {
                session_id: e.session_id.clone(),
                epoch_id: e.id.clone(),
                device: DEVICE.into(),
                counter,
                parents: vec![],
            },
            content.into(),
        )
        .await
        .unwrap()
}

pub fn text(s: &SecretBytes) -> String {
    s.with(|b| String::from_utf8(b.to_vec()).unwrap())
}

fn members_json(e: &Epoch) -> Vec<Value> {
    e.members
        .iter()
        .map(|m| json!({"ua": m.ua, "keyId": m.key_id.to_string(), "via": m.via}))
        .collect()
}

/// `e` stored at `contract` as `sessionOf` / `epochOf` answer it (the SDK's named JSON); the instance keeps no signatures
/// (`sigStore` `none`, CTR-CHAT-23: these records carry stand-in hashes; `tests/signed.rs` serves signed rows).
pub fn put_record(net: &FakeNet, contract: &str, e: &Epoch) {
    net.answer(contract, "IPqChat.sigStore", json!({}), json!({"0": "0"}));
    if e.epoch == 0 {
        let s = json!({"creator": e.author, "nonce": e.nonce.to_string(), "homeChain": hex(&[7; 32]),
            "homeChatContract": HOME, "groupMode": "0", "admins": e.admins, "members": members_json(e), "wrapHashes": e.wrap_hashes,
            "sealedInfo": hex(&e.sealed_info)});
        net.answer(
            contract,
            "IPqChat.sessionOf",
            json!({"sessionId": e.id}),
            json!({"s": s, "sigHash": e.sig_hash}),
        );
    } else {
        let x = json!({"sessionId": e.session_id, "author": e.author, "nonce": e.nonce.to_string(),
            "epoch": e.epoch.to_string(), "parentEpochId": e.parent, "admins": e.admins, "members": members_json(e),
            "wrapHashes": e.wrap_hashes, "sealedInfo": hex(&e.sealed_info)});
        net.answer(
            contract,
            "IPqChat.epochOf",
            json!({"epochId": e.id}),
            json!({"e": x, "sigHash": e.sig_hash}),
        );
    }
    for m in e
        .members
        .iter()
        .map(|m| m.ua.clone())
        .chain(e.admins.iter().cloned())
    {
        for it in ["IPqChat.leftIn", "IPqChat.removedIn"] {
            net.answer(
                contract,
                it,
                json!({"epochId": e.id, "member": m}),
                json!({"0": false}),
            );
        }
    }
}

/// `contract` in the factory's listing as class `class`, version `version`; it keeps no signatures (`sigStore` `none`,
/// CTR-CHAT-23) unless a test serves another setting after this.
pub fn list(net: &FakeNet, contract: &str, class: u16, version: u64) {
    net.answer(contract, "IPqChat.sigStore", json!({}), json!({"0": "0"}));
    let i = json!({"addr": contract, "creatorId": hex(&[0; 32]), "contractClass": class.to_string(), "kind": "0",
        "version": version.to_string(), "createdBlock": "1", "createdAt": "1"});
    net.answer(
        FACTORY,
        "IOpenFactory.infoOf",
        json!({"c": contract}),
        json!({"0": i}),
    );
}

/// `wrap` landed at index `i` of `epoch_id` at `contract`.
pub fn put_wrap(
    net: &FakeNet,
    contract: &str,
    epoch_id: &str,
    i: usize,
    wrap: &scaas_sdk::pqchat_records::PqWrap,
) {
    let x = json!({"member": wrap.member, "keyId": wrap.key_id.to_string(), "mlkemCt": hex(&wrap.mlkem_ct),
        "x25519Eph": wrap.x25519_eph, "sealedKey": hex(&wrap.sealed_key)});
    net.answer(
        contract,
        "IPqChat.wrapAt",
        json!({"epochId": epoch_id, "i": i.to_string()}),
        json!({"0": x}),
    );
}

/// An opened session for the tests: `e` (alice creator, alice and bob members) stored and listed at HOME, `k` its key,
/// bob's real wrap of `k` landed and its hash signed in `e`.
pub struct Opened {
    pub e: Epoch,
    pub k: Arc<AppKey>,
    pub wrap: scaas_sdk::pqchat_records::PqWrap,
    pub s: pqchat_core::reads::SessionRef,
}

pub async fn opened(w: &World, members: &[&Acc]) -> Opened {
    let mut e = session(&w.alice, members);
    let k = w.app.pqchat_epoch_key(&w.seed).unwrap();
    for a in members {
        kem_at(&w.chain, &a.id, 1, &a.kem_pk);
    }
    let i = e.index_of(&w.bob.ua).unwrap();
    let wrap = w
        .app
        .pqchat_wrap(
            CHAIN.into(),
            k.clone(),
            e.session_id.clone(),
            e.id.clone(),
            w.bob.ua.clone(),
            1,
        )
        .await
        .unwrap();
    e.wrap_hashes[i] = w.app.pqchat_wrap_hash(wrap.clone()).unwrap();
    put_record(&w.net, HOME, &e);
    put_wrap(&w.net, HOME, &e.id, i, &wrap);
    list(&w.net, HOME, 3, 1);
    let s = pqchat_core::reads::SessionRef {
        chain: CHAIN.into(),
        home: HOME.into(),
        session_id: e.session_id.clone(),
    };
    Opened { e, k, wrap, s }
}

/// `ua` is no `msig` (`msigOf`: threshold 0, no members).
pub fn not_msig(net: &FakeNet, ua: &str) {
    net.answer(
        REGISTRY,
        "IUARegistry.msigOf",
        json!({ "ua": ua }),
        json!({"0": {"threshold": "0", "members": []}}),
    );
}

/// `seat` an `msig` of `slots` (`(kind, id, accepted)` each).
pub fn msig(net: &FakeNet, seat: &str, slots: &[(u16, &str, bool)]) {
    let m: Vec<Value> = slots
        .iter()
        .map(|(k, id, _)| json!({"kind": k.to_string(), "id": id, "weight": "1"}))
        .collect();
    net.answer(
        REGISTRY,
        "IUARegistry.msigOf",
        json!({ "ua": seat }),
        json!({"0": {"threshold": "1", "members": m}}),
    );
    for (i, (_, _, a)) in slots.iter().enumerate() {
        net.answer(
            REGISTRY,
            "IUARegistry.memberAccepted",
            json!({"ua": seat, "index": i.to_string()}),
            json!({ "0": a }),
        );
    }
}

/// `a`'s KEM key at version `v` (its seed's `kem_key(v)`).
pub fn kem_pk(a: &Acc, v: u64) -> Vec<u8> {
    let KeyRef::Ua { account, .. } = a.key else {
        panic!()
    };
    Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .ua_key(KIND, account, 0)
        .unwrap()
        .kem_key(v)
        .unwrap()
        .kem_pk()
}

/// `a` holds KEM version `v` (`kem_pk`): the crate's trusted reads (`checkedOf.kem` 1, `kemKeyOf`) and the SDK's `kemKeyAt`.
pub fn kem_with(w: &World, a: &Acc, v: u64, kem_pk: &[u8]) {
    kem_at(&w.chain, &a.id, v, kem_pk);
    w.net.answer(
        REGISTRY,
        "IUARegistry.checkedOf",
        json!({"ua": a.ua}),
        json!({"pop": "1", "pqzPop": "0", "kem": "1"}),
    );
    w.net.answer(
        REGISTRY,
        "IUARegistry.kemKeyOf",
        json!({"ua": a.ua}),
        json!({"version": v.to_string(), "kem": {"scheme": "1", "mlkemEk": "0x", "x25519": ZERO32}, "sig": "0x"}),
    );
}

pub fn kem(w: &World, a: &Acc, v: u64) {
    kem_with(w, a, v, &kem_pk(a, v));
}

/// `a` holds no usable KEM key (`checkedOf.kem` `NONE`).
pub fn no_kem(w: &World, a: &Acc) {
    w.net.answer(
        REGISTRY,
        "IUARegistry.checkedOf",
        json!({"ua": a.ua}),
        json!({"pop": "1", "pqzPop": "0", "kem": "0"}),
    );
}

/// `childOf(parent)` at `contract` answers `child` (zero: the slot free).
pub fn child(net: &FakeNet, contract: &str, parent: &str, child: &str) {
    net.answer(
        contract,
        "IPqChat.childOf",
        json!({ "parentEpochId": parent }),
        json!({ "0": child }),
    );
}
