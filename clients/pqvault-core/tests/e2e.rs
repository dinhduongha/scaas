// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan V10e (and V10's chain rows): the real client on a local `anvil` (ignored by default: needs `anvil`, `forge`, `cast` and
//! `smartcontracts/evm/lib`; run by `runs/<date>-pqvault-e2e.sh`, capped, foreground). The contracts' own `script/Deploy.s.sol`
//! deploys the registry, the factory and a PqVault instance (`DEPLOY_PQVAULT`); every member's UA (FN-DSA-512, its KEM key
//! ML-KEM-1024 + X25519) is registered through the SDK; every record is built and signed by `pqvault-core` over the SDK,
//! prepared by the SDK's `prepare_app_call` and sent by `submit_native_send` (the seed's EVM key pays, fee 0); every read is
//! the SDK's `read_app`. No step calls `scaas-ua` or the contract directly except `cast` reads that compare raw state, and the
//! factory's second instance (a replica) made by the deployer. Local only; nothing leaves the machine.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_arguments
)]

use pqvault_core::records::*;
use pqvault_core::*;
use scaas_sdk::account::{AddNative, Register, RegisterAttrs};
use scaas_sdk::app_core::{AppCall, AppKey, AppPath, AppSigned, AppWrap, SecretBytes};
use scaas_sdk::op::{KeyRef, OpState};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, GasRows, Limits, RuntimeChoice, Sdk, SdkConfig,
    SdkError,
};
use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
/// records.json `pqvAccount`'s mnemonic (public test words): member B
const OTHER: &str = "math street property crazy mercy device click story exist velvet cute angle unusual satisfy limit copy resource media rough deal fragile panther acoustic agent";
const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const PASS: &str = "correct horse battery staple vault";

fn say(s: &str) {
    eprintln!("[pqvault-e2e] {s}");
}

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sc() -> String {
    format!("{}/../../smartcontracts/evm", env!("CARGO_MANIFEST_DIR"))
}

fn cast(args: &[&str]) -> String {
    let out = Command::new("cast")
        .args(args)
        .output()
        .expect("cast in PATH");
    assert!(
        out.status.success(),
        "cast {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

async fn anvil() -> (Anvil, String) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let rpc = format!("http://127.0.0.1:{port}");
    let mut a = Anvil(
        Command::new("anvil")
            .args([
                "--chain-id",
                "31337",
                "--hardfork",
                "amsterdam",
                "--gas-limit",
                "200000000",
                "--code-size-limit",
                "65536",
                "--port",
                &port.to_string(),
                "--silent",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("anvil in PATH"),
    );
    for _ in 0..100 {
        assert!(a.0.try_wait().unwrap().is_none(), "anvil exited");
        let id = Command::new("cast")
            .args(["chain-id", "--rpc-url", &rpc])
            .output();
        if id.is_ok_and(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "31337"
        }) {
            return (a, rpc);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("anvil never answered");
}

fn deploy(rpc: &str) -> Value {
    let name = format!("local-31337-{}-testnet", rpc.rsplit(':').next().unwrap());
    let status = Command::new("forge")
        .current_dir(sc())
        .args([
            "script",
            "script/Deploy.s.sol",
            "--rpc-url",
            rpc,
            "--broadcast",
            "--slow",
            "--silent",
            "--disable-code-size-limit",
            "--sender",
            DEPLOYER_ADDRESS,
        ])
        .env("PRIVATE_KEY", DEPLOYER)
        .env("FOUNDRY_PROFILE", "scaas-testnet")
        .env("TX_GAS_CAP", "16777216")
        .env("DEPLOY_NAME", &name)
        .env("DEPLOY_PQVAULT", "true")
        .env("NOTICE_PERIOD", "0")
        .status()
        .expect("forge in PATH");
    assert!(status.success(), "forge script failed");
    let book = format!("{}/deployments/{name}.json", sc());
    let dep = serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
    let _ = std::fs::remove_file(&book);
    dep
}

/// A second PqVault instance (a replica's host), made through the factory by the deployer.
fn second_instance(rpc: &str, factory: &str) -> String {
    let init = cast(&[
        "calldata",
        "initialize(bytes32)",
        &format!("0x{}", "00".repeat(32)),
    ]);
    let salt = format!("0x{}", "5b".repeat(32));
    let base = [
        "--rpc-url",
        rpc,
        factory,
        "createInstance((uint16,uint16,uint64),bytes32,bytes)",
        "(4,0,1)",
        &salt,
        &init,
    ];
    let out = cast(&[&["call", "--from", DEPLOYER_ADDRESS][..], &base[..]].concat());
    cast(&[&["send", "--private-key", DEPLOYER][..], &base[..]].concat());
    format!("0x{}", &out[out.len() - 40..]).to_ascii_lowercase()
}

struct Chain {
    _anvil: Anvil,
    rpc: String,
    registry: String,
    factory: String,
    instance: Addr,
}

async fn chain() -> Chain {
    let (a, rpc) = anvil().await;
    say("anvil up; deploying");
    let dep = deploy(&rpc);
    let s = |k: &str| dep[k].as_str().unwrap().to_ascii_lowercase();
    let inst = s("pqvault_instance");
    say(&format!("deployed: PqVault instance {inst}"));
    Chain {
        _anvil: a,
        registry: s("ua_registry"),
        factory: s("token_factory"),
        instance: Addr(unhex(&inst, 20).unwrap().try_into().unwrap()),
        rpc,
    }
}

fn profile(c: &Chain) -> ChainProfile {
    ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: cast(&["block", "0", "--field", "hash", "--rpc-url", &c.rpc]),
        rpc: vec![EndpointConfig {
            url: c.rpc.clone(),
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(c.registry.clone()),
        factory: Some(c.factory.clone()),
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: Some(1 << 24),
        tokens: vec![],
        gas: GasRows::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        l1_fee: None,
        disabled_kinds: vec![],
        family_params: None,
    }
}

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    let s = SecretBytes::new(b.len()).unwrap();
    s.with_mut(|m| m.copy_from_slice(b));
    Arc::new(s)
}

/// One device: an SDK over the chain with `words` imported, its EVM key 0 funded (the payer).
struct Device {
    sdk: Arc<Sdk>,
    seed: String,
    payer: KeyRef,
}

async fn device(c: &Chain, words: &str) -> Device {
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile(c)],
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
            words: sec(words.as_bytes()),
            vault_passphrase: sec("river-otter-7 ünï".as_bytes()),
        })
        .await
        .unwrap()
        .id;
    let row = sdk
        .account()
        .add_native(AddNative {
            seed: seed.clone(),
            network: "evm".into(),
            index: 0,
            name: "payer".into(),
        })
        .await
        .unwrap();
    cast(&[
        "rpc",
        "--rpc-url",
        &c.rpc,
        "anvil_setBalance",
        &row.id_text,
        "0x8ac7230489e80000",
    ]);
    Device {
        sdk,
        payer: KeyRef::Native {
            seed: seed.clone(),
            network: "evm".into(),
            index: 0,
        },
        seed,
    }
}

async fn follow(sdk: &Arc<Sdk>, op: String) -> OpState {
    for _ in 0..120 {
        let s = sdk.op().state(op.clone()).await.unwrap();
        if s.is_terminal() {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    sdk.op().state(op).await.unwrap()
}

/// `key`'s UA registered with its KEM key (version 0) through the SDK, each write followed to `Landed`.
async fn register(d: &Device, key: &KeyRef) {
    let acc = d.sdk.account();
    let writes = acc
        .prepare_register(Register {
            key: key.clone(),
            chain: "anvil".into(),
            attrs: RegisterAttrs {
                pqz_key: false,
                kem: true,
            },
            payer: d.payer.clone(),
        })
        .await
        .unwrap();
    for w in writes {
        let q = acc.quote_registry_write(w.clone()).await.unwrap();
        let op = acc.submit_registry_write(w.clone(), q).await.unwrap();
        let s = follow(&d.sdk, op).await;
        assert!(matches!(s, OpState::Landed { .. }), "{}: {s:?}", w.entry());
    }
}

/// A prepared call sent by the SDK and followed: `Landed`.
async fn send(d: &Device, call: AppCall) {
    let op = d.sdk.wallet().submit_native_send(call.quote).await.unwrap();
    let s = follow(&d.sdk, op).await;
    assert!(matches!(s, OpState::Landed { .. }), "{s:?}");
}

fn instance(c: &Chain) -> Instance {
    Instance {
        chain: "anvil".into(),
        chain_id: 31337,
        contract: c.instance,
    }
}

fn member(ua: B32) -> MemberKey {
    MemberKey {
        ua,
        key_id: Num(0),
        via: B32::default(),
    }
}

fn info(name: &str, shared: bool) -> VaultInfo {
    VaultInfo {
        name: name.into(),
        shared,
        icon: None,
        settings: None,
    }
}

fn login(title: &str, pw: &str) -> Value {
    json!({"type": "login", "title": title, "username": "u@example.org", "password": pw,
        "urls": [{"url": "https://example.org", "match": "host"}]})
}

fn values(v: &[ItemVersion]) -> Vec<Value> {
    let mut out: Vec<Value> = v
        .iter()
        .map(|x| x.value.as_ref().unwrap().clone())
        .collect();
    out.sort_by_key(|x| x["title"].as_str().unwrap_or_default().to_string());
    out
}

async fn create(
    pv: &PqVault,
    d: &Device,
    at: &Instance,
    key: &KeyRef,
    members: &[MemberKey],
    mode: Mode,
    pass: &Passphrase,
    i: &VaultInfo,
) -> VaultState {
    let (s, wraps) = pv
        .create_vault(key, i, members, at, mode, pass)
        .await
        .unwrap();
    send(
        d,
        pv.prepare_create(at, &s, &wraps, d.payer.clone())
            .await
            .unwrap(),
    )
    .await;
    let vid = vault_id(
        s.record.creator,
        s.record.nonce.0,
        mode_byte(mode),
        s.record.home_chain,
        s.record.home_vault_contract,
    );
    pv.load(at, vid, pv.ua(key).unwrap()).await.unwrap()
}

fn mode_byte(m: Mode) -> u8 {
    u8::from(m == Mode::ChainBound)
}

/// A seam over the SDK's that records every call and, when `lie` is set, flips a byte of every `epochOf` signature it
/// answers, when `lie_wrap` a byte of every `wrapAt` ML-KEM ciphertext (a lying node of the list).
struct Seam {
    inner: SdkNet,
    calls: Mutex<Vec<String>>,
    lie: Mutex<bool>,
    lie_wrap: Mutex<bool>,
    /// answer every `latestRange` item one version lower (a node rolling back)
    lie_count: Mutex<bool>,
}
#[async_trait::async_trait]
impl Net for Seam {
    async fn read(
        &self,
        chain: &str,
        contract: Addr,
        sig: &str,
        args: Value,
    ) -> Result<Value, SdkError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("read {}", sig.split('(').next().unwrap()));
        let mut v = self.inner.read(chain, contract, sig, args).await?;
        if *self.lie.lock().unwrap() && sig.starts_with("function epochOf") {
            let s = v["sig"]["signature"].as_str().unwrap().to_string();
            let flip = if s.ends_with('0') { '1' } else { '0' };
            v["sig"]["signature"] = json!(format!("{}{flip}", &s[..s.len() - 1]));
        }
        if *self.lie_count.lock().unwrap() && sig.starts_with("function latestRange") {
            for x in v["items"].as_array_mut().unwrap() {
                let n: u64 = x["versionCount"].as_str().unwrap().parse().unwrap();
                x["versionCount"] = json!(n.saturating_sub(1).to_string());
            }
        }
        if *self.lie_wrap.lock().unwrap() && sig.starts_with("function wrapAt") {
            let s = v["w"]["mlkemCt"].as_str().unwrap().to_string();
            let flip = if s.ends_with('0') { '1' } else { '0' };
            v["w"]["mlkemCt"] = json!(format!("{}{flip}", &s[..s.len() - 1]));
        }
        Ok(v)
    }
    async fn sign(&self, a: &KeyRef, p: AppPath, t: String) -> Result<AppSigned, SdkError> {
        self.calls.lock().unwrap().push("sign".into());
        self.inner.sign(a, p, t).await
    }
    async fn verify(
        &self,
        c: &str,
        ua: B32,
        p: AppPath,
        t: String,
        s: UaSig,
    ) -> Result<bool, SdkError> {
        self.calls.lock().unwrap().push("verify".into());
        self.inner.verify(c, ua, p, t, s).await
    }
    async fn kem_wrap(
        &self,
        c: &str,
        r: B32,
        v: u64,
        k: Arc<AppKey>,
        l: Vec<u8>,
        a: Vec<u8>,
    ) -> Result<AppWrap, SdkError> {
        self.calls.lock().unwrap().push("kem_wrap".into());
        self.inner.kem_wrap(c, r, v, k, l, a).await
    }
    async fn call(
        &self,
        c: &str,
        ct: Addr,
        s: &str,
        a: Value,
        p: KeyRef,
    ) -> Result<AppCall, SdkError> {
        self.calls.lock().unwrap().push("call".into());
        self.inner.call(c, ct, s, a, p).await
    }
}

fn seamed(d: &Device) -> (PqVault, Arc<Seam>) {
    let core = PqVault::scope(&d.sdk).unwrap();
    let seam = Arc::new(Seam {
        inner: SdkNet(core.clone()),
        calls: Mutex::new(vec![]),
        lie: Mutex::new(false),
        lie_wrap: Mutex::new(false),
        lie_count: Mutex::new(false),
    });
    (PqVault::with_net(d.sdk.clone(), core, seam.clone()), seam)
}

const LIMITS: ChainLimits = ChainLimits {
    max_gas: 12_000_000,
    base_gas: 400_000,
    item_gas: 150_000,
    byte_gas: 700,
};

/// Personal vaults (mode 0): the index vault and a personal vault under per-vault UAs, items, an edit, a version conflict
/// between two devices (one refused, the other merged as `n + 2`), a batch sized by the chain's limits; a second device with
/// only the seed and the passphrase recovers every item from state; a wrong passphrase is `PassphraseWrong` with no call
/// after the state was read; a passphrase change, then recovery with the new one only, the old one opening the history only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib"]
async fn personal_vault_recovery_conflict_passphrase() {
    let c = chain().await;
    let at = instance(&c);
    let d = device(&c, REPO).await;
    let (pv, seam) = seamed(&d);
    let (k0, k1) = (
        PqVault::vault_key(&d.seed, 0),
        PqVault::vault_key(&d.seed, 1),
    );
    register(&d, &k0).await;
    register(&d, &k1).await;
    say("per-vault UAs 0 and 1 registered");
    let main = KeyRef::Ua {
        seed: d.seed.clone(),
        kind: FNDSA512,
        account: 0,
        index: 0,
    };
    register(&d, &main).await;
    let pass = Passphrase::On(sec(PASS.as_bytes()));
    let idx = create(
        &pv,
        &d,
        &at,
        &k0,
        &[member(pv.ua(&k0).unwrap())],
        Mode::Portable,
        &Passphrase::Off,
        &info("index", false),
    )
    .await;
    let per = create(
        &pv,
        &d,
        &at,
        &k1,
        &[member(pv.ua(&k1).unwrap())],
        Mode::Portable,
        &pass,
        &info("personal", false),
    )
    .await;
    say("index and personal vaults created");
    let iu = pv.unlock(&k0, idx.clone(), &Passphrase::Off).await.unwrap();
    let r = pv.accept(&iu, &per, true, Some(1)).await.unwrap();
    send(&d, pv.prepare_item(&at, &r, d.payer.clone()).await.unwrap()).await;

    // items, an edit, a batch
    let u = pv
        .unlock(&k1, per.clone(), &Passphrase::Given(sec(PASS.as_bytes())))
        .await
        .unwrap();
    let it = pv.create_item(&u, &login("mail", "p1")).await.unwrap();
    send(
        &d,
        pv.prepare_item(&at, &it, d.payer.clone()).await.unwrap(),
    )
    .await;
    let latest = pv.open_latest(&u).await.unwrap();
    assert_eq!(values(&latest), vec![login("mail", "p1")]);
    let base = &latest[0];
    // two devices write n + 1 from the same base: the first lands, the second is refused (PqVaultVersion)
    let e1 = pv.edit_item(&u, base, &login("mail", "p2")).await.unwrap();
    let mut ours = login("mail", "p1");
    ours["notes"] = json!("from device 2");
    let e2 = pv.edit_item(&u, base, &ours).await.unwrap();
    send(
        &d,
        pv.prepare_edit(&at, &e1, d.payer.clone()).await.unwrap(),
    )
    .await;
    assert!(
        pv.prepare_edit(&at, &e2, d.payer.clone()).await.is_err(),
        "the second n + 1 is refused"
    );
    let (e3, m) = pv
        .resolve(&u, &login("mail", "p1"), &ours, base.item_id)
        .await
        .unwrap();
    assert_eq!(e3.record.version.0, 3);
    let Merge::Clean(merged) = m else {
        panic!("{m:?}")
    };
    assert_eq!(merged["password"], "p2");
    assert_eq!(merged["notes"], "from device 2");
    send(
        &d,
        pv.prepare_edit(&at, &e3, d.payer.clone()).await.unwrap(),
    )
    .await;
    say("conflict merged as version 3");
    let notes: Vec<Value> = (0..5)
        .map(|i| {
            json!({"type": "note", "title": format!("n{i}"), "mediaType": "text/plain",
        "body": "x".repeat(600)})
        })
        .collect();
    let small = ChainLimits {
        max_gas: 400_000 + 3 * 150_000 + 3 * 1100 * 700,
        ..LIMITS
    };
    let batches = pv.create_items(&u, &notes, &small).await.unwrap();
    assert!(batches.len() >= 2, "sized by the limits: {}", batches.len());
    assert_eq!(
        batches.iter().map(|b| b.record.items.len()).sum::<usize>(),
        5
    );
    for b in &batches {
        send(&d, pv.prepare_batch(&at, b, d.payer.clone()).await.unwrap()).await;
    }
    let all = pv.open_latest(&u).await.unwrap();
    assert_eq!(all.len(), 6);
    let want = values(&all);

    // a second device: the seed and the passphrase only
    let d2 = device(&c, REPO).await;
    drop((iu, u, pv, seam));
    let pv2 = PqVault::new(d2.sdk.clone()).unwrap();
    let main2 = KeyRef::Ua {
        seed: d2.seed.clone(),
        kind: FNDSA512,
        account: 0,
        index: 0,
    };
    let found = pv2.recover(&main2, &at).await.unwrap();
    let k1b = PqVault::vault_key(&d2.seed, 1);
    let per2 = found
        .iter()
        .find(|s| s.vault_id == per.vault_id)
        .expect("the personal vault from the index vault")
        .clone();
    assert!(!per2.pending);
    assert!(matches!(
        pv2.unlock(&k1b, per2.clone(), &Passphrase::Off).await,
        Err(Error::PassphraseRequired)
    ));
    assert!(matches!(
        pv2.unlock(
            &k1b,
            per2.clone(),
            &Passphrase::Given(sec(b"a wrong passphrase here"))
        )
        .await,
        Err(Error::PassphraseWrong)
    ));
    let u2 = pv2
        .unlock(&k1b, per2.clone(), &Passphrase::Given(sec(PASS.as_bytes())))
        .await
        .unwrap();
    assert_eq!(
        values(&pv2.open_latest(&u2).await.unwrap()),
        want,
        "every item from state alone, byte for byte"
    );
    say("recovered on a second device");

    // no-oracle: a wrong passphrase makes no call after the state was read
    drop(pv2);
    let (pv, seam2) = seamed(&d2);
    let s = pv
        .load(&at, per.vault_id, pv.ua(&k1b).unwrap())
        .await
        .unwrap();
    let n = seam2.calls.lock().unwrap().len();
    assert!(pv
        .unlock(
            &k1b,
            s.clone(),
            &Passphrase::Given(sec(b"a wrong passphrase here"))
        )
        .await
        .is_err());
    assert_eq!(
        seam2.calls.lock().unwrap().len(),
        n,
        "no call after a wrong passphrase"
    );

    // passphrase change (rekey with prev), recovery with the new passphrase only
    let u = pv
        .unlock(&k1b, s, &Passphrase::Given(sec(PASS.as_bytes())))
        .await
        .unwrap();
    pv.open_latest(&u).await.unwrap();
    const NEW: &str = "a new passphrase for the vault";
    let (e, wraps, x) = pv
        .rekey(
            &u,
            &u.state.newest().unwrap().members,
            &[u.state.me],
            Some(&Passphrase::On(sec(NEW.as_bytes()))),
            Link::Prev,
        )
        .await
        .unwrap();
    assert!(!x.weaker);
    send(
        &d2,
        pv.prepare_rekey(&at, &e, &wraps, d2.payer.clone())
            .await
            .unwrap(),
    )
    .await;
    let s = pv.load(&at, per.vault_id, u.state.me).await.unwrap();
    let un = pv
        .unlock(&k1b, s.clone(), &Passphrase::Given(sec(NEW.as_bytes())))
        .await
        .unwrap();
    assert_eq!(un.readable().len(), 2, "the old epoch through prev");
    assert_eq!(values(&pv.open_latest(&un).await.unwrap()), want);
    // an item under the new epoch beside those under the old: each opens under its own epoch's key only
    let it = pv
        .create_item(&un, &login("after the change", "c1"))
        .await
        .unwrap();
    assert_ne!(it.record.epoch_id, per.vault_id);
    send(
        &d2,
        pv.prepare_item(&at, &it, d2.payer.clone()).await.unwrap(),
    )
    .await;
    let mut want = want;
    want.push(login("after the change", "c1"));
    want.sort_by_key(|x| x["title"].as_str().unwrap_or_default().to_string());
    assert_eq!(values(&pv.open_latest(&un).await.unwrap()), want);
    let old = pv
        .unlock(&k1b, s.clone(), &Passphrase::Given(sec(PASS.as_bytes())))
        .await
        .unwrap();
    assert_eq!(
        old.unopenable.map(|x| x.0),
        Some(1),
        "the old passphrase: the new epoch cannot be opened"
    );
    assert!(matches!(
        pv.create_item(&old, &login("x", "y")).await,
        Err(Error::EpochUnopenable { epoch: 1, .. })
    ));
    // passphrase off then on again without prev: a fresh epoch without history
    let (e, wraps, x) = pv
        .rekey(
            &un,
            &un.state.newest().unwrap().members,
            &[un.state.me],
            Some(&Passphrase::Off),
            Link::None,
        )
        .await
        .unwrap();
    assert!(x.weaker);
    send(
        &d2,
        pv.prepare_rekey(&at, &e, &wraps, d2.payer.clone())
            .await
            .unwrap(),
    )
    .await;
    let s = pv.load(&at, per.vault_id, un.state.me).await.unwrap();
    let off = pv.unlock(&k1b, s, &Passphrase::Off).await.unwrap();
    assert_eq!(
        off.readable().len(),
        1,
        "no prev: the older epochs need their passphrase"
    );
    let lat = pv.open_latest(&off).await.unwrap();
    assert!(lat
        .iter()
        .all(|x| matches!(x.value, Err(Error::Unreadable))));
    say("passphrase change, off without prev: ok");

    // a malicious admin's epoch whose prev carries another key than its parent's: the walk stops there and says so
    let s = pv.load(&at, per.vault_id, off.state.me).await.unwrap();
    let parent = s.newest().unwrap().clone();
    let core = pv.core.clone();
    let vid = s.vault_id;
    let nonce = 77u64;
    let eid = epoch_id(vid, parent.author, nonce);
    let ke = core
        .random_key(&d2.seed, scaas_sdk::app_core::AppKeyUsage::Derive)
        .unwrap();
    let w = keys::wrap_to(&*pv.net, "anvil", ke.clone(), vid, eid, parent.author, 0)
        .await
        .unwrap();
    let kv = keys::vault_key(&core, ke, None, vid, eid, 0).unwrap();
    let wrong = core
        .random_key(&d2.seed, scaas_sdk::app_core::AppKeyUsage::Derive)
        .unwrap();
    let wire = keys::seal_prev(&core, &kv, vid, eid, parent.id, wrong).unwrap();
    let mut inf = off.infos.get(&parent.id).unwrap().clone();
    inf["prev"] = json!({"epochId": parent.id, "keyWrap": hex(&wire)});
    let rec = VaultEpoch {
        vault_id: vid,
        author: parent.author,
        nonce: Num(nonce),
        epoch: Num(parent.number + 1),
        parent_epoch_id: parent.id,
        admins: parent.admins.clone(),
        members: parent.members.clone(),
        wrap_hashes: vec![wrap_hash(&w)],
        pass_kdf: Num(0),
        pass_salt: B32::default(),
        sealed_info: Bytes(keys::seal_info(&core, &kv, vid, eid, &inf).unwrap()),
    };
    let sg = pv
        .net
        .sign(
            &k1b,
            AppPath::Portable,
            typed_json(&rec, Domain::Portable).unwrap(),
        )
        .await
        .unwrap();
    let signed = Signed {
        record: rec,
        sig: UaSig {
            key_data: sg.key_data,
            signature: sg.signature,
            members: vec![],
        },
    };
    send(
        &d2,
        pv.prepare_rekey(&at, &signed, &[w], d2.payer.clone())
            .await
            .unwrap(),
    )
    .await;
    let s = pv.load(&at, per.vault_id, off.state.me).await.unwrap();
    let f = pv.unlock(&k1b, s, &Passphrase::Off).await.unwrap();
    assert_eq!(
        f.wrong_history.map(|x| x.0),
        Some(parent.number + 1),
        "the wrong history key is named"
    );
    // the forged epoch and, by the user's own wrap, its parent (no passphrase): the parent's key is its own, not prev's
    assert_eq!(f.readable().len(), 2);
    assert_eq!(f.infos.get(&parent.id), off.infos.get(&parent.id));
    say("a wrong prev key named: ok");
}

/// Shared vaults in both modes: A and B (own seeds) read each other's items; a lying node's epoch is `ChainUnverified`; after
/// B's removal and a rekey without B, B reads what it read before and nothing written after; the affected list is the items
/// whose latest version B could read. Mode 0 with a replica instance (its bytes checked against the home, a divergent version
/// found); mode 1 refused at another instance than its home.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib"]
async fn shared_vault_both_modes() {
    let c = chain().await;
    let at = instance(&c);
    let replica = Instance {
        contract: Addr(
            unhex(&second_instance(&c.rpc, &c.factory), 20)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        ..at.clone()
    };
    let (da, db) = (device(&c, REPO).await, device(&c, OTHER).await);
    let ka = KeyRef::Ua {
        seed: da.seed.clone(),
        kind: FNDSA512,
        account: 0,
        index: 0,
    };
    let kb = KeyRef::Ua {
        seed: db.seed.clone(),
        kind: FNDSA512,
        account: 0,
        index: 0,
    };
    register(&da, &ka).await;
    register(&db, &kb).await;
    say("A and B registered");
    // one PqVault scope per process at a time (spec §12.3): each device's phase opens its own and drops it
    for mode in [Mode::Portable, Mode::ChainBound] {
        let given = || Passphrase::Given(sec(PASS.as_bytes()));
        let both = vec![login("by A", "a1"), login("by B", "b1")];
        // A: the vault and A's item
        let (pa, seam) = seamed(&da);
        let ua = pa.ua(&ka).unwrap();
        drop((pa, seam));
        let pb = PqVault::new(db.sdk.clone()).unwrap();
        let ub = pb.ua(&kb).unwrap();
        drop(pb);
        let (pa, seam) = seamed(&da);
        let s = create(
            &pa,
            &da,
            &at,
            &ka,
            &[member(ua), member(ub)],
            mode,
            &Passphrase::On(sec(PASS.as_bytes())),
            &info("shared", true),
        )
        .await;
        let vid = s.vault_id;
        let u = pa.unlock(&ka, s, &given()).await.unwrap();
        let it = pa.create_item(&u, &login("by A", "a1")).await.unwrap();
        send(
            &da,
            pa.prepare_item(&at, &it, da.payer.clone()).await.unwrap(),
        )
        .await;
        drop((u, pa, seam));
        // B: pending until accepted; then reads A's item and writes its own
        let pb = PqVault::new(db.sdk.clone()).unwrap();
        let found = pb.recover(&kb, &at).await.unwrap();
        let mut sb = found.iter().find(|x| x.vault_id == vid).unwrap().clone();
        assert!(sb.pending, "a vault B did not create is pending");
        assert!(matches!(
            pb.unlock(&kb, sb.clone(), &given()).await,
            Err(Error::Pending)
        ));
        sb.pending = false; // the user accepted it (the vaultRef itself is the personal test's)
        let u = pb.unlock(&kb, sb, &given()).await.unwrap();
        let it = pb.create_item(&u, &login("by B", "b1")).await.unwrap();
        send(
            &db,
            pb.prepare_item(&at, &it, db.payer.clone()).await.unwrap(),
        )
        .await;
        assert_eq!(values(&pb.open_latest(&u).await.unwrap()), both);
        drop((u, pb));
        // A: reads B's item; a lying node; removes B and rekeys without it
        let (pa, seam) = seamed(&da);
        let u = pa
            .unlock(&ka, pa.load(&at, vid, ua).await.unwrap(), &given())
            .await
            .unwrap();
        assert_eq!(values(&pa.open_latest(&u).await.unwrap()), both);
        say(&format!("{mode:?}: A and B read each other's items"));
        let (e, wraps, _) = pa
            .rekey(
                &u,
                &u.state.newest().unwrap().members,
                &[ua],
                None,
                Link::Prev,
            )
            .await
            .unwrap();
        send(
            &da,
            pa.prepare_rekey(&at, &e, &wraps, da.payer.clone())
                .await
                .unwrap(),
        )
        .await;
        *seam.lie.lock().unwrap() = true;
        assert!(
            matches!(pa.load(&at, vid, ua).await, Err(Error::ChainUnverified)),
            "a forged epoch signature"
        );
        *seam.lie.lock().unwrap() = false;
        *seam.lie_wrap.lock().unwrap() = true;
        assert!(
            matches!(pa.load(&at, vid, ua).await, Err(Error::ChainUnverified)),
            "a wrap other than the signed hash"
        );
        *seam.lie_wrap.lock().unwrap() = false;
        let u = pa
            .unlock(&ka, pa.load(&at, vid, ua).await.unwrap(), &given())
            .await
            .unwrap();
        pa.open_latest(&u).await.unwrap();
        let (r, affected) = pa.remove(&u, &[ub]).await.unwrap();
        assert_eq!(
            affected.len(),
            2,
            "both items' latest versions were readable by B"
        );
        send(
            &da,
            pa.prepare_remove(&at, &r, da.payer.clone()).await.unwrap(),
        )
        .await;
        let u = pa
            .unlock(&ka, pa.load(&at, vid, ua).await.unwrap(), &given())
            .await
            .unwrap();
        let (e, wraps, _) = pa
            .rekey(&u, &[member(ua)], &[ua], None, Link::Prev)
            .await
            .unwrap();
        send(
            &da,
            pa.prepare_rekey(&at, &e, &wraps, da.payer.clone())
                .await
                .unwrap(),
        )
        .await;
        let home = pa.load(&at, vid, ua).await.unwrap();
        let u = pa.unlock(&ka, home.clone(), &given()).await.unwrap();
        let it = pa
            .create_item(&u, &login("after B left", "z"))
            .await
            .unwrap();
        send(
            &da,
            pa.prepare_item(&at, &it, da.payer.clone()).await.unwrap(),
        )
        .await;
        match mode {
            Mode::Portable => {
                // the replica: the same signed create record and wraps at the second instance
                let mut wraps = vec![];
                for i in 0..home.create.members.len() {
                    let r = pa
                        .net
                        .read(&at.chain, at.contract, "function wrapAt(bytes32 epochId,uint256 i) view returns ((bytes32 member,\
                            uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey) w)", json!({"epochId": vid, "i": i.to_string()}))
                        .await
                        .unwrap();
                    wraps.push(serde_json::from_value::<Wrap>(r["w"].clone()).unwrap());
                }
                let signed = Signed {
                    record: home.create.clone(),
                    sig: home.epochs[0].sig.clone(),
                };
                send(
                    &da,
                    pa.prepare_create(&replica, &signed, &wraps, da.payer.clone())
                        .await
                        .unwrap(),
                )
                .await;
                assert!(
                    pa.replica_agrees(&home, &replica).await.unwrap(),
                    "the replica's bytes are the home's"
                );
                let s0 = pa
                    .verify(pa.fetch(&replica, vid, ua).await.unwrap())
                    .await
                    .unwrap();
                let u0 = pa.unlock(&ka, s0, &given()).await.unwrap();
                let only = pa
                    .create_item(&u0, &login("replica only", "r"))
                    .await
                    .unwrap();
                send(
                    &da,
                    pa.prepare_item(&replica, &only, da.payer.clone())
                        .await
                        .unwrap(),
                )
                .await;
                assert!(
                    !pa.replica_agrees(&home, &replica).await.unwrap(),
                    "a divergent replica is found"
                );
            }
            Mode::ChainBound => {
                let mut s = pa.fetch(&at, vid, ua).await.unwrap();
                s.at.contract = replica.contract;
                assert!(
                    matches!(pa.verify(s).await, Err(Error::ChainUnverified)),
                    "another instance than the home"
                );
                assert!(pa
                    .verify(pa.fetch(&at, vid, ua).await.unwrap())
                    .await
                    .is_ok());
            }
        }
        drop((u, pa, seam));
        // B: reads what it read before, nothing written after its removal
        let (pb, seam) = seamed(&db);
        let mut sb = pb.load(&at, vid, ub).await.unwrap();
        sb.pending = false;
        let u = pb.unlock(&kb, sb, &given()).await.unwrap();
        assert!(u.unopenable.is_some(), "B has no wrap of the new epoch");
        let n = seam.calls.lock().unwrap().len();
        let seen = pb.open_latest(&u).await.unwrap();
        assert_eq!(
            seam.calls.lock().unwrap()[n..],
            [
                "read function itemCount".to_string(),
                "read function latestRange".to_string()
            ],
            "an unreadable version changes nothing read or sent"
        );
        assert_eq!(
            seen.iter().filter(|x| x.value.is_ok()).count(),
            2,
            "B still reads what it could read"
        );
        assert_eq!(
            seen.iter().filter(|x| x.value.is_err()).count(),
            1,
            "and nothing written after its removal"
        );
        // a node answering lower version counts than seen: refused
        *seam.lie_count.lock().unwrap() = true;
        assert!(matches!(pb.open_latest(&u).await, Err(Error::Rollback)));
        *seam.lie_count.lock().unwrap() = false;
        assert!(pb.open_latest(&u).await.is_ok());
        drop((u, pb, seam));
        say(&format!(
            "{mode:?}: removal, rekey, replica / home checks ok"
        ));
    }
}

/// A second app core over the same SDK (its own `appId` and labels): its record is refused by PqVault's verification, PqVault's
/// record by its own, a label of PqVault's refused to it, and the generic signing call refuses a PqVault record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib"]
async fn a_second_app_core_is_kept_apart() {
    use scaas_sdk::app_core::{AppCore, AppDesc, AppKeyUsage, AppUaSig};
    let c = chain().await;
    let d = device(&c, REPO).await;
    let key = KeyRef::Ua {
        seed: d.seed.clone(),
        kind: FNDSA512,
        account: 0,
        index: 0,
    };
    register(&d, &key).await;
    let pv = PqVault::new(d.sdk.clone()).unwrap();
    const TOY: &str = "0x7070707070707070707070707070707070707070707070707070707070707070";
    let toy = AppCore::new(
        d.sdk.clone(),
        AppDesc {
            app_id: Some(TOY.into()),
            name: "Toy".into(),
            class: None,
            labels: vec!["scaas/toy/v1/".into()],
        },
    )
    .unwrap();
    let toy_rec = json!({"types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
        {"name": "salt", "type": "bytes32"}], "Note": [{"name": "body", "type": "string"}]}, "primaryType": "Note",
        "domain": {"name": "Toy", "version": "1", "salt": TOY}, "message": {"body": "hi"}}).to_string();
    let ts = toy
        .sign_app_record(key.clone(), AppPath::Portable, toy_rec.clone())
        .await
        .unwrap();
    let ua = pv.ua(&key).unwrap();
    let sig = |s: &AppSigned| AppUaSig {
        key_data: s.key_data.clone(),
        signature: s.signature.clone(),
        members: vec![],
    };
    assert!(toy
        .verify_app_record(
            "anvil".into(),
            hex(&ua.0),
            AppPath::Portable,
            toy_rec.clone(),
            sig(&ts)
        )
        .await
        .unwrap());
    assert!(
        !pv.net
            .verify("anvil", ua, AppPath::Portable, toy_rec, sig(&ts))
            .await
            .unwrap_or(false),
        "PqVault refuses the toy's record"
    );
    let item = ItemRecord {
        vault_id: B32([1; 32]),
        epoch_id: B32([1; 32]),
        author: ua,
        nonce: Num(1),
        ciphertext: Bytes(vec![7; 288]),
    };
    let typed = typed_json(&item, Domain::Portable).unwrap();
    let ps = pv
        .net
        .sign(&key, AppPath::Portable, typed.clone())
        .await
        .unwrap();
    assert!(pv
        .net
        .verify("anvil", ua, AppPath::Portable, typed.clone(), sig(&ps))
        .await
        .unwrap());
    assert!(!toy
        .verify_app_record(
            "anvil".into(),
            hex(&ua.0),
            AppPath::Portable,
            typed.clone(),
            sig(&ps)
        )
        .await
        .unwrap_or(false));
    assert!(
        toy.sign_app_record(key.clone(), AppPath::Portable, typed)
            .await
            .is_err(),
        "the generic call refuses PqVault's record"
    );
    let k = toy.random_key(&d.seed, AppKeyUsage::Derive).unwrap();
    assert_eq!(
        toy.derive(
            vec![k],
            vec![],
            b"scaas/pqvault/v1/item".to_vec(),
            vec![],
            AppKeyUsage::Data,
            true
        )
        .err()
        .map(|e| e.code()),
        Some("AppLabelRefused")
    );
}
