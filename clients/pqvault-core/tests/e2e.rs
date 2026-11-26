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

#[path = "../../scaas-sdk/tests/common/prepared.rs"]
mod prepared;
use pqvault_core::records::*;
use pqvault_core::*;
use prepared::SignPrepared as _;
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
    anvil_on(31337).await
}

async fn anvil_on(chain_id: u64) -> (Anvil, String) {
    let want = chain_id.to_string();
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
                &want,
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
        if id.is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == want)
        {
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
    profile_of(&c.rpc, 31337, &c.registry, &c.factory)
}

fn profile_of(rpc: &str, chain_id: u64, registry: &str, factory: &str) -> ChainProfile {
    ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(chain_id),
        chain_uid: cast(&["block", "0", "--field", "hash", "--rpc-url", rpc]),
        rpc: vec![EndpointConfig {
            url: rpc.to_string(),
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(registry.to_string()),
        factory: Some(factory.to_string()),
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
        pinned_reads: true,
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
    device_with(&c.rpc, vec![profile(c)], words).await
}

async fn device_with(rpc: &str, profiles: Vec<ChainProfile>, words: &str) -> Device {
    let sdk = Sdk::open(SdkConfig {
        profiles,
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
        rpc,
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
    register_on(d, key, "anvil").await
}

async fn register_on(d: &Device, key: &KeyRef, chain: &str) {
    let acc = d.sdk.account();
    let writes = acc
        .prepare_register(Register {
            key: key.clone(),
            chain: chain.into(),
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
    async fn sign(
        &self,
        c: &str,
        a: &KeyRef,
        p: AppPath,
        t: String,
    ) -> Result<AppSigned, SdkError> {
        self.calls.lock().unwrap().push("sign".into());
        self.inner.sign(c, a, p, t).await
    }
    async fn verify(
        &self,
        c: &str,
        ua: B32,
        p: AppPath,
        t: String,
        s: UaSig,
    ) -> Result<Option<Vec<scaas_sdk::app_core::MsigVersion>>, SdkError> {
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
    // the exposure of a weaker rekey that links prev (passphrase off): every item and version it would open (built, not sent)
    let latest = pv.open_latest(&un).await.unwrap();
    let (_, _, x) = pv
        .rekey(
            &un,
            &un.state.newest().unwrap().members,
            &[un.state.me],
            Some(&Passphrase::Off),
            Link::Prev,
        )
        .await
        .unwrap();
    assert!(x.weaker);
    assert_eq!(x.items, latest.len() as u64);
    assert_eq!(
        x.versions,
        latest
            .iter()
            .map(|v| u64::from(v.version_count))
            .sum::<u64>()
    );
    assert!(
        x.versions > x.items,
        "an edited item counts all its versions"
    );
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
            "anvil",
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
    // handles wiped at lock (VC13): a key handle kept past the lock no longer works
    // (one handle given once per call: the SDK locks each handle it is given, so `same_key(k, k)` would wait on itself)
    let k = f.epoch_key(f.readable()[0]).unwrap();
    let use_it = |k: Arc<scaas_sdk::app_core::AppKey>| {
        pv.core.derive(
            vec![k],
            vec![],
            b"scaas/pqvault/v1/info".to_vec(),
            vec![],
            scaas_sdk::app_core::AppKeyUsage::Data,
            false,
        )
    };
    assert!(use_it(k.clone()).is_ok());
    pv.lock(f);
    assert!(use_it(k).is_err(), "wiped at lock");
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
            .is_ok_and(|v| v.is_some()),
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
        .sign("anvil", &key, AppPath::Portable, typed.clone())
        .await
        .unwrap();
    assert!(pv
        .net
        .verify("anvil", ua, AppPath::Portable, typed.clone(), sig(&ps))
        .await
        .unwrap()
        .is_some());
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

/// Owner 2026-11-22 (CLI-PQV-15 (1)): KEM key rotation and an `msig` admin with a native member, V10e's rows. B stores
/// KEM key version 1 through the SDK's `prepare_set_kem_key` (the registry's `setKemKey` check); A wraps the next epoch to it
/// (`member_key` reads `kemKeyOf`); B opens the old epoch by its version-0 key and the new one by version 1, and reads every
/// item. Then, in both modes, an `msig` M of A's UA and A's native EVM key (threshold 2, both slots accepted at registration)
/// is made an admin and authors a rekey through `sign_pqvault_record` (path A: the native member over the record itself;
/// path B: over `UAAuth` in the registry's domain); the vault verifies (spec §6.9: M's signature by its members) and opens.
/// The share box: the shared vault of exactly {A, B} found, none for another set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib"]
async fn kem_rotation_and_msig_admin() {
    use scaas_sdk::account::{msig_structure, MsigMemberArgs, MsigRegister};
    use scaas_sdk::op::MsigSlot;
    let c = chain().await;
    let at = instance(&c);
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
    let given = || Passphrase::Given(sec(PASS.as_bytes()));
    // KEM rotation
    let pa = PqVault::new(da.sdk.clone()).unwrap();
    let ua = pa.ua(&ka).unwrap();
    drop(pa);
    let pb = PqVault::new(db.sdk.clone()).unwrap();
    let ub = pb.ua(&kb).unwrap();
    drop(pb);
    let pa = PqVault::new(da.sdk.clone()).unwrap();
    let mb0 = pa.member_key(&at, ub).await.unwrap();
    assert_eq!(mb0.key_id.0, 0);
    let s = create(
        &pa,
        &da,
        &at,
        &ka,
        &[member(ua), mb0],
        Mode::Portable,
        &Passphrase::On(sec(PASS.as_bytes())),
        &info("rotation", true),
    )
    .await;
    let vid = s.vault_id;
    let u = pa.unlock(&ka, s, &given()).await.unwrap();
    assert_eq!(
        PqVault::share_box(&[&u], &[ub]),
        Some(vid),
        "the share box of A and B"
    );
    assert_eq!(
        PqVault::share_box(&[&u], &[ua]),
        None,
        "no box for another set"
    );
    let it = pa
        .create_item(&u, &login("before rotation", "r0"))
        .await
        .unwrap();
    send(
        &da,
        pa.prepare_item(&at, &it, da.payer.clone()).await.unwrap(),
    )
    .await;
    drop((u, pa));
    let w = db
        .sdk
        .account()
        .prepare_set_kem_key(kb.clone(), "anvil".into(), 1, db.payer.clone())
        .await
        .unwrap()
        .expect("version 1 not stored yet");
    let acc = db.sdk.account();
    let q = acc.quote_registry_write(w.clone()).await.unwrap();
    let op = acc.submit_registry_write(w, q).await.unwrap();
    assert!(matches!(follow(&db.sdk, op).await, OpState::Landed { .. }));
    assert!(
        acc.prepare_set_kem_key(kb.clone(), "anvil".into(), 1, db.payer.clone())
            .await
            .unwrap()
            .is_none(),
        "stored"
    );
    say("B's KEM key version 1 stored");
    let pa = PqVault::new(da.sdk.clone()).unwrap();
    let mb1 = pa.member_key(&at, ub).await.unwrap();
    assert_eq!(mb1.key_id.0, 1, "kemKeyOf follows the highest version");
    let u = pa
        .unlock(&ka, pa.load(&at, vid, ua).await.unwrap(), &given())
        .await
        .unwrap();
    let ma = u
        .state
        .newest()
        .unwrap()
        .members
        .iter()
        .find(|m| m.ua == ua)
        .unwrap()
        .clone();
    let (e, wraps, _) = pa
        .rekey(&u, &[ma, mb1], &[ua], None, Link::Prev)
        .await
        .unwrap();
    assert_eq!(wraps.iter().find(|w| w.member == ub).unwrap().key_id.0, 1);
    send(
        &da,
        pa.prepare_rekey(&at, &e, &wraps, da.payer.clone())
            .await
            .unwrap(),
    )
    .await;
    let u = pa
        .unlock(&ka, pa.load(&at, vid, ua).await.unwrap(), &given())
        .await
        .unwrap();
    let it = pa
        .create_item(&u, &login("after rotation", "r1"))
        .await
        .unwrap();
    send(
        &da,
        pa.prepare_item(&at, &it, da.payer.clone()).await.unwrap(),
    )
    .await;
    drop((u, pa));
    let pb = PqVault::new(db.sdk.clone()).unwrap();
    let mut sb = pb.load(&at, vid, ub).await.unwrap();
    sb.pending = false;
    let wb: Vec<u64> = sb
        .epochs
        .iter()
        .map(|e| e.own_wraps[0].1.key_id.0)
        .collect();
    assert_eq!(
        wb,
        vec![0, 1],
        "an old wrap under version 0, the new epoch under version 1"
    );
    let u = pb.unlock(&kb, sb, &given()).await.unwrap();
    assert_eq!(u.readable().len(), 2);
    assert_eq!(
        values(&pb.open_latest(&u).await.unwrap()),
        vec![
            login("after rotation", "r1"),
            login("before rotation", "r0")
        ]
    );
    drop((u, pb));
    say("KEM rotation: B reads both epochs");

    // the msig admin M = {A's UA, A's native EVM key}, threshold 2, both slots accepted at registration
    let native = KeyRef::Native {
        seed: da.seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let addr = da
        .sdk
        .account()
        .accounts(da.seed.clone())
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.shape == "native")
        .unwrap()
        .id_text
        .to_ascii_lowercase();
    let nid = format!("0x{}{}", "00".repeat(12), addr.trim_start_matches("0x"));
    let st = msig_structure(
        vec![
            MsigMemberArgs {
                kind: FNDSA512,
                id: hex(&ua.0),
                weight: 1,
            },
            MsigMemberArgs {
                kind: 1,
                id: nid.clone(),
                weight: 1,
            },
        ],
        2,
    )
    .unwrap();
    let m = B32(unhex(&st.ua().unwrap(), 32).unwrap().try_into().unwrap());
    let idx =
        |id: &str| u16::try_from(st.members.iter().position(|x| x.id == id).unwrap()).unwrap();
    let slots = vec![
        MsigSlot::Member {
            index: idx(&hex(&ua.0)),
            key: ka.clone(),
        },
        MsigSlot::Member {
            index: idx(&nid),
            key: native.clone(),
        },
    ];
    let mut slots = slots;
    slots.sort_by_key(|s| match s {
        MsigSlot::Member { index, .. } => *index,
        _ => 0,
    });
    let acc = da.sdk.account();
    for w in acc
        .prepare_msig_register(MsigRegister {
            chain: "anvil".into(),
            structure: st.clone(),
            slots: slots.clone(),
            payer: da.payer.clone(),
        })
        .await
        .unwrap()
    {
        let q = acc.quote_registry_write(w.clone()).await.unwrap();
        let op = acc.submit_registry_write(w, q).await.unwrap();
        assert!(matches!(follow(&da.sdk, op).await, OpState::Landed { .. }));
    }
    assert!(
        acc.msig_state("anvil".into(), hex(&m.0))
            .await
            .unwrap()
            .active,
        "both slots accepted"
    );
    say("msig admin registered");
    // CLI-PQV-15 controller call 3: a slot not accepted signs nothing on this path (`MsigSlotInactive`), beside its twins: the
    // accepted slot signs, and the same slot signs once it accepts
    {
        use scaas_sdk::account::AcceptMembership;
        let st2 = msig_structure(
            vec![
                MsigMemberArgs {
                    kind: FNDSA512,
                    id: hex(&ua.0),
                    weight: 1,
                },
                MsigMemberArgs {
                    kind: 1,
                    id: nid.clone(),
                    weight: 1,
                },
            ],
            1,
        )
        .unwrap();
        let m2 = st2.ua().unwrap();
        let i2 =
            |id: &str| u16::try_from(st2.members.iter().position(|x| x.id == id).unwrap()).unwrap();
        let slot_a = MsigSlot::Member {
            index: i2(&hex(&ua.0)),
            key: ka.clone(),
        };
        let slot_n = MsigSlot::Member {
            index: i2(&nid),
            key: native.clone(),
        };
        for w in acc
            .prepare_msig_register(MsigRegister {
                chain: "anvil".into(),
                structure: st2.clone(),
                slots: vec![],
                payer: da.payer.clone(),
            })
            .await
            .unwrap()
        {
            let q = acc.quote_registry_write(w.clone()).await.unwrap();
            let op = acc.submit_registry_write(w, q).await.unwrap();
            assert!(matches!(follow(&da.sdk, op).await, OpState::Landed { .. }));
        }
        // A's slot accepts; the native one does not yet
        let w = acc
            .prepare_accept_membership(AcceptMembership {
                chain: "anvil".into(),
                ua: m2.clone(),
                slot: slot_a.clone(),
                payer: da.payer.clone(),
            })
            .await
            .unwrap()
            .expect("not accepted yet");
        let q = acc.quote_registry_write(w.clone()).await.unwrap();
        let op = acc.submit_registry_write(w, q).await.unwrap();
        assert!(matches!(follow(&da.sdk, op).await, OpState::Landed { .. }));
        let pa = PqVault::new(da.sdk.clone()).unwrap();
        let item = ItemRecord {
            vault_id: B32([3; 32]),
            epoch_id: B32([3; 32]),
            author: B32(unhex(&m2, 32).unwrap().try_into().unwrap()),
            nonce: Num(9),
            ciphertext: Bytes(vec![5; 288]),
        };
        let t = typed_json(&item, Domain::Portable).unwrap();
        let by = |slot: MsigSlot| KeyRef::Msig {
            ua: m2.clone(),
            slots: vec![slot],
        };
        let e = pa
            .net
            .sign("anvil", &by(slot_n.clone()), AppPath::Portable, t.clone())
            .await
            .err();
        assert_eq!(
            e.map(|e| e.code()),
            Some("MsigSlotInactive"),
            "a slot not accepted"
        );
        assert!(
            pa.net
                .sign("anvil", &by(slot_a.clone()), AppPath::Portable, t.clone())
                .await
                .is_ok(),
            "the accepted slot"
        );
        let w = acc
            .prepare_accept_membership(AcceptMembership {
                chain: "anvil".into(),
                ua: m2.clone(),
                slot: slot_n.clone(),
                payer: da.payer.clone(),
            })
            .await
            .unwrap()
            .expect("not accepted yet");
        let q = acc.quote_registry_write(w.clone()).await.unwrap();
        let op = acc.submit_registry_write(w, q).await.unwrap();
        assert!(matches!(follow(&da.sdk, op).await, OpState::Landed { .. }));
        assert!(
            pa.net
                .sign("anvil", &by(slot_n), AppPath::Portable, t)
                .await
                .is_ok(),
            "the slot once accepted"
        );
        drop(pa);
        say("an msig slot not accepted signs nothing");
    }
    let pa = PqVault::new(da.sdk.clone()).unwrap();
    assert!(
        matches!(pa.member_key(&at, m).await, Err(Error::NotMember)),
        "an msig holds no KEM key"
    );
    drop(pa);
    let msig = KeyRef::Msig {
        ua: hex(&m.0),
        slots,
    };
    for mode in [Mode::Portable, Mode::ChainBound] {
        let pa = PqVault::new(da.sdk.clone()).unwrap();
        let s = create(
            &pa,
            &da,
            &at,
            &ka,
            &[member(ua)],
            mode,
            &Passphrase::Off,
            &info("msig", true),
        )
        .await;
        let vid = s.vault_id;
        let u = pa.unlock(&ka, s, &Passphrase::Off).await.unwrap();
        let it = pa
            .create_item(&u, &login("under epoch 0", "m0"))
            .await
            .unwrap();
        send(
            &da,
            pa.prepare_item(&at, &it, da.payer.clone()).await.unwrap(),
        )
        .await;
        let ms0 = u.state.newest().unwrap().members.clone();
        assert!(
            matches!(
                pa.rekey_by(&u, &msig, m, &ms0, &[ua], None, Link::Prev)
                    .await,
                Err(Error::NotAdmin)
            ),
            "M before it is an admin"
        );
        // A adds M as an admin
        let mut admins = vec![ua, m];
        admins.sort();
        let ms = u.state.newest().unwrap().members.clone();
        let (e, wraps, _) = pa.rekey(&u, &ms, &admins, None, Link::Prev).await.unwrap();
        send(
            &da,
            pa.prepare_rekey(&at, &e, &wraps, da.payer.clone())
                .await
                .unwrap(),
        )
        .await;
        let u = pa
            .unlock(&ka, pa.load(&at, vid, ua).await.unwrap(), &Passphrase::Off)
            .await
            .unwrap();
        // M authors the next epoch, signed by both its members
        let (e, wraps, _) = pa
            .rekey_by(&u, &msig, m, &ms, &admins, None, Link::Prev)
            .await
            .unwrap();
        assert_eq!(e.record.author, m);
        assert!(
            e.sig.key_data.is_empty() && e.sig.signature.is_empty() && e.sig.members.len() == 2
        );
        send(
            &da,
            pa.prepare_rekey(&at, &e, &wraps, da.payer.clone())
                .await
                .unwrap(),
        )
        .await;
        let s = pa.load(&at, vid, ua).await.unwrap();
        assert_eq!(
            s.newest().unwrap().author,
            m,
            "verified with M's signature by its members"
        );
        let u = pa.unlock(&ka, s, &Passphrase::Off).await.unwrap();
        assert_eq!(u.readable().len(), 3);
        assert_eq!(
            values(&pa.open_latest(&u).await.unwrap()),
            vec![login("under epoch 0", "m0")]
        );
        drop((u, pa));
        say(&format!("{mode:?}: the msig admin's epoch verified"));
    }
}

/// Generation 1's book and generation 2 over it (`script/DeployUAGen.s.sol`, as scaas-node's `ua_line_two_generations_on_anvil`):
/// `(book of generation 1, generation 2's registry)`; both books removed after reading.
fn deploy_line(rpc: &str, chain_id: u64) -> (Value, String) {
    let name = format!(
        "local-{chain_id}-{}-testnet",
        rpc.rsplit(':').next().unwrap()
    );
    let run = |script: &str, extra: &[(&str, String)]| {
        let status = Command::new("forge")
            .current_dir(sc())
            .args([
                "script",
                script,
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
            .env("MLDSA_PRECOMPILE", "off")
            .env("DEPLOY_NAME", &name)
            .envs(extra.iter().map(|(k, v)| (*k, v.as_str())))
            .status()
            .expect("forge in PATH");
        assert!(status.success(), "{script} failed");
    };
    run(
        "script/Deploy.s.sol",
        &[
            ("DEPLOY_PQVAULT", "true".into()),
            ("NOTICE_PERIOD", "0".into()),
        ],
    );
    let book = format!("{}/deployments/{name}.json", sc());
    let dep: Value = serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
    run(
        "script/DeployUAGen.s.sol",
        &[
            ("UA_GEN_BOOK", format!("deployments/{name}.json")),
            (
                "SMART_KEY_ACCOUNT_IMPL",
                dep["smart_key_account_implementation"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ),
        ],
    );
    let book2 = format!("{}/deployments/{name}-ua-gen2.json", sc());
    let g2: Value = serde_json::from_str(&std::fs::read_to_string(&book2).unwrap()).unwrap();
    let _ = std::fs::remove_file(&book);
    let _ = std::fs::remove_file(&book2);
    (
        dep,
        g2["ua_registry"].as_str().unwrap().to_ascii_lowercase(),
    )
}

/// Controller call 2026-11-22 (CLI-PQV-15, F2): PqVault's dedicated path on a registry line of two generations (chain 31930,
/// its own). The profile `g2` binds generation 2, `g1` generation 1, where the FN-DSA-512 UA and the `msig` M of it and a
/// native EVM key are registered (generation 2 holds neither). Through `g2`: M's chain-bound record is signed with its native
/// member over `UAAuth` in generation 1's domain (M's holder), generation 2's `requireAuthorized` forwards it there and
/// accepts it, and `verify_pqvault_record` agrees; the native key signing alone is generation 2's (its own check); the same
/// native signature made through `g1` (generation 1's domain) is refused by generation 2; M's portable record through
/// `requirePortableApp`; each beside a twin with one byte changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib"]
async fn pqvault_records_on_a_two_generation_line() {
    use scaas_sdk::account::{msig_structure, MsigMemberArgs, MsigRegister};
    use scaas_sdk::app_core::AppUaSig;
    use scaas_sdk::op::MsigSlot;
    const CHAIN: u64 = 31930;
    let (_a, rpc) = anvil_on(CHAIN).await;
    say("anvil up (31930); deploying generations 1 and 2");
    let (dep, gen2) = deploy_line(&rpc, CHAIN);
    let gen1 = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    let inst = dep["pqvault_instance"]
        .as_str()
        .unwrap()
        .to_ascii_lowercase();
    let factory = dep["token_factory"].as_str().unwrap().to_ascii_lowercase();
    assert_eq!(
        cast(&["call", "--rpc-url", &rpc, &gen2, "generation()(uint8)"]),
        "2"
    );
    say(&format!("generation 2 {gen2} over generation 1 {gen1}"));
    let mut p1 = profile_of(&rpc, CHAIN, &gen1, &factory);
    p1.key = "g1".into();
    let mut p2 = profile_of(&rpc, CHAIN, &gen2, &factory);
    p2.key = "g2".into();
    let d = device_with(&rpc, vec![p1, p2], REPO).await;
    let ka = KeyRef::Ua {
        seed: d.seed.clone(),
        kind: FNDSA512,
        account: 0,
        index: 0,
    };
    register_on(&d, &ka, "g1").await;
    let native = KeyRef::Native {
        seed: d.seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let core = PqVault::scope(&d.sdk).unwrap();
    let ua = B32(core.account_ua(&ka).unwrap());
    let addr = d
        .sdk
        .account()
        .accounts(d.seed.clone())
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.shape == "native")
        .unwrap()
        .id_text
        .to_ascii_lowercase();
    let nid = format!("0x{}{}", "00".repeat(12), addr.trim_start_matches("0x"));
    let st = msig_structure(
        vec![
            MsigMemberArgs {
                kind: FNDSA512,
                id: hex(&ua.0),
                weight: 1,
            },
            MsigMemberArgs {
                kind: 1,
                id: nid.clone(),
                weight: 1,
            },
        ],
        2,
    )
    .unwrap();
    let m = st.ua().unwrap();
    let idx =
        |id: &str| u16::try_from(st.members.iter().position(|x| x.id == id).unwrap()).unwrap();
    let mut slots = vec![
        MsigSlot::Member {
            index: idx(&hex(&ua.0)),
            key: ka.clone(),
        },
        MsigSlot::Member {
            index: idx(&nid),
            key: native.clone(),
        },
    ];
    slots.sort_by_key(|s| match s {
        MsigSlot::Member { index, .. } => *index,
        _ => 0,
    });
    let acc = d.sdk.account();
    for w in acc
        .prepare_msig_register(MsigRegister {
            chain: "g1".into(),
            structure: st.clone(),
            slots: slots.clone(),
            payer: d.payer.clone(),
        })
        .await
        .unwrap()
    {
        let q = acc.quote_registry_write(w.clone()).await.unwrap();
        let op = acc.submit_registry_write(w, q).await.unwrap();
        assert!(matches!(follow(&d.sdk, op).await, OpState::Landed { .. }));
    }
    let holder = cast(&[
        "call",
        "--rpc-url",
        &rpc,
        &gen2,
        "holderOf(bytes32)(address,uint16,address)",
        &m,
    ]);
    assert!(
        holder.to_ascii_lowercase().starts_with(&gen1),
        "generation 1 holds M: {holder}"
    );
    say("M registered on generation 1");

    let app_id = alloy::primitives::keccak256(APP_ID_STRING);
    let p_v = alloy::primitives::keccak256(
        [
            alloy::primitives::keccak256("scaas.ua.purpose.app.v1").0,
            app_id.0,
        ]
        .concat(),
    );
    let item = ItemRecord {
        vault_id: B32([4; 32]),
        epoch_id: B32([4; 32]),
        author: B32(unhex(&m, 32).unwrap().try_into().unwrap()),
        nonce: Num(1),
        ciphertext: Bytes(vec![6; 288]),
    };
    let instance = Addr(unhex(&inst, 20).unwrap().try_into().unwrap());
    let tb = typed_json(
        &item,
        Domain::ChainBound {
            chain_id: CHAIN,
            instance,
        },
    )
    .unwrap();
    let tv = typed_json(&item, Domain::Portable).unwrap();
    let uasig = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
    let lit = |s: &AppSigned| {
        let ms: Vec<String> = s
            .members
            .iter()
            .map(|x| {
                let inner: Vec<String> = x
                    .members
                    .iter()
                    .map(|i| format!("({},{})", i.index, hex(&i.sig)))
                    .collect();
                format!("({},[{}],{})", x.index, inner.join(","), hex(&x.sig))
            })
            .collect();
        format!(
            "({},{},[{}])",
            hex(&s.key_data),
            hex(&s.signature),
            ms.join(",")
        )
    };
    let accepts = |reg: &str, entry: &str, who: &str, tag: &str, s: &AppSigned| {
        Command::new("cast")
            .args([
                "call",
                "--rpc-url",
                &rpc,
                reg,
                &format!("{entry}(bytes32,bytes32,bytes32,{uasig})"),
                who,
                tag,
                &s.digest,
                &lit(s),
            ])
            .output()
            .unwrap()
            .status
            .success()
    };
    let twin = |s: &AppSigned| {
        let mut t = s.clone();
        match t.members.iter_mut().find(|x| !x.sig.is_empty()) {
            Some(x) => x.sig[3] ^= 1,
            None => t.signature[3] ^= 1,
        }
        t
    };
    let app_sig = |s: &AppSigned| AppUaSig {
        key_data: s.key_data.clone(),
        signature: s.signature.clone(),
        members: s.members.clone(),
    };
    let cb = |chain: &str| AppPath::ChainBound {
        chain: chain.into(),
        purpose: None,
    };
    let ms = KeyRef::Msig {
        ua: m.clone(),
        slots: slots.clone(),
    };
    // M, chain-bound through generation 2: its native member in generation 1's domain
    let sm = core
        .sign_pqvault_record(ms.clone(), cb("g2"), None, tb.clone())
        .await
        .unwrap();
    assert!(
        accepts(&gen2, "requireAuthorized", &m, &hex(&p_v.0), &sm),
        "generation 2 forwards M to generation 1"
    );
    assert!(
        !accepts(&gen2, "requireAuthorized", &m, &hex(&p_v.0), &twin(&sm)),
        "the twin"
    );
    assert!(core
        .verify_pqvault_record("g2".into(), m.clone(), cb("g2"), tb.clone(), app_sig(&sm))
        .await
        .unwrap());
    assert!(!core
        .verify_pqvault_record(
            "g2".into(),
            m.clone(),
            cb("g2"),
            tb.clone(),
            app_sig(&twin(&sm))
        )
        .await
        .unwrap());
    // the native key alone, chain-bound: generation 2's own domain; through g1 generation 1's, which generation 2 refuses
    let sn = core
        .sign_pqvault_record(native.clone(), cb("g2"), None, tb.clone())
        .await
        .unwrap();
    assert!(
        accepts(&gen2, "requireAuthorized", &nid, &hex(&p_v.0), &sn),
        "a native id in generation 2's domain"
    );
    assert!(core
        .verify_pqvault_record("g2".into(), nid.clone(), cb("g2"), tb.clone(), app_sig(&sn))
        .await
        .unwrap());
    let s1 = core
        .sign_pqvault_record(native.clone(), cb("g1"), None, tb.clone())
        .await
        .unwrap();
    assert_ne!(s1.signature, sn.signature);
    assert!(
        accepts(&gen1, "requireAuthorized", &nid, &hex(&p_v.0), &s1),
        "generation 1's own"
    );
    assert!(
        !accepts(&gen2, "requireAuthorized", &nid, &hex(&p_v.0), &s1),
        "generation 1's domain refused by generation 2"
    );
    // M's portable record, its records named on g2: requirePortableApp forwards it to the holder
    let sp = core
        .sign_pqvault_record(ms, AppPath::Portable, Some("g2".into()), tv.clone())
        .await
        .unwrap();
    assert!(accepts(
        &gen2,
        "requirePortableApp",
        &m,
        &hex(&app_id.0),
        &sp
    ));
    assert!(
        !accepts(&gen2, "requirePortableApp", &m, &hex(&app_id.0), &twin(&sp)),
        "the twin"
    );
    assert!(core
        .verify_pqvault_record("g2".into(), m.clone(), AppPath::Portable, tv, app_sig(&sp))
        .await
        .unwrap());
    say("generation 2's line: M by generation 1's domain, the native key by generation 2's");

    // F2's generic part (owner 2026-11-23, review T26): the generic record entries read the same line. A native key's generic
    // chain-bound record through g2 is generation 2's own (red before: the generic path's domain refused a generation 2,
    // `Argument`), accepted by generation 2's `requireAuthorized` and by `verify_app_record`, beside its twin.
    let note = json!({
        "types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
            "Note": [{"name": "id", "type": "bytes32"}, {"name": "body", "type": "string"}]},
        "primaryType": "Note",
        "domain": {"name": "E2E App", "version": "1", "chainId": CHAIN, "verifyingContract": format!("0x{}", "5a".repeat(20))},
        "message": {"id": format!("0x{}", "11".repeat(32)), "body": "on the line"},
    })
    .to_string();
    // a generic app's scope (PqVault's purpose is its dedicated path's only)
    let gen_app = format!("0x{}", "5a".repeat(32));
    let gc = scaas_sdk::app_core::AppCore::new(
        d.sdk.clone(),
        scaas_sdk::app_core::AppDesc {
            app_id: Some(gen_app.clone()),
            name: "E2E App".into(),
            class: None,
            labels: vec!["scaas/e2e-app/v1/".into()],
        },
    )
    .unwrap();
    let p_g = hex(&alloy::primitives::keccak256(
        [
            alloy::primitives::keccak256("scaas.ua.purpose.app.v1").0,
            [0x5a; 32],
        ]
        .concat(),
    )
    .0);
    let gn = gc
        .sign_app_record(native.clone(), cb("g2"), note.clone())
        .await
        .unwrap();
    assert!(
        accepts(&gen2, "requireAuthorized", &nid, &p_g, &gn),
        "a generic native record in generation 2's domain"
    );
    assert!(
        !accepts(&gen2, "requireAuthorized", &nid, &p_g, &twin(&gn)),
        "the twin"
    );
    assert!(gc
        .verify_app_record(
            "g2".into(),
            nid.clone(),
            cb("g2"),
            note.clone(),
            app_sig(&gn)
        )
        .await
        .unwrap());
    assert!(!gc
        .verify_app_record(
            "g2".into(),
            nid.clone(),
            cb("g2"),
            note,
            app_sig(&twin(&gn))
        )
        .await
        .unwrap());
    say("F2's generic part: a native record by generation 2's domain");

    // M's `updateMsig` with its native member, prepared through generation 2 (it binds and lands at generation 1, M's holder:
    // F2, (120)), signed by both slots of the stored structure. Threshold 2 -> 1 lets the native member authorize alone: M is
    // no longer PQ-eligible, which the chain refuses (UA-6 U3, `msigBound`'s `UAPqzHolder`), its reason kept (decision (161))
    // `pq`: the PQ member's weight (the native one weighs 1)
    let update = |pq: u16, threshold: u16| {
        let mut members = st.members.clone();
        for m in members.iter_mut().filter(|m| m.kind == FNDSA512) {
            m.weight = pq;
        }
        let structure = msig_structure(members, threshold).unwrap();
        let block: u64 = cast(&["block-number", "--rpc-url", &rpc]).parse().unwrap();
        acc.prepare_update_msig(scaas_sdk::account::UpdateMsig {
            chain: "g2".into(),
            ua: m.clone(),
            structure,
            enabled: vec![0, 1],
            valid_until_block: block + 100,
            slots: slots.clone(),
            payer: d.payer.clone(),
            verifier: false,
            family_without_update: false,
        })
    };
    let plan = update(1, 1).await.unwrap();
    let e = acc.quote_registry_write(plan.write).await.unwrap_err();
    assert!(
        format!("{e:?}").contains("UAPqzHolder") || format!("{e:?}").contains("5c98ad17"),
        "the chain's reason: {e:?}"
    );
    // the twin: the PQ member weighs 2, threshold 2: every quorum holds it, M stays PQ-eligible
    let plan = update(2, 2).await.unwrap();
    let q = acc.quote_registry_write(plan.write.clone()).await.unwrap();
    let op = acc.submit_registry_write(plan.write, q).await.unwrap();
    assert!(matches!(follow(&d.sdk, op).await, OpState::Landed { .. }));
    let st = acc.msig_state("g2".into(), m.clone()).await.unwrap();
    assert!(st.version == 1 && st.active, "{st:?}");
    say("M's updateMsig with its native member landed at generation 1");
}
