// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Fable C-2: the service against a real `OFFCHAIN` token on anvil. Opt-in, like the node's e2e:
//!
//! `cargo test --offline --locked -j2 --test anvil -- --ignored --nocapture`
//!
//! Needs `anvil` and `forge` in `PATH` and `smartcontracts/evm/lib` installed (`scripts/evm_libs.sh install`). The base stack
//! by the repo's deploy script (`script/Deploy.s.sol`, which builds `out/`); the PQZ release (kind 4, `deps = [0]`: no PQZ
//! precompile on anvil) with its libraries and body modules on that factory; a token naming the service's key as its
//! transferable verifier; two `fndsa512` holders with PQZ keys of this set and stored proof bytes. pqz-ffi is faked (`…01`
//! for every input): no prover here and no `R_REG` proof of these keys; `tests/service.rs` runs it real on the vector rows.
//! What this run shows: the views, argument tuples (`ownTag`), registry reads and the locally built `UAAuth` digest of the
//! service are the contracts', and the token accepts the verdict on chain (`PqzVerified` over exactly the statement and
//! proof). It also checks every selector of `abi.rs` against the built ABI. UNAUDITED.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolCall, SolError, SolEvent, SolValue};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use serde_json::{json, Value};
use tower::ServiceExt;

use scaas_pqz_verifier::abi::{self, IPqzToken, IUARegistry, KemKey};
use scaas_pqz_verifier::{check_pins, chain::Rpc, http, pqz_key_hash, Config, Pqz, Service, PROBE_STATEMENT, VALID};

const CHAIN_ID: u64 = 31961;
/// anvil's first test account (its well-known key): the deployer, owner and the transfer's sender.
const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const UA_FNDSA512: u16 = 0x0132;
const TAG: B256 = B256::repeat_byte(0x7a);

mod t {
    alloy::sol! {
        #[derive(Default)]
        struct Roles { bytes32 minter; bytes32 rateAdmin; bytes32 guardian; bytes32 issuer; bytes32 compliance; }
        #[derive(Default)]
        struct Leg { address underlying; uint256 num; uint256 den; }
        #[derive(Default)]
        struct RateConfig { uint32 rateDelay; uint16 maxRateStepBps; }
        #[derive(Default)]
        struct ConfidentialConfig { bytes auditorKey; uint256 shieldScale; uint256 maxShielded; uint256 confidentialFee;
            uint8 disclosureMode; uint8 auditorMode; uint256 minDecoyFee; uint8 pqzVerifyMode; bytes32 pqzVerifierUA;
            bool pqzVerifierFixed; uint8 proofStore; uint64 verifierFee; uint64 verifierFeeMax; }
        #[derive(Default)]
        struct RegulatedParams { address complianceRegistry; uint64 requiredFlags; uint64 deniedFlags; bytes32 termsHash;
            bytes32 taxRecipient; }
        #[derive(Default)]
        struct TokenConfig { string name; string symbol; uint8 decimals; uint256 features; uint256 lockedFeatures; bytes32 owner;
            Roles roles; uint256 initialSupply; address initialHolder; Leg[] legs; RateConfig rate; ConfidentialConfig conf;
            uint64 grantDelay; address rescueTo; uint256 maxSupply; RegulatedParams reg; }
        struct FactoryEnv { address registry; address smartKeyAccountImpl; bool hedera; address[] deps; bytes32[] params;
            address[] libs; bytes32[] libCodeHashes; }
        struct ImplArgs { address[] modules; }
        function tokenEnvOf(uint8 kind, uint16 envVersion) external view returns (FactoryEnv);
        function publishTokenEnv(uint8 kind, uint16 envVersion, bytes32 chainUid, FactoryEnv env) external;
        function deployTokenImplementation(uint8 kind, uint64 version, uint16 envVersion, bytes initcode, bytes implArgs,
            bytes32 chainUid) external returns (address);
        function createToken(uint8 kind, uint64 version, bytes initArgs, bytes32 salt) external returns (address);
        function setTokenKindEnabled(uint8 kind, bool on, bytes32 chainUid) external;
        function latestTokenEnvVersion(uint8 kind) external view returns (uint16);
        function latestVersion(uint8 kind) external view returns (uint64);

        struct KemKeyT { uint8 scheme; bytes mlkemEk; bytes32 x25519; }
        function register(uint16 kind, bytes keyData, UAAttrsT attrs, bytes pop, bytes pqzPop) external returns (bytes32 ua);
        struct UAAttrsT { bytes pqzKey; bytes32 pqzPopHash; KemKeyT kem; bytes32 kemPkHash; }
        function uaOf(uint16 kind, bytes keyData) external pure returns (bytes32);
        function keyHashOf(uint16 kind, bytes keyData) external pure returns (bytes32);
        function registrationDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash, bytes32 pqzPopHash)
            external pure returns (bytes32);
        function generation() external view returns (uint8);

        struct PqzTransferArgs { uint64 p; uint256 validUntilBlock; uint256 shieldIn; bytes32 fromUA; uint64 keyVersion;
            bytes32 toUA; bytes32 beneficiaryUA; bytes16 salt; bytes32 ownTag; bytes u; bytes vTo; bytes vFrom; bytes vAuditor;
            bytes sealedMemo; }
        struct InnerSig { uint16 index; bytes sig; }
        struct MemberSig { uint16 index; InnerSig[] members; bytes sig; }
        struct UASig { bytes keyData; bytes signature; MemberSig[] members; }
        struct PqzVerdict { address token; uint256 chainId; bytes32 proofSystemId; bytes32 statementHash; bytes32 proofHash;
            uint32 pqzVerifierEpoch; uint64 validUntil; }
        struct PqzSignedVerdict { PqzVerdict pqzVerdict; UASig sig; }
        function mtxConfidentialTransferSingle(PqzTransferArgs t, bytes proof, UASig pqzAuth, bytes accHint,
            PqzSignedVerdict pqzVerdict) external returns (bytes32 entryRef);
        event PqzVerified(bytes32 statementHash, bytes32 proofHash, bytes32 verifier, uint32 pqzVerifierEpoch);
        error PqzVerdictMismatch(uint8 field);
    }
}

struct Anvil(Child);

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sc() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm")
}

fn read_json(p: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap()
}

fn deployer() -> PrivateKeySigner {
    DEPLOYER.parse().unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

async fn start_anvil() -> (Anvil, String) {
    let child = Command::new("anvil")
        .args(["--chain-id", &CHAIN_ID.to_string(), "--hardfork", "amsterdam", "--gas-limit", "200000000",
            "--code-size-limit", "65536", "--port", &CHAIN_ID.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("anvil in PATH");
    let rpc = format!("http://127.0.0.1:{CHAIN_ID}");
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_chain_id().await.is_ok() {
            break;
        }
    }
    (Anvil(child), rpc)
}

async fn view<C: SolCall>(rpc: &str, to: Address, c: C) -> C::Return {
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    C::abi_decode_returns(&p.call(TransactionRequest::default().to(to).input(c.abi_encode().into())).await.unwrap()).unwrap()
}

async fn send(rpc: &str, to: Address, data: Vec<u8>) -> alloy::rpc::types::TransactionReceipt {
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(deployer())).connect_http(rpc.parse().unwrap());
    let r = p.send_transaction(TransactionRequest::default().to(to).input(data.into())).await.unwrap().get_receipt().await.unwrap();
    assert!(r.status(), "reverted: {r:?}");
    r
}

/// `eth_call` then send: the return value of a state-changing call.
async fn create(rpc: &str, to: Address, data: Vec<u8>) -> Address {
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let out = p.call(TransactionRequest::default().from(deployer().address()).to(to).input(data.clone().into())).await.unwrap();
    send(rpc, to, data).await;
    Address::abi_decode(&out).unwrap()
}

async fn deploy_code(rpc: &str, code: Vec<u8>) -> Address {
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(deployer())).connect_http(rpc.parse().unwrap());
    let r = p.send_transaction(TransactionRequest::default().with_deploy_code(code)).await.unwrap().get_receipt().await.unwrap();
    assert!(r.status(), "CREATE reverted");
    r.contract_address.unwrap()
}

/// The repo's deploy script on the anvil (the node e2e's way): its book `deployments/local-<id>-testnet.json`.
fn deploy(rpc: &str) -> Value {
    let name = format!("local-{CHAIN_ID}-testnet");
    let status = Command::new("forge")
        .current_dir(sc())
        .args(["script", "script/Deploy.s.sol", "--rpc-url", rpc, "--broadcast", "--slow", "--silent", "--disable-code-size-limit",
            "--sender", DEPLOYER_ADDRESS])
        .env("PRIVATE_KEY", DEPLOYER)
        .env("DEMO_SUPPLY", "1000000000000")
        .env("DEMO_HOLDER", DEPLOYER_ADDRESS)
        .env("FOUNDRY_PROFILE", "scaas-testnet")
        .env("DEPLOY_NAME", &name)
        .status()
        .expect("forge in PATH");
    assert!(status.success(), "forge script failed");
    read_json(&format!("{}/deployments/{name}.json", sc()))
}

/// The init code of `out/<file>/<name>.json`, every library linked (the deploy's or `extra`'s), with the transitive library
/// closure, leaf first (the node e2e's `linked_closure_in`).
fn linked(file: &str, name: &str, extra: &BTreeMap<String, Address>) -> (Vec<u8>, Vec<Address>) {
    let run = read_json(&format!("{}/broadcast/Deploy.s.sol/{CHAIN_ID}/run-latest.json", sc()));
    let mut libs: BTreeMap<String, Address> = run["libraries"].as_array().unwrap().iter().map(|l| {
        let (path, addr) = l.as_str().unwrap().rsplit_once(':').unwrap();
        (path.to_string(), addr.parse().unwrap())
    }).collect();
    libs.extend(extra.iter().map(|(k, v)| (k.clone(), *v)));
    fn walk(file: &str, name: &str, libs: &BTreeMap<String, Address>, out: &mut Vec<Address>) -> Vec<u8> {
        let art = read_json(&format!("{}/out/{file}/{name}.json", sc()));
        let mut code = art["bytecode"]["object"].as_str().unwrap().trim_start_matches("0x").to_string();
        for (path, by) in art["bytecode"]["linkReferences"].as_object().unwrap() {
            for (lib, at) in by.as_object().unwrap() {
                let a = *libs.get(&format!("{path}:{lib}")).unwrap_or_else(|| panic!("{path}:{lib} not deployed"));
                walk(path.rsplit('/').next().unwrap(), lib, libs, out);
                if !out.contains(&a) {
                    out.push(a);
                }
                for o in at.as_array().unwrap() {
                    let i = 2 * o["start"].as_u64().unwrap() as usize;
                    code.replace_range(i..i + 40, &alloy::hex::encode(a));
                }
            }
        }
        alloy::hex::decode(code).unwrap()
    }
    let mut closure = Vec::new();
    let code = walk(file, name, &libs, &mut closure);
    (code, closure)
}

/// Kind 4's body modules as `(artifact file, contract)` (`script/KindModules.sol`, what DeployBase reads).
fn kind_modules(kind: u8) -> Vec<(String, String)> {
    let src = std::fs::read_to_string(format!("{}/script/KindModules.sol", sc())).unwrap();
    let at = src.find(&format!("if (kind == {kind}) {{")).unwrap_or_else(|| panic!("kind {kind} in KindModules.sol"));
    let body = &src[at..at + src[at..].find("return n;").unwrap()];
    body.split('"').skip(1).step_by(2).map(|q| {
        let (f, n) = q.split_once(':').unwrap();
        (f.to_string(), n.to_string())
    }).collect()
}

/// A `fndsa512` UA (pure Solidity Falcon, no precompile) registered with PQZ key `pqz_key` and stored proof bytes `pop`
/// (unchecked: anvil's registry has no `pqz-mlwe` verifier).
struct Holder {
    ua: B256,
    sk: pqcrypto_falcon::falconpadded512::SecretKey,
}

impl Holder {
    async fn register(rpc: &str, registry: Address, pqz_key: Vec<u8>, pop: Vec<u8>) -> Self {
        use pqcrypto_falcon::falconpadded512 as falcon;
        use pqcrypto_traits::sign::PublicKey as _;
        let (pk, sk) = falcon::keypair();
        let pk = pk.as_bytes().to_vec();
        let ua = view(rpc, registry, t::uaOfCall { kind: UA_FNDSA512, keyData: pk.clone().into() }).await;
        let no_kem = t::KemKeyT { scheme: 0, mlkemEk: Bytes::new(), x25519: B256::ZERO };
        let krh = view(rpc, registry, IUARegistry::kemRecordHashCall { ua, version: 0,
            kem: KemKey { scheme: 0, mlkemEk: Bytes::new(), x25519: B256::ZERO } }).await;
        let kh = view(rpc, registry, t::keyHashOfCall { kind: 0x0142, keyData: pqz_key.clone().into() }).await;
        assert_eq!(pqz_key_hash(&pqz_key), kh, "the service's keyHashOf(pqz-mlwe, key) is the registry's");
        let ph = keccak256(&pop);
        let rd = view(rpc, registry, t::registrationDigestCall { ua, kind: UA_FNDSA512, pqzKeyHash: kh, kemRecordHash: krh,
            pqzPopHash: ph }).await;
        let me = Self { ua, sk };
        let sig = me.sign(rpc, registry, b"scaas.ua.purpose.pop.v2", rd).await;
        send(rpc, registry, t::registerCall { kind: UA_FNDSA512, keyData: pk.into(),
            attrs: t::UAAttrsT { pqzKey: pqz_key.into(), pqzPopHash: ph, kem: no_kem, kemPkHash: B256::ZERO }, pop: sig.into(),
            pqzPop: pop.into() }.abi_encode()).await;
        me
    }

    /// The Falcon signature over the registry's `uaMessage(fndsa512, purpose, digest)`.
    async fn sign(&self, rpc: &str, registry: Address, purpose: &[u8], digest: B256) -> Vec<u8> {
        use pqcrypto_falcon::falconpadded512 as falcon;
        use pqcrypto_traits::sign::DetachedSignature as _;
        let m = view(rpc, registry, IUARegistry::uaMessageCall { kind: UA_FNDSA512, purposeTag: keccak256(purpose), digest }).await;
        falcon::detached_sign(m.as_slice(), &self.sk).as_bytes().to_vec()
    }
}

/// The typed `PqzAuth` digest of a debit statement (`PqzCore.authDigest`; the node e2e's `pqz_auth_digest`).
fn pqz_auth_digest(op: u8, stmt: &[u8]) -> B256 {
    const T: &[u8] = b"PqzAuth(uint8 op,bytes32 opTag,bytes32 psid,uint256 chainId,address token,address registry,bytes32 from,\
bytes32 to,bytes32 beneficiary,uint256 fee,uint256 amount,bytes32 recipient,uint64 sendCounter,uint64 p,uint256 validUntilBlock,\
bool auditorOn,uint256 shieldIn,bytes32 chainUid,bytes32 binding,uint128 salt,bytes32 memoHash,bytes32 bodyHash)";
    let d = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    let domain = keccak256([&d[..], &keccak256(b"SCaaS PqzToken")[..], &keccak256(b"1")[..], &stmt[64..96], &stmt[96..128],
        &stmt[512..544]].concat());
    let mut o = [0u8; 32];
    o[31] = op;
    let h = keccak256([&keccak256(T)[..], &o[..], &stmt[..640], &keccak256(&stmt[640..])[..]].concat());
    keccak256([&[0x19, 0x01][..], &domain[..], &h[..]].concat())
}

/// Every selector of the interfaces in `abi.rs` is in the built ABI of the contract it reads (`out/<C>.sol/<C>.json`,
/// `methodIdentifiers`): the two PQZ faces (kind 4 and kind 5, whose `unshieldUnwrapStatement` is its own), the registry.
fn selectors_in_built_abi() {
    for (names, ours) in [(&["NormalPqzToken", "WrappedPqzToken"][..], IPqzToken::IPqzTokenCalls::SELECTORS),
        (&["UARegistry"][..], IUARegistry::IUARegistryCalls::SELECTORS)]
    {
        let arts: Vec<Value> = names.iter().map(|n| read_json(&format!("{}/out/{n}.sol/{n}.json", sc()))).collect();
        let built: Vec<&str> = arts.iter().flat_map(|a| a["methodIdentifiers"].as_object().unwrap().values())
            .map(|v| v.as_str().unwrap()).collect();
        let name = names.join(" + ");
        for s in ours {
            assert!(built.contains(&alloy::hex::encode(s).as_str()), "{name}: selector {} not in the built ABI", alloy::hex::encode(s));
        }
    }
}

async fn post(app: &axum::Router, path: &str, body: String) -> (u16, Value) {
    let req = Request::post(path).header("content-type", "application/json")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9)))).body(Body::from(body)).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status().as_u16();
    let b = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

#[tokio::test]
#[ignore]
async fn verdict_lands_on_anvil() {
    let (_anvil, rpc) = start_anvil().await;
    let dep = deploy(&rpc);
    selectors_in_built_abi();
    let at = |k: &str| -> Address { dep[k].as_str().unwrap_or_else(|| panic!("{k}")).parse().unwrap() };
    let (factory, registry) = (at("token_factory"), at("ua_registry"));
    // the PQZ release on deps = [0]: its four libraries, the face, the kind's body modules
    let mut extra = BTreeMap::new();
    for lib in ["PqzBurnLib", "PqzStateLib", "PqzTransferLib", "PqzViewLib"] {
        let (code, _) = linked(&format!("{lib}.sol"), lib, &BTreeMap::new());
        extra.insert(format!("src/pqz/{lib}.sol:{lib}"), deploy_code(&rpc, code).await);
    }
    let (code, mut libs) = linked("NormalPqzToken.sol", "NormalPqzToken", &extra);
    let mut modules = Vec::new();
    for (file, name) in kind_modules(4) {
        let (mut m, closure) = linked(&file, &name, &extra);
        m.extend((factory, Bytes::new()).abi_encode_params());
        modules.push(deploy_code(&rpc, m).await);
        libs.extend(closure.into_iter().filter(|l| !libs.contains(l)).collect::<Vec<_>>());
    }
    libs.extend(modules.iter().copied());
    let pr = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let mut hashes = Vec::new();
    for l in &libs {
        hashes.push(keccak256(pr.get_code_at(*l).await.unwrap()));
    }
    let mut env = view(&rpc, factory, t::tokenEnvOfCall { kind: 0, envVersion: 1 }).await;
    (env.deps, env.libs, env.libCodeHashes) = (vec![Address::ZERO], libs, hashes);
    let ev = view(&rpc, factory, t::latestTokenEnvVersionCall { kind: 4 }).await + 1;
    let genesis = pr.get_block_by_number(0.into()).await.unwrap().unwrap().header.hash; // the factory's chainUid
    send(&rpc, factory, t::publishTokenEnvCall { kind: 4, envVersion: ev, chainUid: genesis, env }.abi_encode()).await;
    let ver = view(&rpc, factory, t::latestVersionCall { kind: 4 }).await + 1;
    send(&rpc, factory, t::deployTokenImplementationCall { kind: 4, version: ver, envVersion: ev, initcode: code.into(),
        implArgs: t::ImplArgs { modules }.abi_encode().into(), chainUid: genesis }.abi_encode()).await;
    send(&rpc, factory, t::setTokenKindEnabledCall { kind: 4, on: true, chainUid: genesis }.abi_encode()).await;

    // the service: its own key, the chain pinned (an operator reads chainUid and the registry's generation once)
    let signer = PrivateKeySigner::random();
    let uid = pr.get_block_by_number(0.into()).await.unwrap().unwrap().header.hash;
    let generation = view(&rpc, registry, t::generationCall {}).await;
    let release = view(&rpc, factory, IFactory::implementationOfCall { kind: 4, version: ver }).await;
    let cfg = Config::parse(&format!(r#"
bind = "127.0.0.1:0"
rpc_urls = ["{rpc}"]
chain_id = {CHAIN_ID}
chain_uid = "{uid}"
registry = "{registry}"
registry_generation = {generation}
keystore = "unused-in-this-test.json"
keystore_password_env = "UNUSED_IN_THIS_TEST"
valid_minutes = 5
concurrency = 2
queue = 8
rate_per_minute = 1000
[releases]
"{release}" = "{set}"
"#, set = pqz_ffi::stmt::SET)).unwrap();
    // no prover and no R_REG proof of these keys here: pqz-ffi answers …01 (tests/service.rs runs it real)
    let pqz: Pqz = Arc::new(|_: &[u8]| Ok(VALID));
    let rpc_nodes = Rpc::connect(&cfg.rpc_urls, CHAIN_ID).await.unwrap();
    check_pins(&rpc_nodes, &cfg).await.expect("the registry's generation() and chainUid() are the pinned ones (Fable R-4)");
    let svc = Arc::new(Service::new(Arc::new(rpc_nodes), pqz, signer.clone(), &cfg));
    let app = http::router(svc.clone(), &cfg);

    // the OFFCHAIN token naming the service's UA
    let c = t::TokenConfig { name: "SCaaS PQZ OFFCHAIN".into(), symbol: "pqOFF".into(), decimals: 6, features: U256::from(1u8),
        owner: deployer().address().into_word(), initialSupply: U256::from(1_000_000u64), initialHolder: deployer().address(),
        conf: t::ConfidentialConfig { shieldScale: U256::from(1u8), maxShielded: U256::from(1u64 << 40), pqzVerifyMode: 1,
            pqzVerifierUA: svc.ua(), ..Default::default() }, ..Default::default() };
    let token = create(&rpc, factory, t::createTokenCall { kind: 4, version: ver, initArgs: c.abi_encode().into(),
        salt: B256::repeat_byte(0x3f) }.abi_encode()).await;
    let probe = json!({"token": token, "chainId": CHAIN_ID}).to_string();
    let r = post(&app, "/v1/pqz-verdict/probe", probe).await;
    assert_eq!(r.0, 200, "probe: {}", r.1);
    assert_eq!(r.1["pqzVerdict"]["statementHash"], json!(keccak256(PROBE_STATEMENT)));

    // the holders: real PQZ keys of this set (portable.json), proof bytes stored unchecked
    let p = read_json(&format!("{}/../vectors/ua/portable.json", sc()));
    let row = |tb: &str, n: &str| p[tb].as_array().unwrap().iter().find(|r| r["name"] == n).unwrap_or_else(|| panic!("{tb} {n}")).clone();
    let hexb = |v: &Value| alloy::hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
    let set = pqz_ffi::stmt::SET;
    let pop = hexb(&row("registrations", &format!("mldsa65/{set}"))["pqzPop"]);
    let from = Holder::register(&rpc, registry, hexb(&row("pqzKeyRecords", &format!("fndsa512/{set}"))["pqzKey"]), pop.clone()).await;
    let to = Holder::register(&rpc, registry, hexb(&row("pqzKeyRecords", &format!("mldsa87/{set}"))["pqzKey"]), pop).await;

    // op 1 from `from` to `to`, a direct call (binding 0) with ownTag; the statement from the token's own view
    let block = pr.get_block_number().await.unwrap();
    let lanes = |n: usize| -> Bytes { (0..n / 8).flat_map(|_| [0, 0, 0, 0, 0, 0, 0, 1u8]).collect::<Vec<u8>>().into() };
    let (pk, v) = (pqz_ffi::stmt::PK_BYTES, pqz_ffi::stmt::V_BYTES);
    let args = t::PqzTransferArgs { p: 0, validUntilBlock: U256::from(block + 200), shieldIn: U256::ZERO, fromUA: from.ua,
        keyVersion: 0, toUA: to.ua, beneficiaryUA: B256::ZERO, salt: FixedBytes([0x5a; 16]), ownTag: TAG, u: lanes(pk),
        vTo: lanes(v), vFrom: lanes(v), vAuditor: Bytes::new(), sealedMemo: Bytes::new() };
    // the service's own argument tuple (abi.rs) asks the token's view
    let ours = abi::PqzTransferArgs { p: 0, validUntilBlock: args.validUntilBlock, shieldIn: U256::ZERO, fromUA: from.ua,
        keyVersion: 0, toUA: to.ua, beneficiaryUA: B256::ZERO, salt: args.salt, ownTag: TAG, u: args.u.clone(),
        vTo: args.vTo.clone(), vFrom: args.vFrom.clone(), vAuditor: Bytes::new(), sealedMemo: Bytes::new() };
    let stmt = view(&rpc, token, IPqzToken::transferSingleStatementCall { t: ours, binding: B256::ZERO }).await.to_vec();
    let epoch = view(&rpc, token, IPqzToken::pqzVerifyConfigCall {}).await.pqzVerifierEpoch;
    let proof = vec![0x9f; 96];
    let req = json!({"token": token, "chainId": CHAIN_ID, "pqzVerifierEpoch": epoch,
        "statement": format!("0x{}", alloy::hex::encode(&stmt)), "proof": format!("0x{}", alloy::hex::encode(&proof)),
        "op": {"entry": "mtxConfidentialTransferSingle", "args": {"p": 0, "validUntilBlock": args.validUntilBlock, "shieldIn": "0",
            "fromUA": from.ua, "keyVersion": 0, "toUA": to.ua, "beneficiaryUA": B256::ZERO, "salt": args.salt, "ownTag": TAG,
            "u": args.u, "vTo": args.vTo, "vFrom": args.vFrom, "vAuditor": "0x", "sealedMemo": "0x"}}});
    let (status, signed) = post(&app, "/v1/pqz-verdict", req.to_string()).await;
    assert_eq!(status, 200, "verdict: {signed}");
    let pv = &signed["pqzVerdict"];
    let verdict = t::PqzSignedVerdict {
        pqzVerdict: t::PqzVerdict { token, chainId: U256::from(CHAIN_ID), proofSystemId: pv["proofSystemId"].as_str().unwrap().parse().unwrap(),
            statementHash: keccak256(&stmt), proofHash: keccak256(&proof), pqzVerifierEpoch: epoch,
            validUntil: pv["validUntil"].as_u64().unwrap() },
        sig: t::UASig { keyData: Bytes::new(), signature: alloy::hex::decode(signed["pqzVerdictSig"]["signature"].as_str().unwrap())
            .unwrap().into(), members: vec![] } };
    assert!(verdict.pqzVerdict.validUntil > now());
    let auth = t::UASig { keyData: Bytes::new(), members: vec![],
        signature: from.sign(&rpc, registry, b"scaas.ua.purpose.zether-auth.v1", pqz_auth_digest(1, &stmt)).await.into() };
    // the probe's verdict (signed, this verifier, this token's epoch) on the same debit: the token's _check refuses it at
    // statementHash, PqzVerdictMismatch(3); the probe signs a statement no token builds
    let probe_verdict = t::PqzSignedVerdict {
        pqzVerdict: t::PqzVerdict { statementHash: keccak256(PROBE_STATEMENT), proofHash: keccak256(b""),
            validUntil: r.1["pqzVerdict"]["validUntil"].as_u64().unwrap(), ..verdict.pqzVerdict.clone() },
        sig: t::UASig { keyData: Bytes::new(), members: vec![],
            signature: alloy::hex::decode(r.1["pqzVerdictSig"]["signature"].as_str().unwrap()).unwrap().into() } };
    let with_probe = t::mtxConfidentialTransferSingleCall { t: args.clone(), proof: proof.clone().into(), pqzAuth: auth.clone(),
        accHint: Bytes::new(), pqzVerdict: probe_verdict }.abi_encode();
    let e = pr.call(TransactionRequest::default().from(deployer().address()).to(token).input(with_probe.into())).await
        .expect_err("a probe verdict on a real debit");
    assert_eq!(e.as_error_resp().and_then(|p| p.as_revert_data()), Some(t::PqzVerdictMismatch { field: 3 }.abi_encode().into()),
        "the probe verdict refused at statementHash: {e}");
    let rc = send(&rpc, token, t::mtxConfidentialTransferSingleCall { t: args, proof: proof.clone().into(), pqzAuth: auth,
        accHint: Bytes::new(), pqzVerdict: verdict }.abi_encode()).await;
    let ev = rc.inner.logs().iter().find_map(|l| t::PqzVerified::decode_log_data(l.data()).ok())
        .expect("a PqzVerified log: the token accepted the service's verdict");
    assert_eq!((ev.statementHash, ev.proofHash, ev.verifier, ev.pqzVerifierEpoch),
        (keccak256(&stmt), keccak256(&proof), svc.ua(), epoch), "the verdict landed on chain");
}

alloy::sol! {
    interface IFactory {
        function implementationOf(uint8 kind, uint64 version) external view returns (address);
    }
}
