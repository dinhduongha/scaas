// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T48 (3f spec §11.2, §15's Service row): the service through its HTTP door against a fake chain that answers fixed
//! views, with pqz-ffi real (the set's vector rows: real statements, real proofs, the real `R_REG` row) or faked where
//! a negative path must not depend on the proof. Positive control first, then one change at a time.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};

use alloy::primitives::hex;
use alloy::primitives::{address, b256, keccak256, Address, Bytes, Signature, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::{Eip712Domain, SolCall, SolStruct, SolValue};
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use pqz_ffi::stmt;
use serde_json::{json, Value};
use tower::ServiceExt;

use scaas_pqz_verifier::abi::{IPqzToken as T, IUARegistry as R, KemKey, PqzVerdict, PqzVerifyConfig, UAAttrs};
use scaas_pqz_verifier::chain::{Block, Chain, ChainError, Rpc};
use scaas_pqz_verifier::{
    body_limit, check_pins, http, pqz_key_hash, purpose_pqz_verdict, registry_domain, statement_lengths, verdict_auth_digest,
    verdict_digest, Config, Pqz, ProbeRequest, Service, PROBE_STATEMENT, VALID,
};

alloy::sol! {
    /// The registry's view the service used to sign before Fable C-1; the fake answers it with a forged hash.
    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) external view returns (bytes32);
}

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/vectors/pqz/");
const TOKEN: Address = address!("7A7a7A7a7a7a7a7A7a7a7a7A7a7a7A7A7A7a7A7a");
const REGISTRY: Address = address!("5CA5000000000000000000000000000000000001");
/// A registry of the attacker's (Fable C-1): it answers every view as the real one, and a forged `uaAuthDigest`.
const ROGUE: Address = address!("BADBAD0000000000000000000000000000000001");
/// What a lying RPC or a rogue registry answers for `uaAuthDigest`.
const FORGED: B256 = B256::repeat_byte(0x66);
const RELEASE: Address = address!("5CA5000000000000000000000000000000000002");
const CHAIN_ID: u64 = 7622;
const CHAIN_UID: B256 = b256!("24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464");
/// The fixed test scalar of `verdict.json`'s writer (`PqzVerdictVectors.t.sol`, `VKEY = 0xA77E57`): a vector key.
const TEST_KEY: B256 = b256!("0000000000000000000000000000000000000000000000000000000000a77e57");
const PK: usize = stmt::PK_BYTES;
const A: B256 = B256::repeat_byte(0xa1);
const B: B256 = B256::repeat_byte(0xb2);
const C: B256 = B256::repeat_byte(0xc3);
const D: B256 = B256::repeat_byte(0xd4);
const AUD: B256 = B256::repeat_byte(0xad);
const EPOCH: u32 = 3;
/// A debit's `ownTag` (group 3h): a named field of every debit's args.
const TAG: B256 = B256::repeat_byte(0x7a);
const CONFIG: &str = r#"
bind = "127.0.0.1:0"
rpc_urls = ["http://127.0.0.1:1"]
chain_id = 7622
chain_uid = "0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464"
registry = "0x5CA5000000000000000000000000000000000001"
registry_generation = 1
keystore = "unused-in-tests.json"
keystore_password_env = "UNUSED_IN_TESTS"
valid_minutes = 5
concurrency = 2
queue = 8
rate_per_minute = 1000
[releases]
"0x5CA5000000000000000000000000000000000002" = "n2304-kmax4096"
"#;

// ------------------------------------------------------------------ vectors

fn json_file(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(format!("{DIR}{path}")).unwrap()).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn word(v: &Value) -> B256 {
    v.as_str().unwrap().parse().unwrap()
}

fn uint(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

/// `(statement, proof)` of `proof_pqzl.json`'s row `form` (op 7: `case`), the statement from its file under the PQZL id.
fn vector(form: &str, case: Option<&str>) -> (Vec<u8>, Vec<u8>) {
    static PROOFS: OnceLock<Value> = OnceLock::new();
    let p = PROOFS.get_or_init(|| json_file("n2304-kmax4096/proof_pqzl.json"));
    let row = p["rows"].as_array().unwrap().iter()
        .find(|r| r["form"] == form && case.is_none_or(|c| r["statement"]["case"] == c)).unwrap();
    let f = json_file(&format!("n2304-kmax4096/{}", row["statement"]["file"].as_str().unwrap()));
    let s = f["rows"].as_array().unwrap().iter().find(|s| s["form"] == form && case.is_none_or(|c| s["case"] == c)).unwrap();
    let st = bytes(&s["stmt"]);
    assert_eq!(hex::encode(keccak256(&st)), row["stmt_keccak"].as_str().unwrap(), "the PQZL-id statement of {form}");
    (st, bytes(&row["proof"]))
}

// ------------------------------------------------------------------ the fake chain

#[derive(Clone, Default)]
struct Key {
    pk: Vec<u8>,
    pop: Vec<u8>,
    pop_hash: B256,
    sig: Vec<u8>,
}

fn key(pk: &[u8], pop: &[u8]) -> Key {
    Key { pk: pk.to_vec(), pop: pop.to_vec(), pop_hash: keccak256(pop), sig: vec![] }
}

#[derive(Default)]
struct World {
    release: Address,
    /// the registry and `chainUid` the token's code names
    named: (Address, B256),
    /// what the registry answers for `generation()` and `chainUid()`
    pins: (u8, B256),
    mode: u8,
    verifier: B256,
    epoch: u32,
    auditor: B256,
    /// what every statement view of the token answers
    statement: Vec<u8>,
    keys: HashMap<(B256, u64), Key>,
    current: HashMap<B256, u64>,
    owner: HashMap<B256, B256>,
    /// `uaMessage(0x0142, purpose, digest)` answers set by a test (the real `R_REG` row's message)
    message: HashMap<(B256, B256), B256>,
    /// what `pqzEntryBlob` answers
    blob: Vec<u8>,
    /// the token's key class (CTR-PQZ-37): `pqzOwnKey`, `pqzOpening`; its `proofSystemId()` (zero: `PQZL_ID`)
    own: bool,
    opening: bool,
    psid: B256,
    /// how many nodes the chain has (at least one); node `n` is at block `100 + n`
    nodes: usize,
    /// node → how many reads it answers before it stops answering (0: down, its head too)
    down: HashMap<usize, usize>,
    /// every read as `(node, block)`, in order
    seen: Vec<(usize, u64)>,
    /// plan T9: a read by number alone refused (the strict-majority path reads by hash only)
    by_hash: bool,
    /// node → the UA its registry answers as every key's `keyOwner` (a node lying on a key record)
    lie: HashMap<usize, B256>,
    /// how many reads had been made when the proof runner ran, per run
    proof_at: Vec<usize>,
}

struct Fake(Mutex<World>);

fn ptr(ua: B256, v: u64) -> Address {
    Address::from_word(keccak256((ua, v).abi_encode()))
}

/// A fake pure view: the hash of its name and arguments, so another path or argument gives another answer.
fn tagged(name: &str, args: Vec<u8>) -> B256 {
    keccak256([name.as_bytes(), &args].concat())
}

fn registry_separator() -> B256 {
    Eip712Domain::new(Some("SCaaS UARegistry".into()), Some("1".into()), Some(U256::from(CHAIN_ID)), Some(REGISTRY),
        Some(CHAIN_UID)).separator()
}

/// `UAKinds.uaAuthDigest(sep, ua, purpose, digest)`.
fn ua_auth_digest_at(sep: B256, ua: B256, purpose: B256, digest: B256) -> B256 {
    let th = keccak256("UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)");
    keccak256([&[0x19, 0x01][..], sep.as_slice(), keccak256((th, ua, purpose, digest).abi_encode()).as_slice()].concat())
}

macro_rules! answer {
    ($sel:ident, $data:ident; $($c:ty => |$x:pat_param| $e:expr),* $(,)?) => {
        $(if $sel == <$c>::SELECTOR {
            let $x = <$c>::abi_decode(&$data).unwrap();
            return Ok(<$c>::abi_encode_returns(&$e).into());
        })*
    };
}

impl Fake {
    /// One read by `node` at `block`: recorded, then refused when the node has stopped answering.
    fn reach(&self, node: usize, block: Block) -> Result<(), ChainError> {
        let mut w = self.0.lock().unwrap();
        let block = match block {
            Block::Number(_) if w.by_hash => return Err(ChainError::Rpc("a read by number alone".into())),
            Block::Number(n) => n,
            Block::Hash(h) => U256::from_be_bytes(h.0).to::<u64>(),
        };
        let before = w.seen.iter().filter(|s| s.0 == node).count();
        w.seen.push((node, block));
        match w.down.get(&node) {
            Some(&n) if before >= n => Err(ChainError::Rpc(format!("node {node} down"))),
            _ => Ok(()),
        }
    }
}

#[async_trait]
impl Chain for Fake {
    fn nodes(&self) -> usize {
        self.0.lock().unwrap().nodes.max(1)
    }

    async fn head(&self, node: usize) -> Result<u64, ChainError> {
        match self.0.lock().unwrap().down.get(&node) {
            Some(0) => Err(ChainError::Rpc(format!("node {node} down"))),
            _ => Ok(100 + node as u64),
        }
    }

    /// Block `n`'s hash is `n` as a word, on every node.
    async fn header(&self, _node: usize, number: u64) -> Result<B256, ChainError> {
        Ok(B256::from(U256::from(number)))
    }

    async fn code(&self, node: usize, block: Block, at: Address) -> Result<Bytes, ChainError> {
        self.reach(node, block)?;
        let w = self.0.lock().unwrap();
        if at == TOKEN {
            // ChainEnvCode: proxy(release) ‖ chainUid ‖ registry ‖ govRouter ‖ ska ‖ hedera ‖ counts
            let mut c = hex!("363d3d373d3d3d363d73").to_vec();
            c.extend(w.release);
            c.extend(hex!("5af43d82803e903d91602b57fd5bf3"));
            c.extend(w.named.1);
            c.extend(w.named.0);
            c.extend([0u8; 43]);
            return Ok(c.into());
        }
        let k = w.keys.iter().find(|((u, v), _)| ptr(*u, *v) == at);
        Ok(k.map(|(_, k)| [&[0u8][..], &k.pk].concat().into()).unwrap_or_default())
    }

    async fn call(&self, node: usize, block: Block, to: Address, data: Bytes) -> Result<Bytes, ChainError> {
        self.reach(node, block)?;
        let w = self.0.lock().unwrap();
        let sel: [u8; 4] = data[..4].try_into().unwrap();
        let st = || Bytes::from(w.statement.clone());
        let at = |ua: B256, v: u64| w.keys.get(&(ua, v)).cloned().unwrap_or_default();
        if to == TOKEN {
            answer! { sel, data;
                T::transferStatementCall => |_| st(),
                T::transferSingleStatementCall => |_| st(),
                T::burnStatementCall => |_| st(),
                T::unshieldUnwrapStatementCall => |_| st(),
                T::disclosureStatementCall => |_| st(),
                T::proofSystemIdCall => |_| if w.psid.is_zero() { B256::from(stmt::PQZL_ID) } else { w.psid },
                T::auditorUACall => |_| w.auditor,
                T::pqzEntryBlobCall => |_| Bytes::from(w.blob.clone()),
                T::pqzVerifyConfigCall => |_| PqzVerifyConfig { pqzVerifyMode: w.mode, verifier: w.verifier, fixed_: false,
                    pqzVerifierEpoch: w.epoch, pending: B256::ZERO, eta: 0, noticePeriod: 0, verifierFee: 0, verifierFeeMax: 0,
                    verifierFeePending: 0, verifierFeeEta: 0, pqzOwnKey: w.own, pqzOpening: w.opening },
            }
        }
        if to == REGISTRY || to == ROGUE {
            answer! { sel, data;
                uaAuthDigestCall => |_| FORGED,
                R::generationCall => |_| w.pins.0,
                R::chainUidCall => |_| w.pins.1,
                R::pqzKeyOfCall => |c| {
                    let v = w.current.get(&c.ua).copied().unwrap_or(0);
                    R::pqzKeyOfReturn { version: v, ptr: ptr(c.ua, v), pqzPopHash: at(c.ua, v).pop_hash, proven: false }
                },
                R::pqzKeyAtCall => |c| match w.keys.get(&(c.ua, c.version)) {
                    Some(k) => R::pqzKeyAtReturn { ptr: ptr(c.ua, c.version), pqzPopHash: k.pop_hash, proven: false },
                    None => R::pqzKeyAtReturn { ptr: Address::ZERO, pqzPopHash: B256::ZERO, proven: false },
                },
                R::pqzPopOfCall => |c| Bytes::from(at(c.ua, c.version).pop),
                // the scoped records (K3-3) from the same map: one token, one scope per test
                R::pqzScopedKeyOfCall => |c| {
                    let v = w.current.get(&c.ua).copied().unwrap_or(0);
                    R::pqzScopedKeyOfReturn { version: v, ptr: ptr(c.ua, v), pqzPopHash: at(c.ua, v).pop_hash, proven: false }
                },
                R::pqzScopedKeyAtCall => |c| match w.keys.get(&(c.ua, c.version)) {
                    Some(k) => R::pqzScopedKeyAtReturn { ptr: ptr(c.ua, c.version), pqzPopHash: k.pop_hash, proven: false },
                    None => R::pqzScopedKeyAtReturn { ptr: Address::ZERO, pqzPopHash: B256::ZERO, proven: false },
                },
                R::pqzScopedPopOfCall => |c| Bytes::from(at(c.ua, c.version).pop),
                R::pqzScopedKeyDigestCall => |c| tagged("scoped", (c.ua, u16::from(c.keyClass), c.chainUid, c.token, c.version, c.pqzKeyHash)
                    .abi_encode()),
                R::pqzKeySigOfCall => |c| Bytes::from(at(c.ua, c.version).sig),
                R::keyOwnerCall => |c| w.lie.get(&node).copied().or(w.owner.get(&c.keyHash).copied()).unwrap_or_default(),
                R::kindOfCall => |_| 0x0130u16,
                R::registrationOfCall => |_| R::registrationOfReturn { kind: 0x0130, keyData: Bytes::new(),
                    attrs: UAAttrs { pqzKey: Bytes::new(), pqzPopHash: B256::ZERO,
                        kem: KemKey { scheme: 0, mlkemEk: Bytes::new(), x25519: B256::ZERO }, kemPkHash: B256::ZERO },
                    pop: Bytes::new(), pqzPop: Bytes::new() },
                R::kemRecordHashCall => |c| tagged("kem", (c.ua, c.version).abi_encode()),
                R::portableRecordDigestCall => |c| tagged("portable", (c.ua, c.kind, c.pqzKeyHash, c.kemRecordHash).abi_encode()),
                R::pqzKeyDigestCall => |c| tagged("key", (c.ua, c.pqzKeyHash).abi_encode()),
                R::pqzKeyVersionDigestCall => |c| tagged("version", (c.ua, c.version, c.pqzKeyHash).abi_encode()),
                R::uaMessageCall => |c| w.message.get(&(c.purposeTag, c.digest)).copied()
                    .unwrap_or_else(|| tagged("message", (c.kind, c.purposeTag, c.digest).abi_encode())),
            }
        }
        Err(ChainError::Revert(Bytes::new()))
    }
}

// ------------------------------------------------------------------ the service under test

fn signer() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&TEST_KEY).unwrap()
}

/// An OFFCHAIN token naming this verifier at `EPOCH`; `uas[i]` holds the statement's key `i` (at `640 + i·PK`) as
/// version 0 with stored proof bytes `[i + 1; 8]`.
fn world(st: &[u8], uas: &[B256]) -> World {
    let mut w = World { release: RELEASE, named: (REGISTRY, CHAIN_UID), pins: (1, CHAIN_UID), mode: 1, verifier: signer().address().into_word(), epoch: EPOCH, auditor: AUD,
        statement: st.to_vec(), ..Default::default() };
    for (i, &u) in uas.iter().enumerate() {
        w.keys.insert((u, 0), key(&st[640 + i * PK..640 + (i + 1) * PK], &[i as u8 + 1; 8]));
    }
    w
}

/// pqz-ffi on the operation; `R_REG` accepted (the vectors hold no `R_REG` proof of the statement rows' keys)
fn real_op() -> Pqz {
    Arc::new(|i: &[u8]| if i[0] == stmt::OP_REGISTER { Ok(VALID) } else { pqz_ffi::precompile(i) })
}

fn all_valid() -> Pqz {
    Arc::new(|_: &[u8]| Ok(VALID))
}

struct Svc {
    app: axum::Router,
    fake: Arc<Fake>,
}

impl Svc {
    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.fake.0.lock().unwrap()
    }
}

fn service(w: World, pqz: Pqz) -> Svc {
    let fake = Arc::new(Fake(Mutex::new(w)));
    let cfg = Config::parse(CONFIG).unwrap();
    let svc = Arc::new(Service::new(fake.clone(), pqz, signer(), &cfg));
    Svc { app: http::router(svc, &cfg), fake }
}

async fn post(s: &Svc, path: &str, body: impl Into<Body>) -> (u16, Value) {
    let req = Request::post(path).header("content-type", "application/json")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9)))).body(body.into()).unwrap();
    let res = s.app.clone().oneshot(req).await.unwrap();
    let status = res.status().as_u16();
    let b = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

async fn verdict(s: &Svc, req: &Value) -> (u16, Value) {
    post(s, "/v1/pqz-verdict", req.to_string()).await
}

/// The empty `PqzOpening` (a token without the opening).
static NO_OPENING: std::sync::LazyLock<Value> =
    std::sync::LazyLock::new(|| json!({"mlkemCt": "0x", "x25519Eph": B256::ZERO, "sealedSeed": "0x"}));

fn hx(b: &[u8]) -> String {
    hex::encode_prefixed(b)
}

fn request(op: Value, st: &[u8], proof: &[u8]) -> Value {
    json!({"token": TOKEN, "chainId": CHAIN_ID, "op": op, "statement": hx(st), "proof": hx(proof), "pqzVerifierEpoch": EPOCH})
}

fn single(from: B256, kv: u64, to: B256) -> Value {
    json!({"entry": "mtxConfidentialTransferSingle", "args": {"p": 0, "validUntilBlock": "100", "shieldIn": "0",
        "fromUA": from, "keyVersion": kv, "toUA": to, "beneficiaryUA": B256::ZERO, "salt": hx(&[0; 16]), "ownTag": TAG, "u": "0x",
        "vTo": "0x", "vFrom": "0x", "vAuditor": "0x", "uFrom": "0x", "sealedMemo": "0x", "openingTo": NO_OPENING.clone(),
        "openingAuditor": NO_OPENING.clone()}})
}

/// op 7 to `legs`, the parts at their real sizes (`G` groups of `u`, a `v` and `vAuditor` per leg, the memo)
fn multi(from: B256, legs: &[B256], aud: bool) -> Value {
    let g = stmt::groups(legs.len(), aud);
    let v = hx(&[0; stmt::V_BYTES]);
    let va = if aud { v.clone() } else { "0x".into() };
    json!({"entry": "mtxConfidentialTransfer", "args": {"p": 0, "validUntilBlock": "100", "shieldIn": "0", "fromUA": from,
        "keyVersion": 0, "beneficiaryUA": B256::ZERO, "decoyFee": "0", "salt": hx(&[0; 16]), "ownTag": TAG,
        "u": vec![hx(&[0; PK]); g], "legs": legs.iter().map(|l| json!({"ua": l, "v": v, "vAuditor": va})).collect::<Vec<_>>(),
        "vFrom": v, "sealedMemo": hx(&vec![0; 2 + 40 * legs.len()])}})
}

fn unshield(from: B256, kv: u64) -> Value {
    json!({"entry": "mtxUnshield", "args": {"p": 0, "validUntilBlock": "100", "shieldIn": "0", "fromUA": from,
        "keyVersion": kv, "beneficiaryUA": B256::ZERO, "ownTag": TAG, "u": "0x", "vFrom": "0x"}, "amount": "5", "recipient": C})
}

/// Signed by this verifier: the verdict exactly the expected one, the signature over the registry's `uaAuthDigest` of
/// its digest in the token's domain, `validUntil` within the configured minutes.
fn assert_signed(r: &(u16, Value), statement_hash: B256, proof_hash: B256) {
    assert_signed_as(r, statement_hash, proof_hash, stmt::PQZL_ID.into());
}

/// `assert_signed` under the token's `proofSystemId` `psid` (K3-4: `PQZL_SPLIT_ID` on an opening token).
fn assert_signed_as(r: &(u16, Value), statement_hash: B256, proof_hash: B256, psid: B256) {
    assert_eq!(r.0, 200, "{}", r.1);
    let valid_until = r.1["pqzVerdict"]["validUntil"].as_u64().unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert!(valid_until > now && valid_until <= now + 5 * 60, "validUntil {valid_until}");
    let v = PqzVerdict { token: TOKEN, chainId: U256::from(CHAIN_ID), proofSystemId: psid,
        statementHash: statement_hash, proofHash: proof_hash, pqzVerifierEpoch: EPOCH, validUntil: valid_until };
    assert_eq!(r.1["pqzVerdict"], serde_json::to_value(&v).unwrap());
    let sig = &r.1["pqzVerdictSig"];
    assert_eq!((sig["keyData"].as_str(), sig["members"].as_array().map(Vec::len)), (Some("0x"), Some(0)));
    let auth = ua_auth_digest_at(registry_separator(), signer().address().into_word(), purpose_pqz_verdict(),
        verdict_digest(&v, CHAIN_UID));
    let s = Signature::from_raw(&bytes(&sig["signature"])).unwrap();
    assert_eq!(s.recover_address_from_prehash(&auth).unwrap(), signer().address());
    assert_ne!(s.recover_address_from_prehash(&FORGED).ok(), Some(signer().address()), "the RPC's uaAuthDigest signed");
}

fn assert_refused(r: &(u16, Value), error: &str) {
    assert_eq!(r.1["error"], error, "{} {}", r.0, r.1);
    assert_ne!(r.0, 200);
    assert!(r.1.get("pqzVerdictSig").is_none() && r.1.get("pqzVerdict").is_none());
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn signs_valid_statement() {
    // op 1 with the auditor (the TRANSFER row) and op 7 to two legs without (M2-off), through pqz-ffi
    let (st, proof) = vector("TRANSFER", None);
    let s = service(world(&st, &[A, B, AUD]), real_op());
    assert_signed(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, keccak256(&st), keccak256(&proof));
    let (st, proof) = vector("TRANSFER-MULTI", Some("M2-off"));
    let s = service(world(&st, &[A, C, D]), real_op());
    assert_signed(&verdict(&s, &request(multi(A, &[C, D], false), &st, &proof)).await, keccak256(&st), keccak256(&proof));
}

#[tokio::test]
async fn refuses_verdict_zero() {
    let (st, mut proof) = vector("TRANSFER", None);
    let n = proof.len() / 2;
    proof[n] ^= 1;
    let s = service(world(&st, &[A, B, AUD]), real_op());
    assert_refused(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, "VERDICT_ZERO");
}

#[tokio::test]
async fn refuses_tampered_statement() {
    let (st, proof) = vector("TRANSFER", None);
    let s = service(world(&st, &[A, B, AUD]), all_valid());
    assert_signed(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, keccak256(&st), keccak256(&proof));
    // one byte of the outputs: the token's view still builds the original
    let mut bad = st.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_refused(&verdict(&s, &request(single(A, 0, B), &bad, &proof)).await, "STATEMENT_MISMATCH");
}

/// Round 3t (CTR-PQZ-36, V1): a statement proved at another fee word than the token's (a fee change since) is refused by name,
/// `FEE_WORD_MISMATCH`, before the byte compare; the control at the token's word is signed (`refuses_tampered_statement`).
#[tokio::test]
async fn refuses_stale_fee_word() {
    let (st, proof) = vector("TRANSFER", None);
    let s = service(world(&st, &[A, B, AUD]), all_valid());
    assert_signed(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, keccak256(&st), keccak256(&proof));
    let mut stale = st.clone();
    stale[256 + 31] ^= 1;
    assert_refused(&verdict(&s, &request(single(A, 0, B), &stale, &proof)).await, "FEE_WORD_MISMATCH");
}

#[tokio::test]
async fn refuses_key_without_stored_pop() {
    let (st, proof) = vector("TRANSFER", None);
    let req = request(single(A, 0, B), &st, &proof);
    let s = service(world(&st, &[A, B, AUD]), all_valid());
    // the receiver's record keeps only the proof's hash
    s.world().keys.get_mut(&(B, 0)).unwrap().pop.clear();
    assert_refused(&verdict(&s, &req).await, "POP_NOT_STORED");
    // bytes that do not hash to its pqzPopHash
    s.world().keys.get_mut(&(B, 0)).unwrap().pop = vec![9; 8];
    assert_refused(&verdict(&s, &req).await, "POP_HASH");
    // the stored bytes
    s.world().keys.get_mut(&(B, 0)).unwrap().pop = vec![2; 8];
    assert_signed(&verdict(&s, &req).await, keccak256(&st), keccak256(&proof));
}

#[tokio::test]
async fn refuses_key_owned_by_other_ua() {
    let (st, proof) = vector("TRANSFER", None);
    let h = pqz_key_hash(&st[640 + PK..640 + 2 * PK]);
    let s = service(world(&st, &[A, B, AUD]), all_valid());
    // the receiver's key proven by another UA on chain
    s.world().owner.insert(h, C);
    assert_refused(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, "KEY_OWNED_ELSEWHERE");
    // proven by the receiver itself
    s.world().owner.insert(h, B);
    assert_signed(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, keccak256(&st), keccak256(&proof));
    // the same key bytes under another UA, unproven on chain: this verifier holds them for (B, 0)
    {
        let mut w = s.world();
        w.owner.clear();
        let k = w.keys[&(B, 0)].clone();
        w.keys.insert((D, 0), k);
    }
    assert_refused(&verdict(&s, &request(single(A, 0, D), &st, &proof)).await, "KEY_OWNED_ELSEWHERE");
}

#[tokio::test]
async fn cache_keyed_by_ua_and_keyhash() {
    let (st, proof) = vector("TRANSFER", None);
    let runs = Arc::new(AtomicUsize::new(0));
    let r = runs.clone();
    let pqz: Pqz = Arc::new(move |i: &[u8]| {
        if i[0] == stmt::OP_REGISTER {
            r.fetch_add(1, SeqCst);
        }
        Ok(VALID)
    });
    let s = service(world(&st, &[A, B, AUD]), pqz);
    let req = request(single(A, 0, B), &st, &proof);
    assert_signed(&verdict(&s, &req).await, keccak256(&st), keccak256(&proof));
    assert_eq!(runs.load(SeqCst), 3, "R_REG of the three keys");
    assert_signed(&verdict(&s, &req).await, keccak256(&st), keccak256(&proof));
    assert_eq!(runs.load(SeqCst), 3, "cached by (ua, version, pqzKeyHash)");
    // (B, 0) now names other key bytes without stored proof bytes (and the statement holds them): (B, 0) is cached,
    // (B, 0, keyHash of the new key) is not
    let mut st2 = st.clone();
    st2[640 + PK] ^= 1;
    {
        let mut w = s.world();
        w.statement = st2.clone();
        let k = w.keys.get_mut(&(B, 0)).unwrap();
        k.pk = st2[640 + PK..640 + 2 * PK].to_vec();
        k.pop.clear();
    }
    assert_refused(&verdict(&s, &request(single(A, 0, B), &st2, &proof)).await, "POP_NOT_STORED");
}

#[tokio::test]
async fn refuses_oversized_and_deep_body() {
    let s = service(World::default(), all_valid());
    let limit = body_limit();
    assert_refused(&post(&s, "/v1/pqz-verdict", vec![b'x'; limit + 1]).await, "BODY_TOO_LARGE");
    // at the limit: read, then refused as JSON (so the larger one was refused before decoding)
    assert_refused(&post(&s, "/v1/pqz-verdict", vec![b'x'; limit]).await, "BAD_REQUEST");
    let nest = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
    assert_refused(&post(&s, "/v1/pqz-verdict", nest(5)).await, "BAD_REQUEST");
    assert_refused(&post(&s, "/v1/pqz-verdict", nest(6)).await, "JSON_TOO_DEEP");
    assert_refused(&post(&s, "/v1/pqz-verdict/probe", nest(6)).await, "JSON_TOO_DEEP");
    // brackets inside a string, escaped quotes included, do not nest
    assert_refused(&post(&s, "/v1/pqz-verdict", format!("{{\"a\":\"\\\"{}\"}}", "[".repeat(50))).await, "BAD_REQUEST");
    // the largest operation fits: op 7, eight legs, the auditor, every part at its size
    let (st, proof) = vector("TRANSFER-MULTI", Some("M8-on"));
    let legs = [C, D, B256::repeat_byte(1), B256::repeat_byte(2), B256::repeat_byte(3), B256::repeat_byte(4),
        B256::repeat_byte(5), B256::repeat_byte(6)];
    let uas: Vec<B256> = [A].into_iter().chain(legs).chain([AUD]).collect();
    *s.world() = world(&st, &uas);
    let body = request(multi(A, &legs, true), &st, &proof).to_string();
    let largest = *statement_lengths().iter().max().unwrap();
    assert!(body.len() > 2 * (largest + stmt::MAX_PROOF_PQZL) + 4096, "op.args repeats the statement's parts");
    assert_signed(&post(&s, "/v1/pqz-verdict", body).await, keccak256(&st), keccak256(&proof));
}

#[tokio::test]
async fn refuses_wrong_set_length() {
    let (st, proof) = vector("TRANSFER", None);
    let s = service(world(&st, &[A, B, AUD]), all_valid());
    // the view builds the same bytes each time: only the set's lengths refuse. A word more; R_REG's length (no token
    // builds it); op 1's length at n2048-kmax1024
    for bad in [[&st[..], &[0; 32]].concat(), st[..stmt::Form::Register.stmt_len()].to_vec(), st[..83_072].to_vec()] {
        s.world().statement = bad.clone();
        assert_refused(&verdict(&s, &request(single(A, 0, B), &bad, &proof)).await, "STATEMENT_LENGTH");
    }
    s.world().statement = st.clone();
    assert_signed(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, keccak256(&st), keccak256(&proof));
}

#[tokio::test]
async fn refuses_statement_proof_system_not_the_sets() {
    // word 32 the set's PQZH id while the token's proofSystemId() (a field outside the statement) is its PQZL id
    let (mut st, proof) = vector("TRANSFER", None);
    st[32..64].copy_from_slice(&stmt::PQZH_ID);
    let s = service(world(&st, &[A, B, AUD]), all_valid());
    assert_refused(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, "STATEMENT_PROOF_SYSTEM");
}

#[tokio::test]
async fn refuses_token_config_mismatch() {
    let (st, proof) = vector("TRANSFER", None);
    let s = service(world(&st, &[A, B, AUD]), all_valid());
    let req = request(single(A, 0, B), &st, &proof);
    s.world().epoch = EPOCH + 1;
    assert_refused(&verdict(&s, &req).await, "EPOCH_MISMATCH");
    s.world().epoch = EPOCH;
    s.world().verifier = C;
    assert_refused(&verdict(&s, &req).await, "NOT_THIS_VERIFIER");
    s.world().verifier = signer().address().into_word();
    s.world().mode = 0;
    assert_refused(&verdict(&s, &req).await, "NOT_OFFCHAIN");
    s.world().mode = 1;
    let mut other = req.clone();
    other["chainId"] = json!(1);
    assert_refused(&verdict(&s, &other).await, "CHAIN_MISMATCH");
    other = req.clone();
    other["op"]["proofSystemId"] = json!(B256::from(stmt::PQZL_ID));
    assert_refused(&verdict(&s, &other).await, "BAD_REQUEST");
    assert_signed(&verdict(&s, &req).await, keccak256(&st), keccak256(&proof));
}

/// The three-key model (K3-3, CTR-PQZ-30 per scope): an `OFFCHAIN` token's key is a scoped record, and its stored `R_REG`
/// proves over `uaMessage(0x0142, PURPOSE_PQZ_SCOPED_KEY, pqzScopedKeyDigest(ua, keyClass, chainUid, scope, version, keyHash))`:
/// the register row's real proof verifies under class 2 (scope 0); the same record read as class 3 (scope the token), at
/// version 1, or with another `chainUid` gives another message, `POP_INVALID`.
#[tokio::test]
async fn rreg_message_scoped_real_vector() {
    // the register row's key, message and real proof; the burn's own proof faked (no burn by this key in the vectors)
    let reg = &json_file("n2304-kmax4096/statement_register.json")["rows"][0];
    let rst = bytes(&reg["stmt"]);
    let (message, pk) = (B256::from_slice(&rst[64..96]), rst[96..].to_vec());
    let (_, rproof) = vector("REGISTER", None);
    let (mut st, proof) = vector("BURN", None);
    st[640..640 + PK].copy_from_slice(&pk);
    let pqz: Pqz = Arc::new(|i: &[u8]| if i[0] == stmt::OP_REGISTER { pqz_ffi::precompile(i) } else { Ok(VALID) });
    let h = pqz_key_hash(&pk);
    let purpose = keccak256("scaas.ua.purpose.pqz-scoped-key.v1");
    let scoped = |class: u8, token: Address, v: u64| tagged("scoped", (A, u16::from(class), CHAIN_UID, token, v, h).abi_encode());
    let w = |own: bool, version: u64| {
        let mut w = world(&st, &[]);
        w.own = own;
        w.keys.insert((A, version), key(&pk, &rproof));
        w.message.insert((purpose, scoped(2, Address::ZERO, 0)), message);
        w
    };
    let s = service(w(false, 0), pqz.clone());
    assert_signed(&verdict(&s, &request(unshield(A, 0), &st, &proof)).await, keccak256(&st), keccak256(&proof));
    // class 3: the token's scope, another digest
    let s = service(w(true, 0), pqz.clone());
    assert_refused(&verdict(&s, &request(unshield(A, 0), &st, &proof)).await, "POP_INVALID");
    // version 1 of the same scope
    let s = service(w(false, 1), pqz);
    assert_refused(&verdict(&s, &request(unshield(A, 1), &st, &proof)).await, "POP_INVALID");
}

/// K3-4: the verdict signs the token's own `proofSystemId`: `PQZL_SPLIT_ID` on an opening token (its split statement, `u_f`
/// appended), `PQZL_ID` without; a statement of the other id is refused before anything is signed.
#[tokio::test]
async fn split_id_follows_the_opening() {
    let (st0, proof) = vector("TRANSFER", None);
    let mut st = [st0.clone(), vec![0u8; PK]].concat();
    st[32..64].copy_from_slice(&stmt::PQZL_SPLIT_ID);
    let open = |opening: bool, st: &[u8]| {
        let mut w = world(st, &[A, C, AUD]); // the TRANSFER row names the auditor's key too
        (w.opening, w.own) = (opening, true);
        w.psid = B256::from(if opening { stmt::PQZL_SPLIT_ID } else { stmt::PQZL_ID });
        w
    };
    let s = service(open(true, &st), all_valid());
    let r = verdict(&s, &request(single(A, 0, C), &st, &proof)).await;
    assert_signed_as(&r, keccak256(&st), keccak256(&proof), stmt::PQZL_SPLIT_ID.into());
    // the split statement on a token without the opening, the plain one on an opening token: refused
    let s = service(open(false, &st), all_valid());
    assert_refused(&verdict(&s, &request(single(A, 0, C), &st, &proof)).await, "PROOF_SYSTEM");
    let s = service(open(true, &st0), all_valid());
    assert_refused(&verdict(&s, &request(single(A, 0, C), &st0, &proof)).await, "PROOF_SYSTEM");
}

/// K3-4 with a real proof: the TRANSFER-SPLIT row of `proof_pqzl_split.json` verifies through the production entry
/// [`scaas_pqz_verifier::offchain`] (pqz-offchain) and is signed under `PQZL_SPLIT_ID`; the precompile's entry alone answers
/// `…00` on the same input (why the service runs pqz-offchain); one flipped proof byte → `VERDICT_ZERO`.
#[tokio::test]
async fn signs_real_split_proof() {
    let f = json_file("n2304-kmax4096/proof_pqzl_split.json");
    let row = f["rows"].as_array().unwrap().iter().find(|r| r["form"] == "TRANSFER-SPLIT").unwrap();
    let (st, mut proof) = (bytes(&row["stmt"]), bytes(&row["proof"]));
    assert_eq!(st[32..64], stmt::PQZL_SPLIT_ID);
    let input = stmt::input(stmt::OP_TRANSFER, &st, &proof);
    assert_eq!(scaas_pqz_verifier::offchain(&input).unwrap(), VALID);
    assert_eq!(pqz_ffi::precompile(&input).unwrap(), pqz_ffi::INVALID);
    let real: Pqz = Arc::new(|i: &[u8]| if i[0] == stmt::OP_REGISTER { Ok(VALID) } else { scaas_pqz_verifier::offchain(i) });
    let w = |st: &[u8]| {
        let mut w = world(st, &[A, B, AUD]);
        (w.opening, w.own, w.psid) = (true, true, B256::from(stmt::PQZL_SPLIT_ID));
        w
    };
    let s = service(w(&st), real.clone());
    assert_signed_as(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, keccak256(&st), keccak256(&proof),
        stmt::PQZL_SPLIT_ID.into());
    let n = proof.len() / 2;
    proof[n] ^= 1;
    let s = service(w(&st), real);
    assert_refused(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, "VERDICT_ZERO");
}

#[tokio::test]
async fn disclosure_names_the_leg_owner() {
    // an op blob `salt ‖ u_0 ‖ (v_j ‖ UA_j)_{j<2} ‖ P(v_f) ‖ ownTag ‖ kv(8·2) ‖ u8(2)`, packed at PACK_BITS = q's bit length
    // (group 3h: PqzCore.rOf, _legOf)
    let group = (u64::BITS - stmt::Q.leading_zeros()) as usize / 2;
    let (pkp, vp) = (PK / 32 * group, stmt::V_BYTES / 32 * group);
    let blob = [&[0u8; 16][..], &vec![0; pkp], &vec![0; vp], C.as_slice(), &vec![0; vp], D.as_slice(), &vec![0; vp],
        TAG.as_slice(), &[0; 16], &[2]].concat();
    let (st, proof) = vector("DISCLOSE-RECEIVER", None);
    let mut w = world(&st, &[]);
    w.blob = blob;
    let disclosed = key(&st[stmt::DISC_WORDS * 32..stmt::DISC_WORDS * 32 + PK], &[7; 8]);
    let op = |leg: u64, kind: u8| json!({"entry": "verifyTransferAmount",
        "args": {"entryRef": B256::repeat_byte(0xee), "leg": leg.to_string(), "amount": "5", "kind": kind, "keyVersion": 0}});
    // leg 1's owner is D, leg 0's is C (whose record holds another key), kind 2's the auditor; each its own service, so
    // the verifier's ownership record of one does not answer for another
    w.keys.insert((D, 0), disclosed.clone());
    w.keys.insert((C, 0), key(&st[640..640 + PK], &[8; 8]));
    let (blob, keys) = (w.blob.clone(), w.keys.clone());
    let s = service(w, real_op());
    assert_signed(&verdict(&s, &request(op(1, 1), &st, &proof)).await, keccak256(&st), keccak256(&proof));
    assert_refused(&verdict(&s, &request(op(2, 1), &st, &proof)).await, "UNKNOWN_ENTRY");
    let mut w = world(&st, &[]);
    (w.blob, w.keys) = (blob, keys);
    w.keys.remove(&(D, 0));
    let s2 = service(w, real_op());
    assert_refused(&verdict(&s2, &request(op(0, 1), &st, &proof)).await, "KEY_MISMATCH");
    s2.world().keys.insert((AUD, 0), disclosed);
    assert_signed(&verdict(&s2, &request(op(1, 2), &st, &proof)).await, keccak256(&st), keccak256(&proof));
    // a disclosure is direct: a binding is not its field
    let mut bad = request(op(1, 1), &st, &proof);
    bad["op"]["binding"] = json!(B256::repeat_byte(1));
    assert_refused(&verdict(&s, &bad).await, "BAD_REQUEST");
}

#[tokio::test]
async fn probe_signature() {
    let s = service(world(&[], &[]), all_valid());
    let req = json!({"token": TOKEN, "chainId": CHAIN_ID}).to_string();
    assert_signed(&post(&s, "/v1/pqz-verdict/probe", req.clone()).await, keccak256(PROBE_STATEMENT), keccak256(b""));
    s.world().release = Address::repeat_byte(9);
    assert_refused(&post(&s, "/v1/pqz-verdict/probe", req).await, "UNKNOWN_RELEASE");
}

/// Fable C-1: the probe signs only for an `OFFCHAIN` token that names this verifier (one change at a time, then back);
/// a proposal probe (spec §4.2's typo guard of the proposed `next`) also while the token names another verifier or none,
/// never for a token not `OFFCHAIN` or of another chain.
#[tokio::test]
async fn probe_refuses_token_not_served() {
    let s = service(world(&[], &[]), all_valid());
    let req = json!({"token": TOKEN, "chainId": CHAIN_ID}).to_string();
    let proposal = json!({"token": TOKEN, "chainId": CHAIN_ID, "proposal": true}).to_string();
    let probe = |b: &str| post(&s, "/v1/pqz-verdict/probe", b.to_string());
    s.world().mode = 0;
    assert_refused(&probe(&req).await, "NOT_OFFCHAIN");
    assert_refused(&probe(&proposal).await, "NOT_OFFCHAIN");
    s.world().mode = 1;
    for other in [C, B256::ZERO] {
        s.world().verifier = other;
        assert_refused(&probe(&req).await, "NOT_THIS_VERIFIER");
        assert_signed(&probe(&proposal).await, keccak256(PROBE_STATEMENT), keccak256(b""));
    }
    let wrong_chain = json!({"token": TOKEN, "chainId": 1, "proposal": true}).to_string();
    assert_refused(&probe(&wrong_chain).await, "CHAIN_MISMATCH");
    s.world().verifier = signer().address().into_word();
    assert_signed(&probe(&req).await, keccak256(PROBE_STATEMENT), keccak256(b""));
    assert_signed(&probe(&proposal).await, keccak256(PROBE_STATEMENT), keccak256(b""));
}

/// The probe's `statementHash` is no real op statement's: its 27 bytes are shorter than every statement length of the
/// set, each at least 640 bytes, and its keccak is none of the
/// vector rows' (every form). A real debit's `_check` refuses a probe verdict on chain: `tests/anvil.rs`.
#[test]
fn probe_statement_is_no_op_statement() {
    assert!(PROBE_STATEMENT.len() < stmt::HEADER_BYTES && PROBE_STATEMENT.len() < 32);
    assert!(statement_lengths().iter().all(|&n| n >= stmt::HEADER_BYTES && n != PROBE_STATEMENT.len()));
    let rows = json_file("n2304-kmax4096/proof_pqzl.json");
    let ours = hex::encode(keccak256(PROBE_STATEMENT));
    let rows = rows["rows"].as_array().unwrap();
    assert!(rows.len() > 10 && rows.iter().all(|r| r["stmt_keccak"].as_str().unwrap() != ours));
}

/// Fable C-1 (P0): a clone-shaped contract (proxy of the configured release) whose code names a registry or a `chainUid`
/// other than the pinned ones is refused on both routes, though that registry answers every view; the control is signed.
#[tokio::test]
async fn refuses_clone_naming_rogue_registry() {
    let (st, proof) = vector("TRANSFER", None);
    let s = service(world(&st, &[A, B, AUD]), all_valid());
    let req = request(single(A, 0, B), &st, &proof);
    let probe = json!({"token": TOKEN, "chainId": CHAIN_ID}).to_string();
    for (named, error) in [((ROGUE, CHAIN_UID), "FOREIGN_REGISTRY"), ((REGISTRY, B256::repeat_byte(7)), "FOREIGN_CHAIN_UID")] {
        s.world().named = named;
        assert_refused(&verdict(&s, &req).await, error);
        assert_refused(&post(&s, "/v1/pqz-verdict/probe", probe.clone()).await, error);
        let proposal = json!({"token": TOKEN, "chainId": CHAIN_ID, "proposal": true}).to_string();
        assert_refused(&post(&s, "/v1/pqz-verdict/probe", proposal).await, error);
    }
    s.world().named = (REGISTRY, CHAIN_UID);
    assert_signed(&verdict(&s, &req).await, keccak256(&st), keccak256(&proof));
    assert_signed(&post(&s, "/v1/pqz-verdict/probe", probe).await, keccak256(PROBE_STATEMENT), keccak256(b""));
}

/// Fable C-1 (P0): the registry (or the RPC) answers `uaAuthDigest` with a forged hash; the service signs the digest it
/// builds itself from the pinned values (`assert_signed` recovers over the test's own `UAAuth`, never over `FORGED`).
#[tokio::test]
async fn ignores_forged_rpc_digest() {
    let s = service(world(&[], &[]), all_valid());
    let r = post(&s, "/v1/pqz-verdict/probe", json!({"token": TOKEN, "chainId": CHAIN_ID}).to_string()).await;
    assert_signed(&r, keccak256(PROBE_STATEMENT), keccak256(b""));
    let sig = Signature::from_raw(&bytes(&r.1["pqzVerdictSig"]["signature"])).unwrap();
    assert_ne!(sig.recover_address_from_prehash(&FORGED).ok(), Some(signer().address()));
}

/// Fable C-3 (ARCH-POS-15): a list of nodes, failover per request, one node and one block for every read of a request.
#[tokio::test]
async fn fails_over_one_node_one_block() {
    let (st, proof) = vector("TRANSFER", None);
    let s = service(world(&st, &[A, B, AUD]), all_valid());
    let req = request(single(A, 0, B), &st, &proof);
    // node 0 down from the start: node 1 answers every read, at its block 101
    (s.world().nodes, s.world().down) = (3, HashMap::from([(0, 0)]));
    assert_signed(&verdict(&s, &req).await, keccak256(&st), keccak256(&proof));
    assert!(s.world().seen.iter().all(|&r| r == (1, 101)), "{:?}", s.world().seen);
    // node 0 answers four reads, then stops: the request starts over on node 1, never mixing its answers with node 0's
    (s.world().down, s.world().seen) = (HashMap::from([(0, 4)]), vec![]);
    assert_signed(&verdict(&s, &req).await, keccak256(&st), keccak256(&proof));
    let seen = s.world().seen.clone();
    assert_eq!(seen[..5], [(0, 100); 5], "four answered, the fifth refused");
    assert!(seen[5..].iter().all(|&r| r == (1, 101)) && seen.len() > 5, "{seen:?}");
    // a refusal on what node 0 answered is final: no failover (only an RPC that does not answer moves on)
    (s.world().down, s.world().seen, s.world().epoch) = (HashMap::new(), vec![], EPOCH + 1);
    assert_refused(&verdict(&s, &req).await, "EPOCH_MISMATCH");
    assert!(s.world().seen.iter().all(|r| r.0 == 0));
    s.world().epoch = EPOCH;
    // every node down
    s.world().down = HashMap::from([(0, 0), (1, 0), (2, 0)]);
    assert_refused(&verdict(&s, &req).await, "RPC_UNAVAILABLE");
    assert_refused(&post(&s, "/v1/pqz-verdict/probe", json!({"token": TOKEN, "chainId": CHAIN_ID}).to_string()).await,
        "RPC_UNAVAILABLE");
}

/// Fable C-4: a client that sends its headers and then no body holds no queue place: with every place's worth of such
/// clients connected, a whole request is still served; each slow one is refused `BODY_TIMEOUT` (408) after `BODY_TIMEOUT`.
/// The clock runs while the slow clients reach their handlers, then is paused, so the timeout passes at once when nothing
/// else runs.
#[tokio::test]
async fn slow_body_holds_no_queue_place() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let s = service(world(&[], &[]), all_valid());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = l.local_addr().unwrap();
    let app = s.app.clone().into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let mut slow = Vec::new();
    for _ in 0..Config::parse(CONFIG).unwrap().queue {
        let mut c = tokio::net::TcpStream::connect(at).await.unwrap();
        c.write_all(b"POST /v1/pqz-verdict/probe HTTP/1.1\r\nhost: v\r\ncontent-type: application/json\r\ncontent-length: 64\r\n\r\n{")
            .await.unwrap();
        slow.push(c);
    }
    // real time for the server to accept them and enter each handler (reading its body), then the paused clock
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    tokio::time::pause();
    let probe = json!({"token": TOKEN, "chainId": CHAIN_ID}).to_string();
    assert_signed(&post(&s, "/v1/pqz-verdict/probe", probe).await, keccak256(PROBE_STATEMENT), keccak256(b""));
    let start = tokio::time::Instant::now();
    for mut c in slow {
        let mut b = vec![0; 4096];
        let n = c.read(&mut b).await.unwrap();
        let answer = String::from_utf8_lossy(&b[..n]);
        assert!(answer.starts_with("HTTP/1.1 408") && answer.contains("BODY_TIMEOUT"), "{answer}");
    }
    assert!(start.elapsed() + std::time::Duration::from_secs(1) >= http::BODY_TIMEOUT);
}

/// A JSON-RPC endpoint: `answer(request)` is the response's `result` or `error` member; `None` accepts and never answers.
type Answer = Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>;

async fn rpc_server(answer: Answer) -> String {
    let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
        let answer = answer.clone();
        async move {
            let Some(mut a) = answer(&r) else { return std::future::pending().await };
            (a["jsonrpc"], a["id"]) = (json!("2.0"), r["id"].clone());
            axum::Json(a)
        }
    }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

/// A JSON-RPC endpoint that answers `eth_chainId` with `chain_id` (and nothing else).
async fn rpc_answering(chain_id: u64) -> String {
    rpc_server(Arc::new(move |r| (r["method"] == "eth_chainId").then(|| json!({"result": format!("{chain_id:#x}")})))).await
}

/// Fable R-1: a node that accepts and never answers times out (`ChainError::Rpc`) and the request fails over: node 0 silent
/// after `eth_chainId`, node 1 answering (the token has no code there), the probe comes back refused by what node 1 said.
#[tokio::test]
async fn silent_node_times_out_and_fails_over() {
    let chain_id = json!({"result": format!("{CHAIN_ID:#x}")});
    let c = chain_id.clone();
    let silent = rpc_server(Arc::new(move |r| (r["method"] == "eth_chainId").then(|| c.clone()))).await;
    let serving = rpc_server(Arc::new(move |r| Some(match r["method"].as_str().unwrap() {
        "eth_chainId" => chain_id.clone(),
        "eth_blockNumber" => json!({"result": "0x65"}),
        "eth_getCode" => json!({"result": "0x"}),
        _ => json!({"error": {"code": -32601, "message": "no such method"}}),
    }))).await;
    let rpc = Rpc::connect_within(&[silent, serving], CHAIN_ID, std::time::Duration::from_millis(300)).await.unwrap();
    // the outer bound turns a hang into this test's failure
    let bound = std::time::Duration::from_secs(5);
    let head = tokio::time::timeout(bound, rpc.head(0)).await.expect("a silent node times out");
    assert!(matches!(head, Err(ChainError::Rpc(_))), "{head:?}");
    let svc = Service::new(Arc::new(rpc), all_valid(), signer(), &Config::parse(CONFIG).unwrap());
    let r = tokio::time::timeout(bound, svc.probe(ProbeRequest { token: TOKEN, chain_id: CHAIN_ID, proposal: false })).await
        .expect("the request fails over, never hangs");
    assert_eq!(r.unwrap_err().error, "NOT_A_TOKEN", "node 1's answer");
}

/// Fable R-2: an `eth_call` error is a revert only with revert data or an `execution reverted` message; `header not found`
/// or a rate limit is the node's (`ChainError::Rpc`, so the request fails over).
#[tokio::test]
async fn only_a_revert_is_a_revert() {
    let node = rpc_server(Arc::new(|r| Some(match r["method"].as_str().unwrap() {
        "eth_chainId" => json!({"result": format!("{CHAIN_ID:#x}")}),
        _ => match r["params"][0]["to"].as_str().unwrap().chars().last().unwrap() {
            '1' => json!({"error": {"code": 3, "message": "execution reverted: no", "data": "0x08c379a0"}}),
            '2' => json!({"error": {"code": -32000, "message": "execution reverted"}}),
            '3' => json!({"error": {"code": -32000, "message": "header not found"}}),
            _ => json!({"error": {"code": -32005, "message": "rate limit exceeded"}}),
        },
    }))).await;
    let rpc = Rpc::connect(&[node], CHAIN_ID).await.unwrap();
    let call = |n: u8| rpc.call(0, Block::Number(1), Address::with_last_byte(n), Bytes::from_static(b"\x01\x02\x03\x04"));
    assert!(matches!(call(1).await, Err(ChainError::Revert(d)) if d[..] == [0x08, 0xc3, 0x79, 0xa0]));
    assert!(matches!(call(2).await, Err(ChainError::Revert(d)) if d.is_empty()));
    assert!(matches!(call(3).await, Err(ChainError::Rpc(_))));
    assert!(matches!(call(4).await, Err(ChainError::Rpc(_))));
}

/// Fable R-4: at start, the registry's `generation()` and `chainUid()` on every node equal the configured ones.
#[tokio::test]
async fn start_pins_generation_and_chain_uid() {
    let s = service(world(&[], &[]), all_valid());
    let cfg = Config::parse(CONFIG).unwrap();
    check_pins(&*s.fake, &cfg).await.unwrap();
    s.world().pins.0 = 2;
    let e = check_pins(&*s.fake, &cfg).await.unwrap_err().to_string();
    assert!(e.contains("is generation 2, the config pins 1"), "{e}");
    s.world().pins = (1, B256::repeat_byte(7));
    let e = check_pins(&*s.fake, &cfg).await.unwrap_err().to_string();
    assert!(e.contains("has chainUid"), "{e}");
}

/// A node of chain `CHAIN_ID` whose block 0 has hash `zero` (`None`: a node without block 0).
async fn rpc_with_block_0(zero: Option<B256>) -> String {
    rpc_server(Arc::new(move |r| Some(match r["method"].as_str().unwrap() {
        "eth_chainId" => json!({"result": format!("{CHAIN_ID:#x}")}),
        "eth_getBlockByNumber" => json!({"result": zero.map(|h| json!({"timestamp": "0x1", "difficulty": "0x0", "extraData": "0x",
            "gasLimit": "0x1c9c380", "gasUsed": "0x0", "logsBloom": format!("0x{}", "00".repeat(256)),
            "miner": format!("{:#x}", Address::ZERO), "mixHash": format!("{:#x}", B256::ZERO), "nonce": "0x0000000000000000",
            "receiptsRoot": format!("{:#x}", B256::ZERO), "sha3Uncles": format!("{:#x}", B256::ZERO), "size": "0x200",
            "stateRoot": format!("{:#x}", B256::ZERO), "transactions": [], "transactionsRoot": format!("{:#x}", B256::ZERO),
            "uncles": [], "number": "0x0", "hash": format!("{h:#x}"), "parentHash": format!("{:#x}", B256::ZERO)}))}),
        _ => json!({"error": {"code": -32601, "message": "no such method"}}),
    }))).await
}

/// Fable code review T13 S11 (CLI-RPC-03): the service starts with `Rpc::connect_pinned`: every node's block 0 is the pinned
/// `chain_uid`; a node of another genesis, or one without block 0, and it does not start. Control: two nodes of the pin.
#[tokio::test]
async fn start_pins_block_0() {
    let uid = Config::parse(CONFIG).unwrap().chain_uid;
    let ours = rpc_with_block_0(Some(uid)).await;
    assert_eq!(Rpc::connect_pinned(&[ours.clone(), rpc_with_block_0(Some(uid)).await], CHAIN_ID, uid).await.unwrap().nodes(), 2);
    let e = Rpc::connect_pinned(&[ours.clone(), rpc_with_block_0(Some(B256::repeat_byte(7))).await], CHAIN_ID, uid).await
        .err().expect("another genesis");
    assert!(e.to_string().contains("rpc_urls[1]: chain identity"), "{e}");
    let e = Rpc::connect_pinned(&[rpc_with_block_0(Some(B256::repeat_byte(7))).await], CHAIN_ID, uid).await
        .err().expect("every node of another genesis");
    assert!(e.to_string().contains("rpc_urls[0]: chain identity"), "{e}");
    let e = Rpc::connect_pinned(&[ours, rpc_with_block_0(None).await], CHAIN_ID, uid).await.err().expect("no block 0");
    assert!(e.to_string().contains("serves no block 0"), "{e}");
}

/// Fable C-6: the configured `chain_id` is compared with every endpoint's `eth_chainId` at start; one other chain, or one
/// endpoint that does not answer, and the service does not start.
#[tokio::test]
async fn start_pins_chain_id() {
    let (ours, other) = (rpc_answering(CHAIN_ID).await, rpc_answering(1).await);
    assert_eq!(Rpc::connect(std::slice::from_ref(&ours), CHAIN_ID).await.unwrap().nodes(), 1);
    let e = Rpc::connect(&[ours.clone(), other], CHAIN_ID).await.err().expect("another chain");
    assert!(e.to_string().contains("rpc_urls[1] answers chain 1, the config pins 7622"), "{e}");
    assert!(Rpc::connect(&[ours, "http://127.0.0.1:1".into()], CHAIN_ID).await.is_err(), "an endpoint that does not answer");
    assert!(Config::parse(&CONFIG.replace("chain_id = 7622\n", "")).is_err(), "chain_id is required");
}

/// Fable C-2: the views the service calls are the contract's after group 3h (`ownTag` in the three args tuples): the
/// selectors of the forge artifact `out/IPqzToken.sol/IPqzToken.json` (`methodIdentifiers`, the same pins as the node's
/// `views_are_the_contracts`); the opt-in anvil test reads the artifact itself.
#[test]
fn views_are_the_contracts() {
    use scaas_pqz_verifier::abi::IPqzToken as T;
    // the three-key round: `uFrom` and the two `PqzOpening`s in `PqzTransferArgs`, 0x931415ee -> 0x50f9be2f (the node's pin too)
    assert_eq!(T::transferSingleStatementCall::SELECTOR, hex!("50f9be2f"));
    assert_eq!(T::transferStatementCall::SELECTOR, hex!("8a2161ba"));
    assert_eq!(T::burnStatementCall::SELECTOR, hex!("da8c9eed"));
    assert_eq!(T::unshieldUnwrapStatementCall::SELECTOR, hex!("8e4ccf2e"));
    assert_eq!(T::pqzVerifyConfigCall::SELECTOR, hex!("dc59c66e"));
    assert_eq!(T::proofSystemIdCall::SELECTOR, hex!("1f3b28f2"));
}

/// `smartcontracts/vectors/pqz/<set>/verdict.json` (the contracts' forge writer; T-05: the set's own directory, `pqz/` for
/// n2048-kmax1024): the verifier's digest and signature.
#[test]
fn verdict_vectors() {
    let dir = if stmt::SET == "n2048-kmax1024" { String::new() } else { format!("{}/", stmt::SET) };
    let v = json_file(&format!("{dir}verdict.json"));
    assert_eq!(v["set"], stmt::SET);
    assert_eq!(word(&v["typehash"]), keccak256(PqzVerdict::eip712_encode_type().as_bytes()));
    assert_eq!(word(&v["purposeTag"]), purpose_pqz_verdict());
    assert_eq!(word(&v["proofSystemId"]), B256::from(stmt::PQZL_ID));
    let (d, g) = (&v["domain"], &v["registryDomain"]);
    assert_eq!((d["name"].as_str(), d["version"].as_str()), (Some("SCaaS PqzToken"), Some("1")));
    let (token, chain_id, salt) = (d["verifyingContract"].as_str().unwrap().parse::<Address>().unwrap(),
        U256::from(uint(&d["chainId"])), word(&d["salt"]));
    let reg = Eip712Domain::new(Some("SCaaS UARegistry".into()), Some("1".into()), Some(U256::from(uint(&g["chainId"]))),
        Some(g["verifyingContract"].as_str().unwrap().parse().unwrap()), Some(word(&g["salt"])));
    assert_eq!(reg.separator(), word(&g["separator"]));
    let k = PrivateKeySigner::from_bytes(&B256::from(U256::from(uint(&v["verifierKey"])))).unwrap();
    assert_eq!(k.address().into_word(), word(&v["verifierUA"]));
    let rows = v["rows"].as_array().unwrap();
    assert!(rows.len() > 10);
    for r in rows {
        let pv = PqzVerdict { token, chainId: chain_id, proofSystemId: word(&v["proofSystemId"]),
            statementHash: word(&r["statementHash"]), proofHash: word(&r["proofHash"]),
            pqzVerifierEpoch: uint(&r["pqzVerifierEpoch"]) as u32, validUntil: uint(&r["validUntil"]) };
        assert_eq!(pv.eip712_hash_struct(), word(&r["structHash"]), "{r}");
        let digest = verdict_digest(&pv, salt);
        assert_eq!(digest, word(&r["digest"]), "{r}");
        let auth = ua_auth_digest_at(reg.separator(), k.address().into_word(), purpose_pqz_verdict(), digest);
        assert_eq!(auth, word(&r["uaAuthDigest"]), "{r}");
        // the service's own builder, from the configured values
        let mine = registry_domain(g["version"].as_str().unwrap().parse().unwrap(), uint(&g["chainId"]),
            g["verifyingContract"].as_str().unwrap().parse().unwrap(), word(&g["salt"]));
        assert_eq!(verdict_auth_digest(&mine, k.address().into_word(), digest), auth, "{r}");
        assert_eq!(k.sign_hash_sync(&auth).unwrap().as_bytes().to_vec(), bytes(&r["signature"]), "{r}");
    }
}

// ------------------------------------------------------------------ plan T9: rpc_policy = "strict_majority" (CLI-RPC-12)

/// The service over three fake nodes that answer by hash only, under `strict_majority`.
fn strict_service(w: World, pqz: Pqz) -> Svc {
    let fake = Arc::new(Fake(Mutex::new(World { nodes: 3, by_hash: true, ..w })));
    let cfg = Config::parse(&strict_config()).unwrap();
    let svc = Arc::new(Service::new(fake.clone(), pqz, signer(), &cfg));
    Svc { app: http::router(svc, &cfg), fake }
}

fn strict_config() -> String {
    CONFIG.replace(r#"rpc_urls = ["http://127.0.0.1:1"]"#,
        "rpc_urls = [\"http://127.0.0.1:1\", \"http://127.0.0.1:2\", \"http://127.0.0.1:3\"]\nrpc_policy = \"strict_majority\"")
}

#[tokio::test]
async fn strict_majority_signs_the_honest_answer() {
    let (st, proof) = vector("TRANSFER", None);
    let s = strict_service(world(&st, &[A, B, AUD]), all_valid());
    s.world().lie.insert(2, C);
    assert_signed(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, keccak256(&st), keccak256(&proof));
    assert!(s.world().seen.iter().all(|&(_, b)| b == 100), "every read at the agreed block 100 (Depth(1) of 99, 100, 101)");
    // control: the liar alone under failover is believed when it is the first node
    let f = service(World { nodes: 3, ..world(&st, &[A, B, AUD]) }, all_valid());
    f.world().lie.insert(0, C);
    assert_refused(&verdict(&f, &request(single(A, 0, B), &st, &proof)).await, "KEY_OWNED_ELSEWHERE");
}

#[tokio::test]
async fn two_lying_nodes_refuse_rpc_no_majority_and_sign_nothing() {
    let (st, proof) = vector("TRANSFER", None);
    let s = strict_service(world(&st, &[A, B, AUD]), all_valid());
    s.world().lie.insert(1, C);
    s.world().lie.insert(2, D);
    let r = verdict(&s, &request(single(A, 0, B), &st, &proof)).await;
    assert_refused(&r, "RPC_NO_MAJORITY");
    assert_eq!(r.0, 503);
}

#[tokio::test]
async fn probe_runs_under_agree_too() {
    let s = strict_service(world(&[], &[]), all_valid());
    let probe = || post(&s, "/v1/pqz-verdict/probe", json!({"token": TOKEN, "chainId": CHAIN_ID}).to_string());
    assert_eq!(probe().await.0, 200, "three honest nodes");
    assert!(s.world().seen.iter().all(|&(_, b)| b == 100), "{:?}", s.world().seen);
    s.world().down = HashMap::from([(1, 0), (2, 0)]);
    assert_refused(&probe().await, "RPC_NO_MAJORITY");
}

#[tokio::test]
async fn no_chain_read_after_the_proof_check_under_strict_majority() {
    let (st, proof) = vector("TRANSFER", None);
    let cell: Arc<std::sync::OnceLock<Arc<Fake>>> = Default::default();
    let c2 = cell.clone();
    let pqz: Pqz = Arc::new(move |_: &[u8]| {
        let f = c2.get().unwrap();
        let mut w = f.0.lock().unwrap();
        let n = w.seen.len();
        w.proof_at.push(n);
        Ok(VALID)
    });
    let s = strict_service(world(&st, &[A, B, AUD]), pqz);
    let _ = cell.set(s.fake.clone());
    assert_signed(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, keccak256(&st), keccak256(&proof));
    let w = s.world();
    assert!(!w.proof_at.is_empty(), "the proof and every R_REG ran");
    assert!(w.proof_at.iter().all(|&n| n == w.seen.len()), "every read before the first proof: {:?} of {}", w.proof_at, w.seen.len());
}

#[tokio::test]
async fn the_refusal_is_the_same_under_both_policies() {
    // VERDICT_ZERO before any key refusal (the receiver's key also unstored), KEY_OWNED_ELSEWHERE before KEY_NOT_STORED
    let (st, mut bad_proof) = vector("TRANSFER", None);
    let (_, proof) = vector("TRANSFER", None);
    let n = bad_proof.len() / 2;
    bad_proof[n] ^= 1;
    let h = pqz_key_hash(&st[640 + PK..640 + 2 * PK]);
    for (proof, owned, want) in [(&bad_proof, true, "VERDICT_ZERO"), (&proof, true, "KEY_OWNED_ELSEWHERE"), (&proof, false, "KEY_NOT_STORED")] {
        for strict in [false, true] {
            let mut w = world(&st, &[A, B, AUD]);
            w.keys.remove(&(B, 0));
            if owned {
                w.owner.insert(h, C);
            }
            let s = if strict { strict_service(w, real_op()) } else { service(w, real_op()) };
            assert_refused(&verdict(&s, &request(single(A, 0, B), &st, proof)).await, want);
        }
    }
}

#[tokio::test]
async fn failover_is_the_default() {
    let (st, proof) = vector("TRANSFER", None);
    assert_eq!(Config::parse(CONFIG).unwrap().rpc_policy, scaas_pqz_verifier::RpcPolicy::Failover);
    let s = service(World { nodes: 3, by_hash: true, ..world(&st, &[A, B, AUD]) }, all_valid());
    assert_refused(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, "RPC_UNAVAILABLE");
    let s = service(World { nodes: 3, ..world(&st, &[A, B, AUD]) }, all_valid());
    assert_signed(&verdict(&s, &request(single(A, 0, B), &st, &proof)).await, keccak256(&st), keccak256(&proof));
    assert!(s.world().seen.iter().all(|&r| r == (0, 100)), "today's path: node 0 at its head, by number");
}

#[tokio::test]
async fn strict_majority_with_one_endpoint_is_refused_at_start() {
    let one = CONFIG.replace(r#"rpc_urls = ["http://127.0.0.1:1"]"#, "rpc_urls = [\"http://127.0.0.1:1\"]\nrpc_policy = \"strict_majority\"");
    assert!(Config::parse(&one).unwrap_err().to_string().contains("two rpc_urls or more"));
    assert!(Config::parse(&strict_config()).is_ok(), "control: three");
}

#[tokio::test]
async fn an_unknown_policy_is_refused_at_start() {
    let bad = CONFIG.replace(r#"rpc_urls = ["http://127.0.0.1:1"]"#, "rpc_urls = [\"http://127.0.0.1:1\"]\nrpc_policy = \"majority\"");
    assert!(Config::parse(&bad).is_err());
}

/// Q5 (CLI-RPC-50): the crate's classifier. An execution error without revert data was the node's (a failover) and is now a
/// revert (a refusal by name, its data as bytes: none); a node's own limit stays the node's.
#[tokio::test]
async fn the_classifier_is_the_crates() {
    let node = rpc_server(Arc::new(|r| Some(match r["method"].as_str().unwrap() {
        "eth_chainId" => json!({"result": format!("{CHAIN_ID:#x}")}),
        _ => match r["params"][0]["to"].as_str().unwrap().chars().last().unwrap() {
            '1' => json!({"error": {"code": -32000, "message": "VM execution error."}}),
            '2' => json!({"error": {"code": -32000, "message": "execution aborted (timeout = 5s)"}}),
            _ => json!({"error": {"code": -32000, "message": "eth_call request was canceled due to enabled timeout."}}),
        },
    }))).await;
    let rpc = Rpc::connect(&[node], CHAIN_ID).await.unwrap();
    let call = |n: u8| rpc.call(0, Block::Number(1), Address::with_last_byte(n), Bytes::from_static(b"\x01\x02\x03\x04"));
    assert!(matches!(call(1).await, Err(ChainError::Revert(d)) if d.is_empty()), "an execution error: a revert now");
    assert!(matches!(call(2).await, Err(ChainError::Rpc(_))), "a node's own limit");
    assert!(matches!(call(3).await, Err(ChainError::Rpc(_))), "Nethermind's own timeout");
}
