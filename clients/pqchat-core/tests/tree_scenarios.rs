// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan 2026-11-23-pqchat-treekem T6a, T6b (feature `vectors`): the crate's tree mode over a model of the home that answers
//! the contract's views by their ABI names (`IPqChat`, `IPqChatTreeViews`, `IUARegistry`), built from
//! `smartcontracts/vectors/pqchat/tree-secrets.json`'s scenarios (the trees by `ua-rs`'s public tree, the records, pieces,
//! signatures and KEM records as the vectors give them). Recovery from state for every scenario's every device (codex-11,
//! codex-r3-1: the late joiner, the removed and the retired keys), the hostile reads refused before anything opens and with
//! nothing sent, the trace of a failed open equal to its control's (ARCH-POS-13), R13's majority read, one snapshot per
//! state (fable-r3-9). UNAUDITED.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use async_trait::async_trait;
use pqchat_core::net::Net;
use pqchat_core::reads::SessionRef;
use pqchat_core::{MemoryStore, PqChat, PqChatError};
use scaas_sdk::app_core::AppCall;
use scaas_sdk::op::KeyRef;
use scaas_ua::wallet::tree_public::{Changes, Leaf, Node, Remove, Tree};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const ZERO: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const ALL: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../smartcontracts/vectors/pqchat/tree-secrets.json"
    ))
    .unwrap()
}
fn hx(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}
fn unhex(v: &Value) -> Vec<u8> {
    alloy::hex::decode(v.as_str().unwrap()).unwrap()
}
fn a32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().unwrap()
}
fn u(v: &Value) -> u64 {
    v.as_u64().unwrap()
}
/// Numbers as the SDK's named JSON gives them (decimal strings).
fn strings(v: &Value) -> Value {
    match v {
        Value::Number(n) => json!(n.to_string()),
        Value::Array(a) => Value::Array(a.iter().map(strings).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), strings(x))).collect()),
        x => x.clone(),
    }
}
/// A vector signature as the contract keeps it: a `UASig` of named fields.
fn ua_sig(sig: &Value) -> Value {
    match sig {
        Value::String(s) => json!({"keyData": "0x", "signature": s, "members": []}),
        v => {
            let m = unhex(&v["members"]);
            let members = if m.is_empty() {
                vec![]
            } else {
                scaas_ua::ua_portable::decode_member_sigs(&m).unwrap()
            };
            json!({"keyData": "0x", "signature": v["signature"], "members": members.iter().map(|x| json!({
                "index": x.index.to_string(), "sig": hx(&x.sig),
                "members": x.members.iter().map(|i| json!({"index": i.index.to_string(), "sig": hx(&i.sig)})).collect::<Vec<_>>()
            })).collect::<Vec<_>>()})
        }
    }
}

struct Ep {
    id: String,
    record: Value,
    sig: Value,
    ct_targets: Vec<Value>,
    ct_hashes: Vec<Value>,
    cts: Vec<Value>,
    node_keys: Vec<Value>,
    wraps: Vec<Value>,
    leaves: Vec<(Value, Value)>,
    removals: Vec<(Value, Value)>,
}

/// A model of the home (as `ua-rs`'s tests' `Home`), answering by the contract's views.
struct Home {
    sid: String,
    tree_id: String,
    tree: Tree,
    genesis_tree_hash: String,
    epochs: Vec<Ep>,
    join: BTreeMap<u32, (u64, u64)>,
    node_key: BTreeMap<u32, (String, u64)>,
    gone: BTreeMap<String, (u64, u64)>,
    periods: BTreeMap<String, (u64, u64)>,
    kems: BTreeMap<(String, u64), (String, String)>,
    signers: BTreeMap<String, (u16, String)>,
    msigs: BTreeMap<(String, u64), (Vec<u8>, String)>,
}

impl Home {
    fn new(v: &Value, sc: &Value) -> Home {
        let g = &sc["genesis"];
        let rec = &g["record"];
        let kems: BTreeMap<(String, u64), (String, String)> = v["devices"]
            .as_object()
            .unwrap()
            .values()
            .map(|d| {
                (
                    (d["ua"].as_str().unwrap().to_string(), u(&d["keyId"])),
                    (
                        d["kemPk"].as_str().unwrap().to_string(),
                        d["kemSig"].as_str().unwrap().to_string(),
                    ),
                )
            })
            .collect();
        let cold: Vec<Leaf> = rec["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| {
                let pk = &kems[&(m["ua"].as_str().unwrap().to_string(), u(&m["keyId"]))].0;
                Leaf {
                    ua: a32(&m["ua"]),
                    key_id: u(&m["keyId"]),
                    kem_hash: scaas_ua::keccak256(&unhex(&json!(pk))),
                }
            })
            .collect();
        let tree = Tree::cold(&cold).unwrap();
        let mut msigs = BTreeMap::new();
        let mut signers = BTreeMap::new();
        for r in v["signers"].as_array().unwrap() {
            let ua = r["ua"].as_str().unwrap().to_string();
            signers.insert(
                ua.clone(),
                (
                    u(&r["kind"]) as u16,
                    r["keyData"].as_str().unwrap().to_string(),
                ),
            );
            for x in r["versions"].as_array().into_iter().flatten() {
                msigs.insert(
                    (ua.clone(), u(&x["version"])),
                    (
                        unhex(&x["msig"]),
                        x["enabled"].as_str().unwrap().to_string(),
                    ),
                );
            }
        }
        Home {
            sid: g["sessionId"].as_str().unwrap().into(),
            tree_id: g["treeId"].as_str().unwrap().into(),
            genesis_tree_hash: hx(&tree.tree_hash()),
            tree,
            epochs: vec![Ep {
                id: g["sessionId"].as_str().unwrap().into(),
                record: rec.clone(),
                sig: g["sig"].clone(),
                ct_targets: vec![],
                ct_hashes: vec![],
                cts: vec![],
                node_keys: vec![],
                wraps: g["wraps"].as_array().unwrap().clone(),
                leaves: vec![],
                removals: vec![],
            }],
            join: (0..cold.len() as u32)
                .map(|i| (i, (0, u64::from(i))))
                .collect(),
            node_key: BTreeMap::new(),
            gone: BTreeMap::new(),
            periods: BTreeMap::new(),
            kems,
            signers,
            msigs,
        }
    }

    /// The scenario landed up to `upto` steps (all when `None`).
    fn scenario(v: &Value, sc: &Value, upto: Option<usize>) -> Home {
        let mut h = Home::new(v, sc);
        let steps = sc["steps"].as_array().unwrap();
        for st in steps.iter().take(upto.unwrap_or(steps.len())) {
            if st["gone"].is_null() {
                h.land_commit(st);
            } else {
                h.land_gone(&st["gone"]);
            }
        }
        h
    }

    fn land_commit(&mut self, st: &Value) {
        let c = &st["record"];
        let nkh: Vec<[u8; 32]> = c["nodeKeyHashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(a32)
            .collect();
        let a = self
            .tree
            .apply_commit(&Changes::from_json(c).unwrap(), &nkh)
            .unwrap();
        let epoch = u(&c["epoch"]);
        for r in c["removes"].as_array().unwrap() {
            let r = Remove::from_json(r).unwrap();
            let k = self.tree.leaf(r.leaf).unwrap().clone();
            let wide =
                a.tree.gone_key.contains(&k.kem_hash) && !self.tree.gone_key.contains(&k.kem_hash);
            let j = self.join.remove(&r.leaf).unwrap().0;
            let key = if wide {
                format!("wide/{}", hx(&k.kem_hash))
            } else {
                format!("pair/{}/{}", hx(&k.ua), hx(&k.kem_hash))
            };
            self.periods.insert(key, (j, epoch));
        }
        for (i, x) in c["adds"].as_array().unwrap().iter().enumerate() {
            self.join.insert(u(&x["leaf"]) as u32, (epoch, i as u64));
        }
        self.node_key.retain(|x, _| *a.tree.node(*x) != Node::Blank);
        let targets: Vec<u32> = st["ctTargets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| u(x) as u32)
            .collect();
        let path = scaas_ua::wallet::tree::path_from_list(
            u(&c["leaf"]) as u32,
            &targets,
            u(&c["leaves"]) as u32,
        )
        .unwrap_or_default();
        for (k, x) in path.iter().enumerate() {
            self.node_key
                .insert(*x, (st["nodeKeys"][k].as_str().unwrap().to_string(), epoch));
        }
        self.tree = a.tree;
        self.epochs.push(Ep {
            id: st["epochId"].as_str().unwrap().into(),
            record: c.clone(),
            sig: st["sig"].clone(),
            ct_targets: st["ctTargets"].as_array().unwrap().clone(),
            ct_hashes: st["ctHashes"].as_array().unwrap().clone(),
            cts: st["cts"].as_array().unwrap().clone(),
            node_keys: st["nodeKeys"].as_array().unwrap().clone(),
            wraps: st["wraps"].as_array().unwrap().clone(),
            leaves: vec![],
            removals: vec![],
        });
        for ua in self.tree.gone_ua.clone() {
            self.gone.entry(hx(&ua)).or_insert((2, epoch));
        }
    }

    fn land_gone(&mut self, g: &Value) {
        let kind = u(&g["kind"]);
        let uas: Vec<[u8; 32]> = if kind == 1 {
            vec![a32(&g["record"]["member"])]
        } else {
            g["record"]["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(a32)
                .collect()
        };
        self.tree.mark_gone(&uas);
        let head = self.epochs.len() as u64 - 1;
        for ua in uas {
            self.gone.entry(hx(&ua)).or_insert((kind, head));
        }
        let mut kept = g["record"].clone();
        kept.as_object_mut().unwrap().remove("treeId");
        let e = self.epochs.last_mut().unwrap();
        let list = if kind == 1 {
            &mut e.leaves
        } else {
            &mut e.removals
        };
        list.push((kept, g["sig"].clone()));
    }

    fn ep(&self, id: &Value) -> Option<&Ep> {
        let id = id.as_str()?.to_ascii_lowercase();
        self.epochs.iter().find(|e| e.id == id)
    }

    fn period(&self, k: &str) -> Value {
        match self.periods.get(k) {
            Some((j, e)) => {
                json!({"gone": true, "joinEpoch": j.to_string(), "endEpoch": e.to_string()})
            }
            None => json!({"gone": false, "joinEpoch": "0", "endEpoch": "0"}),
        }
    }

    fn tree_of(&self) -> Value {
        json!({"treeId": self.tree_id, "leaves": self.tree.leaves.to_string(), "used": self.tree.used.to_string(),
            "treeHash": hx(&self.tree.tree_hash()), "genesisTreeHash": self.genesis_tree_hash,
            "headEpochId": self.epochs.last().unwrap().id, "owed": "0"})
    }

    /// The contract's answer to `item(args)`, the SDK's named JSON; `None` for an item the home does not serve.
    fn answer(&self, item: &str, a: &Value) -> Option<Value> {
        let idx = |k: &str| a[k].as_str().and_then(|s| s.parse::<usize>().ok());
        Some(match item {
            "IPqChat.sessionOf" => json!({"s": strings(&self.epochs[0].record), "sigHash": ZERO}),
            "IPqChat.sessionSig" => json!({"sig": ua_sig(&self.epochs[0].sig)}),
            "IPqChat.epochCount" => json!({"0": self.epochs.len().to_string()}),
            "IPqChat.epochsOf" => {
                let (o, l) = (idx("offset")?, idx("limit")?);
                json!({"0": self.epochs.iter().skip(o).take(l).map(|e| e.id.clone()).collect::<Vec<_>>()})
            }
            "IPqChatTreeViews.commitOf" => {
                json!({"c": strings(&self.ep(&a["epochId"])?.record), "sigHash": ZERO})
            }
            "IPqChat.epochSig" => json!({"sig": ua_sig(&self.ep(&a["epochId"])?.sig)}),
            "IPqChatTreeViews.pathListOf" => {
                let e = self.ep(&a["epochId"])?;
                json!({"ctTargets": strings(&json!(e.ct_targets)), "ctHashes": e.ct_hashes})
            }
            "IPqChatTreeViews.pathKeys" => json!({"0": self.ep(&a["epochId"])?.node_keys}),
            "IPqChatTreeViews.pathCtAt" => {
                json!({"0": self.ep(&a["epochId"])?.cts.get(idx("i")?)?})
            }
            "IPqChat.wrapAt" => {
                json!({"0": strings(self.ep(&a["epochId"])?.wraps.get(idx("i")?)?)})
            }
            "IPqChat.leaveCount" => json!({"0": self.ep(&a["epochId"])?.leaves.len().to_string()}),
            "IPqChat.removalCount" => {
                json!({"0": self.ep(&a["epochId"])?.removals.len().to_string()})
            }
            "IPqChat.leaveAt" => {
                json!({"l": strings(&self.ep(&a["epochId"])?.leaves.get(idx("index")?)?.0), "sigHash": ZERO})
            }
            "IPqChat.leaveSig" => {
                json!({"sig": ua_sig(&self.ep(&a["epochId"])?.leaves.get(idx("index")?)?.1)})
            }
            "IPqChat.removalAt" => {
                json!({"r": strings(&self.ep(&a["epochId"])?.removals.get(idx("index")?)?.0), "sigHash": ZERO})
            }
            "IPqChat.removalSig" => {
                json!({"sig": ua_sig(&self.ep(&a["epochId"])?.removals.get(idx("index")?)?.1)})
            }
            "IPqChat.epochComplete" => json!({"0": self.ep(&a["epochId"]).is_some()}),
            "IPqChatTreeViews.goneOf" => {
                let (k, e) = self.gone.get(a["ua"].as_str()?).copied().unwrap_or((0, 0));
                json!({"kind": k.to_string(), "epoch": e.to_string()})
            }
            "IPqChatTreeViews.goneKeyOf" => {
                self.period(&format!("wide/{}", a["kemHash"].as_str()?))
            }
            "IPqChatTreeViews.goneOwnKeyOf" => self.period(&format!(
                "pair/{}/{}",
                a["ua"].as_str()?,
                a["kemHash"].as_str()?
            )),
            "IPqChatTreeViews.treeOf" => self.tree_of(),
            "IPqChatTreeViews.treeLeaves" => {
                let (f, n) = (idx("first")?, idx("count")?);
                let leaves: Vec<Value> = (0..self.tree.used)
                    .map(|i| match self.tree.leaf(i) {
                        Some(l) => {
                            let (j, w) = self.join[&i];
                            json!({"ua": hx(&l.ua), "keyId": l.key_id.to_string(), "joinEpoch": j.to_string(),
                                "wrapIndex": w.to_string(), "kemHash": hx(&l.kem_hash)})
                        }
                        None => json!({"ua": ZERO, "keyId": "0", "joinEpoch": "0", "wrapIndex": "0", "kemHash": ZERO}),
                    })
                    .skip(f)
                    .take(n)
                    .collect();
                json!({ "0": leaves })
            }
            "IPqChatTreeViews.treeNodes" => {
                let (f, n) = (idx("first")?, idx("count")?);
                let nodes: Vec<Value> = self
                    .tree
                    .node_hashes()
                    .iter()
                    .enumerate()
                    .map(|(x, h)| {
                        let kh = match self.tree.node(x as u32) {
                            Node::Parent(k) => hx(k),
                            _ => ZERO.into(),
                        };
                        let e = self.node_key.get(&(x as u32)).map_or(0, |n| n.1);
                        json!({"hash": hx(h), "keyHash": kh, "epoch": e.to_string()})
                    })
                    .skip(f)
                    .take(n)
                    .collect();
                json!({ "0": nodes })
            }
            "IPqChatTreeViews.treeNodeKey" => {
                json!({"0": self.node_key.get(&(idx("node")? as u32)).map_or("0x".to_string(), |n| n.0.clone())})
            }
            "IUARegistry.kemKeyAt" => {
                let k = (
                    a["ua"].as_str()?.to_string(),
                    a["version"].as_str()?.parse::<u64>().ok()?,
                );
                match self.kems.get(&k) {
                    Some((pk, sig)) => {
                        json!({"kem": {"scheme": "1", "mlkemEk": format!("0x{}", &pk[4..4 + 3136]),
                        "x25519": format!("0x{}", &pk[4 + 3136..])}, "sig": sig})
                    }
                    None => {
                        json!({"kem": {"scheme": "0", "mlkemEk": "0x", "x25519": ZERO}, "sig": "0x"})
                    }
                }
            }
            "IUARegistry.registrationOf" => match self.signers.get(a["ua"].as_str()?) {
                Some((kind, kd)) => {
                    json!({"kind": kind.to_string(), "keyData": kd, "attrs": {"pqzKey": "0x",
                    "pqzPopHash": ZERO, "kem": {"scheme": "0", "mlkemEk": "0x", "x25519": ZERO}, "kemPkHash": ZERO},
                    "pop": "0x", "pqzPop": "0x"})
                }
                None => {
                    json!({"kind": "0", "keyData": "0x", "attrs": {"pqzKey": "0x", "pqzPopHash": ZERO,
                    "kem": {"scheme": "0", "mlkemEk": "0x", "x25519": ZERO}, "kemPkHash": ZERO}, "pop": "0x", "pqzPop": "0x"})
                }
            },
            "IUARegistry.msigStateOf" => json!({"version": "0", "enabled": ALL, "accepted": ALL}),
            "IUARegistry.msigAt" => {
                let k = (
                    a["ua"].as_str()?.to_string(),
                    a["version"].as_str()?.parse::<u64>().ok()?,
                );
                match self.msigs.get(&k) {
                    Some((kd, en)) => {
                        let s = scaas_ua::ua_portable::MsigStructure::from_key_data(kd).unwrap();
                        let enabled =
                            alloy::primitives::U256::from_str_radix(&en[2..], 16).unwrap();
                        json!({"s": {"threshold": s.threshold.to_string(), "members": s.members.iter().map(|m| json!({
                            "kind": m.kind.to_string(), "id": hx(&m.id), "weight": m.weight.to_string()})).collect::<Vec<_>>()},
                            "enabled": enabled.to_string()})
                    }
                    None => json!({"s": {"threshold": "0", "members": []}, "enabled": "0"}),
                }
            }
            _ => return None,
        })
    }
}

type Tamper = Box<dyn Fn(&str, &Value, &mut Value) + Send + Sync>;

/// The crate's port over a model of the home: every read recorded, every write refused and counted.
struct HomeNet {
    home: Mutex<Home>,
    reads: Mutex<Vec<(String, Value)>>,
    writes: Mutex<usize>,
    tamper: Option<Tamper>,
    /// `read_majority`: the named endpoints the chain lists, and whether the majority's head is the home's
    named: usize,
    majority_agrees: bool,
}

impl HomeNet {
    fn new(home: Home) -> Arc<Self> {
        Self::with(home, None, 3, true)
    }
    fn with(home: Home, tamper: Option<Tamper>, named: usize, majority_agrees: bool) -> Arc<Self> {
        Arc::new(HomeNet {
            home: Mutex::new(home),
            reads: Mutex::new(vec![]),
            writes: Mutex::new(0),
            tamper,
            named,
            majority_agrees,
        })
    }
    fn items(&self) -> Vec<String> {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.0.clone())
            .collect()
    }
}

#[async_trait]
impl Net for HomeNet {
    async fn read(
        &self,
        _: &str,
        _: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        pqchat_core::net::trust(item)?;
        self.reads
            .lock()
            .unwrap()
            .push((item.to_string(), args.clone()));
        let mut v = self
            .home
            .lock()
            .unwrap()
            .answer(item, &args)
            .ok_or(PqChatError::Internal)?;
        if let Some(t) = &self.tamper {
            t(item, &args, &mut v);
        }
        Ok(v)
    }
    async fn prepare(
        &self,
        _: &str,
        _: &str,
        _: &'static str,
        _: Value,
        _: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        *self.writes.lock().unwrap() += 1;
        Err(PqChatError::Internal)
    }
    async fn submit(&self, _: AppCall) -> Result<String, PqChatError> {
        *self.writes.lock().unwrap() += 1;
        Err(PqChatError::Internal)
    }
    async fn read_majority(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<(Value, usize), PqChatError> {
        let mut v = self.read(chain, contract, item, args).await?;
        if !self.majority_agrees {
            v["headEpochId"] = json!(format!("0x{}", "ab".repeat(32)));
        }
        Ok((v, self.named))
    }
}

struct Run {
    pq: Arc<PqChat>,
    seed: String,
}

/// The crate over `net`, in the one SDK world's scope (one live PqChat scope at a time), with a fresh store.
fn crate_over(w: &common::sdk::World, net: Arc<HomeNet>) -> Run {
    let pq = PqChat::with_net(
        w.app.clone(),
        net,
        Arc::new(MemoryStore::new()),
        common::sdk::conf(),
    );
    Run {
        pq,
        seed: w.seed.clone(),
    }
}

fn sref(h: &Home) -> SessionRef {
    SessionRef {
        chain: common::sdk::CHAIN.into(),
        home: common::sdk::HOME.into(),
        session_id: h.sid.clone(),
    }
}

/// The replay of device `dev` through the crate, as the vectors' row shapes it.
async fn replay(
    r: &Run,
    v: &Value,
    s: &SessionRef,
    dev: &str,
) -> Result<pqchat_core::tree::TreeState, PqChatError> {
    let d = &v["devices"][dev];
    r.pq.tree_state_vectors(
        s,
        &r.seed,
        &unhex(&d["kemSeed"]),
        d["ua"].as_str().unwrap(),
        u(&d["keyId"]),
    )
    .await
}

fn rows(st: &pqchat_core::tree::TreeState) -> (Value, Value, Value) {
    let states: Vec<Value> = st
        .replay
        .epochs
        .iter()
        .map(|e| match e.state.strip_prefix("not followed: ") {
            Some(why) => json!([e.epoch, "not followed", why]),
            None => json!([e.epoch, e.state, null]),
        })
        .collect();
    let info: Vec<Value> = st
        .replay
        .epochs
        .iter()
        .map(|e| json!([e.info, e.in_force, e.flagged]))
        .collect();
    let warnings: Vec<Value> = st
        .replay
        .warnings
        .iter()
        .map(|w| {
            json!({"epoch": w.epoch,
                "adds": w.adds.iter().map(|(l, ua, k)| json!({"leaf": l, "ua": ua, "keyId": k})).collect::<Vec<_>>(),
                "removes": w.removes, "adminsChanged": w.admins_changed, "leavesLeft": w.leaves_left})
        })
        .collect();
    (json!(states), json!(info), json!(warnings))
}

/// T6b's gate (codex-11, codex-r3-1): every scenario's every device replays through the crate from state alone (a fresh
/// store) to the vectors' leaf, join, end, states, info, warnings and pin; no write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_every_scenario_device() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let mut n = 0;
    for sc in v["scenarios"].as_array().unwrap() {
        let name = sc["name"].as_str().unwrap();
        for (dev, want) in sc["replays"].as_object().unwrap() {
            let home = Home::scenario(&v, sc, None);
            let s = sref(&home);
            let net = HomeNet::new(home);
            let r = crate_over(&w, net.clone());
            let st = replay(&r, &v, &s, dev)
                .await
                .unwrap_or_else(|e| panic!("{name} / {dev}: {e}"));
            let at = format!("{name} / {dev}");
            assert_eq!(json!(st.replay.leaf), want["leaf"], "{at} leaf");
            assert_eq!(json!(st.replay.join_epoch), want["joinEpoch"], "{at} join");
            assert_eq!(json!(st.replay.end_epoch), want["endEpoch"], "{at} end");
            let (states, info, warnings) = rows(&st);
            assert_eq!(states, want["states"], "{at} states");
            assert_eq!(info, want["info"], "{at} info");
            assert_eq!(warnings, want["warnings"], "{at} warnings");
            assert_eq!(st.replay.pin, want["pin"], "{at} pin");
            assert_eq!(*net.writes.lock().unwrap(), 0, "{at}: a write");
            n += 1;
        }
    }
    println!("[tree] {n} device replays through the crate equal the vectors");
    assert!(n >= 80, "{n}");
}

/// T6a's hostile reads (each a view the home serves altered): a substituted node key, a substituted live leaf key, a
/// commit's tree hash, a forged continuation (one more epoch), an epoch-0 leaf outside the signed members; each refused
/// before anything opens, nothing written. The unaltered home as control.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_reads_are_refused() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = v["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "main")
        .unwrap()
        .clone();
    let flip = |x: &mut Value| {
        let mut b = unhex(x);
        *b.last_mut().unwrap() ^= 1;
        *x = json!(hx(&b));
    };
    let cases: Vec<(&str, Tamper)> = vec![
        ("control", Box::new(|_, _, _| {})),
        (
            "a substituted path ciphertext",
            Box::new(move |i, _, v| {
                if i == "IPqChatTreeViews.pathCtAt"
                    && v["0"]["sealedSecret"].as_str().is_some_and(|s| s.len() > 2)
                {
                    flip(&mut v["0"]["sealedSecret"])
                }
            }),
        ),
        (
            "a substituted leaf key",
            Box::new(move |i, _, v| {
                if i == "IUARegistry.kemKeyAt" && v["kem"]["x25519"] != ZERO {
                    flip(&mut v["kem"]["x25519"])
                }
            }),
        ),
        (
            "a commit's tree hash",
            Box::new(move |i, _, v| {
                if i == "IPqChatTreeViews.commitOf" {
                    flip(&mut v["c"]["treeHash"])
                }
            }),
        ),
        (
            "a forged continuation",
            Box::new(|i, _, v| {
                if i == "IPqChat.epochCount" {
                    let n: u64 = v["0"].as_str().unwrap().parse().unwrap();
                    v["0"] = json!((n + 1).to_string());
                } else if i == "IPqChat.epochsOf" {
                    v["0"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!(format!("0x{}", "cd".repeat(32))));
                }
            }),
        ),
        (
            "an epoch-0 leaf outside the signed members",
            Box::new(|i, _, v| {
                if i == "IPqChat.sessionOf" {
                    v["s"]["members"].as_array_mut().unwrap().pop();
                }
            }),
        ),
    ];
    for (what, t) in cases {
        let home = Home::scenario(&v, &sc, None);
        let s = sref(&home);
        let net = HomeNet::with(home, Some(t), 3, true);
        let r = crate_over(&w, net.clone());
        let got = replay(&r, &v, &s, "A").await;
        if what == "control" {
            assert!(got.is_ok(), "control: {:?}", got.err());
        } else {
            let e = got.err().unwrap_or_else(|| panic!("{what}: followed"));
            assert!(
                matches!(
                    e.code(),
                    "TreeReadCorrupted"
                        | "TreeKeyHash"
                        | "TreeKemRecord"
                        | "TreeReads"
                        | "Internal"
                ),
                "{what}: {}",
                e.code()
            );
        }
        assert_eq!(*net.writes.lock().unwrap(), 0, "{what}: a write");
    }
}

/// ARCH-POS-13 (the trace test, codex-3, fable-8): a device whose opening of an epoch failed (a validly signed bad
/// ciphertext: `gap`'s E at epoch 1) reads what the same device reads where it opens (`gap-control`): the same views in
/// the same order, a later poll (from the pin) the same again, and sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_open_reads_as_a_followed_one() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let trace = |name: &str| {
        let sc = v["scenarios"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == name)
            .unwrap()
            .clone();
        let home = Home::scenario(&v, &sc, None);
        let s = sref(&home);
        let net = HomeNet::new(home);
        (crate_over(&w, net.clone()), net, s)
    };
    async fn run(
        v: &Value,
        r: &Run,
        net: &HomeNet,
        s: &SessionRef,
    ) -> (Value, Vec<String>, Vec<String>) {
        let st = replay(r, v, s, "E").await.unwrap();
        let first = net.items();
        net.reads.lock().unwrap().clear();
        replay(r, v, s, "E").await.unwrap();
        let again = net.items();
        assert_eq!(*net.writes.lock().unwrap(), 0, "a send");
        (rows(&st).0, first, again)
    }
    let (r, net, s) = trace("gap");
    let (failed, f1, f2) = run(&v, &r, &net, &s).await;
    let (r, net, s) = trace("gap-control");
    let (opened, c1, c2) = run(&v, &r, &net, &s).await;
    assert_eq!(failed[1][2], "opening failed", "{failed}");
    assert_eq!(opened[1][1], "followed", "{opened}");
    assert_eq!(f1, c1, "the failed open's reads are the followed one's");
    // a later poll starts at the stored pin: the same reads for both again, and fewer than the first
    assert_eq!(f2, c2, "a later poll's reads are the followed one's too");
    assert!(f2.len() < f1.len(), "the later poll starts at the pin");
}

/// R13: an epoch whose info changed is taken only once a strict majority of at least 3 named endpoints confirms the head:
/// with 2 named endpoints, or a majority that disagrees, `TreeInfoUnconfirmed`; with 3 that agree it is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_info_needs_the_majority() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = v["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "admin-gap")
        .unwrap()
        .clone();
    for (named, agrees, ok) in [(3, true, true), (2, true, false), (3, false, false)] {
        let home = Home::scenario(&v, &sc, None);
        let s = sref(&home);
        let net = HomeNet::with(home, None, named, agrees);
        let r = crate_over(&w, net);
        let got = replay(&r, &v, &s, "A").await;
        match (ok, got) {
            (true, Ok(st)) => assert!(st
                .replay
                .epochs
                .iter()
                .any(|e| e.info.as_deref() == Some("changed"))),
            (false, Err(e)) => assert_eq!(e.code(), "TreeInfoUnconfirmed", "{named} / {agrees}"),
            (ok, got) => panic!("{named} / {agrees}: want ok {ok}, got {:?}", got.err()),
        }
    }
}

/// fable-r3-9: the views of one replay are of one state; a head that moves while they are read (the second `treeOf`
/// differs) makes the crate read them all again, and the replay is the one of the state it settled on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_snapshot_per_state() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = v["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "main")
        .unwrap()
        .clone();
    let home = Home::scenario(&v, &sc, None);
    let s = sref(&home);
    let n = Arc::new(Mutex::new(0usize));
    let m = n.clone();
    let t: Tamper = Box::new(move |i, _, v| {
        if i == "IPqChatTreeViews.treeOf" {
            let mut k = m.lock().unwrap();
            *k += 1;
            if *k == 2 {
                v["treeHash"] = json!(format!("0x{}", "ee".repeat(32)));
            }
        }
    });
    let net = HomeNet::with(home, Some(t), 3, true);
    let r = crate_over(&w, net.clone());
    let st = replay(&r, &v, &s, "A").await.unwrap();
    assert_eq!(json!(st.replay.pin), sc["replays"]["A"]["pin"]);
    assert!(
        *n.lock().unwrap() >= 4,
        "treeOf read again after the moved head: {}",
        n.lock().unwrap()
    );
}

/// C3's size hint: proposed from 7 member keys where several commit; never enforced.
#[test]
fn the_size_hint() {
    assert!(!pqchat_core::tree::tree_advised(6, 3));
    assert!(!pqchat_core::tree::tree_advised(8, 1));
    assert!(pqchat_core::tree::tree_advised(7, 2));
}

/// codex-r3-7 (C33): a device that holds no info in force (heal's A: a gap) seals a new info only as the admin's reviewed
/// action: unreviewed, `TreeInfoReview` before any read or signature; reviewed, the commit goes on to be built.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_info_after_a_gap_needs_its_review() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = v["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "heal")
        .unwrap()
        .clone();
    let home = Home::scenario(&v, &sc, None);
    let s = sref(&home);
    let net = HomeNet::new(home);
    let r = crate_over(&w, net.clone());
    let st = replay(&r, &v, &s, "A").await.unwrap();
    assert!(
        st.replay.info_to_seal.is_none(),
        "heal's A holds no info in force"
    );
    let me = pqchat_core::session::Me {
        key: KeyRef::Ua {
            seed: w.seed.clone(),
            kind: common::sdk::KIND,
            account: 0,
            index: 0,
        },
        ua: v["devices"]["A"]["ua"].as_str().unwrap().into(),
    };
    let commit = |reviewed: bool| pqchat_core::tree::TreeCommit {
        me: me.clone(),
        key_id: 1,
        removes: vec![],
        adds: vec![],
        admins: vec![],
        info: Some("{\"stores\":[]}".into()),
        info_reviewed: reviewed,
        payer: KeyRef::Native {
            seed: w.seed.clone(),
            network: "evm".into(),
            index: 0,
        },
    };
    let reads = net.items().len();
    let e =
        r.pq.tree_commit(&s, &st, commit(false), 0)
            .await
            .err()
            .unwrap();
    assert_eq!(e.code(), "TreeInfoReview");
    assert_eq!(net.items().len(), reads, "refused before any read");
    let e =
        r.pq.tree_commit(&s, &st, commit(true), 0)
            .await
            .err()
            .map(|e| e.code());
    assert_ne!(e, Some("TreeInfoReview"), "reviewed: built further");
    assert_eq!(*net.writes.lock().unwrap(), 0);
}
