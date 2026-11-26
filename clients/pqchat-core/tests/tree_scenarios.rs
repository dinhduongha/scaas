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
    /// a commit accepted and not complete: its record in state, no piece yet (`commitOf` answers it, `epochsOf` does not)
    staged: Option<Ep>,
    /// `treeOf.owed`: the live leaves of the UAs gone at the head, owed by the next commit (the contract's)
    owed: u64,
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
            staged: None,
            owed: 0,
        }
    }

    /// Step `st`'s record accepted alone (staged, no piece in state), as a sender that lands the signed record first leaves it.
    fn stage_record(&mut self, st: &Value) {
        let n = |k: &str| st[k].as_array().unwrap().len();
        let none = json!({"mlkemCt": "0x", "x25519Eph": ZERO, "sealedSecret": "0x"});
        let no_wrap = json!({"member": ZERO, "keyId": "0", "mlkemCt": "0x", "x25519Eph": ZERO, "sealedKey": "0x"});
        self.staged = Some(Ep {
            id: st["epochId"].as_str().unwrap().into(),
            record: st["record"].clone(),
            sig: st["sig"].clone(),
            ct_targets: vec![],
            ct_hashes: vec![],
            cts: vec![none; n("cts")],
            node_keys: vec![],
            wraps: vec![no_wrap; n("wraps")],
            leaves: vec![],
            removals: vec![],
        });
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
        self.owed = 0;
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
        let head = self.epochs.len() as u64 - 1;
        for ua in &uas {
            if !self.gone.contains_key(&hx(ua)) {
                self.owed += (0..self.tree.leaves)
                    .filter(|i| self.tree.leaf(*i).is_some_and(|l| l.ua == *ua))
                    .count() as u64;
            }
        }
        self.tree.mark_gone(&uas);
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
        self.epochs
            .iter()
            .chain(self.staged.as_ref())
            .find(|e| e.id == id)
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
            "headEpochId": self.epochs.last().unwrap().id, "owed": self.owed.to_string()})
    }

    /// The contract's answer to `item(args)`, the SDK's named JSON; `None` for an item the home does not serve.
    fn answer(&self, item: &str, a: &Value) -> Option<Value> {
        let idx = |k: &str| a[k].as_str().and_then(|s| s.parse::<usize>().ok());
        // the home holds one session: a view of another answers nothing (the contract's unknown session)
        if a.get("sessionId")
            .is_some_and(|x| x.as_str() != Some(self.sid.as_str()))
        {
            return None;
        }
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
            "IPqChat.childOf" => {
                let id = a["parentEpochId"].as_str()?.to_ascii_lowercase();
                let i = self.epochs.iter().position(|e| e.id == id)?;
                json!({"0": self.epochs.get(i + 1).map_or(ZERO.to_string(), |e| e.id.clone())})
            }
            "IPqChat.epochComplete" => {
                let id = a["epochId"].as_str()?.to_ascii_lowercase();
                json!({"0": self.epochs.iter().any(|e| e.id == id)})
            }
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
            "IUARegistry.kemKeyOf" => {
                let ua = a["ua"].as_str()?;
                let high = self
                    .kems
                    .keys()
                    .filter(|(u, _)| u == ua)
                    .map(|(_, k)| *k)
                    .max()
                    .unwrap_or(0);
                json!({"version": high.to_string()})
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

/// What the home answers for a view of something it does not hold: the contract's revert for a record (`commitOf` of an
/// epoch not stored: `PqChatUnknown`), the model's gap (`Internal`) for anything else.
fn unknown(item: &str) -> PqChatError {
    if item == "IPqChatTreeViews.commitOf" {
        return PqChatError::Sdk(scaas_sdk::SdkError::Rpc(scaas_rpc::RpcError::Revert {
            endpoint: 0,
            data: vec![],
            reason: "PqChatUnknown()".into(),
        }));
    }
    PqChatError::Internal
}

/// The crate's port over a model of the home: every read recorded, every write refused and counted.
struct HomeNet {
    home: Mutex<Home>,
    reads: Mutex<Vec<(String, Value)>>,
    writes: Mutex<usize>,
    /// every write prepared, by item (each refused after it is recorded)
    prepared: Mutex<Vec<String>>,
    tamper: Option<Tamper>,
    /// `read_majority`: the named endpoints the chain lists, and whether the majority's head is the home's
    named: usize,
    majority_agrees: bool,
    /// the majority's own state, when it is another home than the endpoint's (a hidden exit, a twin)
    majority: Option<Mutex<Home>>,
    /// the latest block's state, when it is ahead of the final block's (`read_latest`)
    latest: Option<Mutex<Home>>,
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
            prepared: Mutex::new(vec![]),
            tamper,
            named,
            majority_agrees,
            majority: None,
            latest: None,
        })
    }
    /// The endpoint serves `home`; a strict majority of `named` named endpoints serves `majority`.
    fn split(home: Home, majority: Home, named: usize) -> Arc<Self> {
        Arc::new(HomeNet {
            home: Mutex::new(home),
            reads: Mutex::new(vec![]),
            writes: Mutex::new(0),
            prepared: Mutex::new(vec![]),
            tamper: None,
            named,
            majority_agrees: true,
            majority: Some(Mutex::new(majority)),
            latest: None,
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
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        pqchat_core::net::trust(item)?;
        // the home's views are served by the home only (a tree session has no replica, C4)
        if item.starts_with("IPqChat") && !contract.eq_ignore_ascii_case(common::sdk::HOME) {
            return Err(PqChatError::Internal);
        }
        self.reads
            .lock()
            .unwrap()
            .push((item.to_string(), args.clone()));
        // a view the home does not serve answers nothing, unless a tamper serves it (a forged record)
        let mut v = self
            .home
            .lock()
            .unwrap()
            .answer(item, &args)
            .unwrap_or(Value::Null);
        if let Some(t) = &self.tamper {
            t(item, &args, &mut v);
        }
        if v.is_null() {
            return Err(unknown(item));
        }
        Ok(v)
    }
    async fn prepare(
        &self,
        _: &str,
        _: &str,
        item: &'static str,
        _: Value,
        _: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        *self.writes.lock().unwrap() += 1;
        self.prepared.lock().unwrap().push(item.to_string());
        Err(PqChatError::Internal)
    }
    async fn submit(&self, _: AppCall) -> Result<String, PqChatError> {
        *self.writes.lock().unwrap() += 1;
        Err(PqChatError::Internal)
    }
    async fn read_latest(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        match &self.latest {
            Some(h) => h
                .lock()
                .unwrap()
                .answer(item, &args)
                .ok_or_else(|| unknown(item)),
            None => self.read(chain, contract, item, args).await,
        }
    }
    async fn read_majority(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<(Value, usize), PqChatError> {
        let mut v = match &self.majority {
            Some(m) => {
                pqchat_core::net::trust(item)?;
                m.lock()
                    .unwrap()
                    .answer(item, &args)
                    .ok_or(PqChatError::Internal)?
            }
            None => self.read(chain, contract, item, args).await?,
        };
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
    crate_with(w, net, Arc::new(MemoryStore::new()))
}

/// [`crate_over`] with the device's store `store` (kept across crates: a restart of the same device).
fn crate_with(w: &common::sdk::World, net: Arc<HomeNet>, store: Arc<MemoryStore>) -> Run {
    let pq = PqChat::with_net(w.app.clone(), net, store, common::sdk::conf());
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
    resume(r, v, s, dev, None).await
}

/// [`replay`] resumed from the device's previous replay `from` (spec §10 step 3).
async fn resume(
    r: &Run,
    v: &Value,
    s: &SessionRef,
    dev: &str,
    from: Option<&scaas_sdk::pqchat_tree::PqTreeReplay>,
) -> Result<pqchat_core::tree::TreeState, PqChatError> {
    let d = &v["devices"][dev];
    r.pq.tree_state_vectors(
        s,
        &r.seed,
        &unhex(&d["kemSeed"]),
        d["ua"].as_str().unwrap(),
        u(&d["keyId"]),
        from,
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
            // C22: a replay reads the tree's views only, never an event or a plain view
            for i in net.items() {
                assert!(
                    pqchat_core::tree::TREE_READS.contains(&i.as_str()),
                    "{at}: read {i}"
                );
            }
            n += 1;
        }
    }
    println!("[tree] {n} device replays through the crate equal the vectors");
    assert!(n >= 80, "{n}");
}

/// T6a's hostile reads (each a view the home serves altered): a substituted path ciphertext, a substituted live leaf key, a
/// commit's tree hash, a forged continuation (one more epoch, its record the head's served again under a new id), an epoch-0
/// leaf outside the signed members; each refused by its own check's name before anything opens (C-9, D-16 of the T4-T9
/// review: never the model's gap), nothing written. The unaltered home as control.
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
    let forged = format!("0x{}", "cd".repeat(32));
    let last = sc["steps"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|x| x["gone"].is_null())
        .unwrap()
        .clone();
    let (rec, sig) = (strings(&last["record"]), ua_sig(&last["sig"]));
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
            Box::new(move |i, a, v| {
                let ours = a["epochId"].as_str() == Some(forged.as_str());
                if i == "IPqChat.epochCount" {
                    let n: u64 = v["0"].as_str().unwrap().parse().unwrap();
                    v["0"] = json!((n + 1).to_string());
                } else if i == "IPqChat.epochsOf" {
                    v["0"].as_array_mut().unwrap().push(json!(forged.clone()));
                } else if i == "IPqChatTreeViews.commitOf" && ours {
                    *v = json!({"c": rec.clone(), "sigHash": ZERO});
                } else if i == "IPqChat.epochSig" && ours {
                    *v = json!({ "sig": sig.clone() });
                } else if matches!(i, "IPqChat.leaveCount" | "IPqChat.removalCount") && ours {
                    *v = json!({"0": "0"});
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
    let want = [
        "",
        "TreeReadCorrupted",
        "TreeKemRecord",
        "TreeReadCorrupted",
        "TreeReadCorrupted",
        "TreeReadCorrupted",
    ];
    for ((what, t), want) in cases.into_iter().zip(want) {
        let home = Home::scenario(&v, &sc, None);
        let s = sref(&home);
        let net = HomeNet::with(home, Some(t), 3, true);
        let r = crate_over(&w, net.clone());
        let got = replay(&r, &v, &s, "A").await;
        if what == "control" {
            assert!(got.is_ok(), "control: {:?}", got.err());
        } else {
            let e = got.err().unwrap_or_else(|| panic!("{what}: followed"));
            assert_eq!(e.code(), want, "{what}");
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

/// R13 binds the publisher, not the reader (the review's D-5): a member whose replay meets an admin's changed info gets the
/// state whatever the majority (with 2 named endpoints, or a majority on another head); a device with a pin moves it to the
/// verified head the same way, so neither the reads nor the pin depend on whether `sealedInfo` opened (ARCH-POS-13).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_info_is_taken_whatever_the_majority() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "admin-gap");
    for (named, agrees) in [(3, true), (2, true), (3, false)] {
        let store = Arc::new(MemoryStore::new());
        let older = Home::scenario(&v, &sc, Some(2));
        let (s, tree_id) = (sref(&older), older.tree_id.clone());
        replay(
            &crate_with(&w, HomeNet::new(older), store.clone()),
            &v,
            &s,
            "A",
        )
        .await
        .unwrap();
        let home = Home::scenario(&v, &sc, None);
        let r = crate_with(&w, HomeNet::with(home, None, named, agrees), store.clone());
        let st = replay(&r, &v, &s, "A")
            .await
            .unwrap_or_else(|e| panic!("{named} / {agrees}: {e}"));
        assert!(st
            .replay
            .epochs
            .iter()
            .any(|e| e.info.as_deref() == Some("changed")));
        assert_eq!(
            pinned(&store, &tree_id).unwrap(),
            sc["replays"]["A"]["pin"],
            "{named} / {agrees}: the pin moved to the head"
        );
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

fn scenario(v: &Value, name: &str) -> Value {
    v["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap()
        .clone()
}

/// The pin `store` keeps for `tree_id` (C26).
fn pinned(store: &MemoryStore, tree_id: &str) -> Option<Value> {
    pqchat_core::Items(store)
        .get::<Value>(&format!("tree/pin/{}", tree_id.to_ascii_lowercase()))
        .unwrap()
        .filter(|p| !p.is_null())
}

/// A commit request by the world's wallet key under vector device `dev`'s UA (its build stops where the wallet key is not
/// the device's: what comes before it is what these tests check).
fn commit_req(
    w: &common::sdk::World,
    v: &Value,
    dev: &str,
    info: Option<&str>,
    adds: Vec<Value>,
) -> pqchat_core::tree::TreeCommit {
    pqchat_core::tree::TreeCommit {
        me: pqchat_core::session::Me {
            key: KeyRef::Ua {
                seed: w.seed.clone(),
                kind: common::sdk::KIND,
                account: 0,
                index: 0,
            },
            ua: v["devices"][dev]["ua"].as_str().unwrap().into(),
        },
        key_id: u(&v["devices"][dev]["keyId"]),
        removes: vec![],
        adds,
        admins: vec![],
        info: info.map(str::to_string),
        info_reviewed: false,
        payer: KeyRef::Native {
            seed: w.seed.clone(),
            network: "evm".into(),
            index: 0,
        },
    }
}

/// R13 on the sending side (the T4-T9 review's C-2 = D-1, D-3): a commit that seals a changed info is built only once a
/// strict majority of at least 3 named endpoints serves the `treeOf` the device read, whole (the head, the tree hash and
/// `owed`, so an exit the endpoint hides is seen). With 2 named endpoints, or a majority whose state holds an exit the
/// endpoint hides, `TreeInfoUnconfirmed` before anything is built; 3 that agree: the build goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_info_is_sealed_only_after_the_majority_read() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    let hidden = || {
        let mut h = Home::scenario(&v, &sc, None);
        h.owed = 4;
        h
    };
    for (what, named, majority) in [
        ("2 named endpoints", 2, None),
        (
            "a majority that holds an exit the endpoint hides",
            3,
            Some(hidden()),
        ),
        ("3 named endpoints that agree", 3, None),
    ] {
        let home = Home::scenario(&v, &sc, None);
        let s = sref(&home);
        let net = match majority {
            Some(m) => HomeNet::split(home, m, named),
            None => HomeNet::with(home, None, named, true),
        };
        let r = crate_over(&w, net.clone());
        let st = replay(&r, &v, &s, "A").await.unwrap();
        assert!(
            st.replay.info_to_seal.is_some(),
            "{what}: A holds the info in force"
        );
        net.reads.lock().unwrap().clear();
        let e =
            r.pq.tree_commit(
                &s,
                &st,
                commit_req(&w, &v, "A", Some("{\"stores\":[]}"), vec![]),
                0,
            )
            .await
            .err()
            .unwrap();
        let built = net.items().iter().any(|i| i == "IPqChat.sessionOf");
        if named == 3 && what.ends_with("agree") {
            assert_ne!(e.code(), "TreeInfoUnconfirmed", "{what}");
            assert!(built, "{what}: the build goes on");
        } else {
            assert_eq!(e.code(), "TreeInfoUnconfirmed", "{what}");
            assert!(!built, "{what}: refused before the build");
        }
        assert_eq!(*net.writes.lock().unwrap(), 0, "{what}");
    }
}

/// R13 (R2-D-1 of the T4-T9 re-check): an endpoint that serves the true `treeOf` (its `owed` the removed member's leaf) and
/// hides the removal kept under the head is a lying read: the replay and a commit sealing a changed info (3 named endpoints
/// that agree on `treeOf`) are refused (`TreeHeadRoot`), nothing pinned; the honest endpoint as control.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hidden_exit_under_the_true_tree_of_is_refused() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "pin-exit");
    let head = sc["steps"][0]["epochId"].as_str().unwrap().to_string();
    let honest = Home::scenario(&v, &sc, None);
    assert_eq!(honest.owed, 1, "the removed member's leaf is owed");
    let (s, tree_id) = (sref(&honest), honest.tree_id.clone());
    let r = crate_over(&w, HomeNet::new(honest));
    let st = replay(&r, &v, &s, "A").await.unwrap();
    let hide: Tamper = Box::new(move |i, a, v| {
        if i == "IPqChat.removalCount" && a["epochId"].as_str() == Some(head.as_str()) {
            *v = json!({"0": "0"});
        }
    });
    let store = Arc::new(MemoryStore::new());
    let net = HomeNet::with(Home::scenario(&v, &sc, None), Some(hide), 3, true);
    let r = crate_with(&w, net.clone(), store.clone());
    let e = replay(&r, &v, &s, "A").await.err().map(|e| e.code());
    assert_eq!(e, Some("TreeHeadRoot"), "the replay");
    assert!(pinned(&store, &tree_id).is_none(), "nothing pinned");
    let e =
        r.pq.tree_commit(
            &s,
            &st,
            commit_req(&w, &v, "A", Some("{\"stores\":[]}"), vec![]),
            0,
        )
        .await
        .err()
        .map(|e| e.code());
    assert_eq!(e, Some("TreeHeadRoot"), "the commit");
    assert_eq!(*net.writes.lock().unwrap(), 0);
}

/// R13 / spec §11 before an Add (the review's C-2 = D-1): the majority read is made; a majority of 3 named endpoints that
/// serves another state refuses the Add before anything is built; with 2 named the Add goes on (its review says the head
/// was not confirmed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_add_reads_the_majority_first() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    let add = json!({"leaf": 9, "ua": v["devices"]["E"]["ua"], "keyId": u(&v["devices"]["E"]["keyId"]), "via": ZERO,
        "kemHash": hx(&scaas_ua::keccak256(&unhex(&v["devices"]["E"]["kemPk"])))});
    for (named, agrees, refused) in [(3, false, true), (2, true, false)] {
        let home = Home::scenario(&v, &sc, None);
        let s = sref(&home);
        let net = HomeNet::with(home, None, named, agrees);
        let r = crate_over(&w, net.clone());
        let st = replay(&r, &v, &s, "A").await.unwrap();
        net.reads.lock().unwrap().clear();
        let e =
            r.pq.tree_commit(&s, &st, commit_req(&w, &v, "A", None, vec![add.clone()]), 0)
                .await
                .err()
                .unwrap();
        let built = net.items().iter().any(|i| i == "IPqChat.sessionOf");
        assert_eq!(
            (e.code() == "TreeInfoUnconfirmed", built),
            (refused, !refused),
            "{named} / {agrees}: {}",
            e.code()
        );
    }
}

/// C33, fable-r3-1 (the review's D-10): a commit is built only on the head of the state the device holds; a head that moved
/// since (another commit landed) refuses it by name (`TreeStale`: replay first), before anything is built.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_commit_on_a_state_behind_the_head_is_refused() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    let store = Arc::new(MemoryStore::new());
    let older = Home::scenario(&v, &sc, Some(5));
    let s = sref(&older);
    let r = crate_with(&w, HomeNet::new(older), store.clone());
    let st = replay(&r, &v, &s, "A").await.unwrap();
    let net = HomeNet::new(Home::scenario(&v, &sc, None));
    let r = crate_with(&w, net.clone(), store);
    let e =
        r.pq.tree_commit(&s, &st, commit_req(&w, &v, "A", None, vec![]), 0)
            .await
            .err()
            .unwrap();
    assert_eq!(e.code(), "TreeStale");
    assert!(
        !net.items().iter().any(|i| i == "IPqChat.sessionOf"),
        "refused before the build"
    );
}

/// C26, CLI-PQC-17 (the review's D-2): a device with no verified tree writes its first pin only from a strict-majority read
/// over at least 3 named endpoints; with 2 the replay is returned, nothing pinned; with 3 that agree the pin is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_pin_needs_the_majority() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    for (named, agrees, pins) in [(2, true, false), (3, false, false), (3, true, true)] {
        let home = Home::scenario(&v, &sc, None);
        let (s, tree_id) = (sref(&home), home.tree_id.clone());
        let store = Arc::new(MemoryStore::new());
        let r = crate_with(&w, HomeNet::with(home, None, named, agrees), store.clone());
        replay(&r, &v, &s, "A").await.unwrap();
        assert_eq!(
            pinned(&store, &tree_id).is_some(),
            pins,
            "{named} / {agrees}"
        );
    }
}

/// C26, fable-r3-3, codex-r3-2 (the review's C-5 = D-5): a twin pinned first (the store's pin names the head's number with
/// another record's hash, as after an endpoint served a validly signed losing twin), then the true records served: with 3
/// named endpoints whose majority serves the endpoint's record at that number, the majority's record replaces the pin and
/// the replay is the true one; with 2 named, or a majority that serves another record there, "conflicting head"
/// (`TreeConflict`), the pin kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_twin_at_the_pin_is_settled_by_the_majority() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    let want = sc["replays"]["A"]["pin"].clone();
    let mut twin = want.clone();
    twin["hash"] = json!(format!("0x{}", "5a".repeat(32)));
    let n = u(&want["epoch"]) as usize;
    let mut below = sc["pins"][n - 1].clone();
    below["hash"] = json!(format!("0x{}", "5b".repeat(32)));
    for (what, named, majority_other, settled) in [
        (
            "3 named, the majority serves the endpoint's record",
            3,
            false,
            true,
        ),
        ("2 named", 2, false, false),
        (
            "3 named, the majority serves another record there",
            3,
            true,
            false,
        ),
        ("a twin pinned below the head, 2 named", 2, false, false),
    ] {
        let twin = if what.contains("below") {
            below.clone()
        } else {
            twin.clone()
        };
        let home = Home::scenario(&v, &sc, None);
        let (s, tree_id) = (sref(&home), home.tree_id.clone());
        let store = Arc::new(MemoryStore::new());
        pqchat_core::Items(&*store)
            .update::<Value, _>(
                &format!("tree/pin/{}", tree_id.to_ascii_lowercase()),
                |_| Ok(twin.clone()),
            )
            .unwrap();
        let net = if majority_other {
            let mut m = Home::scenario(&v, &sc, None);
            m.epochs[n].record["sealedInfo"] = json!("0x00");
            HomeNet::split(home, m, named)
        } else {
            HomeNet::with(home, None, named, true)
        };
        let r = crate_with(&w, net, store.clone());
        match (settled, replay(&r, &v, &s, "A").await) {
            (true, Ok(st)) => {
                assert_eq!(st.replay.pin, want, "{what}");
                assert_eq!(pinned(&store, &tree_id).unwrap(), want, "{what}");
            }
            (false, Err(e)) => {
                assert_eq!(e.code(), "TreeConflict", "{what}");
                assert_eq!(
                    pinned(&store, &tree_id).unwrap(),
                    twin,
                    "{what}: the pin kept"
                );
            }
            (want, got) => panic!("{what}: settled {want}, got {:?}", got.err()),
        }
    }
}

/// The vectors' signed commit of step `st` as `scaas-ua` hands it out (its `K` a stand-in handle).
fn signed_of(w: &common::sdk::World, st: &Value) -> scaas_sdk::pqchat_tree::PqTreeCommitSigned {
    let strs = |k: &str| -> Vec<String> {
        st[k]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    };
    scaas_sdk::pqchat_tree::PqTreeCommitSigned {
        record: st["record"].clone(),
        epoch_id: st["epochId"].as_str().unwrap().into(),
        ct_targets: st["ctTargets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| u(x) as u32)
            .collect(),
        ct_hashes: strs("ctHashes"),
        node_keys: st["nodeKeys"]
            .as_array()
            .unwrap()
            .iter()
            .map(unhex)
            .collect(),
        cts: st["cts"].as_array().unwrap().clone(),
        wraps: st["wraps"].as_array().unwrap().clone(),
        sig: scaas_sdk::app_core::AppUaSig {
            key_data: vec![],
            signature: unhex(&st["sig"]),
            members: vec![],
        },
        k: w.app
            .vectors_import(&w.seed, [7; 32], scaas_sdk::app_core::AppKeyUsage::Derive)
            .unwrap(),
    }
}

/// fable-r2-9 (the review's C-1 = B-4 = D-9): a commit planned as one transaction whose record another sender landed alone is
/// not complete: the next send is the list through the piece entries; the control, the epoch complete, sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_landed_alone_is_not_complete() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    let step = &sc["steps"][1];
    let c = signed_of(&w, step);
    let plan = scaas_sdk::pqchat_tree::PqTreePlan {
        txs: vec![scaas_sdk::pqchat_tree::PqTreeTx {
            entry: "commit",
            first: 0,
            count: 0,
            gas: Default::default(),
        }],
        completion: Default::default(),
        dearest_last: Default::default(),
    };
    let payer = KeyRef::Native {
        seed: w.seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    for staged in [true, false] {
        let mut home = Home::scenario(&v, &sc, Some(if staged { 1 } else { 2 }));
        if staged {
            home.stage_record(step);
        }
        let s = sref(&home);
        let net = HomeNet::new(home);
        let r = crate_over(&w, net.clone());
        let got = r.pq.tree_next(&s, &c, &plan, &payer).await;
        let prepared = net.prepared.lock().unwrap().clone();
        if staged {
            assert_eq!(
                prepared,
                vec!["IPqChat.addPathList".to_string()],
                "{:?}",
                got.err()
            );
        } else {
            assert!(matches!(got, Ok(None)), "complete: {:?}", got.err());
            assert!(prepared.is_empty());
        }
    }
}

/// R11 (C-3, D-8 of the review): a tree epoch opened from the replay carries the info in force there (main's A: a Matrix room
/// only, no chain store), and a receipt under it sends nothing by default, whatever the store list says (mode 0 would send
/// one with no chain store listed); the epoch before it is its parent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tree_epoch_sends_no_receipt_by_default() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    let home = Home::scenario(&v, &sc, None);
    let s = sref(&home);
    let r = crate_over(&w, HomeNet::new(home));
    let st = replay(&r, &v, &s, "A").await.unwrap();
    let head = st.replay.epochs.last().unwrap();
    let ep = r.pq.tree_open(&s, &st, &head.epoch_id).unwrap();
    assert_eq!(ep.epoch.parent, st.ids[head.epoch as usize - 1]);
    let ep = r.pq.use_epoch(&s, ep).await.unwrap();
    let info = r.pq.info(&ep).unwrap();
    assert_eq!(
        info.with(|b| String::from_utf8(b.to_vec()).unwrap()),
        head.in_force.clone().unwrap()
    );
    r.pq.accept(&s, false).unwrap();
    let me = pqchat_core::session::Me {
        key: KeyRef::Ua {
            seed: w.seed.clone(),
            kind: common::sdk::KIND,
            account: 0,
            index: 0,
        },
        ua: v["devices"]["A"]["ua"].as_str().unwrap().into(),
    };
    let rc = pqchat_core::content::Content::Receipt {
        target: format!("0x{}", "42".repeat(32)),
    };
    let o = pqchat_core::stores::SendOpts {
        payer: KeyRef::Native {
            seed: w.seed.clone(),
            network: "evm".into(),
            index: 0,
        },
        post: false,
        post_cost_confirmed: false,
    };
    let got = r.pq.send_content(&s, &me, &rc, None, &o).await.unwrap();
    assert_eq!((got.message_id, got.stores.len()), (None, 0));
}

/// D-6 of the review: a head that moves while a resumed replay's views are read makes the crate read them again before it
/// resumes (never a resume thrown away after it took the device's node keys): every epoch after the previous replay is
/// followed as a full replay follows it, and the replay it resumed from keeps its node keys until then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_head_that_moves_during_a_resume_keeps_every_epoch_followed() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    let older = Home::scenario(&v, &sc, Some(3));
    let s = sref(&older);
    let prev = replay(&crate_over(&w, HomeNet::new(older)), &v, &s, "A")
        .await
        .unwrap();
    let full = replay(
        &crate_over(&w, HomeNet::new(Home::scenario(&v, &sc, None))),
        &v,
        &s,
        "A",
    )
    .await
    .unwrap();
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
    let net = HomeNet::with(Home::scenario(&v, &sc, None), Some(t), 3, true);
    let r = crate_over(&w, net);
    let st = resume(&r, &v, &s, "A", Some(&prev.replay)).await.unwrap();
    assert!(*n.lock().unwrap() >= 4, "the views read again");
    let states = |x: &pqchat_core::tree::TreeState, from: u64| -> Vec<(u64, String)> {
        x.replay
            .epochs
            .iter()
            .filter(|e| e.epoch > from)
            .map(|e| (e.epoch, e.state.clone()))
            .collect()
    };
    let from = prev.head;
    assert_eq!(states(&st, from), states(&full, from));
    // C-8, D-13: a resume reads the records from the previous pin on, not the whole history
    let net = HomeNet::new(Home::scenario(&v, &sc, None));
    let r = crate_over(&w, net.clone());
    resume(&r, &v, &s, "A", Some(&prev.replay)).await.unwrap();
    let commits = net
        .items()
        .iter()
        .filter(|i| *i == "IPqChatTreeViews.commitOf")
        .count();
    assert!(
        commits <= (full.head - from + 1) as usize,
        "{commits} records read"
    );
    assert!(
        states(&st, from).iter().all(|(_, x)| x == "followed"),
        "{:?}",
        states(&st, from)
    );
}

/// R16, spec §15, codex-r3-9 (the review's D-15, the plan's lookup tests): the Add warning finds a candidate's key at an
/// older, non-latest version (B's key 3 of 8), drops a candidate whose keys do not hold it, never names the added UA itself,
/// and answers "not found among N" for a UA outside the candidates, every version of each scanned (none above 64).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_add_warnings_lookup() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let home = Home::scenario(&v, &scenario(&v, "main"), None);
    let r = crate_over(&w, HomeNet::new(home));
    let ua = |d: &str| v["devices"][d]["ua"].as_str().unwrap().to_string();
    let kh = hx(&scaas_ua::keccak256(&unhex(&v["devices"]["B3"]["kemPk"])));
    let chain = common::sdk::CHAIN;
    let got =
        r.pq.tree_add_check(chain, &ua("A"), &kh, &[ua("B"), ua("C"), ua("A")], &[])
            .await
            .unwrap();
    assert_eq!(
        (got.held_by, got.checked, got.not_covered),
        (vec![(ua("B").to_ascii_lowercase(), 3)], 2, vec![])
    );
    let none =
        r.pq.tree_add_check(chain, &ua("A"), &kh, &[ua("C")], &[])
            .await
            .unwrap();
    assert_eq!(
        (none.held_by.len(), none.checked),
        (0, 1),
        "not found among 1"
    );
}

/// C35, CLI-PQC-17 (the review's C-3): a send under a tree epoch whose child is complete at home asks for a replay
/// (`EpochTaken`), never a send under the old epoch; C9, D2-4 (C-10): a tree leave naming an epoch more than 16 below the
/// head is `ExitLag` before anything is signed, one naming the head is signed and prepared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tree_send_meets_its_child_and_an_exit_its_lag() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    let home = Home::scenario(&v, &sc, None);
    let s = sref(&home);
    let r = crate_over(&w, HomeNet::new(home));
    let st = replay(&r, &v, &s, "A").await.unwrap();
    let older = st
        .replay
        .epochs
        .iter()
        .rev()
        .find(|e| e.epoch < st.head && e.state == "followed")
        .unwrap();
    let ep = r.pq.tree_open(&s, &st, &older.epoch_id).unwrap();
    r.pq.use_epoch(&s, ep).await.unwrap();
    r.pq.accept(&s, false).unwrap();
    let me = pqchat_core::session::Me {
        key: KeyRef::Ua {
            seed: w.seed.clone(),
            kind: common::sdk::KIND,
            account: 0,
            index: 0,
        },
        ua: v["devices"]["A"]["ua"].as_str().unwrap().into(),
    };
    let payer = KeyRef::Native {
        seed: w.seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let o = pqchat_core::stores::SendOpts {
        payer: payer.clone(),
        post: false,
        post_cost_confirmed: false,
    };
    let text = pqchat_core::content::Content::Text {
        media_type: None,
        body: "under an older epoch".into(),
    };
    let e =
        r.pq.send_content(&s, &me, &text, None, &o)
            .await
            .err()
            .unwrap();
    assert_eq!(e.code(), "EpochTaken");
    let lag = scenario(&v, "lag");
    let home = Home::scenario(&v, &lag, None);
    let (s, first, head) = (
        sref(&home),
        home.epochs[0].id.clone(),
        home.epochs.last().unwrap().id.clone(),
    );
    let net = HomeNet::new(home);
    let r = crate_over(&w, net.clone());
    let e =
        r.pq.tree_leave(&s, &me, &first, 1, &payer)
            .await
            .err()
            .unwrap();
    assert_eq!(e.code(), "ExitLag");
    assert!(net.prepared.lock().unwrap().is_empty(), "nothing prepared");
    let _ = r.pq.tree_leave(&s, &me, &head, 1, &payer).await;
    assert_eq!(
        *net.prepared.lock().unwrap(),
        vec!["IPqChat.treeLeave".to_string()]
    );
}

/// D-14 (C-11) of the review: a record landed at the latest block and not final is waited for (`EpochNotFinal`), never
/// prepared again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_landed_not_final_is_not_sent_again() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    let step = &sc["steps"][1];
    let c = signed_of(&w, step);
    let plan = scaas_sdk::pqchat_tree::PqTreePlan {
        txs: vec![scaas_sdk::pqchat_tree::PqTreeTx {
            entry: "commit",
            first: 0,
            count: 0,
            gas: Default::default(),
        }],
        completion: Default::default(),
        dearest_last: Default::default(),
    };
    let home = Home::scenario(&v, &sc, Some(1));
    let s = sref(&home);
    let mut latest = Home::scenario(&v, &sc, Some(1));
    latest.stage_record(step);
    let net = Arc::new(HomeNet {
        home: Mutex::new(home),
        reads: Mutex::new(vec![]),
        writes: Mutex::new(0),
        prepared: Mutex::new(vec![]),
        tamper: None,
        named: 3,
        majority_agrees: true,
        majority: None,
        latest: Some(Mutex::new(latest)),
    });
    let r = crate_over(&w, net.clone());
    let payer = KeyRef::Native {
        seed: w.seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let e = r.pq.tree_next(&s, &c, &plan, &payer).await.err().unwrap();
    assert_eq!(e.code(), "EpochNotFinal");
    assert!(net.prepared.lock().unwrap().is_empty());
}

/// C26 (the plan's hostile row, D-16 of the review): a head below the device's checkpoint is refused (`TreeCheckpoint`), the
/// pin kept, nothing written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_head_below_the_checkpoint_is_refused() {
    let _one = common::sdk::ONE.lock().await;
    let w = common::sdk::world().await;
    let v = vectors();
    let sc = scenario(&v, "main");
    let home = Home::scenario(&v, &sc, Some(4));
    let (s, tree_id) = (sref(&home), home.tree_id.clone());
    let store = Arc::new(MemoryStore::new());
    let pin = sc["replays"]["A"]["pin"].clone();
    pqchat_core::Items(&*store)
        .update::<Value, _>(
            &format!("tree/pin/{}", tree_id.to_ascii_lowercase()),
            |_| Ok(pin.clone()),
        )
        .unwrap();
    let net = HomeNet::new(home);
    let r = crate_with(&w, net.clone(), store.clone());
    let e = replay(&r, &v, &s, "A").await.err().unwrap();
    assert_eq!(e.code(), "TreeCheckpoint");
    assert_eq!(pinned(&store, &tree_id).unwrap(), pin);
    assert_eq!(*net.writes.lock().unwrap(), 0);
}
