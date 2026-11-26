// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! TreeKEM in `ua-rs` (plan T2 of docs/superpowers/plans/2026-11-23-pqchat-treekem.md): every row of
//! `smartcontracts/vectors/pqchat/tree.json` (the public side, `wallet::tree_public`) and of `tree-secrets.json` (the secrets
//! behind handles, `wallet::tree`) reproduced byte for byte, the scenarios landed on a model of the home and every device's
//! replay compared with its row: states, `K`, the info in force, the warnings and the reads in order; the tree's signing
//! operations (every signature the rows carry reproduced through prepare → review → sign) and the registry KEM record check
//! before an encapsulation (`smartcontracts/vectors/ua/portable.json`). Feature `app-core,vectors`.
#![cfg(all(feature = "app-core", feature = "vectors"))]
use scaas_ua::ua_portable::{kem_record_digest, kem_record_message, KemKey, UAAttrs};
use scaas_ua::wallet::derive::{ua_key_data, ua_secret};
use scaas_ua::wallet::kem::x25519;
use scaas_ua::wallet::tree::{
    key_of, path_context, tree_prepare, tree_prepare_leave, tree_prepare_remove, warn_at,
    CommitInput, CtAt, EpochFields, Info, InfoTook, PathCt, PathlessInput, Pin, PreparedCommit,
    State, TargetKey, TreeDevice, TreeLeave, TreeReader, TreeRemove, View, ADD_NONCE_TRIES,
    PATHLESS_WARN_LEAVES, PQCHAT_TREE,
};
use scaas_ua::wallet::tree_public::{
    array_hash, ct_targets_hash, genesis_ctx, kem_admission, kem_record_key, leaf_hash,
    path_list_hash, struct_hash, tree_id, Add, Changes, KemRecord, Leaf, Node, Remove, Tree, ZERO,
};
use scaas_ua::wallet::{
    pqchat, tree_public as tp, AppKeys, Error, ExternalKey, KemKeyPair, KeyRef, KeyUsage,
    SignRequest, Wallet,
};
use scaas_ua::{keccak256, ua_message, ua_of};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const MLDSA65: u16 = 0x0131;
const SC: &scaas_ua::wallet::tree::TreeScope = &PQCHAT_TREE;
const MNEMONIC: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

fn pq(f: &str) -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/pqchat/{f}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn a32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().unwrap()
}
fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}
fn u(v: &Value) -> u64 {
    v.as_u64().unwrap()
}
fn keys() -> (Wallet, AppKeys) {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k = w.app_keys();
    (w, k)
}
/// `rnd(name, n)` of the generator: the first n bytes of keccak256("scaas/pqchat/vectors/<name>/0") ‖ ….
fn rnd(name: &str, n: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::new();
    for i in 0..n.div_ceil(32) {
        out.extend(keccak256(
            format!("scaas/pqchat/vectors/{name}/{i}").as_bytes(),
        ));
    }
    out.truncate(n);
    Zeroizing::new(out)
}
fn code<T>(r: scaas_ua::wallet::Result<T>) -> String {
    match r {
        Ok(_) => "accepted".into(),
        Err(e) => e.code().into(),
    }
}
/// A tree's JSON as `tree.json` writes it (with `nodeHashes`, `treeHash`).
fn tree_json(t: &Tree) -> Value {
    let mut j = t.to_json();
    let o = j.as_object_mut().unwrap();
    o.insert(
        "nodeHashes".into(),
        json!(t.node_hashes().iter().map(|h| hx(h)).collect::<Vec<_>>()),
    );
    o.insert("treeHash".into(), json!(hx(&t.tree_hash())));
    j
}

// ------------------------------------------------------------------ the leaf bound (R8)

/// R8 (owner 2026-11-25, 256 -> 512): a cold tree of 512 leaf positions (depth 9) is built and 513 refused; on the full tree
/// leaf 0's cold path is 9 node keys and 511 targets; an Add at position 512 is a Leaf refusal and, after a Remove frees
/// position 511, an Add there lands (the control).
#[test]
fn tree_leaf_bound_512() {
    let leaf = |i: u32| {
        let mut ua = [0u8; 32];
        ua[28..].copy_from_slice(&(i + 1).to_be_bytes());
        Leaf {
            ua,
            key_id: 1,
            kem_hash: keccak256(&ua),
        }
    };
    let full: Vec<Leaf> = (0..512).map(leaf).collect();
    assert_eq!(
        code(Tree::cold(&(0..513).map(leaf).collect::<Vec<_>>())),
        "PqChatShape"
    );
    let t = Tree::cold(&full).unwrap();
    assert_eq!(t.filtered_path(0).len(), 9);
    assert_eq!(t.ct_targets(0).len(), 511);
    let by = |removes: Vec<Remove>, adds: Vec<Add>| Changes {
        author: full[0].ua,
        leaf: 0,
        key_id: 1,
        removes,
        adds,
        pathless: false,
    };
    let add = |at: u32| {
        let n = leaf(600);
        vec![Add {
            leaf: at,
            ua: n.ua,
            key_id: 1,
            via: ZERO,
            kem_hash: n.kem_hash,
        }]
    };
    let nk = vec![[7u8; 32]; 9];
    assert_eq!(
        code(t.apply_commit(&by(vec![], add(512)), &nk)),
        "PqChatTreeLeaf"
    );
    let rm = vec![Remove {
        leaf: 511,
        ua: full[511].ua,
        key_id: 1,
    }];
    let freed = t.apply_commit(&by(rm, vec![]), &nk).unwrap().tree;
    let back = freed.apply_commit(&by(vec![], add(511)), &nk).unwrap();
    assert_eq!(back.tree.leaves, 512);
}

// ------------------------------------------------------------------ tree.json

#[test]
fn tree_json_every_row() {
    let v = pq("tree");
    // type strings: our struct alone + its nested ones encode to the vector's, and its hash
    let ty = &v["typehashes"];
    for (name, row) in ty.as_object().unwrap() {
        assert_eq!(
            hx(&keccak256(row["type"].as_str().unwrap().as_bytes())),
            row["hash"],
            "{name}"
        );
    }
    assert_eq!(
        leaf_hash(
            0,
            &Leaf {
                ua: ZERO,
                key_id: 0,
                kem_hash: ZERO
            }
        ),
        {
            let t = a32(&ty["TreeLeaf"]["hash"]);
            keccak256(&[&t[..], &[0; 128]].concat())
        }
    );
    let mut g = serde_json::Map::new();
    for f in tp::GENESIS_FIELDS {
        g.insert(f.into(), v["digests"]["session"][f].clone());
    }
    assert_eq!(
        pqchat::typed("TreeGenesis", Value::Object(g))
            .unwrap()
            .encode_type(),
        ty["TreeGenesis"]["type"]
    );
    // the keys and their admission
    let keys: BTreeMap<String, Value> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| (k["name"].as_str().unwrap().into(), k.clone()))
        .collect();
    for k in keys.values() {
        assert_eq!(kem_admission(&unhex(&k["kemPk"])), None);
        assert_eq!(hx(&keccak256(&unhex(&k["kemPk"]))), k["kemHash"]);
    }
    let leaf_of = |n: &Value| Leaf::from_json(&keys[n.as_str().unwrap()]).unwrap();
    // RFC 9420's tree math
    for r in v["treeMath"]["rows"].as_array().unwrap() {
        let n = u(&r["n_leaves"]) as u32;
        assert_eq!(tp::node_width(n) as u64, u(&r["n_nodes"]));
        assert_eq!(tp::root(n) as u64, u(&r["root"]));
        for x in 0..u(&r["n_nodes"]) as u32 {
            let opt = |o: Option<u32>| o.map_or(Value::Null, |y| json!(y));
            assert_eq!(opt(tp::left(x)), r["left"][x as usize], "left {n} {x}");
            assert_eq!(opt(tp::right(x)), r["right"][x as usize], "right {n} {x}");
            assert_eq!(
                opt(tp::parent(x, n)),
                r["parent"][x as usize],
                "parent {n} {x}"
            );
            assert_eq!(
                opt(tp::sibling(x, n)),
                r["sibling"][x as usize],
                "sibling {n} {x}"
            );
        }
    }
    // resolution, the filtered path, ctTargets, the cover
    for r in v["resolution"].as_array().unwrap() {
        let t = Tree::vectors_from_json(&r["tree"]).unwrap();
        assert_eq!(tree_json(&t), r["tree"], "{}", r["name"]);
        for (x, want) in r["resolution"].as_array().unwrap().iter().enumerate() {
            assert_eq!(json!(t.resolution(x as u32)), *want);
        }
        for (leaf, want) in r["filteredPath"].as_object().unwrap() {
            let p = t.filtered_path(leaf.parse().unwrap());
            let got: Vec<Value> = p
                .iter()
                .map(|s| json!({"node": s.node, "child": s.child, "targets": s.targets}))
                .collect();
            assert_eq!(json!(got), *want);
        }
        for (leaf, want) in r["ctTargets"].as_object().unwrap() {
            assert_eq!(json!(t.ct_targets(leaf.parse().unwrap())), *want);
        }
        for c in r["cover"].as_array().unwrap() {
            let got = t
                .cover_of(u(&c["author"]) as u32, u(&c["leaf"]) as u32)
                .unwrap();
            assert_eq!(
                json!({"author": c["author"], "leaf": c["leaf"], "index": got.index, "level": got.level, "node": got.node, "target": got.target}),
                *c
            );
        }
    }
    // the cold trees, the commits applied, the refusals
    let mut trees: BTreeMap<String, Tree> = BTreeMap::new();
    for r in v["treeHash"]["cold"].as_array().unwrap() {
        let t = Tree::cold(
            &r["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(leaf_of)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(tree_json(&t), r["tree"], "{}", r["name"]);
        trees.insert(r["name"].as_str().unwrap().into(), t);
    }
    let nkh = |c: &Value| {
        c["nodeKeyHashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(a32)
            .collect::<Vec<_>>()
    };
    // the resolution rows' trees are before trees too (the commit at depth 9, F-5)
    for r in v["resolution"].as_array().unwrap() {
        trees.insert(
            r["name"].as_str().unwrap().into(),
            Tree::vectors_from_json(&r["tree"]).unwrap(),
        );
    }
    let mut deep = false;
    for r in v["treeHash"]["commits"].as_array().unwrap() {
        deep |= r["name"] == "a commit at depth 9 (F-5)"
            && r["after"]["leaves"] == 512
            && r["commit"]["nodeKeyHashes"].as_array().unwrap().len() == 9;
        let before = trees[r["before"].as_str().unwrap()].clone();
        let a = before
            .apply_commit(
                &Changes::from_json(&r["commit"]).unwrap(),
                &nkh(&r["commit"]),
            )
            .unwrap();
        assert_eq!(json!(a.ct_targets), r["ctTargets"], "{}", r["name"]);
        assert_eq!(hx(&ct_targets_hash(&a.ct_targets)), r["ctTargetsHash"]);
        assert_eq!(tree_json(&a.tree), r["after"], "{}", r["name"]);
        trees.insert(r["name"].as_str().unwrap().into(), a.tree);
    }
    assert!(deep, "the commit at depth 9");
    for r in v["treeHash"]["refused"].as_array().unwrap() {
        let before = &trees[r["before"].as_str().unwrap()];
        let got = code(before.apply_commit(
            &Changes::from_json(&r["commit"]).unwrap(),
            &nkh(&r["commit"]),
        ));
        assert_eq!(got, r["error"], "{}", r["name"]);
    }
    // the admission check
    let adm = &v["admission"];
    let mut accepted = BTreeMap::new();
    for r in adm["accepted"].as_array().unwrap() {
        assert_eq!(kem_admission(&unhex(&r["kemPk"])), None, "{}", r["name"]);
        assert_eq!(hx(&keccak256(&unhex(&r["kemPk"]))), r["kemHash"]);
        accepted.insert(r["name"].as_str().unwrap().to_string(), unhex(&r["kemPk"]));
    }
    for r in adm["refused"].as_array().unwrap() {
        assert_eq!(
            kem_admission(&unhex(&r["kemPk"])),
            Some(r["error"].as_str().unwrap()),
            "{}",
            r["name"]
        );
        assert!(matches!(
            tp::admit_kem_key(&unhex(&r["kemPk"])),
            Err(Error::KemCheck)
        ));
        assert!(
            accepted.contains_key(r["twin"].as_str().unwrap()),
            "{}",
            r["name"]
        );
    }
    let rel = &adm["related"];
    let eph = a32(&rel["ephemeral"]);
    let px = |k: &[u8]| -> [u8; 32] { k[1569..].try_into().unwrap() };
    assert_eq!(
        hx(&x25519(&eph, &px(&accepted[rel["base"].as_str().unwrap()]))[..]),
        rel["x25519Output"]
    );
    for s in rel["shifted"].as_array().unwrap() {
        assert_eq!(kem_admission(&unhex(&s["kemPk"])), None);
        assert_eq!(hx(&keccak256(&unhex(&s["kemPk"]))), s["kemHash"]);
        assert_eq!(
            hx(&x25519(&eph, &px(&unhex(&s["kemPk"])))[..]),
            s["x25519Output"]
        );
        assert_eq!(s["x25519Output"], rel["x25519Output"]);
    }
    // the no-return sets (R16): each step's tree, each probe's verdict on it
    for r in v["noReturn"].as_array().unwrap() {
        let mut t = Tree::cold(
            &r["start"]
                .as_array()
                .unwrap()
                .iter()
                .map(leaf_of)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        for s in r["steps"].as_array().unwrap() {
            if let Some(l) = s.get("leave") {
                t.mark_gone(&l.as_array().unwrap().iter().map(a32).collect::<Vec<_>>());
            // a landed treeLeave / treeRemove
            } else {
                t = t
                    .apply_commit(
                        &Changes::from_json(&s["commit"]).unwrap(),
                        &nkh(&s["commit"]),
                    )
                    .unwrap()
                    .tree;
            }
            assert_eq!(tree_json(&t), s["tree"], "{} / {}", r["name"], s["name"]);
            for p in s["probes"].as_array().unwrap() {
                let got = code(t.apply_commit(
                    &Changes::from_json(&p["commit"]).unwrap(),
                    &nkh(&p["commit"]),
                ));
                assert_eq!(got, p["verdict"], "{} / {}", s["name"], p["name"]);
            }
        }
    }
    // the digests
    let d = &v["digests"];
    let sid = SC.session_id(&a32(&d["session"]["creator"]), u(&d["session"]["nonce"]));
    assert_eq!(hx(&sid), d["sessionId"]);
    assert_eq!(
        hx(&tree_id(pqchat::typed, &d["session"]).unwrap()),
        d["treeId"]
    );
    assert_eq!(
        hx(&genesis_ctx(pqchat::typed, &d["session"]).unwrap()),
        d["genesisCtx"]
    );
    let mut nogm = d["session"].clone();
    nogm.as_object_mut().unwrap().remove("groupMode");
    assert_eq!(code(genesis_ctx(pqchat::typed, &nogm)), "PqChatShape");
    let c = &d["records"][0]["record"];
    assert_eq!(
        hx(&SC.epoch_id(&a32(&c["sessionId"]), &a32(&c["author"]), u(&c["nonce"]))),
        d["epochId"]
    );
    let arr = |x: &Value| x.as_array().unwrap().clone();
    assert_eq!(
        hx(&array_hash(pqchat::typed, "TreeRemove", &arr(&c["removes"])).unwrap()),
        d["removesHash"]
    );
    assert_eq!(
        hx(&array_hash(pqchat::typed, "TreeAdd", &arr(&c["adds"])).unwrap()),
        d["addsHash"]
    );
    let targets: Vec<u32> = arr(&d["ctTargets"]).iter().map(|x| u(x) as u32).collect();
    let hashes: Vec<[u8; 32]> = arr(&d["ctHashes"]).iter().map(a32).collect();
    let pl = d["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["struct"] == "PathList")
        .unwrap();
    assert_eq!(
        hx(&path_list_hash(pqchat::typed, &targets, &hashes).unwrap()),
        pl["structHash"]
    );
    assert_eq!(
        hx(&path_list_hash(pqchat::typed, &[], &[]).unwrap()),
        d["emptyPathList"]
    );
    for r in d["records"].as_array().unwrap() {
        let name = r["struct"].as_str().unwrap();
        let td = pqchat::typed(name, r["record"].clone()).unwrap();
        assert_eq!(td.encode_type(), ty[name]["type"], "{name}");
        assert_eq!(
            hx(&struct_hash(pqchat::typed, name, &r["record"]).unwrap()),
            r["structHash"],
            "{name}"
        );
        if !r["typed"].is_null() {
            // a signed record: its typed digest and what its signer signs
            assert_eq!(hx(&td.digest().unwrap()), r["typed"], "{name}");
            let m = ua_message(MLDSA65, &pqchat::purpose(), &td.digest().unwrap()).unwrap();
            assert_eq!(hx(&m), r["signedDigest"], "{name}");
        }
        // a tree record is signed only by the tree's own operations (plan T2): no generic PqChat signing entry takes it
        assert!(!pqchat::RECORDS.contains(&name));
    }
}

// ------------------------------------------------------------------ a model of the home (clientkeys `newHome`, `reader`)

struct Epoch {
    id: [u8; 32],
    record: Value,
    sig: Value,
    ct_targets: Vec<u32>,
    ct_hashes: Vec<Value>,
    cts: Vec<Value>,
    wraps: Vec<Value>,
    /// the exits kept under this epoch, as `leaveAt` / `removalAt` serve them: `{record (without treeId), sig}`
    leaves: Vec<Value>,
    removals: Vec<Value>,
}

/// `msigAt(ua, version)` answers: `(ua, version)` → `(structure, enabled)` (CTR-UA-74).
type MsigVersions = BTreeMap<([u8; 32], u64), (Vec<u8>, [u8; 32])>;

struct Home {
    tree_id: [u8; 32],
    tree: Tree,
    genesis_tree_hash: [u8; 32],
    epochs: Vec<Epoch>,
    join: BTreeMap<u32, (u64, u64)>,
    node_key: BTreeMap<u32, (Vec<u8>, u64)>,
    gone: BTreeMap<[u8; 32], (u64, u64)>,
    periods: BTreeMap<String, (u64, u64)>,
    /// the registry's KEM records (`kemKeyAt` serves `{kemPk, sig}` of each, C-1)
    kems: BTreeMap<([u8; 32], u64), KemRecord>,
    ua_keys: BTreeMap<[u8; 32], (u16, Vec<u8>)>,
    /// an updated `msig`'s structures by version, `msigAt` (CTR-UA-74)
    msig: MsigVersions,
    log: Vec<String>,
    /// the contract's `treeOf.owed`: the live leaves of the UAs gone at the head, owed by the next commit
    owed: u64,
}

impl Home {
    fn land_commit(&mut self, st: &Value) {
        let c = &st["record"];
        let nkh: Vec<[u8; 32]> = c["nodeKeyHashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(a32)
            .collect();
        assert_eq!(u(&c["epoch"]), self.epochs.len() as u64);
        let a = self
            .tree
            .apply_commit(&Changes::from_json(c).unwrap(), &nkh)
            .unwrap();
        assert_eq!(hx(&a.tree_hash), c["treeHash"]);
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
            self.node_key.insert(*x, (unhex(&st["nodeKeys"][k]), epoch));
        }
        self.tree = a.tree;
        self.owed = 0;
        self.epochs.push(Epoch {
            id: a32(&st["epochId"]),
            record: c.clone(),
            sig: st["sig"].clone(),
            ct_targets: targets,
            ct_hashes: st["ctHashes"].as_array().unwrap().clone(),
            cts: st["cts"].as_array().unwrap().clone(),
            wraps: st["wraps"].as_array().unwrap().clone(),
            leaves: vec![],
            removals: vec![],
        });
        for ua in self.tree.gone_ua.clone() {
            self.gone.entry(ua).or_insert((2, epoch));
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
            if !self.gone.contains_key(ua) {
                self.owed += (0..self.tree.leaves)
                    .filter(|i| self.tree.leaf(*i).is_some_and(|l| l.ua == *ua))
                    .count() as u64;
            }
        }
        self.tree.mark_gone(&uas);
        for ua in uas {
            self.gone.entry(ua).or_insert((kind, head));
        }
        let mut kept = g["record"].clone();
        kept.as_object_mut().unwrap().remove("treeId");
        let e = self.epochs.last_mut().unwrap();
        let list = if kind == 1 {
            &mut e.leaves
        } else {
            &mut e.removals
        };
        list.push(json!({"record": kept, "sig": g["sig"]}));
    }
    fn period(&self, k: &str) -> Value {
        match self.periods.get(k) {
            Some((j, e)) => json!({"gone": true, "joinEpoch": j, "endEpoch": e}),
            None => json!({"gone": false, "joinEpoch": 0, "endEpoch": 0}),
        }
    }
}

impl TreeReader for Home {
    fn read(&mut self, v: View) -> scaas_ua::wallet::Result<Value> {
        self.log.push(v.to_string());
        let z = hx(&ZERO);
        let ep = |n: u64| self.epochs.get(n as usize).ok_or(Error::Argument);
        Ok(match v {
            View::SessionOf => json!({"record": self.epochs[0].record, "sig": self.epochs[0].sig}),
            View::TreeOf => json!({"treeId": hx(&self.tree_id), "leaves": self.tree.leaves, "used": self.tree.used,
                "treeHash": hx(&self.tree.tree_hash()), "genesisTreeHash": hx(&self.genesis_tree_hash),
                "sincePath": self.tree.since_path,
                "owed": self.owed}),
            View::TreeLeaves => json!((0..self.tree.leaves)
                .map(|i| match self.tree.leaf(i) {
                    Some(l) => {
                        let (j, w) = self.join[&i];
                        json!({"ua": hx(&l.ua), "keyId": l.key_id, "joinEpoch": j, "wrapIndex": w, "kemHash": hx(&l.kem_hash)})
                    }
                    None => json!({"ua": z, "keyId": 0, "joinEpoch": 0, "wrapIndex": 0, "kemHash": z}),
                })
                .collect::<Vec<_>>()),
            View::TreeNodes => json!(self
                .tree
                .node_hashes()
                .iter()
                .enumerate()
                .map(|(x, h)| {
                    let kh = match self.tree.node(x as u32) {
                        Node::Parent(k) => hx(k),
                        _ => z.clone(),
                    };
                    json!({"hash": hx(h), "keyHash": kh, "epoch": self.node_key.get(&(x as u32)).map_or(0, |n| n.1)})
                })
                .collect::<Vec<_>>()),
            View::TreeNodeKey(x) => json!(self.node_key.get(&x).map_or("0x".into(), |n| hx(&n.0))),
            View::EpochsOf => json!(self.epochs.iter().map(|e| hx(&e.id)).collect::<Vec<_>>()),
            View::CommitOf(n) => json!({"record": ep(n)?.record, "sig": ep(n)?.sig}),
            View::PathListOf(n) => json!({"ctTargets": ep(n)?.ct_targets, "ctHashes": ep(n)?.ct_hashes}),
            View::PathCtAt(n, j) => ep(n)?.cts.get(j).cloned().ok_or(Error::Argument)?,
            View::WrapAt(n, i) => ep(n)?.wraps.get(i).cloned().ok_or(Error::Argument)?,
            View::GoneOf(ua) => match self.gone.get(ua) {
                Some((k, e)) => json!({"kind": k, "epoch": e}),
                None => json!({"kind": 0, "epoch": 0}),
            },
            View::LeaveCount(n) => json!(ep(n)?.leaves.len()),
            View::LeaveAt(n, i) => ep(n)?.leaves.get(i).cloned().ok_or(Error::Argument)?,
            View::RemovalCount(n) => json!(ep(n)?.removals.len()),
            View::RemovalAt(n, i) => ep(n)?.removals.get(i).cloned().ok_or(Error::Argument)?,
            View::GoneOwnKeyOf(ua, k) => self.period(&format!("pair/{}/{}", hx(ua), hx(k))),
            View::GoneKeyOf(k) => self.period(&format!("wide/{}", hx(k))),
            View::KemKeyAt(ua, k) => match self.kems.get(&(*ua, k)) {
                Some(KemRecord::Version { kem_pk, sig, .. }) => json!({"kemPk": hx(kem_pk), "sig": hx(sig)}),
                _ => json!({"kemPk": "0x", "sig": "0x"}),
            },
        })
    }
    fn ua_key_of(&self, ua: &[u8; 32]) -> Option<(u16, Vec<u8>)> {
        self.ua_keys.get(ua).cloned()
    }
    fn accepted(&self, _: &[u8; 32], _: u16) -> bool {
        true
    }
    fn msig_at(&self, ua: &[u8; 32], version: u64) -> Option<(Vec<u8>, [u8; 32])> {
        self.msig.get(&(*ua, version)).cloned()
    }
    fn registration(&self, _: &[u8; 32]) -> Option<(scaas_ua::ua_portable::UAAttrs, Vec<u8>)> {
        None
    }
}

/// A home holding a session's genesis: the cold tree from the registry's keys.
fn new_home(
    rec: &Value,
    sig: Value,
    wraps: Vec<Value>,
    sid: [u8; 32],
    tree_id: [u8; 32],
    kems: BTreeMap<([u8; 32], u64), KemRecord>,
    ua_keys: BTreeMap<[u8; 32], (u16, Vec<u8>)>,
) -> Home {
    let members = rec["members"].as_array().unwrap();
    let cold: Vec<Leaf> = members
        .iter()
        .map(|m| Leaf {
            ua: a32(&m["ua"]),
            key_id: u(&m["keyId"]),
            kem_hash: keccak256(kems[&(a32(&m["ua"]), u(&m["keyId"]))].kem_pk()),
        })
        .collect();
    let tree = Tree::cold_with(&cold, u(&rec["pathRefreshBound"]) as u32).unwrap();
    Home {
        tree_id,
        genesis_tree_hash: tree.tree_hash(),
        tree,
        epochs: vec![Epoch {
            id: sid,
            record: rec.clone(),
            sig,
            ct_targets: vec![],
            ct_hashes: vec![],
            cts: vec![],
            wraps,
            leaves: vec![],
            removals: vec![],
        }],
        join: (0..members.len() as u32)
            .map(|i| (i, (0, i as u64)))
            .collect(),
        node_key: BTreeMap::new(),
        gone: BTreeMap::new(),
        periods: BTreeMap::new(),
        kems,
        ua_keys,
        msig: BTreeMap::new(),
        log: vec![],
        owed: 0,
    }
}

// ------------------------------------------------------------------ tree-secrets.json

/// A vector person's ML-DSA-65 key: `ua_secret(rnd(tree-secrets/mldsa65-bip39-seed, 64), mldsa65, 0, i)`, `i` its `index`,
/// signing as clientkeys' `signUA(…, {extraEntropy: false})`, the deterministic variant (FIPS 204, `rnd` zero).
struct Person {
    ua: [u8; 32],
    xi: Vec<u8>,
    key_data: Vec<u8>,
}

impl Person {
    fn new(seed: &[u8], i: u32, want: &Value) -> Person {
        let xi = ua_secret(seed, MLDSA65, 0, i).unwrap().to_vec();
        let key_data = ua_key_data(MLDSA65, &xi).unwrap();
        assert_eq!(hx(&key_data), want["publicKey"], "person {i}");
        Person {
            ua: ua_of(MLDSA65, &key_data).unwrap(),
            xi,
            key_data,
        }
    }
    fn sign_msg(&self, ua_msg: &[u8; 32]) -> Vec<u8> {
        let seed = ml_dsa::Seed::try_from(&self.xi[..]).unwrap();
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
        let m = scaas_ua::pq::signed_message(MLDSA65, ua_msg);
        let rnd = ml_dsa::B32::try_from(&[0u8; 32][..]).unwrap();
        sk.expanded_key()
            .sign_internal(&[&[0, 0], &m], &rnd)
            .encode()
            .to_vec()
    }
    /// The key as an external signer: it signs whatever `uaMessage` request `ua-rs` builds.
    fn key(&self) -> ExternalKey<'_> {
        let r = KeyRef::Ua {
            kind: MLDSA65,
            key_data: self.key_data.clone(),
        };
        ExternalKey::new(r, move |req| match req {
            SignRequest::UaMsg { ua_msg, .. } => Ok(self.sign_msg(ua_msg)),
            _ => Err(Error::Argument),
        })
    }
    /// The registry record of its KEM key `(version, kem_pk)`: `setKemKey`'s signature over `kemRecordDigest`.
    fn record(&self, version: u64, kem_pk: &[u8]) -> KemRecord {
        let m = kem_record_message(MLDSA65, &self.ua, version, kem_pk).unwrap();
        KemRecord::Version {
            kind: MLDSA65,
            key_data: self.key_data.clone(),
            kem_pk: kem_pk.to_vec(),
            sig: self.sign_msg(&m),
        }
    }
}

struct World {
    devices: BTreeMap<String, (Value, KemKeyPair)>,
    people: BTreeMap<String, Person>,
    records: BTreeMap<([u8; 32], u64), KemRecord>,
}

impl World {
    fn new(v: &Value) -> World {
        let seed = rnd("tree-secrets/mldsa65-bip39-seed", 64);
        let people: BTreeMap<String, Person> = v["people"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(n, p)| {
                let i = p["index"].as_u64().unwrap() as u32;
                (n.clone(), Person::new(&seed, i, p))
            })
            .collect();
        let mut devices = BTreeMap::new();
        let mut records = BTreeMap::new();
        for (name, d) in v["devices"].as_object().unwrap() {
            let seed: [u8; 96] = unhex(&d["kemSeed"]).try_into().unwrap();
            let k = KemKeyPair::vectors_ephemeral(&seed).unwrap();
            assert_eq!(hx(&k.kem_pk()), d["kemPk"], "device {name}");
            let p = &people[&name[..1]];
            let r = p.record(u(&d["keyId"]), &k.kem_pk());
            // the registry's signature of the key, clientkeys' byte for byte (deterministic ML-DSA-65; C-1)
            if let KemRecord::Version { sig, .. } = &r {
                assert_eq!(json!(hx(sig)), d["kemSig"], "device {name} kemSig");
            }
            records.insert((p.ua, u(&d["keyId"])), r);
            devices.insert(name.clone(), (d.clone(), k));
        }
        World {
            devices,
            people,
            records,
        }
    }
    fn person(&self, ua: &[u8; 32]) -> &Person {
        self.people.values().find(|p| p.ua == *ua).unwrap()
    }
    fn record(&self, ua: &[u8; 32], key_id: u64) -> KemRecord {
        self.records[&(*ua, key_id)].clone()
    }
    fn kem(&self, name: &str) -> &KemKeyPair {
        &self.devices[name].1
    }
}

/// Target `x` of `tree` as the SDK hands it in (spec §8 steps 4, 5): on an epoch-0 head a leaf's registry record (`rec`),
/// otherwise the bytes the home serves under the hash that entered the root.
fn target_of(
    rd: &mut dyn TreeReader,
    tree: &Tree,
    epoch: u64,
    x: u32,
    rec: &dyn Fn(&[u8; 32], u64) -> KemRecord,
) -> scaas_ua::wallet::Result<TargetKey> {
    match tree.node(x) {
        Node::Leaf(l) if epoch == 0 => Ok(TargetKey::Record(Box::new(rec(&l.ua, l.key_id)))),
        _ => key_of(rd, tree, x).map(TargetKey::Key),
    }
}

fn info_of(
    keys: &AppKeys,
    k: &[u8; 32],
    session: &[u8; 32],
    epoch: &[u8; 32],
    sealed: &Value,
) -> Option<Option<String>> {
    let h = keys.vectors_import(k, KeyUsage::Derive).unwrap();
    // `None`: the sealedInfo does not open under K (a fault row: the delta's F-8)
    Some(
        match keys.vectors_tree_open_info(SC, &h, session, epoch, &unhex(sealed))? {
            Info::Marker => None,
            Info::Json(j) => Some(j),
        },
    )
}

#[test]
fn tree_secrets_every_row() {
    let v = pq("tree-secrets");
    let (_w, keys) = keys();
    for (name, label) in v["labels"].as_object().unwrap() {
        // clientkeys' scope names (addJoiner, addNonce) for the labels add-joiner, add-nonce (the path-less delta §4.1)
        let l = match name.as_str() {
            "addJoiner" => "add-joiner",
            "addNonce" => "add-nonce",
            x => x,
        };
        assert_eq!(*label, format!("{}/{l}", SC.prefix));
    }
    assert_eq!(hx(&SC.tag_path()), v["tags"]["tagPath"]);
    assert_eq!(hx(&SC.tag_context()), v["tags"]["tagContext"]);
    assert_eq!(
        String::from_utf8(SC.wrap_label()).unwrap(),
        v["tags"]["wrap"]
    );
    assert_eq!(
        u(&v["infoMax"]) as usize,
        scaas_ua::wallet::tree::TREE_INFO_MAX
    );
    for (name, p) in v["people"].as_object().unwrap() {
        assert_eq!(
            hx(&ua_of(MLDSA65, &unhex(&p["publicKey"])).unwrap()),
            p["ua"],
            "{name}"
        );
    }
    let world = World::new(&v);
    // secrets: pathContext, ps[0..m], the node keys
    for r in v["secrets"].as_array().unwrap() {
        let targets: Vec<u32> = r["ctTargets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| u(x) as u32)
            .collect();
        let ctx = path_context(SC, &r["record"], &targets).unwrap();
        assert_eq!(hx(&ctx), r["pathContext"], "{}", r["name"]);
        let m = r["nodeKeyHashes"].as_array().unwrap().len();
        let (ps, nk) = keys
            .vectors_tree_path(SC, world.kem(r["author"].as_str().unwrap()), &ctx, m)
            .unwrap();
        assert_eq!(
            json!(ps.iter().map(|p| hx(p)).collect::<Vec<_>>()),
            r["ps"],
            "{}",
            r["name"]
        );
        assert_eq!(hx(&ps[0]), r["ps0"]);
        assert_eq!(
            json!(nk.iter().map(|k| hx(&keccak256(k))).collect::<Vec<_>>()),
            r["nodeKeyHashes"]
        );
        assert_eq!(r["record"]["nodeKeyHashes"], r["nodeKeyHashes"]);
    }
    // the path ciphertexts
    for r in v["pathCt"].as_array().unwrap() {
        let i = &r["input"];
        let at = CtAt {
            tree_id: a32(&i["treeId"]),
            epoch_id: a32(&i["epochId"]),
            node: u(&i["node"]) as u32,
            target: u(&i["target"]) as u32,
        };
        let (ss, kek, ct) = keys
            .vectors_tree_seal_path_secret(
                SC,
                &at,
                &unhex(&i["kemPk"]),
                &unhex(&i["secret"]),
                &a32(&i["m"]),
                &a32(&i["e"]),
            )
            .unwrap();
        assert_eq!(hx(&ss), r["output"]["ss"], "{}", r["name"]);
        assert_eq!(hx(&kek), r["output"]["kek"]);
        assert_eq!(ct.to_json(), r["output"]["ct"]);
    }
    // the schedule
    for r in v["schedule"].as_array().unwrap() {
        let f = &r["fields"];
        let f = EpochFields {
            tree_id: a32(&f["treeId"]),
            epoch_id: a32(&f["epochId"]),
            epoch: u(&f["epoch"]),
            parent_epoch_id: a32(&f["parentEpochId"]),
            parent_tree_hash: a32(&f["parentTreeHash"]),
            tree_hash: a32(&f["treeHash"]),
            admins: f["admins"].as_array().unwrap().iter().map(a32).collect(),
        };
        assert_eq!(hx(&f.context(SC)), r["ctx"], "{}", r["name"]);
        let (s, k, next, tag) = keys
            .vectors_tree_schedule(SC, &unhex(&r["joiner"]), &f)
            .unwrap();
        assert_eq!(hx(&s), r["S"]);
        assert_eq!(hx(&k), r["K"]);
        // the four branches of one S (the path-less delta §4.1): next and the tag apart from K
        assert_eq!(hx(&next), r["next"], "{} next", r["name"]);
        assert_eq!(hx(&tag), r["confirmTag"], "{} tag", r["name"]);
        assert!(k != next && k != tag && next != tag);
    }
    // the path-less rows (C47, R20, C46)
    let pl = &v["pathless"];
    for r in pl["addNonce"].as_array().unwrap() {
        let i = &r["input"];
        let parent = [
            a32(&i["treeId"]),
            a32(&i["parentEpochId"]),
            a32(&i["parentTreeHash"]),
            a32(&i["addsHash"]),
        ];
        let seed: [u8; 96] = unhex(&r["kemSeed"]).try_into().unwrap();
        let kem = KemKeyPair::vectors_ephemeral(&seed).unwrap();
        for (t, want) in r["nonces"].as_array().unwrap().iter().enumerate() {
            let n = keys
                .vectors_tree_add_nonce(SC, &kem, &parent, t as u32)
                .unwrap();
            assert_eq!(json!(n), *want, "{} try {t}", r["name"]);
        }
        assert_eq!(json!(r["nonces"][0]), r["nonce"]);
        assert_eq!(
            code(keys.vectors_tree_add_nonce(SC, &kem, &parent, ADD_NONCE_TRIES)),
            "TreeAddNonce"
        );
    }
    for r in pl["addJoiner"].as_array().unwrap() {
        let j = keys
            .vectors_tree_add_joiner(
                SC,
                &unhex(&r["next"]),
                &a32(&r["treeId"]),
                &a32(&r["epochId"]),
                &a32(&r["addsHash"]),
            )
            .unwrap();
        assert_eq!(hx(&j), r["joiner"], "{}", r["name"]);
    }
    let e = &pl["exitNext"];
    assert_ne!(e["tried"], e["joiner"]);
    for r in pl["warn"].as_array().unwrap() {
        assert_eq!(json!(warn_at(u(&r["N"]) as u32)), r["W"], "W({})", r["N"]);
    }
    assert_eq!(warn_at(0), PATHLESS_WARN_LEAVES);
    let mut rebuilt_differs = Vec::new();
    for sc in v["scenarios"].as_array().unwrap() {
        scenario(&keys, &v, &world, sc, &mut rebuilt_differs, None);
    }
    // the steps a generator built with a fault or a foreign seed: a seed's own rebuild differs there, nowhere else
    assert_eq!(rebuilt_differs, KNOWN_FAULTS, "rebuilt commits that differ");
}

/// Steps clientkeys scripts/treekem-fixture.mjs builds with `commitBadFor` (a validly signed bad ciphertext: heal 1, 2;
/// behind 1, 2; gap 1; admin-gap 1; flag-clear 1) or a foreign `seedOf` (foreign 1, empty-path-foreign 2), or with a
/// small-order key (small-order 1, 2): not the author's honest build.
const KNOWN_FAULTS: &[&str] = &[
    "heal/epoch-1",
    "heal/epoch-2",
    "behind/epoch-1",
    "behind/epoch-2",
    "gap/epoch-1",
    "foreign/epoch-1",
    "empty-path-foreign/epoch-2",
    "admin-gap/epoch-1",
    "small-order/epoch-1",
    "small-order/epoch-2",
    "flag-clear/epoch-1",
    // the path-less delta's faults: a bad Welcome, wrong tags, a bad sealedInfo; an insider's record under B's UA
    "pathless-faults/epoch-2",
    "pathless-faults/epoch-3",
    "pathless-faults/epoch-5",
    "pathless-faults/epoch-6",
    "pathless-faults/epoch-8",
    "pathless-own/epoch-3",
    "pathless-own-behind/epoch-1",
    "pathless-own-behind/epoch-2",
];

/// Steps whose author chose the info (the fixture's `info:`); every other step seals what its author's replay of the head
/// gives as the info to seal (C33).
const EXPLICIT_INFO: &[&str] = &[
    "gap/epoch-1",
    "gap-control/epoch-1",
    "foreign/epoch-1",
    "admin-gap/epoch-4",
    "pathless-faults/epoch-4",
    "pathless-faults/epoch-7",
    "pathless-own/epoch-3",
    "pathless-own-behind/epoch-2",
];

/// The updated `msig`s of `tree-secrets.json`'s signers (F-1, CTR-UA-74): `msigAt` of each version they hold, its structure and
/// enabled word.
fn currents(v: &Value) -> MsigVersions {
    v["signers"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|r| {
            let ua = a32(&r["ua"]);
            r["versions"]
                .as_array()
                .into_iter()
                .flatten()
                .map(move |x| {
                    (
                        (ua, u(&x["version"])),
                        (unhex(&x["msig"]), a32(&x["enabled"])),
                    )
                })
        })
        .collect()
}

/// Every signer's registry record of `tree-secrets.json` (F-3): the people, the keyless admins M (msig), W (WebAuthn) and
/// N (an msig updated on its registry, F-1).
fn signers(v: &Value) -> BTreeMap<[u8; 32], (u16, Vec<u8>)> {
    v["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (a32(&r["ua"]), (u(&r["kind"]) as u16, unhex(&r["keyData"]))))
        .collect()
}

/// A scenario landed on a model of its home, every row checked on the way; `upto` lands only that many steps and skips
/// the replays.
fn scenario(
    keys: &AppKeys,
    v: &Value,
    world: &World,
    sc: &Value,
    differs: &mut Vec<String>,
    upto: Option<usize>,
) -> Home {
    let tag = sc["name"].as_str().unwrap();
    let g = &sc["genesis"];
    let rec = &g["record"];
    // creation in order (C29): the record, its ids, the wraps and K_0 from the same randomness
    let mut session = rec.clone();
    session.as_object_mut().unwrap().remove("wrapHashes");
    session.as_object_mut().unwrap().remove("sealedInfo");
    let members = rec["members"].as_array().unwrap();
    let kems: Vec<KemRecord> = members
        .iter()
        .map(|m| world.record(&a32(&m["ua"]), u(&m["keyId"])))
        .collect();
    let sid = a32(&g["sessionId"]);
    let info = info_of(keys, &a32(&g["K"]), &sid, &sid, &rec["sealedInfo"])
        .flatten()
        .expect("a genesis carries a full info");
    let mut rand = |name: &str, n: usize| Ok(rnd(&format!("tree-secrets/{tag}/genesis/{name}"), n));
    let gen = keys
        .vectors_tree_create_genesis(SC, &session, &kems, info.as_bytes(), &mut rand)
        .unwrap();
    assert_eq!(gen.record, *rec, "{tag} genesis");
    assert_eq!(hx(&gen.session_id), g["sessionId"]);
    assert_eq!(hx(&gen.genesis_ctx), g["genesisCtx"]);
    assert_eq!(hx(&gen.tree_id), g["treeId"]);
    assert_eq!(json!(gen.wraps), g["wraps"]);
    assert_eq!(hx(&keys.vectors_reveal(&gen.k).unwrap()), g["K"]);
    // the home
    let ua_keys = signers(v);
    let mut home = new_home(
        rec,
        g["sig"].clone(),
        g["wraps"].as_array().unwrap().clone(),
        sid,
        gen.tree_id,
        world.records.clone(),
        ua_keys,
    );
    home.msig = currents(v);
    let roster = |h: &Home| -> Value {
        json!((0..h.tree.leaves)
            .map(|i| h
                .tree
                .leaf(i)
                .map_or(Value::Null, |l| json!({"ua": hx(&l.ua), "keyId": l.key_id})))
            .collect::<Vec<_>>())
    };
    assert_eq!(roster(&home), sc["rosters"][0], "{tag} roster 0");
    let steps = sc["steps"].as_array().unwrap();
    for st in steps.iter().take(upto.unwrap_or(steps.len())) {
        if !st["gone"].is_null() {
            home.land_gone(&st["gone"]);
            continue;
        }
        let name = st["name"].as_str().unwrap();
        // the author's honest build on the head, from the same randomness: byte for byte, or a known fault row
        if !rebuild(keys, world, &mut home, st) {
            differs.push(name.to_string());
        }
        home.land_commit(st);
        assert_eq!(
            roster(&home),
            sc["rosters"][home.epochs.len() - 1],
            "{name} roster"
        );
    }
    if upto.is_none() {
        for (dev, want) in sc["replays"].as_object().unwrap() {
            replay_row(keys, world, &mut home, tag, dev, want);
        }
    }
    home
}

/// Builds the step's commit from the author's seed on the prepared head, through the typed commit-signing operation (prepare,
/// review, sign); whether every byte equals the row's. An equal record carries the row's signature, byte for byte.
fn rebuild(keys: &AppKeys, world: &World, home: &mut Home, st: &Value) -> bool {
    let c = &st["record"];
    let author = st["author"].as_str().unwrap();
    let prep = tree_prepare(SC, home, None).unwrap();
    // a sealedInfo the epoch's K does not open is a fault row (the delta's F-8): not the author's honest build
    let Some(info) = info_of(
        keys,
        &a32(&st["K"]),
        &a32(&c["sessionId"]),
        &a32(&st["epochId"]),
        &c["sealedInfo"],
    ) else {
        return false;
    };
    let adds = c["adds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            let a = Add::from_json(x).unwrap();
            let r = world.record(&a.ua, a.key_id);
            (a, r)
        })
        .collect();
    let name = st["name"].as_str().unwrap().to_string();
    let (d, kem) = &world.devices[author];
    let dev = TreeDevice {
        ua: a32(&d["ua"]),
        key_id: u(&d["keyId"]),
        kem,
    };
    let own = keys.tree_replay(SC, home, &dev, None, 0).unwrap().unwrap();
    if !EXPLICIT_INFO.contains(&name.as_str()) {
        // the info the author's own replay of the head says to seal: the full info in force, or the marker (C33)
        assert_eq!(
            own.info_to_seal(),
            info.as_deref(),
            "{name}: the info to seal"
        );
    }
    let mut rand = |x: &str, n: usize| Ok(rnd(&format!("tree-secrets/{name}/{x}"), n));
    if c["pathless"] == json!(true) {
        // the path-less operation on the author's own head handle (the delta §6.5): none when it does not hold the head
        let Some(hd) = own.head.as_ref() else {
            return false;
        };
        let input = PathlessInput {
            parent: &prep,
            session_id: a32(&c["sessionId"]),
            tree_id: a32(&c["treeId"]),
            author: a32(&c["author"]),
            leaf: u(&c["leaf"]) as u32,
            key_id: u(&c["keyId"]),
            kem: world.kem(author),
            adds,
            info: info.as_deref().map(str::as_bytes),
        };
        let parent = [
            a32(&c["treeId"]),
            a32(&c["parentEpochId"]),
            a32(&c["parentTreeHash"]),
            array_hash(pqchat::typed, "TreeAdd", c["adds"].as_array().unwrap()).unwrap(),
        ];
        let try_ = (0..ADD_NONCE_TRIES).find(|t| {
            json!(keys
                .vectors_tree_add_nonce(SC, world.kem(author), &parent, *t)
                .unwrap())
                == c["nonce"]
        });
        let Some(try_) = try_ else { return false };
        let p = keys
            .vectors_tree_prepare_pathless(SC, input, hd, try_, None, &mut rand)
            .unwrap();
        assert!(p
            .review()
            .iter()
            .any(|(k, v)| k == "pathless" && v.starts_with("adds without refreshing the group's keys")));
        let person = world.person(&a32(&c["author"]));
        let (b, sig) = p.sign(&person.key()).unwrap();
        if b.record == *c {
            assert_eq!(json!(hx(&sig.signature)), st["sig"], "{name}: the author's signature");
        }
        return b.record == *c
            && hx(&b.epoch_id) == st["epochId"]
            && json!(b.wraps) == st["wraps"]
            && hx(&keys.vectors_reveal(&b.k).unwrap()) == st["K"];
    }
    let tree = prep.tree().clone();
    let rec = |ua: &[u8; 32], k: u64| world.record(ua, k);
    let mut key_fn = |x: u32| target_of(home, &tree, prep.parent_epoch(), x, &rec);
    let input = CommitInput {
        parent: &prep,
        session_id: a32(&c["sessionId"]),
        tree_id: a32(&c["treeId"]),
        author: a32(&c["author"]),
        leaf: u(&c["leaf"]) as u32,
        key_id: u(&c["keyId"]),
        kem: world.kem(author),
        removes: c["removes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| Remove::from_json(r).unwrap())
            .collect(),
        adds,
        admins: c["admins"].as_array().unwrap().iter().map(a32).collect(),
        info: info.as_deref().map(str::as_bytes),
        key_of: &mut key_fn,
    };
    let p = keys
        .vectors_tree_prepare_commit(SC, input, u(&c["nonce"]), &mut rand)
        .unwrap();
    let typed = pqchat::typed("PqChatCommit", p.built().record.clone()).unwrap();
    assert_eq!(p.digest().unwrap(), typed.digest().unwrap(), "{name}");
    assert!(p
        .review()
        .contains(&("treeId".into(), c["treeId"].as_str().unwrap().into())));
    let person = world.person(&a32(&c["author"]));
    let (b, sig) = p.sign(&person.key()).unwrap();
    if b.record == *c {
        assert_eq!(
            json!(hx(&sig.signature)),
            st["sig"],
            "{name}: the author's signature"
        );
    }
    b.record == *c
        && hx(&b.epoch_id) == st["epochId"]
        && json!(b.ct_targets) == st["ctTargets"]
        && json!(b.ct_hashes.iter().map(|h| hx(h)).collect::<Vec<_>>()) == st["ctHashes"]
        && json!(b.node_keys.iter().map(|k| hx(k)).collect::<Vec<_>>()) == st["nodeKeys"]
        && json!(b.cts.iter().map(PathCt::to_json).collect::<Vec<_>>()) == st["cts"]
        && json!(b.wraps) == st["wraps"]
        && hx(&keys.vectors_reveal(&b.k).unwrap()) == st["K"]
}

fn replay_row(keys: &AppKeys, world: &World, home: &mut Home, tag: &str, dev: &str, want: &Value) {
    let (d, kem) = &world.devices[dev];
    let device = TreeDevice {
        ua: a32(&d["ua"]),
        key_id: u(&d["keyId"]),
        kem,
    };
    home.log.clear();
    let r = keys
        .tree_replay(SC, home, &device, None, 0)
        .unwrap()
        .expect("in the session");
    let at = format!("{tag} / {dev}");
    assert_eq!(json!(r.leaf), want["leaf"], "{at} leaf");
    assert_eq!(json!(r.join_epoch), want["joinEpoch"], "{at} join");
    assert_eq!(json!(r.end_epoch), want["endEpoch"], "{at} end");
    let states: Vec<Value> = r
        .epochs
        .iter()
        .map(|e| match e.state {
            State::Followed => json!([e.epoch, "followed", null]),
            State::NotFollowed(why) => json!([e.epoch, "not followed", why]),
            State::Compromise => json!([e.epoch, "compromise", null]),
            State::AuthorDidNotHold => json!([e.epoch, "author did not hold", null]),
        })
        .collect();
    assert_eq!(json!(states), want["states"], "{at} states");
    let ks: Vec<Value> = r
        .epochs
        .iter()
        .map(|e| {
            e.k.as_ref()
                .map_or(Value::Null, |k| json!(hx(&keys.vectors_reveal(k).unwrap())))
        })
        .collect();
    assert_eq!(json!(ks), want["K"], "{at} K");
    let info: Vec<Value> = r
        .epochs
        .iter()
        .map(|e| {
            let i = e.info.map(|i| match i {
                InfoTook::Full => "full",
                InfoTook::Changed => "changed",
                InfoTook::Ignored => "ignored",
                InfoTook::Marker => "marker",
                InfoTook::NotTaken => "not taken",
            });
            json!([i, e.in_force, e.flagged])
        })
        .collect();
    assert_eq!(json!(info), want["info"], "{at} info");
    let warnings: Vec<Value> = r
        .warnings
        .iter()
        .map(|w| {
            json!({"epoch": w.epoch,
                "adds": w.adds.iter().map(|(l, ua, k)| json!({"leaf": l, "ua": hx(ua), "keyId": k})).collect::<Vec<_>>(),
                "removes": w.removes.iter().map(Remove::to_json).collect::<Vec<_>>(),
                "adminsChanged": w.admins_changed, "leavesLeft": w.leaves_left})
        })
        .collect();
    assert_eq!(json!(warnings), want["warnings"], "{at} warnings");
    // the path-less delta: the C45 epochs, the leaves under review, the counter, the admins' warning, the head's handle
    let suspects: Vec<Value> = r
        .suspects
        .iter()
        .map(|s| {
            json!({"epoch": s.epoch, "author": hx(&s.author),
                "adds": s.adds.iter().map(|(l, ua, k)| json!({"leaf": l, "ua": hx(ua), "keyId": k})).collect::<Vec<_>>(),
                "leavesLeft": s.leaves_left})
        })
        .collect();
    assert_eq!(json!(suspects), want["suspects"], "{at} suspects");
    assert_eq!(json!(r.review), want["review"], "{at} review");
    assert_eq!(json!(r.since_path), want["sincePath"], "{at} sincePath");
    assert_eq!(json!(r.path_warning), want["pathWarning"], "{at} pathWarning");
    let head = r.head.as_ref().map(|h| {
        json!({"epochId": hx(&h.epoch_id), "treeHash": hx(&h.tree_hash),
            "next": hx(&keys.vectors_reveal(&h.next).unwrap())})
    });
    assert_eq!(json!(head), want["head"], "{at} head");
    assert_eq!(json!(home.log), want["reads"], "{at} reads");
    // a key still in the tree holds exactly the head's nodes it derived: each a parent of the head tree under that key's
    // hash (a node a Remove blanked is dropped, never kept)
    if r.end_epoch.is_none() {
        for (x, k) in &r.held {
            assert_eq!(
                *home.tree.node(*x),
                Node::Parent(keccak256(&k.kem_pk())),
                "{at} held node {x}"
            );
        }
    }
    // the pin it would store (C26, sc-F-3): clientkeys' byte for byte; a replay against it passes, a wrong hash conflicts, a
    // pinned exit the walk does not hold is a lying read; a window of K handles from the head only (B-3)
    let pin = r.pin.clone();
    assert_eq!(pin.to_json(), want["pin"], "{at} pin");
    assert_eq!(Pin::from_json(&want["pin"]).unwrap(), pin);
    assert_eq!(pin.epoch as usize, home.epochs.len() - 1);
    assert!(keys.tree_replay(SC, home, &device, Some(&pin), 0).is_ok());
    let bad = Pin {
        hash: [1; 32],
        ..pin.clone()
    };
    assert_eq!(
        code(keys.tree_replay(SC, home, &device, Some(&bad), 0)),
        "TreeConflict"
    );
    let more = Pin {
        exits: [pin.exits.clone(), vec![([9; 32], 2)]].concat(),
        ..pin.clone()
    };
    assert_eq!(
        code(keys.tree_replay(SC, home, &device, Some(&more), 0)),
        "TreeReadCorrupted"
    );
    let w = keys
        .tree_replay(SC, home, &device, None, pin.epoch)
        .unwrap()
        .unwrap();
    assert!(w.epochs.iter().all(|e| e.k.is_some()
        == (e.epoch == pin.epoch
            && matches!(e.state, State::Followed | State::AuthorDidNotHold))));
}

// ------------------------------------------------------------------ refusals beside their positive twins

/// A lying endpoint: the view named `read` changed by `f`, every other view as the home serves it.
struct Tamper<'a> {
    home: &'a mut Home,
    read: String,
    f: fn(&mut Value),
}
impl TreeReader for Tamper<'_> {
    fn read(&mut self, v: View) -> scaas_ua::wallet::Result<Value> {
        let name = v.to_string();
        let mut x = self.home.read(v)?;
        if name == self.read {
            (self.f)(&mut x);
        }
        Ok(x)
    }
    fn ua_key_of(&self, ua: &[u8; 32]) -> Option<(u16, Vec<u8>)> {
        self.home.ua_key_of(ua)
    }
    fn accepted(&self, ua: &[u8; 32], i: u16) -> bool {
        self.home.accepted(ua, i)
    }
    fn msig_at(&self, ua: &[u8; 32], version: u64) -> Option<(Vec<u8>, [u8; 32])> {
        self.home.msig_at(ua, version)
    }
    fn registration(&self, ua: &[u8; 32]) -> Option<(scaas_ua::ua_portable::UAAttrs, Vec<u8>)> {
        self.home.registration(ua)
    }
}
/// A view to lie about and how.
type Lie = (String, fn(&mut Value));
/// The last byte of the key `kemKeyAt` serves flipped (its signature kept).
fn flip_kem(v: &mut Value) {
    flip(&mut v["kemPk"]);
}
/// The last byte of the hex string at `v` flipped.
fn flip(v: &mut Value) {
    let mut b = unhex(v);
    *b.last_mut().unwrap() ^= 1;
    *v = json!(hx(&b));
}

#[test]
fn tree_refusals_beside_twins() {
    let v = pq("tree-secrets");
    let (_w, keys) = keys();
    let world = World::new(&v);
    let main = &v["scenarios"][0];
    assert_eq!(main["name"], "main");
    let mut home = scenario(&keys, &v, &world, main, &mut vec![], None);
    let (d, kem) = &world.devices["C"];
    let c = TreeDevice {
        ua: a32(&d["ua"]),
        key_id: u(&d["keyId"]),
        kem,
    };
    let reads: Vec<String> = main["replays"]["C"]["reads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().into())
        .collect();
    let first = |p: &str| reads.iter().find(|r| r.starts_with(p)).unwrap().clone();
    // the positive twin: the honest endpoint, every epoch followed
    let r = keys
        .tree_replay(SC, &mut home, &c, None, 0)
        .unwrap()
        .unwrap();
    assert!(r.epochs.iter().all(|e| e.state == State::Followed));
    // bytes that fail a signed hash or a signature: refused at the read boundary, before any decapsulation (codex-13,
    // codex-r2-15); one view at a time
    let cases: [Lie; 6] = [
        (first("pathCtAt("), |x| flip(&mut x["sealedSecret"])),
        (first("pathCtAt("), |x| flip(&mut x["mlkemCt"])),
        (first("wrapAt(0,"), |x| flip(&mut x["sealedKey"])),
        ("commitOf(1)".into(), |x| flip(&mut x["sig"])),
        ("sessionOf()".into(), |x| x["record"]["nonce"] = json!(2)),
        (first("pathListOf("), |x| flip(&mut x["ctHashes"][0])),
    ];
    for (read, f) in cases {
        let mut t = Tamper {
            home: &mut home,
            read: read.clone(),
            f,
        };
        assert_eq!(
            code(keys.tree_replay(SC, &mut t, &c, None, 0)),
            "TreeReadCorrupted",
            "{read}"
        );
    }
    // the snapshot against the head's signed tree hash (codex-r2-6)
    let mut t = Tamper {
        home: &mut home,
        read: "treeNodes()".into(),
        f: |x| flip(&mut x[1]["keyHash"]),
    };
    assert_eq!(
        code(keys.tree_replay(SC, &mut t, &c, None, 0)),
        "TreeHeadRoot"
    );
    // a fetched key against the hash that entered the root (codex-1): a node key and a leaf key
    let prep = tree_prepare(SC, &mut home, None).unwrap();
    let node = (0..prep.tree().nodes.len() as u32)
        .find(|x| matches!(prep.tree().node(*x), Node::Parent(_)))
        .unwrap();
    assert!(key_of(&mut home, prep.tree(), node).is_ok());
    assert!(key_of(&mut home, prep.tree(), 0).is_ok());
    let mut t = Tamper {
        home: &mut home,
        read: format!("treeNodeKey({node})"),
        f: flip,
    };
    assert_eq!(code(key_of(&mut t, prep.tree(), node)), "TreeKeyHash");
    let a = home.tree.leaf(0).unwrap().clone();
    let mut t = Tamper {
        home: &mut home,
        read: format!("kemKeyAt({},{})", hx(&a.ua), a.key_id),
        f: flip_kem,
    };
    assert_eq!(code(key_of(&mut t, prep.tree(), 0)), "TreeKeyHash");
    // the checkpoint: below the pinned epoch, another session
    let pin = r.pin.clone();
    let high = Pin {
        epoch: pin.epoch + 1,
        ..pin.clone()
    };
    assert_eq!(
        code(keys.tree_replay(SC, &mut home, &c, Some(&high), 0)),
        "TreeCheckpoint"
    );
    let other = Pin {
        tree_id: [2; 32],
        ..pin.clone()
    };
    assert_eq!(
        code(keys.tree_replay(SC, &mut home, &c, Some(&other), 0)),
        "TreeCheckpoint"
    );

    // the epoch-0 head: the cold tree rebuilt from the signed member list (codex-r2-1)
    let mut h0 = scenario(&keys, &v, &world, main, &mut vec![], Some(0));
    let (da, ka) = &world.devices["A"];
    let dev_a = TreeDevice {
        ua: a32(&da["ua"]),
        key_id: u(&da["keyId"]),
        kem: ka,
    };
    assert!(keys
        .tree_replay(SC, &mut h0, &dev_a, None, 0)
        .unwrap()
        .is_some());
    let mut t = Tamper {
        home: &mut h0,
        read: "treeLeaves()".into(),
        f: |x| flip(&mut x[1]["kemHash"]),
    };
    assert_eq!(
        code(keys.tree_replay(SC, &mut t, &dev_a, None, 0)),
        "TreeGenesisLeaves"
    );
    // a key in no period of the session
    let (dh, kh) = &world.devices["H"];
    let dev_h = TreeDevice {
        ua: a32(&dh["ua"]),
        key_id: u(&dh["keyId"]),
        kem: kh,
    };
    assert!(keys
        .tree_replay(SC, &mut h0, &dev_h, None, 0)
        .unwrap()
        .is_none());

    // a commit built by the release entry on the epoch-0 head: its nonce drawn inside, so two builds differ (C17); K is an
    // epoch key the mode-0 entries take (the hint, a chain); an added key that fails admission is refused (KemCheck)
    let prep0 = tree_prepare(SC, &mut h0, None).unwrap();
    let rec = &main["genesis"]["record"];
    let records = |ua: &[u8; 32], k: u64| world.record(ua, k);
    let build = |keys: &AppKeys, h0: &mut Home, adds: Vec<(Add, KemRecord)>| {
        let tree = prep0.tree().clone();
        let mut kf = |x: u32| target_of(h0, &tree, 0, x, &records);
        keys.tree_build_commit(
            SC,
            CommitInput {
                parent: &prep0,
                session_id: a32(&main["genesis"]["sessionId"]),
                tree_id: a32(&main["genesis"]["treeId"]),
                author: dev_a.ua,
                leaf: 0,
                key_id: dev_a.key_id,
                kem: ka,
                removes: vec![],
                adds,
                admins: rec["admins"].as_array().unwrap().iter().map(a32).collect(),
                info: None,
                key_of: &mut kf,
            },
        )
    };
    let b1 = build(&keys, &mut h0, vec![]).unwrap();
    let b2 = build(&keys, &mut h0, vec![]).unwrap();
    assert_ne!(b1.record["nonce"], b2.record["nonce"]);
    assert_ne!(b1.epoch_id, b2.epoch_id);
    assert!(keys.pqchat_hint(&b1.k).is_ok());
    assert!(keys
        .pqchat_chain(&b1.k, &[0; 32], &b1.epoch_id, &dev_a.ua, &[0; 16])
        .is_ok());
    let (dd, kd) = &world.devices["D"];
    let add = Add {
        leaf: prep0.tree().used,
        ua: a32(&dd["ua"]),
        key_id: u(&dd["keyId"]),
        via: ZERO,
        kem_hash: keccak256(&kd.kem_pk()),
    };
    let d_rec = world.record(&add.ua, add.key_id);
    assert!(build(&keys, &mut h0, vec![(add.clone(), d_rec.clone())]).is_ok());
    // bit 255 of pk_X set: X25519 ignores it (encapsulation alone would pass), the admission check refuses it (its registry
    // record authenticates it: the admission is the check that refuses)
    let mut bad = kd.kem_pk();
    *bad.last_mut().unwrap() |= 0x80;
    let bad_add = Add {
        kem_hash: keccak256(&bad),
        ..add.clone()
    };
    let bad_rec = world.person(&add.ua).record(add.key_id, &bad);
    assert!(matches!(
        build(&keys, &mut h0, vec![(bad_add, bad_rec)]),
        Err(Error::KemCheck)
    ));
    // the registry record check before an encapsulation (spec §8 step 5, codex-1), each refusal beside the twin above: an
    // added key whose record does not authenticate it (its signature flipped), an added key its record authenticates but the
    // Add's kemHash does not name (D's record of another device's key under D's Add)
    let flipped = |r: &KemRecord| match r.clone() {
        KemRecord::Version {
            kind,
            key_data,
            kem_pk,
            mut sig,
        } => {
            sig[7] ^= 1;
            KemRecord::Version {
                kind,
                key_data,
                kem_pk,
                sig,
            }
        }
        x => x,
    };
    assert_eq!(
        code(build(&keys, &mut h0, vec![(add.clone(), flipped(&d_rec))])),
        "TreeKemRecord"
    );
    let other = world
        .person(&add.ua)
        .record(add.key_id, &world.kem("A2").kem_pk());
    assert_eq!(
        code(build(&keys, &mut h0, vec![(add.clone(), other)])),
        "TreeKeyHash"
    );
    // an epoch-0 head's leaf target: its record is the check (no signed tree hash covers the cold tree yet); its bytes alone,
    // or a record whose signature fails, are refused
    let tree = prep0.tree().clone();
    let target = |rd: &mut Home, x: u32, how: u8| match (tree.node(x), how) {
        (Node::Leaf(_), 1) => Ok(TargetKey::Key(key_of(rd, &tree, x)?)),
        (Node::Leaf(l), 2) => Ok(TargetKey::Record(Box::new(flipped(
            &world.record(&l.ua, l.key_id),
        )))),
        _ => target_of(rd, &tree, 0, x, &records),
    };
    for (how, want) in [(0, "accepted"), (1, "TreeKemRecord"), (2, "TreeKemRecord")] {
        let mut kf = |x: u32| target(&mut h0, x, how);
        let r = keys.tree_build_commit(
            SC,
            CommitInput {
                parent: &prep0,
                session_id: a32(&main["genesis"]["sessionId"]),
                tree_id: a32(&main["genesis"]["treeId"]),
                author: dev_a.ua,
                leaf: 0,
                key_id: dev_a.key_id,
                kem: ka,
                removes: vec![],
                adds: vec![],
                admins: prep0.parent_admins().to_vec(),
                info: None,
                key_of: &mut kf,
            },
        );
        assert_eq!(code(r), want, "an epoch-0 leaf target ({how})");
    }

    // the info's bound: the 4,096-B bucket seals (4,124 B), the next is refused (codex-r2-13)
    let mut session = rec.clone();
    session.as_object_mut().unwrap().remove("wrapHashes");
    session.as_object_mut().unwrap().remove("sealedInfo");
    let kems: Vec<KemRecord> = rec["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| world.record(&a32(&m["ua"]), u(&m["keyId"])))
        .collect();
    let info_n = |n: usize| format!("{{\"a\":\"{}\"}}", "x".repeat(n));
    let fits = (0..5000)
        .rev()
        .find(|n| {
            scaas_ua::wallet::pqchat_keys::pad(info_n(*n).as_bytes())
                .unwrap()
                .len()
                == 4096
        })
        .unwrap();
    let g = keys
        .tree_create_genesis(SC, &session, &kems, info_n(fits).as_bytes())
        .unwrap();
    assert_eq!(unhex(&g.record["sealedInfo"]).len(), 4124);
    assert_eq!(
        code(keys.tree_create_genesis(SC, &session, &kems, info_n(fits + 1).as_bytes())),
        "TreeInfoSize"
    );
    // a member's key authenticated by its registry record at creation (spec §8 step 5): another member's record in its
    // place is refused before any wrap; its twin, every member's own record, is the creation just above
    let mut swapped = kems.clone();
    swapped.swap(0, 1);
    assert_eq!(
        code(keys.tree_create_genesis(SC, &session, &swapped, info_n(1).as_bytes())),
        "TreeKemRecord"
    );

    // app-agnostic (owner 2026-11-23): another app's scope under its own prefix gives other labels and other secrets
    let other = scaas_ua::wallet::tree::TreeScope {
        prefix: "scaas/other/v1/tree",
        ..PQCHAT_TREE
    };
    assert_ne!(other.tag_path(), SC.tag_path());
    assert_ne!(other.tag_context(), SC.tag_context());
    let s = &v["secrets"][0];
    let targets: Vec<u32> = s["ctTargets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| u(x) as u32)
        .collect();
    let (c1, c2) = (
        path_context(SC, &s["record"], &targets).unwrap(),
        path_context(&other, &s["record"], &targets).unwrap(),
    );
    assert_ne!(c1, c2);
    let author = world.kem(s["author"].as_str().unwrap());
    let (p1, _) = keys.vectors_tree_path(SC, author, &c1, 1).unwrap();
    let (p2, _) = keys.vectors_tree_path(&other, author, &c1, 1).unwrap();
    assert_eq!(hx(&p1[0]), s["ps0"]);
    assert_ne!(p1, p2);
}

// ------------------------------------------------------------------ states only a signed fault reaches (built here)

/// A session of the test wallet's UAs X (admin, creator), Y, Z, W (ML-DSA-65, account 0, index 0..3), each with an ephemeral
/// KEM key (its seed in its own store), X, Y and Z members at genesis.
struct Own {
    w: Wallet,
    keys: AppKeys,
    uas: Vec<scaas_ua::wallet::UaKey>,
    kems: Vec<KemKeyPair>,
}
/// The test app's tree: PqChat's labels and records under another app's purpose (the scope is a parameter).
const OWN: &scaas_ua::wallet::tree::TreeScope = &scaas_ua::wallet::tree::TreeScope {
    purpose: own_purpose,
    ..PQCHAT_TREE
};
fn own_app() -> [u8; 32] {
    keccak256(b"test.tree.v1")
}
fn own_purpose() -> [u8; 32] {
    scaas_ua::ua_portable::app_purpose(&own_app()).unwrap()
}
const INFO_A: &str = r#"{"stores":[{"kind":"matrix","room":"!a:example.org"}]}"#;
const INFO_B: &str = r#"{"stores":[{"kind":"matrix","room":"!b:example.org"}]}"#;

impl Own {
    fn new() -> Own {
        let (w, keys) = keys();
        let uas = (0..4).map(|i| w.ua_key(MLDSA65, 0, i).unwrap()).collect();
        let kems = (0..4)
            .map(|_| KemKeyPair::generate_ephemeral().unwrap())
            .collect();
        Own { w, keys, uas, kems }
    }
    fn ua(&self, i: usize) -> [u8; 32] {
        self.uas[i].ua().unwrap()
    }
    fn dev(&self, i: usize) -> TreeDevice<'_> {
        TreeDevice {
            ua: self.ua(i),
            key_id: 1,
            kem: &self.kems[i],
        }
    }
    /// `i`'s KEM key's registry record (version 1): its UA key's `setKemKey` signature.
    fn record(&self, i: usize) -> KemRecord {
        let pk = self.kems[i].kem_pk();
        let d = kem_record_digest(&self.ua(i), 1, &pk).unwrap();
        let tag = scaas_ua::purpose_tag("kem").unwrap();
        KemRecord::Version {
            kind: MLDSA65,
            key_data: self.uas[i].key_data(),
            kem_pk: pk,
            sig: self.uas[i].sign_ua(&tag, &d).unwrap(),
        }
    }
    fn record_of(&self, ua: &[u8; 32]) -> KemRecord {
        self.record((0..4).find(|i| self.ua(*i) == *ua).unwrap())
    }
    fn sign(&self, i: usize, name: &str, rec: &Value) -> Value {
        let d = pqchat::typed(name, rec.clone()).unwrap().digest().unwrap();
        // a signer outside the tree's operations: an app record of this test app's id (its scope's purpose, [`OWN`])
        json!(hx(&self.uas[i].sign_ua_app(&own_app(), &d).unwrap()))
    }
    fn home(&self) -> Home {
        let session = json!({"creator": hx(&self.ua(0)), "nonce": 1, "homeChain": hx(&[7; 32]),
            "homeChatContract": hx(&[0xc4; 20]), "admins": [hx(&self.ua(0))],
            "members": (0..3).map(|i| json!({"ua": hx(&self.ua(i)), "keyId": 1, "via": hx(&ZERO)})).collect::<Vec<_>>(),
            "groupMode": 1, "pathRefreshBound": 0});
        let kems: Vec<KemRecord> = (0..3).map(|i| self.record(i)).collect();
        let g = self
            .keys
            .tree_create_genesis(OWN, &session, &kems, INFO_A.as_bytes())
            .unwrap();
        let sig = self.sign(0, "PqChatSession", &g.record);
        let kems = (0..4).map(|i| ((self.ua(i), 1), self.record(i))).collect();
        let ua_keys = (0..4)
            .map(|i| (self.ua(i), (MLDSA65, self.uas[i].key_data())))
            .collect();
        new_home(
            &g.record,
            sig,
            g.wraps.clone(),
            g.session_id,
            g.tree_id,
            kems,
            ua_keys,
        )
    }
    /// `i`'s commit on the head with `admins`, `info` and `adds` (of UA indexes), prepared by the typed commit-signing
    /// operation under this app's scope.
    fn prepare(
        &self,
        h: &mut Home,
        i: usize,
        admins: &[usize],
        info: &str,
        adds: &[usize],
    ) -> scaas_ua::wallet::Result<(PreparedCommit, Tree)> {
        let prep = tree_prepare(OWN, h, None).unwrap();
        let tree = prep.tree().clone();
        let adds: Vec<(Add, KemRecord)> = adds
            .iter()
            .enumerate()
            .map(|(j, x)| {
                let a = Add {
                    leaf: tree.used + j as u32,
                    ua: self.ua(*x),
                    key_id: 1,
                    via: ZERO,
                    kem_hash: keccak256(&self.kems[*x].kem_pk()),
                };
                (a, self.record(*x))
            })
            .collect();
        let leaf = (0..tree.leaves)
            .find(|l| tree.leaf(*l).is_some_and(|x| x.ua == self.ua(i)))
            .unwrap();
        let (sid, tid) = (h.epochs[0].id, h.tree_id);
        let rec = |ua: &[u8; 32], _: u64| self.record_of(ua);
        let mut kf = |x: u32| target_of(h, &tree, prep.parent_epoch(), x, &rec);
        let p = self.keys.tree_prepare_commit(
            OWN,
            CommitInput {
                parent: &prep,
                session_id: sid,
                tree_id: tid,
                author: self.ua(i),
                leaf,
                key_id: 1,
                kem: &self.kems[i],
                removes: vec![],
                adds,
                admins: {
                    let mut a: Vec<[u8; 32]> = admins.iter().map(|a| self.ua(*a)).collect();
                    a.sort();
                    a
                },
                info: Some(info.as_bytes()),
                key_of: &mut kf,
            },
        )?;
        Ok((p, prep.tree().clone()))
    }
    /// [`Own::prepare`], then `fault` changes the record (and the pieces) and `i` signs it as a signer outside `ua-rs` would;
    /// an unchanged record carries the operation's own signature. Landed.
    fn commit(
        &self,
        h: &mut Home,
        i: usize,
        admins: &[usize],
        info: &str,
        adds: &[usize],
        fault: fn(&Own, &mut Value, &Tree),
    ) {
        let (p, tree) = self.prepare(h, i, admins, info, adds).unwrap();
        let (b, sig) = p.sign(&self.uas[i]).unwrap();
        let mut st = json!({"record": b.record, "epochId": hx(&b.epoch_id), "ctTargets": b.ct_targets,
            "ctHashes": b.ct_hashes.iter().map(|x| hx(x)).collect::<Vec<_>>(),
            "nodeKeys": b.node_keys.iter().map(|x| hx(x)).collect::<Vec<_>>(),
            "cts": b.cts.iter().map(PathCt::to_json).collect::<Vec<_>>(), "wraps": b.wraps});
        fault(self, &mut st, &tree);
        st["sig"] = if st["record"] == b.record {
            json!(hx(&sig.signature))
        } else {
            self.sign(i, "PqChatCommit", &st["record"])
        };
        h.land_commit(&st);
    }
    fn replay(&self, h: &mut Home, i: usize) -> scaas_ua::wallet::tree::Replay {
        self.keys
            .tree_replay(OWN, h, &self.dev(i), None, 0)
            .unwrap()
            .unwrap()
    }
}
fn honest(_: &Own, _: &mut Value, _: &Tree) {}
/// Every node key hash replaced by another key's, the tree hash recomputed: the ciphertexts open, the keys do not match.
fn other_node_keys(_: &Own, st: &mut Value, tree: &Tree) {
    let other = keccak256(&KemKeyPair::generate_ephemeral().unwrap().kem_pk());
    let n = st["record"]["nodeKeyHashes"].as_array().unwrap().len();
    st["record"]["nodeKeyHashes"] = json!(vec![hx(&other); n]);
    let a = tree
        .apply_commit(&Changes::from_json(&st["record"]).unwrap(), &vec![other; n])
        .unwrap();
    st["record"]["treeHash"] = json!(hx(&a.tree_hash));
}
/// The Welcome replaced by a wrap of another joiner secret, its hash in the record.
fn other_welcome(o: &Own, st: &mut Value, _: &Tree) {
    let r = &st["record"];
    let (tid, eid, member) = (
        a32(&r["treeId"]),
        a32(&st["epochId"]),
        a32(&r["adds"][0]["ua"]),
    );
    let aad = [&tid[..], &eid, &member, &1u64.to_be_bytes()].concat();
    let j = o.keys.random_key(KeyUsage::Derive).unwrap();
    let w = o
        .keys
        .kem_wrap(&j, &SC.wrap_label(), &aad, &o.kems[3].kem_pk())
        .unwrap();
    let wrap = json!({"member": hx(&member), "keyId": 1, "mlkemCt": hx(&w.mlkem_ct), "x25519Eph": hx(&w.x25519_eph),
        "sealedKey": hx(&w.sealed_key)});
    st["record"]["wrapHashes"] =
        json!([hx(&scaas_ua::wallet::tree::wrap_hash(SC, &wrap).unwrap())]);
    st["wraps"] = json!([wrap]);
}

#[test]
fn tree_states_of_signed_faults() {
    let o = Own::new();
    let _ = &o.w;
    let last = |r: &scaas_ua::wallet::tree::Replay| {
        (
            r.epochs.last().unwrap().state,
            r.epochs.last().unwrap().info,
        )
    };
    // rights (§9, D-5): a non-admin's commit that changes the admins is refused before it is signed (the contract's
    // PqChatNotAdmin; a walk that meets one signed elsewhere reads a lie: the lie rows); its twin keeps them
    let mut h = o.home();
    assert_eq!(
        code(o.prepare(&mut h, 1, &[0, 1], INFO_A, &[])),
        "PqChatNotAdmin"
    );
    let mut h = o.home();
    o.commit(&mut h, 1, &[0], INFO_A, &[], honest);
    assert_eq!(
        last(&o.replay(&mut h, 2)),
        (State::Followed, Some(InfoTook::Full))
    );
    // the info (C33): a non-admin's differing info is ignored, the one in force kept; an admin's is the changed info
    let mut h = o.home();
    o.commit(&mut h, 1, &[0], INFO_B, &[], honest);
    let r = o.replay(&mut h, 2);
    assert_eq!(last(&r), (State::Followed, Some(InfoTook::Ignored)));
    assert_eq!(r.epochs.last().unwrap().in_force.as_deref(), Some(INFO_A));
    let mut h = o.home();
    o.commit(&mut h, 0, &[0], INFO_B, &[], honest);
    let r = o.replay(&mut h, 2);
    assert_eq!(last(&r), (State::Followed, Some(InfoTook::Changed)));
    assert_eq!(r.epochs.last().unwrap().in_force.as_deref(), Some(INFO_B));
    // the admin judged on the parent's admins (T6b of the TreeKEM plan): an admin that hands the role to another member in the
    // same commit still changes the info; a member made admin by that commit does not count as one for it
    let mut h = o.home();
    o.commit(&mut h, 0, &[1], INFO_B, &[], honest);
    let r = o.replay(&mut h, 2);
    assert_eq!(last(&r), (State::Followed, Some(InfoTook::Changed)));
    assert_eq!(r.epochs.last().unwrap().in_force.as_deref(), Some(INFO_B));
    // the derived-key comparison: ciphertexts that open to secrets whose keys are not the signed ones
    let mut h = o.home();
    o.commit(&mut h, 0, &[0], INFO_A, &[], other_node_keys);
    assert_eq!(
        last(&o.replay(&mut h, 2)).0,
        State::NotFollowed("node key mismatch")
    );
    // the joiner's Welcome against its path ciphertext (codex-5, fable-5)
    let mut h = o.home();
    o.commit(&mut h, 0, &[0], INFO_A, &[3], other_welcome);
    assert_eq!(
        last(&o.replay(&mut h, 3)).0,
        State::NotFollowed("welcome disagrees")
    );
    assert_eq!(last(&o.replay(&mut h, 2)).0, State::Followed);
    let mut h = o.home();
    o.commit(&mut h, 0, &[0], INFO_A, &[3], honest);
    let r = o.replay(&mut h, 3);
    assert_eq!(
        (r.join_epoch, last(&r)),
        (1, (State::Followed, Some(InfoTook::Full)))
    );
    // the joiner's K is the members' K
    let k = |r: &scaas_ua::wallet::tree::Replay| {
        o.keys
            .vectors_reveal(r.epochs.last().unwrap().k.as_ref().unwrap())
            .unwrap()
    };
    assert_eq!(k(&r), k(&o.replay(&mut h, 2)));
    // the committer itself: its own commit reproduced from its seed (node keys and sealedInfo), K equal
    assert_eq!(k(&o.replay(&mut h, 0)), k(&r));
}

// ------------------------------------------------------------------ the signing operations (spec §15, plan T2)

/// The record `r` as `PqChatTreeRemove`'s named fields.
fn remove_of(r: &Value) -> TreeRemove {
    TreeRemove {
        session_id: a32(&r["sessionId"]),
        tree_id: a32(&r["treeId"]),
        epoch_id: a32(&r["epochId"]),
        next_epoch: u(&r["nextEpoch"]),
        members: r["members"].as_array().unwrap().iter().map(a32).collect(),
        admin: a32(&r["admin"]),
        nonce: u(&r["nonce"]),
    }
}
fn leave_of(r: &Value) -> TreeLeave {
    TreeLeave {
        session_id: a32(&r["sessionId"]),
        tree_id: a32(&r["treeId"]),
        epoch_id: a32(&r["epochId"]),
        member: a32(&r["member"]),
        nonce: u(&r["nonce"]),
    }
}
fn line(name: &str, value: &Value) -> (String, String) {
    (name.into(), value.as_str().unwrap().into())
}

/// `treeLeave` and `treeRemove` prepared from named fields, reviewed, then signed on PqChat's dedicated path: the digests of
/// `tree.json`, every signed `treeRemove` of `tree-secrets.json` byte for byte (the commits: `rebuild`, every step), the
/// review naming the session by `treeId` and saying the UA cannot come back. Refused beside their twins: a struct other
/// than a tree record on the tree's path, a tree record on the generic record path.
#[test]
fn tree_signing_ops() {
    let v = pq("tree-secrets");
    let world = World::new(&v);
    let d = &pq("tree")["digests"];
    let row = |name: &str| {
        d["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["struct"] == name)
            .unwrap()
            .clone()
    };
    let (lr, rr) = (row("PqChatTreeLeave"), row("PqChatTreeRemove"));
    for (r, p) in [
        (
            &lr,
            tree_prepare_leave(SC, &leave_of(&lr["record"])).unwrap(),
        ),
        (
            &rr,
            tree_prepare_remove(SC, &remove_of(&rr["record"])).unwrap(),
        ),
    ] {
        assert_eq!(p.record(), r["record"], "{}", r["struct"]);
        assert_eq!(hx(&p.digest().unwrap()), r["typed"], "{}", r["struct"]);
        let m = ua_message(MLDSA65, &pqchat::purpose(), &p.digest().unwrap()).unwrap();
        assert_eq!(hx(&m), r["signedDigest"], "{}", r["struct"]);
        assert!(p.review().contains(&line("treeId", &r["record"]["treeId"])));
        assert!(p.review().iter().any(|(n, _)| n == "cannotComeBack"));
        // F-4 / B2-10: the review says that the exit applies if it lands within the lag of the epoch it names
        let named = if r["struct"] == "PqChatTreeRemove" {
            format!("epoch {}", u(&r["record"]["nextEpoch"]) - 1)
        } else {
            format!(
                "the epoch it names ({})",
                r["record"]["epochId"].as_str().unwrap()
            )
        };
        let want =
            format!("applies if it lands within 16 epochs of {named}; it cannot be withdrawn");
        assert!(
            p.review().contains(&("appliesWithin".to_string(), want)),
            "{}",
            r["struct"]
        );
    }
    // every landed treeRemove and treeLeave of a person: its signature from the named fields, byte for byte (the keyless
    // admins' msig and WebAuthn signatures are verified by every replay of their world)
    let (mut n, mut keyless) = (0, 0);
    for sc in v["scenarios"].as_array().unwrap() {
        for st in sc["steps"].as_array().unwrap() {
            let Some(g) = st.get("gone") else { continue };
            let leave = g["struct"] == "PqChatTreeLeave";
            let signer = a32(&g["record"][if leave { "member" } else { "admin" }]);
            let p = if leave {
                tree_prepare_leave(SC, &leave_of(&g["record"])).unwrap()
            } else {
                tree_prepare_remove(SC, &remove_of(&g["record"])).unwrap()
            };
            assert_eq!(p.record(), g["record"]);
            let Some(person) = world.people.values().find(|x| x.ua == signer) else {
                keyless += 1;
                continue;
            };
            let sig = p.sign(&person.key()).unwrap();
            assert!(sig.key_data.is_empty() && sig.members.is_empty());
            assert_eq!(json!(hx(&sig.signature)), g["sig"], "{}", sc["name"]);
            n += 1;
        }
    }
    // the keyless admins' exits: M's, W's two, N's (the msig updated on its registry, F-1), N's two of msig-history (F-1b: one at
    // version 0, one at version 1), X's of msig-nested (C-4: through its msig member N at N's version 1); 6 -> 7 with msig-nested
    // 6 -> 7 with the path-less delta's world pathless-exit (C's leave at a path-less head)
    assert_eq!((n, keyless), (7, 7));
    // a treeLeave (no row carries its signature): signed by its member, the signature verifies over the row's signedDigest
    let a = &world.people["A"];
    let l = TreeLeave {
        member: a.ua,
        ..leave_of(&lr["record"])
    };
    let p = tree_prepare_leave(SC, &l).unwrap();
    let m = ua_message(MLDSA65, &pqchat::purpose(), &p.digest().unwrap()).unwrap();
    let sig = p.sign(&a.key()).unwrap();
    assert!(scaas_ua::pq::verify(
        MLDSA65,
        &a.key_data,
        &m,
        &sig.signature
    ));

    // the tree's path signs a tree record only: the flat PqChatLeave and a nested struct are refused, the tree record signs
    let flat = pq("records")["leave"]["record"].clone();
    let flat_td = pqchat::typed("PqChatLeave", flat).unwrap();
    let tree_td = pqchat::typed("PqChatTreeRemove", rr["record"].clone()).unwrap();
    let nested = pqchat::typed("TreeAdd", d["records"][0]["record"]["adds"][0].clone()).unwrap();
    let key = a.key();
    assert_eq!(
        pqchat::vectors_sign_tree(&key, &flat_td).err(),
        Some(Error::Argument)
    );
    assert_eq!(
        pqchat::vectors_sign_tree(&key, &nested).err(),
        Some(Error::Argument)
    );
    assert!(pqchat::vectors_sign_tree(&key, &tree_td).is_ok());
    // B-2: a struct under a tree record's name with other fields is refused on the tree's path; the review names the domain
    // and the purpose the signature is under
    let other = scaas_ua::wallet::TypedData::from_json(
        json!({
            "types": {"EIP712Domain": [{"name": "name", "type": "string"}], "PqChatTreeLeave": [
                {"name": "spender", "type": "bytes32"}, {"name": "value", "type": "uint64"}]},
            "primaryType": "PqChatTreeLeave", "domain": {"name": "Any Token"},
            "message": {"spender": hx(&[1; 32]), "value": 1}})
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        pqchat::vectors_sign_tree(&key, &other).err(),
        Some(Error::Argument)
    );
    let p = tree_prepare_leave(SC, &leave_of(&lr["record"])).unwrap();
    assert!(p
        .review()
        .contains(&("purpose".into(), hx(&pqchat::purpose()))));
    assert!(p
        .review()
        .iter()
        .any(|(n, x)| n == "domain" && x.contains("SCaaS PqChat")));
    // the generic record path refuses every tree record; its twin, the flat record, signs
    for r in d["records"].as_array().unwrap() {
        let name = r["struct"].as_str().unwrap();
        if pqchat::TREE_RECORDS.contains(&name) {
            let td = pqchat::typed(name, r["record"].clone()).unwrap();
            assert_eq!(
                pqchat::sign(&key, &td).err(),
                Some(Error::Argument),
                "{name}"
            );
        }
    }
    assert_eq!(pqchat::TREE_RECORDS.len(), 3);
    assert!(pqchat::sign(&key, &flat_td).is_ok());
}

/// The commit's review (spec §15): every field of the record it built, whether the admins change (a twin that keeps them),
/// the session info; the signature over that record verifies (the replay of `tree_states_of_signed_faults` lands them).
#[test]
fn tree_commit_review() {
    let o = Own::new();
    let mut h = o.home();
    let (p, _) = o.prepare(&mut h, 0, &[0, 1], INFO_A, &[3]).unwrap();
    let r = p.review();
    let rec = &p.built().record;
    assert_eq!(r[0], ("record".into(), "PqChatCommit".into()));
    assert!(r.contains(&line("treeId", &rec["treeId"])));
    assert!(r.contains(&("adminsChanged".into(), "true".into())));
    assert!(r.contains(&("sessionInfo".into(), INFO_A.into())));
    assert!(r
        .iter()
        .any(|(n, x)| n == "adds" && x.contains(&hx(&o.ua(3)))));
    // 21 fields since the path-less delta (pathless, confirmTag: C42, C43)
    assert_eq!(r.len(), 1 + 21 + 2 + 2);
    assert!(r.contains(&("pathless".into(), "false".into())));
    assert!(r.contains(&("purpose".into(), hx(&own_purpose()))));
    let (p, _) = o.prepare(&mut h, 0, &[0], INFO_A, &[]).unwrap();
    assert!(p
        .review()
        .contains(&("adminsChanged".into(), "false".into())));
}

/// The registry KEM record check before an encapsulation (spec §8 step 5, codex-1) on `ua/portable.json`'s rows, each refusal
/// beside its twin: a version above 0 by its kept signature (a substituted valid key, a record of another UA, another key's
/// signature, the version-0 form), version 0 by the registration's proof (in full and as the hash commit; a substituted
/// key, another UA's registration, a flipped proof, the other version).
#[test]
fn tree_kem_record_check() {
    let p: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../smartcontracts/vectors/ua/portable.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let rows = |k: &str| p[k].as_array().unwrap().clone();
    let reg_of = |ua: &Value| {
        rows("registrations")
            .into_iter()
            .find(|r| r["ua"] == *ua)
            .unwrap()
    };
    let kem_row = |id: &str| {
        rows("kemRecords")
            .into_iter()
            .find(|r| r["id"] == id)
            .unwrap()
    };
    let version = |r: &Value| {
        let g = reg_of(&r["ua"]);
        KemRecord::Version {
            kind: u(&g["kind"]) as u16,
            key_data: unhex(&g["keyData"]),
            kem_pk: unhex(&r["kemPk"]),
            sig: unhex(&r["sig"]),
        }
    };
    let ok = |ua: &Value, v: u64, rec: &KemRecord| code(kem_record_key(&a32(ua), v, rec));
    // a version above 0
    let (v1, v2, other) = (
        kem_row("mldsa65/v1"),
        kem_row("mldsa65/v2"),
        kem_row("mldsa87/v1"),
    );
    let r1 = version(&v1);
    assert_eq!(
        kem_record_key(&a32(&v1["ua"]), 1, &r1).unwrap(),
        unhex(&v1["kemPk"])
    );
    let with = |r: &KemRecord, f: &dyn Fn(&mut Vec<u8>, &mut Vec<u8>)| {
        let KemRecord::Version {
            kind,
            key_data,
            mut kem_pk,
            mut sig,
        } = r.clone()
        else {
            panic!()
        };
        f(&mut kem_pk, &mut sig);
        KemRecord::Version {
            kind,
            key_data,
            kem_pk,
            sig,
        }
    };
    let swapped = with(&r1, &|k, _| *k = unhex(&v2["kemPk"]));
    assert_eq!(
        ok(&v1["ua"], 1, &swapped),
        "TreeKemRecord",
        "a substituted valid key"
    );
    let foreign = with(&r1, &|_, s| *s = unhex(&other["sig"]));
    assert_eq!(
        ok(&v1["ua"], 1, &foreign),
        "TreeKemRecord",
        "another key's signature"
    );
    let theirs = version(&other);
    assert_eq!(
        ok(&other["ua"], 1, &theirs),
        "accepted",
        "the twin: its own UA"
    );
    assert_eq!(
        ok(&v1["ua"], 1, &theirs),
        "TreeKemRecord",
        "a record of another UA"
    );
    assert_eq!(
        ok(&v1["ua"], 2, &r1),
        "TreeKemRecord",
        "signed for another version"
    );
    assert_eq!(
        ok(&v1["ua"], 0, &r1),
        "TreeKemRecord",
        "version 0 is the registration's"
    );
    // version 0: the registration in full, then as the hash commit
    let g = rows("registrations")
        .into_iter()
        .find(|r| r.get("kemCommit").is_some())
        .unwrap();
    let kem_of = |pk: &[u8]| KemKey::from_kem_pk(pk).unwrap();
    let full = KemRecord::Registration {
        kind: u(&g["kind"]) as u16,
        key_data: unhex(&g["keyData"]),
        attrs: UAAttrs {
            pqz_key: unhex(&g["attrs"]["pqzKey"]),
            pqz_pop_hash: a32(&g["attrs"]["pqzPopHash"]),
            kem: kem_of(&unhex(&g["attrs"]["kemPk"])),
            kem_pk_hash: [0; 32],
        },
        pop: unhex(&g["pop"]),
        kem_pk: unhex(&g["attrs"]["kemPk"]),
    };
    let c = &g["kemCommit"]["register"];
    let commit = KemRecord::Registration {
        kind: u(&g["kind"]) as u16,
        key_data: unhex(&g["keyData"]),
        attrs: UAAttrs {
            pqz_key: unhex(&c["attrs"]["pqzKey"]),
            pqz_pop_hash: a32(&c["attrs"]["pqzPopHash"]),
            kem: KemKey {
                scheme: u(&c["attrs"]["kem"]["scheme"]) as u8,
                ..Default::default()
            },
            kem_pk_hash: a32(&c["attrs"]["kemPkHash"]),
        },
        pop: unhex(&c["pop"]),
        kem_pk: unhex(&g["attrs"]["kemPk"]),
    };
    let reg = |r: &KemRecord, f: &dyn Fn(&mut Vec<u8>, &mut Vec<u8>)| {
        let KemRecord::Registration {
            kind,
            key_data,
            attrs,
            mut pop,
            mut kem_pk,
        } = r.clone()
        else {
            panic!()
        };
        f(&mut pop, &mut kem_pk);
        KemRecord::Registration {
            kind,
            key_data,
            attrs,
            pop,
            kem_pk,
        }
    };
    for (form, r) in [("in full", &full), ("as the hash commit", &commit)] {
        assert_eq!(ok(&g["ua"], 0, r), "accepted", "{form}");
        let sub = reg(r, &|_, k| *k = unhex(&v1["kemPk"]));
        assert_eq!(
            ok(&g["ua"], 0, &sub),
            "TreeKemRecord",
            "{form}: a substituted key"
        );
        let flip = reg(r, &|p, _| p[9] ^= 1);
        assert_eq!(
            ok(&g["ua"], 0, &flip),
            "TreeKemRecord",
            "{form}: a flipped proof"
        );
        assert_eq!(
            ok(&other["ua"], 0, r),
            "TreeKemRecord",
            "{form}: another UA"
        );
        assert_eq!(
            ok(&g["ua"], 1, r),
            "TreeKemRecord",
            "{form}: another version"
        );
    }
    let empty = reg(&full, &|_, k| k.clear());
    assert_eq!(ok(&g["ua"], 0, &empty), "TreeKemRecord", "no key");
}

// ------------------------------------------------------------------ the forward walk (C25, C26; plan T11)

/// An endpoint that lies: the views a lie row names replaced (by read name, each still logged), the others the home's.
struct Lying<'a> {
    home: &'a mut Home,
    overrides: &'a serde_json::Map<String, Value>,
}
impl TreeReader for Lying<'_> {
    fn read(&mut self, v: View) -> scaas_ua::wallet::Result<Value> {
        let name = v.to_string();
        match self.overrides.get(&name) {
            Some(x) => {
                self.home.log.push(name);
                Ok(x.clone())
            }
            None => self.home.read(v),
        }
    }
    fn ua_key_of(&self, ua: &[u8; 32]) -> Option<(u16, Vec<u8>)> {
        self.home.ua_key_of(ua)
    }
    fn accepted(&self, ua: &[u8; 32], i: u16) -> bool {
        self.home.accepted(ua, i)
    }
    fn msig_at(&self, ua: &[u8; 32], version: u64) -> Option<(Vec<u8>, [u8; 32])> {
        self.home.msig_at(ua, version)
    }
    fn registration(&self, ua: &[u8; 32]) -> Option<(scaas_ua::ua_portable::UAAttrs, Vec<u8>)> {
        self.home.registration(ua)
    }
}

/// The pin of every epoch is clientkeys' byte for byte, and the walk from any of them reaches the tree, admins and pin of the
/// walk from the cold tree; every lie row of `tree-secrets.json` (E-1, F-1, sc-F-3, sc-F-7, E-4, the lag, exits under the
/// wrong epoch, treeId or signer) gives the row's result in replay and in prepare, its honest views accepted.
#[test]
fn tree_lies_and_pins() {
    let v = pq("tree-secrets");
    let (_w, keys) = keys();
    let world = World::new(&v);
    let mut homes = BTreeMap::new();
    for sc in v["scenarios"].as_array().unwrap() {
        let steps = sc["steps"].as_array().unwrap().len();
        let mut h = scenario(&keys, &v, &world, sc, &mut vec![], Some(steps));
        let name = sc["name"].as_str().unwrap().to_string();
        let pins = scaas_ua::wallet::tree::tree_pins(SC, &mut h).unwrap();
        assert_eq!(
            json!(pins.iter().map(Pin::to_json).collect::<Vec<_>>()),
            sc["pins"],
            "{name} pins"
        );
        let cold = tree_prepare(SC, &mut h, None).unwrap();
        for p in &pins {
            let q = tree_prepare(SC, &mut h, Some(p)).unwrap();
            assert_eq!(
                (&q.tree(), &q.pin(), &q.parent_admins()),
                (&cold.tree(), &cold.pin(), &cold.parent_admins()),
                "{name} from {}",
                p.epoch
            );
        }
        let head = cold.pin().clone();
        let above = Pin {
            epoch: head.epoch + 1,
            ..head.clone()
        };
        assert_eq!(
            code(tree_prepare(SC, &mut h, Some(&above))),
            "TreeCheckpoint"
        );
        let twin = Pin {
            hash: [3; 32],
            ..head
        };
        assert_eq!(code(tree_prepare(SC, &mut h, Some(&twin))), "TreeConflict");
        homes.insert(name, h);
    }
    let rows = v["lies"].as_array().unwrap();
    assert!(rows.len() >= 13);
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let h = homes.get_mut(row["world"].as_str().unwrap()).unwrap();
        let (d, kem) = &world.devices[row["device"].as_str().unwrap()];
        let dev = TreeDevice {
            ua: a32(&d["ua"]),
            key_id: u(&d["keyId"]),
            kem,
        };
        let pin = (!row["pin"].is_null()).then(|| Pin::from_json(&row["pin"]).unwrap());
        let overrides = row["overrides"].as_object().unwrap();
        let want = |k: &str| row["expect"][k].as_str().unwrap_or("accepted").to_string();
        let mut l = Lying { home: h, overrides };
        let r = keys.tree_replay(SC, &mut l, &dev, pin.as_ref(), 0);
        assert_eq!(code(r.map(|_| ())), want("replay"), "{name}: replay");
        let mut l = Lying { home: h, overrides };
        assert_eq!(
            code(tree_prepare(SC, &mut l, pin.as_ref())),
            want("prepare"),
            "{name}: prepare"
        );
        assert!(
            keys.tree_replay(SC, h, &dev, None, 0).unwrap().is_some(),
            "{name}: honest"
        );
    }
}

/// The builder's own checks before a record is signed (F-4, D-5, B-5, B-8), each beside its twin: a tree that is not the one
/// the parent's hash covers, another KEM key than the author's leaf, more changes, admins or keys of one UA than the contract
/// takes; a tree shape out of bounds from JSON; a tree epoch key never wrapped.
#[test]
fn tree_builder_bounds() {
    let o = Own::new();
    let mut h = o.home();
    assert!(o.prepare(&mut h, 0, &[0], INFO_A, &[3]).is_ok());
    let prep = tree_prepare(OWN, &mut h, None).unwrap();
    let (sid, tid) = (h.epochs[0].id, h.tree_id);
    let tree = prep.tree().clone();
    let rec = |ua: &[u8; 32], _: u64| o.record_of(ua);
    let build = |h: &mut Home, kem: &KemKeyPair, admins: Vec<[u8; 32]>| {
        let mut kf = |x: u32| target_of(h, &tree, 0, x, &rec);
        o.keys
            .tree_build_commit(
                OWN,
                CommitInput {
                    parent: &prep,
                    session_id: sid,
                    tree_id: tid,
                    author: o.ua(0),
                    leaf: 0,
                    key_id: 1,
                    kem,
                    removes: vec![],
                    adds: vec![],
                    admins,
                    info: None,
                    key_of: &mut kf,
                },
            )
            .map(|_| ())
    };
    let admins = prep.parent_admins().to_vec();
    assert_eq!(code(build(&mut h, &o.kems[0], admins.clone())), "accepted");
    // a tree the parent's hash does not cover cannot be handed in since B2-9: `CommitInput` takes the walk's `Prepared`
    assert_eq!(
        code(build(&mut h, &o.kems[1], admins.clone())),
        "TreeKeyHash"
    );
    let many: Vec<[u8; 32]> = (0..33u8).map(|i| [i; 32]).collect();
    assert_eq!(code(build(&mut h, &o.kems[0], many)), "PqChatShape");
    // the change and key bounds on the public tree (the contract's PqChatShape)
    let me = prep.tree().leaf(0).unwrap().clone();
    let add = |i: u32, ua: [u8; 32]| Add {
        leaf: prep.tree().used + i,
        ua,
        key_id: 10 + u64::from(i),
        via: ZERO,
        kem_hash: keccak256(&[i as u8; 4]),
    };
    let ch = |n: u32, ua: &dyn Fn(u32) -> [u8; 32]| Changes {
        author: me.ua,
        leaf: 0,
        key_id: me.key_id,
        removes: vec![],
        adds: (0..n).map(|i| add(i, ua(i))).collect(),
        pathless: false,
    };
    // the author's own UA: 1 leaf + 7 Adds = KEYS_PER_UA_MAX, one more is refused
    assert!(prep.tree().filtered_path_after(&ch(7, &|_| me.ua)).is_ok());
    assert_eq!(
        code(prep.tree().filtered_path_after(&ch(8, &|_| me.ua))),
        "PqChatShape"
    );
    // 20 changes of distinct UAs, then 21 (TREE_CHANGES_MAX, owner 2026-11-25)
    let distinct = |i: u32| [i as u8 + 0x80; 32];
    assert!(prep.tree().filtered_path_after(&ch(20, &distinct)).is_ok());
    assert_eq!(
        code(prep.tree().filtered_path_after(&ch(21, &distinct))),
        "PqChatShape"
    );
    // a tree's JSON out of bounds (B-5): 2^31 leaves, used above leaves, a node list of another width
    let mut j = prep.tree().to_json();
    assert!(Tree::vectors_from_json(&j).is_ok());
    j["leaves"] = json!(2_147_483_648u64);
    assert_eq!(code(Tree::vectors_from_json(&j)), "PqChatShape");
    let mut j = prep.tree().to_json();
    j["used"] = json!(prep.tree().leaves + 1);
    assert_eq!(code(Tree::vectors_from_json(&j)), "PqChatShape");
    let mut j = prep.tree().to_json();
    j["nodes"].as_array_mut().unwrap().push(Value::Null);
    assert_eq!(code(Tree::vectors_from_json(&j)), "PqChatShape");
    // B-8: a tree epoch key is a handle and never wrapped; an epoch key of mode 0 is (the twin)
    let r = o.replay(&mut h, 1);
    let k = r.epochs.last().unwrap().k.as_ref().unwrap();
    let pk = o.kems[2].kem_pk();
    assert_eq!(
        o.keys.kem_wrap(k, b"x", b"", &pk).err(),
        Some(Error::Argument)
    );
    let flat = o.keys.random_key(KeyUsage::Derive).unwrap();
    assert!(o.keys.kem_wrap(&flat, b"x", b"", &pk).is_ok());
}

/// `judge_commit` (§8, §9; F-2, E-2), as clientkeys' `judgeCommit`: a non-admin drops a gone admin plainly; every refusal of
/// the contract's `_walkJudge` beside its twin.
#[test]
fn tree_judge_commit() {
    let id = |s: &str| keccak256(format!("scaas/pqchat/tree-test/{s}").as_bytes());
    let key = |n: &str, k: u64| Leaf {
        ua: id(&format!("ua/{n}")),
        key_id: k,
        kem_hash: id(&format!("kem/{n}/{k}")),
    };
    let mut ks = vec![key("A", 1), key("B", 1), key("C", 1), key("E", 1)];
    ks.sort_by_key(|x| x.ua);
    let t = Tree::cold(&ks).unwrap();
    let ua = |n: &str| id(&format!("ua/{n}"));
    let leaf = |n: &str| {
        (0..t.leaves)
            .find(|i| t.leaf(*i).unwrap().ua == ua(n))
            .unwrap()
    };
    let sorted = |ns: &[&str]| {
        let mut v: Vec<[u8; 32]> = ns.iter().map(|n| ua(n)).collect();
        v.sort();
        v
    };
    let head = sorted(&["A", "E"]);
    let rm = |n: &str| Remove {
        leaf: leaf(n),
        ua: ua(n),
        key_id: 1,
    };
    let judge =
        |tree: &Tree, by: &str, removes: Vec<Remove>, adds: Vec<Add>, admins: &[[u8; 32]]| {
            let c = Changes {
                author: ua(by),
                leaf: leaf(by),
                key_id: 1,
                removes,
                adds,
                pathless: false,
            };
            let n = tree.filtered_path_after(&c).unwrap().len();
            let after = tree.apply_commit(&c, &vec![id("k"); n]).unwrap();
            code(tree.judge_commit(&after.tree, &c, admins, &head))
        };
    let add = |n: &str, k: u64, l: u32| {
        let x = key(n, k);
        Add {
            leaf: l,
            ua: x.ua,
            key_id: k,
            via: ZERO,
            kem_hash: x.kem_hash,
        }
    };
    let mut g = t.clone();
    g.mark_gone(&[ua("E")]);
    assert_eq!(
        judge(&g, "C", vec![rm("E")], vec![], &sorted(&["A"])),
        "accepted"
    );
    assert_eq!(
        judge(&g, "C", vec![rm("E")], vec![], &head),
        "PqChatRemovedKept"
    );
    assert_eq!(
        judge(&t, "C", vec![], vec![], &sorted(&["A"])),
        "PqChatNotAdmin"
    );
    assert_eq!(
        judge(&t, "C", vec![rm("B")], vec![], &head),
        "PqChatNotAdmin"
    );
    assert_eq!(
        judge(&t, "C", vec![], vec![add("D", 1, 4)], &head),
        "PqChatNotAdmin"
    );
    assert_eq!(judge(&t, "A", vec![rm("B")], vec![], &head), "accepted");
    assert_eq!(
        judge(&t, "C", vec![], vec![add("C", 2, 4)], &head),
        "accepted"
    );
    let mut rev = head.clone();
    rev.reverse();
    assert_eq!(judge(&t, "A", vec![], vec![], &rev), "PqChatShape");
    let mut many: Vec<[u8; 32]> = (0..33).map(|i| id(&format!("admin/{i}"))).collect();
    many.sort();
    assert_eq!(judge(&t, "A", vec![], vec![], &many), "PqChatShape");
    assert_eq!(
        judge(&t, "A", vec![rm("E")], vec![], &head),
        "PqChatRemovedKept"
    );
    assert_eq!(
        judge(&t, "A", vec![rm("E")], vec![], &sorted(&["A"])),
        "accepted"
    );
    assert_eq!(
        judge(&t, "A", vec![], vec![], &[id("keyless")]),
        "PqChatTreeAdmins"
    );
    assert_eq!(
        judge(&t, "A", vec![], vec![], &sorted(&["A", "B"])),
        "accepted"
    );
}

/// The key's period from an endpoint (C28, codex-r2-10, C-7), as clientkeys' period test: an end at or below the join or past
/// the head, and a join past the head, are `TreePeriod`; the honest period is the twin.
#[test]
fn tree_period_bounds() {
    let v = pq("tree-secrets");
    let (_w, keys) = keys();
    let world = World::new(&v);
    let sc = v["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "retired")
        .unwrap();
    let steps = sc["steps"].as_array().unwrap().len();
    let mut home = scenario(&keys, &v, &world, sc, &mut vec![], Some(steps));
    let dev = |n: &str| {
        let (d, kem) = &world.devices[n];
        TreeDevice {
            ua: a32(&d["ua"]),
            key_id: u(&d["keyId"]),
            kem,
        }
    };
    let (d, e) = (dev("D"), dev("E"));
    let gone = format!("goneKeyOf({})", hx(&keccak256(&d.kem.kem_pk())));
    assert!(keys
        .tree_replay(SC, &mut home, &d, None, 0)
        .unwrap()
        .is_some());
    let cases: [Lie; 3] = [
        (gone.clone(), |x| x["endEpoch"] = json!(0)),
        (gone, |x| x["endEpoch"] = json!(99)),
        ("treeLeaves()".into(), |x| x[3]["joinEpoch"] = json!(99)),
    ];
    for (i, (read, f)) in cases.into_iter().enumerate() {
        let device = if i < 2 { &d } else { &e };
        let mut t = Tamper {
            home: &mut home,
            read: read.clone(),
            f,
        };
        assert_eq!(
            code(keys.tree_replay(SC, &mut t, device, None, 0)),
            "TreePeriod",
            "{read}"
        );
    }
    assert!(keys
        .tree_replay(SC, &mut home, &e, None, 0)
        .unwrap()
        .is_some());
}

/// C-2, B2-7 (fable-B reproduced it red on 08f68484a): the compromise warning's leaves left come from the walk's head tree;
/// a served `joinEpoch` moved off the Add changes nothing.
#[test]
fn tree_warning_leaves_left_from_the_walk() {
    let o = Own::new();
    let mut h = o.home();
    o.commit(&mut h, 0, &[0], INFO_A, &[3], other_node_keys);
    let r = o.replay(&mut h, 0);
    assert_eq!(r.epochs.last().unwrap().state, State::Compromise);
    assert_eq!(r.warnings[0].leaves_left, vec![3]);
    fn lie(v: &mut Value) {
        v[3]["joinEpoch"] = json!(0);
    }
    let mut t = Tamper {
        home: &mut h,
        read: "treeLeaves()".into(),
        f: lie,
    };
    let r = o
        .keys
        .tree_replay(OWN, &mut t, &o.dev(0), None, 0)
        .unwrap()
        .unwrap();
    assert_eq!(r.warnings[0].leaves_left, vec![3]);
}

/// B2-8 (fable-B reproduced it red): a tree epoch key is a handle and never leaves sealed (`seal_key`), as it never leaves
/// wrapped; its twin, a drawn key, seals.
#[test]
fn tree_key_never_sealed() {
    let o = Own::new();
    let mut h = o.home();
    let r = o.replay(&mut h, 1);
    let k = r.epochs.last().unwrap().k.as_ref().unwrap();
    let under = o.keys.random_key(KeyUsage::KeyWrap).unwrap();
    assert_eq!(code(o.keys.seal_key(&under, k, b"")), "Argument");
    let drawn = o.keys.random_key(KeyUsage::Data).unwrap();
    assert_eq!(o.keys.seal_key(&under, &drawn, b"").unwrap().len(), 60);
}

/// E-3, B2-2: a replay resumed from the device's previous one walks from its pin and opens only the epochs after it, with the
/// same K and info as a full replay; the walk keeps the trees at its start and at the head only (never one per epoch).
#[test]
fn tree_replay_resumed_from_the_pin() {
    let o = Own::new();
    let mut h = o.home();
    for n in 1..=4usize {
        o.commit(&mut h, n % 2, &[0], INFO_A, &[], honest);
    }
    let mut r4 = o.replay(&mut h, 2);
    o.commit(&mut h, 0, &[0], INFO_A, &[3], honest); // 5: the admin adds D
    for n in 6..=8usize {
        o.commit(&mut h, n % 2, &[0], INFO_A, &[], honest);
    }
    let full = o.replay(&mut h, 2);
    // C-6: a lying read during a resume is refused and leaves the previous replay as it was (its node keys and pin), so the
    // device resumes from it again instead of replaying the whole history
    let (held, pin) = (r4.held.keys().copied().collect::<Vec<_>>(), r4.pin.clone());
    assert!(!held.is_empty(), "control: the device holds node keys at 4");
    let mut lying = Tamper {
        home: &mut h,
        read: "commitOf(6)".into(),
        f: |v| flip(&mut v["record"]["treeHash"]),
    };
    let e = o
        .keys
        .tree_resume(OWN, &mut lying, &o.dev(2), &mut r4, 0)
        .map(|_| ());
    assert_eq!(code(e), "TreeReadCorrupted");
    assert_eq!(
        (r4.held.keys().copied().collect::<Vec<_>>(), &r4.pin),
        (held, &pin)
    );
    h.log.clear();
    let more = o
        .keys
        .tree_resume(OWN, &mut h, &o.dev(2), &mut r4, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        more.epochs.iter().map(|e| e.epoch).collect::<Vec<_>>(),
        vec![5, 6, 7, 8]
    );
    let reveal = |k: &Option<scaas_ua::wallet::KeyHandle>| {
        k.as_ref().map(|k| o.keys.vectors_reveal(k).unwrap())
    };
    for e in &more.epochs {
        let g = full.epochs.iter().find(|x| x.epoch == e.epoch).unwrap();
        assert_eq!(
            (e.state, e.in_force.clone(), e.flagged),
            (g.state, g.in_force.clone(), g.flagged)
        );
        assert_eq!(reveal(&e.k), reveal(&g.k), "epoch {}", e.epoch);
        assert_eq!(more.rosters[&e.epoch], full.rosters[&e.epoch]);
    }
    assert_eq!(more.pin, full.pin);
    let commits: Vec<&String> = h
        .log
        .iter()
        .filter(|x| x.starts_with("commitOf("))
        .collect();
    assert_eq!(
        commits,
        [
            "commitOf(4)",
            "commitOf(5)",
            "commitOf(6)",
            "commitOf(7)",
            "commitOf(8)"
        ]
    );
    assert!(!h
        .log
        .iter()
        .any(|x| x.starts_with("kemKeyAt(") || x.starts_with("wrapAt(0,")));
    // the rosters of the secret range only: a member since 0 holds every epoch's
    assert_eq!(
        full.rosters.keys().copied().collect::<Vec<_>>(),
        (0..=8).collect::<Vec<_>>()
    );
    assert_eq!(
        more.rosters.keys().copied().collect::<Vec<_>>(),
        vec![5, 6, 7, 8]
    );
    // a member added at 5 (D) holds the rosters of its own range only (M141)
    let late = o.replay(&mut h, 3);
    assert_eq!(late.join_epoch, 5);
    assert_eq!(
        late.rosters.keys().copied().collect::<Vec<_>>(),
        vec![5, 6, 7, 8]
    );
    assert_eq!(late.rosters[&5], full.rosters[&5]);
    // the memory: the trees at the start and the head
    assert_eq!(
        scaas_ua::wallet::tree::tree_walk_trees(OWN, &mut h, None).unwrap(),
        vec![0, 8]
    );
    let pin4 = full.pin.clone();
    assert_eq!(
        scaas_ua::wallet::tree::tree_walk_trees(OWN, &mut h, Some(&pin4)).unwrap(),
        vec![8]
    );
}

/// B-5: a caller's leaf outside the tree has no path, never an overflow of `2 * leaf`.
#[test]
fn tree_path_of_a_leaf_outside() {
    assert_eq!(
        scaas_ua::wallet::tree::path_from_list(u32::MAX, &[2], 4),
        None
    );
    assert_eq!(scaas_ua::wallet::tree::path_from_list(4, &[2], 4), None);
    assert!(scaas_ua::wallet::tree::path_from_list(0, &[2], 4).is_some());
    let t = Tree::cold(&[]).unwrap_or_default();
    assert!(t.filtered_path(u32::MAX).is_empty());
}

/// C-4 = D-6 (+ B-16) of the TreeKEM T4-T9 review: a resume that finds no new epoch keeps the info in force and the node keys
/// (its replay seals the full info as the previous one did), and a device that resumes from it after more commits follows
/// them as a full replay does: each resume chains, none drops what the device held.
#[test]
fn tree_resume_twice_keeps_the_keys_and_the_info() {
    let o = Own::new();
    let mut h = o.home();
    for n in 1..=4usize {
        o.commit(&mut h, n % 2, &[0], INFO_A, &[], honest);
    }
    let mut r4 = o.replay(&mut h, 2);
    let seal = r4.info_to_seal().map(str::to_string);
    assert!(
        seal.is_some(),
        "control: the device holds the info in force at 4"
    );
    let held = r4.held.keys().copied().collect::<Vec<_>>();
    let mut idle = o
        .keys
        .tree_resume(OWN, &mut h, &o.dev(2), &mut r4, 0)
        .unwrap()
        .unwrap();
    assert!(idle.epochs.is_empty(), "no new epoch");
    assert_eq!(
        idle.info_to_seal().map(str::to_string),
        seal,
        "the info in force kept"
    );
    assert_eq!(
        idle.held.keys().copied().collect::<Vec<_>>(),
        held,
        "the node keys kept"
    );
    for n in 5..=7usize {
        o.commit(&mut h, n % 2, &[0], INFO_A, &[], honest);
    }
    let full = o.replay(&mut h, 2);
    let more = o
        .keys
        .tree_resume(OWN, &mut h, &o.dev(2), &mut idle, 0)
        .unwrap()
        .unwrap();
    let reveal = |k: &Option<scaas_ua::wallet::KeyHandle>| {
        k.as_ref().map(|k| o.keys.vectors_reveal(k).unwrap())
    };
    assert_eq!(
        more.epochs.iter().map(|e| e.epoch).collect::<Vec<_>>(),
        vec![5, 6, 7]
    );
    for e in &more.epochs {
        let g = full.epochs.iter().find(|x| x.epoch == e.epoch).unwrap();
        assert_eq!(
            (e.state, reveal(&e.k)),
            (g.state, reveal(&g.k)),
            "epoch {}",
            e.epoch
        );
    }
    assert_eq!(more.info_to_seal(), full.info_to_seal());
}

// ------------------------------------------------------------------ the path-less operation's handle (the path-less delta §6.5)

/// claude-19: the path-less operation on a handle of another parent is `TreeHandle`, nothing built; the device's handle of
/// the head it replayed builds. The handle's `next` is the replay's head only (every row's `head` compared in `replay_row`:
/// none for a device that did not follow the head or whose period ended).
#[test]
fn tree_pathless_handle_of_another_parent() {
    let v = pq("tree-secrets");
    let (_w, keys) = keys();
    let world = World::new(&v);
    let s = v["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "pathless")
        .unwrap();
    let mut differs = Vec::new();
    let mut home = scenario(&keys, &v, &world, s, &mut differs, Some(3));
    let (d, kem) = &world.devices["A"];
    let dev = TreeDevice {
        ua: a32(&d["ua"]),
        key_id: u(&d["keyId"]),
        kem,
    };
    let old = keys.tree_replay(SC, &mut home, &dev, None, 0).unwrap().unwrap();
    let step6 = &s["steps"][5]["record"];
    let add = Add::from_json(&step6["adds"][0]).unwrap();
    let input = |prep| PathlessInput {
        parent: prep,
        session_id: a32(&step6["sessionId"]),
        tree_id: a32(&step6["treeId"]),
        author: dev.ua,
        leaf: 0,
        key_id: dev.key_id,
        kem,
        adds: vec![(add.clone(), world.record(&add.ua, add.key_id))],
        info: None,
    };
    home.land_commit(&s["steps"][3]);
    let prep = tree_prepare(SC, &mut home, None).unwrap();
    let mut rand = |x: &str, n: usize| Ok(rnd(&format!("t/handle/{x}"), n));
    let hd = old.head.as_ref().expect("the head's handle");
    assert_eq!(
        code(keys.vectors_tree_prepare_pathless(SC, input(&prep), hd, 0, None, &mut rand)),
        "TreeHandle"
    );
    let now = keys.tree_replay(SC, &mut home, &dev, None, 0).unwrap().unwrap();
    let hd = now.head.as_ref().expect("the head's handle");
    assert_eq!(hd.epoch_id, prep.parent_epoch_id());
    assert!(keys
        .vectors_tree_prepare_pathless(SC, input(&prep), hd, 0, None, &mut rand)
        .is_ok());
}

/// C43, F-7 (the path-less delta §4.2): epoch 0's tag in the session record decides the genesis key state: a record signed
/// with another tag is not followed ("tag") by every member; the honest record is followed.
#[test]
fn tree_genesis_tag_decides() {
    let o = Own::new();
    let session = json!({"creator": hx(&o.ua(0)), "nonce": 1, "homeChain": hx(&[7; 32]),
        "homeChatContract": hx(&[0xc4; 20]), "admins": [hx(&o.ua(0))],
        "members": (0..3).map(|i| json!({"ua": hx(&o.ua(i)), "keyId": 1, "via": hx(&ZERO)})).collect::<Vec<_>>(),
        "groupMode": 1, "pathRefreshBound": 0});
    let kems: Vec<KemRecord> = (0..3).map(|i| o.record(i)).collect();
    let g = o
        .keys
        .tree_create_genesis(OWN, &session, &kems, INFO_A.as_bytes())
        .unwrap();
    for bad in [false, true] {
        let mut rec = g.record.clone();
        if bad {
            rec["confirmTag"] = json!(hx(&[0x7a; 32]));
        }
        let sig = o.sign(0, "PqChatSession", &rec);
        let kems = (0..4).map(|i| ((o.ua(i), 1), o.record(i))).collect();
        let ua_keys = (0..4)
            .map(|i| (o.ua(i), (MLDSA65, o.uas[i].key_data())))
            .collect();
        let tid = tp::tree_id(OWN.typed, &rec).unwrap();
        let mut h = new_home(&rec, sig, g.wraps.clone(), g.session_id, tid, kems, ua_keys);
        for i in 0..3 {
            let r = o.replay(&mut h, i);
            let want = if bad {
                State::NotFollowed("tag")
            } else {
                State::Followed
            };
            assert_eq!(r.epochs[0].state, want, "member {i}, bad tag {bad}");
        }
    }
}

/// C41 (the path-less delta §3.1): a session record whose `pathRefreshBound` is above 510 is one the contract refuses, so the
/// walk takes it as a lying read; 510 is walked.
#[test]
fn tree_session_bound_above_the_cap_is_a_lie() {
    let o = Own::new();
    for (bound, ok) in [(510u32, true), (511, false)] {
        let session = json!({"creator": hx(&o.ua(0)), "nonce": 1, "homeChain": hx(&[7; 32]),
            "homeChatContract": hx(&[0xc4; 20]), "admins": [hx(&o.ua(0))],
            "members": (0..3).map(|i| json!({"ua": hx(&o.ua(i)), "keyId": 1, "via": hx(&ZERO)})).collect::<Vec<_>>(),
            "groupMode": 1, "pathRefreshBound": bound});
        let kems: Vec<KemRecord> = (0..3).map(|i| o.record(i)).collect();
        let g = o
            .keys
            .tree_create_genesis(OWN, &session, &kems, INFO_A.as_bytes())
            .unwrap();
        let sig = o.sign(0, "PqChatSession", &g.record);
        let kems = (0..4).map(|i| ((o.ua(i), 1), o.record(i))).collect();
        let ua_keys = (0..4)
            .map(|i| (o.ua(i), (MLDSA65, o.uas[i].key_data())))
            .collect();
        let mut h = new_home(&g.record, sig, g.wraps.clone(), g.session_id, g.tree_id, kems, ua_keys);
        let r = o.keys.tree_replay(OWN, &mut h, &o.dev(1), None, 0);
        if ok {
            assert_eq!(r.unwrap().unwrap().epochs[0].state, State::Followed);
        } else {
            assert_eq!(code(r), "TreeReadCorrupted", "bound {bound}");
        }
    }
}
