// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! TreeKEM in `ua-rs` (plan T2 of docs/superpowers/plans/2026-11-23-pqchat-treekem.md): every row of
//! `smartcontracts/vectors/pqchat/tree.json` (the public side, `wallet::tree_public`) and of `tree-secrets.json` (the secrets
//! behind handles, `wallet::tree`) reproduced byte for byte, the scenarios landed on a model of the home and every device's
//! replay compared with its row: states, `K`, the info in force, the warnings and the reads in order. Feature
//! `app-core,vectors`.
#![cfg(all(feature = "app-core", feature = "vectors"))]
use scaas_ua::wallet::kem::x25519;
use scaas_ua::wallet::tree::{
    key_of, path_context, tree_prepare, CommitInput, CtAt, EpochFields, Info, InfoTook, PathCt,
    Pin, State, TreeDevice, TreeReader, View, PQCHAT_TREE,
};
use scaas_ua::wallet::tree_public::{
    array_hash, ct_targets_hash, genesis_ctx, kem_admission, leaf_hash, path_list_hash,
    struct_hash, tree_id, Add, Changes, Leaf, Node, Remove, Tree, ZERO,
};
use scaas_ua::wallet::{pqchat, tree_public as tp, AppKeys, Error, KemKeyPair, KeyUsage, Wallet};
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
        let t = Tree::from_json(&r["tree"]).unwrap();
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
    for r in v["treeHash"]["commits"].as_array().unwrap() {
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
}

struct Home {
    tree_id: [u8; 32],
    tree: Tree,
    genesis_tree_hash: [u8; 32],
    epochs: Vec<Epoch>,
    join: BTreeMap<u32, (u64, u64)>,
    node_key: BTreeMap<u32, (Vec<u8>, u64)>,
    gone: BTreeMap<[u8; 32], (u64, u64, Value)>,
    periods: BTreeMap<String, (u64, u64)>,
    kems: BTreeMap<([u8; 32], u64), Vec<u8>>,
    ua_keys: BTreeMap<[u8; 32], Vec<u8>>,
    log: Vec<String>,
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
        self.epochs.push(Epoch {
            id: a32(&st["epochId"]),
            record: c.clone(),
            sig: st["sig"].clone(),
            ct_targets: targets,
            ct_hashes: st["ctHashes"].as_array().unwrap().clone(),
            cts: st["cts"].as_array().unwrap().clone(),
            wraps: st["wraps"].as_array().unwrap().clone(),
        });
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
        for ua in uas {
            self.gone
                .insert(ua, (kind, self.epochs.len() as u64 - 1, g.clone()));
        }
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
                "treeHash": hx(&self.tree.tree_hash()), "genesisTreeHash": hx(&self.genesis_tree_hash)}),
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
                Some((k, e, _)) => json!({"kind": k, "epoch": e}),
                None => json!({"kind": 0, "epoch": 0}),
            },
            View::GoneRecord(ua) => match self.gone.get(ua) {
                Some((_, _, g)) => json!({"struct": g["struct"], "record": g["record"], "sig": g["sig"]}),
                None => Value::Null,
            },
            View::GoneOwnKeyOf(ua, k) => self.period(&format!("pair/{}/{}", hx(ua), hx(k))),
            View::GoneKeyOf(k) => self.period(&format!("wide/{}", hx(k))),
            View::KemKeyAt(ua, k) => json!(self.kems.get(&(*ua, k)).map_or("0x".into(), |p| hx(p))),
        })
    }
    fn ua_key_of(&mut self, ua: &[u8; 32]) -> Option<(u16, Vec<u8>)> {
        self.ua_keys.get(ua).map(|k| (MLDSA65, k.clone()))
    }
}

// ------------------------------------------------------------------ tree-secrets.json

struct World {
    devices: BTreeMap<String, (Value, KemKeyPair)>,
}

impl World {
    fn new(v: &Value) -> World {
        let mut devices = BTreeMap::new();
        for (name, d) in v["devices"].as_object().unwrap() {
            let seed: [u8; 96] = unhex(&d["kemSeed"]).try_into().unwrap();
            let k = KemKeyPair::vectors_ephemeral(&seed).unwrap();
            assert_eq!(hx(&k.kem_pk()), d["kemPk"], "device {name}");
            devices.insert(name.clone(), (d.clone(), k));
        }
        World { devices }
    }
    fn kem(&self, name: &str) -> &KemKeyPair {
        &self.devices[name].1
    }
    fn by_key(&self, ua: &Value, key_id: &Value) -> &str {
        self.devices
            .iter()
            .find(|(_, (d, _))| d["ua"] == *ua && d["keyId"] == *key_id)
            .unwrap()
            .0
    }
}

fn info_of(
    keys: &AppKeys,
    k: &[u8; 32],
    session: &[u8; 32],
    epoch: &[u8; 32],
    sealed: &Value,
) -> Option<String> {
    let h = keys.vectors_import(k, KeyUsage::Derive).unwrap();
    match keys
        .vectors_tree_open_info(SC, &h, session, epoch, &unhex(sealed))
        .unwrap()
    {
        Info::Marker => None,
        Info::Json(j) => Some(j),
    }
}

#[test]
fn tree_secrets_every_row() {
    let v = pq("tree-secrets");
    let (_w, keys) = keys();
    for (name, label) in v["labels"].as_object().unwrap() {
        assert_eq!(*label, format!("{}/{name}", SC.prefix));
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
        let (s, k) = keys
            .vectors_tree_schedule(SC, &unhex(&r["joiner"]), &f)
            .unwrap();
        assert_eq!(hx(&s), r["S"]);
        assert_eq!(hx(&k), r["K"]);
    }
    let mut rebuilt_differs = Vec::new();
    for sc in v["scenarios"].as_array().unwrap() {
        scenario(&keys, &v, &world, sc, &mut rebuilt_differs, None);
    }
    // the steps a generator built with a fault or a foreign seed: a seed's own rebuild differs there, nowhere else
    assert_eq!(rebuilt_differs, KNOWN_FAULTS, "rebuilt commits that differ");
}

/// Steps clientkeys scripts/treekem-fixture.mjs builds with `commitBadFor` (a validly signed bad ciphertext: heal 1, 2;
/// behind 1, 2; gap 1; admin-gap 1) or a foreign `seedOf` (foreign 1, empty-path-foreign 2): not the author's honest build.
const KNOWN_FAULTS: &[&str] = &[
    "heal/epoch-1",
    "heal/epoch-2",
    "behind/epoch-1",
    "behind/epoch-2",
    "gap/epoch-1",
    "foreign/epoch-1",
    "empty-path-foreign/epoch-2",
    "admin-gap/epoch-1",
];

/// Steps whose author chose the info (the fixture's `info:`); every other step seals what its author's replay of the head
/// gives as the info to seal (C33).
const EXPLICIT_INFO: &[&str] = &[
    "gap/epoch-1",
    "gap-control/epoch-1",
    "foreign/epoch-1",
    "admin-gap/epoch-4",
];

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
    let kem_pks: Vec<Vec<u8>> = members
        .iter()
        .map(|m| world.kem(world.by_key(&m["ua"], &m["keyId"])).kem_pk())
        .collect();
    let sid = a32(&g["sessionId"]);
    let info = info_of(keys, &a32(&g["K"]), &sid, &sid, &rec["sealedInfo"])
        .expect("a genesis carries a full info");
    let mut rand = |name: &str, n: usize| Ok(rnd(&format!("tree-secrets/{tag}/genesis/{name}"), n));
    let gen = keys
        .vectors_tree_create_genesis(SC, &session, &kem_pks, info.as_bytes(), &mut rand)
        .unwrap();
    assert_eq!(gen.record, *rec, "{tag} genesis");
    assert_eq!(hx(&gen.session_id), g["sessionId"]);
    assert_eq!(hx(&gen.genesis_ctx), g["genesisCtx"]);
    assert_eq!(hx(&gen.tree_id), g["treeId"]);
    assert_eq!(json!(gen.wraps), g["wraps"]);
    assert_eq!(hx(&keys.vectors_reveal(&gen.k).unwrap()), g["K"]);
    // the home
    let mut kems = BTreeMap::new();
    for (d, _) in world.devices.values() {
        kems.insert((a32(&d["ua"]), u(&d["keyId"])), unhex(&d["kemPk"]));
    }
    let ua_keys = v["people"]
        .as_object()
        .unwrap()
        .values()
        .map(|p| (a32(&p["ua"]), unhex(&p["publicKey"])))
        .collect();
    let cold: Vec<Leaf> = members
        .iter()
        .map(|m| Leaf {
            ua: a32(&m["ua"]),
            key_id: u(&m["keyId"]),
            kem_hash: keccak256(&kems[&(a32(&m["ua"]), u(&m["keyId"]))]),
        })
        .collect();
    let tree = Tree::cold(&cold).unwrap();
    let mut home = Home {
        tree_id: gen.tree_id,
        genesis_tree_hash: tree.tree_hash(),
        tree,
        epochs: vec![Epoch {
            id: sid,
            record: rec.clone(),
            sig: g["sig"].clone(),
            ct_targets: vec![],
            ct_hashes: vec![],
            cts: vec![],
            wraps: g["wraps"].as_array().unwrap().clone(),
        }],
        join: (0..members.len() as u32)
            .map(|i| (i, (0, i as u64)))
            .collect(),
        node_key: BTreeMap::new(),
        gone: BTreeMap::new(),
        periods: BTreeMap::new(),
        kems,
        ua_keys,
        log: vec![],
    };
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

/// Builds the step's commit from the author's seed on the prepared head; whether every byte equals the row's.
fn rebuild(keys: &AppKeys, world: &World, home: &mut Home, st: &Value) -> bool {
    let c = &st["record"];
    let author = st["author"].as_str().unwrap();
    let prep = tree_prepare(SC, home, None).unwrap();
    let info = info_of(
        keys,
        &a32(&st["K"]),
        &a32(&c["sessionId"]),
        &a32(&st["epochId"]),
        &c["sealedInfo"],
    );
    let adds = c["adds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            let a = Add::from_json(x).unwrap();
            let k = home.kems[&(a.ua, a.key_id)].clone();
            (a, k)
        })
        .collect();
    let name = st["name"].as_str().unwrap().to_string();
    if !EXPLICIT_INFO.contains(&name.as_str()) {
        // the info the author's own replay of the head says to seal: the full info in force, or the marker (C33)
        let (d, kem) = &world.devices[author];
        let dev = TreeDevice {
            ua: a32(&d["ua"]),
            key_id: u(&d["keyId"]),
            kem,
        };
        let r = keys.tree_replay(SC, home, &dev, None).unwrap().unwrap();
        assert_eq!(
            r.info_to_seal(),
            info.as_deref(),
            "{name}: the info to seal"
        );
    }
    let tree = prep.tree.clone();
    let mut key_fn = |x: u32| key_of(home, &tree, x);
    let input = CommitInput {
        tree: &prep.tree,
        parent_epoch_id: prep.parent_epoch_id,
        parent_epoch: prep.parent_epoch,
        parent_tree_hash: prep.parent_tree_hash,
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
    let mut rand = |x: &str, n: usize| Ok(rnd(&format!("tree-secrets/{name}/{x}"), n));
    let b = keys
        .vectors_tree_build_commit(SC, input, u(&c["nonce"]), &mut rand)
        .unwrap();
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
        .tree_replay(SC, home, &device, None)
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
    assert_eq!(json!(home.log), want["reads"], "{at} reads");
    // the pin it would store: the head and the hash of its record; a replay against it passes, a wrong hash conflicts
    let pin = r.pin.clone();
    assert_eq!(pin.epoch as usize, home.epochs.len() - 1);
    assert!(keys.tree_replay(SC, home, &device, Some(&pin)).is_ok());
    let bad = Pin {
        hash: [1; 32],
        ..pin
    };
    assert_eq!(
        code(keys.tree_replay(SC, home, &device, Some(&bad))),
        "TreeConflict"
    );
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
    fn ua_key_of(&mut self, ua: &[u8; 32]) -> Option<(u16, Vec<u8>)> {
        self.home.ua_key_of(ua)
    }
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
    let r = keys.tree_replay(SC, &mut home, &c, None).unwrap().unwrap();
    assert!(r.epochs.iter().all(|e| e.state == State::Followed));
    // bytes that fail a signed hash or a signature: refused at the read boundary, before any decapsulation (codex-13,
    // codex-r2-15); one view at a time
    let cases: [(String, fn(&mut Value)); 6] = [
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
            code(keys.tree_replay(SC, &mut t, &c, None)),
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
    assert_eq!(code(keys.tree_replay(SC, &mut t, &c, None)), "TreeHeadRoot");
    // a fetched key against the hash that entered the root (codex-1): a node key and a leaf key
    let prep = tree_prepare(SC, &mut home, None).unwrap();
    let node = (0..prep.tree.nodes.len() as u32)
        .find(|x| matches!(prep.tree.node(*x), Node::Parent(_)))
        .unwrap();
    assert!(key_of(&mut home, &prep.tree, node).is_ok());
    assert!(key_of(&mut home, &prep.tree, 0).is_ok());
    let mut t = Tamper {
        home: &mut home,
        read: format!("treeNodeKey({node})"),
        f: flip,
    };
    assert_eq!(code(key_of(&mut t, &prep.tree, node)), "TreeKeyHash");
    let a = home.tree.leaf(0).unwrap().clone();
    let mut t = Tamper {
        home: &mut home,
        read: format!("kemKeyAt({},{})", hx(&a.ua), a.key_id),
        f: flip,
    };
    assert_eq!(code(key_of(&mut t, &prep.tree, 0)), "TreeKeyHash");
    // the checkpoint: below the pinned epoch, another session
    let pin = r.pin.clone();
    let high = Pin {
        epoch: pin.epoch + 1,
        ..pin.clone()
    };
    assert_eq!(
        code(keys.tree_replay(SC, &mut home, &c, Some(&high))),
        "TreeCheckpoint"
    );
    let other = Pin {
        tree_id: [2; 32],
        ..pin.clone()
    };
    assert_eq!(
        code(keys.tree_replay(SC, &mut home, &c, Some(&other))),
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
        .tree_replay(SC, &mut h0, &dev_a, None)
        .unwrap()
        .is_some());
    let mut t = Tamper {
        home: &mut h0,
        read: "treeLeaves()".into(),
        f: |x| flip(&mut x[1]["kemHash"]),
    };
    assert_eq!(
        code(keys.tree_replay(SC, &mut t, &dev_a, None)),
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
        .tree_replay(SC, &mut h0, &dev_h, None)
        .unwrap()
        .is_none());

    // a commit built by the release entry on the epoch-0 head: its nonce drawn inside, so two builds differ (C17); K is an
    // epoch key the mode-0 entries take (the hint, a chain); an added key that fails admission is refused (KemCheck)
    let prep0 = tree_prepare(SC, &mut h0, None).unwrap();
    let rec = &main["genesis"]["record"];
    let build = |keys: &AppKeys, h0: &mut Home, adds: Vec<(Add, Vec<u8>)>| {
        let tree = prep0.tree.clone();
        let mut kf = |x: u32| key_of(h0, &tree, x);
        keys.tree_build_commit(
            SC,
            CommitInput {
                tree: &prep0.tree,
                parent_epoch_id: prep0.parent_epoch_id,
                parent_epoch: 0,
                parent_tree_hash: prep0.parent_tree_hash,
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
        leaf: prep0.tree.used,
        ua: a32(&dd["ua"]),
        key_id: u(&dd["keyId"]),
        via: ZERO,
        kem_hash: keccak256(&kd.kem_pk()),
    };
    assert!(build(&keys, &mut h0, vec![(add.clone(), kd.kem_pk())]).is_ok());
    let mut bad = kd.kem_pk();
    bad[0] = 2;
    let bad_add = Add {
        kem_hash: keccak256(&bad),
        ..add
    };
    assert!(matches!(
        build(&keys, &mut h0, vec![(bad_add, bad)]),
        Err(Error::KemCheck)
    ));

    // the info's bound: the 4,096-B bucket seals (4,124 B), the next is refused (codex-r2-13)
    let mut session = rec.clone();
    session.as_object_mut().unwrap().remove("wrapHashes");
    session.as_object_mut().unwrap().remove("sealedInfo");
    let kem_pks: Vec<Vec<u8>> = rec["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| world.kem(world.by_key(&m["ua"], &m["keyId"])).kem_pk())
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
        .tree_create_genesis(SC, &session, &kem_pks, info_n(fits).as_bytes())
        .unwrap();
    assert_eq!(unhex(&g.record["sealedInfo"]).len(), 4124);
    assert_eq!(
        code(keys.tree_create_genesis(SC, &session, &kem_pks, info_n(fits + 1).as_bytes())),
        "TreeInfoSize"
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
