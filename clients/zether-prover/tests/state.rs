// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T14b (ARCH-POS-13; spec no-decryption-oracle §4.7, §5): Zether on raw storage words. The forge rows
//! (`smartcontracts/vectors/zether/state.json`, `ua-mtx-merge` `test/zether/ZetherStateVectors.t.sol`, real proofs) give the
//! words a reading layer reads and the contract's own views; `state::prepare` rebuilds every `acc`, `pending`, record and leg
//! from the words byte for byte, `state::run` decrypts them, opens the receiver's and the auditor's legs (openings that
//! verify) and proves debits that verify; every word, location and role negative is refused by `prepare`, before the key.
//! UNAUDITED.
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use zether_prover::curve::{decode_point, decode_scalar, encode_point, Bls12381, Fr, G};
use zether_prover::keys::ZetherKey;
use zether_prover::schnorr::{verify_opening, Entry, OpeningKind};
use zether_prover::state::{self, LAYOUT, ROOT};
mod cache_box;

type K = ZetherKey<Bls12381>;

fn rows() -> Value {
    let p = format!("{}/../../smartcontracts/vectors/zether/state.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("{p}"))).unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(&v.as_str().unwrap()[2..]).unwrap()
}

fn pt(v: &Value) -> G<Bls12381> {
    decode_point::<Bls12381>(&h(v)).unwrap()
}

/// The rows' holders: r33_keys.json's `m/12381/60/0/7` (alice), `/1/7` (bob), the fixture's carol, `/1/8` (dave) and the
/// auditor `/0/8`.
fn key(name: &str) -> K {
    let x = match name {
        "alice" => "67c93b3838eb86a76ead85bd6be7ca97ad82758b4ccd30ec58bff013a3392074",
        "bob" => "63a37d32de25c85eafe97a566343e5cae9bf7b957229c247f3ab2c8dc20b1c5a",
        "dave" => "2592aae4a72ff35d24196d8aa5fbf03bb270d3a83056fa7a6b31fb8700bb882e",
        "auditor" => "25f771eaad146dd5c0a479073adf0bdcef837123e5e61770d13bd5f8a9e3e1d9",
        _ => return ZetherKey::from_secret(Fr::<Bls12381>::from(0xCA201u64)).unwrap(),
    };
    ZetherKey::from_secret(decode_scalar::<Bls12381>(&hex::decode(x).unwrap()).unwrap()).unwrap()
}

fn holder(r: &Value) -> &str {
    r["name"].as_str().unwrap().split(':').next().unwrap()
}

/// The location fields of the rows, `ua` the reader's, and small BSGS parameters (the rows' amounts are below 2^11).
fn base(rows: &Value, k: &K) -> Value {
    json!({"curve": "bls12381", "family": "evm", "chainId": rows["chainId"], "chainUid": rows["chainUid"], "token": rows["token"],
        "block": rows["block"], "psid": rows["psid"], "ua": format!("0x{}", hex::encode(k.ua())), "tableBits": 18, "boundBits": 20})
}

fn with(mut v: Value, extra: &Value) -> Value {
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

fn acct_req(rows: &Value, k: &K, a: &Value) -> Value {
    with(base(rows, k), &json!({"account": a["account"], "accountData": a["accountData"]}))
}

fn entry_req(rows: &Value, k: &K, e: &Value) -> Value {
    let mut v = with(base(rows, k), &json!({"fromUA": e["fromUA"], "sendCounter": e["sendCounter"], "entryWords": e["entryWords"],
        "entryPtr": e["entryPtr"]}));
    for f in ["blob", "memoWords"] {
        if !e[f].is_null() {
            v[f] = e[f].clone();
        }
    }
    v
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(7)
}

fn call(cmd: &str, v: &Value, k: &K) -> Result<Value, String> {
    state::call_with_key(cmd, v, k, &mut rng())
}

fn refused(what: &str, cmd: &str, v: &Value, k: &K) {
    assert!(state::prepare(cmd, v, &k.y).is_err(), "{what}: prepare must refuse");
}

#[test]
fn layout_is_the_pin_of_the_rows() {
    let l = &rows()["layout"];
    assert_eq!(l["id"], "scaas.zether");
    assert_eq!(h(&l["root"]), ROOT);
    let labels: Vec<&str> = l["labels"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    for (label, slot, inner, byte, width) in LAYOUT {
        let i = labels.iter().position(|x| x == label).unwrap_or_else(|| panic!("{label} not pinned"));
        let at = |k: &str| l[k][i].as_u64().unwrap();
        assert_eq!((at("slots"), at("inner"), at("bytes") as usize, at("widths") as usize), (*slot, *inner, *byte, *width), "{label}");
    }
}

#[test]
fn accounts_rebuild_and_decrypt() {
    let rows = rows();
    for a in rows["accounts"].as_array().unwrap() {
        let k = key(holder(a));
        let v = acct_req(&rows, &k, a);
        let p = state::prepare("balance", &v, &k.y).unwrap();
        let acc = p.account().unwrap();
        let view = &a["view"];
        for (got, want) in [(acc.acc.c, "accC"), (acc.acc.d, "accD"), (acc.pending.c, "pendingC"), (acc.pending.d, "pendingD")] {
            assert_eq!(encode_point::<Bls12381>(&got), h(&view[want]), "{}: {want}", a["name"]);
        }
        assert_eq!((acc.acc_seq, acc.pending_seq, acc.send_counter), (view["accSeq"].as_u64().unwrap(),
            view["pendingSeq"].as_u64().unwrap(), view["sendCounter"].as_u64().unwrap()), "{}", a["name"]);
        let b = call("balance", &v, &k).unwrap();
        assert_eq!(b["amount"], a["balance"].as_u64().unwrap().to_string(), "{}", a["name"]);
        assert_eq!(call("pendingBalance", &v, &k).unwrap()["amount"], a["pending"].as_u64().unwrap().to_string(), "{}", a["name"]);
        let bal = a["balance"].as_u64().unwrap();
        let mut v = v.clone();
        for f in ["tableBits", "boundBits"] {
            v.as_object_mut().unwrap().remove(f);
        }
        // T15l (Fable P3-1): the holder's sealed box, never a plain number; its entry only at the words' accSeq
        let seq = a["view"]["accSeq"].as_u64().unwrap();
        let bx = |b: u64, s: u64| with(v.clone(), &json!({"cacheBox": cache_box::entry(&k, &rows["token"], b, s)}));
        assert_eq!(call("checkBalance", &bx(bal, seq), &k).unwrap()["ok"], true, "{}", a["name"]);
        assert_eq!(call("checkBalance", &bx(bal + 1, seq), &k).unwrap()["ok"], false);
        assert_eq!(call("checkBalance", &bx(bal, seq + 1), &k).unwrap()["ok"], false, "a stale entry");
        assert!(call("checkBalance", &with(v.clone(), &json!({"balance": bal})), &k).is_err(), "a plain number");
        let other = key(if holder(a) == "alice" { "bob" } else { "alice" });
        let foreign = with(v.clone(), &json!({"cacheBox": cache_box::entry(&other, &rows["token"], bal, seq)}));
        assert!(call("checkBalance", &foreign, &k).is_err(), "another key's box");
        let no_entry = with(v.clone(), &json!({"cacheBox": cache_box::seal(&k, &json!({}))}));
        assert!(call("checkBalance", &no_entry, &k).is_err(), "no entry for this UA and token");
    }
}

#[test]
fn entries_rebuild_and_open_for_the_receiver_and_the_auditor() {
    let rows = rows();
    let aud = key("auditor");
    let mut audited = 0;
    for e in rows["entries"].as_array().unwrap() {
        let view = &e["view"];
        for (j, ua) in e["to"].as_array().unwrap().iter().enumerate() {
            let name = ["alice", "bob", "carol", "dave"].into_iter().find(|n| hex::encode(key(n).ua()) == ua.as_str().unwrap()[2..]).unwrap();
            let k = key(name);
            let v = with(entry_req(&rows, &k, e), &json!({"kind": "receiver", "index": j}));
            let p = state::prepare("openDisclosure", &v, &k.y).unwrap();
            let x = p.entry().unwrap();
            assert_eq!(x.record, h(&view["transferEntry"]), "{}", e["name"]);
            assert_eq!(x.memo.clone().unwrap_or_default(), h(&view["transferMemo"]), "{}", e["name"]);
            let leg = x.leg(j).unwrap();
            let want = h(&view["legs"][j]["ciphertext"]);
            let got: Vec<u8> = [leg[1], leg[2], leg[3], leg[4]].iter().flat_map(encode_point::<Bls12381>).collect();
            assert_eq!(got, want, "{} leg {j}", e["name"]);
            assert_eq!(encode_point::<Bls12381>(&leg[0]), h(&view["legs"][j]["Yt"]));
            let amount = e["amounts"][j].as_u64().unwrap();
            let entry = |y_a| Entry {
                chain_id: rows["chainId"].as_u64().unwrap(),
                chain_uid: h(&rows["chainUid"]).try_into().unwrap(),
                token: h(&rows["token"]).try_into().unwrap(),
                entry_ref: h(&e["entryRef"]).try_into().unwrap(),
                index: j as u64,
                y_t: leg[0],
                c_out: leg[1],
                d_out: leg[2],
                y_a,
                c_aud: leg[3],
                d_aud: leg[4],
            };
            let out = call("openDisclosure", &v, &k).unwrap();
            assert_eq!(out["amount"], amount.to_string());
            verify_opening(&entry(G::default()), amount, OpeningKind::ReceiverX, &h(&out["opening"])).unwrap();
            if leg[3] != G::default() {
                audited += 1;
                let v = with(entry_req(&rows, &aud, e), &json!({"kind": "auditor", "index": j, "modes": rows["modes"],
                    "auditorKeyWords": rows["auditorKeyWords"]}));
                let out = call("openDisclosure", &v, &aud).unwrap();
                assert_eq!(out["amount"], amount.to_string());
                verify_opening(&entry(pt(&rows["auditorY"])), amount, OpeningKind::Auditor, &h(&out["opening"])).unwrap();
            }
        }
    }
    assert_eq!(audited, 3, "the single entry and the audited BUNDLE entry's two legs");
}

fn verify(cmd: &str, out: &Value) -> bool {
    let r = zether_prover::api::call(cmd, &json!({"curve": "bls12381", "statement": out["statement"], "proof": out["proof"]}).to_string());
    serde_json::from_str::<Value>(&r.unwrap()).unwrap()["ok"] == true
}

#[test]
fn debits_over_rebuilt_words_verify() {
    let rows = rows();
    let a = &rows["accounts"][0];
    let (alice, bob, carol) = (key("alice"), key("bob"), key("carol"));
    let y = |k: &K| format!("0x{}", hex::encode(encode_point::<Bls12381>(&k.y)));
    let v = with(acct_req(&rows, &alice, a), &json!({"validUntilBlock": 1000, "yAud": rows["auditorY"]}));
    let seq = a["view"]["accSeq"].as_u64().unwrap();
    let bx = |b: u64, s: u64| json!(cache_box::entry(&alice, &rows["token"], b, s));
    let t = call("proveTransfer", &with(v.clone(), &json!({"yTo": y(&bob), "amount": 10, "cacheBox": bx(843, seq)})), &alice).unwrap();
    assert!(verify("verifyTransfer", &t));
    // a stale entry (another accSeq): the balance by BSGS
    let t = call("proveTransfer", &with(v.clone(), &json!({"yTo": y(&bob), "amount": 10, "cacheBox": bx(844, seq + 1)})), &alice).unwrap();
    assert!(verify("verifyTransfer", &t));
    assert!(call("proveTransfer", &with(v.clone(), &json!({"yTo": y(&bob), "amount": 10, "balance": 843})), &alice).is_err(), "a plain number");
    // the balance from the rebuilt acc by BSGS when the caller gives none
    let t = call("proveTransfer", &with(v.clone(), &json!({"yTo": y(&bob), "amount": 10})), &alice).unwrap();
    assert!(verify("verifyTransfer", &t));
    assert!(call("proveTransfer", &with(v.clone(), &json!({"yTo": y(&bob), "amount": 10, "cacheBox": bx(844, seq)})), &alice).is_err(),
        "a balance hint that does not decrypt from the rebuilt acc");
    let m = call("proveTransferMulti", &with(v.clone(), &json!({"mode": "bundle", "recipients": [{"yTo": y(&bob), "amount": 3},
        {"yTo": y(&carol), "amount": 0}]})), &alice).unwrap();
    assert!(verify("verifyTransferMulti", &m));
    let mut b = v.clone();
    b.as_object_mut().unwrap().remove("yAud");
    let u = call("proveBurn", &with(b, &json!({"amount": 5, "recipient": "0x00000000000000000000000000000000000b0c00"})), &alice).unwrap();
    assert!(verify("verifyBurn", &u));
}

#[test]
fn word_location_and_role_negatives_are_refused_before_the_key() {
    let rows = rows();
    let a = &rows["accounts"][0];
    let alice = key("alice");
    let v = acct_req(&rows, &alice, a);
    assert!(state::prepare("balance", &v, &alice.y).is_ok(), "positive control");
    let set = |k: &str, x: Value| {
        let mut o = v.clone();
        o[k] = x;
        o
    };
    let mut words = a["account"].clone();
    words.as_array_mut().unwrap().pop();
    let mut data = a["accountData"].clone();
    let first = data[0]["word"].clone();
    data[0]["word"] = data[1]["word"].clone();
    data[1]["word"] = first;
    let mut slot_off = a["accountData"].clone();
    slot_off[0]["slot"] = slot_off[1]["slot"].clone();
    let mut extra = a["accountData"].clone();
    extra.as_array_mut().unwrap().push(a["accountData"][0].clone());
    let mut short = a["accountData"].clone();
    short.as_array_mut().unwrap().pop();
    for (what, x) in [
        ("another family", set("family", json!("soroban"))),
        ("another psid", set("psid", json!(format!("0x{}", "11".repeat(32))))),
        ("another reader's ua", set("ua", rows["accounts"][1]["ua"].clone())),
        ("five account words", set("account", words)),
        ("data words swapped (not a point)", set("accountData", data)),
        ("a data slot out of place", set("accountData", slot_off)),
        ("an extra data word", set("accountData", extra)),
        ("a missing data word", set("accountData", short)),
        ("a raw acc", set("acc", json!({"C": a["view"]["accC"], "D": a["view"]["accD"]}))),
        ("a raw sendCounter", set("sendCounter", json!(3))),
        ("a key object", set("key", json!({"x": "0x01"}))),
        ("another curve", set("curve", json!("bn254"))),
    ] {
        refused(what, "balance", &x, &alice);
    }
    // a raw ciphertext beside the words, on every account command
    for cmd in ["balance", "checkBalance", "pendingBalance", "proveTransfer", "proveTransferMulti", "proveBurn"] {
        let mut ok = v.clone();
        ok.as_object_mut().unwrap().retain(|f, _| state::allowed(cmd, f));
        assert!(state::prepare(cmd, &ok, &alice.y).is_ok(), "{cmd}: positive control");
        for (f, x) in [("acc", "acc"), ("ct", "acc"), ("pending", "pending")] {
            let mut r = ok.clone();
            r[f] = json!({"C": a["view"][format!("{x}C")], "D": a["view"][format!("{x}D")]});
            refused(&format!("{cmd} with a raw {f}"), cmd, &r, &alice);
        }
    }
    // bob's account words read with alice's ua: the slots are not hers
    refused("another account's words", "balance", &acct_req(&rows, &alice, &rows["accounts"][1]), &alice);
    // the words of an account whose pending was rolled cannot claim a pending point
    let bob = key("bob");
    let b = &rows["accounts"][1];
    let mut w = b["account"].clone();
    let c = w[4].as_str().unwrap().to_string();
    // big-endian hex: sendCounter [2, 18), lastRolledPendingSeq [18, 34), pendingSeq [34, 50), accSeq [50, 66)
    w[4] = json!(format!("{}{}{}", &c[..18], &c[34..50], &c[34..])); // lastRolledPendingSeq := pendingSeq
    refused("pending set although nothing is new", "balance", &with(acct_req(&rows, &bob, b), &json!({"account": w})), &bob);

    // entries
    let e = &rows["entries"][1]; // BUNDLE, audited, legs [bob, carol]
    let carol = key("carol");
    let r = with(entry_req(&rows, &bob, e), &json!({"kind": "receiver", "index": 0}));
    assert!(state::prepare("openDisclosure", &r, &bob.y).is_ok(), "positive control");
    let aud = key("auditor");
    let ra = with(entry_req(&rows, &aud, e), &json!({"kind": "auditor", "index": 0, "modes": rows["modes"],
        "auditorKeyWords": rows["auditorKeyWords"]}));
    assert!(state::prepare("openDisclosure", &ra, &aud.y).is_ok(), "positive control");
    let none = {
        let m = rows["modes"].as_str().unwrap();
        format!("{}00{}", &m[..22], &m[24..]) // auditorMode (byte 21 from the low end) := NONE
    };
    let hash = &rows["entries"][2]; // HASH, auditor left out, legs [carol, bob]
    let alice = key("alice");
    let own = with(entry_req(&rows, &alice, e), &json!({"auditorKeyWords": rows["auditorKeyWords"]}));
    assert!(state::prepare("recoverTransfer", &own, &alice.y).is_ok(), "positive control: the sender's own entry");
    for (what, cmd, x, k) in [
        ("a foreign leg (carol's) on bob's handle", "openDisclosure", with(r.clone(), &json!({"index": 1})), &bob),
        ("bob's leg on carol's handle", "openDisclosure", with(entry_req(&rows, &carol, e), &json!({"kind": "receiver", "index": 0})), &carol),
        ("a leg outside the entry", "openDisclosure", with(r.clone(), &json!({"index": 2})), &bob),
        ("another sendCounter (entryRef not recomputed to these words)", "openDisclosure", with(r.clone(), &json!({"sendCounter": 0})), &bob),
        ("another fromUA", "openDisclosure", with(r.clone(), &json!({"fromUA": rows["accounts"][1]["ua"]})), &bob),
        ("an auditor read on a receiver handle", "openDisclosure", with(ra.clone(), &json!({"ua": format!("0x{}", hex::encode(bob.ua()))})), &bob),
        ("a receiver read on the auditor handle", "openDisclosure", with(ra.clone(), &json!({"kind": "receiver"})), &aud),
        ("an auditor read with auditorMode NONE", "openDisclosure", with(ra.clone(), &json!({"modes": none})), &aud),
        ("an auditor read of a leg without a copy", "openDisclosure", with(entry_req(&rows, &aud, hash), &json!({"kind": "auditor",
            "index": 0, "modes": rows["modes"], "auditorKeyWords": rows["auditorKeyWords"]})), &aud),
        ("a sender's command on the receiver's handle", "recoverTransfer", with(entry_req(&rows, &bob, e),
            &json!({"auditorKeyWords": rows["auditorKeyWords"]})), &bob),
        ("openMemo of an inline entry", "openMemo", entry_req(&rows, &key("alice"), e), &key("alice")),
        ("a raw entry", "openDisclosure", with(r.clone(), &json!({"entry": e["view"]["transferEntry"]})), &bob),
        ("a raw leg", "openDisclosure", with(r.clone(), &json!({"Cout": e["view"]["legs"][0]["ciphertext"]})), &bob),
        ("an amount from the caller", "openDisclosure", with(r.clone(), &json!({"amount": 30})), &bob),
    ] {
        refused(what, cmd, &x, k);
    }
    // commit-reveal: the blob, the pointer and the memo bound to the entry
    let rh = with(entry_req(&rows, &carol, hash), &json!({"kind": "receiver", "index": 0}));
    assert!(state::prepare("openDisclosure", &rh, &carol.y).is_ok(), "positive control");
    let mut blob = hash["blob"].clone();
    blob["address"] = json!(format!("0x{}", "11".repeat(20)));
    let mut code = hash["blob"].clone();
    code["code"] = json!(format!("0x01{}", &hash["blob"]["code"].as_str().unwrap()[4..]));
    let mut memo = hash["memoWords"].clone();
    memo[1]["word"] = json!(format!("0x{}", "00".repeat(32))); // the salt no longer the record's
    for (what, x) in [
        ("a blob of another pointer", with(rh.clone(), &json!({"blob": blob}))),
        ("not an SSTORE2 code", with(rh.clone(), &json!({"blob": code}))),
        ("a memo of another record", with(rh.clone(), &json!({"memoWords": memo}))),
        ("a pointer with an inline record", with(rh.clone(), &json!({"entryWords": e["entryWords"]}))),
        ("an inline entry with a blob", with(r.clone(), &json!({"blob": hash["blob"]}))),
    ] {
        refused(what, "openDisclosure", &x, if what.starts_with("an inline") { &bob } else { &carol });
    }
}

/// `a + i` (mod 2^256), big-endian.
fn add(a: &[u8; 32], i: u64) -> [u8; 32] {
    let mut o = *a;
    let mut c = u128::from(i);
    for b in o.iter_mut().rev() {
        let t = u128::from(*b) + (c & 0xff);
        *b = t as u8;
        c = (c >> 8) + (t >> 8);
    }
    o
}

fn kk(b: &[u8]) -> [u8; 32] {
    zether_prover::curve::keccak256(b)
}

fn hw(w: &[u8]) -> String {
    format!("0x{}", hex::encode(w))
}

/// `[{slot, word}]` of a long-form `bytes` `b` at slot `s`: the length slot, then the data slots.
fn bytes_words(s: &[u8; 32], b: &[u8]) -> Value {
    let mut len = [0u8; 32];
    len[24..].copy_from_slice(&(2 * b.len() as u64 + 1).to_be_bytes());
    let mut out = vec![json!({"slot": hw(s), "word": hw(&len)})];
    let d = kk(s);
    for (i, c) in b.chunks(32).enumerate() {
        let mut w = [0u8; 32];
        w[..c.len()].copy_from_slice(c);
        out.push(json!({"slot": hw(&add(&d, i as u64)), "word": hw(&w)}));
    }
    Value::Array(out)
}

/// The sender's recovery and memo from the words of entries the prover made (a reading layer's words of a chain that took
/// them: the record inline, or by a pointer with the memo), not from calldata.
#[test]
fn the_sender_recovers_its_own_entries_from_words() {
    let rows = rows();
    let (alice, bob, carol) = (key("alice"), key("bob"), key("carol"));
    let y = |k: &K| hw(&encode_point::<Bls12381>(&k.y));
    let v = with(acct_req(&rows, &alice, &rows["accounts"][0]), &json!({"validUntilBlock": 1000, "yAud": rows["auditorY"],
        "cacheBox": cache_box::entry(&alice, &rows["token"], 843, rows["accounts"][0]["view"]["accSeq"].as_u64().unwrap()),
        "recipients": [{"yTo": y(&bob), "amount": 7}, {"yTo": y(&carol), "amount": 0}]}));
    let ns = |n: u64| add(&h(&rows["layout"]["root"]).try_into().unwrap(), n);
    let map = |k: &[u8], n: u64| kk(&[k, &ns(n)].concat());
    for mode in ["bundle", "compact"] {
        let out = call("proveTransferMulti", &with(v.clone(), &json!({"mode": mode})), &alice).unwrap();
        let (r, entry_ref) = (h(&out["bundles"]), h(&out["entryRef"]));
        let sc = rows["accounts"][0]["view"]["sendCounter"].clone();
        let mut req = with(base(&rows, &alice), &json!({"fromUA": rows["accounts"][0]["ua"], "sendCounter": sc}));
        if mode == "bundle" {
            req["entryWords"] = bytes_words(&map(&entry_ref, 9), &r);
            req["entryPtr"] = json!(hw(&[0; 32]));
        } else {
            let ptr = [0x5Au8; 20];
            req["entryWords"] = json!([{"slot": hw(&map(&entry_ref, 9)), "word": hw(&[0; 32])}]);
            req["entryPtr"] = json!(hw(&[&[0u8; 12][..], &ptr].concat()));
            req["blob"] = json!({"address": hw(&ptr), "code": hw(&[&[0u8][..], &r].concat())});
            req["memoWords"] = bytes_words(&map(&entry_ref, 11), &h(&out["memo"]));
            let mut om = req.clone();
            for f in ["tableBits", "boundBits"] {
                om.as_object_mut().unwrap().remove(f);
            }
            let m = call("openMemo", &om, &alice).unwrap();
            assert_eq!(m["legs"][0]["amount"], "7");
            assert_eq!(m["legs"][1]["toUA"], hw(&carol.ua()));
        }
        req["auditorKeyWords"] = rows["auditorKeyWords"].clone();
        let rec = call("recoverTransfer", &req, &alice).unwrap();
        assert_eq!(rec["entryRef"], out["entryRef"], "{mode}");
        assert_eq!(rec["bundles"], out["bundles"], "{mode}");
        assert_eq!((rec["legs"][0]["amount"].clone(), rec["legs"][1]["amount"].clone()), (json!("7"), json!("0")), "{mode}");
        // bob, a recipient, is no sender of it
        let mut theirs = req.clone();
        theirs["ua"] = json!(hw(&bob.ua()));
        refused("a recipient's recovery", "recoverTransfer", &theirs, &bob);
    }
}
