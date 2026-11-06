// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T14b (ARCH-POS-13; spec no-decryption-oracle §4.3, §4.7, §5): the Zether facade on raw storage words. A
//! decrypting command takes a named location and the raw words a reading layer read; zether-prover's `state` checks the
//! family and `psid`, parses the words by the pinned layout (T19c's `scaas.zether`, compared here with the pin the forge rows
//! carry), binds the leg and the role to the handle's `Y`, rebuilds the ciphertexts as `ZetherLib` and only then is the key
//! used. Here, over the forge rows (`smartcontracts/vectors/zether/state.json`, `ua-mtx-merge`
//! `test/zether/ZetherStateVectors.t.sol`, real proofs; the holders are zether-prover's `r33_keys.json` keys): balances,
//! pending balances and the cache check equal the contract's plaintexts; the receiver's and the auditor's openings verify;
//! debits over the rebuilt words verify; every location, word and role negative is refused with one status and (feature
//! `vectors`) the key unused; consistent fabricated words are decrypted (the residual control: authenticity is the reading
//! layer's duty, spec §4.12). UNAUDITED.
use scaas_ua::facade::zether::{ZetherKey, COMMANDS};
use scaas_ua::wallet::{Error, Wallet};
use serde_json::{json, Value};
use zether_prover::curve::{decode_point, encode_point, Bls12381, G};
use zether_prover::schnorr::{verify_opening, Entry, OpeningKind};

fn unlock() {
    #[cfg(feature = "vectors")]
    scaas_ua::facade::vectors_unlock(scaas_ua::facade::TestOnly);
}

fn read(path: &str) -> Value {
    let p = format!("{}/../{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("{p}"))).unwrap()
}

fn rows() -> Value {
    read("../smartcontracts/vectors/zether/state.json")
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(&v.as_str().unwrap()[2..]).unwrap()
}

fn hw(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// zether-prover's vector wallet (r33_keys.json): alice `m/12381/60/0/7`, bob `/1/7`, dave `/1/8`, the auditor `/0/8`.
fn wallet() -> Wallet {
    let r = read("zether-prover/vectors/r33_keys.json");
    Wallet::from_mnemonic(r["mnemonic"].as_str().unwrap(), r["passphrase"].as_str().unwrap()).unwrap()
}

fn handle(w: &Wallet, name: &str) -> ZetherKey {
    let (a, u) = match name {
        "alice" => (0, 7),
        "bob" => (1, 7),
        "dave" => (1, 8),
        _ => (0, 8),
    };
    w.zether_key(60, a, u).unwrap()
}

fn call(k: &ZetherKey, cmd: &str, v: &Value) -> Result<Value, Error> {
    k.call(cmd, v.to_string().as_bytes()).map(|s| serde_json::from_str(&s).unwrap())
}

fn key_uses() -> usize {
    #[cfg(feature = "vectors")]
    return scaas_ua::facade::zether::vectors_key_uses();
    #[cfg(not(feature = "vectors"))]
    0
}

/// `req` refused with `Argument`, the key unused (feature `vectors`: the key-use counter).
fn refused(what: &str, k: &ZetherKey, cmd: &str, req: &Value) {
    let before = key_uses();
    assert_eq!(call(k, cmd, req).err(), Some(Error::Argument), "{what}");
    assert_eq!(key_uses(), before, "{what}: the key unused");
}

fn with(mut v: Value, extra: Value) -> Value {
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

fn base(rows: &Value, k: &ZetherKey) -> Value {
    json!({"family": "evm", "chainId": rows["chainId"], "chainUid": rows["chainUid"], "token": rows["token"], "block": rows["block"],
        "psid": rows["psid"], "ua": hw(&k.ua())})
}

fn acct(rows: &Value, k: &ZetherKey, a: &Value) -> Value {
    with(base(rows, k), json!({"account": a["account"], "accountData": a["accountData"]}))
}

fn entry(rows: &Value, k: &ZetherKey, e: &Value) -> Value {
    let mut v = with(base(rows, k), json!({"fromUA": e["fromUA"], "sendCounter": e["sendCounter"], "entryWords": e["entryWords"],
        "entryPtr": e["entryPtr"], "tableBits": 18, "boundBits": 20}));
    for f in ["blob", "memoWords"] {
        if !e[f].is_null() {
            v[f] = e[f].clone();
        }
    }
    v
}

fn row<'a>(rows: &'a Value, name: &str) -> &'a Value {
    rows["accounts"].as_array().unwrap().iter().find(|a| a["name"].as_str().unwrap().starts_with(name)).unwrap()
}

const BSGS: &str = r#"{"tableBits": 18, "boundBits": 20}"#;

#[test]
fn the_parser_is_the_pin_of_the_rows() {
    let l = &rows()["layout"];
    assert_eq!(h(&l["root"]), zether_prover::state::ROOT);
    let labels: Vec<&str> = l["labels"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    for (label, slot, inner, byte, width) in zether_prover::state::LAYOUT {
        let i = labels.iter().position(|x| x == label).unwrap_or_else(|| panic!("{label}"));
        let at = |k: &str| l[k][i].as_u64().unwrap();
        assert_eq!((at("slots"), at("inner"), at("bytes") as usize, at("widths") as usize), (*slot, *inner, *byte, *width), "{label}");
    }
}

#[test]
fn balances_from_the_words() {
    unlock();
    let (rows, w) = (rows(), wallet());
    let bsgs: Value = serde_json::from_str(BSGS).unwrap();
    for name in ["alice", "bob", "dave"] {
        let (a, k) = (row(&rows, name), handle(&w, name));
        let v = acct(&rows, &k, a);
        let b = call(&k, "balance", &with(v.clone(), bsgs.clone())).unwrap();
        assert_eq!(b["amount"], a["balance"].as_u64().unwrap().to_string(), "{name}");
        assert_eq!(b["state"]["accSeq"], a["view"]["accSeq"], "{name}");
        assert_eq!(b["state"]["sendCounter"], a["view"]["sendCounter"], "{name}");
        let p = call(&k, "pendingBalance", &with(v.clone(), bsgs.clone())).unwrap();
        assert_eq!(p["amount"], a["pending"].as_u64().unwrap().to_string(), "{name}");
        let bal = a["balance"].as_u64().unwrap();
        assert_eq!(call(&k, "checkBalance", &with(v.clone(), json!({"balance": bal}))).unwrap()["ok"], true, "{name}");
        assert_eq!(call(&k, "checkBalance", &with(v.clone(), json!({"balance": bal + 1}))).unwrap()["ok"], false, "{name}");
    }
    // KeyRevoked after lock: the handle's status, not the words'
    let k = handle(&w, "alice");
    let v = with(acct(&rows, &k, row(&rows, "alice")), bsgs);
    w.lock();
    assert_eq!(call(&k, "balance", &v).err(), Some(Error::KeyRevoked));
}

#[test]
fn openings_for_the_receiver_and_the_auditor_verify() {
    unlock();
    let (rows, w) = (rows(), wallet());
    let (bob, aud) = (handle(&w, "bob"), handle(&w, "auditor"));
    let mut opened = (0, 0);
    for e in rows["entries"].as_array().unwrap() {
        for (j, ua) in e["to"].as_array().unwrap().iter().enumerate() {
            let cts = h(&e["view"]["legs"][j]["ciphertext"]);
            let pt = |i: usize| decode_point::<Bls12381>(&cts[128 * i..128 * (i + 1)]).unwrap();
            let leg = |y_a| Entry {
                chain_id: rows["chainId"].as_u64().unwrap(),
                chain_uid: h(&rows["chainUid"]).try_into().unwrap(),
                token: h(&rows["token"]).try_into().unwrap(),
                entry_ref: h(&e["entryRef"]).try_into().unwrap(),
                index: j as u64,
                y_t: decode_point::<Bls12381>(&h(&e["view"]["legs"][j]["Yt"])).unwrap(),
                c_out: pt(0),
                d_out: pt(1),
                y_a,
                c_aud: pt(2),
                d_aud: pt(3),
            };
            let amount = e["amounts"][j].as_u64().unwrap();
            if h(ua) == bob.ua() {
                let o = call(&bob, "openDisclosure", &with(entry(&rows, &bob, e), json!({"kind": "receiver", "index": j}))).unwrap();
                assert_eq!(o["amount"], amount.to_string());
                verify_opening(&leg(G::default()), amount, OpeningKind::ReceiverX, &h(&o["opening"])).unwrap();
                opened.0 += 1;
            }
            if pt(2) != G::default() {
                let v = with(entry(&rows, &aud, e), json!({"kind": "auditor", "index": j, "modes": rows["modes"],
                    "auditorKeyWords": rows["auditorKeyWords"]}));
                let o = call(&aud, "openDisclosure", &v).unwrap();
                assert_eq!(o["amount"], amount.to_string());
                let y_a = decode_point::<Bls12381>(&h(&rows["auditorY"])).unwrap();
                verify_opening(&leg(y_a), amount, OpeningKind::Auditor, &h(&o["opening"])).unwrap();
                opened.1 += 1;
            }
        }
    }
    assert_eq!(opened, (3, 3), "bob's three legs, the three audited legs");
}

fn verified(cmd: &str, out: &Value) -> bool {
    let r = zether_prover::api::call(cmd, &json!({"curve": "bls12381", "statement": out["statement"], "proof": out["proof"]}).to_string());
    serde_json::from_str::<Value>(&r.unwrap()).unwrap()["ok"] == true
}

#[test]
fn debits_over_the_words_verify() {
    unlock();
    let (rows, w) = (rows(), wallet());
    let (alice, bob) = (handle(&w, "alice"), handle(&w, "bob"));
    let y_bob = hw(&bob.y());
    let v = with(acct(&rows, &alice, row(&rows, "alice")), json!({"validUntilBlock": 1000, "yAud": rows["auditorY"]}));
    let t = call(&alice, "proveTransfer", &with(v.clone(), json!({"yTo": y_bob, "amount": 10, "balance": 843}))).unwrap();
    assert!(verified("verifyTransfer", &t));
    let t = call(&alice, "proveTransfer", &with(v.clone(), json!({"yTo": y_bob, "amount": 10, "tableBits": 18, "boundBits": 20}))).unwrap();
    assert!(verified("verifyTransfer", &t), "the balance by BSGS of the rebuilt acc");
    assert_eq!(call(&alice, "proveTransfer", &with(v.clone(), json!({"yTo": y_bob, "amount": 10, "balance": 842}))).err(),
        Some(Error::Argument), "a balance hint that is not the rebuilt acc's");
    let m = call(&alice, "proveTransferMulti", &with(v.clone(), json!({"mode": "compact", "recipients": [{"yTo": y_bob, "amount": 4}]}))).unwrap();
    assert!(verified("verifyTransferMulti", &m));
    let mut b = with(v, json!({"amount": 5, "recipient": "0x00000000000000000000000000000000000b0c00", "balance": 843}));
    b.as_object_mut().unwrap().remove("yAud");
    assert!(verified("verifyBurn", &call(&alice, "proveBurn", &b).unwrap()));
}

#[test]
fn location_word_and_role_negatives_are_refused_with_the_key_unused() {
    unlock();
    let (rows, w) = (rows(), wallet());
    let (alice, bob, aud) = (handle(&w, "alice"), handle(&w, "bob"), handle(&w, "auditor"));
    let a = row(&rows, "alice");
    let v = acct(&rows, &alice, a);
    assert!(call(&alice, "checkBalance", &with(v.clone(), json!({"balance": 843}))).is_ok(), "positive control");
    let chk = |x: Value| with(with(v.clone(), json!({"balance": 843})), x);
    let mut swapped = a["accountData"].clone();
    let w0 = swapped[0]["word"].clone();
    swapped[0]["word"] = swapped[1]["word"].clone();
    swapped[1]["word"] = w0;
    let mut short = a["account"].clone();
    short.as_array_mut().unwrap().pop();
    let mut extra = a["accountData"].clone();
    extra.as_array_mut().unwrap().push(a["accountData"][0].clone());
    for (what, x) in [
        ("another family's words", chk(json!({"family": "soroban"}))),
        ("another psid", chk(json!({"psid": hw(&[0x11; 32])}))),
        ("another reader's ua", chk(json!({"ua": row(&rows, "bob")["ua"]}))),
        ("bob's account words on alice's handle", with(acct(&rows, &alice, row(&rows, "bob")), json!({"balance": 135}))),
        ("five account slots", chk(json!({"account": short}))),
        ("data words swapped", chk(json!({"accountData": swapped}))),
        ("an extra data word", chk(json!({"accountData": extra}))),
    ] {
        refused(what, &alice, "checkBalance", &x);
    }
    for (what, cmd, x) in [
        ("a raw acc", "checkBalance", json!({"acc": {"C": a["view"]["accC"], "D": a["view"]["accD"]}, "balance": 843})),
        ("a raw ct", "balance", json!({"ct": {"C": a["view"]["accC"], "D": a["view"]["accD"]}})),
        ("a raw acc in a debit", "proveTransfer", with(v.clone(), json!({"acc": {"C": a["view"]["accC"], "D": a["view"]["accD"]}}))),
        ("a parsed sendCounter in a debit", "proveTransfer", with(v.clone(), json!({"sendCounter": 3}))),
        ("a key object", "balance", with(v.clone(), json!({"key": {"x": "0x01"}}))),
    ] {
        refused(what, &alice, cmd, &x);
    }
    let e = &rows["entries"][1]; // BUNDLE, audited, legs [bob, carol]
    let r = with(entry(&rows, &bob, e), json!({"kind": "receiver", "index": 0}));
    assert!(call(&bob, "openDisclosure", &r).is_ok(), "positive control");
    let ra = with(entry(&rows, &aud, e), json!({"kind": "auditor", "index": 0, "modes": rows["modes"],
        "auditorKeyWords": rows["auditorKeyWords"]}));
    assert!(call(&aud, "openDisclosure", &ra).is_ok(), "positive control");
    let m = rows["modes"].as_str().unwrap();
    let none = format!("{}00{}", &m[..22], &m[24..]);
    for (what, k, cmd, x) in [
        ("a foreign leg", &bob, "openDisclosure", with(r.clone(), json!({"index": 1}))),
        ("a leg outside the entry", &bob, "openDisclosure", with(r.clone(), json!({"index": 2}))),
        ("a sendCounter that does not recompute to these words", &bob, "openDisclosure", with(r.clone(), json!({"sendCounter": 2}))),
        ("a receiver read on the auditor handle", &aud, "openDisclosure", with(ra.clone(), json!({"kind": "receiver"}))),
        ("an auditor read on a receiver handle", &bob, "openDisclosure", with(ra.clone(), json!({"ua": hw(&bob.ua())}))),
        ("an auditor read with auditorMode NONE", &aud, "openDisclosure", with(ra.clone(), json!({"modes": none}))),
        ("an auditor read of a leg without a copy", &aud, "openDisclosure", with(entry(&rows, &aud, &rows["entries"][2]),
            json!({"kind": "auditor", "index": 1, "modes": rows["modes"], "auditorKeyWords": rows["auditorKeyWords"]}))),
        ("a recipient's recovery of the sender's entry", &bob, "recoverTransfer", with(entry(&rows, &bob, e),
            json!({"auditorKeyWords": rows["auditorKeyWords"]}))),
        ("a raw entry", &bob, "openDisclosure", with(r.clone(), json!({"entry": e["view"]["transferEntry"]}))),
        ("an amount from the caller", &bob, "openDisclosure", with(r.clone(), json!({"amount": 30}))),
    ] {
        refused(what, k, cmd, &x);
    }
    assert!(COMMANDS.contains(&"openDisclosure"));
}

/// The residual (spec §4.12, §5): `ua-rs` cannot tell chain state from consistent fabricated words. A ciphertext the caller
/// chose, wrapped as the words of the handle's own account, is decrypted: whether words are real chain state of a catalogued
/// token is the reading layer's duty (R1–R7).
#[test]
fn residual_control_consistent_fabricated_words_are_decrypted() {
    unlock();
    let (rows, w) = (rows(), wallet());
    let alice = handle(&w, "alice");
    let y = decode_point::<Bls12381>(&alice.y()).unwrap();
    let ct = zether_prover::elgamal::encrypt(&y, 5, &zether_prover::curve::Fr::<Bls12381>::from(9u64));
    let kk = zether_prover::curve::keccak256;
    let add = |a: &[u8; 32], i: u8| {
        let mut o = *a;
        let (s, c) = o[31].overflowing_add(i);
        o[31] = s;
        assert!(!c);
        o
    };
    let base = kk(&[alice.ua(), add(&zether_prover::state::ROOT, 8)].concat());
    let mut len = [0u8; 32];
    len[30..].copy_from_slice(&257u16.to_be_bytes());
    let mut data = vec![];
    for (i, p) in [ct.c, ct.d].iter().enumerate() {
        let d = kk(&add(&base, i as u8));
        for (j, c) in encode_point::<Bls12381>(p).chunks(32).enumerate() {
            let mut s = d;
            s[31] = s[31].wrapping_add(j as u8); // the four data slots: no carry out of the last byte in this row
            assert!(s[31] >= d[31]);
            data.push(json!({"slot": hw(&s), "word": hw(c)}));
        }
    }
    let zero = hw(&[0; 32]);
    let v = with(self::base(&rows, &alice), json!({"account": [hw(&len), hw(&len), zero, zero, zero, zero], "accountData": data,
        "tableBits": 18, "boundBits": 20}));
    assert_eq!(call(&alice, "balance", &v).unwrap()["amount"], "5");
}
