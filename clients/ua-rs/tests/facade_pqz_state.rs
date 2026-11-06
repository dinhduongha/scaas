// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T15e (ARCH-POS-13; spec no-decryption-oracle §4.3–§4.6, §5): the PQZ facade on raw storage words. A decrypting
//! command takes a named location and the raw words a reading layer read; the facade checks `psid` first, parses the words by
//! the pinned layout, checks them, binds the selected leg and the role to the handle's registered key, rebuilds `T`, `p`, the
//! entries and the op 5 statement as `PqzCore` does, and only then uses the key. Here: the stored form against the contract's
//! (`PqzSet.sol` of this set, the forge rows `state.json`), the rebuilt `T` and leg ciphertexts byte for byte against the
//! contract's statement views (feature `vectors`), debits over rebuilt words verifying with pqz-ffi's precompile, disclosures,
//! auditor reads and the memo, and every word and role negative of spec §5 refused with one status and (feature `vectors`) the
//! key unused. UNAUDITED.
#![allow(non_snake_case)]
mod pqz_chain;
use pqz_chain::*;
#[cfg(feature = "vectors")]
use pqz_ffi::stmt::PQZH_ID;
use pqz_ffi::stmt::{self as st, Form, Stmt, Word, PQZL_ID};
use scaas_ua::facade::pqz::{PqzCmd, PqzKey, STATE_LAYOUT};
use scaas_ua::facade::pqz_pack::{unpack, ACC_WORDS, B, CTP, GROUP, PKP, VP};
use scaas_ua::wallet::{Error, Wallet};
use serde_json::{json, Value};

fn unlock() {
    #[cfg(feature = "vectors")]
    scaas_ua::facade::vectors_unlock(scaas_ua::facade::TestOnly);
}

const WORDS: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn call(k: &PqzKey, cmd: &str, v: &Value) -> Result<Value, Error> {
    k.call(cmd, v.to_string().as_bytes()).map(|s| serde_json::from_str(&s).unwrap())
}
fn verify(op: u8, stmt: &[u8], proof: &[u8]) -> bool {
    pqz_ffi::precompile(&st::input(op, stmt, proof)) == Ok(pqz_ffi::VALID)
}
fn key_uses() -> usize {
    #[cfg(feature = "vectors")]
    return scaas_ua::facade::pqz::vectors_key_uses();
    #[cfg(not(feature = "vectors"))]
    0
}
/// `req` refused with `want` (one status), the key unused (feature `vectors`: the key-use counter).
fn refused(what: &str, k: &PqzKey, cmd: &str, req: &Value, want: Error) {
    let before = key_uses();
    assert_eq!(call(k, cmd, req).err(), Some(want), "{what}");
    assert_eq!(key_uses(), before, "{what}: the key unused");
}
fn set_dir() -> String {
    if st::SET == "n2048-kmax1024" { String::new() } else { format!("{}/", st::SET) }
}
fn rows() -> Value {
    let p = format!("{}/../../smartcontracts/vectors/pqz/{}state.json", env!("CARGO_MANIFEST_DIR"), set_dir());
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("{p}"))).unwrap()
}

const A: Word = [0xA1; 32];
const BOB: Word = [0xB0; 32];
const AUD: Word = [0xAD; 32];
const Z: Word = [0xB1; 32];
const X: Word = [0xB2; 32];
const Y: Word = [0xB3; 32];

/// Six holders of one wallet, registered on a fresh chain (the auditor `AUD`).
struct World {
    _w: Wallet,
    k: Vec<(Word, PqzKey)>,
    c: Chain,
}

impl World {
    fn new() -> World {
        unlock();
        let w = Wallet::from_mnemonic(WORDS, "").unwrap();
        let mut c = Chain::new();
        let k: Vec<(Word, PqzKey)> = [A, BOB, AUD, Z, X, Y].iter().enumerate().map(|(i, ua)| (*ua, w.pqz_key(i as u32, 0).unwrap())).collect();
        for (ua, key) in &k {
            c.register(*ua, &key.pk());
        }
        c.auditor = Some(AUD);
        World { _w: w, k, c }
    }
    fn key(&self, ua: &Word) -> &PqzKey {
        &self.k.iter().find(|x| x.0 == *ua).unwrap().1
    }
    fn pk(&self, ua: &Word) -> String {
        hx(&self.key(ua).pk())
    }
    fn balance(&self, ua: &Word) -> u64 {
        call(self.key(ua), "balance", &self.c.own(ua, 16)).unwrap()["value"].as_u64().unwrap()
    }
    fn debit(&self, ua: &Word, extra: Value) -> Value {
        merge(merge(self.c.own(ua, 16), self.c.debit_fields()), extra)
    }
    /// Op 1 from `from` to `to`, verified and settled; the entry.
    fn pay(&mut self, from: &Word, to: &Word, amount: u64, aud: bool) -> Word {
        let mut extra = json!({"toUA": hx(to), "pkT": self.pk(to), "amount": amount, "memoHash": hx(&[0; 32])});
        if aud {
            extra["pkA"] = json!(self.pk(&AUD));
        }
        let p = call(self.key(from), "proveTransfer", &self.debit(from, extra)).unwrap();
        let stmt = h(&p["stmt"]);
        assert!(verify(1, &stmt, &h(&p["proof"])), "op 1 over rebuilt words verifies");
        self.c.settle1(&stmt, None)
    }
    /// Op 7 from `from` to `legs`, verified and settled; the entry and the answer.
    fn pay_multi(&mut self, from: &Word, legs: &[(Word, u64)], aud: bool, mode: &str) -> (Word, Value) {
        let l: Vec<Value> = legs.iter().map(|(ua, a)| json!({"pk": self.pk(ua), "ua": hx(ua), "amount": a})).collect();
        let mut extra = json!({"legs": l, "mode": mode});
        if aud {
            extra["pkA"] = json!(self.pk(&AUD));
        }
        let p = call(self.key(from), "proveTransferMulti", &self.debit(from, extra)).unwrap();
        let stmt = h(&p["stmt"]);
        assert!(verify(7, &stmt, &h(&p["proof"])), "op 7 over rebuilt words verifies");
        note_legs(&legs.iter().map(|l| l.0).collect::<Vec<_>>());
        let memo = p.get("memo").map(h);
        (self.c.settle7(&stmt, memo.as_deref()), p)
    }
}

/// The stored form is the contract's: `B` and `PQZ_ACC_WORDS` as this set's generated `PqzSet.sol` states them; a hand
/// vector (the four `B`-bit fields of one group, big-endian); the test's packer and the facade's unpacker invert each other;
/// the forge rows' op blobs unpack to the contract's own leg ciphertexts (its disclosure statements).
#[test]
fn stored_form_is_the_contracts() {
    let sol = std::fs::read_to_string(format!("{}/../../pqz-core/params/sets/{}/PqzSet.sol", env!("CARGO_MANIFEST_DIR"), st::SET)).unwrap();
    let num = |key: &str| -> usize {
        let l = sol.lines().find(|l| l.contains(key)).unwrap();
        l.rsplit(" = ").next().unwrap().trim_end_matches(';').replace('_', "").parse().unwrap()
    };
    assert_eq!((B, ACC_WORDS), (num("PACK_BITS ="), num("PQZ_ACC_WORDS =")), "PACK_BITS, PQZ_ACC_WORDS of {}", st::SET);
    assert_eq!((GROUP, PKP, VP, CTP), (B / 2, st::PK_BYTES / 32 * B / 2, 128 / 32 * B / 2, (st::PK_BYTES + 128) / 32 * B / 2));
    // one group: c0 = 1, c1 = 2^B − 1, c2 = 0, c3 = 2^(B−1) + 5 as 4·B big-endian bits
    let f = [1u128, (1 << B) - 1, 0, (1 << (B - 1)) + 5];
    let bits: Vec<bool> = f.iter().flat_map(|x| (0..B).rev().map(move |i| x >> i & 1 == 1)).collect();
    let g: Vec<u8> = bits.chunks(8).map(|c| c.iter().fold(0u8, |a, b| a << 1 | *b as u8)).collect();
    assert_eq!(g.len(), GROUP);
    let want: Vec<u8> = f.iter().flat_map(|x| (*x as u64).to_be_bytes()).collect();
    assert_eq!(unpack(&g).unwrap(), want, "the hand vector");
    assert_eq!(pack(&want), g);
    assert_eq!(unpack(&g[1..]), None, "not a whole group");
    let lanes: Vec<u8> = (0..st::PK_BYTES / 8 + 16).flat_map(|i| ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) % st::Q).to_be_bytes()).collect();
    assert_eq!(unpack(&pack(&lanes)).unwrap(), lanes, "round trip");
    // the forge rows: leg 0 of every op 1 entry, unpacked from the stored blob, is the contract's
    let r = rows();
    assert_eq!(r["set"], st::SET);
    let mut n = 0;
    for e in r["entries"].as_array().unwrap().iter().filter(|e| e["legs"].as_array().unwrap().len() == 1) {
        let d = &h(&e["blob"]["code"])[1..];
        let ct = [unpack(&d[16..16 + PKP]).unwrap(), unpack(&d[16 + PKP..16 + PKP + VP]).unwrap()].concat();
        assert_eq!(hx(&ct), e["legs"][0]["ct"].as_str().unwrap(), "{}", e["name"]);
        n += 1;
    }
    assert!(n >= 4);
}

/// The parser's table is T19c's pin of `scaas.pqz` (copied into the rows by the forge writer at the same contract commit).
#[test]
fn layout_is_the_pin() {
    let r = rows();
    let l = r.get("layout").unwrap_or_else(|| panic!("state.json of contract commit {} carries no layout pin", r["contractCommit"]));
    assert_eq!(l["id"], "scaas.pqz");
    let labels: Vec<&str> = l["labels"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    let at = |k: &str, i: usize| l[k][i].as_u64().unwrap();
    for (label, slot, inner, byte, width) in STATE_LAYOUT {
        let i = labels.iter().position(|x| x == label).unwrap_or_else(|| panic!("{label} not pinned"));
        assert_eq!((at("slots", i), at("inner", i), at("bytes", i) as usize), (*slot, *inner, *byte), "{label}");
        if !label.starts_with("memos") {
            assert_eq!(at("widths", i) as usize, *width, "{label}: width");
        }
    }
}

/// The forge rows (`PqzStateVectors.t.sol` at the commit in the file): every account's `T` at the facade's `p` (with its
/// `shieldIn`) and every entry leg's `u ‖ v` and auditor copy, rebuilt from the raw words, equal the contract's statement
/// views byte for byte; the key the handle must hold is the registry's; `entryRef` recomputes; a HASH memo parses.
#[cfg(feature = "vectors")]
#[test]
fn state_rows_reproduce_the_contract() {
    let r = rows();
    let loc = json!({"chainId": r["chainId"], "chainUid": r["chainUid"], "token": r["token"], "registry": r["registry"], "psid": r["psid"]});
    let rebuilt = |cmd: &str, v: &Value| PqzCmd::from_json(cmd, v.to_string().as_bytes()).unwrap_or_else(|e| panic!("{cmd}: {e:?}")).vectors_rebuilt();
    let mut n = 0;
    for a in r["accounts"].as_array().unwrap() {
        let name = a["name"].as_str().unwrap();
        let mut words = merge(loc.clone(), json!({"ua": a["ua"], "block": a["block"], "account": a["account"], "pending": a["pending"],
            "accWords": a["accWords"], "blobs": a["blobs"], "keyRecord": a["keyRecord"]}));
        words.as_object_mut().unwrap().remove("chainId");
        words.as_object_mut().unwrap().remove("registry");
        let key = hx(&h(&a["blobs"][0]["code"])[1..]);
        if a["shieldIn"] == 0 {
            let b = rebuilt("balance", &words);
            assert_eq!((&b["T"], &b["p"], &b["sendCounter"], &b["key"]), (&a["T"], &a["p"], &a["sendCounter"], &json!(key)), "{name}: balance");
        }
        let refresh = merge(words, json!({"chainId": r["chainId"], "registry": r["registry"], "fee": 0, "validUntilBlock": 1u64 << 40,
            "shieldIn": a["shieldIn"], "envelopeBinding": hx(&[0; 32]), "memoHash": hx(&[0; 32])}));
        let b = rebuilt("proveRefresh", &refresh);
        assert_eq!((&b["T"], &b["p"], &b["sendCounter"]), (&a["T"], &a["p"], &a["sendCounter"]), "{name}: refresh");
        n += 1;
    }
    assert_eq!(n, 5);
    let mut legs = 0;
    for e in r["entries"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let base = merge(loc.clone(), json!({"entryRef": e["entryRef"], "fromUA": e["fromUA"], "sendCounter": e["sendCounter"],
            "entryPtr": e["entryPtr"], "block": 1}));
        for l in e["legs"].as_array().unwrap() {
            let rx = merge(base.clone(), json!({"ua": l["ua"], "leg": l["leg"], "kind": "RECEIVER_X", "blobs": [e["blob"], l["key"]],
                "keyRecord": l["keyRecord"]}));
            let b = rebuilt("proveDisclose", &rx);
            assert_eq!((&b["ct"], &b["window"]), (&l["ct"], &json!(0)), "{name} leg {}", l["leg"]);
            assert_eq!(b["words"][6], e["entryRef"], "{name}: entryRef in the statement");
            assert_eq!(b["key"], json!(hx(&h(&l["key"]["code"])[1..])), "{name}: the leg owner's registered key");
            if l["auditorCt"] != "" {
                let j = l["leg"].as_u64().unwrap();
                let au = merge(base.clone(), json!({"ua": r["auditorUA"], "leg": j, "blobs": [e["blob"], r["auditorKey"]],
                    "keyRecord": r["auditorKeyRecord"], "auditorMode": r["auditorMode"], "auditorUA": r["auditorUA"]}));
                let mut ar = au.clone();
                ar.as_object_mut().unwrap().remove("registry");
                let b = rebuilt("auditRead", &ar);
                assert_eq!((&b["ct"], &b["window"]), (&l["auditorCt"], &json!(j % st::S_AUD as u64)), "{name} leg {j}: auditor copy");
                let d = rebuilt("proveDisclose", &merge(au, json!({"kind": "AUDITOR", "registry": r["registry"]})));
                assert_eq!(d["words"][8], hx(&st::u64_word(2 + 256 * (j % st::S_AUD as u64))), "{name} leg {j}: the kind word");
            }
            legs += 1;
        }
        if e["memo"] != "0x" {
            let mut m = merge(base.clone(), json!({"memo": e["memo"], "blobs": [e["blob"], r["auditorKey"]], "keyRecord": r["auditorKeyRecord"]}));
            m.as_object_mut().unwrap().remove("registry");
            let b = rebuilt("openMemo", &m);
            assert_eq!(b["uas"].as_array().unwrap().len(), e["legs"].as_array().unwrap().len(), "{name}: memo");
        }
    }
    assert!(legs >= 15, "{legs}");
}

/// `balance` and every debit over rebuilt words: shields (TRIVIAL entries), an op 1 credit, the sender's `acc` a reference to
/// its debit's blob, a burn's blob, a materialised `acc` after a rollover, an op 7 credit; each proof verifies with pqz-ffi's
/// precompile and each balance decrypts from the next words.
#[test]
fn balances_and_debits_over_rebuilt_words() {
    let mut wd = World::new();
    wd.c.shield(&A, 600);
    wd.c.shield(&A, 400);
    let b = call(wd.key(&A), "balance", &wd.c.own(&A, 16)).unwrap();
    assert_eq!(b, json!({"value": 1000, "p": 2, "sendCounter": 0}));
    wd.pay(&A, &BOB, 300, true);
    assert_eq!((wd.balance(&A), wd.balance(&BOB)), (700, 300));
    wd.c.shield(&BOB, 5);
    // a burn: Bob's acc becomes the burn blob
    let p = call(wd.key(&BOB), "proveBurn", &wd.debit(&BOB, json!({"amount": 100, "recipient": hx(&[3; 32]), "memoHash": hx(&[0; 32])}))).unwrap();
    assert_eq!(p["p"], 2);
    assert!(verify(2, &h(&p["stmt"]), &h(&p["proof"])));
    wd.c.settle_burn(&h(&p["stmt"]));
    assert_eq!(wd.balance(&BOB), 205);
    // a rollover: Alice's acc materialised (not() slots, accHash), one entry still pending
    wd.c.shield(&A, 50);
    wd.c.shield(&A, 25);
    wd.c.roll(&A, 1);
    assert_eq!(wd.c.own(&A, 16)["accWords"].as_array().unwrap().len(), ACC_WORDS);
    assert_eq!(wd.balance(&A), 775);
    let p = call(wd.key(&A), "proveRefresh", &wd.debit(&A, json!({"memoHash": hx(&[0; 32])}))).unwrap();
    assert!(verify(2, &h(&p["stmt"]), &h(&p["proof"])));
    wd.c.settle_burn(&h(&p["stmt"]));
    assert_eq!(wd.balance(&A), 775);
    // op 7 with the auditor; a BUNDLE has no memo
    let (_, ans) = wd.pay_multi(&A, &[(BOB, 100), (Z, 0)], true, "BUNDLE");
    assert_eq!(ans.get("memo"), None);
    assert_eq!((wd.balance(&A), wd.balance(&BOB), wd.balance(&Z)), (675, 305, 0));
    // over the balance: refused after the key, to the caller only
    let over = wd.debit(&BOB, json!({"toUA": hx(&A), "pkT": wd.pk(&A), "amount": 306, "memoHash": hx(&[0; 32])}));
    assert_eq!(call(wd.key(&BOB), "proveTransfer", &over).err(), Some(Error::Argument));
}

/// Disclosures and auditor reads of old entries: op 1 and op 7 (M = 4, the auditor's windows 0, 1, 2, 0 across two groups),
/// each leg rebuilt from the op blob; `RECEIVER_X` and `AUDITOR` proofs verify; `auditRead` gives every leg's amount; the
/// sender opens its op 7 memo.
#[test]
fn disclosures_audit_reads_and_memo_over_rebuilt_words() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    let e1 = wd.pay(&A, &BOB, 300, true);
    let rx = merge(wd.c.entry(&e1, &BOB), json!({"ua": hx(&BOB), "leg": 0, "kind": "RECEIVER_X", "registry": hx(&REG)}));
    let p = call(wd.key(&BOB), "proveDisclose", &rx).unwrap();
    assert_eq!(p["amount"], 300);
    assert!(verify(5, &h(&p["stmt"]), &h(&p["proof"])));
    let ds = h(&p["stmt"]);
    let Stmt::Disclose(d) = st::parse(5, &ds).unwrap() else { panic!() };
    assert_eq!((d.form, d.words[6], d.amount()), (Form::DiscloseReceiver, e1, 300));
    let au = merge(merge(wd.c.entry(&e1, &AUD), wd.c.auditor_words(2)), json!({"ua": hx(&AUD), "leg": 0}));
    assert_eq!(call(wd.key(&AUD), "auditRead", &au).unwrap(), json!({"amount": 300}));
    let p = call(wd.key(&AUD), "proveDisclose", &merge(au, json!({"kind": "AUDITOR", "registry": hx(&REG)}))).unwrap();
    assert!(verify(5, &h(&p["stmt"]), &h(&p["proof"])));
    let legs = [(BOB, 10), (Z, 20), (X, 30), (Y, 40)];
    let (e7, ans) = wd.pay_multi(&A, &legs, true, "HASH");
    for (j, (ua, amt)) in legs.iter().enumerate() {
        let au = merge(merge(wd.c.entry(&e7, &AUD), wd.c.auditor_words(2)), json!({"ua": hx(&AUD), "leg": j}));
        assert_eq!(call(wd.key(&AUD), "auditRead", &au).unwrap(), json!({"amount": amt}), "auditor leg {j} (window {})", j % st::S_AUD);
        let rx = merge(wd.c.entry(&e7, ua), json!({"ua": hx(ua), "leg": j, "kind": "RECEIVER_X", "registry": hx(&REG)}));
        if j == 3 {
            let p = call(wd.key(ua), "proveDisclose", &rx).unwrap();
            assert!(verify(5, &h(&p["stmt"]), &h(&p["proof"])), "leg 3 (group 1)");
        }
    }
    let m = merge(wd.c.entry(&e7, &A), json!({"memo": ans["memo"]}));
    let o = call(wd.key(&A), "openMemo", &m).unwrap();
    let want: Vec<Value> = legs.iter().map(|(ua, a)| json!({"amount": a, "ua": hx(ua)})).collect();
    assert_eq!(o, json!({"auditorOn": true, "legs": want}));
    assert_eq!(wd.balance(&Y), 40);
}

/// A words command chooses `p` inside (CTR-PQZ-06) and takes no `T`, ciphertext, statement, `p` or parsed field: each such
/// field is refused on every words command, before the key.
#[test]
fn requests_carry_words_only() {
    let mut wd = World::new();
    for i in 0..20 {
        wd.c.shield(&A, i);
    }
    let base = wd.c.own(&A, 16);
    assert_eq!(base["pending"].as_array().unwrap().len(), 16, "p = rolled + INLINE_MAX");
    let b = call(wd.key(&A), "balance", &base).unwrap();
    assert_eq!((b["p"].clone(), b["value"].clone()), (json!(16), json!((0..16).sum::<u64>())));
    let reqs = [
        ("balance", base.clone()),
        ("proveRefresh", wd.debit(&A, json!({"memoHash": hx(&[0; 32])}))),
        ("proveTransfer", wd.debit(&A, json!({"toUA": hx(&BOB), "pkT": wd.pk(&BOB), "amount": 1, "memoHash": hx(&[0; 32])}))),
    ];
    let ct = hx(&vec![0u8; st::PK_BYTES + 128]);
    for (cmd, req) in &reqs {
        assert!(PqzCmd::from_json(cmd, req.to_string().as_bytes()).is_ok(), "{cmd}: positive control");
        for (f, v) in [("T", json!(ct)), ("p", json!(3)), ("ct", json!(ct)), ("stmt", json!("0x00")), ("pendingCount", json!(16)),
            ("acc", json!(ct)), ("value", json!(1)), ("proofSystemId", json!(hx(&PQZL_ID))), ("rolled", json!(0))]
        {
            refused(&format!("{cmd} with {f}"), wd.key(&A), cmd, &merge(req.clone(), json!({ f: v })), Error::Argument);
        }
    }
    if pqz_ffi::PQZH {
        // op 7 of a PQZH token: INLINE_MAX_PQZH (feature vectors: the rebuilt p)
        #[cfg(feature = "vectors")]
        {
            let mut m = merge(wd.c.own(&A, 10), wd.c.debit_fields());
            m["psid"] = json!(hx(&PQZH_ID));
            m["legs"] = json!([{"pk": wd.pk(&BOB), "ua": hx(&BOB), "amount": 1}]);
            m["mode"] = json!("BUNDLE");
            assert_eq!(PqzCmd::from_json("proveTransferMulti", m.to_string().as_bytes()).unwrap().vectors_rebuilt()["p"], 10);
        }
    }
}

fn set_word(v: &mut Value, path: &[&str], f: impl FnOnce(&mut Vec<u8>)) {
    let mut x = &mut *v;
    for p in path {
        x = if let Ok(i) = p.parse::<usize>() { &mut x[i] } else { &mut x[*p] };
    }
    let mut b = h(x);
    f(&mut b);
    *x = json!(hx(&b));
}

/// Spec §5, word negatives on an account (`balance`, a debit): each refused with one status and the key unused; the
/// unchanged request is the positive control.
#[test]
fn word_negatives_refused_before_the_key() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    wd.pay(&A, &BOB, 300, false);
    wd.c.shield(&BOB, 7);
    wd.c.shield(&A, 3);
    wd.c.roll(&A, 1);
    wd.c.shield(&A, 4);
    let k = wd.key(&BOB);
    let ok = wd.c.own(&BOB, 16);
    assert_eq!(call(k, "balance", &ok).unwrap()["value"], 307, "positive control: Bob");
    let ka = wd.key(&A);
    let oka = wd.c.own(&A, 16);
    assert_eq!(call(ka, "balance", &oka).unwrap()["value"], 707, "positive control: Alice (materialised)");
    let neg = |what: &str, k: &PqzKey, base: &Value, f: &dyn Fn(&mut Value), want: Error| {
        let mut r = base.clone();
        f(&mut r);
        refused(what, k, "balance", &r, want);
    };
    let other = if st::SET == "n2048-kmax1024" { "ef1ffbcbd05394f8276e50a6c254022edf53bbd08a56e22aadddac2b9b90336e" } else {
        "c752e7f57778114dbfaac5d43843577b54e13e3ed162517145a37b5a3ec6cdfe"
    };
    neg("psid of another set", k, &ok, &|r| r["psid"] = json!(format!("0x{other}")), Error::PqzSetMismatch);
    neg("a pending index missing", k, &ok, &|r| { r["pending"].as_array_mut().unwrap().pop(); }, Error::Argument);
    neg("an extra pending index", k, &ok, &|r| {
        let mut e = r["pending"][0].clone();
        e["index"] = json!(9);
        r["pending"].as_array_mut().unwrap().push(e);
    }, Error::Argument);
    neg("indexes shifted", k, &ok, &|r| for e in r["pending"].as_array_mut().unwrap() { e["index"] = json!(e["index"].as_u64().unwrap() + 1) }, Error::Argument);
    neg("indexes reordered", k, &ok, &|r| r["pending"].as_array_mut().unwrap().swap(0, 1), Error::Argument);
    neg("a zero pending word", k, &ok, &|r| r["pending"][1]["word"] = json!(hx(&[0; 32])), Error::Argument);
    neg("an offset outside its blob", k, &ok, &|r| set_word(r, &["pending", "0", "word"], |w| w[20..22].copy_from_slice(&[0xff, 0xf0])), Error::Argument);
    neg("a TRIVIAL entry read as a credit", k, &ok, &|r| set_word(r, &["pending", "1", "word"], |w| w[23] = 1), Error::Argument);
    neg("the account short of a slot", k, &ok, &|r| { r["account"].as_array_mut().unwrap().pop(); }, Error::Argument);
    neg("an extra account slot", k, &ok, &|r| r["account"].as_array_mut().unwrap().push(json!(hx(&[0; 32]))), Error::Argument);
    neg("bits above the packed fields", k, &ok, &|r| set_word(r, &["account", "1"], |w| w[0] = 1), Error::Argument);
    neg("cleared above floor", k, &ok, &|r| set_word(r, &["account", "0"], |w| w[7] = 9), Error::Argument);
    neg("more than K_MAX units", k, &ok, &|r| set_word(r, &["account", "1"], |w| w[4..8].copy_from_slice(&(st::K_MAX as u32).to_be_bytes())), Error::Argument);
    neg("more than K_MAX units, nothing pending", k, &ok, &|r| {
        set_word(r, &["account", "1"], |w| w[4..8].copy_from_slice(&(st::K_MAX as u32).to_be_bytes()));
        r["pending"] = json!([]);
        r["blobs"].as_array_mut().unwrap().truncate(1);
    }, Error::Argument);
    neg("acc slots without the flag", k, &ok, &|r| r["accWords"] = oka["accWords"].clone(), Error::Argument);
    neg("a blob missing", k, &ok, &|r| { r["blobs"].as_array_mut().unwrap().pop(); }, Error::Argument);
    neg("an extra blob", k, &ok, &|r| r["blobs"].as_array_mut().unwrap().push(json!({"address": hx(&[9; 20]), "code": "0x00"})), Error::Argument);
    neg("a blob twice", k, &ok, &|r| { let b = r["blobs"][1].clone(); r["blobs"].as_array_mut().unwrap().push(b); }, Error::Argument);
    neg("a code without its STOP byte", k, &ok, &|r| set_word(r, &["blobs", "1", "code"], |c| c[0] = 1), Error::Argument);
    neg("the key not proven", k, &ok, &|r| set_word(r, &["keyRecord"], |w| w[11] = 0), Error::Argument);
    neg("another account's key record", k, &ok, &|r| {
        r["keyRecord"] = json!(hx(&wd.c.key_record(&A)));
        r["blobs"][0] = wd.c.blobs_json(&[wd.c.keys[&A]])[0].clone();
    }, Error::Argument);
    neg("acc not hashing to accHash", ka, &oka, &|r| set_word(r, &["accWords", "7"], |w| w[5] ^= 1), Error::Argument);
    neg("an acc slot missing", ka, &oka, &|r| { r["accWords"].as_array_mut().unwrap().pop(); }, Error::Argument);
    neg("acc slots stored without not()", ka, &oka, &|r| for w in r["accWords"].as_array_mut().unwrap() {
        *w = json!(hx(&h(w).iter().map(|b| !b).collect::<Vec<_>>()));
    }, Error::Argument);
    neg("an acc reference blob given with the flag", ka, &oka, &|r| r["blobs"].as_array_mut().unwrap().push(ok["blobs"][1].clone()), Error::Argument);
}

/// Spec §5, entry, leg and role negatives (Codex C5): each refused with one status and the key unused.
#[test]
fn entry_and_role_negatives_refused_before_the_key() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    let e1 = wd.pay(&A, &BOB, 300, true);
    // an unaudited op 1 entry, structurally valid (zero ciphertexts; nothing here decrypts it)
    let mut blob = vec![0x5a; 16];
    blob.extend(vec![0u8; PKP + VP]);
    blob.extend(Z);
    blob.extend(vec![0u8; VP]);
    let ptr = wd.c.put(blob);
    let e0 = entry_ref(&Z, 77);
    wd.c.entries.insert(e0, Ent { ptr, from: Z, ctr: 77, memo: vec![] });
    // the same on an unaudited op 7 entry of two legs, where `v_j`'s auditor offset still lies inside `R` (zero ciphertexts,
    // small UA words: every field canonical)
    let ua1 = { let mut u = [0u8; 32]; u[31] = 1; u };
    let blob7 = [vec![0x5a; 16], vec![0u8; PKP], vec![0u8; VP], ua1.to_vec(), vec![0u8; VP], ua1.to_vec(), vec![0u8; VP]].concat();
    let ptr7 = wd.c.put(blob7);
    let e7 = entry_ref(&Z, 78);
    wd.c.entries.insert(e7, Ent { ptr: ptr7, from: Z, ctr: 78, memo: vec![] });
    let rx = merge(wd.c.entry(&e1, &BOB), json!({"ua": hx(&BOB), "leg": 0, "kind": "RECEIVER_X", "registry": hx(&REG)}));
    let au = merge(merge(wd.c.entry(&e1, &AUD), wd.c.auditor_words(2)), json!({"ua": hx(&AUD), "leg": 0}));
    let (kb, ka, kz) = (wd.key(&BOB), wd.key(&AUD), wd.key(&Z));
    assert_eq!(call(ka, "auditRead", &au).unwrap()["amount"], 300, "positive control: auditor");
    assert!(PqzCmd::from_json("proveDisclose", rx.to_string().as_bytes()).is_ok(), "positive control: receiver");
    let r = |base: &Value, x: Value| merge(base.clone(), x);
    refused("entryRef not recomputing (sendCounter)", kb, "proveDisclose", &r(&rx, json!({"sendCounter": 1})), Error::Argument);
    refused("entryRef not recomputing (fromUA)", kb, "proveDisclose", &r(&rx, json!({"fromUA": hx(&Z)})), Error::Argument);
    refused("another entryRef", ka, "auditRead", &r(&au, json!({"entryRef": hx(&e0)})), Error::Argument);
    refused("a leg outside the entry", kb, "proveDisclose", &r(&rx, json!({"leg": 1})), Error::Argument);
    refused("a leg outside the entry (auditor)", ka, "auditRead", &r(&au, json!({"leg": 1})), Error::Argument);
    // a foreign leg: Z's own record and handle, but leg 0 is Bob's
    let foreign = merge(wd.c.entry(&e1, &Z), json!({"ua": hx(&Z), "leg": 0, "kind": "RECEIVER_X", "registry": hx(&REG)}));
    refused("a foreign leg", kz, "proveDisclose", &foreign, Error::Argument);
    refused("Bob's record on Z's handle", kz, "proveDisclose", &rx, Error::Argument);
    // roles
    let rx_on_aud = merge(wd.c.entry(&e1, &AUD), json!({"ua": hx(&AUD), "leg": 0, "kind": "RECEIVER_X", "registry": hx(&REG)}));
    refused("a receiver read on the auditor's handle", ka, "proveDisclose", &rx_on_aud, Error::Argument);
    let au_on_bob = merge(merge(wd.c.entry(&e1, &BOB), wd.c.auditor_words(2)), json!({"ua": hx(&BOB), "leg": 0}));
    refused("an auditor read on a receiver's handle", kb, "auditRead", &au_on_bob, Error::Argument);
    refused("the auditor's record on a receiver's handle", kb, "auditRead", &au, Error::Argument);
    refused("auditorMode NONE", ka, "auditRead", &merge(au.clone(), wd.c.auditor_words(0)), Error::Argument);
    refused("auditorMode past OPTIONAL", ka, "auditRead", &merge(au.clone(), wd.c.auditor_words(3)), Error::Argument);
    let au0 = merge(merge(wd.c.entry(&e0, &AUD), wd.c.auditor_words(2)), json!({"ua": hx(&AUD), "leg": 0}));
    refused("an auditor read of an entry without auditor copies", ka, "auditRead", &au0, Error::Argument);
    let au7 = merge(merge(wd.c.entry(&e7, &AUD), wd.c.auditor_words(2)), json!({"ua": hx(&AUD), "leg": 0}));
    refused("an auditor read of an op 7 entry without auditor copies", ka, "auditRead", &au7, Error::Argument);
    refused("the auditor words on a receiver read", kb, "proveDisclose", &merge(rx.clone(), wd.c.auditor_words(2)), Error::Argument);
    let mut no_aud = au.clone();
    no_aud.as_object_mut().unwrap().remove("auditorUA");
    refused("an auditor read without auditorUA", ka, "auditRead", &no_aud, Error::Argument);
    refused("a registry on auditRead", ka, "auditRead", &r(&au, json!({"registry": hx(&REG)})), Error::Argument);
    refused("bits above the entry pointer", kb, "proveDisclose", &{ let mut x = rx.clone(); set_word(&mut x, &["entryPtr"], |w| w[0] = 1); x }, Error::Argument);
    refused("the entry blob missing", kb, "proveDisclose", &{ let mut x = rx.clone(); x["blobs"].as_array_mut().unwrap().remove(0); x }, Error::Argument);
    refused("an unknown kind", kb, "proveDisclose", &r(&rx, json!({"kind": "SENDER_S"})), Error::Argument);
    refused("psid of another set", kb, "proveDisclose", &r(&rx, json!({"psid": hx(&[7; 32])})), Error::PqzSetMismatch);
    for f in ["ct", "stmt", "T", "amount", "u", "v"] {
        refused(&format!("{f} on proveDisclose"), kb, "proveDisclose", &r(&rx, json!({ f: "0x00" })), Error::Argument);
    }
}

/// `openMemo` of an old entry: its memo's salt and length are the entry blob's, the opened legs are the blob's, the sender's
/// key record binds the handle; each negative refused before the key.
#[test]
fn open_memo_binds_the_entry() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    let legs = [(BOB, 250), (Z, 0)];
    let (e7, ans) = wd.pay_multi(&A, &legs, false, "HASH");
    let m = merge(wd.c.entry(&e7, &A), json!({"memo": ans["memo"]}));
    let o = call(wd.key(&A), "openMemo", &m).unwrap();
    assert_eq!(o["legs"][0], json!({"amount": 250, "ua": hx(&BOB)}), "positive control");
    let k = wd.key(&A);
    let memo = h(&ans["memo"]);
    let mut salt = memo.clone();
    salt[0] ^= 1;
    refused("a memo of another salt", k, "openMemo", &merge(m.clone(), json!({"memo": hx(&salt)})), Error::Argument);
    refused("a memo of another length", k, "openMemo", &merge(m.clone(), json!({"memo": hx(&memo[..memo.len() - 40])})), Error::Argument);
    refused("entryRef not recomputing", k, "openMemo", &merge(m.clone(), json!({"sendCounter": 5})), Error::Argument);
    refused("the sender's record on Bob's handle", wd.key(&BOB), "openMemo", &m, Error::Argument);
    // the keystream opened, then the legs compared with the blob's (a flipped UA byte: after the key, to the caller only)
    let mut flip = memo.clone();
    flip[16 + 2 + 8] ^= 1;
    assert_eq!(call(k, "openMemo", &merge(m, json!({"memo": hx(&flip)}))).err(), Some(Error::Argument));
}
