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
        call(self.key(ua), "balance", &self.c.bal(ua)).unwrap()["value"].as_u64().unwrap()
    }
    fn debit(&self, ua: &Word, extra: Value) -> Value {
        merge(merge(self.c.own(ua, 16), self.c.debit_fields()), extra)
    }
    /// Op 1 from `from` to `to`, verified and settled; the entry.
    fn pay(&mut self, from: &Word, to: &Word, amount: u64, aud: bool) -> Word {
        let mut extra = json!({"toUA": hx(to), "pkT": self.pk(to), "amount": amount, "mode": "BUNDLE"});
        if aud {
            extra["pkA"] = json!(self.pk(&AUD));
        }
        let p = call(self.key(from), "proveTransfer", &self.debit(from, extra)).unwrap();
        let stmt = h(&p["stmt"]);
        assert!(verify(1, &stmt, &h(&p["proof"])), "op 1 over rebuilt words verifies");
        self.c.own_tag = tag(&p);
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
        self.c.own_tag = tag(&p);
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
    // T20d2: the facade's packer (for `ownTag`'s `P(u) ‖ P(v_f)`) is the test's, and refuses what has no stored form
    assert_eq!(scaas_ua::facade::pqz_pack::pack(&lanes), Some(pack(&lanes)), "the facade's packer");
    assert_eq!(scaas_ua::facade::pqz_pack::pack(&want), Some(g.clone()), "the hand vector, packed by the facade");
    let mut wide = want.clone();
    wide[7 - B / 8] |= 1 << (B % 8);
    assert_eq!(scaas_ua::facade::pqz_pack::pack(&wide), None, "a coefficient of B + 1 bits");
    assert_eq!(scaas_ua::facade::pqz_pack::pack(&want[..24]), None, "not a whole word");
    // the forge rows: leg 0 of every op 1 entry, unpacked from the stored blob, is the contract's
    let r = rows();
    assert_eq!(r["set"], st::SET);
    let mut n = 0;
    for e in r["entries"].as_array().unwrap().iter().filter(|e| e["legs"].as_array().unwrap().len() == 1) {
        let d = &h(&e["blob"]["code"])[1..];
        let ct = [unpack(&d[16..16 + PKP]).unwrap(), unpack(&d[16 + PKP..16 + PKP + VP]).unwrap()].concat();
        assert_eq!(hx(&ct), e["legs"][0]["ct"].as_str().unwrap(), "{}", e["name"]);
        let stored = &d[16..16 + PKP + VP];
        assert_eq!(scaas_ua::facade::pqz_pack::pack(&ct).as_deref(), Some(stored), "{}: packed back to the contract's bytes", e["name"]);
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
        let mut words = merge(merge(loc.clone(), json!({"ua": a["ua"], "block": a["block"], "account": a["account"], "pending": a["pending"],
            "accWords": a["accWords"], "blobs": a["blobs"], "keyRecord": a["keyRecord"]})), forge_versions(a));
        words.as_object_mut().unwrap().remove("chainId");
        words.as_object_mut().unwrap().remove("registry");
        let key = hx(&h(&a["blobs"][0]["code"])[1..]);
        if a["shieldIn"] == 0 {
            let b = rebuilt("balance", &merge(words.clone(), json!({"forOp7": false})));
            assert_eq!((&b["T"], &b["p"], &b["sendCounter"], &b["key"]), (&a["T"], &a["p"], &a["sendCounter"], &json!(key)), "{name}: balance");
        }
        let refresh = merge(words, json!({"chainId": r["chainId"], "registry": r["registry"], "fee": 0, "validUntilBlock": 1u64 << 40,
            "shieldIn": a["shieldIn"], "envelopeBinding": hx(&[0; 32])}));
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
            // T15l: the sender's op 4 of the same leg (its key record the sender account's row)
            let from = r["accounts"].as_array().unwrap().iter().find(|a| a["ua"] == e["fromUA"]).unwrap();
            let ds = merge(base.clone(), json!({"leg": l["leg"], "blobs": [e["blob"], from["blobs"][0], l["key"]], "keyRecord": from["keyRecord"],
                "legKeyRecords": [l["keyRecord"]]}));
            let b = rebuilt("proveDiscloseSender", &ds);
            assert_eq!((&b["ct"], &b["words"][6], &b["words"][0]), (&l["ct"], &e["entryRef"], &json!(hx(&Form::DiscloseSender.op_tag()))), "{name}: op 4");
            assert_eq!((&b["legKeys"][0], &b["key"]), (&json!(hx(&h(&l["key"]["code"])[1..])), &json!(hx(&h(&from["blobs"][0]["code"])[1..]))), "{name}: op 4 keys");
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
    let b = call(wd.key(&A), "balance", &wd.c.bal(&A)).unwrap();
    assert_eq!(b, json!({"value": 1000, "p": 2, "sendCounter": 0}));
    wd.pay(&A, &BOB, 300, true);
    assert_eq!((wd.balance(&A), wd.balance(&BOB)), (700, 300));
    wd.c.shield(&BOB, 5);
    // a burn: Bob's acc becomes the burn blob
    let p = call(wd.key(&BOB), "proveBurn", &wd.debit(&BOB, json!({"amount": 100, "recipient": hx(&[3; 32])}))).unwrap();
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
    let p = call(wd.key(&A), "proveRefresh", &wd.debit(&A, json!({}))).unwrap();
    assert!(verify(2, &h(&p["stmt"]), &h(&p["proof"])));
    wd.c.settle_burn(&h(&p["stmt"]));
    assert_eq!(wd.balance(&A), 775);
    // op 7 with the auditor; a BUNDLE has no memo
    let (_, ans) = wd.pay_multi(&A, &[(BOB, 100), (Z, 0)], true, "BUNDLE");
    assert_eq!(ans.get("memo"), None);
    assert_eq!((wd.balance(&A), wd.balance(&BOB), wd.balance(&Z)), (675, 305, 0));
    // over the balance: refused after the key, to the caller only
    let over = wd.debit(&BOB, json!({"toUA": hx(&A), "pkT": wd.pk(&A), "amount": 306, "mode": "BUNDLE"}));
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
    let b = call(wd.key(&A), "balance", &wd.c.bal(&A)).unwrap();
    assert_eq!((b["p"].clone(), b["value"].clone()), (json!(16), json!((0..16).sum::<u64>())));
    let reqs = [
        ("balance", wd.c.bal(&A)),
        ("proveRefresh", wd.debit(&A, json!({}))),
        ("proveTransfer", wd.debit(&A, json!({"toUA": hx(&BOB), "pkT": wd.pk(&BOB), "amount": 1, "mode": "HASH"}))),
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
    // `forOp7` (T15l, Fable P3-6): named, no default, a bool
    for bad in [json!(null), json!(0), json!("true")] {
        refused(&format!("forOp7 {bad}"), wd.key(&A), "balance", &merge(base.clone(), json!({"forOp7": bad})), Error::Argument);
    }
    refused("no forOp7", wd.key(&A), "balance", &base, Error::Argument);
    if pqz_ffi::PQZH {
        // an op 7 of a PQZH token reads INLINE_MAX_PQZH pending entries: `balance` with `forOp7` reports that `p` and value
        let mut b10 = merge(wd.c.own(&A, 10), json!({"forOp7": true}));
        b10["psid"] = json!(hx(&st::PQZH_ID));
        let b = call(wd.key(&A), "balance", &b10).unwrap();
        assert_eq!((b["p"].clone(), b["value"].clone()), (json!(10), json!((0..10).sum::<u64>())), "forOp7 on a PQZH token");
        refused("forOp7 false over op 7's window", wd.key(&A), "balance", &merge(b10.clone(), json!({"forOp7": false})), Error::Argument);
        let mut b16 = wd.c.bal(&A);
        b16["psid"] = json!(hx(&st::PQZH_ID));
        assert_eq!(call(wd.key(&A), "balance", &b16).unwrap()["p"], 16, "op 1 / op 2 on a PQZH token: INLINE_MAX");
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
    let ok = wd.c.bal(&BOB);
    assert_eq!(call(k, "balance", &ok).unwrap()["value"], 307, "positive control: Bob");
    let ka = wd.key(&A);
    let oka = wd.c.bal(&A);
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
    // group 3h (T58): `lastDebit` in slot 2 is a `uint64`
    neg("bits above lastDebit", k, &ok, &|r| set_word(r, &["account", "2"], |w| w[23] = 1), Error::Argument);
    // group 3g (T15o): the UA's sendCounter word and the registry's version word
    neg("bits above sendCounter", k, &ok, &|r| set_word(r, &["sendCounterWord"], |w| w[23] = 1), Error::Argument);
    neg("no sendCounterWord", k, &ok, &|r| { r.as_object_mut().unwrap().remove("sendCounterWord"); }, Error::Argument);
    neg("no keyVersion", k, &ok, &|r| { r.as_object_mut().unwrap().remove("keyVersion"); }, Error::Argument);
    neg("no keyVersions", k, &ok, &|r| { r.as_object_mut().unwrap().remove("keyVersions"); }, Error::Argument);
    neg("keyVersion above current", k, &ok, &|r| r["keyVersion"] = json!(1), Error::Argument);
    neg("current above latest", k, &ok, &|r| set_word(r, &["keyVersions"], |w| w[23] = 1), Error::Argument);
    neg("listed not a bool", k, &ok, &|r| set_word(r, &["keyVersions"], |w| w[15] = 2), Error::Argument);
    neg("bits above the version fields", k, &ok, &|r| set_word(r, &["keyVersions"], |w| w[14] = 1), Error::Argument);
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
        r["blobs"][0] = wd.c.blobs_json(&[wd.c.key_ptr(&A)])[0].clone();
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

#[cfg(feature = "vectors")]
fn sender_trials() -> usize {
    scaas_ua::facade::pqz::vectors_sender_trials()
}

fn prover_calls() -> usize {
    #[cfg(feature = "vectors")]
    return scaas_ua::facade::pqz::vectors_prover_calls();
    #[cfg(not(feature = "vectors"))]
    0
}

/// T15l (Fable P2-1; spec §4.6): `proveDiscloseSender` over the sender's own entry words, op 1 (audited, and an amount 0) and
/// op 7 (`M = 1`, the op 1 shape; `M = 4` audited, leg 1 inside group 0, leg 3 in group 1): the amount is the entry's (the request has no amount or
/// statement field), the statement's `pk` the leg owner's registered key, its `u`, `v` the leg's (those of the receiver's
/// `RECEIVER_X` statement); each proof verifies.
#[test]
fn sender_disclosure_over_rebuilt_words() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    let e1 = wd.pay(&A, &BOB, 300, true);
    let e0 = wd.pay(&A, &Z, 0, false);
    let (e7, _) = wd.pay_multi(&A, &[(BOB, 7)], false, "HASH");
    let (e74, _) = wd.pay_multi(&A, &[(BOB, 10), (Z, 20), (X, 30), (Y, 40)], true, "BUNDLE");
    let ka = wd.key(&A);
    for (er, j, owner, amount, rx) in [(e1, 0, BOB, 300, true), (e0, 0, Z, 0, false), (e7, 0, BOB, 7, false), (e74, 0, BOB, 10, false), (e74, 1, Z, 20, false), (e74, 3, Y, 40, true)] {
        let p = call(ka, "proveDiscloseSender", &wd.c.sender_leg(&er, j, &owner)).unwrap();
        assert_eq!(p["amount"], amount, "leg {j}");
        let s = h(&p["stmt"]);
        assert!(verify(4, &s, &h(&p["proof"])), "op 4 leg {j} verifies");
        let Stmt::Disclose(d) = st::parse(4, &s).unwrap() else { panic!() };
        assert_eq!((d.form, d.words[6], d.amount(), d.pk), (Form::DiscloseSender, er, amount, &wd.key(&owner).pk()[..]));
        if rx {
            let q = merge(wd.c.entry(&er, &owner), json!({"ua": hx(&owner), "leg": j, "kind": "RECEIVER_X", "registry": hx(&REG)}));
            let r = h(&call(wd.key(&owner), "proveDisclose", &q).unwrap()["stmt"]);
            let Stmt::Disclose(r) = st::parse(5, &r).unwrap() else { panic!() };
            assert_eq!((r.u, r.v, r.amount(), &r.words[2..7]), (d.u, d.v, amount, &d.words[2..7]), "the receiver's statement, the same leg");
        }
    }
}

/// T15l: `proveDiscloseSender`'s negatives. Before the key (one status, the key unused): a caller `amount`, `stmt`, `salt`,
/// `auditorOn` or `M`; `entryRef` not recomputing; a leg outside the entry; the leg owner's record or code missing; the
/// sender's record on another handle; another set's `psid`. After the key, before the prover (the sender's re-derivation does
/// not match the leg): another key record as the leg owner's, another sender's entry under its own record.
#[test]
fn sender_disclosure_negatives() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    wd.c.shield(&Z, 1000);
    let e1 = wd.pay(&A, &BOB, 300, true);
    let ez = wd.pay(&Z, &BOB, 5, false);
    let (ka, kb) = (wd.key(&A), wd.key(&BOB));
    let ok = wd.c.sender_leg(&e1, 0, &BOB);
    assert!(PqzCmd::from_json("proveDiscloseSender", ok.to_string().as_bytes()).is_ok(), "positive control");
    for (f, v) in [("amount", json!(300)), ("stmt", json!("0x00")), ("salt", json!(hx(&[0x5a; 16]))), ("auditorOn", json!(true)), ("M", json!(1)),
        ("ua", json!(hx(&A))), ("kind", json!("SENDER_S"))]
    {
        refused(&format!("a caller {f}"), ka, "proveDiscloseSender", &merge(ok.clone(), json!({ f: v })), Error::Argument);
    }
    refused("entryRef not recomputing", ka, "proveDiscloseSender", &merge(ok.clone(), json!({"sendCounter": 7})), Error::Argument);
    refused("a leg outside the entry", ka, "proveDiscloseSender", &merge(ok.clone(), json!({"leg": 1})), Error::Argument);
    let mut no_owner = ok.clone();
    no_owner.as_object_mut().unwrap().remove("legKeyRecords");
    refused("no legKeyRecords", ka, "proveDiscloseSender", &no_owner, Error::Argument);
    refused("an empty legKeyRecords", ka, "proveDiscloseSender", &merge(ok.clone(), json!({"legKeyRecords": []})), Error::Argument);
    let mut no_code = ok.clone();
    no_code["blobs"].as_array_mut().unwrap().pop();
    refused("the leg owner's key code missing", ka, "proveDiscloseSender", &no_code, Error::Argument);
    refused("the sender's record on Bob's handle", kb, "proveDiscloseSender", &ok, Error::Argument);
    refused("psid of another set", ka, "proveDiscloseSender", &merge(ok.clone(), json!({"psid": hx(&[7; 32])})), Error::PqzSetMismatch);
    let calls = prover_calls();
    let other_owner = wd.c.sender_leg(&e1, 0, &Z);
    assert_eq!(call(ka, "proveDiscloseSender", &other_owner).err(), Some(Error::Argument), "Z's key as the leg owner's");
    // Z's entry, asked on Alice's handle with Alice's own record: entryRef recomputes, the re-derivation (Alice's seed) does not
    let mut theirs = wd.c.sender_leg(&ez, 0, &BOB);
    theirs["keyRecord"] = json!(hx(&wd.c.key_record(&A)));
    theirs["blobs"] = json!(wd.c.blobs_json(&[wd.c.entries[&ez].ptr, wd.c.key_ptr(&A), wd.c.key_ptr(&BOB)]));
    assert_eq!(call(ka, "proveDiscloseSender", &theirs).err(), Some(Error::Argument), "another sender's entry");
    assert_eq!(prover_calls(), calls, "refused before the prover");
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

// ---------------------------------------------------------------------------------------------------------------------------
// T15k (Fable P3-5; ua-mtx-merge T36a): op 1's memo per `mode`, op 2's `memoHash` 0, as the contract's statements.
// ---------------------------------------------------------------------------------------------------------------------------

/// The forge rows' statement words (`PqzStateVectors.t.sol`, the 3h token's statement views): every debit's `memoHash` is
/// `keccak256(memo ‖ ownTag)` (proof-path spec C3), the memo `salt ‖ sealedMemo` on HASH (op 1's `sealedMemo` 42 bytes, op
/// 7's encoding with M = 1: `PqzCore.SEALED`) and empty on BUNDLE and a burn. The test's formula ([`memo_hash`]), which the
/// facade's statements are checked against below, is checked against them; the pre-3h words (`keccak256(salt ‖ sealedMemo)`,
/// 0) are not the contract's.
#[test]
fn memo_hash_is_the_contracts() {
    let r = rows();
    let rows = r["memoHash"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for m in rows {
        let (op, mode) = (m["op"].as_u64().unwrap(), m["mode"].as_str().unwrap());
        let (want, own_tag): (Vec<u8>, Word) = (h(&m["memoHash"]), h(&m["ownTag"]).try_into().unwrap());
        let memo = if mode == "HASH" {
            let (salt, sealed) = (h(&m["salt"]), h(&m["sealedMemo"]));
            assert_eq!(salt.len(), 16);
            if op == 1 {
                assert_eq!(sealed.len(), pqz_ffi::memo::memo_len(1) - 16, "op 1: op 7's encoding, M = 1");
            }
            assert_ne!(scaas_ua::keccak256(&[&salt[..], &sealed].concat()).to_vec(), want, "op {op} HASH: not the pre-3h word");
            [salt, sealed].concat()
        } else {
            assert_ne!(want, vec![0; 32], "op {op} {mode}: not the pre-3h 0");
            vec![]
        };
        assert_eq!(memo_hash(&memo, &own_tag).to_vec(), want, "op {op} {mode}: keccak256(memo ‖ ownTag)");
    }
}

/// The test's 3h formulas (proof-path spec C3, C4), written from the spec and not from the facade: `memoHash = keccak256(memo ‖
/// ownTag)`; `ownTag = HMAC-SHA256(HKDF-SHA256(seed32, "", "PQZ/owntag/v1", 32), chainUid ‖ token ‖ fromUA ‖ be32(sendCounter)
/// ‖ keccak256(P(u) ‖ P(v_f)))`, the location from the statement's header and `P` the test's packer.
fn memo_hash(memo: &[u8], own_tag: &Word) -> Word {
    scaas_ua::keccak256(&[memo, &own_tag[..]].concat())
}
fn tag_message(chain_uid: &[u8], token: &[u8], from_ua: &[u8], counter: u32, ct_hash: &[u8]) -> Vec<u8> {
    assert_eq!((chain_uid.len(), token.len(), from_ua.len(), ct_hash.len()), (32, 20, 32, 32));
    [chain_uid, token, from_ua, &counter.to_be_bytes(), ct_hash].concat()
}
fn tag_mac(seed32: &[u8], message: &[u8]) -> Word {
    scaas_ua::wallet::hmac_sha256(&scaas_ua::wallet::hkdf_sha256(seed32, &[], b"PQZ/owntag/v1", 32).unwrap(), message)
}
fn own_tag_of(seed32: &[u8], hd: &[Word; 20], u: &[u8], v_f: &[u8]) -> Word {
    let counter = u32::try_from(st::word_u64(&hd[st::H_SEND_COUNTER]).unwrap()).unwrap();
    let ct_hash = scaas_ua::keccak256(&[pack(u), pack(v_f)].concat());
    tag_mac(seed32, &tag_message(&hd[st::H_CHAIN_UID], &hd[st::H_TOKEN][12..], &hd[st::H_FROM], counter, &ct_hash))
}
/// An answer's `ownTag`.
fn tag(p: &Value) -> Word {
    h(&p["ownTag"]).try_into().unwrap()
}
/// The `seed32` of `account`'s key of version `v` (the test's view of the wallet, through the marker export).
fn seed_of(w: &Wallet, account: u32, v: u64) -> [u8; 32] {
    *w.export_pqz_leaf_raw_version(account, 0, v, scaas_ua::facade::pqz::AllowSecretExport).unwrap()
}

/// T20d2 (C-PP-4, the shared KAT of both 3h specs): `pq_kat.json` `ownTag` (three rows: versions 0 and 1, the label
/// `PQZ/owntag/v1`) and `memoHash` (HASH, BUNDLE, burn) reproduced by the test's formulas, and (feature `vectors`) by the
/// facade's own key and HMAC.
#[test]
fn own_tag_and_memo_hash_kat() {
    let p = format!("{}/../../smartcontracts/vectors/ua/pq_kat.json", env!("CARGO_MANIFEST_DIR"));
    let k: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    let tags = k["ownTag"].as_array().unwrap();
    assert_eq!(tags.len(), 3);
    for r in tags {
        assert_eq!(r["label"], "PQZ/owntag/v1");
        let (seed, ctr) = (h(&r["seed32"]), u32::try_from(r["sendCounter"].as_u64().unwrap()).unwrap());
        let msg = tag_message(&h(&r["chainUid"]), &h(&r["token"]), &h(&r["fromUA"]), ctr, &h(&r["ctHash"]));
        assert_eq!(hx(&msg), r["message"].as_str().unwrap(), "version {} counter {ctr}: the message", r["version"]);
        assert_eq!(hx(&tag_mac(&seed, &msg)), r["ownTag"].as_str().unwrap(), "version {} counter {ctr}", r["version"]);
        #[cfg(feature = "vectors")]
        {
            let (key, t) = scaas_ua::facade::pqz::vectors_own_tag(&seed, &msg).unwrap();
            assert_eq!((hx(&key), hx(&t)), (r["key"].as_str().unwrap().to_string(), r["ownTag"].as_str().unwrap().to_string()), "the facade's K and tag");
        }
    }
    assert_ne!(tags[0]["seed32"], tags[2]["seed32"], "version 1's seed is not version 0's");
    let memo_rows = k["memoHash"].as_array().unwrap();
    assert_eq!(memo_rows.iter().map(|r| r["form"].as_str().unwrap()).collect::<Vec<_>>(), ["hash", "bundle", "burn"]);
    for r in memo_rows {
        let (memo, t): (Vec<u8>, Word) = (h(&r["memo"]), h(&r["ownTag"]).try_into().unwrap());
        assert_eq!(memo.len(), if r["form"] == "hash" { 16 + 42 } else { 0 }, "{}", r["form"]);
        assert_eq!(hx(&memo_hash(&memo, &t)), r["memoHash"].as_str().unwrap(), "{}", r["form"]);
    }
}

/// T20d2 (C-PP-4): every path (A) debit form answers its `ownTag` and carries `memoHash = keccak256(memo ‖ ownTag)` in its
/// statement, the tag recomputed here from the debited version's seed, the statement's location words and its own `u_0` /
/// `u′` and `v_f` in the stored form: op 1 HASH and BUNDLE, op 7 HASH and BUNDLE (with the auditor), burn, refresh, and a
/// stale version's refresh and migration (the stale version's seed; version 1's seed at the same message gives another tag).
/// Each statement verifies; the settled blobs carry the facade's tag.
#[test]
fn own_tag_of_every_debit() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    let seed_a = seed_of(&wd._w, 0, 0);
    let check = |what: &str, op: u8, p: &Value, seed: &[u8]| -> Word {
        let stmt = h(&p["stmt"]);
        assert!(verify(op, &stmt, &h(&p["proof"])), "{what}: verifies");
        let memo = p.get("memo").map(h).unwrap_or_default();
        let (hd, u, v_f) = match st::parse(op, &stmt).unwrap() {
            Stmt::Debit(d) => (d.header, d.u.to_vec(), d.v_f.to_vec()),
            Stmt::Multi(m) => (m.header, m.u(0).to_vec(), m.v_f.to_vec()),
            _ => panic!("{what}"),
        };
        let t = own_tag_of(seed, &hd, &u, &v_f);
        assert_eq!(tag(p), t, "{what}: ownTag");
        assert_eq!(hd[st::H_MEMO_HASH], memo_hash(&memo, &t), "{what}: memoHash = keccak256(memo ‖ ownTag)");
        t
    };
    let to_bob = |mode: &str| json!({"toUA": hx(&BOB), "pkT": wd.pk(&BOB), "pkA": wd.pk(&AUD), "amount": 10, "mode": mode});
    let (hash1, bundle1) = (to_bob("HASH"), to_bob("BUNDLE"));
    let ka = wd.key(&A);
    let p = call(ka, "proveTransfer", &wd.debit(&A, hash1)).unwrap();
    let t1 = check("op 1 HASH", 1, &p, &seed_a);
    assert_eq!(h(&p["memo"]).len(), 16 + 42);
    let p = call(ka, "proveTransfer", &wd.debit(&A, bundle1)).unwrap();
    let t2 = check("op 1 BUNDLE", 1, &p, &seed_a);
    assert_ne!(t1, t2, "a fresh ciphertext, another tag at the same counter");
    for mode in ["HASH", "BUNDLE"] {
        let l = json!([{"pk": wd.pk(&BOB), "ua": hx(&BOB), "amount": 5}, {"pk": wd.pk(&Z), "ua": hx(&Z), "amount": 0}]);
        let p = call(ka, "proveTransferMulti", &wd.debit(&A, json!({"legs": l, "pkA": wd.pk(&AUD), "mode": mode}))).unwrap();
        check(&format!("op 7 {mode}"), 7, &p, &seed_a);
    }
    let p = call(ka, "proveBurn", &wd.debit(&A, json!({"amount": 10, "recipient": hx(&[3; 32])}))).unwrap();
    check("burn", 2, &p, &seed_a);
    let p = call(ka, "proveRefresh", &wd.debit(&A, json!({}))).unwrap();
    check("refresh", 2, &p, &seed_a);
    // the settled blobs carry the facade's tag (`World::pay` feeds it to the model)
    let e = wd.pay(&A, &BOB, 300, true);
    let blob = &wd.c.blobs[&wd.c.entries[&e].ptr];
    let at = blob.len() - 1 - 8 * *blob.last().unwrap() as usize;
    assert_eq!(&blob[at - 32..at], &wd.c.own_tag[..], "the stored tail's ownTag");
    // a stale version: its refresh and its migration carry the stale version's tag
    let a1 = wd._w.pqz_key_version(0, 0, 1).unwrap();
    let seed_a1 = seed_of(&wd._w, 0, 1);
    let ka = wd._w.pqz_key(0, 0).unwrap();
    let mut c = std::mem::take(&mut wd.c);
    c.add_version(A, &a1.pk(), true);
    let r = call(&ka, "proveRefresh", &debit_at(&c, &A, 0, json!({}))).unwrap();
    check("stale refresh", 2, &r, &seed_a);
    let m = call(&ka, "proveTransfer", &debit_at(&c, &A, 0, json!({"toUA": hx(&A), "pkT": hx(&a1.pk()), "amount": 650, "mode": "BUNDLE"}))).unwrap();
    let tm = check("migration", 1, &m, &seed_a);
    let ms = h(&m["stmt"]);
    let Stmt::Debit(d) = st::parse(1, &ms).unwrap() else { panic!() };
    assert_ne!(own_tag_of(&seed_a1, &d.header, d.u, d.v_f), tm, "version 1's seed: another tag at the same message");
}

/// Op 1 per `mode` (no default): HASH answers the memo `salt ‖ sealedMemo` (58 bytes, the statement's salt) with 3h's
/// `memoHash = keccak256(salt ‖ sealedMemo ‖ ownTag)` in the statement, and the sender opens it from the settled entry to its one
/// leg `(amount, toUA)`; BUNDLE has `memoHash = keccak256(ownTag)` and no memo; both verify. A request without `mode`, with another value, or with
/// a `memoHash` field is refused before the key.
#[test]
fn op1_memo_per_mode() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    let base = wd.debit(&A, json!({"toUA": hx(&BOB), "pkT": wd.pk(&BOB), "pkA": wd.pk(&AUD), "amount": 300}));
    let ka = wd.key(&A);
    for bad in [json!(null), json!("hash"), json!("NONE"), json!(0)] {
        refused(&format!("mode {bad}"), ka, "proveTransfer", &merge(base.clone(), json!({"mode": bad})), Error::Argument);
    }
    refused("no mode", ka, "proveTransfer", &base, Error::Argument);
    refused("a free memoHash", ka, "proveTransfer", &merge(base.clone(), json!({"mode": "BUNDLE", "memoHash": hx(&[0; 32])})), Error::Argument);
    let b = call(ka, "proveTransfer", &merge(base.clone(), json!({"mode": "BUNDLE"}))).unwrap();
    let st_b = h(&b["stmt"]);
    let Stmt::Debit(d) = st::parse(1, &st_b).unwrap() else { panic!() };
    assert_eq!((d.header[st::H_MEMO_HASH], b.get("memo")), (memo_hash(&[], &tag(&b)), None), "BUNDLE: keccak256(ownTag), no memo");
    assert!(verify(1, &st_b, &h(&b["proof"])));
    let p = call(ka, "proveTransfer", &merge(base, json!({"mode": "HASH"}))).unwrap();
    let (stmt, memo) = (h(&p["stmt"]), h(&p["memo"]));
    assert!(verify(1, &stmt, &h(&p["proof"])));
    let Stmt::Debit(d) = st::parse(1, &stmt).unwrap() else { panic!() };
    assert_eq!(memo.len(), 16 + 42, "salt ‖ sealedMemo, PqzCore.SEALED = 42");
    assert_eq!(&memo[..16], &d.header[st::H_SALT][16..], "the statement's salt");
    assert_eq!(d.header[st::H_MEMO_HASH], memo_hash(&memo, &tag(&p)), "keccak256(salt ‖ sealedMemo ‖ ownTag)");
    wd.c.own_tag = tag(&p);
    let e = wd.c.settle1(&stmt, Some(&memo));
    let o = call(wd.key(&A), "openMemo", &merge(wd.c.entry(&e, &A), json!({"memo": hx(&memo)}))).unwrap();
    assert_eq!(o, json!({"auditorOn": true, "legs": [{"amount": 300, "ua": hx(&BOB)}]}));
}

/// `PqzCore._parseMulti` on BUNDLE (3h, T20d2; was T15b's `memoHash` 0): no memo (`sealedMemo` empty) and `memoHash =
/// keccak256(ownTag)`; the answer no `memo`, the proof verifies.
#[test]
fn multi_bundle_memo_hash_is_the_tags() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    let (_, p) = wd.pay_multi(&A, &[(BOB, 250)], false, "BUNDLE");
    let stmt = h(&p["stmt"]);
    let Stmt::Multi(m) = st::parse(7, &stmt).unwrap() else { panic!() };
    assert_eq!(m.header[st::H_MEMO_HASH], memo_hash(&[], &tag(&p)), "BUNDLE: keccak256(ownTag)");
    assert_eq!(p.get("memo"), None, "BUNDLE: no memo");
}

/// `PqzCore._parseMulti` on HASH (3h): `memoHash = keccak256(abi.encodePacked(t.salt, t.sealedMemo, t.ownTag))`, `salt` the
/// header's low 16 bytes and `sealedMemo` `2 + 40·M` bytes; the facade's `memo` is `salt ‖ sealedMemo`.
#[test]
fn multi_hash_memo_hash_matches_contract() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    let (_, p) = wd.pay_multi(&A, &[(BOB, 250)], false, "HASH");
    let memo = h(&p["memo"]);
    let stmt = h(&p["stmt"]);
    let Stmt::Multi(m) = st::parse(7, &stmt).unwrap() else { panic!() };
    let salt = &m.header[st::H_SALT][16..];
    assert_eq!((&memo[..16], memo.len() - 16), (salt, 2 + 40), "memo = salt ‖ sealedMemo");
    assert_eq!(m.header[st::H_MEMO_HASH], scaas_ua::keccak256(&[salt, &memo[16..], &tag(&p)[..]].concat()), "keccak256(salt ‖ sealedMemo ‖ ownTag)");
}

/// Burn and refresh carry 3h's `memoHash = keccak256(ownTag)` (the memo empty; `PqzCore.prepareBurn`): no `memoHash` or
/// `mode` field is taken.
#[test]
fn burn_and_refresh_memo_hash_is_the_tags() {
    let wd = {
        let mut w = World::new();
        w.c.shield(&A, 1000);
        w
    };
    let k = wd.key(&A);
    let burn = wd.debit(&A, json!({"amount": 10, "recipient": hx(&[3; 32])}));
    for (cmd, req) in [("proveBurn", burn), ("proveRefresh", wd.debit(&A, json!({})))] {
        for (f, v) in [("memoHash", json!(hx(&[0xD1; 32]))), ("mode", json!("HASH"))] {
            refused(&format!("{cmd} with {f}"), k, cmd, &merge(req.clone(), json!({ f: v })), Error::Argument);
        }
        let p = call(k, cmd, &req).unwrap();
        let s = h(&p["stmt"]);
        let Stmt::Debit(d) = st::parse(2, &s).unwrap() else { panic!() };
        assert_eq!(d.header[st::H_MEMO_HASH], memo_hash(&[], &tag(&p)), "{cmd}: memoHash = keccak256(ownTag)");
        assert!(verify(2, &s, &h(&p["proof"])), "{cmd}");
    }
}

/// T15g (the bindings' PQZ row, through `scaas_ua_pqz_call`'s JSON): the forge keys are mocked, so a forge row's words parse,
/// check and rebuild (`from_json` accepts them) but bind to no wallet key: on a wallet's handle each `balance` is refused with
/// `Argument` before the key; the same words with the other set's `psid`, `PqzSetMismatch`, the key unused.
#[test]
fn forge_rows_on_another_handle_are_refused_before_the_key() {
    unlock();
    let r = rows();
    let other = if st::SET == "n2048-kmax1024" { "n2304-kmax4096/" } else { "" };
    let p = format!("{}/../../smartcontracts/vectors/pqz/{other}state.json", env!("CARGO_MANIFEST_DIR"));
    let other: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    assert_ne!(other["psid"], r["psid"]);
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    let k = w.pqz_key(0, 0).unwrap();
    for a in r["accounts"].as_array().unwrap() {
        let name = a["name"].as_str().unwrap();
        let words = merge(json!({"chainUid": r["chainUid"], "token": r["token"], "psid": r["psid"], "ua": a["ua"], "block": a["block"],
            "account": a["account"], "pending": a["pending"], "accWords": a["accWords"], "blobs": a["blobs"], "keyRecord": a["keyRecord"],
            "forOp7": false}), forge_versions(a));
        assert!(PqzCmd::from_json("balance", words.to_string().as_bytes()).is_ok(), "{name}: the words parse (control)");
        refused(name, &k, "balance", &words, Error::Argument);
        refused(name, &k, "balance", &merge(words, json!({"psid": other["psid"]})), Error::PqzSetMismatch);
    }
}

/// Group 3g (T15o; spec 2026-11-06-pqz-key-versions KV-6 to KV-9, KV-11): Alice rotates to version 1 (`pqz_key_version(0, 0, 1)`)
/// and credits land there; version 0 is stale: it only migrates (op 1 to Alice, `pkT` her version-1 key) or refreshes, every
/// other debit refused before the key; the current version never pays itself (`SelfTransfer`); the keys of a statement are
/// pairwise distinct (`KeyReused`); the migration verifies and settles (version 0 keeps the rest, version 1 the moved amount);
/// the sender finds each leg's version additively: the entry's `u` names the sender's version (another one refused before any
/// leg key and before the prover), then the leg owner's listed versions are tried one by one (`legKey` the match).
#[test]
fn key_versions_stale_rule_migration_and_additive_recovery() {
    let mut wd = World::new();
    wd.c.shield(&A, 1000);
    let e_old = wd.pay(&A, &BOB, 300, false);
    let (ka, kb) = (wd._w.pqz_key(0, 0).unwrap(), wd._w.pqz_key(1, 0).unwrap());
    let (a1, b1) = (wd._w.pqz_key_version(0, 0, 1).unwrap(), wd._w.pqz_key_version(1, 0, 1).unwrap());
    let (pa, pb, pz) = (wd.pk(&A), wd.pk(&BOB), wd.pk(&Z));
    assert_ne!(a1.pk(), ka.pk(), "a new key per version");
    let leg = |pk: &str, ua: &Word, amount: u64| json!({"pk": pk, "ua": hx(ua), "amount": amount});
    let mut c = std::mem::take(&mut wd.c);
    c.add_version(A, &a1.pk(), true);
    let calls = prover_calls();
    for (what, cmd, extra) in [
        ("a stale payment", "proveTransfer", json!({"toUA": hx(&BOB), "pkT": pb, "amount": 1, "mode": "BUNDLE"})),
        ("a stale burn", "proveBurn", json!({"amount": 0, "recipient": hx(&[0; 32])})),
        ("a stale op 7", "proveTransferMulti", json!({"legs": [leg(&pb, &BOB, 1), leg(&pz, &Z, 0)], "mode": "BUNDLE"})),
        ("a migration to the stale key itself", "proveTransfer", json!({"toUA": hx(&A), "pkT": pa, "amount": 1, "mode": "BUNDLE"})),
    ] {
        refused(what, &ka, cmd, &debit_at(&c, &A, 0, extra), Error::Argument);
    }
    assert_eq!(prover_calls(), calls, "refused before the prover");
    let r = call(&ka, "proveRefresh", &debit_at(&c, &A, 0, json!({}))).unwrap();
    assert!(verify(2, &h(&r["stmt"]), &h(&r["proof"])), "a stale version refreshes");
    let m = call(&ka, "proveTransfer", &debit_at(&c, &A, 0, json!({"toUA": hx(&A), "pkT": hx(&a1.pk()), "amount": 650, "mode": "BUNDLE"}))).unwrap();
    let ms = h(&m["stmt"]);
    assert!(verify(1, &ms, &h(&m["proof"])), "the migration verifies");
    c.settle1(&ms, None);
    assert_eq!((bal_at(&c, &ka, &A, 0), bal_at(&c, &a1, &A, 1)), (50, 650), "the migration moved 650 from version 0 to version 1");
    assert_eq!(call(&a1, "balance", &merge(c.own_at(&A, 0, 16), json!({"forOp7": false}))).err(), Some(Error::Argument), "v0's words, v1's key");
    // the current version: no payment to itself, every statement's keys distinct
    for (what, cmd, extra) in [
        ("SelfTransfer at the current version", "proveTransfer", json!({"toUA": hx(&A), "pkT": pb, "amount": 1, "mode": "BUNDLE"})),
        ("pkT the sender's key", "proveTransfer", json!({"toUA": hx(&BOB), "pkT": hx(&a1.pk()), "amount": 1, "mode": "BUNDLE"})),
        ("pkA the receiver's key", "proveTransfer", json!({"toUA": hx(&BOB), "pkT": pb, "pkA": pb, "amount": 1, "mode": "BUNDLE"})),
        ("a leg key twice", "proveTransferMulti", json!({"legs": [leg(&pb, &BOB, 1), leg(&pb, &BOB, 0)], "mode": "BUNDLE"})),
        ("pkA a leg's key", "proveTransferMulti", json!({"legs": [leg(&pb, &BOB, 1), leg(&pz, &Z, 0)], "pkA": pz, "mode": "BUNDLE"})),
    ] {
        refused(what, &a1, cmd, &debit_at(&c, &A, 1, extra), Error::Argument);
    }
    // Bob rotates; Alice (version 1) pays his version 1
    c.add_version(BOB, &b1.pk(), true);
    let p = call(&a1, "proveTransfer", &debit_at(&c, &A, 1, json!({"toUA": hx(&BOB), "pkT": hx(&b1.pk()), "amount": 40, "mode": "BUNDLE"}))).unwrap();
    let ps = h(&p["stmt"]);
    assert!(verify(1, &ps, &h(&p["proof"])));
    let e_new = c.settle1(&ps, None);
    assert_eq!((bal_at(&c, &kb, &BOB, 0), bal_at(&c, &b1, &BOB, 1), bal_at(&c, &a1, &A, 1)), (300, 40, 610));
    // additive sender recovery: the sender's version by `u`, each leg's version on its own
    #[cfg(feature = "vectors")]
    let t0 = sender_trials();
    let got = call(&a1, "proveDiscloseSender", &sender_at(&c, &e_new, 1, &[0, 1])).unwrap();
    assert_eq!((&got["legKey"], &got["amount"]), (&json!(1), &json!(40)), "the new entry: Bob's version 1");
    #[cfg(feature = "vectors")]
    assert_eq!(sender_trials() - t0, 2, "one trial per listed version up to the match");
    assert!(verify(4, &h(&got["stmt"]), &h(&got["proof"])));
    let got = call(&ka, "proveDiscloseSender", &sender_at(&c, &e_old, 0, &[1, 0])).unwrap();
    assert_eq!((&got["legKey"], &got["amount"]), (&json!(1), &json!(300)), "the old entry: Bob's version 0, second in the list");
    let calls = prover_calls();
    // (the key is used: `u` is re-derived from the sender's seed; refused at the first leg key, before the others and the prover:
    // the work is the sum of the version lists, never their product)
    #[cfg(feature = "vectors")]
    let t0 = sender_trials();
    assert_eq!(call(&ka, "proveDiscloseSender", &sender_at(&c, &e_new, 0, &[0, 1])).err(), Some(Error::Argument), "the sender's other version");
    #[cfg(feature = "vectors")]
    assert_eq!(sender_trials() - t0, 1, "the sender's other version stops at the first leg key");
    assert_eq!(call(&ka, "proveDiscloseSender", &sender_at(&c, &e_old, 0, &[1])).err(), Some(Error::Argument), "no listed version is the leg's");
    assert_eq!(prover_calls(), calls, "refused before the prover");
}

/// A debit request of `ua`'s account of version `v`.
fn debit_at(c: &Chain, ua: &Word, v: u64, extra: Value) -> Value {
    merge(merge(c.own_at(ua, v, 16), c.debit_fields()), extra)
}

/// `ua`'s balance of version `v` on handle `k`.
fn bal_at(c: &Chain, k: &PqzKey, ua: &Word, v: u64) -> u64 {
    call(k, "balance", &merge(c.own_at(ua, v, 16), json!({"forOp7": false}))).unwrap()["value"].as_u64().unwrap()
}

/// `proveDiscloseSender` of leg 0 of `er` (Alice to Bob) on Alice's version `av`, Bob's versions `bv` listed.
fn sender_at(c: &Chain, er: &Word, av: u64, bv: &[u64]) -> Value {
    let mut v = c.entry(er, &A);
    v["keyRecord"] = json!(hx(&c.key_record_at(&A, av)));
    let mut ptrs = vec![c.entries[er].ptr, c.keys[&(A, av)]];
    ptrs.extend(bv.iter().map(|x| c.keys[&(BOB, *x)]));
    v["blobs"] = json!(c.blobs_json(&ptrs));
    let recs: Vec<String> = bv.iter().map(|x| hx(&c.key_record_at(&BOB, *x))).collect();
    merge(v, json!({"leg": 0, "registry": hx(&REG), "legKeyRecords": recs}))
}
