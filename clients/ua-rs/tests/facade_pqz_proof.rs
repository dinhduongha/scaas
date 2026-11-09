// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T20d4 (C-PP-2; no-oracle spec §4.14.2–§4.14.4): path (B), `provenOpen`, `provenAdd`, `provenCancel`,
//! `balanceProven`, over the `pqz_chain` model of a release 3h token with the facade's own proofs (verified before each
//! settlement; the model keeps each debit's statement, proof and NONE call fields as a reader finds them in history). The positive
//! control first: the proven value equals path (A)'s `balance` over the same state, for op 1 with and without the auditor, op 7
//! with the auditor, NONE and LOG debits, a debit with `shieldIn`, a relayed binding, after a refresh and a rollover, across a
//! rotation (a migration credit by re-encryption, and by P on a handle whose store holds no older seed). Then each negative
//! refused alone with the key unused and the session kept. UNAUDITED.
mod pqz_chain;

use pqz_chain::*;
use pqz_ffi::stmt::{self as st, Word};
use scaas_ua::facade::pqz::PqzKey;
use scaas_ua::wallet::{Error, Wallet};
use serde_json::{json, Value};

const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const A: Word = [0xA1; 32];
const BOB: Word = [0xB0; 32];
const AUD: Word = [0xAD; 32];
const Z: Word = [0xB1; 32];
const X: Word = [0xB2; 32];
const Y: Word = [0xB3; 32];

fn unlock() {
    #[cfg(feature = "vectors")]
    scaas_ua::facade::vectors_unlock(scaas_ua::facade::TestOnly);
}
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
/// `PqzCore._bindMode`: `keccak256(abi.encode(binding == 0 ? TAG_DIRECT_MODE : binding, uint8(mode)))`, HASH 0, BUNDLE 1.
fn bind(binding: &Word, mode: &str) -> Word {
    let b = if *binding == [0; 32] { scaas_ua::keccak256(b"SCAAS-PQZ-DIRECT-MODE-V1") } else { *binding };
    scaas_ua::keccak256(&[b, st::u64_word((mode == "BUNDLE") as u64)].concat())
}

/// A debit's options: LOG or NONE, the relayed binding (0 direct), `shieldIn`.
#[derive(Clone, Copy)]
struct Opt {
    log: bool,
    binding: Word,
    shield_in: u64,
}
const LOG: Opt = Opt { log: true, binding: [0; 32], shield_in: 0 };
const NONE: Opt = Opt { log: false, binding: [0; 32], shield_in: 0 };

/// Holders of one wallet on a fresh chain with the auditor `AUD`; `extra` more UAs (op 7's legs).
struct World {
    w: Wallet,
    k: Vec<(Word, PqzKey)>,
    c: Chain,
    /// The token's proof system (`psid` of every request).
    psid: Word,
}

impl World {
    fn new(extra: usize) -> World {
        unlock();
        let w = Wallet::from_mnemonic(WORDS, "").unwrap();
        let mut c = Chain::new();
        let uas: Vec<Word> = [A, BOB, AUD, Z, X, Y].into_iter().chain((0..extra).map(|i| [0xE0 + i as u8; 32])).collect();
        let k: Vec<(Word, PqzKey)> = uas.iter().enumerate().map(|(i, ua)| (*ua, w.pqz_key(i as u32, 0).unwrap())).collect();
        for (ua, key) in &k {
            c.register(*ua, &key.pk());
        }
        c.auditor = Some(AUD);
        World { w, k, c, psid: st::PQZL_ID }
    }
    fn key(&self, ua: &Word) -> &PqzKey {
        &self.k.iter().find(|x| x.0 == *ua).unwrap().1
    }
    /// `ua`'s current registered key (the one a payer names, 3g KV-7).
    fn pk(&self, ua: &Word) -> String {
        hx(&self.c.blobs[&self.c.key_ptr(ua)][1..])
    }
    fn balance(&self, ua: &Word) -> u64 {
        call(self.key(ua), "balance", &merge(self.c.bal(ua), json!({"psid": hx(&self.psid)}))).unwrap()["value"].as_u64().unwrap()
    }
    fn open(&self, ua: &Word, v: u64) -> Value {
        merge(self.c.proven_open(ua, v), json!({"psid": hx(&self.psid)}))
    }
    /// A words debit of `ua` at version `v` with `o`'s binding and `shieldIn`; the NONE call fields a reader takes from it.
    fn debit(&self, ua: &Word, v: u64, mode: &str, o: Opt, extra: Value) -> (Value, Value) {
        let mut d = merge(merge(self.c.own_at(ua, v, 16), self.c.debit_fields()), extra);
        d["psid"] = json!(hx(&self.psid));
        d["envelopeBinding"] = json!(hx(&bind(&o.binding, mode)));
        d["shieldIn"] = json!(o.shield_in);
        let call = json!({"fee": 0, "validUntilBlock": d["validUntilBlock"], "mode": mode, "binding": hx(&o.binding)});
        (d, call)
    }
    /// Notes P and settles; `op` 1 or 7.
    fn settle(&mut self, op: u8, p: &Value, mut call: Value, o: Opt, legs: &[Word]) -> Word {
        let (stmt, proof) = (h(&p["stmt"]), h(&p["proof"]));
        assert!(verify(op, &stmt, &proof), "the debit verifies");
        if let Some(m) = p.get("memo") {
            call["sealedMemo"] = json!(hx(&h(m)[16..]));
        }
        self.c.proof_store = o.log as u8;
        self.c.own_tag = h(&p["ownTag"]).try_into().unwrap();
        self.c.note_proof(op, &stmt, &proof, call);
        if op == 7 {
            note_legs(legs);
            self.c.settle7(&stmt, p.get("memo").map(h).as_deref())
        } else {
            self.c.settle1(&stmt, p.get("memo").map(h).as_deref())
        }
    }
    /// Op 1 from `from` (its current version) to `to`.
    fn pay(&mut self, from: &Word, to: &Word, amount: u64, aud: bool, mode: &str, o: Opt) -> Word {
        let v = self.c.cur(from);
        let mut extra = json!({"toUA": hx(to), "pkT": self.pk(to), "amount": amount, "mode": mode});
        if aud {
            extra["pkA"] = json!(self.pk(&AUD));
        }
        let (d, cl) = self.debit(from, v, mode, o, extra);
        let p = call(self.key(from), "proveTransfer", &d).unwrap();
        self.settle(1, &p, cl, o, &[])
    }
    /// Op 7 from `from` to `legs`.
    fn pay_multi(&mut self, from: &Word, legs: &[(Word, u64)], aud: bool, mode: &str, o: Opt) -> Word {
        let l: Vec<Value> = legs.iter().map(|(ua, a)| json!({"pk": self.pk(ua), "ua": hx(ua), "amount": a})).collect();
        let mut extra = json!({"legs": l, "mode": mode});
        if aud {
            extra["pkA"] = json!(self.pk(&AUD));
        }
        let (d, cl) = self.debit(from, self.c.cur(from), mode, o, extra);
        let p = call(self.key(from), "proveTransferMulti", &d).unwrap();
        self.settle(7, &p, cl, o, &legs.iter().map(|l| l.0).collect::<Vec<_>>())
    }
    /// A refresh of `ua` at version `v` on handle `k` (its own debit: a fresh `v_f` with its tag).
    fn refresh(&mut self, k: &PqzKey, ua: &Word, v: u64, o: Opt) {
        let (d, _) = self.debit(ua, v, "BUNDLE", o, json!({}));
        let p = call(k, "proveRefresh", &d).unwrap();
        let (stmt, proof) = (h(&p["stmt"]), h(&p["proof"]));
        assert!(verify(2, &stmt, &proof));
        self.c.proof_store = o.log as u8;
        self.c.own_tag = h(&p["ownTag"]).try_into().unwrap();
        self.c.note_proof(2, &stmt, &proof, json!({}));
        self.c.settle_burn(&stmt);
    }
    /// Every credit of `(ua, v)`'s window.
    fn credits(&self, ua: &Word, v: u64, need: &Value) -> Vec<Cred> {
        need.as_array().unwrap().iter().map(|i| self.c.proven_credit(ua, v, i.as_u64().unwrap())).collect()
    }
    /// Path (B) end to end on handle `k`: open, every credit in one batch (all accepted), the proven balance.
    fn proven(&self, k: &PqzKey, ua: &Word, v: u64) -> Value {
        let o = call(k, "provenOpen", &self.open(ua, v)).unwrap();
        let cs = self.credits(ua, v, &o["need"]);
        let r = call(k, "provenAdd", &self.c.add_request(&o["session"], &cs)).unwrap();
        assert_eq!(r, json!({"accepted": o["need"], "refused": []}), "every credit accepted");
        call(k, "balanceProven", &json!({"session": o["session"]})).unwrap()
    }
}

/// A `provenAdd` credit and the blob addresses it names.
type Cred = (Value, Vec<[u8; 20]>);

/// `parts`' kinds, in order.
fn kinds(b: &Value) -> Vec<String> {
    b["parts"].as_array().unwrap().iter().map(|p| p["kind"].as_str().unwrap().to_string()).collect()
}

/// The positive control (no-oracle spec §5, plan T20d4): path (B)'s value equals path (A)'s over the same state for op 1 with
/// and without the auditor (NONE direct, LOG with `shieldIn`, NONE relayed), op 7 with the auditor (LOG), a TRIVIAL entry; then
/// after the holder's own refresh (its `v_f` by its tag) and a rollover (a materialised `acc`, summed from the parts instead); the
/// source's key word for the holder's own leg is never taken (a wrong one given, the credit still passes).
#[test]
fn balance_proven_equals_path_a() {
    let mut wd = World::new(0);
    for (ua, v) in [(A, 1000), (X, 200), (Z, 300)] {
        wd.c.shield(&ua, v);
    }
    wd.pay(&A, &BOB, 300, true, "BUNDLE", NONE);
    wd.pay(&X, &BOB, 50, false, "HASH", Opt { shield_in: 5, ..LOG });
    wd.pay_multi(&Z, &[(BOB, 20), (Y, 5)], true, "BUNDLE", LOG);
    wd.c.shield(&BOB, 7);
    wd.pay(&A, &BOB, 4, true, "HASH", Opt { binding: [0xB7; 32], ..NONE });
    let kb = wd.key(&BOB);
    assert_eq!(wd.balance(&BOB), 381);
    let o = call(kb, "provenOpen", &wd.c.proven_open(&BOB, 0)).unwrap();
    assert_eq!((&o["p"], &o["sendCounter"], o["need"].as_array().unwrap().len()), (&json!(5), &json!(0), 4));
    let mut cs = wd.credits(&BOB, 0, &o["need"]);
    // a source's key record for the holder's own leg (another key): never read
    cs[0].0["keyRecords"].as_array_mut().unwrap().push(json!({"ua": hx(&BOB), "version": 0, "word": hx(&wd.c.key_record(&Y))}));
    cs[0].1.push(wd.c.key_ptr(&Y));
    let r = call(kb, "provenAdd", &wd.c.add_request(&o["session"], &cs)).unwrap();
    assert_eq!(r, json!({"accepted": o["need"], "refused": []}));
    let before = key_uses();
    let b = call(kb, "balanceProven", &json!({"session": o["session"]})).unwrap();
    assert_eq!(key_uses() - before, if cfg!(feature = "vectors") { 1 } else { 0 }, "the key once, at the end");
    assert_eq!((&b["value"], &b["p"], &b["sendCounter"]), (&json!(381), &json!(5), &json!(0)), "path (A)'s value");
    assert_eq!(kinds(&b), ["trivial", "credit", "credit", "credit", "credit"]);
    assert_eq!(call(kb, "balanceProven", &json!({"session": o["session"]})).err(), Some(Error::Argument), "the session closed");
    // the holder's own debit: its `v_f` by its tag; a credit after it, rolled over (path (B) sums the parts, never `acc`)
    let kb = wd.w.pqz_key(1, 0).unwrap();
    wd.refresh(&kb, &BOB, 0, LOG);
    wd.pay(&A, &BOB, 10, false, "BUNDLE", NONE);
    // X's predecessor a refresh (a burn-form blob, `u′` at 0)
    let kx = wd.w.pqz_key(4, 0).unwrap();
    wd.refresh(&kx, &X, 0, NONE);
    wd.pay(&X, &BOB, 1, true, "BUNDLE", LOG);
    wd.c.roll(&BOB, 1);
    assert_eq!(wd.balance(&BOB), 392);
    let b = wd.proven(&kb, &BOB, 0);
    assert_eq!((&b["value"], kinds(&b)), (&json!(392), vec!["own".to_string(), "credit".into(), "credit".into()]));
}

/// A PQZH token (when this set has PQZH): the credits' P are PQZH proofs, the same rules.
#[test]
fn pqzh_token() {
    if !pqz_ffi::PQZH {
        return;
    }
    let mut wd = World::new(0);
    wd.psid = st::PQZH_ID;
    wd.c.shield(&A, 1000);
    wd.pay(&A, &BOB, 300, true, "BUNDLE", LOG);
    wd.pay(&A, &BOB, 30, false, "HASH", NONE);
    let b = wd.proven(wd.key(&BOB), &BOB, 0);
    assert_eq!((&b["value"], b["value"].as_u64()), (&json!(330), Some(wd.balance(&BOB))));
}

/// Group 3g across path (B): Bob rotates to version 1; version 0 migrates to it. On a derived handle the migration credit is
/// checked by re-encryption from version 0's seed (the store derives it), a credit to version 1 by its P; the stale version's
/// own `v_f` by its tag. On a handle whose store holds no older seed (feature `vectors`: a key from its seed alone) the
/// migration credit is checked by its P (owner ruling 2026-11-09, no-oracle spec §7 item 12).
#[test]
fn rotation_migration_by_reencryption_or_p() {
    let mut wd = World::new(0);
    wd.c.shield(&A, 1000);
    wd.pay(&A, &BOB, 300, false, "BUNDLE", LOG);
    let (b0, b1) = (wd.w.pqz_key(1, 0).unwrap(), wd.w.pqz_key_version(1, 0, 1).unwrap());
    wd.c.add_version(BOB, &b1.pk(), true);
    let (d, cl) = wd.debit(&BOB, 0, "BUNDLE", NONE, json!({"toUA": hx(&BOB), "pkT": hx(&b1.pk()), "amount": 260, "mode": "BUNDLE"}));
    let m = call(&b0, "proveTransfer", &d).unwrap();
    wd.settle(1, &m, cl, NONE, &[]);
    // the auditor at version 1 (the credit's `kv` names it)
    let a1 = wd.w.pqz_key_version(2, 0, 1).unwrap();
    wd.c.add_version(AUD, &a1.pk(), true);
    wd.pay(&A, &BOB, 40, true, "HASH", LOG);
    // a credit wrongly given as a migration (the payment from A, labelled as Bob's own debit 0): its re-encryption fails
    let o = call(&b1, "provenOpen", &wd.open(&BOB, 1)).unwrap();
    let cs = wd.credits(&BOB, 1, &o["need"]);
    let mut wrong = cs[1].clone();
    for f in ["fromUA", "sendCounter", "record"] {
        wrong.0[f] = cs[0].0[f].clone();
    }
    let r = call(&b1, "provenAdd", &wd.c.add_request(&o["session"], &[wrong])).unwrap();
    assert_eq!(r, json!({"accepted": [], "refused": [o["need"][1]]}), "not a migration");
    let b = wd.proven(&b1, &BOB, 1);
    assert_eq!((&b["value"], kinds(&b)), (&json!(300), vec!["migration".to_string(), "credit".into()]));
    let b = wd.proven(&b0, &BOB, 0);
    assert_eq!((&b["value"], kinds(&b)), (&json!(40), vec!["own".to_string()]), "version 0 keeps the rest: its own v_f");
    #[cfg(feature = "vectors")]
    {
        let seed = *wd.w.export_pqz_leaf_raw_version(1, 0, 1, scaas_ua::facade::pqz::AllowSecretExport).unwrap();
        let alone = PqzKey::vectors_from_seed32(&seed).unwrap();
        let b = wd.proven(&alone, &BOB, 1);
        assert_eq!((&b["value"], kinds(&b)), (&json!(300), vec!["migration".to_string(), "credit".into()]), "the migration by its P");
        // without P's fields that credit is a malformed request there (it needs its P)
        let o = call(&alone, "provenOpen", &wd.open(&BOB, 1)).unwrap();
        let mut cs = wd.credits(&BOB, 1, &o["need"]);
        cs[0].0.as_object_mut().unwrap().remove("proof");
        assert_eq!(call(&alone, "provenAdd", &wd.c.add_request(&o["session"], &cs)).err(), Some(Error::Argument));
    }
}

/// A credit refused on its own (owner ruling 2026-11-09, no-oracle spec §7 item 11): `refused` names it, the key unused, the
/// session kept; the true credit is then accepted and the value is path (A)'s. One negative of the proof-path spec §11.4 per
/// call: a key of another version at a leg or at the auditor, two legs' keys swapped, the record's `shieldIn`, predecessor, `Δp`
/// and mode, the sender's window of another version, P of another debit, a forged window word, an index outside `need` and one
/// sent twice.
#[test]
fn credit_negatives_refused_alone() {
    let mut wd = World::new(0);
    for (ua, v) in [(A, 1000), (Z, 300)] {
        wd.c.shield(&ua, v);
    }
    // X: version 1 with a window of its own (the version boundary)
    wd.c.shield(&X, 100);
    let x1 = wd.w.pqz_key_version(4, 0, 1).unwrap();
    wd.c.add_version(X, &x1.pk(), true);
    wd.c.shield(&X, 60);
    // Y and the auditor: a pending version 1 each (a key of another version)
    let (y1, a1) = (wd.w.pqz_key_version(5, 0, 1).unwrap(), wd.w.pqz_key_version(2, 0, 1).unwrap());
    wd.c.add_version(Y, &y1.pk(), false);
    wd.c.add_version(AUD, &a1.pk(), false);
    wd.pay(&A, &BOB, 300, true, "BUNDLE", LOG);
    wd.pay_multi(&Z, &[(BOB, 20), (Y, 5)], true, "BUNDLE", LOG);
    let (d, cl) = wd.debit(&X, 1, "BUNDLE", LOG, json!({"toUA": hx(&BOB), "pkT": wd.pk(&BOB), "amount": 30, "mode": "BUNDLE"}));
    let p = call(&x1, "proveTransfer", &d).unwrap();
    wd.settle(1, &p, cl, LOG, &[]);
    let kb = wd.key(&BOB);
    let o = call(kb, "provenOpen", &wd.c.proven_open(&BOB, 0)).unwrap();
    let cs = wd.credits(&BOB, 0, &o["need"]);
    let (op1, op7, xv1) = (cs[0].clone(), cs[1].clone(), cs[2].clone());
    let set = |c: &Cred, f: &dyn Fn(&mut Value)| {
        let mut c = c.clone();
        f(&mut c.0);
        c
    };
    let word = |w: &Word, f: &dyn Fn(&mut [u8; 32])| {
        let mut x = *w;
        f(&mut x);
        hx(&x)
    };
    let w0 = |c: &Cred| -> Word { h(&c.0["record"]["w0"]).try_into().unwrap() };
    let aud_rec = |c: &mut Value, ua: &Word, v: u64, word: Word| {
        for k in c["keyRecords"].as_array_mut().unwrap() {
            if k["ua"] == hx(ua) && k["version"] == v {
                k["word"] = json!(hx(&word));
            }
        }
    };
    let other_blob = wd.c.key_ptr(&Z);
    let cases: Vec<(&str, Cred)> = vec![
        ("the auditor's key of another version", {
            let mut c = set(&op1, &|c| aud_rec(c, &AUD, 0, wd.c.key_record_at(&AUD, 1)));
            c.1.push(wd.c.keys[&(AUD, 1)]);
            c
        }),
        ("a leg's key of another version", {
            let mut c = set(&op7, &|c| aud_rec(c, &Y, 0, wd.c.key_record_at(&Y, 1)));
            c.1.push(wd.c.keys[&(Y, 1)]);
            c
        }),
        ("two keys swapped", set(&op7, &|c| {
            aud_rec(c, &Y, 0, wd.c.key_record_at(&AUD, 0));
            aud_rec(c, &AUD, 0, wd.c.key_record_at(&Y, 0));
        })),
        ("the record's shieldIn", set(&op1, &|c| {
            c["record"]["w0"] = json!(word(&w0(&op1), &|w| w[31] |= 2));
            let mut w1 = [0u8; 32];
            w1[7] = 1;
            c["record"]["w1"] = json!(hx(&w1));
        })),
        ("the record's predecessor", {
            let mut c = set(&op1, &|c| c["record"]["w0"] = json!(word(&w0(&op1), &|w| w[..20].copy_from_slice(&other_blob))));
            c.1.push(other_blob);
            c
        }),
        ("the record's Δp", set(&op1, &|c| {
            c["record"]["w0"] = json!(word(&w0(&op1), &|w| w[29] -= 1));
            c["senderPending"].as_array_mut().unwrap().remove(0);
        })),
        ("the record's mode", set(&op1, &|c| c["record"]["w0"] = json!(word(&w0(&op1), &|w| w[30] ^= 1)))),
        ("the window of another version", set(&xv1, &|c| {
            c["senderPending"][0]["word"] = json!(hx(&wd.c.accts[&(X, 0)].pending[&0]));
        })),
        ("a forged window word", set(&op1, &|c| {
            let mut e = h(&c["senderPending"][0]["word"]);
            e[19] ^= 1;
            c["senderPending"][0]["word"] = json!(hx(&e));
        })),
        ("P of another debit", set(&op1, &|c| c["proof"] = op7.0["proof"].clone())),
        ("an index outside need", set(&op1, &|c| c["index"] = json!(99))),
    ];
    for (what, c) in &cases {
        let before = key_uses();
        let r = call(kb, "provenAdd", &wd.c.add_request(&o["session"], std::slice::from_ref(c))).unwrap();
        assert_eq!(r, json!({"accepted": [], "refused": [c.0["index"]]}), "{what}");
        assert_eq!(key_uses(), before, "{what}: the key unused");
    }
    // the session is kept: the true credits pass, one sent twice is refused the second time
    let r = call(kb, "provenAdd", &wd.c.add_request(&o["session"], &[op1.clone(), op7, op1.clone()])).unwrap();
    assert_eq!(r, json!({"accepted": [o["need"][0], o["need"][1]], "refused": [o["need"][0]]}));
    let r = call(kb, "provenAdd", &wd.c.add_request(&o["session"], &[xv1])).unwrap();
    assert_eq!(r["refused"], json!([]));
    let b = call(kb, "balanceProven", &json!({"session": o["session"]})).unwrap();
    assert_eq!(b["value"].as_u64(), Some(wd.balance(&BOB)));
}

/// The pairing the relation defines (Fable P2-3): Bob is leg 5 of an op 7 of 8 legs without the auditor (`G = 2`, his `v` paired
/// with `u_1`); a slot word whose `uOff` names `u_0` (a source's) makes the credit refused, the true slot's passes.
#[test]
fn op7_leg_paired_with_its_own_group() {
    let mut wd = World::new(8);
    wd.c.shield(&Z, 500);
    let mut legs: Vec<(Word, u64)> = (0..8).map(|i| ([0xE0 + i as u8; 32], 1)).collect();
    legs[5] = (BOB, 9);
    wd.pay_multi(&Z, &legs, false, "BUNDLE", LOG);
    let kb = wd.key(&BOB);
    let mut open = wd.c.proven_open(&BOB, 0);
    let mut slot = h(&open["pending"][0]["word"]);
    assert_eq!(u16::from_be_bytes([slot[20], slot[21]]) as usize, 16 + scaas_ua::facade::pqz_pack::PKP, "u_1");
    slot[20..22].copy_from_slice(&16u16.to_be_bytes());
    open["pending"][0]["word"] = json!(hx(&slot));
    let o = call(kb, "provenOpen", &open).unwrap();
    let cs = wd.credits(&BOB, 0, &o["need"]);
    let before = key_uses();
    assert_eq!(call(kb, "provenAdd", &wd.c.add_request(&o["session"], &cs)).unwrap()["refused"], json!([0]), "v_5 with u_0");
    assert_eq!(call(kb, "balanceProven", &json!({"session": o["session"]})).err(), Some(Error::Argument));
    assert_eq!(key_uses(), before, "the key unused");
    let b = wd.proven(kb, &BOB, 0);
    assert_eq!(b["value"], 9);
}

/// `need` is the slot range `provenOpen` fixed (Fable re-check P3-C): with an index never accepted, `balanceProven` refuses with
/// the key unused, for good; the own `v_f` with a forged tag is refused at the open; more parts than `K_MAX` allows are
/// refused before any check; the session's rules (another id, a second open replaces the first, a cancel, a locked wallet).
#[test]
fn session_rules_and_open_negatives() {
    let mut wd = World::new(0);
    wd.c.shield(&A, 1000);
    wd.pay(&A, &BOB, 300, false, "BUNDLE", LOG);
    wd.pay(&A, &BOB, 20, true, "BUNDLE", LOG);
    let kb = wd.w.pqz_key(1, 0).unwrap();
    let o = call(&kb, "provenOpen", &wd.c.proven_open(&BOB, 0)).unwrap();
    let cs = wd.credits(&BOB, 0, &o["need"]);
    assert_eq!(call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &cs[..1])).unwrap()["accepted"], json!([o["need"][0]]));
    let before = key_uses();
    for _ in 0..2 {
        assert_eq!(call(&kb, "balanceProven", &json!({"session": o["session"]})).err(), Some(Error::Argument), "one need index missing");
    }
    assert_eq!(key_uses(), before, "the key unused");
    // another id; a second open replaces the first
    assert_eq!(call(&kb, "provenAdd", &wd.c.add_request(&json!(hx(&[9; 16])), &cs[1..])).err(), Some(Error::Argument));
    let o2 = call(&kb, "provenOpen", &wd.c.proven_open(&BOB, 0)).unwrap();
    assert_ne!(o2["session"], o["session"]);
    assert_eq!(call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &cs[1..])).err(), Some(Error::Argument), "the old session");
    assert_eq!(call(&kb, "provenCancel", &json!({"session": o2["session"]})).unwrap(), json!({}));
    assert_eq!(call(&kb, "balanceProven", &json!({"session": o2["session"]})).err(), Some(Error::Argument), "cancelled");
    // the own v_f: a forged tag refused at the open
    wd.refresh(&kb, &BOB, 0, LOG);
    let ok = wd.c.proven_open(&BOB, 0);
    assert!(call(&kb, "provenOpen", &ok).is_ok(), "positive control");
    let acc = wd.c.accts[&(BOB, 0)].acc_blob;
    let mut code = wd.c.blobs[&acc].clone();
    let n = code.len() - 1 - 32 - 8 * *code.last().unwrap() as usize;
    code[n] ^= 1;
    let mut forged = ok.clone();
    for b in forged["blobs"].as_array_mut().unwrap() {
        if b["address"] == hx(&acc) {
            b["code"] = json!(hx(&code));
        }
    }
    let before = key_uses();
    assert_eq!(call(&kb, "provenOpen", &forged).err(), Some(Error::Argument), "a forged ownTag");
    assert_eq!(key_uses(), before);
    // the parts' bound at its edge (no debit: `p` entries and `Trivial(shieldIn)`, at most `K_MAX` units): `p = K_MAX − 1` opens,
    // `K_MAX` is refused (forged account words of TRIVIAL entries)
    let mut c = Chain::new();
    c.register(Y, &wd.key(&Y).pk());
    c.auditor = Some(AUD);
    for i in 0..st::K_MAX as u64 {
        c.shield(&Y, i % 3);
    }
    let edge = |count: u64| {
        let mut v = c.proven_open(&Y, 0);
        let mut s0 = h(&v["account"][0]);
        s0[16..24].copy_from_slice(&(st::K_MAX as u64 - 2).to_be_bytes()); // rolled (the model's `slots`: cleared, floor, rolled, count)
        s0[24..32].copy_from_slice(&count.to_be_bytes()); // pendingCount
        v["account"][0] = json!(hx(&s0));
        v["pending"] = json!((0..count).map(|i| json!({"index": i, "word": hx(&c.accts[&(Y, 0)].pending[&i])})).collect::<Vec<_>>());
        v
    };
    assert!(call(wd.key(&Y), "provenOpen", &edge(st::K_MAX as u64 - 1)).is_ok(), "K_MAX units");
    assert_eq!(call(wd.key(&Y), "provenOpen", &edge(st::K_MAX as u64)).err(), Some(Error::Argument), "one part more");
    // a locked wallet drops the session
    let o3 = call(&kb, "provenOpen", &ok).unwrap();
    wd.w.lock();
    assert_eq!(call(&kb, "balanceProven", &json!({"session": o3["session"]})).err(), Some(Error::KeyRevoked));
}

// ---------------------------------------------------------------------------------------------------------------------------
// T20d5 (C-PP-3): the proof-path debit commands.
// ---------------------------------------------------------------------------------------------------------------------------

/// The `T` and header words of a debit statement (op 1, 2 or 7): `(T, p, sendCounter, plainUsed)`.
fn t_of(op: u8, stmt: &[u8]) -> (Vec<u8>, Word, Word, Word) {
    let (t, hd) = match st::parse(op, stmt).unwrap() {
        st::Stmt::Debit(d) => (d.t.to_vec(), d.header),
        st::Stmt::Multi(m) => (m.t.to_vec(), m.header),
        _ => panic!(),
    };
    (t, hd[st::H_P], hd[st::H_SEND_COUNTER], hd[st::H_PLAIN_USED])
}

/// Each `prove*Proven` over the session's checked parts: its statement's `T`, `p`, `sendCounter` are path (A)'s over the same
/// state (a materialised `acc`, a TRIVIAL entry, NONE and LOG credits, `shieldIn`), it verifies, answers `ownTag` and closes the
/// session; a refresh by path (B) settles and both paths read the same balance after it.
#[test]
fn proven_debits_equal_path_a() {
    let mut wd = World::new(0);
    for (ua, v) in [(A, 1000), (X, 200), (Z, 300)] {
        wd.c.shield(&ua, v);
    }
    wd.pay(&A, &BOB, 300, true, "BUNDLE", NONE);
    wd.c.shield(&BOB, 7);
    wd.pay(&X, &BOB, 50, false, "HASH", LOG);
    wd.pay_multi(&Z, &[(BOB, 20), (Y, 5)], true, "BUNDLE", LOG);
    wd.c.roll(&BOB, 2);
    let kb = wd.w.pqz_key(1, 0).unwrap();
    let legs = json!([{"pk": wd.pk(&Y), "ua": hx(&Y), "amount": 3}, {"pk": wd.pk(&Z), "ua": hx(&Z), "amount": 2}]);
    for (b_cmd, a_cmd, op, extra) in [
        ("proveTransferProven", "proveTransfer", 1, json!({"toUA": hx(&Y), "pkT": wd.pk(&Y), "pkA": wd.pk(&AUD), "amount": 30, "mode": "HASH", "shieldIn": 5})),
        ("proveTransferMultiProven", "proveTransferMulti", 7, json!({"legs": legs, "pkA": wd.pk(&AUD), "mode": "BUNDLE"})),
        ("proveBurnProven", "proveBurn", 2, json!({"amount": 10, "recipient": hx(&[3; 32])})),
        ("proveRefreshProven", "proveRefresh", 2, json!({})),
    ] {
        let mut open = wd.open(&BOB, 0);
        open["forOp7"] = json!(op == 7);
        let o = call(&kb, "provenOpen", &open).unwrap();
        let cs = wd.credits(&BOB, 0, &o["need"]);
        call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &cs)).unwrap();
        let fields = merge(wd.c.debit_fields(), extra.clone());
        let pb = call(&kb, b_cmd, &merge(fields.clone(), json!({"session": o["session"]}))).unwrap();
        let pa = call(&kb, a_cmd, &merge(merge(wd.c.own(&BOB, 16), fields), json!({}))).unwrap();
        let (sb, sa) = (h(&pb["stmt"]), h(&pa["stmt"]));
        assert!(verify(op, &sb, &h(&pb["proof"])), "{b_cmd} verifies");
        assert_eq!(t_of(op, &sb), t_of(op, &sa), "{b_cmd}: path (A)'s T, p, sendCounter and plainUsed");
        assert_eq!((pb["p"].clone(), pb["ownTag"].as_str().map(str::len)), (pa["p"].clone(), Some(66)), "{b_cmd}: p, ownTag");
        assert_eq!(call(&kb, b_cmd, &merge(merge(wd.c.debit_fields(), extra), json!({"session": o["session"]}))).err(),
            Some(Error::Argument), "{b_cmd}: the session closed");
    }
    // a refresh by path (B) settles; both paths read the balance after it
    let o = call(&kb, "provenOpen", &wd.open(&BOB, 0)).unwrap();
    call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &wd.credits(&BOB, 0, &o["need"]))).unwrap();
    let p = call(&kb, "proveRefreshProven", &merge(wd.c.debit_fields(), json!({"session": o["session"]}))).unwrap();
    wd.c.own_tag = h(&p["ownTag"]).try_into().unwrap();
    wd.c.settle_burn(&h(&p["stmt"]));
    assert_eq!(wd.balance(&BOB), 377);
    assert_eq!(wd.proven(&kb, &BOB, 0)["value"], 377);
    // the own v_f in the materialised acc: a credit after the refresh, rolled over; a proven refresh's cross-check holds
    wd.pay(&A, &BOB, 3, false, "BUNDLE", LOG);
    wd.c.roll(&BOB, 1);
    let o = call(&kb, "provenOpen", &wd.open(&BOB, 0)).unwrap();
    call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &wd.credits(&BOB, 0, &o["need"]))).unwrap();
    let p = call(&kb, "proveRefreshProven", &merge(wd.c.debit_fields(), json!({"session": o["session"]}))).unwrap();
    let pa = call(&kb, "proveRefresh", &merge(wd.c.own(&BOB, 16), wd.c.debit_fields())).unwrap();
    assert_eq!(t_of(2, &h(&p["stmt"])), t_of(2, &h(&pa["stmt"])), "own v_f and a rolled credit: path (A)'s T");
}

/// The debit's own refusals, each before the key: a `need` index not accepted, `forOp7` not the debit's, another `chainId`,
/// a materialised `acc` that is not the parts below `rolled` (its words and `accHash` forged together), `rolled` past `p_last`
/// without one; group 3g: a stale version's burn, op 7 and payment to another UA refused, its migration and refresh proven.
#[test]
fn proven_debit_negatives() {
    let mut wd = World::new(0);
    wd.c.shield(&A, 1000);
    wd.pay(&A, &BOB, 300, false, "BUNDLE", LOG);
    wd.pay(&A, &BOB, 20, true, "BUNDLE", LOG);
    let kb = wd.w.pqz_key(1, 0).unwrap();
    let burn = json!({"amount": 1, "recipient": hx(&[3; 32])});
    let df = wd.c.debit_fields();
    let fields = |x: &Value, s: &Value| merge(merge(df.clone(), x.clone()), json!({"session": s}));
    let refused = |what: &str, cmd: &str, req: &Value| {
        let before = key_uses();
        assert_eq!(call(&kb, cmd, req).err(), Some(Error::Argument), "{what}");
        assert_eq!(key_uses(), before, "{what}: the key unused");
    };
    let o = call(&kb, "provenOpen", &wd.open(&BOB, 0)).unwrap();
    refused("a need index not accepted", "proveBurnProven", &fields(&burn, &o["session"]));
    let cs = wd.credits(&BOB, 0, &o["need"]);
    call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &cs)).unwrap();
    let legs = json!({"legs": [{"pk": wd.pk(&Y), "ua": hx(&Y), "amount": 1}], "mode": "BUNDLE"});
    refused("forOp7 not the debit's", "proveTransferMultiProven", &fields(&legs, &o["session"]));
    refused("another chainId", "proveBurnProven", &merge(fields(&burn, &o["session"]), json!({"chainId": 1})));
    assert!(call(&kb, "proveBurnProven", &fields(&burn, &o["session"])).is_ok(), "positive control");
    // `rolled` past `p_last` without a materialised `acc`: viewing reads it, a debit refuses
    let mut open = wd.open(&BOB, 0);
    let mut s0 = h(&open["account"][0]);
    s0[16..24].copy_from_slice(&1u64.to_be_bytes());
    open["account"][0] = json!(hx(&s0));
    let o = call(&kb, "provenOpen", &open).unwrap();
    call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &wd.credits(&BOB, 0, &o["need"]))).unwrap();
    refused("rolled past p_last without acc", "proveBurnProven", &fields(&burn, &o["session"]));
    // a materialised `acc` with its words and `accHash` forged together
    wd.c.roll(&BOB, 1);
    let mut open = wd.open(&BOB, 0);
    let mut stream: Vec<u8> = open["accWords"].as_array().unwrap().iter().flat_map(|w| h(w).into_iter().map(|b| !b)).collect();
    stream.truncate(scaas_ua::facade::pqz_pack::CTP);
    stream[scaas_ua::facade::pqz_pack::PKP + 3] ^= 1;
    let mut words = stream.clone();
    words.resize(scaas_ua::facade::pqz_pack::ACC_WORDS * 32, 0);
    open["accWords"] = json!(words.chunks(32).map(|w| hx(&w.iter().map(|b| !b).collect::<Vec<_>>())).collect::<Vec<_>>());
    open["account"][3] = json!(hx(&scaas_ua::keccak256(&stream)));
    let o = call(&kb, "provenOpen", &open).unwrap();
    call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &wd.credits(&BOB, 0, &o["need"]))).unwrap();
    refused("acc not the parts below rolled", "proveRefreshProven", &fields(&json!({}), &o["session"]));
    // group 3g: version 0 stale after a rotation
    let b1 = wd.w.pqz_key_version(1, 0, 1).unwrap();
    wd.c.add_version(BOB, &b1.pk(), true);
    for (what, cmd, x) in [
        ("a stale burn", "proveBurnProven", burn.clone()),
        ("a stale op 7", "proveTransferMultiProven", legs.clone()),
        ("a stale payment to another UA", "proveTransferProven", json!({"toUA": hx(&Y), "pkT": wd.pk(&Y), "amount": 1, "mode": "BUNDLE"})),
    ] {
        let mut open = wd.open(&BOB, 0);
        open["forOp7"] = json!(cmd == "proveTransferMultiProven");
        let o = call(&kb, "provenOpen", &open).unwrap();
        call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &wd.credits(&BOB, 0, &o["need"]))).unwrap();
        refused(what, cmd, &fields(&x, &o["session"]));
    }
    let o = call(&kb, "provenOpen", &wd.open(&BOB, 0)).unwrap();
    call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &wd.credits(&BOB, 0, &o["need"]))).unwrap();
    let m = call(&kb, "proveTransferProven", &fields(&json!({"toUA": hx(&BOB), "pkT": hx(&b1.pk()), "amount": 5, "mode": "BUNDLE"}), &o["session"]))
        .unwrap();
    assert!(verify(1, &h(&m["stmt"]), &h(&m["proof"])), "the stale version's migration is proven");
    let o = call(&kb, "provenOpen", &wd.open(&BOB, 0)).unwrap();
    call(&kb, "provenAdd", &wd.c.add_request(&o["session"], &wd.credits(&BOB, 0, &o["need"]))).unwrap();
    let r = call(&kb, "proveRefreshProven", &fields(&json!({}), &o["session"])).unwrap();
    assert!(verify(2, &h(&r["stmt"]), &h(&r["proof"])), "and its refresh");
}
