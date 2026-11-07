// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T15e: a PQZ token's storage as the contract writes it (`PqzCore` on `ua-mtx-merge`: `_credit`, `_trivial`,
//! `_settleTransfer`, `_bundleMulti`, `_settleBurn`, `_debit`, `rollOver`; the stored form P46), and a reading layer that reads
//! the raw words a words command takes. Group 3g (T15o): accounts per `(ua, key version)`, `sendCounter` per UA, the registry's
//! records per version and `(latest, current)` per UA; credits go to `current`, a debit settles the version whose key is the
//! statement's `pk_f` (the contract selects it by `keyVersion` and checks that key). The test's own code, not the facade's: the packer here, the facade's unpacker and
//! rebuild there; the forge rows (`state.json`) tie both to the contract. Proofs come from the facade and verify with pqz-ffi's
//! precompile before a settlement. UNAUDITED.
#![allow(dead_code)]
use pqz_ffi::stmt::{self as st, Word, K_MAX, PK_BYTES, Q};
use scaas_ua::facade::pqz_pack::{unpack, ACC_WORDS, B, CTP, PKP, VP};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const CHAIN_ID: u64 = 7622;
pub const UID: Word = [0xC1; 32];
pub const TOKEN: [u8; 20] = [0x11; 20];
pub const REG: [u8; 20] = [0x22; 20];

pub fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}
pub fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
pub fn merge(mut a: Value, b: Value) -> Value {
    for (k, v) in b.as_object().unwrap() {
        a[k] = v.clone();
    }
    a
}

/// The stored form of 64-bit lanes (`PqzCt.packMem`): each coefficient's `B` bits, big-endian, in order.
pub fn pack(lanes: &[u8]) -> Vec<u8> {
    let (mut out, mut acc, mut held) = (Vec::new(), 0u128, 0usize);
    for c in lanes.chunks_exact(8) {
        acc = acc << B | u128::from(u64::from_be_bytes(c.try_into().unwrap()));
        held += B;
        while held >= 8 {
            held -= 8;
            out.push((acc >> held) as u8);
            acc &= (1 << held) - 1;
        }
    }
    assert_eq!(held, 0);
    out
}

fn lanes(b: &[u8]) -> Vec<u64> {
    b.chunks_exact(8).map(|c| u64::from_be_bytes(c.try_into().unwrap())).collect()
}
fn bytes(c: &[u64]) -> Vec<u8> {
    c.iter().flat_map(|x| (x % Q).to_be_bytes()).collect()
}

/// `PqzCore.entryRefOf`.
pub fn entry_ref(from: &Word, counter: u64) -> Word {
    let tag = scaas_ua::keccak256(b"SCAAS-PQZ-ENTRY-V1");
    let mut tok = [0u8; 32];
    tok[12..].copy_from_slice(&TOKEN);
    scaas_ua::keccak256(&[tag, st::u64_word(CHAIN_ID), UID, tok, *from, st::u64_word(counter)].concat())
}

#[derive(Clone, Default)]
pub struct Acct {
    pub count: u64,
    pub rolled: u64,
    pub floor: u64,
    pub cleared: u64,
    pub acc_blob: [u8; 20],
    pub acc_u: u64,
    pub acc_v: u64,
    pub units: u64,
    pub flags: u8,
    pub acc_hash: Word,
    pub pending: BTreeMap<u64, Word>,
    pub acc_words: Vec<Word>,
}

impl Acct {
    /// The struct's slots 0..2 as solc packs them (the first field in the low bytes).
    pub fn slots(&self) -> [Word; 3] {
        let mut s = [[0u8; 32]; 3];
        for (i, v) in [self.cleared, self.floor, self.rolled, self.count].iter().enumerate() {
            s[0][8 * i..8 * i + 8].copy_from_slice(&v.to_be_bytes());
        }
        s[1][3] = self.flags;
        s[1][4..8].copy_from_slice(&(self.units as u32).to_be_bytes());
        s[1][8..10].copy_from_slice(&(self.acc_v as u16).to_be_bytes());
        s[1][10..12].copy_from_slice(&(self.acc_u as u16).to_be_bytes());
        s[1][12..].copy_from_slice(&self.acc_blob);
        s[2] = self.acc_hash;
        s
    }
}

/// The version words a forge row (`state.json`, version 0 of every UA) leaves to its reader (group 3g): the UA's
/// `sendCounter[ua]` word from the row's `sendCounter`, `keyVersion` 0, `pqzVersions` `(latest 0, current 0, listed)`.
pub fn forge_versions(a: &Value) -> Value {
    let mut v = [0u8; 32];
    v[15] = 1;
    json!({"sendCounterWord": hx(&st::u64_word(a["sendCounter"].as_u64().unwrap())), "keyVersion": 0, "keyVersions": hx(&v)})
}

/// An entry: its op blob's pointer, the sender's counter, the memo (commit-reveal).
#[derive(Clone)]
pub struct Ent {
    pub ptr: [u8; 20],
    pub from: Word,
    pub ctr: u64,
    pub memo: Vec<u8>,
}

#[derive(Default)]
pub struct Chain {
    pub blobs: BTreeMap<[u8; 20], Vec<u8>>,
    pub accts: BTreeMap<(Word, u64), Acct>,
    pub keys: BTreeMap<(Word, u64), [u8; 20]>,
    /// `(latest, current)` per UA (the registry's `pqzVersions`).
    pub vers: BTreeMap<Word, (u64, u64)>,
    /// `sendCounter[ua]`.
    pub ctrs: BTreeMap<Word, u64>,
    pub entries: BTreeMap<Word, Ent>,
    pub block: u64,
    pub auditor: Option<Word>,
    n: u64,
}

impl Chain {
    pub fn new() -> Chain {
        Chain { block: 100, ..Default::default() }
    }
    /// SSTORE2: `0x00 ‖ data` at a fresh address.
    pub fn put(&mut self, data: Vec<u8>) -> [u8; 20] {
        self.n += 1;
        let a: [u8; 20] = scaas_ua::keccak256(&self.n.to_be_bytes())[..20].try_into().unwrap();
        self.blobs.insert(a, [vec![0u8], data].concat());
        a
    }
    /// Version 0 of `ua`, proven and current.
    pub fn register(&mut self, ua: Word, pk: &[u8]) {
        let a = self.put(pk.to_vec());
        self.keys.insert((ua, 0), a);
        self.vers.insert(ua, (0, 0));
    }
    /// The next version of `ua` (`setPqzKey`), current at once when `eligible` (its proof stored), else pending.
    pub fn add_version(&mut self, ua: Word, pk: &[u8], eligible: bool) -> u64 {
        let a = self.put(pk.to_vec());
        let (latest, current) = self.vers[&ua];
        self.keys.insert((ua, latest + 1), a);
        self.vers.insert(ua, (latest + 1, if eligible { latest + 1 } else { current }));
        latest + 1
    }
    pub fn cur(&self, ua: &Word) -> u64 {
        self.vers[ua].1
    }
    /// The SSTORE2 pointer of `ua`'s current key.
    pub fn key_ptr(&self, ua: &Word) -> [u8; 20] {
        self.keys[&(*ua, self.cur(ua))]
    }
    /// The registry's `pqzKey[ua][current]` word: `ptr ‖ proven ‖ added`.
    pub fn key_record(&self, ua: &Word) -> Word {
        self.key_record_at(ua, self.cur(ua))
    }
    pub fn key_record_at(&self, ua: &Word, v: u64) -> Word {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&self.keys[&(*ua, v)]);
        w[11] = 1;
        w[10] = (v > 0) as u8;
        w
    }
    /// The registry's `pqzVersions[ua]` word: `latest(64) ‖ current(64) ‖ listed(8)`.
    pub fn versions_word(&self, ua: &Word) -> Word {
        let (latest, current) = self.vers[ua];
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&latest.to_be_bytes());
        w[16..24].copy_from_slice(&current.to_be_bytes());
        w[15] = 1;
        w
    }
    /// `ua`'s account at its current version (where credits land).
    pub fn acct(&mut self, ua: &Word) -> &mut Acct {
        let v = self.cur(ua);
        self.accts.entry((*ua, v)).or_default()
    }
    /// The version of `ua` whose key is `pk`.
    fn version_of(&self, ua: &Word, pk: &[u8]) -> u64 {
        self.keys.iter().find(|((u, _), a)| u == ua && &self.blobs[*a][1..] == pk).expect("a key of the UA").0 .1
    }
    /// `PqzCore._trivial` (a new block each time: always appended).
    pub fn shield(&mut self, ua: &Word, amount: u64) {
        self.block += 1;
        let mut w = [0u8; 32];
        w[12..20].copy_from_slice(&amount.to_be_bytes());
        w[24..].copy_from_slice(&self.block.to_be_bytes());
        let a = self.acct(ua);
        a.pending.insert(a.count, w);
        a.count += 1;
    }
    /// `PqzCore._credit`.
    pub fn credit(&mut self, ua: &Word, ptr: [u8; 20], u_off: usize, v_off: usize) {
        let mut w = [0u8; 32];
        w[..20].copy_from_slice(&ptr);
        w[20..22].copy_from_slice(&(u_off as u16).to_be_bytes());
        w[22..24].copy_from_slice(&(v_off as u16).to_be_bytes());
        w[24..].copy_from_slice(&self.block.to_be_bytes());
        let a = self.acct(ua);
        a.pending.insert(a.count, w);
        a.count += 1;
    }
    /// `PqzCore._debit` and `_sent` of version `v`: `acc` the reference, `rolled = floor = cleared = p`, `sendCounter[from]++`.
    fn debit(&mut self, from: &Word, v: u64, ptr: [u8; 20], u_off: usize, v_off: usize, p: u64) {
        *self.ctrs.entry(*from).or_default() += 1;
        let a = self.accts.entry((*from, v)).or_default();
        (a.acc_blob, a.acc_u, a.acc_v, a.units, a.flags) = (ptr, u_off as u64, v_off as u64, 1, a.flags & !1);
        (a.rolled, a.floor) = (p, p);
        for i in a.cleared..p {
            a.pending.remove(&i);
        }
        a.cleared = a.cleared.max(p);
    }
    fn data(&self, a: &[u8; 20]) -> &[u8] {
        &self.blobs[a][1..]
    }
    fn ct(&self, a: &[u8; 20], u_off: usize, v_off: usize) -> Vec<u8> {
        let d = self.data(a);
        [unpack(&d[u_off..u_off + PKP]).unwrap(), unpack(&d[v_off..v_off + VP]).unwrap()].concat()
    }
    /// `acc` as the contract reads it (`_accOf`), at the current version.
    pub fn acc_ct(&self, ua: &Word) -> Vec<u8> {
        let a = &self.accts[&(*ua, self.cur(ua))];
        if a.flags & 1 != 0 {
            let s: Vec<u8> = a.acc_words.iter().flat_map(|w| w.map(|b| !b)).take(CTP).collect();
            unpack(&s).unwrap()
        } else if a.acc_blob == [0; 20] {
            vec![0; PK_BYTES + 128]
        } else {
            self.ct(&a.acc_blob, a.acc_u as usize, a.acc_v as usize)
        }
    }
    /// `rollOver(ua, n)`: `acc += Σ pending[rolled, rolled + n)` written as `not(packed stream)`, `accHash`, `MAT`.
    pub fn roll(&mut self, ua: &Word, n: u64) {
        let mut c = lanes(&self.acc_ct(ua));
        let a = self.accts[&(*ua, self.cur(ua))].clone();
        let delta = st::DELTA.unsigned_abs();
        for i in a.rolled..a.rolled + n {
            let e = a.pending[&i];
            let v_off = u16::from_be_bytes(e[22..24].try_into().unwrap()) as usize;
            if v_off == 0 {
                let amt = u64::from_be_bytes(e[12..20].try_into().unwrap());
                for (k, x) in c.iter_mut().skip(PK_BYTES / 8).take(16).enumerate() {
                    *x += delta * ((amt >> (4 * k)) & 15);
                }
            } else {
                let ptr: [u8; 20] = e[..20].try_into().unwrap();
                let u_off = u16::from_be_bytes(e[20..22].try_into().unwrap()) as usize;
                for (x, y) in c.iter_mut().zip(lanes(&self.ct(&ptr, u_off, v_off))) {
                    *x += y;
                }
            }
        }
        let stream = pack(&bytes(&c));
        assert_eq!(stream.len(), CTP);
        let mut padded = stream.clone();
        padded.resize(ACC_WORDS * 32, 0);
        let words = padded.chunks_exact(32).map(|w| <[u8; 32]>::try_from(w).unwrap().map(|b| !b)).collect();
        let a = self.acct(ua);
        (a.acc_words, a.acc_hash, a.flags) = (words, scaas_ua::keccak256(&stream), a.flags | 7);
        a.rolled += n;
        a.units += n;
    }
    /// The facade's `p` rule (CTR-PQZ-06), as a reading layer computes it to know which pending slots to read.
    pub fn p_of(&self, ua: &Word, v: u64, inline: u64) -> u64 {
        let a = &self.accts[&(*ua, v)];
        a.count.min(a.rolled + inline.min(K_MAX as u64 - 1 - a.units))
    }
    /// A words request for `ua`'s own account at its current version (`balance` and the debits).
    pub fn own(&self, ua: &Word, inline: u64) -> Value {
        self.own_at(ua, self.cur(ua), inline)
    }
    /// A words request for `ua`'s own account of version `v`: the reading layer's words at the inline window.
    pub fn own_at(&self, ua: &Word, v: u64, inline: u64) -> Value {
        let empty = Acct::default();
        let a = self.accts.get(&(*ua, v)).unwrap_or(&empty);
        let p = a.count.min(a.rolled + inline.min(K_MAX as u64 - 1 - a.units));
        let mut blobs = vec![self.keys[&(*ua, v)]];
        if a.flags & 1 == 0 && a.acc_blob != [0; 20] {
            blobs.push(a.acc_blob);
        }
        let pending: Vec<Value> = (a.rolled..p)
            .map(|i| {
                let e = a.pending[&i];
                if e[22..24] != [0, 0] {
                    blobs.push(e[..20].try_into().unwrap());
                }
                json!({"index": i, "word": hx(&e)})
            })
            .collect();
        let acc_words: Vec<String> = if a.flags & 1 != 0 { a.acc_words.iter().map(|w| hx(w)).collect() } else { vec![] };
        json!({"chainUid": hx(&UID), "token": hx(&TOKEN), "ua": hx(ua), "block": self.block, "psid": hx(&st::PQZL_ID),
            "account": a.slots().iter().map(|w| hx(w)).collect::<Vec<_>>(), "pending": pending, "accWords": acc_words,
            "sendCounterWord": hx(&st::u64_word(self.ctrs.get(ua).copied().unwrap_or(0))), "keyVersion": v,
            "keyVersions": hx(&self.versions_word(ua)), "blobs": self.blobs_json(&blobs), "keyRecord": hx(&self.key_record_at(ua, v))})
    }
    /// A `balance` request for `ua` (op 1 / op 2's `p`: `forOp7` false).
    pub fn bal(&self, ua: &Word) -> Value {
        merge(self.own(ua, 16), json!({"forOp7": false}))
    }
    /// A `proveDiscloseSender` request of leg `j` of entry `er` for its sender (`keyRecord` the sender's, `legKeyRecord` and
    /// its code the leg owner's `owner`).
    pub fn sender_leg(&self, er: &Word, j: usize, owner: &Word) -> Value {
        let e = &self.entries[er];
        let mut v = self.entry(er, &e.from);
        v["blobs"] = json!(self.blobs_json(&[e.ptr, self.key_ptr(&e.from), self.key_ptr(owner)]));
        merge(v, json!({"leg": j, "registry": hx(&REG), "legKeyRecords": [hx(&self.key_record(owner))]}))
    }
    pub fn blobs_json(&self, list: &[[u8; 20]]) -> Vec<Value> {
        let mut seen = Vec::new();
        list.iter()
            .filter(|a| if seen.contains(*a) { false } else { seen.push(**a); true })
            .map(|a| json!({"address": hx(a), "code": hx(&self.blobs[a])}))
            .collect()
    }
    /// A debit's caller fields (no beneficiary, fee 0).
    pub fn debit_fields(&self) -> Value {
        json!({"chainId": CHAIN_ID, "registry": hx(&REG), "fee": 0, "validUntilBlock": self.block + 100, "shieldIn": 0,
            "envelopeBinding": hx(&[0xE1; 32])})
    }
    /// An old entry's location and words for `holder`, who reads it (`ua`'s key record and code).
    pub fn entry(&self, er: &Word, holder: &Word) -> Value {
        let e = &self.entries[er];
        let mut ptr = [0u8; 32];
        ptr[12..].copy_from_slice(&e.ptr);
        json!({"chainId": CHAIN_ID, "chainUid": hx(&UID), "token": hx(&TOKEN), "entryRef": hx(er), "fromUA": hx(&e.from),
            "sendCounter": e.ctr, "entryPtr": hx(&ptr), "block": self.block, "psid": hx(&st::PQZL_ID),
            "blobs": self.blobs_json(&[e.ptr, self.key_ptr(holder)]), "keyRecord": hx(&self.key_record(holder))})
    }
    /// The token's `auditorMode` (slot 0: `pqz ‖ disclosureMode ‖ auditorMode`, OPTIONAL) and `auditorUA` words.
    pub fn auditor_words(&self, mode: u8) -> Value {
        let mut w = [0u8; 32];
        w[10] = mode;
        w[31] = 0x0a; // the precompile's address in the low 20 bytes
        json!({"auditorMode": hx(&w), "auditorUA": hx(&self.auditor.unwrap())})
    }
    /// Settles a verified op 1 statement (`_settleTransfer`): the op blob `salt ‖ P(u) ‖ P(v_t) ‖ [P(v_a)] ‖ toUA ‖ P(v_f)`,
    /// the sender's debit, the receiver's credit, the entry.
    pub fn settle1(&mut self, stmt: &[u8], memo: Option<&[u8]>) -> Word {
        let st::Stmt::Debit(d) = st::parse(1, stmt).unwrap() else { panic!() };
        let hd = &d.header;
        let (from, to) = (hd[st::H_FROM], hd[st::H_TO]);
        let (p, ctr) = (st::word_u64(&hd[st::H_P]).unwrap(), st::word_u64(&hd[st::H_SEND_COUNTER]).unwrap());
        let mut blob = [&hd[st::H_SALT][16..], &pack(d.u), &pack(d.v_t.unwrap())].concat();
        if let Some(va) = d.v_a {
            blob.extend(pack(va));
        }
        blob.extend(to);
        blob.extend(pack(d.v_f));
        let len = blob.len();
        self.block += 1;
        let ptr = self.put(blob);
        let v = self.version_of(&from, d.pk_f);
        self.debit(&from, v, ptr, 16, len - VP, p);
        self.credit(&to, ptr, 16, 16 + PKP);
        let er = entry_ref(&from, ctr);
        self.entries.insert(er, Ent { ptr, from, ctr, memo: memo.map(<[u8]>::to_vec).unwrap_or_default() });
        er
    }
    /// Settles a verified op 7 statement (`_bundleMulti`, `_creditLegs`).
    pub fn settle7(&mut self, stmt: &[u8], memo: Option<&[u8]>) -> Word {
        let st::Stmt::Multi(m) = st::parse(7, stmt).unwrap() else { panic!() };
        let hd = &m.header;
        let from = hd[st::H_FROM];
        let (p, ctr) = (st::word_u64(&hd[st::H_P]).unwrap(), st::word_u64(&hd[st::H_SEND_COUNTER]).unwrap());
        let (g, aud) = (m.groups(), m.pk_a.is_some());
        let uas: Vec<Word> = memo_uas(stmt, m.m);
        let mut blob = hd[st::H_SALT][16..].to_vec();
        for i in 0..g {
            blob.extend(pack(m.u(i)));
        }
        for (j, ua) in uas.iter().enumerate() {
            blob.extend(pack(m.v(j)));
            if aud {
                blob.extend(pack(m.v_a(j).unwrap()));
            }
            blob.extend(ua);
        }
        blob.extend(pack(m.v_f));
        let len = blob.len();
        self.block += 1;
        let ptr = self.put(blob);
        let v = self.version_of(&from, m.pk_f);
        self.debit(&from, v, ptr, 16, len - VP, p);
        let (us, ls) = (16 + PKP * g, 32 + VP * (1 + aud as usize));
        for (j, ua) in uas.iter().enumerate() {
            self.credit(ua, ptr, 16 + PKP * (j / st::legs_per_group(aud)), us + ls * j);
        }
        let er = entry_ref(&from, ctr);
        self.entries.insert(er, Ent { ptr, from, ctr, memo: memo.map(<[u8]>::to_vec).unwrap_or_default() });
        er
    }
    /// Settles a verified burn or refresh (`_settleBurn`): the op blob `P(u') ‖ P(v_f)`, the debit.
    pub fn settle_burn(&mut self, stmt: &[u8]) {
        let st::Stmt::Debit(d) = st::parse(2, stmt).unwrap() else { panic!() };
        let hd = &d.header;
        let p = st::word_u64(&hd[st::H_P]).unwrap();
        self.block += 1;
        let ptr = self.put([pack(d.u), pack(d.v_f)].concat());
        let v = self.version_of(&hd[st::H_FROM], d.pk_f);
        self.debit(&hd[st::H_FROM], v, ptr, 0, PKP, p);
    }
}

/// The legs' UAs of an op 7 transfer: the test records them per statement (`recipientsHash` only is in the header).
static UAS: std::sync::Mutex<Vec<(Word, Vec<Word>)>> = std::sync::Mutex::new(Vec::new());

/// Records op 7's leg UAs for the statement whose `recipientsHash` they hash to.
pub fn note_legs(uas: &[Word]) {
    UAS.lock().unwrap().push((scaas_ua::keccak256(&uas.concat()), uas.to_vec()));
}

fn memo_uas(stmt: &[u8], m: usize) -> Vec<Word> {
    let st::Stmt::Multi(x) = st::parse(7, stmt).unwrap() else { panic!() };
    let rh = x.header[st::H_RECIPIENTS_HASH];
    let l = UAS.lock().unwrap();
    let uas = l.iter().find(|(h, _)| *h == rh).expect("note_legs first").1.clone();
    assert_eq!(uas.len(), m);
    uas
}
