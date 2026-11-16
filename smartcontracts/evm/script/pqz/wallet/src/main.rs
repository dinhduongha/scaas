// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `pqz-wallet-sim`: the matrix's wallet for opening tokens (spec 2026-11-13-pqz-three-keys §15.2; CLI-SGN-51). One JSON
//! object on stdin, one on stdout. UNAUDITED test tool: test seeds only.
//!
//! - `keys`: a holder's PQZ public key and opening KEM key of one record (the handle's public data, `PqzKeyHandle::pk` /
//!   `open_kem_pk`).
//! - `credit`: the sender side of an op 1 on an opening token (pqz-ffi `enc_split`, `seal`): `u`, `vTo`, `[vAuditor]`, `uFrom`,
//!   `vFrom`, the openings; `variant` plants a bad credit (`junk`, `wrongseed`, `craftedv`; with the auditor `junk_oa`,
//!   `junk_ot`, `oa_coins`).
//! - `wallet`: the holder side, ALL through ua-rs `pqz3k::PqzKeyHandle` (T21 O5 (b): the handle in a store of its own, the
//!   test constructor `vectors_from_seed`): each pending credit checked (`check`: the blob read, K3-7 by pqz-ffi
//!   `check_recipient` inside the handle, an acceptance or a skip), the marks a wallet may sign (`PqzKeyHandle::marks`: reads
//!   at a finalized block in strict-majority mode), and a debit (`open_debit`: the PQZ secret reaches the decryption
//!   of `T` only when every window entry is accepted, TRIVIAL or marked, and the own part, required when `lastDebit > 0`,
//!   verifies). Since the review of the handle (owner decision (a)) through `open_debit`: the handle builds `T` from the own
//!   part (`window.ownCode`, the account's last debit blob), the window and `window.shieldIn`, and decrypts it; the request
//!   carries no `T`. The acceptances live in this process only, so one call checks and opens the window.
//! - `audit`: the auditor tool (pqz-ffi `check_auditor` with the auditor's opening KEM seed; never a PQZ secret) and
//!   `unreadable, taken` from state.
use pqz_ffi::opening::{self as op, AuditorOutcome, Party, Role};
use pqz_ffi::pqzl::PK_BYTES;
use scaas_ua::facade::pqz_pack::{PKP, VP};
use scaas_ua::facade::pqz_path::tail;
use scaas_ua::pqz3k::{self as k3, AuditorKeys, Checked, Debit, Layout, Own, PqzKeyHandle, Reads, Scope, WindowEntry};
use serde_json::{json, Value};
use std::io::Read;

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap_or("").trim_start_matches("0x");
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
}
fn hex(b: &[u8]) -> String {
    format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}
fn arr<const L: usize>(v: &Value) -> [u8; L] {
    unhex(v).try_into().unwrap_or_else(|b: Vec<u8>| panic!("{L} bytes, got {}", b.len()))
}
fn num(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().map(|s| s.parse().expect("number")).unwrap_or(0))
}
fn opt20(v: &Value) -> Option<[u8; 20]> {
    (!v.is_null() && !unhex(v).is_empty()).then(|| arr(v))
}

/// The set's packing width (P46): `ceil(log2 q)` bits per coefficient.
fn pack_bits() -> usize {
    64 - (pqz_ffi::stmt::Q - 1).leading_zeros() as usize
}
fn layout() -> Layout {
    Layout::of(pqz_ffi::stmt::N, pack_bits())
}
/// The inverse of pqz-ffi `opening::pack`: each `b`-bit big-endian field back to a be8 lane.
fn unpack(p: &[u8]) -> Vec<u8> {
    let b = pack_bits();
    let n = p.len() * 8 / b;
    let mut out = Vec::with_capacity(8 * n);
    let (mut acc, mut bits, mut at) = (0u128, 0usize, 0usize);
    for _ in 0..n {
        while bits < b {
            acc = (acc << 8) | p[at] as u128;
            at += 1;
            bits += 8;
        }
        let x = (acc >> (bits - b)) as u64 & ((1u64 << b) - 1);
        bits -= b;
        acc &= (1u128 << bits) - 1;
        out.extend(x.to_be_bytes());
    }
    out
}
fn digits(amount: u64) -> [u8; 16] {
    let mut d = [0u8; 16];
    for (i, x) in d.iter_mut().enumerate() {
        *x = ((amount >> (4 * i)) & 15) as u8;
    }
    d
}
fn amount(d: &[u8; 16]) -> u64 {
    d.iter().enumerate().map(|(i, x)| (*x as u64) << (4 * i)).sum()
}

struct Rec {
    seed: [u8; 64],
    ua: [u8; 32],
    cu: [u8; 32],
    scope: Option<[u8; 20]>,
    version: u64,
}
impl Rec {
    fn of(r: &Value) -> Self {
        Rec { seed: arr(&r["seed"]), ua: arr(&r["ua"]), cu: arr(&r["chainUid"]), scope: opt20(&r["scope"]), version: num(&r["version"]) }
    }
    fn handle(&self) -> PqzKeyHandle {
        let s = Scope { account: 0, index: 0, ua: self.ua, chain_uid: self.cu, token: self.scope, version: self.version };
        PqzKeyHandle::vectors_from_seed(&self.seed, &s).expect("the handle")
    }
}

fn keys(r: &Value) -> Value {
    let rec = Rec::of(r);
    let h = rec.handle();
    json!({"pqzKey": hex(&h.pk()), "openKem": hex(&h.open_kem_pk()), "seedCommitment": hex(&h.seed_commitment().expect("open"))})
}

fn credit(r: &Value) -> Value {
    let (cu, token, to_ua): ([u8; 32], [u8; 20], [u8; 32]) = (arr(&r["chainUid"]), arr(&r["token"]), arr(&r["toUA"]));
    let (pk_f, pk_t): ([u8; PK_BYTES], [u8; PK_BYTES]) = (arr(&r["pkF"]), arr(&r["pkT"]));
    let kem_t = unhex(&r["kemPkT"]);
    let aud = &r["auditor"];
    let (aud_ua, pk_a, kem_a): (Option<[u8; 32]>, Option<[u8; PK_BYTES]>, Vec<u8>) = if aud.is_null() {
        (None, None, vec![])
    } else {
        (Some(arr(&aud["ua"])), Some(arr(&aud["pk"])), unhex(&aud["kemPk"]))
    };
    let split = op::enc_split(&pk_f, digits(num(&r["balanceF"])), &to_ua, &pk_t, digits(num(&r["amount"])), pk_a.as_ref(),
        &arr(&r["seedEnc"])).expect("enc_split");
    let variant = r["variant"].as_str().unwrap_or("honest");
    let mut v_t: [u8; 128] = split.leg.vs[0];
    if variant == "craftedv" {
        // a planted leg: v_t moved by one off the lattice of Δ·d (the opening itself honest, sealed over the moved v)
        let x = u64::from_be_bytes(v_t[..8].try_into().unwrap());
        v_t[..8].copy_from_slice(&((x + 1) % pqz_ffi::stmt::Q).to_be_bytes());
    }
    let v_a: Option<[u8; 128]> = pk_a.map(|_| split.leg.vs[1]);
    let (kv_t, kv_a) = (num(&r["toVersion"]), num(&aud["version"]));
    let to = Party { ua: &to_ua, key_version: kv_t, pk: &pk_t, kem_pk: &kem_t, v: &v_t, opening: &[] };
    let a = match (aud_ua.as_ref(), pk_a.as_ref(), v_a.as_ref()) {
        (Some(ua), Some(pk), Some(v)) => Some(Party { ua, key_version: kv_a, pk, kem_pk: &kem_a, v, opening: &[] }),
        _ => None,
    };
    let c = op::Credit { chain_uid: &cu, token: &token, u: &split.leg.u, to, auditor: a };
    let junk = |seed: u8| -> Vec<u8> { (0..op::OPENING).map(|i| (i as u8).wrapping_mul(31) ^ seed).collect() };
    let other = op::keccak(&[&split.seed_leg[..]]);
    let o_t = match variant {
        "junk" | "junk_ot" => junk(1),
        "wrongseed" => op::seal(Role::Recipient, &c, &c.to, &other).expect("seal"),
        _ => op::seal(Role::Recipient, &c, &c.to, &split.seed_leg).expect("seal"),
    };
    let o_a = a.map(|p| match variant {
        "junk_oa" => junk(2),
        "oa_coins" => op::seal(Role::Recipient, &c, &p, &split.seed_leg).expect("seal"), // a valid opening, other coins
        _ => op::seal(Role::Auditor, &c, &p, &split.seed_leg).expect("seal"),
    });
    let opening = |o: &[u8]| json!({"mlkemCt": hex(&o[..op::MLKEM_CT]), "x25519Eph": hex(&o[op::MLKEM_CT..op::MLKEM_CT + 32]),
        "sealedSeed": hex(&o[op::MLKEM_CT + 32..])});
    let empty = json!({"mlkemCt": "0x", "x25519Eph": hex(&[0u8; 32]), "sealedSeed": "0x"});
    json!({"u": hex(&split.leg.u[..]), "vTo": hex(&v_t), "vAuditor": v_a.map_or("0x".into(), |v| hex(&v)),
        "uFrom": hex(&split.own.u[..]), "vFrom": hex(&split.own.vs[0]), "openingTo": opening(&o_t),
        "openingAuditor": o_a.as_ref().map_or(empty, |o| opening(o))})
}

fn wallet(r: &Value) -> Value {
    let rec = Rec::of(r);
    let h = rec.handle();
    let pk = h.pk();
    let token: [u8; 20] = arr(&r["token"]);
    let rd = &r["reads"];
    let reads = Reads { block: num(&rd["block"]), finalized: rd["finalized"].as_bool().unwrap_or(false),
        strict_majority: rd["strictMajority"].as_bool().unwrap_or(false) };
    struct E {
        index: u64,
        slot: [u8; 32],
        code: Vec<u8>,
        aud: Option<([u8; 32], Vec<u8>, Vec<u8>)>,
    }
    let es: Vec<E> = r["entries"].as_array().expect("entries").iter().map(|e| E { index: num(&e["index"]), slot: arr(&e["slot"]),
        code: unhex(&e["code"]), aud: (!e["auditor"].is_null()).then(|| (arr(&e["auditor"]["ua"]), unhex(&e["auditor"]["pk"]),
            unhex(&e["auditor"]["kemPk"]))) }).collect();
    let mut out = vec![];
    let mut accepted = vec![];
    let mut skips = vec![];
    for e in &es {
        if k3::slot_trivial(&e.slot) || k3::slot_marked(&e.slot) {
            out.push(json!({"index": e.index, "outcome": if k3::slot_marked(&e.slot) { "marked" } else { "trivial" }}));
            continue;
        }
        let auditor = e.aud.as_ref().map(|(ua, pk, kem)| AuditorKeys { ua: *ua, pk, kem_pk: kem });
        let c = k3::Credit { token, index: e.index, slot: e.slot, code: &e.code, auditor, reads };
        let r = h.check(&c);
        match r {
            Ok(Checked::Accepted(a, amt)) => {
                out.push(json!({"index": e.index, "outcome": "accepted", "amount": amt, "entryHash": hex(&a.entry_hash())}));
                accepted.push(a);
            }
            Ok(Checked::Skip(s)) => {
                out.push(json!({"index": e.index, "outcome": "skip", "entryHash": hex(&s.entry_hash)}));
                skips.push(s);
            }
            Err(x) => out.push(json!({"index": e.index, "outcome": "refused", "why": format!("{x:?}")})),
        }
    }
    let marks = match PqzKeyHandle::marks(&skips) {
        Ok(m) => json!(m),
        Err(x) => json!(format!("refused: {x:?}")),
    };
    let mut window = Value::Null;
    if !r["window"].is_null() {
        let rw = &r["window"];
        let (from, to) = (num(&rw["from"]), num(&rw["to"]));
        let last_debit = rw["lastDebit"].as_u64().expect("window.lastDebit: the account's, a number");
        let w: Vec<WindowEntry> = es.iter().filter(|e| e.index >= from && e.index < to).map(|e| WindowEntry { token, index: e.index,
            slot: e.slot, code: (!e.code.is_empty()).then_some(&e.code[..]), accepted: accepted.iter().find(|a| a.index() == e.index) })
            .collect();
        // the own part from the account's last debit blob (`accBlob`'s code), read the way the facade reads it: `R ‖ P(v_f) ‖
        // ownTag ‖ kv ‖ n`, `u` at 0 (a burn / refresh) or 16 (a transfer, after its salt)
        let own_code = unhex(&rw["ownCode"]);
        let own_parts = (!own_code.is_empty()).then(|| {
            let d = &own_code[1..];
            let t = tail(d).expect("the own blob's tail");
            let u_at = if t.r_len == PKP { 0 } else { 16 };
            (d[u_at..u_at + PKP].to_vec(), d[t.r_len..t.r_len + VP].to_vec(), t.own_tag)
        });
        let own = own_parts.as_ref().map(|(pu, pvf, own_tag)| Own { pu, pvf, own_tag: *own_tag });
        let shield_in = rw["shieldIn"].as_u64().expect("window.shieldIn: a number");
        // T21 O5 (b) review (Fable F4, Codex 3): the handle builds `T` from the gated parts and decrypts it; no `T` from the request
        window = match h.open_debit(&Debit { token, last_debit, own, window: &w, shield_in }) {
            Ok(o) => json!({"opened": true, "balance": o.balance, "t": hex(&o.t)}),
            Err(x) => json!({"opened": false, "why": format!("{x:?}")}),
        };
    }
    json!({"entries": out, "marks": marks, "window": window, "secretLoads": h.secret_loads(), "keygens": h.keygens(),
        "pqzKey": hex(&pk[..])})
}

fn audit(r: &Value) -> Value {
    let rec = Rec::of(r);
    let kem = k3::open_kem_seed(&rec.seed, &rec.ua, &rec.cu, rec.scope.as_ref(), rec.version);
    let kem_pk = op::open_kem_pk(&kem);
    let token: [u8; 20] = arr(&r["token"]);
    let (rolled, floor) = (num(&r["rolled"]), num(&r["floor"]));
    let to_ua: [u8; 32] = arr(&r["recipient"]["ua"]);
    let to_pk: [u8; PK_BYTES] = arr(&r["recipient"]["pk"]);
    let to_kem = unhex(&r["recipient"]["kemPk"]);
    let mut out = vec![];
    for e in r["entries"].as_array().expect("entries") {
        let (index, slot, code): (u64, [u8; 32], Vec<u8>) = (num(&e["index"]), arr(&e["slot"]), unhex(&e["code"]));
        let Some(b) = code.get(1..).and_then(|d| k3::opening_blob(d, layout())) else {
            out.push(json!({"index": index, "outcome": "not an opening blob"}));
            continue;
        };
        if b.pva.is_none() {
            out.push(json!({"index": index, "outcome": "no auditor leg"})); // a credit sent without the auditor (OPTIONAL)
            continue;
        }
        let parts = (unpack(b.pu).try_into(), unpack(b.pvt).try_into(), b.pva.map(|p| unpack(p).try_into()));
        let (Ok(u), Ok(v_t), Some(Ok(v_a))) = parts else {
            out.push(json!({"index": index, "outcome": "unreadable"}));
            continue;
        };
        let (u, v_t, v_a): ([u8; PK_BYTES], [u8; 128], [u8; 128]) = (u, v_t, v_a);
        let to = Party { ua: &to_ua, key_version: b.kv[0], pk: &to_pk, kem_pk: &to_kem, v: &v_t, opening: b.o_t };
        let a = Party { ua: &rec.ua, key_version: b.kv[1], pk: &arr(&r["pk"]), kem_pk: &kem_pk, v: &v_a, opening: b.o_a.unwrap_or(&[]) };
        let fc = op::Credit { chain_uid: &rec.cu, token: &token, u: &u, to, auditor: Some(a) };
        let o = op::check_auditor(&kem, &fc);
        let marked = k3::slot_marked(&slot);
        let mut s = match o {
            AuditorOutcome::Read(d) => json!({"index": index, "outcome": "read", "amount": amount(&d)}),
            AuditorOutcome::RecipientUnreadable => json!({"index": index, "outcome": "recipient-unreadable"}),
            AuditorOutcome::Unreadable => json!({"index": index, "outcome": "unreadable"}),
        };
        if !matches!(o, AuditorOutcome::Read(_)) && op::taken(index, rolled, floor, marked) {
            s["outcome"] = json!(format!("{}, taken", s["outcome"].as_str().unwrap()));
        }
        out.push(s);
    }
    json!({"entries": out})
}

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("stdin");
    let r: Value = serde_json::from_str(&s).expect("json");
    let out = match r["cmd"].as_str().unwrap_or("") {
        "keys" => keys(&r),
        "credit" => credit(&r),
        "wallet" => wallet(&r),
        "audit" => audit(&r),
        c => json!({"error": format!("unknown cmd {c}")}),
    };
    println!("{out}");
}
