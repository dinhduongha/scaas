// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T15i (ARCH-POS-13 "never a decryption oracle"; spec no-decryption-oracle §1, §4.12, §5): the oracle harness.
//! PQZ encryption is IND-CPA, not CCA: a query with `u` the unit polynomial at polynomial `j` and `v_i = ⌈Δ/2⌉ + off` decrypts
//! at window `w` to `M_i = [s_j[16w + i] ≤ off]`, so 8·K queries (off 0 and −1, four windows, K polynomials) recover `s`
//! exactly (research `pqz-threshold-decrypt-prove` §12.1, N3b; the Python reference `pqz_threshold_c1.py` on `ua-mtx-merge`).
//! - Positive control (feature `vectors`): the queries through the test-only raw `dec` recover the handle's `s`.
//! - Negative: every command of the build other than the `vectors`-only raw forms refuses each query in every bare shape (a
//!   ciphertext, `T`, `p`, a statement, `u` / `v`, alone or added to a real words request) with `Argument`, before the key is
//!   used (feature `vectors`: the key-use counter); a release build has no `dec` at all.
//! - Residual control (§4.12): the same queries laid out as consistent fabricated raw words (a credit blob holding the crafted
//!   `u ‖ v`) ARE decrypted by `balance` and recover `s` at window 0: whether words are chain state is the reading layer's
//!   duty (R1–R7), never visible to the library. Asserted so the residual stays visible.
//! - Path (B) (T20d10, C-PP-9; spec §4.14): the residual's fabricated words, laid out wherever a value enters the proof path
//!   (a credit, a migration credit, the own `v_f`, a quorum's credit), are each refused (no credit without a verified P, no own
//!   `v_f` without its tag) and `balanceProven` never answers without them; the proof-path spec's negatives each refused alone.
//! - Zether (a separate scheme, no key recovery, the same rule): every command refuses a bare `(C, D)` in the raw commands'
//!   shapes, the key unused; the raw `decrypt` takes the same shape under `vectors`.
//!
//! The same negatives run in one binding through the C ABI (`clients/ua-py`, `Pqz.test_no_oracle`,
//! `Pqz.test_no_oracle_proof_path`). UNAUDITED.
#![allow(non_snake_case)]
mod pqz_chain;
use pqz_chain::*;
use pqz_ffi::stmt::{DELTA, K_MAX, PK_BYTES, Q};
use scaas_ua::facade::pqz::{AllowSecretExport, PqzCmd, PqzKey, COMMANDS};
use scaas_ua::facade::pqz_pack::{B, PKP, VP};
use scaas_ua::wallet::{Error, Wallet};
use serde_json::{json, Value};

const WORDS: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
/// The holder's UA on the simulated chain.
const A: [u8; 32] = [0xA1; 32];
/// Polynomials of 64 coefficients in `s` (`N = 64·K`).
const K: usize = PK_BYTES / 512;

fn unlock() {
    #[cfg(feature = "vectors")]
    scaas_ua::facade::vectors_unlock(scaas_ua::facade::TestOnly);
}

fn key_uses() -> usize {
    #[cfg(feature = "vectors")]
    return scaas_ua::facade::pqz::vectors_key_uses();
    #[cfg(not(feature = "vectors"))]
    0
}

/// The holder's handle and its secret `s` (the leaf exported with the marker, `pqzl::keygen`).
fn holder() -> (Wallet, PqzKey, Vec<i8>) {
    unlock();
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    let k = w.pqz_key(0, 0).unwrap();
    let leaf = w.export_pqz_leaf_raw(0, 0, AllowSecretExport).unwrap();
    let s = pqz_ffi::pqzl::keygen(&leaf).unwrap().s.to_vec();
    assert_eq!(s.len(), 64 * K);
    (w, k, s)
}

/// The crafted query `(u, v)`: `u` the unit polynomial at polynomial `j`, the 16 `v` coefficients `⌈Δ/2⌉ + off` (mod q).
fn query(j: usize, off: i64) -> (Vec<u8>, Vec<u8>) {
    let mut u = vec![0u64; 64 * K];
    u[64 * j] = 1;
    let v = ((DELTA.unsigned_abs() as i64 + 1) / 2 + off).rem_euclid(Q as i64) as u64;
    let be = |x: &[u64]| x.iter().flat_map(|c| c.to_be_bytes()).collect::<Vec<u8>>();
    (be(&u), be(&[v; 16]))
}

/// Runs the 8·K (or, `windows` = 1, the 2·K) queries through `ask(u, v, w) → the decrypted value`; the recovered
/// coefficients at `64 j + 16 w + i` (`None` where no window asked) and the number of queries.
fn recover(windows: usize, mut ask: impl FnMut(&[u8], &[u8], usize) -> u64) -> (Vec<Option<i8>>, usize) {
    let (mut rec, mut n) = (vec![None; 64 * K], 0);
    for j in 0..K {
        for w in 0..windows {
            let mut m = [0u64; 2];
            for (x, off) in m.iter_mut().zip([0, -1]) {
                let (u, v) = query(j, off);
                *x = ask(&u, &v, w);
                n += 1;
            }
            for i in 0..16 {
                let bit = |x: u64| {
                    let d = (x >> (4 * i)) & 15;
                    assert!(d <= 1, "a digit of a crafted query is 0 or 1");
                    d == 1
                };
                // M_i = [s ≤ off]: off −1 → s = −1; off 0 → s ∈ {−1, 0}; else s = 1
                rec[64 * j + 16 * w + i] = Some(if bit(m[1]) { -1 } else if bit(m[0]) { 0 } else { 1 });
            }
        }
    }
    (rec, n)
}

fn call(k: &PqzKey, cmd: &str, v: &Value) -> Result<Value, Error> {
    k.call(cmd, v.to_string().as_bytes()).map(|s| serde_json::from_str(&s).unwrap())
}

/// Positive control: through the `vectors`-only raw `dec`, the 8·K queries recover `s` exactly (the oracle the release build
/// must not have). A harness that cannot recover `s` here could not show anything below.
#[cfg(feature = "vectors")]
#[test]
fn positive_control_raw_dec_recovers_s() {
    let (_w, k, s) = holder();
    let (rec, n) = recover(4, |u, v, w| {
        let ct = format!("0x{}{}", hex::encode(u), hex::encode(v));
        call(&k, "dec", &json!({"ct": ct, "window": w})).unwrap()["value"].as_u64().unwrap()
    });
    assert_eq!(n, 8 * K, "8·K queries");
    assert_eq!(rec.iter().map(|x| x.unwrap()).collect::<Vec<_>>(), s, "the raw dec is a key-recovery oracle");
}

/// The bare shapes a crafted query can take: a ciphertext (with and without a window), `T` (with `p`), a statement, `u` / `v`.
fn shapes(u: &[u8], v: &[u8], w: usize) -> Vec<Value> {
    let ct = format!("0x{}{}", hex::encode(u), hex::encode(v));
    vec![
        json!({"ct": ct}),
        json!({"ct": ct, "window": w}),
        json!({"T": ct}),
        json!({"T": ct, "p": 1}),
        json!({"stmt": ct}),
        json!({"u": format!("0x{}", hex::encode(u)), "v": format!("0x{}", hex::encode(v))}),
    ]
}

/// The commands of this build a caller may reach in production: all of `COMMANDS` but the `vectors`-only raw forms.
fn production() -> Vec<&'static str> {
    let raw = |c: &str| c == "dec" || c.starts_with("raw");
    let p: Vec<&str> = COMMANDS.iter().copied().filter(|c| !raw(c)).collect();
    if !cfg!(feature = "vectors") {
        assert_eq!(p.len(), COMMANDS.len(), "a release build has no raw form");
    }
    p
}

/// Negative: every production command refuses each of the 8·K queries in each bare shape with one status, the key unused; a
/// release build has no `dec` (an unknown command, the same status).
#[test]
fn production_refuses_every_crafted_query_before_the_key() {
    let (_w, k, _) = holder();
    let cmds = production();
    assert!(cmds.contains(&"balance") && cmds.contains(&"proveTransfer") && cmds.contains(&"proveDisclose"));
    assert_eq!(COMMANDS.contains(&"dec"), cfg!(feature = "vectors"));
    let before = key_uses();
    let mut n = 0;
    for j in 0..K {
        for w in 0..4 {
            for off in [0, -1] {
                let (u, v) = query(j, off);
                for s in shapes(&u, &v, w) {
                    let b = s.to_string();
                    for c in &cmds {
                        assert_eq!(k.call(c, b.as_bytes()).err(), Some(Error::Argument), "{c} {s:.60}");
                    }
                    if !cfg!(feature = "vectors") {
                        assert_eq!(k.call("dec", b.as_bytes()).err(), Some(Error::Argument), "dec: absent");
                    }
                }
                n += 1;
            }
        }
    }
    assert_eq!(n, 8 * K);
    assert_eq!(key_uses(), before, "no query reached the key");
}

/// Negative: a crafted query added to a real words request (the holder's own account: `balance` answers it, each debit's
/// request parses) in any bare field is refused before the key: the allow-list holds no field a ciphertext, `T` or `p` could
/// ride in.
#[test]
fn a_crafted_query_beside_real_words_is_refused() {
    let (_w, k, _) = holder();
    let mut c = Chain::new();
    c.register(A, &k.pk());
    c.shield(&A, 1234);
    let words = c.own(&A, 16);
    assert_eq!(call(&k, "balance", &c.bal(&A)).unwrap()["value"], 1234, "the words alone");
    let debit = merge(words.clone(), c.debit_fields());
    // an old entry of the holder's (an op 1 blob, structurally valid, with 3h's tail: zero tag, the receiver at version 0, n = 1):
    // `proveDiscloseSender`'s words
    let blob = [vec![0x5a; 16], vec![0u8; PKP + VP], [0xB0; 32].to_vec(), vec![0u8; VP], vec![0u8; 32 + 8], vec![1]].concat();
    let ptr = c.put(blob);
    let er = entry_ref(&A, 0);
    c.entries.insert(er, Ent { ptr, from: A, ctr: 0, memo: vec![] });
    // another UA and key than the holder's (group 3g: no payment to itself at the current version, a statement's keys distinct)
    let pk = format!("0x{}", hex::encode(&pqz_ffi::pqzl::keygen(&[7; 32]).unwrap().pk[..]));
    let reqs = [
        ("balance", c.bal(&A)),
        ("proveRefresh", debit.clone()),
        ("proveBurn", merge(debit.clone(), json!({"amount": 1, "recipient": hx(&[0x0B; 32])}))),
        ("proveTransfer", merge(debit.clone(), json!({"toUA": hx(&[0xB0; 32]), "pkT": pk, "amount": 1, "mode": "BUNDLE"}))),
        ("proveTransferMulti", merge(debit, json!({"legs": [{"pk": pk, "ua": hx(&[0xB0; 32]), "amount": 1}], "mode": "BUNDLE"}))),
        ("proveDiscloseSender", c.sender_leg(&er, 0, &A)),
    ];
    let before = key_uses();
    let (u, v) = query(0, 0);
    for (cmd, r) in &reqs {
        assert!(PqzCmd::from_json(cmd, r.to_string().as_bytes()).is_ok(), "{cmd}: the request alone parses");
        // T15l (Fable P2-1): the old op 4 form rode a statement and its amount; beside real words both are refused by the
        // allow-list (the right reason: the words alone parse, so no field is missing), never by a later compare
        let guess = [json!({"amount": 1234}), json!({"amount": 1234, "stmt": format!("0x{}", hex::encode(&u))})];
        let extra = if *cmd == "proveDiscloseSender" || *cmd == "balance" { &guess[..] } else { &[] };
        for s in shapes(&u, &v, 0).into_iter().chain(extra.iter().cloned()) {
            let m = merge(r.clone(), s.clone());
            assert_eq!(PqzCmd::from_json(cmd, m.to_string().as_bytes()).err(), Some(Error::Argument), "{cmd} {s:.60}");
            assert_eq!(call(&k, cmd, &m).err(), Some(Error::Argument), "{cmd} {s:.60}");
        }
    }
    assert_eq!(key_uses(), before, "the key unused");
}

/// Residual control (spec §4.12): the queries as consistent fabricated raw words (a pending credit whose blob holds the crafted
/// `u ‖ v`, the holder's own key record) are decrypted by `balance` and recover `s` at window 0 (2·K queries). The library
/// cannot tell chain state from such words; R1–R7 bind the layer that reads the chain. If this ever fails, the residual moved:
/// update spec §4.12 and this test together.
#[test]
fn residual_control_fabricated_words_are_decrypted() {
    let (_w, k, s) = holder();
    let uses = key_uses();
    let (rec, n) = recover(1, |u, v, _| {
        let mut c = Chain::new();
        c.register(A, &k.pk());
        let ptr = c.put([vec![0u8; 16], pack(u), pack(v)].concat());
        c.credit(&A, ptr, 16, 16 + PKP);
        call(&k, "balance", &c.bal(&A)).unwrap()["value"].as_u64().unwrap()
    });
    assert_eq!(n, 2 * K);
    for (i, r) in rec.iter().enumerate() {
        assert_eq!(*r, if i % 64 < 16 { Some(s[i]) } else { None }, "coefficient {i}");
    }
    if cfg!(feature = "vectors") {
        assert_eq!(key_uses(), uses + n, "each fabricated request reached the key");
    }
}

/// Zether: every command refuses a bare `(C, D)` in the raw commands' shapes (`ct`, `pending`, `acc` + `balance`), the key
/// unused; under `vectors` the raw `decrypt` takes the first shape (the control that the shape is the raw one).
#[test]
fn zether_refuses_a_bare_ciphertext() {
    use scaas_ua::facade::zether::COMMANDS as ZC;
    unlock();
    let p = format!("{}/../zether-prover/vectors/r33_keys.json", env!("CARGO_MANIFEST_DIR"));
    let r: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    let w = Wallet::from_mnemonic(r["mnemonic"].as_str().unwrap(), r["passphrase"].as_str().unwrap()).unwrap();
    let k = w.zether_key(60, 0, 7).unwrap();
    let ct: Value = serde_json::from_str(&k.call("encrypt", json!({"Y": format!("0x{}", hex::encode(k.y())), "amount": 5}).to_string().as_bytes()).unwrap())
        .unwrap();
    let raw = |c: &str| c.starts_with("decrypt") || c.starts_with("raw");
    let shapes = [json!({"ct": ct, "tableBits": 18, "boundBits": 20}), json!({"pending": ct}), json!({"acc": ct, "balance": 5})];
    let before = scaas_ua_zether_key_uses();
    for c in ZC.iter().filter(|c| !raw(c)) {
        for s in &shapes {
            assert_eq!(k.call(c, s.to_string().as_bytes()).err(), Some(Error::Argument), "{c} {s}");
        }
    }
    assert_eq!(scaas_ua_zether_key_uses(), before, "the key unused");
    if cfg!(feature = "vectors") {
        assert_eq!(serde_json::from_str::<Value>(&k.call("decrypt", shapes[0].to_string().as_bytes()).unwrap()).unwrap()["amount"], "5");
    } else {
        assert!(!ZC.iter().any(|c| raw(c)), "a release build has no raw Zether form");
    }
}

fn scaas_ua_zether_key_uses() -> usize {
    #[cfg(feature = "vectors")]
    return scaas_ua::facade::zether::vectors_key_uses();
    #[cfg(not(feature = "vectors"))]
    0
}

// ---------------------------------------------------------------------------------------------------------------------------
// T20d10 (C-PP-9; no-oracle spec §4.14, §5): the harness through the proof path (B).
// ---------------------------------------------------------------------------------------------------------------------------

/// The sender of the proof-path world.
const S: [u8; 32] = [0x5E; 32];

/// A `provenAdd` credit and the blob addresses it names.
type Cred = (Value, Vec<[u8; 20]>);

fn verifies() -> usize {
    #[cfg(feature = "vectors")]
    return scaas_ua::facade::pqz::vectors_verifies();
    #[cfg(not(feature = "vectors"))]
    0
}

/// A LOG debit of `from` at version `v` on handle `kf`, its P noted, settled: op 1 of `amount` to `(to, pk_t)`, else a refresh.
fn debit(c: &mut Chain, kf: &PqzKey, from: &[u8; 32], v: u64, to: Option<(&[u8; 32], &[u8], u64)>) {
    let mut d = merge(c.own_at(from, v, 16), c.debit_fields());
    let (cmd, op) = match to {
        Some((ua, pk, amount)) => {
            let mode = scaas_ua::keccak256(&[scaas_ua::keccak256(b"SCAAS-PQZ-DIRECT-MODE-V1"), pqz_ffi::stmt::u64_word(1)].concat());
            d = merge(d, json!({"toUA": hx(ua), "pkT": hx(pk), "amount": amount, "mode": "BUNDLE", "envelopeBinding": hx(&mode)}));
            ("proveTransfer", 1)
        }
        None => {
            d["envelopeBinding"] = json!(hx(&[0; 32]));
            ("proveRefresh", 2)
        }
    };
    let p = call(kf, cmd, &d).unwrap();
    let (stmt, proof) = (h(&p["stmt"]), h(&p["proof"]));
    c.proof_store = 1;
    c.own_tag = h(&p["ownTag"]).try_into().unwrap();
    c.note_proof(op, &stmt, &proof, json!({}));
    if op == 1 {
        c.settle1(&stmt, p.get("memo").map(h).as_deref());
    } else {
        c.settle_burn(&stmt);
    }
}

/// The proof-path world: the holder `A` at version 1 (current) with a credit from `S` by P (index 0, 300) and the migration of
/// version 0's 50 (index 1); version 0 keeps its own `v_f` (0) with its tag; `S` has a pending version 1. The wallet (the handles live
/// with it), the chain, `A`'s handles of versions 0 and 1.
fn proof_world() -> (Wallet, Chain, PqzKey, PqzKey) {
    let (w, k0, _) = holder();
    let k1 = w.pqz_key_version(0, 0, 1).unwrap();
    let ks = w.pqz_key(1, 0).unwrap();
    let mut c = Chain::new();
    c.register(A, &k0.pk());
    c.register(S, &ks.pk());
    c.shield(&A, 50);
    c.shield(&S, 1000);
    c.add_version(A, &k1.pk(), true);
    debit(&mut c, &ks, &S, 0, Some((&A, &k1.pk(), 300)));
    debit(&mut c, &k0, &A, 0, Some((&A, &k1.pk(), 50)));
    c.add_version(S, &w.pqz_key_version(1, 0, 1).unwrap().pk(), false);
    (w, c, k0, k1)
}

/// The slot `i` of `(ua, v)`: its op blob and the leg's `(uOff, vOff)`.
fn slot(c: &Chain, ua: &[u8; 32], v: u64, i: u64) -> ([u8; 20], usize, usize) {
    let w = c.accts[&(*ua, v)].pending[&i];
    (w[..20].try_into().unwrap(), u16::from_be_bytes([w[20], w[21]]) as usize, u16::from_be_bytes([w[22], w[23]]) as usize)
}

/// `blob`'s stored ciphertext at `(uOff, vOff)` replaced by `(u, v)` (64-bit lanes): fabricated words; the old code returned.
fn lay(c: &mut Chain, blob: [u8; 20], at: (usize, usize), u: &[u8], v: &[u8]) -> Vec<u8> {
    let code = c.blobs.get_mut(&blob).unwrap();
    let old = code.clone();
    code[1 + at.0..1 + at.0 + PKP].copy_from_slice(&pack(u));
    code[1 + at.1..1 + at.1 + VP].copy_from_slice(&pack(v));
    old
}

/// Path (B) (plan T20d10): the residual control's fabricated words no longer reach the key. The 8·K queries are 2·K
/// ciphertexts (path (B) takes no window: a `window` field is refused by the allow-list, the bare shapes above), each laid out
/// as fabricated words, all else true chain state, in the four places a value enters path (B): the holder's credit (its leg in
/// the sender's real op blob, with the debit's real P), the migration credit from the holder's older version, the holder's own
/// `v_f` under its real tag, a quorum's credit (`checkProven`, no handle). 8·K attempts, each refused: a credit by its P
/// (feature `vectors`: one verification each, failed), the migration by re-encryption, the own `v_f` by its tag, the quorum's
/// credit by its P; `balanceProven` refuses the session that lacks the credit, the key unused. Before them the bare shapes:
/// alone to `checkProven` (no handle, so not in `COMMANDS`) and beside the true words of every path (B) request. Positive control
/// first: the true words through the same calls give the value, the quorum its parts.
#[test]
fn proof_path_refuses_the_fabricated_words_attack() {
    let (_w, mut c, k0, k1) = proof_world();
    let open = |c: &Chain, v: u64| merge(c.proven_open(&A, v), json!({"psid": hx(&pqz_ffi::stmt::PQZL_ID)}));
    let o = call(&k1, "provenOpen", &open(&c, 1)).unwrap();
    assert_eq!(o["need"], json!([0, 1]));
    let quorum = |c: &Chain, cs: &[Cred]| {
        scaas_ua::facade::pqz::check_proven(c.check_request(&A, 1, &k1.pk(), None, cs).to_string().as_bytes())
    };
    let truth = [c.proven_credit(&A, 1, 0), c.proven_credit(&A, 1, 1)];
    assert!(quorum(&c, &truth).is_ok(), "the quorum's control");
    assert!(call(&k0, "provenOpen", &open(&c, 0)).is_ok(), "the own v_f's control");
    // a crafted query in a bare shape, alone (`checkProven`: no handle) or beside the true words of each path (B) request: refused
    // by the allow-list, the session kept
    let (u, v) = query(0, 0);
    let sid = json!({"session": o["session"]});
    let reqs = [("provenOpen", open(&c, 1)), ("provenAdd", c.add_request(&o["session"], &truth)), ("balanceProven", sid.clone()),
        ("provenCancel", sid)];
    let check = |r: &Value| scaas_ua::facade::pqz::check_proven(r.to_string().as_bytes()).err();
    for s in shapes(&u, &v, 0) {
        assert_eq!(check(&s), Some(Error::Argument), "checkProven {s:.60}");
        assert_eq!(check(&merge(c.check_request(&A, 1, &k1.pk(), None, &truth), s.clone())), Some(Error::Argument), "checkProven {s:.60}");
        for (cmd, r) in &reqs {
            assert_eq!(call(&k1, cmd, &merge(r.clone(), s.clone())).err(), Some(Error::Argument), "{cmd} {s:.60}");
        }
    }
    let (credit, migration) = (slot(&c, &A, 1, 0), slot(&c, &A, 1, 1));
    let own = c.accts[&(A, 0)].clone();
    let mut n = 0;
    for j in 0..K {
        for off in [0, -1] {
            let (u, v) = query(j, off);
            let uses = key_uses();
            // the holder's credit and the migration, in the open session
            for (i, (blob, uo, vo)) in [(0, credit), (1, migration)] {
                let old = lay(&mut c, blob, (uo, vo), &u, &v);
                let ver = verifies();
                let r = call(&k1, "provenAdd", &c.add_request(&o["session"], &[c.proven_credit(&A, 1, i)])).unwrap();
                assert_eq!(r, json!({"accepted": [], "refused": [i]}), "slot {i}: query ({j}, {off})");
                if i == 0 && cfg!(feature = "vectors") {
                    assert_eq!(verifies(), ver + 1, "refused by its P");
                }
                assert_eq!(call(&k1, "balanceProven", &json!({"session": o["session"]})).err(), Some(Error::Argument));
                // the quorum's credit
                if i == 0 {
                    assert_eq!(quorum(&c, &[c.proven_credit(&A, 1, 0), truth[1].clone()]).err(), Some(Error::Argument), "quorum ({j}, {off})");
                }
                c.blobs.insert(blob, old);
                n += 1 + (i == 0) as usize;
            }
            // the own v_f (version 0's accBlob) under its real tag
            let old = lay(&mut c, own.acc_blob, (own.acc_u as usize, own.acc_v as usize), &u, &v);
            assert_eq!(call(&k0, "provenOpen", &open(&c, 0)).err(), Some(Error::Argument), "own ({j}, {off})");
            c.blobs.insert(own.acc_blob, old);
            n += 1;
            assert_eq!(key_uses(), uses, "the key unused");
        }
    }
    assert_eq!(n, 8 * K);
    // the session was kept: the true credits pass, the value is the holder's
    let r = call(&k1, "provenAdd", &c.add_request(&o["session"], &truth)).unwrap();
    assert_eq!(r, json!({"accepted": [0, 1], "refused": []}));
    assert_eq!(call(&k1, "balanceProven", &json!({"session": o["session"]})).unwrap()["value"], 350);
}

/// The proof-path spec's negatives (C-PP-9), each refused alone over [`proof_world`] (the key unused, the session kept), then
/// the true words accepted. Here: a forged `T` (the sender's window word), a key of another historical version, a swapped leg
/// (the holder's slot naming the sender's own `v_f`), more than `K_MAX` parts (the account's units), a non-canonical
/// coefficient (`c + q`, the same value mod q, at the default set; `2^B − 1` where q leaves no room), a forged `ownTag`, P of
/// another debit. The same classes at more places:
/// `facade_pqz_proof` (`credit_negatives_refused_alone`, `op7_leg_paired_with_its_own_group`, `session_rules_and_open_negatives`,
/// `bounds_refused_before_any_proof_is_checked`, `quorum_check_before_a_partial`); through one binding: ua-py
/// `Pqz.test_no_oracle_proof_path`.
#[test]
fn proof_path_negatives() {
    let (_w, mut c, k0, k1) = proof_world();
    let psid = json!({"psid": hx(&pqz_ffi::stmt::PQZL_ID)});
    let o = call(&k1, "provenOpen", &merge(c.proven_open(&A, 1), psid.clone())).unwrap();
    let (c0, c1) = (c.proven_credit(&A, 1, 0), c.proven_credit(&A, 1, 1));
    let set = |x: &Cred, f: &dyn Fn(&mut Value)| {
        let mut x = x.clone();
        f(&mut x.0);
        x
    };
    // a key of another version of S (pending version 1) in place of version 0's
    let mut other_key = set(&c0, &|x| x["keyRecords"][0]["word"] = json!(hx(&c.key_record_at(&S, 1))));
    other_key.1.push(c.keys[&(S, 1)]);
    // a coefficient of the leg stored at or above q: the first of `u ‖ v_t` with `c + q < 2^B` as `c + q` (the same value mod q),
    // where none fits (q close to 2^B: every set but the default) `v_t`'s first as `2^B − 1`
    let (blob, uo, vo) = slot(&c, &A, 1, 0);
    let code = c.blobs[&blob].clone();
    let mut nc = code.clone();
    let fit = [(uo, PKP), (vo, VP)].into_iter().find_map(|(at, n)| {
        let lanes = unpack_lanes(&code[1 + at..1 + at + n]);
        lanes.iter().position(|x| (x + Q) >> B == 0).map(|i| (at, n, lanes, i, true))
    });
    let (at, n, mut lanes, i, same) = fit.unwrap_or_else(|| (vo, VP, unpack_lanes(&code[1 + vo..1 + vo + VP]), 0, false));
    lanes[i] = if same { lanes[i] + Q } else { (1 << B) - 1 };
    assert!(lanes[i] >= Q && lanes[i] >> B == 0);
    let lanes: Vec<u8> = lanes.iter().flat_map(|x| x.to_be_bytes()).collect();
    nc[1 + at..1 + at + n].copy_from_slice(&scaas_ua::facade::pqz_pack::pack(&lanes).unwrap());
    if pqz_ffi::stmt::SET == "n2304-kmax4096" {
        assert!(same, "the default set: the same value mod q");
    }
    let cases: Vec<(&str, Cred, Option<Vec<u8>>)> = vec![
        ("a forged T (the sender's window word)", set(&c0, &|x| {
            let mut e = h(&x["senderPending"][0]["word"]);
            e[19] ^= 1;
            x["senderPending"][0]["word"] = json!(hx(&e));
        }), None),
        ("a key of another historical version", other_key, None),
        ("P of another debit", set(&c0, &|x| x["proof"] = c1.0["proof"].clone()), None),
        ("a non-canonical coefficient", c0.clone(), Some(nc)),
    ];
    for (what, x, forged) in cases {
        if let Some(f) = forged {
            c.blobs.insert(blob, f);
        }
        let (uses, ver) = (key_uses(), verifies());
        let r = call(&k1, "provenAdd", &c.add_request(&o["session"], std::slice::from_ref(&x))).unwrap();
        assert_eq!(r, json!({"accepted": [], "refused": [0]}), "{what}");
        assert_eq!(key_uses(), uses, "{what}: the key unused");
        if what == "a non-canonical coefficient" && cfg!(feature = "vectors") {
            // the facade's own check, not the precompile's decode of the rebuilt statement
            assert_eq!(verifies(), ver, "{what}: refused before its P");
        }
        c.blobs.insert(blob, code.clone());
    }
    // the session kept: the true words pass, the value is the holder's
    let r = call(&k1, "provenAdd", &c.add_request(&o["session"], &[c0.clone(), c1])).unwrap();
    assert_eq!(r, json!({"accepted": [0, 1], "refused": []}));
    assert_eq!(call(&k1, "balanceProven", &json!({"session": o["session"]})).unwrap()["value"], 350);
    // a swapped leg: the holder's slot names the sender's own v_f (another owner's leg of the same blob)
    let mut swapped = merge(c.proven_open(&A, 1), psid.clone());
    let mut e = h(&swapped["pending"][0]["word"]);
    let own_v = c.accts[&(S, 0)].acc_v as u16;
    e[22..24].copy_from_slice(&own_v.to_be_bytes());
    swapped["pending"][0]["word"] = json!(hx(&e));
    let s = call(&k1, "provenOpen", &swapped).unwrap();
    let r = call(&k1, "provenAdd", &c.add_request(&s["session"], std::slice::from_ref(&c0))).unwrap();
    assert_eq!(r["refused"], json!([0]), "a swapped leg");
    // more than K_MAX parts: the account's units at K_MAX (no window: the bound alone refuses it, not the window's length)
    let mut wide = merge(c.proven_open(&A, 1), psid.clone());
    let mut s1 = h(&wide["account"][1]);
    s1[4..8].copy_from_slice(&(K_MAX as u32).to_be_bytes());
    wide["account"][1] = json!(hx(&s1));
    wide["pending"] = json!([]);
    assert_eq!(call(&k1, "provenOpen", &wide).err(), Some(Error::Argument), "more than K_MAX parts");
    // a forged ownTag (version 0's accBlob, one bit of its tag)
    let ok = merge(c.proven_open(&A, 0), psid.clone());
    let acc = c.accts[&(A, 0)].acc_blob;
    let mut code = c.blobs[&acc].clone();
    let t = code.len() - 1 - 32 - 8 * *code.last().unwrap() as usize;
    code[t] ^= 1;
    let mut forged = ok.clone();
    for b in forged["blobs"].as_array_mut().unwrap() {
        if b["address"] == hx(&acc) {
            b["code"] = json!(hx(&code));
        }
    }
    let uses = key_uses();
    assert_eq!(call(&k0, "provenOpen", &forged).err(), Some(Error::Argument), "a forged ownTag");
    assert_eq!(key_uses(), uses);
    assert!(call(&k0, "provenOpen", &ok).is_ok(), "the true tag");
}

fn unpack_lanes(stored: &[u8]) -> Vec<u64> {
    scaas_ua::facade::pqz_pack::unpack(stored).unwrap().chunks_exact(8).map(|c| u64::from_be_bytes(c.try_into().unwrap())).collect()
}
