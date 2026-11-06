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
//! - Zether (a separate scheme, no key recovery, the same rule): every command refuses a bare `(C, D)` in the raw commands'
//!   shapes, the key unused; the raw `decrypt` takes the same shape under `vectors`.
//!
//! The same negative runs in one binding through the C ABI (`clients/ua-py`, `Pqz.test_no_oracle`). UNAUDITED.
#![allow(non_snake_case)]
mod pqz_chain;
use pqz_chain::*;
use pqz_ffi::stmt::{DELTA, PK_BYTES, Q};
use scaas_ua::facade::pqz::{AllowSecretExport, PqzCmd, PqzKey, COMMANDS};
use scaas_ua::facade::pqz_pack::{PKP, VP};
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
    // an old entry of the holder's (an op 1 blob, structurally valid): `proveDiscloseSender`'s words
    let blob = [vec![0x5a; 16], vec![0u8; PKP + VP], [0xB0; 32].to_vec(), vec![0u8; VP]].concat();
    let ptr = c.put(blob);
    let er = entry_ref(&A, 0);
    c.entries.insert(er, Ent { ptr, from: A, ctr: 0, memo: vec![] });
    let pk = format!("0x{}", hex::encode(k.pk()));
    let reqs = [
        ("balance", c.bal(&A)),
        ("proveRefresh", debit.clone()),
        ("proveBurn", merge(debit.clone(), json!({"amount": 1, "recipient": hx(&[0x0B; 32])}))),
        ("proveTransfer", merge(debit.clone(), json!({"toUA": hx(&A), "pkT": pk, "amount": 1, "mode": "BUNDLE"}))),
        ("proveTransferMulti", merge(debit, json!({"legs": [{"pk": pk, "ua": hx(&A), "amount": 1}], "mode": "BUNDLE"}))),
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
