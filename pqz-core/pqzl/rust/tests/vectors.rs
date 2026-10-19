//! The frozen vectors (smartcontracts/vectors/pqz, pq-zero-knowledge.md §14) against the Rust port. Keys part:
//! keygen.json, enc.json (rows, the trivial ciphertext and the Add / Sub ops), matrix.json, the R_TXM group seeds,
//! and Enc's input errors. Codec part (feature `test-hooks`): every PQZL proof decodes and re-encodes to itself.
//! Verify part: every PQZL proof verifies; negative.json's PQZL rows and the cheating fixtures are rejected.
use pqzl::{dec, enc_group_seed, enc_seed, keygen, keypair_from_secret, Ctx, Error, CT_BYTES, POLYVEC_BYTES};
use std::path::PathBuf;
use serde_json::Value;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Keccak256, Shake256};

mod common;
use common::{hex, json};

const Q: u64 = 4_398_046_510_889;
const DELTA: u64 = (1 << 26) - 1;

fn hex32(s: &Value) -> [u8; 32] {
    hex(s).try_into().expect("32 bytes")
}

fn kec(b: &[u8]) -> String {
    Keccak256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn be8(b: &[u8]) -> Vec<u64> {
    b.chunks(8).map(|c| u64::from_be_bytes(c.try_into().unwrap())).collect()
}

fn ints(v: &Value) -> Vec<i64> {
    v.as_array().unwrap().iter().map(|x| x.as_i64().unwrap()).collect()
}

fn digits(x: u64) -> [u8; 16] {
    core::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
}

/// Σ M_i 16^i, as pqz_kat.py's dec
fn value(m: &[i64; 16]) -> i128 {
    m.iter().rev().fold(0i128, |a, &d| a * 16 + d as i128)
}

#[test]
fn keygen_json() {
    let j = json("keygen.json");
    let rows = j["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 8);
    for r in rows {
        let k = keygen(&hex32(&r["seed"])).expect("keygen");
        let sq = |v: &mut dyn Iterator<Item = i64>| v.map(|x| x * x).sum::<i64>();
        assert_eq!(k.ctr as u64, r["ctr"].as_u64().unwrap());
        assert_eq!(kec(&k.pk[..]), r["pk_keccak"].as_str().unwrap(), "seed {}", r["seed"]);
        assert_eq!(be8(&k.pk[..32]), ints(&r["pk_first4"]).iter().map(|&x| x as u64).collect::<Vec<_>>());
        assert_eq!(sq(&mut k.s.iter().map(|&x| x as i64)), r["s_sq"].as_i64().unwrap());
        assert_eq!(sq(&mut k.e.iter().map(|&x| x as i64)), r["e_sq"].as_i64().unwrap());
    }
}

/// A = the columns pqz_keypair_from_secret(unit vector at poly j, 0) (matrix.json's own derivation)
#[test]
fn matrix_json() {
    let j = json("matrix.json");
    let cols: Vec<Box<[u8; POLYVEC_BYTES]>> = (0..32)
        .map(|c| {
            let mut s = [0i8; 2048];
            s[64 * c] = 1;
            keypair_from_secret(&s, &[0; 2048]).expect("keypair_from_secret")
        })
        .collect();
    let mut a = Vec::new(); // A[0][0], A[0][1], ...: row i of A is poly i of every column
    for i in 0..32 {
        for col in &cols {
            a.extend_from_slice(&col[512 * i..512 * (i + 1)]);
        }
    }
    let coeffs = |i: usize, c: usize, k: usize| be8(&cols[c][512 * i + 8 * k..512 * i + 8 * k + 64]);
    assert_eq!(a.len() as u64, j["a_bytes"].as_u64().unwrap());
    assert_eq!(kec(&a), j["a_keccak"].as_str().unwrap());
    let want = |k: &str| ints(&j[k]).iter().map(|&x| x as u64).collect::<Vec<_>>();
    assert_eq!(coeffs(0, 0, 0), want("A_0_0_first8"));
    assert_eq!(coeffs(0, 0, 56), want("A_0_0_last8"));
    assert_eq!(coeffs(31, 31, 0), want("A_31_31_first8"));
    assert_eq!(coeffs(31, 31, 56), want("A_31_31_last8"));
}

fn ct_of(u: &[u8], v: &[u8]) -> Box<[u8; CT_BYTES]> {
    let mut ct = Box::new([0u8; CT_BYTES]);
    ct[..POLYVEC_BYTES].copy_from_slice(u);
    ct[POLYVEC_BYTES..].copy_from_slice(v);
    ct
}

/// coefficient-wise (a ± b) mod q (pqz_kat.py ct_add / ct_sub)
fn ct_op(a: &[u8; CT_BYTES], b: &[u8; CT_BYTES], add: bool) -> Box<[u8; CT_BYTES]> {
    let mut r = Box::new([0u8; CT_BYTES]);
    for (k, (x, y)) in be8(a).into_iter().zip(be8(b)).enumerate() {
        let z = if add { (x + y) % Q } else { (x + Q - y) % Q };
        r[8 * k..8 * k + 8].copy_from_slice(&z.to_be_bytes());
    }
    r
}

#[test]
fn enc_json() {
    let j = json("enc.json");
    let mut cts = Vec::new();
    let rows = j["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 6);
    for (i, r) in rows.iter().enumerate() {
        let keys: Vec<_> =
            r["recipients"].as_array().unwrap().iter().map(|s| keygen(&hex32(s)).expect("keygen")).collect();
        let values: Vec<u64> = r["values"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        let pks: Vec<&[u8; POLYVEC_BYTES]> = keys.iter().map(|k| &*k.pk).collect();
        let msgs: Vec<[u8; 16]> = values.iter().map(|&v| digits(v)).collect();
        let c = enc_seed(&pks, &msgs, &hex32(&r["seed_enc"])).expect("enc_seed");
        assert_eq!(c.ctr as u64, r["ctr"].as_u64().unwrap(), "row {i}");
        assert_eq!(kec(&c.u[..]), r["u_keccak"].as_str().unwrap(), "row {i}");
        let legs = r["legs"].as_array().unwrap();
        assert_eq!(legs.len(), c.vs.len());
        for (k, leg) in legs.iter().enumerate() {
            assert_eq!(c.vs[k].to_vec(), hex(&leg["v"]), "row {i} leg {k}");
            let (m, _) = dec(&keys[k].s, &ct_of(&c.u[..], &c.vs[k])).expect("dec");
            assert_eq!(m.to_vec(), ints(&leg["M"]), "row {i} leg {k}");
            assert_eq!(value(&m), leg["value"].as_u64().unwrap() as i128);
            assert_eq!(value(&m), values[k] as i128);
        }
        cts.push(ct_of(&c.u[..], &c.vs[0]));
    }
    // Trivial(m): u = 0, v = Delta digits(m) mod q
    let trivial = |x: u64| {
        let mut ct = Box::new([0u8; CT_BYTES]);
        for (i, d) in digits(x).iter().enumerate() {
            ct[POLYVEC_BYTES + 8 * i..POLYVEC_BYTES + 8 * i + 8].copy_from_slice(&(DELTA * *d as u64).to_be_bytes());
        }
        ct
    };
    let t = &j["trivial"];
    assert_eq!(kec(&trivial(t["value"].as_u64().unwrap())[..]), t["ct_keccak"].as_str().unwrap());
    let ops = j["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 4);
    for o in ops {
        assert_eq!(o["a"], "row 0 leg 0");
        let b = match o["b"].as_str().unwrap() {
            "trivial 1000" => trivial(1000),
            "row 5 leg 0" => cts[5].clone(),
            b => panic!("op operand {b}"),
        };
        let c = ct_op(&cts[0], &b, o["op"] == "add");
        assert_eq!(kec(&c[..]), o["ct_keccak"].as_str().unwrap());
        let (m, _) = dec(&keygen(&hex32(&o["dec_key"])).unwrap().s, &c).expect("dec");
        assert_eq!(m.to_vec(), ints(&o["M"]), "op {} {}", o["op"], o["b"]);
        assert_eq!(value(&m), o["value"].as_u64().unwrap() as i128);
    }
}

/// g = 0: seed_enc; else SHAKE256("SCAAS-PQZ-ENC-GROUP-V1" || seed_enc || be4(g))[0..32) (P6-ANON D13). Fails on
/// Task 1's all-zero stub.
#[test]
fn enc_group_seed_eq_shake() {
    for i in 0..4u8 {
        let se: [u8; 32] = core::array::from_fn(|j| 17 * i + j as u8 + 1);
        assert_eq!(enc_group_seed(&se, 0), se);
        for g in [1u32, 2, 3, 0x0102_0304, u32::MAX] {
            let mut h = Shake256::default();
            h.update(b"SCAAS-PQZ-ENC-GROUP-V1");
            h.update(&se);
            h.update(&g.to_be_bytes());
            let mut want = [0u8; 32];
            h.finalize_xof().read(&mut want);
            let got = enc_group_seed(&se, g);
            assert_ne!(got, [0; 32]);
            assert_eq!(got, want, "seed_enc {i} g {g}");
        }
    }
}

/// pqz_enc_seed: a pk coefficient >= q or a digit > 15 -> Input; pqz_dec: a ct coefficient >= q -> Input
#[test]
fn enc_dec_input_errors() {
    let k = keygen(&[7; 32]).unwrap();
    let msg = [digits(0x0123_4567_89ab_cdef)];
    let c = enc_seed(&[&*k.pk], &msg, &[9; 32]).expect("enc_seed");
    let mut ct = ct_of(&c.u[..], &c.vs[0]);
    assert_eq!(dec(&k.s, &ct).unwrap().0.map(|d| d as u8), msg[0]);
    let mut pk = k.pk.clone();
    pk[POLYVEC_BYTES - 8..].copy_from_slice(&Q.to_be_bytes()); // the last coefficient = q
    assert_eq!(enc_seed(&[&*k.pk, &*pk], &[msg[0]; 2], &[9; 32]).err(), Some(Error::Input));
    let mut m = msg;
    m[0][15] = 16;
    assert_eq!(enc_seed(&[&*k.pk], &m, &[9; 32]).err(), Some(Error::Input));
    assert_eq!(enc_seed(&[&*k.pk], &[], &[9; 32]).err(), Some(Error::Input)); // one msg per pk
    ct[CT_BYTES - 8..].copy_from_slice(&(Q - 1).to_be_bytes());
    assert!(dec(&k.s, &ct).is_ok());
    ct[CT_BYTES - 8..].copy_from_slice(&Q.to_be_bytes()); // a v coefficient = q
    assert_eq!(dec(&k.s, &ct).err(), Some(Error::Input));
    ct[CT_BYTES - 8..].copy_from_slice(&[0; 8]);
    ct[..8].copy_from_slice(&[0xff; 8]); // a u coefficient >= q
    assert_eq!(dec(&k.s, &ct).err(), Some(Error::Input));
}

/// every PQZL proof of proof_pqzl.json (19 rows) and fee0.json (4 rows) decodes as its relation and re-encodes to the
/// same bytes (`test_mutate` with a kind past 14: decode, the verifier's reductions, encode)
#[cfg(feature = "test-hooks")]
#[test]
fn codec_roundtrip() {
    let mut n = 0;
    let pqzl = json("proof_pqzl.json");
    let fee0 = json("fee0.json");
    let rows = pqzl["rows"].as_array().unwrap().iter().map(|r| (r, &r["proof"]));
    for (r, proof) in rows.chain(fee0["rows"].as_array().unwrap().iter().map(|r| (r, &r["pqzl"]["proof"]))) {
        let code = common::rel_code(r["form"].as_str().unwrap(), r["statement"]["case"].as_str());
        let p = hex(proof);
        assert!(pqzl::test_mutate(code, &p, 99, 0, 0) == Ok(Some(p.clone())), "{} {}", r["form"], r["statement"]["case"]);
        n += 1;
    }
    assert_eq!(n, 23);
}

/// every PQZL proof of proof_pqzl.json and fee0.json, re-proved from the row's witness and rnd32, is the same bytes
/// (`PQZL_REPROVE`: only the rows whose name contains it)
#[test]
fn reprove_byte_equal() {
    let rows = common::pqzl_rows();
    assert_eq!(rows.len(), 23);
    let only = std::env::var("PQZL_REPROVE").unwrap_or_default();
    let mut ctx = pqzl::Ctx::new();
    for r in rows.iter().filter(|r| r.name.contains(&only)) {
        let p = ctx.prove(r.op, &r.stmt, &r.wit, &r.rnd32).unwrap_or_else(|e| panic!("{}: {e:?}", r.name));
        assert!(p == r.proof, "{}: {} bytes, want {}", r.name, p.len(), r.proof.len());
    }
}

/// `prove` refuses (`Error::Input`) a statement with one non-canonical coefficient (q) or one non-canonical header
/// word (a high byte set) for each statement parser, at places the witness parsers do not read: were the statement
/// parser to accept, the prover would return a proof or `Error::Internal` (the unchanged rows prove:
/// `reprove_byte_equal`)
#[test]
fn prove_refuses_noncanonical_statement() {
    let rows = common::pqzl_rows();
    let mut ctx = pqzl::Ctx::new();
    // (row, a coefficient of the first key, a header word): prefix 64, header 640, disclosure amount 224 / key 288
    let cases = [
        ("REGISTER", 96, None),
        ("TRANSFER", 640, Some(256)),
        ("BURN", 640, Some(288)),
        ("DISCLOSE-SENDER", 288, Some(224)),
        ("DISCLOSE-RECEIVER", 288, Some(224)),
        ("M2-on", 640, Some(320)),
    ];
    for (name, coef, word) in cases {
        let r = rows.iter().find(|r| r.name == name).unwrap();
        let mut st = r.stmt.clone();
        st[coef..coef + 8].copy_from_slice(&Q.to_be_bytes());
        assert_eq!(ctx.prove(r.op, &st, &r.wit, &r.rnd32), Err(Error::Input), "{name} coefficient");
        if let Some(w) = word {
            let mut st = r.stmt.clone();
            st[w] = 1;
            assert_eq!(ctx.prove(r.op, &st, &r.wit, &r.rnd32), Err(Error::Input), "{name} word");
        }
    }
}

/// every PQZL proof of proof_pqzl.json (six forms, REFRESH, AUDITOR, the eleven op 7 rows) and fee0.json verifies
#[test]
fn all_pqzl_proofs_verify() {
    let rows = common::pqzl_rows();
    assert_eq!(rows.len(), 23);
    let mut ctx = pqzl::Ctx::new();
    for r in &rows {
        assert!(ctx.verify(r.op, &r.stmt, &r.proof), "{}", r.name);
    }
}

/// every PQZL row of negative.json (Review Focus 2: length / op / M / auditorOn mismatches, non-canonical words,
/// edited proofs) is rejected by `verify` on the decoder's split (an input whose length field does not fit has no
/// statement to verify)
#[test]
fn negative_rows_reject() {
    let mut ctx = pqzl::Ctx::new();
    let rows = common::negative_inputs();
    // 367 since PQZL v3 (pqzl-fs3 Task 5): + 16 "retired PQZL v2 proofSystemId" rows, - 3 coder-padding rows (the
    // generator adds those only when the proof's last byte is < 0x80)
    assert_eq!(rows.len(), 367);
    let mut n = 0;
    for (name, b) in &rows {
        if let Some((op, stmt, proof)) = common::split(b) {
            assert!(!ctx.verify(op, stmt, proof), "{name}");
            n += 1;
        }
    }
    eprintln!("negative_rows_reject: {n} of {} rows split into (op, stmt, proof), all rejected", rows.len());
}

/// the cheating provers' proofs of check_tbox_fixes.sh (P6-L2: blocks over their own l2 bound within the pooled
/// budget, R_REG and R_TX, and the same prover's proof of an honest witness; P6-Z21: ||z21|| far above Bsq; z1 / w
/// norms over their bounds; z34poc.sh: z3 / z4 over their bounds) are rejected, the norm prover's honest control
/// accepted
#[test]
fn cheating_proofs_reject() {
    let mut ctx = pqzl::Ctx::new();
    for (case, op, stmt, proof, honest) in common::cheating() {
        assert_eq!(ctx.verify(op, &stmt, &proof), honest, "{case}");
    }
}

fn fnv(b: &[u8]) -> u32 {
    b.iter().fold(2166136261u32, |h, &x| (h ^ x as u32).wrapping_mul(16777619))
}

/// hex, "." for no bytes (one field of a space-separated line)
fn hx(b: &[u8]) -> String {
    if b.is_empty() {
        return ".".into();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// native = wasm32 (as ffi/wasm's digest lines): writes target/wasm-replay/in.txt (every PQZL vector row: op,
/// legs, statement, witness, rnd32, proof; every negative.json PQZL row that splits, by index: op, statement, proof) for
/// wasm/run_vectors.mjs, and target/wasm-replay/native.jsonl, one digest line per case: the proof's FNV-1a (the
/// vector's bytes, which `reprove_byte_equal` pins as the native prover's output; omitted for op 7 with M >
/// `WASM_MAX_LEGS`, refused on wasm32), the verify and verify_fast verdicts on this target. run.sh diffs the two.
#[test]
fn wasm_replay_inputs() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/wasm-replay");
    std::fs::create_dir_all(&dir).unwrap();
    let (mut inp, mut out) = (String::new(), String::new());
    let mut c = Ctx::new();
    for r in common::pqzl_rows() {
        let legs: usize = if r.op == 7 { r.name[1..].split('-').next().unwrap().parse().unwrap() } else { 0 };
        inp += &format!("row {} {} {legs} {} {} {} {}\n", r.name.replace(' ', "_"), r.op, hx(&r.stmt), hx(&r.wit),
                        hx(&r.rnd32), hx(&r.proof));
        let pv = if legs > pqzl::WASM_MAX_LEGS { String::new() } else { format!("\"prove\": \"{:08x}\", ", fnv(&r.proof)) };
        let (v, f) = (c.verify(r.op, &r.stmt, &r.proof), c.verify_fast(r.op, &r.stmt, &r.proof));
        assert!(v && f, "{}", r.name);
        out += &format!("{{\"row\": \"{}\", {pv}\"verify\": {}, \"verify_fast\": {}}}\n", r.name.replace(' ', "_"), v as u8, f as u8);
    }
    for (i, (_, b)) in common::negative_inputs().iter().enumerate() {
        let Some((op, st, pf)) = common::split(b) else { continue };
        inp += &format!("neg {i} {op} 0 {} . . {}\n", hx(st), hx(pf));
        let (v, f) = (c.verify(op, st, pf), c.verify_fast(op, st, pf));
        out += &format!("{{\"neg\": \"{i}\", \"verify\": {}, \"verify_fast\": {}}}\n", v as u8, f as u8);
    }
    std::fs::write(dir.join("in.txt"), inp).unwrap();
    std::fs::write(dir.join("native.jsonl"), out).unwrap();
}
