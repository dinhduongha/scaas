//! pqz-vectors (P6e Task 11; plan R4, D9, D13): writes every vector file of `smartcontracts/vectors/pqz/` (the one
//! canonical directory, read in place). Every value comes from this crate: `pqzl` (the C core: KeyGen, Enc, Dec, the
//! matrix, `encrypt` with chosen vectors), `prove` (PQZL by the C core, PQZH by Ligero); every expected output from the
//! C ABI `pqz_precompile` (and `selftest::selftest()`); for PQZL the generic verifier must agree with it. This binary
//! only drives them and writes JSON.
//!
//!   pqz-vectors [DIR]           write the files (default: ../../smartcontracts/vectors/pqz for the set n2048-kmax1024,
//!                               ../../smartcontracts/vectors/pqz/<set> for another set: pqz-ffi feature set-<set>)
//!   pqz-vectors --check [DIR]   regenerate in memory and compare byte for byte; exit 1 on any difference, on a
//!                               *.json in DIR that this generator does not write, or on stale self-test proofs
//!
//! The self-test's compiled-in proofs are the REGISTER rows of the files (build.rs): after a write that changes them,
//! rebuild and run --check (vectors/run.sh does). Independent checks: `pqz_kat.py --check` (Python),
//! `vectors/tamper.py`, `vectors/replay_wasm.mjs` (the same proofs from wasm32).
use std::path::PathBuf;
use std::time::Instant;

use pqz_ffi::stmt::{self as st, Bundle, Debit, Disclose, Form, Register, Stmt, FORMS};
use pqz_ffi::{pqz_precompile, pqzl, selftest, Reject, Word, INVALID, PQZH_ID, PQZL_ID, VALID};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Keccak256, Sha3_256, Shake256};

// The parameter set of this build (pqz-ffi feature `set-<set>`, owner 2026-10-21): every set-dependent number below
// comes from pqz-stmt's set constants (MAX_PROOF_PQZH and MAX_INPUT too) and, for PQZH, from pqzh-ligero at the set (its
// preset, element bytes EB); the n2048-kmax1024 files stay byte-identical. PQZH is in every set whose set.json says pqzh (plan
// 5h Task 8c part 2); a build without it writes the PQZL id's files only (no proof_pqzh.json, no PQZH rows).
const Q: u64 = st::Q;
const DELTA: u64 = st::DELTA as u64;
const PK: usize = st::PK_BYTES;
const N: usize = st::N;
const K: usize = st::K;
const BS: i64 = st::BETA_S as i64;
const BE: i64 = st::BETA_E as i64;
/// E = 2^(EBITS - 1): the proven |e_T| range (v3: 2^24)
const EB: u32 = st::EBITS - 1;
const E_RANGE: i64 = 1 << EB;
const V3: bool = matches!(st::SET.as_bytes(), b"n2048-kmax1024");

/// 12345 -> "12,345" (the descriptions' number format)
fn th(x: impl Into<i128>) -> String {
    let d = x.into().to_string();
    let (sign, d) = if let Some(t) = d.strip_prefix('-') { ("-", t.to_string()) } else { ("", d) };
    let mut out = String::new();
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    format!("{sign}{out}")
}

/// a `&'static str` of a formatted key or description (this binary runs once)
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

// ---------------------------------------------------------------- the crate's API (pqzl, prove, pqz_precompile)
struct Key {
    /// KeyGen seed (hex in the files), or a label for a key built from chosen (s, e)
    label: String,
    pk: Vec<u8>,
    s: Vec<i8>,
    e: Vec<i16>,
    ctr: u32,
}

fn keygen(seed: [u8; 32]) -> Key {
    let k = pqzl::keygen(&seed).expect("pqz keygen");
    Key { label: hex(&seed), pk: k.pk.to_vec(), s: k.s.to_vec(), e: k.e.to_vec(), ctr: k.ctr }
}

/// pk = A s + e from chosen short vectors (no norm check: the caller keeps them inside the proven norms)
fn key_from(label: &str, s: Vec<i8>, e: Vec<i16>) -> Key {
    let pk = pqzl::keypair_from_secret(&s[..].try_into().unwrap(), &e[..].try_into().unwrap()).expect("keypair");
    Key { label: label.into(), pk: pk.to_vec(), s, e, ctr: 0 }
}

impl Key {
    /// prover-API witness of a key (pqz.h, R3): s (int8) ‖ e (int16 LE)
    fn wit(&self) -> Vec<u8> {
        let mut w: Vec<u8> = self.s.iter().map(|&x| x as u8).collect();
        le16(&mut w, &self.e);
        w
    }
}

fn pk_ref(pk: &[u8]) -> &[u8; PK] {
    pk.try_into().unwrap()
}

struct Enc {
    seed: [u8; 32],
    recips: Vec<String>,
    values: Vec<u64>,
    u: Vec<u8>,
    vs: Vec<[u8; 128]>,
    r: Vec<i8>,
    e1: Vec<i16>,
    e2: Vec<[i16; 16]>,
    ctr: u32,
}

fn enc(keys: &[&Key], values: &[u64], seed: [u8; 32]) -> Enc {
    let pks: Vec<&[u8; PK]> = keys.iter().map(|k| pk_ref(&k.pk)).collect();
    let msgs: Vec<[u8; 16]> = values.iter().map(|&v| digits(v)).collect();
    let c = pqzl::enc(&pks, &msgs, &seed).expect("pqz enc");
    Enc {
        seed,
        recips: keys.iter().map(|k| k.label.clone()).collect(),
        values: values.to_vec(),
        u: c.u.to_vec(),
        vs: c.vs,
        r: c.r.to_vec(),
        e1: c.e1.to_vec(),
        e2: c.e2,
        ctr: c.ctr,
    }
}

/// encryption with chosen (r, e1, e2_j): (u, [v_j])
fn encrypt(keys: &[&Key], values: &[u64], r: &[i8], e1: &[i16], e2: &[[i16; 16]]) -> (Vec<u8>, Vec<[u8; 128]>) {
    let pks: Vec<&[u8; PK]> = keys.iter().map(|k| pk_ref(&k.pk)).collect();
    let msgs: Vec<[u8; 16]> = values.iter().map(|&v| digits(v)).collect();
    let (u, vs) = pqzl::encrypt(&pks, &msgs, r.try_into().unwrap(), e1.try_into().unwrap(), e2).expect("pqz encrypt");
    (u.to_vec(), vs)
}

impl Enc {
    fn ct(&self, leg: usize) -> Vec<u8> {
        [&self.u[..], &self.vs[leg][..]].concat()
    }
    /// r (int8) ‖ e1 (int16) ‖ e2 of the legs (int16 each)
    fn wit(&self, legs: &[usize]) -> Vec<u8> {
        let mut w: Vec<u8> = self.r.iter().map(|&x| x as u8).collect();
        le16(&mut w, &self.e1);
        legs.iter().for_each(|&l| le16(&mut w, &self.e2[l]));
        w
    }
    fn json(&self) -> J {
        o(vec![
            ("seed_enc", hx(&self.seed)),
            ("recipients", J::A(self.recips.iter().map(|s| J::from(s.as_str())).collect())),
            ("values", J::A(self.values.iter().map(|&v| J::from(v)).collect())),
        ])
    }
}

fn dec(s: &[i8], ct: &[u8]) -> ([i64; 16], [i64; 16]) {
    pqzl::dec(s.try_into().unwrap(), ct.try_into().unwrap()).expect("pqz dec")
}

fn value(m: &[i64; 16]) -> i128 {
    m.iter().rev().fold(0i128, |a, &x| a * 16 + x as i128)
}

fn prove(id: &Word, op: u8, stmt: &[u8], wit: &[u8], rnd: &[u8; 32]) -> Vec<u8> {
    assert_eq!(&stmt[32..64], id);
    pqz_ffi::prove(op, stmt, wit, rnd).unwrap_or_else(|e| panic!("prove op {op}: {e:?}"))
}

/// The precompile through the C ABI (`pqz_precompile`, P6f's entry): (output, reason). Output "1" / "0" / "revert";
/// reason = the decoder's `Reject`, or "verify" (decoded; the id's verifier decided). PQZL: the generic verifier must
/// agree with the precompile's specialised one (R5).
fn precompile(input: &[u8]) -> (&'static str, String) {
    let mut out = [0u8; 32];
    let rc = unsafe { pqz_precompile(input.as_ptr(), input.len(), out.as_mut_ptr(), 32) };
    match rc {
        pqz_ffi::PQZ_FFI_REVERT => return ("revert", "Input".into()),
        pqz_ffi::PQZ_FFI_OK => {}
        rc => panic!("pqz_precompile status {rc}"),
    }
    let res = if out == VALID { "1" } else if out == INVALID { "0" } else { "selftest" };
    let reason = match pqz_ffi::decode(input) {
        Err(r) => {
            assert_eq!(res, "0");
            rname(r)
        }
        Ok(inp) => {
            if inp.stmt.proof_system_id() == Some(&PQZL_ID) {
                let g = pqzl::verify_generic(inp.op, inp.stmt_bytes, inp.proof).expect("generic verify");
                assert_eq!(g, res == "1", "specialised and generic PQZL verifiers disagree");
            }
            "verify".into()
        }
    };
    (res, reason)
}

fn rname(r: Reject) -> String {
    match r {
        Reject::MustBeZero(f) => format!("MustBeZero({f})"),
        r => format!("{r:?}"),
    }
}

// ---------------------------------------------------------------- small helpers
fn keccak(parts: &[&[u8]]) -> Word {
    let mut h = <Keccak256 as sha3::Digest>::new();
    parts.iter().for_each(|p| sha3::Digest::update(&mut h, p));
    sha3::Digest::finalize(h).into()
}

fn shake256(parts: &[&[u8]], n: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    parts.iter().for_each(|p| h.update(p));
    let mut out = vec![0u8; n];
    h.finalize_xof().read(&mut out);
    out
}

fn fnv(b: &[u8]) -> String {
    format!("{:08x}", b.iter().fold(2166136261u32, |h, &x| (h ^ x as u32).wrapping_mul(16777619)))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn le16(out: &mut Vec<u8>, v: &[i16]) {
    v.iter().for_each(|x| out.extend_from_slice(&x.to_le_bytes()));
}

fn digits(x: u64) -> [u8; 16] {
    std::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
}

fn coeffs(b: &[u8]) -> Vec<u64> {
    b.chunks_exact(8).map(|c| u64::from_be_bytes(c.try_into().unwrap())).collect()
}

fn from_coeffs(c: &[u64]) -> Vec<u8> {
    c.iter().flat_map(|x| x.to_be_bytes()).collect()
}

/// a ± b mod q, coefficient-wise (Add / Sub of §4.2)
fn ct_add(a: &[u8], b: &[u8], sub: bool) -> Vec<u8> {
    let c: Vec<u64> =
        coeffs(a).iter().zip(coeffs(b)).map(|(&x, y)| if sub { (x + Q - y) % Q } else { (x + y) % Q }).collect();
    from_coeffs(&c)
}

/// Trivial(m): u = 0, v_i = Δ·m_i
fn trivial(v: u64) -> Vec<u8> {
    let mut c = vec![0u64; PK / 8];
    c.extend(digits(v).iter().map(|&d| DELTA * d as u64 % Q));
    from_coeffs(&c)
}

fn with_id(stmt: &[u8], id: &Word) -> Vec<u8> {
    let mut s = stmt.to_vec();
    s[32..64].copy_from_slice(id);
    s
}

fn auth_digest(stmt: &[u8]) -> Word {
    keccak(&[b"SCAAS-PQZ-AUTH-V1", &keccak(&[stmt])])
}

/// the ids whose proofs this build writes: PQZL, and PQZH where it is compiled in
const IDS: &[(&str, Word)] = if pqz_ffi::PQZH { &[("pqzl", PQZL_ID), ("pqzh", PQZH_ID)] } else { &[("pqzl", PQZL_ID)] };

/// another set's PQZL id, keccak256 of n2304-kmax4096's current label: the foreign id of the "other id" rows at a set
/// without PQZH (review 8d1b M2: its zero PQZH word would repeat the "unknown proofSystemId (zero word)" rows byte for
/// byte; R0 fix round m7: a live id, the retired ones have their own rows)
const FOREIGN_LABEL: &str = "scaas/pqz/lnp22/mlwe-d64k36-q46l4/v5";

/// the "other id" of a negative row (its name and word): the other proof system's id, and at a set without PQZH (PQZL
/// rows only) another set's PQZL id; both are unknown ids to this set's decoder or verifier
fn other_id(id: usize) -> (&'static str, Word) {
    if id != 0 {
        ("the other system's proofSystemId", PQZL_ID)
    } else if st::HAS_PQZH {
        ("the other system's proofSystemId", PQZH_ID)
    } else {
        let w = keccak(&[FOREIGN_LABEL.as_bytes()]);
        assert_ne!(w, PQZL_ID, "the foreign id is this set's");
        ("another set's proofSystemId (n2304-kmax4096 PQZL)", w)
    }
}

/// The retired ids of a system (decisions CTR-PQZ-09): PQZL v2 (forgeable, lazer#28; F6 / F9 path B) and v3, PQZH v1
/// (both replaced by the per-set ids of plan 5h Task 8d), and this set's own PQZL v4 / PQZH v2 of plan 5h Task 8d
/// (retired by the R0 review fix, 2026-10-25: its label with /v5 -> /v4, /v3 -> /v2); the negative rows "retired <name>
/// proofSystemId" put each on an honest input of that system, which every verifier must reject as an unknown id
fn retired_ids(id: usize) -> Vec<(&'static str, Word)> {
    let k = |l: &str| keccak(&[l.as_bytes()]);
    let prev = |l: &str, now: &str, was: &str| {
        assert!(l.ends_with(now), "{l}: not a {now} label");
        k(&format!("{}{was}", &l[..l.len() - now.len()]))
    };
    if id == 0 {
        let mut v = vec![
            ("PQZL v2", k("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")),
            ("PQZL v3", k("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v3")),
            ("PQZL v4", prev(st::PQZL_LABEL, "/v5", "/v4")),
        ];
        // a set without PQZH (n2816-kmax65536) has no PQZH rows: the retired PQZH v1 id goes on its PQZL inputs
        if !st::HAS_PQZH {
            v.push(("PQZH v1", k("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")));
        }
        v
    } else {
        vec![("PQZH v1", k("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")), ("PQZH v2", prev(st::PQZH_LABEL, "/v3", "/v2"))]
    }
}

fn fname(f: Form) -> &'static str {
    match f {
        Form::Transfer => "TRANSFER",
        Form::Transfer0 => "TRANSFER0",
        Form::Burn => "BURN",
        Form::Refresh => "REFRESH",
        Form::Register => "REGISTER",
        Form::DiscloseSender => "DISCLOSE-SENDER",
        Form::DiscloseReceiver => "DISCLOSE-RECEIVER",
        Form::DiscloseAuditor => "DISCLOSE-AUDITOR",
    }
}

fn sfile(f: Form) -> &'static str {
    match f {
        Form::Transfer | Form::Transfer0 => "statement_transfer.json",
        Form::Burn => "statement_burn.json",
        Form::Refresh => "statement_refresh.json",
        Form::Register => "statement_register.json",
        _ => "statement_disclose.json",
    }
}

fn fidx(f: Form) -> usize {
    FORMS.iter().position(|&x| x == f).unwrap()
}

// ---------------------------------------------------------------- JSON (fixed key order, deterministic layout)
#[derive(Clone)]
enum J {
    N(i128),
    S(String),
    B(bool),
    A(Vec<J>),
    O(Vec<(String, J)>),
}

macro_rules! jfrom {
    ($($t:ty),*) => { $(impl From<$t> for J { fn from(x: $t) -> J { J::N(x as i128) } })* };
}
jfrom!(u8, u32, u64, i64, i128, usize);
impl From<&str> for J {
    fn from(x: &str) -> J {
        J::S(x.into())
    }
}
impl From<String> for J {
    fn from(x: String) -> J {
        J::S(x)
    }
}
impl From<bool> for J {
    fn from(x: bool) -> J {
        J::B(x)
    }
}

fn o(kv: Vec<(&str, J)>) -> J {
    J::O(kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn hx(b: &[u8]) -> J {
    J::S(hex(b))
}

fn nums<T: Copy + Into<i128>>(v: &[T]) -> J {
    J::A(v.iter().map(|&x| J::N(x.into())).collect())
}

fn write(j: &J, ind: usize, out: &mut String) {
    let pad = |out: &mut String, n: usize| out.push_str(&" ".repeat(n));
    match j {
        J::N(n) => out.push_str(&n.to_string()),
        J::B(b) => out.push_str(if *b { "true" } else { "false" }),
        J::S(s) => {
            assert!(s.chars().all(|c| c != '"' && c != '\\' && !c.is_control()), "JSON string: {s}");
            out.push('"');
            out.push_str(s);
            out.push('"');
        }
        J::A(v) => {
            let scalars = v.iter().all(|x| !matches!(x, J::A(_) | J::O(_)));
            let mut one = String::new();
            if scalars {
                for (i, x) in v.iter().enumerate() {
                    one.push_str(if i > 0 { ", " } else { "" });
                    write(x, 0, &mut one);
                }
            }
            if scalars && one.len() <= 2000 {
                out.push('[');
                out.push_str(&one);
                out.push(']');
            } else {
                out.push_str("[\n");
                for (i, x) in v.iter().enumerate() {
                    pad(out, ind + 1);
                    write(x, ind + 1, out);
                    out.push_str(if i + 1 < v.len() { ",\n" } else { "\n" });
                }
                pad(out, ind);
                out.push(']');
            }
        }
        J::O(kv) => {
            out.push_str("{\n");
            for (i, (k, v)) in kv.iter().enumerate() {
                pad(out, ind + 1);
                out.push_str(&format!("\"{k}\": "));
                write(v, ind + 1, out);
                out.push_str(if i + 1 < kv.len() { ",\n" } else { "\n" });
            }
            pad(out, ind);
            out.push('}');
        }
    }
}

fn file(name: &str, desc: &str, mut body: Vec<(&str, J)>) -> (String, String) {
    let mut kv = vec![
        ("file", J::from(name)),
        ("description", J::from(desc)),
        ("generator", J::from("pqz-core/ffi src/bin/pqz-vectors.rs, P6e Task 11")),
    ];
    kv.append(&mut body);
    let mut s = String::new();
    write(&o(kv), 0, &mut s);
    s.push('\n');
    (name.to_string(), s)
}

// ---------------------------------------------------------------- statements
#[derive(Clone)]
enum V {
    I(u64),
    B(Vec<u8>),
}

const HNAMES: [&str; 20] = [
    "opTag", "proofSystemId", "chainId", "token", "registry", "fromUA", "toUA", "beneficiaryUA", "fee", "amount",
    "recipient", "sendCounter", "p", "validUntilBlock", "auditorOn", "plainUsed", "chainUid", "envelopeBinding", "salt",
    "memoHash",
];
const DNAMES: [&str; 9] = ["opTag", "proofSystemId", "chainId", "chainUid", "token", "registry", "entryRef", "amount", "kind"];

fn vword(v: &V) -> Word {
    match v {
        V::I(x) => st::u64_word(*x),
        V::B(b) => {
            let mut w = [0u8; 32];
            w[32 - b.len()..].copy_from_slice(b);
            w
        }
    }
}

fn fields_json(f: &[(&str, V)]) -> J {
    J::O(f.iter().map(|(k, v)| (k.to_string(), match v { V::I(x) => J::from(*x), V::B(b) => hx(b) })).collect())
}

/// header / disclosure words with the given fields (by name); opTag, proofSystemId (and R_TX's auditorOn) preset
fn set_words(w: &mut [Word], names: &[&str], f: &[(&str, V)]) {
    for (k, v) in f {
        w[names.iter().position(|n| n == k).unwrap_or_else(|| panic!("field {k}"))] = vword(v);
    }
}

fn get(f: &[(&str, V)], k: &str) -> Word {
    vword(&f.iter().find(|x| x.0 == k).unwrap().1)
}

fn entry_ref(f: &[(&str, V)]) -> Word {
    let t = keccak(&[b"SCAAS-PQZ-ENTRY-V1"]);
    keccak(&[&t, &get(f, "chainId"), &get(f, "chainUid"), &get(f, "token"), &get(f, "fromUA"), &get(f, "sendCounter")])
}

/// One statement form of the scenario: its PQZL-id statement (the PQZH one differs in bytes 32..63 only), witness,
/// rnd32, the statement-file row.
struct Row {
    form: Form,
    stmt: Vec<u8>,
    wit: Vec<u8>,
    rnd: [u8; 32],
    json: Vec<(&'static str, J)>,
}

fn stmt_json(form: Form, stmt: &[u8], fields: J, objects: J, mut extra: Vec<(&'static str, J)>) -> Vec<(&'static str, J)> {
    let ids = |f: &dyn Fn(&[u8]) -> Word| J::O(IDS.iter().map(|(n, id)| (n.to_string(), hx(&f(&with_id(stmt, id))))).collect());
    let mut v = vec![
        ("form", J::from(fname(form))),
        ("op", J::from(form.op())),
        (if form.op() <= st::OP_BURN { "header" } else { "words" }, fields),
        ("objects", objects),
        ("stmt_bytes", J::from(stmt.len())),
        ("stmt", hx(stmt)),
        ("stmt_keccak", ids(&|s| keccak(&[s]))),
        ("auth_digest", ids(&|s| auth_digest(s))),
    ];
    v.append(&mut extra);
    v
}

fn keyref(k: &Key) -> J {
    o(vec![("keygen", J::from(k.label.as_str()))])
}

struct Scenario {
    rows: Vec<Row>,
    bundle: Vec<u8>,
}

const SEED_F: [u8; 32] = [0x46; 32];
const SEED_T: [u8; 32] = [0x54; 32];
const SEED_A: [u8; 32] = [0x41; 32];
/// the self-test key, message, Enc seed and rnd32 (D13; pqz-ffi `selftest.rs`): the REGISTER rows are its proofs
const SEED_KEY: [u8; 32] = selftest::SEED_KEY;
const SEED_ENC_ST: [u8; 32] = selftest::SEED_ENC;
const RND_ST: [u8; 32] = selftest::RND;
const ST_VALUE: u64 = selftest::MSG_VALUE;

fn rnd_of(f: Form) -> [u8; 32] {
    if f == Form::Register {
        RND_ST
    } else {
        [0x80 + fidx(f) as u8; 32]
    }
}

/// The scenario with `fee` 7 (the main rows) or 0 (owner 2026-10-14: fee 0 is accepted; fee0.json's debit rows: no
/// beneficiary, Enc seeds and rnd32 of their own).
fn scenario(fee: u64) -> Scenario {
    let (kf, kt, ka, kr) = (keygen(SEED_F), keygen(SEED_T), keygen(SEED_A), keygen(SEED_KEY));
    let (bal0, plain, v) = (1_000_000u64, 1_000u64, 123_456u64);
    let off: u8 = if fee == 0 { 0x10 } else { 0 };
    let ben: Vec<(&str, V)> = if fee == 0 { vec![] } else { vec![("beneficiaryUA", V::B(vec![0xA3; 32]))] };
    let acc = enc(&[&kf], &[bal0], [0x61; 32]);
    let t = ct_add(&acc.ct(0), &trivial(plain), false);
    let bal = bal0 + plain;
    let bp = bal - v - fee;
    let out = enc(&[&kt, &kf, &ka], &[v, bp, v], [0x62 + off; 32]);
    let out0 = enc(&[&kt, &kf], &[v, bp], [0x62 + off; 32]);
    let bout = enc(&[&kf], &[bp], [0x64 + off; 32]);
    let rout = enc(&[&kf], &[bal - fee], [0x65 + off; 32]);
    let rnd = |f: Form| if fee == 0 { [0xA0 + fidx(f) as u8; 32] } else { rnd_of(f) };
    let tjson = |e: &Enc| {
        let J::O(mut kv) = e.json() else { unreachable!() };
        kv.push(("plus_trivial".into(), J::from(plain)));
        J::O(kv)
    };

    let common = vec![
        ("chainId", V::I(22776)),
        ("token", V::B(vec![0x11; 20])),
        ("registry", V::B(vec![0x22; 20])),
        ("fromUA", V::B(vec![0xA1; 32])),
    ];
    let tail = vec![
        ("sendCounter", V::I(3)),
        ("p", V::I(5)),
        ("validUntilBlock", V::I(1_000_000)),
        ("plainUsed", V::I(plain)),
        ("chainUid", V::B(vec![0xC1; 32])),
        ("envelopeBinding", V::B(vec![0xE1; 32])),
    ];
    let mut txf = common.clone();
    txf.push(("toUA", V::B(vec![0xA2; 32])));
    txf.extend(ben.clone());
    txf.push(("fee", V::I(fee)));
    txf.extend(tail.clone());
    txf.extend([("salt", V::B(vec![0x5A; 16])), ("memoHash", V::B(vec![0xD1; 32]))]);
    let mut burnf = common.clone();
    burnf.extend(ben.clone());
    burnf.extend([
        ("fee", V::I(fee)),
        ("amount", V::I(v)),
        ("recipient", V::B(vec![0x33; 20])),
    ]);
    burnf.extend(tail.clone());
    burnf.push(("memoHash", V::B(vec![0xD1; 32])));
    let mut reff = common.clone();
    reff.extend(ben.clone());
    reff.push(("fee", V::I(fee)));
    reff.extend(tail);
    reff.push(("memoHash", V::B(vec![0xD1; 32])));

    let debit = |form: Form, f: &[(&str, V)], e: &Enc| {
        let mut header = Debit::header(form, &PQZL_ID);
        set_words(&mut header, &HNAMES, f);
        let tr = matches!(form, Form::Transfer | Form::Transfer0);
        let aud = form == Form::Transfer;
        let d = Debit {
            form,
            header,
            pk_f: &kf.pk,
            pk_t: tr.then_some(&kt.pk[..]),
            pk_a: aud.then_some(&ka.pk[..]),
            t: &t,
            u: &e.u,
            v_t: tr.then(|| &e.vs[0][..]),
            v_f: &e.vs[if tr { 1 } else { 0 }],
            v_a: aud.then(|| &e.vs[2][..]),
        };
        let s = Stmt::Debit(d).encode().unwrap();
        st::parse(form.op(), &s).expect("debit statement canonical");
        s
    };
    let mut rows = Vec::new();
    let to_ua = get(&txf, "toUA");
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&get(&txf, "salt")[16..]);
    let eref = entry_ref(&txf);
    let mut bundle = Vec::new();
    for (form, e) in [(Form::Transfer, &out), (Form::Transfer0, &out0)] {
        let aud = form == Form::Transfer;
        let s = debit(form, &txf, e);
        let mut objs = vec![("pk_f", keyref(&kf)), ("pk_t", keyref(&kt))];
        if aud {
            objs.push(("pk_a", keyref(&ka)));
        }
        objs.extend([("T", tjson(&acc)), ("out", e.json())]);
        let b = Bundle { salt, u: &e.u, v_t: &e.vs[0], v_a: aud.then(|| &e.vs[2][..]), to_ua }.encode().unwrap();
        st::parse_bundle(&b).unwrap();
        let mut w = kf.wit();
        w.extend(e.wit(if aud { &[0, 1, 2] } else { &[0, 1] }));
        w.extend(digits(v));
        w.extend(digits(bp));
        let extra = vec![("entry_ref", hx(&eref)), ("bundle_bytes", J::from(b.len())), ("bundle_keccak", hx(&keccak(&[&b])))];
        if aud {
            bundle = b;
        }
        rows.push(Row { form, json: stmt_json(form, &s, fields_json(&txf), o(objs), extra), stmt: s, wit: w, rnd: rnd(form) });
    }
    for (form, f, e, newbal) in [(Form::Burn, &burnf, &bout, bp), (Form::Refresh, &reff, &rout, bal - fee)] {
        let s = debit(form, f, e);
        let objs = o(vec![("pk_f", keyref(&kf)), ("T", tjson(&acc)), ("out", e.json())]);
        let mut w = kf.wit();
        w.extend(e.wit(&[0]));
        w.extend(digits(newbal));
        rows.push(Row { form, json: stmt_json(form, &s, fields_json(f), objs, vec![]), stmt: s, wit: w, rnd: rnd(form) });
    }
    {
        let msg = keccak(&[b"SCAAS-PQZ-SELFTEST-V1"]);
        let s = Stmt::Register(Register { words: [Form::Register.op_tag(), PQZL_ID, msg], pk: &kr.pk }).encode().unwrap();
        let f = vec![("message", V::B(msg.to_vec()))];
        let objs = o(vec![("pk", keyref(&kr))]);
        rows.push(Row { form: Form::Register, json: stmt_json(Form::Register, &s, fields_json(&f), objs, vec![]), stmt: s, wit: kr.wit(), rnd: RND_ST });
    }
    for (form, kind, key, leg) in
        [(Form::DiscloseSender, 0u64, &kt, 0usize), (Form::DiscloseReceiver, 1, &kt, 0), (Form::DiscloseAuditor, 2, &ka, 2)]
    {
        let f = vec![
            ("chainId", V::I(22776)),
            ("chainUid", V::B(vec![0xC1; 32])),
            ("token", V::B(vec![0x11; 20])),
            ("registry", V::B(vec![0x22; 20])),
            ("entryRef", V::B(eref.to_vec())),
            ("amount", V::I(v)),
            ("kind", V::I(kind)),
        ];
        let mut words = Disclose::words(form, &PQZL_ID);
        set_words(&mut words, &DNAMES, &f);
        let s = Stmt::Disclose(Disclose { form, words, pk: &key.pk, u: &out.u, v: &out.vs[leg] }).encode().unwrap();
        st::parse(form.op(), &s).expect("disclosure canonical");
        let J::O(mut ct) = out.json() else { unreachable!() };
        ct.push(("leg".into(), J::from(leg)));
        let objs = o(vec![("pk", keyref(key)), ("ct", J::O(ct))]);
        let w = if form == Form::DiscloseSender { out.wit(&[0]) } else { key.wit() };
        rows.push(Row { form, json: stmt_json(form, &s, fields_json(&f), objs, vec![]), stmt: s, wit: w, rnd: rnd_of(form) });
    }
    for r in &rows {
        assert_eq!((r.stmt.len(), r.wit.len()), (r.form.stmt_len(), r.form.wit_len()), "{}", fname(r.form));
    }
    rows.sort_by_key(|r| fidx(r.form));
    Scenario { rows, bundle }
}

// ---------------------------------------------------------------- keys, CBD, matrix, encryption files
fn a_bytes() -> Vec<u8> {
    selftest::a_bytes().expect("A") // column j = pqz_keypair_from_secret(unit vector at poly j, 0)
}

fn matrix_file() -> (String, String) {
    let a = a_bytes();
    let poly = |i: usize, j: usize| coeffs(&a[(K * i + j) * 512..(K * i + j + 1) * 512]);
    let l = K - 1;
    let (p0, pl) = (poly(0, 0), poly(l, l));
    file(
        "matrix.json",
        leak(format!("The public matrix A (CTR-PQZ-03; SHAKE128 SCAAS-PQZ-A-V2, rejection to [0, q)): keccak256 of its bytes \
         (A[0][0], A[0][1], ..., 64 be8 coefficients each), first / last 8 coefficients of A[0][0] and A[{l}][{l}]. From the \
         C core: column j = pqz_keypair_from_secret(unit vector at poly j, 0).")),
        vec![
            ("a_bytes", J::from(a.len())),
            ("a_keccak", hx(&keccak(&[&a]))),
            ("A_0_0_first8", nums(&p0[..8])),
            ("A_0_0_last8", nums(&p0[56..])),
            (leak(format!("A_{l}_{l}_first8")), nums(&pl[..8])),
            (leak(format!("A_{l}_{l}_last8")), nums(&pl[56..])),
        ],
    )
}

fn sq<T: Copy + Into<i64>>(v: &[T]) -> i64 {
    v.iter().map(|&x| x.into() * x.into()).sum()
}

const KEYGEN_SEEDS: [[u8; 32]; 8] = [[0x00; 32], [0x01; 32], [0xff; 32], seq32(), SEED_F, SEED_T, SEED_A, SEED_KEY];

const fn seq32() -> [u8; 32] {
    let mut s = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        s[i] = i as u8;
        i += 1;
    }
    s
}

fn keygen_file() -> (String, String) {
    let rows = KEYGEN_SEEDS
        .iter()
        .map(|&seed| {
            let k = keygen(seed);
            o(vec![
                ("seed", hx(&seed)),
                ("ctr", J::from(k.ctr)),
                ("pk_keccak", hx(&keccak(&[&k.pk]))),
                ("pk_first4", nums(&coeffs(&k.pk[..32]))),
                ("s_sq", J::from(sq(&k.s))),
                ("e_sq", J::from(sq(&k.e))),
            ])
        })
        .collect();
    file(
        "keygen.json",
        leak(format!("KeyGen(seed32) of pq-zether.md 4.2 by the C core (pqz_keygen): SHAKE256(SCAAS-PQZ-KEYGEN-V2 || u8(len(set)) || set || \
         seed || be4(ctr)), set = the parameter set's name ({}; review R2-C3), \
         s <- CBD_1, e <- CBD_20, resample above {BS} / {BE}, pk = A s + e. ctr = the counter used. The searched-resample row \
         was dropped (probability about 2^-70 per seed); the resample path and the counter-64 error are pinned by the \
         test-hook KATs (pqz-core test/pqz_keys_kat.c, pqz_kat.py --c-keys).", st::SET)),
        vec![("rows", J::A(rows))],
    )
}

fn cbd_file() -> (String, String) {
    let mut rows = Vec::new();
    for seed in [[0x00; 32], SEED_F] {
        let k = keygen(seed);
        let stream = [&b"SCAAS-PQZ-KEYGEN-V2"[..], &[st::SET.len() as u8], st::SET.as_bytes(), &seed, &k.ctr.to_be_bytes()].concat();
        let e: Vec<i64> = k.e.iter().map(|&x| x as i64).collect();
        let s: Vec<i64> = k.s.iter().map(|&x| x as i64).collect();
        rows.push(o(vec![
            ("stream", hx(&stream)),
            ("parts", J::A(vec![
                part("s[0..64]", 1, 0, &s[..64]),
                part(leak(format!("s[{}..{N}]", N - 64)), 1, 2 * (N - 64), &s[N - 64..]),
                part("e[0..64]", 20, 2 * N, &e[..64]),
                part(leak(format!("e[{}..{N}]", N - 64)), 20, 2 * N + 40 * (N - 64), &e[N - 64..]),
            ])),
        ]));
    }
    let (kf, kt, ka) = (keygen(SEED_F), keygen(SEED_T), keygen(SEED_A));
    let x = enc(&[&kt, &kf, &ka], &[1, 2, 3], [0x62; 32]);
    let stream = [&b"SCAAS-PQZ-ENC-V1"[..], &x.seed, &x.ctr.to_be_bytes()].concat();
    let r: Vec<i64> = x.r.iter().map(|&v| v as i64).collect();
    let e1: Vec<i64> = x.e1.iter().map(|&v| v as i64).collect();
    let e2: Vec<Vec<i64>> = x.e2.iter().map(|l| l.iter().map(|&v| v as i64).collect()).collect();
    let o2 = 2 * N + 40 * N;
    rows.push(o(vec![
        ("stream", hx(&stream)),
        ("parts", J::A(vec![
            part("r[0..64]", 1, 0, &r[..64]),
            part("e1[0..64]", 20, 2 * N, &e1[..64]),
            part("e2_0", 20, o2, &e2[0]),
            part("e2_2", 20, o2 + 2 * 40 * 16, &e2[2]),
        ])),
    ]));
    file(
        "cbd.json",
        leak(format!("CBD_eta samples of the C core's KeyGen / Enc streams (pq-zether.md 4.2): stream = the SHAKE256 input (tag || seed \
         || be4(ctr)); bits LSB-first; a sample = (sum of eta bits) - (sum of the next eta bits) from bit_offset. KeyGen: s \
         (CBD_1, {N}) then e (CBD_20, {N}); Enc (3 recipients): r, e1, then e2_j (16 each).")),
        vec![("rows", J::A(rows))],
    )
}

fn part(what: &str, eta: u32, bit: usize, v: &[i64]) -> J {
    o(vec![("what", J::from(what)), ("eta", J::from(eta)), ("bit_offset", J::from(bit)), ("samples", nums(v))])
}

fn enc_file() -> (String, String) {
    let (kf, kt, ka) = (keygen(SEED_F), keygen(SEED_T), keygen(SEED_A));
    let key = |s: &str| [&kf, &kt, &ka].into_iter().find(|k| k.label == s).unwrap();
    let (v, bp, bal) = (123_456u64, 877_537u64, 1_001_000u64);
    let es = [
        enc(&[&kf], &[1_000_000], [0x61; 32]),
        enc(&[&kt, &kf, &ka], &[v, bp, v], [0x62; 32]),
        enc(&[&kt, &kf], &[v, bp], [0x62; 32]),
        enc(&[&kf], &[bp], [0x64; 32]),
        enc(&[&kf], &[bal - 7], [0x65; 32]),
        enc(&[&kf, &kt], &[0, u64::MAX], [0x66; 32]),
    ];
    let rows = es
        .iter()
        .map(|e| {
            let J::O(mut kv) = e.json() else { unreachable!() };
            let legs: Vec<J> = (0..e.recips.len())
                .map(|j| {
                    let (m, _) = dec(&key(&e.recips[j]).s, &e.ct(j));
                    assert_eq!(value(&m), e.values[j] as i128);
                    o(vec![("v", hx(&e.vs[j])), ("M", nums(&m)), ("value", J::from(value(&m)))])
                })
                .collect();
            kv.extend([
                ("ctr".into(), J::from(e.ctr)),
                ("u_keccak".into(), hx(&keccak(&[&e.u]))),
                ("legs".into(), J::A(legs)),
            ]);
            J::O(kv)
        })
        .collect();
    let leg = |r: usize| es[r].ct(0);
    let tr = trivial(1000);
    let ops = [
        ("add", leg(0), "trivial 1000", tr.clone()),
        ("sub", leg(0), "trivial 1000", tr.clone()),
        ("add", leg(0), "row 5 leg 0", leg(5)),
        ("sub", leg(0), "row 5 leg 0", leg(5)),
    ]
    .into_iter()
    .map(|(op, a, b, bb)| {
        let c = ct_add(&a, &bb, op == "sub");
        let (m, _) = dec(&kf.s, &c);
        o(vec![
            ("op", J::from(op)),
            ("a", J::from("row 0 leg 0")),
            ("b", J::from(b)),
            ("ct_keccak", hx(&keccak(&[&c]))),
            ("dec_key", hx(&SEED_F)),
            ("M", nums(&m)),
            ("value", J::from(value(&m))),
        ])
    })
    .collect();
    file(
        "enc.json",
        "Enc({(pk_j, m_j)}, seed_enc) of pq-zether.md 4.2 by the C core (pqz_enc_seed): SHAKE256(SCAAS-PQZ-ENC-V1 || \
         seed_enc || be4(ctr)), r <- CBD_1, e1 <- CBD_20, e2_j <- CBD_20^16; u = A^T r + e1, v_j = pk_j^T r + e2_j + Delta \
         digits(m_j). Recipients are keygen.json seeds; legs[j] = v_j and Dec by recipient j (pqz_dec: M, value; noise \
         omitted, pq-zether.md 14). ops: Add / Sub (coefficient-wise mod q) with Trivial(m) (u = 0, v = Delta digits(m)) \
         or another ciphertext, decrypted with dec_key.",
        vec![
            ("rows", J::A(rows)),
            ("trivial", o(vec![("value", J::from(1000u64)), ("ct_keccak", hx(&keccak(&[&tr])))])),
            ("ops", J::A(ops)),
        ],
    )
}

// ---------------------------------------------------------------- PQZH (Ligero): only where it is compiled in
/// Everything here that names the Ligero API; without PQZH in the build `IDS` has no PQZH id, so it is never called.
mod ph {
    use super::*;
    #[cfg_attr(not(feature = "pqzh"), allow(dead_code))]
    pub enum Shape {
        Form(Form),
        Multi(usize, bool),
    }

    #[cfg(feature = "pqzh")]
    fn rel(s: &Shape) -> pqzh_ligero::Rel {
        match *s {
            Shape::Form(f) => f.into(),
            Shape::Multi(m, aud) => pqzh_ligero::Rel::Multi { m, aud },
        }
    }

    /// the verifier's exact proof-length bound for the shape
    #[cfg(feature = "pqzh")]
    pub fn max_proof_len(s: Shape) -> usize {
        pqzh_ligero::Params::proven().max_proof_len(rel(&s))
    }

    /// D15 for PQZH proofs: canonical F_q elements (EB-byte BE < q; EB = 6 at n2048-kmax1024), opened columns in strictly increasing index order
    /// without repeats (the indices come from the transcript, so a swapped or repeated column block is the
    /// encoding-level form), the exact length bound
    #[cfg(feature = "pqzh")]
    pub fn negatives(s: Shape) -> Vec<(String, Vec<E>)> {
        let pp = pqzh_ligero::Params::proven();
        let eb = pqzh_ligero::fq::EB;
        let fe = 4 * (2 * (2 * pp.k - 1) + (2 * pp.k - 1 - pp.ell)); // F_q elements of w, q, h
        let col0 = 32 + eb * fe + 8;
        let q6 = Q.to_be_bytes()[8 - eb..].to_vec();
        let what = if matches!(s, Shape::Form(_)) { "form" } else { "shape" };
        let rl = rel(&s);
        let blk = 32 + eb * (pqzh_ligero::cs::Layout::new(rl, pp.ell).m + 12);
        vec![
            (format!("proof of max_proof_len({what}) + 1 bytes"), vec![E::ProofResize(pp.max_proof_len(rl) + 1)]),
            ("w coefficient 0 element = q".into(), vec![E::ProofSet(32, q6.clone())]),
            ("first opened column element 0 = q".into(), vec![E::ProofSet(col0 + 32, q6.clone())]),
            ("opened columns 0 and 1 swapped (not increasing)".into(), vec![E::ProofSwap(col0, col0 + blk, blk)]),
            ("opened column 0 repeated as column 1".into(), vec![E::ProofCopy(col0, col0 + blk, blk)]),
        ]
    }

    /// proof_pqzh.json's params
    #[cfg(feature = "pqzh")]
    pub fn params() -> J {
        let pp = pqzh_ligero::Params::proven();
        o(vec![
            ("n", J::from(pp.n)),
            ("k", J::from(pp.k)),
            ("ell", J::from(pp.ell)),
            ("t", J::from(pp.t)),
            ("pow_bits", J::from(pp.pow_bits)),
            ("max_proof", J::from(st::MAX_PROOF_PQZH)),
        ])
    }

    /// bytes per F_q element in PQZH proofs and the self-test's FFT
    #[cfg(feature = "pqzh")]
    pub fn eb() -> usize {
        pqzh_ligero::fq::EB
    }
    /// no PQZH: the self-test description's number only
    #[cfg(not(feature = "pqzh"))]
    pub fn eb() -> usize {
        6
    }

    #[cfg(not(feature = "pqzh"))]
    pub fn max_proof_len(_: Shape) -> usize {
        unreachable!("no PQZH in this build")
    }
    #[cfg(not(feature = "pqzh"))]
    pub fn negatives(_: Shape) -> Vec<(String, Vec<E>)> {
        unreachable!("no PQZH in this build")
    }
    #[cfg(not(feature = "pqzh"))]
    pub fn params() -> J {
        unreachable!("no PQZH in this build")
    }
}

// ---------------------------------------------------------------- negative inputs
#[derive(Clone)]
#[cfg_attr(not(feature = "pqzh"), allow(dead_code))] // the proof-byte edits of the PQZH rows
enum E {
    Op(u8),
    ProofFrom(Form),
    /// op 7: the proof of another case of statement_transfer_multi.json (same id)
    ProofFromCase(String),
    StmtSet(usize, Vec<u8>),
    StmtResize(usize),
    ProofResize(usize),
    StmtFlip(usize, u8),
    ProofFlip(usize, u8),
    ProofSet(usize, Vec<u8>),
    /// copy proof[src..src + len] over proof[dst..dst + len]
    ProofCopy(usize, usize, usize),
    /// swap proof[a..a + len] and proof[b..b + len]
    ProofSwap(usize, usize, usize),
    LenField(u32),
    InputResize(usize),
    Raw(Vec<u8>),
}

impl E {
    fn json(&self) -> J {
        let pair = |k: &str, a: usize, b: J| o(vec![(k, J::A(vec![J::from(a), b]))]);
        match self {
            E::Op(x) => o(vec![("op", J::from(*x))]),
            E::ProofFrom(f) => o(vec![("proof_from", J::from(fname(*f)))]),
            E::ProofFromCase(c) => o(vec![("proof_from", J::from(c.as_str()))]),
            E::StmtSet(at, b) => pair("stmt_set", *at, hx(b)),
            E::StmtResize(n) => o(vec![("stmt_resize", J::from(*n))]),
            E::ProofResize(n) => o(vec![("proof_resize", J::from(*n))]),
            E::StmtFlip(at, b) => pair("stmt_flip", *at, J::from(*b)),
            E::ProofFlip(at, b) => pair("proof_flip", *at, J::from(*b)),
            E::ProofSet(at, b) => pair("proof_set", *at, hx(b)),
            E::ProofCopy(a, b, n) => o(vec![("proof_copy", J::A(vec![J::from(*a), J::from(*b), J::from(*n)]))]),
            E::ProofSwap(a, b, n) => o(vec![("proof_swap", J::A(vec![J::from(*a), J::from(*b), J::from(*n)]))]),
            E::LenField(n) => o(vec![("len_field", J::from(*n))]),
            E::InputResize(n) => o(vec![("input_resize", J::from(*n))]),
            E::Raw(b) => o(vec![("raw", hx(b))]),
        }
    }
}

/// The precompile input of `edits` applied to the honest input of (form, id): op, statement, proof edited in order,
/// then the input built (`u8(op) ‖ be32(len_field or len(stmt)) ‖ stmt ‖ proof`, or `raw`) and resized.
fn apply(edits: &[E], form: Option<Form>, id: usize, stmts: &[Vec<u8>], proofs: &[[Vec<u8>; 8]; 2]) -> Vec<u8> {
    let (op, s, p) = match form {
        Some(f) => (f.op(), with_id(&stmts[fidx(f)], &IDS[id].1), proofs[id][fidx(f)].clone()),
        None => (0, vec![], vec![]),
    };
    apply_to(edits, op, s, p, id, proofs, &MProofs::new())
}

/// `edits` applied to the input `op`, statement `s`, proof `p` (of id `id`)
fn apply_to(edits: &[E], mut op: u8, mut s: Vec<u8>, mut p: Vec<u8>, id: usize, proofs: &[[Vec<u8>; 8]; 2], mp: &MProofs) -> Vec<u8> {
    let (mut lenf, mut raw, mut size) = (None, None, None);
    for e in edits {
        match e {
            E::Op(x) => op = *x,
            E::ProofFrom(f) => p = proofs[id][fidx(*f)].clone(),
            E::ProofFromCase(c) => p = mp[&(c.clone(), id)].clone(),
            E::StmtSet(at, b) => s[*at..*at + b.len()].copy_from_slice(b),
            E::StmtResize(n) => s.resize(*n, 0),
            E::ProofResize(n) => p.resize(*n, 0),
            E::StmtFlip(at, b) => s[*at] ^= 1 << b,
            E::ProofFlip(at, b) => p[*at] ^= 1 << b,
            E::ProofSet(at, b) => p[*at..*at + b.len()].copy_from_slice(b),
            E::ProofCopy(a, b, n) => p.copy_within(*a..*a + n, *b),
            E::ProofSwap(a, b, n) => {
                let x = p[*a..*a + n].to_vec();
                p.copy_within(*b..*b + n, *a);
                p[*b..*b + n].copy_from_slice(&x);
            }
            E::LenField(n) => lenf = Some(*n),
            E::InputResize(n) => size = Some(*n),
            E::Raw(b) => raw = Some(b.clone()),
        }
    }
    let mut input = raw.unwrap_or_else(|| {
        let mut x = vec![op];
        x.extend_from_slice(&lenf.unwrap_or(s.len() as u32).to_be_bytes());
        x.extend(s);
        x.extend(p);
        x
    });
    if let Some(n) = size {
        input.resize(n, 0);
    }
    input
}

fn negatives(proofs: &[[Vec<u8>; 8]; 2]) -> Vec<(String, Option<Form>, Option<usize>, Vec<E>)> {
    use Form::*;
    let mut v: Vec<(String, Option<Form>, Option<usize>, Vec<E>)> = Vec::new();
    let w = |x: u64| st::u64_word(x).to_vec();
    let qb = |x: u64| x.to_be_bytes().to_vec();
    for id in 0..IDS.len() {
        let mut add = |name: String, f: Form, e: Vec<E>| v.push((name, Some(f), Some(id), e));
        let pl = |f: Form| proofs[id][fidx(f)].len();
        for f in FORMS {
            let (n, nm) = (f.stmt_len(), fname(f));
            add(format!("{nm}: statement length - 1"), f, vec![E::StmtResize(n - 1)]);
            add(format!("{nm}: statement length + 1"), f, vec![E::StmtResize(n + 1)]);
            for op in 1..=5u8 {
                if op != f.op() {
                    add(format!("{nm}: under op {op}"), f, vec![E::Op(op)]);
                }
            }
            add(format!("{nm}: unknown proofSystemId (zero word)"), f, vec![E::StmtSet(32, vec![0; 32])]);
            add(format!("{nm}: {}", other_id(id).0), f, vec![E::StmtSet(32, other_id(id).1.to_vec())]);
            for (r, w) in retired_ids(id) {
                add(format!("{nm}: retired {r} proofSystemId"), f, vec![E::StmtSet(32, w.to_vec())]);
            }
            add(format!("{nm}: proof truncated by 1 byte"), f, vec![E::ProofResize(pl(f) - 1)]);
            add(format!("{nm}: proof extended by 1 zero byte"), f, vec![E::ProofResize(pl(f) + 1)]);
            add(format!("{nm}: proof byte 0 bit 0 flipped"), f, vec![E::ProofFlip(0, 0)]);
            add(format!("{nm}: proof middle byte bit 3 flipped"), f, vec![E::ProofFlip(pl(f) / 2, 3)]);
            add(format!("{nm}: proof last byte bit 7 flipped"), f, vec![E::ProofFlip(pl(f) - 1, 7)]);
        }
        for op in [0u8, 6, 7] {
            add(format!("TRANSFER: under op {op}"), Transfer, vec![E::Op(op)]);
        }
        let set = |at: usize, b: Vec<u8>| vec![E::StmtSet(at, b)];
        let d15: Vec<(&str, Form, Vec<E>)> = vec![
            (leak(format!("auditorOn 0 on the {}-byte form (R6)", th(Transfer.stmt_len() as i128))), Transfer, set(448, w(0))),
            ("auditorOn 2 (R6)", Transfer, set(448, w(2))),
            (leak(format!("auditorOn 1 on the {}-byte form (R6)", th(Transfer0.stmt_len() as i128))), Transfer0, set(448, w(1))),
            ("fee >= 2^64", Transfer, set(256 + 23, vec![1])),
            ("fee >= 2^64", Burn, set(256 + 23, vec![1])),
            ("fee >= 2^64", Refresh, set(256 + 23, vec![1])),
            ("amount >= 2^64", Burn, set(288 + 23, vec![1])),
            ("amount >= 2^64 (decoder stricter than R_TX)", Transfer, set(288 + 23, vec![1])),
            ("amount >= 2^64", DiscloseSender, set(224 + 23, vec![1])),
            ("salt word top byte set", Transfer, set(576, vec![1])),
            ("salt word byte 15 set", Transfer0, set(591, vec![0x80])),
            ("amount != 0", Transfer, set(319, vec![1])),
            ("recipient != 0", Transfer, set(351, vec![1])),
            ("recipient != 0", Transfer0, set(351, vec![1])),
            ("toUA != 0", Burn, set(223, vec![1])),
            ("auditorOn != 0", Burn, set(479, vec![1])),
            ("salt != 0", Burn, set(607, vec![1])),
            ("toUA != 0", Refresh, set(223, vec![1])),
            ("amount != 0", Refresh, set(319, vec![1])),
            ("recipient != 0", Refresh, set(351, vec![1])),
            ("auditorOn != 0", Refresh, set(479, vec![1])),
            ("salt != 0", Refresh, set(607, vec![1])),
            ("pk_f coefficient 0 = q", Transfer, set(640, qb(Q))),
            (leak(format!("pk_a coefficient 0 = 2^{}", st::LOG2Q)), Transfer, set(640 + 2 * PK, qb(1 << st::LOG2Q))),
            ("T coefficient 0 = q", Transfer, set(640 + 3 * PK, qb(Q))),
            ("u coefficient 0 = 2^64 - 1", Transfer, set(640 + 3 * PK + st::CT_BYTES, qb(u64::MAX))),
            ("v_a last coefficient = q", Transfer, set(Transfer.stmt_len() - 8, qb(Q))),
            ("v_f last coefficient = q", Transfer0, set(Transfer0.stmt_len() - 8, qb(Q))),
            ("v_f last coefficient = q", Burn, set(Burn.stmt_len() - 8, qb(Q))),
            ("pk coefficient 0 = q", Register, set(96, qb(Q))),
            (leak(format!("pk last coefficient = 2^{}", st::LOG2Q)), Register, set(Register.stmt_len() - 8, qb(1 << st::LOG2Q))),
            ("pk coefficient 0 = q", DiscloseSender, set(288, qb(Q))),
            ("u coefficient 0 = q", DiscloseReceiver, set(288 + PK, qb(Q))),
            ("v last coefficient = q", DiscloseAuditor, set(DiscloseAuditor.stmt_len() - 8, qb(Q))),
            ("REFRESH opTag on the BURN statement", Burn, set(0, Refresh.op_tag().to_vec())),
            ("BURN opTag on the REFRESH statement", Refresh, set(0, Burn.op_tag().to_vec())),
            ("AUDITOR opTag on the RECEIVER statement", DiscloseReceiver, set(0, DiscloseAuditor.op_tag().to_vec())),
            ("RECEIVER opTag on the AUDITOR statement", DiscloseAuditor, set(0, DiscloseReceiver.op_tag().to_vec())),
            ("REGISTER opTag under op 1", Transfer, set(0, Register.op_tag().to_vec())),
            ("RECEIVER opTag under op 4", DiscloseSender, set(0, DiscloseReceiver.op_tag().to_vec())),
            ("message bit flipped (the self-test's invalid case)", Register, vec![E::StmtFlip(95, 0)]),
            ("chainId bit flipped", Transfer, vec![E::StmtFlip(64 + 31, 0)]),
            ("pk_f coefficient 0 low bit flipped", Transfer, vec![E::StmtFlip(640 + 7, 0)]),
            ("v_f low bit flipped", Transfer0, vec![E::StmtFlip(Transfer0.stmt_len() - 1, 0)]),
            ("kind word changed", DiscloseSender, vec![E::StmtFlip(256 + 31, 0)]),
            // kind = OpeningKind + 256 w (R0-1): w = 0 but for AUDITOR (w < S_AUD), the word < 2^16 (decoder: Kind)
            ("kind window 1", DiscloseSender, set(256 + 30, vec![1])),
            ("kind window 1", DiscloseReceiver, set(256 + 30, vec![1])),
            (leak(format!("kind window {} (S_AUD)", st::S_AUD)), DiscloseAuditor, set(256 + 30, vec![st::S_AUD as u8])),
            ("kind word 2^16", DiscloseAuditor, set(256 + 29, vec![1])),
            ("amount + 1", DiscloseSender, set(224 + 24, qb(123_457))),
            ("amount + 1", Burn, set(288 + 24, qb(123_457))),
            ("TRANSFER0's proof", Transfer, vec![E::ProofFrom(Transfer0)]),
            ("REFRESH's proof", Burn, vec![E::ProofFrom(Refresh)]),
            ("DISCLOSE-RECEIVER's proof", DiscloseSender, vec![E::ProofFrom(DiscloseReceiver)]),
            ("DISCLOSE-RECEIVER's proof", Register, vec![E::ProofFrom(DiscloseReceiver)]),
            ("BURN statement with TRANSFER's proof under op 2", Burn, vec![E::ProofFrom(Transfer)]),
            ("empty proof", Transfer, vec![E::ProofResize(0)]),
            ("proof of MAX_PROOF(id) + 1 bytes", Transfer, vec![E::ProofResize(st::max_proof(&IDS[id].1).unwrap() + 1)]),
            ("proof of MAX_PROOF(id) + 1 bytes", Register, vec![E::ProofResize(st::max_proof(&IDS[id].1).unwrap() + 1)]),
            ("input of MAX_INPUT + 1 bytes (expected revert, P6f)", Transfer, vec![E::InputResize(st::MAX_INPUT + 1)]),
            ("length field 0xffffffff", Transfer, vec![E::LenField(u32::MAX)]),
            ("length field = statement + proof + 1", Transfer, vec![E::LenField((Transfer.stmt_len() + pl(Transfer) + 1) as u32)]),
            ("length field = statement + 1", Transfer, vec![E::LenField(Transfer.stmt_len() as u32 + 1)]),
            ("input of 4 bytes", Transfer, vec![E::InputResize(4)]),
            ("proof of exactly MAX_PROOF(id) bytes", Transfer, vec![E::ProofResize(st::max_proof(&IDS[id].1).unwrap())]),
            ("input of exactly MAX_INPUT bytes (not a revert)", Transfer, vec![E::InputResize(st::MAX_INPUT)]),
        ];
        for (name, f, e) in d15 {
            add(format!("{}: {name}", fname(f)), f, e);
        }
        if IDS[id].1 == PQZH_ID {
            for f in FORMS {
                for (name, e) in ph::negatives(ph::Shape::Form(f)) {
                    add(format!("{}: {name}", fname(f)), f, e);
                }
            }
        } else {
            // D15 for PQZL proofs: the LaZer coder's final 1-bit then zero padding (bits LSB-first): a padding bit set
            for f in FORMS {
                let p = &proofs[id][fidx(f)];
                let last = *p.last().unwrap();
                if last < 0x80 {
                    add(format!("{}: coder padding bit 7 set after the final 1-bit", fname(f)), f, vec![E::ProofFlip(p.len() - 1, 7)]);
                }
            }
        }
    }
    v.push(("SELFTEST with a 1-byte proof".into(), None, None, vec![E::Raw(vec![6, 0, 0, 0, 0, 0])]));
    v.push(("SELFTEST with a 1-byte statement".into(), None, None, vec![E::Raw(vec![6, 0, 0, 0, 1, 0])]));
    v.push(("op 6 with an empty input tail of 3 bytes".into(), None, None, vec![E::Raw(vec![6, 0, 0, 0])]));
    v
}

// ---------------------------------------------------------------- worst-case noise (pq-zether.md 4.3, 14)
const WC_RECV: [u8; 32] = [0x57; 32];
const WC_GEN: [u8; 32] = [0x58; 32];
const WC_OUT: [u8; 32] = [0x59; 32];
const WC_RND: [u8; 32] = [0x90; 32];
const K_MAX: usize = st::K_MAX;
const B_R: i64 = BS * BS;
const B_E1: i64 = BE * BE;
const CREDIT: u64 = (1 << 48) - 1;
const B_FRESH: i64 = BE * BS + BS * BE + 64;
const _: () = assert!(K_MAX as u128 * CREDIT as u128 <= u64::MAX as u128, "worst case: K_MAX credits overflow a value");

/// coefficient-0 weights: (x·y)[0] = Σ_k rot(x)_k y_k in Z[X]/(X^64 + 1), per poly
fn rot(x: &[i64]) -> Vec<i64> {
    (0..N).map(|i| if i % 64 == 0 { x[i] } else { -x[i - i % 64 + 64 - i % 64] }).collect()
}

/// max Σ w_k r_k over integers with Σ r_k² ≤ b: greedy over the increments (k, a) (|r_k| a → a + 1, gain |w_k|,
/// cost 2a + 1) by gain / cost descending, ties by (k, a); an increment is taken while the cost fits
fn align_r(w: &[i64], b: i64) -> Vec<i64> {
    let mut c: Vec<(i64, i64, usize)> =
        (0..N).filter(|&k| w[k] != 0).flat_map(|k| (0..BS).map(move |a| (w[k].abs(), a, k))).collect();
    c.sort_by(|x, y| (y.0 * (2 * x.1 + 1)).cmp(&(x.0 * (2 * y.1 + 1))).then(x.2.cmp(&y.2)).then(x.1.cmp(&y.1)));
    let (mut r, mut left) = (vec![0i64; N], b);
    for (_, a, k) in c {
        if 2 * a + 1 <= left {
            left -= 2 * a + 1;
            r[k] += w[k].signum();
        }
    }
    r
}

/// credit k's e1: every coordinate with z ≠ 0 at level L (the largest with L²·N ≤ B_E1), X = (B_E1 − L²N) / (2L + 1) of
/// them at L + 1 (the X smallest by (prio, index), prio_i = be32 of SHAKE256(SCAAS-PQZ-WORSTCASE-V1 ‖ gen ‖ be4(k))
/// bytes 4i..4i+4); sign −sign(z) so that −Σ z·e1 = L·N + X
fn align_e1(z: &[i64], k: u32) -> Vec<i64> {
    let s: Vec<usize> = (0..N).filter(|&i| z[i] != 0).collect();
    let n = s.len() as i64;
    let mut l = 0;
    while (l + 1) * (l + 1) * n <= B_E1 {
        l += 1;
    }
    let x = ((B_E1 - l * l * n) / (2 * l + 1)) as usize;
    let pr = shake256(&[b"SCAAS-PQZ-WORSTCASE-V1", &WC_GEN, &k.to_be_bytes()], 4 * N);
    let mut ord = s.clone();
    ord.sort_by_key(|&i| (u32::from_be_bytes(pr[4 * i..4 * i + 4].try_into().unwrap()), i));
    let mut e1 = vec![0i64; N];
    for (rank, &i) in ord.iter().enumerate() {
        e1[i] = -z[i].signum() * (l + (rank < x) as i64);
    }
    e1
}

/// the worst-case files' margin key: against the proven range E = 2^EB (v3: margin_2_24)
const MARGIN_E: &str = match EB {
    24 => "margin_2_24",
    26 => "margin_2_26",
    28 => "margin_2_28",
    30 => "margin_2_30",
    _ => panic!("margin key for this E"),
};
/// "both systems" (v3) or "PQZL" (a build without PQZH)
const SYS: &str = if pqz_ffi::PQZH { "both systems" } else { "PQZL (PQZH not in this set's build)" };

fn ids_keccak(stmt: &[u8]) -> J {
    J::O(IDS.iter().map(|(n, id)| (n.to_string(), hx(&keccak(&[&with_id(stmt, id)])))).collect())
}

/// both ids' proofs of `stmt` (PQZL-id bytes), each valid through pqz_precompile (and the generic PQZL verifier)
fn proofs_json(op: u8, stmt: &[u8], wit: &[u8], rnd: &[u8; 32]) -> Vec<(&'static str, J)> {
    (0..IDS.len())
        .map(|i| {
            let s = with_id(stmt, &IDS[i].1);
            let p = prove(&IDS[i].1, op, &s, wit, rnd);
            assert_eq!(precompile(&st::input(op, &s, &p)), ("1", "verify".to_string()), "worst case {}", IDS[i].0);
            let j = o(vec![("proof_bytes", J::from(p.len())), ("proof_keccak", hx(&keccak(&[&p]))), ("proof_fnv", J::from(fnv(&p))), ("proof", hx(&p))]);
            (IDS[i].0, j)
        })
        .collect()
}

fn ratio(a: i64, b: i64) -> String {
    format!("{}.{:02}", a / b, a * 100 / b % 100)
}

/// T = n·ct + Trivial(plain) mod q
fn aggregate(ct: &[u8], n: u64, plain: u64) -> Vec<u8> {
    let c: Vec<u64> = coeffs(ct).iter().map(|&x| ((x as u128 * n as u128) % Q as u128) as u64).collect();
    ct_add(&from_coeffs(&c), &trivial(plain), false)
}

/// The receiver's debit R_TX over T: out = Enc({T: v, receiver: bp, A: v}, WC_OUT), v = 1,000,000, fee 7.
fn debit(kr: &Key, kt: &Key, ka: &Key, t: &[u8], bal: u64, plain: u64, from: u8, rnd: [u8; 32]) -> J {
    let (v, fee) = (1_000_000u64, 7u64);
    let bp = bal - v - fee;
    let out = enc(&[kt, kr, ka], &[v, bp, v], WC_OUT);
    let f = vec![
        ("chainId", V::I(22776)),
        ("token", V::B(vec![0x11; 20])),
        ("registry", V::B(vec![0x22; 20])),
        ("fromUA", V::B(vec![from; 32])),
        ("toUA", V::B(vec![0xA2; 32])),
        ("fee", V::I(fee)),
        ("sendCounter", V::I(1)),
        ("p", V::I(K_MAX as u64 - 1)),
        ("validUntilBlock", V::I(1_000_000)),
        ("plainUsed", V::I(plain)),
        ("chainUid", V::B(vec![0xC1; 32])),
        ("salt", V::B(vec![0x5B; 16])),
    ];
    let mut header = Debit::header(Form::Transfer, &PQZL_ID);
    set_words(&mut header, &HNAMES, &f);
    let d = Debit {
        form: Form::Transfer,
        header,
        pk_f: &kr.pk,
        pk_t: Some(&kt.pk),
        pk_a: Some(&ka.pk),
        t,
        u: &out.u,
        v_t: Some(&out.vs[0]),
        v_f: &out.vs[1],
        v_a: Some(&out.vs[2]),
    };
    let stmt = Stmt::Debit(d).encode().unwrap();
    let mut wit = kr.wit();
    wit.extend(out.wit(&[0, 1, 2]));
    wit.extend(digits(v));
    wit.extend(digits(bp));
    let mut kv = vec![
        ("form", J::from("TRANSFER")),
        ("op", J::from(1u8)),
        ("header", fields_json(&f)),
        ("objects", o(vec![
            ("pk_f", keyref(kr)),
            ("pk_t", keyref(kt)),
            ("pk_a", keyref(ka)),
            ("T", J::from("the aggregate T above")),
            ("out", out.json()),
        ])),
        ("stmt_bytes", J::from(stmt.len())),
        ("stmt", hx(&stmt)),
        ("stmt_keccak", ids_keccak(&stmt)),
        ("wit", hx(&wit)),
        ("wit_keccak", hx(&keccak(&[&wit]))),
        ("rnd32", hx(&rnd)),
    ];
    kv.extend(proofs_json(1, &stmt, &wit, &rnd));
    o(kv)
}

fn sparse<T: Copy + Into<i64>>(v: &[T]) -> J {
    J::A(v.iter().enumerate().filter(|x| (*x.1).into() != 0).map(|(i, &x)| nums(&[(i / 64) as i64, (i % 64) as i64, x.into()])).collect())
}

/// The worst the verifier accepts (controller 2026-10-14): an attacker-registered receiver key at the norm bounds, its
/// R_REG proved; each credit at B_FRESH exactly; the sender's R_TX of a credit proved (credit 0 and the last).
fn bound_case(kf: &Key, kt: &Key, ka: &Key) -> J {
    let mut s = vec![0i8; N];
    s[64] = BS as i8; // poly 1, coefficient 0 (poly 0 carries R_REG's approximate l_inf filler, |s[0]| <= 1)
    let mut e = vec![0i16; N];
    e[0] = BE as i16; // poly 0, coefficient 0
    let kr = key_from("receiver", s, e);
    let msg = keccak(&[b"SCAAS-PQZ-WORSTCASE-KEY-V1"]);
    let reg = Stmt::Register(Register { words: [Form::Register.op_tag(), PQZL_ID, msg], pk: &kr.pk }).encode().unwrap();
    let rrnd = [0x91u8; 32];
    let mut regj = vec![
        ("message", hx(&msg)),
        ("stmt_keccak", ids_keccak(&reg)),
        ("wit", hx(&kr.wit())),
        ("rnd32", hx(&rrnd)),
    ];
    regj.extend(proofs_json(3, &reg, &kr.wit(), &rrnd));

    let w = rot(&kr.e.iter().map(|&x| x as i64).collect::<Vec<_>>());
    let z = rot(&kr.s.iter().map(|&x| x as i64).collect::<Vec<_>>());
    let mut r = vec![0i8; N];
    r[0] = BS as i8; // along rot(e)
    let mut e1 = vec![0i16; N];
    e1[64] = -BE as i16; // against rot(s)
    let mut e2 = [0i16; 16];
    e2[0] = 64;
    let wr: i64 = w.iter().zip(&r).map(|(a, &b)| a * b as i64).sum();
    let ze: i64 = -z.iter().zip(&e1).map(|(a, &b)| a * b as i64).sum::<i64>();
    assert_eq!((wr, ze), (BE * BS, BS * BE));
    let (u1, v1) = encrypt(&[&kr], &[CREDIT], &r, &e1, &[e2]);
    let ct = [&u1[..], &v1[0][..]].concat();
    let (_, nz) = dec(&kr.s, &ct);
    assert_eq!(nz[0], B_FRESH, "credit noise = B_FRESH");

    // the sender (F) proves the credit: R_TX with r, e1, e2_t as above (e2_f = e2_a = 0)
    let acc = enc(&[kf], &[CREDIT + 7], [0x6A; 32]);
    let ts = ct_add(&acc.ct(0), &trivial(1000), false);
    let (u, vs) = encrypt(&[&kr, kf, ka], &[CREDIT, 1000, CREDIT], &r, &e1, &[e2, [0; 16], [0; 16]]);
    assert_eq!([&u[..], &vs[0][..]].concat(), ct);
    let sf = vec![
        ("chainId", V::I(22776)),
        ("token", V::B(vec![0x11; 20])),
        ("registry", V::B(vec![0x22; 20])),
        ("fromUA", V::B(vec![0xA1; 32])),
        ("toUA", V::B(vec![0xB2; 32])),
        ("beneficiaryUA", V::B(vec![0xA3; 32])),
        ("fee", V::I(7)),
        ("p", V::I(5)),
        ("validUntilBlock", V::I(1_000_000)),
        ("plainUsed", V::I(1000)),
        ("chainUid", V::B(vec![0xC1; 32])),
        ("salt", V::B(vec![0x5C; 16])),
    ];
    let mut sw = kf.wit();
    sw.extend(r.iter().map(|&x| x as u8));
    le16(&mut sw, &e1);
    for x in [e2, [0; 16], [0; 16]] {
        le16(&mut sw, &x);
    }
    sw.extend(digits(CREDIT));
    sw.extend(digits(1000));
    let rows: Vec<J> = [(0u64, [0x92u8; 32]), (K_MAX as u64 - 2, [0x93; 32])]
        .into_iter()
        .map(|(k, rnd)| {
            let mut f = sf.clone();
            f.push(("sendCounter", V::I(k)));
            let mut header = Debit::header(Form::Transfer, &PQZL_ID);
            set_words(&mut header, &HNAMES, &f);
            let d = Debit {
                form: Form::Transfer,
                header,
                pk_f: &kf.pk,
                pk_t: Some(&kr.pk),
                pk_a: Some(&ka.pk),
                t: &ts,
                u: &u,
                v_t: Some(&vs[0]),
                v_f: &vs[1],
                v_a: Some(&vs[2]),
            };
            let stmt = Stmt::Debit(d).encode().unwrap();
            let mut kv = vec![("credit", J::from(k)), ("sendCounter", J::from(k)), ("stmt", hx(&stmt)), ("stmt_keccak", ids_keccak(&stmt)), ("rnd32", hx(&rnd))];
            kv.extend(proofs_json(1, &stmt, &sw, &rnd));
            o(kv)
        })
        .collect();

    let ncr = K_MAX as u64 - 1;
    let t = aggregate(&ct, ncr, CREDIT);
    let (tm, tn) = dec(&kr.s, &t);
    assert_eq!((value(&tm), tn[0]), (K_MAX as i128 * CREDIT as i128, ncr as i64 * B_FRESH));
    let maxn = tn.iter().map(|x| x.abs()).max().unwrap();
    let mint = DELTA as i64 - E_RANGE;
    o(vec![
        ("note", J::from(format!(
            "The worst case the verifier accepts: a receiver key at the norm bounds (s = {BS} at one coefficient outside poly 0, \
             whose |coefficients| <= 1 R_REG's approximate l_inf filler proves; e = {BE} at one coefficient), registered \
             (its R_REG proves and verifies in {SYS}), every credit at noise B_FRESH = {BE}*{BS} + {BS}*{BE} + 64 in \
             coefficient 0 (r = {BS} along rot(e), e1 = -{BE} against rot(s), e2_t = (64, 0, ...)), each credit the same \
             ciphertext (the maximum is unique), proved by its sender's R_TX (credit 0 and the last shown, {SYS}), \
             plus the plain unit (noise 0): T noise = {} * {} = {}.",
            th(ncr as i128), th(B_FRESH), th(ncr as i128 * B_FRESH as i128),
        ))),
        ("receiver", o(vec![("s", sparse(&kr.s)), ("e", sparse(&kr.e)), ("pk_keccak", hx(&keccak(&[&kr.pk]))), ("register", o(regj))])),
        ("credit", o(vec![
            ("r", sparse(&r)),
            ("e1", sparse(&e1)),
            ("e2", nums(&e2)),
            ("value", J::from(CREDIT)),
            ("ct_keccak", hx(&keccak(&[&ct]))),
            ("noise0", J::from(nz[0])),
        ])),
        ("sender", o(vec![
            ("key", keyref(kf)),
            ("auditor", keyref(ka)),
            ("T", {
                let J::O(mut kv) = acc.json() else { unreachable!() };
                kv.push(("plus_trivial".into(), J::from(1000u64)));
                J::O(kv)
            }),
            ("out_values", nums(&[CREDIT, 1000, CREDIT])),
            ("header", fields_json(&sf)),
            ("wit", hx(&sw)),
            ("wit_keccak", hx(&keccak(&[&sw]))),
            ("rows", J::A(rows)),
        ])),
        ("plain_used", J::from(CREDIT)),
        ("T_keccak", hx(&keccak(&[&t]))),
        ("T_M", nums(&tm)),
        ("T_noise", nums(&tn)),
        ("max_abs_noise", J::from(maxn)),
        (MARGIN_E, J::from(ratio(E_RANGE, maxn))),
        ("margin_mint", J::from(ratio(mint, maxn))),
        ("debit", debit(&kr, kt, ka, &t, K_MAX as u64 * CREDIT, CREDIT, 0xB2, [0x94; 32])),
    ])
}

/// An honest receiver key (KeyGen) with credits aligned to it: illustrative (below the bound, which assumes the worst
/// key); every credit a different ciphertext.
fn illustrative_case(kt: &Key, ka: &Key) -> J {
    let kr = keygen(WC_RECV);
    let w = rot(&kr.e.iter().map(|&x| x as i64).collect::<Vec<_>>());
    let z = rot(&kr.s.iter().map(|&x| x as i64).collect::<Vec<_>>());
    let r = align_r(&w, B_R);
    let r8: Vec<i8> = r.iter().map(|&x| x as i8).collect();
    let mut e2 = [0i16; 16];
    e2[0] = 64;
    let mut t = vec![0u8; st::CT_BYTES];
    let (mut hashes, mut cat) = (Vec::new(), Vec::new());
    let ncr = K_MAX - 1;
    let (mut e1sq, mut noise0) = (None, None);
    for k in 0..ncr as u32 {
        let e1: Vec<i16> = align_e1(&z, k).iter().map(|&x| x as i16).collect();
        let (u, vs) = encrypt(&[&kr], &[CREDIT], &r8, &e1, &[e2]);
        let ct = [&u[..], &vs[0][..]].concat();
        let h = keccak(&[&ct]);
        cat.extend_from_slice(&h);
        hashes.push(hx(&h));
        t = ct_add(&t, &ct, false);
        let sq1 = sq(&e1);
        assert!(e1sq.is_none_or(|x| x == sq1) && sq1 <= B_E1);
        e1sq = Some(sq1);
        if k == 0 || k + 1 == ncr as u32 {
            let (m, nz) = dec(&kr.s, &ct);
            assert_eq!(value(&m), CREDIT as i128);
            assert!(noise0.is_none_or(|x| x == nz[0]));
            noise0 = Some(nz[0]);
        }
    }
    let plain = CREDIT;
    t = ct_add(&t, &trivial(plain), false);
    let (tm, tn) = dec(&kr.s, &t);
    let bal = (K_MAX as u64) * CREDIT;
    assert_eq!(value(&tm), bal as i128);
    let wr: i64 = w.iter().zip(&r).map(|(a, b)| a * b).sum();
    let ze: i64 = -z.iter().zip(align_e1(&z, 0)).map(|(a, b)| a * b).sum::<i64>();
    assert_eq!(noise0.unwrap(), wr + ze + 64, "credit noise = <w, r> - <z, e1> + e2[0]");
    assert_eq!(tn[0], ncr as i64 * noise0.unwrap());
    let maxn = tn.iter().map(|x| x.abs()).max().unwrap();
    assert!(maxn < E_RANGE);
    o(vec![
        ("note", J::from("Illustrative: an honest receiver key (KeyGen), credits aligned to it; below the bound case.")),
        ("receiver_seed", hx(&WC_RECV)),
        ("generator_seed", hx(&WC_GEN)),
        ("credit_value", J::from(CREDIT)),
        ("plain_used", J::from(plain)),
        ("alignment", J::from(
            format!("Noise of a credit in coefficient 0 = <rot(e), r> - <rot(s), e1> + e2[0] for the receiver key (s, e), rot(x) \
             per poly = (x_0, -x_63, ..., -x_1). r: the same for every credit, greedy max of <rot(e), r> with ||r||^2 <= \
             {B_R} over integer increments (k, a) (gain |w_k|, cost 2a + 1) by gain / cost descending, ties by (k, a). \
             e1 of credit k: every coordinate with rot(s) != 0 at level L (largest with L^2 N <= {B_E1}), X = ({B_E1} - L^2 \
             N) / (2L + 1) of them at L + 1, the X first by (prio, index), prio_i = be32 of SHAKE256(SCAAS-PQZ-WORSTCASE-V1 \
             || generator_seed || be4(k)) bytes 4i..4i+4, sign -sign(rot(s)). e2 = (64, 0, ..., 0). Message digits(credit_value). \
             Credits by pqz_encrypt (C), T = sum of the credits + Trivial(digits(plain_used)) mod q.",
        ))),
        ("credit_norms_sq", o(vec![("r", J::from(sq(&r))), ("e1", J::from(e1sq.unwrap())), ("e2", J::from(64 * 64u64))])),
        ("credit_noise0", J::from(noise0.unwrap())),
        ("credits_ct_keccak", J::A(hashes)),
        ("credits_keccak", hx(&keccak(&[&cat]))),
        ("T_keccak", hx(&keccak(&[&t]))),
        ("T_M", nums(&tm)),
        ("T_noise", nums(&tn)),
        ("max_abs_noise", J::from(maxn)),
        (MARGIN_E, J::from(ratio(E_RANGE, maxn))),
        ("debit", debit(&kr, kt, ka, &t, bal, plain, 0xB1, WC_RND)),
    ])
}

fn worstcase() -> Vec<(&'static str, J)> {
    let (kf, kt, ka) = (keygen(SEED_F), keygen(SEED_T), keygen(SEED_A));
    vec![
        ("k_max", J::from(K_MAX)),
        ("credits_n", J::from(K_MAX - 1)),
        ("b_fresh", J::from(B_FRESH)),
        ("e_T_range", J::from(E_RANGE)),
        ("mint_threshold", J::from(DELTA as i64 - E_RANGE)),
        ("bound", bound_case(&kf, &kt, &ka)),
        ("illustrative", illustrative_case(&kt, &ka)),
    ]
}

// ---------------------------------------------------------------- op 7 R_TXM (P6-ANON S4, plan D15, §4, §5.4)
/// op 7 header names: word 192 = recipientsHash, word 320 = M (P6-ANON §4); the rest as op 1
const MNAMES: [&str; 20] = [
    "opTag", "proofSystemId", "chainId", "token", "registry", "fromUA", "recipientsHash", "beneficiaryUA", "fee", "amount",
    "M", "sendCounter", "p", "validUntilBlock", "auditorOn", "plainUsed", "chainUid", "envelopeBinding", "salt",
    "memoHash",
];
/// op 7 proofs by (case, id index)
type MProofs = std::collections::BTreeMap<(String, usize), Vec<u8>>;
const MULTI_FILE: &str = "statement_transfer_multi.json";
const SEED_LEG0: u8 = 0x60; // recipient j's KeyGen seed: [0x60 + j; 32]
const MEMO_KEY: [u8; 32] = pqz_ffi::fixture::MEMO_KEY_SEED;

/// One op 7 statement of the vectors: its PQZL-id bytes (the PQZH statement differs in bytes 32..63 only), the ids
/// it is built for, witness, the statement-file row.
struct MRow {
    case: String,
    m: usize,
    aud: bool,
    ids: Vec<usize>,
    stmt: Vec<u8>,
    wit: Vec<u8>,
    rnd: [u8; 32],
    header: [Word; 20],
    memo: Vec<u8>,
    json: Vec<(&'static str, J)>,
}

/// (case, M, auditorOn, fee, leg amounts): every built (M, A) with one real leg at a position that varies by shape
/// (D15), then a two-real-leg row, an all-decoy row and a group-boundary row (real legs b - 1 and b: `boundary()`)
fn multi_specs() -> Vec<(String, usize, bool, u64, Vec<u64>)> {
    let v = 123_456u64;
    let one = |m: usize, at: usize| (0..m).map(|j| if j == at { v } else { 0 }).collect::<Vec<u64>>();
    let mut out = Vec::new();
    for (aud, pos) in [(true, [0usize, 1, 2, 5]), (false, [0, 0, 3, 7])] {
        for (m, at) in [1usize, 2, 4, 8].into_iter().zip(pos) {
            out.push((format!("M{m}-{}", if aud { "on" } else { "off" }), m, aud, if aud { 7 } else { 0 }, one(m, at)));
        }
    }
    out.push(("M2-off-two-real".into(), 2, false, 7, vec![v, 7_000]));
    out.push(("M4-off-decoys".into(), 4, false, 0, vec![0; 4]));
    let b = boundary();
    out.push(("M8-on-boundary".into(), 8, true, 7, (0..8).map(|j| if j == b - 1 { v } else if j == b { 7_000 } else { 0 }).collect()));
    out
}

/// the first leg b of an audited group, the one at or after leg 4: b = s ceil(4 / s), s = S_AUD (R0 fix round m6).
/// M8-on-boundary's real legs b - 1 and b are the last of one group and the first of the next at every set: 3 / 4 at
/// s = 2 and 4, 5 / 6 at s = 3 (where the legs 3 / 4 of before sat in one group)
fn boundary() -> usize {
    let s = st::legs_per_group(true);
    s * 4usize.div_ceil(s)
}

fn leg_addr(j: usize) -> Vec<u8> {
    vec![0xB0 + j as u8; 20]
}

fn multi_rows() -> Vec<MRow> {
    let (kf, ka) = (keygen(SEED_F), keygen(SEED_A));
    let kr: Vec<Key> = (0..8).map(|j| keygen([SEED_LEG0 + j as u8; 32])).collect();
    let plain = 1_000u64;
    let acc = enc(&[&kf], &[1_000_000], [0x61; 32]);
    let t = ct_add(&acc.ct(0), &trivial(plain), false);
    let bal = 1_000_000 + plain;
    let mut tj = acc.json();
    if let J::O(kv) = &mut tj {
        kv.push(("plus_trivial".into(), J::from(plain)));
    }
    multi_specs()
        .into_iter()
        .enumerate()
        .map(|(idx, (case, m, aud, fee, amounts))| {
            let ids: Vec<usize> = (0..IDS.len()).filter(|&i| st::built_legs(&IDS[i].1).contains(&m)).collect();
            let bp = bal - amounts.iter().sum::<u64>() - fee;
            let seed = [0x70 + idx as u8; 32];
            let legs: Vec<(&[u8; PK], [u8; 16])> = (0..m).map(|j| (pk_ref(&kr[j].pk), digits(amounts[j]))).collect();
            let c = pqzl::enc_multi(pk_ref(&kf.pk), digits(bp), &legs, aud.then(|| pk_ref(&ka.pk)), &seed).expect("enc_multi");
            let uas: Vec<Word> = (0..m).map(|j| vword(&V::B(leg_addr(j)))).collect();
            let rh = keccak(&[&uas.concat()]);
            let mut f: Vec<(&str, V)> = vec![
                ("chainId", V::I(22776)),
                ("token", V::B(vec![0x11; 20])),
                ("registry", V::B(vec![0x22; 20])),
                ("fromUA", V::B(vec![0xA1; 32])),
                ("recipientsHash", V::B(rh.to_vec())),
            ];
            if fee > 0 {
                f.push(("beneficiaryUA", V::B(vec![0xA3; 32])));
            }
            f.extend([
                ("fee", V::I(fee)),
                ("sendCounter", V::I(3 + idx as u64)),
                ("p", V::I(5)),
                ("validUntilBlock", V::I(1_000_000)),
                ("plainUsed", V::I(plain)),
                ("chainUid", V::B(vec![0xC1; 32])),
                ("envelopeBinding", V::B(vec![0xE1; 32])),
                ("salt", V::B(vec![0x5A; 16])),
            ]);
            let mut header = st::Multi::header(&PQZL_ID, m, aud);
            set_words(&mut header, &MNAMES, &f);
            let legs_memo: Vec<(u64, Word)> = amounts.iter().copied().zip(uas.iter().copied()).collect();
            let memo = pqz_ffi::memo::seal(&MEMO_KEY, &header, aud, &legs_memo).expect("memo");
            assert_eq!(pqz_ffi::memo::open(&MEMO_KEY, &header, &memo), Some((aud, legs_memo)));
            let mh = keccak(&[&memo]);
            header[st::H_MEMO_HASH] = mh;
            f.push(("memoHash", V::B(mh.to_vec())));
            let pks: Vec<u8> = kr[..m].iter().flat_map(|k| k.pk.clone()).collect();
            let us: Vec<u8> = c.groups.iter().flat_map(|g| g.u.to_vec()).collect();
            let (vs, v_as) = (c.v.concat(), c.v_a.concat());
            let s = st::Multi {
                header,
                m,
                pk_f: &kf.pk,
                pks: &pks,
                pk_a: aud.then_some(&ka.pk[..]),
                t: &t,
                us: &us,
                vs: &vs,
                v_f: &c.v_f,
                v_as: aud.then_some(&v_as[..]),
            }
            .encode()
            .unwrap();
            st::parse(st::OP_TRANSFER_MULTI, &s).expect("op 7 statement canonical");
            assert_eq!(st::parse_multi(&s).unwrap().encode().unwrap(), s);
            // witness (pqz.h PQZ_TXM_WIT_BYTES): s_f ‖ e_f ‖ (r_g ‖ e1_g)_g ‖ e2_j ‖ e2_f ‖ [e2_{a,j}] ‖ d_j ‖ d'
            let mut w = kf.wit();
            for g in &c.groups {
                w.extend(g.r.iter().map(|&x| x as u8));
                le16(&mut w, &g.e1[..]);
            }
            c.e2.iter().chain([&c.e2_f]).chain(&c.e2_a).for_each(|e| le16(&mut w, e));
            amounts.iter().chain([&bp]).for_each(|&a| w.extend(digits(a)));
            assert_eq!((s.len(), w.len()), (st::multi_len(m, aud), pqz_ffi::fixture::multi_wit_len(m, aud)));
            let groups: Vec<J> = c
                .groups
                .iter()
                .enumerate()
                .map(|(g, e)| o(vec![("seed_enc_g", hx(&pqzl::enc_group_seed(&seed, g))), ("ctr", J::from(e.ctr))]))
                .collect();
            let mut objs = vec![
                ("pk_f", keyref(&kf)),
                ("pks", J::A(kr[..m].iter().map(keyref).collect())),
            ];
            if aud {
                objs.push(("pk_a", keyref(&ka)));
            }
            objs.extend([
                ("T", tj.clone()),
                ("out", o(vec![
                    ("seed_enc", hx(&seed)),
                    ("values", nums(&amounts)),
                    ("value_f", J::from(bp)),
                    ("groups", J::A(groups)),
                ])),
                ("uas", J::A((0..m).map(|j| hx(&leg_addr(j))).collect())),
            ]);
            let idsj = |g: &dyn Fn(&[u8]) -> Word| J::O(ids.iter().map(|&i| (IDS[i].0.to_string(), hx(&g(&with_id(&s, &IDS[i].1))))).collect());
            let json = vec![
                ("form", J::from("TRANSFER-MULTI")),
                ("case", J::from(case.as_str())),
                ("op", J::from(st::OP_TRANSFER_MULTI)),
                ("M", J::from(m)),
                ("auditorOn", J::from(aud as u8)),
                ("ids", J::A(ids.iter().map(|&i| J::from(IDS[i].0)).collect())),
                ("header", fields_json(&f)),
                ("objects", o(objs)),
                ("memo", o(vec![("key_seed", hx(&MEMO_KEY)), ("memo_bytes", J::from(memo.len())), ("memo", hx(&memo))])),
                ("stmt_bytes", J::from(s.len())),
                ("stmt", hx(&s)),
                ("stmt_keccak", idsj(&|x| keccak(&[x]))),
                ("auth_digest", idsj(&|x| auth_digest(x))),
                ("entry_ref", hx(&entry_ref(&f))),
            ];
            MRow { case, m, aud, ids, stmt: s, wit: w, rnd: [0xB0 + idx as u8; 32], header, memo, json }
        })
        .collect()
}

/// op 7 disclosures (R0-1: R_DR / R_DA at the window of the disclosed v): (case, op 7 case, leg, auditor). The auditor
/// copies of M8-on-boundary's real legs b - 1 and b (`boundary()`) and of leg 2 of M4-on (windows j mod S_AUD: some
/// nonzero at every set) and the receiver of M8-on-boundary's leg b (window 0, its group's u)
fn mdisc() -> [(&'static str, &'static str, usize, bool); 4] {
    let b = boundary();
    let nm = |j: usize, who: &str| leak(format!("M8-on-boundary-leg{j}-{who}"));
    [
        (nm(b - 1, "auditor"), "M8-on-boundary", b - 1, true),
        (nm(b, "auditor"), "M8-on-boundary", b, true),
        ("M4-on-leg2-auditor", "M4-on", 2, true),
        (nm(b, "receiver"), "M8-on-boundary", b, false),
    ]
}

/// One op 7 disclosure statement (statement_transfer_multi.json `disclosures`)
struct DRow {
    case: String,
    form: Form,
    stmt: Vec<u8>,
    wit: Vec<u8>,
    rnd: [u8; 32],
    json: Vec<(&'static str, J)>,
}

fn multi_disclosures(mrows: &[MRow]) -> Vec<DRow> {
    let ka = keygen(SEED_A);
    let specs = multi_specs();
    mdisc()
        .iter()
        .enumerate()
        .map(|(i, &(case, mc, j, aud))| {
            let r = mrows.iter().find(|r| r.case == mc).unwrap();
            assert!(r.aud, "{mc}: an audited op 7 case");
            let amount = specs.iter().find(|x| x.0 == mc).unwrap().4[j];
            let s = st::parse_multi(&r.stmt).unwrap();
            let lpg = st::legs_per_group(true);
            let kr = keygen([SEED_LEG0 + j as u8; 32]);
            let (form, kind, w, key, v) =
                if aud { (Form::DiscloseAuditor, 2u64, j % lpg, &ka, s.v_a(j).unwrap()) } else { (Form::DiscloseReceiver, 1, 0, &kr, s.v(j)) };
            let mut hw = r.header;
            let f: Vec<(&str, V)> = vec![
                ("chainId", V::B(hw[st::H_CHAIN_ID].to_vec())),
                ("chainUid", V::B(hw[st::H_CHAIN_UID].to_vec())),
                ("token", V::B(hw[st::H_TOKEN][12..].to_vec())),
                ("registry", V::B(hw[st::H_REGISTRY][12..].to_vec())),
                ("entryRef", V::B(mentry_ref(&mut hw).to_vec())),
                ("amount", V::I(amount)),
                ("kind", V::I(kind + 256 * w as u64)),
            ];
            let mut words = Disclose::words(form, &PQZL_ID);
            set_words(&mut words, &DNAMES, &f);
            let st_ = Stmt::Disclose(Disclose { form, words, pk: &key.pk, u: s.u(j / lpg), v }).encode().unwrap();
            st::parse(form.op(), &st_).expect("op 7 disclosure canonical");
            let objs = o(vec![
                ("pk", keyref(key)),
                ("multi_case", J::from(mc)),
                ("leg", J::from(j)),
                ("window", J::from(w)),
            ]);
            let mut json = stmt_json(form, &st_, fields_json(&f), objs, vec![]);
            json.insert(1, ("case", J::from(case)));
            DRow { case: case.into(), form, stmt: st_, wit: key.wit(), rnd: [0xD0 + i as u8; 32], json }
        })
        .collect()
}

/// entryRef of an op 7 header (as op 1: chainId, chainUid, token, fromUA, sendCounter)
fn mentry_ref(h: &mut [Word; 20]) -> Word {
    let t = keccak(&[b"SCAAS-PQZ-ENTRY-V1"]);
    keccak(&[&t, &h[st::H_CHAIN_ID], &h[st::H_CHAIN_UID], &h[st::H_TOKEN], &h[st::H_FROM], &h[st::H_SEND_COUNTER]])
}

/// memo::open on edited memos of one row (§5.4): (name, key seed, edits, result)
fn memo_opens(rows: &[MRow]) -> Vec<J> {
    let base = rows.iter().find(|r| r.case == "M2-on").unwrap();
    let n = base.memo.len();
    let cases: Vec<(&str, [u8; 32], Vec<(&str, J)>)> = vec![
        ("the sender's memo", MEMO_KEY, vec![]),
        ("another key seed", [0x4e; 32], vec![]),
        ("truncated by 1 byte", MEMO_KEY, vec![("resize", J::from(n - 1))]),
        ("one more 40-byte leg (zero bytes)", MEMO_KEY, vec![("resize", J::from(n + 40))]),
        ("shorter than one leg (17 bytes)", MEMO_KEY, vec![("resize", J::from(17usize))]),
        ("flags byte bit 1 flipped", MEMO_KEY, vec![("flip", J::A(vec![J::from(16usize), J::from(1u8)]))]),
        ("M byte bit 0 flipped", MEMO_KEY, vec![("flip", J::A(vec![J::from(17usize), J::from(0u8)]))]),
        ("leg 1 amount low bit flipped", MEMO_KEY, vec![("flip", J::A(vec![J::from(18 + 40 + 7usize), J::from(0u8)]))]),
        ("salt byte 0 bit 0 flipped", MEMO_KEY, vec![("flip", J::A(vec![J::from(0usize), J::from(0u8)]))]),
    ];
    cases
        .into_iter()
        .map(|(name, key, edits)| {
            let mut b = base.memo.clone();
            for (k, v) in &edits {
                match (*k, v) {
                    ("resize", J::N(x)) => b.resize(*x as usize, 0),
                    ("flip", J::A(x)) => {
                        let (J::N(at), J::N(bit)) = (&x[0], &x[1]) else { unreachable!() };
                        b[*at as usize] ^= 1 << bit;
                    }
                    _ => unreachable!(),
                }
            }
            let res = match pqz_ffi::memo::open(&key, &base.header, &b) {
                None => J::from("none"),
                Some((a, legs)) => o(vec![
                    ("auditorOn", J::from(a)),
                    ("legs", J::A(legs.iter().map(|(x, ua)| J::A(vec![J::from(*x), hx(ua)])).collect())),
                ]),
            };
            o(vec![
                ("name", J::from(name)),
                ("case", J::from(base.case.as_str())),
                ("key_seed", hx(&key)),
                ("edits", J::A(edits.into_iter().map(|(k, v)| o(vec![(k, v)])).collect())),
                ("result", res),
            ])
        })
        .collect()
}

/// statement offsets of an op 7 shape: (pk_0, u_0, v_0, v_f, v_{a,0})
fn moff(m: usize, aud: bool) -> (usize, usize, usize, usize, usize) {
    let a = aud as usize;
    let pk0 = st::HEADER_BYTES + PK;
    let u0 = pk0 + (m + a) * PK + st::CT_BYTES;
    let v0 = u0 + st::groups(m, aud) * PK;
    (pk0, u0, v0, v0 + 128 * m, v0 + 128 * (m + 1))
}

/// op 7 negative inputs (plan D15, T25): (name, case, id, edits)
fn multi_negatives(rows: &[MRow], mp: &MProofs) -> Vec<(String, String, usize, Vec<E>)> {
    let mut v = Vec::new();
    let w = |x: u64| st::u64_word(x).to_vec();
    let qb = |x: u64| x.to_be_bytes().to_vec();
    let row = |c: &str| rows.iter().find(|r| r.case == c).unwrap();
    for id in 0..IDS.len() {
        let mut add = |name: String, case: &str, e: Vec<E>| v.push((format!("{case}: {name}"), case.to_string(), id, e));
        let defaults: Vec<&MRow> = rows.iter().filter(|r| r.ids.contains(&id) && r.case == format!("M{}-{}", r.m, if r.aud { "on" } else { "off" })).collect();
        for r in &defaults {
            let (n, pl, c) = (r.stmt.len(), mp[&(r.case.clone(), id)].len(), r.case.as_str());
            add("statement length - 1".into(), c, vec![E::StmtResize(n - 1)]);
            add("statement length + 1".into(), c, vec![E::StmtResize(n + 1)]);
            for op in 0..=6u8 {
                add(format!("under op {op}"), c, vec![E::Op(op)]);
            }
            add("unknown proofSystemId (zero word)".into(), c, vec![E::StmtSet(32, vec![0; 32])]);
            add(other_id(id).0.into(), c, vec![E::StmtSet(32, other_id(id).1.to_vec())]);
            for (r, w) in retired_ids(id) {
                add(format!("retired {r} proofSystemId"), c, vec![E::StmtSet(32, w.to_vec())]);
            }
            add("proof truncated by 1 byte".into(), c, vec![E::ProofResize(pl - 1)]);
            add("proof extended by 1 zero byte".into(), c, vec![E::ProofResize(pl + 1)]);
            add("proof byte 0 bit 0 flipped".into(), c, vec![E::ProofFlip(0, 0)]);
            add("proof middle byte bit 3 flipped".into(), c, vec![E::ProofFlip(pl / 2, 3)]);
            add("proof last byte bit 7 flipped".into(), c, vec![E::ProofFlip(pl - 1, 7)]);
            if IDS[id].1 == PQZH_ID {
                for (name, e) in ph::negatives(ph::Shape::Multi(r.m, r.aud)) {
                    add(name, c, e);
                }
            } else if *mp[&(r.case.clone(), id)].last().unwrap() < 0x80 {
                add("coder padding bit 7 set after the final 1-bit".into(), c, vec![E::ProofFlip(pl - 1, 7)]);
            }
        }
        let set = |at: usize, b: Vec<u8>| vec![E::StmtSet(at, b)];
        let r2 = row("M2-on");
        let (pk0, u0, v0, vf, _) = moff(2, true);
        let n2 = r2.stmt.len();
        let v1 = r2.stmt[v0 + 128..v0 + 256].to_vec();
        let mut list: Vec<(&str, &str, Vec<E>)> = vec![
            ("M word 0", "M2-on", set(320, w(0))),
            ("M word 3", "M2-on", set(320, w(3))),
            ("M word 16 (oversize only)", "M2-on", set(320, w(16))),
            ("M word with bit 64 set", "M2-on", set(320 + 23, vec![1])),
            ("M word 4 on the M = 2 length", "M2-on", set(320, w(4))),
            ("auditorOn 0 on an auditor-on statement", "M2-on", set(448, w(0))),
            ("auditorOn 1 on an auditor-off statement", "M4-off", set(448, w(1))),
            ("auditorOn 2", "M2-on", set(448, w(2))),
            ("statement of the 640-byte header only", "M2-on", vec![E::StmtResize(640)]),
            ("statement cut inside the header (639 bytes)", "M2-on", vec![E::StmtResize(639)]),
            ("amount 1", "M2-on", set(288, w(1))),
            ("amount >= 2^64", "M2-on", set(288 + 23, vec![1])),
            ("fee >= 2^64", "M2-on", set(256 + 23, vec![1])),
            ("salt word top byte set", "M2-on", set(576, vec![1])),
            ("salt word byte 15 set", "M4-off", set(591, vec![0x80])),
            ("pk_f coefficient 0 = q", "M2-on", set(640, qb(Q))),
            (leak(format!("pk_1 coefficient 0 = 2^{}", st::LOG2Q)), "M2-on", set(pk0 + PK, qb(1 << st::LOG2Q))),
            ("u_0 coefficient 0 = q", "M2-on", set(u0, qb(Q))),
            ("v_f last coefficient = q", "M2-on", set(vf + 120, qb(Q))),
            ("v_{a,M-1} last coefficient = 2^64 - 1", "M2-on", set(n2 - 8, qb(u64::MAX))),
            ("recipientsHash bit flipped", "M2-on", vec![E::StmtFlip(192 + 31, 0)]),
            ("memoHash bit flipped", "M2-on", vec![E::StmtFlip(608 + 31, 0)]),
            ("fee + 1", "M2-on", set(256 + 24, qb(8))),
            ("chainId bit flipped", "M2-on", vec![E::StmtFlip(64 + 31, 0)]),
            ("pk_0 coefficient 0 low bit flipped", "M2-on", vec![E::StmtFlip(pk0 + 7, 0)]),
            ("v_0 replaced by v_1", "M2-on", set(v0, v1)),
            ("(1, on) read as (2, off): M word 2, auditorOn 0", "M1-on", vec![E::StmtSet(320, w(2)), E::StmtSet(448, w(0))]),
            ("op 1 TRANSFER's proof (same statement length)", "M1-on", vec![E::ProofFrom(Form::Transfer)]),
            ("op 1 TRANSFER0's proof (same statement length)", "M1-off", vec![E::ProofFrom(Form::Transfer0)]),
            ("M4-on's proof", "M2-on", vec![E::ProofFromCase("M4-on".into())]),
            ("M2-on's proof", "M2-off-two-real", vec![E::ProofFromCase("M2-on".into())]),
            ("empty proof", "M2-on", vec![E::ProofResize(0)]),
            ("proof of MAX_PROOF(id) + 1 bytes", "M2-on", vec![E::ProofResize(st::max_proof(&IDS[id].1).unwrap() + 1)]),
            ("proof of exactly MAX_PROOF(id) bytes", "M2-on", vec![E::ProofResize(st::max_proof(&IDS[id].1).unwrap())]),
            ("input of exactly MAX_INPUT bytes (not a revert)", "M4-on", vec![E::InputResize(st::MAX_INPUT)]),
            ("input of MAX_INPUT + 1 bytes (expected revert, P6f)", "M4-on", vec![E::InputResize(st::MAX_INPUT + 1)]),
            ("length field = statement + 1", "M2-on", vec![E::LenField(n2 as u32 + 1)]),
        ];
        let two = row("M2-off-two-real");
        let (_, _, tv0, _, _) = moff(2, false);
        list.push(("v_0 and v_1 swapped", "M2-off-two-real", vec![
            E::StmtSet(tv0, two.stmt[tv0 + 128..tv0 + 256].to_vec()),
            E::StmtSet(tv0 + 128, two.stmt[tv0..tv0 + 128].to_vec()),
        ]));
        if IDS[id].1 == PQZH_ID {
            list.push(("M word 8 (not built for PQZH)", "M4-on", set(320, w(8))));
        } else {
            let b = row("M8-on-boundary");
            let (_, _, bv0, _, _) = moff(8, true);
            let (j, g) = (boundary(), boundary() / st::legs_per_group(true)); // legs j - 1, j: groups g - 1, g
            let (v3, v4) = (bv0 + (j - 1) * 128, bv0 + j * 128);
            list.push((leak(format!("v_{} and v_{j} swapped (legs across groups {} and {g})", j - 1, g - 1)), "M8-on-boundary", vec![
                E::StmtSet(v3, b.stmt[v4..v4 + 128].to_vec()),
                E::StmtSet(v4, b.stmt[v3..v3 + 128].to_vec()),
            ]));
            list.push(("M8-off's proof", "M8-on-boundary", vec![E::ProofFromCase("M8-off".into())]));
            list.push(("M word 4 on the M = 8 length", "M8-on", set(320, w(4))));
        }
        for (name, c, e) in list {
            add(name.into(), c, e);
        }
    }
    v
}

// ---------------------------------------------------------------- everything
fn generate() -> (Vec<(String, String)>, bool) {
    let stale;
    let t0 = Instant::now();
    let mut files = vec![matrix_file(), cbd_file(), keygen_file(), enc_file()];
    eprintln!("keys / cbd / matrix / enc: {:.1} s", t0.elapsed().as_secs_f64());

    let sc = scenario(7);
    for name in ["statement_transfer.json", "statement_burn.json", "statement_refresh.json", "statement_register.json", "statement_disclose.json"] {
        let rows = sc.rows.iter().filter(|r| sfile(r.form) == name).map(|r| o(r.json.clone())).collect();
        files.push(file(
            name,
            "Statements (pq-zether.md 7.2, 7.7, 7.9; serialization v1, P6e plan D15 / R6) built from keygen seeds and Enc \
             parameters: header / words (ints, or hex bytes left-padded to a 32-byte word: addresses 20 B, salt 16 B; opTag, proofSystemId and auditorOn \
             follow from the form and id), objects (keys by KeyGen seed; T = Enc + Trivial(plus_trivial); out = u || v_j; \
             a disclosure's u, v = leg of an Enc), stmt = the bytes under the PQZL id (the PQZH statement differs only in \
             bytes 32..63), keccak256 and authDigest = keccak256(SCAAS-PQZ-AUTH-V1 || keccak256(stmt)) per id; transfers: \
             entryRef, the disclosure bundle R = salt || u || v_t || [v_a] || toUA.",
            vec![("rows", J::A(rows))],
        ));
    }
    let stmts: Vec<Vec<u8>> = sc.rows.iter().map(|r| r.stmt.clone()).collect();

    // proofs: both ids, every form
    let mut proofs: [[Vec<u8>; 8]; 2] = Default::default();
    for (i, (nm, id)) in IDS.iter().enumerate() {
        for r in &sc.rows {
            let t = Instant::now();
            let s = with_id(&r.stmt, id);
            let p = prove(id, r.form.op(), &s, &r.wit, &r.rnd);
            assert_eq!(p, prove(id, r.form.op(), &s, &r.wit, &r.rnd), "prover not deterministic");
            assert_eq!(precompile(&st::input(r.form.op(), &s, &p)), ("1", "verify".to_string()), "{nm} {}", fname(r.form));
            eprintln!("{nm} {:18} proof {:6} B  prove+verify {:.2} s", fname(r.form), p.len(), t.elapsed().as_secs_f64());
            proofs[i][fidx(r.form)] = p;
        }
    }
    // op 7 R_TXM (P6-ANON S4): statements, both ids' proofs of each built shape
    let mrows = multi_rows();
    let mut mp = MProofs::new();
    for r in &mrows {
        for &i in &r.ids {
            let (nm, id) = IDS[i];
            let t = Instant::now();
            let s = with_id(&r.stmt, &id);
            let p = prove(&id, st::OP_TRANSFER_MULTI, &s, &r.wit, &r.rnd);
            assert_eq!(p, prove(&id, st::OP_TRANSFER_MULTI, &s, &r.wit, &r.rnd), "prover not deterministic");
            assert_eq!(precompile(&st::input(st::OP_TRANSFER_MULTI, &s, &p)), ("1", "verify".to_string()), "{nm} {}", r.case);
            eprintln!("{nm} {:18} proof {:6} B  prove+verify {:.2} s", r.case, p.len(), t.elapsed().as_secs_f64());
            mp.insert((r.case.clone(), i), p);
        }
    }
    // op 7 disclosures (R0-1): both ids' proofs
    let mdisc = multi_disclosures(&mrows);
    for r in &mdisc {
        for (i, (nm, id)) in IDS.iter().enumerate() {
            let s = with_id(&r.stmt, id);
            let p = prove(id, r.form.op(), &s, &r.wit, &r.rnd);
            assert_eq!(precompile(&st::input(r.form.op(), &s, &p)), ("1", "verify".to_string()), "{nm} {}", r.case);
            eprintln!("{nm} {:18} proof {:6} B", r.case, p.len());
            mp.insert((r.case.clone(), i), p);
        }
    }
    files.push(file(
        MULTI_FILE,
        "Op 7 R_TXM statements (P6-ANON plan §4, D15; pq-zether.md §8.1 op 7): every built (M, auditorOn) of each id with \
         one real leg (123,456) at a position that varies by shape and decoy legs (0), plus a two-real-leg row, an \
         all-decoy row and a group-boundary row (real legs b - 1 and b, b = s ceil(4 / s) with s = S_AUD: the last leg \
         of one audited group and the first of the next). ids: the proofSystemIds whose \
         built leg counts contain M (PQZL {1, 2, 4, 8}, PQZH {1, 2, 4}). header: as statement_transfer.json with word \
         192 = recipientsHash = keccak256(UA_0 || ... || UA_{M-1}) (32-byte words of objects.uas) and word 320 = M; \
         auditorOn = 1 iff pk_a. objects: keys by KeyGen seed (pks: leg order), T = Enc + Trivial(plus_trivial), out: \
         the multi-group Enc (D13): group g encrypts its legs (j / s = g), then (g = 0) pk_f with value_f, then (auditor \
         on) pk_a once per leg of the group, from seed_enc_g = seed_enc (g = 0) or SHAKE256(SCAAS-PQZ-ENC-GROUP-V1 || \
         seed_enc || be4(g))[0..32), ctr = its counter. memo (§5.4, CTR-PQZ-23): salt || ((u8(auditorOn) || u8(M) || \
         (be8(a_j) || UA_j)_j) XOR ks), key = HKDF-SHA256(IKM key_seed, no salt, info PQZ/memo/v1 || chainUid || \
         token(20) || fromUA || be4(sendCounter) || salt)[32], ks = HKDF-Expand-SHA256(key, PQZ/memo/ks/v1, 2 + 40 M); \
         memoHash = keccak256(memo). memo_open: memo open (the sender's recovery) on edited memos (resize, flip [byte, \
         bit]) of the case, result = (auditorOn, [amount, UA]) or none. stmt = the PQZL-id bytes (PQZH: bytes 32..63 \
         replaced); stmt_keccak / auth_digest per id; entry_ref as op 1. Groups of S_AUD legs with the auditor (set.json \
         s_aud; owner 2026-10-25, R0-1), 4 without: leg j in group j / s, its auditor copy at the coefficients [16 w, 16 w + \
         16) of pk_a^T r_g, w = j mod s (the group's i-th copy at window i). disclosures: §7.9 statements of op 7 legs \
         (R_DR, the auditor's R_DA): words as statement_disclose.json with the case's chainId, chainUid, token, registry, \
         entryRef, the leg's amount and kind = OpeningKind + 256 w (w = window: the auditor copy's j mod S_AUD, 0 for a \
         receiver); pk the disclosing key, u = u_{j / s}, v = v_{a,j} (AUDITOR) or v_j (RECEIVER) of multi_case.",
        vec![
            ("rows", J::A(mrows.iter().map(|r| o(r.json.clone())).collect())),
            ("memo_open", J::A(memo_opens(&mrows))),
            ("disclosures", J::A(mdisc.iter().map(|r| o(r.json.clone())).collect())),
        ],
    ));
    for (i, (nm, id)) in IDS.iter().enumerate() {
        let mut rows: Vec<J> = sc
            .rows
            .iter()
            .map(|r| {
                let p = &proofs[i][fidx(r.form)];
                let mut kv = vec![
                    ("form", J::from(fname(r.form))),
                    ("op", J::from(r.form.op())),
                    ("statement", o(vec![("file", J::from(sfile(r.form))), ("form", J::from(fname(r.form)))])),
                    ("stmt_keccak", hx(&keccak(&[&with_id(&r.stmt, id)]))),
                    ("wit", hx(&r.wit)),
                    ("wit_keccak", hx(&keccak(&[&r.wit]))),
                    ("rnd32", hx(&r.rnd)),
                    ("proof_bytes", J::from(p.len())),
                    ("proof_keccak", hx(&keccak(&[p]))),
                    ("proof_fnv", J::from(fnv(p))),
                ];
                if *id == PQZH_ID {
                    kv.push(("max_proof_len", J::from(ph::max_proof_len(ph::Shape::Form(r.form)))));
                }
                if matches!(r.form, Form::DiscloseSender | Form::DiscloseReceiver | Form::DiscloseAuditor) {
                    let op = st::opening(&sc.bundle, p);
                    assert_eq!(st::parse_opening(&op).unwrap(), (&sc.bundle[..], &p[..]));
                    kv.push(("opening_bytes", J::from(op.len())));
                    kv.push(("opening_keccak", hx(&keccak(&[&op]))));
                }
                kv.extend([("expect", J::from(true)), ("proof", hx(p))]);
                o(kv)
            })
            .collect();
        for r in mrows.iter().filter(|r| r.ids.contains(&i)) {
            let p = &mp[&(r.case.clone(), i)];
            let mut kv = vec![
                ("form", J::from("TRANSFER-MULTI")),
                ("case", J::from(r.case.as_str())),
                ("op", J::from(st::OP_TRANSFER_MULTI)),
                ("statement", o(vec![("file", J::from(MULTI_FILE)), ("case", J::from(r.case.as_str()))])),
                ("stmt_keccak", hx(&keccak(&[&with_id(&r.stmt, id)]))),
                ("wit", hx(&r.wit)),
                ("wit_keccak", hx(&keccak(&[&r.wit]))),
                ("rnd32", hx(&r.rnd)),
                ("proof_bytes", J::from(p.len())),
                ("proof_keccak", hx(&keccak(&[p]))),
                ("proof_fnv", J::from(fnv(p))),
            ];
            if *id == PQZH_ID {
                kv.push(("max_proof_len", J::from(ph::max_proof_len(ph::Shape::Multi(r.m, r.aud)))));
            }
            kv.extend([("expect", J::from(true)), ("proof", hx(p))]);
            rows.push(o(kv));
        }
        for r in &mdisc {
            let p = &mp[&(r.case.clone(), i)];
            let mut kv = vec![
                ("form", J::from(fname(r.form))),
                ("case", J::from(r.case.as_str())),
                ("op", J::from(r.form.op())),
                ("statement", o(vec![("file", J::from(MULTI_FILE)), ("disclosure", J::from(r.case.as_str()))])),
                ("stmt_keccak", hx(&keccak(&[&with_id(&r.stmt, id)]))),
                ("wit", hx(&r.wit)),
                ("wit_keccak", hx(&keccak(&[&r.wit]))),
                ("rnd32", hx(&r.rnd)),
                ("proof_bytes", J::from(p.len())),
                ("proof_keccak", hx(&keccak(&[p]))),
                ("proof_fnv", J::from(fnv(p))),
            ];
            if *id == PQZH_ID {
                kv.push(("max_proof_len", J::from(ph::max_proof_len(ph::Shape::Form(r.form)))));
            }
            kv.extend([("expect", J::from(true)), ("proof", hx(p))]);
            rows.push(o(kv));
        }
        let (desc, params) = if *id == PQZL_ID {
            (
                "PQZL proofs (the set's proofSystemId, set.json pqzl_label) of every statement form, from the C core (pqz_prove, hedged: CTR-PQZ-19), \
                 fixed rnd32: deterministic, byte-exact on every build (native = wasm32). statement: the row of that file, \
                 under this id. wit: the prover-API witness (pqz.h, R3; not consensus), rebuilt by pqz_kat.py from the \
                 seeds. proof_fnv = FNV-1a 32 of the proof. Disclosures: opening = abi.encode(bytes bundle, bytes proof) \
                 with the TRANSFER bundle. Validity: pqz-vectors --check (specialised and generic verifier).",
                o(vec![("max_proof", J::from(st::MAX_PROOF_PQZL))]),
            )
        } else {
            (
                leak(format!("PQZH proofs (Ligero over F_q, the set's proofSystemId, set.json pqzh_label) of every statement form, from pqzh-ligero ({} \
                 preset, params), fixed rnd32: deterministic, byte-exact native = wasm32. Fields as proof_pqzl.json; \
                 max_proof_len = the verifier's exact bound for the form. Validity: pqz-vectors --check (Ligero verify).",
                 if V3 { "THE proven" } else { "the set's proven" })),
                ph::params(),
            )
        };
        let name = format!("proof_{nm}.json");
        files.push(file(&name, desc, vec![("proof_system_id", hx(id)), ("params", params), ("rows", J::A(rows))]));
    }
    eprintln!("proofs: {:.1} s", t0.elapsed().as_secs_f64());

    // negative inputs
    let negs = negatives(&proofs);
    let mut nrows = Vec::new();
    let (mut ndec, mut nver) = (0, 0);
    for (name, form, id, edits) in &negs {
        let input = apply(edits, *form, id.unwrap_or(0), &stmts, &proofs);
        let (out, reason) = precompile(&input);
        assert!(out == "0" || out == "revert", "negative accepted: {name}");
        if reason == "verify" { nver += 1 } else { ndec += 1 }
        nrows.push(o(vec![
            ("name", J::from(name.as_str())),
            ("form", form.map_or(J::from("-"), |f| J::from(fname(f)))),
            ("id", id.map_or(J::from("-"), |i| J::from(IDS[i].0))),
            ("edits", J::A(edits.iter().map(E::json).collect())),
            ("input_bytes", J::from(input.len())),
            ("input_sha3", hx(&<Sha3_256 as sha3::Digest>::digest(&input))),
            ("expect", J::from(out)),
            ("reason", J::from(reason)),
        ]));
    }
    let mnegs = multi_negatives(&mrows, &mp);
    // op 7 disclosures (R0-1): another window than the copy's (a valid kind word, the proof fails), a window >= S_AUD
    // (decoder: Kind)
    let mut dneg: Vec<(String, String, usize, Vec<E>, u8)> = Vec::new();
    for r in mdisc.iter().filter(|r| r.form == Form::DiscloseAuditor) {
        let w = r.stmt[256 + 30];
        for id in 0..IDS.len() {
            if st::S_AUD > 1 {
                let w2 = ((w as usize + 1) % st::S_AUD) as u8;
                dneg.push((format!("{}: kind window {w} -> {w2}", r.case), r.case.clone(), id, vec![E::StmtSet(256 + 30, vec![w2])], 5));
            }
            dneg.push((format!("{}: kind window {}", r.case, st::S_AUD), r.case.clone(), id, vec![E::StmtSet(256 + 30, vec![st::S_AUD as u8])], 5));
        }
    }
    for (name, case, id, edits) in &mnegs {
        let r = mrows.iter().find(|r| &r.case == case).unwrap();
        let input = apply_to(edits, st::OP_TRANSFER_MULTI, with_id(&r.stmt, &IDS[*id].1), mp[&(case.clone(), *id)].clone(), *id, &proofs, &mp);
        let (out, reason) = precompile(&input);
        assert!(out == "0" || out == "revert", "negative accepted: {name}");
        if reason == "verify" { nver += 1 } else { ndec += 1 }
        nrows.push(o(vec![
            ("name", J::from(name.as_str())),
            ("form", J::from("TRANSFER-MULTI")),
            ("case", J::from(case.as_str())),
            ("id", J::from(IDS[*id].0)),
            ("edits", J::A(edits.iter().map(E::json).collect())),
            ("input_bytes", J::from(input.len())),
            ("input_sha3", hx(&<Sha3_256 as sha3::Digest>::digest(&input))),
            ("expect", J::from(out)),
            ("reason", J::from(reason)),
        ]));
    }
    for (name, case, id, edits, op) in &dneg {
        let r = mdisc.iter().find(|r| &r.case == case).unwrap();
        let input = apply_to(edits, *op, with_id(&r.stmt, &IDS[*id].1), mp[&(case.clone(), *id)].clone(), *id, &proofs, &mp);
        let (out, reason) = precompile(&input);
        assert!(out == "0" || out == "revert", "negative accepted: {name}");
        if reason == "verify" { nver += 1 } else { ndec += 1 }
        nrows.push(o(vec![
            ("name", J::from(name.as_str())),
            ("form", J::from(fname(r.form))),
            ("case", J::from(case.as_str())),
            ("id", J::from(IDS[*id].0)),
            ("edits", J::A(edits.iter().map(E::json).collect())),
            ("input_bytes", J::from(input.len())),
            ("input_sha3", hx(&<Sha3_256 as sha3::Digest>::digest(&input))),
            ("expect", J::from(out)),
            ("reason", J::from(reason)),
        ]));
    }
    eprintln!("negative: {} rows ({ndec} decoder, {nver} verifier): {:.1} s", nrows.len(), t0.elapsed().as_secs_f64());
    // the disclosure opening's codec (pqz-stmt parse_opening, D15: the one canonical abi.encode(bytes, bytes)); base =
    // the TRANSFER bundle with the PQZL DISCLOSE-SENDER proof
    let ob = st::opening(&sc.bundle, &proofs[0][fidx(Form::DiscloseSender)]);
    let (bl, n) = (sc.bundle.len(), ob.len());
    let pad1 = 96 + bl.div_ceil(32) * 32; // end of the padded bundle = the proof's length word
    let w = |x: u64| st::u64_word(x).to_vec();
    let oedits: Vec<(&str, Vec<(usize, Vec<u8>)>, Option<usize>)> = vec![
        ("the canonical opening", vec![], None),
        ("head word 0 = 65", vec![(0, w(65))], None),
        ("head word 1 off by 32", vec![(32, w(pad1 as u64 + 32))], None),
        ("bundle length word >= 2^64", vec![(64, vec![1])], None),
        ("bundle padding byte non-zero", vec![(pad1 - 1, vec![1])], None),
        ("proof length word = 2^63", vec![(pad1, w(1 << 63))], None),
        ("proof padding byte non-zero", vec![(n - 1, vec![1])], None),
        ("one trailing zero byte", vec![], Some(n + 1)),
        ("truncated by 1 byte", vec![], Some(n - 1)),
    ];
    assert!(bl % 32 != 0 && ob[n - 1] == 0, "the padding rows need padding");
    let orows: Vec<J> = oedits
        .into_iter()
        .map(|(name, sets, size)| {
            let mut b = ob.clone();
            let mut ej = Vec::new();
            for (at, x) in &sets {
                b[*at..*at + x.len()].copy_from_slice(x);
                ej.push(o(vec![("set", J::A(vec![J::from(*at), hx(x)]))]));
            }
            if let Some(m) = size {
                b.resize(m, 0);
                ej.push(o(vec![("resize", J::from(m))]));
            }
            let reason = match st::parse_opening(&b) {
                Ok((x, y)) => {
                    assert!(x == &sc.bundle[..] && y == &proofs[0][fidx(Form::DiscloseSender)][..]);
                    "ok".to_string()
                }
                Err(r) => rname(r),
            };
            assert_eq!(reason == "ok", sets.is_empty() && size.is_none(), "{name}");
            o(vec![("name", J::from(name)), ("edits", J::A(ej)), ("reason", J::from(reason))])
        })
        .collect();
    files.push(file(
        "negative.json",
        "Precompile inputs that must give 0 (expect 0) or revert (input over MAX_INPUT, P6f): each is the honest input \
         u8(op) || be32(len) || stmt || proof of (form, id) (statements: statement_*.json under the id; proofs: \
         proof_<id>.json) with edits applied in order: op = the op byte; proof_from = another form's proof (same id); stmt_set / proof_set [offset, hex] overwrite; proof_copy [src, dst, len], proof_swap [a, b, len] move bytes; stmt_resize / proof_resize truncate or zero-extend; \
         stmt_flip / proof_flip [byte, bit]; len_field replaces be32(len); raw = the whole input; input_resize truncates or \
         zero-extends the built input. input_sha3 = SHA3-256 of the input (FIPS 202, not Keccak: Python checks it \
         fast). reason: the pqz-stmt decoder's Reject (D5, D15, R6), or verify (the decoder accepts \
         and the verifier of the id rejects: PQZL specialised and generic agree). Expected outputs from pqz_precompile (C ABI). \
         openings: the disclosure opening abi.encode(bytes bundle, bytes proof) (TRANSFER bundle, PQZL DISCLOSE-SENDER \
         proof) with set [offset, hex] / resize edits, and pqz-stmt parse_opening's result (ok or Opening).",
        vec![("max_input", J::from(st::MAX_INPUT)), ("rows", J::A(nrows)), ("openings", J::A(orows))],
    ));

    // self-test (D13), as pqz-ffi computes it
    {
        let rep = selftest::report().expect("self-test report");
        let (a_digest, kat, m, fft_ok) = (rep.a_digest, rep.kat_digest, rep.m, rep.fft_ok);
        assert_eq!(a_digest, keccak(&[&a_bytes()]));
        let reg = fidx(Form::Register);
        let mut res = Vec::new();
        let mut per = Vec::new();
        for (i, (nm, id)) in IDS.iter().enumerate() {
            let mut s = with_id(&stmts[reg], id);
            let valid = precompile(&st::input(3, &s, &proofs[i][reg])).0 == "1";
            s[95] ^= 1;
            let invalid = precompile(&st::input(3, &s, &proofs[i][reg])).0 == "1";
            res.extend([valid as u8, invalid as u8]);
            per.push((nm.to_string(), o(vec![
                ("proof_keccak", hx(&keccak(&[&proofs[i][reg]]))),
                ("valid", J::from(valid as u8)),
                ("invalid", J::from(invalid as u8)),
            ])));
        }
        // a build without PQZH: no PQZH proof, its two results 0 (selftest.rs)
        res.resize(4, 0);
        assert_eq!(res, if pqz_ffi::PQZH { [1, 0, 1, 0] } else { [1, 0, 0, 0] });
        let hash = keccak(&[&kat, &res]);
        // the compiled-in proofs (build.rs: the REGISTER rows of the files) must be these; after a write that changed
        // them the crate must be rebuilt (stale: --check fails)
        stale = selftest::proofs() != [&proofs[0][reg][..], &proofs[1][reg][..]];
        if !stale {
            assert_eq!(&res[..], &rep.results.map(|b| b as u8)[..]);
            let mut out = [0u8; 32];
            let rc = unsafe { pqz_precompile([6u8, 0, 0, 0, 0].as_ptr(), 5, out.as_mut_ptr(), 32) };
            assert_eq!((rc, out, rep.hash), (pqz_ffi::PQZ_FFI_OK, hash, hash), "OP_SELFTEST through pqz_precompile");
            assert_eq!(selftest::selftest(), Ok(hash));
        }
        files.push(file(
            "selftest.json",
            leak(format!("OP_SELFTEST (P6e D13; pq-zether.md 9.1): input exactly 06 00000000, output keccak256(kat_digest || \
             u8(pqzl_valid) || u8(pqzl_invalid) || u8(pqzh_valid) || u8(pqzh_invalid)); kat_digest = keccak256(a_digest || \
             keccak256(pk) || keccak256(u || v) || M (16 bytes) || keccak256(fft) || u8(fft_ok)): a_digest = matrix.json \
             a_keccak; pk = KeyGen(seed_key); u || v = Enc(pk, digits(msg_value), seed_enc); M = Dec; fft = Ligero's \
             forward FFT over the 1,634-point domain (omega = 3^((q-1)/1634)) of a_i = (i^2 * 0x9E3779B9 + 1) mod q, {}-byte \
             BE elements, fft_ok = the inverse gives a back. The four results: the precompile path on the REGISTER \
             statement (opTag || id || keccak256(SCAAS-PQZ-SELFTEST-V1) || pk) with the REGISTER proof of each id (rnd32 = \
             0x53 x 32), and the same proof with the last message byte flipped (statement byte 95 bit 0). Computed by pqz-ffi \
             (selftest::report, the hash also through pqz_precompile on 06 00000000), whose build.rs compiles in these \
             REGISTER proofs.{}", ph::eb(), if pqz_ffi::PQZH { "" } else { " This set's build has no PQZH: \
             fft is empty (n 0, ok 0) and both PQZH results are 0." })),
            vec![
                ("input", J::from("0600000000")),
                ("seed_key", hx(&SEED_KEY)),
                ("seed_enc", hx(&SEED_ENC_ST)),
                ("rnd32", hx(&RND_ST)),
                ("msg_value", J::from(ST_VALUE)),
                ("message", hx(&keccak(&[b"SCAAS-PQZ-SELFTEST-V1"]))),
                ("a_digest", hx(&a_digest)),
                ("pk_keccak", hx(&rep.pk_hash)),
                ("ct_keccak", hx(&rep.ct_hash)),
                ("M", nums(&m.map(|x| x as i64))),
                ("fft", o(vec![("n", J::from(if pqz_ffi::PQZH { 1634u32 } else { 0 })), ("keccak", hx(&rep.fft_hash)), ("ok", J::from(fft_ok))])),
                ("kat_digest", hx(&kat)),
                ("register", J::O(per)),
                ("results", nums(&res)),
                ("hash", hx(&hash)),
            ],
        ));
    }

    let wc = worstcase();
    eprintln!("worst case: {:.1} s", t0.elapsed().as_secs_f64());
    files.push(file(
        "worstcase_noise.json",
        leak(format!("Completeness at the noise cap (pq-zether.md 4.3, 14; P6e D9): K_MAX - 1 = {c} proven-norm credits to a known \
         receiver key, aligned to maximise the decryption noise in coefficient 0, plus the plain unit, summed into T; the \
         receiver's debit R_TX over T proves and verifies in {SYS}. Stored as seeds, per-credit ctHash and the \
         aggregate (not {c} ciphertexts). bound: the worst case the verifier accepts (attacker-registered key at the \
         norm bounds, T noise {c} * B_FRESH, the plain unit has noise 0); illustrative: an honest key. Margins against \
         the proven range 2^{EB} and the mint threshold Delta - 2^{EB} (pq-zether.md 4.3).", c = th((K_MAX - 1) as i128))),
        wc,
    ));
    // fee = 0 (owner 2026-10-14: accepted for PQZ): an honest debit of every form with a fee word, both ids
    let sc0 = scenario(0);
    let rows0: Vec<J> = sc0
        .rows
        .iter()
        .filter(|r| r.form.op() <= st::OP_BURN)
        .map(|r| {
            let mut kv = r.json.clone();
            kv.extend([("wit", hx(&r.wit)), ("wit_keccak", hx(&keccak(&[&r.wit]))), ("rnd32", hx(&r.rnd))]);
            kv.extend(proofs_json(r.form.op(), &r.stmt, &r.wit, &r.rnd));
            o(kv)
        })
        .collect();
    assert_eq!(rows0.len(), 4);
    files.push(file(
        "fee0.json",
        "fee = 0 (owner 2026-10-14: accepted for PQZ and classical Zether): an honest TRANSFER, TRANSFER0, BURN and \
         REFRESH with fee word 0 and no beneficiary, statement rows as statement_*.json (the scenario's keys and T, Enc \
         seeds 0x72 / 0x74 / 0x75), the witness, rnd32, and both ids' proofs (valid through pqz_precompile).",
        vec![("rows", J::A(rows0))],
    ));
    eprintln!("total: {:.1} s", t0.elapsed().as_secs_f64());
    (files, stale)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let check = args.first().is_some_and(|a| a == "--check");
    let dir = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // the set's vectors: v3 at the canonical path (the contracts' until plan 5h Task 8d), others below it
            let v = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../smartcontracts/vectors/pqz");
            if V3 { v } else { v.join(st::SET) }
        });
    std::fs::create_dir_all(&dir).unwrap();
    let (files, stale) = generate();
    if stale {
        println!("self-test proofs compiled into this binary differ from the REGISTER rows: rebuild, then --check");
    }
    let total: usize = files.iter().map(|f| f.1.len()).sum();
    if !check {
        for (n, s) in &files {
            std::fs::write(dir.join(n), s).unwrap();
            println!("wrote {n} {} B", s.len());
        }
        println!("pqz-vectors: {} files, {total} B", files.len());
        return;
    }
    let mut bad = stale as usize;
    for (n, s) in &files {
        let ok = std::fs::read(dir.join(n)).is_ok_and(|b| b == s.as_bytes());
        println!("{} {n} {} B", if ok { "same" } else { "DIFF" }, s.len());
        bad += !ok as usize;
    }
    for e in std::fs::read_dir(&dir).unwrap() {
        let n = e.unwrap().file_name().into_string().unwrap();
        if n.ends_with(".json") && !files.iter().any(|f| f.0 == n) {
            println!("EXTRA {n}: not written by this generator");
            bad += 1;
        }
    }
    println!("pqz-vectors --check: {} files, {total} B: {}", files.len(), if bad == 0 { "ok" } else { "FAIL" });
    std::process::exit((bad != 0) as i32);
}
