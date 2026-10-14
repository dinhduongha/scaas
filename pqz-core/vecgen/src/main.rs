//! pqz-vectors (P6e Task 11; plan R4, D9, D13): writes every vector file of `smartcontracts/vectors/pqz/` (the one
//! canonical directory, read in place). PQZL values come from the C core (`libpqz.a` of `../build.sh`: KeyGen, Enc,
//! Dec, the matrix, proofs, both verifiers), PQZH proofs from the Ligero crate (THE preset `Params::proven()`); this
//! binary only drives them and writes JSON. Every honest proof is replayed through the precompile path (`pqz-stmt`
//! `decode_input`, then the specialised and the generic PQZL verifier, which must agree, or Ligero), every negative
//! input too.
//!
//!   pqz-vectors [DIR]           write the files (default: ../../smartcontracts/vectors/pqz)
//!   pqz-vectors --check [DIR]   regenerate in memory and compare byte for byte; exit 1 on any difference or on a
//!                               *.json in DIR that this generator does not write
//!
//! Independent checks: `pqz_kat.py --check` (Python, everything but proof validity), `replay_wasm.mjs` (the same
//! proofs from wasm32 builds), `run.sh` (all of it under one label).
use std::path::PathBuf;
use std::time::Instant;

use pqz_stmt::{self as st, Bundle, Debit, Disclose, Form, Register, Reject, Stmt, Word, FORMS, PQZH_ID, PQZL_ID};
use pqzh_ligero::Params;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Keccak256, Sha3_256, Shake256};

const Q: u64 = st::Q;
const DELTA: u64 = (1 << 26) - 1;
const PK: usize = st::PK_BYTES;

// ---------------------------------------------------------------- C core (pqz.h)
extern "C" {
    fn pqz_init(arena: *mut u8, len: usize) -> i32;
    fn pqz_prove(
        op: u8, stmt: *const u8, sl: usize, wit: *const u8, wl: usize, rnd: *const u8, proof: *mut u8, pl: *mut usize,
    ) -> i32;
    fn pqz_verify(op: u8, stmt: *const u8, sl: usize, proof: *const u8, pl: usize) -> i32;
    fn pqz_verify_fast(op: u8, stmt: *const u8, sl: usize, proof: *const u8, pl: usize) -> i32;
    fn pqz_keypair_from_secret(s: *const i8, e: *const i16, pk: *mut u8) -> i32;
    fn pqz_encrypt(
        pks: *const *const u8, n: u32, msgs: *const [u8; 16], r: *const i8, e1: *const i16, e2: *const [i16; 16],
        u: *mut u8, vs: *mut [u8; 128],
    ) -> i32;
    fn pqz_keygen(seed: *const u8, pk: *mut u8, s: *mut i8, e: *mut i16, ctr: *mut u32) -> i32;
    fn pqz_enc_seed(
        pks: *const *const u8, n: u32, msgs: *const [u8; 16], seed: *const u8, u: *mut u8, vs: *mut [u8; 128],
        r: *mut i8, e1: *mut i16, e2: *mut [i16; 16], ctr: *mut u32,
    ) -> i32;
    fn pqz_dec(s: *const i8, ct: *const u8, m: *mut i64, noise: *mut i64) -> i32;
}

const ARENA: usize = 768 << 20; // as pqz_bench.c; R_TX prove peaks at 304 MB (STATUS.md)

fn init() {
    let arena: &'static mut [u8] = Box::leak(vec![0u8; ARENA].into_boxed_slice());
    assert_eq!(unsafe { pqz_init(arena.as_mut_ptr(), arena.len()) }, 0, "pqz_init");
}

struct Key {
    seed: [u8; 32],
    pk: Vec<u8>,
    s: Vec<i8>,
    e: Vec<i16>,
    ctr: u32,
}

fn keygen(seed: [u8; 32]) -> Key {
    let (mut pk, mut s, mut e, mut ctr) = (vec![0u8; PK], vec![0i8; 2048], vec![0i16; 2048], 0u32);
    let rc = unsafe { pqz_keygen(seed.as_ptr(), pk.as_mut_ptr(), s.as_mut_ptr(), e.as_mut_ptr(), &mut ctr) };
    assert_eq!(rc, 0, "pqz_keygen");
    Key { seed, pk, s, e, ctr }
}

impl Key {
    /// prover-API witness of a key (pqz.h, R3): s (int8) ‖ e (int16 LE)
    fn wit(&self) -> Vec<u8> {
        let mut w: Vec<u8> = self.s.iter().map(|&x| x as u8).collect();
        le16(&mut w, &self.e);
        w
    }
}

struct Enc {
    seed: [u8; 32],
    recips: Vec<[u8; 32]>,
    values: Vec<u64>,
    u: Vec<u8>,
    vs: Vec<[u8; 128]>,
    r: Vec<i8>,
    e1: Vec<i16>,
    e2: Vec<[i16; 16]>,
    ctr: u32,
}

fn enc(keys: &[&Key], values: &[u64], seed: [u8; 32]) -> Enc {
    let n = keys.len();
    let pks: Vec<*const u8> = keys.iter().map(|k| k.pk.as_ptr()).collect();
    let msgs: Vec<[u8; 16]> = values.iter().map(|&v| digits(v)).collect();
    let (mut u, mut vs, mut r, mut e1, mut e2, mut ctr) =
        (vec![0u8; PK], vec![[0u8; 128]; n], vec![0i8; 2048], vec![0i16; 2048], vec![[0i16; 16]; n], 0u32);
    let rc = unsafe {
        pqz_enc_seed(
            pks.as_ptr(), n as u32, msgs.as_ptr(), seed.as_ptr(), u.as_mut_ptr(), vs.as_mut_ptr(), r.as_mut_ptr(),
            e1.as_mut_ptr(), e2.as_mut_ptr(), &mut ctr,
        )
    };
    assert_eq!(rc, 0, "pqz_enc_seed");
    Enc { seed, recips: keys.iter().map(|k| k.seed).collect(), values: values.to_vec(), u, vs, r, e1, e2, ctr }
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
            ("recipients", J::A(self.recips.iter().map(|s| hx(s)).collect())),
            ("values", J::A(self.values.iter().map(|&v| J::from(v)).collect())),
        ])
    }
}

fn dec(s: &[i8], ct: &[u8]) -> ([i64; 16], [i64; 16]) {
    let (mut m, mut nz) = ([0i64; 16], [0i64; 16]);
    assert_eq!(unsafe { pqz_dec(s.as_ptr(), ct.as_ptr(), m.as_mut_ptr(), nz.as_mut_ptr()) }, 0, "pqz_dec");
    (m, nz)
}

fn value(m: &[i64; 16]) -> i128 {
    m.iter().rev().fold(0i128, |a, &x| a * 16 + x as i128)
}

fn prove(id: &Word, op: u8, stmt: &[u8], wit: &[u8], rnd: &[u8; 32]) -> Vec<u8> {
    assert_eq!(&stmt[32..64], id);
    if *id == PQZH_ID {
        return pqzh_ligero::prove(op, stmt, wit, *rnd, &Params::proven()).expect("Ligero prove");
    }
    let mut p = vec![0u8; st::MAX_PROOF_PQZL];
    let mut n = p.len();
    let rc = unsafe {
        pqz_prove(op, stmt.as_ptr(), stmt.len(), wit.as_ptr(), wit.len(), rnd.as_ptr(), p.as_mut_ptr(), &mut n)
    };
    assert_eq!(rc, 0, "pqz_prove op {op}");
    p.truncate(n);
    p
}

/// The precompile path as pqz-ffi runs it (P6e Task 7): over MAX_INPUT ⇒ revert; `decode_input` (D5, D15, R6); then
/// the id's verifier. PQZL: the specialised verifier (R5) and, as the reference, the generic one; they must agree.
/// Returns (output, reason): output "1" / "0" / "revert"; reason = the decoder's `Reject`, or "verify".
fn precompile(input: &[u8]) -> (&'static str, String) {
    if input.len() > st::MAX_INPUT {
        return ("revert", "Input".into());
    }
    let inp = match st::decode_input(input) {
        Err(r) => return ("0", rname(r)),
        Ok(i) => i,
    };
    let id = *inp.stmt.proof_system_id().expect("not a selftest input");
    let (op, s, p) = (inp.op, inp.stmt_bytes, inp.proof);
    let ok = if id == PQZL_ID {
        let fast = unsafe { pqz_verify_fast(op, s.as_ptr(), s.len(), p.as_ptr(), p.len()) } == 1;
        let generic = unsafe { pqz_verify(op, s.as_ptr(), s.len(), p.as_ptr(), p.len()) } == 1;
        assert_eq!(fast, generic, "specialised and generic PQZL verifiers disagree");
        fast
    } else {
        pqzh_ligero::verify(op, s, p, &Params::proven())
    };
    (if ok { "1" } else { "0" }, "verify".into())
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

const IDS: [(&str, Word); 2] = [("pqzl", PQZL_ID), ("pqzh", PQZH_ID)];

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
        ("generator", J::from("pqz-core/vecgen (pqz-vectors), P6e Task 11")),
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
    o(vec![("keygen", hx(&k.seed))])
}

struct Scenario {
    rows: Vec<Row>,
    bundle: Vec<u8>,
}

const SEED_F: [u8; 32] = [0x46; 32];
const SEED_T: [u8; 32] = [0x54; 32];
const SEED_A: [u8; 32] = [0x41; 32];
/// the self-test key, message, Enc seed and rnd32 (D13; pqz-ffi `selftest.rs`): the REGISTER rows are its proofs
const SEED_KEY: [u8; 32] = [0x51; 32];
const SEED_ENC_ST: [u8; 32] = [0x52; 32];
const RND_ST: [u8; 32] = [0x53; 32];
const ST_VALUE: u64 = 123_456;

fn rnd_of(f: Form) -> [u8; 32] {
    if f == Form::Register {
        RND_ST
    } else {
        [0x80 + fidx(f) as u8; 32]
    }
}

fn scenario() -> Scenario {
    let (kf, kt, ka, kr) = (keygen(SEED_F), keygen(SEED_T), keygen(SEED_A), keygen(SEED_KEY));
    let (bal0, plain, v, fee) = (1_000_000u64, 1_000u64, 123_456u64, 7u64);
    let acc = enc(&[&kf], &[bal0], [0x61; 32]);
    let t = ct_add(&acc.ct(0), &trivial(plain), false);
    let bal = bal0 + plain;
    let bp = bal - v - fee;
    let out = enc(&[&kt, &kf, &ka], &[v, bp, v], [0x62; 32]);
    let out0 = enc(&[&kt, &kf], &[v, bp], [0x62; 32]);
    let bout = enc(&[&kf], &[bp], [0x64; 32]);
    let rout = enc(&[&kf], &[bal - fee], [0x65; 32]);
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
    txf.extend([("toUA", V::B(vec![0xA2; 32])), ("beneficiaryUA", V::B(vec![0xA3; 32])), ("fee", V::I(fee))]);
    txf.extend(tail.clone());
    txf.extend([("salt", V::B(vec![0x5A; 16])), ("memoHash", V::B(vec![0xD1; 32]))]);
    let mut burnf = common.clone();
    burnf.extend([
        ("beneficiaryUA", V::B(vec![0xA3; 32])),
        ("fee", V::I(fee)),
        ("amount", V::I(v)),
        ("recipient", V::B(vec![0x33; 20])),
    ]);
    burnf.extend(tail.clone());
    burnf.push(("memoHash", V::B(vec![0xD1; 32])));
    let mut reff = common.clone();
    reff.extend([("beneficiaryUA", V::B(vec![0xA3; 32])), ("fee", V::I(fee))]);
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
        rows.push(Row { form, json: stmt_json(form, &s, fields_json(&txf), o(objs), extra), stmt: s, wit: w, rnd: rnd_of(form) });
    }
    for (form, f, e, newbal) in [(Form::Burn, &burnf, &bout, bp), (Form::Refresh, &reff, &rout, bal - fee)] {
        let s = debit(form, f, e);
        let objs = o(vec![("pk_f", keyref(&kf)), ("T", tjson(&acc)), ("out", e.json())]);
        let mut w = kf.wit();
        w.extend(e.wit(&[0]));
        w.extend(digits(newbal));
        rows.push(Row { form, json: stmt_json(form, &s, fields_json(f), objs, vec![]), stmt: s, wit: w, rnd: rnd_of(form) });
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
    let cols: Vec<Vec<u8>> = (0..32)
        .map(|j| {
            let mut s = [0i8; 2048];
            s[64 * j] = 1;
            let mut pk = vec![0u8; PK];
            assert_eq!(unsafe { pqz_keypair_from_secret(s.as_ptr(), [0i16; 2048].as_ptr(), pk.as_mut_ptr()) }, 0);
            pk
        })
        .collect();
    let mut a = Vec::with_capacity(32 * PK);
    for i in 0..32 {
        cols.iter().for_each(|c| a.extend_from_slice(&c[512 * i..512 * (i + 1)]));
    }
    a
}

fn matrix_file() -> (String, String) {
    let a = a_bytes();
    let poly = |i: usize, j: usize| coeffs(&a[(32 * i + j) * 512..(32 * i + j + 1) * 512]);
    let (p0, p31) = (poly(0, 0), poly(31, 31));
    file(
        "matrix.json",
        "The public matrix A (CTR-PQZ-03; SHAKE128 SCAAS-PQZ-A-V2, rejection to [0, q)): keccak256 of its bytes \
         (A[0][0], A[0][1], ..., 64 be8 coefficients each), first / last 8 coefficients of A[0][0] and A[31][31]. From the \
         C core: column j = pqz_keypair_from_secret(unit vector at poly j, 0).",
        vec![
            ("a_bytes", J::from(a.len())),
            ("a_keccak", hx(&keccak(&[&a]))),
            ("A_0_0_first8", nums(&p0[..8])),
            ("A_0_0_last8", nums(&p0[56..])),
            ("A_31_31_first8", nums(&p31[..8])),
            ("A_31_31_last8", nums(&p31[56..])),
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
        "KeyGen(seed32) of pq-zether.md 4.2 by the C core (pqz_keygen): SHAKE256(SCAAS-PQZ-KEYGEN-V1 || seed || be4(ctr)), \
         s <- CBD_1, e <- CBD_20, resample above 36 / 164, pk = A s + e. ctr = the counter used. The searched-resample row \
         was dropped (probability about 2^-70 per seed); the resample path and the counter-64 error are pinned by the \
         test-hook KATs (pqz-core test/pqz_keys_kat.c, pqz_kat.py --c-keys).",
        vec![("rows", J::A(rows))],
    )
}

fn cbd_file() -> (String, String) {
    let mut rows = Vec::new();
    for seed in [[0x00; 32], SEED_F] {
        let k = keygen(seed);
        let stream = [&b"SCAAS-PQZ-KEYGEN-V1"[..], &seed, &k.ctr.to_be_bytes()].concat();
        let e: Vec<i64> = k.e.iter().map(|&x| x as i64).collect();
        let s: Vec<i64> = k.s.iter().map(|&x| x as i64).collect();
        rows.push(o(vec![
            ("stream", hx(&stream)),
            ("parts", J::A(vec![
                part("s[0..64]", 1, 0, &s[..64]),
                part("s[1984..2048]", 1, 2 * 1984, &s[1984..]),
                part("e[0..64]", 20, 2 * 2048, &e[..64]),
                part("e[1984..2048]", 20, 2 * 2048 + 40 * 1984, &e[1984..]),
            ])),
        ]));
    }
    let (kf, kt, ka) = (keygen(SEED_F), keygen(SEED_T), keygen(SEED_A));
    let x = enc(&[&kt, &kf, &ka], &[1, 2, 3], [0x62; 32]);
    let stream = [&b"SCAAS-PQZ-ENC-V1"[..], &x.seed, &x.ctr.to_be_bytes()].concat();
    let r: Vec<i64> = x.r.iter().map(|&v| v as i64).collect();
    let e1: Vec<i64> = x.e1.iter().map(|&v| v as i64).collect();
    let e2: Vec<Vec<i64>> = x.e2.iter().map(|l| l.iter().map(|&v| v as i64).collect()).collect();
    let o2 = 2 * 2048 + 40 * 2048;
    rows.push(o(vec![
        ("stream", hx(&stream)),
        ("parts", J::A(vec![
            part("r[0..64]", 1, 0, &r[..64]),
            part("e1[0..64]", 20, 2 * 2048, &e1[..64]),
            part("e2_0", 20, o2, &e2[0]),
            part("e2_2", 20, o2 + 2 * 40 * 16, &e2[2]),
        ])),
    ]));
    file(
        "cbd.json",
        "CBD_eta samples of the C core's KeyGen / Enc streams (pq-zether.md 4.2): stream = the SHAKE256 input (tag || seed \
         || be4(ctr)); bits LSB-first; a sample = (sum of eta bits) - (sum of the next eta bits) from bit_offset. KeyGen: s \
         (CBD_1, 2048) then e (CBD_20, 2048); Enc (3 recipients): r, e1, then e2_j (16 each).",
        vec![("rows", J::A(rows))],
    )
}

fn part(what: &str, eta: u32, bit: usize, v: &[i64]) -> J {
    o(vec![("what", J::from(what)), ("eta", J::from(eta)), ("bit_offset", J::from(bit)), ("samples", nums(v))])
}

fn enc_file() -> (String, String) {
    let (kf, kt, ka) = (keygen(SEED_F), keygen(SEED_T), keygen(SEED_A));
    let key = |s: &[u8; 32]| [&kf, &kt, &ka].into_iter().find(|k| k.seed == *s).unwrap();
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

// ---------------------------------------------------------------- negative inputs
#[derive(Clone)]
enum E {
    Op(u8),
    ProofFrom(Form),
    StmtSet(usize, Vec<u8>),
    StmtResize(usize),
    ProofResize(usize),
    StmtFlip(usize, u8),
    ProofFlip(usize, u8),
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
            E::StmtSet(at, b) => pair("stmt_set", *at, hx(b)),
            E::StmtResize(n) => o(vec![("stmt_resize", J::from(*n))]),
            E::ProofResize(n) => o(vec![("proof_resize", J::from(*n))]),
            E::StmtFlip(at, b) => pair("stmt_flip", *at, J::from(*b)),
            E::ProofFlip(at, b) => pair("proof_flip", *at, J::from(*b)),
            E::LenField(n) => o(vec![("len_field", J::from(*n))]),
            E::InputResize(n) => o(vec![("input_resize", J::from(*n))]),
            E::Raw(b) => o(vec![("raw", hx(b))]),
        }
    }
}

/// The precompile input of `edits` applied to the honest input of (form, id): op, statement, proof edited in order,
/// then the input built (`u8(op) ‖ be32(len_field or len(stmt)) ‖ stmt ‖ proof`, or `raw`) and resized.
fn apply(edits: &[E], form: Option<Form>, id: usize, stmts: &[Vec<u8>], proofs: &[[Vec<u8>; 8]; 2]) -> Vec<u8> {
    let (mut op, mut s, mut p) = match form {
        Some(f) => (f.op(), with_id(&stmts[fidx(f)], &IDS[id].1), proofs[id][fidx(f)].clone()),
        None => (0, vec![], vec![]),
    };
    let (mut lenf, mut raw, mut size) = (None, None, None);
    for e in edits {
        match e {
            E::Op(x) => op = *x,
            E::ProofFrom(f) => p = proofs[id][fidx(*f)].clone(),
            E::StmtSet(at, b) => s[*at..*at + b.len()].copy_from_slice(b),
            E::StmtResize(n) => s.resize(*n, 0),
            E::ProofResize(n) => p.resize(*n, 0),
            E::StmtFlip(at, b) => s[*at] ^= 1 << b,
            E::ProofFlip(at, b) => p[*at] ^= 1 << b,
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
    for id in 0..2 {
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
            add(format!("{nm}: the other system's proofSystemId"), f, vec![E::StmtSet(32, IDS[1 - id].1.to_vec())]);
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
            ("auditorOn 0 on the 83,072-byte form (R6)", Transfer, set(448, w(0))),
            ("auditorOn 2 (R6)", Transfer, set(448, w(2))),
            ("auditorOn 1 on the 66,560-byte form (R6)", Transfer0, set(448, w(1))),
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
            ("pk_a coefficient 0 = 2^42", Transfer, set(640 + 2 * PK, qb(1 << 42))),
            ("T coefficient 0 = q", Transfer, set(640 + 3 * PK, qb(Q))),
            ("u coefficient 0 = 2^64 - 1", Transfer, set(640 + 3 * PK + st::CT_BYTES, qb(u64::MAX))),
            ("v_a last coefficient = q", Transfer, set(83072 - 8, qb(Q))),
            ("v_f last coefficient = q", Transfer0, set(66560 - 8, qb(Q))),
            ("v_f last coefficient = q", Burn, set(50048 - 8, qb(Q))),
            ("pk coefficient 0 = q", Register, set(96, qb(Q))),
            ("pk last coefficient = 2^42", Register, set(16480 - 8, qb(1 << 42))),
            ("pk coefficient 0 = q", DiscloseSender, set(288, qb(Q))),
            ("u coefficient 0 = q", DiscloseReceiver, set(288 + PK, qb(Q))),
            ("v last coefficient = q", DiscloseAuditor, set(33184 - 8, qb(Q))),
            ("REFRESH opTag on the BURN statement", Burn, set(0, Refresh.op_tag().to_vec())),
            ("BURN opTag on the REFRESH statement", Refresh, set(0, Burn.op_tag().to_vec())),
            ("AUDITOR opTag on the RECEIVER statement", DiscloseReceiver, set(0, DiscloseAuditor.op_tag().to_vec())),
            ("RECEIVER opTag on the AUDITOR statement", DiscloseAuditor, set(0, DiscloseReceiver.op_tag().to_vec())),
            ("REGISTER opTag under op 1", Transfer, set(0, Register.op_tag().to_vec())),
            ("RECEIVER opTag under op 4", DiscloseSender, set(0, DiscloseReceiver.op_tag().to_vec())),
            ("message bit flipped (the self-test's invalid case)", Register, vec![E::StmtFlip(95, 0)]),
            ("chainId bit flipped", Transfer, vec![E::StmtFlip(64 + 31, 0)]),
            ("pk_f coefficient 0 low bit flipped", Transfer, vec![E::StmtFlip(640 + 7, 0)]),
            ("v_f low bit flipped", Transfer0, vec![E::StmtFlip(66560 - 1, 0)]),
            ("kind word changed", DiscloseSender, vec![E::StmtFlip(256 + 31, 0)]),
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
            ("length field = statement + proof + 1", Transfer, vec![E::LenField((83072 + pl(Transfer) + 1) as u32)]),
            ("length field = statement + 1", Transfer, vec![E::LenField(83073)]),
            ("input of 4 bytes", Transfer, vec![E::InputResize(4)]),
        ];
        for (name, f, e) in d15 {
            add(format!("{}: {name}", fname(f)), f, e);
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
const K_MAX: usize = 1024;
const B_R: i64 = 36 * 36;
const B_E1: i64 = 164 * 164;
const CREDIT: u64 = (1 << 48) - 1;

/// coefficient-0 weights: (x·y)[0] = Σ_k rot(x)_k y_k in Z[X]/(X^64 + 1), per poly
fn rot(x: &[i64]) -> Vec<i64> {
    (0..2048).map(|i| if i % 64 == 0 { x[i] } else { -x[i - i % 64 + 64 - i % 64] }).collect()
}

/// max Σ w_k r_k over integers with Σ r_k² ≤ b: greedy over the increments (k, a) (|r_k| a → a + 1, gain |w_k|,
/// cost 2a + 1) by gain / cost descending, ties by (k, a); an increment is taken while the cost fits
fn align_r(w: &[i64], b: i64) -> Vec<i64> {
    let mut c: Vec<(i64, i64, usize)> =
        (0..2048).filter(|&k| w[k] != 0).flat_map(|k| (0..36).map(move |a| (w[k].abs(), a, k))).collect();
    c.sort_by(|x, y| (y.0 * (2 * x.1 + 1)).cmp(&(x.0 * (2 * y.1 + 1))).then(x.2.cmp(&y.2)).then(x.1.cmp(&y.1)));
    let (mut r, mut left) = (vec![0i64; 2048], b);
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
    let s: Vec<usize> = (0..2048).filter(|&i| z[i] != 0).collect();
    let n = s.len() as i64;
    let mut l = 0;
    while (l + 1) * (l + 1) * n <= B_E1 {
        l += 1;
    }
    let x = ((B_E1 - l * l * n) / (2 * l + 1)) as usize;
    let pr = shake256(&[b"SCAAS-PQZ-WORSTCASE-V1", &WC_GEN, &k.to_be_bytes()], 4 * 2048);
    let mut ord = s.clone();
    ord.sort_by_key(|&i| (u32::from_be_bytes(pr[4 * i..4 * i + 4].try_into().unwrap()), i));
    let mut e1 = vec![0i64; 2048];
    for (rank, &i) in ord.iter().enumerate() {
        e1[i] = -z[i].signum() * (l + (rank < x) as i64);
    }
    e1
}

struct Worst {
    json: Vec<(&'static str, J)>,
    stmt: Vec<u8>,
    wit: Vec<u8>,
    proofs: [Vec<u8>; 2],
}

fn worstcase() -> Worst {
    let kr = keygen(WC_RECV);
    let (kt, ka) = (keygen(SEED_T), keygen(SEED_A));
    let w = rot(&kr.e.iter().map(|&x| x as i64).collect::<Vec<_>>());
    let z = rot(&kr.s.iter().map(|&x| x as i64).collect::<Vec<_>>());
    let r = align_r(&w, B_R);
    let r8: Vec<i8> = r.iter().map(|&x| x as i8).collect();
    let mut e2 = [0i16; 16];
    e2[0] = 64;
    let msg = digits(CREDIT);
    let mut t = vec![0u8; st::CT_BYTES];
    let (mut hashes, mut cat) = (Vec::new(), Vec::new());
    let ncr = K_MAX - 1;
    let (mut e1sq, mut noise0) = (None, None);
    for k in 0..ncr as u32 {
        let e1: Vec<i16> = align_e1(&z, k).iter().map(|&x| x as i16).collect();
        let (mut u, mut vs) = (vec![0u8; PK], [[0u8; 128]; 1]);
        let rc = unsafe {
            pqz_encrypt([kr.pk.as_ptr()].as_ptr(), 1, [msg].as_ptr(), r8.as_ptr(), e1.as_ptr(), [e2].as_ptr(), u.as_mut_ptr(), vs.as_mut_ptr())
        };
        assert_eq!(rc, 0, "pqz_encrypt");
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
    assert!(maxn < 1 << 24);

    let (v, fee) = (1_000_000u64, 7u64);
    let bp = bal - v - fee;
    let out = enc(&[&kt, &kr, &ka], &[v, bp, v], WC_OUT);
    let f = vec![
        ("chainId", V::I(22776)),
        ("token", V::B(vec![0x11; 20])),
        ("registry", V::B(vec![0x22; 20])),
        ("fromUA", V::B(vec![0xB1; 32])),
        ("toUA", V::B(vec![0xA2; 32])),
        ("fee", V::I(fee)),
        ("sendCounter", V::I(1)),
        ("p", V::I(ncr as u64)),
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
        t: &t,
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
    let proofs: [Vec<u8>; 2] = std::array::from_fn(|i| prove(&IDS[i].1, 1, &with_id(&stmt, &IDS[i].1), &wit, &WC_RND));
    let pj = |i: usize| {
        let p = &proofs[i];
        o(vec![("proof_bytes", J::from(p.len())), ("proof_keccak", hx(&keccak(&[p]))), ("proof_fnv", J::from(fnv(p))), ("proof", hx(p))])
    };
    let json = vec![
        ("k_max", J::from(K_MAX)),
        ("credits_n", J::from(ncr)),
        ("receiver_seed", hx(&WC_RECV)),
        ("generator_seed", hx(&WC_GEN)),
        ("credit_value", J::from(CREDIT)),
        ("plain_used", J::from(plain)),
        ("alignment", J::from(
            "Noise of a credit in coefficient 0 = <rot(e), r> - <rot(s), e1> + e2[0] for the receiver key (s, e), rot(x) \
             per poly = (x_0, -x_63, ..., -x_1). r: the same for every credit, greedy max of <rot(e), r> with ||r||^2 <= \
             1296 over integer increments (k, a) (gain |w_k|, cost 2a + 1) by gain / cost descending, ties by (k, a). \
             e1 of credit k: every coordinate with rot(s) != 0 at level L (largest with L^2 N <= 26896), X = (26896 - L^2 \
             N) / (2L + 1) of them at L + 1, the X first by (prio, index), prio_i = be32 of SHAKE256(SCAAS-PQZ-WORSTCASE-V1 \
             || generator_seed || be4(k)) bytes 4i..4i+4, sign -sign(rot(s)). e2 = (64, 0, ..., 0). Message digits(credit_value). \
             Credits by pqz_encrypt (C), T = sum of the credits + Trivial(digits(plain_used)) mod q.",
        )),
        ("credit_norms_sq", o(vec![("r", J::from(sq(&r))), ("e1", J::from(e1sq.unwrap())), ("e2", J::from(64 * 64u64))])),
        ("credit_noise0", J::from(noise0.unwrap())),
        ("credits_ct_keccak", J::A(hashes)),
        ("credits_keccak", hx(&keccak(&[&cat]))),
        ("T_keccak", hx(&keccak(&[&t]))),
        ("T_M", nums(&tm)),
        ("T_noise", nums(&tn)),
        ("bound", o(vec![
            ("b_fresh", J::from(11_872u64)),
            ("k_max_times_b_fresh", J::from(11_872u64 * K_MAX as u64)),
            ("e_T_range", J::from(1u64 << 24)),
            ("max_abs_noise", J::from(maxn)),
        ])),
        ("debit", o(vec![
            ("form", J::from("TRANSFER")),
            ("op", J::from(1u8)),
            ("header", fields_json(&f)),
            ("objects", o(vec![
                ("pk_f", keyref(&kr)),
                ("pk_t", keyref(&kt)),
                ("pk_a", keyref(&ka)),
                ("T", J::from("the aggregate T above")),
                ("out", out.json()),
            ])),
            ("stmt_bytes", J::from(stmt.len())),
            ("stmt", hx(&stmt)),
            ("stmt_keccak", J::O(IDS.iter().map(|(n, id)| (n.to_string(), hx(&keccak(&[&with_id(&stmt, id)])))).collect())),
            ("wit", hx(&wit)),
            ("wit_keccak", hx(&keccak(&[&wit]))),
            ("rnd32", hx(&WC_RND)),
            ("pqzl", pj(0)),
            ("pqzh", pj(1)),
        ])),
    ];
    Worst { json, stmt, wit, proofs }
}

// ---------------------------------------------------------------- everything
fn generate() -> Vec<(String, String)> {
    let t0 = Instant::now();
    let mut files = vec![matrix_file(), cbd_file(), keygen_file(), enc_file()];
    eprintln!("keys / cbd / matrix / enc: {:.1} s", t0.elapsed().as_secs_f64());

    let sc = scenario();
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
    for (i, (nm, id)) in IDS.iter().enumerate() {
        let rows = sc
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
                    kv.push(("max_proof_len", J::from(Params::proven().max_proof_len(r.form))));
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
        let pp = Params::proven();
        let (desc, params) = if *id == PQZL_ID {
            (
                "PQZL proofs (proofSystemId v2, D2) of every statement form, from the C core (pqz_prove, hedged: CTR-PQZ-19), \
                 fixed rnd32: deterministic, byte-exact on every build (native = wasm32). statement: the row of that file, \
                 under this id. wit: the prover-API witness (pqz.h, R3; not consensus), rebuilt by pqz_kat.py from the \
                 seeds. proof_fnv = FNV-1a 32 of the proof. Disclosures: opening = abi.encode(bytes bundle, bytes proof) \
                 with the TRANSFER bundle. Validity: pqz-vectors --check (specialised and generic verifier).",
                o(vec![("max_proof", J::from(st::MAX_PROOF_PQZL))]),
            )
        } else {
            (
                "PQZH proofs (Ligero over F_q, proofSystemId D3) of every statement form, from pqzh-ligero (THE proven \
                 preset, params), fixed rnd32: deterministic, byte-exact native = wasm32. Fields as proof_pqzl.json; \
                 max_proof_len = the verifier's exact bound for the form. Validity: pqz-vectors --check (Ligero verify).",
                o(vec![
                    ("n", J::from(pp.n)),
                    ("k", J::from(pp.k)),
                    ("ell", J::from(pp.ell)),
                    ("t", J::from(pp.t)),
                    ("pow_bits", J::from(pp.pow_bits)),
                    ("max_proof", J::from(st::MAX_PROOF_PQZH)),
                ]),
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
    eprintln!("negative: {} rows ({ndec} decoder, {nver} verifier): {:.1} s", negs.len(), t0.elapsed().as_secs_f64());
    files.push(file(
        "negative.json",
        "Precompile inputs that must give 0 (expect 0) or revert (input over MAX_INPUT, P6f): each is the honest input \
         u8(op) || be32(len) || stmt || proof of (form, id) (statements: statement_*.json under the id; proofs: \
         proof_<id>.json) with edits applied in order: op = the op byte; proof_from = another form's proof (same id); stmt_set [offset, hex] overwrites; stmt_resize / proof_resize truncate or zero-extend; \
         stmt_flip / proof_flip [byte, bit]; len_field replaces be32(len); raw = the whole input; input_resize truncates or \
         zero-extends the built input. input_sha3 = SHA3-256 of the input (FIPS 202, not Keccak: Python checks it \
         fast). reason: the pqz-stmt decoder's Reject (D5, D15, R6), or verify (the decoder accepts \
         and the verifier of the id rejects: PQZL specialised and generic agree).",
        vec![("max_input", J::from(st::MAX_INPUT)), ("rows", J::A(nrows))],
    ));

    // self-test (D13), as pqz-ffi computes it
    {
        let a_digest = keccak(&[&a_bytes()]);
        let key = keygen(SEED_KEY);
        let c = enc(&[&key], &[ST_VALUE], SEED_ENC_ST);
        let ct = c.ct(0);
        let (m, _) = dec(&key.s, &ct);
        let m8: Vec<u8> = m.iter().map(|&x| x as u8).collect();
        let n = 2 * 19 * 43;
        let d = pqzh_ligero::fft::Domain::new(n);
        let a: Vec<pqzh_ligero::fq::Fq> =
            (0..n as u64).map(|i| pqzh_ligero::fq::Fq((i * i * 0x9E37_79B9 + 1) % pqzh_ligero::fq::Q)).collect();
        let fv = d.fft(&a);
        let mut fb = Vec::new();
        fv.iter().for_each(|x| x.put(&mut fb));
        let fft_ok = d.ifft(&fv) == a;
        let kat = keccak(&[&a_digest, &keccak(&[&key.pk]), &keccak(&[&ct]), &m8, &keccak(&[&fb]), &[fft_ok as u8]]);
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
        assert_eq!(res, [1, 0, 1, 0]);
        let hash = keccak(&[&kat, &res]);
        files.push(file(
            "selftest.json",
            "OP_SELFTEST (P6e D13; pq-zether.md 9.1): input exactly 06 00000000, output keccak256(kat_digest || \
             u8(pqzl_valid) || u8(pqzl_invalid) || u8(pqzh_valid) || u8(pqzh_invalid)); kat_digest = keccak256(a_digest || \
             keccak256(pk) || keccak256(u || v) || M (16 bytes) || keccak256(fft) || u8(fft_ok)): a_digest = matrix.json \
             a_keccak; pk = KeyGen(seed_key); u || v = Enc(pk, digits(msg_value), seed_enc); M = Dec; fft = Ligero's \
             forward FFT over the 1,634-point domain (omega = 3^((q-1)/1634)) of a_i = (i^2 * 0x9E3779B9 + 1) mod q, 6-byte \
             BE elements, fft_ok = the inverse gives a back. The four results: the precompile path on the REGISTER \
             statement (opTag || id || keccak256(SCAAS-PQZ-SELFTEST-V1) || pk) with the REGISTER proof of each id (rnd32 = \
             0x53 x 32), and the same proof with the last message byte flipped (statement byte 95 bit 0). The derivation of \
             pqz-ffi's selftest.rs (branch p6e-a3); its compiled-in proofs must equal these.",
            vec![
                ("input", J::from("0600000000")),
                ("seed_key", hx(&SEED_KEY)),
                ("seed_enc", hx(&SEED_ENC_ST)),
                ("rnd32", hx(&RND_ST)),
                ("msg_value", J::from(ST_VALUE)),
                ("message", hx(&keccak(&[b"SCAAS-PQZ-SELFTEST-V1"]))),
                ("a_digest", hx(&a_digest)),
                ("pk_keccak", hx(&keccak(&[&key.pk]))),
                ("ct_keccak", hx(&keccak(&[&ct]))),
                ("M", nums(&m)),
                ("fft", o(vec![("n", J::from(n)), ("keccak", hx(&keccak(&[&fb]))), ("ok", J::from(fft_ok))])),
                ("kat_digest", hx(&kat)),
                ("register", J::O(per)),
                ("results", nums(&res)),
                ("hash", hx(&hash)),
            ],
        ));
    }

    let wc = worstcase();
    for (i, (nm, id)) in IDS.iter().enumerate() {
        let s = with_id(&wc.stmt, id);
        assert_eq!(precompile(&st::input(1, &s, &wc.proofs[i])), ("1", "verify".to_string()), "worst case {nm}");
        assert_eq!(wc.proofs[i], prove(id, 1, &s, &wc.wit, &WC_RND));
    }
    eprintln!("worst case: {:.1} s", t0.elapsed().as_secs_f64());
    files.push(file(
        "worstcase_noise.json",
        "Completeness at the noise cap (pq-zether.md 4.3, 14; P6e D9): K_MAX - 1 = 1,023 proven-norm credits to a known \
         receiver key, aligned to maximise the decryption noise in coefficient 0, plus the plain unit, summed into T; the \
         receiver's debit R_TX over T proves and verifies in both systems. Stored as seeds, per-credit ctHash and the \
         aggregate (not 1,023 ciphertexts). The noise stays under the proven range 2^24 and the K_MAX * B_FRESH bound.",
        wc.json,
    ));
    eprintln!("total: {:.1} s", t0.elapsed().as_secs_f64());
    files
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let check = args.first().is_some_and(|a| a == "--check");
    let dir = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../smartcontracts/vectors/pqz"));
    // the C prover keeps a ~100 KB proof buffer on the stack: one worker with a large stack
    let files = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(|| {
            init();
            generate()
        })
        .unwrap()
        .join()
        .expect("generator panicked");
    let total: usize = files.iter().map(|f| f.1.len()).sum();
    if !check {
        for (n, s) in &files {
            std::fs::write(dir.join(n), s).unwrap();
            println!("wrote {n} {} B", s.len());
        }
        println!("pqz-vectors: {} files, {total} B", files.len());
        return;
    }
    let mut bad = 0;
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
