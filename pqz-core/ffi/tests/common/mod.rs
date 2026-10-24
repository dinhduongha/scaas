//! Shared by the integration tests: the honest inputs (proved here, or loaded from a child process's file), the
//! decoder-rejection corpus, the abort-freedom generator, the C ABI call.
#![allow(dead_code)]
use pqz_ffi::fixture;
use pqz_ffi::stmt::{self, Form, Reject, H_AUDITOR_ON, H_FEE, H_SALT, H_TO, HEADER_BYTES, MAX_PROOF_PQZH, MAX_PROOF_PQZL};
use pqz_ffi::stmt::{H_LEGS, H_RECIPIENTS_HASH, OP_TRANSFER_MULTI};
use pqz_ffi::*;

pub const RND: [u8; 32] = [0x33; 32];

pub struct Honest {
    pub id: Word,
    pub op: u8,
    /// ops 1-5
    pub form: Option<Form>,
    /// op 7: (M, auditorOn)
    pub multi: Option<(usize, bool)>,
    pub stmt: Vec<u8>,
    pub proof: Vec<u8>,
}

impl Honest {
    pub fn op(&self) -> u8 {
        self.op
    }
    /// the form (`Transfer`, …) or `TransferMulti<M>[_0]`
    pub fn name(&self) -> String {
        match (self.form, self.multi) {
            (Some(f), _) => format!("{f:?}"),
            (_, Some((m, a))) => format!("TransferMulti{m}{}", if a { "" } else { "_0" }),
            _ => "?".into(),
        }
    }
    pub fn input(&self) -> Vec<u8> {
        stmt::input(self.op(), &self.stmt, &self.proof)
    }
    pub fn pqzl(&self) -> bool {
        self.id == PQZL_ID
    }
    /// from a precompile input (decoded: id, form)
    pub fn from_input(b: &[u8]) -> Honest {
        let i = decode(b).expect("honest input");
        let multi = match &i.stmt {
            stmt::Stmt::Multi(m) => Some((m.m, m.pk_a.is_some())),
            _ => None,
        };
        Honest {
            id: *i.stmt.proof_system_id().unwrap(),
            op: i.op,
            form: i.stmt.form(),
            multi,
            stmt: i.stmt_bytes.to_vec(),
            proof: i.proof.to_vec(),
        }
    }
}

/// The ids of this build's parameter set (plan 5h Task 8d: one PQZL and one PQZH id per set): PQZL, and PQZH where it
/// is compiled in.
pub fn ids() -> Vec<Word> {
    if PQZH { vec![PQZL_ID, PQZH_ID] } else { vec![PQZL_ID] }
}

/// Every form of both ids, then every built op 7 shape of both ids, proved (fixture, rnd32 = RND).
pub fn prove_all() -> Vec<Honest> {
    let mut v = Vec::new();
    for id in ids() {
        for c in fixture::cases(&id).expect("fixture") {
            let proof = prove(c.op(), &c.stmt, &c.wit, &RND).unwrap_or_else(|e| panic!("prove {:?} {:?}: {e:?}", id[0], c.form));
            v.push(Honest { id, op: c.op(), form: Some(c.form), multi: None, stmt: c.stmt, proof });
        }
    }
    for id in ids() {
        for c in fixture::multi_cases(&id, usize::MAX).expect("fixture op 7") {
            let proof = prove(c.op(), &c.stmt, &c.wit, &RND).unwrap_or_else(|e| panic!("prove {:?} {}: {e:?}", id[0], c.name()));
            v.push(Honest { id, op: c.op(), form: None, multi: Some((c.m, c.aud)), stmt: c.stmt, proof });
        }
    }
    v
}

/// inputs as `be32(len) ‖ input` records
pub fn to_bytes(hs: &[Honest]) -> Vec<u8> {
    let mut out = Vec::new();
    for h in hs {
        let i = h.input();
        out.extend_from_slice(&(i.len() as u32).to_be_bytes());
        out.extend_from_slice(&i);
    }
    out
}

pub fn from_bytes(mut b: &[u8]) -> Vec<Honest> {
    let mut v = Vec::new();
    while b.len() >= 4 {
        let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
        v.push(Honest::from_input(&b[4..4 + n]));
        b = &b[4 + n..];
    }
    v
}

/// Runs this test binary's test `name` in a child process with `PQZ_FFI_CHILD=arg` (a fresh process: no libpqz state).
pub fn child(name: &str, arg: &str) {
    let st = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads", "1"])
        .env("PQZ_FFI_CHILD", arg)
        .status()
        .unwrap();
    assert!(st.success(), "child {name} {arg}: {st}");
}

pub fn word(b: bool) -> Word {
    if b { VALID } else { INVALID }
}

/// The C ABI on one input: (status, out), `out` pre-filled with 0xEE.
pub fn call(inp: &[u8]) -> (i32, Word) {
    let mut out = [0xEEu8; 32];
    let rc = unsafe { pqz_precompile(inp.as_ptr(), inp.len(), out.as_mut_ptr(), out.len()) };
    (rc, out)
}

/// Input `i` of the abort-freedom generator over `hs`: random bytes, random short framings, honest statements with
/// random proofs, honest inputs with 1–4 bit flips (and sometimes truncated), 1 in 80 an unedited honest input.
pub fn gen(hs: &[Honest], i: usize) -> Vec<u8> {
    let mut x = (i as u64 + 1).wrapping_mul(0x2545_F491_4F6C_DD1D);
    let mut r = move || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let h = &hs[i % hs.len()];
    match i % 5 {
        0 => (0..r() % 2048).map(|_| r() as u8).collect(),
        1 => {
            let mut v: Vec<u8> = (0..5 + r() % 64).map(|_| r() as u8).collect();
            v[0] = 1 + (r() % 6) as u8;
            v
        }
        2 => stmt::input(h.op(), &h.stmt, &(0..1 + r() % 4096).map(|_| r() as u8).collect::<Vec<_>>()),
        4 if r() % 16 == 0 => h.input(),
        _ => {
            let mut v = h.input();
            for _ in 0..1 + r() % 4 {
                let j = r() as usize % v.len();
                v[j] ^= 1 << (r() % 8);
            }
            if r() % 4 == 0 {
                v.truncate(r() as usize % v.len());
            }
            v
        }
    }
}

/// The framing / SELFTEST negatives (precompile …00) besides `negatives`.
pub fn framing(hs: &[Honest]) -> Vec<(&'static str, Vec<u8>)> {
    let st = &hs[0].stmt;
    vec![
        ("empty", vec![]),
        ("4 bytes", vec![1, 0, 0, 0]),
        ("length field over the input", stmt::input(1, st, &[]).into_iter().take(5 + 100).collect()),
        ("selftest + 1 byte", vec![6, 0, 0, 0, 0, 0]),
        ("selftest, length 1", vec![6, 0, 0, 0, 1, 0]),
    ]
}

/// (name, mutated input, expected decoder verdict: Some(reason) or None = decodes, rejected by the verifier)
pub fn negatives(h: &Honest) -> Vec<(String, Vec<u8>, Option<Reject>)> {
    let (op, st, pf) = (h.op(), &h.stmt, &h.proof);
    let max = if h.pqzl() { MAX_PROOF_PQZL } else { MAX_PROOF_PQZH };
    let inp = |op: u8, st: &[u8], pf: &[u8]| stmt::input(op, st, pf);
    let with = |off: usize, f: &dyn Fn(&mut [u8])| {
        let mut s = st.clone();
        f(&mut s[off..]);
        s
    };
    // an op 7 shape that fits MAX_PROOF + 1 within MAX_INPUT (all but n2048-kmax1024's PQZH (4, on): 5 + 132,992 +
    // 262,145 > 393,216, whose boundary `multi_limits_and_memo` checks)
    let over_fits = 5 + st.len() + max + 1 <= MAX_INPUT;
    let mut v: Vec<(String, Vec<u8>, Option<Reject>)> = vec![
        ("op 0".into(), inp(0, st, pf), Some(Reject::Op)),
        ("op 8".into(), inp(8, st, pf), Some(Reject::Op)),
        ("op 1 <-> op 7".into(), inp(if op == OP_TRANSFER_MULTI { 1 } else { OP_TRANSFER_MULTI }, st, pf), Some(Reject::OpTag)),
        ("op 6 with the statement".into(), inp(6, st, pf), Some(Reject::Op)),
        ("other op".into(), inp(op % 5 + 1, st, pf), Some(Reject::OpTag)),
        ("opTag of another op".into(), inp(op, &with(0, &|s| {
            s[..32].copy_from_slice(&if op == 3 { Form::Transfer } else { Form::Register }.op_tag())
        }), pf), Some(Reject::OpTag)),
        ("opTag bit".into(), inp(op, &with(0, &|s| s[0] ^= 1), pf), Some(Reject::OpTag)),
        ("unknown id".into(), inp(op, &with(32, &|s| s[0] ^= 1), pf), Some(Reject::ProofSystemId)),
        ("statement + 1".into(), inp(op, &[&st[..], &[0]].concat(), pf), Some(Reject::Length)),
        ("statement - 1".into(), inp(op, &st[..st.len() - 1], pf), Some(Reject::Length)),
        ("length field + 1".into(), { let mut i = inp(op, st, pf); i[4] += 1; i }, None),
        ("coefficient = q".into(), inp(op, &with(st.len() - 8, &|s| s.copy_from_slice(&stmt::Q.to_be_bytes())), pf),
            Some(Reject::Coefficient)),
        ("coefficient = 2^LOG2Q".into(), inp(op, &with(st.len() - 8, &|s| s.copy_from_slice(&(1u64 << stmt::LOG2Q).to_be_bytes())), pf),
            Some(Reject::Coefficient)),
        ("coefficient top byte".into(), inp(op, &with(st.len() - 8, &|s| s[0] = 0x80), pf), Some(Reject::Coefficient)),
        ("empty proof".into(), inp(op, st, &[]), Some(Reject::ProofLength)),
        ("proof truncated".into(), inp(op, st, &pf[..pf.len() - 1]), None),
        ("proof half".into(), inp(op, st, &pf[..pf.len() / 2]), None),
        ("proof + 1 byte".into(), inp(op, st, &[&pf[..], &[0]].concat()), None),
        ("proof bit 0".into(), { let mut p = pf.clone(); p[0] ^= 1; inp(op, st, &p) }, None),
        ("proof last bit".into(), { let mut p = pf.clone(); *p.last_mut().unwrap() ^= 0x80; inp(op, st, &p) }, None),
        ("proof middle byte".into(), { let mut p = pf.clone(); let m = p.len() / 2; p[m] ^= 0x5a; inp(op, st, &p) }, None),
        ("other system's id".into(), inp(op, &with(32, &|s| s[..32].copy_from_slice(if h.pqzl() { &PQZH_ID } else { &PQZL_ID })), pf), None),
        ("statement last coefficient - 1".into(), inp(op, &with(st.len() - 1, &|s| s[0] ^= 1), pf), None),
    ];
    if over_fits {
        v.push(("MAX_PROOF + 1".into(), inp(op, st, &vec![0; max + 1]), Some(Reject::ProofLength)));
    }
    if let Some((m, aud)) = h.multi {
        let word = |x: u64| stmt::u64_word(x);
        let set = |i: usize, w: stmt::Word| with(32 * i, &move |s| s[..32].copy_from_slice(&w));
        let other_m = if m == 1 { 2 } else { 1 };
        v.extend([
            ("fee 2^64".into(), inp(op, &with(32 * H_FEE + 23, &|s| s[0] = 1), pf), Some(Reject::Fee)),
            ("amount 1".into(), inp(op, &set(stmt::H_AMOUNT, word(1)), pf), Some(Reject::MustBeZero("amount"))),
            ("amount 2^64".into(), inp(op, &with(32 * stmt::H_AMOUNT + 23, &|s| s[0] = 1), pf), Some(Reject::Amount)),
            ("salt high half".into(), inp(op, &with(32 * H_SALT, &|s| s[0] = 1), pf), Some(Reject::Salt)),
            ("fee + 1".into(), inp(op, &with(32 * H_FEE + 31, &|s| s[0] ^= 1), pf), None),
            ("auditorOn 2".into(), inp(op, &set(H_AUDITOR_ON, word(2)), pf), Some(Reject::AuditorOn)),
            ("auditorOn flipped".into(), inp(op, &set(H_AUDITOR_ON, word(!aud as u64)), pf), Some(Reject::Length)),
            ("M word 0".into(), inp(op, &set(H_LEGS, word(0)), pf), Some(Reject::Legs)),
            ("M word 3".into(), inp(op, &set(H_LEGS, word(3)), pf), Some(Reject::Legs)),
            ("M word 16".into(), inp(op, &set(H_LEGS, word(16)), pf), Some(Reject::Legs)),
            ("M word high byte".into(), inp(op, &with(32 * H_LEGS, &|s| s[0] = 1), pf), Some(Reject::Legs)),
            ("M word another built M".into(), inp(op, &set(H_LEGS, word(other_m)), pf), Some(Reject::Length)),
            ("recipientsHash changed".into(), inp(op, &with(32 * H_RECIPIENTS_HASH + 31, &|s| s[0] ^= 1), pf), None),
            ("memoHash changed".into(), inp(op, &with(32 * stmt::H_MEMO_HASH, &|s| s[0] ^= 0x80), pf), None),
            ("body coefficient = q".into(), inp(op, &with(HEADER_BYTES, &|s| s[..8].copy_from_slice(&stmt::Q.to_be_bytes())), pf),
                Some(Reject::Coefficient)),
        ]);
        if !h.pqzl() {
            v.push(("M word 8 (PQZH, not built)".into(), inp(op, &set(H_LEGS, word(8)), pf), Some(Reject::Legs)));
        }
        if (m, aud) == (1, true) {
            // 83,072 B relabelled (M = 2, auditor off): decodes (the words pick the shape), the objects shift, rejected
            let two = with(32 * H_LEGS, &|s| s[..32].copy_from_slice(&stmt::u64_word(2)));
            let two = [&two[..32 * H_AUDITOR_ON], &word(0), &two[32 * H_AUDITOR_ON + 32..]].concat();
            v.push(("(1, on) relabelled (2, off)".into(), inp(op, &two, pf), None));
        }
    }
    if let Some(Form::Transfer | Form::Transfer0 | Form::Burn | Form::Refresh) = h.form {
        let tr = matches!(h.form, Some(Form::Transfer | Form::Transfer0));
        v.extend([
            ("fee 2^64".into(), inp(op, &with(32 * H_FEE + 23, &|s| s[0] = 1), pf), Some(Reject::Fee)),
            ("amount 2^64".into(), inp(op, &with(32 * stmt::H_AMOUNT + 23, &|s| s[0] = 1), pf), Some(Reject::Amount)),
            ("salt high half".into(), inp(op, &with(32 * H_SALT, &|s| s[0] = 1), pf), Some(Reject::Salt)),
            ("fee + 1".into(), inp(op, &with(32 * H_FEE + 31, &|s| s[0] ^= 1), pf), None),
        ]);
        if tr {
            v.extend([
                ("auditorOn 2".into(), inp(op, &with(32 * H_AUDITOR_ON + 31, &|s| s[0] = 2), pf), Some(Reject::AuditorOn)),
                ("auditorOn flipped".into(), inp(op, &with(32 * H_AUDITOR_ON + 31, &|s| s[0] ^= 1), pf), Some(Reject::AuditorOn)),
                ("recipient set".into(), inp(op, &with(32 * stmt::H_RECIPIENT + 31, &|s| s[0] = 1), pf),
                    Some(Reject::MustBeZero("recipient"))),
            ]);
        } else {
            v.push(("toUA set".into(), inp(op, &with(32 * H_TO + 31, &|s| s[0] = 1), pf), Some(Reject::MustBeZero("toUA"))));
        }
        v.push(("body coefficient = q".into(), inp(op, &with(HEADER_BYTES, &|s| s[..8].copy_from_slice(&stmt::Q.to_be_bytes())), pf),
            Some(Reject::Coefficient)));
    }
    if let Some(Form::DiscloseSender | Form::DiscloseReceiver | Form::DiscloseAuditor) = h.form {
        v.push(("disclosure amount 2^64".into(), inp(op, &with(32 * stmt::DW_AMOUNT + 23, &|s| s[0] = 1), pf), Some(Reject::Amount)));
        v.push(("disclosure kind changed".into(), inp(op, &with(32 * stmt::DW_KIND + 31, &|s| s[0] ^= 4), pf), None));
    }
    v
}

