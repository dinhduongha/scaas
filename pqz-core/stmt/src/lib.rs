//! `pqz-stmt`: the one PQZ statement codec (P6e plan R2, D15, R6; pq-zether.md §5, §7.2, §7.7, §7.9, §9.1).
//!
//! Parses and builds every statement form of both proof systems (the statement bytes are the same for PQZL and PQZH;
//! the `proofSystemId` word says which verifier runs), the `pk` / ciphertext objects, the disclosure bundle and
//! opening, and the precompile input. Every decoder accepts exactly one encoding (D15): fixed lengths, coefficients
//! `< q` as `be8`, the header scalars the relations read (`fee`, `amount`) `< 2^64`, `auditorOn` equal to what the
//! length says (op 1: 83,072 B auditor on = 1, 66,560 B off = 0; R6), the opTag of the op, a known `proofSystemId`.
//! For every accepted input `encode(parse(x)) == x`.
//!
//! `no_std` + `alloc`, no dependencies, no `unsafe`, no floats; parsing borrows (no allocation), only the builders
//! allocate. Hashes (`ctHash`, `authDigest`, `entryRef`) need Keccak and stay with the callers.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;

/// q = 2^42 − 215 (CTR-PQZ-03)
pub const Q: u64 = (1 << 42) - 215;
pub const D: usize = 64;
pub const K: usize = 32;
pub type Word = [u8; 32];
/// pk, u: 32 polys × 64 coefficients, `be8`, poly 0 / coefficient 0 first
pub const PK_BYTES: usize = K * D * 8;
/// v: 16 coefficients `be8`
pub const V_BYTES: usize = 16 * 8;
/// ciphertext `u ‖ v` (also `T = u_T ‖ v_T`)
pub const CT_BYTES: usize = PK_BYTES + V_BYTES;

/// §7.7 debit header: 20 words
pub const HEADER_BYTES: usize = 640;
pub const H_OPTAG: usize = 0;
pub const H_ID: usize = 1;
pub const H_CHAIN_ID: usize = 2;
pub const H_TOKEN: usize = 3;
pub const H_REGISTRY: usize = 4;
pub const H_FROM: usize = 5;
pub const H_TO: usize = 6;
pub const H_BENEFICIARY: usize = 7;
pub const H_FEE: usize = 8;
pub const H_AMOUNT: usize = 9;
pub const H_RECIPIENT: usize = 10;
pub const H_SEND_COUNTER: usize = 11;
pub const H_P: usize = 12;
pub const H_VALID_UNTIL: usize = 13;
pub const H_AUDITOR_ON: usize = 14;
pub const H_PLAIN_USED: usize = 15;
pub const H_CHAIN_UID: usize = 16;
pub const H_ENVELOPE: usize = 17;
pub const H_SALT: usize = 18;
pub const H_MEMO_HASH: usize = 19;
/// §7.9 disclosure words: opTag, proofSystemId, chainId, chainUid, token, registry, entryRef, amount, kind
pub const DISC_WORDS: usize = 9;
pub const DW_AMOUNT: usize = 7;
pub const DW_KIND: usize = 8;

pub const OP_TRANSFER: u8 = 1;
pub const OP_BURN: u8 = 2;
pub const OP_REGISTER: u8 = 3;
pub const OP_DISCLOSE_SENDER: u8 = 4;
pub const OP_DISCLOSE_RECEIVER: u8 = 5;
pub const OP_SELFTEST: u8 = 6;

const fn hex32(s: &str) -> Word {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}
const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex"),
    }
}

/// PQZL: `keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")` (D2)
pub const PQZL_ID: Word = hex32("2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f");
/// PQZH: `keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")` (D3)
pub const PQZH_ID: Word = hex32("0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4");
pub const MAX_PROOF_PQZL: usize = 98_304;
pub const MAX_PROOF_PQZH: usize = 262_144;
/// D5: 5 + 83,072 + 262,144 = 345,221 ≤ 393,216
pub const MAX_INPUT: usize = 393_216;

/// `MAX_PROOF(id)`; `None` for an id this codec does not know
pub fn max_proof(id: &Word) -> Option<usize> {
    if *id == PQZL_ID {
        Some(MAX_PROOF_PQZL)
    } else if *id == PQZH_ID {
        Some(MAX_PROOF_PQZH)
    } else {
        None
    }
}

/// The statement forms: op 1 has two (by length), op 2 two and op 5 two (by opTag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    Transfer,
    /// transfer without the auditor (CTR-PQZ-24, D8)
    Transfer0,
    Burn,
    Refresh,
    Register,
    DiscloseSender,
    DiscloseReceiver,
    DiscloseAuditor,
}

pub const FORMS: [Form; 8] = [
    Form::Transfer,
    Form::Transfer0,
    Form::Burn,
    Form::Refresh,
    Form::Register,
    Form::DiscloseSender,
    Form::DiscloseReceiver,
    Form::DiscloseAuditor,
];

impl Form {
    pub const fn op(self) -> u8 {
        match self {
            Form::Transfer | Form::Transfer0 => OP_TRANSFER,
            Form::Burn | Form::Refresh => OP_BURN,
            Form::Register => OP_REGISTER,
            Form::DiscloseSender => OP_DISCLOSE_SENDER,
            Form::DiscloseReceiver | Form::DiscloseAuditor => OP_DISCLOSE_RECEIVER,
        }
    }
    /// `keccak256("SCAAS-PQZ-OP-<NAME>-V1")`
    pub const fn op_tag(self) -> Word {
        match self {
            Form::Transfer | Form::Transfer0 => {
                hex32("ef22f3d1c1fc2edc565522eb73ca8cb782e8780eaf9b1f677965dd0cd5275414")
            }
            Form::Burn => hex32("7383374d83fbb89f84ee079bff7a2742e4acb70f64b0b1e2ef40c34fb4cc1407"),
            Form::Refresh => hex32("f118f2df0f018062e2d4c296a01707dcd7ad7c85f6981d68517ac8b2cd75eede"),
            Form::Register => hex32("69562a9cd615eb3d906cb1934ad56c788c30228d2faf7c517e33d65b4a03c088"),
            Form::DiscloseSender => hex32("868cc07c6ac389251ad6573f65fe35ee4dad66ee305f90c711af904bf5ceef3f"),
            Form::DiscloseReceiver => hex32("d8356cfbd875acb80fe8a8127a57b5c549d20fd65b9acca8672186a1a4296456"),
            Form::DiscloseAuditor => hex32("d6019aa47e04fe91c11df386ddc5bda2178a3f2506c46cdd59b16ef1d21daf81"),
        }
    }
    pub const fn stmt_len(self) -> usize {
        match self {
            Form::Transfer => HEADER_BYTES + 3 * PK_BYTES + CT_BYTES + PK_BYTES + 3 * V_BYTES, // 83,072
            Form::Transfer0 => HEADER_BYTES + 2 * PK_BYTES + CT_BYTES + PK_BYTES + 2 * V_BYTES, // 66,560
            Form::Burn | Form::Refresh => HEADER_BYTES + PK_BYTES + 2 * CT_BYTES,              // 50,048
            Form::Register => 3 * 32 + PK_BYTES,                                                // 16,480
            Form::DiscloseSender | Form::DiscloseReceiver | Form::DiscloseAuditor => {
                DISC_WORDS * 32 + 2 * PK_BYTES + V_BYTES // 33,184
            }
        }
    }
    /// PQZL witness bytes of the prover API (pqz.h; R3: not consensus)
    pub const fn wit_len(self) -> usize {
        match self {
            Form::Transfer => 12_288 + 3 * 32 + 32,
            Form::Transfer0 => 12_288 + 2 * 32 + 32,
            Form::Burn | Form::Refresh => 12_288 + 32 + 16,
            Form::Register => 6_144,
            Form::DiscloseSender => 6_144 + 32,
            Form::DiscloseReceiver | Form::DiscloseAuditor => 6_144,
        }
    }
    fn debit(self) -> bool {
        matches!(self, Form::Transfer | Form::Transfer0 | Form::Burn | Form::Refresh)
    }
    fn disclose(self) -> bool {
        matches!(self, Form::DiscloseSender | Form::DiscloseReceiver | Form::DiscloseAuditor)
    }
}

/// Why a decoder refused its input (one reason per D15 / R6 rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// unknown op, or SELFTEST with a statement
    Op,
    /// opTag is not one of the op's
    OpTag,
    /// unknown proofSystemId
    ProofSystemId,
    /// statement (or object) length is not the form's
    Length,
    /// fee word ≥ 2^64
    Fee,
    /// amount word ≥ 2^64
    Amount,
    /// auditorOn word is not what the length says
    AuditorOn,
    /// a coefficient ≥ q
    Coefficient,
    /// precompile input framing (short, length field, over MAX_INPUT)
    Input,
    /// proof empty or over MAX_PROOF(id)
    ProofLength,
    /// ABI encoding of the opening not canonical
    Opening,
}

/// A 32-byte big-endian word as u64 if it is `< 2^64`.
pub fn word_u64(w: &Word) -> Option<u64> {
    if w[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&w[24..]);
    Some(u64::from_be_bytes(v))
}

pub fn u64_word(x: u64) -> Word {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&x.to_be_bytes());
    w
}

fn word_at(b: &[u8], i: usize) -> Word {
    let mut w = [0u8; 32];
    w.copy_from_slice(&b[32 * i..32 * i + 32]);
    w
}

/// Every `be8` group of `b` is `< q` (and `b` is a whole number of groups).
pub fn coeffs_ok(b: &[u8]) -> bool {
    b.len() % 8 == 0 && b.chunks_exact(8).all(|c| u64::from_be_bytes(c.try_into().unwrap_or([0xff; 8])) < Q)
}

/// The coefficients of `b` (each `< q`) into `out` (`out.len() * 8 == b.len()`).
pub fn read_coeffs(b: &[u8], out: &mut [u64]) -> Result<(), Reject> {
    if b.len() != 8 * out.len() {
        return Err(Reject::Length);
    }
    for (o, c) in out.iter_mut().zip(b.chunks_exact(8)) {
        let v = u64::from_be_bytes(c.try_into().map_err(|_| Reject::Length)?);
        if v >= Q {
            return Err(Reject::Coefficient);
        }
        *o = v;
    }
    Ok(())
}

/// `be8` of each coefficient (each must be `< q`).
pub fn write_coeffs(c: &[u64], out: &mut Vec<u8>) -> Result<(), Reject> {
    for &v in c {
        if v >= Q {
            return Err(Reject::Coefficient);
        }
        out.extend_from_slice(&v.to_be_bytes());
    }
    Ok(())
}

/// A public key (16,384 B, coefficients < q).
pub fn check_pk(b: &[u8]) -> Result<(), Reject> {
    if b.len() != PK_BYTES {
        return Err(Reject::Length);
    }
    if !coeffs_ok(b) {
        return Err(Reject::Coefficient);
    }
    Ok(())
}

/// A ciphertext `u ‖ v` (16,512 B, coefficients < q).
pub fn check_ct(b: &[u8]) -> Result<(), Reject> {
    if b.len() != CT_BYTES {
        return Err(Reject::Length);
    }
    if !coeffs_ok(b) {
        return Err(Reject::Coefficient);
    }
    Ok(())
}

/// `R_REG`: `opTag ‖ proofSystemId ‖ message ‖ pk`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Register<'a> {
    /// opTag, proofSystemId, message
    pub words: [Word; 3],
    pub pk: &'a [u8],
}

/// `R_TX` / `R_TX0` / `R_BURN` (BURN, REFRESH): §7.7 header ‖ `pk_f ‖ [pk_t] ‖ [pk_a] ‖ T ‖ u ‖ [v_t] ‖ v_f ‖ [v_a]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Debit<'a> {
    pub form: Form,
    pub header: [Word; 20],
    pub pk_f: &'a [u8],
    pub pk_t: Option<&'a [u8]>,
    pub pk_a: Option<&'a [u8]>,
    /// `T = u_T ‖ v_T` (16,512 B)
    pub t: &'a [u8],
    pub u: &'a [u8],
    pub v_t: Option<&'a [u8]>,
    pub v_f: &'a [u8],
    pub v_a: Option<&'a [u8]>,
}

/// `R_DS` / `R_DR` (§7.9): 9 words ‖ `pk ‖ u ‖ v`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclose<'a> {
    pub form: Form,
    pub words: [Word; DISC_WORDS],
    pub pk: &'a [u8],
    pub u: &'a [u8],
    pub v: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stmt<'a> {
    Register(Register<'a>),
    Debit(Debit<'a>),
    Disclose(Disclose<'a>),
    /// op 6, empty statement
    SelfTest,
}

impl<'a> Debit<'a> {
    /// A header for `form` with opTag, proofSystemId and auditorOn set (the rest zero, for the caller to fill).
    pub fn header(form: Form, id: &Word) -> [Word; 20] {
        let mut h = [[0u8; 32]; 20];
        h[H_OPTAG] = form.op_tag();
        h[H_ID] = *id;
        if form == Form::Transfer {
            h[H_AUDITOR_ON] = u64_word(1);
        }
        h
    }
    pub fn fee(&self) -> u64 {
        word_u64(&self.header[H_FEE]).unwrap_or(u64::MAX)
    }
    pub fn amount(&self) -> u64 {
        word_u64(&self.header[H_AMOUNT]).unwrap_or(u64::MAX)
    }
}

impl<'a> Disclose<'a> {
    /// The words for `form` with opTag and proofSystemId set (the rest zero).
    pub fn words(form: Form, id: &Word) -> [Word; DISC_WORDS] {
        let mut w = [[0u8; 32]; DISC_WORDS];
        w[0] = form.op_tag();
        w[1] = *id;
        w
    }
    pub fn amount(&self) -> u64 {
        word_u64(&self.words[DW_AMOUNT]).unwrap_or(u64::MAX)
    }
}

impl<'a> Stmt<'a> {
    pub fn form(&self) -> Option<Form> {
        match self {
            Stmt::Register(_) => Some(Form::Register),
            Stmt::Debit(d) => Some(d.form),
            Stmt::Disclose(d) => Some(d.form),
            Stmt::SelfTest => None,
        }
    }
    pub fn proof_system_id(&self) -> Option<&Word> {
        match self {
            Stmt::Register(r) => Some(&r.words[1]),
            Stmt::Debit(d) => Some(&d.header[H_ID]),
            Stmt::Disclose(d) => Some(&d.words[1]),
            Stmt::SelfTest => None,
        }
    }

    /// The statement bytes: the fields concatenated as given (so `encode(parse(x)) == x`); `Err(Length)` if an
    /// object has the wrong length or an optional object does not match the form. Values are not checked: a
    /// builder that puts a non-canonical value in gets bytes that `parse` refuses.
    pub fn encode(&self) -> Result<Vec<u8>, Reject> {
        let mut out = Vec::new();
        let obj = |out: &mut Vec<u8>, b: &[u8], n: usize| -> Result<(), Reject> {
            if b.len() != n {
                return Err(Reject::Length);
            }
            out.extend_from_slice(b);
            Ok(())
        };
        match self {
            Stmt::SelfTest => {}
            Stmt::Register(r) => {
                out.reserve(Form::Register.stmt_len());
                r.words.iter().for_each(|w| out.extend_from_slice(w));
                obj(&mut out, r.pk, PK_BYTES)?;
            }
            Stmt::Disclose(d) => {
                if !d.form.disclose() {
                    return Err(Reject::Length);
                }
                out.reserve(d.form.stmt_len());
                d.words.iter().for_each(|w| out.extend_from_slice(w));
                obj(&mut out, d.pk, PK_BYTES)?;
                obj(&mut out, d.u, PK_BYTES)?;
                obj(&mut out, d.v, V_BYTES)?;
            }
            Stmt::Debit(d) => {
                let (tr, aud) = (matches!(d.form, Form::Transfer | Form::Transfer0), d.form == Form::Transfer);
                if !d.form.debit()
                    || d.pk_t.is_some() != tr
                    || d.v_t.is_some() != tr
                    || d.pk_a.is_some() != aud
                    || d.v_a.is_some() != aud
                {
                    return Err(Reject::Length);
                }
                out.reserve(d.form.stmt_len());
                d.header.iter().for_each(|w| out.extend_from_slice(w));
                obj(&mut out, d.pk_f, PK_BYTES)?;
                for o in [d.pk_t, d.pk_a].into_iter().flatten() {
                    obj(&mut out, o, PK_BYTES)?;
                }
                obj(&mut out, d.t, CT_BYTES)?;
                obj(&mut out, d.u, PK_BYTES)?;
                for o in [d.v_t, Some(d.v_f), d.v_a].into_iter().flatten() {
                    obj(&mut out, o, V_BYTES)?;
                }
            }
        }
        Ok(out)
    }
}

/// Decode the statement of `op` with every D15 / R6 rule, in the order of `pqz_kat.py parse` (opTag, id, length,
/// scalars, auditorOn, coefficients), so both name the same reason. Borrows `stmt`; allocates nothing.
pub fn parse(op: u8, stmt: &[u8]) -> Result<Stmt<'_>, Reject> {
    if op == OP_SELFTEST {
        return if stmt.is_empty() { Ok(Stmt::SelfTest) } else { Err(Reject::Op) };
    }
    if !(OP_TRANSFER..=OP_DISCLOSE_RECEIVER).contains(&op) {
        return Err(Reject::Op);
    }
    let n = stmt.len();
    let tag = &stmt[..n.min(32)];
    let form = FORMS
        .iter()
        .copied()
        .find(|f| f.op() == op && f.op_tag()[..] == *tag && *f != Form::Transfer0)
        .ok_or(Reject::OpTag)?;
    let id = &stmt[n.min(32)..n.min(64)];
    if id != PQZL_ID && id != PQZH_ID {
        return Err(Reject::ProofSystemId);
    }
    // op 1: the form by length (R6)
    let form = match form {
        Form::Transfer if n == Form::Transfer0.stmt_len() => Form::Transfer0,
        f => f,
    };
    if n != form.stmt_len() {
        return Err(Reject::Length);
    }
    match form {
        Form::Register => {
            let pk = &stmt[96..];
            if !coeffs_ok(pk) {
                return Err(Reject::Coefficient);
            }
            Ok(Stmt::Register(Register { words: [word_at(stmt, 0), word_at(stmt, 1), word_at(stmt, 2)], pk }))
        }
        Form::DiscloseSender | Form::DiscloseReceiver | Form::DiscloseAuditor => {
            let mut words = [[0u8; 32]; DISC_WORDS];
            for (i, w) in words.iter_mut().enumerate() {
                *w = word_at(stmt, i);
            }
            if word_u64(&words[DW_AMOUNT]).is_none() {
                return Err(Reject::Amount);
            }
            let body = &stmt[32 * DISC_WORDS..];
            if !coeffs_ok(body) {
                return Err(Reject::Coefficient);
            }
            Ok(Stmt::Disclose(Disclose {
                form,
                words,
                pk: &body[..PK_BYTES],
                u: &body[PK_BYTES..2 * PK_BYTES],
                v: &body[2 * PK_BYTES..],
            }))
        }
        _ => {
            let mut header = [[0u8; 32]; 20];
            for (i, w) in header.iter_mut().enumerate() {
                *w = word_at(stmt, i);
            }
            if word_u64(&header[H_FEE]).is_none() {
                return Err(Reject::Fee);
            }
            if word_u64(&header[H_AMOUNT]).is_none() {
                return Err(Reject::Amount);
            }
            let (tr, aud) = (matches!(form, Form::Transfer | Form::Transfer0), form == Form::Transfer);
            if tr && word_u64(&header[H_AUDITOR_ON]) != Some(aud as u64) {
                return Err(Reject::AuditorOn);
            }
            let body = &stmt[HEADER_BYTES..];
            if !coeffs_ok(body) {
                return Err(Reject::Coefficient);
            }
            let mut o = 0;
            let mut take = |len: usize| {
                let s = &body[o..o + len];
                o += len;
                s
            };
            let pk_f = take(PK_BYTES);
            let pk_t = if tr { Some(take(PK_BYTES)) } else { None };
            let pk_a = if aud { Some(take(PK_BYTES)) } else { None };
            let t = take(CT_BYTES);
            let u = take(PK_BYTES);
            let v_t = if tr { Some(take(V_BYTES)) } else { None };
            let v_f = take(V_BYTES);
            let v_a = if aud { Some(take(V_BYTES)) } else { None };
            Ok(Stmt::Debit(Debit { form, header, pk_f, pk_t, pk_a, t, u, v_t, v_f, v_a }))
        }
    }
}

/// Disclosure bundle `R = salt(16) ‖ u ‖ v_t ‖ [v_a] ‖ toUA(32)` (CTR-PQZ-23): 16,688 B, 16,560 B without `v_a`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle<'a> {
    pub salt: [u8; 16],
    pub u: &'a [u8],
    pub v_t: &'a [u8],
    pub v_a: Option<&'a [u8]>,
    pub to_ua: Word,
}
pub const BUNDLE_BYTES: usize = 16 + PK_BYTES + 2 * V_BYTES + 32;
pub const BUNDLE0_BYTES: usize = 16 + PK_BYTES + V_BYTES + 32;

impl<'a> Bundle<'a> {
    pub fn encode(&self) -> Result<Vec<u8>, Reject> {
        if self.u.len() != PK_BYTES || self.v_t.len() != V_BYTES || self.v_a.is_some_and(|v| v.len() != V_BYTES) {
            return Err(Reject::Length);
        }
        let mut out = Vec::with_capacity(BUNDLE_BYTES);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(self.u);
        out.extend_from_slice(self.v_t);
        if let Some(v) = self.v_a {
            out.extend_from_slice(v);
        }
        out.extend_from_slice(&self.to_ua);
        Ok(out)
    }
}

/// A bundle by its length (with / without `v_a`); coefficients `< q`.
pub fn parse_bundle(b: &[u8]) -> Result<Bundle<'_>, Reject> {
    let aud = match b.len() {
        BUNDLE_BYTES => true,
        BUNDLE0_BYTES => false,
        _ => return Err(Reject::Length),
    };
    let n = b.len();
    if !coeffs_ok(&b[16..n - 32]) {
        return Err(Reject::Coefficient);
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&b[..16]);
    let mut to_ua = [0u8; 32];
    to_ua.copy_from_slice(&b[n - 32..]);
    let u = &b[16..16 + PK_BYTES];
    let v_t = &b[16 + PK_BYTES..16 + PK_BYTES + V_BYTES];
    let v_a = if aud { Some(&b[16 + PK_BYTES + V_BYTES..n - 32]) } else { None };
    Ok(Bundle { salt, u, v_t, v_a, to_ua })
}

fn abi_tail(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&u64_word(b.len() as u64));
    out.extend_from_slice(b);
    out.resize(out.len() + (32 - b.len() % 32) % 32, 0);
}

/// `opening = abi.encode(bytes bundle, bytes proof)` (§7.9).
pub fn opening(bundle: &[u8], proof: &[u8]) -> Vec<u8> {
    let pad1 = bundle.len().div_ceil(32) * 32;
    let mut out = Vec::with_capacity(4 * 32 + pad1 + proof.len().div_ceil(32) * 32);
    out.extend_from_slice(&u64_word(64));
    out.extend_from_slice(&u64_word((64 + 32 + pad1) as u64));
    abi_tail(&mut out, bundle);
    abi_tail(&mut out, proof);
    out
}

/// The canonical `abi.encode(bytes, bytes)`: head offsets 64 and 96 + padded length, zero padding, nothing after.
pub fn parse_opening(b: &[u8]) -> Result<(&[u8], &[u8]), Reject> {
    let w = |i: usize| -> Result<usize, Reject> {
        let s = b.get(i..i + 32).ok_or(Reject::Opening)?;
        let v = word_u64(s.try_into().map_err(|_| Reject::Opening)?).ok_or(Reject::Opening)?;
        usize::try_from(v).map_err(|_| Reject::Opening)
    };
    let tail = |at: usize| -> Result<(&[u8], usize), Reject> {
        let n = w(at)?;
        let end = at.checked_add(32).and_then(|s| s.checked_add(n)).ok_or(Reject::Opening)?;
        let padded = at + 32 + n.div_ceil(32) * 32;
        let data = b.get(at + 32..end).ok_or(Reject::Opening)?;
        let pad = b.get(end..padded).ok_or(Reject::Opening)?;
        if pad.iter().any(|&x| x != 0) {
            return Err(Reject::Opening);
        }
        Ok((data, padded))
    };
    if w(0)? != 64 {
        return Err(Reject::Opening);
    }
    let (bundle, next) = tail(64)?;
    if w(32)? != next {
        return Err(Reject::Opening);
    }
    let (proof, end) = tail(next)?;
    if end != b.len() {
        return Err(Reject::Opening);
    }
    Ok((bundle, proof))
}

/// A decoded precompile input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input<'a> {
    pub op: u8,
    pub stmt: Stmt<'a>,
    pub stmt_bytes: &'a [u8],
    pub proof: &'a [u8],
}

/// `u8(op) ‖ be32(len(stmt)) ‖ stmt ‖ proof` (§9.1).
pub fn input(op: u8, stmt: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + stmt.len() + proof.len());
    out.push(op);
    out.extend_from_slice(&(stmt.len() as u32).to_be_bytes());
    out.extend_from_slice(stmt);
    out.extend_from_slice(proof);
    out
}

/// The precompile's decoder (D5, D15, R6): `≤ MAX_INPUT`, the statement as `parse`, `1 ≤ len(proof) ≤
/// MAX_PROOF(id)`; SELFTEST is exactly `06 00000000`.
pub fn decode_input(b: &[u8]) -> Result<Input<'_>, Reject> {
    if b.len() < 5 || b.len() > MAX_INPUT {
        return Err(Reject::Input);
    }
    let op = b[0];
    let n = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
    let rest = &b[5..];
    if n > rest.len() {
        return Err(Reject::Input);
    }
    let (stmt_bytes, proof) = rest.split_at(n);
    let stmt = parse(op, stmt_bytes)?;
    match stmt.proof_system_id() {
        None => {
            if !proof.is_empty() {
                return Err(Reject::ProofLength);
            }
        }
        Some(id) => {
            let max = max_proof(id).ok_or(Reject::ProofSystemId)?;
            if proof.is_empty() || proof.len() > max {
                return Err(Reject::ProofLength);
            }
        }
    }
    Ok(Input { op, stmt, stmt_bytes, proof })
}

#[cfg(test)]
mod tests;
