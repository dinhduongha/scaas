//! Test and bench inputs (feature `bench`): the same keys, ciphertexts, statements and witnesses as pqz-core's
//! test/pqz_bench.c setup() (same xorshift stream, same samplers, all five relations), so the bytes can be compared
//! with pqz-core's (xcheck/ligero.sh); the mutations of the benches and tests. Layout constants and the coefficient
//! codec are pqz-stmt's.

use pqz_stmt::{DISC_WORDS, DW_AMOUNT, DW_KIND, Form, H_AMOUNT, H_AUDITOR_ON, H_FEE, HEADER_BYTES, PQZH_ID};

use crate::ring::*;

/// byte offsets of the statement words the tests and mutations touch (pq-zether.md §7.7, §7.9)
pub const PREFIX: usize = 64;
pub const HDR_FEE: usize = 32 * H_FEE;
pub const HDR_AMOUNT: usize = 32 * H_AMOUNT;
pub const HDR_AUDITOR_ON: usize = 32 * H_AUDITOR_ON;
pub const DISC_AMOUNT: usize = 32 * DW_AMOUNT;
pub const DISC_KIND: usize = 32 * DW_KIND;
pub const DISC_PK: usize = 32 * DISC_WORDS;

pub struct Rng(pub u64);

impl Rng {
    pub fn new() -> Self {
        Rng(0x243F6A8885A308D3)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(2685821657736338717)
    }
    fn cbd(&mut self, eta: u32) -> i64 {
        let r = self.next();
        let (mut a, mut b) = (0i64, 0i64);
        for i in 0..eta {
            a += ((r >> i) & 1) as i64;
            b += ((r >> (32 + i)) & 1) as i64;
        }
        a - b
    }
    /// short vector of n coefficients with l2 bound (resampled as KeyGen / Enc do)
    pub fn short(&mut self, n: usize, eta: u32, bound: i64) -> Vec<i64> {
        loop {
            let x: Vec<i64> = (0..n).map(|_| self.cbd(eta)).collect();
            if x.iter().map(|v| v * v).sum::<i64>() <= bound * bound {
                return x;
            }
        }
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

/// the first n coefficients of each polynomial, canonical, as pqz-stmt writes them (be8 < q)
fn wr(out: &mut Vec<u8>, v: &[Poly], n: usize) {
    for p in v {
        let c: Vec<u64> = p[..n].iter().map(|&x| x.rem_euclid(Q as i64) as u64).collect();
        pqz_stmt::write_coeffs(&c, out).unwrap();
    }
}

fn wr_vec(out: &mut Vec<u8>, v: &[Poly]) {
    wr(out, v, D);
}

fn wr_v(out: &mut Vec<u8>, p: &Poly) {
    wr(out, std::slice::from_ref(p), 16);
}

pub struct Key {
    pub s: Vec<i64>,
    pub e: Vec<i64>,
    pub pk: Vec<Poly>,
}

pub fn keygen(rng: &mut Rng) -> Key {
    let s = rng.short(2048, 1, 36);
    let e = rng.short(2048, 20, 164);
    let pk = keypair(&polys(&s), &polys(&e));
    Key { s, e, pk }
}

pub struct Setup {
    pub reg_stmt: Vec<u8>,
    pub reg_wit: Vec<u8>,
    pub tx_stmt: Vec<u8>,
    pub tx_wit: Vec<u8>,
    pub burn_stmt: Vec<u8>,
    pub burn_wit: Vec<u8>,
    pub ds_stmt: Vec<u8>,
    pub ds_wit: Vec<u8>,
    pub dr_stmt: Vec<u8>,
    pub dr_wit: Vec<u8>,
}

impl Setup {
    /// (statement, witness) of a relation (REFRESH / AUDITOR: BURN's / DISCLOSE-RECEIVER's, opTag not patched)
    pub fn rel(&self, f: Form) -> (&Vec<u8>, &Vec<u8>) {
        match f {
            Form::Register => (&self.reg_stmt, &self.reg_wit),
            Form::Transfer => (&self.tx_stmt, &self.tx_wit),
            Form::Burn | Form::Refresh => (&self.burn_stmt, &self.burn_wit),
            Form::DiscloseSender => (&self.ds_stmt, &self.ds_wit),
            Form::DiscloseReceiver | Form::DiscloseAuditor => (&self.dr_stmt, &self.dr_wit),
            Form::Transfer0 => panic!("R_TX0: Task 8"),
        }
    }
}

/// relation names as the benches print them
pub fn rel_name(f: Form) -> &'static str {
    match f {
        Form::Register => "R_REG",
        Form::Transfer => "R_TX",
        Form::Transfer0 => "R_TX0",
        Form::Burn | Form::Refresh => "R_BURN",
        Form::DiscloseSender => "R_DS",
        Form::DiscloseReceiver | Form::DiscloseAuditor => "R_DR",
    }
}

fn le16(out: &mut Vec<u8>, v: &[i64]) {
    for &x in v {
        out.extend_from_slice(&(x as i16).to_le_bytes());
    }
}

/// Overrides for negative tests (an honest prover refuses these witnesses).
#[derive(Default, Clone)]
pub struct Tweak {
    /// secret of key F (R_REG, R_TX, R_BURN), pk_f recomputed
    pub s_f: Option<Vec<i64>>,
    /// secret of key T (R_DR; the transfer and the disclosures use the recomputed pk_t)
    pub s_t: Option<Vec<i64>>,
    /// encryption randomness r and e1 of the transfer (R_TX, R_DS) and of the burn (R_BURN); ciphertexts re-encrypted
    pub r: Option<Vec<i64>>,
    pub e1: Option<Vec<i64>>,
    /// R_TX amount digits (v_t, v_a)
    pub d: Option<[u8; 16]>,
    /// R_TX e2_t (also R_DS's e2)
    pub e2_t: Option<Vec<i64>>,
    /// R_BURN new-balance digits d' (v_f)
    pub burn_dp: Option<[u8; 16]>,
    /// R_BURN e2_f
    pub burn_e2: Option<Vec<i64>>,
    /// proofSystemId written at statement bytes 32..63 (default PQZH's, D3; any other is rejected by `cs::parse`)
    pub psid: Option<[u8; 32]>,
}

/// pqz_bench.c setup(): R_REG for key F, R_TX = balance 1,000,000 in T, transfer 123,456 with fee 7; R_TX in the
/// §7.7 layout (640-byte header, fee word at 256, the other header words filled as pqz_bench.c does); R_DS / R_DR
/// disclose the transfer's receiver leg (u, v_t) of 123,456 to pk_t; R_BURN burns 123,456 with fee 7 from the same T.
pub fn setup() -> Setup {
    setup_with(&Tweak::default())
}

/// Statements as the precompile takes them (plan D15 / R6): bytes 0..63 = the op's opTag and the id (pqz_bench.c
/// writes filler before the id); the header words D15 pins as pqz_bench.c sets them (R_TX auditorOn 1, recipient 0,
/// salt word 16 zero bytes || salt; R_BURN toUA, auditorOn, salt 0).
/// xcheck/dump_setup.c applies the same patch to pqz_bench.c's statements; pqz_kat.py parses and rebuilds them.
pub fn setup_with(tw: &Tweak) -> Setup {
    let mut rng = Rng::new();
    let mut kf = keygen(&mut rng);
    if let Some(s) = &tw.s_f {
        kf.s = s.clone();
        kf.pk = keypair(&polys(&kf.s), &polys(&kf.e));
    }
    let mut kt = keygen(&mut rng);
    if let Some(s) = &tw.s_t {
        kt.s = s.clone();
        kt.pk = keypair(&polys(&kt.s), &polys(&kt.e));
    }
    let ka = keygen(&mut rng);
    let _kx = keygen(&mut rng);

    let psid = tw.psid.unwrap_or(PQZH_ID);
    let mut reg_stmt = Form::Register.op_tag().to_vec();
    reg_stmt.extend_from_slice(&psid);
    reg_stmt.extend((0..32u8).collect::<Vec<_>>());
    wr_vec(&mut reg_stmt, &kf.pk);
    let mut reg_wit: Vec<u8> = kf.s.iter().map(|&x| x as i8 as u8).collect();
    le16(&mut reg_wit, &kf.e);
    assert_eq!((reg_stmt.len(), reg_wit.len()), (Form::Register.stmt_len(), Form::Register.wit_len()));

    let (bal, v, fee) = (1_000_000u64, 123_456u64, 7u64);
    let bp = bal - v - fee;
    let r0 = rng.short(2048, 1, 36);
    let e10 = rng.short(2048, 20, 164);
    let e20 = rng.short(16, 20, 64);
    let (ut, vt) = encrypt(&[&kf.pk], &[digits(bal)], &polys(&r0), &polys(&e10), &[e20]);
    let r = rng.short(2048, 1, 36);
    let e1 = rng.short(2048, 20, 164);
    let r = tw.r.clone().unwrap_or(r);
    let e1 = tw.e1.clone().unwrap_or(e1);
    let mut e2: Vec<Vec<i64>> = (0..3).map(|_| rng.short(16, 20, 64)).collect();
    let mut m = [digits(v), digits(bp), digits(v)];
    if let Some(e) = &tw.e2_t {
        e2[0] = e.clone();
    }
    if let Some(d) = tw.d {
        m[0] = d;
        m[2] = d;
    }
    let (u, vs) = encrypt(&[&kt.pk, &kf.pk, &ka.pk], &m, &polys(&r), &polys(&e1), &e2);

    let mut tx: Vec<u8> = (0..HEADER_BYTES).map(|i| if i < PREFIX { 0x5A } else { (i * 3) as u8 }).collect();
    tx[..32].copy_from_slice(&Form::Transfer.op_tag());
    tx[32..64].copy_from_slice(&psid);
    tx[HDR_AUDITOR_ON..HDR_AUDITOR_ON + 32].fill(0);
    tx[HDR_AUDITOR_ON + 31] = 1;
    tx[HDR_FEE..HDR_FEE + 64].fill(0);
    tx[HDR_FEE + 24..HDR_FEE + 32].copy_from_slice(&fee.to_be_bytes());
    // the canonical header the decoder (pqz-stmt, plan D15) accepts, as pqz_bench.c writes it: recipient (word at
    // 320) 0 on a transfer, salt word (576) = 16 zero bytes || salt
    tx[320..352].fill(0);
    tx[576..592].fill(0);
    for x in [&kf.pk, &kt.pk, &ka.pk, &ut] {
        wr_vec(&mut tx, x);
    }
    wr_v(&mut tx, &vt[0]);
    wr_vec(&mut tx, &u);
    for vk in &vs {
        wr_v(&mut tx, vk);
    }

    let mut w: Vec<u8> = kf.s.iter().map(|&x| x as i8 as u8).collect();
    le16(&mut w, &kf.e);
    w.extend(r.iter().map(|&x| x as i8 as u8));
    le16(&mut w, &e1);
    for e in &e2 {
        le16(&mut w, e);
    }
    w.extend_from_slice(&m[0]);
    w.extend_from_slice(&m[1]);
    assert_eq!((tx.len(), w.len()), (Form::Transfer.stmt_len(), Form::Transfer.wit_len()));

    // R_DS / R_DR: header words chainId .. entryRef = (i * 7), amount v, kind 0 / 1; pk_t, u, v_t
    let disc = |k: u8| {
        let mut st = [Form::DiscloseSender, Form::DiscloseReceiver][k as usize].op_tag().to_vec();
        st.extend_from_slice(&psid);
        st.extend((PREFIX..DISC_AMOUNT).map(|i| (i * 7) as u8));
        st.extend([0u8; 64]);
        st[DISC_AMOUNT + 24..DISC_AMOUNT + 32].copy_from_slice(&v.to_be_bytes());
        st[DISC_KIND + 31] = k;
        wr_vec(&mut st, &kt.pk);
        wr_vec(&mut st, &u);
        wr_v(&mut st, &vs[0]);
        st
    };
    let (ds_stmt, dr_stmt) = (disc(0), disc(1));
    let mut ds_wit: Vec<u8> = r.iter().map(|&x| x as i8 as u8).collect();
    le16(&mut ds_wit, &e1);
    le16(&mut ds_wit, &e2[0]);
    let mut dr_wit: Vec<u8> = kt.s.iter().map(|&x| x as i8 as u8).collect();
    le16(&mut dr_wit, &kt.e);
    let disc_len = Form::DiscloseSender.stmt_len();
    assert_eq!(
        (ds_stmt.len(), dr_stmt.len(), ds_wit.len(), dr_wit.len()),
        (disc_len, disc_len, Form::DiscloseSender.wit_len(), Form::DiscloseReceiver.wit_len())
    );

    // R_BURN: fresh (r, e1, e2_f) for the new balance
    let rb = rng.short(2048, 1, 36);
    let e1b = rng.short(2048, 20, 164);
    let rb = tw.r.clone().unwrap_or(rb);
    let e1b = tw.e1.clone().unwrap_or(e1b);
    let mut e2b = rng.short(16, 20, 64);
    if let Some(e) = &tw.burn_e2 {
        e2b = e.clone();
    }
    let mb = tw.burn_dp.unwrap_or(digits(bp));
    let (ub, vb) = encrypt(&[&kf.pk], &[mb], &polys(&rb), &polys(&e1b), &[e2b.clone()]);
    let mut burn: Vec<u8> = (0..HEADER_BYTES).map(|i| if i < PREFIX { 0xB2 } else { (i * 5) as u8 }).collect();
    burn[..32].copy_from_slice(&Form::Burn.op_tag());
    burn[32..64].copy_from_slice(&psid);
    burn[HDR_FEE..HDR_FEE + 64].fill(0);
    burn[HDR_FEE + 24..HDR_FEE + 32].copy_from_slice(&fee.to_be_bytes());
    burn[HDR_AMOUNT + 24..HDR_AMOUNT + 32].copy_from_slice(&v.to_be_bytes());
    // canonical (D15, as pqz_bench.c): toUA (192), auditorOn and the whole salt word (576) 0 on a burn
    burn[192..224].fill(0);
    burn[HDR_AUDITOR_ON..HDR_AUDITOR_ON + 32].fill(0);
    burn[576..608].fill(0);
    wr_vec(&mut burn, &kf.pk);
    wr_vec(&mut burn, &ut);
    wr_v(&mut burn, &vt[0]);
    wr_vec(&mut burn, &ub);
    wr_v(&mut burn, &vb[0]);
    let mut bw = w[..2048 + 4096].to_vec();
    bw.extend(rb.iter().map(|&x| x as i8 as u8));
    le16(&mut bw, &e1b);
    le16(&mut bw, &e2b);
    bw.extend_from_slice(&mb);
    assert_eq!((burn.len(), bw.len()), (Form::Burn.stmt_len(), Form::Burn.wit_len()));

    Setup { reg_stmt, reg_wit, tx_stmt: tx, tx_wit: w, burn_stmt: burn, burn_wit: bw, ds_stmt, ds_wit, dr_stmt, dr_wit }
}

// ---- adversarial inputs (bench native and wasm) ----

/// xorshift for mutations (independent of the setup stream)
pub struct R(pub u64);
impl R {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

pub const KINDS: [&str; 12] = [
    "bitflip", "byte_set", "random_bytes", "truncate", "extend", "stmt_coeff", "stmt_oob", "stmt_prefix",
    "stmt_tail", "other_proof", "field_noncanon", "empty",
];

/// mutated (statement, proof) of kind k
pub fn mutate(k: usize, f: Form, st: &[u8], pf: &[u8], other: &[u8], r: &mut R) -> (Vec<u8>, Vec<u8>) {
    let (mut s, mut p) = (st.to_vec(), pf.to_vec());
    // first coefficient byte; the public scalar the relation reads (low 8 bytes of its word)
    let (body, tail) = match f {
        Form::Register => (PREFIX + 32, PREFIX),
        Form::Transfer | Form::Transfer0 => (HEADER_BYTES, HDR_FEE + 24),
        Form::Burn | Form::Refresh => (HEADER_BYTES, HDR_AMOUNT + 24),
        _ => (DISC_PK, DISC_AMOUNT + 24),
    };
    let ncoef = (s.len() - body) / 8;
    match KINDS[k] {
        "bitflip" => {
            let b = (r.next() % (8 * p.len() as u64)) as usize;
            p[b / 8] ^= 1 << (b % 8);
        }
        "byte_set" => {
            let i = (r.next() % p.len() as u64) as usize;
            p[i] = p[i].wrapping_add(1 + (r.next() % 255) as u8);
        }
        "random_bytes" => p.iter_mut().for_each(|b| *b = r.next() as u8),
        "truncate" => p.truncate(p.len() - 1 - (r.next() % 64) as usize),
        "extend" => p.extend((0..1 + r.next() % 64).map(|_| r.next() as u8)),
        "stmt_coeff" => {
            // +1 mod q on one coefficient (stays canonical)
            let o = body + 8 * (r.next() as usize % ncoef);
            let v = u64::from_be_bytes(s[o..o + 8].try_into().unwrap());
            s[o..o + 8].copy_from_slice(&((v + 1) % Q).to_be_bytes());
        }
        "stmt_oob" => {
            let o = body + 8 * (r.next() as usize % ncoef);
            let v = u64::from_be_bytes(s[o..o + 8].try_into().unwrap());
            s[o..o + 8].copy_from_slice(&(v + Q).to_be_bytes());
        }
        "stmt_prefix" => s[(r.next() % PREFIX as u64) as usize] ^= 1 << (r.next() % 8),
        "stmt_tail" => {
            // R_REG: message byte; R_TX: fee; R_BURN, R_DS, R_DR: amount
            let n = if f == Form::Register { 32 } else { 8 };
            s[tail + (r.next() % n) as usize] ^= 1 << (r.next() % 8);
        }
        "other_proof" => p = other.to_vec(),
        "field_noncanon" => {
            // add a large constant to one big-endian word near the end (a field element of an opened column or a
            // multiproof digest)
            let i = p.len() - 8 * (1 + (r.next() % 16) as usize);
            let w = u64::from_be_bytes(p[i..i + 8].try_into().unwrap());
            p[i..i + 8].copy_from_slice(&w.wrapping_add(0xFFFF_FFFF_0000_0001).to_be_bytes());
        }
        _ => p.clear(),
    }
    (s, p)
}
