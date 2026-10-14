//! Test and bench inputs: the same keys, ciphertexts, statements and witnesses as pqz-core's test/pqz_bench.c
//! setup() (same xorshift stream, same samplers, all five relations), so the bytes can be compared with pqz-core's
//! (xcheck/ligero.sh). Copied from the Plonky3 crate's `pqzh/src/client.rs` (P6e Task 6 prep) and extended to
//! R_BURN / R_DS / R_DR; the mutations of the benches and tests.

use crate::ring::*;
use crate::stmt::*;

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

pub fn polys(v: &[i64]) -> Vec<Poly> {
    v.chunks(D).map(|c| c.try_into().unwrap()).collect()
}

fn wr_vec(out: &mut Vec<u8>, v: &[Poly]) {
    for p in v {
        let mut b = [0u8; 512];
        wr_poly(&mut b, p, D);
        out.extend_from_slice(&b);
    }
}

fn wr_v(out: &mut Vec<u8>, p: &Poly) {
    let mut b = [0u8; VB];
    wr_poly(&mut b, p, 16);
    out.extend_from_slice(&b);
}

/// pk = A s + e mod q
pub fn keypair(s: &[Poly], e: &[Poly]) -> Vec<Poly> {
    let a = a_matrix();
    (0..K)
        .map(|i| {
            let row: Vec<&Poly> = (0..K).map(|j| &a[i * K + j]).collect();
            let y = dot_int(&row, &s.iter().collect::<Vec<_>>());
            std::array::from_fn(|m| modq(y[m] + e[i][m]))
        })
        .collect()
}

/// u = A^T r + e1; v_k[i] = (pk_k^T r)[i] + e2_k[i] + Delta m_k[i] (i < 16)
pub fn encrypt(pks: &[&Vec<Poly>], msgs: &[[u8; 16]], r: &[Poly], e1: &[Poly], e2: &[Vec<i64>]) -> (Vec<Poly>, Vec<Poly>) {
    let a = a_matrix();
    let rr: Vec<&Poly> = r.iter().collect();
    let u = (0..K)
        .map(|i| {
            let col: Vec<&Poly> = (0..K).map(|j| &a[j * K + i]).collect();
            let y = dot_int(&col, &rr);
            std::array::from_fn(|m| modq(y[m] + e1[i][m]))
        })
        .collect();
    let vs = pks
        .iter()
        .zip(msgs)
        .zip(e2)
        .map(|((pk, msg), e2)| {
            let y = dot_int(&pk.iter().collect::<Vec<_>>(), &rr);
            std::array::from_fn(|i| if i < 16 { modq(y[i] + e2[i] + DELTA * msg[i] as i64) } else { 0 })
        })
        .collect();
    (u, vs)
}

pub fn digits(x: u64) -> [u8; 16] {
    std::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
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
    /// (statement, witness) of op
    pub fn rel(&self, op: u8) -> (&Vec<u8>, &Vec<u8>) {
        match op {
            OP_REGISTER => (&self.reg_stmt, &self.reg_wit),
            OP_TRANSFER => (&self.tx_stmt, &self.tx_wit),
            OP_BURN => (&self.burn_stmt, &self.burn_wit),
            OP_DISCLOSE_SENDER => (&self.ds_stmt, &self.ds_wit),
            OP_DISCLOSE_RECEIVER => (&self.dr_stmt, &self.dr_wit),
            _ => panic!("op {op}"),
        }
    }
}

/// relation names as the benches print them
pub fn rel_name(op: u8) -> &'static str {
    match op {
        OP_REGISTER => "R_REG",
        OP_TRANSFER => "R_TX",
        OP_BURN => "R_BURN",
        OP_DISCLOSE_SENDER => "R_DS",
        OP_DISCLOSE_RECEIVER => "R_DR",
        _ => "?",
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
    /// proofSystemId written at statement bytes 32..63 (default PQZH's; xcheck passes PQZL's to match pqz_bench.c)
    pub psid: Option<[u8; 32]>,
}

/// pqz_bench.c setup(): R_REG for key F, R_TX = balance 1,000,000 in T, transfer 123,456 with fee 7; R_TX in the
/// §7.7 layout (640-byte header, fee word at 256, the other header words filled as pqz_bench.c does); R_DS / R_DR
/// disclose the transfer's receiver leg (u, v_t) of 123,456 to pk_t; R_BURN burns 123,456 with fee 7 from the same T.
pub fn setup() -> Setup {
    setup_with(&Tweak::default())
}

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

    let psid = tw.psid.unwrap_or(PQZH_PROOF_SYSTEM_ID);
    let mut reg_stmt = vec![0xA5u8; PREFIX];
    reg_stmt[32..64].copy_from_slice(&psid);
    reg_stmt.extend((0..32u8).collect::<Vec<_>>());
    wr_vec(&mut reg_stmt, &kf.pk);
    let mut reg_wit: Vec<u8> = kf.s.iter().map(|&x| x as i8 as u8).collect();
    le16(&mut reg_wit, &kf.e);
    assert_eq!((reg_stmt.len(), reg_wit.len()), (REG_STMT, REG_WIT));

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

    let mut tx: Vec<u8> = (0..HEADER).map(|i| if i < PREFIX { 0x5A } else { (i * 3) as u8 }).collect();
    tx[32..64].copy_from_slice(&psid);
    tx[HDR_FEE..HDR_FEE + 64].fill(0);
    tx[HDR_FEE + 24..HDR_FEE + 32].copy_from_slice(&fee.to_be_bytes());
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
    assert_eq!((tx.len(), w.len()), (TX_STMT, TX_WIT));

    // R_DS / R_DR: header words chainId .. entryRef = (i * 7), amount v, kind 0 / 1; pk_t, u, v_t
    let disc = |k: u8| {
        let mut st = vec![0xD4 + k; PREFIX];
        st[32..64].copy_from_slice(&psid);
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
    assert_eq!((ds_stmt.len(), dr_stmt.len(), ds_wit.len(), dr_wit.len()), (DISC_STMT, DISC_STMT, DS_WIT, DR_WIT));

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
    let mut burn: Vec<u8> = (0..HEADER).map(|i| if i < PREFIX { 0xB2 } else { (i * 5) as u8 }).collect();
    burn[32..64].copy_from_slice(&psid);
    burn[HDR_FEE..HDR_FEE + 64].fill(0);
    burn[HDR_FEE + 24..HDR_FEE + 32].copy_from_slice(&fee.to_be_bytes());
    burn[HDR_AMOUNT + 24..HDR_AMOUNT + 32].copy_from_slice(&v.to_be_bytes());
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
    assert_eq!((burn.len(), bw.len()), (BURN_STMT, BURN_WIT));

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
pub fn mutate(k: usize, op: u8, st: &[u8], pf: &[u8], other: &[u8], r: &mut R) -> (Vec<u8>, Vec<u8>) {
    let (mut s, mut p) = (st.to_vec(), pf.to_vec());
    // first coefficient byte; the public scalar the relation reads (low 8 bytes of its word)
    let (body, tail) = match op {
        OP_REGISTER => (PREFIX + 32, PREFIX),
        OP_TRANSFER => (HEADER, HDR_FEE + 24),
        OP_BURN => (HEADER, HDR_AMOUNT + 24),
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
            let n = if op == OP_REGISTER { 32 } else { 8 };
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
