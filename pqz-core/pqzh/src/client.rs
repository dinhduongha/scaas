//! Test and bench inputs: the same keys, ciphertexts, statements and witnesses as pqz-core's test/pqz_bench.c
//! setup() (same xorshift stream, same samplers), so the bytes can be compared with pqz-core's (xcheck/).

use crate::rel::{PREFIX, REG_STMT, REG_WIT, TX_STMT, TX_WIT};
use crate::ring::*;

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

/// pk = A s + e mod q
pub fn keypair(s: &[Poly], e: &[Poly]) -> Vec<Poly> {
    let a = a_matrix();
    (0..K).map(|i| {
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
}

fn le16(out: &mut Vec<u8>, v: &[i64]) {
    for &x in v {
        out.extend_from_slice(&(x as i16).to_le_bytes());
    }
}

/// Overrides for negative tests (an honest prover refuses these witnesses).
#[derive(Default, Clone)]
pub struct Tweak {
    pub s_f: Option<Vec<i64>>,
    pub d: Option<[u8; 16]>,
    pub e2_t: Option<Vec<i64>>,
}

/// pqz_bench.c setup(): R_REG for key F, R_TX = balance 1,000,000 in T, transfer 123,456 with fee 7.
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
    let kt = keygen(&mut rng);
    let ka = keygen(&mut rng);
    let _kx = keygen(&mut rng);

    let mut reg_stmt = vec![0xA5u8; PREFIX];
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

    let mut tx = vec![0x5Au8; PREFIX];
    wr_vec(&mut tx, &kf.pk);
    wr_vec(&mut tx, &kt.pk);
    wr_vec(&mut tx, &ka.pk);
    wr_vec(&mut tx, &ut);
    let mut vb = [0u8; 128];
    wr_poly(&mut vb, &vt[0], 16);
    tx.extend_from_slice(&vb);
    wr_vec(&mut tx, &u);
    for vk in &vs {
        wr_poly(&mut vb, vk, 16);
        tx.extend_from_slice(&vb);
    }
    tx.extend_from_slice(&fee.to_be_bytes());

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
    Setup { reg_stmt, reg_wit, tx_stmt: tx, tx_wit: w }
}
