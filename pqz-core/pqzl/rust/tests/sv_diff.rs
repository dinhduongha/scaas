//! The specialised verifier (`Ctx::verify_fast`, pqz_sv.c) against the generic one (`Ctx::verify`, the reference)
//! and against the C core's `pqz_verify_fast`, on the cases of `pqzl/test/pqz_sv_diff.c` (ported below: the same
//! xorshift stream, statements, witnesses, proofs and mutations), with the sample of `pqzl/sv/rel3.sh`
//! (`4 4 2 1 10 12 12 12 12 2`: 3,484 cases over the six forms + every built R_TXM shape); `PQZL_SV_DIFF` takes other
//! arguments (`n_reg n_tx muts seed fuzz n_burn n_ds n_dr n_tx0 n_txm`). Where C evaluates two `rnd ()` calls
//! unsequenced, the port follows clang's order (the C build's compiler): an assignment's right side first, operands
//! and arguments left to right. The case count does not depend on that order.
//!
//! Also: the cheating fixtures of Task 7 and the PQZL vectors (honest rows accepted, negative.json's rows rejected).
#![cfg(feature = "sv")]
mod common;

use pqzl::Ctx;

#[test]
fn cheating_rejected() {
    let mut ctx = Ctx::new();
    for (case, op, stmt, proof, honest) in common::cheating() {
        assert_eq!(ctx.verify_fast(op, &stmt, &proof), honest, "{case}");
    }
}

#[test]
fn vectors_verify_fast() {
    let mut ctx = Ctx::new();
    for r in common::pqzl_rows() {
        assert!(ctx.verify_fast(r.op, &r.stmt, &r.proof), "{}", r.name);
    }
    let mut n = 0;
    for (name, b) in common::negative_inputs() {
        if let Some((op, stmt, proof)) = common::split(&b) {
            assert!(!ctx.verify_fast(op, stmt, proof), "{name}");
            n += 1;
        }
    }
    eprintln!("vectors_verify_fast: 23 honest rows accepted, {n} negative rows rejected");
}

#[cfg(feature = "test-hooks")]
#[allow(clippy::needless_range_loop)] // the index loops follow pqz_sv_diff.c's
mod harness {
    use pqzl::{encrypt, keypair_from_secret, test_mutate, Ctx, MAX_PROOF, POLYVEC_BYTES as PV, PROOF_SYSTEM_ID, V_BYTES as VB};

    const Q: u64 = pqzl::Q;
    const PREFIX: usize = 64;
    const HEADER: usize = 640;
    const HDR_FEE: usize = 256;
    const HDR_AMOUNT: usize = 288;
    const HDR_SALT: usize = 576;
    const HDR_TO_UA: usize = 192;
    const HDR_RECIPIENT: usize = 320;
    const HDR_LEGS: usize = 320;
    const HDR_AUDITOR_ON: usize = 448;
    const DISC_AMOUNT: usize = PREFIX + 5 * 32;
    const DISC_KIND: usize = DISC_AMOUNT + 32;
    const DISC_PK: usize = DISC_KIND + 32;
    const DISC_STMT: usize = DISC_PK + 2 * PV + VB;
    const REG_STMT: usize = PREFIX + 32 + PV;
    const TX_STMT: usize = HEADER + 3 * PV + (PV + VB) + (PV + 3 * VB);
    const TX0_STMT: usize = HEADER + 2 * PV + (PV + VB) + (PV + 2 * VB);
    const BURN_STMT: usize = HEADER + PV + 2 * (PV + VB);

    const fn groups(m: usize) -> usize {
        m.div_ceil(4)
    }
    const fn txm_stmt(m: usize, a: usize) -> usize {
        HEADER + (1 + m + a) * PV + (PV + VB) + groups(m) * PV + (m + 1 + a * m) * VB
    }

    pub const KIND: [&str; 30] = [
        "honest", "reencode", "bitflip", "byte_set", "random_bytes", "truncate", "extend", "stmt_coeff", "stmt_oob",
        "stmt_prefix", "stmt_scalar", "other_proof", "bench_k4_unary", "m_swap_z1", "m_swap_z21", "m_swap_z3z4",
        "m_z1_pm1", "m_z1_large", "m_z4_bound", "m_z3_large", "m_h", "m_hint", "m_c", "m_tB", "m_tA1", "m_z21_pm1",
        "m_swap_h", "stmt_legs", "stmt_auditor", "fuzz",
    ];
    const NK: usize = KIND.len();
    /// first decoded-field kind = test_mutate kind 0
    const K_M0: usize = 13;
    /// the auditorOn word of R_TX / R_TX0 / R_TXM changed (P6e R6), must be rejected
    pub const K_AUD: usize = NK - 2;
    /// the M word of R_TXM changed (P6-ANON R4), must be rejected
    pub const K_LEGS: usize = NK - 3;

    /// R_TXM shapes (M, auditorOn, log2 M), relation 6 + t, as pqz_bench's TXB
    const TXD: &[(usize, usize, u8)] = &[
        (1, 1, 0),
        (2, 1, 1),
        (4, 1, 2),
        (8, 1, 3),
        (1, 0, 0),
        (2, 0, 1),
        (4, 0, 2),
        (8, 0, 3),
        #[cfg(feature = "oversize")]
        (16, 1, 4),
        #[cfg(feature = "oversize")]
        (16, 0, 4),
    ];
    pub const NREL: usize = 6 + TXD.len();

    /// relation names (R_TX0 is op 1 with the 66,560-byte statement: relations are named by index, not by op)
    pub fn name(rel: usize) -> String {
        match rel {
            0 => "R_REG".into(),
            1 => "R_TX".into(),
            2 => "R_BURN".into(),
            3 => "R_DS".into(),
            4 => "R_DR".into(),
            5 => "R_TX0".into(),
            _ => format!("R_TXM{}{}", TXD[rel - 6].0, if TXD[rel - 6].1 == 1 { "" } else { "_0" }),
        }
    }
    fn op(rel: usize) -> u8 {
        [3, 1, 2, 4, 5, 1].get(rel).copied().unwrap_or(7)
    }
    /// the relation code of test_mutate: the op, 0x81 (R_TX0) or 0x70 | auditorOn << 3 | log2 M
    fn mop(rel: usize) -> u8 {
        match rel {
            5 => 0x81,
            0..=4 => op(rel),
            _ => 0x70 | (TXD[rel - 6].1 as u8) << 3 | TXD[rel - 6].2,
        }
    }
    /// first coefficient byte of the polynomial part of each statement, and its length in coefficients
    fn poly0(rel: usize, stlen: usize) -> (usize, usize) {
        match rel {
            0 => (PREFIX + 32, pqzl::N),
            3 | 4 => (DISC_PK, (DISC_STMT - DISC_PK) / 8),
            _ => (HEADER, (stlen - HEADER) / 8),
        }
    }

    fn le16(p: &mut [u8], v: i16) {
        p[..2].copy_from_slice(&v.to_le_bytes());
    }
    fn digits(x: u64) -> [u8; 16] {
        core::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
    }
    fn be8(p: &mut [u8], v: u64) {
        p[..8].copy_from_slice(&v.to_be_bytes());
    }

    struct Key {
        s: [i8; pqzl::N],
        e: [i16; pqzl::N],
        pk: Box<[u8; PV]>,
    }

    /// one case: a kind, the statement (None: the honest one) and the proof
    pub struct Case {
        pub kind: usize,
        pub stmt: Option<Vec<u8>>,
        pub proof: Vec<u8>,
    }

    pub struct Gen {
        xs: u64,
        ctx: Ctx,
        prev: Vec<Option<Vec<u8>>>,
        pub prove_fails: usize,
    }

    impl Gen {
        fn rnd(&mut self) -> u64 {
            self.xs ^= self.xs >> 12;
            self.xs ^= self.xs << 25;
            self.xs ^= self.xs >> 27;
            self.xs.wrapping_mul(2_685_821_657_736_338_717)
        }
        fn cbd(&mut self, eta: u32) -> i32 {
            let r = self.rnd();
            let (mut a, mut b) = (0, 0);
            for i in 0..eta {
                a += ((r >> i) & 1) as i32;
                b += ((r >> (32 + i)) & 1) as i32;
            }
            a - b
        }
        fn short8<const N: usize>(&mut self, eta: u32, bound: i64) -> [i8; N] {
            loop {
                let x: [i8; N] = core::array::from_fn(|_| self.cbd(eta) as i8);
                if x.iter().map(|&v| v as i64 * v as i64).sum::<i64>() <= bound * bound {
                    return x;
                }
            }
        }
        fn short16<const N: usize>(&mut self, eta: u32, bound: i64) -> [i16; N] {
            loop {
                let x: [i16; N] = core::array::from_fn(|_| self.cbd(eta) as i16);
                if x.iter().map(|&v| v as i64 * v as i64).sum::<i64>() <= bound * bound {
                    return x;
                }
            }
        }
        fn keygen(&mut self) -> Key {
            let s = self.short8::<{ pqzl::N }>(1, pqzl::BETA_S as i64);
            let e = self.short16::<{ pqzl::N }>(20, pqzl::BETA_E as i64);
            let pk = keypair_from_secret(&s, &e).unwrap();
            Key { s, e, pk }
        }
        fn rnd_bytes(&mut self, p: &mut [u8]) {
            for x in p {
                *x = self.rnd() as u8;
            }
        }

        /// a fresh R_REG statement: new key, message, prefix byte
        fn make_reg(&mut self) -> (Vec<u8>, Vec<u8>) {
            let k = self.keygen();
            let mut st = vec![0u8; REG_STMT];
            let b = self.rnd() as u8;
            st[..PREFIX].fill(b);
            st[32..64].copy_from_slice(&PROOF_SYSTEM_ID);
            self.rnd_bytes(&mut st[PREFIX..PREFIX + 32]);
            st[PREFIX + 32..].copy_from_slice(&k.pk[..]);
            let mut w = vec![0u8; 3 * pqzl::N];
            for j in 0..pqzl::N {
                w[j] = k.s[j] as u8;
                le16(&mut w[pqzl::N + 2 * j..], k.e[j]);
            }
            (st, w)
        }

        /// a fresh R_TX statement (as pqz_bench.c setup): new keys, balance, amount, fee; or the R_TX0 statement of
        /// the same transfer without the auditor (no pk_a, v_a, e2_a; auditorOn 0)
        fn make_tx(&mut self, tx0: bool) -> (Vec<u8>, Vec<u8>) {
            let (kf, kt, ka) = (self.keygen(), self.keygen(), self.keygen());
            let bal = self.rnd() % (1 << 48);
            let fee = self.rnd() % 4096 % (bal + 1);
            let v = self.rnd() % (bal - fee + 1);
            let bp = bal - v - fee;
            let r0 = self.short8::<{ pqzl::N }>(1, pqzl::BETA_S as i64);
            let e10 = self.short16::<{ pqzl::N }>(20, pqzl::BETA_E as i64);
            let e20 = self.short16::<16>(20, 64);
            let t = encrypt(&[&*kf.pk], &[digits(bal)], &r0, &e10, &[e20]).unwrap();
            let r = self.short8::<{ pqzl::N }>(1, pqzl::BETA_S as i64);
            let e1 = self.short16::<{ pqzl::N }>(20, pqzl::BETA_E as i64);
            let e2: [[i16; 16]; 3] = core::array::from_fn(|_| self.short16::<16>(20, 64));
            let m = [digits(v), digits(bp), digits(v)];
            let o = encrypt(&[&*kt.pk, &*kf.pk, &*ka.pk], &m, &r, &e1, &e2).unwrap();

            // header (pq-zero-knowledge.md §7.7): random bytes, proofSystemId, fee word, amount word 0, auditorOn 1
            let mut st = vec![0u8; TX_STMT];
            self.rnd_bytes(&mut st[..HEADER]);
            st[32..64].copy_from_slice(&PROOF_SYSTEM_ID);
            st[HDR_FEE..HDR_FEE + 64].fill(0);
            be8(&mut st[HDR_FEE + 24..], fee);
            st[HDR_AUDITOR_ON..HDR_AUDITOR_ON + 32].fill(0);
            st[HDR_AUDITOR_ON + 31] = 1;
            st[HDR_SALT..HDR_SALT + 16].fill(0);
            st[HDR_RECIPIENT..HDR_RECIPIENT + 32].fill(0);
            let mut p = HEADER;
            for part in [&kf.pk[..], &kt.pk[..], &ka.pk[..], &t.u[..], &t.vs[0][..], &o.u[..], &o.vs[0][..], &o.vs[1][..], &o.vs[2][..]] {
                st[p..p + part.len()].copy_from_slice(part);
                p += part.len();
            }
            let mut w = vec![0u8; (6 * pqzl::N) + 96 + 32];
            for j in 0..pqzl::N {
                w[j] = kf.s[j] as u8;
                le16(&mut w[pqzl::N + 2 * j..], kf.e[j]);
                w[(3 * pqzl::N) + j] = r[j] as u8;
                le16(&mut w[(4 * pqzl::N) + 2 * j..], e1[j]);
            }
            for k in 0..3 {
                for j in 0..16 {
                    le16(&mut w[(6 * pqzl::N) + 32 * k + 2 * j..], e2[k][j]);
                }
            }
            w[(6 * pqzl::N) + 96..(6 * pqzl::N) + 112].copy_from_slice(&m[0]);
            w[(6 * pqzl::N) + 112..(6 * pqzl::N) + 128].copy_from_slice(&m[1]);
            if !tx0 {
                return (st, w);
            }
            let mut s0 = vec![0u8; TX0_STMT];
            s0[..HEADER].copy_from_slice(&st[..HEADER]);
            s0[HDR_AUDITOR_ON + 31] = 0;
            let mut p = HEADER;
            for part in [&kf.pk[..], &kt.pk[..], &t.u[..], &t.vs[0][..], &o.u[..], &o.vs[0][..], &o.vs[1][..]] {
                s0[p..p + part.len()].copy_from_slice(part);
                p += part.len();
            }
            let mut w0 = w[..(6 * pqzl::N) + 64].to_vec(); // s_f, e_f, r, e1, e2_t, e2_f
            w0.extend_from_slice(&w[(6 * pqzl::N) + 96..(6 * pqzl::N) + 128]); // d, d'
            (s0, w0)
        }

        /// a fresh R_BURN statement: new key, balance in T, amount, fee; fresh (r, e1, e2_f) for the new balance;
        /// random header bytes except the fee and amount words
        fn make_burn(&mut self) -> (Vec<u8>, Vec<u8>) {
            let kf = self.keygen();
            let bal = self.rnd() % (1 << 48);
            let fee = self.rnd() % 4096 % (bal + 1);
            let v = self.rnd() % (bal - fee + 1);
            let bp = bal - v - fee;
            let r0 = self.short8::<{ pqzl::N }>(1, pqzl::BETA_S as i64);
            let e10 = self.short16::<{ pqzl::N }>(20, pqzl::BETA_E as i64);
            let e20 = self.short16::<16>(20, 64);
            let t = encrypt(&[&*kf.pk], &[digits(bal)], &r0, &e10, &[e20]).unwrap();
            let r = self.short8::<{ pqzl::N }>(1, pqzl::BETA_S as i64);
            let e1 = self.short16::<{ pqzl::N }>(20, pqzl::BETA_E as i64);
            let e2 = self.short16::<16>(20, 64);
            let m = digits(bp);
            let o = encrypt(&[&*kf.pk], &[m], &r, &e1, &[e2]).unwrap();
            let mut st = vec![0u8; BURN_STMT];
            self.rnd_bytes(&mut st[..HEADER]);
            st[32..64].copy_from_slice(&PROOF_SYSTEM_ID);
            st[HDR_FEE..HDR_FEE + 64].fill(0);
            be8(&mut st[HDR_FEE + 24..], fee);
            be8(&mut st[HDR_AMOUNT + 24..], v);
            st[HDR_SALT..HDR_SALT + 32].fill(0); // burn salt 0, toUA 0, auditorOn 0 (P6e D15)
            st[HDR_TO_UA..HDR_TO_UA + 32].fill(0);
            st[HDR_AUDITOR_ON..HDR_AUDITOR_ON + 32].fill(0);
            let mut p = HEADER;
            for part in [&kf.pk[..], &t.u[..], &t.vs[0][..], &o.u[..], &o.vs[0][..]] {
                st[p..p + part.len()].copy_from_slice(part);
                p += part.len();
            }
            let mut w = vec![0u8; (6 * pqzl::N) + 32 + 16];
            for j in 0..pqzl::N {
                w[j] = kf.s[j] as u8;
                le16(&mut w[pqzl::N + 2 * j..], kf.e[j]);
                w[(3 * pqzl::N) + j] = r[j] as u8;
                le16(&mut w[(4 * pqzl::N) + 2 * j..], e1[j]);
            }
            for j in 0..16 {
                le16(&mut w[(6 * pqzl::N) + 2 * j..], e2[j]);
            }
            w[(6 * pqzl::N) + 32..].copy_from_slice(&m);
            (st, w)
        }

        /// fresh R_DS and R_DR statements (same transfer leg): new receiver key, amount, (r, e1, e2_t), random header
        fn make_disc(&mut self, recv: bool) -> (Vec<u8>, Vec<u8>) {
            let kt = self.keygen();
            let v = self.rnd();
            let v = v >> (self.rnd() % 64);
            let r = self.short8::<{ pqzl::N }>(1, pqzl::BETA_S as i64);
            let e1 = self.short16::<{ pqzl::N }>(20, pqzl::BETA_E as i64);
            let e2 = self.short16::<16>(20, 64);
            let o = encrypt(&[&*kt.pk], &[digits(v)], &r, &e1, &[e2]).unwrap();
            let mut sts = Vec::new();
            for k in 0..2 {
                let mut st = vec![0u8; DISC_STMT];
                self.rnd_bytes(&mut st[..DISC_PK]);
                st[32..64].copy_from_slice(&PROOF_SYSTEM_ID);
                st[DISC_AMOUNT..DISC_AMOUNT + 64].fill(0);
                be8(&mut st[DISC_AMOUNT + 24..], v);
                // kind word: SENDER_S 0, RECEIVER_X 1, AUDITOR 2
                st[DISC_KIND + 31] = if k == 1 { 1 + (self.rnd() % 2) as u8 } else { 0 };
                st[DISC_PK..DISC_PK + PV].copy_from_slice(&kt.pk[..]);
                st[DISC_PK + PV..DISC_PK + 2 * PV].copy_from_slice(&o.u[..]);
                st[DISC_PK + 2 * PV..].copy_from_slice(&o.vs[0]);
                sts.push(st);
            }
            let mut w = vec![0u8; (3 * pqzl::N) + if recv { 0 } else { 32 }];
            for j in 0..pqzl::N {
                if recv {
                    w[j] = kt.s[j] as u8;
                    le16(&mut w[pqzl::N + 2 * j..], kt.e[j]);
                } else {
                    w[j] = r[j] as u8;
                    le16(&mut w[pqzl::N + 2 * j..], e1[j]);
                }
            }
            if !recv {
                for j in 0..16 {
                    le16(&mut w[(3 * pqzl::N) + 2 * j..], e2[j]);
                }
            }
            (sts.swap_remove(recv as usize), w)
        }

        /// a fresh R_TXM statement of shape t (pqz.h layout): new keys; balance, fee (0 one time in four); each leg
        /// real with probability 1/2 (else a decoy, amount 0), the amounts summing to at most balance - fee; random
        /// (r_g, e1_g) per group, e2 per leg, v_f and auditor copy; random header bytes except fee, amount 0, M,
        /// auditorOn, the salt form
        fn make_txm(&mut self, t: usize) -> (Vec<u8>, Vec<u8>) {
            let (m, a, _) = TXD[t];
            let g = groups(m);
            let (kf, ka) = (self.keygen(), self.keygen());
            let kr: Vec<Key> = (0..m).map(|_| self.keygen()).collect();
            let bal = self.rnd() % (1 << 48);
            let fee = if self.rnd().is_multiple_of(4) { 0 } else { self.rnd() % 4096 % (bal + 1) };
            let mut left = bal - fee;
            let mut dg = Vec::new();
            for _ in 0..m {
                let aj = if self.rnd() & 1 == 1 { self.rnd() % (left / 2 + 1) } else { 0 };
                dg.push(digits(aj));
                left -= aj;
            }
            let dp = digits(left);
            let r0 = self.short8::<{ pqzl::N }>(1, pqzl::BETA_S as i64);
            let e10 = self.short16::<{ pqzl::N }>(20, pqzl::BETA_E as i64);
            let e20 = self.short16::<16>(20, 64);
            let tt = encrypt(&[&*kf.pk], &[digits(bal)], &r0, &e10, &[e20]).unwrap();
            let mut r = Vec::new();
            let mut e1 = Vec::new();
            for _ in 0..g {
                r.push(self.short8::<{ pqzl::N }>(1, pqzl::BETA_S as i64));
                e1.push(self.short16::<{ pqzl::N }>(20, pqzl::BETA_E as i64));
            }
            let (mut e2, mut e2a, mut u, mut v, mut va) = (Vec::new(), Vec::new(), vec![None; g], Vec::new(), Vec::new());
            for j in 0..m {
                e2.push(self.short16::<16>(20, 64));
                e2a.push(self.short16::<16>(20, 64));
                let o = encrypt(&[&*kr[j].pk], &[dg[j]], &r[j / 4], &e1[j / 4], &[e2[j]]).unwrap();
                u[j / 4] = Some(o.u);
                v.push(o.vs[0]);
                if a == 1 {
                    let o = encrypt(&[&*ka.pk], &[dg[j]], &r[j / 4], &e1[j / 4], &[e2a[j]]).unwrap();
                    va.push(o.vs[0]);
                }
            }
            let e2f = self.short16::<16>(20, 64);
            let of = encrypt(&[&*kf.pk], &[dp], &r[0], &e1[0], &[e2f]).unwrap();

            let mut st = vec![0u8; txm_stmt(m, a)];
            self.rnd_bytes(&mut st[..HEADER]);
            st[32..64].copy_from_slice(&PROOF_SYSTEM_ID);
            st[HDR_FEE..HDR_FEE + 64].fill(0);
            be8(&mut st[HDR_FEE + 24..], fee);
            st[HDR_LEGS..HDR_LEGS + 32].fill(0);
            st[HDR_LEGS + 31] = m as u8;
            st[HDR_AUDITOR_ON..HDR_AUDITOR_ON + 32].fill(0);
            st[HDR_AUDITOR_ON + 31] = a as u8;
            st[HDR_SALT..HDR_SALT + 16].fill(0);
            let mut parts: Vec<&[u8]> = vec![&kf.pk[..]];
            parts.extend(kr.iter().map(|k| &k.pk[..]));
            if a == 1 {
                parts.push(&ka.pk[..]);
            }
            parts.push(&tt.u[..]);
            parts.push(&tt.vs[0][..]);
            parts.extend(u.iter().map(|x| &x.as_ref().unwrap()[..]));
            parts.extend(v.iter().map(|x| &x[..]));
            parts.push(&of.vs[0][..]);
            parts.extend(va.iter().map(|x| &x[..]));
            let mut p = HEADER;
            for part in parts {
                st[p..p + part.len()].copy_from_slice(part);
                p += part.len();
            }
            assert_eq!(p, st.len());

            let mut w = Vec::new();
            let se = |s: &[i8; pqzl::N], e: &[i16; pqzl::N], w: &mut Vec<u8>| {
                w.extend(s.iter().map(|&x| x as u8));
                w.extend(e.iter().flat_map(|x| x.to_le_bytes()));
            };
            se(&kf.s, &kf.e, &mut w);
            for gi in 0..g {
                se(&r[gi], &e1[gi], &mut w);
            }
            let e16 = |e: &[i16; 16], w: &mut Vec<u8>| w.extend(e.iter().flat_map(|x| x.to_le_bytes()));
            for x in &e2 {
                e16(x, &mut w);
            }
            e16(&e2f, &mut w);
            if a == 1 {
                for x in &e2a {
                    e16(x, &mut w);
                }
            }
            for d in &dg {
                w.extend_from_slice(d);
            }
            w.extend_from_slice(&dp);
            (st, w)
        }

        /// one round of the mutation list on proof pf of statement st (pqz_sv_diff.c mutate_round)
        fn mutate_round(&mut self, rel: usize, st: &[u8], pf: &[u8], fuzz: usize, out: &mut Vec<Case>) {
            let op = op(rel);
            let len = pf.len();
            let mut check = |kind, stmt: Option<Vec<u8>>, proof: Vec<u8>| out.push(Case { kind, stmt, proof });
            // byte level
            let mut bad = pf.to_vec();
            let bit = (self.rnd() % (8 * len as u64)) as usize;
            bad[bit / 8] ^= 1 << (bit % 8);
            check(2, None, bad);
            let mut bad = pf.to_vec();
            let x = self.rnd() as u8; // clang: the right side first
            bad[(self.rnd() % len as u64) as usize] = x;
            check(3, None, bad);
            let mut bad = vec![0u8; len];
            self.rnd_bytes(&mut bad);
            check(4, None, bad);
            let n = if self.rnd() & 1 == 1 { len - 1 - (self.rnd() % 64) as usize } else { (self.rnd() % len as u64) as usize };
            check(5, None, pf[..n].to_vec());
            let mut bad = pf.to_vec();
            let n = 1 + self.rnd() % 16;
            for _ in 0..n {
                let b = if self.rnd() & 1 == 1 { 0 } else { self.rnd() as u8 };
                bad.push(b);
            }
            check(6, None, bad);
            // statement
            let (p0, ncoef) = poly0(rel, st.len());
            let mut st2 = st.to_vec();
            let off = p0 + 8 * (self.rnd() % ncoef as u64) as usize;
            let mut v = u64::from_be_bytes(st2[off..off + 8].try_into().unwrap());
            v = if v < Q { (v + 1 + self.rnd() % 7) % Q } else { v };
            st2[off..off + 8].copy_from_slice(&v.to_be_bytes());
            check(7, Some(st2), pf.to_vec());
            let mut st2 = st.to_vec();
            let v = Q + self.rnd() % 1000;
            st2[off..off + 8].copy_from_slice(&v.to_be_bytes());
            check(8, Some(st2), pf.to_vec());
            let mut st2 = st.to_vec();
            let x = (1 + self.rnd() % 255) as u8;
            st2[(self.rnd() % PREFIX as u64) as usize] ^= x;
            check(9, Some(st2), pf.to_vec());
            if op != 3 {
                // the public scalars, be32 words (1 in 4 times a high byte set: non-canonical): R_TX / R_TX0 / R_TXM
                // fee, R_BURN fee / amount, disclosure amount
                let mut st2 = st.to_vec();
                let w = match op {
                    1 | 7 => HDR_FEE,
                    2 => {
                        if self.rnd() & 1 == 1 {
                            HDR_FEE
                        } else {
                            HDR_AMOUNT
                        }
                    }
                    _ => DISC_AMOUNT,
                };
                let x = (1 + self.rnd() % 15) as u8;
                let i = if self.rnd().is_multiple_of(4) { self.rnd() % 24 } else { 30 + self.rnd() % 2 };
                st2[w + i as usize] ^= x;
                check(10, Some(st2), pf.to_vec());
            }
            if op == 7 {
                // the M word: another built M (the length then mismatches, or for (2, off) -> (1, on) with
                // auditorOn 1 the other relation), 3, or a random high byte set
                let mut st2 = st.to_vec();
                match self.rnd() % 4 {
                    0 => {
                        st2[HDR_LEGS + 31] = 1 << (self.rnd() % 4);
                        if st2[HDR_LEGS + 31] == st[HDR_LEGS + 31] {
                            st2[HDR_LEGS + 31] ^= 3;
                        }
                    }
                    1 => st2[HDR_LEGS + 31] = 3,
                    2 => {
                        st2[HDR_LEGS + 31] ^= 3;
                        st2[HDR_AUDITOR_ON + 31] ^= 1;
                    }
                    _ => {
                        let x = (1 + self.rnd() % 255) as u8;
                        st2[HDR_LEGS + (self.rnd() % 31) as usize] ^= x;
                    }
                }
                check(K_LEGS, Some(st2), pf.to_vec());
            }
            if op == 1 || op == 7 {
                // the auditorOn word: the other form's value, 2, or a random high byte set
                let mut st2 = st.to_vec();
                match self.rnd() % 3 {
                    0 => st2[HDR_AUDITOR_ON + 31] ^= 1,
                    1 => st2[HDR_AUDITOR_ON + 31] = 2,
                    _ => {
                        let x = (1 + self.rnd() % 255) as u8;
                        st2[HDR_AUDITOR_ON + (self.rnd() % 31) as usize] ^= x;
                    }
                }
                check(K_AUD, Some(st2), pf.to_vec());
            }
            if let Some(p) = &self.prev[rel] {
                check(11, None, p.clone());
            }
            let mut bad = pf.to_vec();
            bad[len / 2..].fill(0xff);
            check(12, None, bad);
            // decoded fields, re-encoded (C's output buffer: MAX_PROOF + 64 bytes)
            for k in 0..14 {
                let (r1, r2) = (self.rnd(), self.rnd());
                if let Some(b) = test_mutate(mop(rel), pf, k, r1, r2).unwrap() {
                    if b.len() <= MAX_PROOF + 64 {
                        check(K_M0 + k as usize, None, b);
                    }
                }
            }
            // fuzz: 1..8 random edits
            for _ in 0..fuzz {
                let mut bad = pf.to_vec();
                let ne = 1 + self.rnd() % 8;
                for _ in 0..ne {
                    let l = bad.len() as u64;
                    match self.rnd() % 5 {
                        0 => {
                            let bit = (self.rnd() % (8 * l)) as usize;
                            bad[bit / 8] ^= 1 << (bit % 8);
                        }
                        1 => {
                            let x = self.rnd() as u8;
                            bad[(self.rnd() % l) as usize] = x;
                        }
                        2 => {
                            // delete a byte
                            if l > 1 {
                                bad.remove((self.rnd() % l) as usize);
                            }
                        }
                        3 => {
                            // insert a byte
                            if (l as usize) < MAX_PROOF {
                                let i = (self.rnd() % l) as usize;
                                bad.insert(i, self.rnd() as u8);
                            }
                        }
                        _ => {
                            // copy a chunk inside the proof
                            let (a, b, c) = (self.rnd() % l, self.rnd() % l, 1 + self.rnd() % 64);
                            if a + c <= l && b + c <= l {
                                let (a, b, c) = (a as usize, b as usize, c as usize);
                                bad.copy_within(a..a + c, b);
                            }
                        }
                    }
                }
                check(NK - 1, None, bad);
            }
        }
    }

    /// the arguments of pqz_sv_diff: n_reg n_tx muts seed fuzz n_burn n_ds n_dr n_tx0 n_txm (rel3.sh's sample by
    /// default, `PQZL_SV_DIFF` to change it)
    pub fn args() -> [u64; 10] {
        let s = std::env::var("PQZL_SV_DIFF").unwrap_or("4 4 2 1 10 12 12 12 12 2".into());
        let v: Vec<u64> = s.split_whitespace().map(|x| x.parse().unwrap()).collect();
        v.try_into().expect("PQZL_SV_DIFF: 10 numbers")
    }

    /// pqz_sv_diff.c main's loop: per relation, per honest proof, the proof and its cases (`sink (rel, op, stmt,
    /// cases)`); returns the number of failed proves
    pub fn run(a: [u64; 10], mut sink: impl FnMut(usize, u8, &[u8], Vec<Case>)) -> usize {
        let [nreg, ntx, muts, seed, fuzz, nburn, nds, ndr, ntx0, ntxm] = a;
        let nps = [nreg, ntx, nburn, nds, ndr, ntx0];
        let mut g = Gen { xs: 0x243F_6A88_85A3_08D3 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), ctx: Ctx::new(), prev: vec![None; NREL], prove_fails: 0 };
        for rel in 0..NREL {
            let np = if rel < 6 { nps[rel] } else { ntxm };
            for _ in 0..np {
                let mut r32 = [0u8; 32];
                g.rnd_bytes(&mut r32);
                let (st, wit) = match rel {
                    0 => g.make_reg(),
                    1 | 5 => g.make_tx(rel == 5), // both transfer forms
                    2 => g.make_burn(),
                    3 | 4 => g.make_disc(rel == 4),
                    _ => g.make_txm(rel - 6),
                };
                let Ok(pf) = g.ctx.prove(op(rel), &st, &wit, &r32) else {
                    eprintln!("{{\"prove_failed\": \"{}\"}}", name(rel));
                    g.prove_fails += 1;
                    continue;
                };
                let mut cases = vec![Case { kind: 0, stmt: None, proof: pf.clone() }];
                let (r1, r2) = (g.rnd(), g.rnd());
                if let Some(b) = test_mutate(mop(rel), &pf, 99, r1, r2).unwrap() {
                    if b.len() <= MAX_PROOF + 64 {
                        cases.push(Case { kind: 1, stmt: None, proof: b });
                    }
                }
                for m in 0..muts {
                    g.mutate_round(rel, &st, &pf, if m == 0 { fuzz as usize } else { 0 }, &mut cases);
                }
                sink(rel, op(rel), &st, cases);
                g.prev[rel] = Some(pf);
            }
        }
        g.prove_fails
    }

    /// per (relation, kind): cases, accepts of the reference, mismatches; the auditor / legs cases accepted
    pub struct Tally {
        pub cases: Vec<[usize; NK]>,
        pub acc: Vec<[usize; NK]>,
        pub mism: Vec<[usize; NK]>,
        pub aud_accepted: usize,
    }

    impl Tally {
        pub fn new() -> Tally {
            Tally { cases: vec![[0; NK]; NREL], acc: vec![[0; NK]; NREL], mism: vec![[0; NK]; NREL], aud_accepted: 0 }
        }
        /// one case: the reference verdict a, the compared one b
        pub fn add(&mut self, rel: usize, kind: usize, a: bool, b: bool) {
            self.cases[rel][kind] += 1;
            self.acc[rel][kind] += a as usize;
            if kind == K_AUD || kind == K_LEGS {
                self.aud_accepted += (a | b) as usize;
            }
            if a != b {
                self.mism[rel][kind] += 1;
                eprintln!("{{\"mismatch\": \"{}\", \"rel\": \"{}\", \"reference\": {a}, \"fast\": {b}}}", KIND[kind], name(rel));
            }
        }
        /// prints the JSON lines; returns (cases of the six forms, all cases, mismatches)
        pub fn report(&self, label: &str) -> (usize, usize, usize) {
            let (mut six, mut tot, mut mism) = (0, 0, 0);
            for rel in 0..NREL {
                for k in 0..NK {
                    if self.cases[rel][k] > 0 {
                        eprintln!(
                            "{{\"rel\": \"{}\", \"kind\": \"{}\", \"cases\": {}, \"reference_accepts\": {}, \"mismatches\": {}}}",
                            name(rel),
                            KIND[k],
                            self.cases[rel][k],
                            self.acc[rel][k],
                            self.mism[rel][k]
                        );
                    }
                    tot += self.cases[rel][k];
                    six += if rel < 6 { self.cases[rel][k] } else { 0 };
                    mism += self.mism[rel][k];
                }
            }
            eprintln!("{label}: {six} cases over the six forms, {tot} in all, {mism} mismatches, {} auditor / legs accepts", self.aud_accepted);
            (six, tot, mism)
        }
    }
}

/// verify_fast = verify on every case (the generic verifier is the reference); verified on PQZL_SV_THREADS threads
/// (default 4), one `Ctx` each
#[cfg(feature = "test-hooks")]
#[test]
fn sv_eq_generic() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let a = harness::args();
    let nt: usize = std::env::var("PQZL_SV_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(4);
    let mut ctxs: Vec<Ctx> = (0..nt).map(|_| Ctx::new()).collect();
    let mut t = harness::Tally::new();
    let fails = harness::run(a, |rel, op, st, cases| {
        let next = AtomicUsize::new(0);
        let res: Vec<Vec<(usize, bool, bool)>> = std::thread::scope(|s| {
            let hs: Vec<_> = ctxs
                .iter_mut()
                .map(|ctx| {
                    let (next, cases) = (&next, &cases);
                    s.spawn(move || {
                        let mut out = Vec::new();
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            let Some(c) = cases.get(i) else { break out };
                            let stmt = c.stmt.as_deref().unwrap_or(st);
                            out.push((i, ctx.verify(op, stmt, &c.proof), ctx.verify_fast(op, stmt, &c.proof)));
                        }
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let mut res: Vec<_> = res.into_iter().flatten().collect();
        res.sort_by_key(|r| r.0);
        for (i, x, y) in res {
            t.add(rel, cases[i].kind, x, y);
        }
    });
    let (six, _, mism) = t.report("sv_eq_generic");
    if a == [4, 4, 2, 1, 10, 12, 12, 12, 12, 2] {
        assert_eq!(six, 3484, "the C run's case count of rel3.sh's sample");
    }
    assert_eq!((fails, mism, t.aud_accepted), (0, 0, 0));
}

/// Rust verify_fast = C pqz_verify_fast on every case
#[cfg(all(feature = "test-hooks", feature = "c-oracle"))]
#[test]
fn sv_eq_c_sv() {
    let a = harness::args();
    let mut ctx = Ctx::new();
    let mut t = harness::Tally::new();
    let fails = harness::run(a, |rel, op, st, cases| {
        for c in &cases {
            let stmt = c.stmt.as_deref().unwrap_or(st);
            let (x, y) = std::thread::scope(|s| {
                let h = s.spawn(|| pqzl::c_oracle::c_verify_fast(op, stmt, &c.proof));
                let y = ctx.verify_fast(op, stmt, &c.proof);
                (h.join().unwrap(), y)
            });
            t.add(rel, c.kind, x, y);
        }
    });
    let (six, _, mism) = t.report("sv_eq_c_sv");
    if a == [4, 4, 2, 1, 10, 12, 12, 12, 12, 2] {
        assert_eq!(six, 3484, "the C run's case count of rel3.sh's sample");
    }
    assert_eq!((fails, mism, t.aud_accepted), (0, 0, 0));
}
