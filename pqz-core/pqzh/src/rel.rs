//! R_REG and R_TX as PQZH statements: the same statement and witness bytes as pqz-core (pqz.h, pqz_rel.c
//! build_reg / build_tx / tx_witness), proved with the AIRs of air.rs.

use p3_batch_stark::{BatchProof, ProverData, StarkInstance, prove_batch, verify_batch};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::air::{DigitAir, MvAir, MvOut, PolyAir, PolySpec, PqzhAir, RANGE_N, RangeAir, dc};
use crate::config::{Challenge5, Params, Plain5Config, PlainConfig, ZkConfig};
use crate::ring::*;

pub const OP_TRANSFER: u8 = 1;
pub const OP_REGISTER: u8 = 3;
pub const PREFIX: usize = 64;
/// Debit statements (pq-zether.md §7.7, pqz.h PQZ_HEADER_BYTES): 640-byte header of 32-byte words; the relation reads
/// only the fee word (offset 256, be32 < 2^64); opTag, proofSystemId and the other words are only hashed.
pub const HEADER: usize = 640;
pub const HDR_FEE: usize = 256;
pub const POLYVEC: usize = 16384;
pub const VB: usize = 128;
pub const REG_STMT: usize = PREFIX + 32 + POLYVEC;
pub const REG_WIT: usize = 2048 + 4096;
pub const TX_STMT: usize = HEADER + 3 * POLYVEC + (POLYVEC + VB) + (POLYVEC + 3 * VB);
pub const TX_WIT: usize = 2048 + 4096 + 2048 + 4096 + 3 * 32 + 16 + 16;
/// Proof limit of the PQZH kind (owner, TODO P6-PQZH): 160 KB.
pub const MAX_PROOF: usize = 160 * 1024;
/// proofSystemId (statement bytes 32..63) of PQZH, proposed in the style of pqz.h's PQZ_PROOF_SYSTEM_ID:
/// keccak256("scaas/pqz/pqzh/stark-d1-goldilocks5-fri-keccak256-zk/v1"). Like pqz-core, the relation only hashes it
/// (the precompile dispatches on it). Provisional until the FRI parameters (soundness regime) are fixed.
pub const PQZH_PROOF_SYSTEM_ID: [u8; 32] = hex32("aa1f92ddc5763201c2582c8387bd6513842e52779310d6bcf39a7fec99284304");
/// PQZL's id as pqz-core v2 writes it (pqz.h PQZ_PROOF_SYSTEM_ID = keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")),
/// used only for the byte cross-check against pqz_bench.c.
pub const PQZL_PROOF_SYSTEM_ID: [u8; 32] = hex32("2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f");

const fn nib(c: u8) -> u8 {
    if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
}

const fn hex32(h: &str) -> [u8; 32] {
    let b = h.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 64 {
        out[i / 2] = nib(b[i]) << 4 | nib(b[i + 1]);
        i += 2;
    }
    out
}

const BS: i64 = 36 * 36;
const BE: i64 = 164 * 164;

/// SHAKE256("SCAAS-PQZH-TRANSCRIPT-V1" || u8(op) || be32(len) || stmt): seeds the challenger before any commitment.
pub fn stmt_digest(op: u8, stmt: &[u8]) -> [u8; 32] {
    let mut h = sha3::Shake256::default();
    h.update(b"SCAAS-PQZH-TRANSCRIPT-V1");
    h.update(&[op]);
    h.update(&(stmt.len() as u32).to_be_bytes());
    h.update(stmt);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

fn rd_i8(b: &[u8], n: usize) -> Vec<Poly> {
    (0..n / D).map(|i| std::array::from_fn(|m| b[i * D + m] as i8 as i64)).collect()
}
fn rd_i16(b: &[u8], n: usize) -> Vec<Poly> {
    (0..n / D)
        .map(|i| std::array::from_fn(|m| i16::from_le_bytes([b[2 * (i * D + m)], b[2 * (i * D + m) + 1]]) as i64))
        .collect()
}

fn delta_arr(on: bool, v: i64) -> [F; D] {
    [if on { fi(v) } else { F::ZERO }; D]
}

fn sum_hat(a: &[&[F; D]], b: &[[F; D]]) -> [F; D] {
    let mut acc = [F::ZERO; D];
    for (x, y) in a.iter().zip(b) {
        for k in 0..D {
            acc[k] += x[k] * y[k];
        }
    }
    acc
}

fn ahat(i: usize, j: usize) -> &'static [F; D] {
    &a_hat()[i * K + j]
}

/// integer coefficients of an NTT-domain value known to be below p/2
fn lift(h: &[F; D]) -> Poly {
    intt(h).map(centre)
}

fn quot(y: &Poly) -> Option<Poly> {
    let mut t = [0i64; D];
    for m in 0..D {
        if y[m] % Q as i64 != 0 {
            return None;
        }
        t[m] = y[m] / Q as i64;
    }
    Some(t)
}

fn l2(v: &[Poly]) -> i64 {
    v.iter().flatten().map(|x| x * x).sum()
}

/// AIRs of one statement, and the traces when a witness is given.
pub struct Built {
    pub airs: Vec<PqzhAir>,
    pub traces: Option<Vec<RowMajorMatrix<F>>>,
}

fn finish(poly: PolyAir, mvs: Vec<MvAir>, digit: Option<(DigitAir, [[i64; dc::W]; 16])>, w: Option<Vec<Poly>>) -> Built {
    let traces = w.map(|w| {
        let what: Vec<[F; D]> = w.iter().map(ntt_i).collect();
        let mut rc = vec![0u32; RANGE_N];
        let mut t = vec![poly.trace(&w, &what, &mut rc)];
        t.extend(mvs.iter().map(|m| m.trace(&what)));
        if let Some((d, rows)) = &digit {
            t.push(d.trace(rows, &mut rc));
        }
        t.push(RangeAir::trace(&rc));
        t
    });
    let mut airs = vec![PqzhAir::Poly(poly)];
    airs.extend(mvs.into_iter().map(PqzhAir::Mv));
    if let Some((d, _)) = digit {
        airs.push(PqzhAir::Digit(d));
    }
    airs.push(PqzhAir::Range(RangeAir));
    Built { airs, traces }
}

fn spec(range: bool, group: Option<usize>) -> PolySpec {
    PolySpec { range, group, ntt: 0, coef16: false }
}

/// One MV AIR for all ring identities; the Poly AIR sends each NTT value once per read.
fn layout(mut specs: Vec<PolySpec>, bsq: Vec<i64>, lists: &[(Vec<usize>, Vec<MvOut>)], p: &Params) -> (PolyAir, MvAir) {
    let (mv, reads) = MvAir::new(lists, p.mv_width);
    for (q, n) in reads {
        specs[q].ntt += n;
    }
    (PolyAir::new(specs, bsq), mv)
}

/// R_REG: pk = A s + e, ||s|| <= 36, ||e|| <= 164. `check` = false skips the honest prover's own checks (tests).
pub fn build_reg(stmt: &[u8], wit: Option<&[u8]>, check: bool, p: &Params) -> Result<Built, &'static str> {
    if stmt.len() != REG_STMT || wit.is_some_and(|w| w.len() != REG_WIT) {
        return Err("length");
    }
    let pk = rd_polyvec(&stmt[PREFIX + 32..]).ok_or("non-canonical")?;
    let pkh: Vec<[F; D]> = pk.iter().map(ntt_i).collect();
    let mut specs = vec![spec(true, Some(0)); K];
    specs.extend(vec![spec(true, Some(1)); K]);
    specs.extend(vec![spec(true, None); K]);
    let outs: Vec<MvOut> = (0..K)
        .map(|i| MvOut {
            coef: (0..K)
                .map(|j| *ahat(i, j))
                .chain((0..K).map(|j| delta_arr(i == j, 1)))
                .chain((0..K).map(|j| delta_arr(i == j, -(Q as i64))))
                .collect(),
            target: pkh[i],
        })
        .collect();
    let (poly, mv) = layout(specs, vec![BS, BE], &[((0..3 * K).collect(), outs)], p);
    let w = match wit {
        None => None,
        Some(wit) => {
            let s = rd_i8(wit, 2048);
            let e = rd_i16(&wit[2048..], 2048);
            if check && (l2(&s) > BS || l2(&e) > BE) {
                return Err("witness norm");
            }
            let sh: Vec<[F; D]> = s.iter().map(ntt_i).collect();
            let mut w = s.clone();
            w.extend(e.iter().copied());
            for i in 0..K {
                let mut y = sum_hat(&(0..K).map(|j| ahat(i, j)).collect::<Vec<_>>(), &sh);
                let eh = ntt_i(&e[i]);
                for k in 0..D {
                    y[k] += eh[k] - pkh[i][k];
                }
                w.push(quot(&lift(&y)).ok_or("pk != A s + e")?);
            }
            Some(w)
        }
    };
    Ok(finish(poly, vec![mv], None, w))
}

struct TxSt {
    pkf: Vec<Poly>,
    pkt: Vec<Poly>,
    pka: Vec<Poly>,
    ut: Vec<Poly>,
    vt_: Poly,
    u: Vec<Poly>,
    v: [Poly; 3], // v_t, v_f, v_a
    fee: u64,
}

fn parse_tx(stmt: &[u8]) -> Option<TxSt> {
    // fee: a be32 word that must be < 2^64 (pqz_rel.c rd_word64)
    let fw = &stmt[HDR_FEE..HDR_FEE + 32];
    if fw[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let fee = u64::from_be_bytes(fw[24..].try_into().unwrap());
    let mut p = HEADER;
    let mut pv = || {
        let r = rd_polyvec(&stmt[p..]);
        p += POLYVEC;
        r
    };
    let (pkf, pkt, pka, ut) = (pv()?, pv()?, pv()?, pv()?);
    let vt_ = rd_poly(&stmt[p..], 16)?;
    p += VB;
    let u = rd_polyvec(&stmt[p..])?;
    p += POLYVEC;
    let v = [rd_poly(&stmt[p..], 16)?, rd_poly(&stmt[p + VB..], 16)?, rd_poly(&stmt[p + 2 * VB..], 16)?];
    Some(TxSt { pkf, pkt, pka, ut, vt_, u, v, fee })
}

/// Digit table height: 16 rows, or enough for the hiding PCS's masking budget (2 (queries + 2 * 2 points) rows).
pub fn digit_height(p: &Params) -> usize {
    if p.zk { (2 * (p.num_queries + 8)).next_power_of_two().max(16) } else { 16 }
}

/// R_TX rows 1-7 (pq-zether.md §7.4, pqz_rel.c build_tx).
pub fn build_tx(stmt: &[u8], wit: Option<&[u8]>, check: bool, p: &Params) -> Result<Built, &'static str> {
    if stmt.len() != TX_STMT || wit.is_some_and(|w| w.len() != TX_WIT) {
        return Err("length");
    }
    let t = parse_tx(stmt).ok_or("non-canonical")?;
    let hat = |v: &[Poly]| -> Vec<[F; D]> { v.iter().map(ntt_i).collect() };
    let (pkfh, pkth, pkah, uth, uh) = (hat(&t.pkf), hat(&t.pkt), hat(&t.pka), hat(&t.ut), hat(&t.u));
    // polys: s_f 0..32, e_f 32..64, t1 64..96, r 96..128, e1 128..160, t2 160..192, y_t, y_f, y_a, y_T 192..196
    let mut specs = vec![spec(true, Some(0)); K];
    specs.extend(vec![spec(true, Some(1)); K]);
    specs.extend(vec![spec(true, None); K]);
    specs.extend(vec![spec(true, Some(2)); K]);
    specs.extend(vec![spec(true, Some(3)); K]);
    specs.extend(vec![spec(true, None); K]);
    specs.extend(vec![PolySpec { range: false, group: None, ntt: 0, coef16: true }; 4]);
    let zero = [F::ZERO; D];
    let neg1 = [-F::ONE; D];
    // MV1: inputs s_f, e_f, t1, y_T
    let mut outs1: Vec<MvOut> = (0..K)
        .map(|i| MvOut {
            coef: (0..K)
                .map(|j| *ahat(i, j))
                .chain((0..K).map(|j| delta_arr(i == j, 1)))
                .chain((0..K).map(|j| delta_arr(i == j, -(Q as i64))))
                .chain([zero])
                .collect(),
            target: pkfh[i],
        })
        .collect();
    outs1.push(MvOut { coef: uth.iter().copied().chain(vec![zero; 2 * K]).chain([neg1]).collect(), target: zero });

    // MV2: inputs r, e1, t2, y_t, y_f, y_a
    let mut outs2: Vec<MvOut> = (0..K)
        .map(|i| MvOut {
            coef: (0..K)
                .map(|j| *ahat(j, i))
                .chain((0..K).map(|j| delta_arr(i == j, 1)))
                .chain((0..K).map(|j| delta_arr(i == j, -(Q as i64))))
                .chain([zero; 3])
                .collect(),
            target: uh[i],
        })
        .collect();
    for (x, pkx) in [&pkth, &pkfh, &pkah].into_iter().enumerate() {
        let mut coef: Vec<[F; D]> = pkx.iter().copied().chain(vec![zero; 2 * K]).chain([zero; 3]).collect();
        coef[3 * K + x] = neg1;
        outs2.push(MvOut { coef, target: zero });
    }
    let (poly, mv) = layout(
        specs,
        vec![BS, BE, BS, BE],
        &[((0..3 * K).chain([195]).collect(), outs1), ((3 * K..6 * K).chain([192, 193, 194]).collect(), outs2)],
        p,
    );
    let v4 = [t.v[0], t.v[1], t.v[2], t.vt_].map(|p| std::array::from_fn(|i| p[i]));
    let digit = DigitAir::new(digit_height(p), v4, t.fee, [192 * D, 193 * D, 194 * D, 195 * D]);

    let Some(wit) = wit else {
        return Ok(finish(poly, vec![mv], Some((digit, [[0; dc::W]; 16])), None));
    };
    let sf = rd_i8(wit, 2048);
    let ef = rd_i16(&wit[2048..], 2048);
    let r = rd_i8(&wit[6144..], 2048);
    let e1 = rd_i16(&wit[8192..], 2048);
    let e2: Vec<[i64; 16]> = (0..3)
        .map(|x| std::array::from_fn(|j| i16::from_le_bytes([wit[12288 + 32 * x + 2 * j], wit[12289 + 32 * x + 2 * j]]) as i64))
        .collect();
    let d: [i64; 16] = std::array::from_fn(|i| wit[12384 + i] as i64);
    let dp: [i64; 16] = std::array::from_fn(|i| wit[12400 + i] as i64);
    if check
        && (l2(&sf) > BS
            || l2(&ef) > BE
            || l2(&r) > BS
            || l2(&e1) > BE
            || e2.iter().any(|x| x.iter().map(|v| v * v).sum::<i64>() > 64 * 64))
    {
        return Err("witness norm");
    }
    let (sfh, efh, rh, e1h) = (hat(&sf), hat(&ef), hat(&r), hat(&e1));
    let prod = |a: &[[F; D]], b: &[[F; D]]| lift(&sum_hat(&a.iter().collect::<Vec<_>>(), b));
    let y = [prod(&pkth, &rh), prod(&pkfh, &rh), prod(&pkah, &rh), prod(&uth, &sfh)];
    let mut w: Vec<Poly> = sf.clone();
    w.extend(ef.iter().copied());
    for i in 0..K {
        let mut h = sum_hat(&(0..K).map(|j| ahat(i, j)).collect::<Vec<_>>(), &sfh);
        for k in 0..D {
            h[k] += efh[i][k] - pkfh[i][k];
        }
        w.push(quot(&lift(&h)).ok_or("pk_f != A s_f + e_f")?);
    }
    w.extend(r.iter().copied());
    w.extend(e1.iter().copied());
    for i in 0..K {
        let mut h = sum_hat(&(0..K).map(|j| ahat(j, i)).collect::<Vec<_>>(), &rh);
        for k in 0..D {
            h[k] += e1h[i][k] - uh[i][k];
        }
        w.push(quot(&lift(&h)).ok_or("u != A^T r + e1")?);
    }
    w.extend(y.iter().copied());

    // digit rows (pqz_rel.c tx_witness): M, e_T by rounding, carries, quotients
    let qi = Q as i64;
    let exact = |num: i64| if num % qi == 0 { Some(num / qi) } else { None };
    let mut rows = [[0i64; dc::W]; 16];
    let mut cprev = 0i64;
    for i in 0..16 {
        let wv = modq(t.vt_[i] - y[3][i]);
        let m = (if wv >= 0 { wv + DELTA / 2 } else { wv - DELTA / 2 }) / DELTA;
        let et = wv - DELTA * m;
        let s = m + cprev - dp[i] - d[i] - ((t.fee >> (4 * i)) & 15) as i64;
        if check && (s % 16 != 0 || d[i] > 15 || dp[i] > 15 || !(0..1 << 14).contains(&m) || !(-(1 << 24)..1 << 24).contains(&et)) {
            return Err("digits");
        }
        let c = s / 16;
        if check && !(-64..1984).contains(&c) {
            return Err("carry");
        }
        let row = &mut rows[i];
        for x in 0..4 {
            row[dc::YT + x] = y[x][i];
        }
        for x in 0..3 {
            row[dc::E2 + x] = e2[x][i];
        }
        row[dc::DD] = d[i];
        row[dc::DP] = dp[i];
        row[dc::MLO] = m.rem_euclid(RANGE_N as i64);
        row[dc::MHI] = m.div_euclid(RANGE_N as i64);
        row[dc::C] = c;
        row[dc::ETLO] = (et + (1 << 24)).rem_euclid(RANGE_N as i64);
        row[dc::ETHI] = (et + (1 << 24)).div_euclid(RANGE_N as i64);
        let taus = [
            exact(y[0][i] + e2[0][i] + DELTA * d[i] - t.v[0][i]),
            exact(y[1][i] + e2[1][i] + DELTA * dp[i] - t.v[1][i]),
            exact(y[2][i] + e2[2][i] + DELTA * d[i] - t.v[2][i]),
            exact(t.vt_[i] - y[3][i] - DELTA * m - et),
        ];
        for x in 0..4 {
            row[dc::TAU + x] = taus[x].ok_or("v != pk^T r + e2 + Delta d")?;
        }
        cprev = c;
    }
    if check && cprev != 0 {
        return Err("carry out");
    }
    Ok(finish(poly, vec![mv], Some((digit, rows)), Some(w)))
}

pub fn build(op: u8, stmt: &[u8], wit: Option<&[u8]>, check: bool, p: &Params) -> Result<Built, &'static str> {
    match op {
        OP_REGISTER => build_reg(stmt, wit, check, p),
        OP_TRANSFER => build_tx(stmt, wit, check, p),
        _ => Err("op"),
    }
}

/// log2 of each AIR's committed height (trace height, +1 under the hiding PCS)
pub fn degrees(b: &Built, zk: bool) -> Vec<usize> {
    b.airs
        .iter()
        .map(|a| {
            let h = match a {
                PqzhAir::Poly(x) => x.height,
                PqzhAir::Mv(x) => x.height,
                PqzhAir::Range(_) => RANGE_N,
                PqzhAir::Digit(x) => x.height,
            };
            h.trailing_zeros() as usize + zk as usize
        })
        .collect()
}

macro_rules! prove_with {
    ($cfg:expr, $b:expr) => {{
        let cfg = $cfg;
        let traces = $b.traces.as_ref().unwrap();
        let inst: Vec<StarkInstance<_, PqzhAir>> = $b
            .airs
            .iter()
            .zip(traces)
            .map(|(air, trace)| StarkInstance { air, trace, public_values: vec![] })
            .collect();
        let pd = ProverData::from_instances(&cfg, &inst).map_err(|_| "setup")?;
        let proof = prove_batch(&cfg, &inst, &pd).map_err(|_| "prove")?;
        postcard::to_allocvec(&proof).map_err(|_| "encode")?
    }};
}

macro_rules! verify_with {
    ($cfg:expr, $ty:ty, $b:expr, $proof:expr, $zk:expr) => {{
        let cfg = $cfg;
        let Ok((proof, rest)) = postcard::take_from_bytes::<BatchProof<$ty>>($proof) else { return false };
        let deg = degrees(&$b, $zk);
        if !rest.is_empty() || proof.degree_bits != deg {
            return false;
        }
        let Ok(pd) = ProverData::from_airs_and_degrees(&cfg, &$b.airs, &deg) else { return false };
        let pvs = vec![vec![]; $b.airs.len()];
        verify_batch(&cfg, &$b.airs, &proof, &pvs, &pd.common).is_ok()
    }};
}

/// Prove `op` on `stmt` with witness `wit` (pqz-core byte formats). `rnd32` seeds the hiding masks (ZK mode).
pub fn prove(op: u8, stmt: &[u8], wit: &[u8], rnd32: [u8; 32], p: &Params) -> Result<Vec<u8>, &'static str> {
    prove_inner(op, stmt, wit, rnd32, p, true)
}

/// Test hook: skips the honest prover's checks so out-of-range witnesses reach the proof system.
pub fn prove_unchecked(op: u8, stmt: &[u8], wit: &[u8], rnd32: [u8; 32], p: &Params) -> Result<Vec<u8>, &'static str> {
    prove_inner(op, stmt, wit, rnd32, p, false)
}

fn prove_inner(op: u8, stmt: &[u8], wit: &[u8], rnd32: [u8; 32], p: &Params, check: bool) -> Result<Vec<u8>, &'static str> {
    if p.zk && p.ext5 {
        return Err("zk with ext5 not built");
    }
    let b = build(op, stmt, Some(wit), check, p)?;
    let seed = stmt_digest(op, stmt);
    let proof = if p.zk {
        prove_with!(p.zk(&seed, rnd32), b)
    } else if p.ext5 {
        prove_with!(p.plain_ext::<Challenge5>(&seed), b)
    } else {
        prove_with!(p.plain(&seed), b)
    };
    Ok(proof) // a proof above MAX_PROOF is returned (for measurement); verify rejects it
}

/// Panics caught by `verify` (diagnostics: wasm32 has no unwinding, so there a panic would trap).
pub static VERIFY_PANICS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 1 = valid, 0 = anything else; panics inside the verifier count as invalid.
pub fn verify(op: u8, stmt: &[u8], proof: &[u8], p: &Params) -> bool {
    if proof.len() > p.max_proof {
        return false;
    }
    std::panic::catch_unwind(|| {
        let Ok(b) = build(op, stmt, None, false, p) else { return false };
        let seed = stmt_digest(op, stmt);
        if p.zk {
            verify_with!(p.zk(&seed, [0; 32]), ZkConfig, b, proof, true)
        } else if p.ext5 {
            verify_with!(p.plain_ext::<Challenge5>(&seed), Plain5Config, b, proof, false)
        } else {
            verify_with!(p.plain(&seed), PlainConfig, b, proof, false)
        }
    })
    .unwrap_or_else(|_| {
        VERIFY_PANICS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        false
    })
}

fn sz<T: serde::Serialize>(t: &T) -> usize {
    postcard::to_allocvec(t).map(|v| v.len()).unwrap_or(0)
}

/// Byte breakdown of a plain (non-hiding) proof: commitments, out-of-domain values, per-round input openings
/// (opened rows / Merkle multiproof), FRI layers, final polynomial.
pub fn breakdown(proof: &[u8]) -> Vec<(String, usize)> {
    let Ok(p) = postcard::from_bytes::<BatchProof<PlainConfig>>(proof) else { return vec![] };
    let f = &p.opening_proof;
    let mut out = vec![
        ("total".into(), proof.len()),
        ("commitments".into(), sz(&p.commitments)),
        ("ood_values".into(), sz(&p.opened_values)),
        ("lookup_terminals".into(), sz(&p.lookup_terminals)),
    ];
    for (i, o) in f.input_openings.iter().enumerate() {
        out.push((format!("round{i}_rows"), sz(&o.opened_values)));
        out.push((format!("round{i}_merkle"), sz(&o.opening_proof)));
    }
    out.push(("fri_commits".into(), sz(&f.commit_phase_commits)));
    for (i, s) in f.commit_phase_openings.iter().enumerate() {
        out.push((format!("fri{i}_siblings"), sz(&s.sibling_values)));
        out.push((format!("fri{i}_merkle"), sz(&s.opening_proof)));
    }
    out.push(("final_poly".into(), sz(&f.final_poly)));
    out
}
