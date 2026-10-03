//! Statements, Σ-protocol and proofs for `transfer` and `burn`, byte-exact per zether-design
//! §6 (statement), §7 (Σ), §8 (Bulletproofs), §9 (wire + payload). `fund` carries no proof
//! (public amount, §5). The verifier here mirrors the Solidity verifier for tests/vectors.

use ark_ff::{PrimeField, Zero};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::bulletproofs::{self as bp, msm, nz_challenge, Gens, RangeProof};
use crate::curve::{
    decode_point, decode_scalar, encode_point, encode_scalar, generator, keccak256, point_len, proof_system_id, Fr,
    ZCurve, G,
};
use crate::elgamal::Ciphertext;
use crate::keys::ZetherKey;
use crate::nonce::Nonces;
use crate::transcript::Transcript;
use crate::ZError;

pub const N_V: usize = 32;
pub const N_B: usize = 64;
pub const HEADER_LEN: usize = 384;

pub fn op_tag_transfer() -> [u8; 32] {
    keccak256(b"BAMBOO-ZETHER-OP-TRANSFER-V1")
}
pub fn op_tag_burn() -> [u8; 32] {
    keccak256(b"BAMBOO-ZETHER-OP-BURN-V1")
}

/// `bindingTag` + `envelopeBinding` (§6, §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// `ZTX_V1_DIRECT`, binding 0: the subject calls the token itself.
    Direct,
    /// `ZTX_V1_RELAYED` with `envelopeBinding` from [`crate::envelope::envelope_binding`].
    Relayed([u8; 32]),
}

/// The 384-byte statement header (§6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub chain_id: u64,
    pub token: [u8; 20],
    pub binding: Binding,
    pub send_counter: u64,
    pub acc_seq: u64,
    /// Inner fee in shielded units; must be 0 when `beneficiary` is 0.
    pub fee: u64,
    pub beneficiary: [u8; 32],
    /// Burn only (transfer: 0).
    pub amount: u64,
    /// Burn only (transfer: zero address).
    pub recipient: [u8; 20],
}

fn be32_u64(v: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[24..].copy_from_slice(&v.to_be_bytes());
    o
}

fn be32_addr(a: &[u8; 20]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[12..].copy_from_slice(a);
    o
}

fn u64_of(w: &[u8]) -> Result<u64, ZError> {
    if w[..24].iter().any(|&b| b != 0) {
        return Err(ZError::BadStatement("word does not fit uint64"));
    }
    Ok(u64::from_be_bytes(w[24..32].try_into().unwrap()))
}

fn addr_of(w: &[u8]) -> Result<[u8; 20], ZError> {
    if w[..12].iter().any(|&b| b != 0) {
        return Err(ZError::BadStatement("address word has dirty high bytes"));
    }
    Ok(w[12..32].try_into().unwrap())
}

impl Header {
    pub fn encode<C: ZCurve>(&self, op_tag: [u8; 32]) -> Vec<u8> {
        let (tag, binding) = match self.binding {
            Binding::Direct => (keccak256(b"ZTX_V1_DIRECT"), [0u8; 32]),
            Binding::Relayed(b) => (keccak256(b"ZTX_V1_RELAYED"), b),
        };
        let words: [[u8; 32]; 12] = [
            op_tag,
            proof_system_id::<C>(),
            be32_u64(self.chain_id),
            be32_addr(&self.token),
            tag,
            binding,
            be32_u64(self.send_counter),
            be32_u64(self.acc_seq),
            be32_u64(self.fee),
            self.beneficiary,
            be32_u64(self.amount),
            be32_addr(&self.recipient),
        ];
        words.concat()
    }

    pub fn decode<C: ZCurve>(b: &[u8], op_tag: [u8; 32]) -> Result<Self, ZError> {
        if b.len() < HEADER_LEN {
            return Err(ZError::BadStatement("short header"));
        }
        let w = |i: usize| &b[32 * i..32 * i + 32];
        if w(0) != op_tag {
            return Err(ZError::BadStatement("opTag"));
        }
        if w(1) != proof_system_id::<C>() {
            return Err(ZError::BadStatement("proofSystemId"));
        }
        let binding = if w(4) == keccak256(b"ZTX_V1_DIRECT") {
            if w(5) != [0u8; 32] {
                return Err(ZError::BadStatement("DIRECT with non-zero envelopeBinding"));
            }
            Binding::Direct
        } else if w(4) == keccak256(b"ZTX_V1_RELAYED") {
            Binding::Relayed(w(5).try_into().unwrap())
        } else {
            return Err(ZError::BadStatement("bindingTag"));
        };
        Ok(Self {
            chain_id: u64_of(w(2))?,
            token: addr_of(w(3))?,
            binding,
            send_counter: u64_of(w(6))?,
            acc_seq: u64_of(w(7))?,
            fee: u64_of(w(8))?,
            beneficiary: w(9).try_into().unwrap(),
            amount: u64_of(w(10))?,
            recipient: addr_of(w(11))?,
        })
    }

    fn check_fee(&self) -> Result<(), ZError> {
        if self.fee >= 1 << N_V {
            return Err(ZError::BadStatement("fee >= 2^n_v"));
        }
        if self.beneficiary == [0u8; 32] && self.fee != 0 {
            return Err(ZError::BadStatement("fee without beneficiary"));
        }
        Ok(())
    }
}

struct Reader<'a, C: ZCurve> {
    b: &'a [u8],
    at: usize,
    _c: std::marker::PhantomData<C>,
}

impl<'a, C: ZCurve> Reader<'a, C> {
    fn new(b: &'a [u8], at: usize) -> Self {
        Self { b, at, _c: Default::default() }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ZError> {
        let s = self.b.get(self.at..self.at + n).ok_or(ZError::BadProof("truncated"))?;
        self.at += n;
        Ok(s)
    }
    fn point(&mut self) -> Result<G<C>, ZError> {
        decode_point::<C>(self.take(point_len::<C>())?)
    }
    fn scalar(&mut self) -> Result<Fr<C>, ZError> {
        decode_scalar::<C>(self.take(32)?)
    }
    fn range_proof(&mut self, n: usize) -> Result<RangeProof<C>, ZError> {
        RangeProof::<C>::decode(n, self.take(RangeProof::<C>::wire_len(n))?)
    }
    fn done(&self) -> Result<(), ZError> {
        if self.at != self.b.len() {
            return Err(ZError::BadProof("trailing bytes"));
        }
        Ok(())
    }
}

fn cat<C: ZCurve>(pts: &[&G<C>]) -> Vec<u8> {
    pts.iter().flat_map(|p| encode_point::<C>(p)).collect()
}

fn cat_s<C: ZCurve>(ss: &[&Fr<C>]) -> Vec<u8> {
    ss.iter().flat_map(|s| encode_scalar::<C>(s)).collect()
}

fn is_zero_msm<C: ZCurve>(bases: &[G<C>], scalars: &[Fr<C>], what: &'static str) -> Result<(), ZError> {
    if msm(bases, scalars).is_zero() {
        Ok(())
    } else {
        Err(ZError::Verify(what))
    }
}

/// `keccak256("BAMBOO-ZETHER-AUTH-V1" ‖ keccak256(statement))` — what `authSig` signs (§11).
pub fn auth_digest(statement: &[u8]) -> [u8; 32] {
    let mut b = b"BAMBOO-ZETHER-AUTH-V1".to_vec();
    b.extend_from_slice(&keccak256(statement));
    keccak256(&b)
}

// ---------------------------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq)]
pub struct TransferStatement<C: ZCurve> {
    pub header: Header,
    pub y_f: G<C>,
    pub y_t: G<C>,
    /// Token auditor key, `O` when the auditor is off.
    pub y_a: G<C>,
    pub acc: Ciphertext<C>,
    pub c_out: G<C>,
    pub d_out: G<C>,
    pub c_deb: G<C>,
    pub c_aud: G<C>,
}

impl<C: ZCurve> TransferStatement<C> {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.header.encode::<C>(op_tag_transfer());
        b.extend(cat::<C>(&[
            &self.y_f, &self.y_t, &self.y_a, &self.acc.c, &self.acc.d, &self.c_out, &self.d_out, &self.c_deb,
            &self.c_aud,
        ]));
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, ZError> {
        if b.len() != HEADER_LEN + 9 * point_len::<C>() {
            return Err(ZError::BadStatement("transfer statement length"));
        }
        let header = Header::decode::<C>(b, op_tag_transfer())?;
        let mut r = Reader::<C>::new(b, HEADER_LEN);
        let st = Self {
            header,
            y_f: r.point()?,
            y_t: r.point()?,
            y_a: r.point()?,
            acc: Ciphertext { c: r.point()?, d: r.point()? },
            c_out: r.point()?,
            d_out: r.point()?,
            c_deb: r.point()?,
            c_aud: r.point()?,
        };
        Ok(st)
    }

    /// `be32(accSeq) ‖ be32(sendCounter) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud` (§9).
    pub fn payload(&self) -> Vec<u8> {
        let mut b = be32_u64(self.header.acc_seq).to_vec();
        b.extend(be32_u64(self.header.send_counter));
        b.extend(cat::<C>(&[&self.y_f, &self.y_t, &self.c_out, &self.d_out, &self.c_deb, &self.c_aud]));
        b
    }

    pub fn auditor_on(&self) -> bool {
        !self.y_a.is_zero()
    }

    /// Structural rules the token enforces before verify (§2, §6).
    pub fn validate(&self) -> Result<(), ZError> {
        let h = &self.header;
        h.check_fee()?;
        if h.amount != 0 || h.recipient != [0u8; 20] {
            return Err(ZError::BadStatement("transfer with amount/recipient"));
        }
        if self.y_f.is_zero() || self.y_t.is_zero() {
            return Err(ZError::BadStatement("Y = O"));
        }
        if self.y_f == self.y_t {
            return Err(ZError::BadStatement("Y_from == Y_to"));
        }
        if self.d_out.is_zero() {
            return Err(ZError::BadStatement("D_out = O"));
        }
        if !self.auditor_on() && !self.c_aud.is_zero() {
            return Err(ZError::BadStatement("auditor off but C_aud != O"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct TransferWitness<C: ZCurve> {
    pub x: Fr<C>,
    pub v: Fr<C>,
    pub s: Fr<C>,
    pub b: Fr<C>,
    pub b_prime: Fr<C>,
    pub gamma_v: Fr<C>,
    pub gamma_b: Fr<C>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TransferProof<C: ZCurve> {
    pub v_v: G<C>,
    pub v_b: G<C>,
    pub a_y: G<C>,
    pub a_d: G<C>,
    pub a_out: G<C>,
    pub a_deb: G<C>,
    pub a_bal: G<C>,
    pub a_aud: G<C>,
    pub a_vv: G<C>,
    pub a_vb: G<C>,
    pub z_x: Fr<C>,
    pub z_v: Fr<C>,
    pub z_s: Fr<C>,
    pub z_b: Fr<C>,
    pub z_gv: Fr<C>,
    pub z_gb: Fr<C>,
    pub bp_v: RangeProof<C>,
    pub bp_b: RangeProof<C>,
}

impl<C: ZCurve> TransferProof<C> {
    fn commit_bytes(&self) -> Vec<u8> {
        cat::<C>(&[
            &self.v_v, &self.v_b, &self.a_y, &self.a_d, &self.a_out, &self.a_deb, &self.a_bal, &self.a_aud, &self.a_vv,
            &self.a_vb,
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.commit_bytes();
        b.extend(cat_s::<C>(&[&self.z_x, &self.z_v, &self.z_s, &self.z_b, &self.z_gv, &self.z_gb]));
        b.extend(self.bp_v.encode());
        b.extend(self.bp_b.encode());
        b
    }

    pub fn wire_len() -> usize {
        40 * point_len::<C>() + 512
    }

    pub fn decode(b: &[u8]) -> Result<Self, ZError> {
        if b.len() != Self::wire_len() {
            return Err(ZError::BadProof("transfer proof length"));
        }
        let mut r = Reader::<C>::new(b, 0);
        let p = Self {
            v_v: r.point()?,
            v_b: r.point()?,
            a_y: r.point()?,
            a_d: r.point()?,
            a_out: r.point()?,
            a_deb: r.point()?,
            a_bal: r.point()?,
            a_aud: r.point()?,
            a_vv: r.point()?,
            a_vb: r.point()?,
            z_x: r.scalar()?,
            z_v: r.scalar()?,
            z_s: r.scalar()?,
            z_b: r.scalar()?,
            z_gv: r.scalar()?,
            z_gb: r.scalar()?,
            bp_v: r.range_proof(N_V)?,
            bp_b: r.range_proof(N_B)?,
        };
        r.done()?;
        Ok(p)
    }
}

fn witness_bytes<C: ZCurve>(ss: &[&Fr<C>], statement: &[u8]) -> Vec<u8> {
    let mut b = cat_s::<C>(ss);
    b.extend_from_slice(statement);
    b
}

/// Σ + both Bulletproofs for a given statement and witness. No consistency checks: the
/// public API [`prove_transfer`] checks first; tests call this directly to show that an
/// inconsistent witness yields a proof the verifier rejects.
#[doc(hidden)]
pub fn prove_transfer_core<C: ZCurve, R: RngCore + CryptoRng>(
    gens: &Gens<C>,
    st: &TransferStatement<C>,
    w: &TransferWitness<C>,
    rng: &mut R,
) -> Result<TransferProof<C>, ZError> {
    let g = gens.g;
    let hb = gens.h;
    let stmt = st.encode();
    let mut n = Nonces::new(
        &witness_bytes::<C>(&[&w.x, &w.v, &w.s, &w.b_prime, &w.gamma_v, &w.gamma_b], &stmt),
        rng,
    );
    let (k_x, k_v, k_s, k_b, k_gv, k_gb) =
        (n.next::<C>(), n.next::<C>(), n.next::<C>(), n.next::<C>(), n.next::<C>(), n.next::<C>());
    let v_v = g * w.v + hb * w.gamma_v;
    let v_b = g * w.b_prime + hb * w.gamma_b;
    let a_y = g * k_x;
    let a_d = g * k_s;
    let a_out = g * k_v + st.y_t * k_s;
    let a_deb = g * k_v + st.y_f * k_s;
    let a_bal = g * k_b + (st.acc.d - st.d_out) * k_x;
    let a_aud = if st.auditor_on() { g * k_v + st.y_a * k_s } else { G::<C>::zero() };
    let a_vv = g * k_v + hb * k_gv;
    let a_vb = g * k_b + hb * k_gb;

    let mut tr = Transcript::new();
    tr.absorb("statement", &stmt);
    tr.absorb("sigma.commit", &cat::<C>(&[&v_v, &v_b, &a_y, &a_d, &a_out, &a_deb, &a_bal, &a_aud, &a_vv, &a_vb]));
    let c = nz_challenge::<C>(&mut tr, "sigma.c")?;
    let bp_v = bp::prove_unchecked(&mut tr, gens, N_V, &w.v, &w.gamma_v, &mut n)?;
    let bp_b = bp::prove_unchecked(&mut tr, gens, N_B, &w.b_prime, &w.gamma_b, &mut n)?;
    Ok(TransferProof {
        v_v,
        v_b,
        a_y,
        a_d,
        a_out,
        a_deb,
        a_bal,
        a_aud,
        a_vv,
        a_vb,
        z_x: k_x + c * w.x,
        z_v: k_v + c * w.v,
        z_s: k_s + c * w.s,
        z_b: k_b + c * w.b_prime,
        z_gv: k_gv + c * w.gamma_v,
        z_gb: k_gb + c * w.gamma_b,
        bp_v,
        bp_b,
    })
}

/// Native mirror of the on-chain transfer verifier (E1–E8 + BP(32, V_v) + BP(64, V_b)).
/// Returns the transcript on success (the byte vectors are cut from it).
pub fn verify_transfer<C: ZCurve>(
    gens: &Gens<C>,
    st: &TransferStatement<C>,
    p: &TransferProof<C>,
) -> Result<Transcript, ZError> {
    st.validate()?;
    if !st.auditor_on() && !p.a_aud.is_zero() {
        return Err(ZError::Verify("auditor off but A_aud != O"));
    }
    let (g, hb) = (gens.g, gens.h);
    let mut tr = Transcript::new();
    tr.absorb("statement", &st.encode());
    tr.absorb("sigma.commit", &p.commit_bytes());
    let c = nz_challenge::<C>(&mut tr, "sigma.c")?;
    let one = Fr::<C>::from(1u64);
    let fee = Fr::<C>::from(st.header.fee);
    is_zero_msm::<C>(&[g, st.y_f, p.a_y], &[p.z_x, -c, -one], "E1")?;
    is_zero_msm::<C>(&[g, st.d_out, p.a_d], &[p.z_s, -c, -one], "E2")?;
    is_zero_msm::<C>(&[g, st.y_t, st.c_out, p.a_out], &[p.z_v, p.z_s, -c, -one], "E3")?;
    is_zero_msm::<C>(&[g, st.y_f, st.c_deb, p.a_deb], &[p.z_v, p.z_s, -c, -one], "E4")?;
    is_zero_msm::<C>(
        &[g, st.acc.d, st.d_out, st.acc.c, st.c_deb, p.a_bal],
        &[p.z_b + c * fee, p.z_x, -p.z_x, -c, c, -one],
        "E5",
    )?;
    if st.auditor_on() {
        is_zero_msm::<C>(&[g, st.y_a, st.c_aud, p.a_aud], &[p.z_v, p.z_s, -c, -one], "E6")?;
    }
    is_zero_msm::<C>(&[g, hb, p.v_v, p.a_vv], &[p.z_v, p.z_gv, -c, -one], "E7")?;
    is_zero_msm::<C>(&[g, hb, p.v_b, p.a_vb], &[p.z_b, p.z_gb, -c, -one], "E8")?;
    bp::verify(&mut tr, gens, N_V, &p.v_v, &p.bp_v)?;
    bp::verify(&mut tr, gens, N_B, &p.v_b, &p.bp_b)?;
    Ok(tr)
}

/// Transfer randomness `s` as a PRF of the conf key (zether-design §5 "PRF `s` phía client"):
/// the sender can re-derive `s` for a `SENDER_S` disclosure, re-proving the same transfer gives
/// the same ciphertexts, and two different transfers never share `s` (which would leak `v1 - v2`).
pub fn derive_s<C: ZCurve>(x: &Fr<C>, h: &Header, y_to: &G<C>, v: u64) -> Fr<C> {
    let mut d = Sha512::new();
    d.update(b"BAMBOO-ZETHER-S-V1");
    d.update(encode_scalar::<C>(x));
    d.update(h.chain_id.to_be_bytes());
    d.update(h.token);
    d.update(h.send_counter.to_be_bytes());
    d.update(encode_point::<C>(y_to));
    d.update(v.to_be_bytes());
    Fr::<C>::from_be_bytes_mod_order(&d.finalize())
}

/// Build the statement from the sender's state and prove it.
///
/// `acc` is the sender's on-chain `acc` slot and `balance` its plaintext (from BSGS); the
/// prover refuses when they disagree, when `balance < v + fee`, when `v >= 2^32`, or when the
/// header breaks the token's structural rules.
#[allow(clippy::too_many_arguments)]
pub fn prove_transfer<C: ZCurve, R: RngCore + CryptoRng>(
    gens: &Gens<C>,
    key: &ZetherKey<C>,
    header: Header,
    y_to: G<C>,
    y_aud: G<C>,
    acc: Ciphertext<C>,
    balance: u64,
    v: u64,
    rng: &mut R,
) -> Result<(TransferStatement<C>, TransferProof<C>, TransferWitness<C>), ZError> {
    let g = generator::<C>();
    if v >= 1 << N_V {
        return Err(ZError::OutOfRange);
    }
    if acc.c - acc.d * key.x != g * Fr::<C>::from(balance) {
        return Err(ZError::BadStatement("balance does not decrypt from acc"));
    }
    let b_prime = (balance as u128)
        .checked_sub(v as u128 + header.fee as u128)
        .ok_or(ZError::BadStatement("insufficient balance"))? as u64;
    let s = derive_s::<C>(&key.x, &header, &y_to, v);
    let (vf, sf) = (Fr::<C>::from(v), s);
    let st = TransferStatement {
        y_f: key.y,
        y_t: y_to,
        y_a: y_aud,
        acc,
        c_out: g * vf + y_to * sf,
        d_out: g * sf,
        c_deb: g * vf + key.y * sf,
        c_aud: if y_aud.is_zero() { G::<C>::zero() } else { g * vf + y_aud * sf },
        header,
    };
    st.validate()?;
    let mut n = Nonces::new(&witness_bytes::<C>(&[&key.x], &st.encode()), rng);
    let w = TransferWitness {
        x: key.x,
        v: vf,
        s,
        b: Fr::<C>::from(balance),
        b_prime: Fr::<C>::from(b_prime),
        gamma_v: n.next::<C>(),
        gamma_b: n.next::<C>(),
    };
    let p = prove_transfer_core(gens, &st, &w, rng)?;
    Ok((st, p, w))
}

// ---------------------------------------------------------------------------------------------
// Burn
// ---------------------------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq)]
pub struct BurnStatement<C: ZCurve> {
    pub header: Header,
    pub y_f: G<C>,
    pub acc: Ciphertext<C>,
}

impl<C: ZCurve> BurnStatement<C> {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.header.encode::<C>(op_tag_burn());
        b.extend(cat::<C>(&[&self.y_f, &self.acc.c, &self.acc.d]));
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, ZError> {
        if b.len() != HEADER_LEN + 3 * point_len::<C>() {
            return Err(ZError::BadStatement("burn statement length"));
        }
        let header = Header::decode::<C>(b, op_tag_burn())?;
        let mut r = Reader::<C>::new(b, HEADER_LEN);
        Ok(Self { header, y_f: r.point()?, acc: Ciphertext { c: r.point()?, d: r.point()? } })
    }

    /// `be32(accSeq) ‖ be32(sendCounter) ‖ Y_f` (§9).
    pub fn payload(&self) -> Vec<u8> {
        let mut b = be32_u64(self.header.acc_seq).to_vec();
        b.extend(be32_u64(self.header.send_counter));
        b.extend(encode_point::<C>(&self.y_f));
        b
    }

    pub fn validate(&self) -> Result<(), ZError> {
        self.header.check_fee()?;
        if self.y_f.is_zero() {
            return Err(ZError::BadStatement("Y = O"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct BurnWitness<C: ZCurve> {
    pub x: Fr<C>,
    pub b: Fr<C>,
    pub b_prime: Fr<C>,
    pub gamma_b: Fr<C>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BurnProof<C: ZCurve> {
    pub v_b: G<C>,
    pub a_y: G<C>,
    pub a_bal: G<C>,
    pub a_vb: G<C>,
    pub z_x: Fr<C>,
    pub z_b: Fr<C>,
    pub z_gb: Fr<C>,
    pub bp_b: RangeProof<C>,
}

impl<C: ZCurve> BurnProof<C> {
    fn commit_bytes(&self) -> Vec<u8> {
        cat::<C>(&[&self.v_b, &self.a_y, &self.a_bal, &self.a_vb])
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.commit_bytes();
        b.extend(cat_s::<C>(&[&self.z_x, &self.z_b, &self.z_gb]));
        b.extend(self.bp_b.encode());
        b
    }

    pub fn wire_len() -> usize {
        20 * point_len::<C>() + 256
    }

    pub fn decode(b: &[u8]) -> Result<Self, ZError> {
        if b.len() != Self::wire_len() {
            return Err(ZError::BadProof("burn proof length"));
        }
        let mut r = Reader::<C>::new(b, 0);
        let p = Self {
            v_b: r.point()?,
            a_y: r.point()?,
            a_bal: r.point()?,
            a_vb: r.point()?,
            z_x: r.scalar()?,
            z_b: r.scalar()?,
            z_gb: r.scalar()?,
            bp_b: r.range_proof(N_B)?,
        };
        r.done()?;
        Ok(p)
    }
}

#[doc(hidden)]
pub fn prove_burn_core<C: ZCurve, R: RngCore + CryptoRng>(
    gens: &Gens<C>,
    st: &BurnStatement<C>,
    w: &BurnWitness<C>,
    rng: &mut R,
) -> Result<BurnProof<C>, ZError> {
    let (g, hb) = (gens.g, gens.h);
    let stmt = st.encode();
    let mut n = Nonces::new(&witness_bytes::<C>(&[&w.x, &w.b_prime, &w.gamma_b], &stmt), rng);
    let (k_x, k_b, k_gb) = (n.next::<C>(), n.next::<C>(), n.next::<C>());
    let v_b = g * w.b_prime + hb * w.gamma_b;
    let a_y = g * k_x;
    let a_bal = g * k_b + st.acc.d * k_x;
    let a_vb = g * k_b + hb * k_gb;
    let mut tr = Transcript::new();
    tr.absorb("statement", &stmt);
    tr.absorb("sigma.commit", &cat::<C>(&[&v_b, &a_y, &a_bal, &a_vb]));
    let c = nz_challenge::<C>(&mut tr, "sigma.c")?;
    let bp_b = bp::prove_unchecked(&mut tr, gens, N_B, &w.b_prime, &w.gamma_b, &mut n)?;
    Ok(BurnProof {
        v_b,
        a_y,
        a_bal,
        a_vb,
        z_x: k_x + c * w.x,
        z_b: k_b + c * w.b_prime,
        z_gb: k_gb + c * w.gamma_b,
        bp_b,
    })
}

/// Native mirror of the on-chain burn verifier (E1, E5, E8 + BP(64, V_b)).
pub fn verify_burn<C: ZCurve>(gens: &Gens<C>, st: &BurnStatement<C>, p: &BurnProof<C>) -> Result<Transcript, ZError> {
    st.validate()?;
    let (g, hb) = (gens.g, gens.h);
    let mut tr = Transcript::new();
    tr.absorb("statement", &st.encode());
    tr.absorb("sigma.commit", &p.commit_bytes());
    let c = nz_challenge::<C>(&mut tr, "sigma.c")?;
    let one = Fr::<C>::from(1u64);
    let out = Fr::<C>::from(st.header.amount) + Fr::<C>::from(st.header.fee);
    is_zero_msm::<C>(&[g, st.y_f, p.a_y], &[p.z_x, -c, -one], "E1")?;
    is_zero_msm::<C>(&[g, st.acc.d, st.acc.c, p.a_bal], &[p.z_b + c * out, p.z_x, -c, -one], "E5")?;
    is_zero_msm::<C>(&[g, hb, p.v_b, p.a_vb], &[p.z_b, p.z_gb, -c, -one], "E8")?;
    bp::verify(&mut tr, gens, N_B, &p.v_b, &p.bp_b)?;
    Ok(tr)
}

/// Build and prove a burn of `amount` (shielded units) to `header.recipient`.
pub fn prove_burn<C: ZCurve, R: RngCore + CryptoRng>(
    gens: &Gens<C>,
    key: &ZetherKey<C>,
    header: Header,
    acc: Ciphertext<C>,
    balance: u64,
    rng: &mut R,
) -> Result<(BurnStatement<C>, BurnProof<C>, BurnWitness<C>), ZError> {
    if acc.c - acc.d * key.x != generator::<C>() * Fr::<C>::from(balance) {
        return Err(ZError::BadStatement("balance does not decrypt from acc"));
    }
    let b_prime = (balance as u128)
        .checked_sub(header.amount as u128 + header.fee as u128)
        .ok_or(ZError::BadStatement("insufficient balance"))? as u64;
    let st = BurnStatement { header, y_f: key.y, acc };
    st.validate()?;
    let mut n = Nonces::new(&witness_bytes::<C>(&[&key.x], &st.encode()), rng);
    let w = BurnWitness { x: key.x, b: Fr::<C>::from(balance), b_prime: Fr::<C>::from(b_prime), gamma_b: n.next::<C>() };
    let p = prove_burn_core(gens, &st, &w, rng)?;
    Ok((st, p, w))
}
