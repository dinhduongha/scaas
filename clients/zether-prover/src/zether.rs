//! Statements, Σ-protocol and proofs for `transfer` and `burn`, byte-exact per zether-design
//! §6 (statement), §7 (Σ), §8 (Bulletproofs), §9 (wire + payload). `zetherShield` carries no proof
//! (public amount, §5). The verifier here mirrors the Solidity verifier for tests/vectors.

use ark_ff::{PrimeField, Zero};
use hkdf::Hkdf;
use zeroize::Zeroize;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::bulletproofs::{self as bp, msm, nz_challenge, Gens, RangeProof};
use crate::curve::{
    decode_point, decode_scalar, encode_point, encode_scalar, generator, keccak256, point_len, proof_system_id, ua_of,
    proof_system_id_multi, Fr, ZCurve, G,
};
use crate::elgamal::Ciphertext;
use crate::keys::ZetherKey;
use crate::nonce::Nonces;
use crate::transcript::Transcript;
use crate::ZError;

/// Range of a transferred value (limits D1). `n_v = n_b` relaxes SRS §7.3 `n_b − n_v ≥ 24`;
/// soundness comes from `MAX_TOTAL_SHIELDED` instead (zether-design ruling RS-NV64-1).
pub const N_V: usize = 64;
pub const N_B: usize = 64;
pub const HEADER_LEN: usize = 480;
/// `MAX_TOTAL_SHIELDED` (§1): ceiling of `maxDecryptableShielded`.
pub const MAX_TOTAL_SHIELDED: u64 = 1 << 54;

/// `v < 2^n_v` — the bound on a transfer value, the inner fee and a disclosed amount. With
/// `n_v = 64` every `u64` is in range; the check keeps the bound in one place.
pub fn value_in_range(v: u64) -> bool {
    (v as u128) < 1u128 << N_V
}

pub fn op_tag_transfer() -> [u8; 32] {
    keccak256(b"SCAAS-ZETHER-OP-TRANSFER-V1")
}
pub fn op_tag_burn() -> [u8; 32] {
    keccak256(b"SCAAS-ZETHER-OP-BURN-V1")
}

/// `bindingTag` + `envelopeBinding` (zether.md §7, §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// `ZTX_V1_DIRECT`, binding 0: the subject calls the token itself.
    Direct,
    /// `ZTX_V1_RELAYED` with `envelopeBinding` from [`crate::envelope::envelope_binding`].
    Relayed([u8; 32]),
    /// `ZTX_V1_DIRECT` with [`crate::envelope::unwrap_binding`]: a direct `zetherUnshieldUnwrap` binds its leg and
    /// `minOut` (controller ruling, pending the owner).
    Unwrap([u8; 32]),
}

/// The 480-byte statement header (zether.md §7): `chainUid` is word 3 (CTR-ZTH-36), the build salt word 13
/// (`16 zero bytes ‖ salt`, CTR-ZTH-30), `memoHash` word 14 (`keccak256(memo)` on commit-reveal, CTR-ZTH-50; else 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub chain_id: u64,
    /// The token's `chainUid()`: the chain's genesis hash (CTR-GEN-05).
    pub chain_uid: [u8; 32],
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
    /// Transfer only (burn: 0): 16 fresh random bytes per build, an input of [`derive_s`]; the prove functions draw it.
    pub salt: [u8; 16],
    /// Commit-reveal only (else 0): `keccak256` of the sender memo the payload ends with ([`seal_memo`]).
    pub memo_hash: [u8; 32],
}

fn salt_word(salt: &[u8; 16]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[16..].copy_from_slice(salt);
    o
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
        self.encode_with(op_tag, proof_system_id::<C>())
    }

    fn encode_with(&self, op_tag: [u8; 32], psid: [u8; 32]) -> Vec<u8> {
        let (tag, binding) = match self.binding {
            Binding::Direct => (keccak256(b"ZTX_V1_DIRECT"), [0u8; 32]),
            Binding::Relayed(b) => (keccak256(b"ZTX_V1_RELAYED"), b),
            Binding::Unwrap(b) => (keccak256(b"ZTX_V1_DIRECT"), b),
        };
        let words: [[u8; 32]; 15] = [
            op_tag,
            psid,
            be32_u64(self.chain_id),
            self.chain_uid,
            be32_addr(&self.token),
            tag,
            binding,
            be32_u64(self.send_counter),
            be32_u64(self.acc_seq),
            be32_u64(self.fee),
            self.beneficiary,
            be32_u64(self.amount),
            be32_addr(&self.recipient),
            salt_word(&self.salt),
            self.memo_hash,
        ];
        words.concat()
    }

    pub fn decode<C: ZCurve>(b: &[u8], op_tag: [u8; 32]) -> Result<Self, ZError> {
        Self::decode_with(b, op_tag, proof_system_id::<C>())
    }

    fn decode_with(b: &[u8], op_tag: [u8; 32], psid: [u8; 32]) -> Result<Self, ZError> {
        if b.len() < HEADER_LEN {
            return Err(ZError::BadStatement("short header"));
        }
        let w = |i: usize| &b[32 * i..32 * i + 32];
        if w(0) != op_tag {
            return Err(ZError::BadStatement("opTag"));
        }
        if w(1) != psid {
            return Err(ZError::BadStatement("proofSystemId"));
        }
        let binding = if w(5) == keccak256(b"ZTX_V1_DIRECT") {
            let b: [u8; 32] = w(6).try_into().unwrap();
            if b == [0u8; 32] { Binding::Direct } else { Binding::Unwrap(b) }
        } else if w(5) == keccak256(b"ZTX_V1_RELAYED") {
            Binding::Relayed(w(6).try_into().unwrap())
        } else {
            return Err(ZError::BadStatement("bindingTag"));
        };
        if w(13)[..16].iter().any(|&b| b != 0) {
            return Err(ZError::BadStatement("salt word has dirty high bytes"));
        }
        Ok(Self {
            chain_id: u64_of(w(2))?,
            chain_uid: w(3).try_into().unwrap(),
            token: addr_of(w(4))?,
            binding,
            send_counter: u64_of(w(7))?,
            acc_seq: u64_of(w(8))?,
            fee: u64_of(w(9))?,
            beneficiary: w(10).try_into().unwrap(),
            amount: u64_of(w(11))?,
            recipient: addr_of(w(12))?,
            salt: w(13)[16..].try_into().unwrap(),
            memo_hash: w(14).try_into().unwrap(),
        })
    }

    fn check_fee(&self) -> Result<(), ZError> {
        if !value_in_range(self.fee) {
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

/// `keccak256("SCAAS-ZETHER-AUTH-V1" ‖ keccak256(statement))` — what `authSig` signs (§11).
pub fn auth_digest(statement: &[u8]) -> [u8; 32] {
    let mut b = b"SCAAS-ZETHER-AUTH-V1".to_vec();
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

    /// `be32(accSeq) ‖ be32(sendCounter) ‖ salt(16) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud` (§9).
    pub fn payload(&self) -> Vec<u8> {
        let mut b = be32_u64(self.header.acc_seq).to_vec();
        b.extend(be32_u64(self.header.send_counter));
        b.extend_from_slice(&self.header.salt);
        b.extend(cat::<C>(&[&self.y_f, &self.y_t, &self.c_out, &self.d_out, &self.c_deb, &self.c_aud]));
        b
    }

    /// The record the token stores, `R = salt ‖ Y_t ‖ C_out ‖ D_out ‖ C_aud` (CTR-ZTH-38).
    pub fn record(&self) -> Vec<u8> {
        let mut b = self.header.salt.to_vec();
        b.extend(cat::<C>(&[&self.y_t, &self.c_out, &self.d_out, &self.c_aud]));
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
        if h.memo_hash != [0u8; 32] {
            return Err(ZError::BadStatement("a memo hash on the single format"));
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

// ponytail: Fr is Copy, so stack copies made while proving are not wiped; this clears the
// long-lived structs. Full coverage needs a non-Copy secret scalar type.
impl<C: ZCurve> Drop for TransferWitness<C> {
    fn drop(&mut self) {
        for f in [&mut self.x, &mut self.v, &mut self.s, &mut self.b, &mut self.b_prime, &mut self.gamma_v, &mut self.gamma_b] {
            f.zeroize();
        }
    }
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

    /// Σ `10P + 192` ‖ BP(n_v = 64) `16P + 160` ‖ BP(n_b = 64) `16P + 160`.
    pub fn wire_len() -> usize {
        42 * point_len::<C>() + 512
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

fn witness_bytes<C: ZCurve>(ss: &[&Fr<C>], statement: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
    let mut b = zeroize::Zeroizing::new(cat_s::<C>(ss));
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

/// Native mirror of the on-chain transfer verifier (E1–E8 + BP(64, V_v) + BP(64, V_b)).
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

/// `info = tag ‖ chainUid ‖ token(20) ‖ fromUA ‖ be32(sendCounter) ‖ salt` (CTR-ZTH-30, CTR-ZTH-50).
fn sender_info(tag: &[u8], h: &Header, from_ua: &[u8; 32], salt: &[u8; 16]) -> Vec<u8> {
    [tag, &h.chain_uid, &h.token, from_ua, &be32_u64(h.send_counter), salt].concat()
}

/// `HKDF-SHA256(IKM = seed_zether, salt = ∅, info, L)`; `seed_zether` is the R33 conf key `x` (the per-account Zether
/// secret the wallet seed determines; controller ruling, pending the owner).
fn sender_hkdf<C: ZCurve>(x: &Fr<C>, info: &[u8], out: &mut [u8]) {
    let mut ikm = encode_scalar::<C>(x);
    Hkdf::<Sha256>::new(None, &ikm).expand(info, out).expect("L <= 255*32");
    ikm.zeroize();
}

/// The transfer randomness `s` (CTR-ZTH-30): `OKM mod r`, `OKM = HKDF-SHA256(seed_zether, "ZTX/s/v2" ‖ chainUid ‖ token
/// ‖ fromUA ‖ be32(sendCounter) ‖ salt, L = 64)`. The salt (16 fresh random bytes per build, re-drawn on `s = 0`) and
/// `sendCounter` are on chain, so the sender rebuilds `s` from its key and chain data alone, remembers no amount, and two
/// builds at one counter (a retry after a failed transaction) never share `s` (which would leak `v1 − v2` through
/// `C_aud`). One `s` per transfer, every recipient (owner Z3).
pub fn derive_s<C: ZCurve>(x: &Fr<C>, h: &Header, from_ua: &[u8; 32], salt: &[u8; 16]) -> Fr<C> {
    let mut okm = [0u8; 64];
    sender_hkdf::<C>(x, &sender_info(b"ZTX/s/v2", h, from_ua, salt), &mut okm);
    let s = Fr::<C>::from_be_bytes_mod_order(&okm);
    okm.zeroize();
    s
}

/// A fresh salt whose `s` is not 0 (CTR-ZTH-30: re-drawn on 0), and that `s`.
fn draw_salt<C: ZCurve, R: RngCore>(x: &Fr<C>, h: &Header, from_ua: &[u8; 32], rng: &mut R) -> ([u8; 16], Fr<C>) {
    loop {
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let s = derive_s::<C>(x, h, from_ua, &salt);
        if !s.is_zero() {
            return (salt, s);
        }
    }
}

/// Length of the sender memo of `m` legs: `17 + 40·m` (CTR-ZTH-50).
pub fn memo_len(m: usize) -> usize {
    17 + 40 * m
}

/// The memo keystream: `key = HKDF-SHA256(seed_zether, "ZTX/memo/v1" ‖ chainUid ‖ token ‖ fromUA ‖ be32(sendCounter) ‖
/// salt)` (32 B), `ks = HKDF-Expand-SHA256(key, "ZTX/memo/ks/v1", L)`.
fn memo_stream<C: ZCurve>(x: &Fr<C>, h: &Header, from_ua: &[u8; 32], salt: &[u8; 16], len: usize) -> Vec<u8> {
    let mut key = [0u8; 32];
    sender_hkdf::<C>(x, &sender_info(b"ZTX/memo/v1", h, from_ua, salt), &mut key);
    let mut ks = vec![0u8; len];
    Hkdf::<Sha256>::from_prk(&key).expect("32-byte PRK").expand(b"ZTX/memo/ks/v1", &mut ks).expect("L <= 255*32");
    key.zeroize();
    ks
}

/// The sender memo (CTR-ZTH-50): `salt ‖ ((flags ‖ (be8(v_j) ‖ toUA_j)_j) XOR ks)`, `flags` bit0 = the auditor included.
/// The token stores it next to the commitment; with it, the key and `sendCounter` the sender rebuilds every bundle from
/// storage alone (the recipients' keys from the registry). No MAC: a wrong key or a tampered memo rebuilds a record that
/// misses the commitment.
pub fn seal_memo<C: ZCurve>(
    x: &Fr<C>,
    h: &Header,
    from_ua: &[u8; 32],
    salt: &[u8; 16],
    auditor: bool,
    legs: &[(G<C>, u64)],
) -> Vec<u8> {
    let mut plain = vec![u8::from(auditor)];
    for (y, v) in legs {
        plain.extend_from_slice(&v.to_be_bytes());
        plain.extend_from_slice(&ua_of::<C>(y));
    }
    let ks = memo_stream::<C>(x, h, from_ua, salt, plain.len());
    let mut memo = salt.to_vec();
    memo.extend(plain.iter().zip(&ks).map(|(a, b)| a ^ b));
    memo
}

/// One leg of an opened memo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoLeg {
    pub amount: u64,
    pub to_ua: [u8; 32],
}

/// [`seal_memo`] backwards: the salt, the auditor flag and every `(v_j, toUA_j)`; `h` needs `chainUid`, `token` and
/// `sendCounter`. A wrong key gives garbage, caught by the commitment.
pub fn open_memo<C: ZCurve>(
    x: &Fr<C>,
    h: &Header,
    from_ua: &[u8; 32],
    memo: &[u8],
) -> Result<([u8; 16], bool, Vec<MemoLeg>), ZError> {
    if memo.len() < memo_len(1) || (memo.len() - 17) % 40 != 0 {
        return Err(ZError::BadStatement("memo length"));
    }
    let salt: [u8; 16] = memo[..16].try_into().unwrap();
    let ks = memo_stream::<C>(x, h, from_ua, &salt, memo.len() - 16);
    let plain: Vec<u8> = memo[16..].iter().zip(&ks).map(|(a, b)| a ^ b).collect();
    let legs = plain[1..]
        .chunks(40)
        .map(|c| MemoLeg { amount: u64::from_be_bytes(c[..8].try_into().unwrap()), to_ua: c[8..].try_into().unwrap() })
        .collect();
    Ok((salt, plain[0] & 1 == 1, legs))
}

/// Build the statement from the sender's state and prove it.
///
/// `acc` is the sender's on-chain `acc` slot and `balance` its plaintext (from BSGS); the
/// prover refuses when they disagree, when `balance < v + fee`, or when the
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
    let mut header = header;
    let g = generator::<C>();
    if !value_in_range(v) {
        return Err(ZError::OutOfRange);
    }
    if acc.c - acc.d * key.x != g * Fr::<C>::from(balance) {
        return Err(ZError::BadStatement("balance does not decrypt from acc"));
    }
    let b_prime = (balance as u128)
        .checked_sub(v as u128 + header.fee as u128)
        .ok_or(ZError::BadStatement("insufficient balance"))? as u64;
    let (salt, s) = draw_salt::<C, R>(&key.x, &header, &key.ua(), rng);
    (header.salt, header.memo_hash) = (salt, [0; 32]); // the single format has no memo
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
// Multi-recipient transfer (spec 2026-10-08-zether-multi-recipient-design §3–§4)
// ---------------------------------------------------------------------------------------------

/// `1 ≤ M ≤ MAX_RECIPIENTS` recipients per transfer.
pub const MAX_RECIPIENTS: usize = 16;
/// EIP-7825: the cap on a transaction's gas LIMIT (2^24), intrinsic and calldata included.
pub const TX_GAS_CAP: u64 = 16_777_216;
/// Headroom the prover keeps under [`TX_GAS_CAP`]: 1 % (167,772 gas) for bytecode, calldata and state drift; the
/// measured limits are already the dear case (cold accounts, every account's first credit).
pub const GAS_MARGIN: u64 = TX_GAS_CAP / 100;

/// zether.md §19 (a): the smallest transaction gas limit that settles a transfer to `M = 1, 2, …` recipients
/// (`ZetherGasLimit.t.sol`, `ZETHER_GAS_PROBE=1`): every call its own transaction (cold accounts and slots, 21,000 +
/// calldata with the EIP-7623 floor), binary search on the limit, inner fee paid. Relayed = through `mtxExecute`, which
/// adds the envelope and two more frames that each keep 1/64 (EIP-150). A row ends at the first `M` over the cap less
/// the margin. Re-measure with §19 and the edges move (`gas_table_edges` pins them).
fn gas_limits(bls: bool, mode: TransferMode, auditor: bool, relayed: bool) -> &'static [u64] {
    use TransferMode::*;
    match (bls, mode, auditor, relayed) {
        (false, Hash, true, false) => &[3_478_200, 5_127_191, 6_757_333, 8_391_120, 10_028_787, 11_672_911, 13_339_034, 14_988_311, 16_641_769],
        (false, Hash, true, true) => &[3_631_311, 5_333_664, 7_016_459, 8_703_431, 10_394_341, 12_091_786, 13_811_970, 15_515_275, 17_222_681],
        (false, Hash, false, false) => &[3_448_616, 5_067_362, 6_666_998, 8_270_124, 9_876_934, 11_489_853, 13_124_849, 14_742_559, 16_364_440, 18_012_699],
        (false, Hash, false, true) => &[3_600_794, 5_272_053, 6_923_390, 8_578_782, 10_237_824, 11_903_226, 13_591_309, 15_262_054, 16_936_814],
        (false, Bundle, true, false) => &[3_609_610, 5_393_165, 7_180_560, 8_971_885, 10_766_855, 12_565_789, 14_368_615, 16_175_389, 17_986_008],
        (false, Bundle, true, true) => &[3_766_809, 5_608_032, 7_453_356, 9_302_535, 11_155_836, 13_013_253, 14_874_606, 16_739_892],
        (false, Bundle, false, false) => &[3_538_940, 5_271_739, 7_008_161, 8_748_026, 10_491_746, 12_239_058, 13_990_088, 15_744_842, 17_503_407],
        (false, Bundle, false, true) => &[3_693_950, 5_482_779, 7_275_523, 9_071_916, 10_872_083, 12_676_303, 14_484_274, 16_295_902, 18_111_911],
        (false, NoBundle, true, false) => &[3_377_330, 4_976_325, 6_579_193, 8_185_824, 9_796_159, 11_410_630, 13_028_468, 14_650_074, 16_275_709, 17_905_215],
        (false, NoBundle, true, true) => &[3_527_161, 5_177_930, 6_832_869, 8_491_412, 10_154_291, 11_820_917, 13_491_606, 15_166_166, 16_844_747],
        (false, NoBundle, false, false) => &[3_347_734, 4_916_520, 6_488_845, 8_064_756, 9_644_318, 11_227_464, 12_814_331, 14_404_524, 15_998_568, 17_595_998],
        (false, NoBundle, false, true) => &[3_496_667, 5_116_235, 6_739_562, 8_366_775, 9_997_617, 11_632_490, 13_270_836, 14_913_003, 16_559_080, 18_208_894],
        (true, Hash, true, false) => &[3_980_739, 5_870_893, 7_759_065, 9_668_131, 11_597_793, 13_550_800, 15_542_949, 17_535_556],
        (true, Hash, true, true) => &[4_151_576, 6_104_001, 8_054_379, 10_026_595, 12_020_210, 14_038_108, 16_096_752, 18_155_759],
        (true, Hash, false, false) => &[3_935_776, 5_779_178, 7_619_618, 9_479_769, 11_359_561, 13_261_911, 15_202_174, 17_142_001],
        (true, Hash, false, true) => &[4_105_286, 6_009_450, 7_910_723, 9_832_513, 11_774_798, 13_740_510, 15_745_625, 17_750_224],
        (true, Bundle, true, false) => &[4_293_033, 6_498_853, 8_725_439, 10_972_723, 13_240_686, 15_529_396, 17_838_917],
        (true, Bundle, true, true) => &[4_473_865, 6_751_940, 9_051_611, 11_372_729, 13_715_493, 16_079_862, 18_465_985],
        (true, Bundle, false, false) => &[4_165_995, 6_242_964, 8_339_442, 10_455_737, 12_591_803, 14_747_469, 16_923_160],
        (true, Bundle, false, true) => &[4_342_846, 6_487_922, 8_653_484, 10_839_557, 13_046_035, 15_273_371, 17_521_427],
        (true, NoBundle, true, false) => &[3_877_522, 5_715_741, 7_574_603, 9_453_850, 11_353_954, 13_274_710, 15_215_864, 17_177_775],
        (true, NoBundle, true, true) => &[4_045_125, 5_943_722, 7_863_722, 9_805_273, 11_768_369, 13_753_189, 15_759_174, 17_786_510],
        (true, NoBundle, false, false) => &[3_832_679, 5_623_833, 7_434_987, 9_265_452, 11_115_794, 12_985_761, 14_875_267, 16_784_409],
        (true, NoBundle, false, true) => &[3_998_893, 5_849_170, 7_720_078, 9_611_179, 11_523_029, 13_455_278, 15_407_985, 17_381_188],
    }
}

/// The transaction gas limit of a multi-recipient transfer (`1 ≤ m`), [`gas_limits`]; past its row, the row's last step
/// per extra recipient (an estimate for the refusal's message only: those `M` are refused either way).
pub fn transfer_gas<C: ZCurve>(mode: TransferMode, auditor: bool, relayed: bool, m: usize) -> u64 {
    let t = gas_limits(C::NAME == "bls12381", mode, auditor, relayed);
    let n = t.len();
    if m <= n {
        t[m - 1]
    } else {
        t[n - 1] + (t[n - 1] - t[n - 2]) * (m - n) as u64
    }
}

/// The largest `M` whose [`transfer_gas`] fits [`TX_GAS_CAP`] less [`GAS_MARGIN`] (`zetherTransfer*` builds above it
/// are refused, [`ZError::GasCap`]).
pub fn max_recipients<C: ZCurve>(mode: TransferMode, auditor: bool, relayed: bool) -> usize {
    (1..=MAX_RECIPIENTS)
        .rev()
        .find(|&m| transfer_gas::<C>(mode, auditor, relayed, m) <= TX_GAS_CAP - GAS_MARGIN)
        .unwrap_or(0)
}

/// Refuse a build over the cap, naming the estimate, the most recipients this form takes and the cheaper forms that
/// fit at this `M` (leaving the auditor out is the sender's choice on an `OPTIONAL` token only; `bundle` and `none`
/// need a `BUNDLE` token). `relayed`: the build carries an envelope binding, so the relayed column applies.
fn check_gas<C: ZCurve>(mode: TransferMode, auditor: bool, relayed: bool, m: usize) -> Result<(), ZError> {
    let gas = transfer_gas::<C>(mode, auditor, relayed, m);
    if gas <= TX_GAS_CAP - GAS_MARGIN {
        return Ok(());
    }
    let aud = |a: bool| if a { "with the auditor" } else { "without the auditor" };
    let alternatives = TransferMode::ALL
        .into_iter()
        .flat_map(|f| [(f, true), (f, false)])
        .filter(|&(f, a)| (a <= auditor) && (f, a) != (mode, auditor))
        .filter_map(|(f, a)| {
            let g = transfer_gas::<C>(f, a, relayed, m);
            (g <= TX_GAS_CAP - GAS_MARGIN).then(|| format!("{} {} (~{g})", f.name(), aud(a)))
        })
        .collect::<Vec<_>>()
        .join(", ");
    Err(ZError::GasCap {
        what: format!("{} {} {}, {}", C::NAME, mode.name(), aud(auditor), if relayed { "relayed" } else { "direct" }),
        m,
        gas,
        cap: TX_GAS_CAP,
        margin: GAS_MARGIN,
        max_m: max_recipients::<C>(mode, auditor, relayed),
        alternatives: if alternatives.is_empty() { "none".into() } else { alternatives },
    })
}

/// Where the token keeps the disclosure bundles; part of `opTag`, so a relayer cannot switch it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferMode {
    /// Commit-reveal: `keccak256(R)` and the sender memo stored, `R` in an event
    /// (`zetherTransferCompact`; `zetherTransfer` on a `COMPACT` token, its only form). JSON `compact`.
    Hash,
    /// `B_1 ‖ … ‖ B_M` stored (`zetherTransfer` on a `BUNDLE` token, the default).
    Bundle,
    /// Nothing stored; disclosure off chain from calldata.
    NoBundle,
}

impl TransferMode {
    pub const ALL: [Self; 3] = [Self::Hash, Self::Bundle, Self::NoBundle];

    pub fn op_tag(self) -> [u8; 32] {
        keccak256(match self {
            Self::Hash => b"SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/HASH".as_slice(),
            Self::Bundle => b"SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/BUNDLE",
            Self::NoBundle => b"SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/NONE",
        })
    }

    /// The JSON name (the entries: `zetherTransfer` the token's default, `…Compact`, `…NoBundle`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Hash => "compact",
            Self::Bundle => "bundle",
            Self::NoBundle => "none",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == s)
    }

    fn from_tag(t: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.op_tag() == t)
    }
}

/// One recipient: `Y_t`, `C_out = [v]G + [s]Y_t`, `C_aud = [v]G + [s]Y_a` (O when the auditor is off).
#[derive(Clone, PartialEq, Eq)]
pub struct Leg<C: ZCurve> {
    pub y_t: G<C>,
    pub c_out: G<C>,
    pub c_aud: G<C>,
}

/// Shared `s` and `D_out = [s]G` for every leg; one debit `C_deb = [Σv]G + [s]Y_f`.
#[derive(Clone, PartialEq, Eq)]
pub struct MultiTransferStatement<C: ZCurve> {
    pub header: Header,
    pub mode: TransferMode,
    pub y_f: G<C>,
    pub y_a: G<C>,
    pub acc: Ciphertext<C>,
    pub d_out: G<C>,
    pub c_deb: G<C>,
    pub legs: Vec<Leg<C>>,
}

impl<C: ZCurve> MultiTransferStatement<C> {
    fn leg_bytes(&self) -> Vec<u8> {
        self.legs.iter().flat_map(|l| cat::<C>(&[&l.y_t, &l.c_out, &l.c_aud])).collect()
    }

    /// `header ‖ Y_f ‖ Y_a ‖ C_acc ‖ D_acc ‖ D_out ‖ C_deb ‖ be32(M) ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.header.encode_with(self.mode.op_tag(), proof_system_id_multi::<C>());
        b.extend(cat::<C>(&[&self.y_f, &self.y_a, &self.acc.c, &self.acc.d, &self.d_out, &self.c_deb]));
        b.extend(be32_u64(self.legs.len() as u64));
        b.extend(self.leg_bytes());
        b
    }

    /// The mode comes from `opTag`.
    pub fn decode(b: &[u8]) -> Result<Self, ZError> {
        let p = point_len::<C>();
        let at_m = HEADER_LEN + 6 * p;
        if b.len() < at_m + 32 {
            return Err(ZError::BadStatement("multi transfer statement length"));
        }
        let mode = TransferMode::from_tag(&b[..32]).ok_or(ZError::BadStatement("opTag"))?;
        let m = u64_of(&b[at_m..at_m + 32])? as usize;
        if m == 0 || m > MAX_RECIPIENTS || b.len() != at_m + 32 + 3 * p * m {
            return Err(ZError::BadStatement("multi transfer statement length"));
        }
        let header = Header::decode_with(b, mode.op_tag(), proof_system_id_multi::<C>())?;
        let mut r = Reader::<C>::new(b, HEADER_LEN);
        let (y_f, y_a) = (r.point()?, r.point()?);
        let acc = Ciphertext { c: r.point()?, d: r.point()? };
        let (d_out, c_deb) = (r.point()?, r.point()?);
        r.take(32)?;
        let legs = (0..m)
            .map(|_| Ok(Leg { y_t: r.point()?, c_out: r.point()?, c_aud: r.point()? }))
            .collect::<Result<_, ZError>>()?;
        Ok(Self { header, mode, y_f, y_a, acc, d_out, c_deb, legs })
    }

    /// `be32(accSeq) ‖ be32(sendCounter) ‖ salt(16) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`, then
    /// `memo` (the witness's: commit-reveal only, empty otherwise).
    pub fn payload(&self, memo: &[u8]) -> Vec<u8> {
        let mut b = be32_u64(self.header.acc_seq).to_vec();
        b.extend(be32_u64(self.header.send_counter));
        b.extend_from_slice(&self.header.salt);
        b.extend(be32_u64(self.legs.len() as u64));
        b.extend(cat::<C>(&[&self.y_f, &self.d_out, &self.c_deb]));
        b.extend(self.leg_bytes());
        b.extend_from_slice(memo);
        b
    }

    /// The record `R = salt ‖ B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j` — what the token stores or hashes.
    pub fn bundles(&self) -> Vec<u8> {
        let mut b = self.header.salt.to_vec();
        b.extend(self.legs.iter().flat_map(|l| cat::<C>(&[&l.y_t, &l.c_out, &self.d_out, &l.c_aud])));
        b
    }

    pub fn auditor_on(&self) -> bool {
        !self.y_a.is_zero()
    }

    /// Structural rules the token enforces before verify (spec §4).
    pub fn validate(&self) -> Result<(), ZError> {
        let h = &self.header;
        h.check_fee()?;
        if h.amount != 0 || h.recipient != [0u8; 20] {
            return Err(ZError::BadStatement("transfer with amount/recipient"));
        }
        if self.legs.is_empty() || self.legs.len() > MAX_RECIPIENTS {
            return Err(ZError::BadStatement("recipient count"));
        }
        if (h.memo_hash != [0u8; 32]) != (self.mode == TransferMode::Hash) {
            return Err(ZError::BadStatement("a memo hash exactly on commit-reveal"));
        }
        if self.y_f.is_zero() || self.d_out.is_zero() {
            return Err(ZError::BadStatement("Y_f or D_out = O"));
        }
        for (j, l) in self.legs.iter().enumerate() {
            if l.y_t.is_zero() || l.y_t == self.y_f {
                return Err(ZError::BadStatement("Y_to = O or Y_from"));
            }
            if self.legs[..j].iter().any(|o| o.y_t == l.y_t) {
                return Err(ZError::BadStatement("duplicate recipient"));
            }
            if !self.auditor_on() && !l.c_aud.is_zero() {
                return Err(ZError::BadStatement("auditor off but C_aud != O"));
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct MultiTransferWitness<C: ZCurve> {
    pub x: Fr<C>,
    pub s: Fr<C>,
    pub v: Vec<Fr<C>>,
    pub b: Fr<C>,
    pub b_prime: Fr<C>,
    pub gamma_v: Vec<Fr<C>>,
    pub gamma_b: Fr<C>,
    /// The sender memo a commit-reveal payload ends with ([`seal_memo`]); empty for the other forms.
    pub memo: Vec<u8>,
}

impl<C: ZCurve> Drop for MultiTransferWitness<C> {
    fn drop(&mut self) {
        for f in [&mut self.x, &mut self.s, &mut self.b, &mut self.b_prime, &mut self.gamma_b] {
            f.zeroize();
        }
        self.v.iter_mut().chain(self.gamma_v.iter_mut()).for_each(|f| f.zeroize());
    }
}

/// Per recipient: `V_vj`, `A_out_j`, `A_aud_j`, `A_Vvj`, `z_vj`, `z_gvj` and the range proof of `v_j`.
#[derive(Clone, PartialEq, Eq)]
pub struct LegProof<C: ZCurve> {
    pub v_v: G<C>,
    pub a_out: G<C>,
    pub a_aud: G<C>,
    pub a_vv: G<C>,
    pub z_v: Fr<C>,
    pub z_gv: Fr<C>,
    pub bp_v: RangeProof<C>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MultiTransferProof<C: ZCurve> {
    pub v_b: G<C>,
    pub a_y: G<C>,
    pub a_d: G<C>,
    pub a_deb: G<C>,
    pub a_bal: G<C>,
    pub a_vb: G<C>,
    pub z_x: Fr<C>,
    pub z_s: Fr<C>,
    pub z_b: Fr<C>,
    pub z_gb: Fr<C>,
    pub legs: Vec<LegProof<C>>,
    pub bp_b: RangeProof<C>,
}

impl<C: ZCurve> MultiTransferProof<C> {
    /// `V_b ‖ A_y ‖ A_D ‖ A_deb ‖ A_bal ‖ A_Vb ‖ (V_vj ‖ A_out_j ‖ A_aud_j ‖ A_Vvj)_j` — what `sigma.commit` absorbs.
    fn commit_bytes(&self) -> Vec<u8> {
        let mut b = cat::<C>(&[&self.v_b, &self.a_y, &self.a_d, &self.a_deb, &self.a_bal, &self.a_vb]);
        for l in &self.legs {
            b.extend(cat::<C>(&[&l.v_v, &l.a_out, &l.a_aud, &l.a_vv]));
        }
        b
    }

    /// commitments ‖ `z_x z_s z_b z_gb (z_vj z_gvj)_j` ‖ `BP(v_1) … BP(v_M)` ‖ `BP(b')`.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.commit_bytes();
        b.extend(cat_s::<C>(&[&self.z_x, &self.z_s, &self.z_b, &self.z_gb]));
        for l in &self.legs {
            b.extend(cat_s::<C>(&[&l.z_v, &l.z_gv]));
        }
        for l in &self.legs {
            b.extend(l.bp_v.encode());
        }
        b.extend(self.bp_b.encode());
        b
    }

    /// `(6 + 4M)P + (4 + 2M)·32 + (M + 1)·(16P + 160)`; `M = 1` is the single transfer's `42P + 512`.
    pub fn wire_len(m: usize) -> usize {
        (6 + 4 * m) * point_len::<C>() + (4 + 2 * m) * 32 + (m + 1) * RangeProof::<C>::wire_len(N_V)
    }

    pub fn decode(b: &[u8], m: usize) -> Result<Self, ZError> {
        if m == 0 || m > MAX_RECIPIENTS || b.len() != Self::wire_len(m) {
            return Err(ZError::BadProof("multi transfer proof length"));
        }
        let mut r = Reader::<C>::new(b, 0);
        let (v_b, a_y, a_d, a_deb, a_bal, a_vb) =
            (r.point()?, r.point()?, r.point()?, r.point()?, r.point()?, r.point()?);
        let pts = (0..m)
            .map(|_| Ok([r.point()?, r.point()?, r.point()?, r.point()?]))
            .collect::<Result<Vec<_>, ZError>>()?;
        let (z_x, z_s, z_b, z_gb) = (r.scalar()?, r.scalar()?, r.scalar()?, r.scalar()?);
        let zs = (0..m).map(|_| Ok((r.scalar()?, r.scalar()?))).collect::<Result<Vec<_>, ZError>>()?;
        let bps = (0..m).map(|_| r.range_proof(N_V)).collect::<Result<Vec<_>, ZError>>()?;
        let bp_b = r.range_proof(N_B)?;
        r.done()?;
        let legs = pts
            .into_iter()
            .zip(zs)
            .zip(bps)
            .map(|(([v_v, a_out, a_aud, a_vv], (z_v, z_gv)), bp_v)| LegProof { v_v, a_out, a_aud, a_vv, z_v, z_gv, bp_v })
            .collect();
        Ok(Self { v_b, a_y, a_d, a_deb, a_bal, a_vb, z_x, z_s, z_b, z_gb, legs, bp_b })
    }
}

/// Σ (E1–E8 with E3_j/E6_j/E7_j per recipient) + one Bulletproof per `v_j` + one for `b'`, one
/// transcript. No consistency checks, as [`prove_transfer_core`].
#[doc(hidden)]
pub fn prove_transfer_multi_core<C: ZCurve, R: RngCore + CryptoRng>(
    gens: &Gens<C>,
    st: &MultiTransferStatement<C>,
    w: &MultiTransferWitness<C>,
    rng: &mut R,
) -> Result<MultiTransferProof<C>, ZError> {
    let (g, hb) = (gens.g, gens.h);
    let stmt = st.encode();
    let mut secrets = vec![&w.x, &w.s, &w.b_prime, &w.gamma_b];
    secrets.extend(w.v.iter().chain(&w.gamma_v));
    let mut n = Nonces::new(&witness_bytes::<C>(&secrets, &stmt), rng);
    let (k_x, k_s, k_b, k_gb) = (n.next::<C>(), n.next::<C>(), n.next::<C>(), n.next::<C>());
    let k: Vec<(Fr<C>, Fr<C>)> = st.legs.iter().map(|_| (n.next::<C>(), n.next::<C>())).collect(); // (k_vj, k_gvj)
    let k_v_sum: Fr<C> = k.iter().map(|x| x.0).sum();
    let head = [
        g * w.b_prime + hb * w.gamma_b,              // V_b
        g * k_x,                                     // A_y
        g * k_s,                                     // A_D
        g * k_v_sum + st.y_f * k_s,                  // A_deb
        g * k_b + (st.acc.d - st.d_out) * k_x,       // A_bal
        g * k_b + hb * k_gb,                         // A_Vb
    ];
    let leg_pts: Vec<[G<C>; 4]> = st
        .legs
        .iter()
        .zip(&k)
        .enumerate()
        .map(|(j, (l, &(k_v, k_gv)))| {
            [
                g * w.v[j] + hb * w.gamma_v[j],                                              // V_vj
                g * k_v + l.y_t * k_s,                                                       // A_out_j
                if st.auditor_on() { g * k_v + st.y_a * k_s } else { G::<C>::zero() },      // A_aud_j
                g * k_v + hb * k_gv,                                                         // A_Vvj
            ]
        })
        .collect();
    let mut commits = cat::<C>(&head.iter().collect::<Vec<_>>());
    for l in &leg_pts {
        commits.extend(cat::<C>(&l.iter().collect::<Vec<_>>()));
    }
    let mut tr = Transcript::new();
    tr.absorb("statement", &stmt);
    tr.absorb("sigma.commit", &commits);
    let c = nz_challenge::<C>(&mut tr, "sigma.c")?;
    let mut legs = Vec::with_capacity(leg_pts.len());
    for (j, [v_v, a_out, a_aud, a_vv]) in leg_pts.into_iter().enumerate() {
        let bp_v = bp::prove_unchecked(&mut tr, gens, N_V, &w.v[j], &w.gamma_v[j], &mut n)?;
        legs.push(LegProof { v_v, a_out, a_aud, a_vv, z_v: k[j].0 + c * w.v[j], z_gv: k[j].1 + c * w.gamma_v[j], bp_v });
    }
    let bp_b = bp::prove_unchecked(&mut tr, gens, N_B, &w.b_prime, &w.gamma_b, &mut n)?;
    let [v_b, a_y, a_d, a_deb, a_bal, a_vb] = head;
    Ok(MultiTransferProof {
        v_b,
        a_y,
        a_d,
        a_deb,
        a_bal,
        a_vb,
        z_x: k_x + c * w.x,
        z_s: k_s + c * w.s,
        z_b: k_b + c * w.b_prime,
        z_gb: k_gb + c * w.gamma_b,
        legs,
        bp_b,
    })
}

/// Native mirror of the on-chain multi-recipient verifier.
pub fn verify_transfer_multi<C: ZCurve>(
    gens: &Gens<C>,
    st: &MultiTransferStatement<C>,
    p: &MultiTransferProof<C>,
) -> Result<Transcript, ZError> {
    st.validate()?;
    if p.legs.len() != st.legs.len() {
        return Err(ZError::Verify("leg count"));
    }
    let (g, hb) = (gens.g, gens.h);
    let mut tr = Transcript::new();
    tr.absorb("statement", &st.encode());
    tr.absorb("sigma.commit", &p.commit_bytes());
    let c = nz_challenge::<C>(&mut tr, "sigma.c")?;
    let one = Fr::<C>::from(1u64);
    let fee = Fr::<C>::from(st.header.fee);
    let z_v_sum: Fr<C> = p.legs.iter().map(|l| l.z_v).sum();
    is_zero_msm::<C>(&[g, st.y_f, p.a_y], &[p.z_x, -c, -one], "E1")?;
    is_zero_msm::<C>(&[g, st.d_out, p.a_d], &[p.z_s, -c, -one], "E2")?;
    for (l, lp) in st.legs.iter().zip(&p.legs) {
        is_zero_msm::<C>(&[g, l.y_t, l.c_out, lp.a_out], &[lp.z_v, p.z_s, -c, -one], "E3")?;
        if st.auditor_on() {
            is_zero_msm::<C>(&[g, st.y_a, l.c_aud, lp.a_aud], &[lp.z_v, p.z_s, -c, -one], "E6")?;
        } else if !lp.a_aud.is_zero() {
            return Err(ZError::Verify("auditor off but A_aud != O"));
        }
        is_zero_msm::<C>(&[g, hb, lp.v_v, lp.a_vv], &[lp.z_v, lp.z_gv, -c, -one], "E7")?;
    }
    is_zero_msm::<C>(&[g, st.y_f, st.c_deb, p.a_deb], &[z_v_sum, p.z_s, -c, -one], "E4")?;
    is_zero_msm::<C>(
        &[g, st.acc.d, st.d_out, st.acc.c, st.c_deb, p.a_bal],
        &[p.z_b + c * fee, p.z_x, -p.z_x, -c, c, -one],
        "E5",
    )?;
    is_zero_msm::<C>(&[g, hb, p.v_b, p.a_vb], &[p.z_b, p.z_gb, -c, -one], "E8")?;
    for lp in &p.legs {
        bp::verify(&mut tr, gens, N_V, &lp.v_v, &lp.bp_v)?;
    }
    bp::verify(&mut tr, gens, N_B, &p.v_b, &p.bp_b)?;
    Ok(tr)
}

/// Build the statement for `recipients` (`(Y_to, v)`, decoys with `v = 0`) and prove it; the
/// same checks as [`prove_transfer`], with `balance ≥ Σv + fee`.
#[allow(clippy::too_many_arguments)]
pub fn prove_transfer_multi<C: ZCurve, R: RngCore + CryptoRng>(
    gens: &Gens<C>,
    key: &ZetherKey<C>,
    header: Header,
    mode: TransferMode,
    recipients: &[(G<C>, u64)],
    y_aud: G<C>,
    acc: Ciphertext<C>,
    balance: u64,
    rng: &mut R,
) -> Result<(MultiTransferStatement<C>, MultiTransferProof<C>, MultiTransferWitness<C>), ZError> {
    let mut header = header;
    let g = generator::<C>();
    if acc.c - acc.d * key.x != g * Fr::<C>::from(balance) {
        return Err(ZError::BadStatement("balance does not decrypt from acc"));
    }
    let total: u128 = recipients.iter().map(|(_, v)| *v as u128).sum();
    let b_prime = (balance as u128)
        .checked_sub(total + header.fee as u128)
        .ok_or(ZError::BadStatement("insufficient balance"))? as u64;
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(ZError::BadStatement("recipient count"));
    }
    check_gas::<C>(mode, !y_aud.is_zero(), matches!(header.binding, Binding::Relayed(_)), recipients.len())?;
    let (salt, s) = draw_salt::<C, R>(&key.x, &header, &key.ua(), rng);
    header.salt = salt;
    let memo = if mode == TransferMode::Hash {
        seal_memo::<C>(&key.x, &header, &key.ua(), &salt, !y_aud.is_zero(), recipients)
    } else {
        Vec::new()
    };
    header.memo_hash = if memo.is_empty() { [0; 32] } else { keccak256(&memo) };
    let vs: Vec<Fr<C>> = recipients.iter().map(|(_, v)| Fr::<C>::from(*v)).collect();
    let legs = recipients
        .iter()
        .zip(&vs)
        .map(|((y, _), v)| Leg {
            y_t: *y,
            c_out: g * *v + *y * s,
            c_aud: if y_aud.is_zero() { G::<C>::zero() } else { g * *v + y_aud * s },
        })
        .collect();
    let st = MultiTransferStatement {
        mode,
        y_f: key.y,
        y_a: y_aud,
        acc,
        d_out: g * s,
        c_deb: g * vs.iter().copied().sum::<Fr<C>>() + key.y * s,
        legs,
        header,
    };
    st.validate()?;
    let mut n = Nonces::new(&witness_bytes::<C>(&[&key.x], &st.encode()), rng);
    let w = MultiTransferWitness {
        x: key.x,
        s,
        gamma_v: vs.iter().map(|_| n.next::<C>()).collect(),
        v: vs,
        b: Fr::<C>::from(balance),
        b_prime: Fr::<C>::from(b_prime),
        gamma_b: n.next::<C>(),
        memo,
    };
    let p = prove_transfer_multi_core(gens, &st, &w, rng)?;
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
        // §10: 0 < amount <= maxDecryptableShielded (<= 2^54) — with fee < 2^64, amount + fee < r.
        if self.header.amount == 0 || self.header.amount > MAX_TOTAL_SHIELDED {
            return Err(ZError::BadStatement("burn amount outside (0, 2^54]"));
        }
        if self.header.salt != [0u8; 16] || self.header.memo_hash != [0u8; 32] {
            return Err(ZError::BadStatement("salt or memo on a burn"));
        }
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

impl<C: ZCurve> Drop for BurnWitness<C> {
    fn drop(&mut self) {
        for f in [&mut self.x, &mut self.b, &mut self.b_prime, &mut self.gamma_b] {
            f.zeroize();
        }
    }
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
