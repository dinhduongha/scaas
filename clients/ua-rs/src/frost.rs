//! RFC 9591 FROST with the DKG of ZF `frost-core` (accounts.md §1.6.1): FROST(secp256k1, SHA-256) is ZF
//! `frost-secp256k1` ([`Secp256K1Sha256`]); FROST(bn254, keccak256) is the [`Bn254Keccak256`] ciphersuite defined here
//! per the spec table: `contextString = "FROST-BN254-KECCAK256-SCAAS-v1"`, elements 64-byte EIP-196 `x ‖ y`, scalars
//! 32-byte big-endian, `H1/H3/H4/H5/HDKG(m) = keccak256(cs ‖ label ‖ m ‖ 0x00) ‖ keccak256(cs ‖ label ‖ m ‖ 0x01) mod r`
//! (labels `rho`, `nonce`, `msg`, `com`, `dkg`; `H4`/`H5` output that scalar's 32 bytes), `H2` = the scaas Schnorr
//! challenge, so a signature verifies as `schnorr-bn254`. No `HID` (identifiers are the scalars 1..n). Plus
//! [`dkg`] / [`Dkg::sign`]: every participant simulated in one process, for groups.json. Feature `signers`. UNAUDITED.
use crate::keccak;
use crate::musig2::{bn_parse, bn_schnorr_challenge, bn_ser};
use frost_core::keys::dkg::{part1, part2, part3, round1};
use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::{Ciphersuite, Error, Field, FieldError, Group, GroupError, Identifier, Signature, SigningPackage};
pub use frost_secp256k1::Secp256K1Sha256;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;

pub const BN254_CONTEXT: &str = "FROST-BN254-KECCAK256-SCAAS-v1";

#[derive(Clone, Copy)]
pub struct Bn254ScalarField;

impl Field for Bn254ScalarField {
    type Scalar = ark_bn254::Fr;
    type Serialization = [u8; 32];
    fn zero() -> Self::Scalar {
        ark_bn254::Fr::from(0u64)
    }
    fn one() -> Self::Scalar {
        ark_bn254::Fr::from(1u64)
    }
    fn invert(s: &Self::Scalar) -> Result<Self::Scalar, FieldError> {
        ark_ff::Field::inverse(s).ok_or(FieldError::InvalidZeroScalar)
    }
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        use ark_ff::PrimeField;
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        ark_bn254::Fr::from_be_bytes_mod_order(&b)
    }
    fn serialize(s: &Self::Scalar) -> Self::Serialization {
        use crate::musig2::{Bn254, Curve};
        Bn254::s_bytes(s)
    }
    fn little_endian_serialize(s: &Self::Scalar) -> Self::Serialization {
        let mut b = Self::serialize(s);
        b.reverse();
        b
    }
    fn deserialize(b: &Self::Serialization) -> Result<Self::Scalar, FieldError> {
        use crate::musig2::{Bn254, Curve};
        Bn254::s_parse(b).ok_or(FieldError::MalformedScalar)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Bn254Group;

impl Group for Bn254Group {
    type Field = Bn254ScalarField;
    type Element = ark_bn254::G1Projective;
    type Serialization = [u8; 64];
    fn cofactor() -> ark_bn254::Fr {
        ark_bn254::Fr::from(1u64)
    }
    fn identity() -> Self::Element {
        ark_ff::Zero::zero()
    }
    fn generator() -> Self::Element {
        ark_ec::PrimeGroup::generator()
    }
    fn serialize(e: &Self::Element) -> Result<Self::Serialization, GroupError> {
        if *e == Self::identity() {
            return Err(GroupError::InvalidIdentityElement);
        }
        Ok(bn_ser(e).try_into().expect("64 bytes"))
    }
    fn deserialize(b: &Self::Serialization) -> Result<Self::Element, GroupError> {
        if b.iter().all(|x| *x == 0) {
            return Err(GroupError::InvalidIdentityElement);
        }
        bn_parse(b).ok_or(GroupError::MalformedElement)
    }
}

/// `keccak256(cs ‖ label ‖ m ‖ 0x00) ‖ keccak256(cs ‖ label ‖ m ‖ 0x01)` mod r.
pub fn bn254_hash(label: &[u8], m: &[u8]) -> ark_bn254::Fr {
    use ark_ff::PrimeField;
    let h = |b: u8| keccak(&[BN254_CONTEXT.as_bytes(), label, m, &[b]]);
    ark_bn254::Fr::from_be_bytes_mod_order(&[h(0), h(1)].concat())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bn254Keccak256;

impl Ciphersuite for Bn254Keccak256 {
    const ID: &'static str = BN254_CONTEXT;
    type Group = Bn254Group;
    type HashOutput = [u8; 32];
    type SignatureSerialization = [u8; 96];
    fn H1(m: &[u8]) -> ark_bn254::Fr {
        bn254_hash(b"rho", m)
    }
    /// frost-core passes `m = R ‖ Y ‖ msg`: exactly the scaas Schnorr transcript.
    fn H2(m: &[u8]) -> ark_bn254::Fr {
        bn_schnorr_challenge(m)
    }
    fn H3(m: &[u8]) -> ark_bn254::Fr {
        bn254_hash(b"nonce", m)
    }
    fn H4(m: &[u8]) -> [u8; 32] {
        Bn254ScalarField::serialize(&bn254_hash(b"msg", m))
    }
    fn H5(m: &[u8]) -> [u8; 32] {
        Bn254ScalarField::serialize(&bn254_hash(b"com", m))
    }
    fn HDKG(m: &[u8]) -> Option<ark_bn254::Fr> {
        Some(bn254_hash(b"dkg", m))
    }
}

/// Participant `i` (1..=n); panics on 0 — a fixture helper, `Dkg::sign` takes untrusted indices without it.
pub fn id<C: Ciphersuite>(i: u16) -> Identifier<C> {
    Identifier::try_from(i).expect("nonzero")
}

/// One DKG run (frost-core `part1/2/3`) with participants `1..=n`.
pub struct Dkg<C: Ciphersuite> {
    pub t: u16,
    pub n: u16,
    pub round1: BTreeMap<Identifier<C>, round1::Package<C>>,
    pub keys: BTreeMap<Identifier<C>, KeyPackage<C>>,
    pub public: PublicKeyPackage<C>,
}

fn others<K: Ord + Copy, V: Clone>(m: &BTreeMap<K, V>, me: &K) -> BTreeMap<K, V> {
    m.iter().filter(|(k, _)| *k != me).map(|(k, v)| (*k, v.clone())).collect()
}

pub fn dkg<C: Ciphersuite, R: RngCore + CryptoRng>(t: u16, n: u16, rng: &mut R) -> Result<Dkg<C>, Error<C>> {
    if n < 2 {
        return Err(Error::InvalidMaxSigners); // part1 checks t and n, but n = 0 would never reach it
    }
    let mut sec1 = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for i in 1..=n {
        let (s, p) = part1::<C, _>(id(i), n, t, &mut *rng)?;
        sec1.insert(id::<C>(i), s);
        round1.insert(id::<C>(i), p);
    }
    let mut sec2 = BTreeMap::new();
    let mut inbox: BTreeMap<Identifier<C>, BTreeMap<Identifier<C>, _>> = BTreeMap::new();
    for (me, s) in sec1 {
        let (s2, out) = part2(s, &others(&round1, &me))?;
        sec2.insert(me, s2);
        for (to, pkg) in out {
            inbox.entry(to).or_default().insert(me, pkg);
        }
    }
    let mut keys = BTreeMap::new();
    let mut public = None;
    for (me, s2) in &sec2 {
        let (kp, pkp) = part3(s2, &others(&round1, me), &inbox[me])?;
        assert!(public.as_ref().is_none_or(|p| *p == pkp), "participants disagree on the public key package");
        public = Some(pkp);
        keys.insert(*me, kp);
    }
    Ok(Dkg { t, n, round1, keys, public: public.expect("n ≥ 2") })
}

impl<C: Ciphersuite> Dkg<C> {
    /// Registry key data `Y ‖ u16 t ‖ u16 n ‖ n × (t × C_ik ‖ R_i ‖ μ_i)`.
    pub fn key_data(&self) -> Vec<u8> {
        let mut d = self.public.verifying_key().serialize().expect("Y");
        d.extend(self.t.to_be_bytes());
        d.extend(self.n.to_be_bytes());
        for p in self.round1.values() {
            d.extend(p.commitment().serialize_whole().expect("commitments"));
            d.extend(p.proof_of_knowledge().serialize().expect("PoK"));
        }
        d
    }

    /// The group secret (Σ a_i0), reconstructed from `t` shares.
    pub fn group_secret(&self) -> frost_core::SigningKey<C> {
        let kps: Vec<KeyPackage<C>> = self.keys.values().take(self.t as usize).cloned().collect();
        frost_core::keys::reconstruct(&kps).expect("t shares")
    }

    /// RFC 9591 two-round signing by `signers`, aggregated and checked against `Y`.
    pub fn sign<R: RngCore + CryptoRng>(&self, signers: &[u16], msg: &[u8], rng: &mut R) -> Result<Signature<C>, Error<C>> {
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for i in signers {
            let me = Identifier::try_from(*i)?;
            let key = self.keys.get(&me).ok_or(Error::UnknownIdentifier)?;
            let (n, c) = frost_core::round1::commit(key.signing_share(), &mut *rng);
            nonces.insert(me, n);
            commitments.insert(me, c);
        }
        let package = SigningPackage::new(commitments, msg);
        let mut shares = BTreeMap::new();
        for (i, n) in &nonces {
            shares.insert(*i, frost_core::round2::sign(&package, n, &self.keys[i])?);
        }
        let sig = frost_core::aggregate(&package, &shares, &self.public)?;
        self.public.verifying_key().verify(msg, &sig)?;
        Ok(sig)
    }
}
