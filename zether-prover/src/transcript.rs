//! Fiat-Shamir transcript, byte-exact per zether-design §4. One transcript covers the
//! statement, the Sigma commitments and both Bulletproofs (research §3.4.6/§3.4.7).
//!
//! ```text
//! init():               st = keccak256("SCAAS-ZETHER-TRANSCRIPT-V1")
//! absorb(label, data):  st = keccak256(st ‖ 0x00 ‖ u8(len(label)) ‖ label ‖ be4(len(data)) ‖ data)
//! challenge(label):     st = keccak256(st ‖ 0x01 ‖ u8(len(label)) ‖ label); return hashToScalar(st)
//! hashToScalar(seed) = (keccak256(seed ‖ 0x02) · 2^256 + keccak256(seed ‖ 0x03)) mod r
//! ```

use ark_ff::PrimeField;

use crate::curve::{keccak256, Fr, ZCurve};

pub fn hash_to_scalar<C: ZCurve>(seed: &[u8; 32]) -> Fr<C> {
    let mut wide = [0u8; 64];
    for (i, tag) in [2u8, 3].into_iter().enumerate() {
        let mut b = seed.to_vec();
        b.push(tag);
        wide[32 * i..32 * i + 32].copy_from_slice(&keccak256(&b));
    }
    Fr::<C>::from_be_bytes_mod_order(&wide)
}

/// One transcript operation, recorded for the byte-for-byte vectors (§14 `transcript.json`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Absorb { label: String, data: Vec<u8> },
    Challenge { label: String },
}

#[derive(Clone)]
pub struct Transcript {
    st: [u8; 32],
    pub ops: Vec<Op>,
    pub states: Vec<[u8; 32]>,
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    pub fn new() -> Self {
        Self { st: keccak256(b"SCAAS-ZETHER-TRANSCRIPT-V1"), ops: vec![], states: vec![] }
    }

    fn step(&mut self, kind: u8, label: &str, data: Option<&[u8]>) {
        assert!(label.len() < 256);
        let mut b = Vec::with_capacity(38 + label.len() + data.map_or(0, |d| d.len()));
        b.extend_from_slice(&self.st);
        b.push(kind);
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
        if let Some(d) = data {
            b.extend_from_slice(&(d.len() as u32).to_be_bytes());
            b.extend_from_slice(d);
        }
        self.st = keccak256(&b);
        self.states.push(self.st);
    }

    pub fn absorb(&mut self, label: &str, data: &[u8]) {
        self.step(0x00, label, Some(data));
        self.ops.push(Op::Absorb { label: label.into(), data: data.to_vec() });
    }

    /// Never zero for a verifier that checks `!= 0`; callers reject a zero challenge.
    pub fn challenge<C: ZCurve>(&mut self, label: &str) -> Fr<C> {
        self.step(0x01, label, None);
        self.ops.push(Op::Challenge { label: label.into() });
        hash_to_scalar::<C>(&self.st)
    }

    pub fn state(&self) -> [u8; 32] {
        self.st
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{Bls12381, Bn254};
    use ark_ff::Zero;

    #[test]
    fn layout_matches_spec_by_hand() {
        let mut t = Transcript::new();
        t.absorb("statement", &[0xab, 0xcd]);
        let mut pre = keccak256(b"SCAAS-ZETHER-TRANSCRIPT-V1").to_vec();
        pre.extend_from_slice(&[0x00, 9]);
        pre.extend_from_slice(b"statement");
        pre.extend_from_slice(&[0, 0, 0, 2, 0xab, 0xcd]);
        let st1 = keccak256(&pre);
        assert_eq!(t.state(), st1);
        let c = t.challenge::<Bn254>("sigma.c");
        let mut pre = st1.to_vec();
        pre.extend_from_slice(&[0x01, 7]);
        pre.extend_from_slice(b"sigma.c");
        let st2 = keccak256(&pre);
        assert_eq!(t.state(), st2);
        assert_eq!(c, hash_to_scalar::<Bn254>(&st2));
        assert!(!c.is_zero());
        // Same state, different curve: different reduction.
        let _ = hash_to_scalar::<Bls12381>(&st2);
    }
}
