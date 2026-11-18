//! Fiat–Shamir transcript: Keccak-256 chained state (the EVM's opcode, as the STARK's transcript seed), seeded with
//! keccak256("SCAAS-PQZH-LIGERO-V1" || u8(op) || be32(len) || stmt). absorb: state = keccak(TAG_ABSORB || state ||
//! data). Squeeze: keccak(TAG_SQUEEZE || state || be64(counter)) gives four 8-byte big-endian words; a field element is
//! a word masked to LOG2Q bits, rejected if >= q (as pqz-core's expand_A). PoW: keccak(TAG_POW || state || be64(nonce)).
//! The one-byte role tags (merkle.rs; T-35, PQZH_ID v4) replace v3's untagged absorb, the 0xff squeeze byte after the
//! state and the "PoW" string.

use crate::fq::{Fq, F4, Q};
use crate::merkle::{keccak, H, TAG_ABSORB, TAG_POW, TAG_SQUEEZE};

pub struct Tr {
    st: H,
    ctr: u64,
    buf: Vec<u64>,
}

impl Tr {
    pub fn new(op: u8, stmt: &[u8]) -> Tr {
        let st = keccak(&[
            b"SCAAS-PQZH-LIGERO-V1",
            &[op],
            &(stmt.len() as u32).to_be_bytes(),
            stmt,
        ]);
        Tr {
            st,
            ctr: 0,
            buf: Vec::new(),
        }
    }
    pub fn absorb(&mut self, data: &[u8]) {
        self.st = keccak(&[&[TAG_ABSORB], &self.st, data]);
        self.ctr = 0;
        self.buf.clear();
    }
    pub fn word(&mut self) -> u64 {
        if self.buf.is_empty() {
            let h = keccak(&[&[TAG_SQUEEZE], &self.st, &self.ctr.to_be_bytes()]);
            self.ctr += 1;
            self.buf = h
                .chunks(8)
                .rev()
                .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
                .collect();
        }
        self.buf.pop().unwrap()
    }
    pub fn fq(&mut self) -> Fq {
        loop {
            let v = self.word() & crate::fq::MASK;
            if v < Q {
                return Fq(v);
            }
        }
    }
    pub fn f4(&mut self) -> F4 {
        F4([self.fq(), self.fq(), self.fq(), self.fq()])
    }
    /// uniform index in [0, n) by rejection
    pub fn index(&mut self, n: usize) -> usize {
        let mask = (n.next_power_of_two() - 1) as u64;
        loop {
            let v = (self.word() & mask) as usize;
            if v < n {
                return v;
            }
        }
    }
    /// proof of work: keccak(TAG_POW || state || be64(nonce)) starts with `bits` zero bits
    pub fn pow_ok(&self, nonce: u64, bits: u32) -> bool {
        let h = keccak(&[&[TAG_POW], &self.st, &nonce.to_be_bytes()]);
        u64::from_be_bytes(h[..8].try_into().unwrap()).leading_zeros() >= bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::node;

    /// T-35: absorb, squeeze and PoW hash their tagged inputs; an absorb of two digests is never the Merkle node of the
    /// state and that digest (fails if a tag is dropped or two roles share one)
    #[test]
    fn transcript_roles_are_tagged() {
        let mut t = Tr::new(3, b"stmt");
        let st0 = t.st;
        let d = keccak(&[b"root"]);
        t.absorb(&d);
        assert_eq!(t.st, keccak(&[&[TAG_ABSORB], &st0, &d]));
        assert_ne!(t.st, node(&st0, &d));
        assert_ne!(t.st, keccak(&[&st0, &d]));
        let w = t.word();
        let h = keccak(&[&[TAG_SQUEEZE], &t.st, &0u64.to_be_bytes()]);
        assert_eq!(w, u64::from_be_bytes(h[..8].try_into().unwrap()));
        let pow = keccak(&[&[TAG_POW], &t.st, &5u64.to_be_bytes()]);
        assert_eq!(
            t.pow_ok(
                5,
                u64::from_be_bytes(pow[..8].try_into().unwrap()).leading_zeros()
            ),
            true
        );
    }
}
