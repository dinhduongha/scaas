//! Fiat–Shamir transcript: Keccak-256 chained state (the EVM's opcode, as the STARK's transcript seed), seeded with
//! keccak256("SCAAS-PQZH-LIGERO-V1" || u8(op) || be32(len) || stmt). absorb: state = keccak(state || data).
//! Squeeze: keccak(state || 0xff || be64(counter)) gives four 8-byte big-endian words; a field element is a word masked
//! to LOG2Q bits (v3 42), rejected if >= q (as pqz-core's expand_A).

use crate::fq::{F4, Fq, Q};
use crate::merkle::{H, keccak};

pub struct Tr {
    st: H,
    ctr: u64,
    buf: Vec<u64>,
}

impl Tr {
    pub fn new(op: u8, stmt: &[u8]) -> Tr {
        let st = keccak(&[b"SCAAS-PQZH-LIGERO-V1", &[op], &(stmt.len() as u32).to_be_bytes(), stmt]);
        Tr { st, ctr: 0, buf: Vec::new() }
    }
    pub fn absorb(&mut self, data: &[u8]) {
        self.st = keccak(&[&self.st, data]);
        self.ctr = 0;
        self.buf.clear();
    }
    pub fn word(&mut self) -> u64 {
        if self.buf.is_empty() {
            let h = keccak(&[&self.st, &[0xff], &self.ctr.to_be_bytes()]);
            self.ctr += 1;
            self.buf = h.chunks(8).rev().map(|c| u64::from_be_bytes(c.try_into().unwrap())).collect();
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
    /// proof of work: keccak(state || "PoW" || be64(nonce)) starts with `bits` zero bits
    pub fn pow_ok(&self, nonce: u64, bits: u32) -> bool {
        let h = keccak(&[&self.st, b"PoW", &nonce.to_be_bytes()]);
        u64::from_be_bytes(h[..8].try_into().unwrap()).leading_zeros() >= bits
    }
}
