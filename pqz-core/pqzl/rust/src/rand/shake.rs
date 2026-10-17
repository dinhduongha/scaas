//! `shake128.c`: SHAKE128 (LaZer's transcript hashes, `pqz_rel.c` `shake_tag` / `expand_A`) and the fork's SHAKE256
//! (`pqz_keys.c`), from the `sha3` crate (D1). C's state allows absorb after a squeeze only as an `ASSERT_ERR`; here
//! the types rule it out (absorb all parts, then squeeze). Successive squeezes continue one output stream, as C's.
//!
//! `pqz_keys.c`'s bit stream: SHAKE256(tag || seed || be4(ctr)), one squeezed byte per 8 bits, bits LSB first, and
//! CBD_eta on it.
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader, Shake256, Shake256Reader};

/// a SHAKE output stream
pub(crate) struct Xof<R>(R);

impl<R: XofReader> Xof<R> {
    /// the next `out.len()` bytes (`shake128_squeeze` / `shake256_squeeze`)
    pub(crate) fn squeeze(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

/// SHAKE128 of the concatenated `parts`
pub(crate) fn shake128(parts: &[&[u8]]) -> Xof<Shake128Reader> {
    let mut h = Shake128::default();
    parts.iter().for_each(|p| h.update(p));
    Xof(h.finalize_xof())
}

/// SHAKE256 of the concatenated `parts`
pub(crate) fn shake256(parts: &[&[u8]]) -> Xof<Shake256Reader> {
    let mut h = Shake256::default();
    parts.iter().for_each(|p| h.update(p));
    Xof(h.finalize_xof())
}

/// `pqz_keys.c`'s `bits_t`
pub(crate) struct Stream {
    xof: Xof<Shake256Reader>,
    byte: u8,
    nbits: u32,
}

impl Stream {
    /// the bits of SHAKE256 of the concatenated `parts`
    pub(crate) fn new(parts: &[&[u8]]) -> Stream {
        Stream { xof: shake256(parts), byte: 0, nbits: 0 }
    }

    /// `stream (b, tag, taglen, seed, ctr)`: SHAKE256(tag || seed || be4(ctr))
    pub(crate) fn keys(tag: &[u8], seed: &[u8; 32], ctr: u32) -> Stream {
        Stream::new(&[tag, seed, &ctr.to_be_bytes()])
    }

    /// `bit`
    pub(crate) fn bit(&mut self) -> u32 {
        if self.nbits == 0 {
            let mut x = [0u8];
            self.xof.squeeze(&mut x);
            (self.byte, self.nbits) = (x[0], 8);
        }
        let v = (self.byte & 1) as u32;
        self.byte >>= 1;
        self.nbits -= 1;
        v
    }

    /// squeeze bytes straight from the SHAKE state (`pqz_enc_group_seed`, before any bit is read)
    pub(crate) fn squeeze(&mut self, out: &mut [u8]) {
        self.xof.squeeze(out);
    }
}

/// `cbd`: CBD_eta, (sum of eta bits) - (sum of the next eta bits)
pub(crate) fn cbd(eta: u32, s: &mut Stream) -> i32 {
    let a: u32 = (0..eta).map(|_| s.bit()).sum();
    let c: u32 = (0..eta).map(|_| s.bit()).sum();
    a as i32 - c as i32
}
