//! `aes256ctr.c`: AES-256 in counter mode, the counter a 128-bit big-endian integer starting at the nonce (the AES-NI
//! stream of upstream LaZer). The C core makes the keystream 64 bytes at a time and hands it out from a cache; the
//! bytes are the same as one block at a time, so this is the plain CTR keystream. AES from the `aes` crate (D1).
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

pub(crate) struct AesCtr {
    aes: Aes256,
    ctr: [u8; 16],
    buf: [u8; 16],
    pos: usize,
}

impl AesCtr {
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 16]) -> AesCtr {
        AesCtr { aes: Aes256::new(key.into()), ctr: *nonce, buf: [0; 16], pos: 16 }
    }

    /// the next `out.len()` keystream bytes
    pub(crate) fn stream(&mut self, out: &mut [u8]) {
        for b in out {
            if self.pos == 16 {
                let mut blk = GenericArray::from(self.ctr);
                self.aes.encrypt_block(&mut blk);
                self.buf = blk.into();
                self.ctr = (u128::from_be_bytes(self.ctr).wrapping_add(1)).to_be_bytes();
                self.pos = 0;
            }
            *b = self.buf[self.pos];
            self.pos += 1;
        }
    }
}
