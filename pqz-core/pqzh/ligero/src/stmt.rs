//! Ops and statement / witness layouts of pqz-core (pqz.h): the constants the Ligero relations read. Copied from the
//! Plonky3 crate's `pqzh/src/rel.rs` and extended to R_BURN / R_DS / R_DR (P6e Task 6 prep / Task 8); replaced by
//! `pqz-stmt` (plan R2, Task 5 / 6).

pub const OP_TRANSFER: u8 = 1;
pub const OP_BURN: u8 = 2;
pub const OP_REGISTER: u8 = 3;
pub const OP_DISCLOSE_SENDER: u8 = 4;
pub const OP_DISCLOSE_RECEIVER: u8 = 5;
/// every op with a relation (REFRESH = op 2, AUDITOR = op 5: same relation, other opTag)
pub const OPS: [u8; 5] = [OP_REGISTER, OP_TRANSFER, OP_BURN, OP_DISCLOSE_SENDER, OP_DISCLOSE_RECEIVER];

pub const PREFIX: usize = 64;
/// Debit statements (pq-zether.md §7.7, pqz.h PQZ_HEADER_BYTES): 640-byte header of 32-byte words; the relations
/// read the fee word (offset 256) and, R_BURN, the amount word (288), each be32 < 2^64; the rest is only hashed.
pub const HEADER: usize = 640;
pub const HDR_FEE: usize = 256;
pub const HDR_AMOUNT: usize = 288;
pub const POLYVEC: usize = 16384;
pub const VB: usize = 128;
pub const REG_STMT: usize = PREFIX + 32 + POLYVEC;
pub const REG_WIT: usize = 2048 + 4096;
pub const TX_STMT: usize = HEADER + 3 * POLYVEC + (POLYVEC + VB) + (POLYVEC + 3 * VB);
pub const TX_WIT: usize = 2048 + 4096 + 2048 + 4096 + 3 * 32 + 16 + 16;
/// header || pk_f || u_T || v_T || u || v_f
pub const BURN_STMT: usize = HEADER + POLYVEC + (POLYVEC + VB) + (POLYVEC + VB);
/// s_f || e_f || r || e1 || e2_f || d'
pub const BURN_WIT: usize = 2048 + 4096 + 2048 + 4096 + 32 + 16;
/// Disclosure (§7.9): opTag || proofSystemId || chainId || chainUid || token || registry || entryRef || amount || kind
/// (32-byte words) || pk || u || v; the relations read amount (< 2^64), pk, u, v
pub const DISC_AMOUNT: usize = PREFIX + 5 * 32;
pub const DISC_KIND: usize = DISC_AMOUNT + 32;
pub const DISC_PK: usize = DISC_KIND + 32;
pub const DISC_STMT: usize = DISC_PK + 2 * POLYVEC + VB;
/// R_DS: r || e1 || e2_t
pub const DS_WIT: usize = 2048 + 4096 + 32;
/// R_DR: s || e
pub const DR_WIT: usize = 2048 + 4096;

/// proofSystemId (statement bytes 32..63) the bench statements carry: still the STARK's provisional
/// keccak256("scaas/pqz/pqzh/stark-d1-goldilocks5-fri-keccak256-zk/v1"); the relations only hash it. The Ligero id
/// (plan D3) replaces it in Task 9.
pub const PQZH_PROOF_SYSTEM_ID: [u8; 32] = hex32("aa1f92ddc5763201c2582c8387bd6513842e52779310d6bcf39a7fec99284304");
/// PQZL's id as pqz-core v2 writes it, used only for the byte cross-check against pqz_bench.c.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// pqz.h sizes
    #[test]
    fn sizes() {
        assert_eq!([REG_STMT, TX_STMT, BURN_STMT, DISC_STMT], [16480, 83072, 50048, 33184]);
        assert_eq!([REG_WIT, TX_WIT, BURN_WIT, DS_WIT, DR_WIT], [6144, 12416, 12336, 6176, 6144]);
        assert_eq!((DISC_AMOUNT, DISC_PK), (224, 288));
    }
}
