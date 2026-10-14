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
/// auditorOn word (R_TX: 1 for the 83,072-byte statement, plan R6; only hashed by the relation)
pub const HDR_AUDITOR_ON: usize = 448;
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

/// proofSystemId (statement bytes 32..63) of PQZH-Ligero, plan D3:
/// keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1"). `cs::parse` (prover and verifier) rejects
/// every other id. The STARK's provisional id keccak256("scaas/pqz/pqzh/stark-d1-goldilocks5-fri-keccak256-zk/v1")
/// = 0xaa1f92dd... is retired unused.
pub const PQZH_PROOF_SYSTEM_ID: [u8; 32] = hex32("0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4");
/// PQZL's id as pqz-core v2 writes it (pqz.h PQZ_PROOF_SYSTEM_ID, plan D2); a PQZH statement carrying it is rejected.
pub const PQZL_PROOF_SYSTEM_ID: [u8; 32] = hex32("2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f");

/// opTags keccak256("SCAAS-PQZ-OP-<NAME>-V1") (pq-zether.md §7, plan Serialization v1), statement bytes 0..31
pub const TAG_TRANSFER: [u8; 32] = hex32("ef22f3d1c1fc2edc565522eb73ca8cb782e8780eaf9b1f677965dd0cd5275414");
pub const TAG_BURN: [u8; 32] = hex32("7383374d83fbb89f84ee079bff7a2742e4acb70f64b0b1e2ef40c34fb4cc1407");
pub const TAG_REFRESH: [u8; 32] = hex32("f118f2df0f018062e2d4c296a01707dcd7ad7c85f6981d68517ac8b2cd75eede");
pub const TAG_REGISTER: [u8; 32] = hex32("69562a9cd615eb3d906cb1934ad56c788c30228d2faf7c517e33d65b4a03c088");
pub const TAG_DISCLOSE_SENDER: [u8; 32] = hex32("868cc07c6ac389251ad6573f65fe35ee4dad66ee305f90c711af904bf5ceef3f");
pub const TAG_DISCLOSE_RECEIVER: [u8; 32] = hex32("d8356cfbd875acb80fe8a8127a57b5c549d20fd65b9acca8672186a1a4296456");
pub const TAG_DISCLOSE_AUDITOR: [u8; 32] = hex32("d6019aa47e04fe91c11df386ddc5bda2178a3f2506c46cdd59b16ef1d21daf81");

/// the opTags an op accepts: REFRESH shares op 2 with BURN, AUDITOR op 5 with DISCLOSE-RECEIVER
pub fn op_tags(op: u8) -> &'static [[u8; 32]] {
    match op {
        OP_TRANSFER => &[TAG_TRANSFER],
        OP_BURN => &[TAG_BURN, TAG_REFRESH],
        OP_REGISTER => &[TAG_REGISTER],
        OP_DISCLOSE_SENDER => &[TAG_DISCLOSE_SENDER],
        OP_DISCLOSE_RECEIVER => &[TAG_DISCLOSE_RECEIVER, TAG_DISCLOSE_AUDITOR],
        _ => &[],
    }
}

/// Proof and input limits (plan D5): per-id MAX_PROOF, and the precompile input u8(op) || be32(len(stmt)) || stmt ||
/// proof (INPUT_HEADER = 5 bytes) <= MAX_INPUT. PQZH's verifier bound is `Params::max_proof_len(op)` (the exact
/// maximum, <= PQZH_MAX_PROOF at THE preset). Moved to pqz-stmt with Task 6.
pub const PQZL_MAX_PROOF: usize = 98_304;
pub const PQZH_MAX_PROOF: usize = 262_144;
pub const MAX_INPUT: usize = 393_216;
pub const INPUT_HEADER: usize = 5;

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
        // auditorOn is the 15th header word (pq-zether.md §7.7)
        assert_eq!(HDR_AUDITOR_ON, 14 * 32);
    }

    /// D3: the id is the keccak256 of its string
    #[test]
    fn pqzh_id_d3() {
        let h = crate::merkle::keccak(&[b"scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1"]);
        assert_eq!(h, PQZH_PROOF_SYSTEM_ID);
    }

    /// the opTag constants are the keccak256 of their names
    #[test]
    fn op_tags_hash() {
        for (t, n) in [(TAG_TRANSFER, "TRANSFER"), (TAG_BURN, "BURN"), (TAG_REFRESH, "REFRESH"), (TAG_REGISTER, "REGISTER"), (TAG_DISCLOSE_SENDER, "DISCLOSE-SENDER"), (TAG_DISCLOSE_RECEIVER, "DISCLOSE-RECEIVER"), (TAG_DISCLOSE_AUDITOR, "DISCLOSE-AUDITOR")] {
            assert_eq!(t, crate::merkle::keccak(&[b"SCAAS-PQZ-OP-", n.as_bytes(), b"-V1"]), "{n}");
        }
    }

    /// D5: the largest input, a PQZH transfer with a proof at the limit, fits MAX_INPUT
    #[test]
    fn input_limit() {
        assert_eq!(INPUT_HEADER + TX_STMT + PQZH_MAX_PROOF, 345_221);
        assert!(INPUT_HEADER + TX_STMT + PQZH_MAX_PROOF.max(PQZL_MAX_PROOF) <= MAX_INPUT);
    }
}
