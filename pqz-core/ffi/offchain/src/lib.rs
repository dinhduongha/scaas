// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `pqz-offchain`: the off-chain verifier's entry (three-key spec K3-4; UNAUDITED). See `Cargo.toml` for why it is a
//! crate of its own.

use std::panic::catch_unwind;

use pqz_ffi::stmt::PQZL_SPLIT_ID;
use pqz_ffi::{decode, pqzh, pqzl, NodeFault, PQZH_ID, PQZL_ID};

/// [`pqz_ffi::verify_input`] plus PQZL_SPLIT_ID, whose split transfers (R_TXS / R_TXS0, opening tokens) are OFFCHAIN
/// only and never served by the precompile. Same input `u8(op) ‖ be32(len(stmt)) ‖ stmt ‖ proof`, same decode
/// (`pqz_stmt::decode_input`, which ties the split forms to PQZL_SPLIT_ID and the others to their ids), same verifiers:
/// PQZL_ID and PQZL_SPLIT_ID to the specialised PQZL verifier, PQZH_ID to Ligero. `Ok(true)` only for a canonical input
/// whose proof verifies; anything undecodable, op 6 or an unknown id is `Ok(false)`; a fault of this node is
/// `Err(NodeFault)`, never an invalid input. A panic in the decode / verify logic (input-caused) is caught: `Ok(false)`.
pub fn verify_offchain(input: &[u8]) -> Result<bool, NodeFault> {
    catch_unwind(|| {
        let Ok(inp) = decode(input) else {
            return Ok(false);
        };
        match inp.stmt.proof_system_id() {
            Some(id) if *id == PQZL_ID || *id == PQZL_SPLIT_ID => {
                pqzl::verify_fast(inp.op, inp.stmt_bytes, inp.proof)
            }
            Some(id) if *id == PQZH_ID => pqzh::verify(inp.op, inp.stmt_bytes, inp.proof),
            _ => Ok(false),
        }
    })
    .unwrap_or(Ok(false))
}
