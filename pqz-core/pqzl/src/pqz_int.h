/*
 * pqz-core internals shared by pqz_rel.c (statements, prover, generic verifier) and pqz_sv.c (specialised
 * verifier). Not part of the C ABI.
 */
#ifndef PQZ_INT_H
#define PQZ_INT_H

#include "lazer.h"

/* internal relation code of R_TX0 (op 1 with the 66,560-byte statement), where pqz_rel.c and pqz_sv.c name a relation
   by its op, and the tag byte of R_TX0's ABDLOP keys (SCAAS-PQZ-ABDLOP-PP-V1 || 0x81); never an op on the wire (the
   transcript hashes op 1) */
#define PQZ_REL_TX0 0x81
/* internal relation codes of R_TXM (op 7, P6-ANON), one per (M, auditorOn): 0x70 | A << 3 | log2(M), e.g. M = 8 with
   the auditor 0x7b; the tag byte of the shape's own ABDLOP keys, never on the wire (the transcript hashes op 7) */
#define PQZ_REL_TXM(log2m, aud) ((uint8_t)(0x70 | ((aud) << 3) | (log2m)))
#define PQZ_REL_IS_TXM(code) (((code) & 0xf0) == 0x70)
#define PQZ_REL_TXM_LEGS(code) (1u << ((code) & 7))
#define PQZ_REL_TXM_AUD(code) (((code) >> 3) & 1u)

/* statement digest: SHAKE128("SCAAS-PQZ-TRANSCRIPT-V1" || op || be32(len) || stmt) */
void pqz_stmt_hash (uint8_t h[32], uint8_t op, const uint8_t *stmt, size_t len);

/* the bounded proof decoder (LaZer lin-proofs.c's lnp_tbox_decproof); 1 = well formed, exactly len bytes */
int pqz_decproof (size_t len, const uint8_t *in, polyvec_t tA1, polyvec_t tB, polyvec_t h, poly_t c,
                  polyvec_t z1, polyvec_t z21, polyvec_t hint, polyvec_t z3, polyvec_t z4,
                  const lnp_tbox_params_t params);

/* pqz_sv.c (builds with PQZ_SV): per-relation tables (rel = the op, or PQZ_REL_TX0), built at the relation's first
   pqz_verify_fast (PQZ_OK at once if built; the caller moves the arena base mark above them), the verify body (called
   by pqz_verify_fast with the arena released to the base mark; hash is the statement digest under the real op), and
   the reset at pqz_init (the arena they lived in is gone) */
void pqz_sv_reset (void);
int pqz_sv_setup (uint8_t rel, const lnp_tbox_params_struct *P, polymat_t A, polymat_t A1, polymat_t A2p,
                  polymat_t Bp);
int pqz_sv_verify (uint8_t rel, const uint8_t hash[32], const uint8_t *stmt, size_t stmt_len,
                   const uint8_t *proof, size_t proof_len);

#endif
