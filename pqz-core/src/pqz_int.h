/*
 * pqz-core internals shared by pqz_rel.c (statements, prover, generic verifier) and pqz_sv.c (specialised
 * verifier). Not part of the C ABI.
 */
#ifndef PQZ_INT_H
#define PQZ_INT_H

#include "lazer.h"

/* statement digest: SHAKE128("SCAAS-PQZ-TRANSCRIPT-V1" || op || be32(len) || stmt) */
void pqz_stmt_hash (uint8_t h[32], uint8_t op, const uint8_t *stmt, size_t len);

/* the bounded proof decoder (LaZer lin-proofs.c's lnp_tbox_decproof); 1 = well formed, exactly len bytes */
int pqz_decproof (size_t len, const uint8_t *in, polyvec_t tA1, polyvec_t tB, polyvec_t h, poly_t c,
                  polyvec_t z1, polyvec_t z21, polyvec_t hint, polyvec_t z3, polyvec_t z4,
                  const lnp_tbox_params_t params);

/* pqz_sv.c: per-relation precomputation at pqz_init (below the arena base mark) and the verify body
   (called by pqz_verify_fast with the arena released to the base mark) */
int pqz_sv_setup (uint8_t op, const lnp_tbox_params_struct *P, polymat_t A, polymat_t A1, polymat_t A2p,
                  polymat_t Bp);
int pqz_sv_verify (uint8_t op, const uint8_t hash[32], const uint8_t *stmt, size_t stmt_len,
                   const uint8_t *proof, size_t proof_len);

#endif
