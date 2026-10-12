/*
 * pqz-core C ABI (pq-zether.md §8, CTR-PQZ-09), E-S1 spike subset: R_REG (OP_REGISTER) and R_TX (OP_TRANSFER).
 * Single-threaded; all memory comes from the arena given to pqz_init (no malloc), errors are return codes.
 */
#ifndef PQZ_H
#define PQZ_H

#include <stddef.h>
#include <stdint.h>

#define PQZ_OP_TRANSFER 1
#define PQZ_OP_REGISTER 3
#define PQZ_MAX_PROOF 98304 /* MAX_PROOF (pq-zether.md §8) */

#define PQZ_POLYVEC_BYTES 16384 /* 32 polys x 64 coeffs x be8 */
#define PQZ_V_BYTES 128         /* 16 coeffs x be8 */
#define PQZ_PREFIX_BYTES 64     /* opTag || proofSystemId */

/* R_REG: prefix || message (32) || pk */
#define PQZ_REG_STMT_BYTES (PQZ_PREFIX_BYTES + 32 + PQZ_POLYVEC_BYTES)
/* R_REG witness: s (2048 x int8) || e (2048 x int16 LE) */
#define PQZ_REG_WIT_BYTES (2048 + 4096)

/* R_TX (spike): prefix || pk_f || pk_t || pk_a || T = u_T || v_T || out = u || v_t || v_f || v_a || be8(fee) */
#define PQZ_TX_STMT_BYTES                                                                                   \
  (PQZ_PREFIX_BYTES + 3 * PQZ_POLYVEC_BYTES + (PQZ_POLYVEC_BYTES + PQZ_V_BYTES)                            \
   + (PQZ_POLYVEC_BYTES + 3 * PQZ_V_BYTES) + 8)
/* R_TX witness: s_f (int8) || e_f (int16) || r (int8) || e1 (int16) || e2_t, e2_f, e2_a (16 x int16 each)
   || d (16 x u8) || d' (16 x u8)   [M, carries and e_T are derived by the prover] */
#define PQZ_TX_WIT_BYTES (2048 + 4096 + 2048 + 4096 + 3 * 32 + 16 + 16)

/* arena: caller memory used for every call (long-lived caches at the bottom); returns 0 on success */
int pqz_init (void *arena, size_t arena_len);
size_t pqz_arena_peak_bytes (void);

int pqz_prove (uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *wit, size_t wit_len,
               const uint8_t rnd32[32], uint8_t *proof, size_t *proof_len); /* 0 = ok */
int pqz_verify (uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *proof,
                size_t proof_len); /* 1 = valid, 0 = anything else */

/* helpers for tests and clients: the public matrix A (spec CTR-PQZ-03) applied to short vectors */
int pqz_keypair_from_secret (const int8_t s[2048], const int16_t e[2048], uint8_t pk[PQZ_POLYVEC_BYTES]);
int pqz_encrypt (const uint8_t *const pks[], unsigned int npk, const uint8_t msgs[][16], const int8_t r[2048],
                 const int16_t e1[2048], const int16_t e2[][16], uint8_t u[PQZ_POLYVEC_BYTES],
                 uint8_t vs[][PQZ_V_BYTES]);
int pqz_decrypt_raw (const int8_t s[2048], const uint8_t u[PQZ_POLYVEC_BYTES], const uint8_t v[PQZ_V_BYTES],
                     int64_t w[16]); /* w_i = centre(v_i - (u^T s)_i) */

#endif
