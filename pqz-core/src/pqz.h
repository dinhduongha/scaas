/*
 * pqz-core C ABI (pq-zether.md §8, CTR-PQZ-09), E-S1 spike subset: R_REG (OP_REGISTER), R_TX (OP_TRANSFER),
 * R_BURN (OP_BURN, also REFRESH), R_DS (OP_DISCLOSE_SENDER), R_DR (OP_DISCLOSE_RECEIVER, also AUDITOR).
 * Single-threaded; all memory comes from the arena given to pqz_init (no malloc), errors are return codes.
 */
#ifndef PQZ_H
#define PQZ_H

#include <stddef.h>
#include <stdint.h>

#define PQZ_OP_TRANSFER 1
#define PQZ_OP_BURN 2
#define PQZ_OP_REGISTER 3
#define PQZ_OP_DISCLOSE_SENDER 4
#define PQZ_OP_DISCLOSE_RECEIVER 5
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

/* R_BURN (pq-zether.md §7.5, §7.7): header (640) || pk_f || T = u_T || v_T || out = u || v_f. The relation reads
   fee (header offset 256) and amount (288), each a be32 word < 2^64; the rest of the header is only hashed. */
#define PQZ_HEADER_BYTES 640
#define PQZ_HDR_FEE 256
#define PQZ_HDR_AMOUNT 288
#define PQZ_BURN_STMT_BYTES (PQZ_HEADER_BYTES + PQZ_POLYVEC_BYTES + 2 * (PQZ_POLYVEC_BYTES + PQZ_V_BYTES))
/* R_BURN witness: s_f (int8) || e_f (int16) || r (int8) || e1 (int16) || e2_f (16 x int16) || d' (16 x u8)
   [M, carries and e_T are derived by the prover; d = digits(amount) is public] */
#define PQZ_BURN_WIT_BYTES (2048 + 4096 + 2048 + 4096 + 32 + 16)

/* Disclosure (pq-zether.md §7.9): opTag || proofSystemId || chainId || chainUid || token || registry || entryRef
   || be32(amount) || u8(kind) || pk || u || v  (32-byte words; amount < 2^64). Same layout for R_DS and R_DR. */
#define PQZ_DISC_AMOUNT (PQZ_PREFIX_BYTES + 5 * 32)
#define PQZ_DISC_PK (PQZ_DISC_AMOUNT + 32 + 1)
#define PQZ_DISC_STMT_BYTES (PQZ_DISC_PK + 2 * PQZ_POLYVEC_BYTES + PQZ_V_BYTES)
/* R_DS witness (sender): r (int8) || e1 (int16) || e2_t (16 x int16) */
#define PQZ_DS_WIT_BYTES (2048 + 4096 + 32)
/* R_DR witness (receiver or auditor): s (int8) || e (int16)   [e' is derived by the prover] */
#define PQZ_DR_WIT_BYTES (2048 + 4096)

/* arena: caller memory used for every call (long-lived caches at the bottom); returns 0 on success */
int pqz_init (void *arena, size_t arena_len);
size_t pqz_arena_peak_bytes (void);
void pqz_arena_peak_reset (void); /* diagnostics: the next pqz_arena_peak_bytes covers the calls that follow */

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
