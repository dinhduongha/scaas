/*
 * pqz-core C ABI (pq-zether.md §8, CTR-PQZ-09): R_REG (OP_REGISTER), R_TX and R_TX0 (OP_TRANSFER, auditor on / off,
 * told apart by the statement length), R_BURN (OP_BURN, also REFRESH), R_DS (OP_DISCLOSE_SENDER), R_DR
 * (OP_DISCLOSE_RECEIVER, also AUDITOR).
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
/* proofSystemId (statement bytes 32..63) = keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2") (pq-zether.md §8,
   CTR-PQZ-09). pqz-core only hashes it; the precompile accepts only ids it implements. v2 (was .../v1): the LaZer tbox
   Schwartz-Zippel fixes P6-SZ / P6-L2 (lazer/lnp-tbox.c; lazer-crypto/lazer issues 24, 25) change the transcript. */
#define PQZ_PROOF_SYSTEM_ID                                                                                 \
  { 0x2e, 0x07, 0xe6, 0xed, 0x1f, 0xd3, 0x03, 0xa0, 0x8c, 0x89, 0xb3, 0xea, 0xb6, 0xe8, 0x42, 0x3f,  \
    0xdf, 0xb8, 0xf3, 0x12, 0x02, 0x95, 0x8d, 0xd6, 0x82, 0xa0, 0x61, 0x93, 0x13, 0x79, 0x8c, 0x2f }

/* R_REG: prefix || message (32) || pk */
#define PQZ_REG_STMT_BYTES (PQZ_PREFIX_BYTES + 32 + PQZ_POLYVEC_BYTES)
/* R_REG witness: s (2048 x int8) || e (2048 x int16 LE) */
#define PQZ_REG_WIT_BYTES (2048 + 4096)

/* Debit statements (pq-zether.md §7.7): header (640 B of 32-byte words) || body. The relations read fee (header
   offset 256) and, for R_BURN, amount (288), each a be32 word that must be < 2^64; the rest of the header is only
   hashed (opTag, proofSystemId: the precompile checks them, §9.1). */
#define PQZ_HEADER_BYTES 640
#define PQZ_HDR_FEE 256
#define PQZ_HDR_AMOUNT 288
/* auditorOn word (§7.7 offset 448; CTR-PQZ-24): op 1 is R_TX with an 83,072-byte statement, which requires the word
   = 1, and R_TX0 with a 66,560-byte one, which requires 0; anything else is rejected (P6e plan R6) */
#define PQZ_HDR_AUDITOR_ON 448
/* R_TX (auditor on): header || pk_f || pk_t || pk_a || T = u_T || v_T || out = u || v_t || v_f || v_a */
#define PQZ_TX_STMT_BYTES                                                                                   \
  (PQZ_HEADER_BYTES + 3 * PQZ_POLYVEC_BYTES + (PQZ_POLYVEC_BYTES + PQZ_V_BYTES)                            \
   + (PQZ_POLYVEC_BYTES + 3 * PQZ_V_BYTES))
/* R_TX witness: s_f (int8) || e_f (int16) || r (int8) || e1 (int16) || e2_t, e2_f, e2_a (16 x int16 each)
   || d (16 x u8) || d' (16 x u8)   [M, carries and e_T are derived by the prover] */
#define PQZ_TX_WIT_BYTES (2048 + 4096 + 2048 + 4096 + 3 * 32 + 16 + 16)

/* R_TX0 (auditor off, CTR-PQZ-24: no pk_a / v_a, row 5 skipped; P6e D8): header || pk_f || pk_t || T = u_T || v_T
   || out = u || v_t || v_f */
#define PQZ_TX0_STMT_BYTES                                                                                  \
  (PQZ_HEADER_BYTES + 2 * PQZ_POLYVEC_BYTES + (PQZ_POLYVEC_BYTES + PQZ_V_BYTES)                            \
   + (PQZ_POLYVEC_BYTES + 2 * PQZ_V_BYTES))
/* R_TX0 witness: s_f (int8) || e_f (int16) || r (int8) || e1 (int16) || e2_t, e2_f (16 x int16 each) || d (16 x u8)
   || d' (16 x u8) */
#define PQZ_TX0_WIT_BYTES (2048 + 4096 + 2048 + 4096 + 2 * 32 + 16 + 16)

/* R_BURN (§7.5): header || pk_f || T = u_T || v_T || out = u || v_f */
#define PQZ_BURN_STMT_BYTES (PQZ_HEADER_BYTES + PQZ_POLYVEC_BYTES + 2 * (PQZ_POLYVEC_BYTES + PQZ_V_BYTES))
/* R_BURN witness: s_f (int8) || e_f (int16) || r (int8) || e1 (int16) || e2_f (16 x int16) || d' (16 x u8)
   [M, carries and e_T are derived by the prover; d = digits(amount) is public] */
#define PQZ_BURN_WIT_BYTES (2048 + 4096 + 2048 + 4096 + 32 + 16)

/* Disclosure (pq-zether.md §7.9): opTag || proofSystemId || chainId || chainUid || token || registry || entryRef
   || amount || kind || pk || u || v, every scalar a 32-byte word (amount < 2^64; kind is hashed only), so pk starts
   at 288. Same layout for R_DS and R_DR; 33,184 B. */
#define PQZ_DISC_AMOUNT (PQZ_PREFIX_BYTES + 5 * 32)
#define PQZ_DISC_KIND (PQZ_DISC_AMOUNT + 32)
#define PQZ_DISC_PK (PQZ_DISC_KIND + 32)
#define PQZ_DISC_STMT_BYTES (PQZ_DISC_PK + 2 * PQZ_POLYVEC_BYTES + PQZ_V_BYTES)
/* R_DS witness (sender): r (int8) || e1 (int16) || e2_t (16 x int16) */
#define PQZ_DS_WIT_BYTES (2048 + 4096 + 32)
/* R_DR witness (receiver or auditor): s (int8) || e (int16)   [e' is derived by the prover] */
#define PQZ_DR_WIT_BYTES (2048 + 4096)

/* arena: caller memory used for every call (long-lived caches at the bottom); returns 0 on success */
int pqz_init (void *arena, size_t arena_len);
size_t pqz_arena_peak_bytes (void);
void pqz_arena_peak_reset (void); /* diagnostics: the next pqz_arena_peak_bytes covers the calls that follow */

/* rnd32: 32 bytes of CSPRNG output. The masks are hedged (CTR-PQZ-19): derived from rnd32, a hash of the witness and
   the statement digest, so a repeated rnd32 never repeats masks across witnesses or statements; equal inputs give
   equal proofs (deterministic, the KATs fix rnd32) */
int pqz_prove (uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *wit, size_t wit_len,
               const uint8_t rnd32[32], uint8_t *proof, size_t *proof_len); /* 0 = ok */
int pqz_verify (uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *proof,
                size_t proof_len); /* 1 = valid, 0 = anything else */
/* specialised verifier for the same statements (pqz_sv.c): accepts exactly the proofs pqz_verify accepts, by
   evaluating the relation's equations directly; pqz_verify stays the reference. Its tables for an op are built at
   the op's first call. Only in builds with PQZ_SV (build.sh default; SV=0 leaves it out, e.g. a wallet's prover). */
int pqz_verify_fast (uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *proof, size_t proof_len);

/* helpers for tests and clients: the public matrix A (spec CTR-PQZ-03) applied to short vectors */
int pqz_keypair_from_secret (const int8_t s[2048], const int16_t e[2048], uint8_t pk[PQZ_POLYVEC_BYTES]);
int pqz_encrypt (const uint8_t *const pks[], unsigned int npk, const uint8_t msgs[][16], const int8_t r[2048],
                 const int16_t e1[2048], const int16_t e2[][16], uint8_t u[PQZ_POLYVEC_BYTES],
                 uint8_t vs[][PQZ_V_BYTES]);
int pqz_decrypt_raw (const int8_t s[2048], const uint8_t u[PQZ_POLYVEC_BYTES], const uint8_t v[PQZ_V_BYTES],
                     int64_t w[16]); /* w_i = centre(v_i - (u^T s)_i) */

/* keys and encryption from seeds (pq-zether.md §4.2, pqz_keys.c). 0 = ok; PQZ_ERR_INTERNAL (1) before pqz_init (as the
   three helpers above); PQZ_ERR_REJECT (4) after 64 counters (never in practice: the thresholds sit >= 10 s.d. above the mean norms), PQZ_ERR_INPUT (3) on a pk or
   ciphertext coefficient >= q or a digit > 15. ctr_used (may be NULL): the counter of the accepted attempt.
   KeyGen: SHAKE256("SCAAS-PQZ-KEYGEN-V1" || seed32 || be4(ctr)), s <- CBD_1, e <- CBD_20, pk = A s + e. */
int pqz_keygen (const uint8_t seed32[32], uint8_t pk[PQZ_POLYVEC_BYTES], int8_t s[2048], int16_t e[2048],
                unsigned *ctr_used);
/* Enc: SHAKE256("SCAAS-PQZ-ENC-V1" || seed_enc || be4(ctr)), r <- CBD_1, e1 <- CBD_20, e2_j <- CBD_20^16 in recipient
   order; u = A^T r + e1, v_j = pk_j^T r + e2_j + Delta m_j (msgs: 16 digits < 16 per recipient) */
int pqz_enc_seed (const uint8_t *const pks[], unsigned int npk, const uint8_t msgs[][16], const uint8_t seed_enc[32],
                  uint8_t u[PQZ_POLYVEC_BYTES], uint8_t vs[][PQZ_V_BYTES], int8_t r[2048], int16_t e1[2048],
                  int16_t e2[][16], unsigned *ctr_used);
/* Dec of ct = u || v: M_i = round(w_i / Delta), noise_i = w_i - Delta M_i; value = sum M_i 16^i (the caller's) */
int pqz_dec (const int8_t s[2048], const uint8_t ct[PQZ_POLYVEC_BYTES + PQZ_V_BYTES], int64_t M[16],
             int64_t noise[16]);

#endif
