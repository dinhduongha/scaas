/*
 * pqz-core C ABI (pq-zero-knowledge.md §8, CTR-PQZ-09): R_REG (OP_REGISTER), R_TX and R_TX0 (OP_TRANSFER, auditor on / off,
 * told apart by the statement length), R_BURN (OP_BURN, also REFRESH), R_DS (OP_DISCLOSE_SENDER), R_DR
 * (OP_DISCLOSE_RECEIVER, also AUDITOR), R_TXM (OP_TRANSFER_MULTI, op 7: M legs, P6-ANON).
 * Single-threaded; all memory comes from the arena given to pqz_init (no malloc), errors are return codes. An arena
 * too small for an allocation inside LaZer (A, a relation's keys, the prover, the generic verifier) stops the process
 * (a trap: no write may follow a failed allocation, review round 2 Q-C); the specialised verifier's own allocations
 * return PQZ_ERR_ARENA (2). Secret-holding calls (pqz_prove, keygen / enc / dec) zero the arena they used (Q-B).
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
#define PQZ_MAX_PROOF 98304 /* MAX_PROOF (pq-zero-knowledge.md §8) */

/* The parameter set (owner 2026-10-21: one directory per set, chosen at compile time, one set per library build;
   PQZ_SET=<set> ./build.sh native | wasm, <set> a directory name such as n2304-kmax4096): params/sets/<set>/pqz_set.h
   gives n = PQZ_N = k d (k = PQZ_K polys of d = 64), q, Delta, K_MAX, the norm bounds and the bit widths
   (n2304-kmax4096: n 2304, q = 61,275,424,977,257, M_i 16, carries 13, e_T 27 bits; n2048-kmax1024: n 2048,
   q = 2^42 - 215, 14 / 11 / 25). */
#include "pqz_set.h"
#define PQZ_EOFF ((int64_t)1 << (PQZ_EBITS - 1)) /* e_T + E, e' + E in EBITS bits */
/* debit bit layout after the legs' digits d_j (64 bits each): d' at 0, M_i at PQZ_BITS_M + MBITS i, c_i + 64 at
   PQZ_BITS_C + CBITS i, e_T,i + E at PQZ_BITS_E + EBITS i; R_BURN (no leg) has PQZ_BITS_BURN bits (n2048-kmax1024 853, n2304-kmax4096 947), a
   debit with M legs PQZ_BITS_BURN + 64 M */
#define PQZ_BITS_M 64
#define PQZ_BITS_C (PQZ_BITS_M + 16 * PQZ_MBITS)
#define PQZ_BITS_E (PQZ_BITS_C + 15 * PQZ_CBITS)
#define PQZ_BITS_BURN (PQZ_BITS_E + 16 * PQZ_EBITS)
#define PQZ_POLYVEC_BYTES (PQZ_K * 512) /* k polys x 64 coeffs x be8 */
#define PQZ_V_BYTES 128         /* 16 coeffs x be8 */
#define PQZ_PREFIX_BYTES 64     /* opTag || proofSystemId */
/* proofSystemId (statement bytes 32..63): PQZ_PROOF_SYSTEM_ID of the set's pqz_set.h, keccak256 of its set.toml label
   pqzl_id (gen_set.py; plan 5h Task 8d: one id per set, ".../mlwe-d64k<k>-q<log2q>l4/v4", CTR-PQZ-09). pqz-core only
   hashes it; the precompile accepts only ids it implements. v4: B-1 / A-2 / R_REG (plan 5h Task 8a) and the set's
   parameters; v3 (retired): the Fiat-Shamir transcript absorbs z3, z4 before V3 / V4 and h before mu and the final
   challenge (P6-FS, lazer#28); v2 (retired, forgeable): the LaZer tbox Schwartz-Zippel fixes (lazer#24, #25). */

/* R_REG: prefix || message (32) || pk */
#define PQZ_REG_STMT_BYTES (PQZ_PREFIX_BYTES + 32 + PQZ_POLYVEC_BYTES)
/* R_REG witness: s (n x int8) || e (n x int16 LE) */
#define PQZ_REG_WIT_BYTES (3 * PQZ_N)

/* Debit statements (pq-zero-knowledge.md §7.7): header (640 B of 32-byte words) || body. The relations read fee (header
   offset 256) and, for R_BURN, amount (288), each a be32 word that must be < 2^64; the rest of the header is only
   hashed (opTag, proofSystemId: the precompile checks them, §9.1). */
#define PQZ_HEADER_BYTES 640
#define PQZ_HDR_FEE 256
#define PQZ_HDR_AMOUNT 288
/* salt word (§7.7 offset 576, CTR-PQZ-19): 16 zero bytes || salt; pqz-core only hashes it, the precompile decoder
   (pqz-stmt, P6e D15) rejects any other form */
#define PQZ_HDR_SALT 576
/* further header words the decoder pins to 0 (pq-zero-knowledge.md §7.7 / §7.5, P6e D15): toUA on BURN / REFRESH, recipient
   on transfers and REFRESH (amount: transfers and REFRESH); auditorOn and the whole salt word on BURN / REFRESH */
#define PQZ_HDR_TO_UA 192
#define PQZ_HDR_RECIPIENT 320
/* auditorOn word (§7.7 offset 448; CTR-PQZ-24): op 1 is R_TX with a 93,312-byte statement, which requires the word
   = 1, and R_TX0 with a 74,752-byte one (n2304-kmax4096; n2048-kmax1024: 83,072 / 66,560), which requires 0; anything else is rejected (P6e plan R6) */
#define PQZ_HDR_AUDITOR_ON 448
/* R_TX (auditor on): header || pk_f || pk_t || pk_a || T = u_T || v_T || out = u || v_t || v_f || v_a */
#define PQZ_TX_STMT_BYTES                                                                                   \
  (PQZ_HEADER_BYTES + 3 * PQZ_POLYVEC_BYTES + (PQZ_POLYVEC_BYTES + PQZ_V_BYTES)                            \
   + (PQZ_POLYVEC_BYTES + 3 * PQZ_V_BYTES))
/* R_TX witness: s_f (int8) || e_f (int16) || r (int8) || e1 (int16) || e2_t, e2_f, e2_a (16 x int16 each)
   || d (16 x u8) || d' (16 x u8)   [M, carries and e_T are derived by the prover] */
#define PQZ_TX_WIT_BYTES (6 * PQZ_N + 3 * 32 + 16 + 16)

/* R_TX0 (auditor off, CTR-PQZ-24: no pk_a / v_a, row 5 skipped; P6e D8): header || pk_f || pk_t || T = u_T || v_T
   || out = u || v_t || v_f */
#define PQZ_TX0_STMT_BYTES                                                                                  \
  (PQZ_HEADER_BYTES + 2 * PQZ_POLYVEC_BYTES + (PQZ_POLYVEC_BYTES + PQZ_V_BYTES)                            \
   + (PQZ_POLYVEC_BYTES + 2 * PQZ_V_BYTES))
/* R_TX0 witness: s_f (int8) || e_f (int16) || r (int8) || e1 (int16) || e2_t, e2_f (16 x int16 each) || d (16 x u8)
   || d' (16 x u8) */
#define PQZ_TX0_WIT_BYTES (6 * PQZ_N + 2 * 32 + 16 + 16)

/* R_TXM (op 7, OP_TRANSFER_MULTI; P6-ANON plan §3, §4): M legs (a decoy is a leg of amount 0), G randomness groups of
   s legs (leg j in group j / s, v_f in group 0), auditor on (A = 1, one copy v_{a,j} per leg) or off; s = PQZ_S_AUD with
   the auditor (owner 2026-10-25, R0-1: the set's pqz_set.h), 4 without, G = ceil(M / s). The auditor copy of leg j uses
   the coefficients [16 w, 16 w + 16) of pk_a^T r_g, w = j mod s (its window; R0-1 direction 2: no two copies of a
   group share a coefficient of pk_a^T r_g).
   Header: §7.7's with word 192 = recipientsHash (hashed only) and word 320 = M; the core picks the relation by the
   M word (PQZ_TXM_BUILT) and the auditorOn word (0 / 1) and requires the length PQZ_TXM_STMT_BYTES(M, A) (the length
   alone does not fix (M, A): (1, on) and (2, off) have the same length, n2304-kmax4096 93,312 B, n2048-kmax1024 83,072 B). Body: pk_f || pk_0 .. pk_{M-1} || [pk_a] ||
   T = u_T || v_T || u_0 .. u_{G-1} || v_0 .. v_{M-1} || v_f || [v_{a,0} .. v_{a,M-1}]; at M = 1 that is R_TX's /
   R_TX0's body, and the relation uses R_TX's / R_TX0's parameters with ABDLOP keys of its own. Built M: 1, 2, 4, 8;
   M = 16 only with -DPQZ_TXM_OVERSIZE (bench builds; it does not fit MAX_INPUT, plan D3 / D20). */
#define PQZ_OP_TRANSFER_MULTI 7
#define PQZ_HDR_LEGS 320 /* op 7: M (op 1's recipient word) */
#define PQZ_TXM_LPG(a) ((a) ? PQZ_S_AUD : 4) /* legs per group */
#define PQZ_TXM_GROUPS(m, a) (((m) + PQZ_TXM_LPG (a) - 1) / PQZ_TXM_LPG (a))
#ifdef PQZ_TXM_OVERSIZE
#define PQZ_TXM_MAX_LEGS 16
#else
#define PQZ_TXM_MAX_LEGS 8
#endif
#define PQZ_TXM_STMT_BYTES(m, a)                                                                            \
  (PQZ_HEADER_BYTES + (1 + (m) + (a)) * PQZ_POLYVEC_BYTES + (PQZ_POLYVEC_BYTES + PQZ_V_BYTES)               \
   + PQZ_TXM_GROUPS (m, a) * PQZ_POLYVEC_BYTES + ((m) + 1 + (a) * (m)) * PQZ_V_BYTES)
/* R_TXM witness (R_TX's layout with a group's r_g, e1_g after the previous group's, M leg noises and digit vectors):
   s_f (int8) || e_f (int16) || (r_g (int8) || e1_g (int16)) for g < G || e2_j (16 x int16) for j < M || e2_f
   || [e2_{a,j} for j < M] || d_j (16 x u8) for j < M || d' (16 x u8); at M = 1 R_TX's / R_TX0's witness */
#define PQZ_TXM_WIT_BYTES(m, a)                                                                             \
  ((1 + PQZ_TXM_GROUPS (m, a)) * 3 * PQZ_N + 32 * ((m) + 1 + (a) * (m)) + 16 * (m) + 16)

/* R_BURN (§7.5): header || pk_f || T = u_T || v_T || out = u || v_f */
#define PQZ_BURN_STMT_BYTES (PQZ_HEADER_BYTES + PQZ_POLYVEC_BYTES + 2 * (PQZ_POLYVEC_BYTES + PQZ_V_BYTES))
/* R_BURN witness: s_f (int8) || e_f (int16) || r (int8) || e1 (int16) || e2_f (16 x int16) || d' (16 x u8)
   [M, carries and e_T are derived by the prover; d = digits(amount) is public] */
#define PQZ_BURN_WIT_BYTES (6 * PQZ_N + 32 + 16)

/* Disclosure (pq-zero-knowledge.md §7.9): opTag || proofSystemId || chainId || chainUid || token || registry || entryRef
   || amount || kind || pk || u || v, every scalar a 32-byte word (amount < 2^64), so pk starts at 288. Same layout for
   R_DS and R_DR; n2304-kmax4096 37,280 B, n2048-kmax1024 33,184 B. kind = OpeningKind + 256 w (R0-1, owner 2026-10-25):
   the word must be < 2^16; w is the window of the ciphertext's v (R_DR decrypts at coefficients [16 w, 16 w + 16) of
   u^T s: an auditor copy of an R_TXM leg j has w = j mod PQZ_S_AUD), w < PQZ_S_AUD for R_DR, 0 for R_DS; the low
   byte is hashed only. */
#define PQZ_DISC_AMOUNT (PQZ_PREFIX_BYTES + 5 * 32)
#define PQZ_DISC_KIND (PQZ_DISC_AMOUNT + 32)
#define PQZ_DISC_PK (PQZ_DISC_KIND + 32)
#define PQZ_DISC_STMT_BYTES (PQZ_DISC_PK + 2 * PQZ_POLYVEC_BYTES + PQZ_V_BYTES)
/* R_DS witness (sender): r (int8) || e1 (int16) || e2_t (16 x int16) */
#define PQZ_DS_WIT_BYTES (3 * PQZ_N + 32)
/* R_DR witness (receiver or auditor): s (int8) || e (int16)   [e' is derived by the prover] */
#define PQZ_DR_WIT_BYTES (3 * PQZ_N)

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
int pqz_keypair_from_secret (const int8_t s[PQZ_N], const int16_t e[PQZ_N], uint8_t pk[PQZ_POLYVEC_BYTES]);
int pqz_encrypt (const uint8_t *const pks[], unsigned int npk, const uint8_t msgs[][16], const int8_t r[PQZ_N],
                 const int16_t e1[PQZ_N], const int16_t e2[][16], uint8_t u[PQZ_POLYVEC_BYTES],
                 uint8_t vs[][PQZ_V_BYTES]);
int pqz_decrypt_raw (const int8_t s[PQZ_N], const uint8_t u[PQZ_POLYVEC_BYTES], const uint8_t v[PQZ_V_BYTES],
                     int64_t w[16]); /* w_i = centre(v_i - (u^T s)_i) */
/* the same with windows (R0-1): recipient k's v_k uses the coefficients [16 win[k], 16 win[k] + 16) of pk_k^T r
   (win[k] < 4; NULL = all 0, pqz_encrypt), and w_i = centre(v_i - (u^T s)_{16 win + i}); PQZ_ERR_INPUT on a window >= 4 */
int pqz_encrypt_win (const uint8_t *const pks[], unsigned int npk, const uint8_t win[], const uint8_t msgs[][16],
                     const int8_t r[PQZ_N], const int16_t e1[PQZ_N], const int16_t e2[][16],
                     uint8_t u[PQZ_POLYVEC_BYTES], uint8_t vs[][PQZ_V_BYTES]);
int pqz_decrypt_raw_win (const int8_t s[PQZ_N], const uint8_t u[PQZ_POLYVEC_BYTES], const uint8_t v[PQZ_V_BYTES],
                         unsigned win, int64_t w[16]);

/* keys and encryption from seeds (pq-zero-knowledge.md §4.2, pqz_keys.c). 0 = ok; PQZ_ERR_INTERNAL (1) before pqz_init (as the
   three helpers above); PQZ_ERR_REJECT (4) after 64 counters (never in practice: the thresholds sit >= 10 s.d. above the mean norms), PQZ_ERR_INPUT (3) on a pk or
   ciphertext coefficient >= q or a digit > 15. ctr_used (may be NULL): the counter of the accepted attempt.
   KeyGen: SHAKE256("SCAAS-PQZ-KEYGEN-V2" || u8(len(set)) || set || seed32 || be4(ctr)), set = the set's name
   (PQZ_SET_NAME; review R2-C3: one seed32 gives unrelated keys at two sets), s <- CBD_1, e <- CBD_20, pk = A s + e.
   On an error exit s, e (and pk) are zeroed (review R2-C10). */
int pqz_keygen (const uint8_t seed32[32], uint8_t pk[PQZ_POLYVEC_BYTES], int8_t s[PQZ_N], int16_t e[PQZ_N],
                unsigned *ctr_used);
/* Enc: SHAKE256("SCAAS-PQZ-ENC-V1" || seed_enc || be4(ctr)), r <- CBD_1, e1 <- CBD_20, e2_j <- CBD_20^16 in recipient
   order; u = A^T r + e1, v_j = pk_j^T r + e2_j + Delta m_j (msgs: 16 digits < 16 per recipient); on an error exit the
   outputs are zeroed (R2-C10). pqz_enc_seed_win: recipient j at window win[j] as pqz_encrypt_win (R0-1) */
int pqz_enc_seed (const uint8_t *const pks[], unsigned int npk, const uint8_t msgs[][16], const uint8_t seed_enc[32],
                  uint8_t u[PQZ_POLYVEC_BYTES], uint8_t vs[][PQZ_V_BYTES], int8_t r[PQZ_N], int16_t e1[PQZ_N],
                  int16_t e2[][16], unsigned *ctr_used);
int pqz_enc_seed_win (const uint8_t *const pks[], unsigned int npk, const uint8_t win[], const uint8_t msgs[][16],
                      const uint8_t seed_enc[32], uint8_t u[PQZ_POLYVEC_BYTES], uint8_t vs[][PQZ_V_BYTES],
                      int8_t r[PQZ_N], int16_t e1[PQZ_N], int16_t e2[][16], unsigned *ctr_used);
/* R_TXM group seeds (CTR-PQZ-19 extended, P6-ANON D13): group 0 uses seed_enc itself, group g >= 1
   SHAKE256("SCAAS-PQZ-ENC-GROUP-V1" || seed_enc || be4(g))[0..32); pqz_enc_seed_win then encrypts the group's legs
   (PQZ_TXM_LPG (A) legs per group), then (group 0) pk_f, then the group's auditor copies at windows 0, 1, ... (the
   leg's position in its group), in that order. Pure hashing: no pqz_init needed. */
void pqz_enc_group_seed (const uint8_t seed_enc[32], unsigned g, uint8_t out[32]);
/* Dec of ct = u || v: M_i = round(w_i / Delta), noise_i = w_i - Delta M_i; value = sum M_i 16^i (the caller's) */
int pqz_dec (const int8_t s[PQZ_N], const uint8_t ct[PQZ_POLYVEC_BYTES + PQZ_V_BYTES], int64_t M[16],
             int64_t noise[16]);
/* the same for a v at window win < 4 (the auditor's copy of an R_TXM leg j: win = j mod PQZ_S_AUD; R0-1) */
int pqz_dec_win (const int8_t s[PQZ_N], const uint8_t ct[PQZ_POLYVEC_BYTES + PQZ_V_BYTES], unsigned win, int64_t M[16],
                 int64_t noise[16]);

#endif
