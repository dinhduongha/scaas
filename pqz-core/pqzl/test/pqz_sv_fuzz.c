/*
 * P6-SV libFuzzer target: an input is an edit script applied to an honest proof; the generic verifier
 * (pqz_verify) and the specialised one (pqz_verify_fast) must agree on the result. Built and run by sv/fuzz.sh
 * (clang -fsanitize=fuzzer,address,undefined; the arena build, so ASan sees the library's stack and globals
 * and the arena block as a whole).
 *
 * Input: byte 0 bits 0..6 mod 5 = relation (0 R_REG, 1 R_TX, 2 R_TX0, 3 R_TXM M = 2 auditor on, 4 R_TXM M = 8
 * auditor off: two randomness groups; P6-ANON L2), bit 7 = also edit the statement; then 4-byte edits
 * [offset lo, offset mid, offset hi, value]: offset < 2^24 wraps modulo the target length, value XORed in.
 * A trailing 1-3 bytes truncate (1), extend by zeros (2) or extend by 0xff (3) the proof by their sum mod 64.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pqz.h"

#define ARENA_BYTES ((size_t)2048 << 20) /* R_TXM M = 8: more than the 768 MiB of the five P6e forms */

#define NR 5
static uint8_t reg_stmt[PQZ_REG_STMT_BYTES], tx_stmt[PQZ_TX_STMT_BYTES], tx0_stmt[PQZ_TX0_STMT_BYTES];
static uint8_t txm2_stmt[PQZ_TXM_STMT_BYTES (2, 1)], txm80_stmt[PQZ_TXM_STMT_BYTES (8, 0)];
static uint8_t proof[NR][PQZ_MAX_PROOF], bad[PQZ_MAX_PROOF + 64], st[PQZ_TXM_STMT_BYTES (8, 0)];
static size_t plen[NR];
static const uint8_t OP[NR] = { PQZ_OP_REGISTER, PQZ_OP_TRANSFER, PQZ_OP_TRANSFER, PQZ_OP_TRANSFER_MULTI,
                                PQZ_OP_TRANSFER_MULTI };
static const uint8_t *const STM[NR] = { reg_stmt, tx_stmt, tx0_stmt, txm2_stmt, txm80_stmt };
static const size_t STL[NR] = { sizeof reg_stmt, sizeof tx_stmt, sizeof tx0_stmt, sizeof txm2_stmt,
                                sizeof txm80_stmt };

/* an R_TXM zero instance as R_TX's below: every key pk, amounts and fee 0, e2 = 0, one (r, e1) for every group */
static void
setup_txm (int k, unsigned m, unsigned a, const uint8_t *pk, const int8_t *s, const int16_t *e, const int8_t *r,
           const int16_t *e1)
{
  static uint8_t wit[PQZ_TXM_WIT_BYTES (8, 1)], v[4][PQZ_V_BYTES], uT[PQZ_POLYVEC_BYTES];
  static int16_t e2[4][16];
  uint8_t mz[4][16] = { { 0 } }, r32[32] = { 0 }, win[4] = { 0, 1, 2, 3 };
  const uint8_t *pks[4] = { pk, pk, pk, pk };
  const unsigned G = PQZ_TXM_GROUPS (m, a), lpg = PQZ_TXM_LPG (a);
  uint8_t *p = (uint8_t *)STM[k];
  /* T, every u and v (window 0); the auditor copies at their windows j mod lpg (R0-1) */
  pqz_encrypt_win (pks, 4, win, (const uint8_t (*)[16])mz, r, e1, (const int16_t (*)[16])e2, uT, v);
  memset (p, 0x5A, PQZ_HEADER_BYTES);
  memset (p + PQZ_HDR_FEE, 0, 64), memset (p + PQZ_HDR_SALT, 0, 16);
  memset (p + PQZ_HDR_LEGS, 0, 32), p[PQZ_HDR_LEGS + 31] = (uint8_t)m;
  memset (p + PQZ_HDR_AUDITOR_ON, 0, 32), p[PQZ_HDR_AUDITOR_ON + 31] = (uint8_t)a;
  p += PQZ_HEADER_BYTES;
  for (unsigned j = 0; j < 1 + m + a; j++)
    memcpy (p, pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, uT, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, v[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
  for (unsigned g = 0; g < G; g++)
    memcpy (p, uT, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  for (unsigned j = 0; j < m + 1 + a * m; j++)
    memcpy (p, v[j < m + 1 ? 0 : (j - m - 1) % lpg], PQZ_V_BYTES), p += PQZ_V_BYTES;
  p = wit;
  for (int j = 0; j < PQZ_N; j++)
    p[j] = (uint8_t)s[j], p[PQZ_N + 2 * j] = (uint8_t)e[j], p[PQZ_N + 1 + 2 * j] = (uint8_t)(e[j] >> 8);
  p += (3 * PQZ_N);
  for (unsigned g = 0; g < G; g++, p += (3 * PQZ_N))
    for (int j = 0; j < PQZ_N; j++)
      p[j] = (uint8_t)r[j], p[PQZ_N + 2 * j] = (uint8_t)e1[j], p[PQZ_N + 1 + 2 * j] = (uint8_t)(e1[j] >> 8);
  memset (p, 0, 32 * (m + 1 + a * m) + 16 * (m + 1)); /* e2 = 0, digits 0 */
  plen[k] = PQZ_MAX_PROOF;
  pqz_prove (PQZ_OP_TRANSFER_MULTI, STM[k], STL[k], wit, PQZ_TXM_WIT_BYTES (m, a), r32, proof[k], &plen[k]);
}

/* deterministic statements and witnesses as test/pqz_bench.c (fixed keys from the client helpers) */
static void
setup (void)
{
  static int8_t s[PQZ_N], r[PQZ_N];
  static int16_t e[PQZ_N], e1[PQZ_N], e2[3][16];
  static uint8_t pk[PQZ_POLYVEC_BYTES], u[PQZ_POLYVEC_BYTES], vs[3][PQZ_V_BYTES];
  static uint8_t reg_wit[PQZ_REG_WIT_BYTES], tx_wit[PQZ_TX_WIT_BYTES], tx0_wit[PQZ_TX0_WIT_BYTES];
  uint8_t m[3][16] = { { 0 } }, r32[32] = { 0 };
  for (int j = 0; j < PQZ_N; j++)
    s[j] = (int8_t)(j % 3 ? 0 : (j / 3) & 1 ? 1 : -1), r[j] = (int8_t)(j % 3 != 1 ? 0 : (j / 3) & 1 ? -1 : 1),
    e[j] = (int16_t)(j % 5 - 2), e1[j] = (int16_t)(j % 7 - 3); /* within the l2 bounds 38 / 173 */
  pqz_keypair_from_secret (s, e, pk);
  memset (reg_stmt, 0xA5, PQZ_PREFIX_BYTES);
  memcpy (reg_stmt + PQZ_PREFIX_BYTES + 32, pk, PQZ_POLYVEC_BYTES);
  for (int j = 0; j < PQZ_N; j++)
    reg_wit[j] = (uint8_t)s[j], reg_wit[PQZ_N + 2 * j] = (uint8_t)e[j], reg_wit[PQZ_N + 1 + 2 * j] = (uint8_t)(e[j] >> 8);
  plen[0] = PQZ_MAX_PROOF;
  pqz_prove (PQZ_OP_REGISTER, reg_stmt, sizeof reg_stmt, reg_wit, sizeof reg_wit, r32, proof[0], &plen[0]);

  /* R_TX: zero balance moved from and to the same key (amounts 0, fee 0), as an honest relation instance */
  const uint8_t *pks[3] = { pk, pk, pk };
  static uint8_t uT[PQZ_POLYVEC_BYTES], vT[1][PQZ_V_BYTES];
  pqz_encrypt (pks, 1, (const uint8_t (*)[16])m, r, e1, (const int16_t (*)[16])e2, uT, vT);
  pqz_encrypt (pks, 3, (const uint8_t (*)[16])m, r, e1, (const int16_t (*)[16])e2, u, vs);
  uint8_t *p = tx_stmt;
  memset (p, 0x5A, PQZ_HEADER_BYTES); /* pq-zero-knowledge.md §7.7 header; fee and amount words 0, auditorOn 1 (P6e R6) */
  memset (p + PQZ_HDR_FEE, 0, 64), memset (p + PQZ_HDR_AUDITOR_ON, 0, 32), p[PQZ_HDR_AUDITOR_ON + 31] = 1;
  memset (p + PQZ_HDR_SALT, 0, 16), memset (p + PQZ_HDR_RECIPIENT, 0, 32); /* canonical (P6e D15) */
  p += PQZ_HEADER_BYTES;
  for (int k = 0; k < 3; k++)
    memcpy (p, pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, uT, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, vT[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
  memcpy (p, u, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  for (int k = 0; k < 3; k++)
    memcpy (p, vs[k], PQZ_V_BYTES), p += PQZ_V_BYTES;
  p = tx_wit;
  for (int j = 0; j < PQZ_N; j++)
    p[j] = (uint8_t)s[j], p[PQZ_N + 2 * j] = (uint8_t)e[j], p[PQZ_N + 1 + 2 * j] = (uint8_t)(e[j] >> 8);
  p += (3 * PQZ_N);
  for (int j = 0; j < PQZ_N; j++)
    p[j] = (uint8_t)r[j], p[PQZ_N + 2 * j] = (uint8_t)e1[j], p[PQZ_N + 1 + 2 * j] = (uint8_t)(e1[j] >> 8);
  p += (3 * PQZ_N);
  memset (p, 0, 96 + 32); /* e2 = 0, digits d = d' = 0 */
  plen[1] = PQZ_MAX_PROOF;
  pqz_prove (PQZ_OP_TRANSFER, tx_stmt, sizeof tx_stmt, tx_wit, sizeof tx_wit, r32, proof[1], &plen[1]);

  /* R_TX0: the same instance without pk_a / v_a / e2_a, auditorOn 0 */
  memcpy (tx0_stmt, tx_stmt, PQZ_HEADER_BYTES), tx0_stmt[PQZ_HDR_AUDITOR_ON + 31] = 0;
  memcpy (tx0_stmt + PQZ_HEADER_BYTES, tx_stmt + PQZ_HEADER_BYTES, 2 * PQZ_POLYVEC_BYTES); /* pk_f, pk_t */
  memcpy (tx0_stmt + PQZ_HEADER_BYTES + 2 * PQZ_POLYVEC_BYTES, tx_stmt + PQZ_HEADER_BYTES + 3 * PQZ_POLYVEC_BYTES,
          PQZ_TX0_STMT_BYTES - PQZ_HEADER_BYTES - 2 * PQZ_POLYVEC_BYTES); /* T, u, v_t, v_f (v_a dropped) */
  memcpy (tx0_wit, tx_wit, (6 * PQZ_N) + 64), memset (tx0_wit + (6 * PQZ_N) + 64, 0, 32);
  plen[2] = PQZ_MAX_PROOF;
  pqz_prove (PQZ_OP_TRANSFER, tx0_stmt, sizeof tx0_stmt, tx0_wit, sizeof tx0_wit, r32, proof[2], &plen[2]);

  setup_txm (3, 2, 1, pk, s, e, r, e1);
  setup_txm (4, 8, 0, pk, s, e, r, e1);
}

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void)argc, (void)argv;
  if (pqz_init (malloc (ARENA_BYTES), ARENA_BYTES) != 0)
    abort ();
  setup ();
  for (int r = 0; r < NR; r++)
    if (pqz_verify (OP[r], STM[r], STL[r], proof[r], plen[r]) != 1
        || pqz_verify_fast (OP[r], STM[r], STL[r], proof[r], plen[r]) != 1)
      abort (); /* the honest instances must verify */
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;
  const int rel = (data[0] & 0x7f) % NR, est = data[0] >> 7;
  const uint8_t op = OP[rel];
  const size_t stlen = STL[rel];
  size_t len = plen[rel], i = 1;
  memcpy (bad, proof[rel], len);
  memcpy (st, STM[rel], stlen);
  for (; i + 4 <= size; i += 4)
    {
      const size_t off = data[i] | (data[i + 1] << 8) | ((size_t)data[i + 2] << 16);
      if (est && (data[i + 2] & 0x80))
        st[off % stlen] ^= data[i + 3];
      else
        bad[off % len] ^= data[i + 3];
    }
  if (i < size)
    {
      const size_t n = (data[i] + (i + 1 < size ? data[i + 1] : 0)) % 64;
      const int how = (int)(size - i);
      if (how == 1)
        len = n < len ? len - n : len;
      else
        memset (bad + len, how == 2 ? 0 : 0xff, n), len += n;
    }
  if (pqz_verify (op, st, stlen, bad, len) != pqz_verify_fast (op, st, stlen, bad, len))
    abort ();
  return 0;
}
