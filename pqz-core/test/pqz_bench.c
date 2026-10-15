/*
 * pqz-core test and benchmark: R_REG, R_TX, R_BURN, R_DS, R_DR, R_TX0, R_TXM prove / verify, negative cases, timing.
 * Same source for native (build/native/pqz_bench) and wasm32 (build/wasm/pqz.wasm, driven by test/run_wasm.mjs):
 * PQZ_WASM builds export the steps instead of main() and time on the JS side.
 *
 *   pqz_bench [n_prove] [n_verify] [rel] [checks]   prints JSON lines: sizes, times (ms), check results
 *   rel: bit mask, 1 = R_REG, 2 = R_TX, 4 = R_BURN, 8 = R_DS, 16 = R_DR, 32 = R_TX0 (default 63), 64 << t = R_TXM
 *   (op 7) shape TXB[t] (64 (1, on), 128 (2, on), 256 (4, on), 512 (8, on), 1024 .. 8192 the same off; with
 *   -DPQZ_TXM_OVERSIZE 16384 (16, on), 32768 (16, off)); n_verify = 0 also skips the adversarial verifies;
 *   checks = 1: the R_TXM variants and negatives (txm_check). PQZ_ARENA_MB: arena size (default 768 MiB)
 *   PQZ_VERIFY=fast (native) / step_set_fast (wasm): time pqz_verify_fast instead of pqz_verify (P6-SV; builds with
 *   PQZ_SV only, the default of build.sh)
 */
#include <stddef.h>
#include <stdint.h>

#include "pqz.h"

#ifndef PQZ_WASM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#else
void *memcpy (void *d, const void *s, size_t n);
void *memset (void *d, int c, size_t n);
#endif

#define ARENA_BYTES ((size_t)768 << 20) /* measured peaks well below (STATUS.md); native: PQZ_ARENA_MB overrides */

static uint64_t xs = 0x243F6A8885A308D3ULL;
static uint64_t
rnd (void)
{
  xs ^= xs >> 12;
  xs ^= xs << 25;
  xs ^= xs >> 27;
  return xs * 2685821657736338717ULL;
}

static int
cbd (int eta)
{
  int a = 0, b = 0;
  uint64_t r = rnd ();
  for (int i = 0; i < eta; i++)
    a += (r >> i) & 1, b += (r >> (32 + i)) & 1;
  return a - b;
}

/* short vector with l2 bound (resample as KeyGen / Enc do) */
static void
short8 (int8_t *x, unsigned n, int eta, int64_t bound)
{
  int64_t s;
  do
    {
      s = 0;
      for (unsigned i = 0; i < n; i++)
        x[i] = (int8_t)cbd (eta), s += x[i] * x[i];
    }
  while (s > bound * bound);
}

static void
short16 (int16_t *x, unsigned n, int eta, int64_t bound)
{
  int64_t s;
  do
    {
      s = 0;
      for (unsigned i = 0; i < n; i++)
        x[i] = (int16_t)cbd (eta), s += x[i] * x[i];
    }
  while (s > bound * bound);
}

static void
le16 (uint8_t *p, int16_t v)
{
  p[0] = (uint8_t)v, p[1] = (uint8_t)((uint16_t)v >> 8);
}

static void
digits (uint8_t m[16], uint64_t x)
{
  for (int i = 0; i < 16; i++)
    m[i] = (uint8_t)((x >> (4 * i)) & 15);
}

typedef struct
{
  int8_t s[2048];
  int16_t e[2048];
  uint8_t pk[PQZ_POLYVEC_BYTES];
} pqzkey_t;

static void
keygen (pqzkey_t *k)
{
  short8 (k->s, 2048, 1, 36);
  short16 (k->e, 2048, 20, 164);
  pqz_keypair_from_secret (k->s, k->e, k->pk);
}

/* ---- state shared by the steps ---- */
static pqzkey_t KF, KT, KA, KX;
static uint8_t reg_stmt[PQZ_REG_STMT_BYTES], reg_wit[PQZ_REG_WIT_BYTES];
static uint8_t tx_stmt[PQZ_TX_STMT_BYTES], tx_wit[PQZ_TX_WIT_BYTES];
static uint8_t tx0_stmt[PQZ_TX0_STMT_BYTES], tx0_wit[PQZ_TX0_WIT_BYTES];
static uint8_t burn_stmt[PQZ_BURN_STMT_BYTES], burn_wit[PQZ_BURN_WIT_BYTES];
static uint8_t ds_stmt[PQZ_DISC_STMT_BYTES], ds_wit[PQZ_DS_WIT_BYTES];
static uint8_t dr_stmt[PQZ_DISC_STMT_BYTES], dr_wit[PQZ_DR_WIT_BYTES];
static uint8_t proofs[6][PQZ_MAX_PROOF], bad[PQZ_MAX_PROOF];
static size_t lens[6];
static uint8_t rnd32[32];
static int fast; /* 1: verify with pqz_verify_fast */

static int
vfy (uint8_t op, const uint8_t *st, size_t stlen, const uint8_t *pf, size_t len)
{
#ifdef PQZ_SV
  if (fast)
    return pqz_verify_fast (op, st, stlen, pf, len);
#endif
  return pqz_verify (op, st, stlen, pf, len);
}

/* 0 ok; -1: asked for the specialised verifier in a build without it (SV=0) */
int
step_set_fast (int on)
{
#ifndef PQZ_SV
  if (on)
    return -1;
#endif
  fast = on;
  return 0;
}

/* relation index: 0 R_REG, 1 R_TX, 2 R_BURN, 3 R_DS, 4 R_DR, 5 R_TX0 (op 1, told apart from R_TX by the length),
   6 + t R_TXM shape TXB[t] (op 7; P6-ANON L1): (M, auditorOn) = (1, on), (2, on), (4, on), (8, on), (1, off), (2, off),
   (4, off), (8, off), with -DPQZ_TXM_OVERSIZE also (16, on), (16, off) */
static const struct
{
  unsigned m, a;
} TXB[] = { { 1, 1 }, { 2, 1 }, { 4, 1 }, { 8, 1 }, { 1, 0 }, { 2, 0 }, { 4, 0 }, { 8, 0 },
#ifdef PQZ_TXM_OVERSIZE
            { 16, 1 }, { 16, 0 },
#endif
};
#define NTXB (sizeof TXB / sizeof TXB[0])
#define NREL (6 + (int)NTXB)
#define TXM_ST_MAX PQZ_TXM_STMT_BYTES (PQZ_TXM_MAX_LEGS, 1)
#define TXM_WIT_MAX PQZ_TXM_WIT_BYTES (PQZ_TXM_MAX_LEGS, 1)
static uint8_t txm_stmt[NTXB][TXM_ST_MAX], txm_wit[NTXB][TXM_WIT_MAX];
static uint8_t OPS[NREL] = { PQZ_OP_REGISTER, PQZ_OP_TRANSFER, PQZ_OP_BURN, PQZ_OP_DISCLOSE_SENDER,
                             PQZ_OP_DISCLOSE_RECEIVER, PQZ_OP_TRANSFER };
static uint8_t *STMT[NREL] = { reg_stmt, tx_stmt, burn_stmt, ds_stmt, dr_stmt, tx0_stmt };
static size_t STLEN[NREL] = { sizeof reg_stmt, sizeof tx_stmt, sizeof burn_stmt, sizeof ds_stmt, sizeof dr_stmt,
                              sizeof tx0_stmt };
static const uint8_t *WIT[NREL] = { reg_wit, tx_wit, burn_wit, ds_wit, dr_wit, tx0_wit };
static size_t WLEN[NREL] = { sizeof reg_wit, sizeof tx_wit, sizeof burn_wit, sizeof ds_wit, sizeof dr_wit,
                             sizeof tx0_wit };
static unsigned SEEDMUL[NREL] = { 31, 17, 13, 11, 7, 19 };
static const uint8_t PSID[32] = PQZ_PROOF_SYSTEM_ID; /* statement bytes 32..63 */
/* tamper kind 2: first byte of a 2048-coefficient key in the statement (R_REG pk, R_TX / R_BURN / R_TXM pk_f,
   disclosure pk); kind 5: the last byte of a public scalar (R_REG message, R_TX / R_TX0 / R_TXM fee, R_BURN /
   disclosure amount) */
static size_t KEYOFF[NREL] = { PQZ_PREFIX_BYTES + 32, PQZ_HEADER_BYTES, PQZ_HEADER_BYTES, PQZ_DISC_PK, PQZ_DISC_PK,
                               PQZ_HEADER_BYTES };
static size_t SCALOFF[NREL] = { PQZ_PREFIX_BYTES + 31, PQZ_HDR_FEE + 31, PQZ_HDR_AMOUNT + 31, PQZ_DISC_AMOUNT + 31,
                                PQZ_DISC_AMOUNT + 31, PQZ_HDR_FEE + 31 };

static void
be8 (uint8_t *p, uint64_t v)
{
  for (int b = 7; b >= 0; b--)
    *p++ = (uint8_t)(v >> (8 * b));
}

static void
setup (void)
{
  keygen (&KF), keygen (&KT), keygen (&KA), keygen (&KX);

  /* R_REG: prefix || message || pk */
  memset (reg_stmt, 0xA5, PQZ_PREFIX_BYTES);
  memcpy (reg_stmt + 32, PSID, 32);
  for (int i = 0; i < 32; i++)
    reg_stmt[PQZ_PREFIX_BYTES + i] = (uint8_t)i;
  memcpy (reg_stmt + PQZ_PREFIX_BYTES + 32, KF.pk, PQZ_POLYVEC_BYTES);
  for (int j = 0; j < 2048; j++)
    reg_wit[j] = (uint8_t)KF.s[j], le16 (reg_wit + 2048 + 2 * j, KF.e[j]);

  /* R_TX: balance 1,000,000 in T (to pk_f), transfer 123,456 with fee 7 */
  const uint64_t B = 1000000, v = 123456, fee = 7, bp = B - v - fee;
  static int8_t r[2048], r0[2048];
  static int16_t e1[2048], e10[2048], e2[3][16], e20[1][16];
  static uint8_t uT[PQZ_POLYVEC_BYTES], vT[1][PQZ_V_BYTES], u[PQZ_POLYVEC_BYTES], vs[3][PQZ_V_BYTES];
  uint8_t mT[1][16], m[3][16];
  short8 (r0, 2048, 1, 36), short16 (e10, 2048, 20, 164), short16 (e20[0], 16, 20, 64);
  digits (mT[0], B);
  const uint8_t *pkf[1] = { KF.pk };
  pqz_encrypt (pkf, 1, (const uint8_t (*)[16])mT, r0, e10, (const int16_t (*)[16])e20, uT, vT);
  short8 (r, 2048, 1, 36), short16 (e1, 2048, 20, 164);
  for (int k = 0; k < 3; k++)
    short16 (e2[k], 16, 20, 64);
  digits (m[0], v), digits (m[1], bp), digits (m[2], v);
  const uint8_t *pks[3] = { KT.pk, KF.pk, KA.pk };
  pqz_encrypt (pks, 3, (const uint8_t (*)[16])m, r, e1, (const int16_t (*)[16])e2, u, vs);

  /* header (pq-zether.md §7.7): opTag, proofSystemId, then words hashed only, fee at 256, amount 0, auditorOn 1
     (P6e R6: the 83,072-byte form requires it; was hashed only before P6e Task 2) */
  uint8_t *p = tx_stmt;
  memset (p, 0x5A, PQZ_PREFIX_BYTES);
  memcpy (p + 32, PSID, 32);
  for (int i = PQZ_PREFIX_BYTES; i < PQZ_HEADER_BYTES; i++)
    p[i] = (uint8_t)(i * 3);
  memset (p + PQZ_HDR_FEE, 0, 64);
  be8 (p + PQZ_HDR_FEE + 24, fee);
  memset (p + PQZ_HDR_AUDITOR_ON, 0, 32);
  p[PQZ_HDR_AUDITOR_ON + 31] = 1;
  memset (p + PQZ_HDR_SALT, 0, 16); /* canonical salt word: 16 zero bytes || salt (P6e D15; the filler stays as salt) */
  memset (p + PQZ_HDR_RECIPIENT, 0, 32); /* recipient 0 on a transfer (§7.7, D15) */
  p += PQZ_HEADER_BYTES;
  memcpy (p, KF.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, KT.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, KA.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, uT, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, vT[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
  memcpy (p, u, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  for (int k = 0; k < 3; k++)
    memcpy (p, vs[k], PQZ_V_BYTES), p += PQZ_V_BYTES;

  p = tx_wit;
  for (int j = 0; j < 2048; j++)
    p[j] = (uint8_t)KF.s[j];
  p += 2048;
  for (int j = 0; j < 2048; j++)
    le16 (p + 2 * j, KF.e[j]);
  p += 4096;
  for (int j = 0; j < 2048; j++)
    p[j] = (uint8_t)r[j];
  p += 2048;
  for (int j = 0; j < 2048; j++)
    le16 (p + 2 * j, e1[j]);
  p += 4096;
  for (int k = 0; k < 3; k++)
    for (int j = 0; j < 16; j++)
      le16 (p + 32 * k + 2 * j, e2[k][j]);
  p += 96;
  for (int i = 0; i < 16; i++)
    p[i] = m[0][i], p[16 + i] = m[1][i];

  /* R_DS / R_DR: disclose the transfer's receiver leg (u, v_t) of amount v to pk_t; the sender re-uses r, e1,
     e2_t, the receiver proves with s_t, e_t. Header words: chainId, chainUid, token, registry, entryRef. */
  for (int k = 0; k < 2; k++)
    {
      uint8_t *st = k ? dr_stmt : ds_stmt;
      memset (st, k ? 0xD5 : 0xD4, PQZ_PREFIX_BYTES);
      memcpy (st + 32, PSID, 32);
      for (int i = PQZ_PREFIX_BYTES; i < PQZ_DISC_AMOUNT; i++)
        st[i] = (uint8_t)(i * 7);
      memset (st + PQZ_DISC_AMOUNT, 0, 64);
      be8 (st + PQZ_DISC_AMOUNT + 24, v);
      st[PQZ_DISC_KIND + 31] = (uint8_t)(k ? 1 : 0); /* kind: SENDER_S 0, RECEIVER_X 1 (AUDITOR 2) */
      memcpy (st + PQZ_DISC_PK, KT.pk, PQZ_POLYVEC_BYTES);
      memcpy (st + PQZ_DISC_PK + PQZ_POLYVEC_BYTES, u, PQZ_POLYVEC_BYTES);
      memcpy (st + PQZ_DISC_PK + 2 * PQZ_POLYVEC_BYTES, vs[0], PQZ_V_BYTES);
    }
  p = ds_wit;
  for (int j = 0; j < 2048; j++)
    p[j] = (uint8_t)r[j];
  p += 2048;
  for (int j = 0; j < 2048; j++)
    le16 (p + 2 * j, e1[j]);
  p += 4096;
  for (int j = 0; j < 16; j++)
    le16 (p + 2 * j, e2[0][j]);
  for (int j = 0; j < 2048; j++)
    dr_wit[j] = (uint8_t)KT.s[j], le16 (dr_wit + 2048 + 2 * j, KT.e[j]);

  /* R_BURN: burn 123,456 with fee 7 from the same T; fresh (r, e1, e2_f) for the new balance (pq-zether.md
     CTR-PQZ-19: burn / refresh randomness is fresh CSPRNG output, never derived from the counter; here the test RNG) */
  {
    static int8_t rb[2048];
    static int16_t e1b[2048], e2b[1][16];
    static uint8_t ub[PQZ_POLYVEC_BYTES], vb[1][PQZ_V_BYTES];
    uint8_t mb[1][16];
    short8 (rb, 2048, 1, 36), short16 (e1b, 2048, 20, 164), short16 (e2b[0], 16, 20, 64);
    digits (mb[0], bp);
    pqz_encrypt (pkf, 1, (const uint8_t (*)[16])mb, rb, e1b, (const int16_t (*)[16])e2b, ub, vb);
    p = burn_stmt;
    memset (p, 0xB2, PQZ_PREFIX_BYTES);
    memcpy (p + 32, PSID, 32);
    for (int i = PQZ_PREFIX_BYTES; i < PQZ_HEADER_BYTES; i++)
      p[i] = (uint8_t)(i * 5); /* chainId .. memoHash: hashed only */
    memset (p + PQZ_HDR_FEE, 0, 64);
    be8 (p + PQZ_HDR_FEE + 24, fee);
    be8 (p + PQZ_HDR_AMOUNT + 24, v);
    memset (p + PQZ_HDR_SALT, 0, 32); /* burn / refresh salt 0 (§7.7, CTR-PQZ-19) */
    memset (p + PQZ_HDR_TO_UA, 0, 32), memset (p + PQZ_HDR_AUDITOR_ON, 0, 32); /* toUA, auditorOn 0 (§7.7, D15) */
    p += PQZ_HEADER_BYTES;
    memcpy (p, KF.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
    memcpy (p, uT, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
    memcpy (p, vT[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
    memcpy (p, ub, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
    memcpy (p, vb[0], PQZ_V_BYTES);
    p = burn_wit;
    memcpy (p, tx_wit, 2048 + 4096), p += 2048 + 4096; /* s_f, e_f */
    for (int j = 0; j < 2048; j++)
      p[j] = (uint8_t)rb[j];
    p += 2048;
    for (int j = 0; j < 2048; j++)
      le16 (p + 2 * j, e1b[j]);
    p += 4096;
    for (int j = 0; j < 16; j++)
      le16 (p + 2 * j, e2b[0][j]);
    p += 32;
    memcpy (p, mb[0], 16);
  }

  /* R_TX0 (auditor off, CTR-PQZ-24): the R_TX transfer without pk_a and v_a (the same r, e1, e2_t, e2_f, so u, v_t,
     v_f are R_TX's), header as R_TX's with auditorOn 0; no draws from the test RNG (the other setups are unchanged) */
  memcpy (tx0_stmt, tx_stmt, PQZ_HEADER_BYTES);
  tx0_stmt[PQZ_HDR_AUDITOR_ON + 31] = 0;
  p = tx0_stmt + PQZ_HEADER_BYTES;
  memcpy (p, KF.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, KT.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, uT, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, vT[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
  memcpy (p, u, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, vs[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
  memcpy (p, vs[1], PQZ_V_BYTES);
  /* witness: s_f || e_f || r || e1 || e2_t || e2_f || d || d' (R_TX's without e2_a) */
  memcpy (tx0_wit, tx_wit, 12288 + 64);
  memcpy (tx0_wit + 12288 + 64, tx_wit + 12288 + 96, 32);
}

/* ---- R_TXM (op 7, P6-ANON L1): keys and encryption randomness from the test RNG reseeded per statement (xs saved and
   restored), so the other relations' statements and proofs are unchanged; client helpers of pqz_rel.c only (no
   pqz_keys.c, which several builds of this file do not link) ---- */
#define MAXL PQZ_TXM_MAX_LEGS
#define MAXG PQZ_TXM_GROUPS (PQZ_TXM_MAX_LEGS)
static pqzkey_t KTS, KTR[MAXL], KTA; /* sender, recipients (leg j: KTR[j]), auditor */

typedef struct
{
  unsigned m, a;
  uint64_t amount[MAXL], fee, balance;
  /* negatives: leg j is encrypted under KTR[key[j]] with group grp[j]'s randomness; add0 is added to leg 0's digit 0
     in v_0, v_{a,0} and the witness, aud0 in v_{a,0} only; big0: leg 0's e2 set to 30 in every coefficient (the
     legs' block norm over 64 sqrt(M) for M < 7); swap: the statement and witness positions 3 and 4 exchanged after
     encryption (a leg moved between groups) */
  unsigned key[MAXL], grp[MAXL], add0, aud0, big0, swap;
  uint8_t tag; /* seed tag */
} txspec_t;

static void
txspec (txspec_t *X, unsigned m, unsigned a, uint8_t tag)
{
  memset (X, 0, sizeof *X);
  X->m = m, X->a = a, X->tag = tag, X->balance = 1000000, X->fee = a ? 7 : 0; /* fee 0 allowed (owner 2026-10-14) */
  for (unsigned j = 0; j < MAXL; j++)
    X->key[j] = j, X->grp[j] = j / 4;
  X->amount[m - 1] = 123456; /* one real leg, the last; the rest decoys (amount 0) */
}

static void
wr_word (uint8_t *p, uint64_t v)
{
  memset (p, 0, 24);
  be8 (p + 24, v);
}

/* the op 7 statement and witness of X (layouts of pqz.h); returns 0 if an encryption call failed */
static int
txm_build (const txspec_t *X, uint8_t *st, size_t *stlen, uint8_t *wt, size_t *wtlen)
{
  const unsigned m = X->m, a = X->a, G = PQZ_TXM_GROUPS (m);
  static int8_t r[MAXG][2048], rT[2048];
  static int16_t e1[MAXG][2048], e1T[2048], e2T[1][16], e2l[MAXL][16], e2f[16], e2a[MAXL][16], zero16[1][16];
  static uint8_t u[MAXG][PQZ_POLYVEC_BYTES], uT[PQZ_POLYVEC_BYTES], vT[1][PQZ_V_BYTES], utmp[PQZ_POLYVEC_BYTES];
  static uint8_t v[MAXL][PQZ_V_BYTES], vf[1][PQZ_V_BYTES], va[MAXL][PQZ_V_BYTES], vs[1][PQZ_V_BYTES];
  static uint8_t zero[1][16];
  uint8_t dg[MAXL][16], dpg[1][16], mT[1][16], P[MAXL];
  uint64_t sum = X->fee;
  unsigned j, g, k;
  int rc = 0;

  for (j = 0; j < m; j++)
    digits (dg[j], X->amount[j]), sum += X->amount[j], P[j] = (uint8_t)j;
  digits (dpg[0], X->balance - sum); /* wraps when overspent: the prover must refuse */
  dg[0][0] += (uint8_t)X->add0;
  if (X->swap)
    P[3] = 4, P[4] = 3;
  /* T = Enc(pk_f, balance); per group r_g, e1_g (u_g = A^T r_g + e1_g); e2 per leg, v_f, auditor copy */
  const uint64_t xs0 = xs;
  xs = 0x7E57AB1E00000000ULL ^ ((uint64_t)X->tag * 0x9E3779B97F4A7C15ULL);
  digits (mT[0], X->balance);
  short8 (rT, 2048, 1, 36), short16 (e1T, 2048, 20, 164), short16 (e2T[0], 16, 20, 64);
  {
    const uint8_t *p1[1] = { KTS.pk };
    rc |= pqz_encrypt (p1, 1, (const uint8_t (*)[16])mT, rT, e1T, (const int16_t (*)[16])e2T, uT, vT);
    for (g = 0; g < G; g++)
      {
        short8 (r[g], 2048, 1, 36), short16 (e1[g], 2048, 20, 164);
        rc |= pqz_encrypt (p1, 1, (const uint8_t (*)[16])zero, r[g], e1[g], (const int16_t (*)[16])zero16, u[g], vs);
      }
  }
  for (j = 0; j < m; j++)
    short16 (e2l[j], 16, 20, 64), short16 (e2a[j], 16, 20, 64);
  short16 (e2f, 16, 20, 64);
  xs = xs0;
  if (X->big0)
    for (k = 0; k < 16; k++)
      e2l[0][k] = 30;
  /* the ciphertexts, leg by leg (the honest case equals the group encryption) */
  for (j = 0; j < m; j++)
    {
      const uint8_t *pk1[1] = { KTR[X->key[j]].pk }, *pa1[1] = { KTA.pk };
      uint8_t ma[1][16];
      rc |= pqz_encrypt (pk1, 1, (const uint8_t (*)[16])dg[j], r[X->grp[j]], e1[X->grp[j]],
                         (const int16_t (*)[16])e2l[j], utmp, &v[j]);
      memcpy (ma[0], dg[j], 16);
      if (j == 0)
        ma[0][0] += (uint8_t)X->aud0;
      if (a)
        rc |= pqz_encrypt (pa1, 1, (const uint8_t (*)[16])ma, r[X->grp[j]], e1[X->grp[j]],
                           (const int16_t (*)[16])e2a[j], utmp, &va[j]);
    }
  {
    const uint8_t *p1[1] = { KTS.pk };
    rc |= pqz_encrypt (p1, 1, (const uint8_t (*)[16])dpg, r[0], e1[0], (const int16_t (*)[16])e2f, utmp, vf);
  }

  /* header: filler words hashed only; fee, amount 0, M, auditorOn, canonical salt; recipientsHash (192) filler */
  uint8_t *p = st;
  memset (p, 0x77, PQZ_PREFIX_BYTES);
  memcpy (p + 32, PSID, 32);
  for (unsigned i = PQZ_PREFIX_BYTES; i < PQZ_HEADER_BYTES; i++)
    p[i] = (uint8_t)(i * 11 + X->tag);
  wr_word (p + PQZ_HDR_FEE, X->fee);
  wr_word (p + PQZ_HDR_AMOUNT, 0);
  wr_word (p + PQZ_HDR_LEGS, m);
  wr_word (p + PQZ_HDR_AUDITOR_ON, a);
  memset (p + PQZ_HDR_SALT, 0, 16);
  p += PQZ_HEADER_BYTES;
  memcpy (p, KTS.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  for (j = 0; j < m; j++)
    memcpy (p, KTR[P[j]].pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  if (a)
    memcpy (p, KTA.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, uT, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, vT[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
  for (g = 0; g < G; g++)
    memcpy (p, u[g], PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  for (j = 0; j < m; j++)
    memcpy (p, v[P[j]], PQZ_V_BYTES), p += PQZ_V_BYTES;
  memcpy (p, vf[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
  for (j = 0; j < m && a; j++)
    memcpy (p, va[P[j]], PQZ_V_BYTES), p += PQZ_V_BYTES;
  *stlen = (size_t)(p - st);

  /* witness: s_f || e_f || (r_g || e1_g) || e2_j || e2_f || [e2_{a,j}] || d_j || d' */
  p = wt;
  for (k = 0; k < 2048; k++)
    p[k] = (uint8_t)KTS.s[k], le16 (p + 2048 + 2 * k, KTS.e[k]);
  p += 6144;
  for (g = 0; g < G; g++, p += 6144)
    for (k = 0; k < 2048; k++)
      p[k] = (uint8_t)r[g][k], le16 (p + 2048 + 2 * k, e1[g][k]);
  for (j = 0; j < m; j++, p += 32)
    for (k = 0; k < 16; k++)
      le16 (p + 2 * k, e2l[P[j]][k]);
  for (k = 0; k < 16; k++)
    le16 (p + 2 * k, e2f[k]);
  p += 32;
  for (j = 0; j < m && a; j++, p += 32)
    for (k = 0; k < 16; k++)
      le16 (p + 2 * k, e2a[P[j]][k]);
  for (j = 0; j < m; j++, p += 16)
    memcpy (p, dg[P[j]], 16);
  memcpy (p, dpg[0], 16), p += 16;
  *wtlen = (size_t)(p - wt);
  return rc == 0 && *stlen == PQZ_TXM_STMT_BYTES (m, a) && *wtlen == PQZ_TXM_WIT_BYTES (m, a);
}

static int
setup_txm (void)
{
  const uint64_t xs0 = xs;
  int ok = 1;
  xs = 0x7E57AB1EBEEF0001ULL;
  keygen (&KTS), keygen (&KTA);
  for (unsigned j = 0; j < MAXL; j++)
    keygen (&KTR[j]);
  xs = xs0;
  for (unsigned t = 0; t < NTXB; t++)
    {
      txspec_t X;
      const int rel = 6 + (int)t;
      txspec (&X, TXB[t].m, TXB[t].a, (uint8_t)t);
      OPS[rel] = PQZ_OP_TRANSFER_MULTI, STMT[rel] = txm_stmt[t], WIT[rel] = txm_wit[t];
      SEEDMUL[rel] = 23 + 2 * t, KEYOFF[rel] = PQZ_HEADER_BYTES, SCALOFF[rel] = PQZ_HDR_FEE + 31;
      ok &= txm_build (&X, txm_stmt[t], &STLEN[rel], txm_wit[t], &WLEN[rel]);
    }
  return ok;
}

/* exported steps (wasm) / called from main (native) */
int
step_init (void *arena, size_t len)
{
  int rc = pqz_init (arena, len);
  if (rc == 0)
    {
      setup ();
      if (!setup_txm ())
        rc = -2;
    }
  return rc;
}

int
step_prove (int rel, unsigned seed)
{
  for (int i = 0; i < 32; i++)
    rnd32[i] = (uint8_t)(seed * SEEDMUL[rel] + i);
  lens[rel] = sizeof (proofs[rel]);
  return pqz_prove (OPS[rel], STMT[rel], STLEN[rel], WIT[rel], WLEN[rel], rnd32, proofs[rel], &lens[rel]);
}

size_t
step_len (int rel)
{
  return lens[rel];
}

int
step_verify (int rel)
{
  return vfy (OPS[rel], STMT[rel], STLEN[rel], proofs[rel], lens[rel]);
}

/* adversarial verify inputs: kind 0 = one random bit flipped in the proof, 1 = random bytes of the valid
   length, 2 = one statement coefficient changed, 3 = proof truncated by one byte, 4 = proof with a long
   unary run (all-ones tail), 5 = public scalar changed (KEYOFF / SCALOFF) */
#define NKIND 6
static int verify_bad (int rel, int kind, unsigned seed);

/* deterministic in (kind, seed): the generator state is restored, so the same call can run with both verifiers */
int
step_verify_bad (int rel, int kind, unsigned seed)
{
  uint64_t xs0 = xs;
  int rc = verify_bad (rel, kind, seed);
  xs = xs0;
  return rc;
}

static int
verify_bad (int rel, int kind, unsigned seed)
{
  uint8_t *pf = proofs[rel];
  size_t len = lens[rel];
  uint8_t *st = STMT[rel];
  size_t stlen = STLEN[rel];
  uint8_t op = OPS[rel];
  int rc;
  xs ^= seed * 0x9E3779B97F4A7C15ULL;
  memcpy (bad, pf, len);
  if (kind == 0)
    {
      uint64_t b = rnd () % (8 * len);
      bad[b >> 3] ^= (uint8_t)(1 << (b & 7));
      return vfy (op, st, stlen, bad, len);
    }
  if (kind == 1)
    {
      for (size_t i = 0; i < len; i++)
        bad[i] = (uint8_t)rnd ();
      return vfy (op, st, stlen, bad, len);
    }
  if (kind == 2 || kind == 5)
    {
      size_t off = kind == 2 ? KEYOFF[rel] + 8 * (rnd () % 2048) + 7 : SCALOFF[rel];
      st[off] ^= 1;
      rc = vfy (op, st, stlen, pf, len);
      st[off] ^= 1;
      return rc;
    }
  if (kind == 3)
    return vfy (op, st, stlen, bad, len - 1);
  memset (bad + len / 2, 0xff, len - len / 2);
  return vfy (op, st, stlen, bad, len);
}

/* FNV-1a of the last proof: same seeds must give the same bytes before and after a pure implementation change,
   and on native and wasm */
uint32_t
step_hash (int rel)
{
  const uint8_t *pf = proofs[rel];
  size_t len = lens[rel];
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < len; i++)
    h = (h ^ pf[i]) * 16777619u;
  return h;
}

void
step_peak_reset (void)
{
  pqz_arena_peak_reset ();
}

size_t
step_arena_peak (void)
{
  return pqz_arena_peak_bytes ();
}

/* number of bench relations (wasm: run_wasm.mjs reads it) */
int
step_nrel (void)
{
  return NREL;
}

#ifndef PQZ_WASM
static const char *NAMES[NREL] = { "R_REG", "R_TX", "R_BURN", "R_DS", "R_DR", "R_TX0" };
static char TXM_NAMES[NTXB][16];

static double
now_ms (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static int
cmpd (const void *a, const void *b)
{
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}

static void
stats (const char *name, double *v, int n)
{
  if (n == 0)
    return;
  qsort (v, n, sizeof (double), cmpd);
  double s = 0;
  for (int i = 0; i < n; i++)
    s += v[i];
  printf ("{\"timing\": \"%s\", \"n\": %d, \"mean_ms\": %.3f, \"p50_ms\": %.3f, \"p99_ms\": %.3f, \"max_ms\": %.3f}\n",
          name, n, s / n, v[n / 2], v[(int)(0.99 * (n - 1))], v[n - 1]);
}

/* P6e Task 1 (CTR-PQZ-19 hedging, D6): the mask seeds of two valid R_REG witnesses (keys KF, KT) under the same rnd32
   and statement digest are unrelated (Hamming distance of the 512 seed bits near 256), as are those of one witness
   under two statements; equal inputs give equal seeds, and proving twice with one rnd32 gives the same proof. */
void pqz_prover_seeds (uint8_t ex[64], const uint8_t rnd32[32], const uint8_t *wit, size_t wit_len,
                       const uint8_t hash0[32]);
void pqz_stmt_hash (uint8_t h[32], uint8_t op, const uint8_t *stmt, size_t len);

static int
hamming (const uint8_t *a, const uint8_t *b, int n)
{
  int d = 0;
  for (int i = 0; i < n; i++)
    d += __builtin_popcount (a[i] ^ b[i]);
  return d;
}

static int
hedge_check (void)
{
  uint8_t r[32], h0[32], h1[32], exA[64], exA2[64], exB[64], exA1[64], first[PQZ_MAX_PROOF];
  size_t n0;
  memset (r, 0x42, 32);
  pqz_stmt_hash (h0, PQZ_OP_REGISTER, reg_stmt, sizeof reg_stmt);
  reg_stmt[PQZ_PREFIX_BYTES] ^= 1; /* another message: another statement for the same witness */
  pqz_stmt_hash (h1, PQZ_OP_REGISTER, reg_stmt, sizeof reg_stmt);
  reg_stmt[PQZ_PREFIX_BYTES] ^= 1;
  pqz_prover_seeds (exA, r, reg_wit, sizeof reg_wit, h0);
  pqz_prover_seeds (exA2, r, reg_wit, sizeof reg_wit, h0);
  pqz_prover_seeds (exB, r, dr_wit, sizeof dr_wit, h0); /* dr_wit = KT's (s, e): R_REG witness layout */
  pqz_prover_seeds (exA1, r, reg_wit, sizeof reg_wit, h1);
  int dw = hamming (exA, exB, 64), ds = hamming (exA, exA1, 64), same = memcmp (exA, exA2, 64) == 0;
  int rc1 = step_prove (0, 0);
  memcpy (first, proofs[0], n0 = lens[0]);
  int rc2 = step_prove (0, 0);
  int det = rc1 == 0 && rc2 == 0 && n0 == lens[0] && memcmp (first, proofs[0], n0) == 0;
  int ok = same && det && dw >= 160 && dw <= 352 && ds >= 160 && ds <= 352;
  printf ("{\"hedge\": %s, \"seed_bits_diff_witness\": %d, \"seed_bits_diff_statement\": %d, "
          "\"same_inputs_same_seeds\": %d, \"same_rnd32_same_proof\": %d}\n",
          ok ? "true" : "false", dw, ds, same, det);
  return !ok;
}

/* P6e R6 / D8 (CTR-PQZ-24): op 1 is R_TX with the 83,072-byte statement and R_TX0 with the 66,560-byte one, and the
   auditorOn word must say the same (1 / 0). With the honest proofs of the last prove: the R_TX statement with the word
   0 (the "dummy auditor" form: pk_a, v_a present, auditor off), 2, or a high byte set, and the R_TX0 statement with
   the word 1 or 2, are rejected by both verifiers and refused by the prover; each proof is rejected under the other
   form's statement. rel: the relations proved (bit 2 R_TX, bit 32 R_TX0). */
static int
auditor_check (int rels)
{
  static const struct
  {
    int rel;
    unsigned at; /* byte of the auditorOn word changed */
    uint8_t val;
  } C[] = { { 1, 31, 0 }, { 1, 31, 2 }, { 1, 0, 1 }, { 1, 24, 1 }, { 5, 31, 1 }, { 5, 31, 2 }, { 5, 7, 0x80 } };
  int fails = 0, n = 0;
  for (unsigned k = 0; k < sizeof C / sizeof C[0]; k++)
    {
      const int rel = C[k].rel;
      if (!(rels >> rel & 1) || lens[rel] == 0)
        continue;
      uint8_t *st = STMT[rel], old = st[PQZ_HDR_AUDITOR_ON + C[k].at];
      uint8_t pf[PQZ_MAX_PROOF];
      size_t pl = sizeof pf;
      st[PQZ_HDR_AUDITOR_ON + C[k].at] = C[k].val;
      int g = pqz_verify (OPS[rel], st, STLEN[rel], proofs[rel], lens[rel]), f = 0;
#ifdef PQZ_SV
      f = pqz_verify_fast (OPS[rel], st, STLEN[rel], proofs[rel], lens[rel]);
#endif
      int prc = pqz_prove (OPS[rel], st, STLEN[rel], WIT[rel], WLEN[rel], rnd32, pf, &pl);
      st[PQZ_HDR_AUDITOR_ON + C[k].at] = old;
      n++;
      if (g != 0 || f != 0 || prc == 0)
        {
          printf ("{\"auditor_check\": \"%s byte %u = %u\", \"generic\": %d, \"fast\": %d, \"prove_rc\": %d}\n",
                  NAMES[rel], C[k].at, C[k].val, g, f, prc);
          fails++;
        }
    }
  if ((rels & 34) == 34 && lens[1] && lens[5]) /* each proof under the other form's statement */
    {
      int x = pqz_verify (OPS[1], tx0_stmt, sizeof tx0_stmt, proofs[1], lens[1])
              | pqz_verify (OPS[5], tx_stmt, sizeof tx_stmt, proofs[5], lens[5]);
#ifdef PQZ_SV
      x |= pqz_verify_fast (OPS[1], tx0_stmt, sizeof tx0_stmt, proofs[1], lens[1])
           | pqz_verify_fast (OPS[5], tx_stmt, sizeof tx_stmt, proofs[5], lens[5]);
#endif
      n += 2;
      fails += x != 0;
    }
  printf ("{\"auditor_check\": %s, \"cases\": %d, \"fails\": %d}\n", fails ? "false" : "true", n, fails);
  return fails;
}

/* P6-ANON L1: R_TXM variants and negatives (pqz_bench n_p n_v mask 1). Variants (both verifiers accept): the real leg
   at other positions, two real legs across the group boundary, all legs decoys, fee 0. Negatives: a false witness or
   statement, expected = the prover refuses or both verifiers reject its proof (leg digit 16, sum + fee over the
   balance, a leg under another key or another group's randomness, legs moved between groups, an auditor copy of another
   amount, the legs' noise block over its bound), and the honest proofs of the bench statements under changed
   statements (M word, auditorOn, recipientsHash, legs or groups swapped, (2, off) read as (1, on), op 7 against op 1
   both ways). */
static int
txm_case (const char *name, const txspec_t *X, int expect)
{
  static uint8_t st[TXM_ST_MAX], wt[TXM_WIT_MAX], pf[PQZ_MAX_PROOF];
  size_t sl = 0, wl = 0, pl = sizeof pf;
  int g = 0, f = 0, prc = -1;
  if (txm_build (X, st, &sl, wt, &wl))
    prc = pqz_prove (PQZ_OP_TRANSFER_MULTI, st, sl, wt, wl, rnd32, pf, &pl);
  if (prc == 0)
    {
      g = pqz_verify (PQZ_OP_TRANSFER_MULTI, st, sl, pf, pl);
#ifdef PQZ_SV
      f = pqz_verify_fast (PQZ_OP_TRANSFER_MULTI, st, sl, pf, pl);
#else
      f = g;
#endif
    }
  const int ok = expect ? prc == 0 && g == 1 && f == 1 : g == 0 && f == 0;
  printf ("{\"txm_check\": \"%s\", \"expect\": \"%s\", \"prove_rc\": %d, \"generic\": %d, \"fast\": %d, \"ok\": %s}\n",
          name, expect ? "accept" : "reject", prc, g, f, ok ? "true" : "false");
  return !ok;
}

static int
txm_rel (unsigned m, unsigned a)
{
  for (unsigned t = 0; t < NTXB; t++)
    if (TXB[t].m == m && TXB[t].a == a)
      return 6 + (int)t;
  return -1;
}

/* the honest proof of rel under a changed copy of a statement (op, st, sl): both verifiers must reject */
static int
txm_tamper (const char *name, int rel, uint8_t op, const uint8_t *st, size_t sl)
{
  int g = pqz_verify (op, st, sl, proofs[rel], lens[rel]), f = 0;
#ifdef PQZ_SV
  f = pqz_verify_fast (op, st, sl, proofs[rel], lens[rel]);
#endif
  const int ok = lens[rel] > 0 && g == 0 && f == 0;
  printf ("{\"txm_check\": \"%s\", \"expect\": \"reject\", \"generic\": %d, \"fast\": %d, \"ok\": %s}\n", name, g, f,
          ok ? "true" : "false");
  return !ok;
}

static void
swap_bytes (uint8_t *a, uint8_t *b, size_t n)
{
  for (size_t i = 0; i < n; i++)
    {
      uint8_t t = a[i];
      a[i] = b[i], b[i] = t;
    }
}

static int
txm_check (int rels)
{
  static uint8_t st[TXM_ST_MAX];
  txspec_t X;
  int fails = 0, n = 0;
  const int r81 = txm_rel (8, 1), r20 = txm_rel (2, 0), r11 = txm_rel (1, 1);
  for (int r = 6; r < NREL; r++) /* the honest proofs the tampers need */
    if ((r == r81 || r == r20 || r == r11) && lens[r] == 0)
      fails += step_prove (r, 0) != 0;
  if (lens[1] == 0)
    fails += step_prove (1, 0) != 0;

  /* variants */
  txspec (&X, 4, 1, 100), X.amount[3] = 0, X.amount[0] = 5000;
  fails += txm_case ("M 4 on: real leg 0", &X, 1), n++;
  txspec (&X, 8, 1, 101), X.amount[7] = 0, X.amount[3] = 1111, X.amount[4] = 2222, X.fee = 0;
  fails += txm_case ("M 8 on: real legs 3 and 4 (group boundary), fee 0", &X, 1), n++;
  txspec (&X, 8, 0, 102), X.amount[7] = 0, X.fee = 0;
  fails += txm_case ("M 8 off: all legs decoys, fee 0", &X, 1), n++;
  txspec (&X, 2, 0, 103), X.amount[0] = 77, X.amount[1] = 88;
  fails += txm_case ("M 2 off: two real legs", &X, 1), n++;
  txspec (&X, 8, 1, 104), X.amount[7] = X.balance - X.fee; /* the whole balance: b' = 0 */
  fails += txm_case ("M 8 on: sum + fee = balance", &X, 1), n++;

  /* false witnesses / statements */
  txspec (&X, 8, 1, 110), X.add0 = 16;
  fails += txm_case ("leg digit 16", &X, 0), n++;
  txspec (&X, 8, 1, 111), X.amount[7] = X.balance - X.fee + 1;
  fails += txm_case ("sum + fee = balance + 1", &X, 0), n++;
  txspec (&X, 8, 1, 112), X.key[1] = 2, X.amount[1] = 9;
  fails += txm_case ("v_1 encrypted to another recipient's key", &X, 0), n++;
  txspec (&X, 8, 1, 113), X.grp[4] = 0, X.amount[4] = 9;
  fails += txm_case ("leg 4 under group 0's randomness", &X, 0), n++;
  txspec (&X, 8, 1, 114), X.swap = 1, X.amount[3] = 5;
  fails += txm_case ("legs 3 and 4 moved between groups", &X, 0), n++;
  txspec (&X, 8, 1, 115), X.aud0 = 1;
  fails += txm_case ("auditor copy of leg 0 of another amount", &X, 0), n++;
  txspec (&X, 2, 1, 116), X.big0 = 1;
  fails += txm_case ("legs' e2 block over 64 sqrt(M)", &X, 0), n++;

  /* honest proofs under changed statements */
  if (r81 >= 0)
    {
      const size_t sl = STLEN[r81];
      const unsigned m = 8, G = 2;
      const size_t pk0 = PQZ_HEADER_BYTES + PQZ_POLYVEC_BYTES, u0 = pk0 + (m + 1) * PQZ_POLYVEC_BYTES + 16512,
                   v0 = u0 + G * PQZ_POLYVEC_BYTES, va0 = v0 + (m + 1) * PQZ_V_BYTES;
      memcpy (st, STMT[r81], sl), st[PQZ_HDR_LEGS + 31] = 4;
      fails += txm_tamper ("M word 8 -> 4", r81, 7, st, sl), n++;
      st[PQZ_HDR_LEGS + 31] = 3;
      fails += txm_tamper ("M word 8 -> 3 (not built)", r81, 7, st, sl), n++;
      memcpy (st, STMT[r81], sl), st[PQZ_HDR_LEGS + 30] = 1;
      fails += txm_tamper ("M word 8 -> 264", r81, 7, st, sl), n++;
      memcpy (st, STMT[r81], sl), st[PQZ_HDR_AUDITOR_ON + 31] = 0;
      fails += txm_tamper ("auditorOn 1 -> 0", r81, 7, st, sl), n++;
      memcpy (st, STMT[r81], sl), st[192 + 31] ^= 1;
      fails += txm_tamper ("recipientsHash changed", r81, 7, st, sl), n++;
      memcpy (st, STMT[r81], sl);
      swap_bytes (st + pk0 + 3 * PQZ_POLYVEC_BYTES, st + pk0 + 4 * PQZ_POLYVEC_BYTES, PQZ_POLYVEC_BYTES);
      swap_bytes (st + v0 + 3 * PQZ_V_BYTES, st + v0 + 4 * PQZ_V_BYTES, PQZ_V_BYTES);
      swap_bytes (st + va0 + 3 * PQZ_V_BYTES, st + va0 + 4 * PQZ_V_BYTES, PQZ_V_BYTES);
      fails += txm_tamper ("legs 3 and 4 swapped in the statement", r81, 7, st, sl), n++;
      memcpy (st, STMT[r81], sl);
      swap_bytes (st + u0, st + u0 + PQZ_POLYVEC_BYTES, PQZ_POLYVEC_BYTES);
      fails += txm_tamper ("u_0 and u_1 swapped", r81, 7, st, sl), n++;
    }
  if (r20 >= 0) /* 83,072 B: also the length of (1, on) */
    {
      memcpy (st, STMT[r20], STLEN[r20]), st[PQZ_HDR_LEGS + 31] = 1, st[PQZ_HDR_AUDITOR_ON + 31] = 1;
      fails += txm_tamper ("(2, off) read as (1, on)", r20, 7, st, STLEN[r20]), n++;
    }
  if (r11 >= 0) /* op 7 at M = 1 against op 1 (R_TX), both ways */
    {
      memcpy (st, STMT[r11], STLEN[r11]), wr_word (st + PQZ_HDR_LEGS, 0);
      fails += txm_tamper ("R_TXM 1 proof as op 1", r11, 1, st, STLEN[r11]), n++;
      fails += txm_tamper ("R_TXM 1 proof, op 7 statement, op 1", r11, 1, STMT[r11], STLEN[r11]), n++;
      memcpy (st, tx_stmt, sizeof tx_stmt), wr_word (st + PQZ_HDR_LEGS, 1);
      fails += txm_tamper ("R_TX proof as op 7", 1, 7, st, sizeof tx_stmt), n++;
    }
  printf ("{\"txm_check\": %s, \"cases\": %d, \"fails\": %d}\n", fails ? "false" : "true", n, fails);
  (void)rels;
  return fails;
}

int
main (int argc, char **argv)
{
  int np = argc > 1 ? atoi (argv[1]) : 10, nv = argc > 2 ? atoi (argv[2]) : 100, fails = 0;
  int rels = argc > 3 ? atoi (argv[3]) : 63, checks = argc > 4 ? atoi (argv[4]) : 0;
  const char *amb = getenv ("PQZ_ARENA_MB");
  const size_t arena_bytes = amb != NULL ? (size_t)atoi (amb) << 20 : ARENA_BYTES;
  void *arena = malloc (arena_bytes);
  for (unsigned t = 0; t < NTXB; t++)
    {
      snprintf (TXM_NAMES[t], sizeof TXM_NAMES[t], "R_TXM%u%s", TXB[t].m, TXB[t].a ? "" : "_0");
      NAMES[6 + t] = TXM_NAMES[t];
    }
  const char *ve = getenv ("PQZ_VERIFY");
  if (step_set_fast (ve != NULL && strcmp (ve, "fast") == 0) != 0)
    {
      printf ("{\"error\": \"PQZ_VERIFY=fast: built without the specialised verifier (SV=0)\"}\n");
      return 1;
    }
  double t0, *tp = malloc (sizeof (double) * (np > nv ? np : nv) * 7 + 64);

  t0 = now_ms ();
  if (step_init (arena, arena_bytes) != 0)
    {
      printf ("{\"error\": \"init\"}\n");
      return 1;
    }
  printf ("{\"init_ms\": %.1f, \"init_arena\": %zu, \"verify\": \"%s\"}\n", now_ms () - t0, step_arena_peak (),
          fast ? "fast" : "generic");

  if (rels & 1)
    fails += hedge_check ();

  for (int tx = 0; tx < NREL; tx++)
    {
      if (!(rels >> tx & 1))
        continue;
      const char *rel = NAMES[tx];
      step_peak_reset ();
      size_t maxlen = 0;
      unsigned tries = 0;
      uint32_t hall = 2166136261u;
      for (int i = 0; i < np; i++)
        {
          extern unsigned pqz_rej_tries;
          pqz_rej_tries = 0;
          t0 = now_ms ();
          int rc = step_prove (tx, i);
          tp[i] = now_ms () - t0;
          tries += pqz_rej_tries;
          if (rc != 0)
            {
              extern const char *pqz_err_file;
              extern int pqz_err_line;
              printf ("{\"rel\": \"%s\", \"prove_rc\": %d, \"at\": \"%s:%d\"}\n", rel, rc,
                      pqz_err_file ? pqz_err_file : "", pqz_err_line);
              fails++;
              continue;
            }
          if (step_len (tx) > maxlen)
            maxlen = step_len (tx);
          hall = (hall ^ step_hash (tx)) * 16777619u;
          if (step_verify (tx) != 1)
            {
              printf ("{\"rel\": \"%s\", \"verify_honest\": 0, \"run\": %d}\n", rel, i);
              fails++;
            }
        }
      char nm[64];
      snprintf (nm, sizeof nm, "%s prove", rel);
      stats (nm, tp, np);
      printf ("{\"rel\": \"%s\", \"proof_bytes_last\": %zu, \"proof_bytes_max\": %zu, \"arena_peak\": %zu, "
              "\"rej_tries_mean\": %.2f, \"proofs_fnv\": \"%08x\"}\n",
              rel, step_len (tx), maxlen, step_arena_peak (), np ? (double)tries / np : 0.0, hall);
      for (int i = 0; i < nv; i++)
        {
          t0 = now_ms ();
          int ok = step_verify (tx);
          tp[i] = now_ms () - t0;
          fails += ok != 1;
        }
      snprintf (nm, sizeof nm, "%s verify valid", rel);
      stats (nm, tp, nv);
      int n = 0;
      for (int kind = 0; kind < NKIND * (nv > 0); kind++)
        for (int i = 0; i < nv / 5 + 1; i++)
          {
            t0 = now_ms ();
            int ok = step_verify_bad (tx, kind, (unsigned)(i * 7 + kind));
            tp[n++] = now_ms () - t0;
            if (ok != 0)
              {
                printf ("{\"rel\": \"%s\", \"accepted_bad_kind\": %d}\n", rel, kind);
                fails++;
              }
          }
      snprintf (nm, sizeof nm, "%s verify adversarial", rel);
      stats (nm, tp, n);
    }
  if (rels & 34)
    fails += auditor_check (rels);
  if (checks)
    fails += txm_check (rels);
  printf ("{\"fails\": %d}\n", fails);
  return fails != 0;
}
#endif
