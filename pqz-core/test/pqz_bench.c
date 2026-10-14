/*
 * pqz-core test and benchmark: R_REG, R_TX, R_BURN, R_DS, R_DR, R_TX0 prove / verify, negative cases, timing.
 * Same source for native (build/native/pqz_bench) and wasm32 (build/wasm/pqz.wasm, driven by test/run_wasm.mjs):
 * PQZ_WASM builds export the steps instead of main() and time on the JS side.
 *
 *   pqz_bench [n_prove] [n_verify] [rel]   prints JSON lines: sizes, times (ms), check results
 *   rel: bit mask, 1 = R_REG, 2 = R_TX, 4 = R_BURN, 8 = R_DS, 16 = R_DR, 32 = R_TX0 (default 63 = all); n_verify = 0
 *   also skips the adversarial verifies
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

#define ARENA_BYTES ((size_t)768 << 20) /* measured peaks well below (STATUS.md) */

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

/* relation index: 0 R_REG, 1 R_TX, 2 R_BURN, 3 R_DS, 4 R_DR, 5 R_TX0 (op 1, told apart from R_TX by the length) */
#define NREL 6
static const uint8_t OPS[NREL] = { PQZ_OP_REGISTER, PQZ_OP_TRANSFER, PQZ_OP_BURN, PQZ_OP_DISCLOSE_SENDER,
                                   PQZ_OP_DISCLOSE_RECEIVER, PQZ_OP_TRANSFER };
static uint8_t *const STMT[NREL] = { reg_stmt, tx_stmt, burn_stmt, ds_stmt, dr_stmt, tx0_stmt };
static const size_t STLEN[NREL] = { sizeof reg_stmt, sizeof tx_stmt, sizeof burn_stmt, sizeof ds_stmt,
                                    sizeof dr_stmt, sizeof tx0_stmt };
static const uint8_t *const WIT[NREL] = { reg_wit, tx_wit, burn_wit, ds_wit, dr_wit, tx0_wit };
static const size_t WLEN[NREL] = { sizeof reg_wit, sizeof tx_wit, sizeof burn_wit, sizeof ds_wit, sizeof dr_wit,
                                   sizeof tx0_wit };
static const unsigned SEEDMUL[NREL] = { 31, 17, 13, 11, 7, 19 };
static const uint8_t PSID[32] = PQZ_PROOF_SYSTEM_ID; /* statement bytes 32..63 */
/* tamper kind 2: first byte of a 2048-coefficient key in the statement (R_REG pk, R_TX / R_BURN pk_f, disclosure
   pk); kind 5: the last byte of a public scalar (R_REG message, R_TX / R_TX0 fee, R_BURN / disclosure amount) */
static const size_t KEYOFF[NREL] = { PQZ_PREFIX_BYTES + 32, PQZ_HEADER_BYTES, PQZ_HEADER_BYTES, PQZ_DISC_PK,
                                     PQZ_DISC_PK, PQZ_HEADER_BYTES };
static const size_t SCALOFF[NREL] = { PQZ_PREFIX_BYTES + 31, PQZ_HDR_FEE + 31, PQZ_HDR_AMOUNT + 31,
                                      PQZ_DISC_AMOUNT + 31, PQZ_DISC_AMOUNT + 31, PQZ_HDR_FEE + 31 };

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

/* exported steps (wasm) / called from main (native) */
int
step_init (void *arena, size_t len)
{
  int rc = pqz_init (arena, len);
  if (rc == 0)
    setup ();
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

#ifndef PQZ_WASM
static const char *const NAMES[NREL] = { "R_REG", "R_TX", "R_BURN", "R_DS", "R_DR", "R_TX0" };

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

int
main (int argc, char **argv)
{
  int np = argc > 1 ? atoi (argv[1]) : 10, nv = argc > 2 ? atoi (argv[2]) : 100, fails = 0;
  int rels = argc > 3 ? atoi (argv[3]) : 63;
  void *arena = malloc (ARENA_BYTES);
  const char *ve = getenv ("PQZ_VERIFY");
  if (step_set_fast (ve != NULL && strcmp (ve, "fast") == 0) != 0)
    {
      printf ("{\"error\": \"PQZ_VERIFY=fast: built without the specialised verifier (SV=0)\"}\n");
      return 1;
    }
  double t0, *tp = malloc (sizeof (double) * (np > nv ? np : nv) * 7 + 64);

  t0 = now_ms ();
  if (step_init (arena, ARENA_BYTES) != 0)
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
  printf ("{\"fails\": %d}\n", fails);
  return fails != 0;
}
#endif
