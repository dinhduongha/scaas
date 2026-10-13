/*
 * pqz-core test and benchmark: R_REG, R_TX, R_BURN, R_DS, R_DR prove / verify, negative cases, timing.
 * Same source for native (build/native/pqz_bench) and wasm32 (build/wasm/pqz.wasm, driven by test/run_wasm.mjs):
 * PQZ_WASM builds export the steps instead of main() and time on the JS side.
 *
 *   pqz_bench [n_prove] [n_verify] [rel]   prints JSON lines: sizes, times (ms), check results
 *   rel: bit mask, 1 = R_REG, 2 = R_TX, 4 = R_BURN, 8 = R_DS, 16 = R_DR (default 31 = all); n_verify = 0 also
 *   skips the adversarial verifies
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
static uint8_t burn_stmt[PQZ_BURN_STMT_BYTES], burn_wit[PQZ_BURN_WIT_BYTES];
static uint8_t ds_stmt[PQZ_DISC_STMT_BYTES], ds_wit[PQZ_DS_WIT_BYTES];
static uint8_t dr_stmt[PQZ_DISC_STMT_BYTES], dr_wit[PQZ_DR_WIT_BYTES];
static uint8_t proofs[5][PQZ_MAX_PROOF], bad[PQZ_MAX_PROOF];
static size_t lens[5];
static uint8_t rnd32[32];

/* relation index: 0 R_REG, 1 R_TX, 2 R_BURN, 3 R_DS, 4 R_DR */
#define NREL 5
static const char *const NAMES[NREL] = { "R_REG", "R_TX", "R_BURN", "R_DS", "R_DR" };
static const uint8_t OPS[NREL] = { PQZ_OP_REGISTER, PQZ_OP_TRANSFER, PQZ_OP_BURN, PQZ_OP_DISCLOSE_SENDER,
                                   PQZ_OP_DISCLOSE_RECEIVER };
static uint8_t *const STMT[NREL] = { reg_stmt, tx_stmt, burn_stmt, ds_stmt, dr_stmt };
static const size_t STLEN[NREL] = { sizeof reg_stmt, sizeof tx_stmt, sizeof burn_stmt, sizeof ds_stmt,
                                    sizeof dr_stmt };
static const uint8_t *const WIT[NREL] = { reg_wit, tx_wit, burn_wit, ds_wit, dr_wit };
static const size_t WLEN[NREL] = { sizeof reg_wit, sizeof tx_wit, sizeof burn_wit, sizeof ds_wit, sizeof dr_wit };
static const unsigned SEEDMUL[NREL] = { 31, 17, 13, 11, 7 };
/* tamper kind 2: first byte of a 2048-coefficient key in the statement (R_REG pk, R_TX / R_BURN pk_f, disclosure
   pk); kind 5: the last byte of a public scalar (R_REG message, R_TX fee, R_BURN / disclosure amount) */
static const size_t KEYOFF[NREL] = { PQZ_PREFIX_BYTES + 32, PQZ_PREFIX_BYTES + 32, PQZ_HEADER_BYTES, PQZ_DISC_PK,
                                     PQZ_DISC_PK };
static const size_t SCALOFF[NREL] = { PQZ_PREFIX_BYTES + 31, PQZ_TX_STMT_BYTES - 1, PQZ_HDR_AMOUNT + 31,
                                      PQZ_DISC_AMOUNT + 31, PQZ_DISC_AMOUNT + 31 };

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

  uint8_t *p = tx_stmt;
  memset (p, 0x5A, PQZ_PREFIX_BYTES), p += PQZ_PREFIX_BYTES;
  memcpy (p, KF.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, KT.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, KA.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, uT, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, vT[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
  memcpy (p, u, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  for (int k = 0; k < 3; k++)
    memcpy (p, vs[k], PQZ_V_BYTES), p += PQZ_V_BYTES;
  for (int b = 7; b >= 0; b--)
    *p++ = (uint8_t)(fee >> (8 * b));

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
      for (int i = PQZ_PREFIX_BYTES; i < PQZ_DISC_AMOUNT; i++)
        st[i] = (uint8_t)(i * 7);
      memset (st + PQZ_DISC_AMOUNT, 0, 32);
      be8 (st + PQZ_DISC_AMOUNT + 24, v);
      st[PQZ_DISC_AMOUNT + 32] = (uint8_t)(k ? 1 : 0); /* kind */
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

  /* R_BURN: burn 123,456 with fee 7 from the same T; fresh (r, e1, e2_f) for the new balance */
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
    for (int i = PQZ_PREFIX_BYTES; i < PQZ_HEADER_BYTES; i++)
      p[i] = (uint8_t)(i * 5); /* chainId .. memoHash: hashed only */
    memset (p + PQZ_HDR_FEE, 0, 64);
    be8 (p + PQZ_HDR_FEE + 24, fee);
    be8 (p + PQZ_HDR_AMOUNT + 24, v);
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
  return pqz_verify (OPS[rel], STMT[rel], STLEN[rel], proofs[rel], lens[rel]);
}

/* adversarial verify inputs: kind 0 = one random bit flipped in the proof, 1 = random bytes of the valid
   length, 2 = one statement coefficient changed, 3 = proof truncated by one byte, 4 = proof with a long
   unary run (all-ones tail), 5 = public scalar changed (KEYOFF / SCALOFF) */
#define NKIND 6
int
step_verify_bad (int rel, int kind, unsigned seed)
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
      return pqz_verify (op, st, stlen, bad, len);
    }
  if (kind == 1)
    {
      for (size_t i = 0; i < len; i++)
        bad[i] = (uint8_t)rnd ();
      return pqz_verify (op, st, stlen, bad, len);
    }
  if (kind == 2 || kind == 5)
    {
      size_t off = kind == 2 ? KEYOFF[rel] + 8 * (rnd () % 2048) + 7 : SCALOFF[rel];
      st[off] ^= 1;
      rc = pqz_verify (op, st, stlen, pf, len);
      st[off] ^= 1;
      return rc;
    }
  if (kind == 3)
    return pqz_verify (op, st, stlen, bad, len - 1);
  memset (bad + len / 2, 0xff, len - len / 2);
  return pqz_verify (op, st, stlen, bad, len);
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

int
main (int argc, char **argv)
{
  int np = argc > 1 ? atoi (argv[1]) : 10, nv = argc > 2 ? atoi (argv[2]) : 100, fails = 0;
  int rels = argc > 3 ? atoi (argv[3]) : 31;
  void *arena = malloc (ARENA_BYTES);
  double t0, *tp = malloc (sizeof (double) * (np > nv ? np : nv) * 7 + 64);

  t0 = now_ms ();
  if (step_init (arena, ARENA_BYTES) != 0)
    {
      printf ("{\"error\": \"init\"}\n");
      return 1;
    }
  printf ("{\"init_ms\": %.1f}\n", now_ms () - t0);

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
  printf ("{\"fails\": %d}\n", fails);
  return fails != 0;
}
#endif
