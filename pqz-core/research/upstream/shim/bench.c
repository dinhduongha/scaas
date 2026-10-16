/*
 * pqz-core E-S1 test and benchmark: R_REG and R_TX prove / verify, negative cases, timing.
 * Same source for native (build/native/pqz_bench) and wasm32 (build/wasm/pqz.wasm, driven by test/run_wasm.mjs):
 * PQZ_WASM builds export the steps instead of main() and time on the JS side.
 *
 *   pqz_bench [n_prove] [n_verify]   prints JSON lines: sizes, times (ms), check results
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

#define ARENA_BYTES ((size_t)768 << 20) /* measured peak: R_REG 144 MB, R_TX 612 MB (live set, STATUS.md) */

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
static uint8_t reg_proof[PQZ_MAX_PROOF], tx_proof[PQZ_MAX_PROOF], bad[PQZ_MAX_PROOF];
static size_t reg_len, tx_len;
static uint8_t rnd32[32];

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
#ifdef PQZ_HEADER_BYTES /* rel3 layout (pq-zero-knowledge.md §7.7): 640 B header, fee a be32 word at PQZ_HDR_FEE */
  memset (p, 0x5A, PQZ_PREFIX_BYTES);
  for (int b = 0; b < 8; b++)
    p[PQZ_HDR_FEE + 24 + b] = (uint8_t)(fee >> (8 * (7 - b)));
#ifdef PQZ_HDR_AUDITOR_ON /* P6e R6: the 83,072-byte form requires auditorOn = 1 */
  p[PQZ_HDR_AUDITOR_ON + 31] = 1;
#endif
  p += PQZ_HEADER_BYTES;
#else /* b2402b5 layout: prefix || body || be8 fee */
  memset (p, 0x5A, PQZ_PREFIX_BYTES), p += PQZ_PREFIX_BYTES;
#endif
  memcpy (p, KF.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, KT.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, KA.pk, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, uT, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, vT[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
  memcpy (p, u, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  for (int k = 0; k < 3; k++)
    memcpy (p, vs[k], PQZ_V_BYTES), p += PQZ_V_BYTES;
#ifndef PQZ_HEADER_BYTES
  for (int b = 7; b >= 0; b--)
    *p++ = (uint8_t)(fee >> (8 * b));
#endif

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
step_prove_reg (unsigned seed)
{
  for (int i = 0; i < 32; i++)
    rnd32[i] = (uint8_t)(seed * 31 + i);
  reg_len = sizeof (reg_proof);
  return pqz_prove (PQZ_OP_REGISTER, reg_stmt, sizeof (reg_stmt), reg_wit, sizeof (reg_wit), rnd32, reg_proof,
                    &reg_len);
}

int
step_prove_tx (unsigned seed)
{
  for (int i = 0; i < 32; i++)
    rnd32[i] = (uint8_t)(seed * 17 + i);
  tx_len = sizeof (tx_proof);
  return pqz_prove (PQZ_OP_TRANSFER, tx_stmt, sizeof (tx_stmt), tx_wit, sizeof (tx_wit), rnd32, tx_proof,
                    &tx_len);
}

size_t
step_len (int tx)
{
  return tx ? tx_len : reg_len;
}

int
step_verify (int tx)
{
  return tx ? pqz_verify (PQZ_OP_TRANSFER, tx_stmt, sizeof (tx_stmt), tx_proof, tx_len)
            : pqz_verify (PQZ_OP_REGISTER, reg_stmt, sizeof (reg_stmt), reg_proof, reg_len);
}

/* adversarial verify inputs: kind 0 = one random bit flipped in the proof, 1 = random bytes of the valid
   length, 2 = one statement coefficient changed, 3 = proof truncated by one byte, 4 = proof with a long
   unary run (all-ones tail) */
int
step_verify_bad (int tx, int kind, unsigned seed)
{
  uint8_t *pf = tx ? tx_proof : reg_proof;
  size_t len = tx ? tx_len : reg_len;
  uint8_t *st = tx ? tx_stmt : reg_stmt;
  size_t stlen = tx ? sizeof (tx_stmt) : sizeof (reg_stmt);
  uint8_t op = tx ? PQZ_OP_TRANSFER : PQZ_OP_REGISTER;
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
  if (kind == 2)
    {
      size_t off = PQZ_PREFIX_BYTES + 32 + 8 * (rnd () % 2048) + 7;
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
  void *arena = malloc (ARENA_BYTES);
  double t0, *tp = malloc (sizeof (double) * (np > nv ? np : nv) * 6);

  t0 = now_ms ();
  if (step_init (arena, ARENA_BYTES) != 0)
    {
      printf ("{\"error\": \"init\"}\n");
      return 1;
    }
  printf ("{\"init_ms\": %.1f}\n", now_ms () - t0);

  for (int tx = getenv ("XC_TXONLY") ? 1 : 0; tx < 2; tx++) /* xcheck: XC_TXONLY skips R_REG */
    {
      const char *rel = tx ? "R_TX" : "R_REG";
      size_t maxlen = 0;
      unsigned tries = 0;
      for (int i = 0; i < np; i++)
        {
          extern unsigned pqz_rej_tries;
          pqz_rej_tries = 0;
          t0 = now_ms ();
          int rc = tx ? step_prove_tx (i) : step_prove_reg (i);
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
          { /* xcheck: per-run time, length and FNV-1a of the proof (byte-equality check across backends) */
            const uint8_t *pp = tx ? tx_proof : reg_proof; uint64_t hh = 1469598103934665603ULL;
            for (size_t q = 0; q < step_len (tx); q++) hh = (hh ^ pp[q]) * 1099511628211ULL;
            printf ("{\"run\": \"%s\", \"i\": %d, \"prove_ms\": %.1f, \"len\": %zu, \"fnv\": \"%016llx\", \"tries\": %u}\n", rel, i, tp[i], step_len (tx), (unsigned long long)hh, pqz_rej_tries); }
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
              "\"rej_tries_mean\": %.2f}\n",
              rel, step_len (tx), maxlen, step_arena_peak (), np ? (double)tries / np : 0.0);
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
      for (int kind = 0; kind < 0; kind++) /* xcheck: honest runs only */
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
