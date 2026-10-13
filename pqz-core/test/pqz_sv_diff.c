/*
 * P6-SV differential test: the generic verifier (pqz_verify, the reference) against the specialised one
 * (pqz_verify_fast) on honest and mutated proofs of R_REG and R_TX. Every case must get the same accept / reject
 * from both. Deterministic: everything derives from the seed argument.
 *
 *   pqz_sv_diff [n_reg] [n_tx] [muts] [seed] [fuzz]
 *     n_reg / n_tx  honest proofs per relation, each on a fresh statement (new keys, amounts, fee)
 *     muts          rounds of the mutation list per proof (each round runs every kind once)
 *     fuzz          random multi-edit mutations per proof
 *
 * Prints JSON lines (per kind: cases, accepted by the generic verifier, mismatches; timing of the fast verifier)
 * and exits 1 on any mismatch. Built by build.sh native with the test hooks (pqz_test_mutate re-encodes a decoded
 * proof with one field changed; pqz_sv_test_prg checks the fast verifier's PRG against LaZer's).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pqz.h"

int pqz_test_mutate (uint8_t op, const uint8_t *proof, size_t len, unsigned kind, uint64_t r1, uint64_t r2,
                     uint8_t *out, size_t *outlen);
int pqz_sv_test_prg (unsigned iters);
size_t pqz_arena_used (void);
size_t pqz_arena_peak (void);
void pqz_arena_peak_reset (void);

#define ARENA_BYTES ((size_t)768 << 20)
#define Q 4398046510889ULL

static uint64_t xs;
static uint64_t
rnd (void)
{
  xs ^= xs >> 12, xs ^= xs << 25, xs ^= xs >> 27;
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
} key_t_;
static void
keygen (key_t_ *k)
{
  short8 (k->s, 2048, 1, 36);
  short16 (k->e, 2048, 20, 164);
  pqz_keypair_from_secret (k->s, k->e, k->pk);
}

static uint8_t reg_stmt[PQZ_REG_STMT_BYTES], reg_wit[PQZ_REG_WIT_BYTES];
static uint8_t tx_stmt[PQZ_TX_STMT_BYTES], tx_wit[PQZ_TX_WIT_BYTES];

/* a fresh R_REG statement: new key, message, prefix byte */
static void
make_reg (void)
{
  static key_t_ K;
  keygen (&K);
  memset (reg_stmt, (int)(rnd () & 255), PQZ_PREFIX_BYTES);
  for (int i = 0; i < 32; i++)
    reg_stmt[PQZ_PREFIX_BYTES + i] = (uint8_t)rnd ();
  memcpy (reg_stmt + PQZ_PREFIX_BYTES + 32, K.pk, PQZ_POLYVEC_BYTES);
  for (int j = 0; j < 2048; j++)
    reg_wit[j] = (uint8_t)K.s[j], le16 (reg_wit + 2048 + 2 * j, K.e[j]);
}

/* a fresh R_TX statement (as pqz_bench.c setup): new keys, balance, amount, fee */
static void
make_tx (void)
{
  static key_t_ KF, KT, KA;
  keygen (&KF), keygen (&KT), keygen (&KA);
  const uint64_t B = rnd () % ((uint64_t)1 << 48), fee = rnd () % 4096 % (B + 1), v = rnd () % (B - fee + 1),
                 bp = B - v - fee;
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
  memset (p, (int)(rnd () & 255), PQZ_PREFIX_BYTES), p += PQZ_PREFIX_BYTES;
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
}

/* ---------------------------------------------------------------- bookkeeping */

static const char *KIND[] = {
  "honest",        "reencode",       "bitflip",       "byte_set",      "random_bytes", "truncate",
  "extend",        "stmt_coeff",     "stmt_oob",      "stmt_prefix",   "stmt_fee",     "other_proof",
  "bench_k4_unary", "m_swap_z1",     "m_swap_z21",    "m_swap_z3z4",   "m_z1_pm1",     "m_z1_large",
  "m_z4_bound",    "m_z3_large",     "m_h",           "m_hint",        "m_c",          "m_tB",
  "m_tA1",         "m_z21_pm1",      "m_swap_h",      "fuzz",
};
#define NK (int)(sizeof KIND / sizeof KIND[0])
#define K_M0 13 /* first decoded-field kind = pqz_test_mutate kind 0 */
static long cases[2][NK], acc_gen[2][NK], mism[2][NK];
static double *tf[2][2]; /* fast verify ms: [rel][0 honest, 1 adversarial] */
static size_t ntf[2][2];
static int tx_rel;

static double
now_ms (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static void
check (int kind, uint8_t op, const uint8_t *st, size_t stlen, const uint8_t *pf, size_t len)
{
  int a = pqz_verify (op, st, stlen, pf, len);
  double t0 = now_ms ();
  int b = pqz_verify_fast (op, st, stlen, pf, len);
  double t = now_ms () - t0;
  const int rel = op == PQZ_OP_TRANSFER;
  tf[rel][kind != 0][ntf[rel][kind != 0]++] = t;
  cases[rel][kind]++;
  acc_gen[rel][kind] += a;
  if (a != b)
    {
      mism[rel][kind]++;
      printf ("{\"mismatch\": \"%s\", \"rel\": \"%s\", \"generic\": %d, \"fast\": %d, \"len\": %zu}\n", KIND[kind],
              rel ? "R_TX" : "R_REG", a, b, len);
      fflush (stdout);
    }
}

static int
cmpd (const void *a, const void *b)
{
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}
static void
stats (const char *name, double *v, size_t n)
{
  if (n == 0)
    return;
  qsort (v, n, sizeof (double), cmpd);
  printf ("{\"timing\": \"%s\", \"n\": %zu, \"p50_ms\": %.3f, \"p99_ms\": %.3f, \"max_ms\": %.3f}\n", name, n,
          v[n / 2], v[(size_t)(0.99 * (n - 1))], v[n - 1]);
}

static uint8_t pf[PQZ_MAX_PROOF + 64], bad[PQZ_MAX_PROOF + 64], prev[2][PQZ_MAX_PROOF];
static size_t prevlen[2];
static uint8_t st2[PQZ_TX_STMT_BYTES];

static void
mutate_round (uint8_t op, const uint8_t *st, size_t stlen, size_t len, int fuzz)
{
  const int rel = op == PQZ_OP_TRANSFER;
  size_t n;
  /* byte level */
  memcpy (bad, pf, len);
  uint64_t bit = rnd () % (8 * len);
  bad[bit / 8] ^= (uint8_t)(1u << (bit % 8));
  check (2, op, st, stlen, bad, len);
  memcpy (bad, pf, len);
  bad[rnd () % len] = (uint8_t)rnd ();
  check (3, op, st, stlen, bad, len);
  for (size_t i = 0; i < len; i++)
    bad[i] = (uint8_t)rnd ();
  check (4, op, st, stlen, bad, len);
  memcpy (bad, pf, len);
  check (5, op, st, stlen, bad, rnd () & 1 ? len - 1 - rnd () % 64 : rnd () % len);
  memcpy (bad, pf, len);
  n = 1 + rnd () % 16;
  for (size_t i = 0; i < n; i++)
    bad[len + i] = rnd () & 1 ? 0 : (uint8_t)rnd ();
  check (6, op, st, stlen, bad, len + n);
  /* statement */
  memcpy (st2, st, stlen);
  size_t off = PQZ_PREFIX_BYTES + (op == PQZ_OP_REGISTER ? 32 + 8 * (rnd () % 2048) : 8 * (rnd () % ((stlen - 72) / 8)));
  uint64_t v = 0;
  for (int b = 0; b < 8; b++)
    v = (v << 8) | st2[off + b];
  v = v < Q ? (v + 1 + rnd () % 7) % Q : v;
  for (int b = 7; b >= 0; b--)
    st2[off + b] = (uint8_t)v, v >>= 8;
  check (7, op, st2, stlen, pf, len);
  memcpy (st2, st, stlen);
  v = Q + rnd () % 1000;
  for (int b = 7; b >= 0; b--)
    st2[off + b] = (uint8_t)v, v >>= 8;
  check (8, op, st2, stlen, pf, len);
  memcpy (st2, st, stlen);
  st2[rnd () % PQZ_PREFIX_BYTES] ^= (uint8_t)(1 + rnd () % 255);
  check (9, op, st2, stlen, pf, len);
  if (op == PQZ_OP_TRANSFER)
    {
      memcpy (st2, st, stlen);
      st2[stlen - 1 - rnd () % 2] ^= (uint8_t)(1 + rnd () % 15);
      check (10, op, st2, stlen, pf, len);
    }
  if (prevlen[rel])
    check (11, op, st, stlen, prev[rel], prevlen[rel]);
  memcpy (bad, pf, len);
  memset (bad + len / 2, 0xff, len - len / 2);
  check (12, op, st, stlen, bad, len);
  /* decoded fields, re-encoded */
  for (unsigned k = 0; k < 14; k++)
    {
      n = sizeof bad;
      if (pqz_test_mutate (op, pf, len, k, rnd (), rnd (), bad, &n))
        check (K_M0 + (int)k, op, st, stlen, bad, n);
    }
  /* fuzz: 1..8 random edits */
  for (int f = 0; f < fuzz; f++)
    {
      size_t l = len;
      memcpy (bad, pf, len);
      for (int e = 1 + (int)(rnd () % 8); e > 0; e--)
        switch (rnd () % 5)
          {
          case 0:
            bit = rnd () % (8 * l), bad[bit / 8] ^= (uint8_t)(1u << (bit % 8));
            break;
          case 1:
            bad[rnd () % l] = (uint8_t)rnd ();
            break;
          case 2: /* delete a byte */
            if (l > 1)
              {
                size_t i = rnd () % l;
                memmove (bad + i, bad + i + 1, l - i - 1), l--;
              }
            break;
          case 3: /* insert a byte */
            if (l < PQZ_MAX_PROOF)
              {
                size_t i = rnd () % l;
                memmove (bad + i + 1, bad + i, l - i), bad[i] = (uint8_t)rnd (), l++;
              }
            break;
          default: /* copy a chunk inside the proof */
            {
              size_t a = rnd () % l, b = rnd () % l, c = 1 + rnd () % 64;
              if (a + c <= l && b + c <= l)
                memmove (bad + b, bad + a, c);
            }
          }
      check (NK - 1, op, st, stlen, bad, l);
    }
}

int
main (int argc, char **argv)
{
  const int nreg = argc > 1 ? atoi (argv[1]) : 10, ntx = argc > 2 ? atoi (argv[2]) : 5;
  const int muts = argc > 3 ? atoi (argv[3]) : 2, fuzz = argc > 5 ? atoi (argv[5]) : 10;
  const unsigned long seed = argc > 4 ? strtoul (argv[4], NULL, 0) : 1;
  void *arena = malloc (ARENA_BYTES);
  int fails = 0;

  xs = 0x243F6A8885A308D3ULL ^ (seed * 0x9E3779B97F4A7C15ULL);
  if (pqz_init (arena, ARENA_BYTES) != 0)
    {
      printf ("{\"error\": \"init\"}\n");
      return 1;
    }
  int prg = pqz_sv_test_prg (200);
  printf ("{\"prg_mismatches\": %d}\n", prg);
  fails += prg != 0;
  for (int rel = 0; rel < 2; rel++)
    {
      const int np = rel ? ntx : nreg;
      const size_t per = (size_t)np * (1 + muts * (14 + 16 + fuzz));
      tf[rel][0] = malloc (sizeof (double) * (np + 1));
      tf[rel][1] = malloc (sizeof (double) * (per + 1));
    }
  for (tx_rel = 0; tx_rel < 2; tx_rel++)
    {
      const int np = tx_rel ? ntx : nreg;
      const uint8_t op = tx_rel ? PQZ_OP_TRANSFER : PQZ_OP_REGISTER;
      for (int i = 0; i < np; i++)
        {
          uint8_t r32[32];
          size_t len = PQZ_MAX_PROOF;
          int rc;
          for (int b = 0; b < 32; b++)
            r32[b] = (uint8_t)rnd ();
          if (tx_rel)
            make_tx (), rc = pqz_prove (op, tx_stmt, sizeof tx_stmt, tx_wit, sizeof tx_wit, r32, pf, &len);
          else
            make_reg (), rc = pqz_prove (op, reg_stmt, sizeof reg_stmt, reg_wit, sizeof reg_wit, r32, pf, &len);
          if (rc != 0)
            {
              printf ("{\"prove_rc\": %d, \"rel\": %d, \"i\": %d}\n", rc, tx_rel, i);
              fails++;
              continue;
            }
          const uint8_t *st = tx_rel ? tx_stmt : reg_stmt;
          const size_t stlen = tx_rel ? sizeof tx_stmt : sizeof reg_stmt;
          if (i == 0) /* arena working set of one verify, above the base mark (init tables) */
            {
              size_t base = pqz_arena_used (), pg, pfst;
              pqz_arena_peak_reset ();
              pqz_verify (op, st, stlen, pf, len);
              pg = pqz_arena_peak () - base;
              pqz_arena_peak_reset ();
              pqz_verify_fast (op, st, stlen, pf, len);
              pfst = pqz_arena_peak () - base;
              printf ("{\"rel\": \"%s\", \"arena_base\": %zu, \"verify_peak_generic\": %zu, \"verify_peak_fast\": %zu}\n",
                      tx_rel ? "R_TX" : "R_REG", base, pg, pfst);
            }
          check (0, op, st, stlen, pf, len);
          {
            size_t n = sizeof bad;
            if (pqz_test_mutate (op, pf, len, 99, rnd (), rnd (), bad, &n))
              check (1, op, st, stlen, bad, n);
          }
          for (int m = 0; m < muts; m++)
            mutate_round (op, st, stlen, len, m == 0 ? fuzz : 0);
          memcpy (prev[tx_rel], pf, len), prevlen[tx_rel] = len;
        }
    }
  long tot = 0, totm = 0;
  for (int rel = 0; rel < 2; rel++)
    for (int k = 0; k < NK; k++)
      if (cases[rel][k])
        {
          printf ("{\"rel\": \"%s\", \"kind\": \"%s\", \"cases\": %ld, \"generic_accepts\": %ld, \"mismatches\": %ld}\n",
                  rel ? "R_TX" : "R_REG", KIND[k], cases[rel][k], acc_gen[rel][k], mism[rel][k]);
          tot += cases[rel][k], totm += mism[rel][k];
        }
  stats ("R_REG fast honest", tf[0][0], ntf[0][0]);
  stats ("R_REG fast adversarial", tf[0][1], ntf[0][1]);
  stats ("R_TX fast honest", tf[1][0], ntf[1][0]);
  stats ("R_TX fast adversarial", tf[1][1], ntf[1][1]);
  printf ("{\"seed\": %lu, \"cases\": %ld, \"mismatches\": %ld, \"other_fails\": %d}\n", seed, tot, totm, fails);
  return totm != 0 || fails != 0;
}
