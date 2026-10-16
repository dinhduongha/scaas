/*
 * P6d-2 microbench: candidate base multiplications mod X^16 - rho (q = 2^42 - 215) against the E-S1 kernel.
 * Every candidate is checked against pqz_poly_mul_ref (negacyclic schoolbook) through the NTT.
 *
 *   clang -O2 -Isrc opt/micro_basemul.c src/pqz_ntt.c -o build/micro_basemul && build/micro_basemul
 *   add -DPQZ_MUL128=0 to check and time the library's wasm32 (21-bit limb) path on the host
 *   (wasm: build.sh does not build it; the limb kernel is what wasm32 runs, timed by test/run_wasm.mjs)
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "pqz_ntt.h"

#define Q PQZ_Q
#define MASK42 ((((uint64_t)1) << 42) - 1)
#define MASK21 ((((uint64_t)1) << 21) - 1)

static const uint64_t RHO[4] = { 3367489746414ULL, PQZ_Q - 3367489746414ULL, 969320936632ULL,
                                 PQZ_Q - 969320936632ULL };

static inline uint64_t
mulq (uint64_t a, uint64_t b)
{
  return pqz_red128 ((pqz_u128)a * b);
}

/* E-S1 kernel (copy of pqz_ntt.c basemul16 at main) */
static void
bm_e1 (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
  pqz_u128 lo[16] = { 0 }, hi[16] = { 0 };
  for (int i = 0; i < 16; i++)
    for (int j = 0; j < 16; j++)
      {
        pqz_u128 p = (pqz_u128)a[i] * b[j];
        if (i + j < 16)
          lo[i + j] += p;
        else
          hi[i + j - 16] += p;
      }
  for (int k = 0; k < 16; k++)
    r[k] = pqz_csubq (pqz_red128 (lo[k]) + mulq (rho, pqz_red128 (hi[k])));
}

/* B: twisted operand bb[1..15] = rho * b[1..15], bb[16..31] = b[0..15]; one u128 column sum per output */
static void
bm_col (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
  uint64_t bb[32];
  for (int j = 1; j < 16; j++)
    bb[j] = mulq (rho, b[j]);
  for (int j = 0; j < 16; j++)
    bb[16 + j] = b[j];
  for (int k = 0; k < 16; k++)
    {
      pqz_u128 acc = 0;
      for (int i = 0; i < 16; i++)
        acc += (pqz_u128)a[i] * bb[16 + k - i];
      r[k] = pqz_red128 (acc);
    }
}

/* B with a cheaper final reduction: acc < 16 q^2 < 2^88 */
static inline uint64_t
red88 (pqz_u128 x)
{
  uint64_t lo = (uint64_t)x & MASK42;
  uint64_t hi = (uint64_t)(x >> 42); /* < 2^46 */
  uint64_t t = (hi & MASK42) * 215 + (hi >> 42) * (215 * 215) + lo; /* < 2^50 + 2^20 + 2^42 */
  t = (t >> 42) * 215 + (t & MASK42);                                  /* < 2^42 + 2^16 */
  return pqz_csubq (t);
}

static void
bm_col2 (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
  uint64_t bb[32];
  for (int j = 1; j < 16; j++)
    bb[j] = mulq (rho, b[j]);
  for (int j = 0; j < 16; j++)
    bb[16 + j] = b[j];
  for (int k = 0; k < 16; k++)
    {
      pqz_u128 acc = 0;
      for (int i = 0; i < 16; i++)
        acc += (pqz_u128)a[i] * bb[16 + k - i];
      r[k] = red88 (acc);
    }
}

/* D: 21-bit limbs, u64 products only (no 64x64->128), 4 products per term */
static void
bm_limb (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
  uint64_t a0[16], a1[16], b0[32], b1[32];
  for (int i = 0; i < 16; i++)
    a0[i] = a[i] & MASK21, a1[i] = a[i] >> 21;
  for (int j = 1; j < 16; j++)
    {
      uint64_t t = mulq (rho, b[j]);
      b0[j] = t & MASK21, b1[j] = t >> 21;
    }
  for (int j = 0; j < 16; j++)
    b0[16 + j] = b[j] & MASK21, b1[16 + j] = b[j] >> 21;
  for (int k = 0; k < 16; k++)
    {
      uint64_t l = 0, m = 0, h = 0;
      for (int i = 0; i < 16; i++)
        {
          l += a0[i] * b0[16 + k - i];
          m += a0[i] * b1[16 + k - i] + a1[i] * b0[16 + k - i];
          h += a1[i] * b1[16 + k - i];
        }
      /* l < 2^46, m < 2^47, h < 2^46; 2^42 = 215 mod q */
      uint64_t x = l + ((m & MASK21) << 21) + (m >> 21) * 215 + h * 215; /* < 2^55 */
      x = (x >> 42) * 215 + (x & MASK42);
      r[k] = pqz_csubq (x);
    }
}

/* D3: limbs with Karatsuba on the limbs (3 products per term) */
static void
bm_limb3 (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
  uint64_t a0[16], a1[16], as[16], b0[32], b1[32], bs[32];
  for (int i = 0; i < 16; i++)
    a0[i] = a[i] & MASK21, a1[i] = a[i] >> 21, as[i] = a0[i] + a1[i];
  for (int j = 1; j < 16; j++)
    {
      uint64_t t = mulq (rho, b[j]);
      b0[j] = t & MASK21, b1[j] = t >> 21, bs[j] = b0[j] + b1[j];
    }
  for (int j = 0; j < 16; j++)
    b0[16 + j] = b[j] & MASK21, b1[16 + j] = b[j] >> 21, bs[16 + j] = b0[16 + j] + b1[16 + j];
  for (int k = 0; k < 16; k++)
    {
      uint64_t l = 0, s = 0, h = 0;
      for (int i = 0; i < 16; i++)
        {
          l += a0[i] * b0[16 + k - i];
          s += as[i] * bs[16 + k - i];
          h += a1[i] * b1[16 + k - i];
        }
      uint64_t m = s - l - h;
      uint64_t x = l + ((m & MASK21) << 21) + (m >> 21) * 215 + h * 215;
      x = (x >> 42) * 215 + (x & MASK42);
      r[k] = pqz_csubq (x);
    }
}

/* full 16 x 16 product, schoolbook, into c[0..31) (c[31] = 0) */
static inline void
sb_n (pqz_u128 *c, const uint64_t *a, const uint64_t *b, int n)
{
  for (int k = 0; k < 2 * n - 1; k++)
    {
      pqz_u128 acc = 0;
      int lo = k < n ? 0 : k - n + 1, hi = k < n ? k : n - 1;
      for (int i = lo; i <= hi; i++)
        acc += (pqz_u128)a[i] * b[k - i];
      c[k] = acc;
    }
}

/* Karatsuba: n = 16 -> three 8 x 8 (each 8 x 8 -> three 4 x 4 schoolbooks if lvl2) */
static void
kara8 (pqz_u128 c[15], const uint64_t a[8], const uint64_t b[8], int lvl2)
{
  if (!lvl2)
    {
      sb_n (c, a, b, 8);
      return;
    }
  pqz_u128 l[7], h[7], m[7];
  uint64_t as[4], bs[4];
  for (int i = 0; i < 4; i++)
    as[i] = a[i] + a[i + 4], bs[i] = b[i] + b[i + 4];
  sb_n (l, a, b, 4), sb_n (h, a + 4, b + 4, 4);
  /* operands < 2^44 after two sums: products < 2^88, 4 terms < 2^90 */
  for (int k = 0; k < 7; k++)
    {
      pqz_u128 acc = 0;
      int lo = k < 4 ? 0 : k - 3, hi = k < 4 ? k : 3;
      for (int i = lo; i <= hi; i++)
        acc += (pqz_u128)as[i] * bs[k - i];
      m[k] = acc - l[k] - h[k];
    }
  for (int k = 0; k < 15; k++)
    c[k] = 0;
  for (int k = 0; k < 7; k++)
    c[k] += l[k], c[k + 4] += m[k], c[k + 8] += h[k];
}

static void
bm_kara (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho, int lvl2)
{
  pqz_u128 l[15], h[15], m[15], c[31];
  uint64_t as[8], bs[8];
  for (int i = 0; i < 8; i++)
    as[i] = a[i] + a[i + 8], bs[i] = b[i] + b[i + 8];
  kara8 (l, a, b, lvl2), kara8 (h, a + 8, b + 8, lvl2), kara8 (m, as, bs, lvl2);
  for (int k = 0; k < 31; k++)
    c[k] = 0;
  for (int k = 0; k < 15; k++)
    c[k] += l[k], c[k + 8] += m[k] - l[k] - h[k], c[k + 16] += h[k];
  /* c[k] < 16 q^2 < 2^88; fold X^16 = rho */
  for (int k = 0; k < 15; k++)
    r[k] = pqz_red128 (c[k] + (pqz_u128)rho * pqz_red128 (c[k + 16]));
  r[15] = pqz_red128 (c[15]);
}

static void
bm_kara1 (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
  bm_kara (r, a, b, rho, 0);
}

static void
bm_kara2 (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
  bm_kara (r, a, b, rho, 1);
}

/* col with the 16 x 16 convolution fully unrolled */
static void
bm_colu (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
  uint64_t bb[32];
  for (int j = 1; j < 16; j++)
    bb[j] = mulq (rho, b[j]);
  for (int j = 0; j < 16; j++)
    bb[16 + j] = b[j];
#pragma clang loop unroll(full)
  for (int k = 0; k < 16; k++)
    {
      pqz_u128 acc = 0;
#pragma clang loop unroll(full)
      for (int i = 0; i < 16; i++)
        acc += (pqz_u128)a[i] * bb[16 + k - i];
      r[k] = pqz_red128 (acc);
    }
}

/* the library kernel (src/pqz_ntt.c, compiled with or without -DPQZ_MUL128=0) */
static void
bm_lib (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
  (void)r, (void)a, (void)b, (void)rho;
}

typedef void (*bm_fn) (uint64_t *, const uint64_t *, const uint64_t *, uint64_t);

static void
basemul (bm_fn f, uint64_t r[64], const uint64_t a[64], const uint64_t b[64])
{
  if (f == bm_lib)
    {
      pqz_ntt_basemul (r, a, b);
      return;
    }
  for (int j = 0; j < 4; j++)
    f (r + 16 * j, a + 16 * j, b + 16 * j, RHO[j]);
}

static uint64_t xs = 88172645463325252ULL;
static uint64_t
rnd (void)
{
  xs ^= xs << 13, xs ^= xs >> 7, xs ^= xs << 17;
  return xs;
}

static double
now_ns (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e9 + t.tv_nsec;
}

#define N 512

int
main (void)
{
  static uint64_t A[N][64], B[N][64], R[N][64];
  const char *names[] = { "e1 (E-S1)", "col u128", "col u128 red88", "limb21 x4", "limb21 karatsuba x3", "karatsuba 1 lvl", "karatsuba 2 lvl", "col unrolled", "library pqz_ntt_basemul" };
  bm_fn fns[] = { bm_e1, bm_col, bm_col2, bm_limb, bm_limb3, bm_kara1, bm_kara2, bm_colu, bm_lib };
  int bad = 0;

  for (int n = 0; n < N; n++)
    for (int k = 0; k < 64; k++)
      {
        A[n][k] = rnd () % Q, B[n][k] = rnd () % Q;
        if (n < 4) /* edge values */
          A[n][k] = Q - 1 - (n & 1), B[n][k] = Q - 1 - (n >> 1);
      }

  /* correctness through the NTT against the schoolbook reference */
  for (int n = 0; n < 64; n++)
    {
      uint64_t ref[64], a[64], b[64], r[64];
      pqz_poly_mul_ref (ref, A[n], B[n]);
      memcpy (a, A[n], sizeof a), memcpy (b, B[n], sizeof b);
      pqz_ntt_fwd (a), pqz_ntt_fwd (b);
      for (unsigned f = 0; f < sizeof fns / sizeof fns[0]; f++)
        {
          basemul (fns[f], r, a, b);
          pqz_ntt_inv (r);
          if (memcmp (r, ref, sizeof r))
            printf ("MISMATCH %s n=%d\n", names[f], n), bad = 1;
        }
    }

  for (unsigned f = 0; f < sizeof fns / sizeof fns[0]; f++)
    {
      double best = 1e30;
      for (int rep = 0; rep < 7; rep++)
        {
          double t0 = now_ns ();
          for (int it = 0; it < 20; it++)
            for (int n = 0; n < N; n++)
              basemul (fns[f], R[n], A[n], B[(n + it) % N]);
          double t = (now_ns () - t0) / (20.0 * N);
          if (t < best)
            best = t;
        }
      printf ("%-22s %8.1f ns per pointwise product (4 blocks), best of 7\n", names[f], best);
    }
  return bad;
}
