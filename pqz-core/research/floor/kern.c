/*
 * PQZL verifier floor: unit costs of the primitives a specialised LNP22 / tbox verifier needs
 * (docs/research/pqz-verifier-floor.md). Prints JSON lines {"op": ..., "ns": ...}, median of 7 reps.
 *
 * Built by floor/build.sh in two variants from this one source:
 *   kern_portable  clang -O2, generic x86-64 (as pqz-core ships), no intrinsics
 *   kern_native    clang -O3 -march=native: adds the AVX2 kernels (__AVX2__) and OpenSSL (AES-NI, SHAKE128)
 *
 * Kernels, each checked against an oracle before it is timed (assert):
 *   - the fork's ring arithmetic mod q = 2^42 - 215 (incomplete NTT, 4 x 16 blocks): raw pqz_ntt_* and LaZer's poly_mul
 *   - the same representation with lazy u128 accumulation over a whole mat-vec row
 *   - CRT over 3 NTT-friendly 30-bit primes (complete negacyclic NTT, 32-bit Montgomery): scalar and AVX2
 *   - prototypes of the two biggest mandatory terms: the ABDLOP mat-vec w = A1 z1 + A2' z21 - c 2^D tA1
 *     (R_TX 23 x 198) end to end, and the JL fold vR = V^T R (lambda = 4 challenge rows, 256 x nex*d ternary R)
 *   - PRG / hash: the fork's AES-256-CTR (bitsliced) and SHAKE128, OpenSSL's (native build only)
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lazer.h"
#include "pqz_ntt.h"
#include "pqz_tx_params.h"

#ifdef __AVX2__
#include <immintrin.h>
#endif
#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#endif

void pqz_arena_init (void *mem, size_t len);

/* ---------------------------------------------------------------- timing */

static double
now (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e9 + t.tv_nsec;
}
static int
cmpd (const void *a, const void *b)
{
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}
#define REPS 7
static int quick; /* KERN_QUICK=1: run every kernel and check once, no timing (smoke test) */
#define BENCH(name, unit, iters, body)                                                                         \
  do                                                                                                           \
    {                                                                                                          \
      double tv_[REPS] = { 0 };                                                                                \
      for (int r_ = 0; r_ < (quick ? 1 : REPS); r_++)                                                          \
        {                                                                                                      \
          double t0_ = now ();                                                                                 \
          for (long it = 0; it < (quick ? 1 : (iters)); it++)                                                  \
            {                                                                                                  \
              body;                                                                                            \
            }                                                                                                  \
          tv_[r_] = (now () - t0_) / (iters);                                                                  \
        }                                                                                                      \
      qsort (tv_, REPS, sizeof (double), cmpd);                                                                \
      printf ("{\"op\": \"%s\", \"unit\": \"%s\", \"ns\": %.1f}\n", name, unit, tv_[REPS / 2]);               \
      fflush (stdout);                                                                                         \
    }                                                                                                          \
  while (0)

static uint64_t xs = 0x9E3779B97F4A7C15ULL;
static uint64_t
rnd (void)
{
  xs ^= xs >> 12, xs ^= xs << 25, xs ^= xs >> 27;
  return xs * 2685821657736338717ULL;
}
static volatile uint64_t sink;

/* ---------------------------------------------------------------- mod q (fork representation) */

#define Q PQZ_Q
#define MASK42 ((((uint64_t)1) << 42) - 1)
static uint64_t
mulq (uint64_t a, uint64_t b)
{
  return pqz_red128 ((pqz_u128)a * b);
}
static uint64_t
addq (uint64_t a, uint64_t b)
{
  return pqz_csubq (a + b);
}
static uint64_t
subq (uint64_t a, uint64_t b)
{
  return pqz_csubq (a + Q - b);
}
static uint64_t
modq_i64 (int64_t v)
{
  if (v > -(int64_t)Q && v < (int64_t)Q) /* the usual case: no division */
    return (uint64_t)(v + ((int64_t)Q & (v >> 63)));
  int64_t r = v % (int64_t)Q;
  return (uint64_t)(r < 0 ? r + (int64_t)Q : r);
}

/* r[i] = sum_j A[i][j] * z[j] in the fork's NTT domain, u128 accumulators over the whole row, one reduction
   per output coefficient (products < 2^84, <= 2^12 terms) */
static void
mv_q_lazy (uint64_t *r, const uint64_t *A, const uint64_t *z, unsigned rows, unsigned cols)
{
  static const uint64_t rho[4] = { 3367489746414ULL, Q - 3367489746414ULL, 969320936632ULL, Q - 969320936632ULL };
  for (unsigned i = 0; i < rows; i++)
    {
      pqz_u128 lo[64] = { 0 }, hi[64] = { 0 };
      for (unsigned j = 0; j < cols; j++)
        {
          const uint64_t *a = A + ((size_t)i * cols + j) * 64, *b = z + (size_t)j * 64;
          for (unsigned blk = 0; blk < 4; blk++)
            for (unsigned u = 0; u < 16; u++)
              for (unsigned v = 0; v < 16; v++)
                {
                  pqz_u128 p = (pqz_u128)a[16 * blk + u] * b[16 * blk + v];
                  if (u + v < 16)
                    lo[16 * blk + u + v] += p;
                  else
                    hi[16 * blk + u + v - 16] += p;
                }
        }
      for (unsigned blk = 0; blk < 4; blk++)
        for (unsigned k = 0; k < 16; k++)
          r[(size_t)i * 64 + 16 * blk + k]
              = addq (pqz_red128 (lo[16 * blk + k]), mulq (rho[blk], pqz_red128 (hi[16 * blk + k])));
    }
}

/* ---------------------------------------------------------------- CRT: 3 x 30-bit primes, complete NTT */

#include "kern_core.h"
static pqz_u128 CRT_M, CRT_Mi[NP]; /* x = sum (x_i * CRT_inv[i] mod p_i) * M / p_i mod M */
static uint64_t CRT_inv[NP];
static void
crt_init (void)
{
  primes_init ();
  CRT_M = 1;
  for (int i = 0; i < NP; i++)
    CRT_M *= PR[i].p;
  for (int i = 0; i < NP; i++)
    {
      CRT_Mi[i] = CRT_M / PR[i].p;
      CRT_inv[i] = powm ((uint64_t)(CRT_Mi[i] % PR[i].p), PR[i].p - 2, PR[i].p);
    }
}

static uint32_t
mod_i64 (int64_t v, uint32_t p)
{
  if (v > -(int64_t)p && v < (int64_t)p) /* short operands (z, c): no division */
    return (uint32_t)(v + ((int64_t)p & (v >> 63)));
  int64_t r = v % (int64_t)p;
  return (uint32_t)(r < 0 ? r + p : r);
}
/* residues -> centred integer -> mod q */
static uint64_t
crt_modq (const uint32_t x[NP])
{
  pqz_u128 s = 0;
  for (int i = 0; i < NP; i++)
    s += CRT_Mi[i] * ((uint64_t)x[i] * CRT_inv[i] % PR[i].p); /* < M each */
  while (s >= CRT_M)
    s -= CRT_M;
  if (s > CRT_M / 2)
    return pqz_csubq (Q - pqz_red128 (CRT_M - s));
  return pqz_red128 (s);
}

static void
negacyclic_ref_p (uint32_t r[64], const uint32_t a[64], const uint32_t b[64], uint32_t p)
{
  for (int k = 0; k < 64; k++)
    {
      uint64_t pos = 0, neg = 0;
      for (int i = 0; i < 64; i++)
        {
          int j = k - i;
          if (j >= 0)
            pos = (pos + (uint64_t)a[i] * b[j]) % p;
          else
            neg = (neg + (uint64_t)a[i] * b[j + 64]) % p;
        }
      r[k] = (uint32_t)((pos + p - neg) % p);
    }
}

#ifdef __AVX2__
/* 4 polynomials side by side: a[64 * 4], lane l of coefficient c at a[4 c + l], one 32-bit value per 64-bit lane */
static inline __m256i
mont4 (__m256i a, __m256i b, __m256i pv, __m256i pinvv)
{
  __m256i t = _mm256_mul_epu32 (a, b);
  __m256i m = _mm256_mul_epu32 (_mm256_mul_epu32 (t, pinvv), pv);
  return _mm256_srli_epi64 (_mm256_add_epi64 (t, m), 32);
}
static inline __m256i
csub4 (__m256i x, __m256i m)
{
  __m256i t = _mm256_sub_epi64 (x, m);
  return _mm256_add_epi64 (t, _mm256_and_si256 (_mm256_cmpgt_epi64 (_mm256_setzero_si256 (), t), m));
}
static void
ntt_fwd4 (uint64_t *a, const prime_t *P)
{
  const __m256i pv = _mm256_set1_epi64x (P->p), pinvv = _mm256_set1_epi64x (P->pinv),
                p2 = _mm256_set1_epi64x (2 * (uint64_t)P->p);
  unsigned k = 1;
  for (unsigned len = 32; len >= 1; len >>= 1)
    for (unsigned s = 0; s < 64; s += 2 * len)
      {
        const __m256i z = _mm256_set1_epi64x (P->zetas[k++]);
        for (unsigned j = s; j < s + len; j++)
          {
            __m256i x = _mm256_loadu_si256 ((__m256i *)(a + 4 * j));
            __m256i t = mont4 (z, _mm256_loadu_si256 ((__m256i *)(a + 4 * (j + len))), pv, pinvv);
            _mm256_storeu_si256 ((__m256i *)(a + 4 * (j + len)),
                                 csub4 (_mm256_sub_epi64 (_mm256_add_epi64 (x, p2), t), p2));
            _mm256_storeu_si256 ((__m256i *)(a + 4 * j), csub4 (_mm256_add_epi64 (x, t), p2));
          }
      }
}
static void
ntt_inv4 (uint64_t *a, const prime_t *P)
{
  const __m256i pv = _mm256_set1_epi64x (P->p), pinvv = _mm256_set1_epi64x (P->pinv),
                p2 = _mm256_set1_epi64x (2 * (uint64_t)P->p), F = _mm256_set1_epi64x (P->F);
  unsigned k = 64;
  for (unsigned len = 1; len < 64; len <<= 1)
    for (unsigned s = 0; s < 64; s += 2 * len)
      {
        const __m256i z = _mm256_set1_epi64x (P->p - P->zetas[--k]);
        for (unsigned j = s; j < s + len; j++)
          {
            __m256i x = _mm256_loadu_si256 ((__m256i *)(a + 4 * j));
            __m256i y = _mm256_loadu_si256 ((__m256i *)(a + 4 * (j + len)));
            _mm256_storeu_si256 ((__m256i *)(a + 4 * j), csub4 (_mm256_add_epi64 (x, y), p2));
            _mm256_storeu_si256 ((__m256i *)(a + 4 * (j + len)),
                                 mont4 (z, _mm256_sub_epi64 (_mm256_add_epi64 (x, p2), y), pv, pinvv));
          }
      }
  for (unsigned j = 0; j < 64; j++)
    _mm256_storeu_si256 ((__m256i *)(a + 4 * j),
                         csub4 (mont4 (_mm256_loadu_si256 ((__m256i *)(a + 4 * j)), F, pv, pinvv), pv));
}
static void
pw_acc4 (uint64_t *acc, const uint64_t *a, const uint64_t *b, const prime_t *P)
{
  const __m256i pv = _mm256_set1_epi64x (P->p), pinvv = _mm256_set1_epi64x (P->pinv);
  for (unsigned j = 0; j < 64; j++)
    {
      __m256i s = _mm256_loadu_si256 ((__m256i *)(acc + 4 * j));
      __m256i t = mont4 (_mm256_loadu_si256 ((__m256i *)(a + 4 * j)), _mm256_loadu_si256 ((__m256i *)(b + 4 * j)),
                         pv, pinvv);
      _mm256_storeu_si256 ((__m256i *)(acc + 4 * j), _mm256_add_epi64 (s, t));
    }
}
#endif

/* ---------------------------------------------------------------- ABDLOP mat-vec prototype */

/* w = A z + c * T (rows x cols NTT-precomputed A, cols short z, per-row T = -2^D tA1, short c), all mod q.
   Mirrors lnp_quad_verify: polyvec_mul (A1, z1) + polyvec_addmul (A2', z21) - (c << D) tA1. */
typedef struct
{
  unsigned rows, cols;
  int64_t *A;   /* rows x cols x 64 coefficients, centred mod q */
  int64_t *z;   /* cols x 64, short */
  int64_t *T;   /* rows x 64, centred mod q */
  int64_t c[64];
  uint64_t *w;  /* oracle result rows x 64 */
} mv_t;

static void
mv_setup (mv_t *M, unsigned rows, unsigned cols)
{
  M->rows = rows, M->cols = cols;
  M->A = malloc (sizeof (int64_t) * rows * cols * 64);
  M->z = malloc (sizeof (int64_t) * cols * 64);
  M->T = malloc (sizeof (int64_t) * rows * 64);
  M->w = malloc (sizeof (uint64_t) * rows * 64);
  for (size_t i = 0; i < (size_t)rows * cols * 64; i++)
    M->A[i] = (int64_t)(rnd () % Q) - (int64_t)(Q / 2);
  for (size_t i = 0; i < (size_t)cols * 64; i++)
    M->z[i] = (int64_t)(rnd () % (1u << 22)) - (1 << 21); /* |z1| < 2^21: 5 sigma1 = 2^20.95 */
  for (size_t i = 0; i < (size_t)rows * 64; i++)
    M->T[i] = (int64_t)(rnd () % Q) - (int64_t)(Q / 2);
  for (int i = 0; i < 64; i++)
    M->c[i] = (int64_t)(rnd () % 17) - 8; /* omega = 8 */
  /* oracle: the fork's mod-q arithmetic, one basemul per product */
  uint64_t a[64], b[64], t[64], acc[64];
  for (unsigned i = 0; i < rows; i++)
    {
      memset (acc, 0, sizeof acc);
      for (unsigned j = 0; j <= cols; j++)
        {
          for (int k = 0; k < 64; k++)
            {
              a[k] = modq_i64 (j < cols ? M->A[((size_t)i * cols + j) * 64 + k] : M->T[(size_t)i * 64 + k]);
              b[k] = modq_i64 (j < cols ? M->z[(size_t)j * 64 + k] : M->c[k]);
            }
          pqz_ntt_fwd (a), pqz_ntt_fwd (b), pqz_ntt_basemul (t, a, b);
          for (int k = 0; k < 64; k++)
            acc[k] = addq (acc[k], t[k]);
        }
      pqz_ntt_inv (acc);
      memcpy (M->w + (size_t)i * 64, acc, sizeof acc);
    }
}

/* (a) fork representation, one basemul + add per product (what LaZer's polyvec_mul does, minus its overheads) */
typedef struct
{
  uint64_t *Ah, *Th; /* NTT form, per parameter set / per proof */
} mvq_t;
static void
mvq_pre (mvq_t *X, const mv_t *M)
{
  X->Ah = malloc (sizeof (uint64_t) * M->rows * M->cols * 64);
  for (size_t i = 0; i < (size_t)M->rows * M->cols; i++)
    {
      for (int k = 0; k < 64; k++)
        X->Ah[i * 64 + k] = modq_i64 (M->A[i * 64 + k]);
      pqz_ntt_fwd (X->Ah + i * 64);
    }
}
static void
mvq_run (uint64_t *w, const mvq_t *X, const mv_t *M, int lazy, uint64_t *zh /* (cols + 1) x 64 scratch */,
         uint64_t *Th /* rows x 64 scratch */)
{
  const unsigned rows = M->rows, cols = M->cols;
  for (unsigned j = 0; j < cols; j++)
    {
      for (int k = 0; k < 64; k++)
        zh[j * 64 + k] = modq_i64 (M->z[(size_t)j * 64 + k]);
      pqz_ntt_fwd (zh + j * 64);
    }
  for (int k = 0; k < 64; k++)
    zh[(size_t)cols * 64 + k] = modq_i64 (M->c[k]);
  pqz_ntt_fwd (zh + (size_t)cols * 64);
  for (unsigned i = 0; i < rows; i++)
    {
      for (int k = 0; k < 64; k++)
        Th[i * 64 + k] = modq_i64 (M->T[(size_t)i * 64 + k]);
      pqz_ntt_fwd (Th + i * 64);
    }
  if (lazy)
    mv_q_lazy (w, X->Ah, zh, rows, cols);
  uint64_t t[64];
  for (unsigned i = 0; i < rows; i++)
    {
      uint64_t *acc = w + (size_t)i * 64;
      if (!lazy)
        {
          memset (acc, 0, 64 * sizeof (uint64_t));
          for (unsigned j = 0; j < cols; j++)
            {
              pqz_ntt_basemul (t, X->Ah + ((size_t)i * cols + j) * 64, zh + (size_t)j * 64);
              for (int k = 0; k < 64; k++)
                acc[k] = addq (acc[k], t[k]);
            }
        }
      pqz_ntt_basemul (t, Th + i * 64, zh + (size_t)cols * 64);
      for (int k = 0; k < 64; k++)
        acc[k] = addq (acc[k], t[k]);
      pqz_ntt_inv (acc);
    }
}

/* (b) CRT scalar */
typedef struct
{
  uint32_t *Ah; /* NP x rows x cols x 64, NTT, Montgomery-lifted (x R) so one pw_acc gives the plain product */
} mvc_t;
static void
mvc_pre (mvc_t *X, const mv_t *M)
{
  const size_t n = (size_t)M->rows * M->cols;
  X->Ah = malloc (sizeof (uint32_t) * NP * n * 64);
  for (int pi = 0; pi < NP; pi++)
    for (size_t i = 0; i < n; i++)
      {
        uint32_t *a = X->Ah + (pi * n + i) * 64;
        for (int k = 0; k < 64; k++)
          a[k] = tomont (mod_i64 (M->A[i * 64 + k], PR[pi].p), &PR[pi]);
        ntt_fwd (a, &PR[pi]);
      }
}
static void
mvc_run (uint64_t *w, const mvc_t *X, const mv_t *M, uint32_t *zh /* (cols + 1) x 64 */, uint32_t *Th,
         uint64_t *acc /* rows x 64 */, uint32_t *res /* NP x rows x 64 */)
{
  const unsigned rows = M->rows, cols = M->cols;
  const size_t n = (size_t)rows * cols;
  for (int pi = 0; pi < NP; pi++)
    {
      const prime_t *P = &PR[pi];
      for (unsigned j = 0; j < cols; j++)
        {
          for (int k = 0; k < 64; k++)
            zh[j * 64 + k] = mod_i64 (M->z[(size_t)j * 64 + k], P->p);
          ntt_fwd (zh + j * 64, P);
        }
      for (int k = 0; k < 64; k++)
        zh[(size_t)cols * 64 + k] = mod_i64 (M->c[k], P->p);
      ntt_fwd (zh + (size_t)cols * 64, P);
      memset (acc, 0, sizeof (uint64_t) * rows * 64);
      for (unsigned i = 0; i < rows; i++)
        {
          for (int k = 0; k < 64; k++)
            Th[k] = tomont (mod_i64 (M->T[(size_t)i * 64 + k], P->p), P);
          ntt_fwd (Th, P);
          uint64_t *ai = acc + (size_t)i * 64;
          for (unsigned j = 0; j < cols; j++)
            pw_acc (ai, X->Ah + ((size_t)pi * n + (size_t)i * cols + j) * 64, zh + j * 64, P);
          pw_acc (ai, Th, zh + (size_t)cols * 64, P);
          uint32_t *r = res + ((size_t)pi * rows + i) * 64;
          for (int k = 0; k < 64; k++)
            r[k] = (uint32_t)(ai[k] % P->p);
          ntt_inv (r, P);
        }
    }
  for (unsigned i = 0; i < rows; i++)
    for (int k = 0; k < 64; k++)
      {
        uint32_t x[NP];
        for (int pi = 0; pi < NP; pi++)
          x[pi] = res[((size_t)pi * rows + i) * 64 + k];
        w[(size_t)i * 64 + k] = crt_modq (x);
      }
}

#ifdef __AVX2__
/* (c) CRT AVX2: groups of 4 columns side by side, partial sums per lane, lanes summed after the row */
typedef struct
{
  unsigned g;   /* column groups of 4 (cols + 1 rounded up: the c * T column is folded in per row) */
  uint64_t *Ah; /* NP x rows x g x 256 */
} mva_t;
static void
mva_pre (mva_t *X, const mv_t *M)
{
  const unsigned rows = M->rows, cols = M->cols;
  X->g = (cols + 3) / 4;
  X->Ah = calloc ((size_t)NP * rows * X->g * 256, sizeof (uint64_t));
  for (int pi = 0; pi < NP; pi++)
    for (unsigned i = 0; i < rows; i++)
      for (unsigned gj = 0; gj < X->g; gj++)
        {
          uint64_t *a = X->Ah + (((size_t)pi * rows + i) * X->g + gj) * 256;
          for (unsigned l = 0; l < 4; l++)
            for (int k = 0; k < 64; k++)
              {
                unsigned j = 4 * gj + l;
                a[4 * k + l] = j < cols ? tomont (mod_i64 (M->A[((size_t)i * cols + j) * 64 + k], PR[pi].p), &PR[pi]) : 0;
              }
          ntt_fwd4 (a, &PR[pi]);
        }
}
static void
mva_run (uint64_t *w, const mva_t *X, const mv_t *M, uint64_t *zh /* g x 256 */, uint64_t *Th /* 4 rows x 256 */,
         uint64_t *acc /* 256 */, uint32_t *res /* NP x rows x 64 */)
{
  const unsigned rows = M->rows, cols = M->cols, g = X->g;
  for (int pi = 0; pi < NP; pi++)
    {
      const prime_t *P = &PR[pi];
      for (unsigned gj = 0; gj < g; gj++)
        {
          uint64_t *b = zh + (size_t)gj * 256;
          for (unsigned l = 0; l < 4; l++)
            {
              unsigned j = 4 * gj + l;
              for (int k = 0; k < 64; k++)
                b[4 * k + l] = j < cols ? mod_i64 (M->z[(size_t)j * 64 + k], P->p) : 0;
            }
          ntt_fwd4 (b, P);
        }
      /* c in all 4 lanes (one NTT, counted once per 4 rows here: negligible) and T 4 rows at a time */
      uint64_t ch[256];
      for (int k = 0; k < 64; k++)
        for (unsigned l = 0; l < 4; l++)
          ch[4 * k + l] = mod_i64 (M->c[k], P->p);
      ntt_fwd4 (ch, P);
      for (unsigned i0 = 0; i0 < rows; i0 += 4)
        {
          for (unsigned l = 0; l < 4; l++)
            for (int k = 0; k < 64; k++)
              Th[4 * k + l] = i0 + l < rows ? tomont (mod_i64 (M->T[(size_t)(i0 + l) * 64 + k], P->p), P) : 0;
          ntt_fwd4 (Th, P);
          uint64_t cT[256];
          memset (cT, 0, sizeof cT);
          pw_acc4 (cT, Th, ch, P); /* lane l = row i0 + l */
          for (unsigned l = 0; l < 4 && i0 + l < rows; l++)
            {
              const unsigned i = i0 + l;
              memset (acc, 0, 256 * sizeof (uint64_t));
              for (unsigned gj = 0; gj < g; gj++)
                pw_acc4 (acc, X->Ah + (((size_t)pi * rows + i) * g + gj) * 256, zh + (size_t)gj * 256, P);
              uint32_t *r = res + ((size_t)pi * rows + i) * 64;
              for (int k = 0; k < 64; k++)
                r[k] = (uint32_t)((acc[4 * k] + acc[4 * k + 1] + acc[4 * k + 2] + acc[4 * k + 3] + cT[4 * k + l])
                                  % P->p);
            }
        }
      /* inverse NTTs 4 rows at a time */
      for (unsigned i0 = 0; i0 < rows; i0 += 4)
        {
          uint64_t t[256];
          for (unsigned l = 0; l < 4; l++)
            for (int k = 0; k < 64; k++)
              t[4 * k + l] = i0 + l < rows ? res[((size_t)pi * rows + i0 + l) * 64 + k] : 0;
          ntt_inv4 (t, P);
          for (unsigned l = 0; l < 4 && i0 + l < rows; l++)
            for (int k = 0; k < 64; k++)
              res[((size_t)pi * rows + i0 + l) * 64 + k] = (uint32_t)t[4 * k + l];
        }
    }
  for (unsigned i = 0; i < rows; i++)
    for (int k = 0; k < 64; k++)
      {
        uint32_t x[NP];
        for (int pi = 0; pi < NP; pi++)
          x[pi] = res[((size_t)pi * rows + i) * 64 + k];
        w[(size_t)i * 64 + k] = crt_modq (x);
      }
}
#endif

/* ---------------------------------------------------------------- JL fold prototype */

#ifdef __AVX2__
/* lanes = 4 adjacent columns, one accumulator vector per challenge row, column tiles of 256 (L1) */
static void
jl_avx2 (int64_t *acc /* 4 x ncols, k-major */, const uint8_t *R, const int64_t V[4][JLR], unsigned ncols)
{
  const unsigned rb = 2 * ncols / 8, T = 256;
  __m256i lut[16];
  for (int n = 0; n < 16; n++)
    lut[n] = _mm256_set_epi64x (-(int64_t)((n >> 3) & 1), -(int64_t)((n >> 2) & 1), -(int64_t)((n >> 1) & 1),
                                -(int64_t)(n & 1));
  memset (acc, 0, sizeof (int64_t) * ncols * 4);
  for (unsigned t0 = 0; t0 < ncols; t0 += T)
    {
      const unsigned t1 = t0 + T < ncols ? t0 + T : ncols;
      for (unsigned i = 0; i < JLR; i++)
        {
          const uint8_t *row = R + (size_t)i * rb;
          const __m256i v0 = _mm256_set1_epi64x (V[0][i]), v1 = _mm256_set1_epi64x (V[1][i]),
                        v2 = _mm256_set1_epi64x (V[2][i]), v3 = _mm256_set1_epi64x (V[3][i]);
          for (unsigned j = t0; j < t1; j += 4)
            {
              const __m256i m1 = lut[(row[j >> 3] >> (j & 4)) & 15];
              const __m256i m2 = lut[(row[(ncols + j) >> 3] >> ((ncols + j) & 4)) & 15];
#define JL1(K, VV)                                                                                             \
  {                                                                                                            \
    __m256i *p = (__m256i *)(acc + (size_t)(K) * ncols + j);                                                   \
    __m256i s = _mm256_loadu_si256 (p);                                                                        \
    s = _mm256_add_epi64 (s, _mm256_and_si256 (VV, m1));                                                       \
    s = _mm256_sub_epi64 (s, _mm256_and_si256 (VV, m2));                                                       \
    _mm256_storeu_si256 (p, s);                                                                                \
  }
              JL1 (0, v0) JL1 (1, v1) JL1 (2, v2) JL1 (3, v3)
            }
        }
    }
}
#endif

/* ---------------------------------------------------------------- main */

int
main (void)
{
  static char arena[64 << 20];
  pqz_arena_init (arena, sizeof arena);
  quick = getenv ("KERN_QUICK") != NULL;
  crt_init ();
  printf ("{\"build\": \"%s\", \"primes\": [%u, %u, %u]}\n",
#ifdef __AVX2__
          "native (AVX2 kernels on)",
#else
          "portable",
#endif
          PR[0].p, PR[1].p, PR[2].p);

  /* ---- self-checks of the CRT NTT against the schoolbook product mod p */
  for (int pi = 0; pi < NP; pi++)
    {
      uint32_t a[64], b[64], r[64], ref[64];
      uint64_t acc[64] = { 0 };
      for (int k = 0; k < 64; k++)
        a[k] = rnd () % PR[pi].p, b[k] = rnd () % PR[pi].p;
      negacyclic_ref_p (ref, a, b, PR[pi].p);
      uint32_t ah[64], bh[64];
      for (int k = 0; k < 64; k++)
        ah[k] = tomont (a[k], &PR[pi]), bh[k] = b[k];
      ntt_fwd (ah, &PR[pi]), ntt_fwd (bh, &PR[pi]);
      pw_acc (acc, ah, bh, &PR[pi]);
      for (int k = 0; k < 64; k++)
        r[k] = (uint32_t)(acc[k] % PR[pi].p);
      ntt_inv (r, &PR[pi]);
      assert (memcmp (r, ref, sizeof r) == 0);
#ifdef __AVX2__
      uint64_t a4[256], b4[256], c4[256] = { 0 };
      for (int k = 0; k < 64; k++)
        for (int l = 0; l < 4; l++)
          a4[4 * k + l] = tomont (a[k], &PR[pi]), b4[4 * k + l] = b[k];
      ntt_fwd4 (a4, &PR[pi]), ntt_fwd4 (b4, &PR[pi]);
      for (int k = 0; k < 64; k++)
        assert (a4[4 * k + 3] == ah[k] && b4[4 * k] == bh[k]);
      pw_acc4 (c4, a4, b4, &PR[pi]);
      for (int k = 0; k < 256; k++)
        c4[k] %= PR[pi].p;
      ntt_inv4 (c4, &PR[pi]);
      for (int k = 0; k < 64; k++)
        assert (c4[4 * k + 2] == ref[k]);
#endif
    }

  /* ---- 1. ring primitives */
  {
    uint64_t a[64], b[64], r[64];
    for (int k = 0; k < 64; k++)
      a[k] = rnd () % Q, b[k] = rnd () % Q;
    BENCH ("fork pqz_ntt_fwd (mod q, 2 layers, 4 x 16 blocks)", "per poly", 200000, {
      pqz_ntt_fwd (a);
      sink += a[0];
    });
    BENCH ("fork pqz_ntt_inv", "per poly", 200000, {
      pqz_ntt_inv (a);
      sink += a[0];
    });
    BENCH ("fork pqz_ntt_basemul (pointwise product, 4 x 16x16 schoolbook)", "per product", 200000, {
      pqz_ntt_basemul (r, a, b);
      a[0] = r[1];
    });
    sink += a[0];
    uint64_t x[4096];
    for (int k = 0; k < 4096; k++)
      x[k] = rnd () % Q;
    BENCH ("scalar mod-q multiply (u128 product + pqz_red128)", "per 4096 dependent mulmods", 200, {
      uint64_t s = 1;
      for (int k = 0; k < 4096; k++)
        s = mulq (s ^ (uint64_t)k, x[k]);
      sink += s;
    });
  }
  {
    /* LaZer's poly_mul at the API level (int_t limbs, crt flags; the xcheck number) */
    polyring_srcptr Rq = pqz_tx_ring;
    uint8_t seed[32] = { 7 };
    poly_t a, b, r;
    poly_alloc (a, Rq), poly_alloc (b, Rq), poly_alloc (r, Rq);
    poly_urandom (a, Rq->q, Rq->log2q, seed, 0), poly_urandom (b, Rq->q, Rq->log2q, seed, 1);
    poly_tocrt (a), poly_tocrt (b);
    BENCH ("fork LaZer poly_mul, both in NTT form (API level)", "per product", 200000, { poly_mul (r, a, b); });
  }
  {
    uint32_t a[64], b[64];
    uint64_t acc[64] = { 0 };
    const prime_t *P = &PR[0];
    for (int k = 0; k < 64; k++)
      a[k] = rnd () % P->p, b[k] = rnd () % P->p;
    BENCH ("crt30 ntt_fwd, one prime (scalar)", "per poly per prime", 200000, {
      ntt_fwd (a, P);
      sink += a[0];
    });
    BENCH ("crt30 ntt_inv, one prime (scalar)", "per poly per prime", 200000, {
      ntt_inv (a, P);
      sink += a[0];
    });
    BENCH ("crt30 pointwise multiply-accumulate, one prime (scalar)", "per product per prime", 1000000, {
      pw_acc (acc, a, b, P);
      a[it & 63] ^= 1;
    });
    sink += acc[5];
#ifdef __AVX2__
    uint64_t a4[256], b4[256], c4[256] = { 0 };
    for (int k = 0; k < 256; k++)
      a4[k] = rnd () % P->p, b4[k] = rnd () % P->p;
    BENCH ("crt30 ntt_fwd x4 (AVX2, 4 polys per call)", "per 4 polys per prime", 200000, {
      ntt_fwd4 (a4, P);
      sink += a4[0];
    });
    BENCH ("crt30 ntt_inv x4 (AVX2)", "per 4 polys per prime", 200000, {
      ntt_inv4 (a4, P);
      sink += a4[0];
    });
    BENCH ("crt30 pointwise multiply-accumulate x4 (AVX2)", "per 4 products per prime", 1000000, {
      pw_acc4 (c4, a4, b4, P);
      a4[it & 255] ^= 1;
    });
    sink += c4[5];
#endif
  }

  /* ---- 2. ABDLOP mat-vec prototype at R_TX (23 x 153+45) and R_REG (22 x 66+45) */
  const unsigned shapes[2][3] = { { 23, 153 + 45, 1 }, { 22, 66 + 45, 0 } };
  for (int s = 0; s < 2; s++)
    {
      mv_t M;
      mv_setup (&M, shapes[s][0], shapes[s][1]);
      const char *rel = shapes[s][2] ? "R_TX" : "R_REG";
      const unsigned rows = M.rows, cols = M.cols;
      uint64_t *w = malloc (sizeof (uint64_t) * rows * 64);
      char nm[160];
      mvq_t X;
      mvq_pre (&X, &M);
      uint64_t *zh = malloc (sizeof (uint64_t) * (cols + 1) * 64), *Th = malloc (sizeof (uint64_t) * rows * 64);
      mvq_run (w, &X, &M, 0, zh, Th);
      assert (memcmp (w, M.w, sizeof (uint64_t) * rows * 64) == 0);
      snprintf (nm, sizeof nm, "%s w = A1 z1 + A2' z21 - c 2^D tA1 (%u x %u), fork basemul per product", rel, rows, cols);
      BENCH (nm, "per mat-vec", 5, mvq_run (w, &X, &M, 0, zh, Th));
      mvq_run (w, &X, &M, 1, zh, Th);
      assert (memcmp (w, M.w, sizeof (uint64_t) * rows * 64) == 0);
      snprintf (nm, sizeof nm, "%s w mat-vec, fork representation, lazy u128 row accumulation", rel);
      BENCH (nm, "per mat-vec", 5, mvq_run (w, &X, &M, 1, zh, Th));

      mvc_t C;
      mvc_pre (&C, &M);
      uint32_t *zc = malloc (sizeof (uint32_t) * (cols + 1) * 64), Tc[64];
      uint64_t *acc = malloc (sizeof (uint64_t) * rows * 64);
      uint32_t *res = malloc (sizeof (uint32_t) * NP * rows * 64);
      mvc_run (w, &C, &M, zc, Tc, acc, res);
      assert (memcmp (w, M.w, sizeof (uint64_t) * rows * 64) == 0);
      snprintf (nm, sizeof nm, "%s w mat-vec, CRT 3 x 30-bit scalar (NTT z, T; products; INTT; CRT to mod q)", rel);
      BENCH (nm, "per mat-vec", 20, mvc_run (w, &C, &M, zc, Tc, acc, res));
#ifdef __AVX2__
      mva_t Av;
      mva_pre (&Av, &M);
      uint64_t *za = malloc (sizeof (uint64_t) * Av.g * 256), Ta[256], acc4[256];
      mva_run (w, &Av, &M, za, Ta, acc4, res);
      assert (memcmp (w, M.w, sizeof (uint64_t) * rows * 64) == 0);
      snprintf (nm, sizeof nm, "%s w mat-vec, CRT 3 x 30-bit AVX2", rel);
      BENCH (nm, "per mat-vec", 50, mva_run (w, &Av, &M, za, Ta, acc4, res));
      free (za), free (Av.Ah);
#endif
      free (zc), free (acc), free (res), free (C.Ah), free (zh), free (Th), free (X.Ah), free (w);
      free (M.A), free (M.z), free (M.T), free (M.w);
    }

  /* ---- 3. JL fold prototype: R_TX nex d = 153 x 64 = 9792, R_REG 66 x 64 = 4224; the l_inf filler 64 */
  const unsigned jlcols[3] = { 153 * 64, 66 * 64, 64 };
  const char *jlname[3] = { "R_TX", "R_REG", "filler" };
  for (int s = 0; s < 3; s++)
    {
      const unsigned nc = jlcols[s], rb = 2 * nc / 8;
      uint8_t *R = malloc ((size_t)JLR * rb);
      static int64_t V[4][JLR];
      for (size_t i = 0; i < (size_t)JLR * rb; i++)
        R[i] = (uint8_t)rnd ();
      for (int k = 0; k < 4; k++)
        for (int i = 0; i < JLR; i++)
          V[k][i] = (int64_t)(rnd () % Q);
      int64_t *a1 = malloc (sizeof (int64_t) * nc * 4), *a2 = malloc (sizeof (int64_t) * nc * 4);
      char nm[160];
      snprintf (nm, sizeof nm, "%s JL fold vR = V^T R, 4 x 256 x %u ternary, scalar branchless", jlname[s], nc);
      BENCH (nm, "per fold", 5, jl_scalar (a1, R, (const int64_t (*)[JLR])V, nc));
#ifdef __AVX2__
      jl_avx2 (a2, R, (const int64_t (*)[JLR])V, nc);
      for (unsigned j = 0; j < nc; j++)
        for (int k = 0; k < 4; k++)
          assert (a1[4 * j + k] == a2[(size_t)k * nc + j]);
      snprintf (nm, sizeof nm, "%s JL fold, AVX2 (4 columns per vector, nibble LUT, 256-column tiles)", jlname[s]);
      BENCH (nm, "per fold", 20, jl_avx2 (a2, R, (const int64_t (*)[JLR])V, nc));
#endif
      /* spot check against the plain definition */
      for (unsigned j = 0; j < nc; j += 997)
        {
          int64_t e = 0;
          for (int i = 0; i < JLR; i++)
            {
              const uint8_t *row = R + (size_t)i * rb;
              int b1 = (row[j >> 3] >> (j & 7)) & 1, b2 = (row[(nc + j) >> 3] >> ((nc + j) & 7)) & 1;
              e += V[1][i] * (b1 - b2);
            }
          assert (e == a1[4 * j + 1]);
        }
      free (R), free (a1), free (a2);
    }

  /* ---- 4. PRG and hash */
  {
    static uint8_t buf[1 << 20];
    uint8_t seed[32] = { 1 };
    rng_state_t st;
    rng_init (st, seed, 0);
    BENCH ("fork AES-256-CTR stream (bitsliced, LaZer rng_urandom)", "per MiB", 10, rng_urandom (st, buf, sizeof buf));
    rng_clear (st);
    BENCH ("fork rng_init + 16 B + clear (AES key schedule per challenge domain)", "per call", 2000, {
      rng_init (st, seed, (uint64_t)it);
      rng_urandom (st, buf, 16);
      rng_clear (st);
    });
    shake128_state_t sh;
    shake128_init (sh);
    shake128_absorb (sh, seed, 32);
    BENCH ("fork SHAKE128 squeeze", "per MiB", 10, shake128_squeeze (sh, buf, sizeof buf));
    shake128_clear (sh);
    BENCH ("fork SHAKE128 absorb 64 KiB + squeeze 32 B", "per 64 KiB", 100, {
      shake128_init (sh);
      shake128_absorb (sh, buf, 65536);
      shake128_squeeze (sh, seed, 32);
      shake128_clear (sh);
    });
  }
#ifdef WITH_OPENSSL
  {
    static uint8_t in[1 << 20], out[1 << 20];
    uint8_t key[32] = { 1 }, iv[16] = { 0 };
    int len;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new ();
    EVP_EncryptInit_ex (c, EVP_aes_256_ctr (), NULL, key, iv);
    BENCH ("OpenSSL 3.0 AES-256-CTR (AES-NI)", "per MiB", 200, EVP_EncryptUpdate (c, out, &len, in, sizeof in));
    EVP_CIPHER_CTX_free (c);
    EVP_MD_CTX *m = EVP_MD_CTX_new ();
    BENCH ("OpenSSL 3.0 SHAKE128 squeeze", "per MiB", 50, {
      EVP_DigestInit_ex (m, EVP_shake128 (), NULL);
      EVP_DigestUpdate (m, key, 32);
      EVP_DigestFinalXOF (m, out, sizeof out);
    });
    BENCH ("OpenSSL 3.0 SHAKE128 absorb 64 KiB + squeeze 32 B", "per 64 KiB", 500, {
      EVP_DigestInit_ex (m, EVP_shake128 (), NULL);
      EVP_DigestUpdate (m, in, 65536);
      EVP_DigestFinalXOF (m, key, 32);
    });
    EVP_MD_CTX_free (m);
  }
#endif
  return (int)(sink & 0);
}
