/*
 * PQZL verifier floor: the portable kernels of kern.c in freestanding wasm32 (no SIMD), for a measured
 * wasm / native ratio. Linked with the fork's wasm objects (build.sh wasm); driven by floor/run_wasm.mjs, which
 * supplies env.now (ns) and takes the median of 7 calls to bench().
 */
#include "lazer.h"
#include "pqz_ntt.h"

#include "kern_core.h"

double now (void); /* imported */

static uint64_t xs = 0x9E3779B97F4A7C15ULL;
static uint64_t
rnd (void)
{
  xs ^= xs >> 12, xs ^= xs << 25, xs ^= xs >> 27;
  return xs * 2685821657736338717ULL;
}

static uint64_t qa[64], qb[64], qr[64];
static uint32_t ca[64], cb[64];
static uint64_t cacc[64];
static uint8_t R[JLR * 2448];
static int64_t V[4][JLR], acc[153 * 64 * 4];
static uint8_t buf[1 << 20];
static volatile uint64_t sink;

/* 1 if every kernel matches its oracle */
int
check (void)
{
  primes_init ();
  for (int k = 0; k < 64; k++)
    qa[k] = rnd () % PQZ_Q, qb[k] = rnd () % PQZ_Q;
  uint64_t a[64], b[64], ref[64];
  for (int k = 0; k < 64; k++)
    a[k] = qa[k], b[k] = qb[k];
  pqz_poly_mul_ref (ref, a, b);
  pqz_ntt_fwd (a), pqz_ntt_fwd (b), pqz_ntt_basemul (qr, a, b), pqz_ntt_inv (qr);
  for (int k = 0; k < 64; k++)
    if (qr[k] != ref[k])
      return 0;
  for (int pi = 0; pi < NP; pi++)
    {
      uint32_t x[64], y[64];
      for (int k = 0; k < 64; k++)
        x[k] = y[k] = rnd () % PR[pi].p;
      ntt_fwd (x, &PR[pi]), ntt_inv (x, &PR[pi]);
      for (int k = 0; k < 64; k++)
        if (x[k] != y[k])
          return 0;
    }
  for (unsigned i = 0; i < sizeof R; i++)
    R[i] = (uint8_t)rnd ();
  for (int k = 0; k < 4; k++)
    for (int i = 0; i < JLR; i++)
      V[k][i] = (int64_t)(rnd () % PQZ_Q);
  const unsigned nc = 153 * 64;
  jl_scalar (acc, R, (const int64_t (*)[JLR])V, nc);
  for (unsigned j = 0; j < nc; j += 997)
    {
      int64_t e = 0;
      for (int i = 0; i < JLR; i++)
        {
          const uint8_t *row = R + (unsigned)i * (2 * nc / 8);
          e += V[2][i] * (int64_t)(((row[j >> 3] >> (j & 7)) & 1) - ((row[(nc + j) >> 3] >> ((nc + j) & 7)) & 1));
        }
      if (e != acc[4 * j + 2])
        return 0;
    }
  for (int k = 0; k < 64; k++)
    ca[k] = rnd () % PR[0].p, cb[k] = rnd () % PR[0].p;
  return 1;
}

/* ns per iteration of kernel `which` */
double
bench (int which, int iters)
{
  uint8_t seed[32] = { 1 };
  rng_state_t st;
  shake128_state_t sh;
  if (which == 7)
    rng_init (st, seed, 0);
  if (which == 9)
    shake128_init (sh), shake128_absorb (sh, seed, 32);
  double t0 = now ();
  for (int it = 0; it < iters; it++)
    switch (which)
      {
      case 0: pqz_ntt_basemul (qr, qa, qb), qa[0] = qr[1]; break;
      case 1: pqz_ntt_fwd (qa); break;
      case 2: pqz_ntt_inv (qa); break;
      case 3: ntt_fwd (ca, &PR[0]); break;
      case 4: ntt_inv (ca, &PR[0]); break;
      case 5: pw_acc (cacc, ca, cb, &PR[0]), ca[it & 63] ^= 1; break;
      case 6: jl_scalar (acc, R, (const int64_t (*)[JLR])V, 153 * 64); break;
      case 7: rng_urandom (st, buf, sizeof buf); break;
      case 8: rng_init (st, seed, (uint64_t)it), rng_urandom (st, buf, 16), rng_clear (st); break;
      case 9: shake128_squeeze (sh, buf, sizeof buf); break;
      case 10:
        shake128_init (sh), shake128_absorb (sh, buf, 65536), shake128_squeeze (sh, seed, 32), shake128_clear (sh);
        break;
      default: return -1;
      }
  double t = (now () - t0) / iters;
  if (which == 7)
    rng_clear (st);
  if (which == 9)
    shake128_clear (sh);
  sink += qa[0] + ca[0] + cacc[0] + (uint64_t)acc[0] + buf[0];
  return t;
}
