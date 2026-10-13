/*
 * PQZL verifier floor: what the fork's generic LaZer verifier actually executes for one R_REG / R_TX verify.
 * build.sh compiles src/pqz_ntt.c with its four entry points renamed to real_*; the wrappers below count every
 * call made from LaZer (forward / inverse NTT, pointwise product, 128-bit mod-q reduction) and forward it.
 * test/pqz_bench.c is linked unchanged (its main renamed) for the statements, witnesses and steps.
 *
 *   count  ->  JSON lines: per relation, counts and wall time of one honest verify (after one prove),
 *              and of one verify of a truncated proof (statement build + decode only)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "pqz_ntt.h"

uint64_t real_red128 (pqz_u128 x);
void real_ntt_fwd (uint64_t c[64]);
void real_ntt_inv (uint64_t c[64]);
void real_ntt_basemul (uint64_t r[64], const uint64_t a[64], const uint64_t b[64]);

static uint64_t n_fwd, n_inv, n_mul, n_red;

uint64_t
pqz_red128 (pqz_u128 x)
{
  n_red++;
  return real_red128 (x);
}
void
pqz_ntt_fwd (uint64_t c[64])
{
  n_fwd++;
  real_ntt_fwd (c);
}
void
pqz_ntt_inv (uint64_t c[64])
{
  n_inv++;
  real_ntt_inv (c);
}
void
pqz_ntt_basemul (uint64_t r[64], const uint64_t a[64], const uint64_t b[64])
{
  n_mul++;
  real_ntt_basemul (r, a, b);
}

int step_init (void *arena, size_t len);
int step_prove_reg (unsigned seed);
int step_prove_tx (unsigned seed);
int step_verify (int tx);
int step_verify_bad (int tx, int kind, unsigned seed);

static double
now_ms (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static void
run (int tx, int bad)
{
  n_fwd = n_inv = n_mul = n_red = 0;
  double t0 = now_ms ();
  int ok = bad ? step_verify_bad (tx, 3, 0) : step_verify (tx);
  double t = now_ms () - t0;
  printf ("{\"rel\": \"%s\", \"case\": \"%s\", \"result\": %d, \"ms\": %.1f, \"ntt_fwd\": %llu, \"ntt_inv\": %llu, "
          "\"pointwise\": %llu, \"red128_outside_ntt\": %llu}\n",
          tx ? "R_TX" : "R_REG", bad ? "truncated proof (statement + decode)" : "honest verify", ok, t,
          (unsigned long long)n_fwd, (unsigned long long)n_inv, (unsigned long long)n_mul,
          (unsigned long long)n_red);
  fflush (stdout);
}

int
main (void)
{
  const size_t len = (size_t)768 << 20;
  if (step_init (malloc (len), len) != 0)
    return 1;
  if (step_prove_reg (0) != 0 || step_prove_tx (0) != 0)
    return 1;
  for (int tx = 0; tx < 2; tx++)
    run (tx, 0), run (tx, 1);
  return 0;
}
