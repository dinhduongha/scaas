/* xcheck per-operation microbench, same source on upstream LaZer (-DUPSTREAM) and the fork (libpqz.a).
   Ring = pqz_tx_ring (d = 64, q = 2^42 - 215). Median of 7 reps; prints JSON lines in ns per op. */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lazer.h"
#include "pqz_tx_params.h"
#ifdef UPSTREAM
void lazer_init (void);
#else
void pqz_arena_init (void *mem, size_t len);
#endif

static double now (void) { struct timespec t; clock_gettime (CLOCK_MONOTONIC, &t); return t.tv_sec * 1e9 + t.tv_nsec; }
static int cmpd (const void *a, const void *b) { double x = *(const double *)a, y = *(const double *)b; return x < y ? -1 : x > y; }
#define REPS 7
#define BENCH(name, iters, body) do { double tv_[REPS]; for (int r_ = 0; r_ < REPS; r_++) { double t0 = now (); \
  for (long it_ = 0; it_ < (iters); it_++) { body; } tv_[r_] = (now () - t0) / (iters); } qsort (tv_, REPS, sizeof (double), cmpd); \
  printf ("{\"op\": \"%s\", \"ns\": %.1f}\n", name, tv_[REPS / 2]); fflush (stdout); } while (0)

int main (void)
{
#ifdef UPSTREAM
  lazer_init ();
#else
  static char arena[256 << 20];
  pqz_arena_init (arena, sizeof arena);
#endif
  polyring_srcptr Rq = pqz_tx_ring;
  uint8_t seed[32] = { 1 };
  poly_t a0, b0, a, b, r;
  poly_alloc (a0, Rq), poly_alloc (b0, Rq), poly_alloc (a, Rq), poly_alloc (b, Rq), poly_alloc (r, Rq);
  poly_urandom (a0, Rq->q, Rq->log2q, seed, 0);
  poly_urandom (b0, Rq->q, Rq->log2q, seed, 1);

  /* full product from coefficient form: 2 forward transforms + pointwise + 1 inverse */
  BENCH ("poly_mul full (coeff in, coeff out)", 20000, { poly_set (a, a0); poly_set (b, b0); poly_mul (r, a, b); poly_fromcrt (r); });
  poly_set (a, a0); poly_set (b, b0); poly_tocrt (a); poly_tocrt (b);
  BENCH ("poly_mul pointwise (both in NTT/CRT form)", 200000, { poly_mul (r, a, b); });
  BENCH ("poly_tocrt (forward)", 50000, { poly_set (r, a0); poly_tocrt (r); });
  BENCH ("poly_set (copy, baseline for the line above)", 200000, { poly_set (r, a0); });

  /* A1 * s1 at the R_TX tbox size: kmsis x m1 = 23 x 153, A1 in NTT/CRT form (as at init), s1 from coeffs */
  {
    const unsigned km = pqz_tx_tbox->kmsis, m1 = pqz_tx_tbox->m1;
    polymat_t A; polyvec_t v0, v, w;
    polymat_alloc (A, Rq, km, m1); polyvec_alloc (v0, Rq, m1); polyvec_alloc (v, Rq, m1); polyvec_alloc (w, Rq, km);
    polymat_urandom (A, Rq->q, Rq->log2q, seed, 2);
    polyvec_urandom (v0, Rq->q, Rq->log2q, seed, 3);
    polymat_tocrt (A);
    char nm[96];
    snprintf (nm, sizeof nm, "polyvec_mul A(%ux%u, NTT) * v(%u, coeff), result to coeff", km, m1, m1);
    BENCH (nm, 20, { polyvec_set (v, v0); polyvec_mul (w, A, v); polyvec_fromcrt (w); });
  }

  /* LaZer's PRG (RNG_AES256CTR on both sides): 1 MiB per op */
  {
    static uint8_t buf[1 << 20];
    rng_state_t st;
    rng_init (st, seed, 0);
    BENCH ("rng_urandom AES-256-CTR 1 MiB", 20, { rng_urandom (st, buf, sizeof buf); });
    rng_clear (st);
  }
  return 0;
}
