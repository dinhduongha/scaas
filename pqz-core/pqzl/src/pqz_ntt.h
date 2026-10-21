#ifndef PQZ_NTT_H
#define PQZ_NTT_H

#include <stdint.h>

/* q, its width and the ring constants come from the parameter set (params/sets/<set>/pqz_set.h, one set per build) */
#include "pqz_set.h"

#define PQZ_D 64

typedef unsigned __int128 pqz_u128;

/* a in [0, 2q) -> a mod q, constant-time */
static inline uint64_t
pqz_csubq (uint64_t a)
{
  uint64_t t = a - PQZ_Q;
  return t + (PQZ_Q & (uint64_t)((int64_t)t >> 63));
}

/* x < 2^X -> x mod q, constant-time (Barrett; L = PQZ_LOG2Q, 2^(L-1) < q < 2^L, X = PQZ_BARX = 2L + 4 <= L + 63,
   MUX = floor(2^X / q) < 2^(X-L+1)): qh = floor(floor(x / 2^(L-1)) MUX / 2^(X-L+1)) <= floor(x / q), and the three
   floors lose less than 2^(L-1) / q + x / 2^X + 1 < 3, so r = x - qh q < 3q; the product is below 2^(2X-2L+2) <= 2^128 */
static inline uint64_t
pqz_redx (pqz_u128 x)
{
  const uint64_t qh = (uint64_t)(((x >> (PQZ_LOG2Q - 1)) * PQZ_MUX) >> (PQZ_BARX - PQZ_LOG2Q + 1));
  uint64_t r = (uint64_t)x - qh * PQZ_Q; /* exact mod 2^64, and r < 3q */
  uint64_t t = r - 2 * PQZ_Q;
  r = t + (2 * PQZ_Q & (uint64_t)((int64_t)t >> 63));
  return pqz_csubq (r);
}

/* a b mod q for a, b < q (a b < 2^(2L)) */
static inline uint64_t
pqz_mulq (uint64_t a, uint64_t b)
{
  return pqz_redx ((pqz_u128)a * b);
}

/* x mod q in [0, q) for x >= -q 2^(63-L) (any int64 above that; q 2^(63-L) < 2^63): x + q 2^(63-L) < 2^64 */
static inline uint64_t
pqz_modq_i64 (int64_t x)
{
  return pqz_redx ((pqz_u128)((uint64_t)x + (PQZ_Q << (63 - PQZ_LOG2Q))));
}

uint64_t pqz_red128 (pqz_u128 x);
void pqz_ntt_fwd (uint64_t c[64]);
void pqz_ntt_inv (uint64_t c[64]);
void pqz_ntt_basemul (uint64_t r[64], const uint64_t a[64], const uint64_t b[64]);
void pqz_poly_mul_ref (uint64_t r[64], const uint64_t a[64], const uint64_t b[64]);

#endif
