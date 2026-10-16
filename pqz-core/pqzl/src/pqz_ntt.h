#ifndef PQZ_NTT_H
#define PQZ_NTT_H

#include <stdint.h>

#define PQZ_Q 4398046510889ULL /* 2^42 - 215 */
#define PQZ_D 64

typedef unsigned __int128 pqz_u128;

/* a in [0, 2q) -> a mod q, constant-time */
static inline uint64_t
pqz_csubq (uint64_t a)
{
  uint64_t t = a - PQZ_Q;
  return t + (PQZ_Q & (uint64_t)((int64_t)t >> 63));
}

uint64_t pqz_red128 (pqz_u128 x);
void pqz_ntt_fwd (uint64_t c[64]);
void pqz_ntt_inv (uint64_t c[64]);
void pqz_ntt_basemul (uint64_t r[64], const uint64_t a[64], const uint64_t b[64]);
void pqz_poly_mul_ref (uint64_t r[64], const uint64_t a[64], const uint64_t b[64]);

#endif
