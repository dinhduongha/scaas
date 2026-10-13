/*
 * pqz-core ring arithmetic for R_q = Z_q[X]/(X^64 + 1), q = 2^42 - 215 (CTR-PQZ-03), replacing LaZer's
 * CRT-over-50-bit-primes representation (Intel HEXL NTTs, __int128 '%' and a float rounding step).
 *
 * q = 9 mod 16, so X^64 + 1 = prod_{j<4} (X^16 - rho_j) with rho_j the primitive 8th roots of unity
 * (incomplete NTT, two layers): layer 1 splits X^64 + 1 = (X^32 - i)(X^32 + i), i = zeta^2; layer 2
 * splits X^32 - i = (X^16 - zeta)(X^16 + zeta) and X^32 + i = (X^16 - zeta^3)(X^16 + zeta^3).
 * The "NTT domain" is the four residues (16 coefficients each, in [0, q)); addition is coefficient-wise
 * and multiplication is a 16 x 16 schoolbook product mod X^16 - rho_j per block.
 *
 * Integer-only, constant-time: no table lookups indexed by data, no data-dependent branches.
 * Reduction uses 2^42 = 215 (mod q).
 */
#include <stdint.h>

#include "pqz_ntt.h"

#define Q PQZ_Q
#define MASK42 ((((uint64_t)1) << 42) - 1)

static const uint64_t ZETA = 3367489746414ULL;   /* primitive 8th root of unity mod q */
static const uint64_t IROOT = 2273236395452ULL;  /* zeta^2, a square root of -1 */
static const uint64_t ZETA3 = 969320936632ULL;   /* zeta^3 */
static const uint64_t INV2 = 2199023255445ULL;   /* 1/2 */
static const uint64_t INVZ = 3428725574257ULL;   /* 1/zeta */
static const uint64_t INVI = 2124810115437ULL;   /* 1/i */
static const uint64_t INVZ3 = 1030556764475ULL;  /* 1/zeta^3 */

/* x < 2^128 -> x mod q */
uint64_t
pqz_red128 (pqz_u128 x)
{
  pqz_u128 t = (x >> 42) * 215 + (x & MASK42); /* < 2^94 */
  uint64_t u = (uint64_t)(t >> 42) * 215 + (uint64_t)(t & MASK42); /* < 2^60 */
  u = (u >> 42) * 215 + (u & MASK42);                             /* < 2^42 + 2^26 */
  return pqz_csubq (u);
}

static inline uint64_t
mulq (uint64_t a, uint64_t b)
{
  return pqz_red128 ((pqz_u128)a * b);
}

static inline uint64_t
addq (uint64_t a, uint64_t b)
{
  return pqz_csubq (a + b);
}

static inline uint64_t
subq (uint64_t a, uint64_t b)
{
  return pqz_csubq (a + Q - b);
}

/* c[0..64) in [0,q) -> residues mod X^16 - zeta, X^16 + zeta, X^16 - zeta^3, X^16 + zeta^3 */
void
pqz_ntt_fwd (uint64_t c[64])
{
  for (int k = 0; k < 32; k++)
    {
      uint64_t t = mulq (IROOT, c[k + 32]);
      c[k + 32] = subq (c[k], t);
      c[k] = addq (c[k], t);
    }
  for (int k = 0; k < 16; k++)
    {
      uint64_t t = mulq (ZETA, c[k + 16]);
      c[k + 16] = subq (c[k], t);
      c[k] = addq (c[k], t);
      t = mulq (ZETA3, c[k + 48]);
      c[k + 48] = subq (c[k + 32], t);
      c[k + 32] = addq (c[k + 32], t);
    }
}

void
pqz_ntt_inv (uint64_t c[64])
{
  for (int k = 0; k < 16; k++)
    {
      uint64_t x = c[k], y = c[k + 16];
      c[k] = addq (x, y);
      c[k + 16] = mulq (subq (x, y), INVZ);
      x = c[k + 32], y = c[k + 48];
      c[k + 32] = addq (x, y);
      c[k + 48] = mulq (subq (x, y), INVZ3);
    }
  for (int k = 0; k < 32; k++)
    {
      uint64_t x = c[k], y = c[k + 32];
      c[k] = addq (x, y);
      c[k + 32] = mulq (subq (x, y), INVI);
    }
  /* both layers halve: 1/4 = INV2^2 */
  const uint64_t inv4 = mulq (INV2, INV2);
  for (int k = 0; k < 64; k++)
    c[k] = mulq (c[k], inv4);
}

static void
basemul16 (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
  pqz_u128 lo[16] = { 0 }, hi[16] = { 0 };
  for (int i = 0; i < 16; i++)
    for (int j = 0; j < 16; j++)
      {
        pqz_u128 p = (pqz_u128)a[i] * b[j];
        if (i + j < 16) /* index-only branch: same for every input */
          lo[i + j] += p;
        else
          hi[i + j - 16] += p;
      }
  for (int k = 0; k < 16; k++)
    r[k] = addq (pqz_red128 (lo[k]), mulq (rho, pqz_red128 (hi[k])));
}

/* r = a * b in the NTT domain; r may alias a or b */
void
pqz_ntt_basemul (uint64_t r[64], const uint64_t a[64], const uint64_t b[64])
{
  uint64_t t[64];
  basemul16 (t, a, b, ZETA);
  basemul16 (t + 16, a + 16, b + 16, Q - ZETA);
  basemul16 (t + 32, a + 32, b + 32, ZETA3);
  basemul16 (t + 48, a + 48, b + 48, Q - ZETA3);
  for (int k = 0; k < 64; k++)
    r[k] = t[k];
}

/* plain negacyclic schoolbook product, used by the tests as a second oracle */
void
pqz_poly_mul_ref (uint64_t r[64], const uint64_t a[64], const uint64_t b[64])
{
  uint64_t t[64];
  for (int k = 0; k < 64; k++)
    {
      pqz_u128 pos = 0, neg = 0;
      for (int i = 0; i < 64; i++)
        {
          int j = k - i;
          if (j >= 0)
            pos += (pqz_u128)a[i] * b[j];
          else
            neg += (pqz_u128)a[i] * b[j + 64];
        }
      t[k] = subq (pqz_red128 (pos), pqz_red128 (neg));
    }
  for (int k = 0; k < 64; k++)
    r[k] = t[k];
}
