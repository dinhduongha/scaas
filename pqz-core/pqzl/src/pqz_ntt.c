/*
 * pqz-core ring arithmetic for R_q = Z_q[X]/(X^64 + 1), q of the parameter set (pqz_set.h; CTR-PQZ-03, -06),
 * replacing LaZer's CRT-over-50-bit-primes representation (Intel HEXL NTTs, __int128 '%' and a float rounding step).
 *
 * q = 9 mod 16, so X^64 + 1 = prod_{j<4} (X^16 - rho_j) with rho_j the primitive 8th roots of unity
 * (incomplete NTT, two layers): layer 1 splits X^64 + 1 = (X^32 - i)(X^32 + i), i = zeta^2; layer 2
 * splits X^32 - i = (X^16 - zeta)(X^16 + zeta) and X^32 + i = (X^16 - zeta^3)(X^16 + zeta^3).
 * The "NTT domain" is the four residues (16 coefficients each, in [0, q)); addition is coefficient-wise
 * and multiplication is a 16 x 16 schoolbook product mod X^16 - rho_j per block.
 *
 * Integer-only, constant-time: no table lookups indexed by data, no data-dependent branches.
 * Reduction: Barrett (pqz_ntt.h pqz_redx), the same canonical residues for every set (v3: the 2^42 - 215 folds it
 * replaced gave the same values). zeta = 3^((q - 1) / 8) (pqz_set.h).
 */
#include <stdint.h>

#include "pqz_ntt.h"

#define Q PQZ_Q

static const uint64_t ZETA = PQZ_ZETA, IROOT = PQZ_IROOT, ZETA3 = PQZ_ZETA3; /* zeta, zeta^2 = sqrt(-1), zeta^3 */
static const uint64_t INV2 = PQZ_INV2, INVZ = PQZ_INVZ, INVI = PQZ_INVI, INVZ3 = PQZ_INVZ3;

/* x < 2^128 -> x mod q: x = hi 2^64 + lo, (hi mod q) (2^64 mod q) + lo < 2^(2L) + 2^64 < 2^(2L + 4) */
uint64_t
pqz_red128 (pqz_u128 x)
{
  const uint64_t hi = pqz_redx (x >> 64);
  return pqz_redx ((pqz_u128)hi * PQZ_R64 + (uint64_t)x);
}

#ifndef PQZ_MUL128 /* -DPQZ_MUL128=0 tests the limb path on a 64-bit host */
#if UINTPTR_MAX > 0xffffffffu
#define PQZ_MUL128 1 /* 64-bit target: 64 x 64 -> 128 is one instruction */
#else
#define PQZ_MUL128 0 /* wasm32: the basemul column sums in two limbs per value, 64-bit products only */
#endif
#endif

#define LB ((PQZ_LOG2Q + 1) / 2) /* limb width of the wasm32 basemul: values < q in two LB-bit limbs */
#define MASKL ((((uint64_t)1) << LB) - 1)
_Static_assert (PQZ_LOG2Q <= 56, "16 products of two (LB + 1)-bit limb sums fit 64 bits");

static inline uint64_t
mulq (uint64_t a, uint64_t b)
{
  return pqz_mulq (a, b);
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

/* r = a * b mod X^16 - rho. P6d-2: with the twisted operand bb[16 + m] = b[m], bb[16 - m] = rho b[16 - m]
   (0 < m < 16), r[k] = sum_i a[i] bb[16 + k - i] is one column sum per output, reduced once (E-S1: separate
   low / high sums, three reductions and a multiplication by rho per output) */
static void
basemul16 (uint64_t r[16], const uint64_t a[16], const uint64_t b[16], uint64_t rho)
{
#if PQZ_MUL128
  uint64_t bb[32];
  for (int j = 1; j < 16; j++)
    bb[j] = mulq (rho, b[j]);
  for (int j = 0; j < 16; j++)
    bb[16 + j] = b[j];
#pragma GCC unroll 16
  for (int k = 0; k < 16; k++)
    {
      pqz_u128 acc = 0; /* < 16 q^2 < 2^BARX */
#pragma GCC unroll 16
      for (int i = 0; i < 16; i++)
        acc += (pqz_u128)a[i] * bb[16 + k - i];
      r[k] = pqz_redx (acc);
    }
#else
  /* LB-bit limbs (a, b < q < 2^(2 LB)), Karatsuba on the limbs: l = sum a0 b0, h = sum a1 b1, s = sum (a0 + a1)(b0 +
     b1) (< 16 2^(2 LB + 2) <= 2^64); the column sum l + 2^LB (s - l - h) + 2^(2 LB) h = sum a_i bb_j < 16 q^2 < 2^BARX
     is formed with shifts and adds */
  uint64_t a0[16], a1[16], as[16], b0[32], b1[32], bs[32];
  for (int i = 0; i < 16; i++)
    a0[i] = a[i] & MASKL, a1[i] = a[i] >> LB, as[i] = a0[i] + a1[i];
  for (int j = 1; j < 32; j++)
    {
      uint64_t t = j < 16 ? mulq (rho, b[j]) : b[j - 16]; /* index-only branch */
      b0[j] = t & MASKL, b1[j] = t >> LB, bs[j] = b0[j] + b1[j];
    }
  for (int k = 0; k < 16; k++)
    {
      uint64_t l = 0, sm = 0, h = 0;
      for (int i = 0; i < 16; i++)
        {
          l += a0[i] * b0[16 + k - i];
          sm += as[i] * bs[16 + k - i];
          h += a1[i] * b1[16 + k - i];
        }
      r[k] = pqz_redx ((pqz_u128)l + ((pqz_u128)(sm - l - h) << LB) + ((pqz_u128)h << (2 * LB)));
    }
#endif
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
