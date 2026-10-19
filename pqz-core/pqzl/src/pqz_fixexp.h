/*
 * pqz-core fixed-point exp for the samplers and rejection tests (replaces double exp in grandom.c and MPFR
 * in rejection.c). Integer-only, constant-time in its arguments: fixed iteration counts, masked selects,
 * shifts by data-dependent amounts only through the shift instruction (constant-time on x86-64, aarch64
 * and wasm).
 *
 * Precision: exp(-s) for s in [0, ln 2] by a degree-20 Taylor polynomial in Q63 (truncation < 2^-71),
 * Horner rounding about 2^-60 relative. ponytail: ~60-bit acceptance probabilities; upstream used doubles
 * (53 bits) in the Gaussian sampler and 128-bit MPFR in rejection. A 2^-128 statistical-distance budget
 * per test needs a 128-bit-mantissa variant (two-limb Horner) - open for P6e.
 */
#ifndef PQZ_FIXEXP_H
#define PQZ_FIXEXP_H

#include <stdint.h>

typedef unsigned __int128 pqz_fx_u128;
typedef __int128 pqz_fx_i128;

#define PQZ_LN2_Q56 ((int64_t)49946518145322874LL)        /* ln 2 * 2^56 */
#define PQZ_INVLN2_Q60 ((uint64_t)1663314137230540311ULL) /* 2^60 / ln 2 */
#define PQZ_X_MAX ((int64_t)1 << 62)                      /* |x| <= 64 in Q56 */

static const uint64_t pqz_exp_c[21] = { /* 2^63 / k! */
  9223372036854775808ULL, 9223372036854775808ULL, 4611686018427387904ULL, 1537228672809129301ULL,
  384307168202282325ULL, 76861433640456465ULL, 12810238940076078ULL, 1830034134296583ULL,
  228754266787073ULL, 25417140754119ULL, 2541714075412ULL, 231064915947ULL, 19255409662ULL,
  1481185359ULL, 105798954ULL, 7053264ULL, 440829ULL, 25931ULL, 1441ULL, 76ULL, 4ULL };

static inline uint64_t
pqz_ct_sel64 (uint64_t mask, uint64_t a, uint64_t b) /* mask ? a : b, mask all-ones or zero */
{
  return (a & mask) | (b & ~mask);
}

/* a - b saturated into [INT64_MIN, INT64_MAX] / the signed 128-bit range, constant-time (2026-10-18, as the Rust
   port's saturating_sub): overflow iff a and b differ in sign and the wrapped difference's sign differs from a's;
   then the result is INT64_MIN if a < 0, else INT64_MAX (same in 128 bits) */
static inline int64_t
pqz_sat_sub64 (int64_t a, int64_t b)
{
  uint64_t ua = (uint64_t)a, r = ua - (uint64_t)b;
  uint64_t ov = 0 - (((ua ^ (uint64_t)b) & (ua ^ r)) >> 63);
  return (int64_t)pqz_ct_sel64 (ov, (ua >> 63) + (uint64_t)INT64_MAX, r);
}

static inline pqz_fx_i128
pqz_sat_sub128 (pqz_fx_i128 a, pqz_fx_i128 b)
{
  pqz_fx_u128 ua = (pqz_fx_u128)a, ub = (pqz_fx_u128)b, r = ua - ub;
  pqz_fx_u128 ov = (pqz_fx_u128)0 - (((ua ^ ub) & (ua ^ r)) >> 127);
  pqz_fx_u128 sat = (ua >> 127) + (~(pqz_fx_u128)0 >> 1);
  return (pqz_fx_i128)((sat & ov) | (r & ~ov));
}

/* exp(-s) in Q63 for s in [0, ln 2] given in Q56 */
static inline uint64_t
pqz_expneg_q63 (uint64_t s)
{
  uint64_t y = pqz_exp_c[20];
  for (int k = 19; k >= 0; k--)
    y = pqz_exp_c[k] - (uint64_t)(((pqz_fx_u128)s * y) >> 56);
  return y;
}

/*
 * exp(x) = mant * 2^(e - 63), mant in (2^62, 2^63], for x in Q56; x is clamped to [-64, 64].
 * The two clamp comparisons are formed in 128 bits (2026-10-18, as the Rust port's fixexp.rs): in 64 bits x - X_MAX
 * overflowed for x < -X_MAX and x + X_MAX for x >= X_MAX (undefined behaviour). Same result on [-X_MAX, X_MAX);
 * outside it saturates as intended. Only a rejection exponent beyond +-64 gets there (never an honest one).
 */
static inline void
pqz_exp_fp (int64_t x, uint64_t *mant, int32_t *e)
{
  uint64_t hi = ~(uint64_t)(((pqz_fx_i128)x - PQZ_X_MAX) >> 127); /* x >= X_MAX ? all ones : 0 */
  x = (int64_t)pqz_ct_sel64 (hi, (uint64_t)PQZ_X_MAX, (uint64_t)x);
  uint64_t lo = (uint64_t)(((pqz_fx_i128)x + PQZ_X_MAX) >> 127); /* x < -X_MAX ? all ones : 0 */
  x = (int64_t)pqz_ct_sel64 (lo, (uint64_t)(-PQZ_X_MAX), (uint64_t)x);

  /* n = floor(x / ln 2) */
  pqz_fx_i128 prod = (pqz_fx_i128)x * (pqz_fx_i128)PQZ_INVLN2_Q60;
  int64_t n = (int64_t)(prod >> 116);
  int64_t r = x - n * PQZ_LN2_Q56;
  /* rounding of 1/ln2: bring r into [0, ln 2) */
  int64_t m1 = r >> 63;                   /* r < 0 */
  n += m1, r += PQZ_LN2_Q56 & m1;
  int64_t m2 = ((r - PQZ_LN2_Q56) >> 63) ^ (int64_t)-1; /* r >= ln 2 */
  n -= m2, r -= PQZ_LN2_Q56 & m2;
  /* exp(r) = 2 * exp(-(ln 2 - r)) */
  *mant = pqz_expneg_q63 ((uint64_t)(PQZ_LN2_Q56 - r));
  *e = (int32_t)(n + 1);
}

/* u / 2^64 < mant * 2^(e - 63) ? 1 : 0, constant-time; u uniform 64-bit */
static inline int
pqz_bernoulli_fp (uint64_t u, uint64_t mant, int32_t e)
{
  int64_t sh = (int64_t)e + 1;                 /* threshold = mant * 2^sh, compared with u */
  uint64_t neg = (uint64_t)(sh >> 63);         /* sh < 0 */
  uint64_t far = (uint64_t)((sh + 63) >> 63);  /* sh < -63: threshold 0 */
  uint64_t always = (uint64_t)((1 - sh) >> 63); /* sh >= 2: threshold >= 2^64 > u */
  pqz_fx_u128 tneg = mant >> ((uint64_t)(-sh) & 63);
  tneg &= ~(pqz_fx_u128)far;
  /* mant * 2^(sh & 1) as a masked add (review round 2, Q-A): a 128-bit shift by a variable amount is a libcall on
     wasm32 (__ashlti3), and compiler_builtins' version branches on the amount; sh is secret-derived */
  pqz_fx_u128 tpos = (pqz_fx_u128)mant + ((pqz_fx_u128)mant & ((pqz_fx_u128)0 - (pqz_fx_u128)((uint64_t)sh & 1)));
  pqz_fx_u128 nm = (pqz_fx_u128)0 - (neg & 1);
  pqz_fx_u128 thr = (tneg & nm) | (tpos & ~nm);
  return (int)((always & 1) | (uint64_t)((pqz_fx_u128)u < thr));
}

/* floor(a * 2^56 / d) for a < 2^70 (given as u128), d < 2^64: 128-step masked long division */
static inline pqz_fx_u128
pqz_div_q56 (pqz_fx_u128 a, uint64_t d)
{
  pqz_fx_u128 n = a << 56, rem = 0, q = 0;
  for (int b = 127; b >= 0; b--)
    {
      rem = (rem << 1) | ((n >> b) & 1);
      pqz_fx_u128 t = rem - d;
      pqz_fx_u128 ge = (pqz_fx_u128)0 - (((t >> 127) & 1) ^ 1); /* rem >= d */
      rem = (t & ge) | (rem & ~ge);
      q |= (ge & 1) << b;
    }
  return q;
}

#endif
