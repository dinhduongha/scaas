/*
 * PQZ rewrite of LaZer's rejection tests (upstream: MPFR exp / cosh on 128-bit floats).
 *
 * Same tests and the same inputs (scM = round(M * 2^128), sigma2 = sigma^2):
 *   standard: accept iff u < exp((<v,v> - 2<z,v>) / (2 sigma^2)) / M
 *   bimodal:  accept iff u < 1 / (M exp(-<v,v> / (2 sigma^2)) cosh(<z,v> / sigma^2))
 * with u uniform. The exponents are formed exactly as Q56 fixed-point quotients (masked long division),
 * exp() is pqz_fixexp.h's integer exp, and the comparison uses a 64-bit uniform u (see the precision note
 * there). Integer-only and constant-time in z and v. All functions return 1 for reject, 0 for accept.
 *
 * Overflow: the exponent arithmetic on dishonest-size inputs (<z,v> near -2^126: t2 - 2 t1; an exponent t or
 * a - |y| near -2^63: minus ln M) saturates (pqz_sat_sub64 / pqz_sat_sub128; 2026-10-18 it wrapped, before that it
 * was signed overflow), as the Rust port's saturating_sub: an exponent below -2^63 stays the most negative one and
 * rejects (the prover's retry loop then ends at PQZ_REJ_MAX), num above 2^127 stays the largest and accepts, as the
 * exact value would. No honest prover gets near: the exponents stay within +-64 in Q56 (2^62) there. Prover only.
 */
#include "lazer.h"

#include "pqz_fixexp.h"

/* int_t (|a| < 2^126, at most 2 limbs used) -> signed 128-bit */
static pqz_fx_i128
_int2i128 (const int_t a)
{
  pqz_fx_u128 m = a->limbs[0];
  if (a->nlimbs > 1)
    m |= (pqz_fx_u128)a->limbs[1] << 64;
  for (unsigned i = 2; i < a->nlimbs; i++)
    ERR (a->limbs[i] != 0, "%s", "rejection input too large");
  ERR ((m >> 126) != 0, "%s", "rejection input too large");
  pqz_fx_u128 s = (pqz_fx_u128)0 - (a->neg & 1);
  return (pqz_fx_i128)((m ^ s) - s); /* unsigned: m >= 2^127 after the ERR above must not overflow */
}

/* signed a / d in Q56, d > 0, clamped into int64 */
static int64_t
_quot_q56 (pqz_fx_i128 a, uint64_t d)
{
  pqz_fx_i128 s = a >> 127;
  pqz_fx_u128 mag = ((pqz_fx_u128)a ^ (pqz_fx_u128)s) - (pqz_fx_u128)s; /* unsigned: |-2^127| = 2^127 */
  /* |a| < 2^70 keeps |a| * 2^56 inside 128 bits; beyond that exp() saturates anyway */
  pqz_fx_u128 big = (pqz_fx_u128)0 - (pqz_fx_u128)((mag >> 70) != 0);
  mag = (mag & ~big) | ((((pqz_fx_u128)1 << 70) - 1) & big);
  pqz_fx_u128 q = pqz_div_q56 (mag, d);
  pqz_fx_u128 qb = (pqz_fx_u128)0 - (pqz_fx_u128)((q >> 63) != 0);
  q = (q & ~qb) | ((((pqz_fx_u128)1 << 63) - 1) & qb);
  int64_t r = (int64_t)q;
  int64_t s64 = (int64_t)s;
  return (r ^ s64) - s64;
}

static uint64_t
_u64 (rng_state_t state)
{
  uint8_t b[8];
  uint64_t v = 0;
  rng_urandom (state, b, 8);
  for (int j = 0; j < 8; j++)
    v |= (uint64_t)b[j] << (8 * j);
  return v;
}

/* ln M in Q56 from scM = round(M * 2^128), 1 <= M < 64. scM is a public parameter: plain bisection on
   the fixed-point exp (exp(x) <= M), no data-dependent secret. */
static int64_t
_lnM_q56 (const int_t scM)
{
  uint64_t mid = scM->limbs[1], hi = scM->nlimbs > 2 ? scM->limbs[2] : 0;
  uint64_t m56 = (mid >> 8) | (hi << 56); /* M * 2^56 */
  int64_t x = 0;
  for (int b = 58; b >= 0; b--)
    {
      int64_t t = x + ((int64_t)1 << b);
      uint64_t mant;
      int32_t e;
      pqz_exp_fp (t, &mant, &e); /* exp(t) = mant * 2^(e - 63), e in [1, 7] here */
      if (e <= 7 && ((pqz_fx_u128)mant << e) <= ((pqz_fx_u128)m56 << 7))
        x = t;
    }
  return x;
}

/* accept iff u * M * exp(-t) <= 1, i.e. u < exp(t - ln M) */
static int
_accept_exp (rng_state_t state, int64_t t_q56, int64_t lnM_q56)
{
  uint64_t mant;
  int32_t e;
  pqz_exp_fp (pqz_sat_sub64 (t_q56, lnM_q56), &mant, &e); /* saturates (see the note at the top) */
  return pqz_bernoulli_fp (_u64 (state), mant, e);
}

int
rej_standard (rng_state_t state, const intvec_t z, const intvec_t v,
              const int_t scM, const int_t sigma2)
{
  INT_T (t1, z->nlimbs << 1);
  INT_T (t2, v->nlimbs << 1);

  ASSERT_ERR (z->nelems == v->nelems);
  ASSERT_ERR (z->nlimbs == v->nlimbs);

  intvec_dot (t1, z, v); /* <z,v> */
  intvec_dot (t2, v, v); /* <v,v> */
  /* saturates for <z,v> near -2^126 (see the note at the top); 2 t1 in unsigned: exact for |t1| < 2^126, no UB after
     _int2i128's ERR */
  pqz_fx_i128 num = pqz_sat_sub128 (_int2i128 (t2), (pqz_fx_i128)(2 * (pqz_fx_u128)_int2i128 (t1)));
  uint64_t den = 2 * (uint64_t)_int2i128 (sigma2);
  int64_t t = _quot_q56 (num, den);
  return !_accept_exp (state, t, _lnM_q56 (scM));
}

int
rej_bimodal (rng_state_t state, const intvec_t z, const intvec_t v,
             const int_t scM, const int_t sigma2)
{
  INT_T (t1, z->nlimbs << 1);
  INT_T (t2, v->nlimbs << 1);

  ASSERT_ERR (z->nelems == v->nelems);
  ASSERT_ERR (z->nlimbs == v->nlimbs);

  intvec_dot (t1, z, v); /* <z,v> */
  intvec_dot (t2, v, v); /* <v,v> */
  uint64_t s2 = (uint64_t)_int2i128 (sigma2);
  int64_t a = _quot_q56 (_int2i128 (t2), 2 * s2); /* <v,v> / (2 sigma^2) >= 0 */
  int64_t y = _quot_q56 (_int2i128 (t1), s2);     /* <z,v> / sigma^2 */
  int64_t ys = y >> 63;
  y = (y ^ ys) - ys;                                /* |y| */
  /* p = exp(a) / (M cosh y) = 2 exp(a - |y|) / (M (1 + exp(-2|y|))) ; accept iff u < p.
     Draw u, compare u * (1 + exp(-2|y|)) / 2 < exp(a - |y| - ln M) in 64-bit fixed point. */
  uint64_t m1, m2;
  int32_t e1, e2;
  pqz_exp_fp (pqz_sat_sub64 (pqz_sat_sub64 (a, y), _lnM_q56 (scM)), &m1, &e1); /* saturates (note at the top) */
  uint64_t yc = pqz_ct_sel64 (-(uint64_t)(y > PQZ_X_MAX / 2), (uint64_t)(PQZ_X_MAX / 2), (uint64_t)y);
  pqz_exp_fp (-2 * (int64_t)yc, &m2, &e2); /* exp(-2|y|) = m2 * 2^(e2 - 63), e2 <= 1 */
  /* as Q63: m2 << 1 if e2 == 1, else m2 >> -e2 (0 below 2^-63) */
  uint64_t f_hi = m2 << 1;
  uint64_t f_lo = m2 >> ((uint64_t)(-e2) & 63);
  f_lo &= -(uint64_t)(-e2 < 64);
  uint64_t f = pqz_ct_sel64 (-(uint64_t)(e2 >= 1), f_hi, f_lo);
  /* w = (1 + exp(-2|y|)) / 2 in Q63, in (1/2, 1] */
  uint64_t w = (uint64_t)((((pqz_fx_u128)1 << 63) + f) >> 1);
  /* u' = u * w (Q64 * Q63 >> 63 = Q64) */
  uint64_t u = _u64 (state);
  uint64_t uw = (uint64_t)(((pqz_fx_u128)u * w) >> 63);
  return !pqz_bernoulli_fp (uw, m1, e1);
}
