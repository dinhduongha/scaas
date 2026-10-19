/*
 * C core hardening tests (2026-10-18): the inputs that reached undefined behaviour or an out-of-bounds write before
 * the fixes. Built and run by test/ub_test.sh with -fsanitize=undefined,address -fno-sanitize-recover=all and
 * -DPQZ_DEBUG_MALLOC (libc heap, so ASan sees each block); before the fixes the sanitizer aborts, after them every
 * check prints "ok" and the expected value is the one the Rust port (crate pqzl) computes.
 *   (a) pqz_fixexp.h pqz_exp_fp outside [-64, 64]: the intended clamp; pqz_sat_sub64 / pqz_sat_sub128 at the range
 *       edges; rejection.c with exponents near +-2^63 (follow-up 2026-10-18: rej_standard t2 - 2 t1 and t - ln M,
 *       rej_bimodal a - |y| - ln M saturate, as the Rust port's saturating_sub, where they first wrapped: below -2^63
 *       rejects, num above 2^127 accepts); rej_onetime (P6-D2, Rej1 for z2): rejects every <z,v> < 0, = rej_standard
 *       otherwise with the same rng offset, acceptance rate 1/(2 M2);
 *   (b) pqz_encrypt / pqz_decrypt_raw with a coefficient in [2^63, 2^63 + q) and 2^63 + q (rd_poly, int_set_i64);
 *   (c) poly_auto_self in the NTT domain (crt == 1): X -> X^-1 via the coefficients (follow-up 2026-10-18), equal to
 *       the coefficient-domain automorphism, no write past the residue vector.
 *   review round 2 (2026-10-19, research/code-review-2026-10-19/M-agy-pqzl-c.md triage):
 *   (d) Q-A pqz_bernoulli_fp's masked add = the former shift; (e) Q-D the entropy decoders stop at the first failed
 *       read (and the 10,552-zero-byte R_REG proof); (f) Q-E the bounds asserts return before the write, Q-F pqz__div
 *       nn < dn; on the arena (built without -DPQZ_DEBUG_MALLOC): (g) Q-B the arena is zero above the mark after every
 *       secret-holding call; (h) Q-C an undersized arena traps before any write (ASan: no report).
 *   pqz_ub_test [parts]     parts: any of a .. f (default abcdef); the arena binary: g, h
 */
#include "lazer.h"

#include "pqz.h"
#include "pqz_fixexp.h"
#include "pqz_reg_params.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;

static void
check (const char *name, int ok)
{
  printf ("%s %s\n", ok ? "ok  " : "FAIL", name);
  fails += !ok;
}

/* ---- (a) fixexp and rejection ---- */

/* the pre-fix pqz_exp_fp, valid (no overflow) only for x in [-X_MAX, X_MAX) */
static void
old_exp_fp (int64_t x, uint64_t *mant, int32_t *e)
{
  int64_t hi = (int64_t)((uint64_t)(x - PQZ_X_MAX) >> 63) - 1;
  x = (int64_t)pqz_ct_sel64 ((uint64_t)hi, (uint64_t)PQZ_X_MAX, (uint64_t)x);
  int64_t lo = (int64_t)((uint64_t)(x + PQZ_X_MAX) >> 63) * -1;
  x = (int64_t)pqz_ct_sel64 ((uint64_t)lo, (uint64_t)(-PQZ_X_MAX), (uint64_t)x);
  pqz_fx_i128 prod = (pqz_fx_i128)x * (pqz_fx_i128)PQZ_INVLN2_Q60;
  int64_t n = (int64_t)(prod >> 116);
  int64_t r = x - n * PQZ_LN2_Q56;
  int64_t m1 = r >> 63;
  n += m1, r += PQZ_LN2_Q56 & m1;
  int64_t m2 = ((r - PQZ_LN2_Q56) >> 63) ^ (int64_t)-1;
  n -= m2, r -= PQZ_LN2_Q56 & m2;
  *mant = pqz_expneg_q63 ((uint64_t)(PQZ_LN2_Q56 - r));
  *e = (int32_t)(n + 1);
}

static int
exp_eq (int64_t x, int64_t y)
{
  uint64_t m1, m2;
  int32_t e1, e2;
  pqz_exp_fp (x, &m1, &e1);
  pqz_exp_fp (y, &m2, &e2);
  return m1 == m2 && e1 == e2;
}

static void
test_fixexp (void)
{
  const int64_t hi[] = { PQZ_X_MAX, PQZ_X_MAX + 1, (int64_t)1 << 62 | 12345, INT64_MAX - 1, INT64_MAX };
  const int64_t lo[] = { -PQZ_X_MAX - 1, -PQZ_X_MAX - 2, INT64_MIN / 2 - 7, INT64_MIN + 1, INT64_MIN };
  int ok = 1;
  for (unsigned i = 0; i < sizeof hi / sizeof hi[0]; i++)
    ok &= exp_eq (hi[i], PQZ_X_MAX);
  check ("fixexp x >= 64 saturates to exp(64)", ok);
  ok = 1;
  for (unsigned i = 0; i < sizeof lo / sizeof lo[0]; i++)
    ok &= exp_eq (lo[i], -PQZ_X_MAX);
  check ("fixexp x < -64 saturates to exp(-64)", ok);
  /* inside [-X_MAX, X_MAX) the new clamp equals the old code (splitmix64 points + the edges) */
  ok = 1;
  uint64_t s = 1;
  for (int i = 0; i < 100000; i++)
    {
      s += 0x9E3779B97F4A7C15ULL;
      uint64_t z = (s ^ (s >> 30)) * 0xBF58476D1CE4E5B9ULL;
      z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
      z ^= z >> 31;
      int64_t x = (int64_t)(z >> 1) - PQZ_X_MAX; /* [-X_MAX, X_MAX) */
      if (i == 0)
        x = -PQZ_X_MAX;
      if (i == 1)
        x = PQZ_X_MAX - 1;
      uint64_t m1, m2;
      int32_t e1, e2;
      pqz_exp_fp (x, &m1, &e1);
      old_exp_fp (x, &m2, &e2);
      ok &= m1 == m2 && e1 == e2;
    }
  check ("fixexp unchanged on [-64, 64)", ok);
}

/* pqz_sat_sub64 / pqz_sat_sub128 on every pair of edge values = the exact difference clamped into the range */
static void
test_satsub (void)
{
  const int64_t e64[] = { INT64_MIN, INT64_MIN + 1, INT64_MIN / 2, -PQZ_X_MAX, -1, 0, 1, PQZ_X_MAX, INT64_MAX / 2,
                          INT64_MAX - 1, INT64_MAX };
  const pqz_fx_i128 max128 = (pqz_fx_i128)(~(pqz_fx_u128)0 >> 1), min128 = -max128 - 1;
  const pqz_fx_i128 e128[] = { min128, min128 + 1, min128 / 2, -((pqz_fx_i128)1 << 126), -1, 0, 1,
                               (pqz_fx_i128)1 << 126, max128 / 2, max128 - 1, max128 };
  int ok = 1;
  for (unsigned i = 0; i < sizeof e64 / sizeof e64[0]; i++)
    for (unsigned j = 0; j < sizeof e64 / sizeof e64[0]; j++)
      {
        pqz_fx_i128 d = (pqz_fx_i128)e64[i] - e64[j];
        int64_t want = d > INT64_MAX ? INT64_MAX : d < INT64_MIN ? INT64_MIN : (int64_t)d;
        ok &= pqz_sat_sub64 (e64[i], e64[j]) == want;
      }
  check ("pqz_sat_sub64 = the clamped exact difference on the edges", ok);
  ok = 1;
  for (unsigned i = 0; i < sizeof e128 / sizeof e128[0]; i++)
    for (unsigned j = 0; j < sizeof e128 / sizeof e128[0]; j++)
      {
        pqz_fx_i128 d;
        pqz_fx_i128 want = __builtin_sub_overflow (e128[i], e128[j], &d) ? (e128[i] < 0 ? min128 : max128) : d;
        ok &= pqz_sat_sub128 (e128[i], e128[j]) == want;
      }
  check ("pqz_sat_sub128 = the clamped exact difference on the edges", ok);
}

/* int_t r = sign * (hi * 2^64 + lo) */
static void
set_big (int_ptr r, int neg, uint64_t hi, uint64_t lo)
{
  int_set_zero (r);
  r->limbs[0] = lo;
  if (r->nlimbs > 1)
    r->limbs[1] = hi;
  r->neg = neg ? 1 : 0;
}

typedef int (*rej_fn) (rng_state_t, const intvec_t, const intvec_t, const int_t, const int_t);

/* rej(z, v) on 64 different u: the expected verdict whatever u is */
static int
rej_all (rej_fn f, intvec_t z, intvec_t v, const int_t scM, const int_t sigma2, int want)
{
  uint8_t seed[32] = { 7 };
  rng_state_t st;
  int ok = 1;
  rng_init (st, seed, 0);
  for (int i = 0; i < 64; i++)
    ok &= f (st, z, v, scM, sigma2) == want;
  rng_clear (st);
  return ok && pqz_err == PQZ_OK;
}

static void
test_rejection (void)
{
  INT_T (scM, 3);   /* round(1.5 * 2^128) */
  INT_T (sig1, 1);  /* sigma^2 = 2^20 */
  int_set_zero (scM);
  scM->limbs[2] = 1, scM->limbs[1] = (uint64_t)1 << 63;
  int_set_i64 (sig1, (int64_t)1 << 20);
  intvec_t z, v, z2, v2;
  intvec_alloc (z, 1, 1), intvec_alloc (v, 1, 1);
  intvec_alloc (z2, 2, 2), intvec_alloc (v2, 2, 2);

  /* S1 standard, num = t2 - 2 t1 = 3 (2^126 - 2^64 + 1) > 2^127 saturates to 2^127 - 1 (2026-10-18 it wrapped
     negative); t = 2^63 - 1 after the clamps, t - ln M near +2^63 -> exp(64) -> accept (0), as the exact value */
  intvec_set_elem_i64 (v, 0, INT64_MAX);
  intvec_set_elem_i64 (z, 0, -INT64_MAX);
  check ("rej_standard t2 - 2 t1 saturates at 2^127 - 1: accept", rej_all (rej_standard, z, v, scM, sig1, 0));

  /* S2 standard, num = 1 - 2^63, t = -(2^63 - 1); t - ln M saturates at -2^63 (it wrapped to +2^63 - ...) -> exp(-64)
     -> reject (1) */
  intvec_set_elem_i64 (v, 0, 1);
  intvec_set_elem_i64 (z, 0, (int64_t)1 << 62);
  check ("rej_standard t - ln M saturates at -2^63: reject", rej_all (rej_standard, z, v, scM, sig1, 1));

  /* S3 standard, two-limb entries: t2 = 2, t1 = -(2^126 - 1), num = 2^127 saturates to 2^127 - 1 (it wrapped to
     -2^127), t = 2^63 - 1 -> accept (0) */
  set_big (intvec_get_elem (v2, 0), 0, 0, 1), set_big (intvec_get_elem (v2, 1), 0, 0, 1);
  set_big (intvec_get_elem (z2, 0), 1, ((uint64_t)1 << 62) - 1, UINT64_MAX), set_big (intvec_get_elem (z2, 1), 0, 0, 0);
  check ("rej_standard num = 2^127 saturates (two limbs): accept", rej_all (rej_standard, z2, v2, scM, sig1, 0));

  /* S4 standard, num = 1 + 2^63, t = 2^63 - 1 (clamped), t - ln M near +2^63, no saturation -> accept (0) */
  intvec_set_elem_i64 (v, 0, 1);
  intvec_set_elem_i64 (z, 0, -((int64_t)1 << 62));
  check ("rej_standard t - ln M near +2^63: accept", rej_all (rej_standard, z, v, scM, sig1, 0));

  /* B1 bimodal, a = 2^35, |y| = 2^63 - 1 (clamped), a - |y| - ln M saturates at -2^63 (it wrapped) -> reject (1) */
  intvec_set_elem_i64 (v, 0, 1);
  intvec_set_elem_i64 (z, 0, (int64_t)1 << 62);
  check ("rej_bimodal a - |y| - ln M saturates at -2^63: reject", rej_all (rej_bimodal, z, v, scM, sig1, 1));

  /* B2 bimodal, a = 2^63 - 1 (clamped), y = 0, a - |y| - ln M near +2^63, no saturation -> accept (0) */
  intvec_set_elem_i64 (v, 0, INT64_MAX);
  intvec_set_elem_i64 (z, 0, 0);
  check ("rej_bimodal a - |y| - ln M near +2^63: accept", rej_all (rej_bimodal, z, v, scM, sig1, 0));

  intvec_free (z), intvec_free (v), intvec_free (z2), intvec_free (v2);
}

/* rej_onetime (P6-D2, review D-2: Rej1 for z2) on R_REG's z2 parameters (scM2, sigma2^2 = stdev2sq): z = y + v with
   y ~ D_sigma2 (intvec_grandom, log2o 12 = log2stdev2) and v fixed, ||v||^2 = 64 * 1100^2 < 2 sigma2^2 ln M2 (the
   bound under which Rej1 outputs exactly D_sigma2). Per sample rej_onetime on one rng and rej_standard on a second rng
   with the same seed: onetime = standard | (<z,v> < 0) (every <z,v> < 0 rejects; the count of those rej_standard
   accepted shows the sign test is not vacuous), and afterwards both streams are at the same offset (one u per call).
   Acceptance rate: (1/M2) Pr[<y,v> >= 0] = 1/(2 M2) (the mass at <y,v> = 0 is ~1e-5), to 5 standard errors of 2^16
   Bernoulli samples, |rate - p| <= 5 sqrt(p (1 - p) / n) ~ 0.0074 (squared, no libm). The seeds are fixed, so the bound
   only guards the expected value; the old z2 call (rej_bimodal with stdev1sqr) and rej_standard accept ~1/M2 = 0.35. */
static void
test_onetime (void)
{
  enum { N = 64, S = 1 << 16 };
  uint8_t seed[32] = { 9 }, ua[8], ub[8];
  rng_state_t ra, rb;
  intvec_t y, z, v;
  INT_T (dot, 2);
  intvec_alloc (y, N, 1), intvec_alloc (z, N, 1), intvec_alloc (v, N, 1);
  for (int i = 0; i < N; i++)
    intvec_set_elem_i64 (v, i, (i & 1) ? 1100 : -1100);
  rng_init (ra, seed, 0), rng_init (rb, seed, 0);
  long acc = 0, neg = 0, negstd = 0;
  int ok = 1;
  for (uint32_t s = 0; s < S; s++)
    {
      intvec_grandom (y, 12, seed, s + 1);
      intvec_add (z, y, v);
      intvec_dot (dot, z, v);
      int n = int_sgn (dot) < 0;
      int r1 = rej_onetime (ra, z, v, pqz_reg_scM2, pqz_reg_stdev2sq);
      int r0 = rej_standard (rb, z, v, pqz_reg_scM2, pqz_reg_stdev2sq);
      ok &= r1 == (r0 | n);
      neg += n, negstd += n & !r0, acc += !r1;
    }
  rng_urandom (ra, ua, 8), rng_urandom (rb, ub, 8);
  check ("rej_onetime = rej_standard | (<z,v> < 0) on 2^16 samples", ok && negstd > 0 && pqz_err == PQZ_OK);
  check ("rej_onetime: same rng offset as rej_standard afterwards", memcmp (ua, ub, 8) == 0);
  double m2 = (double)pqz_reg_scM2->limbs[2] + (double)pqz_reg_scM2->limbs[1] / 18446744073709551616.0;
  double p = 1 / (2 * m2), rate = (double)acc / S;
  printf ("     rej_onetime: M2 %.7f, accepted %ld / %d = %.5f, 1/(2 M2) = %.5f; <z,v> < 0: %ld (%ld of them "
          "accepted by rej_standard)\n", m2, acc, S, rate, p, neg, negstd);
  check ("rej_onetime acceptance rate = 1/(2 M2) within 5 standard errors",
         (rate - p) * (rate - p) <= 25 * p * (1 - p) / S);
  rng_clear (ra), rng_clear (rb);
  intvec_free (y), intvec_free (z), intvec_free (v);
}

/* ---- (b) pqz_encrypt / pqz_decrypt_raw on non-canonical coefficients ---- */

#define PQZ_Q_ ((((uint64_t)1) << 42) - 215)

static void
wr_be8 (uint8_t *p, uint64_t v)
{
  for (int b = 7; b >= 0; b--, v >>= 8)
    p[b] = (uint8_t)v;
}

/* rd_poly's reading of a be8 word V >= (q+1)/2: the int64 (V - q) mod 2^64 (Rust keys.rs: wrapping_sub), reduced
   into [0, q) as the NTT does with it (pqz_int_modq of sign-magnitude, |INT64_MIN| = 2^63) */
static uint64_t
canon (uint64_t V)
{
  int64_t c = (int64_t)(V - PQZ_Q_);
  uint64_t mag = c < 0 ? 0 - (uint64_t)c : (uint64_t)c;
  uint64_t r = mag % PQZ_Q_;
  return c < 0 && r ? PQZ_Q_ - r : r;
}

static void
test_enc_dec (void)
{
  static int8_t s[2048], r[2048];
  static int16_t e[2048], e1[2048], e2[1][16];
  static uint8_t pk[PQZ_POLYVEC_BYTES], pkx[PQZ_POLYVEC_BYTES], pkc[PQZ_POLYVEC_BYTES];
  static uint8_t u[PQZ_POLYVEC_BYTES], ux[PQZ_POLYVEC_BYTES], uc[PQZ_POLYVEC_BYTES], v[1][PQZ_V_BYTES],
      vx[1][PQZ_V_BYTES], vc[1][PQZ_V_BYTES];
  uint8_t msg[1][16];
  int64_t w[16], wx[16];
  const uint64_t Vs[] = { (uint64_t)1 << 63, ((uint64_t)1 << 63) + 5, ((uint64_t)1 << 63) + PQZ_Q_ - 1,
                          ((uint64_t)1 << 63) + PQZ_Q_ };
  for (int i = 0; i < 2048; i++)
    s[i] = (int8_t)(i % 3 - 1), r[i] = (int8_t)((i * 7) % 3 - 1), e[i] = (int16_t)(i % 5 - 2),
    e1[i] = (int16_t)((i * 3) % 5 - 2);
  for (int i = 0; i < 16; i++)
    msg[0][i] = (uint8_t)i, e2[0][i] = (int16_t)(i % 3 - 1);
  check ("keypair", pqz_keypair_from_secret (s, e, pk) == PQZ_OK);

  for (unsigned t = 0; t < sizeof Vs / sizeof Vs[0]; t++)
    {
      char name[96];
      const uint64_t V = Vs[t];
      const unsigned at = 8 * (3 * 64 + 17); /* poly 3, coefficient 17 */
      const uint8_t *pkxs[1] = { pkx }, *pkcs[1] = { pkc };
      memcpy (pkx, pk, sizeof pk), memcpy (pkc, pk, sizeof pk);
      wr_be8 (pkx + at, V), wr_be8 (pkc + at, canon (V));
      int rc1 = pqz_encrypt (pkxs, 1, msg, r, e1, e2, ux, vx);
      int rc2 = pqz_encrypt (pkcs, 1, msg, r, e1, e2, uc, vc);
      snprintf (name, sizeof name, "pqz_encrypt pk coefficient 2^63 + %llu = its reading mod q",
                (unsigned long long)(V - ((uint64_t)1 << 63)));
      check (name, rc1 == PQZ_OK && rc2 == PQZ_OK && !memcmp (ux, uc, sizeof ux) && !memcmp (vx, vc, sizeof vx));

      /* u enters only A-products (mod q): equal to its reading mod q */
      pqz_encrypt (pkcs, 1, msg, r, e1, e2, u, v);
      memcpy (ux, u, sizeof u), memcpy (uc, u, sizeof u);
      wr_be8 (ux + at, V), wr_be8 (uc + at, canon (V));
      rc1 = pqz_decrypt_raw (s, ux, v[0], wx);
      rc2 = pqz_decrypt_raw (s, uc, v[0], w);
      snprintf (name, sizeof name, "pqz_decrypt_raw u coefficient 2^63 + %llu = its reading mod q",
                (unsigned long long)(V - ((uint64_t)1 << 63)));
      check (name, rc1 == PQZ_OK && rc2 == PQZ_OK && !memcmp (w, wx, sizeof w));

      /* v is subtracted over Z: w_5 = (V - q) - acc_5 mod 2^64 (as int64), the other w_i unchanged; acc_5 = -w0_5
         from v_5 = 0 */
      memcpy (vx[0], v[0], PQZ_V_BYTES), memcpy (vc[0], v[0], PQZ_V_BYTES);
      wr_be8 (vx[0] + 8 * 5, V), wr_be8 (vc[0] + 8 * 5, 0);
      rc1 = pqz_decrypt_raw (s, u, vx[0], wx);
      rc2 = pqz_decrypt_raw (s, u, vc[0], w);
      int ok = rc1 == PQZ_OK && rc2 == PQZ_OK && wx[5] == (int64_t)((V - PQZ_Q_) + (uint64_t)w[5]);
      for (int i = 0; i < 16; i++)
        ok &= i == 5 || wx[i] == w[i];
      snprintf (name, sizeof name, "pqz_decrypt_raw v coefficient 2^63 + %llu = (V - q) - acc mod 2^64",
                (unsigned long long)(V - ((uint64_t)1 << 63)));
      check (name, ok);
    }
}

/* ---- (c) poly_auto_self in the NTT domain ---- */

static void
test_auto_ntt (void)
{
  poly_t p, c;
  int64_t a[64];
  for (int j = 0; j < 64; j++)
    a[j] = (int64_t)(j * 1000003 % 4001) - 2000;
  poly_alloc (p, pqz_reg_ring), poly_alloc (c, pqz_reg_ring);
  poly_set_coeffvec_i64 (p, a);
  poly_tocrt (p);
  poly_auto_self (p); /* before the hardening: ASan heap-buffer-overflow (second pass, crtrep[64..127]) */
  poly_set_coeffvec_i64 (c, a);
  poly_auto_self (c); /* coefficient domain: the automorphism */
  int ok = p->crt == 0 && c->crt == 0 && pqz_err == PQZ_OK;
  for (int j = 0; j < 64; j++)
    ok &= int_get_i64 (poly_get_coeff (p, j)) == int_get_i64 (poly_get_coeff (c, j));
  ok &= int_get_i64 (poly_get_coeff (c, 0)) == a[0] && int_get_i64 (poly_get_coeff (c, 1)) == -a[63];
  check ("poly_auto_self crt: X -> X^-1 via the coefficients (= the coefficient-domain branch)", ok);
  poly_free (p), poly_free (c);
}


/* ---- review round 2 (2026-10-19, M-agy-pqzl-c.md triage Q-A .. Q-F) ---- */

/* (d) Q-A: pqz_bernoulli_fp's masked add equals the former shift mant << (sh & 1) around every exponent edge */
static void
test_bernoulli (void)
{
  uint64_t x = 0x9E3779B97F4A7C15ULL;
  int ok = 1;
  for (int32_t e = -70; e <= 4; e++)
    for (int k = 0; k < 2000; k++)
      {
        x ^= x << 13, x ^= x >> 7, x ^= x << 17;
        const uint64_t mant = ((x << 29) | (x >> 35)) | (uint64_t)1 << 63;
        for (int h = 0; h < 2; h++)
          {
            const uint64_t u = x >> h;
            const int64_t sh = (int64_t)e + 1;
            const uint64_t neg = (uint64_t)(sh >> 63), far = (uint64_t)((sh + 63) >> 63);
            const uint64_t always = (uint64_t)((1 - sh) >> 63);
            pqz_fx_u128 tneg = (pqz_fx_u128)(mant >> ((uint64_t)(-sh) & 63)) & ~(pqz_fx_u128)far;
            pqz_fx_u128 tpos = (pqz_fx_u128)mant << ((uint64_t)sh & 1);
            pqz_fx_u128 nm = (pqz_fx_u128)0 - (neg & 1);
            int old = (int)((always & 1) | (uint64_t)((pqz_fx_u128)u < ((tneg & nm) | (tpos & ~nm))));
            ok &= pqz_bernoulli_fp (u, mant, e) == old;
          }
      }
  check ("Q-A pqz_bernoulli_fp masked add = the former shift (e in [-70, 4], 300,000 cases)", ok);
}

/* (e) Q-D: a failed read stops the entropy decoders; their input pointer never moves past the buffer. The end-to-end
   case: a canonical R_REG statement with 10,552 zero proof bytes (L-codex C2-3) is rejected by both verifiers */
static void
test_truncated (void)
{
  static const uint8_t PSID[32] = PQZ_PROOF_SYSTEM_ID;
  static uint8_t st[PQZ_REG_STMT_BYTES], pf[10552];
  uint8_t buf[2] = { 0, 0 };
  coder_state_t cs;
  polyvec_t v;
  polyvec_alloc (v, pqz_reg_ring, 4);
  pqz_err = PQZ_OK;
  coder_dec_begin_len (cs, buf, 1);
  coder_dec_ghint3 (cs, v); /* all-zero hint: 2 bits per coefficient, 256 coefficients from one byte */
  check ("Q-D coder_dec_ghint3 on 1 byte: err, in stays in the buffer", cs->err && cs->in <= buf + 1 && cs->byte_off <= 1);
  coder_dec_begin_len (cs, buf, 1);
  coder_dec_grandom3 (cs, v, 10);
  check ("Q-D coder_dec_grandom3 on 1 byte: err, in stays in the buffer", cs->err && cs->in <= buf + 1 && cs->byte_off <= 1);
  polyvec_free (v);
  memcpy (st + 32, PSID, 32);
  pqz_err = PQZ_OK;
  check ("Q-D R_REG, 10,552 zero proof bytes: pqz_verify rejects",
         pqz_verify (PQZ_OP_REGISTER, st, sizeof st, pf, sizeof pf) == 0);
  check ("Q-D R_REG, 10,552 zero proof bytes: pqz_verify_fast rejects",
         pqz_verify_fast (PQZ_OP_REGISTER, st, sizeof st, pf, sizeof pf) == 0);
}

/* (f) Q-E / Q-F: a failed bounds assert returns before the write; pqz__div refuses nn < dn */
static void
test_asserts (void)
{
  spolyvec_t sv;
  spolyvec_alloc (sv, pqz_reg_ring, 0, 1);
  pqz_err = PQZ_OK;
  poly_ptr a = spolyvec_insert_elem (sv, 0);
  poly_set_zero (a);
  poly_ptr b = spolyvec_insert_elem (sv, 1); /* nelems_max 1: before the fix a write past elems */
  poly_set_zero (b);
  check ("Q-E spolyvec_insert_elem past nelems_max: a scratch poly, PQZ_ERR_INTERNAL, nelems stays 1",
         b != a && sv->nelems == 1 && pqz_err == PQZ_ERR_INTERNAL);
  spolyvec_free (sv);
  spolymat_t sm;
  spolymat_alloc (sm, pqz_reg_ring, 2, 2, 1);
  pqz_err = PQZ_OK;
  a = spolymat_insert_elem (sm, 0, 0);
  b = spolymat_insert_elem (sm, 0, 1);
  poly_set_zero (b);
  check ("Q-E spolymat_insert_elem past nelems_max: a scratch poly, PQZ_ERR_INTERNAL, nelems stays 1",
         b != a && sm->nelems == 1 && pqz_err == PQZ_ERR_INTERNAL);
  spolymat_free (sm);
  uint8_t hdr[4] = { 0xff, 0xff, 0, 0 };
  coder_state_t cs;
  INT_T (m, 1);
  int_set_i64 (m, 5);
  spolyvec_alloc (sv, pqz_reg_ring, 0, 1);
  coder_dec_begin_len (cs, hdr, sizeof hdr);
  coder_dec_urandom6 (cs, sv, m, 3);
  check ("Q-E coder_dec_urandom6, header 65,535 > nelems_max: err, nothing read or inserted",
         cs->err && cs->in == hdr && sv->nelems == 0);
  spolyvec_free (sv);
  mp_limb_t n[1] = { 7 }, d[2] = { 3, 1 };
  pqz_err = PQZ_OK;
  check ("Q-F pqz__div nn < dn: PQZ_ERR_INTERNAL, nothing read past q",
         pqz__div (NULL, n, 1, d, 2) == 0 && pqz_err == PQZ_ERR_INTERNAL);
  pqz_err = PQZ_OK;
}

#ifndef PQZ_DEBUG_MALLOC
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

/* (g) Q-B (the arena build): after every call that held a secret (keygen, enc, dec, prove) the arena above the call's
   mark up to the peak is zero (the arena was filled with 0xA5 first) */
static int
zero_above (const uint8_t *arena)
{
  for (size_t i = pqz_arena_used (); i < pqz_arena_peak (); i++)
    if (arena[i] != 0)
      return 0;
  return pqz_arena_peak () > pqz_arena_used ();
}

static void
test_wipe (uint8_t *arena, size_t len)
{
  static const uint8_t PSID[32] = PQZ_PROOF_SYSTEM_ID;
  static uint8_t pk[PQZ_POLYVEC_BYTES], u[PQZ_POLYVEC_BYTES], vs[1][PQZ_V_BYTES], st[PQZ_REG_STMT_BYTES];
  static uint8_t wit[PQZ_REG_WIT_BYTES], proof[PQZ_MAX_PROOF];
  static int8_t s[2048], r[2048];
  static int16_t e[2048], e1[2048], e2[1][16];
  uint8_t seed[32] = { 1 }, msg[1][16] = { { 3 } }, ct[PQZ_POLYVEC_BYTES + PQZ_V_BYTES];
  int64_t M[16], noise[16];
  unsigned ctr;
  memset (arena, 0xA5, len);
  check ("Q-B pqz_init", pqz_init (arena, len) == PQZ_OK);
  check ("Q-B pqz_keygen; the arena above the mark is zero", pqz_keygen (seed, pk, s, e, &ctr) == PQZ_OK && zero_above (arena));
  const uint8_t *pks[1] = { pk };
  seed[0] = 2;
  check ("Q-B pqz_enc_seed; the arena above the mark is zero",
         pqz_enc_seed (pks, 1, msg, seed, u, vs, r, e1, e2, &ctr) == PQZ_OK && zero_above (arena));
  memcpy (ct, u, sizeof u), memcpy (ct + sizeof u, vs[0], PQZ_V_BYTES);
  check ("Q-B pqz_dec; the arena above the mark is zero",
         pqz_dec (s, ct, M, noise) == PQZ_OK && M[0] == 3 && zero_above (arena));
  memcpy (st + 32, PSID, 32);
  memcpy (st + PQZ_PREFIX_BYTES + 32, pk, sizeof pk);
  for (int j = 0; j < 2048; j++)
    wit[j] = (uint8_t)s[j], wit[2048 + 2 * j] = (uint8_t)e[j], wit[2049 + 2 * j] = (uint8_t)((uint16_t)e[j] >> 8);
  size_t plen = sizeof proof;
  check ("Q-B pqz_prove R_REG; the arena above the mark is zero",
         pqz_prove (PQZ_OP_REGISTER, st, sizeof st, wit, sizeof wit, seed, proof, &plen) == PQZ_OK && zero_above (arena));
  check ("Q-B the proof verifies", pqz_verify_fast (PQZ_OP_REGISTER, st, sizeof st, proof, plen) == 1);
}

/* (h) Q-C (the arena build, under ASan): an arena too small for an allocation stops the process (a trap: SIGILL on
   x86-64) before anything is written; before the fix the shared 1 MiB sink took A (2 MB) and the relation keys, an
   out-of-bounds write. pqz_arena_try_alloc (the specialised verifier's tables and working memory) fails gracefully. */
static int
child_dies (uint8_t *arena, size_t len, int verify)
{
  static uint8_t st[PQZ_REG_STMT_BYTES], pf[64];
  fflush (stdout);
  pid_t p = fork ();
  if (p == 0)
    {
      if (pqz_init (arena, len) == PQZ_OK && verify)
        pqz_verify (PQZ_OP_REGISTER, st, sizeof st, pf, sizeof pf);
      _exit (0);
    }
  int ws;
  waitpid (p, &ws, 0);
  return WIFSIGNALED (ws) && WTERMSIG (ws) == SIGILL;
}

static void
test_exhaustion (uint8_t *arena, size_t len)
{
  pqz_init (arena, len);
  const size_t a = pqz_arena_used (); /* A */
  printf ("     arena after pqz_init: %zu B\n", a);
  check ("Q-C pqz_init on an arena 16 B short of A: trap (SIGILL), no write", child_dies (arena, a - 16, 0));
  check ("Q-C pqz_init fits, R_REG's keys do not (arena A + 64 KiB): pqz_verify traps (SIGILL), no write",
         child_dies (arena, a + 65536, 1));
  pqz_err = PQZ_OK;
  check ("Q-C pqz_arena_try_alloc over the capacity: NULL and PQZ_ERR_ARENA, the call goes on",
         pqz_arena_try_alloc (len) == NULL && pqz_err == PQZ_ERR_ARENA);
  pqz_err = PQZ_OK;
}
#endif

int
main (int argc, char **argv)
{
  static uint8_t arena[(size_t)64 << 20];
  /* the parts to run, one process each in ub_test.sh: a, b, c (2026-10-18), d, e, f (review round 2) on the libc heap
     (-DPQZ_DEBUG_MALLOC); g, h on the arena (the second binary, built without it) */
  const char *part = argc > 1 ? argv[1] : "abcdef";
  if (strchr (part, 'a'))
    test_fixexp (), test_satsub (), test_rejection (), test_onetime ();
  if (strchr (part, 'b') || strchr (part, 'e'))
    check ("pqz_init", pqz_init (arena, sizeof arena) == PQZ_OK);
  if (strchr (part, 'b'))
    test_enc_dec ();
  if (strchr (part, 'c'))
    test_auto_ntt ();
  if (strchr (part, 'd'))
    test_bernoulli ();
  if (strchr (part, 'e'))
    test_truncated ();
  if (strchr (part, 'f'))
    test_asserts ();
#ifndef PQZ_DEBUG_MALLOC
  if (strchr (part, 'g'))
    {
      const size_t big = (size_t)256 << 20; /* R_REG prove: about 100 MB of arena */
      test_wipe (malloc (big), big);
    }
  if (strchr (part, 'h'))
    test_exhaustion (arena, sizeof arena);
#endif
  printf ("%s (%d failed)\n", fails ? "FAIL" : "PASS", fails);
  return fails != 0;
}
