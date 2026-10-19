/*
 * pqz-core: the limb operations LaZer took from GMP's mpn layer, rewritten in C99 without GMP.
 *
 * Only the calls LaZer 3330e48 makes are provided, under pqz_mpn_* names (the mpn_* names are macros so
 * the vendored int code compiles unchanged). Everything is constant-time in the operand values: loops run
 * over the full limb counts, conditional steps use masks. Division is bitwise restoring division (the
 * sizes here are 1-3 limbs); the hot reduction mod q has its own path (pqz_modq in pqz_ntt.c).
 */
#ifndef PQZ_MPN_H
#define PQZ_MPN_H

#include <stddef.h>
#include <stdint.h>

typedef uint64_t mp_limb_t;
typedef long mp_size_t;
typedef unsigned long mp_bitcnt_t;
#define GMP_NUMB_BITS 64

typedef unsigned __int128 pqz_u128;

static inline void
pqz_mpn_copyi (mp_limb_t *r, const mp_limb_t *a, mp_size_t n)
{
  for (mp_size_t i = 0; i < n; i++)
    r[i] = a[i];
}

static inline void
pqz_mpn_com (mp_limb_t *r, const mp_limb_t *a, mp_size_t n)
{
  for (mp_size_t i = 0; i < n; i++)
    r[i] = ~a[i];
}

static inline void
pqz_mpn_cnd_swap (mp_limb_t cnd, mp_limb_t *a, mp_limb_t *b, mp_size_t n)
{
  const mp_limb_t m = -(mp_limb_t)(cnd != 0);
  for (mp_size_t i = 0; i < n; i++)
    {
      mp_limb_t t = (a[i] ^ b[i]) & m;
      a[i] ^= t;
      b[i] ^= t;
    }
}

#define pqz_mpn_sec_add_1_itch(n) ((mp_size_t)1)
static inline mp_limb_t
pqz_mpn_sec_add_1 (mp_limb_t *r, const mp_limb_t *a, mp_size_t n, mp_limb_t b, mp_limb_t *tp)
{
  (void)tp;
  for (mp_size_t i = 0; i < n; i++)
    {
      mp_limb_t s = a[i] + b;
      b = s < b;
      r[i] = s;
    }
  return b;
}

static inline mp_limb_t
pqz_mpn_mul_1 (mp_limb_t *r, const mp_limb_t *a, mp_size_t n, mp_limb_t b)
{
  mp_limb_t c = 0;
  for (mp_size_t i = 0; i < n; i++)
    {
      pqz_u128 p = (pqz_u128)a[i] * b + c;
      r[i] = (mp_limb_t)p;
      c = (mp_limb_t)(p >> 64);
    }
  return c;
}

/* 0 < cnt < 64; returns the bits shifted out (GMP convention). */
static inline mp_limb_t
pqz_mpn_lshift (mp_limb_t *r, const mp_limb_t *a, mp_size_t n, unsigned cnt)
{
  mp_limb_t out = a[n - 1] >> (64 - cnt);
  for (mp_size_t i = n - 1; i > 0; i--)
    r[i] = (a[i] << cnt) | (a[i - 1] >> (64 - cnt));
  r[0] = a[0] << cnt;
  return out;
}

static inline mp_limb_t
pqz_mpn_rshift (mp_limb_t *r, const mp_limb_t *a, mp_size_t n, unsigned cnt)
{
  mp_limb_t out = a[0] << (64 - cnt);
  for (mp_size_t i = 0; i < n - 1; i++)
    r[i] = (a[i] >> cnt) | (a[i + 1] << (64 - cnt));
  r[n - 1] = a[n - 1] >> cnt;
  return out;
}

#define pqz_mpn_sec_mul_itch(an, bn) ((mp_size_t)1)
static inline void
pqz_mpn_sec_mul (mp_limb_t *r, const mp_limb_t *a, mp_size_t an, const mp_limb_t *b, mp_size_t bn,
                 mp_limb_t *tp)
{
  (void)tp;
  for (mp_size_t i = 0; i < an + bn; i++)
    r[i] = 0;
  for (mp_size_t j = 0; j < bn; j++)
    {
      mp_limb_t c = 0;
      for (mp_size_t i = 0; i < an; i++)
        {
          pqz_u128 p = (pqz_u128)a[i] * b[j] + r[i + j] + c;
          r[i + j] = (mp_limb_t)p;
          c = (mp_limb_t)(p >> 64);
        }
      r[an + j] = c;
    }
}

#define pqz_mpn_sec_sqr_itch(an) ((mp_size_t)1)
static inline void
pqz_mpn_sec_sqr (mp_limb_t *r, const mp_limb_t *a, mp_size_t an, mp_limb_t *tp)
{
  pqz_mpn_sec_mul (r, a, an, a, an, tp);
}

/* r[0..n) >= m[0..n) ? subtract (masked); returns nothing. */
static inline void
pqz__cnd_sub_ge (mp_limb_t *r, const mp_limb_t *m, mp_size_t n, mp_limb_t top)
{
  mp_limb_t t[n], br = 0;
  for (mp_size_t i = 0; i < n; i++)
    {
      mp_limb_t d = r[i] - m[i];
      mp_limb_t b1 = r[i] < m[i];
      mp_limb_t d2 = d - br;
      mp_limb_t b2 = d < br;
      t[i] = d2;
      br = b1 | b2;
    }
  /* take t when (top || !borrow) */
  const mp_limb_t take = pqz_ct_barrier (-(mp_limb_t)((top | (br ^ 1)) & 1)); /* review E: barrier */
  for (mp_size_t i = 0; i < n; i++)
    r[i] = (r[i] & ~take) | (t[i] & take);
}

/*
 * Restoring division, one bit at a time, fixed iteration count nn*64:
 * np[0..nn) / dp[0..dn) -> quotient qp[0..nn-dn) + returned top limb, remainder in np[0..dn).
 * dp[dn-1] != 0. When qp == NULL only the remainder is produced.
 */
static inline mp_limb_t
pqz__div (mp_limb_t *qp, mp_limb_t *np, mp_size_t nn, const mp_limb_t *dp, mp_size_t dn)
{
  mp_limb_t rem[dn], q[nn], qtop;
  for (mp_size_t i = 0; i < dn; i++)
    rem[i] = 0;
  for (mp_size_t i = 0; i < nn; i++)
    q[i] = 0;
  for (long bit = (long)nn * 64 - 1; bit >= 0; bit--)
    {
      mp_limb_t top = rem[dn - 1] >> 63;
      pqz_mpn_lshift (rem, rem, dn, 1);
      rem[0] |= (np[bit >> 6] >> (bit & 63)) & 1;
      /* ge = top || rem >= d */
      mp_limb_t br = 0;
      for (mp_size_t i = 0; i < dn; i++)
        {
          mp_limb_t d = rem[i] - dp[i];
          mp_limb_t b1 = rem[i] < dp[i];
          b1 |= d < br;
          br = b1;
        }
      mp_limb_t ge = (top | (br ^ 1)) & 1;
      pqz__cnd_sub_ge (rem, dp, dn, top);
      q[bit >> 6] |= ge << (bit & 63);
    }
  for (mp_size_t i = 0; i < dn; i++)
    np[i] = rem[i];
  qtop = q[nn - dn];
  if (qp != NULL)
    for (mp_size_t i = 0; i < nn - dn; i++)
      qp[i] = q[i];
  return qtop;
}

#define pqz_mpn_sec_div_qr_itch(nn, dn) ((mp_size_t)1)
static inline mp_limb_t
pqz_mpn_sec_div_qr (mp_limb_t *qp, mp_limb_t *np, mp_size_t nn, const mp_limb_t *dp, mp_size_t dn,
                    mp_limb_t *tp)
{
  (void)tp;
  return pqz__div (qp, np, nn, dp, dn);
}

#define pqz_mpn_sec_div_r_itch(nn, dn) ((mp_size_t)1)
static inline void
pqz_mpn_sec_div_r (mp_limb_t *np, mp_size_t nn, const mp_limb_t *dp, mp_size_t dn, mp_limb_t *tp)
{
  (void)tp;
  (void)pqz__div (NULL, np, nn, dp, dn);
}

/*
 * r = a^-1 mod m for odd prime m by Fermat (a^(m-2)), square-and-multiply over all bits of m - 2
 * with a masked multiply: constant-time in a. Used only on public constants (int_invmod).
 * Returns 1 (m is prime in every caller).
 */
#define pqz_mpn_sec_invert_itch(n) ((mp_size_t)1)
static inline int
pqz_mpn_sec_invert (mp_limb_t *r, mp_limb_t *a, const mp_limb_t *m, mp_size_t n, mp_bitcnt_t bits,
                    mp_limb_t *tp)
{
  (void)bits;
  (void)tp;
  mp_limb_t e[n], acc[n], prod[2 * n], base[n], one = 1;
  pqz_mpn_copyi (e, m, n);
  /* e = m - 2 */
  {
    mp_limb_t br = 2;
    for (mp_size_t i = 0; i < n; i++)
      {
        mp_limb_t d = e[i] - br;
        br = e[i] < br;
        e[i] = d;
      }
  }
  for (mp_size_t i = 0; i < n; i++)
    acc[i] = 0;
  acc[0] = one;
  pqz_mpn_copyi (base, a, n);
  for (long bit = (long)n * 64 - 1; bit >= 0; bit--)
    {
      pqz_mpn_sec_mul (prod, acc, n, acc, n, NULL);
      pqz__div (NULL, prod, 2 * n, m, n);
      pqz_mpn_copyi (acc, prod, n);
      pqz_mpn_sec_mul (prod, acc, n, base, n, NULL);
      pqz__div (NULL, prod, 2 * n, m, n);
      const mp_limb_t take = -((e[bit >> 6] >> (bit & 63)) & 1);
      for (mp_size_t i = 0; i < n; i++)
        acc[i] = (acc[i] & ~take) | (prod[i] & take);
    }
  pqz_mpn_copyi (r, acc, n);
  return 1;
}

#define mpn_copyi pqz_mpn_copyi
#define mpn_com pqz_mpn_com
#define mpn_cnd_swap pqz_mpn_cnd_swap
#define mpn_sec_add_1_itch pqz_mpn_sec_add_1_itch
#define mpn_sec_add_1 pqz_mpn_sec_add_1
#define mpn_mul_1 pqz_mpn_mul_1
#define mpn_lshift pqz_mpn_lshift
#define mpn_rshift pqz_mpn_rshift
#define mpn_sec_mul_itch pqz_mpn_sec_mul_itch
#define mpn_sec_mul pqz_mpn_sec_mul
#define mpn_sec_sqr_itch pqz_mpn_sec_sqr_itch
#define mpn_sec_sqr pqz_mpn_sec_sqr
#define mpn_sec_div_qr_itch pqz_mpn_sec_div_qr_itch
#define mpn_sec_div_qr pqz_mpn_sec_div_qr
#define mpn_sec_div_r_itch pqz_mpn_sec_div_r_itch
#define mpn_sec_div_r pqz_mpn_sec_div_r
#define mpn_sec_invert_itch pqz_mpn_sec_invert_itch
#define mpn_sec_invert pqz_mpn_sec_invert

#endif
