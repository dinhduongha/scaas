/*
 * pqz-core glue between LaZer's int_t (sign-magnitude limbs) and the uint64 arithmetic mod q.
 * Included at the end of lazer-in2.h (needs int_t and the limb helpers).
 */
#ifndef PQZ_GLUE_H
#define PQZ_GLUE_H

#include "pqz_ntt.h"

/* |a| mod m for a single-limb modulus m < 2^63: limb-by-limb, 64 masked shift-subtract steps per limb */
static inline uint64_t
pqz_absmod1 (const int_t a, uint64_t m)
{
  uint64_t r = 0;
  int k;
  if (m == PQZ_Q)
    {
      for (k = (int)a->nlimbs - 1; k >= 0; k--)
        r = pqz_red128 (((pqz_u128)r << 64) | a->limbs[k]);
      return r;
    }
  for (k = (int)a->nlimbs - 1; k >= 0; k--)
    for (int b = 63; b >= 0; b--)
      {
        r = (r << 1) | ((a->limbs[k] >> b) & 1);
        uint64_t t = r - m;
        r = t + (m & (uint64_t)((int64_t)t >> 63));
      }
  return r;
}

/* upstream int_mod_XXX semantics: result in (-m, m) with the sign of a */
static inline int64_t
pqz_int_mod1 (const int_t a, uint64_t m)
{
  int64_t r = (int64_t)pqz_absmod1 (a, m);
  int64_t s = -(int64_t)(a->neg & 1);
  return (r ^ s) - s;
}

/* a mod q in [0, q) */
static inline uint64_t
pqz_int_modq (const int_t a)
{
  uint64_t r = pqz_absmod1 (a, PQZ_Q);
  uint64_t neg = -(uint64_t)(a->neg & 1);
  return pqz_csubq ((r & ~neg) | ((PQZ_Q - r) & neg));
}

/* c = centred representative of v in [0, q) */
static inline void
pqz_int_set_centred (int_t c, uint64_t v)
{
  /* compiled to a flag move, no branch; the mask through the value barrier (review round 2, Q-G) */
  uint64_t big = pqz_ct_barrier (-(uint64_t)(v > (PQZ_Q - 1) / 2));
  c->limbs[0] = (v & ~big) | ((PQZ_Q - v) & big);
  for (unsigned i = 1; i < c->nlimbs; i++)
    c->limbs[i] = 0;
  c->neg = big & 1;
}

static inline void
pqz_ntt_add (uint64_t r[64], const uint64_t a[64], const uint64_t b[64])
{
  for (int k = 0; k < 64; k++)
    r[k] = pqz_csubq (a[k] + b[k]);
}

static inline void
pqz_ntt_sub (uint64_t r[64], const uint64_t a[64], const uint64_t b[64])
{
  for (int k = 0; k < 64; k++)
    r[k] = pqz_csubq (a[k] + PQZ_Q - b[k]);
}

/* 1 iff p is the zero polynomial, in either domain (the NTT residues are canonical, in [0, q)). Variable-time:
   for public data only (statement selection matrices, P6d-2) */
static inline int
pqz_poly_is_zero_pub (const poly_struct *p)
{
  unsigned int j;

  if (p->crt)
    {
      for (j = 0; j < PQZ_D; j++)
        if (((const uint64_t *)p->crtrep)[j] != 0)
          return 0;
      return 1;
    }
  for (j = 0; j < p->coeffs->nelems; j++)
    if (!int_eqzero (intvec_get_elem (p->coeffs, j)))
      return 0;
  return 1;
}

#endif
