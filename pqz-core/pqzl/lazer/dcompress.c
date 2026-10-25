#include "lazer.h"

/* PQZ (review E): the prover decomposes secret-derived values (w = A1 y1 + A2 y2 in lnp-quad.c, the hint inputs), so
   decompose, power2round and make_ghint are branch-free: each conditional add / subtract of gamma, 2^D or m adds
   or subtracts a masked copy (a masked-out 0 leaves the operand as it was, sign included), and each conditional
   assignment is a masked select. Same values as upstream's branches ("not ctime" below is upstream's note). */

/* r = r + (c ? a : 0) (add) or r - (c ? a : 0); c in {0, 1} */
static void
_cnd_addsub (int_ptr r, int_srcptr a, limb_t c, int sub)
{
  INT_T (t, r->nlimbs);
  const limb_t mask = pqz_ct_barrier (0 - c);

  int_set (t, a);
  for (unsigned int k = 0; k < t->nlimbs; k++)
    t->limbs[k] &= mask;
  t->neg &= mask;
  if (sub)
    int_sub (r, r, t);
  else
    int_add (r, r, t);
}

/* upstream's centring branches, masked: r negative and |r| <= g/2 (>= if geq): r += g; r non-negative and
   |r| > g/2: r -= g (both tests on the input r) */
static void
_centre (int_ptr r, int_srcptr g, int_srcptr gby2, int geq)
{
  const limb_t neg = r->neg & (1 ^ limbs_eq_zero_ct (r->limbs, r->nlimbs)); /* int_sgn (r) == -1 */
  const limb_t lo = (limb_t)(geq ? int_absge (r, gby2) : int_absle (r, gby2));
  const limb_t hi = (limb_t)int_absgt (r, gby2);

  _cnd_addsub (r, g, neg & lo, 0);
  _cnd_addsub (r, g, (neg ^ 1) & hi, 1);
}

/*
 * not ctime, r in (-q,q)
 */
void
dcompress_decompose (intvec_t r1, intvec_t r0, const intvec_t r,
                     const dcompress_params_t params)
{
  int_ptr r1i, r0i;
  unsigned int i;
  unsigned int nlimbs = params->gamma->nlimbs;

  for (; params->gamma->limbs[nlimbs - 1] == 0; nlimbs--)
    ;

  INT_T (rq, r1->nlimbs - nlimbs + 1);
  INT_T (rr, nlimbs);
  INT_T (gamma_, nlimbs); /* gamma w/o zero padding */
  INT_T (one, r0->nlimbs);
  INTVEC_T (tmp, r0->nelems, nlimbs);

  ASSERT_ERR (r->nelems == r1->nelems);
  ASSERT_ERR (r->nlimbs == r1->nlimbs);
  ASSERT_ERR (r->nelems == r0->nelems);
  ASSERT_ERR (r->nlimbs == r0->nlimbs);
  ASSERT_ERR (r->nlimbs == params->qminus1->nlimbs);
  ASSERT_ERR (r->nlimbs == params->q->nlimbs);

  int_set (gamma_, params->gamma);
  int_set_i64 (one, 1);
  intvec_redp (r1, r, params->q);

  intvec_mod (tmp, r1, gamma_); /* in (-gamma,gamma) */
  intvec_set (r0, tmp);
  /* to (-gamma/2,gamma/2] */
  _VEC_FOREACH_ELEM (r0, i)
  {
    r0i = intvec_get_elem (r0, i);
    _centre (r0i, params->gamma, params->gammaby2, 0);
  }

  intvec_sub (r1, r1, r0);
  _VEC_FOREACH_ELEM (r1, i)
  {
    r1i = intvec_get_elem (r1, i);
    r0i = intvec_get_elem (r0, i);
    /* r1i == q - 1 ? (0, r0i - 1) : (r1i / gamma, r0i); the division always runs (public divisor, fixed steps) */
    const limb_t eq = (limb_t)int_eq (r1i, params->qminus1);
    const limb_t keep = pqz_ct_barrier (eq - 1); /* all ones iff not eq */
    INT_T (t, r1i->nlimbs);

    int_div (rq, rr, r1i, gamma_);
    int_set (t, rq);
    for (unsigned int k = 0; k < t->nlimbs; k++)
      r1i->limbs[k] = t->limbs[k] & keep;
    r1i->neg = t->neg & keep;
    _cnd_addsub (r0i, one, eq, 1);
  }
}

/*
 * not ctime, r in (-q,q)
 * PQZ (review R1-C1 / R2-C2): when q sits less than 2^(D-1) below 2^log2q (n2048-kmax1024: q = 2^42 - 215), r in
 * [q - 2^(D-1) + g, q) (g = 2^log2q - q) rounds to r1 = 2^(log2q - D), one above the (log2q - D)-bit commitment
 * field, and the honest prove failed. Such an r is given r1 = 0 and r := redp(r) - q, in (-2^(D-1), 0): r - r1 2^D (the
 * caller's low part tA2) stays below 2^(D-1) in absolute value and r1 2^D + tA2 = r mod q. No other r changes.
 */
void
dcompress_power2round (intvec_t ret, intvec_t r,
                       const dcompress_params_t params)
{
  int_ptr r0i;
  unsigned int i;
  INTVEC_T (r0, r->nelems, r->nlimbs);
  INTVEC_T (rp, r->nelems, r->nlimbs); /* redp(r) */

  ASSERT_ERR (ret->nelems == r->nelems);
  ASSERT_ERR (ret->nlimbs == r->nlimbs);

  intvec_redp (ret, r, params->q);

  intvec_rshift (r0, ret, params->D);
  intvec_lshift (r0, r0, params->D);
  intvec_sub (r0, ret, r0); /* in [0,2^D) */
  /* to (-(2^D)/2,(2^D)/2] */
  _VEC_FOREACH_ELEM (r0, i)
  {
    r0i = intvec_get_elem (r0, i);
    _cnd_addsub (r0i, params->pow2D, (limb_t)int_absgt (r0i, params->pow2Dby2), 1); /* PQZ (review E) */
  }

  intvec_set (rp, ret);
  intvec_sub (ret, ret, r0);
  /* PQZ (R1-C1 / R2-C2): ret = r1 2^D >= q only in the wrap case: r1 := 0, r := redp(r) - q (masked) */
  _VEC_FOREACH_ELEM (ret, i)
  {
    int_ptr reti = intvec_get_elem (ret, i), ri = intvec_get_elem (r, i);
    const limb_t wrap = (limb_t)int_absge (reti, params->q);
    const limb_t keep = pqz_ct_barrier (wrap - 1); /* all ones iff no wrap */
    INT_T (dlt, ri->nlimbs);
    for (unsigned int k = 0; k < reti->nlimbs; k++)
      reti->limbs[k] &= keep;
    int_sub (dlt, intvec_get_elem (rp, i), params->q);
    int_sub (dlt, dlt, ri);
    _cnd_addsub (ri, dlt, wrap, 0);
  }
  intvec_rshift (ret, ret, params->D);
}

/*
 * r in (-q,q), y in (-m/2,m/2], not ctime
 */
void
dcompress_use_ghint (intvec_t ret, const intvec_t y, const intvec_t r,
                     const dcompress_params_t params)
{
  INTVEC_T (r0, ret->nelems, ret->nlimbs);
  int_ptr reti;
  unsigned int i;

  ASSERT_ERR (ret->nlimbs == y->nlimbs);
  ASSERT_ERR (ret->nelems == y->nelems);
  ASSERT_ERR (ret->nlimbs == r->nlimbs);
  ASSERT_ERR (ret->nelems == r->nelems);

  dcompress_decompose (ret, r0, r, params);
  intvec_add (ret, ret, y);
  intvec_mod (ret, ret, params->m); /* in (-m,m) */
  /* to [0,m) */
  _VEC_FOREACH_ELEM (r0, i)
  {
    reti = intvec_get_elem (ret, i);

    if (int_sgn (reti) == -1)
      int_add (reti, reti, params->m);
  }
}

/*
 * r in [-(q-1)/2,(q-1)/2], z in [-gamma/2, gamma/2], not ctime
 */
void
dcompress_make_ghint (intvec_t ret, const intvec_t z, const intvec_t r,
                      const dcompress_params_t params)
{
  INTVEC_T (r1, ret->nelems, ret->nlimbs);
  INTVEC_T (r0, ret->nelems, ret->nlimbs);
  INTVEC_T (v0, ret->nelems, ret->nlimbs);
  int_ptr reti;
  unsigned int i;

  ASSERT_ERR (ret->nelems == z->nelems);
  ASSERT_ERR (ret->nlimbs == z->nlimbs);
  ASSERT_ERR (ret->nelems == r->nelems);
  ASSERT_ERR (ret->nlimbs == r->nlimbs);

  intvec_add (ret, r, z); /* ret in (-q,q) */

  dcompress_decompose (r1, r0, r, params);
  dcompress_decompose (ret, v0, ret, params);

  intvec_sub (ret, ret, r1);
  intvec_mod (ret, ret, params->m); /* in (-m,m) */
  if (params->m_odd)
    {
      /* to [-(m-1)/2,(m-1)/2] */
      intvec_redc (ret, ret, params->m);
    }
  else
    {
      /* to (-m/2,m/2] */
      _VEC_FOREACH_ELEM (r0, i)
      {
        reti = intvec_get_elem (ret, i);
        _centre (reti, params->m, params->mby2, 1); /* PQZ (review E) */
      }
    }
}
