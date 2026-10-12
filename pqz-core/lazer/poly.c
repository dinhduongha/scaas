#include "poly.h"
#include "brandom.h"
#include "grandom.h"
#include "intvec.h"
#include "lazer.h"
#include "memory.h"
// #include "ntt.h"
#include "urandom.h"

void
poly_alloc (poly_ptr r, const polyring_t ring)
{
  void *mem;

  mem = _alloc (_sizeof_poly_data (ring));

  _poly_init (r, ring, mem);
  r->mem = mem;
}

void
poly_free (poly_ptr r)
{
  if (r == NULL)
    return;

  if (r->crt)
    _free (r->crtrep, _sizeof_crtrep_data (r->ring));
  _free (r->mem, _sizeof_poly_data (r->ring));
}

void
poly_set (poly_t r, const poly_t a)
{
  polyring_srcptr ring = a->ring;
  intvec_srcptr acoeffs;

  // XXXASSERT_ERR (r->ring == a->ring);

  r->crt = a->crt;
  if (r->crt)
    {
      if (r->crtrep == NULL)
        r->crtrep = _alloc (_sizeof_crtrep_data (ring));

      memcpy (r->crtrep, a->crtrep, _sizeof_crtrep_data (ring));
    }
  else
    {
      acoeffs = _get_coeffvec_src (a);
      poly_set_coeffvec (r, acoeffs);
    }
}

void
poly_add (poly_t r, poly_t a, poly_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);

  ASSERT_ERR (ring == poly_get_ring (a));
  ASSERT_ERR (ring == poly_get_ring (b));

  r->crt = _to_same_dom (a, b, crt);
  if (r->crt)
    {
      /* PQZ: NTT domain mod q (pqz_ntt.c); was HEXL per CRT prime */
      if (r->crtrep == NULL)
        r->crtrep = _alloc (_sizeof_crtrep_data (ring));
      pqz_ntt_add ((uint64_t *)r->crtrep, (uint64_t *)a->crtrep, (uint64_t *)b->crtrep);
    }
  else
    {
      intvec_add (r->coeffs, a->coeffs, b->coeffs);
      intvec_redc (r->coeffs, r->coeffs, ring->q);
    }
}

void
poly_sub (poly_t r, poly_t a, poly_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);

  ASSERT_ERR (ring == poly_get_ring (a));
  ASSERT_ERR (ring == poly_get_ring (b));

  r->crt = _to_same_dom (a, b, crt);
  if (r->crt)
    {
      /* PQZ: NTT domain mod q (pqz_ntt.c); was HEXL per CRT prime */
      if (r->crtrep == NULL)
        r->crtrep = _alloc (_sizeof_crtrep_data (ring));
      pqz_ntt_sub ((uint64_t *)r->crtrep, (uint64_t *)a->crtrep, (uint64_t *)b->crtrep);
    }
  else
    {
      intvec_sub (r->coeffs, a->coeffs, b->coeffs);
      intvec_redc (r->coeffs, r->coeffs, ring->q);
    }
}

void
poly_neg (poly_t r, poly_t b)
{
#if ASSERT == ASSERT_ENABLED
  polyring_srcptr ring = poly_get_ring (r);
#endif
  ASSERT_ERR (ring == poly_get_ring (b));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (b->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt neg");
#endif
  _fromcrt (b); // XXX can also do this in crt dom

  r->crt = 0;
  intvec_neg (r->coeffs, b->coeffs);
}

void
poly_scale (poly_t r, const int_t a, poly_t b)
{
  polyring_srcptr ring = poly_get_ring (r);

  ASSERT_ERR (ring == poly_get_ring (b));
  ASSERT_ERR (a->nlimbs == b->coeffs->nlimbs);

  INTVEC_T (tmp, polyring_get_deg (ring), 2 * a->nlimbs);

  _fromcrt (b); // XXX can also do this in crt dom

  r->crt = 0;
  intvec_scale (tmp, a, _get_coeffvec_src (b));
  intvec_mod (r->coeffs, tmp, ring->q);
  intvec_redc (r->coeffs, r->coeffs, ring->q);
}

void
poly_rshift (poly_t r, poly_t a, unsigned int n)
{
  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt rshift");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_rshift (r->coeffs, a->coeffs, n);
}

void
poly_lshift (poly_t r, poly_t a, unsigned int n)
{
  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt lshift");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_lshift (r->coeffs, a->coeffs, n);
}

void
poly_rrot (poly_t r, poly_t a, unsigned int n)
{
  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt rrot");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_rrot (r->coeffs, a->coeffs, n);
}

void
poly_lrot (poly_t r, poly_t a, unsigned int n)
{
  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt lrot");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_lrot (r->coeffs, a->coeffs, n);
}

void
poly_mod (poly_t r, poly_t a)
{
  polyring_srcptr ring = poly_get_ring (r);

  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt mod");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_mod (r->coeffs, a->coeffs, ring->q);
}

void
poly_redc (poly_t r, poly_t a)
{
  polyring_srcptr ring = poly_get_ring (r);

  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt redc");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_redc (r->coeffs, a->coeffs, ring->q);
}

void
poly_redp (poly_t r, poly_t a)
{
  polyring_srcptr ring = poly_get_ring (r);

  ASSERT_ERR (poly_get_ring (r) == poly_get_ring (a));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt redp");
#endif
  _fromcrt (a);

  r->crt = 0;
  intvec_redp (r->coeffs, a->coeffs, ring->q);
}

int
poly_eq (poly_t a, poly_t b)
{
  ASSERT_ERR (poly_get_ring (a) == poly_get_ring (b));

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt eq");
#endif
  _fromcrt (a);
#if DEBUGINFO == DEBUGINFO_ENABLED
  if (b->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt eq");
#endif
  _fromcrt (b);

  return intvec_eq (_get_coeffvec_src (a), _get_coeffvec_src (b));
}

void
poly_toisoring (polyvec_t vec, poly_t a)
{
  polyring_srcptr Rprime = poly_get_ring (a);
  polyring_srcptr R = polyvec_get_ring (vec);
  const unsigned int dprime = polyring_get_deg (Rprime);
  const unsigned int d = polyring_get_deg (R);
  const unsigned int k = dprime / d;
  unsigned int i, j, l;
  poly_ptr poly;
  int_ptr coeffprime, coeff;

  ASSERT_ERR (!a->crt);
  ASSERT_ERR (d * k == dprime);
  ASSERT_ERR (polyvec_get_nelems (vec) == k);
  // XXXASSERT_ERR (int_eq (polyring_get_mod (Rprime), polyring_get_mod (R)) ==
  // 1);

  for (i = 0; i < k; i++)
    {
      poly = polyvec_get_elem (vec, i);
      poly->crt = 0;
      for (j = 0; j < d; j++)
        {
          l = k * j + i;

          coeffprime = poly_get_coeff (a, l);
          coeff = poly_get_coeff (poly, j);
          int_set (coeff, coeffprime);
        }
    }
}

void
poly_fromisoring (poly_t a, polyvec_t vec)
{
  polyring_srcptr Rprime = poly_get_ring (a);
  polyring_srcptr R = polyvec_get_ring (vec);
  const unsigned int dprime = polyring_get_deg (Rprime);
  const unsigned int d = polyring_get_deg (R);
  const unsigned int k = dprime / d;
  unsigned int i, j, l;
  poly_ptr poly;
  int_ptr coeffprime, coeff;

  ASSERT_ERR (d * k == dprime);
  ASSERT_ERR (polyvec_get_nelems (vec) == k);
  // XXXASSERT_ERR (int_eq (polyring_get_mod (Rprime), polyring_get_mod (R)) ==
  // 1);

  polyvec_fromcrt (vec);

  for (i = 0; i < k; i++)
    {
      poly = polyvec_get_elem (vec, i);
      for (j = 0; j < d; j++)
        {
          l = k * j + i;

          coeff = poly_get_coeff (poly, j);
          coeffprime = poly_get_coeff (a, l);
          int_set (coeffprime, coeff);
        }
    }
  a->crt = 0;
}

void
poly_mul (poly_t r, poly_t a, poly_t b)
{
  polyring_srcptr ring = r->ring;

  ASSERT_ERR (r->ring == a->ring);
  ASSERT_ERR (r->ring == b->ring);

  _tocrt (a);
  _tocrt (b);

  if (r->crtrep == NULL)
    {
      ASSERT_ERR (r->crt == 0);
      r->crtrep = _alloc (_sizeof_crtrep_data (ring));
    }
  r->crt = 1;
  /* PQZ: base multiplication mod X^16 - rho_j (pqz_ntt.c); was HEXL pointwise per CRT prime */
  pqz_ntt_basemul ((uint64_t *)r->crtrep, (uint64_t *)a->crtrep, (uint64_t *)b->crtrep);
}

void
poly_addmul (poly_t r, poly_t a, poly_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  poly_mul (tmp, a, b);
  poly_add (r, r, tmp, crt);

  poly_free (tmp);
}

void
poly_submul (poly_t r, poly_t a, poly_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  poly_mul (tmp, a, b);
  poly_sub (r, r, tmp, crt);

  poly_free (tmp);
}

void
poly_addmul2 (poly_t r, polymat_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  polyvec_t tmp;

  polyvec_alloc (tmp, ring, 1);

  ASSERT_ERR (polymat_get_nrows (a) == 1);

  polyvec_mul (tmp, a, b);
  poly_add (r, r, polyvec_get_elem (tmp, 0), crt);

  polyvec_free (tmp);
}

void
poly_submul2 (poly_t r, polymat_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  polyvec_t tmp;

  polyvec_alloc (tmp, ring, 1);

  ASSERT_ERR (polymat_get_nrows (a) == 1);

  polyvec_mul (tmp, a, b);
  poly_sub (r, r, polyvec_get_elem (tmp, 0), crt);

  polyvec_free (tmp);
}

void
poly_adddot (poly_t r, polyvec_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  polyvec_dot (tmp, a, b);
  poly_add (r, r, tmp, crt);

  poly_free (tmp);
}

void
poly_adddot2 (poly_t r, spolyvec_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  polyvec_dot2 (tmp, a, b);
  poly_add (r, r, tmp, crt);

  poly_free (tmp);
}

void
poly_subdot (poly_t r, polyvec_t a, polyvec_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  polyvec_dot (tmp, a, b);
  poly_sub (r, r, tmp, crt);

  poly_free (tmp);
}

void
poly_addscale (poly_t r, int_t a, poly_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  poly_scale (tmp, a, b);
  poly_add (r, r, tmp, crt);

  poly_free (tmp);
}

void
poly_subscale (poly_t r, int_t a, poly_t b, int crt)
{
  polyring_srcptr ring = poly_get_ring (r);
  poly_t tmp;

  poly_alloc (tmp, ring);

  poly_scale (tmp, a, b);
  poly_sub (r, r, tmp, crt);

  poly_free (tmp);
}

void
poly_tocrt (poly_t r)
{
  if (r->crt == 1)
    return;

  polyring_srcptr ring = poly_get_ring (r);
  const unsigned int deg = polyring_get_deg (ring);
  unsigned int j;

  /* PQZ: coefficients -> [0, q) -> incomplete NTT mod q. Only the PQZ ring exists. */
  ERR (deg != PQZ_D || ring->q->nlimbs != 1 || ring->q->limbs[0] != PQZ_Q, "%s", "ring is not R_q");

  if (r->crtrep == NULL)
    r->crtrep = _alloc (_sizeof_crtrep_data (ring));
  r->crt = 1;

  uint64_t *c = (uint64_t *)r->crtrep;
  for (j = 0; j < PQZ_D; j++)
    c[j] = pqz_int_modq (intvec_get_elem (r->coeffs, j));
  pqz_ntt_fwd (c);
}

void
poly_fromcrt (poly_t r)
{
  if (r->crt == 0)
    return;

  polyring_srcptr ring = poly_get_ring (r);
  intvec_ptr coeffs = _get_coeffvec (r);
  uint64_t *c = (uint64_t *)r->crtrep;
  unsigned int j;

  /* PQZ: inverse NTT mod q, then the centred representative in [-(q-1)/2, (q-1)/2] (as upstream's
     int_mod + int_redc after the CRT reconstruction, which used a float rounding step) */
  pqz_ntt_inv (c);
  for (j = 0; j < PQZ_D; j++)
    pqz_int_set_centred (intvec_get_elem (coeffs, j), c[j]);

  _free (r->crtrep, _sizeof_crtrep_data (ring));
  r->crtrep = NULL;
  r->crt = 0;
}

void
poly_grandom (poly_t r, unsigned int log2o, const uint8_t seed[32],
              uint32_t dom)
{
  _poly_grandom (r, log2o, seed, dom);
}

void
poly_urandom (poly_t r, const int_t mod, unsigned int log2mod,
              const uint8_t seed[32], uint32_t dom)
{
  _poly_urandom (r, mod, log2mod, seed, dom);
}

void
poly_urandom_autostable (poly_t r, int64_t bnd, unsigned int log2,
                         const uint8_t seed[32], uint32_t dom)
{
  _poly_urandom_autostable (r, bnd, log2, seed, dom);
}

void
poly_urandom_bnd (poly_t r, const int_t lo, const int_t hi,
                  const uint8_t seed[32], uint32_t dom)
{
  _poly_urandom_bnd (r, lo, hi, seed, dom);
}

void
poly_brandom (poly_t r, unsigned int k, const uint8_t seed[32], uint32_t dom)
{
  _poly_brandom (r, k, seed, dom);
}

/* output coeffs in (-q,q) */
void
poly_tracemap (poly_t r, poly_t a)
{
  INT_T (prod, r->ring->q->nlimbs * 2);
  intvec_ptr rcoeffs = r->coeffs;
  intvec_ptr acoeffs = a->coeffs;
  const unsigned int nelems = rcoeffs->nelems / 2;
  unsigned int i;
  int_ptr ri, ai;
  int_srcptr ris, ais;

  ASSERT_ERR (r->ring == a->ring);

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt tracemap");
#endif
  _fromcrt (a);

  intvec_set_elem (rcoeffs, 0, intvec_get_elem_src (acoeffs, 0));

  for (i = 1; i < nelems; i++)
    {
      ri = intvec_get_elem (rcoeffs, i);
      ai = intvec_get_elem (acoeffs, i);
      ais = intvec_get_elem_src (acoeffs, acoeffs->nelems - i);
      int_sub (ri, ai, ais);
      int_mul (prod, ri, r->ring->inv2);
      int_mod (ri, prod, r->ring->q);
      int_redc (ri, ri, r->ring->q);
    }
  intvec_set_elem_i64 (rcoeffs, nelems, 0);
  for (i = nelems + 1; i < rcoeffs->nelems; i++)
    {
      ri = intvec_get_elem (rcoeffs, i);
      ris = intvec_get_elem_src (rcoeffs, 2 * nelems - i);
      int_neg (ri, ris);
    }

  r->crt = 0;
}

void
poly_auto (poly_t r, poly_t a)
{
  ASSERT_ERR (r != a);

#ifdef XXX
  /* o-1 auto in crt form reverses crt coeffs */
  if (a->crt == 1)
    {
      crtcoeff_t *ca, *cr;
      polyring_srcptr ring = poly_get_ring (a);
      const unsigned int deg = polyring_get_deg (ring);
      unsigned int i, j;

      if (r->crtrep == NULL)
        r->crtrep = _alloc (_sizeof_crtrep_data (ring));
      r->crt = 1;

      _POLYRING_FOREACH_P (ring, i)
      {
        for (j = 0; j < deg; j++)
          {
            cr = _get_crtcoeff (r->crtrep, i, j, deg);
            ca = _get_crtcoeff (a->crtrep, i, deg - j - 1, deg);

            *cr = *ca;
          }
      }
    }
  else
    {
      intvec_ptr rcoeffvec = _get_coeffvec (r);
      intvec_ptr acoeffvec = _get_coeffvec (a);

      intvec_auto (rcoeffvec, acoeffvec);
    }

  /* o-1 auto in crt form reverses crt coeffs */
  if (a->crt == 1)
    {
      crtcoeff_t *ca, *cb, tmp;
      polyring_srcptr ring = poly_get_ring (a);
      const unsigned int deg = polyring_get_deg (ring);
      unsigned int i, j;

      _POLYRING_FOREACH_P (ring, i)
      {
        for (j = 0; j < deg / 2; j++)
          {
            ca = _get_crtcoeff (a->crtrep, i, j, deg);
            cb = _get_crtcoeff (a->crtrep, i, deg - j - 1, deg);

            tmp = *cb;
            *cb = *ca;
            *ca = tmp;
          }
      }
    }
  else
    {
      intvec_ptr rcoeffvec = _get_coeffvec (r);
      intvec_ptr acoeffvec = _get_coeffvec (a);

      intvec_auto (rcoeffvec, acoeffvec);
    }
#endif

  intvec_ptr rcoeffvec = _get_coeffvec (r);
  intvec_ptr acoeffvec = _get_coeffvec (a);

  ASSERT_ERR (r->ring == a->ring);

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt auto");
#endif
  _fromcrt (a);

  intvec_auto (rcoeffvec, acoeffvec);
  r->crt = 0;
}

void
poly_auto_self (poly_t r)
{
  /* o-1 auto in crt form reverses crt coeffs */
  if (r->crt == 1)
    {
      crtcoeff_t *crb, *cre, tmp;
      polyring_srcptr ring = poly_get_ring (r);
      const unsigned int deg = polyring_get_deg (ring);
      unsigned int i, j;

      _POLYRING_FOREACH_P (ring, i)
      {
        for (j = 0; j < deg / 2; j++)
          {
            crb = _get_crtcoeff (r->crtrep, i, j, deg);
            cre = _get_crtcoeff (r->crtrep, i, deg - j - 1, deg);

            tmp = *crb;
            *crb = *cre;
            *cre = tmp;
          }
      }
    }
  else
    {
      intvec_ptr rcoeffvec = _get_coeffvec (r);

      intvec_auto_self (rcoeffvec);
    }
}

void
poly_dcompress_power2round (poly_t r, poly_t a,
                            const dcompress_params_t params)
{
  intvec_ptr rcoeffvec = _get_coeffvec (r);
  intvec_ptr acoeffvec = _get_coeffvec (a);

  ASSERT_ERR (r->ring == a->ring);

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s",
                  "implicit icrt dcompress power2round");
#endif
  _fromcrt (a);

  dcompress_power2round (rcoeffvec, acoeffvec, params);
  r->crt = 0;
}

void
poly_dcompress_decompose (poly_t r1, poly_t r0, poly_t r,
                          const dcompress_params_t params)
{
  intvec_ptr r0coeffvec = _get_coeffvec (r0);
  intvec_ptr r1coeffvec = _get_coeffvec (r1);
  intvec_ptr rcoeffvec = _get_coeffvec (r);

  ASSERT_ERR (r->ring == r0->ring);
  ASSERT_ERR (r->ring == r1->ring);

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (r->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt dcompress decompose");
#endif
  _fromcrt (r);

  dcompress_decompose (r1coeffvec, r0coeffvec, rcoeffvec, params);
  r1->crt = 0;
  r0->crt = 0;
}

void
poly_dcompress_use_ghint (poly_t ret, poly_t y, poly_t r,
                          const dcompress_params_t params)
{
  intvec_ptr retcoeffvec = _get_coeffvec (ret);
  intvec_ptr ycoeffvec = _get_coeffvec (y);
  intvec_ptr rcoeffvec = _get_coeffvec (r);

  ASSERT_ERR (ret->ring == y->ring);
  ASSERT_ERR (ret->ring == r->ring);

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (y->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt dcompress use ghint");
#endif
  _fromcrt (y);
#if DEBUGINFO == DEBUGINFO_ENABLED
  if (r->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt dcompress use ghint");
#endif
  _fromcrt (r);

  dcompress_use_ghint (retcoeffvec, ycoeffvec, rcoeffvec, params);
  ret->crt = 0;
}

void
poly_dcompress_make_ghint (poly_t ret, poly_t z, poly_t r,
                           const dcompress_params_t params)
{
  intvec_ptr retcoeffvec = _get_coeffvec (ret);
  intvec_ptr zcoeffvec = _get_coeffvec (z);
  intvec_ptr rcoeffvec = _get_coeffvec (r);

  ASSERT_ERR (ret->ring == z->ring);
  ASSERT_ERR (ret->ring == r->ring);

  _fromcrt (z);
  _fromcrt (r);

  dcompress_make_ghint (retcoeffvec, zcoeffvec, rcoeffvec, params);
  ret->crt = 0;
}

void
poly_l2sqr (int_t r, poly_t a)
{
  _fromcrt (a);

  intvec_l2sqr (r, poly_get_coeffvec (a));
}

void
poly_linf (int_t r, poly_t a)
{
  _fromcrt (a);

  intvec_linf (r, poly_get_coeffvec (a));
}

#if PQZ_STDIO
size_t
poly_out_str (FILE *stream, int base, poly_t a)
{
  _fromcrt (a);
  return intvec_out_str (stream, base, a->coeffs);
}
#endif

#if PQZ_STDIO
void
poly_dump (poly_t a)
{
  poly_out_str (stdout, 10, a);
  fprintf (stdout, "\n");
  fflush (stdout);
}
#endif

static void
_poly_urandom (poly_t r, const int_t mod, unsigned int log2mod,
               const uint8_t seed[32], uint64_t dom)
{
  intvec_ptr coeffvec = _get_coeffvec (r);

  r->crt = 0;
  _intvec_urandom (coeffvec, mod, log2mod, seed, dom);
}

static void
_poly_brandom (poly_t r, unsigned int k, const uint8_t seed[32], uint64_t dom)
{
  intvec_ptr coeffvec = _get_coeffvec (r);

  r->crt = 0;
  _intvec_brandom (coeffvec, k, seed, dom);
}

static void
_poly_grandom (poly_t r, unsigned int log2o, const uint8_t seed[32],
               uint64_t dom)
{
  intvec_ptr coeffvec = _get_coeffvec (r);

  r->crt = 0;
  _intvec_grandom (coeffvec, log2o, seed, dom);
}

static void
_poly_urandom_autostable (poly_t r, int64_t bnd, unsigned int log2,
                          const uint8_t seed[32], uint64_t dom)
{
  _intvec_urandom_autostable (r->coeffs, bnd, log2, seed, dom);
  r->crt = 0;
}

static void
_poly_urandom_bnd (poly_t r, const int_t lo, const int_t hi,
                   const uint8_t seed[32], uint64_t dom)
{
  intvec_ptr coeffvec = _get_coeffvec (r);

  r->crt = 0;
  _urandom_bnd (coeffvec, lo, hi, seed, dom);
}
