/*
 * Test entry points into the C core's layers for the Rust port's oracle tests (feature c-oracle only: build.rs
 * compiles this file next to the core, never into it). Each entry point mirrors a function of src/testkit.rs step for
 * step; tests/oracle_*.rs compare the two outputs byte for byte. Plain data in and out.
 */
#include "lazer.h"

#include "pqz_tx_params.h"

/* a poly's whole live state: domain flag, then the signs (bit j) and the 64 magnitudes, or 0 and the 64 residues */
static void
dump_poly (uint64_t **o, poly_ptr p)
{
  unsigned j;
  *(*o)++ = (uint64_t)p->crt;
  if (p->crt)
    {
      *(*o)++ = 0;
      for (j = 0; j < 64; j++)
        *(*o)++ = ((uint64_t *)p->crtrep)[j];
      return;
    }
  uint64_t m = 0;
  for (j = 0; j < 64; j++)
    m |= (intvec_get_elem (p->coeffs, j)->neg & 1) << j;
  *(*o)++ = m;
  for (j = 0; j < 64; j++)
    *(*o)++ = intvec_get_elem (p->coeffs, j)->limbs[0];
}

static void
dump_vec (uint64_t **o, polyvec_t v)
{
  for (unsigned i = 0; i < polyvec_get_nelems (v); i++)
    dump_poly (o, polyvec_get_elem (v, i));
}

static void
dump_int (uint64_t **o, int_t a)
{
  *(*o)++ = a->nlimbs;
  *(*o)++ = a->neg;
  *(*o)++ = a->limbs[0];
  *(*o)++ = a->nlimbs > 1 ? a->limbs[1] : 0;
}

/* testkit::polyvec_ops: in = 31 polys x 64 coefficients (A 3x4, x 4, y 4, z 3, c, 3 sparse-vector entries, 4
   sparse-matrix entries) then the scalar; returns pqz_err, *n = words written */
int
pqz_shim_polyvec_ops (const int64_t *in, uint64_t *out, size_t *n)
{
  polyring_srcptr R = pqz_tx_ring;
  pqz_arena_mark_t mark;
  uint64_t *o = out;
  unsigned i, j, k = 0;
  polymat_t A, B;
  polyvec_t x, y, z, r3, r4, t4, svp, smp;
  poly_t c, d, e;
  spolyvec_t sv, sv2, sv3;
  spolymat_t sm, sm2, sm3;
  INT_T (s, 1);
  INT_T (l2, 2);
  INT_T (li, 1);

  pqz_err = PQZ_OK;
  pqz_arena_mark (&mark);
  polymat_alloc (A, R, 3, 4);
  polymat_alloc (B, R, 3, 4);
  polyvec_alloc (x, R, 4);
  polyvec_alloc (y, R, 4);
  polyvec_alloc (z, R, 3);
  polyvec_alloc (svp, R, 3);
  polyvec_alloc (smp, R, 4);
  polyvec_alloc (r3, R, 3);
  polyvec_alloc (r4, R, 4);
  polyvec_alloc (t4, R, 4);
  poly_alloc (c, R);
  poly_alloc (d, R);
  poly_alloc (e, R);
#define NEXT(p) poly_set_coeffvec_i64 ((p), in + 64 * k++)
  for (i = 0; i < 3; i++)
    for (j = 0; j < 4; j++)
      NEXT (polymat_get_elem (A, i, j));
  for (i = 0; i < 4; i++)
    NEXT (polyvec_get_elem (x, i));
  for (i = 0; i < 4; i++)
    NEXT (polyvec_get_elem (y, i));
  for (i = 0; i < 3; i++)
    NEXT (polyvec_get_elem (z, i));
  NEXT (c);
  for (i = 0; i < 3; i++)
    NEXT (polyvec_get_elem (svp, i));
  for (i = 0; i < 4; i++)
    NEXT (polyvec_get_elem (smp, i));
  int_set_i64 (s, in[64 * k]);

  poly_tocrt (polyvec_get_elem (y, 1)); /* mixed domains */
  poly_tocrt (polyvec_get_elem (z, 0));
  polyvec_mul (r3, A, x);
  dump_vec (&o, r3);
  polyvec_add (r4, x, y, 0);
  dump_vec (&o, r4);
  polyvec_sub (t4, x, y, 1);
  dump_vec (&o, t4);
  polyvec_addmul (r3, A, y, 0);
  dump_vec (&o, r3);
  polyvec_mul2 (r4, z, A);
  dump_vec (&o, r4);
  polyvec_scale (t4, s, y);
  dump_vec (&o, t4);
  polyvec_scale2 (r4, c, x);
  dump_vec (&o, r4);
  polyvec_dot (d, x, y);
  dump_poly (&o, d);
  polyvec_auto (t4, x);
  dump_vec (&o, t4);
  polyvec_lrot (r4, y, 5);
  dump_vec (&o, r4);
  polyvec_redp (t4, y);
  polyvec_mod (r4, x);
  dump_vec (&o, t4);
  dump_vec (&o, r4);
  polyvec_l2sqr (l2, y);
  polyvec_linf (li, x);
  dump_int (&o, l2);
  dump_int (&o, li);

  spolyvec_alloc (sv, R, 0, 4);
  poly_set (spolyvec_insert_elem (sv, 3), polyvec_get_elem (svp, 0));
  poly_set (spolyvec_insert_elem (sv, 0), polyvec_get_elem (svp, 1));
  poly_set (spolyvec_insert_elem (sv, 2), polyvec_get_elem (svp, 2));
  spolyvec_sort (sv);
  polyvec_dot2 (d, sv, x);
  dump_poly (&o, d);

  spolymat_alloc (sm, R, 3, 4, 6);
  poly_set (spolymat_insert_elem (sm, 2, 1), polyvec_get_elem (smp, 0));
  poly_set (spolymat_insert_elem (sm, 0, 3), polyvec_get_elem (smp, 1));
  poly_set (spolymat_insert_elem (sm, 0, 0), polyvec_get_elem (smp, 2));
  poly_set (spolymat_insert_elem (sm, 1, 2), polyvec_get_elem (smp, 3));
  spolymat_sort (sm);
  polyvec_mulsparse (r3, sm, y);
  dump_vec (&o, r3);

  polyvec_subscale2 (r3, c, z, 1);
  dump_vec (&o, r3);
  polyvec_addscale (r4, s, x, 0);
  dump_vec (&o, r4);
  poly_tracemap (d, c);
  dump_poly (&o, d);
  polyvec_neg_self (x);
  dump_vec (&o, x);

  spolymat_alloc (sm2, R, 3, 4, 6);
  spolymat_set (sm2, sm);
  spolymat_alloc (sm3, R, 3, 4, 10);
  spolymat_add (sm3, sm, sm2, 0);
  polyvec_mulsparse (r3, sm3, x);
  dump_vec (&o, r3);

  polyvec_redc (t4, x);
  dump_vec (&o, t4);
  polyvec_sublshift (r4, t4, 3);
  dump_vec (&o, r4);

  poly_auto_self (d);
  dump_poly (&o, d);
  /* poly_auto_self in the NTT domain (e = c x[0] is in it) */
  poly_mul (e, c, polyvec_get_elem (x, 0));
  poly_auto_self (e);
  dump_poly (&o, e);

  polymat_auto (B, A);
  for (i = 0; i < 3; i++)
    for (j = 0; j < 4; j++)
      dump_poly (&o, polymat_get_elem (B, i, j));
  polymat_lrot (B, A, 7);
  for (i = 0; i < 3; i++)
    for (j = 0; j < 4; j++)
      dump_poly (&o, polymat_get_elem (B, i, j));
  *o++ = (uint64_t)polymat_is_upperdiag (B);

  spolyvec_alloc (sv2, R, 0, 4);
  spolyvec_lrot (sv2, sv, 9);
  spolyvec_alloc (sv3, R, 0, 8);
  spolyvec_add (sv3, sv, sv2, 1);
  polyvec_dot2 (d, sv3, y);
  dump_poly (&o, d);
  spolyvec_scale2 (sv2, c, sv);
  polyvec_dot2 (d, sv2, x);
  dump_poly (&o, d);
  spolyvec_mod (sv2, sv);
  polyvec_dot2 (d, sv2, y);
  dump_poly (&o, d);
  spolyvec_scale (sv2, s, sv);
  polyvec_dot2 (d, sv2, x);
  dump_poly (&o, d);

  /* every operand's final state */
  for (i = 0; i < 3; i++)
    for (j = 0; j < 4; j++)
      dump_poly (&o, polymat_get_elem (A, i, j));
  dump_vec (&o, x);
  dump_vec (&o, y);
  dump_vec (&o, z);
  dump_poly (&o, c);
  for (i = 0; i < spolyvec_get_nelems (sv); i++)
    dump_poly (&o, spolyvec_get_elem (sv, i));
  for (i = 0; i < sm->nelems; i++)
    dump_poly (&o, spolymat_get_elem (sm, i));

  *n = (size_t)(o - out);
  pqz_arena_release (&mark);
  return pqz_err;
}

static void
dump_intn (uint64_t **o, const int_t a)
{
  *(*o)++ = a->nlimbs;
  *(*o)++ = a->neg;
  for (unsigned i = 0; i < a->nlimbs; i++)
    *(*o)++ = a->limbs[i];
}

/* testkit::int_ops: in = a (2 limbs, sign), b (2 limbs, sign), m (2 limbs), k (1 limb), shift, v[4], w[4] */
int
pqz_shim_int_ops (const uint64_t *in, uint64_t *out, size_t *n)
{
  uint64_t *o = out;
  unsigned i;
  INT_T (a, 2);
  INT_T (b, 2);
  INT_T (m, 2);
  INT_T (k, 1);
  INT_T (r1, 1);
  INT_T (r2, 2);
  INT_T (r4, 4);
  INT_T (q3, 3);
  INTVEC_T (v, 4, 1);
  INTVEC_T (w, 4, 1);

  pqz_err = PQZ_OK;
  a->limbs[0] = in[0], a->limbs[1] = in[1], a->neg = in[2] & 1;
  b->limbs[0] = in[3], b->limbs[1] = in[4], b->neg = in[5] & 1;
  m->limbs[0] = in[6], m->limbs[1] = in[7] | 1;
  k->limbs[0] = in[8] | 1;
  unsigned sh = (unsigned)(in[9] % 140);
  for (i = 0; i < 4; i++)
    {
      intvec_set_elem_i64 (v, i, (int64_t)in[10 + i]);
      intvec_set_elem_i64 (w, i, (int64_t)in[14 + i]);
    }

  int_add (r2, a, b);
  dump_intn (&o, r2);
  int_sub (r2, a, b);
  dump_intn (&o, r2);
  int_mul (r4, a, b);
  dump_intn (&o, r4);
  int_mod (r2, r4, m);
  dump_intn (&o, r2);
  int_mod (r1, a, k);
  dump_intn (&o, r1);
  int_div (q3, r2, r4, m);
  dump_intn (&o, q3);
  dump_intn (&o, r2);
  int_rshift (r2, a, sh);
  dump_intn (&o, r2);
  int_lshift (r2, a, sh);
  dump_intn (&o, r2);
  int_lshift (r4, a, sh);
  dump_intn (&o, r4);
  int_redc (r2, a, m);
  dump_intn (&o, r2);
  int_redp (r2, a, m);
  dump_intn (&o, r2);
  int_set (r1, a);
  dump_intn (&o, r1);
  int_set (r4, b);
  int_addmul (r4, a, b);
  dump_intn (&o, r4);
  int_submul (r4, b, b);
  dump_intn (&o, r4);
  int_subsqr (r4, a);
  dump_intn (&o, r4);
  int_set (r2, a);
  int_mul_sgn_self (r2, -1);
  dump_intn (&o, r2);
  *o++ = (uint64_t)int_eq (a, b) | (uint64_t)int_lt (a, b) << 1 | (uint64_t)int_le (a, b) << 2
         | (uint64_t)int_gt (a, b) << 3 | (uint64_t)int_ge (a, b) << 4 | (uint64_t)int_abslt (a, b) << 5
         | (uint64_t)int_absle (a, b) << 6 | (uint64_t)int_absgt (a, b) << 7 | (uint64_t)int_absge (a, b) << 8
         | (uint64_t)int_abseq (a, b) << 9 | (uint64_t)(int_sgn (a) + 1) << 10 | (uint64_t)int_eqzero (a) << 12;
  *o++ = (uint64_t)int_get_i64 (a);

  intvec_dot (r2, v, w);
  dump_intn (&o, r2);
  intvec_l2sqr (r2, v);
  dump_intn (&o, r2);
  intvec_linf (r1, w);
  dump_intn (&o, r1);
  *o++ = (uint64_t)intvec_lt (v, k) | (uint64_t)intvec_ge (v, k) << 1 | (uint64_t)intvec_le (w, k) << 2
         | (uint64_t)intvec_gt (w, k) << 3 | (uint64_t)intvec_eq (v, w) << 4;
  intvec_add (v, v, w);
  intvec_mod (v, v, k);
  intvec_redc (w, w, k);
  intvec_sub (v, v, w);
  intvec_redp (w, w, k);
  intvec_rshift (v, v, 3);
  intvec_lshift (w, w, 5);
  intvec_mul_sgn_self (v, -1);
  intvec_neg_self (w);
  for (i = 0; i < 4; i++)
    {
      dump_intn (&o, intvec_get_elem (v, i));
      dump_intn (&o, intvec_get_elem (w, i));
    }

  *n = (size_t)(o - out);
  return pqz_err;
}

/* ---------------------------------------------------------------- hashing, rng, samplers (testkit::rand_*) */

/* an int from 5 words: limbs[0..3), sign, nlimbs (1..3) */
static void
load_int (int_t r, const uint64_t w[5])
{
  for (unsigned i = 0; i < r->nlimbs; i++)
    r->limbs[i] = w[i];
  r->neg = w[3] & 1;
}

/* testkit::rand_rng: rng_init (seed, dom), then rng_urandom of lens[i] bytes each, concatenated */
int
pqz_shim_rng (const uint8_t seed[32], uint64_t dom, const uint32_t *lens, size_t nlens, uint8_t *out)
{
  rng_state_t st;
  pqz_err = PQZ_OK;
  rng_init (st, seed, dom);
  for (size_t i = 0; i < nlens; i++)
    {
      rng_urandom (st, out, lens[i]);
      out += lens[i];
    }
  rng_clear (st);
  return pqz_err;
}

/* testkit::rand_shake: SHAKE128 (which = 128) or SHAKE256 of in, absorbed in pieces alens[], squeezed in pieces
   slens[], the squeezed bytes concatenated */
int
pqz_shim_shake (unsigned which, const uint8_t *in, const uint32_t *alens, size_t na, const uint32_t *slens, size_t ns,
                uint8_t *out)
{
  shake128_state_t st;
  size_t i;
  pqz_err = PQZ_OK;
  if (which == 128)
    shake128_init (st);
  else
    shake256_init (st);
  for (i = 0; i < na; in += alens[i++])
    if (which == 128)
      shake128_absorb (st, in, alens[i]);
    else
      shake256_absorb (st, in, alens[i]);
  for (i = 0; i < ns; out += slens[i++])
    if (which == 128)
      shake128_squeeze (st, out, slens[i]);
    else
      shake256_squeeze (st, out, slens[i]);
  shake128_clear (st);
  return pqz_err;
}

/* testkit::rand_grandom: intvec_grandom (n >= 1 one-limb elements, dom) then polyvec_grandom (2 polys, dom); out =
   the n elements then the 128 coefficients */
int
pqz_shim_grandom (const uint8_t seed[32], uint32_t dom, unsigned log2o, unsigned n, int64_t *out)
{
  pqz_arena_mark_t mark;
  polyvec_t pv;
  INTVEC_T (r, n, 1);
  unsigned i, j;

  pqz_err = PQZ_OK;
  intvec_grandom (r, log2o, seed, dom);
  for (i = 0; i < n; i++)
    *out++ = intvec_get_elem_i64 (r, i);
  pqz_arena_mark (&mark);
  polyvec_alloc (pv, pqz_tx_ring, 2);
  polyvec_grandom (pv, log2o, seed, dom);
  for (i = 0; i < 2; i++)
    for (j = 0; j < 64; j++)
      *out++ = int_get_i64 (poly_get_coeff (polyvec_get_elem (pv, i), j));
  pqz_arena_release (&mark);
  return pqz_err;
}

/* testkit::rand_rej: rej_standard (bimodal = 0) or rej_bimodal on z, v (n >= 1 one-limb elements), scM (3 limbs),
   sigma2 (2 limbs) with the stream rng_init (seed, dom); *rej = the verdict, next8 = the 8 stream bytes after it */
int
pqz_shim_rej (unsigned bimodal, const uint8_t seed[32], uint64_t dom, const int64_t *z, const int64_t *v, unsigned n,
              const uint64_t scm[3], const uint64_t s2[2], int *rej, uint8_t next8[8])
{
  rng_state_t st;
  INTVEC_T (zz, n, 1);
  INTVEC_T (vv, n, 1);
  INT_T (sc, 3);
  INT_T (sg, 2);
  unsigned i;

  pqz_err = PQZ_OK;
  for (i = 0; i < n; i++)
    {
      intvec_set_elem_i64 (zz, i, z[i]);
      intvec_set_elem_i64 (vv, i, v[i]);
    }
  for (i = 0; i < 3; i++)
    sc->limbs[i] = scm[i];
  sg->limbs[0] = s2[0], sg->limbs[1] = s2[1];
  rng_init (st, seed, dom);
  *rej = bimodal ? rej_bimodal (st, zz, vv, sc, sg) : rej_standard (st, zz, vv, sc, sg);
  rng_urandom (st, next8, 8);
  rng_clear (st);
  return pqz_err;
}

/* pqz_shim_rej on multi-limb entries (review round 2, the port's deferred minor: rejection S3 is two-limb): z and v
   hold n elements of nl limbs then the sign, (nl + 1) words each */
int
pqz_shim_rej_limbs (unsigned bimodal, const uint8_t seed[32], uint64_t dom, const uint64_t *z, const uint64_t *v,
                    unsigned n, unsigned nl, const uint64_t scm[3], const uint64_t s2[2], int *rej, uint8_t next8[8])
{
  rng_state_t st;
  INTVEC_T (zz, n, nl);
  INTVEC_T (vv, n, nl);
  INT_T (sc, 3);
  INT_T (sg, 2);

  pqz_err = PQZ_OK;
  for (unsigned i = 0; i < n; i++)
    for (unsigned k = 0; k <= nl; k++)
      {
        int_ptr a = intvec_get_elem (zz, i), b = intvec_get_elem (vv, i);
        if (k < nl)
          a->limbs[k] = z[i * (nl + 1) + k], b->limbs[k] = v[i * (nl + 1) + k];
        else
          a->neg = z[i * (nl + 1) + k] & 1, b->neg = v[i * (nl + 1) + k] & 1;
      }
  for (unsigned i = 0; i < 3; i++)
    sc->limbs[i] = scm[i];
  sg->limbs[0] = s2[0], sg->limbs[1] = s2[1];
  rng_init (st, seed, dom);
  *rej = bimodal ? rej_bimodal (st, zz, vv, sc, sg) : rej_standard (st, zz, vv, sc, sg);
  rng_urandom (st, next8, 8);
  rng_clear (st);
  return pqz_err;
}

/* every element of an intvec: its nlimbs limbs, then the sign */
static void
dump_intvec (uint64_t **o, intvec_t r)
{
  for (unsigned i = 0; i < r->nelems; i++)
    {
      int_ptr e = intvec_get_elem (r, i);
      for (unsigned k = 0; k < r->nlimbs; k++)
        *(*o)++ = e->limbs[k];
      *(*o)++ = e->neg;
    }
}

/* a poly's 64 coefficients as int64 (the coefficient domain) */
static void
dump_coeffs (uint64_t **o, poly_ptr p)
{
  for (unsigned j = 0; j < 64; j++)
    *(*o)++ = (uint64_t)int_get_i64 (poly_get_coeff (p, j));
}

/* testkit::rand_urandom: intvec_urandom (n >= 1 elements of nl limbs, mod, log2mod, dom) then polymat_urandom (2 x 2,
   the same arguments) */
int
pqz_shim_urandom (const uint8_t seed[32], uint32_t dom, unsigned n, unsigned nl, const uint64_t m[5], unsigned log2mod,
                  uint64_t *out, size_t *nout)
{
  pqz_arena_mark_t mark;
  polymat_t pm;
  INTVEC_T (r, n, nl);
  INT_T (mm, (unsigned)m[4]);
  uint64_t *o = out;

  pqz_err = PQZ_OK;
  load_int (mm, m);
  intvec_urandom (r, mm, log2mod, seed, dom);
  dump_intvec (&o, r);
  pqz_arena_mark (&mark);
  polymat_alloc (pm, pqz_tx_ring, 2, 2);
  polymat_urandom (pm, mm, log2mod, seed, dom);
  for (unsigned i = 0; i < 2; i++)
    for (unsigned j = 0; j < 2; j++)
      dump_coeffs (&o, polymat_get_elem (pm, i, j));
  pqz_arena_release (&mark);
  *nout = (size_t)(o - out);
  return pqz_err;
}

/* testkit::rand_urandom_bnd: intvec_urandom_bnd (n >= 1 elements of nl limbs, lo, hi, dom) then, for one-limb lo and
   hi, polyvec_urandom_bnd (2 polys, the same arguments) */
int
pqz_shim_urandom_bnd (const uint8_t seed[32], uint32_t dom, unsigned n, unsigned nl, const uint64_t lo[5],
                      const uint64_t hi[5], uint64_t *out, size_t *nout)
{
  pqz_arena_mark_t mark;
  polyvec_t pv;
  INTVEC_T (r, n, nl);
  INT_T (l, (unsigned)lo[4]);
  INT_T (h, (unsigned)hi[4]);
  uint64_t *o = out;

  pqz_err = PQZ_OK;
  load_int (l, lo);
  load_int (h, hi);
  intvec_urandom_bnd (r, l, h, seed, dom);
  dump_intvec (&o, r);
  if (lo[4] == 1 && hi[4] == 1) /* else the one-limb coefficients fail C's width assert */
    {
      pqz_arena_mark (&mark);
      polyvec_alloc (pv, pqz_tx_ring, 2);
      polyvec_urandom_bnd (pv, l, h, seed, dom);
      for (unsigned i = 0; i < 2; i++)
        dump_coeffs (&o, polyvec_get_elem (pv, i));
      pqz_arena_release (&mark);
    }
  *nout = (size_t)(o - out);
  return pqz_err;
}

/* testkit::rand_autostable: poly_urandom_autostable (bnd, log2, dom); out = the 64 coefficients */
int
pqz_shim_autostable (const uint8_t seed[32], uint32_t dom, int64_t bnd, unsigned log2, uint64_t *out)
{
  pqz_arena_mark_t mark;
  poly_t p;

  pqz_err = PQZ_OK;
  pqz_arena_mark (&mark);
  poly_alloc (p, pqz_tx_ring);
  poly_urandom_autostable (p, bnd, log2, seed, dom);
  dump_coeffs (&out, p);
  pqz_arena_release (&mark);
  return pqz_err;
}

/* testkit::params_words: relation i's lnp_tbox_params_t as the C compiler laid out the generated header (every field,
   pointers followed; ints as nlimbs, neg, limbs), in testkit's relation order; -1 past the last relation */
#include "pqz_burn_params.h"
#include "pqz_dr_params.h"
#include "pqz_ds_params.h"
#include "pqz_reg_params.h"
#include "pqz_tx0_params.h"
#include "pqz_txm20_params.h"
#include "pqz_txm2_params.h"
#include "pqz_txm40_params.h"
#include "pqz_txm4_params.h"
#include "pqz_txm80_params.h"
#include "pqz_txm8_params.h"
#ifdef PQZ_TXM_OVERSIZE
#include "pqz_txm160_params.h"
#include "pqz_txm16_params.h"
#endif

static void
params_int (uint64_t **o, int_srcptr a)
{
  *(*o)++ = a->nlimbs;
  *(*o)++ = a->neg;
  for (unsigned i = 0; i < a->nlimbs; i++)
    *(*o)++ = a->limbs[i];
}

static void
params_abdlop (uint64_t **o, abdlop_params_srcptr a)
{
  polyring_srcptr r = a->ring;
  dcompress_params_srcptr d = a->dcompress;
  params_int (o, r->q);
  *(*o)++ = r->d;
  *(*o)++ = r->log2q;
  *(*o)++ = r->log2d;
  *(*o)++ = r->moduli != 0;
  *(*o)++ = r->nmoduli;
  params_int (o, r->Pmodq);
  for (unsigned i = 0; i < r->nmoduli; i++)
    params_int (o, r->Ppmodq[i]);
  params_int (o, r->inv2);
  params_int (o, d->q);
  params_int (o, d->qminus1);
  params_int (o, d->m);
  params_int (o, d->mby2);
  params_int (o, d->gamma);
  params_int (o, d->gammaby2);
  params_int (o, d->pow2D);
  params_int (o, d->pow2Dby2);
  *(*o)++ = d->D;
  *(*o)++ = (uint64_t)(int64_t)d->m_odd;
  *(*o)++ = d->log2m;
  *(*o)++ = a->m1;
  *(*o)++ = a->m2;
  *(*o)++ = a->l;
  *(*o)++ = a->lext;
  *(*o)++ = a->kmsis;
  params_int (o, a->Bsqr);
  *(*o)++ = (uint64_t)a->nu;
  *(*o)++ = (uint64_t)a->omega;
  *(*o)++ = a->log2omega;
  *(*o)++ = a->eta;
  *(*o)++ = (uint64_t)(int64_t)a->rej1;
  *(*o)++ = a->log2stdev1;
  params_int (o, a->scM1);
  params_int (o, a->stdev1sqr);
  *(*o)++ = (uint64_t)(int64_t)a->rej2;
  *(*o)++ = a->log2stdev2;
  params_int (o, a->scM2);
  params_int (o, a->stdev2sqr);
}

static const lnp_tbox_params_struct *const P[] = { pqz_reg,   pqz_tx,    pqz_tx0,   pqz_burn,  pqz_ds,   pqz_dr,
                                                   pqz_txm2,  pqz_txm4,  pqz_txm8,  pqz_txm20, pqz_txm40, pqz_txm80,
#ifdef PQZ_TXM_OVERSIZE
                                                   pqz_txm16, pqz_txm160,
#endif
};
#define NP (sizeof P / sizeof P[0])

int
pqz_shim_params (unsigned i, uint64_t *out, size_t *n)
{
  uint64_t *o = out;
  if (i >= NP)
    return -1;
  const lnp_tbox_params_struct *p = P[i];
  params_abdlop (&o, p->tbox);
  params_abdlop (&o, p->quad_eval->quad_eval);
  params_abdlop (&o, p->quad_eval->quad_many);
  *o++ = p->quad_eval->lambda;
  *o++ = p->nbin;
  *o++ = p->Z;
  for (unsigned z = 0; z < p->Z; z++)
    *o++ = p->n[z];
  *o++ = p->nprime;
  *o++ = p->nex;
  *o++ = (uint64_t)(int64_t)p->rej3;
  *o++ = p->log2stdev3;
  params_int (&o, p->scM3);
  params_int (&o, p->stdev3sqr);
  *o++ = (uint64_t)(int64_t)p->rej4;
  *o++ = p->log2stdev4;
  params_int (&o, p->scM4);
  params_int (&o, p->stdev4sqr);
  params_int (&o, p->Bz3sqr);
  params_int (&o, p->Bz4);
  for (unsigned z = 0; z < p->Z; z++)
    params_int (&o, p->l2Bsqr[z]);
  params_int (&o, p->inv4);
  *o++ = p->prooflen;
  *n = (size_t)(o - out);
  return 0;
}

/* testkit::ghint: relation i's (P above) quad_many dcompress: poly_dcompress_use_ghint (ret, y, r) and
   poly_dcompress_make_ghint (ret, z, r) of in = y[64], z[64], r[64], each result dumped; -1 past the last relation */
int
pqz_shim_ghint (unsigned i, const int64_t *in, uint64_t *out)
{
  pqz_arena_mark_t mark;
  poly_t y, z, r, ret;
  if (i >= NP)
    return -1;
  dcompress_params_srcptr d = P[i]->quad_eval->quad_many->dcompress;
  pqz_err = PQZ_OK;
  pqz_arena_mark (&mark);
  poly_alloc (y, pqz_tx_ring);
  poly_alloc (z, pqz_tx_ring);
  poly_alloc (r, pqz_tx_ring);
  poly_alloc (ret, pqz_tx_ring);
  poly_set_coeffvec_i64 (y, in);
  poly_set_coeffvec_i64 (z, in + 64);
  poly_set_coeffvec_i64 (r, in + 128);
  poly_dcompress_use_ghint (ret, y, r, d);
  dump_poly (&out, ret);
  poly_dcompress_make_ghint (ret, z, r, d);
  dump_poly (&out, ret);
  pqz_arena_release (&mark);
  return pqz_err;
}
