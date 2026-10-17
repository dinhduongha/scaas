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
  /* poly_auto_self in the NTT domain: its loop runs over the ring's two former CRT moduli, so the second pass reverses
     the 64 words after the 512-byte residue buffer (outside the poly). Give e a 1,024-byte residue block first
     (poly_mul allocates only when crtrep is NULL), so that pass stays in scratch the shim owns; freed below. */
  e->crtrep = pqz_arena_alloc (2 * _sizeof_crtrep_data (R));
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
  pqz_arena_free (e->crtrep, 2 * _sizeof_crtrep_data (R));
  e->crtrep = NULL;
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
