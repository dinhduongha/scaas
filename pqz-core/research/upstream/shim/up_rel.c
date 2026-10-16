/*
 * pqz-core relations for the E-S1 spike: R_REG and R_TX as LaZer tbox statements
 * (pq-zether.md §7.2 step 6 and §7.4), the C ABI of pqz.h, proof encoding (LaZer lin-proofs.c's
 * lnp_tbox_encproof / decproof, MIT, with the bounded decoder), and the A / ABDLOP-key caches.
 *
 * Witness layout in the tbox vector s1 (R_TX, m1 = 146 + Z = 7 slack polys):
 *   0..31 s_f | 32..63 e_f | 64..95 r | 96..127 e1 | 128 e2_t | 129 e2_f | 130 e2_a | 131..145 bits
 * Bits (slot k = coefficient k % 64 of poly 131 + k / 64):
 *   d_i: 4i+b | d'_i: 64+4i+b | M_i: 128+14i+b | c_i + 64: 352+11i+b (i < 15) | e_T[i] + 2^24: 517+25i+b
 * Rows 1, 2 are R_q-linear equations (quadeqs with no quadratic part); rows 3-7 are Z_q-linear equations
 * on single coefficients: ct(X^-i * (...)) = 0 (tbox evaleqs). Norms: 7 exact l2 proofs, 1 binary proof.
 */
#include "lazer.h"
#include "lnp-tbox.h"
#include "memory.h"

#include "pqz.h"
#include "pqz_reg_params.h"
#include "pqz_tx_params.h"

#define K 32
#define DELTA ((int64_t)((1 << 26) - 1))
#define NREG 32
#define NTXQ 64
#define NTXE 80

typedef struct
{
  const lnp_tbox_params_struct *P;
  polymat_t A, A1, A2p, Bp;
} rel_t;

static rel_t REG, TX;
static int ready;
static pqz_arena_mark_t base;

/* ---------------------------------------------------------------- helpers */

static void
shake_tag (uint8_t out[32], const char *tag, const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
  shake128_state_t st;
  size_t n = 0;
  while (tag[n])
    n++;
  shake128_init (st);
  shake128_absorb (st, (const uint8_t *)tag, n);
  if (alen)
    shake128_absorb (st, a, alen);
  if (blen)
    shake128_absorb (st, b, blen);
  shake128_squeeze (st, out, 32);
  shake128_clear (st);
}

static void
set_c (poly_ptr p, unsigned j, int64_t v)
{
  int_set_i64 (poly_get_coeff (p, j), v);
}

/* A[i][j] from SHAKE128("SCAAS-PQZ-A-V2" || u8(i) || u8(j)): 8-byte BE words, low 42 bits, accept if < q */
static void
expand_A (polymat_t A)
{
  for (unsigned i = 0; i < K; i++)
    for (unsigned j = 0; j < K; j++)
      {
        shake128_state_t st;
        uint8_t ij[2] = { (uint8_t)i, (uint8_t)j }, w[8];
        poly_ptr p = polymat_get_elem (A, i, j);
        shake128_init (st);
        shake128_absorb (st, (const uint8_t *)"SCAAS-PQZ-A-V2", 14);
        shake128_absorb (st, ij, 2);
        for (unsigned k = 0; k < PQZ_D;)
          {
            shake128_squeeze (st, w, 8);
            uint64_t v = 0;
            for (int b = 0; b < 8; b++)
              v = (v << 8) | w[b];
            v &= (((uint64_t)1) << 42) - 1;
            if (v < PQZ_Q) /* public data: rejection on the public stream */
              {
                set_c (p, k, v > (PQZ_Q - 1) / 2 ? (int64_t)v - (int64_t)PQZ_Q : (int64_t)v);
                k++;
              }
          }
        shake128_clear (st);
        poly_tocrt (p);
      }
}

static int
rel_init (rel_t *R, const lnp_tbox_params_struct *P, uint8_t op)
{
  abdlop_params_srcptr tb = P->tbox;
  polyring_srcptr Rq = tb->ring;
  uint8_t pp[32];

  R->P = P;
  polymat_alloc (R->A, Rq, K, K);
  expand_A (R->A);
  polymat_alloc (R->A1, Rq, tb->kmsis, tb->m1);
  polymat_alloc (R->A2p, Rq, tb->kmsis, tb->m2 - tb->kmsis);
  polymat_alloc (R->Bp, Rq, tb->l + tb->lext, tb->m2 - tb->kmsis);
  shake_tag (pp, "SCAAS-PQZ-ABDLOP-PP-V1", &op, 1, NULL, 0);
  abdlop_keygen (R->A1, R->A2p, R->Bp, pp, tb);
  /* NTT form now: a crtrep created lazily inside a call would sit above the arena mark and be dropped */
  polymat_tocrt (R->A1);
  polymat_tocrt (R->A2p);
  polymat_tocrt (R->Bp);
  return pqz_err;
}

int
pqz_init (void *arena, size_t len)
{
  pqz_err = PQZ_OK;
  pqz_arena_init (arena, len);
  if (rel_init (&REG, pqz_reg, PQZ_OP_REGISTER) || rel_init (&TX, pqz_tx, PQZ_OP_TRANSFER))
    return pqz_err;
  pqz_arena_mark (&base);
  ready = 1;
  return PQZ_OK;
}

size_t
pqz_arena_peak_bytes (void)
{
  return pqz_arena_peak ();
}

static uint64_t
rd_be8 (const uint8_t *p)
{
  uint64_t v = 0;
  for (int b = 0; b < 8; b++)
    v = (v << 8) | p[b];
  return v;
}

static void
wr_be8 (uint8_t *p, uint64_t v)
{
  for (int b = 7; b >= 0; b--, v >>= 8)
    p[b] = (uint8_t)v;
}

/* n coefficients (be8, each < q) into poly p, centred; the rest of p zero. Returns 0 if a value is >= q. */
static int
rd_poly (poly_ptr p, const uint8_t *in, unsigned n)
{
  int ok = 1;
  poly_set_zero (p);
  for (unsigned k = 0; k < n; k++)
    {
      uint64_t v = rd_be8 (in + 8 * k);
      ok &= v < PQZ_Q;
      set_c (p, k, v > (PQZ_Q - 1) / 2 ? (int64_t)v - (int64_t)PQZ_Q : (int64_t)v);
    }
  return ok;
}

static int
rd_polyvec (polyvec_t v, const uint8_t *in)
{
  int ok = 1;
  for (unsigned i = 0; i < K; i++)
    ok &= rd_poly (polyvec_get_elem (v, i), in + i * 512, PQZ_D);
  return ok;
}

static void
wr_poly (uint8_t *out, poly_ptr p, unsigned n)
{
  poly_redp (p, p); /* [0, q) */
  for (unsigned k = 0; k < n; k++)
    wr_be8 (out + 8 * k, (uint64_t)int_get_i64 (poly_get_coeff (p, k)));
}

static int16_t
rd_le16 (const uint8_t *p)
{
  return (int16_t)(p[0] | (p[1] << 8));
}

/* r = X^-i * a (negacyclic) */
static void
mul_xinv (poly_ptr r, poly_ptr a, unsigned i)
{
  poly_fromcrt (a);
  for (unsigned m = 0; m < PQZ_D; m++)
    {
      int64_t v = int_get_i64 (poly_get_coeff (a, m));
      if (m >= i)
        set_c (r, m - i, v);
      else
        set_c (r, m - i + PQZ_D, -v);
    }
}

static int64_t
l2sq_poly (poly_ptr p)
{
  int64_t s = 0;
  for (unsigned k = 0; k < PQZ_D; k++)
    {
      int64_t v = int_get_i64 (poly_get_coeff (p, k));
      s += v * v;
    }
  return s;
}

/* statement digest: SHAKE128("SCAAS-PQZ-TRANSCRIPT-V1" || op || be32(len) || stmt) */
static void
stmt_hash (uint8_t h[32], uint8_t op, const uint8_t *stmt, size_t len)
{
  uint8_t hdr[5] = { op, (uint8_t)(len >> 24), (uint8_t)(len >> 16), (uint8_t)(len >> 8), (uint8_t)len };
  shake_tag (h, "SCAAS-PQZ-TRANSCRIPT-V1", hdr, 5, stmt, len);
}

/* ---------------------------------------------------------------- proof encoding (LaZer lin-proofs.c) */

static void
encproof (uint8_t *out, size_t *len, polyvec_t tA1, polyvec_t tB, polyvec_t h, poly_t c, polyvec_t z1,
          polyvec_t z21, polyvec_t hint, polyvec_t z3, polyvec_t z4, const lnp_tbox_params_t params)
{
  polyring_srcptr Rq = params->tbox->ring;
  int_srcptr q = Rq->q;
  const unsigned int d = Rq->d;
  INTVEC_T (coeffs, d, q->nlimbs);
  const unsigned int log2q = Rq->log2q;
  const unsigned int log2omega = params->quad_eval->quad_many->log2omega;
  const unsigned int D = params->quad_eval->quad_many->dcompress->D;
  const int64_t omega = params->quad_eval->quad_many->omega;
  coder_state_t cstate;
  INT_T (mod, q->nlimbs);

  coder_enc_begin (cstate, out);
  polyvec_fromcrt (tB);
  polyvec_mod (tB, tB);
  polyvec_redp (tB, tB);
  coder_enc_urandom3 (cstate, tB, q, log2q);
  polyvec_fromcrt (h);
  polyvec_mod (h, h);
  polyvec_redp (h, h);
  coder_enc_urandom3 (cstate, h, q, log2q);
  int_set_one (mod);
  int_lshift (mod, mod, log2q - D);
  polyvec_fromcrt (tA1);
  polyvec_mod (tA1, tA1);
  polyvec_redp (tA1, tA1);
  coder_enc_urandom3 (cstate, tA1, mod, log2q - D);
  int_set_i64 (mod, 2 * omega + 1);
  poly_fromcrt (c);
  intvec_set (coeffs, poly_get_coeffvec (c));
  intvec_redp (coeffs, coeffs, mod);
  coder_enc_urandom (cstate, coeffs, mod, log2omega);
  coder_enc_ghint3 (cstate, hint);
  polyvec_fromcrt (z1);
  polyvec_fromcrt (z21);
  polyvec_fromcrt (z3);
  polyvec_mod (z1, z1);
  polyvec_mod (z21, z21);
  polyvec_mod (z3, z3);
  polyvec_redc (z1, z1);
  polyvec_redc (z21, z21);
  polyvec_redc (z3, z3);
  coder_enc_grandom3 (cstate, z1, params->quad_eval->quad_many->log2stdev1);
  coder_enc_grandom3 (cstate, z21, params->quad_eval->quad_many->log2stdev2);
  coder_enc_grandom3 (cstate, z3, params->log2stdev3);
  polyvec_fromcrt (z4); /* the nprime = 1 approximate l_inf filler */
  polyvec_mod (z4, z4);
  polyvec_redc (z4, z4);
  coder_enc_grandom3 (cstate, z4, params->log2stdev4);
  coder_enc_end (cstate);
  *len = coder_get_offset (cstate) >> 3;
}

static int
decproof (size_t len, const uint8_t *in, polyvec_t tA1, polyvec_t tB, polyvec_t h, poly_t c, polyvec_t z1,
          polyvec_t z21, polyvec_t hint, polyvec_t z3, polyvec_t z4, const lnp_tbox_params_t params)
{
  polyring_srcptr Rq = params->tbox->ring;
  int_srcptr q = Rq->q;
  const unsigned int log2q = Rq->log2q;
  const unsigned int log2omega = params->quad_eval->quad_many->log2omega;
  const unsigned int D = params->quad_eval->quad_many->dcompress->D;
  const int64_t omega = params->quad_eval->quad_many->omega;
  coder_state_t cstate;
  INT_T (mod, q->nlimbs);

  coder_dec_begin (cstate, in); /* xcheck: upstream has no bounded decoder */
  if (coder_dec_urandom3 (cstate, tB, q, log2q) || coder_dec_urandom3 (cstate, h, q, log2q))
    return 0;
  int_set_one (mod);
  int_lshift (mod, mod, log2q - D);
  if (coder_dec_urandom3 (cstate, tA1, mod, log2q - D))
    return 0;
  int_set_i64 (mod, 2 * omega + 1);
  if (coder_dec_urandom2 (cstate, c, mod, log2omega))
    return 0;
  intvec_redc (poly_get_coeffvec (c), poly_get_coeffvec (c), mod);
  coder_dec_ghint3 (cstate, hint);
  coder_dec_grandom3 (cstate, z1, params->quad_eval->quad_many->log2stdev1);
  coder_dec_grandom3 (cstate, z21, params->quad_eval->quad_many->log2stdev2);
  coder_dec_grandom3 (cstate, z3, params->log2stdev3);
  coder_dec_grandom3 (cstate, z4, params->log2stdev4);
  if (0 /* xcheck: upstream coder has no err flag */ || coder_dec_end (cstate) != 1)
    return 0;
  return (coder_get_offset (cstate) >> 3) == len; /* exactly the given length, no trailing bytes */
}

/* ---------------------------------------------------------------- the statements */

typedef struct
{
  rel_t *R;
  unsigned N, M;
  spolymat_ptr R2[NTXQ], R2p[NTXE];
  spolyvec_ptr r1[NTXQ], r1p[NTXE];
  poly_ptr r0[NTXQ], r0p[NTXE];
  polymat_ptr Es[7];
  polymat_ptr Ps;
  polymat_ptr Ds; /* nprime = 1 approximate l_inf filler: one witness poly, u = 0 */
} sys_t;

static spolyvec_ptr
new_r1 (polyring_srcptr Rq, unsigned n)
{
  spolyvec_ptr v = _alloc (sizeof (spolyvec_t));
  spolyvec_alloc (v, Rq, n, n);
  return v;
}

static poly_ptr
new_poly (polyring_srcptr Rq)
{
  poly_ptr p = _alloc (sizeof (poly_t));
  poly_alloc (p, Rq);
  poly_set_zero (p);
  return p;
}

static polymat_ptr
new_sel (polyring_srcptr Rq, unsigned rows, unsigned cols, unsigned off)
{
  polymat_ptr m = _alloc (sizeof (polymat_t));
  polymat_alloc (m, Rq, rows, cols);
  polymat_set_zero (m);
  for (unsigned i = 0; i < rows; i++)
    poly_set_one (polymat_get_elem (m, i, off + i));
  return m;
}

/* R_q-linear row: sum_j A'[i][j] x[off_x + j] + y[off_y + i] - rhs_i = 0 (A' = A or A^T) */
static void
add_lin_row (sys_t *S, unsigned idx, int transpose, unsigned i, unsigned off_x, unsigned off_y, poly_ptr rhs)
{
  rel_t *R = S->R;
  abdlop_params_srcptr tb = R->P->tbox;
  polyring_srcptr Rq = tb->ring;
  const unsigned n = 2 * (tb->m1 + R->P->quad_eval->quad_many->l);
  S->R2[idx] = NULL; /* linear: no quadratic part (the tbox uses a non-NULL R2 as scratch of NELEMS_DIAG(np)) */
  S->r1[idx] = new_r1 (Rq, n);
  for (unsigned j = 0; j < K; j++)
    poly_set (spolyvec_insert_elem (S->r1[idx], 2 * (off_x + j)),
              transpose ? polymat_get_elem (R->A, j, i) : polymat_get_elem (R->A, i, j));
  poly_set_one (spolyvec_insert_elem (S->r1[idx], 2 * (off_y + i)));
  S->r1[idx]->sorted = 0;
  spolyvec_sort (S->r1[idx]);
  S->r0[idx] = new_poly (Rq);
  if (rhs != NULL)
    poly_neg (S->r0[idx], rhs);
}

/* ---- R_REG ---- */

static int
build_reg (sys_t *S, const uint8_t *stmt, polyvec_t pk)
{
  rel_t *R = &REG;
  polyring_srcptr Rq = R->P->tbox->ring;
  S->R = R;
  S->N = NREG;
  S->M = 0;
  if (!rd_polyvec (pk, stmt + PQZ_PREFIX_BYTES + 32))
    return 0;
  for (unsigned i = 0; i < NREG; i++)
    add_lin_row (S, i, 0, i, 0, 32, polyvec_get_elem (pk, i));
  S->Es[0] = new_sel (Rq, 32, 64, 0);
  S->Es[1] = new_sel (Rq, 32, 64, 32);
  S->Ps = NULL;
  S->Ds = new_sel (Rq, 1, 64, 0); /* s[0], coefficients in [-1, 1] (reg_params.sage Bprime) */
  return 1;
}

/* ---- R_TX ---- */

#define TX_BITS 131
#define SLOT_D(i, b) (4 * (i) + (b))
#define SLOT_DP(i, b) (64 + 4 * (i) + (b))
#define SLOT_M(i, b) (128 + 14 * (i) + (b))
#define SLOT_C(i, b) (352 + 11 * (i) + (b))
#define SLOT_E(i, b) (517 + 25 * (i) + (b))

typedef struct
{
  polyvec_ptr pkf, pkt, pka, uT, u;
  poly_t vT, vt, vf, va;
  uint64_t fee;
} txst_t;

/* coefficient term coef * bit(slot) into the evaleq vector accumulators (one poly per bit poly) */
static void
add_bit (poly_ptr acc[15], unsigned slot, int64_t coef)
{
  poly_ptr p = acc[slot / 64];
  unsigned a = slot % 64; /* ct(X^-a * P) = P_a */
  int_ptr c;
  INT_T (t, 1);
  if (a == 0)
    c = poly_get_coeff (p, 0), int_set_i64 (t, coef);
  else
    c = poly_get_coeff (p, 64 - a), int_set_i64 (t, -coef);
  int_add (c, c, t);
}

static void
evaleq (sys_t *S, unsigned idx, polyvec_ptr pkrow, unsigned off_x, unsigned i, int e2idx, poly_ptr acc[15],
        int64_t rhs)
{
  rel_t *R = S->R;
  abdlop_params_srcptr tb = R->P->tbox;
  polyring_srcptr Rq = tb->ring;
  const unsigned n = 2 * (tb->m1 + R->P->quad_eval->quad_eval->l);
  S->R2p[idx] = NULL;
  S->r1p[idx] = new_r1 (Rq, n);
  if (pkrow != NULL)
    for (unsigned j = 0; j < K; j++)
      mul_xinv (spolyvec_insert_elem (S->r1p[idx], 2 * (off_x + j)), polyvec_get_elem (pkrow, j), i);
  if (e2idx >= 0)
    {
      poly_ptr p = spolyvec_insert_elem (S->r1p[idx], 2 * (unsigned)e2idx);
      poly_set_zero (p);
      if (i == 0)
        set_c (p, 0, 1);
      else
        set_c (p, PQZ_D - i, -1);
    }
  for (unsigned b = 0; b < 15; b++)
    {
      poly_ptr p = spolyvec_insert_elem (S->r1p[idx], 2 * (TX_BITS + b));
      poly_set (p, acc[b]);
      poly_redc (p, p);
    }
  S->r1p[idx]->sorted = 0;
  spolyvec_sort (S->r1p[idx]);
  S->r0p[idx] = new_poly (Rq);
  set_c (S->r0p[idx], 0, rhs);
  poly_redc (S->r0p[idx], S->r0p[idx]);
}

static void
acc_zero (poly_ptr acc[15])
{
  for (unsigned b = 0; b < 15; b++)
    poly_set_zero (acc[b]);
}

static int64_t
cval (poly_ptr p, unsigned k)
{
  return int_get_i64 (poly_get_coeff (p, k));
}

static int
parse_tx (txst_t *T, polyring_srcptr Rq, const uint8_t *stmt)
{
#ifdef PQZ_HEADER_BYTES /* rel3 layout, as the fork's parse_debit: header || body, fee a be32 word < 2^64 */
  const uint8_t *p = stmt + PQZ_HEADER_BYTES;
  int ok = 1;
  for (unsigned b = 0; b < 24; b++)
    ok &= stmt[PQZ_HDR_FEE + b] == 0;
  T->fee = rd_be8 (stmt + PQZ_HDR_FEE + 24);
#else
  const uint8_t *p = stmt + PQZ_PREFIX_BYTES;
  int ok = 1;
#endif
  T->pkf = _alloc (sizeof (polyvec_t)), polyvec_alloc (T->pkf, Rq, K);
  T->pkt = _alloc (sizeof (polyvec_t)), polyvec_alloc (T->pkt, Rq, K);
  T->pka = _alloc (sizeof (polyvec_t)), polyvec_alloc (T->pka, Rq, K);
  T->uT = _alloc (sizeof (polyvec_t)), polyvec_alloc (T->uT, Rq, K);
  T->u = _alloc (sizeof (polyvec_t)), polyvec_alloc (T->u, Rq, K);
  poly_alloc (T->vT, Rq), poly_alloc (T->vt, Rq), poly_alloc (T->vf, Rq), poly_alloc (T->va, Rq);
  ok &= rd_polyvec (T->pkf, p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_polyvec (T->pkt, p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_polyvec (T->pka, p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_polyvec (T->uT, p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_poly (T->vT, p, 16), p += PQZ_V_BYTES;
  ok &= rd_polyvec (T->u, p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_poly (T->vt, p, 16), p += PQZ_V_BYTES;
  ok &= rd_poly (T->vf, p, 16), p += PQZ_V_BYTES;
  ok &= rd_poly (T->va, p, 16), p += PQZ_V_BYTES;
#ifndef PQZ_HEADER_BYTES
  T->fee = rd_be8 (p);
#endif
  return ok;
}

static int
build_tx (sys_t *S, txst_t *T, const uint8_t *stmt)
{
  rel_t *R = &TX;
  polyring_srcptr Rq = R->P->tbox->ring;
  poly_ptr acc[15];
  unsigned i, b, e = 0;

  S->R = R;
  S->N = NTXQ;
  S->M = NTXE;
  if (!parse_tx (T, Rq, stmt))
    return 0;
  for (b = 0; b < 15; b++)
    acc[b] = new_poly (Rq);

  /* row 1: pk_f = A s_f + e_f ; row 2: u = A^T r + e1 */
  for (i = 0; i < K; i++)
    add_lin_row (S, i, 0, i, 0, 32, polyvec_get_elem (T->pkf, i));
  for (i = 0; i < K; i++)
    add_lin_row (S, K + i, 1, i, 64, 96, polyvec_get_elem (T->u, i));

  for (i = 0; i < 16; i++)
    {
      /* rows 3-5: (pk^T r)_i + e2_i + Delta * digit_i - v_i = 0 */
      acc_zero (acc);
      for (b = 0; b < 4; b++)
        add_bit (acc, SLOT_D (i, b), DELTA << b);
      evaleq (S, e++, T->pkt, 64, i, 128, acc, -cval (T->vt, i));
      acc_zero (acc);
      for (b = 0; b < 4; b++)
        add_bit (acc, SLOT_DP (i, b), DELTA << b);
      evaleq (S, e++, T->pkf, 64, i, 129, acc, -cval (T->vf, i));
      acc_zero (acc);
      for (b = 0; b < 4; b++)
        add_bit (acc, SLOT_D (i, b), DELTA << b);
      evaleq (S, e++, T->pka, 64, i, 130, acc, -cval (T->va, i));
      /* row 6: (u_T^T s_f)_i + Delta M_i + (e_T,i + 2^24) - 2^24 - v_T,i = 0 */
      acc_zero (acc);
      for (b = 0; b < 14; b++)
        add_bit (acc, SLOT_M (i, b), DELTA << b);
      for (b = 0; b < 25; b++)
        add_bit (acc, SLOT_E (i, b), (int64_t)1 << b);
      evaleq (S, e++, T->uT, 0, i, -1, acc, -cval (T->vT, i) - ((int64_t)1 << 24));
      /* row 7 (over Z, all terms < 2^15): M_i + c_{i-1} - d'_i - d_i - f_i - 16 c_i = 0, c = cbits - 64 */
      acc_zero (acc);
      int64_t rhs = -(int64_t)((T->fee >> (4 * i)) & 15);
      for (b = 0; b < 14; b++)
        add_bit (acc, SLOT_M (i, b), (int64_t)1 << b);
      if (i >= 1)
        {
          for (b = 0; b < 11; b++)
            add_bit (acc, SLOT_C (i - 1, b), (int64_t)1 << b);
          rhs -= 64;
        }
      for (b = 0; b < 4; b++)
        {
          add_bit (acc, SLOT_DP (i, b), -((int64_t)1 << b));
          add_bit (acc, SLOT_D (i, b), -((int64_t)1 << b));
        }
      if (i <= 14)
        {
          for (b = 0; b < 11; b++)
            add_bit (acc, SLOT_C (i, b), -((int64_t)16 << b));
          rhs += 16 * 64;
        }
      evaleq (S, e++, NULL, 0, i, -1, acc, rhs);
    }

  S->Es[0] = new_sel (Rq, 32, 146, 0);
  S->Es[1] = new_sel (Rq, 32, 146, 32);
  S->Es[2] = new_sel (Rq, 32, 146, 64);
  S->Es[3] = new_sel (Rq, 32, 146, 96);
  S->Es[4] = new_sel (Rq, 1, 146, 128);
  S->Es[5] = new_sel (Rq, 1, 146, 129);
  S->Es[6] = new_sel (Rq, 1, 146, 130);
  S->Ps = new_sel (Rq, 15, 146, TX_BITS);
  S->Ds = new_sel (Rq, 1, 146, 128); /* e2_t, |coefficients| <= 20 < 64 (tx_params.sage Bprime) */
  return 1;
}

/* ---------------------------------------------------------------- prove / verify */

typedef struct
{
  polyvec_t tA1, tA2, tB, h, z1, z21, hint, z3, z4, s1, s2, m;
  poly_t c;
} pf_t;

static void
pf_alloc (pf_t *F, const lnp_tbox_params_struct *P)
{
  abdlop_params_srcptr tb = P->tbox;
  polyring_srcptr Rq = tb->ring;
  polyvec_alloc (F->tA1, Rq, tb->kmsis);
  polyvec_alloc (F->tA2, Rq, tb->kmsis);
  polyvec_alloc (F->tB, Rq, tb->l + tb->lext);
  polyvec_alloc (F->h, Rq, P->quad_eval->lambda / 2);
  polyvec_alloc (F->z1, Rq, tb->m1);
  polyvec_alloc (F->z21, Rq, tb->m2 - tb->kmsis);
  polyvec_alloc (F->hint, Rq, tb->kmsis);
  polyvec_alloc (F->z3, Rq, 256 / PQZ_D);
  polyvec_alloc (F->z4, Rq, 256 / PQZ_D);
  polyvec_alloc (F->s1, Rq, tb->m1);
  polyvec_alloc (F->s2, Rq, tb->m2);
  polyvec_alloc (F->m, Rq, tb->l + tb->lext);
  poly_alloc (F->c, Rq);
  polyvec_set_zero (F->s1);
  polyvec_set_zero (F->m);
}

/* s1 slack polys: upsilon_i = binexp(B_i^2 - ||x_i||^2) */
static int
set_upsilon (const lnp_tbox_params_struct *P, polyvec_t s1, const unsigned *start, const unsigned *len)
{
  const unsigned m1 = P->tbox->m1 - P->Z;
  for (unsigned z = 0; z < P->Z; z++)
    {
      int64_t n2 = 0;
      for (unsigned j = 0; j < len[z]; j++)
        n2 += l2sq_poly (polyvec_get_elem (s1, start[z] + j));
      INT_T (d, 2 * P->tbox->ring->q->nlimbs);
      int_set (d, P->l2Bsqr[z]);
      INT_T (n2t, 2 * P->tbox->ring->q->nlimbs);
      int_set_i64 (n2t, n2);
      int_sub (d, d, n2t);
      if (int_sgn (d) < 0)
        return 0; /* witness above its norm bound */
      int_binexp (polyvec_get_elem (s1, m1 + z), NULL, d);
    }
  return 1;
}

static int
do_prove (sys_t *S, pf_t *F, const uint8_t hash0[32], const uint8_t rnd32[32], uint8_t *proof,
          size_t *proof_len)
{
  const lnp_tbox_params_struct *P = S->R->P;
  abdlop_params_srcptr tb = P->tbox;
  uint8_t hash[32], ex[64];
  INT_T (lo, 1);
  INT_T (hi, 1);
  uint8_t buf[PQZ_MAX_PROOF + 4096];
  size_t len;

  shake_tag (ex, "SCAAS-PQZ-PROVER-RND-V1", rnd32, 32, NULL, 0);
  shake_tag (ex + 32, "SCAAS-PQZ-PROVER-SUB-V1", rnd32, 32, NULL, 0);
  int_set_i64 (lo, -tb->nu);
  int_set_i64 (hi, tb->nu);
  polyvec_urandom_bnd (F->s2, lo, hi, ex, 0);
  memcpy (hash, hash0, 32);
  abdlop_commit (F->tA1, F->tA2, F->tB, F->s1, F->m, F->s2, S->R->A1, S->R->A2p, S->R->Bp, tb);
  abdlop_hashcomm (hash, F->tA1, F->tB, tb);
  lnp_tbox_prove (hash, F->tB, F->h, F->c, F->z1, F->z21, F->hint, F->z3, F->z4, F->s1, F->m, F->s2, F->tA2,
                  S->R->A1, S->R->A2p, S->R->Bp, S->R2, S->r1, S->N, S->R2p, S->r1p, S->r0p, S->M, S->Es, NULL,
                  NULL, S->Ps, NULL, NULL, S->Ds, NULL, NULL, ex + 32, P);
  if (pqz_err)
    return pqz_err;
  encproof (buf, &len, F->tA1, F->tB, F->h, F->c, F->z1, F->z21, F->hint, F->z3, F->z4, P);
  if (len > PQZ_MAX_PROOF || len > *proof_len)
    return PQZ_ERR_INPUT;
  memcpy (proof, buf, len);
  *proof_len = len;
  return pqz_err;
}

static int
do_verify (sys_t *S, pf_t *F, const uint8_t hash0[32], const uint8_t *proof, size_t proof_len)
{
  const lnp_tbox_params_struct *P = S->R->P;
  uint8_t hash[32];
  if (proof_len > PQZ_MAX_PROOF
      || !decproof (proof_len, proof, F->tA1, F->tB, F->h, F->c, F->z1, F->z21, F->hint, F->z3, F->z4, P))
    return 0;
  polyvec_mod (F->h, F->h), polyvec_redc (F->h, F->h);
  poly_mod (F->c, F->c), poly_redc (F->c, F->c);
  polyvec_mod (F->z1, F->z1), polyvec_redc (F->z1, F->z1);
  polyvec_mod (F->z21, F->z21), polyvec_redc (F->z21, F->z21);
  polyvec_mod (F->z3, F->z3), polyvec_redc (F->z3, F->z3);
  polyvec_mod (F->z4, F->z4), polyvec_redc (F->z4, F->z4);
  memcpy (hash, hash0, 32);
  abdlop_hashcomm (hash, F->tA1, F->tB, P->tbox);
  return lnp_tbox_verify (hash, F->h, F->c, F->z1, F->z21, F->hint, F->z3, F->z4, F->tA1, F->tB, S->R->A1,
                          S->R->A2p, S->R->Bp, S->R2, S->r1, S->r0, S->N, S->R2p, S->r1p, S->r0p, S->M, S->Es,
                          NULL, NULL, S->Ps, NULL, NULL, S->Ds, NULL, NULL, P)
         == 1;
}

/* R_TX witness -> s1 (incl. derived M, carries, e_T); returns 0 if inconsistent */
static int
tx_witness (const lnp_tbox_params_struct *P, txst_t *T, const uint8_t *w, polyvec_t s1)
{
  polyring_srcptr Rq = P->tbox->ring;
  const uint8_t *p = w;
  unsigned i, j, b;
  int64_t d[16], dp[16], M[16], eT[16], c[16];

  for (j = 0; j < 2048; j++)
    set_c (polyvec_get_elem (s1, j / 64), j % 64, (int8_t)p[j]);
  p += 2048;
  for (j = 0; j < 2048; j++)
    set_c (polyvec_get_elem (s1, 32 + j / 64), j % 64, rd_le16 (p + 2 * j));
  p += 4096;
  for (j = 0; j < 2048; j++)
    set_c (polyvec_get_elem (s1, 64 + j / 64), j % 64, (int8_t)p[j]);
  p += 2048;
  for (j = 0; j < 2048; j++)
    set_c (polyvec_get_elem (s1, 96 + j / 64), j % 64, rd_le16 (p + 2 * j));
  p += 4096;
  for (i = 0; i < 3; i++)
    for (j = 0; j < 16; j++)
      set_c (polyvec_get_elem (s1, 128 + i), j, rd_le16 (p + 32 * i + 2 * j));
  p += 96;
  for (i = 0; i < 16; i++)
    d[i] = p[i], dp[i] = p[16 + i];

  /* decrypt T with s_f: w_i = centre(v_T,i - (u_T^T s_f)_i), M_i = round(w_i / Delta), e_T = w - Delta M */
  {
    polyvec_t sf;
    poly_t acc;
    poly_alloc (acc, Rq);
    polyvec_get_subvec (sf, s1, 0, K, 1);
    polyvec_dot (acc, T->uT, sf);
    poly_fromcrt (acc);
    for (i = 0; i < 16; i++)
      {
        int64_t wv = cval (T->vT, i) - cval (acc, i);
        wv %= (int64_t)PQZ_Q;
        if (wv > (int64_t)(PQZ_Q - 1) / 2)
          wv -= (int64_t)PQZ_Q;
        if (wv < -(int64_t)(PQZ_Q - 1) / 2)
          wv += (int64_t)PQZ_Q;
        int64_t m = (wv >= 0 ? wv + DELTA / 2 : wv - DELTA / 2) / DELTA;
        M[i] = m;
        eT[i] = wv - DELTA * m;
      }
    poly_free (acc);
  }
  /* carries: c_i = (M_i + c_{i-1} - d'_i - d_i - f_i) / 16, exact, c_15 = 0 */
  int64_t cprev = 0;
  for (i = 0; i < 16; i++)
    {
      int64_t s = M[i] + cprev - dp[i] - d[i] - (int64_t)((T->fee >> (4 * i)) & 15);
      if (s % 16 != 0)
        return 0;
      c[i] = s / 16;
      cprev = c[i];
    }
  if (c[15] != 0)
    return 0;
  /* ranges (the proof shows them; an honest prover checks first) */
  for (i = 0; i < 16; i++)
    if (d[i] > 15 || dp[i] > 15 || M[i] < 0 || M[i] >= (1 << 14) || c[i] < -64 || c[i] >= 1984
        || eT[i] < -(1 << 24) || eT[i] >= (1 << 24))
      return 0;
  for (i = 0; i < 16; i++)
    for (b = 0; b < 25; b++)
      {
        unsigned slots[5] = { SLOT_D (i, b), SLOT_DP (i, b), SLOT_M (i, b), SLOT_C (i, b), SLOT_E (i, b) };
        int64_t vals[5] = { d[i], dp[i], M[i], c[i] + 64, eT[i] + (1 << 24) };
        unsigned widths[5] = { 4, 4, 14, i < 15 ? 11u : 0u, 25 };
        for (unsigned k = 0; k < 5; k++)
          if (b < widths[k])
            set_c (polyvec_get_elem (s1, TX_BITS + slots[k] / 64), slots[k] % 64, (vals[k] >> b) & 1);
      }
  return 1;
}

int
pqz_prove (uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *wit, size_t wit_len,
           const uint8_t rnd32[32], uint8_t *proof, size_t *proof_len)
{
  sys_t S;
  pf_t F;
  uint8_t h[32];
  int rc = PQZ_ERR_INPUT;

  if (!ready)
    return PQZ_ERR_INTERNAL;
  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  memset (&S, 0, sizeof (S));
  stmt_hash (h, op, stmt, stmt_len);
  if (op == PQZ_OP_REGISTER && stmt_len == PQZ_REG_STMT_BYTES && wit_len == PQZ_REG_WIT_BYTES)
    {
      polyvec_t pk;
      polyvec_alloc (pk, REG.P->tbox->ring, K);
      pf_alloc (&F, REG.P);
      if (build_reg (&S, stmt, pk))
        {
          for (unsigned j = 0; j < 2048; j++)
            {
              set_c (polyvec_get_elem (F.s1, j / 64), j % 64, (int8_t)wit[j]);
              set_c (polyvec_get_elem (F.s1, 32 + j / 64), j % 64, rd_le16 (wit + 2048 + 2 * j));
            }
          static const unsigned st[2] = { 0, 32 }, ln[2] = { 32, 32 };
          if (set_upsilon (REG.P, F.s1, st, ln))
            rc = do_prove (&S, &F, h, rnd32, proof, proof_len);
        }
    }
  else if (op == PQZ_OP_TRANSFER && stmt_len == PQZ_TX_STMT_BYTES && wit_len == PQZ_TX_WIT_BYTES)
    {
      txst_t T;
      pf_alloc (&F, TX.P);
      if (build_tx (&S, &T, stmt) && tx_witness (TX.P, &T, wit, F.s1))
        {
          static const unsigned st[7] = { 0, 32, 64, 96, 128, 129, 130 }, ln[7] = { 32, 32, 32, 32, 1, 1, 1 };
          if (set_upsilon (TX.P, F.s1, st, ln))
            rc = do_prove (&S, &F, h, rnd32, proof, proof_len);
        }
    }
  if (pqz_err)
    rc = pqz_err;
  pqz_arena_release (&base);
  return rc;
}

int
pqz_verify (uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *proof, size_t proof_len)
{
  sys_t S;
  pf_t F;
  uint8_t h[32];
  int ok = 0;

  if (!ready)
    return 0;
  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  memset (&S, 0, sizeof (S));
  stmt_hash (h, op, stmt, stmt_len);
  if (op == PQZ_OP_REGISTER && stmt_len == PQZ_REG_STMT_BYTES)
    {
      polyvec_t pk;
      polyvec_alloc (pk, REG.P->tbox->ring, K);
      pf_alloc (&F, REG.P);
      if (build_reg (&S, stmt, pk))
        ok = do_verify (&S, &F, h, proof, proof_len);
    }
  else if (op == PQZ_OP_TRANSFER && stmt_len == PQZ_TX_STMT_BYTES)
    {
      txst_t T;
      pf_alloc (&F, TX.P);
      if (build_tx (&S, &T, stmt))
        ok = do_verify (&S, &F, h, proof, proof_len);
    }
  if (pqz_err)
    ok = 0;
  pqz_arena_release (&base);
  return ok;
}

/* ---------------------------------------------------------------- client helpers (tests) */

static void
set_short (polyvec_t v, const int8_t *s8, const int16_t *s16)
{
  for (unsigned j = 0; j < 2048; j++)
    set_c (polyvec_get_elem (v, j / 64), j % 64, s8 ? s8[j] : s16[j]);
}

int
pqz_keypair_from_secret (const int8_t s[2048], const int16_t e[2048], uint8_t pk[PQZ_POLYVEC_BYTES])
{
  polyring_srcptr Rq = REG.P->tbox->ring;
  polyvec_t sv, ev, t;
  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  polyvec_alloc (sv, Rq, K), polyvec_alloc (ev, Rq, K), polyvec_alloc (t, Rq, K);
  set_short (sv, s, NULL);
  set_short (ev, NULL, e);
  polyvec_mul (t, REG.A, sv);
  polyvec_fromcrt (t);
  polyvec_add (t, t, ev, 0);
  for (unsigned i = 0; i < K; i++)
    wr_poly (pk + 512 * i, polyvec_get_elem (t, i), PQZ_D);
  pqz_arena_release (&base);
  return pqz_err;
}

int
pqz_encrypt (const uint8_t *const pks[], unsigned npk, const uint8_t msgs[][16], const int8_t r[2048],
             const int16_t e1[2048], const int16_t e2[][16], uint8_t u[PQZ_POLYVEC_BYTES],
             uint8_t vs[][PQZ_V_BYTES])
{
  polyring_srcptr Rq = REG.P->tbox->ring;
  polyvec_t rv, ev, t, pk, row;
  poly_t acc;
  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  polyvec_alloc (rv, Rq, K), polyvec_alloc (ev, Rq, K), polyvec_alloc (t, Rq, K), polyvec_alloc (pk, Rq, K);
  polyvec_alloc (row, Rq, K);
  poly_alloc (acc, Rq);
  set_short (rv, r, NULL);
  set_short (ev, NULL, e1);
  for (unsigned i = 0; i < K; i++) /* u = A^T r + e1 */
    {
      for (unsigned j = 0; j < K; j++)
        poly_set (polyvec_get_elem (row, j), polymat_get_elem (REG.A, j, i));
      polyvec_dot (polyvec_get_elem (t, i), row, rv);
    }
  polyvec_fromcrt (t);
  polyvec_add (t, t, ev, 0);
  for (unsigned i = 0; i < K; i++)
    wr_poly (u + 512 * i, polyvec_get_elem (t, i), PQZ_D);
  for (unsigned k = 0; k < npk; k++)
    {
      rd_polyvec (pk, pks[k]);
      polyvec_dot (acc, pk, rv);
      poly_fromcrt (acc);
      for (unsigned i = 0; i < 16; i++)
        set_c (acc, i, cval (acc, i) + e2[k][i] + DELTA * msgs[k][i]);
      poly_redc (acc, acc);
      wr_poly (vs[k], acc, 16);
    }
  pqz_arena_release (&base);
  return pqz_err;
}

int
pqz_decrypt_raw (const int8_t s[2048], const uint8_t u[PQZ_POLYVEC_BYTES], const uint8_t v[PQZ_V_BYTES],
                 int64_t w[16])
{
  polyring_srcptr Rq = REG.P->tbox->ring;
  polyvec_t sv, uv;
  poly_t acc, vv;
  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  polyvec_alloc (sv, Rq, K), polyvec_alloc (uv, Rq, K);
  poly_alloc (acc, Rq), poly_alloc (vv, Rq);
  set_short (sv, s, NULL);
  rd_polyvec (uv, u);
  rd_poly (vv, v, 16);
  polyvec_dot (acc, uv, sv);
  poly_fromcrt (acc);
  poly_sub (vv, vv, acc, 0);
  for (unsigned i = 0; i < 16; i++)
    w[i] = cval (vv, i);
  pqz_arena_release (&base);
  return pqz_err;
}
