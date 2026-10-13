/*
 * pqz-core relations: R_REG, R_TX (E-S1 spike), R_BURN, R_DS and R_DR as LaZer tbox statements
 * (pq-zether.md §7.2 step 6, §7.4, §7.5, §7.9), the C ABI of pqz.h, proof encoding (LaZer lin-proofs.c's
 * lnp_tbox_encproof / decproof, MIT, with the bounded decoder), and the A / ABDLOP-key caches (A at pqz_init,
 * each relation's keys at its first use).
 *
 * Witness layout in the tbox vector s1 (R_TX, m1 = 146 + Z = 7 slack polys):
 *   0..31 s_f | 32..63 e_f | 64..95 r | 96..127 e1 | 128 e2_t | 129 e2_f | 130 e2_a | 131..145 bits
 * Bits (slot k = coefficient k % 64 of poly 131 + k / 64):
 *   d_i: 4i+b | d'_i: 64+4i+b | M_i: 128+14i+b | c_i + 64: 352+11i+b (i < 15) | e_T[i] + 2^24: 517+25i+b
 * Rows 1, 2 are R_q-linear equations (quadeqs with no quadratic part); rows 3-7 are Z_q-linear equations
 * on single coefficients: ct(X^-i * (...)) = 0 (tbox evaleqs). Norms: 7 exact l2 proofs, 1 binary proof.
 *
 * R_BURN = R_TX rows 1, 2, 4, 6, 7 with d = digits(amount) public (m1 = 143 + Z = 5):
 *   0..31 s_f | 32..63 e_f | 64..95 r | 96..127 e1 | 128 e2_f | 129..142 bits
 *   d'_i: 4i+b | M_i: 64+14i+b | c_i + 64: 288+11i+b (i < 15) | e_T[i] + 2^24: 453+25i+b
 * R_DS (SENDER_S): u = A^T r + e1 (R_q rows), (pk_t^T r)_i + e2_t,i + Delta d_i - v_i = 0 (evaleqs), d public;
 *   s1 = 0..31 r | 32..63 e1 | 64 e2_t (m1 = 65 + Z = 3), no binary part.
 * R_DR (RECEIVER_X, AUDITOR): pk = A s + e (R_q rows), (u^T s)_i + (e'_i + 2^24) - 2^24 + Delta d_i - v_i = 0
 *   (evaleqs), d public; s1 = 0..31 s | 32..63 e | 64..70 bits (m1 = 71 + Z = 2), e'_i + 2^24: 25i+b.
 */
#include "lazer.h"
#include "lnp-tbox.h"
#include "memory.h"

#include "pqz.h"
#include "pqz_burn_params.h"
#include "pqz_dr_params.h"
#include "pqz_ds_params.h"
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
  uint8_t op;
  int ready; /* ABDLOP keys built (at the first prove / verify of this op) */
  polymat_t A1, A2p, Bp;
} rel_t;

static rel_t REG = { .P = pqz_reg, .op = PQZ_OP_REGISTER }, TX = { .P = pqz_tx, .op = PQZ_OP_TRANSFER },
             BURN = { .P = pqz_burn, .op = PQZ_OP_BURN }, DS = { .P = pqz_ds, .op = PQZ_OP_DISCLOSE_SENDER },
             DR = { .P = pqz_dr, .op = PQZ_OP_DISCLOSE_RECEIVER };
static polymat_t A; /* public, the same for every relation */
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

/* ABDLOP keys of R from SHAKE128("SCAAS-PQZ-ABDLOP-PP-V1" || op), built at the relation's first use and kept below
   the arena base mark, so an op never carries the keys of relations it does not use. Call with the arena released
   to the base mark (start of pqz_prove / pqz_verify); moves the mark above the keys. */
static int
rel_keys (rel_t *R)
{
  abdlop_params_srcptr tb = R->P->tbox;
  polyring_srcptr Rq = tb->ring;
  uint8_t pp[32];

  if (R->ready)
    return PQZ_OK;
  polymat_alloc (R->A1, Rq, tb->kmsis, tb->m1);
  polymat_alloc (R->A2p, Rq, tb->kmsis, tb->m2 - tb->kmsis);
  polymat_alloc (R->Bp, Rq, tb->l + tb->lext, tb->m2 - tb->kmsis);
  shake_tag (pp, "SCAAS-PQZ-ABDLOP-PP-V1", &R->op, 1, NULL, 0);
  abdlop_keygen (R->A1, R->A2p, R->Bp, pp, tb);
  /* NTT form now: a crtrep created lazily inside a call would sit above the arena mark and be dropped */
  polymat_tocrt (R->A1);
  polymat_tocrt (R->A2p);
  polymat_tocrt (R->Bp);
  if (pqz_err)
    return pqz_err; /* nothing kept: the caller releases to the old mark */
  pqz_arena_mark (&base);
  R->ready = 1;
  return PQZ_OK;
}

int
pqz_init (void *arena, size_t len)
{
  pqz_err = PQZ_OK;
  REG.ready = TX.ready = BURN.ready = DS.ready = DR.ready = 0;
  pqz_arena_init (arena, len);
  polymat_alloc (A, REG.P->tbox->ring, K, K);
  expand_A (A);
  if (pqz_err)
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

  coder_dec_begin_len (cstate, in, len);
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
  if (cstate->err || coder_dec_end (cstate) != 1)
    return 0;
  return (coder_get_offset (cstate) >> 3) == len; /* exactly the given length, no trailing bytes */
}

/* ---------------------------------------------------------------- the statements */

typedef struct
{
  rel_t *R;
  unsigned N, M;
  unsigned bits, nbin; /* evaleqs: the binary witness polys are s1[bits .. bits + nbin) */
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
              transpose ? polymat_get_elem (A, j, i) : polymat_get_elem (A, i, j));
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

#define TX_BITS 131
/* ---- R_TX and R_BURN (the debit relations) ---- */

/* bit slots: base of each group (slot = base + width * i + b), -1 if the group is absent (R_BURN: d public) */
typedef struct
{
  int d, dp, m, c, e;
} lay_t;
static const lay_t LAY_TX = { 0, 64, 128, 352, 517 }, LAY_BURN = { -1, 0, 64, 288, 453 };
#define SLOT(base, w, i, b) ((unsigned)(base) + (w) * (i) + (b))

typedef struct
{
  polyvec_ptr pkf, pkt, pka, uT, u; /* R_DS / R_DR: pkt = pk, u = u */
  poly_t vT, vt, vf, va;            /* R_DS / R_DR: vt = v */
  uint64_t fee, amount;             /* amount: R_BURN, R_DS, R_DR */
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
  for (unsigned b = 0; b < S->nbin; b++)
    {
      poly_ptr p = spolyvec_insert_elem (S->r1p[idx], 2 * (S->bits + b));
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

static unsigned
digit (uint64_t x, unsigned i)
{
  return (unsigned)((x >> (4 * i)) & 15);
}

/* a be32 statement word that must be < 2^64 (pq-zether.md §5: anything else is non-canonical) */
static int
rd_word64 (uint64_t *v, const uint8_t *p)
{
  int ok = 1;
  for (unsigned b = 0; b < 24; b++)
    ok &= p[b] == 0;
  *v = rd_be8 (p + 24);
  return ok;
}

static polyvec_ptr
new_vec (polyring_srcptr Rq)
{
  polyvec_ptr v = _alloc (sizeof (polyvec_t));
  polyvec_alloc (v, Rq, K);
  return v;
}

/* R_TX: header || pk_f || pk_t || pk_a || u_T || v_T || u || v_t || v_f || v_a; R_BURN: header || pk_f || u_T || v_T
   || u || v_f (pq-zether.md §7.7). Reads fee and (R_BURN) amount from the header; the rest of it is hashed only. */
static int
parse_debit (txst_t *T, polyring_srcptr Rq, const uint8_t *stmt, int burn)
{
  const uint8_t *p = stmt + PQZ_HEADER_BYTES;
  int ok = rd_word64 (&T->fee, stmt + PQZ_HDR_FEE);
  T->amount = 0;
  if (burn)
    ok &= rd_word64 (&T->amount, stmt + PQZ_HDR_AMOUNT);
  T->pkf = new_vec (Rq), T->uT = new_vec (Rq), T->u = new_vec (Rq);
  poly_alloc (T->vT, Rq), poly_alloc (T->vf, Rq);
  ok &= rd_polyvec (T->pkf, p), p += PQZ_POLYVEC_BYTES;
  if (!burn)
    {
      T->pkt = new_vec (Rq), T->pka = new_vec (Rq);
      poly_alloc (T->vt, Rq), poly_alloc (T->va, Rq);
      ok &= rd_polyvec (T->pkt, p), p += PQZ_POLYVEC_BYTES;
      ok &= rd_polyvec (T->pka, p), p += PQZ_POLYVEC_BYTES;
    }
  ok &= rd_polyvec (T->uT, p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_poly (T->vT, p, 16), p += PQZ_V_BYTES;
  ok &= rd_polyvec (T->u, p), p += PQZ_POLYVEC_BYTES;
  if (!burn)
    ok &= rd_poly (T->vt, p, 16), p += PQZ_V_BYTES;
  ok &= rd_poly (T->vf, p, 16), p += PQZ_V_BYTES;
  if (!burn)
    ok &= rd_poly (T->va, p, 16);
  return ok;
}

/* R_TX (burn = 0) or R_BURN (burn = 1): the rows of pq-zether.md §7.4; R_BURN skips rows 3 and 5 and moves
   Delta d_i (row 4 has none: d' is the witness) and d_i (row 7) into the constant term */
static int
build_debit (sys_t *S, txst_t *T, const uint8_t *stmt, int burn)
{
  rel_t *R = burn ? &BURN : &TX;
  const lay_t *L = burn ? &LAY_BURN : &LAY_TX;
  polyring_srcptr Rq = R->P->tbox->ring;
  const unsigned m1 = burn ? 143 : 146, e2f = burn ? 128 : 129;
  poly_ptr acc[15];
  unsigned i, b, e = 0;

  S->R = R;
  S->N = NTXQ;
  S->M = burn ? 48 : NTXE;
  S->bits = burn ? 129 : TX_BITS;
  S->nbin = burn ? 14 : 15;
  if (!parse_debit (T, Rq, stmt, burn))
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
      const int64_t dpub = burn ? digit (T->amount, i) : 0;
      /* rows 3-5: (pk^T r)_i + e2_i + Delta * digit_i - v_i = 0 */
      if (!burn)
        {
          acc_zero (acc);
          for (b = 0; b < 4; b++)
            add_bit (acc, SLOT (L->d, 4, i, b), DELTA << b);
          evaleq (S, e++, T->pkt, 64, i, 128, acc, -cval (T->vt, i));
        }
      acc_zero (acc);
      for (b = 0; b < 4; b++)
        add_bit (acc, SLOT (L->dp, 4, i, b), DELTA << b);
      evaleq (S, e++, T->pkf, 64, i, e2f, acc, -cval (T->vf, i));
      if (!burn)
        {
          acc_zero (acc);
          for (b = 0; b < 4; b++)
            add_bit (acc, SLOT (L->d, 4, i, b), DELTA << b);
          evaleq (S, e++, T->pka, 64, i, 130, acc, -cval (T->va, i));
        }
      /* row 6: (u_T^T s_f)_i + Delta M_i + (e_T,i + 2^24) - 2^24 - v_T,i = 0 */
      acc_zero (acc);
      for (b = 0; b < 14; b++)
        add_bit (acc, SLOT (L->m, 14, i, b), DELTA << b);
      for (b = 0; b < 25; b++)
        add_bit (acc, SLOT (L->e, 25, i, b), (int64_t)1 << b);
      evaleq (S, e++, T->uT, 0, i, -1, acc, -cval (T->vT, i) - ((int64_t)1 << 24));
      /* row 7 (over Z, all terms < 2^15): M_i + c_{i-1} - d'_i - d_i - f_i - 16 c_i = 0, c = cbits - 64 */
      acc_zero (acc);
      int64_t rhs = -(int64_t)digit (T->fee, i) - dpub;
      for (b = 0; b < 14; b++)
        add_bit (acc, SLOT (L->m, 14, i, b), (int64_t)1 << b);
      if (i >= 1)
        {
          for (b = 0; b < 11; b++)
            add_bit (acc, SLOT (L->c, 11, i - 1, b), (int64_t)1 << b);
          rhs -= 64;
        }
      for (b = 0; b < 4; b++)
        {
          add_bit (acc, SLOT (L->dp, 4, i, b), -((int64_t)1 << b));
          if (!burn)
            add_bit (acc, SLOT (L->d, 4, i, b), -((int64_t)1 << b));
        }
      if (i <= 14)
        {
          for (b = 0; b < 11; b++)
            add_bit (acc, SLOT (L->c, 11, i, b), -((int64_t)16 << b));
          rhs += 16 * 64;
        }
      evaleq (S, e++, NULL, 0, i, -1, acc, rhs);
    }

  S->Es[0] = new_sel (Rq, 32, m1, 0);
  S->Es[1] = new_sel (Rq, 32, m1, 32);
  S->Es[2] = new_sel (Rq, 32, m1, 64);
  S->Es[3] = new_sel (Rq, 32, m1, 96);
  S->Es[4] = new_sel (Rq, 1, m1, 128);
  if (!burn)
    {
      S->Es[5] = new_sel (Rq, 1, m1, 129);
      S->Es[6] = new_sel (Rq, 1, m1, 130);
    }
  S->Ps = new_sel (Rq, S->nbin, m1, S->bits);
  S->Ds = new_sel (Rq, 1, m1, 128); /* e2_t (R_TX) / e2_f (R_BURN), |coefficients| <= 20 < 64 (Bprime) */
  return 1;
}

/* ---- R_DS and R_DR (disclosure, pq-zether.md §7.9) ---- */

/* opTag || proofSystemId || chainId || chainUid || token || registry || entryRef || amount || kind (32-byte words)
   || pk || u || v; only amount, pk, u, v enter the equations, the rest is hashed */
static int
parse_disc (txst_t *T, polyring_srcptr Rq, const uint8_t *stmt)
{
  const uint8_t *p = stmt + PQZ_DISC_PK;
  int ok = rd_word64 (&T->amount, stmt + PQZ_DISC_AMOUNT);
  T->pkt = new_vec (Rq), T->u = new_vec (Rq);
  poly_alloc (T->vt, Rq);
  ok &= rd_polyvec (T->pkt, p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_polyvec (T->u, p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_poly (T->vt, p, 16);
  return ok;
}

/* R_DS: u = A^T r + e1; (pk^T r)_i + e2_i + Delta d_i - v_i = 0 */
static int
build_ds (sys_t *S, txst_t *T, const uint8_t *stmt)
{
  rel_t *R = &DS;
  polyring_srcptr Rq = R->P->tbox->ring;
  S->R = R;
  S->N = K;
  S->M = 16;
  S->bits = 65;
  S->nbin = 0;
  if (!parse_disc (T, Rq, stmt))
    return 0;
  for (unsigned i = 0; i < K; i++)
    add_lin_row (S, i, 1, i, 0, 32, polyvec_get_elem (T->u, i));
  for (unsigned i = 0; i < 16; i++)
    evaleq (S, i, T->pkt, 0, i, 64, NULL, DELTA * digit (T->amount, i) - cval (T->vt, i));
  S->Es[0] = new_sel (Rq, 32, 65, 0);
  S->Es[1] = new_sel (Rq, 32, 65, 32);
  S->Es[2] = new_sel (Rq, 1, 65, 64);
  S->Ps = NULL;
  S->Ds = new_sel (Rq, 1, 65, 64); /* e2_t, |coefficients| <= 20 < 64 (ds_params.sage Bprime) */
  return 1;
}

/* R_DR: pk = A s + e; (u^T s)_i + (e'_i + 2^24) - 2^24 + Delta d_i - v_i = 0 */
static int
build_dr (sys_t *S, txst_t *T, const uint8_t *stmt)
{
  rel_t *R = &DR;
  polyring_srcptr Rq = R->P->tbox->ring;
  poly_ptr acc[15];
  S->R = R;
  S->N = K;
  S->M = 16;
  S->bits = 64;
  S->nbin = 7;
  if (!parse_disc (T, Rq, stmt))
    return 0;
  for (unsigned b = 0; b < 15; b++)
    acc[b] = new_poly (Rq);
  for (unsigned i = 0; i < K; i++)
    add_lin_row (S, i, 0, i, 0, 32, polyvec_get_elem (T->pkt, i));
  for (unsigned i = 0; i < 16; i++)
    {
      acc_zero (acc);
      for (unsigned b = 0; b < 25; b++)
        add_bit (acc, 25 * i + b, (int64_t)1 << b);
      evaleq (S, i, T->u, 0, i, -1, acc, DELTA * digit (T->amount, i) - cval (T->vt, i) - ((int64_t)1 << 24));
    }
  S->Es[0] = new_sel (Rq, 32, 71, 0);
  S->Es[1] = new_sel (Rq, 32, 71, 32);
  S->Ps = new_sel (Rq, 7, 71, 64);
  S->Ds = new_sel (Rq, 1, 71, 0); /* s[0], coefficients in [-1, 1] (dr_params.sage Bprime) */
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

#ifdef PQZ_L2DOM_POC
/* Test-only cheating prover (pqz-core/l2dom/, never in a production build): when set, pool the l2 slack of all
   Z blocks, sum_z (B_z^2 - ||x_z||^2), and spread it greedily over the upsilon_z (each holds bitlen(B_z^2) bits), so a
   block may exceed its own B_z as long as sum_z ||x_z||^2 <= sum_z B_z^2. Checks whether the verifier enforces each
   exact-l2 equation separately. */
int pqz_l2dom_poc;
#define POC_IGNORE_ERR pqz_l2dom_poc /* and emit the proof although the prover's own self-checks fail */
#else
#define POC_IGNORE_ERR 0
#endif

/* s1 slack polys: upsilon_i = binexp(B_i^2 - ||x_i||^2) */
static int
set_upsilon (const lnp_tbox_params_struct *P, polyvec_t s1, const unsigned *start, const unsigned *len)
{
  const unsigned m1 = P->tbox->m1 - P->Z;
#ifdef PQZ_L2DOM_POC
  if (pqz_l2dom_poc)
    {
      int64_t slack = 0;
      for (unsigned z = 0; z < P->Z; z++)
        {
          slack += int_get_i64 (P->l2Bsqr[z]);
          for (unsigned j = 0; j < len[z]; j++)
            slack -= l2sq_poly (polyvec_get_elem (s1, start[z] + j));
          poly_set_zero (polyvec_get_elem (s1, m1 + z));
        }
      if (slack < 0)
        return 0;
      for (unsigned z = 0; z < P->Z; z++)
        {
          /* upsilon_z carries bits 2^0 .. 2^(bitlen(B_z^2) - 1) */
          int64_t cap = ((int64_t)2 << (63 - __builtin_clzll (int_get_i64 (P->l2Bsqr[z])))) - 1;
          int64_t put = slack < cap ? slack : cap;
          INT_T (d, 2 * P->tbox->ring->q->nlimbs);
          int_set_i64 (d, put);
          int_binexp (polyvec_get_elem (s1, m1 + z), NULL, d);
          slack -= put;
        }
      if (slack > 0)
        return 0;
      return 1;
    }
#endif
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
  if (pqz_err && !POC_IGNORE_ERR)
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

/* 2048 witness coefficients (int8, or int16 LE if wide) into s1[off .. off + 32) */
static const uint8_t *
wit_vec (polyvec_t s1, unsigned off, const uint8_t *p, int wide)
{
  for (unsigned j = 0; j < 2048; j++)
    set_c (polyvec_get_elem (s1, off + j / 64), j % 64, wide ? rd_le16 (p + 2 * j) : (int8_t)p[j]);
  return p + (wide ? 4096 : 2048);
}

/* w_i = centre(v_i - (u^T s)_i), s = s1[0 .. 32) */
static void
dec_w (polyring_srcptr Rq, polyvec_ptr u, poly_ptr v, polyvec_t s1, int64_t w[16])
{
  polyvec_t s;
  poly_t acc;
  poly_alloc (acc, Rq);
  polyvec_get_subvec (s, s1, 0, K, 1);
  polyvec_dot (acc, u, s);
  poly_fromcrt (acc);
  for (unsigned i = 0; i < 16; i++)
    {
      int64_t wv = cval (v, i) - cval (acc, i);
      wv %= (int64_t)PQZ_Q;
      if (wv > (int64_t)(PQZ_Q - 1) / 2)
        wv -= (int64_t)PQZ_Q;
      if (wv < -(int64_t)(PQZ_Q - 1) / 2)
        wv += (int64_t)PQZ_Q;
      w[i] = wv;
    }
  poly_free (acc);
}

/* R_TX / R_BURN witness -> s1 (incl. derived M, carries, e_T); returns 0 if inconsistent */
static int
debit_witness (txst_t *T, const uint8_t *w, polyvec_t s1, int burn)
{
  polyring_srcptr Rq = (burn ? BURN.P : TX.P)->tbox->ring;
  const lay_t *L = burn ? &LAY_BURN : &LAY_TX;
  const unsigned bits = burn ? 129 : TX_BITS, ne2 = burn ? 1 : 3;
  const uint8_t *p = w;
  unsigned i, j, b;
  int64_t d[16], dp[16], M[16], eT[16], c[16];

  p = wit_vec (s1, 0, p, 0);
  p = wit_vec (s1, 32, p, 1);
  p = wit_vec (s1, 64, p, 0);
  p = wit_vec (s1, 96, p, 1);
  for (i = 0; i < ne2; i++)
    for (j = 0; j < 16; j++)
      set_c (polyvec_get_elem (s1, 128 + i), j, rd_le16 (p + 32 * i + 2 * j));
  p += 32 * ne2;
  for (i = 0; i < 16; i++)
    if (burn)
      d[i] = digit (T->amount, i), dp[i] = p[i];
    else
      d[i] = p[i], dp[i] = p[16 + i];

  /* decrypt T with s_f: w_i = centre(v_T,i - (u_T^T s_f)_i), M_i = round(w_i / Delta), e_T = w - Delta M */
  {
    int64_t wv[16];
    dec_w (Rq, T->uT, T->vT, s1, wv);
    for (i = 0; i < 16; i++)
      {
        int64_t m = (wv[i] >= 0 ? wv[i] + DELTA / 2 : wv[i] - DELTA / 2) / DELTA;
        M[i] = m;
        eT[i] = wv[i] - DELTA * m;
      }
  }
  /* carries: c_i = (M_i + c_{i-1} - d'_i - d_i - f_i) / 16, exact, c_15 = 0 */
  int64_t cprev = 0;
  for (i = 0; i < 16; i++)
    {
      int64_t s = M[i] + cprev - dp[i] - d[i] - (int64_t)digit (T->fee, i);
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
        int base[5] = { L->d, L->dp, L->m, L->c, L->e };
        int64_t vals[5] = { d[i], dp[i], M[i], c[i] + 64, eT[i] + (1 << 24) };
        unsigned widths[5] = { 4, 4, 14, 11, 25 }, n[5] = { 4, 4, 14, i < 15 ? 11u : 0u, 25 };
        for (unsigned k = 0; k < 5; k++)
          if (base[k] >= 0 && b < n[k])
            {
              unsigned slot = SLOT (base[k], widths[k], i, b);
              set_c (polyvec_get_elem (s1, bits + slot / 64), slot % 64, (vals[k] >> b) & 1);
            }
      }
  return 1;
}

/* R_DR witness -> s1: s, e and the bits of e'_i + 2^24, e'_i = centre(v_i - (u^T s)_i) - Delta d_i */
static int
dr_witness (txst_t *T, const uint8_t *w, polyvec_t s1)
{
  int64_t wv[16];
  wit_vec (s1, 32, wit_vec (s1, 0, w, 0), 1);
  dec_w (DR.P->tbox->ring, T->u, T->vt, s1, wv);
  for (unsigned i = 0; i < 16; i++)
    {
      int64_t e = wv[i] - DELTA * digit (T->amount, i);
      if (e < -(1 << 24) || e >= (1 << 24))
        return 0; /* not an encryption of amount under this key */
      for (unsigned b = 0; b < 25; b++)
        set_c (polyvec_get_elem (s1, 64 + (25 * i + b) / 64), (25 * i + b) % 64, ((e + (1 << 24)) >> b) & 1);
    }
  return 1;
}

/* the statement of op (stmt_len checked); 0 if the op is unknown or the statement malformed */
static int
build (sys_t *S, txst_t *T, uint8_t op, const uint8_t *stmt, size_t stmt_len, polyvec_t pk)
{
  switch (op)
    {
    case PQZ_OP_REGISTER:
      return stmt_len == PQZ_REG_STMT_BYTES && build_reg (S, stmt, pk);
    case PQZ_OP_TRANSFER:
      return stmt_len == PQZ_TX_STMT_BYTES && build_debit (S, T, stmt, 0);
    case PQZ_OP_BURN:
      return stmt_len == PQZ_BURN_STMT_BYTES && build_debit (S, T, stmt, 1);
    case PQZ_OP_DISCLOSE_SENDER:
      return stmt_len == PQZ_DISC_STMT_BYTES && build_ds (S, T, stmt);
    case PQZ_OP_DISCLOSE_RECEIVER:
      return stmt_len == PQZ_DISC_STMT_BYTES && build_dr (S, T, stmt);
    }
  return 0;
}

static rel_t *
rel_of (uint8_t op)
{
  switch (op)
    {
    case PQZ_OP_REGISTER:
      return &REG;
    case PQZ_OP_TRANSFER:
      return &TX;
    case PQZ_OP_BURN:
      return &BURN;
    case PQZ_OP_DISCLOSE_SENDER:
      return &DS;
    case PQZ_OP_DISCLOSE_RECEIVER:
      return &DR;
    }
  return NULL;
}

/* witness -> s1 and the l2 slack (upsilon); 0 if the witness is malformed, inconsistent or above a bound */
static int
witness (txst_t *T, uint8_t op, const uint8_t *wit, size_t wit_len, polyvec_t s1)
{
  static const unsigned st_reg[2] = { 0, 32 }, ln_reg[2] = { 32, 32 };
  static const unsigned st_tx[7] = { 0, 32, 64, 96, 128, 129, 130 }, ln_tx[7] = { 32, 32, 32, 32, 1, 1, 1 };
  static const unsigned st_ds[3] = { 0, 32, 64 }, ln_ds[3] = { 32, 32, 1 };
  const unsigned *st = st_reg, *ln = ln_reg;
  switch (op)
    {
    case PQZ_OP_REGISTER:
      if (wit_len != PQZ_REG_WIT_BYTES)
        return 0;
      wit_vec (s1, 32, wit_vec (s1, 0, wit, 0), 1);
      break;
    case PQZ_OP_TRANSFER:
    case PQZ_OP_BURN:
      if (wit_len != (op == PQZ_OP_BURN ? PQZ_BURN_WIT_BYTES : PQZ_TX_WIT_BYTES)
          || !debit_witness (T, wit, s1, op == PQZ_OP_BURN))
        return 0;
      st = st_tx, ln = ln_tx; /* R_BURN: the first 5 blocks */
      break;
    case PQZ_OP_DISCLOSE_SENDER:
      if (wit_len != PQZ_DS_WIT_BYTES)
        return 0;
      wit = wit_vec (s1, 32, wit_vec (s1, 0, wit, 0), 1);
      for (unsigned j = 0; j < 16; j++)
        set_c (polyvec_get_elem (s1, 64), j, rd_le16 (wit + 2 * j));
      st = st_ds, ln = ln_ds;
      break;
    case PQZ_OP_DISCLOSE_RECEIVER:
      if (wit_len != PQZ_DR_WIT_BYTES || !dr_witness (T, wit, s1))
        return 0;
      break;
    default:
      return 0;
    }
  return set_upsilon (rel_of (op)->P, s1, st, ln);
}

int
pqz_prove (uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *wit, size_t wit_len,
           const uint8_t rnd32[32], uint8_t *proof, size_t *proof_len)
{
  sys_t S;
  pf_t F;
  txst_t T;
  polyvec_t pk;
  uint8_t h[32];
  int rc = PQZ_ERR_INPUT;
  rel_t *R = rel_of (op);

  if (!ready)
    return PQZ_ERR_INTERNAL;
  if (R == NULL)
    return PQZ_ERR_INPUT;
  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  if (rel_keys (R))
    {
      rc = pqz_err;
      pqz_arena_release (&base);
      return rc;
    }
  memset (&S, 0, sizeof (S));
  stmt_hash (h, op, stmt, stmt_len);
  if (op == PQZ_OP_REGISTER)
    polyvec_alloc (pk, REG.P->tbox->ring, K);
  pf_alloc (&F, R->P);
  if (build (&S, &T, op, stmt, stmt_len, pk) && witness (&T, op, wit, wit_len, F.s1))
    rc = do_prove (&S, &F, h, rnd32, proof, proof_len);
  if (pqz_err && !POC_IGNORE_ERR)
    rc = pqz_err;
  pqz_arena_release (&base);
  return rc;
}

int
pqz_verify (uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *proof, size_t proof_len)
{
  sys_t S;
  pf_t F;
  txst_t T;
  polyvec_t pk;
  uint8_t h[32];
  int ok = 0;
  rel_t *R = rel_of (op);

  if (!ready || R == NULL)
    return 0;
  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  if (rel_keys (R))
    {
      pqz_arena_release (&base);
      return 0;
    }
  memset (&S, 0, sizeof (S));
  stmt_hash (h, op, stmt, stmt_len);
  if (op == PQZ_OP_REGISTER)
    polyvec_alloc (pk, REG.P->tbox->ring, K);
  pf_alloc (&F, R->P);
  if (build (&S, &T, op, stmt, stmt_len, pk))
    ok = do_verify (&S, &F, h, proof, proof_len);
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
  polyvec_mul (t, A, sv);
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
        poly_set (polyvec_get_elem (row, j), polymat_get_elem (A, j, i));
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
