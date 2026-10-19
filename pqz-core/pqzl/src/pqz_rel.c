/*
 * pqz-core relations: R_REG, R_TX (E-S1 spike), R_BURN, R_DS, R_DR and R_TXM as LaZer tbox statements
 * (pq-zero-knowledge.md §7.2 step 6, §7.4, §7.5, §7.9), the C ABI of pqz.h, proof encoding (LaZer lin-proofs.c's
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
 * R_TX0 = R_TX without the auditor (CTR-PQZ-24: no pk_a / v_a, row 5 skipped; m1 = 145 + Z = 6), op 1 with the
 *   66,560-byte statement, the same bit layout as R_TX:
 *   0..31 s_f | 32..63 e_f | 64..95 r | 96..127 e1 | 128 e2_t | 129 e2_f | 130..144 bits
 *   Op 1 is R_TX or R_TX0 by the statement length; the auditorOn header word must be 1 / 0 (P6e plan R6).
 * R_BURN = R_TX rows 1, 2, 4, 6, 7 with d = digits(amount) public (m1 = 143 + Z = 5):
 *   0..31 s_f | 32..63 e_f | 64..95 r | 96..127 e1 | 128 e2_f | 129..142 bits
 *   d'_i: 4i+b | M_i: 64+14i+b | c_i + 64: 288+11i+b (i < 15) | e_T[i] + 2^24: 453+25i+b
 * R_TXM (op 7, P6-ANON) = R_TX with M legs and G = ceil(M / 4) randomness groups (layout at shape_t below; M = 1
 *   is R_TX / R_TX0 byte for byte, with its own ABDLOP keys); the relation is named by the header's M and auditorOn
 *   words, the length must be that shape's.
 * R_DS (SENDER_S): u = A^T r + e1 (R_q rows), (pk_t^T r)_i + e2_t,i + Delta d_i - v_i = 0 (evaleqs), d public;
 *   s1 = 0..31 r | 32..63 e1 | 64 e2_t (m1 = 65 + Z = 3), no binary part.
 * R_DR (RECEIVER_X, AUDITOR): pk = A s + e (R_q rows), (u^T s)_i + (e'_i + 2^24) - 2^24 + Delta d_i - v_i = 0
 *   (evaleqs), d public; s1 = 0..31 s | 32..63 e | 64..70 bits (m1 = 71 + Z = 2), e'_i + 2^24: 25i+b.
 */
#include "lazer.h"
#include "lnp-tbox.h"
#include "memory.h"

#include "pqz.h"
#include "pqz_int.h"
#include "pqz_burn_params.h"
#include "pqz_dr_params.h"
#include "pqz_ds_params.h"
#include "pqz_reg_params.h"
#include "pqz_tx0_params.h"
#include "pqz_tx_params.h"
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

#define K 32
#define DELTA ((int64_t)((1 << 26) - 1))
#define NREG 32
#define MAXL PQZ_TXM_MAX_LEGS                 /* legs */
#define MAXG PQZ_TXM_GROUPS (PQZ_TXM_MAX_LEGS) /* randomness groups */
#define NTXQ (K * (1 + MAXG))                 /* R_q-linear rows: row 1, row 2 per group */
#define NTXE (16 * (3 + 2 * MAXL))            /* evaleqs: 16 per leg, auditor copy, v_f, row 6, row 7 */
#define NBIN ((853 + 64 * MAXL + 63) / 64)    /* binary polys: 853 + 64 M bits */
#define NZ (3 + 2 * MAXG + 2 * MAXL)  /* exact l2 blocks: s_f, e_f, r_g, e1_g, one per e2 vector */

typedef struct
{
  const lnp_tbox_params_struct *P;
  uint8_t op;   /* the op the relation serves */
  uint8_t code; /* the op, PQZ_REL_TX0 or PQZ_REL_TXM (M, A): names the relation in pqz_sv.c and the test hook, and is
                   the byte of its ABDLOP keys' tag (R_TX0: 0x81, its own keys; REFRESH / AUDITOR share their op's
                   relation; every R_TXM shape its own, also M = 1, which shares R_TX's / R_TX0's parameters) */
  uint8_t legs, aud; /* debit shape: legs (R_TX, R_TX0: 1; R_BURN: 0, d public; R_TXM: M), auditor copies (0 / 1) */
  int ready;         /* ABDLOP keys built (at the first prove / verify of this relation) */
  polymat_t A1, A2p, Bp;
} rel_t;

static rel_t REG = { .P = pqz_reg, .op = PQZ_OP_REGISTER, .code = PQZ_OP_REGISTER },
             TX = { .P = pqz_tx, .op = PQZ_OP_TRANSFER, .code = PQZ_OP_TRANSFER, .legs = 1, .aud = 1 },
             TX0 = { .P = pqz_tx0, .op = PQZ_OP_TRANSFER, .code = PQZ_REL_TX0, .legs = 1 },
             BURN = { .P = pqz_burn, .op = PQZ_OP_BURN, .code = PQZ_OP_BURN },
             DS = { .P = pqz_ds, .op = PQZ_OP_DISCLOSE_SENDER, .code = PQZ_OP_DISCLOSE_SENDER },
             DR = { .P = pqz_dr, .op = PQZ_OP_DISCLOSE_RECEIVER, .code = PQZ_OP_DISCLOSE_RECEIVER };
/* R_TXM (op 7) by (M, auditorOn); M = 1 on R_TX's / R_TX0's parameters (P6-ANON F6) */
#define TXM_REL(p, m, lg, a) { .P = p, .op = PQZ_OP_TRANSFER_MULTI, .code = PQZ_REL_TXM (lg, a), .legs = m, .aud = a }
static rel_t TXM[] = { TXM_REL (pqz_tx, 1, 0, 1),     TXM_REL (pqz_txm2, 2, 1, 1),  TXM_REL (pqz_txm4, 4, 2, 1),
                       TXM_REL (pqz_txm8, 8, 3, 1),   TXM_REL (pqz_tx0, 1, 0, 0),   TXM_REL (pqz_txm20, 2, 1, 0),
                       TXM_REL (pqz_txm40, 4, 2, 0),  TXM_REL (pqz_txm80, 8, 3, 0),
#ifdef PQZ_TXM_OVERSIZE
                       TXM_REL (pqz_txm16, 16, 4, 1), TXM_REL (pqz_txm160, 16, 4, 0),
#endif
};
#define NTXM (sizeof TXM / sizeof TXM[0])
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

/* ABDLOP keys of R from SHAKE128("SCAAS-PQZ-ABDLOP-PP-V1" || code), code = the op (R_TX0: 0x81), built at the relation's first use and kept below
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
  shake_tag (pp, "SCAAS-PQZ-ABDLOP-PP-V1", &R->code, 1, NULL, 0);
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
  REG.ready = TX.ready = TX0.ready = BURN.ready = DS.ready = DR.ready = 0;
  for (unsigned t = 0; t < NTXM; t++)
    TXM[t].ready = 0;
#ifdef PQZ_SV
  pqz_sv_reset ();
#endif
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

/* n coefficients (be8, each < q) into poly p, centred; the rest of p zero. Returns 0 if a value is >= q. A value >= q
   is still read, as the int64 (v - q) mod 2^64 (2026-10-18: unsigned subtraction; (int64_t)v - q overflowed for v in
   [2^63, 2^63 + q), undefined behaviour; the same value the compiled code and the Rust port's keys.rs rd_poly give) */
static int
rd_poly (poly_ptr p, const uint8_t *in, unsigned n)
{
  int ok = 1;
  poly_set_zero (p);
  for (unsigned k = 0; k < n; k++)
    {
      uint64_t v = rd_be8 (in + 8 * k);
      ok &= v < PQZ_Q;
      set_c (p, k, v > (PQZ_Q - 1) / 2 ? (int64_t)(v - PQZ_Q) : (int64_t)v);
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

/* statement digest: SHAKE128("SCAAS-PQZ-TRANSCRIPT-V1" || op || be32(len) || stmt). be32 keeps the low 32 bits of
   len; every caller passes a relation's exact statement length (< 70,000 B, checked in rel_of first: review fix A),
   as Rust's u32::try_from. */
void
pqz_stmt_hash (uint8_t h[32], uint8_t op, const uint8_t *stmt, size_t len)
{
  uint8_t hdr[5] = { op, (uint8_t)(len >> 24), (uint8_t)(len >> 16), (uint8_t)(len >> 8), (uint8_t)len };
  shake_tag (h, "SCAAS-PQZ-TRANSCRIPT-V1", hdr, 5, stmt, len);
}

/* ---------------------------------------------------------------- proof encoding (LaZer lin-proofs.c) */

/* bits of coder_enc_ghint3 (v) */
static size_t
ghint_bits (polyvec_t v)
{
  size_t n = 0;
  for (unsigned i = 0; i < v->nelems; i++)
    for (unsigned k = 0; k < PQZ_D; k++)
      {
        const int64_t e = int_get_i64 (poly_get_coeff (polyvec_get_elem (v, i), k));
        n += e >= -1 && e <= 1 ? 2 : (size_t)(e >= 2 ? 2 * e - 1 : -2 * e);
      }
  return n;
}

/* the proof into out[0 .. cap); 0 if it would not fit (nothing written past cap: L-5, the entropy-coded parts are
   data-dependent), or if the encoder's length differs from the predicted one */
static int
encproof (uint8_t *out, size_t cap, size_t *len, polyvec_t tA1, polyvec_t tB, polyvec_t h, poly_t c, polyvec_t z1,
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
  size_t bits;

  polyvec_fromcrt (z1);
  polyvec_fromcrt (z21);
  polyvec_fromcrt (z3);
  polyvec_fromcrt (z4); /* the nprime = 1 approximate l_inf filler */
  polyvec_mod (z1, z1);
  polyvec_mod (z21, z21);
  polyvec_mod (z3, z3);
  polyvec_mod (z4, z4);
  polyvec_redc (z1, z1);
  polyvec_redc (z21, z21);
  polyvec_redc (z3, z3);
  polyvec_redc (z4, z4);
  bits = (size_t)d * ((tB->nelems + h->nelems) * log2q + tA1->nelems * (log2q - D) + log2omega) + ghint_bits (hint)
         + coder_grandom3_nbits (z1, params->quad_eval->quad_many->log2stdev1)
         + coder_grandom3_nbits (z21, params->quad_eval->quad_many->log2stdev2)
         + coder_grandom3_nbits (z3, params->log2stdev3) + coder_grandom3_nbits (z4, params->log2stdev4);
  if (bits / 8 + 1 > cap) /* coder_enc_end: one pad bit, then the byte count */
    return 0;
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
  coder_enc_grandom3 (cstate, z1, params->quad_eval->quad_many->log2stdev1);
  coder_enc_grandom3 (cstate, z21, params->quad_eval->quad_many->log2stdev2);
  coder_enc_grandom3 (cstate, z3, params->log2stdev3);
  coder_enc_grandom3 (cstate, z4, params->log2stdev4);
  coder_enc_end (cstate);
  *len = coder_get_offset (cstate) >> 3;
  return *len == bits / 8 + 1;
}

int
pqz_decproof (size_t len, const uint8_t *in, polyvec_t tA1, polyvec_t tB, polyvec_t h, poly_t c, polyvec_t z1,
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
  polymat_ptr Es[NZ];
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

/* ---- R_TX, R_TX0, R_BURN and R_TXM (the debit relations) ---- */

/* The debit shape of a relation: M legs (R_TX / R_TX0: 1; R_BURN: 0 with d = digits(amount) public; R_TXM: M), G
   randomness groups of <= 4 legs (leg j in group j / 4, v_f in group 0), A auditor copies on / off. One layout serves
   all (P6-ANON R1); at M = 1, G = 1 it is R_TX's / R_TX0's, at M = 0 R_BURN's:
     s1: 0..31 s_f | 32..63 e_f | 64 + 64 g r_g | 96 + 64 g e1_g | E = 64 + 64 G: e2_j at E + j | e2_f at E + M
         | e2_{a,j} at E + M + 1 + j | bits at E + M + 1 + A M (nbin polys, 853 + 64 M bits)
     bits: d_j at 64 j + 4 i + b | d' at 64 M + 4 i + b | M_i at 64 M + 64 + 14 i + b | c_i + 64 at 64 M + 288 + 11 i
         + b (i < 15) | e_T[i] + 2^24 at 64 M + 453 + 25 i + b */
typedef struct
{
  unsigned legs, groups, aud, burn, txm;
  unsigned E, e2f, bits, nbin, m1;      /* s1 slots (m1 without the Z slack polys) */
  unsigned dp, m, c, e;                 /* bit bases; d_j at 64 j */
  unsigned nblk, bst[NZ], bln[NZ];      /* exact-l2 blocks: s1 slots [bst, bst + bln) */
} shape_t;
#define SLOT(base, w, i, b) ((unsigned)(base) + (w) * (i) + (b))

static void
shape_of (const rel_t *R, shape_t *H)
{
  const unsigned M = R->legs, G = R->op == PQZ_OP_BURN ? 1 : PQZ_TXM_GROUPS (M), A = R->aud;
  unsigned g, z = 0;
  H->legs = M, H->groups = G, H->aud = A, H->burn = R->op == PQZ_OP_BURN, H->txm = R->op == PQZ_OP_TRANSFER_MULTI;
  H->E = 64 + 64 * G, H->e2f = H->E + M, H->bits = H->e2f + 1 + A * M;
  H->nbin = (853 + 64 * M + 63) / 64, H->m1 = H->bits + H->nbin;
  H->dp = 64 * M, H->m = H->dp + 64, H->c = H->dp + 288, H->e = H->dp + 453;
  H->bst[z] = 0, H->bln[z++] = 32;
  H->bst[z] = 32, H->bln[z++] = 32;
  for (g = 0; g < G; g++)
    {
      H->bst[z] = 64 + 64 * g, H->bln[z++] = 32;
      H->bst[z] = 96 + 64 * g, H->bln[z++] = 32;
    }
  /* every e2 vector its own block, bound 64 (pq-zero-knowledge.md §4.3; owner 2026-10-15, X-1: not one 64 sqrt(M) block):
     the legs' e2_j, e2_f, the auditor copies' e2_{a,j}, contiguous from E */
  for (unsigned k = 0; k < M + 1 + A * M; k++)
    H->bst[z] = H->E + k, H->bln[z++] = 1;
  H->nblk = z;
}

/* the shape agrees with the relation's generated parameters (spec file and builder written together) */
static int
shape_ok (const rel_t *R, const shape_t *H)
{
  const lnp_tbox_params_struct *P = R->P;
  int ok = H->nbin == P->nbin && H->nblk == P->Z && H->m1 + P->Z == P->tbox->m1 && H->legs <= MAXL
           && H->groups <= MAXG && K * (1 + H->groups) <= NTXQ && 16 * (H->legs + 1 + H->aud * H->legs + 2) <= NTXE;
  for (unsigned z = 0; ok && z < H->nblk; z++)
    ok &= P->n[z] == H->bln[z];
  return ok;
}

typedef struct
{
  polyvec_ptr pkf, pka, uT;           /* debit */
  polyvec_ptr pk[MAXL], u[MAXG];      /* debit: leg keys, group u; R_DS / R_DR: pk[0] = pk, u[0] = u */
  poly_t vT, vf, v[MAXL], va[MAXL];   /* debit; R_DS / R_DR: v[0] = v */
  uint64_t fee, amount;               /* amount: R_BURN, R_DS, R_DR */
} txst_t;

/* coefficient term coef * bit(slot) into the evaleq vector accumulators (one poly per bit poly) */
static void
add_bit (poly_ptr acc[], unsigned slot, int64_t coef)
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
evaleq (sys_t *S, unsigned idx, polyvec_ptr pkrow, unsigned off_x, unsigned i, int e2idx, poly_ptr acc[],
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
acc_zero (poly_ptr acc[], unsigned n)
{
  for (unsigned b = 0; b < n; b++)
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

/* a be32 statement word that must be < 2^64 (pq-zero-knowledge.md §5: anything else is non-canonical) */
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

/* R_TX: header || pk_f || pk_t || pk_a || u_T || v_T || u || v_t || v_f || v_a; R_TX0: the same without pk_a and
   v_a; R_BURN: header || pk_f || u_T || v_T || u || v_f (pq-zero-knowledge.md §7.7); R_TXM: header || pk_f || pk_0 .. pk_{M-1}
   || [pk_a] || u_T || v_T || u_0 .. u_{G-1} || v_0 .. v_{M-1} || v_f || [v_{a,0} .. v_{a,M-1}] (the same order with
   M legs and G groups). Reads fee, (R_BURN) amount, (the transfers) the auditorOn word and (R_TXM) the M word from
   the header; the rest of it is hashed only. */
static int
parse_debit (txst_t *T, polyring_srcptr Rq, const uint8_t *stmt, const shape_t *H)
{
  const uint8_t *p = stmt + PQZ_HEADER_BYTES;
  const unsigned M = H->legs, A = H->aud;
  uint64_t on = 0, legs = 0;
  unsigned j, g;
  int ok = rd_word64 (&T->fee, stmt + PQZ_HDR_FEE);
  T->amount = 0;
  if (H->burn)
    ok &= rd_word64 (&T->amount, stmt + PQZ_HDR_AMOUNT);
  else /* R6: the word says what the length says, 1 with pk_a and v_a, 0 without */
    {
      ok &= rd_word64 (&on, stmt + PQZ_HDR_AUDITOR_ON); /* two statements: on is read after the call */
      ok &= on == (uint64_t)A;
    }
  if (H->txm) /* R4: the M word names the relation (pqz_verify picked it by the word, so this holds) */
    {
      ok &= rd_word64 (&legs, stmt + PQZ_HDR_LEGS);
      ok &= legs == (uint64_t)M;
    }
  T->pkf = new_vec (Rq), T->uT = new_vec (Rq);
  poly_alloc (T->vT, Rq), poly_alloc (T->vf, Rq);
  ok &= rd_polyvec (T->pkf, p), p += PQZ_POLYVEC_BYTES;
  for (j = 0; j < M; j++)
    {
      T->pk[j] = new_vec (Rq);
      ok &= rd_polyvec (T->pk[j], p), p += PQZ_POLYVEC_BYTES;
    }
  if (A)
    {
      T->pka = new_vec (Rq);
      ok &= rd_polyvec (T->pka, p), p += PQZ_POLYVEC_BYTES;
    }
  ok &= rd_polyvec (T->uT, p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_poly (T->vT, p, 16), p += PQZ_V_BYTES;
  for (g = 0; g < H->groups; g++)
    {
      T->u[g] = new_vec (Rq);
      ok &= rd_polyvec (T->u[g], p), p += PQZ_POLYVEC_BYTES;
    }
  for (j = 0; j < M; j++)
    {
      poly_alloc (T->v[j], Rq);
      ok &= rd_poly (T->v[j], p, 16), p += PQZ_V_BYTES;
    }
  ok &= rd_poly (T->vf, p, 16), p += PQZ_V_BYTES;
  for (j = 0; j < A * M; j++)
    {
      poly_alloc (T->va[j], Rq);
      ok &= rd_poly (T->va[j], p, 16), p += PQZ_V_BYTES;
    }
  return ok;
}

/* The rows of pq-zero-knowledge.md §7.4 with M legs (P6-ANON plan §3): row 1 pk_f = A s_f + e_f; row 2 u_g = A^T r_g + e1_g
   per group; per coefficient i < 16, in this order: row 3 per leg j (pk_j^T r_{g(j)})_i + e2_j,i + Delta d_j,i - v_j,i,
   row 4 (pk_f^T r_0)_i + e2_f,i + Delta d'_i - v_f,i, row 5 per leg (auditor on) the same under pk_a with e2_{a,j},
   row 6 (u_T^T s_f)_i + Delta M_i + (e_T,i + 2^24) - 2^24 - v_T,i, row 7 (over Z, all terms < 2^15) M_i + c_{i-1}
   - d'_i - sum_j d_j,i - f_i - 16 c_i = 0. R_TX is M = 1 with the auditor, R_TX0 without (row 5 skipped); R_BURN is
   M = 0 with Delta d_i (row 4 has none: d' is the witness) and d_i (row 7) public in the constant term. One code
   path for every amount: a decoy is a leg whose digits are 0 (plan R6). */
static int
build_debit (sys_t *S, txst_t *T, const uint8_t *stmt, rel_t *R)
{
  shape_t H;
  polyring_srcptr Rq = R->P->tbox->ring;
  poly_ptr acc[NBIN];
  unsigned i, j, b, g, e = 0;

  shape_of (R, &H);
  if (!shape_ok (R, &H))
    return 0;
  const unsigned M = H.legs, A = H.aud, nbin = H.nbin, m1 = H.m1;
  S->R = R;
  S->N = K * (1 + H.groups);
  S->M = 16 * (M + 1 + A * M + 2);
  S->bits = H.bits;
  S->nbin = nbin;
  if (!parse_debit (T, Rq, stmt, &H))
    return 0;
  for (b = 0; b < nbin; b++)
    acc[b] = new_poly (Rq);

  /* row 1: pk_f = A s_f + e_f ; row 2: u_g = A^T r_g + e1_g */
  for (i = 0; i < K; i++)
    add_lin_row (S, i, 0, i, 0, 32, polyvec_get_elem (T->pkf, i));
  for (g = 0; g < H.groups; g++)
    for (i = 0; i < K; i++)
      add_lin_row (S, K * (1 + g) + i, 1, i, 64 + 64 * g, 96 + 64 * g, polyvec_get_elem (T->u[g], i));

  for (i = 0; i < 16; i++)
    {
      const int64_t dpub = H.burn ? digit (T->amount, i) : 0;
      /* rows 3-5: (pk^T r)_i + e2_i + Delta * digit_i - v_i = 0 */
      for (j = 0; j < M; j++)
        {
          acc_zero (acc, nbin);
          for (b = 0; b < 4; b++)
            add_bit (acc, SLOT (64 * j, 4, i, b), DELTA << b);
          evaleq (S, e++, T->pk[j], 64 + 64 * (j / 4), i, (int)(H.E + j), acc, -cval (T->v[j], i));
        }
      acc_zero (acc, nbin);
      for (b = 0; b < 4; b++)
        add_bit (acc, SLOT (H.dp, 4, i, b), DELTA << b);
      evaleq (S, e++, T->pkf, 64, i, (int)H.e2f, acc, -cval (T->vf, i));
      for (j = 0; j < A * M; j++)
        {
          acc_zero (acc, nbin);
          for (b = 0; b < 4; b++)
            add_bit (acc, SLOT (64 * j, 4, i, b), DELTA << b);
          evaleq (S, e++, T->pka, 64 + 64 * (j / 4), i, (int)(H.e2f + 1 + j), acc, -cval (T->va[j], i));
        }
      /* row 6: (u_T^T s_f)_i + Delta M_i + (e_T,i + 2^24) - 2^24 - v_T,i = 0 */
      acc_zero (acc, nbin);
      for (b = 0; b < 14; b++)
        add_bit (acc, SLOT (H.m, 14, i, b), DELTA << b);
      for (b = 0; b < 25; b++)
        add_bit (acc, SLOT (H.e, 25, i, b), (int64_t)1 << b);
      evaleq (S, e++, T->uT, 0, i, -1, acc, -cval (T->vT, i) - ((int64_t)1 << 24));
      /* row 7 (over Z, all terms < 2^15): M_i + c_{i-1} - d'_i - sum_j d_j,i - f_i - 16 c_i = 0, c = cbits - 64 */
      acc_zero (acc, nbin);
      int64_t rhs = -(int64_t)digit (T->fee, i) - dpub;
      for (b = 0; b < 14; b++)
        add_bit (acc, SLOT (H.m, 14, i, b), (int64_t)1 << b);
      if (i >= 1)
        {
          for (b = 0; b < 11; b++)
            add_bit (acc, SLOT (H.c, 11, i - 1, b), (int64_t)1 << b);
          rhs -= 64;
        }
      for (b = 0; b < 4; b++)
        {
          add_bit (acc, SLOT (H.dp, 4, i, b), -((int64_t)1 << b));
          for (j = 0; j < M; j++)
            add_bit (acc, SLOT (64 * j, 4, i, b), -((int64_t)1 << b));
        }
      if (i <= 14)
        {
          for (b = 0; b < 11; b++)
            add_bit (acc, SLOT (H.c, 11, i, b), -((int64_t)16 << b));
          rhs += 16 * 64;
        }
      evaleq (S, e++, NULL, 0, i, -1, acc, rhs);
    }

  for (unsigned z = 0; z < H.nblk; z++)
    S->Es[z] = new_sel (Rq, H.bln[z], m1, H.bst[z]);
  S->Ps = new_sel (Rq, nbin, m1, H.bits);
  /* e2_0 (the first leg; R_TX, R_TX0: e2_t) / e2_f (R_BURN), |coefficients| <= 20 < 64 (Bprime) */
  S->Ds = new_sel (Rq, 1, m1, H.E);
  return 1;
}

/* ---- R_DS and R_DR (disclosure, pq-zero-knowledge.md §7.9) ---- */

/* opTag || proofSystemId || chainId || chainUid || token || registry || entryRef || amount || kind (32-byte words)
   || pk || u || v; only amount, pk, u, v enter the equations, the rest is hashed */
static int
parse_disc (txst_t *T, polyring_srcptr Rq, const uint8_t *stmt)
{
  const uint8_t *p = stmt + PQZ_DISC_PK;
  int ok = rd_word64 (&T->amount, stmt + PQZ_DISC_AMOUNT);
  T->pk[0] = new_vec (Rq), T->u[0] = new_vec (Rq);
  poly_alloc (T->v[0], Rq);
  ok &= rd_polyvec (T->pk[0], p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_polyvec (T->u[0], p), p += PQZ_POLYVEC_BYTES;
  ok &= rd_poly (T->v[0], p, 16);
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
    add_lin_row (S, i, 1, i, 0, 32, polyvec_get_elem (T->u[0], i));
  for (unsigned i = 0; i < 16; i++)
    evaleq (S, i, T->pk[0], 0, i, 64, NULL, DELTA * digit (T->amount, i) - cval (T->v[0], i));
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
    add_lin_row (S, i, 0, i, 0, 32, polyvec_get_elem (T->pk[0], i));
  for (unsigned i = 0; i < 16; i++)
    {
      acc_zero (acc, 15);
      for (unsigned b = 0; b < 25; b++)
        add_bit (acc, 25 * i + b, (int64_t)1 << b);
      evaleq (S, i, T->u[0], 0, i, -1, acc, DELTA * digit (T->amount, i) - cval (T->v[0], i) - ((int64_t)1 << 24));
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

#ifdef PQZ_TEST_HOOKS
/* Test-only cheating prover (bench txm_check, P6-ANON pre-review L-1; never in libpqz): when set, the debit witness's
   carry / range checks and the l2 slack refusal are skipped (a block over its bound gets upsilon 0), and the proof is
   emitted although LaZer's prover self-checks fail (rc 0 then; a rejection-loop cap still fails). The verifiers
   must reject every such proof of a false witness. */
int pqz_test_cheat;
#define CHEAT pqz_test_cheat
#else
#define CHEAT 0
#endif

#ifdef PQZ_L2DOM_POC
/* Test-only cheating prover (pqz-core/pqzl/l2dom/, never in a production build): when set, pool the l2 slack of all
   Z blocks, sum_z (B_z^2 - ||x_z||^2), and spread it greedily over the upsilon_z (each holds bitlen(B_z^2) bits), so a
   block may exceed its own B_z as long as sum_z ||x_z||^2 <= sum_z B_z^2. Checks whether the verifier enforces each
   exact-l2 equation separately. */
int pqz_l2dom_poc;
#define POC_IGNORE_ERR (pqz_l2dom_poc || CHEAT) /* and emit the proof although the prover's own self-checks fail */
#else
#define POC_IGNORE_ERR CHEAT
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
        {
          if (!CHEAT)
            return 0; /* witness above its norm bound */
          int_set_i64 (d, 0);
        }
      int_binexp (polyvec_get_elem (s1, m1 + z), NULL, d);
    }
  return 1;
}

/* Hedged prover seeds (pq-zero-knowledge.md CTR-PQZ-19; P6e D6): ex[0..32) seeds the commitment randomness s2, ex[32..64)
   every mask of lnp_tbox_prove; each = SHAKE128(tag || rnd32 || wh || hash0) with tag "SCAAS-PQZ-PROVER-RND-V2" /
   "...-SUB-V2" and wh = SHAKE128("SCAAS-PQZ-PROVER-WIT-V2" || wit)[0..32). A repeated or weak rnd32 for two witnesses
   or two statements still gives unrelated masks (V1 hashed rnd32 alone). Not static: the tests check it directly. */
void
pqz_prover_seeds (uint8_t ex[64], const uint8_t rnd32[32], const uint8_t *wit, size_t wit_len,
                  const uint8_t hash0[32])
{
  uint8_t wh[64];
  shake_tag (wh, "SCAAS-PQZ-PROVER-WIT-V2", wit, wit_len, NULL, 0);
  memcpy (wh + 32, hash0, 32);
  shake_tag (ex, "SCAAS-PQZ-PROVER-RND-V2", rnd32, 32, wh, 64);
  shake_tag (ex + 32, "SCAAS-PQZ-PROVER-SUB-V2", rnd32, 32, wh, 64);
  explicit_bzero (wh, sizeof wh);
}

#ifdef PQZ_TEST_HOOKS
uint8_t pqz_test_last_ex[64]; /* the seeds the last do_prove used (test/pqz_sv_diff.c compares them) */
#endif

static int
do_prove (sys_t *S, pf_t *F, const uint8_t hash0[32], const uint8_t *wit, size_t wit_len,
          const uint8_t rnd32[32], uint8_t *proof, size_t *proof_len)
{
  const lnp_tbox_params_struct *P = S->R->P;
  abdlop_params_srcptr tb = P->tbox;
  uint8_t hash[32], ex[64];
  INT_T (lo, 1);
  INT_T (hi, 1);
  uint8_t buf[PQZ_MAX_PROOF + 4096];
  size_t len;

  pqz_prover_seeds (ex, rnd32, wit, wit_len, hash0);
#ifdef PQZ_TEST_HOOKS
  memcpy (pqz_test_last_ex, ex, 64);
#endif
  int_set_i64 (lo, -tb->nu);
  int_set_i64 (hi, tb->nu);
  polyvec_urandom_bnd (F->s2, lo, hi, ex, 0);
  memcpy (hash, hash0, 32);
  abdlop_commit (F->tA1, F->tA2, F->tB, F->s1, F->m, F->s2, S->R->A1, S->R->A2p, S->R->Bp, tb);
  abdlop_hashcomm (hash, F->tA1, F->tB, tb);
  lnp_tbox_prove (hash, F->tB, F->h, F->c, F->z1, F->z21, F->hint, F->z3, F->z4, F->s1, F->m, F->s2, F->tA2,
                  S->R->A1, S->R->A2p, S->R->Bp, S->R2, S->r1, S->N, S->R2p, S->r1p, S->r0p, S->M, S->Es, NULL,
                  NULL, S->Ps, NULL, NULL, S->Ds, NULL, NULL, ex + 32, P);
  explicit_bzero (ex, sizeof ex); /* secret-derived; the arena's witness copies are not zeroed (STATUS Open 8) */
  if (pqz_err && !POC_IGNORE_ERR)
    return pqz_err;
  if (!encproof (buf, sizeof buf, &len, F->tA1, F->tB, F->h, F->c, F->z1, F->z21, F->hint, F->z3, F->z4, P)
      || len > PQZ_MAX_PROOF || len > *proof_len)
    return PQZ_ERR_INPUT;
  memcpy (proof, buf, len);
  *proof_len = len;
  return CHEAT && pqz_err == PQZ_ERR_INTERNAL ? PQZ_OK : pqz_err;
}

static int
do_verify (sys_t *S, pf_t *F, const uint8_t hash0[32], const uint8_t *proof, size_t proof_len)
{
  const lnp_tbox_params_struct *P = S->R->P;
  uint8_t hash[32];
  if (proof_len > PQZ_MAX_PROOF
      || !pqz_decproof (proof_len, proof, F->tA1, F->tB, F->h, F->c, F->z1, F->z21, F->hint, F->z3, F->z4, P))
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

/* debit witness (R_TX, R_TX0, R_BURN, R_TXM; the layout of pqz.h) -> s1 (incl. derived M, carries, e_T); returns 0
   if inconsistent */
static int
debit_witness (txst_t *T, const uint8_t *w, polyvec_t s1, const rel_t *R)
{
  shape_t H;
  /* the relation's own ring object: LaZer asserts operands share the ring pointer */
  polyring_srcptr Rq = R->P->tbox->ring;
  const uint8_t *p = w;
  unsigned i, j, b, g;
  int64_t d[MAXL][16], dp[16], dsum[16], M[16], eT[16], c[16];

  shape_of (R, &H);
  const unsigned L = H.legs, ne2 = L + 1 + H.aud * L;
  p = wit_vec (s1, 0, p, 0);
  p = wit_vec (s1, 32, p, 1);
  for (g = 0; g < H.groups; g++)
    {
      p = wit_vec (s1, 64 + 64 * g, p, 0);
      p = wit_vec (s1, 96 + 64 * g, p, 1);
    }
  for (i = 0; i < ne2; i++)
    for (j = 0; j < 16; j++)
      set_c (polyvec_get_elem (s1, H.E + i), j, rd_le16 (p + 32 * i + 2 * j));
  p += 32 * ne2;
  /* the legs' digits (R_BURN: d = digits(amount), public), d'; one path for every amount (plan R6) */
  for (i = 0; i < 16; i++)
    {
      dsum[i] = H.burn ? digit (T->amount, i) : 0;
      for (j = 0; j < L; j++)
        d[j][i] = p[16 * j + i], dsum[i] += d[j][i];
      dp[i] = p[16 * L + i];
    }

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
  /* carries: c_i = (M_i + c_{i-1} - d'_i - sum_j d_j,i - f_i) / 16, exact, c_15 = 0 (so sum_j a_j + fee <= balance) */
  int64_t cprev = 0;
  for (i = 0; i < 16; i++)
    {
      int64_t s = M[i] + cprev - dp[i] - dsum[i] - (int64_t)digit (T->fee, i);
      if (s % 16 != 0 && !CHEAT)
        return 0;
      c[i] = s / 16;
      cprev = c[i];
    }
  if (c[15] != 0 && !CHEAT)
    return 0;
  /* ranges (the proof shows them; an honest prover checks first) */
  for (i = 0; i < 16; i++)
    {
      int bad = dp[i] > 15 || M[i] < 0 || M[i] >= (1 << 14) || c[i] < -64 || c[i] >= 1984 || eT[i] < -(1 << 24)
                || eT[i] >= (1 << 24);
      for (j = 0; j < L; j++)
        bad |= d[j][i] > 15;
      if (bad && !CHEAT)
        return 0;
    }
  for (i = 0; i < 16; i++)
    for (b = 0; b < 25; b++)
      {
        unsigned base[4] = { H.dp, H.m, H.c, H.e };
        int64_t vals[4] = { dp[i], M[i], c[i] + 64, eT[i] + (1 << 24) };
        unsigned widths[4] = { 4, 14, 11, 25 }, n[4] = { 4, 14, i < 15 ? 11u : 0u, 25 };
        for (unsigned k = 0; k < 4; k++)
          if (b < n[k])
            {
              unsigned slot = SLOT (base[k], widths[k], i, b);
              set_c (polyvec_get_elem (s1, H.bits + slot / 64), slot % 64, (vals[k] >> b) & 1);
            }
        for (j = 0; j < L && b < 4; j++)
          {
            unsigned slot = SLOT (64 * j, 4, i, b);
            set_c (polyvec_get_elem (s1, H.bits + slot / 64), slot % 64, (d[j][i] >> b) & 1);
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
  dec_w (DR.P->tbox->ring, T->u[0], T->v[0], s1, wv);
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

/* the exact statement length of relation R */
static size_t
stmt_bytes (const rel_t *R)
{
  switch (R->code)
    {
    case PQZ_OP_REGISTER:
      return PQZ_REG_STMT_BYTES;
    case PQZ_OP_TRANSFER:
      return PQZ_TX_STMT_BYTES;
    case PQZ_REL_TX0:
      return PQZ_TX0_STMT_BYTES;
    case PQZ_OP_BURN:
      return PQZ_BURN_STMT_BYTES;
    case PQZ_OP_DISCLOSE_SENDER:
    case PQZ_OP_DISCLOSE_RECEIVER:
      return PQZ_DISC_STMT_BYTES;
    }
  return PQZ_TXM_STMT_BYTES (R->legs, R->aud);
}

/* the statement of relation R (its length checked); 0 if the statement is malformed */
static int
build (sys_t *S, txst_t *T, const rel_t *R, const uint8_t *stmt, size_t stmt_len, polyvec_t pk)
{
  if (stmt_len != stmt_bytes (R))
    return 0;
  switch (R->code)
    {
    case PQZ_OP_REGISTER:
      return build_reg (S, stmt, pk);
    case PQZ_OP_TRANSFER:
      return build_debit (S, T, stmt, &TX);
    case PQZ_REL_TX0:
      return build_debit (S, T, stmt, &TX0);
    case PQZ_OP_BURN:
      return build_debit (S, T, stmt, &BURN);
    case PQZ_OP_DISCLOSE_SENDER:
      return build_ds (S, T, stmt);
    case PQZ_OP_DISCLOSE_RECEIVER:
      return build_dr (S, T, stmt);
    }
  if (R->op == PQZ_OP_TRANSFER_MULTI)
    return build_debit (S, T, stmt, (rel_t *)R);
  return 0;
}

/* op 7: the R_TXM shape named by the header's M word and auditorOn word (R4: the length alone does not fix it; the
   builder then requires the length of that shape). NULL without a header, for a non-canonical word or an M that is
   not built. */
static rel_t *
txm_rel (const uint8_t *stmt, size_t stmt_len)
{
  uint64_t m, a;
  if (stmt == NULL || stmt_len < PQZ_HEADER_BYTES)
    return NULL;
  int ok = rd_word64 (&m, stmt + PQZ_HDR_LEGS);
  ok &= rd_word64 (&a, stmt + PQZ_HDR_AUDITOR_ON);
  for (unsigned t = 0; ok && t < NTXM; t++)
    if (TXM[t].legs == m && TXM[t].aud == a)
      return &TXM[t];
  return NULL;
}

/* the relation of op; op 1 is R_TX0 with the 66,560-byte statement, else R_TX; op 7 by its header words. NULL also
   when the statement is not exactly that relation's length: every entry (prove, verify, verify_fast) checks the length
   here, before the keys or tables are built and the statement hashed (review G-3 / H-4, fix A) */
static rel_t *
rel_of (uint8_t op, const uint8_t *stmt, size_t stmt_len)
{
  rel_t *R = NULL;
  switch (op)
    {
    case PQZ_OP_REGISTER:
      R = &REG;
      break;
    case PQZ_OP_TRANSFER:
      R = stmt_len == PQZ_TX0_STMT_BYTES ? &TX0 : &TX;
      break;
    case PQZ_OP_BURN:
      R = &BURN;
      break;
    case PQZ_OP_DISCLOSE_SENDER:
      R = &DS;
      break;
    case PQZ_OP_DISCLOSE_RECEIVER:
      R = &DR;
      break;
    case PQZ_OP_TRANSFER_MULTI:
      R = txm_rel (stmt, stmt_len);
      break;
    }
  return R != NULL && stmt_len == stmt_bytes (R) ? R : NULL;
}

/* witness -> s1 and the l2 slack (upsilon); 0 if the witness is malformed, inconsistent or above a bound */
static int
witness (txst_t *T, const rel_t *R, const uint8_t *wit, size_t wit_len, polyvec_t s1)
{
  static const unsigned st_reg[2] = { 0, 32 }, ln_reg[2] = { 32, 32 };
  static const unsigned st_ds[3] = { 0, 32, 64 }, ln_ds[3] = { 32, 32, 1 };
  const unsigned *st = st_reg, *ln = ln_reg;
  shape_t H;
  switch (R->code)
    {
    case PQZ_OP_REGISTER:
      if (wit_len != PQZ_REG_WIT_BYTES)
        return 0;
      wit_vec (s1, 32, wit_vec (s1, 0, wit, 0), 1);
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
    default: /* the debit relations (R_TX, R_TX0, R_BURN, R_TXM): pqz.h's layout, one l2 slack per block */
      if (R->code != PQZ_OP_TRANSFER && R->code != PQZ_REL_TX0 && R->code != PQZ_OP_BURN
          && R->op != PQZ_OP_TRANSFER_MULTI)
        return 0;
      shape_of (R, &H);
      if (wit_len != (1 + H.groups) * (2048 + 4096) + 32 * (H.legs + 1 + H.aud * H.legs) + 16 * H.legs + 16
          || !debit_witness (T, wit, s1, R))
        return 0;
      st = H.bst, ln = H.bln;
      break;
    }
  return set_upsilon (R->P, s1, st, ln);
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
  rel_t *R = rel_of (op, stmt, stmt_len);

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
  pqz_stmt_hash (h, op, stmt, stmt_len);
  if (op == PQZ_OP_REGISTER)
    polyvec_alloc (pk, REG.P->tbox->ring, K);
  pf_alloc (&F, R->P);
  if (build (&S, &T, R, stmt, stmt_len, pk) && witness (&T, R, wit, wit_len, F.s1))
    rc = do_prove (&S, &F, h, wit, wit_len, rnd32, proof, proof_len);
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
  rel_t *R = rel_of (op, stmt, stmt_len);

  if (!ready || R == NULL || proof_len > PQZ_MAX_PROOF) /* before the keys and the hash (fix A) */
    return 0;
  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  if (rel_keys (R))
    {
      pqz_arena_release (&base);
      return 0;
    }
  memset (&S, 0, sizeof (S));
  pqz_stmt_hash (h, op, stmt, stmt_len);
  if (op == PQZ_OP_REGISTER)
    polyvec_alloc (pk, REG.P->tbox->ring, K);
  pf_alloc (&F, R->P);
  if (build (&S, &T, R, stmt, stmt_len, pk))
    ok = do_verify (&S, &F, h, proof, proof_len);
  if (pqz_err)
    ok = 0;
  pqz_arena_release (&base);
  return ok;
}

#ifdef PQZ_SV
/* the specialised verifier (pqz_sv.c): same statements, same transcript, same accept / reject. Its tables for op are
   built at the first pqz_verify_fast of op, after the relation's ABDLOP keys, and kept below the base mark like
   them; a build without PQZ_SV (SV=0 ./build.sh wasm, the wallet's prover) has neither the code nor the tables */
int
pqz_verify_fast (uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *proof, size_t proof_len)
{
  uint8_t h[32];
  int ok;
  rel_t *R = rel_of (op, stmt, stmt_len);

  if (!ready || R == NULL || proof_len > PQZ_MAX_PROOF) /* before the keys, the tables and the hash (fix A) */
    return 0;
  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  if (rel_keys (R) || pqz_sv_setup (R->code, R->P, A, R->A1, R->A2p, R->Bp))
    {
      pqz_arena_release (&base);
      return 0;
    }
  pqz_arena_mark (&base); /* the tables just built, if any, stay */
  pqz_stmt_hash (h, op, stmt, stmt_len);
  ok = pqz_sv_verify (R->code, h, stmt, stmt_len, proof, proof_len) == 1;
  if (pqz_err)
    ok = 0;
  pqz_arena_release (&base);
  return ok;
}
#endif

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
  if (!ready)
    return PQZ_ERR_INTERNAL; /* before pqz_init: no A */
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
  if (!ready)
    return PQZ_ERR_INTERNAL; /* before pqz_init: no A */
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
  if (!ready)
    return PQZ_ERR_INTERNAL; /* before pqz_init: no A */
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

#ifdef PQZ_TEST_HOOKS
/* ---------------------------------------------------------------- test hook (P6-SV diff harness only; not in
   libpqz): decode a proof, change one field, re-encode. kind / r1 / r2 pick the field and the change. op names the
   relation: an op, PQZ_REL_TX0 (0x81) for R_TX0 or PQZ_REL_TXM (M, A) for an R_TXM shape. Returns 1 and the new proof in out, or 0 if the input does not
   decode. */
static void
mut_swap (poly_ptr a, poly_ptr b)
{
  for (unsigned j = 0; j < PQZ_D; j++)
    {
      int64_t t = cval (a, j);
      set_c (a, j, cval (b, j));
      set_c (b, j, t);
    }
}

static rel_t *
rel_by_code (uint8_t code)
{
  rel_t *all[] = { &REG, &TX, &TX0, &BURN, &DS, &DR };
  for (unsigned t = 0; t < sizeof all / sizeof all[0]; t++)
    if (all[t]->code == code)
      return all[t];
  for (unsigned t = 0; t < NTXM; t++)
    if (TXM[t].code == code)
      return &TXM[t];
  return NULL;
}

int
pqz_test_mutate (uint8_t op, const uint8_t *proof, size_t len, unsigned kind, uint64_t r1, uint64_t r2,
                 uint8_t *out, size_t *outlen)
{
  rel_t *R = rel_by_code (op);
  const lnp_tbox_params_struct *P = R != NULL ? R->P : REG.P;
  abdlop_params_srcptr tb = P->tbox;
  static uint8_t buf[2 * PQZ_MAX_PROOF];
  pf_t F;
  size_t n;
  int ok = 0;

  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  pf_alloc (&F, P);
  if (R == NULL || len > PQZ_MAX_PROOF
      || !pqz_decproof (len, proof, F.tA1, F.tB, F.h, F.c, F.z1, F.z21, F.hint, F.z3, F.z4, P))
    goto done;
  polyvec_mod (F.h, F.h), polyvec_redc (F.h, F.h);
  poly_mod (F.c, F.c), poly_redc (F.c, F.c);
  polyvec_mod (F.z1, F.z1), polyvec_redc (F.z1, F.z1);
  polyvec_mod (F.z21, F.z21), polyvec_redc (F.z21, F.z21);
  polyvec_mod (F.z3, F.z3), polyvec_redc (F.z3, F.z3);
  polyvec_mod (F.z4, F.z4), polyvec_redc (F.z4, F.z4);
  const unsigned m1 = tb->m1, m2r = tb->m2 - tb->kmsis, km = tb->kmsis, c64 = (unsigned)(r2 % PQZ_D);
  const int64_t sg = (r2 >> 8) & 1 ? 1 : -1;
  poly_ptr p;
  switch (kind)
    {
    case 0: /* swap two z1 polys */
      mut_swap (polyvec_get_elem (F.z1, r1 % m1), polyvec_get_elem (F.z1, (r1 / m1 + 1 + r1 % m1) % m1));
      break;
    case 1: /* swap two z21 polys */
      mut_swap (polyvec_get_elem (F.z21, r1 % m2r), polyvec_get_elem (F.z21, (r1 / m2r + 1 + r1 % m2r) % m2r));
      break;
    case 2: /* swap a z3 poly with a z4 poly */
      mut_swap (polyvec_get_elem (F.z3, r1 % 4), polyvec_get_elem (F.z4, (r1 >> 8) % 4));
      break;
    case 3: /* z1 coefficient +-1 */
      p = polyvec_get_elem (F.z1, r1 % m1), set_c (p, c64, cval (p, c64) + sg);
      break;
    case 4: /* z1 coefficient large (norm) */
      p = polyvec_get_elem (F.z1, r1 % m1), set_c (p, c64, sg * (((int64_t)1 << 25) + (int64_t)(r1 % 1000)));
      break;
    case 5: /* z4 coefficient at / over the l_inf bound */
      p = polyvec_get_elem (F.z4, r1 % 4), set_c (p, c64, sg * (int_get_i64 (P->Bz4) + (int64_t)(r1 >> 8) % 2));
      break;
    case 6: /* z3 coefficient large (norm) */
      p = polyvec_get_elem (F.z3, r1 % 4), set_c (p, c64, cval (p, c64) + sg * ((int64_t)1 << 20));
      break;
    case 7: /* h: coefficient 0 / d/2 nonzero, or another coefficient changed */
      p = polyvec_get_elem (F.h, r1 % 2);
      set_c (p, r1 & 4 ? 0 : (r1 & 8 ? PQZ_D / 2 : c64), cval (p, r1 & 4 ? 0 : (r1 & 8 ? PQZ_D / 2 : c64)) + sg);
      break;
    case 8: /* hint coefficient +-1..1000 (|hint| = m would need 2m bits, more than PQZ_MAX_PROOF) */
      p = polyvec_get_elem (F.hint, r1 % km), set_c (p, c64, cval (p, c64) + sg * (1 + (int64_t)(r1 >> 9) % 1000));
      break;
    case 9: /* c: one coefficient to another value in [-8, 8] */
      p = F.c, set_c (p, c64, (cval (p, c64) + 8 + 1 + (int64_t)(r1 % 16)) % 17 - 8);
      break;
    case 10: /* tB coefficient */
      p = polyvec_get_elem (F.tB, r1 % (tb->l + tb->lext)), set_c (p, c64, (int64_t)(r1 % PQZ_Q));
      break;
    case 11: /* tA1 coefficient */
      p = polyvec_get_elem (F.tA1, r1 % km);
      set_c (p, c64, (int64_t)((r1 >> 8) % ((uint64_t)1 << (42 - P->quad_eval->quad_many->dcompress->D))));
      break;
    case 12: /* z21 coefficient +-1 */
      p = polyvec_get_elem (F.z21, r1 % m2r), set_c (p, c64, cval (p, c64) + sg);
      break;
    case 13: /* swap the two h polys */
      mut_swap (polyvec_get_elem (F.h, 0), polyvec_get_elem (F.h, 1));
      break;
    case 14: /* z3 coefficient +-1 (not clamped: a coefficient at Bz3 leaves it; the P6-FS binding test, sz/fs_bind.c; not in the fuzzers' % 14) */
      p = polyvec_get_elem (F.z3, r1 % 4), set_c (p, c64, cval (p, c64) + sg);
      break;
    default: /* re-encode only */
      break;
    }
  if (encproof (buf, sizeof buf, &n, F.tA1, F.tB, F.h, F.c, F.z1, F.z21, F.hint, F.z3, F.z4, P) && pqz_err == PQZ_OK
      && n <= *outlen)
    {
      memcpy (out, buf, n);
      *outlen = n;
      ok = 1;
    }
done:
  pqz_err = PQZ_OK;
  pqz_arena_release (&base);
  return ok;
}
#endif
