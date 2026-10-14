/*
 * pqz-core specialised verifier for R_REG, R_TX, R_TX0, R_BURN, R_DS, R_DR (spike P6-SV,
 * docs/research/pqz-specialised-verifier.md).
 *
 * pqz_verify_fast accepts exactly the proofs pqz_verify accepts: the same decoder, the same Fiat-Shamir transcript
 * (statement digest, commitments, z3 / z4 round, tg round, the final t || v || w1 round), the same challenges and
 * the same checks. What differs is how the verifier's polynomial v is computed. lnp_tbox_verify builds every
 * equation as a sparse quadratic form over the 2 (m1 + l) interleaved witness slots (s, o(s)), folds them with
 * the Schwartz-Zippel challenges into accumulators, applies the automorphism step, folds again with mu and then
 * evaluates z^T R2 z + c r1^T z + c^2 r0 - f once. All of that is linear, so v is the same element of R_q when
 * every equation is evaluated on z directly and combined with the same scalars; that is what this file does.
 * The selection matrices of the statement are identity blocks, so e.g. the exact l2 term is
 * sum o(z_i) z_i over the 32 selected polynomials instead of a 146 x 146 Gram matrix.
 *
 * Ring products: complete negacyclic NTT of degree 64 over NP = 4 NTT-friendly 30-bit primes (product P ~ 2^120),
 * Montgomery form throughout. An integer polynomial is held exactly while its coefficients stay below P/2 in
 * absolute value; it is then CRT-reconstructed and reduced mod q (red ()). Inputs enter as integers below 2^42
 * (values mod q) or as small integers (c, c^2, X^32, the all-ones polynomial); the largest sum formed below is
 * < 2^106 (bounds next to each sum), so no input, honest or adversarial, can overflow it.
 *
 * PRG: LaZer's AES-256-CTR (rng.c: key = seed, nonce = le64(dom) || 0^8, 128-bit big-endian counter). The streams
 * here are public (derived from the transcript), so a table-based AES is used; the prover keeps the bitsliced one.
 *
 * No malloc, no float, no abort: working memory comes from the arena (released by the caller), every failed
 * invariant is an error return.
 */
#include "lazer.h"
#include "memory.h"

#include "pqz.h"
#include "pqz_int.h"

#define NP 4
#define DEG 64
#define LAMBDA 4
#define NQL 11  /* quad_many l: y3 (4), y4 (4), beta, g (2) */
#define NQEL 9  /* quad_eval l: y3, y4, beta */
#define NPK 32  /* K: polys per public key / ciphertext vector */
#define JLR 256 /* JL rows */
#define M30 ((((uint32_t)1) << 30) - 1)
#define M42 ((((uint64_t)1) << 42) - 1)
#define M21 ((((uint64_t)1) << 21) - 1)
#define Q PQZ_Q

typedef struct
{
  uint32_t c[NP][DEG]; /* NTT domain, Montgomery form, entries in [0, 2p) */
} nt_t;
typedef struct
{
  uint64_t c[NP][DEG]; /* lazy sum of fewer than 2^31 terms in [0, 2p) */
} acc_t;

typedef struct
{
  uint32_t p, pinv;    /* pinv = -p^-1 mod 2^32 */
  uint32_t R2;         /* 2^64 mod p */
  uint32_t F1, F2;     /* 64^-1 and 64^-1 2^32 mod p: inverse-NTT scale for Montgomery / plain inputs */
  uint32_t delta;      /* 2^30 - p */
  uint64_t K;          /* a multiple of p >= 2^42 (lifts signed inputs) */
  uint32_t G[NP];      /* Garner: p_j^-1 2^32 mod p, j < this prime's index */
  uint32_t zetas[DEG]; /* psi^brv(k) 2^32 mod p, psi a primitive 128th root of unity */
  uint8_t perm[DEG];   /* automorphism X -> X^-1 in the NTT domain: o(a)[s] = a[perm[s]] */
} prime_t;

static prime_t PR[NP];
static uint64_t MQ[NP], PQ; /* p_0 ... p_{i-1} mod q, P mod q */
static uint32_t HD[NP];     /* mixed-radix digits of (P - 1) / 2 */
static nt_t NJ;             /* the all-ones polynomial */
static uint32_t TE[4][256]; /* AES round tables */
static uint8_t SB[256];

/* ---------------------------------------------------------------- arithmetic mod q (values in [0, q)) */

static inline uint64_t
addq (uint64_t a, uint64_t b)
{
  return pqz_csubq (a + b);
}
static inline uint64_t
subq (uint64_t a, uint64_t b)
{
  return pqz_csubq (a + Q - b);
}
static inline uint64_t
negq (uint64_t a)
{
  return pqz_csubq (Q - a);
}
/* a, b < 2^42: 21-bit limbs, 64-bit products only (wasm32 has no 64 x 64 -> 128) */
static inline uint64_t
mulq (uint64_t a, uint64_t b)
{
  uint64_t a0 = a & M21, a1 = a >> 21, b0 = b & M21, b1 = b >> 21;
  uint64_t l = a0 * b0, m = a0 * b1 + a1 * b0, h = a1 * b1;
  uint64_t x = (l & M42) + ((m & M21) << 21) + 215 * ((l >> 42) + (m >> 21) + h); /* < 2^51 */
  x = (x >> 42) * 215 + (x & M42);
  return pqz_csubq (x);
}
/* -q 2^20 <= x < 2^62 -> [0, q). q 2^20 = 2^62 - 215 2^20, so x + q 2^20 lies in [0, 2^63); below -q 2^20 the
   result would be wrong. Every caller passes |x| < 2^51 (JL fold < 256 q, statement and proof values < q, bit
   coefficients < 2^40). */
static inline uint64_t
modq (int64_t x)
{
  uint64_t u = (uint64_t)(x + ((int64_t)Q << 20)); /* in [0, 2^63) by the precondition */
  u = (u & M42) + 215 * (u >> 42);                  /* < 2^42 + 2^31 */
  u = (u & M42) + 215 * (u >> 42);
  return pqz_csubq (u);
}
static inline int64_t
centre (uint64_t a) /* [0, q) -> (-q/2, q/2] */
{
  return a > (Q - 1) / 2 ? (int64_t)a - (int64_t)Q : (int64_t)a;
}

/* coefficient-domain polynomials mod q */
static void
cp_auto (int64_t r[DEG], const int64_t a[DEG]) /* r = o(a) = a(X^-1), r != a */
{
  r[0] = a[0];
  r[DEG / 2] = negq (a[DEG / 2]);
  for (unsigned i = 1; i < DEG / 2; i++)
    r[i] = negq (a[DEG - i]), r[DEG - i] = negq (a[i]);
}
static void
cp_mulx (int64_t r[DEG], const int64_t a[DEG], unsigned n) /* r = X^n a, n < 64, r != a */
{
  for (unsigned i = 0; i < DEG; i++)
    r[(i + n) % DEG] = i + n < DEG ? a[i] : negq (a[i]);
}

/* ---------------------------------------------------------------- CRT / NTT over NP primes */

static inline uint32_t
mred (uint64_t t, const prime_t *P) /* t < p 2^32 -> t 2^-32 mod p, in [0, 2p) */
{
  uint32_t m = (uint32_t)t * P->pinv;
  return (uint32_t)((t + (uint64_t)m * P->p) >> 32);
}
static inline uint32_t
mmul (uint32_t a, uint32_t b, const prime_t *P) /* a b < p 2^32 */
{
  return mred ((uint64_t)a * b, P);
}
static inline uint32_t
csub (uint32_t x, uint32_t m) /* x < 2m < 2^32 -> x mod m */
{
  uint32_t t = x - m;
  return t + (m & -(t >> 31));
}
/* |x| < 2^42 -> x 2^32 mod p in [0, 2p) */
static inline uint32_t
lift (int64_t x, const prime_t *P)
{
  uint64_t u = (uint64_t)(x + (int64_t)P->K); /* < 2^44 */
  u = (u & M30) + (u >> 30) * P->delta;       /* < 2^30 + 2^14 delta < 2^31 */
  u = (u & M30) + (u >> 30) * P->delta;
  return mmul ((uint32_t)u, P->R2, P);
}

static uint64_t
powm (uint64_t b, uint64_t e, uint64_t m) /* init only, m < 2^32 */
{
  uint64_t r = 1;
  b %= m;
  for (; e; e >>= 1, b = b * b % m)
    if (e & 1)
      r = r * b % m;
  return r;
}
static int
isprime (uint32_t n)
{
  for (uint32_t d = 2; d * d <= n; d++)
    if (n % d == 0)
      return 0;
  return n > 1;
}
static unsigned
brv6 (unsigned x)
{
  unsigned r = 0;
  for (int b = 0; b < 6; b++)
    r |= ((x >> b) & 1) << (5 - b);
  return r;
}

static void
ntt_fwd (uint32_t a[DEG], const prime_t *P) /* in, out in [0, 2p) */
{
  const uint32_t p2 = 2 * P->p;
  unsigned k = 1;
  for (unsigned len = 32; len >= 1; len >>= 1)
    for (unsigned s = 0; s < DEG; s += 2 * len)
      {
        const uint32_t z = P->zetas[k++];
        for (unsigned j = s; j < s + len; j++)
          {
            uint32_t t = mmul (z, a[j + len], P), x = a[j];
            a[j + len] = csub (x + p2 - t, p2);
            a[j] = csub (x + t, p2);
          }
      }
}
static void
ntt_inv (uint32_t a[DEG], const prime_t *P, uint32_t F) /* in [0, 2p) -> F 64 a 2^-32 ... in [0, p) */
{
  const uint32_t p2 = 2 * P->p;
  unsigned k = DEG;
  for (unsigned len = 1; len < DEG; len <<= 1)
    for (unsigned s = 0; s < DEG; s += 2 * len)
      {
        const uint32_t z = P->p - P->zetas[--k];
        for (unsigned j = s; j < s + len; j++)
          {
            uint32_t x = a[j], y = a[j + len];
            a[j] = csub (x + y, p2);
            a[j + len] = mmul (z, x + p2 - y, P);
          }
      }
  for (unsigned j = 0; j < DEG; j++)
    a[j] = csub (mmul (a[j], F, P), P->p);
}

static void
fwd (nt_t *r, const int64_t a[DEG]) /* |a_j| < 2^42 */
{
  for (int i = 0; i < NP; i++)
    {
      const prime_t *P = &PR[i];
      for (int j = 0; j < DEG; j++)
        r->c[i][j] = lift (a[j], P);
      ntt_fwd (r->c[i], P);
    }
}

/* residues in [0, p_i) of an integer polynomial with |coefficients| < P/2 -> coefficients mod q in [0, q) */
static void
crt (int64_t r[DEG], uint32_t x[NP][DEG])
{
  for (int j = 0; j < DEG; j++)
    {
      uint32_t a[NP];
      for (int i = 0; i < NP; i++)
        {
          const prime_t *P = &PR[i];
          uint32_t y = x[i][j];
          for (int k = 0; k < i; k++) /* Garner: a_i = ((x_i - a_0) / p_0 - a_1) / p_1 ... mod p_i */
            y = mmul (y + 2 * P->p - a[k], P->G[k], P);
          a[i] = csub (y, P->p);
        }
      int neg = 0, decided = 0; /* x > (P - 1) / 2: the integer is x - P */
      for (int i = NP - 1; i >= 0 && !decided; i--)
        if (a[i] != HD[i])
          neg = a[i] > HD[i], decided = 1;
      uint64_t v = 0;
      for (int i = 0; i < NP; i++)
        v = addq (v, mulq (a[i], MQ[i]));
      r[j] = (int64_t)(neg ? subq (v, PQ) : v);
    }
}

static void
red_nt (int64_t r[DEG], const nt_t *a) /* Montgomery form -> coefficients mod q */
{
  uint32_t x[NP][DEG];
  for (int i = 0; i < NP; i++)
    {
      memcpy (x[i], a->c[i], sizeof x[i]);
      ntt_inv (x[i], &PR[i], PR[i].F1);
    }
  crt (r, x);
}
static void
red (int64_t r[DEG], const acc_t *a) /* accumulator -> coefficients mod q */
{
  uint32_t x[NP][DEG];
  for (int i = 0; i < NP; i++)
    {
      for (int j = 0; j < DEG; j++)
        x[i][j] = mred (a->c[i][j], &PR[i]); /* plain form, [0, 2p) */
      ntt_inv (x[i], &PR[i], PR[i].F2);
    }
  crt (r, x);
}
static void
acc_nt (nt_t *r, const acc_t *a) /* accumulator -> Montgomery form, same integer polynomial */
{
  for (int i = 0; i < NP; i++)
    for (int j = 0; j < DEG; j++)
      r->c[i][j] = mmul (mred (a->c[i][j], &PR[i]), PR[i].R2, &PR[i]);
}

static inline void
nt_mul (nt_t *r, const nt_t *a, const nt_t *b)
{
  for (int i = 0; i < NP; i++)
    for (int j = 0; j < DEG; j++)
      r->c[i][j] = mmul (a->c[i][j], b->c[i][j], &PR[i]);
}
static inline void
nt_add (nt_t *r, const nt_t *a, const nt_t *b)
{
  for (int i = 0; i < NP; i++)
    for (int j = 0; j < DEG; j++)
      r->c[i][j] = csub (a->c[i][j] + b->c[i][j], 2 * PR[i].p);
}
static inline void
nt_sub (nt_t *r, const nt_t *a, const nt_t *b)
{
  for (int i = 0; i < NP; i++)
    for (int j = 0; j < DEG; j++)
      r->c[i][j] = csub (a->c[i][j] + 2 * PR[i].p - b->c[i][j], 2 * PR[i].p);
}
static inline void
nt_auto (nt_t *r, const nt_t *a) /* r = o(a), r != a */
{
  for (int i = 0; i < NP; i++)
    for (int j = 0; j < DEG; j++)
      r->c[i][j] = a->c[i][PR[i].perm[j]];
}
static inline void
acc_mul (acc_t *r, const nt_t *a, const nt_t *b) /* r += a b */
{
  for (int i = 0; i < NP; i++)
    {
      const prime_t *P = &PR[i];
      for (int j = 0; j < DEG; j++)
        r->c[i][j] += mmul (a->c[i][j], b->c[i][j], P);
    }
}
static inline void
acc_mulsub (acc_t *r, const nt_t *a, const nt_t *b) /* r -= a b */
{
  for (int i = 0; i < NP; i++)
    {
      const prime_t *P = &PR[i];
      for (int j = 0; j < DEG; j++)
        r->c[i][j] += 2 * P->p - mmul (a->c[i][j], b->c[i][j], P);
    }
}
static inline void
acc_add (acc_t *r, const nt_t *a)
{
  for (int i = 0; i < NP; i++)
    for (int j = 0; j < DEG; j++)
      r->c[i][j] += a->c[i][j];
}
static inline void
acc_sub (acc_t *r, const nt_t *a)
{
  for (int i = 0; i < NP; i++)
    for (int j = 0; j < DEG; j++)
      r->c[i][j] += 2 * PR[i].p - a->c[i][j];
}
static inline void
acc_scal (acc_t *r, const nt_t *a, uint64_t s, int sub) /* r += / -= s a, s < 2^42 */
{
  for (int i = 0; i < NP; i++)
    {
      const prime_t *P = &PR[i];
      const uint32_t sm = lift ((int64_t)s, P);
      for (int j = 0; j < DEG; j++)
        {
          uint32_t t = mmul (a->c[i][j], sm, P);
          r->c[i][j] += sub ? 2 * P->p - t : t;
        }
    }
}
static void
fwd_small (nt_t *r, int64_t c0, int64_t ck, unsigned k) /* NTT of c0 + ck X^k */
{
  int64_t a[DEG] = { 0 };
  a[0] += c0;
  a[k] += ck;
  fwd (r, a);
}

static int
primes_init (void)
{
  uint32_t p = (1u << 30) - 127; /* = 1 mod 128 */
  for (int n = 0; n < NP; p -= 128)
    {
      if (!isprime (p))
        continue;
      prime_t *P = &PR[n];
      P->p = p;
      uint32_t x = p; /* Newton: p^-1 mod 2^32 */
      for (int i = 0; i < 5; i++)
        x *= 2 - p * x;
      P->pinv = -x;
      P->delta = (1u << 30) - p;
      if (P->delta >= (1u << 16))
        return 0;
      P->K = (((uint64_t)1 << 42) / p + 1) * p;
      uint64_t R = ((uint64_t)1 << 32) % p, psi = 0;
      for (uint64_t g = 2;; g++)
        {
          psi = powm (g, (p - 1) / 128, p);
          if (powm (psi, 64, p) == p - 1)
            break;
        }
      for (unsigned k = 0; k < DEG; k++)
        P->zetas[k] = (uint32_t)(powm (psi, brv6 (k), p) * R % p);
      P->R2 = (uint32_t)(R * R % p);
      P->F1 = (uint32_t)powm (64, p - 2, p);
      P->F2 = (uint32_t)(P->F1 * R % p);
      for (int k = 0; k < n; k++)
        P->G[k] = (uint32_t)(powm (PR[k].p, p - 2, p) * R % p);
      n++;
    }
  /* automorphism as a permutation of the evaluation points: NTT(X) holds the points, NTT(-X^63) their inverses */
  for (int i = 0; i < NP; i++)
    {
      const prime_t *P = &PR[i];
      uint32_t x[DEG] = { 0 }, y[DEG] = { 0 };
      x[1] = mmul (1, P->R2, P);
      y[DEG - 1] = mmul (P->p - 1, P->R2, P);
      ntt_fwd (x, P), ntt_fwd (y, P);
      for (int s = 0; s < DEG; s++)
        {
          int t = 0;
          while (t < DEG && csub (x[t], P->p) != csub (y[s], P->p))
            t++;
          if (t == DEG)
            return 0;
          PR[i].perm[s] = (uint8_t)t;
        }
    }
  /* mod-q images of the mixed-radix weights, P mod q, (P - 1) / 2 in mixed radix */
  MQ[0] = 1;
  for (int i = 1; i < NP; i++)
    MQ[i] = mulq (MQ[i - 1], PR[i - 1].p);
  PQ = mulq (MQ[NP - 1], PR[NP - 1].p);
  uint64_t carry = 0;
  for (int i = NP - 1; i >= 0; i--)
    {
      uint64_t v = carry * PR[i].p + (PR[i].p - 1); /* digits of P - 1 are p_i - 1 */
      HD[i] = (uint32_t)(v / 2), carry = v % 2;
    }
  int64_t ones[DEG];
  for (int j = 0; j < DEG; j++)
    ones[j] = 1;
  fwd (&NJ, ones);
  /* self-check: (1 + X)(1 - X^63) = 1 + X^64 - X^63 + X  ... negacyclic: = 2 + X - X^63, through every step */
  {
    nt_t a, b, c;
    int64_t r[DEG];
    fwd_small (&a, 1, 1, 1);
    fwd_small (&b, 1, -1, DEG - 1);
    nt_mul (&c, &a, &b);
    red_nt (r, &c);
    for (int j = 0; j < DEG; j++)
      if ((uint64_t)r[j] != (j == 0 ? 2 : j == 1 ? 1 : j == DEG - 1 ? Q - 1 : 0))
        return 0;
    nt_auto (&c, &a); /* o(1 + X) = 1 - X^63 */
    red_nt (r, &c);
    for (int j = 0; j < DEG; j++)
      if ((uint64_t)r[j] != (j == 0 ? 1 : j == DEG - 1 ? Q - 1 : 0))
        return 0;
  }
  return 1;
}

/* ---------------------------------------------------------------- AES-256-CTR, LaZer's PRG (rng.c) */

static uint8_t
xt (uint8_t a)
{
  return (uint8_t)((a << 1) ^ (0x1b & -(a >> 7)));
}
static uint8_t
rotl8 (uint8_t x, int s)
{
  return (uint8_t)((x << s) | (x >> (8 - s)));
}
static void
aes_tables (void)
{
  uint8_t p = 1, q = 1;
  do /* p runs over GF(2^8)* by x 3, q = p^-1 */
    {
      p = (uint8_t)(p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0));
      q ^= (uint8_t)(q << 1);
      q ^= (uint8_t)(q << 2);
      q ^= (uint8_t)(q << 4);
      if (q & 0x80)
        q ^= 0x09;
      SB[p] = (uint8_t)(q ^ rotl8 (q, 1) ^ rotl8 (q, 2) ^ rotl8 (q, 3) ^ rotl8 (q, 4) ^ 0x63);
    }
  while (p != 1);
  SB[0] = 0x63;
  for (int x = 0; x < 256; x++)
    {
      uint32_t s = SB[x], s2 = xt ((uint8_t)s), s3 = s2 ^ s;
      uint32_t w = s2 | (s << 8) | (s << 16) | (s3 << 24); /* column bytes = rows 0..3, little-endian */
      TE[0][x] = w;
      TE[1][x] = (w << 8) | (w >> 24);
      TE[2][x] = (w << 16) | (w >> 16);
      TE[3][x] = (w << 24) | (w >> 8);
    }
}

typedef struct
{
  uint32_t rk[60];
} prg_t; /* an expanded seed */

static inline uint32_t
ld32 (const uint8_t *b)
{
  return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static inline void
st32 (uint8_t *b, uint32_t w)
{
  b[0] = (uint8_t)w, b[1] = (uint8_t)(w >> 8), b[2] = (uint8_t)(w >> 16), b[3] = (uint8_t)(w >> 24);
}
static inline uint32_t
subw (uint32_t w)
{
  return SB[w & 255] | (SB[(w >> 8) & 255] << 8) | (SB[(w >> 16) & 255] << 16) | ((uint32_t)SB[w >> 24] << 24);
}
static void
prg_seed (prg_t *g, const uint8_t seed[32])
{
  uint8_t rcon = 1;
  for (int i = 0; i < 8; i++)
    g->rk[i] = ld32 (seed + 4 * i);
  for (int i = 8; i < 60; i++)
    {
      uint32_t t = g->rk[i - 1];
      if (i % 8 == 0)
        t = subw ((t >> 8) | (t << 24)) ^ rcon, rcon = xt (rcon);
      else if (i % 8 == 4)
        t = subw (t);
      g->rk[i] = g->rk[i - 8] ^ t;
    }
}
static void
aes_enc (const uint32_t *rk, const uint8_t in[16], uint8_t out[16])
{
  uint32_t s0 = ld32 (in) ^ rk[0], s1 = ld32 (in + 4) ^ rk[1], s2 = ld32 (in + 8) ^ rk[2],
           s3 = ld32 (in + 12) ^ rk[3];
  for (int r = 1; r < 14; r++)
    {
      const uint32_t *k = rk + 4 * r;
      uint32_t t0 = TE[0][s0 & 255] ^ TE[1][(s1 >> 8) & 255] ^ TE[2][(s2 >> 16) & 255] ^ TE[3][s3 >> 24] ^ k[0];
      uint32_t t1 = TE[0][s1 & 255] ^ TE[1][(s2 >> 8) & 255] ^ TE[2][(s3 >> 16) & 255] ^ TE[3][s0 >> 24] ^ k[1];
      uint32_t t2 = TE[0][s2 & 255] ^ TE[1][(s3 >> 8) & 255] ^ TE[2][(s0 >> 16) & 255] ^ TE[3][s1 >> 24] ^ k[2];
      uint32_t t3 = TE[0][s3 & 255] ^ TE[1][(s0 >> 8) & 255] ^ TE[2][(s1 >> 16) & 255] ^ TE[3][s2 >> 24] ^ k[3];
      s0 = t0, s1 = t1, s2 = t2, s3 = t3;
    }
#define LASTB(a, b, c, d)                                                                                    \
  (SB[(a) & 255] | (SB[((b) >> 8) & 255] << 8) | (SB[((c) >> 16) & 255] << 16) | ((uint32_t)SB[(d) >> 24] << 24))
  st32 (out, LASTB (s0, s1, s2, s3) ^ rk[56]);
  st32 (out + 4, LASTB (s1, s2, s3, s0) ^ rk[57]);
  st32 (out + 8, LASTB (s2, s3, s0, s1) ^ rk[58]);
  st32 (out + 12, LASTB (s3, s0, s1, s2) ^ rk[59]);
#undef LASTB
}

typedef struct
{
  const prg_t *g;
  uint8_t ctr[16], ks[16];
  unsigned used;
} ctr_t;

static void
ctr_init (ctr_t *s, const prg_t *g, uint64_t dom)
{
  s->g = g;
  for (int b = 0; b < 8; b++)
    s->ctr[b] = (uint8_t)(dom >> (8 * b)), s->ctr[8 + b] = 0;
  s->used = 16;
}
static inline void
ctr_inc (uint8_t ctr[16])
{
  for (int i = 15; i >= 0 && ++ctr[i] == 0; i--)
    ;
}
static inline void
ctr_block (ctr_t *s, uint8_t out[16])
{
  aes_enc (s->g->rk, s->ctr, out);
  ctr_inc (s->ctr);
}

#ifdef __AES__
/* optional native backend (build.sh native-x86v3): AES-NI, 8 blocks in flight; same stream. The round keys of
   prg_seed are the FIPS-197 key schedule bytes in order (little-endian words), which is AES-NI's layout. */
#include <immintrin.h>
static size_t
ctr_bulk (ctr_t *s, uint8_t *out, size_t nblk)
{
  __m128i k[15];
  for (int r = 0; r < 15; r++)
    k[r] = _mm_loadu_si128 ((const __m128i *)(s->g->rk + 4 * r));
  size_t done = 0;
  for (; done + 8 <= nblk; done += 8)
    {
      __m128i x[8];
      for (int b = 0; b < 8; b++)
        x[b] = _mm_xor_si128 (_mm_loadu_si128 ((const __m128i *)s->ctr), k[0]), ctr_inc (s->ctr);
      for (int r = 1; r < 14; r++)
        for (int b = 0; b < 8; b++)
          x[b] = _mm_aesenc_si128 (x[b], k[r]);
      for (int b = 0; b < 8; b++)
        _mm_storeu_si128 ((__m128i *)(out + 16 * (done + b)), _mm_aesenclast_si128 (x[b], k[14]));
    }
  return done;
}
#else
static size_t
ctr_bulk (ctr_t *s, uint8_t *out, size_t nblk)
{
  (void)s, (void)out, (void)nblk;
  return 0;
}
#endif
static void
ctr_read (ctr_t *s, uint8_t *out, size_t n)
{
  while (n > 0)
    {
      if (s->used == 16)
        {
          size_t nb = ctr_bulk (s, out, n / 16);
          out += 16 * nb, n -= 16 * nb;
          if (n >= 16)
            {
              ctr_block (s, out);
              out += 16, n -= 16;
              continue;
            }
          ctr_block (s, s->ks);
          s->used = 0;
        }
      size_t k = 16 - s->used < n ? 16 - s->used : n;
      memcpy (out, s->ks + s->used, k);
      s->used += (unsigned)k, out += k, n -= k;
    }
}

#define URND_MAX 320 /* values per urandom call (mu polys: 64, V rows: 256, challenge batches: <= 4 M) */
/* LaZer urandom.c _urandom_i64: n values uniform in [0, mod) by rejection, log2mod-bit fields LSB first; a batch
   that rejects draws the missing values from the next bytes of the stream */
static int
urandom (uint64_t *v, unsigned n, uint64_t mod, unsigned log2mod, const prg_t *g, uint64_t dom)
{
  uint8_t out[(42 * URND_MAX + 7) / 8 + 8];
  const uint64_t mask = (((uint64_t)1) << log2mod) - 1;
  ctr_t s;
  unsigned k = 0;
  if (n > URND_MAX || log2mod > 42)
    return 0;
  ctr_init (&s, g, dom);
  while (k < n)
    {
      const unsigned l = n - k;
      const size_t outlen = (log2mod * l + 7) / 8;
      ctr_read (&s, out, outlen);
      memset (out + outlen, 0, 8);
      for (unsigned i = 0; i < l; i++)
        {
          const size_t bit = (size_t)i * log2mod;
          uint64_t w = 0;
          for (int b = 7; b >= 0; b--)
            w = (w << 8) | out[bit / 8 + b];
          w = (w >> (bit & 7)) & mask;
          if (w < mod)
            v[k++] = w;
        }
    }
  return 1;
}
#define urandom_q(v, n, g, dom) urandom ((v), (n), Q, 42, (g), (dom))

/* Challenges of one batch of M evaluation equations, derived as lnp-tbox.c's __schwartz_zippel_accumulate2
   derives them (LAMBDA M values mod q from (seed, dom), row 2 i + h for half h of pair i). g[(2 i + h) M + j]
   weights equation j in half h (0: first accumulator, 1: second) of accumulator pair i < LAMBDA / 2. */
static int
sz_eval_challenges (uint64_t *g, const prg_t *seed, uint32_t dom, unsigned M)
{
  return urandom_q (g, LAMBDA * M, seed, dom);
}

/* intmat_urandom: row i from dom (dom << 32 | i * ncols) */
static int
urandom_mat (uint64_t V[LAMBDA][JLR], const prg_t *g, uint32_t dom)
{
  for (unsigned i = 0; i < LAMBDA; i++)
    if (!urandom_q (V[i], JLR, g, ((uint64_t)dom << 32) | (i * JLR)))
      return 0;
  return 1;
}

/* ---------------------------------------------------------------- JL fold */

static inline uint64_t
tr8 (uint64_t x) /* transpose the 8 x 8 bit matrix (byte b, bit t) -> (byte t, bit b) */
{
  uint64_t t;
  t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AAULL, x ^= t ^ (t << 7);
  t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCCULL, x ^= t ^ (t << 14);
  t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0ULL, x ^= t ^ (t << 28);
  return x;
}

/* acc[4 j + k] = sum_{i < 256} V[k][i] R_i[j], j < ncols, R_i = LaZer _brandom (k = 1) of ncols entries from
   (seed, dom0 + i): ncols plus bits then ncols minus bits, LSB first. Eight rows at a time: T[x] = sum of the
   eight rows' challenges selected by the bits of x, indexed by each column's transposed plus / minus bits.
   |acc| < 256 q < 2^50. rows: scratch of 8 ncols / 4 bytes. */
static void
jl_fold (int64_t *acc, unsigned ncols, uint64_t V[LAMBDA][JLR], const prg_t *g, uint64_t dom0, uint8_t *rows)
{
  const unsigned rb = ncols / 4, half = ncols / 8;
  int64_t T[256][LAMBDA];
  memset (acc, 0, sizeof (int64_t) * LAMBDA * ncols);
  for (unsigned i0 = 0; i0 < JLR; i0 += 8)
    {
      for (unsigned b = 0; b < 8; b++)
        {
          ctr_t s;
          ctr_init (&s, g, dom0 + i0 + b);
          ctr_read (&s, rows + b * rb, rb);
        }
      for (int k = 0; k < LAMBDA; k++)
        T[0][k] = 0;
      for (unsigned x = 1; x < 256; x++)
        for (int k = 0; k < LAMBDA; k++)
          T[x][k] = T[x & (x - 1)][k] + (int64_t)V[k][i0 + __builtin_ctz (x)];
      for (unsigned c = 0; c < half; c++)
        {
          uint64_t xp = 0, xm = 0;
          for (unsigned b = 0; b < 8; b++)
            xp |= (uint64_t)rows[b * rb + c] << (8 * b), xm |= (uint64_t)rows[b * rb + half + c] << (8 * b);
          xp = tr8 (xp), xm = tr8 (xm);
          int64_t *a = acc + (size_t)LAMBDA * 8 * c;
          for (unsigned t = 0; t < 8; t++, a += LAMBDA)
            {
              const int64_t *tp = T[(xp >> (8 * t)) & 255], *tm = T[(xm >> (8 * t)) & 255];
              for (int k = 0; k < LAMBDA; k++)
                a[k] += tp[k] - tm[k];
            }
        }
    }
}

/* ---------------------------------------------------------------- per-relation tables */

typedef struct
{
  const lnp_tbox_params_struct *P;
  int ready;
  unsigned mq, m1s, Z, kmsis, m2r, nbin, nex, N, M;
  unsigned nblk, bstart[8], blen[8]; /* Es selections: s1 slots [bstart, bstart + blen) (pqz_rel.c new_sel) */
  unsigned pstart;                   /* Ps: slots [pstart, pstart + nbin) */
  unsigned dsel;                     /* Ds: slot dsel */
  unsigned nrb;                      /* R_q-linear rows: blocks of 32, (A or A^T) x[ox..] + y[oy + i] = vec[rhs][i] */
  struct
  {
    unsigned tr, ox, oy, rhs;
  } rb[2];
  unsigned nprod; /* evaluation equations: the products vec[v]^T x[ox..] (+ the e2 slot), folded with Gm[k] */
  struct
  {
    unsigned v, ox;
    int e2;
  } pr[4];
  nt_t *A1, *A2p, *Bp;               /* kmsis x mq, kmsis x m2r, 12 x m2r */
  nt_t opow[8];                      /* o(sum_{2^i <= B_k^2} 2^i X^i), exact l2 bound k */
  uint64_t B2[8];                    /* B_k^2 */
  uint64_t z1bnd, Bz3sqr, Bz4, Bsq, inv2, inv4;
  uint64_t gamma, gammaby2, m, qm1;
  unsigned D, log2m;
} svrel_t;

#define NSR 6
static svrel_t SR[NSR];
static nt_t *SA; /* A (32 x 32), shared by all relations */

/* statement vectors (stmt_t.vec) */
enum
{
  V_PK, /* R_REG, R_DR: pk */
  V_PKF,
  V_PKT, /* R_DS: pk */
  V_PKA,
  V_UT,
  V_U, /* R_DS, R_DR: u */
  NVEC
};

static int
sv_idx (uint8_t rel) /* rel: the op, or PQZ_REL_TX0 */
{
  switch (rel)
    {
    case PQZ_OP_REGISTER:
      return 0;
    case PQZ_OP_TRANSFER:
      return 1;
    case PQZ_OP_BURN:
      return 2;
    case PQZ_OP_DISCLOSE_SENDER:
      return 3;
    case PQZ_OP_DISCLOSE_RECEIVER:
      return 4;
    case PQZ_REL_TX0:
      return 5;
    }
  return -1;
}
static int sv_ready;

static void *
tab_alloc (size_t n) /* init tables, kept; NULL on arena exhaustion (_alloc then returns a shared 1 MiB sink) */
{
  void *p = _alloc (n);
  return pqz_err ? NULL : p;
}
/* per-call working memory: freed in reverse order at the end of the call (the arena pops it; with
   -DPQZ_DEBUG_MALLOC it is libc heap, so ASan sees each block) */
#define SV_NBLK 48
static struct
{
  void *p;
  size_t n;
} svb[SV_NBLK];
static int nsvb;
static void *
sv_alloc (size_t n)
{
  void *p = _alloc (n);
  if (pqz_err || nsvb == SV_NBLK)
    {
      pqz_err_set (PQZ_ERR_ARENA);
      return NULL;
    }
  svb[nsvb].p = p, svb[nsvb++].n = n;
  return p;
}

static void
lz_coeffs (int64_t r[DEG], poly_ptr p) /* a LaZer poly (either domain) -> coefficients, as LaZer holds them */
{
  if (p->crt)
    {
      uint64_t t[DEG];
      memcpy (t, p->crtrep, sizeof t);
      pqz_ntt_inv (t); /* [0, q) */
      for (int j = 0; j < DEG; j++)
        r[j] = (int64_t)t[j];
    }
  else
    for (int j = 0; j < DEG; j++)
      r[j] = int_get_i64 (poly_get_coeff (p, j));
}
static void
lz_fwd (nt_t *r, poly_ptr p)
{
  int64_t a[DEG];
  lz_coeffs (a, p);
  for (int j = 0; j < DEG; j++)
    a[j] = (int64_t)modq (a[j]);
  fwd (r, a);
}
static nt_t *
lz_mat (polymat_t A, unsigned rows, unsigned cols)
{
  nt_t *r = tab_alloc (sizeof (nt_t) * rows * cols);
  if (r == NULL || polymat_get_nrows (A) != rows || polymat_get_ncols (A) != cols)
    return NULL;
  for (unsigned i = 0; i < rows; i++)
    for (unsigned j = 0; j < cols; j++)
      lz_fwd (&r[i * cols + j], polymat_get_elem (A, i, j));
  return r;
}
static int
int_u64 (uint64_t *r, int_srcptr a) /* a non-negative int_t below 2^63 */
{
  for (unsigned i = 1; i < a->nlimbs; i++)
    if (a->limbs[i] != 0)
      return 0;
  *r = a->limbs[0];
  return !a->neg && *r < ((uint64_t)1 << 63);
}

int
pqz_sv_setup (uint8_t op, const lnp_tbox_params_struct *P, polymat_t A, polymat_t A1, polymat_t A2p, polymat_t Bp)
{
  abdlop_params_srcptr tb = P->tbox, qm = P->quad_eval->quad_many;
  dcompress_params_srcptr dc = qm->dcompress;
  const int idx = sv_idx (op); /* op: the relation code (the op, or PQZ_REL_TX0) */
  int ok = 1;

  if (idx < 0) /* before any slot is touched: the fail path below would clear SR[0] (R_REG) and could drop SA */
    {
      pqz_err_set (PQZ_ERR_INTERNAL);
      return pqz_err;
    }
  svrel_t *S = &SR[idx];
  if (S->ready)
    return PQZ_OK;
  if (!sv_ready)
    {
      aes_tables ();
      if (!primes_init ())
        goto fail;
      if ((SA = lz_mat (A, NPK, NPK)) == NULL)
        goto fail;
      sv_ready = 1;
    }
  memset (S, 0, sizeof *S);
  S->P = P;
  S->mq = tb->m1, S->Z = P->Z, S->m1s = tb->m1 - P->Z, S->kmsis = tb->kmsis, S->m2r = tb->m2 - tb->kmsis;
  S->nbin = P->nbin, S->nex = P->nex;
  /* the statements of pqz_rel.c (build_reg / build_debit / build_ds / build_dr) */
  {
    static const unsigned st[7] = { 0, 32, 64, 96, 128, 129, 130 };
    switch (op)
      {
      case PQZ_OP_REGISTER:
        S->N = 32, S->M = 0, S->nblk = 2, S->dsel = 0, S->pstart = 0;
        S->nrb = 1, S->rb[0].tr = 0, S->rb[0].ox = 0, S->rb[0].oy = 32, S->rb[0].rhs = V_PK;
        break;
      case PQZ_OP_TRANSFER:
      case PQZ_REL_TX0:
      case PQZ_OP_BURN: /* rows 1, 2; R_TX products: pk_t, pk_f, pk_a (rows 3-5), u_T (row 6); R_TX0: pk_t, pk_f, u_T;
                           R_BURN: pk_f, u_T */
        if (op == PQZ_OP_TRANSFER)
          {
            S->N = 64, S->M = 80, S->nblk = 7, S->dsel = 128, S->pstart = 131, S->nprod = 4;
            S->pr[0].v = V_PKT, S->pr[1].v = V_PKF, S->pr[2].v = V_PKA, S->pr[3].v = V_UT;
            for (int k = 0; k < 3; k++)
              S->pr[k].ox = 64, S->pr[k].e2 = 128 + k;
            S->pr[3].ox = 0, S->pr[3].e2 = -1;
          }
        else if (op == PQZ_REL_TX0)
          {
            S->N = 64, S->M = 64, S->nblk = 6, S->dsel = 128, S->pstart = 130, S->nprod = 3;
            S->pr[0].v = V_PKT, S->pr[1].v = V_PKF, S->pr[2].v = V_UT;
            for (int k = 0; k < 2; k++)
              S->pr[k].ox = 64, S->pr[k].e2 = 128 + k;
            S->pr[2].ox = 0, S->pr[2].e2 = -1;
          }
        else
          {
            S->N = 64, S->M = 48, S->nblk = 5, S->dsel = 128, S->pstart = 129, S->nprod = 2;
            S->pr[0].v = V_PKF, S->pr[0].ox = 64, S->pr[0].e2 = 128;
            S->pr[1].v = V_UT, S->pr[1].ox = 0, S->pr[1].e2 = -1;
          }
        S->nrb = 2;
        S->rb[0].tr = 0, S->rb[0].ox = 0, S->rb[0].oy = 32, S->rb[0].rhs = V_PKF;
        S->rb[1].tr = 1, S->rb[1].ox = 64, S->rb[1].oy = 96, S->rb[1].rhs = V_U;
        break;
      case PQZ_OP_DISCLOSE_SENDER: /* u = A^T r + e1; pk^T r + e2_t */
        S->N = 32, S->M = 16, S->nblk = 3, S->dsel = 64, S->pstart = 65;
        S->nrb = 1, S->rb[0].tr = 1, S->rb[0].ox = 0, S->rb[0].oy = 32, S->rb[0].rhs = V_U;
        S->nprod = 1, S->pr[0].v = V_PKT, S->pr[0].ox = 0, S->pr[0].e2 = 64;
        break;
      case PQZ_OP_DISCLOSE_RECEIVER: /* pk = A s + e; u^T s */
        S->N = 32, S->M = 16, S->nblk = 2, S->dsel = 0, S->pstart = 64;
        S->nrb = 1, S->rb[0].tr = 0, S->rb[0].ox = 0, S->rb[0].oy = 32, S->rb[0].rhs = V_PK;
        S->nprod = 1, S->pr[0].v = V_U, S->pr[0].ox = 0, S->pr[0].e2 = -1;
        break;
      }
    for (unsigned i = 0; i < S->nblk && i < 7; i++)
      S->bstart[i] = st[i];
  }
  ok &= S->nblk == S->Z && S->Z <= 8 && S->nrb * NPK == S->N && S->nprod <= 4 && S->nbin <= 15;
  unsigned tot = S->nbin;
  for (unsigned i = 0; ok && i < S->nblk; i++)
    S->blen[i] = P->n[i], tot += P->n[i];
  ok &= tot + S->Z == S->nex && tot == S->m1s && S->nex == S->mq;
  ok &= P->nprime == 1 && P->quad_eval->lambda == LAMBDA && tb->ring->d == DEG && tb->l == 0
        && tb->lext == NQL + 1 && qm->l == NQL && P->quad_eval->quad_eval->l == NQEL && qm->m1 == S->mq
        && P->quad_eval->quad_eval->m1 == S->mq && qm->kmsis == S->kmsis && tb->ring->log2q == 42
        && qm->omega == 8 && qm->log2omega == 5;
  if (!ok)
    goto fail;
  /* constants */
  {
    uint64_t t;
    ok &= int_u64 (&S->Bz3sqr, P->Bz3sqr) & int_u64 (&S->Bz4, P->Bz4) & int_u64 (&S->Bsq, qm->Bsqr);
    ok &= int_u64 (&S->gamma, dc->gamma) & int_u64 (&S->gammaby2, dc->gammaby2) & int_u64 (&S->m, dc->m);
    ok &= int_u64 (&S->qm1, dc->qminus1);
    S->D = dc->D, S->log2m = dc->log2m;
    ok &= S->log2m <= 42; /* the final-round transcript buffer in pqz_sv_verify is sized from log2m */
    S->inv2 = pqz_int_modq (tb->ring->inv2), S->inv4 = pqz_int_modq (P->inv4);
    ok &= mulq (S->inv2, 2) == 1 && mulq (S->inv4, 4) == 1 && S->qm1 == Q - 1;
    /* lnp_quad_verify: ||z1||^2 <= 2 m1 d 962 2^(2 log2stdev1) / 400 */
    t = (uint64_t)2 * S->mq * DEG * 962;
    ok &= qm->log2stdev1 <= 20 && t < ((uint64_t)1 << (62 - 2 * qm->log2stdev1)); /* t 2^(2 log2stdev1) < 2^62 */
    S->z1bnd = ok ? (t << (2 * qm->log2stdev1)) / 400 : 0;
    /* l2_le / l2_sum need bnd < 2^62 (no wrap of the running sum); actual 2^36.7 .. 2^51.5 */
    ok &= S->Bz3sqr < ((uint64_t)1 << 62) && S->Bsq < ((uint64_t)1 << 62) && S->z1bnd < ((uint64_t)1 << 62);
    for (unsigned i = 0; ok && i < S->Z; i++)
      {
        int64_t a[DEG] = { 0 }, o[DEG];
        nt_t pw;
        ok &= int_u64 (&S->B2[i], P->l2Bsqr[i]) && S->B2[i] < ((uint64_t)1 << 42);
        for (unsigned k = 0; k < 42; k++) /* int_binexp (NULL, powB, B^2) */
          if (((uint64_t)1 << k) <= S->B2[i])
            a[k] = (int64_t)1 << k;
        cp_auto (o, a);
        for (int j = 0; j < DEG; j++)
          o[j] = centre ((uint64_t)o[j]);
        fwd (&pw, o);
        S->opow[i] = pw;
      }
  }
  if (!ok)
    goto fail;
  S->A1 = lz_mat (A1, S->kmsis, S->mq);
  S->A2p = S->A1 ? lz_mat (A2p, S->kmsis, S->m2r) : NULL;
  S->Bp = S->A2p ? lz_mat (Bp, NQL + 1, S->m2r) : NULL;
  if (S->Bp == NULL)
    goto fail;
  S->ready = 1;
  return PQZ_OK;
fail:
  /* the caller releases the arena to the mark before this call: a shared table built here goes with it */
  {
    int any = 0;
    for (int i = 0; i < NSR; i++)
      any |= SR[i].ready;
    if (SA != NULL && !any)
      sv_ready = 0, SA = NULL;
  }
  memset (S, 0, sizeof *S);
  pqz_err_set (PQZ_ERR_INTERNAL);
  return pqz_err;
}

void
pqz_sv_reset (void)
{
  memset (SR, 0, sizeof SR);
  sv_ready = 0, SA = NULL;
}

/* ---------------------------------------------------------------- statement */

typedef struct
{
  int64_t vec[NVEC][NPK][DEG];            /* V_PK .. V_U */
  int64_t vT[16], vt[16], vf[16], va[16]; /* R_DS / R_DR: vt = v */
  uint64_t fee, amount;
} stmt_t;

static uint64_t
rd_be8 (const uint8_t *p)
{
  uint64_t v = 0;
  for (int b = 0; b < 8; b++)
    v = (v << 8) | p[b];
  return v;
}
static int
rd_coeffs (int64_t *r, const uint8_t *in, unsigned n) /* pqz_rel.c rd_poly: every value < q */
{
  int ok = 1;
  for (unsigned k = 0; k < n; k++)
    {
      uint64_t v = rd_be8 (in + 8 * k);
      ok &= v < Q;
      r[k] = (int64_t)v;
    }
  return ok;
}
static int
rd_vec (int64_t r[NPK][DEG], const uint8_t *in)
{
  int ok = 1;
  for (unsigned i = 0; i < NPK; i++)
    ok &= rd_coeffs (r[i], in + i * 512, DEG);
  return ok;
}
static int
rd_word64 (uint64_t *v, const uint8_t *p) /* pqz_rel.c rd_word64: a be32 word < 2^64 */
{
  int ok = 1;
  for (unsigned b = 0; b < 24; b++)
    ok &= p[b] == 0;
  *v = rd_be8 (p + 24);
  return ok;
}
static int
parse_stmt (stmt_t *T, uint8_t op, const uint8_t *stmt, size_t len)
{
  const uint8_t *p = stmt + PQZ_PREFIX_BYTES;
  int ok = 1;
  switch (op)
    {
    case PQZ_OP_REGISTER:
      return len == PQZ_REG_STMT_BYTES && rd_vec (T->vec[V_PK], p + 32);
    case PQZ_OP_TRANSFER:
    case PQZ_REL_TX0:
    case PQZ_OP_BURN: /* pqz_rel.c parse_debit: header || pk_f (|| pk_t (|| pk_a)) || u_T || v_T || u (|| v_t) || v_f
                         (|| v_a), fee (and the R_BURN amount, the R_TX / R_TX0 auditorOn word) from the header */
      {
        const int burn = op == PQZ_OP_BURN, aud = op == PQZ_OP_TRANSFER;
        uint64_t on = 0;
        if (len != (burn ? PQZ_BURN_STMT_BYTES : aud ? PQZ_TX_STMT_BYTES : PQZ_TX0_STMT_BYTES))
          return 0;
        ok &= rd_word64 (&T->fee, stmt + PQZ_HDR_FEE);
        T->amount = 0;
        if (burn)
          ok &= rd_word64 (&T->amount, stmt + PQZ_HDR_AMOUNT);
        else /* P6e R6: 1 with pk_a and v_a, 0 without */
          ok &= rd_word64 (&on, stmt + PQZ_HDR_AUDITOR_ON) & (on == (uint64_t)aud);
        p = stmt + PQZ_HEADER_BYTES;
        ok &= rd_vec (T->vec[V_PKF], p), p += PQZ_POLYVEC_BYTES;
        if (!burn)
          ok &= rd_vec (T->vec[V_PKT], p), p += PQZ_POLYVEC_BYTES;
        if (aud)
          ok &= rd_vec (T->vec[V_PKA], p), p += PQZ_POLYVEC_BYTES;
        ok &= rd_vec (T->vec[V_UT], p), p += PQZ_POLYVEC_BYTES;
        ok &= rd_coeffs (T->vT, p, 16), p += PQZ_V_BYTES;
        ok &= rd_vec (T->vec[V_U], p), p += PQZ_POLYVEC_BYTES;
        if (!burn)
          ok &= rd_coeffs (T->vt, p, 16), p += PQZ_V_BYTES;
        ok &= rd_coeffs (T->vf, p, 16), p += PQZ_V_BYTES;
        if (aud)
          ok &= rd_coeffs (T->va, p, 16);
        return ok;
      }
    case PQZ_OP_DISCLOSE_SENDER:
    case PQZ_OP_DISCLOSE_RECEIVER: /* pqz_rel.c parse_disc */
      if (len != PQZ_DISC_STMT_BYTES)
        return 0;
      ok &= rd_word64 (&T->amount, stmt + PQZ_DISC_AMOUNT);
      p = stmt + PQZ_DISC_PK;
      ok &= rd_vec (T->vec[op == PQZ_OP_DISCLOSE_SENDER ? V_PKT : V_PK], p), p += PQZ_POLYVEC_BYTES;
      ok &= rd_vec (T->vec[V_U], p), p += PQZ_POLYVEC_BYTES;
      ok &= rd_coeffs (T->vt, p, 16);
      return ok;
    }
  return 0;
}

/* evaluation equations (pqz_rel.c build_debit / build_ds / build_dr, in their order e = 0, 1, ...) folded with
   weights g[M]: sum_e g_e E_e(s) = sum_k Gm[k] P_k + sum_b Ab[b] bits_b + rho, P_k the products of svrel_t.pr
   (vec^T x (+ e2)), Gm[k] = sum over the equations on product k of g_e X^-i, Ab the weighted bit coefficients
   (add_bit: coef X^-(slot % 64) on bit poly slot / 64), rho the weighted constants */
#define TX_DELTA ((int64_t)((1 << 26) - 1))
typedef struct
{
  int d, dp, m, c, e; /* bit slot bases (slot = base + width i + b), -1 if absent: pqz_rel.c LAY_TX / LAY_BURN */
} lay_t;
static const lay_t LAY_TX = { 0, 64, 128, 352, 517 }, LAY_BURN = { -1, 0, 64, 288, 453 };
#define SLOT(base, w, i, b) ((unsigned)(base) + (w) * (i) + (b))
static void
tx_bit (int64_t Ab[15][DEG], unsigned slot, int64_t coef, uint64_t g)
{
  uint64_t w = mulq (g, modq (coef));
  unsigned a = slot % DEG;
  int64_t *p = Ab[slot / DEG];
  if (a == 0)
    p[0] = (int64_t)addq ((uint64_t)p[0], w);
  else
    p[DEG - a] = (int64_t)subq ((uint64_t)p[DEG - a], w);
}
static void
tx_xinv (int64_t G[DEG], unsigned i, uint64_t g) /* G += g X^-i */
{
  if (i == 0)
    G[0] = (int64_t)addq ((uint64_t)G[0], g);
  else
    G[DEG - i] = (int64_t)subq ((uint64_t)G[DEG - i], g);
}
static unsigned
digit (uint64_t x, unsigned i)
{
  return (unsigned)((x >> (4 * i)) & 15);
}
/* R_TX (rel PQZ_OP_TRANSFER), R_TX0 (PQZ_REL_TX0: row 5 absent) and R_BURN (PQZ_OP_BURN: d = digits(amount)
   public, rows 3 and 5 absent) */
static void
debit_eval_fold (int64_t Gm[4][DEG], int64_t Ab[15][DEG], uint64_t *rho, const uint64_t *g, const stmt_t *T,
                 uint8_t rel)
{
  const int burn = rel == PQZ_OP_BURN, aud = rel == PQZ_OP_TRANSFER;
  const lay_t *L = burn ? &LAY_BURN : &LAY_TX;
  /* product index of pk_f (row 4) and u_T (row 6): svrel_t.pr of the relation */
  const unsigned kf = burn ? 0 : 1, kT = burn ? 1 : aud ? 3 : 2;
  unsigned i, b, e = 0;
  uint64_t r = 0;
  memset (Gm, 0, sizeof (int64_t) * 4 * DEG);
  memset (Ab, 0, sizeof (int64_t) * 15 * DEG);
  for (i = 0; i < 16; i++)
    {
      const int64_t dpub = burn ? digit (T->amount, i) : 0;
      /* rows 3-5: (pk^T r)_i + e2_i + Delta digit_i - v_i */
      if (!burn)
        {
          tx_xinv (Gm[0], i, g[e]);
          for (b = 0; b < 4; b++)
            tx_bit (Ab, SLOT (L->d, 4, i, b), TX_DELTA << b, g[e]);
          r = addq (r, mulq (g[e], negq ((uint64_t)T->vt[i]))), e++;
        }
      tx_xinv (Gm[kf], i, g[e]);
      for (b = 0; b < 4; b++)
        tx_bit (Ab, SLOT (L->dp, 4, i, b), TX_DELTA << b, g[e]);
      r = addq (r, mulq (g[e], negq ((uint64_t)T->vf[i]))), e++;
      if (aud)
        {
          tx_xinv (Gm[2], i, g[e]);
          for (b = 0; b < 4; b++)
            tx_bit (Ab, SLOT (L->d, 4, i, b), TX_DELTA << b, g[e]);
          r = addq (r, mulq (g[e], negq ((uint64_t)T->va[i]))), e++;
        }
      /* row 6: (u_T^T s_f)_i + Delta M_i + (e_T,i + 2^24) - 2^24 - v_T,i */
      tx_xinv (Gm[kT], i, g[e]);
      for (b = 0; b < 14; b++)
        tx_bit (Ab, SLOT (L->m, 14, i, b), TX_DELTA << b, g[e]);
      for (b = 0; b < 25; b++)
        tx_bit (Ab, SLOT (L->e, 25, i, b), (int64_t)1 << b, g[e]);
      r = addq (r, mulq (g[e], modq (-(int64_t)T->vT[i] - ((int64_t)1 << 24)))), e++;
      /* row 7: M_i + c_{i-1} - d'_i - d_i - f_i - 16 c_i (c = cbits - 64) */
      int64_t rhs = -(int64_t)digit (T->fee, i) - dpub;
      for (b = 0; b < 14; b++)
        tx_bit (Ab, SLOT (L->m, 14, i, b), (int64_t)1 << b, g[e]);
      if (i >= 1)
        {
          for (b = 0; b < 11; b++)
            tx_bit (Ab, SLOT (L->c, 11, i - 1, b), (int64_t)1 << b, g[e]);
          rhs -= 64;
        }
      for (b = 0; b < 4; b++)
        {
          tx_bit (Ab, SLOT (L->dp, 4, i, b), -((int64_t)1 << b), g[e]);
          if (!burn)
            tx_bit (Ab, SLOT (L->d, 4, i, b), -((int64_t)1 << b), g[e]);
        }
      if (i <= 14)
        {
          for (b = 0; b < 11; b++)
            tx_bit (Ab, SLOT (L->c, 11, i, b), -((int64_t)16 << b), g[e]);
          rhs += 16 * 64;
        }
      r = addq (r, mulq (g[e], modq (rhs))), e++;
    }
  *rho = r;
}
/* R_DS: (pk^T r)_i + e2_i + Delta d_i - v_i; R_DR: (u^T s)_i + (e'_i + 2^24) - 2^24 + Delta d_i - v_i */
static void
disc_eval_fold (int64_t Gm[4][DEG], int64_t Ab[15][DEG], uint64_t *rho, const uint64_t *g, const stmt_t *T,
                int recv)
{
  uint64_t r = 0;
  memset (Gm, 0, sizeof (int64_t) * 4 * DEG);
  memset (Ab, 0, sizeof (int64_t) * 15 * DEG);
  for (unsigned i = 0; i < 16; i++)
    {
      tx_xinv (Gm[0], i, g[i]);
      if (recv)
        for (unsigned b = 0; b < 25; b++)
          tx_bit (Ab, 25 * i + b, (int64_t)1 << b, g[i]);
      r = addq (r, mulq (g[i], modq (TX_DELTA * digit (T->amount, i) - T->vt[i] - (recv ? (int64_t)1 << 24 : 0))));
    }
  *rho = r;
}
static void
eval_fold (uint8_t op, int64_t Gm[4][DEG], int64_t Ab[15][DEG], uint64_t *rho, const uint64_t *g, const stmt_t *T)
{
  if (op == PQZ_OP_TRANSFER || op == PQZ_REL_TX0 || op == PQZ_OP_BURN)
    debit_eval_fold (Gm, Ab, rho, g, T, op);
  else
    disc_eval_fold (Gm, Ab, rho, g, T, op == PQZ_OP_DISCLOSE_RECEIVER);
}

/* ---------------------------------------------------------------- verify */

typedef struct
{
  polyvec_t tA1, tB, h, z1, z21, hint, z3, z4;
  poly_t c;
} lzpf_t;

static uint64_t
l2_sum (const int64_t *a, unsigned n, uint64_t bnd) /* sum a_i^2 if <= bnd, else bnd + 1; bnd < 2^62, |a_i| < 2^62 */
{
  uint64_t s = 0;
  for (unsigned i = 0; i < n; i++)
    {
      uint64_t x = (uint64_t)(a[i] < 0 ? -a[i] : a[i]);
      if (x >= ((uint64_t)1 << 31)) /* x^2 >= 2^62 > bnd */
        return bnd + 1;
      s += x * x;
      if (s > bnd)
        return bnd + 1;
    }
  return s;
}
static int
l2_le (const int64_t *a, unsigned n, uint64_t bnd) /* sum a_i^2 <= bnd < 2^62, |a_i| < 2^62 */
{
  return l2_sum (a, n, bnd) <= bnd;
}
static void
lz_get (int64_t *r, polyvec_t v, unsigned n) /* n polys of a LaZer polyvec -> coefficients */
{
  for (unsigned i = 0; i < n; i++)
    lz_coeffs (r + DEG * i, polyvec_get_elem (v, i));
}
/* hash = SHAKE128(hash || enc(v)): one Fiat-Shamir round over urandom-coded polys */
static void
hash_enc (uint8_t out32[32], const uint8_t hash[32], polyvec_t v, int_srcptr mod, unsigned bits, uint8_t *buf)
{
  coder_state_t cs;
  shake128_state_t hs;
  coder_enc_begin (cs, buf);
  coder_enc_urandom3 (cs, v, mod, bits);
  coder_enc_end (cs);
  shake128_init (hs);
  shake128_absorb (hs, hash, 32);
  shake128_absorb (hs, buf, coder_get_offset (cs) >> 3);
  shake128_squeeze (hs, out32, 32);
  shake128_clear (hs);
}

typedef struct
{
  nt_t *Z, *SZ;   /* nq witness slots and their automorphisms */
  int64_t *zc;    /* coefficients of slots >= mq (mod q) */
  nt_t *z21, *tB; /* m2r, 12 */
  nt_t c, cD, c2, cJ, Bp_, Bm_, cBp, cBm;
  int64_t *vR;    /* JL fold, 4 nex 64 */
  uint8_t *rows;  /* 8 JL rows */
} work_t;

static int
verify_body (const svrel_t *S, uint8_t op, const uint8_t hash_stmt[32], const uint8_t *stmt, size_t stmt_len,
             const uint8_t *proof, size_t proof_len, lzpf_t *Fp);

int
pqz_sv_verify (uint8_t op, const uint8_t hash_stmt[32], const uint8_t *stmt, size_t stmt_len,
               const uint8_t *proof, size_t proof_len)
{
  const svrel_t *S;
  lzpf_t F;
  int ok;

  if (sv_idx (op) < 0)
    return 0;
  S = &SR[sv_idx (op)];
  if (!S->ready)
    return 0;
  polyring_srcptr Rq = S->P->tbox->ring;
  nsvb = 0;
  polyvec_alloc (F.tA1, Rq, S->kmsis), polyvec_alloc (F.tB, Rq, NQL + 1), polyvec_alloc (F.h, Rq, LAMBDA / 2);
  polyvec_alloc (F.z1, Rq, S->mq), polyvec_alloc (F.z21, Rq, S->m2r), polyvec_alloc (F.hint, Rq, S->kmsis);
  polyvec_alloc (F.z3, Rq, JLR / DEG), polyvec_alloc (F.z4, Rq, JLR / DEG), poly_alloc (F.c, Rq);
  ok = pqz_err == PQZ_OK && verify_body (S, op, hash_stmt, stmt, stmt_len, proof, proof_len, &F) == 1;
  while (nsvb > 0)
    nsvb--, _free (svb[nsvb].p, svb[nsvb].n);
  poly_free (F.c), polyvec_free (F.z4), polyvec_free (F.z3), polyvec_free (F.hint), polyvec_free (F.z21);
  polyvec_free (F.z1), polyvec_free (F.h), polyvec_free (F.tB), polyvec_free (F.tA1);
  return ok && pqz_err == PQZ_OK;
}

static int
verify_body (const svrel_t *S, uint8_t op, const uint8_t hash_stmt[32], const uint8_t *stmt, size_t stmt_len,
             const uint8_t *proof, size_t proof_len, lzpf_t *Fp)
{
  const lnp_tbox_params_struct *P;
  stmt_t *T;
  work_t W;
#define F (*Fp) /* the decoded proof, owned by pqz_sv_verify */
  uint8_t hash[32], hash0[32], hash1[32], cseed[32];
  prg_t g0, g1;
  polyring_srcptr Rq;
  unsigned i, j, k, h;
  int64_t a[DEG], b[DEG], r[DEG];
  acc_t acc;
  nt_t t1;

  P = S->P;
  Rq = P->tbox->ring;
  const unsigned mq = S->mq, m1s = S->m1s, Z = S->Z, km = S->kmsis, m2r = S->m2r, M = S->M;
  const unsigned nq = mq + NQL, iy3 = mq, ibeta = mq + 8, ig = mq + NQEL;
  const unsigned ntot = LAMBDA / 2 + 2 + S->N;

  /* statement (pqz_rel.c build_reg / parse_tx: every coefficient < q) */
  if ((T = sv_alloc (sizeof *T)) == NULL || !parse_stmt (T, op, stmt, stmt_len))
    return 0;

  /* proof: the generic decoder, then the reductions of pqz_rel.c do_verify */
  if (proof_len > PQZ_MAX_PROOF)
    return 0;
  if (pqz_err || !pqz_decproof (proof_len, proof, F.tA1, F.tB, F.h, F.c, F.z1, F.z21, F.hint, F.z3, F.z4, P))
    return 0;
  polyvec_mod (F.h, F.h), polyvec_redc (F.h, F.h);
  poly_mod (F.c, F.c), poly_redc (F.c, F.c);
  polyvec_mod (F.z1, F.z1), polyvec_redc (F.z1, F.z1);
  polyvec_mod (F.z21, F.z21), polyvec_redc (F.z21, F.z21);
  polyvec_mod (F.z3, F.z3), polyvec_redc (F.z3, F.z3);
  polyvec_mod (F.z4, F.z4), polyvec_redc (F.z4, F.z4);

  /* working memory */
  W.Z = sv_alloc (sizeof (nt_t) * nq), W.SZ = sv_alloc (sizeof (nt_t) * nq);
  W.zc = sv_alloc (sizeof (int64_t) * DEG * nq);
  W.z21 = sv_alloc (sizeof (nt_t) * m2r), W.tB = sv_alloc (sizeof (nt_t) * (NQL + 1));
  W.vR = sv_alloc (sizeof (int64_t) * LAMBDA * S->nex * DEG);
  W.rows = sv_alloc (8 * S->nex * DEG / 4);
  int64_t *z3c = sv_alloc (sizeof (int64_t) * JLR), *z4c = sv_alloc (sizeof (int64_t) * JLR);
  int64_t *hc = sv_alloc (sizeof (int64_t) * DEG * LAMBDA / 2), *cc = sv_alloc (sizeof (int64_t) * DEG);
  int64_t *hint = sv_alloc (sizeof (int64_t) * DEG * km), *tA1 = sv_alloc (sizeof (int64_t) * DEG * km);
  int64_t *z21 = sv_alloc (sizeof (int64_t) * DEG * m2r), *tBc = sv_alloc (sizeof (int64_t) * DEG * (NQL + 1));
  /* transcript buffer: the largest of the encodings (ty3 || ty4 || tbeta: 9 polys of 42 bits; tg: 2; final:
     t || v || w1, 2 polys of 42 bits + km of log2m bits, as lnp_quad_verify's out[]), log2m <= 42 at setup */
  const size_t nfin = CEIL (2 * 42 * DEG + S->log2m * DEG * km, 8), nty = CEIL (256 * 2 * 42 + DEG * 42, 8);
  uint8_t *buf = sv_alloc ((nfin > nty ? nfin : nty) + 64);
  if (buf == NULL)
    return 0;

  /* Fiat-Shamir round 1: statement digest, tA1 (abdlop_hashcomm, as pqz_rel.c do_verify) */
  memcpy (hash, hash_stmt, 32);
  abdlop_hashcomm (hash, F.tA1, F.tB, P->tbox);

  /* _lnp_tbox_check_z34: ||z3||^2 <= Bz3sqr, ||z4||_inf <= Bz4, then the round over ty3 || ty4 || tbeta */
  lz_get (z3c, F.z3, JLR / DEG), lz_get (z4c, F.z4, JLR / DEG);
  if (!l2_le (z3c, JLR, S->Bz3sqr))
    return 0;
  for (j = 0; j < JLR; j++)
    if ((uint64_t)(z4c[j] < 0 ? -z4c[j] : z4c[j]) > S->Bz4)
      return 0;
  {
    polyvec_t ty3, ty4, tbeta;
    coder_state_t cs;
    shake128_state_t hs;
    polyvec_get_subvec (ty3, F.tB, 0, 4, 1), polyvec_mod (ty3, ty3), polyvec_redp (ty3, ty3);
    polyvec_get_subvec (ty4, F.tB, 4, 4, 1), polyvec_mod (ty4, ty4), polyvec_redp (ty4, ty4);
    polyvec_get_subvec (tbeta, F.tB, 8, 1, 1), polyvec_mod (tbeta, tbeta), polyvec_redp (tbeta, tbeta);
    coder_enc_begin (cs, buf);
    coder_enc_urandom3 (cs, ty3, Rq->q, 42);
    coder_enc_urandom3 (cs, ty4, Rq->q, 42);
    coder_enc_urandom3 (cs, tbeta, Rq->q, 42);
    coder_enc_end (cs);
    shake128_init (hs);
    shake128_absorb (hs, hash, 32);
    shake128_absorb (hs, buf, coder_get_offset (cs) >> 3);
    shake128_squeeze (hs, hash0, 32);
    shake128_clear (hs);
  }
  /* h: coefficients 0 and d/2 are zero */
  lz_get (hc, F.h, LAMBDA / 2);
  for (i = 0; i < LAMBDA / 2; i++)
    if (hc[DEG * i] != 0 || hc[DEG * i + DEG / 2] != 0)
      return 0;
  /* round over tg */
  {
    polyvec_t tg;
    polyvec_get_subvec (tg, F.tB, NQEL, LAMBDA / 2, 1), polyvec_mod (tg, tg), polyvec_redp (tg, tg);
    hash_enc (hash1, hash0, tg, Rq->q, 42, buf);
  }

  /* checks that need only the proof (lnp_quad_verify checks them after the challenge; any order gives the same
     accept / reject): ||z1||^2, ||hint||_inf */
  lz_get (W.zc, F.z1, mq);
  if (!l2_le (W.zc, DEG * mq, S->z1bnd))
    return 0;
  lz_get (hint, F.hint, km);
  for (j = 0; j < DEG * km; j++)
    if ((uint64_t)(hint[j] < 0 ? -hint[j] : hint[j]) > S->m)
      return 0;

  /* proof values in the NTT domain */
  lz_coeffs (cc, F.c);
  for (j = 0; j < DEG; j++)
    if (cc[j] < -8 || cc[j] > 8)
      return 0; /* the challenge c2 has coefficients in [-8, 8]; c differs from it */
  fwd (&W.c, cc);
  nt_mul (&W.c2, &W.c, &W.c); /* |c^2| <= 64 * 64 */
  for (j = 0; j < DEG; j++)
    a[j] = cc[j] * ((int64_t)1 << S->D);
  fwd (&W.cD, a); /* c 2^D */
  nt_mul (&W.cJ, &W.c, &NJ);
  lz_get (z21, F.z21, m2r);
  for (j = 0; j < m2r; j++)
    fwd (&W.z21[j], z21 + DEG * j);
  lz_get (tBc, F.tB, NQL + 1);
  for (j = 0; j < NQL + 1; j++)
    fwd (&W.tB[j], tBc + DEG * j);
  for (i = 0; i < mq; i++)
    fwd (&W.Z[i], W.zc + DEG * i), nt_auto (&W.SZ[i], &W.Z[i]);
  /* slots mq.. (y3, y4, beta, g): c tB_i - B'_i z21  (|.| < 46 2^90) */
  for (i = 0; i < NQL; i++)
    {
      memset (&acc, 0, sizeof acc);
      acc_mul (&acc, &W.c, &W.tB[i]);
      for (j = 0; j < m2r; j++)
        acc_mulsub (&acc, &S->Bp[i * m2r + j], &W.z21[j]);
      red (W.zc + DEG * (mq + i), &acc);
      fwd (&W.Z[mq + i], W.zc + DEG * (mq + i)), nt_auto (&W.SZ[mq + i], &W.Z[mq + i]);
    }
  const int64_t *zb = W.zc + DEG * ibeta;
  nt_add (&W.Bp_, &W.Z[ibeta], &W.SZ[ibeta]); /* beta + o(beta) */
  nt_sub (&W.Bm_, &W.SZ[ibeta], &W.Z[ibeta]); /* o(beta) - beta */
  nt_mul (&W.cBp, &W.c, &W.Bp_);              /* |.| < 2^52 */
  nt_mul (&W.cBm, &W.c, &W.Bm_);

  /* challenges */
  prg_seed (&g0, hash0);
  prg_seed (&g1, hash1);

  /* ---- the evaluation-equation polynomials that do not depend on the challenges ---- */
  int64_t *Eu = sv_alloc (sizeof (int64_t) * DEG), *Eb = sv_alloc (sizeof (int64_t) * DEG);
  int64_t *El = sv_alloc (sizeof (int64_t) * DEG * Z);
  nt_t *PKe = sv_alloc (sizeof (nt_t) * 4);
  if (PKe == NULL)
    return 0;
  /* upsilon: sum_j o(u_j) (u_j - c J)   (|.| < 7 * 2^91) */
  memset (&acc, 0, sizeof acc);
  for (j = 0; j < Z; j++)
    nt_sub (&t1, &W.Z[m1s + j], &W.cJ), acc_mul (&acc, &W.SZ[m1s + j], &t1);
  red (Eu, &acc);
  /* binary: sum_b o(b) (b - c J) */
  memset (&acc, 0, sizeof acc);
  for (j = 0; j < S->nbin; j++)
    nt_sub (&t1, &W.Z[S->pstart + j], &W.cJ), acc_mul (&acc, &W.SZ[S->pstart + j], &t1);
  red (Eb, &acc);
  /* exact l2, block i: sum o(x) x + c o(powB_i) upsilon_i - B_i^2 c^2   (|.| < 2^96 + 2^98) */
  for (i = 0; i < Z; i++)
    {
      memset (&acc, 0, sizeof acc);
      for (j = 0; j < S->blen[i]; j++)
        acc_mul (&acc, &W.SZ[S->bstart[i] + j], &W.Z[S->bstart[i] + j]);
      nt_mul (&t1, &W.c, &S->opow[i]);
      acc_mul (&acc, &t1, &W.Z[m1s + i]);
      acc_scal (&acc, &W.c2, S->B2[i], 1);
      red (El + DEG * i, &acc);
    }
  /* evaluation-equation products: vec^T x (+ e2), e.g. R_TX pk_t^T r + e2_t (t < 3), u_T^T s_f */
  for (k = 0; k < S->nprod; k++)
    {
      memset (&acc, 0, sizeof acc);
      for (j = 0; j < NPK; j++)
        fwd (&t1, T->vec[S->pr[k].v][j]), acc_mul (&acc, &t1, &W.Z[S->pr[k].ox + j]);
      if (S->pr[k].e2 >= 0)
        acc_add (&acc, &W.Z[S->pr[k].e2]);
      red (r, &acc);
      fwd (&PKe[k], r);
    }

  /* ---- z3 / z4 (JL) rows: V from (hash0, dom), R / R' rows from (hash0, i) / (hash0, 256 + i) ---- */
  uint64_t (*V3)[JLR] = sv_alloc (sizeof (uint64_t) * LAMBDA * JLR);
  uint64_t (*V4)[JLR] = sv_alloc (sizeof (uint64_t) * LAMBDA * JLR);
  nt_t *Gz = sv_alloc (sizeof (nt_t) * LAMBDA); /* z3 + z4 term of accumulator half k (reduced) */
  if (Gz == NULL)
    return 0;
  const uint32_t dom_z4 = M + 2 * (DEG - 1) + 2 + Z, dom_z3 = dom_z4 + 256;
  if (!urandom_mat (V4, &g0, dom_z4) || !urandom_mat (V3, &g0, dom_z3))
    return 0;
  {
    nt_t Bh, Bm, P4, cy[8];
    acc_t *Ga = sv_alloc (sizeof (acc_t) * LAMBDA);
    if (Ga == NULL)
      return 0;
    /* inv2 (beta + o(beta)), inv2 X^32 (o(beta) - beta) as coefficients mod q */
    cp_auto (a, zb);
    for (j = 0; j < DEG; j++)
      b[j] = (int64_t)mulq (S->inv2, addq ((uint64_t)zb[j], (uint64_t)a[j]));
    fwd (&Bh, b);
    for (j = 0; j < DEG; j++)
      r[j] = (int64_t)subq ((uint64_t)a[j], (uint64_t)zb[j]);
    cp_mulx (b, r, DEG / 2);
    for (j = 0; j < DEG; j++)
      b[j] = (int64_t)mulq (S->inv2, (uint64_t)b[j]);
    fwd (&Bm, b);
    nt_mul (&t1, &W.SZ[S->dsel], &Bm);
    red_nt (r, &t1);
    fwd (&P4, r); /* o(s_D) inv2 X^32 (o(beta) - beta), reduced */
    for (i = 0; i < 8; i++)
      nt_mul (&cy[i], &W.c, &W.SZ[iy3 + i]); /* c o(y3_i), c o(y4_i): |.| < 2^51 */

    /* z4: inv2 X^32 W4_k o(s_D) (o(beta) - beta) + c sum_i V4_k,i o(y4_i) - <z4, V4_k> c^2 */
    jl_fold (W.vR, DEG, V4, &g0, 256, W.rows);
    for (k = 0; k < LAMBDA; k++)
      {
        memset (&Ga[k], 0, sizeof (acc_t));
        for (j = 0; j < DEG; j++)
          a[j] = (int64_t)modq (W.vR[LAMBDA * j + k]);
        fwd (&t1, a);
        acc_mul (&Ga[k], &t1, &P4);
        uint64_t s = 0;
        for (i = 0; i < JLR / DEG; i++)
          {
            for (j = 0; j < DEG; j++)
              a[j] = (int64_t)V4[k][DEG * i + j];
            fwd (&t1, a);
            acc_mul (&Ga[k], &t1, &cy[4 + i]);
          }
        for (j = 0; j < JLR; j++)
          s = addq (s, mulq (modq (z4c[j]), V4[k][j]));
        acc_scal (&Ga[k], &W.c2, s, 1);
      }
    /* z3: inv2 (beta + o(beta)) sum_p o(s_p) W3_k,col(p) + c sum_i V3_k,i o(y3_i) - <z3, V3_k> c^2 */
    jl_fold (W.vR, S->nex * DEG, V3, &g0, 0, W.rows);
    for (k = 0; k < LAMBDA; k++)
      {
        unsigned col = 0;
        memset (&acc, 0, sizeof acc); /* |.| < 153 2^90 */
#define W3MAC(slot)                                                                                          \
  do                                                                                                         \
    {                                                                                                        \
      for (j = 0; j < DEG; j++)                                                                              \
        a[j] = (int64_t)modq (W.vR[LAMBDA * (DEG * col + j) + k]);                                          \
      fwd (&t1, a);                                                                                          \
      acc_mul (&acc, &W.SZ[slot], &t1);                                                                      \
      col++;                                                                                                 \
    }                                                                                                        \
  while (0)
        for (i = 0; i < S->nbin; i++) /* the columns of vR: Ps rows, then each Es_i's rows, then upsilon */
          W3MAC (S->pstart + i);
        for (h = 0; h < S->nblk; h++)
          for (i = 0; i < S->blen[h]; i++)
            W3MAC (S->bstart[h] + i);
        for (i = 0; i < Z; i++)
          W3MAC (m1s + i);
#undef W3MAC
        red (r, &acc);
        fwd (&t1, r);
        acc_mul (&Ga[k], &Bh, &t1);
        uint64_t s = 0;
        for (i = 0; i < JLR / DEG; i++)
          {
            for (j = 0; j < DEG; j++)
              a[j] = (int64_t)V3[k][DEG * i + j];
            fwd (&t1, a);
            acc_mul (&Ga[k], &t1, &cy[i]);
          }
        for (j = 0; j < JLR; j++)
          s = addq (s, mulq (modq (z3c[j]), V3[k][j]));
        acc_scal (&Ga[k], &W.c2, s, 1);
        acc_nt (&Gz[k], &Ga[k]); /* the k-th z3 + z4 terms, |.| < 2^102, Montgomery form */
      }
  }

  /* ---- the Schwartz-Zippel accumulators: half k' = 2 i + h of pair i ---- */
  const unsigned nsz = 2 * (DEG - 1) + 2 + Z;   /* beta3 (63), beta4 (63), upsilon, binary, l2 (Z) */
  uint64_t *gsz = sv_alloc (sizeof (uint64_t) * LAMBDA * nsz);
  uint64_t *gin = sv_alloc (sizeof (uint64_t) * LAMBDA * (M ? M : 1));
  int64_t *H = sv_alloc (sizeof (int64_t) * DEG * LAMBDA);
  if (H == NULL)
    return 0;
  {
    uint64_t gb[LAMBDA];
    unsigned e = 0;
    if (M > 0 && !sz_eval_challenges (gin, &g1, 0, M))
      return 0;
#define ONE(dom)                                                                                             \
  do                                                                                                         \
    {                                                                                                        \
      if (!sz_eval_challenges (gb, &g1, (dom), 1))                                                           \
        return 0;                                                                                            \
      for (k = 0; k < LAMBDA; k++)                                                                           \
        gsz[k * nsz + e] = gb[k];                                                                            \
      e++;                                                                                                   \
    }                                                                                                        \
  while (0)
    for (i = 1; i < DEG; i++) /* beta3: dom M + i */
      ONE (M + i);
    for (i = 1; i < DEG; i++) /* beta4: dom M + d - 1 + i */
      ONE (M + DEG - 1 + i);
    ONE (M + 2 * (DEG - 1)); /* upsilon */
    if (S->nbin > 0)
      ONE (M + 2 * (DEG - 1) + 1); /* binary */
    else
      e++;
    for (i = 0; i < Z; i++) /* l2: one call per equation, dom + i as __schwartz_zippel_accumulate_l2 (P6-L2) */
      ONE (M + 2 * (DEG - 1) + 2 + i);
#undef ONE
  }
  for (k = 0; k < LAMBDA; k++)
    {
      const uint64_t *g = gsz + k * nsz;
      int64_t G[DEG];
      memset (&acc, 0, sizeof acc);
      acc_add (&acc, &Gz[k]);
      /* beta3: c inv2 (beta + o(beta)) sum_i g_i X^i ; beta4: c inv2 X^32 (o(beta) - beta) sum_i g_i X^i */
      a[0] = 0;
      for (i = 1; i < DEG; i++)
        a[i] = (int64_t)mulq (S->inv2, g[i - 1]);
      fwd (&t1, a);
      acc_mul (&acc, &W.cBp, &t1); /* |.| < 2^100 */
      r[0] = 0;
      for (i = 1; i < DEG; i++)
        r[i] = (int64_t)mulq (S->inv2, g[DEG - 1 + i - 1]);
      cp_mulx (a, r, DEG / 2);
      fwd (&t1, a);
      acc_mul (&acc, &W.cBm, &t1);
      if (M > 0) /* c (sum_k Gm_k P_k + sum_b Ab_b bits_b) + rho c^2, e.g. R_TX P = pk_t^T r + e2_t, .., u_T^T s_f */
        {
          int64_t Gm[4][DEG], Ab[15][DEG];
          uint64_t rho;
          acc_t br;
          eval_fold (op, Gm, Ab, &rho, gin + k * M, T);
          memset (&br, 0, sizeof br); /* |.| < 19 2^90 */
          for (i = 0; i < S->nprod; i++)
            fwd (&t1, Gm[i]), acc_mul (&br, &t1, &PKe[i]);
          for (i = 0; i < S->nbin; i++)
            fwd (&t1, Ab[i]), acc_mul (&br, &t1, &W.Z[S->pstart + i]);
          acc_nt (&t1, &br);
          acc_mul (&acc, &W.c, &t1); /* |.| < 2^104 */
          acc_scal (&acc, &W.c2, rho, 0);
        }
      red (G, &acc);
      /* + g_ups E_ups + g_bin E_bin + sum_i g_l2 E_l2,i (coefficients mod q) */
      for (j = 0; j < DEG; j++)
        {
          uint64_t x = addq ((uint64_t)G[j], mulq (g[2 * (DEG - 1)], (uint64_t)Eu[j]));
          if (S->nbin > 0)
            x = addq (x, mulq (g[2 * (DEG - 1) + 1], (uint64_t)Eb[j]));
          for (i = 0; i < Z; i++)
            x = addq (x, mulq (g[2 * (DEG - 1) + 2 + i], (uint64_t)El[DEG * i + j]));
          G[j] = (int64_t)x;
        }
      memcpy (H + DEG * k, G, sizeof G);
    }
  /* __schwartz_zippel_auto: pair i -> inv2 (G1 + o(G1) + X^32 (G2 + o(G2))) */
  for (i = 0; i < LAMBDA / 2; i++)
    {
      int64_t *G1 = H + DEG * (2 * i), *G2 = H + DEG * (2 * i + 1);
      cp_auto (a, G2);
      for (j = 0; j < DEG; j++)
        r[j] = (int64_t)addq ((uint64_t)G2[j], (uint64_t)a[j]);
      cp_mulx (b, r, DEG / 2);
      cp_auto (a, G1);
      for (j = 0; j < DEG; j++)
        G2[j] = (int64_t)mulq (S->inv2, addq (addq ((uint64_t)G1[j], (uint64_t)a[j]), (uint64_t)b[j]));
    }

  /* ---- lnp_quad_many_verify / lnp_quad_verify: v = sum_k mu_k E_k(z) - f, grouped by the power of c ---- */
  acc_t *Qa = sv_alloc (sizeof (acc_t)), *La = sv_alloc (sizeof (acc_t)), *Ra = sv_alloc (sizeof (acc_t));
  if (Ra == NULL)
    return 0;
  memset (Qa, 0, sizeof *Qa), memset (La, 0, sizeof *La), memset (Ra, 0, sizeof *Ra);
  for (k = 0; k < ntot; k++)
    {
      uint64_t mu[DEG];
      nt_t mn;
      if (!urandom_q (mu, DEG, &g1, k + 1)) /* polyvec_urandom (mu, q, log2q, hash, 0) */
        return 0;
      for (j = 0; j < DEG; j++)
        a[j] = (int64_t)mu[j];
      fwd (&mn, a);
      if (k < LAMBDA / 2) /* accumulator pair k: E = H_k + c g_k - c^2 h_k */
        {
          fwd (&t1, H + DEG * (2 * k + 1));
          acc_mul (Qa, &mn, &t1);
          acc_mul (La, &mn, &W.Z[ig + k]);
          for (j = 0; j < DEG; j++)
            a[j] = hc[DEG * k + j];
          fwd (&t1, a);
          acc_mulsub (Ra, &mn, &t1);
        }
      else if (k < LAMBDA / 2 + 2) /* beta3^2 - 1, beta4^2 - 1 */
        {
          const int sg = k == LAMBDA / 2 ? 1 : -1;
          int64_t sq[DEG], x[DEG], osq[DEG];
          nt_mul (&t1, &W.Z[ibeta], &W.Z[ibeta]);
          red_nt (sq, &t1);
          nt_mul (&t1, &W.Z[ibeta], &W.SZ[ibeta]);
          red_nt (x, &t1);
          cp_auto (osq, sq);
          for (j = 0; j < DEG; j++)
            {
              uint64_t y = mulq (S->inv4, addq ((uint64_t)sq[j], (uint64_t)osq[j]));
              a[j] = (int64_t)addq (sg > 0 ? y : negq (y), mulq (S->inv2, (uint64_t)x[j]));
            }
          fwd (&t1, a);
          acc_mul (Qa, &mn, &t1);
          acc_sub (Ra, &mn);
        }
      else /* input row i: c (A' x + y)_i - c^2 rhs_i */
        {
          const unsigned row = k - (LAMBDA / 2 + 2), blk = row / NPK, ii = row % NPK;
          const unsigned tr = S->rb[blk].tr, ox = S->rb[blk].ox, oy = S->rb[blk].oy;
          memset (&acc, 0, sizeof acc); /* |.| < 33 2^90 */
          for (j = 0; j < NPK; j++)
            acc_mul (&acc, tr ? &SA[j * NPK + ii] : &SA[ii * NPK + j], &W.Z[ox + j]);
          acc_add (&acc, &W.Z[oy + ii]);
          red (r, &acc);
          fwd (&t1, r);
          acc_mul (La, &mn, &t1);
          fwd (&t1, T->vec[S->rb[blk].rhs][ii]);
          acc_mulsub (Ra, &mn, &t1);
        }
    }
  /* - f = - c t + B'_ext z21 */
  for (j = 0; j < m2r; j++)
    acc_mul (Qa, &S->Bp[NQL * m2r + j], &W.z21[j]);
  acc_sub (La, &W.tB[NQL]);
  red (r, La), fwd (&t1, r), acc_mul (Qa, &W.c, &t1);
  red (r, Ra), fwd (&t1, r), acc_mul (Qa, &W.c2, &t1);
  int64_t v[DEG];
  red (v, Qa); /* |.| < 2^97 */

  /* ---- w = A1 z1 + A2' z21 - c 2^D tA1 (|.| < 198 2^90), w1 = UseHint (hint, w) ---- */
  int64_t *w1 = sv_alloc (sizeof (int64_t) * DEG * km), *wl = sv_alloc (sizeof (int64_t) * DEG * km);
  if (wl == NULL)
    return 0;
  lz_get (tA1, F.tA1, km);
  for (i = 0; i < km; i++)
    {
      memset (&acc, 0, sizeof acc);
      for (j = 0; j < mq; j++)
        acc_mul (&acc, &S->A1[i * mq + j], &W.Z[j]);
      for (j = 0; j < m2r; j++)
        acc_mul (&acc, &S->A2p[i * m2r + j], &W.z21[j]);
      fwd (&t1, tA1 + DEG * i);
      acc_mulsub (&acc, &W.cD, &t1);
      red (r, &acc);
      for (j = 0; j < DEG; j++) /* dcompress_use_ghint (r in [0, q)) */
        {
          const uint64_t r1 = (uint64_t)r[j];
          int64_t r0 = (int64_t)(r1 % S->gamma), y;
          if ((uint64_t)r0 > S->gammaby2)
            r0 -= (int64_t)S->gamma;
          uint64_t hi = (uint64_t)((int64_t)r1 - r0);
          hi = hi == S->qm1 ? 0 : hi / S->gamma;
          y = ((int64_t)hi + hint[DEG * i + j]) % (int64_t)S->m;
          if (y < 0)
            y += (int64_t)S->m;
          w1[DEG * i + j] = y;
          /* lnp_quad_verify norm term: centre (w - gamma w1) */
          wl[DEG * i + j] = centre (subq (r1, mulq (S->gamma % Q, (uint64_t)y)));
        }
    }

  /* ---- final round: c' = H(hash1 || t || v || w1) must give c ---- */
  {
    coder_state_t cs;
    shake128_state_t hs;
    polyvec_t tt, w1v;
    poly_t vv, c2;
    INT_T (mm, 1);
    polyvec_alloc (w1v, Rq, km), poly_alloc (vv, Rq), poly_alloc (c2, Rq);
    for (j = 0; j < DEG; j++)
      int_set_i64 (poly_get_coeff (vv, j), v[j]); /* [0, q), as poly_mod + poly_redp leave it */
    for (i = 0; i < km; i++)
      for (j = 0; j < DEG; j++)
        int_set_i64 (poly_get_coeff (polyvec_get_elem (w1v, i), j), w1[DEG * i + j]);
    polyvec_get_subvec (tt, F.tB, NQL, 1, 1), polyvec_mod (tt, tt), polyvec_redp (tt, tt);
    int_set_i64 (mm, (int64_t)S->m);
    coder_enc_begin (cs, buf);
    coder_enc_urandom3 (cs, tt, Rq->q, 42);
    coder_enc_urandom2 (cs, vv, Rq->q, 42);
    coder_enc_urandom3 (cs, w1v, mm, S->log2m);
    coder_enc_end (cs);
    shake128_init (hs);
    shake128_absorb (hs, hash1, 32);
    shake128_absorb (hs, buf, coder_get_offset (cs) >> 3);
    shake128_squeeze (hs, cseed, 32);
    shake128_clear (hs);
    poly_urandom_autostable (c2, 8, 5, cseed, 0);
    const int eq = pqz_err == PQZ_OK && poly_eq (F.c, c2);
    poly_free (c2), poly_free (vv), polyvec_free (w1v);
    if (!eq)
      return 0;
  }
  /* ||(z21, w - gamma w1)||^2 <= B^2: the whole z2, as LNP22 Fig. 18 and the honest prover (P6-Z21, lazer#26;
     lnp_quad_verify does the same). Upstream bounded only the w - gamma w1 (z22) part. */
  const uint64_t s21 = l2_sum (z21, DEG * m2r, S->Bsq);
  if (s21 > S->Bsq || !l2_le (wl, DEG * km, S->Bsq - s21))
    return 0;
  return pqz_err == PQZ_OK;
#undef F
}

#ifdef PQZ_TEST_HOOKS
/* ---------------------------------------------------------------- test hook (P6-SV diff harness only): this
   file's PRG against LaZer's (rng.c via intvec_urandom / intvec_brandom) and the FIPS-197 AES-256 vector.
   Returns the number of mismatches. */
int
pqz_sv_test_prg (unsigned iters)
{
  static const uint8_t k[32] = { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
  static const uint8_t pt[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  static const uint8_t ct[16] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                                  0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
  static const struct
  {
    uint64_t mod;
    unsigned bits;
  } md[3] = { { Q, 42 }, { 17, 5 }, { 1000, 10 } };
  uint8_t o[16], seed[32];
  prg_t g;
  int bad = 0;
  uint64_t x = 0x9E3779B97F4A7C15ULL;

  aes_tables (); /* the tables are built lazily; idempotent */
  prg_seed (&g, k);
  aes_enc (g.rk, pt, o);
  bad += memcmp (o, ct, 16) != 0;
  for (unsigned it = 0; it < iters; it++)
    {
      for (int i = 0; i < 32; i++)
        x ^= x << 13, x ^= x >> 7, x ^= x << 17, seed[i] = (uint8_t)x;
      const uint32_t dom = (uint32_t)(x >> 40);
      const unsigned n = 1 + (unsigned)(x % 300), w = 16 + (unsigned)(x >> 20) % 200 * 8;
      prg_seed (&g, seed);
      for (int m = 0; m < 3; m++)
        {
          uint64_t v[URND_MAX];
          INTVEC_T (r, URND_MAX, 1);
          INT_T (mod, 1);
          intvec_t rs;
          int_set_i64 (mod, (int64_t)md[m].mod);
          intvec_get_subvec (rs, r, 0, n, 1);
          intvec_urandom (rs, mod, md[m].bits, seed, dom);
          urandom (v, n, md[m].mod, md[m].bits, &g, dom);
          for (unsigned i = 0; i < n; i++)
            bad += (uint64_t)int_get_i64 (intvec_get_elem (rs, i)) != v[i];
        }
      {
        INTVEC_T (r, 2048, 1);
        intvec_t rs;
        uint8_t rows[2048 / 4];
        ctr_t s;
        intvec_get_subvec (rs, r, 0, w, 1);
        intvec_brandom (rs, 1, seed, dom);
        ctr_init (&s, &g, dom);
        ctr_read (&s, rows, w / 4);
        for (unsigned j = 0; j < w; j++)
          bad += int_get_i64 (intvec_get_elem (rs, j))
                 != (int64_t)((rows[j / 8] >> (j % 8)) & 1) - (int64_t)((rows[(w + j) / 8] >> ((w + j) % 8)) & 1);
      }
    }
  return bad;
}
#endif
