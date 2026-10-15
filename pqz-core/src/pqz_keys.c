/*
 * pqz-core keys and encryption from seeds (pq-zether.md §4.2; P6e gap G4): CBD_eta, KeyGen(seed32),
 * Enc({(pk_j, m_j)}, seed_enc), Dec. Each attempt reads one SHAKE256 stream, tag || seed || be4(ctr), bits LSB-first
 * (FIPS 203 style): s then e (KeyGen), r, e1, then e2_j in recipient order (Enc); an attempt above a norm threshold
 * is resampled with the next counter, counter 64 is an error. The ring work is pqz_rel.c's (pqz_keypair_from_secret,
 * pqz_encrypt, pqz_decrypt_raw), so pqz_init must have run (else PQZ_ERR_INTERNAL). No malloc, no stdio; the arena
 * only through pqz_rel.c.
 */
#include "lazer.h"

#include "pqz.h"

#define N 2048
#define DELTA ((int64_t)((1 << 26) - 1))
#define MAXCTR 64

#ifdef PQZ_TEST_HOOKS
/* test-only norm thresholds (never in libpqz): test/pqz_keys_kat.c lowers them to pin the resample path and the
   counter-64 error, which the real thresholds (>= 10 s.d. above the mean norms) never reach */
int pqz_test_bs = 36, pqz_test_be = 164, pqz_test_b2 = 64;
#define BS pqz_test_bs
#define BE pqz_test_be
#define B2 pqz_test_b2
#else
#define BS 36
#define BE 164
#define B2 64
#endif

typedef struct
{
  shake128_state_t st; /* SHAKE256 on the same state type (lazer/shake128.c) */
  unsigned byte, nbits;
} bits_t;

static void
stream_clear (bits_t *b)
{
  shake128_clear (b->st);
  b->byte = b->nbits = 0;
}

static void
stream (bits_t *b, const char *tag, unsigned taglen, const uint8_t seed[32], uint32_t ctr)
{
  const uint8_t c4[4] = { (uint8_t)(ctr >> 24), (uint8_t)(ctr >> 16), (uint8_t)(ctr >> 8), (uint8_t)ctr };
  shake256_init (b->st);
  shake256_absorb (b->st, (const uint8_t *)tag, taglen);
  shake256_absorb (b->st, seed, 32);
  shake256_absorb (b->st, c4, 4);
  b->nbits = 0;
}

static unsigned
bit (bits_t *b)
{
  if (b->nbits == 0)
    {
      uint8_t x;
      shake256_squeeze (b->st, &x, 1);
      b->byte = x, b->nbits = 8;
    }
  unsigned v = b->byte & 1;
  b->byte >>= 1, b->nbits--;
  return v;
}

/* CBD_eta: a = sum of eta bits, b = sum of the next eta bits, a - b */
static int
cbd (bits_t *b, int eta)
{
  int a = 0, c = 0;
  for (int i = 0; i < eta; i++)
    a += (int)bit (b);
  for (int i = 0; i < eta; i++)
    c += (int)bit (b);
  return a - c;
}

static int64_t
cbd8 (bits_t *b, int8_t *x, unsigned n)
{
  int64_t s = 0;
  for (unsigned i = 0; i < n; i++)
    x[i] = (int8_t)cbd (b, 1), s += x[i] * x[i];
  return s;
}

static int64_t
cbd16 (bits_t *b, int16_t *x, unsigned n)
{
  int64_t s = 0;
  for (unsigned i = 0; i < n; i++)
    x[i] = (int16_t)cbd (b, 20), s += x[i] * x[i];
  return s;
}

/* every be8 coefficient < q (pq-zether.md §5: anything else is NonCanonical) */
static int
canonical (const uint8_t *p, size_t n)
{
  int ok = 1;
  for (size_t k = 0; k < n; k += 8)
    {
      uint64_t v = 0;
      for (int i = 0; i < 8; i++)
        v = (v << 8) | p[k + i];
      ok &= v < PQZ_Q;
    }
  return ok;
}

int
pqz_keygen (const uint8_t seed32[32], uint8_t pk[PQZ_POLYVEC_BYTES], int8_t s[2048], int16_t e[2048],
            unsigned *ctr_used)
{
  bits_t b;
  for (uint32_t ctr = 0; ctr < MAXCTR; ctr++)
    {
      stream (&b, "SCAAS-PQZ-KEYGEN-V1", 19, seed32, ctr);
      int64_t ns = cbd8 (&b, s, N), ne = cbd16 (&b, e, N);
      stream_clear (&b);
      if (ns <= BS * BS && ne <= BE * BE)
        {
          if (ctr_used)
            *ctr_used = ctr;
          return pqz_keypair_from_secret (s, e, pk);
        }
    }
  return PQZ_ERR_REJECT;
}

int
pqz_enc_seed (const uint8_t *const pks[], unsigned npk, const uint8_t msgs[][16], const uint8_t seed_enc[32],
              uint8_t u[PQZ_POLYVEC_BYTES], uint8_t vs[][PQZ_V_BYTES], int8_t r[2048], int16_t e1[2048],
              int16_t e2[][16], unsigned *ctr_used)
{
  bits_t b;
  for (unsigned k = 0; k < npk; k++)
    {
      if (!canonical (pks[k], PQZ_POLYVEC_BYTES))
        return PQZ_ERR_INPUT;
      for (unsigned i = 0; i < 16; i++)
        if (msgs[k][i] > 15)
          return PQZ_ERR_INPUT;
    }
  for (uint32_t ctr = 0; ctr < MAXCTR; ctr++)
    {
      stream (&b, "SCAAS-PQZ-ENC-V1", 16, seed_enc, ctr);
      int ok = cbd8 (&b, r, N) <= BS * BS;
      ok &= cbd16 (&b, e1, N) <= BE * BE;
      for (unsigned k = 0; k < npk; k++)
        ok &= cbd16 (&b, e2[k], 16) <= B2 * B2;
      stream_clear (&b);
      if (ok)
        {
          if (ctr_used)
            *ctr_used = ctr;
          return pqz_encrypt (pks, npk, msgs, r, e1, (const int16_t (*)[16])e2, u, vs);
        }
    }
  return PQZ_ERR_REJECT;
}

/* group seed of R_TXM (P6-ANON D13): g = 0 -> seed_enc, else SHAKE256("SCAAS-PQZ-ENC-GROUP-V1" || seed_enc || be4(g)) */
void
pqz_enc_group_seed (const uint8_t seed_enc[32], unsigned g, uint8_t out[32])
{
  bits_t b;
  if (g == 0)
    {
      memcpy (out, seed_enc, 32);
      return;
    }
  stream (&b, "SCAAS-PQZ-ENC-GROUP-V1", 22, seed_enc, g);
  shake256_squeeze (b.st, out, 32);
  stream_clear (&b);
}

int
pqz_dec (const int8_t s[2048], const uint8_t ct[PQZ_POLYVEC_BYTES + PQZ_V_BYTES], int64_t M[16], int64_t noise[16])
{
  int64_t w[16];
  if (!canonical (ct, PQZ_POLYVEC_BYTES + PQZ_V_BYTES))
    return PQZ_ERR_INPUT;
  int rc = pqz_decrypt_raw (s, ct, ct + PQZ_POLYVEC_BYTES, w);
  if (rc)
    return rc;
  for (unsigned i = 0; i < 16; i++)
    {
      /* M = round(w / Delta) = floor((2w + Delta) / (2 Delta)), no ties (Delta odd); branch-free: |w| < q/2 < 2^41, so
         t = 2w + Delta + 2 Delta 2^17 > 0, and floor(t / (2 Delta)) = M + 2^17 (one unsigned division by a constant) */
      uint64_t t = (uint64_t)(2 * w[i] + DELTA + 2 * DELTA * ((int64_t)1 << 17));
      int64_t m = (int64_t)(t / (uint64_t)(2 * DELTA)) - ((int64_t)1 << 17);
      M[i] = m, noise[i] = w[i] - DELTA * m;
    }
  explicit_bzero (w, sizeof w);
  return PQZ_OK;
}
