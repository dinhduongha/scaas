/*
 * pqz-core keys and encryption from seeds (pq-zero-knowledge.md §4.2; P6e gap G4): CBD_eta, KeyGen(seed32),
 * Enc({(pk_j, m_j)}, seed_enc), Dec. Each attempt reads one SHAKE256 stream, tag || [set] || seed || be4(ctr), bits LSB-first
 * (FIPS 203 style): s then e (KeyGen), r, e1, then e2_j in recipient order (Enc); an attempt above a norm threshold
 * is resampled with the next counter, counter 64 is an error. The ring work is pqz_rel.c's (pqz_keypair_from_secret,
 * pqz_encrypt, pqz_decrypt_raw), so pqz_init must have run (else PQZ_ERR_INTERNAL). No malloc, no stdio; the arena
 * only through pqz_rel.c.
 */
#include "lazer.h"

#include "pqz.h"

#define N PQZ_N
#define DELTA PQZ_DELTA
#define MAXCTR 64

#ifdef PQZ_TEST_HOOKS
/* test-only norm thresholds (never in libpqz): test/pqz_keys_kat.c lowers them to pin the resample path and the
   counter-64 error, which the real thresholds (>= 10 s.d. above the mean norms) never reach */
int pqz_test_bs = PQZ_BETA_S, pqz_test_be = PQZ_BETA_E, pqz_test_b2 = PQZ_BETA_2;
#define BS pqz_test_bs
#define BE pqz_test_be
#define B2 pqz_test_b2
#else
#define BS PQZ_BETA_S /* the set's norm bounds (pqz_set.h) */
#define BE PQZ_BETA_E
#define B2 PQZ_BETA_2
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

/* tag || [u8(len(set)) || set] || seed || be4(ctr); the set's name for KeyGen only (KEYGEN-V2, review R2-C3) */
static void
stream_set (bits_t *b, const char *tag, unsigned taglen, int with_set, const uint8_t seed[32], uint32_t ctr)
{
  const uint8_t c4[4] = { (uint8_t)(ctr >> 24), (uint8_t)(ctr >> 16), (uint8_t)(ctr >> 8), (uint8_t)ctr };
  static const char set[] = PQZ_SET_NAME;
  const uint8_t setlen = (uint8_t)(sizeof set - 1);
  shake256_init (b->st);
  shake256_absorb (b->st, (const uint8_t *)tag, taglen);
  if (with_set)
    {
      shake256_absorb (b->st, &setlen, 1);
      shake256_absorb (b->st, (const uint8_t *)set, setlen);
    }
  shake256_absorb (b->st, seed, 32);
  shake256_absorb (b->st, c4, 4);
  b->nbits = 0;
}

static void
stream (bits_t *b, const char *tag, unsigned taglen, const uint8_t seed[32], uint32_t ctr)
{
  stream_set (b, tag, taglen, 0, seed, ctr);
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

/* every be8 coefficient < q (pq-zero-knowledge.md §5: anything else is NonCanonical); n a multiple of 8 (review
   round 2, Q-F: the twin of Rust fix C, chunks_exact) */
static int
canonical (const uint8_t *p, size_t n)
{
  int ok = n % 8 == 0;
  for (size_t k = 0; k + 8 <= n; k += 8)
    {
      uint64_t v = 0;
      for (int i = 0; i < 8; i++)
        v = (v << 8) | p[k + i];
      ok &= v < PQZ_Q;
    }
  return ok;
}

int
pqz_keygen (const uint8_t seed32[32], uint8_t pk[PQZ_POLYVEC_BYTES], int8_t s[PQZ_N], int16_t e[PQZ_N],
            unsigned *ctr_used)
{
  bits_t b;
  int rc = PQZ_ERR_REJECT;
  for (uint32_t ctr = 0; ctr < MAXCTR; ctr++)
    {
      stream_set (&b, "SCAAS-PQZ-KEYGEN-V2", 19, 1, seed32, ctr);
      int64_t ns = cbd8 (&b, s, N), ne = cbd16 (&b, e, N);
      stream_clear (&b);
      /* review E: the resample verdict is public (the counter is an output); the norms are not */
      int ok = (ns <= BS * BS) & (ne <= BE * BE);
      PQZ_CT_PUBLIC (&ok, sizeof ok);
      if (ok)
        {
          if (ctr_used)
            *ctr_used = ctr;
          rc = pqz_keypair_from_secret (s, e, pk);
          if (rc == PQZ_OK)
            return PQZ_OK;
          break;
        }
    }
  /* review R2-C10: no rejected or unused secret sample stays in the caller's buffers */
  explicit_bzero (s, PQZ_N), explicit_bzero (e, 2 * PQZ_N), explicit_bzero (pk, PQZ_POLYVEC_BYTES);
  return rc;
}

int
pqz_enc_seed_win (const uint8_t *const pks[], unsigned npk, const uint8_t win[], const uint8_t msgs[][16],
                  const uint8_t seed_enc[32], uint8_t u[PQZ_POLYVEC_BYTES], uint8_t vs[][PQZ_V_BYTES], int8_t r[PQZ_N],
                  int16_t e1[PQZ_N], int16_t e2[][16], unsigned *ctr_used)
{
  bits_t b;
  int bad = 0, rc = PQZ_ERR_REJECT;
  for (unsigned k = 0; k < npk; k++)
    {
      if (!canonical (pks[k], PQZ_POLYVEC_BYTES) || (win != NULL && win[k] >= 4))
        return PQZ_ERR_INPUT;
      for (unsigned i = 0; i < 16; i++)
        bad |= msgs[k][i] > 15; /* review E: the digits are secret, only the verdict is public */
    }
  PQZ_CT_PUBLIC (&bad, sizeof bad);
  if (bad)
    return PQZ_ERR_INPUT;
  for (uint32_t ctr = 0; ctr < MAXCTR; ctr++)
    {
      stream (&b, "SCAAS-PQZ-ENC-V1", 16, seed_enc, ctr);
      int ok = cbd8 (&b, r, N) <= BS * BS;
      ok &= cbd16 (&b, e1, N) <= BE * BE;
      for (unsigned k = 0; k < npk; k++)
        ok &= cbd16 (&b, e2[k], 16) <= B2 * B2;
      stream_clear (&b);
      PQZ_CT_PUBLIC (&ok, sizeof ok); /* review E: the resample verdict is public */
      if (ok)
        {
          if (ctr_used)
            *ctr_used = ctr;
          rc = pqz_encrypt_win (pks, npk, win, msgs, r, e1, (const int16_t (*)[16])e2, u, vs);
          if (rc == PQZ_OK)
            return PQZ_OK;
          break;
        }
    }
  /* review R2-C10: the encryption randomness of a rejected or failed attempt does not stay in the caller's buffers */
  explicit_bzero (r, PQZ_N), explicit_bzero (e1, 2 * PQZ_N), explicit_bzero (u, PQZ_POLYVEC_BYTES);
  for (unsigned k = 0; k < npk; k++)
    explicit_bzero (e2[k], 32), explicit_bzero (vs[k], PQZ_V_BYTES);
  return rc;
}

int
pqz_enc_seed (const uint8_t *const pks[], unsigned npk, const uint8_t msgs[][16], const uint8_t seed_enc[32],
              uint8_t u[PQZ_POLYVEC_BYTES], uint8_t vs[][PQZ_V_BYTES], int8_t r[PQZ_N], int16_t e1[PQZ_N],
              int16_t e2[][16], unsigned *ctr_used)
{
  return pqz_enc_seed_win (pks, npk, NULL, msgs, seed_enc, u, vs, r, e1, e2, ctr_used);
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
pqz_dec (const int8_t s[PQZ_N], const uint8_t ct[PQZ_POLYVEC_BYTES + PQZ_V_BYTES], int64_t M[16], int64_t noise[16])
{
  return pqz_dec_win (s, ct, 0, M, noise);
}

int
pqz_dec_win (const int8_t s[PQZ_N], const uint8_t ct[PQZ_POLYVEC_BYTES + PQZ_V_BYTES], unsigned win, int64_t M[16],
             int64_t noise[16])
{
  int64_t w[16];
  if (!canonical (ct, PQZ_POLYVEC_BYTES + PQZ_V_BYTES) || win >= 4)
    return PQZ_ERR_INPUT;
  int rc = pqz_decrypt_raw_win (s, ct, ct + PQZ_POLYVEC_BYTES, win, w);
  if (rc)
    {
      explicit_bzero (w, sizeof w); /* Q-B: every exit */
      return rc;
    }
  for (unsigned i = 0; i < 16; i++)
    {
      /* M = round(w / Delta) = floor((2w + Delta) / (2 Delta)), ties up (n2048-kmax1024: Delta odd, no ties; n2304-kmax4096: Delta even, and an
         encryption's |noise| < Delta / 2 never ties); branch-free: |w| < q/2 and Delta ~ q / 2^(MBITS + 2), so with
         SH = MBITS + 3, 2 Delta 2^SH ~ 4q, t = 2w + Delta + 2 Delta 2^SH > 0 and floor(t / (2 Delta)) = M + 2^SH.
         review E: the division is the fixed-step restoring division of pqz_mpn.h (w is secret; wasm32 keeps a 64-bit
         '/' as i64.div_u even by a constant) */
      mp_limb_t t = (uint64_t)(2 * w[i] + DELTA + 2 * DELTA * ((int64_t)1 << (PQZ_MBITS + 3))), d = 2 * DELTA;
      int64_t m = (int64_t)pqz__div (NULL, &t, 1, &d, 1) - ((int64_t)1 << (PQZ_MBITS + 3));
      M[i] = m, noise[i] = w[i] - DELTA * m;
    }
  explicit_bzero (w, sizeof w);
  return PQZ_OK;
}
