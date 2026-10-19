/*
 * PQZ rewrite of LaZer's discrete Gaussian sampler (upstream: double exp_small / BerExp / pow / log).
 *
 * Same construction as upstream: a sample of D_{Z, 1.55 * 2^s} is k * 2^s - u with u uniform in
 * [0, 2^s) and k from D_{Z, 1.55, c = u / 2^s}, drawn from the bimodal half-Gaussian CDF table CDF155
 * (upstream's) and accepted with probability exp(-x), x = ((k - c)^2 - (k - b)^2) / (2 * 1.55^2).
 * Changes: integer fixed-point x and exp (pqz_fixexp.h), a constant-time full scan of the CDF table,
 * per-iteration bits from the stream (upstream kept a static bit buffer across calls), a capped loop.
 * Upstream cannot reproduce these streams: KATs of masks are fork-generated (pq-zero-knowledge.md CTR-PQZ-09).
 */
#include "grandom.h"
#include "lazer.h"
#include "rng.h"

#include "pqz_fixexp.h"

#include <stdint.h>

#define PQZ_GAUSS_MAX_TRIES 256 /* P(reject) <= 0.6 per try; 256 tries fail with prob < 2^-180 */

typedef struct
{
  uint64_t hi, lo;
} z128;

static const z128 CDF155[]
    = { { 10894764499197476522ULL, 10804844707381617341ULL },
        { 4761708367981796450ULL, 6209732027000382074ULL },
        { 1476784279527800432ULL, 14108379346150813303ULL },
        { 316388870594767345ULL, 17827298407763885637ULL },
        { 46043503515468600ULL, 18385899657892021654ULL },
        { 4503729779335039ULL, 3860889375818664979ULL },
        { 294122444862326ULL, 13947176349836216550ULL },
        { 12769598070895ULL, 14321894682751135119ULL },
        { 367552986472ULL, 10286761328368440884ULL },
        { 7001273393ULL, 2287787188970898528ULL },
        { 88153536ULL, 17843977990435837663ULL },
        { 733119ULL, 12174894787802692461ULL },
        { 4024ULL, 18067426722645776197ULL },
        { 14ULL, 10764017821655913055ULL },
        { 0ULL, 643125733022530080ULL },
        { 0ULL, 1014291014134832ULL },
        { 0ULL, 1055215183460ULL },
        { 0ULL, 724109373ULL },
        { 0ULL, 327744ULL },
        { 0ULL, 98ULL },
        { 0ULL, 0ULL } };

#define DSS_Q62 ((uint64_t)959768162003618710ULL) /* 2^62 / (2 * 1.55^2) = 2^62 * 200 / 961 */

/* k from D_{Z,1.55,c}, c = u / 2^s; constant-time per try */
static int64_t
gaussian155 (rng_state_t state, uint64_t u, unsigned int s)
{
  for (int tries = 0; tries < PQZ_GAUSS_MAX_TRIES; tries++)
    {
      uint8_t buf[32];
      uint64_t w[4];
      int64_t k0 = 0, k, b;
      unsigned int z;

      rng_urandom (state, buf, sizeof (buf));
      for (z = 0; z < 4; z++)
        {
          uint64_t v = 0;
          for (int j = 0; j < 8; j++)
            v |= (uint64_t)buf[8 * z + j] << (8 * j);
          w[z] = v;
        }
      /* k0 = #{z : (hi, lo) < CDF155[z]} (the table decreases) */
      pqz_fx_u128 x128 = ((pqz_fx_u128)w[0] << 64) | w[1];
      for (z = 0; z < sizeof (CDF155) / sizeof (CDF155[0]); z++)
        k0 += (int64_t)(x128 < (((pqz_fx_u128)CDF155[z].hi << 64) | CDF155[z].lo));
      b = (int64_t)(w[3] & 1);
      k = ((-b) & (2 * k0)) - k0 + b; /* bimodal: b ? k0 + 1 : -k0 (upstream's formula) */

      /* x = ((k - c)^2 - (k - b)^2) / (2 * 1.55^2) = (b - c)(2k - b - c) / (2 * 1.55^2), in Q56 */
      int64_t f1 = b * ((int64_t)1 << s) - (int64_t)u;           /* (b - c) * 2^s */
      int64_t f2 = (2 * k - b) * ((int64_t)1 << s) - (int64_t)u; /* (2k - b - c) * 2^s */
      f1 *= (int64_t)1 << (56 - s);
      f2 *= (int64_t)1 << (56 - s);                     /* |f2| < 44 * 2^56 */
      pqz_fx_i128 x56 = ((pqz_fx_i128)f1 * f2) >> 56;  /* >= 0 */
      int64_t x = (int64_t)(((pqz_fx_u128)x56 * DSS_Q62) >> 62);

      uint64_t mant;
      int32_t e;
      pqz_exp_fp (-x, &mant, &e);
      /* PQZ (review E): the try count is public (class b): per try P(accept) = sum_k exp(-(k - c)^2 / (2 1.55^2)) /
         const, independent of the centre c up to 2^-68 (Poisson sum, 2 exp(-2 pi^2 1.55^2) ~ 2^-68), so the count
         carries no information on the sample */
      int acc = pqz_bernoulli_fp (w[2], mant, e);
      PQZ_CT_PUBLIC (&acc, sizeof (acc));
      if (acc)
        return k;
    }
  pqz_err_set (PQZ_ERR_REJECT);
  return 0;
}

/*
 * sample centered discrete gaussian with sigma = 1.55 * 2^log2o
 */
static void
_grandom_sample_i32 (int32_t *ret, unsigned int nelems, unsigned int log2o,
                    const uint8_t seed[32], uint64_t dom)
{
  rng_state_t state;
  unsigned int i, j;
  unsigned int outlen = CEIL (log2o * nelems, 8);
  uint8_t out[outlen + 1];
  uint32_t urand;

  _rng_init (state, seed, dom);
  _rng_urandom (state, out, outlen);

  for (i = 0; i < nelems; i++)
    {
      urand = 0;
      for (j = 0; j < log2o; j++)
        {
          const unsigned int q = (i * log2o + j) >> 3;
          const unsigned int r = (i * log2o + j) - (q << 3);

          urand |= (((out[q] & (1 << r)) >> r) << j);
        }
      int64_t k = gaussian155 (state, urand, log2o);
      ret[i] = (int32_t)((k * ((int64_t)1 << log2o)) - (int64_t)urand);
    }

  _rng_clear (state);
}

/*
 * sample centered discrete gaussian with sigma = 1.55 * 2^log2o (log2o <= 56)
 */
static void
_grandom_sample (int_t z, unsigned int log2o, const uint8_t seed[32],
                uint64_t dom)
{
  rng_state_t state;
  uint8_t buf[8] = { 0 };
  uint64_t u = 0;

  ERR (log2o > 56, "%s", "log2o");
  _rng_init (state, seed, dom);
  _rng_urandom (state, buf, CEIL (log2o, 8));
  for (int j = 0; j < 8; j++)
    u |= (uint64_t)buf[j] << (8 * j);
  u &= ((uint64_t)1 << log2o) - 1;
  int64_t k = gaussian155 (state, u, log2o);
  _rng_clear (state);

  int_set_i64 (z, k * ((int64_t)1 << log2o) - (int64_t)u);
}
