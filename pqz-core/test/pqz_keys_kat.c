/*
 * Keys KAT of pqz_keys.c (P6e Task 3): JSON lines for the independent Python check
 * (smartcontracts/vectors/pqz/pqz_kat.py --c-keys <file>) and a round trip.
 *   pqz_keys_kat [n_roundtrip]     (default 1000)
 * 1. SHAKE256 (lazer/shake128.c, rate 136) on 10 inputs, absorbed and squeezed in two parts each;
 * 2. KeyGen on 20 seeds (seed_i[j] = 31 i + j), the pk as SHAKE256(pk) (32 B); Enc of two values to recipients i and
 *    i + 1 (seed_enc_i[j] = 17 i + j + 1), u as SHAKE256(u), both v in full, Dec by recipient i (M, noise);
 * 3. Dec(Enc(m)) = m with |noise| <= B_FRESH = 11,872 (pq-zether.md §4.3) for n_roundtrip seeds.
 */
#include "lazer.h"

#include "pqz.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARENA ((size_t)64 << 20)
#define B_FRESH 11872

static void
hex (const uint8_t *p, size_t n)
{
  for (size_t i = 0; i < n; i++)
    printf ("%02x", p[i]);
}

static void
sh256 (uint8_t out[32], const uint8_t *in, size_t n)
{
  shake128_state_t st;
  shake256_init (st);
  shake256_absorb (st, in, n);
  shake256_squeeze (st, out, 32);
  shake256_clear (st);
}

static void
digits (uint8_t m[16], uint64_t x)
{
  for (int i = 0; i < 16; i++)
    m[i] = (uint8_t)((x >> (4 * i)) & 15);
}

static uint64_t
mix (uint64_t x) /* splitmix64 */
{
  x += 0x9E3779B97F4A7C15ULL;
  x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
  x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
  return x ^ (x >> 31);
}

static void
ints (const int64_t *v, int n)
{
  for (int i = 0; i < n; i++)
    printf ("%s%lld", i ? ", " : "", (long long)v[i]);
}

#define NK 20
static uint8_t pk[NK][PQZ_POLYVEC_BYTES], seed[NK][32];
static int8_t s[NK][2048];
static int16_t e[NK][2048];

int
main (int argc, char **argv)
{
  int nrt = argc > 1 ? atoi (argv[1]) : 1000, fails = 0;
  static uint8_t in[5000], out[1000], out2[1000];
  static uint8_t u[PQZ_POLYVEC_BYTES], ct[PQZ_POLYVEC_BYTES + PQZ_V_BYTES], vs[2][PQZ_V_BYTES];
  static int8_t r[2048];
  static int16_t e1[2048], e2[2][16];
  uint8_t h[32], m[2][16], se[32];
  int64_t M[16], noise[16];
  unsigned ctr;

  if (pqz_init (malloc (ARENA), ARENA) != 0)
    {
      printf ("{\"error\": \"init\"}\n");
      return 1;
    }
  /* 1. SHAKE256 */
  static const unsigned IL[10] = { 0, 1, 31, 135, 136, 137, 271, 272, 1000, 4999 };
  static const unsigned OL[10] = { 32, 64, 135, 136, 137, 272, 300, 500, 32, 1000 };
  for (int c = 0; c < 10; c++)
    {
      shake128_state_t st;
      for (unsigned i = 0; i < IL[c]; i++)
        in[i] = (uint8_t)(i * 7 + c);
      shake256_init (st);
      shake256_absorb (st, in, IL[c] / 3);
      shake256_absorb (st, in + IL[c] / 3, IL[c] - IL[c] / 3);
      shake256_squeeze (st, out, OL[c] / 2);
      shake256_squeeze (st, out + OL[c] / 2, OL[c] - OL[c] / 2);
      shake256_clear (st);
      sh256 (out2, in, IL[c]); /* one-shot: the first 32 bytes must agree */
      fails += memcmp (out, out2, 32) != 0;
      printf ("{\"shake256\": {\"in\": \"");
      hex (in, IL[c]);
      printf ("\", \"outlen\": %u, \"out\": \"", OL[c]);
      hex (out, OL[c]);
      printf ("\"}}\n");
    }
  /* 2. KeyGen, Enc, Dec on 20 seeds */
  for (int i = 0; i < NK; i++)
    {
      for (int j = 0; j < 32; j++)
        seed[i][j] = (uint8_t)(31 * i + j);
      int rc = pqz_keygen (seed[i], pk[i], s[i], e[i], &ctr);
      fails += rc != 0;
      sh256 (h, pk[i], PQZ_POLYVEC_BYTES);
      printf ("{\"keygen\": {\"seed\": \"");
      hex (seed[i], 32);
      printf ("\", \"ctr\": %u, \"rc\": %d, \"pk_shake256\": \"", ctr, rc);
      hex (h, 32);
      printf ("\"}}\n");
    }
  for (int i = 0; i < NK; i++)
    {
      const int t = (i + 1) % NK;
      const uint64_t v[2] = { mix (i), i == 0 ? ~(uint64_t)0 : mix (i) >> (i % 64) };
      const uint8_t *pks[2] = { pk[i], pk[t] };
      for (int j = 0; j < 32; j++)
        se[j] = (uint8_t)(17 * i + j + 1);
      digits (m[0], v[0]), digits (m[1], v[1]);
      int rc = pqz_enc_seed (pks, 2, (const uint8_t (*)[16])m, se, u, vs, r, e1, e2, &ctr);
      memcpy (ct, u, PQZ_POLYVEC_BYTES), memcpy (ct + PQZ_POLYVEC_BYTES, vs[0], PQZ_V_BYTES);
      rc |= pqz_dec (s[i], ct, M, noise);
      fails += rc != 0;
      for (int k = 0; k < 16; k++)
        fails += M[k] != m[0][k];
      sh256 (h, u, PQZ_POLYVEC_BYTES);
      printf ("{\"enc\": {\"seed_enc\": \"");
      hex (se, 32);
      printf ("\", \"recipients\": [\"");
      hex (seed[i], 32);
      printf ("\", \"");
      hex (seed[t], 32);
      printf ("\"], \"values\": [%llu, %llu], \"ctr\": %u, \"rc\": %d, \"u_shake256\": \"", (unsigned long long)v[0],
              (unsigned long long)v[1], ctr, rc);
      hex (h, 32);
      printf ("\", \"v\": [\"");
      hex (vs[0], PQZ_V_BYTES);
      printf ("\", \"");
      hex (vs[1], PQZ_V_BYTES);
      printf ("\"], \"dec\": {\"M\": [");
      ints (M, 16);
      printf ("], \"noise\": [");
      ints (noise, 16);
      printf ("]}}}\n");
    }
  /* 3. round trip; non-canonical inputs rejected */
  int64_t maxn = 0;
  unsigned maxctr = 0;
  for (int i = 0; i < nrt; i++)
    {
      uint8_t sd[32], kp[PQZ_POLYVEC_BYTES];
      for (int j = 0; j < 4; j++)
        {
          uint64_t x = mix ((uint64_t)i * 4 + j + 1000);
          memcpy (sd + 8 * j, &x, 8), x = mix (x);
          memcpy (se + 8 * j, &x, 8);
        }
      unsigned c1 = 0, c2 = 0;
      int rc = pqz_keygen (sd, kp, s[0], e[0], &c1);
      const uint8_t *pks[1] = { kp };
      const uint64_t v = mix ((uint64_t)i);
      digits (m[0], v);
      rc |= pqz_enc_seed (pks, 1, (const uint8_t (*)[16])m, se, u, vs, r, e1, e2, &c2);
      memcpy (ct, u, PQZ_POLYVEC_BYTES), memcpy (ct + PQZ_POLYVEC_BYTES, vs[0], PQZ_V_BYTES);
      rc |= pqz_dec (s[0], ct, M, noise);
      int bad = rc != 0;
      for (int k = 0; k < 16; k++)
        {
          bad |= M[k] != m[0][k] || noise[k] > B_FRESH || noise[k] < -B_FRESH;
          maxn = noise[k] > maxn ? noise[k] : -noise[k] > maxn ? -noise[k] : maxn;
        }
      maxctr = c1 > maxctr ? c1 : c2 > maxctr ? c2 : maxctr;
      fails += bad;
    }
  memset (ct + PQZ_POLYVEC_BYTES - 8, 0xff, 8); /* a u coefficient >= q */
  int nc = pqz_dec (s[0], ct, M, noise) != 0;
  memset (pk[0], 0xff, 8); /* a pk coefficient >= q */
  const uint8_t *pkx[1] = { pk[0] }, *pky[1] = { pk[1] };
  nc += pqz_enc_seed (pkx, 1, (const uint8_t (*)[16])m, se, u, vs, r, e1, e2, &ctr) != 0;
  m[0][3] = 16; /* a digit >= 16 */
  nc += pqz_enc_seed (pky, 1, (const uint8_t (*)[16])m, se, u, vs, r, e1, e2, &ctr) != 0;
  fails += nc != 3;
  printf ("{\"roundtrip\": %d, \"max_abs_noise\": %lld, \"bound\": %d, \"max_ctr\": %u, \"noncanonical_rejected\": %d, "
          "\"fails\": %d}\n",
          nrt, (long long)maxn, B_FRESH, maxctr, nc, fails);
  return fails != 0;
}
