/*
 * P6-FS binding test (https://github.com/lazer-crypto/lazer/issues/28; see sz/README.md).
 *
 * Observes which bytes seed which Fiat-Shamir challenge in the two production verifiers, pqz_verify and
 * pqz_verify_fast, through the trace hook (-DPQZ_SZ_TRACE; lazer/lnp-tbox.c and src/pqz_sv.c). One honest R_REG
 * proof with a fixed rnd32, and four re-encodings of it with one field changed (pqz_test_mutate):
 *   h  : kind 7, h_0 coefficient 5 +1 (r1 & 12 == 0: not coefficient 0 or 32, so it passes the h check)
 *   z3 : kind 14, z3 coefficient +1 (within Bz3)
 *   z4 : kind 5 at the bound, z4 coefficient = +Bz4 (passes the l_inf check)
 *   tg : kind 15, tg (the commitment to g) coefficient +1 mod q (B-1, review B)
 * Every challenge must be drawn after every prover message it is combined with: the V4 / V3 seeds (kinds 2 / 3)
 * must differ between the honest and the z3-, z4- and tg-changed proofs, the mu seed (kind 5) between the honest and
 * the h-changed proof; the tg-changed proof must be rejected. A record that is not emitted (the verifier rejected before the challenge) counts as a failure,
 * never as "differ". The honest proof must verify. verify_fast must report pqz_sv.c's tagged kinds 12 / 13 / 15
 * (another path records the untagged ones: MISSING). Exit 0 = binding holds in both verifiers.
 *
 * Observation only: it builds no proof meant to verify and searches for none.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pqz.h"

extern void (*pqz_sz_trace_fn) (int kind, const uint8_t seed[32], uint64_t dom, int acc, const int64_t *v,
                                unsigned int n);
int pqz_test_mutate (uint8_t op, const uint8_t *proof, size_t len, unsigned kind, uint64_t r1, uint64_t r2,
                     uint8_t *out, size_t *outlen);

/* the first seed of kinds 2, 3, 5 (generic) and 12, 13, 15 (pqz_sv.c's tagged kinds) in one verifier call */
static struct
{
  int seen[16];
  uint8_t seed[16][32];
} cur;

static void
trace (int kind, const uint8_t seed[32], uint64_t dom, int acc, const int64_t *v, unsigned int n)
{
  (void)dom, (void)acc, (void)v, (void)n;
  if ((kind % 10 == 2 || kind % 10 == 3 || kind % 10 == 5) && kind < 16 && !cur.seen[kind])
    cur.seen[kind] = 1, memcpy (cur.seed[kind], seed, 32);
}

/* ---- the honest R_REG statement and witness of sz_trace.c ---- */
static uint64_t xs = 0x243F6A8885A308D3ULL;
static uint64_t
rnd (void)
{
  xs ^= xs >> 12, xs ^= xs << 25, xs ^= xs >> 27;
  return xs * 2685821657736338717ULL;
}
static int
cbd (int eta)
{
  int a = 0, b = 0;
  uint64_t r = rnd ();
  for (int i = 0; i < eta; i++)
    a += (r >> i) & 1, b += (r >> (32 + i)) & 1;
  return a - b;
}
static void
short8 (int8_t *x, unsigned n, int eta, int64_t bound)
{
  int64_t s;
  do
    {
      s = 0;
      for (unsigned i = 0; i < n; i++)
        x[i] = (int8_t)cbd (eta), s += x[i] * x[i];
    }
  while (s > bound * bound);
}
static void
short16 (int16_t *x, unsigned n, int eta, int64_t bound)
{
  int64_t s;
  do
    {
      s = 0;
      for (unsigned i = 0; i < n; i++)
        x[i] = (int16_t)cbd (eta), s += x[i] * x[i];
    }
  while (s > bound * bound);
}

static uint8_t stmt[PQZ_REG_STMT_BYTES];

static int
run (int fast, const uint8_t *proof, size_t len)
{
  memset (&cur, 0, sizeof cur);
  return fast ? pqz_verify_fast (PQZ_OP_REGISTER, stmt, sizeof stmt, proof, len)
              : pqz_verify (PQZ_OP_REGISTER, stmt, sizeof stmt, proof, len);
}

int
main (void)
{
  static uint8_t arena[(size_t)768 << 20];
  static uint8_t proof[PQZ_MAX_PROOF], mut[4][2 * PQZ_MAX_PROOF];
  int8_t s[2048];
  int16_t e[2048];
  uint8_t pk[PQZ_POLYVEC_BYTES], wit[PQZ_REG_WIT_BYTES], rnd32[32];
  size_t len = sizeof proof, mlen[4];
  const char *mname[4] = { "h", "z3", "z4", "tg" };
  const unsigned mkind[4] = { 7, 14, 5, 15 };
  const char *kname[6] = { "", "", "V4 seed", "V3 seed", "", "mu seed" };
  int fails = 0;

  if (pqz_init (arena, sizeof (arena)))
    return fprintf (stderr, "init failed\n"), 1;
  short8 (s, 2048, 1, 36);
  short16 (e, 2048, 20, 164);
  if (pqz_keypair_from_secret (s, e, pk))
    return fprintf (stderr, "keypair failed\n"), 1;
  memset (stmt, 0xA5, PQZ_PREFIX_BYTES);
  for (int i = 0; i < 32; i++)
    stmt[PQZ_PREFIX_BYTES + i] = (uint8_t)i;
  memcpy (stmt + PQZ_PREFIX_BYTES + 32, pk, PQZ_POLYVEC_BYTES);
  for (int j = 0; j < 2048; j++)
    {
      wit[j] = (uint8_t)s[j];
      wit[2048 + 2 * j] = (uint8_t)(uint16_t)e[j];
      wit[2048 + 2 * j + 1] = (uint8_t)((uint16_t)e[j] >> 8);
    }
  for (int i = 0; i < 32; i++)
    rnd32[i] = (uint8_t)(i * 31 + 7);
  if (pqz_prove (PQZ_OP_REGISTER, stmt, sizeof stmt, wit, sizeof wit, rnd32, proof, &len))
    return fprintf (stderr, "prove failed\n"), 1;

  /* r1 = 0: h_0 / z3_0 / z4_0, (r1 >> 8) even (z4 at the bound), r1 & 12 == 0; r2 = 0x105: coefficient 5, sign + */
  for (int m = 0; m < 4; m++)
    {
      mlen[m] = sizeof mut[m];
      if (!pqz_test_mutate (PQZ_OP_REGISTER, proof, len, mkind[m], 0, 0x105, mut[m], &mlen[m])
          || (mlen[m] == len && memcmp (mut[m], proof, len) == 0))
        return fprintf (stderr, "mutation %s failed\n", mname[m]), 1;
    }

  pqz_sz_trace_fn = trace;
  for (int fast = 0; fast < 2; fast++)
    {
      const char *vn = fast ? "verify_fast" : "verify";
      uint8_t hon[16][32];
      int hseen[16];
      int ok = run (fast, proof, len);
      memcpy (hon, cur.seed, sizeof hon), memcpy (hseen, cur.seen, sizeof hseen);
      printf ("P6-FS %s honest: %s\n", vn, ok == 1 ? "ACCEPT" : "REJECT (FAIL)");
      fails += ok != 1;
      for (int m = 0; m < 4; m++)
        {
          int okm = run (fast, mut[m], mlen[m]);
          if (m == 3 && okm == 1)
            printf ("P6-FS %s tg-mutated: ACCEPT (FAIL)\n", vn), fails++;
          for (int k = 2; k <= 5; k++)
            {
              if ((m == 0) != (k == 5) || k == 4)
                continue; /* h -> kind 5; z3, z4 -> kinds 2, 3 */
              const int t = k + 10 * fast; /* verify_fast must report pqz_sv.c's tagged kinds */
              const char *res = !hseen[t] || !cur.seen[t]           ? "MISSING (FAIL)"
                                : memcmp (hon[t], cur.seed[t], 32) ? "differ"
                                                                   : "EQUAL (FAIL)";
              printf ("P6-FS %s %s-mutated (%s) kind %d %s: honest %02x%02x%02x%02x mutated %02x%02x%02x%02x -> %s\n",
                      vn, mname[m], okm == 1 ? "accepted" : "rejected", t, kname[k], hon[t][0], hon[t][1],
                      hon[t][2], hon[t][3], cur.seed[t][0], cur.seed[t][1], cur.seed[t][2], cur.seed[t][3], res);
              fails += res[0] != 'd';
            }
        }
    }
  pqz_sz_trace_fn = 0;
  printf ("\nVERDICT: P6-FS Fiat-Shamir binding (lazer#28) %s (%d failed checks of 18)\n", fails ? "FAIL" : "ok",
          fails);
  return fails != 0;
}
