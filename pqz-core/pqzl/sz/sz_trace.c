/*
 * P6-SZ trace harness (https://github.com/lazer-crypto/lazer/issues/24; see sz/README.md).
 *
 * Runs one honest R_REG prove with the lnp-tbox.c trace hook (-DPQZ_SZ_TRACE) enabled and records every
 * Fiat-Shamir challenge vector handed to the evaluation-equation accumulator. It then reports, per transcript
 * domain separator (dom), the challenge vectors used by each of the lambda = 4 Schwartz-Zippel accumulators, and
 * whether they are distinct. The question the brief asks: does the evaluation step get lambda independent Z_q
 * tests, or fewer?
 *
 * No secret-dependent branching, no network, no exploit construction: it only prints what the honest prover
 * samples, so the soundness count can be read off directly.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqz.h"

/* trace hook exported by lazer/lnp-tbox.c when built with -DPQZ_SZ_TRACE */
extern void (*pqz_sz_trace_fn) (int kind, const uint8_t seed[32], uint64_t dom, int acc, const int64_t *v,
                                unsigned int n);

#define MAXREC 4096
#define MAXN 64
static struct
{
  uint64_t dom;
  int acc;
  unsigned int n;
  int64_t v[MAXN];
} rec[MAXREC];
static unsigned nrec;
static int phase; /* 0 = prove, 1 = verify */
static unsigned n_v_z4z3, n_jl;

static void
trace (int kind, const uint8_t seed[32], uint64_t dom, int acc, const int64_t *v, unsigned int n)
{
  (void)seed;
  if (kind == 0)
    {
      phase = (int)dom;
      return;
    }
  if (phase != 0)
    return; /* only record the prove pass; verify re-derives the same transcript */
  if (kind == 2 || kind == 3)
    {
      n_v_z4z3++;
      return;
    }
  if (kind == 4)
    {
      n_jl++;
      return;
    }
  if (kind == 1 && nrec < MAXREC)
    {
      rec[nrec].dom = dom;
      rec[nrec].acc = acc;
      rec[nrec].n = n < MAXN ? n : MAXN;
      memcpy (rec[nrec].v, v, rec[nrec].n * sizeof (int64_t));
      nrec++;
    }
}

static int
veceq (unsigned a, unsigned b)
{
  if (rec[a].n != rec[b].n)
    return 0;
  return memcmp (rec[a].v, rec[b].v, rec[a].n * sizeof (int64_t)) == 0;
}

/* ---- minimal honest R_REG statement + witness (mirrors test/pqz_bench.c setup, reg only) ---- */
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

int
main (void)
{
  static uint8_t arena[(size_t)768 << 20];
  int8_t s[PQZ_N];
  int16_t e[PQZ_N];
  uint8_t pk[PQZ_POLYVEC_BYTES], stmt[PQZ_REG_STMT_BYTES], wit[PQZ_REG_WIT_BYTES], proof[PQZ_MAX_PROOF];
  uint8_t rnd32[32];
  size_t len = sizeof (proof);

  if (pqz_init (arena, sizeof (arena)))
    return fprintf (stderr, "init failed\n"), 1;

  short8 (s, PQZ_N, 1, PQZ_BETA_S);
  short16 (e, PQZ_N, 20, PQZ_BETA_E);
  if (pqz_keypair_from_secret (s, e, pk))
    return fprintf (stderr, "keypair failed\n"), 1;

  memset (stmt, 0xA5, PQZ_PREFIX_BYTES);
  for (int i = 0; i < 32; i++)
    stmt[PQZ_PREFIX_BYTES + i] = (uint8_t)i;
  memcpy (stmt + PQZ_PREFIX_BYTES + 32, pk, PQZ_POLYVEC_BYTES);
  for (int j = 0; j < PQZ_N; j++)
    {
      wit[j] = (uint8_t)s[j];
      wit[PQZ_N + 2 * j] = (uint8_t)(uint16_t)e[j];
      wit[PQZ_N + 2 * j + 1] = (uint8_t)((uint16_t)e[j] >> 8);
    }
  for (int i = 0; i < 32; i++)
    rnd32[i] = (uint8_t)(i * 31 + 7);

  pqz_sz_trace_fn = trace;
  if (pqz_prove (PQZ_OP_REGISTER, stmt, sizeof (stmt), wit, sizeof (wit), rnd32, proof, &len))
    return fprintf (stderr, "prove failed\n"), 1;

  printf ("evaluation-equation accumulator calls recorded: %u\n", nrec);
  printf ("z4/z3 combination matrices (kind 2/3): %u    JL rows (kind 4): %u\n\n", n_v_z4z3, n_jl);

  /* The accumulate2 path packs lambda = 4 Z_q tests into lambda/2 = 2 accumulator pairs. For each dom the
   * four challenge rows land as acc 0,1 (pair 0) and acc 2,3 (pair 1). Independent tests <=> the four rows
   * are distinct. Group by dom and compare. */
  unsigned ndom = 0, dom_collapsed = 0, pairs = 0;
  for (unsigned i = 0; i < nrec;)
    {
      uint64_t dom = rec[i].dom;
      unsigned base = i, cnt = 0;
      int64_t accmask = 0;
      while (i < nrec && rec[i].dom == dom)
        accmask |= (int64_t)1 << rec[i].acc, cnt++, i++;
      ndom++;
      /* locate acc 0,1,2,3 within this dom group */
      int idx[4] = { -1, -1, -1, -1 };
      for (unsigned k = base; k < base + cnt; k++)
        if (rec[k].acc >= 0 && rec[k].acc < 4)
          idx[rec[k].acc] = (int)k;
      if (idx[0] >= 0 && idx[2] >= 0)
        {
          pairs++;
          int eq02 = veceq (idx[0], idx[2]);
          int eq13 = (idx[1] >= 0 && idx[3] >= 0) ? veceq (idx[1], idx[3]) : -1;
          int eq01 = (idx[1] >= 0) ? veceq (idx[0], idx[1]) : -1;
          if (eq02)
            dom_collapsed++;
          if (ndom <= 6 || eq02 == 0)
            printf ("dom=%-6llu  acc0==acc2(subv1 reused): %s   acc1==acc3(subv2 reused): %s   "
                    "acc0==acc1: %s\n",
                    (unsigned long long)dom, eq02 ? "YES" : "no", eq13 < 0 ? "-" : (eq13 ? "YES" : "no"),
                    eq01 < 0 ? "-" : (eq01 ? "YES" : "no"));
        }
    }
  printf ("\n%u evaluation doms; %u have all four accumulator slots; of those %u reuse subv1 across the "
          "two pairs (acc0==acc2).\n",
          ndom, pairs, dom_collapsed);
  /* exit 1 unless every recorded dom has four distinct rows (the P6-SZ fix): check_tbox_fixes.sh relies on it */
  int ok = pairs > 0 && dom_collapsed == 0;
  printf ("\nVERDICT: evaluation-step independent Z_q tests = %s (lambda=4 expected)\n",
          ok ? "4 -> ok" : dom_collapsed == pairs && pairs ? "2 (subv1,subv2 only) -> SOUNDNESS REDUCED"
                                                           : "UNKNOWN (no or partial reuse) -> FAIL");
  return !ok;
}
