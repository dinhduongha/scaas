/*
 * Review PoC (docs/reviews/specs/2026-10-13-pqz-sv-review.md): cheating R_REG provers whose proofs pass the final
 * Fiat-Shamir check and differ from an honest proof only in a norm that is checked after it. Mutation testing cannot
 * reach these checks (a mutated proof fails the hash first), so they are exercised here with proofs from a patched
 * prover (sv/review/normpoc_hooks.h on a copy of lazer/lnp-quad.c, built by sv/review/review.sh):
 *
 *   mode 0 honest     control: both verifiers accept
 *   mode 1 z1_over    ||z1||^2 above lnp_quad_verify's bound -> both must reject (and accept with that check removed)
 *   mode 2 z21_big    ||z21||^2 far above Bsq (the bound the codegen derives for the whole z2 = (z21, z22))
 *   mode 3 w_over     ||w - gamma w1||^2 above Bsq -> both must reject (and accept with that check removed)
 *
 *   normpoc prove DIR     (linked with the patched prover) writes DIR/<mode>.{stmt,proof}
 *   normpoc verify DIR    (linked with a verifier library) prints generic / fast accept for each file
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqz.h"

#ifdef PQZ_NORM_POC
#include "lazer.h"
#include "pqz_reg_params.h" /* the set's R_REG Bsq (build/include) */
extern int pqz_poc_mode;
extern int pqz_poc_shift;
extern int64_t pqz_poc_z21sq;
#endif

static const char *const MODE[] = { "honest", "z1_over", "z21_big", "w_over" };
#define NMODE 4

static uint64_t xs = 0x9E3779B97F4A7C15ULL;
static int
cbd (int eta)
{
  xs ^= xs >> 12, xs ^= xs << 25, xs ^= xs >> 27;
  uint64_t r = xs * 2685821657736338717ULL;
  int a = 0, b = 0;
  for (int i = 0; i < eta; i++)
    a += (r >> i) & 1, b += (r >> (32 + i)) & 1;
  return a - b;
}

static int
rw (const char *dir, const char *c, const char *ext, uint8_t *buf, size_t *len, int wr)
{
  char path[512];
  snprintf (path, sizeof path, "%s/%s.%s", dir, c, ext);
  FILE *f = fopen (path, wr ? "wb" : "rb");
  if (!f)
    return 0;
  if (wr)
    fwrite (buf, 1, *len, f);
  else
    *len = fread (buf, 1, *len, f);
  fclose (f);
  return 1;
}

int
main (int argc, char **argv)
{
  static uint8_t stmt[PQZ_REG_STMT_BYTES], wit[PQZ_REG_WIT_BYTES], proof[PQZ_MAX_PROOF];
  static int8_t s[PQZ_N];
  static int16_t e[PQZ_N];
  size_t arena_len = (size_t)512 << 20;
  void *arena = malloc (arena_len);
  if (argc < 3 || !arena || pqz_init (arena, arena_len))
    return fprintf (stderr, "usage: %s prove|verify DIR\n", argv[0]), 2;
  const int prove = !strcmp (argv[1], "prove");
  for (int k = 0; k < NMODE; k++)
    {
      size_t sl = sizeof stmt, pl = sizeof proof;
      if (prove)
        {
#ifdef PQZ_NORM_POC
          long ns, ne;
          do
            {
              ns = ne = 0;
              for (int j = 0; j < PQZ_N; j++)
                s[j] = (int8_t)cbd (1), e[j] = (int16_t)cbd (20), ns += s[j] * s[j], ne += e[j] * e[j];
            }
          while (ns > PQZ_BETA_S * PQZ_BETA_S || ne > PQZ_BETA_E * PQZ_BETA_E);
          memset (stmt, 0xA5, PQZ_PREFIX_BYTES);
          const uint8_t psid[32] = PQZ_PROOF_SYSTEM_ID;
          memcpy (stmt + 32, psid, 32);
          for (int i = 0; i < 32; i++)
            stmt[PQZ_PREFIX_BYTES + i] = (uint8_t)(i + 7 * k);
          pqz_keypair_from_secret (s, e, stmt + PQZ_PREFIX_BYTES + 32);
          for (int j = 0; j < PQZ_N; j++)
            wit[j] = (uint8_t)s[j], wit[PQZ_N + 2 * j] = (uint8_t)e[j], wit[PQZ_N + 1 + 2 * j] = (uint8_t)((uint16_t)e[j] >> 8);
          uint8_t rnd32[32];
          for (int i = 0; i < 32; i++)
            rnd32[i] = (uint8_t)(k * 31 + i);
          /* mode 2: y21 << 7, or the largest shift whose proof fits PQZ_MAX_PROOF (a larger q encodes z21 wider) */
          int rc;
          for (pqz_poc_shift = 7;; pqz_poc_shift--)
            {
              pqz_poc_mode = k;
              pqz_poc_z21sq = 0;
              rc = pqz_prove (PQZ_OP_REGISTER, stmt, sl, wit, sizeof wit, rnd32, proof, &pl);
              pqz_poc_mode = 0;
              if (rc == 0 || k != 2 || pqz_poc_shift == 1)
                break;
            }
          printf ("%-8s prove rc=%d proof %zu B", MODE[k], rc, pl);
          if (k == 2)
            printf ("  y21 << %d: ||z21||^2 = %lld (%.1fx the set's R_REG Bsq %llu)", pqz_poc_shift,
                    (long long)pqz_poc_z21sq, pqz_poc_z21sq / (double)pqz_reg_Bsq_limbs[0],
                    (unsigned long long)pqz_reg_Bsq_limbs[0]);
          printf ("\n");
          if (rc)
            continue;
          rw (argv[2], MODE[k], "stmt", stmt, &sl, 1);
          rw (argv[2], MODE[k], "proof", proof, &pl, 1);
          continue;
#else
          return fprintf (stderr, "prove needs -DPQZ_NORM_POC\n"), 2;
#endif
        }
      if (!rw (argv[2], MODE[k], "stmt", stmt, &sl, 0) || !rw (argv[2], MODE[k], "proof", proof, &pl, 0))
        {
          printf ("%-8s (no proof file)\n", MODE[k]);
          continue;
        }
      int g = pqz_verify (PQZ_OP_REGISTER, stmt, sl, proof, pl);
      int f = pqz_verify_fast (PQZ_OP_REGISTER, stmt, sl, proof, pl);
      printf ("%-8s generic %s  fast %s%s\n", MODE[k], g ? "ACCEPT" : "REJECT", f ? "ACCEPT" : "REJECT",
              g != f ? "  <-- DISAGREE" : "");
    }
  return 0;
}
