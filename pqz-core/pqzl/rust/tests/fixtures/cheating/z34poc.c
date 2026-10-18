/*
 * z34poc (tests/fixtures/cheating/z34poc.sh): cheating R_REG provers whose proofs pass the final Fiat-Shamir check
 * and break only the z3 l2 bound or the z4 l_inf bound, which are checked after it (sv/review/normpoc.c's pattern):
 *
 *   mode 0 honest    control: both verifiers accept
 *   mode 1 z3_over   ||z3||^2 above Bz3sqr -> both must reject
 *   mode 2 z4_over   ||z4||_inf above Bz4 -> both must reject
 *
 *   z34poc prove DIR    (linked with the patched prover, -DPQZ_Z34_POC) writes DIR/<case>.{stmt,proof}
 *   z34poc verify DIR   (linked with a verifier library) prints generic / fast accept for each file
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqz.h"

#ifdef PQZ_Z34_POC
extern int pqz_z34_mode;
#endif

static const char *const MODE[] = { "honest", "z3_over", "z4_over" };
#define NMODE 3

static uint64_t xs = 0x2545F4914F6CDD1DULL;
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
  static int8_t s[2048];
  static int16_t e[2048];
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
#ifdef PQZ_Z34_POC
          long ns, ne;
          do
            {
              ns = ne = 0;
              for (int j = 0; j < 2048; j++)
                s[j] = (int8_t)cbd (1), e[j] = (int16_t)cbd (20), ns += s[j] * s[j], ne += e[j] * e[j];
            }
          while (ns > 36 * 36 || ne > 164 * 164);
          memset (stmt, 0x5A, PQZ_PREFIX_BYTES);
          const uint8_t psid[32] = PQZ_PROOF_SYSTEM_ID;
          memcpy (stmt + 32, psid, 32);
          for (int i = 0; i < 32; i++)
            stmt[PQZ_PREFIX_BYTES + i] = (uint8_t)(i + 11 * k);
          pqz_keypair_from_secret (s, e, stmt + PQZ_PREFIX_BYTES + 32);
          for (int j = 0; j < 2048; j++)
            wit[j] = (uint8_t)s[j], wit[2048 + 2 * j] = (uint8_t)e[j], wit[2049 + 2 * j] = (uint8_t)((uint16_t)e[j] >> 8);
          uint8_t rnd32[32];
          for (int i = 0; i < 32; i++)
            rnd32[i] = (uint8_t)(k * 37 + i);
          pqz_z34_mode = k;
          int rc = pqz_prove (PQZ_OP_REGISTER, stmt, sl, wit, sizeof wit, rnd32, proof, &pl);
          pqz_z34_mode = 0;
          printf ("%-8s prove rc=%d proof %zu B\n", MODE[k], rc, pl);
          if (rc)
            continue;
          rw (argv[2], MODE[k], "stmt", stmt, &sl, 1);
          rw (argv[2], MODE[k], "proof", proof, &pl, 1);
          continue;
#else
          return fprintf (stderr, "prove needs -DPQZ_Z34_POC\n"), 2;
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
