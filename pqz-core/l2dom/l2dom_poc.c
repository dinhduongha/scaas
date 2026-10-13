/*
 * l2dom PoC (P6-L2, https://github.com/lazer-crypto/lazer/issues/25): does the tbox verifier enforce each exact-l2 bound separately?
 * R_REG proves pk = A s + e with ||s|| <= 36, ||e|| <= 164. The cheating prover (pqz_rel.c set_upsilon under
 * -DPQZ_L2DOM_POC) only needs ||s||^2 + ||e||^2 <= 36^2 + 164^2.
 *
 *   l2dom_poc prove DIR    (built with -DPQZ_L2DOM_POC) prove cases, verify in-process, write DIR/<case>.{stmt,proof}
 *   l2dom_poc verify DIR   (linked against the production libpqz.a) verify the written proofs
 * Exit 0 always; the lines "ACCEPT" / "REJECT" are the result.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqz.h"

#ifdef PQZ_L2DOM_POC
extern int pqz_l2dom_poc;
extern int pqz_err;
extern const char *pqz_err_file;
extern int pqz_err_line;
#endif

static uint64_t xs = 0x9E3779B97F4A7C15ULL;
static int
tern (void)
{
  xs ^= xs >> 12, xs ^= xs << 25, xs ^= xs >> 27;
  uint64_t r = xs * 2685821657736338717ULL;
  return (int)((r >> 7) & 1) - (int)((r >> 33) & 1); /* cbd(1) */
}

static const char *cases[] = { "honest", "s_over_A", "s_over_B" };

/* honest: cbd(1) s, small e. A: s polys 1..31 = +-3 (||s||^2 ~ 17,900), e cbd(1).
   B: all of the budget in s: 1762 coefficients +-4 = 28192 = 36^2 + 164^2, e = 0. s[0] poly stays cbd(1)/0
   (it also carries the approximate filler proof). */
static void
witness (int c, int8_t s[2048], int16_t e[2048])
{
  for (int j = 0; j < 2048; j++)
    {
      s[j] = (int8_t)(c == 2 ? 0 : tern ());
      e[j] = (int16_t)(c == 2 ? 0 : tern ());
      if (c == 1 && j >= 64)
        s[j] = (int8_t)((j & 1) ? 3 : -3);
      if (c == 2 && j >= 64 && j < 64 + 1762)
        s[j] = (int8_t)((j & 1) ? 4 : -4);
    }
}

static void
build (int c, uint8_t *stmt, uint8_t *wit)
{
  static int8_t s[2048];
  static int16_t e[2048];
  long ns = 0, ne = 0;
  witness (c, s, e);
  for (int j = 0; j < 2048; j++)
    ns += s[j] * s[j], ne += e[j] * e[j];
  memset (stmt, 0xA5, PQZ_PREFIX_BYTES);
  for (int i = 0; i < 32; i++)
    stmt[PQZ_PREFIX_BYTES + i] = (uint8_t)i;
  pqz_keypair_from_secret (s, e, stmt + PQZ_PREFIX_BYTES + 32);
  for (int j = 0; j < 2048; j++)
    wit[j] = (uint8_t)s[j], wit[2048 + 2 * j] = (uint8_t)e[j], wit[2049 + 2 * j] = (uint8_t)((uint16_t)e[j] >> 8);
  printf ("%-9s ||s||^2=%ld (bound 1296) ||e||^2=%ld (bound 26896) sum=%ld (bound 28192)%s\n", cases[c], ns, ne,
          ns + ne, ns > 1296 ? "  <-- s exceeds its own bound" : "");
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
  size_t arena_len = (size_t)256 << 20;
  void *arena = malloc (arena_len);
  if (argc < 3 || !arena || pqz_init (arena, arena_len))
    return fprintf (stderr, "usage: %s prove|verify DIR\n", argv[0]), 2;
  int prove = !strcmp (argv[1], "prove");
  for (int c = 0; c < 3; c++)
    {
      size_t sl = sizeof stmt, pl = sizeof proof;
      if (prove)
        {
#ifdef PQZ_L2DOM_POC
          uint8_t rnd32[32];
          for (int i = 0; i < 32; i++)
            rnd32[i] = (uint8_t)(c * 31 + i);
          build (c, stmt, wit);
          pqz_l2dom_poc = 0;
          int rc0 = pqz_prove (PQZ_OP_REGISTER, stmt, sl, wit, sizeof wit, rnd32, proof, &pl);
          printf ("  honest prover rc=%d (%s)\n", rc0, rc0 ? "refuses: witness above a block bound" : "proves");
          pqz_l2dom_poc = 1;
          pl = sizeof proof;
          int rc = pqz_prove (PQZ_OP_REGISTER, stmt, sl, wit, sizeof wit, rnd32, proof, &pl);
          printf ("  pooled-slack prover rc=%d proof %zu B; prover self-checks: %s%s:%d\n", rc, pl,
                  pqz_err ? "FAIL (ignored), first at " : "pass", pqz_err ? pqz_err_file : "", pqz_err ? pqz_err_line : 0);
          if (rc && !(rc == pqz_err && pl < sizeof proof)) /* rc = the ignored self-check error, proof emitted */
            continue;
          rw (argv[2], cases[c], "stmt", stmt, &sl, 1);
          rw (argv[2], cases[c], "proof", proof, &pl, 1);
#else
          return fprintf (stderr, "prove needs -DPQZ_L2DOM_POC\n"), 2;
#endif
        }
      else if (!rw (argv[2], cases[c], "stmt", stmt, &sl, 0) || !rw (argv[2], cases[c], "proof", proof, &pl, 0))
        {
          printf ("%-9s (no proof file)\n", cases[c]);
          continue;
        }
      int ok = pqz_verify (PQZ_OP_REGISTER, stmt, sl, proof, pl);
      printf ("  %s pqz_verify(%s): %s\n", prove ? "in-process" : "production-lib", cases[c], ok ? "ACCEPT" : "REJECT");
    }
  return 0;
}
