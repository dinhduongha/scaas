/*
 * Review harness (docs/reviews/specs/2026-10-13-pqz-sv-review.md, finding 3): do two different Schwartz-Zippel
 * equation calls of lnp_tbox share one (seed, dom) and hence one challenge row?
 *
 * Reuses sz/sz_trace.c (one honest R_REG prove with the -DPQZ_SZ_TRACE hook; every __schwartz_zippel_accumulate2
 * call records its dom and the lambda = 4 challenge rows, all under the same seed, the hash after the tg round).
 * Each call is four consecutive records (acc 0..3). Calls are listed in transcript order: beta3 (dom M + i, i < d),
 * beta4 (M + d - 1 + i), upsilon (M + 2 (d - 1)), binary (absent for R_REG), l2 (M + 2 (d - 1) + 2 + i). Prints
 * every dom used by more than one call and whether their rows are equal. pqz_sv.c sz_eval_challenges reproduces
 * the same derivation (ONE (M + DEG - 1 + i) for beta4, ONE (M + 2 * (DEG - 1)) for upsilon).
 * Exit 0 = no shared dom, 1 = at least one.
 */
#define main sz_trace_main
#include "../../sz/sz_trace.c"
#undef main

int
main (void)
{
  if (sz_trace_main () != 0)
    printf ("(sz_trace verdict non-zero)\n");
  const unsigned ncall = nrec / 4;
  unsigned shared = 0;
  printf ("\n%u accumulate2 calls (R_REG, M = 0)\n", ncall);
  for (unsigned a = 0; a < ncall; a++)
    for (unsigned b = a + 1; b < ncall; b++)
      if (rec[4 * a].dom == rec[4 * b].dom)
        {
          int same = 1;
          for (unsigned k = 0; k < 4; k++)
            same &= veceq (4 * a + k, 4 * b + k);
          printf ("SHARED dom %llu: call %u and call %u (calls 0..62 beta3, 63..125 beta4, 126 upsilon, 127.. l2); "
                  "challenge rows %s\n",
                  (unsigned long long)rec[4 * a].dom, a, b, same ? "IDENTICAL" : "differ");
          shared++;
        }
  printf ("%u shared dom(s)\n", shared);
  return shared != 0;
}
