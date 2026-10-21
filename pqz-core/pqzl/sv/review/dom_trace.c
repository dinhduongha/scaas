/*
 * Review harness (docs/reviews/specs/2026-10-13-pqz-sv-review.md, finding 3): do two different Schwartz-Zippel
 * equation calls of lnp_tbox share one (seed, dom) and hence one challenge row?
 *
 * Reuses sz/sz_trace.c (one honest R_REG prove with the -DPQZ_SZ_TRACE hook; every __schwartz_zippel_accumulate2
 * call records its dom and the lambda = 4 challenge rows, all under the same seed, the hash after the tg round).
 * Each call is four consecutive records (acc 0..3). Calls are listed in transcript order: beta3 (dom M + i, i < d),
 * beta4 (M + d - 1 + i), upsilon (M + 2 (d - 1) + 1), binary (absent for R_REG), l2 (M + 2 (d - 1) + 3 + i). Prints
 * every dom used by more than one call and whether their rows are equal. pqz_sv.c sz_eval_challenges reproduces
 * the same derivation (ONE (M + DEG - 1 + i) for beta4, ONE (M + 2 * (DEG - 1) + 1) for upsilon). Finding 3 here is
 * review A's A-2 (the last beta4 row and upsilon shared M + 2 (d - 1)); since the A-2 renumbering this exits 0.
 * Since B-1 the V4 / V3 matrices (intmat_urandom: row i from the PRG nonce dom << 32 | 256 i) are drawn from the same
 * seed as every Schwartz-Zippel call (the hash after tg), so their row nonces are checked too (8a review m1): against
 * every accumulate2 call's nonce (its dom) and against each other; a V4 / V3 dom that equals a Gamma dom is reported
 * as well (the nonces still differ while that dom is nonzero, but the layout is then off).
 * Exit 0 = no shared dom / nonce, 1 = at least one.
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
  /* V4 / V3 (kinds 2 / 3, B-1: the same seed) */
  printf ("%u V matrices (V4, V3)\n", n_v_z4z3);
  for (unsigned v = 0; v < n_v_z4z3 && v < 8; v++)
    {
      for (unsigned a = 0; a < ncall; a++)
        for (unsigned i = 0; i < 4; i++)
          if (rec[4 * a].dom == vdom[v] || rec[4 * a].dom == ((vdom[v] << 32) | (256u * i)))
            {
              printf ("SHARED dom / nonce: V%d dom %llu (row %u) and accumulate2 call %u (dom %llu)\n", vkind[v] == 2 ? 4 : 3,
                      (unsigned long long)vdom[v], i, a, (unsigned long long)rec[4 * a].dom);
              shared++;
              i = 4;
            }
      for (unsigned w = v + 1; w < n_v_z4z3 && w < 8; w++)
        if (vdom[w] == vdom[v])
          {
            printf ("SHARED dom: V matrices %u and %u (dom %llu)\n", v, w, (unsigned long long)vdom[v]);
            shared++;
          }
    }
  printf ("%u shared dom(s)\n", shared);
  return shared != 0;
}
