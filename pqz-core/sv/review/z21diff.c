/*
 * P6-Z21 differential (lazer#26, docs/research/pqz-z21-norm.md): z21-inflated proofs of all six relations, verified
 * by both verifiers in-process. Mutated proofs never reach the z2 norm check (they fail the final hash first), so the
 * proofs come from the cheating prover of sv/review/normpoc_hooks.h, mode 4: the first polynomial of y21 times k,
 * the z2 rejection and the prover's own ||y2|| check skipped. For k = round(1.25^j), j = 0 .. JMAX, ||(z21, z22)||^2
 * sweeps from honest to far above Bsq, through the bound. Per case: pqz_verify and pqz_verify_fast must agree, and
 * both must accept exactly when the prover's ||(z21, z22)||^2 <= Bsq (the verifier's ||(z21, w - gamma w1)||^2 is
 * that same vector). Linked only against the patched-prover library of review.sh (build/review/poc), never into a
 * production build.
 *   z21diff [nseeds = 1] [jmax = 31] [mask = 63]  JSON lines (mask: 1 R_REG, 2 R_TX, 4 R_BURN, 8 R_DS, 16 R_DR,
 *                                             32 R_TX0, 64 << t the R_TXM shape TXD[t] of pqz_sv_diff.c: 64 (1, on),
 *                                             128 (2, on), 256 (4, on), 512 (8, on), 1024 .. 8192 the same off);
 *                                             exit 0 = no disagreement, no expectation mismatch, and both verdicts
 *                                             seen for every relation; PQZ_ARENA_MB as pqz_sv_diff
 */
#define main pqz_sv_diff_main
#include "../../test/pqz_sv_diff.c"
#undef main
#include <math.h>

extern int pqz_poc_mode;
extern int64_t pqz_poc_k, pqz_poc_z21sq, pqz_poc_z2sq;

/* params/pqz_{reg,tx,burn,ds,dr,tx0}_params.h, then the R_TXM shapes' headers (M = 1: tx / tx0, txm2, txm4, txm8,
   txm20, txm40, txm80, oversize txm16, txm160): <name>_Bsq = floor(Bound_()^2) */
static const int64_t BSQ[NREL] = { 22226101053479LL,   384257620087633LL,  384257620087633LL,  4636547823165LL,
                                   1490938094717228LL, 384257620087633LL,  384257620087633LL,  384257620087633LL,
                                   384257620087633LL,  7393984317519398LL, 384257620087633LL,  384257620087633LL,
                                   384257620087633LL,  7393984317519398LL,
#ifdef PQZ_TXM_OVERSIZE
                                   1619251171041139LL, 1619251171041139LL,
#endif
};

int
main (int argc, char **argv)
{
  static uint8_t proof[PQZ_MAX_PROOF];
  const int nseeds = argc > 1 ? atoi (argv[1]) : 1, jmax = argc > 2 ? atoi (argv[2]) : 31;
  const int mask = argc > 3 ? atoi (argv[3]) : 63; /* one relation per process keeps an ASan malloc build small */
  long cases = 0, dis = 0, mis = 0, err = 0, acc[NREL] = { 0 }, rej[NREL] = { 0 };
  double closest = 1e9;
  const char *amb = getenv ("PQZ_ARENA_MB");
  const size_t arena_bytes = amb != NULL ? (size_t)atoi (amb) << 20 : ARENA_BYTES;
  xs = 0x5A21D1FF00000001ULL;
  if (pqz_init (malloc (arena_bytes), arena_bytes) != 0)
    return 2;
  txm_tables ();
  make_reg (), make_tx (), make_burn (), make_disc ();
  for (int t = 0; t < NTXD; t++)
    if (mask >> (6 + t) & 1)
      make_txm (t);
  for (int rel = 0; rel < NREL; rel++)
    {
      int64_t last = 0;
      if (!(mask >> rel & 1))
        continue;
      for (int j = 0; j <= jmax; j++)
        {
          const int64_t k = (int64_t)llround (pow (1.25, j));
          if (k == last)
            continue;
          last = k;
          for (int s = 0; s < nseeds; s++)
            {
              uint8_t r32[32] = { (uint8_t)rel, (uint8_t)s, (uint8_t)k, (uint8_t)(k >> 8), 0x21 };
              size_t pl = sizeof proof;
              pqz_poc_mode = 4, pqz_poc_k = k, pqz_poc_z21sq = pqz_poc_z2sq = -1;
              const int rc = pqz_prove (OPS[rel], STMT[rel], STLEN[rel], WIT[rel], WLEN[rel], r32, proof, &pl);
              pqz_poc_mode = 0;
              if (rc != 0)
                {
                  printf ("{\"rel\": \"%s\", \"k\": %lld, \"seed\": %d, \"prove_rc\": %d}\n", RN[rel], (long long)k, s,
                          rc);
                  err++;
                  continue;
                }
              const int g = pqz_verify (OPS[rel], STMT[rel], STLEN[rel], proof, pl) == 1;
              const int f = pqz_verify_fast (OPS[rel], STMT[rel], STLEN[rel], proof, pl) == 1;
              const int e = pqz_poc_z2sq <= BSQ[rel];
              const double ratio = (double)pqz_poc_z2sq / (double)BSQ[rel];
              cases++, dis += g != f, mis += g != e;
              (g ? acc : rej)[rel]++;
              if (fabs (ratio - 1) < fabs (closest - 1))
                closest = ratio;
              printf ("{\"rel\": \"%s\", \"k\": %lld, \"seed\": %d, \"proof_bytes\": %zu, \"z21sq\": %lld, "
                      "\"z2sq\": %lld, \"bsq\": %lld, \"z2sq_over_bsq\": %.6f, \"expect\": \"%s\", \"generic\": "
                      "\"%s\", \"fast\": \"%s\"%s}\n",
                      RN[rel], (long long)k, s, pl, (long long)pqz_poc_z21sq, (long long)pqz_poc_z2sq,
                      (long long)BSQ[rel], ratio, e ? "ACCEPT" : "REJECT", g ? "ACCEPT" : "REJECT",
                      f ? "ACCEPT" : "REJECT", g != f ? ", \"DISAGREE\": 1" : (g != e ? ", \"UNEXPECTED\": 1" : ""));
              fflush (stdout);
            }
        }
    }
  int both = 1;
  for (int rel = 0; rel < NREL; rel++)
    {
      printf ("{\"rel\": \"%s\", \"accepted\": %ld, \"rejected\": %ld}\n", RN[rel], acc[rel], rej[rel]);
      both &= !(mask >> rel & 1) || (acc[rel] > 0 && rej[rel] > 0);
    }
  printf ("{\"z21diff\": 1, \"cases\": %ld, \"disagreements\": %ld, \"expect_mismatches\": %ld, \"prove_errors\": %ld, "
          "\"closest_z2sq_over_bsq\": %.6f, \"both_verdicts_every_relation\": %d}\n",
          cases, dis, mis, err, closest, both);
  return dis == 0 && mis == 0 && both ? 0 : 1;
}
