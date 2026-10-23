/*
 * P6-Z21 differential (lazer#26, docs/research/pqz-z21-norm.md): z21-inflated proofs of all six relations, verified
 * by both verifiers in-process. Mutated proofs never reach the z2 norm check (they fail the final hash first), so the
 * proofs come from the cheating prover of sv/review/normpoc_hooks.h, mode 4: the first polynomial of y21 times k,
 * the z2 rejection and the prover's own ||y2|| check skipped. For k = round(1.25^j), j = 0 .. JMAX, ||(z21, z22)||^2
 * sweeps from honest to far above Bsq, through the bound; a relation not yet rejected at JMAX goes on (j <= JCAP) until
 * its first reject, so every relation crosses its own bound (8b review I1: at n2048-kmax1024 R_TXM8 and at n2560-kmax16384 most
 * relations stayed below Bsq at k = 1010). Per case: pqz_verify and pqz_verify_fast must agree, and
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
#define JCAP 48 /* k = 1.25^48 ~ 45,000: z2sq stays far below 2^63 at every set (it stops at the first reject) */

extern int pqz_poc_mode;
extern int64_t pqz_poc_k, pqz_poc_z21sq, pqz_poc_z2sq;

/* each relation's <rel>_Bsq = floor(Bound_()^2) from the set's generated headers (build/include, set.sh): the six P6e
   forms, then the R_TXM shapes in TXD order (M = 1 on R_TX's / R_TX0's parameters, as pqz_rel.c's TXM[]) */
#include "lazer.h"
#include "pqz_burn_params.h"
#include "pqz_dr_params.h"
#include "pqz_ds_params.h"
#include "pqz_reg_params.h"
#include "pqz_tx0_params.h"
#include "pqz_tx_params.h"
#include "pqz_txm20_params.h"
#include "pqz_txm2_params.h"
#include "pqz_txm40_params.h"
#include "pqz_txm4_params.h"
#include "pqz_txm80_params.h"
#include "pqz_txm8_params.h"
#ifdef PQZ_TXM_OVERSIZE
#include "pqz_txm160_params.h"
#include "pqz_txm16_params.h"
#endif
static const int_struct *const BSQL[NREL] = { pqz_reg_Bsq,  pqz_tx_Bsq,   pqz_burn_Bsq,  pqz_ds_Bsq,
                                          pqz_dr_Bsq,   pqz_tx0_Bsq,  pqz_tx_Bsq,    pqz_txm2_Bsq,
                                          pqz_txm4_Bsq, pqz_txm8_Bsq, pqz_tx0_Bsq,   pqz_txm20_Bsq,
                                          pqz_txm40_Bsq, pqz_txm80_Bsq,
#ifdef PQZ_TXM_OVERSIZE
                                          pqz_txm16_Bsq, pqz_txm160_Bsq,
#endif
};
static int64_t BSQ[NREL];

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
  for (int rel = 0; rel < NREL; rel++) /* every set's Bsq is one limb < 2^63 (the header's higher limbs, if any, 0) */
    {
      if (BSQL[rel]->neg || BSQL[rel]->limbs[0] > INT64_MAX)
        return 2;
      for (unsigned int i = 1; i < BSQL[rel]->nlimbs; i++)
        if (BSQL[rel]->limbs[i] != 0)
          return 2;
      BSQ[rel] = (int64_t)BSQL[rel]->limbs[0];
    }
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
      for (int j = 0; j <= jmax || (rej[rel] == 0 && j <= JCAP); j++)
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
