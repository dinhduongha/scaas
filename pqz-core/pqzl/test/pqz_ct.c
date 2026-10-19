/*
 * Constant-time check of the prover (ctgrind technique, review fix E, 2026-10-19): the witness and rnd32 are marked
 * undefined (secret) for valgrind's memcheck, so every branch or memory address that depends on them is reported as
 * "Conditional jump or move depends on uninitialised value(s)" / "Use of uninitialised value of size 8".
 * Values that are public by design are marked defined again where they become public (PQZ_CT_PUBLIC, pqz_rt.h:
 * the rejection-sampling verdicts, the witness-valid verdict, the proof components and transcript messages);
 * the list is in research/code-review-2026-10-19/E-constant-time.md. Driven by test/ct.sh under valgrind.
 *   pqz_ct [rels] [nprove]    rels: pqz_bench's bit mask (1 = R_REG, ..., 32 = R_TX0, 64 << t = R_TXM)
 */
#define main pqz_bench_main
#include "pqz_bench.c"
#undef main
#include <valgrind/memcheck.h>

int
main (int argc, char **argv)
{
  int rels = argc > 1 ? atoi (argv[1]) : 1, np = argc > 2 ? atoi (argv[2]) : 1, fails = 0;
  void *arena = malloc (ARENA_BYTES);
  if (arena == NULL || step_init (arena, ARENA_BYTES) != 0)
    return printf ("init failed\n"), 2;
  for (int rel = 0; rel < NREL; rel++)
    for (int i = 0; i < np && (rels >> rel & 1); i++)
      {
        for (int k = 0; k < 32; k++)
          rnd32[k] = (uint8_t)(i * SEEDMUL[rel] + k);
        lens[rel] = sizeof proofs[rel];
        VALGRIND_MAKE_MEM_UNDEFINED (WIT[rel], WLEN[rel]);
        VALGRIND_MAKE_MEM_UNDEFINED (rnd32, 32);
        int rc = pqz_prove (OPS[rel], STMT[rel], STLEN[rel], WIT[rel], WLEN[rel], rnd32, proofs[rel], &lens[rel]);
        VALGRIND_MAKE_MEM_DEFINED (WIT[rel], WLEN[rel]);
        VALGRIND_MAKE_MEM_DEFINED (rnd32, 32);
        VALGRIND_MAKE_MEM_DEFINED (&rc, sizeof rc); /* prove succeeded: public (the caller sees it) */
        VALGRIND_MAKE_MEM_DEFINED (&lens[rel], sizeof lens[rel]);
        VALGRIND_MAKE_MEM_DEFINED (proofs[rel], lens[rel]);
        int ok = rc == 0 && step_verify (rel) == 1;
        printf ("{\"rel\": \"%s\", \"run\": %d, \"prove_rc\": %d, \"verify\": %d, \"fnv\": \"%08x\"}\n",
                rel < 6 ? NAMES[rel] : "R_TXM", i, rc, ok, step_hash (rel));
        fails += !ok;
      }
  printf ("{\"fails\": %d}\n", fails);
  return fails != 0;
}
