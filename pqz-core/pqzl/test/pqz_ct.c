/*
 * Constant-time check of the prover (ctgrind technique, review fix E, 2026-10-19): the witness and rnd32 are marked
 * undefined (secret) for valgrind's memcheck, so every branch or memory address that depends on them is reported as
 * "Conditional jump or move depends on uninitialised value(s)" / "Use of uninitialised value of size 8".
 * Values that are public by design are marked defined again where they become public (PQZ_CT_PUBLIC, pqz_rt.h:
 * the rejection-sampling verdicts, the witness-valid verdict, the proof components and transcript messages);
 * the list is in research/code-review-2026-10-19/E-constant-time.md. Driven by test/ct.sh under valgrind.
 *   pqz_ct [rels] [nprove] [keys]    rels: pqz_bench's bit mask (1 = R_REG, ..., 32 = R_TX0, 64 << t = R_TXM);
 *   keys: rounds of KeyGen (seed secret), Enc to two recipients (seed_enc and the digits secret), Dec (s secret)
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
  for (int i = 0; i < (argc > 3 ? atoi (argv[3]) : 0); i++)
    {
      static uint8_t seed[32], seed_enc[32], pk[2][PQZ_POLYVEC_BYTES], msgs[2][16], ct[PQZ_POLYVEC_BYTES + PQZ_V_BYTES];
      static uint8_t vs[2][PQZ_V_BYTES];
      static int8_t s[2][PQZ_N], r[PQZ_N];
      static int16_t e[PQZ_N], e1[PQZ_N], e2[2][16];
      int64_t M[16], noise[16];
      unsigned ctr = 0, ctr2 = 0;
      int rc = 0, ok = 1;
      for (int k = 0; k < 2; k++)
        {
          for (int j = 0; j < 32; j++)
            seed[j] = (uint8_t)(31 * i + 7 * k + j);
          VALGRIND_MAKE_MEM_UNDEFINED (seed, 32);
          rc |= pqz_keygen (seed, pk[k], s[k], e, &ctr);
          VALGRIND_MAKE_MEM_DEFINED (pk[k], sizeof pk[k]); /* the public key */
        }
      for (int j = 0; j < 32; j++)
        seed_enc[j] = (uint8_t)(17 * i + j);
      for (int j = 0; j < 16; j++)
        msgs[0][j] = (uint8_t)((i + j) & 15), msgs[1][j] = (uint8_t)((3 * i + 5 * j) & 15);
      VALGRIND_MAKE_MEM_UNDEFINED (seed_enc, 32);
      VALGRIND_MAKE_MEM_UNDEFINED (msgs, sizeof msgs);
      const uint8_t *pks[2] = { pk[0], pk[1] };
      rc |= pqz_enc_seed (pks, 2, (const uint8_t (*)[16])msgs, seed_enc, ct, vs, r, e1, e2, &ctr2);
      VALGRIND_MAKE_MEM_DEFINED (ct, PQZ_POLYVEC_BYTES); /* the ciphertext */
      VALGRIND_MAKE_MEM_DEFINED (vs, sizeof vs);
      VALGRIND_MAKE_MEM_DEFINED (msgs, sizeof msgs);
      for (int k = 0; k < 2; k++)
        {
          memcpy (ct + PQZ_POLYVEC_BYTES, vs[k], PQZ_V_BYTES);
          rc |= pqz_dec (s[k], ct, M, noise);
          VALGRIND_MAKE_MEM_DEFINED (M, sizeof M); /* the driver checks the plaintext */
          for (int j = 0; j < 16; j++)
            ok &= M[j] == msgs[k][j];
        }
      VALGRIND_MAKE_MEM_DEFINED (&rc, sizeof rc);
      printf ("{\"keys\": %d, \"rc\": %d, \"dec_ok\": %d, \"ctr\": [%u, %u]}\n", i, rc, ok, ctr, ctr2);
      fails += rc != 0 || !ok;
    }
  printf ("{\"fails\": %d}\n", fails);
  return fails != 0;
}
