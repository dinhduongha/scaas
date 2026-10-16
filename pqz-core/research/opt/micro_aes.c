/*
 * P6d-2 microbench: the library's AES-256-CTR PRNG (rng_urandom), 1 MiB per run, and a fresh stream of 64 bytes
 * (key schedule + one 4-block call, the pattern of the per-sample streams in the prover). Best of 7.
 *   clang -O2 -Ibuild/include -Isrc -Ilazer -Iparams opt/micro_aes.c build/native/libpqz.a -o build/micro_aes
 */
#include <stdio.h>
#include <time.h>

#include "lazer.h"

static double
now_ms (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

int
main (void)
{
  static uint8_t out[1 << 20];
  uint8_t seed[32] = { 1, 2, 3 };
  rng_state_t st;
  double best = 1e30, best2 = 1e30;

  for (int rep = 0; rep < 7; rep++)
    {
      double t0 = now_ms ();
      rng_init (st, seed, 5);
      rng_urandom (st, out, sizeof out);
      rng_clear (st);
      double t = now_ms () - t0;
      best = t < best ? t : best;
      t0 = now_ms ();
      for (int i = 0; i < 1000; i++)
        {
          rng_init (st, seed, i);
          rng_urandom (st, out, 64);
          rng_clear (st);
        }
      t = (now_ms () - t0) * 1e3 / 1000;
      best2 = t < best2 ? t : best2;
    }
  printf ("rng_urandom 1 MiB: %.2f ms; fresh 64-byte stream: %.2f us (out[0] = %u)\n", best, best2, out[0]);
  return 0;
}
