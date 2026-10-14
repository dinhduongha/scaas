/* Dump pqz_bench.c setup()'s statements and witnesses for the PQZH byte cross-check (xcheck/run.sh: R_REG, R_TX) and
   the pqz-stmt codec check (pqz-core/stmt, all six forms; P6e Task 5).
   pqz_bench.c is included whole so its static buffers are visible; its main() is renamed away. */
#define main pqz_bench_main
#include "../../test/pqz_bench.c"
#undef main

static int
dump (const char *dir, const char *name, const uint8_t *b, size_t n)
{
  char path[4096];
  snprintf (path, sizeof path, "%s/%s", dir, name);
  FILE *f = fopen (path, "wb");
  if (!f || fwrite (b, 1, n, f) != n)
    return 1;
  return fclose (f) != 0;
}

int
main (int argc, char **argv)
{
  if (argc != 2)
    return 2;
  void *arena = malloc (ARENA_BYTES);
  if (!arena || step_init (arena, ARENA_BYTES) != 0)
    return 1;
  static const char *const N[NREL] = { "reg", "tx", "burn", "ds", "dr", "tx0" };
  int rc = 0;
  for (int r = 0; r < NREL; r++)
    {
      char a[32], b[32];
      snprintf (a, sizeof a, "%s_stmt.bin", N[r]), snprintf (b, sizeof b, "%s_wit.bin", N[r]);
      rc |= dump (argv[1], a, STMT[r], STLEN[r]) | dump (argv[1], b, WIT[r], WLEN[r]);
    }
  return rc;
}
