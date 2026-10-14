/* Dump pqz_bench.c setup()'s statements and witnesses (R_REG, R_TX; R_BURN, R_DS, R_DR for ligero.sh) for the PQZH
   byte cross-checks (xcheck/run.sh: the Plonky3 crate, R_REG / R_TX; xcheck/ligero.sh: the Ligero crate, all five).
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
  return dump (argv[1], "reg_stmt.bin", reg_stmt, sizeof reg_stmt) | dump (argv[1], "reg_wit.bin", reg_wit, sizeof reg_wit)
         | dump (argv[1], "tx_stmt.bin", tx_stmt, sizeof tx_stmt) | dump (argv[1], "tx_wit.bin", tx_wit, sizeof tx_wit)
         | dump (argv[1], "burn_stmt.bin", burn_stmt, sizeof burn_stmt)
         | dump (argv[1], "burn_wit.bin", burn_wit, sizeof burn_wit) | dump (argv[1], "ds_stmt.bin", ds_stmt, sizeof ds_stmt)
         | dump (argv[1], "ds_wit.bin", ds_wit, sizeof ds_wit) | dump (argv[1], "dr_stmt.bin", dr_stmt, sizeof dr_stmt)
         | dump (argv[1], "dr_wit.bin", dr_wit, sizeof dr_wit);
}
