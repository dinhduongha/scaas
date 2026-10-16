/* Dump pqz_bench.c setup()'s statements and witnesses, all six forms (reg, tx, burn, ds, dr, tx0), for the PQZH byte
   cross-checks (xcheck/run.sh: the Plonky3 crate, R_REG / R_TX; xcheck/ligero.sh: the Ligero crate) and the pqz-stmt
   codec check (pqz-core/stmt/xcheck.sh, P6e Task 5).
   pqz_bench.c is included whole so its static buffers are visible; its main() is renamed away.
   `dump_setup DIR pqzh` (ligero.sh, stmt/xcheck.sh) writes PQZH statements as the Ligero crate's client::setup_with
   does: bytes 0..63 = the op's opTag keccak256("SCAAS-PQZ-OP-<NAME>-V1") and PQZH's proofSystemId (plan D3) instead of
   pqz_bench.c's filler and PQZL's id (R_TX0 gets op 1's tag). Without it (run.sh) the bytes are pqz_bench.c's.
   `dump_setup DIR txm` (P6-ANON S4, LH-2: ffi/vectors/lh2.sh) writes pqz_bench.c's op 7 R_TXM statements and
   witnesses instead, every shape of TXB (txm<M>[_0]_{stmt,wit}.bin), bytes as pqz_bench.c builds them (filler opTag
   and recipientsHash, PQZL's id); lh2.sh's Rust side sets those words. */
#define main pqz_bench_main
#include "../../pqzl/test/pqz_bench.c"
#undef main

/* keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1") */
static const uint8_t PQZH_ID[32] = { 0x0a, 0x47, 0xa7, 0x68, 0x92, 0x50, 0xba, 0x17, 0x8a, 0x52, 0xad, 0x59, 0x72, 0xcd, 0xd9, 0x15, 0x33, 0x58, 0xc0, 0x22, 0xcb, 0x69, 0x4c, 0x08, 0xd2, 0x38, 0x9e, 0x82, 0xde, 0x2f, 0xea, 0xd4 };
static const uint8_t TAG_REG[32] = { 0x69, 0x56, 0x2a, 0x9c, 0xd6, 0x15, 0xeb, 0x3d, 0x90, 0x6c, 0xb1, 0x93, 0x4a, 0xd5, 0x6c, 0x78, 0x8c, 0x30, 0x22, 0x8d, 0x2f, 0xaf, 0x7c, 0x51, 0x7e, 0x33, 0xd6, 0x5b, 0x4a, 0x03, 0xc0, 0x88 };
static const uint8_t TAG_TX[32] = { 0xef, 0x22, 0xf3, 0xd1, 0xc1, 0xfc, 0x2e, 0xdc, 0x56, 0x55, 0x22, 0xeb, 0x73, 0xca, 0x8c, 0xb7, 0x82, 0xe8, 0x78, 0x0e, 0xaf, 0x9b, 0x1f, 0x67, 0x79, 0x65, 0xdd, 0x0c, 0xd5, 0x27, 0x54, 0x14 };
static const uint8_t TAG_BURN[32] = { 0x73, 0x83, 0x37, 0x4d, 0x83, 0xfb, 0xb8, 0x9f, 0x84, 0xee, 0x07, 0x9b, 0xff, 0x7a, 0x27, 0x42, 0xe4, 0xac, 0xb7, 0x0f, 0x64, 0xb0, 0xb1, 0xe2, 0xef, 0x40, 0xc3, 0x4f, 0xb4, 0xcc, 0x14, 0x07 };
static const uint8_t TAG_DS[32] = { 0x86, 0x8c, 0xc0, 0x7c, 0x6a, 0xc3, 0x89, 0x25, 0x1a, 0xd6, 0x57, 0x3f, 0x65, 0xfe, 0x35, 0xee, 0x4d, 0xad, 0x66, 0xee, 0x30, 0x5f, 0x90, 0xc7, 0x11, 0xaf, 0x90, 0x4b, 0xf5, 0xce, 0xef, 0x3f };
static const uint8_t TAG_DR[32] = { 0xd8, 0x35, 0x6c, 0xfb, 0xd8, 0x75, 0xac, 0xb8, 0x0f, 0xe8, 0xa8, 0x12, 0x7a, 0x57, 0xb5, 0xc5, 0x49, 0xd2, 0x0f, 0xd6, 0x5b, 0x9a, 0xcc, 0xa8, 0x67, 0x21, 0x86, 0xa1, 0xa4, 0x29, 0x64, 0x56 };

static void
pqzh_prefix (uint8_t *st, const uint8_t *tag)
{
  memcpy (st, tag, 32);
  memcpy (st + 32, PQZH_ID, 32);
}

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
  const int txm = argc == 3 && strcmp (argv[2], "txm") == 0;
  if (argc != 2 && !(argc == 3 && strcmp (argv[2], "pqzh") == 0) && !txm)
    return 2;
  void *arena = malloc (ARENA_BYTES);
  if (!arena || step_init (arena, ARENA_BYTES) != 0)
    return 1;
  if (txm)
    {
      int rc = 0;
      for (unsigned t = 0; t < NTXB; t++)
        {
          char a[48], b[48];
          const char *off = TXB[t].a ? "" : "_0";
          snprintf (a, sizeof a, "txm%u%s_stmt.bin", TXB[t].m, off), snprintf (b, sizeof b, "txm%u%s_wit.bin", TXB[t].m, off);
          rc |= dump (argv[1], a, STMT[6 + t], STLEN[6 + t]) | dump (argv[1], b, WIT[6 + t], WLEN[6 + t]);
        }
      return rc;
    }
  if (argc == 3)
    {
      pqzh_prefix (reg_stmt, TAG_REG), pqzh_prefix (tx_stmt, TAG_TX), pqzh_prefix (burn_stmt, TAG_BURN);
      pqzh_prefix (ds_stmt, TAG_DS), pqzh_prefix (dr_stmt, TAG_DR), pqzh_prefix (tx0_stmt, TAG_TX);
    }
  static const char *const N[6] = { "reg", "tx", "burn", "ds", "dr", "tx0" };
  int rc = 0;
  for (int r = 0; r < 6; r++) /* the six forms (NREL also counts the op 7 shapes: mode txm) */
    {
      char a[32], b[32];
      snprintf (a, sizeof a, "%s_stmt.bin", N[r]), snprintf (b, sizeof b, "%s_wit.bin", N[r]);
      rc |= dump (argv[1], a, STMT[r], STLEN[r]) | dump (argv[1], b, WIT[r], WLEN[r]);
    }
  return rc;
}
