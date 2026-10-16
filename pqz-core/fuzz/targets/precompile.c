/*
 * libFuzzer target `precompile` (P6e plan Task 10, D12): raw bytes into the C ABI pqz_precompile (pqz_ffi.h), the
 * entry point the node calls (P6f), twice; src/lib.rs checks the two results (status, verdict, determinism, arena).
 * Seeds (seeds.py, at run time): the honest inputs (P6e's 24 and every built op 7 (id, M, auditorOn), P6-ANON S5),
 * the self-test and every negative.json row (op 7's included); -max_len=400000 (over MAX_INPUT).
 */
#include "../../ffi/pqz_ffi.h"

void pqz_fuzz_init (const char *target);
void pqz_fuzz_check (const uint8_t *data, size_t len, int rc1, const uint8_t *out1, int rc2, const uint8_t *out2);

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void)argc, (void)argv;
  pqz_fuzz_init ("precompile");
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  uint8_t o1[32], o2[32];
  const int r1 = pqz_precompile (data, size, o1, sizeof o1), r2 = pqz_precompile (data, size, o2, sizeof o2);
  pqz_fuzz_check (data, size, r1, o1, r2, o2);
  return 0;
}
