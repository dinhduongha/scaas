/*
 * libFuzzer target `mutate` (P6e plan Task 10, D12, D15): structure-aware edit scripts (<= 512 B) over one of the
 * honest inputs (op 7's included, P6-ANON S5); the input format and the oracle are pqz_fuzz_mutate in src/lib.rs.
 */
#include <stddef.h>
#include <stdint.h>

void pqz_fuzz_init (const char *target);
void pqz_fuzz_mutate (const uint8_t *data, size_t len);

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void)argc, (void)argv;
  pqz_fuzz_init ("mutate");
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  pqz_fuzz_mutate (data, size);
  return 0;
}
