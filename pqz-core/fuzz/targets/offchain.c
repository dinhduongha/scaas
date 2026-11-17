/*
 * libFuzzer target `offchain` (three-key spec K3-4; UNAUDITED): raw bytes into pqz-offchain's verify_offchain (the
 * off-chain verifier's entry: the precompile's ids plus PQZL_SPLIT_ID), twice; the oracle is pqz_fuzz_offchain in
 * src/lib.rs (no panic, no node fault, deterministic, true exactly for the honest inputs and the honest split inputs).
 * Seeds (seeds.py, at run time): the honest inputs, the honest split inputs (proof_pqzl_split.json) and negative.json's
 * split_rows; -max_len as precompile's.
 */
#include <stddef.h>
#include <stdint.h>

void pqz_fuzz_init(const char *target);
void pqz_fuzz_offchain(const uint8_t *data, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc, (void)argv;
    pqz_fuzz_init("offchain");
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pqz_fuzz_offchain(data, size);
    return 0;
}
