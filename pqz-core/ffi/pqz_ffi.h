/*
 * pqz-ffi C ABI (P6e Task 7, plan D10; pq-zero-knowledge.md §9.1, CTR-PQZ-10): the PQZ precompile for the node (P6f,
 * Nethermind P/Invoke). Hand-written; tests/c_abi.c compiles against it and links libpqz_ffi (run.sh), and the Rust
 * test `header_matches` checks every constant here against the crate.
 *
 * input  = u8(op) || be32(len(stmt)) || stmt || proof   (op 1..5 and 7; op 6 = SELFTEST, exactly 06 00000000)
 * output = 32 bytes: ...01 valid, ...00 anything else (malformed, unknown op / opTag / proofSystemId, wrong length,
 *          non-canonical encoding, failed check), or the self-test hash for op 6
 *
 * Thread-safe (the PQZL core's calls, Rust by default or the C core, are serialised inside, one process-wide lock,
 * and run on one worker thread with its own 16 MiB stack); never unwinds, aborts or exits (native builds;
 * except Rust's abort on a failed heap allocation; a panic = abort build does not compile). The
 * caller's stack: 1 MiB suffices (test one_mib_stack).
 */
#ifndef PQZ_FFI_H
#define PQZ_FFI_H

#include <stddef.h>
#include <stdint.h>

#define PQZ_FFI_OK 0       /* out[0..32] holds the result */
#define PQZ_FFI_REVERT 1   /* len > PQZ_FFI_MAX_INPUT: the precompile reverts (consumes all gas); out zeroed */
#define PQZ_FFI_BAD_ARGS 2 /* input NULL with len > 0, out NULL, or out_len < 32: nothing written */
#define PQZ_FFI_INTERNAL 3 /* a panic in the decode / verify logic was caught: input-caused, the same on every
                              node; out = ...00 (the input is invalid); log it */
#define PQZ_FFI_NODE_FAULT 4 /* a fault of this node, not of the input (worker or core unavailable; C core: arena
                                exhaustion or reservation failure): no result, out untouched; abort block processing, never treat the
                                input as invalid (controller 2026-10-14) */

#define PQZ_FFI_MAX_INPUT 393216 /* P6e D5: 5 + 83,072 + 262,144 = 345,221 <= 393,216 */
#define PQZ_FFI_OUT_BYTES 32

#ifdef __cplusplus
extern "C" {
#endif

int pqz_precompile (const uint8_t *input, size_t len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
