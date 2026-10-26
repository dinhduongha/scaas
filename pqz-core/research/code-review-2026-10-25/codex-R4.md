R4 review at `008e196c`: **no substantiated new findings** in the reviewed precompile path. The prior W-G library-pin and W-R ML-DSA exception fixes remain present.

This was static, read-only review. No files were changed and no builds, tests, benchmarks, or timing runs were performed.

## Checked and sound

Paths below are relative to `pqz-core/`.

| Invariant | Evidence |
|---|---|
| Malformed inputs do not escape as Rust panics | `ffi/src/lib.rs:98–112,146–164` catches verification panics and protects the C ABI; native `panic="abort"` builds are forbidden at lines 21–24. This does **not** establish unconditional abort-freedom under memory exhaustion; see below. |
| Length and `MAX_INPUT` checks precede unsafe access | `ffi/src/lib.rs:147–155` checks arguments and `MAX_INPUT` before constructing the input slice. `stmt/src/lib.rs:943–953` checks minimum framing and declared statement length before splitting. Nethermind checks the library-exported limit before dispatch: `PqzPrecompile.cs:47–55`, `Native.cs:17`. |
| Statement shape and `MAX_PROOF(id)` checked before verification | `stmt/src/lib.rs:521–619,761–819` validates fixed lengths, canonical fields, coefficients, and supported multi-recipient shapes. Lines 961–965 enforce nonempty, bounded proofs before `ffi/src/lib.rs:84–85` dispatches. Proof-length checking follows allocation-free statement parsing, rather than preceding all parsing work. |
| Retired and other sets’ IDs refused | `stmt/src/lib.rs:140–153,538–540,766–770` accepts only the selected set’s IDs. `HAS_PQZH` gates PQZH recognition, so the zero placeholder at `n2816-kmax65536` is rejected. `ffi/src/pqzh_none.rs:5–6` also fails closed. |
| Verification results are exactly 32-byte zero or one | `ffi/src/lib.rs:65–72,106,163` constructs fixed words and writes exactly 32 bytes. **Canonical op 6 intentionally returns a self-test digest**, as documented in `ffi/pqz_ffi.h:6–8`; the zero/one invariant applies to verification operations. |
| Gas follows the active schedule row | `PqzChainSpecEngineParameters.cs:97–119,141–151` validates rows and matches `(op, id, stmtLen, legs, auditorOn)`. `PqzPrecompile.cs:37–41,51–52` charges row gas plus the word term, uses the minimum row on misses, and prevents misses from reaching verification. Op 6 has the documented fixed price. |
| Addresses and activation agree | `Addresses.cs:10–12` defines PQZ `0x…5caa0f01`, MLDSA44 `0x…5caa0012`, and MLDSA65 `0x…5caa0013`. `PqzPrecompileProvider.cs:14–20` registers those same addresses; `PqzReleaseSpec.cs:25–32` activates all three with the schedule. |
| Self-test and library pin enforced | `SelfTest.cs:13–20` matches all four sets’ committed `selftest.json` hashes. `PqzPlugin.cs:56–62` checks the library SHA-256, self-test result, and exported input limit before genesis execution. `ffi/src/selftest.rs:117–126` does not cache failed computations. |
| Wrapper allocation failures remain node faults | `ffi/src/pqzl/rust.rs:69–94,106–110` uses fallible context allocation and maps core memory errors to `NodeFault`. `ffi/src/pqzl/c.rs:125–148` reserves the fixed arena fallibly and checks arena exhaustion after calls. `ffi/src/pqzh.rs:12–13` propagates allocation failure as `NodeFault`. Nethermind exits rather than converting these faults into proof rejection (`PqzPrecompile.cs:65–80`). |

The earlier malformed-self-test gas claim is not re-reported: it was explicitly refuted in the prior triage (`research/code-review-2026-10-19/U-agy-chain.md:356`), and fixed-price malformed op-6 handling remains documented.

## Not covered

- Full PQZL C/Rust and Ligero verifier internals, including a proof of maximum stack and allocation consumption for every parameter set and adversarial proof.
- Full review of `ffi/src/fixture.rs`, `ffi/src/bin/pqz-vectors.rs`, and every test body; these were inspected selectively.
- Rebuilding or hashing the actual shared library, deployed binaries, production chainspecs, gas calibration, or Nethermind/OpenSSL dependency internals.

**Remaining qualification:** unconditional “never crashes” is not established. The ABI explicitly permits Rust allocation aborts (`ffi/pqz_ffi.h:10–12`), and the C adapter documents fatal exhaustion during LaZer allocations (`ffi/src/pqzl/c.rs:13–19`). No concrete accepted input exceeding the configured bounds was established in this pass.