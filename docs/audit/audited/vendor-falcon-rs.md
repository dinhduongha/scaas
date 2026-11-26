# AI audit record: `vendor-falcon-rs`

A separate audit stream ([README](../README.md)); since 2026-11-26 the pre-freeze round audits the same code again at its
tag as unit 32, `vendor-falcon-rs` (controller call; [INDEX](../INDEX.md)), with this record as its prior review. The owner asked for it on 2026-11-26
because nobody had audited falcon-rs, and asked that this one result be kept in the repository; the pre-freeze round's results
stay local (owner 2026-11-24). Rules: [ARCH-POS-14](../../decisions.md#ARCH-POS-14) (an AI audit names its models; code
changed after its round is `UNAUDITED` again), [ARCH-POS-22](../../review.md#ARCH-POS-22) (13 dimensions). The use it covers:
[CLI-UAL-66](../../clients/ua-libraries.md#CLI-UAL-66).

## Status

**UNAUDITED.** The audit ran; its fixes have not landed. After the fixes listed below, the covered path is labelled
`AI-AUDITED (Fable)` at the fix commit, and `UNAUDITED` again on any later change to it.

## Scope and run

| | |
|---|---|
| Code | `vendor/falcon-rs-0.3.1/` ([its record](../../../vendor/falcon-rs-0.3.1.VENDORED.md); installed by `scripts/vendor.sh`, not committed since 2026-11-26) (crates.io `falcon-rs` 0.3.1, MIT; features `default-features = false, fpemu`; used by `ua-rs` on `wasm32-unknown-unknown` only) and the `ua-rs` glue: `clients/ua-rs/src/falcon/soft.rs`, `src/falcon.rs`, `build.rs` / `Cargo.toml` routing, `src/wallet/pqsign.rs`, the gate tests `tests/fndsa_vrfy.rs`, `tests/fndsa/` |
| Reference | the round-3 C in `vendor/pqclean-falcon-seeded/` (PQClean `falcon-padded-512` / `-1024`) and `seeded.c` (since 2026-11-26 in `vendor/pqclean-falcon-seeded.local/`), function by function |
| Commit | `5120ac3c5cfc671217bb561f5e9834c15ec02dd3` (branch `ua-rs-wasm-fndsa`); git tree id of `vendor/falcon-rs-0.3.1` there: `57a1aa39f980835a94100cf0b0d81bf8b221752e` |
| Reviewer | Fable (model `claude-fable-5-2`, effort as the harness default), 2026-11-26, one read-only agent |
| Method | reading only: no build, test, benchmark or timing run; every constant-time statement below is by reading the source |
| Not covered | `src/safe_api.rs` (not called by `ua-rs`), the tree-signing and expanded-key entry points, the Keccak permutation body, the float tables value by value |

## Verdict

Approve with fixes: 0 P0, 0 P1, 3 P2, 9 P3. By reading, the round-3 code under `fpemu` is a faithful port of the C PQClean
ships, and the glue routes correctly and fails closed.

Confirmed by reading:
- `fpr/native.rs` is not compiled under `fpemu`; no hardware float or `libm` call on the signing path.
- The integer tables (`PRIMES`, `REV10`, the key-generation Gaussian table, `GMb`, `iGMb`) are text-equal to the C.
- `rnd = nonce || sampler seed` matches `seeded.c` `do_sign`; the padded retry continues on the same stream.
- The routing cannot pick falcon-rs natively or PQClean on wasm32; header and length checks give the same verdicts on both.
- No panic reachable from untrusted input on the verify path.

## Findings

| id | sev | where | finding | fix | state |
|---|---|---|---|---|---|
| FR-3 | P2 | `vendor/falcon-rs-0.3.1/VENDORED.md`; `clients/ua-rs/Cargo.lock` (a `path` entry has no checksum) | nothing re-checks the vendored tree against the published package | a `vendor.sh` that fetches the `.crate`, checks its sha256 and diffs the tree, run in CI; record the git tree id in `VENDORED.md` | fixed by `scripts/vendor.sh check` in CI at `f3ebb2da4`: the crate's sha256 before unpacking, the tree id `315fb462…` of the installed directory, and the audit's tree `57a1aa39…` recomputed as that tree plus the audit-time `VENDORED.md` ([ARCH-POS-24](../../decisions.md#ARCH-POS-24)) |
| FR-4 | P2 | `clients/ua-rs/tests/fndsa/wasm/run.sh`; `.github/workflows/ci.yml` | the wasm32 gate (the code that ships) runs by hand only | a CI job with the wasm-bindgen + Node the JS job has | open |
| FR-5 | P2 | `clients/ua-rs/tests/fndsa/sign.rs` | seed -> key-pair equality native vs wasm32 rests on 24 key pairs; rare key-generation restart branches untested | a parity test over at least 1,000 seeds per degree | open |
| FR-1 | P3 | `vendor/falcon-rs-0.3.1/src/fpr/emu.rs` `fpr_expm_p63` | the reference's Horner form in emulated floats, where PQClean clean uses 64-bit fixed point: the same `(sk, msg, rnd)` gives a different, equally valid signature with probability about 2^-39 per signature; key pairs unaffected | state the caveat beside "byte-equal to PQClean" in `soft.rs` and CLI-UAL-66 | open |
| FR-2 | P3 | `emu.rs` `fpr_floor`, `fpr_half`, `fpr_sqrt`, `fpr_lt` | signed-zero semantics differ from PQClean's emulation; not reachable with hashed targets | record with FR-1 as a known difference | open |
| FR-6 | P3 | `src/falcon.rs` (`sv_buf`) | a rejected padded candidate (a second signature on the same hash point) is dropped unwiped | wipe it, or sign through the wiped-buffer path | open |
| FR-7 | P3 | `src/falcon.rs` (`hash_to_point_vartime`) | the padded signer hashes to a point in variable time (`seeded.c` uses the constant-time one) | the rule beside `soft::sign`: never a secret message on this path (the public `ua_msg` only) | open |
| FR-8 | P3 | `src/sign.rs`, `src/keygen.rs`, `src/vrfy.rs` | hidden `pub` functions with debug-only preconditions; not reachable through the API `soft.rs` uses | keep the glue on `falcon::falcon::*` only; note the preconditions | open |
| FR-9 | P3 | `src/sign.rs`, `src/keygen.rs` | the sampler panics and key generation gives up after 1,000 tries where the C loops (negligible probability) | named errors in the glue; note it | open |
| FR-10 | P3 | `clients/ua-rs/src/falcon/soft.rs` | wipes with `fill(0)` + `black_box` | use `zeroize` | open |
| FR-11 | P3 | `clients/ua-rs/tests/fndsa/rows.rs` | the refusals hold no targeted encoding-edge cases and no sign-side negatives | edge refusal rows and sign-side negatives | open |
| FR-12 | P3 | `clients/ua-rs/Cargo.toml`; the vendored `SECURITY.md` | a stale "0.4.0" comment; the dependency is not target-gated; an upstream contact address in the vendored file; no verify-after-sign | fix the comment, gate the dependency to wasm32, verify after signing | open |

## A timing test must cover (wasm32 build)

- `fpr::emu`: `fpr_add`, `fpr_sub`, `fpr_mul`, `fpr_sqr`, `fpr_div`, `fpr_inv`, `fpr_sqrt`, `fpr_half`, `fpr_double`, `fpr_of` /
  `fpr_scaled`, `fpr_rint`, `fpr_floor`, `fpr_trunc`, `fpr_expm_p63`, `fpr_lt`, over the operand classes (small and large
  exponent gaps, zero, carries).
- `sign`: `gaussian0_sampler`; `ber_exp` with the stream fixed; `sampler` by centre and sigma class with the accept count fixed;
  `ff_sampling_fft_dyntree`, `do_sign_dyn` / `sign_dyn` with a fixed key against random keys.
- `fft`: `fft`, `ifft`, `poly_ldl_fft`, `poly_split_fft`, `poly_merge_fft`, `poly_mul_fft`.
- Key load: `codec::trim_i8_decode`, `vrfy::complete_private`.
- `rng`: `prng_init`, `prng_refill`.
- End to end: `soft::sign` with a fixed against a random secret key, the same `ua_msg` and `rnd`.
- Besides timing: no `f64.*` opcode in the Falcon functions of the wasm32 artefact.

Key generation is variable time by design (restarts); if measured, its per-attempt primitives.
