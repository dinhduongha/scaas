# AI audit record: `vendor-falcon-rs`

A separate audit stream ([README](../README.md)); since 2026-11-26 the pre-freeze round audits the same code again at its
tag as unit 32, `vendor-falcon-rs` (controller call; [INDEX](../INDEX.md)), with this record as its prior review. The owner asked for it on 2026-11-26
because nobody had audited falcon-rs, and asked that this one result be kept in the repository; the pre-freeze round's results
stay local (owner 2026-11-24). Rules: [ARCH-POS-14](../../decisions.md#ARCH-POS-14) (an AI audit names its models; code
changed after its round is `UNAUDITED` again), [ARCH-POS-22](../../review.md#ARCH-POS-22) (13 dimensions). The use it covers:
[CLI-UAL-66](../../clients/ua-libraries.md#CLI-UAL-66).

## Status

**UNAUDITED.** The audit ran; its fixes in our glue, tests, CI and docs landed at `b9b5a4c24` (code and CI) and the commit after it
(this record and the docs), on branch `falcon-rs-fixes` (the vendored tree is not edited, ARCH-POS-24). Before the covered path is labelled
`AI-AUDITED (Fable)`: the timing measurement (written, `tests/fndsa_timing.rs` and `tests/fndsa/wasm/timing.cjs`, not run: no
timing run without the owner's word on an idle machine), the check that the wasm32 artefact holds no `f64.*` opcode in the Falcon
functions (not done), the findings open upstream (FR-6, FR-7, FR-8, FR-9; issue drafts kept outside the repository, not sent),
and Fable's look at the fix commits themselves: they change the glue the round read, so it is `UNAUDITED` until then
(ARCH-POS-14). Then the label holds at that commit, and `UNAUDITED` again on any later change.

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
| FR-4 | P2 | `clients/ua-rs/tests/fndsa/wasm/run.sh`; `.github/workflows/ci.yml` | the wasm32 gate (the code that ships) runs by hand only | a CI job with the wasm-bindgen + Node the JS job has | fixed at `b9b5a4c24`: CI job `ua-rs-fndsa-wasm` (`.github/ci_changes.py` maps ua-rs, its crates, `vendor/` and the vectors to it): `vendor.sh install` / `check`, wasm-bindgen-cli 0.2.130, Node 26.8.1, clippy for wasm32, `run.sh` |
| FR-5 | P2 | `clients/ua-rs/tests/fndsa/sign.rs` | seed -> key-pair equality native vs wasm32 rests on 24 key pairs; rare key-generation restart branches untested | a parity test over at least 1,000 seeds per degree | fixed at `b9b5a4c24`: the key pairs of 1,000 SHAKE256 seeds per degree, falcon-rs (`soft::keypair`) equal to PQClean's natively (release, in the CI job), and their digest `02513c7b…` equal in wasm32 (`run.sh`); 96 s native release, about 60 s for the whole wasm32 run under Node |
| FR-1 | P3 | `vendor/falcon-rs-0.3.1/src/fpr/emu.rs` `fpr_expm_p63` | the reference's Horner form in emulated floats, where PQClean clean uses 64-bit fixed point: the same `(sk, msg, rnd)` gives a different, equally valid signature with probability about 2^-39 per signature; key pairs unaffected | state the caveat beside "byte-equal to PQClean" in `soft.rs` and CLI-UAL-66 | documented at `b9b5a4c24`: `soft.rs`'s header and CLI-UAL-66 ("except with probability about 2^-39 per signature"; nothing relies on cross-platform signature bytes) |
| FR-2 | P3 | `emu.rs` `fpr_floor`, `fpr_half`, `fpr_sqrt`, `fpr_lt` | signed-zero semantics differ from PQClean's emulation; not reachable with hashed targets | record with FR-1 as a known difference | documented at `b9b5a4c24`, with FR-1 |
| FR-6 | P3 | `src/falcon.rs` (`sv_buf`) | a rejected padded candidate (a second signature on the same hash point) is dropped unwiped | wipe it, or sign through the wiped-buffer path | documented at `b9b5a4c24` (`soft.rs`'s header names the residual; its wider "clear none" corrected); open upstream: signing through the low-level path would need the `#[doc(hidden)]` modules FR-8 keeps out of the glue, so the round-3 call stays |
| FR-7 | P3 | `src/falcon.rs` (`hash_to_point_vartime`) | the padded signer hashes to a point in variable time (`seeded.c` uses the constant-time one) | the rule beside `soft::sign`: never a secret message on this path (the public `ua_msg` only) | documented at `b9b5a4c24`: the rule beside `soft::sign` and in CLI-UAL-66 (never a secret message; the message is the public `ua_msg`); open upstream |
| FR-8 | P3 | `src/sign.rs`, `src/keygen.rs`, `src/vrfy.rs` | hidden `pub` functions with debug-only preconditions; not reachable through the API `soft.rs` uses | keep the glue on `falcon::falcon::*` only; note the preconditions | fixed in the glue at `b9b5a4c24`: `soft.rs` on `falcon::falcon::*` and the SHAKE context type only, said in its header; `tests/fndsa_vrfy.rs` `soft_uses_the_round3_api_only` refuses any other path (a mutant adding `use ::falcon::sign` is killed); the preconditions open upstream |
| FR-9 | P3 | `src/sign.rs`, `src/keygen.rs` | the sampler panics and key generation gives up after 1,000 tries where the C loops (negligible probability) | named errors in the glue; note it | fixed at `b9b5a4c24` for keygen: `FALCON_ERR_RANDOM` after the 1,000 attempts is `Error::FalconKeygenCap` (was `Argument`); the sampler's panic stays (wasm32-unknown-unknown aborts on panic: nothing to catch; probability below 2^-1000), documented; open upstream |
| FR-10 | P3 | `clients/ua-rs/src/falcon/soft.rs` | wipes with `fill(0)` + `black_box` | use `zeroize` | fixed at `b9b5a4c24`: `zeroize::Zeroize` (feature `pq` takes the wallet's `zeroize` pin, already in falcon-rs's graph) |
| FR-11 | P3 | `clients/ua-rs/tests/fndsa/rows.rs` | the refusals hold no targeted encoding-edge cases and no sign-side negatives | edge refusal rows and sign-side negatives | fixed at `b9b5a4c24` as ua-rs test rows read natively and in wasm32 (`tests/fndsa/rows.rs` `edges`: a "-0" coefficient, a high part past 2,047, the first bit after `s2`, unpadded and one byte past the padding, a key coefficient = q and = 2^14 - 1, three key headers, three signature headers; 624 rows, 844 in all: 48 accept, 796 refuse, PQClean = falcon-rs on each); sign-side refusals in `fndsa_vrfy.rs` and `pqsign.rs`'s unit test; 7 mutants of the glue, every one killed. Not in `smartcontracts/vectors/` (the rows are derived from the vectors' accept rows; no other reader needs new bytes). Not done: a norm exactly at and one above the bound (needs a crafted secret key) |
| FR-12 | P3 | `clients/ua-rs/Cargo.toml`; the vendored `SECURITY.md` | a stale "0.4.0" comment; the dependency is not target-gated; an upstream contact address in the vendored file; no verify-after-sign | fix the comment, gate the dependency to wasm32, verify after signing | fixed at `b9b5a4c24`: the comment says 0.3.1; the dependency was target-gated already at the audited commit (`[target.'cfg(target_arch = "wasm32")'.dependencies]`; natively only the test's dev-dependency); verify after sign in `pqsign::sign` for both paths (`FalconSelfCheck`). The upstream address in the vendored `SECURITY.md` stays (the tree as published; `docs_check paths` passes) |

## Timing measurement (written, not run)

`clients/ua-rs/tests/fndsa/timing.rs` at `b9b5a4c24`: dudect-style, Welch's t between a fixed and a random input class,
interleaved at random, the largest |t| over dudect's percentile crops, 4.5 as the mark. Natively
`cargo test --release --features pq --test fndsa_timing -- --ignored --nocapture` (ignored: not a gate); in wasm32 under Node
`node timing.cjs [scale]` in `tests/fndsa/wasm` after `run.sh`. It covers, at degree 512, every function of the `fpr::emu`
list below, `gaussian0_sampler`, `sampler` by centre and sigma, `prng_init`, `prng_refill`, `fft`, `ifft`,
`poly_mul_fft`, `poly_ldl_fft`, `poly_split_fft`, `poly_merge_fft`, `trim_i8_decode`, `complete_private`, `sign_dyn` and
`soft::sign` with a fixed key against seven others at a fixed message and randomness. Not reachable through the crate's public
API, so measured through their callers: `ber_exp`, `ff_sampling_fft_dyntree`, `do_sign_dyn`. Rejection loops are variable time
by design, so the sampler, `sign_dyn` and `soft::sign` rows mix that in. Not run (2026-11-26): the round's full matrix held the
machine, and timing runs need the owner's word; the no-`f64.*` check of the wasm32 artefact is not done either.

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
