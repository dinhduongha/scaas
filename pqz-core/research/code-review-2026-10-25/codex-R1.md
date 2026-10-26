Reviewed `008e196c7409034b8645c386d7c1bed7715e0eb0` by static reading only. **One residual finding in an unused LaZer API; no transcript defect found in the PQZ payment entry points.**

All paths below are relative to `pqz-core/`.

## R1-1 — P2 — Standalone quadratic-evaluation API still omits `h` before μ

**Locations:** `pqzl/lazer/lnp-quad-eval.c:639–677,749–755`; `pqzl/lazer/lnp-quad-many.c:34`.

**Claim.** The previous missing-`h` fix covers `lnp_tbox_*`, but remains incomplete across the retained LaZer APIs: `lnp_quad_eval_verify` derives μ without binding `h`.

**Evidence.** `_lnp_quad_eval_verify` checks only that each `h` polynomial’s constant coefficient is zero (`:639–647`). Its transcript then absorbs `tg`:

```c
shake128_absorb (hstate, hash, 32);
shake128_absorb (hstate, out, outlen);
shake128_squeeze (hstate, hash, 32);
```

Here `out` encodes `tg` (`:650–659`). It subsequently incorporates `h` into the equations without hashing it:

```c
_schwartz_zippel_int (..., M, h, v, params);
```

The wrapper passes that unchanged hash directly to `lnp_quad_many_verify` (`:749–755`), which derives:

```c
polyvec_urandom (mu, q, log2q, hash, 0);
```

A concrete distinguishing input is `h₀ ← h₀ + X`: this preserves the constant-coefficient check and leaves every challenge seed unchanged, while changing the equation’s constant term through:

```c
poly_sub (r0i[i], r0i[i], hi, 0);
```

(`lnp-quad-eval.c:290`). Thus the prover can choose `h` after learning μ—the dependency behind prior C-F1 remains here. The standalone prover likewise omits the absorption between constructing `h` and invoking `lnp_quad_many_prove` (`:489–505,603–606`).

**Reachability and severity.** The file remains included by `pqzl/src/pqz_lazer.c:14`, and its API is declared in `lazer-in2.h:1464–1483`. Repository-wide call-site search found only definitions and declarations. PQZ relations call the corrected `lnp_tbox_verify` (`pqz_rel.c:1084–1086`). P2 reflects a retained unsafe API; this review establishes no live payment-path forgery.

**Suggested fix.** Remove the unused standalone API, or absorb canonically encoded `h` in both standalone prover and verifier before entering `lnp_quad_many_*`. Add an API-specific binding regression; the existing `fs_bind` checks exercise the tbox entry points.

## Checked and sound

These conclusions concern the active PQZ transcript paths; R1-1 is the standalone exception.

- **Challenge ordering, including B-1:** C generic absorbs `z3/z4`, then `tg`, before V3/V4 (`lnp-tbox.c:1185–1224,1283–1302`); Rust matches (`proof/tbox.rs:791–808`). Both specialised verifiers use the hash after `tg` (`pqz_sv.c:1544,1598,1649`; `sv.rs:1331–1335,1453–1454`). All four absorb `h` before μ. Final `c` binds `t,v,w1` (`lnp-quad.c:478–494`; `proof/quad.rs:137–142`).
- **Separate challenge domains, including A-2:** β4 ends at `M+126`; υ uses `M+127`, binary `M+128`, and exact-ℓ² block `i` uses `M+129+i`. V3/V4 use distinct matrix domains; μ uses the subsequent hash. The schedules agree across generic and specialised implementations (`lnp-tbox.c:1237–1302`; `proof/tbox.rs:640–734`; `pqz_sv.c:1646,1759–1769`; `sv.rs:1446–1454,1567–1580`).
- **Statement binding:** Both PQZL cores seed the transcript with `SHAKE128(tag || op || be32(length) || entire_statement)` (`pqz_rel.c:312–316`; Rust `rel.rs:167–171`). PQZH likewise hashes the entire statement (`ligero/src/transcript.rs:16–18`).
- **`proofSystemId` and `R_REG` message binding:** The ID occupies statement bytes 32–63 and the registration message bytes 64–95 (`pqzl/src/pqz.h:39–47`); both enter the complete-statement hashes above. Their absence from relation equations does not omit them from the transcript.
- **C = Rust, generic and specialised:** The inspected paths agree on round inputs, coefficient reductions, LSB-first encoding, terminal padding, and effective challenge domains. In particular, generic μ polynomial `k` uses domain `k+1`, matching both specialised verifiers (`lazer/polyvec.c:920–929`; Rust `rand/urandom.rs:145–149`; `pqz_sv.c:1842`; `sv.rs:1647`). This is a static transcript comparison.
- **PQZH ordering and domains:** The root precedes aggregation challenges; test polynomials and nonce precede query indices (`ligero.rs:360–362,439–447,542–550`). Challenge sets consume successive words; absorption clears buffered words and resets the counter under the updated state (`transcript.rs:20–42`).

## Not covered

- Full relation arithmetic, parameter-generation correctness, cryptographic primitive internals, FFI/plugin dispatch, and on-chain registration-message construction.
- Exhaustive generated-parameter parity across every relation and all four sets.
- Builds, tests, benchmarks, timing, or executable forgery demonstrations. No files were changed.

Runtime parity and exploitability were not tested; conclusions are limited to the inspected transcript code and call sites.