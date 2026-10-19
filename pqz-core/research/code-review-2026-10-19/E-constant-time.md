# E: constant-time secret arithmetic in the PQZL prover (C core and Rust crate)

Review fix E, 2026-10-19, branch `pqzl-fs3-ct` from `0dc869d`. Codex finding G-1: the prover's control flow depends on
secret witness values (`rel.rs` `set_upsilon` computes the secret slack B² − ‖x‖², `poly.rs` `binexp` branches and
writes per set bit of it, `int.rs` `Int` add / sub branch on signs and borrow; inherited from C `int.c` / `lazer-in2.h`).
Owner ruling 2026-10-19: fix before the merge, in both cores. Proof bytes are unchanged (control flow only).

## Method

The **ctgrind** technique under valgrind 3.22 memcheck (no new packages; the owner installed valgrind on 2026-10-19):

- `pqzl/test/ct.sh <label> [rels] [nprove]` (under `scripts/capped`) builds the C library objects with `-DPQZ_CTGRIND`
  at the production `-O2` and the Rust crate with the test-only feature `ctgrind` (release profile), then runs the
  drivers `pqzl/test/pqz_ct.c` and `pqzl/rust/src/bin/ct.rs` under memcheck. The drivers prove with the **witness and
  `rnd32` marked undefined** (`VALGRIND_MAKE_MEM_UNDEFINED`), so every value derived from them (s1, s2, the slack, the
  masks y, s·c, the inner products of the rejection tests) is "uninitialised" to memcheck, and every branch or address
  computed from one is reported ("Conditional jump or move depends on uninitialised value(s)", "Use of uninitialised
  value of size 8").
- Where a secret-derived value becomes public by design, the code marks it defined again: `PQZ_CT_PUBLIC` /
  `pqz_ct_public_poly(vec)` in C (`pqz_rt.h`, `lazer-in2.h`; no-ops unless `PQZ_CTGRIND`), `ct::public` in Rust
  (`rust/src/ct.rs`; a no-op unless the feature `ctgrind`). The Rust client request is valgrind.h's amd64 magic
  sequence in `core::arch::asm!` (test-only feature; the production crate keeps `forbid(unsafe_code)`).
- Pass: zero reports on both sides, every proof verifies. Counted per error context (distinct stack), as memcheck
  deduplicates.

Limits, stated plainly: memcheck sees only the paths the run takes (the relations and seeds run, not every branch of
every input), only the x86-64 code of this compiler (clang 18.1.3, rustc 1.97.1), and only branches and addresses. It
does not report a `cmov` / wasm `select` on a secret (it propagates the taint instead; both are constant-time on the
targets' hardware), and not variable-latency instructions (a division). wasm32 is covered by reading the generated
code (below), not by a tool. This is not a timing measurement; timings were not run (see "To measure").

## Inventory

(a) = secret-dependent branch / address / variable-latency instruction on witness-derived values, **fixed**; (b) =
inherent and public by design, **declassified** (listed); (c) = public data only, unchanged. C and Rust have the same
structure; each row names both. The memcheck counts per row (before the fix, with the (b) points in place) are under
Results.

### (a) fixed

| # | Where (C / Rust) | Secret | What it did | Fix |
|---|---|---|---|---|
| a1 | `int_add`, `int_sub` (`lazer-in2.h`) / `Int::add`, `Int::sub` (`int.rs`) | every prover sum: s·c, z = y + cs, w, the evaluations, the slack | branch on equal signs, on the borrow, and `limbs_from_twoscom`'s conditional negate | both \|a\|+\|b\| and \|a\|−\|b\| and its negation formed, selected by masks (`pqz_int_addsub` / `Int::addsub`); same bits as upstream, negative zero included |
| a2 | `int_redc` / `Int::redc` | centring of secret coefficients (`poly_redc`, the SZ accumulators) | variable-time `limbs_lt` and a branch | `limbs_lt_ct` (borrow) + masked select |
| a3 | `limbs_cnd_select` (via `int_redp`) / `Int::redp` | `redp` of secret coefficients (commitment, ty, t) | already masks in the source, but clang 18 compiled them to a `cmov` of **pointers** plus a load: a secret-dependent address ("Use of uninitialised value of size 8") | value barrier on the mask: `pqz_ct_barrier` (empty `asm`, no instruction) / `ct::mask` (`core::hint::black_box`) |
| a4 | `pqz__cnd_sub_ge` (`pqz_mpn.h`, the restoring division behind `int_mod` / `int_div`) / `mpn::cnd_sub_ge` | multi-limb `mod` / `div` of secrets (`dcompress`) | the same cmov-of-pointers pattern | value barrier |
| a5 | `int_mul_sgn_self`, `intvec_mul_sgn_self` (C only) | the sign β3 / β4 (`_lnp_tbox_compute_z34`) | `ASSERT_ERR (sgn == 1 \|\| sgn == -1)`: a branch on the secret sign | assert removed (β = 1 − 2·bit by construction; Rust never had it) |
| a6 | `int_binexp` (`int.c`) / `Poly::binexp` (`poly.rs`) | the l2 slack B² − ‖x‖² (`set_upsilon`) | per bit: `if (B_ >= 2^i) { B_ -= 2^i; coeff_i = 1 }` | every bit written (0 / 1), 2^i masked before the subtraction (a masked-out 0 leaves B_ unchanged, sign included) |
| a7 | `dcompress_decompose`, `_power2round`, `_make_ghint` (`dcompress.c`) / `Dcomp` (`coder.rs`) | w = A1 y1 + A2 y2 (`lnp_quad_prove`: w0 is part of the rejection condition), tA (`abdlop_commit`), the hint inputs y22, w1 | upstream "not ctime": centring branches, the `r1 == q − 1` branch, conditional −2^D, the hint centring | masked `_cnd_addsub` / `_centre` (`cnd_addsub` / `centre`); the public-divisor division always runs and is selected |
| a8 | `_int2i128` (`rejection.c`) / `int2i128` (`rejection.rs`) | ⟨z,v⟩, ⟨v,v⟩ | `ERR` bound checks per limb and on the top bits | bound collected without a branch; only the abort verdict declassified (b7) |
| a9 | `dec_w`, `debit_witness`, `dr_witness` (`pqz_rel.c`) / the same in `rel.rs` | the decryption w = v − uᵀs, M_i, carries, e_T, d, d′ | round-half-away branch on w; centring branches; early returns and `\|\|` short-circuit chains on the consistency / range checks; **divisions** `% q`, `/ Δ`, `/ 16`, `% 16` (x86-64: multiplies; wasm32: `i64.rem_s` / `i64.div_s`, whose latency is the engine's and the CPU's) | masks; `ct_sdiv` (C) / `ct_sdiv` (Rust): sign-magnitude over the fixed-step restoring division of `pqz_mpn.h` / `mpn.rs`; `/ 16`, `% 16` as shifts and masks; checks OR-ed into one verdict, declassified (b4) |
| a10 | `_urandom_i64` (`urandom.c`) / `urandom::gt` (`urandom.rs`) | the accepted uniform values (masks g, s2) | `ASSERT_ERR (tmp < mod)`, `(tmp >= 0)` after the accept (C); `x == y && r` short-circuit (Rust) | asserts dropped (true by the accept test and by construction); `&` |

### (b) public by design: the declassification points

| # | Point (C / Rust) | Why it is public |
|---|---|---|
| b1 | the rejection verdicts: `lnp_quad_prove` (rej1 on z1, Rej1 on z2, ‖z2‖² ≤ B²) / `quad.rs`; `_lnp_tbox_compute_z34` (z3, z4 bimodal) / `tbox.rs` | standard for Fiat–Shamir with aborts (Lyubashevsky; Dilithium): by the rejection lemma the number of tries is geometric with a witness-independent parameter (≈ 1/M per test), so the verdicts reveal nothing. Only the verdict bit is declassified: a rejected try's z and the test's inner products and exponent stay secret and are checked up to the verdict |
| b2 | every transcript message the coder encodes: `coder_enc_urandom`, `_grandom`, `_ghint` entries (`coder.c`) / `Coder::urandom`, `Coder::grandom` (`proof/mod.rs`) — tA1, tB (ty3, ty4, tβ, tg, t), v, w1, z3‖z4, h | they are hashed into the challenges or sent. A rejected try's messages are commitments (ty3 = y3 + B·s21 …, t, v, w1 = HighBits(A1 y1 + A2 y2)), computationally hiding under MLWE; the challenges derived from them are then public too (the challenge-dependent branches, e.g. `R_i[j] == 0`, are class c) |
| b3 | the accepted proof fields: z1, z21 and the hint (`lnp-quad.c` / `quad.rs`), z3, z4 (`lnp-tbox.c` / `tbox.rs`), each h_i after it is formed, all fields in `encode_proof` (Rust) | they are the proof |
| b4 | the witness-valid verdicts: `set_upsilon` (above its bound), `debit_witness` (consistency, ranges), `dr_witness` (range) | the prover fails with `PQZ_ERR_INPUT` on a bad witness: public |
| b5 | the prover self-checks: `__check_coeff0` (`_pqz_eqzero_public`) / `check_coeff0`; the h_i coefficient asserts (on h_i, public by b3) | the verdict is 1 for every valid witness; a failure is an internal error (public) |
| b6 | the samplers' loops: `gaussian155`'s Bernoulli verdict (`grandom.c` / `grandom.rs`); the accept bits of `_urandom_i64` / `urandom_i64` and `_urandom_bnd` / `urandom_bnd` | uniform rejection sampling: the try count is independent of the accepted value. The Gaussian sampler: per try P(accept) = Σ_k exp(−(k−c)²/(2·1.55²))/const, independent of the centre c up to 2·exp(−2π²·1.55²) ≈ 2^−68 (Poisson summation), so the count carries no information on the sample |
| b7 | the rejection-input bound error (`_int2i128` / `int2i128`) | an abort (internal error), never for an honest prover |

The test driver itself declassifies the prove's return code, the proof bytes and the inputs after the call.

### (c) public data only (unchanged)

Statement parsing and the relation build (`build_*`, `rd_poly`, keys), the challenge expansion (`_expand_R_i`, `c`,
the Schwartz–Zippel challenge rows V, μ, γ), the Schwartz–Zippel accumulations over the public z3 / z4 and challenges,
the coder internals on declassified inputs, arena sizes computed from public proof fields, the verifiers (generic and
specialised; they share a1–a7's routines, whose results are unchanged, so every verdict is unchanged).

### Not in this fix (open)

- `pqz_decrypt_raw` / `pqz_keys.c` Dec (`t / (2Δ)`) and `keys.rs`: the wallet's decryption with the secret key is not
  the prover; it now runs on the constant-time arithmetic, but its own division and the keygen / Enc paths were not run
  under ctgrind. Fixes A–D touch `keys.rs`; a follow-up can apply `ct_sdiv` there.
- wasm32 is checked by reading the code only; the engines' tiers (Liftoff / TurboFan, wasmtime) decide how `select`
  and `i64.mul` are lowered.

## Results

Runs (`pqzl/test/runs/ct-*.txt`: `ct-before-raw`, `ct-before-decl-c`, `ct-before-decl-rust` (scratch trees built from
`0dc869d` as described), `ct-after3c` (C), `ct-rust-final` (Rust)):

| Run | Code | Relations (1 proof each) | memcheck contexts / errors |
|---|---|---|---|
| C before-raw | `0dc869d` + the driver, no declassification at all | R_REG | 197 / 15,094,028 |
| C before-decl | `0dc869d` arithmetic + the (b) points (and a10's dropped asserts) | R_REG, R_TX, R_BURN, R_DS, R_DR, R_TX0, R_TXM (M = 1) | **135** / 29,112,243 |
| C after (`ct-after3c`) | this branch | the same seven | **0** / 0 |
| Rust before-decl | `0dc869d` `int.rs`, `mpn.rs`, `poly.rs`, `rejection.rs`, `rel.rs`, `coder.rs` + the (b) points | the same seven | **141** / 18,435,062 |
| Rust after (`ct-rust-final`) | this branch | the same seven | **0** / 0 |

C before-decl by top frame (contexts): `int_add` 29, `limbs_to_twoscom` 15, `int_sub` 14, `int_redc` 10, `limbs_lt` 10,
`_int2i128` 9, `dcompress_decompose` 9, `limbs_cnd_select` 9 (all "Use of uninitialised value": the address),
`int_mul_sgn_self` 8, `intvec_mul_sgn_self` 8, `debit_witness` 6, `dcompress_make_ghint` 3, `dr_witness` 2,
`dcompress_power2round` 1, `int_binexp` 1, `pqz__cnd_sub_ge` 1 (address).
Rust before-decl: `Int::add` 43, `from_twoscom` 22, `debit_witness` 22 (incl. the `any` closure), `Int::redp` 15 (LLVM
turned the source's mask select into a **branch**: the reason for `ct::mask`'s barrier), `Int::sub` 13, `int2i128` 8,
`Dcomp::decompose` 9, `Dcomp::make_ghint` 3, `dr_witness` 1, `Dcomp::power2round` 1, `Poly::binexp` 1, `cnd_sub_ge` 1,
other inlined 3.

Every proof verified, and each relation's proof is byte-identical before / after and C / Rust (FNV-1a of the first
proof: R_REG 563d42ff, R_TX dc0f804c, R_BURN 8511a528, R_DS f2f9656d, R_DR 8149b562, R_TX0 7b49e3f7, R_TXM1 1eea8091).

One pitfall found on the way (Rust): `ct::public(&rej)` followed by `if rej` still branched on the register copy, which
memcheck rightly kept secret (through a shared reference the compiler may assume the value unchanged). Scalar verdicts
therefore go through `ct::verdict`, which marks a memory copy and reads it back (volatile).

## Generated code (x86-64, wasm32)

C (`clang 18.1.3 -O2`, the library's flags) and Rust (rustc 1.97.1, release), x86-64 and wasm32, read for the
changed routines:

- **cmov of pointers.** Before: `int_redp` compiled `limbs_cnd_select` to `cmove %r11,%rbx; movdqu (%rbx),%xmm0`
  (a load from a secret-selected address). After: no cmov in `intvec_redp`; memcheck reports no address use.
- **Divisions on secrets.** Before, wasm32 `pqz_prove` (inlined witness code) had `i64.div_s` by Δ = 2^26 − 1 and by 16
  and `dec_w` an `i64.rem_s` by q (x86-64 strength-reduces these to multiplies; wasm32 has no 64-bit multiply-high, so
  LLVM keeps the division and the engine decides). After: no 64-bit division left in `pqz_rel.c`'s wasm32 code, nor in
  the Rust prover's (the remaining `i64.div_s` / `rem_s` of the Rust wasm32 build are in `keys::dec` (open item above),
  the coder's encoding of public fields, the specialised verifier and `tbox::vr_polys`, all public).
- **Remaining conditional branches** in `pqz_int_addsub`, `_cnd_addsub`, `_centre`, `dcompress_*`, `int_binexp`
  (wasm32 `br_if`, x86-64 `jcc`) and in Rust `Int::addsub` / `redc` / `redp`, `cnd_addsub`, `centre`, `Dcomp::decompose`,
  `Poly::binexp`: on the limb count (public; LLVM unrolls per n = 1..8), loop bounds, `geq` / `m_odd` / `sub`
  (constants) and the `pqz_err` asserts. Data-dependent choices are `i64.select` / `i32.select` (1–5 per routine) on
  wasm32 and `cmov` on x86-64 (V8 and wasmtime lower `select` to `cmov` on x86-64; a tier that branched would not be
  seen here). Counts (wasm32 `br_if` / x86-64 jcc, before → after): `intvec_add` 28 → 10 / 32 → 10,
  `dcompress_decompose` 125 → 76 / 170 → 88, `dcompress_make_ghint` 69 → 37 / 94 → 37, `dcompress_power2round` 25 → 24
  / 44 → 25 (`pqz_ct_barrier` itself emits no instruction: an empty `asm` with a register operand).

## To measure (not run: the owner stops another session first)

Prove and verify p50 / p99, native and wasm32 (`pqz_bench` / `node test/run_wasm.mjs` with `NP` / `NV`, the Rust
`bench` and `wasm/run_wasm.mjs`), against `0dc869d`: `int_add` / `int_sub` now form three limb vectors instead of one,
`int_redc` always reads both candidates, `decompose` always divides, and `ct::mask` goes through `black_box` (a stack
round trip in Rust). The verifiers share these routines, so verify time moves too. Expected: a few percent on prove,
less on verify; if verify regresses beyond the gas calibration's margin, the verifier can keep variable-time copies
(its inputs are public).
