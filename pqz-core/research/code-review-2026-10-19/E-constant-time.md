# E: constant-time secret arithmetic in the PQZL prover (C core and Rust crate)

Review fix E, 2026-10-19, branch `pqzl-fs3-ct` from `0dc869d`. Codex finding G-1: the prover's control flow depends on
secret witness values (`rel.rs` `set_upsilon` computes the secret slack B² − ‖x‖², `poly.rs` `binexp` branches and
writes per set bit of it, `int.rs` `Int` add / sub branch on signs and borrow; inherited from C `int.c` / `lazer-in2.h`).
Owner ruling 2026-10-19: fix before the merge, in both cores. Proof bytes are unchanged (control flow only).

## Method

The **ctgrind** technique under valgrind 3.22 memcheck (no new packages; the owner installed valgrind on 2026-10-19):

- `pqzl/test/ct.sh <label> [rels] [nprove] [keys]` (under `scripts/capped`) builds the C library objects with
  `-DPQZ_CTGRIND` and build.sh's library flags (`-O2 -fPIC -fstack-protector-strong`, function / data sections) and
  the Rust crate with the test-only feature `ctgrind` (release profile), then runs the
  drivers `pqzl/test/pqz_ct.c` and `pqzl/rust/src/bin/ct.rs` under memcheck. The drivers prove with the **witness and
  `rnd32` marked undefined** (`VALGRIND_MAKE_MEM_UNDEFINED`), so every value derived from them (s1, s2, the slack, the
  masks y, s·c, the inner products of the rejection tests) is "uninitialised" to memcheck, and every branch or address
  computed from one is reported ("Conditional jump or move depends on uninitialised value(s)", "Use of uninitialised
  value of size 8"). The `keys` rounds run KeyGen (seed secret), Enc to two recipients (`seed_enc` and the digits
  secret) and Dec (s secret). memcheck runs with `--max-stackframe=4000000` (the provers' large stack frames). Each
  log's header records the tree: `HEAD` and the sha256 of the uncommitted diff.
- Where a secret-derived value becomes public by design, the code marks it defined again: `PQZ_CT_PUBLIC` /
  `pqz_ct_public_poly(vec)` in C (`pqz_rt.h`, `lazer-in2.h`; no-ops unless `PQZ_CTGRIND`), `ct::public` in Rust
  (`rust/src/ct.rs`; a no-op unless the feature `ctgrind`). The Rust client request is valgrind.h's amd64 magic
  sequence in `core::arch::asm!` (test-only feature; the production crate keeps `forbid(unsafe_code)`). The marks for transcript messages sit at
  the hash sites, right before the coder, not inside it, so the coder itself stays checked on every input.
- Pass: zero reports on both sides, every proof verifies. Counted per error context (distinct stack), as memcheck
  deduplicates.

Limits, stated plainly: memcheck sees only the paths the run takes (the relations and seeds run, not every branch of
every input), only the x86-64 code of this compiler (clang 18.1.3, rustc 1.97.1 from `rust-toolchain.toml`), and only branches and addresses. It
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
| b1 | the rejection verdicts: `lnp_quad_prove` (rej1 on z1, Rej1 on z2, ‖z2‖² ≤ B²) / `quad.rs`; `_lnp_tbox_compute_z34` (z3, z4 bimodal) / `tbox.rs` | observable by design: the per-test verdicts and the try count show in the total prove time. They leak only what the Fiat–Shamir-with-aborts analysis allows (Lyubashevsky; Dilithium; for the one-time commitments the extended-MLWE analysis of LNP22 / LNS21): the try count is geometric with parameter ≈ 1/M per test, but this is not "nothing": e.g. for Rej1 the mass at ⟨z, v⟩ = 0 depends on v. Only the verdict bit is declassified: a rejected try's z, the test's inner products and its exponent stay secret and are checked up to the verdict |
| b2 | each try's transcript messages, marked at the hash site right before the coder (the coder stays checked): tA1, tB after `abdlop_commit` (`do_prove` / `prove_rel`); t, v, w1 (`lnp_quad_prove` / `quad.rs`); ty3, ty4, tβ (`_lnp_tbox_compute_z34` / `tbox.rs`); tg (`lnp_tbox_prove` / `tbox.rs`). z3‖z4 and h are hashed after b3 marked them | they are hashed into the challenges or sent. A rejected try's messages are commitments (ty3 = y3 + B·s21 …, t, v, w1 = HighBits(A1 y1 + A2 y2)), computationally hiding under MLWE; the challenges derived from them are then public too (the challenge-dependent branches, e.g. `R_i[j] == 0`, are class c) |
| b3 | the accepted proof fields: z1, z21 and the hint (`lnp-quad.c` / `quad.rs`), z3, z4 (`lnp-tbox.c` / `tbox.rs`), each h_i after it is formed (c follows from public seeds; tA1, tB by b2) | they are the proof |
| b4 | the witness-valid verdicts: `set_upsilon` (above its bound), `debit_witness` (consistency, ranges), `dr_witness` (range) | the prover fails with `PQZ_ERR_INPUT` on a bad witness: public |
| b5 | the prover self-checks: `__check_coeff0` (`_pqz_eqzero_public`) / `check_coeff0`; the h_i coefficient asserts (on h_i, public by b3) | the verdict is 1 for every valid witness; a failure is an internal error (public) |
| b6 | the samplers' loops: `gaussian155`'s Bernoulli verdict (`grandom.c` / `grandom.rs`); the accept bits of `_urandom_i64` / `urandom_i64` and `_urandom_bnd` / `urandom_bnd` | uniform rejection sampling: the try count is independent of the accepted value. The Gaussian sampler: per try P(accept) = Σ_k exp(−(k−c)²/(2·1.55²))/const, independent of the centre c up to 2·exp(−2π²·1.55²) ≈ 2^−68 (Poisson summation), so the count carries no information on the sample |
| b7 | the rejection-input bound error (`_int2i128` / `int2i128`) | an abort (internal error), never for an honest prover |

The test driver itself declassifies the prove's return code, the proof bytes and the inputs after the call.

### (c) public data only (unchanged)

Statement parsing and the relation build (`build_*`, `rd_poly`, keys), the challenge expansion (`_expand_R_i`, `c`,
the Schwartz–Zippel challenge rows V, μ, γ), the Schwartz–Zippel accumulations over the public z3 / z4 and challenges,
the coder (checked: its inputs are marked public only at the call sites above), arena sizes computed from public proof fields, the verifiers (generic and
specialised; they share a1–a7's routines, whose results are unchanged, so every verdict is unchanged).

### Keys: KeyGen, Enc, Dec (second round, after the rebase onto fixes A–D)

| # | Where (C `pqz_keys.c` / Rust `keys.rs`) | Class | Change |
|---|---|---|---|
| k1 | `pqz_dec` / `dec`: M = floor(t / (2Δ)) − 2^17 with t from w = v − uᵀs | a | x86-64 multiplies, but wasm32 keeps `i64.div_u` by the constant 2Δ: now the fixed-step restoring division (`pqz__div` / `mpn::div`) |
| k2 | `pqz_enc_seed` / `enc_seed`: the digit check `msgs[k][i] > 15` per digit (early return) | a | collected with `\|`, one verdict, declassified (b: the input error is public) |
| k3 | `pqz_keygen` / `keygen`: `ns <= BS² && ne <= BE²` (short-circuit) | b | one `&` verdict, declassified: the counter is an output |
| k4 | `pqz_enc_seed` / `enc_seed`: the resample verdict | b | declassified (the counter is an output) |
| k5 | `canonical (pk)`, the KAT thresholds, `pqz_enc_group_seed` | c | public inputs / derivation only |

The rest (`pqz_keypair_from_secret`, `pqz_encrypt`, `pqz_decrypt_raw`, `set_short`, `wr_poly`) runs on the a1–a4 arithmetic
and showed no report. memcheck contexts, 2 rounds each: before (keys code of `cd881a6`, prover fixes in place) C 18
(`pqz_enc_seed` digit checks 16, resample 1, `pqz_keygen` 1), Rust 21 (the digit `any` 16, `keygen` 4, `enc_seed` 1);
after 0 / 0 (`ct-keys-before.txt`, `ct-ct2.txt`). Outputs unchanged: the C keys KAT against `pqz_kat.py --c-keys` ok,
the Rust keys KAT (`rust/run.sh`) ok.

### Not in this fix (open)

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

**Final evidence on the committed, rebased tree** (`ct-ct2.txt`: `HEAD 7659e56`, empty diff, `test/ct.sh ct2 383 3 2`):
R_REG, R_TX, R_BURN, R_DS, R_DR, R_TX0, R_TXM (M = 1, auditor on) and R_TXM (M = 4, auditor on), three proofs each,
plus two rounds of KeyGen / Enc / Dec: C 0 reports, Rust 0 reports, every proof verifies, every Dec returns the digits.
The earlier rows above ran on `0dc869d` + uncommitted changes (before the rebase). The same tree: `relfix.sh ct2` (KAT 19/19, `check_tbox_fixes` ok,
FNVs = Task 4's native and wasm32, fails 0, ASan only the known UBSan notes), `sv/diff.sh ct2` portable pass 0 mismatches
(x86v3 / z21diff deferred to the Task 9 gate), `rust/run.sh ct2` fully green, `ffi/vectors/run.sh ct2` ok, C keys KAT
against `pqz_kat.py --c-keys` ok.

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

## Timing

Measured 2026-10-19 16:12–16:42 by the controller on an idle host (owner stopped the other session and the knowledge / odoo19 / mssql / timescaledb / odoo-uuidv7 containers; load 0.46 at start): the Rust crate, `0dc869d` vs `06e0384` (fix E), same session, two rounds interleaved base / new, the six forms plus R_TXM8 / R_TXM8_0, `pqz-core/pqzl/rust/runs/ct-timing/` (`ct-timing.sh`, `summarize.py`, `summary.md`; `env.txt`'s rustc line is the system rustc, the binaries are built with the crate's pinned toolchain 1.97.1). p50 ratio new / base: **verify_fast (the node's path, the gas basis) 1.00–1.02 native, 1.00–1.01 wasm32**: the gas calibration margin is untouched; generic verify 1.11–1.16 native, 1.13–1.15 wasm32 (fallback / cross-check path only); prove 1.04–1.09 native, 1.02–1.06 wasm32 (e.g. wasm32 R_TX 2.18 → 2.23 s, R_TXM8 2.76 → 2.93 s). No variable-time verifier copies needed.

Plan before the run (kept):

Prove and verify p50 / p99, native and wasm32 (`pqz_bench` / `node test/run_wasm.mjs` with `NP` / `NV`, the Rust
`bench` and `wasm/run_wasm.mjs`), against `0dc869d`: `int_add` / `int_sub` now form three limb vectors instead of one,
`int_redc` always reads both candidates, `decompose` always divides, and `ct::mask` goes through `black_box` (a stack
round trip in Rust). The verifiers share these routines, so verify time moves too. Expected: a few percent on prove,
less on verify; if verify regresses beyond the gas calibration's margin, the verifier can keep variable-time copies
(its inputs are public).
