# O: constant-time secret arithmetic and wiping in the PQZH prover (Ligero)

Review round 2 fixes P-A, P-B, P-C (triage in [J-agy-pqzh-rust.md](J-agy-pqzh-rust.md); findings A-F1, A-F2, A-Note,
I-2, I-5, I-6, K-F1…F4), 2026-10-19, branch `rev2-pqzh` from `b1c4de5` (plan Task 5c). The method is PQZL fix E's
([E-constant-time.md](E-constant-time.md)) and fix B's (`Wiped`). Rule: control flow only; proof bytes and verdicts
unchanged (all twelve relations byte-equal before / after, below).

## Method

The **ctgrind** technique under valgrind 3.22 memcheck, as in fix E:

- `pqzh/ligero/runs/ct.sh <label> [rels] [nprove]` (under `scripts/capped`) builds the crate with the test-only
  feature `ctgrind` (release profile, x86-64, rustc 1.97.1 from `rust-toolchain.toml`) and runs the driver
  `src/bin/ct.rs` under memcheck. The driver proves at THE preset with the **witness and `rnd32` marked undefined**
  (`ct::secret`), so every value derived from them (the witness rows, the row polynomials, the masks, the salts, the
  encodings, the test polynomials before they are published, the honest prover's decryptions) is "uninitialised" to
  memcheck, and every branch or address computed from one is reported. Each proof is then verified.
- Where a secret-derived value becomes public by design the code marks it defined again (`ct::public`,
  `ct::verdict` in `src/ct.rs`; no-ops unless `ctgrind`). The client request is valgrind.h's amd64 magic sequence in
  `core::arch::asm!`, test-only: the production crate has `#![forbid(unsafe_code)]` (review P-E); only under `ctgrind`
  is it `deny`, with `#[allow(unsafe_code)]` on the two request functions.
- Pass: zero reports ("Conditional jump or move depends on uninitialised value(s)", "Use of uninitialised value",
  "Syscall param"), every proof verifies. Counted per error context, as memcheck deduplicates.

Limits, as fix E's: only the paths the runs take (the twelve relations at one seed each), only this compiler's
x86-64 code, only branches and addresses (a `cmov` / wasm `select` propagates the taint and is not reported, nor is a
variable-latency instruction such as a division). wasm32 is checked by reading the generated code (below). Not a
timing measurement; nothing was timed beyond what the existing tests and `gateb.sh` already time.

## Inventory

(a) = secret-dependent branch / address / variable-latency instruction, **fixed**; (b) = public by design,
**declassified**; (c) = public data only, unchanged.

### (a) fixed

| # | Where | Secret | What it did | Fix |
|---|---|---|---|---|
| a1 | `fft.rs` `Domain::rec` (P-A) | the witness rows in `hk.ifft` (prove_once), via the radix stage's inputs | filtered the stage's values for zeros, branched on their count (`nz.len() * 4 < r`), indexed `eps[s * u % r]` with the secret-selected `s` | the sparse path is chosen from the structural zero padding: `rec` carries `len` (inp[j] = 0 for j ≥ len), sub-transform s is zero iff `s · stride ≥ len`, so only the first `ns = ⌈len / stride⌉` are summed; `ifft` passes `len = n`, so the inverse transform (the witness) is always dense. The forward transform of zero-padded coefficients (`coset_fft`, `h2.fft`) keeps the speed-up. Outputs identical (the skipped terms are exact zeros) |
| a2 | `ring.rs` `dot_int` (P-B) | s, s_f, r_g (second operand; `keypair`, `encrypt`, the R_TX / R_DR decryptions) | `if y[m] == 0 { continue }`: a skipped 64-iteration loop per zero coefficient | no skip; the negacyclic wrap split by index (`0..D−m`, `D−m..D`) instead of a per-term branch |
| a3 | `ring.rs` `modq` (P-B) | A s + e, Aᵀr + e1, pkᵀr + e2 + Δm, v_T − u_Tᵀs_f, v − uᵀs | `rem_euclid(q)` (wasm32 `i64.rem_s`), centring `if r > (q−1)/2` | `Fq::from_i64` (a4), then the centring by a mask through `ct::mask` (`black_box`): with a plain mask x86-64's cmov conversion still emitted a branch here (memcheck run `ct-rev2-wip`: 6 contexts, `encrypt`'s and `dr`'s `modq`), the same lesson as fix E a3 |
| a4 | `fq.rs` `Fq::from_i64` (P-B) | every witness value and square (`cs::rows`), via `modq` | `rem_euclid(q)`: wasm32 `i64.rem_s` | \|v\| folded twice at 2^42 = 215 (mod q), a masked final subtraction, the negation selected by the sign mask; no division |
| a5 | `fq.rs` `red`, `limb::red3`, `Add`, `Sub` (P-B) | every prover product and sum | `if x >= q { x − q }`, `if a >= b` (compiled to cmov / setcc on x86-64: the negative control shows no report there; a wasm `select` / branch is the engine's) | `csub` (mask from the borrow's sign bit) and a masked borrow in `Sub` |
| a6 | `cs.rs` `witness` (P-B) | w = modq(v_T − (u_Tᵀs_f)_i), M_i, e_T, d, d′, the carries, the l2 norms, A s + e, u, v | round-half-away branch on the sign of w and `/ Δ` (wasm32 `i64.div_s`); `s % 16`, `s.div_euclid(16)`; per-coefficient range checks with an early return and `\|\|` short-circuits (digits, M, e_T, carries, carry out, norms, R_DR's e′); `Vec !=` (memcmp's early exit) of A s + e, u, v against the statement | `round_delta`: sign and magnitude over `ct_udiv`, a fixed 64-step restoring division (PQZL `ct_sdiv`'s idea); `& 15`, `>> 4`; every check a 0 / nonzero word OR-ed into one verdict per error message (b4); `diff` = OR of XORs |
| a7 | `ligero.rs` `prove_once` (P-B) | the quadratic remainder | `rem.iter().any(\|v\| v != 0)` | OR fold, one verdict (b5) |

### (b) public by design: the declassification points

| # | Point | Why it is public |
|---|---|---|
| b1 | the commitment root (`prove_once`, right after `tree.root()`) | sent in the proof; the Merkle leaves are salted column hashes (hiding) |
| b2 | w, q, h (`prove_once`, as each is formed) | proof fields, masked in exactly their spaces (design note §4.1) |
| b3 | the finished proof (`prove_once`'s last line): the opened columns, their salts, the multiproof digests | the proof; t = 121 ≤ k − ℓ − 1 openings reveal nothing of the witness (zero knowledge) |
| b4 | the witness-valid verdicts of `cs::witness`: "witness norm", "pk != A s + e", "pk_f != A s_f + e_f", "ciphertext", "digits", "carry", "carry out", "not an encryption of amount" | the prover returns the error: its output. One verdict per message (for a valid witness all are 0); the message order changed for a witness with several faults ("digits" before "carry" across all coefficients; tests check only `is_err`) |
| b5 | the prover's self-checks: "quadratic constraints" (OR of the remainder); "linear constraints" is computed on the published q | 0 for every valid witness; a failure is the prover's error |
| b6 | `Rng::fq`'s accept bit (`v < q` on a 42-bit word) | uniform rejection sampling: the try count is independent of the accepted value |

### (c) public data only (unchanged)

Statement parsing (`pqz-stmt`, `cs::parse`, `polys_of`, `centre`), the layout, the linear test's combination vectors
(`cs::comb`, `Bld::ring` over A and the statement), the transcript and its challenges, the PoW search, the query
indices and the multiproof index logic, the domains, `interp` of the public combination vectors, `Domain::pw` and
`Domain::new`'s `(q − 1) / n` (the two divisions left in the wasm32 code), and the whole verifier.

## Wiping (P-C)

Fix B's pattern: a drop guard `Wiped<T: Wipe>` (`lib.rs`; plain stores plus `black_box`) on every secret buffer, so
every exit (`?` and the retry loop's discarded attempts included) clears it, and `Wit` wipes itself on drop.
Wiped: the witness values (`Wit`, and `witness()`'s locals s, e, s_f, e_f, r_g, e1_g, e2, d_j, d′, the decryption
u_Tᵀs_f / uᵀs, M, e_T, the carries, the slack list), the polynomial copies (`polys`) and the products inside
`keypair` / `encrypt` / `dot_int`, the A s + e / u / v recomputed for the checks; in `prove_once` the rows, the row
polynomials `pc`, the per-row message ‖ tail buffer, the masks u_0, u_lin, h_0, u_quad, the encodings `enc`, the
salts, each column buffer, `pe`, the q and quadratic accumulators and their inverse transforms, the remainder; in the
FFT the padded input copy, the coset-scaled copy and the stage scratch `t`. The SHAKE256 reader (its state yields
every mask and salt: Keccak-f is a permutation) is replaced in place on drop: sha3 0.10.8 has no `zeroize` feature
and no `Drop`, and reaching the state otherwise needs `unsafe`. Buffers sized up front (`Vec::with_capacity`) where
growth would leave a stale copy behind.

Platform boundary (as fix B, stated in `lib.rs`): best effort, not guaranteed; the compiler is not bound to keep the
stores, and copies it or the allocator made are never cleared: by-value arguments (`rnd32` through `prove`,
`prove_inner`, `Rng::new`, and pqz-ffi's `*rnd32`), moves, register spills, stack temporaries (e.g. `dot_int`'s
returned array), and the sha3 hasher's state before `finalize_xof` (moved by value). The published values (w, q, h,
the opened columns) are not secret.

## Results

Runs in `pqzh/ligero/runs/`:

| Run | Code | Relations (1 proof each) | memcheck contexts / errors |
|---|---|---|---|
| `ct-rev2-control.txt` (negative control) | a scratch copy of this branch with the **old** arithmetic restored (fq branches and `rem_euclid`, `dot_int` skip, `modq`, the value-based FFT decision, the rounding branch, the per-coefficient early returns, the keypair `!=`), the new marks kept | R_REG, R_TX, R_DR | **21** / 11,034,666 |
| `ct-rev2-wip.txt` | this branch before the `ct::mask` barrier in `modq` | all twelve | **6** / 1,120 |
| `ct-rev2.txt` | this branch, committed (`HEAD 50e5dbc` in its header, empty diff of `pqzh/ligero`) | all twelve | **0** / 0 |

Negative control by top frame: the FFT's value filter 8, `dot_int` 7, the digit / range checks 5 (`cs.rs` and the
`any` closure), `bcmp` (the keypair `!=`) 1. Not reported there, though changed: the conditional subtractions, the
rounding branch and `modq`'s centring (compiled to cmov / setcc), and the divisions (x86-64 multiplies; they matter on
wasm32, below). `ct-rev2-wip`: `modq` (inlined into `encrypt` and R_DR's witness) 6, i.e. LLVM turned the mask back
into a branch, fixed by `ct::mask`.

Every proof verified, and each proof's FNV-1a equals the base run's at the same seed (`[0; 32]`): R_REG `0ecf451a`,
R_TX `534b3a74`, R_BURN `f4fef37e`, R_DS `0a7acf34`, R_DR `e42aa3da`, R_TX0 `360216a0`, R_TXM1 / 2 / 4 `f67f3b40`,
`ff71ea35`, `7a69ddcb`, R_TXM1_0 / 2_0 / 4_0 `547bc12e`, `07d08cd9`, `e02eb2df` (`rev2-fnv-compare.txt`: native
`ligero_bench` before (`b1c4de5`) and after, both seeds, all twelve identical).

## Generated code (wasm32)

`cargo rustc --release --no-default-features --lib --target wasm32-unknown-unknown -- --emit=asm`, 64-bit divisions
and remainders per function counted by `runs/wasm_div.py` (functions as LLVM emitted them, inlining included):

| | before (`rev2-wasm-div-before.txt`, `b1c4de5`) | after (`rev2-wasm-div-after.txt`) |
|---|---|---|
| `Fq::from_i64` | `i64.rem_s` 1 | none |
| `ring::modq`, `keypair`, `encrypt` | `i64.rem_s` 1, 1, 2 | none |
| `cs::rows` | `i64.rem_s` 4 | none |
| `cs::witness` (closure #17, R_DR) | `i64.rem_s` 1 | none |
| `ligero::prove_once` | `i64.rem_s` 1, `i64.div_s` 1 | none |
| `cs::Bld::ring`, `Bld::rsum` (public A, statement) | `i64.rem_s` 1, 1 | none |
| `Domain::pw` (public exponent), `Domain::new` / `try_new` (`(q − 1) / n`) | `i64.rem_s` 1, `i64.div_u` 1 | the same (public) |

No `__divti3` / `__modti3` calls. Not read: the engines' lowering of `select` and of the `__multi3` u128 products
(V8, SpiderMonkey, wasmtime tiers); as fix E, a tier that branched on a `select` would not be seen here.
