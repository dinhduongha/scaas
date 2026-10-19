# K: PQZH Rust security review, round 2 (Claude, 2026-10-19)

Static, read-only review of the frozen worktree `/home/ha/work/ainative/scaas/.claude/worktrees/rev2` (detached at
`e9cabd1`). Nothing was built, run, fuzzed or timed. All `path:line` references are relative to that tree.

**Primary scope (live):** `pqz-core/pqzh/ligero/` (`src/{fq,ring,fft,merkle,transcript,cs,ligero}.rs`, `client.rs`
skimmed, `wasm/lib.rs`), the PQZH path of `pqz-core/ffi/` (`src/lib.rs`, `src/pqzh.rs`, `src/selftest.rs`, PQZH parts
of `src/fixture.rs`, `wasm/lib.rs`, `build.rs` self-test vector), `pqz-core/stmt/src/lib.rs`, and
`pqz-core/pqzh/xcheck/`. **Secondary scope:** `pqz-core/pqzh/stark-backup/` (round-1 findings re-verified only).

**Tree delta since round 1.** `git diff 4c20032 e9cabd1` touches no file under `pqz-core/pqzh/ligero/src`. In the
scope it changes only `stmt/src/lib.rs` (PQZL id v2 → v3), `stmt/src/tests.rs`, `stark-backup/src/rel.rs` (the PQZL id
constant) and doc comments in `ffi/src/pqzl/*` / `ffi/src/bin/pqz-vectors.rs`. So every round-1 Ligero finding is
still present at the same lines. I re-checked each one against the code rather than relying on that diff.

**Result: no P0 and no P1 in the live scope.** The verifier (Fiat–Shamir order, Ligero tests, query sampling, Merkle
verification, canonical decoding, length gates) is sound and consensus-safe as far as static reading can establish.
The open issues are all on the prover side:

- one P2: the sparse FFT branches on witness values (A-F1, still present);
- four P3s: the `dot_int` skip and the rounding branches (A-F2, now with one more site); divisions on secrets on wasm32,
  with no constant-time verification of the PQZH prover at all; no wiping of secrets (A-Note, now behind PQZL's fix B);
  infallible allocation, so an out-of-memory verify aborts the process instead of returning a node fault;
- one P3 hygiene item: safe `extern "C"` exports in the bench/test wasm wrappers do unchecked raw-pointer work.

---

## Findings

### F1 — P2 — The sparse-DFT shortcut branches on raw witness values when the prover interpolates the witness rows (round-1 A-F1, still present)

**Locations**
- `pqz-core/pqzh/ligero/src/fft.rs:119-128`:
  - line 121 filters on the value (`filter(|x| *x.1 != 0)`);
  - line 122 is the branch (`nz.len() * 4 < r`);
  - line 124 is the secret-selected table address `eps[s * u % r]`. The `%` there also runs on a secret-selected `s`.
- Secret input: `pqz-core/pqzh/ligero/src/ligero.rs:285-292`, `hk.ifft(&v)` at line 290, where `v` is a witness row
  (ℓ = 695 message slots) followed by the k − ℓ = 122 uniform tail values.

**Trigger (traced)**
1. `Domain::new(817)` builds radices `[19, 43]` (fft.rs:30-47).
2. `ifft` → `rec(level 0, r = 19)` recurses into 19 sub-DFTs at level 1 with `r = 43`, `m = 1`, `stride = 19`.
3. At `k = 0` every twiddle is `w[0] = 1` (fft.rs:117), so `t[s]` is exactly `v[s0 + 19·s]`. That is the raw slot
   values of one residue class mod 19.
4. A class holds 37 message slots and 6 tail values when s0 < 11, and 36 and 7 when s0 ≥ 11. The sparse path runs
   when nz ≤ 10, which means at most 4 (or 3) nonzero witness values in the class.
5. Rows that cross that threshold:
   - **R_TX small-value row:** digits, d′, M, carries, e_T. Its high digits and carries are mostly 0, so the decision
     encodes the magnitude of the amount and of the balance.
   - **CBD(1) bit rows j = 1..5:** bit j of x + 64 is 1 exactly when x = −1, so about 2 % of classes take the sparse
     path and reveal the exact positions of the −1 coefficients.
   - **Square rows and packed small-bit rows:** the same pattern as above.
6. The other FFT call sites leak nothing. `coset_fft` / `h2.fft` see masked coefficients: a value is zero with
   probability 1/q, and the zero padding is public. `ifft4(qe)` is dense. `ifft4(pq)` is zero exactly on ζ, which is
   public for a valid witness.

**Impact**
- A local observer (a branch-predictor or cache-line observer, or a coarse timer summed over classes) learns zero
  patterns and magnitudes of the witness. The most practical case is a co-tenant in the wallet's wasm prover.
- This contradicts pq-zero-knowledge.md §11 ("the code avoids secret-dependent branches and indices") and T11.

**Confirmed or hypothesis:** confirmed on the code path. How exploitable it is in practice was not measured.

**Suggested fix**
- **Smallest:** never take the sparse path in the inverse transform. At fft.rs:122 write
  `if !inv && nz.len() * 4 < r`.
  - `ifft` is called only on the witness rows, on public `interp` vectors (already about 36 of 43 nonzero at that
    stage) and on the dense `ifft4` inputs, so the cost is negligible.
  - The forward `fft` keeps its speed-up on the structural zero padding of `coset_fft`. There a value-based decision
    differs from the structural one only with probability 1/q per coefficient.
- **Cleaner:** decide sparsity from the structural length `a.len()` instead of the values.
- Either way the output values are identical: **no change to proof bytes or verdicts**. Re-time the prover after the
  change.

### F2 — P3 — `dot_int` skips zero secret coefficients; rounding and centring branch on secret decrypted values (round-1 A-F2, still present, one more site)

**Locations**
- `pqz-core/pqzh/ligero/src/ring.rs:70-72` (`if y[m] == 0 { continue; }`, where `y` is the second operand). Secret
  second operands reach it from:
  - `cs.rs:480`: `dot_int(u_T, s_f)`, run on every debit proof;
  - `cs.rs:554`: R_DR;
  - `keypair` (ring.rs:93) from cs.rs:430, 463, 550;
  - `encrypt` (ring.rs:106, 115) from cs.rs:473, 535.
- `cs.rs:485`: a branch on the sign of the secret `wv`.
- **New relative to round 1:** `ring.rs:84`, the centring branch inside `modq`, runs on the secret `vt − y` at
  `cs.rs:484` (the decrypted ΔM + e_T) and on R_DR's e′ at `cs.rs:556`. In `keypair` / `encrypt` the centred result
  is the public `pk` / `u` / `v`, so those calls leak nothing through it.

**Trigger:** any production `prove` (`check = true`, ligero.rs:249). The `continue` skips a 64-iteration inner loop.
The compiler cannot if-convert that, so it is a real branch and a real change in run time.

**Impact:** the run time reveals ‖s‖² (the number of zeros of a ternary secret) and the weight of `r`. A
branch-tracing observer gets the zero positions. The amount is small next to MLWE security, as round 1 said. The
`cs.rs:485` / `ring.rs:84` branches are probably compiled to `select` / `cmov`, but this is unverified (see F3).

**Confirmed or hypothesis:** the `dot_int` branch is confirmed. Whether the compiled code branches at ring.rs:84 and
cs.rs:485 is a hypothesis.

**Suggested fix:** delete the skip at ring.rs:70-72 (at most 2× on about 4 M MACs). Round with masks, as the PQZL
`ct_sdiv` fix did (E-constant-time.md a9). **No byte change.**

### F3 — P3 — The PQZH prover was never put through the constant-time pass PQZL received (fix E); secret divisions run as `i64.rem_s` / `i64.div_s` on wasm32 (new)

**Locations**
- `pqz-core/pqzh/ligero/src/fq.rs:79`, `Fq::from_i64` = `v.rem_euclid(Q)`. It is called on every witness entry and
  every square in `cs.rs:579, 580, 590, 592` (`rows`). That is roughly 2 × 2,085 slots × 4–6 big groups plus every
  small value per proof.
- `ring.rs:83`, `modq`'s `rem_euclid(Q)`, on secret-derived integers:
  - `y + e` in `keypair` / `encrypt` (ring.rs:94, 107, 116);
  - `vt − y` at cs.rs:484 and R_DR at cs.rs:556. Here the dividend magnitude, up to about 2^57, depends on s.
- `cs.rs:485`: `/ DELTA` on the secret `wv`.
- Conditional subtractions written as branches on secret-derived values: fq.rs:37, 69, 112, 119. They run in `rows`,
  in the witness-row `ifft` and in the products at ligero.rs:374, where `pe` on the even points of H_N2 = H_k holds the
  raw witness values.

**Trigger**
- Native x86-64: LLVM strength-reduces constant-divisor `i64` division to multiplies, so it is constant time.
- wasm32 has no 64-bit high multiply, so LLVM keeps `i64.rem_s` / `i64.div_s`. The browser engine then emits `idiv`,
  certainly in its baseline tier (Liftoff). 64-bit `idiv` latency depends on the operands on many x86 cores.
- The PQZL review classed exactly this pattern as (a) "fixed" (E-constant-time.md a9: "divisions `% q`, `/ Δ` …
  wasm32: `i64.rem_s` / `i64.div_s`, whose latency is the engine's and the CPU's").
- For PQZH there is no `ctgrind` driver, no `ct::public` points and no inventory. `grep -i ctgrind` finds nothing under
  `pqzh/ligero`.

**Impact:** the leak is mainly the magnitude of the `modq(vt − y)` dividend, plus the signs of small coefficients
where the CPU's `idiv` timing depends on them. Like F2 it needs a local timer, and it contradicts §11 / T11. The
larger issue is method: F1 and F2 would both have been reported by the E pass, and no such pass exists for the
second live prover.

**Confirmed or hypothesis:** the divisions on secret values are confirmed in the source. The emitted wasm, the
engine's code and the `cmov` / `select` lowering of fq.rs:37/69/112/119 are a **hypothesis**: I could not inspect
generated code under the brief's rules.

**Suggested fix**
1. Replace `Fq::from_i64` with a branch-free reduction, for example
   `Fq(red((v as i128 + ((Q as i128) << 64)) as u128))`. It gives the same canonical value for every i64, uses no
   division, and its only conditional is the final subtraction.
2. Do the same in `modq`, with the centring done by a mask.
3. Port PQZL's `ct_sdiv` (or a multiply–shift on i128) for `/ DELTA`.
4. Extend `pqzl/test/ct.sh`'s method to a Ligero driver with the witness and `rnd32` marked undefined, and declassify
   the root, `w`, `q`, `h`, the columns and the PoW search.

**No byte change.**

### F4 — P3 — The PQZH prover clears no secret; PQZL now does, and STATUS Open item 8 still names only PQZL (round-1 A-Note, still present, now a gap between the two provers)

**Locations**
- `pqz-core/pqzh/ligero/src/ligero.rs:264-273` (`prove_inner`, the retry loop) and `ligero.rs:275-411`
  (`prove_once`). Left in freed memory:
  - `w: Wit` (279), `rows` (280), `pc` (285);
  - `u0`, `ul`, `h0`, `uq` (296-303), `enc` (306), `salts` (308);
  - `pe` (335; it contains the raw witness on H_k), `qe`, `pq`, `pc0`, `rem`.
- The `Rng` SHAKE256 reader (`ligero.rs:167-178`). sha3 0.10.8 has no `zeroize` and no `Drop`, as checked in the
  registry source. Keccak-f is a permutation, so the leaked sponge state yields every past and future mask, tail value
  and salt. With the published proof, that gives back every witness row.
- `cs.rs:419-564` (`witness`): `sf`, `ef`, `rs`, `e1s`, `e2`, `ds`, `dp`, `y`, `mv`, `et`, `cv`, `small`, and the
  temporaries of `keypair` / `encrypt` / `polys`.
- `pqz-core/ffi/src/pqzh.rs:16` (`*rnd32` copied by value) and `ffi/src/lib.rs:173-190`.
- Early exits that skip any clearing:
  - `cs.rs:421, 428, 431, 461, 464, 475, 496, 500, 506, 532, 537, 548, 551, 558`;
  - `ligero.rs:276-279` (`?`), 367, 389;
  - the discarded attempts of the retry loop at 266-271.
- `pqz-core/STATUS.md:1352-1365`: Open item 8 describes the PQZL C core and the Rust fix B (`Wiped` drop guard) only.

**Trigger:** every prove, successful or not.

**Impact:** a later memory disclosure in the wallet process (wasm linear memory is never returned to the OS, a crash
dump, a heap read primitive) recovers the witness: the secret key `s`, the randomness, the amounts and the balance.
The PQZL prover has had fix B since 2026-10-19; PQZH has nothing.

**Confirmed or hypothesis:** confirmed.

**Suggested fix:**
- Apply PQZL's `Wiped` pattern (plain stores plus `black_box`, same platform caveat) to `Wit`, `rows`, `pc`, `pe`,
  `enc`, the four mask polynomials, `salts`, and the `witness` locals.
- Keep the SHAKE reader inside a wrapper that overwrites its state on drop. This needs either the `zeroize` /
  `keccak` state access, or deriving the masks from a 64-byte seed that is wiped instead.
- Update Open item 8 to name PQZH.

**No byte change.**

### F5 — P3 — PQZH verify allocates infallibly: an out-of-memory node aborts instead of reporting `NodeFault` (new)

**Locations**
- `pqz-core/ffi/src/lib.rs:9-13`: "Every entry catches panics; nothing here aborts … Rust core: out of memory in a
  verifier, `Error::Memory` ⇒ … `PQZ_FFI_NODE_FAULT`". Also lib.rs:123-125.
- Versus the Ligero verify path:
  - `ligero.rs:496`: `Domain::new(n)`, a 32,756-element `Vec` built at fft.rs:41-46;
  - `cs.rs:701`, `cs.rs:631`: `comb` with up to m own vectors of ℓ F_q^4 values, about 22 KB each;
  - `ligero.rs:478-486` (`cols`) and the per-column `xp`, `dif`, `lc` at 505-529.
- All of these use `vec!` / `collect`. On failure, Rust's `handle_alloc_error` aborts the process. `catch_unwind` at
  `ligero.rs:433` and `lib.rs:90 / 144` cannot catch an abort.

**Trigger:** node memory pressure during a PQZH verify. The sizes are fixed by the parameters and the relation, a few
MB per call by my estimate, not chosen by an attacker. An attacker can only add concurrent verifies, within gas.

**Impact:** the node process dies instead of returning `PQZ_FFI_NODE_FAULT`. This is not a consensus split: it is a
crash of this node, which is the outcome the fault taxonomy tries to classify, and the documentation promises
otherwise. Severity P3 because the input cannot size the allocation.

**Confirmed or hypothesis:** the code path is confirmed. Its practical relevance depends on node memory limits.

**Suggested fix:**
- **Smallest:** correct the documentation: PQZH aborts on OOM, PQZL Rust returns `Error::Memory`.
- **Alternatively:** have `verify_inner` `try_reserve` its few large buffers up front and return a tri-state, which
  `pqz-ffi` maps to `NodeFault`.

**No byte or verdict change.**

### F6 — P3 (hygiene, not production) — Safe `extern "C"` wasm exports do unchecked raw-pointer work

**Locations**
- `pqz-core/pqzh/ligero/wasm/lib.rs:124-126`: `step_load`, a safe fn, calls `Vec::from_raw_parts(ptr, len, len)` on a
  pointer and length supplied by JS. This is UB unless they are exactly a `step_alloc(len)` allocation, and a double
  free if loaded twice.
- `wasm/lib.rs:26-28`: `form(rel)` panics, which is a wasm abort, on an out-of-range `rel`.
- `pqz-core/ffi/wasm/lib.rs:37-39`: `sl()`, a safe fn, wraps `slice::from_raw_parts`. A null `p` with `n = 0` is UB.
  It is used by `prove_v` / `precompile_v` (lines 49-71).

**Trigger:** a caller passes mismatched arguments. Both crates are bench / test harnesses: the Ligero wasm crate
depends on `pqzh-ligero` with `bench`, and the ffi wasm crate is the vectors' replay harness. Neither is linked into
the node.

**Impact:** none in production today. The risk is that the P6h client wrapper copies this pattern.

**Confirmed or hypothesis:** confirmed (code).

**Suggested fix:** mark them `unsafe extern "C"` with a `# Safety` contract, or take ownership through a handle table.
Add `#![forbid(unsafe_code)]` to `pqzh-ligero/src/lib.rs`: it has no `unsafe` (only `src/bin/ligero_bench.rs:20-35`,
a separate bench target), and `pqz-stmt` already forbids it (`stmt/src/lib.rs:22`).

---

## Round-1 findings: status in this tree

| ID | Status | Lines in this tree |
|---|---|---|
| **A-F1** (P2) | **still present** | `fft.rs:119-128` (filter 121, branch 122, `eps` 124); secret input `ligero.rs:290`. Unchanged; see F1, which adds a one-line fix. |
| **A-F2** (P3) | **still present** | `ring.rs:70-72`; callers `cs.rs:430, 463, 473, 480, 535, 550, 554`; sign branch `cs.rs:485`. F2 adds the `modq` centring branch at `ring.rs:84` via cs.rs:484 / 556. |
| **A-Note** (P3) | **still present** | `ligero.rs:264-411`, `cs.rs:419-600`. STATUS item 8 (`STATUS.md:1352-1365`) is still PQZL-only. See F4. |
| **B-F1** (P1, backup) | **still present** | `stark-backup/src/config.rs:211-224` (`DEFAULT`: `zk: false, ext5: false`); `rel.rs:28` (`MAX_PROOF = 160 KiB`); `rel.rs:236-238` (`digit_height` = 16 when `!zk`); `rel.rs:523`; `tests/smoke.rs:22, 46` (`max_proof = usize::MAX`). |
| **B-F2** (P2, backup) | **still present** | `stark-backup/src/enc.rs:221-234`: a terminating `0x00` after continuation bytes is accepted at line 229; no re-encode check after `take_from_bytes` (`rel.rs` `verify_with!`, `!rest.is_empty()` only). |
| **B-F3** (P2, backup) | **still present** | `rel.rs:503, 505, 507, 509` pass `rnd32` unchanged; `config.rs:252-258` `StdRng::from_seed(rnd)`; `whirpcs.rs:77-78` `StdRng::from_seed(rnd)`. |
| **B-F4** (P3, backup) | **still present** | `rel.rs:436-449` (cache keyed by `(op, Params)` with `max_proof` zeroed); `air.rs:236-240` (`used` by coefficient value); `air.rs:282-284` (`scol`). |
| **B-F5** (P3, backup) | **still present** | `rel.rs:155-159` (`build_reg`) and `rel.rs:212-232` (`parse_tx`) read only the fee word; `rel.rs:392-398` handles ops 1 and 3 only; no id / opTag check. |

The only backup change since round 1 is the PQZL id constant (`rel.rs:30-33`). It is used only by the C cross-check.

---

## Checked and clean

**Fiat–Shamir (`transcript.rs`, `ligero.rs:448-475`)**
- **Seed:** `keccak("SCAAS-PQZH-LIGERO-V1" ‖ op ‖ be32(len) ‖ stmt)` (transcript.rs:16-19). The statement carries
  `opTag` and `proofSystemId`, and `Params` are fixed per id by `ffi/src/pqzh.rs:6`.
- **Order:**
  1. the root is absorbed (466);
  2. every challenge (a_i, b_i, c_lin, c_quad, ρ, r_t) is drawn from the root alone (467, `draw` 239-245);
  3. w ‖ q ‖ h are absorbed (468), only after all three were parsed with canonical elements (460-462);
  4. PoW over that state (469);
  5. nonce absorbed (472);
  6. t indices drawn (473-475).
  The prover follows the same order (319-321, 392-402).
- **Domain separation by length:**

  | Keccak input | Length (bytes) |
  |---|---|
  | absorb root | 64 |
  | absorb nonce | 40 |
  | squeeze | 41 |
  | PoW | 43 |
  | absorb polys | 32 + 117,600 |

  No two hash inputs of different kinds can collide.
- **Squeeze order and buffer:** `absorb` resets the counter and the buffer (20-24). Word order is first chunk first
  (29-31).

**Sampling**
- `Tr::fq` (33-40) and `Rng::fq` (ligero.rs:179-188) mask to 42 bits and reject ≥ q: unbiased.
- `Tr::index` (45-53) masks with 2^15 − 1 and rejects ≥ n = 32,756: unbiased.
- Draws are i.i.d. with replacement. Dedup is identical on both sides (prover 400-402, verifier 473-475), so
  P(all t draws pass) = (|S|/n)^t whatever the duplicates.

**Merkle (`merkle.rs:62-80`)**
- Fixed depth `depth(n)` = 15. Leaves are sorted and distinct.
- A sibling is read only when the pair is not complete. The root must reduce to index 0.
- A leaf preimage is 32 + 6(m + 12) bytes, never 64, so a leaf cannot pose as an inner node.
- Sibling bytes come after all columns; trailing bytes are rejected (`ligero.rs:487`).
- Third-party re-encoding is not possible: a new nonce or new polys give new indices, and the unopened columns are
  needed for those.

**Canonical decoding and length gates**
- `Fq::get` rejects ≥ q (fq.rs:99-104). `F4::get` (175-177). Columns are read as exact `chunks(EB)` (ligero.rs:483).
- The fixed counts 2k−1, 2k−1 and 2k−1−ℓ enforce the degree bounds.
- `proof_len_ok` (exact `max_len_exact`) runs before `cs::parse` (449-453).
- `&proof[32..]` at 459 cannot underflow, because `rd.take(32)?` at 458 runs first.

**Ligero tests vs design note §4**
- **Proximity:** 515-523. The blind offsets m + 4b (512) match the prover's `enc` chain (307).
- **Linear:** 492-495 and 525-549. Σ_{H_k} q = k(q₀ + q_k) for deg ≤ 2k − 2. The Lagrange basis
  ω^c(η^k − 1)/(k(η − ω^c)) was re-derived.
- **Quadratic:** 551-558, with Z_ζ(η) from `batch_inv`.
- η ∈ 3·H_n never meets H_k (3 generates F_q^*, fq.rs:345-348), so `batch_inv` never sees 0.
- **Prover consistency:** `u_lin` has v₀ = −v_k (299), so its sum is 0. `u_quad = Z_ζ·h₀` has exactly d2
  coefficients. N2 = 1,634 > 2k − 2, so `ifft4` is exact.

**Zero knowledge**
- t = 121 ≤ k − ℓ − 1.
- Opened witness evaluations are uniform. The map from the 122 random tail values to |J| ≤ t evaluations off H_k is,
  up to row and column scalings, a Cauchy submatrix, so it has full rank.
- w, q and h are masked in exactly their spaces (design note §4.1 matches the code).
- The hedge in `Rng::new` (ligero.rs:169-178) equals CTR-PQZ-19's PQZH text byte for byte
  (pq-zero-knowledge.md:810).

**Constraint system (`cs.rs`)**
- Weights start at ρ¹ (702) and the exponents are distinct (`take`).
- The ring recurrence (661-663) was re-derived: f_{m+1} = ρ f_m − ρ^K (X^m a)_{K−1} − (X^m a)_{63}.
- Slack item indices (`sig`) are consistent across the layout (165-179), the witness (516-520) and comb (761, 778,
  813).
- Leg, group and digit mapping for op 7 (379-385 vs 714-726).
- The l2 sums cannot wrap: at most 2,085 · 2^16 + 2^15 < q, and padding slots only add squares, which are ≥ 0.
- Row 7 telescopes to an integer equality, with c₁₅ = 0 forced (753-754).
- The honest prover's range checks cover every row it writes (454-506, 557).

**Arithmetic**
- `red`: < 2^95, then < 2^61, then < 2^42 + 2^28, then one subtraction (fq.rs:64-70).
- `limb::red3` with folded inputs stays < 2^52 (33-38).
- F_q^4 product terms are < 2^88.
- wasm32 `Acc4` needs Σk ≤ 2^20. The largest accumulators are `eval4` with 1,633 terms, prover `qe` / `s` with ≤ m,
  `pq` with ≤ #triples, and `ring` with 32. All are far below the bound.
- Every `Fq(...)` built from a constant or a small value is canonical.

**wasm32 vs native**
- The only `usize` mask is n < 2^15 (transcript.rs:46). `stmt.len() as u32` is bounded by MAX_INPUT.
- The verifier has no target-dependent value; the chain verifies natively.
- `fft.rs` uses u128 on both targets (`__multi3` on wasm32) and gives the same values.

**`pqz-stmt` (not covered in round 1)**
- `decode_input` (stmt/lib.rs:897-923) checks `MAX_INPUT` first, then the `n ≤ rest.len()` framing, then `parse`,
  then `1 ≤ len(proof) ≤ MAX_PROOF(id)`.
- `parse` (475-576) checks in order: opTag (by op, Transfer0 by length), id, length, fee, amount, salt, auditorOn, zero
  words, coefficients. Every slice comes after the exact-length check.
- `parse_multi` (715-774) reads the header only after `n ≥ 640`, `M` comes from `built_legs(id)`, and the length is
  `multi_len`.
- `encode(parse(x)) = x` by construction (borrowed slices, concatenated).
- No panics are reachable from input. `#![forbid(unsafe_code)]` is set.
- The disclosure `kind` word is unchecked by design (pq-zero-knowledge.md:1447, 1608-1609).
- Ligero re-parses through the same crate and then checks `PQZH_ID` (cs.rs:331-338, 370-374).
- `rel_of` for op 7 reads only the auditorOn / `M` words and takes `M` from PQZH's built set before any layout is
  sized (cs.rs:312-325).

**`pqz-ffi` PQZH path**
- `run` checks `MAX_INPUT` before anything else (lib.rs:86-89). Dispatch is on the decoded id (69-76).
- C ABI: null / length / `out_len` checks, and the revert happens before any slice is built (133-141).
- Double `catch_unwind` (90, 144; Ligero's own at ligero.rs:433). Native builds refuse `panic = "abort"` (22-23).
- `OVERSIZE` const assert (27). `pqzh-ligero` is built with `default-features = false`; `bench` only adds functions and
  does not change verify.
- `selftest` is cached, and a failure counts as a node fault (selftest.rs:115-123).
- `build.rs:17-28` fails the build if the self-test vector is missing.
- The fixture's PQZH witness layouts match `cs::witness` offsets (fixture.rs:38-58 vs cs.rs:438-453).

**`xcheck/`**
- `run.sh` and `ligero.sh` fail closed: `cmp` with `rc=1`.
- `kat_stmt.py` raises on a parse failure, which `|| rc=1` turns into a failure.

**Backup**
- Only the round-1 items were re-verified (table above). No new review.

---

## Not checked

- A re-derivation of the BCIKS20 / unique-decoding soundness numbers (t = 121, factor 0.525, field terms). I took the
  design note §4.1 / §5 and the gate-B ZK review as given, and checked only that the code implements that protocol.
- Generated code: the x86-64 assembly and the wasm module, for the `cmov` / `select` lowering of fq.rs:37/69/112/119,
  ring.rs:84 and cs.rs:485, and whether `i64.rem_s` is emitted. Also the behaviour of V8 / SpiderMonkey tiers on
  `i64.rem_s` with a constant divisor. F3's latency claim is therefore a hypothesis.
- Dynamic confirmation of F1's and F2's timing differences (running anything was not allowed).
- `ffi/src/memo.rs`, the PQZL parts of `pqz-ffi`, `src/bin/pqz-vectors.rs`, Ligero `client.rs` beyond a skim, the
  bench binaries, `ligero_params.py`, `evm_model.py`, and the Python KATs beyond the xcheck drivers.
- Stark-backup beyond the round-1 items, and Plonky3 internals.
- The client's `rnd32` source (P6h, outside this tree).
