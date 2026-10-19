# J — agy review of PQZH Rust (round 2) and triage of I + J + K

**Date:** 2026-10-19. **Reviewer:** agy 1.4.2 (Gemini via Antigravity CLI, `--mode plan`, no
`--dangerously-skip-permissions`; conversation `0a769e80-a2a7-473f-9bf3-768d638ba459`; the first call returned only a
review plan, a resumed call in the same conversation produced the review; worktree unmodified). Same brief and target as
[I](I-codex-pqzh-rust.md) (Codex) and [K](K-claude-pqzh-rust.md) (Claude sub-agent). agy's report follows verbatim,
then the controller's triage.

---

# Security Review of PQZH Rust (Round 2, 2026-10-19)

**Target commit:** `e9cabd1` (detached worktree at `/home/ha/work/ainative/scaas/.claude/worktrees/rev2`).  
**Scope:** Primary live code (`pqz-core/pqzh/ligero/`, the PQZH dispatch and selftest paths of `pqz-core/ffi/`, `pqz-core/stmt/`, and `pqz-core/pqzh/xcheck/`), followed by secondary backup code (`pqz-core/pqzh/stark-backup/`).  
**Mode:** Static, read-only analysis. Nothing was built, edited, run, fuzzed, or timed. All citations reference `path:line` relative to the worktree root.

---

## Findings (by Severity)

### B-F1 — P1 — stark-backup: Only preset is non-hiding, and `MAX_PROOF` rules out every hiding proof
- **Locations**:
  - [pqz-core/pqzh/stark-backup/src/config.rs:211-224](../../../pqz-core/pqzh/stark-backup/src/config.rs#L211-L224) (`Params::DEFAULT`: `zk: false`, `ext5: false`)
  - [pqz-core/pqzh/stark-backup/src/rel.rs:28](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L28) (`MAX_PROOF = 160 * 1024`)
  - [pqz-core/pqzh/stark-backup/src/rel.rs:236-238](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L236-L238) (`digit_height` = 16 when `!zk`)
  - [pqz-core/pqzh/stark-backup/src/rel.rs:523-525](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L523-L525) (`if proof.len() > p.max_proof { return false; }`)
  - [pqz-core/pqzh/stark-backup/tests/smoke.rs:22, 46](../../../pqz-core/pqzh/stark-backup/tests/smoke.rs#L22) (`p.max_proof = usize::MAX`)
- **Trigger**: Verifying or proving an $R_{TX}$ statement with the default crate parameters.
- **Impact**: Complete loss of transfer confidentiality (zero-knowledge breach). When `zk: false`, the Digit table has height 16. Column `DD` holds amount digits $d_0..d_{15}$ and column `DP` holds new-balance digits $d'_0..d'_{15}$. Because each column is an evaluation polynomial of degree $< 16$, the 28 FRI query openings (evaluating to ~26 distinct points on the 256-point LDE) plus 2 out-of-domain evaluation points over-constrain the system. Any observer reading the proof bytes can interpolate both columns, directly recovering the transfer amount and new balance. Furthermore, because a true hiding proof requires ~622 KB (FRI + ZK at Goldilocks$^5$) or ~1.95 MB (ZK-WHIR), line 523 unconditionally rejects all valid zero-knowledge proofs under the crate's `MAX_PROOF` limit of 160 KB.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**: Add a dedicated hiding preset (`zk: true, ext5: true`, with verified FRI query parameters) as the default; make `verify` reject `!p.zk`; increase `MAX_PROOF` to the exact upper bound of the parsed hiding proof. Does not alter Ligero proof bytes or live precompile verdicts.

---

### A-F1 — P2 — pqzh-ligero: Sparse-DFT shortcut branches on raw witness values during row interpolation
- **Locations**:
  - [pqz-core/pqzh/ligero/src/fft.rs:121-128](../../../pqz-core/pqzh/ligero/src/fft.rs#L121-L128) (`filter(|x| *x.1 != 0)`, branching on `nz.len() * 4 < r`, data-dependent `eps` indexing)
  - [pqz-core/pqzh/ligero/src/ligero.rs:285-292](../../../pqz-core/pqzh/ligero/src/ligero.rs#L285-L292) (`hk.ifft(&v)` passing unblinded witness row slots)
- **Trigger**: Proving any statement where secret witness rows (e.g. the small-value row in $R_{TX}$, $R_{TX0}$, $R_{BURN}$, $R_{TXM}$ containing digits, carries, and $e_T$) have sparse non-zero entries in residue classes mod 19.
- **Impact**: Prover microarchitectural side channel. For $k = 817 = 19 \times 43$, stage 1 ($r = 43, m = 1$) groups elements by residue class mod 19. If a class has $\le 4$ non-zero elements, line 122 takes the $O(nz \cdot r)$ path instead of the dense $O(r^2)$ loop. For typical balances and transfer amounts, high digits ($d_9..d_{15}$, carries) are zero, placing the class near the threshold. A co-located process or malicious browser thread with high-resolution timers or cache/branch-predictor probes can distinguish dense vs. sparse paths, learning coarse magnitudes of amounts, balances, or private key CBD(1) Hamming weights.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**: Make the shortcut depend solely on the structural length of the non-zero inputs (i.e. public prefix length before zero-padding) rather than filtering runtime element values, or provide a constant-time `ifft_ct` for witness rows at `ligero.rs:290`. Output vectors are identical; proof bytes and verifier verdicts do not change.

---

### B-F2 — P2 — stark-backup: Proof decoder accepts overlong varints allowing malleable re-encoding
- **Locations**:
  - [pqz-core/pqzh/stark-backup/src/enc.rs:221-234](../../../pqz-core/pqzh/stark-backup/src/enc.rs#L221-L234) (`De::varint`)
  - [pqz-core/pqzh/stark-backup/src/rel.rs:475-479](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L475-L479) (no round-trip re-encoding check)
- **Trigger**: Any valid proof where sequence length bytes in Plonky3's `BatchProof` are replaced with overlong multi-byte varints (e.g. `0x01` replaced by `0x81, 0x00`).
- **Impact**: Proof malleability. A valid proof can be modified by a third party without knowledge of the witness into multiple distinct byte representations that all decode to the same proof structure and verify. This violates the canonical encoding requirement (`encode(decode(x)) == x`, D15) and can disrupt transaction deduplication or relayer tracking.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**: In `De::varint`, reject continuation sequences ending in `0x00` (`if i > 0 && b == 0 { return err("non-canonical varint"); }`), or enforce a canonical re-encoding round-trip in `verify_with!`. Does not affect honest prover output.

---

### B-F3 — P2 — stark-backup: Prover masks seeded from raw `rnd32` without CTR-PQZ-19 hedge
- **Locations**:
  - [pqz-core/pqzh/stark-backup/src/rel.rs:502-514](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L502-L514) (`rnd32` passed directly into config methods)
  - [pqz-core/pqzh/stark-backup/src/config.rs:252-258](../../../pqz-core/pqzh/stark-backup/src/config.rs#L252-L258) (`StdRng::from_seed(rnd)` seeding `HidingValMmcs` and `HidingFriPcs`)
  - [pqz-core/pqzh/stark-backup/src/whirpcs.rs:78-80](../../../pqz-core/pqzh/stark-backup/src/whirpcs.rs#L78-L80) (`StdRng::from_seed(rnd)` for WHIR trace and quotient masking)
- **Trigger**: Running the prover in a client environment where the operating system or browser CSPRNG is compromised, predictable, or repeated across VM snapshots.
- **Impact**: Failure of catastrophic hedge. CTR-PQZ-19 requires all proof masking randomness to be hedged with `H(secret || statement || rnd32)` so that low-entropy or repeated `rnd32` values cannot compromise zero-knowledge. Because `stark-backup` feeds raw `rnd32` into `StdRng`, predictable randomness allows an observer to regenerate all random trace rows, quotient blinding polynomials, and Merkle salts, subtracting them from open proof values and exposing secret witness data.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**: In `prove_inner`, derive the prover RNG seed via `SHAKE256("SCAAS-PQZH-STARK-RNG-V1" || rnd32 || op || be32(len) || stmt || wit)[0..32]`, matching the defense in Ligero. Does not change proof verification.

---

### A-F2 — P3 — pqzh-ligero: `dot_int` skips zero secret coefficients; `cs.rs` branches on decrypted sign
- **Locations**:
  - [pqz-core/pqzh/ligero/src/ring.rs:70-72](../../../pqz-core/pqzh/ligero/src/ring.rs#L70-L72) (`if y[m] == 0 { continue; }`)
  - [pqz-core/pqzh/ligero/src/cs.rs:480, 554](../../../pqz-core/pqzh/ligero/src/cs.rs#L480) (`dot_int(&t.ut, &polys(&sf))` in debit witness, and `dot_int(&t.u, &polys(&s))` in $R_{DR}$)
  - [pqz-core/pqzh/ligero/src/cs.rs:485](../../../pqz-core/pqzh/ligero/src/cs.rs#L485) (`if wv >= 0 { wv + DELTA / 2 } else { wv - DELTA / 2 }`)
- **Trigger**: Generating debit proofs ($R_{TX}$, $R_{TX0}$, $R_{BURN}$, $R_{TXM}$) or disclosure proofs ($R_{DR}$) where secret polynomials $s_f$ or $s$ have variable zero-coefficient counts, or where decrypted values $wv$ change sign.
- **Impact**: Prover timing and branch predictor leakage. The number of skipped loop iterations directly reveals the Hamming weight / $\ell_2$ norm of the secret CBD(1) ternary secret vector $s_f$, leaking information that the zero-knowledge proof explicitly hides via slack variables. Branching on `wv >= 0` leaks the sign of decrypted balance components.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**: Remove `if y[m] == 0 { continue; }` from `dot_int` or ensure the skipped operand is always the public polynomial. Replace `if wv >= 0` in `cs.rs:485` with branch-free arithmetic / conditional select (`cmov`). Does not change proof bytes or verifier behavior.

---

### B-F4 — P3 — stark-backup: Preprocessed commitment cache keyed by `(op, Params)` while MV layout depends on statement values
- **Locations**:
  - [pqz-core/pqzh/stark-backup/src/rel.rs:436-449](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L436-L449) (`common`: cache keyed by `(op, key)` with `key.max_proof = 0`)
  - [pqz-core/pqzh/stark-backup/src/air.rs:236-240, 282-284](../../../pqz-core/pqzh/stark-backup/src/air.rs#L236-L240) (`used` filters out zero-coefficient statement candidates)
  - [pqz-core/pqzh/stark-backup/src/rel.rs:271, 286-290](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L271) (`NTT(u_T)`, `NTT(pk)` feeding statement outputs)
- **Trigger**: Verifying statements with zero statement polynomials (e.g. $pk = 0$ in $R_{REG}$ or all-zero initial balance ciphertext $u_T$) when `mv_width` separates statement outputs into isolated groups.
- **Impact**: Latent consensus divergence. If statement data removes candidates from `used`, the preprocessed columns and height change. A node thread that caches `CommonData` for such a statement will reuse an incompatible preprocessed root for standard statements, causing valid proofs to fail verification. Latent at current default `mv_width = 9`.
- **Confirmed or hypothesis**: Confirmed (latent).
- **Suggested fix**: Determine `used` and column layouts strictly by structural index rather than coefficient values, or include statement shape invariants in the cache key.

---

### B-F5 — P3 — stark-backup: Spec drift: Verifier checks no header words and lacks five relation forms
- **Locations**:
  - [pqz-core/pqzh/stark-backup/src/rel.rs:155-159, 212-232](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L155-L159) (`build_reg` and `parse_tx` reading only fee)
  - [pqz-core/pqzh/stark-backup/src/rel.rs:392-398](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L392-L398) (only `OP_TRANSFER` and `OP_REGISTER` supported)
  - [pqz-core/pqzh/stark-backup/src/rel.rs:28](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L28) (`MAX_PROOF = 160 * 1024` vs spec 262,144 B)
- **Trigger**: Direct dispatch to `stark-backup` without `pqz-stmt` validation in front.
- **Impact**: Incomplete spec implementation. The backup crate omits `R_TX0`, `R_BURN`, `R_DS`, `R_DR`, and `R_TXM`, does not validate `proofSystemId` (never compares `PQZH_PROOF_SYSTEM_ID`), and ignores `opTag`, `auditorOn`, and zero words.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**: Route all statement parsing through `pqz-stmt`, validate `proofSystemId`, and implement missing forms before activating this backend.

---

### A-Note — P3 — pqzh-ligero: Prover allocations and witness buffers not zeroized on deallocation
- **Locations**:
  - [pqz-core/pqzh/ligero/src/ligero.rs:275-411](../../../pqz-core/pqzh/ligero/src/ligero.rs#L275-L411) (`prove`, `prove_once`)
  - [pqz-core/pqzh/ligero/src/cs.rs:419-564](../../../pqz-core/pqzh/ligero/src/cs.rs#L419-L564) (`witness`)
- **Trigger**: Normal execution or error return of `pqzh_ligero::prove`.
- **Impact**: Hygiene / defense-in-depth weakness. Private keys ($s_f, e_f, s, e$), encryption randomness ($r_g, e_{1,g}, e_{2,j}$), amounts, plaintext rows, and witness polynomial coefficients remain in freed heap memory without zeroization.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**: Implement zeroization on `Wit`, `rows`, `pc`, and reader buffers before drop using the `zeroize` crate.

---

## Round-1 Findings: Status in this Tree

- **A-F1 (P2)**: Still present at [pqz-core/pqzh/ligero/src/fft.rs:121-128](../../../pqz-core/pqzh/ligero/src/fft.rs#L121-L128) via [pqz-core/pqzh/ligero/src/ligero.rs:290](../../../pqz-core/pqzh/ligero/src/ligero.rs#L290).
- **A-F2 (P3)**: Still present at [pqz-core/pqzh/ligero/src/ring.rs:70-72](../../../pqz-core/pqzh/ligero/src/ring.rs#L70-L72) and [pqz-core/pqzh/ligero/src/cs.rs:480, 485, 554](../../../pqz-core/pqzh/ligero/src/cs.rs#L480).
- **A-Note (P3)**: Still present at [pqz-core/pqzh/ligero/src/ligero.rs:275-411](../../../pqz-core/pqzh/ligero/src/ligero.rs#L275-L411) and [pqz-core/pqzh/ligero/src/cs.rs:419-564](../../../pqz-core/pqzh/ligero/src/cs.rs#L419-L564).
- **B-F1 (P1)**: Still present at [pqz-core/pqzh/stark-backup/src/config.rs:211-224](../../../pqz-core/pqzh/stark-backup/src/config.rs#L211-L224) and [pqz-core/pqzh/stark-backup/src/rel.rs:28, 523](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L28).
- **B-F2 (P2)**: Still present at [pqz-core/pqzh/stark-backup/src/enc.rs:221-234](../../../pqz-core/pqzh/stark-backup/src/enc.rs#L221-L234).
- **B-F3 (P2)**: Still present at [pqz-core/pqzh/stark-backup/src/rel.rs:496-515](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L496-L515), [config.rs:252-258](../../../pqz-core/pqzh/stark-backup/src/config.rs#L252-L258), and [whirpcs.rs:78-80](../../../pqz-core/pqzh/stark-backup/src/whirpcs.rs#L78-L80).
- **B-F4 / B-F5 (P3)**: Still present at [pqz-core/pqzh/stark-backup/src/rel.rs:436-449](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L436-L449), [air.rs:236-240](../../../pqz-core/pqzh/stark-backup/src/air.rs#L236-L240), and [rel.rs:28, 155-159, 212-232, 392-398](../../../pqz-core/pqzh/stark-backup/src/rel.rs#L28).

---

## Checked and Clean

1. **Fiat–Shamir Binding & Separation (`transcript.rs`, `ligero.rs`)**:
   - Seed binds domain tag `"SCAAS-PQZH-LIGERO-V1"`, `op`, `be32(len)`, and the full statement bytes including `proofSystemId` ([pqz-core/pqzh/ligero/src/transcript.rs:16-19](../../../pqz-core/pqzh/ligero/src/transcript.rs#L16-L19)).
   - Absorption order is strict: `root` absorbed before challenges $(a_i, b_i, c_{lin}, c_{quad}, \rho, r_q)$; $w, q, h$ polynomials absorbed before PoW verification; `nonce` absorbed before query index sampling ([pqz-core/pqzh/ligero/src/ligero.rs:465-475](../../../pqz-core/pqzh/ligero/src/ligero.rs#L465-L475)).
   - Domain separation between `absorb` and `squeeze` is enforced via an explicit `0xff` byte ([pqz-core/pqzh/ligero/src/transcript.rs:27](../../../pqz-core/pqzh/ligero/src/transcript.rs#L27)).

2. **Query Sampling & Deduplication (`transcript.rs`, `ligero.rs`)**:
   - Uniform query sampling uses unbiased power-of-two rejection masking ($mask = 32,767$ for $n = 32,756$) ([pqz-core/pqzh/ligero/src/transcript.rs:45-53](../../../pqz-core/pqzh/ligero/src/transcript.rs#L45-L53)).
   - Sorting and deduplication of query indices (`idx.dedup()`) correctly reduces serialized wire size without reducing query verification coverage, as both prover and verifier deduce identical query sets ([pqz-core/pqzh/ligero/src/ligero.rs:400-403, 473-475](../../../pqz-core/pqzh/ligero/src/ligero.rs#L400-L403)).

3. **Merkle Commitments & Multiproofs (`merkle.rs`, `ligero.rs`)**:
   - Leaf preimage length is $32 + (m + 12) \times 6 \ge 140$ bytes, preventing collision with 64-byte internal nodes ([pqz-core/pqzh/ligero/src/ligero.rs:484](../../../pqz-core/pqzh/ligero/src/ligero.rs#L484)).
   - Multiproof reconstruction verifies exact depth ($d = 15$), index parity, sibling sequence, and root matching index 0 ([pqz-core/pqzh/ligero/src/merkle.rs:62-80](../../../pqz-core/pqzh/ligero/src/merkle.rs#L62-L80)).
   - 32-byte column salts hide opened evaluations ([pqz-core/pqzh/ligero/src/ligero.rs:306, 481](../../../pqz-core/pqzh/ligero/src/ligero.rs#L306)).

4. **Field Arithmetic & Canonical Checks (`fq.rs`)**:
   - Modulus $q = 2^{42} - 215$ is prime. Canonical form ($x < q$) is enforced on every 6-byte decoded element in `Fq::get` ([pqz-core/pqzh/ligero/src/fq.rs:99-104](../../../pqz-core/pqzh/ligero/src/fq.rs#L99-L104)).
   - Non-canonical field elements are rejected at parse time before polynomial absorption.
   - Three-stage reduction in `red` handles all $u128$ intermediate values without overflow or aliasing ([pqz-core/pqzh/ligero/src/fq.rs:64-70](../../../pqz-core/pqzh/ligero/src/fq.rs#L64-L70)).
   - $3 \cdot H_n \cap H_k = \emptyset$ ensures $Z_\zeta(\eta) \ne 0$ and batch inversion never divides by zero ([pqz-core/pqzh/ligero/src/ligero.rs:504, 526-528](../../../pqz-core/pqzh/ligero/src/ligero.rs#L504)).

5. **Decoding Strictness & Non-Malleability (`ligero.rs`, `stmt/lib.rs`)**:
   - Verifier checks `p.proof_len_ok` before parsing ([pqz-core/pqzh/ligero/src/ligero.rs:450](../../../pqz-core/pqzh/ligero/src/ligero.rs#L450)).
   - Trailing proof bytes are strictly rejected by `!rd.0.is_empty()` ([pqz-core/pqzh/ligero/src/ligero.rs:487](../../../pqz-core/pqzh/ligero/src/ligero.rs#L487)).
   - `pqz_stmt::decode_input` strictly bounds proof length ($1 \le len \le MAX\_PROOF(id)$) and enforces statement canonicality ([pqz-core/stmt/src/lib.rs:897-923](../../../pqz-core/stmt/src/lib.rs#L897-L923)).

6. **Target Portability: wasm32 vs Native (`fq.rs`)**:
   - `fq.rs:limb` provides 21-bit limb arithmetic (`mul3`, `red3`, `mac`, `f4_mul`) for wasm32, avoiding software `__multi3` calls while ensuring bit-for-bit equivalence with native $u128$ arithmetic ([pqz-core/pqzh/ligero/src/fq.rs:15-60, 252-267](../../../pqz-core/pqzh/ligero/src/fq.rs#L15-L60)).
   - `Acc4` accumulator capacity ($\le 2^{20}$ additions on wasm32, $\le 2^{40}$ on native) safely accommodates all verifier inner loops ($\le 700$ terms).

7. **Panic Containment & Memory Safety (`ffi/lib.rs`, `stmt/lib.rs`)**:
   - `pqz-stmt` enforces `#![forbid(unsafe_code)]` ([pqz-core/stmt/src/lib.rs:22](../../../pqz-core/stmt/src/lib.rs#L22)).
   - FFI boundary in `ffi/src/lib.rs` safely catches all panics via `catch_unwind`, mapping input-caused faults to `INVALID` (`…00` / `PQZ_FFI_INTERNAL`) and node faults to `PQZ_FFI_NODE_FAULT` ([pqz-core/ffi/src/lib.rs:86-100, 105-152](../../../pqz-core/ffi/src/lib.rs#L86-L100)).
   - Native builds forbid `panic = "abort"` at compile time ([pqz-core/ffi/src/lib.rs:22-23](../../../pqz-core/ffi/src/lib.rs#L22-L23)).
   - Input length exceeding `MAX_INPUT` (393,216 B) reverts cleanly without allocating ([pqz-core/ffi/src/lib.rs:87, 137-141](../../../pqz-core/ffi/src/lib.rs#L87)).

8. **Constraint System & Linear Test Recurrence (`cs.rs`)**:
   - Weight exponents $\rho^{e_c}$ are generated with strictly increasing, distinct exponents $e_c \ge 1$ via `take`, preventing cancellation by committed blinding rows ([pqz-core/pqzh/ligero/src/cs.rs:624-628, 702](../../../pqz-core/pqzh/ligero/src/cs.rs#L624-L628)).
   - Integer relation bounds ($L_2$ norm bounds $BS = 36^2, BE = 164^2, B2 = 64^2$, carry chain bounds $[-64, 1984)$ with $c_{15} = 0$) do not wrap modulo $q$ ([pqz-core/pqzh/ligero/src/cs.rs:45-48, 499, 735-763](../../../pqz-core/pqzh/ligero/src/cs.rs#L45-L48)).
   - Multi-recipient transfer $R_{TXM}$ (op 7) layout and constraints are correctly bound by header words and built leg sets ([pqz-core/pqzh/ligero/src/cs.rs:175-178, 312-325, 370-391](../../../pqz-core/pqzh/ligero/src/cs.rs#L175-L178)).

9. **Prover Mask Hedging (`ligero.rs`)**:
   - Fully compliant with CTR-PQZ-19: `Rng::new` derives all masking polynomials and column salts from `SHAKE256("SCAAS-PQZH-LIGERO-RNG-V2" || rnd32 || op || be32(len) || stmt || wit)` ([pqz-core/pqzh/ligero/src/ligero.rs:165-178](../../../pqz-core/pqzh/ligero/src/ligero.rs#L165-L178)).

10. **Build Flags & Feature Separation (`Cargo.toml`)**:
    - `pqz-ffi` depends on `pqzh-ligero` with `default-features = false`, excluding bench-only floating point calculations and client test modules ([pqz-core/ffi/Cargo.toml:18](../../../pqz-core/ffi/Cargo.toml#L18)).
    - Assertions prevent `pqz-stmt` feature `oversize` from entering production builds ([pqz-core/ffi/src/lib.rs:27](../../../pqz-core/ffi/src/lib.rs#L27)).

---

## Not Checked

1. **Plonky3 Library Core Primitives**: Plonky3 (`0.9.0-rc.1`) crate internals (`p3-fri`, `p3-batch-stark`, `p3-challenger`, `p3-whir`) were taken as-is; internal soundness proofs of FRI / WHIR polynomial commitment schemes were not re-derived.
2. **Mathematical Soundness Theorem Derivations**: The formal mathematical proof of the Ligero proximity soundness theorem under list-decoding was not re-derived from first principles (spot checks confirmed parameter constants match `docs/research/pqzh-ligero.md`).
3. **Bench-Only & Measurement Code**: `wasm/lib.rs:118-128` (`step_alloc`, `step_load` with raw pointers), `src/client.rs`, `src/bin/pqzh_bench.rs`, and `evm_model.py` were excluded from production memory-safety checks as they are behind `feature = "bench"`.
4. **Hardware Entropy Sources**: The quality of the caller's CSPRNG providing `rnd32` at the wallet/client boundary is external to this codebase.
5. **Dynamic Timing & Hardware Traces**: Side-channel findings (A-F1, A-F2) were confirmed via static code analysis; physical cache/branch microarchitectural execution traces were not recorded due to read-only constraints.

---

## Triage (controller, I = Codex, J = agy, K = Claude)

Verified by the controller against `e9cabd1` (`fft.rs:119–128`, `ring.rs:66–85`, `cs.rs:480–486`, `fq.rs:30–37 / 77–79`,
`ligero.rs:284–292`). **No P0 / P1 in the live PQZH path from any of the three reviewers**; the only P1 is the backup's
non-hiding preset (B-F1), not reachable from pqz-ffi. No Ligero source changed since round 1 (`4c20032..e9cabd1`).
Fix branch `rev2-pqzh` (plan Task 5c). None of P-A…P-F changes PQZH proof bytes or verdicts, so the PQZH
`proofSystemId`, vectors and gas rows stay; P-G changes only stark-backup proofs (not live, own tests).

| # | Finding | Sources | Verdict | Disposition |
|---|---|---|---|---|
| P-A | Sparse-FFT shortcut decides on witness values (`fft.rs:121–124` via `ligero.rs:290`) | A-F1, I-2, J, K-F1 | Confirmed (all three) | Fix: the sparse path only where the zero pattern is structural (forward transform of zero-padded coefficients), never on the prover's witness interpolation; proof bytes unchanged |
| P-B | Secret-dependent work / branches / divisions in the prover: `dot_int` zero skip (`ring.rs:70`), `modq` centring (`ring.rs:83–84`), rounding sign and `/ DELTA` (`cs.rs:485`), `Fq::from_i64` `rem_euclid` (`fq.rs:79`, `i64.rem_s` on wasm32), conditional subtractions (`fq.rs:37/69/112/119`) | A-F2, I-5, J, K-F2, K-F3 | Confirmed in source; leakage of the generated code a hypothesis | Fix as PQZL fix E: branch-free arithmetic on secret paths (no skip, mask-based centring / reduction, constant-time signed division as PQZL `ct_sdiv`), plus a Ligero ctgrind driver (method of [E-constant-time.md](E-constant-time.md)); 0 reports on the paths run |
| P-C | The PQZH prover wipes nothing: `Wit`, `rows`, `pc`, `pe`, `enc`, masks, salts, the `rnd32` copy, `witness()` locals; SHAKE256 reader state (Keccak-f invertible ⇒ masks) | A-Note, I-6, J, K-F4 | Confirmed | Fix as PQZL fix B: wiping drop guards on every secret buffer, every exit; the SHAKE state wiped if the pinned `sha3` allows it without `unsafe`, else recorded as the platform boundary (documented); STATUS Open item 8 names PQZH |
| P-D | Verifier allocations infallible: OOM aborts the node instead of `NodeFault` (`ligero.rs:478–529`, `cs.rs:631/701`, `fft.rs:41`) | K-F5, I (note) | Confirmed; sizes fixed by parameters, not input | Fix: fallible reservation (`try_reserve`) for the verifier's buffers → `NodeFault`, as the PQZL Rust crate; update `pq-zero-knowledge.md:1574` |
| P-E | Safe `extern "C"` wasm exports do raw-pointer work (`ligero/wasm/lib.rs:124–126`, `ffi/wasm/lib.rs:37–39`) | K-F6, I (note) | Bench / test harnesses only | Fix: `#![forbid(unsafe_code)]` in `pqzh-ligero`'s lib; the harness exports marked `unsafe extern "C"` or documented as trusted-caller |
| P-F | Backup decoder accepts overlong varints (`stark-backup/src/enc.rs:221–234`) | B-F2, I-3, J | Confirmed | Fix (small): reject non-minimal varints; test with the `01` → `81 00` mutation |
| P-G | Backup masks from `rnd32` alone (`rel.rs:496–514`, `config.rs:252–258`, `whirpcs.rs:78–80`) | B-F3, I-4, J | Confirmed | Fix (small): one domain-separated SHAKE256 seed over op ‖ statement ‖ witness ‖ `rnd32`, as Ligero's `Rng::new` |
| P-H | Backup cache keyed by (op, Params) while the MV layout depends on coefficient values (`rel.rs:436–449`, `air.rs:236–240`) | B-F4, I-7, J | Latent (default `mv_width = 9` safe) | Fix (small): layout from structural indices, or the layout in the cache key |
| P-I | Backup preset non-hiding, `MAX_PROOF` below hiding proofs (`config.rs:211–224`, `rel.rs:28/523`); spec drift (no id / op / auditor checks, two relations) | B-F1, B-F5, I-1, I-8, J | Confirmed; not reachable (pqz-ffi never dispatches to the backup) | Recorded as a **gate before the backup is ever promoted** (a reviewed hiding preset, a size bound, `pqz-stmt` parsing, a distinct id, all relations); no code now |
