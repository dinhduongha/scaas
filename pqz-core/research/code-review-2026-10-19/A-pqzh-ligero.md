# Code review A: PQZH Ligero (Rust) and the pqz-ffi PQZH dispatch (2026-10-19)

Static, read-only review at `main` 4c20032. Scope: `pqz-core/pqzh/ligero/src/*.rs`, `wasm/lib.rs`, `ligero_params.py`
(read for intent), `pqz-core/ffi/src/{lib.rs,pqzh.rs}` (PQZH path only). Nothing was built or run.

**Result: no P0 or P1 findings.** The verifier is sound and consensus-safe as far as this review could check. There are two
prover side-channel findings (one P2, one P3). The Codex lead is **confirmed**, with a narrower and more exact
scope than first stated.

---

## Findings

### F1 (P2): the sparse-DFT shortcut branches on raw witness values when the prover interpolates the witness rows (Codex lead: confirmed)

- **Where:** `pqz-core/pqzh/ligero/src/fft.rs:119-128`. The data-dependent filter is on line 121, the branch on line 122,
  and the secret-indexed `eps[s * u % r]` on line 124. The only call that passes secret, non-random data is
  `src/ligero.rs:285-292` (`hk.ifft(&v)`, line 290).
- **Defect:** `Domain::rec` collects the nonzero inputs of each radix group (`filter(|x| *x.1 != 0)`) and takes an
  O(nz·r) path instead of the O(r²) path when `nz·4 < r`. When the prover interpolates the witness rows on H_k, the
  group inputs are the raw witness slot values. So the branch, the loop length and the `eps` access pattern depend
  on which witness entries are zero. The spec claims the opposite control: pq-zero-knowledge.md §11, "the code
  avoids secret-dependent branches and indices", and T11.
- **Mechanics (preset k = 817, radices [19, 43]):**
  - Level 1 of `hk.ifft` runs `r = 43, m = 1`. Its twiddle is `w[0] = 1`, so `t[s]` is exactly
    `v[s0 + 19·s]`: the raw values of one residue class mod 19 of the row.
  - Positions 695..816 are the uniform tail: 6 values per class for s0 ≤ 10, 7 for s0 ≥ 11. The sparse path therefore
    runs exactly when the class holds ≤ 4 (or ≤ 3) nonzero witness values out of its 36–37.
  - The top level (r = 19) sees pseudo-random sub-DFT outputs and always takes the dense path.
  - Every other FFT in `prove_once` gets public data (`interp` of `comb` vectors) or uniformly masked
    coefficients/evaluations (`coset_fft`/`h2.fft` of `pc`, `ifft4` of `qe`/`pq`). There, a zero shows up with
    probability 1/q and the zero padding is public. So those calls leak nothing.
- **Failure scenario:** R_TX. The small-value row (`cs.rs` Layout: e2 at slots 0..47, d at 48..63, d' 64..79, M 80..95,
  carries 96..111, e_T 112..127, slacks to 134, zero padding up to 694) puts about 8 secret values in each class.
  - Class 0, for example, holds e2[0], e2[19], e2[38], d_9, d'_12, M_15, e_T[2] and one slack.
  - For typical amounts and balances, the high digits d_9, d'_12 and M_15, plus most carries, are 0. The count sits right at
    the 3/4 threshold, so the dense-or-sparse decision of each class encodes whether high digits of the amount, the
    new balance and the decrypted balance are zero. That is a coarse magnitude of the amount and the balance.
  - The square row repeats the same pattern, and the last packed small-bit row has the same kind of pattern.
  - In the big groups, a CBD(1) bit row j ∈ 1..5 is 1 exactly where s_i = −1. A class with ≤ 3 such entries
    (about 1–2 % of classes) switches to the sparse path and reveals that.
  - Coarse timing gives the sum over all classes (about 1,500 fewer u128 MACs per sparse class). A branch-predictor
    or cache observer on the same core (the filter's per-element branch; the `eps` line touched depends on which
    `s` are nonzero) learns *which* entries are zero. The attacker must be local: browser co-tenant JS
    with a wasm timer, or a co-resident process. A remote observer only sees the total time, which is too noisy.
- **Fix:** make the sparse decision use public structure only. Pass the number of structurally nonzero inputs from
  `fft(a)` (that is, `a.len()`) down to the deepest stage, and skip only the indices ≥ `a.len()`. Do not filter on
  values. Alternatively, add a dense `ifft_ct` and use it at `ligero.rs:290`. Output values are identical, so proof
  bytes and vectors do not change. Re-check the preset prover time, because the zero-padded `coset_fft` keeps its
  speed-up under the structural rule.
- **Confidence:** high that the leak exists and where it comes from; medium on how exploitable it is in practice.

### F2 (P3): `dot_int` skips zero coefficients of the secret operand, so the prover's timing and branches follow s, s_f and r

- **Where:** `pqz-core/pqzh/ligero/src/ring.rs:70-72` (`if y[m] == 0 { continue; }`, where `y` iterates the second
  argument).
  - Secret second arguments come from these calls: `cs.rs:480` (`dot_int(u_T, s_f)`, run on **every** debit proof,
    whatever `check` is), `cs.rs:554` (`dot_int(u, s)`, R_DR), `cs.rs:430/463/550` (`keypair(s, e)` → `ring.rs:93`),
    and `cs.rs:473/535` (`encrypt(.., r, ..)` → `ring.rs:106, 115`). The production `prove` always runs with
    `check = true`.
  - Related: `cs.rs:485` rounds by branching on the sign of the secret decrypted value `wv`. The PQZL core's
    `pqz_dec` rounds branch-free, according to STATUS.md.
- **Defect:** secret-dependent branches and loop lengths. The spec (§11/T11) says none exist.
- **Failure scenario:** for a ternary CBD(1) secret, the number of skipped coefficients is 2048 − ‖s‖², so the
  run time of `keypair`/row 6 reveals ‖s‖² (or the weight of r in `encrypt`). That number is the l2 norm the proof
  otherwise hides behind the slack. A branch-predictor observer gets the zero positions of s_f and r. The leak is small
  compared with MLWE security (at most about 11 bits of weight information from timing), so this is P3. With branch
  tracing the positions leak, which is worse.
- **Fix:** delete the skip, or make all callers pass the public matrix as the skipped operand. `dot_int` is not hot
  in the prover; it costs at most 2× on about 4 M MACs. Use a mask/cmov for the rounding at `cs.rs:485`.
- **Confidence:** high (the code is unambiguous); low on practical impact.

### Note (P3, scope of Open item 8): the PQZH prover does not clear secrets

STATUS.md Open item 8 says "project-wide" but names only PQZL objects (the arena, `pqz_keygen`). The Ligero prover
(`ligero.rs:275-411`, `cs.rs:419-600`) leaves several things on the heap when it returns, with no zeroization:
- `Wit` (s, e, r, e1, e2, digits, balances);
- the m×ℓ plaintext matrix `rows`;
- `pc`/`pe` (the witness polynomials, from which the witness can be read back by evaluating on H_k);
- the SHAKE256 reader state, which is derived from `wit`.

This is not worse in kind than item 8. Only the item's text should name PQZH as well. A fix (`zeroize` on these
buffers, or overwrite before drop) changes no bytes.

---

## Codex lead: verdict

"The sparse FFT path in the prover branches on raw witness bit rows during interpolation; its filtering decisions
reveal which entries are zero."

**Confirmed (F1), refined as follows:**
1. The leak is in `hk.ifft` of the witness rows only (`ligero.rs:290`), at the r = 43 stage. Value rows, square rows and
   packed small rows leak, not only bit rows. The most informative is the small-value row (digits, balance digits,
   carries).
2. The uniform tail of k − ℓ = t + 1 values goes through the same transform, but it does not mask anything here:
   the filter reads the witness slots themselves.
3. Coarse timing reveals per-class nonzero counts around a threshold, summed. Per-entry zero positions need a local
   microarchitectural observer.
4. The coset/LDE FFTs and every FFT on public or masked data do not leak.

## Prover-mask hedging: verdict

**Compliant with CTR-PQZ-19** (decisions.md, the 2026-10-14 "PQZH half" change). `Rng::new` (`ligero.rs:165-178`) is
`SHAKE256("SCAAS-PQZH-LIGERO-RNG-V2" ‖ rnd32 ‖ u8(op) ‖ be32(len(stmt)) ‖ stmt ‖ wit)`. That is the statement framed
by its length, with the witness last, so no framing is needed after it.
- Every random value comes from that stream: the t + 1 tail evaluations of each row, u_0, u_lin, h_0 and the n
  column salts.
- A retry for length (`prove_inner`) continues the stream.
- The tests `rng_hedged_with_witness` and `attacks.rs::hedged_proofs` pin this behaviour.
- `rnd32` itself is supplied by the caller (`pqz_ffi::prove`). The client's CSPRNG is outside this scope.

---

## Areas checked and found sound

**Fiat–Shamir**
- The seed binds the domain tag, op, be32 length and the full statement (`proofSystemId` included). The parameters are
  fixed per id and never read from the proof.
- The order is: root → every challenge (a_i, b_i, c_lin, c_quad, ρ, r_t) → absorb the w, q, h bytes → PoW over that
  state → absorb the nonce → t indices.
- Absorb and squeeze inputs differ in length and tag, so they cannot collide. The polys bytes are absorbed only after
  every element passed its canonical check.
- Index sampling uses unbiased rejection (mask 2^15 − 1 for n = 32,756).

**Encoding**
- Every F_q element is canonical (`Fq::get`, `< q`). Fixed counts are read: 2k−1, 2k−1 and 2k−1−ℓ coefficients, so the
  degree bounds are enforced by length. Columns have exactly m + 12 elements.
- The proof must be consumed exactly (`!rd.0.is_empty()`), and the length gate (`max_len_exact`) runs before
  parsing. A third party cannot make a different valid proof: a new nonce means new columns.

**Merkle**
- Fixed depth, sorted distinct indices, every sibling read in a deterministic order, and the root rebuilt to index 0.
- A leaf preimage (32 + 6(m+12) bytes) can never be 64 bytes long, so a leaf cannot pass as an internal node.
- A 32-byte salt per column hides the column.

**Proximity, linear and quadratic tests (matched against `prove_once`)**
- **Proximity:** the degree correction (a_i + b_i X^{k−1}) on the witness rows. The blinding rows are covered as F_q^4
  words with coefficients c_lin, c_quad and 1 (an affine shift). The degree-correction condition (1−δ)n ≥ 3k−2 holds at
  the unique-decoding radius.
- **Linear:** the identity Σ_{H_k} q = k(q_0 + q_k) holds for deg q ≤ 2k−2. The Lagrange basis
  ω^c(η^k−1)/(k(η−ω^c)) is correct.
- **Quadratic:** h·Z_ζ against Σ r_t(U_x U_y − U_z) + u_quad.
- The coset 3·H_n never meets H_k: 3 generates F_q^*, and q−1 does not divide lcm(n, k). So `batch_inv` never sees
  a zero, and Z_ζ(η) ≠ 0.
- The blinding-row offsets on the verifier (m + 4b) match the prover's `enc` order (u_0, u_lin, u_quad).
- **Parameters:** t = 121, ℓ = k − t − 1 (ZK: t openings < k − ℓ). The proven factor is 0.525 per query, 112.5 + 16 bits,
  which matches `ligero_params.py`/`factor`. I did not re-derive the proof of the soundness theorem (gate B covered that).

**Constraint system (`cs.rs`)**
- Weight exponents are distinct and ≥ 1 throughout (`take`), so a committed u_lin with a nonzero H_k sum cannot cancel
  a violation. The ring recurrence for f_m was checked by hand.
- Slack and item indices (`sig`) were checked for every form, op 7 included. Witness `small` ordering matches the
  Layout.
- Bit ranges and l2 slacks: 11, 15 and 13 bits cover 36², 164² and 64². None of the integer identities can wrap mod q
  (big l2 sums < 2^28; row 7 and the carry chain bounded; c_15 = 0 forces the telescoped integer equality).
- R_BURN's public digits enter through the rhs. The R_DS/R_DR amount enters through `v_minus`. The op 7 legs and
  auditor copies use d_j and group g(j).
- `rel_of` for op 7 picks M only from the built set, so no layout is ever sized from an unchecked word. `parse` then
  re-validates the same header words.

**Consensus safety**
- No `unsafe` in production code (only the bench allocator).
- Allocation and time are fixed by the relation, apart from ≤ t columns. The rejection loops have negligible tails.
- Arithmetic bounds are fine:
  - `red` handles any u128;
  - F4 products are < 2^89;
  - `Acc4` holds 2^40 terms natively and 2^20 on wasm32. Every accumulator here has ≤ about 700 terms.
- No floats in the production build. No usize-width-dependent values (only n < 2^15 is masked).
- The verifier uses no FFT. The self-test FFT KAT is deterministic.
- Panics are caught twice (`verify`, then `pqz_ffi::run`/`pqz_precompile`). The ffi refuses to compile with native
  panic = abort.
- The PQZH path in `verify_input` dispatches on the decoded id and passes the decoded op and statement bytes.
  Ligero re-parses them itself (`cs::parse` → `pqz_stmt::parse` + `PQZH_ID`).

**wasm32**
- `limb` arithmetic is used for `Mul`/`F4`/`Acc4`. The lazy-sum bound (Σk ≤ 2^20) holds at every call site in prover
  and verifier.
- The proof bytes are target-independent. The chain verifies natively.

## Not covered

- `pqz-stmt` internals (`parse`, `parse_multi`, `read_coeffs`, `decode_input`): I assumed them as documented.
- A full re-derivation of the soundness theorem and of the modified-ZK simulator. I spot-checked the mask
  dimensions and the simulatability of w, q, h with t openings, and found no issue.
- The spec-level correctness of each relation against pq-zero-knowledge.md §7: I checked the code against `cs.rs`'s own
  header and the Layout, not every spec line.
- `client.rs`, the bench binaries and `evm_model.py` (feature `bench`, not production).
- The client's source of `rnd32` (P6h, outside this crate).
- No dynamic confirmation of F1's timing difference: running anything was not allowed.
