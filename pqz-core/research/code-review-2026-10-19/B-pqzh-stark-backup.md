# Code review B: `pqz-core/pqzh/stark-backup/` and `pqz-core/pqzh/xcheck/` (2026-10-19)

A static, read-only review of the main checkout (branch `main`, HEAD `1adbd56`). Nothing was built or run. I reviewed
the STARK backup as if it were switched on as a consensus verifier.

**Version note:** this crate pins Plonky3 **`=0.9.0-rc.1`**, a release candidate (`stark-backup/Cargo.toml`), not
`=0.8.0`. I checked the Plonky3 behaviour below against the 0.9.0-rc.1 sources in `~/.cargo/registry`.

## Findings

### F1 — P1 — The only preset is non-hiding, and `MAX_PROOF` rules out every hiding one; an observer reads the amount and the new balance

- **Where:** `src/config.rs:211-224` (`Params::DEFAULT`: `zk: false`, `ext5: false`); `src/rel.rs:28`
  (`MAX_PROOF = 160 * 1024`); `src/rel.rs:236-238` (`digit_height` = 16 when `!zk`); `src/rel.rs:523` (the length
  check).
- **Defect:** the one parameter set in the code (used by the tests, the bench and the wasm defaults) is not zero
  knowledge. Its proven soundness is 71.9 bits (`config.rs:207-209`), not 128. A hiding proof cannot pass `verify` at
  the crate's own limit. FRI + ZK at Goldilocks⁵ is about 622 KB, ZK WHIR about 1.95 MB, and the hiding tests set
  `p.max_proof = usize::MAX` (`tests/smoke.rs:22, 46`). The 128-bit ZK configuration exists only as command-line flags
  in `runs/*.sh`.
- **Failure scenario:** switched on as coded, every `R_TX` proof is a plain FRI proof (143,128 B,
  `runs/t1-base-default.jsonl`). The Digit table has exactly 16 rows. Column `DD` holds the amount digits `d_0..15`, and
  column `DP` holds the sender's new-balance digits `d'_0..15` (`rel.rs:368-369`). Each column is a polynomial of
  degree < 16:
  - 28 FRI query openings reduce to the Digit matrix's 256-point LDE, giving about 26 distinct points.
  - Two out-of-domain values (ζ, ζg) add 4 base-field equations.
  - That is far more than 16 evaluations, so anyone who reads the proof interpolates both columns. This recovers the
    transfer amount and the remaining balance exactly, from every transfer.
  - The Poly table's openings also give about 1,800 linear equations per proof on the secret coefficients.
- **Fix:** before any switch-on, add a named hiding preset that meets the claim (`zk: true, ext5: true`, the FRI values
  of the 128-bit proven run), and make `verify` reject `zk == false`. Raise the backup's `MAX_PROOF` to the exact
  largest parseable hiding proof, as Ligero does. Otherwise state in `lib.rs` / README that `DEFAULT` is a measurement
  preset only.
- **Confidence:** high. The mechanism follows from the code. The recovery itself was not run.

### F2 — P2 — The proof decoder accepts overlong varints, so a valid proof can be re-encoded without the witness (Codex lead (a): confirmed)

- **Where:** `src/enc.rs:221-234` (`De::varint`). Also `src/rel.rs:475-479`: after decoding there is no re-encode
  check, only `rest.is_empty()`.
- **Defect:** `varint` returns as soon as a byte < 0x80 arrives, even when that byte is `0x00` after continuation
  bytes. So length 1 decodes from `01`, `81 00`, `81 80 00`, … up to 10 bytes. Every `Vec` / sequence length in the
  `BatchProof` is such a varint. The Plonky3 types decode to the same value, and the transcript absorbs decoded
  values, not raw bytes.
- **Failure scenario:** take any valid `R_TX` proof (143,128 B) and replace any sequence-length byte `L` with
  `L|0x80, 0x00`. The proof grows by 1 byte and still fits under 160 KB. It decodes to the identical `BatchProof` and
  verifies. Anyone can do this without the witness, and can make up to about 17 KB of distinct encodings per proof.
  - This breaks the spec's canonical-encoding rule (pq-zero-knowledge.md, "Canonical encodings (P6e D15)": "Every
    decoder accepts exactly one encoding … `encode(decode(x)) = x`").
  - The proof bytes are not covered by `authDigest` (`keccak256(stmt)` only). Anything that keys on the proof or
    calldata bytes, such as dedupe, tx tracking or relayer bookkeeping, can be confused.
- **Fix:** in `varint`, reject a terminating byte of 0 when `i > 0` (and keep the 10th-byte check). Better still, in
  `verify_with!` require `enc::to_vec(&proof)? == $proof` (an exact round trip). That also catches any other
  non-canonical encoding that slips through serde.
- **Confidence:** high. Field elements, bools and options are strict: Goldilocks' `Deserialize` rejects values ≥ p in
  0.9.0-rc.1, and `enc.rs` rejects tags other than 0/1. So the overlong varint is the hole.

### F3 — P2 — Both hiding paths seed every mask and salt straight from `rnd32`, without the spec's hedge (Codex lead (b): confirmed)

- **Where:**
  - `src/rel.rs:496-514`: `rnd32` is passed unchanged into `p.zk(&seed, rnd32)`, `p.zk_ext(…, rnd32)` and
    `p.whir_ext(…, rnd32)`.
  - `src/config.rs:252-258`: `StdRng::from_seed(rnd)` seeds both the `HidingFriPcs` masks and the Merkle salts.
  - `src/whirpcs.rs:78-80`: `StdRng::from_seed(rnd)` for the trace / quotient masks and the HVZK-WHIR randomness.
- **Defect:** CTR-PQZ-19 requires the masking randomness inside the proof to be hedged as
  `H(secret ‖ statement ‖ 32 B CSPRNG)`. PQZH-Ligero does this with
  `SHAKE256("SCAAS-PQZH-LIGERO-RNG-V2" ‖ rnd32 ‖ op ‖ len ‖ stmt ‖ wit)`. The backup does not, and neither the
  witness nor the statement reaches the RNG.
- **Failure scenario:** a wallet whose RNG fails or is predictable (a constant, a VM snapshot, a wasm
  `getRandomValues` fallback) passes a guessable `rnd32`.
  - The mask draws do not depend on the witness values, only on the shapes. So an observer re-runs
    `StdRng::from_seed(rnd32)` with the same draw order, regenerates every random trace row / `Z_H·r` mask and every
    salt, and subtracts them from the opened values.
  - The proof then leaks exactly as in F1: the Digit table's amount and balance digits.
  - A repeated `rnd32` across two statements also repeats the masks.
  - With the hedge, the secret witness keeps the masks secret even when `rnd32` is predictable.
- **Fix:** derive the RNG seed as the spec does, for example
  `SHAKE256("SCAAS-PQZH-STARK-RNG-V1" ‖ rnd32 ‖ u8(op) ‖ be32(len) ‖ stmt ‖ wit)[0..32)`, in `prove_inner`. Pass that
  seed, never `rnd32` itself, to `zk` / `zk_ext` / `whir_ext`.
- **Confidence:** high.

### F4 — P3 (latent) — The verifier caches the preprocessed commitment per (op, Params), but the MV layout depends on statement values

- **Where:**
  - `src/rel.rs:436-449` (`common`: thread-local cache keyed by `(op, Params)`; the comment says a precompile would
    hard-code the root);
  - `src/air.rs:236-240` (`used` drops candidates whose coefficient array is all zero);
  - `src/air.rs:282-284` (`scol`, the same dependence);
  - the statement-coefficient outputs at `src/rel.rs:271, 286-290`.
- **Defect:**
  - `MvAir::new` decides which inputs a group reads from the coefficient values, and for `R_TX` some of those values
    are statement data (`NTT(u_T[j])`, `NTT(pk_t[j])`, `NTT(pk_f[j])`, `NTT(pk_a[j])`).
  - When a group holds only statement outputs, a zero statement polynomial removes a candidate. That changes `src`,
    the preprocessed columns, `PolyAir`'s `PR_NTT` counts and possibly `block` / height.
  - So the preprocessed root, which is supposed to be statement-independent, is not.
- **Failure scenario:**
  - The trigger needs `mv_width` ∈ {1, 2, 4, 8, 16, 32, …}. At those widths output 32 of MV1 (33 outputs), or the
    three statement outputs of MV2 (35 outputs), sit in a group of their own.
  - `pk = 0` passes `R_REG` (s = e = 0 meets both norms). A zero `u_T` polynomial (for example an all-zero initial
    balance ciphertext) works too.
  - Either one changes the layout. A node's result for such a transfer then depends on which statement that thread
    verified first, so nodes diverge.
  - A hard-coded root would make these transfers unprovable.
  - At the only width ever used (`mv_width = 9`: groups 27..32 and 27..34 also contain fixed outputs that read every
    candidate), the layout is stable. Hence latent.
- **Fix:** decide `used` and `scol` by structure (every candidate `c < stmt_lead` of an output counts as used,
  whatever its value). Or reject any `mv_width` for which a group holds only statement outputs, and assert in
  `common` that the cached `CommonData` matches the current AIRs' preprocessed widths and heights.
- **Confidence:** high on the code path; it is latent at the parameters actually used.

### F5 — P3 — Spec drift if switched on: the verifier checks no header words and supports only two forms

- **Where:** `src/rel.rs:155-159` (`build_reg`) and `src/rel.rs:212-232` (`parse_tx`) read only the `fee` word.
  `src/rel.rs:392-398` handles only ops 1 and 3. `src/rel.rs:28` sets 160 KB, where the spec sets 262,144 B for PQZH.
- **Defect:**
  - The verifier does not check `opTag`, `proofSystemId` (its own `PQZH_PROOF_SYSTEM_ID` is never compared),
    `auditorOn` (rule R6), the salt form or the zero words.
  - There is no `R_TX0`, `R_BURN`, `R_DS`, `R_DR` or `R_TXM`.
  - The id `aa1f92dd…` is marked provisional.
  - Ligero, by contrast, decodes through `pqz-stmt` and then checks its own id.
- **Failure scenario:** if `pqz-ffi` dispatched to this backend without `pqz-stmt` in front of it, a statement
  carrying another system's id or a non-canonical header would be verified on the hashed bytes alone. The 66,560-byte
  `R_TX0` form has no verifier at all.
- **Fix:** route every statement through `pqz-stmt` (as Ligero does), check this backend's own id, and add the missing
  forms before any switch-on.
- **Confidence:** high; the impact depends on how the dispatcher is wired.

## Checked and found sound

**AIR soundness (`air.rs`), with all bounds re-derived:**

- **Poly rotation:** the rows of a block are linked by the transitions `n[m] = c[m+1]` and `n[63] = −c[0]`, gated by
  the period-64 block end.
- **`ev`:** it equals `NTT(w)[k]` (I re-derived the negacyclic identity).
- **Coefficient range:** every coefficient is range-checked to [−4096, 4096) on every row of every range block.
- **Exact l2 norms:** the field sum stays < 2^35 with no wrap, and the slack limbs (2 × 13 bits) force norm ≤ bound.
- **NTT bus:** keys are `(p·64 + k, value)` with preprocessed multiplicities that match the MV reads.
- **COEF bus:** keys are `(192..195)·64 + i` for `i < 16`, sent once and received once.
- **MV accumulators:** they reset at the block end and must be zero there. Target rows are pinned to the periodic
  targets. Padding rows have coefficient 0.
- **Range table:** it starts at 0 and steps by 1 over 8,192 rows.
- **Digit rows 3-7:**
  - digits are in [0, 16), M in [0, 2^14), carries in [−64, 1984), e_T in [−2^24, 2^24), τ in [−4096, 4096);
  - `c_15 = 0`, and padding rows cannot extend the chain;
  - every identity stays below 2^55 (statement coefficients are centred, ‖s‖ ≤ 36), so equality mod p is equality
    over Z.

**Statement binding:**

- The statement enters only through verifier-computed periodic columns (targets, statement coefficients, `v`, fee
  nibbles) plus the challenger seed `keccak256(tag ‖ op ‖ be32(len) ‖ stmt)` (strong Fiat-Shamir).
- `public_values` are empty by design.
- `degree_bits` must equal the expected degrees before `verify_batch`, and the preprocessed root comes from the
  verifier's side, never from the proof.

**Challenger (`config.rs`):**

- Base-field and extension sampling rejects 64-bit words ≥ p.
- Grinding uses canonical witnesses. Plonky3 0.9 also rejects a nonzero PoW witness when bits = 0.

**Plonky3 0.9.0-rc.1 shape checks:**

- The FRI verifier checks commit and query counts, sibling lengths, the final-polynomial length and non-canonical PoW
  witnesses.
- The batch-STARK verifier checks instance counts, opened widths, chunk counts, preprocessed metadata and degree
  bits.

**ZK-WHIR adapter verifier (`whirpcs.rs:449-513`):**

- The randomisation round must be the zero cap with zero values.
- The proof count must match. Widths come from opened values that batch-stark has already checked, and must not be
  ragged.
- `n0 ≤ 26`, `pre = n − k − m` cannot underflow, and offsets are multiples of the heights.
- `s.inverse()` is safe because every factor passed `try_inverse`.
- Claims are recomputed and compared to `pf.evals`. p3-whir's `verify` observes the commitment and the claims itself.
- I checked the trace masking (`r·(X^h − 1)`) and the quotient masking (`t·((X/s)^h − 1)`) against the formulas.

**Determinism:**

- WHIR parameters are derived at verify time with floats, through the `libm` crate (pure Rust, the same on native and
  wasm32).
- The `HashMap` in the cache affects only lookup speed, not results.
- There are no float or OS dependencies on the FRI path.

**Allocation and time:**

- The proof is length-checked before parsing.
- `De::len` caps every sequence length at the remaining input, and the decoder has no recursion driven by the input.
- Verify cost is fixed by the parameters and by `degree_bits`.
- Statement parsing is length-checked first, so all slicing is in bounds. This crate's verify path has no `unwrap`
  reachable from the input.

**`xcheck/`:**

- `run.sh` compares the four `R_REG` / `R_TX` files byte for byte; the last run, `runs/s5-xcheck.txt`, was equal.
- `ligero.sh` with `kat_stmt.py` / `kat_multi.py` parse, rebuild and recheck the norms and the debit identity.
- `kat_multi.py` turns exceptions into FAIL.
- STATUS.md line 526 ("still writes the filler") is stale: commit `68def08` fixed `client.rs`.

## Not covered or not established

- **The LogUp terminals in hiding mode:** each AIR's `lookup_terminals` value is sent in the clear. It is a
  deterministic function of the witness; for example the Range AIR's value is `Σ_v m_v/(α − v)` over the exact
  histogram of every range-checked value. I found no blinding in p3-lookup / p3-batch-stark 0.9.0-rc.1. I found no
  practical attack, because `R_TX` terminals mix fresh high-entropy `r`, `e1`, `e2` and `y`. But the ZK claim needs
  either a proof that covers the terminals or blinding. Treat this as an open question to settle before any switch-on,
  not as a finding.
- **Plonky3 internals:** I did not audit `HidingFriPcs` masking or the ZK quotient randomisation; I took them as
  correct.
- **Measurement code:** I did not review `src/bin/pqzh_whir.rs` (non-hiding p3-multi-stark), `pqzh_security.rs`, or
  `runs/wr-probe` (measurement only), and did not re-check the 71.9 / 100.6-bit soundness figures.
- **wasm32 panics:** the wasm build uses `panic = "abort"`, so `verify`'s `catch_unwind` does nothing there and any
  panic reachable inside Plonky3 would trap rather than return false. I found no such path in this crate.
- **Bench-only code:** `wasm/lib.rs:145-147` (`step_load`, `Vec::from_raw_parts` on a pointer supplied by JS) is
  bench code and was not reviewed for memory safety.
- **Witness buffers:** the prover does not zeroize its witness or trace buffers, unlike the PQZL review's
  secret-clear fix. It is prover-side only and was not assessed further.
