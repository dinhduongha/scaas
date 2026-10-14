> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH with zero-knowledge WHIR: options, choice, design, measurement (P6-PQZH)

Written 2026-10-14 for the owner's decision of the same day (TODO P6-PQZH: "PQZH is NOT shelved; build and measure a
zero-knowledge WHIR path, Goldilocks⁵ and Goldilocks², Johnson-bound bits"). Follows `pqzh-zk-ext5.md` (§7: WHIR does
not plug into Plonky3's uni/batch STARK; the multilinear `p3-multi-stark` takes only non-hiding WHIR and is not ZK;
non-ZK WHIR Goldilocks⁵ Johnson `R_TX` 257,530 B at 125.3 composed bits), `pqzh-prototype.md` and `pqzh-design.md`.
Code: crate `pqz-core/pqzh/` on branch `pqzh-zkwhir` (from main `79924cf`, not merged); raw runs
`pqz-core/pqzh/runs/w*` (every file named below).

**Status: built and measured (2026-10-14, session 4). The FRI fallback of owner decision (2) triggered: `R_TX` with ZK
WHIR at 128 bits is 1,948,901 B, above FRI + ZK conjectured (340,431 B) — record: settle on FRI.** §7–§9 hold the
measurements, §10 the recommendation, §12 the open questions.

Tags as in `pqzh-zk-ext5.md`: **[source]** read from the Plonky3 0.9.0-rc.1 crate sources in `~/.cargo/registry`
(file named), **[paper]** from the cited paper, **[measured]** from a run file named next to it (machine as in
`pqzh-prototype.md` §2: AMD Ryzen 5 7235HS, single thread, every run alone under `scripts/capped`, 4 GB memory cap,
2 GB swap), **[model]** bits computed from the configuration (no proof needed), **[probe]** a single run (n = 1),
**[estimate]** a computed or reasoned bound, **[inference]** a conclusion drawn here.

## 0. Owner decisions of 2026-10-14 (recorded in full, as given for this step)

1. **Accept option (b-uni) as the ZK WHIR path** — Plonky3's zero-knowledge batch STARK (`p3-batch-stark`, `ZK =
   true`, unchanged) plus an adapter `src/whirpcs.rs` implementing `UnivariateStarkPcs` over `p3-whir`'s
   `HidingWhirPcs` (HVZK-WHIR, ePrint 2026/391); **no** ZK variant of `p3-multi-stark` (option (a)). Status: applied —
   the adapter is built, tested and measured on branch `pqzh-zkwhir` (§5, §7).
2. **If `R_TX` with ZK WHIR at 128 bits lands above FRI + ZK conjectured (340,431 B), stop and record "settle on
   FRI"**; do **not** build a batched multi-round WHIR opening (§6). Status: triggered — `R_TX` is 1,948,901 B
   (5.7× the threshold) at the best setting within the 4 GB cap (`runs/w2-zkwhir5-r3.jsonl`); no batched opening was
   built; recorded here as "settle on FRI" (§10).
3. **Goldilocks² is reported only at its reachable per-term targets of 96–100 bits** (128 is refused by WHIR's
   grinding budget). Status: applied — measured at target 96 / 16 grinding bits and 100 / 20 (§8); the measurement
   also shows that HVZK-WHIR's masked base case has no security over Goldilocks² by p3's own accounting (§8).

## 1. Result

- **Built** (`src/whirpcs.rs`, ≈ 600 lines incl. tests; `config.rs` `WhirParams` / `WhirCfg`; `rel.rs` dispatch and
  per-opening breakdown; bench / security / wasm flags): Plonky3's hiding batch STARK runs unchanged over an
  HVZK-WHIR PCS. `R_REG` and `R_TX` prove and verify natively and in wasm32; **0 of 1,440 native and 0 of 480 wasm32
  mutated inputs accepted, 0 panics** (`runs/w2-*`, `runs/w3-*`); unit tests of the embedding, the masking and the
  rejections pass (`runs/w1-tests.txt`); the C cross-check of statement / witness bytes is unchanged
  (`runs/w7-xcheck.txt`).
- **Measured, Goldilocks⁵, Johnson bound, 128-bit per-term target** (starting rate 3 = blowup 8, fold 4, 16 grinding
  bits, mask code rate 1/16), `R_TX`: **1,948,901 B, prove 206 s, 2.42 GB peak heap, verify p50 / p99 43.7 / 46.5 ms
  native and 83.8 / 93.5 ms wasm32, 124.2 bits composed** (union bound; binding: the four WHIR openings at 126.3 bits
  each, then the 128-bit Keccak collision term) [measured, `runs/w2-zkwhir5-r3*.jsonl`]. Against FRI + ZK at the same
  128 bits: 5.7× conjectured (340,431 B) and 3.1× proven (622,448 B); 10× the prove time; verify 3× native and over
  the 50 ms p99 line in wasm32.
- **Why** [measured breakdown, §9]: each HVZK-WHIR opening costs ≈ 470–490 KB whatever the committed size (2^20 to 2^22
  coefficients), of which ≈ 360 KB is the masked base case (Construction 7.2: blinded mask messages and randomness, and
  paired spot checks of every mask oracle) and ≈ 110–120 KB the code-switching rounds; the batch STARK needs four
  openings (main, quotient, preprocessed, LogUp). **One opening alone is above 340,431 B**, so even the batched single
  opening of §6 would not reach FRI + ZK conjectured [inference].
- **Goldilocks²** (96 / 100-bit per-term targets): `R_TX` 1,015,469 / 1,028,925 B, prove 179 / 181 s, verify p99 24.7 /
  26.5 ms [measured, `runs/w3-*`]; but the base case's shared-γ round has **0 bits** at this mask rate and at most 27.5
  bits at any mask rate over a 2^128 field [model, `runs/w6-ext2-mask-bits.jsonl`]: no ZK WHIR configuration over
  Goldilocks² has a meaningful bound by p3-whir's accounting.
- **Recommendation: settle on FRI for PQZH** (owner decision 2 triggered): FRI + ZK over Goldilocks⁵ (`pqzh-zk-ext5.md`
  §4) stays the PQZH proof system; the ZK WHIR code stays on branch `pqzh-zkwhir` as a measured negative result (§10).

## 2. What Plonky3 0.9.0-rc.1 provides [source]

| Piece | Crate / file | ZK status |
|---|---|---|
| `HidingWhirPcs`: hiding multilinear PCS over HVZK-WHIR | `p3-whir` `src/pcs/zk/{mod,adapter}.rs` | "Opening a set of evaluation claims reveals exactly those evaluations. Nothing else about the committed polynomial leaks. The guarantee is honest-verifier zero knowledge (eprint 2026/391)." Masked sumcheck batches (Construction 6.3), HVZK code switching (9.7), masked base case (7.2); out-of-domain answers padded; per-oracle encoding randomness ≥ the spot checks opened against it (`ZkWhirConfig::new`, `oracle_randomness`). Implements `MultilinearPcs` only. |
| `WhirProver`: plain WHIR | `p3-whir` `src/pcs/adapter.rs` | not hiding; implements `PrescribedPointPcs` (needed by `p3-multi-stark`) |
| `p3-multi-stark`: multilinear SuperSpartan-style STARK (zerocheck sumcheck, LogUp by fractional GKR) | `src/contract/mod.rs` | "Nothing this backend accepts hides anything, so no proof framed here is zero-knowledge" |
| `p3-batch-stark` / `p3-uni-stark` ZK layout | `p3-batch-stark` `src/prover.rs`; `p3-fri` `src/hiding_pcs.rs` | trace committed on a `2n` domain (`log_ext_degrees = log_degrees + is_zk`), quotient chunk count doubled and chunks masked (`get_quotient_ldes`, ePrint 2024/1037 §4.2), a randomisation polynomial `R` committed and opened at ζ (only used inside hiding FRI's batched polynomial), preprocessed columns unrandomised (`commit_preprocessing`) |
| `UnivariateStarkPcs` trait | `p3-commit` `src/pcs/univariate.rs` | the hook the adapter implements: `commit`, `commit_preprocessing`, `get_quotient_ldes`, `commit_ldes`, `get_evaluations_on_domain[_no_random]`, `open_with_preprocessing`, `verify_with_preprocessing`, `get_opt_randomization_poly_commitment`, `const ZK` |
| Security terms | `p3-security` `src/whir/{mod,hiding}.rs`, `src/{stark,deep,ldt}.rs` | WHIR round terms (`queries_error`, `prox_gaps_error`, `fold_sumcheck_error`, `ood_error`, `initial_claims_error`); a hiding base-case report that the crate itself calls "diagnostic … not an end-to-end security claim" (`whir/hiding.rs`); STARK composition generic over a `LowDegreeTest` trait, "WHIR … not yet a `LowDegreeTest` impl" (`ldt.rs`) |

## 3. Options for zero knowledge with WHIR

What has to stay hidden: the witness columns of `R_REG` / `R_TX` (secret key, encryption randomness, the digit
decompositions). Everything the verifier sees is: Merkle roots, the PCS opening transcript, the values opened at the
verifier's points, and (multilinear provers) every sumcheck / GKR round message.

### (a) Hiding WHIR inside a ZK `p3-multi-stark`

Replace `WhirProver` by `HidingWhirPcs` and make every other message of `p3-multi-stark` hiding:

- **Zerocheck sumcheck** (`Σ_x eq(τ, x) · C(trace(x), trace(x+1)) = 0`): each round polynomial is a fixed linear
  function of the witness, so it leaks. Standard fix: ZK sumcheck by a committed random masking polynomial `g`
  (Chiesa–Forbes–Spooner, ePrint 2017/305; Libra, Xie et al., ePrint 2019/317): the prover commits `g` (hiding), sends
  `Σ g`, the verifier draws ρ, the sumcheck runs on `f + ρ·g`; HVZK-WHIR's own Construction 6.3 is a cheaper variant
  (small per-round masks, ePrint 2026/391). [paper]
- **Final evaluation claims** of the zerocheck (each column at the sumcheck point `r` and at its shift) are sent in
  the clear and are linear in the witness. Libra masks them by adding `Z(x)·R(x)` to the witness MLE, which leaves
  the multilinear class (degree 2 per variable) and so does not fit a multilinear PCS; the alternative is extra
  random, constraint-exempt rows in every table, which needs a selector in every constraint and in every LogUp
  multiplicity [inference].
- **Fractional GKR (LogUp)**: every layer reveals evaluations of the numerator / denominator layer polynomials at
  random points (functions of the witness), plus its own sumchecks. ZK GKR needs per-layer masking (Libra §4) or
  committing the layers [paper: Libra].
- **Cost**: three new masked sub-protocols inside a 63,600-line crate whose transcript, security report and contract
  layer would all change; the ZK of the composed protocol is new and unreviewed. **Weeks**, then a review
  [estimate]. Smallest proofs if done (the 257 KB non-ZK lower bound plus the masks).

### (b) Univariate batch STARK over an HVZK-WHIR PCS (chosen; "b-uni")

Keep Plonky3's ZK STARK (`p3-batch-stark`, `ZK = true`) and swap the PCS: a `UnivariateStarkPcs` adapter whose
commitments and openings are `HidingWhirPcs`.

- **What the verifier sees and why it does not leak** [paper, inference]:
  - opened values `t'(ζ)`, `t'(ζ·g)` of each trace / permutation column: `t' = t + Z_H·r`, `r` uniform of degree
    `< n`, so any ≤ `n` evaluations off `H` are uniform and independent of `t` (ePrint 2024/1037 §3; two points here,
    `n ≥ 16`);
  - opened quotient chunk values `q'_i(ζ)`: chunks masked by `v_{H_i}·t_i` with the masks cancelling in the
    verifier's recombination (2024/1037 §4.2: splitting the quotient without these masks leaks, which is the paper's
    main point);
  - the PCS transcript: HVZK-WHIR's simulator needs only the claimed evaluations (2026/391; the `HidingWhirPcs`
    doc: "opening a set of evaluation claims reveals exactly those evaluations"); the adapter's claims are fixed
    public linear combinations of the opened values (§5.3), so they add nothing;
  - the preprocessed columns are public (no masking needed);
  - Plonky3's randomisation polynomial `R` exists only to hide hiding-FRI's batched codeword; with WHIR it is
    unnecessary, and the adapter commits nothing for it (§5.4).
- **Cost**: the adapter only; the proof carries one HVZK-WHIR opening per commitment round (four), the
  univariate-to-multilinear embedding costs nothing in soundness (an exact linear map, §5.2).
- **Soundness**: the STARK's ALI / DEEP / LogUp terms (as for FRI, with WHIR's Johnson list size in place of FRI's),
  plus the four WHIR openings, plus the claim-batching term of §5.3, plus the Keccak-256 collision term; §5.5.

### (b') A plain ZK wrapper around the non-ZK `p3-multi-stark`

"Randomise the witness (extra random rows / columns) and use a hiding commitment" without masking the protocol
messages does **not** give ZK: the zerocheck and GKR round messages are linear in the real rows regardless of extra
rows (random rows only shift them by an independent known-structure term when the constraint selector excludes
those rows), and the PCS evaluations at the sumcheck point are linear in all rows. Random rows help only the final
evaluation claims (as in (a)); the round messages still need the masks of (a). Rejected [inference].

### (c) Other approaches in the literature

- **Recursion / proof composition**: prove "I know a valid non-ZK WHIR proof" with a ZK outer proof (FRI + ZK, or
  Groth16 is ruled out: not PQ). Hides everything, but the outer proof is a STARK of a WHIR verifier (Keccak-256
  Merkle paths in AIR): far larger prover work than the PQZH relation itself. Rejected for cost [inference].
- **WHIR paper (ePrint 2024/1586)**: soundness only; its abstract states no ZK construction [paper]. ZK WHIR is the
  subject of the same group's ePrint 2026/391 (Chiesa, Fenzi, Weissenberg, "Zero-Knowledge IOPPs for Constrained
  Interleaved Codes"): HVZK, round-by-round knowledge soundness with a straight-line extractor, "a negligible overhead
  compared to the (non-zero-knowledge) state of the art" [paper]; that is what `p3-whir`'s `HidingWhirPcs` implements
  [source].
- **ZK sumcheck by masking**: Chiesa–Forbes–Spooner (ePrint 2017/305), Libra (ePrint 2019/317); used by option (a).
- **BlindFold / folding-based ZK** (Jolt's plan, `jolt.a16zcrypto.com/future/zk.html`; page not reachable on
  2026-10-14): commits the sumcheck messages and proves the verifier's checks in a folded instance; designed for
  elliptic-curve commitments, not PQ. Not applicable.

**Fiat–Shamir.** All options are public-coin; the HVZK simulators program the random oracle (the challenges), so
the Fiat–Shamir transform with Keccak-256 as the random oracle gives zero knowledge for the non-interactive proof in
the programmable random-oracle model, provided the prover's masks come from a CSPRNG seeded with fresh entropy
(`HidingWhirPcs::new` documents the same requirement) [inference, standard; not re-proved here].

## 4. What is argued and what is assumed (option b-uni)

- **Argued**: honest-verifier statistical ZK of the interactive protocol, by a simulator that (1) samples the opened
  values `t'(ζ)`, `t'(ζg)`, `q'_i(ζ)` from their (uniform-given-constraints) distribution as in 2024/1037, the
  preprocessed values from the public columns, and (2) runs the HVZK-WHIR simulator of 2026/391 on the resulting
  claims for each of the four commitments. Then ZK after Fiat–Shamir as in §3.
- **Assumed, not re-proved**: (i) the HVZK theorem of 2026/391 and that `p3-whir` implements it faithfully (the crate
  deviates in places it documents, e.g. "no commitment-phase out-of-domain samples: the round-by-round analysis of
  eprint 2026/391 replaces them with list-size union bounds"); (ii) the 2024/1037 analysis as implemented by
  `p3-batch-stark`; (iii) that four HVZK openings of independently masked commitments compose (each has its own
  encoding randomness; the claims share only the public point ζ) [inference]; (iv) Keccak-256 as a random oracle.
- **Statistical, not perfect**: Plonky3 notes its trace randomisation is statistical (`p3-batch-stark` prover:
  "This approach is only statistically ZK") [source]; the failure event is ζ hitting the trace domain, ≤ `2n/|F|`.
- **Not claimed**: a full machine-checked proof; ZK against a malicious verifier beyond what Fiat–Shamir gives.

## 5. Design of the adapter (`src/whirpcs.rs`; as built, deviations in §5.6)

### 5.1 Commit

| Call from `p3-batch-stark` | Adapter |
|---|---|
| `commit((ext domain 2n, trace n × w))` (main, permutation) | coefficients `c = IDFT_n(column)` padded to `2n`, plus `Z_H·r`: `c[i] −= r[i]`, `c[n+i] += r[i]`, `r` from the CSPRNG (= 2024/1037's `t + Z_H·r`) |
| `commit_preprocessing` | coefficients `IDFT_n`, zero-padded to `2n`; committed with a fixed seed so the root is a verifier constant (as the FRI path does) |
| `get_quotient_ldes(chunks on cosets sᵢ⟨ω⟩, num_chunks)` | `q_i = coset_IDFT(evals, s_i)`; `q'_i = q_i + ((X/s_i)^h − 1)·r_i`, `r_last = −Σ_{j<last} (c_j/c_last)·r_j` with Plonky3's `get_zp_cis` constants (copied, 10 lines); returns coefficient matrices of height `2h` |
| `commit_ldes(coefficient matrices)` | stack and commit |
| `get_evaluations_on_domain[_no_random](data, i, quotient coset)` | coset DFT of matrix `i`'s stored coefficients onto the requested coset, natural order (owned `RowMajorMatrix`) |
| `get_opt_randomization_poly_commitment` | no commitment: a fixed all-zero digest, opened values all zero (§5.4) |

**Stacking.** One multilinear polynomial per commitment: columns ordered by height (descending), within a height
those opened at two points first; column `k` of height `2^m` occupies indices `[u_k·2^m, (u_k+1)·2^m)`; total padded
to `2^N`. `HidingWhirPcs` (num_variables `N`, built per `N` on demand) commits it; `Poly` is lexicographic with the
first coordinate the most significant bit [source: `p3-multilinear-util` `poly/eq_table.rs`].

### 5.2 Univariate opening as a multilinear evaluation

For a block of `2^k` adjacent columns (aligned) of height `2^m` at unit offset `U` and a point `z`:
`Σ_{c<2^k} β^c · col_c(z) = Σ_x f(x) · Π_j a_j^{x_j}` over the block's `k + m` low variables, with
`a = (β^{2^{k−1}}, …, β, z^{2^{m−1}}, …, z)`. Since `eq(p, x) = Π_j a_j^{x_j} / (1 + a_j)` for `p_j = a_j / (1 + a_j)`,
this equals `S · f̃(bits(U >> k), p)` with `S = Π_j (1 + a_j)`. So every block gives one evaluation claim of the
stacked polynomial (prefix coordinates boolean). `1 + a_j = 0` happens with probability ≤ `2^j/|F|`; prover and
verifier then return an error (completeness loss only). Checked first by a unit test against a direct univariate
evaluation (the `eval_base` doc formula `1 − p + 2px` looks like a typo for the standard `eq`; the test settles it).

### 5.3 Claims per commitment

After all opened values are absorbed, one β is drawn. For every height class and point (ζ, or ζ·g of that height's
trace domain), the run of columns opened there is split into aligned dyadic blocks (a range of `L` columns gives
≤ 2·log₂ L blocks), one claim each. `R_TX` main / permutation / quotient / preprocessed: a few tens of claims per
commitment [estimate], against hundreds if each column were its own claim (each claim costs the prover one
`2^N` eq table). The verifier recomputes every claim value from the opened values and **checks it against
`ZkWhirProof::evals`** before `HidingWhirPcs::verify` (which otherwise trusts the proof's evals). Soundness of the β
combination: ≤ `2^k / |F|` per block (Schwartz–Zippel), union over blocks.

### 5.4 The randomisation round and the transcript

`p3-batch-stark` in ZK mode always puts the `R` round first and checks only its presence and width
(`Challenge::DIMENSION` per instance) [source: `verifier/mod.rs`]; its value enters no constraint. The adapter commits
nothing for it (zero digest), opens it to zeros, and the verifier rejects round 0 unless its digest and values are
exactly zero. Transcript order: opened values of every round → β → per real round: `observe_commitment` then
`HidingWhirPcs::open` (its `verify` re-observes the commitment, so the prover mirrors that). Prover data of a hiding
round is single-use (`Mutex<Option<…>>`, taken at `open`; a second open is an error, as `HidingFriPcs` enforces);
the preprocessed round stores its coefficients and seed and recommits per proof (public data).

### 5.5 Bits

Composed as a union bound (as `p3-multi-stark`'s `security_report`): STARK terms from `p3-security`
(`air::composition_error`, `deep::deep_ali_error`, `logup::security_term`) at the Johnson list size of WHIR's first
code (`1/(2η√ρ)`, η from the config); each of the four WHIR openings from the `p3-whir` round formulas
(`prescribed_security` in `src/pcs/security.rs`, re-implemented because it is crate-private; no commitment OOD term
under HVZK) plus the hiding base case's `round_by_round` bits (`hiding_base_case_security_report`); the β term of
§5.3; Keccak-256 collision 128. Conjectured: the same with `SecurityAssumption::CapacityBound` where p3 computes it,
labelled conjectured (the capacity conjecture is the one ePrint 2025/2046 disproved for some codes, as noted in
`pqzh-zk-ext5.md` §7; reported separately, never as the headline). Goldilocks²: 128 is out of reach (WHIR refuses
the configuration, 42–50 grinding bits, `pqzh-zk-ext5.md` §7); measure at the per-term targets of `runs/t13`
(96 / 16 bits and 100 / 20 bits).

### 5.6 As built: deviations and additions to §5.1–§5.5

- **Salted Merkle trees.** `HidingWhirPcs` runs over `HidingValMmcs` (Keccak-256 Merkle tree with 4 random salt
  elements per leaf, the tree FRI + ZK uses), not the plain tree of p3-whir's tests: the Merkle compiler of a ZK IOP
  needs hiding leaf commitments (sibling digests of unopened leaves are sent) [inference, standard BCS argument]. Cost:
  32 B of salt per opened leaf.
- **Trace masking by `t + Z_H·r` on coefficients** (as §5.1), the same distribution as `HidingFriPcs`'s interleaved
  random rows (a uniform polynomial of degree < 2n agreeing with the trace on H) [inference]; the quotient masks are
  §5.1's, with `v_{H_i}(X) = (X/s_i)^h − 1` in the plain monomial basis; unit-tested: the masked trace equals the
  trace on H, the masked chunks equal the chunks on their domains, and the masks cancel in the Lagrange recombination
  (`whirpcs::tests::coefficient_forms`).
- **Claims**: per matrix (not per height class) and per point, one claim per aligned dyadic block of its columns;
  β is drawn once after every opened value of every round is absorbed. The embedding of §5.2 is exact (unit test
  `embedding_matches_direct_evaluation`; p3's `eval_base` is the standard `eq`, the doc formula is a typo). `R_TX`:
  24 / 60 / 5 / 24 claims for main / quotient / preprocessed / LogUp.
- **Variable count**: the stacked size rounded up to a power of two, raised until `ZkWhirConfig::new` accepts it (its
  per-oracle randomness must fit the codeword slack); a function of the public shapes only. `R_TX`: 2^22 / 2^22 / 2^20
  / 2^21 coefficients.
- **Preprocessed round**: committed with a fixed seed (`PRE_SEED`, salts and encoding randomness), recommitted at open
  (same root, checked), opened with the prover's fresh randomness. A private round opened twice is refused (its data
  is taken at the first open).
- **Mask code**: `ell_zk = 4`, mask code rate 1/16 (`WhirParams::DEFAULT`). Rate 1/2 (p3-whir's test value) needs
  305 mask spot checks at 128 bits and gave `R_REG` 4.73 MB; 1/4, 1/8, 1/16: 2.76 / 2.16 / 1.91 MB; 1/64: 1.64 MB but
  the base case's γ round drops to 49.5 bits [probe, `runs/w0-mask-probe.log`, `runs/w0-probe-*`]. 1/32 gives 115
  bits for that round [model, `runs/w6-ext2-mask-bits.jsonl`]. 1/16 is the smallest proof with every term at target.
- **Bits** (`pqzh_security --whir`): union bound of — ALI (`p3-security` `composition_error`), DEEP (`deep_ali_error`)
  and LogUp (`logup::security_term`) at list size 1 (the extracted polynomials of a PCS opening are unique; the WHIR
  terms carry the decoding regime, as `p3-multi-stark`'s report composes its PCS); the β claim batching
  (`log2|F| − log2(opened values)`); each HVZK-WHIR opening = union of the initial-claims term, every fold's
  proximity-gap and sumcheck term (Johnson, p3-whir's one-bit reserve), every round's OOD, query and
  query-combination term (+ its grinding), the base case's γ round and its query round with grinding
  (`hiding_base_case_security_report`, which p3-whir calls "diagnostic only"; no commitment OOD term under HVZK);
  Keccak-256 collision 128. Re-implemented from p3-whir's crate-private `prescribed_security`
  (`src/pcs/security.rs`), so it is this note's composition, not a p3 certificate.

## 6. If the four openings make it too large (not built: owner decision 2)

[estimate, not built] (1) Batch all rounds into one WHIR opening: the rounds are committed at different times, but
all are opened at ζ after the last commitment, so a batched-WHIR (random linear combination of the four committed
oracles, same domain after padding) needs one query phase instead of four — needs a batch mode in the hiding
pipeline, which `p3-whir` 0.9.0-rc.1 does not expose. (2) Rounds cannot be merged at commit time (the Fiat–Shamir
order main → LogUp challenges → permutation → α → quotient fixes four commitments); `R` already costs nothing.
(3) Rate / fold sweep as in `pqzh-zk-ext5.md` §7.

## 7. Measurements: Goldilocks⁵, Johnson bound, 128-bit per-term target

Setting (`runs/w2-zkwhir5.sh`): starting rate 3 (blowup 8), fold 4 (3 code-switching rounds: 79 / 39 / 26 queries,
base case 21–23 queries, 68 mask spot checks), 16 grinding bits, mask code rate 1/16; n = 3 proofs, 100 honest
verifies, 12 mutation kinds × 40 per relation; wasm32 verify of the natively made proofs (n = 100, 12 × 10)
[measured, `runs/w2-zkwhir5-r3.jsonl`, `-time.txt`, `-bits.jsonl`, `-wasm.jsonl`; the first wasm attempt trapped on a
32-bit shift in `claims`, `runs/w2-zkwhir5.log`; fixed, rerun `runs/w2-wasm-rerun.sh`]:

| | `R_REG` | `R_TX` |
|---|---|---|
| Proof | 1,913,510 B | 1,948,901 B |
| Prove p50 | 34.9 s | 205.9 s |
| Peak heap (prove) / process max RSS | 1,213 MB | 2,424 MB / 2.52 GB |
| Verify honest p50 / p99, native | 38.4 / 40.7 ms | 43.7 / 46.5 ms |
| Verify adversarial p99, native | 33.1 ms | 36.2 ms |
| Mutated inputs accepted / panics, native | 0 / 0 of 480 | 0 / 0 of 480 |
| Verify honest p50 / p99, wasm32 (memory) | 73.4 / 91.6 ms (82 MiB) | 83.8 / 93.5 ms (161 MiB) |
| Mutated accepted, wasm32 | 0 of 120 | 0 of 120 |
| Bits composed (union) | 124.24 | 124.22 |

Soundness terms of `R_TX` (bits) [model, `runs/w2-zkwhir5-r3-bits.jsonl`]: WHIR openings main 126.31 (2^22, 24
claims), quotient 126.31 (2^22, 60), LogUp 126.31 (2^21, 24), preprocessed 126.41 (2^20, 5) — inside each the weakest
are the base-case query round 128.02 (with its 14 grinding bits) and the code-switching queries 128.17–128.94; Keccak
collision 128.0; LogUp fingerprint 299.0; DEEP 299.8; β claim batching 309.9; ALI 311.8. `R_REG` the same within
0.1 bit. As with non-ZK WHIR (`pqzh-zk-ext5.md` §7) a per-term target of 128 composes to ≈ 124–125, because the
union bound sums four openings and the collision term; FRI's 128 is `p3-security`'s weakest term, not a sum.

Starting rate 2 and 4 [probe, one proof each, `runs/w4-rate-probe.log`, `runs/w4-probe-zkwhir5-r*.jsonl`, `-time.txt`]:

| Starting rate (blowup) | `R_REG` | `R_TX` | `R_TX` prove | `R_TX` peak heap |
|---|---|---|---|---|
| 2 (4) | 2,034,976 B | 2,074,279 B | 191 s | 1,480 MB |
| 3 (8), §7 table | 1,913,510 B | 1,948,901 B | 206 s | 2,424 MB |
| 4 (16) | 1,830,394 B | 1,856,665 B | 234 s | 4,312 MB (over the 4 GB cap: max RSS 4.18 GB, swapped) |

A higher rate shrinks only the code-switching rounds (143 → 116 → 100 KB per opening); the base case stays at
≈ 355–365 KB per opening at every rate [measured breakdowns].

## 8. Measurements: Goldilocks² at 96 and 100 bits

Starting rate 3, fold 4, mask code rate 1/16; per-term target 96 with 16 grinding bits, 100 with 20 (the settings of
`pqzh-zk-ext5.md` §7 `runs/t13`); n = 3 / 100 / 12 × 10 [measured, `runs/w3-zkwhir2-r3-t96-pow16*`,
`-t100-pow20*`]:

| | `R_REG` 96 / 100 | `R_TX` 96 / 100 |
|---|---|---|
| Proof | 999,610 / 1,018,602 B | 1,015,469 / 1,028,925 B |
| Prove p50 | 23.8 / 25.2 s | 179.4 / 181.2 s |
| Peak heap | 723 MB | 1,445 MB (max RSS 1.50 GB) |
| Verify honest p50 / p99 | 18.1 / 19.3, 18.1 / 21.1 ms | 21.5 / 24.7, 21.8 / 26.5 ms |
| Mutated accepted / panics | 0 / 0 of 120 each | 0 / 0 of 120 each |

**Bits**: every WHIR round term reaches its target (code-switching queries 96.03–96.16 / 100.03–100.16, base-case
queries 96.44 / 100.44), and the STARK terms are LogUp 107–108, DEEP 107.8–108.8, β 118.5–119.1, ALI 119.8–120.2,
collision 128; **but the masked base case's shared-γ round is vacuous (0 bits)**, so the composed bound is 0
[model, `runs/w3-*-bits.jsonl`]. Over mask code rates 1/2 … 1/64 that round gives at most 27.5 bits (1/2), 13.5 (1/4)
and 0 from 1/8 on, at both targets; over Goldilocks⁵ the same round gives 219.5 … 49.5 bits [model,
`runs/w6-ext2-mask-bits.jsonl`, `runs/w6-ext2-mask-bits.sh`]. The term is the sum of the source and mask groups' MCA
errors plus the product of all old / fresh candidate-list bounds divided by |F| (p3-security `whir/hiding.rs`
`HidingGammaRoundReport`); with seven mask groups the product list exceeds 2^128 [inference from the report fields].
So **HVZK-WHIR over Goldilocks² has no meaningful soundness bound in p3-whir 0.9.0-rc.1's accounting**; the 96–100-bit
figures hold only for the non-base-case terms. Goldilocks² at a 128-bit target: refused by WHIR's configuration
(48 grinding bits needed against a 16-bit budget, `runs/w6-ext2-mask-bits.jsonl`), as for non-ZK WHIR.

## 9. Comparison and where the bytes go

`R_TX`, zero knowledge, the smallest proof within the 4 GB prover cap per row:

| `R_TX`, ZK | Bits | Proof | Prove | Peak heap | Verify p99 native / wasm32 | Source |
|---|---|---|---|---|---|---|
| FRI + ZK, Goldilocks⁵, conjectured, blowup 16 | 128 (weakest term) | 340,431 B | 20.3 s | 2.82 GB | 15.5 / 24.1 ms | `pqzh-zk-ext5.md` §4, `runs/t6-zk5-conj-b4-q29*` |
| FRI + ZK, Goldilocks⁵, proven, blowup 16 | 128 (weakest term) | 622,448 B | 20.4 s | 2.82 GB | 19.1 / 28.7 ms | `runs/t6-zk5-proven-b4-q57*` |
| **ZK WHIR, Goldilocks⁵, Johnson, rate 3** | 124.2 (union) | **1,948,901 B** | 205.9 s | 2.42 GB | 46.5 / 93.5 ms | `runs/w2-zkwhir5-r3*` |
| ZK WHIR, Goldilocks², Johnson, target 100 | 0 (base-case γ) | 1,028,925 B | 181.2 s | 1.45 GB | 26.5 ms / — | `runs/w3-zkwhir2-r3-t100-pow20*` |
| Non-ZK WHIR (`p3-multi-stark`), Goldilocks⁵, rate 4 — not ZK, lower bound | 125.3 (union) | 257,530 B | 11.4 s | 1.12 GB | 20.1 ms / — | `pqzh-zk-ext5.md` §7, `runs/t12-whir-ext5-r4*` |

`R_TX` bytes per opening at rate 3 [measured, `runs/w2-zkwhir5-r3.jsonl` breakdown]: main 487,754 (rounds 120,537,
base case 364,018), quotient 486,026, preprocessed 474,174, LogUp 477,770; commitments, opened values and lookup
terminals 23,126. The base case carries, per opening, the blinded messages and randomness of every mask (the
sumcheck masks of 16–18 folded variables and 3 code-switch masks, 68 randomness coefficients each) and 68 paired spot
checks (carried + fresh oracle, each with salts and a pruned Merkle path) of 7 mask groups, plus the source and fresh
main-mask openings [inference from `ZkWhirProof` / `BaseCaseZkProof` and the config numbers in `-bits.jsonl`].

- **ZK costs WHIR 7.6×** (257,530 → 1,948,901 B), against FRI's ≈ 1.7× (FRI plain proven `R_TX` 358,874 B at blowup
  16 → 622,448 B ZK, `pqzh-zk-ext5.md` §7). The HVZK base case is a fixed ≈ 360 KB per opening at 128 bits.
- **Why far above the §1 design estimate of ≈ 400–500 KB** (four openings at ≈ 100–120 KB each, as one plain WHIR
  opening in `pqzh-zk-ext5.md` §7): the plain part of each hiding opening (the code-switching rounds, 111–121 KB at
  rate 3) matched that estimate; what the estimate missed is the masked base case, ≈ 360 KB per opening. ePrint 2026/391
  calls the ZK overhead negligible against the non-ZK state of the art, which is asymptotic in the witness size; at
  128 bits the base case is a constant set by the mask spot-check count (68) times the mask groups (7, two per
  code-switching round plus one) and the per-mask randomness, and at 2^20–2^22 coefficients that constant dominates
  [inference]. The mask code rate trades it against the γ round's bits (§5.6), and the starting rate barely moves it
  (§7).
- **Batching the four openings (§6) would not fix it** [inference]: one opening alone is ≈ 470 KB at rate 3 (450 KB at
  rate 4), above 340,431 B before the STARK's own 23 KB.
- **Prove time** 206 s against FRI's 20 s. Not profiled (a `perf` probe was not permitted in the sandbox, so it was
  dropped); the per-claim equality tables of the HVZK prover over 2^22 points (24–60 claims per round) are the likely
  cost [inference, unverified]. It does not change the size result.
- **wasm32 verify** 93.5 ms p99 for `R_TX`, over the 50 ms line; native 46.5 ms.

## 10. Recommendation

**Settle on FRI for PQZH** (owner decision 2 triggered, 2026-10-14): FRI + ZK over Goldilocks⁵ (`pqzh-zk-ext5.md`
§4) stays the PQZH proof system; the soundness regime / proof limit questions of `pqzh-zk-ext5.md` §9 remain the open
ones. ZK WHIR is 3.1–5.7× larger, 10× slower to prove, 3× slower to verify, and over Goldilocks² has no bound.
For context (reported by the controller on 2026-10-14 from the parallel Ligero branch, not measured in this note):
the Ligero backend gave `R_TX` with ZK at 128 bits 230 KB proven / 92 KB conjectured, below both FRI + ZK rows of §9,
so it is the likely PQZH backend; that comparison belongs to the Ligero note. Measurements here stopped on the
controller's instruction once the stop condition was clear (no further tuning probes).
Keep the ZK WHIR adapter on branch `pqzh-zkwhir` (code, tests, runs) as the measured negative result; revisit only if
p3-whir ships a cheaper hiding base case (the ≈ 360 KB per opening) or a batched hiding opening and one opening falls
well under 340 KB.

## 11. Status / reruns (2026-10-14)

- **Done**: §5 adapter built and tested; §7–§9 measured; the owner's stop rule applied (no batched opening). No
  background jobs left running.
- **Not done**: a batched multi-round opening (owner decision 2); a profile of the prove time (§9); ZK sanity test of
  §5 step 4 beyond "two proofs differ, both verify" (`tests/smoke.rs` `zk_whir_honest_and_hiding`) — not needed once
  WHIR is not chosen.
- Reruns, from `pqz-core/pqzh/`, each alone under the machine lock:

```sh
scripts/capped sh -c 'cargo test --release --offline > runs/w1-tests.txt 2>&1'   # unit + smoke + attacks
scripts/capped runs/w0-mask-probe.sh > runs/w0-mask-probe.log                    # §5.6 mask code rate [probe]
scripts/capped runs/w2-zkwhir5.sh > runs/w2-zkwhir5.log; scripts/capped runs/w2-wasm-rerun.sh   # §7
scripts/capped runs/w3-zkwhir2.sh > runs/w3-zkwhir2.log                          # §8
scripts/capped runs/w4-rate-probe.sh > runs/w4-rate-probe.log                    # §7 rates 2 / 4 [probe]
scripts/capped sh -c 'runs/w6-ext2-mask-bits.sh > runs/w6-ext2-mask-bits.jsonl' # §8 base-case γ bits [model]
scripts/capped sh -c 'xcheck/run.sh > runs/w7-xcheck.txt'                        # statement / witness bytes vs C
```

## 12. Open questions for the owner

1. Close the ZK WHIR line for PQZH (settle on FRI + ZK, Goldilocks⁵, or Ligero once its note is in) and keep branch `pqzh-zkwhir` unmerged as the
   record, or merge the adapter to main as a backup path (it touches only `whirpcs.rs` and dispatch arms; FRI paths
   unchanged)? Recommendation: merge the code and runs (backup, not delete) without changing the PQZH configuration.
2. The FRI questions of `pqzh-zk-ext5.md` §9 (soundness regime conjectured / proven, proof limit, prover memory) are
   now the deciding ones for PQZH.

## References

- ePrint 2024/1586, Arnon, Chiesa, Fenzi, Yogev, "WHIR: Reed–Solomon Proximity Testing with Super-Fast Verification".
- ePrint 2026/391, Chiesa, Fenzi, Weissenberg, "Zero-Knowledge IOPPs for Constrained Interleaved Codes" (HVZK-WHIR).
- ePrint 2024/1037, Haböck, Al Kindi, "A note on adding zero-knowledge to STARKs".
- ePrint 2017/305, Chiesa, Forbes, Spooner, "A Zero Knowledge Sumcheck and its Applications".
- ePrint 2019/317, Xie, Zhang, Zhang, Papamanthou, Song, "Libra: Succinct Zero-Knowledge Proofs with Optimal Prover
  Computation".
- Plonky3 0.9.0-rc.1 crates `p3-whir`, `p3-multi-stark`, `p3-batch-stark`, `p3-fri`, `p3-commit`, `p3-security`,
  `p3-multilinear-util` (files named in the text).
