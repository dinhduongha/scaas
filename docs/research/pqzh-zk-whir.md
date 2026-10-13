> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH with zero-knowledge WHIR: options, choice, design (P6-PQZH, next step)

Written 2026-10-14 for the owner's decision of the same day (TODO P6-PQZH: "PQZH is NOT shelved; build and measure a
zero-knowledge WHIR path, Goldilocks⁵ and Goldilocks², Johnson-bound bits"). Follows `pqzh-zk-ext5.md` (§7: WHIR does
not plug into Plonky3's uni/batch STARK; the multilinear `p3-multi-stark` takes only non-hiding WHIR and is not ZK;
non-ZK WHIR Goldilocks⁵ Johnson `R_TX` 257,530 B at 125.3 composed bits), `pqzh-prototype.md` and `pqzh-design.md`.
Code: crate `pqz-core/pqzh/` on branch `pqzh-zkwhir` (from main `79924cf`, not merged). **No decision is recorded
here**; §8 lists the owner questions.

**Status: design note only. The work was paused on the owner's request of 2026-10-14 (machine shutdown after the
Docker package job) before any implementation or measurement; nothing in this note is [measured].** §7 says exactly
where to resume.

Tags as in `pqzh-zk-ext5.md`: **[source]** read from the Plonky3 0.9.0-rc.1 crate sources in `~/.cargo/registry`
(file named), **[paper]** from the cited paper, **[estimate]** a computed or reasoned bound, **[inference]** a
conclusion drawn here.

## 1. Result

- **Chosen option (b-uni): Plonky3's hiding batch STARK with an HVZK-WHIR commitment.** A new PCS adapter in the
  crate implements `UnivariateStarkPcs` (`ZK = true`) on top of p3-whir's `HidingWhirPcs` (HVZK-WHIR, ePrint
  2026/391). Each trace / quotient / permutation column is committed in coefficient form inside one stacked
  multilinear polynomial per commitment round; an out-of-domain opening `p(ζ)` is a multilinear evaluation of that
  polynomial at a point built from `ζ, ζ², ζ⁴, …`. The STARK side keeps Plonky3's existing ZK layout unchanged
  (trace randomised to degree `2n`, quotient chunks masked as in ePrint 2024/1037 §4.2).
- **Why this one**: it is the only option whose zero-knowledge argument is a composition of two existing, published
  arguments with existing code on both sides (the STARK-level masking of 2024/1037 already in `p3-batch-stark`, the
  PCS-level HVZK of 2026/391 already in `p3-whir`). The new code is the adapter only (≈ 600–900 lines [estimate]),
  with no change to Plonky3. The alternative of making `p3-multi-stark` zero-knowledge (§3, option a) is a protocol
  change across its zerocheck, fractional-GKR LogUp and opening code (≈ 63,600 lines in the crate [source]), with no
  published ZK analysis of that exact protocol: weeks, plus a security review.
- **Feasibility**: within the 2-week bound the brief set [estimate: 3–5 days adapter + tests, 1–2 days measurement and
  bit accounting]. Not abandoned.
- **Expected size (not measured)**: four HVZK-WHIR openings per proof (main, LogUp permutation, quotient,
  preprocessed) where `p3-multi-stark` had two plain ones. If each opening costs about what one plain opening cost in
  `pqzh-zk-ext5.md` §7 (≈ 100–120 KB at Goldilocks⁵, rate 4), `R_TX` lands at ≈ 400–500 KB [estimate, rough]: likely
  **above** conjectured FRI + ZK (340,431 B) and below proven FRI + ZK (622,448 B). This has to be measured; §6
  lists how to bring it down if it holds (one batched opening for all rounds).

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

## 5. Design of the adapter (to build, `src/whirpcs.rs`)

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

## 6. If the four openings make it too large

[estimate, not built] (1) Batch all rounds into one WHIR opening: the rounds are committed at different times, but
all are opened at ζ after the last commitment, so a batched-WHIR (random linear combination of the four committed
oracles, same domain after padding) needs one query phase instead of four — needs a batch mode in the hiding
pipeline, which `p3-whir` 0.9.0-rc.1 does not expose. (2) Rounds cannot be merged at commit time (the Fiat–Shamir
order main → LogUp challenges → permutation → α → quotient fixes four commitments); `R` already costs nothing.
(3) Rate / fold sweep as in `pqzh-zk-ext5.md` §7.

## 7. Status / resume (2026-10-14)

- **Done**: sources read (§2); options and choice (§3, §4); adapter design (§5). No code, no runs; no background
  jobs left running.
- **In progress**: nothing half-written in the crate (the branch has only this note, the README index row and the
  TODO entry).
- **Next exact steps** (worktree `.claude/worktrees/zkwhir`, branch `pqzh-zkwhir`, crate `pqz-core/pqzh`):
  1. `src/whirpcs.rs`: the adapter of §5 (`WhirUniPcs<EF>` over `HidingWhirPcs<EF, F, Radix2DFTSmallBatch<F>,
     ValMmcs, BeChallenger, StdRng>`), unit tests: §5.2 embedding vs direct evaluation; commit / open / verify round
     trip on random matrices; a wrong opened value and a wrong `evals` entry rejected.
  2. `src/config.rs`: `Params.whir: Option<WhirParams { rate, fold, pow, target, unique: bool, ell_zk, mask_rate }>`
     (Copy/Hash), `WhirZkCfg<EF> = StarkConfig<WhirUniPcs<EF>, EF, BeChallenger>`; `rel.rs`: two more dispatch arms
     in `prove_inner`, `verify`, `setup_cfg!`, `breakdown` (per-round proof bytes); `digit_height` = 16 under WHIR
     (no FRI query budget to cover). FRI paths untouched.
  3. `src/bin/pqzh_bench.rs`: flags `--whir-rate R --whir-fold K --whir-pow B --whir-target T [--whir-unique]`;
     `src/bin/pqzh_security.rs` or a new `--whir` mode for the bits of §5.5; `wasm/lib.rs`: a `step_init3` taking
     the WHIR parameters.
  4. ZK sanity test (`tests/smoke.rs`): two witnesses of the same statement shape (`client::setup` with two seeds),
     proofs with fixed masks; assert no witness field element appears verbatim among the opened values / proof
     words, and that the opened values of the two proofs pass the same coarse distribution check (a test of the
     plumbing, not a proof of ZK).
  5. Tests, then runs, one at a time under the lock (each a committed run file, `runs/w*`):
     `scripts/capped sh -c 'cargo test --release --offline > runs/w1-tests.txt 2>&1'`;
     `scripts/capped runs/bench.sh w2-zkwhir5-r3 --rel both --np 3 --nv 100 --nadv 10 --max-proof 4000000 --whir-rate 3 --ext5`
     and `-r4` (check memory against the 4 GB cap first with `--np 1 --sizes-only`); Goldilocks²
     `w3-zkwhir2-r3-t96` / `-t100-pow20`; wasm verify of the dumped proofs as `runs/t6-zk5.sh` does; `xcheck/run.sh`
     unchanged (`runs/s5-xcheck.txt`) and the wasm32 build.
  6. Fill the comparison table (ZK WHIR Goldilocks⁵ / ², FRI + ZK conjectured / proven, non-ZK WHIR), update §1,
     the TODO P6-PQZH entry, `python3 scripts/docs_check.py check`.

## 8. Open questions for the owner

1. Accept option (b-uni) as the ZK WHIR path (HVZK-WHIR under Plonky3's hiding batch STARK), with option (a), a ZK
   `p3-multi-stark`, left out as weeks of protocol work without a published analysis?
2. If the measured `R_TX` is above conjectured FRI + ZK (the [estimate] of §1), is a batched-opening WHIR (§6, needs
   a `p3-whir` change or our own batch layer) worth building, or does that settle "FRI for PQZH"?
3. Goldilocks²: report it at the reachable per-term targets (96–100 bits) only, as in `pqzh-zk-ext5.md` §7?

## References

- ePrint 2024/1586, Arnon, Chiesa, Fenzi, Yogev, "WHIR: Reed–Solomon Proximity Testing with Super-Fast Verification".
- ePrint 2026/391, Chiesa, Fenzi, Weissenberg, "Zero-Knowledge IOPPs for Constrained Interleaved Codes" (HVZK-WHIR).
- ePrint 2024/1037, Haböck, Al Kindi, "A note on adding zero-knowledge to STARKs".
- ePrint 2017/305, Chiesa, Forbes, Spooner, "A Zero Knowledge Sumcheck and its Applications".
- ePrint 2019/317, Xie, Zhang, Zhang, Papamanthou, Song, "Libra: Succinct Zero-Knowledge Proofs with Optimal Prover
  Computation".
- Plonky3 0.9.0-rc.1 crates `p3-whir`, `p3-multi-stark`, `p3-batch-stark`, `p3-fri`, `p3-commit`, `p3-security`,
  `p3-multilinear-util` (files named in the text).
