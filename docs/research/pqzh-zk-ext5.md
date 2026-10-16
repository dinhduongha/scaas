> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH with zero knowledge over Goldilocks⁵ at 128 bits (P6-PQZH, next step)

Written 2026-10-14 for the owner's next PQZH step (TODO P6-PQZH and P6-PQZH-SOL, owner decisions 2026-10-13):
zero knowledge is required (the ZK numbers are the real ones), the challenge field is Goldilocks⁵, the target is 128
bits measured both proven (Johnson bound) and conjectured, proving may be native-only, and the one PQZH configuration
takes the EVM-friendly choices of `pqzh-solidity-verifier.md` §6. Follows `pqzh-prototype.md` (the prototype, its
§10 questions) on branch `pqzh-next` (from main `dde1fa6`, not merged). Code: crate `pqz-core/pqzh/`; raw runs
`pqz-core/pqzh/stark-backup/runs/` (every file named below). **No decision is recorded here**; §9 lists the owner questions.

**[measured]** marks a number from a run in this note (machine as in `pqzh-prototype.md` §2: AMD Ryzen 5 7235HS,
single thread, every timed run alone under `scripts/capped`, 4 GB memory cap, 2 GB swap). **[model]** marks bits from
Plonky3's calculator `p3-security` 0.8.0 on the measured AIR shapes. **[estimate]** marks a computed bound, **[probe]**
a single run (n = 1), **[inference]** a conclusion drawn here.

## 1. Result

**ZK + Goldilocks⁵ builds, proves and verifies for `R_REG` and `R_TX`; at 128 bits the smallest `R_TX` proof that
fits the 4 GB prover cap is 340,431 B conjectured / 622,448 B proven (blowup 16, FRI arity 8, 16 grinding bits),
proving in 20 s with 2.8 GB peak heap; verify p99 is 15.5 / 19.1 ms native and 24.1 / 28.7 ms wasm32, 0 of 960
mutated inputs accepted, 0 panics** [measured, `runs/t6-zk5-*`]. None of the 128-bit ZK settings comes near the
prototype's 160 KB line:

| `R_TX`, ZK, Goldilocks⁵, 128 bits | Proven (Johnson / unique decoding) | Conjectured (random words) |
|---|---|---|
| Smallest within 4 GB (blowup 16, 16 grinding bits) | 622,448 B (worst case ≈ 672 KB) | 340,431 B (worst case ≈ 365 KB) |
| Same, 24 grinding bits [probe] | 587,152 B | 323,487 B |
| Blowup 32 [probe, swapped past the 4 GB cap] | 518,000 B | 289,823 B |
| Prove native (blowup 16) | 20.4 s, 2.82 GB peak heap | 20.3 s, 2.82 GB |
| Prove native (blowup 8) | 10.4 s, 1.42 GB, 776,128 B | 10.4 s, 1.42 GB, 418,983 B |
| Verify p99 honest, native / wasm32 (blowup 16) | 19.1 / 28.7 ms | 15.5 / 24.1 ms |

- **The EVM-friendly configuration** (Keccak-256 Merkle tree over big-endian words, Keccak-256 transcript seed,
  big-endian proof encoding, `NTT(A)` and the selectors in a preprocessed tree) is built as the one PQZH
  configuration. At the prototype's default parameters it costs `R_TX` +0.4 % bytes (143,128 → 143,704 B) and
  +67 % prove time (2.64 → 4.41 s; scalar Keccak-256 and the per-proof preprocessed commitment), and verifies
  faster (p99 11.8 → 9.8 ms) [measured, §3]. Not badly worse: kept.
- **Merkle caps do not help** (§5): Plonky3's pruned multiproof already sends each shared top node once, so a cap
  only adds its 2^h digests per tree; cap 0 is the smallest at every setting [measured].
- **WHIR** does not plug into the uni/batch-STARK path of Plonky3 0.9.0-rc.1 (it is a multilinear PCS; the batch
  STARK needs a univariate one), and the multilinear Plonky3 prover it does plug into is not ZK (§7). Measured
  without ZK through that prover: Goldilocks⁵ Johnson `R_TX` 257,530 B at 125.3 composed bits (11.4 s, 1.1 GB),
  ≈ 17 % under proven FRI at equal memory; Goldilocks² caps at ≈ 91–95 bits (WHIR fold term, LogUp fingerprint).
- The Plonky3 upgrade 0.8.0 → 0.9.0-rc.1 needed no source change (own commit `2e1788c`).
- **Goldilocks² cannot reach 128 bits with ZK either**: the opening-batching term caps `R_TX` at 97.9–99.9 bits
  [model, §6]; Goldilocks⁵ reaches 128 in both regimes, bound by the 128-bit Keccak collision term.
- `R_TX` statement now on the §7.7 layout (640-byte header, fee word at 256); C cross-check against main's
  `pqz_bench.c` byte-identical (§2).

## 2. Statement layout and proofSystemId (task 1)

`rel.rs` reads `R_TX` as pqz-core v2 does (pq-zero-knowledge.md §7.7, `pqz.h`): header of 640 bytes (32-byte words), fee =
the be32 word at offset 256 that must be < 2^64 (as `pqz_rel.c` `rd_word64`; test `tx_fee_word_above_2_64`), body
`pk_f ‖ pk_t ‖ pk_a ‖ u_T ‖ v_T ‖ u ‖ v_t ‖ v_f ‖ v_a` (83,072 B). The proofSystemId sits at statement bytes 32..63 and,
as in pqz-core, is only hashed (the precompile dispatches on it).

**Proposed PQZH proofSystemId** (in the style of `pqz.h`'s `PQZ_PROOF_SYSTEM_ID`):
`keccak256("scaas/pqz/pqzh/stark-d1-goldilocks5-fri-keccak256-zk/v1")` =
`0xaa1f92ddc5763201c2582c8387bd6513842e52779310d6bcf39a7fec99284304` (`rel::PQZH_PROOF_SYSTEM_ID`). Status:
proposal; the FRI parameters (regime, blowup, queries) are fixed per id, so the string has to name them (or the id
bumps) once the owner picks the regime.

Cross-check (`xcheck/run.sh`, `runs/s5-xcheck.txt`) [measured]: pqz-core built from this branch (= main's
`pqz_bench.c` `setup()`) against `client::setup_with(psid = PQZL's v2 id)`:

| Buffer | Bytes | SHA-256 (first 16 hex), C = Rust |
|---|---|---|
| `R_REG` statement | 16,480 | `191aaefa0841d7a0` |
| `R_REG` witness | 6,144 | `17c7a9f62fa77af1` |
| `R_TX` statement | 83,072 | `be45138690990f31` |
| `R_TX` witness | 12,416 | `258e15b72416daa6` |

PQZH's own statements differ only in bytes 32..63 (its id).

## 3. The EVM-friendly configuration (task 2), before → after

One configuration (`src/config.rs`, `src/enc.rs`), no fork:

| Item | Prototype | Now |
|---|---|---|
| Merkle leaf / node | Keccak-f sponge over little-endian `u64` lanes (vectorised) | `keccak256(be8(x₀) ‖ be8(x₁) ‖ …)` / `keccak256(l ‖ r)` (`BeKeccak`, scalar `sha3`) |
| Transcript seed | `SHAKE256(tag ‖ op ‖ be32(len) ‖ stmt)` | `keccak256(tag ‖ op ‖ be32(len) ‖ stmt)` |
| Challenger | Plonky3 `SerializingChallenger64` (little-endian words) | `BeChallenger`: the same Keccak-256 hash challenger, absorbing `be8` words and reading samples as big-endian `u64` |
| Proof encoding | postcard (field elements fixed 8-byte LE, digests `[u64; 4]` varints ≈ 38 B) | `enc.rs`: postcard's layout, field elements `be8` (canonical check kept), digests raw 32 B |
| `NTT(A)`, selectors, bus keys | full-height periodic columns | preprocessed tree (root a verifier constant); `Poly` width 72 → 68, `Mv` 12 → 10 |
| Statement data in `Mv` | in every coefficient column (targets) | one target row per output: one full-height periodic target column (+ 3 statement-product coefficient columns for `R_TX`) |

The preprocessed tree is committed with a fixed setup configuration (seed and, under the hiding PCS, salts fixed), so
prover and verifier get the same root; the verifier computes it once per (op, parameters) and keeps it, as a
precompile would hard-code it. The prover rebuilds it per proof here (a wallet or node would keep it).

Default parameters (Goldilocks², blowup 16, 28 queries, 16 grinding bits, arity 8, plain), n = 5 proofs, 100 honest
and 120 mutated verifies [measured]:

| `R_TX` | Prototype layout + config (`runs/t1-base-default.jsonl`) | + Keccak-256 / BE (`runs/t2-keccak256-be-default.jsonl`) | + preprocessed (`runs/t3-preprocessed-default.jsonl`) |
|---|---|---|---|
| Proof | 143,128 B | 128,335 B | 143,704 B |
| Worst case over query positions [estimate, §4] | 159,144 B | 141,575 B | 158,604 B |
| Prove p50 | 2.64 s | 3.68 s | 4.41 s |
| Prove peak heap / max RSS | 448.5 MB / 466 MB | 448.5 MB / 467 MB | 526.6 MB / 546 MB |
| Verify honest p50 / p99 | 8.52 / 11.78 ms | 8.58 / 10.80 ms | 7.65 / 9.81 ms (first verify 730 ms: setup) |
| Verify adversarial p99 | 4.69 ms | 5.47 ms | 6.66 ms |
| `R_REG` proof / prove | 110,501 B / 1.22 s | 99,859 B / 1.63 s | 112,796 B / 1.92 s |

- Keccak-256 digests are 32 B against ≈ 38 B of varints: −10 % bytes. Prove time +40 %: the Merkle hashing is now
  scalar Keccak-256 instead of Plonky3's vectorised Keccak-f [inference: the only change on the prover's hot path].
  A vectorised Keccak-256 leaf hasher (the same Keccak-f lanes with Keccak's padding) would recover most of it; not
  built.
- The preprocessed tree adds one opened tree per query (+15.4 KB for `R_TX`), and the per-proof commitment adds
  ≈ 0.7 s and 78 MB. The verifier no longer interpolates the full-height selector and `NTT(A)` columns, which takes
  its p50 from 8.6 to 7.7 ms.
- The statement still enters through full-height periodic columns (1 for `R_REG`, 4 for `R_TX`): an EVM verifier
  would still pay O(trace height) for those. The Horner-fingerprint binding of `pqzh-solidity-verifier.md` §6 is the
  remaining step for a Solidity verifier (not in the owner's list, not built; the owner decided no Solidity PQZH
  verifier for now).

## 4. ZK + Goldilocks⁵ at 128 bits (task 3)

**Built**: `Params { zk: true, ext5: true }` = `HidingFriPcs` with Goldilocks⁵ challenges (`Zk5Config`). Plonky3 needs
at least as many random codewords as the extension degree (5, was 4) and a masking budget of
`2 · (queries + extension degree · 2 points)` rows per committed table, which sets the `Digit` table to 256 rows at
57–75 queries (was 128). Tests (`runs/t3-tests.txt`): attacks 7/7, smoke incl. `zk_honest_and_hiding` 2/2.

**Soundness** [model, `runs/t4-model-ext5-zk.jsonl`, `-pow24.jsonl`]: shape `R_TX` 151 constraints, degree 3,
8 quotient chunks (blowup ≥ 8), 795 batched functions, committed domain 2^16; `R_REG` 2^15, 488. Queries for 128 bits
at FRI arity 8 (the same counts as plain mode in the prototype; ZK does not change them):

| Blowup | Proven, 16 / 24 grinding bits | Conjectured, 16 / 24 | Binding term at the target |
|---|---|---|---|
| 8 | 75 / 70 | 38 / 35 | Keccak-256 collision (128) |
| 16 | 57 / 53 | 29 / 27 | same |
| 32 | 45 / 42 | 23 / 21 | same |

**Measured** on Plonky3 0.8.0 before the upgrade of §7 (repeat on 0.9.0-rc.1 for conjectured blowup 16: 344,239 B,
23.2 s, verify p99 16.1 ms, `runs/t9-p3-0.9-zk5-conj-b4-q29.jsonl`) (`runs/t6-zk5-<regime>-b<log blowup>-q<queries>.jsonl`, wasm `…-wasm.jsonl`; n = 3 proofs, 100 honest
verifies, 12 mutation kinds × 10; 16 grinding bits, arity 8, cap 0):

| Relation | Regime | Blowup / queries | Proof B | Worst case B [estimate] | Prove p50 | Peak heap / max RSS | Verify p50 / p99 honest | Verify p99 adversarial | Accepted / panics | wasm32 verify p50 / p99, memory |
|---|---|---|---|---|---|---|---|---|---|---|
| `R_REG` | proven | 8 / 75 | 573,972 | 626,481 | 5.31 s | 749 MB | 10.5 / 14.9 ms | 8.0 ms | 0 / 0 of 120 | 15.6 / 19.4 ms, 69 MiB |
| `R_REG` | proven | 16 / 57 | 468,231 | 512,730 | 10.37 s | 1,486 MB | 8.7 / 11.1 ms | 6.1 ms | 0 / 0 | 14.0 / 16.5 ms, 131 MiB |
| `R_REG` | conjectured | 8 / 38 | 314,953 | 345,301 | 5.33 s | 749 MB | 7.0 / 8.8 ms | 4.4 ms | 0 / 0 | 11.6 / 15.4 ms, 68 MiB |
| `R_REG` | conjectured | 16 / 29 | 255,906 | 277,148 | 10.50 s | 1,486 MB | 6.5 / 10.9 ms | 4.5 ms | 0 / 0 | 10.7 / 12.7 ms, 130 MiB |
| `R_TX` | proven | 8 / 75 | 776,128 | 836,578 | 10.37 s | 1,424 MB / 1.47 GB | 16.4 / 25.9 ms | 11.8 ms | 0 / 0 | 26.9 / 30.8 ms, 141 MiB |
| `R_TX` | proven | 16 / 57 | 622,448 | 672,305 | 20.44 s | 2,824 MB / 2.90 GB | 14.6 / 19.1 ms | 9.3 ms | 0 / 0 | 24.3 / 28.7 ms, 260 MiB |
| `R_TX` | conjectured | 8 / 38 | 418,983 | 452,659 | 10.39 s | 1,420 MB / 1.47 GB | 12.8 / 16.5 ms | 7.7 ms | 0 / 0 | 21.6 / 29.3 ms, 140 MiB |
| `R_TX` | conjectured | 16 / 29 | 340,431 | 364,602 | 20.25 s | 2,816 MB / 2.89 GB | 11.6 / 15.5 ms | 6.8 ms | 0 / 0 | 20.2 / 24.1 ms, 258 MiB |

Single runs [probe] (`runs/t5-probe-b*-q*.jsonl`, `-time.txt`, `runs/t5-probe.log`; `runs/t8-pow24-*.jsonl`):

| Setting | `R_REG` B / prove | `R_TX` B / prove | Peak heap `R_TX` | Note |
|---|---|---|---|---|
| proven, blowup 32 / 45 q | 393,427 / 21.5 s | 518,000 / 184.4 s | 5,608 MB | over the 4 GB cap: swapped (process max RSS 4.19 GB); the time is swap-bound, not CPU |
| conjectured, blowup 32 / 23 q | 216,488 / 21.2 s | 289,823 / 145.0 s | 5,608 MB | same |
| proven, blowup 8 / 70 q, 24 bits | 546,633 / 6.6 s | 729,832 / 12.7 s | 1,424 MB | grinding 2^24 hashes adds 1–11 s (random) |
| proven, blowup 16 / 53 q, 24 bits | 438,123 / 12.3 s | 587,152 / 23.2 s | 2,816 MB | |
| conjectured, blowup 8 / 35 q, 24 bits | 293,500 / 8.7 s | 387,775 / 21.1 s | 1,420 MB | |
| conjectured, blowup 16 / 27 q, 24 bits | 242,308 / 20.8 s | 323,487 / 22.6 s | 2,816 MB | |

- **Prover**: ZK doubles the committed domain, and the masks and quotient chunks are extension-heavy: `R_TX` needs
  1.42 GB at blowup 8, 2.82 GB at 16, 5.6 GB at 32 [measured]. Native-only proving (owner, 2026-10-13) is needed: a
  4 GiB wasm32 address space would hold blowup 8 at most [inference].
- **Verifier**: well under the 50 ms p99 limit everywhere, native and wasm32 (wasm: 0 of 960 mutated inputs accepted,
  `fails: 0` in each `-wasm.jsonl`); verifying in wasm needs 68–260 MiB of
  linear memory (the preprocessed commitment is recomputed once per op in that process; a precompile keeps the root
  as a constant) [measured].
- **Worst case** (`runs/worstcase.py`, `runs/t6-worstcase.jsonl`) [estimate]: each Merkle multiproof part scaled
  by (no-sharing sibling count) / (mean pruned count over 200 random query sets at the tree's depth): +7–10 %. A proof
  limit has to hold that bound, not a sample.
- Against the ZK prototype (Goldilocks², ≈ 99 bits, blowup 16 / 28 queries): `R_TX` 253,294 B, 10.3 s, 2.0 GB
  (`pqzh-prototype.md` §6). 128-bit conjectured costs +34 % bytes and 2× time at the same blowup; 128-bit proven
  2.5× bytes.

## 5. Merkle caps (task 4)

`runs/t7-cap-zk5-b<lb>-q<q>-cap<h>.jsonl` [measured, one proof each; the cap-0 sizes differ slightly from §4 because
the prover randomness differs]:

| `R_TX` (`R_REG`), ZK, Goldilocks⁵ | cap 0 | cap 4 | cap 6 | cap 8 |
|---|---|---|---|---|
| proven, blowup 8 / 75 q | 778,560 (582,484) | 783,968 (583,252) | 790,080 (587,764) | 822,376 (617,148) |
| proven, blowup 16 / 57 q | 623,536 (466,343) | 628,880 (471,143) | 636,688 (483,398) | 670,137 (510,927) |
| conjectured, blowup 8 / 38 q | 421,383 (313,897) | 424,071 (315,753) | 435,719 (325,193) | 466,255 (360,400) |
| conjectured, blowup 16 / 29 q | 337,615 (256,770) | 340,783 (263,202) | 355,023 (271,586) | 396,728 (303,978) |

Caps grow the proof at every setting [measured]. Plonky3 0.8's openings are pruned multiproofs: with 29–75 queries
the top ≈ log₂(queries) levels of each tree are already shared and sent once, so a cap removes almost nothing from
the paths while it puts 2^h digests per tree (5 input trees + 5–6 FRI layers) into the commitments [inference from
the breakdowns]. Caps help unpruned per-query paths (the Solidity skeleton's layout, `pqzh-solidity-verifier.md` §4),
not this encoding.

## 6. Goldilocks² with ZK

`runs/t4-model-ext2-zk.jsonl` [model]: `R_TX` ceiling 99.9 / 98.9 / 97.9 bits at blowup 8 / 16 / 32 in both regimes,
binding term `batch-combination` (the opening-batching round: 567 batched functions over a 2^20–2^21 point domain,
one challenge from a 2^128 field); `R_REG` 101.4 / 100.4 / 99.4. No query count reaches 128 over Goldilocks² with
FRI, as in the prototype's plain mode (`pqzh-prototype.md` §7).

## 7. WHIR (task 5)

**Upgrade.** Plonky3 0.8.0 → 0.9.0-rc.1 is its own commit (`2e1788c`, revertable) and needed no source change:
tests pass (`runs/t9-p3-0.9-tests.txt`), default-parameter proofs keep their sizes (`R_TX` 143,704 B), prove
4.41 → 4.78 s, verify p99 9.8 → 11.6 ms (`runs/t9-p3-0.9-default.jsonl`); ZK + Goldilocks⁵ conjectured blowup 16:
`R_TX` 344,239 B, 23.2 s, 2.82 GB, verify p99 16.1 ms, 0 of 240 mutated accepted (`runs/t9-p3-0.9-zk5-conj-b4-q29.jsonl`);
`p3-security` 0.9 gives the same 128-bit query counts (`runs/t9-p3-0.9-model-ext5-zk.jsonl`); the wasm32 module
builds (`runs/t15-wasm-build-0.9.txt`); tests after the WHIR driver's AIR-bound change pass (`runs/t14-tests.txt`)
[measured].

**Hiding WHIR does not plug into the batch STARK** (0.9.0-rc.1, from the sources):

1. `p3-uni-stark` / `p3-batch-stark` take `StarkGenericConfig::Pcs: UnivariateStarkPcs` (p3-commit
   `pcs/univariate.rs`): a univariate PCS over two-adic cosets that the prover asks for LDEs and quotient-domain
   evaluations (`get_evaluations_on_domain`, `commit_quotient`, `get_quotient_ldes`, `commit_ldes`), opens at the
   out-of-domain points ζ and ζ·g, and, in ZK mode, supplies the randomisation polynomial
   (`get_opt_randomization_poly_commitment`, `const ZK`).
2. `p3-whir` implements only `MultilinearPcs` (`WhirProver`, `pcs/adapter.rs`; `HidingWhirPcs`, `pcs/zk/adapter.rs`):
   commitments to multilinear polynomials opened at points of F^n through sumcheck. Neither implements
   `UnivariateStarkPcs`.
3. The Plonky3 prover that takes a multilinear PCS is `p3-multi-stark` (SuperSpartan-style zerocheck, LogUp by
   fractional GKR). It needs `PrescribedPointPcs`, which only the **non-hiding** `WhirProver` implements; and it is
   not zero-knowledge by its own statement ("Nothing this backend accepts hides anything, so no proof framed here is
   zero-knowledge", `src/contract/mod.rs`): its sumcheck and GKR round messages are sent unmasked.

So a ZK WHIR proof of PQZH has no Plonky3 path today. Two ways to build one [estimate of effort]:

- **WHIR under the batch STARK**: an adapter implementing `UnivariateStarkPcs` on HVZK-WHIR — commit the
  coefficient form of each column (WHIR's default code is the two-adic monomial RS code, so its codeword is the
  column's LDE), open at ζ through the univariate embedding point (ζ, ζ², ζ⁴, …), provide the quotient-domain
  evaluations and the randomisation polynomial. About 1–2 weeks plus a security review of the composition (the
  batch STARK's DEEP/quotient argument with a WHIR opening; ZK of the composition).
- **Masked multi-stark**: a ZK variant of `p3-multi-stark` (masked zerocheck and GKR rounds, as HVZK-WHIR does for
  its own sumchecks) with `HidingWhirPcs` given `PrescribedPointPcs`. Larger: weeks, and it is a protocol change.

**What was measurable: non-hiding WHIR** through `p3-multi-stark` (`src/bin/pqzh_whir.rs`, the same AIRs, Keccak-256
Merkle tree and challenger as §3), Goldilocks² and Goldilocks⁵, 128-bit target under the Johnson bound
(`SecurityAssumption::JohnsonBound`; the capacity bound is the conjecture ePrint 2025/2046 disproved and is not
used). These are **not ZK** numbers: a lower bound for what a hiding WHIR proof would cost.

Bits are `p3-multi-stark`'s `security_report`: the union bound over every term (WHIR opening of the main and the
preprocessed commitment, Keccak-256 collision 128, LogUp fingerprint, fractional GKR, constraint sumcheck and
batching). With a 128-bit collision term in the sum the composed bound cannot reach 128.0; a per-term target of 128
gives 125.1–125.4 bits composed, 130 gives 126.6–126.9 (binding: the collision term) [model,
`runs/t10-whir-sweep.jsonl`]. The FRI numbers of §4 are `p3-security`'s report, whose figure is the weakest term
(128.0 = the collision term); the two are not the same yardstick: WHIR's 125.2 is a sum, FRI's 128 a minimum.

Non-hiding WHIR, Goldilocks⁵, Johnson bound, per-term target 128, fold 4, 16 grinding bits
(`runs/t12-whir-ext5-r<rate>.jsonl`, `-time.txt`; n = 3 proofs, 100 honest + 120 mutated verifies; rate 5 a single
run from `runs/t11-whir-sweep2.jsonl`) [measured]:

| Relation | Starting rate (blowup) | Bits composed (binding) | Proof B | Prove p50 | Peak heap / max RSS | Verify p50 / p99 honest | Verify p99 adversarial | Accepted |
|---|---|---|---|---|---|---|---|---|
| `R_REG` | 2 (4) | 125.4 (WHIR opening, main) | 301,298 | 1.75 s | 141 MB | 7.5 / 11.7 ms | 6.9 ms | 0 / 120 |
| `R_REG` | 3 (8) | 125.4 | 256,102 | 2.90 s | 280 MB | 6.6 / 7.6 ms | 6.0 ms | 0 / 120 |
| `R_REG` | 4 (16) | 125.4 | 228,651 | 5.45 s | 560 MB | 6.5 / 8.2 ms | 6.3 ms | 0 / 120 |
| `R_REG` | 5 (32) [probe] | 125.3 | 209,446 | 10.5 s | 1,120 MB | 6.4 ms (n = 3) | — | 0 / 12 |
| `R_TX` | 2 (4) | 125.2 | 336,036 | 3.57 s | 284 MB / 398 MB | 15.2 / 24.5 ms | 19.0 ms | 0 / 120 |
| `R_TX` | 3 (8) | 125.2 | 286,646 | 6.02 s | 564 MB / 680 MB | 13.7 / 18.6 ms | 12.6 ms | 0 / 120 |
| `R_TX` | 4 (16) | 125.3 | 257,530 | 11.43 s | 1,123 MB / 1.31 GB | 13.6 / 20.1 ms | 13.8 ms | 0 / 120 |
| `R_TX` | 5 (32) [probe] | 125.2 | 238,932 | 22.2 s | 2,243 MB | 13.5 ms (n = 3) | — | 0 / 12 |

Folding factors 6 and 8 (`runs/t11-whir-sweep2.jsonl`, `.err`): `R_REG` grows to 333–873 KB, and `R_TX` is refused by
`p3-multi-stark` ("trace arity is outside the supported range": the fold is the per-table padding floor, and the
16-row `Digit` table is below it) [measured]. Fold 4 is the best here.

**The same regime with FRI, this configuration, not ZK** (Goldilocks⁵, 128 bits by `p3-security`, one proof each,
`runs/t13-fri-plain5-*.jsonl`) [probe]: proven `R_TX` 358,874 B at blowup 16 (5.0 s, 673 MB), 309,539 B at blowup 32
(10.0 s, 1.33 GB); conjectured 201,698 B (blowup 16) / 175,126 B (blowup 32). **WHIR (proven, Johnson) is ≈ 17–20 %
smaller than proven FRI at the same prover memory** (`R_TX` 257,530 B at rate 4 / 1.12 GB against 309,539 B at blowup
32 / 1.33 GB), still larger than conjectured FRI, and far from the 60–110 KB hoped for in `pqzh-design.md` §5.5
[inference]. Verify is similar (13.6 ms p50 `R_TX`).

**Goldilocks² with WHIR**: the 128-bit target is out of reach the same way as with FRI, with a different binding term
(`runs/t10-whir-sweep.err`, `runs/t11-whir-sweep2.err`, `runs/t12-whir-ext2-*-time.txt`) [model]: WHIR refuses the
configuration because the grinding needed per phase exceeds the budget — 42–50 bits for a 128-bit per-term target
(rate 1–4), 18 for 100, 28 for 110, 33 for 115, 38 for 120 (rate 3). The phase error it grinds against is the
Johnson-radius proximity-gap error of a fold, ≈ n·m³ / |F| for a 2^128 field (p3-security `assumption.rs`, [DKT26]
Thm 5.12). At what grinding allows [measured, `runs/t13-whir-ext2-r3-*.jsonl`, n = 3 / 100 / 120]:

| Goldilocks², rate 3 | Bits composed | Weakest terms | `R_TX` proof | Prove | Verify p99 |
|---|---|---|---|---|---|
| target 96, 16 grinding bits | 90.9 (`R_REG` 91.1) | WHIR opening 96.0 (main / preprocessed), LogUp fingerprint 95.4 | 152,186 B (`R_REG` 135,759) | 3.12 s | 14.3 ms |
| target 100, 20 grinding bits | 94.2 (`R_REG` 94.7) | LogUp fingerprint 95.4, WHIR openings 96.0, fractional GKR 105.6, constraint sumcheck 107.9 | 152,986 B (`R_REG` 135,935) | 5.30 s | 14.7 ms |

So over Goldilocks² WHIR's composed bound sits at ≈ 91–95 bits, against FRI's ≈ 98–101 (§6): **the same kind of cap,
a little lower**, bound by the WHIR fold's proximity-gap term (grinding-limited) and by the LogUp fingerprint
(≈ 95.4 bits for `R_TX`, field-size-limited, no grinding) [inference from the term lists]. Goldilocks⁵ removes both
(LogUp 285 bits, the WHIR openings at their target).

## 8. What was not done

- **Blowup 32 under ZK**: needs ≈ 5.6 GB for `R_TX`, over the machine-wide 4 GB cap; only the swapped single probe
  above. On a larger prover it would give the smallest FRI proofs (518 KB proven / 290 KB conjectured `R_TX`).
- **wasm32 proving**: native-only (owner); `R_TX` ZK needs 1.4–2.8 GB.
- **Vectorised Keccak-256 Merkle hashing** (would recover most of the +40 % prove time of §3): not built.
- **Horner statement binding** (removes the last full-height periodic columns, needed only for a Solidity verifier):
  not built.
- **ZK with WHIR**: no Plonky3 path (§7); only non-hiding WHIR measured. Goldilocks² WHIR at 128 bits: refused by
  WHIR's own configuration check (42–50 grinding bits), so no proof exists to measure.
- **wasm32 verify of WHIR proofs**: not built (the WHIR driver is native only); native verify is 13.6 ms p50 `R_TX`.

## 9. Open questions for the owner

1. **Soundness regime** (still open from the prototype): with ZK over Goldilocks⁵, `R_TX` is ≈ 340–365 KB
   conjectured or ≈ 620–670 KB proven (blowup 16, worst case included). Neither fits 160 KB or the precompile's
   `MAX_INPUT` of 262,144 B. Recommendation: decide the regime together with the proof limit; if a precompile input
   ≥ 400 KB is acceptable, conjectured (random words, ePrint 2025/2010) at blowup 16 is the practical point; proven
   needs ≈ 700 KB inputs (or WHIR inside a ZK multilinear prover, §7).
2. **Proof limit / `MAX_INPUT`** for PQZH: set from the worst-case column of §4, not the samples.
3. **Prover hardware**: blowup 16 needs ≈ 2.9 GB RSS for `R_TX`, blowup 32 ≈ 5.6 GB. Is a 4 GB native prover the
   target (then blowup 16), or more?
4. **proofSystemId** string of §2: accept, and name the final FRI parameters in it when the regime is chosen?
   Recommendation: yes; bump `/v1` → `/v2` once the parameters are fixed.
5. **WHIR**: build a ZK WHIR path (a `UnivariateStarkPcs` adapter over HVZK-WHIR, ≈ 1–2 weeks plus review, or a
   masked multi-stark, weeks)? The non-ZK lower bound saves ≈ 17 % against proven FRI. Recommendation: not now; the
   proof stays ≈ 250–340 KB either way, so it does not change the limit question of (1)–(2). Revisit if Plonky3 ships a
   ZK multilinear prover.
6. **Keep the Plonky3 0.9.0-rc.1 upgrade** (`2e1788c`)? It is a release candidate; nothing in the FRI path needs it.
   Recommendation: keep it on this branch for the WHIR driver, pin the final 0.9.0 before any merge to main, or revert
   `2e1788c` and the WHIR driver commit if the branch should stay on 0.8.0.

## 10. Reruns

From `pqz-core/pqzh/`, each heavy command alone under the machine lock:

```sh
scripts/capped xcheck/run.sh > runs/s5-xcheck.txt                                       # §2
scripts/capped runs/bench.sh t3-preprocessed-default --np 5 --nv 100 --nadv 10          # §3 (t1 / t2: earlier commits)
scripts/capped sh -c 'target/release/pqzh_security --ext 5 --zk > runs/t4-model-ext5-zk.jsonl'   # §4, §6
scripts/capped runs/t5-probe.sh                                                         # §4 single runs incl. blowup 32
scripts/capped runs/t6-zk5.sh > runs/t6-zk5.log                                         # §4 benches, wasm, §5 caps
scripts/capped runs/t8-pow24.sh > runs/t8-pow24.log                                     # §4 24 grinding bits
scripts/capped runs/t9-p3-0.9.sh > runs/t9-p3-0.9.log                                   # §7 upgrade check
scripts/capped runs/t10-whir-sweep.sh; scripts/capped runs/t11-whir-sweep2.sh            # §7 WHIR sweeps
scripts/capped runs/t12-whir-bench.sh > runs/t12-whir-bench.log                          # §7 WHIR Goldilocks^5
scripts/capped runs/t13-whir-ext2-fri-plain.sh > runs/t13-whir-ext2-fri-plain.log        # §7 Goldilocks^2, FRI plain
python3 runs/summ.py runs/t6-*.jsonl; python3 runs/whir-summ.py runs/t12-*.jsonl
python3 runs/worstcase.py runs/t6-zk5-conj-b4-q29.jsonl 29 4 5 1
```

`runs/` also holds the trial runs of this step: `t1`–`t3` (§3), `t3-tests.txt`, `t4-model-*` (§4, §6), `t5-probe*`
(§4), `t6-*` (§4), `t6-worstcase.jsonl`, `t7-cap-*` (§5), `t8-pow24-*` (§4), `t9-*` (§7), `t10`–`t13` (§7),
`t14-tests.txt` (tests after the AIR bound change for the WHIR driver).
