> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH design study: the hash-based proof kind of PQ Zether (P6-PQZH, E-S1H)

Written 2026-10-13 at the owner's request ("Giao phần thiết kế PQZH luôn"; TODO P6-PQZH, E-S1H). PQZH is the second
proof system of PQ Zether next to PQZL (the lattice proof in `pqz-core`): the same statements, encryption and state,
proved by an independent proof system that rests only on hash assumptions. This is a paper design with counting
scripts; **nothing was built or measured for PQZH**, and **no decision is recorded here**. The prototype and its
measurements come later (§7).

**[estimate]** marks a number computed here from counts or a model (script `pqz-core/pqzh/pqzh_count.py`, output
`pqz-core/pqzh/counts.txt`). **[measured by others]** marks a published number, with its source and the date it was
read (§9). **[inference]** marks a conclusion drawn here. Numbers for PQZL come from the earlier notes
(`pqz-core-e-s1.md`, `pqz-specialised-verifier.md`).

## 1. Result

**A STARK over the 64-bit Goldilocks field fits PQZ's arithmetic best: every mod-q identity of the five relations
stays below 2^51.7 as an integer once the witness is range-checked, so it holds over Goldilocks with one quotient
witness per coefficient and no limbs, and X^64 + 1 splits in Goldilocks, so ring products are pointwise in the proof
field [estimate, checked by the script's self-test].** `R_TX` then needs ≈ 12.5 k range lookups and ≈ 139 k NTT-domain
products in the challenge-free design (D1), or ≈ 17 k extension MACs when the ring identities are checked at one
random point (D2) [estimate]. That is small for a STARK: prove time is expected well under the 6 s limit and verify
in single-digit milliseconds. **The proof is the problem: ≈ 105–125 KB in the conjectured FRI regime and ≈ 195–225 KB
in the provable (Johnson-bound) regime at 128 bits with FRI folding arity 8–16 (167–336 KB with arity 2), against
the 96 KB kill line of CTR-PQZ-09 [estimate].** A WHIR
commitment may bring it near or under 96 KB [inference]; Ligero over F_q is natural for the arithmetic but its
verifier is ≈ 40–130 ms for `R_TX` [estimate].

| `R_TX`, per backend | Proof | Prove, desktop native | Prove, wasm32 | Verify, native | Verify gas (0.12 M/ms) | Zero knowledge | Soundness basis |
|---|---|---|---|---|---|---|---|
| **Plonky3, FRI, Goldilocks, Keccak** (recommended) | 105–125 KB conjectured / 195–225 KB provable [estimate] | 0.1–0.3 s (D2), 0.2–1.0 s (D1) [estimate] | 0.3–1.3 s (D2), 0.7–3.9 s (D1) [estimate] | 2–6 ms [estimate] | 0.25–0.7 M [estimate] | `HidingFriPcs` and the uni-STARK ZK path exist (docs, §9) — to confirm in the prototype | hash (random oracle) + FRI proximity; Goldilocks² = 128-bit field limits the provable regime [inference] |
| Plonky3, FRI, KoalaBear | 124–147 KB / 232–266 KB [estimate] | 0.1–0.35 s (D2), 0.6–2.3 s (D1) [estimate] | 0.3–1.4 s (D2), 1.7–9 s (D1) [estimate] | 2–6 ms [estimate] | 0.25–0.7 M | as above | as above; KoalaBear⁴ ≈ 2^124 is below 128 bits even before FRI terms [inference] |
| Stwo, Circle STARK, M31 | ≈ KoalaBear's [inference] | ≈ 2× KoalaBear's D1 cells (X^64 + 1 splits only over CM31) [estimate] | no browser numbers found | a few ms [inference] | — | not confirmed (§5.3) | as FRI |
| Ligero over F_q (own code) | 137–166 KB (Johnson) / 261–283 KB (classic) [estimate] | tens of ms [estimate] | < 1 s [estimate] | **43–131 ms** [estimate] | 5–16 M | built in (masked rows) | hash + Reed–Solomon proximity, proven bounds |
| WHIR as the commitment (Plonky3 `WhirPcs`) | ≈ 60–110 KB [inference] | ≈ FRI's | ≈ FRI's | < 2 ms [inference] | < 0.25 M | `HidingWhirPcs` (docs) | as FRI (Johnson or conjectured) |
| Binius64 | not estimated: excluded (§5.5) | | | | | not zero-knowledge (§9) | |

**Against the limits** [inference]:

| Limit | Value | PQZH (Plonky3, Goldilocks) |
|---|---|---|
| CTR-PQZ-09 proof | ≤ 96 KB | **likely missed** with FRI (105–225 KB); maybe met with WHIR |
| CTR-PQZ-09 verify | ≤ 50 ms p99 adversarial | met with a wide margin (2–6 ms) |
| CTR-PQZ-09 prove | ≤ 6 s desktop native | met (≤ 1 s) |
| CTR-PQZ-18 desktop browser prove | ≤ 5 s p95 | likely met (≤ 1.3 s D2, ≤ 3.9 s D1) |
| CTR-PQZ-18 WASM memory | ≤ 128 MiB budget, 256 MiB hard | **at risk** for D1 (≈ 200 MB at blowup 8 in the model); D2 with small tables and blowup ≤ 8 fits [estimate] |
| CTR-PQZ-18 module size | ≤ 1.0 MB gzip | unknown; Plonky3 prover + verifier in Rust, to measure |
| Precompile `MAX_INPUT` (§9.1) | 262,144 B | `R_TX` proof ≤ 179,067 B (statement 83,072 B + 5) |
| EIP-7825 with +16 inline credits (CTR-PQZ-11) | ≤ 16,777,216 gas | proof ≤ ≈ 175 KB at the calldata floor [estimate] |

Alternative limits the owner could set for a PQZH kind (§5.6): proof ≤ 160 KB (fits the precompile input and the
+16 inline case without other changes), or ≤ 128 KB to keep a margin; verify and prove limits unchanged.

**Recommendation (§7):** prototype on Plonky3 with Goldilocks, FRI and Keccak, design D1 first (stock framework
features), `R_REG` then `R_TX`; then D2, the parameter sweep (blowup, arity, regime) and a WHIR run for the proof size.

## 2. What PQZH proves

The same five statements as PQZL, byte for byte the same statement layouts (pq-zether.md §7.2, §7.4, §7.5, §7.7,
§7.9), over the same MLWE ciphertexts, keys and state. Only the proof bytes, the verifier and the `proofSystemId` in
the statement prefix differ. The relations below are those of `pqz_rel.c` on branch `pqz-rel3` (`build_reg`,
`build_debit`, `build_ds`, `build_dr`).

| op | Relation | Equations (all mod q unless marked) | Short witness (ℓ2 bound) | Other witness |
|---|---|---|---|---|
| 3 `OP_REGISTER` | `R_REG` | `pk = A s + e` | `s` (36), `e` (164): 4,096 coefficients | — (the message is absorbed into the transcript only) |
| 1 `OP_TRANSFER` | `R_TX` | rows 1 `pk_f = A s_f + e_f`; 2 `u = A^T r + e1`; 3–5 `v_x[i] = (pk_x^T r)[i] + e2_x[i] + Δ·d_i` (x = t, f with `d'`, a); 6 `v_T[i] − (u_T^T s_f)[i] = Δ·M_i + e_T[i]`; 7 over Z `M_i + c_{i−1} = d'_i + d_i + f_i + 16 c_i` | `s_f`, `r` (36), `e_f`, `e1` (164), `e2_t/f/a` (64, 16 coefficients each): 8,240 | digits `d`, `d'` (4 bits), `M` (14), carries `c + 64` (11), `e_T + 2^24` (25) |
| 2 `OP_BURN` (REFRESH) | `R_BURN` | `R_TX` rows 1, 2, 4, 6, 7 with `d = digits(amount)` public | `s_f, e_f, r, e1, e2_f`: 8,208 | `d'`, `M`, `c`, `e_T` |
| 4 `OP_DISCLOSE_SENDER` | `R_DS` | `u = A^T r + e1`; `v[i] = (pk^T r)[i] + e2[i] + Δ·d_i`, `d` public | `r`, `e1`, `e2`: 4,112 | — |
| 5 `OP_DISCLOSE_RECEIVER` (AUDITOR) | `R_DR` | `pk = A s + e`; `v[i] − (u^T s)[i] = Δ·d_i + e'_i`, `d` public | `s`, `e`: 4,096 | `e' + 2^24` (25 bits) |

The norms are exact ℓ2 bounds (`‖s‖ ≤ 36` …) as in PQZL, so the noise budget, `K_MAX` and the uniqueness argument
of pq-zether.md §4.3 carry over unchanged. A hash-based proof has no extraction slack on the norms (they are checked
exactly in the circuit), so §4.3's "γ > 1" clause does not apply [inference].

**What stays shared** (pq-zether.md, `pqz-proof-alternatives.md` §6): MLWE encryption and its parameters, the state
and contract checks, `pqz-mlwe` keys, disclosure semantics, the client wallet and decryption. Privacy of balances
rests on MLWE under both kinds; PQZH gives the soundness of transfers (no mint, no overspend) a second, hash-only
foundation.

## 3. Arithmetisation

### 3.1 Mod-q identities as bounded integer identities

Every mod-q equation is rewritten as an integer equation with a quotient witness: for row 1,
`(A s)_k + e_k − pk_k = q·t_k` over Z for each of the 2,048 coefficients k, with the negacyclic product taken over
Z[X]/(X^64 + 1). With A and pk centred (`|a| ≤ (q−1)/2 < 2^41`) and the exact ℓ2 bound giving
`‖s‖₁ ≤ √2048 · 36 = 1,629`, the left side is below 2^51.67 in absolute value and `|t_k| ≤ 816` (11 bits signed)
[estimate; `bounds()` in the script]. Rows 3–6 reach the same size (`Δ·M` adds 2^40). Row 7 is over Z with every term
below 2^15 and needs no quotient. If every witness value is range-checked, the integer identity has no room to wrap in
a field with `p/2 > 2^52`; so checking it in the proof field proves it over Z, hence mod q.

| Field | `p` | Fits a 2^52 identity? | Representation of a coefficient mod q | X^64 + 1 splits? |
|---|---|---|---|---|
| Goldilocks | 2^64 − 2^32 + 1 | yes (`p/2 ≈ 2^63`) | one element; one quotient per identity | yes (`128 | p − 1`) |
| KoalaBear / BabyBear | 2^31 − 2^24 + 1 / 2^31 − 2^27 + 1 | no | 3 limbs of 14 bits; per limb, the sums `Σ a_m·s` stay below 2^25.3 [estimate], then a carry chain (2 carries per coefficient) | yes |
| Mersenne-31 (Circle STARK) | 2^31 − 1 | no | as KoalaBear | only over the extension CM31 (`p − 1 = 2·(2^30 − 1)`), so every NTT-domain value is 2 elements and every product 3 base multiplications |
| Binary towers (Binius) | GF(2^k) | integers have to be built from bits or 64-bit words | MUL / AND constraints over 64-bit words | no multiplicative NTT for X^64 + 1 over Z |
| F_q itself (Ligero) | q = 2^42 − 215 | native: the mod-q equations are the field equations | one element, no quotient | — (linear constraints are free; see §3.6) |

The limbs cost three times the products, a carry chain per identity, and statement values that arrive as limbs. That is
why the 64-bit field is the better fit for this statement, against the general trend of STARK tooling towards 31-bit
fields [inference].

### 3.2 Ring products

`A·s` is 1,024 products in R_q, 4.2 M coefficient multiply-adds if done schoolbook. Two designs avoid that:

- **D1, challenge-free (NTT domain).** Because the integer product is below `p/2`, the identity
  `Σ_j A_ij s_j + e_i − pk_i − q t_i = 0` in Z[X]/(X^64 + 1) is equivalent to the same identity in
  F_p[X]/(X^64 + 1), and that to 64 pointwise identities after a 64-point negacyclic NTT over F_p. `Â = NTT(A)` is
  fixed at setup and goes into **preprocessed columns** (65,536 Goldilocks elements; three limb sets in 31-bit
  fields); `NTT(s_j)` and `NTT(e_i − pk_i − q t_i)` are computed in the trace (6 butterfly layers each). Per
  A-product: 65,536 pointwise products. The statement products of rows 3–6 (`pk^T r`, `u_T^T s_f`) take NTTs of the
  statement polynomials (32 each), 2,048 products and one inverse NTT for the 16 coefficients the row needs.
  Works with any AIR framework that has preprocessed columns and LogUp [inference].
- **D2, Schwartz–Zippel at one point.** After the witness is committed, the verifier draws ρ (extension field) and
  row weights γ_i. The trace holds, besides the witness, the quotient polynomials `W_i` of the reduction by X^64 + 1
  (63 free coefficients each) and evaluates the committed polynomials at ρ by Horner columns; the identity
  `Σ_i γ_i [Σ_j A_ij(ρ) s_j(ρ) + (e_i − q t_i)(ρ) − pk_i(ρ) − (ρ^64 + 1) W_i(ρ)] = 0` is checked once. The
  **verifier** computes the public side: `α_j = Σ_i γ_i A_ij(ρ)` (65,536 base × extension MACs, shared by A and
  A^T) and `Σ γ_i pk_i(ρ)` from the statement. A false identity passes with probability ≤ 127/|F_ext| per check. It
  needs constants derived from challenges inside the constraints, which Stwo's interaction phase provides and
  Plonky3 provides for LogUp; a generic hook may need framework work [inference]. Per A-product ≈ 8 k extension MACs
  instead of 65 k products; no preprocessed A.

### 3.3 Norms, ranges, digits

- **Range checks** by LogUp (Haböck, ePrint 2022/1530) into a preprocessed table: every short coefficient against
  its exact bound (`[−36, 36]`, `[−164, 164]`, `[−64, 64]`; this also keeps every sum below `p/2`), every quotient
  (11 bits signed) and carry, every digit-like value (`d`, `d'` 4 bits, `M` 14, `c + 64` 11, `e_T + 2^24` and
  `e' + 2^24` 25 bits as two lookups).
- **Exact ℓ2** by one square per coefficient, summed in the field (at most 2048 · 164² < 2^26, no wrap), and one
  range check on the slack `B² − ‖x‖² ≥ 0`. No binary decomposition of the norms is needed (PQZL proves them through
  917 bits and ℓ2 proofs).
- **Row 7** is checked directly as a field identity: every term is below 2^15, so it is an integer identity.
- **Digits of public values** (`fee`, `amount`) are computed by the verifier from the statement and enter as public
  values (a `fee < 2^64` can exceed the Goldilocks modulus, its 16 nibbles cannot).

### 3.4 Public data: A, the statement

A is global and fixed by `proofSystemId` (pq-zether.md §4.1): D1 commits `NTT(A)` once as preprocessed columns (the
root is a constant of the verifier), D2 lets the verifier evaluate A at ρ. The statement (up to 10,304 coefficients for
`R_TX`) enters the trace as a **public-memory table**: a LogUp argument whose public side
`Σ_k 1/(β − (k + α·stmt_k))` the verifier computes from the statement bytes, as Cairo binds its public memory. Cost
to the verifier: one batched inversion per statement word, ≈ 0.1–0.2 ms [estimate]; no statement data in the proof.

### 3.5 Counts per relation

From `counts.txt` [estimate]. "Main cells" counts witness values, squares, quotients and carries, NTT layer outputs
and both operand and accumulator cells of each pointwise product (a scalar layout, §3.7); "LogUp interactions" are
range lookups plus the bus between the NTT, product and public-memory tables.

| Relation | Short coeffs / ℓ2 norms | A-products / statement products (R_q) | mod-q identities | Statement coeffs |
|---|---|---|---|---|
| `R_REG` | 4,096 / 2 | 1,024 / 0 | 2,048 | 2,048 |
| `R_TX` | 8,240 / 7 | 2,048 / 128 | 4,160 | 10,304 |
| `R_BURN` | 8,208 / 5 | 2,048 / 64 | 4,128 | 6,176 |
| `R_DS` | 4,112 / 3 | 1,024 / 32 | 2,064 | 4,112 |
| `R_DR` | 4,096 / 2 | 1,024 / 32 | 2,064 | 4,112 |

| Relation | Goldilocks D1: lookups / NTT-domain products / NTTs / main cells / preprocessed / LogUp | Goldilocks D2: lookups / ext MACs / main cells / verifier MACs | KoalaBear D1: lookups / products / main cells | M31 D1: products / main cells |
|---|---|---|---|---|
| `R_REG` | 6,146 / 65,536 / 64 / 168 k / 131 k / 76 k | 6,146 / 8,160 / 14 k / 69 k | 10,242 / 196,608 / 463 k | 589,824 / 905 k |
| `R_TX` | 12,502 / 139,264 / 260 / 409 k / 197 k / 174 k | 12,502 / 16,828 / 29 k / 78 k | 20,822 / 417,792 / 1,146 k | 1,253,376 / 2,232 k |
| `R_BURN` | 12,420 / 135,168 / 194 / 372 k / 197 k / 162 k | 12,420 / 16,574 / 29 k / 74 k | 20,676 / 405,504 / 1,033 k | 1,216,512 / 2,018 k |
| `R_DS` | 6,179 / 67,584 / 97 / 187 k / 131 k / 82 k | 6,179 / 8,287 / 14 k / 71 k | 10,307 / 202,752 / 519 k | 608,256 / 1,012 k |
| `R_DR` | 6,194 / 67,584 / 97 / 187 k / 131 k / 82 k | 6,194 / 8,287 / 14 k / 71 k | 10,322 / 202,752 / 519 k | 608,256 / 1,012 k |

The preprocessed count includes a 2^16-row range table. In 31-bit fields the limbs triple the products and add
≈ 4 k carries per A-product; on M31 the CM31 NTT domain doubles the cells and triples the products again.

### 3.6 Ligero over F_q

Ligero commits the witness as rows of a Reed–Solomon-encoded matrix and checks linear constraints, quadratic
constraints and code membership with random combinations and a few opened columns (Ames, Hazay, Ishai,
Venkitasubramaniam; ePrint 2022/1608). Over F_q the mod-q rows are **linear constraints**: no quotients, no limbs,
no NTT in the circuit. What remains are the range checks, done by bits (no lookups in Ligero): 7–9 bits per short
coefficient so that the exact ℓ2 sum cannot wrap, the digit bits, and the slack bits. `R_TX`: 83,408 witness
elements of which ≈ 75 k bits, 12,502 linear and 75,168 quadratic constraints [estimate].

Two practical points [inference]: `q − 1 = 2^3 · 19 · 43 · 431 · 1,561,243`, so Reed–Solomon encoding over F_q needs
a mixed-radix FFT (domains of 2^a · 19 · 43 elements) or direct encoding; and a 42-bit field needs the random
combinations in an extension F_{q^3} or F_{q^4} (or repetitions) for 128 bits. The verifier is linear in the witness:
the linear test needs, per opened column, the verifier's own combination vector interpolated per row — `n · t`
extension multiplications, ≈ 4.6–14 M for `R_TX`, i.e. **≈ 43–131 ms** [estimate]. Cutting the ≈ 75 k range bits
(for example a JL-style projection bound) would shrink the verifier and the proof together, at the cost of
research-grade protocol work.

### 3.7 Trace layout and what it changes

A STARK proof opens one row of each committed matrix per query, so the opened width (columns) costs proof bytes on
every query while the height costs only Merkle depth; prover time and memory follow the cell count times the blowup.
The model therefore uses a tall, narrow scalar layout (2^16 rows for `R_TX` in Goldilocks, 7 main + 3 preprocessed
columns + 3 LogUp extension columns + 2 quotient extension columns) [estimate]. The Merkle trees then dominate prover
memory (four trees at 2^19 leaves ≈ 128 MB), so the prototype has to trade width against memory for the 128 MiB
browser budget [inference].

## 4. Statement binding and Fiat–Shamir

**No hash inside the circuit.** None of the five relations contains a hash: the statement is bound by the public-memory
argument (§3.4) and by absorbing its digest into the transcript; `R_REG`'s message is only absorbed. So the hash is a
free choice for the Merkle trees and the transcript, and only the verifier's speed and the audit matter [inference].

| Hash for Merkle + transcript | For | Against |
|---|---|---|
| **Keccak-256 / SHAKE256** (recommended) | standard, already in the precompile and the PQZ transcript (SHAKE256, pq-zether.md §5) and in the EVM; Plonky3 has Keccak Merkle trees and challengers | slower than an algebraic hash only if PQZH proofs are ever verified inside another proof |
| Poseidon2 over the proof field | cheap inside a STARK: needed for recursion / aggregation of many PQZH proofs | a newer algebraic hash; slower in the native verifier; a second hash family to audit |
| BLAKE3 | fastest native | not otherwise used in PQZ or the EVM |

Recursion is not planned (aggregation is the spec's LaBRADOR path, pq-zether.md §8), so Keccak/SHAKE [inference].

**Transcript.** As pq-zether.md §5 (strong Fiat–Shamir): the challenger is seeded with
`SHAKE256("SCAAS-PQZH-TRANSCRIPT-V1" ‖ u8(op) ‖ be32(len) ‖ stmt)` before any commitment, so `opTag ‖ proofSystemId`
(the first 64 bytes of every statement) and every statement byte are bound. The FRI parameters (blowup, queries,
grinding bits, arity), the field and extension, the AIR version and the preprocessed root are fixed per
`proofSystemId` and never read from the proof (the Least Authority audit of Plonky3 lists a verifier that trusted
prover-supplied proof parameters; §9). Grinding (proof-of-work) bits are part of the parameters and count towards
the 128-bit target.

## 5. Backends

### 5.1 Plonky3, FRI (Goldilocks or KoalaBear)

A toolkit of AIR STARK components (Polygon), MIT / Apache-2.0, fields Goldilocks, BabyBear, KoalaBear, Mersenne-31
and binary towers; FRI, STIR and WHIR commitments; LogUp lookups; a hiding FRI commitment (`HidingFriPcs`) and ZK
paths in the uni-STARK crates (repository docs, read 2026-10-13). Audited by Least Authority in 2024 (§9). Its
optimisation focus is the 31-bit fields; Goldilocks is supported with a quadratic extension. WebAssembly is not
documented as a target; the README mentions SIMD128 fallbacks, and the Miden team's migration plan requires a WASM
build with performance close to Winterfell's (§9). No published browser numbers were found.

Proof size from the FRI model (`counts.txt`), `R_TX`, Goldilocks, 128 bits with 16 grinding bits [estimate]:

| Blowup | FRI arity | Queries (conjectured / provable) | Proof, conjectured | Proof, provable (Johnson) | Verify hash permutations |
|---|---|---|---|---|---|
| 4 | 2 | 56 / 112 | 252 KB | 448 KB | 12 k / 25 k |
| 8 | 2 | 38 / 75 | 190 KB | 336 KB | 9 k / 18 k |
| 8 | 8 | 38 / 75 | 124 KB | 225 KB | 5 k / 10 k |
| 16 | 2 | 28 / 56 | 167 KB | 305 KB | 7 k / 14 k |
| 16 | 16 | 28 / 56 | 105 KB | 196 KB | 3.4 k / 6.9 k |

The proof hardly depends on the relation: `R_REG` is within 2–3 % of `R_TX` (`counts.txt`), because Merkle paths
and FRI layers dominate. Higher folding arity is what brings it down; whether Plonky3's FRI exposes an arity above 2
is to check [inference]. **Conjectured vs provable.** The conjectured column assumes FRI is sound up to list-decoding
capacity; Crites and Stewart (ePrint 2025/2046) disproved the up-to-capacity conjectures behind FRI, STIR and WHIR,
and the Ethereum Foundation asks zkEVMs for 128-bit **provable** security by the end of 2026 (≤ 300 KiB proofs) (§9).
The Johnson column is provable from the Reed–Solomon proximity gaps, but the proven error terms grow with the domain
size over the field size, so 128 provable bits want an extension field larger than Goldilocks² (2^128) or KoalaBear⁴
(≈ 2^124): a cubic Goldilocks or a larger KoalaBear extension [inference]; the exact count is a soundcalc-style
calculation for the prototype.

Prove and memory, `R_TX`, blowup 8, one thread [estimate from a throughput band derived from Polygon's > 2 M
Poseidon2 permutations/s on an M3 Max (§9), ≈ 300 trace columns per permutation and blowup 2 over ≈ 16 threads —
an inference, not a benchmark]: D1 Goldilocks 0.24–0.97 s native, 0.7–3.9 s wasm32; D2 Goldilocks 0.08–0.33 s native,
0.25–1.3 s wasm32. Prover memory 150–200 MB in the narrow layout, dominated by the Merkle trees; a wider, shorter
trace or blowup 4 brings it under 128 MiB [estimate].

Verify: 3.4–18 k Keccak permutations at ≈ 0.3 µs, plus the out-of-domain constraint check, the public-memory sum and
(D2) ≈ 78 k base × extension MACs: **≈ 2–6 ms native** [estimate], ≈ 0.25–0.7 M gas at 0.12 M gas/ms.

### 5.2 KoalaBear vs Goldilocks inside Plonky3

KoalaBear arithmetic is faster per element (31-bit SIMD lanes), but the limbs give ≈ 2.8× the cells in D1 and ≈ 2×
in D2, statement values arrive as three limbs, and the carry chains are extra constraints to get right. Net prove time
is similar in D2 and ≈ 2× in D1 by the model; the proof is ≈ 15–20 % larger (taller trace) [estimate]. Goldilocks keeps
the circuit closest to the relation, which is what a first prototype and its review need [inference].

### 5.3 Stwo (Circle STARK over M31)

StarkWare's prover, Apache-2.0; zkSecurity audited the Stwo-Cairo verifier in 2025 (§9). Circle FFTs work over M31,
but X^64 + 1 splits only over CM31, so the NTT-domain products cost three base multiplications and two cells, on top
of the three limbs: ≈ 2× KoalaBear's D1 cells [estimate]. Its interaction phase suits D2. No statement on a
zero-knowledge mode was found; the published S-two benchmarks (zkVM proofs, 96-bit security, July 2025) are not
comparable to a custom AIR (§9). Kept as a second choice if Plonky3's Goldilocks path disappoints [inference].

### 5.4 Ligero / Ligetron

No library fits as is: Ligetron (Wang, Hazay, Venkitasubramaniam, IEEE S&P 2024; `ligero-prover`, Apache-2.0) takes
WebAssembly programs as the circuit and needs WebGPU, with no fallback (repository, read 2026-10-13); it targets
general programs, not a custom field q. Ligero over F_q would be our own code: simplest arithmetic (§3.6), the
smallest prover, zero knowledge built in, proven soundness — and a verifier of ≈ 43–131 ms for `R_TX`, which misses or
grazes the 50 ms limit, and a proof of 137–283 KB for `R_TX` (103–220 KB for the smaller relations) [estimate]. It is the natural choice for a light prover with an
off-chain verifier, not for the precompile [inference].

### 5.5 WHIR, Binius

**WHIR** (Arnon, Chiesa, Fenzi, Yogev; ePrint 2024/1586) replaces FRI as the Reed–Solomon proximity test: for a
polynomial of degree 2^22 at 100 bits, 63 KiB and 360 µs verify (paper); a KoalaBear quintic-extension instance at
100 bits under the Johnson bound gave a 54,436-byte proof (ethresear.ch, 2026-05-19) [measured by others]. Plonky3
has a WHIR commitment with a hiding variant. Our trace is ≈ 2^19–2^21 cells, so a WHIR-committed PQZH proof of
≈ 60–110 KB at 128 bits is plausible [inference] — the one route seen to the 96 KB line. Less mature than FRI.

**Binius64** proves constraints over 64-bit words (AND, MUL, free XOR) and is not zero-knowledge per its architecture
document (§9); binary fields have no multiplicative NTT for X^64 + 1 over Z, so each A-product is 4.2 M word
multiplications. Excluded [inference].

### 5.6 The limits for a PQZH kind

CTR-PQZ-09's 96 KB was set for a lattice proof of ≈ 30–50 KB. For PQZH the binding limits are elsewhere:

| Proof | Transfer calldata floor | With +16 inline credits | `R_TX` precompile input |
|---|---|---|---|
| 42.7 KB (PQZL) | 2.89 M gas | 11.2 M | 125,777 B |
| 96 KB | 5.02 M | 13.3 M | 179,077 B |
| 128 KB | 6.30 M | 14.6 M | 211,077 B |
| 150 KB | 7.17 M | 15.5 M | 233,077 B |
| 179 KB | 8.33 M | 16.65 M | 262,077 B (= `MAX_INPUT`) |
| 200 KB | 9.17 M | 17.5 M (over EIP-7825) | 283,077 B (over) |

[estimate: EIP-7623 floor of 10 gas per token, ≈ 119 k tokens of non-proof calldata as pq-zether.md §9.3, ≈ 3.99
tokens per proof byte]. So:

- **Proof ≤ 160 KB** fits the precompile input, the +16 inline worst case under EIP-7825 and the token's statement
  layout without other change; the transfer floor rises from ≈ 2.9 M to ≈ 5–7.6 M gas, ≈ 10–16 transfers per 80 M
  block instead of ≈ 28 [estimate].
- Above that, the precompile `MAX_INPUT` must rise (e.g. 512 KiB) and `INLINE_MAX` fall (8 inline credits leave room
  for a ≈ 280 KB proof), and the tx-pool size limit (≥ 1 MiB already recommended) still holds.
- The contract's `MAX_PROOF = 98,304` becomes a per-kind constant (immutable with `proofSystemId`).
- Upload per transfer grows from ≈ 77 KB to ≈ 140–200 KB (CTR-PQZ-18 lists it as information, not a budget).

## 6. Integration

**Precompile.** Same address `0x…0F01`, same ops 1–6, same statement layouts; the prefix check already requires a
`proofSystemId` the precompile implements (pq-zether.md §9.1), so dispatch by id is enough: PQZL ids go to
`pqz_verify`, PQZH ids to `pqzh_verify`. Proposed id form: `keccak256("scaas/pqz/pqzh-p3fri-gl-keccak/mlwe-d64k32-q42l4/v1")`,
bumped by any change of the AIR, the FRI parameters, the field or the hash. `OP_SELFTEST` keeps its input and folds the
PQZH KATs and one valid / one invalid PQZH `R_REG` proof into its hash, so a node without PQZH fails the contracts'
self-test. Gas per CTR-PQZ-11 with `G_op` measured per (op, id).

**Verifier in the node.** Plonky3 is Rust; the spec already puts a Rust decoder (`pqz-ffi`) in front of the C core.
The PQZH verifier is a Rust crate behind the same C ABI shape (`pqzh_verify(op, stmt, stmt_len, proof, proof_len)`,
1 valid / 0 anything else), called from `Nethermind.Pqz` by P/Invoke like `pqz_verify`. Requirements from CTR-PQZ-10
carried over [inference]: no threads (Plonky3's `parallel` feature off), `panic = "unwind"` with `catch_unwind` → 0,
the proof length bounded before parsing and every vector length checked against the fixed configuration before any
allocation sized from the proof, integer-only (it is), libFuzzer + sanitizers in CI. The prover and verifier share no
code path with `pqz-core`, which is the point.

**Token kinds.** As `pqz-proof-alternatives.md` §6: either eight `TokenKind` values (`*_PQZL`, `*_PQZH`) or four kinds
with the `proofSystemId` at `initialize`; the token already stores an immutable `proofSystemId`, so both readings work
technically. One point needs a decision (§8, Q3): registration. `UAPqzVerifier` has one immutable `proofSystemId` per
registry generation, so a `pqz-mlwe` key registered with a PQZL `R_REG` proof would back PQZH tokens too, and the
shortness of that key (which the noise budget and the uniqueness argument need) would rest on the lattice proof.

**Clients.** `zether-prover` is Rust with wasm-bindgen already; a `pqzh` feature adds the Plonky3 prover natively and
for `wasm32-unknown-unknown` without a C toolchain (unlike PQZL's C-in-WASM). `pqz-cli` gains `--proof-system
pqzl|pqzh`; the witness (keys, randomness re-derived from the seed and salt, CTR-PQZ-19) and the statement builder are
shared. Single-threaded in the browser as CTR-PQZ-18; memory is the budget to watch (§5.1).

## 7. Recommendation and prototype plan

**Backend: Plonky3, FRI, Goldilocks, Keccak Merkle trees and challenger, LogUp; design D1 first.** Why
[inference]: the only candidate field where every PQZ identity is a single-element identity (§3.1) and X^64 + 1
splits; a mature, audited, permissively licensed toolkit with hiding commitments and a WHIR option in the same code
base; a verifier in single-digit milliseconds; Rust like `zether-prover` and `pqz-ffi`. D1 needs only preprocessed
columns and LogUp; D2 is the second step once the challenge-derived constants are wired. Ligero stays the fallback
for an off-chain verifier; Stwo the fallback toolkit.

| Step | Build | Measure / check | Effort [estimate] |
|---|---|---|---|
| 0 | Crate `pqz-core/pqzh/` (Rust, Plonky3 pinned): `src/air/{ntt,ring,range,pubmem}.rs`, `src/rel/{reg,tx,burn,ds,dr}.rs`, `src/witness.rs` (from the same keygen / enc as `pqz-core`, checked against its vectors), `bench/`, `runs/` (JSON lines as `sv/runs/`), scripts under `scripts/capped` | builds native and wasm32; statement bytes equal to `pqz-core`'s | 2–3 days |
| 1 | `R_REG` D1: NTT, `Â` preprocessed, quotients, ranges, ℓ2, public memory | proof bytes, prove (1 thread / all), verify p50 / p99, memory; honest + mutated proofs and statements (the `sv/diff.sh` mutation set) | 1–1.5 weeks |
| 2 | `R_TX` D1: rows 1–7, statement products, digits and carries | the E-S1 table: proof, prove native and wasm, p99 adversarial verify, memory, module size | 1–1.5 weeks |
| 3 | ZK on (`HidingFriPcs` + trace randomisation); check what it covers (preprocessed, LogUp, quotient) | cost of ZK on each metric | 2–4 days |
| 4 | Sweep: blowup 4/8/16, arity, conjectured vs provable, D2, WHIR commitment | proof size against 96 / 128 / 160 KB; soundness bits per regime | 1 week |
| 5 | `R_BURN`, `R_DS`, `R_DR`; C ABI `pqzh_verify`; fuzz target | coverage of the five ops | 1 week |

Total ≈ 5–7 agent-weeks to a measured, five-relation prototype [estimate]. Steps 1–2 settle the go / no-go;
step 4 settles which proof-size limit is realistic.

## 8. Open questions for the owner

1. **Proof-size limit for the PQZH kind.** 96 KB is likely out of reach with FRI. Accept ≤ 160 KB (no other change),
   or keep 96 KB and make WHIR a requirement of the prototype?
2. **Soundness regime.** 128 bits *provable* (Johnson bound; ≈ 1.8× the proof of the conjectured regime and a larger
   extension field) or *conjectured* (smaller, but the up-to-capacity conjecture is now disproved)?
3. **Registration under PQZH.** Should `pqz-mlwe` keys used by PQZH tokens be registered with a PQZH `R_REG` proof
   (a second `UAPqzVerifier` / registry generation, or a PoP carrying its `proofSystemId`), or may PQZH tokens accept
   keys registered under PQZL?
4. **Kinds.** Eight `TokenKind` values, or four plus the `proofSystemId` at `initialize`?
5. **Hash.** Keccak / SHAKE (no recursion), or Poseidon2 to keep the door open for recursive aggregation of PQZH
   proofs?
6. **Order.** Start the Plonky3 prototype now, in parallel with the PQZL work, or after it?

## 9. Sources and reruns

External numbers and statements, read 2026-10-13 unless stated:

| Item | Source |
|---|---|
| Plonky3 fields, FRI / STIR / WHIR, licence MIT / Apache-2.0, SIMD128 fallbacks | [github.com/Plonky3/Plonky3](https://github.com/Plonky3/Plonky3) README |
| `HidingFriPcs`, `HidingWhirPcs`, uni-STARK ZK paths, LogUp in `p3-lookup` | [Plonky3 docs/architecture.md](https://github.com/Plonky3/Plonky3/blob/main/docs/architecture.md) |
| > 2 M Poseidon2 hashes/s on an M3 Max [measured by others] | [Polygon blog, 2024-12](https://polygon.technology/blog/open-source-polygon-plonky3-is-once-again-the-fastest-zk-proving-system) (first stated by D. Lubarov on X, 2024-10-31) |
| Least Authority audit of Plonky3 (final report July 2024, updated 2024-11-07; finding: verifier trusted proof parameters) | [leastauthority.com](https://leastauthority.com/blog/audit-of-plonky3/) |
| Miden's Plonky3 migration plan (WASM prover requirement, ZK as a later step) | [hackmd.io/@bobbinth/SyUwZiDKle](https://hackmd.io/@bobbinth/SyUwZiDKle) |
| Disproof of the up-to-capacity proximity-gap conjectures (FRI, DEEP-FRI, STIR, WHIR) | Crites, Stewart, [ePrint 2025/2046](https://eprint.iacr.org/2025/2046) (2025-11-05, rev. 2025-12-19) |
| EF milestones: 100-bit provable by May 2026, 128-bit provable and ≤ 300 KiB by end of 2026 | [blog.ethereum.org, 2025-12-18](https://blog.ethereum.org/2025/12/18/zkevm-security-foundations) |
| WHIR: degree 2^22, 100 bits: 63 KiB, 360 µs verify, 1.2 s commit + open [measured by others] | Arnon, Chiesa, Fenzi, Yogev, [ePrint 2024/1586](https://eprint.iacr.org/2024/1586) |
| WHIR over KoalaBear (quintic), 2^22, 100 bits Johnson: 54,436 B proof [measured by others] | [ethresear.ch, 2026-05-19](https://ethresear.ch/t/evm-verification-of-whir-over-a-31-bit-field/24902) |
| Stwo: Apache-2.0; zkSecurity audit of the Stwo-Cairo verifier (2025-07/08) | [reports.zksecurity.xyz](https://reports.zksecurity.xyz/reports/starkware-stwo-cairo); S-two benchmarks (zkVM, 96-bit, 2025-07-03): [docs.starknet.io](https://docs.starknet.io/learn/S-two-book/benchmarks) |
| Ligetron: IEEE S&P 2024; `ligero-prover` Apache-2.0, WebGPU required | [cris.biu.ac.il](https://cris.biu.ac.il/en/publications/ligetron-lightweight-scalable-end-to-end-zero-knowledge-proofs-po/), [github.com/ligeroinc/ligero-prover](https://github.com/ligeroinc/ligero-prover) |
| Binius64: 64-bit word constraints (AND, MUL), not zero-knowledge | [binius64 ARCHITECTURE.md](https://github.com/binius-zk/binius64/blob/main/ARCHITECTURE.md) |
| Ligero; LogUp | [ePrint 2022/1608](https://eprint.iacr.org/2022/1608); Haböck, [ePrint 2022/1530](https://eprint.iacr.org/2022/1530) |

```sh
python3 pqz-core/pqzh/pqzh_count.py --selftest              # the bounds of §3.1 (asserts)
python3 pqz-core/pqzh/pqzh_count.py > pqz-core/pqzh/counts.txt   # every table of §1, §3.5, §5
```
