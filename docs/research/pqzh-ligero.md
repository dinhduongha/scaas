> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH over Ligero: design and parameters (P6-PQZH, Ligero backend)

Written 2026-10-14 at the owner's request (owner decision 2026-10-14: build and measure a Ligero backend for PQZH
as the alternative to the Plonky3 STARK of `pqzh-prototype.md` / `pqzh-zk-ext5.md`). Branch `pqzh-ligero` (from main
`79924cf`). **Status: design and parameter model done; the Rust prover / verifier and the measurements are not
built yet** (the session was paused for a machine shutdown; §7 lists the exact next steps). **No decision is
recorded here.**

**[estimate]** marks a number from the parameter model `pqz-core/pqzh/ligero/ligero_params.py` (stdlib Python,
output committed as `pqz-core/pqzh/ligero/runs/p0-params.txt`); nothing in this note is measured yet.
**[inference]** marks a conclusion drawn here. Paper references are to the extended Ligero paper, Ames, Hazay,
Ishai, Venkitasubramaniam, *Ligero: Lightweight Sublinear Arguments Without a Trusted Setup*, ePrint 2022/1608
(the extended version of CCS 2017, read 2026-10-14 from the eprint PDF; theorem and lemma numbers below are that
version's).

## 1. Result so far

- **Field: F_q itself works**, with q = 2^42 − 215: `q − 1 = 2^3 · 19 · 43 · 431 · 1,561,243`, so Reed–Solomon
  domains are multiplicative subgroups (and cosets) of order `2^a · 19^b · 43^c` up to 6,536, encoded by a small
  mixed-radix FFT (radices 2, 19, 43). Challenges live in `F_{q^4} = F_q[X]/(X^4 − 3)` (|F| = 2^168.0); `F_{q^3}`
  (2^126) cannot reach 128 bits [estimate, `runs/p0-params.txt`].
- **The mod-q rows of `R_TX` / `R_REG` are plain linear constraints** over F_q (no quotients, no limbs, no NTT in the
  circuit); range checks are bits (quadratic `b·b = b`), exact ℓ2 norms are squares plus a slack decomposed in bits.
- **The column count is not set by the proximity test but by the consistency checks of the linear and quadratic
  tests** (polynomials of degree 2k − 2 compared at opened columns). This is the main gap to the design estimate,
  which counted Johnson-regime proximity only (§5.3).
- **Model, 128 bits (112 query bits + 16 grinding bits), ZK on** [estimate]: `R_TX` ≈ 298 KB proven (rate 1/8,
  n = 6,536, k = 817, t = 166) and ≈ 112 KB conjectured (rate 1/19, n = 6,536, k = 344, t = 35); `R_REG` ≈ 218 KB
  proven / ≈ 78 KB conjectured. The STARK (ZK, Goldilocks⁵, `pqzh-zk-ext5.md` §1) measured 622,448 B proven /
  340,431 B conjectured for `R_TX`. Verifier work ≈ 16 M (proven) / 2.9 M (conjectured) 42-bit products for `R_TX`
  with the aligned layout of §3.3, i.e. ≈ 15–40 ms / 3–8 ms native if a product with lazy u128 reduction costs
  1–2.5 ns [inference, to be measured].

## 2. Field and domains

| Item | Choice | Why |
|---|---|---|
| Base field | F_q, q = 2^42 − 215 (pq-zether.md) | the relation's own field: every mod-q row is linear, no quotient witnesses, statement coefficients enter as they are |
| `q − 1` | `2^3 · 19 · 43 · 431 · 1,561,243`; generator 3 | checked by `ligero_params.py` (`checks()`) |
| Evaluation domain η | coset `3 · H_n` of the subgroup H_n, n ∈ {3,268, 6,536} | disjoint from the message points (Ligero needs ζ ∩ η = ∅); FFT of size n with radices 2, 19, 43 (≈ 64 products per point) |
| Interpolation domain | subgroup H_k, k \| n; message points ζ = the first ℓ elements of H_k, the other k − ℓ points carry the prover's randomness | encoding = inverse FFT on H_k, zero-pad to n, coset FFT on 3·H_n |
| Challenge field | `F_{q^4} = F_q[X]/(X^4 − 3)` | 3 is a non-square and q ≡ 1 mod 4, so X^4 − 3 is irreducible; |F| = 2^168 leaves the field terms (n + 3)/|F| ≈ 2^−155 |
| Larger domains | `n = 2^3·19·43·431` would allow lower rates | needs a radix-431 stage (≈ 430 products per point); not modelled, an option if the proven size matters (§7) |
| Element encoding | 6 bytes big-endian per F_q element, canonical (< q) checked | 42 bits in 48; an extension element is 4 base elements (24 B) |

X^64 + 1 does not split over F_q (q ≡ 41 mod 128, so its roots live in F_{q^16}); Ligero does not need it: the ring
products only appear inside linear constraints, and the verifier evaluates them by the recurrence of §3.4.

## 3. Constraint system

### 3.1 Witness

Per short vector (`s`, `e` of `R_REG`; `s_f`, `e_f`, `r`, `e1`, `e2_t/f/a` of `R_TX`): the values x, their squares
x², and the bits of `x + 2^b` with `2^b` above the exact ℓ2 bound (36 → b = 6, 7 bits; 164 → b = 8, 9 bits;
64 → b = 7, 8 bits). Per norm: a slack `B² − ‖x‖²` and its bits (11, 15, 13 bits for B = 36, 164, 64). For `R_TX`
also the digits `d`, `d'` (4 bits each), `M` (14 bits), carries `c + 64` (11 bits), `e_T + 2^24` (25 bits), as
`rel.rs`' digit rows.

Bounds that make every field identity an integer identity [inference, same arguments as `pqzh-design.md` §3.1]:
the squares sum to at most 2,048 · 2^16 < 2^27 ≪ q/2, slacks are below 2^15, row 7 terms below 2^15. The mod-q rows
need no bound at all: they are identities in F_q.

### 3.2 Constraints

| Kind | Constraint | `R_REG` | `R_TX` |
|---|---|---|---|
| linear, mod q | `pk = A s + e` (row 1); `u = A^T r + e1` (row 2); `v_x[i] = (pk_x^T r)[i] + e2_x[i] + Δ·d_i` (rows 3–5, i < 16); `v_T[i] − (u_T^T s_f)[i] = Δ·M_i + e_T[i]` (row 6) | 2,048 | 4,160 |
| linear, integer | row 7 `M_i + c_{i−1} = d'_i + d_i + f_i + 16 c_i` (`c_{−1} = c_15 = 0`, `f` = fee digits from the statement) | — | 16 |
| linear, bits | `x + 2^b = Σ_j 2^j bit_j` per value; slack `= B² − Σ x²` and its bits | per value / norm | per value / norm |
| quadratic | `bit · bit = bit` (every slot of a bit row); `x · x = sq` (every slot of a value row) | ≈ 36.9 k | ≈ 75 k |

The relation is exactly `rel.rs`' (the STARK's): same ranges for M, e_T, carries and digits, same reading of the
statement (`parse_tx`, fee word < 2^64, canonical coefficients), and the statement and witness bytes come from
`client::setup()`, which `xcheck/` keeps byte-identical to pqz-core's `pqz_bench.c`.

### 3.3 Layout: aligned rows

A big group (2,048 values) occupies ⌈2048/ℓ⌉ value rows, the same number of square rows and, per bit, the same number
of bit rows, **slot-aligned**: bit j of the value in (row r, slot c) sits in (bit row j of r, slot c). Then the
linear-test combination vector of bit row j is `−2^j` times the bit-decomposition part of row r, and the quadratic
triples (x, x, sq), (bit, bit, bit) reference existing rows. The verifier interpolates only two vectors per value
row (A-part + bit part, bit part alone) instead of one per row; that is what brings the verifier from ≈ N_w·t to
≈ 2·(values)·t products (§1). Small values (e2, digits, M, c, e_T, slacks) are packed horizontally into a few
"small" rows with general sparse constraints.

### 3.4 The verifier's combination vector for the ring rows

The linear test draws one ρ ∈ F_{q^4} and uses r_c = ρ^c for constraint c (Schwartz–Zippel: a false system passes
with probability ≤ (M − 1)/|F|, M ≈ 6.3 k constraints for `R_TX`). For a row group `Σ_j A_ij s_j` the coefficient of
`s_{j,m}` is `f_m(a_j) = Σ_k ρ_k (X^m a_j mod X^64 + 1)_k` with `a_j = Σ_i γ_i A_ij` (γ_i = ρ^(64 i)), and
`f_{m+1} = ρ·f_m − (ρ^64 + 1)·(X^m a)_63` (rows 3–6 use only k < 16: `f_{m+1} = ρ f_m − ρ^16 (X^m a)_15 − (X^m a)_63`).
Cost: 32 · 2,048 base × extension products per matrix plus 64 steps per column of polynomials, ≈ 1 ms; no 2048 × 2048
dense matrix is ever formed [inference].

## 4. Protocol, zero knowledge, Fiat–Shamir

Let the m witness rows be encoded with polynomials p_i of degree < k (`p_i(ζ_c)` = the row's message, `p_i` at the
other k − ℓ points of H_k uniformly random), U the m × n matrix of evaluations on η.

1. **Blinding rows** (all committed with U, in the same Merkle tree):
   - `u_0`: a uniformly random polynomial of degree < 2k − 1 (masks the proximity combination);
   - `u_lin`: random, degree < 2k − 1, with `Σ_{h ∈ H_k} u_lin(h) = 0` (masks the linear test);
   - `u_quad = Z_ζ · h_0`: random, degree < 2k − 1, vanishing on the ℓ message points (masks the quadratic test).
2. **Commit**: column j = (salt_j ‖ U[·, j] ‖ blinds[·, j]); leaf = Keccak-256(salt_j ‖ column bytes), salt_j = 32
   prover-random bytes (an unopened column is otherwise a deterministic function of the witness once t columns are
   open, and its hash would allow offline guessing of short secrets); Keccak-256 binary Merkle tree, root R.
3. **Challenges** from the transcript after R: proximity coefficients `a_i, b_i` per row and `c_lin, c_quad`;
   linear ρ; quadratic `r_i` per quadratic triple (all in F_{q^4}).
4. **Prover sends** (coefficients in F_{q^4}):
   - proximity `w = Σ_i (a_i + b_i X^(k−1)) p_i + c_lin u_lin + c_quad u_quad + u_0` (degree < 2k − 1; the
     `X^(k−1)` term is the usual degree correction, so passing proves deg p_i < k);
   - linear `q = Σ_i R_i · p_i + u_lin` (degree < 2k − 1), R_i the degree < k interpolant of the combination vector
     on ζ and of 0 on the k − ℓ random points; the verifier checks `k · (q_0 + q_k) = Σ_c r_c b_c` (the sum over
     H_k);
   - quadratic `p_0 = Σ_i r_i (p_x p_y − p_z) + u_quad`, sent as `h = p_0 / Z_ζ` (degree < 2k − 1 − ℓ), so
     `p_0(ζ_c) = 0` holds by construction and ℓ coefficients are saved.
5. **Grinding**: a nonce such that Keccak-256(state ‖ nonce) has 16 leading zero bits (as the STARK's 16 bits).
6. **Queries**: t column indices (rejection sampling, with replacement); the prover opens the distinct columns with
   their salts and one pruned Merkle multiproof. The verifier checks at each opened η_j the three identities
   `w(η_j) = Σ (a_i + b_i η_j^(k−1)) U_ij + c_lin u_lin[j] + c_quad u_quad[j] + u_0[j]`,
   `q(η_j) = Σ R_i(η_j) U_ij + u_lin[j]`, `Z_ζ(η_j) h(η_j) = Σ r_i (U_x U_y − U_z)[j] + u_quad[j]`.

**Transcript.** Keccak-256 chained state, seeded with `keccak256("SCAAS-PQZH-LIGERO-V1" ‖ u8(op) ‖ be32(len) ‖
stmt)` (as `rel::stmt_digest`, with a Ligero label), then R, then every sent polynomial before the next challenge,
then the nonce. Field elements are squeezed as 8-byte words masked to 42 bits and rejected if ≥ q (as `a_matrix`).
The parameters (n, k, ℓ, t, grinding bits, layout version) are fixed per `proofSystemId` and never read from the
proof; every vector length in the proof is checked against them before any allocation.

**Zero knowledge (honest verifier, then Fiat–Shamir in the ROM).** As Ligero Lemma 4.15 (k > ℓ + t): the t opened
columns of the witness rows are uniform because each p_i has k − ℓ > t random evaluations; `w`, `q`, `h` are
uniform in their spaces (degree < 2k − 1; with `Σ_{H_k} = 0`; degree < 2k − 1 − ℓ) because `u_0`, `u_lin`, `u_quad`
are uniform in exactly those spaces and enter with coefficient 1; the opened blind values are then fixed by the
three identities, as in the paper's simulator. The salts hide the unopened columns behind their hashes.
Difference to the paper: its §4.7 protocol samples the blinding rows from RS[n, k] but uses them as blinds of
degree < k + ℓ − 1 and < 2k − 1, and does not run the proximity test on them (its Lemma B.7 assumes the blinded
matrix is close to the code); here every blinding row has the degree of the polynomial it masks and is inside the
one proximity test, which is what the soundness argument below needs [inference].

## 5. Soundness at 128 bits

### 5.1 Terms

With δ the relative proximity radius and ρ = k/n:

| Term | Bound | Source |
|---|---|---|
| proximity of all rows (+ degree correction) to RS[n, 2k − 1] | `(n + 1)/|F| + (1 − δ)^t` for δ < (1 − 2ρ)/2 | Ligero Lemma 4.6 (= BCIKS20 Thm 1.2, unique decoding) with App. C's accounting |
| degree correction | `2m/|F|` extra in the combination | standard; field term |
| linear test | `(M − 1)/|F| + ((2k − 1)/n)^t` | Ligero Lemma 4.8 / App. C (degree of q − q* < 2k − 1), Schwartz–Zippel for r_c = ρ^c |
| quadratic test | `1/|F| + ((2k − 1)/n)^t` | Ligero Lemma 4.10 / App. C |
| Fiat–Shamir | round-by-round errors above, 16 grinding bits on the query round | as the STARK accounting (`pqzh-zk-ext5.md`) |

All field terms are below 2^−150 with F_{q^4}. The query term per column is `max(1 − δ, (2k − 1)/n)`; with δ at
the unique-decoding radius (1 − 2ρ)/2 of RS[n, 2k − 1] the **proven** factor is `max((1 + 2ρ)/2, 2ρ)` =
(1 + 2ρ)/2 for ρ ≤ 1/2. The paper's main-theorem form (Thm 4.7, e-terms included:
`(1 − e/n)^t + 2((e + 2k)/n)^t`) gives the same t to within one column (`p0-params.txt`).

**Conjectured**: the proximity test sound up to capacity of RS[n, 2k − 1] (δ → 1 − 2ρ), consistency terms 2ρ;
factor 2ρ per column. Note that the up-to-capacity conjecture is disproved in general (Crites–Stewart, ePrint
2025/2046, `pqzh-design.md` §5.1); this column is reported for comparison with the STARK's conjectured numbers only.

### 5.2 Opened columns t (112 query bits + 16 grinding bits) [estimate, `runs/p0-params.txt`]

| rate k/n | 1/4 | 1/8 | 1/16 | 1/19 | 1/32 | 1/43 |
|---|---|---|---|---|---|---|
| proven | 270 | 166 | 135 | 131 | 123 | 120 |
| conjectured | 112 | 56 | 38 | 35 | 28 | 26 |

### 5.3 Why the design estimate was lower

`pqzh-design.md` §3.6 / `counts.txt` used t = 128 / −log2 √ρ ("Johnson") and t = 128 / −log2(1 − (1 − ρ)/3)
("classic") for the proximity test alone, ext degree 3 (2^126, short of 128 bits), no grinding, and a quadratic
test of length 2k with no degree correction. The linear and quadratic consistency terms ((2k − 1)/n)^t were not
counted; they bound t from below by 112 / log2(1/(2ρ)) even under the capacity conjecture, and in the proven
regime t ≥ 112 for any rate. F_{q^4} instead of F_{q^3} adds a third to every sent polynomial [inference].

### 5.4 Parameter choice [estimate, `runs/p0-params.txt`]

Searched over smooth n, k (k | n, n ≤ 6,536) with ℓ = k − t − 1 (Lemma 4.15) and the layout of §3.3:

| | `R_TX` proven | `R_TX` conjectured | `R_REG` proven | `R_REG` conjectured |
|---|---|---|---|---|
| n, k, rate | 6,536, 817, 1/8 | 6,536, 344, 1/19 | 6,536, 817, 1/8 | 6,536, 172, 1/38 |
| t, ℓ, rows m | 166, 650, 163 | 35, 308, 286 | 166, 650, 81 | 27, 144, 301 |
| sent polynomials | 102 KB | 42 KB | 102 KB | 21 KB |
| opened columns (+ salts) | 169 KB | 62 KB | 88 KB | 50 KB |
| Merkle multiproof | 28 KB | 8 KB | 28 KB | 7 KB |
| **proof** | **≈ 298 KB** | **≈ 112 KB** | **≈ 218 KB** | **≈ 78 KB** |
| verifier 42-bit products | ≈ 16 M | ≈ 2.9 M | ≈ 8.3 M | ≈ 1.1 M |

The prover encodes m + 3 rows (inverse FFT of size k, FFT of size n each) and computes the three test polynomials by
FFTs of size n: for `R_TX` proven ≈ 170 rows × ≈ 0.5 M products, ≈ 0.1–0.3 s native [inference].

## 6. Comparison (to be filled by measurements)

| `R_TX`, ZK, 128 bits | Proof proven / conjectured | Prove native | Verify p99 native / wasm32 | Source |
|---|---|---|---|---|
| STARK, FRI, Goldilocks⁵, blowup 16 | 622,448 B / 340,431 B | 20.4 s, 2.82 GB | 19.1 / 28.7 ms (proven) | `pqzh-zk-ext5.md` §1, `runs/t6-zk5-*` |
| Design estimate, Ligero over F_q | 261–283 KB classic / 137–166 KB Johnson | tens of ms | 43–131 ms | `pqzh-design.md` §3.6 |
| Ligero over F_q, model (this note) | ≈ 298 KB / ≈ 112 KB | ≈ 0.1–0.3 s | ≈ 15–40 / 3–8 ms native (proven / conjectured) | `ligero/runs/p0-params.txt` [estimate] |
| Ligero over F_q, measured | — | — | — | not run yet (§7) |

## 7. Status / resume

**Done (committed on `pqzh-ligero`):** this design; the parameter model `pqz-core/pqzh/ligero/ligero_params.py` and
its output `pqz-core/pqzh/ligero/runs/p0-params.txt`; the note's entry in `docs/research/README.md`.

**Not started:** Rust code, builds, runs. No capped job was started or interrupted. `TODO.md` is unchanged (the
"Ligero measured" entry waits for measurements).

**Next steps, in order:**

1. Crate `pqz-core/pqzh/ligero/` (own `Cargo.toml`, `[workspace]`, path dependency on `pqzh` for `client`, `ring`
   (`a_matrix`, `rd_poly`, `Q`, `D`, `K`, `DELTA`), `rel` (`parse`-equivalent, `PREFIX`, `HEADER`, `HDR_FEE`,
   `stmt_digest` style); `sha3` already in the lock). Modules: `fq.rs` (F_q, 6-byte codec, `F_{q^4}`), `fft.rs`
   (mixed radix 2/19/43, coset), `merkle.rs` (salted Keccak-256 leaves, pruned multiproof), `transcript.rs`,
   `cs.rs` (layout §3.3, combination vectors §3.4), `ligero.rs` (prove / verify §4), `lib.rs`
   (`prove(op, stmt, wit, rnd32, &Params)`, `verify(op, stmt, proof, &Params) -> bool` with `catch_unwind`).
2. Unit tests: field / FFT / recurrence against naive; honest `R_REG`, `R_TX` accept; the `client::mutate` 12 kinds ×
   ≥ 40 cases × 2 relations (≥ 960) + the negative witnesses of `pqzh/tests/attacks.rs`, 0 accepted.
3. Bench binary `ligero_bench` (copy of `pqzh_bench`: JSON lines, peak heap) and a wasm32 verify (and prove)
   harness like `pqzh/wasm/`. Runs, one at a time, alone under the lock:
   `scripts/capped sh -c 'cd pqz-core/pqzh/ligero && cargo test --release --offline'`,
   `scripts/capped pqz-core/pqzh/ligero/runs/bench.sh l1-proven --params proven ...`,
   then the conjectured parameters and the wasm32 runs; results into `pqz-core/pqzh/ligero/runs/`.
4. Check that the STARK path still builds and its tests and `xcheck/` pass (`scripts/capped
   pqz-core/pqzh/xcheck/run.sh`), and the `pqzh/wasm` build.
5. Fill §6 from the runs, add the dated "Ligero measured" entry to the P6-PQZH line of `TODO.md`,
   `python3 scripts/docs_check.py check`, commit.

**Open questions for the owner** (none blocks the build):

1. The proven `R_TX` model (≈ 298 KB) is under the STARK's proven 622 KB but over the 160 KB line; a radix-431 FFT
   (n up to 2.8 M) gives lower rates and t → 120, which the model has not explored. Worth the extra FFT code?
2. Accept the modified ZK construction of §4 (blinding rows of full degree inside the one proximity test) over the
   paper's §4.7 text, whose blinding-row degrees do not match its simulator?
