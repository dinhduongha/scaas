> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH over Ligero: design, parameters and measurements (P6-PQZH, Ligero backend)

Written 2026-10-14 at the owner's request (owner decision 2026-10-14: build and measure a Ligero backend for PQZH
as the alternative to the Plonky3 STARK of `pqzh-prototype.md` / `pqzh-zk-ext5.md`). Branch `pqzh-ligero` (from main
`79924cf`, not merged). **Status: built and measured** (crate `pqz-core/pqzh/ligero/`, raw runs
`pqz-core/pqzh/ligero/runs/`, every file named below). The two owner decisions of 2026-10-14 on this design are
recorded in full in §9; **no other decision is recorded here** (§9 lists the open questions).

**[measured]** marks a number from a run in `runs/` (machine as in `pqzh-prototype.md` §2: AMD Ryzen 5 7235HS, single
thread, every timed run alone under `scripts/capped`, 4 GB memory cap). **[estimate]** marks a number from the
parameter model `pqz-core/pqzh/ligero/ligero_params.py` (stdlib Python; outputs `runs/p0-params.txt`, the first model,
and `runs/p1-params.txt`, the model of the crate's layout). **[probe]** marks a single run, **[inference]** a
conclusion drawn here. Paper references are to the extended Ligero paper, Ames, Hazay, Ishai, Venkitasubramaniam,
*Ligero: Lightweight Sublinear Arguments Without a Trusted Setup*, ePrint 2022/1608.

## 1. Result

**Ligero over F_q builds, proves and verifies `R_REG` and `R_TX` with zero knowledge at 128 bits (per term). With the
radix-431 domains (owner decision (1), §9) `R_TX` is 230,392 B proven / 92,072 B conjectured, proving in 0.67 /
0.93 s with 43 / 50 MB peak heap; verify p99 is 10.5 / 3.5 ms native and 55.9 / 16.8 ms wasm32; 0 of 3,840 mutated
inputs accepted, 0 verifier panics** [measured, `runs/l2-*`]. Against the FRI+ZK STARK over Goldilocks⁵
(`pqzh-zk-ext5.md` §1):

| `R_TX`, ZK, 128 bits | Proof proven / conjectured | Prove native | Peak heap | Verify p99 native | Verify p99 wasm32 |
|---|---|---|---|---|---|
| STARK, FRI, Goldilocks⁵, blowup 16 | 622,448 B / 340,431 B | 20.4 s | 2,824 MB | 19.1 / 15.5 ms | 28.7 / 24.1 ms |
| **Ligero over F_q, radix 431** (n = 32,756 / 18,533) | **230,392 B / 92,072 B** | **0.67 / 0.93 s** | **43 / 50 MB** | **10.5 / 3.5 ms** | **55.9 / 16.8 ms** |
| Ligero over F_q, radices 2/19/43 (n = 6,536) | 305,080 B / 113,414 B | 0.29 / 0.30 s | 16 / 20 MB | 17.0 / 4.3 ms | 72.4 / 17.6 ms |

- **Ligero beats the STARK on every axis except wasm32 verify**: proven `R_TX` −63 % bytes (−73 % conjectured),
  30× faster to prove, 65× less prover memory, native verify p99 −45 %; wasm32 verify is ≈ 2× slower (the verifier's
  u128 products are emulated on wasm32) and the proven `R_TX` p99 (55.9 ms) is above a 50 ms budget if that budget
  applies to wasm32 (it holds natively with a 5× margin).
- **Radix 431 lowers the proven size**: `R_TX` 305,080 → 230,392 B (−24.5 %), `R_REG` 224,360 → 186,970 B
  (−16.7 %); conjectured −19 / −21 % [measured]. It lowers the rate from 1/8 to 1/40, which brings t from 166 to 121
  columns; the cost is prove time (0.29 → 0.67 s for `R_TX` proven) — affordable only because the 431 stage is
  pruned (§6.3: unpruned it was 4.1 s [measured, `runs/l0-tests.txt`]).
- **The 160 KB line**: the conjectured proofs are under it (`R_TX` 92 KB, `R_REG` 63 KB); the proven ones are not
  (`R_TX` 230 KB = 1.44×, `R_REG` 187 KB).
- **Model vs measurement**: the p1 model is within 1–3 % of every measured size (it slightly over-counts the Merkle
  multiproof) and the verifier's modelled products track native verify time at ≈ 1.1 ns per product (§7).
- Statement / witness bytes are pqzh's `client::setup()`, byte-identical to pqz-core's C `setup()`
  [measured, `runs/l2-xcheck.txt`]; the relation (ranges, norms, carries, fee word) is rel.rs' (§3).

## 2. Field and domains

| Item | Choice | Why |
|---|---|---|
| Base field | F_q, q = 2^42 − 215 (pq-zether.md) | the relation's own field: every mod-q row is linear, no quotient witnesses, statement coefficients enter as they are |
| `q − 1` | `2^3 · 19 · 43 · 431 · 1,561,243`; generator 3 | checked by `ligero_params.py` and `fq.rs` tests |
| Domains | subgroups H_n, n \| 2^3·19·43·431 (radices 2, 19, 43, **431**: owner decision (1)) | mixed-radix FFT `fft.rs`: each stage a direct r-point DFT with lazy u128 sums (r + 1 products per point and stage); the 431 stage is the deepest one and skips zero inputs (§6.3) |
| Evaluation domain η | coset `3 · H_n` | disjoint from H_k for every k, n (3 generates F_q^*, so 3 ∉ H_lcm(k,n)); k need **not** divide n |
| Interpolation domain | H_k; message points ζ = ω_k^0..ω_k^(ℓ−1), the other k − ℓ points carry the prover's randomness | encoding = inverse FFT on H_k, coset FFT of size n |
| Product domain | H_N2, N2 = the smallest smooth size ≥ 2k − 1 | the prover's q and h products (N2 = 1,634 for k = 817) |
| Challenge field | `F_{q^4} = F_q[X]/(X^4 − 3)` | 3 is a non-square and q ≡ 1 mod 4, so X^4 − 3 is irreducible; \|F\| = 2^168 |
| Element encoding | 6 bytes big-endian per F_q element, canonical (< q) checked | an extension element is 4 base elements (24 B) |

## 3. Constraint system (`cs.rs`)

### 3.1 Witness and relation

Exactly rel.rs' relation (pq-zether.md §7.4, pqz-core `pqz_rel.c`), read from pqz-core's statement and witness
bytes: `R_REG`: pk = A s + e mod q, ‖s‖ ≤ 36, ‖e‖ ≤ 164. `R_TX`: rows 1–6 mod q (pk_f = A s_f + e_f; u = A^T r + e1;
v_x = pk_x^T r + e2_x + Δ·digit for x = t, f, a with digits d, d', d; v_T − u_T^T s_f = Δ M + e_T), row 7 over the
integers (M_i + c_{i−1} = d'_i + d_i + f_i + 16 c_i, c_15 = 0, fee digits f from the statement), ‖s_f‖, ‖r‖ ≤ 36,
‖e_f‖, ‖e1‖ ≤ 164, ‖e2_x‖ ≤ 64, digits < 16, M < 2^14, c + 64 < 2^11, e_T + 2^24 < 2^25. Statement parsing as rel.rs
(length, canonical coefficients, fee word < 2^64); the honest prover runs rel.rs' checks (norms, `pk`, ciphertext,
digits, carries) and refuses an invalid witness.

Witness values: per big vector (2048 coefficients) the values, their squares and the bits of x + off
(off = 64 / 256: 7 / 9 bits); small values: e2 (48, 8 bits, off 128), d, d' (4 bits), M (14), c (11, off 64),
e_T (25, off 2^24) and the ℓ2 slacks B² − ‖x‖² (11 / 15 / 13 bits). Every integer identity stays below 2^28 ≪ q/2,
so it holds over Z iff in F_q.

### 3.2 Layout (as built)

Rows have ℓ slots. A big group has ⌈2048/ℓ⌉ value rows, as many slot-aligned square rows, and per bit as many
slot-aligned bit rows; the bit decomposition covers **every** slot of the group's rows (padding slots hold 0, square 0
and the bits of off), and the norm sums the squares of every slot — padding can only enlarge the norm, so this stays
sound. Small values are packed into small value rows, aligned small square rows, and small bit rows holding the bits
back to back (§3.3's "horizontal" packing). Quadratic triples: (value, value, square) and (bit, bit, bit) per row.
`R_TX` at ℓ = 695: 4 · 3 · (2 + bits) = 120 big rows + 5 small rows = **m = 125** (`R_REG` 63).

### 3.3 Linear test combination

Constraint c gets weight ρ^(e_c), all exponents distinct and **≥ 1** (§4.1, item 3 of the soundness argument). Ring
rows use tensor weights `w(i, k) = w0 · G^i · ρ^k` (G = ρ^K), so the coefficient of `x_{j,m}` is
`f_m(a_j) = Σ_k ρ^k (X^m a_j mod X^64 + 1)_k` with `a_j = Σ_i w0 G^i M_ij`, by the recurrence
`f_{m+1} = ρ f_m − ρ^K (X^m a)_{K−1} − (X^m a)_63` (K = 64 for rows 1–2, 16 for rows 3–6; unit test against the
naive sum). The bit decompositions of big rows use `λ_r · ρ^c` (λ_r one power per row): every value and bit row's
vector is then a multiple of **one** shared vector β = (ρ^c)_c, and the norms use the all-ones vector on the square
rows. The verifier interpolates only the "own" vectors (big value rows: ring terms; small rows) and the two shared
ones: 17 + 2 vectors for `R_TX` instead of 125.

## 4. Protocol, zero knowledge, Fiat–Shamir (`ligero.rs`)

1. **Rows**: each witness row p_i (degree < k): message on ζ, uniform on the other k − ℓ points of H_k.
   **Blinding rows** (in F_{q^4}, committed as 4 base rows each, 12 rows): `u_0` uniform of degree < 2k − 1; `u_lin`
   uniform of degree < 2k − 1 with `Σ_{H_k} u_lin = k (c_0 + c_k) = 0`; `u_quad = Z_ζ · h_0`, h_0 uniform of degree
   < 2k − 1 − ℓ (Z_ζ = Π_{c<ℓ} (X − ζ_c)).
2. **Commit**: column j = salt_j (32 prover-random bytes) ‖ the m + 12 values; leaf = Keccak-256(column); Keccak-256
   binary tree padded with zero digests to a power of two; root R.
3. **Challenges** (after R, all in F_{q^4}, independent): a_i, b_i per row, c_lin, c_quad, ρ, r_t per triple.
4. **Prover sends** `w = Σ_i (a_i + b_i X^(k−1)) p_i + c_lin u_lin + c_quad u_quad + u_0` (2k − 1 coefficients),
   `q = Σ_i R_i p_i + u_lin` (2k − 1; R_i the interpolant of row i's combination on ζ and 0 on the other k − ℓ points),
   `h = (Σ_t r_t (p_x p_y − p_z) + u_quad) / Z_ζ` (2k − 1 − ℓ).
5. **Grinding**: nonce with Keccak-256(state ‖ "PoW" ‖ be64(nonce)) starting with 16 zero bits.
6. **Queries**: t indices (with replacement, rejection sampled); the prover opens the distinct ones in increasing
   order with their salts, then the pruned multiproof. The verifier checks `k (q_0 + q_k) = Σ_c ρ^(e_c) b_c` and at
   each opened η_j = 3 ω_n^j: `w(η_j) = Σ (a_i + b_i η_j^(k−1)) U_ij + c_lin u_lin + c_quad u_quad + u_0`,
   `q(η_j) = Σ R_i(η_j) U_ij + u_lin`, `Z_ζ(η_j) h(η_j) = Σ r_t (U_x U_y − U_z) + u_quad` (R_i(η_j) by the
   Lagrange basis of H_k; Z_ζ(η_j) falls out of the batch inversion).

**Transcript.** Keccak-256 chained state seeded with `keccak256("SCAAS-PQZH-LIGERO-V1" ‖ u8(op) ‖ be32(len) ‖ stmt)`;
absorb R, draw the challenges, absorb w ‖ q ‖ h, check the nonce, absorb it, draw the indices. Squeezing: Keccak-256
(state ‖ 0xff ‖ be64(counter)) → 8-byte big-endian words; a field element is a word masked to 42 bits, rejected if
≥ q. The parameters (n, k, ℓ, t, grinding bits) are fixed per proofSystemId (`Params::preset`) and never read from
the proof; the proof length is bounded before parsing and must be consumed exactly. Prover randomness:
SHAKE256("SCAAS-PQZH-LIGERO-RNG" ‖ rnd32 ‖ op ‖ stmt).

**Proof bytes**: R (32) ‖ w ‖ q ‖ h (F_{q^4} coefficients, 24 B each) ‖ nonce (8) ‖ per distinct opened column: salt
(32) and m + 12 F_q values (6 B) ‖ multiproof digests (32 B each).

### 4.1 Zero knowledge and soundness of the modified construction (owner decision (2), §9)

**Why the blinds are in F_{q^4}.** w, q, h have F_{q^4} coefficients; a base-field blind masks only the first of
their four F_q components. 12 instead of 3 base rows cost ≈ 72 B per opened column (counted in the p1 model).

**Honest-verifier zero knowledge.** Fix the challenges and the query set J (|J| ≤ t ≤ k − ℓ − 1).

1. *Opened witness entries are uniform.* `p_i = L_i + Z_ζ g_i` with L_i the interpolant of the message on ζ and g_i
   uniform in `F_q[X]_{<k−ℓ}` (uniform values at the k − ℓ non-message points of H_k ⇔ g_i uniform, Z_ζ ≠ 0 there).
   No η_j lies in H_k (§2), so Z_ζ(η_j) ≠ 0, and `(g_i(η_j))_{j∈J}` is uniform for |J| ≤ k − ℓ: the opened
   `(U_ij)_{i ≤ m, j ∈ J}` are uniform in F_q^{m×|J|}, independent of the witness.
2. *The sent polynomials are uniform in their spaces, independent of (1) and of each other.* For a valid witness
   `Σ R_i p_i` has `Σ_{H_k} = r^T b` and `Σ r_t (p_x p_y − p_z)` vanishes on ζ (the division by Z_ζ is exact). u_0,
   u_lin, h_0 are independent and uniform, so q is uniform on `{deg < 2k − 1, Σ_{H_k} = r^T b}`, h = p_0/Z_ζ + h_0 is
   uniform on `F_{q^4}[X]_{<2k−1−ℓ}`, and w is uniform on `F_{q^4}[X]_{<2k−1}` given everything else (u_0 enters
   with coefficient 1).
3. *The opened blind entries are determined* by the three verifier identities at each η_j:
   `u_0(η_j) = w(η_j) − Σ (a_i + b_i η_j^(k−1)) U_ij − c_lin u_lin(η_j) − c_quad u_quad(η_j)`,
   `u_lin(η_j) = q(η_j) − Σ R_i(η_j) U_ij`, `u_quad(η_j) = Z_ζ(η_j) h(η_j) − Σ r_t (U_x U_y − U_z)_j`.
4. *Commitment.* Leaves are Keccak-256(salt_j ‖ column j) with fresh 32-byte salts; unopened leaves are random-oracle
   outputs on inputs nobody else queries.

Simulator: sample the opened witness entries uniformly, w, q, h uniformly in the spaces of (2), the blind entries by
(3), salts and unopened leaf digests uniformly; build the root and multiproof; search the nonce. (1)–(3) are
distributed exactly as in a real proof; (4) differs only if the distinguisher queries Keccak on an unopened salted
column (2^−256 per query). Non-interactive: Fiat–Shamir in the random-oracle model; the simulator programs the oracle
at the transcript points (fresh, since the root carries the salts' entropy).

*Difference to the paper's §4.7 text*: there the blinding rows are RS[n, k] codewords (degree < k) but mask
polynomials of degree < k + ℓ − 1 and < 2k − 1, so the high coefficients of the linear and quadratic test polynomials
are not masked and the simulator's uniform polynomials are not the real distribution; and the blinds are not in the
proximity test, while the soundness proof (its Lemma B.7) needs the whole blinded matrix close to the code. Here
every blind lives in exactly the space of the polynomial it masks and is inside the one proximity test.

**Soundness.** Let U be the committed matrix (fixed by R under Keccak-256 collision resistance, 128 bits).

1. *Proximity* (RS[n, 2k − 1] over F_{q^4}, evaluation points in F_q, δ = e/n at most its unique-decoding radius):
   the tested combination is a uniform element of the affine space `u_0 + span{p_i, X^(k−1) p_i, u_lin, u_quad}`
   (independent coefficients). If these 2m + 3 words have no common agreement set S of density ≥ 1 − δ with
   low-degree polynomials, a uniform element is δ-close with probability ≤ (2m + 3) n / |F_{q^4}| (BCIKS20 Thm 1.6
   for affine spaces, counted conservatively per word); else the sent w agrees with the combination on < (1 − δ) n
   points and each query passes with probability < 1 − δ.
2. *Degree.* Otherwise p_i = g_i and η^(k−1) p_i = g'_i on S, so g'_i = X^(k−1) g_i on ≥ (1 − δ) n ≥ 3k − 2 points
   (rate ≤ 1/4): deg g_i < k. The blinds decode to ĝ_0, ĝ_lin, ĝ_quad of degree < 2k − 1; the extracted witness is
   g_i on ζ.
3. *Linear.* If the extracted witness violates a linear constraint, `P(ρ) = Σ_c ρ^(e_c) (A w − b)_c + Σ_{H_k} ĝ_lin`
   is a non-constant polynomial in ρ (every e_c ≥ 1; ĝ_lin is fixed before ρ), so P(ρ) = 0 with probability
   ≤ max e_c / |F_{q^4}|. Otherwise q* = Σ R_i g_i + ĝ_lin has the wrong sum over H_k while q's is checked, so
   q ≠ q* (both of degree ≤ 2k − 2): a query passes only if η_j ∉ S or q(η_j) = q*(η_j), probability ≤ δ + (2k − 2)/n.
   (So `Σ u_lin = 0` matters only for ZK, and a constraint weight ρ^0 = 1 would have let a blind with a chosen sum
   cancel one violated constraint.)
4. *Quadratic.* If a triple fails at a message point ζ_c, `Σ_t r_t (g_x g_y − g_z)(ζ_c) + ĝ_quad(ζ_c)` is a
   non-constant affine function of r: zero with probability ≤ 1/|F_{q^4}|. Otherwise p* = Σ r_t (…) + ĝ_quad does not
   vanish at ζ_c, so p* ≠ Z_ζ h, and a query passes with probability ≤ δ + (2k − 2)/n.
5. Given U exactly one of these cases applies, so per query a cheating prover passes with probability
   ≤ max(1 − δ, δ + (2k − 2)/n), minimised at the unique-decoding radius (§5.1); t queries after 16 grinding bits. With
   Fiat–Shamir each round's error above is its round-by-round error.
6. An extracted witness satisfying every constraint satisfies the pqz-core relation: bits are 0/1, so every range
   holds, and every integer identity stays far below q/2 (§3.1).

## 5. Soundness at 128 bits

### 5.1 Terms (per term ≥ 128 bits, as the STARK's accounting in `pqzh-zk-ext5.md`)

| Term | Bound | Measured presets [`runs/l2-*.jsonl`, `soundness_bits`] |
|---|---|---|
| query, proven | `max(1 − e/n, (e + 2k − 2)/n)^t · 2^−16`, e = ⌊(n − 2k + 1)/2⌋ (unique decoding of RS[n, 2k − 1]; Ligero Thm 4.7 / App. C form) | 128.5–128.6 bits |
| query, conjectured | `((2k − 1)/n)^t · 2^−16` (rate of RS[n, 2k − 1], the ethSTARK-style analogue; the up-to-capacity conjecture is disproved in general, Crites–Stewart ePrint 2025/2046) | 129.8–131.1 bits |
| proximity field | `(2m + 3) n / |F_{q^4}|` | 144.6–147.9 bits |
| linear field | `max e_c / |F_{q^4}|` | 154.2–155.4 bits |
| quadratic field | `1 / |F_{q^4}|` | 168 bits |
| Keccak-256 collision | 2^−128 | 128 bits (the binding term, as the STARK's) |

Summing all six probabilities gives 127.2–127.8 bits (`total` in the run files); per term every bound is ≥ 128.

### 5.2 Parameter search [estimate, `runs/p1-params.txt`]

p1 = the crate's exact layout (12 blinding base rows, packed small rows, k need not divide n, n ≥ 4k, exact
unique-decoding factor), radices with and without 431, prover budget ≤ 4·10^9 modelled base products (without it the
conjectured search picks n/k ≈ 8,000 and 4·10^11 products). Best per relation and regime:

| | radices | n, k, rate | t, ℓ, m | test polys | columns | Merkle | **proof (model)** | proof measured |
|---|---|---|---|---|---|---|---|---|
| `R_TX` proven | 2/19/43 | 6,536, 817, 1/8 | 166, 650, 165 | 101,976 | 179,331 | 29,601 | **310,948** | 305,080 |
| `R_TX` proven | +431 | 32,756, 817, 1/40 | 121, 695, 125 | 100,896 | 103,145 | 31,243 | **235,324** | 230,392 |
| `R_TX` conjectured | 2/19/43 | 6,536, 344, 1/19 | 35, 308, 287 | 42,072 | 63,744 | 8,797 | **114,653** | 113,414 |
| `R_TX` conjectured | +431 | 18,533, 344, 1/54 | 24, 319, 287 | 41,808 | 43,797 | 7,994 | **93,639** | 92,072 |
| `R_REG` proven | 2/19/43 | 6,536, 817, 1/8 | 166, 650, 83 | 101,976 | 98,681 | 29,601 | **230,298** | 224,360 |
| `R_REG` proven | +431 | 32,756, 817, 1/40 | 121, 695, 63 | 100,896 | 58,215 | 31,243 | **190,394** | 186,970 |
| `R_REG` conjectured | 2/19/43 | 6,536, 172, 1/38 | 27, 144, 303 | 21,240 | 51,791 | 7,112 | **80,183** | 79,478 |
| `R_REG` conjectured | +431 | 18,533, 172, 1/108 | 20, 151, 283 | 21,072 | 36,022 | 6,831 | **63,964** | 63,040 |

Next-best proven `R_TX` with 431: n = 37,066 (238.1 KB); larger n add prover work for < 1 KB: the gain flattens at
rate ≈ 1/40 because t → 112 as the rate → 0 (factor → 1/2) and the test polynomials (≈ 101 KB, 44 %) do not
shrink with the rate. The first model (`runs/p0-params.txt`) had 3 base blinding rows and k | n; its
298 / 112 KB `R_TX` estimates were 2 % / 1 % below the measured 2/19/43 build (305 / 113 KB).

## 6. Measurements [measured]

### 6.1 Native (`runs/l2-<regime>-r431-<0|1>.jsonl`, `-time.txt`; 3 proofs, 100 honest verifies, 12 mutation kinds × 40 per relation)

| Relation | Regime | Radices | n, k, t, ℓ, m | Proof B (polys / columns / Merkle) | Prove p50 | Peak heap / max RSS | Verify p50 / p99 honest | Verify p99 adversarial | Accepted / panics | Bits query / prox / lin |
|---|---|---|---|---|---|---|---|---|---|---|
| `R_REG` | proven | +431 | 32,756, 817, 121, 695, 63 | 186,970 (100,896 / 58,322 / 27,712) | 375 ms | 25.9 MB / 47 MB | 7.12 / 7.64 ms | 1.22 ms | 0 / 0 of 480 | 128.5 / 146.0 / 155.4 |
| `R_TX` | proven | +431 | 32,756, 817, 121, 695, 125 | 230,392 (100,896 / 102,480 / 26,976) | 669 ms | 43.2 MB / 47 MB | 9.81 / 10.46 ms | 1.61 ms | 0 / 0 of 480 | 128.5 / 145.0 / 154.4 |
| `R_REG` | proven | 2/19/43 | 6,536, 817, 166, 650, 83 | 224,360 (101,976 / 98,728 / 23,616) | 170 ms | 9.0 MB / 20 MB | 9.34 / 9.97 ms | 1.06 ms | 0 / 0 | 128.6 / 147.9 / 155.2 |
| `R_TX` | proven | 2/19/43 | 6,536, 817, 166, 650, 165 | 305,080 (101,976 / 179,416 / 23,648) | 292 ms | 15.8 MB / 20 MB | 13.08 / 17.03 ms | 1.58 ms | 0 / 0 | 128.6 / 146.9 / 154.2 |
| `R_REG` | conjectured | +431 | 18,533, 172, 20, 151, 283 | 63,040 (21,072 / 36,040 / 5,888) | 816 ms | 46.5 MB / 54 MB | 1.47 / 2.11 ms | 0.57 ms | 0 / 0 | 131.1 / 144.7 / 155.4 |
| `R_TX` | conjectured | +431 | 18,533, 344, 24, 319, 287 | 92,072 (41,808 / 43,824 / 6,400) | 932 ms | 49.5 MB / 54 MB | 3.18 / 3.51 ms | 0.82 ms | 0 / 0 | 130.1 / 144.6 / 154.3 |
| `R_REG` | conjectured | 2/19/43 | 6,536, 172, 27, 144, 303 | 79,478 (21,240 / 51,894 / 6,304) | 247 ms | 18.8 MB / 24 MB | 1.63 / 1.74 ms | 0.66 ms | 0 / 0 | 130.8 / 146.1 / 155.4 |
| `R_TX` | conjectured | 2/19/43 | 6,536, 344, 35, 308, 287 | 113,414 (42,072 / 63,910 / 7,392) | 295 ms | 20.1 MB / 24 MB | 3.59 / 4.31 ms | 1.08 ms | 0 / 0 | 129.8 / 146.2 / 154.3 |

Max RSS is the whole bench process (both relations). Sizes vary by up to ≈ 1.5 KB with the prover's randomness (the
number of distinct opened columns and the multiproof depend on the transcript): `R_TX` proven 230,392 B here,
231,950 B with seed 1 (`runs/l1-tests.txt`). The verifier's length bound (t distinct columns, full paths) is 262,350 B
(`R_TX` proven, radix 431).

### 6.2 wasm32 (`runs/l2-<regime>-r431-<0|1>-wasm.jsonl`; node v26.8.1, 2 proofs, 50 honest verifies, 12 × 4 mutations per relation, all made in wasm)

| Relation | Regime | Radices | Prove mean | Verify p50 / p99 honest | Verify p99 adversarial | Linear memory | Fails |
|---|---|---|---|---|---|---|---|
| `R_REG` | proven | +431 | 838 ms | 31.3 / 33.4 ms | 1.06 ms | 28 MiB | 0 |
| `R_TX` | proven | +431 | 1,422 ms | 48.7 / 55.9 ms | 1.50 ms | 46 MiB | 0 |
| `R_REG` | proven | 2/19/43 | 389 ms | 43.1 / 46.6 ms | 1.17 ms | 11 MiB | 0 |
| `R_TX` | proven | 2/19/43 | 603 ms | 67.3 / 72.4 ms | 1.79 ms | 19 MiB | 0 |
| `R_REG` | conjectured | +431 | 1,634 ms | 5.43 / 5.87 ms | 0.81 ms | 48 MiB | 0 |
| `R_TX` | conjectured | +431 | 1,878 ms | 14.7 / 16.8 ms | 1.06 ms | 52 MiB | 0 |
| `R_REG` | conjectured | 2/19/43 | 537 ms | 6.15 / 7.29 ms | 0.75 ms | 21 MiB | 0 |
| `R_TX` | conjectured | 2/19/43 | 674 ms | 16.2 / 17.6 ms | 1.03 ms | 22 MiB | 0 |

wasm32 module 252,947 B (`wasm_bytes` in the run files; build log `runs/l2-wasm-build.txt`). The wasm32 proofs for seed 1 have the same lengths as the native
seed-1 proofs of `runs/l1-tests.txt` (187,994 / 231,950 B proven, 63,008 / 92,552 B conjectured, radix 431), and
the same FNV-1a: native and wasm32 proofs are byte-identical (`runs/l3-probe-fnv-seed1-*.jsonl` [probe]:
d87fb536, 1f45a7c8, ad8e8177, 0de4da9a).

### 6.3 The radix-431 stage and its cost

The 431 stage costs 432 products per point and dominates the encoding (n = 32,756 = 2²·19·431: 458 products per
point). The first build (`runs/l0-tests.txt`) proved `R_TX` proven in 4.10 s, `R_REG` 2.32 s, conjectured 5.1–5.3 s.
Placing 431 as the deepest DIT stage, where the inputs are the zero-padded coefficients (≈ k / (n/431) ≈ 11 nonzero
of 431 per group), and skipping zero inputs there cut this to 0.66 / 0.39 / 0.83–0.94 s (`runs/l1-tests.txt`),
identical proofs. Prove time with 431 is now 2.3× the 2/19/43 build's, at 13–28 % fewer bytes.

### 6.4 Tests (`runs/l1-tests.txt`; `runs/l0-tests.txt` before the FFT pruning, `runs/l1-tests-failed-n1-index.txt` a test-indexing bug of the FFT unit test, fixed)

Unit: F_q / F_{q^4} arithmetic against naive, 3 generates F_q^*, FFT against the naive DFT for every radix incl. 431
(dense and zero-padded inputs, coset, inverse; n up to 32,756), ring-row recurrence against the naive sum (K = 64, 16),
multiproof round trip. Integration (`tests/attacks.rs`): honest proofs for all 8 presets verify; wrong op, swapped
proofs and other parameters rejected; two seeds give different proofs; **960 mutated inputs** (`client::mutate`, 12
kinds × 40 × 2 relations) **0 accepted, 0 panics**; the negative witnesses of `pqzh/tests/attacks.rs` (ℓ2 norm with
small coefficients, coefficient out of range, digit out of range, e2 norm, overspend, fee word ≥ 2^64) plus a wrong
ring row: the honest prover refuses each, and an unchecked proof does not verify. The benches add 3 × 960 more
mutations (§6.1), 0 accepted.

## 7. Comparison

### 7.1 Model vs measurement

| `R_TX` | Model proof B | Measured B | Model verifier products | Verify p50 native | ns / product |
|---|---|---|---|---|---|
| proven, +431 | 235,324 | 230,392 (−2.1 %) | 8.75 M | 9.81 ms | 1.12 |
| proven, 2/19/43 | 310,948 | 305,080 (−1.9 %) | 13.0 M | 13.1 ms | 1.00 |
| conjectured, +431 | 93,639 | 92,072 (−1.7 %) | 1.33 M | 3.18 ms | — (fixed costs dominate) |
| conjectured, 2/19/43 | 114,653 | 113,414 (−1.1 %) | 1.88 M | 3.59 ms | — |

The first note's estimates (§1 of the p0 version: ≈ 298 KB proven / ≈ 112 KB conjectured, verify 15–40 / 3–8 ms,
prove 0.1–0.3 s) hold for the 2/19/43 build (305 KB / 113 KB, 17.0 / 4.3 ms p99, 0.29 / 0.30 s). The modelled prover
work (2.1·10^9 products with 431) does not know the pruning; measured 0.67 s.

### 7.2 Ligero vs FRI+ZK STARK (Goldilocks⁵, `pqzh-zk-ext5.md` §4, blowup 16)

| | STARK `R_TX` | Ligero `R_TX` (+431) | Ratio | STARK `R_REG` | Ligero `R_REG` (+431) |
|---|---|---|---|---|---|
| Proof, proven | 622,448 B | 230,392 B | 0.37 | 468,231 B | 186,970 B |
| Proof, conjectured | 340,431 B | 92,072 B | 0.27 | 255,906 B | 63,040 B |
| Prove native (proven) | 20.44 s | 0.67 s | 1/30 | 10.37 s | 0.38 s |
| Peak heap (proven) | 2,824 MB | 43 MB | 1/65 | 1,486 MB | 26 MB |
| Verify p99 native, proven / conj. | 19.1 / 15.5 ms | 10.5 / 3.5 ms | 0.55 / 0.23 | 11.1 / 10.9 ms | 7.6 / 2.1 ms |
| Verify p99 wasm32, proven / conj. | 28.7 / 24.1 ms | 55.9 / 16.8 ms | 1.95 / 0.70 | 16.5 / 12.7 ms | 33.4 / 5.9 ms |
| Prover in wasm32 | not measured at blowup 16 (wasm32 runs verified native proofs) | 1.4 s, 46 MiB | — | — | 0.84 s, 28 MiB |
| Soundness accounting | per term ≥ 128 (Keccak collision binding) | same | | | |

The STARK numbers are its §4 table (Plonky3 0.8.0; 0.9.0-rc.1 repeat for conjectured: 344,239 B). Where the proven
Ligero verifier spends its time [inference]: ≈ 6.4 M F_{q^4} × F_q products for the 19 interpolated combination
vectors at 120 columns, ≈ 2 M for evaluating w, q, h — u64 × u64 → u128 products that wasm32 emulates.

## 8. Recommendation [inference]

**Ligero over F_q with the radix-431 domains is the better PQZH backend on this evidence**: at equal 128-bit (per term)
soundness and with zero knowledge it is 2.7× smaller proven (3.7× conjectured), 30× faster and 65× leaner to prove
(a wallet can prove in wasm32 in 1.4 s within 46 MiB), and faster to verify natively; the code is ≈ 1,700 lines of
own Rust (library incl. unit tests) over F_q with Keccak only (no Plonky3). Its one weak axis is wasm32 verify (55.9 ms p99 proven `R_TX`).

What it does not do: **reach 160 KB proven** — 230 KB, of which ≈ 101 KB are the three test polynomials that no rate
change shrinks. The conjectured proofs (92 / 63 KB) are well under the line. Suggested defaults if the owner adopts
it: the radix-431 proven preset (n = 32,756, k = 817, t = 121, ℓ = 695) for both relations; the conjectured preset
only if the owner accepts the conjectured regime (§5.1 caveat).

Not covered here and needed before adoption: an EVM verifier gas estimate (the verify is Keccak plus 42-bit modular
arithmetic, `mulmod`-friendly [inference]), a proofSystemId for the Ligero kind, and an independent review of §4.1.

## 9. Owner decisions 2026-10-14 and open questions

**Decisions recorded (owner, 2026-10-14, session 4; applied on this branch):**

1. **Radix-431 FFT stage for longer codes — ADD.** Domains of order 2^a·19^b·43^c·431^d (a ≤ 3; b, c, d ≤ 1) via a
   radix-431 stage, and re-run the parameter model to see whether it lowers the proven size. *Status: done* —
   `fft.rs` (radices 2, 19, 43, 431; pruned deepest stage), model p1 (`runs/p1-params.txt`): yes, proven `R_TX`
   ≈ 311 → 235 KB [estimate], measured 305,080 → 230,392 B (−24.5 %), `R_REG` −16.7 %, conjectured −19 / −21 %; prove
   time ×2.3 (§6.3).
2. **Modified ZK construction — USE** (blinding rows at full degree inside the one proximity test) instead of the
   paper's §4.7 text; write the argument why it is HVZK and sound. *Status: done* — built in `ligero.rs` (with the
   blinds in F_{q^4}, 12 base rows, which ZK needs because w, q, h have F_{q^4} coefficients), argument in §4.1,
   tests in `tests/attacks.rs`.

**Open questions for the owner** (none blocks further work):

1. Adopt Ligero over F_q as the PQZH backend in place of the FRI (or WHIR) STARK?
2. Proven `R_TX` is 230 KB, over the 160 KB line: raise the line, accept the conjectured regime (92 KB), or try the
   remaining reductions — 24 grinding bits (t 121 → 112, ≈ −9.5 KB [estimate]), 16-byte salts (≈ −1.9 KB), a smaller
   test-polynomial encoding (not explored)?
3. Does the 50 ms verify budget apply to wasm32? Native p99 is 10.5 ms; wasm32 55.9 ms (proven `R_TX`). A wasm-specific
   32-bit-limb product could close it (not done).
4. proofSystemId for the Ligero kind (the bench statements carry the STARK's id, which the relation only hashes).
5. An external review of the modified ZK construction's argument (§4.1) before adoption.

## 10. Files and how to rerun

Crate `pqz-core/pqzh/ligero/` (own `Cargo.toml` / `[workspace]`, path dependency on `pqzh` for `client`, `ring`,
`rel`; `sha3` 0.10.8): `fq.rs` (F_q, F_{q^4}, lazy sums, batch inversion), `fft.rs`, `merkle.rs`, `transcript.rs`,
`cs.rs`, `ligero.rs` (`Params::preset`, `prove`, `prove_unchecked`, `verify`, `soundness`, `breakdown`),
`src/bin/ligero_bench.rs`, `tests/attacks.rs`, `wasm/` (`lib.rs`, `run_wasm.mjs`). Runs, each alone under the lock:
`scripts/capped sh -c 'cd pqz-core/pqzh/ligero && cargo test --release --offline'`, then
`scripts/capped pqz-core/pqzh/ligero/runs/measure.sh l2` (4 native presets, wasm32 build and 4 wasm runs, `xcheck`).
The STARK crate `pqz-core/pqzh/` is unchanged on this branch (`measure.sh` reruns its `xcheck`, which builds it; its tests were not rerun since no file of it changed).
