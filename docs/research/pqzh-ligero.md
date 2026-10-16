> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH over Ligero: design, parameters and measurements (P6-PQZH, Ligero backend)

Written 2026-10-14 at the owner's request (owner decision 2026-10-14: build and measure a Ligero backend for PQZH
as the alternative to the Plonky3 STARK of `pqzh-prototype.md` / `pqzh-zk-ext5.md`). Branch `pqzh-ligero` (from main
`79924cf`, not merged). **Status: built and measured** (crate `pqz-core/pqzh/ligero/`, raw runs
`pqz-core/pqzh/ligero/runs/`, every file named below), **including a full EVM verifier** (test-only Solidity/Yul,
§11). The owner decisions of 2026-10-14 on this design (radix 431, the modified ZK construction, the proven regime
with THE preset, the Johnson-bound reference preset) are recorded in full in §9, with the controller's 256 KB proposal;
**no other decision is recorded here** (§9 lists the open questions).

**[measured]** marks a number from a run in `runs/` (machine as in `pqzh-prototype.md` §2: AMD Ryzen 5 7235HS, single
thread, every timed run alone under `scripts/capped`, 4 GB memory cap). **[estimate]** marks a number from the
parameter model `pqz-core/pqzh/ligero/ligero_params.py` (stdlib Python; outputs `runs/p0-params.txt`, the first model,
and `runs/p1-params.txt`, the model of the crate's layout). **[probe]** marks a single run, **[inference]** a
conclusion drawn here. Paper references are to the extended Ligero paper, Ames, Hazay, Ishai, Venkitasubramaniam,
*Ligero: Lightweight Sublinear Arguments Without a Trusted Setup*, ePrint 2022/1608.

## 1. Result

- **Owner decision 2026-10-14 (a): the PQZH soundness regime is PROVEN** (unique decoding, Ligero Thm 4.7 form), and
  the radix-431 preset n = 32,756, k = 817, t = 121 is THE preset: `R_TX` 230,392 B, `R_REG` 186,970 B. Conjectured
  numbers below are reference only; the Johnson-bound preset (decision (b), §5.3) is reference only and is *larger*
  in F_q^4 (`R_TX` 257,592 B).
- **Without the precompile (EVM, §11): no.** A full Solidity/Yul verifier accepts the real proofs and rejects every
  mutation, but proven `R_TX` costs 530 M gas to verify (534.6 M per transaction with the EIP-7623 calldata floor,
  31.9× the 16,777,216 cap); a hand-scheduled verifier would still need ≈ 124 M [estimate]. The precompile is
  required; with the proposed 256 KB proof limit / `MAX_INPUT` 262,144 B (proposal (c)) the proven preset fits it
  (worst case 243,150 B as first bounded here; the exact maximum is 235,470 B, §12.3).

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
  u128 products are emulated on wasm32); the proven `R_TX` p99 (55.9 ms) is within the 60 ms verify limit (owner
  2026-10-14, CTR-PQZ-09: 60 ms p99 on the chain host, also bounding wasm32; it was 50 ms), with a 7 % margin;
  natively 10.5 ms (5.7× margin).
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
SHAKE256("SCAAS-PQZH-LIGERO-RNG" ‖ rnd32 ‖ op ‖ stmt) (since §12, hedged with the witness: `SHAKE256("SCAAS-PQZH-LIGERO-RNG-V2" ‖ rnd32 ‖ u8(op) ‖ be32(len) ‖ stmt ‖ wit)`; the frozen byte layout is pq-zether.md §8.1).

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

### 5.3 Johnson-bound proven preset — reference only (owner decision (b))

**What it rests on.**

1. *Proximity:* BCIKS20 (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, *Proximity Gaps for Reed–Solomon Codes*, FOCS
   2020 / JACM 2023), correlated agreement in the list-decoding regime: Theorem 1.5 (lines) in its affine-space form
   (Theorem 1.6), the bound ethSTARK and Plonky3's `p3-security` call "Johnson". For RS[n, 2k − 1] over F_{q^4}
   (evaluation points in F_q), rate r = (2k − 1)/n, δ = 1 − √r − η, m = max(⌈√r/(2η)⌉, 3): if a random element of
   the tested affine space is δ-close with probability above ε = (m + ½)^7 / (3 r^{3/2}) · n² / |F_{q^4}|, all
   spanning words agree with codewords on one set S, |S| ≥ (1 − δ) n. Charged **once** for the affine space of the
   2m + 3 words, the best F_q^4 parameters reach 128.7 bits; charged **per spanning word** (the conservative
   accounting this note uses for the unique-decoding term) **no F_q^4 parameter reaches 128 bits** (best 124.4,
   `runs/p1-params.txt`, Johnson table).
2. *Interleaving and ZK:* the committed rows (witness rows, their degree-correction words X^{k−1} p_i, the F_q^4
   blinding rows) are one interleaved RS code tested by one random combination, as in §4.1. ZK is unchanged: it uses
   only t ≤ k − ℓ − 1 and the blinds' spaces, not δ. The degree correction needs (1 − δ) n ≥ 3k − 2 (holds:
   0.599 · 6,536 = 3,915 ≥ 2,584).
3. *Consistency tests (linear, quadratic):* the per-query factor max(1 − δ, (2k − 2)/n) needs **mutual correlated
   agreement** up to δ: every codeword δ-close to the tested combination must agree with the combination of the
   decoded rows on S, so that a prover who sends w ≠ ŵ is caught at a rate ≥ δ. In the unique-decoding regime that
   is automatic; up to the Johnson radius it is a newer kind of statement (the notion WHIR, Arnon–Chiesa–Fenzi–Yogev,
   ePrint 2024/1586, works with). **Gap:** I did not verify a proof of it up to the Johnson radius for Reed–Solomon
   codes, and none specific to Ligero's interleaved tests with ZK blinding rows. Without it the per-query term is
   δ + (2k − 2)/n (a second codeword close to the combination can match corrupted columns), and
   max(1 − δ, δ + (2k − 2)/n) is smallest at the unique-decoding radius: the Johnson regime then gains nothing.

**Preset** (`Params::johnson_preset`, `ligero_params.py` `johnson`): n = 6,536, k = 862 (rate ≈ 1/7.6), m = 3,
η = √r/6, per-query factor 0.599, t = 152, ℓ = 709; field term 128.7 bits (once), query 128.4 bits. Measured
[`runs/l4-johnson*.jsonl`]: `R_TX` 257,592 B, prove 608 ms, verify p99 12.2 ms native / 60.3 ms wasm32; `R_REG`
203,768 B; 960 mutations, 0 accepted (§6).

**Why reference only:** (i) in F_q^4 it is *larger* than the unique-decoding preset (257.6 vs 230.4 KB for `R_TX`):
the list-decoding error grows as n² (m + ½)^7 / r^{3/2}, so 128 bits force a short code (n = 6,536) at a high rate,
and t stays at 152; (ii) its field term clears 128 bits only when the BCIKS20 error is charged once for the whole
affine space; (iii) it relies on mutual correlated agreement up to the Johnson radius for Ligero's consistency tests
with ZK blinds — newer, with larger error terms, and less vetted for interleaved Ligero with ZK than the
unique-decoding argument of §4.1. A larger challenge field (F_{q^5} / F_{q^6}) would relax (i)–(ii); not built.

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
| `R_REG` | Johnson (reference) | 2/19/43/431 | 6,536, 862, 152, 709, 63 | 203,768 (107,040 / 73,264 / 23,424) | 342 ms | 7.7 MB / 17 MB | 8.62 / 9.56 ms | 1.08 ms | 0 / 0 | 128.4 / 128.7 (BCIKS once) / 155.4 |
| `R_TX` | Johnson (reference) | 2/19/43/431 | 6,536, 862, 152, 709, 124 | 257,592 (107,040 / 128,048 / 22,464) | 608 ms | 12.5 MB / 17 MB | 11.57 / 12.21 ms | 1.34 ms | 0 / 0 | 128.4 / 128.7 (BCIKS once) / 154.4 |

The Johnson rows are `runs/l4-johnson.jsonl` / `-time.txt` (same bench settings); their proximity term is the BCIKS20
list-decoding error (§5.3), not (2m + 3) n / |F|.

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
| `R_REG` | Johnson (reference) | 2/19/43/431 | 713 ms | 39.2 / 57.4 ms | 1.31 ms | 10 MiB | 0 |
| `R_TX` | Johnson (reference) | 2/19/43/431 | 1,259 ms | 57.8 / 60.3 ms (above the 60 ms limit) | 1.51 ms | 15 MiB | 0 |

Johnson rows: `runs/l4-johnson-wasm.jsonl`.

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
own Rust (library incl. unit tests) over F_q with Keccak only (no Plonky3). Its one weak axis is wasm32 verify (55.9 ms p99 proven `R_TX`, inside the 60 ms limit of CTR-PQZ-09 with 7 % to
spare).

What it does not do: **reach 160 KB proven** — 230 KB, of which ≈ 101 KB are the three test polynomials that no rate
change shrinks. With the owner's decision (a) (proven regime, THE preset n = 32,756, k = 817, t = 121, ℓ = 695 for both
relations) the controller's proposal (c) — PQZH proof limit 160 KB → 256 KB, precompile `MAX_INPUT` 262,144 B — fits
it: the largest possible proven proof (t distinct columns, every multiproof level at its maximum) is 243,150 B for
`R_TX` and 198,138 B for `R_REG`; measured 230,392 / 186,970 B. (Those two are upper bounds: a level of the
multiproof cannot send t siblings once its distinct nodes start to pair up; the exact maxima are 235,470 / 190,458 B,
§12.3.) (The Johnson reference preset could exceed it: worst
case 273,288 B for `R_TX`.)

**It needs the precompile**: without it (§11) proven `R_TX` costs ≈ 32× the transaction cap as measured and ≈ 7× at
an opcode floor; no tuning, parameter choice or local protocol change closes that. Still needed before adoption: a
proofSystemId for the Ligero kind and an independent review of §4.1.

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
3. **(a) Soundness regime = PROVEN** (owner, 2026-10-14), using the unique-decoding analysis of §4.1 / §5.1 (Ligero
   Thm 4.7 form): the radix-431 preset n = 32,756, k = 817, t = 121 is THE preset (`R_TX` 230,392 B, `R_REG`
   186,970 B). Conjectured is not used (it rests on the up-to-capacity conjecture, disproved in general by
   Crites–Stewart, ePrint 2025/2046); its numbers stay as reference. *Status: recorded; `Params::preset(op, true,
   true)` is that preset; the note's tables mark conjectured as reference.*
4. **(b) Johnson-bound proven preset — add as documentation / reference only**: soundness from the list-decoding
   proximity gaps (BCIKS20-style, field-size error terms in F_q^4), stating exactly the theorem and the interleaved /
   ZK conditions relied on and any gap in applying it to Ligero's tests; extend `ligero_params.py`; measure it like
   the others (sizes, prove, verify native + wasm32, 960 mutations) and include it in the EVM gas table; say why it is
   reference only (newer, larger error terms, less vetted for interleaved Ligero with ZK). *Status: done* — §5.3
   (theorem, conditions, the mutual-correlated-agreement gap), `ligero_params.py` Johnson table,
   `Params::johnson_preset` (n = 6,536, k = 862, t = 152), `runs/l4-johnson*` (960 mutations, 0 accepted), EVM rows
   in §11.
5. **(c) Controller proposal (not an owner decision): PQZH proof limit 160 KB → 256 KB, precompile `MAX_INPUT`
   262,144 B**, so that the proven preset fits. Recorded as a proposal; the proven worst cases are 243,150 B (`R_TX`)
   and 198,138 B (`R_REG`) (§8).
6. **EVM verifier (owner correction 2026-10-14):** the 2026-10-13 ruling "no chain needs PQZH without the precompile,
   build no Solidity verifier" is **withdrawn**; if PQZH fits the limits on a chain without the precompile it will be
   used there. *Status: measured* (§11): it does not fit, in any regime.

**Open questions for the owner** (none blocks further work):

1. Adopt Ligero over F_q as the PQZH backend in place of the FRI (or WHIR) STARK?
2. The 160 KB line: adopt proposal (c) (256 KB / `MAX_INPUT` 262,144 B)? Remaining size reductions if wanted:
   24 grinding bits (t 121 → 112, ≈ −9.5 KB [estimate]), 16-byte salts (≈ −1.9 KB).
3. ~~Does the 50 ms verify budget apply to wasm32?~~ **Resolved** by the owner's ruling of 2026-10-14 (CTR-PQZ-09,
   `docs/contracts/pq-zether.md`, `docs/decisions.md`): the verify limit is 60 ms p99 on the chain host and also bounds
   wasm32. Ligero's proven `R_TX` (55.9 ms wasm32, 10.5 ms native) passes; no wasm-specific multiply is needed.
4. proofSystemId for the Ligero kind (the bench statements carry the STARK's id, which the relation only hashes).
5. An external review of the modified ZK construction's argument (§4.1) before adoption.
6. PQZH on chains without the precompile: §11 says Ligero cannot serve them (nor, for proven + ZK, the STARK of
   `pqzh-solidity-verifier.md`). Accept that PQZH needs the precompile, or fund a different design for such chains
   (e.g. a succinct-verifier proof system or recursion)?

## 10. Files and how to rerun

Crate `pqz-core/pqzh/ligero/` (own `Cargo.toml` / `[workspace]`; until P6e branch `p6e-b1` a path dependency on
`pqzh` for `client`, `ring`, `rel`, since then only `sha3` 0.10.8, §12.1): `fq.rs` (F_q, F_{q^4}, lazy sums, batch inversion), `fft.rs`, `merkle.rs`, `transcript.rs`,
`cs.rs`, `ligero.rs` (`Params::preset`, `prove`, `prove_unchecked`, `verify`, `soundness`, `breakdown`),
`src/bin/ligero_bench.rs`, `tests/attacks.rs`, `wasm/` (`lib.rs`, `run_wasm.mjs`). Runs, each alone under the lock:
`scripts/capped sh -c 'cd pqz-core/pqzh/ligero && cargo test --release --offline'`, then
`scripts/capped pqz-core/pqzh/ligero/runs/measure.sh l2` (4 native presets, wasm32 build and 4 wasm runs, `xcheck`).
The STARK crate `pqz-core/pqzh/` is unchanged on this branch (`measure.sh` reruns its `xcheck`, which builds it; its tests were not rerun since no file of it changed).
EVM (§11): `src/bin/ligero_export.rs` (fixtures), `evm_model.py`, `runs/evm.sh` (tests, Johnson bench + wasm32,
fixtures, forge), `runs/forge.sh`; Solidity in `smartcontracts/evm/test/pqzh/ligero/`, fixtures in
`smartcontracts/evm/test/vectors/pqzh-ligero/`.

## 11. EVM verifier without the precompile

Owner correction 2026-10-14 (§9, item 6): the 2026-10-13 ruling "build no Solidity verifier" is withdrawn; if PQZH fits
the limits on a chain without the precompile it will be used there. The question measured here: **does one transaction
carrying a Ligero proof verify under the EIP-7825 cap of 16,777,216 gas**, with the EIP-7623 calldata floor? Layout as
`pqzh-solidity-verifier.md`: test-only code, never deployed; the transaction model is that note's (21,000 + max(4
tokens + execution, 10 tokens), with the operation's other calldata and execution from pq-zether.md §9.3: transfer
119 k tokens and 0.31 M, register 67 k tokens and 3.45 M including the SSTORE2 of the key).

### 11.1 Result: no, in any regime

| Relation | Preset | t | Proof B | Verify gas [measured] | Proof calldata floor (EIP-7623) | Tx gas (EIP-7623) | × cap | Tx gas at the opcode floor [estimate] | × cap |
|---|---|---|---|---|---|---|---|---|---|
| `R_TX` | **proven (THE preset)** | 121 | 231,950 | 530.2 M | 9.00 M | 534.6 M | 31.9 | 124.2 M | 7.4 |
| `R_REG` | **proven (THE preset)** | 121 | 187,994 | 323.8 M | 7.31 M | 330.5 M | 19.7 | 79.9 M | 4.8 |
| `R_TX` | conjectured (reference) | 24 | 92,552 | 176.7 M | 3.59 M | 179.0 M | 10.7 | 35.4 M | 2.1 |
| `R_REG` | conjectured (reference) | 20 | 63,008 | 64.9 M | 2.44 M | 69.6 M | 4.1 | 17.7 M | 1.05 |
| `R_TX` | Johnson (reference) | 152 | 258,264 | 644.9 M | 10.01 M | 649.7 M | 38.7 | 152.8 M | 9.1 |
| `R_REG` | Johnson (reference) | 152 | 201,588 | 403.4 M | 7.83 M | 410.3 M | 24.5 | 98.8 M | 5.9 |

[measured: `runs/l6-forge.txt` (`test_gas_*`: verify gas inside `verify`, proof tokens, the transaction line);
floor: `runs/e1-evm-model.txt`.] Proofs are the seed-1 fixtures (`ligero_export`), so sizes differ by ≤ 1.6 KB from
§6's seed-2 benches.

Decide-ready [inference]:

- **Proven `R_TX` does not fit without the precompile**: 31.9× the cap as measured; even a hand-scheduled verifier
  (every value on the stack) needs ≈ 124 M, 7.4× the cap. The proof's calldata floor alone is 9.0 M (54 % of the
  cap), 10.2 M with the transfer's other calldata, which leaves ≈ 12.4 M of execution for the verifier.
- **Proven `R_REG` does not fit either**: 19.7× measured, ≈ 4.8× at the floor.
- The reference presets do not fit: conjectured `R_REG` is the closest (≈ 17.7 M at the floor, 5 % over; 69.6 M as
  measured); Johnson is worse than proven.
- **PQZH-Ligero therefore needs the precompile.** The STARK route does not fill the gap for the decided regime: proven
  + ZK `R_TX` was ≈ 21.4 M even at its floor (`pqzh-solidity-verifier.md` §1).

### 11.2 What was built [measured]

- `smartcontracts/evm/test/pqzh/ligero/LigeroVerifier.sol`: a full port of `ligero.rs` verify and `cs.rs` comb —
  Keccak-256 transcript and seed, the 16-bit proof of work, query indices, canonical checks of every field element,
  salted leaves and the pruned Keccak multiproof, statement parsing as rel.rs (length, canonical coefficients, fee
  word < 2^64), the layout, the linear test's combination (ring blocks with the `f_m` recurrence, e-terms, rows 3–7,
  norms, bit decompositions), the sum check, and per opened column the proximity, linear and quadratic identities with
  the twelve ZK blinding rows. F_q^4 is one packed word (four 64-bit lanes); lazy sums use two words of 128-bit
  lanes. Runtime code 18,177 B (under EIP-170). `scripts/size_gate.py` checks `forge build src` only, so it does not
  apply to these test contracts. The matrix A (393,216 B, canonical 6-byte coefficients) sits in 16 data contracts of
  24,576 B (EIP-170-sized, so valid on mainnet-style chains too) and is copied to memory once per verify.
- Fixtures: `ligero_export` writes the same statement and proof bytes the Rust verifier takes
  (`smartcontracts/evm/test/vectors/pqzh-ligero/`, 3.8 MB): A, the six honest proofs (+ a proof of the statement with
  byte 0 flipped, for the `other_proof` kind), and seven invalid-witness proofs made with `prove_unchecked`.
- `LigeroTest.t.sol` [`runs/l6-forge.txt`]: all six honest proofs accepted. 12 mutation kinds (pqzh
  `client::mutate`, adapted to this proof format) × 9 per relation and preset = **648 mutated inputs, 0 accepted,
  0 reverts**. The **7 invalid witnesses** (`R_REG`: ℓ2 norm exceeded with small coefficients, a coefficient out of
  range; `R_TX`: ℓ2 norm, digit out of range, e2 norm, overspend, a wrong ring row) are **all rejected**, each by the
  linear or quadratic test after a full verification. Earlier forge runs are kept as `runs/l4-forge-failed-compile.txt`
  and `runs/l5-forge-failed-test-overflow.txt` (a uint8 overflow in the test's own mutation code, fixed).

### 11.3 Where the gas goes [measured, `runs/l6-forge.txt`]

| Stage (M gas) | `R_TX` proven | `R_REG` proven | `R_TX` conjectured | `R_REG` conjectured |
|---|---|---|---|---|
| statement checks + Keccak seed | 0.90 | 0.18 | 0.90 | 0.18 |
| transcript, proof of work, query indices | 4.20 | 3.77 | 2.98 | 2.57 |
| columns (canonical checks, leaves) + Merkle multiproof | 2.71 | 2.09 | 0.91 | 0.75 |
| copy of A from the data contracts | 1.00 | 0.87 | 0.87 | 0.72 |
| combination, ring blocks (the statement-matrix work) | 98.77 | 31.06 | 98.64 | 30.93 |
| combination, rest + linear sum check | 5.36 | 1.76 | 4.93 | 0.84 |
| **per-column checks** | **417.21** | **284.09** | 67.49 | 28.92 |
| total | 530.16 | 323.82 | 176.72 | 64.90 |

Unit costs (`LigeroUnits.t.sol`, same file): F_q^4 × F_q multiply-accumulate 180 gas (an 8×-unrolled pointer loop:
160), test-polynomial coefficient 213, power 88, Lagrange slot 346, column row sum 194, quadratic triple 380, F_q^4
product 598, A-pass term 284, ring recurrence step 3,923. The model built from these counts reproduces every measured
verify within −4.5 to −7 % (`runs/e1-evm-model.txt`).

- **Dominant: the per-column checks** (79 % of proven `R_TX`, 88 % of proven `R_REG`). At each opened column the
  verifier evaluates the linear test's combination vectors at η_j (one multiply-accumulate per witness value that has
  a statement coefficient: ≈ 10,500 for `R_TX`, ≈ 4,800 for `R_REG`) and the three test polynomials (4,204
  coefficients), for 121 columns: 1.78 M (`R_TX`) / 1.09 M (`R_REG`) multiply-accumulates. At ≥ 40 gas each, that is
  ≥ 71 M / 44 M gas whatever the code. This is Ligero's verifier — linear in the circuit times t — meeting an EVM
  where a 42-bit multiply-accumulate costs tens of gas.
- **Second: the statement matrix** (19 % of `R_TX`): two passes over A (2 × 65,536 multiply-accumulates) and 12,288
  recurrence steps — ≈ 15.6 M even at the floor for `R_TX` (5.3 M for `R_REG`), more than the 12.4 M of execution the
  cap leaves next to the proven `R_TX` calldata.
- Keccak (transcript, leaves, multiproof) is ≤ 1.5 %.

### 11.4 Fixes considered [estimate, `evm_model.py`]

| Fix | What it changes | Proven `R_TX` tx gas | Fits? |
|---|---|---|---|
| None (this code) | — | 534.6 M | no |
| Hand-scheduled Yul/Huff (opcode floor) | ÷ 4.4 on execution | 124.2 M | no |
| Parameter choice (the cheapest (n, k) over the grid) | fewer test-polynomial coefficients per column (k = 431) against more bytes | 110.5 M (floor), n = 18,533, k = 431, t = 120, 304 KB | no |
| Preprocessed statement commitment for A | at most the A passes (≈ 6.6 M at the floor) | ≥ 118 M | no |
| Protocol variant: the prover sends R_i(η_j) for the 19 interpolated vectors; one batched tensor check replaces the witness-sized term per column | −1.27 M multiply-accumulates; +55 KB of calldata (+2.2 M floor) | ≈ 60 M (floor: 40 M per-column, 15.6 M statement, 4.9 M calldata) | no |
| + a polynomial commitment for w, q, h (an FRI / WHIR opening instead of evaluating them at t points) | removes the 4,204-coefficient term; a different proof system | statement ≈ 15.6 M > the 12.4 M left by the calldata | no |

No change inside this design brings proven `R_TX` under the cap; the decided regime puts t ≥ 112 for every rate,
and each opened column costs work linear in the witness. Execution the cap can absorb is bounded by the calldata: under
EIP-7623, 4 tokens per proof byte leave ≈ 12.4 M of execution for proven `R_TX`.

### 11.5 Which preset minimises the total

From the grid of `runs/e1-evm-model.txt` (smallest transaction per regime; size model p1, units of §11.3):

| Relation | Regime | Verifier | n | k | t | Proof B | Tx gas |
|---|---|---|---|---|---|---|---|
| `R_TX` | proven | this code | 18,533 | 344 | 119 | 378,347 | 443.7 M |
| `R_TX` | proven | floor | 18,533 | 431 | 120 | 304,006 | 110.5 M |
| `R_REG` | proven | this code / floor | 32,756 | 344 | 116 | 227,319 | 221.7 / 59.4 M |
| `R_TX` | conjectured | this code / floor | 18,533 | 344 | 24 | 93,639 | 167.0 / 35.4 M |
| `R_REG` | conjectured | floor | 18,533 | 152 | 19 | 64,002 | 17.4 M |
| `R_TX` / `R_REG` | Johnson | floor | 3,448 | 172 / 152 | 78 / 74 | 479,715 / 279,784 | 87.0 / 44.2 M |

The gas-optimal presets are smaller-k, larger-proof versions of the size-optimal ones (a smaller k shortens the three
test polynomials evaluated at every column, at the price of more rows per column). The best gives 110 M against
124 M for THE preset. **The choice of preset does not change the conclusion.**

### 11.6 Rerun

```sh
scripts/capped pqz-core/pqzh/ligero/runs/evm.sh l4      # Rust tests, Johnson bench + wasm32, fixtures, forge
scripts/capped pqz-core/pqzh/ligero/runs/forge.sh l6    # forge only (verifier + unit costs)
python3 pqz-core/pqzh/ligero/evm_model.py > pqz-core/pqzh/ligero/runs/e1-evm-model.txt
```

## 12. P6e Part B: all five relations, the hedged prover, no Plonky3 dependency

Branch `p6e-b1` (from main `9e7cd20`), plan `docs/superpowers/plans/2026-10-14-p6e-relations.md` Task 8 (G6) without
`R_TX0`, the Ligero half of D6, and the part of Task 6 that does not need `pqz-stmt`. Results, not decisions (the
decision lines are in `docs/decisions.md`, CTR-PQZ-09 and CTR-PQZ-19). Runs `runs/l7-*` (`runs/rel5.sh l7`, one capped
session) and one probe, `runs/l7-probe-wasm-tx-repeat.jsonl`; after the controller's review, `runs/l8-*` and `runs/l9-*`
(`runs/gateb.sh`, `l8` before its native-FNV step was added: the added tests, the gate-B wasm32 measurement before and after the wasm32 multiply, §12.3).

### 12.1 What changed

- **Relations (`cs.rs`).** `R_BURN`, `R_DS`, `R_DR` as Ligero constraint systems on pqz-core's statement and witness
  bytes (`pqz_rel.c`, `pq-zether.md` §7.5 / §7.9), with every exact ℓ2 bound and bit range pqz-core proves:

  | Relation | Equations | Big groups | Small values (count, bits) | m at THE preset |
  |---|---|---|---|---|
  | `R_BURN` (op 2, also REFRESH) | `R_TX` rows 1, 2, 4, 6, 7 with d = digits(amount) public: pk_f = A s_f + e_f; u = Aᵀr + e1; v_f = pk_fᵀr + e2_f + Δ d′; u_Tᵀs_f + Δ M + e_T = v_T; M_i + c_{i−1} − d′_i − 16 c_i = f_i + d_i, c_15 = 0 | s_f, e_f, r, e1 | e2_f (16, 8), d′ (16, 4), M (16, 14), c (16, 11), e_T (16, 25), 5 ℓ2 slacks | 124 |
  | `R_DS` (op 4) | u = Aᵀr + e1; pkᵀr + e2 = v − Δ d (16 coefficients) | r, e1 | e2 (16, 8), 3 ℓ2 slacks | 63 |
  | `R_DR` (op 5, also AUDITOR) | pk = A s + e; uᵀs + e′ = v − Δ d (16 coefficients), e′ + 2^24 in 25 bits | s, e | e′ (16, 25), 2 ℓ2 slacks | 63 |

  The statement checks are pqz-core's: exact length, canonical coefficients, fee / amount words < 2^64 (`R_BURN` reads
  fee at 256 and amount at 288, the disclosures amount at 224); the rest of a statement (opTag, id, `kind`, the other
  header words) is only hashed into the transcript. `R_TX` and `R_BURN` share one builder (as `build_debit` in C); the
  combination vectors of `R_REG` and `R_TX` are unchanged, so the earlier `R_REG` / `R_TX` proofs (the EVM fixtures of
  §11) still verify (`tests/attacks.rs` `evm_fixtures`, run before the re-export). REFRESH and AUDITOR differ from
  op 2 / op 5 only in hashed bytes and need no relation of their own. `R_TX0` (auditor off, G1) is not built: its
  statement layout comes with PQZL Task 2.
- **Hedging (D6).** The prover RNG is `SHAKE256("SCAAS-PQZH-LIGERO-RNG-V2" ‖ rnd32 ‖ u8(op) ‖ be32(len(stmt)) ‖ stmt
  ‖ wit)` (was `"SCAAS-PQZH-LIGERO-RNG" ‖ rnd32 ‖ u8(op) ‖ stmt`). The verifier is unchanged; every PQZH proof byte
  changes once. Unit test `rng_hedged_with_witness`: equal inputs give equal masks; a witness differing in one bit
  gives 256 masks of which none agrees; the statement length is framed.
- **No Plonky3 dependency (Task 6 prep).** The crate's only dependency is `sha3` (`Cargo.toml`, `wasm/Cargo.toml`;
  neither `Cargo.lock` lists a `p3-*` crate). It carries copies of the Plonky3 crate's `ring` (without the Goldilocks NTT),
  statement constants (`stmt.rs`, extended to the five relations) and test client (`client.rs`: the `pqz_bench.c`
  setup for all five, `mutate`, `Tweak`); the Plonky3 crate is untouched. Left for Task 6 once `pqz-stmt` exists:
  replace `stmt.rs` and the codec half of `ring.rs` (`rd_poly`, `rd_polyvec`, `wr_poly`, the layout constants, both
  ids) by `pqz-stmt`; keep `a_matrix` / `dot_int` / `modq` (or take them from `pqz-stmt` if it carries A); move
  `client.rs` to test support (`tests/support.rs`) — the bench binaries, `ligero_export`, the wasm module and the
  `dump_setup` example use it too, so it must stay reachable from them (the `bench` feature below is the obvious place,
  with `soundness()`, D11).
- **Feature `bench` (review item 5).** `Params::proven()` is THE preset and the only one without the feature;
  `Params::preset` (conjectured, proven without radix 431) and `Params::johnson_preset` are behind `bench`, as are the
  two bench binaries and `tests/attacks.rs`. `bench` is a default feature; a production user (`pqz-ffi`, Task 7)
  depends with `default-features = false`. The library and its unit tests build and pass that way
  (`runs/l8-nobench.txt`, `l9-nobench.txt`). `Params::new(n, k, proven)` stays public.
- **wasm32 multiply (review item 3, after `l8`).** wasm32 has no 64 × 64 → 128-bit multiply, so every u128 product
  was a `__multi3` call. On wasm32 the F_q product, the F_{q^4} product and the lazy sums (`Acc4`) now use 21-bit
  pieces in u64 (`fq.rs` `limb`: a b = h 2^42 + m 2^21 + l, reduced with 2^42 = 215; a lazy sum holds at most 2^20
  terms, the largest in use is 1,633); native keeps the u128 path. Same canonical values, so the proofs are
  byte-identical: unit test `limb_matches_u128` (20,000 products and F_{q^4} products, sums of 1 to 2^20 terms, edge
  values) and the FNV of the seed-1 proofs of all five relations, native (`runs/l9-native-fnv.jsonl`) = wasm32
  (`runs/l9-proven-wasm.jsonl`) = the wasm32 proofs before the change (`runs/l8-proven-wasm.jsonl`): `b68d0484`,
  `47ead576`, `4801b383`, `a1d5885d`, `9da9d5d5`. The FFT (prover only) still uses u128.
- **Exact maximum (G7, measured here, the verifier's bound is Task 9).** `Params::max_len_exact(op)`: t distinct
  columns and the largest pruned multiproof. With a_l distinct nodes on tree level l (a_0 = t, a_d = 1) level l sends
  2 a_{l+1} − a_l siblings, so the total is Σ_{0<l<d} a_l + 2 − t, largest at a_l = min(t, ⌈n / 2^l⌉): 975 digests at
  THE preset, against t·d = 1,815 in the verifier's current bound. Unit test `max_len_exact_multiproof_tight`: evenly
  spread columns reach it, 300 random column sets never exceed it.
- **Cross-check.** `pqz-core/pqzh/xcheck/ligero.sh`: the Ligero crate's statements and witnesses of all five relations
  equal pqz-core's `pqz_bench.c` setup byte for byte (`runs/l7-xcheck.txt`, 10 of 10 equal).

### 12.2 Tests [measured, `runs/l7-tests.txt`; with the review's additions `runs/l8-tests.txt`, `l9-tests.txt`]

9 unit tests and 14 integration tests (`tests/attacks.rs`), all pass (`l9`; `l7` had 8 and 11). Integration: honest proofs of all five relations
verify at the proven and conjectured presets with and without radix 431 and at the Johnson preset, each proof
≤ `max_len_exact`; equal inputs give equal proofs, other seeds other proofs; every proof is rejected under each of the
other four ops (`R_DS` / `R_DR` share the statement length) and under ops 0, 6, 255; **960 mutated inputs per
relation** (12 kinds × 80, `client::mutate`; the public scalar of kind `stmt_tail` is the fee for `R_TX`, the amount
for `R_BURN` / `R_DS` / `R_DR`) **— 4,800, 0 accepted, 0 panics**. Negative witnesses, each refused by the honest
prover and, proved without its checks, rejected by the verifier:

| Case | `R_REG` | `R_TX` | `R_BURN` | `R_DS` | `R_DR` |
|---|---|---|---|---|---|
| ℓ2 norm exceeded with coefficients in [−1, 1] (‖s‖² = 1,300 > 36²) | yes | yes | yes | — | yes (s_t) |
| a coefficient out of range (s_5 = 100) | yes | — | yes | — | yes |
| digit out of range, same value | — | yes (d) | yes (d′) | — | — |
| e2 norm exceeded (one coefficient 65) | — | yes | yes (e2_f) | yes | — |
| overspend (new-balance digits all 15) | — | yes | yes | — | — |
| public amount ± 1 with the honest witness (`R_DR`: − 1 puts +Δ into e′) | — | — | yes (also fee ± 1) | yes | yes |
| r ℓ2 bound exceeded (‖r‖² = 1,300 > 36², coefficients in [−1, 1]) | — | yes | yes | yes | — |
| r coefficient outside its 7 bits (r_5 = 100) | — | yes | yes | yes | — |
| e1 ℓ2 bound exceeded (all ±4: ‖e1‖² = 32,768 > 164²) | — | yes | yes | yes | — |
| e1 coefficient outside its 9 bits (e1_5 = 300) | — | yes | yes | yes | — |
| fee / amount word ≥ 2^64 (also: the honest proof rejected) | — | yes | yes (both words) | yes | yes |
| wrong ring row (one CBD(20) coefficient + 1) | — | yes | yes | yes (e1) | yes (e) |

(r and e1 are the transfer's for `R_TX` / `R_DS` and the burn's for `R_BURN`, set by `Tweak { r, e1 }` and
re-encrypted, so only the norm and range proofs can catch them.) `dr_noise_range_edges`: v_0 crafted so that e′_0 =
2^24 − 1 and −2^24 prove and verify, while e′_0 = 2^24 and −2^24 − 1 are refused and, proved without the checks,
rejected. `hedged_proofs`: for every relation, two `prove_unchecked` on one statement with the same `rnd32` and
witnesses differing in one byte give different commitments (proof bytes 0..32); equal inputs give equal proofs.

The benches add 2 × 4,800 mutations (§12.3, 0 accepted, 0 panics) and the wasm32 runs 2 × 240.

### 12.3 Measurements [measured]

Native: `runs/l7-proven.jsonl` / `l7-conj.jsonl` (+ `-time.txt`), 5 proofs (seeds 0–4), 100 honest verifies, 12 × 80
mutations per relation, every relation in one process. Proof B is the range over the 5 seeds; "max exact" is
`max_len_exact`, "bound" the verifier's current length check (`max_len`, t full paths). Max RSS is the whole process
(five relations): 47 MB proven, 54 MB conjectured.

| Relation | Preset | n, k, t, ℓ, m | Proof B (5 seeds) | Max exact / bound | Prove p50 | Peak heap prove / verify | Verify p50 / p99 honest | p99 adversarial | Accepted / panics of 960 | Bits query / prox / lin |
|---|---|---|---|---|---|---|---|---|---|---|
| `R_REG` | proven | 32,756, 817, 121, 695, 63 | 186,008–187,802 | 190,458 / 217,338 | 375 ms | 25.9 / 0.8 MB | 6.98 / 7.68 ms | 1.06 ms | 0 / 0 | 128.5 / 146.0 / 155.4 |
| `R_TX` | proven | 32,756, 817, 121, 695, 125 | 231,000–232,430 | 235,470 / 262,350 | 648 ms | 43.2 / 1.2 MB | 9.72 / 10.79 ms | 1.32 ms | 0 / 0 | 128.5 / 145.0 / 154.4 |
| `R_BURN` | proven | 32,756, 817, 121, 695, 124 | 230,584–231,512 | 234,744 / 261,624 | 616 ms | 42.9 / 1.1 MB | 9.25 / 9.82 ms | 1.46 ms | 0 / 0 | 128.5 / 145.0 / 154.4 |
| `R_DS` | proven | 32,756, 817, 121, 695, 63 | 186,360–187,546 | 190,458 / 217,338 | 363 ms | 25.9 / 0.8 MB | 7.39 / 9.75 ms | 1.24 ms | 0 / 0 | 128.5 / 146.0 / 155.4 |
| `R_DR` | proven | 32,756, 817, 121, 695, 63 | 185,878–187,962 | 190,458 / 217,338 | 398 ms | 25.9 / 0.8 MB | 7.16 / 7.49 ms | 0.96 ms | 0 / 0 | 128.5 / 146.0 / 155.4 |
| `R_REG` | conjectured (reference) | 18,533, 172, 20, 151, 283 | 61,142–63,104 | 63,584 / 66,752 | 831 ms | 46.5 / 0.5 MB | 1.46 / 1.76 ms | 0.67 ms | 0 / 0 | 131.1 / 144.7 / 155.4 |
| `R_TX` | conjectured (reference) | 18,533, 344, 24, 319, 287 | 92,520–92,616 | 93,128 / 97,192 | 946 ms | 49.5 / 0.8 MB | 3.17 / 3.27 ms | 0.87 ms | 0 / 0 | 130.1 / 144.6 / 154.3 |
| `R_BURN` | conjectured (reference) | 18,533, 344, 24, 319, 286 | 92,120–92,536 | 92,984 / 97,048 | 933 ms | 49.3 / 0.8 MB | 2.86 / 3.59 ms | 0.75 ms | 0 / 0 | 130.1 / 144.7 / 154.3 |
| `R_DS` | conjectured (reference) | 18,533, 172, 20, 151, 284 | 62,776–63,384 | 63,704 / 66,872 | 835 ms | 46.7 / 0.5 MB | 1.64 / 1.73 ms | 0.62 ms | 0 / 0 | 131.1 / 144.7 / 155.4 |
| `R_DR` | conjectured (reference) | 18,533, 172, 20, 151, 285 | 62,960–63,504 | 63,824 / 66,992 | 821 ms | 46.8 / 0.5 MB | 1.64 / 2.04 ms | 0.65 ms | 0 / 0 | 131.1 / 144.7 / 155.4 |

All presets keep the total ≥ 127.2 bits (proven) / 127.7 (conjectured) as in §5. Every op uses THE proven preset
(owner decision (a)); the plan's "per-op preset by the p1 model" was not done (THE preset is not to be changed here),
and the conjectured presets of the new relations are borrowed from `R_REG` (disclosures) and `R_TX` (`R_BURN`), not
re-optimised. `R_REG` / `R_TX` match §6.1 within noise (the hedge changes bytes, not sizes or work).

wasm32 (node v26.8.1, module 280,242 B; `runs/l7-proven-wasm.jsonl`, `l7-conj-wasm.jsonl`): 2 proofs, 100 honest
verifies, 12 × 4 mutations per relation, all five relations in one module instance, proofs made in wasm.

| Relation | Preset | Prove mean | Verify p50 / p99 honest | p99 adversarial | Fails |
|---|---|---|---|---|---|
| `R_REG` | proven | 845 ms | 32.2 / 50.6 ms | 1.05 ms | 0 |
| `R_TX` | proven | 1,473 ms | 48.9 / **66.5 ms** (max 69.6) | 1.49 ms | 0 |
| `R_BURN` | proven | 1,447 ms | 45.8 / 48.0 ms | 1.39 ms | 0 |
| `R_DS` | proven | 808 ms | 33.2 / 37.2 ms | 1.15 ms | 0 |
| `R_DR` | proven | 835 ms | 31.9 / 34.7 ms | 1.09 ms | 0 |
| `R_REG` | conjectured (reference) | 1,622 ms | 5.29 / 5.84 ms | 0.67 ms | 0 |
| `R_TX` | conjectured (reference) | 1,925 ms | 13.6 / 15.5 ms | 0.96 ms | 0 |
| `R_BURN` | conjectured (reference) | 1,882 ms | 12.1 / 16.0 ms | 0.86 ms | 0 |
| `R_DS` | conjectured (reference) | 1,614 ms | 6.05 / 10.1 ms | 0.80 ms | 0 |
| `R_DR` | conjectured (reference) | 1,680 ms | 6.06 / 8.15 ms | 0.71 ms | 0 |

Linear memory 46.6 MiB proven / 51.9 MiB conjectured (the high-water mark of the module, all five relations). The
proven `R_TX` p99 of this run, 66.5 ms, was above the 60 ms limit: two of 100 verifies took 66–70 ms against a p50
of 48.9 ms. A repeat in a fresh process (`runs/l7-probe-wasm-tx-repeat.jsonl` [probe]: `R_TX`, `R_BURN`, `R_TX`,
200 honest verifies each) gave `R_TX` p99 54.4 / 53.1 ms (max 56.7 / 57.3) and `R_BURN` p99 56.0 ms with one 78.0 ms
outlier; §6.2 had 55.9 ms (50 verifies). The p50 is unchanged since §6.2 (48.7 → 48.9 ms) and the verifier code path
is the same, so the tail is this noisy host [inference]; but proven `R_TX` / `R_BURN` sit within ≈ 10 % of the limit at
p99 in wasm32, and a single run can cross it. Native p99 is ≤ 10.8 ms for every relation.

**Gate-B measurement (controller decision of the review: wasm32 verify p99 over ≥ 1,000 honest verifies per relation,
under `scripts/capped`, proven preset).** `runs/gateb.sh`: 2 proofs, 1,000 honest verifies, 12 × 4 mutations per
relation, all made in wasm32, `fails` 0 in both runs.

| wasm32, proven | `l8`: u128 products (as `l7`) — prove mean | verify p50 / p99 / max | `l9`: 21-bit pieces — prove mean | verify p50 / p99 / max | p99 adversarial (`l9`) |
|---|---|---|---|---|---|
| `R_REG` | 846 ms | 31.2 / 42.9 / 51.7 ms | 746 ms | 11.4 / 16.9 / 18.1 ms | 1.03 ms |
| `R_TX` | 1,469 ms | 48.6 / **59.7** / 73.5 ms | 1,331 ms | 17.1 / **18.7** / 22.7 ms | 1.57 ms |
| `R_BURN` | 1,460 ms | 45.8 / 55.8 / 69.0 ms | 1,323 ms | 17.0 / 19.9 / 23.7 ms | 1.51 ms |
| `R_DS` | 834 ms | 32.9 / 48.7 / 74.0 ms | 738 ms | 11.9 / 17.0 / 18.8 ms | 1.08 ms |
| `R_DR` | 829 ms | 31.3 / 35.1 / 44.3 ms | 735 ms | 11.4 / 13.3 / 16.3 ms | 1.09 ms |

`l8` put proven `R_TX` at 59.7 ms, within 5 % of the limit, which by the same decision triggers the wasm32 multiply
(§12.1). With it (`l9`) every relation verifies at p99 ≤ 19.9 ms in wasm32, 2.7–2.8× faster at p50 (`R_TX`
p99 3.2×) and a third of the limit; module 280,804 → 257,055 B; linear memory unchanged (46.6 MiB). Native code and
timings are unchanged (`runs/l9-native-fnv.jsonl`: verify 7.2–10.0 ms, one sample each).

**Exact maximum vs the 256 KB proposal.** At THE preset the largest acceptable proofs are 235,470 B (`R_TX`), 234,744 B
(`R_BURN`), 190,458 B (`R_REG`, `R_DS`, `R_DR`): all under 262,144 B. The verifier's current bound (t full paths) is
262,350 B for `R_TX`, above it; Task 9 replaces it by `max_len_exact`. §8's 243,150 / 198,138 B were upper bounds
(t siblings on every level).

**EVM fixtures.** Hedging changes every proof, so `ligero_export` re-wrote the 19 proof files of
`smartcontracts/evm/test/vectors/pqzh-ligero/` (statements, A and parameters byte-identical; `runs/l7-export.jsonl`)
and the forge test passed again (`runs/l7-forge.txt`: 14 tests, all six honest proofs accepted, 6 × 108 mutations
0 accepted / 0 reverts, the 7 negative witnesses rejected; gas within 0.6 % of `l6`, so §11's tables stand). The EVM
verifier still covers `R_REG` / `R_TX` only.

### 12.4 Left for later

- Task 8: `R_TX0` (auditor off) and the xcheck of the sixth form: done on `p6e-b3`, §14.
- Task 6: the switch to `pqz-stmt` (§12.1), `soundness` / `breakdown` (floats) behind `bench`, proofs byte-identical:
  done on `p6e-b3`, §14.
- Task 9: done on `p6e-b2`, §13.

### 12.5 Rerun

```sh
scripts/capped pqz-core/pqzh/ligero/runs/rel5.sh l7   # tests, native both presets, wasm32, xcheck, fixtures, forge
scripts/capped pqz-core/pqzh/xcheck/ligero.sh         # statement / witness bytes vs pqz_bench.c, all five relations
scripts/capped pqz-core/pqzh/ligero/runs/gateb.sh l9  # tests, --no-default-features, native FNV, wasm32 1,000 verifies
```

## 13. P6e Task 9: the PQZH id, the exact length bound, the limits

Branch `p6e-b2` (from main `99ad859`), plan Task 9 (D3, D5, G7) without `pqz-stmt` (Task 6). Results, not decisions
(the decision lines, D3 under CTR-PQZ-09 and D5 under CTR-PQZ-10, are in `docs/decisions.md`). Runs `runs/l10-*` (failed,
kept), `runs/l11-*` (`runs/limits.sh`, one capped session; xcheck and forge rerun after the `kat_stmt.py` fix below).

### 13.1 What changed

- **Id (D3).** `stmt.rs` `PQZH_PROOF_SYSTEM_ID` = `keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")`
  = `0x0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4` (unit test `pqzh_id_d3` hashes the string),
  replacing the STARK's provisional `0xaa1f92dd…`. `cs::parse`, which both prover and verifier call first, returns
  nothing for a statement whose bytes 32..63 carry another id, so such a statement is neither proved nor verified
  (`tests/attacks.rs` `other_ids_and_length_bound_rejected`: PQZL's id, the STARK id and zeros, all five relations).
- **opTag and auditorOn in depth (review of `p6e-b2`, controller).** `cs::parse` also requires bytes 0..31 to be one
  of the op's opTags (`stmt.rs` `op_tags`: op 2 BURN or REFRESH, op 5 DISCLOSE-RECEIVER or AUDITOR) and, for the
  83,072-byte `R_TX`, the auditorOn word = 1 (bytes 448..478 zero, 479 = 1, R6); the pqz-ffi decoder (Task 7) checks
  them as well, and this keeps PQZH's own checks after Task 6. The test above adds byte 0 flipped, every other op's
  opTag and auditorOn 0 / 2 / high byte set; REFRESH and AUDITOR statements parse. The Solidity port
  (`LigeroVerifier.sol` `stmtOk`) checks id, opTag and auditorOn (forge `test_stmt_and_length_reg` / `_tx`). The
  "other statement" of the mutation sets, the benches and the EVM `.other` fixtures now flips byte 64 (chainId, or
  `R_REG`'s message word: hashed only) instead of byte 0.
- **Statements as the precompile takes them.** `client::setup` writes each op's opTag `keccak256("SCAAS-PQZ-OP-<NAME>-V1")`
  at bytes 0..31 (was pqz_bench.c's filler) and, for `R_TX`, the auditorOn word = 1 (R6). `xcheck/dump_setup.c pqzh` patches pqz_bench.c's statements the same way (pqz_bench.c itself, PQZL's, is
  unchanged), and `xcheck/kat_stmt.py` makes pqz_kat.py parse every Ligero statement under its D15 / R6 rules with
  PQZH's id only (PQZL's id: rejected) and rebuild it byte for byte from the parsed fields with its own builders.
- **Exact length bound (G7).** The verifier's first check, before the statement or the proof is parsed, is
  `Params::proof_len_ok(op, len)`: `1 ≤ len ≤ max_proof_len(op)` = `max_len_exact(op)` (§12.1); the Solidity port
  runs the same exact bound (`maxLen`) first in `_verify`, before `stmtOk` (forge: `maxProofLen` = the Rust values,
  `MAX` padded and `MAX + 1` rejected, the latter far cheaper). It rejects nothing the
  parser would accept (a longer proof cannot be consumed exactly); it rejects early. Unit tests: `limits_exact` (the
  table below; `MAX` passes the gate, `MAX + 1` and 0 do not), `max_len_exact_multiproof_tight` (the bound equals the
  proof grammar at t evenly spread columns: root, polynomials, nonce, t columns, that set's multiproof). Integration: an
  honest proof zero-padded to `MAX` passes the gate and is rejected as not consumed exactly, `MAX + 1` is rejected by
  the gate. The bound is not capped at 262,144 B: run `l10` capped it and the reference preset "proven without radix
  431" (n = 6,536, t = 166, not the id) then refused every `R_TX` proof (`runs/l10-tests-failed-cap.txt`); D5's limit
  holds at THE preset, which is what the id fixes.
- **Prover retry.** `prove_inner` proves again with the RNG stream continued (fresh masks and salts, so a fresh
  commitment, query set and multiproof) if a proof is longer than the verifier's bound, at most 16 attempts, then
  `Err("proof length")`. It is a guard: every proof is ≤ `max_len_exact` by construction, so the first attempt always
  returns. Unit test `prover_retries_over_limit`: with the limit set one byte below `prove`'s proof the retry returns a
  shorter proof with another commitment, which verifies; an impossible limit gives `Err("proof length")`.
- **Limits (D5).** `stmt.rs` `PQZL_MAX_PROOF` 98,304, `PQZH_MAX_PROOF` 262,144, `MAX_INPUT` 393,216, `INPUT_HEADER` 5
  (move to `pqz-stmt` with Task 6); unit test `input_limit`: 5 + 83,072 + 262,144 = 345,221 ≤ 393,216.

### 13.2 Limits at THE preset [measured: unit test `limits_exact`, `runs/l11-proven.jsonl` 5 proofs per relation]

| Relation | Statement B | Exact max proof B (verifier bound) | Proofs measured (5 seeds) | 5 + statement + max | ≤ 262,144 / ≤ 393,216 |
|---|---|---|---|---|---|
| `R_REG` | 16,480 | 190,458 | 186,232–187,674 | 206,943 | yes / yes |
| `R_TX` | 83,072 | 235,470 | 231,854–232,462 | 318,547 | yes / yes |
| `R_BURN` | 50,048 | 234,744 | 230,568–231,896 | 284,797 | yes / yes |
| `R_DS` | 33,184 | 190,458 | 187,354–187,802 | 223,647 | yes / yes |
| `R_DR` | 33,184 | 190,458 | 185,462–187,226 | 223,647 | yes / yes |

The largest input any PQZH proof allows is 318,547 B (`R_TX`); `MAX_INPUT` is sized for 5 + 83,072 + 262,144 = 345,221 B.
`R_TX0` (auditor off, 66,560 B): built on `p6e-b3`, exact maximum 234,744 B (§14.3).

### 13.3 Runs [measured]

- `runs/l11-tests.txt`: 13 unit tests and 15 integration tests pass (`l9`: 9 and 14), 4,800 mutations 0 accepted /
  0 panics; `evm_fixtures` passes on the re-exported fixtures. `runs/l11-nobench.txt`: the production build
  (`--no-default-features`) lib and its 13 unit tests.
- `runs/l11-proven.jsonl`: native, proven, 5 proofs, 10 honest verifies, 12 × 4 mutations per relation, 0 accepted,
  0 panics; verify p50 7.1–9.7 ms (`R_TX` 9.73 ms, `l7` 9.72 ms). No wasm32 run: the verifier changed by an O(1)
  length gate and a 32-byte compare, nothing per column, so the gate-B wasm32 numbers of §12.3 (`l9`) stand.
- `runs/l11-xcheck.txt`: statements and witnesses of all five relations equal to the patched pqz_bench.c bytes, and
  pqz_kat.py parses and rebuilds all five (`ok`). The first try (`runs/l11-xcheck-failed-burn-rebuild.txt`) failed
  on `R_BURN` in `kat_stmt.py` itself: it dropped the auditorOn word for every debit op, while pqz_kat.py's builder
  sets it only for TRANSFER; fixed in the script.
- EVM: `ligero_export` re-wrote the fixtures (`runs/l10-export.jsonl` = `runs/l11-export.jsonl`; statements now carry
  the opTags, the D3 id and auditorOn, so every statement and proof file changed); `runs/l11-forge.txt`: 14 tests pass,
  the six honest proofs accepted, 6 × 108 mutations 0 accepted / 0 reverts, the 7 negative witnesses rejected; verify gas
  of proven `R_TX` 530.3 M (`l7` 530.3 M), so §11 stands.

- After the review's fixes (opTag / auditorOn in depth, the exact bound first in Solidity, the "other statement" on
  byte 64), `runs/l12-*` (`runs/limits.sh l12`, now with a wasm32 compile check): 14 unit and 15 integration tests
  pass, also `--no-default-features` (14); 4,800 mutations 0 accepted / 0 panics; xcheck and `kat_stmt` equal / ok;
  fixtures re-exported (`.other` files changed, honest proofs byte-identical with `l11`: same statements); forge 16
  tests pass (`l12-forge.txt`), mutations 0 accepted, negatives rejected, `maxProofLen` 190,458 / 235,470 B as Rust,
  `MAX + 1` rejected at 0.79 M (`R_REG`) / 1.79 M (`R_TX`) test-call gas against 6.50 M / 9.50 M for `MAX` padded
  (the caller's copies of statement and proof included). Honest verify gas moved by −0.04 % (proven `R_TX` 530.34 →
  530.10 M, `R_REG` 321.30 → 321.25 M: the layout now runs before the statement checks).

### 13.4 Rerun

```sh
scripts/capped pqz-core/pqzh/ligero/runs/limits.sh l12   # fixtures, tests, --no-default-features, wasm32 build, native bench, xcheck, forge
```

## 14. P6e Tasks 6 and 8: the crate on `pqz-stmt`, `R_TX0`

Branch `p6e-b3` (from main `9f55013`), plan Task 6 (R2, D11) and the rest of Task 8 (`R_TX0`, G1 / D8). Results, not
decisions (the decision lines are in `docs/decisions.md`: D11 under CTR-PQZ-09, the PQZH `R_TX0` under CTR-PQZ-24).
Runs `runs/l14-base-fnv*` (the base commit's seed-1 proofs, before any change), `runs/l14-*` (`runs/stmt.sh l14`,
Task 6) and `runs/l14-tx0-*` (`runs/tx0.sh l14-tx0`, Task 8), each one capped session.

### 14.1 What changed

- **On `pqz-stmt` (Task 6).** `src/stmt.rs` is gone; `cs::parse` is `pqz_stmt::parse` (every D15 / R6 rule: length,
  the op's opTag, a known id, fee / amount < 2^64, the salt form, `auditorOn` by length, the zero words, coefficients
  < q) followed by PQZH's own id check (D3, kept on the Ligero side: `pqz-stmt` knows both ids). `ring.rs` keeps A,
  the integer products and the honest prover's `keypair` / `encrypt` / `digits` (moved from `client.rs`, which the
  production build no longer has); the coefficient codec, layout constants, ids and opTags are `pqz-stmt`'s. The
  Ligero verifier therefore accepts what `pqz-stmt` accepts and no more: an accepted-set tightening (e.g. a non-zero
  high half of the salt word, a non-zero zero-word) before any deployment, no proof byte changes.
- **Relations keyed by form.** `Layout`, `max_len_exact`, `max_proof_len`, `proof_len_ok` take a `pqz_stmt::Form`;
  `cs::form_of(op, len)` gives the form from the op and the statement length alone (op 1: `R_TX0` iff 66,560 B), so
  the verifier's length gate still runs before anything is parsed. `prove` / `verify` keep `(op, stmt, …)`;
  `RELS` (six forms, `pqz_bench.c`'s order) replaces `OPS`.
- **Feature `bench` (D11).** `client.rs`, `Params::new` / `preset` / `johnson` / `johnson_preset`, `factor*`,
  `soundness`, `breakdown` are behind `bench`; `Params::proven()` is written out as a `const fn` (unit test
  `proven_is_the_model`: equal to `Params::new(32756, 817, true)`). The production build (`--no-default-features`)
  depends on `sha3` and `pqz-stmt` only and contains no scalar float instruction: `runs/l14-deps.txt` (`cargo tree`,
  and `objdump -d` of the production rlib: 0 `cvt*` / `add|sub|mul|div|sqrt s[sd]`; the default-feature rlib's 55 are
  in `runs/l15-deps.txt`). `#![deny(clippy::float_arithmetic)]` applies without `bench`; clippy passes it (§14.4).
- **`R_TX0` (Task 8).** `R_TX` without the auditor (`pqz_rel.c`, D8): rows 1–4, 6, 7, legs t and f (no `pk_a`, `v_a`,
  `e2_a`), every norm and range of `R_TX`; same constraint-system code, `Layout` with two e2 legs. Statement 66,560 B
  and witness 12,384 B as pqz-core; `client::setup` builds them as `pqz_bench.c` does (`R_TX`'s transfer without
  `pk_a` / `v_a`, header with `auditorOn` 0). m = 124 rows, as `R_BURN`, so its exact bound equals `R_BURN`'s.
- **Cross-check.** `xcheck/ligero.sh` and `kat_stmt.py` cover the sixth form (`runs/l14-tx0-xcheck.txt`: 12 of 12
  files equal to `pqz_bench.c`'s; `pqz_kat.py` parses and rebuilds all six, `kat_stmt: ok`).
- **EVM (test-only).** `LigeroVerifier.sol` takes `R_TX0` (op 1 by length; `auditorOn` 0; two legs; `maxProofLen`
  now takes the statement length), `ligero_export` writes `tx0-proven.*`, the forge test adds gas, 108 mutations,
  statement / length checks and the cross-form check. Its `stmtOk` still checks only id, opTag, `auditorOn`, fee and
  coefficients, not every D15 rule (the Rust verifier does, through `pqz-stmt`).

### 14.2 Task 6: proofs byte-identical [measured]

Same statements, same `rnd32`: FNV-1a of the proofs, `runs/l14-proven.jsonl` `fnv_by_seed` against the base commit
(`runs/l14-base-fnv.jsonl`, seed 1) and `runs/l13-proven.jsonl` (seed 4).

| Relation | seed 1: base `9f55013` = `l14` | seed 4: `l13` = `l14` |
|---|---|---|
| `R_REG` | `36b1d3e5` | `b6215ec2` |
| `R_TX` | `720b94e0` | `f8c936d9` |
| `R_BURN` | `e270d5c8` | `e6464eb5` |
| `R_DS` | `020286c2` | `e62e8079` |
| `R_DR` | `c5f5fb23` | `d83e24fc` |

Sizes and times are `l13`'s within noise (`R_TX` prove p50 636 / 639 ms, verify p50 over 10 samples 9.99 / 9.69 ms;
over 1,000 in `l14-tx0` 9.78 ms). Tests (`runs/l14-tests.txt`): 13 unit and 15 integration tests pass, 4,800
mutations 0 accepted / 0 panics; `runs/l14-nobench.txt`: 11 unit tests without `bench`; wasm32 builds
(`runs/l14-wasm-build.txt`).

### 14.3 Task 8: `R_TX0` at THE preset [measured]

Native: `runs/l14-tx0-proven.jsonl` (+ `-time.txt`), all six forms in one process, 5 proofs (seeds 0–4), 1,000 honest
verifies, 12 × 80 mutations each. wasm32 (gate-B method, §12.3): `runs/l14-tx0-proven-wasm.jsonl`, node v26.8.1,
module 275,535 B, 2 proofs made in wasm32, 1,000 honest verifies, 12 × 4 mutations each, `fails` 0. Limit 60 ms p99.

| Relation | m | Proof B (5 seeds) | Exact max | Prove p50 native / wasm32 mean | Peak heap prove / verify | Verify p50 / p99 native | Verify p50 / p99 wasm32 | Mutations accepted / panics |
|---|---|---|---|---|---|---|---|---|
| **`R_TX0`** | 124 | 229,672–231,800 | 234,744 | 614 / 1,310 ms | 42.9 / 1.2 MB | 9.48 / 11.10 ms | 16.75 / **22.33** ms | 0 / 0 of 960 |
| `R_TX` | 125 | 230,584–232,302 | 235,470 | 646 / 1,295 ms | 43.2 / 1.2 MB | 9.78 / 10.65 ms | 17.12 / 21.03 ms | 0 / 0 of 960 |
| `R_BURN` | 124 | 231,256–232,632 | 234,744 | 632 / 1,277 ms | 42.9 / 1.1 MB | 9.24 / 12.02 ms | 16.36 / 24.02 ms | 0 / 0 of 960 |
| `R_REG` | 63 | 186,232–187,674 | 190,458 | 381 / 784 ms | 25.9 / 0.8 MB | 7.01 / 8.05 ms | 11.28 / 16.37 ms | 0 / 0 of 960 |
| `R_DS` | 63 | 187,354–187,802 | 190,458 | 384 / 737 ms | 25.9 / 0.8 MB | 7.28 / 7.92 ms | 11.97 / 13.57 ms | 0 / 0 of 960 |
| `R_DR` | 63 | 185,462–187,226 | 190,458 | 373 / 741 ms | 25.9 / 0.8 MB | 7.17 / 8.04 ms | 11.53 / 13.36 ms | 0 / 0 of 960 |

Soundness at THE preset is `R_TX`'s for `R_TX0` (query 128.5, proximity 145.0, linear 154.4 bits, total 127.2).
Process max RSS 47 MB native (six forms), wasm32 linear memory 48.1 MiB; adversarial verify p99 ≤ 1.4 ms native,
≤ 2.0 ms wasm32. The wasm32 seed-1 proofs equal the native ones for all six forms (`R_TX0` `a69e9010`). `R_TX0` limits:
5 + 66,560 + 234,744 = 301,309 B ≤ `MAX_INPUT` 393,216; 234,744 ≤ 262,144 (unit test `limits_exact`).

**Tests** (`runs/l14-tx0-tests.txt`): 13 unit and 16 integration tests pass; 6 × 960 mutations 0 accepted /
0 panics (`R_TX0` 960). `R_TX0` gets every negative witness `R_TX` has, each refused by the honest prover and, proved
without its checks, rejected: ℓ2 norm of s_f exceeded with coefficients in [−1, 1]; r and e1 ℓ2 bound and bit range;
digit out of range (d); e2_t norm 65; overspend (d′ all 15); fee word ≥ 2^64 (honest proof rejected too); a wrong ring
row (e1). Statement checks: the PQZL, STARK and zero ids, opTag byte 0 and every other op's opTag, `auditorOn` 1 / 2 /
high byte (`R_TX`: 0 / 2 / high byte) — none parsed, proved or verified. `transfer_forms_cross_rejected`: an `R_TX`
proof against the `R_TX0` statement of the same transfer and vice versa are rejected (the two statements convert into
each other by adding / removing `pk_a`, `v_a` and flipping `auditorOn`), a witness of the other form is refused by its
length, and `R_TX0`'s bound is below `R_TX`'s. `runs/l14-tx0-nobench.txt`: 11 unit tests without `bench`.

**EVM** (`runs/l14-tx0-forge.txt`, fixtures `runs/l14-tx0-export.jsonl`; the existing fixture files re-exported
byte-identical): 20 tests pass; proven `R_TX0` verifies at 516.3 M gas (`R_TX` 526.8 M), 108 mutations 0 accepted /
0 reverts, `maxProofLen` 234,744 B as Rust, `MAX + 1` rejected at 1.64 M against 9.05 M for `MAX` padded, and the two
cross-form inputs rejected. §11's conclusion (no EVM verification without the precompile) holds for `R_TX0`.

### 14.4 Review fixes (`runs/l15-*`, `runs/l15-tx0-*`) [measured]

After the controller's review of `p6e-b3`: `runs/stmt.sh l15` then `runs/tx0.sh l15-tx0`, one capped session.

- **Negative witnesses for every debit condition.** New `Tweak` fields `e2_f` (the transfer's sender leg) and `e_f`
  (key F's error). `e2_norm_exceeded`: e2_f = 65 for `R_TX` and `R_TX0`. `coefficient_out_of_range`: s_f_5 = 100 and
  e_f_5 = 300 (outside the 7 / 9 bits) for `R_REG`, `R_TX`, `R_TX0`, `R_BURN`. `wrong_witness_ring_row`: one e_f
  coefficient changed (row 1) for `R_REG`, `R_TX`, `R_TX0`, `R_BURN`, besides e1. New `debit_noise_range_edges`
  (row 6, as `dr_noise_range_edges`): v_T_0 crafted so that e_T_0 = 2^24 − 1 and −2^24 prove and verify while 2^24
  and −2^24 − 1 are refused and, proved without the checks, rejected, for `R_TX`, `R_TX0` and `R_BURN`. Each case is
  refused by the honest prover and rejected by the verifier.
- **Production surface.** `prove_unchecked` exists only in tests and with `bench`; the `dump_setup` example requires
  `bench`. `runs/l15-nobench.txt`: `cargo test --no-default-features` (all targets: 11 unit tests, the integration
  test and the bins / example skipped) and `cargo build --no-default-features --examples --bins` succeed.
- **clippy** (now installed for 1.97.1), `runs/l15-clippy.txt`: `cargo clippy --no-default-features -- -D
  clippy::float_arithmetic` passes (rc 0); `cargo clippy --all-targets` with the default lints reports style
  warnings only (needless range loops, `is_multiple_of` / `div_ceil`, a method named `next`, two complex types), no
  error. `runs/l15-deps.txt` scans both rlibs: 55 scalar float instructions with `bench`, 0 without.
- **EVM.** `LigeroVerifier.sol` `stmtOk` also requires a transfer's amount and recipient words 0 and the salt word's
  high half 0 (D15, as `pqz-stmt`); the forge statement tests set each to non-zero and expect a rejection, for `R_TX`
  and `R_TX0` (`runs/l15-tx0-forge.txt`, 20 tests pass).
- **Rerun results.** `runs/l15-tx0-tests.txt`: 13 unit and 17 integration tests pass, 6 × 960 mutations 0 accepted /
  0 panics; xcheck 12 / 12 equal, `kat_stmt: ok`; fixtures re-exported byte-identical; wasm32 `fails` 0. Verify p50 /
  p99 over 1,000: `R_TX0` 9.38 / 11.36 ms native, 16.60 / 20.88 ms wasm32 (§14.3: 11.10 / 22.33 ms p99).

### 14.5 Rerun

```sh
scripts/capped pqz-core/pqzh/ligero/runs/stmt.sh l14      # Task 6: tests, --no-default-features, deps / float scan, wasm32 build, native FNV
scripts/capped pqz-core/pqzh/ligero/runs/tx0.sh l14-tx0   # Task 8: fixtures, tests, native + wasm32 (1,000 verifies), xcheck, forge
```

## 15. P6-ANON Track H: op 7 `R_TXM` in Ligero (H1, H2) [measured]

Plan `docs/superpowers/plans/2026-10-14-p6-anon.md` Tasks H1 / H2, branch `p6-anon-h`. One capped round
`runs/txm.sh l16-txm` (all ten steps ran: tests, oversize tests, `--no-default-features`, native FNV of the six forms,
native bench, oversize native bench, wasm32, oversize wasm32, `xcheck` + `kat_multi.py`, `pqz-ffi` check), raw files
`runs/l16-txm-*`; the pre-review fixes of §15.5 reran the tests (`runs/l16-txm-fix-*`).

### 15.1 Relation, layout and the e2 rule

- **Shape before size.** `cs::rel_of` reads the `auditorOn` and `M` header words and admits only PQZH's built set
  (`pqz_stmt::built_legs(PQZH_ID)`: {1, 2, 4}; feature `oversize` adds 8, 16) before any `Layout` is sized; then
  `pqz_stmt::parse_multi` with every D15 / R6 rule, then PQZH's id. (1, on) and (2, off) are both 83,072 B and are told
  apart by the words.
- **Rows** (plan §3): `R_TX` with M receiver legs, one randomness group (r_g, e1_g, u_g) per 4 legs (g(j) = ⌊j/4⌋,
  v_f in group 0), auditor on: one copy v_{a,j} per leg under pk_a with the leg's digits d_j, row 7 with Σ_j d_j.
  Witness (prover API) `s_f ‖ e_f ‖ (r_g ‖ e1_g)_g ‖ e2 (legs, f, auditor copies) ‖ d_j ‖ d′`; M = 1 is `R_TX`'s
  (`R_TX0`'s) witness and rows (op 7 keeps its own op byte and opTag in the transcript).
- **e2 bound: per vector ≤ 64 (ℓ2) — the decided rule.** Every e2 vector (each leg, v_f, each auditor copy) is proven
  ‖e2‖ ≤ 64, exactly as the single-recipient forms (pq-zether.md §4.3). The plan's §3 / R3 / D5 text first proposed
  one ℓ2 block per kind of leg noise with bound 64·√M; the pre-review (finding X-1) found PQZL and PQZH proving
  different bounds, and the **owner decided on 2026-10-15: per vector ≤ 64** (decisions.md CTR-PQZ-03 Change
  2026-10-15, TODO.md). PQZH already implemented it, so no row changed here; PQZL (`p6-anon-l`) moves to per-vector
  bounds. The per-vector bound implies the block bound, honest encryptions meet it (CTR-PQZ-19 resamples each e2 to
  ≤ 64), and a leg credit's noise stays `R_TX`'s 2·36·164 + 64 = 11,872 per unit (K_MAX · 11,872 = 12,156,928 < 2^24,
  mint margin 4.14× as §4.3), independent of M. Negative test: one e2 vector with ‖e2‖² = 5,120 (> 64², < 64²·M for
  M ≥ 2), so only the per-vector rule rejects it (§15.5).
- **Rows per shape** (`m`): (1, on) 125 (= `R_TX`), (1, off) 124 (= `R_TX0`), (2, on) 125, (2, off) 125, (4, on) 126,
  (4, off) 125; oversize (8, on) 188, (8, off) 186, (16, on) 314, (16, off) 309.

### 15.2 Sizes and limits (THE preset: n 32,756, k 817, ℓ 695, t 121, proven)

Exact bound = `max_len_exact` = the verifier's `max_proof_len`, pinned in unit test `limits_exact` for all ten shapes
(equal to the pre-review's table, H-3). Input = 5 + statement + exact bound. Proof min–max over 10 seeds (built) or 3
seeds (oversize, `runs/l16-txm-oversize.jsonl`).

| Shape (M, auditor) | Statement B | Witness B | Proof B min–max | Exact bound B | Input B | ≤ `MAX_PROOF_PQZH` 262,144 and ≤ `MAX_INPUT` 393,216 |
|---|---|---|---|---|---|---|
| (1, on) | 83,072 | 12,416 | 230,242–233,102 | 235,470 | 318,547 | yes |
| (1, off) | 66,560 | 12,384 | 230,408–232,440 | 234,744 | 301,309 | yes |
| (2, on) | 99,712 | 12,496 | 231,128–232,526 | 235,470 | 335,187 | yes |
| (2, off) | 83,072 | 12,432 | 231,150–232,590 | 235,470 | 318,547 | yes |
| **(4, on)** | 132,992 | 12,656 | 231,944–233,604 | **236,196** | **369,193** | yes |
| (4, off) | 116,096 | 12,528 | 230,872–232,654 | 235,470 | 351,571 | yes |
| (8, on) oversize | 215,936 | 19,120 | 276,584–278,456 | 281,208 | 497,149 | no, both |
| (8, off) oversize | 198,528 | 18,864 | 276,428–276,780 | 279,756 | 478,289 | no, both |
| (16, on) oversize | 381,824 | 32,048 | 368,588–369,420 | 372,684 | 754,513 | no, both |
| (16, off) oversize | 363,392 | 31,536 | 365,022–366,078 | 369,054 | 732,451 | no, both |

The S3 note's worry for (4, on) (5 + 132,992 + 262,144 = 395,141 > `MAX_INPUT`; a proof over 260,219 B would not fit)
is settled: Ligero's exact bound for this shape is 236,196 B, so every valid (4, on) input is ≤ 369,193 B.

**Soundness** per term, every shape: query 128.5, proximity 145.0 (M = 8: 144.4, M = 16: 143.7), linear 154.4 (4, on:
154.3; M = 8: 153.8; M = 16: 153.0), quadratic 168.0, Keccak collision 128.0, total 127.2 bits — as the six forms.

### 15.3 Time and memory

Native: `runs/l16-txm-proven.jsonl` (10 proofs, 1,000 honest verifies, 12 × 80 mutations per shape) and
`runs/l16-txm-oversize.jsonl` (3 proofs, 100 verifies, 12 × 10 mutations). wasm32 (gate-B method, node v26.8.1):
`runs/l16-txm-proven-wasm.jsonl` (module 315,724 B; 2 proofs made in wasm32, 1,000 verifies, 12 × 4 mutations) and
`runs/l16-txm-oversize-wasm.jsonl` (312,660 B; 2 proofs, 100 verifies). Limit: verify p99 ≤ 60 ms.

| Shape | Prove p50 / p99 native | Prove mean wasm32 | Prove heap native | Verify p50 / p99 native | Verify p50 / p99 wasm32 | Adversarial p99 native / wasm32 | Mutations accepted / panics |
|---|---|---|---|---|---|---|---|
| (1, on) | 698 / 715 ms | 1,527 ms | 43.2 MB | 10.04 / 14.03 ms | 19.29 / 26.88 ms | 2.28 / 2.11 ms | 0 / 0 of 960 |
| (1, off) | 677 / 730 ms | 1,606 ms | 42.9 MB | 9.75 / 13.92 ms | 17.70 / 24.40 ms | 2.35 / 2.03 ms | 0 / 0 of 960 |
| (2, on) | 677 / 699 ms | 1,530 ms | 43.2 MB | 10.24 / 15.03 ms | 19.18 / 28.62 ms | 2.15 / 1.68 ms | 0 / 0 of 960 |
| (2, off) | 663 / 680 ms | 1,444 ms | 43.2 MB | 10.08 / 14.23 ms | 18.14 / 25.57 ms | 2.08 / 2.33 ms | 0 / 0 of 960 |
| (4, on) | 680 / 707 ms | 1,531 ms | 43.6 MB | 11.13 / 16.05 ms | 20.89 / **28.85** ms | 2.31 / 1.78 ms | 0 / 0 of 960 |
| (4, off) | 695 / 747 ms | 1,426 ms | 43.2 MB | 10.39 / 15.29 ms | 18.76 / 27.01 ms | 2.17 / 2.83 ms | 0 / 0 of 960 |
| (8, on) oversize | 986 ms (3) | 2,094 ms | 61.4 MB | 14.20 / 17.82 ms | 26.67 / 36.06 ms | 3.36 / 2.30 ms | 0 / 0 of 120 |
| (8, off) oversize | 993 ms (3) | 1,989 ms | 60.6 MB | 12.83 / 17.42 ms | 24.09 / 30.20 ms | 3.24 / 2.30 ms | 0 / 0 of 120 |
| (16, on) oversize | 1,532 ms (3) | 3,217 ms | 96.6 MB | 22.56 / 31.28 ms | 39.98 / 50.65 ms | 4.27 / 3.46 ms | 0 / 0 of 120 |
| (16, off) oversize | 1,572 ms (3) | 3,380 ms | 94.9 MB | 18.57 / 21.77 ms | 38.58 / **54.57** ms | 2.97 / 3.57 ms | 0 / 0 of 120 |

Verify heap 1.2–1.3 MB (M ≤ 4), 1.5–1.6 MB (M = 8), 2.2–2.6 MB (M = 16). wasm32 linear memory (cumulative, one
process) 48.75 MiB after the six built shapes, 105.75 MiB after all ten — far below 256 MiB. Process max RSS: native
bench 48.4 MB, oversize 102.6 MB, wasm32 119.0 MB, wasm32 oversize 174.5 MB (`-time.txt`). wasm32 `fails` 0 in both
runs; the wasm32 proofs equal the native seed-1 proofs for all ten shapes (FNV `22dcbad4`, `4cadc229`, `5f5c03ab`,
`7facbac3`, `b875ae1e`, `7fe7b355`, `8a9f68a5`, `b76b59c6`, `24a6b91c`, `6464b4f3`).

**One M-leg transfer vs M op 1 transfers** [inference from the numbers above]: (4, on) is one input of ≤ 369,193 B and
one verify (p50 11.13 ms native), against 4 × 318,547 = 1,274,188 B and 4 × `R_TX` verifies (§14.3 p50 9.78 ms →
≈ 39 ms) — 3.5× fewer bytes and ≈ 3.5× less verify time; the Ligero proof hardly grows with M ≤ 4 (one row more at
(4, on)). Gas by the calldata model (`anon_sizes.py`) is S3's, not run here.

### 15.4 D3 verdict for PQZH

- **Built: M = 1, 2, 4, auditor on and off** — every bound within `MAX_PROOF_PQZH` and `MAX_INPUT`, verify p99 ≤
  28.85 ms wasm32 (60 ms limit), prove peak ≤ 43.6 MB native, ≤ 48.75 MiB wasm32.
- **Not built: M = 8, 16** — the exact bound (279,756–372,684 B) exceeds `MAX_PROOF_PQZH` 262,144 and the input
  (478,289–754,513 B) exceeds `MAX_INPUT` 393,216 (D8 / D20: no limit raise). Time is not what excludes them (wasm32
  p99 ≤ 54.57 ms at M = 16) but it is close to the limit at M = 16. They stay behind feature `oversize` (bench only;
  pqz-ffi refuses the feature).
- This is the plan's expected set PQZH {1, 2, 4}; `pqz_stmt::built_legs(PQZH_ID)` already says so.

### 15.5 Tests and cross-checks

- **`runs/l16-txm-tests.txt`**: 13 unit, 17 `attacks`, 8 `multi` tests pass; `runs/l16-txm-tests-oversize.txt`:
  `multi` with the ten shapes, 8 pass (10 × 960 mutated op 7 inputs rejected, 0 verifier panics);
  `runs/l16-txm-nobench.txt`: 11 unit tests without `bench`.
- **Pre-review fixes, rerun `runs/l16-txm-fix-*`** (all pass: 13 unit + 17 `attacks` + 8 `multi`; oversize `multi`
  8; `limits_exact` with `oversize`; 11 without `bench`). **H-2:** `rejected()` (in `multi.rs` and the same helper in
  `attacks.rs`) no longer counts an error or panic of the unchecked prover as a rejection — the cheating prover must
  return a proof and the verifier must reject it; in the rerun every negative case did. **H-3:** `limits_exact` pins
  the ten op 7 bounds of §15.2 and the built set. **X-1:** the per-vector e2 negative (‖e2‖² = 5,120) for each of
  four e2 vectors per shape. Negative witnesses per shape now 24 / 25 / 26 (auditor on, M = 1 / 2 / 4), 22 / 23 / 24
  (off), 33 / 34 and 31 / 32 at M = 8 / 16 (on / off), each + 3 ring rows.
- **`multi.rs`**: honest proofs of every shape (default, fee 0 with every leg 0, two real legs, the real leg at 0,
  M/2, M − 1 and the group boundary 3 / 4, the whole balance spent); 960 mutations per shape; per shape 22–34 negative
  witnesses (s_f, e_f, r_g, e1_g ℓ2 and bit range per group, a leg digit ≥ 16 with the same value, e2 per vector,
  overspend, Σ a_j + fee = balance + 1, d′ = b′ + 1, a leg under another key or the auditor's key, an auditor copy of
  amount + 1, legs moved between groups) + 3 ring rows; statement changes (fee ± 1 and 0, fee ≥ 2^64, amount ≠ 0, the
  M word, `auditorOn`, PQZL id, opTag, length ± 1, `recipientsHash`, legs swapped within and across groups); op 1 /
  op 7 separation at M = 1 and (1, on) / (2, off) separation; e_T range edges; hedging.
- **Six P6e forms unchanged** (`runs/l16-txm-native-fnv.jsonl`, seeds 0–4, equal to `runs/l15-tx0-proven.jsonl`):

  | Form | FNV seeds 0–4 |
  |---|---|
  | `R_REG` | `0ecf451a` `36b1d3e5` `bd7e088c` `e1019551` `b6215ec2` |
  | `R_TX` | `534b3a74` `720b94e0` `f5bb1d99` `b28db0b7` `f8c936d9` |
  | `R_BURN` | `f4fef37e` `e270d5c8` `400f16e3` `37999f9a` `e6464eb5` |
  | `R_DS` | `0a7acf34` `020286c2` `59182207` `0c0d5a95` `e62e8079` |
  | `R_DR` | `e42aa3da` `c5f5fb23` `f8cd4b87` `caa4fc89` `d83e24fc` |
  | `R_TX0` | `360216a0` `a69e9010` `4820dd60` `6db6d5aa` `d1b4f175` |

- **Cross-checks.** `runs/l16-txm-xcheck.txt`: the six forms' statements and witnesses 12 / 12 equal to
  `pqz_bench.c`'s, `kat_stmt: ok`. `runs/l16-txm-kat-multi.txt`: 18 op 7 statements (every built shape × default, fee
  0, two legs) parse under `pqz_kat.py`'s op 7 rules with PQZH's id only, rebuild byte for byte, carry the right
  `recipientsHash` and words, and their witnesses reproduce every u_g, v_j, v_f, v_{a,j} and the debit — `ok`.
  `runs/l16-txm-ffi-check.txt`: pqz-ffi `cargo check --all-targets` against the crate passes.
- **C ↔ Rust for op 7 (plan H1 "statements byte-identical with C", pre-review LH-2): not done on this branch.**
  pqz-core's C has no op 7 here (it is Track L's, `p6-anon-l`), and L's bench statements carry a filler opTag and
  recipientsHash, so they are not valid pqz-stmt statements. H's op 7 statements are checked against `pqz-stmt`
  (`parse_multi`, used by the crate itself) and `pqz_kat.py` (an independent Python codec). The C check belongs after
  L merges: feed `dump_setup`'s `txm*_{stmt,wit}.bin` to `pqz_prove(7, …)` / `pqz_verify` / `pqz_verify_fast`, and a
  C-made op 7 (stmt, wit) with a real opTag and recipientsHash to Ligero `prove` / `verify` (S4). **Done in P6-ANON S4** (`pqz-core/ffi/vectors/lh2.sh`, run
  `ffi/vectors/runs/s4a-lh2.txt`): both directions, 50 cases, 0 failures.

### 15.6 Rerun

```sh
CARGO_BUILD_JOBS=2 scripts/capped pqz-core/pqzh/ligero/runs/txm.sh l16-txm   # H1 + H2: tests, oversize, FNV, native + wasm32 benches, xcheck, ffi
```
