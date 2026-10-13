> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH Solidity verifier: gas without the precompile (P6-PQZH-SOL)

Written 2026-10-13 for the owner's question (TODO P6-PQZH-SOL: "measure, write into research"): **can a PQZH proof
be verified by a Solidity contract on a chain without the PQZ precompile, and at what gas, against the EIP-7825
transaction cap of 16,777,216?** Inputs: the design study `pqzh-design.md` and the prototype `pqzh-prototype.md`
(Plonky3 0.8.0, Goldilocks, FRI, Keccak, LogUp; measured proof shapes). Code: test-only Solidity in
`smartcontracts/evm/test/pqzh/` (never deployed), Python in `pqz-core/pqzh/sol/`. **No decision is recorded here.**

**[measured]** marks a number from a forge run in this note (§2). **[estimate]** marks a number from the model
(`model.py`), built from those measurements and the prototype's proof shapes. **[inference]** marks a conclusion drawn
here.

## 1. Result

**Yes, with conditions; how far depends on the soundness regime and on zero knowledge.** A Plonky3-style FRI verifier
for PQZH runs in Solidity at about 10–21 M gas as written here (straightforward Solidity and Yul, [measured] on a
synthetic end-to-end verifier, extrapolated per configuration). A hand-scheduled verifier is estimated at 1.4–6 M
[estimate, opcode floor]. Calldata, not the verifier, then decides the fit. Under EIP-7623 a 280–500 KB proof alone
costs 12–21 M gas.

| `R_TX`, cheapest setting per regime | Proof | Verify, this code | Verify, floor | Tx total, this code | Tx total, floor | ≤ 16.78 M? |
|---|---|---|---|---|---|---|
| Goldilocks², blowup 16, arity 8, 28 queries (the prototype default, ≈ 100 bits conjectured) | 135 KB | 9.8 M | 1.4 M | 12.8 M | 6.6 M | yes / yes |
| Goldilocks⁵, 128 bits conjectured: blowup 32, arity 8, 21 queries | 155 KB | 15.0 M | 2.4 M | 18.3 M | 7.4 M | **no** / yes |
| Goldilocks⁵, 128 bits proven (Johnson): blowup 32, arity 8, 42 queries | 277 KB | 21.4 M | 3.7 M | 26.7 M | 12.3 M | **no** / yes |
| Goldilocks⁵, 128 conjectured, **ZK** | 282 KB | 19.8 M | 3.4 M | 25.1 M | 12.5 M | **no** / yes |
| Goldilocks⁵, 128 proven, **ZK** | 506 KB | 29.3 M | 5.4 M | 38.2 M | 21.4 M | **no / no** |

[estimate; proofs in the EVM layout of §6 with 32-byte digests; tx = 21,000 + max(4·tokens + execution,
10·tokens) (EIP-7623) with the transfer's non-proof calldata and execution from pq-zether.md §9.3.]

- **Proven + ZK (the owner's current target: ZK required, Goldilocks⁵, 128 bits) does not fit any EVM transaction
  under the cap**, whoever writes the verifier: the EIP-7623 calldata floor of the 506 KB `R_TX` proof plus the
  transfer's other calldata is 21.4 M before any execution [estimate]. On a chain without EIP-7623 the same
  transaction pays 8.6 M of calldata, and with a floor-class verifier ≈ 14.3 M in total: it fits there, narrowly.
- **Conjectured + ZK and proven without ZK fit only with a tuned verifier** (≈ 12.3–12.5 M at the floor). As written
  here they do not (25–27 M).
- **What fits with straightforward code:** the four smaller relations at 128 bits conjectured without ZK
  (`R_REG` 14.1 M including its 3.3 M SSTORE2, `R_BURN` 15.3 M, `R_DS` / `R_DR` 12.9 M), and `R_TX` only at the
  prototype's ≈ 100-bit default (§8).
- Under EIP-7623, execution up to 6 gas per calldata token is free (the floor binds). For `R_TX` at 155 KB that is
  ≈ 4.1 M of verifier, so a verifier near the floor costs almost nothing beyond the calldata the proof needs anyway
  [inference].

**The planning value is about twice the floor** [inference]. The floor counts opcodes with every value on the stack.
Measured Solidity is 6–7× the floor (§5.3). A careful Yul verifier usually lands at 2–3× its opcode count. At 2× the
floor, `R_TX` comes to 8.1 M conjectured without ZK, 12.5 M conjectured with ZK and 12.6 M proven without ZK, all of
which fit. Proven with ZK comes to 21.4 M and does not: the calldata floor still binds.

**Conditions.** A PQZH proof is verifiable on the EVM only in an EVM variant of the proof system, i.e. its own
`proofSystemId` (§6):
1. **Keccak-256 everywhere** (Merkle leaves and nodes, transcript), not the prototype's raw Keccak-f sponge, which no
   opcode computes.
2. The **transcript seed by the keccak opcode, not SHAKE256**: SHAKE256 over the 83 KB `R_TX` statement costs
   **43.3 M** in Solidity against **49 k** for `keccak256` [measured]. A Horner fingerprint cannot replace the
   transcript hash: its point must be drawn after the statement is fixed, which takes a hash of the statement
   anyway. It is the tool for binding the statement into the AIR (§7).
3. **No full-height periodic columns**: `NTT(A)` and the selectors go into a preprocessed tree whose root is a
   verifier constant.
4. **Big-endian field elements** in the hashed bytes, so a calldata word needs one shift, not a byte swap.

## 2. What ran

| Item | Value |
|---|---|
| Toolchain | solc 0.8.37, EVM `osaka`, optimizer on (200 runs), legacy code generator (the repo's `foundry.toml`); forge; Python 3.12 stdlib |
| Machine | AMD Ryzen 5 7235HS; gas is deterministic, the machine does not matter |
| References | `pqz-core/pqzh/sol/ref.py`: Goldilocks, Fp2 (u² = 7), Fp3 (x³ = x + 1), Fp5 (x⁵ = 3), as in Plonky3 0.8 `p3-goldilocks`; pure-Python Keccak-256 / SHAKE256; Plonky3's mixed-height Merkle opening (`verify_batch`) and pruning count; FRI `fold_row` (closed form for arity 2, Lagrange interpolation otherwise); LogUp public sum; Horner fingerprint; the synthetic end-to-end proofs. `--selftest` asserts the field identities (x · x⁻¹ = 1, x^(pᴱ−1) = 1, x⁵ = 3), the Keccak empty-string digests, fold = interpolation and the pruning example of `pruning.rs` |
| Solidity | `test/pqzh/Pqzh.sol`: library `Pqzh` (field, extension, Merkle walk, fold, LogUp, Horner, row combination), contract `PqzhSkeleton` (end-to-end verifier skeleton, `verify` and `profile`); `test/pqzh/PqzhTest.t.sol`: 15 tests. Vectors `test/vectors/pqzh/` (`components.json`, three `e2e_*.bin`) |
| Model | `pqz-core/pqzh/sol/model.py` → `grid.txt`; `--selftest` checks the proof-size model against the prototype's measured sizes |
| Checks | every component value equals the Python reference; every e2e proof verifies with all Merkle paths and the 16-bit proof of work enforced, and a flipped sibling byte reverts; the default `forge test` suite and the size gate are unaffected (test-only, `src/` unchanged) |

## 3. Per-component gas [measured]

`forge test --match-contract PqzhTest -vv`. Per operation = (gas(n) − gas(0)) / n of a harness loop, loop and call
overhead included, as the skeleton pays it.

| Component | Gas |
|---|---|
| Goldilocks multiplication (`mulmod` + loop) | 52 |
| Goldilocks inversion (addition chain, 64 squarings + 9 multiplications) | 4,668 |
| Fp2 / Fp3 multiplication (packed word, library call) | 292 / 443 |
| Fp5 multiplication (5 words, unrolled, fixed buffers) | 788 |
| Fp2 / Fp3 inversion | 5,056 / 5,391 |
| base × extension + extension add | 389 |
| Merkle level, keccak opcode (plain path, per level) | 176 |
| Mixed-height opening, depth 10 (24-value leaf + one injected 6-value row) | 2,333 |
| Leaf hash of an opened row of 116 values (928 B) | 412 |
| Row combination Σ αᶜ·vᶜ over 116 opened values, E = 2 / 3 (incl. the `< p` check) | 18,603 / 22,210 |
| FRI fold, arity 2 / 8 / 16, Fp2 | 1,496 / 12,572 / 28,762 |
| FRI fold, arity 2 / 8 / 16, Fp3 | 1,897 / 13,629 / 31,027 |
| LogUp public term m / (β − k), batched inversion, Fp2 / Fp3 | 1,938 / 2,413 |
| Horner fingerprint per statement coefficient (incl. the `< q` check), Fp2 / Fp3 | 183 / 289 |
| SHAKE256 over 83,101 B (`src/ua/Shake.sol`, Keccak-f in Solidity: 611 permutations) | 43,316,724 |
| `keccak256` opcode over the same 83,101 B (call + copy included) | 53,333 |

The fold numbers include the harness copying the k inputs to memory (≈ 150 gas each). The arity-8 and arity-16
folds use an inverse DFT with base twiddles and a Horner step at β/s; 1/k is a constant (k divides p − 1).
**Horner beats the LogUp public-memory sum by ≈ 10×** per statement coefficient (183 against 1,938 in Fp2): LogUp
needs an extension inversion per term even when batched [measured].

## 4. End-to-end skeleton [measured]

`PqzhSkeleton.verify(shape, stmt, proof)` does the work of a Plonky3-style verifier for a given proof shape: the
seed `keccak256(TAG ‖ op ‖ be32(len) ‖ stmt)`, the challenges from a Keccak-256 duplex over the roots and
out-of-domain values, the Horner fingerprint of the statement, the DEEP precomputation, then per query: every
committed tree's opened rows (canonical check, Σ αᶜ·vᶜ), the mixed-height Merkle opening against the root, the DEEP
quotients with one batched inversion per query, every FRI round (siblings, leaf hash, Merkle path, fold, the roll-in
of shorter inputs), the final polynomial. **Enforced:** every Merkle path (trace, preprocessed and FRI trees, with
the verifier's own folded value inside each FRI leaf, so the layers are chained by the hashes) and the proof of work.
**Synthetic:** the query indices come from the statement digest, so `ref.py` can build sparse trees first (same gas);
the constraint check at the out-of-domain point is a stand-in loop of the estimated size (`model.ood_muls`: ≈ 900
extension multiplications plus the 64-point transform that evaluates the 64 period-64 NTT-weight columns at once, 192
butterflies); the final-polynomial values are computed but not compared, as they are random. Merkle paths are
unpruned (one full path per query), which costs ≈ 20 % more hashing than Plonky3's pruned multiproof.

`R_TX` in the EVM layout (§6), `PqzhSkeleton.profile` [measured]:

| Stage (k gas) | Fp2, blowup 16, arity 8, 28 queries | Fp3, blowup 16, arity 8, 56 queries | Fp2, blowup 8, arity 2, 38 queries |
|---|---|---|---|
| seed: keccak256 of the statement | 49 | 49 | 49 |
| roots, challenges, out-of-domain absorb, FRI roots, proof of work | 24 | 29 | 30 |
| Horner fingerprint of the 10,304 coefficients | 1,855 | 2,937 | 1,855 |
| DEEP precomputation (352 / 393 out-of-domain values) | 552 | 784 | 552 |
| constraint-check stand-in | 980 | 1,153 | 980 |
| opened rows: Σ αᶜ·vᶜ and DEEP numerators (201 values per query) | 1,725 | 4,298 | 2,341 |
| trace Merkle openings (4 trees, depth 19 / 18) | 538 | 1,080 | 700 |
| DEEP inversions | 825 | 1,871 | 1,108 |
| FRI rows and Merkle paths | 1,063 | 2,379 | 1,991 |
| FRI folds | 1,316 | 2,837 | 1,277 |
| final polynomial, query loop | 866 | 1,767 | 1,326 |
| **total inside `verify`** | **9,812** | **19,204** | **12,229** |
| skeleton proof bytes (unpruned paths) | 181,416 | 386,656 | 330,008 |

The gas of the external call is 1–3 M higher (10.8 / 22.2 / 14.5 M). That difference is the test's own memory
for building the 0.2–0.4 MB call, which a transaction pays as calldata instead (§7). Hashing is cheap (Merkle ≈ 5 %
of the total). **The cost is field arithmetic in Solidity**: an Fp2 multiplication as written costs 292 gas for about
40 gas of arithmetic opcodes, and the Horner pass over the statement alone is 1.9–2.9 M.

## 5. The model [estimate]

### 5.1 Proof bytes

`model.counts` rebuilds Plonky3's proof layout from the AIR shapes: commitments, out-of-domain values, opened rows
per query, pruned Merkle multiproofs (expected sibling count over random query sets), FRI siblings, final
polynomial. Against the prototype's measured sizes (its digests are four varint `u64`s, ≈ 38 B):

| Prototype proof | Model | Measured | Error |
|---|---|---|---|
| `R_REG`, Goldilocks², blowup 16, 28 queries | 108,772 B | 110,388 B | −1.5 % |
| `R_TX`, Goldilocks², blowup 16, 28 queries | 141,384 B | 143,965 B | −1.8 % |
| `R_REG`, Goldilocks², blowup 8, 38 queries | 130,708 B | 130,700 B | +0.0 % |
| `R_TX`, Goldilocks², blowup 8, 38 queries | 172,295 B | 178,000 B | −3.2 % |
| `R_TX`, Goldilocks⁵, blowup 16, 29 queries (conjectured 128) | 195,209 B | 199,884 B | −2.3 % |
| `R_TX`, Goldilocks⁵, blowup 32, 21 queries | 157,162 B | 160,813 B | −2.3 % |
| `R_TX`, Goldilocks⁵, blowup 16, 57 queries (proven 128) | 350,301 B | 355,513 B | −1.5 % |
| `R_TX`, Goldilocks⁵, blowup 32, arity 4, 42 queries | 288,056 B | 288,945 B | −0.3 % |

ZK (`HidingFriPcs`) is modelled as: committed domain one bit longer, quotient in 8 chunks instead of 2, 8 random and
salt columns per committed matrix, 4 salt elements per FRI leaf, a randomisation tree, and the Digit table at 128
rows. That comes out 9–14 % under the prototype's measured ZK sizes (`R_TX` 253,294 B, `R_REG` 195,134 B), so the ZK
rows are optimistic by about that much.

### 5.2 Verify gas of this code

`model.skeleton_gas` charges each stage of §4 by its count (opened values, terms, Merkle levels, FRI rounds and
levels, out-of-domain values, statement coefficients), with the measured units of §3. The remaining constants are
fitted to the three profiles: the shape terms from the two Fp2 runs, the extension-dependent terms from Fp2 and Fp3.
All three runs are reproduced within 0.1 %. **Goldilocks⁵ is an extrapolation**: each extension-dependent unit grows
linearly with the cost of one extension multiplication (292 → 443 → 788 gas), and an Fp5 inversion is taken as 3
multiplications plus a base inversion (Itoh–Tsujii).

### 5.3 The floor

`model.floor_gas` counts opcodes for a hand-scheduled verifier: a Merkle level ≈ 100 gas, pruned multiproofs, one
inversion per proof (all queries batched), an extension multiplication ≈ 60 / 100 / 250 gas (E = 2 / 3 / 5), a
base × extension MAC ≈ 15 + 8E, a butterfly ≈ 12E + 20, and E statement coefficients (each < 2⁴²) packed into
one extension element per Horner step. Stage by stage, `R_TX` (k gas, this code / floor):

| Stage | Goldilocks², b16, 28 queries | Goldilocks⁵, b32, 21 queries (conj.) | Goldilocks⁵, b32, 42 queries (proven) |
|---|---|---|---|
| Horner fingerprint | 1,886 / 412 | 5,473 / 556 | 5,473 / 556 |
| DEEP precomputation + constraint stand-in | 1,532 / 104 | 2,960 / 476 | 2,960 / 476 |
| opened rows | 1,725 / 260 | 2,448 / 614 | 4,896 / 1,228 |
| Merkle (trace and FRI) | 538 / 314 | 427 / 271 | 853 / 503 |
| DEEP inversions | 825 / 35 | 931 / 100 | 1,862 / 194 |
| FRI rows, paths, folds | 2,379 / 125 | 1,956 / 248 | 3,911 / 497 |
| rest (seed, commit, query loop) | 939 / 167 | 783 / 143 | 1,475 / 216 |
| **total** | **9,823 / 1,418** | **14,977 / 2,407** | **21,430 / 3,669** |

The floor is a lower bound. The 6–7× gap to measured code is stack shuffling, bounds checks, memory structs and
function calls, not hashing [inference]. The floor of the prototype default (1.4 M) matches the precompile pricing of
its native verify (11 ms p99 × 0.12 M gas/ms ≈ 1.3 M, `pqzh-prototype.md` §4), a rough cross-check.

## 6. The EVM variant of PQZH

What a Solidity-verifiable PQZH changes against the prototype (one `proofSystemId`, fixed with its FRI parameters)
[inference]:

| Item | Prototype | EVM variant | Why |
|---|---|---|---|
| Merkle hash | `PaddingFreeSponge<KeccakF>` over `u64` lanes | Keccak-256 of bytes (`SerializingHasher` + `Keccak256Hash`, compression keccak(l ‖ r)) | the EVM has the Keccak-256 opcode, not Keccak-f; a Keccak-f permutation in Solidity costs ≈ 66 k (`PqGas.t.sol`, `pq-eips-vs-scaas.md`) |
| Transcript seed | SHAKE256(tag ‖ op ‖ be32(len) ‖ stmt) | Keccak-256 of the same bytes (owner decision 5 allows Keccak or SHAKE) | 43.3 M against 49 k for `R_TX` [measured]; the token contract already hashes the statement for `authDigest` |
| Field element bytes | little-endian | big-endian | one `shr` per value instead of a byte swap (≈ 0.2 M per proof) |
| `NTT(A)`, selectors | periodic columns of full trace height | preprocessed tree, root a verifier constant (one more opened tree per query: ≈ 18 values + one path) | a periodic column costs the verifier O(period) at the out-of-domain point: 12 columns of 2^15 values in `Mv` alone would be ≈ 400 k extension operations, far over the cap [estimate] |
| Statement | periodic columns | its polynomials in the Poly AIR, coefficients bound by a Horner fingerprint (aux column, boundary value checked against the verifier's own Horner sum) | O(n) at ≈ 183 gas per coefficient as written, ≈ 40 at the floor; LogUp public memory is 10× dearer (§3) |
| Period-64 NTT weights | 64 periodic columns | kept periodic, evaluated by one 64-point transform | 192 butterflies instead of 4,096 MACs |

The extra tree costs about 10 KB of proof at 28 queries. The model's EVM-layout `R_TX` at the prototype default is
135 KB, against the prototype's 141 KB, because its 32-byte digests replace ≈ 38-byte varints. Alternative D2
(ring identities checked at one random point, `pqzh-design.md` §3.2) avoids the preprocessed tree but makes the verifier evaluate
A at a point: 65,536 base × extension MACs (≈ 1–2 M) and A (512 KB) in contract code [estimate]. D1 with a
preprocessed tree is cheaper.

## 7. Transcript and statement binding: what is viable

| Option | `R_TX` cost | Viable |
|---|---|---|
| SHAKE256 of the statement in Solidity (as the prototype seeds) | 43.3 M [measured] | no: 2.6× the cap alone |
| Keccak-256 opcode over the statement | 49 k [measured] | **yes**; the seed of the EVM variant |
| Horner fingerprint as the seed | — | no: not a hash. Its point must come from a transcript that already binds the statement, so the hash is needed anyway |
| Horner fingerprint to bind the statement into the AIR | 1.9 M Fp2 / 2.9 M Fp3 / ≈ 5.5 M Fp5 as written; 0.4–0.6 M at the floor with E coefficients per extension element | **yes**, in place of periodic statement columns |
| LogUp public memory (`pqzh-design.md` §3.4) | ≈ 20 M Fp2 (1,938 per coefficient) [measured unit] | no |

## 8. Five relations

Cheapest Goldilocks⁵ setting per relation and regime (by the total with this code; `grid.txt` has every setting)
[estimate]:

| Relation | Regime | ZK | Blowup / arity / queries | Proof KB | Verify M, this code / floor | Calldata M (EIP-7623 floor) | Tx M, this code / floor | ≤ cap |
|---|---|---|---|---|---|---|---|---|
| `R_REG` | conjectured | no | 32 / 8 / 21 | 123 | 8.4 / 1.6 | 5.56 | 14.1 / 7.4 | yes / yes |
| `R_REG` | conjectured | yes | 32 / 8 / 21 | 190 | 10.7 / 2.2 | 8.23 | 17.5 / 8.9 | no / yes |
| `R_REG` | proven | no | 32 / 4 / 42 | 220 | 13.5 / 2.6 | 9.47 | 20.8 / 9.9 | no / yes |
| `R_REG` | proven | yes | 32 / 8 / 42 | 341 | 17.5 / 3.5 | 14.28 | 26.6 / 14.3 | no / yes |
| `R_TX` | conjectured | no | 32 / 8 / 21 | 155 | 15.0 / 3.2 | 7.37 | 18.3 / 7.4 | no / yes |
| `R_TX` | conjectured | yes | 32 / 8 / 21 | 282 | 19.8 / 4.2 | 12.44 | 25.1 / 12.5 | no / yes |
| `R_TX` | proven | no | 32 / 8 / 42 | 277 | 21.4 / 4.5 | 12.25 | 26.7 / 12.3 | no / yes |
| `R_TX` | proven | yes | 32 / 8 / 42 | 506 | 29.3 / 6.2 | 21.40 | 38.2 / 21.4 | no / **no** |
| `R_BURN` | conjectured | no | 32 / 8 / 21 | 147 | 12.3 / 2.6 | 6.84 | 15.3 / 6.9 | yes / yes |
| `R_BURN` | conjectured | yes | 32 / 8 / 21 | 258 | 16.4 / 3.4 | 11.28 | 21.2 / 11.3 | no / yes |
| `R_BURN` | proven | no | 32 / 8 / 42 | 263 | 18.5 / 3.8 | 11.47 | 23.4 / 11.5 | no / yes |
| `R_BURN` | proven | yes | 32 / 8 / 42 | 464 | 25.3 / 5.3 | 19.49 | 33.4 / 19.5 | no / **no** |
| `R_DS` | conjectured | no | 32 / 8 / 21 | 134 | 10.5 / 2.2 | 5.88 | 12.9 / 5.9 | yes / yes |
| `R_DS` | conjectured | yes | 32 / 8 / 21 | 229 | 14.0 / 2.9 | 9.67 | 17.9 / 9.7 | no / yes |
| `R_DS` | proven | no | 32 / 8 / 42 | 239 | 16.4 / 3.3 | 10.07 | 20.5 / 10.1 | no / yes |
| `R_DS` | proven | yes | 32 / 8 / 42 | 410 | 22.1 / 4.5 | 16.91 | 28.9 / 16.9 | no / **no** |
| `R_DR` | conjectured | no | 32 / 8 / 21 | 133 | 10.5 / 2.2 | 5.87 | 12.9 / 5.9 | yes / yes |
| `R_DR` | conjectured | yes | 32 / 8 / 21 | 229 | 14.0 / 2.9 | 9.66 | 17.9 / 9.7 | no / yes |
| `R_DR` | proven | no | 32 / 8 / 42 | 238 | 16.4 / 3.3 | 10.05 | 20.4 / 10.1 | no / yes |
| `R_DR` | proven | yes | 32 / 8 / 42 | 410 | 22.0 / 4.5 | 16.90 | 28.9 / 16.9 | no / **no** |

Queries are the prototype's `p3-security` counts for 128 bits over Goldilocks⁵ with 24 grinding bits
(`pqzh-prototype.md` §7). Blowup 32 wins every row: the proof shrinks with fewer queries, and so does the
per-query verifier work. Its prover cost (12.4 s, 1.17 GB for `R_TX`, prototype §7) is a separate problem. The
non-proof parts come from pq-zether.md §9.3 [estimate there]: `R_REG` includes the 3.3 M SSTORE2 of the key, and
`R_DS` / `R_DR` are views (`verifyTransferAmount`). Their totals are the gas of a contract calling the view in a
transaction; the RPC gas cap of `eth_call` (geth's default 50 M) is not the binding limit [inference]. Arity 8 beats
2 and 16 in every regime. Arity 16 forces arity-2 rounds at the input heights, and an arity-16 fold costs 2.3× an
arity-8 fold.

## 9. Open questions

1. **Which chains have no precompile but need PQZH?** On chains with EIP-7623, proven + ZK is out of reach for a
   contract verifier (21.4 M of calldata floor for `R_TX`), so a PQZH token there would need conjectured soundness
   or no ZK, or a proof below ≈ 390 KB, where the `R_TX` calldata floor alone reaches the cap (WHIR; `pqzh-design.md` §5.5, TODO P6-PQZH next step). The precompile
   path has no such limit beyond `MAX_INPUT`.
2. **An EVM variant `proofSystemId`?** Keccak-256 digests, Keccak-256 seed, big-endian bytes, preprocessed `NTT(A)`,
   Horner statement binding (§6) are all cheap or neutral for the native verifier. One configuration could serve
   both, which avoids two PQZH ids. This is a decision for the PQZH spec.
3. **Verifier quality.** Between the measured 10–21 M and the 1.4–6 M floor, the real number for a production
   verifier is unmeasured. A hand-written Yul (or Huff) verifier of one fixed configuration would settle it. It is
   also the audit surface: a full FRI / AIR verifier in Solidity is a large audit item next to the precompile's Rust
   verifier.
4. **The constraint check is a stand-in** (≈ 900 extension multiplications). The real AIR evaluation at the
   out-of-domain point (LogUp terms, Digit rows, the Horner boundary) has to be generated from the AIR for the
   verifier, as the circuit compilers of Stwo / Plonky3 recursion do.

## 10. Reruns

```sh
python3 pqz-core/pqzh/sol/ref.py --selftest             # field / Keccak / fold / pruning identities
python3 pqz-core/pqzh/sol/ref.py                        # regenerates smartcontracts/evm/test/vectors/pqzh/* (~1 min)
python3 pqz-core/pqzh/sol/model.py --selftest           # proof-size calibration against the prototype
python3 pqz-core/pqzh/sol/model.py > pqz-core/pqzh/sol/grid.txt
cd smartcontracts/evm && scripts/capped forge test --match-contract PqzhTest -vv   # values, gas, e2e profiles
```

The `PROFILE` and `UNIT` tables of `model.py` hold the forge numbers of this note. After a change to `Pqzh.sol`,
copy the new forge output into them before rerunning the grid.
