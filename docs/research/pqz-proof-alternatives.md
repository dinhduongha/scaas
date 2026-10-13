> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQ Zether proof system: LNP22 and the alternatives

Written 2026-10-13 after the P6d spike (`pqz-core-e-s1.md`) missed the verify and prove kill criteria. It explains
what the "hash-based fallback" of CTR-PQZ-09 means, compares the two hash-based families the spec names (STARK and
Ligero), and lists the other zero-knowledge options. **No decision is recorded here:** the kill / fallback decision
is the owner's and waits for the upstream timing cross-check (owner, 2026-10-13). Nothing here was measured for PQZ
unless marked **[measured]**; **[estimate]** marks a rough calculation, **[inference]** a conclusion drawn here, and
the rest is general knowledge of the published systems, not checked against our relations.

## 1. What the fallback replaces

PQZ has two cryptographic parts. The fallback replaces only the proof:

| Part | Today (CTR-PQZ-03, CTR-PQZ-09) | With the hash-based fallback |
|---|---|---|
| Balance encryption | MLWE, Kyber-style (`d = 64`, `q = 2^42 − 215`) | unchanged |
| Zero-knowledge proof that a transfer is valid without showing the amount | LNP22 through LaZer, a lattice proof (`pqz-core`) | a hash-based proof: STARK or Ligero |

A hash-based proof is secure from the hash function alone (Merkle trees and Fiat–Shamir), so it is post-quantum in
the same sense as SLH-DSA, and needs no trusted setup. It proves an arbitrary arithmetic circuit; the relations
`R_REG` / `R_TX` (ring arithmetic mod q, norm bounds, binary decompositions) would be written as a circuit.

| | LNP22 (P6d) | Hash-based (spec §4.4 estimate) |
|---|---|---|
| Proof size | 42.7 KB **[measured]** | 100–300 KB |
| Prove | 17.0 s native, fork not optimised **[measured]** | seconds to tens of seconds |
| Verify | 15.2 s native **[measured]** | a few ms for a STARK (general knowledge, §2) |
| Zero knowledge | built in | not the default in Plonky3 / Winterfell; enabled or added by trace masking |
| Maturity | research code (LaZer) | mature Rust libraries (Plonky3, Winterfell) |

Trade-offs **[inference]**:

- It removes the verify bottleneck, the criterion P6d misses most (≈ 300×).
- The proof is 2–7× larger and exceeds the 96 KB kill line, so choosing the fallback means restating that criterion.
- Calldata grows with it: scaling the spec's ≈ 77 KB ↔ ≈ 2.81 M gas EIP-7623 floor, a ≈ 185 KB transfer costs
  ≈ 6–7 M gas instead of ≈ 2.8 M **[estimate]**.
- Prove may stay slow, and the circuit for arithmetic mod 2^42 − 215 and the zero-knowledge masking are our work.

## 2. STARK and Ligero

Both are hash-based, transparent and post-quantum. They differ in how the statement is written and how it is checked.

| | **Ligero** (Ames, Hazay, Ishai, Venkitasubramaniam, CCS 2017, [ePrint 2022/1608](https://eprint.iacr.org/2022/1608)) | **STARK** (Ben-Sasson, Bentov, Horesh, Riabzev, [ePrint 2018/046](https://eprint.iacr.org/2018/046)) |
|---|---|---|
| Idea | "MPC-in-the-head": the circuit's witness is Reed–Solomon encoded into a matrix; the verifier opens a few random columns | the whole execution trace (AIR: states and transition constraints) is shown to be a low-degree polynomial with FRI |
| Input | an arithmetic circuit (additions, multiplications over a field) | a state machine or a trace with a repeating rule; irregular circuits are harder to express |
| Proof size | ≈ √N (N = number of gates) | polylog N (≈ log² N) |
| Verify time | **linear in N**: the verifier recomputes the circuit's linear constraints | **polylog N**: a few ms, almost independent of the statement size |
| Prove time | fast, small constants, simple to implement | O(N log N), larger constants (many FFTs and hashes) |
| Zero knowledge | nearly built in (randomness added to the codewords) | not the default in Plonky3 / Winterfell; enabled or added by randomising the trace |
| Suits | small and medium circuits, a fast and simple prover | large statements or cheap verification (on chain), recursion |
| Ecosystem | mostly research code (Ligero++, and the linear-code family Brakedown / Orion) | mature: Plonky3, Winterfell, Stwo, Risc0 |

For PQZ **[inference]**:

- **The 50 ms verify limit favours STARK.** Its verifier stays at a few ms; Ligero's grows with the `R_TX` circuit
  and could hit the same problem P6d has.
- **Proving in the browser favours Ligero**: a lighter prover with less memory.
- **The field is the common obstacle.** STARK libraries work over small fields (Goldilocks 2^64 − 2^32 + 1,
  BabyBear 2^31 − 2^27 + 1); PQZ needs arithmetic mod q = 2^42 − 215, which has to be emulated with limbs and range
  checks, so the circuit grows several times. Ligero can in principle run over the field mod q directly if q − 1 has
  enough small factors for the FFT; not checked.
- **Proof size** is in the spec's 100–300 KB band for a statement of `R_TX`'s size for both; the exact figure depends
  on the security level and the blowup factor.

Knowing for sure needs a spike of its own: `R_TX` as a circuit in each system, measured.

## 3. Other zero-knowledge options

Grouped by family. "Fits" is a first judgement against the PQZ constraints (post-quantum, public verification on
chain, verify ≤ 50 ms, proof ≤ 96 KB, browser prover) **[inference]**, not a ruling.

| Family | Systems | Post-quantum | Fits PQZ? |
|---|---|---|---|
| Lattice RingCT proofs | MatRiCT / MatRiCT+; SMILE (Lyubashevsky, Nguyen, Seiler, CRYPTO 2021, [ePrint 2021/564](https://eprint.iacr.org/2021/564): ≈ 30 KB for a 2-in / 2-out transaction with 2^15 anonymity); Gao et al. ([ePrint 2021/1674](https://eprint.iacr.org/2021/1674): up to 50 % / 20 % smaller than MatRiCT / MatRiCT+) | yes | built for UTXO ring confidential transactions; PQZ is account-based without anonymity, so their set-membership part is unused; the balance and range parts are the same kind of LNP22-family proof |
| Lattice, other than LNP22 | LaBRADOR (recursive, ≈ 50 KB floor, not zero-knowledge in its original form); Greyhound (a polynomial commitment, with LaBRADOR); LatticeFold / LatticeFold+ (folding, not a final proof) | yes | not for one transfer; LaBRADOR is the spec's later block-level aggregation path (§4.4) |
| Hash-based, other IOPs | Aurora (R1CS, polylog proof, verifier linear in the circuit); Fractal (preprocessing, recursion); Brakedown / Orion / Blaze (linear-time prover, larger proofs); Binius (binary fields); FRI successors STIR / WHIR / Basefold (smaller proofs) | yes | candidates beside STARK / Ligero; WHIR-class commitments shrink the proof |
| MPC-in-the-head and VOLE-in-the-head | ZKBoo, ZKB++, KKW, Limbo; FAEST-style VOLEitH | yes | proof grows linearly with the circuit (MB class for `R_TX`); fits small statements only |
| Designated-verifier / interactive VOLE ZK | Wolverine, QuickSilver, Mac'n'Cheese | yes | no: needs interaction or a designated verifier; a chain cannot be one |
| Pairing SNARK around a PQ statement | Groth16, PLONK over BN254 / BLS12-381 | no | rejected by the spec (pairing soundness) |
| Lattice SNARKs with a preprocessed CRS | research only | yes | no mature implementation |

## 4. Options that change the architecture, not the proof system

| Option | What changes | Effect on the P6d misses | Cost |
|---|---|---|---|
| Optimise LNP22 first | nothing in the spec: lazy reduction, a real sort, fewer `R_TX` equations, verifier reuse, an AVX2 / `simd128` backend | unknown; the upstream cross-check tells how far it can go | engineering time only |
| Split the statement | `R_TX` proved as several smaller statements (or transactions), each under the gas cap | per-proof verify drops; the total does not | more transactions per transfer, more calldata |
| Aggregate | many transfers per proof (LaBRADOR, or STARK recursion); the chain verifies one proof per block | verify paid once per block | changes the transaction model (an aggregator, latency) |
| Verify off chain | a committee or a TEE attests the proof | removes on-chain verify | changes the trust model; not compatible with the current spec |

## 5. Other chains: Cellframe

Cellframe (DemLabs, built on the DAP SDK) is a post-quantum chain. What its public material shows (2026-10-13):

| Item | Cellframe | Source |
|---|---|---|
| Signatures | CRYSTALS-Dilithium (default, hybrid mode possible), Falcon, SPHINCS+ (backup, large), Shipovnik (code-based, Stern identification + Fiat–Shamir); Picnic in older posts | [wiki: Encryption Protocols](https://wiki.cellframe.net/02.+Learn/Technology/Architecture/Encryption+Protocols), [blog](https://cellframe.net/blog/cellframe-alphabet-asymmetric-encryption/) |
| Key encapsulation | Kyber-512 | wiki |
| "Zero-knowledge transactions" | outputs tied to one-time keys and closed by a ring signature; no proof system for hidden amounts is named | [white paper](https://cellframe.net/white-paper/) |
| Ring signature | ChipmunkRing (Gerasimov, [arXiv 2510.09617](https://arxiv.org/abs/2510.09617)), on the Chipmunk lattice signature: rings of 2–64, 20.5–279.7 KB, sign 1.1–15.1 ms, verify 0.4–4.5 ms (paper's figures); code in a DAP SDK feature branch; deployment not stated | arXiv |

For PQZ **[inference]**: Cellframe hides the **signer** (ring signatures), not the **amount**; nothing found proves
balance conservation or a range over encrypted amounts. PQZ is the opposite case (amounts hidden, no anonymity), so
Cellframe offers no proof system to take over. Its signature set matches what P6c already has (ML-DSA, Falcon,
SLH-DSA). A ring signature such as ChipmunkRing would only matter if PQZ later adds sender anonymity.
