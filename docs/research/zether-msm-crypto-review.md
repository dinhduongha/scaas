> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Cryptographic review of the merged Zether verifier

**A machine review, not an independent audit.** Claude Opus agents ran it on 2026-11-01, on the `zether-msm` snapshot `6fed9881`:
eight review lenses (Σ equations, Bulletproof equations, Fiat-Shamir and weights, groups and subgroups, scalar field and
encoding, reduction and completeness, forgery attempts, composition), plus one gap-closing execution at `M = 16`. Each finding
went to three verifiers: 24 of 27 votes real, 3 refuted. The verifier stays **UNAUDITED**. The design is
[contracts/zether.md §9.1](../contracts/zether.md#merged-check), the ruling CTR-ZTH-53.

## Verdict

- **Soundness holds.** The one G1MSM is equivalent to the per-equation check up to `(e − 1)/r + 2^-250` per attempt. About 95
  executed attacks found no forgery, no false statement accepted and no theft path: 44 targeted forgeries, 51 single-field
  malleability edits, cancelling pairs, cross-proof splicing, overspend, auditor-off slots, torsion and `M` shape confusion.
- **Completeness holds.** The per-equation verifier accepts ⇒ the merged one accepts, except at `ρ = 0` (`2^-254.86` per proof).
- **Proof bytes unchanged.** Proof, statement, prover and the challenges `c, y, z, x, w, u_j` are byte-identical: a transcript replay
  matched all 41 states and 21 challenges of `transcript_s3.json`, and the `ρ` fork discards its state.

The highest finding was **low**.

## Theorems

Setting: BLS12-381 G1, prime order `r` (`2^254.857`); keccak-256 as a random oracle; G1MSM refuses any input outside G1 whatever
the scalar or `k`, and returns 128 zero bytes for `O`. `e` is the number of equations: transfer 12 (11 auditor off), burn 5,
multi `7 + 6M` (`7 + 4M` auditor off), largest 103 at `M = 16`.

**Lemma (fold identity, proved).** For every form and slot, `f_new[slot] = Σ_i ρ^i · s_i[slot]` as a polynomial identity over the
integers in `c`, `ρ`, every `z_*`, `fee`, `amount` and every Bulletproof scalar and challenge. The slot map is a bijection onto the
per-equation verifier's points (182, 154, `159 + 25M`), and the weights are distinct consecutive powers. Symbolic at
`M ∈ {1, 2, 3, 16}`; numeric with the literal `addmod` / `mulmod` / `r − c` / `_negS` at `M = 1..16`, both auditor settings.

**Theorem A (soundness relative to the per-equation verifier, proved).** For an adversary making at most `Q` oracle queries:

```text
Pr[new accepts ∧ per-equation rejects] ≤ (Q + 1)·(e − 1)·(⌊2^512/r⌋ + 1)/2^512 + (Q + 1)²/2^256
```

Per attempt that is `2^-248.185` at `e = 103`; the `(e − 1)/r + 2^-250` and `< Q · 2^-247` of §9.1 are correct upper bounds. The
bound holds for every query order: `ρ` and the Bulletproof challenges are distinct oracle points, so conditioning on everything else
fixes the `d_i` and leaves `ρ` uniform.

**Theorem B (knowledge soundness transfer, conditional).** `κ_new(Q) ≤ κ_legacy(Q) + ε_fold(Q)`, via a wrapper that filters the
adversary's output by the per-equation verifier. Conditional on the per-equation extractor, which was not re-derived.

**Theorem C (completeness, proved).** Per-equation accepts ⇒ merged accepts iff `ρ ≠ 0`.

**Theorem D (zero knowledge, proved).** Unchanged: the prover and its proof distribution are identical, and the verifier is
deterministic in the statement and proof.

**Load-bearing precondition.** Every point is in G1. On the full curve group the root bound fails: an order-3 pair folds to `O` for
`ρ ≡ 1` mod 3, executed about 1/3 of the time.

## Preconditions

1. **G1MSM subgroup-checks every input, scalar 0 and `k = 1` included, and errors on failure.** EIP-2537 mandates it; executed on revm
   and on the SCaaS testnet's Nethermind by `eth_call`; the client source of geth, Erigon, Besu native, Nethermind and revm was
   read. The official EIP vectors pin neither negative case, so any other stack must be probed.
2. **`O` is encoded only as 128 zero bytes** and G1MSM returns it for a zero sum.
3. **keccak-256 behaves as a random oracle**; the absorb chain is injective per step.
4. **The per-equation verifier's knowledge soundness:** inherited, not re-derived.
5. **Callers of `verifyFold` and `verifyRange` supply** a transcript-derived `ρ`, a state binding every `V`, and weight `ρ^e ≠ 0` mod `r`.
6. **The token bounds `fee < 2^64` and `0 < amount ≤ maxShielded ≤ 2^54`** before it builds the header: E5 is a congruence mod `r`.
7. **Every untrusted point reaches the MSM**, its slot kept at scalar 0, and the token's G1ADD and G1SUB only touch points already
   validated.
8. **Off-EVM ports subgroup-check every untrusted point before folding.**

## Findings, and what became of each

| Id | Severity | Finding | Status on the branch |
|---|---|---|---|
| F1 | low | `isSupportedOnThisChain` did not probe the subgroup check; on a chain skipping it everywhere, a sender could plant a 3-torsion component in a recipient's balance. Griefing, no theft | fixed: two capped probes |
| F2 | low / info | `verifyFold` accepted weight 0, and `ρ = r` passed its guard. Unreachable through the token | fixed: reduced mod `r`, refused at 0 |
| F3 | info | §9.1's off-EVM note was wrong on the `−1` slots | rewritten |
| F4 | info | `fee` and `amount` enter E5 mod `r` unchecked; the token's bounds were not named there | named in §8 and the NatSpec |
| F5 | info | `verifyFold` and `verifyRange` trust the caller's `ρ`, weight and state | documented, no change |
| F6 | info | an honest proof is refused at `ρ = 0` | required, documented |
| F7 | info | the suites stopped below `M = 16` and had no BP-1 residual on the multi form | closed: `M = 16` both auditor settings, `M = 17` |

Refuted, 3 of 3 verifiers: an extra `D/r` term in §9.1's bound. No change.

Reviewers split on F2's severity, low or info; the fix is the same. On F1's mechanics the verifiers corrected the write-up: the freeze
is repairable by a second `2T`, and the attack needs an MSM that skips the check on **all** inputs.

## Not done

- RFC 9380 re-derivation of the 130 generators: recomputed only through the repo's `HashToCurve.sol`.
- The per-equation verifier's special-soundness proof, the hypothesis of Theorem B.
- Nethermind's zkevm accelerator build and Besu's Java result cache.
- Token-level suites at `M = 16`: the verifier is driven directly, on hand-built statements.
- Every leg at `M = 16` broken alone on bytecode: the last leg is, legs 0..14 only in the Python check.
- Malleability across several fields beyond the two constructed pairs.
- A `verifyRange` weak-Fiat-Shamir forgery: derived, not executed.
- Gas: not measured, by the owner's order.

## Reproducing it

The models are in `smartcontracts/evm/runs/2026-11-01-zether-msm-crypto/`. They transcribe the verifier at the snapshot, before F1 and
F2, neither of which moves a fold scalar.
