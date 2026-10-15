> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZ for arbitrary circuits: what general-purpose post-quantum zero knowledge would take (estimate, no code)

Written 2026-10-15 at the owner's question: "if PQZ were made general-purpose, like a zkEVM, what would it take and
cost?" PQZ (Post-Quantum Zero-knowledge, decisions.md CTR-PQZ-01) today proves a **fixed set of relations**: each
operation (`R_REG`, `R_TX`, `R_TX0`, `R_BURN`, `R_DS`, `R_DR`, and the multi-recipient `R_TXM` in progress) has its own
hand-written constraint system. "General-purpose" means proving **any program or circuit** a user supplies. Nothing
here is built or measured; every figure is an estimate. Tags: **[measured]** from our runs, **[estimate]** /
**[inference]** this note.

## 1. Result

Three levels, increasing cost:

| Level | What it proves | Effort [estimate] | Stays post-quantum? | Recommendation |
|---|---|---|---|---|
| **1. Arbitrary circuits on Ligero** | any arithmetic circuit, bounded size | ≈ 1–2 months | yes | **the only level that fits this project** |
| 2. A zkVM (e.g. RISC-V) | any program compiled for the VM | many months to integrate an existing one; years to build | only if the final STARK proof is verified directly (no elliptic-curve wrapping) | not now |
| 3. A zkEVM | execution of EVM transactions / blocks | years, teams of dozens | usually not (final wrapping in Groth16) | do not build; use an existing one if ever needed |

## 2. Level 1 — zero knowledge for arbitrary circuits on Ligero

**Why Ligero and not the lattice system.** Ligero (our PQZH backend, `pqz-core/pqzh/ligero/`, `pqzh-ligero.md`) is by
construction a proof system for arithmetic circuits over a field: it already proves linear and quadratic constraints
over F_q (q = 2^42 − 215) with a Reed–Solomon commitment, Merkle trees and a Keccak transcript, hash-only security and
zero knowledge [measured]. The lattice system (PQZL, LNP22 through LaZer) is strong for the linear / norm relations of
module lattices, but has no natural front-end for arbitrary circuits [inference].

**What has to be built:**

1. **A circuit front-end.** Accept a standard circuit format — R1CS (circom / gnark style), a Plonkish table, or
   Noir's ACIR — and translate it into Ligero's linear + quadratic constraints over F_q. Choices: which format (ACIR is
   the friendliest for developers); how to handle values wider than 42 bits (limb decomposition, range checks); hash
   gadgets inside circuits (Poseidon-type over F_q, or Keccak emulated — costly).
2. **A generic Ligero prover / verifier path** driven by the compiled circuit instead of the six hand-written layouts:
   witness layout from the circuit, constraint matrices built once per circuit (cacheable), the same proven
   (unique-decoding) soundness analysis per circuit size, zero knowledge as today.
3. **A circuit registry on chain.** Each circuit gets an id = hash of its compiled constraint system (a "verification
   key"); a contract registers it once; proofs name the circuit id. The precompile loads (or caches) the constraint
   system by id.
4. **Precompile changes.** A new op (or a separate precompile) "verify proof for circuit id"; **gas priced by circuit
   size** (rows, constraints), calibrated like today's rows; a **maximum circuit size** so verification stays within
   the 60 ms p99 limit and the input limit.
5. **Tooling and assurance.** Developer SDK (compile, prove in wasm32 / native), test vectors per circuit, fuzzing of
   the front-end and of the generic verifier, a bigger audit scope (the compiler is now part of the trusted base).

**Costs and limits [estimate, scaled from the measured Ligero relations]:**

| Item | Estimate |
|---|---|
| Engineering | ≈ 1–2 months (front-end ≈ 3–4 weeks, generic prover / verifier ≈ 2 weeks, registry + precompile + gas ≈ 2 weeks, SDK / tests / fuzzing ≈ 2 weeks) |
| Proof size | grows roughly with √(circuit size): our `R_TX` (≈ 10^5 field constraints) is 231 KB [measured]; ≈ 10^6 constraints → ≈ 0.6–1 MB; ≈ 10^7 → several MB |
| Prove time | roughly linear in circuit size: 0.65 s for `R_TX` [measured] → seconds to tens of seconds for 10^6–10^7 |
| Verify time | linear in the parts the verifier touches; 10.5 ms for `R_TX` [measured] → the 60 ms p99 limit allows circuits a few times larger than `R_TX` on chain, larger ones need a bigger limit or aggregation |
| On-chain input | proofs above the 262,144 B PQZH limit (and `MAX_INPUT` 393,216 B) need new limits or splitting |
| Audit | the circuit compiler and the generic verifier join the audit scope |

**What it would enable:** other confidential applications on the same precompile — private voting, private auctions,
credential checks (prove an attribute without revealing it), confidential DEX matching, game rules with hidden state —
each as a circuit instead of a new hand-written relation, still post-quantum and zero-knowledge.

## 3. Level 2 — a zkVM

Prove that a program ran correctly on a virtual machine (typically RISC-V). Existing zkVMs (RISC Zero, SP1, Jolt and
similar) are built on STARK / FRI-style hash-based proofs, so their core is post-quantum. **The catch:** to make
on-chain verification cheap they usually **wrap the final proof in Groth16 over an elliptic curve**, and that last step
is **not** post-quantum. Keeping post-quantum security means verifying the STARK proof itself: our measurements of
comparable STARKs give 0.6–2 MB proofs, tens of seconds of proving and several GB of prover memory
([pqzh-backend-comparison.md](pqzh-backend-comparison.md)) [measured for our relation; zkVM proofs are larger]. Effort:
many months to integrate one (precompile for its STARK verifier with zero knowledge, tooling); years to build one.
Proving typically takes minutes and benefits from GPUs.

## 4. Level 3 — a zkEVM

Prove the execution of EVM transactions or whole blocks (every opcode, precompile, gas rule and state access). The
teams that built one (Scroll, Polygon, Taiko, the Ethereum L1 zkEVM efforts) needed years and dozens of engineers.
Most still end in an elliptic-curve wrapping, so they are not post-quantum end to end. Not a sensible project here; if
ever needed, use an existing one and accept its assumptions.

## 5. Recommendation

If PQZ is to become general-purpose, build **level 1 only**: arbitrary circuits on Ligero, with a bounded circuit size
so proofs and verification stay within the chain's limits. It reuses the PQZH backend, the precompile, `pqz-ffi`, the
vectors and fuzzing infrastructure, and it matches the name — post-quantum zero knowledge — without overclaiming.
Levels 2 and 3 are far beyond the project's size and tend to lose post-quantum security at the final step.

Status: **research only, no decision** (owner question 2026-10-15; nothing planned).
