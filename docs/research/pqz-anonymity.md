> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZ with hidden identities: what sender / receiver anonymity would cost (estimate, no code)

Written 2026-10-14 at the owner's request ("PQZL hides only the amount; what if identities are hidden too — estimate,
no code"). PQZ today hides amounts and balances; sender, receiver and auditor accounts are public (pq-zether.md, ring
size 2, no linkable tags). This note estimates two ways to hide identities. **No decision is recorded here and nothing
was measured**: every number below is an estimate scaled from the measured PQZL figures (`pqz-core/STATUS.md`,
`pqz-relations-burn-disclose.md` §1) and from published figures of others. Tags: [measured] our runs, [paper] a
published figure, [estimate] / [inference] this note.

## 1. Two options

| | A. Ring anonymity (Anonymous Zether paradigm) | B. One-time receiver accounts (stealth) |
|---|---|---|
| Hides | sender and receiver among N accounts | receiver only (unlinkable receive accounts) |
| Sender visible | no (needs a relayer: `msg.sender` / fee payer leak otherwise) | yes |
| New machinery | one-of-N relation, linkable tag per epoch / event, epoch roll-over | key re-randomisation from an ML-KEM shared secret, a key-registration rule without `R_REG` by the owner |
| Prior art | Lether (ePrint 2026/076, ACM CCS 2026): account model, LNP22 through LaZer, ≈ 68 KB per transaction of which ≈ 51 KB proof, prove and verify "a fraction of a second" [paper; ring size not checked, the PDF was not readable here] | stealth addresses (classical: ERC-5564); lattice re-randomised keys need their own noise analysis |

Option C, hiding in the whole set of notes (Zcash style), needs a note / UTXO model with nullifiers and a membership
proof (SMILE: ≈ 30 KB for a 2-in / 2-out transaction with 2^15 anonymity [paper], `pqz-proof-alternatives.md` §3). That
is a different token model, not an extension of PQZ, and is not estimated here.

## 2. Option A — ring of N accounts

**Mechanism.** The sender picks N accounts including itself and the receiver. Every member gets an update
ciphertext: −amount for the sender, +amount for the receiver, 0 for the others, indistinguishable from outside. The
proof adds: the sender knows the secret key of one member, that member's balance ≥ amount (without saying which),
exactly one debit and one credit. A deterministic linkable tag lets each account spend once per epoch (or per event,
as Lether's "event-oriented linkable tag"), so two proofs against the same balance cannot both land; balances are
frozen inside an epoch and pending credits roll over at the next one.

**What is cheap and what is not.**
- Cheap: the shared randomness of CTR-PQZ-04 (`out = u ‖ v_t ‖ v_f ‖ v_a`) extends to N recipients, so each extra
  member costs one `v` part (≈ 128 B) in the transfer output [inference from the 16,512 B ciphertext = 16,384 B `u` +
  128 B `v`].
- Expensive: the statement needs all N current balances `acc` (16,512 B each) and all N public keys (16,384 B each),
  because the proof may not reveal which one is the sender's. The balances come in calldata (CTR-PQZ-07) and both go
  into the precompile input.

**Estimate for an anonymous `R_TX`** [estimate; the proof growth is anchored on Lether's ≈ 51 KB vs our measured
42.7 KB, the rest scales the measured PQZL figures linearly in N]:

| | today (amount hidden) | N = 4 | N = 8 | N = 16 |
|---|---|---|---|---|
| Proof | 42,770 B [measured] | ≈ 48–52 KB | ≈ 50–56 KB | ≈ 55–65 KB |
| Transaction bytes | ≈ 77 KB (pq-zether.md cost line) | ≈ 120 KB | ≈ 185 KB | ≈ 320 KB |
| Precompile input (N × (key + acc)) | < 262,144 B | ≈ 130 KB | ≈ 263 KB, at `MAX_INPUT` | over `MAX_INPUT` |
| Prove native / wasm32 | 1.0 / 1.6 s [measured] | ≈ 1.5–2.5 / 2.5–4 s | ≈ 2–4 / 3–6 s | ≈ 4–8 / 6–12 s |
| Specialised verify | ≈ 8 ms p50 [measured] | ≈ 12–20 ms | ≈ 20–40 ms | ≈ 50–80 ms, over the 50 ms budget |
| Gas (EIP-7623 calldata floor + precompile at ≈ 0.12 M gas / ms) | ≈ 4 M | ≈ 7–8 M | ≈ 10–12 M | ≈ 19–23 M, over the EIP-7825 cap 16,777,216 |

- **Practical ring size ≈ 8** under the current limits. Packing keys and ciphertexts at 42 bits per coefficient
  instead of 8 bytes cuts the input by ≈ 35 % and allows N ≈ 11–12 [estimate]. Chains we run (7622, 22776) could raise
  `MAX_INPUT` and the gas cap.
- An anonymity set of 8–12 is small next to Zcash's whole note set; ring choice must avoid patterns that single the
  sender out (decoy selection is a wallet problem).

**Other effects.**
- UX: one spend per account per epoch; a proof goes stale if any ring member's balance changes mid-epoch (the epoch
  freeze exists for this); wallets need decoy selection and an epoch clock.
- Network: without a relayer the transaction sender and fee payer reveal the spender; the relayer path exists
  (root README §10).
- Compliance: the auditor still decrypts amounts; a new disclosure kind could also encrypt the sender / receiver
  identity to the auditor, so identities are hidden from the public but not from the regulator.
- Soundness: new relation (one-of-N selection, products of selector bits with the secret key, tag correctness), new
  MSIS / MLWE sizing, a new `proofSystemId`, a larger audit scope.
- Licence / patents: the anonymity extension and linkable tags were not in the G-LIC preliminary search; they would
  have to be added to the lawyer's scope.

**Effort** [estimate]: spec 2–3 weeks (relation, epochs, tags, contract state and events); `pqz-core` 3–5 weeks
(relation, codegen parameters, MSIS estimate, specialised verifier, differential tests); then audit.

## 3. Option B — one-time receiver accounts

The receiver publishes a scan key (ML-KEM-768, 1,184 B). The sender derives a shared secret and from it a
re-randomised MLWE key `pk′ = pk + A·δ + e′` whose secret `s + δ` only the receiver can compute; the transfer credits a
fresh account under `pk′`. No ring, no epoch.

- Cost: a new account per receive, ≈ 3.3 M gas to store the 16 KB key with SSTORE2 (pq-zether.md record storage), on
  top of the transfer [estimate].
- Open: the extra noise `e′` against the noise budget (B_FRESH, T5); key uniqueness today rests on `R_REG` proved by the
  key owner (§4.3), and here the sender creates the key, so the registration rule needs a new argument.
- The sender stays visible.

## 4. Status / next

Estimates only. Before any decision: read the Lether paper in full (ring size behind the 68 KB, tag construction,
refresh cost, how stale balances are handled), then size the anonymous `R_TX` with the codegen (as `params/e_s1_proof.sage`
did for `R_TX`) to replace the proof-size guesses above.
