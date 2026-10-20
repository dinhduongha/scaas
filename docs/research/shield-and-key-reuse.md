> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Zether key reuse and a proof-free `pqzShield`

Status: controller analysis 2026-10-20 on two owner questions (chat). Nothing is decided by this note.

## 1. The Zether key both signs and decrypts: is it a leak risk?

Under CTR-UA-30 option (A) a classical Zether UA uses one secret `x` (public key `Y = [x]G`) for three things:
ElGamal decryption of its own balance (done locally by the wallet), the Σ-protocol inside every transfer / burn proof
(it proves knowledge of `x`), and Schnorr signatures (`pop` at `register`, `zetherRollOverSigned`,
`zetherSetRollOverMode`; zether.md §13).

Cryptographic answer: no extra leak from the reuse itself, given the rules already in place.
- Zether as published (Bünz et al., FC 2020) uses exactly this: the account is `y = g^x`, the proof shows knowledge of
  `x`, registration is a Schnorr signature by `x`. ElGamal and Schnorr over one key in one group are a known
  jointly-secure combination (Haber–Pinkas, CCS 2001) [inference for our exact variant: not re-proved here].
- Nobody can ask the chain to decrypt: decryption is local, there is no decryption oracle an attacker can drive with
  chosen signatures, and a Schnorr signature (hedged nonce, random-oracle model) reveals nothing about `x` beyond `Y`.
- Domain separation: Schnorr hashes `"SCAAS-ZETHER-SCHNORR-V1" ‖ R ‖ Y ‖ msg32` with `uaMessage(kind, purpose, …)`;
  the proofs use their own Fiat–Shamir transcripts, so a signature cannot be replayed as a proof part or the reverse.
- The one known cross-scheme hazard is already blocked: a BLS key on the curve of `Y` is refused (publishing `[x]G2`
  makes DDH on G1 decidable and breaks ElGamal privacy), and one key may serve one kind / one UA only (CTR-UA-10,
  `keyOwner`).

Operational risks (real, not caused by the reuse but by "one key does everything"):
1. **A leaked `x` loses funds and privacy together.** With a separate spending UA (`authRef ≠ 0`, today's rule) a leak
   was only a read-only breach (`survivesEncKeyLeak`). In "self" mode it is a full loss.
2. **`x` is a hot key.** The wallet needs it for every balance read and every proof, so it sits in software memory
   often; passkeys / HSMs / secure enclaves cannot hold a bn254 / BLS12-381 Zether key or run the prover.
3. **No view-only key.** An accountant, auditor or tax office that must read the balance gets spending power too
   (disclosure proofs per amount remain the alternative).
4. **Bad randomness** in a Schnorr nonce or the prover leaks `x` (hedged nonces mitigate; same for any Schnorr key).
5. Quantum: `x` falls to a quantum computer either way; reuse changes nothing there (that is PQZ's job).

Option for the owner: keep "self" mode as the default but keep an **optional** spending co-signer for Zether UAs
(today's `authRef`: a passkey, HSM or msig UA must also sign `authDigest`), so a holder who wants it gets "leak = read
only". Open question: CTR-UA-30 removes `authRef` for `pqz-mlwe`; the text does not say whether the Zether `authRef`
stays.

## 2. Does `pqzShield` need a proof?

Classical Zether: `shield` adds `[amount]G` to the account's pending ciphertext without a proof
(`ZetherLib.shield` → `_credit`), and anyone may roll pending into the balance.

PQZ can do the same. The PQZ encryption is additively homomorphic and a public amount has a trivial encryption
`Trivial(amount)` (no randomness, no noise); the contract already adds it (`PqzCt.addTrivial`), and `pqzRollOver` is
already permissionless and computes `acc += Σ cts` on chain (`PqzLib.rollOver`). So:

- Shield (signer's own UA only, as CTR-PQZ-06 2026-10-20 already rules): move `amount · shieldScale` from the signer's
  public balance to `SHIELD_POOL`, append a **trivial pending entry** `(TRIVIAL, amount)` to the signer's own ordered
  queue (one slot, no blob, ≈ 26 k gas under the 5h layout D2).
- Rollover (anyone): when it meets trivial entries it adds `Trivial(Σ amounts of the run)` to `acc` — zero noise, and
  **one unit** of `K_MAX` per run (the digits of a public sum are normalised, unlike a sum of ciphertexts).
- Debits: unrolled trivial entries in the inline window are summed into the existing `Trivial(shieldIn)` term of `T`;
  the relation does not change. A debit's un-roll of `[p, rolled)` (5h D4) treats trivial entries like any other
  entry, so nothing is lost or skipped.
- Unshield stays a proven burn (spending an encrypted balance always needs a proof), then pool → public → unwrap.

Wrap then becomes the same flow as Zether: mint to the public UA balance → move to `SHIELD_POOL` → pending →
rollover; unwrap is the reverse.

Why the design had a proof: before 2026-10-20 public amounts went to the shared integer `plainPending`, which only a
debit could consume (as the trivial term), and anyone could shield into another account; counting such dust as pending
slots let `pqzShield(victim, 1)` × 4096 lock a victim (CTR-PQZ-06). The 2026-10-20 ruling dropped `plainPending` and
third-party shielding and made the shield a proven debit "so it lands in `acc` in one call". With shielding limited
to one's own account, the dust attack is gone, so the trivial-entry path no longer needs that protection.

Trade-off:

| | Proven-debit shield (ruling 2026-10-20) | Trivial entry + rollover (this note) |
|---|---|---|
| Client needs a PQZ prover | yes | no (wallets, the Odoo connector can wrap + shield) |
| Spendable | at once | after a rollover (anyone may call it) |
| Gas [estimate] | one debit ≈ 3.5 M + verify | shield ≈ 0.1 M + rollover base ≈ 2.8 M (shared by every entry rolled with it) |
| `K_MAX` units | debit resets `acc` (1 unit) | 1 unit per run of trivial entries |
| Relation / `proofSystemId` | unchanged | unchanged |

Both can coexist: the trivial-entry shield as the default, and `shieldIn` on a debit for a holder who is proving
anyway. Status: proposal for the owner; if accepted it folds into plan Task 5h (state layout D2 gains an entry type).

## 3. The four transfer flows, rollover vs debit, one name for both layers (owner questions, 2026-10-20)

| Flow (A → B) | Classical Zether today | PQZ today (rulings 2026-10-20) | Proof needed |
|---|---|---|---|
| 1. public → public | UA-ledger / ERC-20 transfer | same | no (A's signature) |
| 2. public → B's confidential | `zetherShield(ua, amount)`: any registered UA, `pending_B += [amount]G` | removed ("no shielding into another account"); own account only, as a proven debit | **no, cryptographically** (a public amount has a trivial encryption) |
| 3. A's confidential → public | `zetherUnshield` with a `recipient` | `pqzUnshield` with a `recipient` | yes: A's debit (burn) |
| 4. confidential → confidential | Zether transfer | `R_TX` (op 1), `R_TXM` (op 7) | yes: A's debit |

Flows 2 and 3 are conveniences (flow 1 + B shields, or A unshields + flow 1) that save a transaction and let B stay
offline; the amount is public in both either way.

**Rollover vs debit (PQZ).** A rollover is permissionless, needs no proof and no key: `acc += Σ pending ciphertexts`
(homomorphic, on chain); it only raises the balance and the noise (`accUnits += n`). A debit is every operation that
lowers the encrypted balance — `R_TX`, `R_TXM`, burn / unshield, refresh — and only the owner can make it: the proof
shows knowledge of the secret key and `b' = b + shieldIn − v − fee ≥ 0`, and `acc` becomes a fresh encryption of `b'`
(noise reset, `accUnits = 1`). `plainPending` / `shieldIn` was only a public term inside a debit's `T`; removing it
removes no debit. Its real flaw was that **only a debit could consume it**, so a shielded amount needed a proof before
it counted in `acc`. Folding public amounts in the rollover (`Trivial(sum)`, zero noise, one unit) removes that flaw.

**Why flow 2 differs between the layers.** Zether: pending is one aggregated ciphertext and EC-ElGamal addition has
no noise, so any number of third-party shields costs the victim nothing (the spammer pays gas); a public rollover can
change `acc` under an in-flight debit, which `OWNER_ONLY` mode answers. PQZ: proven credits are separate ciphertexts,
each costing a unit of `K_MAX` and a state slot — the 2026-10-06 dust attack came from counting public shields the same
way. Public amounts can instead be **merged into one per-account accumulator** (or one trivial tail entry) folded by
the rollover as a single unit, so third-party shields cost the receiver nothing either. Design detail for 5h: the fold
must sit at an ordered position (or be keyed by block) so a debit in flight neither loses the folded amount when it
replaces `acc` (D4) nor gets griefed by a merge into an entry it inlined.

Controller recommendation: allow all four flows on both layers; flow 2 proof-free on both (Zether as today; PQZ with
the merged accumulator folded by rollover; shield-to-self is flow 2 with B = A); `shieldIn` on a debit stays optional.

**One name: `mtxShield` / `mtxUnshield`.** Feasible. `zetherShield(ua, amount)` and `pqzShield(ua, amount)` already
have the same shape; after 5h (D5: debits read `acc` from state, optional hint) the unshields converge on
`(bytes payload, bytes proof, bytes authSig[, bytes hint])` with the layer's own payload. Points to settle: (1) the
`*_ZETHER_PQZ` kinds (in the enum, not built) carry both layers, so they need a layer argument or the kind decides;
(2) `mtx*` in this code base names relayed meta-transaction entry points (`mtxWrap`, `mtxSettle`, …), which fits since
both layers are relayed through the envelope (CTR-PQZ-21); (3) the siblings follow the same scheme (`mtxWrapShield`,
`mtxUnshieldUnwrap`, `mtxConfidentialTransfer…`, `mtxRollOver`) and the events (`Shielded` / `Unshielded`) as one
`IConfidentialToken` interface; (4) timing: with 5h, where the PQZ ABI changes anyway (test chains, no migration).
