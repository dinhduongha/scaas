> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

Requested by the owner (2026-11-06); Fable reviewed the first draft of [the attested-verify spec](../superpowers/specs/2026-11-06-attested-verify.md), with Zether still in (removed afterwards by owner ruling R1). Copied verbatim below.

# Counter-review: `docs/superpowers/specs/2026-11-06-attested-verify.md` (group 3f)

Reviewer: Fable 5.1, 2026-11-06. Read-only; nothing built or run. Code read at `ua-mtx-merge` HEAD `65caf46f`.
Owner ruling received mid-review (2026-11-06): **Zether is out of 3f; O4 withdrawn.** Zether findings are kept in one
line (§1.Z) only to say what the removal closes. Everything below is about PQZ unless marked Z.

## 0. The two open PQZ points (answer first)

### (a) Per-chain book, or the attestation inline on the debit entry?

**Inline.** The book exists only to avoid an ABI change; what it costs is larger than what it saves:

| Book (spec C1) | Inline |
|---|---|
| 2 new contracts (`AttestBookBase`, `PqzAttestBook`, 4–7 KB), codehash pinned in the release `Env` → `PqzLayer._init` deps change (finding 1) | 0 new contracts; one struct + one `requireAuthorized` call inside `PqzCore._check` |
| 2 transactions per debit; the second is unpaid by the envelope's `fee` (finding 5); orphan records (risk 7); `epoch` machinery (I3); `validUntil` | 1 transaction; the op's own `validUntilBlock` bounds the attestation; the verifier is read once from storage at the op; nothing stored, nothing to grief, nothing to order |
| Node: attest-before-op on one lane. The node has no per-job two-transaction chain today (`submit.rs`; `prerequisite_job_id` is the consumer's, `job-api.md:882`), a `signed` outer tx is never requeued (`submit-lanes.md` §4) → new machinery, and a landed attest with a replaced op is an orphan | Node: one more named sub-object in the existing rows `typed.rs:136–140` (`attest: {validUntil, verifier, auth}`), no new contract class, no lane rule, no mesh refusal row, no `attest_proof` job (which also conflicts with CTR-PQZ-15 "no new kind" — missing from §10) |
| Two governance stubs on every PQZ kind (+0.2–0.35 KB on kind 13) **plus** the `PqzLayer._init` deps change the spec does not count | Six debit entries gain two calldata params (`PqzAttest a, UASig attSig`, next to `proof` / `accHint`, outside the subject's typed struct, so no typehash moves). Decoding/forwarding ≈ 30–60 B each ⇒ +0.2–0.4 KB on kind 13: the same order as the stubs, and the stubs stay (verifier transfer) in both designs |
| CTR-PQZ-14 / CTR-ZTH-39 "no on-chain attestation": a stored record exists; §10 row 6 waves it | nothing is stored; row 6 disappears |
| Auditability: `ProofAttested` + `AttestationUsed` | one event `ProofAttested(statementHash, proofHash, verifier)` emitted by the debit, beside the proof in calldata: the same record |

Rules: CTR-MTX-29 is satisfied (named typed struct, one `UASig`; §9's "not a lever" line is about hiding it inside
`proof` bytes, which inline does not do). CTR-MTX-30 holds: still one signed entry per operation; the attestation is an
unbound field of the entry like `relayer` / `feeRecipient` (a relayer may swap it for another valid one over the same
hashes, harmless). O1–O3 are untouched; C1 is a controller call, so it may be overridden.
Gas on the op: + registry `requireAuthorized` on the verifier (secp256k1 / EOA ≈ 8–11 k; 2-of-3 `msig` ≈ 30–40 k; pure-
Solidity `mldsa65` 5.8 M measured `verifyCached`). With `−3.7…−5.4 M` for the precompile the debit still fits 2^24 for every
kind in §4.1; the `UAPqzHolder` 2^24 bound (`UARegistryLib.sol:364–369`) is the holder's, not the verifier's, unchanged.
Starvation: reuse `_check`'s `try/catch` shape (`PqzCore.sol:823–829`) so a starved registry is `UAVerifyGas`, never
`AuthRejected` / `ProofRejected`.
What inline needs in the mutant table: `a.token != address(this)` unchecked; `a.chainId` unchecked; `proofHash` not
compared; verifier read from calldata instead of storage; `validUntil` unchecked.

### (b) Accept unproven keys; the verifier checks `R_REG` off chain

**Nothing material is lost; take it and drop §6.3 (T46, `attestPqzKey`, `pqzKeyFor`, `PURPOSE_KEY_ATTEST`, CTR-UA-41,
the registry dependency on 3c, Q6).** Field by field:

- **`keyOwner` uniqueness (`UAKeyInUse`).** Enforced only "where a proof is checked" (`IUARegistry.sol:281`). What it
  prevents is one proven key under two UAs. The verifier's off-chain `R_REG` check gives the same guarantee of sk-knowledge
  per UA (the `R_REG` message binds the UA, `IUARegistry.sol:258`), so a stranger cannot bind a victim's pk to his own UA.
  The one thing not prevented is the *same owner* binding one key to two of his UAs: the registry forbids it for proven
  keys only as hygiene; the ciphertexts for either UA are his anyway. No value moves wrongly.
- **S32** (`accounts.md:2086`): "a UA that lists someone else's key gains nothing: it cannot decrypt". Already true for the
  unproven state the registry stores today; an honest verifier additionally refuses the listing because `R_REG` fails. The
  KEM key has no uniqueness rule *on purpose* for the same reason (a uniqueness rule is a blocking vector).
- **CTR-PQZ-12 (only a PQ signer holds a key)** is enforced at store time by `_pqzHolder` (`UARegistryLib.sol:356–369`),
  before any proof, for proven and unproven keys alike. Unchanged.
- **Key replacement (R-cross-set, `setPqzKey` on an unproven key).** The verifier's cache key must be `(ua, pqzKeyHash)`,
  never `ua`. Belt and braces: the statement itself carries `pk_f`, `pk_t`, `pk_a` (§5.2 table), so a swapped key changes
  `statementHash` and an attestation for the old key does not fit the op. Say both in the spec.
- **The `0x0142` list and `proven` as a chain-readable fact.** Lost for wallets and indexers: nobody can read from chain
  whether a payee's key is usable on an ATTESTED token; the wallet asks the verifier (or the node's service) before a send.
  Liveness only: a refused key fails the debit before any credit. Acceptable; write it in AV-1 and `integration.md`.
- **Soundness of the key.** In ATTESTED mode the verifier already decides whether a lattice proof over those keys is valid
  (AV-1); deciding whether `R_REG` is valid adds no new trusted party.
- **Code consequences.** `PqzCore._keyPtr` / `_creditKey` in ATTESTED mode drop the `proven` test and keep
  `ptr.code.length == PqzCt.PK + 1` (`PqzCore.sol:898–901`); `PqzStateLib.init`'s auditor check (`PqzStateLib.sol:40`)
  must accept an unproven auditor key in ATTESTED mode (today it calls `_keyPtr`, which requires `proven`); gen-2 forwarding
  stays `pqzKeyOf`'s. The verifier service verifies `R_REG` over `uaMessage(0x0142, PURPOSE_POP_V2 | PURPOSE_PQZ_KEY, …)`
  from `registrationOf` / `pqzKeyOf` (`pqzPop` bytes are stored unchecked, `IUARegistry.sol:257`), caches per
  `(ua, pqzKeyHash)`, and refuses an op whose statement names a key it has not passed.
- One requirement to keep: the registry must have the `pqzPop` **bytes** (a hash-only record cannot be re-verified); the
  verifier refuses a key whose pop was never stored, and the disclosure says so.

Together, (a) + (b) + the Zether removal take out T44 (as a contract), T46, T47, T48, most of T50 and the registry
coupling to 3c. Realistic remainder: ≈ 6–8 agent-days (§2 of this report), not 16.

## 1. Findings

Severity: P0 funds/soundness, P1 design hole or wrong claim that changes the build, P2 inconsistency or under-counted
cost, P3 polish.

1. **P1 — §3 "PQZ release without the precompile": the gate is misplaced.** The spec changes "`OpenFactory`'s canonical-
   verifier check". `OpenFactory` has no such check ("verifiers … are immutables of the code by construction",
   `OpenFactory.sol:15–22`). The gate is `PqzLayer._init`: `if (env.deps.length != 1 || env.hedera ||
   !SigCheck.isContract(env.deps[ENV_PQZ_VERIFIER])) revert BadInit();` (`PqzLayer.sol:70`), then `PqzStateLib.init`
   reading `v.PRECOMPILE()` / `v.PROOF_SYSTEM_ID()` and `PqzSafety.requirePqz` (`PqzStateLib.sol:42–45`). Fix: name
   `PqzLayer._init` and `PqzStateLib.init`; count the token bytes of the new branch in §9 (today "+0 for the init"); and
   note that `DeployBase` does not deploy the PQZ kinds at all (its comment: "12, 13 by `script/pqz/e2e.py`",
   `DeployBase.sol:381`), so T45's deploy change lands in `script/pqz/e2e.py`, not `DeployBase`. With the book design the
   book would also be a dep (`deps.length` 1 → 2 on every PQZ release, PRECOMPILE ones included), contradicting "no change
   to the PRECOMPILE … shape". Inline (0.a) avoids the dep.

2. **P1 — §2 / §4.2: a compromised verifier on kinds 4–5 cannot be stopped.** The only on-chain answer the spec gives is
   the transfer, which waits `noticePeriod` (≤ 30 d, `OpenFactory.sol:36`; "7622: minutes, 22776: days", `:56`). During
   the notice window the attacker **is** the old verifier and keeps draining up to `totalShielded`; "holders can exit through
   the old verifier" (§4.2) is the attacker's door, not the holders'. The notice protects holders against a *hostile owner*
   moving the trust root; a move to **nobody** needs no such protection (it can only freeze, like PAUSE). Fix: an owner
   `revokeAttestVerifier()` that sets `verifier = 0` at once (every debit refuses `ProofNotAttested` / `AttestationRejected`),
   while a new verifier still waits the notice. This is inside O2 (a transfer waits; a revocation is not a transfer). Also
   state the maximum loss in AV-1: `min(totalShielded, maxShielded) · shieldScale` of the underlying on 3/5/11/13.

3. **P1 — §9 under-counts kind 13.** Missing from the table: (i) the `PqzLayer._init` branch of finding 1; (ii) the three
   new `ConfidentialConfig` fields. `TokenConfig` carries every sub-struct for every kind and the token decodes it in
   `_init` (the regulated spec's §2.4 ripple; `IFactoryToken.sol:81–84` for the same pattern), so **every token kind**, 13
   included, grows by the decode of three fields and the `VerifyModeInvalid` / `AttestConfigInvalid` checks (≈ 0.1–0.2 KB)
   even if the checks live in `PqzStateLib`. Kind 13 sits at 62,285 B with 2,227 B left *before* T31–T36 and 3e's
   +2.3–4.0 K (`runs/2026-11-04-ua-mtx-merge-regulated-sizes.txt:107,113`). Fix: add both rows; keep "measure 13 first";
   the levers of §9 stay valid.

4. **P1 — §11.1 node: "attest on the same lane before the op" is new machinery, not a row.** `submit.rs` batches up to 50
   rows into one outer nonce and never requeues a `signed` row (`submit-lanes.md` §4, lines 183–188); there is no per-job
   two-transaction dependency (the only `prerequisite_job_id` is a consumer's field, `job-api.md:882`). A landed attest whose
   op is later replaced by the 0-value self-send (NODE-LANE-04) is an orphan the node cannot clean. T50's 3 days do not cover
   this. Closed entirely by inline (0.a).

5. **P2 — §8 / §11.1 economics: the attest transaction has no payer.** A signed entry carries one `fee`; the book design
   adds a second transaction the relayer pays from its lane key with nothing in the envelope to meter it. The node would need
   a fee quote covering both or a refusal rule. Closed by inline.

6. **P2 — §2 trust disclosure is incomplete on censorship.** "The verifier sees only public data" is true for bytes, but
   the verifier sees each debit *before inclusion* and can refuse or delay one party's unshields selectively; a relayer can
   too, but a relayer is replaceable at once and the verifier only after the notice (finding 2). Add one sentence to AV-1
   and the wizard warning.

7. **P2 — §2 liveness: shields keep flowing into a frozen pool.** When the verifier is offline, shields (proof-free,
   `PqzStateLib` shield path) still work, so holders can lock more value they cannot debit. Fix: the indexer exposes
   `lastAttestationAt(token)` / verifier endpoint health and the node refuses shield jobs with a named `VERIFIER_UNREACHABLE`
   when the operator enables that check; wallets show it. A node-level signal keeps "the node is open" (one rule for every
   consumer).

8. **P2 — §6.3 is superseded by (b); if kept, two gaps.** (i) `keyAttest[ua][attester]` stored *in the registry* makes a
   per-chain registry fact out of a per-token trust decision; CTR-UA-15's "never removed" then keeps stale attestations of a
   verifier that was later found dishonest. (ii) Q6 forces every holder's key to be re-attested at each transfer (the node
   batches it in the notice window) — a liveness cliff on a 1,000-holder token. Both vanish with (b).

9. **P2 — §10 misses two conflict rows.** (i) CTR-PQZ-15 ("no new kind", `job-api.md:148`) vs. the standalone
   `attest_proof` / `attest_pqz_key` jobs. (ii) CTR-PQZ-11 / `PQZ_DEBIT_MIN_GAS` and the gas pins: ATTESTED debits have a
   different minimum; the `_pqzHolder` msig bound keeps the precompile-inclusive figure (conservative, fine) but the pins'
   comments should say which mode they measure. (i) closes with inline; (ii) is a one-line Change.

10. **P2 — §5.2 "verifier sees only public data" vs the auditor.** With `auditorMode` FULL the statement carries `pk_a` and
    `out` for the auditor; the verifier learns which ops are audited. Public on chain anyway; say it.

11. **P2 — §3 `proofSystemId = PqzSet.PQZL_ID` compiled in; the set is implicit.** The verifier must run the token's set
    (`PQZ_SET` of the release's build). The attestation struct has `proofSystemId` but no set name; the statement does not
    carry the set either (it is implied by lengths). Fix: the verifier service is configured per release address → set, and
    refuses a token whose statement length is not the configured set's `STMT_*` (`PqzSet.sol:38–46`); the operator note
    says so. No struct change needed.

12. **P2 — §4.1 kind check at init needs a registered verifier.** `requireAuthorized` on a derived id (`secp256k1`,
    `p256`, `mldsa*`, `msig`) needs the record in *this chain's* registry; `kindOf` returns 0 otherwise, and the token
    creation would refuse `AttestVerifierKind(0)`. Correct, but say it: "register the verifier UA on the chain first; an
    `mldsa*` verifier also needs `expandKey` where no precompile exists". The `AttestVerifierKind(0)` case should get its own
    name (`AttestVerifierUnregistered`) so the node does not misreport.

13. **P3 — §14 ids are not next-free.** Highest today: CTR-PQZ-26, NODE-JOB-21 (`docs/` scan). The spec proposes
    CTR-PQZ-81…84 and NODE-JOB-82; CTR-UA-41 and CTR-ZTH-95 are next-free. Fix: CTR-PQZ-27…30, NODE-JOB-22 (T19 allocates).

14. **P3 — §8 statement size.** `STMT_TRANSFER = 93,312` B (`PqzSet.sol:38`), not "83 KB"; keccak ≈ 17.6 k. The
    estimate's band still holds.

15. **P3 — Q5 "no acceptance".** A typo in `next` on a transferable verifier freezes confidential balances for another
    notice period. The repo already has the two-step owner pattern (`GovernanceLib.sol:382–393`). Cheapest guard without an
    entry: the node/wizard requires a signed probe attestation from `next` before it submits the proposal. Keep "no" on
    chain; add the off-chain rule.

16. **P3 — §17 estimates.** After the owner's ruling and (a)+(b): T44 becomes a `PqzCore` + `PqzStateLib` change
    (1 d), T45 stays (2.5 d, kind 13 first), T46/T47/T48 out, T49 1 d, T50 1–1.5 d (one sub-object, the optional service,
    errors, indexer event), T51 1 d, T52 1 d (ten docs in 0.5 d is low). ≈ 7.5–8.5 agent-days.

**1.Z — closed by the Zether removal (one line each, no further work):** Z1–Z5 seat analysis (correct: `ZetherLib.sol:300,
406, 833–853`, `ZetherDisclosure.sol:51–101`, init `isValidPoint` `:220`); `ZetherSolCurve` realism (my estimate for the
Z5 Schnorr: two 255-bit variable-base ladders ≈ 13–30 M > 7.92 M, so Q1 would have ended at (a) and Zether ATTESTED would
have been deployable only where it is not needed); the pure-Solidity path's silent dependence on EIP-198 modexp for Fp
inversion; the 6–25 M disclosure `eth_call`; `Ctx.burnVer` (`ZetherLib.sol:79, 571`) not covered by "no proof verifiers";
I6 differential gate; T47, T48, `solcurve.json`, `ZetherAttestBook`, CTR-ZTH-95, §10 row 3.

## 2. Verdicts

**Q1–Q9.** Q1 moot (Zether out). Q2 agree: PQZL only; PQZH debits are bound by the calldata floor (CTR-PQZ-11) and
`PqzSet.PQZH_VALUE` (`PqzStateLib.sol:48`). Q3 agree (not now). Q4 agree (no bit; the owner is already the trust root,
`GovernanceBase.sol:53–55, 83`). Q5 agree on chain, with the off-chain probe of finding 15. Q6 closed by (b); if §6.3
stays, agree "current verifier only". Q7 agree no cap; with inline, `validUntil` can stay as the verifier's shorter life
under the op's `validUntilBlock`. Q8 agree (allowed), with the maximum-loss sentence of finding 2. Q9 agree: the refusal is
`env.hedera` in the release `Env` (`PqzLayer.sol:70`, `ZetherLayer.sol:68`), independent of mode; not this group.

**§10 conflict list.** Rows 1, 2, 5, 7, 8, 9, 10, 11, 12, 14: agree. Row 3: moot. Row 4: agree, and it applies to PQZ
through W-B exactly as written. Row 6: disagree with "not a conflict in substance" for the book design — a stored,
consumable on-chain attestation record is what CTR-ZTH-39 / CTR-PQZ-14 removed; it is a Change line, or it vanishes with
inline. Row 13: totals move (finding 16). Missing rows: finding 9.

**Five "beyond the brief" findings.** (1) Zether needs EIP-2537 in five places: agree, now moot. (2) PQZ refuses unproven
keys: agree (`PqzCore.sol:898–901`), and (b) is the right answer for ATTESTED. (3) No PQZ release without the precompile:
agree in substance, wrong location (finding 1): `PqzLayer._init` + `PqzStateLib.init` + `script/pqz/e2e.py`, not
`OpenFactory` / `DeployBase`. (4) Plain confidential kinds have no PAUSE: agree (`GovernanceBits.sol:15`, bits 5–7 are
regulated-only per CTR-GOV-03) — and it is why finding 2's immediate revocation is needed. (5) Hedera refusal: agree, an
`Env` flag, keep.

## 3. Missing from the spec

- An immediate owner revocation of the verifier (freeze-only), separate from the notice-bound transfer (finding 2).
- The maximum-loss figure in the creation disclosure and wallets (finding 2).
- The verifier's censorship / selective-delay power in AV-1 (finding 6).
- A liveness signal and a shield refusal rule while the verifier is unreachable (finding 7).
- Who pays the second transaction (finding 5) — or inline.
- The `PqzLayer._init` deps gate, `PqzStateLib.init`'s precompile reads and `script/pqz/e2e.py` as the actual places of
  the "verifier 0 release" change (finding 1).
- The `TokenConfig` decode cost on every kind (finding 3).
- Set binding of the verifier service per release (finding 11).
- The verifier-registration prerequisite per chain and a named error for it (finding 12).
- Conflict rows for CTR-PQZ-15 and the gas pins (finding 9).
- Mutants for the inline design (0.a) if adopted.
- For (b): the `(ua, pqzKeyHash)` cache key, the `pqzPop`-bytes requirement, and the ATTESTED auditor-key check at init.

## 4. Checked and found sound

- `PqzStorage` slot 0 holds `pqz` (20 B) + two enums (2 B); byte 22 is free for `verifyMode` (`PqzCore.sol:60–63`).
- `statementHash` over the bytes after the 5-byte prefix matches `_check`'s buffer layout (`buf + 37`, `len`;
  `PqzCore.sol:818–834`) and the `verdict` call; hashing in place is possible.
- `0x…0F01` is `0x…5caa0f01` (CTR-PQZ-10, `pq-zero-knowledge.md:1892`).
- `UAVerifyGas` propagation pattern exists and is reusable (`PqzCore.sol:823–829`, C2-6 at `:701–704`).
- `msig` one level only is already a registry rule (`UAKinds.sol:147`); the spec's "no nested msig" restates it.
- The EOA wording ("no code other than the EIP-7702 designator") matches CTR-UA-24 and `UAStore.sol:185–200`; it is not
  a 7702 feature, it is the existing classification. No conflict with the no-7702 rule.
- `noticePeriod` is an `OpenFactory` immutable, ≤ 30 d (`OpenFactory.sol:36, 40, 57–62`); 3e Q9 uses it the same way.
- Owner identity by UA and `_govSubject()` through the router (`GovernanceBase.sol:53–55, 83`); `renounceOwnership` sets
  `owner = 0` (`GovernanceLib.sol:401–405`), so "a renounced owner leaves a transferable verifier unchangeable" is right.
- Kind 13 figures: 62,285 B runtime, 65,088 B init, 2,227 B under the 64,512 B line, `_above64KiB` empty
  (`size-baseline.json`, runs file lines 105–113).
- CTR-UA-23 budget 12 M / 66 % → 7.92 M and the `mldsa65` 5.95 M cap; CTR-UA-39 `mldsa87` refusal; the §4.1 refusal list
  is consistent with both.
- S32 (`accounts.md:2086`) says what the spec says; UA8-D9 directory semantics (`recordOf` lists unproven keys) hold.
- `env.hedera` is a release flag read at init, not run-time chain detection (`PqzLayer.sol:70`).
- Single use through `sendCounter` (`_sent`, incremented by the debit) and `T` unchanged by a rollover (D6 `ROLL_AGE`,
  `_total` at `PqzCore.sol:262, 471, 599`): the §5.2 verdict's correction ("binds `T`, not an `acc` hash") is right.
- The ids CTR-UA-41 and CTR-ZTH-95 are next-free; the §14 table otherwise maps one rule to one id.
