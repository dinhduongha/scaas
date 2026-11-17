> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

Requested by the owner (2026-11-06); Fable reviewed the first draft of [the versioned PQZ keys spec](../superpowers/specs/2026-11-06-pqz-key-versions.md) (group 3g), before the owner's rulings R1–R5. Copied verbatim below.

# Fable review: `docs/superpowers/specs/2026-11-06-pqz-key-versions.md` (versioned PQZ keys, group 3g)

Reviewer: Fable 5.1, 2026-11-06. Read-only; nothing built or run. Owner rulings O1–O7 not reopened; where one creates a concrete
risk it is named. Everything cryptographic here is UNAUDITED; this review is a reading of the spec against the code and docs,
not an audit. Paths are relative to the worktree `.claude/worktrees/ua-mtx-merge`.

Sources checked: `smartcontracts/evm/src/ua/{UAStore,UARegistryLib,UARegistry,UAKinds}.sol`,
`smartcontracts/evm/src/pqz/{PqzCore,PqzLayer,PqzStateLib}.sol`, `docs/contracts/accounts.md` (CTR-UA-13/-15/-16/-29/-32),
`docs/contracts/pq-zero-knowledge.md` (CTR-PQZ-12/-13/-19/-23, §7.2), `docs/superpowers/specs/2026-11-06-attested-verify.md`
(R3, AV-6), `docs/research/pqz-threshold-decrypt-prove.md` §7, `smartcontracts/evm/runs/2026-11-04-ua-mtx-merge-deploy-gas.txt`,
`smartcontracts/evm/size-baseline.json`, `clients/clientkeys/src/pq.js`, `scaas-node/src/typed.rs`, `TODO.md`.

---

## 1. Findings

Severity: P0 funds or soundness; P1 a guarantee the spec claims does not hold as written; P2 a real gap with a concrete fix;
P3 wording, missing detail, or a residual to state.

### F-1 — P2 — §2.2 KV-3 / C2, §5 KV-12: on a registry without the verifier, `current` moves before the proof bytes exist, so every credit to the UA is un-attestable in the window

**Problem.** C2 makes a version eligible when it is "stored with this set's length". That is true at `setPqzKey` time, before
`storePqzPop`. The 3f verifier service refuses to attest any statement naming a key whose `pqzPop` bytes are not stored
(attested-verify.md:311–316, "a hash-only record cannot be re-verified: refused"). So between `setPqzKey(ua, v+1, …)` and
`storePqzPop(ua, v+1, …)` the UA's current is v+1, every credit's statement carries `pk_{v+1}`, and the attestation service
must refuse all of them: `AttestationMismatch`-class liveness for every counterparty, re-opened at every rotation, and the
tell-tale that 3f's R3 only ever had at a UA's birth. Today a register-key v0 without `pqzPop` has the same window once; versions
make it recurring and move `current` into it.

**Fix.** Eligibility on a registry without the verifier = stored with this set's length **and `pqzPop[ua][v]` stored** (its hash
already checked, `UAPqzPopHash`). Then both registry kinds move `current` in `storePqzPop` and the rule reads the same way
everywhere: "eligible when the chain holds the proof bytes, and the verifier, where present, accepted them". One `length != 0`
read; the test "v1 of this set's length current at store" becomes "current at `storePqzPop`". Mutant M-R6 gains the case
"eligible without the bytes".

**Evidence.** UARegistryLib.sol:499–522 (`setPqzKey` stores key and hash only), :438–462 (`storePqzPop` stores bytes),
attested-verify.md:311–316 (AV-6 obligations), spec §2.2 table row "slot `0x0142` is empty".

### F-2 — P2 — §3.2 KV-7, Q3: a rotation (or anyone replaying a UA's public records) kills counterparties' in-flight proofs; the spec has no mitigation beyond "re-prove"

**Problem.** Two sender-paid liveness vectors the spec does not name:

1. A decoy leg is chosen by the sender from the `0x0142` list (CTR-UA-29). A UA that rotates often, or an attacker who registers
   PQZ holders and rotates them, invalidates every op 7 that drew it as a decoy (`ProofRejected` / `AttestationMismatch`). A
   PQZL proof costs the sender seconds to minutes and the whole transaction's gas; the rotator pays one `storePqzPop` per hit.
2. `UAPqzKeyAdded` carries `sig` and `UAPqzPopStored` carries `pqzPop`, both public, both portable (CTR-UA-07). Anyone can
   replay a UA's v+1 record and proof from chain A onto chain B, timed to kill credits in flight to that UA on B. The UA
   consented to the record on every chain, so this is not a forgery; it is a timing choice taken away from the UA and given
   to anyone.

**Fix (three lines, no contract change).**
- Wallet decoy rule, an addition to CTR-UA-29's decoy filter: never draw a UA whose `pqzKeyLatest(ua) > current(ua)` (a
  stored, not-yet-eligible version is the on-chain tell of an imminent rotation), and prefer UAs with no `UAPqzKeyCurrent` in
  the look-back window.
- Node intake: refuse by name (`PQZ_KEY_ROTATION_PENDING`) a PQZ job whose statement names a party with `latest > current`
  on the job's registry; cheaper for the sender than the refusal after the fact.
- State under KV-1 that activation of a version on a chain is permissionless once the record is public, and that wallets of
  an `msig` holder should register and prove v+1 on every chain they use in one sitting.

**Evidence.** PqzCore.sol:435–449 (`_legs` reads every leg's key), spec §7.3 (`PQZ_KEY_ROTATED` only after the fact),
accounts.md CTR-UA-29 (decoy selection rule), UARegistryLib.sol:521, :433 (the public `sig` and `pqzPop`).

### F-3 — P2 — §2.3 Generations: host mode is under-specified where gen 1 keeps accepting versions

**Problem.** A gen 1 of this release that does not enable `0x0142` still accepts `setPqzKey(ua, v, …)` for its own records
(`_host` returns false when `records[ua].kind != 0`, UARegistryLib.sol:492–497; gen 1 has no successor pointer and cannot see
gen 2). The host gen 2 also accepts versions for that UA ("the host stores the proofs and new versions of gen-1 records"). Two
different records can then exist at one version number on one chain, each UA-signed (the client rule broken once, or an
old operator still holding a key for the same number). "`latest` is the larger of the two generations'" does not say which
record `pqzKeyAt(ua, v)` returns when both hold v, nor what the host's sequence check does when gen 1 later stores a v the host
skipped. Separately, by C2 gen 1 (no verifier) computes `current` by length while the host computes it by proof: one UA, one
chain, two currents. An ATTESTED token bound to gen 1 and a PRECOMPILE token bound to gen 2 then credit different versions.
That is coherent per token but nowhere written.

**Fix.** Write the three rules: (1) the host's `latest` and sequence check read `max(latest_host, latest_gen1)`; (2) `pqzKeyAt`
on the host returns its own record for v when it holds one, else gen 1's (today's `_pqzElsewhere` pattern, UARegistry.sol:299–301);
(3) a gen-1 write of a version the host already holds is the known A6-I1 divergence, listed as accepted, with a test; wallets
write to the newest generation only. Add "one `current` per `(ua, registry generation)`" to KV-3 and say which registry each
token reads.

### F-4 — P2 — §6.2, KV-5: the per-version `R_REG` is a 60 M-gas transaction at `n2816-kmax65536`; on a 60 M chain a rotation is at the limit and the host variant is over it

**Problem.** KV-5 says each version "costs its UA one signed record and one `R_REG` proof". `TODO.md:354–361` records the real
figure: `storePqzPop` at `n2816-kmax65536` is ≈ 59.9 M gas with the real verify, and the gen-2 host variant ≈ 60.1 M, above a
60 M block. With versions, that cost recurs per rotation, and on a 60 M chain running `n2816-kmax65536` no version ≥ 1 can ever
become current through the host, so O7's "ship in the generation that first enables `0x0142`" leaves such a chain with
version 0 forever. The spec's gas section only discusses deploy gas.

**Fix.** Add the figure to KV-5 and §6.2; state that a 60 M chain runs `n2304-kmax4096` (≈ 7 M headroom) if it wants rotations,
and that the Q4 60 M pin applies to deploys, not to `storePqzPop`. No contract change: the proof cannot be split (TODO:358–360).

### F-5 — P2 — §7.2, §1: the read threshold k of the backup is below the spend threshold m, and member departure is a rotation trigger the spec does not name

**Problem.** O3 accepts the k-of-n seed backup. Any k members can rebuild `seed32_v` and read every balance and credit under v
without being able to spend (m-of-n). A member who leaves the organisation keeps its shares of every version it was given;
CTR-UA-13 keeps members in the id, so the UA cannot drop the member, and only a new version stops that member reading the
future. The spec frames rotation as "operator change" only (§1, §3.4, §7.3 runbook).

**Fix.** In §7.2 and the runbook: rotate after any share holder leaves or is suspected; the shares of v+1 go to the current
members only; and the T16a coordination row should carry the owner's choice of k against m (recommend k ≥ m, or state the
read threshold explicitly). This is a security-relevant operational rule, text only.

### F-6 — P3 — §4.2 row 6, §3.3 KV-8, Risk 4: a debit from a stale version to a third party reveals its amount to the old key holder; say so, and make the wallet rule explicit

**Problem.** The spec says the old operator re-derives the migration's `r` and "learns the migrated amount, which it learns
anyway by decrypting `T_v`". It does not say the same for *any* debit under v to a third party after rotation: `v_f` under
`pk_v` is the new balance, so old − new = amount + fee is readable by the holder of `s_v`. KV-8 allows such debits ("a debit on
v to another UA works", tested in §14). Deriving `seed_enc` from another version's seed would not help: `v_f` leaks the amount
regardless.

**Fix.** State in KV-8/Risk 4: "every debit under v, not only every credit, is readable by `s_v`; after a rotation for
compromise the only debit a wallet makes on v is the migration (self-transfer)". §3.4 implies it; make it a rule.

### F-7 — P3 — §3.4 KV-9: `KeyReused` is pk_f-only; pairwise leg/auditor equality stays the 3f service's check, and the spec should say so rather than call `KeyReused` "the defence against the F-4 class"

**Problem.** The on-chain compare is each credited key against `pk_f`. Two op 7 legs in one randomness group with equal key bytes
(two UAs that stored the same key on a registry without `keyOwner`, i.e. an ATTESTED chain) give `v_j − v_k = Δ(d_j − d_k) +
noise`, which with decoys at amount 0 exposes the real legs. A leg equal to the auditor's key gives `Δ(d_j − d_j) = 0`, no
amount leak, but publicly confirms key equality. Versions do not widen this (one UA contributes one current key per statement),
and on a registry with the verifier `keyOwner` excludes it; it is a 3f residual that this spec's wording hides.

**Fix.** Reword KV-9: `KeyReused` closes the migration case (sender vs its own next version) in every mode; pairwise leg and
auditor equality is excluded by `keyOwner` where the verifier exists and by the verifier service's single-ownership check in
ATTESTED (AV-6). If kind 13's size allows, a pairwise compare over ≤ 9 warm `EXTCODEHASH`es costs ≈ 3.6 k gas and closes it on
chain; otherwise list it under §5 as given up (Fable (b) of 3f).

### F-8 — P3 — §4.2 row 1 / Q1: state the residual where keys are not distinct

**Problem.** The domain-separation argument needs distinct keys per version. Where nothing enforces that (a registry without the
verifier: `keyOwner` is never claimed, KV-2), a UA can store identical bytes at v and v′. The statements for `(ua, v)` and
`(ua, v′)` then differ only in `T`, and coincide exactly when both accounts are fresh (`T = Trivial(shieldIn)` for both). One
proof and one `PqzAuth` signature then verify for either `keyVersion`; `sendCounter` limits it to one landing and both accounts
decrypt under one key, so no value moves wrongly — but "a proof accepted for (ua, v) cannot be used for (ua, v′)" is false in
that corner. The direct forms' `keyVersion` is a bare calldata word a submitter may change.

**Fix.** Add the corner to §4.2 as the stated residual (self-inflicted, value-neutral), add it to M-T5's test list, and let
Q1's "No" rest on "funds and amounts are unaffected by which identical-key account is debited", not on "bodyHash binds the
version".

### F-9 — P3 — Q1 vs research §7.3: the spec reverses the research note's recommendation silently

**Problem.** `docs/research/pqz-threshold-decrypt-prove.md:687` recommends "an explicit `keyVersion` field in `PqzAuth` follows
the explicit-parameter rule". Spec Q1 says No. O6 says "a debit names its version explicitly"; for the direct forms the only
typed object an `msig` member signs is `PqzAuth`, so the member never sees the version. The risk is low (the version changes
neither amount nor recipient, and funds stay in the UA), so No is defensible, but the divergence belongs in §10 and the vectors
note needs reconciling: `auth_digest` is a field of the `statement_*.json` rows, so "regenerates the `auth_digest` field of every
debit statement vector" (Q1) and J8 "statement rows byte-equal" cannot both be read literally.

**Fix.** Add a §10 row (research §7.3 → Q1), and in KV-13/J8 say "the statement bytes and proofs are byte-equal; `auth_digest`
rows are regenerated only if Q1 changes".

### F-10 — P3 — §2.2 KV-3 events vs KV-1 / J7: does `register` emit `UAPqzKeyAdded` for version 0?

**Problem.** KV-3 writes `UAPqzKeyAdded(…, bytes sig)` "as `UAKemKeySet`; `sig` empty for a `register` key", which implies
`register` now emits it; today `register` emits only `UARegistered` with the key in `attrs` (UARegistryLib.sol:234) and
`UAPqzKeyAdded` fires in `setPqzKey` alone (:521). KV-1 says version-0 "records, digests and `R_REG` messages stay byte for
byte" and J7 says "events' non-version fields are byte-equal to today's". Adding an event to `register` breaks neither literally
but changes the indexer's contract.

**Fix.** Decide and write it: either `register` emits `UAPqzKeyAdded(ua, 0, …, "")` beside `UARegistered` (then the indexer
row and `e2e.py` change, and `UAPqzKeyCurrent(ua, 0)` fires with it), or it does not and v0 is found through `UARegistered`.

### F-11 — P3 — §14 negatives: two replay forms missing

**Problem.** The registry negatives list "v1's proof over v2's message, over the unversioned `PURPOSE_PQZ_KEY` message or over
another UA". Version 0 has *two* message forms: `uaMessage(0x0142, PURPOSE_POP_V2, typed(UAPortableRecord))` for a `register`
key and `uaMessage(0x0142, PURPOSE_PQZ_KEY, typed(UAPqzKey))` for a `setPqzKey` key (UARegistryLib.sol:454–456). Only the second
is listed. Also missing: a v1 record signed on chain A replayed on chain B accepted (the positive control for portability), and
a v1 `UAPqzKeyVersionRecord` signature replayed as the consent for v1 of another UA (refused: `ua` is in the struct).

**Fix.** Add the three rows; M-R1 should include the `PURPOSE_POP_V2` form.

### F-12 — P3 — §6.2: the "57 M each" target is not in `TODO.md`, the plan or `HANDOFF.md`; and the library estimate is low

**Problem.** `grep "57 M"` over `TODO.md`, `docs/superpowers/plans/2026-11-04-ua-mtx-merge.md` and `HANDOFF.md` finds nothing;
the spec cites "3c's target, TODO". The run figures themselves check out: `UARegistryLib` 36,192 B, state 55,557,360 →
1,535 gas/B, 60.83 M asked (runs/2026-11-04-ua-mtx-merge-deploy-gas.txt:25, :48). The +1.0 to +1.8 KB estimate for the
library looks low: `setPqzKey` and `storePqzPop` each gain a version branch and a host branch per version (predecessor calls
`pqzKeyAt`, `pqzKeyLatest`, `pqzPopOf(ua, v)`), a second `R_REG` message builder, the `PqzVersions` read-modify-write in
`_pqzAttach`, `_pqzProof` and `setPqzKey`, and `UAPqzKeyCurrent`. Budget +1.5 to +2.5 KB; the 60 M line (5.3 KB of room today)
still holds before 3c, the 57 M line does not.

**Fix.** Cite the 57 M source by file and line or drop the word "TODO"; widen the estimate; keep the stop rule.

### F-13 — P3 — §0.1 O7 wording vs C2 / §5

**Problem.** O7 as written ("versions ship in the generation that first enables `0x0142`") reads as "no versions on a chain
that never enables it", which contradicts C2 and §5 (versions work on ATTESTED chains without the verifier). §6.1 resolves it
("after reset 2 that is the generation of this branch") but the ruling's row does not.

**Fix.** Under KV-14: "the generation of this release on every chain; where a chain enables `0x0142`, only that generation does".

### F-14 — P3 — §7.2 C8, `msig`: the vault label `pqz:<ua>:<version>` does not survive an operator change; key backups by `(ua, version)` alone are ambiguous

**Problem.** For an `msig` the one-key-per-version property is operator discipline. After an operator change the new operator
has no access to the old vault; if the old operator registered v+1 on chain A but not B before leaving, the members can
replay A's record (good), but a new operator who generates its own v+1 for B first produces two keys at one number across chains.
Per-chain state tolerates it; the T16a backups do not if keyed by `(ua, version)`.

**Fix.** The spec already says T16a's header binds `pqzKeyHash`; make the wallet rule "backups and vault entries are keyed by
`(ua, version, pqzKeyHash)`", and the runbook's first step after reconstruction "read `pqzKeyLatest` and `UAPqzKeyAdded` on every
chain the UA uses before generating v+1".

### F-15 — P3 — §15 estimates: T53, T54 and T56 are tight

**Problem.** T53 (1.5 d) includes the rotation scenario in `script/pqz/e2e.py` on a local chain with the PQZ precompile: bringing
up the Nethermind plugin chain locally is itself a half-day. T54 (3 d) touches ten clients (`clientkeys`, `ua-rs` plus the five
wrappers that follow it, `ua-py`, `ua-go`, `ua-cs`, `ua-dart`) with new record builders, the derivation and three vector files:
4–5 d. T56 (1.5 d) is nine invariant handlers plus sixteen mutants at four sets; T35's harness with 26 kills was a task of its
own. T52 (3.5 d) is right only if kind 13 stays under 64,512 B without levers: 62,285 B today + 0.4–0.9 KB leaves 1.3–1.8 KB
*before* 3e and 3f add theirs.

**Fix.** 19–22 agent-days in this branch; keep T52's "kind 13 first" and the stop rule.

---

## 2. Verdicts

### Q1 — `PqzAuth` gains `uint64 keyVersion`? Spec: No.

**Agree, with the residual of F-8 stated and the reversal of F-9 recorded.** `bodyHash` covers `pk_f` and `T`; with distinct keys
per version (every registry with the verifier; the UA's own discipline without one) the digest names the version. In the
identical-key corner the two accounts are the same key and the debit's amount and recipient do not depend on the version, so
nothing of value turns on it. The relayed forms sign `keyVersion` in their args. Cost of Yes: the `PqzAuth` typehash pin and the
`auth_digest` rows.

### Q2 — Retire R-cross-set's version-0 replacement? Spec: Yes.

**Agree.** A v1 of this chain's set does exactly what the replacement did, every record becomes write-once, slots 13 and 14,
`_pqzKeyFree`'s replacement branch (UARegistryLib.sol:540–548) and `registrationOf`'s fallback (UARegistry.sol:325–329) go, and
`registrationOf` returns v0 as registered without a copy. Same transaction count for the affected UA (one `setPqzKey`, one
`storePqzPop`). Owner's word required (ruling 2026-10-30). Keep R-cross-set's *test* for v0 on a registry without the verifier
("nothing is replaced") as the positive control of the retired branch.

### Q3 — Debits name the receiver's and auditor's versions? Spec: No.

**Agree on the parameter; disagree that "re-prove" is the whole mitigation.** F-2's two rules (decoy filter on `latest >
current`; node intake refusal by name) cost no bytes on chain and remove most of the sender-paid griefing. Also note why the
after-the-fact refusal is safe: `current` is non-decreasing, so a proof against `pk_v` can never land once `current > v`; that is
what lets the node say `PQZ_KEY_ROTATED` without ever saying `dead` while a transaction may still land.

### Q4 — Accept the 60 M public line if 57 M is missed? Spec: Yes.

**Agree, with two notes.** (1) The pin should be the public gate's own formula (`asked = (regular + state) × 1.05 ≤ 60 M` and
`regular × 1.05 < 2^24`, runs:44), not a byte count. (2) 60 M is also where `storePqzPop` at `n2816-kmax65536` sits (F-4), so a
60 M chain is effectively an `n2304-kmax4096` chain already; the deploy line adds no new constraint on such chains.

### §10 conflict list

Rows 1–16 are correct as stated against the sources read (CTR-UA-13/-15/-16/-32, CTR-PQZ-13/-14, §7.1/§7.2/§7.4 of
pq-zero-knowledge.md, 3f AV-6, T16a's "Why"). Missing rows:

| Add | Source | Change |
|---|---|---|
| 17 | CTR-PQZ-19, CTR-PQZ-23 | `seed_enc` and the memo key come from the **debited version's** `pqzKeySeed`; the sender's recovery tries each stored version of the receiver (the spec says it in §3.6 and §4.2 row 6, §9 lists the docs, §10 does not) |
| 18 | CTR-UA-29 | the `0x0142` list holds a UA once, at its first proven version (§9 names it; it is a rule change) |
| 19 | research §7.3 "an explicit `keyVersion` field in `PqzAuth`" | not adopted (Q1) |
| 20 | O7 wording | versions ship in this release's generation on every chain, verifier or not (F-13) |
| 21 | `IConfidentialToken` / the node's `PLAIN` rows | PQZ no longer answers `mtxRollOver(bytes32,uint256)` / `mtxPrepareAcc(bytes32,uint256)`; Zether keeps them; interface ids and `selector_audit.json` move |
| 22 | 3f R3's "accept unproven keys" | unchanged, but the *moment* of eligibility on a no-verifier registry should be `storePqzPop` (F-1) |

---

## 3. Missing from the spec

- The eligibility window of F-1 and the griefing vectors of F-2 (both liveness, both cheap to close).
- Host-mode rules when gen 1 keeps writing (F-3); "one `current` per `(ua, generation)`" and which registry each token reads.
- The `storePqzPop` gas per rotation at the largest set (F-4).
- Membership and the read threshold: k vs m, member departure as a rotation trigger (F-5).
- The explicit wallet rule "after a rotation for compromise, the only debit on v is the migration" (F-6).
- The factory catalogue: new releases of kinds 4, 5, 12, 13 need their catalogue rows; T52 lists `mtxSelectors` and
  `selector_audit.json` but not `Factory` / `DeployBase` catalogue entries.
- The node: `grep` finds no `from == to` refusal in `scaas-node/src`, so nothing changes there, but §7.3 should say "the node
  does not refuse a self-transfer; the token does (`SelfTransfer` unless `keyVersion ≠ current`)". `PqzTransferArgs` in
  `scaas-node/src/typed.rs:61–63` gains `keyVersion` after `fromUA`; the row is implied by "allow-lists equal", say it.
- `prepareAcc` and the rollover call `_keyPtr(registry, ua)` today (PqzStateLib.sol:121, C2-4); with versions they read
  `pqzKeyAt(ua, keyVersion)` under the mode's key check (proven on PRECOMPILE) — a rollover on a never-proven version is refused.
  State it under KV-10.
- Whether `register` emits `UAPqzKeyAdded` / `UAPqzKeyCurrent` for v0 (F-10).
- The three replay negatives of F-11 and the host write race of F-3 in §14.
- A wallet rule for the identical-key corner (F-8): a wallet never signs a version whose key bytes equal a stored version's.
- The source of the 57 M target (F-12).

---

## 4. Checked and sound

- **Consent and `R_REG` replay across UAs, versions and struct forms.** `ua` and `version` are inside both new structs; the
  typehashes differ from `UAPqzKey` / `UAPqzKeyRecord` (UAKinds.sol:83–85) so a v0 signature or proof cannot serve v ≥ 1, and
  `PURPOSE_PQZ_KEY` stays the only purpose `_sigOk` admits for it (UARegistryLib.sol:635–637). Cross-chain and cross-generation
  replay are intended (CTR-UA-07); see F-2 for the timing consequence.
- **Squatting.** Only the UA's `UASig` (m-of-n minimal form, `_portableOk`, never `keyData`) adds a version; `storePqzPop`
  needs no signature but is a no-op or a hash mismatch for anyone else; the current pointer moves only on eligibility of a
  UA-signed version. No third party can add, skip, lower or reorder.
- **`keyOwner` per version at proof time** (KV-2) matches today's `_pqzProof` (UARegistryLib.sol:427–429); the same-UA case
  is new and needed for §4.2 row 1. A UA that stores identical bytes at two unproven versions can prove only one; the other is a
  dead number, self-inflicted and tested ("v1 with version 0's key … `UAKeyInUse` at proof").
- **Statement and transcript argument (§4.2).** With distinct keys, `pk_f` (and `pk_t`, `pk_a`, the op 7 keys) are statement
  bytes absorbed by `hash0`, so a proof or a `PqzAttest` (binds `statementHash`) made for `(ua, v)` fails for `(ua, v′)`; the
  version decides only which bytes the contract writes at `HEADER`, `HEADER + PK`, … (PqzCore.sol:264–269, :472–479) and which
  account `_total` reads (:748–767). Row 3's fail-closed claim is right: `T` under `pk_{v′}` decrypted with `s_v` leaves
  `r^T A (s_{v′} − s_v)` plus noise, outside row 6's bound except with negligible probability, and the UA itself cannot turn a
  pairing bug into a double spend since it would need a valid opening of `T_{v′}` under `s_v`. Residual stated in F-8.
- **Single use.** `sendCounter` per UA (header word 352, PqzCore.sol:915) and `entryRefOf(chainUid, from, counter)` (:876–878)
  keep `entryRef` unique across versions; a per-version counter would collide `entryPtr`. Correct reasoning, correct choice.
- **F-4 class in a migration (row 4).** Same `r`, `v_t` under `pk_{v+1}`, `v_f` under `pk_v`: `v_t − v_f = (pk_{v+1} − pk_v)^T r
  + Δ(amount − balance′) + noise`, masked iff the keys differ. `KeyReused` closes it on chain in every mode; `keyOwner` closes
  it where the verifier exists. Correct. (Pairwise legs: F-7.)
- **`R_REG` message binding.** `uaMessage(0x0142, PURPOSE_PQZ_KEY, typed(UAPqzKeyVersion{ua, v, h}))` changes only the 32-byte
  pre-image; the relation `pk = A s + e` with the message absorbed and the statement `opTag ‖ proofSystemId ‖ message ‖ pk` are
  as today (pq-zero-knowledge.md:848–856), so no `proofSystemId` move and no full gate (CTR-PQZ-09's trigger not met). Correct.
- **C8 derivation.** `info_0 = tag ‖ u32 account ‖ u32 i` and `info_v = … ‖ be64 v` differ in length by 8 bytes, so no v ≥ 1
  info equals the v0 info and fixed widths make the map injective; HKDF-SHA256 with distinct `info` gives independent OKM. The
  client's `hkdf()` is extract-then-expand in one call (clients/clientkeys/src/pq.js:63), so the exported 32-byte leaf is the
  OKM and reveals nothing about another version; a leaked leaf is repaired by v+1, a leaked BIP-39 seed is not (new UA), as the
  spec says. M-C1 pins "`be64` appended at version 0".
- **Fresh seed per version for an `msig`.** No master secret exists, so `s_v` and `s_{v+1}` are independent; what `s_v` exposes
  is exactly everything under v (credits, `v_f` of every debit under v, the migration's `r` and so its amount, the memo keys of
  debits under v) and nothing under v+1 (fresh `r` from other senders; `seed_enc` of later debits from `seed_{v+1}`). Matches
  research §7.2's table.
- **Old operator cannot spend, grief or stall.** Every debit needs the m-of-n `PqzAuth` (CTR-PQZ-12); shields go to current,
  rollovers preserve `T` (D4/D6), so nothing the old operator can do changes `T_v` between prove and submit. O4's objection is
  indeed removed by (A).
- **Credits under a stale version / debits of another version's balance.** Credits read `current` in the same call that writes
  `pk_t` (KV-7, J5); debits build `T` only from `acct[from][keyVersion]` with `pk_f = pqzKeyAt(from, keyVersion)`; a version above
  current holds nothing but the signer's own `shieldIn`; on PRECOMPILE an unproven version is refused (`_keyPtr`'s rule,
  PqzCore.sol:898–902). Consistent.
- **Auditor versions.** `_keyPtr(auditorUA)` is read per transfer (PqzCore.sol:229, :449) so an auditor rotation is automatic;
  `init`'s check (PqzStateLib.sol:38–40) runs once and is unaffected; disclosure kind 2 takes the auditor's version explicitly
  (KV-11). An auditor UA cannot migrate on a `FULL` token, but it cannot be a party there today either (`AuditorAsParty` /
  `AuditorRequired`, PqzCore.sol:224–237, :295–296) and so holds no balance to migrate: not new.
- **Decoys and fingerprinting.** Decoy legs land on current; the `0x0142` list has one entry per UA; the migration is public as
  `from == to` and `UAPqzKeyCurrent` is public anyway, amounts stay hidden; old versions receive nothing, so they add no
  signal. Correct.
- **Storage layout claims.** `Account.sendCounter` sits alone in slot 2 (slot 0: four `uint64`; slot 1: 29 bytes; slot 3:
  `accHash`; PqzCore.sol:41–57), so removing it does not change a debit's slot count. `UAStore.Layout` slots 2, 7, 8, 9 become
  nested mappings at the same slot numbers, slot 17 is new; pins move old → new; no deployed state (all chains test-only).
- **Typehash moves.** `UAPqzTransferSingle` et al. embed `PqzTransferArgs` as a typed member (PqzLayer.sol:50), so a field in
  the args moves them; `UARollOver` / `UAPrepareAcc` gain a field (PqzLayer.sol:44, :47). Pins old → new, vectors regenerated.
- **Deploy-gas arithmetic.** 36,192 B ↔ 55,557,360 state gas = 1,535 gas/B; 60.83 M asked; `UARegistry` 29,710 B, 50.61 M
  (runs/2026-11-04-ua-mtx-merge-deploy-gas.txt:25, :47–48, size-baseline.json). The 60 M table in §6.2 follows.
- **Node refusal semantics.** `PQZ_KEY_ROTATED` only after an indexed `UAPqzKeyCurrent` of a party since intake is safe
  because `current` never goes down: a proof against `pk_v` can never land once `current > v`. Never `dead` while it may land
  is respected.
- **Family plan.** Family-neutral rule; Soroban's directory mode takes `checked` per version and C2's eligibility; NEAR and
  Algorand kept apart with their own storage; no Zether change anywhere. Consistent with the repository's rules.
