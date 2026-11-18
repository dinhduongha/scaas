# `setAuditor`: replacing the auditor of a confidential token on bit 32 `AUDITOR` — design

**Status:** BUILT at `eb05597c8` (plan A1-A8; A9 matrix rows `db10fdd09`), **UNAUDITED**; the closing review (Fable) pending. Written 2026-11-17 on branch `prefreeze-contracts` at `f655cb0e`, from
the owner's rulings of 2026-11-17 (quoted in §1, not reopened) and the frame in
[`plans/2026-11-17-code-format.md`](../plans/2026-11-17-code-format.md) ("Bundled: `setAuditor` on one governance bit").
Revised the same day after the Fable review `scratchpad/set-auditor-review/20261117-18-fable-fable-high-spec.md` (P0 0, P1 2,
P2 7, P3 6, info 4; every finding applied, §16 maps them) and the owner's rulings on the holder (O3) and on O1, O2, O4.
Calls the owner has not ruled on are controller calls, listed in §15. Plan:
[`plans/2026-11-17-set-auditor.md`](../plans/2026-11-17-set-auditor.md).

Rules this spec defines (normative text in the component docs; entries in [`decisions.md`](../../decisions.md)):

| Id | Where | What |
|---|---|---|
| [CTR-GOV-31](../../decisions.md#CTR-GOV-31) | `decisions.md` (the governance rules live there) | bit 32 `AUDITOR`: kinds, holder, delay, masks |
| [CTR-ZTH-95](../../contracts/zether.md#CTR-ZTH-95) | `contracts/zether.md` §14.1 | the Zether auditor key: setter, consent, epochs, history, disclosure by the entry's key |
| [CTR-PQZ-43](../../contracts/pq-zero-knowledge.md#CTR-PQZ-43) | `contracts/pq-zero-knowledge.md` §9.7 | the PQZ auditor UA: setter, consent, epochs, history, the three-key model, disclosure by the entry's auditor |

Changes to existing rules: CTR-ZTH-09 (no longer immutable when bit 32 is set at creation), CTR-ZTH-41 (the "no setter"
Change is replaced; threshold re-sharing stays the way to change parties without a new key), CTR-ZTH-43 (`ZetherDisclosure`
reads the entry's key), CTR-PQZ-24 and CTR-PQZ-14 (the auditor UA may change; the `AUDITOR` owner is the entry's auditor),
CTR-GOV-10 (bit 32 allocated, 33–127 free). `auditorMode` (CTR-ZTH-49, CTR-PQZ-24) stays immutable.

Sources read: `GovernanceBits`, `GovernanceLib` (`init`, `_check`, `_due`, `_setDue`, `_clear`, the masks), `GovernanceBase.use`,
`RegulatedBase`, `OpenFactory.configureChain` and `noticePeriod`, `ZetherLib` (`init`, `_auditorPoint`, `_noAuditorParty`,
the record writers), `ZetherDisclosure`, `ZetherStatements`, `PqzStateLib` (`init`, `shield`, `setVerifier`, `setVerifierFee`,
`setProofStore`), `PqzCore` (`PqzStorage`, `_noAuditorParty`, `_distinct`, `_usable`, `_legOf`, the `requireAuthorized` calls),
`IUARegistry.requireAuthorized`, the kinds' cores and generated faces and modules (`script/modules/entries.json`),
`GovernanceRouter(Base)`, `test/v2/layout/namespaces.json`, `size-baseline.json`, `scripts/size_gate.py`,
`clients/zether-prover/src/state.rs`, `clients/ua-rs/src/facade/pqz.rs`, `scaas-node/src/typed.rs`, `guard.rs`; rules
CTR-GOV-01…30, CTR-ZTH-09, -38, -40, -41, -42, -43, -49, CTR-PQZ-14, -24, -28, -31, -34, -37, -40, CTR-UA-43, ARCH-POS-13,
CTR-AS-19.

Figures: **[baseline]** is `size-baseline.json` at `f655cb0e` (a ratchet: each row is the most the contract may reach, not
its measured size); **[estimate]** is arithmetic over it and over the per-stub cost the burner / wrap-caps spec measured
(about 165 B per stub). Nothing here was measured; plan task A0 measures.

## 1. Rulings (owner, 2026-11-17, verbatim)

1. First, on "no setter now; threshold re-sharing; PQZ key versions": **"Ok, theo đề xuất"** (OK, as proposed). Recorded as
   CTR-ZTH-41's Change of 2026-11-17 (no setter, CTR-ZTH-09 holds).
2. Then, replacing it: **"Do format phải chạy lại rất nhiều, tiện thể làm luôn '- setAuditor', dùng 1 bit cho việc này. Gom
   chung vào format code, để chạy gate .v.v. 1 lần"** (since formatting forces a long re-run anyway, build `setAuditor` now,
   on one bit, and bundle it with the formatting so the gates run once).
3. Then: **"Làm luôn"** (do it now).
4. On the holder (the first draft's O3, contract or `msig` only, overruled): **"Vẫn UA như bình thường chứ, bao gồm cả contract
   và msig"** (an ordinary UA as usual, contracts and `msig`s included): any holder, a single key too.
5. On O1, O2, O4 of the revised draft: **"Ok, theo đề xuất cả O1, O2, O4"** (OK, as proposed: O1, O2 and O4):
   - **O1:** the delay is `max(noticePeriod(), grantDelay)`;
   - **O2:** the kind-4 setter stays in `NormalPqzTokenQ`, measured at A0; the work stops and asks only if a figure crosses T-1;
   - **O4:** when the delay is 0 the change applies at once, and the wallet says so.

What is the owner's: the setter exists, on one bit, built in the formatting round with one gate run; any UA holds it; the
delay; kind 4's placement; the at-once case. Everything else below is a controller call.

## 2. Goal and scope

**Goal.** A token created with bit 32 `AUDITOR` lets a holder of that bit replace who can read the auditor copies of its
**later** transfers: the Zether auditor key `Y_a`, or the PQZ auditor UA. The new auditor consents on chain. Earlier transfers
stay readable by the key of their time only, and every disclosure of an old transfer checks against that key.

**In scope.** EVM: the Zether kinds 2, 3 and their regulated twins 10, 11; the PQZ kinds 4, 5 and their twins 12, 13; the
governance bit and masks; the direct entries, the router ops, the consent, the views, events and errors; the per-entry auditor
epoch and the key history; `ZetherDisclosure` and the PQZ disclosure; the node rows; the `ua-rs` and clientkeys builders and
readers; the Zether prover; the vectors (`governance_bits.json`, `typed_ops.json`, `namespaces.json`, the selector audit, the
Zether proof-of-possession vectors).

**Out of scope.** `auditorMode` (stays immutable). No change to an existing relation, statement, transcript or
`proofSystemId`: the transfer statement already takes `Y_a` / `pk_a` from the token at execution. One **new** transcript, the
Zether auditor's proof of possession (§5.2); nothing in `pqz-core` changes (§10). No other family in this round: no non-EVM
token carries governance bits for its confidential kinds today; the same bit comes in each family's next round (one rule on
every chain, as CTR-GOV-29 / CTR-GOV-30 state for their bits). Changing the auditing parties **without** a new key stays
possible off chain by re-sharing the threshold key (CTR-ZTH-41); the setter is for a new key.

## 3. The bit: 32 `AUDITOR` (CTR-GOV-31)

**Number.** 32 is the next free bit: `governance_bits.json` allocates 0–31 (13 and 14 never reused, CTR-GOV-14) and says
"Bits 32-127 are free"; 32 is in SCaaS's band 0–127 (CTR-GOV-10). Tested: no constant in `GovernanceBits` holds 32.

**Type.** A power (it has holders), not scalar, no scope. Set **only at creation** (not in `ENABLEABLE`), lockable at creation
like every bit, disabled one-way at once by the admin (`disableFeature(32, chainUid_)`), which freezes the auditor at its
current value for good, the way `disableFeature(24)` freezes `proofStore` (CTR-GOV-22); so it is never the remedy after a
hostile apply (§5.3). A token created without bit 32 keeps CTR-ZTH-09's immutability; a wallet reads it from `features()`.

**Kinds.** In `_validBits()` and `_roleBits()` of the kinds 2, 3, 4, 5, 10, 11, 12, 13 only, and nowhere else: not in
`_contractOnlyBits()`, not in `GovernanceBits.REGULATED_ROLES` (which feeds the regulated kinds' role and contract-only masks,
`RegulatedBase` `REG_ROLES` / `REG_CONTRACT_ONLY`: adding 32 there would put it on kinds 8 and 9 and turn their refusal into
`RoleWithoutFeature(32)`). Every other kind (0, 1, 8, 9) and `SCaaSDex` refuse it with `FeatureInvalidForKind(32)` at `init`
and `NoSuchRole(32)` at a grant, by their masks. Tested both ways per kind.

**At `init`.** Refused (in the confidential init after `GovernanceLib.init`, which has written `features` and `admin`) on a
token whose `auditorMode` is NONE (`BadAuditorMode(0)`: a NONE token never gains an auditor) and on a token whose admin is 0
(`FeatureNeedsAdmin(32)`: with no `Roles` seat the bit could never get a holder). FULL and OPTIONAL keep a key at every moment.

**Holder (owner ruling 4).** **Any holder**, like every governance holder: a single-key UA, an `msig` or a contract. Not in
`ISSUER_BITS`, no `Roles` seat: the admin grants it after creation (`grantRole(32, holder, chainUid_)`, two calls under
`grantDelay`, CTR-GOV-04), so the first holder is announced (`GrantProposed`). **No delegation:** `setGrant` refuses
`delegable` terms on bit 32 (`DelegableRefused(32)`), so no holder can add another holder at once and unannounced, and no
leaf can outlive its parent's revoke while holding the one proposal slot. **One key can act alone**: the wallet warns of it
(§8, the bit's sentence) and recommends an `msig`; that is a client rule, not a contract rule.

**Revoke.** **Never delay-relaxed**: bit 32 is not in `_delayedRelaxBits()` (the regulated mask is `ISSUER_BITS` minus 23 and
24, which bit 32 is not in; pinned by a test). `revokeRole(32, …)`, `renounceRole(32, …)`, `disableFeature(32, …)` act at once,
so the admin stops a compromised single key at once, and the stop kills its live proposal (§5.3). The `TAX` precedent
(CTR-GOV-21: any holder, so the revoke must be immediate) fits exactly.

**Locked bit, renounced admin.** With bit 32 locked at creation and the admin later renounced (allowed once every unlocked bit
has no live root, CTR-GOV-02), the holders are permanent and nobody can revoke them; the bit's sentence says so (§8).

## 4. The delay (owner ruling 5, O1)

Two delays exist today:

| Delay | Set by | Range | What it delays today |
|---|---|---|---|
| `grantDelay` (CTR-GOV-04) | the token's creator, in `TokenConfig`, immutable | 0 to 30 days | the admin's grants and widenings, the relaxations of 5, 6, 7, 28 (CTR-GOV-09), the cap changes of bit 31 (CTR-GOV-30) |
| the factory's `noticePeriod()` | the chain, once, at `OpenFactory.configureChain` (no writer after) | 0 to 30 days (`MAX_NOTICE_PERIOD`) | a release's use, a `TAX` rate increase (CTR-AS-19), the wrap-limit changes that wait, the PQZ verifier transfer and fee increase (CTR-PQZ-28, CTR-PQZ-36) |

**The delay is `D = max(IOpenFactory(FACTORY).noticePeriod(), grantDelay)`** (owner). With a single-key holder allowed, the
notice is the only guard with teeth between a stolen key and a redirected audit; the chain's notice may be 0, and the `max`
lets a token's creator give its holders a notice on such a chain. Both values never change after creation, so `D` is
constant per token; it is read at the proposal (one cold call to the factory on a governance path, never on a transfer) and
again at the confirm. **`PqzStorage.noticePeriod` is never used**: it is written only on `OFFCHAIN` tokens and is 0 on every
`PRECOMPILE` token, so following the PQZ verifier's code would give those tokens no notice.

**Owner ruling 5, O4: `D = 0` applies at once** (both values 0: the proposal applies in the same call, both events in one
transaction), and the wallet says so (§8). On such a token the bit is also a transfer stop: each apply invalidates every proof
in flight (T4), so a hostile holder alternating keys stops audited transfers until the admin revokes it.

**It never waits forever:** both values are capped at 30 days (`OpenFactory.MAX_NOTICE_PERIOD`,
`GovernanceLib.MAX_GRANT_DELAY`), so `D ≤ 30 days`.

**Mechanics: two calls.** The holder proposes, `eta = now + D`; the same holder confirms with the same value within
`[eta, eta + AUDITOR_CONFIRM_WINDOW]`, **`AUDITOR_CONFIRM_WINDOW = 7 days`, a constant of its own, independent of `D`**
(coordinator ruling, controller call, owner may override): a window of length `D` or `noticePeriod` would be empty when
`noticePeriod = 0` and `grantDelay > 0`, and the proposal could never be confirmed. Why two calls and not "apply at `eta` by
itself" (the `TAX` fold-in): a fold-in puts a pending check on every transfer, the hottest path; two calls put nothing there.
Why a window: a proposal nobody confirms expires, so an old proposal never lands by surprise; **an expired proposal frees the
slot**: a new proposal replaces it with no cancel needed. The generic `GovernanceLib._due` is not reused: it is private, keyed to `grantDelay`, and tied to
the admin generation, while this proposer is a holder.

## 5. Design

### 5.1 State machine (both families)

`setAuditorKey(newKey, epoch, pop, chainUid_)` (Zether) / `setAuditorUA(newAuditor, epoch, consent, chainUid_)` (PQZ), caller
`c`, `e` = the current `auditorEpoch`:

1. `_holderOnChain(32, chainUid_)` (CTR-GOV-28: a caller without the bit `MissingRole(32, c)` first, then the holder's word
   `ChainUidMismatch`), then `use(32, c, 0)` (the grant's checks; **every call is one use**, so a replacement takes two, three
   with a cancel; the client checks `maxUses` before it proposes). Bit 32 off or disabled: `FeatureNotSet(32)`.
2. `epoch == e + 1`, else `AuditorEpochMismatch(e + 1, epoch)`: the signed call names the epoch the new auditor takes, so a
   held confirm or cancel cannot turn into a fresh proposal after the state moved (a wallet shows what is signed).
3. A **live** pending `P` (stored; `now ≤ P.eta + AUDITOR_CONFIRM_WINDOW`; `P.proposerRoleEpoch == epoch[32][P.proposer]`,
   so a revoke or renounce of the proposer, which bumps its role epoch through `_clear`, kills it for good, re-grant included;
   bit 32 set). A stored proposal that is not live (expired, its proposer revoked, or the bit off) counts as none: step 4
   overwrites it.
   - the same new auditor: `c == P.proposer` (else `NotProposer(32, 0, P.proposer)`), `now ≥ P.eta` (else
     `AuditorNotReady(P.eta)`), the checks of §5.2 again, then **apply** (§5.4).
   - the current auditor: the holder cancels its own pending proposal before the confirm: `c == P.proposer` (else
     `NotProposer`), then cancel (`AuditorProposalCancelled(e + 1)`); a cancel checks no consent.
   - any other value: `AuditorPending()` (one proposal at a time, until it is confirmed, cancelled, expired or its proposer
     revoked).
4. No live pending (none stored, or an expired or void one, which is overwritten): the current auditor `AuditorSame()`; else
   the checks of §5.2, then propose: store `P` (the new auditor or its key's hash, `eta`, `c`, `epoch[32][c]`) and emit
   `AuditorKeyProposed` / `AuditorUAProposed`; with `D = 0` apply at once. A confirm call after the window finds no live
   proposal and so proposes afresh (with a fresh `eta`); it never applies.

### 5.2 Checks on the new auditor (at the proposal and again at the apply)

**The new auditor's consent** (replaces the first draft's "no account state" check, which anyone could veto on PQZ by shielding
one unit into the proposed UA). A typed struct, signed under the token's own EIP-712 domain (the domain `PqzAuth` and the
owner digests use, TS-D19):

```
AuditorConsent(address token,bytes32 auditor,uint32 epoch,bytes32 chainUid)
```

`auditor` is the new auditor's UA (Zether: `toUA(newKey)`, which binds the key bytes), `epoch` the epoch it takes, `chainUid`
the token's word. The digest `d` is checked at the proposal and again at the apply (the confirm carries the consent again).

- **PQZ:** `consent` is an `IUARegistry.UASig` of `newAuditor` over `d`, checked by `IUARegistry.requireAuthorized(newAuditor,
  UAKinds.PURPOSE_AUDITOR_CONSENT, d, consent)`, a purpose of its own, `PURPOSE_AUDITOR_CONSENT =
  keccak256("scaas.ua.purpose.auditor-consent.v1")` in `UAKinds` (the string form of the other purposes, asserted by the
  drift test). `requireAuthorized` accepts any purpose, so the registry and its closed portable list do not change.
  `PURPOSE_ZETHER_AUTH` is not reused: it names Zether's operations, and on a PQZ token it would mislead readers and
  auditors even though the typehash keeps the digests apart. A refusal is the registry's.
- **Zether:** `pop` is a Schnorr proof of possession of `x_a` for `Y_a = newKey`, a new crypto object (one `bytes`, the proof):
  `pop = R ‖ be32(z)` (`P + 32` bytes, `P` the curve's G1 encoding). Prover: `k` hedged (`H(x_a ‖ d ‖ 32 random bytes)` mod `r`,
  as every opening's nonce), `R = [k]G`, `c = hashToScalar(keccak256("SCAAS-ZETHER-AUDITOR-POP-V1" ‖ d ‖ G ‖ Y_a ‖ R), r)`,
  `z = k + c·x_a mod r`. Verifier (`ZetherLib`, through the token's verifier): exact length, `R` a valid point, `z < r`, `c ≠ 0`,
  `[z]G − R − [c]Y_a == O` (one MSM). Strong Fiat–Shamir: the statement points `G`, `Y_a` and the commitment `R` are absorbed,
  and `d` binds token, epoch and word. A threshold auditor (CTR-ZTH-41) produces one `(R, z)` by a k-of-n Schnorr off chain;
  the contract sees one proof. Refusal: `AuditorConsentInvalid()`.

**A consent is not withdrawn on chain** (owner ruling 2026-11-18, option (c), no `validUntil`): within one epoch it stays
valid after a cancel or an expired window, and any holder of bit 32 may reuse it to propose the same auditor again; the auditor
cannot revoke it. Accepted as governance: the holder is the trusted party; residual in T3, ruling in
[decisions.md](../../decisions.md#CTR-GOV-31) (the Change of 2026-11-18 on the consent's reuse).

What consent closes: an auditor that never signs can never be named, so a holder cannot point the auditor at another
holder's key (the targeted freeze through `AuditorKeyAsParty` / `AuditorAsParty`) and, on Zether, cannot name a key nobody
holds (auditor blinding). It reads no account state, so nobody can veto it.

**Also checked:**
- **Zether:** `newKey` is `P` bytes, `isValidPoint`, not `O` (`AuditorKeyInvalid()`), as `init` checks `auditorKey`;
  `AuditorSame()` compares the canonical encoding (A0 reads `isValidPoint` for aliases: if two encodings of one point pass,
  the comparison is on the decoded point).
- **PQZ:** the key checks a transfer with the auditor on makes (`PqzCore._keyPtrV`: a key of the token's class and scope,
  CTR-PQZ-37; on an opening token also the opening KEM key in that scoped record, CTR-UA-43); unlike `init`, this runs on an
  `offchain-token` too (the token exists). On an `OFFCHAIN` token `_usable` accepts a stored key that is not proven, so a consenting UA could carry a copy of a
  holder's public key and stop that holder's audited transfers (`KeyReused`). **The rule (controller ruling 2026-11-18, the
  same rule as `_usable`'s "proven, or nothing"):** where the registry has a `0x0142` verifier (`kindEnabled(0x0142)`), the
  setter requires the new auditor's current key record of the token's class and scope to be `proven` (the flag of
  `pqzKeyOf` / `pqzScopedKeyOf`: its `R_REG` proof checked by that verifier); on a chain without the verifier no proven check
  is made (stored proof bytes are not a check), and the T3 key-copy residual stands there, as in the three-key model's
  accepted risk for `OFFCHAIN` keys (CTR-PQZ-37). The consent signature is required on every chain, unchanged.

Checking again at the apply matters: between the proposal and the apply the new auditor may have dropped its key, and a FULL
token with an unusable auditor refuses every transfer.

### 5.3 Who can stop a proposal, and the way back

Before the apply: the proposer (cancel by proposing the current auditor), and the admin at once: `revokeRole(32, proposer)`
(kills it by the role epoch) or `disableFeature(32)`. The 7-day window ends it by itself, and the next proposal takes the
slot. **Revoke before `eta`**: a holder may
confirm at `eta` ahead of the admin's revoke.

After a hostile apply there is no fast undo: the revoke stops further proposals, not the applied auditor. The way back is a
new holder (`grantRole`, `grantDelay`) and a new proposal of the previous key (its consent, then `D`): up to `grantDelay + D`
(60 days at most), during which the applied key reads every audited transfer, or, if that auditor dropped its usable PQZ key,
during which every FULL transfer reverts (T8). **Never `disableFeature(32)` after a hostile apply**: it freezes the hostile
auditor for good. Entries made in between keep their epoch. An admin emergency restore would be a new rule; none is
proposed. Operator note: [ops.md](../../node/ops.md#operator-notes).

### 5.4 Apply

Epoch `e`. Zether: `auditorKeys[e] = auditorKey` (the outgoing key enters the history), `auditorKey = newKey`; PQZ:
`auditorUAs[e] = auditorUA`, `auditorUA = newAuditor`. Then `auditorEpoch = e + 1`, the pending is deleted, and
`AuditorKeySet(e + 1, previous, next)` / `AuditorUASet(e + 1, previous, next)`. A history entry is written once, at its
epoch's end, and never rewritten, also when the same key returns at a later epoch (it gets a new epoch). The current key
stays in its old slot, so a transfer reads what it reads today.

### 5.5 Per kind

| Kinds | Auditor | Entry | Views | Body (module) / logic (library) |
|---|---|---|---|---|
| 2, 3, 10, 11 (Zether) | `auditorKey` (`bytes`, `Y_a`) | `setAuditorKey(bytes newKey, uint32 epoch, bytes pop, bytes32 chainUid_)` | `auditorKeyOf(bytes32 entryRef)`, `auditorState()` | the Zether module (Z of each kind); `ZetherLib` (external, DELEGATECALL) |
| 4, 5, 12, 13 (PQZ) | `auditorUA` (`bytes32`, a `pqz-mlwe` UA) | `setAuditorUA(bytes32 newAuditor, uint32 epoch, IUARegistry.UASig consent, bytes32 chainUid_)` | `auditorUAOf(bytes32 entryRef)`, `auditorState()` | the PQZ setters module (S on 5, 12, 13; Q on 4, owner ruling 5, O2); `PqzStateLib` |

The regulated twins take the same entries from their base layer; nothing regulated-specific. `PAUSE` does not stop the
setter (it stops value movements, not governance). Two entries, not one: the Zether auditor is a key (`bytes`, a crypto
object), the PQZ auditor is a UA (`bytes32`); one `bytes` parameter holding either would be a packed field.

## 6. Storage

Appended or placed in free bytes; **no existing field moves** (`test/v2/layout/` pins every old row unchanged and gains the
new ones; `namespaces.json` gains their rows with `widths` and `encodings`, which `ua-rs` reads as a vector).

`scaas.zether` (`ZetherLib.ZetherStorage`):

| Field | Where (expected; the layout test pins it) | Written by |
|---|---|---|
| `uint32 auditorEpoch` | slot 0, offset 22, after `auditorMode` (slot 0 is `verifier(160) ‖ disclosureMode(8) ‖ auditorMode(8)` today, 10 bytes free) | the apply |
| `uint64 auditorEta`, `uint32 auditorProposerRoleEpoch` | slot 13 (after `minDecoyFee`, slot 12) | the proposal |
| `bytes32 auditorProposer` | slot 14 | the proposal |
| `bytes32 pendingAuditorKeyHash` (`keccak256` of the proposed key; the event carries the key) | slot 15 | the proposal |
| `mapping(uint32 => bytes) auditorKeys` (epoch → the key that epoch used, for every epoch below the current one) | slot 16 | the apply |
| `mapping(bytes32 => uint32) entryAuditorEpoch` | slot 17 | a transfer (§7) |

`scaas.pqz` (`PqzCore.PqzStorage`):

| Field | Where (expected) | Written by |
|---|---|---|
| `uint32 auditorEpoch` | slot 0, offset 26, after `pqzOpening` (6 bytes free) | the apply |
| `uint64 auditorEta`, `uint32 auditorProposerRoleEpoch` | slot 22, after `verifierFeeProposerGeneration` (its free bytes) | the proposal |
| `bytes32 auditorProposer` | slot 23 | the proposal |
| `bytes32 pendingAuditorUA` | slot 24 | the proposal |
| `mapping(uint32 => bytes32) auditorUAs` | slot 25 | the apply |
| `mapping(bytes32 => uint32) entryAuditorEpoch` | slot 26 | a transfer (§7) |

Why the epoch sits in slot 0: every confidential transfer already reads slot 0 for `auditorMode`, so reading the epoch adds
no storage read to the hot path. A token that never replaces its auditor writes none of the new slots. Readers that parse
slot 0 by hand take the new bytes: `clients/zether-prover/src/state.rs` (`modes`) and `clients/ua-rs/src/facade/pqz.rs`
(`auditor()`'s `only_low(&w, 22)` refuses every byte above 21; I1 of the review: it may already refuse an `OFFCHAIN` or `LOG`
token's slot 0, so plan A4 tests that first).

**Name.** `auditorEpoch`, not "auditor key version": on PQZ "key version" is the UA's own PQZ key version (CTR-PQZ-31, the
op blob's `kv` tail), a different counter; the epoch counts replacements of the token's auditor, like `pqzVerifierEpoch`.

## 7. Recording the epoch per operation

A transfer **with the auditor on** (Zether: `Y_a ≠ O` in the statement; PQZ: `auditorOn = 1`), single or multi-recipient, on a
token whose `auditorEpoch ≠ 0`, writes `entryAuditorEpoch[entryRef] = auditorEpoch` next to its record. Nothing else writes it.
Absent reads as 0, which is right: an entry made at epoch 0 needs no row (and `auditorKeys[0]` holds the first key once it is
replaced). So a token at epoch 0 pays nothing, and after the first replacement each audited transfer pays one new slot
([estimate] about 5 k regular gas and 97,920 state gas under EIP-8037). The regular part counts against the EIP-7825 cap:
the Zether prover's `gas_limits` edge cells and the PQZ op 7 cells nearest the cap at each set are re-measured at an epoch
other than 0 (forge does not enforce the cap; plan A2, A4). Burns, unshields, refreshes, rollovers and shields carry no auditor
copy and write nothing. `entryRef` binds sender and counter, so a row is written once; Zether's HASH mode stores the record in
the transaction that checks the proof, so the epoch cannot move between them.

On PQZ the op blob tail already records the auditor's **key version** (`kv(8·n)`, CTR-PQZ-34); with the epoch the full identity
of an old entry's auditor key is `(auditorUAOf(entryRef), kv_a)`. On Zether the record `R` carries no auditor key, so the
epoch row is the only link. Rejected: appending the epoch to `R` or the op blob (moves the record formats and the disclosure
parse by length, for every transfer); one row per transfer always (state gas on every token).

## 8. Entries, views, events, errors

**Direct entries** (the holder): `setAuditorKey(bytes newKey, uint32 epoch, bytes pop, bytes32 chainUid_)` on 2, 3, 10, 11;
`setAuditorUA(bytes32 newAuditor, uint32 epoch, IUARegistry.UASig consent, bytes32 chainUid_)` on 4, 5, 12, 13. Each carries
the chain word as every holder entry does (CTR-GOV-28's Change). They are governance entries, not token meta-tx ops: the
tokens' allow-lists (`mtxSelectors`, `_uaAllowed`, `_mtxRule`) are unchanged, as for `setProofStore`; the selector audit
(`test/vectors/selector_audit.json`) classifies them as `setProofStore`'s class.

**Router ops** (a derived holder signs through the chain's `GovernanceRouter`; fee mode `NONE`, relayable at fee 0). The
holder's struct names the op's own fields; the new auditor's consent travels beside it, unsigned by the holder (it is the
auditor's own signature or proof over its own typed struct):

| Op | Typed struct |
|---|---|
| `mtxSetAuditorKey(UAEnvelope e, address target, bytes newKey, uint32 epoch, bytes pop, bytes32 chainUid, UASig auth)` | `UASetAuditorKey(bytes32 from,address target,bytes newKey,uint32 epoch,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)` |
| `mtxSetAuditorUA(UAEnvelope e, address target, bytes32 newAuditor, uint32 epoch, UASig consent, bytes32 chainUid, UASig auth)` | `UASetAuditorUA(bytes32 from,address target,bytes32 newAuditor,uint32 epoch,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)` |

`bytes newKey` is hashed into the struct as EIP-712 says. The typehashes (these two and `AuditorConsent`) are computed and
pinned by the build (`GovRouterTypehash.t.sol`, `vectors/typed/typed_ops.json`). Two `UASig` arguments in one router op may
hit stack-too-deep (CTR-GOV-27 met it at 13 parameters): if `mtxSetAuditorUA` does not compile, the build stops and reports.

**Views.** `auditorKey()` / `auditorUA()` keep returning the current auditor. New:
- `auditorKeyOf(bytes32 entryRef) returns (bytes)` (Zether) / `auditorUAOf(bytes32 entryRef) returns (bytes32)` (PQZ): the
  auditor of the entry's epoch. For an unknown `entryRef`, or an opt-out entry, it answers epoch 0's; callers check the entry
  and its auditor copy (the disclosures do).
- `auditorState() returns (uint32 epoch, bytes32 pending, uint64 eta, bytes32 proposer, uint8 status)`: the current epoch and
  the stored proposal (Zether `pending` = the proposed key's hash, the key itself is in the event; PQZ `pending` = the proposed
  UA), with `status` 0 none, 1 waiting (before `eta`), 2 confirmable (`[eta, eta + AUDITOR_CONFIRM_WINDOW]`), 3 expired (past
  the window; the slot is free), 4 void (its proposer revoked or bit 32 off, `disableFeature(32)` included).

**Events.** `AuditorKeyProposed(uint32 epoch, bytes newKey, bytes32 proposer, uint64 eta)`, `AuditorKeySet(uint32 epoch, bytes
previousKey, bytes newKey)` (Zether); `AuditorUAProposed(uint32 epoch, bytes32 newAuditor, bytes32 proposer, uint64 eta)`,
`AuditorUASet(uint32 epoch, bytes32 previousAuditor, bytes32 newAuditor)` (PQZ); `AuditorProposalCancelled(uint32 epoch)` (both).
`epoch` is the epoch the new auditor takes.

**Errors.** `AuditorNotReady(uint64 eta)`, `AuditorPending()`, `AuditorSame()`, `AuditorEpochMismatch(uint32 expected, uint32
got)` (both families), `AuditorKeyInvalid()`, `AuditorConsentInvalid()` (Zether), `FeatureNeedsAdmin(uint8 bit)` and
`DelegableRefused(uint8 bit)` (`IGovernance`); reused: `MissingRole`, `FeatureNotSet(32)`, `NotProposer`,
`IAdmin.ChainUidMismatch`, `FeatureInvalidForKind(32)`, `NoSuchRole(32)`, `BadAuditorMode(0)`, the registry's signature
refusals and the PQZ key errors. Names are controller calls (O8).

**Node verdicts** ([submit-lanes](../../node/submit-lanes.md)): on the two router ops `AuditorNotReady` is `queued` (it passes
once `eta` is reached, as `GrantNotReady(31)` on the cap setters); every other refusal is `dead`. A transfer proven against
the outgoing auditor and mined after the apply fails its statement check, as after a PQZ key rotation today: `dead`, the
wallet proves again; the proposal event gives wallets `D` to drain such builds (operator note in [ops.md](../../node/ops.md)).

**Bit vector row** (`governance_bits.json`, written by `GovBitsVector.t.sol` with `WRITE_BITS=true`, never by hand; named
here, edited by plan task A1): `{"bit": 32, "name": "AUDITOR", "type": "power", "kinds": [2, 3, 4, 5, 10, 11, 12, 13],
"holder": "any", "sentences": {"all": "A holder can replace this token's auditor with one that consents: the new auditor
reads every later transfer that includes the auditor, never an earlier one. Each replacement is announced on chain, takes two
calls of the same holder (two uses of its grant) and applies only after {auditorDelay}, the longer of the factory's notice
period and this token's grant delay; the admin can stop it at once by revoking the holder before it applies. A token without
an auditor never gains one.", "atOnce": "This token's delay is 0: a holder of this power replaces the auditor at once, with no
notice.", "singleKey": "A holder of this power is a single key: that one key can redirect who reads later transfers, after the
delay. A threshold (msig) holder is recommended.", "locked": "This power can never be switched off, and its admin is gone:
nobody can revoke its holders."}, "sentencesWhen": "atOnce while max(noticePeriod(), grantDelay()) is 0; singleKey per holder
whose registry kind is a single key; locked while bit 32 is locked and admin() is 0."}`; the note's "Bits 32-127 are free"
becomes "Bits 33-127 are free".

## 9. Disclosure across epochs

**Zether** ([CTR-ZTH-43](../../contracts/zether.md#CTR-ZTH-43)). `ZetherDisclosure.verifyTransferAmount(…, AUDITOR, …)` reads
`auditorKeyOf(entryRef)` instead of `auditorKey()`; empty (NONE) or `C_aud_j = O` stays `false`. `K = Y_a(epoch)` is absorbed
into the strong Fiat–Shamir challenge (`G ‖ K ‖ B ‖ M`, CTR-ZTH-40), so an opening made with one epoch's key never verifies
against another's. Reading the current key instead would be a forgery path, not only a liveness one: a sender who knows `v`
and `s`, with an old auditor who knows `x_a`, can derive a key under which a chosen false amount opens; the test and mutant
for it stay. No transcript change for the openings. `ZetherDisclosure` is stateless and shared, so it is a new deployment
carried by each Zether release's `disclosure()` immutable; nothing deployed is upgraded. The prover follows: `openDisclosure`
and the sender's `recoverTransfer` (which rebuilds `C_aud_j = [v_j]G + [t_j]Y_a` from the memo and must use the entry's `Y_a`)
read `entryAuditorEpoch[entryRef]` and that epoch's key from state (slots 16, 17, or slot 5 for the current epoch).

**PQZ** ([CTR-PQZ-14](../../contracts/pq-zero-knowledge.md#CTR-PQZ-14)). On a token without the opening (class `registry`,
and `offchain-token` without the opening), the `AUDITOR` kind checks against the auditor of the entry's epoch: `_legOf`'s
owner becomes `auditorUAOf(entryRef)`; `keyVersion` stays the caller's (KV-11), and the op blob's `kv` tail says which version
that auditor used. On an opening token the only disclosure kind is `SENDER_S` (CTR-PQZ-14's Change), whose statement names no
auditor; each auditor's opening `O_a` stays sealed to the opening KEM key of its epoch's auditor. The sender's recovery rebuilds
`v_a` with `pk_a` of `(auditorUAOf(entryRef), kv_a)`.

**The auditor's readers** (`ua-rs` `facade/pqz.rs` `auditRead` / `proveDisclose AUDITOR`, its Zether facade, clientkeys where it
reads; ARCH-POS-13). A reader reads `auditorEpoch`, resolves each entry's auditor (`entryAuditorEpoch[entryRef]`, then
`auditorUAs[epoch]` / `auditorKeys[epoch]`, or the current one; on PQZ pinned to the tail's `kv_a`), and **refuses to apply its
secret to an entry whose auditor is not its own, before any decryption**: an entry of another epoch was encrypted to another
key, so applying the secret to it and showing any outcome would decrypt a ciphertext someone else chose. The refusal names the
entry's auditor and nothing else.

**The proof path** (`ua-rs` `provenOpen` / `provenAdd` / `checkProven`, no-oracle spec §4.14.4, and `pqz-read
--command balanceProven`) takes no auditor secret, yet names the auditor's key in each audited debit's statement: it resolves the
auditor of each audited credit and of the own debit the same way (`entryAuditorEpoch[entryRef]`, then `auditorUA` at slot 7 for
the current epoch or `auditorUAs[epoch]` at 25), from the record's `auditor` words, which `pqz-read` reads and the facade checks
as `auditRead`'s; a record without them is read by the current auditor (correct for the current epoch, refused otherwise).
Closing review (Fable, 2026-11-18) C1: the current auditor for every record refused each one audited before a replacement.

## 10. The three-key model (CTR-PQZ-37), ARCH-POS-13 and `pqz-core`

- **Key class and scope.** The new auditor needs a key of the token's class and scope before the proposal and at the apply
  (§5.2): the registry key on a `PRECOMPILE` token, the shared second key on `offchain-shared`, its key of that token on
  `offchain-token`; and on every opening token the opening KEM key in that scoped record (CTR-UA-43), so `O_a` of every later
  transfer is sealed to the new auditor.
- **No retroactive reading either way.** Earlier `O_a` and `v_a` stay under the outgoing auditor's keys; the new auditor reads
  from its epoch on. The outgoing auditor keeps what it could read (a disclosure is irrevocable, CTR-ZTH-43).
- **`offchain-token` without the opening.** CTR-PQZ-37 states that the token's auditor "once named, has no such choice" about
  its key of that token being exposed to a dishonest verifier. A replacement auditor does choose: it signs its consent and has
  registered its key for the token first.
- **ARCH-POS-13.** The setter decrypts nothing, and nothing in it reacts to a ciphertext anyone chose: it reads a key or a UA, a
  signature and a proof of possession over a typed struct. The client side is the readers' refusal of §9.
- **`pqz-core` untouched.** No file of `pqz-core/ffi/src` (or `pqzl`, `pqzh/ligero/src`, `stmt`, set parameters) changes: the
  callers pass `pk_a` of `(auditorUAOf(entryRef), kv_a)` into the recovery, which already takes keys as input. So no
  `gate.sh` step runs for this round. If the build finds an `ffi` change needed after all, it says so and runs the affected
  steps of `gate.sh` (not the full gate, unless a core input changes).

## 11. Threat model

| # | Threat | Guard | Residual (stated, not closed) |
|---|---|---|---|
| T1 | **A bit holder redirects the readability of every later amount** to a key it controls; with the owner's ruling one single key can do it alone | the new auditor's consent (it can only be a party that agrees); the holder granted by the admin under `grantDelay` with `GrantProposed`, no delegation; every replacement proposed in public and applied only after `D = max(noticePeriod, grantDelay)`, by the same holder, inside a window, naming its epoch; the admin's immediate revoke and `disableFeature(32)` before the apply; a creator who wants none leaves bit 32 off; under OPTIONAL a sender may leave the auditor out per transfer (CTR-ZTH-42, publicly visible); the wallet's single-key warning | after `D` the new key reads every later audited transfer; a holder who does not leave in time accepts it. **One stolen single key does it alone**, with a consenting accomplice key. An admin that colludes with a holder needs `grantDelay + D`, nothing more. **`D = 0` (owner ruling: applies at once) gives no notice** and makes the bit a transfer stop (T4). After the apply there is no fast undo (§5.3). With bit 32 locked and the admin renounced, holders are permanent. The contract cannot tell an honest replacement from a hostile one |
| T2 | auditor blinding: a key with no known secret | Zether: the proof of possession; PQZ: the UA's signature and its registered key | the auditor itself may later discard its secret, as today |
| T3 | a targeted freeze by naming a holder's key or UA as auditor | consent: a holder can only be named if it signs | a holder that consents stops its own confidential transfers (it keeps unshield). **A consent outlives a cancel or an expired window within its epoch:** any holder of the bit may reuse it, and the auditor cannot withdraw it on chain (owner ruling 2026-11-18, option (c): no `validUntil`; the holder is the trusted party, the dispute is off-chain governance; §5.2). On an `OFFCHAIN` token on a chain whose registry has no `0x0142` verifier, a consenting UA carrying a copy of another holder's public key stops that holder's audited transfers (`KeyReused`) until the next replacement (§5.2; with the verifier, the `proven` check closes it) |
| T4 | transfers proven against the outgoing auditor fail after the apply; at `D = 0` a holder alternating keys stops audited transfers | the proposal event and `D`; the admin's revoke | liveness only: `dead`, prove again; at `D = 0` until the admin revokes, and the last applied key stays |
| T5 | an old proposal applied by surprise; a held signed call replayed after the state moved; a proposal that can never be confirmed and blocks every later one | the window `[eta, eta + 7 days]`, its own constant (never empty, whatever `D`); an expired proposal frees the slot; the epoch in the entry and the struct | none |
| T6 | a revoked holder's proposal survives a re-grant; a leaf holds the slot after its parent's revoke | the proposer's role epoch; no delegation on bit 32 | an expired grant's proposal holds the slot for at most `D + 7 days`, or until the admin revokes |
| T7 | an old entry disclosed against the wrong key | `entryAuditorEpoch` and the key history; `K` in the challenge | an unknown or opt-out `entryRef` answers epoch 0's key from the view; the disclosure refuses or answers `false` |
| T8 | a FULL token left with an unusable auditor (every transfer reverts) | §5.2 again at the apply | the auditor itself may later drop or rotate its PQZ key, as today; the setter is the first way out of that state (review I3) |
| T9 | sibling replay of a holder's direct call or of a consent | the chain word (CTR-GOV-28); the router's domain; `chainUid` and the token in `AuditorConsent` | as CTR-GOV-28 |
| T10 | a new auditor under FULL cannot rebuild balances by bookkeeping (CTR-PQZ-24) | none in the contract | it reads only its epochs; a hand-over of earlier records is off chain |
| T11 | a reader applies an auditor secret to an entry of another epoch (a decryption of a chosen ciphertext) | the readers' refusal before decryption (§9), with a test and a mutant | none known |

## 12. Sizes

Lines (`size_gate.py`): release T-2 33,594 / T-1 35,386; module 33,780 / 35,570; library 33,903 / 35,694; plain 33,516 /
35,286. The baseline is a ratchet: every row the build grows moves in `size-baseline.json` with old → new figures and this
spec as the reason, and every contract that passes 24,576 B for the first time takes a **new row and its `_forms` entry**
(`PqzStateLib`, projected up to about 27.5 K; possibly the Z modules of kinds 2 and 10 and the S modules). The round's
`bytecode_hash = "none"` takes about 40 B off every contract (the code-format plan's figure).

| Contract | [baseline] | Change [estimate] | Note |
|---|---|---|---|
| faces of 2, 3, 10, 11 | 17,480; 23,721; 21,419; 27,929 | +0.5 KB each (3 stubs, about 165 B each) | `gen_faces.py` from `entries.json` |
| faces of 4, 5, 12, 13 | 19,965; 27,130; 24,056; **31,530** (`WrappedPqzRegulatedToken`) | +0.5 KB each | the largest face to about 32.0 K, under T-2 33,594 |
| Zether modules Z of 2, 3, 10, 11 | 2 and 10 under 24,576 (no row); 28,621; 29,292 | +0.5 to +0.8 KB | thin bodies into `ZetherLib`; the `pop` argument |
| PQZ module S of 5, 12, 13 | under 24,576 (no row) | +0.6 to +0.9 KB | the `UASig` argument |
| **`NormalPqzTokenQ`** (kind 4 has no S; owner ruling 5, O2: it stays here) | **33,384** | three dispatched entries with their argument decoding, the `UASig`, the factory call and the `_legOf` change: +0.8 to +1.5 KB | **about 34.2 to 34.9 K: over the T-2 notice line 33,780 (certain), under T-1 35,570 by about 0.7 to 1.4 K.** Measured at A0; the work stops and asks only if a figure crosses T-1. The next PQZ feature on kind 4 will need an S module |
| PQZ modules Q of 5, 12, 13 (`_legOf` by epoch) | 29,956; 24,990; 31,107 | +100 to +200 B | |
| `ZetherLib` | 27,341 | +2.3 to +3.7 KB | the setter, the checks, the proof of possession, the consent digest, the history, the per-entry write, the views; to about 31 K at most, under T-2 33,903 |
| `PqzStateLib` | under 24,576 (no row) | +1.8 to +2.8 KB | the setter, the checks, the consent; a new row if it passes 24,576 |
| `PqzTransferLib` and the op 1 body (per-entry write) | 26,321 | +100 to +200 B | |
| `GovernanceRouter` | 26,399 | +400 to +700 B (two rows, five more arguments) | |
| `GovernanceLib` | 15,737 | +50 to +150 B | the `delegable` refusal, the `init` admin check |
| `ZetherDisclosure` | no row | tens of B | one view name |

No contract is projected over its T-1 line. Contracts near their lines that this spec does **not** touch: `OpenFactory`
35,040 (246 B under the plain T-1), `SCaaSDex` (15 B under T-2), `UARegistryCoreLib` (107 B under T-2), `UARegistryAuxLib`
(177 B under T-2); **no factory-side or registry-side check for bit 32 may be added**. No module split is made by the build
(owner rule: only `NormalPqzRegulatedTokenQ` may be split automatically).

## 13. Tests and mutants

Tests first, per task (plan). Every refusal test has a positive control (the right holder, word, epoch, consent and value
pass) and changes one thing.

- **Bits and masks** (`test/governance/GovAuditorBit.t.sol`): bit 32 accepted on 2, 3, 4, 5, 10, 11, 12, 13, refused on 0, 1, 8,
  9 and the DEX (`FeatureInvalidForKind(32)` at `init`, `NoSuchRole(32)` at a grant, never `RoleWithoutFeature(32)`); `init`
  refuses it on a NONE token (`BadAuditorMode(0)`) and with admin 0 (`FeatureNeedsAdmin(32)`); a single-key UA, an `msig` UA, a
  native EOA and a contract are each accepted as holder; `delegable` terms refused (`DelegableRefused(32)`); `revokeRole`,
  `renounceRole`, `disableFeature` act at once (one call with `grantDelay ≠ 0`); bit 32 not in `ENABLEABLE`, not in
  `REGULATED_ROLES`.
- **Setter, both families** (`test/zether/ZetherAuditor.t.sol`, `test/pqz/PqzAuditor.t.sol`, the regulated kinds in
  `test/as/confidential/AuditorKinds.t.sol`): propose → `AuditorNotReady` before `eta` → apply at `eta`; the delay is
  `max(noticePeriod, grantDelay)` (each larger in turn); `D = 0`: one call; **a zero-notice chain with `grantDelay > 0`
  confirms within `[eta, eta + 7 days]`**; a confirm after the window is refused as a confirm (it proposes afresh with a new
  `eta`, nothing applied); a new proposal of another value is refused (`AuditorPending`) before the window ends and allowed
  after it, with no cancel; the holder cancels its own proposal before the confirm; `auditorState().status` 1, 2, 3, 4 in turn; **a `PRECOMPILE`
  PQZ token with the factory notice not 0 waits it** (A8); another holder cannot confirm (`NotProposer`); a revoked proposer's
  pending is dead after a re-grant; a wrong epoch (`AuditorEpochMismatch`) on a proposal, a confirm and a cancel; a held
  confirm after the window is not sent by the node (a requeued `AUDITOR_NOT_READY` job is resent only at status 2 with the same
  `pending` and `proposer`, else `dead` `AUDITOR_PROPOSAL_GONE` with no send, `consumed` if it landed; the mark is the
  job row's `error`, so a restarted node gives the same verdict; the contract itself proposes afresh, §5.1, which stands: the
  node rule is extra; ops: sign the confirm at `eta`; closing review C2); cancel by proposing the current, then a new proposal; `AuditorPending`,
  `AuditorSame` (Zether also for another encoding of the current point, if one exists), `AuditorKeyInvalid`; consent: a missing,
  wrong-token, wrong-epoch, wrong-word and wrong-key consent refused at the proposal, and a consent valid at the proposal but
  refused at the apply (PQZ: the auditor's signing key changed); the Zether proof of possession against its vectors (BLS12-381 only: `vectors/zether/auditor_pop.json`; a BN254 verifier
  needs its own rows, closing review C3), with `z ≥
  r`, `R` invalid, `c = 0` forced and a proof for another `d`; a stranger shielding into the proposed UA no longer blocks the
  apply; PQZ: an unregistered auditor, an `offchain-token` auditor without its token key, an opening token's auditor without an
  opening KEM key, an `OFFCHAIN` auditor key without its proof (A4's outcome); a sibling chain word refused with nothing
  written; a stranger `MissingRole` first; two uses per replacement (`maxUses = 1` proposes and cannot confirm);
  `auditorState()` reads zeros after `disableFeature(32)`.
- **The way back** (A4 of the review): revoke the hostile holder, grant another, restore the previous key with its consent;
  entries in between keep their epoch.
- **Epochs and disclosure**: an audited transfer at epoch 0 writes no row (`vm.load` and the slot count: +0 slots); at epoch 1
  it writes 1; an opt-out writes none; three epochs (0, 1, 2) with entries in each, each disclosed with its own key and refused
  with the others; an opt-out entry at epoch 2 (`auditorKeyOf` answers epoch 0's key; the disclosure returns `false` or
  `BadPayload`); the same key returning at epoch 2 leaves `auditorKeys[0]` unchanged; `ZetherDisclosure` single and
  multi-recipient; the PQZ `AUDITOR` disclosure on a `PRECOMPILE` token at the four sets; an opening token's `SENDER_S`
  unchanged; the gas probes at epoch ≠ 0 (Zether edge cells, PQZ op 7 nearest the cap per set).
- **Layout and pins**: every old row of `namespaces.json` unchanged, the new rows pinned; the router and consent typehashes;
  the selector audit; the bit vector; `typed_ops.json` rows; the "+0" pins on the plain kinds unchanged (`PlusZero.t.sol`).
- **Clients**: clientkeys and `ua-rs` build the two router ops and `AuditorConsent`, and sign the PQZ consent under
  `PURPOSE_AUDITOR_CONSENT`, to the vector bytes; the purpose constant equal in `UAKinds`, `kinds.json`, clientkeys and `ua-rs`
  (the drift tests); the Zether prover builds
  the proof of possession to its vectors; every `ua-*` reads bit 32's row; the Zether prover recovers and opens an epoch-1
  entry with the epoch-1 key (the epoch-0 key must fail); the `ua-rs` PQZ reader at epoch 1 on both handles (`auditRead`,
  `proveDisclose AUDITOR`); **the old auditor's handle refuses an epoch-1 entry and the new one an epoch-0 entry, each before
  the secret is applied** (Zether and PQZ readers); first, `auditRead` on an `OFFCHAIN` and a `LOG` token at epoch 0 (I1).
- **Node**: the two `typed.rs` rows, the `guard.rs` counts, the verdicts of §8.

**Mutants** (one per check; each killed by a named test; `runs/<date>-set-auditor/`): drop `use(32)`; drop the chain word; drop
the epoch check; allow a confirm before `eta`; drop the window's end; size the window by `D` or `noticePeriod` instead of
`AUDITOR_CONFIRM_WINDOW`; refuse a new proposal over an expired one; accept a new proposal over a live one; drop the cancel
branch; drop the proposer check; drop the role-epoch tie; read
`noticePeriod` alone; read `grantDelay` alone; **read `PqzStorage.noticePeriod`**; skip the consent at the proposal; check the PQZ consent under another purpose; skip it at
the apply; accept a proof of possession for another `d`; drop `c ≠ 0` or `z < r`; skip the per-entry write; write it at epoch
0; write it on an opt-out; disclosure reads the current key; the apply overwrites the history; skip the key check at the
apply; accept bit 32 on NONE; accept it with admin 0; accept `delegable` on 32; put 32 into `_delayedRelaxBits()`; put 32 into
`REGULATED_ROLES`; place `auditorEpoch` so that it moves a pinned field; the prover's recovery uses the current key; **the
reader uses the current auditor** (Zether and PQZ); the reader applies its secret before the epoch check.

## 14. Interaction with the bundled round

The order (plan): PqVault Part R (R1–R4) → this round's tasks A0–A10 → F2 `forge fmt` with `bytecode_hash = "none"` → one
compile and one re-pin of every code hash (the factory catalogue, `LinkClosure`, the `*_CODEHASH` constants,
`size-baseline.json`) and of every gas pin (old → new in the commit) → **one full gate** (every forge directory at
`n2304-kmax4096`, the four PQZ sets by `script/pqz/at-set.sh`, the node with e2e, every client; `pqz-core/gate.sh` not run, §10)
→ **one SCaaS testnet reset** with deploy, Blockscout verify and the matrix (new `setAuditor` matrix rows: grant, consent,
propose, apply after the testnet's delay, an audited transfer, an `AUDITOR` disclosure at both epochs). Between A1 and the
closing re-pin the code-hash pin tests are expected red; A0 lists them by name and each commit message names the ones it
leaves red, everything else green. The build's commits are not formatted by hand; F2 formats them with everything else.
Every chain is test-only: no migration; every confidential kind gets a new release in the catalogue at the reset.

## 15. Open points

| # | Point | Status |
|---|---|---|
| O1 | The delay | **Owner 2026-11-17: `max(noticePeriod(), grantDelay)`** (§4) |
| O2 | `NormalPqzTokenQ` at about 34.2–34.9 K (over T-2, under T-1) | **Owner 2026-11-17: stays in Q, measured at A0; stop and ask only if a figure crosses T-1** |
| O3 | Holder class | **Owner 2026-11-17: any UA**, a single key too (§3); the wallet warns of a single key and recommends an `msig` |
| O4 | The delay 0 | **Owner 2026-11-17: applies at once, and the wallet says so** (§4, §8) |
| O5 | The new auditor's consent (UA signature on PQZ, proof of possession on Zether) | controller call (coordinator's ruling on the review's A1); replaces the account-state check |
| O6 | A consent or account check at `init` | not added: the creation-time auditor is public before anyone holds the token |
| O7 | Hand-over to a new FULL auditor | off chain only (T10); the way back of §5.3 is in the operator note |
| O8 | Names: `AUDITOR`, `setAuditorKey`, `setAuditorUA`, `AuditorConsent`, `PURPOSE_AUDITOR_CONSENT`, `"SCAAS-ZETHER-AUDITOR-POP-V1"`, `auditorEpoch`, `auditorKeyOf`, `auditorUAOf`, `auditorState`, the events and errors | controller calls |
| O9 | One proposal at a time (`AuditorPending`) | kept, with no delegation on bit 32 and the two-use rule |
| O10 | The PQZ consent's purpose | coordinator ruling 2026-11-17 (controller call, owner may override): its own `PURPOSE_AUDITOR_CONSENT = keccak256("scaas.ua.purpose.auditor-consent.v1")` in `UAKinds`, through `requireAuthorized`, which takes any purpose: the registry and its closed portable list do not change; `PURPOSE_ZETHER_AUTH` is not reused |
| O12 | The confirm window: `AUDITOR_CONFIRM_WINDOW = 7 days`, independent of `D`; an expired proposal frees the slot; the holder cancels its own | coordinator ruling 2026-11-17 (controller call, owner may override), after the owner asked whether `max(noticePeriod(), grantDelay)` can wait forever: it cannot (both capped at 30 days), but a window sized by `noticePeriod` was empty at notice 0 |
| O13 | A wallet helper that picks the delay sentences (§4, O4) | **PLANNED in the scaas-sdk round** (owner 2026-11-18, closing review P3-5: no change in this round) |
| O11 | KV-11: the `AUDITOR` disclosure checks the caller's `keyVersion`; with the epoch on chain the contract could require `keyVersion == kv_a` | existing behaviour, not changed here (review I2) |

## 16. Review map (Fable, 2026-11-17)

| Finding | Where applied |
|---|---|
| A1 (P1) `AuditorIsAccount` is a veto for anyone on PQZ | §5.2 consent replaces it; T2, T3; O5 |
| A2 (P1) the PQZ reader in `ua-rs` | §6 readers, §9 readers' refusal, T11, §13 clients and mutants; plan A4, A7 |
| A3 (P2) delay 0 with a single key | §4 (`max`, owner), T1, T4; O1, O4 |
| A4 (P2) no fast undo; `disableFeature` after a hostile apply | §3, §5.3, T1; test "the way back"; ops note |
| A5 (P2) delegable leaves | §3 no delegation (`DelegableRefused(32)`), T6 |
| A6 (P2) the account check incomplete | removed with A1; the key-copy residual on `OFFCHAIN` in §5.2, T3 |
| A7 (P2) the holder ruling | §1 ruling 4, §3, §8 row, T1, §13; CTR-GOV-31 and the Changes reworded; `REGULATED_ROLES` untouched |
| A8 (P2) `PqzStorage.noticePeriod` is 0 on `PRECOMPILE` | §4; §13 test and mutant |
| A9 (P2) `pqz-core/ffi` and the gate | §10: no `ffi` change; plan Closing |
| A10 (P3) the step is not signed | `uint32 epoch` in both entries and structs (§5.1, §8) |
| A11 (P3) uses and the view | §5.1 two uses, §8 bit sentence, `auditorState()` dead after disable |
| A12 (P3) admin 0 | `init` refuses (`FeatureNeedsAdmin(32)`); the locked case in §3, T1, the bit sentence |
| A13 (P3) sizes | §12: Q 34.2–34.9 K, new rows and `_forms`, untouched contracts near their lines |
| A14 (P3) gas edges and red pins | §7, §14; plan A0, A2, A4 |
| A15 (P3) tests | §13 epochs and disclosure |
| I1 | §6, §13 (test first in A4) |
| I2 | O11 |
| I3 | T8 |
| I4 | §5.2 (`AuditorSame` on the canonical point), plan A0 |
