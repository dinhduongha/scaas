# `setAuditor`: replacing the auditor of a confidential token on bit 32 `AUDITOR` — design

**Status:** SPECIFIED, nothing built, **UNAUDITED**. Written 2026-11-17 on branch `prefreeze-contracts` at `f655cb0e`, from
the owner's rulings of 2026-11-17 (quoted in §1, not reopened) and the frame in
[`plans/2026-11-17-code-format.md`](../plans/2026-11-17-code-format.md) ("Bundled: `setAuditor` on one governance bit"). The
frame's items are **controller proposals**; each is tested here and decided with its reason (§3–§9). Every call the owner may
override is listed in §12. Plan: [`plans/2026-11-17-set-auditor.md`](../plans/2026-11-17-set-auditor.md).

Rules this spec defines (normative text in the component docs; entries in [`decisions.md`](../../decisions.md)):

| Id | Where | What |
|---|---|---|
| [CTR-GOV-31](../../decisions.md#CTR-GOV-31) | `decisions.md` (the governance rules live there) | bit 32 `AUDITOR`: kinds, holder, delay class, masks |
| [CTR-ZTH-95](../../contracts/zether.md#CTR-ZTH-95) | `contracts/zether.md` §14.1 | the Zether auditor key: setter, epochs, history, disclosure by the entry's key |
| [CTR-PQZ-43](../../contracts/pq-zero-knowledge.md#CTR-PQZ-43) | `contracts/pq-zero-knowledge.md` §9.7 | the PQZ auditor UA: setter, epochs, history, the three-key model, disclosure by the entry's auditor |

Changes to existing rules: CTR-ZTH-09 (no longer immutable when bit 32 is set at creation), CTR-ZTH-41 (the "no setter"
Change is replaced; threshold re-sharing stays the way to change parties without a new key), CTR-ZTH-43 (`ZetherDisclosure`
reads the entry's key), CTR-PQZ-24 (the auditor UA may change under bit 32), CTR-GOV-10 (bit 32 allocated, 33–127 free).
`auditorMode` (CTR-ZTH-49, CTR-PQZ-24) is unchanged and stays immutable.

Sources read: `GovernanceBits`, `GovernanceLib` (`init`, `_check`, `_due`, the masks), `OpenFactory.configureChain` and
`noticePeriod`, `ZetherLib` (`init`, `_auditorPoint`, `_noAuditorParty`, the record writers), `ZetherDisclosure`,
`ZetherStatements`, `PqzStateLib` (`init`, `setVerifier`, `setVerifierFee`, `setProofStore`), `PqzCore` (`PqzStorage`,
`_noAuditorParty`, `KeyReused`, `_legOf`), the kinds' cores and generated faces and modules (`script/modules/entries.json`),
`GovernanceRouter(Base)`, `test/v2/layout/namespaces.json`, `size-baseline.json`, `scripts/size_gate.py`,
`clients/zether-prover/src/state.rs`, `scaas-node/src/typed.rs`, `guard.rs`; rules CTR-GOV-01…30, CTR-ZTH-09, -38, -41, -42,
-43, -49, CTR-PQZ-14, -24, -31, -34, -37, -40, CTR-UA-43, ARCH-POS-13, CTR-AS-19.

Figures: **[baseline]** is `size-baseline.json` at `f655cb0e` (a ratchet: each row is the most the contract may reach, not
its measured size); **[estimate]** is arithmetic over it and over the per-stub cost the burner / wrap-caps spec measured
(about 165 B per face stub). Nothing here was measured; plan task A0 measures.

## 1. Rulings (owner, 2026-11-17, verbatim)

1. First, on "no setter now; threshold re-sharing; PQZ key versions": **"Ok, theo đề xuất"** (OK, as proposed). Recorded as
   CTR-ZTH-41's Change of 2026-11-17 (no setter, CTR-ZTH-09 holds).
2. Then, replacing it: **"Do format phải chạy lại rất nhiều, tiện thể làm luôn '- setAuditor', dùng 1 bit cho việc này. Gom
   chung vào format code, để chạy gate .v.v. 1 lần"** (since formatting forces a long re-run anyway, build `setAuditor` now,
   on one bit, and bundle it with the formatting so the gates run once).
3. Then: **"Làm luôn"** (do it now).

What is the owner's: the setter exists, it is one governance bit, it is built in the formatting round with one gate run.
Everything else below is a controller call.

## 2. Goal and scope

**Goal.** A token created with bit 32 `AUDITOR` lets a holder of that bit replace who can read the auditor copies of its
**later** transfers: the Zether auditor key `Y_a`, or the PQZ auditor UA. Earlier transfers stay readable by the key of their
time only, and every disclosure of an old transfer checks against that key.

**In scope.** EVM: the Zether kinds 2, 3 and their regulated twins 10, 11; the PQZ kinds 4, 5 and their twins 12, 13; the
governance bit and masks; the direct entries, the router ops, the views, events and errors; the per-entry auditor epoch and
the key history; `ZetherDisclosure` and the PQZ disclosure; the node rows; the `ua-rs` and clientkeys builders; the vectors
(`governance_bits.json`, `typed_ops.json`, `namespaces.json`, the selector audit); the provers' readers.

**Out of scope.** `auditorMode` (stays immutable). No relation, statement, transcript or `proofSystemId` changes: the
transfer statement already takes `Y_a` / `pk_a` from the token at execution. No other family in this round: no non-EVM token
carries governance bits for its confidential kinds today; the same bit comes in each family's next round (one rule on every
chain, as CTR-GOV-29 / CTR-GOV-30 state for their bits). Changing the auditing parties **without** a new key stays possible
off chain by re-sharing the threshold key (CTR-ZTH-41); the setter is for a new key.

## 3. The bit: 32 `AUDITOR` (CTR-GOV-31)

**Number.** 32 is the next free bit: `governance_bits.json` allocates 0–31 (13 and 14 never reused, CTR-GOV-14) and says
"Bits 32-127 are free"; 32 is in SCaaS's band 0–127 (CTR-GOV-10). Tested: no constant in `GovernanceBits` holds 32.

**Type.** A power (it has holders), not scalar, no scope. Set **only at creation** (not in `ENABLEABLE`), lockable at creation
like every bit, disabled one-way at once by the admin (`disableFeature(32, chainUid_)`), which freezes the auditor at its
current value for good, the way `disableFeature(24)` freezes `proofStore` (CTR-GOV-22). A token created without bit 32
keeps CTR-ZTH-09's immutability, so creators who want "never changes" leave it off; a wallet reads it from `features()`.

**Kinds.** In `_validBits()` and `_roleBits()` of the kinds 2, 3, 4, 5, 10, 11, 12, 13 only. Every other kind (0, 1, 8, 9)
and `SCaaSDex` refuse it with `FeatureInvalidForKind(32)` at `init` and `NoSuchRole(32)` at a grant, by their masks, with no
code of their own. Tested both ways per kind.

**Auditor mode.** On a token whose `auditorMode` is NONE, `init` refuses bit 32 (`BadAuditorMode(0)`, in the confidential
init after `GovernanceLib.init`, which has written `features`): a NONE token never gains an auditor, and a wallet never shows
a power that cannot act. FULL and OPTIONAL keep a key at every moment (the setter never writes an empty key).

**Holder.** **A contract or a threshold (`msig`) UA**, never a single key: bit 32 joins `_contractOnlyBits()` of the eight
kinds and the msig set `GovernanceBits.REGULATED_ROLES` (the mask `_check` reads for an msig holder; its name stays, its
NatSpec names bit 32). Reason: the power reads every later amount; the frame names "an `msig` holder" as part of the guard;
the same class as FREEZE / FORCE / PAUSE / RECORD (RK-1). Not in `ISSUER_BITS`, no `Roles` seat: the admin grants it after
creation (`grantRole(32, holder, chainUid_)`, two calls under `grantDelay`, CTR-GOV-04), so the first holder is also
announced (`GrantProposed`).

**Revoke.** **Never delay-relaxed**: bit 32 is not in `_delayedRelaxBits()` (the regulated mask is `ISSUER_BITS` minus 23
and 24, which bit 32 is not in, so nothing changes there; pinned by a test). `revokeRole(32, …)`, `renounceRole(32, …)`,
`disableFeature(32, …)` act at once, so the admin stops a hostile or compromised holder at once, and the stop kills its live
proposal (§5.3). Same reason as `TAX` (CTR-GOV-21): a power that harms holders must be stoppable at once.

## 4. Which delay (tested against today's mechanics)

Two delays exist today:

| Delay | Set by | Range | What it delays today |
|---|---|---|---|
| `grantDelay` (CTR-GOV-04) | the token's creator, in `TokenConfig`, immutable | 0 to 30 days, 0 allowed on any chain | the admin's grants and widenings, the relaxations of 5, 6, 7, 28 (CTR-GOV-09), the cap changes of bit 31 (CTR-GOV-30) |
| the factory's `noticePeriod()` | the chain, once, at `OpenFactory.configureChain` (no writer after) | 0 to 30 days (`MAX_NOTICE_PERIOD`) | a release's use after its deploy, a `TAX` rate increase (CTR-AS-19), a wrap-side relaxation or unwrap-side tightening (`setWrapLimits`), the PQZ verifier transfer and verifier fee increase (CTR-PQZ-28, CTR-PQZ-36) |

**Decision: the factory's `noticePeriod()`.** `grantDelay` delays who holds a power; `noticePeriod` delays a change a holder
must see before it binds its later operations. A new auditor is the second kind, and its closest precedent, replacing the
party behind a PQZ token's verifier key (CTR-PQZ-28), already waits `noticePeriod`. `grantDelay` is the creator's choice and
may be 0 on a production chain; `noticePeriod` is the chain's and the token's creator cannot shorten it. Read live from
`IOpenFactory(FACTORY).noticePeriod()` at the proposal (every token has the `FACTORY` immutable; the value never changes after
`configureChain`, so reading it again at the confirm gives the same number; no new field). Open point O1 asks the owner
whether the longer of the two should apply instead.

**Mechanics: two calls, the PQZ verifier pattern.** The holder proposes; the same holder confirms with the same value within
`[eta, eta + noticePeriod]`, `eta = now + noticePeriod`. With `noticePeriod = 0` the first call applies at once (both events in
one transaction). Why two calls and not "apply at `eta` by itself" (the `TAX` fold-in): a fold-in puts a pending check on every
transfer, the hottest path; two calls put nothing there. Why a window: a proposal nobody confirms dies, so an old proposal
never lands by surprise. The generic `GovernanceLib._due` is not reused: it is private, keyed to `grantDelay`, and tied to
the admin generation, while this proposer is a holder.

## 5. Design

### 5.1 State machine (both families)

`setAuditorKey(next, chainUid_)` (Zether) / `setAuditorUA(next, chainUid_)` (PQZ), caller `c`:

1. `_holderOnChain(32, chainUid_)` (CTR-GOV-28: a caller without the bit `MissingRole(32, c)` first, then the holder's word
   `ChainUidMismatch`), then `use(32, c, 0)` (the grant's checks: `validUntil`, `maxUses`, the leaf's epoch; every call is one
   use). Bit 32 off or disabled: `FeatureNotSet(32)`.
2. A **live** pending `P` (proposed, `now ≤ P.eta + noticePeriod`, and `P.proposerRoleEpoch == epoch[32][P.proposer]`, so a
   revoke or renounce of the proposer, which bumps its role epoch, kills it for good):
   - `next == P.next`: `c == P.proposer` (else `NotProposer(32, 0, P.proposer)`), `now ≥ P.eta` (else
     `AuditorNotReady(P.eta)`), the checks of §5.2 again, then **apply** (§5.4).
   - `next ==` the current auditor: `c == P.proposer` (else `NotProposer`), then cancel (`AuditorProposalCancelled(epoch + 1)`).
   - any other value: `AuditorPending()` (one proposal at a time; the admin's revoke ends a stuck one).
3. No live pending: `next ==` the current auditor `AuditorSame()`; else the checks of §5.2, then propose: store `P`
   (`next` or its hash, `eta`, `c`, `epoch[32][c]`) and emit `AuditorKeyProposed` / `AuditorUAProposed`; with
   `noticePeriod = 0` apply at once.

### 5.2 Checks on the new auditor (at the proposal and again at the apply)

- **Zether:** `next` is `p` bytes (the curve's G1 encoding), `isValidPoint`, not `O` (`AuditorKeyInvalid()`), the same check
  as `init` makes on `auditorKey`.
- **PQZ:** the checks a transfer with the auditor on makes on the auditor (`PqzCore._keyPtrV`: a registered key of the token's
  class and scope, CTR-PQZ-37; on an opening token also the opening KEM key in that scoped record, CTR-UA-43); refusals are
  theirs (`AccountNotRegistered(next)` and the key errors). Unlike `init`, this runs on an `offchain-token` too: the token
  exists, so the new auditor must have registered its key for it first.
- **Both: not an account of this token** (`AuditorIsAccount(ua)`; Zether `ua = toUA(next)`, PQZ `ua = next`): the UA has no
  state on this token (Zether `acct[ua]` never written; PQZ `sendCounter[ua] == 0` and no state at its current key version).
  Reason: today's per-transfer guards (`AuditorKeyAsParty`, Zether; `AuditorAsParty` and `KeyReused`, PQZ F-4) refuse a
  transfer from or to the auditor, so naming a holder's key would stop that holder's confidential transfers (it keeps
  `mtxUnshield`) and hand it every later amount. Those guards stay and keep the cryptographic reason (F-4); the new check
  keeps the setter from being a targeted freeze.

Checking again at the apply matters: between the proposal and the apply the new auditor may have received a credit or
dropped its key, and a FULL token with an unusable auditor refuses every transfer.

### 5.3 Who can stop a proposal

The proposer (cancel by proposing the current auditor), and the admin at once: `revokeRole(32, proposer)` (kills it by the
role epoch) or `disableFeature(32)` (no call passes `use(32)` again). The window ends it by itself.

### 5.4 Apply

Epoch `e = auditorEpoch`. Zether: `auditorKeys[e] = auditorKey` (the outgoing key enters the history), `auditorKey = next`;
PQZ: `auditorUAs[e] = auditorUA`, `auditorUA = next`. Then `auditorEpoch = e + 1`, the pending is deleted, and
`AuditorKeySet(e + 1, previous, next)` / `AuditorUASet(e + 1, previous, next)`. The current key stays in its old slot, so a
transfer reads what it reads today; the history map is written only here.

### 5.5 Per kind

| Kinds | Auditor | Entry | Views | Body (module) / logic (library) |
|---|---|---|---|---|
| 2, 3, 10, 11 (Zether) | `auditorKey` (`bytes`, `Y_a`) | `setAuditorKey(bytes newKey, bytes32 chainUid_)` | `auditorKeyOf(bytes32 entryRef)`, `auditorState()` | the Zether module (Z of each kind); `ZetherLib` (external, DELEGATECALL) |
| 4, 5, 12, 13 (PQZ) | `auditorUA` (`bytes32`, a `pqz-mlwe` UA) | `setAuditorUA(bytes32 newAuditor, bytes32 chainUid_)` | `auditorUAOf(bytes32 entryRef)`, `auditorState()` | the PQZ setters module (S on 5, 12, 13; Q on 4, which has no S: O2); `PqzStateLib` |

The regulated twins take the same entries from their base layer: nothing regulated-specific beyond the masks
(`RegulatedBase._contractOnlyBits()` adds 32 next to 5, 6, 7, 10, 21). `PAUSE` does not stop the setter (it stops value
movements, not governance). Two entries, not one: the Zether auditor is a key (`bytes`, a crypto object), the PQZ auditor is a
UA (`bytes32`); one `bytes` parameter holding either would be a packed field (explicit parameters rule).

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
slot 0 by hand (`clients/zether-prover/src/state.rs` `modes`) take the new bytes.

**Name.** `auditorEpoch`, not "auditor key version": on PQZ "key version" is the UA's own PQZ key version (CTR-PQZ-31, the
op blob's `kv` tail), a different counter; the epoch counts replacements of the token's auditor, like `pqzVerifierEpoch`.

## 7. Recording the epoch per operation

A transfer **with the auditor on** (Zether: `Y_a ≠ O` in the statement; PQZ: `auditorOn = 1`), single or multi-recipient, on a
token whose `auditorEpoch ≠ 0`, writes `entryAuditorEpoch[entryRef] = auditorEpoch` next to its record. Nothing else writes it.
Absent reads as 0, which is right: an entry made at epoch 0 needs no row. So a token at epoch 0 pays nothing, and after the
first replacement each audited transfer pays one new slot ([estimate] about 5 k regular gas and 97,920 state gas under
EIP-8037; the regular part counts against the EIP-7825 cap the Zether prover's `gas_limits` table guards, so the edge cells
are re-measured at epoch ≠ 0 in the round's re-pin). Burns, unshields, refreshes, rollovers and shields carry no auditor copy
and write nothing.

On PQZ the op blob tail already records the auditor's **key version** (`kv(8·n)`, CTR-PQZ-34); with the epoch the full identity
of an old entry's auditor key is `(auditorUAOf(entryRef), kv_a)`. On Zether the record `R` carries no auditor key, so the
epoch row is the only link. Rejected: appending the epoch to `R` or the op blob (moves the record formats every client and the
disclosure parse by length, for every transfer, epoch 0 included); one row per transfer always (state gas on every token).

## 8. Entries, views, events, errors

**Direct entries** (the holder; native contract holders call them directly): `setAuditorKey(bytes newKey, bytes32 chainUid_)`
on 2, 3, 10, 11; `setAuditorUA(bytes32 newAuditor, bytes32 chainUid_)` on 4, 5, 12, 13. Each carries the chain word as every
holder entry does (CTR-GOV-28's Change). They are governance entries, not token meta-tx ops: the tokens' allow-lists
(`mtxSelectors`, `_uaAllowed`, `_mtxRule`) are unchanged, as for `setProofStore`; the selector audit
(`test/vectors/selector_audit.json`) classifies the two entries as `setProofStore`'s class.

**Router ops** (an `msig` holder signs through the chain's `GovernanceRouter`; fee mode `NONE`, relayable at fee 0):

| Op | Typed struct |
|---|---|
| `mtxSetAuditorKey(UAEnvelope e, address target, bytes newKey, bytes32 chainUid, UASig auth)` | `UASetAuditorKey(bytes32 from,address target,bytes newKey,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)` |
| `mtxSetAuditorUA(UAEnvelope e, address target, bytes32 newAuditor, bytes32 chainUid, UASig auth)` | `UASetAuditorUA(bytes32 from,address target,bytes32 newAuditor,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)` |

`bytes newKey` is hashed into the struct as EIP-712 says (`keccak256(newKey)`). The typehashes are computed and pinned by the
build (`GovRouterTypehash.t.sol`, `vectors/typed/typed_ops.json`); the router's closed table gains two rows.

**Views.** `auditorKey()` / `auditorUA()` keep returning the current auditor. New:
- `auditorKeyOf(bytes32 entryRef) returns (bytes)` (Zether) / `auditorUAOf(bytes32 entryRef) returns (bytes32)` (PQZ): the
  auditor of the entry's epoch (`entryAuditorEpoch[entryRef]`; the current one when that epoch is the current one). For an
  unknown `entryRef` it answers epoch 0's; callers check the entry exists (the disclosures do: `UnknownEntry`).
- `auditorState() returns (uint32 epoch, bytes32 pending, uint64 eta, bytes32 proposer)`: the current epoch and a live
  proposal (Zether `pending` = the proposed key's hash, the key itself is in the event; PQZ `pending` = the proposed UA); a dead
  proposal reads as zeros.

**Events.** `AuditorKeyProposed(uint32 epoch, bytes newKey, bytes32 proposer, uint64 eta)`, `AuditorKeySet(uint32 epoch, bytes
previousKey, bytes newKey)` (Zether); `AuditorUAProposed(uint32 epoch, bytes32 newAuditor, bytes32 proposer, uint64 eta)`,
`AuditorUASet(uint32 epoch, bytes32 previousAuditor, bytes32 newAuditor)` (PQZ); `AuditorProposalCancelled(uint32 epoch)` (both).
`epoch` is the epoch the new auditor takes.

**Errors.** `AuditorNotReady(uint64 eta)`, `AuditorPending()`, `AuditorSame()`, `AuditorIsAccount(bytes32 ua)` (both families),
`AuditorKeyInvalid()` (Zether); reused: `MissingRole`, `FeatureNotSet(32)`, `NotProposer`, `IAdmin.ChainUidMismatch`,
`FeatureInvalidForKind(32)`, `NoSuchRole(32)`, `RoleNotContract(32, …)`, `BadAuditorMode(0)`, the PQZ key errors. Names are
controller calls (O8).

**Node verdicts** ([submit-lanes](../../node/submit-lanes.md)): on the two router ops `AuditorNotReady` is `queued` (it passes
once `eta` is reached, as `GrantNotReady(31)` on the cap setters); every other refusal is `dead`. A transfer proven against
the outgoing auditor and mined after the apply fails its statement check, as after a PQZ key rotation today: `dead`, the
wallet proves again; the proposal event gives wallets `noticePeriod` to drain such builds (operator note in
[ops.md](../../node/ops.md)).

**Bit vector row** (`governance_bits.json`, written by `GovBitsVector.t.sol` with `WRITE_BITS=true`, never by hand; named
here, edited by plan task A1): `{"bit": 32, "name": "AUDITOR", "type": "power", "kinds": [2, 3, 4, 5, 10, 11, 12, 13],
"holder": "contractOrMsig", "sentences": {"all": "A holder can replace this token's auditor: the new auditor reads every
later transfer that includes the auditor, never an earlier one. Each replacement is announced on chain and applies only after
the factory's notice period {noticePeriod} (0: at once), confirmed by the same holder; the admin can stop it at once by
revoking the holder. A token without an auditor never gains one. The holder is a contract or a threshold (msig) UA."}}`; the
note's "Bits 32-127 are free" becomes "Bits 33-127 are free"; `sentences.msig` names bit 32 with 5, 6, 7, 10, 21.

## 9. Disclosure across epochs

**Zether** ([CTR-ZTH-43](../../contracts/zether.md#CTR-ZTH-43)). `ZetherDisclosure.verifyTransferAmount(…, AUDITOR, …)` reads
`auditorKeyOf(entryRef)` instead of `auditorKey()`; empty (NONE) or `C_aud_j = O` stays `false`. `K = Y_a(epoch)` is absorbed
into the strong Fiat–Shamir challenge (`G ‖ K ‖ B ‖ M`, CTR-ZTH-40), so an opening made with one epoch's key never verifies
against another's. No transcript change, no new tag: the statement points are the same bytes as before for every epoch-0
entry. `ZetherDisclosure` is stateless and shared, so it is a new deployment (new code, new address), carried by each Zether
release's `disclosure()` immutable; nothing deployed is upgraded. The prover follows: `openDisclosure` and the sender's
`recoverTransfer` (which rebuilds `C_aud_j = [v_j]G + [t_j]Y_a` from the memo and must use the entry's `Y_a`) read
`entryAuditorEpoch[entryRef]` and the key of that epoch from state (slots 16, 17, or slot 5 for the current epoch); the
auditor's own reader picks the key per entry the same way.

**PQZ** ([CTR-PQZ-14](../../contracts/pq-zero-knowledge.md#CTR-PQZ-14)). On a token without the opening (class `registry`,
and `offchain-token` without the opening), the `AUDITOR` kind checks against the auditor of the entry's epoch:
`_legOf`'s owner becomes `auditorUAOf(entryRef)` instead of `auditorUA`; `keyVersion` stays the caller's (KV-11), and the op
blob's `kv` tail says which version that auditor used. On an opening token the only disclosure kind is `SENDER_S` (CTR-PQZ-14's
Change), whose statement names no auditor, so nothing changes there; each auditor's opening `O_a` stays sealed to the opening
KEM key of the auditor of its epoch. The sender's recovery rebuilds `v_a` with `pk_a` of `(auditorUAOf(entryRef), kv_a)`.

## 10. The three-key model (CTR-PQZ-37) and ARCH-POS-13

- **Key class and scope.** The new auditor needs a key of the token's class and scope before the proposal and at the apply
  (§5.2): the registry key on a `PRECOMPILE` token, the shared second key on `offchain-shared`, its key of that token on
  `offchain-token`; and on every opening token the opening KEM key in that scoped record (CTR-UA-43), so `O_a` of every later
  transfer is sealed to the new auditor.
- **No retroactive reading either way.** Earlier `O_a` and `v_a` stay under the outgoing auditor's keys; the new auditor reads
  from its epoch on. The outgoing auditor keeps what it could read (a disclosure is irrevocable, CTR-ZTH-43).
- **`offchain-token` without the opening.** CTR-PQZ-37 states that the token's auditor "once named, has no such choice" about
  its key of that token being exposed to a dishonest verifier. A replacement auditor does choose: §5.2 requires it to have
  registered its key for the token before it can be named.
- **ARCH-POS-13 (never a decryption oracle).** The setter decrypts nothing, and nothing in it reacts to a ciphertext anyone
  chose: it reads a key or a UA and account flags. No client or tool gains a decryption step: the auditor's readers pick a key
  per entry and decrypt only what was encrypted to their own key, as today.

## 11. Threat model

| # | Threat | Guard | Residual (stated, not closed) |
|---|---|---|---|
| T1 | **A bit holder redirects the readability of every later amount** to a key it controls | a contract or `msig` holder only; granted by the admin under `grantDelay` with `GrantProposed`; every replacement proposed in public (`AuditorKeyProposed` / `AuditorUAProposed`) and applied only after `noticePeriod`, by the same holder, inside a window; the admin's immediate revoke and `disableFeature(32)`; a creator who wants none leaves bit 32 off (or the holder sets it off later); under OPTIONAL a sender may leave the auditor out per transfer (CTR-ZTH-42, publicly visible) | after the notice the new key reads every later audited transfer; a holder who does not leave in time accepts it, and received amounts are the sender's choice. An admin that colludes with a holder needs `grantDelay + noticePeriod`, nothing more. **On a chain whose `noticePeriod` is 0 there is no notice at all** (O4). The contract cannot tell an honest replacement from a hostile one |
| T2 | auditor blinding: a key with no known secret (hash-to-curve) | public event, same guards as T1 | the auditor function ends silently for later transfers; transfers still go (the prover needs no `x_a`). A regulator's concern, not the holders' |
| T3 | a targeted freeze by naming a holder's key or UA as auditor | `AuditorIsAccount` at the proposal and the apply | a UA that becomes the auditor cannot later be a party of this token (today's guards); it is not a holder at that moment by construction |
| T4 | transfers proven against the outgoing auditor fail after the apply | the proposal event and `noticePeriod` | liveness only: `dead`, prove again |
| T5 | an old proposal applied by surprise | the window `[eta, eta + noticePeriod]` | none |
| T6 | a revoked holder's proposal survives a re-grant | the proposer's role epoch is stored and checked | none |
| T7 | an old entry disclosed against the wrong key | `entryAuditorEpoch` and the key history; `K` in the challenge | an unknown `entryRef` answers epoch 0's key from the view; the disclosure refuses the ref first |
| T8 | a FULL token left with an unusable auditor (every transfer reverts) | §5.2 again at the apply | the auditor itself may later drop or rotate its PQZ key, as today |
| T9 | sibling replay of a holder's direct call | the chain word (CTR-GOV-28); the router's domain | as CTR-GOV-28 |
| T10 | a new auditor under FULL cannot rebuild balances by bookkeeping (CTR-PQZ-24) | none in the contract | it reads only its epochs; a hand-over of earlier records is off chain |

## 12. Sizes

Lines (`size_gate.py`): release T-2 33,594 / T-1 35,386; module 33,780 / 35,570; library 33,903 / 35,694; plain 33,516 /
35,286. The baseline is a ratchet: every row the build grows moves in `size-baseline.json` with old → new figures and this
spec as the reason. The round's `bytecode_hash = "none"` takes about 40 B off every contract (the code-format plan's figure).

| Contract | [baseline] | Change [estimate] | Note |
|---|---|---|---|
| faces of 2, 3, 10, 11 (`NormalZetherToken`, `WrappedZetherToken`, `NormalZetherRegulatedToken`, `WrappedZetherRegulatedToken`) | 17,480; 23,721; 21,419; 27,929 | +0.5 KB each (3 stubs, about 165 B each) | `gen_faces.py` from `entries.json` |
| faces of 4, 5, 12, 13 | 19,965; 27,130; 24,056; **31,530** (`WrappedPqzRegulatedToken`) | +0.5 KB each | the largest face to about 32.0 K, under T-2 33,594 |
| Zether modules Z of 2, 3, 10, 11 | 2 and 10 under 24,576 (no row); 28,621; 29,292 | +300 to +500 B | thin bodies into `ZetherLib` |
| PQZ module S of 5, 12, 13 | under 24,576 (no row) | +300 to +500 B | |
| **`NormalPqzTokenQ`** (kind 4 has no S) | **33,384** | +300 to +500 B setter and views, +100 to +200 B `_legOf` | **about 33.8 to 34.1 K: at or over the T-2 notice line 33,780, under T-1 35,570** (O2) |
| PQZ modules Q of 5, 12, 13 (`_legOf` by epoch) | 29,956; 24,990; 31,107 | +100 to +200 B | |
| `ZetherLib` | 27,341 | +1.5 to +2.5 KB | the setter, the checks, the history, the per-entry write, the views; to about 29.8 K at most |
| `PqzStateLib` | under 24,576 (no row) | +1.5 to +2.5 KB | the setter and the checks; at most about 27 K |
| `PqzTransferLib` and the op 1 body (per-entry write) | 26,321 | +100 to +200 B | |
| `GovernanceRouter` | 26,399 | +250 to +400 B (two rows, as the wrap-caps spec measured) | |
| `GovernanceLib` | 15,737 | about 0 B | one mask constant |
| `ZetherDisclosure` | no row | tens of B | one view name |

No contract is projected over its T-1 line. The one notice is `NormalPqzTokenQ`. **No module split is made by the build**
(owner rule: only `NormalPqzRegulatedTokenQ` may be split automatically); if A0's measurement projects any contract over T-1,
the build stops and reports (O2).

## 13. Tests and mutants

Tests first, per task (plan). Every refusal test has a positive control (the right holder, word and value pass) and changes
one thing.

- **Bits and masks** (`test/governance/GovAuditorBit.t.sol`): bit 32 accepted on 2, 3, 4, 5, 10, 11, 12, 13, refused on 0, 1,
  8, 9 and the DEX (`FeatureInvalidForKind(32)`, `NoSuchRole(32)`); `init` refuses it on a NONE token (`BadAuditorMode(0)`);
  a native EOA and a single-key UA refused as holder (`RoleNotContract(32, …)`), a contract and an `msig` UA accepted; `revokeRole`,
  `renounceRole`, `disableFeature` act at once (one call with `grantDelay ≠ 0`); bit 32 not in `ENABLEABLE`.
- **Setter, both families** (`test/zether/ZetherAuditor.t.sol`, `test/pqz/PqzAuditor.t.sol`, the regulated kinds in
  `test/as/confidential/AuditorKinds.t.sol`): propose → `AuditorNotReady` before `eta` → apply at `eta`; window passed: dead,
  a new call proposes; `noticePeriod = 0`: one call; `noticePeriod` and `grantDelay` set to different values, only the first
  counts; another holder cannot confirm (`NotProposer`); a revoked proposer's pending is dead after a re-grant; cancel by
  proposing the current; `AuditorPending`, `AuditorSame`, `AuditorKeyInvalid` (wrong length, off curve, `O`); `AuditorIsAccount`
  for a sender, for a credited-only UA, at the proposal and at the apply; PQZ: an unregistered auditor, an `offchain-token`
  auditor without its token key, an opening token's auditor without an opening KEM key; a sibling chain word refused with
  nothing written; a stranger `MissingRole` first.
- **Epochs and disclosure**: an audited transfer at epoch 0 writes no row (`vm.load` of `entryAuditorEpoch` and the slot count:
  +0 slots); at epoch 1 it writes 1; an opt-out transfer writes none; `ZetherDisclosure` opens an epoch-0 entry with the old
  key after the replacement and refuses it with the new key, and the reverse for an epoch-1 entry, single and multi-recipient;
  the PQZ `AUDITOR` disclosure the same on a `PRECOMPILE` token at the four sets; an opening token's `SENDER_S` unchanged.
- **Layout and pins**: every old row of `namespaces.json` unchanged, the new rows pinned; the router typehashes; the selector
  audit; the bit vector; `typed_ops.json` rows; the "+0" pins on the plain kinds unchanged (`PlusZero.t.sol`).
- **Clients**: clientkeys and `ua-rs` build the two router ops to the vector bytes; every `ua-*` reads bit 32's row; the Zether
  prover recovers and opens an epoch-1 entry with the epoch-1 key (an epoch-0 key must fail: the negative control).
- **Node**: the two `typed.rs` rows, the `guard.rs` counts, the verdicts of §8.

**Mutants** (one per check; each must be killed by a named test; `runs/<date>-set-auditor/`): drop `use(32)`; drop the chain
word; allow a confirm before `eta`; drop the window's end; drop the proposer check; drop the role-epoch tie; read `grantDelay`
instead of `noticePeriod`; skip the per-entry write; write it at epoch 0; write it on an opt-out; disclosure reads the current
key; the apply overwrites the history; skip the key check at the apply; skip `AuditorIsAccount`; accept bit 32 on NONE; put 32
into `_delayedRelaxBits()`; drop 32 from `_contractOnlyBits()`; place `auditorEpoch` so that it moves a pinned field; the
prover's recovery uses the current key.

## 14. Interaction with the bundled round

The order (plan): PqVault Part R (R1–R4) → this round's tasks A0–A10 → F2 `forge fmt` with `bytecode_hash = "none"` → one
compile and one re-pin of every code hash (the factory catalogue, `LinkClosure`, the `*_CODEHASH` constants, `size-baseline.json`)
and of every gas pin (old → new in the commit) → **one full gate** (every forge directory at `n2304-kmax4096`, the four PQZ
sets by `script/pqz/at-set.sh`, the node with e2e, every client) → **one SCaaS testnet reset** with deploy, Blockscout verify
and the matrix (new `setAuditor` matrix rows: propose, apply after the testnet's notice, an audited transfer, an `AUDITOR`
disclosure at both epochs). The build's own commits are not formatted by hand; F2 formats them with everything else, so this
round must land before F2 and its diff is kept clean of style-only edits. Every chain is test-only: no migration; every
confidential kind gets a new release in the catalogue at the reset, as every code hash moves anyway.

## 15. Open points (recommendations; the owner may override every one)

| # | Point | Recommendation |
|---|---|---|
| **O1** | **Which delay.** The factory's `noticePeriod()` (§4), the token's `grantDelay`, or the longer of the two | **`noticePeriod()`**: the holder-notice class, the PQZ verifier's precedent, and the creator cannot set it to 0. The longer of the two adds a read and a rule for little: `grantDelay` already delays the grant of the bit |
| **O2** | **`NormalPqzTokenQ`** ([baseline] 33,384) would pass the T-2 notice line (33,780) at about 33.8–34.1 K, under T-1 (35,570) | **keep kind 4's setter and views in Q** if A0's measurement confirms T-1 holds (a notice is not an error); a new S module for kind 4, like 5, 12, 13 have, is a module split and the owner's call. The build stops if any contract is projected over T-1 |
| O3 | Holder class | contract or `msig` (§3); "any holder" would let a single key redirect every later amount |
| **O4** | **`noticePeriod = 0`** gives holders no notice of a new auditor | the owner's chain setting: a production chain's `configureChain` should set it above 0; wallets print the 0 case ("at once") from the bit sentence |
| O5 | `AuditorIsAccount` (§5.2) | keep: one read, closes T3 |
| O6 | The same account check at `init` | not added: the creation-time auditor is public before anyone holds the token; adding it could break existing deploy scripts that reuse a registered key |
| O7 | Hand-over to a new FULL auditor | off chain only (T10); no contract support |
| O8 | Names: `AUDITOR`, `setAuditorKey`, `setAuditorUA`, `auditorEpoch`, `auditorKeyOf`, `auditorUAOf`, `auditorState`, the events and errors | as written (controller calls) |
| O9 | One proposal at a time (`AuditorPending`) rather than "a new value replaces" | keep: a replacement would restart the clock without a cancel event; the admin's revoke ends a stuck proposal |
