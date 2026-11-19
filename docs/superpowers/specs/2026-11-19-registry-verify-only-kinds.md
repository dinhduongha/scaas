# Spec: a registry generation 2 that verifies generation-1 kinds ("verify-only kinds")

2026-11-19. **Revision 2**: every finding of the Fable review of revision 1 (Fable, high effort, P0 0 / P1 2 / P2 7 / P3 8,
F1 – F17, verdict "build after fixes"; review file in the private scratchpad, not in the repo) applied, and the owner's rulings
of 2026-11-19 on it recorded in §0. Status: **SPECIFIED**, nothing built. Everything cryptographic stays **UNAUDITED**. Scope:
**EVM** (the contracts, the factory, the deploy, the node, the SDK and clients); the other families take the principle in
their own rounds (§12, PLANNED).

Rule ids `CTR-UA-58` … `CTR-UA-70` are **placeholders**: the highest id defined is `CTR-UA-46`, and
`2026-11-19-bls12381-multi.md` holds `CTR-UA-47` … `CTR-UA-57` (placeholders too); landing assigns the real ones, writes the
[decisions.md](../../decisions.md) entry with §0 verbatim and moves the rules into [accounts.md](../../contracts/accounts.md).
Rows marked **owner** are the owner's ruling; **follows** applies a stated rule; **proposal** is the author's and is listed in
§16 for the owner. Despite the title, the design covers every later generation (§11): "gen 2" below reads "a later
generation", "gen 1" "the generation that holds the record", unless a section says otherwise.

## 0. Owner rulings this spec implements

### 0.1 Option (b) (2026-11-19, revision 1)

The question: Ethereum has no PQ precompile today (EIP-8051, 8052 and 8355 are drafts). If one is accepted later, how does
SCaaS use it? Today a verifier's path is fixed at deploy by a probe, the verifier is immutable, and a generation 2 may enable
only kinds whose kind **and** keyHash group gen 1 does not enable ([accounts.md §1.8](../../contracts/accounts.md#registry)
"Generations", T-REG-4). So a gen-1 UA of a PQ kind could never use a later precompile; only a new kind version (a new UA
id, re-registration, assets moved) would.

The owner chose option **(b)**: "Do option b, write the spec, then a Fable review." Option (b): **a gen-2 registry may
re-enable a kind that gen 1 enables, for verification only**, with its own (new) verifier, e.g. one that calls a precompile
that did not exist when gen 1 was deployed. Registration, the record, the key pointer, the keyHash group and every key write
stay with gen 1 (no second record, no second owner of the group, no re-registration: the UA id is unchanged). Token
implementations released later (factory catalogue) that point to gen 2 verify gen-1 UAs of that kind through gen 2's
verifier; existing tokens keep gen 1. No admin key, no mutable verifier table: gen 2 is a new immutable deployment, and each
token release chooses its registry.

### 0.2 Rulings on the review (owner 2026-11-19)

The owner on the review's positions and the spec's proposals: **"approved all as proposed"**; on the probe of Draft
addresses: **"the middle way, as proposed"**; on "only two generations" against "N generations": **"Choose b, put it in
revision 2"**; on the depth cap: **"Accept 16 generations"**.

| # | Topic | Ruling | Where |
|---|---|---|---|
| V1 | Verify-only kinds | a later generation may carry a kind a predecessor enables as verify-only, with its own verifier | **owner** (b); §2 |
| V2 | Writes | registration, record, key pointer, keyHash group, every key write stay with the generation that holds them | **owner** (b); §3 |
| V3 | Who uses it | releases that bind the later generation; existing tokens keep theirs | **owner** (b); §10 |
| V4 | Mutability | none: a new immutable deployment, no admin, no table | **owner** (b); [CTR-UA-15](../../contracts/accounts.md#CTR-UA-15) |
| R1 (Q11, F1) | How a release binds gen 2 | relax "one registry per factory": the factory's env checks accept the router's registry **or** a registry whose `predecessor()` is the router's registry, same `chainUid`, `generation() == 2`, checked in code, no admin key; the statement of [admin-not-owner §13.4](2026-11-10-admin-not-owner.md) changes on landing (§15). Generalised by R10 to a bounded walk of the predecessor chain | **owner**; §10 |
| R2 (F2) | Who authenticates writes | one rule: **every write is authenticated by the generation that holds the record**: a gen-1 record's `setPqzKey` / `setPqzScopedKey` and any other write go to gen 1; a gen-1 `msig` holder's derived members `via(_pred())`; §13 corrected | **owner**; §3, §4 |
| R3 (F5) | Key form | an explicit key-form bit per verify-only kind, checked in the constructor; only key forms the verifier can **derive per call** within its gas cap are allowed; no cache in gen 2 ("gen 2 writes nothing"); a form that cannot be derived per call makes the kind ineligible; the deploy refuses the impossible combination by name | **owner**; §2, §6 |
| R4 (Q10, F6) | Fallback | when gen 2's verifier gives **no answer** (no code at the precompile, revert, out of gas), gen 2 falls back to gen 1's verdict; **never** when it answers 0 (invalid). A relayer forcing out-of-gas only gains gen 1's (sound) path at more gas: stated and bounded | **owner**; §5 |
| R5 (Q7, F15) | Strictness | gen 2 is **never laxer** than gen 1; a difference found by the equivalence tests or the deploy probe goes to the owner with its rows (no automatic refusal, no automatic acceptance); equivalence is defined modulo gas (F3) | **owner**; §7 |
| R6 (Q1, F7) | Gen-1 `msig` | gen-1 `msig` records stay on gen 1's verifiers; the reason is that a registered gen-1 `msig` cannot register in gen 2 (`UAAlreadyRegistered` via `_kindOf`) | **owner**; §4 |
| R7 (Q2, F10) | Sibling verify-only generation | none. A gen 2 deployed after a qualifying precompile exists enables the verify-only kinds in the same deploy. The case "a gen 2 deployed for new kinds before the precompile" was left to a later gen-3 design; R10 now covers it (§11) | **owner**; §9, §11 |
| R8 (Q3 – Q6, Q8, Q9) | As proposed, with the review's additions | Q3 `KindConfig.verifyOnly` + the key-form bit; Q4 `UAVerifyOnly`, `verifyOnly(kind)`, and `expandedKeyOf` forwarded (F12); Q5 every single-key kind, each eligible only with its own edge-class list and vectors, ML-DSA first; Q6 a Final EIP address or the chain profile's own precompile; Q8 `ua_registries` validated on chain, order carries no meaning, plus F9's node rules; Q9 SDK verify rows keyed by chain, registry address and kind, the verify path a column | **owner**; §2, §3, §6, §12 |
| R9 | Probe of Draft addresses ("the middle way") | `script/pq_verifiers.py` (gen 1's ML-DSA verifiers today, and gen 2's) probes by default only Final EIP addresses and the precompiles the chain profile declares as the chain's own (`0x…5caa…` on the SCaaS chains). A Draft address (EIP-8355's `0x12` / `0x13` / `0x14`) is probed only when the chain's profile sets an explicit flag, confirmed by the owner per chain and recorded in the deploy book, and then with a fuller probe: the valid row, a flipped row and the edge-class vectors | **owner**; §9 |
| R10 | N generations | a registry takes as predecessor the chain's **latest** generation (any n ≥ 1) and is generation n + 1; one registry code serves every generation; lookups walk back to the generation that holds the record, under a fixed depth cap; R2 generalises to N; a generation may re-enable as verify-only a kind any predecessor enables; keyHash groups stay with the generation that first enabled them, checked across the whole chain; a sibling generation (Q2) is unnecessary; the factory binding becomes a bounded walk to the router's registry; node `ua_registries` the ordered chain, validated on chain | **owner**; §11 |
| R11 | Depth cap | the line of generations is capped at **16**: a deploy of generation 17 is refused by name | **owner**; §11 |

The rules `CTR-UA-58` … `-70` below write these rulings out; a detail no ruling names is marked **proposal**.

## 1. The code today (`ua-rs-sign` `a19151d64`)

| Where | What it does | Why it blocks V1 |
|---|---|---|
| `UARegistry` constructor | `p.generation() != 1` ⇒ `UAConfig(0)`; `_groupInPredecessor(pred, kind)` reverts `UAConfig(kind)` for any kind whose keyHash group a gen-1 kind enables | at most two generations; a kind gen 1 enables cannot be configured at all |
| `UARegistry.KindConfig` | `{uint16 kind; address verifier; uint64 cap}`, stored as one immutable word `verifier \| cap << 160` per slot (bits 224–255 unused) | no way to declare "verify only" or a key form |
| `UARegistry._authorized` | `kind == 0` (record not held here) ⇒ `UAStore.via(predecessor, …)`: gen 1 checks with gen 1's verifier | a gen-1 record never meets gen 2's verifier |
| `UARegistry._derived` | for a stored kind or purpose `member`, reads `_s.records[id]` only; `r.kind != kind` ⇒ `false` | a gen-2 `msig`'s member held in gen 1 would be refused |
| `UAStore.expanded`, `expandedKeyOf` | this generation's ML-DSA cache only; `_derived` prefers the cache whenever one is there; `expandedKeyOf` is not forwarded | gen 1's cache is invisible through gen 2 |
| `requireAuthorized` (`UAKeyNotCached` branch), `UARegistryCoreLib._notCached` | read `_s.records[ua].kind` | no named refusal for a gen-1 record |
| `UARegistry.requirePortable` / `requirePortableApp` | `_elsewhere(ua)` ⇒ forward to gen 1; `UARegistryCoreLib._portable` refuses `r.kind == 0` | portable and app purposes of a gen-1 record never meet gen 2's verifier |
| `UARegistryCoreLib._single` (host writes) | `cfg == 0` (the local record's kind, 0 for a gen-1 record) ⇒ `UAStore.via(_pred(), …)`: a gen-1 holder's `setPqzKey` / `setPqzScopedKey` on a gen-2 host is checked by gen 1 (ruling A6-I1) | must stay so (R2) |
| `UARegistryCoreLib._memberOk` | a derived member goes through `UAStore.via(address(this), …)`, also for a gen-1 `msig` holder on the host (`here == false`) | after V1 it would reach gen 2's verifier for a gen-1 record's member (R2) |
| `UARegistryCoreLib._pqzHolder` | a gen-1 single-key holder counts `IUARegistry(g1).verifyCap(kind)` (MD-13) | the bound must count the path the token will pay |
| `UARegistry._listedHere`, `UARegistryCoreLib._listedHere` | a kind with a verifier here is listed here | lists of a verify-only kind would read gen 2's empty list |
| `UARegistryCoreLib._identify` | step 1 `UAKindDisabled` only when the verifier word is 0; `_kindOf(ua) != 0` ⇒ `UAAlreadyRegistered` (forwarded to gen 1) | a verify-only kind would register in gen 2; a gen-1 `msig` cannot re-register in gen 2 |
| `UARegistryCoreLib._slotCap` | `verifyCap(kind) == 0` ⇒ the member is handed to gen 1 (`cap + cap/63 + GAS_MARGIN`) | must count a verify-only member's own path |
| `kindEnabled(kind)` | true iff a verifier word is set; clients read it before offering a kind for registration ([§1.9](../../contracts/accounts.md#verifiers)) | true for a kind gen 2 must refuse to register |
| `OpenFactory.uaRegistry()`, `publishTokenEnv` / `publishDexEnv` / `publishClassEnv` | `uaRegistry()` is the router's `registry()`; an `env.registry` other than 0 or that value reverts `EnvRegistryMismatch` (`OpenFactory.sol`, the env check); `configureChain` runs once | no release can bind gen 2 on a factory with a router (F1) |
| `DeployBase._deployUARegistry`, `_mldsaCandidates`; `script/pq_verifiers.py` | gen 1 only; the ML-DSA candidates are probed in the order EIP-8355's `0x12` / `0x13` / `0x14` (Draft), then `0x…5caa0012` / `13` / `14` | no gen-2 path; a Draft address is probed first (R9) |
| node | one `[[chains]] ua_registry` (`main.rs`); the nine registry writes target it only ([NODE-JOB-19](../../node/job-api.md#NODE-JOB-19)); the guard's `Rule::UaRegistry` is that one address; the indexer reads one registry, PQZ key-version events included (`indexer.rs`, `pay_filter`); `UA_KEY_NOT_CACHED` is never `dead` ([NODE-JOB-29](../../node/job-api.md#NODE-JOB-29)) | §12 |

## 2. Which kinds, and how they are declared (`CTR-UA-58`)

**CTR-UA-58 (owner R8 Q3 / Q5, R3; details proposal).** A later `UARegistry` may carry a kind **verify-only**: a
**single-key** kind of the kind table that a predecessor enables. One rule for every such kind (the signing kinds, PQ
`0x0130`–`0x0135`, the group kinds `0x0110`–`0x0113`, `zether-bls12381` `0x0141`), but a kind is **eligible** only once its
edge-class list and vectors exist (§7); ML-DSA (`0x0130`, `0x0131`, `0x0134`) first. Never `msig` `0x0120` (a structure: each
generation re-enables it in full, §1.8 "Structures"; a predecessor's `msig` record stays forwarded whole, §4), never
`pqz-mlwe` `0x0142` (not a kind: its proof check is a write of the PQZ attachment, ruling A6-I1). `bls12381-multi` `0x0121`
is left out of this build (F16): its spec is not built; its rows (stored form `p`, `verifyMinimal`) are added when that kind
lands.

- **Declaration.** `KindConfig` gains `bool verifyOnly` and `uint8 keyForm`; the constructor stores them as bit 224 and bit
  225 of the kind's word (`verifyCap` reads `uint64(word >> 160)` and is unchanged). The word reaches the libraries as today
  (`_lib`'s appended `_cfg(kind)`), so they need no getter.
- **Key form (R3).** Bit 225 states which key form the registry hands the verifier; the constructor requires it to equal
  the verifier's own getter `KEY_FORM()` (new on verify-only verifiers):
  - `0` **stored**: the bytes the holding generation's code passes on that path (§4 "Key bytes"). Any other form the
    verifier needs (an EIP-8051 expanded key, an EIP-8052 NTT-domain Falcon key, a 32-byte `tr`) it **derives per call**
    from those bytes, inside its own cap; the measured cost of the derivation is part of the cap (§13 Gas).
  - `1` **holder's cache** (**proposal**, §16 P1): the holding generation's complete ML-DSA expanded-key cache, read through
    `expandedKeyOf` (§3) and passed as `verifyCached` takes it. Allowed only where the holding generation's verifier of the
    kind is on the cache path, so the cache can be filled there by anyone. Gen 2 never caches (R3).
  - **Impossible combination** (refused by name): form `1` where the holding generation's verifier has a precompile (its
    `cacheExpandedKey` reverts `UAKeyCache`, so no cache can exist), or a form that cannot be derived per call within the
    cap. The constructor reverts `UAConfig(kind)` when bit 225 is `1` and the predecessor's verifier of the kind reports
    `PRECOMPILE() ≠ 0` (read through the new view `verifierOf(kind)`, proposal); the deploy refuses before broadcast with
    `GEN2_KEY_FORM_IMPOSSIBLE <kind>`.
- **Constructor.** `UAConfig(kind)` unless `verifyOnly ⇔ IUARegistry(predecessor).kindEnabled(kind)` (`kindEnabled` of a
  later generation answers for its whole chain, §11): a verify-only flag on generation 1, on a kind no predecessor enables, or
  on `msig` / `0x0142` is refused; a kind a predecessor enables without the flag is refused as today. A verify-only kind is
  exempt from the group check (its group **is** the predecessor's and stays there); every other kind keeps it, across the
  whole chain (§11). The existing predecessor checks stay (`chainUid`, `hederaNative`, `checkedOf`, `memberSigHashOf`,
  `msigStateOf`; `generation()` as §11). The cap is the generation's own measured cap, `0 < cap ≤ verifyBudget` as every
  kind, and the deploy's 75 % rule (`_pqKindFits`) applies.
- **The keyHash group stays where it is.** A later generation writes no `keyOwner` for a verify-only kind and reads
  `keyOwner` through its predecessors as today.

## 3. Writes, refusals and views (`CTR-UA-59`)

**CTR-UA-59 (owner R2, R8 Q4; details proposal).** **Every write is authenticated by the generation that holds the record**,
wherever the write is stored. A generation's verifier of a verify-only kind authenticates **no** write: it serves only the
consumer checks of §4.

- **Registrations.** `register`, `registerWebAuthn`, `registerMuSig2`, `registerFrost` of a verify-only kind revert
  **`UAVerifyOnly(uint16 kind)`** (new, named: "register in the generation that enables it", `kindHome(kind)`, §11) at step 1
  (`_identify`), before any other check.
- **`cacheExpandedKey(kind, …)`** of a verify-only kind reverts `UAVerifyOnly(kind)`: the cache is filled in the holding
  generation (open to anyone, as today).
- **Key writes held in the holding generation** (`setKemKey`, `storePqzPop`, `storePqzScopedPop`, `acceptMembership`,
  `updateMsig`) keep today's rule: `UAUnauthorized` on a generation that does not hold the record.
- **Writes stored on a later host for a predecessor's record** (ruling A6-I1: `setPqzKey`, `setPqzScopedKey` on the
  generation that enables `0x0142`): the signature goes to the holding generation, never to the host's verify-only verifier.
  Single key: `_single` with the local word `cfg == 0` forwards to the holder as today (`UAStore.via(_pred(), …)`, which
  walks back, §11). A predecessor's `msig` holder: its derived members go `via(_pred())` when `!here`, not
  `via(address(this))` (a code change in `UARegistryCoreLib._memberOk`); its native members keep the holder's clone hash.
  The verify-only path of §4 is taken only from the consumer entries (`requireAuthorized`, `requirePortable`,
  `requirePortableApp`), never from `_sigOk` / `_portableOk` on a write.
- **Bounds of those writes (F8).** `_pqzHolder` counts what the write pays: a predecessor's single-key holder
  `verifyCap(kind)` of the holding generation plus each hop's hold (§11); a predecessor's `msig` holder counts its members by
  the holding generation's caps (in `_slotCap`'s `gen1` mode a verify-only member counts as a hand-off, not as this
  generation's cap).
- **Views.** `kindEnabled(kind)` stays true (a verifier is there); new view **`verifyOnly(uint16 kind) → bool`**. A client
  offers registration on a registry only where `kindEnabled && !verifyOnly`. `uaCount` / `uaAt` / `uaPage` / `uaIndex` of a
  verify-only kind forward to the predecessor (`_listedHere` is false for it, in `UARegistry` and `UARegistryCoreLib`).
  **`expandedKeyOf(ua)` forwards** for a record this generation does not hold (F12), so the node and clients read the cache
  where it is and never try to fill it on a verify-only generation. `kindOf`, `recordOf`, `keyOf`, `registrationOf` and the
  other readers forward as today. A generation emits no event for a verify-only kind.
- An `msig` registered in a later generation may name a predecessor's members of a verify-only kind (`kindOf(member) ==
  memberKind` through the chain, as today).

## 4. The authorization path (`CTR-UA-60`)

**CTR-UA-60 (proposal, within V1 / V3, R2, R6).** Wherever a consumer entry of a later generation checks a signature of a
single-key record a predecessor holds, and the kind is verify-only here, this generation verifies it itself, with its own
verifier, under its own `verifyCap` and the caller's hold (T-AUTH-4); the fallback of §5 applies.

| Path | Today | Verify-only |
|---|---|---|
| `requireAuthorized`, the signer (`_authorized`) | `via(predecessor)` | `kindOf(ua)` through the chain, then `_derived` with the holder's key |
| `requireAuthorized`, this generation's `msig`'s member at either level (`_memberOk` → `_derived`, purpose `member`) | `false` (unreachable: no shared kind) | as the signer, purpose `member`, `keyData` empty ([CTR-UA-33](../../contracts/accounts.md#CTR-UA-33) B); the member's kind re-checked against `kindOf` through the chain (test) |
| `requirePortable`, `requirePortableApp` (`_portable` → `_single`) | forward to the predecessor | the library's `_portable` on the holder's record |
| this generation's `msig`'s stored paths (`UARegistryCoreLib._memberOk`, consumer entries) | `via(address(this))` | as the hot path |
| a write for a predecessor's record (host `setPqzKey` / `setPqzScopedKey`, single key or a predecessor's `msig` holder's members) | `via(_pred())`; `msig` members `via(address(this))` | **the holding generation** (R2, §3): `via(_pred())` for both |
| a predecessor's `msig` record (any consumer path) | forwarded whole | **unchanged** (R6): forwarded whole, its members use the holding generation's verifiers |
| PoP (`PURPOSE_POP_V2`) | the holding generation at registration | never checked by a later generation; `_portable` refuses the purpose as today |

- **R6, the true reason.** A registered gen-1 `msig` keeps gen 1's verifiers because it cannot register in gen 2: the same
  structure is the same id, and gen 2's `_identify` reverts `UAAlreadyRegistered` when `_kindOf(ua) ≠ 0`, which forwards to
  gen 1. Only a different structure (a new id, assets moved) gets gen 2's verifiers. Evaluating a gen-1 `msig` in gen 2
  would also need gen 1's accepted bits, current structure, clone hash and `UAAuth` domain.
- **Key bytes.** The generation passes exactly the bytes the holding generation's code passes on that path: `keyOf(ua)`
  where it reads the key pointer (the stored kinds); `webAuthnKeyOf(ua)` for WebAuthn; `registrationOf(ua).keyData` where it
  reads its registration blob (a classical kind under purpose `member`; a group kind's full key data on the portable path,
  whose `verifyPop` runs the group check under `verifyBudget`); `auth.keyData` checked by `uaOf(kind, keyData) == ua` where
  the holder does that (a classical kind's hot path). Under key form `1` (§2), the holder's complete cache from
  `expandedKeyOf(ua)`; an incomplete one is `UAKeyNotCached(ua)` (the named refusal reads the kind through the chain).
  `verifyCached` trusts its pointers ([CTR-UA-23](../../contracts/accounts.md#CTR-UA-23) MD-10): the generation passes only
  pointers its constructor-checked chain wrote.
- **The entry and the DST** are the ones the holding generation's code calls for that path and purpose (`verify`;
  `verifyPop` where it calls it on the portable path, e.g. `0x0106` under its `DST_POP`; `verifyCached` under form `1`).
- **A failed read is never a verdict (F11).** `kindOf` / `keyOf` / `webAuthnKeyOf` / `registrationOf` / `expandedKeyOf` on
  a predecessor fail only by gas; a failure re-raises `UAVerifyGas` (as `_accepted` does), and the reads are counted in the
  caller's hold.
- **Cost on other records.** Only a generation with at least one verify-only kind (an immutable bool) asks the chain's
  `kindOf` before forwarding a predecessor's record; one without keeps today's code path.
- **`msig` bound.** `_slotCap` counts a verify-only member as `verifyCap(kind)` (this generation's) plus the reads of its
  record through the chain, pinned per kind at the worst case (F8): `kindOf` and `keyOf` for the stored kinds;
  `webAuthnKeyOf` for WebAuthn; `registrationOf` only where nothing smaller serves, at its worst size (a FROST rest of up to
  17,924 B on the portable path), plus one hop per generation passed (§11). It no longer counts the hand-off
  `cap + cap/63 + GAS_MARGIN`. The fallback of §5 is outside this bound (§5).

## 5. Fallback to the holder's verdict (`CTR-UA-68`)

**CTR-UA-68 (owner R4; the encoding is a proposal).** When this generation's verifier of a verify-only kind gives **no
answer**, the check falls back to the holding generation's verdict (`via(holder)`, under the holder's hold); when it
**answers 0**, the check is refused and there is no fallback.

- **Three states.** A verify-only verifier reports an answer only when the precompile call succeeded and returned exactly
  one 32-byte word equal to 0 or 1 (a precompile has no code, so "no code at the precompile" shows as success with empty
  returndata). Anything else (call failed, empty or malformed returndata, out of gas inside the cap) is no answer: the
  verifier reverts with the named error `PqNoAnswer()` instead of returning `false` (today's `PqUA.callBool` folds all of
  them into `false`; the verify-only verifier uses a three-state call, proposal). The registry reads its own call: word `1`
  accept, word `0` refuse, `PqNoAnswer` or any other revert ⇒ fallback.
- **The relayer cannot buy a fallback below the cap.** The registry's hold check (T-AUTH-4) re-raises `UAVerifyGas` before
  the call when the caller's gas cannot cover this generation's cap plus its hold, so out of gas inside the verifier happens
  only with the full cap, i.e. a precompile repriced or gone. If a relayer could still force it, it gains only the holder's
  path: sound by definition (the holder generation is the reference), at more gas, paid by the sender of the transaction.
- **Bound.** The accepted set is the holder's set plus this generation's; with R5 (never laxer) it never exceeds the
  holder's. A stricter gen 2 that the owner confirms (§7) is not strict against a forced fallback: it falls back to the
  holder's verdict. The fallback needs the holder's gas (e.g. `mldsa65` 5.95 M on the cache): an `msig` sized by this
  generation's caps may not fit then, and that check fails closed with `UAVerifyGas` until the precompile answers again;
  `_slotCap` counts the normal path (proposal, §16 P3).
- **What it fixes (F6).** A removed, moved or repriced precompile no longer locks a gen-1 UA's funds in gen-2-bound tokens:
  the holder's software path, which still works, answers ([ARCH-POS-18](../../decisions.md#ARCH-POS-18)).

## 6. Which later precompile a verify-only kind can use (`CTR-UA-61`)

**CTR-UA-61 (proposal, within R3).** Same kind means the same signature scheme over the same message with the same key: a
gen-1 signature must verify unchanged. The current choices fix what that is: ML-DSA and SLH-DSA sign the 32-byte
`pq_msg = keccak256(TAG(kind) ‖ ua_msg)`, **pure** (not HashML-DSA / HashSLH-DSA), with the **empty** context
([CTR-UA-23](../../contracts/accounts.md#CTR-UA-23)); ML-DSA's precompile layout is EIP-8355 as pinned at `3aea9f36`
([plan P6f](../plans/2026-10-14-p6f-precompiles.md)); `fndsa512` / `fndsa1024` are Falcon specification v1.2 with EIP-8052's
SHAKE256 hash-to-point over `ua_msg`; SLH-DSA has no EIP.

| Case | Example | Eligible? |
|---|---|---|
| 1. Only the call shape differs: address, argument order, output encoding, gas | an EIP-8355 Final at another address or with another gas schedule | **yes**: a new verifier adapts the call; key form `0` |
| 2. The precompile needs a key form derivable from the stored key | an EIP-8051 precompile on the expanded key; EIP-8052 on the NTT-domain key | **yes** only if the verifier derives the form per call within its cap (form `0`), or, ML-DSA only, reads the holder's complete cache (form `1`, proposal); else **no** (R3), refused by name |
| 3. The algorithm differs | a precompile for HashML-DSA only; a mandatory non-empty context; Falcon FIPS 206 final ≠ Falcon v1.2 / EIP-8052 as pinned | **no**: gen-1 signatures cannot verify there; that is a new kind version (new tag, new id, re-registration: e.g. `…fndsa512.v2`, CTR-UA-23), never verify-only |

Per call, an ML-DSA-65 key expansion does not fit any cap that makes the precompile worth having (the cache was introduced
because the FIPS-key verify of ML-DSA-65 / -87 is over EIP-7825's 2^24); so an EIP-8051 precompile serves an ML-DSA kind only
under form `1`. What separates case 1 / 2 from case 3 is decided by evidence (§7), not by reading the EIP; the EIP's status
only guards the address (§9).

## 7. Equivalence (`CTR-UA-62`)

**CTR-UA-62 (owner R5 for strictness; the method is a proposal).**

- **Definition (modulo gas).** For a verify-only kind, with sufficient gas on both sides, gen 2's verifier gives the same
  cryptographic verdict as the holding generation's path for the same key, message and signature: same scheme, `ua_msg` /
  `pq_msg`, DST, encodings, length checks and strictness. Gas refusals are outside the definition (gen 1's Solidity verify is
  input-dependent under a cap close to its cost; a precompile is flat); §5 covers no answer.
- **Never laxer (R5).** Gen 2 never accepts what the holder refuses. Any difference, in either direction, found by the tests
  or by the deploy probe stops that kind's verify-only deploy and goes to the owner with its rows; there is no automatic
  refusal and no automatic acceptance. The owner may confirm a stricter gen 2 (e.g. where the holder is the lax side);
  with §5 a confirmed stricter gen 2 still falls back to the holder's verdict when it gives no answer. A known case:
  `FnDsa.sol` accepts `‖s‖² ≤ ⌊β²⌋` (the reference's `l2bound`) while EIP-8052's text says `<`; a precompile following the
  text is stricter on that one boundary row.
- **Edge classes per kind (F3).** A kind is eligible only with its list, each class with pinned vectors and its own mutant
  (one stand-in that accepts that class must make the tests fail):
  - ML-DSA: hint indices not strictly increasing, non-zero hint padding, cumulative count decreasing or above ω,
    `‖z‖∞` at `γ1 − β − 1` and `γ1 − β`, `c~` flipped, signature and key length ± 1, a signature made with a non-empty
    context, a HashML-DSA signature; plus the NIST ACVP sigVer and Wycheproof ML-DSA verify sets and the pinned KATs (the
    EIP-8355 cases, `pq_kat.json`, `pq_external.json`, `pq_signatures.json`).
  - Falcon: the norm at `⌊β²⌋` and at `⌊β²⌋ + 1` (ground vectors made with a test key), "−0", non-zero padding, `|s2| = 2047 /
    2048`, the header byte, a `pk` coefficient `≥ q`; the EIP-8051 / 8052 KATs.
  - Classical kinds: high-S, `r` / `s` zero or `≥ n`, the `r + n < p` wrap, off-curve and infinity keys (P-256 / secp256k1);
    `S ≥ L`, small-order `A` / `R`, non-canonical encodings (ed25519); infinity and out-of-subgroup points, `DST` against
    `DST_POP` (BLS).
- **Reuse the decoding.** Where the precompile's interface allows it (e.g. EIP-8052's core on decoded inputs), the gen-2
  verifier reuses the holder verifier's decoding code unchanged and replaces only the arithmetic, so equivalence reduces to
  the core. Where an EIP leaves an encoding check to the implementation and the holder enforces it, the gen-2 verifier
  enforces it with that same code before the call; the build lists these checks per kind.
- **Every entry.** `verify`, `verifyPop` (the portable path, `_single`), `verifyCached` (form `1`) are each covered.
- **Tests.** (a) Shared vectors: every row of the kind's files (valid, negative, edge classes) gives the same verdict on both
  verifiers. (b) A verifier-level differential test: the edge classes plus random mutants (each byte of `sig`, `pk`, message
  flipped; lengths ± 1; trailing bytes). On forge the precompile is absent: a stand-in at the precompile address tests the
  registry logic only; the verifier-level run against a real precompile runs on a local chain whose client has it (never the
  live testnet). (c) A registry-level differential test: for the same gen-1 record, `requireAuthorized` (signer and `msig`
  member), `requirePortable` and `requirePortableApp` under every purpose give the same verdict on gen 1 directly and on gen
  2, and the R2 writes are refused by a gen-2 stand-in verifier that accepts everything. (d) The per-class mutants.

## 8. Domain separation and replay (`CTR-UA-63`)

**CTR-UA-63 (follows from the code; no change).** Verify-only adds no message form, so no cross-generation replay (the
review checked this against the code and found it holds):

- A derived kind signs `ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)`
  ([CTR-UA-12](../../contracts/accounts.md#CTR-UA-12)): no registry, no generation. A signature the holder accepts for
  `(ua, purpose, digest)` is already accepted through a later generation today (forwarding); with §7 the accepted set is the
  same, only the verifier differs. Replay protection is the operation's `digest` (the token's EIP-712 domain and nonce; a
  portable record's own fields, e.g. `chainUid` and token of a scoped PQZ key record), as today.
- `uaAuthDigest` is registry-bound (`EIP712Domain("SCaaS UARegistry", version, chainid, address(this), salt = chainUid)`,
  version the generation's decimal number, §11) and is signed only by **native** ids and native `msig` members on the hot
  path. Native ids are never registered, so never verify-only; a predecessor's `msig` is forwarded whole, so its native
  members keep signing their generation's domain. `updateMsig`'s digest names `address registry`.
- The portable purposes' native members sign the chain-free typed digest under `PORTABLE_DOMAIN_SEPARATOR`; derived members sign
  `ua_msg`. Neither names a registry.

## 9. Deploy and probes (`CTR-UA-64`, `CTR-UA-69`)

**CTR-UA-64 (owner R7 for "same deploy"; the rest proposal).**

- **Same deploy (R7).** A later generation deployed after a qualifying precompile exists for a kind a predecessor enables
  carries that kind verify-only in the same deploy (once eligible, §7). No sibling verify-only generation is deployed; a
  precompile that arrives after the latest generation is used by the next generation (§11).
- **When.** For such a kind, the new verifier finds a precompile at an address allowed by CTR-UA-69 by its constructor probe;
  the deploy's differential probe passes; its measured cap fits `_pqKindFits`; the key form is possible (§2). A probe call
  that fails refuses the deploy by name (as MD-15).
- **The constructor probe (F4).** Next to the valid / flipped pair, the verify-only verifier's constructor runs one cheap
  negative row per edge class of §7 (a few KB each, in its init code): a precompile that fails one leaves `PRECOMPILE = 0`,
  and the deploy then does not list the kind (gen 1 keeps serving it). The rows are part of the init code, so of the
  verifier's CREATE2 address: what the chain probed is on chain.
- **The deploy's differential probe (F4).** By `eth_call` against the holding generation's verifier, through the chain's
  node list with the strict-majority option ([ARCH-POS-15](../../decisions.md#ARCH-POS-15)); the client versions of the nodes
  are recorded in the book. The holder entry per kind, under 2^24 per call:
  - ML-DSA, holder on the cache path: `expandedKeyPart(pk, p)` for each part (each one under 2^24 by design), concatenated,
    then `verifyExpanded(ek, message, sig)` (≈ the cached cost: 4.1 / 5.8 / 8.85 M per row); never `verify` on the FIPS key
    (over 2^24 for ML-DSA-65 / -87).
  - ML-DSA, holder on a precompile: `verify(pk, message, sig)` (≈ 0.15–0.25 M per row).
  - Other kinds: the holder's `verify` / `verifyPop` as its registry calls it, its gas measured per row; a row over the
    client's cap refuses the probe by name.
  Any difference stops before broadcast and goes to the owner with the rows (R5).
- **After client upgrades (F4).** A precompile is client code; gen 2 cannot follow a change. The differential probe is
  re-run after every client upgrade on the chain as an operations check. A precompile that stops answering is covered by §5;
  one that answers differently goes to the owner with its rows (a laxer answer is the forgery row of §13).
- **How.** A later-generation mode of `DeployBase` (`_deployUARegistry` with `predecessor` = the book's latest generation,
  §11), its own `UARegistryCoreLib` / `UARegistryAuxLib` (new code, new addresses), the verifiers by CREATE2 from
  `script/pq_verifiers.py` on the real chain as today; the same probes (`_precompiles`, `PqPrecompileProbe`). A kind gen 1 left
  disabled for its budget is not verify-only: it is an ordinary later-generation kind under today's rule, its group being new.
- **Deploy book (F14).** The registry's address, generation and `predecessor`; its two libraries; per verify-only kind
  `{kind, verifier, cap, keyForm, precompile, eip, status, probe_rows_hash, probe_rows}` (the constructor's rows and the
  differential rows run); the node list and client versions of the probe; the router and factory that bind it (§10); the
  Blockscout verification of every one of them ([NET-EVM-12](../../networks/evm.md#NET-EVM-12)); the Draft flag of
  CTR-UA-69 where set.
- **Size.** Today `UARegistry` 32,477 B, `UARegistryCoreLib` 34,116 B, `UARegistryAuxLib` 33,685 B (`size-baseline.json`), under
  the 131,072 B runtime ceiling; the change adds to `UARegistry`, both libraries and `OpenFactory` [estimate: a few hundred
  bytes to about 2 KB, not measured]; the baseline moves with this reason, old → new in the commit.

**CTR-UA-69 (owner R9).** Which addresses a PQ verifier's deploy probes, for gen 1's ML-DSA verifiers today and every later
generation's verifiers:

- **By default** only the addresses of an EIP in **Final** status and the precompiles the chain profile declares as the
  chain's own: on the SCaaS chains `0x…5caa0012` / `13` / `14` ([evm.md](../../networks/evm.md) "PQ precompiles on the SCaaS
  testnet"; the ruling cites `NET-EVM-15`, not defined on this tree, so the chain-own list gets its rule id on landing). The
  chain profile also states whether the chain commits to keep its own precompile (Q6 addition).
- **A Draft address** (EIP-8355's `0x12` / `0x13` / `0x14` today) is probed only when the chain's profile sets an explicit
  flag (`probe_draft_precompiles`, name proposal), confirmed by the owner for that chain and recorded in the deploy book,
  and then with the fuller probe: the valid row, a flipped row and the edge-class vectors of §7.
- **Change to the existing script.** `script/pq_verifiers.py` and `DeployBase._mldsaCandidates` probe `0x12`–`0x14` first
  today; both change to the default list above, the Draft candidates added only under the flag (work list §14).

## 10. How a release binds a later generation (`CTR-UA-67`)

**CTR-UA-67 (owner R1, generalised by R10; the clone-hash check is a proposal).** `OpenFactory`'s env check (in
`publishTokenEnv`, `publishDexEnv`, `publishClassEnv`) accepts `env.registry` equal to 0, to `uaRegistry()` (the router's
registry), **or** a registry whose predecessor chain reaches `uaRegistry()`: walk `r = r.predecessor()` at most `MAX_GENERATION
− 1` times (§11), each step a contract, the reached registry equal to `uaRegistry()`; `chainUid()` equal (the existing
`_requireChainUid`); else `EnvRegistryMismatch(expected, got)` as today. Checked in code, no admin key, no stored list.
Proposal (§16 P4): also require `smartKeyCloneHash()` of the env's registry to equal the router's, so §13.4's
`SmartKeyAccount` binding holds for every generation an env may name.

- **What it means.** `uaRegistry()` and the directory keep naming the router's registry, and the router authenticates
  governance through it (gen 1's verifiers); token operations of a release that names a later generation go through that
  generation's verifiers. One factory, one catalogue, one router.
- **Trust.** An env is published by governance, so a registry the factory accepts is one governance named; the walk only
  refuses a registry of another chain or line. Which registry is the chain's real later generation is the deploy book's
  word (§11), not the constructor's views (F13).
- **Built factories.** A factory already deployed keeps its rule (nothing deployed is upgraded); the check lands with the
  factory code of the round. All chains are test-only today.
- **Conflict to change on landing:** [admin-not-owner §13.4](2026-11-10-admin-not-owner.md) "one registry per factory holds"
  (§15).

## 11. Generations beyond two (`CTR-UA-70`)

**CTR-UA-70 (owner R10, R11 for the cap; the gas figures and the mitigations are proposals).**

- **The line.** Generation 1 has `predecessor = 0`. A later registry takes as predecessor the chain's **latest** generation,
  any `n ≥ 1`, and is generation `n + 1` (`generation = p.generation() + 1`, today `p.generation() != 1` is refused). One
  registry code serves every generation; its EIP-712 version is the generation's decimal number. **Depth cap:**
  `MAX_GENERATION = 16` (owner R11); the constructor refuses a predecessor with `generation() ≥ 16` (`UAConfig(0)`), so a
  generation 17 cannot deploy; the deploy refuses it first by name (`GEN_DEPTH`).
- **Lookups walk back.** Every reader that forwards today forwards to `predecessor`, which forwards in turn, so a lookup ends
  at the generation that holds the record or at generation 1: `recordOf`, `kindOf`, `keyOwner` (so `UAAlreadyRegistered` /
  `UAKeyInUse` across the whole line), `registrationOf`, `keyOf`, `webAuthnKeyOf`, `msigOf`, `msigStateOf`,
  `memberAccepted`, `memberSigHashOf`, `checkedOf`, the PQZ and KEM views, `expandedKeyOf`, the per-kind lists and decoys
  ([CTR-UA-29](../../contracts/accounts.md#CTR-UA-29): a kind's list lives in its home generation; `msig` has one list per
  generation). New views (proposal): `kindHome(kind) → address` (the generation where the kind is registrable, walking back;
  0 if none) and `holderOf(ua) → address` (the generation that holds the record; 0 if none).
- **Writes (R2 for N).** The generation that holds the record authenticates every write. A host write for a predecessor's
  record goes `via(holderOf(ua))`, not `via(_pred())` once a middle generation may carry the kind verify-only (its
  `requireAuthorized` would use its own verifier); for two generations both are the same.
- **Kinds and groups.** A generation may carry verify-only a kind **any** predecessor enables (§2: `kindEnabled` of the
  predecessor answers for its whole line). A keyHash group stays with the generation that first enabled a kind of it: the
  constructor refuses a non-verify-only kind whose group any predecessor enables (`_groupInPredecessor` asks the predecessor,
  which answers for its line). `0x0142` lives in one generation of the line (ruling A5-I1, the check generalised the same
  way); the PQZ host is `kindHome(0x0142)`.
- **The sibling question is gone (R7).** A precompile that arrives after the latest generation is used by the next one, which
  carries the kind verify-only over the whole line; Q2's sibling is unnecessary.
- **"Latest" (threat).** A registry cannot see its successors (immutable, nothing written back), so "latest" is not checkable
  on chain by the new registry. The deploy reads the book's latest generation and refuses another predecessor by name
  (`GEN_NOT_LATEST`); it also refuses when the latest's `generation()` is not the book's. Each registry's predecessor is
  immutable, so no middle generation can be inserted under an existing one; a **sibling** (a second registry over the same
  predecessor) can be deployed by anyone, as a second gen 2 can today: it does not see its sibling's records, and it is used
  only where governance publishes an env naming it (§10).
- **Gas per hop** (EIP-2929 prices; **estimates**, the round measures them, T-GAS): a cold `STATICCALL` to the predecessor
  ≈ 2,600, plus its cold record slot ≈ 2,100: ≈ 5 k per generation passed without the record; ≈ 5–9 k to read the record
  where it lives (one to three cold slots); warm repeats ≈ 100 each. The **worst case is a miss**: a lookup for an id
  registered nowhere (e.g. a token's `kindOf(to)` for an unknown id) walks the whole line: ≈ 80–120 k at depth 16. Each hop that
  forwards a signature check (not a read) also holds `1/63` of it plus `GAS_MARGIN`; `_slotCap`, `_pqzHolder` and the caps
  count the hops to the member's holder (fixed: a record never moves, a predecessor never changes).
- **Mitigations (proposals).** (1) An id in the native space (`UAKinds.inNativeSpace`: top 12 bytes zero) is answered
  `kindOf = 0` without walking: registration refuses such an id (`UAIdInNativeSpace`), so no generation can hold it; tokens
  already skip the registry for it (`MtxPipelineLib._checkTo`). (2) The depth cap bounds the miss. (3) The SDK gas table
  carries the extra per registry (§12).

## 12. Node, SDK, clients, indexers, families (`CTR-UA-65`, `CTR-UA-66`)

**CTR-UA-65 (owner R8 Q8 / Q9, R10; details proposal).**

- **Node config.** `ua_registries = [...]` replaces `ua_registry` (a note for operators: config shape change). Validated on
  chain at start: every entry's `chainUid()` is the chain's; exactly one has `generation() == 1` and `predecessor() == 0`; the
  others form one line, each `predecessor()` an entry, generations consecutive, none above `MAX_GENERATION`. The node orders
  them by those links, so the order written in the config carries no meaning. This also closes today's gap "writes that must
  go to generation 1 cannot be relayed" ([§1.8 Relaying](../../contracts/accounts.md#CTR-UA-31)).
- **Node guard (F9).** `Rule::UaRegistry` becomes the set of the line's addresses; the allow-list check (`typed.rs` `REG`
  rows against each contract's selectors) holds per registry. A `register` of a kind sent to a generation where it is
  verify-only is refused before sending, `UA_VERIFY_ONLY` (named; the target is `kindHome(kind)`); a key write sent to a
  generation that does not hold the record is refused, `UA_WRONG_GENERATION` (target `holderOf(ua)`).
- **NODE-JOB-29 (F9).** `UA_KEY_NOT_CACHED` through a later generation: the parts belong in the holding generation
  (`cacheExpandedKey` there; the lane sends them there for a `register`); still `queued`, never `dead`. Where the holding
  generation refuses the cache (`UAKeyCache`: its verifier has a precompile) the case cannot complete: `dead`
  `UA_KEY_NOT_CACHEABLE` (the constructor check of §2 makes it unreachable; the node names it anyway).
- **Indexer (F9).** Reads every generation of the line (today one registry, `ua_registry`), `UARegistered` from each and the
  PQZ key-version events from the PQZ host `kindHome(0x0142)`. A verify-only generation emits nothing for its verify-only
  kinds.
- The node verifies nothing itself: a token checks on chain through its bound registry; the node's simulation follows.
- **SDK.** The target of a registration is `kindHome(kind)`, of a key write `holderOf(ua)`. The gas table's verify rows are
  keyed by chain, registry address and signer kind; the verify path (`cache` / `precompile` / `fallback`) and the hops are
  columns, measured per chain per registry ([CLI-SDK-09](../../clients/scaas-sdk.md#CLI-SDK-09)); the quote takes the row of
  the registry the token binds; the reference table carries every path.
- **Clients.** Signing is unchanged (same kind, same message). A client choosing a token release shows its registry and that
  registry's verify path for the holder's kind. `ua-rs` and every `ua-*` registration builder read `verifyOnly` / `kindHome`
  before offering a kind on a registry.

**CTR-UA-66 (proposal; families PLANNED).** One principle on every family: a later registry (or verifier) deployment may
verify, through its own verifier, records an earlier deployment holds for the same kind, reading them and writing nothing;
equivalence as §7; nothing is upgraded. EVM now. Soroban (no generations; a new kind is a new registry with new tokens,
[NET-SOR-17](../../networks/soroban.md#NET-SOR-17)), Solana, Move, TON, Cosmos: in each family round. NEAR and Algorand have
no registry (records per token / in the account app): the principle applies to their token or account-app releases.

**Maximal support and "nothing deployed is upgraded".** [ARCH-POS-18](../../decisions.md#ARCH-POS-18): the holding generation
keeps its software path for every kind; verify-only adds a faster path and falls back to the holder when it gives no answer
(§5); nothing is disabled. No deployed registry changes; each later generation is a new immutable deployment with no admin
and no table, each token release binds its registry at `initialize` ([CTR-UA-05](../../contracts/accounts.md#CTR-UA-05),
[CTR-UA-15](../../contracts/accounts.md#CTR-UA-15)).

## 13. Threat model, residual, gas

| Threat | Effect | Bound |
|---|---|---|
| A gen-2 verifier (or the chain's precompile) accepts a forgery for kind K | anyone can authorize as any gen-1 UA of kind K in every consumer that binds gen 2: token operations, portable and app records read through gen 2 (e.g. a PqChat KEM record), a DEX | the holder's records, keys, groups and every registry write are untouched: writes are authenticated by the holder (R2, §3), so a forgery cannot place a PQZ key or change a record; §7 tests, the constructor's edge-class rows and the probe; UNAUDITED until an AI audit round covers the verifier |
| Gen 2 refuses what the holder accepts | a gen-1 UA of kind K cannot act in gen-2-bound consumers | §7 (never laxer, differences to the owner); only a stricter gen 2 the owner confirmed can refuse more, and §5's fallback then still applies on no answer |
| A precompile removed, moved or repriced above gen 2's cap | no answer from gen 2's verifier | §5: the holder's verdict, at the holder's gas; an `msig` sized by gen 2's caps may not fit then (`UAVerifyGas`, fail closed until the precompile answers) |
| A client upgrade changes the precompile's answers | gen 2 cannot follow | the probe re-run after upgrades (§9); a laxer answer is the forgery row; a stricter one goes to the owner |
| A wrong predecessor | a registry reads keys from a contract that only answers like a registry | the constructor's checks bind only what a contract answers (any contract can answer `generation()`, `chainUid()` and the views). What binds a later generation to the real line is the deploy book, the CREATE2 addresses, the deploy's `GEN_NOT_LATEST` check and the governance-published env that binds it to tokens (§10, §11) |
| A sibling generation | records split between siblings | used only where governance names it in an env; the deploy refuses it (§11) |
| A deep line | each miss walks every generation | `MAX_GENERATION`; native-space ids answered without walking; the SDK quotes the hops (§11) |

**Residual (F17).** A token is already trusted code for its balances, so a gen-1 UA credited in a gen-2-bound token adds no
trust beyond the release. What is new is that **every consumer bound to a later generation inherits that generation's
verifier for the predecessors' UAs**: tokens and DEX releases that name it in their env, and contracts that read portable or
app records through it (`PqChat` records, the PQZ attachment's consumers). The router's governance stays on the router's
registry (§10). Wallets show the release's registry and verify path (§12).

**Gas** (caps from `DeployBase` and [CTR-UA-23](../../contracts/accounts.md#CTR-UA-23); measured unless marked):

| Kind | gen 1 on the cache (cap; measured `verifyCached`) | with a precompile (cap; measured) |
|---|---|---|
| `mldsa44` | 4,250,000; 4.11 M | 200,000; ≈ 175 k `verify` (P6f copy) |
| `mldsa65` | 5,950,000; 5.80 M | 200,000; ≈ 236 k `verify` (P6f copy, `estimateGas`), `requireAuthorized` 301,776 with intrinsic and calldata |
| `mldsa87` | 8,850,000; 8.85 M | 250,000 PROVISIONAL; ≈ 140 k execution (reset 4 T-GAS) |

Verify-only adds the chain's `kindOf` and the key read where the record lives, ≈ 8–15 k for one hop [estimate], plus ≈ 5 k
per further generation passed (§11), and drops today's forwarding hold (`cap/63 + GAS_MARGIN`). Calldata is the same on both
paths (an ML-DSA-65 signature is 53–132 k gas of calldata). A `{mldsa65 ×3} t=2` treasury `msig`, unregistrable at the cached
cap (2 × 5.95 M + holds > 12 M), fits a gen 2 whose `mldsa65` is verify-only on a precompile (its fallback case does not:
§5).

## 14. Work list

| Component | Work |
|---|---|
| Contracts | `KindConfig.verifyOnly`, `keyForm`, bits 224 / 225, constructor rules incl. the impossible combination (§2); `verifierOf(kind)`; `UAVerifyOnly`, `verifyOnly(kind)`, `_listedHere`, `expandedKeyOf` forwarded (§3); R2: `_memberOk` `via(_pred())` / `via(holderOf)` when `!here`, `_single`'s host path unchanged, `_pqzHolder` and `_slotCap`'s `gen1` mode (§3); `_authorized`, `_derived`, `requireAuthorized`'s `UAKeyNotCached`, `requirePortable(App)`, the library's `_portable` / `_memberOk` / `_notCached` / `_slotCap` on the holder's record and keys from the consumer entries only (§4); failed reads ⇒ `UAVerifyGas` (§4); the three-state call and `PqNoAnswer`, the fallback (§5); a verify-only verifier per kind with `KEY_FORM()` and the edge-class constructor rows (§9); N generations: `generation = p + 1`, `MAX_GENERATION`, `kindHome`, `holderOf`, the group check over the line, the EIP-712 version, `kindOf` without walking for native-space ids (§11); `OpenFactory`'s env check (§10); `IUARegistry` doc comments; size baseline |
| Tests | T-REG-4 changed: a later generation refuses a kind a predecessor enables unless flagged verify-only, refuses the flag otherwise, refuses the impossible key form, refuses its registration (`UAVerifyOnly`) and its `cacheExpandedKey`, forwards its lists and `expandedKeyOf`; `UAKeyInUse` across the line. New: §7 (a)–(d) per eligible kind (ML-DSA first); every path of §4's table; R2: a gen-2 stand-in verifier that accepts everything cannot pass a host `setPqzKey` / `setPqzScopedKey` for a gen-1 single key or `msig` holder; §5: no-answer stand-ins (empty account, revert, malformed returndata, out of gas at the cap) fall back, an answer 0 does not, gas below the cap is `UAVerifyGas`; ML-DSA with gen 1 on the cache and gen 2 on a precompile stand-in (form `0`), gen 2 under form `1` (incomplete cache ⇒ `UAKeyNotCached`); three generations (gen 3 over gen 2 over gen 1: lookups, writes by the holder, groups, lists, the PQZ host); the depth cap; the factory walk (accept the line, refuse another chain's and a non-registry); T-GAS with verify-only `msig` members at the budget and per hop; T-AUTH-4 on the new path; storage layout and typehash pins unchanged |
| Deploy | the later-generation mode of `DeployBase` with the book's latest as predecessor (`GEN_NOT_LATEST`, `GEN_DEPTH`, `GEN2_KEY_FORM_IMPOSSIBLE`); the differential probe through the node list under strict majority, the holder entry per kind (§9); the book fields (§9); `script/pq_verifiers.py` and `DeployBase._mldsaCandidates`: default candidates Final + chain-own only, Draft only under the profile flag with the fuller probe (CTR-UA-69); the verify-only verifiers; the probe re-run after client upgrades in the operations runbook |
| Node | `ua_registries` and its on-chain validation; the guard per registry, `UA_VERIFY_ONLY`, `UA_WRONG_GENERATION`; NODE-JOB-29's target and `UA_KEY_NOT_CACHEABLE`; the indexer over every generation and the PQZ host (§12); a note for operators |
| SDK | write targets `kindHome` / `holderOf`; verify rows keyed by chain, registry and kind with the path and hops as columns; reference table rows (§12) |
| Clients | `verifyOnly` / `kindHome` before offering a kind; the release's registry and verify path in the review (§12) |
| Docs | [accounts.md](../../contracts/accounts.md) §1.8 "Generations" and §1.9, T-REG-4's row, CTR-UA-05's "a registry generation supports a fixed set of kinds" (a verify-only kind is verified, not supported for registration), CTR-UA-29's per-generation lists; the chain profiles (chain-own precompiles, the Draft flag, the keep commitment); `decisions.md` entry with §0; node config doc; SDK spec; §15's conflicts |

## 15. Conflicts to change on landing

| Where | Today | After |
|---|---|---|
| [admin-not-owner §13.4](2026-11-10-admin-not-owner.md) | "A stack with its own registry has its own router and its own factory, so one registry per factory holds"; every env publish refuses an `env.registry` other than 0 or the router's registry | one registry **line** per factory: an env may name the router's registry or a registry whose predecessor chain reaches it, same `chainUid` (CTR-UA-67) |
| [accounts.md](../../contracts/accounts.md) §1.9 "Generations" | "at most two generations per chain"; gen 2 enables only kinds and groups absent from gen 1 | a line of up to `MAX_GENERATION` generations (CTR-UA-70); a later generation may carry a predecessor's kind verify-only (CTR-UA-58) |
| [accounts.md](../../contracts/accounts.md) §1.8 "Generations" | gen 2 forwards views to gen 1; "Indexers read both generations" | lookups walk the line; indexers read every generation (CTR-UA-65) |
| `script/pq_verifiers.py`, `DeployBase._mldsaCandidates`, [evm.md](../../networks/evm.md) | `0x12`–`0x14` probed first | Final and chain-own by default; Draft under the owner-confirmed flag (CTR-UA-69) |

## 16. Open questions for the owner (proposals, not rulings)

The questions of revision 1 (Q1 – Q11) are ruled (§0.2). The author's proposals that no ruling names:

| # | Question | Proposal |
|---|---|---|
| P1 | Is key form `1` (reading the holding generation's existing ML-DSA cache, §2) within R3? R3 allows forms derived per call and forbids a gen-2 cache; reading the holder's cache is neither. | Allowed: it writes nothing in gen 2 and the cache is filled in the holder by anyone. Without it an EIP-8051 precompile can never serve an ML-DSA kind (per-call expansion does not fit, §6). If refused, bit 225 is fixed at `0`. |
| P2 | The three-state answer (§5) | A verify-only verifier reverts `PqNoAnswer()` on no answer (call failed, returndata not exactly one word 0 / 1); the registry falls back on any revert of the verifier call, never on word 0. |
| P3 | Does `_slotCap` count the fallback? | No: it counts the normal path, so a verify-only `msig` that needs the precompile can register; its fallback case fails closed with `UAVerifyGas` (§5, §13). |
| P4 | Factory clone-hash check (§10) | Require `smartKeyCloneHash()` of the env's registry to equal the router's, so §13.4's `SmartKeyAccount` binding holds for every generation an env names. |
| P5 | New views and the native-id shortcut (§11) | Views `kindHome(kind)`, `holderOf(ua)`, `verifierOf(kind)`; native-space ids answered `kindOf = 0` without walking. |
| P6 | Names | errors `UAVerifyOnly(uint16)`, `PqNoAnswer()`; deploy refusals `GEN2_KEY_FORM_IMPOSSIBLE`, `GEN_DEPTH`, `GEN_NOT_LATEST`; node names `UA_VERIFY_ONLY`, `UA_WRONG_GENERATION`, `UA_KEY_NOT_CACHEABLE`; profile flag `probe_draft_precompiles`. |

## Sources

Fable review of revision 1 (2026-11-19; private scratchpad, not in the repo). [accounts.md](../../contracts/accounts.md) §1.8
(registration, "Generations", Relaying), §1.9 (verifiers, per-chain enablement,
[gen-1 kind gate](../../contracts/accounts.md#gen1-kind-gate)), [CTR-UA-23](../../contracts/accounts.md#CTR-UA-23),
[CTR-UA-29](../../contracts/accounts.md#CTR-UA-29), [CTR-UA-33](../../contracts/accounts.md#CTR-UA-33),
[CTR-UA-46](../../contracts/accounts.md#CTR-UA-46); [2026-11-15-mldsa-precompile-cache.md](2026-11-15-mldsa-precompile-cache.md)
(MD-2, MD-10, MD-13, MD-15); [2026-11-10-admin-not-owner.md](2026-11-10-admin-not-owner.md) §13.4;
[2026-11-19-bls12381-multi.md](2026-11-19-bls12381-multi.md); [plan P6f](../plans/2026-10-14-p6f-precompiles.md) (EIP-8355 pin);
[ARCH-POS-15](../../decisions.md#ARCH-POS-15), [ARCH-POS-18](../../decisions.md#ARCH-POS-18). Code at `a19151d64`:
`smartcontracts/evm/src/ua/UARegistry.sol` (constructor, `kindOf`, `keyOwner`, `recordOf`, `_elsewhere`, `_authorized`,
`_derived`, `_memberOk`, `_listedHere`, `_groupInPredecessor`, `expandedKeyOf`, `requirePortable`, `requirePortableApp`),
`UARegistryCoreLib.sol` (`_identify`, `_pqzHolder`, `_msigDebit`, `_portable`, `_single`, `_notCached`, `_memberOk`,
`_slotCap`, `uaCount`), `UARegistryAuxLib.sol` (`_portableOk`), `UAStore.sol` (`expanded`, `noPrecompile`, `capped`, `via`),
`MlDsa.sol` (`MldsaVerifier`: `verify`, `expandedKeyPart`, `verifyCached`, `verifyExpanded`), `FnDsa.sol` (the norm bound),
`UAKinds.sol` (`inNativeSpace`), `src/factory/OpenFactory.sol` (`uaRegistry`, the env check, `EnvRegistryMismatch`,
`configureChain`), `src/metatx/MtxPipelineLib.sol` (`_checkTo`), `script/DeployBase.sol` (`_deployUARegistry`, `_pqKindFits`,
`_mldsaCandidates`), `script/pq_verifiers.py`; `scaas-node/src/main.rs` (`ua_registry`), `guard.rs` (`Rule::UaRegistry`,
`UA_KEY_NOT_CACHED`), `indexer.rs` (`pay_filter`).
