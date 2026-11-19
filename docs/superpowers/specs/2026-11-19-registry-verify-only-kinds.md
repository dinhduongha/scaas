# Spec: a registry generation 2 that verifies generation-1 kinds ("verify-only kinds")

2026-11-19. **Revision 3**: every finding of the Fable fix-check of revision 2 (Fable, high effort, verdict "build after
fixes", P0 0 / P1 1 / P2 6 / P3 9, N1 – N16, positions on P1 – P6; file in the private scratchpad, not in the repo) applied, and
the owner's rulings of 2026-11-19 on it recorded in §0.3. Revision 2 applied the Fable review of revision 1 (F1 – F17) and
recorded the owner's rulings on it (§0.2). Status: **SPECIFIED**, nothing built. Everything cryptographic stays
**UNAUDITED**. Scope: **EVM** (the contracts, the factory, the deploy, the node, the SDK and clients); the other families take
the principle in their own rounds (§12, PLANNED).

Rule ids `CTR-UA-58` … `CTR-UA-72` are **placeholders**: the highest id defined is `CTR-UA-46`, and
`2026-11-19-bls12381-multi.md` holds `CTR-UA-47` … `CTR-UA-57` (placeholders too); landing assigns the real ones, writes the
[decisions.md](../../decisions.md) entry with §0 verbatim and moves the rules into [accounts.md](../../contracts/accounts.md).
Rows marked **owner** are the owner's ruling; **follows** applies a stated rule or a fix-check finding as the fix-check states
it; **proposal** is the author's and is listed in §16 for the owner. Despite the title, the design covers every later
generation (§11): "gen 2" below reads "a later generation", "gen 1" "the generation that holds the record", unless a section
says otherwise.

The work list (§14) is written against the registry's library layout of branch `bls-multi` (owner-approved, in progress):
`UARegistryRegLib` holds every `register*` form and the registration helpers (`keyUa`, `pqzHolder`, `msigBound`,
`pqzProof`); `UARegistryCoreLib` keeps the authorization and verify paths; `UARegistryAuxLib` keeps the PQZ attachment, the
KEM records, `cacheExpandedKey` and the list pages; `UARegistry` keeps the constructor, the views and the walks.

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

### 0.2 Rulings on the review of revision 1 (owner 2026-11-19)

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
| R2 (F2) | Who authenticates writes | one rule: **every write is authenticated by the generation that holds the record**: a gen-1 record's `setPqzKey` / `setPqzScopedKey` and any other write go to gen 1; a gen-1 `msig` holder's derived members `via(_pred())`; §13 corrected. Revision 3: the target is `holderOf` (W1, W2 below), and the rule reads "every signature-authenticated write" (N14) | **owner**; §3, §4 |
| R3 (F5) | Key form | an explicit key-form bit per verify-only kind, checked in the constructor; only key forms the verifier can **derive per call** within its gas cap are allowed; no cache in gen 2 ("gen 2 writes nothing"); a form that cannot be derived per call makes the kind ineligible; the deploy refuses the impossible combination by name. Revision 3: reading the holder's existing ML-DSA cache (key form `1`) is allowed too (P1, §0.3) | **owner**; §2, §6 |
| R4 (Q10, F6) | Fallback | when gen 2's verifier gives **no answer** (no code at the precompile, revert, out of gas), gen 2 falls back to gen 1's verdict; **never** when it answers 0 (invalid). A relayer forcing out-of-gas only gains gen 1's (sound) path at more gas: stated and bounded | **owner**; §5 |
| R5 (Q7, F15) | Strictness | gen 2 is **never laxer** than gen 1; a difference found by the equivalence tests or the deploy probe goes to the owner with its rows (no automatic refusal, no automatic acceptance); equivalence is defined modulo gas (F3) | **owner**; §7 |
| R6 (Q1, F7) | Gen-1 `msig` | gen-1 `msig` records stay on gen 1's verifiers; the reason is that a registered gen-1 `msig` cannot register in gen 2 (`UAAlreadyRegistered` via `_kindOf`) | **owner**; §4 |
| R7 (Q2, F10) | Sibling verify-only generation | none. A gen 2 deployed after a qualifying precompile exists enables the verify-only kinds in the same deploy. The case "a gen 2 deployed for new kinds before the precompile" was left to a later gen-3 design; R10 now covers it (§11) | **owner**; §9, §11 |
| R8 (Q3 – Q6, Q8, Q9) | As proposed, with the review's additions | Q3 `KindConfig.verifyOnly` + the key-form bit; Q4 `UAVerifyOnly`, `verifyOnly(kind)`, and `expandedKeyOf` forwarded (F12); Q5 every single-key kind, each eligible only with its own edge-class list and vectors, ML-DSA first; Q6 a Final EIP address or the chain profile's own precompile; Q8 `ua_registries` validated on chain, order carries no meaning, plus F9's node rules; Q9 SDK verify rows keyed by chain, registry address and kind, the verify path a column | **owner**; §2, §3, §6, §12 |
| R9 | Probe of Draft addresses ("the middle way") | `script/pq_verifiers.py` (gen 1's ML-DSA verifiers today, and gen 2's) probes by default only Final EIP addresses and the precompiles the chain profile declares as the chain's own (`0x…5caa…` on the SCaaS chains). A Draft address (EIP-8355's `0x12` / `0x13` / `0x14`) is probed only when the chain's profile sets an explicit flag, confirmed by the owner per chain and recorded in the deploy book, and then with a fuller probe: the valid row, a flipped row and the edge-class vectors | **owner**; §9 |
| R10 | N generations | a registry takes as predecessor the chain's **latest** generation (any n ≥ 1) and is generation n + 1; one registry code serves every generation; lookups walk back to the generation that holds the record, under a fixed depth cap; R2 generalises to N; a generation may re-enable as verify-only a kind any predecessor enables; keyHash groups stay with the generation that first enabled them, checked across the whole chain; a sibling generation (Q2) is unnecessary; the factory binding becomes a bounded walk to the router's registry; node `ua_registries` the ordered chain, validated on chain | **owner**; §11 |
| R11 | Depth cap | the line of generations is capped at **16**: a deploy of generation 17 is refused by name | **owner**; §11 |

### 0.3 Rulings on the fix-check of revision 2 (owner 2026-11-19)

The owner on the fix-check's two decisions and its positions: **"Approved both as proposed"**; **"approved all as
proposed"**.

| # | Topic | Ruling | Where |
|---|---|---|---|
| W1 (N1, severity P1) | Member signatures on writes | option (b): member signatures on **write** paths (the registration PoP, `acceptMembership`, `updateMsig`, `setPqzKey` / `setPqzScopedKey` of an `msig`, any signature-authenticated write) are verified by `holderOf(member)`, the generation holding that member's record, never by a verify-only verifier; verify-only runs only on consumer entries. The gas cost is stated (writes pay the holder's path; the treasury example ≈ 2 × 5.95 M), and `msigBound` counts that path against 2^24 (refuse or flag an `msig` whose write path cannot fit, numbers to the owner per [ARCH-POS-18](../../decisions.md#ARCH-POS-18)). Test: an accept-all stand-in verifier against each write | **owner**; §3, §4, §14 |
| W2 (N6) | PQZ host over N generations | do **not** accept that later-generation UAs can never hold a PQZ key. Redesign the PQZ host for N generations: a later generation may host the PQZ attachment of its **own** records (enable `0x0142` for them); the `pqz-mlwe` keyHash group uniqueness is checked across the whole line (walk); the spec states the rule per position (`_pqzHost`, `_host`, `_away`, `_scopedFrom`, `_pqzRecord`, `pqzKeyLatest`, `_kemHash`, the per-kind lists and decoys), with three-generation tests, and marks what changes in today's A5-I1 rule | **owner**; §11.2 (`CTR-UA-71`) |
| W3 (N7 i) | Views on every generation | gen 1 carries the new views (`holderOf` returning the kind too, `kindHome`, `verifierOf`, a forwarding `expandedKeyOf`) from now (pre-freeze; the SCaaS testnet redeploys at its next reset); every generation's constructor probes them on its predecessors | **owner**; §11.3 (`CTR-UA-72`) |
| W4 (N7 ii) | Frozen interface | the walked selectors are listed and pinned as a frozen interface | **owner**; §11.3 |
| W5 (N7 iii) | Trust in predecessors | every generation trusts its predecessors fully; the deploy compares every address and code hash on the walk with the deploy book; `GEN_NOT_LATEST` can be overridden only with the owner's confirmation recorded in the book | **owner**; §9, §11.3 |
| P1 | Key form `1` | accepted: reading the holder's existing ML-DSA expanded-key cache, with the fix-check's conditions: byte-level layout equality or a counted transform, as an equivalence class of §7; N8 (the home's verifier decides the impossible combination); the F13 wording | **owner**; §2, §4, §6, §7 |
| P2 | Three-state answer | accepted: fallback on any revert of the verifier call, never on word 0, with N5: the verifier owns the mapping of its precompile to {1, 0, `PqNoAnswer`} | **owner**; §5 |
| P3 | `_slotCap` and the fallback | accepted: `verifyBudget` counts the normal path, **plus a hard bound** per N1: the fallback and the write path must fit one 2^24 transaction | **owner**; §4, §5 |
| P4 | Factory clone-hash check | accepted: `smartKeyCloneHash()` of the env's registry equals the router's; cost stated: the `SmartKeyAccount` implementation is frozen for the factory's line | **owner**; §10 |
| P5 | Views and the native-space shortcut | accepted, with `holderOf` returning the kind, the views in the frozen list, the shortcut on `kindOf`, `holderOf` and `isRegistered`, and a test that no registration stores a native-space id | **owner**; §11 |
| P6 | Names | accepted, with `GEN2_KEY_FORM_IMPOSSIBLE` renamed generation-neutral: **`GEN_KEY_FORM_IMPOSSIBLE`** | **owner**; §2, §16 |

Every other finding (N2 – N5, N8 – N16) is applied as the fix-check states it (**follows**); a detail it leaves open is a
**proposal** in §16. The rules `CTR-UA-58` … `-72` below write these rulings out.

## 1. The code today (`ua-rs-sign` `a19151d64`)

| Where | What it does | Why it blocks V1 |
|---|---|---|
| `UARegistry` constructor | `p.generation() != 1` ⇒ `UAConfig(0)`; `_groupInPredecessor(pred, kind)` reverts `UAConfig(kind)` for any kind whose keyHash group a gen-1 kind enables, `0x0142` included | at most two generations; a kind gen 1 enables cannot be configured at all; `0x0142` in one generation only |
| `UARegistry.KindConfig` | `{uint16 kind; address verifier; uint64 cap}`, stored as one immutable word `verifier \| cap << 160` per slot (bits 224–255 unused) | no way to declare "verify only" or a key form |
| `UARegistry._authorized` | `kind == 0` (record not held here) ⇒ `UAStore.via(predecessor, …)`: gen 1 checks with gen 1's verifier | a gen-1 record never meets gen 2's verifier |
| `UARegistry._derived` | for a stored kind or purpose `member`, reads `_s.records[id]` only; `r.kind != kind` ⇒ `false`; a kind not enabled here ⇒ `via(predecessor)` | a gen-2 `msig`'s member held in gen 1 would be refused; a hop by hop hand-off (N3) |
| `UARegistry._memberOk` | an `msig` member not held here ⇒ `via(predecessor)` | hop by hop (N3) |
| `UAStore.expanded`, `expandedKeyOf` | this generation's ML-DSA cache only; `_derived` prefers the cache whenever one is there; `expandedKeyOf` is not forwarded | gen 1's cache is invisible through gen 2 |
| `requireAuthorized` (`UAKeyNotCached` branch), `UARegistryCoreLib._notCached` | read `_s.records[ua].kind` | no named refusal for a gen-1 record |
| `UARegistry.requirePortable` / `requirePortableApp` | `_elsewhere(ua)` ⇒ forward to gen 1; `UARegistryCoreLib._portable` refuses `r.kind == 0` | portable and app purposes of a gen-1 record never meet gen 2's verifier |
| `UARegistryCoreLib._single` (host writes) | `cfg == 0` (the local record's kind, 0 for a gen-1 record) ⇒ `UAStore.via(_pred(), …)`: a gen-1 holder's `setPqzKey` / `setPqzScopedKey` on a gen-2 host is checked by gen 1 (ruling A6-I1) | must reach the holder directly (R2, N2) |
| `UARegistryCoreLib._memberOk` | a derived member goes through `UAStore.via(address(this), …)` on every path, writes included, also for a gen-1 `msig` holder on the host (`here == false`) | after V1 it would reach a verify-only verifier on a write (N1) |
| `UARegistryCoreLib._pqzHolder` | A5-I1: `UAKindDisabled(0x0142)` when the predecessor enables `0x0142`; a gen-1 single-key holder counts `IUARegistry(g1).verifyCap(kind)` (MD-13) | the bound must count the path the write pays; A5-I1 bars every later generation's records from PQZ (N6) |
| the PQZ attachment (`UARegistry._pqzHost`, `pqzKeyOf`, `pqzKeyLatest`, `recordOf`, `checkedOf`; `UARegistryAuxLib._host`, `_away`, `_scopedFrom`, `_pqzRecord`, `_pqzNext`, `_kemHash`, `registrationOf`) | written for two generations: the host is "a gen 2 with `0x0142`", the holder is "the predecessor" | N6, §11.2 |
| `UARegistry._listedHere`, `UARegistryCoreLib._listedHere` | a kind with a verifier word here is listed here | lists of a verify-only kind would read gen 2's empty list |
| `UARegistryCoreLib._identify` | step 1 `UAKindDisabled` only when the verifier word is 0; `_kindOf(ua) != 0` ⇒ `UAAlreadyRegistered` (forwarded to gen 1) | a verify-only kind would register in gen 2; a gen-1 `msig` cannot re-register in gen 2 |
| `UARegistryCoreLib._slotCap` | `verifyCap(kind) == 0` ⇒ the member is handed to gen 1 (`IUARegistry(self.predecessor()).verifyCap(kind)` + `cap/63 + GAS_MARGIN`) | must count a verify-only member's own path; 0 when the predecessor does not carry the kind (N3) |
| `kindEnabled(kind)` | true iff a verifier word is set; clients read it before offering a kind for registration ([§1.9](../../contracts/accounts.md#verifiers)); also asked of the predecessor by `_groupInPredecessor`, `_pqzHolder` and `PqzStateLib._auditorChecks` | two meanings once a line exists (N4) |
| `OpenFactory.uaRegistry()`, `publishTokenEnv` / `publishDexEnv` / `publishClassEnv` | `uaRegistry()` is the router's `registry()`; an `env.registry` other than 0 or that value reverts `EnvRegistryMismatch` (`OpenFactory.sol`, the env check); `configureChain` runs once | no release can bind gen 2 on a factory with a router (F1) |
| `DeployBase._deployUARegistry`, `_mldsaCandidates`; `script/pq_verifiers.py` | gen 1 only; the ML-DSA candidates are probed in the order EIP-8355's `0x12` / `0x13` / `0x14` (Draft), then `0x…5caa0012` / `13` / `14` | no gen-2 path; a Draft address is probed first (R9) |
| node | one `[[chains]] ua_registry` (`main.rs`); the nine registry writes target it only ([NODE-JOB-19](../../node/job-api.md#NODE-JOB-19)); the guard's `Rule::UaRegistry` is that one address; the indexer reads one registry, PQZ key-version events included (`indexer.rs`, `pay_filter`); `UA_KEY_NOT_CACHED` is never `dead` ([NODE-JOB-29](../../node/job-api.md#NODE-JOB-29)) | §12 |

## 2. Which kinds, and how they are declared (`CTR-UA-58`)

**CTR-UA-58 (owner R8 Q3 / Q5, R3, P1, P6; details proposal).** A later `UARegistry` may carry a kind **verify-only**: a
**single-key** kind of the kind table that a predecessor enables. One rule for every such kind (the signing kinds, PQ
`0x0130`–`0x0135`, the group kinds `0x0110`–`0x0113`, `zether-bls12381` `0x0141`), but a kind is **eligible** only once its
edge-class list and vectors exist (§7); ML-DSA (`0x0130`, `0x0131`, `0x0134`) first. Never `msig` `0x0120` (a structure: each
generation re-enables it in full, §1.8 "Structures"; a predecessor's `msig` record stays forwarded whole, §4), never
`pqz-mlwe` `0x0142` (not a kind: its proof check is a write of the PQZ attachment, ruling A6-I1; §11.2 lets a later
generation enable it in full for its own records, never verify-only). `bls12381-multi` `0x0121` is left out of this build
(F16): its spec is not built; its rows (stored form `p`, `verifyMinimal`) are added when that kind lands.

- **Declaration.** `KindConfig` gains `bool verifyOnly` and `uint8 keyForm`; the constructor stores them as bit 224 and bit
  225 of the kind's word. The word reaches the libraries as today (`_lib`'s appended `_cfg(kind)`), so they need no getter.
  **Every reader masks (N12).** Two helpers replace the raw reads: `_capOf(cfg) = uint64(cfg >> 160)` and
  `_registrable(cfg) = uint160(cfg) != 0 && cfg >> 224 & 1 == 0`; `verifyCap` keeps `uint64(word >> 160)`. The sites are
  listed in §14 (an unmasked `cfg >> 160` with a flag bit set is above 2^64 and turns every check into `UAVerifyGas`;
  `uint160(cfg) != 0` alone would read "registrable here" for a verify-only kind).
- **Key form (R3, P1).** Bit 225 states which key form the registry hands the verifier; the constructor requires it to equal
  the verifier's own getter `KEY_FORM()` (new on verify-only verifiers):
  - `0` **stored**: the bytes the holding generation's code passes on that path (§4 "Key bytes"). Any other form the
    verifier needs (an EIP-8051 expanded key, an EIP-8052 NTT-domain Falcon key, a 32-byte `tr`) it **derives per call**
    from those bytes, inside its own cap; the measured cost of the derivation is part of the cap (§13 Gas).
  - `1` **holder's cache** (owner P1): the holding generation's complete ML-DSA expanded-key cache, read through the
    holder's `expandedKeyOf` (§3) and passed as `verifyCached` takes it. Allowed only (a) where the kind's home verifier is
    on the cache path, so the cache can be filled there by anyone, and (b) where the bytes of the holder's parts,
    concatenated, are exactly the input the new verifier's precompile consumes (byte-level layout equality, pinned by a
    test), or the verifier transforms them inside its cap with the transform's measured gas counted in the cap and the
    transform an equivalence class of §7 (own vectors, own mutant). Gen 2 never caches (R3).
  - **Impossible combination** (refused by name): form `1` where the kind's home verifier has a precompile (its
    `cacheExpandedKey` reverts `UAKeyCache`, so no cache can exist), or a form that cannot be derived per call within the
    cap. The constructor reverts `UAConfig(kind)` when bit 225 is `1` and
    `IUARegistry(IUARegistry(predecessor).kindHome(kind)).verifierOf(kind)` reports `PRECOMPILE() ≠ 0` (N8: the **home's**
    verifier, never a middle generation's verify-only verifier, which always has a precompile); the deploy refuses before
    broadcast with **`GEN_KEY_FORM_IMPOSSIBLE <kind>`** (owner P6).
- **A verify-only verifier has a working precompile (N16, proposal).** Its constructor probe sets `PRECOMPILE`; a
  verify-only verifier whose probe failed (`PRECOMPILE() == 0`) would answer `PqNoAnswer` on every call (§5), so the
  registry constructor refuses it, `UAConfig(kind)`, and the deploy first by name (`GEN_VERIFY_ONLY_NO_PRECOMPILE <kind>`).
  A Solidity-only verify-only verifier is not allowed: it adds a second verifier of the same kind and no capability the
  holder lacks ([ARCH-POS-18](../../decisions.md#ARCH-POS-18) is served by the holder's software path).
- **Constructor (N4).** `UAConfig(kind)` unless `verifyOnly ⇔ IUARegistry(predecessor).kindHome(kind) != 0` (`kindHome`
  answers for the line, `kindEnabled` stays local, §3): a verify-only flag on generation 1, on a kind no predecessor enables,
  or on `msig` / `0x0142` is refused; a kind a predecessor enables without the flag is refused as today. A verify-only kind
  is exempt from the group check (its group **is** the home's and stays there); every other kind keeps it, across the whole
  line (`_groupInPredecessor` asks `kindHome(j) != 0` of the predecessor for each `j` of the group); `0x0142` is the one
  exception (§11.2). The existing predecessor checks stay (`chainUid`, `hederaNative`, `checkedOf`, `memberSigHashOf`,
  `msigStateOf`; `generation()` as §11), with the new views' probes of §11.3. The cap is the generation's own measured cap,
  `0 < cap ≤ verifyBudget` as every kind, and the deploy's 75 % rule (`_pqKindFits`) applies.
- **The keyHash group stays where it is.** A later generation writes no `keyOwner` for a verify-only kind and reads
  `keyOwner` through its predecessors as today.

## 3. Writes, refusals and views (`CTR-UA-59`)

**CTR-UA-59 (owner R2, W1, R8 Q4; N4, N14 follow; details proposal).** **Every signature-authenticated write is
authenticated by the generation that holds the signer's record**, wherever the write is stored: a single-key signer by
`holderOf(ua)`, each member of an `msig` by `holderOf(member)` (W1). A generation's verifier of a verify-only kind
authenticates **no** write: it serves only the consumer entries of §4. So a forgery accepted by a verify-only verifier changes
no registry state, in any generation. Permissionless writes have no signer: `cacheExpandedKey` (the key is authenticated by
its id) and the proof stores `storePqzPop` / `storePqzScopedPop` (checked by a proof, at the record's PQZ home, §11.2) (N14).

- **Registrations.** `register`, `registerWebAuthn`, `registerMuSig2`, `registerFrost` of a verify-only kind revert
  **`UAVerifyOnly(uint16 kind)`** (new, named: "register in the generation that enables it", `kindHome(kind)`, §11) at step 1,
  before any other check (`UARegistryRegLib`'s step 1 tests `_registrable(cfg)`, then the flag).
- **`cacheExpandedKey(kind, …)`** of a verify-only kind reverts `UAVerifyOnly(kind)`: the cache is filled in the holding
  generation (open to anyone, as today).
- **Key writes held in the holding generation** (`setKemKey`, `acceptMembership`, `updateMsig`) keep today's rule:
  `UAUnauthorized` on a generation that does not hold the record.
- **Writes of the PQZ attachment** (`setPqzKey`, `setPqzScopedKey`; and the permissionless `storePqzPop`,
  `storePqzScopedPop`) are stored at the record's PQZ home (§11.2); the signature of a signed one goes to the holder.
  Single key: `_single` with the local word `cfg == 0` forwards to **`holderOf(ua)` directly**, never through
  `predecessor` (N2: a middle generation that carries the kind verify-only would otherwise answer with its verify-only
  verifier). An `msig` signer, held here or in a predecessor: its derived members go `via(holderOf(member))`, never
  `via(address(this))`; its native members keep the holder's clone hash.
- **Member signatures on writes (W1).** `UARegistryCoreLib._sigOk` / `_msig` / `_memberOk` take a flag `write` beside
  `here`: on a write (the registration PoP `_consent`, `acceptMembership`, `updateMsig`, `setPqzKey` / `setPqzScopedKey` and
  `setKemKey` through `_portableOk`, any other `_sigOk` caller) a derived member goes `UAStore.via(holderOf(member), …)` and
  its holder checks it under its own verifier; only the consumer entries (`requireAuthorized`, `requirePortable`,
  `requirePortableApp`, and `_portable` under them) pass `write = false` and may take the verify-only path of §4. Where the
  member's kind is enabled here, `holderOf(member) == address(this)` and nothing changes.
- **Cost of W1.** A write pays the holder's path: the treasury `msig` `{mldsa65 ×3} t=2` of §13, with gen-1 members on the
  cache, pays ≈ 2 × (5.95 M + 5.95 M / 63 + 5 k) + the reads ≈ 12.3 M per `updateMsig`, `acceptMembership` round or PQZ
  key write [estimate], against ≈ 2 × 0.25 M on the consumer path. The write bound of §4 counts it against 2^24.
- **Bounds of those writes (F8, W1).** `_pqzHolder` counts what the write pays: a single-key holder held elsewhere
  `verifyCap(kind)` of `holderOf(ua)` plus one hand-off hold (the write goes there directly); an `msig` holder its members at
  their holders' caps (the write mode of §4's bound).
- **Views (N4).** `kindEnabled(kind)` stays **local** (a verifier word is set here, a verify-only kind included); new views
  **`verifyOnly(uint16 kind) → bool`** and **`kindHome(uint16 kind) → address`** (§11). Every line-wide question is
  `kindHome(kind) != 0`; a client offers registration of a kind on a registry only where `kindHome(kind) == registry`.
  `uaCount` / `uaAt` / `uaPage` / `uaIndex` of a verify-only kind forward to the home (`_listedHere` is false for it, in
  `UARegistry` and `UARegistryCoreLib`). **`expandedKeyOf(ua)` forwards** to `holderOf(ua)` for a record this generation
  does not hold (F12), so the node and clients read the cache where it is and never try to fill it on a verify-only
  generation. `kindOf`, `recordOf`, `keyOf`, `registrationOf` and the other readers forward as §11. A generation emits no
  event for a verify-only kind.
- An `msig` registered in a later generation may name a predecessor's members of a verify-only kind (`kindOf(member) ==
  memberKind` through the line, as today).

## 4. The authorization path (`CTR-UA-60`)

**CTR-UA-60 (proposal, within V1 / V3, R2, R6, W1; N3, N10, N11 follow).** One rule for a consumer entry of generation `k`
that checks a signature of a record it does not hold: read `(holder, kind) = holderOf(ua)` once; **if `kind` is verify-only
here, verify with this generation's verifier**, under its own `verifyCap` and the caller's hold (T-AUTH-4), with the
fallback of §5; **else hand the check to `holder` directly** (N3), never to `predecessor`: a middle generation that carries
the kind verify-only is never asked on behalf of a later one, and holds do not stack per hop.

| Path | Today | Verify-only here | Kind not carried here | Fallback entry on the holder (§5, N10) |
|---|---|---|---|---|
| `requireAuthorized`, the signer (`_authorized`) | `via(predecessor)` | `_derived` with the holder's key | `via(holder)` | `requireAuthorized(ua, purposeTag, digest, auth)`, the caller's `auth` unchanged |
| `requireAuthorized`, this generation's `msig`'s member at either level (`UARegistry._memberOk` → `_derived`, purpose `member`) | `false` (unreachable: no shared kind) | as the signer, purpose `member`, `keyData` empty ([CTR-UA-33](../../contracts/accounts.md#CTR-UA-33) B); the member's kind is `holderOf`'s (test) | `via(holder)` | `requireAuthorized(member, PURPOSE_MEMBER, md, UASig("", sig, []))` |
| an inner `msig` member held elsewhere (`UARegistry._memberOk`) | `via(predecessor)` | n/a (forwarded whole) | `via(holderOf(id))` | n/a |
| `requirePortable` (`_portable` → `_single`) | forward to the predecessor | the library's `_portable` on the holder's record | forward to `holder` | `requirePortable(ua, purposeTag, typedDigest, auth)` |
| `requirePortableApp` | forward to the predecessor | as `requirePortable`, the purpose derived from `appId` | forward to `holder` | `requirePortableApp(ua, appId, typedDigest, auth)` (the same entry, never `requirePortable` with the derived purpose) |
| this generation's `msig`'s stored paths on a consumer entry (`UARegistryCoreLib._memberOk`, `write = false`) | `via(address(this))` | as the hot path | `via(holder)` | as the member row |
| **any write** (`write = true`): a member of any `msig` (registration PoP, `acceptMembership`, `updateMsig`, PQZ key writes), a single-key signer of a host write | `via(address(this))` / `via(_pred())` | **never**: `via(holderOf(member))` / `via(holderOf(ua))` (W1, N2) | `via(holder)` | none (the holder's own verdict) |
| a predecessor's `msig` record (any consumer path) | forwarded whole | **unchanged** (R6): forwarded whole to `holderOf(ua)`, its members use the holding generation's verifiers | the same | none |
| PoP (`PURPOSE_POP_V2`) | the holding generation at registration | never checked by a later generation; `_portable` refuses the purpose as today | | |

- **R6, the true reason.** A registered gen-1 `msig` keeps gen 1's verifiers because it cannot register in gen 2: the same
  structure is the same id, and gen 2's `_identify` reverts `UAAlreadyRegistered` when `_kindOf(ua) ≠ 0`, which forwards to
  gen 1. Only a different structure (a new id, assets moved) gets gen 2's verifiers. Evaluating a gen-1 `msig` in gen 2
  would also need gen 1's accepted bits, current structure, clone hash and `UAAuth` domain.
- **One walk (N11).** `holderOf(ua) → (address holder, uint16 kind)` is the only walk of a check: each generation answers
  for a record it holds, else asks its predecessor; the answer is two words, so nothing large is re-encoded per hop. Every
  further read (`keyOf`, `webAuthnKeyOf`, `registrationOf`, `expandedKeyOf`, `msigOf`, `memberAccepted`, …) goes to `holder`
  directly. Every `_pred()` / `predecessor` read of a record in today's code becomes a read of `holderOf(ua)` (the
  accepted bits of an inner `msig` in `_accepted`, `_msigBytes`, the PQZ positions of §11.2).
- **Key bytes.** The generation passes exactly the bytes the holding generation's code passes on that path: `keyOf(ua)`
  where it reads the key pointer (the stored kinds); `webAuthnKeyOf(ua)` for WebAuthn; `registrationOf(ua).keyData` where it
  reads its registration blob (a classical kind under purpose `member`; a group kind's full key data on the portable path,
  whose `verifyPop` runs the group check under `verifyBudget`); `auth.keyData` checked by `uaOf(kind, keyData) == ua` where
  the holder does that (a classical kind's hot path). Under key form `1` (§2), the holder's complete cache from the
  holder's `expandedKeyOf(ua)`; an incomplete one is `UAKeyNotCached(ua)` (the named refusal reads the kind from
  `holderOf`). `verifyCached` trusts its pointers ([CTR-UA-23](../../contracts/accounts.md#CTR-UA-23) MD-10): the
  generation passes only pointers read from the holder on the line of the deploy book (F13), which wrote them by its own
  `cacheExpandedKey` from the authenticated key; the trust in that line is §11.3's.
- **The entry and the DST** are the ones the holding generation's code calls for that path and purpose (`verify`;
  `verifyPop` where it calls it on the portable path, e.g. `0x0106` under its `DST_POP`; `verifyCached` under form `1`).
- **A failed read is never a verdict (F11).** `holderOf` / `keyOf` / `webAuthnKeyOf` / `registrationOf` / `expandedKeyOf`
  on a predecessor fail only by gas, given §11.3's probes; a failure re-raises `UAVerifyGas` (as `_accepted` does), and the
  reads are counted in the caller's hold.
- **Cost on other records.** Only a generation with at least one verify-only kind (an immutable bool) asks `holderOf` before
  handing on a predecessor's record; one without hands the check to `holderOf(ua)` too (N3), so it walks once as well.
- **Two bounds of an `msig` (P3, W1).**
  - **Consumer bound, `verifyBudget`** (registration step 4, `_membersWorst` / `_slotCap`, as today): a verify-only member
    counts this generation's `verifyCap(kind)` plus the reads of its record, pinned per kind at the worst case (F8):
    `holderOf` over the hops to the holder, then `keyOf` for the stored kinds; `webAuthnKeyOf` for WebAuthn;
    `registrationOf` only where nothing smaller serves, at its worst size (a FROST rest of up to 17,924 B on the portable
    path). A member of a kind not carried here counts `IUARegistry(holder).verifyCap(kind)` plus one hand-off
    (`cap/63 + GAS_MARGIN`) (N3; today `self.predecessor()`'s cap, 0 where the predecessor does not carry the kind).
  - **Hard bound, `TX_GAS_CAP` = 2^24** (new, the write mode of the same walk over the slots): for a minimal authorizing
    set, each derived member at this generation's cap plus its hold (the no-answer case) **plus** the holder's path (the
    holder's cap, one hand-off, the reads), the native members as today, plus the measured constants of the dearest write
    (`MSIG_UPDATE_GAS` and the slot rows `msigBound` counts). It covers the fallback of §5 and every write of W1 (which pay
    the holder's path only). Over it, registration refuses `UAKeyData(0x0120)` and `updateMsig` `UAMsigSlots(n)` (the
    errors of today's two bounds; proposal). Examples [estimates]: the treasury `{mldsa65 ×3} t=2` ≈ 2 × (0.25 M + 6.05 M)
    ≈ 12.6 M + constants, fits; `{mldsa87 ×2} t=2` ≈ 2 × (0.25 M + 8.99 M) ≈ 18.5 M > 2^24, refused although it fits
    `verifyBudget` on the precompile path; such structures go to the owner with their numbers (ARCH-POS-18, §16).

## 5. Fallback to the holder's verdict (`CTR-UA-68`)

**CTR-UA-68 (owner R4, P2, P3; N5, N9, N10, N13 follow; details proposal).** When this generation's verifier of a verify-only
kind gives **no answer**, the check falls back to the holding generation's verdict (the holder's entry of §4's last column,
under the holder's hold); when it **answers 0**, the check is refused and there is no fallback.

- **The verifier owns the three states (N5, P2).** A verify-only verifier maps its precompile to {`1`, `0`, `PqNoAnswer`}
  itself, per precompile, because "no answer" is not definable at the registry for every precompile (EIP-7951 `P256VERIFY`
  and `ecrecover` return empty output for an invalid signature, the same as an absent precompile; the EIP-2537 calls fail on
  a malformed point):
  1. **Lengths and encodings first**: every length, range and encoding check the holder enforces runs before the call (§7
     "Reuse the decoding"); a malformed input answers **0**, never `PqNoAnswer`.
  2. **The call**: success with exactly one word `1` (or the precompile's own valid encoding) answers **1**; exactly one word
     `0` answers **0**.
  3. **Anything else** (call failed, empty or malformed return data): the verifier re-runs its constructor's valid row (kept
     in its code) as an **alive-check**; if the precompile answers it correctly, the input was invalid and the answer is
     **0**; otherwise the verifier reverts **`PqNoAnswer()`**. The alive-check's gas is inside the cap (the cap covers the
     worst input: a failed call plus the valid row).
  The registry reads its own call: `true` accept, `false` refuse, **any revert** of the verifier call (`PqNoAnswer`, out of
  gas, anything) ⇒ fallback (P2). Today's `PqUA.callBool`, which folds every failure into `false`, stays on the holders'
  verifiers.
- **Hold on every verify-only call (N9, proposal).** The verify-only path always calls with the hold (T-AUTH-4), the group
  kinds' portable path included (today `_single` calls them with `verifyBudget` and `hold = false`): the cap is
  `verifyBudget` there, held like every other cap (≈ `verifyBudget/63 + GAS_MARGIN` ≈ 0.2 M more gas on that path).
- **The relayer cannot buy a fallback below the cap.** With that hold, the registry re-raises `UAVerifyGas` before the
  call when the caller's gas cannot cover this generation's cap plus its hold, so out of gas inside the verifier happens
  only with the full cap, i.e. a precompile repriced or gone. With the verifier's mapping, a caller-chosen input cannot
  force `PqNoAnswer` on a working precompile. If a relayer could still force a fallback, it gains only the holder's path:
  sound by definition (the holder generation is the reference), at more gas, paid by the sender of the transaction.
- **Bound.** The accepted set is the holder's set plus this generation's; with R5 (never laxer) it never exceeds the
  holder's. A stricter gen 2 that the owner confirms (§7) is not strict against a fallback: it falls back to the holder's
  verdict on no answer. The fallback costs this generation's cap plus the holder's path (e.g. `mldsa65` ≈ 0.25 M + 6.05 M
  per member on the cache). **Nothing limits a check to `verifyBudget` at run time (N13)**: `verifyBudget` bounds the
  normal path at registration; at run time the check takes what the transaction carries, up to 2^24. The hard bound of §4
  keeps every registered `msig`'s fallback within one 2^24 transaction, so the fallback fails closed with `UAVerifyGas` only
  when the transaction does not carry the gas, never for good.
- **What it fixes (F6).** A removed, moved or repriced precompile no longer locks a gen-1 UA's funds in gen-2-bound tokens:
  the holder's software path, which still works, answers ([ARCH-POS-18](../../decisions.md#ARCH-POS-18)).
- **Tests (N5).** Per verify-only verifier: a fuzz test "no caller-chosen `sig`, key or message produces `PqNoAnswer` or a
  revert on a working precompile stand-in" (the empty-on-invalid stand-in of `P256VERIFY` / `ecrecover` and a
  revert-on-malformed stand-in included), and a mutant without the alive-check (it must make that test fail); the cap
  covers the worst input (a failed call plus the alive-check), pinned.

## 6. Which later precompile a verify-only kind can use (`CTR-UA-61`)

**CTR-UA-61 (proposal, within R3 and P1).** Same kind means the same signature scheme over the same message with the same
key: a gen-1 signature must verify unchanged. The current choices fix what that is: ML-DSA and SLH-DSA sign the 32-byte
`pq_msg = keccak256(TAG(kind) ‖ ua_msg)`, **pure** (not HashML-DSA / HashSLH-DSA), with the **empty** context
([CTR-UA-23](../../contracts/accounts.md#CTR-UA-23)); ML-DSA's precompile layout is EIP-8355 as pinned at `3aea9f36`
([plan P6f](../plans/2026-10-14-p6f-precompiles.md)); `fndsa512` / `fndsa1024` are Falcon specification v1.2 with EIP-8052's
SHAKE256 hash-to-point over `ua_msg`; SLH-DSA has no EIP.

| Case | Example | Eligible? |
|---|---|---|
| 1. Only the call shape differs: address, argument order, output encoding, gas | an EIP-8355 Final at another address or with another gas schedule | **yes**: a new verifier adapts the call; key form `0` |
| 2. The precompile needs a key form derivable from the stored key | an EIP-8051 precompile on the expanded key; EIP-8052 on the NTT-domain key | **yes** only if the verifier derives the form per call within its cap (form `0`), or, ML-DSA only, reads the holder's complete cache (form `1`, owner P1, under §2's conditions); else **no** (R3), refused by name |
| 3. The algorithm differs | a precompile for HashML-DSA only; a mandatory non-empty context; Falcon FIPS 206 final ≠ Falcon v1.2 / EIP-8052 as pinned | **no**: gen-1 signatures cannot verify there; that is a new kind version (new tag, new id, re-registration: e.g. `…fndsa512.v2`, CTR-UA-23), never verify-only |

Per call, an ML-DSA-65 key expansion does not fit any cap that makes the precompile worth having (the cache was introduced
because the FIPS-key verify of ML-DSA-65 / -87 is over EIP-7825's 2^24); so an EIP-8051 precompile serves an ML-DSA kind only
under form `1`. What separates case 1 / 2 from case 3 is decided by evidence (§7), not by reading the EIP; the EIP's status
only guards the address (§9).

## 7. Equivalence (`CTR-UA-62`)

**CTR-UA-62 (owner R5 for strictness, P1 for the form-`1` class; the method is a proposal).**

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
    EIP-8355 cases, `pq_kat.json`, `pq_external.json`, `pq_signatures.json`). Under form `1`: the cache layout (P1) — a test
    that the holder's parts, concatenated, equal the precompile's expected input byte for byte for every KAT key, or, with a
    transform, the transform's rows and its mutant (one byte of the transform's output flipped must fail).
  - Falcon: the norm at `⌊β²⌋` and at `⌊β²⌋ + 1` (ground vectors made with a test key), "−0", non-zero padding, `|s2| = 2047 /
    2048`, the header byte, a `pk` coefficient `≥ q`; the EIP-8051 / 8052 KATs.
  - Classical kinds: high-S, `r` / `s` zero or `≥ n`, the `r + n < p` wrap, off-curve and infinity keys (P-256 / secp256k1);
    `S ≥ L`, small-order `A` / `R`, non-canonical encodings (ed25519); infinity and out-of-subgroup points, `DST` against
    `DST_POP` (BLS).
- **Reuse the decoding.** Where the precompile's interface allows it (e.g. EIP-8052's core on decoded inputs), the gen-2
  verifier reuses the holder verifier's decoding code unchanged and replaces only the arithmetic, so equivalence reduces to
  the core. Where an EIP leaves an encoding check to the implementation and the holder enforces it, the gen-2 verifier
  enforces it with that same code before the call (§5 step 1); the build lists these checks per kind.
- **Every entry.** `verify`, `verifyPop` (the portable path, `_single`), `verifyCached` (form `1`) are each covered.
- **Tests.** (a) Shared vectors: every row of the kind's files (valid, negative, edge classes) gives the same verdict on both
  verifiers. (b) A verifier-level differential test: the edge classes plus random mutants (each byte of `sig`, `pk`, message
  flipped; lengths ± 1; trailing bytes). On forge the precompile is absent: a stand-in at the precompile address tests the
  registry logic only; the verifier-level run against a real precompile runs on a local chain whose client has it (never the
  live testnet). (c) A registry-level differential test: for the same gen-1 record, `requireAuthorized` (signer and `msig`
  member), `requirePortable` and `requirePortableApp` under every purpose give the same verdict on gen 1 directly and on gen
  2. (d) The per-class mutants. (e) **Writes (W1, N2):** a stand-in verify-only verifier that accepts everything, against each
  write: the registration PoP of a gen-2 `msig` with gen-1 members, `acceptMembership`, `updateMsig`, `setPqzKey`,
  `setPqzScopedKey` (single key and `msig` holder, held here and held in a predecessor); each must stay refused for a bad
  signature. (f) **Three generations (N2, N3):** gen 3 over gen 2 over gen 1, gen 2 carrying the kind verify-only with an
  accept-all stand-in: a gen-1 record's host write on gen 3, and a consumer check through gen 3 that does not carry the kind,
  stay refused for a bad signature (gen 3 goes to gen 1 directly).

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

**CTR-UA-64 (owner R7 for "same deploy", W5 for the walk check; the rest proposal).**

- **Same deploy (R7).** A later generation deployed after a qualifying precompile exists for a kind a predecessor enables
  carries that kind verify-only in the same deploy (once eligible, §7). No sibling verify-only generation is deployed; a
  precompile that arrives after the latest generation is used by the next generation (§11).
- **When.** For such a kind, the new verifier finds a precompile at an address allowed by CTR-UA-69 by its constructor probe;
  the deploy's differential probe passes; its measured cap fits `_pqKindFits`; the key form is possible (§2). A probe call
  that fails refuses the deploy by name (as MD-15).
- **The constructor probe (F4).** Next to the valid / flipped pair, the verify-only verifier's constructor runs one cheap
  negative row per edge class of §7 (a few KB each, in its init code): a precompile that fails one leaves `PRECOMPILE = 0`,
  and the deploy then does not list the kind (gen 1 keeps serving it); listing such a verifier is refused by the registry
  constructor (§2, N16). The rows are part of the init code, so of the verifier's CREATE2 address: what the chain probed is
  on chain. The valid row stays in the verifier's code for §5's alive-check.
- **The deploy's differential probe (F4).** By `eth_call` against the kind's home verifier, through the chain's node list
  with the strict-majority option ([ARCH-POS-15](../../decisions.md#ARCH-POS-15)); the client versions of the nodes are
  recorded in the book. The holder entry per kind, under 2^24 per call:
  - ML-DSA, holder on the cache path: `expandedKeyPart(pk, p)` for each part (each one under 2^24 by design), concatenated,
    then `verifyExpanded(ek, message, sig)` (≈ the cached cost: 4.1 / 5.8 / 8.85 M per row); never `verify` on the FIPS key
    (over 2^24 for ML-DSA-65 / -87).
  - ML-DSA, holder on a precompile: `verify(pk, message, sig)` (≈ 0.15–0.25 M per row).
  - Other kinds: the holder's `verify` / `verifyPop` as its registry calls it, its gas measured per row; a row over the
    client's cap refuses the probe by name.
  Any difference stops before broadcast and goes to the owner with the rows (R5).
- **The walk check (W5).** Before broadcast the deploy walks `predecessor()` from the new registry's predecessor to
  generation 1 and compares **every** address and its code hash (`EXTCODEHASH`), and each library address the book records
  for it, with the deploy book's line; any difference refuses by name (`GEN_WALK_MISMATCH <generation>`, proposal). The
  predecessor must be the book's latest generation (`GEN_NOT_LATEST`); that refusal can be overridden **only** with the
  owner's confirmation, recorded in the book with the reason (W5).
- **After client upgrades (F4).** A precompile is client code; gen 2 cannot follow a change. The differential probe is
  re-run after every client upgrade on the chain as an operations check. A precompile that stops answering is covered by §5;
  one that answers differently goes to the owner with its rows (a laxer answer is the forgery row of §13).
- **How.** A later-generation mode of `DeployBase` (`_deployUARegistry` with `predecessor` = the book's latest generation,
  §11), its own libraries (new code, new addresses), the verifiers by CREATE2 from `script/pq_verifiers.py` on the real chain
  as today; the same probes (`_precompiles`, `PqPrecompileProbe`). A kind gen 1 left disabled for its budget is not
  verify-only: it is an ordinary later-generation kind under today's rule, its group being new.
- **Generation 1 carries the new views (W3).** Pre-freeze, the gen-1 code gains the views of §11.3; the SCaaS testnet's
  gen 1 is redeployed with it at its next reset. A gen 1 deployed before that cannot be a predecessor (the probes of §11.3
  refuse it, `UAConfig(0)`); all chains are test-only today.
- **Deploy book (F14).** The registry's address, generation, `predecessor` and code hash; its libraries and their code
  hashes; per verify-only kind `{kind, verifier, cap, keyForm, precompile, eip, status, probe_rows_hash, probe_rows}` (the
  constructor's rows and the differential rows run); the node list and client versions of the probe; the walk check's
  result and any owner-confirmed `GEN_NOT_LATEST` override; the router and factory that bind it (§10); the Blockscout
  verification of every one of them ([NET-EVM-12](../../networks/evm.md#NET-EVM-12)); the Draft flag of CTR-UA-69 where set.
- **Size.** Today `UARegistry` 32,477 B, `UARegistryCoreLib` 34,116 B, `UARegistryAuxLib` 33,685 B (`size-baseline.json`),
  under the 131,072 B runtime ceiling; the `bls-multi` split moves the registration code to `UARegistryRegLib` and leaves
  `UARegistryCoreLib` about 20 KB of room. The change adds to `UARegistry`, the libraries and `OpenFactory` [estimate: a few
  KB, not measured; the PQZ positions of §11.2 and the write flag are the largest part]; the baseline moves with this reason,
  old → new in the commit.

**CTR-UA-69 (owner R9).** Which addresses a PQ verifier's deploy probes, for gen 1's ML-DSA verifiers today and every later
generation's verifiers:

- **By default** only the addresses of an EIP in **Final** status and the precompiles the chain profile declares as the
  chain's own: on the SCaaS chains `0x…5caa0012` / `13` / `14` ([evm.md](../../networks/evm.md) "PQ precompiles on the SCaaS
  testnet"; the ruling cites `NET-EVM-15`, not defined on this tree, so the chain-own list gets its rule id on landing). The
  chain profile also states whether the chain commits to keep its own precompile (Q6 addition).
- **A Draft address** (EIP-8355's `0x12` / `0x13` / `0x14` today) is probed only when the chain's profile sets an explicit
  flag (`probe_draft_precompiles`, name owner P6), confirmed by the owner for that chain and recorded in the deploy book,
  and then with the fuller probe: the valid row, a flipped row and the edge-class vectors of §7.
- **Change to the existing script.** `script/pq_verifiers.py` and `DeployBase._mldsaCandidates` probe `0x12`–`0x14` first
  today; both change to the default list above, the Draft candidates added only under the flag (work list §14).

## 10. How a release binds a later generation (`CTR-UA-67`)

**CTR-UA-67 (owner R1, generalised by R10; P4).** `OpenFactory`'s env check (in `publishTokenEnv`, `publishDexEnv`,
`publishClassEnv`) accepts `env.registry` equal to 0, to `uaRegistry()` (the router's registry), **or** a registry whose
predecessor chain reaches `uaRegistry()`: walk `r = r.predecessor()` at most `MAX_GENERATION − 1` times (§11), each step a
contract, the reached registry equal to `uaRegistry()`; `chainUid()` equal (the existing `_requireChainUid`); and
`smartKeyCloneHash()` of the env's registry equal to the router's (owner P4); else `EnvRegistryMismatch(expected, got)` as
today. Checked in code, no admin key, no stored list.

- **Cost of P4.** Every generation of a factory's line must be deployed with the same `SmartKeyAccount` implementation: the
  implementation is frozen for the factory's line. A new implementation needs a new factory line. Without the check a
  `SmartKeyAccount` clone would get the 50 k ERC-1271 cap in that generation and its native members would fail (a liveness
  trap, not a forgery).
- **What it means.** `uaRegistry()` and the directory keep naming the router's registry, and the router authenticates
  governance through it (gen 1's verifiers); token operations of a release that names a later generation go through that
  generation's verifiers. One factory, one catalogue, one router.
- **Trust.** An env is published by governance, so a registry the factory accepts is one governance named; the walk only
  refuses a registry of another chain or line. Which registry is the chain's real later generation is the deploy book's
  word (§9 walk check, §11), not the constructor's views (F13). The walk accepts any contract whose `predecessor()` chain
  reaches the router's registry, a sibling line included; the env's publisher is the guard.
- **Built factories.** A factory already deployed keeps its rule (nothing deployed is upgraded); the check lands with the
  factory code of the round. All chains are test-only today.
- **Conflict to change on landing:** [admin-not-owner §13.4](2026-11-10-admin-not-owner.md) "one registry per factory holds"
  (§15).

## 11. Generations beyond two (`CTR-UA-70`, `CTR-UA-71`, `CTR-UA-72`)

### 11.1 The line and its walks (`CTR-UA-70`)

**CTR-UA-70 (owner R10, R11, P5; N2, N3, N4, N11 follow; the gas figures are proposals).**

- **The line.** Generation 1 has `predecessor = 0`. A later registry takes as predecessor the chain's **latest** generation,
  any `n ≥ 1`, and is generation `n + 1` (`generation = p.generation() + 1`, today `p.generation() != 1` is refused). One
  registry code serves every generation; its EIP-712 version is the generation's decimal number. **Depth cap:**
  `MAX_GENERATION = 16` (owner R11); the constructor refuses a predecessor with `generation() ≥ 16` (`UAConfig(0)`), so a
  generation 17 cannot deploy; the deploy refuses it first by name (`GEN_DEPTH`).
- **Views (owner P5).** `holderOf(bytes32 ua) → (address holder, uint16 kind)`: this generation and the record's kind if it
  holds the record, else the predecessor's answer, `(0, 0)` at generation 1. `kindHome(uint16 kind) → address`: this
  generation if the kind is registrable here (`_registrable`), else the predecessor's answer, 0 at generation 1 (for
  `0x0142`, which several generations may enable, §11.2, it is the newest such generation on the walk). `verifierOf(uint16
  kind) → address`: this generation's verifier word's address (0 if none). `verifyOnly(kind)`. `pqzHomeOf(ua)` (§11.2).
- **Lookups.** Every reader that forwards today reads `holderOf(ua)` once and reads the record at the holder directly (N11):
  `recordOf`, `kindOf`, `registrationOf`, `keyOf`, `webAuthnKeyOf`, `muSig2KeyOf`, `frostKeyOf`, `popOf`, `popSlotsOf`,
  `msigOf`, `msigStateOf`, `memberAccepted`, `memberSigHashOf`, `checkedOf`, the KEM views, `expandedKeyOf`; the PQZ views
  by §11.2. `keyOwner` walks back (local first, then the predecessor), so `UAAlreadyRegistered` / `UAKeyInUse` cover the
  line. The per-kind lists and decoys ([CTR-UA-29](../../contracts/accounts.md#CTR-UA-29)): a kind's list lives in its home;
  `msig` has one list per generation; `0x0142` by §11.2.
- **Native-space shortcut (owner P5).** An id in the native space (`UAKinds.inNativeSpace`: top 12 bytes zero) is answered
  `kindOf = 0`, `holderOf = (0, 0)`, `isRegistered = false` without walking: every generation's registration refuses such an
  id (`UAIdInNativeSpace`), so none can hold it; tokens already skip the registry for it (`MtxPipelineLib._checkTo`). It
  rests on every generation of the line refusing such ids (§11.3); a test registers through every form with a native-space
  id and finds nothing stored.
- **Single-key registrations walk nothing (N11, proposal).** A single-key kind registrable here has its kind and its keyHash
  group only in this generation (the constructor refuses it otherwise), so `_identify`'s `UAAlreadyRegistered` and the
  group's `UAKeyInUse` read this generation only; `msig` (re-enabled in every generation) and the PQZ key (§11.2) keep the
  walk.
- **Writes (R2 for N, N2).** The generation that holds the signer's record authenticates every signature-authenticated
  write: a forwarded check goes **directly to `holderOf(ua)`**, never through `predecessor` (§3, §4).
- **A kind this generation does not carry (N3).** A check of a record held elsewhere is this generation's own verifier
  where the kind is verify-only here, **else the holder directly**: one hand-off, one hold, whatever the depth.
- **Kinds and groups (N4).** A generation may carry verify-only a kind **any** predecessor enables
  (`predecessor.kindHome(kind) != 0`). A keyHash group stays with the generation that first enabled a kind of it: the
  constructor refuses a non-verify-only kind whose group any predecessor enables (`_groupInPredecessor` asks `kindHome(j) !=
  0`), `0x0142` excepted (§11.2). `PqzStateLib._auditorChecks` asks `kindHome(0x0142) != 0` of the token's registry for "a
  `0x0142` verifier on the line" ("proven, or nothing"), not `kindEnabled`: a PQZ change, so its per-set run (AGENTS.md).
- **The sibling question is gone (R7).** A precompile that arrives after the latest generation is used by the next one, which
  carries the kind verify-only over the whole line; Q2's sibling is unnecessary.
- **"Latest" (threat).** A registry cannot see its successors (immutable, nothing written back), so "latest" is not checkable
  on chain by the new registry. The deploy reads the book's latest generation and refuses another predecessor by name
  (`GEN_NOT_LATEST`, overridable only as §9 says) and compares the whole walk with the book (§9). Each registry's predecessor
  is immutable, so no middle generation can be inserted under an existing one; a **sibling** (a second registry over the
  same predecessor) can be deployed by anyone, as a second gen 2 can today: it does not see its sibling's records, and it is
  used only where governance publishes an env naming it (§10).
- **Gas (N11; EIP-2929 prices; estimates, the round measures them, T-GAS).** `holderOf` per generation passed without the
  record: a cold `STATICCALL` ≈ 2,600 plus its cold record slot ≈ 2,100, ≈ 5 k; at the holder one to three cold slots. Then
  one cold call to the holder per further read (≈ 2,600 + its slots), with no per-hop re-encoding of the returned bytes. The
  **common** cost is a **deep hit**: an operation of a gen-1 UA in a gen-n token reads `holderOf` for the sender and for the
  receiver's `kindOf`, then the key at the holder: ≈ 2 × 5 k × (n − 1) + the reads. The worst case is a **miss** (an id
  registered nowhere): the whole line, ≈ 80–120 k at depth 16. A forwarded signature check (not a read) holds `1/63` of the
  holder's cap plus `GAS_MARGIN` once (N3). `_slotCap`, `_pqzHolder` and the caps count the hops to the member's holder
  (fixed: a record never moves, a predecessor never changes).
- **Mitigations (proposals).** (1) The native-space shortcut (owner P5). (2) The depth cap bounds the miss. (3) The SDK gas
  table carries the extra per registry and per depth (§12).

### 11.2 The PQZ attachment over N generations (`CTR-UA-71`)

**CTR-UA-71 (owner W2; the per-position rules are proposals).** Today (rulings A5-I1 and A6-I1, [decisions.md](../../decisions.md)
UA-8 entry (d)) a UA's PQZ attachment (the `setPqzKey` versions, the proofs, `proven`, the `keyOwner` of proven PQZ keys, the
`0x0142` list slot, `current`, the scoped records) lives in the oldest generation that enables `0x0142`, the record stays
where it was registered, `0x0142` lives in one generation (the group check), and a generation in front of one that enables
`0x0142` refuses a PQZ key. With N generations that bars every later generation's records from PQZ for the life of the line;
the owner refused that (W2).

- **The PQZ home of a record (proposal).** For a record held in generation `j`, read through generation `k ≥ j`: the
  **oldest generation `g` with `j ≤ g ≤ k` that enables `0x0142`**, or none. New view `pqzHomeOf(ua) → address`, recursive:
  at the holder, itself if it enables `0x0142`, else 0; at a later generation, the predecessor's answer if it is not 0, else
  itself if it enables `0x0142` and `holderOf(ua) ≠ 0`, else 0. A later generation that enables `0x0142` so hosts its **own**
  records (W2) and the records of earlier generations that have no home below it (today's A6-I1 host); a record's home, once
  a reader sees one, never changes (records never move, predecessors never change). A reader below the home sees none, as
  gen 1 sees none of gen 2's attachment today.
- **What changes in today's A5-I1 rule.** (1) A later generation **may** enable `0x0142` although a predecessor enables it:
  `0x0142` is exempt from `_groupInPredecessor`; it is never verify-only (§2). (2) The `pqz-mlwe` keyHash group stays unique
  across the line by the walk: a proof in a home checks `keyOwner` here and through every predecessor (`UAKeyInUse`), as
  `_pqzOwn` does through `keyOwner` today. (3) The refusal `UAKindDisabled(0x0142)` stays only for a generation that does not
  enable `0x0142` while `predecessor.kindHome(0x0142) != 0`, for its own records (a key placed there has no home yet;
  its records get one when a later generation that enables `0x0142` is deployed, and their keys are then set there by
  `setPqzKey`). (4) "The oldest generation that enables `0x0142`" of A6-I1 reads "the record's PQZ home". Today's
  two-generation behaviour is the case `k ≤ 2` of these rules.
- **Writes.** `setPqzKey`, `setPqzScopedKey`, `storePqzPop`, `storePqzScopedPop` are accepted only at `pqzHomeOf(ua)`
  (`UAUnauthorized` elsewhere; the node's `UA_WRONG_GENERATION` names that target), the signature of a signed one checked
  by `holderOf(ua)` (§3).

| Position | Today (two generations) | N generations (proposal) |
|---|---|---|
| `UARegistry._pqzHost()` | per generation: `predecessor ≠ 0` and `0x0142` enabled here | per UA: `pqzHomeOf(ua) == address(this)` and the record not held here |
| `UARegistryAuxLib._host(ua)` (where the four PQZ writes go) | held here ⇒ false; a gen 2 with `0x0142` and `kindOf ≠ 0` ⇒ true; else `UAUnauthorized` | held here ⇒ false (then A5-I1 (3) decides whether a key is allowed); `pqzHomeOf(ua) == address(this)` ⇒ true; else `UAUnauthorized` |
| `UARegistryAuxLib._away(ua)` (scoped reads) | not held here and no `0x0142` here ⇒ the predecessor | not held here and `pqzHomeOf(ua) ≠ address(this)` ⇒ forward to `pqzHomeOf(ua)`, or to `holderOf(ua)` where it is 0 |
| `UARegistryAuxLib._scopedFrom()` (a scope's holder list) | no `0x0142` here ⇒ the predecessor's list first, then this one's (U4h-2) | the lists of every generation on the walk that enables `0x0142`, oldest first; where none does, today's rule. Sound with A5-I1 (3): above the first generation that enables `0x0142` no record without a home holds a key |
| `UARegistryAuxLib._pqzRecord` (copy of a version at the home) | from `_pred()` ("gen 1") | from `holderOf(ua)` (no generation between the holder and the home writes the attachment) |
| `UARegistryAuxLib._pqzNext` (version 0, `latest`) | `_pred()`'s | `holderOf(ua)`'s |
| `UARegistryAuxLib._kemHash`, `_registerKeyMessage` | `_pred().registrationOf`, `_kindOf` | `holderOf(ua).registrationOf`, the kind from `holderOf` |
| `pqzKeyOf`, `pqzKeyAt` (`_pqzAt`), `pqzKeySigOf`, `pqzPopOf`, `pqzKeyUsed`, `pqzKeyLatest`, `recordOf`'s `pqzKey`, `checkedOf`'s `pqzPop`, `registrationOf`'s proof patch, `pqzScopedKeyOf` / `At` / `Latest`, `pqzScopedPopOf`, `pqzOpenKemAt` | forward to the predecessor unless `_pqzHost()`; `pqzKeyLatest` the max of this and the predecessor's; `pqzKeyUsed` this or the predecessor's | one rule: home == this ⇒ this generation's, with the holder's for a version not copied (host rule 2), `pqzKeyLatest` the max of this and the holder's, `pqzKeyUsed` this or the holder's, `registrationOf` the holder's with this home's stored proof; home ≠ this and ≠ 0 ⇒ forward to the home; home == 0 ⇒ forward to the holder |
| `0x0142` list (`uaCount` / `uaAt` / `uaPage` / `uaIndex` of `0x0142`: the decoy set) | the one enabling generation's list | one list per enabling generation (as `msig`); read through `k`: the lists of every enabling generation on the walk, oldest first, `uaIndex` the position in that sequence. Decoys are drawn from that sequence, so the anonymity set covers the line |
| `keyOwner` of group `pqz-mlwe` (`_pqzOwn`) | walks back; one enabling generation | walks back (this and every predecessor): unique for proofs made in the newest home; residual below |
| `_pqzHolder` (A5-I1, MD-13) | `UAKindDisabled(0x0142)` when the predecessor enables it; a gen-1 holder's cap from `_pred()` | A5-I1 (3); the holder's cap from `holderOf(ua)` plus one hand-off |
| indexer, node | the PQZ events of one host | the PQZ events of every generation that enables `0x0142` (§12) |

- **Residual (for the owner, §16).** An older home cannot see a newer one: a PQZ key proven first in a newer home can later
  be proven for another UA in an older home (whose own walk does not reach the newer generation), so two UAs of the line may
  own the same `pqz-mlwe` hash. Each reader sees one owner (`keyOwner` answers local first). The same class as A1-I1's
  documented "gen 1 cannot see gen 2". Indexers flag a hash owned twice on the line (proposal).
- **Tests (three generations).** (a) gen 1 with `0x0142`, gen 2 without, gen 3 with: a gen-1 record's attachment stays in
  gen 1 and reads through gen 3 forward there; gen 2 refuses a PQZ key for its own record (`UAKindDisabled(0x0142)`); gen 3
  accepts `setPqzKey` for that gen-2 record and for its own; gen 3 refuses a key hash proven in gen 1 (`UAKeyInUse`); the
  `0x0142` list through gen 3 is gen 1's then gen 3's. (b) gen 1 without, gen 2 with, gen 3 with: a gen-1 record's home is
  gen 2; through gen 3 every PQZ view forwards to gen 2, and gen 3 refuses its PQZ writes (`UAUnauthorized`); gen 3's own
  records are homed in gen 3. (c) The residual: a hash proven in gen 3 is then proven for another UA in gen 1 (documented
  behaviour, the test pins it). (d) The scoped lists and `pqzKeyLatest` in (a) and (b). (e) `PqzStateLib` on a token bound
  to gen 3 in (a): a gen-1 holder's unproven key is refused. These are PQZ changes: the per-set run of AGENTS.md.

### 11.3 The walked interface and the trust in predecessors (`CTR-UA-72`)

**CTR-UA-72 (owner W3, W4, W5; the pin's form is a proposal).**

- **Every generation carries the views (W3).** `holderOf` (with the kind), `kindHome`, `verifierOf`, `verifyOnly`,
  `pqzHomeOf` and a forwarding `expandedKeyOf` are in the registry code from now, generation 1 included (pre-freeze; the
  SCaaS testnet's gen 1 is redeployed at its next reset). Each generation's constructor walks its predecessors and probes
  each one (`try` … `catch` ⇒ `UAConfig(0)`, as `checkedOf` today): `holderOf(0)`, `kindHome(0)`, `verifierOf(0)`,
  `verifyOnly(0)`, `pqzHomeOf(0)`, `expandedKeyOf(0)`, plus today's `checkedOf`, `memberSigHashOf`, `msigStateOf`. So a read
  on a predecessor fails only by gas (F11).
- **The frozen interface (W4).** Later generations are later code; what a successor calls on a predecessor is frozen. The
  list (function, argument and return types as in `IUARegistry`): identity `predecessor`, `generation`, `chainUid`,
  `hederaNative`, `verifyBudget`, `smartKeyCloneHash`; kind table `kindEnabled`, `verifyOnly`, `verifyCap`, `verifierOf`,
  `kindHome`; records `holderOf`, `kindOf`, `isRegistered`, `recordOf`, `keyOf`, `webAuthnKeyOf`, `muSig2KeyOf`,
  `frostKeyOf`, `registrationOf`, `popOf`, `popSlotsOf`, `expandedKeyOf`, `keyOwner`, `checkedOf`; `msig` `msigOf`,
  `msigStateOf`, `memberAccepted`, `memberSigHashOf`; KEM `kemKeyOf`, `kemKeyAt`; PQZ `pqzHomeOf`, `pqzKeyOf`, `pqzKeyAt`,
  `pqzKeyLatest`, `pqzKeyUsed`, `pqzKeySigOf`, `pqzPopOf`, `pqzScopedKeyOf`, `pqzScopedKeyAt`, `pqzScopedKeyLatest`,
  `pqzScopedPopOf`, `pqzOpenKemAt`, `pqzScopedCount`, `pqzScopedAt`; lists `uaCount`, `uaAt`, `uaPage`, `uaIndex`; checks
  `requireAuthorized`, `requirePortable`, `requirePortableApp`. Pinned by a test (`RegistryWalkInterfaceIsPinned`,
  proposal): the full signatures with return types, their selectors and the hash of the list, as the typehash pins; a change
  moves the pin with old → new in the commit and needs the owner.
- **Trust (W5).** Every generation trusts each predecessor completely: a middle generation answers before those below it,
  so wrong code there can answer for any id. Nothing on chain checks "same code". The guards are the deploy's walk check
  against the book (every address and code hash, §9) and the governance-published env (§10). The only recovery from a
  faulty generation is a sibling line from the generation below it, which loses the records of the faulty generation and of
  every later one.

## 12. Node, SDK, clients, indexers, families (`CTR-UA-65`, `CTR-UA-66`)

**CTR-UA-65 (owner R8 Q8 / Q9, R10; details proposal).**

- **Node config.** `ua_registries = [...]` replaces `ua_registry` (a note for operators: config shape change). Validated on
  chain at start: every entry's `chainUid()` is the chain's; exactly one has `generation() == 1` and `predecessor() == 0`; the
  others form one line, each `predecessor()` an entry, generations consecutive, none above `MAX_GENERATION`. The node orders
  them by those links, so the order written in the config carries no meaning. This also closes today's gap "writes that must
  go to generation 1 cannot be relayed" ([§1.8 Relaying](../../contracts/accounts.md#CTR-UA-31)).
- **Node guard (F9).** `Rule::UaRegistry` becomes the set of the line's addresses; the allow-list check (`typed.rs` `REG`
  rows against each contract's selectors) holds per registry. A `register` of a kind sent to a generation where it is not
  registrable is refused before sending, `UA_VERIFY_ONLY` (named; the target is `kindHome(kind)`); a key write sent to a
  generation that does not hold the record, or a PQZ write sent elsewhere than `pqzHomeOf(ua)`, is refused,
  `UA_WRONG_GENERATION` (the target named).
- **NODE-JOB-29 (F9).** `UA_KEY_NOT_CACHED` through a later generation: the parts belong in the holding generation
  (`cacheExpandedKey` there; the lane sends them there for a `register`); still `queued`, never `dead`. Where the holding
  generation refuses the cache (`UAKeyCache`: its verifier has a precompile) the case cannot complete: `dead`
  `UA_KEY_NOT_CACHEABLE` (the constructor check of §2 makes it unreachable; the node names it anyway).
- **Indexer (F9, W2).** Reads every generation of the line (today one registry, `ua_registry`): `UARegistered` from each and
  the PQZ key-version events from every generation that enables `0x0142`; it flags a `pqz-mlwe` hash owned twice on the line
  (§11.2). A verify-only generation emits nothing for its verify-only kinds.
- The node verifies nothing itself: a token checks on chain through its bound registry; the node's simulation follows.
- **SDK.** The target of a registration is `kindHome(kind)`, of a key write `holderOf(ua)`, of a PQZ write `pqzHomeOf(ua)`.
  The gas table's verify rows are keyed by chain, registry address and signer kind; the verify path (`cache` / `precompile` /
  `fallback`), the depth and the write path of W1 are columns, measured per chain per registry
  ([CLI-SDK-09](../../clients/scaas-sdk.md#CLI-SDK-09)); the quote takes the row of the registry the token binds; the
  reference table carries every path. The PQZ decoy draw reads the `0x0142` sequence of §11.2 through the token's registry.
- **Clients.** Signing is unchanged (same kind, same message). A client choosing a token release shows its registry and that
  registry's verify path for the holder's kind. `ua-rs` and every `ua-*` registration builder offer a kind on a registry only
  where `kindHome(kind) == registry`.

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
| A gen-2 verifier (or the chain's precompile) accepts a forgery for kind K | anyone can authorize as any gen-1 UA of kind K, or as a gen-1 member of kind K in a gen-2 `msig`'s consumer checks, in every consumer that binds gen 2: token operations, token roles (below), portable and app records read through gen 2 (e.g. a PqChat KEM record), a DEX | no registry state changes in any generation: every signature-authenticated write, members of every `msig` included, is checked by the holder (R2, W1, §3); a forgery cannot register, alter or attach keys to any record or `msig`; §7 tests (e) and (f), the constructor's edge-class rows and the probe; UNAUDITED until an AI audit round covers the verifier |
| A middle generation carries K verify-only with a faulty verifier | — | its verdict reaches no later generation: a generation that does not carry K hands the check to the holder directly (N3), writes go to the holder (N2) |
| Gen 2 refuses what the holder accepts | a gen-1 UA of kind K cannot act in gen-2-bound consumers | §7 (never laxer, differences to the owner); only a stricter gen 2 the owner confirmed can refuse more, and §5's fallback then still applies on no answer |
| A precompile removed, moved or repriced above gen 2's cap | no answer from gen 2's verifier | §5: the holder's verdict, at this cap plus the holder's gas; the hard bound (§4) keeps every registered `msig`'s fallback within one 2^24 transaction |
| A caller crafts input to force "no answer" | — | §5: the verifier answers 0 for malformed input and for an invalid one on a live precompile (alive-check); a test and a mutant per verifier |
| A client upgrade changes the precompile's answers | gen 2 cannot follow | the probe re-run after upgrades (§9); a laxer answer is the forgery row; a stricter one goes to the owner |
| A wrong or faulty predecessor | a registry reads keys, records and pointers from a contract that only answers like a registry; a faulty middle generation answers for any id | every generation trusts its predecessors fully (W5, §11.3); the constructor's probes bind only what a contract answers; what binds a later generation to the real line is the deploy's walk check of every address and code hash against the book (§9), `GEN_NOT_LATEST` (overridable only by the owner, recorded), the CREATE2 addresses and the governance-published env (§10). Recovery: a sibling line from the generation below, losing the records of the faulty one and later |
| A sibling generation | records split between siblings | used only where governance names it in an env; the deploy refuses it (§11) |
| A deep line | each miss walks every generation | `MAX_GENERATION`; native-space ids answered without walking; the SDK quotes the depth (§11) |
| The PQZ attachment in several homes | two UAs of the line may own the same `pqz-mlwe` hash (§11.2 residual) | each reader sees one owner; indexers flag it; the owner decides (§16) |

**Residual (F17, N15).** A token is already trusted code for its balances, so a gen-1 UA credited in a gen-2-bound token adds
no trust beyond the release. What is new is that **every consumer bound to a later generation inherits that generation's
verifier for the predecessors' UAs**: tokens and DEX releases that name it in their env, and contracts that read portable or
app records through it (`PqChat` records, the PQZ attachment's consumers). **Token roles too (N15):** a token checks its own
roles through its bound registry (`MetaTokenBase._uaRegistry`), so the mint, force, freeze and admin roles of a release that
binds a later generation, where a predecessor's UA of a verify-only kind holds them, inherit that verify-only verifier; they
are worth more than a balance. The router's governance stays on the router's registry (§10). Wallets show the release's
registry and verify path (§12).

**Gas** (caps from `DeployBase` and [CTR-UA-23](../../contracts/accounts.md#CTR-UA-23); measured unless marked):

| Kind | gen 1 on the cache (cap; measured `verifyCached`) | with a precompile (cap; measured) |
|---|---|---|
| `mldsa44` | 4,250,000; 4.11 M | 200,000; ≈ 175 k `verify` (P6f copy) |
| `mldsa65` | 5,950,000; 5.80 M | 200,000; ≈ 236 k `verify` (P6f copy, `estimateGas`), `requireAuthorized` 301,776 with intrinsic and calldata |
| `mldsa87` | 8,850,000; 8.85 M | 250,000 PROVISIONAL; ≈ 140 k execution (reset 4 T-GAS) |

Verify-only adds `holderOf` and the key read at the holder, ≈ 8–15 k for one hop [estimate], plus ≈ 5 k per further
generation passed (§11), and drops today's forwarding hold (`cap/63 + GAS_MARGIN`). Calldata is the same on both paths (an
ML-DSA-65 signature is 53–132 k gas of calldata). **The treasury (N13).** A `{mldsa65 ×3} t=2` treasury `msig`,
unregistrable at the cached cap in gen 1 (2 × 5.95 M + holds > `verifyBudget` 12 M), registers in a gen 2 whose `mldsa65`
is verify-only on a precompile (≈ 2 × 0.25 M on its consumer path). Its fallback is ≈ 2 × (0.25 M + 5.95 M + holds) ≈ 12.6 M
[estimate] and its writes (W1) ≈ 12.3 M [estimate]: both are above `verifyBudget` but fit one 2^24 transaction (16.78 M),
and nothing limits a check to `verifyBudget` at run time; the hard bound of §4 checks this at registration and at
`updateMsig`.

## 14. Work list

Against the `bls-multi` layout (front matter). Each row names its file.

| Component | Work |
|---|---|
| `UARegistry` (constructor, views, walks) | `KindConfig.verifyOnly`, `keyForm`, bits 224 / 225; the constructor rules of §2 (`verifyOnly ⇔ predecessor.kindHome(kind) != 0`, the impossible combination through the home's `verifierOf`, `PRECOMPILE() == 0` refused, `_groupInPredecessor` by `kindHome`, `0x0142` exempt); `generation = p + 1`, `MAX_GENERATION`; the walk over every predecessor with the probes of §11.3; the views `holderOf` (with the kind), `kindHome`, `verifierOf`, `verifyOnly`, `pqzHomeOf`, forwarding `expandedKeyOf`; the native-space shortcut on `kindOf`, `holderOf`, `isRegistered`; every forwarding reader by `holderOf` (§11.1); `_authorized`, `_derived`, `_memberOk` by §4 (own verifier, else the holder directly); `requireAuthorized`'s `UAKeyNotCached` branch on `holderOf`'s kind; `requirePortable(App)` by §4; `_listedHere` false for a verify-only kind; the `0x0142` list sequence; `_pqzHost` and the PQZ views of §11.2; the EIP-712 version; N12 masking at `_verifierCall` (`cfg >> 160`), `kindEnabled`, `_listedHere`, `requireAuthorized`, `_derived` (`uint160(cfg)`) |
| `UARegistryCoreLib` (authorization, verify) | the `write` flag through `_sigOk` / `_msig` / `_memberOk` / `_portableOk` (W1): on a write `via(holderOf(member))`; `_single`'s host path `via(holderOf(ua))` (N2); the verify-only branch of `_portable` / `_single` / `_memberOk` from consumer entries only, with the hold on every verify-only call, group kinds included (N9); the three-state call and the fallback to the holder's entry of §4 (§5); failed reads ⇒ `UAVerifyGas`; `_notCached` on `holderOf`'s kind; `_slotCap` by the holder's cap plus one hand-off (N3) and the hard bound's write mode (P3, W1); `_accepted` / `_msigBytes` from `holderOf`; N12 masking at `_single` (`cfg >> 160`), `_notCached`, `_listedHere`, `_pqzProof` |
| `UARegistryRegLib` (registration) | step 1 of every `register*` form: `_registrable` then `UAVerifyOnly(kind)`; `_identify` without the line walk for a single-key kind (N11); `pqzHolder`: A5-I1 (3) by `kindHome(0x0142)`, the holder's cap from `holderOf(ua)` plus one hand-off; `msigBound` and the registration bound with the hard bound against `TX_GAS_CAP` (`UAKeyData(0x0120)` / `UAMsigSlots(n)`); `pqzProof` with the line-wide `keyOwner` walk; N12 masking at `pqzHolder`'s `_cfgKind() >> 160` |
| `UARegistryAuxLib` (PQZ attachment, KEM, cache, pages) | `cacheExpandedKey` refuses a verify-only kind (`UAVerifyOnly`), N12 masking; `_host`, `_away`, `_scopedFrom`, `_pqzRecord`, `_pqzNext`, `_kemHash`, `_registerKeyMessage`, `registrationOf`'s patch by §11.2; `uaAt` / `uaPage` / `uaIndex` of `0x0142` over the sequence |
| Verify-only verifiers | one per eligible kind (ML-DSA first): `KEY_FORM()`, the edge-class constructor rows, the valid row kept for the alive-check, the mapping of §5 (lengths and encodings first, alive-check, `PqNoAnswer`) |
| `PqzStateLib` | `_auditorChecks`: `kindHome(0x0142) != 0` instead of `kindEnabled` (N4); a PQZ change: its per-set run |
| `OpenFactory` | the env check of §10 (bounded walk, `chainUid`, `smartKeyCloneHash`) |
| `IUARegistry` | the new views and errors (`UAVerifyOnly`), doc comments; the frozen list of §11.3 |
| Tests | T-REG-4 changed: a later generation refuses a kind a predecessor enables unless flagged verify-only, refuses the flag otherwise, refuses the impossible key form (through a middle verify-only generation too, N8), refuses a verify-only verifier without a precompile, refuses its registration (`UAVerifyOnly`) and its `cacheExpandedKey`, forwards its lists and `expandedKeyOf`; `UAKeyInUse` across the line. New: §7 (a)–(f) per eligible kind; every row of §4's table, its fallback entry included; W1: an accept-all stand-in against each of the five writes (§7 (e)); N2 / N3: the three-generation accept-all middle test (§7 (f)); §5: no-answer stand-ins (empty account, revert, malformed return data, out of gas at the cap) fall back, an answer 0 does not, gas below the cap is `UAVerifyGas`, the group kinds' path holds; N5: per verifier, the fuzz test and the mutant without the alive-check; ML-DSA with gen 1 on the cache and gen 2 on a precompile stand-in (form `0`), gen 2 under form `1` (incomplete cache ⇒ `UAKeyNotCached`; the layout test); the hard bound (the treasury fits, `{mldsa87 ×2} t=2` is refused); §11.2 (a)–(e); the constructor probes of §11.3 against a predecessor lacking each view; `RegistryWalkInterfaceIsPinned`; P5: no registration stores a native-space id; the depth cap; the factory walk (accept the line, refuse another chain's, a non-registry and another clone hash); T-GAS with verify-only `msig` members at the budget, per depth and on the write path; T-AUTH-4 on the new path; storage layout and typehash pins unchanged |
| Deploy | the later-generation mode of `DeployBase` with the book's latest as predecessor (`GEN_NOT_LATEST` with the owner-confirmed override, `GEN_DEPTH`, `GEN_KEY_FORM_IMPOSSIBLE`, `GEN_VERIFY_ONLY_NO_PRECOMPILE`, the walk check `GEN_WALK_MISMATCH`); gen 1 with the new views at the SCaaS testnet's next reset; the differential probe through the node list under strict majority, the holder entry per kind (§9); the book fields (§9); `script/pq_verifiers.py` and `DeployBase._mldsaCandidates`: default candidates Final + chain-own only, Draft only under the profile flag with the fuller probe (CTR-UA-69); the verify-only verifiers; the probe re-run after client upgrades in the operations runbook |
| Node | `ua_registries` and its on-chain validation; the guard per registry, `UA_VERIFY_ONLY`, `UA_WRONG_GENERATION` (holder and PQZ home targets); NODE-JOB-29's target and `UA_KEY_NOT_CACHEABLE`; the indexer over every generation and every `0x0142` generation, the duplicate-hash flag (§12); a note for operators |
| SDK | write targets `kindHome` / `holderOf` / `pqzHomeOf`; verify rows keyed by chain, registry and kind with the path, depth and write path as columns; the decoy draw over the `0x0142` sequence; reference table rows (§12) |
| Clients | offer a kind only where `kindHome(kind) == registry`; the release's registry and verify path in the review (§12) |
| Docs | [accounts.md](../../contracts/accounts.md) §1.8 "Generations" and §1.9, T-REG-4's row, CTR-UA-05's "a registry generation supports a fixed set of kinds" (a verify-only kind is verified, not supported for registration), CTR-UA-29's per-generation lists and the `0x0142` sequence; the PQZ attachment rule (A5-I1 / A6-I1 as §11.2); the chain profiles (chain-own precompiles, the Draft flag, the keep commitment); `decisions.md` entry with §0; node config doc; SDK spec; §15's conflicts |

N12's full list of raw reads: `cfg >> 160` at `UARegistry._verifierCall`, `UARegistryCoreLib._single`, `_pqzHolder`
(`_cfgKind() >> 160`), `_pqzProof` and `UARegistryAuxLib._scopedProve` (both on `_cfgPqz()`, never flagged; masked
for one rule); `uint160(cfg) != 0` meaning "registrable here" at `_identify` and the step 1 of `registerMuSig2` /
`registerFrost`, `cacheExpandedKey`, `_notCached` and `requireAuthorized`'s branch, both `_listedHere`, `kindEnabled`
(stays local, by design), `_derived`.

## 15. Conflicts to change on landing

| Where | Today | After |
|---|---|---|
| [admin-not-owner §13.4](2026-11-10-admin-not-owner.md) | "A stack with its own registry has its own router and its own factory, so one registry per factory holds"; every env publish refuses an `env.registry` other than 0 or the router's registry | one registry **line** per factory: an env may name the router's registry or a registry whose predecessor chain reaches it, same `chainUid`, same `smartKeyCloneHash` (CTR-UA-67) |
| [accounts.md](../../contracts/accounts.md) §1.9 "Generations" | "at most two generations per chain"; gen 2 enables only kinds and groups absent from gen 1 | a line of up to `MAX_GENERATION` generations (CTR-UA-70); a later generation may carry a predecessor's kind verify-only (CTR-UA-58); `0x0142` may be enabled in several generations (CTR-UA-71) |
| [accounts.md](../../contracts/accounts.md) §1.8 "Generations" | gen 2 forwards views to gen 1; "Indexers read both generations" | lookups by `holderOf` over the line; indexers read every generation (CTR-UA-65) |
| [decisions.md](../../decisions.md) UA-8 entry (d), rulings A5-I1 / A6-I1 | the PQZ attachment lives in the oldest generation that enables `0x0142`; a gen 2 in front of a gen 1 that enables it refuses a PQZ key | the record's PQZ home (CTR-UA-71); the refusal only for a generation without `0x0142` behind one with it |
| `PqzStateLib._auditorChecks` | `kindEnabled(0x0142)` of the token's registry | `kindHome(0x0142) != 0` |
| `script/pq_verifiers.py`, `DeployBase._mldsaCandidates`, [evm.md](../../networks/evm.md) | `0x12`–`0x14` probed first | Final and chain-own by default; Draft under the owner-confirmed flag (CTR-UA-69) |

## 16. Open questions for the owner (proposals, not rulings)

The questions of revision 1 (Q1 – Q11) are ruled (§0.2); revision 2's P1 – P6 are ruled (§0.3). The author's proposals of
revision 3 that no ruling names:

| # | Question | Proposal |
|---|---|---|
| P7 | The PQZ home (§11.2, W2's details) | `pqzHomeOf(ua)` = the oldest generation from the holder to the reader that enables `0x0142`; A5-I1's refusal kept only for a generation without `0x0142` behind one with it; the `0x0142` lists and scope lists as the walk's sequence of enabling generations, oldest first; every PQZ view by the one rule of §11.2's table |
| P8 | The `pqz-mlwe` residual (§11.2) | accept: an older home cannot see a newer one's proven keys (the class of A1-I1); readers see one owner; indexers flag a hash owned twice. Alternative: none on chain without upgrading a deployed generation |
| P9 | The hard bound (§4, P3 / W1) | refuse, not flag: registration `UAKeyData(0x0120)`, `updateMsig` `UAMsigSlots(n)`; one bound for the fallback and the write path. Numbers for the owner (ARCH-POS-18) [estimates]: `{mldsa87 ×2} t=2` ≈ 18.5 M and `{mldsa65 ×3} t=3` ≈ 18.9 M are over 2^24 and refused, although they fit `verifyBudget` on a precompile |
| P10 | Hold on the group kinds' verify-only path (§5, N9) | hold (≈ 0.2 M more on that path), so "no fallback below the cap" holds for every kind |
| P11 | Verify-only verifiers without a working precompile (§2, N16) | refused by the registry constructor (`UAConfig(kind)`) and the deploy (`GEN_VERIFY_ONLY_NO_PRECOMPILE`); no Solidity-only verify-only verifier |
| P12 | Single-key registrations (§11.1, N11) | no line walk for `UAAlreadyRegistered` and the group's `UAKeyInUse` (kind and group live only here); `msig` and the PQZ key keep the walk |
| P13 | The pin of the frozen interface (§11.3) | `RegistryWalkInterfaceIsPinned`: the full signatures with return types, their selectors and the list's hash |
| P14 | Names | `pqzHomeOf`, `RegistryWalkInterfaceIsPinned`; deploy refusals `GEN_VERIFY_ONLY_NO_PRECOMPILE`, `GEN_WALK_MISMATCH`; helpers `_capOf`, `_registrable` |

## Sources

Fable review of revision 1 and Fable fix-check of revision 2 (2026-11-19; private scratchpad, not in the repo).
[accounts.md](../../contracts/accounts.md) §1.8 (registration, "Generations", Relaying), §1.9 (verifiers, per-chain
enablement, [gen-1 kind gate](../../contracts/accounts.md#gen1-kind-gate)), [CTR-UA-23](../../contracts/accounts.md#CTR-UA-23),
[CTR-UA-29](../../contracts/accounts.md#CTR-UA-29), [CTR-UA-33](../../contracts/accounts.md#CTR-UA-33),
[CTR-UA-46](../../contracts/accounts.md#CTR-UA-46); [decisions.md](../../decisions.md) UA-8 entry (rulings A1-I1, A5-I1,
A6-I1); [2026-11-15-mldsa-precompile-cache.md](2026-11-15-mldsa-precompile-cache.md) (MD-2, MD-10, MD-13, MD-15);
[2026-11-13-pqz-three-keys.md](2026-11-13-pqz-three-keys.md) (scoped records, U4h-2);
[2026-11-10-admin-not-owner.md](2026-11-10-admin-not-owner.md) §13.4; [2026-11-19-bls12381-multi.md](2026-11-19-bls12381-multi.md);
[plan P6f](../plans/2026-10-14-p6f-precompiles.md) (EIP-8355 pin); [ARCH-POS-15](../../decisions.md#ARCH-POS-15),
[ARCH-POS-18](../../decisions.md#ARCH-POS-18). Code at `a19151d64`: `smartcontracts/evm/src/ua/UARegistry.sol` (constructor,
`kindOf`, `keyOwner`, `recordOf`, `_elsewhere`, `_pqzHost`, `pqzKeyOf`, `pqzKeyLatest`, `checkedOf`, `_authorized`,
`_derived`, `_memberOk`, `_verifierCall`, `_listedHere`, `_groupInPredecessor`, `expandedKeyOf`, `requirePortable`,
`requirePortableApp`), `UARegistryCoreLib.sol` (`_identify`, `_consent`, `_pqzHolder`, `_msigDebit`, `msigBound`, `_pqzOwn`,
`_portable`, `_sigOk`, `_single`, `_notCached`, `_memberOk`, `_slotCap`, `uaCount`), `UARegistryAuxLib.sol` (`_portableOk`,
`cacheExpandedKey`, `storePqzPop`, `_pqzRecord`, `_kemHash`, `_host`, `_away`, `_scopedFrom`, `_pqzNext`, `registrationOf`),
`UAStore.sol` (`expanded`, `noPrecompile`, `capped`, `via`), `MlDsa.sol` (`MldsaVerifier`: `verify`, `expandedKeyPart`,
`verifyCached`, `verifyExpanded`), `FnDsa.sol` (the norm bound), `UAKinds.sol` (`inNativeSpace`),
`src/pqz/PqzStateLib.sol` (`_auditorChecks`), `src/factory/OpenFactory.sol` (`uaRegistry`, the env check,
`EnvRegistryMismatch`, `configureChain`), `src/metatx/MtxPipelineLib.sol` (`_checkTo`), `script/DeployBase.sol`
(`_deployUARegistry`, `_pqKindFits`, `_mldsaCandidates`, `UA_VERIFY_BUDGET`), `script/pq_verifiers.py`;
`scaas-node/src/main.rs` (`ua_registry`), `guard.rs` (`Rule::UaRegistry`, `UA_KEY_NOT_CACHED`), `indexer.rs` (`pay_filter`).
