# Spec: a registry generation 2 that verifies generation-1 kinds ("verify-only kinds")

2026-11-19. **Revision 4**: every finding of the Fable fix-check of revision 3 (Fable, high effort, verdict "build after
fixes", P0 0 / P1 0 / P2 3 / P3 7, M1 – M10, positions on P7 – P14; file in the private scratchpad, not in the repo) applied,
and the owner's rulings of 2026-11-19 on it recorded in §0.4 (P7 – P14, P9's refusal, the per-transaction cap as a deploy
parameter, M2, M9), amended the same day with the owner's rulings on revision 4's proposals P15 – P20 and on the
library that holds the generation walk (§0.4, Y1). Revision 3 applied the fix-check of revision 2 (N1 – N16, rulings §0.3); revision 2 the Fable review of
revision 1 (F1 – F17, rulings §0.2). Build plan:
[plans/2026-11-19-registry-verify-only-kinds.md](../plans/2026-11-19-registry-verify-only-kinds.md). Status:
**BUILT (EVM contracts, deploy, node, scaas-sdk, clients' target check)** on branch `multi-gen-verify`: contracts `d2f6b6c32`, `9ebf6931c`, `2bbe3380d`,
`0a78d4d64`, `cc82e3ecc`, `4f643c791`, `72ced51f3`, `0812a0467`, `a40d8acc0`, `de05b0789`, `6c558f1dd`, `773ae4988`,
`098c30feb`; deploy `53d4ad79d`, `78ce41390`; gas rows `9cb373c30`; node `d019be659`, `e6268a472`; scaas-sdk `535bf1dcb`;
clients `ff732ade0`, `9cac74ea0`, `afbc160f2` (the ua-rs bindings' export **PLANNED**); the other families
**PLANNED** (§12, CTR-UA-66). Everything cryptographic stays **UNAUDITED**. Scope: **EVM** (the contracts, the factory, the
deploy, the node, the SDK and clients); the other families take the principle in their own rounds.

Rule ids `CTR-UA-58` … `CTR-UA-72` are **final** (checked free at landing, no renumbering): the rules are normative in
[accounts.md §1.8.1](../../contracts/accounts.md#registry-line), the owner's rulings of §0 verbatim in the
[decisions.md](../../decisions.md) entry CTR-UA-58, the other entries CTR-UA-59 … -72 beside it. This spec stays the design
record.
Rows marked **owner** are the owner's ruling; **follows** applies a stated rule or a fix-check finding as the fix-check states
it; **proposal** is the author's and is listed in §16 for the owner (revision 3's P7 – P14 and revision 4's P15 – P20 are
owner rulings in §0.4; P21 is open). Despite the title, the design covers every later
generation (§11): "gen 2" below reads "a later generation", "gen 1" "the generation that holds the record", unless a section
says otherwise.

The work list (§14) is written against the registry's library layout of branch `bls-multi` (owner-approved, in progress):
`UARegistryRegLib` holds every `register*` form and the registration helpers (`keyUa`, `pqzHolder`, `msigBound`,
`pqzProof`); `UARegistryCoreLib` keeps the authorization and verify paths and, with this spec, **the generation walk's
logic** (owner Y1, §0.4); `UARegistryAuxLib` keeps the PQZ attachment, the KEM records, `cacheExpandedKey` and the list
pages; `UARegistry` keeps the constructor and the views, the walk's views thin (`_libView` into `UARegistryCoreLib`).

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

### 0.4 Rulings on the fix-check of revision 3 (owner 2026-11-19)

The owner on revision 3's proposals P7 – P14, through the controller's proposal to take them with the fix-check's
positions: **"approve all 8 as proposed"**. On P9: **"refuse such msigs at registration — ok"**. On the per-transaction cap:
**"agreed, as proposed"**. On M2 and M9: **"approve M2 and M9 as proposed"**.

| # | Topic | Ruling | Where |
|---|---|---|---|
| P7 | The PQZ home | the home rule of §11.2 (a record's PQZ home is the oldest generation from its holder to the reader that enables `0x0142`; every PQZ view by §11.2's one rule) and A5-I1's changes (1) – (4), with the fix-check's M1 (the write flag reaches `_single`), M4 (one walk returns `(holder, kind, pqzHome)`), M5 (one `0x0142` list per enabling generation, the SDK concatenates) and M9 (below) | **owner**; §3, §11.1, §11.2 |
| P8 | The `pqz-mlwe` residual | accepted with the corrected text of M3: not A1-I1's class; a duplicate needs the secret key; the reader-side rule exists on chain. **If a `PqzCore` property relies on one key per UA, the reader-side rule is taken instead** | **owner**; §11.2 Residual |
| P9 | The hard bound | an `msig` whose write path cannot fit the per-transaction cap is **refused at registration and at `updateMsig`** (not at the write), with the existing named errors `UAKeyData(0x0120)` and `UAMsigSlots(n)`. It is a structure bound, not a disabled kind under [ARCH-POS-18](../../decisions.md#ARCH-POS-18) | **owner**; §4 |
| P10 | Hold on the group kinds' verify-only path | as proposed: hold, ≈ 0.2 M more on that path | **owner**; §5 |
| P11 | Verify-only verifiers without a working precompile | as proposed: refused by the registry constructor and the deploy; no Solidity-only verify-only verifier | **owner**; §2 |
| P12 | Single-key registrations | as proposed: no line walk for `UAAlreadyRegistered` and the group's `UAKeyInUse`; this rests on the constructor's "kind and group only here", so on the predecessors' `kindHome` answers (W5's trust) | **owner**; §11.1 |
| P13 | The frozen interface's pin | as proposed: `RegistryWalkInterfaceIsPinned` pins the full signatures with return types, their selectors and the list's hash; with M8's additions (error selectors, `UASig` / `MemberSig` encodings, verifier getters, the hold formula, `expandedKeyOf`'s pointer form) | **owner**; §11.3 |
| P14 | Names | as proposed: view `pqzHomeOf` (a view over the one walk, M4), test `RegistryWalkInterfaceIsPinned`, deploy refusals `GEN_VERIFY_ONLY_NO_PRECOMPILE` and `GEN_WALK_MISMATCH`, helpers `_capOf` and `_registrable` | **owner**; §2, §9, §11 |
| X1 | Per-transaction cap | the registry takes the chain's per-transaction gas cap as an **immutable constructor parameter** (`txGasCap`) from the deploy book, not a hard-coded 2^24; the deploy script probes it off chain (e.g. `eth_estimateGas` / `eth_call` above 2^24; no opcode exposes EIP-7825's cap); every bound (P9, M2, M10, the fallback and write bounds) uses it; a raised cap later is a new generation | **owner**; §4, §9 |
| M2 | The consumer's reserve and the PQZ debit | accepted as a stated limit: on a chain without an ML-DSA precompile, an `msig` with two ML-DSA members cannot hold a PQZ key (fallback worst + `PQZ_DEBIT_MIN_GAS` > the cap); such a registration (`msig` + PQZ key) is refused like P9; the bound uses the fallback worst for consumer paths: `w` of `_msigDebit` is the fallback worst, a reserve is stated for the consumer's operation, and "never for good" is narrowed to the registry's check | **owner**; §3, §4, §5, §13 |
| M9 | `0x0142` in later generations | the deploy enables `0x0142` in every later generation whenever a predecessor enables it; omitting it is refused by name and can be overridden only with the owner's confirmation recorded in the book | **owner**; §9, §11.2 |

The fix-check's M1, M3 – M8 and M10 are applied as it states them (**follows**; M1, M3, M4, M5 and M8 also through P7, P8,
P13 and P14 above).

The owner on revision 4's own proposals P15 – P20 and on the controller's proposal for the walk's library (Y1): **"approve
all as proposed"** (2026-11-19).

| # | Topic | Ruling | Where |
|---|---|---|---|
| P15 | Names | constants `UA_CONSUMER_RESERVE_GAS`, `MSIG_REGISTER_GAS`, `PQZ_KEY_WRITE_GAS` (values measured by the round, pinned old → new); deploy refusals `GEN_PQZ_OMITTED` (M9), `GEN_PQZ_DEBIT_BOUND <kind>` (M10 d), `GEN_TX_CAP_UNKNOWN`, `GEN_TX_CAP_MISMATCH` (X1); view `txGasCap()` | **owner**; §2, §4, §9 |
| P16 | Where M10 (d)'s check runs | in the constructor (`UAConfig(kind)`) and first in the deploy by name, only where `0x0142` is on the line; the kind stays served by its home | **owner**; §2, §9 |
| P17 | `txGasCap`'s constructor bounds | `verifyBudget ≤ txGasCap < 2^64`, else `UAConfig(0)`; no relation to a predecessor's value is required (each generation's bounds use its own) | **owner**; §2 |
| P18 | The cap probe | `eth_call` at `2^24` and `2^24 + 1` through the node list under strict majority, then a binary search up to the block gas limit where `2^24 + 1` is accepted; the rows in the book; no cap found ⇒ `GEN_TX_CAP_UNKNOWN` until the owner sets the value in the book | **owner**; §9 |
| P19 | Decoys over concatenated lists | the SDK draws decoys by distinct key hash, so a key held by two UAs (§11.2 residual) counts once | **owner**; §11.2, §12 |
| P20 | The explicit gas limit of a verify-only verifier's precompile call (M7) | the precompile's worst cost for the kind's largest input, measured on the chain's client, a constant of the verifier (part of its init code, so of its CREATE2 address) and covered by its cap | **owner**; §5 |
| Y1 | Where the walk lives | the generation walk's **logic** (`holderOf`'s recursion and `pqzHome` fill, `kindHome`, the forwarding readers' target choice, the constructor-time line checks that can run in a library) lives in `UARegistryCoreLib` (≈ 20 KB of room after `bls-multi`'s split), not in `UARegistry` (≈ 2 KB of room). `UARegistry` keeps thin views (`holderOf`, `kindHome`, `verifierOf`, `pqzHomeOf`, the forwarding readers) that DELEGATECALL into the library walk through `_libView` / `_lib`, as today's library readers and writers do. The frozen interface is unchanged: its selectors stay on the registry | **owner**; §9 Size, §11.1, §14 |

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
| `UARegistryCoreLib.TX_GAS_CAP = 1 << 24` (`_msigDebit`, `msigBound`); `DeployBase.TX_REGULAR_GAS_CAP` | the per-transaction cap is a constant: EIP-7825's 2^24 | a chain with another cap gets wrong bounds; X1 makes it a constructor parameter |
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
- **A verify-only verifier has a working precompile (N16, owner P11).** Its constructor probe sets `PRECOMPILE`; a
  verify-only verifier whose probe failed (`PRECOMPILE() == 0`) would answer `PqNoAnswer` on every call (§5), so the
  registry constructor refuses it, `UAConfig(kind)`, and the deploy first by name (`GEN_VERIFY_ONLY_NO_PRECOMPILE <kind>`).
  A Solidity-only verify-only verifier is not allowed: it adds a second verifier of the same kind and no capability the
  holder lacks ([ARCH-POS-18](../../decisions.md#ARCH-POS-18) is served by the holder's software path).
- **Constructor (N4, M6).** For a **single-key** kind (every kind but `msig` `0x0120` and `0x0142`): `UAConfig(kind)`
  unless `verifyOnly ⇔ IUARegistry(predecessor).kindHome(kind) != 0` (`kindHome` answers for the line, `kindEnabled` stays
  local, §3): a verify-only flag on generation 1 or on a kind no predecessor enables is refused; a single-key kind a
  predecessor enables without the flag is refused as today. `msig` and `0x0142` are outside the `⇔` rule: never flagged
  (the flag on either is `UAConfig(kind)`), and never refused because a predecessor enables them (`msig` is re-enabled in
  full in every generation; `0x0142` by §11.2). A verify-only kind
  is exempt from the group check (its group **is** the home's and stays there); every other kind keeps it, across the whole
  line (`_groupInPredecessor` asks `kindHome(j) != 0` of the predecessor for each `j` of the group); `0x0142` is the one
  exception (§11.2). The existing predecessor checks stay (`chainUid`, `hederaNative`, `checkedOf`, `memberSigHashOf`,
  `msigStateOf`; `generation()` as §11), with the new views' probes of §11.3. The cap is the generation's own measured cap,
  `0 < cap ≤ verifyBudget` as every kind, and the deploy's 75 % rule (`_pqKindFits`) applies.
- **The single-key fallback against the home's PQZ debit bound (M10 d; owner P16).** The home checked a
  single-key holder's PQZ key with its own numbers only (`_pqzHolder`: the home's cap). Through this generation a debit of
  that holder pays the fallback: this generation's cap and hold, then the home's cap and one hand-off, plus the reads. Where
  `0x0142` is on the line (`kindHome(0x0142) != 0` here or below), the constructor checks, per verify-only kind, that this
  fallback passes `_msigDebit`'s bound (§4) with the compiled set's `PQZ_DEBIT_MIN_GAS`, the kind's largest signature and
  this generation's `txGasCap`; else `UAConfig(kind)`, and the deploy refuses first by name (`GEN_PQZ_DEBIT_BOUND <kind>`,
  owner P15) with the numbers for the owner. The kind stays served by its home (nothing is disabled). Today's figures pass:
  `mldsa87` at `n2048-kmax1024` ≈ 16.6 M of 16.78 M [estimate].
- **`txGasCap` (owner X1).** An immutable constructor parameter, the chain's per-transaction gas cap from the deploy book
  (§9), read by the libraries as `verifyBudget` is (`IUARegistry(address(this)).txGasCap()`) and replacing the constant
  `TX_GAS_CAP`; a view `txGasCap()` in the frozen list (§11.3). The constructor requires `verifyBudget ≤ txGasCap < 2^64`
  (`UAConfig(0)`, owner P17). A raised cap later is a new generation.
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
  Single key (M1): `_single` takes the flag `write`; on `write = true` it forwards to **`holderOf(ua)` directly** whenever
  `!_registrable(cfg)`, i.e. for a kind not carried here (`uint160(cfg) == 0`) **and** for a kind carried here verify-only
  (the word is not 0: verifier and cap are set). Today's test `uint160(cfg) == 0` alone would run the verify-only
  verifier's `verifyPop` on `setPqzKey` / `setPqzScopedKey` of a predecessor's single-key UA at a generation that is both its
  PQZ home and a verify-only carrier of its kind: N1 again, on a write-once key. Never through `predecessor` either (N2: a
  middle generation that carries the kind verify-only would otherwise answer with its verify-only verifier). An `msig`
  signer, held here or in a predecessor: its derived members go `via(holderOf(member))`, never `via(address(this))`; its
  native members keep the holder's clone hash.
- **Member signatures on writes (W1).** `UARegistryCoreLib._sigOk` / `_msig` / `_memberOk` / `_single` take a flag `write`
  beside `here`; **its default is the write side** (fix-check suggestion, follows): every internal caller passes `true`, and
  only the three external consumer entries below pass `false`. On a write (the registration PoP `_consent`,
  `acceptMembership`, `updateMsig`, `setPqzKey` / `setPqzScopedKey` and `setKemKey` through `_portableOk`, any other `_sigOk` caller) a derived member goes `UAStore.via(holderOf(member), …)` and
  its holder checks it under its own verifier; only the consumer entries (`requireAuthorized`, `requirePortable`,
  `requirePortableApp`, and `_portable` under them) pass `write = false` and may take the verify-only path of §4. Where the
  member's kind is enabled here, `holderOf(member) == address(this)` and nothing changes.
- **Cost of W1.** A write pays the holder's path: the treasury `msig` `{mldsa65 ×3} t=2` of §13, with gen-1 members on the
  cache, pays ≈ 2 × (5.95 M + 5.95 M / 63 + 5 k) + the reads ≈ 12.3 M per `updateMsig` or PQZ key write [estimate],
  against ≈ 2 × 0.25 M on the consumer path; `acceptMembership` checks one member per call, ≈ 6.05 M (M10 c). The write
  mode of §4's bound counts it against `txGasCap`.
- **The PQZ holder bound (F8, owner M2).** `_pqzHolder` / `_msigDebit` is CTR-PQZ-12's bound of a **debit**, a consumer
  operation (`w + w/63 + GAS_MARGIN + PQZ_DEBIT_MIN_GAS + calldata ≤ txGasCap`, "else every credit could be locked"), so its
  `w` is the **fallback worst** of the consumer path (§4's consumer mode), never the write mode: for a single-key holder held
  elsewhere whose kind is verify-only here, this generation's cap and hold plus `verifyCap(kind)` of `holderOf(ua)`, one
  hand-off and the reads; of a kind not carried here, the holder's cap plus one hand-off; for an `msig` holder, its minimal
  authorizing set at the fallback worst. A structure over it is refused at registration and at `setPqzKey` /
  `updateMsig` with today's `UAPqzHolder(ua)` (owner M2: "refused like P9"). Stated limit (owner M2): "on a chain without an
  ML-DSA precompile, an `msig` with two ML-DSA members cannot hold a PQZ key"; the same holds through a verify-only
  generation, whose bound counts the fallback worst. Per structure the bound decides [estimates, default set `n2304-kmax4096`, `PQZ_DEBIT_MIN_GAS` 6.07 M]: two `mldsa65` or
  `mldsa87` members exceed the cap at every set (the treasury of §13: 12.6 M + 6.07 M > 16.78 M); two `mldsa44` members
  (≈ 9.1 M fallback, ≈ 9.3 M with its hold and calldata) fit at `n2304-kmax4096` and `n2048-kmax1024` and exceed it at
  `n2560-kmax16384` and `n2816-kmax65536` (`PQZ_DEBIT_MIN_GAS` 7.79 M, 8.03 M).
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
that checks a signature of a record it does not hold: read `holderOf(ua)` once (its `holder` and `kind`); **if `kind` is verify-only
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
| **any write** (`write = true`): a member of any `msig` (registration PoP, `acceptMembership`, `updateMsig`, PQZ key writes), a single-key signer of a host write | `via(address(this))` / `via(_pred())` | **never**: `via(holderOf(member))` / `via(holderOf(ua))` (W1, N2; `_single` whenever `!_registrable(cfg)`, M1) | `via(holder)` | none (the holder's own verdict) |
| a predecessor's `msig` record (any consumer path) | forwarded whole | **unchanged** (R6): forwarded whole to `holderOf(ua)`, its members use the holding generation's verifiers | the same | none |
| PoP (`PURPOSE_POP_V2`) | the holding generation at registration | never checked by a later generation; `_portable` refuses the purpose as today | | |

- **R6, the true reason.** A registered gen-1 `msig` keeps gen 1's verifiers because it cannot register in gen 2: the same
  structure is the same id, and gen 2's `_identify` reverts `UAAlreadyRegistered` when `_kindOf(ua) ≠ 0`, which forwards to
  gen 1. Only a different structure (a new id, assets moved) gets gen 2's verifiers. Evaluating a gen-1 `msig` in gen 2
  would also need gen 1's accepted bits, current structure, clone hash and `UAAuth` domain.
- **One walk (N11, M4).** `holderOf(ua) → (address holder, uint16 kind, address pqzHome)` is the only walk of a check or
  a PQZ read: each generation answers for a record it holds, else asks its predecessor once and fills `pqzHome` on the way
  back (§11.1); the answer is three words, so nothing large is re-encoded per hop. Every
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
  - **Hard bound, `txGasCap`** (owner P9, X1; M2, M10 follow): the same walk over the slots of a minimal authorizing set,
    in two modes; the bound is their **maximum**, never their sum (M10 a):
    - **Consumer mode** (the fallback of §5): each derived member at this generation's cap plus its hold (the no-answer
      case) **plus** the holder's path (the holder's cap, one hand-off, the reads), the native members as today, **plus the
      consumer reserve**: the intrinsic 21,000, the signatures' calldata at the larger of 16 gas a byte and the EIP-7976
      floor of 64 gas a byte, and a named constant for the consumer's operation, `UA_CONSUMER_RESERVE_GAS` (measured by the
      round, owner P15). For a PQZ holder this mode is `_msigDebit`'s bound, whose reserve is `PQZ_DEBIT_MIN_GAS` (§3,
      owner M2).
    - **Write mode** (W1): each derived member at its holder's path only, the native members as today, plus the signatures'
      calldata as above, plus the measured constants of the **dearest** of the three writes that fix or use the structure
      (M10 b): registration (`MSIG_REGISTER_GAS`, owner P15), `updateMsig` (`MSIG_UPDATE_GAS` + n × `MSIG_UPDATE_SLOT_GAS`
      + the inner rows `msigBound` counts today) and `setPqzKey` (`PQZ_KEY_WRITE_GAS`, owner P15). `acceptMembership`
      checks one member per call (one slot, M10 c) and needs no structure bound.
    Over the bound, **registration refuses `UAKeyData(0x0120)` and `updateMsig` `UAMsigSlots(n)`** (owner P9: the errors of
    today's two bounds; never at the write: nothing can be done there, the transaction cannot carry the gas). This is a
    structure bound, not a disabled kind under ARCH-POS-18 (owner P9): such structures are unregistrable today
    (`verifyBudget`) and, with W1, write-dead even with a live precompile. Examples [estimates]: the treasury `{mldsa65 ×3}
    t=2`, consumer mode ≈ 2 × (0.25 M + 6.05 M) ≈ 12.6 M + the reserve, write mode ≈ 12.3 M + constants, fits;
    `{mldsa87 ×2} t=2` ≈ 2 × (0.25 M + 8.99 M) ≈ 18.5 M (write mode alone ≈ 18.0 M) > 2^24 (the `txGasCap` of the SCaaS
    chains and Ethereum), refused although it fits `verifyBudget` on the precompile path; `{mldsa65 ×3} t=3` ≈ 18.9 M (write mode ≈ 18.2 M), refused.

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
  2. **The call**, with an **explicit gas limit** (M7): the verifier calls its precompile with a fixed limit, the
     precompile's own worst cost for the kind's largest input (measured, a constant of the verifier, owner P20), never all its gas, so a
     precompile that burns all forwarded gas on failure (EIP-2537 style) leaves the alive-check its gas; otherwise the
     verifier would keep 1/64 of its cap, the alive-check would run out of gas and the registry would fall back: a
     caller-forced fallback. Success with exactly one word `1` (or the precompile's own valid encoding) answers **1**; exactly
     one word `0` answers **0**.
  3. **Anything else** (call failed, empty or malformed return data): the verifier re-runs its constructor's valid row (kept
     in its code) as an **alive-check**, with the same explicit limit; if the precompile answers it correctly, the input was
     invalid and the answer is **0**; otherwise the verifier reverts **`PqNoAnswer()`**. The alive-check's gas is inside the
     cap (the cap covers the worst input: the failed call at its limit plus the valid row).
  The registry reads its own call: a return of exactly one word `1` accepts, exactly one word `0` refuses; **any revert** of
  the verifier call (`PqNoAnswer`, out of gas, anything) **and any successful return that is not exactly one word `0` or `1`**
  (M7: empty, longer, another value) ⇒ fallback (P2). The verify-only call therefore does not go through `UAStore.capped`'s
  boolean read (which reads such a return as `false`); it keeps `capped`'s gas rule (the cap, the hold, `UAVerifyGas`).
  Today's `PqUA.callBool`, which folds every failure into `false`, stays on the holders' verifiers.
- **Hold on every verify-only call (N9, owner P10).** The verify-only path always calls with the hold (T-AUTH-4), the group
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
  normal path at registration; at run time the check takes what the transaction carries, up to `txGasCap`. The hard bound
  of §4 keeps the **registry's check** of every registered `msig` (fallback included) within one transaction of
  `txGasCap`, with the consumer reserve beside it (owner M2: "never for good" is narrowed to the registry's check). A
  consumer operation dearer than the reserve (`UA_CONSUMER_RESERVE_GAS`; `PQZ_DEBIT_MIN_GAS` for a PQZ debit, which the
  bound covers in full) fails while the precompile gives no answer, and works again when it answers; the check itself
  fails closed with `UAVerifyGas` only when the transaction does not carry the gas.
- **What it fixes (F6).** A removed, moved or repriced precompile no longer locks a gen-1 UA's funds in gen-2-bound tokens:
  the holder's software path, which still works, answers ([ARCH-POS-18](../../decisions.md#ARCH-POS-18)).
- **Tests (N5).** Per verify-only verifier: a fuzz test "no caller-chosen `sig`, key or message produces `PqNoAnswer` or a
  revert on a working precompile stand-in" (the empty-on-invalid stand-in of `P256VERIFY` / `ecrecover`, a
  revert-on-malformed stand-in and a **burn-all stand-in** that consumes all forwarded gas on malformed input included, M7),
  a mutant without the alive-check and a mutant without the explicit gas limit (each must make that test fail); the cap
  covers the worst input (a failed call at its limit plus the alive-check), pinned. At the registry: a stand-in verifier
  returning an empty, a two-word and a `2` return each falls back, never accepts (M7).

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
  signature. The configuration that catches M1: the accept-all generation is **both** the verify-only carrier of the
  record's kind **and** the record's PQZ home (it enables `0x0142`, the holder's generation does not), and a predecessor's
  single-key UA sends `setPqzKey` / `setPqzScopedKey` there with a bad signature; a mutant of `_single` that tests
  `uint160(cfg) == 0` instead of `!_registrable(cfg)` must make it fail. (f) **Three generations (N2, N3):** gen 3 over gen 2 over gen 1, gen 2 carrying the kind verify-only with an
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
- **Generation 1 carries the new views (W3).** Pre-freeze, the gen-1 code gains the views of §11.3 and the `txGasCap`
  parameter (X1; one registry code serves every generation, so generation 1's deploy probes the cap too); the SCaaS testnet's
  gen 1 is redeployed with it at its next reset. A gen 1 deployed before that cannot be a predecessor (the probes of §11.3
  refuse it, `UAConfig(0)`); all chains are test-only today.
- **The per-transaction cap (owner X1).** No opcode exposes EIP-7825's cap, so the deploy script probes it off chain before
  broadcast, through the chain's node list with the strict-majority option (ARCH-POS-15): `eth_call` (or `eth_estimateGas`)
  of a cheap call with gas `2^24` and `2^24 + 1`, then, where `2^24 + 1` is accepted, a binary search up to the block gas
  limit for the largest accepted value (owner P18: the search and its rows). The value found is the constructor's
  `txGasCap` and is recorded in the book with the probe's rows and the nodes' client versions. Where no cap is found below the
  block gas limit (a chain without EIP-7825), the deploy refuses by name (`GEN_TX_CAP_UNKNOWN`, owner P15) until the owner
  sets the value in the book. The book's value and the probe must agree, else `GEN_TX_CAP_MISMATCH` (owner P15). A chain
  that raises its cap later keeps the old bound in every deployed generation; the next generation takes the new value. One
  rule on every chain: nothing assumes 2^24.
- **`0x0142` in every later generation (owner M9).** `msig` is a PQZ holder kind in every generation, so a later generation
  without `0x0142` behind one with it would bar its own `msig`s and holder kinds from PQZ until the next generation, and a
  portable registration that carries a PQZ key could not be copied there at all (`UAKindDisabled(0x0142)` at `register`).
  The deploy therefore enables `0x0142` in every later generation whenever a predecessor enables it (the same `pqz-mlwe`
  verifier address serves, its code hash checked). Leaving it out is refused by name (**`GEN_PQZ_OMITTED`**, owner P15)
  and can be overridden only with the owner's confirmation recorded in the book with the reason.
- **The PQZ debit check (M10 d).** Per verify-only kind, the deploy runs §2's check of the single-key fallback against
  `_msigDebit`'s bound before broadcast and refuses by name (`GEN_PQZ_DEBIT_BOUND <kind>`) with the numbers for the owner.
- **Deploy book (F14).** The registry's address, generation, `predecessor` and code hash; its `txGasCap` with its probe rows
  (X1); whether `0x0142` is enabled and any owner-confirmed `GEN_PQZ_OMITTED` override (M9); its libraries and their code
  hashes; per verify-only kind `{kind, verifier, cap, keyForm, precompile, eip, status, probe_rows_hash, probe_rows}` (the
  constructor's rows and the differential rows run); the node list and client versions of the probe; the walk check's
  result and any owner-confirmed `GEN_NOT_LATEST` override; the router and factory that bind it (§10); the Blockscout
  verification of every one of them ([NET-EVM-12](../../networks/evm.md#NET-EVM-12)); the Draft flag of CTR-UA-69 where set.
- **Size.** On `bls-multi` after its library split (`size-baseline.json` there, commit `383d1e2f8`), against the size gate's
  T-1 lines (library 35,694 B, plain 35,286 B; `scripts/size_gate.py`) under the 131,072 B ceiling:

  | Contract | Form | Runtime | T-1 line | Room |
  |---|---|---|---|---|
  | `UARegistry` | plain | 33,293 B | 35,286 B | 1,993 B |
  | `UARegistryCoreLib` | library | 15,737 B | 35,694 B | 19,957 B |
  | `UARegistryRegLib` | library | 30,157 B | 35,694 B | 5,537 B |
  | `UARegistryAuxLib` | library | 35,417 B | 35,694 B | 277 B |
  | `OpenFactory` | plain | 34,999 B | 35,286 B | 287 B |

  So the walk's logic goes to `UARegistryCoreLib` (owner Y1) and `UARegistry` grows only by the thin views, the constructor
  rules and the kind word's flags. `UARegistryAuxLib` (the PQZ positions of §11.2) and `OpenFactory` (the env walk of §10)
  have almost no room: the build stops and reports the sizes there if a T-1 line is crossed (no module split and no size
  lever without the owner's word). The figures move with `bls-multi`'s remaining tasks; the round re-reads them before
  its first task. The baseline moves with its reason, old → new in each commit.

**CTR-UA-69 (owner R9).** Which addresses a PQ verifier's deploy probes, for gen 1's ML-DSA verifiers today and every later
generation's verifiers:

- **By default** only the addresses of an EIP in **Final** status and the precompiles the chain profile declares as the
  chain's own: on the SCaaS chains `0x…5caa0012` / `13` / `14` ([NET-EVM-15](../../networks/evm.md#NET-EVM-15), defined since
  this spec was written). The
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

**CTR-UA-70 (owner R10, R11, P5, P12, X1; N2, N3, N4, N11, M4 follow; the gas figures are proposals).**

- **The line.** Generation 1 has `predecessor = 0`. A later registry takes as predecessor the chain's **latest** generation,
  any `n ≥ 1`, and is generation `n + 1` (`generation = p.generation() + 1`, today `p.generation() != 1` is refused). One
  registry code serves every generation; its EIP-712 version is the generation's decimal number. **Depth cap:**
  `MAX_GENERATION = 16` (owner R11); the constructor refuses a predecessor with `generation() ≥ 16` (`UAConfig(0)`), so a
  generation 17 cannot deploy; the deploy refuses it first by name (`GEN_DEPTH`).
- **Views (owner P5, P7 with M4, P14).** `holderOf(bytes32 ua) → (address holder, uint16 kind, address pqzHome)`, the one
  walk: if this generation holds the record, `(this, kind, this if it enables 0x0142 else 0)`; else `(h, k, p) =
  predecessor.holderOf(ua)` (`(0, 0, 0)` at generation 1), and where `h ≠ 0`, `p == 0` and this generation enables `0x0142`,
  `p = this`; return `(h, k, p)`. One call per generation, O(n) at depth n (M4: a second recursive walk per PQZ read, with a
  `holderOf` at every enabling generation, would cost O(n²) hops, ≈ 1.3 M on a miss at depth 16). `pqzHomeOf(ua)` is a thin
  view returning the third word. **Where the logic lives (owner Y1):** the walk's logic (the local answer, the predecessor
  call, the `pqzHome` fill, `kindHome`'s recursion, each forwarding reader's choice of target) is in `UARegistryCoreLib`;
  `UARegistry`'s `holderOf`, `kindHome`, `verifierOf`, `pqzHomeOf` and the forwarding readers are thin views that
  DELEGATECALL into it through `_libView`, as today's library readers do; the consumer path in `UARegistry` reaches the
  walk by a static self-call to its own thin `holderOf` view (a few hundred gas more [estimate]; proposal P21), the
  libraries by their internal walk. The selectors stay on the registry, so the frozen interface (§11.3) does not change; a predecessor's
  walk is called as `IUARegistry(predecessor).holderOf(ua)`. `kindHome(uint16 kind) → address`: this
  generation if the kind is registrable here (`_registrable`), else the predecessor's answer, 0 at generation 1 (for
  `0x0142`, which several generations may enable, §11.2, it is the newest such generation on the walk). `verifierOf(uint16
  kind) → address`: this generation's verifier word's address (0 if none). `verifyOnly(kind)`. `pqzHomeOf(ua)` (§11.2).
  `txGasCap()` (X1).
- **Lookups.** Every reader that forwards today reads `holderOf(ua)` once and reads the record at the holder directly (N11):
  `recordOf`, `kindOf`, `registrationOf`, `keyOf`, `webAuthnKeyOf`, `muSig2KeyOf`, `frostKeyOf`, `popOf`, `popSlotsOf`,
  `msigOf`, `msigStateOf`, `memberAccepted`, `memberSigHashOf`, `checkedOf`, the KEM views, `expandedKeyOf`; the PQZ views
  by §11.2. `keyOwner` walks back (local first, then the predecessor), so `UAAlreadyRegistered` / `UAKeyInUse` cover the
  line. The per-kind lists and decoys ([CTR-UA-29](../../contracts/accounts.md#CTR-UA-29)): a kind's list lives in its home;
  `msig` has one list per generation; `0x0142` by §11.2.
- **Native-space shortcut (owner P5).** An id in the native space (`UAKinds.inNativeSpace`: top 12 bytes zero) is answered
  `kindOf = 0`, `holderOf = (0, 0, 0)`, `isRegistered = false` without walking: every generation's registration refuses such an
  id (`UAIdInNativeSpace`), so none can hold it; tokens already skip the registry for it (`MtxPipelineLib._checkTo`). It
  rests on every generation of the line refusing such ids (§11.3); a test registers through every form with a native-space
  id and finds nothing stored.
- **Single-key registrations walk nothing (N11, owner P12).** A single-key kind registrable here has its kind and its
  keyHash group only in this generation (the constructor refuses it otherwise), so `_identify`'s `UAAlreadyRegistered` and
  the group's `UAKeyInUse` read this generation only; `msig` (re-enabled in every generation) and the PQZ key (§11.2) keep
  the walk. This rests on the constructor's "kind and group only here", so on the predecessors' `kindHome` answers at
  deploy: W5's trust in predecessors (§11.3), guarded by the deploy's walk check against the book (§9).
- **The per-transaction cap (owner X1).** Each generation has its own immutable `txGasCap` (§2, §9); every bound of the
  generation (§3's PQZ holder bound, §4's hard bound, §2's PQZ debit check) uses its own value.
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
  registered nowhere): the whole line, ≈ 80–120 k at depth 16. **Library call overhead (owner Y1):** each thin view's
  DELEGATECALL into `UARegistryCoreLib` costs a few hundred gas [estimate: the call, `_lib`'s calldata copy with its appended
  words, the return copy], plus 2,600 once per transaction where that generation's library address is still cold
  (EIP-2929); generations that share one library deployment (same code, same CREATE2 address) pay the cold access once. So a
  hop costs ≈ 5 k plus the view's few hundred, ≈ 8 k with a cold library [estimate], and a miss at depth 16 ≈ 125–170 k
  [estimate]. A forwarded signature check (not a read) holds `1/63` of the
  holder's cap plus `GAS_MARGIN` once (N3). `_slotCap`, `_pqzHolder` and the caps count the hops to the member's holder
  (fixed: a record never moves, a predecessor never changes).
- **Mitigations (proposals).** (1) The native-space shortcut (owner P5). (2) The depth cap bounds the miss. (3) The SDK gas
  table carries the extra per registry and per depth (§12).

### 11.2 The PQZ attachment over N generations (`CTR-UA-71`)

**CTR-UA-71 (owner W2, P7, P8, M9; M1, M3, M4, M5 follow).** Today (rulings A5-I1 and A6-I1, [decisions.md](../../decisions.md)
UA-8 entry (d)) a UA's PQZ attachment (the `setPqzKey` versions, the proofs, `proven`, the `keyOwner` of proven PQZ keys, the
`0x0142` list slot, `current`, the scoped records) lives in the oldest generation that enables `0x0142`, the record stays
where it was registered, `0x0142` lives in one generation (the group check), and a generation in front of one that enables
`0x0142` refuses a PQZ key. With N generations that bars every later generation's records from PQZ for the life of the line;
the owner refused that (W2).

- **The PQZ home of a record (owner P7).** For a record held in generation `j`, read through generation `k ≥ j`: the
  **oldest generation `g` with `j ≤ g ≤ k` that enables `0x0142`**, or none. It is the third word of the one walk
  `holderOf(ua)` (§11.1, M4): at the holder, itself if it enables `0x0142`, else 0; at a later generation, the predecessor's
  answer if it is not 0, else itself if it enables `0x0142` and the holder is not 0, else 0. `pqzHomeOf(ua) → address` is a
  thin view over that walk (owner P14), never a second walk. A later generation that enables `0x0142` so hosts its **own**
  records (W2) and the records of earlier generations that have no home below it (today's A6-I1 host); a record's home, once
  a reader sees one, never changes (records never move, predecessors never change). A reader below the home sees none, as
  gen 1 sees none of gen 2's attachment today.
- **What changes in today's A5-I1 rule.** (1) A later generation **may** enable `0x0142` although a predecessor enables it:
  `0x0142` is exempt from `_groupInPredecessor`; it is never verify-only (§2). (2) The `pqz-mlwe` keyHash group stays unique
  across the line by the walk: a proof in a home checks `keyOwner` here and through every predecessor (`UAKeyInUse`), as
  `_pqzOwn` does through `keyOwner` today. (3) The refusal `UAKindDisabled(0x0142)` stays only for a generation that does not
  enable `0x0142` while `predecessor.kindHome(0x0142) != 0`, for its own records (a key placed there has no home yet;
  its records get one when a later generation that enables `0x0142` is deployed, and their keys are then set there by
  `setPqzKey`). With owner M9 the deploy no longer builds such a generation (§9: `GEN_PQZ_OMITTED`, overridable only by the
  owner, recorded), so (3) applies only under that override; the contract keeps the refusal for it. (4) "The oldest
  generation that enables `0x0142`" of A6-I1 reads "the record's PQZ home". Today's two-generation behaviour is the case
  `k ≤ 2` of these rules.
- **Writes.** `setPqzKey`, `setPqzScopedKey`, `storePqzPop`, `storePqzScopedPop` are accepted only at `pqzHomeOf(ua)`
  (`UAUnauthorized` elsewhere; the node's `UA_WRONG_GENERATION` names that target), the signature of a signed one checked
  by `holderOf(ua)` (§3).

| Position | Today (two generations) | N generations (owner P7) |
|---|---|---|
| `UARegistry._pqzHost()` | per generation: `predecessor ≠ 0` and `0x0142` enabled here | per UA: `pqzHomeOf(ua) == address(this)` and the record not held here |
| `UARegistryAuxLib._host(ua)` (where the four PQZ writes go) | held here ⇒ false; a gen 2 with `0x0142` and `kindOf ≠ 0` ⇒ true; else `UAUnauthorized` | held here ⇒ false (then A5-I1 (3) decides whether a key is allowed); `pqzHomeOf(ua) == address(this)` ⇒ true; else `UAUnauthorized` |
| `UARegistryAuxLib._away(ua)` (scoped reads) | not held here and no `0x0142` here ⇒ the predecessor | not held here and `pqzHomeOf(ua) ≠ address(this)` ⇒ forward to `pqzHomeOf(ua)`, or to `holderOf(ua)` where it is 0 |
| `UARegistryAuxLib._scopedFrom()` (a scope's holder list) | no `0x0142` here ⇒ the predecessor's list first, then this one's (U4h-2) | the lists of every generation on the walk that enables `0x0142`, oldest first; where none does, today's rule. Sound with A5-I1 (3): above the first generation that enables `0x0142` no record without a home holds a key |
| `UARegistryAuxLib._pqzRecord` (copy of a version at the home) | from `_pred()` ("gen 1") | from `holderOf(ua)` (no generation between the holder and the home writes the attachment) |
| `UARegistryAuxLib._pqzNext` (version 0, `latest`) | `_pred()`'s | `holderOf(ua)`'s |
| `UARegistryAuxLib._kemHash`, `_registerKeyMessage` | `_pred().registrationOf`, `_kindOf` | `holderOf(ua).registrationOf`, the kind from `holderOf` |
| `pqzKeyOf`, `pqzKeyAt` (`_pqzAt`), `pqzKeySigOf`, `pqzPopOf`, `pqzKeyUsed`, `pqzKeyLatest`, `recordOf`'s `pqzKey`, `checkedOf`'s `pqzPop`, `registrationOf`'s proof patch, `pqzScopedKeyOf` / `At` / `Latest`, `pqzScopedPopOf`, `pqzOpenKemAt` | forward to the predecessor unless `_pqzHost()`; `pqzKeyLatest` the max of this and the predecessor's; `pqzKeyUsed` this or the predecessor's | one rule: home == this ⇒ this generation's, with the holder's for a version not copied (host rule 2), `pqzKeyLatest` the max of this and the holder's, `pqzKeyUsed` this or the holder's, `registrationOf` the holder's with this home's stored proof; home ≠ this and ≠ 0 ⇒ forward to the home; home == 0 ⇒ forward to the holder |
| `0x0142` list (`uaCount` / `uaAt` / `uaPage` / `uaIndex` of `0x0142`: the decoy set) | the one enabling generation's list | one list per enabling generation (as `msig`, M5): `uaCount` / `uaAt` / `uaPage` / `uaIndex` of `0x0142` on a generation answer **its own** list only, never a concatenation (every enabling generation's list keeps growing, an older home still takes proofs, so a position in a concatenated sequence would shift and `uaPage` would race; nothing on chain consumes a position). The SDK reads the list of every enabling generation on the token's registry's walk and concatenates them for the decoy draw, so the anonymity set covers the line |
| `keyOwner` of group `pqz-mlwe` (`_pqzOwn`) | walks back; one enabling generation | walks back (this and every predecessor): unique for proofs made in the newest home; residual below |
| `_pqzHolder` (A5-I1, MD-13) | `UAKindDisabled(0x0142)` when the predecessor enables it; a gen-1 holder's cap from `_pred()` | A5-I1 (3); `w` of `_msigDebit` the fallback worst of the consumer path (owner M2, §3): this generation's cap and hold where the kind is verify-only here, plus the holder's cap from `holderOf(ua)`, one hand-off and the reads; against `txGasCap` |
| indexer, node | the PQZ events of one host | the PQZ events of every generation that enables `0x0142` (§12) |

- **Residual (owner P8, corrected text of M3).** An older home cannot see a newer one: a PQZ key proven first in a newer
  home can later be proven for another UA in an older home (whose own walk does not reach the newer generation), so two UAs
  of the line may each hold the same `pqz-mlwe` key **proven**, and a token bound to a generation at or above the newer home
  reads both (`pqzKeyOf` forwards to each record's home). This is **not** A1-I1's class (one UA with a second,
  never-provable key in gen 1).
  - **Who can cause it.** Only the holder of the secret key: placing the hash in a home needs that home's `R_REG` proof,
    which binds the UA (`pqzKeyDigest`), so a duplicate is self-inflicted **if `R_REG` is a proof of knowledge**
    (UNAUDITED). No one can squat another UA's key (KV-2's purpose).
  - **What relies on uniqueness.** Checked on this tree: no code under `src/pqz/` reads `keyOwner`; `PqzCore` reads a
    holder's key only forward, from the UA (`_keyOf`: `pqzKeyOf` / `pqzScopedKeyOf`; `_debitKey`: KV-8's capture-once
    debit), and never maps a key back to a UA. So no `PqzCore` property relies on one key per UA by code; the build
    re-checks this and Fable's review of the built round is asked it. The one observable effect is on the decoy draw: one
    key may appear twice in the concatenated `0x0142` lists (the SDK draws decoys by distinct key hash, owner P19).
  - **Accepted (owner P8)**, each reader seeing one owner per generation (`keyOwner` answers local first) and indexers
    flagging a hash owned twice on the line (§12).
  - **The on-chain alternative, taken instead if the build or the review finds a `PqzCore` property that relies on one key
    per UA (owner P8).** A duplicate can only arise newer home first, older home second (the newer home's proof walks every
    predecessor's `keyOwner`). So a reader at or above the newer home can refuse the late one: **a key read from home `g`
    through generation `k` is usable only if no generation in `(g, k]` has `keyOwner[hash]` set to another UA** (cost:
    `k − g` more hops on a PQZ key read; no griefing, since placing a hash in the newer home needs its `R_REG` proof, which
    binds the UA).
- **Tests (three generations).** (a) gen 1 with `0x0142`, gen 2 without (built directly, as under the owner's M9 override;
  the deploy refuses it by default, test (f)), gen 3 with: a gen-1 record's attachment stays in
  gen 1 and reads through gen 3 forward there; gen 2 refuses a PQZ key for its own record (`UAKindDisabled(0x0142)`); gen 3
  accepts `setPqzKey` for that gen-2 record and for its own; gen 3 refuses a key hash proven in gen 1 (`UAKeyInUse`); the
  `0x0142` list of each generation is its own (gen 1's list unchanged by gen 3's entries, M5). (b) gen 1 without, gen 2 with, gen 3 with: a gen-1 record's home is
  gen 2; through gen 3 every PQZ view forwards to gen 2, and gen 3 refuses its PQZ writes (`UAUnauthorized`); gen 3's own
  records are homed in gen 3. (c) The residual: a hash proven in gen 3 is then proven for another UA in gen 1 (documented
  behaviour, the test pins it). (d) The scoped lists and `pqzKeyLatest` in (a) and (b). (e) `PqzStateLib` on a token bound
  to gen 3 in (a): a gen-1 holder's unproven key is refused. (f) M9: the deploy of a later generation without `0x0142`
  behind one with it is refused `GEN_PQZ_OMITTED`, and passes only with the owner's override recorded in the book. (g) M4:
  `holderOf` of an unregistered id through a line of four generations that all enable `0x0142` makes one call per
  generation (gas against a pinned per-hop figure), and `pqzHomeOf` equals `holderOf`'s third word for every record of (a)
  and (b). (h) M1 in a PQZ home: §7 (e)'s single-key configuration. These are PQZ changes: the per-set run of AGENTS.md.

### 11.3 The walked interface and the trust in predecessors (`CTR-UA-72`)

**CTR-UA-72 (owner W3, W4, W5, P13; M8 follows).**

- **Every generation carries the views (W3).** `holderOf` (with the kind and the PQZ home, M4), `kindHome`, `verifierOf`,
  `verifyOnly`, `pqzHomeOf`, `txGasCap` (X1) and a forwarding `expandedKeyOf` are in the registry code from now, generation 1 included (pre-freeze; the
  SCaaS testnet's gen 1 is redeployed at its next reset). Each generation's constructor walks its predecessors and probes
  each one (`try` … `catch` ⇒ `UAConfig(0)`, as `checkedOf` today): `holderOf(0)`, `kindHome(0)`, `verifierOf(0)`,
  `verifyOnly(0)`, `pqzHomeOf(0)`, `txGasCap()`, `expandedKeyOf(0)`, plus today's `checkedOf`, `memberSigHashOf`, `msigStateOf`. So a read
  on a predecessor fails only by gas (F11).
- **The frozen interface (W4).** Later generations are later code; what a successor calls on a predecessor is frozen. The
  list (function, argument and return types as in `IUARegistry`): identity `predecessor`, `generation`, `chainUid`,
  `hederaNative`, `verifyBudget`, `txGasCap`, `smartKeyCloneHash`; kind table `kindEnabled`, `verifyOnly`, `verifyCap`, `verifierOf`,
  `kindHome`; records `holderOf`, `kindOf`, `isRegistered`, `recordOf`, `keyOf`, `webAuthnKeyOf`, `muSig2KeyOf`,
  `frostKeyOf`, `registrationOf`, `popOf`, `popSlotsOf`, `expandedKeyOf`, `keyOwner`, `checkedOf`; `msig` `msigOf`,
  `msigStateOf`, `memberAccepted`, `memberSigHashOf`; KEM `kemKeyOf`, `kemKeyAt`; PQZ `pqzHomeOf`, `pqzKeyOf`, `pqzKeyAt`,
  `pqzKeyLatest`, `pqzKeyUsed`, `pqzKeySigOf`, `pqzPopOf`, `pqzScopedKeyOf`, `pqzScopedKeyAt`, `pqzScopedKeyLatest`,
  `pqzScopedPopOf`, `pqzOpenKemAt`, `pqzScopedCount`, `pqzScopedAt`; lists `uaCount`, `uaAt`, `uaPage`, `uaIndex`; checks
  `requireAuthorized`, `requirePortable`, `requirePortableApp`. **Also frozen (M8)**, because successors and the node
  depend on them: the error selectors `UAStore.via` matches (`UAVerifyGas`) and the errors the node names (`UAKeyNotCached`,
  `UAKeyCache`, `UAKeyData`, `UAPoP`, `UAUnauthorized`, and the new `UAVerifyOnly`); the ABI encodings of `UASig` and
  `MemberSig`; the verifier getters a successor calls on a predecessor's verifier (`PRECOMPILE()` on every PQ verifier, and
  `KEY_FORM()` on a verify-only one); the hold formula `cap/63 + GAS_MARGIN` (`GAS_MARGIN` = 5,000) that `_slotCap` and the
  bounds assume of a holder; the pointer form that `expandedKeyOf` returns (`address[3]`, SSTORE2 pointers to the cache
  parts in the form `UAStore` writes and `verifyCached` reads). Pinned by a test (`RegistryWalkInterfaceIsPinned`, owner P13): the full signatures
  with return types, their selectors, the error selectors, the two struct encodings' type strings, the verifier getters,
  the hold constants and the hash of the list, as the typehash pins; a change moves the pin with old → new in the commit and
  needs the owner.
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
  reference table carries every path. The PQZ decoy draw reads the `0x0142` list of every enabling generation on the walk of the token's registry and concatenates them (§11.2, M5), drawing by distinct key hash (owner P19).
- **Off-chain readers** (SDK review finding F2, 2026-11-20; normative at
  [accounts.md, off-chain readers](../../contracts/accounts.md#off-chain-readers) under CTR-UA-70). One rule for every
  off-chain reader (the SDK's PQZ, verdict and Zether reading layers, indexers, wallets): a record of `ua` is read where it is
  held. Call `holderOf(ua)` once on the registry the token binds (one walk; a native-space id answers `(0, 0, 0)` without a
  walk), then read the record (keys, registration, KEM, `popOf`, `msig` state) at `holder` and the PQZ attachment at
  `pqzHomeOf(ua)`, the third word (at `holder` where it is 0). A reader that goes through the bound registry's own views gets
  the same answer by forwarding; a reader that reads storage, logs or library state of one registry directly must not assume
  that registry holds the record: a gen-1 holder read through a gen-2 registry must not fail closed for that reason.
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
| A precompile removed, moved or repriced above gen 2's cap | no answer from gen 2's verifier | §5: the holder's verdict, at this cap plus the holder's gas; the hard bound (§4) keeps the registry's check of every registered `msig`, fallback included, within one transaction of `txGasCap` beside the consumer reserve; an operation dearer than the reserve fails until the precompile answers again (owner M2) |
| A caller crafts input to force "no answer" | — | §5: the verifier answers 0 for malformed input and for an invalid one on a live precompile (alive-check); a test and a mutant per verifier |
| A client upgrade changes the precompile's answers | gen 2 cannot follow | the probe re-run after upgrades (§9); a laxer answer is the forgery row; a stricter one goes to the owner |
| A wrong or faulty predecessor | a registry reads keys, records and pointers from a contract that only answers like a registry; a faulty middle generation answers for any id | every generation trusts its predecessors fully (W5, §11.3); the constructor's probes bind only what a contract answers; what binds a later generation to the real line is the deploy's walk check of every address and code hash against the book (§9), `GEN_NOT_LATEST` (overridable only by the owner, recorded), the CREATE2 addresses and the governance-published env (§10). Recovery: a sibling line from the generation below, losing the records of the faulty one and later |
| A sibling generation | records split between siblings | used only where governance names it in an env; the deploy refuses it (§11) |
| A deep line | each miss walks every generation | `MAX_GENERATION`; native-space ids answered without walking; the SDK quotes the depth (§11) |
| The PQZ attachment in several homes | two UAs of the line may each hold the same `pqz-mlwe` key proven, and a token above the newer home reads both (§11.2 residual) | only the secret key's holder can cause it (`R_REG` binds the UA; UNAUDITED as a proof of knowledge); no `PqzCore` code maps a key back to a UA; indexers flag it; accepted (owner P8), with the reader-side rule of §11.2 taken instead if a `PqzCore` property is found to rely on one key per UA |
| A precompile that burns all forwarded gas on failure | the alive-check would run out of gas and the registry fall back: a caller-forced fallback | §5 (M7): the verifier calls the precompile with an explicit gas limit; a burn-all stand-in test and a mutant |
| A chain whose per-transaction cap is not 2^24 | bounds computed for 2^24 would admit structures that cannot run, or refuse ones that can | `txGasCap` is a constructor parameter probed at deploy and recorded in the book (owner X1, §9) |

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
[estimate] and its writes (W1) ≈ 12.3 M [estimate]: both are above `verifyBudget` but fit one transaction of `txGasCap` = 2^24 (16.78 M),
and nothing limits a check to `verifyBudget` at run time; the hard bound of §4 checks this at registration and at
`updateMsig`. **It cannot hold a PQZ key at any set (owner M2):** its fallback worst ≈ 12.6 M plus `PQZ_DEBIT_MIN_GAS`
(6.07 M at the default set, up to 8.03 M) is over 16.78 M, so a registration or `setPqzKey` that gives it one is refused
`UAPqzHolder` (§3). Its other operations are bounded by §4's consumer mode: registration refuses it if its fallback plus the consumer reserve does not fit.

## 14. Work list

Against the `bls-multi` layout (front matter). Each row names its file.

| Component | Work |
|---|---|
| `UARegistry` (constructor, thin views; ≈ 2.0 KB of room) | `KindConfig.verifyOnly`, `keyForm`, bits 224 / 225; the constructor rules of §2 (`verifyOnly ⇔ predecessor.kindHome(kind) != 0`, the impossible combination through the home's `verifierOf`, `PRECOMPILE() == 0` refused, `_groupInPredecessor` by `kindHome`, `0x0142` exempt); `msig` / `0x0142` outside the `⇔` rule (M6); the PQZ debit check per verify-only kind (M10 d); the immutable `txGasCap` and its view (X1); `generation = p + 1`, `MAX_GENERATION`; the walk over every predecessor with the probes of §11.3; the thin views `holderOf`, `kindHome`, `verifierOf`, `pqzHomeOf` and the forwarding readers (`_libView` into `UARegistryCoreLib`'s walk, owner Y1), `verifyOnly`, `txGasCap`; the native-space shortcut on `kindOf`, `holderOf`, `isRegistered` (before the library call); `_authorized`, `_derived`, `_memberOk` by §4 (own verifier, else the holder directly); `requireAuthorized`'s `UAKeyNotCached` branch on `holderOf`'s kind; `requirePortable(App)` by §4; `_listedHere` false for a verify-only kind; the `0x0142` list per generation (M5); `_pqzHost` and the PQZ views of §11.2; the EIP-712 version; N12 masking at `_verifierCall` (`cfg >> 160`), `kindEnabled`, `_listedHere`, `requireAuthorized`, `_derived` (`uint160(cfg)`) |
| `UARegistryCoreLib` (authorization, verify, the walk; ≈ 20 KB of room) | the walk's logic (owner Y1): `holderOf` (holder, kind, PQZ home: the one walk, M4), `kindHome`'s recursion, `pqzHomeOf` as its third word, each forwarding reader's target by `holderOf` (§11.1); the `write` flag through `_sigOk` / `_msig` / `_memberOk` / `_portableOk` / `_single` (W1, M1), default the write side, `false` only from the three consumer entries: on a write `via(holderOf(member))`; `_single` on a write `via(holderOf(ua))` whenever `!_registrable(cfg)` (N2, M1); the verify-only branch of `_portable` / `_single` / `_memberOk` from consumer entries only, with the hold on every verify-only call, group kinds included (N9); the three-state call (not through `capped`'s boolean read: exactly one word `0` / `1`, anything else and any revert ⇒ fallback, M7) and the fallback to the holder's entry of §4 (§5); failed reads ⇒ `UAVerifyGas`; `_notCached` on `holderOf`'s kind; `_slotCap` by the holder's cap plus one hand-off (N3); the hard bound as the maximum of its consumer mode (with the consumer reserve) and its write mode (the dearest of registration, `updateMsig`, `setPqzKey`) against `txGasCap` (P9, M2, M10); `_msigDebit` with `w` the fallback worst and `txGasCap` (M2); the constant `TX_GAS_CAP` removed (X1); `_accepted` / `_msigBytes` from `holderOf`; N12 masking at `_single` (`cfg >> 160` and its `uint160(cfg) == 0` test, M1), `_consent`'s `_notCached(_cfgKind(), …)` (M1), `_notCached`, `_listedHere`, `_pqzProof` |
| `UARegistryRegLib` (registration) | step 1 of every `register*` form: `_registrable` then `UAVerifyOnly(kind)`; `_identify` without the line walk for a single-key kind (N11); `pqzHolder`: A5-I1 (3) by `kindHome(0x0142)`, `w` the fallback worst (owner M2), `UAPqzHolder`; `msigBound` and the registration bound with the hard bound against `txGasCap` (`UAKeyData(0x0120)` / `UAMsigSlots(n)`, owner P9); `pqzProof` with the line-wide `keyOwner` walk; N12 masking at `pqzHolder`'s `_cfgKind() >> 160` |
| `UARegistryAuxLib` (PQZ attachment, KEM, cache, pages; ≈ 0.3 KB of room: the likely size stop) | `cacheExpandedKey` refuses a verify-only kind (`UAVerifyOnly`), N12 masking; `_host`, `_away`, `_scopedFrom`, `_pqzRecord`, `_pqzNext`, `_kemHash`, `_registerKeyMessage`, `registrationOf`'s patch by §11.2; `uaCount` / `uaAt` / `uaPage` / `uaIndex` of `0x0142` on this generation's own list (M5) |
| Verify-only verifiers | one per eligible kind (ML-DSA first): `KEY_FORM()`, the edge-class constructor rows, the valid row kept for the alive-check, the mapping of §5 (lengths and encodings first, the precompile called with an explicit gas limit, alive-check, `PqNoAnswer`; M7) |
| `PqzStateLib` | `_auditorChecks`: `kindHome(0x0142) != 0` instead of `kindEnabled` (N4); a PQZ change: its per-set run |
| `OpenFactory` (≈ 0.3 KB of room) | the env check of §10 (bounded walk, `chainUid`, `smartKeyCloneHash`) |
| `IUARegistry` | the new views (`holderOf` with three words, `txGasCap`) and errors (`UAVerifyOnly`), doc comments; the frozen list of §11.3 with M8's additions |
| Tests | T-REG-4 changed: a later generation refuses a kind a predecessor enables unless flagged verify-only, refuses the flag otherwise, refuses the impossible key form (through a middle verify-only generation too, N8), refuses a verify-only verifier without a precompile, refuses its registration (`UAVerifyOnly`) and its `cacheExpandedKey`, forwards its lists and `expandedKeyOf`; `UAKeyInUse` across the line. New: §7 (a)–(f) per eligible kind; every row of §4's table, its fallback entry included; W1: an accept-all stand-in against each of the five writes (§7 (e)), M1's single-key configuration in a PQZ home included; N2 / N3: the three-generation accept-all middle test (§7 (f)); §5: no-answer stand-ins (empty account, revert, malformed return data, out of gas at the cap, burn-all on malformed input, M7) fall back, a verifier return that is not exactly one word `0` / `1` falls back (M7), an answer 0 does not, gas below the cap is `UAVerifyGas`, the group kinds' path holds; N5: per verifier, the fuzz test and the mutant without the alive-check; ML-DSA with gen 1 on the cache and gen 2 on a precompile stand-in (form `0`), gen 2 under form `1` (incomplete cache ⇒ `UAKeyNotCached`; the layout test); the hard bound (the treasury fits, `{mldsa87 ×2} t=2` and `{mldsa65 ×3} t=3` are refused at registration and at `updateMsig`, P9; the maximum, not the sum, of the two modes; the treasury with a PQZ key refused `UAPqzHolder`, M2; every bound read from `txGasCap`: a registry deployed with a smaller cap refuses what one at 2^24 accepts, X1); the PQZ debit check per verify-only kind (M10 d); §11.2 (a)–(h); the constructor probes of §11.3 against a predecessor lacking each view; `RegistryWalkInterfaceIsPinned`; P5: no registration stores a native-space id; the depth cap; the factory walk (accept the line, refuse another chain's, a non-registry and another clone hash); T-GAS with verify-only `msig` members at the budget, per depth and on the write path; T-AUTH-4 on the new path; storage layout and typehash pins unchanged |
| Deploy | the later-generation mode of `DeployBase` with the book's latest as predecessor (`GEN_NOT_LATEST` with the owner-confirmed override, `GEN_DEPTH`, `GEN_KEY_FORM_IMPOSSIBLE`, `GEN_VERIFY_ONLY_NO_PRECOMPILE`, the walk check `GEN_WALK_MISMATCH`, `GEN_PQZ_OMITTED` (M9), `GEN_PQZ_DEBIT_BOUND` (M10 d), `GEN_TX_CAP_UNKNOWN` / `GEN_TX_CAP_MISMATCH` (X1)); the per-transaction cap probe and the constructor parameter (X1); `0x0142` enabled in every later generation where a predecessor enables it (M9); gen 1 with the new views at the SCaaS testnet's next reset; the differential probe through the node list under strict majority, the holder entry per kind (§9); the book fields (§9); `script/pq_verifiers.py` and `DeployBase._mldsaCandidates`: default candidates Final + chain-own only, Draft only under the profile flag with the fuller probe (CTR-UA-69); the verify-only verifiers; the probe re-run after client upgrades in the operations runbook |
| Node | `ua_registries` and its on-chain validation; the guard per registry, `UA_VERIFY_ONLY`, `UA_WRONG_GENERATION` (holder and PQZ home targets); NODE-JOB-29's target and `UA_KEY_NOT_CACHEABLE`; the indexer over every generation and every `0x0142` generation, the duplicate-hash flag (§12); a note for operators |
| SDK | write targets `kindHome` / `holderOf` / `pqzHomeOf`; verify rows keyed by chain, registry and kind with the path, depth and write path as columns; the decoy draw over the concatenated per-generation `0x0142` lists, by distinct key hash (P19); the per-chain `txGasCap` row; reference table rows (§12) |
| Clients | offer a kind only where `kindHome(kind) == registry`; the release's registry and verify path in the review (§12) |
| Docs | [accounts.md](../../contracts/accounts.md) §1.8 "Generations" and §1.9, T-REG-4's row, CTR-UA-05's "a registry generation supports a fixed set of kinds" (a verify-only kind is verified, not supported for registration), CTR-UA-29's per-generation lists, `0x0142` included (one list per enabling generation); the PQZ attachment rule (A5-I1 / A6-I1 as §11.2); the chain profiles (chain-own precompiles, the Draft flag, the keep commitment); `decisions.md` entry with §0; node config doc; SDK spec; §15's conflicts |

N12's full list of raw reads (M1 adds `_single`'s `uint160(cfg) == 0` and `_consent`'s `_notCached(_cfgKind(), …)`):
`cfg >> 160` at `UARegistry._verifierCall`, `UARegistryCoreLib._single`, `_pqzHolder`
(`_cfgKind() >> 160`), `_pqzProof` and `UARegistryAuxLib._scopedProve` (both on `_cfgPqz()`, never flagged; masked
for one rule); `uint160(cfg) != 0` meaning "registrable here" at `_identify` and the step 1 of `registerMuSig2` /
`registerFrost`, `cacheExpandedKey`, `_notCached` (reached from `requireAuthorized`'s branch and from `_consent` with
`_cfgKind()`), `_single`'s `uint160(cfg) == 0` (becomes `!_registrable(cfg)` on a write, M1), both `_listedHere`,
`kindEnabled` (stays local, by design), `_derived`.

## 15. Conflicts to change on landing

| Where | Today | After |
|---|---|---|
| [admin-not-owner §13.4](2026-11-10-admin-not-owner.md) | "A stack with its own registry has its own router and its own factory, so one registry per factory holds"; every env publish refuses an `env.registry` other than 0 or the router's registry | one registry **line** per factory: an env may name the router's registry or a registry whose predecessor chain reaches it, same `chainUid`, same `smartKeyCloneHash` (CTR-UA-67) |
| [accounts.md](../../contracts/accounts.md) §1.9 "Generations" | "at most two generations per chain"; gen 2 enables only kinds and groups absent from gen 1 | a line of up to `MAX_GENERATION` generations (CTR-UA-70); a later generation may carry a predecessor's kind verify-only (CTR-UA-58); `0x0142` may be enabled in several generations (CTR-UA-71) |
| [accounts.md](../../contracts/accounts.md) §1.8 "Generations" | gen 2 forwards views to gen 1; "Indexers read both generations" | lookups by `holderOf` over the line; indexers read every generation (CTR-UA-65) |
| [decisions.md](../../decisions.md) UA-8 entry (d), rulings A5-I1 / A6-I1 | the PQZ attachment lives in the oldest generation that enables `0x0142`; a gen 2 in front of a gen 1 that enables it refuses a PQZ key | the record's PQZ home (CTR-UA-71); the refusal only for a generation without `0x0142` behind one with it, which the deploy builds only under the owner's override (M9) |
| `UARegistryCoreLib.TX_GAS_CAP`, `DeployBase.TX_REGULAR_GAS_CAP`, `_msigDebit` / `msigBound` | the constant 2^24 | the registry's immutable `txGasCap` from the deploy book, probed at deploy (owner X1) |
| `PqzStateLib._auditorChecks` | `kindEnabled(0x0142)` of the token's registry | `kindHome(0x0142) != 0` |
| `script/pq_verifiers.py`, `DeployBase._mldsaCandidates`, [evm.md](../../networks/evm.md) | `0x12`–`0x14` probed first | Final and chain-own by default; Draft under the owner-confirmed flag (CTR-UA-69) |

## 16. Open questions for the owner

The questions of revision 1 (Q1 – Q11) are ruled (§0.2), revision 2's P1 – P6 (§0.3), revision 3's P7 – P14 and
revision 4's P15 – P20 and Y1 (§0.4). Open (proposal, not a ruling):

| # | Question | Proposal |
|---|---|---|
| P21 | How `UARegistry`'s own consumer path reads the walk under Y1 | a static self-call `IUARegistry(address(this)).holderOf(ua)` to its thin view (smallest in `UARegistry`'s bytes; a few hundred gas more per check [estimate]), rather than a second DELEGATECALL helper with its own calldata or moving the consumer branch into the library |

## Sources

Fable review of revision 1 and Fable fix-checks of revisions 2 and 3 (2026-11-19; private scratchpad, not in the repo).
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
`src/pqz/PqzStateLib.sol` (`_auditorChecks`), `src/pqz/PqzCore.sol` (`_keyOf`, `_debitKey`; revision 4's check that no `src/pqz/` code reads `keyOwner`, at `3e01f2f18`), `src/pqz/PqzSet.sol` and `pqz-core/params/sets/*/PqzSet.sol` (`PQZ_DEBIT_MIN_GAS`), `src/factory/OpenFactory.sol` (`uaRegistry`, the env check,
`EnvRegistryMismatch`, `configureChain`), `src/metatx/MtxPipelineLib.sol` (`_checkTo`), `script/DeployBase.sol`
(`_deployUARegistry`, `_pqKindFits`, `_mldsaCandidates`, `UA_VERIFY_BUDGET`), `script/pq_verifiers.py`;
`scaas-node/src/main.rs` (`ua_registry`), `guard.rs` (`Rule::UaRegistry`, `UA_KEY_NOT_CACHED`), `indexer.rs` (`pay_filter`).
