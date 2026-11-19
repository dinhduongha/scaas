# Spec: a registry generation 2 that verifies generation-1 kinds ("verify-only kinds")

2026-11-19. Status: **SPECIFIED**, nothing built. Everything cryptographic stays **UNAUDITED**. Scope: **EVM** (the contracts,
the deploy, the node, the SDK and clients); the other families take the principle in their own rounds (§9, PLANNED).
Rule ids `CTR-UA-58` … `CTR-UA-66` are **placeholders**: the highest id defined is `CTR-UA-46`, and
`2026-11-19-bls12381-multi.md` holds `CTR-UA-47` … `CTR-UA-57`; landing assigns the real ones, writes the
[decisions.md](../../decisions.md) entry with §0 verbatim and moves the rules into [accounts.md](../../contracts/accounts.md).
Rows marked **owner** are the owner's ruling; **follows** applies a stated rule; **proposal** is the author's and is listed in
§12 for the owner.

## 0. Owner ruling this spec implements (2026-11-19)

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

| # | Topic | Resolution | Source |
|---|---|---|---|
| V1 | Verify-only kinds in gen 2 | a gen 2 may carry a kind gen 1 enables as verify-only, with its own verifier | **owner** (b) |
| V2 | Writes | registration, record, key pointer, keyHash group, every key write stay with gen 1 | **owner** (b) |
| V3 | Who uses it | token releases that bind gen 2; existing tokens keep gen 1 | **owner** (b) |
| V4 | Mutability | none: gen 2 is a new immutable deployment, no admin, no table | **owner** (b); [CTR-UA-15](../../contracts/accounts.md#CTR-UA-15) |
| V5 | Rules `CTR-UA-58` … `-66` | §2 – §9 | **proposal** except where a row cites a ruling |

## 1. The code today (`ua-rs-sign` `a19151d64`)

| Where | What it does | Why it blocks V1 |
|---|---|---|
| `UARegistry` constructor | `_groupInPredecessor(pred, kind)` reverts `UAConfig(kind)` for any kind whose keyHash group a gen-1 kind enables | a kind gen 1 enables cannot be configured at all |
| `UARegistry.KindConfig` | `{uint16 kind; address verifier; uint64 cap}`, stored as one immutable word `verifier \| cap << 160` per slot (bits 224–255 unused) | no way to declare "verify only" |
| `UARegistry._authorized` | `kind == 0` (record not held here) ⇒ `UAStore.via(predecessor, …)`: gen 1 checks with gen 1's verifier | a gen-1 record never meets gen 2's verifier |
| `UARegistry._derived` | for a stored kind or purpose `member`, reads `_s.records[id]` only; `r.kind != kind` ⇒ `false` | a gen-2 `msig`'s member held in gen 1, of a kind gen 2 enables, would be refused |
| `UAStore.expanded`, `expandedKeyOf` | this generation's ML-DSA cache only; `_derived` prefers the cache whenever one is there | gen 1's cache is invisible; a gen-2 precompile verifier would be handed a cache it cannot use |
| `requireAuthorized` (`UAKeyNotCached` branch), `UARegistryCoreLib._notCached` | read `_s.records[ua].kind` | no named refusal for a gen-1 record |
| `UARegistry.requirePortable` / `requirePortableApp` | `_elsewhere(ua)` ⇒ forward to gen 1; `UARegistryCoreLib._portable` refuses `r.kind == 0` | portable and app purposes of a gen-1 record never meet gen 2's verifier |
| `UARegistryCoreLib._memberOk` (stored paths) | a derived member goes through `UAStore.via(address(this), …)`, i.e. `requireAuthorized` | follows `_authorized`; the bls spec's `0x0121` branch adds "the member's record must be held here with that kind (else `false`)" |
| `UARegistry._listedHere`, `UARegistryCoreLib._listedHere` | a kind with a verifier here is listed here | `uaCount` / `uaAt` / `uaPage` of a verify-only kind would read gen 2's empty list, not gen 1's |
| `UARegistryCoreLib._identify` step 1 | `UAKindDisabled` only when the verifier word is 0 | a verify-only kind would register in gen 2 |
| `UARegistryCoreLib._slotCap` | `verifyCap(kind) == 0` ⇒ the member is handed to gen 1 (`cap + cap/63 + GAS_MARGIN`) | must count a verify-only member's own path instead |
| `kindEnabled(kind)` | true iff a verifier word is set; clients read it before offering a kind for registration ([§1.9](../../contracts/accounts.md#verifiers)) | true for a kind gen 2 must refuse to register |
| `DeployBase._deployUARegistry` | deploys generation 1 only (`predecessor` 0); no gen-2 deploy path exists | §6 |
| node config | one `[[chains]] ua_registry`; the nine registry writes target it only ([NODE-JOB-19](../../node/job-api.md#NODE-JOB-19)) | registrations of a verify-only kind must go to gen 1 |

## 2. Which kinds, and how they are declared (`CTR-UA-58`)

**CTR-UA-58 (proposal).** A generation-2 `UARegistry` may carry a kind **verify-only**: every **single-key** kind of the kind
table that gen 1 enables (the signing kinds, PQ `0x0130`–`0x0135`, the group kinds `0x0110`–`0x0113`, `zether-bls12381`
`0x0141`, and `bls12381-multi` `0x0121` once built). Never `msig` `0x0120` (a structure: gen 2 already re-enables it in full,
§1.8 "Structures"; a gen-1 `msig` record stays forwarded whole, §3), never `pqz-mlwe` `0x0142` (not a kind: its proof check is a
write of the PQZ attachment, ruling A6-I1).

- **Declaration.** `KindConfig` gains `bool verifyOnly`; the constructor stores it as bit 224 of the kind's word (`verifyCap`
  reads `uint64(word >> 160)` and is unchanged). The word reaches the libraries as today (`_lib`'s appended `_cfg(kind)`), so
  they need no getter.
- **Constructor.** `UAConfig(kind)` unless `verifyOnly ⇔ IUARegistry(predecessor).kindEnabled(kind)`: a verify-only flag on gen 1,
  on a kind gen 1 does not enable, or on `msig` / `0x0142` is refused; a kind gen 1 enables without the flag is refused as
  today. A verify-only kind is exempt from `_groupInPredecessor` (its group **is** gen 1's and stays there); every other kind
  keeps that check. The existing predecessor checks stay (`generation() == 1`, `chainUid`, `hederaNative`, `checkedOf`,
  `memberSigHashOf`, `msigStateOf`). The cap is gen 2's own measured cap, `0 < cap ≤ verifyBudget` as every kind, and the
  deploy's 75 % rule (`_pqKindFits`) applies.
- **The keyHash group stays gen 1's.** Gen 2 writes no `keyOwner` for a verify-only kind and reads `keyOwner` through gen 1
  as today.

## 3. Writes refused, reads forwarded (`CTR-UA-59`)

**CTR-UA-59 (proposal).** For a verify-only kind gen 2 writes nothing:

- `register`, `registerWebAuthn`, `registerMuSig2`, `registerFrost` (and `registerBlsMulti`) of that kind revert
  **`UAVerifyOnly(uint16 kind)`** (new, named: "register in `predecessor()`"), at step 1 (`_identify`), before any other check.
- `cacheExpandedKey(kind, …)` of that kind reverts `UAVerifyOnly(kind)`: the cache is filled in gen 1 (open to anyone, as today).
- The later key writes of a gen-1 record (`setKemKey`, `setPqzKey`, `storePqzPop`, `setPqzScopedKey`, `storePqzScopedPop`,
  `acceptMembership`, `updateMsig`) keep today's rule: `UAUnauthorized` on gen 2 for a record it does not hold, except the PQZ
  host case of ruling A6-I1, unchanged.
- **Views.** `kindEnabled(kind)` stays true (a verifier is there); new view **`verifyOnly(uint16 kind) → bool`**. A client
  offers registration on a registry only where `kindEnabled && !verifyOnly`. `uaCount` / `uaAt` / `uaPage` / `uaIndex` of a
  verify-only kind forward to gen 1 (`_listedHere` is false for it, in `UARegistry` and `UARegistryCoreLib`). `kindOf`,
  `recordOf`, `keyOf`, `registrationOf` and the other readers forward as today. Gen 2 emits no event for a verify-only kind.
- An `msig` registered in gen 2 may name gen-1 members of a verify-only kind (`kindOf(member) == memberKind` through gen 1, as
  today).

## 4. The authorization path (`CTR-UA-60`)

**CTR-UA-60 (proposal).** Wherever gen 2 checks a signature of a single-key record that gen 1 holds and whose kind is
verify-only in gen 2, gen 2 verifies it itself, with its own verifier, under its own `verifyCap` and the caller's hold
(T-AUTH-4), and never hands it to gen 1:

| Path | Today | Verify-only |
|---|---|---|
| `requireAuthorized`, the signer (`_authorized`) | `via(predecessor)` | `kindOf(ua)` from gen 1, then `_derived` with gen 1's key |
| `requireAuthorized`, a gen-2 `msig`'s member at either level (`_memberOk` → `_derived`, purpose `member`) | `false` (unreachable: no shared kind) | as the signer, purpose `member`, `keyData` empty ([CTR-UA-33](../../contracts/accounts.md#CTR-UA-33) B) |
| `requirePortable`, `requirePortableApp` (`_portable` → `_single`) | forward to gen 1 | the library's `_portable` on gen 1's record |
| stored paths of a gen-2 `msig` (`UARegistryCoreLib._memberOk`; the `0x0121` direct `verifyMinimal` call of the bls spec §5.3) | `via(address(this))`; `0x0121`: record held here, else `false` | as the hot path; `0x0121`: gen 1's record and key pointer instead of "held here" |
| a gen-1 `msig` record (any path) | forwarded whole to gen 1 | **unchanged**: forwarded whole; its members use gen 1's verifiers (proposal, §12 Q1) |
| PoP (`PURPOSE_POP_V2`) | gen 1 at registration | never checked by gen 2: registration is gen 1's; `_portable` refuses the purpose as today |

- **Key bytes.** Gen 2 passes exactly the bytes gen 1's code passes on that path: `keyOf(ua)` where gen 1 reads the key pointer
  (the stored kinds; `0x0121`'s stored form `p`); `registrationOf(ua).keyData` where gen 1 reads its registration blob (a
  classical kind under purpose `member`; a group kind's full key data on the portable path, whose `verifyPop` runs the group
  check under `verifyBudget`); `auth.keyData` checked by `uaOf(kind, keyData) == ua` where gen 1 does that (a classical kind's
  hot path).
- **The entry and the DST** are the ones gen 1's code calls for that path and purpose (`verify`; `verifyPop` where gen 1 calls
  it on the portable path, e.g. `0x0106` under its `DST_POP`; `verifyMinimal` for `0x0121` on the stored paths).
- **ML-DSA key form by gen 2's verifier, not by gen 1's cache.** A gen-2 verifier that verifies on the FIPS 204 `pk` (a
  precompile, `PRECOMPILE() ≠ 0`) gets `keyOf(ua)`, even where gen 1 holds a cache. A gen-2 verifier that needs the expanded key
  (no precompile, or §5 case 2) gets gen 1's **complete** cache from `IUARegistry(predecessor).expandedKeyOf(ua)`; an incomplete
  one is `UAKeyNotCached(ua)` (the named refusal reads the kind from gen 1 too). `verifyCached` trusts its pointers
  ([CTR-UA-23](../../contracts/accounts.md#CTR-UA-23) MD-10): gen 2 passes only pointers its own constructor-checked
  predecessor wrote.
- **Cost on other gen-1 records.** Only a gen 2 with at least one verify-only kind (an immutable bool) asks gen 1's `kindOf`
  before forwarding a gen-1 record; one without keeps today's code path.
- **`msig` bound.** `_slotCap` counts a verify-only member as `verifyCap(kind)` (gen 2's) plus a measured constant for the
  gen-1 reads (`kindOf`, `keyOf` or `registrationOf`), pinned by T-GAS, instead of today's hand-off `cap + cap/63 + GAS_MARGIN`.

## 5. Which later precompile a verify-only kind can use (`CTR-UA-61`)

**CTR-UA-61 (proposal).** Same kind means the same signature scheme over the same message with the same key: a gen-1
signature must verify unchanged. The current choices fix what that is: ML-DSA and SLH-DSA sign the 32-byte
`pq_msg = keccak256(TAG(kind) ‖ ua_msg)`, **pure** (not HashML-DSA / HashSLH-DSA), with the **empty** context
([CTR-UA-23](../../contracts/accounts.md#CTR-UA-23)); ML-DSA's precompile layout is EIP-8355 as pinned at `3aea9f36`
([plan P6f](../plans/2026-10-14-p6f-precompiles.md)); `fndsa512` / `fndsa1024` are Falcon specification v1.2 with EIP-8052's
SHAKE256 hash-to-point over `ua_msg`; SLH-DSA has no EIP.

| Case | Example | Eligible? |
|---|---|---|
| 1. Only the call shape differs: address, argument order, output encoding, gas | an EIP-8355 Final at another address or with another gas schedule | **yes**: a new gen-2 verifier adapts the call; same kind |
| 2. The precompile needs a key form derivable from the stored key | an EIP-8051 precompile on the expanded key derived from the FIPS 204 `pk` | **yes**: the verifier reads gen 1's cache (§4) or derives the form itself within its cap; same kind |
| 3. The algorithm differs | a precompile for HashML-DSA only; a mandatory non-empty context; Falcon FIPS 206 final ≠ Falcon v1.2 / EIP-8052 as pinned | **no**: gen-1 signatures cannot verify there; that is a new kind version (new tag, new id, re-registration: e.g. `…fndsa512.v2`, CTR-UA-23), never verify-only |

What separates case 1 / 2 from case 3 is decided by evidence, not by reading the EIP: §6's equivalence vectors (including
the pinned KATs: the EIP-8355 cases, the EIP-8051 / 8052 KATs, `pq_kat.json`, `pq_external.json`, `pq_signatures.json`) must
pass on both verifiers.

## 6. Equivalence (`CTR-UA-62`)

**CTR-UA-62 (proposal).** For a verify-only kind, gen 2's verifier accepts **exactly** what gen 1's path accepts for the same
key, message and signature: same scheme, `ua_msg` / `pq_msg`, DST, encodings, length checks and strictness. Accepting more is
a forgery path; accepting less strands a gen-1 UA's funds in gen-2 tokens. Neither is allowed; there is no "subset" mode.

- **Proof.** (a) Shared vectors: every row of the kind's vector files (valid and negative) gives the same verdict on both
  verifiers. (b) A **verifier-level differential test**: valid signatures plus mutants (each byte of `sig`, `pk`, message
  flipped; lengths ± 1; trailing bytes; for ML-DSA malformed hint encodings and `‖z‖∞` at and over the bound; for Falcon
  non-canonical compression and the norm bound) give the same verdict on gen 1's and gen 2's verifier. On forge the precompile is
  absent: a stand-in at the precompile address tests the registry logic only; the verifier-level run against a real precompile
  runs on a local chain whose client has it (never the live testnet). (c) A **registry-level differential test**: for the same
  gen-1 record, `requireAuthorized` (signer and `msig` member), `requirePortable` and `requirePortableApp` under every purpose
  give the same verdict on gen 1 directly and on gen 2. (d) **Mutant**: a gen-2 verifier stand-in that accepts one extra input
  must make (b) and (c) fail.
- **Disagreement fails closed.** Gen 2 cannot run both paths at verify time (gas). So a disagreement found on any pinned row,
  at test or at deploy (§7's probe), refuses that kind as verify-only: the deploy does not list it, gen 1 keeps serving it.
  Where an EIP leaves an encoding check to the implementation and gen 1 enforces it, gen 2's verifier enforces it in Solidity
  before the call (proposal; the build lists which checks per kind).

## 7. Domain separation and replay (`CTR-UA-63`)

**CTR-UA-63 (follows from the code; no change).** Verify-only adds no message form, so no cross-generation replay:

- A derived kind signs `ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)`
  ([CTR-UA-12](../../contracts/accounts.md#CTR-UA-12)): no registry, no generation. A signature gen 1 accepts for
  `(ua, purpose, digest)` is already accepted through gen 2 today (forwarding); with §6 the accepted set is the same, only the
  verifier differs. Replay protection is the operation's `digest` (the token's EIP-712 domain and nonce; a portable record's
  own fields, e.g. `chainUid` and token of a scoped PQZ key record), as today.
- `uaAuthDigest` is registry-bound (`EIP712Domain("SCaaS UARegistry", "1" | "2", chainid, address(this), salt = chainUid)`) and
  is signed only by **native** ids and native `msig` members on the hot path. Native ids are never registered, so never
  verify-only; a gen-1 `msig` is forwarded whole, so its native members keep signing gen 1's domain; a gen-2 `msig`'s native
  members sign gen 2's, as today.
- The portable purposes' native members sign the chain-free typed digest under `PORTABLE_DOMAIN_SEPARATOR`; derived members sign
  `ua_msg`. Neither names a registry.

## 8. Deploy (`CTR-UA-64`)

**CTR-UA-64 (proposal).**

- **When.** A deploy ships a gen 2 with verify-only kinds only when, for a kind gen 1 enables, a new verifier finds a precompile
  at a **Final** address (an EIP in Final status, or a precompile the chain profile documents as the chain's own, as the SCaaS
  testnet's `…5caa0012`–`…0014`; never a Draft's address) by its constructor probe (as `MldsaVerifier`'s: exact `1` on the
  valid KAT input, exact `0` on the flipped one, the call shape of §5 case 1 or 2), §6's differential probe passes by `eth_call`
  on the chain against gen 1's verifier (every pinned row; any difference refuses the kind by name and nothing is broadcast),
  and its measured cap fits `_pqKindFits`. A probe call that fails refuses the deploy by name (as MD-15).
- **How.** A gen-2 mode of `DeployBase` (`_deployUARegistry` with `predecessor` = the book's gen-1 registry), the verifiers by
  CREATE2 from `script/pq_verifiers.py` on the real chain as today; the same probes (`_precompiles`, `PqPrecompileProbe`). A
  kind gen 1 left disabled for its budget (e.g. `mldsa87` at Hedera's 10.5 M on the cache) is not verify-only: it is an
  ordinary gen-2 kind under today's rule, its group being new.
- **Deploy book.** `ua_registry_gen2`, `predecessor`, and per verify-only kind `{kind, verifier, cap, precompile, eip, status,
  vectors_hash}` (the hash of the rows the differential probe ran).
- **Size.** Today `UARegistry` 32,477 B, `UARegistryCoreLib` 34,116 B, `UARegistryAuxLib` 33,685 B (`size-baseline.json`), under
  the 131,072 B runtime ceiling; the change adds a few hundred bytes to `UARegistry` and the core library [estimate]; the
  baseline moves with this reason, old → new in the commit.

## 9. Node, SDK, clients, indexers, families (`CTR-UA-65`, `CTR-UA-66`)

**CTR-UA-65 (proposal).**

- **Node.** The chain config takes the registry generations, `ua_registries = [gen1, gen2]` (replacing the single
  `ua_registry`): the nine registry writes may target either; each must be bound to the chain (`chainUid()`), and gen 2's
  `predecessor()` must be the listed gen 1. This also closes today's gap "writes that must go to generation 1 cannot be
  relayed" ([§1.8 Relaying](../../contracts/accounts.md#CTR-UA-31)). The node verifies nothing itself: a token checks on chain
  through its bound registry; the node's simulation follows.
- **SDK.** The target of a registration or a key write is the generation that holds or will hold the record: gen 1 for a
  verify-only kind (`verifyOnly(kind)` on gen 2 ⇒ `predecessor()`). The gas table's verify row is keyed by signer kind **and
  verify path** (`cache` / `precompile`), measured per chain per registry; the quote takes the row of the registry the token
  binds ([CLI-SDK-09](../../clients/scaas-sdk.md#CLI-SDK-09)); the reference table carries both paths.
- **Clients.** Signing is unchanged (same kind, same message). A client choosing a token release shows its registry and that
  registry's verify path for the holder's kind. `ua-rs` and every `ua-*` registration builder read `verifyOnly` before
  offering a kind on a registry.
- **Indexers** read both generations (unchanged): gen 2 emits nothing for a verify-only kind.

**CTR-UA-66 (proposal; families PLANNED).** One principle on every family: a later registry (or verifier) deployment may
verify, through its own verifier, records an earlier deployment holds for the same kind, reading them and writing nothing;
equivalence as §6; nothing is upgraded. EVM now. Soroban (no generations; a new kind is a new registry with new tokens,
[NET-SOR-17](../../networks/soroban.md#NET-SOR-17)), Solana, Move, TON, Cosmos: in each family round. NEAR and Algorand have
no registry (records per token / in the account app): the principle applies to their token or account-app releases.

**Maximal support and "nothing deployed is upgraded".** [ARCH-POS-18](../../decisions.md#ARCH-POS-18): gen 1 keeps its
software path for every kind; verify-only only adds a faster path, nothing is disabled. Gen 1 is never changed, gen 2 is a new
immutable deployment with no admin and no table, each token release binds its registry at `initialize`
([CTR-UA-05](../../contracts/accounts.md#CTR-UA-05), [CTR-UA-15](../../contracts/accounts.md#CTR-UA-15)).

## 10. Threat model, residual, gas

| Threat | Effect | Bound |
|---|---|---|
| A gen-2 verifier (or the chain's precompile) accepts a forgery for kind K | anyone can authorize as any gen-1 UA of kind K on every token, app or contract that binds gen 2 (operations, and portable / app records read through gen 2, e.g. a PqChat KEM record) | gen-1-bound tokens, gen 1's records, keys and groups are untouched (gen 2 writes nothing for them); §6 tests and probe; UNAUDITED label until an AI audit round covers the verifier |
| Gen 2 refuses what gen 1 accepts | a gen-1 UA of kind K cannot move funds held in gen-2 tokens | §6 (exact equivalence); the deploy refuses a disagreeing kind |
| A later repricing of the precompile above gen 2's cap | checks through gen 2 fail closed (`UAVerifyGas` / refusal) | the 75 % rule leaves room; immutable cap, as every kind today ([CTR-UA-23](../../contracts/accounts.md#CTR-UA-23)) |
| A wrong predecessor | gen 2 reads keys from a forged "gen 1" | the constructor's predecessor checks (§2) |

**Residual.** Receiving is not choosing: a gen-1 UA of kind K credited in a gen-2-bound token holds funds there under gen 2's
verifier without having picked that release. Its holder moves them to a gen-1-bound release by its own choice; wallets show
the token's registry and verify path (§9).

**Gas** (caps from `DeployBase` and [CTR-UA-23](../../contracts/accounts.md#CTR-UA-23); measured unless marked):

| Kind | gen 1 on the cache (cap; measured `verifyCached`) | with a precompile (cap; measured) |
|---|---|---|
| `mldsa44` | 4,250,000; 4.11 M | 200,000; ≈ 175 k `verify` (P6f copy) |
| `mldsa65` | 5,950,000; 5.80 M | 200,000; ≈ 236 k `verify` (P6f copy, `estimateGas`), `requireAuthorized` 301,776 with intrinsic and calldata |
| `mldsa87` | 8,850,000; 8.85 M | 250,000 PROVISIONAL; ≈ 140 k execution (reset 4 T-GAS) |

Verify-only adds gen 1's `kindOf` and `keyOf` reads, ≈ 8–15 k [estimate], and drops today's forwarding hold
(`cap/63 + GAS_MARGIN`). Calldata is the same on both paths (an ML-DSA-65 signature is 53–132 k gas of calldata). A
`{mldsa65 ×3} t=2` treasury `msig`, unregistrable at the cached cap (2 × 5.95 M + holds > 12 M), fits a gen 2 whose `mldsa65` is
verify-only on a precompile.

## 11. Work list

| Component | Work |
|---|---|
| Contracts | `KindConfig.verifyOnly`, bit 224, constructor rule (§2); `UAVerifyOnly`, `verifyOnly(kind)`, `_listedHere` (§3); `_authorized`, `_derived`, `requireAuthorized`'s `UAKeyNotCached`, `requirePortable(App)` and the library's `_portable` / `_single` / `_memberOk` / `_notCached` / `_slotCap` on gen 1's record and keys (§4); the ML-DSA key form by gen 2's verifier (§4); `IUARegistry` doc comments; size baseline |
| Tests | T-REG-4 changed: gen 2 refuses a kind gen 1 enables unless flagged verify-only, refuses the flag otherwise, refuses its registration (`UAVerifyOnly`) and its `cacheExpandedKey`, forwards its list; `UAKeyInUse` across generations unchanged. New: §6 (a)–(d); every path of §4's table; ML-DSA with gen 1 on the cache and gen 2 on a precompile stand-in (gen 2 never uses gen 1's cache), gen 2 on the cache (gen 1's cache read, incomplete ⇒ `UAKeyNotCached`); T-GAS with verify-only `msig` members at the budget; T-AUTH-4 on the new path; storage layout and typehash pins unchanged |
| Deploy | gen-2 mode of `DeployBase`, the differential probe, the book fields (§8); `pq_verifiers.py` for the new verifiers |
| Node | `ua_registries`, the guard rule for both, the chain-binding and predecessor checks (§9); a note for operators (config shape change) |
| SDK | write target by generation; verify rows per path; reference table rows (§9) |
| Clients | `verifyOnly` before offering a kind; the token's registry and verify path in the review (§9) |
| Docs | [accounts.md](../../contracts/accounts.md) §1.8 "Generations" and §1.9, T-REG-4's row, CTR-UA-05's "a registry generation supports a fixed set of kinds" (a verify-only kind is verified, not supported for registration); `decisions.md` entry with §0; node config doc; SDK spec |

## 12. Open questions for the owner (each with a proposal, not a ruling)

| # | Question | Proposal |
|---|---|---|
| Q1 | Does gen 2 evaluate a **gen-1 `msig`** itself so its verify-only members use gen 2's verifier? | No: a gen-1 `msig` is forwarded whole, as today. Evaluating it in gen 2 needs gen 1's structure, accepted bits and native-member domain, and gen 2's `msig` code may differ from gen 1's; an `msig` that wants the faster path registers in gen 2 (its id is the same, §1.8 "Structures"). |
| Q2 | A chain whose gen 2 already exists when a precompile arrives (at most two generations) | Allow a **verify-only generation**: a gen 2 pointing at gen 1 beside the existing gen 2, with only verify-only kinds and `msig` off; it registers nothing, so uniqueness cannot break. It cannot verify the first gen 2's records; tokens choose. |
| Q3 | Declaration | `KindConfig.verifyOnly`, checked `⇔ predecessor.kindEnabled(kind)` (§2). |
| Q4 | Registration refusal | New `UAVerifyOnly(kind)`; `kindEnabled` stays true; new `verifyOnly(kind)` view (§3). |
| Q5 | Which kinds | Every single-key kind gen 1 enables, classical ones included (one rule); never `msig`, never `0x0142` (§2). |
| Q6 | "Final address" | An EIP in Final status, or a precompile the chain profile documents as the chain's own; never a Draft's address (§8). |
| Q7 | Equivalence strictness | Exact equality on every pinned row and mutant; no "gen 2 may be stricter" mode (§6). |
| Q8 | Node config | `ua_registries = [gen1, gen2]` replaces `ua_registry` (§9). |
| Q9 | SDK gas rows | Verify rows keyed by kind and verify path, measured per chain per registry (§9). |

## Sources

[accounts.md](../../contracts/accounts.md) §1.8 (registration, "Generations", Relaying), §1.9 (verifiers, per-chain enablement,
[gen-1 kind gate](../../contracts/accounts.md#gen1-kind-gate)), [CTR-UA-23](../../contracts/accounts.md#CTR-UA-23),
[CTR-UA-33](../../contracts/accounts.md#CTR-UA-33), [CTR-UA-46](../../contracts/accounts.md#CTR-UA-46);
[2026-11-15-mldsa-precompile-cache.md](2026-11-15-mldsa-precompile-cache.md) (MD-2, MD-10, MD-15);
[2026-11-19-bls12381-multi.md](2026-11-19-bls12381-multi.md) §5.3 (stored paths, `verifyMinimal`); [plan P6f](../plans/2026-10-14-p6f-precompiles.md)
(EIP-8355 pin); [ARCH-POS-18](../../decisions.md#ARCH-POS-18). Code at `a19151d64`: `smartcontracts/evm/src/ua/UARegistry.sol`
(constructor, `recordOf`, `_elsewhere`, `_authorized`, `_derived`, `_memberOk`, `_listedHere`, `_groupInPredecessor`,
`requirePortable`, `requirePortableApp`), `UARegistryCoreLib.sol` (`_identify`, `_portable`, `_single`, `_notCached`,
`_memberOk`, `_slotCap`, `uaCount`), `UAStore.sol` (`expanded`, `noPrecompile`, `capped`, `via`), `MlDsa.sol`
(`MldsaVerifier`), `smartcontracts/evm/script/DeployBase.sol` (`_deployUARegistry`, `_pqKindFits`, `_mldsaVerifier`).
