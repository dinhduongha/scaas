# PQZ verifier mode (3f) — design

**PQZ verifier** = a UA that signs a `PqzVerdict` off chain; not `UAPqzVerifier` (the registry's on-chain PoP verifier contract,
unchanged). "Verdict" also keeps its older sense here: the precompile's (or `pqz-ffi`'s) 0 / 1 result on a proof.

**Names renamed by the owner 2026-11-07.** "Attest" is reserved for identity and compliance attestation (KYC,
`ComplianceRegistry`, `attesterId`, the DEX attestation). The review notes ([Codex](../../research/attest-codex-review.md),
[Fable](../../research/attest-fable-review.md)) are history and keep the old names:

| Old | New |
|---|---|
| attested proof verification; group "Attested PQZ" | PQZ verifier mode; group "PQZ verifier mode (3f)" |
| `verifyMode`; values `PRECOMPILE` / `ATTESTED` | `pqzVerifyMode`; values `PRECOMPILE` / `OFFCHAIN` |
| `attesterUA`, `attestVerifier` | `pqzVerifierUA` |
| `attestFixed` | `pqzVerifierFixed` |
| `PqzAttest` (the signed struct), "attestation" | `PqzVerdict`, "verdict" |
| `PqzAttestation` (the struct-pair fallback) | `PqzSignedVerdict` |
| `PqzAttestTypehashIsPinned` | `PqzVerdictTypehashIsPinned` |
| `PURPOSE_PROOF_ATTEST`, `proof-attest` | `PURPOSE_PQZ_VERDICT`, `pqz-verdict` |
| `setAttestVerifier`, `cancelAttestVerifier`, `revokeAttestVerifier` (and their `mtx*` / `UA*` router forms) | `pqzSetVerifier`, `pqzCancelVerifier`, `pqzRevokeVerifier`; router `mtxPqz{Set,Cancel,Revoke}Verifier` over `UAPqz{Set,Cancel,Revoke}Verifier` (pqz first, owner 2026-11-07) |
| `AttestVerifier{Unregistered,Kind,Fixed,Same,Changed,Revoked,NotReady,Pending,Proposed,Set,Cancelled}` | `PqzVerifier{…}` |
| `AttestationRequired`, `AttestationRejected`, `AttestationMismatch` | `PqzVerdictRequired`, `PqzVerdictRejected`, `PqzVerdictMismatch` |
| `AttestConfigInvalid`, `attestConfig()` / `AttestConfig` | `PqzVerifyConfigInvalid`, `pqzVerifyConfig()` / `PqzVerifyConfig` |
| event `ProofAttested`; `lastAttestationAt` | `PqzVerified`; `pqzLastVerdictAt` |
| node `attest` sub-object, `[attest]` config, `ATTESTATION_MISSING`, `ATTESTATION_NOT_EXPECTED` | `pqz_verdict`, `[pqz_verifier]`, `PQZ_VERDICT_MISSING`, `PQZ_VERDICT_NOT_EXPECTED` |
| the verifier service `scaas-attestd`, `POST /v1/attest` | the PQZ verifier (off-chain) `scaas-pqz-verifier`, `POST /v1/pqz-verdict` |
| `vectors/pqz/attest.json` | `vectors/pqz/verdict.json` |

**Status:** **approved by the owner 2026-11-06; build after T57 (3g; owner 2026-11-07: 3g before 3f).** SPECIFIED; nothing is built. Revised after the Codex and Fable
reviews of the first draft ([Codex](../../research/attest-codex-review.md): 2 high, 6 medium, 3 low;
[Fable](../../research/attest-fable-review.md): 0 P0, 4 P1, 8 P2, 4 P3, its answers (a) and (b)) and the owner's rulings R1–R4 of
2026-11-06; every finding's outcome is in §17. Work-order group **3f** of branch `ua-mtx-merge`: tasks **T44–T50** after 3e
(T37–T43) and 3g (T51–T57, owner 2026-11-07), before 3h and 3c (`PqChat` and the registry generation), so the round's docs (T19), gates (T21), review (T22) and PR (T23)
cover it and the EVM freeze and audit include it (O5). **PQZ only** (R1). **Everything here is UNAUDITED.**

**Rules this spec applies, not reopens:** [CTR-PQZ-09](../../contracts/pq-zero-knowledge.md#CTR-PQZ-09) (proof systems and
their ids), [CTR-PQZ-12](../../contracts/pq-zero-knowledge.md#CTR-PQZ-12) (only a PQ signer holds a PQZ key; it authorizes every
spend), [CTR-PQZ-14](../../contracts/pq-zero-knowledge.md#CTR-PQZ-14) (disclosure is a view, nothing recorded),
[CTR-PQZ-15](../../contracts/pq-zero-knowledge.md#CTR-PQZ-15) (PQZ ops are named entries, no new job kind),
[CTR-PQZ-23](../../contracts/pq-zero-knowledge.md#CTR-PQZ-23) and the never-lose-ciphertext rule,
[CTR-UA-07](../../contracts/accounts.md#CTR-UA-07) (portable PoP), [CTR-UA-23](../../contracts/accounts.md#CTR-UA-23) (verify caps,
the 66 % rule), [CTR-UA-39](../../contracts/accounts.md#CTR-UA-39) (`mldsa87` only with a precompile),
[CTR-MTX-30](../../decisions.md#CTR-MTX-30) (one signed entry per operation),
[CTR-MTX-29](../../decisions.md#ctr-mtx-29--every-parameter-is-explicit) (explicit parameters),
[CTR-GOV-10](../../decisions.md#ctr-gov-10--bit-bands-0-127-one-meaning-128-255-per-application-none-refused) (bit bands); the
regulated-kinds spec [2026-11-05-regulated-kinds.md](2026-11-05-regulated-kinds.md) (FREEZE / PAUSE, RK-2's pending, §6.2's size
method); the 3e spec [2026-11-05-pay-meta-tax.md](2026-11-05-pay-meta-tax.md) (Q9: the factory's `noticePeriod()`; O18: the
64,512 B stop line, reduce, never `_above64KiB`).

## 0. Owner rulings, controller calls (2026-11-06)

### 0.1 Owner rulings

Written as given; not reopened. R1–R4 replace O3 and O4 and the first draft's book, Zether and registry designs.

| # | Ruling | Where |
|---|---|---|
| O1 | **Mode chosen per token at creation:** `PRECOMPILE` (today's behaviour) or `OFFCHAIN`. The contract never detects the chain kind, so the same rule applies on every chain. The default stays as today: without the precompile, verification refuses (`UAVerifyGas`) — "option 1: not working". | §3, AV-2 |
| O2 | **OFFCHAIN:** the proof is verified off chain; a verifier UA signs the result, and a valid signature counts as a verified proof. Each token has its own verifier UA, set once at init, either **fixed** (immutable) or **transferable** to another person or group. A transfer goes through governance and waits the notice period, because it changes the trust model. Both kinds are allowed; the choice is made at init. | §4, AV-3, AV-4 |
| O3 | ~~Registry PQZ: an optional verifier-signed registration mode beside the existing "unproven" mode.~~ **Withdrawn by R3 as unnecessary.** | — |
| O4 | ~~Zether: the same off-chain verifier mode on chains without EIP-2537.~~ **Withdrawn by R1.** | — |
| O5 | **Group 3f** goes in `ua-mtx-merge`, before the EVM freeze, after 3e. | §16 |
| R1 | **Zether is removed from 3f entirely.** Zether runs on chain where EIP-2537 exists; an off-chain verifier for it was only a gas saving and too complex. O4 is withdrawn; `ZetherAttestBook`, `ZetherProofAttest` (superseded draft names), the pure-Solidity curve and the first draft's T47, T48 are removed. **3f is PQZ only.** | §1 |
| R2 | **No verdict book.** Every PQZ entry that carries a proof takes the verdict **inline as its last parameters**: the entries routed through `PqzCore._check` (transfer op 1 single, BUNDLE and COMPACT; op 7 multi; burn / unshield, unshield-unwrap included; refresh). The parameters are `PqzVerdict att, UASig attSig` (Fable (a)), outside the subject's typed struct, so no typehash moves. The verdict is empty or ignored in PRECOMPILE mode and required in OFFCHAIN mode. One `requireAuthorized` check in `PqzCore._check`, with the existing `UAVerifyGas` `try`/`catch` shape. The signed struct binds `verifierEpoch` (Codex #1). `verifyTransferAmount` takes an optional verdict; without one, in OFFCHAIN mode, it answers "cannot verify". Codex #3, #7 and Fable P1-4 close. | §5, AV-5 |
| R3 | **An OFFCHAIN token accepts unproven PQZ keys.** The verifier checks off chain the `R_REG` proof of every key in the operation and its single ownership, with a cache keyed by `(ua, pqzKeyHash)`. Requirements: the `pqzPop` bytes are stored in the registry (hash matching); in OFFCHAIN mode `PqzStateLib.init`'s auditor check accepts an unproven auditor key. The first draft's §6.3, T46, CTR-UA-41, the 3c registry coupling and Q6 are dropped. | §6, AV-6 |
| R4 | **An owner `pqzRevokeVerifier()`**: immediate, freeze only. After it every proof-carrying op refuses until a new verifier is in place through the notice-period transfer. A revocation is not a transfer, so it stays inside O2. The trust model states the maximum loss `min(totalShielded, maxShielded) · shieldScale` (Fable P1-2). | §2, §4.3 |

### 0.2 Controller calls (2026-11-06, the owner may override)

| # | Call | Where |
|---|---|---|
| C1 | `statementHash = keccak256(statement)` over the exact bytes the token builds; `proofHash = keccak256(proof)`; the binding claim is checked field by field (§5.2) | §5.2 |
| C2 | Verifier kinds: secp256k1 / EOA, P-256, WebAuthn P-256, ML-DSA-44, ML-DSA-65, one-level `msig` of those; a derived verifier must be registered on the chain first (`PqzVerifierUnregistered`) | §4.1 |
| C3 | **The verifier's shape is frozen at assignment** (Codex #2): a native id's code hash, an `msig`'s structure, accepted slots and its native members' code hashes; a change makes every OFFCHAIN op refuse until a transfer (with notice) re-assigns | §4.1 |
| C4 | **No new governance bit.** Transfer and revocation are owner acts; the transfer waits the factory's `noticePeriod()` (3e Q9), is confirmed by its proposer and dies with an owner change | §4.2 |
| C5 | The release proof-verifier address and the PQZ verifier UA are two named values: `releaseProofVerifier` (`address`, may be 0) and `pqzVerifierUA` (`bytes32`) (Codex #5) | §3, §6.1 |
| C6 | The verifier-0 gate lives in `PqzLayer`'s constructor and `_init`, `PqzStateLib.init` and `script/pqz/e2e.py`, not in `OpenFactory` / `DeployBase` (Fable P1-1, Codex #9) | §3 |
| C7 | The node stays keyless: it carries or fetches verdicts; signing is a **separate PQZ verifier (off-chain)**, its own process and custody (Codex #8) | §11.1 |
| C8 | A node health signal and an opt-in shield refusal while a token's verifier is unreachable or revoked (Fable P2-7) | §11.1 |
| C9 | Rule ids next-free: CTR-PQZ-27…30, NODE-JOB-22 (Fable P3-13) | §13 |

## 1. Scope and non-goals — SPECIFIED

**In scope (EVM; the PQZ kinds 4, 5, 12, 13):**

| Item | Rule |
|---|---|
| `pqzVerifyMode` per PQZ token, chosen at creation, immutable | §3 |
| The verifier UA: kinds, frozen shape, fixed or transferable, transfer with notice, immediate revocation | §4 |
| The inline verdict on the proof-carrying entries (twelve on 5, 13; ten on 4, 12, which have no unwrap) and on `verifyTransferAmount` | §5 |
| Unproven keys in OFFCHAIN mode; the verifier's off-chain key checks | §6 |
| Vectors, `clientkeys`, `ua-rs` and wrappers, node rows and health signal, the separate PQZ verifier (off-chain) | §11 |

**Non-goals.** **Zether** (R1): every Zether rule, contract and gate stays as it is, EIP-2537 required
([CTR-ZTH-52](../../contracts/zether.md#CTR-ZTH-52)). **Hedera:** `PqzLayer` keeps refusing a Hedera env (§10 row 9). No change to
any statement, transcript, relation, `proofSystemId`, set parameter or prover. No change to the registry (R3). No new contract, no
book, no stored verdict (R2). No on-chain slashing. No chain detection. No non-EVM contract change (§12). No migration: every
chain is test-only.

## 2. Trust model — SPECIFIED

<a id="trust"></a>**AV-1.** Stated plainly, for the creation disclosure, wallets and docs:

- **Soundness is replaced by trust in the verifier UA.** In OFFCHAIN mode a proof is accepted because the verifier signed that it
  verifies. A verifier that signs a false proof can create value that does not exist and spend it: unshield up to
  `totalShielded`, and on the wrapped kinds 5 and 13 take the underlying in escrow. **Maximum loss: `min(totalShielded,
  maxShielded) · shieldScale` public units** (the whole shielded pool, and on 5 / 13 that much underlying) (R4, Fable P1-2).
- **Authorization is unchanged.** Every debit still needs the subject's signature over `PqzAuth`, checked on chain
  ([CTR-PQZ-12](../../contracts/pq-zero-knowledge.md#CTR-PQZ-12)). A dishonest verifier cannot spend a victim's balance: it can
  fabricate a balance under a signing UA it controls and drain the pool through it.
- **Confidentiality** of honestly formed data is unchanged under the existing assumptions: the verifier sees only public bytes (the
  statement and the proof), no secret leaves the client. It does not guarantee that outputs of a dishonest verdict are valid
  encryptions, correct auditor copies or recoverable balances. With an auditor on, the verifier learns which ops are audited
  (public on chain anyway; Fable P2-10).
- **Censorship and delay.** The verifier sees each debit **before inclusion** and can refuse or delay any party's transfers and
  unshields selectively. A relayer can do the same, but is replaced at once; a verifier is replaced only after the notice period
  (a revocation stops everyone, §4.3) (Fable P2-6).
- **Liveness depends on the verifier.** A verifier that stops signing freezes every confidential balance (debits, unshield,
  refresh). Shields keep working and can lock more value into a pool nobody serves (§11.1's health signal and opt-in refusal).
  A **fixed** verifier that is lost freezes the balances for ever.
- **Containment, by configuration** (Codex #11):

  | Configuration | On-chain answer to a dishonest verifier |
  |---|---|
  | transferable, live owner | `pqzRevokeVerifier()` at once (freeze), then a new verifier after the notice period |
  | fixed, or owner renounced (`owner() = 0`) | **none** on the plain kinds 4, 5 (no `PAUSE`); on 12, 13 the issuer's `PAUSE` / `FREEZE` **only if** those features were set at creation and their roles are live |
  | regulated 12, 13 with live controls | `PAUSE` / `FREEZE` at once, in addition to the above |

- **Ciphertexts stay in contract state:** every SSTORE2 op blob, entry and memo is written exactly as in PRECOMPILE mode (I4).
- **Auditable, not slashable.** The proof and the verdict are in the op's calldata; `PqzVerified` names the verifier and
  both hashes. Anyone can re-verify an accepted proof by replaying the transaction **at its exact position** with its execution
  context and envelope binding, rebuilding the statement, comparing `statementHash`, then running `pqz-ffi` on it and the calldata
  proof (Codex #10: a parent-block view is not enough, since an earlier transaction of the same block can change the account or
  the verifier).
- **Keys.** An OFFCHAIN token accepts keys the chain never proved (R3); whether a payee's key is usable is a question for the
  verifier, not a chain-readable fact; a refused key fails the debit before any credit.

## 3. The mode (O1) — SPECIFIED

**AV-2.** `IFactoryToken.ConfidentialConfig` gains three named fields:

| Field | Type | Rule |
|---|---|---|
| `pqzVerifyMode` | `uint8` | `0` `PRECOMPILE` (the default, today's behaviour), `1` `OFFCHAIN`; any other value `VerifyModeInvalid(uint8)` |
| `pqzVerifierUA` | `bytes32` | `PRECOMPILE`: 0. `OFFCHAIN`: the `pqzVerifierUA`, a verifier of §4.1 |
| `pqzVerifierFixed` | `bool` | `PRECOMPILE`: false. `OFFCHAIN`: true = fixed for ever, false = transferable |

A field set against the mode reverts `PqzVerifyConfigInvalid()`. `TokenConfig` carries every sub-struct for every kind and each token
decodes it in `_init`, so the encoding moves for every kind (the regulated spec §2.4 ripple: wizard, `clientkeys`, vectors, node).

- **Stored.** `pqzVerifyMode` takes byte 22 of `PqzStorage` slot 0 beside `pqz` and the two mode enums, so a PRECOMPILE debit reads
  no new slot. The verifier state is appended at the end of `PqzStorage` (§4.4) and read only on the OFFCHAIN branch. Layout pins
  move old → new.
- **Immutable.** No entry writes `pqzVerifyMode` after init; there is no mode switch (I1).
- **No chain detection.** A PRECOMPILE token without the precompile refuses as today; an OFFCHAIN token never calls `0x…5caa0f01`,
  on any chain, the SCaaS testnet included. OFFCHAIN ignores whether a precompile exists.
- **The release without a precompile (C6).** Today `PqzLayer`'s constructor refuses `env.deps.length != 1 || env.hedera ||
  !isContract(env.deps[ENV_PQZ_VERIFIER])` and `PqzStateLib.init` reads `PRECOMPILE()` / `PROOF_SYSTEM_ID()` from it and runs
  `PqzSafety.requirePqz`. Changes: the constructor admits `releaseProofVerifier = env.deps[ENV_PQZ_VERIFIER] = 0` (still exactly one
  dep, still never Hedera; a non-zero dep must be a contract); `PqzLayer._init` / `PqzStateLib.init` in PRECOMPILE mode refuse a
  zero `releaseProofVerifier` with `SelfTestFailed(address(0))` **before any call**, then run today's reads and self-test
  unchanged; in OFFCHAIN mode they read nothing from it. The PQZ releases are deployed by `script/pqz/e2e.py` (not `DeployBase`,
  whose comment names it), which gains the zero-dep form for a chain where `UAPqzVerifier` cannot be deployed. `OpenFactory` is
  unchanged: it has no canonical-verifier list ([CTR-ZTH-20](../../contracts/zether.md#CTR-ZTH-20)'s 5g-Z2 note). The mode is never
  inferred from a missing dependency.
- **`proofSystemId` in OFFCHAIN mode:** `PqzSet.PQZL_ID` of the release's build (Q2 answered: PQZL only). The set is implicit in the
  release; the PQZ verifier (off-chain) is configured per release address → set and refuses a statement whose length is not that set's
  `STMT_*` (Fable P2-11).

## 4. The verifier UA (O2, R4) — SPECIFIED

### 4.1 Kinds and the frozen shape (C2, C3)

**AV-3.** A verifier is accepted at init and at a transfer's proposal only if it is one of:

| Kind | Id | Verify path without SCaaS precompiles |
|---|---|---|
| native EOA | `0x0001` (a padded address) | `ecrecover`; no code other than the EIP-7702 designator (the registry's `byCode` would take ERC-1271) |
| `secp256k1` | `0x0108` | `ecrecover` |
| `p256` | `0x0101` | EIP-7951 where its probe passes, else OpenZeppelin's Solidity verifier (`P256Precompile`) |
| `webauthn-p256` | `0x0100` | as `p256`, plus SHA-256 |
| `mldsa44`, `mldsa65` | `0x0130`, `0x0131` | the SCaaS ML-DSA precompile where probed, else pure Solidity on the cached expanded key (`expandKey` first: uncached `mldsa65`, 18.9 M, is over the registry's 5.95 M cap and over 2^24) |
| `msig` | `0x0120` | k-of-n of the kinds above, one level (the registry's own rule), within the registry's aggregate budget |

- A derived verifier (every row but the native EOA) must be **registered on this chain** before the token is created or the
  transfer proposed: `kindOf = 0` reverts `PqzVerifierUnregistered(bytes32)` (Fable P2-12), any other kind outside the table
  `PqzVerifierKind(uint16)`: `mldsa87` ([CTR-UA-39](../../contracts/accounts.md#CTR-UA-39)), the EIP-2537 kinds, the bn254 kinds
  (no Solidity path), `zether-bls12381`, `pqz-mlwe`, a native id with code (ERC-1271), a nested `msig`.
- The reason is O1's: the mode exists for chains without the precompiles, so its check must not need one; and the verifier UA should
  be registrable on every chain the issuer uses. A listed kind is not a liveness guarantee for any quorum: the registry's aggregate
  budget and signability checks and the chain's gas limit still apply (Codex §10 row 11).
- **Frozen shape (C3, Codex #2).** At assignment (init, transfer confirm) the token stores `verifierShape = keccak256` of: for a
  native id, its `extcodehash`; for a derived single key, its kind; for an `msig`, its `msigOf` structure, its accepted-slot mask
  and the `extcodehash` of each native member. Every OFFCHAIN check recomputes it (§5.3) and refuses with
  `PqzVerifierChanged()` on a mismatch, so a native slot that gains code, or a slot accepted later, never changes the policy
  without a transfer through the notice period. **Recommended: a transferable k-of-n `msig`** of derived keys (no native slots):
  for example 2-of-3 `secp256k1` / `p256` held by separate parties, or `mldsa65` members for the post-quantum horizon.

### 4.2 Fixed or transferable; the transfer (C4)

**AV-4.**

- **Fixed** (`pqzVerifierFixed = true`): `pqzSetVerifier` reverts `PqzVerifierFixed()`.
- **Transferable:** the token's governance **owner** (`_govSubject() == owner()`, identity by UA) calls `pqzSetVerifier(bytes32
  next)` twice. The first call proposes (`eta = now + noticePeriod`; the §4.1 checks; `next ≠ current`, else
  `PqzVerifierSame()`). The second call, by the **same proposer**, still the owner, in the **same owner generation**, with the same
  `next`, in `[eta, eta + noticePeriod]`, confirms: the verifier, its shape and `verifierEpoch + 1` (checked arithmetic) are
  written. Before `eta`: `PqzVerifierNotReady(eta)`; another value while one is live: `PqzVerifierPending(pending)`; another
  caller: `NotProposer`; an owner change kills the pending (as `GovernanceLib`'s `ownerGeneration`, Codex). `pqzCancelVerifier()`
  (owner) deletes a live pending. With `noticePeriod = 0` the first call applies at once (shown, may be 0 on a test chain).
- **The period** is the factory's `noticePeriod()` (an immutable of `OpenFactory`, 3e Q9), stored at init, so nothing later can
  shorten it; never the creator's `grantDelay`.
- **Off-chain guard against a typo (Fable P3-15):** the wizard and the node submit a proposal only with a signed probe verdict
  from `next` (a `PqzVerdict` over a fixed probe statement). Nothing on chain.
- **Relayed** through the `GovernanceRouter` as `mtxPqzSetVerifier(UAEnvelope e, address target, bytes32 next, UASig auth)`,
  `mtxPqzCancelVerifier(…)`, `mtxPqzRevokeVerifier(…)` over `UAPqzSetVerifier(bytes32 next)`, `UAPqzCancelVerifier()`,
  `UAPqzRevokeVerifier()`; fee mode `NONE`, relayable at fee 0.
- **Why no bit.** A bit would make the trust root a delegable role apart from the owner; moving it is an ownership-level act like
  `transferOwnership`. The governance pending runs on `grantDelay`, not the notice the owner asked for. So no bit of the SCaaS band
  is taken (Q4 answered).

### 4.3 Revocation (R4)

`pqzRevokeVerifier()` (owner, a transferable verifier, live owner): **at once** writes `verifier = 0`, `verifierEpoch + 1`, and
deletes any pending transfer. Every proof-carrying op then refuses `PqzVerifierRevoked()`, and the OFFCHAIN
`verifyTransferAmount` answers false. A new verifier comes only through §4.2 (proposal, notice, confirm); the token stays frozen
meanwhile. Revocation can only stop, never move, the trust root, so it needs no notice (inside O2). On a **fixed** verifier,
`pqzRevokeVerifier` reverts `PqzVerifierFixed()` (owner 2026-11-06, Q1: no; keeps "fixed" meaning no
owner power over the verifier). Events: `PqzVerifierProposed(bytes32 current, bytes32 next, uint64 eta)`,
`PqzVerifierSet(bytes32 previous, bytes32 next, uint32 epoch)`, `PqzVerifierCancelled(bytes32 next)`,
`PqzVerifierRevoked(bytes32 previous, uint32 epoch)`.

### 4.4 Storage and views

Appended to `PqzStorage` (namespace `scaas.pqz`): `bytes32 pqzVerifierUA`; `bytes32 verifierShape`; `{uint32 verifierEpoch;
bool pqzVerifierFixed; uint64 noticePeriod; uint64 eta}` in one slot; `bytes32 pendingVerifier`; `bytes32 proposer`; `uint32
proposerGeneration`. One struct view `pqzVerifyConfig() returns (PqzVerifyConfig {uint8 pqzVerifyMode; bytes32 verifier; bool fixed_;
uint32 verifierEpoch; bytes32 pending; uint64 eta; uint64 noticePeriod;})` for wallets and the node. The bodies of the three
governance entries are in `PqzStateLib` (already linked); the token keeps thin stubs (§9).

## 5. The inline verdict (R2) — SPECIFIED

### 5.1 The struct

**AV-5.** Typed EIP-712 in the **token's own domain** (`"SCaaS PqzToken"`, as `PqzAuth`), signed by the verifier through
`IUARegistry.requireAuthorized(verifier, PURPOSE_PQZ_VERDICT, digest, attSig)` with the new purpose `PURPOSE_PQZ_VERDICT =
keccak256("scaas.ua.purpose.pqz-verdict.v1")` (the registry takes any purpose; no registry change):

```
PqzVerdict(address token,uint256 chainId,bytes32 proofSystemId,bytes32 statementHash,bytes32 proofHash,uint32 verifierEpoch,uint64 validUntil)
```

`validUntil` is unix seconds (the verifier's own shorter life; the op is bounded by its `validUntilBlock` anyway). Typehash pin
`PqzVerdictTypehashIsPinned`; vectors in `smartcontracts/vectors/pqz/verdict.json` (§11.3). **Empty verdict:** every field 0 and
an empty `UASig`.

### 5.2 What is bound (C1)

`statementHash = keccak256(statement)` over the bytes after the precompile's 5-byte prefix, hashed in place in `_check`'s buffer
(`buf + 37`, `len`) — exactly what the token's statement views return (`transferStatement`, `transferSingleStatement`,
`burnStatement`, `unshieldUnwrapStatement`, `disclosureStatement`). `proofHash = keccak256(proof)` of the exact calldata bytes.
Both are recomputed by the token; nothing is taken from the submitter.

The claim "the statement already binds the `acc` hash and the parameters, so a verdict cannot be replayed onto another
transaction", checked against [§7.7](../../contracts/pq-zero-knowledge.md#statement) and `PqzCore`:

| Fact | Where in the statement |
|---|---|
| Op and proof system | `opTag` word 0 (transfer, op 7, burn, refresh, the disclosure kinds), `proofSystemId` word 32 |
| Chain and token | `chainId`, `chainUid`, `token`, `registry` |
| Parties, amounts | `from`, `to`, `beneficiary`, `fee`, `amount`, `recipient`, `auditorOn`, `shieldIn` |
| Single use | `sendCounter` (incremented by every debit, refresh included), `validUntilBlock` |
| Account state | **not an `acc` hash:** the body's `T = acc ± window + Trivial(shieldIn)`, which a rollover leaves unchanged by design (D4 / D6) |
| Keys | `pk_f`, `pk_t`, `pk_a`: a replaced key (R-cross-set) changes `statementHash`, so a verdict for the old key never fits |
| Relay path | `envelopeBinding` (direct, v1 / v3 envelope, mode) |
| Outputs | `out` (the new ciphertexts), `salt`, `memoHash` |

**Verdict.** The claim holds in substance with one correction: PQZ binds `T`, not an `acc` hash; single use comes from
`sendCounter`. A debit statement with a verdict fits exactly one transaction, once. A disclosure statement has no counter, but a
disclosure changes no state. **What the verdict adds:** `proofHash` (so an auditor can tell a lying verifier from a swapped
proof), `verifierEpoch` (an old signature dies at every verifier change and cannot be revived by A → B → A, Codex #1),
`validUntil`, and the domain and purpose (no signature the verifier made for anything else reads as a verdict). The struct's
`token` and `chainId` repeat the domain and are checked equal. `proofSystemId` is for the verifier's dispatch and the audit; the
token checks it equal to its `psid`, and the PQZ verifier (off-chain) validates the statement's own word 32 against its set, never
dispatching on the outer field alone.

### 5.3 The check in `PqzCore._check`

```
_check(o, buf, proof, authSig, att, attSig):
  the subject's authorization (unchanged)
  if pqzVerifyMode == PRECOMPILE: verdict($().pqz, buf) as today; att and attSig are ignored
  else:
    v = pqzVerifierUA;            v == 0                      → PqzVerifierRevoked()
    shape(v) != verifierShape                                   → PqzVerifierChanged()
    att.token != this, att.chainId != chainid, att.proofSystemId != psid,
    att.verifierEpoch != verifierEpoch, att.validUntil < now,
    att.statementHash != keccak256(statement), att.proofHash != keccak256(proof) → PqzVerdictMismatch(uint8 field)
    try registry.requireAuthorized(v, PURPOSE_PQZ_VERDICT, digest(att), attSig) {}
    catch: UAVerifyGas (its own, or the frame out of gas: no data, < g/63 left)  → UAVerifyGas()
           else                                                  → PqzVerdictRejected()
    emit PqzVerified(statementHash, proofHash, v, verifierEpoch)
```

- **The twelve entries** (ten on 4 and 12, which have no `mtxUnshieldUnwrap`) take `PqzVerdict calldata att, IUARegistry.UASig calldata attSig` as their **last** parameters: the direct
  `mtxConfidentialTransfer`, `…Compact`, `…Single`, `…SingleCompact`, `mtxUnshield` (burn and refresh), `mtxUnshieldUnwrap` (5, 13),
  and the six signed `UAEnvelope` forms. The signed forms hash `args`, `proof` and `accHint` into their `UA*` structs as today and
  pass `att, attSig` on to the self-call outside them: **no typehash moves**, `PqzAuth` is untouched. The verdict is an unbound
  field like `relayer` / `feeRecipient`: a relayer may swap it for another valid one over the same hashes, harmlessly.
- **Stack:** with `via_ir` off a signed form has eight parameters; if the legacy decoder runs out of stack, T45 passes the pair as
  one named struct `PqzSignedVerdict { PqzVerdict att; UASig sig; }` (the 3e `RelayPay` fallback precedent), still explicit.
- **One transaction, nothing stored:** no book, no record, no epoch machinery beyond one counter, no ordering, no orphan, no second
  payer. A failed op reverts the event with it.
- The library entry points (`PqzTransferLib.transfer` / `transferMulti`, `PqzBurnLib`) gain the two parameters; `mtxSelectors()`,
  `selector_audit.json` and the node rows move.

### 5.4 Disclosure (`verifyTransferAmount`)

- The five-argument `verifyTransferAmount(entryRef, leg, amount, kind, proof)` keeps its ABI (`ITransferDisclosure`). PRECOMPILE:
  unchanged. **OFFCHAIN: "cannot verify"**, the named revert `PqzVerdictRequired()` — a `bool` view has no third value, and `false`
  would read "the amount is wrong" (C2-6's rule: a failed check is never a verdict).
- A seven-argument PQZ form `verifyTransferAmount(entryRef, leg, amount, kind, proof, PqzVerdict att, UASig attSig)`: PRECOMPILE
  ignores the verdict (the precompile's verdict); OFFCHAIN checks the verdict as §5.3 against `disclosureStatement(…)` and the
  proof, returns `true` when every check passes, `false` on a mismatch, a refused signature, a revoked or changed verifier; a starved
  call `UAVerifyGas`. Nothing is recorded ([CTR-PQZ-14](../../contracts/pq-zero-knowledge.md#CTR-PQZ-14)).
- **The stronger path stays off chain:** anyone runs `pqz-ffi`'s verifier on `disclosureStatement(…)` and the proof and gets the
  verdict without trusting the verifier (`docs/integration.md` gets the recipe).

## 6. Keys in OFFCHAIN mode (R3) — SPECIFIED

**AV-6.**

- `PqzCore._keyPtr` and `_creditKey` (sender, recipients, auditor, shields, op 7 legs): PRECOMPILE as today (`pqzKeyOf`,
  `proven`, the set length). OFFCHAIN: **`proven` is not required**; the pointer must still exist with the set's exact length
  (`ptr.code.length == PqzCt.PK + 1`), else `AccountNotRegistered(ua)`. Generations as `pqzKeyOf`.
- `PqzStateLib.init`'s auditor check accepts an unproven auditor key in OFFCHAIN mode, same length rule.
- **The verifier's obligations** (off chain, the service of §11.2), for every key the statement names (`pk_f`, `pk_t`, `pk_a`, the
  op 7 groups): the registry holds the `pqzPop` **bytes** and they hash to `pqzPopHash` (a hash-only record cannot be re-verified:
  refused); the `R_REG` proof verifies over the right message (`uaMessage(0x0142, PURPOSE_POP_V2, portableRecordDigest(…))` for a
  `register` key with its initial KEM commitment, `uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest(…))` for a `setPqzKey` key; one
  path is never evidence for the other); **single ownership:** the same `pqzKeyHash` under another UA is refused; results cached by
  `(ua, pqzKeyHash)`, never by `ua` alone. An op naming a key that fails any of these gets no verdict.
- **What is given up** (Fable (b)): `keyOwner` uniqueness for these keys becomes the verifier's check; the `0x0142` list and
  `proven` are not chain-readable for OFFCHAIN holders (wallets ask the verifier before a send; liveness only). CTR-PQZ-12's holder
  rule is enforced by the registry at store time for unproven keys too, unchanged. S32 holds: listing someone else's key gains
  nothing.
- A shield into a UA whose key the verifier refuses lands (shields carry no proof) and stays undebitable until the key passes; the
  wallet's pre-send check and the disclosure say so.

## 7. Gas — SPECIFIED (estimates, measured in T45)

**On a debit** (the verdict is in the same transaction): −`G_op` (P6f measured rows at `n2048-kmax1024`, PQZL: op 1
5,223,000–5,409,000, op 2 3,723,000) + the statement hash (`STMT_TRANSFER` 93,312 B at `n2304-kmax4096` ≈ 17.6 k; Fable P3-14) +
the proof hash ≈ 9 k + the verdict's calldata (≈ 0.4 KB with a single classical signature) + the verifier's reads and shape
(≈ 5 k; an `msig` adds `msigOf` and one `extcodehash` per native member, ≈ 10–40 k) + the signature:

| Verifier kind | Signature verify in `requireAuthorized` | Net on PQZ op 1 at `n2304-kmax4096` (9.17 M measured today) |
|---|---|---|
| native EOA, `secp256k1` | ≈ 8–11 k | ≈ 3.8–3.9 M |
| `p256` | EIP-7951 ≈ 15–20 k; OZ Solidity ≈ 0.25–0.4 M | ≈ 3.8–4.3 M |
| `webauthn-p256` | `p256` + 30–60 k | ≈ 3.9–4.4 M |
| `mldsa44` / `mldsa65` | SCaaS precompile 175 k / 236 k (P6f, measured); pure Solidity cached 4.11 / 5.80 M (measured `verifyCached`) + 2,420 / 3,309 B calldata | ≈ 4.0–4.1 M / ≈ 8.0–9.9 M |
| `msig` k-of-n | Σ k member verifies + ≈ 4–6 k each | 2-of-3 `secp256k1` ≈ 3.85–3.95 M |

Every row fits 2^24 at every set; the `UAPqzHolder` 2^24 bound on the holder stays as measured with the precompile (conservative).
A pure-Solidity `mldsa65` verifier costs more than the precompile it replaces; the disclosure and the node's quote say so.
**PRECOMPILE debits** pay the verdict's empty calldata (two empty dynamic params, ≈ 0.1–0.2 KB at the EIP-7976 floor) and a few
gas of branching: their pins move old → new (§10 row 8).

## 8. Family impact — SPECIFIED (one rule, each family in its own round)

The rule is family-neutral: a PQZ token chooses `PRECOMPILE` or `OFFCHAIN` at creation, immutable; OFFCHAIN names a verifier UA of
§4.1's kinds, frozen shape, fixed or transferable with notice, revocable at once; each proof-carrying entry takes a verdict
over `{token, chainId, proofSystemId, statementHash, proofHash, verifierEpoch, validUntil}` as its last parameters; the proof stays
in the transaction; ciphertexts stay in state; OFFCHAIN accepts unproven keys that its verifier checks off chain.

| Family | PQZ today | In its round |
|---|---|---|
| EVM | this group | — |
| Hedera (EVM code) | refused (`env.hedera`) | a later Hedera item, on the owner's word (§10 row 9) |
| Soroban, Solana, NEAR, Algorand, Aptos, Sui, TON, Cosmos | no PQZ token built | the PQZ family round takes the mode, the per-token verifier and the inline verdict with that family's own signature check; NEAR ≠ Algorand, separate rounds |

Zether: no family change (R1).

## 9. Size plan — SPECIFIED

**Baseline.** Kind 13 measured 62,285 B after T29/T30 (2,227 B under the 64,512 B stop line), before T31–T36 and 3e's +2.3–4.0 K
(3e §6.4, reduced under the line by its own levers). 3f starts from what T57 leaves (3g in).

| Contract | Δ runtime [est.] | What |
|---|---|---|
| kind 13 (and 12, 5, 4) | **+0.4 to +0.8 KB** | the two calldata parameters on twelve entries (decode and forward ≈ 30–60 B each) |
| kind 13 (and 12, 5, 4) | +0.2 to +0.3 KB | the seven-argument `verifyTransferAmount` stub |
| kind 13 (and 12, 5, 4) | +0.3 to +0.5 KB | the three governance stubs and `pqzVerifyConfig()` |
| kind 13 (and 12, 5, 4) | +0.1 to +0.2 KB | the `_init` / constructor branch (verifier 0) (Fable P1-1) |
| **every token kind 0–13** | +0.1 to +0.2 KB | the decode of the three new `ConfidentialConfig` fields and their checks in `_init` (Fable P1-3) |
| **kind 13 in all** | **+1.1 to +2.0 KB** | |
| `PqzTransferLib`, `PqzBurnLib` | +0.4 to +0.7 KB each | the OFFCHAIN branch of `_check`, the key branch, the event |
| `PqzStateLib`, `PqzWrappedLib` | +0.6 to +1.0 KB | OFFCHAIN init, the auditor rule, the verifier transfer and revocation bodies |
| `PqzViewLib` | +0.3 to +0.5 KB | `PqzVerdictRequired`, the OFFCHAIN disclosure check |
| `GovernanceRouter` | +0.5 to +0.8 KB | three router ops; its CREATE2 address moves |

**How it is measured.** `forge build src --sizes --json` and `scripts/size_gate.py`; deploy gas by the regulated spec's §6.2 method;
`size-baseline.json` rows old → new with the reason in `_comment`. **T45 measures kind 13 first** (the parameters on one entry, then
the rest, then the stubs), then 12, 5, 4, then every other kind (the config decode).

**Stop rule (3e O18).** The stop line is **64,512 B** of runtime. A kind at or above it is **reduced**: the task applies the levers
below in order, one at a time, re-measures after each (size, then the whole `forge test`), and stops as soon as it is under; it goes
back to the controller only when every lever is applied and the kind is still at or above the line. `_above64KiB` is never a
fallback. A deploy-gas figure more than 50 % over the estimate is reported without stopping.

**Levers, in order** (each passes the split checklist: DELEGATECALL storage is the token's own, `address(this)` the token,
`msg.sender` the direct caller, `_govSubject()` and every immutable read in the token and passed, return data fixed and checked, the
one `nonReentrant` around the entry, `LinkClosure` pins and codehashes old → new):

| # | Lever | Saving [est.] | Constraints |
|---|---|---|---|
| 1 | The three governance stubs forward their calldata words and `_govSubject()` to `PqzStateLib` with no local decoding or event | 0.1–0.2 KB | gas +100–300 on cold paths |
| 2 | `pqzVerifyConfig()` merged into an existing PQZ struct view | 0.1–0.2 KB | an `eth_call` shape change for wallets and the node |
| 3 | The seven-argument `verifyTransferAmount` body in `PqzViewLib` behind a forward with no local decode | 0.1–0.2 KB | view gas +~1 k |
| 4 | The verdict pair as one named struct `PqzSignedVerdict` on every entry (one decoder instead of two per entry) | 0.1–0.3 KB | an ABI shape choice for clients; still explicit |
| 5 | 3e's levers not yet used (its §6.4 rows), then 3g's (its §6.3), in their order | per 3e, 3g | as 3e, 3g |

**Not levers without the owner's word:** a views-behind-`fallback` module, `optimizer_runs`, `via_ir`, dropping an entry or a ruling,
or putting the verdict inside the `proof` bytes (CTR-MTX-29).

## 10. Conflicts with existing rules (for Change lines in T19; none resolved here)

| # | Source | Rule and what it says today | Change needed |
|---|---|---|---|
| 1 | O1, O2 | [CTR-PQZ-01](../../contracts/pq-zero-knowledge.md#CTR-PQZ-01): "every constructor/`initialize` runs the precompile self-test … a chain without the precompile … fails it"; "**Public chains** … the route there is a lattice-verification precompile on that chain, which SCaaS waits for — no Solidity verifier split over transactions, no STARK-wrapped proof and no SCaaS appchain is planned"; "The self-test is what keeps PQZ off chains whose client is not ours" | the self-test is the PRECOMPILE mode's gate; an OFFCHAIN token runs without it on any chain; the public-chain route gains "or OFFCHAIN, with AV-1". The release gates (G-LIC, audit) are unchanged: OFFCHAIN does not discharge them |
| 2 | O1 | [CTR-PQZ-10](../../contracts/pq-zero-knowledge.md#CTR-PQZ-10) and its §9 table: the off-chain co-processor "(quorum of verifiers signs ML-DSA attestations; contract checks t-of-n) … The later path for customer-run private chains (owner); **rejected on the SCaaS testnet**" | this group is that path, open on every chain, the SCaaS testnet included; the quorum is one verifier UA (usually an `msig`) of §4.1's kinds, classical or post-quantum, disclosed as such |
| 3 | O2 | W-B, the rule PQZ's release `verifier` follows (as [CTR-ZTH-20](../../contracts/zether.md#CTR-ZTH-20)): "the creator never names a verifier", because a fake one drains the escrow | code stays canonical; the creator now names a verifier **UA** that can approve a false proof — the same drain, by a named party, disclosed with AV-1's maximum loss |
| 4 | R3 | [CTR-UA-16](../../contracts/accounts.md#CTR-UA-16): "**PQZ tokens accept only proven keys**"; `accounts.md` §1.13: a key on a chain without the verifier is "a directory entry that PQZ tokens do not accept" | PRECOMPILE tokens unchanged; OFFCHAIN tokens accept unproven keys of the set length, checked off chain by their verifier (§6) |
| 5 | R2 | [CTR-PQZ-14](../../contracts/pq-zero-knowledge.md#CTR-PQZ-14): `verifyTransferAmount` "takes the proof alone as the opening"; a failed precompile call reverts `UAVerifyGas`, "only the statement's shape errors read `false`" | the five-argument form answers `PqzVerdictRequired()` in OFFCHAIN mode; a seven-argument form takes the verdict. Nothing is recorded, so "no on-chain verdict" (CTR-PQZ-14, CTR-ZTH-39) still holds |
| 6 | R2 | [CTR-PQZ-15](../../contracts/pq-zero-knowledge.md#CTR-PQZ-15) "no new kind" (`job-api.md`) | **applied, not changed**: the verdict is a named sub-object of the existing named entries; no `pqz_verdict_*` job kind (Fable P2-9 (i) closes with R2) |
| 7 | AV-1 | `pq-zero-knowledge.md` §12 threats: soundness rests on the on-chain verifier | a threat row "dishonest, censoring or compromised verifier UA" (drain up to the maximum loss, selective delay, freeze), with AV-1's containment table |
| 8 | R2 | [CTR-PQZ-11](../../contracts/pq-zero-knowledge.md#CTR-PQZ-11)'s measured gas tables, `PqzSet.PQZ_DEBIT_MIN_GAS` and the gas pins of every PQZ entry | the twelve entries' calldata grows in both modes: the pins move old → new in T45's commit, with their comments naming the mode they measure; OFFCHAIN rows added; the `UAPqzHolder` bound keeps the precompile-inclusive figure (Fable P2-9 (ii)) |
| 9 | O1 | `docs/networks/hedera.md`: "PQZ never runs on Hedera either (`PqzLayer` refuses a Hedera env)"; O1: "the same rule applies on every chain" | a **retained scope exception**: the refusal is the release flag `env.hedera`, independent of the mode, and stays; it is a real exception to O1's literal wording, to be reconciled by a later Hedera item (Codex row 14) |
| 10 | C7 | AGENTS: "the node never holds subject … keys"; "a lane key holds gas only and never a contract role" | **applied**: the node holds no verifier key; signing is a separately operated service (§11.2) (Codex #8) |
| 11 | AV-4 | 3e Q9: the factory's `noticePeriod()` "may be 0 on a test chain" | applied as is: on a factory with period 0 a transfer is immediate; wallets show the actual period |
| 12 | AV-3 | [CTR-UA-23](../../contracts/accounts.md#CTR-UA-23): ML-DSA without a precompile verifies on the cached expanded key within its cap | applied: an `mldsa*` verifier needs `expandKey` first |
| 13 | §3 | `docs/networks/evm.md`: "Post-quantum Zether: the only PQZ chain" (the SCaaS testnet) | PQZ OFFCHAIN releases (verifier 0) deploy on any EVM chain through `script/pqz/e2e.py`; the rows are rewritten in T19 |
| 14 | §16 | the merge plan's order and totals (3e → 3c) | 3f between 3e and 3c, 10 agent-days (§16) |

The first draft's rows on CTR-ZTH-52, CTR-ZTH-20 for Zether, the book and the registry verifier-signed key are gone with R1–R3.

## 11. Node, PQZ verifier (off-chain), clients, vectors — SPECIFIED

### 11.1 Node (`scaas-node`)

The verifier role belongs to the token (O2), never to the node. The node is open and **keyless** for this group: it relays
verdicts it is given or fetches, it never signs one. The guarantees below are the node's, in `job-api.md`, for every consumer.

| Area | Change |
|---|---|
| PQZ entries (`metatx` / `ua_metatx`, `contract = "pqz"`, the twelve named entries) | `args` gain a named `pqz_verdict: {verifierEpoch, validUntil, auth: WireUASig}`; the node builds `PqzVerdict` itself from the token, the chain, `proofSystemId()`, the statement it simulates through the token's statement view and the job's proof, so the verifier's signature must match what the node rebuilt. A hex or packed verdict is `HEX_ARGS_REFUSED`. PRECOMPILE token: the node sends the empty verdict; a job `pqz_verdict` there is refused `PQZ_VERDICT_NOT_EXPECTED` |
| Fetching (optional) | an OFFCHAIN job without `pqz_verdict` is sent to the operator's configured verifier endpoints (`[pqz_verifier] endpoints`, in order); the response is decoded with the existing bounded `UASig` decoder (two levels, 16 slots), a size limit and a timeout; none answers ⇒ refused `PQZ_VERDICT_MISSING`, zero sends |
| Pre-checks | `pqzVerifyConfig()`: mode, verifier, epoch, revoked; `verifierEpoch` equal; `validUntil` beyond the expected inclusion plus the operator's margin; simulation of the whole entry (the signature, the shape, the hashes) |
| Health signal (C8, Fable P2-7) | the indexer keeps per OFFCHAIN token `pqzLastVerdictAt` (the last `PqzVerified`), the current epoch and revoked state, and the probed health of the configured endpoints; exposed in the token feed. With `[pqz_verifier] refuse_shield_when_unserved = true` (off by default) the node refuses shield and wrap-shield jobs into a token whose verifier is revoked or unreachable, `VERIFIER_UNREACHABLE`, so no relayer of that node adds value to a pool nobody serves; the same rule for every consumer |
| `typed.rs`, `guard.rs` | the twelve entries' rows with the two parameters, the seven-argument view, the three stubs per kind, three router rows; equality both directions with `mtxSelectors()` and `selector_audit.json` |
| Errors | named decode of `PqzVerdictMismatch(field)`, `PqzVerdictRejected`, `PqzVerifierRevoked`, `PqzVerifierChanged`, `PqzVerifierFixed`, `PqzVerifierNotReady`, `PqzVerifierPending`, `PqzVerifierSame`, `PqzVerifierUnregistered`, `PqzVerifierKind`, `PqzVerdictRequired`, `VerifyModeInvalid`, `PqzVerifyConfigInvalid`: refusals, never `dead` while a transaction may land; an epoch change makes the node re-fetch once |
| Indexer, feeds | `PqzVerified` joined to the op's `ConfidentialTransfer*` / `Unshielded` by transaction, with the transaction position (for the audit replay, Codex #10); `PqzVerifierProposed` an **alert** with `eta`; `…Set`, `…Cancelled`, `…Revoked` (an alert) |
| Mesh | unchanged: PQZ ops are never on the mesh (CTR-PQZ-15) |

### 11.2 The PQZ verifier (off-chain; separate, optional)

A **separately operated** process with its own custody, resource limits and operator — a trust role named by tokens, not a node
module (C7). The repository ships a reference implementation (`scaas-pqz-verifier`, its own crate and binary, never linked into
`scaas-node`); anyone may run another that keeps this contract.

| Area | Rule |
|---|---|
| Request | `POST /v1/pqz-verdict` `{token, chainId, op, statement, proof, verifierEpoch}` with `statement` and `proof` hex; named fields only; the route's body limit is set from the configured set's largest `STMT_*` plus `MAX_PROOF(id)` (98,304 B PQZL) doubled for hex plus 4 KiB; JSON depth ≤ 4; refused before decoding when larger (Codex #6) |
| Verification | the release address → set mapping; the statement length must be one of the set's `STMT_*`, its word 32 the set's PQZL id; `pqz-ffi`'s `pqz_precompile` (byte for byte the precompile's verdict); the token's state read to rebuild and compare the statement (never trusting the request's bytes alone); every key named passes §6's checks |
| Signing | only on verdict 1 and passing key checks; the keystore named in the service's own config (never a lane key, never the node's); `validUntil` short (minutes), `verifierEpoch` the token's current; every signature logged with `token`, `statementHash`, `proofHash` |
| Bounds | a bounded queue and concurrency; per-client rate limits; a refusal is a named JSON error, never a signature |
| Probe | signs a fixed probe statement on request (the typo guard of §4.2) |

### 11.3 Clients and vectors

| Item | Change |
|---|---|
| `clientkeys` | `PqzVerdict` digest and builder, `statementHash` / `proofHash` helpers, the twelve entries' calldata with the pair, the creation fields |
| `ua-rs` (the one signer) and `ua-c`, `ua-cxx`, `ua-qt`, `ua-dart-frb` | sign `PqzVerdict` under `pqz-verdict` (a verifier is a UA like any other) |
| App, wallets | show the mode, the verifier, fixed or transferable, its epoch, a pending transfer with `eta`, a revocation, and AV-1's sentences with the maximum loss before a shield into an OFFCHAIN token; ask the verifier whether a payee key is usable before a send |
| new `smartcontracts/vectors/pqz/verdict.json` | `PqzVerdict` digests in the token domain; `statementHash` / `proofHash` of the existing `pqz/statement_*.json` rows; written by a forge test, read by `clientkeys`, `ua-rs`, the node, `scaas-pqz-verifier` |
| `smartcontracts/vectors/typed/typed_ops.json` | the three router rows |
| `smartcontracts/evm/test/vectors/selector_audit.json` | the twelve entries' new selectors, the view, the stubs, per kind 4, 5, 12, 13 |
| Unchanged | every statement, proof, `R_REG`, `portable.json` and every Zether vector |

## 12. Open questions

| # | Question | Recommendation |
|---|---|---|
| Q1 | May the owner revoke a **fixed** verifier (R4 does not say)? Revoking it freezes the confidential balances for ever, since a fixed token can never take a new verifier | **Answered (owner 2026-11-06): no.** "fixed" means the owner has no power over the verifier (O2); a fixed token's containment is the creation-time choice of a regulated kind with `PAUSE` / `FREEZE` (AV-1's table). Built so in §4.3 (`PqzVerifierFixed`); was: until the owner rules |

Answered by the reviews and the rulings: Q2 (PQZL only) agreed by both reviews; Q3 (no extra verifier kinds now), Q4 (no bit),
Q5 (no on-chain acceptance; the off-chain probe), Q7 (no cap on `validUntil`), Q8 (wrapped kinds allowed with the maximum-loss
sentence), Q9 (Hedera not in this group) agreed by Fable; Q1 (Zether) and Q6 (re-verified keys) closed by R1 and R3.

## 13. Rules this group adds — SPECIFIED

Each lands in `docs/decisions.md` in T19 (T19 confirms the ids are still next-free with `docs_check.py`).

| Label | Proposed id | Rule (one line) | Section |
|---|---|---|---|
| AV-1, AV-2 | CTR-PQZ-27 | `pqzVerifyMode` per PQZ token at creation, immutable, no chain detection; OFFCHAIN trades soundness for trust in a named verifier UA (maximum loss `min(totalShielded, maxShielded) · shieldScale`), authorization, ciphertexts and confidentiality of honest data unchanged | §2, §3 |
| AV-3, AV-4 | CTR-PQZ-28 | The verifier UA: allowed kinds, registered, shape frozen at assignment; fixed or transferable; transfer by the owner with the factory's notice, confirmed by its proposer in the same owner generation; immediate revocation (freeze only); no bit | §4 |
| AV-5 | CTR-PQZ-29 | `PqzVerdict` inline as the last parameters of every proof-carrying entry, checked in `_check` against the rebuilt statement, the proof, the epoch and the verifier; ignored in PRECOMPILE; disclosure "cannot verify" without it | §5 |
| AV-6 | CTR-PQZ-30 | OFFCHAIN tokens accept unproven keys of the set length; the verifier checks `R_REG`, stored `pqzPop` bytes and single ownership off chain, cached by `(ua, pqzKeyHash)` | §6 |
| — | NODE-JOB-22 | The named `pqz_verdict` sub-object of PQZ entries; fetching from configured endpoints; the node never signs; the health signal and the opt-in `VERIFIER_UNREACHABLE` shield refusal | §11.1 |

## 14. Invariants — SPECIFIED

| # | Invariant | Test |
|---|---|---|
| I1 | `pqzVerifyMode` is written only by init; no entry or router op changes it | `vm.accesses` on every selector of 4, 5, 12, 13 |
| I2 | an OFFCHAIN debit lands only with a verdict signed by the current, non-revoked, unchanged-shape verifier over exactly `(this, chainid, psid, keccak256(statement), keccak256(proof), verifierEpoch)`, live at `now` | `PqzVerdict.t.sol`, invariant handler |
| I3 | after a transfer or a revocation no verdict of an older epoch is accepted, including a re-assignment back to an earlier verifier | handler with A → B → A and revocations |
| I4 | the state writes of a debit (op blob, entry, memo, pending, `acc`) are identical in both modes for the same op | differential fixture in both modes |
| I5 | a PRECOMPILE token never reads the verdict; an OFFCHAIN token never calls `0x…5caa0f01` | a reverting precompile etched in OFFCHAIN tests; an always-reverting registry path for `PURPOSE_PQZ_VERDICT` in PRECOMPILE tests |
| I6 | public balances, `totalShielded` and the escrow invariant hold in both modes | the existing PQZ invariant suites run in OFFCHAIN mode |

## 15. Tests and mutants — SPECIFIED

Red first; **positive control first** (the same call with a valid verdict by the current verifier), then one change at a time.
Negatives, each able to fail:

- **Wrong token / chain:** `att.token` another token ⇒ `PqzVerdictMismatch(token)`; `att.chainId` another ⇒ `(chainId)`; a
  signature in another token's domain ⇒ `PqzVerdictRejected`.
- **Expired:** `validUntil = now − 1` ⇒ `PqzVerdictMismatch(validUntil)`; `now` passes.
- **Statement swap:** a verdict over S1, the op builds S2 (another `fee`, `beneficiary`, `p`, `salt`, `envelopeBinding`, a replaced key) ⇒
  `(statementHash)`. **Proof swap:** same S, another proof ⇒ `(proofHash)`.
- **Epoch:** a signature at epoch e after a transfer ⇒ `(verifierEpoch)`; A → B → A with A's withheld epoch-1 signature ⇒ refused;
  a same-UA transfer ⇒ `PqzVerifierSame`.
- **Verifier changed without notice:** confirm at `eta − 1` ⇒ `PqzVerifierNotReady`; at `eta` passes; non-owner ⇒ refused;
  another caller ⇒ `NotProposer`; an owner change between proposal and confirm ⇒ the pending is dead; fixed ⇒ `PqzVerifierFixed`;
  `noticePeriod = 0` applies at once.
- **Revocation:** immediate; the next debit ⇒ `PqzVerifierRevoked`; the OFFCHAIN view false; a pending transfer deleted; a new
  verifier only after a full notice; a fixed verifier ⇒ `PqzVerifierFixed`.
- **Shape:** a native verifier that gains code, an `msig` native member that gains code, a slot accepted after assignment ⇒
  `PqzVerifierChanged`; a re-assignment through the notice accepts the new shape.
- **Precompile-dependent verifier kind accepted:** `mldsa87`, `zether-bls12381`, `bls12381-minsig`, `schnorr-bn254`, a native id
  with code, an `msig` with an `mldsa87` member, a nested `msig` ⇒ `PqzVerifierKind`; an unregistered derived id ⇒
  `PqzVerifierUnregistered`; positive controls EOA, `secp256k1`, `p256`, `webauthn-p256`, `mldsa65` (cached), 2-of-3 `msig` pass.
- **Mode switch after init:** I1; `PqzVerifyConfigInvalid` for PRECOMPILE with a verifier and OFFCHAIN with 0; `VerifyModeInvalid(2)`.
- **The default:** a PRECOMPILE token from a zero-dep release ⇒ `SelfTestFailed(address(0))` before any call; without the
  precompile a verdict ⇒ `UAVerifyGas` (pins unchanged in meaning); an OFFCHAIN token with a reverting precompile etched works (I5).
- **PRECOMPILE ignores the verdict:** a garbage verdict on a PRECOMPILE token changes nothing; the precompile decides.
- **Keys:** an unproven key: PRECOMPILE ⇒ `AccountNotRegistered`, OFFCHAIN passes; a key of another set's length ⇒
  `AccountNotRegistered` in both; an unproven auditor at OFFCHAIN init passes, at PRECOMPILE init refused.
- **Disclosure:** five-argument form on OFFCHAIN ⇒ `PqzVerdictRequired`; seven-argument form true for a valid verdict, false
  for another `amount`, `leg`, `kind`, a revoked verifier.
- **Ciphertexts:** I4 on op 1, op 7 (M = 4, auditor), burn, refresh, unshield-unwrap.
- **Starvation:** the signature check with too little gas ⇒ `UAVerifyGas`, never `PqzVerdictRejected` / `ProofRejected`.
- **Typehashes unchanged:** every `UA*` typehash pin and `PqzAuth`'s stay green.
- **Client digests:** `clientkeys` and `ua-rs` against `pqz/verdict.json`.

**Mutants** (one at a time, clean tree, logged `mutant | test that went red | rc`; a survivor is a finding):

| Area | Mutants |
|---|---|
| Binding | `att.token != address(this)` unchecked; `att.chainId` unchecked; `att.proofSystemId` unchecked; `proofHash` not compared; `statementHash` over the buffer with its prefix; `verifierEpoch` unchecked; `validUntil` unchecked |
| Verifier | the verifier read from calldata instead of storage; revocation not checked; the shape not recomputed; the kind check skipped at proposal; `mldsa87` in the allow-list; the notice not waited; confirm by any owner rather than the proposer; the owner generation ignored; `pqzVerifierFixed` ignored; the epoch not bumped on transfer or revocation |
| Mode | a setter writing the mode; OFFCHAIN calling the precompile when present; PRECOMPILE reading the verdict |
| Keys | OFFCHAIN dropping the length check; PRECOMPILE accepting an unproven key; the auditor rule applied in PRECOMPILE |
| Disclosure | the five-argument form returning `false` instead of `PqzVerdictRequired` |
| Node | an OFFCHAIN job sent without a verdict; the verdict struct taken from the job rather than rebuilt; `PqzVerdictMismatch` decoded as `dead`; a shield sent with `refuse_shield_when_unserved` on and the verifier revoked |
| Service | signing on verdict 0; a key without stored `pqzPop` bytes given a verdict; a cache keyed by `ua` only; dispatch on the outer `proofSystemId` |

## 16. Tasks — SPECIFIED

Written into the merge plan as **T44–T50**, after T57 (3g; owner 2026-11-07) and before 3h and 3c; T19 (docs), T21 (gates), T22 (review) and T23 (PR) cover
the group. Contracts T44 → T45 sequential in this worktree (shared `PqzCore`, `PqzLayer`, `size-baseline.json`); T46 after T45
fixes the ABI; T47 after T46; T48 beside T46–T47 (its own crate); T49 after T45, beside T46–T48. Every contracts task ends with
the whole `forge test` green at the default set and the size gate, and runs `script/pqz/at-set.sh <set> test --match-path
'test/{ua,pqz,as/confidential}/*'` at the four sets (one run per work tree, `PqzSet.sol` restored). Legacy copies (MD-4) first where
a body is replaced. Heavy runs through `scripts/capped`, foreground.

| Task | Content | Depends on | Estimate (agent-days) |
|---|---|---|---|
| T44 | Core: `ConfidentialConfig` fields and `TokenConfig` ripple; `PqzLayer` constructor and `_init` (zero dep), `PqzStateLib.init` (OFFCHAIN init, the auditor rule); `PqzCore._check` OFFCHAIN branch, `_keyPtr` / `_creditKey`; the verifier storage, shape, transfer, revocation bodies; events, errors; `PqzVerdict` typehash pin, `PURPOSE_PQZ_VERDICT`; `script/pqz/e2e.py` zero-dep form | T57 | 2 |
| T45 | Entries: the two parameters on the proof-carrying entries of 4, 5, 12, 13 (twelve on 5, 13; ten on 4, 12) (the struct fallback if the stack needs it); the seven-argument `verifyTransferAmount` and `PqzVerdictRequired`; the three stubs, `pqzVerifyConfig()`, the three router ops; `mtxSelectors()`, `selector_audit.json`; layout and gas pins old → new; **kind 13 measured first**, stop rule and levers (§9), then every kind; the four sets; the tests of §15 | T44 | 2.5 |
| T46 | Vectors and clients: `pqz/verdict.json`, `typed_ops.json` rows, `clientkeys` builders and digests, `ua-rs` and wrappers, the creation fields in the wizard and clients; generators re-run, `git diff --exit-code` | T45 | 1 |
| T47 | Node: the `pqz_verdict` sub-object, rebuilding `PqzVerdict`, fetching with bounds, pre-checks, rows, errors, indexer joins and alerts, the health signal and the opt-in shield refusal, operator-note draft; `CAPPED_MEM=6G` whole suite alone, clippy, e2e on anvil in both modes | T46 | 1.5 |
| T48 | `scaas-pqz-verifier`: the reference PQZ verifier (off-chain) (separate crate and binary, its own keystore config, bounded request, `pqz-ffi` verdict, statement rebuild from state, §6's key checks and cache, set binding, probe); tests with tampered statements, keys without stored proofs, oversized and deep bodies | T45; beside T46–T47 | 1 |
| T49 | Invariants I1–I6 and the mutant harness of §15 | T45; beside T46–T48 | 1 |
| T50 | T19's share: §10's Change lines, §13's entries, `pq-zero-knowledge.md` §1, §9, §12 and §14, `accounts.md` CTR-UA-16, `docs/networks/evm.md`, `integration.md` (the off-chain disclosure and audit-replay recipes), `job-api.md`, `ops.md` (the PQZ verifier (off-chain) as a separate trust role), `indexer-feeds.md`; BUILT only with code and tests | T44–T49 | 1 |

**Total: 10 agent-days.** Fable's 7.5–8.5 counted no reference service and no shape freeze or revocation: T48 adds 1, the
shape freeze and revocation about 0.5 across T44 and T45.

## 17. Review disposition

Every item of the two reviews ([Codex](../../research/attest-codex-review.md), [Fable](../../research/attest-fable-review.md)):
**adopted** (where), **rejected** (reason) or **closed by owner ruling** (R1–R4).

| Item | Severity | Outcome |
|---|---|---|
| Codex #1 the signed verdict has no epoch | high | adopted: `verifierEpoch` in `PqzVerdict`, checked equal, bumped on every transfer and revocation, `PqzVerifierSame` (§5.1, §4.2, I3); confirmed by R2 |
| Codex #2 native `msig` members change policy without notice | high | adopted: the frozen shape (C3, §4.1), `PqzVerifierChanged`, tests and mutants |
| Codex #3 last-write-wins expiry rollback | medium | closed by R2 (nothing is stored) |
| Codex #4 Zether views use the immutable verifier | medium | closed by R1 |
| Codex #5 release verifier vs PQZ verifier UA conflated | medium | adopted: `releaseProofVerifier` and `pqzVerifierUA` named apart (C5, §3) |
| Codex #6 endpoint without a bounded request contract | medium | adopted for the separate service (§11.2: named fields, set-derived body limit, depth, queue) and the node's fetch (bounded `UASig` decoder, size, timeout) |
| Codex #7 same-lane ordering does not prove the verdict landed | medium | closed by R2 (one transaction) |
| Codex #8 an in-node signer changes key custody | medium | adopted: the node is keyless; the service is a separate process and trust role (C7, §10 row 10, §11.2) |
| Codex #9 the zero-verifier change targets a removed factory check | low | adopted: the gate in `PqzLayer`'s constructor and `_init`, `PqzStateLib.init`, `script/pqz/e2e.py`; never inferring the mode from a missing dep (C6, §3); the Zether half closed by R1 |
| Codex #10 parent-block views do not reconstruct the audit | low | adopted: replay at the exact transaction position; the indexer keeps the position (§2, §11.1) |
| Codex #11 containment excludes fixed / renounced configurations | low | adopted: AV-1's containment table; R4 adds revocation for transferable verifiers; Q1 for fixed ones |
| Codex §10 judgments (rows 1–14) | — | adopted where the row survives: row 1 keeps the release gates; row 2 discloses classical verifiers; row 9 (Hedera) stated as a retained exception (§10 row 9); row 11's aggregate-budget caveat (§4.1); rows on Zether, the book and the registry key closed by R1–R3 |
| Codex "checked and sound": ownership-generation invalidation of the pending; never dispatch on the outer `proofSystemId`; `R_REG` message per path | — | adopted (§4.2, §5.2, §6) |
| Fable (a) inline, not a book | answer | closed by R2 |
| Fable (b) accept unproven keys | answer | closed by R3, with its requirements (§6) |
| Fable P1-1 the gate is in `PqzLayer._init`, not `OpenFactory` | P1 | adopted (C6, §3, §9 row) |
| Fable P1-2 kinds 4–5 cannot stop a compromised verifier; maximum loss | P1 | closed by R4 (§4.3); maximum loss in AV-1 |
| Fable P1-3 the size count misses the `_init` branch and the config fields | P1 | adopted (§9 rows) |
| Fable P1-4 verdict-before-op is new node machinery | P1 | closed by R2 |
| Fable P2-5 the verdict transaction has no payer | P2 | closed by R2 |
| Fable P2-6 censorship and delay | P2 | adopted (AV-1) |
| Fable P2-7 shields flow into an unserved pool | P2 | adopted: the health signal and the opt-in `VERIFIER_UNREACHABLE` refusal (C8, §11.1) |
| Fable P2-8 the registry verifier-signed key's gaps | P2 | closed by R3 |
| Fable P2-9 missing rows: CTR-PQZ-15, gas pins | P2 | adopted: §10 rows 6 and 8 |
| Fable P2-10 the verifier learns which ops are audited | P2 | adopted (AV-1) |
| Fable P2-11 the set is implicit | P2 | adopted: the service binds release → set and checks the length (§3, §11.2) |
| Fable P2-12 a verifier must be registered first; its own error | P2 | adopted: `PqzVerifierUnregistered` (§4.1) |
| Fable P3-13 ids not next-free | P3 | adopted: CTR-PQZ-27…30, NODE-JOB-22 (§13) |
| Fable P3-14 statement size 93,312 B at `n2304-kmax4096` | P3 | adopted (§7) |
| Fable P3-15 a typo in `next` freezes balances for another notice | P3 | adopted: the off-chain probe verdict before a proposal (§4.2, §11.2); still no on-chain acceptance |
| Fable P3-16 estimates ≈ 7.5–8.5 | P3 | adopted with the additions named in §16: 10 |
| Fable 1.Z (Zether findings) | — | closed by R1 |
| Fable §2 verdicts on Q1–Q9 and §10 | — | adopted (§12, §10) |

## 18. Risks — SPECIFIED

| # | Risk | Mitigation |
|---|---|---|
| 1 | A dishonest or compromised verifier approves a false proof: loss up to `min(totalShielded, maxShielded) · shieldScale` | AV-1 at creation and in wallets; k-of-n `msig` of derived keys; every acceptance auditable; immediate revocation; PAUSE / FREEZE on 12, 13 where configured |
| 2 | The verifier stops or censors: balances freeze or selected parties wait | transferable recommended; revocation and transfer; the health signal and opt-in shield refusal |
| 3 | A fixed verifier is lost or dishonest: no on-chain answer on 4, 5 | disclosed (AV-1's table); Q1 |
| 4 | Kind 13 crosses the stop line after 3e | measured first in T45; five ordered levers |
| 5 | A pure-Solidity `mldsa65` verifier costs more than the precompile | §7's table in the disclosure and the node's quote |
| 6 | OFFCHAIN holders' keys are not chain-readable as usable | wallets ask the verifier before a send; a refused key fails before any credit |
| 7 | A reference service bug signs a bad statement | the service rebuilds the statement from state, binds release → set, and is separate from the node; its mutants (§15) |
