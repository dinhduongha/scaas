# Governance: identity by UA — Change to the governance spec (draft for the owner)

**Status:** ACCEPTED by the owner 2026-11-04 (all three points of §7). BUILT on branch `governance`: identity by UA by plan
task T10b (`ac29de05`), the `GovernanceRouter` of §3 by T11 (governance spec §3, `src/governance/GovernanceRouter*.sol`);
the node rows (T15) and the clients' rows (T12) are SPECIFIED. Changes `docs/superpowers/specs/2026-11-02-governance.md`
(accepted 2026-11-03) §1.4, §2, §3, §3.6, §8, recorded as Changes on CTR-GOV-01 and CTR-GOV-15.

**Owner, 2026-11-04:** use UA, the same on every chain — every governance identity is a UA, the same id on
every family; agreed with the controller's design below, Change spec first.

## 1. The rule

Every identity the governance model stores or names is a **UA id (`bytes32`)**: `owner`, `pendingOwner`, every holder in
`roles`, `grants`, `epoch`, `pending`, every grantor in a `Grant`, every proposer in a `PendingGrant`, and the same in every
event and view. A native account's identity is its native id (on EVM `bytes32(uint256(uint160(addr)))`, the existing
native space of `UAKinds.inNativeSpace`); a derived UA (any registered kind: PQ, `msig`, MuSig2, FROST, WebAuthn, …) is
its registered id. One rule on every family: each family stores the same `bytes32` and maps its own caller to it.

**Unchanged:** the bits and bands (CTR-GOV-10), `features` / `lockedFeatures`, the Grant terms and every rule of §1.5-§1.7,
the two-call delay, the masks, "+0" (a transfer reads no governance slot). **Payout destinations stay native addresses**
(`rescueTo`, the DEX `treasury`): they receive assets, which live in native accounts on each chain.

## 2. Who is calling: `_govSubject()`

Authentication does not move into the governed contract: no signature is verified there, and the relay rule G19 stands
(an owner or holder operation has one direct entry and no `mtx*` / `ua*` twin on the governed contract).

| Caller | Subject the contract uses | Cost |
|---|---|---|
| any address (EOA, Safe, `SmartKeyAccount`, any contract) | its native id, `bytes32(uint256(uint160(msg.sender)))` | arithmetic only |
| `GOV_ROUTER` (one per chain, an immutable of the governed contract) | `IGovernanceRouter(GOV_ROUTER).subject()`: the UA the router authenticated for this call; 0 outside a live call → refused | one STATICCALL, only on this path |

`GovernanceBase._govSubject()` replaces `_caller()` for every governance check (`use`, the owner's entries, `grantRole`
by a grantor, `renounceRole`, `acceptOwnership`, `cancelGrant`). A power's own entry (`mint`, `freeze`, …) uses the same
subject. `UA_POOL`, `SHIELD_POOL` and `bytes32(0)` stay refused as owner and as holder.

## 3. `GovernanceRouter` replaces the per-operator `GovernanceHolder` (recommended)

One contract per chain, CREATE2 at a predictable address, no owner, holds nothing.

- **Entries:** the closed table of spec §3.2, each as `mtx<Op>` and `ua<Op>` (fee mode `NONE`, relayable at fee 0), the
  op's parameters with `bytes32` identities and `target` a signed word. No `execute(bytes)`; the generic path is refused.
- **Flow:** verify through `UARegistry.requireAuthorized(subject, PURPOSE_METATX, digest, auth)` (msig, PQ, every kind the
  registry verifies), consume the nonce, write the transient pair `(subject, target)`, call `target.<op>(...)`, clear the
  pair. `subject()` returns the subject only while `msg.sender`-side `target` equals the live target; a re-entry into the
  router reverts (`Reentrancy`).
- **Domain:** `("SCaaS GovernanceRouter", "1", chainId, router, chain_uid)`; `target` signed, so no replay across chains,
  routers, targets.
- **What goes away:** the per-operator clone factory, `operator`, `proposeOperator` / `acceptOperator`, `generation`.
  Changing who controls a power is the governed contract's own rule: the owner grants or revokes the new UA (two calls when
  widening, §1.6); ownership moves by `transferOwnership(bytes32)` + `acceptOwnership` signed by the new UA through the
  router. An `msig`'s members cannot change (CTR-UA-37): a new `msig` takes over by these same calls.
- **Gas bounds of spec §3.5 stand** (the registry's `verifyBudget`, 2^24 per transaction, one lane per target).

**Alternative (not recommended):** keep one `GovernanceHolder` clone per UA, salted by the UA, and resolve the subject by
asking a verified clone for its UA. It keeps operator rotation but needs a code-hash check per call and one deployment per
issuer, and rotation would move powers away from the UA they were granted to, which contradicts identity by UA.

**Also weighed and refused (owner 2026-11-04: keep the router):** `ua<Op>` entries in `GovernanceBase` itself, no `mtx*`. A native account signs `ua*` as its native kind, so it would cover every caller, and no shared router would exist; but each entry measures 287-301 B per kind (spec §3.6), about 13-15 entries put about 4-4.5 KB on every governed contract (estimate): `WrappedPqzToken` past the 74 KB deploy bound, `WrappedZetherToken` past 64 KiB, the base kinds further from a public block. The router adds about 0.2-0.5 KB per contract and keeps the verification in one audited place.

## 4. ABI, storage, events (EVM)

- **Entries:** `grantRole(uint8, bytes32 account)`, `revokeRole(uint8, bytes32)`, `renounceRole(uint8)`,
  `setGrant(uint8, bytes32 holder, GrantTerms)`, `cancelGrant(uint8, bytes32)`, `transferOwnership(bytes32)`,
  `acceptOwnership()`, `renounceOwnership()`, `disableFeature(uint8)`; views `owner() → bytes32`, `pendingOwner() → bytes32`,
  `hasRole(uint8, bytes32)`, `grantOf(uint8, bytes32)`, `pendingGrant(uint8, bytes32)`. `TokenConfig.owner` / `DexConfig.owner`
  and `init`'s owner and initial roles become `bytes32`.
- **Storage `erc7201:scaas.governance`:** the same slots, keys and owner words widened to `bytes32`: `owner` and
  `pendingOwner` each take their own slot, so `grantDelay`, `ownerGeneration`, `lastProposedAt` move to a packed slot of
  their own; mappings keyed `bytes32`; `Grant.grantor` and `PendingGrant.proposer` `bytes32`. New layout pins (no deployed
  contract exists: all chains are test-only).
- **Events:** every `address indexed account / holder / grantor / sender / by / owner` becomes `bytes32 indexed`.
- **Contract-only bits** (`_contractOnlyBits`, e.g. `RATE_ADJUSTABLE`): the holder must be a native id whose address has
  code at the grant (the rule today), so a derived UA cannot hold such a bit; unchanged.

## 5. Every family

The stored identity is the same `bytes32`; the family maps its caller: Soroban `Address::require_auth()` → the native id
of that address, or its router's subject; Solana the signer's pubkey as native id, or its router program; NEAR the
predecessor account's native id, or its router; and so on per family round (Part D7 and later). Bits keep the 0-255 width
(CTR-GOV-10).

## 6. What it costs in the work done

| Area | Change |
|---|---|
| T1-T10 code | `GovernanceLib`, `GovernanceBase`, `IGovernance`, the six kinds, `SCaaSDex`, `DexPuller`, `WrappedLib`, factory config: key and owner types, `_govSubject()`, events |
| Tests | every governance suite and fixture to `bytes32`; layout pins renewed; `dex_order_kat.json` regenerated; mutants: router subject ignored, router subject read outside a live call, native id computed wrong, `UA_POOL` as owner accepted |
| Size | estimate +0.2 to +0.5 KB per governed contract (the router branch, wider ABI words); measured at the task |
| T11-T13 | T11 builds `GovernanceRouter` instead of `GovernanceHolder` (smaller: no clone factory, no rotation); T12's `typed_ops.json` rows and T13's selector audit follow the new ABI |
| Node | NODE-JOB rows for the router (T15) instead of the holder; the gateway's governance views read `bytes32` |
| Docs | CTR-GOV-01 Change (identity by UA), CTR-GOV-15 Change (router, no operator rotation), spec §1.4, §2, §3, §3.6, §7, §8, §12; `accounts.md` cross-reference |

**Plan:** a new task **T10b** right after T10 (done) and before T11: identity by UA on every governed contract, with its
tests, mutants, pins and gates; then T11 as the router.

## 7. For the owner

1. Accept identity by UA as written (§1, §2, §4, §5).
2. Router (§3) instead of per-UA holder clones: recommended.
3. Payout destinations (`rescueTo`, `treasury`) stay native addresses: recommended.
