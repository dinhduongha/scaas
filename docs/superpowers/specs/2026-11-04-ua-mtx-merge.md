# `ua*` / `mtx*` merge: one signed entry per operation, and the base token size for public chains — design

**Status:** DRAFT for the owner; numbers to re-measure after PR #9 merges. Nothing is built. Work-order item 3 of TODO
(owner 2026-11-03), its own round between SCaaS testnet reset 1 and reset 2. Owner 2026-11-04: the spec now, the measurement
after PR #9 (governance) merges.

The spike behind it is [research/governance/prototype/merge-entries.md](../../research/governance/prototype/merge-entries.md)
(branch `token-merge`, not to be merged); the earlier size options are `docs/research/governance/prototype/size-options.md` on
branch `token-core` (not to be merged). The rules it changes are in [contracts/metatx.md](../../contracts/metatx.md),
[contracts/accounts.md](../../contracts/accounts.md) and [contracts/dex.md](../../contracts/dex.md); the governance rules
(`CTR-GOV-*`) and the router are on branch `governance` (PR #9) and are cited by id only until it merges.

**Tags.** **[M-old]** measured by the spike on the governance prototype D1 + D2 (`6e09e008`), before the governance build,
the `ZetherLib` split (CTR-ZTH-94) and ML-DSA-87 / Falcon-1024; **[R]** read from code, not run; **[P]** projection, a sum
of measured deltas on another base; **[M]** measured on the base named. **Every figure in this file is re-measured after
PR #9 (§9)**; none of it is a pin. Rows marked **controller proposal** are the controller's and the owner may override them;
§5 and §10 list what only the owner decides. Everything cryptographic stays `UNAUDITED`.

## 0. Summary and the owner's words

**The owner, 2026-11-03** (as recorded in the spike and TODO): for every pair of `ua*` + `mtx*` entries, keep the `ua*`
implementation and give it the `mtx*` name; the old `mtx*` implementation goes, because the pair is one feature written
twice. The wallets keep the address surface. It is its own round, after the governance build, between the two SCaaS
testnet resets, and it carries the base token size for public chains (TODO: "Pick the smallest set that fits 60 M and
70 M").

**What this spec proposes, in one paragraph.** Every relayed, subject-signed operation of a SCaaS EVM token kind (and of
`MtxRelayFee`, the DEX's SCaaS legs and `GovernanceRouter`) has **one** entry, named `mtx<Op>`, with the ABI of today's
`ua<Op>` (`MetaTxLib.UAEnvelope e, <explicit op parameters>, IUARegistry.UASig auth` for a named op; the flat explicit form
with `bytes32 from` for the transfer group) and signing the typed struct `UA<Op>` with a `bytes32 from`. A native address is its zero-padded id and signs with its own key in `auth.signature`, with **no registry
call**; a derived UA is authorized by `UARegistry.requireAuthorized`. A registry is needed only by a derived side, so
`NORMAL` and `WRAPPED` at `registry() == 0` keep a relayed path for EOAs. The wallets (`MandateWallet`,
`SmartKeyAccount`, `HederaMandateWallet`) keep `MetaTransaction` and their address entries. Direct entries
(`transfer`, `approve`, `wrap`, `payWithFee`, the governance entries, …) do not change. The address bodies move to
`legacy/`. On the old base the merge freed 8.7 to 11.5 KB per kind [M-old]; it does not alone bring `WrappedToken` under a
60 M deploy, so §4 sets how the round picks further levers.

**Recommendations, short:** take A + B + C (§2.6) as the round's base; take A2 for the five wrap entries and move
`executeMetaTransaction`'s alias onto the merged generic entry on tokens, kept on the wallets (Q2); keep the `UA<Op>` type
names so no UA-side vector changes (Q3); merge the router's 19 pairs too (Q4); measure lever 3 (D) and the library
pattern (L) after PR #9 and take the smallest set that makes `NormalToken`, `WrappedToken` and their regulated stand-ins
fit a 60 M deploy (Q5, Q6).

## 1. Goal and non-goals

**Goal.**

1. One subject-signed relayed entry per operation on the six EVM token kinds (`NormalToken`, `WrappedToken`,
   `NormalZetherToken`, `WrappedZetherToken`, `NormalPqzToken`, `WrappedPqzToken`), on Hedera through the same kinds,
   on `MtxRelayFee`, on the DEX's SCaaS legs and on `GovernanceRouter`: the `ua*` body under the `mtx*` name.
2. Every such entry stays relayable at fee 0 (fee mode `NONE`), on a chain with or without a UA registry for a native
   subject.
3. The base token kinds fit a public chain's block for their implementation deploy: `NormalToken` and `WrappedToken` under
   the EIP-8037 inclusion rule at 60 M (and so at 70 M); the Zether kinds measured against the same thresholds (§4).

**Non-goals.**

- **Wallets.** `MandateWallet`, `SmartKeyAccount`, `HederaMandateWallet` keep `MetaTransaction`, `mtxExecute`, `mtxBatch`,
  `mtxNonce`, `mtxDigest`, `mtxCancelNonce`, `executeMetaTransaction` and their own named entries, all with `address from`
  (owner). They have no registry and no `ua*` twins; the spike shows them byte-identical [M-old].
- **Direct entries.** `transfer`, `transferFrom`, `approve`, `transferToUA`, `payWithFee`, `payWithFeeToUA`, `wrap*`,
  `unwrap*`, `addReserve`, `cancelNonce`, the direct confidential ops, every `GovernanceBase` entry and every power's own
  entry stay as they are.
- **Ledgers.** No balance moves: derived balances stay in the separate `bytes32` ledger, natives in the ERC-20 ledger
  ([CTR-UA-18](../../contracts/accounts.md#CTR-UA-18) holds). No storage slot moves (layout pins hold).
- **Registry, kinds, proofs.** `UARegistry`, the kinds (ML-DSA-87 `0x0134` and Falcon-1024 `0x0135` included), the PQZ and
  Zether statements, transcripts and `proofSystemId`s do not change.
- **PQZ kinds on public chains.** Not a target: they run only where the PQZ precompile is, on an operator-controlled chain
  (CTR-GOV-19).
- **Other families' code.** No non-EVM contract changes in this round; the rule below binds their own rounds.
- **Migration.** None: every chain is test-only; the SCaaS testnet takes the new contracts at reset 2.

**One rule on every chain.** The merged form is the EVM expression of a rule every family can state the same way
(proposed as R15, a new row of the family checklist
[NET-ALL-84](../../networks/README.md#NET-ALL-84)): *per operation, a contract has its direct entry (the chain's own caller)
and at most one contract-verified signed entry; that entry's subject is a UA id covering both spaces; a native subject uses
it where the chain's host does not already authorize a native account for a call someone else submits, and signs it with
its own key.* On EVM no host path exists for an EOA (no EIP-7702, [CTR-UA-24](../../contracts/accounts.md#CTR-UA-24)), so
the one signed entry takes native ids. On Soroban the host already authorizes a native `Address` (`require_auth`) on the
direct entry, so the signed `ua_*` entry takes derived ids only, as built
([NET-SOR-20](../../networks/soroban.md#NET-SOR-20)); the mandate's entries are already one entry for both holder kinds
([NET-SOR-21](../../networks/soroban.md#NET-SOR-21)). Both satisfy the same row; neither family has two contract-verified
signed forms of one operation. NEAR and Algorand answer the row in their own UA rounds, each by its own mechanism.

## 2. The design

### 2.1 The entry

```solidity
// One entry per operation, on every token kind that has the operation (controller proposal: names and shapes of the spike).
function mtx<Op>(MetaTxLib.UAEnvelope calldata e, /* explicit op parameters, bytes32 ids */, IUARegistry.UASig calldata auth)
    external;
// Signed struct, unchanged from today's ua<Op>:
// UA<Op>(bytes32 from,<op params>,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)

// The transfer group (CTR-MTX-09) keeps today's flat ua* form, e.g. today's uaTransfer under the mtx name:
function mtxTransfer(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
    uint32 mode, address relayer, IUARegistry.UASig calldata auth) external returns (bool); // builds UAMetaTransfer
```

- **The body is today's `ua<Op>`**, with today's ABI; only the selector's name changes. That holds for the named ops of
  [CTR-MTX-28](../../contracts/metatx.md#CTR-MTX-28) (`UAEnvelope` first) and for the flat transfer group of
  [CTR-MTX-09](../../contracts/metatx.md#CTR-MTX-09) (`mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxPayMeta`), and
  `mtxRelayFee(bytes32 from, …, bytes32 payee, …)` is today's `uaRelayFee`. `mtxExecute(UAMetaTransaction m,
  bytes auth)` and `mtxBatch` are today's `uaExecute` / `uaBatch` (the generic path keeps `bytes auth`, as TS-D14 kept it);
  `mtxExecuteTransfer(UAMetaTransfer t, UASig auth)` and `mtxBatchTransfer(UAMetaTransfer[], UASig[])` are today's
  `uaExecuteTransfer` / `uaBatchTransfer`; `mtxCancelNonce(bytes32 ua, uint256 batch, uint256 validUntil, UASig auth)` takes
  `uaCancelNonce`'s form (no envelope, no fee, the used-digest set).
- **Subject dispatch, one test:** `UAKinds.inNativeSpace(from)` (`from >> 160 == 0`).
  - **Native id:** `_authorizeNative`: `0`, `UA_POOL`, `SHIELD_POOL` refused; HIP-632 on Hedera for a 64-byte signature by an
    account without code; else `SigCheck.isValid` (ECDSA low-s by the address's own key, an EIP-7702 designator by its own
    key only, ERC-1271 under the code-hash cap). **No registry call** [M-old: `vm.expectCall(reg, "", 0)`].
  - **Derived id:** `UARegistry.requireAuthorized(from, purpose, digest, auth)`. At `registry() == 0` it reverts
    `UALedgerOff` by name (spike C: the guard sits in the derived branch of `_authorize` and of `_checkTo` only).
  - **Controller proposal, R17:** a native id's `UASig` must have empty `keyData` and `members`, else
    `MetaTxBadSignature`. Today `_authorize` reads `auth.signature` alone, so a relayer can append junk; it moves nothing (the
    digest does not cover `UASig`), but after the merge it is every EOA's path, and failing closed costs a few bytes.
- **Receivers:** `_checkTo` takes both spaces: a native `to` is credited in the ERC-20 ledger, a derived `to` must be
  registered and SIGNING (one registry `kindOf` call). `mtxTransfer` from an EOA to a derived UA is new on the address side
  [M-old].
- **Ledger moves:** native sides through the ERC-20 ledger, derived sides through `_uaBalance`, every signed transfer through
  `_uaMove`. `_uaMove` calls `ERC20._update` directly and so skips `ERC20MetaTx._update`: a regulated hook (CTR-GOV-17,
  SPECIFIED) must hook `_uaMove` too, or it misses every relayed transfer (§8).
- **Allow-list of the generic entry:** a derived subject reads `_uaAllowed`; a native subject reads `_mtxRule`, so an EOA
  keeps `wrap`, `addReserve`, `wrapToUA`, `cancelNonce` through `mtxExecute` (spike B fix).
- **`_msgSender()`** inside the self-call: a native subject reads as its address, `UA_POOL` only for a derived one;
  unchanged.
- **Relayed proofs (Zether, PQZ):** the envelope binding of every relayed proof becomes the UA one, tag `TAG_UA_ENVELOPE`,
  native subjects included. The contract computes it; the provers bind it. No statement layout or relation changes (to be
  confirmed in the build, §8 risk 9).

### 2.2 Nonce space

Unchanged: one map `_uaNonce[bytes32][batch]`, natives zero-padded, already shared by both paths
([CTR-UA-26](../../contracts/accounts.md#CTR-UA-26)). A pay lane stays `payLane(payId)`, nonce 0. The view names follow the
entries: `mtxNonce(bytes32, uint256)` on tokens (today's `uaNonce`); the wallets keep `mtxNonce(address, uint256)`.
Domain unchanged: `("SCaaS MetaToken", "1", chainId, clone, salt = chainUid)`; the router's
`("SCaaS GovernanceRouter", "1", chainId, router, chain_uid)`.

### 2.3 Names (controller proposal)

- A pair keeps the non-`ua` name with the id form: `mtx<Op>`, and for the views and helpers that pair without the `mtx`
  prefix (`tradeOrderDigest` / `uaTradeOrderDigest`, `minNonce` / `uaMinNonce`, `envelopeBinding` / `uaEnvelopeBinding`,
  `receiverFeeDigest` / `uaReceiverFeeDigest`, `invalidateNoncesDigest` / `uaInvalidateNoncesDigest`, `restorePulled`) the
  plain name takes the id form.
- A `ua*` name with no address twin keeps its name (the registry's `uaAt`, `uaOf`, …; `uaCancelDigest`): no rename was asked.
- **Typed struct names keep the `UA` prefix** (`UAMetaTransfer`, `UA<Op>`, `UATradeOrder`): their type strings and typehashes
  do not change, so every UA-side vector row stays valid and only the address rows retire (Q3).
- Inside one contract kind every name has one meaning. Across kinds `mtxExecute` is `(UAMetaTransaction, bytes)` on a token
  and `(MetaTransaction, bytes)` on a wallet: the node's call table is per kind already ([NODE-JOB-20](../../node/job-api.md#NODE-JOB-20)).

### 2.4 Events

A merged path emits the `UA…` events with a `bytes32` subject: `UAMetaTransactionExecuted`, `UAPaymentSettled`,
`UATradeFilled`, `UAOrderCancelled`, `UANoncesInvalidated`, `UAReceiverFeePaid`, `UALegSettled`, `UATransfer` where a
derived side moves. A native ledger move still emits the ERC-20 `Transfer`. Address events stay where an address entry
stays: the wallets, the direct `payWithFee` (`PaymentSettled`), the DEX's outside legs (`LegSettled`). Controller proposal:
no second, address-typed event for a native subject on a merged path (one shape per path, fewer bytes); the indexer reads
the `UA…` topics for every relayed token operation (Q10).

### 2.5 What moves to `legacy/`

Backup, not delete (AGENTS.md):

| Where | Moves to `legacy/ua-mtx-merge/` |
|---|---|
| `smartcontracts/evm/src` | every address body of a merged pair, the address named-entry typehashes of tokens, `wrapBySig`, `_executeTransfer`, `_pay`, `_payMeta`, `_notPool`, `_tradeOf`, `preTransfer`, the address `requireSignature`; with A2 the token's address pipeline (`_execute`, `_named`, `_namedCall`, `_settle`, `preCall(false)`, `preNamed`, `envelopeBinding`) |
| `MetaTxBase` | split: the core stays; `mtxNonce`, `mtxDigest`, `mtxExecute`, `mtxBatch`, `mtxCancelNonce`, `executeMetaTransaction` (address forms) move to `MetaTxAddressBase` / `IMetaTxAddress`, inherited by `WalletExecute`; nothing is deleted |
| `GovernanceRouter` | the 19 `_mtxCall` address entries and their 19 typehashes (if Q4) |
| `MtxRelayFee` | `relay(address …)`; `uaRelay`'s body takes the name `relay` with `bytes32 from, payee` and a `UASig` (open mode unchanged) |
| vectors | the address rows of `vectors/typed/typed_ops.json`, `vectors/metatx/` transfer and pay rows, the DEX order KAT's SCaaS-leg rows, regenerated by their generators; old rows under each area's `legacy/ua-mtx-merge/` as typed-signing did |
| node, clients | the address builders of the merged entries, in each crate's or package's legacy place |

`MetaTxLib.MetaTransfer` keeps its pinned typehash where an outside leg or a wallet still reaches it; if nothing does in the
build, it moves with the bodies (decided in the build, by grep, recorded).

### 2.6 Options and the measured spike

Runtime bytes, stop line 64,500 B, on the old base. Gas: `transfer` / `mtxTransfer`, EOA to EOA, `WrappedPqzToken`.

| Option | What | `WrappedPqzToken` | `WrappedZetherToken` | `NormalToken` / `WrappedToken` / `NormalZetherToken` / `NormalPqzToken` | Gas |
|---|---|---:|---:|---|---|
| Base D1 + D2 | the old base | 65,520 [M-old] | 64,284 [M-old] | 40,575 / 50,166 / 55,974 / 56,088 | 49,840 / 87,343 |
| **A** | every pair merged, no-twin entries left on `Envelope` | 54,345 | 52,865 | 32,232 / 40,696 / 46,134 / 46,641 | not run |
| **A + B** | an EOA runs the merged path (allow-list and cancel fixes) | 54,247 | 52,767 | 31,872 / 40,336 / 46,036 / 46,543 | 49,807 / 88,441 |
| **A + B + C** | a registry only for a derived side | **54,254** | **52,774** | 31,879 / 40,343 / 46,043 / 46,550 | 49,807 / 88,218 (+875) |
| + **A2** | the no-twin entries (`mtxWrap`, `mtxWrapLeg`, `mtxWrapToUA`, `mtxAddReserve`, `mtxWrapShield`, `executeMetaTransaction`) on the one path; the token's address pipeline removed | 52,867 | 51,339 | 31,238 / 39,177 / 45,008 / 45,530 | 49,829 / 88,191 |
| + **D** | lever 3 by deletion: 47 views behind `fallback` (no module built) | 47,455 | 49,579 | 31,889 / 37,148 / 44,436 / 41,948 | not run |
| + A2 + D | both, scratch copy | 46,128 | 48,208 | 31,248 / 35,982 / 43,453 / 40,976 | not run |

All [M-old]. Other contracts on A + B + C: `SCaaSDex` 32,377 (+134 for C), `WrappedLib` 16,002, `MtxPipelineLib` 10,976,
`MtxRelayFee` 2,349 (−741), wallets unchanged. `WrappedPqzToken` 152 selectors from 188. EOA `mtxTransfer` +875 to +992 gas on
every kind (calldata: a 65-byte signature in a three-field `UASig`, 420 → 580 B [R]); the direct `transfer` −45 to +55
(dispatcher); EOA to a UA 108,919 (one `kindOf`, 5,873 cold). Not measured: generic `mtxExecute`, `mtxPayReceiverFee`,
`mtxTrade` through the DEX, `MetaTxGasV2`'s rows.

**Recommendation.**

- **A + B + C is the round's base.** B is required (without it an EOA loses `wrap`, `addReserve`, `wrapToUA`, `cancelNonce`
  on the generic entry); C is required (without it a `NORMAL` / `WRAPPED` token at `registry() == 0` has no relayed path for
  an EOA at all, and a derived `to` reverts with empty data instead of a named error).
- **A2: yes** (Q2). It makes "one entry per operation" true on tokens with no address pipeline left, so the audit reviews one
  path; it is the one change that removes a whole pipeline, −1.2 to −1.4 KB on the wrapped kinds [M-old]. Cost: it
  reverses the owner's 2026-11-01 ruling that keeps `executeMetaTransaction` on tokens with `address from`; the name stays
  as the alias of the merged `mtxExecute` (returns `bool`), and the address form stays on the wallets. If the owner keeps the
  address form on tokens, the round measures A2 without it (the pipeline stays for that one entry).
- **D: decided by §4's measurement**, not by default (Q5).

## 3. Composition

### 3.1 Governance (PR #9)

- **`GovernanceBase` entries are untouched.** An owner or holder operation has one direct entry and no `mtx*` / `ua*` twin on
  the governed contract (G19 of the governance spec; selector audit `selector_audit.json`). `_govSubject()` is unchanged: a
  direct caller is its native id; a call from `GOV_ROUTER` is the subject the router authenticated.
- **`GovernanceRouter` has 19 pairs** (`mtx<Op>` by `_mtxCall`, `ua<Op>` by `_uaCall`; 38 typed entries, 38 node rows). The
  owner's words cover every pair, and one rule per chain argues the same shape on the router as on tokens: **merge them**
  (Q4). `mtx<Op>` takes `UAEnvelope` + `UASig` and `_uaCall`'s flow; the subject an EOA produces is `pad(addr)`, exactly
  what `_mtxCall` writes today, so `_govSubject()` returns the same value and no governance check moves. A new init code
  means a new CREATE2 address: every release's `Env.govRouter` follows, the router is deployed before the releases as
  today.
- **Powers' entries** (`mint`, `mintToUA`, `disableWrap`, the rate entries, the DEX setters) are reached through the router
  only; no change on the governed contracts.
- **CTR-GOV-11 ("+0": no new read on a plain `transfer` and `mtxTransfer`)** holds on the probed kind [M-old: the same three
  slots, 8 reads, 3 writes]; `PlusZero.t.sol` re-targets its `mtxTransfer` and `uaExecuteTransfer` rows to the merged
  entries and is re-run on every kind.
- **CTR-GOV-19** stands: PQZ kinds on the raised ceiling only. A merged `WrappedPqzToken` may drop back under 65,536 B
  (projection §4), which removes it from `_above64KiB` but changes no rule.
- **Bit bands, `Grant`, the two-call delay, the regulated rules** do not change. A regulated implementation, when built,
  hooks `_uaMove` as well as `_update` (§2.1).

### 3.2 ML-DSA-87, Falcon-1024 and the other kinds

The merged entries authorize a derived subject through `requireAuthorized`, so every kind the registry verifies works as it
does on today's `ua*` entries: `mldsa87` where a precompile answers ([CTR-UA-39](../../contracts/accounts.md#CTR-UA-39)),
`fndsa1024` everywhere ([CTR-UA-40](../../contracts/accounts.md#CTR-UA-40)), `msig` with nested members, WebAuthn, the group
kinds. No kind, cap or vector of the registry changes. A PQ signature travels in `auth.signature` (4,627 B for ML-DSA-87);
the gas bounds of the registry's `verifyBudget` are unchanged.

### 3.3 PQZ and Zether

- The confidential pairs merge like the others: `mtxShield`, `mtxConfidentialTransfer*` (four forms; the compact single on
  the PQZ kinds only), `mtxUnshield`, `mtxUnshieldUnwrap`, `mtxRollOver`, `mtxRollOverBatch`, `mtxRollOverSigned`,
  `mtxSetRollOverMode`, `mtxPrepareAcc`, `mtxWrapShield` (A2).
- **Never lose ciphertext** holds: the operation bodies do not change; every ciphertext stays in contract state.
- Since CTR-ZTH-94 the signed and `ua*` Zether forms and their typehashes run in `ZetherLib` / `ZetherWrappedLib`. The
  merge edits those libraries too: the library-split checklist applies (DELEGATECALL storage, `this`, `msg.sender`, return
  data, the guard, `LinkClosure` pins). The spike predates the split, so its Zether savings are an upper bound (§4).
- Relayed proofs bind the UA envelope (`TAG_UA_ENVELOPE`) for every subject: `zether-prover`, the PQZ provers and
  `clientkeys` change at once (§7).
- PQZ: `script/pqz/at-set.sh` at all four sets for the build, not for the size spike.

### 3.4 DEX (`CTR-DEX-25`)

A SCaaS token leg is `UATradeOrder` only (shape 1), its signature in `auth`; the token's `mtxTrade` is today's `uaTrade`.
`TradeOrder` stays for outside legs (`DexOrder` nests it), with its vectors; `LegSettled` stays for outside legs, a SCaaS leg
emits `UALegSettled`. `orderHash` / `cancelHash` lose their `ua` flag on the token side; the DEX's `record`, `cancel`,
`invalidate` keep it for outside legs. The DEX asks for a ledger only for a derived seller (C, +134 B [M-old]). The DEX tests
did not compile in the spike: nothing here ran (§9).

### 3.5 Hedera

The same kinds with `IS_HEDERA`; `_authorizeNative` keeps HIP-632 (a 64-byte signature by an account without code).
`HederaMandateWallet` keeps the address surface. Not run in the spike; the build runs the Hedera suites and the node's Hedera
adapter.

## 4. Base token size for public chains

**Targets.** A token kind's implementation is deployed once per release, as one transaction. Under EIP-8037 it is included
only if regular + state gas fits the block limit; a block's `gas_used = max(...)` is accounting and proves nothing about
inclusion. About 1,601 to 1,606 gas per runtime byte in all, about 1,530 of it state gas, so a 60 M block holds about
37.3 KB of runtime and a 70 M block about 43.5 KB (`docs/contracts/zether.md`, CTR-ZTH-94 figures). Tokens are clones: only
the implementation and its libraries must fit, each its own transaction.

**Where the kinds stand.** PR #9's `size-baseline.json` (ratchet ceilings, not measurements) against the projection of the
spike's deltas [P]:

| Kind | Main | PR #9 | + A + B + C [P] | + A2 [P] | + A2 + D [P] | 60 M (37.3 KB) | 70 M (43.5 KB) |
|---|---:|---:|---:|---:|---:|---|---|
| `NormalToken` | 37,487 | 40,853 | ~32,160 | ~31,520 | ~31,530 | fits from A + B + C | fits |
| `WrappedToken` | 48,278 | 52,297 | ~42,470 | ~41,310 | ~38,110 | **no**, ~0.8 KB over even with A2 + D | fits from A + B + C, ~1 KB margin |
| `NormalZetherToken` | 47,470 | 50,547 | ~40,620 | ~39,580 | ~37,970 | no | fits from A + B + C |
| `WrappedZetherToken` | 58,407 | 62,472 | ~50,960 | ~49,530 | ~46,400 | no | no |
| `NormalPqzToken`, `WrappedPqzToken` | 53,042, 63,563 | 56,191, 72,160 | ~46,650, ~56,000 | | | not a target (CTR-GOV-19) | |

How the projection is made: PR #9's figure minus the spike's delta for that option on the same kind. It is rough: the
governance build differs from the prototype (+0.3 to +2.1 KB on the base kinds), the Zether bodies moved to libraries after
the spike (so the Zether deltas are upper bounds), and `WrappedPqzToken` crosses back under the 65,536 B cliff (about 4.7 KB
of jump widths, inferred). **None of these numbers decides anything; §9's do.**

**Levers in scope**, in the order the round measures them:

| Lever | What | Rules and cost |
|---|---|---|
| **M** = A + B + C | the merge | §5 rules; +0.9 to +1.0 K gas per EOA relayed transfer |
| **A2** | no-twin entries on the one path | Q2 |
| **L** | the `zether-lib` pattern on the base bodies: `ERC20MetaTx` and `UAMetaTxBase` bodies into a linked library, the decoders and the ABI stay on the token (as CTR-ZTH-94) | no ABI, storage or rule change; +1 to +2 K gas per signed call (Zether's figure, to measure); the library-split checklist; `LinkClosure` pins move with old → new; the library deploy must itself fit |
| **D** | lever 3: the read-only views behind a `fallback` to an immutable module pinned in `Env` | no ABI change seen from outside; a module per release, one `env.deps` entry, `libCodeHashes`, about 720 test call sites; a view +3 K gas, `eth_call` only; `hasRole`, `pendingOwner` and every view another contract reads on chain stay on the token |

Out of scope, with reason: an own ERC-20 core (−0.3 to −0.4 KB [M-old], CTR-UA-18 for the one-ledger form, an own core to
audit); B-26 (0 B on the wrapped kinds); narrowing `Grant` to `NORMAL*` and the DEX (CTR-GOV-02's fallback, a lost feature);
dropping named entries beyond the merge (rules, and the merge already removes the duplicates).

**How to decide (controller proposal, Q5 / Q6).**

1. Target: `NormalToken` and `WrappedToken` fit a **60 M** deploy, and so does a stand-in of their regulated form (one
   regulated implementation per kind: the six regulated entries and the hook, about +1.7 to 1.9 KB [P] in the size-options
   note's §10). 70 M alone is not enough: Ethereum's block is the lower one, and one rule holds on every chain.
2. The Zether kinds are measured against the same two thresholds and reported; whether they must fit before a public chain
   stays the owner's (CTR-GOV-19: "decided later").
3. Take M + A2, then measure L and D on main after PR #9, each alone and together. Pick the smallest set that meets 1;
   between two sets that both meet it, take the one with no hot-path gas cost (D before L), then the one with fewer new
   mechanisms.
4. **The deploy gate** (`runtime × 1,530 + 2^24`, GD-4 on PR #9) assumes the regular part at its 2^24 cap and so refuses
   above about 28.2 KB at 60 M and 34.8 KB at 70 M, where the real limit is about 37.3 and 43.5 KB. Before any public deploy
   it must count the measured regular gas of the deploy (a fork or local simulation), not the cap. A tool fix, no rule.

## 5. Rules: decisions for the owner

Each row: the rule as written, the proposed text or "holds", why, cost. R1 to R9 are the rulings TODO names; the rest follow
from the design.

| # | Rule | Proposal | Why | Cost |
|---|---|---|---|---|
| R1 | [CTR-MTX-09](../../contracts/metatx.md#CTR-MTX-09): the named transfer entries "keep their signatures (owner: kept separate, nothing merged)" | **Reversed.** "`mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxPayMeta`, `mtxBatch`, `mtxBatchTransfer` take the form of today's `ua*` twin (the same flat explicit parameters with `bytes32` ids, `UASig` / `bytes auth`) and build `UAMetaTransfer` / `UAMetaTransaction`; one form per operation (owner 2026-11-03, the `ua*` / `mtx*` merge)." The mode shapes and the equivalences stay, on the UA structs | the owner's merge; a pair is one feature twice | the 2026-10-08 ruling "nothing merged" is reversed; every caller of the address forms moves |
| R2 | [CTR-MTX-15](../../contracts/metatx.md#CTR-MTX-15): "Two structs, one nonce space"; `MetaTransfer` "exists on tokens only" | Tokens: `UAMetaTransaction` and `UAMetaTransfer`, one nonce space (unchanged). `MetaTransaction` stays on the wallets. `MetaTransfer` has no token entry | follows R1 | wallets that displayed `MetaTransfer` field by field now see `UAMetaTransfer` (§6) |
| R3 | [CTR-MTX-17](../../contracts/metatx.md#CTR-MTX-17) and [CTR-MTX-22](../../contracts/metatx.md#CTR-MTX-22): `executeMetaTransaction` stays beside `mtxExecute`, `address from` | With A2: on tokens `executeMetaTransaction` is the `bool` alias of the merged `mtxExecute(UAMetaTransaction, bytes)`; the address form stays on the wallets in `MetaTxAddressBase`. Without A2: holds | one path on tokens; −1.2 to −1.4 KB with the wraps [M-old] | reverses the 2026-11-01 "stays" on tokens; an outside tool that decodes the address struct on a token breaks |
| R4 | [CTR-MTX-23](../../contracts/metatx.md#CTR-MTX-23), [CTR-MTX-24](../../contracts/metatx.md#CTR-MTX-24): `mtxExecuteTransfer(MetaTransfer, bytes)`, `mtxBatchTransfer(MetaTransfer[], bytes[])` | `mtxExecuteTransfer(UAMetaTransfer, UASig)`, `mtxBatchTransfer(UAMetaTransfer[], UASig[])`; the steps stay, step 3 becomes the UA receiver rule (a derived `to` registered and SIGNING) | follows R1 | events become `UA…` (R18) |
| R5 | [CTR-MTX-28](../../contracts/metatx.md#CTR-MTX-28) (TS-D14): `mtx<Op>(Envelope, …, bytes sig)` and, where UA-allowed, `ua<Op>(UAEnvelope, …, UASig)` | "`mtx<Op>(MetaTxLib.UAEnvelope e, <explicit op parameters>, IUARegistry.UASig auth)`, struct `UA<Op>`; one form" on tokens and the router; the wallets keep `Envelope` + `bytes` (or `AccountSig`). Its "Size" bullet is rewritten to §4's targets | every field stays named and typed (CTR-MTX-29 holds) | `from` is `bytes32` on screen |
| R6 | [CTR-MTX-14](../../contracts/metatx.md#CTR-MTX-14): EIP-712 typed data, "wallets display the fields" | **Holds.** Still typed data, every field named, no blind hash; the `address` type of `from` / `to` goes on token paths | — | §6 |
| R7 | [CTR-UA-26](../../contracts/accounts.md#CTR-UA-26): "The UA path splits like the address path"; "The `ua*` functions keep their signatures"; `uaExecuteTransfer` mirrors `mtxExecuteTransfer` | "The signed path has two structs, a generic `UAMetaTransaction` and a typed `UAMetaTransfer`, under the `mtx*` names; they take native and derived ids." The mirror sentence goes | nothing left to mirror | none beyond R1 |
| R8 | [CTR-UA-27](../../contracts/accounts.md#CTR-UA-27): parity; "Own struct, any id … it takes a native id too" | **Holds by construction**: this text is the merged path. "the `ua*` functions" reads "the signed entries"; "Named UA builders exist only where the address path has one" goes | parity stops being two forms | — |
| R9 | [CTR-UA-19](../../contracts/accounts.md#CTR-UA-19): the UA-ledger meta-transactions have their own structs; registry 0 = "every `ua*` reverts `UALedgerOff`" | The UA structs are the token's only signed structs. **`registry() == 0`: a derived side reverts `UALedgerOff`; a call whose every side is native runs** (spike C) | an EOA keeps a relayed path on a plain token without a registry | `supportsInterface(IUALedger)` stays false at 0, so `IUALedger` splits (entries vs. ledger views) |
| R10 | [CTR-UA-18](../../contracts/accounts.md#CTR-UA-18): derived balances in a separate `bytes32` ledger | **Holds.** No balance moves | — | — |
| R11 | [CTR-UA-24](../../contracts/accounts.md#CTR-UA-24): own key only, never the delegate | **Holds** [M-old] | — | — |
| R12 | [CTR-DEX-25](../../contracts/dex.md#CTR-DEX-25): "`TradeOrder` and its vectors do not change. A native id may sign it too" | "A SCaaS token leg is a `UATradeOrder`, native or derived; `TradeOrder` and its vectors stay for outside legs." [CTR-DEX-15](../../contracts/dex.md#CTR-DEX-15) shape 0 on a SCaaS token goes | follows R1 | the DEX KAT regenerates; 30 DEX test files move to shape 1 |
| R13 | CTR-GOV-11 (PR #9): "+0" = no new read on `transfer` and `mtxTransfer` | **Holds**; the pins re-target the merged entries | — | gas pins move with old → new |
| R14 | Governance spec G19 and CTR-GOV-15's router: 19 ops, each `mtx<Op>` and `ua<Op>` | The router's pairs merge (Q4): 19 entries, `UAEnvelope` + `UASig`; G19 holds on the governed contracts | one rule for every signed entry | new router address per chain; node rows 38 → 19 |
| R15 | AGENTS.md "one rule on every chain"; [NET-ALL-84](../../networks/README.md#NET-ALL-84) | New checklist row: "per operation, the direct entry and at most one contract-verified signed entry, its subject a UA id covering both spaces; a native uses it where the host does not authorize it for a call someone else submits" (§1) | the EVM merge and Soroban's built split are the same rule | each family's UA spec answers one more row |
| R16 | AGENTS.md "Backup, do not delete" | **Holds**: §2.5 | — | — |
| R17 | new (controller proposal) | A native id's `UASig` has empty `keyData` and `members`, else `MetaTxBadSignature` | fail closed on every EOA path; no relayer padding | a few bytes per entry |
| R18 | CTR-UA-27 "Events": an address-typed event keeps its shape, a UA party gets a `UA…` event | A merged path emits the `UA…` events only; address events stay on address entries (§2.4) | one event shape per path | indexers and the node read new topics for EOAs |
| R19 | `mtxCancelNonce` (address form: envelope, fee, relayer binding) | Takes `uaCancelNonce`'s form: no envelope, no fee, each signed cancel runs once (used-digest set). A native that wants a fee or a bound relayer uses `cancelNonce` through `mtxExecute` | one form; a cancel needs no binding (a front-runner can only run the same cancel) | the token fee on a signed cancel goes |

## 6. Wallet and EIP-712 display

Today an EOA's wallet shows `MetaTransfer(address from, address to, uint256 value, …)`. After the merge it shows
`UAMetaTransfer(bytes32 from, bytes32 to, uint256 value, …)` and, for a named op, `UA<Op>(bytes32 from, …)`. The operation,
amounts, lanes, deadline, fee, relayer and fee recipient stay on screen, named; `relayer` and `feeRecipient` stay `address`.
`from` and `to` become 32-byte words with 12 leading zero bytes for a native.

What is lost: a wallet treats an `address` field as an address (checksum, address book, warnings on known bad addresses) and a
`bytes32` as hex. That is an expectation; **no wallet was tested**. It is the one cost the bytes cannot pay back.

- **Our clients** (`clientkeys`, every `ua-*`) show a native id as its checksummed address (top 96 bits zero) and a derived id
  as its `urn:scaas:ua:v1:<kind name>:<hex32>` before the user signs; the typed data itself does not change.
- **A test wallet is needed** (Q7, controller proposal): before reset 2, sign the regenerated `UAMetaTransfer` and one
  `UA<Op>` row of `typed_ops.json` in two widely used browser wallets and one hardware wallet, and record what each shows
  (a text note in `docs/research/`, screenshots local). Whether a clear-signing descriptor can render a `bytes32` as an
  address is not checked.
- The primary type name keeps the `UA` prefix (Q3), so the wallet's title reads `UAMetaTransfer` for an EOA too.

## 7. Blast radius

Counts from main `783bacee` by grep [R], plus PR #9; recounted at the build.

| Area | What changes |
|---|---|
| Contracts | the six token kinds, `MetaTokenBase`, `ERC20MetaTx`, `UAMetaTxBase`, `MetaTxBase` (split), `MtxPipelineLib`, `WrappedLib`, `TradeLib`, `ZetherLib`, `ZetherWrappedLib`, the PQZ layer and `PqzWrappedLib`, `MtxRelayFee`, `SCaaSDex` and `DexPuller`, `GovernanceRouterBase` / `GovernanceRouter` (Q4); interfaces `IERC20MetaTx`, `IMetaTx`, `IUALedger` (split), `ITradeToken`, `IZetherToken`, `IPqzToken`, `IConfidentialToken`, `IWrappedToken`, `IMetaTokenV2`: new interface ids; `HederaMandateWallet`, `MandateWallet`, `SmartKeyAccount` byte-identical (re-checked) |
| Node | `abi.rs`, `guard.rs` (`CALL_TABLE`, both directions against `mtxSelectors` and `_uaAllowed`), `typed.rs`, `submit.rs`, `gateway.rs`, `metatx.rs`, `indexer.rs`, `chain.rs`, `dex/venue.rs`, `adapters/hedera.rs`, the legacy pull path module; the router rows (`gov_router`). The EVM `ua_metatx` precondition `registry() ≠ 0` becomes "only for a derived side" |
| Job shape | Controller proposal (Q8): every merged EVM entry is a `ua_metatx` job (its shape already carries `from` as bytes32 and `auth` as `UASig`; `entry` names the `mtx*` name); `metatx` stays for the wallets' address entries; a `metatx` job or a `struct: "transfer"` job naming a token's merged entry is refused by name. **Operator note** with the release: EVM clients of the address token forms must move to `ua_metatx`; a job of the old shape is refused, never silently `dead` |
| Events | §2.4: new topics for EOA relayed operations; the indexer maps them; `pay_ref` lookups read `UAPaymentSettled` for EOAs |
| Clients | `clientkeys` (about 50 files touch the forms), `ua-cxx` (9), `ua-dart` (6), `ua-dart-frb` (5), `ua-qt` (3), `ua-go` (1), `zether-prover` (3, `src/typed.rs`, the envelope tag), the PQZ provers' binding; [R] grep counts |
| Vectors | `vectors/typed/typed_ops.json` (74 rows on main, 25 of them `UA*`; 112 on PR #9, 44 `UA*`): the address rows of merged ops retire, the `UA*` rows stay byte-identical under Q3; `vectors/ua/metatx3.json`, `uatrade_kat.json` unchanged under Q3; the `vectors/metatx/` transfer, pay and relay rows, the DEX order KAT and `selector_audit.json` regenerate |
| Docs | `metatx.md` (CTR-MTX-09, -15, -17, -22, -23, -24, -28), `accounts.md` (CTR-UA-19, -26, -27), `dex.md` (CTR-DEX-15, -25), `zether.md` and `pq-zero-knowledge.md` (entry names), `token-wrappers.md`, `networks/README.md` (R15), `node/job-api.md`, `integration.md`, `decisions.md` entries for R1-R19 as ruled |
| Tests | on the old base 86 test files, 6 helpers and 1 script did not compile, 1,383 of 2,142 tests [M-old]; by class: call shape (most, mechanical, carried by six helpers), address events (19 files), DEX leg shape (30), meaning reversed (at least 7: a native at `registry() == 0`, a native `mtxCancelNonce`, a native off the UA list), gas or size pins (33), typehash or interface pins (5), parity tests that lose their point (`MetaTxParity`). Recount on main after PR #9 |

## 8. Risks and the invariants to keep

**Invariants** (each a test that can fail, shown by a mutant as the spike's eight):

1. **No forgery.** A merged entry runs only for a subject that signed its typed digest: a derived id through
   `requireAuthorized(from, purpose, digest, auth)`, a native id by its own key (ECDSA low-s, ERC-1271 under the cap, HIP-632
   on Hedera), an EIP-7702 designator by its own key only.
2. **A relayer cannot alter.** The digest covers every operation parameter and every envelope word; `relayer` and
   `feeRecipient` hash as 0 when unbound (`MetaTxLib.canon`); `UASig` is not signed, so for a derived id the registry checks
   `keyData` / `members` against the record and for a native id R17 refuses anything but `signature`.
3. **Replay domains.** The domain names the contract, the chain and `chainUid`; one typehash per operation; one lane
   `(from, batch)` per id with natives padded; old address-form signatures cannot run (their typehashes and entries are gone);
   the router signs `target`; a signed cancel is spent by its digest.
4. **Relayable at fee 0.** Every merged entry accepts fee mode `NONE`, on every kind, with or without a registry for a native
   subject.
5. **All or nothing**, the call before its fee, as [CTR-MTX-16](../../contracts/metatx.md#CTR-MTX-16).
6. **Never lose ciphertext**; no new read on a plain transfer (CTR-GOV-11); storage layout pinned; `_msgSender()` is
   `UA_POOL` only for a derived subject.

**Risks** (spike §7, then new):

1. Every EOA path becomes the path native ids used least: review the merged bodies as new code.
2. `_uaMove` is the only hot move of signed transfers; a regulated hook only in `_update` misses every relayed transfer.
3. A native `UASig`'s ignored fields (closed by R17 if taken).
4. The DEX's refusal list (`_interact` refuses `ITradeToken.mtxTrade.selector`): with old-release tokens on one chain, old
   selectors and the old order shape would need a place. Nothing is live with value; at mainnet this returns.
5. `mtxCancelNonce` without envelope (R19).
6. `mtxTransfer` from an EOA now reaches a derived `to`: the receiver rule is the UA path's.
7. **The numbers move.** The spike's base is not PR #9's; the Zether savings are upper bounds after CTR-ZTH-94; `WrappedToken`
   may still miss 60 M after M + A2 + D (§4).
8. **Library splits** (`ZetherLib`, and L if taken): DELEGATECALL storage, `this`, `msg.sender`, return data, the guard,
   `LinkClosure` pins; the class of each fix checked in every library.
9. **Relayed proofs.** The EOA binding moves to `TAG_UA_ENVELOPE`: a client that binds with the address tag yields a proof the
   contract refuses. Confirm in the build that only the binding value changes, not a statement layout or relation; if a
   layout changes, that is a new `proofSystemId`, new vectors in every client and a full gate.
10. **New router address** (Q4): every release's `Env.govRouter` and the node's `governance_routers` change together.
11. **Interface ids** change; `mtxWrapOrder`'s ERC-165 check of a leg and the DEX's ledger check must ask the right
    interface after the `IUALedger` split.
12. **Test repairs can hide a change of meaning**: the "meaning reversed" class is reviewed by hand, not repaired by script.
13. **Wallet display** (§6).
14. **Hedera** was not run in the spike.
15. **EOA gas** +0.9 to +1.0 K per relayed transfer, calldata; higher where calldata costs more, on every chain alike.

## 9. Measurement plan after PR #9

Nothing runs before PR #9 merges (owner 2026-11-04). Then, on a branch from main, through `scripts/capped`, foreground:

1. **Port the harness** of the spike (`merge_pairs.py`, `no_twin.py`, `lever3_delete.py`, `mutants.py`, `red_skip.py`, and the
   `test/merge` set) into `smartcontracts/evm/runs/<date>-ua-mtx-merge/` (kept, git-tracked: research harness and results stay
   in the repo; full logs local, one summary committed).
2. **Sizes** (`forge build src --sizes --json`, default set `n2304-kmax4096`): every kind, `SCaaSDex`, `GovernanceRouter`,
   `MtxRelayFee`, `MtxPipelineLib`, `WrappedLib`, `ZetherLib`, `ZetherWrappedLib`, `PqzWrappedLib`, the wallets, for: base;
   M; M + A2 (with and without `executeMetaTransaction`'s address form); M + A2 + D; M + A2 + L; M + A2 + L + D; and the
   regulated stand-in on `NormalToken` and `WrappedToken`.
3. **Deploy gas**, regular + state, per implementation and library, each its own transaction (the method of
   `ZetherDeploy.t.sol`), against 60 M and 70 M.
4. **Gas** (forge, deterministic; no timing, no calibration): `GovGas` rows, `MetaTxGasV2` rows, `PlusZero` slots on every
   kind, EOA → EOA and EOA → UA, and what the spike did not run: generic `mtxExecute`, `mtxPayReceiverFee`, `mtxTrade` through
   the DEX, a Zether and a PQZ relayed op.
5. **Tests**: the recount of §7 on the merged tree; `test/merge` and the eight mutants, plus a Hedera case and a router case.

**What decides:** step 3 against §4's rule 1 picks the lever set; step 2 shows whether `WrappedPqzToken` leaves
`_above64KiB`; step 4 is reported with old → new, it decides only if a lever's hot-path cost is out of line. Results go into
this spec as a dated table and into the research note's re-measure line.

## 10. Open questions for the owner

| # | Question | Recommendation |
|---|---|---|
| Q1 | Accept the merge on A + B + C and the rulings R1, R2, R4, R5, R7, R9, R12 (CTR-MTX-09 reversed) | Yes: it is the owner's direction, it needs no registry for an EOA, and B and C are what make it work |
| Q2 | A2: the five wrap entries and `executeMetaTransaction` on the one path on tokens (R3) | Yes; `executeMetaTransaction` stays as the alias name on tokens and in its address form on the wallets |
| Q3 | Keep the `UA` prefix on typed struct names (`UAMetaTransfer`, `UA<Op>`) | Yes: no UA-side vector or client digest changes; a rename to `MetaTransfer(bytes32 …)` buys a title on screen for a full regeneration |
| Q4 | Merge the `GovernanceRouter`'s 19 pairs (R14) | Yes: one rule for every signed entry; G19 is untouched |
| Q5 | Lever 3 (D) and the library pattern (L): in this round, chosen by §4's rule | Yes, measured after PR #9; take the smallest set that meets the target |
| Q6 | Target: `NormalToken`, `WrappedToken` and their regulated stand-ins fit a 60 M deploy; the Zether kinds reported, decided later | Yes |
| Q7 | A test of the display in real wallets before reset 2 (§6) | Yes, small and manual |
| Q8 | Node: every merged EVM entry is a `ua_metatx` job; `metatx` for the wallets; old shapes refused by name | Yes: the shape exists; only the entry names change |
| Q9 | R17: a native `UASig` with non-empty `keyData` or `members` is refused | Yes |
| Q10 | R18: `UA…` events only on merged paths | Yes |
| Q11 | R15: the one-rule row in NET-ALL-84 | Yes |
| Q12 | Review of this spec before acceptance: it reverses owner rules and touches every signed path | One adversarial review by one other model (Codex or agy, owner's choice of credits) on §2, §5 and §8 before acceptance; the full multi-model review stays with the contracts audit after the round |
| Q13 | Branches `token-merge` and `token-core` | Keep as reference, never merged; the harness is ported (§9) |

## 11. Testnet: between reset 1 and reset 2

- **Reset 1** (after `GovernanceBase` lands; chainspec without EIP-7954, `maxCodeSize` `0x20000`): loads PR #9 and PR #10 with
  today's two forms. Clients and node built for it use the address forms.
- **This round** builds and tests locally only; nothing touches the live testnet stack.
- **Reset 2** (after this round merges): without a backup, as ruled; every kind, `DEPLOY_ZETHER=1`, the new `MtxRelayFee` and
  `GovernanceRouter` addresses, the PQZ / Zether e2e with an EOA relaying a proof under the UA binding, an EOA `mtxTransfer` to
  an EOA and to a UA, a router op signed by an EOA, Blockscout re-verification. Signatures made against reset 1's contracts do
  not run on reset 2 (new typehashes, new selectors, new addresses).
- The size targets of §4 are not tested on the testnet (its ceiling is 128 KiB and its block 200 M); they are decided by §9's
  deploy-gas measurement on a local chain.
- The contracts audit (work-order item 7) targets `main` after this round.
