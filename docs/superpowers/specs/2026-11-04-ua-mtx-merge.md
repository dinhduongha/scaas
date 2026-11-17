# `ua*` / `mtx*` merge: one signed entry per operation, and the base token size for public chains — design

**Status:** ACCEPTED by the owner 2026-11-04 (Q1–Q7); Q3's final lever choice after the §9 measurement; numbers to re-measure. Reviewed by Claude (4 lenses), Fable, Codex. Nothing is built. Recorded as [CTR-MTX-30](../../contracts/metatx.md#CTR-MTX-30) (SPECIFIED); the answers are in §10. **Owner 2026-11-04, after T0 (§9.1): build M first; the lever (D, with L only if needed) is decided by the owner after M's PR.** **Owner 2026-11-04, after T1: Q6 changed: the mandate wallets `MandateWallet` and `HederaMandateWallet` are built in this round in the merged form (§2.7); `SmartKeyAccount` stays as it is.**
Work-order item 3 of TODO (owner 2026-11-03), its own round between SCaaS testnet reset 1 and reset 2. Owner 2026-11-04:
the spec now, the measurement after PR #9 (governance) merges; PR #9 is merged into this branch (`d97f5a39`). Revised
2026-11-04 after a Claude workflow review, then after Fable's counter-review and Codex's security review (§12).

The spike behind it is [research/governance/prototype/merge-entries.md](../../research/governance/prototype/merge-entries.md)
(branch `token-merge`, not to be merged); the earlier size options are `docs/research/governance/prototype/size-options.md` on
branch `token-core` (not to be merged). The rules it changes are listed in §5 with their docs; the governance rules
(`CTR-GOV-*`), the router and the governance text of NET-EVM-06 are on branch `governance` (PR #9) and are cited by id only
until it merges.

**Tags.** **[M-old]** measured by the spike on the governance prototype D1 + D2 (`6e09e008`), before the governance build,
the `ZetherLib` split (CTR-ZTH-94) and ML-DSA-87 / Falcon-1024; **[R]** read from code, not run; **[P]** projection, a sum
of measured deltas on another base; **[M]** measured on the base named. **Every figure in this file is re-measured after
PR #9 (§9)**; none of it is a pin. Rows marked **controller** are decided by the controller, each with its reason, and the
owner may override them; §10 lists the seven questions only the owner decides. Everything cryptographic stays `UNAUDITED`.

## 0. Summary and the owner's words

**The owner, 2026-11-03** (as recorded in the spike and TODO): for every pair of `ua*` + `mtx*` entries, keep the `ua*`
implementation and give it the `mtx*` name; the old `mtx*` implementation goes, because the pair is one feature written
twice. The wallets keep the address surface. It is its own round, after the governance build, between the two SCaaS
testnet resets, and it carries the base token size for public chains (TODO: "Pick the smallest set that fits 60 M and
70 M"). **The owner, 2026-11-04 (Q6 changed):** "the wallets keep the address surface" now means `SmartKeyAccount` only;
the mandate wallets `MandateWallet` and `HederaMandateWallet` take the merged form in this round (§2.7).

**What this spec proposes, in one paragraph.** Every relayed, subject-signed operation of a SCaaS EVM token kind (and of
`MtxRelayFee`, the DEX's SCaaS legs and `GovernanceRouter`) that has a `ua*` / `mtx*` pair keeps **one** entry, named
`mtx<Op>`, with the ABI of today's `ua<Op>` (`MetaTxLib.UAEnvelope e, <explicit op parameters>, IUARegistry.UASig auth` for a
named op; the flat explicit form with `bytes32 from` for the transfer group) and signing the typed struct `UA<Op>` with a
`bytes32 from`. Two departures, both put to the owner: the cancel pair keeps the ordered `mtxCancelNonce` body, widened to
`bytes32` (§2.1, Q2), and the generic entries take `UASig` instead of `bytes auth` (R47). A native address is its zero-padded id and signs with its own key in `auth.signature`, with **no registry
call**; a derived UA is authorized by `UARegistry.requireAuthorized`. A registry is needed only by a derived side, so
`NORMAL` and `WRAPPED` at `registry() == 0` keep a relayed path for EOAs. The mandate wallets (`MandateWallet`,
`HederaMandateWallet`) take the same merged form, one `mtx<Op>` per wallet operation over `UAEnvelope` with `bytes32` ids
and `UASig` (owner 2026-11-04, Q6, §2.7); `SmartKeyAccount` keeps `MetaTransaction` and its address entries. Direct entries
(`transfer`, `approve`, `wrap`, `payWithFee`, the governance entries, …) do not change. The address bodies move to
`legacy/`. On the old base the merge freed 8.7 to 11.5 KB per kind [M-old]; it does not alone bring `WrappedToken` under a
60 M deploy, so §4 sets how the round picks further levers.

**Recommendations, short:** the base is A + B + C (§2.6). `executeMetaTransaction` stays on tokens as the owner ruled on
2026-11-01 (R3, not reopened); the five no-twin wrap entries are not pairs and stay as they are (controller). The router's
19 pairs merge like every pair (controller: the owner's words). The signed cancel is the ordered form (Q2). Measure lever 3
(D, with its §8 invariants) and the library pattern (L) after PR #9 and take the smallest set that makes `NormalToken`,
`WrappedToken` and their regulated stand-ins fit the owner's 60 M and 70 M under the deploy's real gas ask, total × 1.05
(Q3, Q4).

## 1. Goal and non-goals

**Goal.**

1. One subject-signed relayed entry per operation on the six EVM token kinds (`NormalToken`, `WrappedToken`,
   `NormalZetherToken`, `WrappedZetherToken`, `NormalPqzToken`, `WrappedPqzToken`), on Hedera through the same kinds,
   on `MtxRelayFee`, on the DEX's SCaaS legs and on `GovernanceRouter`: the `ua*` body under the `mtx*` name (the cancel
   pair per Q2). The one exception the owner has ruled is `executeMetaTransaction` (R3). On the mandate wallets
   `MandateWallet` and `HederaMandateWallet`, which have no `ua*` twin, the address bodies widened to `bytes32` ids take
   that form (owner 2026-11-04, Q6, §2.7).
2. Every operation stays relayable at fee 0 (fee mode `NONE`) through a merged entry, on a chain with or without a UA
   registry for a native subject (§8 invariant 4 lists the entries whose point is a fee).
3. The base token kinds fit a public chain's block for their implementation deploy: `NormalToken` and `WrappedToken` under
   the EIP-8037 inclusion rule at the owner's 60 M and 70 M (TODO, owner 2026-11-03: "Pick the smallest set that fits 60 M
   and 70 M"), counted as the gas the deploy transaction asks; the Zether kinds measured against the same thresholds (§4).

**Non-goals.**

- **`SmartKeyAccount`.** Keeps `MetaTransaction`, `mtxExecute`, `mtxBatch`, `mtxNonce`, `mtxDigest`, `mtxCancelNonce`,
  `executeMetaTransaction` and its own named entries (`AccountSig`), all with `address from` (owner): no registry, no
  `ua*` twin, byte-identical. The mandate wallets are no longer a non-goal: the owner changed Q6 on 2026-11-04 (§2.7,
  R32); [CTR-ACC-12](../../contracts/mandates.md#CTR-ACC-12)'s planned twins are not built.
- **Direct entries.** `transfer`, `transferFrom`, `approve`, `transferToUA`, `payWithFee`, `payWithFeeToUA`, `wrap*`,
  `unwrap*`, `addReserve`, `cancelNonce`, the direct confidential ops, every `GovernanceBase` entry and every power's own
  entry stay as they are.
- **Ledgers.** No balance moves: derived balances stay in the separate `bytes32` ledger, natives in the ERC-20 ledger
  ([CTR-UA-18](../../contracts/accounts.md#CTR-UA-18) holds). No storage slot moves (layout pins hold).
- **Registry, kinds, proofs.** `UARegistry`'s code, the kinds (ML-DSA-87 `0x0134` and Falcon-1024 `0x0135` included), the
  Zether statements, transcripts and `proofSystemId`s do not change, nor do the PQZ ones. One qualification: `UARegistryLib`
  compiles `PqzSet.PQZ_DEBIT_MIN_GAS`, which is measured on the relay path this round rewrites; if the owner moves that set
  parameter (R41), the registry's bytecode changes with it.
- **PQZ kinds on public chains.** Not a target: they run only where the PQZ precompile is, on an operator-controlled chain
  (CTR-GOV-19).
- **Other families' code.** No non-EVM contract changes in this round; the rule below binds their own rounds.
- **Migration.** None: every chain is test-only; the SCaaS testnet takes the new contracts at reset 2.

**One rule on every chain.** The merged form is the EVM expression of a rule every family can state the same way. It is
proposed once, in [NET-ALL-28](../../networks/README.md#NET-ALL-28) (R31), and the family checklist
[NET-ALL-84](../../networks/README.md#NET-ALL-84) only asks it (R15): *per operation, a contract has its direct entry (the
chain's own caller) and at most one contract-verified signed entry. That entry takes every subject the chain's host cannot
authorize for a call someone else submits, and a native subject signs it with its own key. On EVM a token also keeps the
EIP-1776 alias `executeMetaTransaction` beside the generic `mtxExecute` (owner ruling 2026-11-01).* The exception is
written into the rule, so the rule matches the code the round ships (Fable M3). The five no-twin wrap entries keep
`Envelope` with `address from`, but each is still the one signed entry of its operation, so the per-operation rule holds
for them. On EVM no host path exists for an EOA (no EIP-7702, [CTR-UA-24](../../contracts/accounts.md#CTR-UA-24)), so the one signed entry takes native and derived
ids. On Soroban the host already authorizes a native `Address` (`require_auth`) on the direct entry, so the signed `ua_*`
entry takes derived ids only, as built ([NET-SOR-20](../../networks/soroban.md#NET-SOR-20)); the mandate's entries are
already one entry for both holder kinds ([NET-SOR-21](../../networks/soroban.md#NET-SOR-21)). Both satisfy the same row;
neither family has two contract-verified signed forms of one operation. NEAR and Algorand answer the row in their own UA
rounds, each by its own mechanism.

## 2. The design

### 2.1 The entry

```solidity
// One entry per operation, on every token kind that has the operation (controller: names and shapes of the spike).
function mtx<Op>(MetaTxLib.UAEnvelope calldata e, /* explicit op parameters, bytes32 ids */, IUARegistry.UASig calldata auth)
    external;
// Signed struct, unchanged from today's ua<Op>:
// UA<Op>(bytes32 from,<op params>,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)

// The transfer group (CTR-MTX-09) keeps today's flat ua* form, e.g. today's uaTransfer under the mtx name:
function mtxTransfer(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
    uint32 mode, address relayer, IUARegistry.UASig calldata auth) external returns (bool); // builds UAMetaTransfer
```

- **The body is today's `ua<Op>`**, with today's ABI; only the selector's name changes (two exceptions: R47's three
  entries `mtxExecute`, `mtxBatch`, `mtxShield` take `UASig`, and the cancel, below). That holds for the named ops of
  [CTR-MTX-28](../../contracts/metatx.md#CTR-MTX-28) (`UAEnvelope` first) and for the flat transfer group of
  [CTR-MTX-09](../../contracts/metatx.md#CTR-MTX-09) (`mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxPayMeta`), and
  `mtxRelayFee(bytes32 from, …, bytes32 payee, …)` is today's `uaRelayFee`. `mtxExecute(UAMetaTransaction m, UASig auth)`,
  `mtxBatch(UAMetaTransaction[] ms, UASig[] auths)` and `mtxShield(…, UASig auth)` are today's `uaExecute` / `uaBatch` /
  `uaShield` with `UASig` in place of `bytes auth` (R47: explicit parameters, a derived subject's `bytes auth` is a packed
  `UASig`); `mtxExecuteTransfer(UAMetaTransfer t, UASig auth)` and `mtxBatchTransfer(UAMetaTransfer[], UASig[])` are
  today's `uaExecuteTransfer` / `uaBatchTransfer`.
- **The cancel pair is the one pair whose kept body is the `mtx*` one, widened to `bytes32` (Q2).** Today's `uaCancelNonce`
  cannot serve a native (it refuses a native-space id and calls the registry directly, `UAMetaTxBase.sol:95-106`) and binds
  no nonce, so after the merge every EOA's named cancel would be unordered. The merged entry is
  `mtxCancelNonce(MetaTxLib.UAEnvelope e, uint256 lane, IUARegistry.UASig auth)`, struct
  `UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)`
  (CTR-MTX-28's shape, today's address `CancelNonce` with `bytes32 from`), run through `MtxPipelineLib.preNamedUA` like every
  named op: nonce-ordered on its own lane `e.batch`, relayer-bound when the mode says so, fee 0 or more, native and derived
  alike. The body bumps `lane` for `e.from` itself and emits `UANonceCancelled(bytes32, …)`; it does **not** self-call
  `cancelNonce`, because inside the self-call a derived subject reads as `UA_POOL` and `cancelNonce` refuses it
  (`MetaTxBase.sol:120-123`). The struct keeps the name `UACancelNonce` (CTR-MTX-28's `UA<Op>` rule) with a new type string,
  so its one `typed_ops.json` row changes. The unordered `uaCancelNonce`, `uaCancelDigest` and the old `UACancelNonce(bytes32
  ua,uint256 batch,uint256 validUntil)` go to `legacy/`; the `cancelUsed` mapping stays in `UALedgerStorage`, unused, since the
  storage layout is pinned. The direct `cancelNonce(uint256)` stays as it is (a native caller; through the generic
  `mtxExecute` for a native subject by `_mtxRule`, as today).
- **No-twin entries (controller: not moved).** `mtxWrap`, `mtxWrapLeg`, `mtxWrapToUA`, `mtxAddReserve`, `mtxWrapShield` have
  no `ua*` twin and stay on `Envelope` + `bytes sig` with `address from`. The owner's rule covers pairs; each of these is
  already the one signed entry of its operation, and they are native-only by nature (a wrap pulls the underlying ERC-20
  from an address; a derived id has none). Moving them would add five structs that no derived signer can use.
- **Subject dispatch, one test:** `UAKinds.inNativeSpace(from)` (`from >> 160 == 0`).
  - **Native id:** `_authorizeNative`: `0`, `UA_POOL`, `SHIELD_POOL` refused; HIP-632 on Hedera for a 64-byte signature by an
    account `SigCheck.isContract` classes as no contract (no code, or an EIP-7702 designator); else `SigCheck.isValid`
    (ECDSA low-s by the address's own key, an EIP-7702 designator by its own key only, ERC-1271 under the code-hash cap).
    **No registry call** [M-old: `vm.expectCall(reg, "", 0)`].
  - **Derived id:** `UARegistry.requireAuthorized(from, purpose, digest, auth)`. At `registry() == 0` it reverts
    `UALedgerOff` by name (spike C: the guard sits in the derived branch of `_authorize` and of `_checkTo` only).
  - **Controller, R17:** a native id's `UASig` must have empty `keyData` and `members`, else `MetaTxBadSignature`. Today
    `_authorize` reads `auth.signature` alone, so a relayer can append junk; it moves nothing (the digest does not cover
    `UASig`), but after the merge it is every EOA's path, and failing closed costs a few bytes. With R47 it holds on every
    merged entry, the generic ones included.
- **Receivers:** `_checkTo` takes both spaces: a native `to` is credited in the ERC-20 ledger, a derived `to` must be
  registered and SIGNING (one registry `kindOf` call). `mtxTransfer` from an EOA to a derived UA is new on the address side
  [M-old].
- **Ledger moves:** native sides through the ERC-20 ledger, derived sides through `_uaBalance`, every signed transfer through
  `_uaMove`. `_uaMove` calls `ERC20._update` directly and so skips `ERC20MetaTx._update`: a regulated hook (CTR-GOV-17,
  SPECIFIED) must hook `_uaMove` too, or it misses every relayed transfer (§8).
- **Allow-list of the generic entry (B):** a derived subject reads `_uaAllowed` only. That is the invariant: inside the
  self-call a derived subject is `UA_POOL` (`MetaTxBase.sol:297-300`), so an op on `_mtxRule`'s list (`transfer`, `approve`,
  …) would act on the pool; the spike's mutant `derived-off-ua-list` tests it. A native subject reads `_mtxRule`, so an EOA
  also keeps `wrap`, `addReserve`, `wrapToUA`, `cancelNonce` on the generic entry (a convenience: each has a named entry).
  `_uaAllowed` gains nothing.
- **`_msgSender()`** inside the self-call: a native subject reads as its address, `UA_POOL` only for a derived one;
  unchanged.
- **Relayed Zether proofs:** on every merged entry the envelope binding becomes the UA binding, native subjects included:
  `TAG_UA_ENVELOPE = keccak256("SCAAS-ZETHER-UA-ENVELOPE-V1")` (R35). The contract computes it; `zether-prover` binds it.
- **Relayed PQZ proofs:** on every merged entry the envelope binding becomes the UA binding, native subjects included:
  `TAG_UA_ENVELOPE = keccak256("SCAAS-PQZ-UA-ENVELOPE-V1")` (R36). The contract computes it; the PQZ provers bind it.
- **Bindings, common to both:** no statement layout or relation changes (to be confirmed in the build, §8 risk 9). The one
  exception is `executeMetaTransaction` (R3): it is the address form, kept as it is, so a confidential call through it
  keeps today's address binding (`SCAAS-ZETHER-ENVELOPE-V1` on Zether kinds, `SCAAS-PQZ-ENVELOPE-V1` on PQZ kinds) over
  its `MetaTransaction`. The internal address binding stays for that entry; the public address `envelopeBinding` view goes
  to legacy (clients compute the address binding, as `zether-prover` does today).

### 2.2 Nonce space

Unchanged: one map `_uaNonce[bytes32][batch]`, natives zero-padded, already shared by both paths
([CTR-UA-26](../../contracts/accounts.md#CTR-UA-26)). A pay lane stays `payLane(payId)`, nonce 0. The view names follow the
entries: `mtxNonce(bytes32, uint256)` on tokens (today's `uaNonce`), the router and the mandate wallets (§2.7);
`SmartKeyAccount` keeps `mtxNonce(address, uint256)`, so the node picks the view by contract kind. Domain unchanged:
`("SCaaS MetaToken", "1", chainId, clone, salt = chainUid)`; the router's `("SCaaS GovernanceRouter", "1", chainId,
router, chain_uid)`; the mandate wallet's `("SCaaS MandateWallet", "1", chainId, wallet, chain_uid)`.

### 2.3 Names (controller)

- A pair keeps the non-`ua` name with the id form: `mtx<Op>`, and for the views and helpers that pair without the `mtx`
  prefix (`tradeOrderDigest` / `uaTradeOrderDigest`, `minNonce` / `uaMinNonce`, `envelopeBinding` / `uaEnvelopeBinding`,
  `receiverFeeDigest` / `uaReceiverFeeDigest`, `invalidateNoncesDigest` / `uaInvalidateNoncesDigest`, `restorePulled`) the
  plain name takes the id form.
- A `ua*` name with no address twin keeps its name (the registry's `uaAt`, `uaOf`, …): no rename was asked. `uaCancelDigest`
  goes to legacy with the unordered cancel (§2.1).
- **Typed struct names keep the `UA` prefix** (`UAMetaTransfer`, `UA<Op>`, `UATradeOrder`). Controller: their type strings
  and typehashes do not change, so every existing UA-side vector row stays valid and the address rows of merged ops retire.
  The one UA row that changes is `UACancelNonce` (§2.1, Q2). The only rows added are the mandate wallets' `UA<Op>` rows
  (§2.7, Q6): those wallets had no `ua*` twin, so their merged structs are new and their address rows retire.
- Inside one contract kind every name has one meaning. Across kinds `mtxExecute` is `(UAMetaTransaction, UASig)` on a
  token, the router and a mandate wallet and `(MetaTransaction, bytes)` on `SmartKeyAccount`: the node's call table is per
  kind already ([NODE-JOB-20](../../node/job-api.md#NODE-JOB-20)).

### 2.4 Events

A merged path emits the `UA…` events with a `bytes32` subject: `UAMetaTransactionExecuted`, `UAPaymentSettled`,
`UATradeFilled`, `UAOrderCancelled`, `UANoncesInvalidated`, `UAReceiverFeePaid`, `UALegSettled`, `UATransfer` where a
derived side moves, `UANonceCancelled` for the signed cancel. A native ledger move still emits the ERC-20 `Transfer`.
The mandate wallets' own events take `bytes32` ids (§2.7).
Address events stay where an address entry stays: `SmartKeyAccount`, the direct `payWithFee` (`PaymentSettled`), the direct
`cancelNonce` (`MetaNonceCancelled`), the DEX's outside legs (`LegSettled`), `executeMetaTransaction`
(`MetaTransactionExecuted`). Controller (R18): no second, address-typed event for a native subject on a merged path, because
one shape per path costs fewer bytes and the indexer reads the `UA…` topics for every relayed token operation.

### 2.5 What moves to `legacy/`

Backup, not delete (AGENTS.md):

| Where | Moves to `legacy/ua-mtx-merge/` |
|---|---|
| `smartcontracts/evm/src` | every address body of a merged pair, the address named-entry typehashes of tokens, `wrapBySig`, `_executeTransfer`, `_pay`, `_payMeta`, `_notPool`, `_tradeOf`, `preTransfer`, the address `requireSignature`, the public address `envelopeBinding(MetaTransaction)` views; the unordered `uaCancelNonce`, `uaCancelDigest` and the old `UACancelNonce` typehash (§2.1; the `cancelUsed` field stays in `UALedgerStorage`, layout pinned). The token's address pipeline (`_execute`, `_named`, `_namedCall`, `_settle`, `preCall(false)`, `preNamed`) stays for `executeMetaTransaction` and the five wrap entries (R3, §2.1) |
| `MetaTxBase` | split: the core stays; `mtxNonce`, `mtxDigest`, `mtxExecute`, `mtxBatch`, `mtxCancelNonce` (address forms) move to `MetaTxAddressBase` / `IMetaTxAddress`, inherited by `WalletExecute` (after Q6 `SmartKeyAccount` only); `executeMetaTransaction` stays on tokens (R3); nothing is deleted |
| `MandateWallet`, `HederaMandateWallet` (Q6, §2.7) | the address-form bodies: the five named entries over `SetMandate`, `SetPayee`, `RevokeMandate`, `PayUnderMandate`, `DelegateRevoke` and the named `mtxExecute` over `Execute`, with their typehashes; the flat builders `mtxPayUnderMandate(token, …, sig)`, `mtxRevoke`, `mtxExecuteAsOwner`, `mtxExecuteAsOwnerRaw`; the `address` storage and constructor; `HederaMandateWallet._requireValidSignature`; the vectors `mandate_pay_kat.json`, `mandate_revoke_kat.json` |
| `GovernanceRouter` | the 19 `_mtxCall` address entries and their 19 typehashes |
| `MtxRelayFee` | `relay(address …)` and the `RelayFee(address from, …)` struct; `uaRelay`'s body takes the name `relay` with `bytes32 from, payee` and a `UASig` (open mode unchanged) |
| `ITradeToken`, `WrappedLib` | `WrapOrder`, `CancelWrapOrder` and `mtxWrapOrder(address, WrapOrder, bytes)` (R39) |
| `MetaTxLib` | `MetaTransfer` and its typehash (R46) |
| vectors | the files of §7's Vectors row, each regenerated by its generator; old rows under each area's `legacy/ua-mtx-merge/` as typed-signing did |
| node, clients | the address builders of the merged entries, in each crate's or package's legacy place; the gateway's `POST /v1/metatx` handler for tokens (§7, Q7) |

`MetaTxLib.MetaTransfer` (R46, controller): after R20–R22, R33 and R42 no EVM entry or SPECIFIED EVM rule takes it, and the
owner's words say the old `mtx*` implementation goes, so it moves to legacy with the bodies it served (backup, not delete).
The non-EVM `MetaTransfer` of [NET-ALL-26](../../networks/README.md#NET-ALL-26) is each family's own struct and stays (R30).

### 2.6 The spike's measurements

Not a menu: A, B and C are the three parts of the base the owner's rule needs; A2 and D are the spike's other runs, kept as
data (A2 is out of scope, §4; D is a lever of §4). Runtime bytes, stop line 64,500 B, on the old base. Gas: `transfer` /
`mtxTransfer`, EOA to EOA, `WrappedPqzToken`.

| Run | What | `WrappedPqzToken` | `WrappedZetherToken` | `NormalToken` / `WrappedToken` / `NormalZetherToken` / `NormalPqzToken` | Gas |
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
`mtxTrade` through the DEX, `MetaTxGasV2`'s rows. The spike's A2 moved `executeMetaTransaction` onto `UAMetaTransaction`, which
changes its selector from `0x47aea5b5`; that shape is not proposed (R3), so A2's figure is not available to this round.

**The base.**

- **A + B + C.** A is the owner's rule. B is required because a derived subject must read `_uaAllowed` only (§2.1: inside
  the self-call it is `UA_POOL`); that an EOA keeps `wrap`, `addReserve`, `wrapToUA`, `cancelNonce` on the generic entry is a
  side benefit. C is required: without it a `NORMAL` / `WRAPPED` token at `registry() == 0` has no relayed path for an EOA at
  all, and a derived `to` reverts with empty data instead of a named error.
- **`executeMetaTransaction`** stays on tokens in its address form, selector `0x47aea5b5`, returning `bool`, as the owner
  ruled on 2026-11-01 ("for tender and outside tools"); the address pipeline stays on tokens for it and the five wrap entries.
  Not reopened (R3).
- **D: decided by §4's measurement**, not by default, and only with §8's invariant 7 (Q3).

### 2.7 The mandate wallets (owner 2026-11-04, Q6)

`MandateWallet` and `HederaMandateWallet` are built in this round in the merged form. They have no `ua*` twin today, so
nothing is renamed: each address body is widened to `bytes32` ids and moved onto `UAMetaTxBase`, as the cancel was (Q2).
[CTR-ACC-12](../../contracts/mandates.md#CTR-ACC-12)'s ids hold; its twins `uaExecute`, `uaPayUnderMandate`, `uaRevoke`,
`uaExecuteAsOwner` beside the `mtx*` ones are not built.

- **One signed entry per operation**, each `mtx<Op>(MetaTxLib.UAEnvelope e, <op parameters>, IUARegistry.UASig auth)` over
  `UA<Op>` in the wallet's domain: `mtxSetMandate` (`UASetMandate(bytes32 from,address token,bytes32 delegate,uint128
  maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry,E)`), `mtxSetPayee` (`UASetPayee(bytes32 from,address
  token,bytes32 payee,bool allowed,E)`), `mtxRevokeMandate` (`UARevokeMandate(bytes32 from,address token,E)`),
  `mtxPayUnderMandate` (`UAPayUnderMandate(bytes32 from,address token,bytes32 payee,uint256 amount,bytes32 entryRef,uint64
  epoch,E)`), `mtxDelegateRevoke` (`UADelegateRevoke(bytes32 from,address token,uint64 epoch,E)`), the named `mtxExecute`
  (`UAExecute(bytes32 from,address target,uint256 value,bytes data,E)`); `E` is `uint256 batch,uint256 nonce,uint256
  validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient`. From `UAMetaTxBase`, as on tokens: the generic
  `mtxExecute(UAMetaTransaction, UASig)`, `mtxBatch`, the ordered `mtxCancelNonce(UAEnvelope, lane, UASig)` (Q2),
  `mtxNonce(bytes32, uint256)`, `mtxDigest(UAMetaTransaction)`. Fee mode `NONE` only, every entry relayable.
- **Signers** ([CTR-MTX-30](../../contracts/metatx.md#CTR-MTX-30)'s B and C): a native signer (an EOA, or ERC-1271 code) signs with
  its own key in `auth.signature`, R17 holds, and no registry is called; a derived UA authenticates through
  `UARegistry.requireAuthorized`, so the wallet's `registry` is needed only when a side is derived (`UALedgerOff` by name at
  0). On `HederaMandateWallet` the native branch keeps HIP-632 through `UAMetaTxBase`'s `IS_HEDERA`, as the token kinds.
- **Ids** (CTR-ACC-12): `owner`, `Mandate.delegate` and the payee keys of `payeeAllowed` are `bytes32`; every authority check
  compares `_subject()` (the ticket's id in a self-call, else `pad(msg.sender)`) with the stored id, never `_msgSender()`,
  which is `UA_POOL` for a derived subject. A native payee is paid by `payWithFee`, a derived one by `payWithFeeToUA`
  ([CTR-UA-28](../../contracts/accounts.md#CTR-UA-28)). ERC-1271: a native owner keeps the ECDSA answer; a derived owner
  gets `0xffffffff` and acts through `mtxExecute`.
- **Allow-lists:** a native subject reads `_mtxRule`, a derived one `_uaAllowed` only (B); both list the six wallet
  operations, `cancelNonce` stays on `_mtxRule` only (its body refuses `UA_POOL`).
- **Controller calls** (plan MD-11; (a) owner confirmed 2026-11-05): the flat builders `mtxPayUnderMandate(token, …, sig)`,
  `mtxRevoke`, `mtxExecuteAsOwner` and `mtxExecuteAsOwnerRaw` are second signed entries of operations that have their
  named entry, so they move to legacy (this reverses the owner's 2026-11-01 keep, under the owner's 2026-11-04 "exactly one
  signed entry"); `executeMetaTransaction` on the mandate wallets refuses every call (`MtxSelectorNotAllowed`), as the
  router's does, because the EIP-1776 alias is the token's exception (R3); events and errors take `bytes32` ids.
- **Lanes** `mandatePayLane(entryRef)` and `mandateRevokeLane(token, epoch)` stay views, and the node keeps their shape
  rule for the delegate's two entries (nonce 0).
- **Unchanged:** `SmartKeyAccount`, `WalletExecute` and `MetaTxAddressBase` (its only user after this). No token storage
  moves; the wallets have no row in `test/v2/layout/`.

## 3. Composition

### 3.1 Governance (PR #9)

- **`GovernanceBase` entries are untouched.** An owner or holder operation has one direct entry and no `mtx*` / `ua*` twin on
  the governed contract (G19 of the governance spec; selector audit `selector_audit.json`). `_govSubject()` is unchanged: a
  direct caller is its native id; a call from `GOV_ROUTER` is the subject the router authenticated.
- **The router changes under every option.** `GovernanceRouterBase` inherits `UAMetaTxBase` and overrides `uaExecute` /
  `uaBatch` (refusing `MtxSelectorNotAllowed`) and the address `mtxExecute` / `executeMetaTransaction` / `mtxBatch` path. The
  merge renames the first and moves the second to `MetaTxAddressBase`, so the router's bytecode, init code and CREATE2
  address change under every option: every release's `Env.govRouter` follows, the router is deployed before the releases as
  today. After the merge the router refuses `mtxExecute` / `mtxBatch` under the merged names and keeps refusing
  `executeMetaTransaction` (R3). Its generic path refuses every call, so its only ordered cancel is the named one: it
  takes the merged `mtxCancelNonce(UAEnvelope, lane, UASig)` of §2.1 like a token (fee mode `NONE`), so the router keeps a
  nonce-ordered cancel for every subject. The node's shared `mtxCancelNonce` row (`ALL`) splits: tokens and the router
  take the `UACancelNonce` form, the mandate wallets too (§2.7); `SmartKeyAccount` keeps `CancelNonce`.
- **`GovernanceRouter` has 19 named pairs** (`mtx<Op>` by `_mtxCall`, `ua<Op>` by `_uaCall`; 38 typed entries, 38 node rows).
  **Controller: they merge**, because the owner's words cover every pair. `mtx<Op>` takes `UAEnvelope` + `UASig` and
  `_uaCall`'s flow; the subject an EOA produces is `pad(addr)`, exactly what `_mtxCall` writes today
  (`GovernanceRouterBase.sol:276-282`), so `_govSubject()` returns the same value and no governance check moves.
- **Powers' entries** (`mint`, `mintToUA`, `disableWrap`, the rate entries, the DEX setters) are reached through the router
  only; no change on the governed contracts.
- **CTR-GOV-11 ("+0": no new read on a plain `transfer` and `mtxTransfer`)** holds on the probed kind [M-old: the same three
  slots, 8 reads, 3 writes]; `PlusZero.t.sol` re-targets its `mtxTransfer` and `uaExecuteTransfer` rows to the merged
  entries and is re-run on every kind; `plus_zero_slots.json` regenerates.
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

### 3.3 Confidential kinds

**Never lose ciphertext** holds on both: the operation bodies do not change; every ciphertext stays in contract state.

**Zether.**

- The Zether pairs merge like the others: `mtxShield`, `mtxConfidentialTransfer`, `mtxConfidentialTransferCompact`,
  `mtxConfidentialTransferSingle`, `mtxUnshield`, `mtxUnshieldUnwrap`, `mtxRollOver`, `mtxRollOverBatch`, `mtxRollOverSigned`,
  `mtxSetRollOverMode`; `mtxWrapShield` stays on `Envelope` (§2.1).
- Since CTR-ZTH-94 the signed and `ua*` Zether forms and their typehashes run in `ZetherLib` / `ZetherWrappedLib`, and the
  Zether `ua*` entries sit in `ZetherLayer`. The merge edits those files too: the library-split checklist applies
  (DELEGATECALL storage, `this`, `msg.sender`, return data, the guard, `LinkClosure` pins). The spike predates the split, so
  its Zether savings are an upper bound (§4).
- Relayed proofs bind `SCAAS-ZETHER-UA-ENVELOPE-V1` for every subject on the merged entries (R35). `zether-prover` gains a
  UA binding function (today it computes only the address binding, `SCAAS-ZETHER-ENVELOPE-V1` over `MetaTransaction`, which
  it keeps for `executeMetaTransaction`, §2.1).

**PQZ.**

- The PQZ pairs merge the same way: `mtxShield`, `mtxConfidentialTransfer*` (four forms, the compact single included),
  `mtxUnshield`, `mtxUnshieldUnwrap`, `mtxRollOver`, `mtxPrepareAcc`; `mtxWrapShield` stays on `Envelope` (§2.1).
- Relayed proofs bind `SCAAS-PQZ-UA-ENVELOPE-V1` for every subject on the merged entries (R36); the PQZ provers and
  `clientkeys` change at once (§7).
- `script/pqz/at-set.sh` at all four sets for the build, and for the set parameters measured on the relay path
  (`roll_max`, `debit_min_gas`, §9 step 5); not for the size spike.

### 3.4 DEX (`CTR-DEX-25`, `CTR-DEX-26`)

A SCaaS token leg is `UATradeOrder` only (shape 1 of [CTR-DEX-26](../../contracts/dex.md#CTR-DEX-26)), its signature in
`auth`; the token's `mtxTrade` is today's `uaTrade`, its `minNonce` keyed by `bytes32` (R38). `TradeOrder` stays for outside
legs (`DexOrder` nests it), with its vectors; `LegSettled` stays for outside legs, a SCaaS leg emits `UALegSettled`.
`orderHash` / `cancelHash` lose their `ua` flag on the token side; the DEX's `record`, `cancel`, `invalidate` keep it for
outside legs. The DEX asks for a ledger only for a derived seller (C, +134 B [M-old]). This reverses the recorded rationale
of CTR-DEX-25 (R12). The DEX tests did not compile in the spike: nothing here ran (§9).

**The node's DEX is new work, not a rename.** Its book holds shape 0 `TradeOrder`s only today (UA intake waits for UA F5),
its watcher tracks `LegSettled`, `POST /v1/dex/orders` takes a `TradeOrder` for a SCaaS sell token, and
`POST /v1/dex/cancel-all` signs an address `InvalidateNonces`. After R12 the book gains `UATradeOrder` intake (a POST body
with `bytes32 from` and a `UASig`), the UA cancel and UA invalidate in the sell token's domain, and a `UALegSettled` watcher;
the shared typed row of `InvalidateNonces` (token kinds and the DEX) splits per kind. The public DEX gateway API changes and
is in the operator note (§7).

### 3.5 Hedera

The same kinds with `IS_HEDERA`; `_authorizeNative` keeps HIP-632 (a 64-byte signature by an account without code).
`HederaMandateWallet` takes the merged form with `MandateWallet` (§2.7, Q6), HIP-632 through `IS_HEDERA` on its native
branch. The Hedera `MetaOp` v1 becomes the token's `UAMetaTransfer` (R42). Not run
in the spike; the build runs the Hedera suites, the node's Hedera adapter and `tests/e2e_hedera.rs`.

## 4. Base token size for public chains

**Targets.** A token kind's implementation is deployed once per release, as one `CREATE2` inside the factory's release
transaction. Under EIP-8037 a transaction is included only if the gas it asks fits the block limit; a block's
`gas_used = max(...)` is accounting and proves nothing about inclusion. The deploy asks total × 1.05
(`--gas-estimate-multiplier 105`, `deploy.sh`), and governance's NET-EVM-06 fits a kind when regular × 1.05 < 2^24 and
total × 1.05 ≤ the limit. On the governance figures that is about 1,685 gas asked per runtime byte (`WRAPPED`: 52,297 B,
83.92 M total, 88.1 M asked), so a 60 M block holds about **35.6 KB** of runtime and a 70 M block about **41.5 KB**, before
the frame `deployTokenImplementation` adds. Tokens are clones: only the implementation and its libraries must fit, each its own
transaction. If the owner rules that a public deploy drops the multiplier (R40, Q4), that is a `deploy.sh` change and the
thresholds become about 37.3 / 43.5 KB.

**Where the kinds stand.** PR #9's `size-baseline.json` (ratchet ceilings, not measurements) against the projection of the
spike's deltas [P]:

| Kind | Main | PR #9 | M = A + B + C [P] | M + D [P] | 60 M (≈35.6 KB) | 70 M (≈41.5 KB) |
|---|---:|---:|---:|---:|---|---|
| `NormalToken` | 37,487 | 40,853 | ~32,160 | ~32,170 | fits with M, ~3.4 KB margin | fits |
| `WrappedToken` | 48,278 | 52,297 | ~42,470 | ~39,280 | **no**: ~3.7 KB over with M + D (~5.5 KB with the regulated stand-in) | no with M (~1.0 KB over); fits with M + D, ~2.2 KB margin (~0.4 KB with the stand-in) |
| `NormalZetherToken` | 47,470 | 50,547 | ~40,620 | ~39,010 | no, ~3.4 KB over with M + D | fits with M, ~0.9 KB margin |
| `WrappedZetherToken` | 58,407 | 62,472 | ~50,960 | ~47,770 | no | no |
| `NormalPqzToken`, `WrappedPqzToken` | 53,042, 63,563 | 56,191, 72,160 | ~46,650, ~56,000 | | not a target (CTR-GOV-19) | |

How the projection is made: PR #9's figure minus the spike's delta for that run on the same kind (§2.6). It is rough: the
governance build differs from the prototype (+0.3 to +2.1 KB on the base kinds), the Zether bodies moved to libraries after
the spike (so the Zether deltas are upper bounds), and `WrappedPqzToken` crosses back under the 65,536 B cliff (about 4.7 KB
of jump widths, inferred). L has no spike figure. On these figures `WrappedToken` misses 60 M without L. **None of these
numbers decides anything; §9's do.**

**Levers in scope**, in the order the round measures them:

| Lever | What | Rules and cost |
|---|---|---|
| **M** = A + B + C | the merge | §5 rules; +0.9 to +1.0 K gas per EOA relayed transfer |
| **L** | the `zether-lib` pattern on the base bodies: `ERC20MetaTx` and `UAMetaTxBase` bodies into a linked library, the decoders and the ABI stay on the token (as CTR-ZTH-94) | no ABI, storage or rule change; +1 to +2 K gas per signed call (Zether's figure, to measure); the library-split checklist; `LinkClosure` pins move with old → new; the library deploy must itself fit |
| **D** | lever 3: the read-only views behind a `fallback` to an immutable module pinned in `Env` | no ABI change seen from outside; a module per release, one `env.deps` entry, `libCodeHashes`, about 720 test call sites; a view +3 K gas, `eth_call` only; `hasRole`, `pendingOwner` and every view another contract reads on chain stay on the token. **A new dispatch path on every token**: taken only with §8's invariant 7 and its tests |

Out of scope, with reason: A2 (moving the five no-twin wrap entries and the token's address pipeline: they are not pairs,
and the pipeline stays for `executeMetaTransaction` by the owner's 2026-11-01 ruling, so most of A2's bytes are not
available); an own ERC-20 core (−0.3 to −0.4 KB [M-old], CTR-UA-18 for the one-ledger form, an own core to audit); B-26
(0 B on the wrapped kinds); narrowing `Grant` to `NORMAL*` and the DEX (CTR-GOV-02's fallback, a lost feature); dropping
named entries beyond the merge (rules, and the merge already removes the duplicates).

**How to decide (controller, under Q3).**

1. Target: `NormalToken` and `WrappedToken` fit the owner's **60 M and 70 M** (TODO, owner 2026-11-03: "Pick the smallest
   set that fits 60 M and 70 M") under the fit test of R40, and so does a stand-in of their regulated form (one regulated
   implementation per kind: the six regulated entries and the hook, about +1.7 to 1.9 KB [P] in the size-options note's
   §10). A set that fits 60 M fits 70 M.
2. The Zether kinds are measured against the same two thresholds and reported; whether they must fit before a public chain
   stays the owner's (CTR-GOV-19: "decided later").
3. Take M, then measure L and D on main after PR #9, each alone and together. Pick the smallest set that meets 1; between
   two sets that both meet it, take the one with no hot-path gas cost (D before L), then the one with fewer new mechanisms.
   L is measured alone first: if its yield is small, the order never matters.
4. **If no set in scope meets 1** (the projection's likely case for `WrappedToken` at 60 M), §9 reports the gap per kind
   and threshold and the owner rules (Q3). Recommendation: the merge and the best set land in this round; the 60 M target
   for the kinds that miss it stays open past this round, recorded in TODO with the measured gap. Reopening an
   out-of-scope lever (an own ERC-20 core, narrowing `Grant`) is the owner's choice then, with the numbers.
5. **The deploy gate** (`runtime × 1,530 + 2^24`, GD-4 on PR #9; NET-EVM-06) assumes the regular part at its 2^24 cap and so
   refuses above about 28.2 KB at 60 M and 34.8 KB at 70 M. The formula is the owner's and stays unless the owner changes
   it: R40 and Q4 put the public-chain gate to the owner.

## 5. Rules: decisions for the owner

Each row: the rule as written, the proposed text or "holds", why, cost. R1 to R9 are the rulings TODO names; the rest follow
from the design. Rows marked **Reversed** reverse an owner ruling or an owner-recorded rationale; Q1 lists every one of them.
Rows marked **Controller** are decided here with their reason; the owner may override them.

| # | Rule | Proposal | Why | Cost |
|---|---|---|---|---|
| R1 | [CTR-MTX-09](../../contracts/metatx.md#CTR-MTX-09): the named transfer entries "keep their signatures (owner: kept separate, nothing merged)" | **Reversed.** "`mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxPayMeta`, `mtxBatch`, `mtxBatchTransfer` take the form of today's `ua*` twin (the same flat explicit parameters with `bytes32` ids, `UASig` / `bytes auth`) and build `UAMetaTransfer` / `UAMetaTransaction`; one form per operation (owner 2026-11-03, the `ua*` / `mtx*` merge)." The mode shapes and the equivalences stay, on the UA structs | the owner's merge; a pair is one feature twice | the 2026-10-08 ruling "nothing merged" is reversed; every caller of the address forms moves |
| R2 | [CTR-MTX-15](../../contracts/metatx.md#CTR-MTX-15): "Two structs, one nonce space"; `MetaTransfer` "exists on tokens only" | Tokens: `UAMetaTransaction` and `UAMetaTransfer`, one nonce space (unchanged); `MetaTransaction` also stays on tokens for `executeMetaTransaction` (R3) and on `SmartKeyAccount` (the mandate wallets take `UAMetaTransaction`, §2.7). `MetaTransfer` has no token entry | follows R1 | wallets that displayed `MetaTransfer` field by field now see `UAMetaTransfer` (§6) |
| R3 | [CTR-MTX-17](../../contracts/metatx.md#CTR-MTX-17) and [CTR-MTX-22](../../contracts/metatx.md#CTR-MTX-22): `executeMetaTransaction` stays beside `mtxExecute`, `address from` | **Holds** (owner 2026-11-01), not reopened: on tokens `executeMetaTransaction(MetaTransaction, bytes)`, selector `0x47aea5b5`, returns `bool`, over the address pipeline with today's address proof binding (§2.1), beside the merged `mtxExecute`; on `SmartKeyAccount` unchanged; the mandate wallets refuse it (§2.7, plan MD-11) | the owner's ruling; tender and outside tools decode the `bool`; the tender's BUILT transitional deposit (`data = pay(depositRef)` through `executeMetaTransaction`, [tender.md](../../contracts/tender.md)) keeps running | the token keeps the address pipeline for this entry and the five wrap entries (size measured in §9); NET-ALL-28's rule names the alias as its EVM exception (R31) |
| R4 | [CTR-MTX-23](../../contracts/metatx.md#CTR-MTX-23), [CTR-MTX-24](../../contracts/metatx.md#CTR-MTX-24): `mtxExecuteTransfer(MetaTransfer, bytes)`, `mtxBatchTransfer(MetaTransfer[], bytes[])` | `mtxExecuteTransfer(UAMetaTransfer, UASig)`, `mtxBatchTransfer(UAMetaTransfer[], UASig[])`; the steps stay, step 3 becomes the UA receiver rule (a derived `to` registered and SIGNING) | follows R1 | events become `UA…` (R18) |
| R5 | [CTR-MTX-28](../../contracts/metatx.md#CTR-MTX-28) (TS-D14): `mtx<Op>(Envelope, …, bytes sig)` and, where UA-allowed, `ua<Op>(UAEnvelope, …, UASig)` | "`mtx<Op>(MetaTxLib.UAEnvelope e, <explicit op parameters>, IUARegistry.UASig auth)`, struct `UA<Op>`; one form" on tokens and the router for every op with a `ua*` twin; the cancel per Q2; the no-twin wrap entries stay on `Envelope` (§2.1); `SmartKeyAccount` keeps `Envelope` + `AccountSig`; the mandate wallets take this form (§2.7). Its "Size" bullet is rewritten to §4's targets | every field stays named and typed (CTR-MTX-29 holds) | `from` is `bytes32` on screen |
| R6 | [CTR-MTX-14](../../contracts/metatx.md#CTR-MTX-14): EIP-712 typed data, "wallets display the fields" | **Holds.** Still typed data, every field named, no blind hash; the `address` type of the fields §6 lists goes on token paths; an unbound `relayer` / `feeRecipient` is signed as 0 and shown as unbound (§6, invariant 2) | — | §6 |
| R7 | [CTR-UA-26](../../contracts/accounts.md#CTR-UA-26): "The UA path splits like the address path"; "The `ua*` functions keep their signatures"; `uaExecuteTransfer` mirrors `mtxExecuteTransfer` | "The signed path has two structs, a generic `UAMetaTransaction` and a typed `UAMetaTransfer`, under the `mtx*` names; they take native and derived ids." The mirror sentence goes | nothing left to mirror | none beyond R1 |
| R8 | [CTR-UA-27](../../contracts/accounts.md#CTR-UA-27): parity; "Own struct, any id … it takes a native id too" | **Holds by construction**: this text is the merged path. "the `ua*` functions" reads "the signed entries"; "Named UA builders exist only where the address path has one" goes; its citation of `bytes32` ids in `MandateWallet` follows R32 | parity stops being two forms | — |
| R9 | [CTR-UA-19](../../contracts/accounts.md#CTR-UA-19) (owner: yes): the UA-ledger meta-transactions have their own structs; registry 0 = "every `ua*` reverts `UALedgerOff`"; and [CTR-DEX-25](../../contracts/dex.md#CTR-DEX-25)'s 2026-10-13 controller ruling confirmed by the owner (C5b-2): "the `ua*` trade functions revert `UALedgerOff` while the ledger is off, a padded native `from` included" | **Reversed** (both). The UA structs are the token's signed structs for every merged op. **`registry() == 0`: a derived side reverts `UALedgerOff`; a call whose every side is native runs** (spike C) | an EOA keeps a relayed path on a plain token without a registry | `supportsInterface(IUALedger)` stays false at 0, so `IUALedger` splits (entries vs. ledger views) |
| R10 | [CTR-UA-18](../../contracts/accounts.md#CTR-UA-18): derived balances in a separate `bytes32` ledger | **Holds.** No balance moves | — | — |
| R11 | [CTR-UA-24](../../contracts/accounts.md#CTR-UA-24): own key only, never the delegate | **Holds** [M-old] | — | — |
| R12 | [CTR-DEX-25](../../contracts/dex.md#CTR-DEX-25): "`TradeOrder` and its vectors do not change. A native id may sign it too"; its Why: "Widening `TradeOrder` for everyone was rejected: native wallets keep displaying an `address`, and existing vectors and node encoders stay" (owner 2026-10-13) | **Reversed** (the rationale): "A SCaaS token leg is a `UATradeOrder`, native or derived; `TradeOrder` and its vectors stay for outside legs." [CTR-DEX-26](../../contracts/dex.md#CTR-DEX-26)'s shape 0 on a SCaaS token goes | follows R1 | EOA makers on SCaaS legs sign `bytes32 from` and `bytes32 destination`; the DEX KAT regenerates; 30 DEX test files move to shape 1; the node's book gains UA intake (§3.4) |
| R13 | CTR-GOV-11 (PR #9): "+0" = no new read on `transfer` and `mtxTransfer` | **Holds**; the pins re-target the merged entries | — | gas pins move with old → new |
| R14 | Governance spec G19 and CTR-GOV-15's router: 19 ops, each `mtx<Op>` and `ua<Op>` | **Controller:** the router's 19 pairs merge (the owner's words cover every pair): 19 entries, `UAEnvelope` + `UASig`; G19 holds on the governed contracts | one rule for every signed entry | node rows 38 → 19; the new router address comes from the base change under every option (§3.1) |
| R15 | [NET-ALL-84](../../networks/README.md#NET-ALL-84): the family checklist | New row, a question only: "Per operation, how many contract-verified signed entries, and which subjects take them? (answer per NET-ALL-28)"; UA-Soroban cell: "one, `ua_*`, derived ids only; natives by `require_auth` on the direct entry ([NET-SOR-20](../../networks/soroban.md#NET-SOR-20))" | one rule, one place (R31) | each family's UA spec answers one more row |
| R16 | AGENTS.md "Backup, do not delete" | **Holds**: §2.5 | — | — |
| R17 | new (**Controller**: fail closed on every EOA path) | A native id's `UASig` has empty `keyData` and `members`, else `MetaTxBadSignature` | fail closed on every EOA path; no relayer padding | a few bytes per entry |
| R18 | CTR-UA-27 "Events": an address-typed event keeps its shape, a UA party gets a `UA…` event | **Controller:** a merged path emits the `UA…` events only; address events stay on address entries (§2.4) | one event shape per path | indexers and the node read new topics for EOAs |
| R19 | `mtxCancelNonce(Envelope e, uint256 lane, bytes sig)` (address, TS-D14: nonce-ordered, relayer-bound, fee-capable) and `uaCancelNonce(bytes32 ua, uint256 batch, uint256 validUntil, UASig)` (derived only, no envelope, no fee, used-digest set, no nonce bound; [CTR-UA-26](../../contracts/accounts.md#CTR-UA-26)'s 2026-10-19 Change accepted that for derived ids) | Owner (Q2). Proposal: one entry, `mtxCancelNonce(UAEnvelope e, uint256 lane, UASig auth)` over `UACancelNonce(bytes32 from,uint256 lane,E)`, the ordered address body widened to `bytes32` (§2.1), on tokens and the router; the unordered form, `uaCancelDigest` and the used-digest check go to legacy (the `cancelUsed` slot stays, layout pinned). `cancelNonce` does not join `_uaAllowed`: its body refuses `UA_POOL` (`MetaTxBase.sol:120-123`), so the row would change nothing | the `ua*` body cannot serve a native and binds no nonce; keeping it would make every EOA's named cancel unordered and leave the router with no ordered cancel at all (its generic path refuses every call); typed-signing option B (owner 2026-10-31) wants a named entry per operation, not a generic blob | the cancel pair keeps the `mtx*` body, not the `ua*` one (a departure from the owner's 2026-11-03 words, so Q2); a derived subject's cancel becomes nonce-ordered (clients move); one `typed_ops.json` row changes |
| R20 | [CTR-MTX-01](../../contracts/metatx.md#CTR-MTX-01): "A payment is a `MetaTransfer` with `entryRef ≠ 0`", `PaymentSettled` | "A relayed payment is a `UAMetaTransfer` with `entryRef ≠ 0`, run through `mtxExecuteTransfer` or built by `mtxPay` and `mtxPayReceiverFee`; it emits `UAPaymentSettled`." The direct `payWithFee` keeps `PaymentSettled` | follows R1 | `pay_ref` lookups read `UAPaymentSettled` for EOAs |
| R21 | [CTR-MTX-05](../../contracts/metatx.md#CTR-MTX-05), [CTR-MTX-06](../../contracts/metatx.md#CTR-MTX-06): `ReceiverFee(MetaTransfer payment, …)`; the payer shape is a `MetaTransfer` | `UAReceiverFee(UAMetaTransfer payment, uint256 fee, address feeRecipient, uint256 validUntil)` is the token's only receiver-fee struct; the payer shape is a `UAMetaTransfer` with the same constraints | follows R1 | `ReceiverFee` and its vectors to legacy |
| R22 | [CTR-MTX-11](../../contracts/metatx.md#CTR-MTX-11): "a transfer or payment is signed only as a `MetaTransfer` and a call only as a `MetaTransaction`" | On tokens: "only as a `UAMetaTransfer`, a call only as a `UAMetaTransaction`" (plus `MetaTransaction` for `executeMetaTransaction`, R3); `SmartKeyAccount` unchanged, the mandate wallets as tokens (§2.7) | follows R1 | — |
| R23 | [CTR-MTX-12](../../contracts/metatx.md#CTR-MTX-12): "`mtxUnwrap` / `mtxUnwrapLeg` … `uaUnwrap` for a UA" | "`mtxUnwrap` / `mtxUnwrapLeg` (today's `uaUnwrap` form), for native and derived ids" | follows R5 | — |
| R24 | [CTR-MTX-18](../../contracts/metatx.md#CTR-MTX-18) and `MsgSenderLint`'s pinned `msg.sender` read counts | The counts are re-pinned with old → new in the commit (the spike saw `4 != 7`) | the merged bodies read `msg.sender` in other places | one source pin moves |
| R25 | [CTR-MTX-21](../../contracts/metatx.md#CTR-MTX-21): its entry table lists the `ua*` twins and `mtxCancelNonce(Envelope, lane, sig)` on every `MetaTxBase` contract | The table lists one `mtx*` form per operation on tokens and the router, `mtxCancelNonce(UAEnvelope, uint256 lane, UASig)` there (R19), the address forms on `SmartKeyAccount`, the merged ones on the mandate wallets (§2.7); `executeMetaTransaction` per R3 | follows R1, R19 | — |
| R26 | [CTR-MTX-22](../../contracts/metatx.md#CTR-MTX-22): `MetaTxBase` holds `MetaTransaction`, `mtxExecute`, `mtxCancelNonce`; `UAMetaTxBase` "0 = off: `UALedgerOff`" | `MetaTxBase` holds the core; `MetaTxAddressBase` holds the address generic path (`SmartKeyAccount` after Q6, and `executeMetaTransaction` on tokens per R3); `UAMetaTxBase` at registry 0 per R9 | §2.5 split | — |
| R27 | [CTR-MTX-26](../../contracts/metatx.md#CTR-MTX-26): the `mtxPayMeta` / `uaPayMeta` pair | On EVM one `mtxPayMeta` in today's `uaPayMeta` form; the non-EVM BUILT entries change only in their own rounds (R31) | follows R1 | — |
| R28 | [CTR-MTX-27](../../contracts/metatx.md#CTR-MTX-27): `MtxRelayFee.relay` / `uaRelay`, the `RelayFee(address from, …, address payee, …)` struct; the token's `mtxRelayFee` / `uaRelayFee` | `relay(bytes32 from, …, bytes32 payee, …, UASig)` is today's `uaRelay`; `UARelayFee` is the only struct; the token's `mtxRelayFee` is today's `uaRelayFee`; `RelayFee` to legacy | follows R1 | new `MtxRelayFee` CREATE2 address; node config `params.relay_fee.router` follows |
| R29 | [CTR-MTX-29](../../contracts/metatx.md#CTR-MTX-29): every parameter explicit | **Holds** | — | — |
| R30 | [NET-ALL-26](../../networks/README.md#NET-ALL-26): the non-EVM "`MetaTransfer` is the EVM `MetaTransfer` (CTR-MTX-23)" | "`MetaTransfer` carries the fields of the EVM `UAMetaTransfer` (CTR-MTX-23); its `from` is the family's native account in its own form; a derived subject signs the family's UA form" | follows R1; the two kinds stay | text only; no non-EVM code moves in this round |
| R31 | [NET-ALL-28](../../networks/README.md#NET-ALL-28): parity table `mtxTransfer` → `MetaTransfer{entry_ref: 0}`, citing CTR-MTX-09, -23, -24 | The EVM column names the merged entries over `UAMetaTransfer`; the citations follow R1 and R4. It gains the one-rule sentence of §1: "Per operation, a contract has its direct entry and at most one contract-verified signed entry. That entry takes every subject the chain's host cannot authorize for a call someone else submits: on EVM native and derived ids, on Soroban derived ids only, natives by host auth on the direct entry. On EVM a token also keeps the EIP-1776 alias `executeMetaTransaction` beside `mtxExecute` (owner ruling 2026-11-01)." **Controller** with R15 and R30 | one rule, one place; the alias is written in so the rule matches the code | NEAR and Algorand state their mechanism in their rounds |
| R32 | [CTR-ACC-12](../../contracts/mandates.md#CTR-ACC-12) (SPECIFIED, UA-5c): `uaExecute`, `uaPayUnderMandate`, `uaRevoke`, `uaExecuteAsOwner` on the mandate wallets, "mirroring the `mtx*` ones" | **Owner (Q6), changed 2026-11-04:** (a), in this round. `MandateWallet` and `HederaMandateWallet` get merged entries, not twins: one `mtx<Op>(UAEnvelope e, <op parameters, bytes32 ids>, UASig auth)` per wallet operation over `UA<Op>` (§2.7); a native signer by its own key without a registry, a derived UA through `requireAuthorized`; CTR-ACC-12's ids hold, its `uaExecute`, `uaPayUnderMandate`, `uaRevoke`, `uaExecuteAsOwner` are not built; the address bodies go to `legacy/ua-mtx-merge/`. `SmartKeyAccount` stays as it is. (First answer, same day: (b), deferred.) | as specified it would create the pairs R31 forbids; the merge removes twins on SCaaS contract wallets as on tokens, and external wallets only display | "the wallets keep the address surface" now means `SmartKeyAccount` only; new wallet bytecode, typehashes, `typed_ops.json` rows and KATs; the flat builders go to legacy (plan MD-11); node wallet rows move to `ua_metatx`; a wallet shows `bytes32` for `from`, `delegate`, `payee` (§6) |
| R33 | [CTR-TND-01](../../contracts/tender.md#CTR-TND-01): `commitBid(…, MetaTxLib.MetaTransfer t, bytes depositSig)` calls `token.mtxExecuteTransfer(t, sig)` | `commitBid(…, MetaTxLib.UAMetaTransfer t, IUARegistry.UASig depositSig)` calls the merged `mtxExecuteTransfer` | follows R4 | tender's spec and vectors |
| R34 | [CTR-AS-13](../../contracts/asset-suite.md#CTR-AS-13): `ExchangeOffer.exchange` takes a `TradeOrder` leg and calls `tokenIn.mtxTrade(leg, sig, …)` on a SCaaS token | The leg is a `UATradeOrder` + `UASig` through the merged `mtxTrade` | follows R12 | asset-suite spec |
| R35 | [CTR-ZTH-06](../../contracts/zether.md#CTR-ZTH-06), [CTR-ZTH-34](../../contracts/zether.md#CTR-ZTH-34), [CTR-ZTH-51](../../contracts/zether.md#CTR-ZTH-51): the relayed binding `SCAAS-ZETHER-ENVELOPE-V1` over an address `from` in `mtxExecute`; the UA binding beside it | On tokens the relayed binding is the UA binding for every subject, `SCAAS-ZETHER-UA-ENVELOPE-V1` over `UAMetaTransaction`; `envelopeBinding` names it; the address `envelopeBinding(MetaTransaction)` view moves to legacy | follows R1 | `zether-prover` gains the UA binding; e2e scripts follow |
| R36 | [CTR-PQZ-21](../../contracts/pq-zero-knowledge.md#CTR-PQZ-21): binding tag `SCAAS-PQZ-ENVELOPE-V1` (address) / `SCAAS-PQZ-UA-ENVELOPE-V1` (UA) | On tokens `SCAAS-PQZ-UA-ENVELOPE-V1` for every subject; the address row and view move to legacy | follows R1 | PQZ provers and `clientkeys` |
| R37 | [CTR-DEX-13](../../contracts/dex.md#CTR-DEX-13): "One struct, `TradeOrder`, for every leg" (owner) | "`TradeOrder` for every outside leg; a SCaaS token leg is a `UATradeOrder` (CTR-DEX-26 shape 1)" | follows R12 | — |
| R38 | [CTR-DEX-15](../../contracts/dex.md#CTR-DEX-15): the token-side `mtxTrade(TradeOrder, bytes sig, …)`, its address-keyed `minNonce`, `tradeOrderDigest` | Rewritten: `mtxTrade(UATradeOrder, UASig, …)` (today's `uaTrade`), `minNonce(bytes32, …)`, `tradeOrderDigest` over `UATradeOrder` | follows R12 | trade KAT and node builders |
| R39 | [CTR-TOK-20](../../contracts/token-wrappers.md#CTR-TOK-20): `mtxWrapOrder(address underlying, WrapOrder, bytes sig)` / `uaWrapOrder(…, UAWrapOrder, …)` | `mtxWrapOrder` takes `UAWrapOrder` + `UASig` (today's `uaWrapOrder`); `WrapOrder`, `CancelWrapOrder` and their vectors move to legacy | a pair, merged | — |
| R40 | NET-EVM-06 (PR #9): the gate `runtime × 1,530 + 2^24` ("the owner's and stays") and the fit test "regular × 1.05 < 2^24 and total × 1.05 ≤ the limit" | Owner (Q4). Proposal: the testnet gate keeps the owner's formula; before a public deploy the gate takes the measured regular + state gas of the release transaction (a fork or local simulation, through `deployTokenImplementation`), × 1.05, against that chain's limit | the formula refuses every token kind at 60 M; the fit test is the rule §4 uses | `DeployBase._releaseGasNeed` / `_requireReleaseGas`, `e2e.py require_release_gas`, `test_registryDeployGate` |
| R41 | PQZ set parameters `roll_max` and `debit_min_gas`, measured on the `uaExecute` relay path (`n2560-kmax16384`: "TIGHT: uaExecute 6,032 under … re-run the rollscan after a contract change") | Re-measured at all four sets on the merged `mtxExecute` (§9 step 5) with old → new. **Controller:** the 2026-10-27 rule (`ROLL_MAX` 48 if the margin is gone) applies as stated; any other value change is the owner's (a set parameter) and goes to the owner with old → new when §9 shows it | the merge adds R17's check, B's allow-list branch and C's guard to that path | if `debit_min_gas` moves: `set.toml`, `gen_set.py`'s `PqzSet` comment, `UARegistryLib` |
| R42 | [hedera.md §2 Payload](../../networks/hedera.md#payload): "the `MetaOp` v1 **is** the token's EIP-712 `MetaTransfer`"; "a SCaaS leg's `TradeOrder`" | "`MetaOp` v1 is the token's `UAMetaTransfer`, `from` the account's EVM address zero-padded (long-zero for an ED25519 account, its alias for an ECDSA account)"; "a SCaaS leg's `UATradeOrder`" | follows R1, R12 | `hedera_kat.json`, `adapters/hedera.rs`, `HederaKat.t.sol` |
| R43 | [job-api.md](../../node/job-api.md) error table: `OP_KIND_MISMATCH` = "a `ua*` entry on a job that is not `ua_metatx`" | "an entry that the per-kind call table ([NODE-JOB-20](../../node/job-api.md#NODE-JOB-20)) does not list for the job's kind" | names no longer carry the form | — |
| R44 | job-api.md intake step 7a ("`ua_metatx` needs `token.features ∋ ua` and a registered `from`") and [gateway.md](../../node/gateway.md)'s routes: the `POST /v1/ua-metatx` row (`features ∋ ua`, `registry() ≠ 0`; a table row, **not built**: `gateway.rs` registers `/v1/metatx` and `/v1/op` only, and `/v1/op` refuses a `ua*` entry, `FEATURE_UNSUPPORTED`), `POST /v1/metatx` (a `MetaTransfer`) | Step 7a and the `/v1/ua-metatx` gate apply only to a derived `from` or `to`; an all-native `ua_metatx` job runs at `registry() == 0`. The gateway's token doors (Q7): `/v1/op` takes the merged named entries with `auth: UASig`; `/v1/ua-metatx` is built for `UAMetaTransaction` / `UAMetaTransfer`; `/v1/metatx` refuses a token by name (its `MetaTransfer` has no token entry) | follows R9; without new doors no EVM token op is relayable through the gateway after reset 2 | gateway and intake code; the gateway rows of `gateway.md` become BUILT only with code and tests |
| R45 | [NODE-MESH-09](../../node/mesh.md#NODE-MESH-09) EVM body (`WireMetaTx`: the fields of `MetaTransaction` or `MetaTransfer`), [NODE-MESH-08](../../node/mesh.md#NODE-MESH-08) intent id, [NODE-MESH-16](../../node/mesh.md#NODE-MESH-16) KAT cases | The EVM and Hedera token body becomes the UA structs (`evm.ua_meta_tx`), its intent id the UA digest, its KAT cases the regenerated rows; `SmartKeyAccount` keeps the address body, the mandate wallets' body is the UA structs too (§2.7). Owner (Q7): build it in this round, or mark mesh relaying of EVM token ops unavailable (refused by name) until it lands | the address struct has no token entry left | `src/mesh/digest.rs`, `tests/mesh_vectors.rs` |
| R46 | `MetaTxLib.MetaTransfer` and its pinned typehash | **Controller:** after R20–R22, R33, R42 no EVM entry or SPECIFIED EVM rule takes it, and the owner's words retire the old `mtx*` implementation; it moves to legacy with the bodies and its vectors. The non-EVM `MetaTransfer` (R30) is each family's own and stays | backup, not delete; not decided by grep | `metatransfer_kat.json` and its consumers |
| R47 | [CTR-MTX-28](../../contracts/metatx.md#CTR-MTX-28) / [CTR-MTX-29](../../contracts/metatx.md#CTR-MTX-29)'s exception (owner table 2026-11-01): `uaExecute` / `uaBatch` / `uaShield` keep `bytes auth` | **Reversed** (the exception): `mtxExecute(UAMetaTransaction, UASig)`, `mtxBatch(UAMetaTransaction[], UASig[])`, `mtxShield(…, UASig)`; `executeMetaTransaction` keeps `bytes signature` (one crypto object) | explicit parameters (owner 2026-10-31): for a derived subject that `bytes` is a packed `UASig` (`MtxPipelineLib.sol:338-352`); after the merge it is the EOA's generic entry too, and R17 can then hold on it | the generic path's `bytes` authorize branch goes; node `ua_metatx` already carries `auth` as `UASig`; `clientkeys` and `zether-prover` builders; R41's relay-path measurement covers the gas |

## 6. Wallet and EIP-712 display

Today an EOA's wallet shows `MetaTransfer(address from, address to, uint256 value, …)`. After the merge it shows
`UAMetaTransfer(bytes32 from, bytes32 to, uint256 value, …)` and, for a named op, `UA<Op>(bytes32 from, …)`. The operation,
amounts, lanes, deadline, fee, relayer and fee recipient stay on screen, named; `relayer` and `feeRecipient` stay `address`.
Every field that goes from `address` to `bytes32` for an EOA, per struct: `from` and `to` (`UAMetaTransfer`, `UA<Op>`),
`destination` (`UATradeOrder`, receives the proceeds), `payee` (`UARelayFee`), the nested payment's `from` and `to`
(`UAReceiverFee`), and on the mandate wallets (§2.7) `from`, `delegate` (`UASetMandate`) and `payee` (`UASetPayee`,
`UAPayUnderMandate`); `UAExecute`'s `target` stays `address`. Each is a 32-byte word with 12 leading zero bytes for a native. The five wrap entries keep `address from`
(§2.1).

What is lost: a wallet treats an `address` field as an address (checksum, address book, warnings on known bad addresses) and a
`bytes32` as hex. That is an expectation; **no wallet was tested**. With a 24-digit zero prefix the leading characters a user
compares against an address-poisoning lookalike carry no information, so only the tail is left to check, on recipient
fields too. It is the one cost the bytes cannot pay back.

**What the signature fixes, and what it leaves to the relayer** (Codex medium 3). `relayer` and `feeRecipient` hash as 0
unless the mode's restriction bit is set (`MetaTxLib.canon` and the UA `hashStruct`, `MetaTxLib.sol:190-203`), and the
contract pays the fee to `feeRecipient == 0 ? msg.sender : feeRecipient` from calldata (`MtxPipelineLib.sol:245-252`,
`:321-326`). So with `MODE_RESTRICT_FEE_RECIPIENT` off, whoever submits picks where the fee goes; with
`MODE_RESTRICT_RELAYER` off, anyone may submit. That is the design, not a leak: the amount, the fee, the recipient of the
operation and every other field stay fixed. Two client rules follow, for `clientkeys`, every `ua-*`, `zether-prover` and the
node's builders: the EIP-712 message handed to the wallet carries the canonical 0 in an unbound field (a wallet hashes what
it is shown, so a non-zero unbound value there yields a signature the contract refuses), and the client shows "any relayer"
/ "fee goes to the submitter's choice" for an unbound field. A signer who wants one fee recipient sets its restriction bit.

- **Our clients (new work, not a mitigation).** `clientkeys` renders `urn:scaas:ua:v1:…` only in its Soroban module today and
  has no `bytes32`-id renderer on EVM; no `ua-*` has one. The round adds one to `clientkeys/src/evm.js` and each `ua-*`: a
  padded id as its checksummed address, a derived id as its URN ([NET-ALL-21](../../networks/README.md#NET-ALL-21)), before
  the user signs. A phishing dapp does not go through our clients, so this does not reduce the risk above.
- **A test wallet is needed** (Q5): before reset 2, sign the regenerated `UAMetaTransfer`, one `UA<Op>`
  row of `typed_ops.json`, a `UATradeOrder` with a non-zero `destination`, a `UARelayFee` row and a mandate payment (`UAPayUnderMandate` with a
  non-zero `payee`, Q6) in two widely used browser
  wallets and one hardware wallet, and record what each shows (a text note in `docs/research/`, screenshots local). Whether a
  clear-signing descriptor can render a `bytes32` as an address is not checked.
- The primary type name keeps the `UA` prefix (§2.3), so the wallet's title reads `UAMetaTransfer` for an EOA too.

## 7. Blast radius

Counts from main `783bacee` by grep [R], plus PR #9. The recount on this branch's base (`d97f5a39`, PR #9 in) by a grep of
every listed area (docs: everything outside `history/`, `research/` and `superpowers/`) replaces this table at the build.

| Area | What changes |
|---|---|
| Contracts | the six token kinds, `MetaTokenBase`, `ERC20MetaTx`, `UAMetaTxBase`, `MetaTxBase` (split), `MetaTxLib` (structs and typehashes), `MtxPipelineLib`, `WrappedLib`, `TradeLib`, `ZetherLayer`, `ZetherLib`, `ZetherWrappedLib`, the PQZ layer and `PqzWrappedLib`, `MtxRelayFee`, `SCaaSDex`, `ISCaaSDex` (leg types) and `DexPuller`, `HederaAccountAuth` (the HIP-632 entry names), `GovernanceRouterBase` / `GovernanceRouter` (under every option, §3.1); interfaces `IERC20MetaTx`, `IMetaTx`, `IUALedger` (split), `ITradeToken`, `IZetherToken`, `IPqzToken`, `IConfidentialToken`, `IWrappedToken`, `IMetaTokenV2`: new interface ids; `MandateWallet`, `HederaMandateWallet` in the merged form (next row); `SmartKeyAccount` byte-identical (re-checked) |
| Mandate wallets (Q6, §2.7) | **Contracts:** `src/wallet/MandateWallet.sol` (on `UAMetaTxBase`, not `WalletExecute`), `src/hedera/HederaMandateWallet.sol`; NatSpec of `WalletExecute`, `MetaTxAddressBase`, `IMetaTxAddress` (now `SmartKeyAccount`'s). **Tests:** `test/wallet/{MandateWallet,NamedWallets}.t.sol`, `test/account/AccountKat.t.sol` (`MandateWalletKatTest`), `test/metatx/{TypedOps,NamedEntry,Sweeper7702,MsgSenderLint}.t.sol`, `test/merge/Invariants.t.sol` (`test_walletsByteIdentical` keeps `SmartKeyAccount` only). **Vectors:** `mandate_pay_kat.json` and `mandate_revoke_kat.json` (consumers: `AccountKat.t.sol`, node `typed.rs`, `clientkeys` `evm.test.js`) to legacy, a new `mandate_kat.json` over the merged entries; `typed_ops.json`: the six wallet address rows retire, six `UA<Op>` rows are added, `UACancelNonce` gains the wallet. **Node:** `typed.rs` (`W` rows on the UA structs, `WA` split: `mtxExecuteAsOwner` stays for `account`; the `PLAIN` rows `mtxExecuteAsOwnerRaw`, flat `mtxPayUnderMandate`, `mtxRevoke` to legacy; `mandate_shape` on the UA rows), `guard.rs` (the wallet selector pins), `abi.rs` (`IMandateWallet` errors with `bytes32`), `submit.rs` (lane rows), `tests/e2e.rs` (the wallet calls). **Clients:** `clientkeys` `src/evm.js` (`WALLET` rows), `test/evm.test.js`, `scripts/typed-ops-vectors.mjs`; `zether-prover` `tests/typed_ops.rs` reads the rows. **Docs:** `contracts/mandates.md` (CTR-ACC-06, -07, -12, §1.1 the auto-pay path), `contracts/accounts.md` (CTR-UA-27's `MandateWallet` row), `networks/hedera.md` (NET-HED-03), `node/job-api.md` (the wallet's named entries), `clients/signers-clientkeys.md` (the mandate ops) |
| PQZ set parameters | if R41 moves a value: `pqz-core/params/sets/<set>/set.toml`, `gen_set.py` (the `PqzSet` comment), the regenerated `PqzSet.sol`, `UARegistryLib` |
| Node | `abi.rs` (token and DEX types), `guard.rs` (`CALL_TABLE`, both directions against `mtxSelectors` and `_uaAllowed`), `typed.rs` (per-kind rows; the shared `InvalidateNonces` and `mtxCancelNonce` rows split), `submit.rs`, `chain.rs` and `adapter.rs` (the nonce view: `mtxNonce(bytes32)` on tokens, the router and the mandate wallets, `mtxNonce(address)` on `SmartKeyAccount`, by kind), `gateway.rs` (new work, R44 / Q7: `/v1/op` takes the merged named entries with `UASig`, `/v1/ua-metatx` is built, `/v1/metatx` refuses a token by name; the DEX routes), `metatx.rs`, `indexer.rs`, `dex.rs` (UA intake, `UALegSettled` watcher), `dex/venue.rs`, `adapters/hedera.rs`, `src/mesh/digest.rs` (R45), the legacy pull path module; the router rows (`gov_router`); tests `tests/e2e.rs`, `tests/e2e_hedera.rs`, `tests/mesh_vectors.rs`. Rules: R43, R44, R45 |
| Job shape | Controller: every merged EVM entry is a `ua_metatx` job, because the job API's shape already carries `from` as bytes32 and `auth` as `UASig` (`entry` names the `mtx*` name); the gateway has no built door for it (R44, Q7); `metatx` stays for `SmartKeyAccount`'s address entries and `executeMetaTransaction`; the mandate wallets' entries are `ua_metatx` jobs (§2.7); a `metatx` job or a `struct: "transfer"` job naming a token's merged entry is refused by name. **Operator note** with the release: EVM clients of the address token forms must move to `ua_metatx`; the public DEX API takes `UATradeOrder` for SCaaS sell tokens and the UA cancel forms; the mesh's EVM token body changes (R45); a job of the old shape is refused, never silently `dead`; the auto-pay path signs the mandate wallet's named `UAPayUnderMandate` / `UADelegateRevoke` instead of the flat builders (Q6) |
| Events | §2.4: new topics for EOA relayed operations; the indexer maps them; `pay_ref` lookups read `UAPaymentSettled` for EOAs |
| Scripts and config | `script/pqz/e2e.py` (the UA binding for EOAs, the merged entry names, `require_release_gas`), `script/ZetherE2E.s.sol`, `scripts/e2e-zether.sh`, `DeployBase` (`govRouter`, the `MtxRelayFee` CREATE2, the release gate of R40), `node.example.toml` and operator config (`governance_routers`, `params.relay_fee.router`) |
| Clients | `clientkeys`: `src/evm.js` (the forms and a `bytes32`-id renderer, §6), `scripts/typed-ops-vectors.mjs`, `typed-ops-expected.mjs`, `typed-ops-cast-check.mjs`, `ua-sig-vectors.mjs`, tests `evm`, `typed-ops`, `ua-metatx3`, `ua-sig`, `pq-sig`, `ua-trade`. `zether-prover`: `src/typed.rs`, `src/envelope.rs` (a new UA binding function, `SCAAS-ZETHER-UA-ENVELOPE-V1` over `UAMetaTransaction`), `src/api.rs`, `tests/typed_ops.rs`. The PQZ provers' binding. The `ua-*` libraries hold no entry-form code (their hits are `UAAuth` registry digests) and change only by the renderer of §6 |
| Vectors | Retire to legacy, regenerated by their generators: `smartcontracts/evm/test/vectors/metatransfer_kat.json` (node `abi.rs`, `metatx.rs`, `tests/mesh_vectors.rs`, `clientkeys` `evm.test.js`, `TokenKat.t.sol`, `MtxCtx.t.sol`), `metatx_kat.json` (same consumers), `trade_kat.json` (node `submit.rs`, `typed.rs`, `abi.rs`, `dex.rs`, `clientkeys` `evm.test.js` / `ua-trade.test.js`, `TradeKat.t.sol`, `UATradeVectors.t.sol`), `hedera_kat.json` (node `adapters/hedera.rs`, `HederaKat.t.sol`, `gen_hedera_kat.py`), `metatx-parity.json` (with `MetaTxParity`). Regenerate: `vectors/typed/typed_ops.json` (address rows of merged ops retire; the existing `UA*` rows stay byte-identical except `UACancelNonce`, R19; no row is added), PR #9's `plus_zero_slots.json`, `dex_order_kat.json`, `selector_audit.json`. `vectors/ua/metatx3.json` (its note names `uaPayReceiverFee`) and `uatrade_kat.json`: rows unchanged (§2.3), notes renamed. **Unchanged:** `vectors/metatx/paymeta.json` and `relayref.json` (payId, payLane, relayRef: no `from`, no form), so no other family is touched |
| Docs | `contracts/`: `metatx.md` (CTR-MTX-01, -05, -06, -09, -11, -12, -14, -15, -17, -18, -21, -22, -23, -24, -26, -27, -28), `accounts.md` (CTR-UA-19, -26, -27), `dex.md` (CTR-DEX-13, -15, -25, -26), `zether.md` (CTR-ZTH-06, -34, -51, entry names), `pq-zero-knowledge.md` (CTR-PQZ-21, entry names), `token-wrappers.md` (CTR-TOK-20), `settlement.md`, `tender.md` (CTR-TND-01), `asset-suite.md` (CTR-AS-13), `mandates.md` (CTR-ACC-12); `networks/`: `README.md` (NET-ALL-26, -28, -84), `evm.md` (NET-EVM-06, the `ua_metatx` relay rows), `hedera.md` (§2 Payload, the DEX row); `node/`: `job-api.md`, `gateway.md`, `mesh.md`, `submit-lanes.md`, `dex-venue.md`, `indexer-feeds.md`, `sponsorship.md`, `threat-model.md`; `clients/`: `signers-clientkeys.md`, `app.md`; `architecture.md`, `assets/settlement-kinds.svg`, `assets/token-tree.svg`, `integration.md`; `decisions.md` entries for every R row as ruled |
| Tests | on the old base 86 test files, 6 helpers and 1 script did not compile, 1,383 of 2,142 tests [M-old]; by class: call shape (most, mechanical, carried by six helpers), address events (19 files), DEX leg shape (30), meaning reversed (at least 7: a native at `registry() == 0`, a native `mtxCancelNonce`, a native off the UA list), gas or size pins (33), typehash or interface pins (5), source pins (`MsgSenderLint.test_msgSenderReadsArePinned`, red at `4 != 7` on the spike tip; R24), parity tests that lose their point (`MetaTxParity`). Recount on `d97f5a39` (PR #9 in) at the build |

## 8. Risks and the invariants to keep

**Invariants** (each a test that can fail, shown by a mutant as the spike's eight):

1. **No forgery.** A merged entry runs only for a subject that signed its typed digest: a derived id through
   `requireAuthorized(from, purpose, digest, auth)`, a native id by its own key (ECDSA low-s, ERC-1271 under the cap, HIP-632
   on Hedera), an EIP-7702 designator by its own key only.
2. **A relayer cannot alter the canonical signed intent.** The digest covers every operation parameter and every envelope
   word in its canonical form: `relayer` and `feeRecipient` hash as 0 unless the mode's restriction bit binds them
   (`MetaTxLib.canon` and the UA `hashStruct`). The exception, by design: with a bit off, the submitter chooses that field
   (any relayer may submit; the fee goes to `feeRecipient` from calldata, or to `msg.sender` at 0), so a bound value is the
   only promised one (§6). `UASig` is not signed, so for a derived id the registry checks `keyData` / `members` against the
   record and for a native id R17 refuses anything but `signature`. Tests: a signature over the canonical message verifies
   with a non-zero unbound `relayer` and `feeRecipient` in calldata and pays the fee where calldata says; changing any bound
   field or any operation field fails; a client that puts the non-zero unbound value into the signed message gets a refusal.
3. **Replay domains.** The domain names the contract, the chain and `chainUid`; one typehash per operation; one lane
   `(from, batch)` per id with natives padded; the router signs `target`. The retired forms cannot run: the address
   `MetaTransfer`, the address named-entry structs of merged ops (`CancelNonce`, `TradeOrder` on a SCaaS leg, `WrapOrder`,
   `RelayFee`, `ReceiverFee`, …), the mandate wallets' address structs and `MetaTransaction` (§2.7) and the old
   `UACancelNonce(bytes32 ua,uint256 batch,uint256 validUntil)` have no entry left.
   Two address forms stay and still run, by design: `MetaTransaction` through `executeMetaTransaction` (R3; a signature made
   for the old address `mtxExecute` is the same struct in the same domain and runs there with the same meaning) and the five
   wrap entries' `Envelope` structs. Renaming a selector invalidates no signature; only a changed type string or domain
   does. Tests, each with a positive control first: an old `MetaTransfer` and an old `CancelNonce` signature are refused on
   every token entry; an old `mtxExecute` signature runs through `executeMetaTransaction`; a confidential call through
   `executeMetaTransaction` verifies only with a proof bound to the address tag, and one through `mtxExecute` only with the
   UA tag. **Cancel (R19):** the merged `mtxCancelNonce` is nonce-ordered: a test lands a cancel signed at nonce n of lane
   `e.batch` and then shows a withheld cancel at the same nonce cannot land after a newer operation consumed it, for a
   native and a derived subject on a token and on the router.
4. **Relayable at fee 0.** Every operation has a merged entry that runs at fee mode `NONE`, on every kind, with and without a
   registry for a native subject. The entries whose point is a fee are listed and not tested at `NONE`:
   `mtxTransferWithFee` (PERCENT or FIXED with a bound non-zero recipient; at 0 it is `mtxTransfer`), the payee leg of
   `mtxPayReceiverFee` (`fee > 0`; the payer's leg is `NONE`), `mtxRelayFee` and `MtxRelayFee.relay` (the relay fee is their
   point; the relayed call runs at `NONE`); `mtxWrapShield` with the native coin is not relayable at all
   ([CTR-MTX-19](../../contracts/metatx.md#CTR-MTX-19), review C0-18). Every other merged entry is tested at `NONE`.
5. **All or nothing**, the call before its fee, as [CTR-MTX-16](../../contracts/metatx.md#CTR-MTX-16).
6. **Never lose ciphertext**; no new read on a plain transfer (CTR-GOV-11); storage layout pinned; `_msgSender()` is
   `UA_POOL` only for a derived subject, and a derived subject reaches `_uaAllowed` only (B; mutant `derived-off-ua-list`).
7. **Lever D, if taken.** The module's code is pinned by hash in `Env` and passes a `LinkClosure`-style opcode check: no
   `SSTORE`, `TSTORE` (the ticket slots), `CALL`, `CALLCODE`, `DELEGATECALL`, `CREATE` / `CREATE2`, `SELFDESTRUCT` or
   `LOG*`; `STATICCALL` is its only call (a view reads the registry, never writes). A zero-value `CALL` is refused too: run
   by `DELEGATECALL` in the token's context, it could move the token's underlying reserves or call back into the token,
   where `_msgSender()` would read the live ticket's subject (`MetaTxBase.sol:297-300`). The token's `fallback` is not
   `payable`, reverts on every selector the module does not serve, and never answers `isValidSignature` (so
   `SigCheck._erc1271` cannot take a module return as the magic). The fallback cannot be reached as an allow-listed
   self-call (`_mtxRule` / `_uaAllowed` list no module selector), and a call through `MtxRelayExecutor.exec` or the DEX's
   `_interact` (both plain `call`, no static frame) reaches only the read-only views. Tests: each of these; mutant modules
   with one `SSTORE`, with one zero-value `CALL` that would transfer an ERC-20, and with one `CALLCODE` must each turn the
   opcode check red; the module's source and dispatch targets are reviewed by hand, since an opcode test proves no more than
   its list.

**Risks** (spike §7, then new):

1. Every EOA path becomes the path native ids used least: review the merged bodies as new code.
2. `_uaMove` is the only hot move of signed transfers; a regulated hook only in `_update` misses every relayed transfer.
3. A native `UASig`'s ignored fields (closed by R17 if taken).
4. The DEX's refusal list (`_interact` refuses `ITradeToken.mtxTrade.selector`): with old-release tokens on one chain, old
   selectors and the old order shape would need a place. Nothing is live with value; at mainnet this returns.
5. **The cancel** (R19, Q2): if the owner keeps the unordered `UACancelNonce` instead, a withheld but valid cancel can kill
   an operation signed after it on that lane until `validUntil`, for every EOA too, and the router has no ordered cancel at
   all. That is then an accepted regression, recorded as such, not a documented outcome.
6. `mtxTransfer` from an EOA now reaches a derived `to`: the receiver rule is the UA path's.
7. **The numbers move.** The spike's base is not PR #9's; the Zether savings are upper bounds after CTR-ZTH-94; `WrappedToken`
   misses 60 M on the projection even after M + A2 + D (§4).
8. **Library splits** (`ZetherLib`, and L if taken): DELEGATECALL storage, `this`, `msg.sender`, return data, the guard,
   `LinkClosure` pins; the class of each fix checked in every library.
9. **Relayed proofs.** On a merged entry the EOA binding moves to the kind's UA tag (`executeMetaTransaction` keeps the
   address tag, §2.1): a client that binds with the wrong tag for the entry yields a proof
   the contract refuses. Confirm in the build that only the binding value changes, not a statement layout or relation; if a
   layout changes, that is a new `proofSystemId`, new vectors in every client and a full gate.
10. **New router address** (every option, §3.1): every release's `Env.govRouter` and the node's `governance_routers` change
    together.
11. **Interface ids** change; `mtxWrapOrder`'s ERC-165 check of a leg and the DEX's ledger check must ask the right
    interface after the `IUALedger` split.
12. **Test repairs can hide a change of meaning**: the "meaning reversed" class is reviewed by hand, not repaired by script.
13. **Wallet display** (§6), recipient fields included.
14. **Hedera** was not run in the spike.
15. **EOA gas** +0.9 to +1.0 K per relayed transfer, calldata; higher where calldata costs more, on every chain alike.
16. **Lever D's dispatch path** (invariant 7): a module that writes, calls (a zero-value `CALL` included) or logs would act
    as the token.
17. **PQZ set margins**: `n2560-kmax16384`'s `roll_max` margin is 6,032 gas on the relay path the merge rewrites (R41).
18. **Mesh and the node's DEX** lose their only valid token body or gain new intake (R45, §3.4): new node work, not renames.
19. **Mandate wallets** (Q6, §2.7): every wallet check must read `_subject()`, not `_msgSender()` (`UA_POOL` for a derived
    subject); a derived owner has no ERC-1271 answer; the auto-pay clients of the flat builders move to the named entries.

## 9. Measurement plan after PR #9

Nothing ran before PR #9 merged (owner 2026-11-04); it is merged into this branch at `d97f5a39`. On a branch from main, through `scripts/capped`, foreground:

1. **Port the harness** of the spike (`merge_pairs.py`, `no_twin.py`, `lever3_delete.py`, `mutants.py`, `red_skip.py`, and the
   `test/merge` set) into `smartcontracts/evm/runs/<date>-ua-mtx-merge/` (kept, git-tracked: research harness and results stay
   in the repo; full logs local, one summary committed).
2. **Sizes** (`forge build src --sizes --json`, default set `n2304-kmax4096`): every kind, `SCaaSDex`, `GovernanceRouter`,
   `MtxRelayFee`, `MtxPipelineLib`, `WrappedLib`, `ZetherLib`, `ZetherWrappedLib`, `PqzWrappedLib`, the wallets, for: base;
   M; M + L (first: L alone decides whether §4's D-before-L order matters); M + D; M + L + D; and the regulated stand-in on
   `NormalToken` and `WrappedToken`: a scratch copy with the six regulated entries and the hook, measured, not committed.
3. **Deploy gas** per implementation and library, each its own transaction, by the method of governance's
   `GovDeploy.t.sol` `test_releaseGasPerKind` (regular × 64/63 + state, × 1.05), plus the frame `deployTokenImplementation` adds,
   measured once on the factory path; reported as the gas asked against 60 M and 70 M, and regular × 1.05 against 2^24.
4. **Gas** (forge, deterministic; no timing, no calibration): `GovGas` rows on `NormalToken` and `WrappedToken` at
   `registry() == 0` and `≠ 0` (C moved a check off the hot path, and CTR-GOV-11's "+0" is per kind, not per registry
   state), `MetaTxGasV2` rows, `PlusZero` slots on every kind, EOA → EOA and EOA → UA, the merged `mtxCancelNonce`, and what the spike did not run: generic `mtxExecute`, `mtxPayReceiverFee`, `mtxTrade` through
   the DEX, a Zether and a PQZ relayed op.
5. **PQZ set parameters** at all four sets through `script/pqz/at-set.sh` (one run per work tree, `PqzSet.sol` restored):
   `test_gas_rollMax_relayedFullTx`, the rollscan, and the `debit_min_gas` measurement, on the merged `mtxExecute`, each with
   old → new. A value that moves outside the 2026-10-27 rule goes to the owner (R41).
6. **Tests**: the recount of §7 on the merged tree (it replaces §7's counts); `test/merge` and the eight mutants, the
   tests of invariants 2 and 3 (unbound fields, retired and retained forms, both binding tags, the cancel), invariant 7's
   tests and mutants if D is measured, plus a Hedera case and a router case.

**What decides:** step 3 against §4's rule 1 picks the lever set; step 2 shows whether `WrappedPqzToken` leaves
`_above64KiB`; step 4 is reported with old → new, it decides only if a lever's hot-path cost is out of line; step 5 decides
nothing by itself (set parameters are the owner's). Results go into this spec as a dated table and into the research note's
re-measure line.

### 9.1 Results of T0 (2026-11-04, at `main` `bf6f3d04`)

All [M] (forge, deterministic). Full tables, the harness and how each run was built:
`smartcontracts/evm/runs/2026-11-04-ua-mtx-merge/` (`results.txt`, `README.md`). The merged code was built as scratch on the
local branch `ua-mtx-merge-t0`, never merged. M = A + B + C with Q2's cancel, R47, R17, the router's 19 pairs and one
`envelopeBinding` view (MD-2). L = `TokenBodyLib` (the typed transfer group, receiver-pays and the trade group on the
`ZetherLib` pattern). D = 43 views by deletion and a STATICCALL-then-DELEGATECALL `fallback` (no module built). Stand-in = six
direct regulated stubs and a hook in `_update` and `_uaMove`.

Runtime bytes and deploy gas asked (one release transaction: (regular x 64/63 + state) x 1.05 of the CREATE2, plus the
factory frame of +0.36 to +0.37 M):

| Kind | base | M | M + L | M + D | M + L + D | stand-in on M / M + L / M + D / M + L + D |
|---|---:|---:|---:|---:|---:|---|
| `NormalToken` B | 40,853 | 32,098 | 30,156 | 31,535 | 29,593 | 33,093 / 31,151 / 32,530 / 30,588 |
| `NormalToken` asked | 69.31 M | 54.65 M | 51.40 M | 53.71 M | 50.46 M | 56.32 / 53.07 / 55.37 / 52.12 M |
| `WrappedToken` B | 52,297 | 42,678 | 40,693 | 39,792 | 37,807 | 43,745 / 41,760 / 40,955 / 38,970 |
| `WrappedToken` asked | 88.48 M | 72.37 M | 69.05 M | 67.54 M | 64.22 M | 74.16 / 70.84 / 69.49 / 66.17 M |
| `NormalZetherToken` B / asked | 50,547 / 85.65 M | 40,552 / 68.91 M | 38,646 / 65.72 M | 38,908 / 66.16 M | 37,002 / 62.97 M | |
| `WrappedZetherToken` B / asked | 62,472 / 105.63 M | 51,040 / 86.49 M | 49,079 / 83.20 M | 48,283 / 81.87 M | 46,322 / 78.58 M | |
| `NormalPqzToken` B | 56,191 | 46,393 | 44,359 | 41,025 | 38,991 | |
| `WrappedPqzToken` B | 72,160 | 56,232 | 54,145 | 49,883 | 47,796 | |
| `GovernanceRouter` B | 20,073 | 11,744 | 11,744 | 11,744 | 11,744 | |
| `TokenBodyLib` B / asked | | | 9,296 / 15.79 M | | 9,296 / 15.79 M | |

Gas, `GovGas.t.sol`'s method: relayed transfer EOA to EOA base 87.3 to 87.4 K, M +1.3 to +1.4 K (calldata 420 -> 580 B), M + L
a further +7.5 K, D +-30; EOA to a UA +112 to +177 (base: `uaTransfer`); the signed cancel -3.1 to -5.1 K; the generic entry
+1.7 to +2.5 K; a derived `mldsa65` subject on the generic entry +1,993; `transfer` +-66; `registry() == 0` and `!= 0` equal.
Mutants on M: 10 of 10 red. Wallets byte-identical (at T0; after Q6's change the mandate wallets move in plan T3b). Test recount on M (replaces §7's counts): 99 files do not compile (92 test files, 6 helpers, 1 script; 21 by an own error, 78 only through a moved import), 1,486 test functions; 76 test files with 948 test functions compile.

**Reading by §4 (Q3, the owner's).** No set in scope fits 60 M for `WrappedToken`: the gap is 4,469 B on M + D (5,624 B with
the stand-in) and 2,499 B on M + L + D (3,652 B). `NormalToken` fits 60 M on M, stand-in included. For 70 M the smallest set
that fits both kinds and both stand-ins is **M + D** (M misses by 1,408 B; M + L misses with the stand-in by 497 B), and it
has no hot-path cost; L costs +7.5 K gas per typed relayed transfer. **Recommendation: M + D; the 60 M target for
`WrappedToken` stays open at 4,469 B (5,624 B regulated).** Caveat: with the stand-in M + D fits 70 M by about 300 B, and the
stand-in (+995 / +1,163 B) is below §4's +1.7 to 1.9 KB [P]; a regulated form 300 B larger than it needs M + L + D. The Zether
kinds: `NormalZetherToken` fits 70 M on M, 60 M on no set (gap 1,754 B on M + L + D); `WrappedZetherToken` fits neither.
`WrappedPqzToken` leaves `_above64KiB` on M (56,232 B).

Not run at T0, with reason (left to the task named): step 5's at-set runs of `PqzStateGas`, the rollscan and `debit_min_gas`
(their tests import the address-form helpers, `NamedEntry.t.sol` among them, which no longer compile: T5 re-runs R41 at all
four sets; the derived relay path's +1,993 gas is the proxy against the 6,032 margin of `n2560-kmax16384`); `MetaTxGasV2`
rows and `PlusZero` on every kind (T2); `mtxTrade` through the DEX, a relayed Zether op and a relayed PQZ op (T4, T5, T6);
invariant 7's tests and mutants on D (no module at T0: T9); a Hedera case and a router case (T8, T7).

## 10. Open questions for the owner

Seven questions; each is a reversal of an owner ruling, a departure from the owner's words, a target, scope or a wallet
test. Everything else is decided below as the controller's call. **The owner answered on 2026-11-04**: Q1 accepted, Q2–Q7
as recommended; recorded in [CTR-MTX-30](../../contracts/metatx.md#CTR-MTX-30) (SPECIFIED, nothing built). Later the same day,
after T1, the owner changed Q6 (its row, and CTR-MTX-30's Change line).

| # | Question | Recommendation | Owner, 2026-11-04 |
|---|---|---|---|
| Q1 | Accept the merge on A + B + C and its reversals: **R1** (CTR-MTX-09 "nothing merged", owner 2026-10-08), **R9** (CTR-UA-19, `owner: yes`, "every `ua*` reverts `UALedgerOff`" at registry 0; and CTR-DEX-25's C5b-2, confirmed by the owner 2026-10-13, "a padded native `from` included"), **R12** (CTR-DEX-25's display rationale, owner 2026-10-13), **R47** (the owner table's `bytes auth` exception on `uaExecute` / `uaBatch` / `uaShield`, 2026-11-01); with the follow-on rows R2, R4, R5, R7, R20–R31, R33–R39, R42–R44 | Yes: it is the owner's direction; an EOA needs no registry (R9); R47 applies the owner's explicit-parameters rule to what becomes every EOA's generic entry | **Accepted.** The merge is A + B + C. A: every pair merges, the `ua<Op>` body takes the `mtx<Op>` name. B: an EOA signs the `UA<Op>` struct with its own key (`auth.signature`), no registry call. C: a registry is needed only when a side is a derived UA. The reversals are accepted with it: R1 (CTR-MTX-09 "nothing merged"), R9 (CTR-UA-19 and CTR-DEX-25's C5b-2: at `registry() == 0` only a derived side reverts `UALedgerOff`), R12 (CTR-DEX-25's rationale: a SCaaS token leg is a `UATradeOrder`) and R47 (`UASig` on `mtxExecute` / `mtxBatch` / `mtxShield`) |
| Q2 | The signed cancel (R19): keep the ordered envelope form, `mtxCancelNonce(UAEnvelope, lane, UASig)` over `UACancelNonce(bytes32 from, uint256 lane, E)`, for native and derived subjects on tokens and the router; or the unordered `uaCancelNonce` form under the `mtx*` name, as the owner's 2026-11-03 words say literally | The ordered form. The `ua*` body cannot serve a native as built and binds no nonce: it would make every EOA's named cancel unordered (a withheld cancel kills a later operation) and leave the router with no ordered cancel at all. Soroban's `ua_cancel_nonce` stays unordered; NET-ALL-28 lets each family answer by its own mechanism, so this is not a split of the rule | **As recommended.** The ordered `mtxCancelNonce(UAEnvelope e, uint256 lane, UASig auth)` over `UACancelNonce(bytes32 from, uint256 lane, E)`, for native and derived subjects on tokens and the router; for this one pair the kept body is the `mtx*` one, departing from "the `ua*` body wins" |
| Q3 | Size (§4): target `NormalToken`, `WrappedToken` and their regulated stand-ins at the owner's 60 M and 70 M, as the gas the deploy asks (total × 1.05); the Zether kinds reported and decided later; L and D measured in this round and chosen by §4's rule; if no set in scope fits | Yes to the target and the rule. If none fits (likely for `WrappedToken` at 60 M), land the merge with the best set and keep the 60 M target open past this round with the measured gap; an out-of-scope lever only by the owner's choice then | **As recommended.** The target is to fit 60 M and 70 M, counted as deploy gas (the gas the deploy transaction asks, total × 1.05), with levers L and D chosen by §4's rule. If no lever set fits, the merge lands with the best set and the 60 M target stays open with the measured gap. The final choice is made after the §9 measurement |
| Q4 | R40: the public-chain deploy gate and fit test (NET-EVM-06) | The owner's formula stays as the testnet gate; a public deploy is gated on the measured regular + state gas × 1.05 of the release transaction, regular × 1.05 < 2^24 | **As recommended.** The public-chain deploy gate is the measured gas of the release transaction × 1.05 (regular + state, against that chain's limit; regular × 1.05 < 2^24). The testnet keeps the owner's formula |
| Q5 | A test of the display in real wallets before reset 2 (§6): two browser wallets and one hardware wallet, with a `UATradeOrder` (`destination`) and a `UARelayFee` (`payee`) row | Yes, small and manual | **As recommended.** A real-wallet display test before reset 2: two browser wallets and one hardware wallet, with the rows of §6 |
| Q6 | R32: CTR-ACC-12 (UA-5c mandate-wallet twins) | Defer it: it follows the owner's 2026-11-03 "the wallets keep the address surface"; UA-5c reopens it with merged entries as its proposal | **Changed 2026-11-04, after T1.** Old: CTR-ACC-12 is deferred; the wallets stay address-only; UA-5c reopens it with merged entries. New: the mandate wallets `MandateWallet` and `HederaMandateWallet` are built in this round in the merged form, one `mtx<Op>` per operation over `UAEnvelope`, explicit parameters with `bytes32` ids and `UASig`; a native signer (EOA or ERC-1271 code) by its own key with no registry, a derived UA through `UARegistry.requireAuthorized`; CTR-ACC-12's twins are not built; the address bodies go to `legacy/ua-mtx-merge/`; `SmartKeyAccount` stays as it is, and "the wallets keep the address surface" now means it only (§2.7, R32). Why: the merge removes twins on SCaaS contract wallets as on tokens; external wallets only display |
| Q7 | Node doors at reset 2 (R44, R45): the gateway's token doors (`/v1/op` with `UASig`, `/v1/ua-metatx` built, `/v1/metatx` refusing a token) and the mesh's `evm.ua_meta_tx` built in this round, or each refused by name until it lands | Build both in this round: gateway and mesh relaying of EVM token ops are BUILT today, and reset 2 should not drop them; the node is open, so the guarantee stays in the node | **As recommended.** Both are built in this round: the gateway token doors (`/v1/op` with `UASig`, `/v1/ua-metatx` built, `/v1/metatx` refusing a token) and the mesh's `evm.ua_meta_tx` |

**Decided by the controller** (the owner may override any; one line of reason each):

| Was | Decision | Reason |
|---|---|---|
| Q2a | The five no-twin wrap entries stay on `Envelope` with `address from` | Not pairs; each is already the one signed entry of its operation, native-only by nature |
| Q2b | `executeMetaTransaction` stays on tokens, address form, `0x47aea5b5`, `bool`; its removal is not measured | Owner ruling 2026-11-01; AGENTS.md: follow a stated rule, do not reopen it with options |
| Q3 (old) | Typed struct names keep the `UA` prefix | Type strings unchanged, so every UA-side row and client digest stays valid; only `UACancelNonce` changes (Q2) |
| Q4 (old) | The router's 19 pairs merge (R14) | The owner's words cover every pair; `_govSubject()` is unchanged for an EOA |
| Q8 | Every merged EVM entry is a `ua_metatx` job (the mandate wallets' too, Q6); `metatx` for `SmartKeyAccount` and `executeMetaTransaction`; old shapes refused by name (R43, R44) | The job shape already carries `bytes32 from` and `UASig`; the gateway's doors are Q7 |
| Q9 | R17: a native `UASig` with non-empty `keyData` or `members` is refused | Fail closed on what becomes every EOA's path, for a few bytes |
| Q10 | R18: `UA…` events only on merged paths | One event shape per path, fewer bytes; the indexer maps the topics |
| Q11 | R15, R30, R31: the one-rule sentence (with the EVM alias) in NET-ALL-28, a question row in NET-ALL-84, NET-ALL-26 re-pointed | One rule, one place; the alias written in so the rule matches the code |
| Q12 | Review: done (§12) | Fable's counter-review and Codex's security review ran on the real base `d97f5a39`; the full multi-model review stays with the contracts audit after the round |
| Q13 | Branches `token-merge` and `token-core` kept as reference, never merged; the harness is ported (§9) | Keep experiment code |
| Q15 | R41: the 2026-10-27 `roll_max` rule applies as stated; any other value move goes to the owner with old → new | Set parameters are the owner's; nothing to ask before §9 measures |
| Q17 | R46: `MetaTxLib.MetaTransfer` moves to legacy with the bodies; the non-EVM `MetaTransfer` stays | No EVM entry takes it after the merge; backup, not delete |
| Q19 | Replaced by Q2; `cancelNonce` does not join `_uaAllowed` | The row would change nothing: `cancelNonce` refuses `UA_POOL` (`MetaTxBase.sol:120-123`) |

## 11. Testnet: between reset 1 and reset 2

- **Reset 1** (after `GovernanceBase` lands; chainspec without EIP-7954, `maxCodeSize` `0x20000`): loads PR #9 and PR #10 with
  today's two forms. Clients and node built for it use the address forms.
- **This round** builds and tests locally only; nothing touches the live testnet stack.
- **Reset 2** (after this round merges): without a backup, as ruled; every kind, `DEPLOY_ZETHER=1`, the new `MtxRelayFee` and
  `GovernanceRouter` addresses, the Zether e2e (`ZetherE2E.s.sol`) and the PQZ e2e (`e2e.py`), each with an EOA relaying a
  proof under the kind's UA binding, an EOA `mtxTransfer` to an EOA and to a UA, a router op signed by an EOA, a DEX order with a SCaaS leg as
  `UATradeOrder`, Blockscout re-verification. Signatures made against reset 1's contracts do not run on reset 2 (new
  typehashes, new selectors, new addresses).
- The size targets of §4 are not tested on the testnet (its ceiling is 128 KiB and its block 200 M); they are decided by §9's
  deploy-gas measurement on a local chain.
- The contracts audit (work-order item 7) targets `main` after this round.

## 12. Review (2026-11-04)

Three reviews, in order: a Claude workflow review of the first draft (four lenses), then on the real base `d97f5a39` Fable's
independent counter-review and Codex's security review (signatures, EIP-712, §2, §5, §6, §8; source reading, nothing run).
Every finding below was checked by the controller against the code and `docs/decisions.md` before it was acted on. Nothing
here is an audit: everything cryptographic stays `UNAUDITED`.

### 12.1 Claude workflow (security, rules, blast radius, wallet display)

32 findings confirmed, all resolved; 8 not confirmed (security-1, security-2, rules-1, rules-2, rules-4, rules-5, wallet-3,
wallet-7) and not acted on; within confirmed findings, the tag-name part of rules-10 and the `deployTokenImplementation` detail of
blast-2 were refuted. Question numbers in this table are the first draft's; §10 renumbered them after §12.2 and §12.3.

| Id | Severity | Resolution |
|---|---|---|
| security-3 | major | §8 invariant 7 and risk 16 for lever D (hash pin, opcode check, non-payable fallback, no `isValidSignature`, no self-call reach, mutant); §4 lever row and Q5 tie D to it |
| security-4 | minor | R19 states that `UACancelNonce` binds no nonce, names the ordered form, proposes `cancelNonce` on `_uaAllowed` (Q19); invariant 3 adds both tests |
| security-5 | minor | Invariant 4 restated per operation, with the fee-carrying entries listed; Goal 2 follows |
| rules-3 | major | R20–R29 cover CTR-MTX-01, -05/-06, -11, -12, -18, -21, -22, -26, -27, -29; §7 Docs lists them |
| rules-6 | major | R30 rewrites NET-ALL-26, R31 NET-ALL-28 (with the one-rule sentence); R15 is a question row only |
| rules-7 | major | The one-rule text names per chain which subjects the signed entry takes (§1, R31) |
| rules-8 | major | R32 and Q16 put CTR-ACC-12 to the owner; §1 non-goal names it |
| rules-9 | major | R33 (CTR-TND-01), R34 (CTR-AS-13); MetaTransfer's fate is owner row R46 / Q17, not a grep |
| rules-10 | major | R35 (CTR-ZTH-06, -34, -51) and R36 (CTR-PQZ-21); §2.1 and §3.3 name both UA tags |
| rules-11 | major | R12 cites CTR-DEX-26; R37 (CTR-DEX-13), R38 (CTR-DEX-15), R39 (CTR-TOK-20) added |
| rules-12 | major | §4 thresholds use the × 1.05 fit test; R40 rewrites NET-EVM-06 for public chains |
| rules-13 | major | R43 (OP_KIND_MISMATCH), R44 (step 7a, gateway gate), R45 (mesh); Q8 rewritten |
| rules-14 | minor | §7 Docs row extended (settlement, tender, asset-suite, mandates, hedera, evm, node docs, signers-clientkeys); R42 for Hedera |
| blast-1 | major | R41, Q15, §9 step 5 (rollMax test, rollscan, debit at four sets); registry non-goal qualified; §7 set-parameter row |
| blast-2 | major | §4 thresholds ≈35.6 / 41.5 KB and verdicts recomputed; §9 step 3 uses `test_releaseGasPerKind` plus the factory frame |
| blast-3 | major | The gate formula is the owner's: R40 and Q14, not "a tool fix"; gate code listed in R40 |
| blast-4 | major | Mesh in §7 Node, R45, Q18 and the operator note |
| blast-5 | major | §3.4 scopes the node DEX's UA intake as new work; §7 lists `dex.rs`, routes, typed-row split, operator note |
| blast-6 | major | §2.1, §2.3, §7 state Q2a's five new structs and rows, native-only; Q3 qualified |
| blast-7 | major | §7 Vectors lists the real address KATs and consumers; `paymeta.json` / `relayref.json` stated unchanged |
| blast-8 | major | §3.1: the router changes under every option, its generic entries and cancel stated; Q4 only for the 19 pairs |
| blast-9 | major | §7 Scripts and config row; §11 names the e2e scripts |
| blast-10 | minor | §7 Node adds `adapter.rs`, `chain.rs`, `tests/e2e.rs`, `tests/e2e_hedera.rs` and the per-kind nonce view |
| blast-11 | minor | §7 Clients replaced with the real `clientkeys` and `zether-prover` files; `ua-*` stated unchanged but for the renderer |
| blast-12 | minor | §7 Docs extended and a recount by grep of `docs/` stated |
| blast-13 | minor | §7 Contracts adds `ZetherLayer`, `MetaTxLib`, `ISCaaSDex`, `HederaAccountAuth`; Tests adds the `MsgSenderLint` pin (R24) |
| wallet-1 | major | Same as blast-6, plus the wrap display in §6 and Q2a defaulting to no move |
| wallet-2 | major | The alias recommendation is dropped; Q2b gives the owner's two positions, the ruling stands by default (R3) |
| wallet-4 | major | R12 quotes CTR-DEX-25's rationale and is marked Reversed; Q1 lists it as a reversal |
| wallet-5 | minor | §6 lists every address → `bytes32` field per struct and the poisoning effect; Q7 adds `destination` and `payee` rows |
| wallet-6 | minor | §6 marks the `bytes32`-id renderer as new work, not a mitigation; §7 Clients lists it |
| wallet-8 | minor | Q12 follows TODO: Fable and Codex after PR #9 on the real base, Codex's scope includes §6 |

### 12.2 Fable (counter-review)

1 blocker, 6 major, 6 minor; all confirmed against the code, all acted on (M3 in part, see its line).

| Id | Severity | Resolution |
|---|---|---|
| B1 | blocker | Confirmed (`MetaTxBase.sol:120-123` refuses `UA_POOL`; the router's generic path refuses every call). With Codex 2: the cancel keeps the ordered body widened to `bytes32`, `mtxCancelNonce(UAEnvelope, lane, UASig)`, on tokens and the router; no `_uaAllowed` row; unordered form to legacy (§2.1, §3.1, R19, invariant 3, risk 5, Q2) |
| M1 | major | Confirmed (`gateway.rs` has `/v1/metatx` and `/v1/op` only; `/v1/op` refuses `ua*`). R44 names the doors: `/v1/op` with `UASig`, `/v1/ua-metatx` built, `/v1/metatx` refusing a token; scope in Q7 with the mesh; §7 Node and Job shape say it |
| M2 | major | Confirmed (CTR-UA-19 `owner: yes`; C5b-2 at CTR-DEX-25). R9 marked Reversed with both sources; listed in Q1 |
| M3 | major | Held for `executeMetaTransaction`: the EVM alias is written into the NET-ALL-28 sentence (§1, R31) and the tender's BUILT transitional path into R3. Not taken for the wraps: each is still the one signed entry of its operation, so the per-operation rule holds without a per-struct phrasing |
| M4 | major | §4 step 4: if no set in scope fits, §9 reports the gap and the owner rules (Q3), with a recommendation; 60 M / 70 M cited as the owner's targets (TODO 2026-11-03), the "Ethereum's block" claim removed |
| M5 | major | With Codex 1: invariant 7 forbids `CALL` and `CALLCODE` outright, `STATICCALL` only; mutants with a zero-value `CALL` and a `CALLCODE`; risk 16 |
| M6 | major | §10 cut to seven owner questions; twelve former questions decided as the controller's calls with one-line reasons and Q19 replaced by Q2; Q2b not reopened; §2.6 relabelled as measured data, not a menu; A2 out of scope (§4) |
| m1 | minor | R47: `mtxExecute` / `mtxBatch` / `mtxShield` take `UASig`; it reverses the owner table's `bytes auth` exception, so it is marked Reversed and listed in Q1; R17 then holds on every merged entry |
| m2 | minor | B's reason restated: a derived subject reads `_uaAllowed` only (§2.1, §2.6, invariant 6, mutant `derived-off-ua-list`); the EOA convenience is a note |
| m3 | minor | R42: `from` is the account's EVM address, long-zero for ED25519, the alias for ECDSA |
| m4 | minor | Zether and PQZ separated: §2.1 two bullets, §3.3 two parts, §11 two e2e runs, §1 non-goal |
| m5 | minor | §9: the regulated stand-in is a scratch copy, not committed; `GovGas` at `registry() == 0` and `≠ 0`; L measured alone first; the §7 recount replaces §7 |
| m6 | minor | Closed by B1: the node keeps its named-entry default, the cancel is a named entry |

What Fable confirmed sound: A + B + C as the base; no native / derived collision (`inNativeSpace`, `UAIdInNativeSpace` at
registration, `_authorizeNative`'s refusals); no registry call for an EOA and one `kindOf` for a derived receiver; R35 / R36
change the binding value only; no cross-form replay on the one lane map; `_msgSender()` unchanged; the router's subject for an
EOA unchanged; §4's arithmetic within ~0.3 KB of a two-point fit; CTR-GOV-11 "+0"; ciphertext, layout, EIP-7702, zero-gas,
backup-not-delete and no-upgrade untouched; §6 stated honestly; no migration work claimed.

### 12.3 Codex (security, signatures, EIP-712)

1 high (conditional on lever D), 3 medium; all confirmed against the code, all acted on.

| Id | Severity | Resolution |
|---|---|---|
| 1 | high | Resolved with Fable M5 (invariant 7: no `CALL`, no `CALLCODE`, `STATICCALL` only; a zero-value state-changing `CALL` mutant; the executor and the DEX use plain `call`, named; the module source reviewed by hand) |
| 2 | medium | Resolved with Fable B1 (the ordered, `bytes32`-widened cancel covers natives, derived ids and the router; the `ua*` body's native refusal no longer matters, since it goes to legacy) |
| 3 | medium | Invariant 2 is stated over the canonical signed intent, the unbound `relayer` / `feeRecipient` routing named as the exception; §6 adds the client rules (canonical 0 in the signed message, "any relayer" / submitter's fee choice on screen, a restriction bit to promise a recipient); R6; tests with non-zero unbound values |
| 4 | medium | Invariant 3 lists the retired forms and the two retained ones (`MetaTransaction` through `executeMetaTransaction`, the wraps' `Envelope`); an old `mtxExecute` signature runs through the alias by design; `executeMetaTransaction` keeps the address proof binding, the merged entries the UA one (§2.1, §3.3, R3, risk 9); tests on both entries and both tags |

What Codex confirmed sound (observations, not proofs): no native / derived collision (registration refuses a native-space
id; authorization and ledger dispatch use the same test); salted domains separate chains and contracts, the router's domain
is distinct and signs `target`; address and UA type strings, DEX order and cancel types and the portable records do not
collide; derived authorization checks key data against the id and wraps the digest with kind and purpose; ECDSA, ERC-1271
(gas floor and cap, static call, exact magic) and designators are separated in `SigCheck`; HIP-632 is guarded by the flag,
the length and the non-contract test (designators included, now said in §2.1); meta-transaction nonces and unordered cancels
are separate stores, and DEX orders keep their own floor (a meta-tx cancel does not cancel trade orders); ciphertext stays in
state on both confidential families; the regulated-hook bypass through `_uaMove` is already in §2.1 and §8.

