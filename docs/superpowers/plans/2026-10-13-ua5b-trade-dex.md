# UA-5b — trade and DEX for Universal Accounts: `UATradeOrder`, purpose `trade`, `TradeLib` on ids, `uaTrade` / `uaCancelOrder` / `uaInvalidateNonces`, verify once, `uaWrap`, `SCaaSDex` tagged legs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Status: BUILT, awaiting owner review (2026-10-13; Tasks 1–8 committed, Final below).** Branch `ua5b` from `main` `279b5d8`, worktree `.claude/worktrees/ua5b`. One commit
per task; the controller merges after the owner approves. Rulings R5b-1…R5b-n restate the accepted design where it is
exact; the implementer's own choices where the design leaves room are C5b-1…C5b-n (recorded, not blocking).

**Goal:** the UA-5b row of the UA-5 stream (`TODO.md`; owner 2026-10-13): the trade axis of UA parity
([accounts.md](../../contracts/accounts.md) CTR-UA-27, [dex.md](../../contracts/dex.md) CTR-DEX-25, CTR-DEX-26,
[token-wrappers.md](../../contracts/token-wrappers.md) CTR-TOK-20 `uaWrap`). A UA (any SIGNING kind, PQ included; a
native id zero-padded too) signs a `UATradeOrder` in the sell token's domain under the new purpose `trade`; the token
verifies it (`uaTrade`, only `o.dex` calls) and moves the fill by `_uaMove`; `SCaaSDex` takes tagged legs (shape 0
`TradeOrder`, shape 1 `UATradeOrder`) in one book, pays derived parties by `transferToUA`, re-raises `UAVerifyGas`;
`uaWrap` wraps a SCaaS ledger underlying by a `UATradeOrder` and mints into a UA. Gate: the new suites green, the DEX
conservation invariant with UA handlers (0 reverts), the full forge suite (default and `private7622`), the size gate,
the six UA libraries and clientkeys on the new purpose and typed data.

**Not here:** UA-5c (Zether public side, the UA pipeline in `MetaTxBase`, `MandateWallet`); the node's UA order intake,
`bytes32` book / TradeEngine, settlement packing by kind caps and PQ order gossip (after UA F5, `TODO.md` UA-5b: "the
node part after UA F5"; C5b-11); size work (Glamsterdam); any chain action.

**Architecture.** `TradeOrder` and `UATradeOrder` are both 13 static ABI words in the same order; a native id is its
address zero-padded. So the one internal form is `UATradeOrder memory`: a `TradeOrder` is copied to memory and its
pointer read as a `UATradeOrder` (no field moves; the address words are already validated). `TradeLib`'s `precheck`,
`record`, `cancel`, `invalidate` take that form; `minNonce` is keyed `bytes32` (the same slots for an address and its
padded id), so `mtxInvalidateNonces(a, b, n)` and `uaInvalidateNonces(pad(a), b, n)` raise one floor. The events follow
the entry point (`TradeFilled` / `UATradeFilled`, …). The token checks the signature unless `pulled[h] ≠ 0` (UP-12) —
`_requireValidSignature` on `mtxTrade`, `_uaAuthorize(from, PURPOSE_TRADE, h, auth)` on `uaTrade` — and moves by
`_transfer` / `_uaMove(from, pad(dex), move)`. The DEX decodes each leg's `bytes order` into the same form (shape 0 by
`abi.decode(order, (TradeOrder))`, shape 1 by `abi.decode(order, (UATradeOrder))`) and runs today's logic once; the
shape picks the hash, the pull (`mtxTrade` / `uaTrade` / the puller), and the event; a party's payout goes by
`safeTransfer` to a native id and by `IUALedger(token).transferToUA` to a derived one.

```mermaid
sequenceDiagram
    participant N as Relayer
    participant D as SCaaSDex
    participant A as Sell token A (ledger on)
    participant R as UARegistry
    participant B as Receive token B
    N->>D: mtxSettle([taker shape 1, maker shape 0])
    D->>A: uaTradeOrderDigest(o) / uaTrade(o, auth, fill)
    A->>R: requireAuthorized(from, trade, h, auth) (skipped when pulled[h] ≠ 0)
    A->>A: TradeLib.record; _uaMove(from, pad(D), sellFill)
    D->>B: mtxTrade(maker order, sig, fill)
    D->>B: transferToUA(taker destination, received)
    D->>A: transfer(maker destination, received)
    D->>D: fee split, conservation per token
```

**Tech stack:** Solidity 0.8.37, Foundry (osaka), OpenZeppelin 5.2; Node 22 (clientkeys, `@noble/post-quantum` 0.7.1);
Rust (scaas-node, `ua-rs`), Python, Go, .NET, Dart for the six UA libraries.

**Spec:** `docs/contracts/dex.md` CTR-DEX-13, -15 (step 4, `minNonce` by id), -16, -23, CTR-DEX-25, CTR-DEX-26;
`docs/contracts/accounts.md` §1.6 purposes (`trade`), CTR-UA-14, -19, -26, -27; `docs/contracts/token-wrappers.md`
CTR-TOK-20 (`uaWrap`); `docs/contracts/metatx.md` CTR-MTX-18 (the `msg.sender` set); design record
`docs/history/specs/2026-10-13-ua-parity-design.md` §4.3, §4.6, §4.7, §4.15–§4.18, §7 row UA-5b.

**Base (main `279b5d8`):** forge default 97 suites, 1157 passed (TODO UA-5a, merge `04bad29`; later commits docs only);
`size-baseline.json` as of UA-5a.

## Global constraints

- Worktree `.claude/worktrees/ua5b` (symlinks `smartcontracts/evm/lib`, `clients/clientkeys/node_modules` to the main
  checkout's); `/usr/bin/git`; heavy commands (forge, cargo, dotnet, big node runs) only through `scripts/capped`, one at
  a time machine-wide; `dotnet build-server shutdown` after a capped `dotnet`.
- TDD per task: the test first (red: compile error or failing assertion), then the code (green); one commit per task.
- Vector files are generated, never hand-edited; existing keys of every vector file stay byte-identical (insertions
  only); `kinds.json` gains only the `trade` rows.
- No size optimisation (owner: Glamsterdam); the size gate passes with the new sizes recorded in `size-baseline.json`.
- No chain-7622 or public-chain action; nothing deployed changes (all chains are test chains). Never merge, never push.
- SPDX header on every new source file; commit trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review focus

- **One floor per id.** `minNonce` keyed `bytes32` at the same slots; `mtxInvalidateNonces` and `uaInvalidateNonces`
  share it both ways; a `UATradeOrder` from a padded native and a `TradeOrder` from the address hit the same floor.
- **Verify once.** The signature check is skipped only when `pulled[h] ≠ 0`; `h` binds every field (digest over the
  struct in the token's domain); a first pull and every cancel always verify.
- **Funds move only into `o.dex`.** `uaTrade` moves exactly `record`'s amount from `o.from` to `pad(o.dex)` through
  `_uaMove` (a derived seller: `Transfer(UA_POOL, dex)` + `UATransfer`); `UA_POOL` stays Σ of the UA balances.
- **DEX conservation with UA parties.** `transferToUA` lowers the DEX's own `balanceOf` exactly as `safeTransfer`;
  `ConservationBroken` unchanged; a shape-1 leg in an outside or ledger-off token reverts `UALegNotLedger` before any
  pull; a derived payout in a non-ledger token `UAReceiveNotLedger`.
- **Starvation is the submitter's.** `UAVerifyGas` from any leg reverts the whole `mtxSettle`, never `MatchFailed`.
- **Interactions.** `uaTrade`'s selector refused as `mtxTrade`'s (the DEX is `o.dex` of every order).

## Rulings restated from the accepted design (R5b)

- **R5b-1 Struct and typehashes** exactly as CTR-DEX-25: `UATradeOrder(bytes32 from,address receiveToken,uint256
  amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,bytes32 destination,uint8
  flags,uint256 batch,uint256 nonce,uint256 validUntil)`, `UAInvalidateNonces(bytes32 from,uint256 batch,uint256
  minNonce)`; cancel = the existing `CancelOrder(bytes32 orderHash)` over the UA order hash.
- **R5b-2 Purpose `trade`** = `keccak256("scaas.ua.purpose.trade.v1")` in `UAKinds` and the six UA libraries
  (`ua-rs`, `ua-py`, `ua-go`, `ua-cs`, clientkeys `ua.js`, `ua-dart`; the bindings `ua-c`, `ua-cxx`, `ua-qt`,
  `ua-dart-frb` take it from `ua-rs`), `kinds.json` regenerated (appended).
- **R5b-3 `uaTrade`** = CTR-DEX-15 steps 1–8 with `o.from ≠ pad(this)` (`SelfOrder`), step 4 by `_uaAuthorize` under
  `trade`, the move by `_uaMove`; `uaCancelOrder` never expires; `uaInvalidateNonces` strictly up, `2^128` cap; views
  `uaTradeOrderDigest`, `uaInvalidateNoncesDigest`, `uaMinNonce`; events `UATradeFilled`, `UAOrderCancelled`,
  `UANoncesInvalidated`.
- **R5b-4 UP-12** on both paths and the DEX's outside legs.
- **R5b-5 `uaWrap(address u, UATradeOrder o, bytes auth)`** = `mtxWrap` with the order pulled by the underlying's
  `uaTrade`; underlying a SCaaS ledger token (`UALegNotLedger(u)`); `minted − wrapFee` to `o.destination` (0 ⇒
  `o.from`): derived ⇒ `_uaMint`, native ⇒ `_mint`; `wrapFee` to `msg.sender`; event `UAWrapped(bytes32 indexed from,
  address indexed u, uint256 received, uint256 minted)`. Not allowlisted.
- **R5b-6 DEX** exactly CTR-DEX-26: `Leg {sellToken, shape, order, sig, fill}`, `ExchangeLeg {sellToken, shape, order,
  sig, sellFill, receiveFill}`; shape-1 leg kind (`UALegNotLedger`), pull by `uaTrade`, self-trade over ids, payouts and
  Path B refunds to derived ids by `transferToUA` (`UAReceiveNotLedger`), fee shares to addresses, events
  `UALegSettled` / `UAExchangeLegSettled`, `UAVerifyGas` re-raised, `uaTrade` refused in interactions.

## Controller rulings (C5b, implementer's choices)

- **C5b-1 One internal form.** `TradeLib`'s public functions take `ITradeToken.UATradeOrder memory`; a `TradeOrder` is
  copied to memory and its pointer read as a `UATradeOrder` (`TradeLib.core`). Events by entry point (a `bool ua`
  argument). `hashStruct` / `hashStructUA` take memory.
- **C5b-2 Ledger on.** `uaTrade`, `uaCancelOrder`, `uaInvalidateNonces` revert `UALedgerOff` while `registry() == 0`,
  as every `ua*` function, a padded native `from` included (it uses `mtxTrade` there).
- **C5b-3 `SelfTrade(bytes32 from)`** (was `address`): an id; ABI change, nothing deployed; the node ABI follows.
- **C5b-4 `LegShapeUnknown(uint8 shape)`** for a shape other than 0 or 1 (new error).
- **C5b-5 Ledger test on the DEX** = the listing: `tokenKind == SCaaS` and `IUALedger(token).registry() ≠ 0` (a SCaaS
  token is factory-made, so `registry()` exists); not ERC-165.
- **C5b-6 Derived destination** is checked by the receive token's own `transferToUA` at the payout
  (`UANotRegistered` / `UAKindNotAccepted` revert that settlement: `MatchFailed`); the DEX does not pre-check it.
- **C5b-7 Shape-0 decode** by `abi.decode(order, (TradeOrder))` (address words validated); trailing bytes after the 13
  words are ignored (the hash is over the decoded fields).
- **C5b-8 Placement.** `UATradeOrder`, the `ua*` trade functions and events in `ITradeToken`; `uaWrap`, `UAWrapped` in
  `IUnderlyingToken`; `UALegNotLedger` (also in `IUALedger`), `UAReceiveNotLedger`, `LegShapeUnknown`, `UALegSettled`,
  `UAExchangeLegSettled` in `ISCaaSDex`.
- **C5b-9 `uaWrap` events**: `UAWrapped` only (plus `Transfer` / `UATransfer`), no `Wrapped`; the leg check is
  `ERC165Checker` on `IUALedger` (as `payOutToUA`), before the pull.
- **C5b-10 Test shim.** `test/helpers/DexLegs.sol` keeps the existing DEX suites' address-shaped legs and wraps them
  into shape-0 tagged legs at the call (`wire`); the UA suites build tagged legs directly.
- **C5b-11 Node.** In UA-5b: the tagged-leg ABI (shape 0) in `abi.rs` / `dex.rs`, `SelfTrade(bytes32)`, `UALegSettled`
  decoded and indexed (`dex_fill_ingest` event `UALegSettled`, the book's `settled`). After UA F5 (TODO): UA order
  intake, the `bytes32` book and committed balance from `balanceOfUA`, packing by the kinds' caps, PQ order gossip.
- **C5b-12 Vectors.** `smartcontracts/vectors/ua/uatrade_kat.json` by `clients/clientkeys/scripts/ua-trade-vectors.mjs`
  on the `metatx3.json` keys and context: classical rows (native ECDSA, `p256`, `bip340`, `ed25519`) and PQ rows
  (`mldsa65` ×3 for the caps); order, cancel, invalidate digests and auths; a fixed DEX and token pair.
- **C5b-13 clientkeys.** `uaTradeOrderTypedData`, `uaInvalidateNoncesTypedData`; the UA cancel is
  `orderCancelTypedData({orderHash})` over the UA order hash (unchanged); `checkTradeOrder` gains `ua: true` (the order
  is a `UATradeOrder`, `account` an id).
- **C5b-14 Sizes.** Measured after Task 4: `SCaaSDex` 23,493 (+1,627) stays under 24,576, so it does not join
  `size-baseline.json` (the design estimated + 4–6 K); the token implementations ratchet in `size-baseline.json`;
  the `UNDERLYING` pin in `Factory.t.sol` / `HederaV2.t.sol` 45,056 → 49,152 (as C5a-9).

## File map

| File | Change | Task |
|---|---|---|
| `smartcontracts/evm/src/ua/UAKinds.sol`, `test/ua/UAKinds.t.sol` | `PURPOSE_TRADE` | 1 |
| `clients/{ua-rs,ua-py,ua-go,ua-cs,ua-dart}`, `clients/clientkeys/src/ua.js`, `smartcontracts/vectors/ua/kinds.json` | purpose `trade` | 1 |
| `smartcontracts/evm/src/trade/ITradeToken.sol`, `TradeLib.sol` | `UATradeOrder`, ua functions/events; the id core | 2 |
| `smartcontracts/evm/src/metatx/ERC20MetaTx.sol` | `uaTrade`, `uaCancelOrder`, `uaInvalidateNonces`, views; UP-12 | 2 |
| `smartcontracts/evm/test/ua/UATrade.t.sol` (new) | CTR-DEX-15 matrix on the UA shape, floors, UP-12 | 2 |
| `smartcontracts/evm/src/metatx/UnderlyingLib.sol`, `IUnderlyingToken.sol`, `UnderlyingToken.sol` | `uaWrap` | 3 |
| `smartcontracts/evm/test/ua/UAWrap.t.sol` (new) | `uaWrap` | 3 |
| `smartcontracts/evm/src/dex/ISCaaSDex.sol`, `SCaaSDex.sol` | tagged legs, UA payouts, `UAVerifyGas`, interactions | 4 |
| `smartcontracts/evm/test/helpers/DexLegs.sol` (new), `test/v2/Dex*.t.sol` | shim | 4 |
| `smartcontracts/evm/test/ua/UADex.t.sol` (new) | mixed settlements, self-trade by id, refunds, errors, exchange | 4 |
| `smartcontracts/evm/test/ua/UADexInvariant.t.sol` (new) | conservation with UA handlers | 5 |
| `clients/clientkeys/src/evm.js`, `scripts/ua-trade-vectors.mjs` (new), tests; `smartcontracts/vectors/ua/uatrade_kat.json` | typed data, vectors | 6 |
| `smartcontracts/evm/test/ua/UATradeVectors.t.sol` (new) | the rows on chain; PQ caps | 6 |
| `scaas-node/src/abi.rs`, `src/dex.rs`, `src/dex/venue.rs` | tagged legs, `UALegSettled` | 7 |
| `docs/contracts/*.md`, `docs/decisions.md`, `TODO.md` | BUILT, numbers | 8 |

## Tasks

### Task 1: purpose `trade`

- [ ] `UAKinds.PURPOSE_TRADE`; `UAKinds.t.sol` purpose list; `trade` appended to the six libraries' purpose lists;
  `node scripts/ua-vectors.mjs` regenerates `kinds.json` (two rows appended, nothing else changes; a second run is
  byte-identical). Tests: forge `UAKinds`, clientkeys `ua.test.js`, `ua-rs` (cargo), `ua-py`, `ua-go`, `ua-cs`, `ua-dart`.
- [ ] Commit `feat(ua5b): purpose trade in UAKinds, the six UA libraries and kinds.json`.

### Task 2: `TradeLib` on ids; `uaTrade`, `uaCancelOrder`, `uaInvalidateNonces`; UP-12

- [ ] Tests first (`test/ua/UATrade.t.sol`): every CTR-DEX-15 error on the UA shape (`NotDex`, `DexNotContract`,
  `SelfOrder` (from = pad(token), dex = token), `WrongRelayer`, `OrderExpired`, `NonceInvalidated`, `BadFlags`,
  `ZeroAmount`, `BadMinFill`, `FeeAboveCap`, `OrderClosed`, `ZeroFill`, `Overfill`, `BelowMinFill`, `PriceLimit`,
  `FeeAboveSigned`, `EscrowFillShape`); derived (`p256`, `bip340`) and padded-native signers; wrong purpose refused;
  `UALedgerOff`; the move and its events; UP-12 (second fill passes with a garbage auth; first fill does not; same on
  `mtxTrade`); cancel (never expires, idempotent, wrong signer); invalidate (strictly up, cap, shared floors both ways).
- [ ] Code; `Trade.t.sol`, `TradeKat.t.sol`, `DexOutside.t.sol` stay green; `MsgSenderLint` pin `ERC20MetaTx` 7 → 8.
- [ ] Commit `feat(ua5b): UATradeOrder on the token — TradeLib on ids, uaTrade/uaCancelOrder/uaInvalidateNonces, verify once`.

### Task 3: `uaWrap`

- [ ] Tests first (`test/ua/UAWrap.t.sol`): derived and native holders, derived / native / zero destination, fee to
  the submitter, `UALegNotLedger` (outside leg), `NativeNotGasless`, `WrapOrderInvalid`, wrong purpose, the reserve.
- [ ] Code; `MsgSenderLint` pin `UnderlyingToken` 2 → 4; sizes.
- [ ] Commit `feat(ua5b): uaWrap — wrap a SCaaS ledger underlying by a UATradeOrder into a UA`.

### Task 4: `SCaaSDex` tagged legs

- [ ] `DexLegs` shim and the existing DEX suites through it (green before the UA suite); `DexKat` rewritten
  (`WRITE_KAT`), the node KAT reader follows in Task 7.
- [ ] Tests first (`test/ua/UADex.t.sol`): UA taker × native makers and the reverse, UA × UA, native shape 1 (a padded
  id with a UA destination), self-trade by id (shape 0 vs padded shape 1), `UALegNotLedger` (outside sell token,
  ledger-off token), `UAReceiveNotLedger`, a derived destination unregistered (`MatchFailed`), Path B refund to a UA,
  fee shares, `UALegSettled` fields, `LegShapeUnknown`, `UAVerifyGas` re-raised (whole call), `uaTrade` refused in an
  interaction, the exchange path with a UA leg receiving surplus (`UAExchangeLegSettled`), conservation.
- [ ] Code; sizes into `size-baseline.json` (tokens; the DEX fits, C5b-14).
- [ ] Commit `feat(ua5b): SCaaSDex tagged legs — UA orders in one book, UA payouts and refunds, UAVerifyGas re-raised`.

### Task 5: DEX conservation invariant with UA handlers

- [ ] `test/ua/UADexInvariant.t.sol`: handlers settle random matches (native / derived taker and maker, Path A and B,
  shape 0 and 1, both directions) and the exchange path; invariants: the DEX holds nothing between calls, Σ UA balances
  == `balanceOf(UA_POOL)` per token, supply constant; 0 reverts.
- [ ] Commit `test(ua5b): DEX conservation invariant with UA handlers`.

### Task 6: vectors and clientkeys

- [ ] `uaTradeOrderTypedData`, `uaInvalidateNoncesTypedData`, `checkTradeOrder({ua})`; `scripts/ua-trade-vectors.mjs`
  writes `uatrade_kat.json`; JS tests verify the classical rows with noble and the PQ rows with `@noble/post-quantum`;
  `test/ua/UATradeVectors.t.sol` recomputes every digest on chain and passes every auth through the real verifiers; the
  PQ caps: a settlement with two `mldsa65` legs fits 16,777,216 (intrinsic and calldata included), three do not and
  the call reverts `UAVerifyGas`.
- [ ] Commit `feat(ua5b): uatrade_kat.json, clientkeys UATradeOrder typed data; PQ legs at the caps`.

### Task 7: node — tagged legs and `UALegSettled`

- [ ] `abi.rs` (`Leg`, `ExchangeLeg` tagged, `UATradeOrder`, `SelfTrade(bytes32)`, `UALegSettled`), `dex.rs`
  `to_settlement` (shape 0), `venue.rs` (watcher filter and `encode_event`), the KAT test on the new `settle_calldata`.
  `cargo test` (capped).
- [ ] Commit `feat(ua5b): node — tagged DEX legs (shape 0) and UALegSettled indexing`.

### Task 8: docs

- [ ] dex.md CTR-DEX-25/26 (+ -15 step 4, `minNonce`, -16, -23) BUILT with numbers; accounts.md purpose `trade`,
  CTR-UA-14 / -19 / -26 / -27 status, §1.7 rows; token-wrappers.md CTR-TOK-20 `uaWrap` BUILT; metatx.md CTR-MTX-18
  set; decisions.md dated records (built as ruled; C5b rulings that touch a rule); TODO UA-5b ticked with the merge
  placeholder. `docs_check.py check` and `facts check` 0 errors.
- [ ] Commit `docs(ua5b): UA trade and DEX BUILT; TODO`.

### Final

- [ ] forge default and `private7622` (all suites), `test/ua`, invariants, `UAGas` / `UARegistryGroups` `--isolate`,
  the size gate; clientkeys; the six libraries; `cargo test` in scaas-node; docs checkers. Mutations on the settlement
  and accounting lines (apply, run, revert). Self-review against the design row.

**Results (Final, 2026-10-13).** forge default 102 suites, 1196 passed / 0 failed / 10 skipped; `private7622` the same;
`test/ua/**` 31 suites, 320 passed; `--isolate` `UAGas` 6, `UARegistryGroups` 14; size gate 0 errors, 84 contracts
(`SCaaSDex` 23,493 B fits; NONE 35,272, UNDERLYING 45,132, NONE_ZETHER 43,624, UNDERLYING_ZETHER 55,528 / init 57,223,
`UnderlyingLib` 13,016, `TradeLib` 3,369). scaas-node `cargo test` 279 passed, e2e (EVM, anvil) 4/4, clippy
`-D warnings` clean; settle selector `0x0403b13c` (solc). clientkeys 109 / 107 / 2 skipped; `ua-vectors.mjs`,
`ua-sig-vectors.mjs` and `WRITE_KAT` `DexKat` regenerate byte-identical. Docs checkers 0 errors, facts 0 misses.
Mutations (applied, run, reverted; each killed): `_uaMove` amount in `uaTrade` − 1 (23 fail); `pulled[h] == 0` →
`!= 0` on `uaTrade` (8) and `mtxTrade` (7), always verify on `uaTrade` (3); `_sendTo` without the ledger check (1) and
with the native branch negated (68); `_payLeg` refund to `to` (3) and dropped (5); `uaWrap` destination → `o.from`
(3); `UAVerifyGas` not re-raised (2).

