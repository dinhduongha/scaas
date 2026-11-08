> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# EVM library organisation for 60 M per contract (T66b part 4 study)

Written 2026-11-08 for plan task T66b part 4 (`docs/superpowers/plans/2026-11-04-ua-mtx-merge.md`, branch `ua-mtx-merge`,
tree `937b454f`). It measures, proposes and asks; nothing in `src/` changed, and every spike was built in a scratch
worktree of that tree. Harness, outputs and spike patches: `smartcontracts/evm/runs/2026-11-07-ua-mtx-merge-size-study/`.
Forge 1.8.5, solc 0.8.37, optimizer 200, legacy code generation, Amsterdam, default set `n2304-kmax4096`. Gas figures are
paper arithmetic or forge's ordinary deterministic figures; nothing here is a timing or gas calibration. Everything
cryptographic in these contracts stays **UNAUDITED**.

Tags: [repo] read from the tree; [measured] a build or forge run of this study (or a cited run file); [inference] follows
from measured facts; [estimate] an arithmetic range.

## 1. Result

- **Today's organisation cannot reach 60 M.** At `937b454f` only `NormalToken` (55.9 M asked) and the DEX (57.3 M) of the
  release contracts fit; with the groups still to land (chain-neutral, 3f, 3h), `NormalToken` asks about 57.7 M and every
  other kind 70.7–115.6 M [measured + estimate]. The owner's two suggestions alone, a pay library and a `TradeLib` split, free
  5.8–8.3 KB per kind [measured] and leave 10 of 12 kinds above the line.
- **The token's floor is low.** A token that keeps its whole ABI, every entry a typed stub that only forwards its calldata,
  is 7.0 KB (`NormalToken`, 84 entries) to 15.6 KB (`WrappedPqzRegulatedToken`, 178 entries), about 80–90 B per entry
  [measured]. Variant A (the token keeps its entry points, the body runs by DELEGATECALL) is therefore not what blocks 60 M:
  the bodies left in the token are.
- **The form that reaches 60 M:** each entry keeps its signature, modifiers and the one guard in the token, and its body
  becomes one forward of the unchanged calldata by DELEGATECALL into a **body module**, a contract compiled from the same
  token bases (same storage layout by construction, same hooks by override), reached only by DELEGATECALL. Measured on every
  kind at once: with every body out except the ERC-20 core, the tokens are **12.7–26.0 KB** (22–45 M asked), kind 13 included
  [measured]; with growth, **12.9–27.7 KB, at most 47.2 M** [estimate]. The bodies fit in 3–5 modules per kind of at most
  **33.3 KB** each, upper bound with growth (≤ 56.3 M) [measured + estimate].
- **Gas:** small hot paths stay about neutral when each entry forwards into the module that also holds the library code it
  calls today (one cold account per operation, as now): `mtxTransfer` −1.1 to −0.2 k, `mtxPay` −1.5 to −0.3 k; ERC-20
  `transfer` unchanged. Proof-carrying PQZ ops pay two more calldata copies: about +8 k on a 21 KB op (+0.2 %), up to about
  +0.5 M on a 340 KB op (+4.8 %), +0.27 M with the mitigation of §5.5 [estimate]. Same ABI: no node or client change.
- **This is the large form of T9's lever L,** deprecated by the owner on 2026-11-05 on T0's figures (≈ 2 KB per kind for
  +7.5 k gas per relayed transfer, `runs/2026-11-04-ua-mtx-merge/results.txt`). The forward form avoids both of T0's costs
  (no re-encoding, no extra cold account), but reusing L needs the owner's word: question 1 (§11).
- **`UARegistryLib`** is the one library over the line (37,536 B, 63.1 M asked). With `UARegistry`, the pair has about
  0.9–1.6 KB of room in total at 60 M after T66b's two registry items: part 3's rebalance can fit both, without margin
  [estimate]. Question 3.

## 2. What 60 M buys

`asked = (regular + state) × 1.05` (T10's formula; EIP-8037 inclusion: a transaction fits only if its regular plus state gas
fits the block, never by a block's `gas_used`). Fitted on T10's and T33's measured release rows
(`runs/2026-11-04-ua-mtx-merge-deploy-gas.txt`, `…-regulated-deploy-gas.txt`) [measured]:

| Deployment | state gas | regular gas | asked | 60 M line |
|---|---|---|---|---|
| token release through `deployImplementation` | 1,530 / B + 281,520 (account, code, the constructor's lock slot) | ≈ 65.5 / B + 204 k | 1,675.3 / B + 0.88 M (0.37 M of it the factory frame) | **35,289 B** |
| library | 1,530 / B + 183,600 | ≈ 64.5 / B + 35 k | 1,674.7 / B + 0.23 M | **35,689 B** |
| body module (a contract on the token bases, no frame) | as a token | as a token | ≈ 1,675.3 / B + 0.51 M [estimate] | ≈ 35,510 B |
| plain contract with a constructor (registry, router, factory) | 1,530 / B + 183,600 | ≈ 86 / B (registry row) | ≈ 1,697 / B + 0.19 M [estimate] | ≈ 35,244 B |

The brief's "≈ 35.6 KB at 1,536 state + 66 regular gas per byte" holds for a library; a token release is about 0.4 KB lower
because of the factory frame and its lock slot. The fits reproduce the measured rows to within 0.04 M (`NormalToken`
32,089 B: 54.64 M measured and fitted; `WrappedPqzToken` 56,223 B: 95.11 M measured, 95.07 M fitted). Regular × 1.05 stays
below 2^24 everywhere (≤ 4.6 M). `project.py` holds the formulas.

## 3. The measured map

`size_map.py` charges every runtime byte to the innermost Solidity function or modifier of its source location, to the Yul
utility (ABI coder) solc generated, to the dispatcher or to the metadata (`size-map.out` §1–§7); `evmmap.py` adds a static
control-flow closure per entry (the bytes only one entry or domain reaches). solc was rerun on forge's own build input with the
outputs forge drops (`generatedSources`), and its 187 runtime objects equal forge's byte for byte (`solc_full.py`) [measured].

### 3.1 Where the bytes are (runtime B by domain) [measured]

| Domain | `NormalToken` (0) | `WrappedPqzToken` (5) | `WrappedZetherRegulatedToken` (11) | `WrappedPqzRegulatedToken` (13) |
|---|---:|---:|---:|---:|
| dispatcher and external wrappers (no source / contract) | 5,397 | 9,119 | 10,176 | 10,708 |
| ABI decoders | 4,144 | 6,717 | 6,448 | 7,064 |
| ABI encoders (library calls, self-call data, returns) | 4,553 | 8,365 | 7,152 | 9,241 |
| other Yul utilities | 1,239 | 1,127 | 1,119 | 1,152 |
| the guard (`nonReentrant`, inlined per entry) | 571 | 1,123 | 1,335 | 1,301 |
| ERC-20 core and the UA ledger moves | 1,947 | 2,090 | 2,139 | 2,119 |
| signed pipeline (`MetaTxBase`, `UAMetaTxBase`, `ERC20MetaTx`) | 5,983 | 6,781 | 6,896 | 6,907 |
| named transfers (`mtxTransfer`, `mtxTransferWithFee`) | 347 | 369 | 369 | 369 |
| pay (`mtxPay*`, `payWithFee*`, `mtxRelayFee`, receiver-pays, tax) | 1,823 | 1,880 | 3,104 | 3,081 |
| trade (`mtxTrade`, cancels, digests, `mtxWrapOrder`) | 1,813 | 2,146 | 2,125 | 2,166 |
| governance (`GovernanceBase`, `GovernanceUse`) | 2,308 | 2,332 | 2,300 | 2,319 |
| init, allowlist tables, metadata views | 2,015 | 1,891 | 2,027 | 2,212 |
| kind bodies, each layer apart: wrapped; Zether; PQZ; regulated | 242 (mint, burn) | wrapped 4,134; PQZ 8,370 | wrapped 4,100; Zether 6,256; regulated 3,518 | wrapped 4,097; PQZ 8,135; regulated 3,511 |
| math, metadata, other | 488 | 582 | 614 | 614 |
| **runtime** | **32,870** | **57,026** | **59,678** | **64,996** |

The other eight kinds and every library are in `size-map.out` §1.

- **Shared:** about 23.5–25.1 KB of every kind is code present in all twelve kinds: the pipeline, pay, trade, governance, init,
  the ERC-20 core, the guard (`size-map.out` §3) [measured]. A kind's own bytes (only in that kind) are 0.2–0.8 KB; the rest
  is code shared with some kinds (the wrapped, Zether, PQZ or regulated layers).
- **The fixed part grows with the entry count:** dispatcher, wrappers and decoders are 9.5 KB of `NormalToken` (84 entries)
  and 17.8 KB of kind 13 (178). Coders together (decode, encode, other) are 9.9 KB on kind 0 and 17.5 KB on kind 13.
- **Encoders are as large as many bodies.** 4.6–9.2 KB per kind is ABI encoding, mostly arguments re-encoded for a library call
  or a self-call (`abi_encode_struct_UASig_calldata` alone 360–397 B in every kind, the PQZ args structs 286–323 B each). This
  is T40's "libraries are not free": a split whose stub re-encodes its arguments can grow the token.
- **Entries are thin, the shared core is thick:** the closure view gives 0–1,100 B reachable only from any single entry; most
  code is reached from many entries (`size-map.out` §4, §5).
- **Biggest single items:** the inlined guard (429–1,212 B per kind), `mtxSelectors` (280–928 B), `initialize` with the
  `TokenConfig` decoder (≈ 0.8 KB), `_receiverFee` 483–493 B, `mtxCancelNonce` 496–535 B, `mtxTrade` 437–444 B.
- **Registry:** `UAKinds.name` is 1,193 B in both `UARegistry` and `UARegistryLib` (`size-map.out` §6) [measured]: one copy is a
  part-3 lever.

### 3.2 Variant A's floor [measured]

`gen_floor.py` writes, from a kind's ABI, a contract with the same selectors, argument and return types, every entry a stub
that only forwards its calldata by DELEGATECALL (state-changing stubs keep a guard, views keep `view` through a pointer cast,
the registry R2 form). This is the smallest a token can be while it keeps every entry point (`floor.out`):

| Kind | 0 | 1 | 2 | 3 | 4 | 5 | 8 | 9 | 10 | 11 | 12 | 13 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| entries | 84 | 113 | 120 | 153 | 124 | 159 | 103 | 132 | 139 | 172 | 143 | 178 |
| floor B | 6,957 | 10,069 | 9,579 | 12,780 | 10,294 | 13,926 | 8,759 | 11,837 | 11,150 | 14,495 | 11,862 | 15,637 |

An unused calldata argument is checked only for its head (a calldata struct is not copied), so a stub costs dispatch, a
shallow check and a jump. A real stub adds its own modifier (the guard, `governed`): ≈ 80–90 B per entry in all.

## 4. Spikes (scratch worktree only; patches in `spikes/`)

### 4.1 Token side: forward stubs, every kind at once [measured]

`fwd_spike.py` rewrites the bodies of the chosen domains' entries to one forward (`fwdCall`, `fwdView`, `fwdPure`), keeping
signature, modifiers and ABI; the compiler then drops everything only those bodies used. An entry another kept routine still
calls internally stays whole: `supportedModes`, `setGrant`, `receiverFeeDigest`, `mtxUnshield`, `mtxUnshieldUnwrap`,
`unwrapBinding`, `mtxRollOverBatch`, `mtxRollOverSigned`, `mtxSetRollOverMode` (`spikes/fwd-V7.txt`). Runtime B (`fwd-sizes.out`):

| Kind | HEAD | V1 pay | V2 trade | V3 = V1 + V2 + named transfers | V4 governance | V5 = V3 + V4 + init, tables, views | V6 = V5 + kind bodies | V7 = all but the ERC-20 core |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 32,870 | −2,367 | −2,928 | 26,993 | −1,830 | 21,236 | 20,279 | **12,693** |
| 1 | 43,503 | −2,430 | −3,554 | 36,903 | −1,694 | 30,396 | 24,119 | **16,055** |
| 2 | 41,076 | −2,351 | −2,842 | 35,305 | −1,762 | 30,986 | 25,091 | **17,043** |
| 3 | 51,522 | −2,350 | −3,517 | 45,039 | −1,651 | 41,549 | 29,161 | **20,529** |
| 4 | 47,714 | −2,347 | −2,928 | 41,857 | −1,802 | 35,168 | 26,354 | **18,217** |
| 5 | 57,026 | −2,354 | −3,538 | 50,518 | −1,687 | 47,031 | 31,636 | **22,858** |
| 8 | 40,638 | −4,046 | −2,888 | 33,126 | −1,588 | 27,230 | 23,735 | **15,843** |
| 9 | 51,292 | −4,110 | −3,576 | 42,989 | −1,684 | 36,109 | 27,564 | **19,167** |
| 10 | 49,020 | −4,042 | −2,851 | 41,549 | −1,541 | 37,087 | 28,354 | **19,970** |
| 11 | 59,678 | −4,038 | −3,539 | 51,484 | −1,647 | 47,618 | 32,591 | **23,597** |
| 12 | 55,472 | −4,042 | −2,888 | 47,964 | −1,566 | 41,091 | 29,713 | **21,252** |
| 13 | 64,996 | −4,042 | −3,565 | 56,772 | −1,662 | 52,902 | 35,161 | **26,038** |

The governance forward also frees 1,713 B on `SCaaSDex`, which shares `GovernanceBase` [measured]. V5 frees more than
V3 + V4 because init and the allowlist tables leave too (the `TokenConfig` decoder, `mtxSelectors`).

### 4.2 Library side: body modules [measured, then corrected]

A body module holds a domain's bodies and everything they call. It is measured as the kind compiled with every entry
**outside** the domain forwarded (the complement build), less the stubs of the forwarded entries at the kind's floor cost per
entry (`mod_est.py`, `modules.out`). Every complement build also keeps a residue no real module would hold (the whole-kept
entries above, their internals): the V8 build, everything forwarded, measures it at 4.1 KB (kind 0) to 9.9 KB (kind 13). So the
table gives an upper bound and, less the residue, a lower bound:

| Module (domains) | kind 0 | kind 5 | kind 11 | kind 13 |
|---|---|---|---|---|
| MA: signed pipeline, named transfers, pay | 14.0–18.1 KB | 14.1–22.6 | 17.7–25.1 | 16.8–26.7 |
| MB: trade (`mtxTrade`, cancels, digests, `mtxWrapOrder`) | 5.2–9.3 | 5.1–13.6 | 6.3–13.8 | 5.2–15.1 |
| MC: governance, init, tables, metadata views, mint / burn | 14.5–18.6 | 6.5–15.0 | 6.8–14.2 | 6.9–16.8 |
| MD1: PQZ entries | — | 20.4–28.8 | — | 20.1–30.0 |
| MD2: wrapped entries, regulated powers | — | 13.3–21.7 | 18.7–26.1 | 17.7–27.6 |
| MD3: Zether entries | — | — | 18.0–25.5 | — |
| the owner's pay library alone (Mpay) | 6.7–10.8 | 5.0–13.4 | 8.7–16.1 | 7.5–17.4 |
| MA + MB in one module (MAB) | 17.8–21.9 | 18.9–27.3 | 22.4–29.8 | 21.6–31.5 |

All twelve kinds: `modules.out`. Every module of the plan (MA, MB, MC, MD1–MD3) and MAB is under the 35,510 B module line at
the upper bound before growth on every kind; the largest are kind 13's MAB at 31.5 KB and its PQZ module at 30.0 KB. The kind bodies of kind 13 in one module (MD = MD1 + MD2) would be 41.3 KB
upper bound: over, so the domain modules stay split [measured].

### 4.3 The owner's suggestions, measured

- **Pay library (`mtxPay*`, `payWithFee*`, `mtxPayReceiverFee`, `mtxRelayFee`, the tax pays and powers).** Token −2.35 to −2.43 KB on
  kinds 0–5, −4.04 to −4.11 KB on 8–13 (the tax) [measured]. A separate pay module is 5.0–17.4 KB [measured], holds its own copy of the typed transfer
  pipeline and the moves, and is a new cold account on every pay call (+2.6–2.9 k) [estimate]. Inside the pipeline module MA,
  pay calls get cheaper instead (§5.5). Alone it fits no kind that misses today.
- **`TradeLib` split (the trade entries into the library that holds the trade state).** Token −2.84 to −3.58 KB [measured]; a
  trade module of 5.1–15.1 KB [measured]. `mtxTrade` touches `TradeLib` and `MtxPipelineLib` today (two cold accounts); a trade
  module that holds `TradeLib`'s code and the authorisation rule touches one: −2.6 k per first fill [estimate].
- **Shared parts on their own.** The ≈ 24 KB of base code every kind carries is what the pipeline and admin modules hold. As a
  library the token calls with re-encoded arguments it costs bytes in the token (T40: levers 4 and 8 grew kind 13) and +2.6 k on
  hot paths (T0's lever L: +7.5 k per relayed transfer, measured); behind forward stubs it is the main saving (V5: −10.0 to
  −15.2 KB). One module per family across kinds is possible only if the per-kind hooks (`_mtxRule`, `_uaAllowed`, the envelope
  bindings, the regulated hooks) become data the module reads [inference]; it lowers release cost, not any contract's size.

### 4.4 A module behind `fallback`, for comparison only

The owner chose variant A (2026-10-21). With the same modules behind a `fallback`, a token keeps only its ERC-20 core and
the entries it serves itself: about 6.8 KB (kind 0) to 11.9 KB (kind 13), 6–14 KB smaller than variant A's V7 token (the stubs
of the forwarded entries, ≈ 80–90 B each) [estimate]. It saves no gas (a dispatch miss then a forward against a stub then a
forward) and gives up the token's typed ABI (explorers, `this.f.selector` in the token's own code, the selector audit). Variant
A reaches 60 M on every kind (§5.4), so there is no reason to ask the owner to revisit it.

### 4.5 Per call, on paper [estimate]

A forward costs `calldatacopy` (3 gas per word plus memory) + DELEGATECALL (2,600 cold, 100 warm) + `returndatacopy`; it saves
whatever the stub no longer encodes and the target no longer decodes. Memory per frame costs `3w + w²/512` for w words. Forge's
figures for the old rows: T40's `MetaTxGasV2` (`mtxPay` fresh lane 202,216; `mtxExecuteTransfer` 191,312), T0's
relayed EOA → EOA transfer 88,721 (`results.txt`) [measured]. The new rows below are paper deltas, not forge runs: the spike's
forward target is not deployed.

## 5. Proposed organisation

### 5.1 The rule

1. **The token keeps every entry point** with its signature, modifiers, the one `nonReentrant` guard and its ABI (variant A).
   It keeps the ERC-20 core itself: `transfer`, `transferFrom`, `approve`, `balanceOf`, `allowance`, `totalSupply`, `name`,
   `symbol`, `decimals`, `kind`, `_update` with its hook, `_msgSender`, the guard. Every other entry's body is one forward.
2. **A body module** is a contract compiled from the token's own bases, holding one group of bodies, reached only by
   DELEGATECALL from the token's stubs; its code hash is pinned in the release as a library's is. Same storage layout by
   construction; the kind's hooks by override; no storage-pointer rewrite of the bodies.
3. **One cold account per operation.** A stub forwards to the module that also holds, inlined, the library code the operation
   calls today, so no operation touches more accounts than now: the pipeline module holds `MtxPipelineLib`'s code; the trade
   module `TradeLib`'s and the authorisation rule; the ops the generic signed path may run (`burn`, the `unwrap`s) sit in the
   pipeline module.
4. **Bodies are written once**, as internal functions in their domain's base file; the token's entry forwards, the module's
   entry calls the body without the guard.

### 5.2 Contracts, holdings, links and deploy order

| Contract | Holds | Size (with growth) | Links / reaches | Deploy |
|---|---|---|---|---|
| Libraries as today: `GovernanceLib`, `WrappedLib`, `ZetherLib`, `ZetherWrappedLib`, `PqzTransferLib`, `PqzBurnLib`, `PqzStateLib`, `PqzViewLib`, `PqzWrappedLib`, `RegulatedLib`, `HederaLib` | unchanged; 3f / 3h / chain-neutral bodies as their specs place them | 0.8–26.2 KB, largest `ZetherLib` 26.2, `PqzTransferLib` 21.5 | none (`ZetherWrappedLib` chains two, pinned) | 1st, each its own transaction |
| `MtxPipelineLib`, `TradeLib` | kept for the router, the mandate wallets and the DEX | 11.5, 4.8 KB | none | 1st |
| Pipeline module (per kind) | `mtxExecute`, `mtxBatch`, `mtxCancelNonce`, `executeMetaTransaction`, `cancelNonce`, `mtxExecuteTransfer`, `mtxBatchTransfer`, the named transfers, pay, the relay fee, the generic path's direct ops; `MtxPipelineLib`'s code inlined | 16.3–32.5 KB | `HederaLib`; `RegulatedLib` on 8–13 | 2nd |
| Trade module (per kind) | the trade entries, `mtxWrapOrder`; `TradeLib`'s code inlined | 4.1–14.8 KB | — | 2nd |
| Admin module (per kind) | governance entries, `initialize`, `mtxSelectors`, `supportsInterface`, metadata views, `rescue`, `mint` / `mintToUA`, chain-neutral's `chainEnv` / `validateEnv` bodies, 3f's config checks | 6.6–24.3 KB | `GovernanceLib`, `WrappedLib` (rescue) | 2nd |
| Wrapped / regulated module (1, 3, 5, 8–13) | wrap, unwrap, rate, reserve; the regulated powers and tax powers | 3.8–27.2 KB | `WrappedLib`, `RegulatedLib` | 2nd |
| Zether module (2, 3, 10, 11) | the Zether entries | 12.7–25.2 KB | `ZetherLib`, `ZetherWrappedLib` | 2nd |
| PQZ module (4, 5, 12, 13) | the PQZ entries, 3f's and 3h's entry bodies | 15.3–30.7 KB | the PQZ libraries | 2nd |
| Token implementation (12 kinds) | stubs and the ERC-20 core | 12.9–27.7 KB | its modules and libraries by address | 3rd, through `deployImplementation` |
| `SCaaSDex` | unchanged (optionally its governance entries forwarded: −1.7 KB) | 34.5 KB | as today | release |
| `UARegistry`, `UARegistryLib` | part 3's rebalance | ≤ 35.2 / 35.7 KB each | `UARegistryLib` | as today |
| `GovernanceRouter`, `OpenFactory`, `MandateWallet`, `MtxRelayFee`, `PqChat` (3c) | unchanged | 14.7, ≤ 27.1, 17.9, 2.6, 8–12 KB | as today | as today |

Module sizes are §4.2's bounds plus growth (`projection.out`). Fewer modules are possible where the sum fits: pipeline and
trade together (MAB) are 17.8–31.5 KB before growth.

### 5.3 The split checklist (3e spec §6.4)

| Item | How the proposal meets it |
|---|---|
| DELEGATECALL storage | A module is compiled from the token's bases, so its layout is the token's by construction; the layout pin (`test/v2/layout/`) runs on each module artifact as on the token. |
| `this` | Under DELEGATECALL `address(this)` is the clone in every frame: the self-call (`address(this).call`) enters the token's dispatcher, its stub forwards again, the ticket in the clone's transient storage admits it. `this.f.selector` is a compile-time value. |
| `msg.sender`, `msg.value` | Kept by DELEGATECALL: `_msgSender()`, the ticket and the `requireNotDelegated` check read the same values; a payable stub forwards `msg.value` unchanged (`wrap`, `addReserve`, `mtxWrapShield`). |
| Return data | The stub returns the module's return and revert data verbatim; its typed return is never re-encoded. A differential test (R2's `test_diff` pattern: return, revert data, logs, every slot written, every call out) compares each entry with today's body. |
| The one `nonReentrant` | In the stub only; module entries carry none (rule 4). A guard left in a module reverts every call (`Reentrancy`): a mutant and a test. |
| `LinkClosure` pins | Modules join the release's closure with code-hash pins; a new opcode rule for modules: DELEGATECALL only to the release's linked libraries, no CALLCODE, no SELFDESTRUCT; CALL allowed (self-call, registry, verifiers). The library rule (no DELEGATECALL) is unchanged. |
| Immutables | A module has its own: before chain-neutral it needs the release's `Env`; after it, only `FACTORY` (the same on every chain) and its own `_SELF`, which must not decide "is this the implementation" (§7). `implementation()` stays a kept view or reads the clone's code. |
| A direct call to a module | Runs on the module's own storage, locked by its constructor; every entry also checks `address(this) != _SELF` (`onlyDelegated`, ≈ 20 B per entry). |
| EIP-8037 inclusion | Every module and every token its own transaction, each asked ≤ 60 M (largest 56.3 M upper bound); regular × 1.05 < 2^24 (≤ 2.5 M). |

### 5.4 Projected sizes and asked, every contract [measured + estimate]

`projection.out`; growth ranges in §6; "hi" is the top of each range.

| Release | HEAD B / asked | today's form + growth (hi) | V6 token + growth (hi) | **proposed: V7 token + growth** |
|---|---|---|---|---|
| `NormalToken` (0) | 32,870 / 55.9 M | 33,894 / 57.7 M | 20,586 / 35.4 M | **12,898–13,000 / 22.7 M** |
| `WrappedToken` (1) | 43,503 / 73.8 M | 44,527 / 75.5 M | 24,426 / 41.8 M | **16,260–16,362 / 28.3 M** |
| `NormalZetherToken` (2) | 41,076 / 69.7 M | 42,100 / 71.4 M | 25,398 / 43.4 M | **17,248–17,350 / 29.9 M** |
| `WrappedZetherToken` (3) | 51,522 / 87.2 M | 52,546 / 88.9 M | 29,468 / 50.2 M | **20,734–20,836 / 35.8 M** |
| `NormalPqzToken` (4) | 47,714 / 80.8 M | 51,196 / 86.6 M | 27,992 / 47.8 M | **19,292–19,855 / 34.1 M** |
| `WrappedPqzToken` (5) | 57,026 / 96.4 M | 60,508 / 102.2 M | 33,274 / 56.6 M | **23,933–24,496 / 41.9 M** |
| `NormalRegulatedToken` (8) | 40,638 / 69.0 M | 41,662 / 70.7 M | 24,042 / 41.2 M | **16,048–16,150 / 27.9 M** |
| `WrappedRegulatedToken` (9) | 51,292 / 86.8 M | 52,316 / 88.5 M | 27,871 / 47.6 M | **19,372–19,474 / 33.5 M** |
| `NormalZetherRegulatedToken` (10) | 49,020 / 83.0 M | 50,044 / 84.7 M | 28,661 / 48.9 M | **20,175–20,277 / 34.9 M** |
| `WrappedZetherRegulatedToken` (11) | 59,678 / 100.9 M | 60,702 / 102.6 M | 32,898 / 56.0 M | **23,802–23,904 / 40.9 M** |
| `NormalPqzRegulatedToken` (12) | 55,472 / 93.8 M | 58,954 / 99.6 M | 31,351 / 53.4 M | **22,327–22,890 / 39.2 M** |
| `WrappedPqzRegulatedToken` (13) | 64,996 / 109.8 M | 68,478 / 115.6 M | 36,799 / 62.5 M **no** | **27,113–27,676 / 47.2 M** |

V6 (the generic pipeline left in the token) fits every kind but 13, which misses by 1.5 KB at the top of its range; V7 fits
every kind with at least 12.8 M to spare. Largest module per kind with growth, upper bound: kind 0 24.6 KB, 1 25.5, 2 26.7,
3 27.7, 4 27.4, 5 30.3, 8 28.6, 9 29.5, 10 30.7, 11 31.7, 12 31.4, 13 33.3 KB (≤ 56.3 M) [estimate].

| Other contract | form | HEAD B / asked | + growth (hi) | 60 M |
|---|---|---|---|---|
| `SCaaSDex` | release | 33,704 / 57.3 M | 34,523 / 58.7 M | yes, 1.3 M left; governance forwarded: ≈ 55.8 M |
| `UARegistry` | plain | 31,438 / 53.5 M | 32,155 / 54.8 M | yes |
| `UARegistryLib` | library | 37,536 / 63.1 M | 37,843 / 63.6 M | **no** until part 3: the pair needs ≤ 70.9 KB together and is 69.4–70.0 KB with T66b's items |
| `GovernanceRouter` | plain | 13,396 / 22.9 M | 14,727 / 25.2 M | yes |
| `OpenFactory` | plain | 15,821 / 27.0 M | 27,085 / 46.2 M | yes (index, generic catalogue, chain-neutral) |
| `MandateWallet` | plain | 17,704 / 30.2 M | 17,909 / 30.6 M | yes |
| `ZetherLib` | library | 25,351 / 42.7 M | 26,170 / 44.1 M | yes |
| `PqzTransferLib` | library | 19,724 / 33.3 M | 21,465 / 36.2 M | yes |
| `PqzViewLib` | library | 19,886 / 33.5 M | 20,910 / 35.2 M | yes |
| `WrappedLib`, `GovernanceLib`, `PqzBurnLib`, `ZetherWrappedLib`, `RegulatedLib`, `MtxPipelineLib`, `PqzStateLib`, `PqzWrappedLib`, `TradeLib`, `HederaLib` | library | 0.8–17.0 KB | ≤ 17.0 KB / ≤ 28.7 M | yes |
| `PqChat` (3c, own release) | release | — | 8–12 KB / ≤ 21 M | yes |

**Release cost** (one-off per chain; shared libraries not counted on either side): a kind's release becomes the token plus
3–5 modules, each its own transaction. Per kind the sum asks 87–260 M against 58–116 M for the single implementation in today's
form with growth (`projection.out`); with per-family module sharing (§4.3) it falls toward the lower end.

### 5.5 Gas per operation, old → new on paper [estimate]

| Operation | Today (one cold library account) | Proposed | Δ |
|---|---|---|---|
| `transfer`, `transferFrom`, `approve` (ERC-20 direct) | in the token | in the token | 0 |
| `mtxTransfer` / `mtxExecuteTransfer`, relayed (T0 88.7 k; T40 191.3 k fresh lane) | token encodes `Ctx`, the transfer, `have`, `UASig` (≈ 35 words) into a call of `MtxPipelineLib` (cold), decodes `Out` | stub copies ≈ 19 words, one cold DELEGATECALL to the pipeline module, which decodes calldata once and runs the pipeline inline | **−1.1 to −0.2 k** |
| same, if the pipeline module did not inline `MtxPipelineLib` | | a second cold account | +2.7 to +2.9 k |
| `mtxPay` (T40 202.2 k fresh lane) | `payMeta` (cold) + `preTransferUA` (warm) with `PayMeta`'s string and bytes encoded | one cold account, nothing re-encoded | **−1.5 to −0.3 k** (more with a large body) |
| `mtxExecute(burn)` and the generic path's direct ops | pipeline cold, op in the token | the op in the pipeline module: warm | ≈ −0.5 to +0.2 k |
| `mtxTrade`, first fill | `TradeLib` and `MtxPipelineLib`, both cold | the trade module, one cold | **≈ −2.6 k** |
| governance, admin, wrap / unwrap, regulated powers (direct) | the op's library, cold | the module, cold (the library's code inlined where it is the only one) | 0 to +2.9 k |
| shielded transfer, PQZ op 1 (≈ 4 M, ≈ 21 KB calldata) | two calldata buffers (the self-call data, the library call) | + the PQZ module (cold) + two stub copies (the signed stub, the self-call's stub): 2,600 + 2 × ≈ 2.8 k | **≈ +8 k (+0.2 %)** |
| largest PQZ op (≈ 340 KB, ≈ 11 M) | as above | two stub copies of ≈ 0.26 M each | **≈ +0.53 M (+4.8 %)**; ≈ +0.27 M (+2.4 %) if the direct body forwards its calldata to the PQZ library unchanged |
| Zether shielded transfer (calldata a few KB) | as above | + the Zether module (cold) + two small copies | ≈ +3–4 k |

### 5.6 Node and client impact

None expected: selectors, argument and return types, events (a DELEGATECALL's event carries the token's address), errors
(revert data passes through) and `mtxSelectors()` answers are unchanged, so `typed.rs`, `guard.rs`, `selector_audit.json`,
the vectors and every client stay as they are [inference]. What moves: the deploy tooling (`DeployBase`, `deploy.sh`,
`e2e.py`: modules in the release, their code-hash pins, one gate per transaction), gas pins (old → new), and the node's
gas estimates where a pin was hard-coded.

## 6. Growth included

| Group | Token, today's form | Token, proposed form | Where else |
|---|---|---|---|
| chain-neutral (spec `2026-11-07-chain-neutral-releases.md` §7.1) | +0.2–0.8 KB every kind | +0.2–0.3 KB (two stubs) | readers in the modules +0.2–0.4 KB each; `OpenFactory` +1.5–2 KB; `RegulatedLib`, `ZetherLib`, `PqzStateLib` +0.3–0.8 KB if the reader stays there |
| 3f (`2026-11-06-attested-verify.md` §9) | +0.1–0.2 KB every kind; kinds 4, 5, 12, 13 +1.1–2.0 KB in all | PQZ kinds +0.6–0.95 KB (two calldata arguments on twelve stubs, four new stubs) | PQZ libraries +0.3–1.0 KB each; router +0.5–0.8 KB |
| 3h (`2026-11-06-pqz-proof-path.md` §8) | PQZ kinds +0.3–0.6 KB | +0.25–0.35 KB (three stubs) | `PqzTransferLib`, `PqzBurnLib` +0.6–1.0 KB each, `PqzViewLib` +0.3–0.5, `PqzStateLib` +0.1; router op [estimate] +0.3–0.5 |
| 3g (`2026-11-06-pqz-key-versions.md`) | already in `937b454f` (T51–T53; T54–T57 touch no `src/`) | | |
| factory index (`2026-11-07-factory-contract-index.md` §4, §8.7) | — | — | `OpenFactory` +5.5–9 KB |
| T66b's registry items | — | — | `UARegistry` +0.3–0.7 KB (`requirePortable`), `UARegistryLib` +0.1–0.3 KB (the `msig` KEM refusal) [estimate] |
| `PqChat` (3c, branch `ua7-research`) | — | — | its own release, 8–12 KB |

## 7. `ChainEnv` under DELEGATECALL

Chain-neutral option I appends the instance's `ChainEnv` to the clone's runtime code and reads it with
`EXTCODECOPY(address(this), 0x2d + offset, n)`. **It works from a library and from a body module:** the frames run clone →
(DELEGATECALL) implementation → (DELEGATECALL) library or module, and `address(this)` is the clone in each, so the copy reads the
clone's appended bytes; the account is the transaction's target and warm [inference from the EVM's DELEGATECALL semantics].
**The catch is the implementation check.** The spec returns an all-zero env when `address(this) == _SELF`; `_SELF` is an
immutable of the implementation, which a library cannot read and a module holds with its own value. Called directly, the
implementation forwards into its module with `address(this)` = the implementation, and a reader that trusts `_SELF` would take
the implementation's own code after offset 45 as an env. **Proposed:** the reader decides from the code itself, copying from
offset 0 and requiring the 45-byte EIP-1167 form (prefix `363d3d373d3d3d363d73`, suffix `5af43d82803e903d91602b57fd5bf3`)
before the head, else all zero. One copy of 138 B instead of 93 B (≈ +10 gas); no immutable; the same code in the token, a
library and a module. **What it adds:** the decoder `ChainEnvCode` (≈ 0.2–0.4 KB) in each contract that reads it [estimate],
and the spec's +0.1–0.2 k per signed call; it removes the per-chain constructor values that modules would otherwise need,
which makes modules chain-neutral bytecode too.

## 8. Guidance for the groups built before T66b (chain-neutral, then 3f, then 3h)

Short rules to copy into those task blocks, so their code does not have to move in T66b:

- **G1 (all three).** A new entry's body goes in its domain's base or library (governance and admin: `GovernanceBase` /
  `GovernanceLib`; PQZ: `PqzLayer` and the PQZ libraries; Zether: `ZetherLayer` / `ZetherLib`; regulated: `RegulatedBase` /
  `RegulatedLib`), never in the kept code: `_update`, `_uaMove`, `_poolMove`, `transfer`, `approve`, `transferFrom`,
  `_msgSender`, the guard.
- **G2 (all three).** No new `public` function that other code calls internally: write an `external` entry and an `internal`
  helper. Today's nine such entries (§4.1) are the ones a forward cannot take.
- **G3 (all three).** Pass large arguments as calldata and do not re-encode them for a library call where the stub can hand the
  library its own calldata (T40's lesson, §3.1).
- **CN-1 (chain-neutral).** `ChainEnvCode` decides "is this a clone" from the code (§7), never from `_SELF`.
- **CN-2 (chain-neutral).** `chainEnv()` and `validateEnv()` are external entries with bodies in one admin-side place;
  `_mtxCtx()` stays the token's only reader, and libraries keep receiving values as arguments. No new immutable.
- **3F-1 (3f).** The verdict parameters stay calldata through to `PqzTransferLib` / `PqzBurnLib`; the three governance powers
  and `pqzVerifyConfig()` as forwards into `PqzStateLib` (the spec's lever 1 from the start); the new `ConfidentialConfig`
  fields decoded only in `_init`.
- **3H-1 (3h).** `setProofStore`, `proofStore`, `pqzDebitRecord` as forwards into `PqzStateLib` / `PqzViewLib` (the spec's
  lever 1 from the start); bit 24 only in the masks; `ownTag` and the key-version tail only in the args structs and the PQZ
  libraries.
- The size window of the plan's header (kind 13 may stay above the stop line, pinned in `_above64KiB` until T66b) is unchanged.

## 9. Verdict

| Suggestion | Verdict | Numbers |
|---|---|---|
| Split `TradeLib` (the trade entries into a module with the trade state's library code) | **Yes, inside the forward form** | token −2.84 to −3.58 KB; module 5.1–15.1 KB; first fill ≈ −2.6 k gas. Alone it fits no kind that misses. |
| A pay library | **Yes, as part of the pipeline module, not as its own library** | token −2.35 to −2.43 KB (0–5) / −4.04 to −4.11 KB (8–13); its own module 5.0–17.4 KB and +2.6–2.9 k per pay call; in the pipeline module −1.5 to −0.3 k per `mtxPay` |
| Move the shared parts out | **Yes, behind forward stubs** | the ≈ 24 KB base in every kind; V5 −10.0 to −15.2 KB; as a library with re-encoded calls it grows tokens (T40) and costs +2.6 to +7.5 k on hot paths (T0's L) |
| Reduce each kind | **Yes: every body out of the token but the ERC-20 core (V7)** | tokens 12.9–27.7 KB (22.7–47.2 M), modules ≤ 33.3 KB (≤ 56.3 M); V6 leaves kind 13 at 62.5 M |
| PQZ kinds | **Reachable**, at the gas price of §5.5 | kind 13 token 47.2 M, its PQZ module ≤ 30.7 KB; +0.2 % to +4.8 % on proof-carrying ops |

## 10. Task breakdown for T66b part 4 (after part 3's rebalance)

| Step | Work | Agent-days |
|---|---|---|
| 4.1 | Spec: the forward form, the module pattern, which entry goes to which module per kind, the checklist of §5.3, the module pin and opcode rules, the release with modules, the tests; Codex and Fable reviews | 2.5 |
| 4.2 | Source: each entry split into a token stub and an internal body (rule 4); the nine whole-kept entries split (G2); `MtxPipelineLib` / `TradeLib` code as internal for the modules; the module contracts, 3–5 per kind | 6–7 |
| 4.3 | Deploy: `DeployBase`, `deploy.sh`, `e2e.py`: modules first, their code-hash pins in the release, one public gate per transaction; the factory's release checks extended to modules | 2–3 |
| 4.4 | Tests: the differential test per entry against today's bodies (return, revert data, logs, slots, calls), layout pins per module, `LinkClosure` rows, mutants (a guard left in a module, `this` or `msg.sender` read wrongly, a stub to the wrong module, `onlyDelegated` dropped, a module storage slot moved) | 4–5 |
| 4.5 | Gas pins old → new, the four PQZ sets, size gate and baseline, the stop line and CTR-GOV-19's entry, the deploy-gas table of every contract against 60 M | 1.5–2 |
| 4.6 | Docs: `decisions.md` entry, contracts docs, this note's status line | 1 |
| | **Part 4 in all** | **17–20.5** |

Parts 1–3 keep the plan's estimates (2.5 + 2). Part 3's rebalance should take `UAKinds.name`'s duplicate (1,193 B) first.

## 11. Owner questions

**Owner 2026-11-07: all four answered as recommended** (lever L in its forward form allowed; per-kind modules and their
release cost accepted; the registry pair rebalanced first; the PQZ calldata cost accepted). Recorded on CTR-GOV-19.

1. **Reuse lever L in its forward form?** T9's levers L and D were deprecated on 2026-11-05; the measured way to 60 M for 11 of the
   12 kinds is L's large form: every body but the ERC-20 core in DELEGATECALL body modules, behind typed stubs (variant A
   kept), the modules contracts on the token's own bases pinned like libraries. **Recommendation: yes.** The alternative is to
   accept today's gap (only `NormalToken` and the DEX fit 60 M).
2. **The release cost.** A kind becomes the token plus 3–5 modules, 87–260 M of deploy gas per kind per chain against 58–116 M,
   each transaction within 60 M. **Recommendation: accept per-kind modules now;** per-family sharing (the rule tables as data)
   later, as a cost lever, not a size one.
3. **The registry pair.** After T66b's two items `UARegistry` + `UARegistryLib` have about 0.9–1.6 KB of total room under 60 M
   each: part 3 can fit both, not "with margin". **Recommendation:** rebalance first (R4 accepts 60 M); if the margin is wanted,
   allow the forward form on the registry's entries too, rather than a second registry library (the owner's 2026-11-01 ruling
   of one library stands).
4. **The proof-carrying PQZ ops pay +0.2 % to +4.8 % gas** (two more calldata copies; +2.4 % at the top with the mitigation of
   §5.5). **Recommendation: accept** for kinds 4, 5, 12, 13 ("if not possible, that is still OK": it is possible, at this price).

## 12. Method and limits

- **The module bounds are bounds.** The complement build carries the residue (4.1–9.9 KB) no real module holds; the true module
  sits between the two figures. The pipeline module's inlined `MtxPipelineLib` (+3–6 KB) is an estimate.
- **The token side is exact for the shape built.** A real stub may differ by tens of bytes (`onlyDelegated` in modules, an
  appended word), and growth after the forward lands mostly in modules.
- **The closure view errs low on "exclusive":** a constant equal to a jump target adds an edge. The map's domain table uses the
  source map, which charges a block the optimizer merged to one of its users.
- **No forge gas for the new rows:** the forward target was not deployed; the rows are paper arithmetic over the cited forge
  figures. **Not run:** `forge test` on any spike (compile-only, by design), the four PQZ sets, mutants.
- Rerun: `README.md` in the runs directory.
