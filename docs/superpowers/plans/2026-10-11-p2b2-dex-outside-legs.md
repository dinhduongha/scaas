# P2b-2 — Outside-token legs on `SCaaSDex`: `DexOrder`, `DexPuller`, DEX-side cancels, the ERC-1271 cap; bounded `MatchFailed` reason — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Settle legs in tokens SCaaS does not control on the P2b-1 `SCaaSDex` (CTR-DEX-18, -22, -08, -02): the same
`TradeOrder`, signed in the DEX's domain as `DexOrder`, checked by the DEX with the token's own rules on the DEX's own
fill state, pulled through a `DexPuller` the DEX deploys at `initialize`; DEX-side `mtxCancelOrders` and
`mtxInvalidateNonces`; the ERC-1271 call capped by codehash (400 k for this chain's `SmartKeyAccount` clones, else 50 k).
Also: a failed settlement's `MatchFailed` reason is bounded (returnbomb), a starved ERC-1271 check reverts the whole
`mtxSettle` (TODO m8), and fee-on-transfer or rebasing outside tokens are caught by conservation.

**Architecture:** `TradeLib.precheck` gains the sell token as an argument (`address(this)` in a token), so the DEX can run
`precheck` → `SigCheck.isValid(…, _cap(from))` → `record` by delegatecall on its own ERC-7201 `scaas.trade` state, then
`DexPuller.pull(token, from, move)`. The leg's kind comes from the DEX's listing (`setMarket`), never from the leg:
`kind ≠ SCaaS` ⇒ `DexOrder` digest, `ESCROW` refused, the puller path; else `mtxTrade` as in P2b-1. `mtxSettle` replaces
`try`/`catch` by a low-level self-call that copies at most 256 bytes of revert data and re-raises `SigCheckGasStarved`.
Every payout is a `SafeERC20` transfer. The exchange path stays P2c.

**Tech Stack:** Solidity 0.8.37 (`osaka`), Foundry (forge 1.3.5), OpenZeppelin 5.2.0 (`SafeERC20`, `Clones` in tests),
forge-std 1.16.2 (`expectPartialRevert`); `scaas-node` e2e (anvil) as the deploy check.

**Spec:** `docs/contracts/dex.md` CTR-DEX-18, -22, -08, -02 (§3.1 cancels), -16 (`MatchFailed`, conservation), -14, §10
invariants and intake reads, §13, §14; `docs/contracts/settlement.md` §3.5 and the DEX row; TODO.md P2b-2 line and the m8
note.

**Base:** `main` at `0510c7d` (P2b-1 merged). The spike `f6e3e76` (worktree `.claude/worktrees/p2b2-spike`) sits on an
older P2b-1 spike (`f1565db`), not on `main`: its `LegSettled.received` is gross and its `_onlyAdmin` has a zero clause,
both superseded by `main`; this plan is the spike resolved against `main` and extended. Every code block below was applied
to a scratch worktree from `main` and run green (full suite 910, Dex 36, DexOutside 19, size gate 0 errors, e2e 4/4 and
1/1, docs checkers 0 errors).

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; forge in `smartcontracts/evm` of worktree `.claude/worktrees/p2b2`
  (branch `p2b2-dex` from `main`; `lib/` is not tracked: copy `smartcontracts/evm/lib/forge-std` and symlink
  `lib/openzeppelin-contracts → /home/ha/work/blockchain/openzeppelin-contracts` as in the main checkout). Heavy commands
  only through `scripts/capped`, one at a time. `/usr/bin/grep`, `rtk proxy git diff`.
- `scaas.dex` = `0xb144ea5327f344ea7e3b34dd1898f534c8ce28f9f54d0d89a1b78f8fcf7dac00` (one field appended: `puller`);
  `scaas.trade` = `0x2c9c6bfc4d8563261a812845f5cbef41fd06d0e8f173455fd0e077ab420e2f00` (the DEX's own copy, through
  `TradeLib`).
- `DexOrder` typehash string: `DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,address
  receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address
  destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)`; `CancelOrder` and `InvalidateNonces` reuse
  `TradeLib`'s typehashes in the DEX's domain `("SCaaS Dex","1",chainId,clone,chain_uid)`.
- `MAX_REASON = 256` bytes; `SMART_KEY_1271_GAS = 400_000`, else `SigCheck.ERC1271_GAS = 50_000`.
- Tests: compute anything that makes an external call (`dexOrderDigest`, `tradeOrderDigest`, `cancelOrderDigest`,
  `invalidateNoncesDigest`, `dex.puller()`, building a settlement) **before** `vm.prank` / `vm.expectRevert` /
  `vm.expectPartialRevert`: the external call would consume the cheatcode. Every DEX-only check has a named killer test
  (mutation table, Task 1 Step 8).
- Code size is not a concern (owner: wait for the Glamsterdam fork); the ratchet baseline records sizes. Measured:
  `SCaaSDex` 14,672 B (was 9,574), `DexPuller` 624 B, `TradeLib` 3,140 B, `NoUnderlyingToken` 22,960 B (+9),
  `UnderlyingToken` 29,983 B (+9) — the two token entries of `size-baseline.json` are raised by those 9 bytes.
- Commit trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never `git add claude-code-api.txt`.

## Review Focus

- An outside leg that moves funds without the DEX's checks or with someone else's signature (precheck, signature,
  `record` order; the digest binding `sellToken` and the DEX domain) — pinned by `test_outsideOrder_isCheckedByTheDex`,
  `test_dexOrderDigest_isEip712OverTheDexDomain_andBindsTheSellToken`, `test_outsidePartialFills_accumulateOnTheDex_thenClosed`.
- An allowance the DEX itself could spend, or a pull to anywhere but the DEX — pinned by
  `test_pullUsesTheAllowanceToThePuller_notToTheDex`, `test_onlyTheDexPulls`, `test_outsideMaker_pulledThroughThePuller`.
- The kind taken from the leg (a SCaaS-signed leg of a token listed as outside, a fallback-only "token" sent down
  `mtxTrade`) — pinned by `test_deprecatedTokenListedAsOutside_isADexOrderPulledByThePuller`,
  `test_fallbackOnlyToken_isOutside_andFails`.
- One hostile party taking the batch down: a returnbomb outside token, a gas-burning or bomb ERC-1271 signer in a settle
  or cancel batch — pinned by `test_returnbombToken_reasonIsBounded_othersSettle` (an unbounded copy runs out of gas under
  its 3 M limit), `test_*1271OutsideMaker_othersStillSettle`, `test_hostile1271InACancelBatch_isSkipped`. Conversely a
  starved check must take the batch down — `test_starvedSigCheck_revertsTheWholeCall`. Residual (H5): a listed outside
  token can revert with the `SigCheckGasStarved` selector and so revert a whole call — no more power than a token that
  burns all gas; the relayer's simulation sees it, the admin delists.
- The cap by codehash wrong in one of its three uses (settle, cancel, invalidate) — `test_erc1271Cap_400kOnlyForSmartKeyClones`.
- Inexact tokens: fee-on-transfer, rebasing, no return value — `test_feeOnTransferToken_conservationCatchesIt`,
  `test_rebasingUpToken_conservationCatchesIt`, `test_noReturnValueToken_settles`.
- `TradeLib.precheck`'s new argument in the token path (`SelfOrder` must still refuse `from`/`dex` = the token): the P2a
  suite `test/v2/Trade.t.sol` runs unchanged.

## Rulings (docs vs code) and defaults taken

- **H1 — Outside leg = `DexOrder` checked by `TradeLib` on the DEX.** The DEX runs the token's steps (`precheck` →
  `SigCheck.isValid` with the cap → `record`) by delegatecall on its own `scaas.trade` state, so `pulled[h]`/`minNonce`
  are keyed by the `DexOrder` digest and behave as on a token (Path A bounds, IOC close, cancel). `precheck` takes the
  sell token (`token`) for the `SelfOrder` identity check (`from` or `dex` = the token); tokens pass `address(this)`.
  `TradeLib`'s errors keep their `ITradeToken` selectors and are re-declared in `ISCaaSDex` for the ABI; the DEX's own
  signature failure is `BadSignature(digest)`. `ESCROW` on an outside leg ⇒ `BadFlags(h)` (checked in `_calc`, before any
  pull). No `DexOrder` KAT file: `dex_kat.json` stays `SCaaSDexV1`'s (§14 ruling of P2b-1); the digest is pinned by an
  independent EIP-712 recomputation in the test.
- **H2 — `DexPuller` is deployed by `initialize`** (CTR-DEX-24, owner) — CTR-DEX-22 says "the DEX's constructor", which a
  clone does not run; the doc is aligned. `pull(token, from, amount)` = `safeTransferFrom(from, dex, amount)`, only the
  DEX (`NotDex(caller)`); `puller()` view. Every payout of the DEX is `SafeERC20.safeTransfer` (USDT-style tokens).
- **H3 — The cap by codehash.** The constructor takes the `SmartKeyAccount` implementation (`DeployBase` passes the same
  address as to the token implementations; Hedera passes 0 ⇒ every contract gets 50 k) and keeps the EIP-1167 runtime
  codehash of its clones, as `MetaTokenBase` does; `_cap(signer)` serves outside legs, `mtxCancelOrders` and
  `mtxInvalidateNonces`. SCaaS legs keep their token's cap.
- **H4 — Bounded `MatchFailed`.** `mtxSettle` self-calls `settleOne` with a low-level `call` and copies at most
  `MAX_REASON = 256` bytes of revert data (enough for every DEX/token error and an `Error(string)` of ~188 bytes), so a
  token that reverts with megabytes costs only its own settlement.
- **H5 — m8: `SigCheckGasStarved` reverts the whole `mtxSettle`** (CTR-DEX-08: "the whole transaction reverts"). It is the
  only "starved" error in the code (`SigCheck`), raised by the DEX for outside legs and by a token for SCaaS legs; the DEX
  re-raises it by selector. `mtxCancelOrders`/`mtxInvalidateNonces` have no `try`, so it reverts them as is.
- **H6 — DEX-side cancels.** `mtxCancelOrders(DexOrder[] orders, bytes[] sigs)`: `LengthMismatch` if the arrays differ;
  per item `CancelOrder(dexOrderDigest)` in the DEX domain, a bad signature or an already-closed order is skipped (no
  revert, no event). `mtxInvalidateNonces(from, batch, newMin, sig)`: `BadSignature(digest)`, then `TradeLib`'s
  `MinNonceNotIncreasing`/`MinNonceAboveCap`. Never expire (CTR-DEX-02); `nonReentrant`.
- **H7 — `checkOrder` is not built.** TODO/HANDOFF listed it for P2b-2, but the spec gives the new DEX no `checkOrder`:
  dex.md §10 names the intake reads (for an outside leg the DEX's `pulled`/`minNonce`, the party's balance and allowance
  to `puller()`), all built here. A combined view waits for the node's intake of the new DEX (P7) to say what it returns
  (controller ruling, pending the owner).
- **H8 — Inexact outside tokens** are not refused on chain: listing exact-transfer tokens is the admin's job (dex.md
  CTR-DEX-16), and conservation is the backstop. A fee-on-transfer token fails the payment (or, with a donated DEX
  balance, `ConservationBroken`); a token crediting more fails `ConservationBroken`.
- **H9 — Tests.** `test/v2/Dex.t.sol` keeps 36 tests: its two `OutsideLegNotBuilt` tests become
  `test_deprecatedTokenListedAsOutside_isADexOrderPulledByThePuller` and `test_takerSellsAnOutsideToken_settles`;
  `test/v2/DexOutside.t.sol` adds 19. `OutsideLegNotBuilt` is removed from `ISCaaSDex`.
- **H10 — Size baseline** raised for `NoUnderlyingToken` (22,960) and `UnderlyingToken` (29,983): the extra `precheck`
  argument costs 9 bytes in every token (owner: size is not a concern until Glamsterdam).

---

### Task 1: Outside legs, `DexPuller`, DEX cancels, the cap, bounded reason, m8; tests; deploy

**Model:** Sonnet, effort high (validated transcription on a money path; the mutation probe in Step 8 is the gate).

**Files:**
- Create: `smartcontracts/evm/src/dex/DexPuller.sol`, `smartcontracts/evm/test/v2/DexOutside.t.sol`
- Replace (full text): `smartcontracts/evm/src/dex/ISCaaSDex.sol`, `smartcontracts/evm/src/dex/SCaaSDex.sol`
- Modify: `smartcontracts/evm/src/trade/TradeLib.sol`, `smartcontracts/evm/src/metatx/ERC20MetaTx.sol`,
  `smartcontracts/evm/script/DeployBase.sol`, `smartcontracts/evm/size-baseline.json`, `smartcontracts/evm/test/v2/Dex.t.sol`

**Interfaces:** Consumes P2a `TradeLib` (`hashStruct`, `precheck`, `record`, `cancel`, `invalidate`, `$()`, typehashes),
`SigCheck` (`isValid`, `ERC1271_GAS`, `SigCheckGasStarved`), P2b-1 `SCaaSDex`. Produces `SCaaSDex(address factory,
bytes32 chainUid, address smartKeyAccountImpl)`, `ISCaaSDex.DexOrder`, `mtxCancelOrders`, `mtxInvalidateNonces`,
`dexOrderDigest`, `cancelOrderDigest`, `invalidateNoncesDigest`, `pulled`, `minNonce`, `puller`, `DexPuller`;
`TradeLib.precheck(o, f, h, caller, token)`.

- [ ] **Step 1: `TradeLib.precheck` takes the sell token** — apply to `src/trade/TradeLib.sol` and `src/metatx/ERC20MetaTx.sol`:

```diff
diff --git a/smartcontracts/evm/src/trade/TradeLib.sol b/smartcontracts/evm/src/trade/TradeLib.sol
index bbaf856..43dd882 100644
--- a/smartcontracts/evm/src/trade/TradeLib.sol
+++ b/smartcontracts/evm/src/trade/TradeLib.sol
@@ -46,13 +46,14 @@ library TradeLib {
             o.destination, o.flags, o.batch, o.nonce, o.validUntil));
     }
 
-    /// @notice Steps 1–3 (before the signature): caller and identities, relayer, shape.
-    function precheck(ITradeToken.TradeOrder calldata o, ITradeToken.TradeFill calldata f, bytes32 h, address caller)
-        public view
+    /// @notice Steps 1–3 (before the signature): caller and identities, relayer, shape. `token` is the sell token:
+    ///         `address(this)` in a token; the leg's token in the DEX, which runs the same checks for outside tokens.
+    function precheck(ITradeToken.TradeOrder calldata o, ITradeToken.TradeFill calldata f, bytes32 h, address caller,
+        address token) public view
     {
         if (caller != o.dex) revert ITradeToken.NotDex(caller);
         if (!SigCheck.isContract(o.dex)) revert ITradeToken.DexNotContract(o.dex);
-        if (o.from == address(this) || o.dex == address(this)) revert ITradeToken.SelfOrder(h);
+        if (o.from == token || o.dex == token) revert ITradeToken.SelfOrder(h);
         if (o.relayer != address(0) && o.relayer != f.submitter) revert ITradeToken.WrongRelayer(h, f.submitter);
         if (block.timestamp > o.validUntil) revert ITradeToken.OrderExpired(h);
         if (o.nonce < $().minNonce[o.from][o.batch]) revert ITradeToken.NonceInvalidated(h);
diff --git a/smartcontracts/evm/src/metatx/ERC20MetaTx.sol b/smartcontracts/evm/src/metatx/ERC20MetaTx.sol
index 6538fe6..1f8b625 100644
--- a/smartcontracts/evm/src/metatx/ERC20MetaTx.sol
+++ b/smartcontracts/evm/src/metatx/ERC20MetaTx.sol
@@ -61,7 +61,7 @@ abstract contract ERC20MetaTx is ERC20, MetaTxBase, IERC20Payment, ITradeToken {
     ///         `o.from` to `o.dex` and nowhere else.
     function mtxTrade(TradeOrder calldata o, bytes calldata sig, TradeFill calldata f) external nonReentrant {
         bytes32 h = tradeOrderDigest(o);
-        TradeLib.precheck(o, f, h, msg.sender);
+        TradeLib.precheck(o, f, h, msg.sender, address(this));
         _requireValidSignature(o.from, h, sig);
         _transfer(o.from, o.dex, TradeLib.record(o, f, h));
     }
```

- [ ] **Step 2: `src/dex/DexPuller.sol`** (new)

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title `DexPuller` (CTR-DEX-22): the only holder of user allowances for outside tokens. Deployed by its DEX's
///        `initialize` (a clone has no constructor, CTR-DEX-24); only that DEX may call `pull`, which moves exactly
///        `amount` from `from` to the DEX.
/// @notice Holders of an outside token approve the puller, never the DEX: an exchange-path interaction runs as the DEX,
///         so an allowance held by the DEX could be spent by a crafted `transferFrom`.
contract DexPuller {
    using SafeERC20 for IERC20;

    address public immutable dex;

    error NotDex(address caller);

    constructor() {
        dex = msg.sender;
    }

    function pull(address token, address from, uint256 amount) external {
        if (msg.sender != dex) revert NotDex(msg.sender);
        IERC20(token).safeTransferFrom(from, dex, amount);
    }
}
```

- [ ] **Step 3: `src/dex/ISCaaSDex.sol`** (full text; `OutsideLegNotBuilt` removed)

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ITradeToken} from "../trade/ITradeToken.sol";

/// @title The DEX side of `TradeOrder` (CTR-DEX-16, -17, -11, -03, -24, -18, -22, -08): one taker against many makers
///        per settlement, every leg pulled into the DEX (a SCaaS token through its `mtxTrade`, an outside token through
///        the `DexPuller` against a `DexOrder`), every party, fee share and refund paid in the same call, and the DEX's
///        balance of every token unchanged at the end.
interface ISCaaSDex {
    /// @notice Written once by `initialize` (CTR-DEX-24). `relayerSharePpm` of every fee goes to the submitter, the
    ///         rest to `treasury`. `listedOnly` belongs to the exchange path (P2c).
    struct DexConfig {
        address admin;
        uint32 relayerSharePpm;
        address treasury;
        bool listedOnly;
    }

    /// @notice One order in one settlement; `fill` = its `sellFill` in this call (Path B: the matched part).
    struct Leg {
        address sellToken;
        ITradeToken.TradeOrder o;
        bytes sig;
        uint256 fill;
    }

    /// @notice An outside-token order (CTR-DEX-18): the same `TradeOrder`, signed in the DEX's domain as
    ///         `DexOrder(address sellToken,TradeOrder order)`, `order.dex` = this DEX.
    struct DexOrder {
        address sellToken;
        ITradeToken.TradeOrder order;
    }

    /// @notice `ref` is the submitter's, echoed in events only; taker/makers is a call-time arrangement.
    struct Settlement {
        bytes32 ref;
        Leg taker;
        Leg[] makers;
    }

    event MarketSet(address indexed base, address indexed quote, bool listed);
    event FeeSplitSet(uint32 relayerSharePpm, address treasury);
    /// @notice `received` is net of the DEX fee: the party gets `receiveFill - dexFee`, so `received + dexFee` is the gross
    ///         and `relayerShare + treasuryShare == dexFee`. `destination` is where `received` went.
    event LegSettled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed from, address destination,
        uint256 sold, uint256 received, uint256 dexFee, uint256 refund, uint256 relayerShare, uint256 treasuryShare);
    /// @notice `reason` = the failed settlement's revert data, at most its first 256 bytes.
    event MatchFailed(bytes32 indexed ref, bytes reason);
    /// @notice Raised by `TradeLib` on outside-token legs and DEX-side cancels (same as `ITradeToken`), listed for the ABI.
    event TradeFilled(bytes32 indexed orderHash, address indexed from, uint256 sellFill, uint256 receiveFill,
        uint256 dexFee);
    event OrderCancelled(bytes32 indexed orderHash, address indexed from);
    event NoncesInvalidated(address indexed from, uint256 indexed batch, uint256 minNonce);

    error NotFactory();
    error AlreadyInitialized();
    error NotAdmin(address caller);
    error FeeSplitInvalid(uint32 relayerSharePpm, address treasury);
    error NotSelf();
    error NothingSettled();
    error NoMakers();
    error WrongRelayer(address submitter);
    error DexMismatch(address dex);
    error TokenMismatch();
    error SelfTrade(address from);
    error DuplicateOrder(bytes32 orderHash);
    error MarketNotListed(address tokenA, address tokenB);
    /// @notice An outside leg or a DEX-side cancel whose signature does not verify (ECDSA, or ERC-1271 under its cap);
    ///         the argument is the digest that was checked.
    error BadSignature(bytes32 digest);
    error LengthMismatch();
    /// @notice Raised by `TradeLib` on outside-token legs (same selectors as `ITradeToken`), listed for the ABI.
    error NotDex(address caller);
    error DexNotContract(address dex);
    error SelfOrder(bytes32 orderHash);
    error OrderExpired(bytes32 orderHash);
    error NonceInvalidated(bytes32 orderHash);
    error BadFlags(bytes32 orderHash);
    error ZeroAmount(bytes32 orderHash);
    error BadMinFill(bytes32 orderHash);
    error FeeAboveCap(bytes32 orderHash);
    error OrderClosed(bytes32 orderHash);
    error ZeroFill(bytes32 orderHash);
    error FeeAboveSigned(bytes32 orderHash);
    error EscrowFillShape(bytes32 orderHash);
    error MinNonceNotIncreasing(uint256 current, uint256 requested);
    error MinNonceAboveCap(uint256 requested);
    /// @notice `SigCheck`'s: the submitter left too little gas for a capped ERC-1271 call (CTR-DEX-08); it reverts the
    ///         whole `mtxSettle`, never only one settlement.
    error SigCheckGasStarved(uint256 cap, uint256 gasLeft);
    error FillMismatch(uint256 expected, uint256 got);
    /// @notice Path B checks the DEX makes on the matched part (the token checks Path A itself).
    error BelowMinFill(bytes32 orderHash);
    error PriceLimit(bytes32 orderHash);
    error Overfill(bytes32 orderHash);
    error ConservationBroken(address token);

    function initialize(address creator, uint64 version, DexConfig calldata cfg) external;
    function setMarket(address base, address quote, bool listed) external;
    function setFeeSplit(uint32 relayerSharePpm, address treasury) external;
    function mtxSettle(Settlement[] calldata s) external returns (bool[] memory ok);
    /// @notice Outside-token orders (CTR-DEX-18, CTR-DEX-02): closed or bad-signature items are skipped.
    function mtxCancelOrders(DexOrder[] calldata orders, bytes[] calldata sigs) external;
    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external;

    function dexOrderDigest(address sellToken, ITradeToken.TradeOrder calldata o) external view returns (bytes32);
    function cancelOrderDigest(bytes32 orderHash) external view returns (bytes32);
    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
    /// @notice Fill state of outside-token orders, kept by the DEX (`h` = the `DexOrder` digest).
    function pulled(bytes32 orderHash) external view returns (uint256);
    function minNonce(address from, uint256 batch) external view returns (uint256);
    /// @notice The `DexPuller` holders of outside tokens approve (CTR-DEX-22), deployed by `initialize`.
    function puller() external view returns (address);

    function admin() external view returns (address);
    function relayerSharePpm() external view returns (uint32);
    function treasury() external view returns (address);
    function listedOnly() external view returns (bool);
    function marketListed(address a, address b) external view returns (bool);
    /// @notice 0 unknown, 1 SCaaS (made by the factory from a registered, non-deprecated version), 2 outside.
    function tokenKind(address token) external view returns (uint8);
    function factory() external view returns (address);
    function chainUid() external view returns (bytes32);
}
```

- [ ] **Step 4: `src/dex/SCaaSDex.sol`** (full text). Changes against `main`: constructor's third argument and the clone
  codehash; `puller` in storage, deployed by `initialize`; the views and digests; `mtxCancelOrders`,
  `mtxInvalidateNonces`, `_cap`; `mtxSettle` as a bounded low-level self-call re-raising `SigCheckGasStarved`;
  `_checkMarket` without the `OutsideLegNotBuilt` lines; `_calc` picks the kind and digest, refuses `ESCROW` outside;
  `_pull`'s outside branch; `safeTransfer`.

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ISCaaSDex} from "./ISCaaSDex.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {TradeLib} from "../trade/TradeLib.sol";
import {DexPuller} from "./DexPuller.sol";

/// @title `SCaaSDex` (CTR-DEX-16, -17, -11, -03, -24, -18, -22, -08): an EIP-1167 clone made by `OpenFactory.createDex`.
/// @notice One settlement = one taker against 1..n makers at each maker's signed price (rounded in the maker's favour).
///         Every leg is pulled into the DEX through its sell token's `mtxTrade` (Path A: the exact fill, the token
///         checks every signed bound; Path B, `ESCROW`: the whole amount, the DEX checks the matched part and refunds
///         the rest), every party is paid in the same call, each order's fee `⌈receiveFill·fee/10⁶⌉` is charged once on
///         its aggregate receive and split between the submitter and the treasury, and the DEX's balance of both
///         tokens is unchanged at the end (`ConservationBroken`). Each settlement is atomic; one that fails emits
///         `MatchFailed` (its first 256 bytes of revert data) and the others still run; a starved ERC-1271 check
///         (`SigCheckGasStarved`) reverts the whole call. The admin lists markets and sets the fee split, never an amount.
///         An outside-token leg (CTR-DEX-18) is the same `TradeOrder` signed in this DEX's domain as `DexOrder`: the DEX
///         runs the token's checks (`TradeLib`, its own `scaas.trade` state), the signature (`SigCheck`, ERC-1271
///         capped by codehash, CTR-DEX-08) and pulls the fill through its `DexPuller` (CTR-DEX-22); `ESCROW` is refused.
///         Exchange path: P2c.
contract SCaaSDex is ISCaaSDex, SaltedEIP712, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    uint256 internal constant PPM = 1_000_000;
    uint8 internal constant ESCROW = 2;
    uint8 internal constant KIND_SCAAS = 1;
    uint8 internal constant KIND_OUTSIDE = 2;
    /// @dev Bytes of a failed settlement's revert data kept for `MatchFailed`: the copy costs this frame at most this
    ///      much, so a returnbomb (an outside token reverting with megabytes) cannot take the other settlements down.
    uint256 internal constant MAX_REASON = 256;
    /// @dev ERC-1271 gas cap for this chain's `SmartKeyAccount` clones (CTR-ACC-05); other contracts get
    ///      `SigCheck.ERC1271_GAS` (50 000).
    uint256 internal constant SMART_KEY_1271_GAS = 400_000;

    /// @custom:storage-location erc7201:scaas.dex
    struct DexStorage {
        bool initialized;
        address admin;
        uint32 relayerSharePpm;
        address treasury;
        bool listedOnly;
        mapping(bytes32 pair => bool) listed;
        mapping(address token => uint8) kind;
        address puller;
    }

    bytes32 internal constant DEX_ORDER_TYPEHASH = keccak256(
        "DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,address receiveToken,uint256 amount,"
        "uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address destination,uint8 flags,"
        "uint256 batch,uint256 nonce,uint256 validUntil)"
    );

    // keccak256(abi.encode(uint256(keccak256("scaas.dex")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xb144ea5327f344ea7e3b34dd1898f534c8ce28f9f54d0d89a1b78f8fcf7dac00;

    address public immutable FACTORY;
    /// @dev EIP-1167 runtime codehash of this chain's `SmartKeyAccount` clones (0 = none), as the token's.
    bytes32 private immutable _SMART_KEY_CLONE_CODEHASH;

    /// @dev Per leg, computed before any transfer.
    struct Calc {
        bytes32 h;
        uint256 sold;    // matched sell fill
        uint256 recv;    // gross receive
        uint256 fee;     // dexFee on recv
        uint256 refund;  // Path B: amount - sold
        bool outside;    // an outside-token leg (`DexOrder`), from the DEX's listing
    }

    /// @dev Runs once on the implementation and locks it.
    constructor(address factory_, bytes32 chainUid_, address smartKeyAccountImpl_)
        SaltedEIP712("SCaaS Dex", "1", chainUid_)
    {
        FACTORY = factory_;
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0) ? bytes32(0) : keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3"));
        _s().initialized = true;
    }

    function _s() private pure returns (DexStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init and admin (CTR-DEX-24, CTR-DEX-03)

    function initialize(address, uint64, DexConfig calldata cfg) external {
        if (msg.sender != FACTORY) revert NotFactory();
        DexStorage storage s = _s();
        if (s.initialized) revert AlreadyInitialized();
        s.initialized = true;
        s.admin = cfg.admin;
        s.listedOnly = cfg.listedOnly;
        s.puller = address(new DexPuller());
        _setFeeSplit(s, cfg.relayerSharePpm, cfg.treasury);
    }

    /// @notice Lists or delists the pair and records each token's kind from the factory (never from a leg).
    function setMarket(address base, address quote, bool listed) external {
        DexStorage storage s = _onlyAdmin();
        s.listed[_pair(base, quote)] = listed;
        s.kind[base] = _classify(base);
        s.kind[quote] = _classify(quote);
        emit MarketSet(base, quote, listed);
    }

    function setFeeSplit(uint32 relayerSharePpm_, address treasury_) external {
        _setFeeSplit(_onlyAdmin(), relayerSharePpm_, treasury_);
    }

    function _setFeeSplit(DexStorage storage s, uint32 ppm, address t) private {
        if (ppm > PPM || (ppm < PPM && (t == address(0) || t == address(this)))) revert FeeSplitInvalid(ppm, t);
        s.relayerSharePpm = ppm;
        s.treasury = t;
        emit FeeSplitSet(ppm, t);
    }

    function _onlyAdmin() private view returns (DexStorage storage s) {
        s = _s();
        if (msg.sender != s.admin) revert NotAdmin(msg.sender);
    }

    /// @dev SCaaS iff the factory made it from a registered (version ≠ 0), non-deprecated implementation.
    function _classify(address token) private view returns (uint8) {
        IOpenFactory f = IOpenFactory(FACTORY);
        if (!f.isToken(token)) return KIND_OUTSIDE;
        (IOpenFactory.TokenKind k, uint64 v) = f.versionOf(token);
        return v != 0 && !f.isDeprecated(k, v) ? KIND_SCAAS : KIND_OUTSIDE;
    }

    function _pair(address a, address b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }

    // ------------------------------------------------------------------ views

    function admin() external view returns (address) { return _s().admin; }
    function relayerSharePpm() external view returns (uint32) { return _s().relayerSharePpm; }
    function treasury() external view returns (address) { return _s().treasury; }
    function listedOnly() external view returns (bool) { return _s().listedOnly; }
    function marketListed(address a, address b) external view returns (bool) { return _s().listed[_pair(a, b)]; }
    function tokenKind(address token) external view returns (uint8) { return _s().kind[token]; }
    function factory() external view returns (address) { return FACTORY; }
    function chainUid() external view returns (bytes32) { return CHAIN_UID; }
    function puller() external view returns (address) { return _s().puller; }
    function pulled(bytes32 orderHash) external view returns (uint256) { return TradeLib.$().pulled[orderHash]; }
    function minNonce(address from, uint256 batch) external view returns (uint256) {
        return TradeLib.$().minNonce[from][batch];
    }

    function dexOrderDigest(address sellToken, ITradeToken.TradeOrder calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(DEX_ORDER_TYPEHASH, sellToken, TradeLib.hashStruct(o))));
    }

    function cancelOrderDigest(bytes32 orderHash) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.CANCEL_ORDER_TYPEHASH, orderHash)));
    }

    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.INVALIDATE_NONCES_TYPEHASH, from, batch, newMin)));
    }

    // ------------------------------------------------------------------ outside-token cancels (CTR-DEX-18, -02)

    /// @notice Never expire; a closed order or a bad signature skips that item (the batch does not revert); a starved
    ///         ERC-1271 check reverts the call (CTR-DEX-08).
    function mtxCancelOrders(DexOrder[] calldata orders, bytes[] calldata sigs) external nonReentrant {
        if (orders.length != sigs.length) revert LengthMismatch();
        for (uint256 i; i < orders.length; ++i) {
            ITradeToken.TradeOrder calldata o = orders[i].order;
            bytes32 h = dexOrderDigest(orders[i].sellToken, o);
            if (SigCheck.isValid(o.from, cancelOrderDigest(h), sigs[i], _cap(o.from))) TradeLib.cancel(o, h);
        }
    }

    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external nonReentrant {
        bytes32 d = invalidateNoncesDigest(from, batch, newMin);
        if (!SigCheck.isValid(from, d, sig, _cap(from))) revert BadSignature(d);
        TradeLib.invalidate(from, batch, newMin);
    }

    /// @dev CTR-DEX-08: 400 k for a `SmartKeyAccount` clone, else 50 k.
    function _cap(address signer) private view returns (uint256) {
        bytes32 h = _SMART_KEY_CLONE_CODEHASH;
        return h != bytes32(0) && signer.codehash == h ? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
    }

    // ------------------------------------------------------------------ settle (CTR-DEX-16)

    /// @notice Each settlement atomic; at least one must succeed, else the call reverts (the relayer's simulation
    ///         catches it). A failed settlement emits `MatchFailed` with at most `MAX_REASON` bytes of its revert data;
    ///         `SigCheckGasStarved` reverts the whole call (CTR-DEX-08: the submitter's gas, not the signature, failed).
    function mtxSettle(Settlement[] calldata ss) external nonReentrant returns (bool[] memory ok) {
        ok = new bool[](ss.length);
        bool any;
        for (uint256 i; i < ss.length; ++i) {
            bytes memory data = abi.encodeCall(this.settleOne, (ss[i], msg.sender));
            bool success;
            bytes memory reason;
            assembly ("memory-safe") {
                success := call(gas(), address(), 0, add(data, 0x20), mload(data), 0, 0)
                let n := returndatasize()
                if gt(n, MAX_REASON) { n := MAX_REASON }
                reason := mload(0x40)
                mstore(reason, n)
                returndatacopy(add(reason, 0x20), 0, n)
                mstore(0x40, add(add(reason, 0x20), and(add(n, 0x1f), not(0x1f))))
            }
            if (success) {
                ok[i] = true;
                any = true;
            } else if (reason.length >= 4 && bytes4(reason) == SigCheckGasStarved.selector) {
                assembly ("memory-safe") { revert(add(reason, 0x20), mload(reason)) }
            } else {
                emit MatchFailed(ss[i].ref, reason);
            }
        }
        if (!any) revert NothingSettled();
    }

    /// @notice Only through `mtxSettle` (the self-call isolates one settlement); `submitter` is the real caller.
    function settleOne(Settlement calldata s, address submitter) external {
        if (msg.sender != address(this)) revert NotSelf();
        uint256 n = s.makers.length;
        if (n == 0) revert NoMakers();
        address tokenA = s.taker.sellToken;      // the taker sells A, the makers sell B
        address tokenB = s.taker.o.receiveToken;
        _checkMarket(tokenA, tokenB);
        Calc[] memory makers = new Calc[](n);
        uint256 takerSell;
        uint256 takerRecv;
        for (uint256 i; i < n; ++i) {
            Leg calldata m = s.makers[i];
            if (m.sellToken != tokenB || m.o.receiveToken != tokenA) revert TokenMismatch();
            if (m.o.from == s.taker.o.from) revert SelfTrade(m.o.from);
            makers[i] = _makerCalc(m, submitter);
            for (uint256 j; j < i; ++j) if (makers[j].h == makers[i].h) revert DuplicateOrder(makers[i].h);
            takerSell += makers[i].recv;
            takerRecv += makers[i].sold;
        }
        if (s.taker.fill != takerSell) revert FillMismatch(takerSell, s.taker.fill);
        Calc memory taker = _calc(s.taker, submitter, takerSell, takerRecv);
        uint256 balA = IERC20(tokenA).balanceOf(address(this));
        uint256 balB = IERC20(tokenB).balanceOf(address(this));
        _pull(s.taker, taker, submitter);
        for (uint256 i; i < n; ++i) _pull(s.makers[i], makers[i], submitter);
        _pay(s.ref, s.taker, taker, tokenB, submitter);
        for (uint256 i; i < n; ++i) _pay(s.ref, s.makers[i], makers[i], tokenA, submitter);
        if (IERC20(tokenA).balanceOf(address(this)) != balA) revert ConservationBroken(tokenA);
        if (IERC20(tokenB).balanceOf(address(this)) != balB) revert ConservationBroken(tokenB);
    }

    function _checkMarket(address a, address b) private view {
        DexStorage storage s = _s();
        if (a == b) revert TokenMismatch();
        if (!s.listed[_pair(a, b)]) revert MarketNotListed(a, b);
    }

    /// @dev A maker sells `fill` at its own price: it receives `⌈fill·receiveAmount/amount⌉` (in its favour).
    function _makerCalc(Leg calldata m, address submitter) private view returns (Calc memory c) {
        uint256 recv = Math.mulDiv(m.fill, m.o.receiveAmount, m.o.amount, Math.Rounding.Ceil);
        c = _calc(m, submitter, m.fill, recv);
    }

    /// @dev Relayer binding, `dex`, the leg's kind from the listing (an outside leg is a `DexOrder`, never `ESCROW`),
    ///      the fee on the aggregate receive; Path B: the DEX's own checks on the matched part.
    function _calc(Leg calldata l, address submitter, uint256 sold, uint256 recv) private view returns (Calc memory c) {
        ITradeToken.TradeOrder calldata o = l.o;
        if (o.relayer != address(0) && o.relayer != submitter) revert WrongRelayer(submitter);
        if (o.dex != address(this)) revert DexMismatch(o.dex);
        c.outside = _s().kind[l.sellToken] != KIND_SCAAS;
        c.h = c.outside ? dexOrderDigest(l.sellToken, o) : ITradeToken(l.sellToken).tradeOrderDigest(o);
        if (c.outside && o.flags & ESCROW != 0) revert BadFlags(c.h); // pulled exactly into the DEX: nothing to escrow
        c.sold = sold;
        c.recv = recv;
        c.fee = Math.mulDiv(recv, o.fee, PPM, Math.Rounding.Ceil);
        if (o.flags & ESCROW != 0) {
            // the token pulls `amount` once (Path B); the DEX checks what the token cannot see
            if (sold > o.amount) revert Overfill(c.h);
            if (sold != o.amount) {
                uint256 m = o.minFill > o.amount - o.amount / 2 ? o.minFill : o.amount - o.amount / 2;
                if (sold < m || recv < o.receiveAmount - o.receiveAmount / 2) revert BelowMinFill(c.h);
            }
            if (sold * o.receiveAmount > recv * o.amount) revert PriceLimit(c.h);
            c.refund = o.amount - sold;
        }
    }

    function _pull(Leg calldata l, Calc memory c, address submitter) private {
        ITradeToken.TradeFill memory f = l.o.flags & ESCROW != 0
            ? ITradeToken.TradeFill(l.o.amount, 0, 0, submitter)
            : ITradeToken.TradeFill(c.sold, c.recv, c.fee, submitter);
        if (!c.outside) return ITradeToken(l.sellToken).mtxTrade(l.o, l.sig, f);
        // outside token: the DEX runs the token's checks on its own state, then pulls through the puller
        TradeLib.precheck(l.o, f, c.h, address(this), l.sellToken);
        if (!SigCheck.isValid(l.o.from, c.h, l.sig, _cap(l.o.from))) revert BadSignature(c.h);
        DexPuller(_s().puller).pull(l.sellToken, l.o.from, TradeLib.record(l.o, f, c.h));
    }

    /// @dev Proceeds net of the fee to `destination` (or `from`), the fee split, the Path B refund.
    function _pay(bytes32 ref, Leg calldata l, Calc memory c, address recvToken, address submitter) private {
        DexStorage storage s = _s();
        address to = l.o.destination == address(0) ? l.o.from : l.o.destination;
        uint256 relayerShare = c.fee * s.relayerSharePpm / PPM;
        uint256 treasuryShare = c.fee - relayerShare;
        _send(recvToken, to, c.recv - c.fee);
        _send(recvToken, submitter, relayerShare);
        _send(recvToken, s.treasury, treasuryShare);
        _send(l.sellToken, l.o.from, c.refund);
        emit LegSettled(ref, c.h, l.o.from, to, c.sold, c.recv - c.fee, c.fee, c.refund, relayerShare, treasuryShare);
    }

    function _send(address token, address to, uint256 amount) private {
        if (amount != 0) IERC20(token).safeTransfer(to, amount);
    }
}
```

- [ ] **Step 5: deploy and the size baseline** — apply:

```diff
diff --git a/smartcontracts/evm/script/DeployBase.sol b/smartcontracts/evm/script/DeployBase.sol
index 0ee989c..fd630c3 100644
--- a/smartcontracts/evm/script/DeployBase.sol
+++ b/smartcontracts/evm/script/DeployBase.sol
@@ -55,7 +55,7 @@ abstract contract DeployBase is Script {
         vm.serializeAddress("deploy", "token_factory", address(f));
         vm.serializeAddress("deploy", "implementation_none", address(none));
         // The DEX implementation (CTR-DEX-24): clones come from `createDex`; registered as DEX version 1.
-        SCaaSDex dexImpl = new SCaaSDex{salt: salt}(address(f), uid);
+        SCaaSDex dexImpl = new SCaaSDex{salt: salt}(address(f), uid, smartKeyAccountImpl);
         if (register) f.registerDexImplementation(1, address(dexImpl));
         _gate(address(dexImpl));
         vm.serializeAddress("deploy", "dex_implementation", address(dexImpl));
diff --git a/smartcontracts/evm/size-baseline.json b/smartcontracts/evm/size-baseline.json
index a49c42d..42010b9 100644
--- a/smartcontracts/evm/size-baseline.json
+++ b/smartcontracts/evm/size-baseline.json
@@ -1,6 +1,6 @@
 {
   "_comment": "CTR-TOK-24 size gate (scripts/size_gate.py). Contracts allowed over their limit, with the measured runtime size they may not exceed. Owner 2026-10-11: size optimised later; remove an entry once the contract fits.",
-  "NoUnderlyingToken": 22951,
-  "UnderlyingToken": 29974,
+  "NoUnderlyingToken": 22960,
+  "UnderlyingToken": 29983,
   "ZetherToken": 28860
 }
```

`script/hedera/DeployHedera.s.sol` already passes `address(0)` as `smartKeyAccountImpl` to `_deployTokenFactory`; no
change there.

- [ ] **Step 6: `test/v2/Dex.t.sol`** — the 3-argument constructor everywhere (`sed -i -E 's/new SCaaSDex\(([^;]*)\);/new
  SCaaSDex(\1, address(0));/' test/v2/Dex.t.sol`), the two `OutsideLegNotBuilt` tests replaced. Resulting diff:

```diff
diff --git a/smartcontracts/evm/test/v2/Dex.t.sol b/smartcontracts/evm/test/v2/Dex.t.sol
index 2599cda..441d1a7 100644
--- a/smartcontracts/evm/test/v2/Dex.t.sol
+++ b/smartcontracts/evm/test/v2/Dex.t.sol
@@ -9,6 +9,7 @@ import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
 import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
 import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
 import {ITradeToken} from "../../src/trade/ITradeToken.sol";
+import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
 import {MockERC20} from "../helpers/Mocks.sol";
 import {UID_, noneInit} from "./helpers/V2Fixture.sol";
 
@@ -45,7 +46,7 @@ contract DexTest is Test {
     function setUp() public {
         f = new OpenFactory(registrar, UID_);
         address noneImpl = address(new NoUnderlyingToken(address(f), address(0), UID_, false));
-        dexImpl = new SCaaSDex(address(f), UID_);
+        dexImpl = new SCaaSDex(address(f), UID_, address(0));
         vm.startPrank(registrar);
         f.registerImplementation(IOpenFactory.TokenKind.NONE, 1, noneImpl);
         f.registerDexImplementation(1, address(dexImpl));
@@ -523,25 +524,57 @@ contract DexTest is Test {
     function test_gasBurning1271Maker_othersStillSettle() public { _hostileMaker(address(new Burner1271())); }
     function test_returndataBomb1271Maker_othersStillSettle() public { _hostileMaker(address(new Bomb1271())); }
 
-    function test_outsideTokenLegsAreNotBuiltYet() public {
-        MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
+    /// The kind is the DEX's listing, never the leg's: once the version is deprecated and the market listed again, `a`
+    /// and `b` are outside, a leg signed on the token is checked against its `DexOrder` digest, and the fill is pulled
+    /// through the puller (EOAs cannot approve a SCaaS token, CTR-TOK-01, so it fails on the allowance).
+    function test_deprecatedTokenListedAsOutside_isADexOrderPulledByThePuller() public {
+        vm.prank(registrar);
+        f.deprecate(IOpenFactory.TokenKind.NONE, 1, "x");
         vm.prank(admin);
-        dex.setMarket(address(a), address(usdc), true);
-        assertEq(dex.tokenKind(address(usdc)), 2);
-        assertEq(dex.tokenKind(address(a)), 1);
+        dex.setMarket(address(a), address(b), true);
         ISCaaSDex.Settlement memory s = _book();
-        s.taker.o.receiveToken = address(usdc);
-        s.taker = _leg(ALICE_PK, a, s.taker.o, 1020);
-        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.OutsideLegNotBuilt.selector, address(usdc)));
+        bytes32 h = dex.dexOrderDigest(address(a), s.taker.o);
+        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, h));
+        s.taker = _dexLeg(ALICE_PK, address(a), s.taker.o, 1020);
+        address p = dex.puller();
+        _expectOne(s, abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, p, 0, 1020));
     }
 
-    function test_takerSellsAnOutsideToken_notBuilt() public {
+    /// Alice sells 1020 of an outside token (a `DexOrder`, pulled by the puller) against the SCaaS makers of `_book`.
+    function test_takerSellsAnOutsideToken_settles() public {
         MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
+        usdc.mint(alice, 5000);
         vm.prank(admin);
         dex.setMarket(address(usdc), address(b), true);
+        assertEq(dex.tokenKind(address(usdc)), 2);
+        assertEq(dex.tokenKind(address(b)), 1);
+        address p = dex.puller();
+        vm.prank(alice);
+        usdc.approve(p, 1020);
         ISCaaSDex.Settlement memory s = _book();
-        s.taker.sellToken = address(usdc);
-        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.OutsideLegNotBuilt.selector, address(usdc)));
+        for (uint256 i; i < 2; ++i) {
+            ITradeToken.TradeOrder memory mo = s.makers[i].o;
+            mo.receiveToken = address(usdc);
+            s.makers[i] = _leg(i == 0 ? BOB_PK : CAROL_PK, b, mo, 1000);
+        }
+        s.taker = _dexLeg(ALICE_PK, address(usdc), s.taker.o, 1020);
+        bytes32 h = dex.dexOrderDigest(address(usdc), s.taker.o);
+        ISCaaSDex.Settlement[] memory ss = _one(s);
+        vm.prank(relayer);
+        dex.mtxSettle(ss);
+        assertEq(b.balanceOf(alice), 1994);
+        assertEq(usdc.balanceOf(alice), 5000 - 1020);
+        assertEq(usdc.balanceOf(bob), 499); // 500 less ceil(0.5) fee
+        assertEq(usdc.balanceOf(carol), 519);
+        assertEq(usdc.balanceOf(address(dex)), 0);
+        assertEq(dex.pulled(h), 1020);
+    }
+
+    function _dexLeg(uint256 pk, address sellToken, ITradeToken.TradeOrder memory o, uint256 fill)
+        internal view returns (ISCaaSDex.Leg memory)
+    {
+        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, dex.dexOrderDigest(sellToken, o));
+        return ISCaaSDex.Leg(sellToken, o, abi.encodePacked(r, s, v), fill);
     }
 
     function test_settleOneOnlyThroughSettle() public {
@@ -579,8 +612,8 @@ contract DexTest is Test {
 
     function test_dexCatalogue_versionZeroRefused_latestTracksTheHighest() public {
         assertEq(f.latestDexVersion(), 1);
-        SCaaSDex v5 = new SCaaSDex(address(f), UID_);
-        SCaaSDex v2 = new SCaaSDex(address(f), UID_);
+        SCaaSDex v5 = new SCaaSDex(address(f), UID_, address(0));
+        SCaaSDex v2 = new SCaaSDex(address(f), UID_, address(0));
         vm.startPrank(registrar);
         vm.expectRevert(abi.encodeWithSelector(IOpenFactory.DexVersionUnknown.selector, 0));
         f.registerDexImplementation(0, address(v2));
@@ -618,11 +651,11 @@ contract DexTest is Test {
     }
 
     function test_registerDex_checksFactoryAndChain() public {
-        SCaaSDex other = new SCaaSDex(address(0xFAC), UID_);
+        SCaaSDex other = new SCaaSDex(address(0xFAC), UID_, address(0));
         vm.startPrank(registrar);
         vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationFactoryMismatch.selector, address(other)));
         f.registerDexImplementation(2, address(other));
-        SCaaSDex wrongChain = new SCaaSDex(address(f), keccak256("x"));
+        SCaaSDex wrongChain = new SCaaSDex(address(f), keccak256("x"), address(0));
         vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, keccak256("x")));
         f.registerDexImplementation(2, address(wrongChain));
         vm.expectRevert(abi.encodeWithSelector(IOpenFactory.DexVersionAlreadyRegistered.selector, 1, address(dexImpl)));
```

- [ ] **Step 7: `test/v2/DexOutside.t.sol`** (new, full text). The DEX implementation of this fixture is built with
  `Work1271` as the `SmartKeyAccount` implementation, so `Clones.clone(work)` is a "smart key clone" (400 k) and `work`
  itself is any other contract (50 k). `Burner1271`/`Bomb1271` are imported from `Dex.t.sol`.

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {DexPuller} from "../../src/dex/DexPuller.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MockERC20, FeeOnTransferERC20} from "../helpers/Mocks.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {Burner1271, Bomb1271} from "./Dex.t.sol";
import {UID_, noneInit} from "./helpers/V2Fixture.sol";

/// ERC-1271 wallet that needs ~100 k gas to say "valid": passes under 400 k (a `SmartKeyAccount` clone), not under 50 k.
contract Work1271 {
    function isValidSignature(bytes32 d, bytes calldata) external pure returns (bytes4) {
        for (uint256 i; i < 600; i++) d = keccak256(abi.encode(d, i));
        return d == bytes32(0) ? bytes4(0) : bytes4(0x1626ba7e);
    }
}

/// Credits the recipient 1 % more than sent (a positive rebase on transfer).
contract RebaseUpERC20 is MockERC20 {
    constructor() MockERC20("Up", "UP", 18) {}
    function _update(address from, address to, uint256 v) internal override {
        super._update(from, to, v);
        if (from != address(0) && to != address(0)) super._update(address(0), to, v / 100);
    }
}

/// USDT-style: `transfer`/`transferFrom` return nothing.
contract NoReturnERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 v) external { balanceOf[to] += v; }
    function approve(address s, uint256 v) external { allowance[msg.sender][s] = v; }
    function transfer(address to, uint256 v) external { balanceOf[msg.sender] -= v; balanceOf[to] += v; }
    function transferFrom(address from, address to, uint256 v) external {
        allowance[from][msg.sender] -= v;
        balanceOf[from] -= v;
        balanceOf[to] += v;
    }
}

/// Reverts every pull with 320 000 bytes of revert data.
contract BombERC20 {
    function balanceOf(address) external pure returns (uint256) { return 0; }
    function transferFrom(address, address, uint256) external pure returns (bool) {
        assembly { revert(0, 320000) }
    }
}

/// Code, no functions: "succeeds" at everything with no return data.
contract FallbackOnly {
    fallback() external {}
}

/// Outside-token legs (CTR-DEX-18, -22, -08, -02): the same `TradeOrder` signed in the DEX's domain as `DexOrder`, the
/// token's checks run by the DEX on its own state, the fill pulled through the `DexPuller` under the party's allowance
/// to the puller, `ESCROW` refused, cancels per DEX, the ERC-1271 cap by codehash, a bounded `MatchFailed` reason, a
/// starved signature check reverting the whole call, conservation catching inexact tokens.
contract DexOutsideTest is Test {
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant DAVE_PK = 0xDA7E;
    address alice = vm.addr(ALICE_PK);
    address dave = vm.addr(DAVE_PK);
    address admin = address(0xAD);
    address treasury = address(0x7EA5);
    address relayer = address(0xBEEF);
    OpenFactory f;
    SCaaSDex dex;
    address work;             // the "SmartKeyAccount implementation" of this chain
    NoUnderlyingToken a;      // SCaaS: Alice, the taker, sells it
    MockERC20 usdc;           // outside: Dave, the maker, sells it

    function setUp() public {
        work = address(new Work1271());
        f = new OpenFactory(address(this), UID_);
        f.registerImplementation(IOpenFactory.TokenKind.NONE, 1,
            address(new NoUnderlyingToken(address(f), address(0), UID_, false)));
        f.registerDexImplementation(1, address(new SCaaSDex(address(f), UID_, work)));
        a = NoUnderlyingToken(f.createToken(IOpenFactory.TokenKind.NONE, 1,
            noneInit("A", "A", 0, 1e6, alice, address(0)), "a"));
        dex = SCaaSDex(f.createDex(1, ISCaaSDex.DexConfig(admin, 0, treasury, false), "dex"));
        usdc = _list(new MockERC20("USD Coin", "USDC", 6));
        _fund(usdc, dave);
    }

    // ------------------------------------------------------------------ helpers

    function _list(MockERC20 t) internal returns (MockERC20) {
        vm.prank(admin);
        dex.setMarket(address(a), address(t), true);
        return t;
    }

    /// `who` holds 1e6 of `t` and approves the puller (read before the prank: an external call would consume it).
    function _fund(MockERC20 t, address who) internal {
        t.mint(who, 1e6);
        address p = dex.puller();
        vm.prank(who);
        t.approve(p, type(uint256).max);
    }

    function _order(address from, address receiveToken, uint256 amount, uint256 receiveAmount, uint256 nonce)
        internal view returns (ITradeToken.TradeOrder memory o)
    {
        o.from = from;
        o.receiveToken = receiveToken;
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.dex = address(dex);
        o.batch = 1;
        o.nonce = nonce;
        o.validUntil = block.timestamp + 300;
    }

    function _outsideLeg(uint256 pk, address token, ITradeToken.TradeOrder memory o, uint256 fill)
        internal view returns (ISCaaSDex.Leg memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, dex.dexOrderDigest(token, o));
        return ISCaaSDex.Leg(token, o, abi.encodePacked(r, s, v), fill);
    }

    /// Dave's order: sells 2000 of `token` for 1000 A.
    function _dave(address token, uint256 nonce, uint256 fill) internal view returns (ISCaaSDex.Leg memory) {
        return _outsideLeg(DAVE_PK, token, _order(dave, address(a), 2000, 1000, nonce), fill);
    }

    /// Alice sells 1000 A for at least 2000 of the maker's token, filled at the maker's price.
    function _settlement(ISCaaSDex.Leg memory maker, uint256 takerNonce)
        internal view returns (ISCaaSDex.Settlement memory s)
    {
        s.ref = bytes32(takerNonce);
        s.makers = new ISCaaSDex.Leg[](1);
        s.makers[0] = maker;
        s.taker = _taker(_order(alice, maker.sellToken, 1000, 2000, takerNonce), (maker.fill + 1) / 2);
    }

    function _taker(ITradeToken.TradeOrder memory t, uint256 fill) internal view returns (ISCaaSDex.Leg memory) {
        return ISCaaSDex.Leg(address(a), t, _sig(ALICE_PK, a.tradeOrderDigest(t)), fill);
    }

    function _one(ISCaaSDex.Settlement memory s) internal pure returns (ISCaaSDex.Settlement[] memory ss) {
        ss = new ISCaaSDex.Settlement[](1);
        ss[0] = s;
    }

    function _two(ISCaaSDex.Settlement memory s0, ISCaaSDex.Settlement memory s1)
        internal pure returns (ISCaaSDex.Settlement[] memory ss)
    {
        ss = new ISCaaSDex.Settlement[](2);
        ss[0] = s0;
        ss[1] = s1;
    }

    function _expectOne(ISCaaSDex.Settlement memory s, bytes memory err) internal {
        vm.prank(address(dex));
        vm.expectRevert(err);
        dex.settleOne(s, relayer);
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    // ------------------------------------------------------------------ the leg

    function test_outsideMaker_pulledThroughThePuller() public {
        ISCaaSDex.Settlement memory s = _settlement(_dave(address(usdc), 1, 2000), 1);
        bytes32 h = dex.dexOrderDigest(address(usdc), s.makers[0].o);
        address p = dex.puller();
        ISCaaSDex.Settlement[] memory ss = _one(s);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.TradeFilled(h, dave, 2000, 1000, 0);
        vm.prank(relayer);
        dex.mtxSettle(ss);
        assertEq(usdc.balanceOf(alice), 2000);
        assertEq(a.balanceOf(dave), 1000);
        assertEq(usdc.balanceOf(dave), 1e6 - 2000);
        assertEq(usdc.balanceOf(address(dex)), 0);
        assertEq(usdc.balanceOf(p), 0);
        assertEq(dex.pulled(h), 2000);
        assertEq(usdc.allowance(dave, address(dex)), 0); // the DEX holds no allowance
    }

    function test_outsideOrder_isCheckedByTheDex() public {
        ITradeToken.TradeOrder memory mo = _order(dave, address(a), 2000, 1000, 1);
        mo.flags = 3; // IOC | ESCROW: refused for outside legs
        ISCaaSDex.Settlement memory s = _settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 2000), 1);
        bytes32 h = dex.dexOrderDigest(address(usdc), mo);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BadFlags.selector, h));
        s = _settlement(_dave(address(usdc), 1, 2000), 1);
        s.makers[0].sig[0] = bytes1(uint8(s.makers[0].sig[0]) ^ 1);
        h = dex.dexOrderDigest(address(usdc), s.makers[0].o);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, h));
        mo = _order(dave, address(a), 2000, 1000, 1);
        mo.validUntil = block.timestamp - 1;
        s = _settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 2000), 1);
        h = dex.dexOrderDigest(address(usdc), mo);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.OrderExpired.selector, h));
        mo = _order(address(usdc), address(a), 2000, 1000, 1); // `from` is the sell token itself
        s = _settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 2000), 1);
        h = dex.dexOrderDigest(address(usdc), mo);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.SelfOrder.selector, h));
        mo = _order(dave, address(a), 2000, 1000, 1);
        mo.flags = 1; // IOC alone is allowed
        s = _settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 1000), 1);
        ISCaaSDex.Settlement[] memory ss = _one(s);
        vm.prank(relayer);
        dex.mtxSettle(ss);
        assertEq(dex.pulled(dex.dexOrderDigest(address(usdc), mo)), 2000); // IOC: closed at its one pull
    }

    /// Path A bounds on an outside leg are the DEX's (`TradeLib.record` on its own state): minimum fill, accumulation,
    /// remainder, close.
    function test_outsidePartialFills_accumulateOnTheDex_thenClosed() public {
        ISCaaSDex.Settlement memory s = _settlement(_dave(address(usdc), 1, 998), 1);
        s.taker = _taker(_order(alice, address(usdc), 499, 998, 1), 499); // the taker whole, Dave below half
        bytes32 h = dex.dexOrderDigest(address(usdc), s.makers[0].o);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BelowMinFill.selector, h));
        ISCaaSDex.Settlement[] memory ss = _two(
            _settlement(_dave(address(usdc), 1, 1000), 1), _settlement(_dave(address(usdc), 1, 1000), 2));
        vm.prank(relayer);
        dex.mtxSettle(ss);
        assertEq(dex.pulled(h), 2000);
        assertEq(usdc.balanceOf(alice), 2000);
        s = _settlement(_dave(address(usdc), 1, 1000), 3);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.OrderClosed.selector, h));
    }

    /// The digest is EIP-712 over the DEX's salted domain and binds the sell token.
    function test_dexOrderDigest_isEip712OverTheDexDomain_andBindsTheSellToken() public {
        ITradeToken.TradeOrder memory o = _order(dave, address(a), 2000, 1000, 1);
        bytes32 domain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS Dex"), keccak256("1"), block.chainid, address(dex), UID_));
        bytes32 orderStruct = keccak256(abi.encode(keccak256(
            "TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,"
            "uint256 fee,address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,"
            "uint256 validUntil)"), o));
        bytes32 dexOrderType = keccak256(
            "DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,address receiveToken,uint256 amount,"
            "uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address destination,"
            "uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)");
        bytes32 h = keccak256(abi.encodePacked(
            "\x19\x01", domain, keccak256(abi.encode(dexOrderType, address(usdc), orderStruct))));
        assertEq(dex.dexOrderDigest(address(usdc), o), h);
        assertEq(dex.cancelOrderDigest(h), keccak256(abi.encodePacked(
            "\x19\x01", domain, keccak256(abi.encode(keccak256("CancelOrder(bytes32 orderHash)"), h)))));
        assertEq(dex.invalidateNoncesDigest(dave, 1, 5), keccak256(abi.encodePacked("\x19\x01", domain, keccak256(
            abi.encode(keccak256("InvalidateNonces(address from,uint256 batch,uint256 minNonce)"), dave, 1, 5)))));
        // signed for another sell token: refused
        ISCaaSDex.Settlement memory s = _settlement(_dave(address(usdc), 1, 2000), 1);
        s.makers[0].sig = _sig(DAVE_PK, dex.dexOrderDigest(address(a), o));
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, h));
    }

    /// The spender is the puller: an allowance to the DEX moves nothing.
    function test_pullUsesTheAllowanceToThePuller_notToTheDex() public {
        address p = dex.puller();
        vm.startPrank(dave);
        usdc.approve(p, 0);
        usdc.approve(address(dex), type(uint256).max);
        vm.stopPrank();
        ISCaaSDex.Settlement memory s = _settlement(_dave(address(usdc), 1, 2000), 1);
        _expectOne(s, abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, p, 0, 2000));
    }

    function test_onlyTheDexPulls() public {
        DexPuller p = DexPuller(dex.puller());
        assertEq(p.dex(), address(dex));
        vm.expectRevert(abi.encodeWithSelector(DexPuller.NotDex.selector, address(this)));
        p.pull(address(usdc), dave, 1);
    }

    // ------------------------------------------------------------------ tokens that are not exact

    function test_feeOnTransferToken_conservationCatchesIt() public {
        MockERC20 fot = _list(new FeeOnTransferERC20());
        _fund(fot, dave);
        ISCaaSDex.Settlement[] memory ss = _one(_settlement(_dave(address(fot), 1, 2000), 1));
        // the DEX receives 1 % less than it pulled: paying the taker fails, nothing moves
        vm.prank(relayer);
        vm.expectRevert(ISCaaSDex.NothingSettled.selector);
        dex.mtxSettle(ss);
        // with a donated balance the payment goes through and conservation reverts the settlement
        fot.mint(address(dex), 10_000);
        _expectOne(ss[0], abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(fot)));
    }

    function test_rebasingUpToken_conservationCatchesIt() public {
        MockERC20 up = _list(new RebaseUpERC20());
        _fund(up, dave);
        ISCaaSDex.Settlement memory s = _settlement(_dave(address(up), 1, 2000), 1);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(up)));
    }

    /// `transfer`/`transferFrom` without a return value (USDT): settles through `SafeERC20`.
    function test_noReturnValueToken_settles() public {
        NoReturnERC20 t = new NoReturnERC20();
        vm.prank(admin);
        dex.setMarket(address(a), address(t), true);
        t.mint(dave, 5000);
        address p = dex.puller();
        vm.prank(dave);
        t.approve(p, 2000);
        ISCaaSDex.Settlement[] memory ss = _one(_settlement(_dave(address(t), 1, 2000), 1));
        vm.prank(relayer);
        dex.mtxSettle(ss);
        assertEq(t.balanceOf(alice), 2000);
        assertEq(t.balanceOf(dave), 3000);
        assertEq(t.balanceOf(address(dex)), 0);
    }

    /// A contract with only a fallback is outside (the factory did not make it), so it never goes down `mtxTrade`;
    /// its empty answers fail the settlement.
    function test_fallbackOnlyToken_isOutside_andFails() public {
        address fb = address(new FallbackOnly());
        vm.prank(admin);
        dex.setMarket(address(a), fb, true);
        assertEq(dex.tokenKind(fb), 2);
        ISCaaSDex.Settlement[] memory ss = _one(_settlement(_dave(fb, 1, 2000), 1));
        vm.prank(relayer);
        vm.expectRevert(ISCaaSDex.NothingSettled.selector);
        dex.mtxSettle(ss);
    }

    // ------------------------------------------------------------------ MatchFailed

    function test_matchFailed_carriesTheRevertData() public {
        ITradeToken.TradeOrder memory mo = _order(dave, address(a), 2000, 1000, 1);
        mo.validUntil = block.timestamp - 1;
        bytes32 h = dex.dexOrderDigest(address(usdc), mo);
        ISCaaSDex.Settlement[] memory ss = _two(
            _settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 2000), 1), _settlement(_dave(address(usdc), 2, 2000), 2));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.MatchFailed(bytes32(uint256(1)), abi.encodeWithSelector(ITradeToken.OrderExpired.selector, h));
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle(ss);
        assertFalse(ok[0]);
        assertTrue(ok[1]);
    }

    /// An outside token reverting with 320 000 bytes: `MatchFailed` keeps 256, and the copy is cheap enough that the
    /// next settlement still runs under a gas limit an unbounded copy would exhaust.
    function test_returnbombToken_reasonIsBounded_othersSettle() public {
        address bomb = address(new BombERC20());
        vm.prank(admin);
        dex.setMarket(address(a), bomb, true);
        ISCaaSDex.Settlement[] memory ss = _two(
            _settlement(_dave(bomb, 1, 2000), 1), _settlement(_dave(address(usdc), 2, 2000), 2));
        vm.recordLogs();
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle{gas: 3_000_000}(ss);
        assertFalse(ok[0]);
        assertTrue(ok[1]);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes memory reason;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == ISCaaSDex.MatchFailed.selector) reason = abi.decode(logs[i].data, (bytes));
        }
        assertEq(reason.length, 256);
    }

    // ------------------------------------------------------------------ ERC-1271 (CTR-DEX-08)

    function test_erc1271OutsideSigner_settles() public {
        Mock1271Wallet w = new Mock1271Wallet(dave);
        _fund(usdc, address(w));
        ITradeToken.TradeOrder memory mo = _order(address(w), address(a), 2000, 1000, 1);
        ISCaaSDex.Settlement[] memory ss = _one(_settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 2000), 1));
        vm.prank(relayer);
        dex.mtxSettle(ss);
        assertEq(a.balanceOf(address(w)), 1000);
    }

    /// 400 k for a clone of this chain's `SmartKeyAccount` implementation, 50 k for any other contract: in settle,
    /// cancel and invalidate alike.
    function test_erc1271Cap_400kOnlyForSmartKeyClones() public {
        address clone = Clones.clone(work);
        _fund(usdc, clone);
        _fund(usdc, work);
        ITradeToken.TradeOrder memory co = _order(clone, address(a), 2000, 1000, 1);
        ITradeToken.TradeOrder memory wo = _order(work, address(a), 2000, 1000, 1);
        bytes32 hc = dex.dexOrderDigest(address(usdc), co);
        bytes32 hw = dex.dexOrderDigest(address(usdc), wo);
        ISCaaSDex.Settlement memory sw = _settlement(ISCaaSDex.Leg(address(usdc), wo, hex"00", 2000), 1);
        _expectOne(sw, abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, hw));
        ISCaaSDex.Settlement[] memory ss = _one(_settlement(ISCaaSDex.Leg(address(usdc), co, hex"00", 1000), 1));
        vm.prank(relayer);
        dex.mtxSettle(ss);
        assertEq(dex.pulled(hc), 1000);
        // cancel: the clone's item closes, the bare contract's is skipped
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](2);
        os[0] = ISCaaSDex.DexOrder(address(usdc), co);
        os[1] = ISCaaSDex.DexOrder(address(usdc), wo);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = hex"00";
        sigs[1] = hex"00";
        dex.mtxCancelOrders(os, sigs);
        assertEq(dex.pulled(hc), 2000);
        assertEq(dex.pulled(hw), 0);
        // invalidate
        dex.mtxInvalidateNonces(clone, 1, 5, hex"00");
        assertEq(dex.minNonce(clone, 1), 5);
        bytes32 d = dex.invalidateNoncesDigest(work, 1, 5);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, d));
        dex.mtxInvalidateNonces(work, 1, 5, hex"00");
    }

    /// m8 (CTR-DEX-08): a submitter that leaves too little gas for a capped ERC-1271 check reverts the whole call, even
    /// when another settlement in it succeeded; with enough gas the same call settles both.
    function test_starvedSigCheck_revertsTheWholeCall() public {
        address clone = Clones.clone(work);
        _fund(usdc, clone);
        ITradeToken.TradeOrder memory co = _order(clone, address(a), 2000, 1000, 1);
        ISCaaSDex.Settlement[] memory ss = _two(
            _settlement(_dave(address(usdc), 1, 2000), 1),
            _settlement(ISCaaSDex.Leg(address(usdc), co, hex"00", 2000), 2));
        vm.prank(relayer);
        vm.expectPartialRevert(ISCaaSDex.SigCheckGasStarved.selector);
        dex.mtxSettle{gas: 700_000}(ss);
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle(ss);
        assertTrue(ok[0] && ok[1]);
    }

    function _hostileMaker(address w) internal {
        ISCaaSDex.Settlement[] memory ss = _two(
            _settlement(ISCaaSDex.Leg(address(usdc), _order(w, address(a), 2000, 1000, 1), hex"00", 2000), 1),
            _settlement(_dave(address(usdc), 1, 2000), 2));
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle{gas: 3_000_000}(ss);
        assertFalse(ok[0]);
        assertTrue(ok[1]);
    }

    function test_gasBurning1271OutsideMaker_othersStillSettle() public { _hostileMaker(address(new Burner1271())); }
    function test_returndataBomb1271OutsideMaker_othersStillSettle() public { _hostileMaker(address(new Bomb1271())); }

    // ------------------------------------------------------------------ cancels (CTR-DEX-02, CTR-DEX-18)

    function test_cancelOrders_skipsBadItems_andInvalidateNonces() public {
        ITradeToken.TradeOrder memory good = _order(dave, address(a), 2000, 1000, 1);
        ITradeToken.TradeOrder memory bad = _order(dave, address(a), 2000, 1000, 2);
        bytes32 hg = dex.dexOrderDigest(address(usdc), good);
        bytes32 hb = dex.dexOrderDigest(address(usdc), bad);
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](2);
        os[0] = ISCaaSDex.DexOrder(address(usdc), good);
        os[1] = ISCaaSDex.DexOrder(address(usdc), bad);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sig(DAVE_PK, dex.cancelOrderDigest(hg));
        sigs[1] = _sig(0xBAD, dex.cancelOrderDigest(hb));
        vm.expectRevert(ISCaaSDex.LengthMismatch.selector);
        dex.mtxCancelOrders(os, new bytes[](1));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.OrderCancelled(hg, dave);
        dex.mtxCancelOrders(os, sigs);
        assertEq(dex.pulled(hg), 2000);
        assertEq(dex.pulled(hb), 0);
        dex.mtxCancelOrders(os, sigs); // replay: a no-op, not an error
        ISCaaSDex.Settlement memory st = _settlement(_dave(address(usdc), 1, 2000), 1);
        _expectOne(st, abi.encodeWithSelector(ISCaaSDex.OrderClosed.selector, hg));
        bytes memory inv = _sig(DAVE_PK, dex.invalidateNoncesDigest(dave, 1, 5));
        dex.mtxInvalidateNonces(dave, 1, 5, inv);
        assertEq(dex.minNonce(dave, 1), 5);
        st = _settlement(_dave(address(usdc), 2, 2000), 1);
        _expectOne(st, abi.encodeWithSelector(ISCaaSDex.NonceInvalidated.selector, hb));
        bytes32 d6 = dex.invalidateNoncesDigest(dave, 1, 6);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, d6)); // signed for 5, replayed for 6
        dex.mtxInvalidateNonces(dave, 1, 6, inv);
    }

    /// A gas-burning or returndata-bomb ERC-1271 signer in a cancel batch is skipped; the others are cancelled.
    function test_hostile1271InACancelBatch_isSkipped() public {
        address burner = address(new Burner1271());
        address bomb = address(new Bomb1271());
        ITradeToken.TradeOrder memory good = _order(dave, address(a), 2000, 1000, 1);
        bytes32 hg = dex.dexOrderDigest(address(usdc), good);
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](3);
        os[0] = ISCaaSDex.DexOrder(address(usdc), _order(burner, address(a), 2000, 1000, 1));
        os[1] = ISCaaSDex.DexOrder(address(usdc), _order(bomb, address(a), 2000, 1000, 1));
        os[2] = ISCaaSDex.DexOrder(address(usdc), good);
        bytes[] memory sigs = new bytes[](3);
        sigs[0] = hex"00";
        sigs[1] = hex"00";
        sigs[2] = _sig(DAVE_PK, dex.cancelOrderDigest(hg));
        dex.mtxCancelOrders{gas: 1_000_000}(os, sigs);
        assertEq(dex.pulled(hg), 2000);
        assertEq(dex.pulled(dex.dexOrderDigest(address(usdc), os[0].order)), 0);
    }
}
```

- [ ] **Step 8: Run** (each through `scripts/capped`, one at a time):
  - `forge test --match-path "test/v2/Dex*.t.sol"` → 55 passed (Dex 36, DexOutside 19).
  - `forge test` → **910 passed** (891 + 19), 0 failed.
  - Size gate: `forge build src --sizes --json > /tmp/sizes.json || true; python3 ../../scripts/size_gate.py
    /tmp/sizes.json size-baseline.json` → `0 error(s)`.
  - e2e: `forge build` (full), then in `scaas-node`: `cargo test --test e2e -- --ignored --test-threads=1` → 4 passed;
    `cargo test --test e2e_hedera -- --ignored` → 1 passed. (A fresh worktree may reuse the main checkout's build cache
    with `CARGO_TARGET_DIR=/home/ha/work/ainative/scaas/scaas-node/target`.)
  - **Mutation probe** (not committed; save as a scratch file and run with `scripts/capped python3 <file>`): every mutant
    must be `KILLED`. Validated: 20/20 killed.

```python
import subprocess, sys, shutil
W='/home/ha/work/ainative/scaas/.claude/worktrees/p2b2/smartcontracts/evm'
D=W+'/src/dex/SCaaSDex.sol'
L=W+'/src/trade/TradeLib.sol'
P=W+'/src/dex/DexPuller.sol'
muts=[
 ('M1 unbounded reason', D, 'if gt(n, MAX_REASON) { n := MAX_REASON }', ''),
 ('M2 no m8 re-raise', D, 'else if (reason.length >= 4 && bytes4(reason) == SigCheckGasStarved.selector)', 'else if (false)'),
 ('M3 cap always 50k', D, '? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS', '? SigCheck.ERC1271_GAS : SigCheck.ERC1271_GAS'),
 ('M4 cap always 400k', D, '? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS', '? SMART_KEY_1271_GAS : SMART_KEY_1271_GAS'),
 ('M5 no BadFlags for outside escrow', D, 'if (c.outside && o.flags & ESCROW != 0) revert BadFlags(c.h);', ''),
 ('M6 unsafe transfer', D, 'IERC20(token).safeTransfer(to, amount)', 'IERC20(token).transfer(to, amount)'),
 ('M7 SelfOrder token clause dropped', L, 'if (o.from == token || o.dex == token)', 'if (o.dex == token)'),
 ('M8 cancel cap 50k', D, 'cancelOrderDigest(h), sigs[i], _cap(o.from))', 'cancelOrderDigest(h), sigs[i], SigCheck.ERC1271_GAS)'),
 ('M9 invalidate cap 50k', D, 'if (!SigCheck.isValid(from, d, sig, _cap(from)))', 'if (!SigCheck.isValid(from, d, sig, SigCheck.ERC1271_GAS))'),
 ('M10 skip record', D, 'DexPuller(_s().puller).pull(l.sellToken, l.o.from, TradeLib.record(l.o, f, c.h));', 'DexPuller(_s().puller).pull(l.sellToken, l.o.from, c.sold);'),
 ('M11 skip precheck', D, 'TradeLib.precheck(l.o, f, c.h, address(this), l.sellToken);', ''),
 ('M12 skip outside sig', D, 'if (!SigCheck.isValid(l.o.from, c.h, l.sig, _cap(l.o.from))) revert BadSignature(c.h);', ''),
 ('M13 reason length 0', D, 'mstore(reason, n)', 'mstore(reason, 0)'),
 ('M14 MAX_REASON 32', D, 'uint256 internal constant MAX_REASON = 256;', 'uint256 internal constant MAX_REASON = 32;'),
 ('M15 cancel if invalid', D, 'if (SigCheck.isValid(o.from, cancelOrderDigest(h)', 'if (!SigCheck.isValid(o.from, cancelOrderDigest(h)'),
 ('M16 no length check', D, 'if (orders.length != sigs.length) revert LengthMismatch();', ''),
 ('M17 puller unrestricted', P, 'if (msg.sender != dex) revert NotDex(msg.sender);', ''),
 ('M18 pull to puller', P, 'safeTransferFrom(from, dex, amount)', 'safeTransferFrom(from, address(this), amount)'),
 ('M19 digest no sellToken', D, 'keccak256(abi.encode(DEX_ORDER_TYPEHASH, sellToken, TradeLib.hashStruct(o)))', 'keccak256(abi.encode(DEX_ORDER_TYPEHASH, address(0), TradeLib.hashStruct(o)))'),
 ('M20 outside by leg false', D, 'c.outside = _s().kind[l.sellToken] != KIND_SCAAS;', 'c.outside = false;'),
]
sel=sys.argv[1:] 
for name,f,a,b in muts:
    if sel and name.split()[0] not in sel: continue
    src=open(f).read(); assert src.count(a)==1,(name)
    open(f,'w').write(src.replace(a,b))
    try:
        r=subprocess.run(['forge','test','--match-path','test/v2/Dex*.t.sol'],cwd=W,capture_output=True,text=True)
        out=r.stdout+r.stderr
        fails=[l for l in out.splitlines() if l.startswith('[FAIL')]
        status='KILLED' if fails or 'Compiler run failed' in out or r.returncode!=0 else 'SURVIVED'
        print(name, status, len(fails), (fails[0][:150] if fails else ''), flush=True)
    finally:
        open(f,'w').write(src)
```

  | Mutant | Killed by |
  |---|---|
  | M1 reason copy unbounded | `test_returnbombToken_reasonIsBounded_othersSettle` (out of gas at 3 M) |
  | M2 no m8 re-raise | `test_starvedSigCheck_revertsTheWholeCall` |
  | M3 / M4 cap always 50 k / always 400 k | `test_erc1271Cap_400kOnlyForSmartKeyClones` |
  | M5 no `BadFlags` for an outside `ESCROW` | `test_outsideOrder_isCheckedByTheDex` |
  | M6 `transfer` instead of `safeTransfer` | `test_noReturnValueToken_settles` |
  | M7 `SelfOrder` without the `from == token` clause | `test_outsideOrder_isCheckedByTheDex` |
  | M8 / M9 cancel / invalidate with the 50 k cap | `test_erc1271Cap_400kOnlyForSmartKeyClones` |
  | M10 pull `c.sold` without `record` | `test_outsidePartialFills_…`, `test_outsideMaker_…`, cancel tests |
  | M11 no `precheck` / M12 no outside signature check | `test_outsideOrder_isCheckedByTheDex`, digest test |
  | M13 empty reason / M14 `MAX_REASON = 32` | `test_matchFailed_carriesTheRevertData`, returnbomb test |
  | M15 cancel on an invalid signature / M16 no `LengthMismatch` | `test_cancelOrders_skipsBadItems_andInvalidateNonces` |
  | M17 puller callable by anyone / M18 puller pulls to itself | `test_onlyTheDexPulls` / every outside settle |
  | M19 digest without `sellToken` | `test_dexOrderDigest_isEip712OverTheDexDomain_andBindsTheSellToken` |
  | M20 kind always SCaaS | every outside test |

- [ ] **Step 9: Commit** — `P2b-2: outside-token legs on SCaaSDex — DexOrder, DexPuller, DEX-side cancels, ERC-1271 cap by codehash; bounded MatchFailed reason, SigCheckGasStarved reverts the call` + trailer.

---

### Task 2: Docs, TODO, HANDOFF

**Model:** Sonnet, effort medium. Component docs say "controller ruling, pending the owner", never an H-id. `dex.md` net
≤ 0 lines (validated: −1); `settlement.md` net 0.

- [ ] **Step 1: `docs/contracts/dex.md`** — the header status (built except the exchange path); the CTR-DEX-16 note
  (P2b-1 + P2b-2, `OutsideLegNotBuilt` gone, bounded `MatchFailed`, `SigCheckGasStarved`); CTR-DEX-18 gets a
  "Transitional (BUILT, P2b-2)" table row (built names, `TradeLib` on the DEX's state, `BadSignature(digest)`,
  `LengthMismatch`, `SafeERC20`, no `checkOrder` — H7); CTR-DEX-22 "deployed by the DEX's `initialize`" (H2); CTR-DEX-08
  status **BUILT** (P2b-2); §13's closing paragraph; §14's forge row names `DexOutside.t.sol`. Apply:

```diff
diff --git a/docs/contracts/dex.md b/docs/contracts/dex.md
index 277947f..d214776 100644
--- a/docs/contracts/dex.md
+++ b/docs/contracts/dex.md
@@ -5,7 +5,7 @@ and whose settlement contract settles signed orders on chain. Users never pay ga
 messages that a relayer submits, and a SCaaS token needs **no allowance** to trade — its order is verified by the token
 itself, which moves funds only into the DEX the signer named. Status: the target of this file (token-verified
 `TradeOrder`s, `SCaaSDex.mtxSettle`, outside-token legs, one signed fee rate, the exchange path against AMMs
-`mtxExchange`, the `DexPuller`) **SPECIFIED**, **BUILT** for SCaaS legs, fee split and `createDex` (`SCaaSDex`, P2b-1);
+`mtxExchange`, the `DexPuller`) **SPECIFIED**, **BUILT** except the exchange path (`SCaaSDex`, P2b-1, P2b-2);
 `SCaaSDexV1` (DEX-signed orders over allowances, the node's DEX until P5) and the legacy `MetaTxDex` are **BUILT**
 ([Transitional](#transitional-built)); non-EVM settlement programs **BUILT** with the fixes below **SPECIFIED**.
 
@@ -229,13 +229,12 @@ reason)`); if none succeeds the whole call reverts, so the relayer's simulation
 5. **Invariant**, asserted at the end of each settlement: the DEX's balance of every token touched is unchanged
    (`ConservationBroken(token)`).
 
-**Transitional (BUILT, P2b-1).** `SCaaSDex` (`src/dex/SCaaSDex.sol`; a clone, namespace `scaas.dex`, salted domain `("SCaaS
-Dex","1",chainId,clone,chain_uid)`) builds this for SCaaS legs, each in a self-call (`settleOne`). Outside-token legs,
-`DexOrder`, the `DexPuller`, DEX-side cancels, `checkOrder` and the ERC-1271 cap are P2b-2, the exchange path P2c (controller
-ruling, pending the owner): an outside token's market lists but settling it reverts `OutsideLegNotBuilt(token)`. Path A
-bounds are the token's; on Path B the DEX checks `Overfill`, `BelowMinFill`, `PriceLimit` on the matched part. Also
-`SelfTrade`, `DuplicateOrder`, `NoMakers`, `FillMismatch`, `NothingSettled`; a maker receives `ceil(fill · receiveAmount /
-amount)`. Before it: `SCaaSDexV1` ([§13](#transitional-built)).
+**Transitional (BUILT, P2b-1, P2b-2).** `SCaaSDex` (`src/dex/SCaaSDex.sol`; a clone, namespace `scaas.dex`, salted domain
+`("SCaaS Dex","1",chainId,clone,chain_uid)`) builds this, each settlement in a self-call (`settleOne`), outside legs per
+[CTR-DEX-18](#CTR-DEX-18). Path A bounds are the token's; on Path B the DEX checks `Overfill`, `BelowMinFill`, `PriceLimit`
+on the matched part. Also `SelfTrade`, `DuplicateOrder`, `NoMakers`, `FillMismatch`, `NothingSettled`; a maker receives
+`ceil(fill · receiveAmount / amount)`; `MatchFailed` keeps the first 256 bytes of the revert data, `SigCheckGasStarved`
+reverts the whole call (controller ruling, pending the owner). Before it: `SCaaSDexV1` ([§13](#transitional-built)).
 
 | Leg | Pulled into the DEX | Bounds checked by |
 |---|---|---|
@@ -336,6 +335,7 @@ by the DEX** (a contract SCaaS does not control cannot verify it):
 | Pull | `DexPuller.pull(token, from, sellFill)` = `safeTransferFrom(from, DEX, sellFill)` under the party's allowance to the **puller**, never to the DEX ([CTR-DEX-22](#CTR-DEX-22)); an EOA may approve a contract on a token SCaaS does not control |
 | Cancel | `mtxCancelOrders(DexOrder[] orders, bytes[] sigs)` (`CancelOrder(bytes32 orderHash)` in the DEX domain; closed or bad-signature items skipped, no revert of the batch) and `mtxInvalidateNonces(from, batch, newMin, sig)` (`InvalidateNonces(address from,uint256 batch,uint256 minNonce)` in the DEX domain) |
 | Backstop | conservation ([CTR-DEX-16](#CTR-DEX-16)) |
+| Transitional (BUILT, P2b-2) | on the DEX: `dexOrderDigest(sellToken, o)`, `cancelOrderDigest`, `invalidateNoncesDigest`, `pulled`, `minNonce`, `puller()`; `TradeLib`'s checks on the DEX's own `scaas.trade` state, the leg's token as the sell token (`SelfOrder` if `from` is it); `BadSignature(digest)`, `LengthMismatch`; payouts by `SafeERC20`; no `checkOrder`: the [section 10](#10-intake-reads-and-invariants) reads are the intake (controller ruling, pending the owner) |
 
 ## 7. Exchange settlement
 
@@ -381,7 +381,7 @@ policy ([NODE-DEX-18](../node/dex-venue.md#NODE-DEX-18)), measurable through `Ex
 
 <a id="puller"></a>
 <a id="CTR-DEX-22"></a>**CTR-DEX-22** — **`DexPuller`: the DEX holds no user allowance.** An immutable contract deployed
-by the DEX's constructor, `pull(token, from, amount)` callable only by the DEX (`safeTransferFrom(from, dex, amount)`).
+by the DEX's `initialize`, `pull(token, from, amount)` callable only by the DEX (`safeTransferFrom(from, dex, amount)`).
 Holders of an **outside** token approve the puller, never the DEX; the DEX calls `pull` only after its own checks of the
 `DexOrder`, for `mtxSettle` and the exchange path alike. Why: an interaction runs as the DEX, so any allowance the DEX
 held could be spent by `outsideToken.transferFrom(victim, attacker, x)`. SCaaS tokens need no allowance at all.
@@ -421,7 +421,7 @@ only returns `false` ⇒ the item is skipped. The node does not restore an ERC-1
 gas. Why: the built contract calls `SignatureChecker` without a cap (`SCaaSDexV1.sol:383-384`), so a contract maker
 that answers correctly under `eth_call` but burns gas or returns huge returndata in the real block breaks a whole
 `settle` batch (the remaining 1/64 gas is not enough for the next pairs) and **every** `cancel` batch. SCaaS legs get
-the same cap inside their token. Status **SPECIFIED**.
+the same cap inside their token. Status **BUILT** (P2b-2).
 
 ## 10. Intake reads and invariants
 
@@ -542,15 +542,14 @@ intake fails alone (`MatchFailed`). The node side (home-bound orders only, the f
   to `a.m.from` with `SafeERC20.safeTransfer` and `emit TradeSettled(a.m.from, b.m.from, a.token, b.token, a.m.value, b.m.value)`. Fill-or-kill; the surplus
   `b.m.value > minCounterValue` belongs to the seller of leg A.
 
-The rebuild deletes `MetaTxDex` and the trade and approve ops, renames `settle`/`cancel`/`invalidateNonces` to `mtxSettle`/`mtxCancelOrders`/`mtxInvalidateNonces`, keeps the
-DEX-domain `Order` only as `DexOrder` (P2b-2), keeps allowances only for outside tokens (the `DexPuller`) and turns the relayer fee into the relayer's share of the signed DEX
-fee (built in `SCaaSDex`, P2b-1); the exchange path ([CTR-DEX-20](#CTR-DEX-20)…[CTR-DEX-23](#CTR-DEX-23)) is not built.
+The rebuild (`SCaaSDex`, P2b-1, P2b-2) deletes `MetaTxDex` and the trade and approve ops, renames `settle`/`cancel`/`invalidateNonces` to `mtxSettle`/`mtxCancelOrders`/
+`mtxInvalidateNonces`, keeps the DEX-domain `Order` only as `DexOrder`, allowances only to the `DexPuller`, the relayer fee only as its share of the signed DEX fee; P2c: [CTR-DEX-20](#CTR-DEX-20)…[-23](#CTR-DEX-23).
 
 ## 14. Conformance
 
 | Layer | Tests |
 |---|---|
-| forge | Path A and Path B, one taker × many makers; `mtxTrade` on a closed, cancelled or IOC-pulled order and with `sellFill = 0` reverts; Path B `sellFill ≠ amount` reverts; `dex` = EOA refused; caller ≠ `dex` refused; every `mtxTrade` error; effective minimum fill for taker and makers incl. the remainder close and `minFill > amount`; FOK via `minFill = amount`; taker fee charged once on the aggregate; split rounding; conservation (unit + invariant: the DEX holds 0 after every handler sequence; for the new DEX the unit tests are built in `test/v2/Dex.t.sol` (P2b-1: settle with two makers, maker rounding, aggregate fee, Path B fee, signed `minFill` and refund, Path A figures seen by the token, isolated failure, arrangement checks, `createDex` and the DEX catalogue, registry, fee split, salted domain) and the invariant suite is open); `DexOrder` legs incl. a fallback-only "token" classified outside and `ESCROW` refused; cancel per token and per DEX (signature, replay, lane cap); ERC-1271 maker under the 400 k cap; a 1271 maker that burns gas or returns a returndata bomb inside a multi-settlement call (the others still settle) and inside a cancel batch; replay of an order on another token, another DEX or another chain fails; salted-domain KATs for `TradeOrder`, `CancelOrder`, `InvalidateNonces` → `test/vectors/trade_kat.json` (built, P2a); `DexOrder` → `test/vectors/dex_kat.json`, which stays the `SCaaSDexV1` `Order` vector the node reads (controller ruling, pending the owner); the fee round-up cases above; exchange path: an interaction calling `mtxTrade` of a resting order, targeting the DEX or the puller, or `transferFrom(victim, …)` (all refused or failing); surplus split over several legs receiving one token, remainder to the last; a sold-only or intermediate leftover reverts; `InsufficientOutput`; a profitable cycle X→X; multi-hop through mock Uniswap v2/v3 and a fork test with real Uniswap bytecode on anvil; `LISTED_POOLS` × `setListedOnly` on both entry points; an executor returning less (revert) or more (distributed), re-entering, calling `mtxTrade` or the puller; `receiveToken == this` on the token; a Path B leg; an outside leg through the puller in `mtxSettle` and `mtxExchange`; a reverting and a gas-burning target; invariant: between calls the DEX holds 0 of every token and residual allowances move nothing |
+| forge | Path A and Path B, one taker × many makers; `mtxTrade` on a closed, cancelled or IOC-pulled order and with `sellFill = 0` reverts; Path B `sellFill ≠ amount` reverts; `dex` = EOA refused; caller ≠ `dex` refused; every `mtxTrade` error; effective minimum fill for taker and makers incl. the remainder close and `minFill > amount`; FOK via `minFill = amount`; taker fee charged once on the aggregate; split rounding; conservation (unit + invariant: the DEX holds 0 after every handler sequence; for the new DEX the unit tests are built in `test/v2/Dex.t.sol` (P2b-1: settle with two makers, maker rounding, aggregate fee, Path B fee, signed `minFill` and refund, Path A figures seen by the token, isolated failure, arrangement checks, `createDex` and the DEX catalogue, registry, fee split, salted domain) and `test/v2/DexOutside.t.sol` (P2b-2: outside legs through the puller, `DexOrder` digest, `ESCROW` refused, DEX cancels, the ERC-1271 cap by codehash, hostile 1271 signers in settle and cancel batches, the bounded `MatchFailed` reason, a starved check reverting the call, fee-on-transfer, rebasing and no-return tokens), and the invariant suite is open); `DexOrder` legs incl. a fallback-only "token" classified outside and `ESCROW` refused; cancel per token and per DEX (signature, replay, lane cap); ERC-1271 maker under the 400 k cap; a 1271 maker that burns gas or returns a returndata bomb inside a multi-settlement call (the others still settle) and inside a cancel batch; replay of an order on another token, another DEX or another chain fails; salted-domain KATs for `TradeOrder`, `CancelOrder`, `InvalidateNonces` → `test/vectors/trade_kat.json` (built, P2a); `DexOrder` → `test/vectors/dex_kat.json`, which stays the `SCaaSDexV1` `Order` vector the node reads (controller ruling, pending the owner); the fee round-up cases above; exchange path: an interaction calling `mtxTrade` of a resting order, targeting the DEX or the puller, or `transferFrom(victim, …)` (all refused or failing); surplus split over several legs receiving one token, remainder to the last; a sold-only or intermediate leftover reverts; `InsufficientOutput`; a profitable cycle X→X; multi-hop through mock Uniswap v2/v3 and a fork test with real Uniswap bytecode on anvil; `LISTED_POOLS` × `setListedOnly` on both entry points; an executor returning less (revert) or more (distributed), re-entering, calling `mtxTrade` or the puller; `receiveToken == this` on the token; a Path B leg; an outside leg through the puller in `mtxSettle` and `mtxExchange`; a reverting and a gas-burning target; invariant: between calls the DEX holds 0 of every token and residual allowances move nothing |
 | non-EVM | a third party settling on Cosmos/Soroban/TON fails; `min_nonce` above the cap refused; a dust fill pays fee 1 |
 | e2e (anvil 31950–31959, gateway 18650–18659) | two orders through the gateway → partial match → settle job → balances, no `approve` for SCaaS tokens; cancel ⇒ settle never runs; venue restart ⇒ book intact |
 | managed markets (forge) | one e2e with a regulated equity and an unregulated stablecoin: frozen maker, ineligible taker, ineligible fee recipient, an eligible pair settles |
```

- [ ] **Step 2: `docs/contracts/settlement.md`** — the DEX row's status and §3.5 "Status and Transitional (BUILT)". Apply:

```diff
diff --git a/docs/contracts/settlement.md b/docs/contracts/settlement.md
index 8938adf..8fe827b 100644
--- a/docs/contracts/settlement.md
+++ b/docs/contracts/settlement.md
@@ -52,7 +52,7 @@ intent is a booked fact. Every kind below shares these properties:
 | Receiver pays | `mtxPayReceiverFee` | payer signs `MetaTransfer`, payee co-signs `ReceiverFee`; the bound relayer | token | absolute fee from the payee's balance | tx | **BUILT** (EVM, Hedera) | [CTR-MTX-05](metatx.md#CTR-MTX-05), [-06](metatx.md#CTR-MTX-06) |
 | Generic gasless call | `mtxExecute`, `mtxBatch`, `executeMetaTransaction` | subject signs `MetaTransaction`; any relayer | the contract's selector allowlist | per fee class, after the call | tx | **BUILT** | [CTR-MTX-12](metatx.md#CTR-MTX-12), [-19](metatx.md#CTR-MTX-19), [-20](metatx.md#CTR-MTX-20) |
 | Signature wrap | `mtxWrap` | holder signs a `TradeOrder` in the underlying's domain; any relayer | underlying and wrapper | order `fee` to the relayer, out of the minted units | tx | **BUILT** (P2a, `UnderlyingToken`) | [CTR-TOK-20](token-wrappers.md#CTR-TOK-20) |
-| DEX order book | `SCaaSDex.mtxSettle`, `mtxCancelOrders`, `mtxInvalidateNonces`; token side `mtxTrade` | each party signs a `TradeOrder`; the venue lane | token (Path A) or DEX (Path B, outside legs); DEX conservation | one signed rate, split relayer / treasury by the DEX | tx, then the DEX watcher | token side **BUILT** (P2a); `SCaaSDex` clone in progress (P2b-1), outside legs in progress (P2b-2); pair `settle` **BUILT** | [CTR-DEX-13](dex.md#CTR-DEX-13) to [-19](dex.md#CTR-DEX-19), [-22](dex.md#CTR-DEX-22), [-24](dex.md#CTR-DEX-24) |
+| DEX order book | `SCaaSDex.mtxSettle`, `mtxCancelOrders`, `mtxInvalidateNonces`; token side `mtxTrade` | each party signs a `TradeOrder`; the venue lane | token (Path A) or DEX (Path B, outside legs); DEX conservation | one signed rate, split relayer / treasury by the DEX | tx, then the DEX watcher | token side **BUILT** (P2a); `SCaaSDex` **BUILT** (P2b-1 SCaaS legs, P2b-2 outside legs); `SCaaSDexV1` pair `settle` **BUILT** | [CTR-DEX-13](dex.md#CTR-DEX-13) to [-19](dex.md#CTR-DEX-19), [-22](dex.md#CTR-DEX-22), [-24](dex.md#CTR-DEX-24) |
 | Exchange against AMMs | `mtxExchange`, `mtxExchangeVia` | the same signed orders; the venue lane | token or DEX, DEX conservation | signed rate on the floor; surplus to the signers | tx, then the DEX watcher | **SPECIFIED** (P2c) | [CTR-DEX-20](dex.md#CTR-DEX-20) to [-23](dex.md#CTR-DEX-23) |
 | Confidential (Zether) | target `zetherTransfer*`, `zetherShield`, `zetherUnshield`, roll-over; built `transferConfidential*`, `fund`, `burn` | owner signs the call, the proof binds the envelope; any relayer | token verifier | outer NONE / FIXED (never PERCENT), inner `confidentialFee` | tx (dev chains) | **BUILT, UNAUDITED** (dev chains only); target kinds P3 **SPECIFIED**; PQZ **SPECIFIED** | [zether.md](zether.md), [pq-zether.md](pq-zether.md) |
 | Mandate | `payUnderMandate` (named `mtxPayUnderMandate`), `revoke` | delegate signs; any relayer | `MandateWallet` | NONE; relayer pays gas | tx | **BUILT**; epoch and `mtx` names **SPECIFIED** | [CTR-ACC-06](mandates.md#CTR-ACC-06), [-07](mandates.md#CTR-ACC-07) |
@@ -212,13 +212,13 @@ sequenceDiagram
   cursor ([NODE-DEX-15](../node/dex-venue.md#NODE-DEX-15), [NODE-DEX-04](../node/dex-venue.md#NODE-DEX-04),
   [NODE-DEX-16](../node/dex-venue.md#NODE-DEX-16)); `settled` is final, a late settled trade debits a restored order
   ([NODE-DEX-10](../node/dex-venue.md#NODE-DEX-10)).
-- **Status and Transitional (BUILT):** the token side (`mtxTrade`, cancels, `TradeLib`) is built in P2a. The
-  `SCaaSDex` clone with SCaaS legs is in progress (P2b-1, on branch `p2b-dex`, not merged when this page was
-  written), outside-token legs and `DexPuller` are in progress (P2b-2). What the node uses until P5 is the built pair
-  `settle(Match[])`: DEX-signed `Order`s over allowances, one pair per self-call, fees per market, a separate relayer
-  fee, `OrderFilled` / `Matched` / `MatchFailed`; on `main` it is still `src/dex/SCaaSDex.sol` and P2b-1 renames it
-  `SCaaSDexV1` ([dex.md section 13](dex.md#transitional-built)). The legacy `MetaTxDex` pairs two `MetaTransaction`
-  legs and is removed by the rebuild.
+- **Status and Transitional (BUILT):** the token side (`mtxTrade`, cancels, `TradeLib`) is built in P2a; the
+  `SCaaSDex` clone (`createDex`) with SCaaS legs in P2b-1; outside-token legs (`DexOrder`, `DexPuller`), the DEX's
+  `mtxCancelOrders` / `mtxInvalidateNonces` and the ERC-1271 cap in P2b-2. `MatchFailed` keeps the first 256 bytes of
+  the revert data and a starved ERC-1271 check reverts the whole call (controller ruling, pending the owner). What the
+  node uses until P5 is the pair `settle(Match[])` of `SCaaSDexV1` (the DEX built before P2b, renamed): DEX-signed
+  `Order`s over allowances, one pair per self-call, fees per market, a separate relayer fee, `OrderFilled` / `Matched` /
+  `MatchFailed` ([dex.md section 13](dex.md#transitional-built)). The legacy `MetaTxDex` is removed by the rebuild.
 
 ### 3.6 Exchange against AMM routes
 
```

- [ ] **Step 3: `TODO.md`** —
  - Line `| P2 |`: P2b-1 "(done, merged `0510c7d`; old `SCaaSDex` kept as `SCaaSDexV1` for the node until P5)"; P2b-2
    "outside legs (`DexOrder`, `DexPuller`, DEX-side cancels, ERC-1271 cap, bounded `MatchFailed`) (done on branch
    `p2b2-dex`, merge pending the final review; `checkOrder` not built, H7)".
  - Bullet `P2b-1 (…)`: "done, merged `0510c7d`"; replace its "Open for P2b-2: …" sentence by "P2b-2 built them except
    `checkOrder` (see P2b-2)".
  - Replace the bullet `P2b-2 note: mtxSettle try/catch turns SigCheckGasStarved into MatchFailed …` by: "- P2b-2 (done on
    branch `p2b2-dex`, merge pending the final review): outside legs (`DexOrder` in the DEX domain, `TradeLib` on the
    DEX's own `scaas.trade` state, `ESCROW` refused), `DexPuller` deployed by `initialize`, `mtxCancelOrders` /
    `mtxInvalidateNonces`, ERC-1271 cap by codehash (constructor takes the `SmartKeyAccount` implementation),
    `MatchFailed` reason capped at 256 bytes, `SigCheckGasStarved` reverts the whole `mtxSettle` (m8 closed), payouts by
    `SafeERC20`; 910 tests. Plan `docs/superpowers/plans/2026-10-11-p2b2-dex-outside-legs.md`. Open: `checkOrder` for the
    new DEX (not specified: dex.md §10 reads are the intake; with the node's P7 intake), the DEX invariant suite (§14),
    P2c. Size baseline raised by 9 B per token (`precheck` argument)."
  - **MT-5** line: "open: P2b/P2c" → "P2b done (P2b-1, P2b-2); open: P2c".
- [ ] **Step 4: `HANDOFF.md`** — new top section `## Session 2026-10-11 (P2b-2)`: **State** (branch `p2b2-dex`, code and
  plan commits, 910 tests); **Built** (files and entry points of Task 1, tests Dex 36 / DexOutside 19, sizes `SCaaSDex`
  14,672 B, `DexPuller` 624 B, tokens +9 B with the baseline raised); **Rulings H1–H10** (one line each); **Not done /
  next** (`checkOrder` H7 pending the owner, DEX invariant suite, the P2c plan: `mtxExchange`/`mtxExchangeVia`,
  `setExchangeTarget`, `setListedOnly`). In the P2b-1 section change "merge pending the final review" to "merged
  `0510c7d`".
- [ ] **Step 5: Run** `python3 scripts/test_docs_check.py`, `python3 scripts/docs_check.py check`, `python3
  scripts/docs_check.py facts check` → 0 errors (the `dex.md` budget warning predates this plan: 537 → 536 lines).
- [ ] **Step 6: Commit** `P2b-2: docs, TODO and HANDOFF` + trailer.

---

### Final

- Whole-branch review (Opus, effort xhigh): rerun the mutation probe of Task 1 Step 8 and probe beyond it (`settleOne`
  with mixed SCaaS/outside makers, the `MatchFailed` copy in assembly, `_cap` on Hedera with no implementation); one fix
  wave; scoped re-review.
- Merge `p2b2-dex` into `main` `--no-ff`; push; remove the worktree `.claude/worktrees/p2b2`. The spike worktree
  `.claude/worktrees/p2b2-spike` (branch `p2b2-spike`) is superseded by this plan: remove it when the owner agrees.
