# P2a — The token's side of the DEX: `TradeOrder`, `TradeLib` (`mtxTrade`, cancel, invalidate) and `mtxWrap` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every SCaaS token the sell side of a role-free signed `TradeOrder` (CTR-DEX-13/14/15, cancel CTR-DEX-02)
through an external library `TradeLib` (ERC-7201 `scaas.trade`), and give `WrappedToken` the signature wrap of a SCaaS
underlying `mtxWrap` (CTR-TOK-20) that uses it. The DEX side (`SCaaSDex` clone, `createDex`, `mtxSettle`) is P2b; the
exchange path is P2c.

**Architecture:** `TradeLib` holds `pulled[orderHash]` and `minNonce[from][batch]` and runs the checks in the spec's
order: `precheck` (caller = `o.dex`, `dex` a contract, no self order, relayer, expiry, lane, flags, amounts, `minFill`,
fee cap) → the token checks the signature (`_requireValidSignature`, Hedera branch included) → `record` (closed, Path A
bounds or Path B shape, `pulled`, `TradeFilled`) → the token moves the fill to `o.dex` (ERC-20 inline). Cancel and lane
invalidation never expire. `ITradeToken` carries the structs, events, errors and functions so the library's events and
errors are in every token's ABI. `mtxWrap` lives in `WrappedLib.wrapBySig`: the wrapper is the order's `dex`, calls the
underlying's `mtxTrade`, measures the delta and mints.

**Tech Stack:** Solidity 0.8.37 (`evm_version = "osaka"`), Foundry (forge 1.3.5), OpenZeppelin 5.2.0, forge-std 1.16.2.

**Spec:** `docs/contracts/dex.md` CTR-DEX-13, -14, -15, -04, -05, -02, §14 forge row (token side); `docs/contracts/token-wrappers.md`
CTR-TOK-20, CTR-TOK-24 (`TradeLib`, `scaas.trade`); `docs/contracts/metatx.md` CTR-MTX-18 (direct `msg.sender` reads);
TODO.md §00 P2 notes (D1: `mtxWrap` and `NativeNotGasless` come with P2).

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; forge in `smartcontracts/evm` of the worktree `.claude/worktrees/p2a`
  (branch `p2a-trade`), created by the controller with `lib/` copied.
- **Heavy commands only through `scripts/capped`, one at a time** (`timeout 900 scripts/capped bash -c 'cd smartcontracts/evm
  && forge …'`). `/usr/bin/grep`, `rtk proxy git diff`. `forge build --sizes` exits non-zero by design (EIP-170 over-size
  contracts in the baseline); measure with `forge build src --sizes --json … || true`.
- Namespace `scaas.trade` = `0x2c9c6bfc4d8563261a812845f5cbef41fd06d0e8f173455fd0e077ab420e2f00` (`cast index-erc7201 scaas.trade`).
- `TradeOrder` typehash `0xffe350903bdef674d7c33448fa7ce9b1cd306aa838f3ce1bbdd82aca46773f5d` (the string in CTR-DEX-13);
  `CancelOrder(bytes32 orderHash)`; `InvalidateNonces(address from,uint256 batch,uint256 minNonce)`. Domain: the sell
  token's `("SCaaS MetaToken","1",chainId,token,chain_uid)`. `orderHash` = the order's EIP-712 digest.
- Constants: `IOC = 1`, `ESCROW = 2` (requires `IOC`), `LISTED_POOLS = 4` (not read by the token), `MIN_FILL_PPM =
  500_000`, fee cap `10_000` ppm, `minNonce` cap `2^128`, strictly increasing.
- **Size (owner: optimise later):** `NormalToken` grows to 22,951 B (over the 20,480 budget, under EIP-170) and
  `WrappedToken` to 29,974 B; both go into the ratchet baseline (`smartcontracts/evm/size-baseline.json`); `TradeLib`
  3,129 B, `WrappedLib` 11,654 B. Measured in the spike.
- Test chain: id 7622, `chain_uid` `0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464`; key `0xA11CE`.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push. Never `git add claude-code-api.txt`.

## Review Focus

- Funds leaving to anyone but `o.dex`, or a fill pulled by a caller other than the named DEX or by an EOA "dex" —
  pinned by `test_onlyTheNamedDex_andItMustBeAContract`, `test_pathA_partialFillsToTheDex_thenTheRemainderCloses` (Task 1).
- A fill beyond a signed bound: over the amount, below the effective minimum, under the price, a fee above the signed
  rate, a second pull of an IOC or escrow order — pinned by `test_pathA_bounds`, `test_minFill_signerAboveTheFloor_andFillOrKill`,
  `test_ioc_closesAtItsSinglePull`, `test_pathB_escrowPullsTheWholeAmountOnce` (Task 1).
- A signature replayed on another token or a cancel that can be undone — pinned by
  `test_badSignature_andReplayOnAnotherToken`, `test_cancel_closesForever_replayIsANoOp`,
  `test_invalidateNonces_strictlyIncreasing_capped` (Task 1).
- A signature wrap that mints more than the underlying delivered, pays the fee to the wrong party, or runs on a native
  or paused leg — pinned by `test_mtxWrap_mintsAtTheRate_feeToTheSubmitter`, `test_mtxWrap_nativeLegIsNotGasless`,
  `test_mtxWrap_pausedDuringARateChange`, `test_mtxWrap_signedMinimumIsThePrice` (Task 1).
- The trade entries reachable gaslessly (a self-call would make the token its own `dex`) — pinned by
  `test_tradeEntriesAreNotAllowlisted`, `test_mtxWrap_isNotAllowlisted`.

## Rulings (docs vs code) and defaults taken

- **F1 — `TradeLib` is split around the signature** (`precheck` → token signature → `record`): the spec orders the
  checks with the signature at step 4 and the signature check must stay the token's (Hedera branch); two delegatecalls.
- **F2 — Error names the spec leaves open:** `MinNonceNotIncreasing(current, requested)` and `MinNonceAboveCap(requested)`
  for `mtxInvalidateNonces`; `NotDex(caller)` and `DexNotContract(dex)` carry addresses (no order hash yet at that point
  of the spec's list — they come first); every other `mtxTrade` error carries the order hash.
- **F3 — `mtxWrap` errors:** `NativeNotGasless()`, `WrapOrderInvalid(receiveToken)` (step 2, `o.receiveToken ≠ this`),
  `WrapReceivedMismatch(expected, received)`. The relayer binding of step 2 is enforced by the underlying's `mtxTrade`
  (the wrapper passes its caller as `submitter`), so the wrapper does not repeat it.
- **F4 — Size:** the owner's "optimise later" stands: `NormalToken` and `WrappedToken` enter the ratchet
  baseline at their new sizes; the size-pin tests move to NORMAL ≤ 23,552 and WRAPPED ≤ 30,720. Flag to the owner: NORMAL
  is now over its 20,480 budget (still deployable).
- **F5 — Vectors:** the new KAT is `test/vectors/trade_kat.json`; `dex_kat.json` stays the built `SCaaSDex` `Order`
  vector that the node reads (`scaas-node/src/dex.rs`) until P2b/P5.
- **F6 — Placement:** the trade entries are in `ERC20MetaTx` (spec: "in the base `ERC20MetaTx`"), so every kind has them.

---

### Task 1: `ITradeToken` + `TradeLib`, the trade entries in `ERC20MetaTx`, `mtxWrap`; tests, KAT, pins

**Model:** Sonnet, effort high (transcription of spike-tested code on a money path; the review is the gate).

**Files:**
- Create: `smartcontracts/evm/src/trade/ITradeToken.sol`, `smartcontracts/evm/src/trade/TradeLib.sol`,
  `smartcontracts/evm/test/v2/Trade.t.sol`, `smartcontracts/evm/test/metatx/TradeKat.t.sol`,
  `smartcontracts/evm/test/vectors/trade_kat.json` (written by the KAT test)
- Create also: `smartcontracts/evm/test/v2/MtxWrap.t.sol`
- Modify: `smartcontracts/evm/src/metatx/{ERC20MetaTx,IWrappedToken,WrappedLib,WrappedToken}.sol`,
  `smartcontracts/evm/test/metatx/MsgSenderLint.t.sol`,
  `smartcontracts/evm/test/v2/Factory.t.sol`, `smartcontracts/evm/test/hedera/HederaV2.t.sol`,
  `smartcontracts/evm/size-baseline.json`

**Interfaces:**
- Produces (P2b relies on them): `ITradeToken.TradeOrder`, `ITradeToken.TradeFill(sellFill, receiveFill, dexFee,
  submitter)`, `ITradeToken.mtxTrade(TradeOrder, bytes, TradeFill)`, errors `WrongRelayer(bytes32, address)`,
  `PriceLimit(bytes32)`, `NotDex(address)`; `tradeOrderDigest(TradeOrder)`, `pulled(bytes32)` on every token;
  `mtxWrap(address underlying, ITradeToken.TradeOrder o, bytes sig) returns (uint256 minted)` and errors
  `NativeNotGasless()`, `WrapOrderInvalid(address)`, `WrapReceivedMismatch(uint256,uint256)` on `WrappedToken`.

- [ ] **Step 1: `src/trade/ITradeToken.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title The token's side of the DEX (CTR-DEX-13, CTR-DEX-15, CTR-DEX-02): a role-free signed `TradeOrder`, checked by
///        the sell token against the fill figures its `dex` passes; funds move only into `dex`, never by allowance.
/// @notice Events and errors raised by `TradeLib` (an external library) are declared here so that they are in the
///         token ABI. Every error carries the order hash where it has one.
interface ITradeToken {
    /// @notice Signed in the sell token's own domain. `nonce` is not consumed per fill: it is the cancel handle of its
    ///         lane (`batch`, distinct from the meta-tx lane of the same name).
    struct TradeOrder {
        address from;          // signer; this token's balance is sold
        address receiveToken;  // what the signer receives
        uint256 amount;        // at most this much of THIS token in total
        uint256 receiveAmount; // signed price limit: `amount` for at least `receiveAmount` (gross, before the DEX fee)
        uint256 minFill;       // per settlement; effective = max(minFill, ceil(amount/2)); = amount => fill-or-kill
        uint256 fee;           // DEX fee rate in ppm on what the signer receives; <= 10 000 (1 %)
        address relayer;       // the only submitter allowed (0 = anyone)
        address dex;           // the only contract that may pull, and the only recipient; a contract
        address destination;   // receives the proceeds in receiveToken; 0 = from
        uint8 flags;           // IOC 1 | ESCROW 2 (Path B; implies IOC) | LISTED_POOLS 4 (not read by the token)
        uint256 batch;         // order lane (minNonce)
        uint256 nonce;         // valid while nonce >= minNonce[from][batch]
        uint256 validUntil;
    }

    /// @notice What the DEX passes: the fill of THIS order (Path B: `amount`, 0, 0) and its own `msg.sender`.
    struct TradeFill {
        uint256 sellFill;
        uint256 receiveFill;
        uint256 dexFee;
        address submitter;
    }

    event TradeFilled(bytes32 indexed orderHash, address indexed from, uint256 sellFill, uint256 receiveFill,
        uint256 dexFee);
    event OrderCancelled(bytes32 indexed orderHash, address indexed from);
    event NoncesInvalidated(address indexed from, uint256 indexed batch, uint256 minNonce);

    error NotDex(address caller);
    error DexNotContract(address dex);
    error SelfOrder(bytes32 orderHash);
    error WrongRelayer(bytes32 orderHash, address submitter);
    error OrderExpired(bytes32 orderHash);
    error NonceInvalidated(bytes32 orderHash);
    error BadFlags(bytes32 orderHash);
    error ZeroAmount(bytes32 orderHash);
    error BadMinFill(bytes32 orderHash);
    error FeeAboveCap(bytes32 orderHash);
    error OrderClosed(bytes32 orderHash);
    error ZeroFill(bytes32 orderHash);
    error Overfill(bytes32 orderHash);
    error BelowMinFill(bytes32 orderHash);
    error PriceLimit(bytes32 orderHash);
    error FeeAboveSigned(bytes32 orderHash);
    error EscrowFillShape(bytes32 orderHash);
    /// @notice `mtxInvalidateNonces`: strictly increasing, at most `2^128`.
    error MinNonceNotIncreasing(uint256 current, uint256 requested);
    error MinNonceAboveCap(uint256 requested);

    /// @notice Verify `o` (signature, bounds) and move the fill from `o.from` to `o.dex`; only `o.dex` may call.
    function mtxTrade(TradeOrder calldata o, bytes calldata sig, TradeFill calldata f) external;
    /// @notice `CancelOrder(bytes32 orderHash)` signed by `o.from`: closes the order forever; already closed = no-op.
    function mtxCancelOrder(TradeOrder calldata o, bytes calldata sig) external;
    /// @notice `InvalidateNonces(address from,uint256 batch,uint256 minNonce)` signed by `from`.
    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external;

    function tradeOrderDigest(TradeOrder calldata o) external view returns (bytes32);
    function cancelOrderDigest(bytes32 orderHash) external view returns (bytes32);
    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
    function pulled(bytes32 orderHash) external view returns (uint256);
    function minNonce(address from, uint256 batch) external view returns (uint256);
}
```

- [ ] **Step 2: `src/trade/TradeLib.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ITradeToken} from "./ITradeToken.sol";
import {SigCheck} from "../common/SigCheck.sol";

/// @title The token side of `TradeOrder` (CTR-DEX-15, CTR-DEX-02, CTR-TOK-24), in the ERC-7201 namespace `scaas.trade`.
/// @notice External library: order checks and the per-order state (`pulled`, `minNonce`); the token computes the
///         digest (its domain), checks the signature (its `_requireValidSignature`, Hedera branch included) and moves
///         the funds (ERC-20 stays inline). Order of the checks is the spec's: caller and identities, relayer, shape,
///         [token: signature], closed, Path A / Path B, effects.
library TradeLib {
    bytes32 internal constant TRADE_ORDER_TYPEHASH = keccak256(
        "TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,"
        "address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"
    );
    bytes32 internal constant CANCEL_ORDER_TYPEHASH = keccak256("CancelOrder(bytes32 orderHash)");
    bytes32 internal constant INVALIDATE_NONCES_TYPEHASH =
        keccak256("InvalidateNonces(address from,uint256 batch,uint256 minNonce)");

    uint8 internal constant IOC = 1;
    uint8 internal constant ESCROW = 2;
    uint8 internal constant LISTED_POOLS = 4;
    uint256 internal constant PPM = 1_000_000;
    uint256 internal constant MIN_FILL_PPM = 500_000;
    uint256 internal constant MAX_FEE_PPM = 10_000;
    uint256 internal constant MAX_MIN_NONCE = 2 ** 128;

    /// @custom:storage-location erc7201:scaas.trade
    struct TradeStorage {
        mapping(bytes32 orderHash => uint256) pulled;
        mapping(address from => mapping(uint256 batch => uint256)) minNonce;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.trade")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x2c9c6bfc4d8563261a812845f5cbef41fd06d0e8f173455fd0e077ab420e2f00;

    function $() internal pure returns (TradeStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    /// @dev EIP-712 struct hash of `o` (the token wraps it in its domain).
    function hashStruct(ITradeToken.TradeOrder calldata o) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            TRADE_ORDER_TYPEHASH, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer, o.dex,
            o.destination, o.flags, o.batch, o.nonce, o.validUntil));
    }

    /// @notice Steps 1–3 (before the signature): caller and identities, relayer, shape.
    function precheck(ITradeToken.TradeOrder calldata o, ITradeToken.TradeFill calldata f, bytes32 h, address caller)
        public view
    {
        if (caller != o.dex) revert ITradeToken.NotDex(caller);
        if (!SigCheck.isContract(o.dex)) revert ITradeToken.DexNotContract(o.dex);
        if (o.from == address(this) || o.dex == address(this)) revert ITradeToken.SelfOrder(h);
        if (o.relayer != address(0) && o.relayer != f.submitter) revert ITradeToken.WrongRelayer(h, f.submitter);
        if (block.timestamp > o.validUntil) revert ITradeToken.OrderExpired(h);
        if (o.nonce < $().minNonce[o.from][o.batch]) revert ITradeToken.NonceInvalidated(h);
        if (o.flags & ~(IOC | ESCROW | LISTED_POOLS) != 0 || (o.flags & ESCROW != 0 && o.flags & IOC == 0)) {
            revert ITradeToken.BadFlags(h);
        }
        if (o.amount == 0 || o.receiveAmount == 0) revert ITradeToken.ZeroAmount(h);
        if (o.minFill > o.amount) revert ITradeToken.BadMinFill(h);
        if (o.fee > MAX_FEE_PPM) revert ITradeToken.FeeAboveCap(h);
    }

    /// @notice Steps 5–8 (after the signature): closed, Path A bounds or Path B shape, then `pulled` and the event.
    /// @return move the amount the token transfers from `o.from` to `o.dex`
    function record(ITradeToken.TradeOrder calldata o, ITradeToken.TradeFill calldata f, bytes32 h)
        public returns (uint256 move)
    {
        TradeStorage storage s = $();
        uint256 p = s.pulled[h];
        if (p >= o.amount) revert ITradeToken.OrderClosed(h);
        if (o.flags & ESCROW == 0) {
            move = f.sellFill;
            if (move == 0) revert ITradeToken.ZeroFill(h);
            if (move > o.amount - p) revert ITradeToken.Overfill(h);
            if (move != o.amount - p) {
                // effective minimum: max(minFill, ceil(amount/2)); received side: receiveFill >= receiveAmount/2
                uint256 half = (o.amount * MIN_FILL_PPM + PPM - 1) / PPM;
                uint256 m = o.minFill > half ? o.minFill : half;
                if (move < m || f.receiveFill * PPM < o.receiveAmount * MIN_FILL_PPM) {
                    revert ITradeToken.BelowMinFill(h);
                }
            }
            if (move * o.receiveAmount > f.receiveFill * o.amount) revert ITradeToken.PriceLimit(h);
            if (f.dexFee > (f.receiveFill * o.fee + PPM - 1) / PPM) revert ITradeToken.FeeAboveSigned(h);
        } else {
            move = o.amount;
            if (p != 0 || f.sellFill != move || f.receiveFill != 0 || f.dexFee != 0) {
                revert ITradeToken.EscrowFillShape(h);
            }
        }
        s.pulled[h] = o.flags & IOC != 0 ? o.amount : p + move;
        emit ITradeToken.TradeFilled(h, o.from, move, f.receiveFill, f.dexFee);
    }

    /// @notice After the `CancelOrder` signature: closed forever; an already closed order is a no-op.
    function cancel(ITradeToken.TradeOrder calldata o, bytes32 h) public {
        TradeStorage storage s = $();
        if (s.pulled[h] >= o.amount) return;
        s.pulled[h] = o.amount;
        emit ITradeToken.OrderCancelled(h, o.from);
    }

    /// @notice After the `InvalidateNonces` signature: strictly increasing, capped at `2^128`.
    function invalidate(address from, uint256 batch, uint256 newMin) public {
        TradeStorage storage s = $();
        uint256 cur = s.minNonce[from][batch];
        if (newMin <= cur) revert ITradeToken.MinNonceNotIncreasing(cur, newMin);
        if (newMin > MAX_MIN_NONCE) revert ITradeToken.MinNonceAboveCap(newMin);
        s.minNonce[from][batch] = newMin;
        emit ITradeToken.NoncesInvalidated(from, batch, newMin);
    }
}
```

- [ ] **Step 3: `ERC20MetaTx`** — apply:

```diff
diff --git a/smartcontracts/evm/src/metatx/ERC20MetaTx.sol b/smartcontracts/evm/src/metatx/ERC20MetaTx.sol
index 5d82265..6538fe6 100644
--- a/smartcontracts/evm/src/metatx/ERC20MetaTx.sol
+++ b/smartcontracts/evm/src/metatx/ERC20MetaTx.sol
@@ -10,13 +10,16 @@ import {IERC20Payment} from "./IERC20Payment.sol";
 import {MetaTxLib} from "../common/MetaTxLib.sol";
 import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
 import {SigCheck} from "../common/SigCheck.sol";
+import {ITradeToken} from "../trade/ITradeToken.sol";
+import {TradeLib} from "../trade/TradeLib.sol";
 
 /// @title The token base of every SCaaS token (CTR-MTX-07): ERC-20 on `MetaTxBase`.
 /// @notice Adds to the generic base: the fee in this token (`_chargeFee` by fee class, CTR-MTX-20), the typed
 ///         `MetaTransfer` path (`mtxExecuteTransfer`, `mtxBatchTransfer`, CTR-MTX-23/24) on the same lanes, the
 ///         allowance rule (CTR-TOK-01) and "no tokens at the token's own address" (CTR-MTX-18). Domain
-///         `("SCaaS MetaToken", "1", chainId, clone, chain_uid)` for every kind (CTR-MTX-02).
-abstract contract ERC20MetaTx is ERC20, MetaTxBase, IERC20Payment {
+///         `("SCaaS MetaToken", "1", chainId, clone, chain_uid)` for every kind (CTR-MTX-02). The sell side of a
+///         `TradeOrder` (CTR-DEX-15) through `TradeLib`.
+abstract contract ERC20MetaTx is ERC20, MetaTxBase, IERC20Payment, ITradeToken {
     using MetaTxLib for MetaTxLib.MetaTransfer;
 
     constructor(bytes32 chainUid_) ERC20("", "") MetaTxBase("SCaaS MetaToken", chainUid_) {}
@@ -32,6 +35,49 @@ abstract contract ERC20MetaTx is ERC20, MetaTxBase, IERC20Payment {
         return _hashTypedDataV4(t.hashStruct());
     }
 
+    // ------------------------------------------------------------------ trade orders (CTR-DEX-15, CTR-DEX-02)
+
+    function tradeOrderDigest(TradeOrder calldata o) public view returns (bytes32) {
+        return _hashTypedDataV4(TradeLib.hashStruct(o));
+    }
+
+    function cancelOrderDigest(bytes32 orderHash) public view returns (bytes32) {
+        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.CANCEL_ORDER_TYPEHASH, orderHash)));
+    }
+
+    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) public view returns (bytes32) {
+        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.INVALIDATE_NONCES_TYPEHASH, from, batch, newMin)));
+    }
+
+    function pulled(bytes32 orderHash) external view returns (uint256) {
+        return TradeLib.$().pulled[orderHash];
+    }
+
+    function minNonce(address from, uint256 batch) external view returns (uint256) {
+        return TradeLib.$().minNonce[from][batch];
+    }
+
+    /// @notice Only `o.dex` calls (a direct read of the caller, CTR-MTX-18); never allowlisted. Moves the fill from
+    ///         `o.from` to `o.dex` and nowhere else.
+    function mtxTrade(TradeOrder calldata o, bytes calldata sig, TradeFill calldata f) external nonReentrant {
+        bytes32 h = tradeOrderDigest(o);
+        TradeLib.precheck(o, f, h, msg.sender);
+        _requireValidSignature(o.from, h, sig);
+        _transfer(o.from, o.dex, TradeLib.record(o, f, h));
+    }
+
+    /// @notice Cancel signatures never expire (CTR-DEX-02); anyone may submit one.
+    function mtxCancelOrder(TradeOrder calldata o, bytes calldata sig) external nonReentrant {
+        bytes32 h = tradeOrderDigest(o);
+        _requireValidSignature(o.from, cancelOrderDigest(h), sig);
+        TradeLib.cancel(o, h);
+    }
+
+    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external nonReentrant {
+        _requireValidSignature(from, invalidateNoncesDigest(from, batch, newMin), sig);
+        TradeLib.invalidate(from, batch, newMin);
+    }
+
     // ------------------------------------------------------------------ typed path (CTR-MTX-23, CTR-MTX-24)
 
     function mtxExecuteTransfer(MetaTxLib.MetaTransfer calldata t, bytes calldata signature)
```

- [ ] **Step 4: `test/v2/Trade.t.sol`** (full text)

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {V2Fixture} from "./helpers/V2Fixture.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";

/// The sell token's side of a `TradeOrder` (CTR-DEX-15, -14, -04, -05, -02). This test contract plays the DEX: it is
/// a contract and it is `o.dex`.
contract TradeTest is V2Fixture {
    uint256 constant ALICE_PK = 0xA11CE;
    address alice = vm.addr(ALICE_PK);
    address other = address(0x07E5);
    NormalToken t;
    NormalToken t2;

    function setUp() public {
        t = _none(alice, 1_000_000, address(0));
        t2 = _none(alice, 1_000_000, address(0));
    }

    function _order(uint256 amount, uint256 receiveAmount) internal view returns (ITradeToken.TradeOrder memory o) {
        o.from = alice;
        o.receiveToken = address(t2);
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.dex = address(this);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _sign(NormalToken tok, ITradeToken.TradeOrder memory o) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, tok.tradeOrderDigest(o));
        return abi.encodePacked(r, s, v);
    }

    function _fill(uint256 sell, uint256 recv, uint256 fee) internal view returns (ITradeToken.TradeFill memory) {
        return ITradeToken.TradeFill(sell, recv, fee, relayer);
    }

    function _trade(ITradeToken.TradeOrder memory o, ITradeToken.TradeFill memory f) internal {
        t.mtxTrade(o, _sign(t, o), f);
    }

    function _expect(bytes4 sel, ITradeToken.TradeOrder memory o, ITradeToken.TradeFill memory f) internal {
        bytes memory sig = _sign(t, o);
        vm.expectRevert(abi.encodeWithSelector(sel, t.tradeOrderDigest(o)));
        t.mtxTrade(o, sig, f);
    }

    // ------------------------------------------------------------------ Path A

    function test_pathA_partialFillsToTheDex_thenTheRemainderCloses() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes32 h = t.tradeOrderDigest(o);
        vm.expectEmit(address(t));
        emit ITradeToken.TradeFilled(h, alice, 600, 1200, 0);
        _trade(o, _fill(600, 1200, 0));
        assertEq(t.balanceOf(address(this)), 600);
        assertEq(t.pulled(h), 600);
        _trade(o, _fill(400, 800, 0)); // the remainder may close below the minimum
        assertEq(t.pulled(h), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _fill(1, 2, 0));
    }

    function test_pathA_bounds() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        _expect(ITradeToken.ZeroFill.selector, o, _fill(0, 0, 0));
        _expect(ITradeToken.Overfill.selector, o, _fill(1001, 2002, 0));
        _expect(ITradeToken.BelowMinFill.selector, o, _fill(499, 998, 0)); // 50 % floor
        _expect(ITradeToken.PriceLimit.selector, o, _fill(600, 1199, 0));
        _expect(ITradeToken.FeeAboveSigned.selector, o, _fill(600, 1200, 1)); // fee 0 signed
        o.fee = 3_000; // 0.3 % of 1200 = 3.6 -> 4 (rounded up)
        _trade(o, _fill(600, 1200, 4));
        ITradeToken.TradeOrder memory o2 = _order(1000, 2000);
        o2.nonce = 2;
        o2.fee = 3_000;
        _expect(ITradeToken.FeeAboveSigned.selector, o2, _fill(600, 1200, 5));
    }

    function test_minFill_signerAboveTheFloor_andFillOrKill() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.minFill = 800;
        _expect(ITradeToken.BelowMinFill.selector, o, _fill(700, 1400, 0));
        o.minFill = 1000; // fill-or-kill
        _expect(ITradeToken.BelowMinFill.selector, o, _fill(999, 1998, 0));
        _trade(o, _fill(1000, 2000, 0));
        o.minFill = 1001;
        o.nonce = 2;
        _expect(ITradeToken.BadMinFill.selector, o, _fill(1000, 2000, 0));
    }

    function test_ioc_closesAtItsSinglePull() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.flags = 1; // IOC
        _trade(o, _fill(600, 1200, 0));
        assertEq(t.pulled(t.tradeOrderDigest(o)), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _fill(400, 800, 0));
    }

    // ------------------------------------------------------------------ Path B

    function test_pathB_escrowPullsTheWholeAmountOnce() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.flags = 3; // IOC | ESCROW
        _expect(ITradeToken.EscrowFillShape.selector, o, _fill(999, 0, 0));
        _expect(ITradeToken.EscrowFillShape.selector, o, _fill(1000, 2000, 0));
        _trade(o, _fill(1000, 0, 0));
        assertEq(t.balanceOf(address(this)), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _fill(1000, 0, 0));
        o.flags = 2; // ESCROW without IOC
        o.nonce = 2;
        _expect(ITradeToken.BadFlags.selector, o, _fill(1000, 0, 0));
        o.flags = 8; // unknown bit
        _expect(ITradeToken.BadFlags.selector, o, _fill(1000, 0, 0));
    }

    // ------------------------------------------------------------------ caller, identities, shape

    function test_onlyTheNamedDex_andItMustBeAContract() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes memory sig = _sign(t, o);
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotDex.selector, other));
        t.mtxTrade(o, sig, _fill(600, 1200, 0));
        o.dex = other; // an EOA
        sig = _sign(t, o);
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.DexNotContract.selector, other));
        t.mtxTrade(o, sig, _fill(600, 1200, 0));
    }

    function test_selfOrder_relayer_expiry_shape() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.relayer = address(0x5E1);
        bytes memory sig = _sign(t, o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.WrongRelayer.selector, t.tradeOrderDigest(o), relayer));
        t.mtxTrade(o, sig, _fill(600, 1200, 0));
        o = _order(1000, 2000);
        o.validUntil = block.timestamp - 1;
        _expect(ITradeToken.OrderExpired.selector, o, _fill(600, 1200, 0));
        o = _order(0, 2000);
        _expect(ITradeToken.ZeroAmount.selector, o, _fill(600, 1200, 0));
        o = _order(1000, 0);
        _expect(ITradeToken.ZeroAmount.selector, o, _fill(600, 1200, 0));
        o = _order(1000, 2000);
        o.fee = 10_001;
        _expect(ITradeToken.FeeAboveCap.selector, o, _fill(600, 1200, 0));
        o = _order(1000, 2000);
        o.receiveToken = address(t); // a cycle order X -> X is allowed by the token
        _trade(o, _fill(600, 1200, 0));
    }

    function test_badSignature_andReplayOnAnotherToken() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes memory sigOnT2 = _sign(t2, o); // signed in t2's domain
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxTrade(o, sigOnT2, _fill(600, 1200, 0));
    }

    function test_erc1271Signer() public {
        Mock1271Wallet w = new Mock1271Wallet(alice);
        vm.prank(alice);
        t.transfer(address(w), 1000);
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.from = address(w);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, t.tradeOrderDigest(o));
        t.mtxTrade(o, abi.encodePacked(r, s, v), _fill(600, 1200, 0));
        assertEq(t.balanceOf(address(this)), 600);
    }

    // ------------------------------------------------------------------ cancel (CTR-DEX-02)

    function test_cancel_closesForever_replayIsANoOp() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes32 h = t.tradeOrderDigest(o);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, t.cancelOrderDigest(h));
        bytes memory c = abi.encodePacked(r, s, v);
        vm.expectEmit(address(t));
        emit ITradeToken.OrderCancelled(h, alice);
        vm.prank(other); // anyone submits
        t.mtxCancelOrder(o, c);
        assertEq(t.pulled(h), 1000);
        vm.recordLogs();
        t.mtxCancelOrder(o, c);
        assertEq(vm.getRecordedLogs().length, 0);
        _expect(ITradeToken.OrderClosed.selector, o, _fill(600, 1200, 0));
        (v, r, s) = vm.sign(0xBAD, t.cancelOrderDigest(h));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxCancelOrder(o, abi.encodePacked(r, s, v));
    }

    function test_invalidateNonces_strictlyIncreasing_capped() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, t.invalidateNoncesDigest(alice, 1, 2));
        vm.expectEmit(address(t));
        emit ITradeToken.NoncesInvalidated(alice, 1, 2);
        t.mtxInvalidateNonces(alice, 1, 2, abi.encodePacked(r, s, v));
        assertEq(t.minNonce(alice, 1), 2);
        _expect(ITradeToken.NonceInvalidated.selector, o, _fill(600, 1200, 0)); // nonce 1 < 2
        bytes memory again = abi.encodePacked(r, s, v);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.MinNonceNotIncreasing.selector, 2, 2));
        t.mtxInvalidateNonces(alice, 1, 2, again);
        uint256 big = 2 ** 128 + 1;
        (v, r, s) = vm.sign(ALICE_PK, t.invalidateNoncesDigest(alice, 1, big));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.MinNonceAboveCap.selector, big));
        t.mtxInvalidateNonces(alice, 1, big, abi.encodePacked(r, s, v));
        o.batch = 2; // another lane is untouched
        _trade(o, _fill(600, 1200, 0));
    }

    // ------------------------------------------------------------------ never gasless

    function test_tradeEntriesAreNotAllowlisted() public {
        bytes4[3] memory sels = [t.mtxTrade.selector, t.mtxCancelOrder.selector, t.mtxInvalidateNonces.selector];
        (bytes4[] memory s,,) = t.mtxSelectors();
        for (uint256 i; i < sels.length; ++i) {
            for (uint256 j; j < s.length; ++j) assertTrue(s[j] != sels[i]);
        }
    }

    function test_typehashesArePinned() public pure {
        assertEq(keccak256(
            "TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,"
            "uint256 fee,address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,"
            "uint256 validUntil)"), 0xffe350903bdef674d7c33448fa7ce9b1cd306aa838f3ce1bbdd82aca46773f5d);
    }
}
```

- [ ] **Step 5: `test/metatx/TradeKat.t.sol`** (full text); write the vectors once with
  `WRITE_KAT=true forge test --match-contract TradeKatTest`, then run without `WRITE_KAT` (must pass on the file). The
  file is deterministic; a different value on a re-run means the code differs from the plan.

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";

/// KATs of the token-side DEX structs (CTR-DEX-13, CTR-DEX-02) on a real token: `trade_kat.json` holds a
/// `TradeOrder`, its `CancelOrder` and an `InvalidateNonces`, in the token domain "SCaaS MetaToken" of a
/// `NormalToken` clone on chain 7622 with its real `chain_uid`. (`dex_kat.json` stays the built `SCaaSDex`
/// `Order` vector the node reads.) `WRITE_KAT=true forge test --match-contract TradeKatTest` rewrites the file.
contract TradeKatTest is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant ALICE_PK = 0xA11CE;
    string internal constant OUT = "./test/vectors/trade_kat.json";
    NormalToken internal tok;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        tok = NormalToken(Clones.clone(address(new NormalToken(address(this), address(0), UID, false))));
        tok.initialize(address(this), 1, normalInit("Points", "PTS", 6, 0, address(this), address(this)));
    }

    function _domainSep() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), uint256(7622), address(tok), UID));
    }

    function _sign(bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_tradeKat() public {
        ITradeToken.TradeOrder memory o = ITradeToken.TradeOrder({
            from: vm.addr(ALICE_PK), receiveToken: address(0x7E57), amount: 1_000e6, receiveAmount: 2_000e6,
            minFill: 600e6, fee: 3_000, relayer: address(0xBEEF), dex: address(0xDE7), destination: address(0),
            flags: 1, batch: 7, nonce: 42, validUntil: 1_800_000_300
        });
        bytes32 domainSep = _domainSep();
        bytes32 structHash = keccak256(abi.encode(
            TradeLib.TRADE_ORDER_TYPEHASH, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee,
            o.relayer, o.dex, o.destination, o.flags, o.batch, o.nonce, o.validUntil));
        bytes32 h = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
        assertEq(h, tok.tradeOrderDigest(o));
        bytes32 cancelStruct = keccak256(abi.encode(TradeLib.CANCEL_ORDER_TYPEHASH, h));
        bytes32 cancelDigest = keccak256(abi.encodePacked(hex"1901", domainSep, cancelStruct));
        assertEq(cancelDigest, tok.cancelOrderDigest(h));
        bytes32 invStruct = keccak256(abi.encode(TradeLib.INVALIDATE_NONCES_TYPEHASH, o.from, uint256(7), uint256(43)));
        bytes32 invDigest = keccak256(abi.encodePacked(hex"1901", domainSep, invStruct));
        assertEq(invDigest, tok.invalidateNoncesDigest(o.from, 7, 43));

        string memory k = "trade";
        vm.serializeString(k, "domain_name", "SCaaS MetaToken");
        vm.serializeString(k, "domain_version", "1");
        vm.serializeString(k, "chain_id", "7622");
        vm.serializeString(k, "verifying_contract", vm.toString(address(tok)));
        vm.serializeString(k, "salt", vm.toString(UID));
        vm.serializeString(k, "domain_separator", vm.toString(domainSep));
        vm.serializeString(k, "signer", vm.toString(o.from));
        vm.serializeString(k, "order_abi", vm.toString(abi.encode(o)));
        vm.serializeString(k, "trade_order_type_hash", vm.toString(TradeLib.TRADE_ORDER_TYPEHASH));
        vm.serializeString(k, "trade_order_struct_hash", vm.toString(structHash));
        vm.serializeString(k, "order_hash", vm.toString(h));
        vm.serializeString(k, "order_signature", vm.toString(_sign(h)));
        vm.serializeString(k, "cancel_type_hash", vm.toString(TradeLib.CANCEL_ORDER_TYPEHASH));
        vm.serializeString(k, "cancel_digest", vm.toString(cancelDigest));
        vm.serializeString(k, "cancel_signature", vm.toString(_sign(cancelDigest)));
        vm.serializeString(k, "invalidate_type_hash", vm.toString(TradeLib.INVALIDATE_NONCES_TYPEHASH));
        vm.serializeString(k, "invalidate_batch", "7");
        vm.serializeString(k, "invalidate_min_nonce", "43");
        vm.serializeString(k, "invalidate_digest", vm.toString(invDigest));
        string memory out = vm.serializeString(k, "invalidate_signature", vm.toString(_sign(invDigest)));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);

        string memory onDisk = vm.readFile(OUT);
        assertEq(vm.parseJsonBytes32(onDisk, ".order_hash"), h);
        assertEq(vm.parseJsonBytes32(onDisk, ".cancel_digest"), cancelDigest);
        assertEq(vm.parseJsonBytes32(onDisk, ".invalidate_digest"), invDigest);
        assertEq(vm.parseJsonAddress(onDisk, ".verifying_contract"), address(tok));
        assertEq(vm.parseJsonBytes(onDisk, ".order_signature"), _sign(h));
    }
}
```

- [ ] **Step 6: `mtxWrap` (CTR-TOK-20)** — apply:

```diff
diff --git a/smartcontracts/evm/src/metatx/IWrappedToken.sol b/smartcontracts/evm/src/metatx/IWrappedToken.sol
index 2b50b01..eb6277c 100644
--- a/smartcontracts/evm/src/metatx/IWrappedToken.sol
+++ b/smartcontracts/evm/src/metatx/IWrappedToken.sol
@@ -1,6 +1,8 @@
 // SPDX-License-Identifier: Apache-2.0
 pragma solidity ^0.8.24;
 
+import {ITradeToken} from "../trade/ITradeToken.sol";
+
 /// @title Kind `WRAPPED` (CTR-TOK-21): 1–8 legs, each an ERC-20 or the native coin (`address(0)`, CTR-TOK-26).
 /// @notice Events and errors raised by `WrappedLib` (an external library) are declared here so that they are in the
 ///         token ABI. The creation config is `IFactoryToken.TokenConfig` (`legs`, `rate`).
@@ -43,6 +45,11 @@ interface IWrappedToken {
     error WrapPausedForRateChange(address u);
     /// @notice `msg.value` must equal `amount` on the native leg and be 0 on any other leg (CTR-TOK-26).
     error NativeValueMismatch(uint256 value, uint256 expected);
+    /// @notice `mtxWrap` (CTR-TOK-20): a signature cannot carry coin; the order must buy this token; the underlying
+    ///         must deliver exactly `o.amount`.
+    error NativeNotGasless();
+    error WrapOrderInvalid(address receiveToken);
+    error WrapReceivedMismatch(uint256 expected, uint256 received);
     /// @notice Raised by OpenZeppelin inside WrappedLib (same selectors), listed for the ABI.
     error FailedCall();
     error SafeERC20FailedOperation(address token);
@@ -58,6 +65,10 @@ interface IWrappedToken {
     function unwrap(address underlying, uint256 wrapped, address recipient, uint256 minOut)
         external returns (uint256 out, uint256 burned);
     function addReserve(address underlying, uint256 amount) external payable;
+    /// @notice Wrap a SCaaS underlying by the holder's `TradeOrder` (`dex` = this token, `receiveToken` = this
+    ///         token, `receiveAmount` = the minimum minted, `minFill = amount`); `fee` pays the submitter in minted units.
+    function mtxWrap(address underlying, ITradeToken.TradeOrder calldata o, bytes calldata sig)
+        external returns (uint256 minted);
     function disableWrap(address underlying, bytes32 reason) external;
     function proposeRate(address underlying, uint96 num, uint96 den) external;
     function cancelRate() external;
```

```diff
diff --git a/smartcontracts/evm/src/metatx/WrappedLib.sol b/smartcontracts/evm/src/metatx/WrappedLib.sol
index b6238c6..e546376 100644
--- a/smartcontracts/evm/src/metatx/WrappedLib.sol
+++ b/smartcontracts/evm/src/metatx/WrappedLib.sol
@@ -8,6 +8,7 @@ import {Address} from "@openzeppelin/contracts/utils/Address.sol";
 import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
 import {IWrappedToken} from "./IWrappedToken.sol";
 import {IFactoryToken} from "../factory/IFactoryToken.sol";
+import {ITradeToken} from "../trade/ITradeToken.sol";
 import {AdminLib} from "./AdminLib.sol";
 import {MetaTokenBase} from "./MetaTokenBase.sol";
 import {HederaLib} from "../hedera/HederaLib.sol";
@@ -165,6 +166,45 @@ library WrappedLib {
         L.reserve = reserve + received;
     }
 
+    /// @notice `mtxWrap` (CTR-TOK-20): the leg must accept a wrap (enabled, no pending change, no shortfall); the
+    ///         underlying's `mtxTrade` checks the holder's signature, that this token is `o.dex`, the price
+    ///         (`receiveAmount <= minted`), the relayer (`submitter`) and the fee bound, and moves `o.amount` here.
+    /// @return received the measured delta (must be `o.amount`)
+    /// @return minted `⌊o.amount·num/den⌋`
+    /// @return fee `⌈minted·o.fee/10⁶⌉`, the submitter's part of `minted`
+    function wrapBySig(address u, ITradeToken.TradeOrder calldata o, bytes calldata sig, address submitter)
+        public returns (uint256 received, uint256 minted, uint256 fee)
+    {
+        Leg storage L = _wrapLeg(u, o);
+        minted = Math.mulDiv(o.amount, L.num, L.den);
+        if (minted == 0) revert IWrappedToken.WrapTooSmall();
+        fee = Math.mulDiv(minted, o.fee, 1_000_000, Math.Rounding.Ceil);
+        received = _pullBySig(L, o, sig, ITradeToken.TradeFill(o.amount, minted, fee, submitter));
+    }
+
+    function _wrapLeg(address u, ITradeToken.TradeOrder calldata o) private view returns (Leg storage L) {
+        if (u == NATIVE) revert IWrappedToken.NativeNotGasless();
+        WrappedStorage storage s = $();
+        L = s.legs[indexOf(u)];
+        if (!L.wrapEnabled) revert IWrappedToken.WrapDisabledFor(u);
+        if (L.adjustable && _isPending(s)) revert IWrappedToken.WrapPausedForRateChange(u);
+        if (o.receiveToken != address(this)) revert IWrappedToken.WrapOrderInvalid(o.receiveToken);
+    }
+
+    /// @dev One balance read before serves the shortfall check and the measurement, as in `_pull`.
+    function _pullBySig(Leg storage L, ITradeToken.TradeOrder calldata o, bytes calldata sig,
+        ITradeToken.TradeFill memory f) private returns (uint256 received)
+    {
+        address u = L.token;
+        uint256 reserve = L.reserve;
+        uint256 before = IERC20(u).balanceOf(address(this));
+        if (before < reserve) revert IWrappedToken.ReserveShortfall(u, before, reserve);
+        ITradeToken(u).mtxTrade(o, sig, f);
+        received = IERC20(u).balanceOf(address(this)) - before;
+        if (received != o.amount) revert IWrappedToken.WrapReceivedMismatch(o.amount, received);
+        L.reserve = reserve + received;
+    }
+
     /// @notice Every check before any effect: recipient, `0 < out`, `out ≥ minOut`, `out ≤ reserve`.
     function quoteUnwrap(uint256 i, uint256 wrapped, address recipient, uint256 minOut)
         public view returns (uint256 out, uint256 burned)
```

```diff
diff --git a/smartcontracts/evm/src/metatx/WrappedToken.sol b/smartcontracts/evm/src/metatx/WrappedToken.sol
index 6e712e1..e661556 100644
--- a/smartcontracts/evm/src/metatx/WrappedToken.sol
+++ b/smartcontracts/evm/src/metatx/WrappedToken.sol
@@ -71,6 +71,19 @@ contract WrappedToken is MetaTokenBase, IWrappedToken {
         emit ReserveAdded(from, u, WrappedLib.addReserve(WrappedLib.indexOf(u), amount, from, msg.value));
     }
 
+    /// @notice Signature wrap of a SCaaS underlying (CTR-TOK-20): mints `minted − fee` to `o.destination` (or
+    ///         `o.from`) and `fee` to the submitter. Not allowlisted: a direct read of the caller (the submitter).
+    function mtxWrap(address u, TradeOrder calldata o, bytes calldata sig)
+        external nonReentrant returns (uint256 minted)
+    {
+        uint256 received;
+        uint256 fee;
+        (received, minted, fee) = WrappedLib.wrapBySig(u, o, sig, msg.sender);
+        _mint(o.destination == address(0) ? o.from : o.destination, minted - fee);
+        if (fee != 0) _mint(msg.sender, fee);
+        emit Wrapped(o.from, u, received, minted);
+    }
+
     function _wrap(uint256 i, uint256 amount) private returns (uint256 minted) {
         address account = _msgSender();
         (address u, uint256 received, uint256 m) = WrappedLib.wrap(i, amount, account, msg.value);
```

- [ ] **Step 7: `test/v2/MtxWrap.t.sol`** (full text). Compute signatures and order hashes **before** `vm.prank`: an
  external call (`u.tradeOrderDigest`) consumes the prank.

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {V2Fixture, Rate} from "./helpers/V2Fixture.sol";
import {RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";

/// Signature wrap of a SCaaS underlying (CTR-TOK-20): the holder signs a `TradeOrder` in the underlying's domain with
/// `dex` = `receiveToken` = the wrapper; no allowance anywhere.
contract MtxWrapTest is V2Fixture {
    uint256 constant ALICE_PK = 0xA11CE;
    address alice = vm.addr(ALICE_PK);
    address bob = address(0xB0B);
    NormalToken u;
    WrappedToken w;

    function setUp() public {
        u = _none(alice, 1_000_000, address(0)); // decimals 0
        w = _single(address(u), 0, 3, 1, _fixedRate()); // 1 u -> 3 w
    }

    function _order(uint256 amount, uint256 minOut, uint256 fee) internal view returns (ITradeToken.TradeOrder memory o) {
        o.from = alice;
        o.receiveToken = address(w);
        o.amount = amount;
        o.receiveAmount = minOut;
        o.minFill = amount;
        o.fee = fee;
        o.dex = address(w);
        o.batch = 7;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _sig(ITradeToken.TradeOrder memory o) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, u.tradeOrderDigest(o));
        return abi.encodePacked(r, s, v);
    }

    function test_mtxWrap_mintsAtTheRate_feeToTheSubmitter() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 1_000); // 0.1 % of 3000 = 3
        bytes memory sig = _sig(o); // before the prank: an external call would consume it
        vm.expectEmit(address(w));
        emit IWrappedToken.Wrapped(alice, address(u), 1000, 3000);
        vm.prank(relayer);
        assertEq(w.mtxWrap(address(u), o, sig), 3000);
        assertEq(w.balanceOf(alice), 2997);
        assertEq(w.balanceOf(relayer), 3);
        assertEq(u.balanceOf(address(w)), 1000);
        (,, uint256 reserve,,) = w.legOf(address(u));
        assertEq(reserve, 1000);
        assertEq(u.allowance(alice, address(w)), 0);
        assertEq(u.pulled(u.tradeOrderDigest(o)), 1000);
    }

    function test_mtxWrap_toDestination() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        o.destination = bob;
        bytes memory sig = _sig(o);
        vm.prank(relayer);
        w.mtxWrap(address(u), o, sig);
        assertEq(w.balanceOf(bob), 3000);
        assertEq(w.balanceOf(alice), 0);
    }

    function test_mtxWrap_signedMinimumIsThePrice() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3001, 0);
        bytes memory sig = _sig(o);
        bytes32 h = u.tradeOrderDigest(o);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.PriceLimit.selector, h));
        w.mtxWrap(address(u), o, sig);
    }

    function test_mtxWrap_relayerBinding() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        o.relayer = bob;
        bytes memory sig = _sig(o);
        bytes32 h = u.tradeOrderDigest(o);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.WrongRelayer.selector, h, relayer));
        w.mtxWrap(address(u), o, sig);
        vm.prank(bob);
        w.mtxWrap(address(u), o, sig);
    }

    function test_mtxWrap_refusals() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        bytes memory sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnknownUnderlying.selector, address(0xDEAD)));
        w.mtxWrap(address(0xDEAD), o, sig);
        o.receiveToken = address(u);
        sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapOrderInvalid.selector, address(u)));
        w.mtxWrap(address(u), o, sig);
        // the order names another dex: the underlying refuses the wrapper as caller
        o = _order(1000, 3000, 0);
        o.dex = address(this);
        sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotDex.selector, address(w)));
        w.mtxWrap(address(u), o, sig);
    }

    function test_mtxWrap_nativeLegIsNotGasless() public {
        WrappedToken n = _single(address(0), 18, 1, 1, _fixedRate());
        ITradeToken.TradeOrder memory o = _order(1000, 1000, 0);
        o.receiveToken = address(n);
        o.dex = address(n);
        vm.expectRevert(IWrappedToken.NativeNotGasless.selector);
        n.mtxWrap(address(0), o, "");
    }

    function test_mtxWrap_pausedDuringARateChange() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        WrappedToken a = _single(address(u), 0, 3, 1, _adjustable(address(adm)));
        adm.exec(address(a), abi.encodeCall(a.proposeRate, (address(u), 301, 100)));
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        o.receiveToken = address(a);
        o.dex = address(a);
        bytes memory sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapPausedForRateChange.selector, address(u)));
        a.mtxWrap(address(u), o, sig);
    }

    function test_mtxWrap_anOutsideLegHasNoMtxTrade() public {
        MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
        WrappedToken x = _single(address(usdc), 6, 1, 1, _fixedRate());
        ITradeToken.TradeOrder memory o = _order(1000, 1000, 0);
        o.receiveToken = address(x);
        o.dex = address(x);
        vm.expectRevert();
        x.mtxWrap(address(usdc), o, "");
    }

    function test_mtxWrap_isNotAllowlisted() public view {
        (bytes4[] memory s,,) = w.mtxSelectors();
        for (uint256 i; i < s.length; ++i) assertTrue(s[i] != w.mtxWrap.selector);
    }
}
```

- [ ] **Step 8: Lint, size pins and baseline** — apply:

```diff
diff --git a/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol b/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
index 2a9ef43..6dc812c 100644
--- a/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
+++ b/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
@@ -9,9 +9,9 @@ import {Test} from "forge-std/Test.sol";
 /// are `//` are skipped (block comments are not). A change here is deliberate: update the pin in the same commit and
 /// say why.
 contract MsgSenderLintTest is Test {
-    string[8] internal FILES = ["src/metatx/MetaTxBase.sol", "src/metatx/ERC20MetaTx.sol", "src/metatx/MetaTokenBase.sol",
+    string[9] internal FILES = ["src/metatx/MetaTxBase.sol", "src/metatx/ERC20MetaTx.sol", "src/metatx/MetaTokenBase.sol",
         "src/metatx/NormalToken.sol", "src/metatx/WrappedToken.sol", "src/metatx/WrappedLib.sol",
-        "src/metatx/AdminLib.sol", "src/hedera/HederaLib.sol"];
+        "src/metatx/AdminLib.sol", "src/hedera/HederaLib.sol", "src/trade/TradeLib.sol"];
 
     /// Occurrences of `pat` (not preceded by an identifier character); `exceptSelector` skips `pat<ident>.selector`.
     function _count(string memory path, bytes memory pat, bool exceptSelector) internal view returns (uint256 n) {
@@ -53,11 +53,12 @@ contract MsgSenderLintTest is Test {
 
     function test_msgSenderReadsArePinned() public view {
         assertEq(_count("src/metatx/MetaTxBase.sol", "msg.sender", false), 7, "MetaTxBase: guard, event, relayer binding x2, _msgSender x2, fee default");
-        assertEq(_count("src/metatx/ERC20MetaTx.sol", "msg.sender", false), 2, "ERC20MetaTx: event relayer, fee default");
+        assertEq(_count("src/metatx/ERC20MetaTx.sol", "msg.sender", false), 3, "ERC20MetaTx: event relayer, fee default, mtxTrade caller (CTR-DEX-15)");
         assertEq(_count("src/metatx/MetaTokenBase.sol", "msg.sender", false), 1, "MetaTokenBase: factory check in initialize");
         assertEq(_count("src/metatx/NormalToken.sol", "msg.sender", false), 0, "NormalToken");
-        assertEq(_count("src/metatx/WrappedToken.sol", "msg.sender", false), 0, "WrappedToken");
+        assertEq(_count("src/metatx/WrappedToken.sol", "msg.sender", false), 2, "WrappedToken: mtxWrap submitter x2 (CTR-TOK-20)");
         assertEq(_count("src/metatx/WrappedLib.sol", "msg.sender", false), 0, "WrappedLib");
+        assertEq(_count("src/trade/TradeLib.sol", "msg.sender", false), 0, "TradeLib: the caller is a parameter");
         assertEq(_count("src/metatx/AdminLib.sol", "msg.sender", false), 0, "AdminLib");
         assertEq(_count("src/hedera/HederaLib.sol", "msg.sender", false), 0, "HederaLib");
     }
```

```diff
diff --git a/smartcontracts/evm/test/v2/Factory.t.sol b/smartcontracts/evm/test/v2/Factory.t.sol
index a56c796..e1ba4a5 100644
--- a/smartcontracts/evm/test/v2/Factory.t.sol
+++ b/smartcontracts/evm/test/v2/Factory.t.sol
@@ -300,9 +300,9 @@ contract FactoryTest is Test {
     }
 
     function test_sizes() public view {
-        assertLe(address(normalImpl).code.length, 20_480); // CTR-TOK-24
+        assertLe(address(normalImpl).code.length, 23_552); // owner: size later; budget 20,480 (P2a ruling)
         assertLe(address(f).code.length, 24_576);
         // Transitional (P1d D2): over EIP-170 until the size work
-        assertLe(address(wrappedImpl).code.length, 27_648);
+        assertLe(address(wrappedImpl).code.length, 30_720);
     }
 }
```

```diff
diff --git a/smartcontracts/evm/test/hedera/HederaV2.t.sol b/smartcontracts/evm/test/hedera/HederaV2.t.sol
index e9ccdf0..3eab985 100644
--- a/smartcontracts/evm/test/hedera/HederaV2.t.sol
+++ b/smartcontracts/evm/test/hedera/HederaV2.t.sol
@@ -52,9 +52,9 @@ contract HederaV2Test is Test {
     }
 
     function test_implementationSizes() public view {
-        assertLe(f.implementationOf(IOpenFactory.TokenKind.NORMAL, 1).code.length, 20_480); // CTR-TOK-24
+        assertLe(f.implementationOf(IOpenFactory.TokenKind.NORMAL, 1).code.length, 23_552); // owner: size later; budget 20,480 (P2a ruling)
         // Transitional (P1d D2): over EIP-170 until the size work
-        assertLe(f.implementationOf(IOpenFactory.TokenKind.WRAPPED, 1).code.length, 27_648);
+        assertLe(f.implementationOf(IOpenFactory.TokenKind.WRAPPED, 1).code.length, 30_720);
     }
 
     function _edSign(bytes32 digest) internal pure returns (bytes memory) {
```

```diff
diff --git a/smartcontracts/evm/size-baseline.json b/smartcontracts/evm/size-baseline.json
index 55e4507..a49c42d 100644
--- a/smartcontracts/evm/size-baseline.json
+++ b/smartcontracts/evm/size-baseline.json
@@ -1,5 +1,6 @@
 {
   "_comment": "CTR-TOK-24 size gate (scripts/size_gate.py). Contracts allowed over their limit, with the measured runtime size they may not exceed. Owner 2026-10-11: size optimised later; remove an entry once the contract fits.",
-  "WrappedToken": 26449,
+  "NormalToken": 22951,
+  "WrappedToken": 29974,
   "ZetherToken": 28860
 }
```

- [ ] **Step 9: Run** — `--match-path test/v2/Trade.t.sol` (13 passed), `--match-path test/v2/MtxWrap.t.sol` (9),
  `--match-contract TradeKatTest` (1); full suite: 817 + 23 = 840; size gate (`forge build src --sizes --json … || true`
  then `python3 scripts/size_gate.py /tmp/sizes.json smartcontracts/evm/size-baseline.json`): 0 errors.

- [ ] **Step 10: Commit** — `P2a: TradeOrder on every token (TradeLib, scaas.trade), mtxWrap, trade KAT` + trailer.

---

### Task 2: Docs, TODO, HANDOFF

**Model:** Sonnet, effort medium.

- `docs/contracts/dex.md` CTR-DEX-15 and §13: "Transitional (BUILT, P2a)": the token side is built on every token
  (`TradeLib`, `scaas.trade`, error names F2); the DEX side is still the built `SCaaSDex` until P2b.
- `docs/contracts/token-wrappers.md` CTR-TOK-20 (built, errors F3; the relayer binding is the underlying's), CTR-TOK-24
  (`TradeLib` row as built with its size; sizes and the baseline, "controller ruling, pending the owner"), §7 Interfaces
  (`mtxWrap` and its errors). Net ≤ 0 lines.
- `docs/contracts/metatx.md` CTR-MTX-18 inventory: `mtxTrade` and `mtxWrap` read the caller directly.
- `TODO.md`: P2 split into P2a (done), P2b (`SCaaSDex` clone, `createDex`, `mtxSettle`, `DexPuller`; old `SCaaSDex`
  kept as `SCaaSDexV1` for the node until P5), P2c (exchange path); MT-3 `mtxWrap` done; D1 note closed.
  `HANDOFF.md`: new top section (state, built, F1–F6 with F4 flagged, sizes, next = P2b plan).
- Checkers: `python3 scripts/docs_check.py check`, `… facts check`, `python3 scripts/test_docs_check.py` — 0 errors.
- Commit `P2a: docs, TODO and HANDOFF` + trailer.

---

### Final

- Whole-branch review (Opus, effort xhigh); one fix wave if needed; scoped re-review.
- Merge `p2a-trade` into `main` with `--no-ff`; push (the owner asked to push); remove the worktree.
