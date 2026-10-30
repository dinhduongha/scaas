# P2c — The exchange path on `SCaaSDex`: `mtxExchange`, `mtxExchangeVia`, exchange targets, `listedOnly`, the surplus — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute the same signed `TradeOrder`s against outside liquidity on the P2b `SCaaSDex` clone (CTR-DEX-20, -21,
-23, -03): `mtxExchange(plan, interactions)` where the DEX makes each call itself, `mtxExchangeVia(plan, executor, data)`
where an executor gets the sold fills and pays the DEX back in a callback; every order at a floor the submitter commits
to, every unit above the floors paid to the signers, the DEX's balance of every token unchanged at the end. The admin
gets its two remaining powers, `setExchangeTarget` and `setListedOnly`, and a leg's `LISTED_POOLS` asks the same.

**Architecture:** One plan = one atomic call, no `try`. `_exchangeIn` checks each leg (known tokens, distinct signers,
the shared `_calc` — relayer, `dex`, kind from the listing, fee on the floor, Path B bounds), builds a per-token table
(`Tok`: snapshot, Σ sold, Σ refunds, Σ floors), snapshots every leg and `extraTokens` token, pulls every leg through the
P2b `_pull` (SCaaS `mtxTrade` with the floor figures, outside `TradeLib` + `DexPuller`), and requires each balance to have
risen by exactly what was pulled. Path (a) runs each interaction through `_interact` (blocklist, listing, bubble) and
resets every allowance an `approve` interaction granted; path (b) hands out Σ sold per token, tells the executor Σ floors
per receive token, calls `exchangeCallback`. `_exchangeOut` computes `excess_T` per receive token (`InsufficientOutput`
below 0), pays each leg its floor − fee + `floor(excess · floor_i / Σ floors)` (the last leg the remainder) through the
same `_payLeg` as `mtxSettle`, emits `ExchangeLegSettled`, and asserts every snapshotted balance is back at its snapshot.
`setMarket` now counts listed markets per token (`tokenKnown`). No token, `TradeLib` or deploy change.

**Tech Stack:** Solidity 0.8.37 (`osaka`), Foundry (forge 1.3.5), OpenZeppelin 5.2.0 (`SafeERC20.forceApprove`,
`ReentrancyGuardTransient`), forge-std 1.16.2 (`snapshotState`/`revertToState`); `scaas-node` e2e (anvil) as the deploy
check.

**Spec:** `docs/contracts/dex.md` CTR-DEX-20 (entry points, steps, `ExchangeLegSettled`), -21 (surplus), -22 (no DEX
allowance), -23 (interaction blocklist, listed targets), -03 (admin powers), -15 (`receiveToken == this`, flag 4 on the
token: built in P2a), §10 invariants, §14 exchange-path tests; `docs/contracts/settlement.md` §3.6 and the "Exchange
against AMMs" row; design record `docs/history/specs/2026-10-08-dex-exchange-design.md` (DS-1…DS-6); TODO.md P2c line
and MT-5. `token-wrappers.md` assigns nothing to P2c (the token side is P2a).

**Base:** `main` at `7049c78` (P2b-2 merged). Every code block below was applied to a scratch worktree from `main` and run
green: full suite **937** (913 + 24), `DexExchange` 24, `Dex*` 82, size gate 0 errors, e2e 4/4 and 1/1, docs checkers 0
errors, mutation probe 34/34 killed (and the P2b-2 probe, patterns updated for the refactor, 20/20).

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; forge in `smartcontracts/evm` of worktree `.claude/worktrees/p2c`
  (branch `p2c-dex` from `main`; `lib/` is not tracked: `mkdir lib`, copy `smartcontracts/evm/lib/forge-std` into it and
  symlink `lib/openzeppelin-contracts → /home/ha/work/blockchain/openzeppelin-contracts`, as in the main checkout).
  Heavy commands only through `scripts/capped`, one at a time. `/usr/bin/grep`, `rtk proxy git diff`; if a hook blocks
  bare `git`, use `/usr/bin/git`.
- `scaas.dex` = `0xb144ea5327f344ea7e3b34dd1898f534c8ce28f9f54d0d89a1b78f8fcf7dac00`: two fields appended to `DexStorage`
  (`listings`, `exchangeTarget`); no layout file pins the DEX, and no clone is deployed outside tests.
- Flags: `IOC 1 | ESCROW 2 | LISTED_POOLS 4` (`TradeLib` accepts 4 since P2a; the DEX reads it here).
- Tests: compute anything that makes an external call (`tradeOrderDigest`, `dexOrderDigest`, `dex.puller()`,
  `dex.tokenKind`, building a leg) **before** `vm.prank` / `vm.expectRevert`: the external call would consume the
  cheatcode. A gas-burning target is always called with an explicit gas cap (`{gas: 1_000_000}`), or the test hangs.
  Every DEX-only check has a named killer test (mutation table, Task 1 Step 4).
- Code size is not a concern (owner: wait for the Glamsterdam fork); the ratchet baseline records sizes. Measured:
  `SCaaSDex` 21,761 B (was 14,722; under EIP-170, no baseline entry), `DexPuller` 624 B, tokens unchanged
  (`NormalToken` 22,960, `WrappedToken` 29,983): `size-baseline.json` unchanged.
- Component docs say "controller ruling, pending the owner", never a J-id. The multi-key account is `SmartKeyAccount`.
- Commit trailer (both lines): `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01GBLbPyQuG5HXALewwBZ7Bb`. Never `git add claude-code-api.txt`.

## Review Focus

- **A route that takes funds the signers did not sell, or pays them less than the floor.** Pull check, surplus formula,
  final conservation — pinned by `test_exchange_feeOnTransferSellToken_failsAtThePull`, `test_exchange_routerPullingMore_fails`,
  `test_exchange_lyingRouter_insufficientOutput_exactFloorsSettle` (the `<` boundary), `test_exchange_intermediateLeftover_reverts`,
  `test_exchange_soldOnlyLeftover_reverts`, `test_exchangeVia_executorPaysLess_reverts`.
- **An interaction acting as the DEX against a third party.** `mtxTrade` of a resting order that names this DEX (the
  attack works without the block: the stolen units come back as surplus and conservation balances), the DEX or the
  puller as target, `transferFrom(victim, …)` (no DEX allowance, CTR-DEX-22 kept: holders approve the puller only),
  re-entry — pinned by `test_exchange_forbiddenSelector_mtxTradeOfARestingOrder_andShortData`,
  `test_exchange_forbiddenTargets_theDexAndThePuller`, `test_exchange_transferFromAVictim_fails`,
  `test_exchange_reenteringTarget_isRefused`, `test_exchangeVia_hostileExecutor_reenterTradePull_fail`.
- **An allowance that outlives the route.** `test_exchange_approvalsResetToZero` (router and a second spender, both back
  to 0). Residual (J4): allowance-raising calls other than ERC-20 `approve` are not tracked.
- **Surplus split.** By floor, the last leg (by index) the remainder, no fee on the surplus, refunds never distributed —
  `test_exchange_twoLegs_floorsPlusSurplus_feesOnTheFloor`, `test_exchangeVia_executorPaysMore_distributed` (513/487, the
  fee unchanged), `test_exchange_coincidenceOfWants_noInteractions_refundNotDistributed`.
- **Listing.** `LISTED_POOLS` × `setListedOnly` × both entry points — `test_exchange_listedPoolsTimesListedOnly_bothEntryPoints`;
  known tokens counted per market — `test_exchange_tokenNotKnown`.
- **The `_calc` / `_pull` / `_pay` refactor** (parts instead of a `Leg`, so `ExchangeLeg` reuses them): `test/v2/Dex.t.sol`
  and `DexOutside.t.sol` run unchanged, and the P2b-2 mutation probe (20 mutants, patterns updated) still kills 20/20.

## Rulings (docs vs code) and defaults taken

- **J1 — Who checks what on the exchange path.** CTR-DEX-20 step 1 lists price and minimum fill among the DEX's checks.
  As in `mtxSettle` (P2b-1), Path A bounds are checked once, at the pull, by the token (or by `TradeLib` on the DEX for an
  outside leg) against the floor figures — same rule, the token's errors with the order hash (`PriceLimit(h)`,
  `BelowMinFill(h)`); Path B bounds (`Overfill`, `BelowMinFill`, `PriceLimit`) by the DEX in the shared `_calc`. The DEX
  adds no second Path A check (it would add nothing and no killable mutant).
- **J2 — "Known" token = a side of at least one listed market**, counted per market in `setMarket` (`listings`; a repeated
  listing counts once, the last delisting makes it unknown; the kind snapshot stays). `tokenKnown(token)` is the view the
  node's intake needs (NODE-DEX-17). `extraTokens` need not be known: they are only snapshotted and must end at their
  snapshot.
- **J3 — Pull check.** The design record says a fee-on-transfer or rebasing token "breaks conservation and reverts"; on
  the exchange path a route could spend only what arrived, so final conservation alone would not see it. After the
  pulls each token's balance must equal snapshot + Σ (sold + Path B amount pulled), else `ConservationBroken(token)` —
  before any interaction. An inexact **receive** token stays the admin's listing job (H8): the DEX cannot see what a
  destination is credited.
- **J4 — Allowances reset (stricter than CTR-DEX-23).** The spec lets interactions `approve` and accepts the residual
  ("between calls the DEX holds no user funds"). The DEX records every ERC-20 `approve(spender, x)` interaction
  (`bytes4(data) == IERC20.approve.selector`, spender decoded) and calls `forceApprove(spender, 0)` on each after the
  last interaction, before any payout: no allowance the DEX granted survives the call. Residual: other allowance-raising
  calls (`increaseAllowance`, Permit2's own `approve`) are not tracked; a Permit2 allowance is inert once the ERC-20
  allowance to Permit2 is back to 0. CTR-DEX-22 unchanged: users approve the puller, never the DEX.
- **J5 — Leftovers.** CTR-DEX-21's "a sold-only or intermediate token must end at its snapshot plus the refunds still to
  pay" is enforced by the final conservation check over every snapshotted token (same `ConservationBroken(token)`), not
  by a separate pre-payout check (it would be redundant and unkillable). `InsufficientOutput(token)` is raised only for
  tokens some leg receives.
- **J6 — Error arguments the spec leaves open:** `TokenNotKnown(token)`, `ForbiddenTarget(target)`,
  `ForbiddenSelector(target, selector)` (`selector` = `bytes4(data)`, zero-padded: 0 for empty data), `TargetNotListed(target)`,
  `InsufficientOutput(token)`, `NoLegs()`; `SelfTrade(from)` reused for two legs of one signer.
- **J7 — The listing condition covers every interaction target, the tokens included.** When a leg sets `LISTED_POOLS` or
  the mode is on, an `approve`/`transfer` on a token is an interaction like any other: the admin lists the tokens routes
  may touch as well as the pools (spec-literal; no exemption for known tokens).
- **J8 — `NoLegs`.** An empty plan is refused: it would run arbitrary calls as the DEX with nothing to settle.
- **J9 — `ExchangeLegSettled.receivedFloor` is the gross floor** (`receiveFill`), so `receivedFloor + surplus` compares
  with the gross `limitReceive`; the destination got `receivedFloor − dexFee + surplus`; the fee shares are not in the
  event (spec field list kept; derivable from `FeeSplitSet`). `IExchangeExecutor` lives in `ISCaaSDex.sol`.
- **J10 — Tests.** Mocks stand in for Uniswap v3 (a router pulling under an allowance) and v2 (a pair paid first); the
  fork test with real Uniswap bytecode (§14) and the DEX invariant suite stay open (no Uniswap artifacts in the repo).
  `test/v2/DexExchange.t.sol` adds 24 tests; `Dex.t.sol`, `DexOutside.t.sol` unchanged.
- **J11 — Deploy.** No constructor change, so `DeployBase`, the Hedera script and `size-baseline.json` are unchanged;
  `mtxExchangeVia` blocks no executor address (the DEX and the puller have no `exchangeCallback`, so the call reverts).

## Open questions (not blocking)

- J4's residual: should `increaseAllowance(address,uint256)` and Permit2's `approve` selector be refused as well (a
  blocklist that can never be complete), or is the ERC-20 reset plus "no user funds between calls" enough?
- The §14 fork test needs Uniswap v2/v3 bytecode (a vendored artifact or an anvil fork of a public chain): which source
  does the owner accept?

---

### Task 1: The exchange path on `SCaaSDex`; tests; probe

**Model:** Sonnet, effort high (validated transcription on a money path; the mutation probe in Step 4 is the gate).

**Files:**
- Replace (full text): `smartcontracts/evm/src/dex/ISCaaSDex.sol`, `smartcontracts/evm/src/dex/SCaaSDex.sol`
- Create: `smartcontracts/evm/test/v2/DexExchange.t.sol`

**Interfaces:** Consumes P2b `SCaaSDex` (`_calc`, `_pull`, `_send`, `_cap`, `_onlyAdmin`, `DexStorage`), `TradeLib`,
`DexPuller`, `ITradeToken.mtxTrade` (selector). Produces `ISCaaSDex.ExchangeLeg`, `Interaction`, `ExchangePlan`,
`mtxExchange`, `mtxExchangeVia`, `setExchangeTarget`, `setListedOnly`, `exchangeTarget`, `tokenKnown`, the events
`ExchangeLegSettled`, `ExchangeTargetSet`, `ListedOnlySet`, the six errors of J6, and `IExchangeExecutor`.

- [ ] **Step 1: `src/dex/ISCaaSDex.sol`** (full text)

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ITradeToken} from "../trade/ITradeToken.sol";

/// @title The DEX side of `TradeOrder` (CTR-DEX-16, -17, -11, -03, -24, -18, -22, -08, -20, -21, -23): one taker against
///        many makers per settlement, or a plan of orders against AMM routes (the exchange path); every leg pulled into
///        the DEX (a SCaaS token through its `mtxTrade`, an outside token through the `DexPuller` against a `DexOrder`),
///        every party, fee share, surplus and refund paid in the same call, and the DEX's balance of every token
///        unchanged at the end.
interface ISCaaSDex {
    /// @notice Written once by `initialize` (CTR-DEX-24). `relayerSharePpm` of every fee goes to the submitter, the
    ///         rest to `treasury`. `listedOnly`: every exchange target or executor must be listed (CTR-DEX-23).
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

    /// @notice One order on the exchange path (CTR-DEX-20): `sellFill` of its sell token in this call (Path B: the
    ///         matched part), `receiveFill` the floor the submitter commits to; the order gets the floor plus its share
    ///         of the surplus (CTR-DEX-21).
    struct ExchangeLeg {
        address sellToken;
        ITradeToken.TradeOrder o;
        bytes sig;
        uint256 sellFill;
        uint256 receiveFill;
    }

    /// @notice A call the DEX makes on path (a); no value: the DEX holds no native coin.
    struct Interaction {
        address target;
        bytes data;
    }

    /// @notice One route, atomic. `extraTokens`: intermediate hop tokens that pass through the DEX (snapshotted; each
    ///         must end at its snapshot).
    struct ExchangePlan {
        bytes32 ref;
        ExchangeLeg[] legs;
        address[] extraTokens;
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
    event ExchangeTargetSet(address indexed target, bool listed);
    event ListedOnlySet(bool on);
    /// @notice `receivedFloor` is the gross floor (`receiveFill`): the party gets `receivedFloor - dexFee + surplus`;
    ///         `limitReceive = ceil(sold · receiveAmount / amount)` is what the signed price guarantees for `sold`.
    event ExchangeLegSettled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed from, address destination,
        uint256 sold, uint256 receivedFloor, uint256 surplus, uint256 dexFee, uint256 refund, uint256 limitReceive);

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
    /// @notice Exchange path (CTR-DEX-20, -21, -23).
    error NoLegs();
    error TokenNotKnown(address token);
    error ForbiddenTarget(address target);
    error ForbiddenSelector(address target, bytes4 selector);
    error TargetNotListed(address target);
    error InsufficientOutput(address token);

    function initialize(address creator, uint64 version, DexConfig calldata cfg) external;
    function setMarket(address base, address quote, bool listed) external;
    function setFeeSplit(uint32 relayerSharePpm, address treasury) external;
    function mtxSettle(Settlement[] calldata s) external returns (bool[] memory ok);
    /// @notice Outside-token orders (CTR-DEX-18, CTR-DEX-02): closed or bad-signature items are skipped.
    function mtxCancelOrders(DexOrder[] calldata orders, bytes[] calldata sigs) external;
    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external;
    /// @notice Exchange path (a): the DEX makes each interaction itself (CTR-DEX-20, -23).
    function mtxExchange(ExchangePlan calldata p, Interaction[] calldata interactions) external;
    /// @notice Exchange path (b): the pulled sell fills go to `executor`, which pays the DEX back in its callback.
    function mtxExchangeVia(ExchangePlan calldata p, address executor, bytes calldata data) external;
    function setExchangeTarget(address target, bool listed) external;
    function setListedOnly(bool on) external;

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
    /// @notice A side of at least one listed market: the exchange path takes only known tokens.
    function tokenKnown(address token) external view returns (bool);
    function exchangeTarget(address target) external view returns (bool);
    /// @notice 0 unknown, 1 SCaaS (made by the factory from a registered, non-deprecated version), 2 outside.
    function tokenKind(address token) external view returns (uint8);
    function factory() external view returns (address);
    function chainUid() external view returns (bytes32);
}

/// @notice An executor of `mtxExchangeVia` (CTR-DEX-20 (b)): it has received `amountsOut` of `tokensOut` and must
///         transfer at least `amountsIn` of `tokensIn` (the floors) to the DEX before it returns; anything more is
///         surplus for the signers.
interface IExchangeExecutor {
    function exchangeCallback(bytes32 ref, address[] calldata tokensOut, uint256[] calldata amountsOut,
        address[] calldata tokensIn, uint256[] calldata amountsIn, bytes calldata data) external;
}
```

- [ ] **Step 2: `src/dex/SCaaSDex.sol`** (full text). Changes against `main`: the NatSpec header; `LISTED_POOLS`;
  `listings` and `exchangeTarget` in storage; `Tok`; `setMarket` counts listed markets; `setExchangeTarget`,
  `setListedOnly`, `tokenKnown`, `exchangeTarget`; `_calc`/`_pull` take the order's parts (`_pullLeg` keeps `settleOne`
  under the stack limit), `_pay` splits into `_pay` + `_payLeg` (with a `surplus` argument); the exchange section
  (`mtxExchange`, `mtxExchangeVia`, `_flows`, `_exchangeIn`, `_interact`, `_exchangeOut`, `_payExchange`,
  `_emitExchangeLeg`, `_tok`). `via_ir` stays off: the helpers exist to stay under the stack limit.

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ISCaaSDex, IExchangeExecutor} from "./ISCaaSDex.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {TradeLib} from "../trade/TradeLib.sol";
import {DexPuller} from "./DexPuller.sol";

/// @title `SCaaSDex` (CTR-DEX-16, -17, -11, -03, -24, -18, -22, -08, -20, -21, -23): an EIP-1167 clone made by
///        `OpenFactory.createDex`.
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
///         Exchange path (CTR-DEX-20): the same orders against AMM routes instead of makers, each at a floor the
///         submitter commits to; every output above the floors is paid to the signers (CTR-DEX-21); interactions may
///         not call the DEX, the puller or any `mtxTrade`, listed targets only when a leg or the admin asks
///         (CTR-DEX-23), and every allowance an `approve` interaction grants is set back to 0 before the payout.
contract SCaaSDex is ISCaaSDex, SaltedEIP712, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    uint256 internal constant PPM = 1_000_000;
    uint8 internal constant ESCROW = 2;
    uint8 internal constant KIND_SCAAS = 1;
    uint8 internal constant KIND_OUTSIDE = 2;
    /// @dev Bytes of a failed settlement's revert data kept for `MatchFailed`: the copy costs this frame at most this
    ///      much, so a returnbomb (an outside token reverting with megabytes) cannot take the other settlements down.
    uint256 internal constant MAX_REASON = 256;
    /// @dev `TradeOrder.flags` bit: every interaction target or executor must be listed (CTR-DEX-23).
    uint8 internal constant LISTED_POOLS = 4;
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
        mapping(address token => uint256) listings; // listed markets the token is a side of: > 0 = known
        mapping(address target => bool) exchangeTarget;
    }

    bytes32 internal constant DEX_ORDER_TYPEHASH = keccak256(
        "DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,address receiveToken,uint256 amount,"
        "uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address destination,uint8 flags,"
        "uint256 batch,uint256 nonce,uint256 validUntil)"
    );

    // keccak256(abi.encode(uint256(keccak256("scaas.dex")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xb144ea5327f344ea7e3b34dd1898f534c8ce28f9f54d0d89a1b78f8fcf7dac00;

    address public immutable FACTORY;
    /// @notice This chain's `SmartKeyAccount` implementation (0 = none), as the tokens expose it; the deploy checks they agree.
    address public immutable SMART_KEY_ACCOUNT_IMPL;
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

    /// @dev Per token of an exchange plan.
    struct Tok {
        address token;
        uint256 snap;       // the DEX's balance before the pulls
        uint256 sold;       // Σ sellFill of the legs selling it: what the route may spend
        uint256 refunds;    // Σ Path B refunds of the legs selling it
        uint256 floors;     // Σ receiveFill of the legs receiving it
        uint256 excess;     // surplus above the floors, for the legs receiving it
        uint256 floorsLeft; // floors of the legs not yet paid: the last one takes the rounding remainder
        uint256 paid;       // surplus paid so far
    }

    /// @dev Runs once on the implementation and locks it.
    constructor(address factory_, bytes32 chainUid_, address smartKeyAccountImpl_)
        SaltedEIP712("SCaaS Dex", "1", chainUid_)
    {
        FACTORY = factory_;
        SMART_KEY_ACCOUNT_IMPL = smartKeyAccountImpl_;
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
        bytes32 k = _pair(base, quote);
        if (s.listed[k] != listed) {
            s.listed[k] = listed;
            if (listed) {
                ++s.listings[base];
                ++s.listings[quote];
            } else {
                --s.listings[base];
                --s.listings[quote];
            }
        }
        s.kind[base] = _classify(base);
        s.kind[quote] = _classify(quote);
        emit MarketSet(base, quote, listed);
    }

    function setFeeSplit(uint32 relayerSharePpm_, address treasury_) external {
        _setFeeSplit(_onlyAdmin(), relayerSharePpm_, treasury_);
    }

    /// @notice Lists or delists an interaction target or an executor (CTR-DEX-23).
    function setExchangeTarget(address target, bool listed) external {
        _onlyAdmin().exchangeTarget[target] = listed;
        emit ExchangeTargetSet(target, listed);
    }

    /// @notice DEX-wide listed-only mode for the exchange path (CTR-DEX-23); a leg's `LISTED_POOLS` asks the same.
    function setListedOnly(bool on) external {
        _onlyAdmin().listedOnly = on;
        emit ListedOnlySet(on);
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
    function tokenKnown(address token) external view returns (bool) { return _s().listings[token] != 0; }
    function exchangeTarget(address target) external view returns (bool) { return _s().exchangeTarget[target]; }
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
        Calc memory taker = _calc(s.taker.sellToken, s.taker.o, submitter, takerSell, takerRecv);
        uint256 balA = IERC20(tokenA).balanceOf(address(this));
        uint256 balB = IERC20(tokenB).balanceOf(address(this));
        _pullLeg(s.taker, taker, submitter);
        for (uint256 i; i < n; ++i) _pullLeg(s.makers[i], makers[i], submitter);
        _pay(s.ref, s.taker, taker, submitter);
        for (uint256 i; i < n; ++i) _pay(s.ref, s.makers[i], makers[i], submitter);
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
        c = _calc(m.sellToken, m.o, submitter, m.fill, recv);
    }

    /// @dev Relayer binding, `dex`, the leg's kind from the listing (an outside leg is a `DexOrder`, never `ESCROW`),
    ///      the fee on the aggregate receive (the floor on the exchange path); Path B: the DEX's own checks on the
    ///      matched part. Path A bounds are checked at the pull, by the token or by `TradeLib` on the DEX.
    function _calc(address sellToken, ITradeToken.TradeOrder calldata o, address submitter, uint256 sold, uint256 recv)
        private view returns (Calc memory c)
    {
        if (o.relayer != address(0) && o.relayer != submitter) revert WrongRelayer(submitter);
        if (o.dex != address(this)) revert DexMismatch(o.dex);
        c.outside = _s().kind[sellToken] != KIND_SCAAS;
        c.h = c.outside ? dexOrderDigest(sellToken, o) : ITradeToken(sellToken).tradeOrderDigest(o);
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

    function _pullLeg(Leg calldata l, Calc memory c, address submitter) private {
        _pull(l.sellToken, l.o, l.sig, c, submitter);
    }

    function _pull(address sellToken, ITradeToken.TradeOrder calldata o, bytes calldata sig, Calc memory c,
        address submitter) private
    {
        ITradeToken.TradeFill memory f = o.flags & ESCROW != 0
            ? ITradeToken.TradeFill(o.amount, 0, 0, submitter)
            : ITradeToken.TradeFill(c.sold, c.recv, c.fee, submitter);
        if (!c.outside) return ITradeToken(sellToken).mtxTrade(o, sig, f);
        // outside token: the DEX runs the token's checks on its own state, then pulls through the puller
        TradeLib.precheck(o, f, c.h, address(this), sellToken);
        if (!SigCheck.isValid(o.from, c.h, sig, _cap(o.from))) revert BadSignature(c.h);
        DexPuller(_s().puller).pull(sellToken, o.from, TradeLib.record(o, f, c.h));
    }

    function _pay(bytes32 ref, Leg calldata l, Calc memory c, address submitter) private {
        (address to, uint256 relayerShare, uint256 treasuryShare) = _payLeg(l.sellToken, l.o, c, 0, submitter);
        emit LegSettled(ref, c.h, l.o.from, to, c.sold, c.recv - c.fee, c.fee, c.refund, relayerShare, treasuryShare);
    }

    /// @dev Proceeds net of the fee, plus `surplus`, to `destination` (or `from`), the fee split, the Path B refund.
    function _payLeg(address sellToken, ITradeToken.TradeOrder calldata o, Calc memory c, uint256 surplus,
        address submitter) private returns (address to, uint256 relayerShare, uint256 treasuryShare)
    {
        DexStorage storage s = _s();
        to = o.destination == address(0) ? o.from : o.destination;
        relayerShare = c.fee * s.relayerSharePpm / PPM;
        treasuryShare = c.fee - relayerShare;
        _send(o.receiveToken, to, c.recv - c.fee + surplus);
        _send(o.receiveToken, submitter, relayerShare);
        _send(o.receiveToken, s.treasury, treasuryShare);
        _send(sellToken, o.from, c.refund);
    }

    // ------------------------------------------------------------------ exchange path (CTR-DEX-20, -21, -23)

    /// @notice Path (a): the DEX makes each interaction (never on itself or its puller, never `mtxTrade`, listed when a
    ///         leg or the admin asks); a failing one reverts the plan with its data. Every allowance an `approve`
    ///         interaction granted is set back to 0 after the last interaction (controller ruling: the DEX keeps no
    ///         allowance past the route).
    function mtxExchange(ExchangePlan calldata p, Interaction[] calldata xs) external nonReentrant {
        (Tok[] memory t, Calc[] memory c, bool onlyListed) = _exchangeIn(p);
        address[] memory approvedToken = new address[](xs.length);
        address[] memory approvedSpender = new address[](xs.length);
        uint256 na;
        for (uint256 i; i < xs.length; ++i) {
            bytes4 sel = _interact(xs[i], onlyListed);
            if (sel == IERC20.approve.selector) {
                approvedToken[na] = xs[i].target;
                (approvedSpender[na++],) = abi.decode(xs[i].data[4:], (address, uint256));
            }
        }
        for (uint256 i; i < na; ++i) IERC20(approvedToken[i]).forceApprove(approvedSpender[i], 0);
        _exchangeOut(p, t, c);
    }

    /// @notice Path (b): the sold fills go to `executor` (listed when a leg or the admin asks), which must transfer at
    ///         least the floors to the DEX inside `exchangeCallback`; re-entry hits `nonReentrant`, a `mtxTrade` or a
    ///         puller call from it fails (it is neither `o.dex` nor the DEX).
    function mtxExchangeVia(ExchangePlan calldata p, address executor, bytes calldata data) external nonReentrant {
        (Tok[] memory t, Calc[] memory c, bool onlyListed) = _exchangeIn(p);
        if (onlyListed && !_s().exchangeTarget[executor]) revert TargetNotListed(executor);
        (address[] memory tokensOut, uint256[] memory amountsOut, address[] memory tokensIn, uint256[] memory amountsIn)
            = _flows(t);
        for (uint256 i; i < tokensOut.length; ++i) _send(tokensOut[i], executor, amountsOut[i]);
        IExchangeExecutor(executor).exchangeCallback(p.ref, tokensOut, amountsOut, tokensIn, amountsIn, data);
        _exchangeOut(p, t, c);
    }

    /// @dev Path (b)'s figures: per sold token Σ sellFill (the Path B remainders stay for the refunds), per receive
    ///      token Σ floors.
    function _flows(Tok[] memory t) private pure returns (address[] memory tokensOut, uint256[] memory amountsOut,
        address[] memory tokensIn, uint256[] memory amountsIn)
    {
        uint256 nOut;
        uint256 nIn;
        for (uint256 i; i < t.length; ++i) {
            if (t[i].sold != 0) ++nOut;
            if (t[i].floors != 0) ++nIn;
        }
        (tokensOut, amountsOut) = (new address[](nOut), new uint256[](nOut));
        (tokensIn, amountsIn) = (new address[](nIn), new uint256[](nIn));
        (nOut, nIn) = (0, 0);
        for (uint256 i; i < t.length; ++i) {
            if (t[i].sold != 0) (tokensOut[nOut], amountsOut[nOut++]) = (t[i].token, t[i].sold);
            if (t[i].floors != 0) (tokensIn[nIn], amountsIn[nIn++]) = (t[i].token, t[i].floors);
        }
    }

    /// @dev Steps 1-3: check every leg, snapshot every token, pull every leg; each pulled token's balance must rise by
    ///      exactly what was pulled (a fee-on-transfer or rebasing sell token fails here).
    function _exchangeIn(ExchangePlan calldata p) private returns (Tok[] memory t, Calc[] memory c, bool onlyListed) {
        DexStorage storage s = _s();
        uint256 n = p.legs.length;
        if (n == 0) revert NoLegs();
        onlyListed = s.listedOnly;
        t = new Tok[](2 * n + p.extraTokens.length);
        c = new Calc[](n);
        for (uint256 i; i < n; ++i) {
            ExchangeLeg calldata l = p.legs[i];
            address rt = l.o.receiveToken;
            if (s.listings[l.sellToken] == 0) revert TokenNotKnown(l.sellToken);
            if (s.listings[rt] == 0) revert TokenNotKnown(rt);
            for (uint256 j; j < i; ++j) if (p.legs[j].o.from == l.o.from) revert SelfTrade(l.o.from);
            c[i] = _calc(l.sellToken, l.o, msg.sender, l.sellFill, l.receiveFill);
            if (l.o.flags & LISTED_POOLS != 0) onlyListed = true;
            Tok memory ts = _tok(t, l.sellToken);
            ts.sold += c[i].sold;
            ts.refunds += c[i].refund;
            _tok(t, rt).floors += c[i].recv;
        }
        for (uint256 i; i < p.extraTokens.length; ++i) _tok(t, p.extraTokens[i]);
        uint256 nt;
        while (nt < t.length && t[nt].token != address(0)) ++nt;
        assembly ("memory-safe") { mstore(t, nt) }
        for (uint256 i; i < nt; ++i) {
            t[i].snap = IERC20(t[i].token).balanceOf(address(this));
            t[i].floorsLeft = t[i].floors;
        }
        for (uint256 i; i < n; ++i) _pull(p.legs[i].sellToken, p.legs[i].o, p.legs[i].sig, c[i], msg.sender);
        for (uint256 i; i < nt; ++i) {
            Tok memory x = t[i];
            if (IERC20(x.token).balanceOf(address(this)) != x.snap + x.sold + x.refunds) {
                revert ConservationBroken(x.token);
            }
        }
    }

    /// @dev One interaction of path (a); returns its selector.
    function _interact(Interaction calldata x, bool onlyListed) private returns (bytes4 sel) {
        DexStorage storage s = _s();
        if (x.target == address(this) || x.target == s.puller) revert ForbiddenTarget(x.target);
        sel = bytes4(x.data);
        if (x.data.length < 4 || sel == ITradeToken.mtxTrade.selector) revert ForbiddenSelector(x.target, sel);
        if (onlyListed && !s.exchangeTarget[x.target]) revert TargetNotListed(x.target);
        (bool ok, bytes memory ret) = x.target.call(x.data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
    }

    /// @dev Steps 5-6: the surplus per receive token (CTR-DEX-21), the payouts, conservation over every token (a
    ///      sold-only or intermediate leftover fails there: a route bug, not something to assign).
    function _exchangeOut(ExchangePlan calldata p, Tok[] memory t, Calc[] memory c) private {
        for (uint256 i; i < t.length; ++i) {
            Tok memory x = t[i];
            if (x.floors == 0) continue;
            uint256 bal = IERC20(x.token).balanceOf(address(this));
            uint256 keep = x.snap + x.refunds + x.floors;
            if (bal < keep) revert InsufficientOutput(x.token);
            x.excess = bal - keep;
        }
        for (uint256 i; i < p.legs.length; ++i) {
            ExchangeLeg calldata l = p.legs[i];
            Tok memory x = _tok(t, l.o.receiveToken);
            uint256 share = x.floorsLeft == c[i].recv ? x.excess - x.paid : Math.mulDiv(x.excess, c[i].recv, x.floors);
            x.floorsLeft -= c[i].recv;
            x.paid += share;
            _payExchange(p.ref, l, c[i], share);
        }
        for (uint256 i; i < t.length; ++i) {
            if (IERC20(t[i].token).balanceOf(address(this)) != t[i].snap) revert ConservationBroken(t[i].token);
        }
    }

    function _payExchange(bytes32 ref, ExchangeLeg calldata l, Calc memory c, uint256 surplus) private {
        (address to,,) = _payLeg(l.sellToken, l.o, c, surplus, msg.sender);
        uint256 limit = Math.mulDiv(c.sold, l.o.receiveAmount, l.o.amount, Math.Rounding.Ceil);
        _emitExchangeLeg(ref, l.o.from, to, c, surplus, limit);
    }

    function _emitExchangeLeg(bytes32 ref, address from, address to, Calc memory c, uint256 surplus, uint256 limit)
        private
    {
        emit ExchangeLegSettled(ref, c.h, from, to, c.sold, c.recv, surplus, c.fee, c.refund, limit);
    }

    /// @dev The entry of `token`, added in the first free slot if absent (`t` is sized for every token of the plan).
    function _tok(Tok[] memory t, address token) private pure returns (Tok memory x) {
        for (uint256 i; i < t.length; ++i) {
            x = t[i];
            if (x.token == token) return x;
            if (x.token == address(0)) {
                x.token = token;
                return x;
            }
        }
    }

    function _send(address token, address to, uint256 amount) private {
        if (amount != 0) IERC20(token).safeTransfer(to, amount);
    }
}
```

- [ ] **Step 3: `test/v2/DexExchange.t.sol`** (new, full text). Fixture: SCaaS `A` (Alice 800 k, Carol 100 k, the router
  100 k) and `B` (Bob 500 k, the router 500 k), outside `USDC` (Dave, approved to the puller), an unlisted hop token `C`;
  markets A/B and USDC/B; fee split 20 % to the relayer.

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex, IExchangeExecutor} from "../../src/dex/ISCaaSDex.sol";
import {DexPuller} from "../../src/dex/DexPuller.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MockERC20, FeeOnTransferERC20} from "../helpers/Mocks.sol";
import {UID_, normalInit} from "./helpers/V2Fixture.sol";

/// Router (v3 style): pulls `amountIn` (+ `extraIn`) from the caller under its allowance, pays `amountOut`
/// (- `shortOut`) to `to` and always claims `amountOut` (the DEX never reads it).
contract MockRouter {
    uint256 public extraIn;
    uint256 public shortOut;

    function setQuirks(uint256 extraIn_, uint256 shortOut_) external {
        (extraIn, shortOut) = (extraIn_, shortOut_);
    }

    function swap(address tIn, address tOut, uint256 amountIn, uint256 amountOut, address to) external returns (uint256) {
        IERC20(tIn).transferFrom(msg.sender, address(this), amountIn + extraIn);
        IERC20(tOut).transfer(to, amountOut - shortOut);
        return amountOut;
    }
}

/// Pair (v2 style): paid first by a transfer, `swap` pays `(new input) · num / den` of `tokenOut` to `to`.
contract MockPair {
    IERC20 immutable tokenIn;
    IERC20 immutable tokenOut;
    uint256 immutable num;
    uint256 immutable den;
    uint256 reserveIn;

    constructor(address i, address o, uint256 n, uint256 d) {
        (tokenIn, tokenOut, num, den) = (IERC20(i), IERC20(o), n, d);
    }

    function swap(address to) external {
        uint256 bal = tokenIn.balanceOf(address(this));
        uint256 out = (bal - reserveIn) * num / den;
        reserveIn = bal;
        tokenOut.transfer(to, out);
    }
}

/// Executor of path (b): optionally makes one call (re-entry, `mtxTrade`, the puller), records what it was told, then
/// pays each floor plus `abi.decode(data, (int256))` from its own inventory.
contract MockExecutor is IExchangeExecutor {
    address public callTarget;
    bytes public callData;
    address[] outT;
    uint256[] outA;
    address[] inT;
    uint256[] inA;

    function setCall(address t, bytes calldata d) external {
        (callTarget, callData) = (t, d);
    }

    function exchangeCallback(bytes32, address[] calldata tokensOut, uint256[] calldata amountsOut,
        address[] calldata tokensIn, uint256[] calldata amountsIn, bytes calldata data) external
    {
        if (callTarget != address(0)) {
            (bool ok, bytes memory r) = callTarget.call(callData);
            if (!ok) assembly { revert(add(r, 32), mload(r)) }
        }
        outT = tokensOut;
        outA = amountsOut;
        inT = tokensIn;
        inA = amountsIn;
        int256 bonus = abi.decode(data, (int256));
        for (uint256 i; i < tokensIn.length; ++i) {
            IERC20(tokensIn[i]).transfer(msg.sender, uint256(int256(amountsIn[i]) + bonus));
        }
    }

    function got() external view returns (address[] memory, uint256[] memory, address[] memory, uint256[] memory) {
        return (outT, outA, inT, inA);
    }
}

/// Interaction targets that misbehave.
contract Hostile {
    error Boom(uint256 code);

    function boom() external pure { revert Boom(42); }
    function burn() external pure { while (true) {} }
    function reenter(ISCaaSDex d) external { d.mtxSettle(new ISCaaSDex.Settlement[](0)); }
}

/// The exchange path (CTR-DEX-20, -21, -23, -03): `TradeOrder`s executed against AMM routes at a floor, the surplus to
/// the signers, conservation over every token; what an interaction may call; listed targets; allowances reset.
contract DexExchangeTest is Test {
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant BOB_PK = 0xB0B;
    uint256 constant CAROL_PK = 0xCA401;
    uint256 constant DAVE_PK = 0xDA7E;
    address alice = vm.addr(ALICE_PK);
    address bob = vm.addr(BOB_PK);
    address carol = vm.addr(CAROL_PK);
    address dave = vm.addr(DAVE_PK);
    address admin = address(0xAD);
    address treasury = address(0x7EA5);
    address relayer = address(0xBEEF);

    OpenFactory f;
    SCaaSDex dex;
    address puller;
    NormalToken a;  // SCaaS: Alice 800 k, Carol 100 k, the router 100 k
    NormalToken b;  // SCaaS: Bob 500 k, the router 500 k
    MockERC20 usdc;       // outside: Dave 1e6 (approved to the puller), the router 1e6
    MockERC20 c;          // an intermediate hop token, never listed
    MockRouter router;

    function setUp() public {
        f = new OpenFactory(address(this), UID_);
        f.registerImplementation(IOpenFactory.TokenKind.NORMAL, 1,
            address(new NormalToken(address(f), address(0), UID_, false)));
        f.registerDexImplementation(1, address(new SCaaSDex(address(f), UID_, address(0))));
        a = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1,
            normalInit("A", "A", 0, 1e6, alice, address(0)), "a"));
        b = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1,
            normalInit("B", "B", 0, 1e6, bob, address(0)), "b"));
        dex = SCaaSDex(f.createDex(1, ISCaaSDex.DexConfig(admin, 200_000, treasury, false), "dex"));
        puller = dex.puller();
        usdc = new MockERC20("USD Coin", "USDC", 6);
        c = new MockERC20("Hop", "C", 18);
        router = new MockRouter();
        usdc.mint(dave, 1e6);
        usdc.mint(address(router), 1e6);
        c.mint(address(router), 1e6);
        vm.prank(dave);
        usdc.approve(puller, type(uint256).max);
        vm.startPrank(alice);
        a.transfer(carol, 100_000);
        a.transfer(address(router), 100_000);
        vm.stopPrank();
        vm.prank(bob);
        b.transfer(address(router), 500_000);
        vm.startPrank(admin);
        dex.setMarket(address(a), address(b), true);
        dex.setMarket(address(usdc), address(b), true);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ helpers

    function _order(address from, address receiveToken, uint256 amount, uint256 receiveAmount, uint256 fee)
        internal view returns (ITradeToken.TradeOrder memory o)
    {
        o.from = from;
        o.receiveToken = receiveToken;
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.fee = fee;
        o.dex = address(dex);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    /// Signed on the token for a SCaaS sell token, as a `DexOrder` otherwise (the DEX's listing decides).
    function _leg(uint256 pk, address sellToken, ITradeToken.TradeOrder memory o, uint256 sellFill, uint256 floor)
        internal view returns (ISCaaSDex.ExchangeLeg memory)
    {
        bytes32 d = dex.tokenKind(sellToken) == 1
            ? ITradeToken(sellToken).tradeOrderDigest(o) : dex.dexOrderDigest(sellToken, o);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return ISCaaSDex.ExchangeLeg(sellToken, o, abi.encodePacked(r, s, v), sellFill, floor);
    }

    function _plan(ISCaaSDex.ExchangeLeg memory l0) internal pure returns (ISCaaSDex.ExchangePlan memory p) {
        p.ref = "x";
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        p.legs[0] = l0;
    }

    function _plan2(ISCaaSDex.ExchangeLeg memory l0, ISCaaSDex.ExchangeLeg memory l1)
        internal pure returns (ISCaaSDex.ExchangePlan memory p)
    {
        p.ref = "x";
        p.legs = new ISCaaSDex.ExchangeLeg[](2);
        p.legs[0] = l0;
        p.legs[1] = l1;
    }

    /// Alice sells 1000 A for at least 1900 B (fee 0.3 %), floor 1900.
    function _alice() internal view returns (ISCaaSDex.ExchangeLeg memory) {
        return _leg(ALICE_PK, address(a), _order(alice, address(b), 1000, 1900, 3_000), 1000, 1900);
    }

    /// Alice as above; Carol sells 1000 of 1999 A at 3597 B (limit ceil(1799.4) = 1800, fee 0.1 %), floor 1800.
    function _twoLegs() internal view returns (ISCaaSDex.ExchangePlan memory) {
        return _plan2(_alice(), _leg(CAROL_PK, address(a), _order(carol, address(b), 1999, 3597, 1_000), 1000, 1800));
    }

    function _ix(address target, bytes memory data) internal pure returns (ISCaaSDex.Interaction[] memory xs) {
        xs = new ISCaaSDex.Interaction[](1);
        xs[0] = ISCaaSDex.Interaction(target, data);
    }

    /// `approve(router, amountIn)` on `tIn`, then `router.swap(tIn, tOut, amountIn, amountOut, dex)`.
    function _swap(address tIn, address tOut, uint256 amountIn, uint256 amountOut)
        internal view returns (ISCaaSDex.Interaction[] memory xs)
    {
        xs = _cat(_ix(tIn, abi.encodeCall(IERC20.approve, (address(router), amountIn))),
            _ix(address(router), abi.encodeCall(MockRouter.swap, (tIn, tOut, amountIn, amountOut, address(dex)))));
    }

    function _cat(ISCaaSDex.Interaction[] memory x, ISCaaSDex.Interaction[] memory y)
        internal pure returns (ISCaaSDex.Interaction[] memory z)
    {
        z = new ISCaaSDex.Interaction[](x.length + y.length);
        for (uint256 i; i < x.length; ++i) z[i] = x[i];
        for (uint256 i; i < y.length; ++i) z[x.length + i] = y[i];
    }

    function _exchange(ISCaaSDex.ExchangePlan memory p, ISCaaSDex.Interaction[] memory xs) internal {
        vm.prank(relayer);
        dex.mtxExchange(p, xs);
    }

    function _expectExchange(ISCaaSDex.ExchangePlan memory p, ISCaaSDex.Interaction[] memory xs, bytes memory err)
        internal
    {
        vm.prank(relayer);
        vm.expectRevert(err);
        dex.mtxExchange(p, xs);
    }

    function _err(bytes4 sel, address x) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, x);
    }

    function _executor() internal returns (MockExecutor e) {
        e = new MockExecutor();
        vm.prank(bob);
        b.transfer(address(e), 100_000);
    }

    /// The `ExchangeLegSettled` fields after the indexed ones, of the `i`-th such event.
    function _legEvent(Vm.Log[] memory logs, uint256 i) internal pure returns (bytes32 h, uint256[7] memory v) {
        for (uint256 k; k < logs.length; ++k) {
            if (logs[k].topics[0] != ISCaaSDex.ExchangeLegSettled.selector) continue;
            if (i != 0) {
                --i;
                continue;
            }
            address to;
            (to, v[1], v[2], v[3], v[4], v[5], v[6]) =
                abi.decode(logs[k].data, (address, uint256, uint256, uint256, uint256, uint256, uint256));
            v[0] = uint256(uint160(to));
            return (logs[k].topics[2], v);
        }
        revert("no such event");
    }

    // ------------------------------------------------------------------ path (a): routes, surplus, conservation

    /// Two legs, one router swap of 2000 A for 3800 B: floors 3700, surplus 100 split by floor (51, and 49 for the last
    /// leg with the remainder), fees on the floors only, the DEX left with nothing.
    function test_exchange_twoLegs_floorsPlusSurplus_feesOnTheFloor() public {
        ISCaaSDex.ExchangePlan memory p = _twoLegs();
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 2000, 3800);
        bytes32 ha = a.tradeOrderDigest(p.legs[0].o);
        bytes32 hc = a.tradeOrderDigest(p.legs[1].o);
        vm.recordLogs();
        _exchange(p, xs);
        assertEq(b.balanceOf(alice), 1900 - 6 + 51);
        assertEq(b.balanceOf(carol), 1800 - 2 + 49);
        assertEq(b.balanceOf(relayer), 1); // floor(6 · 20 %) + floor(2 · 20 %)
        assertEq(b.balanceOf(treasury), 7);
        assertEq(a.balanceOf(alice), 800_000 - 1000);
        assertEq(a.balanceOf(carol), 100_000 - 1000);
        assertEq(a.balanceOf(address(dex)), 0);
        assertEq(b.balanceOf(address(dex)), 0);
        assertEq(a.pulled(ha), 1000);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (bytes32 h, uint256[7] memory v) = _legEvent(logs, 0);
        assertEq(h, ha);
        assertEq(abi.encode(v), abi.encode([uint256(uint160(alice)), 1000, 1900, 51, 6, 0, 1900]));
        (h, v) = _legEvent(logs, 1);
        assertEq(h, hc);
        assertEq(abi.encode(v), abi.encode([uint256(uint160(carol)), 1000, 1800, 49, 2, 0, 1800]));
    }

    /// A cycle X→X (`receiveToken` = the sell token, accepted by the token): 1000 A → 2000 B → 1050 A, floor 1010, B a
    /// declared intermediate token back at its snapshot.
    function test_exchange_profitableCycle_xToX() public {
        ITradeToken.TradeOrder memory o = _order(alice, address(a), 1000, 1010, 0);
        ISCaaSDex.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(a), o, 1000, 1010));
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(b);
        ISCaaSDex.Interaction[] memory xs =
            _cat(_swap(address(a), address(b), 1000, 2000), _swap(address(b), address(a), 2000, 1050));
        _exchange(p, xs);
        assertEq(a.balanceOf(alice), 800_000 + 50);
        assertEq(a.balanceOf(address(dex)), 0);
        assertEq(b.balanceOf(address(dex)), 0);
    }

    /// Multi-hop through two v2-style pairs, A → C → B, the hop token never touching the DEX.
    function test_exchange_multiHopThroughPairs() public {
        MockPair p1 = new MockPair(address(a), address(c), 2, 1);
        MockPair p2 = new MockPair(address(c), address(b), 1, 1);
        c.mint(address(p1), 1e6);
        vm.prank(bob);
        b.transfer(address(p2), 10_000);
        ISCaaSDex.Interaction[] memory xs = _cat(_ix(address(a), abi.encodeCall(IERC20.transfer, (address(p1), 1000))),
            _cat(_ix(address(p1), abi.encodeCall(MockPair.swap, (address(p2)))),
                _ix(address(p2), abi.encodeCall(MockPair.swap, (address(dex))))));
        _exchange(_plan(_alice()), xs);
        assertEq(b.balanceOf(alice), 1900 - 6 + 100);
        assertEq(a.balanceOf(address(p1)), 1000);
    }

    /// A → C → B through the DEX: C is declared, so a unit of C left behind fails conservation; the exact route passes.
    function test_exchange_intermediateLeftover_reverts() public {
        ISCaaSDex.ExchangePlan memory p = _plan(_alice());
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(c);
        ISCaaSDex.Interaction[] memory first = _swap(address(a), address(c), 1000, 2000);
        _expectExchange(p, _cat(first, _swap(address(c), address(b), 1999, 2000)),
            _err(ISCaaSDex.ConservationBroken.selector, address(c)));
        _exchange(p, _cat(first, _swap(address(c), address(b), 2000, 2000)));
        assertEq(b.balanceOf(alice), 1900 - 6 + 100);
        assertEq(c.balanceOf(address(dex)), 0);
    }

    function test_exchange_soldOnlyLeftover_reverts() public {
        _expectExchange(_plan(_alice()), _swap(address(a), address(b), 999, 2000),
            _err(ISCaaSDex.ConservationBroken.selector, address(a)));
    }

    /// A router that pulls more than the route sells: under an exact approval the token refuses; under an unlimited
    /// one it takes a donation the DEX held, and conservation fails.
    function test_exchange_routerPullingMore_fails() public {
        vm.prank(alice);
        a.transfer(address(dex), 50);
        router.setQuirks(50, 0);
        ISCaaSDex.ExchangePlan memory p = _plan(_alice());
        _expectExchange(p, _swap(address(a), address(b), 1000, 2000), abi.encodeWithSelector(
            IERC20Errors.ERC20InsufficientAllowance.selector, address(router), 1000, 1050));
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 1000, 2000);
        xs[0].data = abi.encodeCall(IERC20.approve, (address(router), type(uint256).max));
        _expectExchange(p, xs, _err(ISCaaSDex.ConservationBroken.selector, address(a)));
    }

    /// The router claims 3800 and pays 3699: below the floors (3700) ⇒ `InsufficientOutput`; at exactly the floors the
    /// plan settles with no surplus.
    function test_exchange_lyingRouter_insufficientOutput_exactFloorsSettle() public {
        ISCaaSDex.ExchangePlan memory p = _twoLegs();
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 2000, 3800);
        router.setQuirks(0, 101);
        _expectExchange(p, xs, _err(ISCaaSDex.InsufficientOutput.selector, address(b)));
        router.setQuirks(0, 100);
        _exchange(p, xs);
        assertEq(b.balanceOf(alice), 1900 - 6);
        assertEq(b.balanceOf(carol), 1800 - 2);
    }

    /// Path B on the exchange path: Carol's 2000 A are pulled whole, 1000 are routed, 1000 refunded.
    function test_exchange_pathBLeg_refundsTheRest() public {
        ITradeToken.TradeOrder memory o = _order(carol, address(b), 2000, 3600, 1_000);
        o.flags = 3; // IOC | ESCROW
        ISCaaSDex.ExchangePlan memory p = _plan(_leg(CAROL_PK, address(a), o, 1000, 1800));
        vm.recordLogs();
        _exchange(p, _swap(address(a), address(b), 1000, 1850));
        assertEq(a.balanceOf(carol), 100_000 - 1000);
        assertEq(b.balanceOf(carol), 1800 - 2 + 50);
        (, uint256[7] memory v) = _legEvent(vm.getRecordedLogs(), 0);
        assertEq(v[5], 1000); // refund
    }

    /// Two signers trade with each other, no interaction at all (a coincidence of wants): each gets the other's excess.
    /// Bob's Path B leg holds 2000 B of refund in the token Alice receives.
    function test_exchange_coincidenceOfWants_noInteractions_refundNotDistributed() public {
        ITradeToken.TradeOrder memory ob = _order(bob, address(a), 4000, 1900, 1_000);
        ob.flags = 3;
        ISCaaSDex.ExchangePlan memory p = _plan2(_alice(), _leg(BOB_PK, address(b), ob, 2000, 950));
        _exchange(p, new ISCaaSDex.Interaction[](0));
        assertEq(b.balanceOf(alice), 1900 - 6 + 100);
        assertEq(a.balanceOf(bob), 950 - 1 + 50);
        assertEq(b.balanceOf(bob), 500_000 - 2000);
        assertEq(b.balanceOf(address(dex)), 0);
        assertEq(a.balanceOf(address(dex)), 0);
    }

    /// An outside leg on the exchange path: a `DexOrder` pulled through the puller.
    function test_exchange_outsideLeg_throughThePuller() public {
        ITradeToken.TradeOrder memory o = _order(dave, address(b), 2000, 3800, 0);
        ISCaaSDex.ExchangePlan memory p = _plan(_leg(DAVE_PK, address(usdc), o, 2000, 3800));
        bytes32 h = dex.dexOrderDigest(address(usdc), o);
        _exchange(p, _swap(address(usdc), address(b), 2000, 3900));
        assertEq(b.balanceOf(dave), 3900);
        assertEq(usdc.balanceOf(dave), 1e6 - 2000);
        assertEq(dex.pulled(h), 2000);
    }

    /// A fee-on-transfer sell token delivers 990 for 1000 pulled: refused at the pull, before any interaction, even
    /// though this route spends only what arrived.
    function test_exchange_feeOnTransferSellToken_failsAtThePull() public {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        fot.mint(dave, 1e6);
        vm.prank(dave);
        fot.approve(puller, type(uint256).max);
        vm.prank(admin);
        dex.setMarket(address(fot), address(b), true);
        ISCaaSDex.ExchangePlan memory p =
            _plan(_leg(DAVE_PK, address(fot), _order(dave, address(b), 1000, 1000, 0), 1000, 1000));
        _expectExchange(p, _swap(address(fot), address(b), 990, 1000),
            _err(ISCaaSDex.ConservationBroken.selector, address(fot)));
    }

    /// Every allowance an `approve` interaction grants (to the router, and to any other spender) is back to 0 after the
    /// plan: nothing the DEX approved outlives the route.
    function test_exchange_approvalsResetToZero() public {
        MockRouter spy = new MockRouter();
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 2000, 3800);
        xs[0].data = abi.encodeCall(IERC20.approve, (address(router), type(uint256).max));
        xs = _cat(_ix(address(a), abi.encodeCall(IERC20.approve, (address(spy), 777))), xs);
        _exchange(_twoLegs(), xs);
        assertEq(a.allowance(address(dex), address(router)), 0);
        assertEq(a.allowance(address(dex), address(spy)), 0);
    }

    // ------------------------------------------------------------------ what an interaction may call (CTR-DEX-23)

    function test_exchange_forbiddenTargets_theDexAndThePuller() public {
        ISCaaSDex.ExchangePlan memory p = _plan(_alice());
        _expectExchange(p, _ix(address(dex), abi.encodeCall(ISCaaSDex.setListedOnly, (true))),
            _err(ISCaaSDex.ForbiddenTarget.selector, address(dex)));
        _expectExchange(p, _ix(puller, abi.encodeCall(DexPuller.pull, (address(usdc), dave, 1))),
            _err(ISCaaSDex.ForbiddenTarget.selector, puller));
    }

    /// Without the selector block, this interaction pulls Bob's resting order (it names this DEX) with an invented
    /// `receiveFill` and the plan pays his 1000 B to Alice as surplus; conservation would balance.
    function test_exchange_forbiddenSelector_mtxTradeOfARestingOrder_andShortData() public {
        ITradeToken.TradeOrder memory ob = _order(bob, address(a), 1000, 500, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB_PK, b.tradeOrderDigest(ob));
        bytes memory steal = abi.encodeCall(ITradeToken.mtxTrade,
            (ob, abi.encodePacked(r, s, v), ITradeToken.TradeFill(1000, 1e9, 0, relayer)));
        ISCaaSDex.ExchangePlan memory p = _plan(_alice());
        ISCaaSDex.Interaction[] memory route = _swap(address(a), address(b), 1000, 2000);
        _expectExchange(p, _cat(_ix(address(b), steal), route), abi.encodeWithSelector(
            ISCaaSDex.ForbiddenSelector.selector, address(b), ITradeToken.mtxTrade.selector));
        _expectExchange(p, _cat(_ix(address(router), ""), route),
            abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(router), bytes4(0)));
        _expectExchange(p, _cat(_ix(address(router), hex"abcdef"), route),
            abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(router), bytes4(0xabcdef00)));
    }

    /// The DEX holds no user allowance (holders approve the puller): `transferFrom(victim, …)` from an interaction fails.
    function test_exchange_transferFromAVictim_fails() public {
        ISCaaSDex.Interaction[] memory xs = _cat(
            _ix(address(usdc), abi.encodeCall(IERC20.transferFrom, (dave, address(0xBAD), 100))),
            _swap(address(a), address(b), 1000, 2000));
        _expectExchange(_plan(_alice()), xs,
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, address(dex), 0, 100));
    }

    function test_exchange_reenteringTarget_isRefused() public {
        Hostile h = new Hostile();
        ISCaaSDex.Interaction[] memory xs =
            _cat(_ix(address(h), abi.encodeCall(Hostile.reenter, (ISCaaSDex(address(dex))))),
                _swap(address(a), address(b), 1000, 2000));
        _expectExchange(_plan(_alice()), xs,
            abi.encodeWithSelector(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector));
    }

    /// A failing interaction reverts the plan with its own data; a gas-burning one fails only this call.
    function test_exchange_revertingAndGasBurningTargets() public {
        Hostile h = new Hostile();
        ISCaaSDex.ExchangePlan memory p = _plan(_alice());
        _expectExchange(p, _ix(address(h), abi.encodeCall(Hostile.boom, ())),
            abi.encodeWithSelector(Hostile.Boom.selector, 42));
        ISCaaSDex.Interaction[] memory xs = _ix(address(h), abi.encodeCall(Hostile.burn, ()));
        vm.prank(relayer);
        vm.expectRevert();
        dex.mtxExchange{gas: 1_000_000}(p, xs);
    }

    // ------------------------------------------------------------------ listed targets: LISTED_POOLS × listed-only

    /// Four combinations on both entry points: an unlisted target or executor is refused iff a leg sets `LISTED_POOLS`
    /// or the admin's mode is on; once listed (the token's `approve` is an interaction too) the plan settles.
    function test_exchange_listedPoolsTimesListedOnly_bothEntryPoints() public {
        for (uint256 k; k < 8; ++k) {
            uint256 id = vm.snapshotState();
            bool flag = k & 1 != 0;
            bool mode = k & 2 != 0;
            bool via = k & 4 != 0;
            if (mode) {
                vm.prank(admin);
                dex.setListedOnly(true);
            }
            ITradeToken.TradeOrder memory o = _order(alice, address(b), 1000, 1900, 0);
            if (flag) o.flags = 4;
            ISCaaSDex.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(a), o, 1000, 1900));
            if (via) _listedVia(p, flag || mode);
            else _listedDirect(p, flag || mode);
            assertEq(b.balanceOf(alice), 2000);
            vm.revertToState(id);
        }
    }

    function _listedDirect(ISCaaSDex.ExchangePlan memory p, bool needsListing) internal {
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 1000, 2000);
        if (needsListing) {
            _expectExchange(p, xs, _err(ISCaaSDex.TargetNotListed.selector, address(a)));
            vm.prank(admin);
            dex.setExchangeTarget(address(a), true);
            _expectExchange(p, xs, _err(ISCaaSDex.TargetNotListed.selector, address(router)));
            vm.prank(admin);
            dex.setExchangeTarget(address(router), true);
        }
        _exchange(p, xs);
    }

    function _listedVia(ISCaaSDex.ExchangePlan memory p, bool needsListing) internal {
        MockExecutor e = _executor();
        bytes memory data = abi.encode(int256(100));
        if (needsListing) {
            vm.prank(relayer);
            vm.expectRevert(_err(ISCaaSDex.TargetNotListed.selector, address(e)));
            dex.mtxExchangeVia(p, address(e), data);
            vm.prank(admin);
            dex.setExchangeTarget(address(e), true);
        }
        vm.prank(relayer);
        dex.mtxExchangeVia(p, address(e), data);
    }

    // ------------------------------------------------------------------ plan checks

    /// Known = a side of a listed market (counted per listed market, so a repeated listing is one): an unlisted token,
    /// or one whose last market was delisted, is refused on either side of a leg.
    function test_exchange_tokenNotKnown() public {
        ISCaaSDex.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(c), _order(alice, address(b), 1000, 1900, 0),
            1000, 1900));
        _expectExchange(p, new ISCaaSDex.Interaction[](0), _err(ISCaaSDex.TokenNotKnown.selector, address(c)));
        p = _plan(_leg(ALICE_PK, address(a), _order(alice, address(c), 1000, 1900, 0), 1000, 1900));
        _expectExchange(p, new ISCaaSDex.Interaction[](0), _err(ISCaaSDex.TokenNotKnown.selector, address(c)));
        vm.startPrank(admin);
        dex.setMarket(address(a), address(b), true); // already listed: no second count
        dex.setMarket(address(a), address(b), false);
        vm.stopPrank();
        assertFalse(dex.tokenKnown(address(a)));
        assertTrue(dex.tokenKnown(address(b))); // still a side of USDC/B
        assertEq(dex.tokenKind(address(a)), 1); // the kind stays recorded
        _expectExchange(_plan(_alice()), new ISCaaSDex.Interaction[](0),
            _err(ISCaaSDex.TokenNotKnown.selector, address(a)));
        vm.prank(admin);
        dex.setMarket(address(a), address(b), true);
        assertTrue(dex.tokenKnown(address(a)));
    }

    function test_exchange_distinctSigners_noLegs_relayer_priceLimit() public {
        ISCaaSDex.ExchangeLeg memory l2 = _alice();
        l2.o.nonce = 2;
        l2 = _leg(ALICE_PK, address(a), l2.o, 1000, 1900);
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 2000, 3800);
        _expectExchange(_plan2(_alice(), l2), xs, _err(ISCaaSDex.SelfTrade.selector, alice));
        _expectExchange(ISCaaSDex.ExchangePlan("x", new ISCaaSDex.ExchangeLeg[](0), new address[](0)),
            new ISCaaSDex.Interaction[](0), abi.encodeWithSelector(ISCaaSDex.NoLegs.selector));
        ITradeToken.TradeOrder memory o = _order(alice, address(b), 1000, 1900, 0);
        o.relayer = address(0x5EED);
        ISCaaSDex.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(a), o, 1000, 1900));
        _expectExchange(p, xs, _err(ISCaaSDex.WrongRelayer.selector, relayer));
        // a floor below the signed limit: the token refuses it (Path A)
        p = _plan(_leg(ALICE_PK, address(a), _order(alice, address(b), 1000, 1900, 0), 1000, 1899));
        bytes32 h = a.tradeOrderDigest(p.legs[0].o);
        _expectExchange(p, _swap(address(a), address(b), 1000, 2000),
            abi.encodeWithSelector(ITradeToken.PriceLimit.selector, h));
    }

    // ------------------------------------------------------------------ path (b): the executor

    /// The executor is handed the sold fills (Path B remainder kept for the refund) and told the floors; it pays 1000
    /// more than the floors, which goes to the signers as on path (a) (513 and 487) and carries no fee.
    function test_exchangeVia_executorPaysMore_distributed() public {
        ITradeToken.TradeOrder memory oc = _order(carol, address(b), 2000, 3600, 1_000);
        oc.flags = 3;
        ISCaaSDex.ExchangePlan memory p = _plan2(_alice(), _leg(CAROL_PK, address(a), oc, 1000, 1800));
        MockExecutor e = _executor();
        vm.prank(relayer);
        dex.mtxExchangeVia(p, address(e), abi.encode(int256(1000)));
        assertEq(b.balanceOf(alice), 1900 - 6 + 513);
        assertEq(b.balanceOf(carol), 1800 - 2 + 487);
        assertEq(b.balanceOf(treasury), 7);
        assertEq(a.balanceOf(carol), 100_000 - 1000);
        assertEq(a.balanceOf(address(e)), 2000);
        (address[] memory to, uint256[] memory ao, address[] memory ti, uint256[] memory ai) = e.got();
        assertEq(to.length, 1);
        assertEq(to[0], address(a));
        assertEq(ao[0], 2000);
        assertEq(ti.length, 1);
        assertEq(ti[0], address(b));
        assertEq(ai[0], 3700);
    }

    function test_exchangeVia_executorPaysLess_reverts() public {
        ISCaaSDex.ExchangePlan memory p = _twoLegs();
        MockExecutor e = _executor();
        vm.prank(relayer);
        vm.expectRevert(_err(ISCaaSDex.InsufficientOutput.selector, address(b)));
        dex.mtxExchangeVia(p, address(e), abi.encode(int256(-1)));
    }

    /// An executor that re-enters the DEX, calls `mtxTrade` of a resting order or calls the puller fails.
    function test_exchangeVia_hostileExecutor_reenterTradePull_fail() public {
        ISCaaSDex.ExchangePlan memory p = _plan(_alice());
        MockExecutor e = _executor();
        bytes memory data = abi.encode(int256(0));
        ITradeToken.TradeOrder memory ob = _order(bob, address(a), 1000, 500, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB_PK, b.tradeOrderDigest(ob));
        bytes[3] memory calls = [
            abi.encodeCall(ISCaaSDex.mtxSettle, (new ISCaaSDex.Settlement[](0))),
            abi.encodeCall(ITradeToken.mtxTrade, (ob, abi.encodePacked(r, s, v), ITradeToken.TradeFill(1000, 1e9, 0, relayer))),
            abi.encodeCall(DexPuller.pull, (address(usdc), dave, 1))
        ];
        address[3] memory targets = [address(dex), address(b), puller];
        bytes[3] memory errs = [
            abi.encodeWithSelector(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector),
            abi.encodeWithSelector(ITradeToken.NotDex.selector, address(e)),
            abi.encodeWithSelector(DexPuller.NotDex.selector, address(e))
        ];
        for (uint256 i; i < 3; ++i) {
            e.setCall(targets[i], calls[i]);
            vm.prank(relayer);
            vm.expectRevert(errs[i]);
            dex.mtxExchangeVia(p, address(e), data);
        }
    }

    // ------------------------------------------------------------------ admin (CTR-DEX-03)

    function test_setExchangeTarget_setListedOnly_onlyAdmin() public {
        vm.expectRevert(_err(ISCaaSDex.NotAdmin.selector, address(this)));
        dex.setExchangeTarget(address(router), true);
        vm.expectRevert(_err(ISCaaSDex.NotAdmin.selector, address(this)));
        dex.setListedOnly(true);
        vm.startPrank(admin);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeTargetSet(address(router), true);
        dex.setExchangeTarget(address(router), true);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ListedOnlySet(true);
        dex.setListedOnly(true);
        vm.stopPrank();
        assertTrue(dex.exchangeTarget(address(router)));
        assertTrue(dex.listedOnly());
    }
}
```

- [ ] **Step 4: Run** (each through `scripts/capped`, one at a time):
  - `forge test --match-path test/v2/DexExchange.t.sol` → 24 passed; `forge test --match-path "test/v2/Dex*.t.sol"` → 82
    passed (Dex 36, DexOutside 22, DexExchange 24).
  - `forge test` → **937 passed** (913 + 24), 0 failed.
  - Size gate: `forge build src --sizes --json > /tmp/sizes.json || true; python3 ../../scripts/size_gate.py
    /tmp/sizes.json size-baseline.json` → `0 error(s)`; `SCaaSDex` 21,761 B.
  - e2e: `forge build` (full), then in `scaas-node`: `cargo test --test e2e -- --ignored --test-threads=1` → 4 passed;
    `cargo test --test e2e_hedera -- --ignored` → 1 passed (a fresh worktree may reuse the main checkout's build cache
    with `CARGO_TARGET_DIR=/home/ha/work/ainative/scaas/scaas-node/target`).
  - **Mutation probe** (not committed; save as a scratch file and run with `scripts/capped python3 <file>`): every mutant
    must be `KILLED`. Validated: 34/34 killed. Also rerun the P2b-2 probe (its Task 1 Step 8) with the worktree path and
    the four patterns the refactor renamed (`l.o`/`l.sellToken`/`l.sig` → `o`/`sellToken`/`sig` in M10, M11, M12, M20):
    validated 20/20 killed.

```python
import subprocess, sys
W='/home/ha/work/ainative/scaas/.claude/worktrees/p2c/smartcontracts/evm'
D=W+'/src/dex/SCaaSDex.sol'
muts=[
 ('X1 no NoLegs', D, 'if (n == 0) revert NoLegs();', ''),
 ('X2 sell token known unchecked', D, 'if (s.listings[l.sellToken] == 0) revert TokenNotKnown(l.sellToken);', ''),
 ('X3 receive token known unchecked', D, 'if (s.listings[rt] == 0) revert TokenNotKnown(rt);', ''),
 ('X4 no SelfTrade', D, 'for (uint256 j; j < i; ++j) if (p.legs[j].o.from == l.o.from) revert SelfTrade(l.o.from);', ''),
 ('X5 LISTED_POOLS ignored', D, 'if (l.o.flags & LISTED_POOLS != 0) onlyListed = true;', ''),
 ('X6 listedOnly ignored', D, 'onlyListed = s.listedOnly;', ''),
 ('X7 executor listing unchecked', D, 'if (onlyListed && !_s().exchangeTarget[executor]) revert TargetNotListed(executor);', ''),
 ('X8 no pull check', D, 'if (IERC20(x.token).balanceOf(address(this)) != x.snap + x.sold + x.refunds) {\n                revert ConservationBroken(x.token);\n            }', ''),
 ('X9 DEX target allowed', D, 'if (x.target == address(this) || x.target == s.puller)', 'if (x.target == s.puller)'),
 ('X10 puller target allowed', D, 'if (x.target == address(this) || x.target == s.puller)', 'if (x.target == address(this))'),
 ('X11 mtxTrade selector allowed', D, 'if (x.data.length < 4 || sel == ITradeToken.mtxTrade.selector)', 'if (x.data.length < 4)'),
 ('X12 short data allowed', D, 'if (x.data.length < 4 || sel == ITradeToken.mtxTrade.selector)', 'if (sel == ITradeToken.mtxTrade.selector)'),
 ('X13 interaction listing unchecked', D, 'if (onlyListed && !s.exchangeTarget[x.target]) revert TargetNotListed(x.target);', ''),
 ('X14 failure not bubbled', D, 'if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }', 'ok; ret;'),
 ('X15 no approval reset', D, 'for (uint256 i; i < na; ++i) IERC20(approvedToken[i]).forceApprove(approvedSpender[i], 0);', ''),
 ('X16 reset the target, not the spender', D, '(approvedSpender[na++],) = abi.decode(xs[i].data[4:], (address, uint256));', 'approvedSpender[na++] = xs[i].target == address(0) ? address(0) : 0x0000000000000000000000000000000000000001;'),
 ('X17 InsufficientOutput <=', D, 'if (bal < keep) revert InsufficientOutput(x.token);', 'if (bal <= keep) revert InsufficientOutput(x.token);'),
 ('X18 no InsufficientOutput', D, 'if (bal < keep) revert InsufficientOutput(x.token);', 'if (bal < keep) return;'),
 ('X19 excess ignores refunds', D, 'uint256 keep = x.snap + x.refunds + x.floors;', 'uint256 keep = x.snap + x.floors;'),
 ('X20 no final conservation', D, 'if (IERC20(t[i].token).balanceOf(address(this)) != t[i].snap) revert ConservationBroken(t[i].token);', ''),
 ('X21 no remainder to the last', D, 'uint256 share = x.floorsLeft == c[i].recv ? x.excess - x.paid : Math.mulDiv(x.excess, c[i].recv, x.floors);', 'uint256 share = Math.mulDiv(x.excess, c[i].recv, x.floors);'),
 ('X22 surplus all to the first', D, 'uint256 share = x.floorsLeft == c[i].recv ? x.excess - x.paid : Math.mulDiv(x.excess, c[i].recv, x.floors);', 'uint256 share = x.excess - x.paid;'),
 ('X23 surplus not paid', D, '_send(o.receiveToken, to, c.recv - c.fee + surplus);', '_send(o.receiveToken, to, c.recv - c.fee);'),
 ('X24 amountsOut include refunds', D, '(tokensOut[nOut], amountsOut[nOut++]) = (t[i].token, t[i].sold);', '(tokensOut[nOut], amountsOut[nOut++]) = (t[i].token, t[i].sold + t[i].refunds);'),
 ('X25 amountsIn wrong', D, '(tokensIn[nIn], amountsIn[nIn++]) = (t[i].token, t[i].floors);', '(tokensIn[nIn], amountsIn[nIn++]) = (t[i].token, t[i].floors - 1);'),
 ('X26 no hand-out to executor', D, 'for (uint256 i; i < tokensOut.length; ++i) _send(tokensOut[i], executor, amountsOut[i]);', ''),
 ('X27 listings double-count', D, 'if (s.listed[k] != listed) {', 'if (true) {'),
 ('X28 limitReceive floor', D, 'uint256 limit = Math.mulDiv(c.sold, l.o.receiveAmount, l.o.amount, Math.Rounding.Ceil);', 'uint256 limit = Math.mulDiv(c.sold, l.o.receiveAmount, l.o.amount);'),
 ('X29 fee on floor plus surplus', D, '(address to,,) = _payLeg(l.sellToken, l.o, c, surplus, msg.sender);', 'c.fee = Math.mulDiv(c.recv + surplus, l.o.fee, PPM, Math.Rounding.Ceil);\n        (address to,,) = _payLeg(l.sellToken, l.o, c, surplus, msg.sender);'),
 ('X30 event receivedFloor net', D, 'emit ExchangeLegSettled(ref, c.h, from, to, c.sold, c.recv, surplus, c.fee, c.refund, limit);', 'emit ExchangeLegSettled(ref, c.h, from, to, c.sold, c.recv - c.fee, surplus, c.fee, c.refund, limit);'),
 ('X31 nonReentrant off mtxExchange', D, 'function mtxExchange(ExchangePlan calldata p, Interaction[] calldata xs) external nonReentrant {', 'function mtxExchange(ExchangePlan calldata p, Interaction[] calldata xs) external {'),
 ('X32 nonReentrant off mtxExchangeVia', D, 'function mtxExchangeVia(ExchangePlan calldata p, address executor, bytes calldata data) external nonReentrant {', 'function mtxExchangeVia(ExchangePlan calldata p, address executor, bytes calldata data) external {'),
 ('X33 setListedOnly unguarded', D, '_onlyAdmin().listedOnly = on;', '_s().listedOnly = on;'),
 ('X34 setExchangeTarget unguarded', D, '_onlyAdmin().exchangeTarget[target] = listed;', '_s().exchangeTarget[target] = listed;'),
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
        print(name, status, len(fails), (fails[0][:150] if fails else ('compile' if 'Compiler run failed' in out else '')), flush=True)
    finally:
        open(f,'w').write(src)
```

  | Mutant | Killed by |
  |---|---|
  | X1 no `NoLegs` / X4 no `SelfTrade` | `test_exchange_distinctSigners_noLegs_relayer_priceLimit` |
  | X2 / X3 sell / receive token not checked known | `test_exchange_tokenNotKnown` |
  | X5 `LISTED_POOLS` ignored / X6 mode ignored / X7 executor unlisted / X13 interaction target unlisted | `test_exchange_listedPoolsTimesListedOnly_bothEntryPoints` |
  | X8 no pull check | `test_exchange_feeOnTransferSellToken_failsAtThePull` |
  | X9 / X10 the DEX / the puller allowed as target | `test_exchange_forbiddenTargets_theDexAndThePuller` |
  | X11 `mtxTrade` allowed / X12 short data allowed | `test_exchange_forbiddenSelector_mtxTradeOfARestingOrder_andShortData` |
  | X14 a failed interaction ignored | `test_exchange_reenteringTarget_isRefused`, `test_exchange_revertingAndGasBurningTargets`, routers that revert |
  | X15 no allowance reset / X16 the wrong spender reset | `test_exchange_approvalsResetToZero` (X16 also breaks every route) |
  | X17 `InsufficientOutput` at `<=` | `test_exchange_lyingRouter_insufficientOutput_exactFloorsSettle` |
  | X18 no `InsufficientOutput` | `test_exchangeVia_executorPaysLess_reverts`, the lying router |
  | X19 excess ignores Path B refunds | `test_exchange_coincidenceOfWants_noInteractions_refundNotDistributed` |
  | X20 no final conservation | `test_exchange_intermediateLeftover_reverts`, `test_exchange_soldOnlyLeftover_reverts` |
  | X21 no remainder to the last / X22 all surplus to the first / X23 surplus not paid | `test_exchangeVia_executorPaysMore_distributed`, `test_exchange_twoLegs_…` |
  | X24 `amountsOut` include refunds / X25 `amountsIn` wrong / X26 nothing handed to the executor | `test_exchangeVia_executorPaysMore_distributed` |
  | X27 listings double-counted | `test_exchange_tokenNotKnown` |
  | X28 `limitReceive` rounded down / X30 `receivedFloor` net | `test_exchange_twoLegs_floorsPlusSurplus_feesOnTheFloor` (event fields) |
  | X29 fee on floor + surplus | `test_exchangeVia_executorPaysMore_distributed` (2405 ≠ 2407) |
  | X31 / X32 `nonReentrant` off `mtxExchange` / `mtxExchangeVia` | `test_exchange_reenteringTarget_isRefused` / `test_exchangeVia_hostileExecutor_reenterTradePull_fail` |
  | X33 / X34 setters without `_onlyAdmin` | `test_setExchangeTarget_setListedOnly_onlyAdmin` |

- [ ] **Step 5: Commit** — `P2c: exchange path on SCaaSDex — mtxExchange, mtxExchangeVia, exchange targets, listed-only, surplus to the signers, allowances reset` + trailer.

---

### Task 2: Docs, TODO, HANDOFF

**Model:** Sonnet, effort medium. Component docs say "controller ruling, pending the owner", never a J-id. `dex.md` net
0 lines (555 → 555: the transitional note joins the CTR-DEX-23 paragraph, §13's closing two lines become one);
`settlement.md` +1.

- [ ] **Step 1: `docs/contracts/dex.md`, `settlement.md`, `README.md`, `docs/assets/settlement-kinds.svg`** — the header
  status (built, P2c); CTR-DEX-20 status **BUILT**; a "Transitional (BUILT, P2c)" note at the end of CTR-DEX-23 (built
  names, J1–J5, J7, J9 as controller rulings; the fork test not built); §13's closing paragraph; §14's forge row names
  `DexExchange.t.sol`; settlement.md's row, §3.6 status and image alt text; the contracts index row; the SVG chip
  (SPECIFIED → BUILT). Apply:

```diff
diff --git a/docs/assets/settlement-kinds.svg b/docs/assets/settlement-kinds.svg
index 6187ede..89d9d58 100644
--- a/docs/assets/settlement-kinds.svg
+++ b/docs/assets/settlement-kinds.svg
@@ -1,6 +1,6 @@
 <svg xmlns="http://www.w3.org/2000/svg" width="960" height="540" viewBox="0 0 960 540" role="img" aria-labelledby="t d">
   <title id="t">Settlement kinds</title>
-  <desc id="d">Twelve settlement kinds grouped by who checks them. The token checks: typed transfer and payment (built, v2 tiers), receiver pays (built on EVM and Hedera), signature wrap (built, P2a), confidential Zether (built, unaudited, dev chains only). Other contracts take part: generic gasless call through the selector allowlist (built), DEX order book (token side built, P2a), exchange against AMMs (specified, P2c), mandate through MandateWallet (built), asset-suite actions (specified, nothing built), tender (specified, nothing built). Elsewhere: gas sponsorship by node policy (specified; SponsorshipPool planned) and the non-EVM families (built as MetaOp v1; target specified).</desc>
+  <desc id="d">Twelve settlement kinds grouped by who checks them. The token checks: typed transfer and payment (built, v2 tiers), receiver pays (built on EVM and Hedera), signature wrap (built, P2a), confidential Zether (built, unaudited, dev chains only). Other contracts take part: generic gasless call through the selector allowlist (built), DEX order book (token side built, P2a), exchange against AMMs (built, P2c), mandate through MandateWallet (built), asset-suite actions (specified, nothing built), tender (specified, nothing built). Elsewhere: gas sponsorship by node policy (specified; SponsorshipPool planned) and the non-EVM families (built as MetaOp v1; target specified).</desc>
   <defs>
     <marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
       <path d="M0 0 L10 5 L0 10 z" fill="#57606a"/>
@@ -60,8 +60,8 @@
   <rect class="card" stroke="#3b82f6" x="344" y="195" width="288" height="76" rx="8"/>
   <text class="b" x="356" y="216">Exchange against AMMs</text>
   <text class="s" x="356" y="238">mtxExchange, mtxExchangeVia</text>
-  <rect x="356" y="248" width="70" height="16" rx="8" fill="#ddf4ff"/><text class="chip" x="391" y="260" text-anchor="middle" fill="#0969da">SPECIFIED</text>
-  <text class="s" x="432" y="260">P2c</text>
+  <rect x="356" y="248" width="42" height="16" rx="8" fill="#dafbe1"/><text class="chip" x="377" y="260" text-anchor="middle" fill="#1a7f37">BUILT</text>
+  <text class="s" x="404" y="260">P2c, SCaaSDex</text>
   <rect class="card" stroke="#3b82f6" x="641" y="195" width="288" height="76" rx="8"/>
   <text class="b" x="653" y="216">Mandate</text>
   <text class="s" x="653" y="238">payUnderMandate, checked by MandateWallet</text>
diff --git a/docs/contracts/README.md b/docs/contracts/README.md
index f52e48e..e02285d 100644
--- a/docs/contracts/README.md
+++ b/docs/contracts/README.md
@@ -11,7 +11,7 @@ the rules every one of them shares. Status tags (**BUILT**, **SPECIFIED**, **PLA
 | [accounts.md](accounts.md) | the three account forms; Universal Account (ids, kinds, registry, verifiers, credentials, migration); passkeys on chain; the optional `SmartKeyAccount` smart account and its factory, guardians | UA **SPECIFIED**; `SmartKeyAccount` **BUILT** |
 | [metatx.md](metatx.md) | the one base `ERC20MetaTx`: `MetaTransaction` struct, typehash, `mode`, 2D nonces, `mtxExecute` (generic self-call, ticket, selector allowlist, fee classes), `mtx` names, pay references and the pay-once horizon, receiver-pays | **SPECIFIED** (built as the v1/v2 lines) |
 | [token-wrappers.md](token-wrappers.md) | three token tiers, conversion rates, multi-underlying wrappers, signature wrap, the one `OpenFactory`, allowance rule | tiers **BUILT** (EVM, Hedera); one base and factory **SPECIFIED** |
-| [dex.md](dex.md) | `SCaaSDex` with token-verified `TradeOrder`s, outside-token legs through the `DexPuller`, the exchange path against AMMs (`mtxExchange`), managed-market venue contract | **SPECIFIED** (built: `SCaaSDex` with SCaaS legs, P2b-1; `SCaaSDexV1` with DEX-signed orders over allowances) |
+| [dex.md](dex.md) | `SCaaSDex` with token-verified `TradeOrder`s, outside-token legs through the `DexPuller`, the exchange path against AMMs (`mtxExchange`), managed-market venue contract | **SPECIFIED** (built: `SCaaSDex`, P2b-1, P2b-2, P2c; `SCaaSDexV1` with DEX-signed orders over allowances) |
 | [tender.md](tender.md) | `SealedBidTender` | **SPECIFIED** |
 | [asset-suite.md](asset-suite.md) | regulated module, vesting, distributions, corporate actions, templates | **SPECIFIED** |
 | [zether.md](zether.md) | classical Zether, byte-exact; limits; decryption bound | **BUILT, UNAUDITED** (dev chains) |
diff --git a/docs/contracts/dex.md b/docs/contracts/dex.md
index 771dc18..0feafb1 100644
--- a/docs/contracts/dex.md
+++ b/docs/contracts/dex.md
@@ -5,7 +5,7 @@ and whose settlement contract settles signed orders on chain. Users never pay ga
 messages that a relayer submits, and a SCaaS token needs **no allowance** to trade — its order is verified by the token
 itself, which moves funds only into the DEX the signer named. Status: the target of this file (token-verified
 `TradeOrder`s, `SCaaSDex.mtxSettle`, outside-token legs, one signed fee rate, the exchange path against AMMs
-`mtxExchange`, the `DexPuller`) **SPECIFIED**, **BUILT** except the exchange path (`SCaaSDex`, P2b-1, P2b-2);
+`mtxExchange`, the `DexPuller`) **SPECIFIED**, **BUILT** (`SCaaSDex`, P2b-1, P2b-2, P2c);
 `SCaaSDexV1` (DEX-signed orders over allowances, the node's DEX until P5) and the legacy `MetaTxDex` are **BUILT**
 ([Transitional](#transitional-built)); non-EVM settlement programs **BUILT** with the fixes below **SPECIFIED**.
 
@@ -368,7 +368,7 @@ on the floor ([CTR-DEX-11](#CTR-DEX-11)); (2) **snapshot** the DEX's balance of
 snapshotted token (`ConservationBroken`) and per leg `ExchangeLegSettled(ref, orderHash, from, destination, sold,
 receivedFloor, surplus, dexFee, refund, limitReceive)`, `limitReceive = ceil(sellFill · receiveAmount / amount)`, so a
 client checks what the signer got against what it signed without trusting the submitter. Not to be confused with
-`ExchangeOffer.exchange` ([CTR-AS-13](asset-suite.md#CTR-AS-13)), another contract. EVM only. Status **SPECIFIED**.
+`ExchangeOffer.exchange` ([CTR-AS-13](asset-suite.md#CTR-AS-13)), another contract. EVM only. Status **BUILT** (P2c; Transitional after [CTR-DEX-23](#CTR-DEX-23)).
 
 <a id="CTR-DEX-21"></a>**CTR-DEX-21** — **The surplus goes to the signers, on chain** (owner). After step 4, for each
 receive token `T`: `excess_T = balance_T − snapshot_T − Σ receiveFill(legs receiving T) − Σ refund(Path B legs
@@ -396,6 +396,7 @@ when any leg sets `LISTED_POOLS` **or** the admin's listed-only mode is on, `exc
 (owner). Interactions may `approve` routers (both are contracts, [CTR-TOK-01](token-wrappers.md#CTR-TOK-01)); a
 residual allowance moves nothing, because between calls the DEX holds no user funds. Grief (a target that reverts or
 burns gas) fails only its own plan.
+**Transitional (BUILT, P2c).** `SCaaSDex`: `mtxExchange`, `mtxExchangeVia`, `IExchangeExecutor`, `setExchangeTarget`, `setListedOnly`, `exchangeTarget`, `tokenKnown` (a side of at least one listed market, counted per market; a delisted token is unknown, its recorded kind stays); `NoLegs`, `TokenNotKnown`, `ForbiddenTarget`, `ForbiddenSelector(target, selector)` (selector 0 for `data` under 4 bytes), `TargetNotListed`, `InsufficientOutput`. Path A bounds are checked at the pull by the token (by `TradeLib` on the DEX for an outside leg), Path B bounds by the DEX, as in `mtxSettle`; after the pulls each sell token's balance must have risen by exactly what was pulled (`ConservationBroken`: a fee-on-transfer or rebasing sell token fails before any interaction); a sold-only or intermediate leftover fails the final conservation check; every allowance an `approve` interaction granted is set back to 0 after the last interaction; under the listing condition a token an interaction calls (`approve`, `transfer`) is a target and must be listed too; `receivedFloor` is the gross floor (controller ruling, pending the owner). Not built: the fork test with real Uniswap bytecode.
 
 ## 8. The named `dex`
 
@@ -542,14 +543,13 @@ intake fails alone (`MatchFailed`). The node side (home-bound orders only, the f
   to `a.m.from` with `SafeERC20.safeTransfer` and `emit TradeSettled(a.m.from, b.m.from, a.token, b.token, a.m.value, b.m.value)`. Fill-or-kill; the surplus
   `b.m.value > minCounterValue` belongs to the seller of leg A.
 
-`MetaTxDex` stays (built and deployed) until its planned removal (P5, to `legacy/`). The rebuild (`SCaaSDex`, P2b-1, P2b-2) drops its trade and approve ops, renames `settle`/`cancel`/`invalidateNonces` to `mtxSettle`/`mtxCancelOrders`/
-`mtxInvalidateNonces`, keeps the DEX-domain `Order` only as `DexOrder`, allowances only to the `DexPuller`, the relayer fee only as its share of the signed DEX fee; P2c: [CTR-DEX-20](#CTR-DEX-20)…[-23](#CTR-DEX-23).
+`MetaTxDex` stays (built and deployed) until its planned removal (P5, to `legacy/`). The rebuild (`SCaaSDex`, P2b-1, P2b-2, P2c) drops its trade and approve ops, renames `settle`/`cancel`/`invalidateNonces` to `mtxSettle`/`mtxCancelOrders`/`mtxInvalidateNonces`, keeps the DEX-domain `Order` only as `DexOrder`, allowances only to the `DexPuller`, the relayer fee only as its share of the signed DEX fee, and adds the exchange path ([CTR-DEX-20](#CTR-DEX-20)…[-23](#CTR-DEX-23)).
 
 ## 14. Conformance
 
 | Layer | Tests |
 |---|---|
-| forge | Path A and Path B, one taker × many makers; `mtxTrade` on a closed, cancelled or IOC-pulled order and with `sellFill = 0` reverts; Path B `sellFill ≠ amount` reverts; `dex` = EOA refused; caller ≠ `dex` refused; every `mtxTrade` error; effective minimum fill for taker and makers incl. the remainder close and `minFill > amount`; FOK via `minFill = amount`; taker fee charged once on the aggregate; split rounding; conservation (unit + invariant: the DEX holds 0 after every handler sequence; for the new DEX the unit tests are built in `test/v2/Dex.t.sol` (P2b-1: settle with two makers, maker rounding, aggregate fee, Path B fee, signed `minFill` and refund, Path A figures seen by the token, isolated failure, arrangement checks, `createDex` and the DEX catalogue, registry, fee split, salted domain) and `test/v2/DexOutside.t.sol` (P2b-2: outside legs through the puller, `DexOrder` digest, `ESCROW` refused, DEX cancels, the ERC-1271 cap by codehash, hostile 1271 signers in settle and cancel batches, the bounded `MatchFailed` reason, a starved check reverting the call, fee-on-transfer, rebasing and no-return tokens), and the invariant suite is open); `DexOrder` legs incl. a fallback-only "token" classified outside and `ESCROW` refused; cancel per token and per DEX (signature, replay, lane cap); ERC-1271 maker under the 400 k cap; a 1271 maker that burns gas or returns a returndata bomb inside a multi-settlement call (the others still settle) and inside a cancel batch; replay of an order on another token, another DEX or another chain fails; salted-domain KATs for `TradeOrder`, `CancelOrder`, `InvalidateNonces` → `test/vectors/trade_kat.json` (built, P2a); `DexOrder` → `test/vectors/dex_kat.json`, which stays the `SCaaSDexV1` `Order` vector the node reads (controller ruling, pending the owner); the fee round-up cases above; exchange path: an interaction calling `mtxTrade` of a resting order, targeting the DEX or the puller, or `transferFrom(victim, …)` (all refused or failing); surplus split over several legs receiving one token, remainder to the last; a sold-only or intermediate leftover reverts; `InsufficientOutput`; a profitable cycle X→X; multi-hop through mock Uniswap v2/v3 and a fork test with real Uniswap bytecode on anvil; `LISTED_POOLS` × `setListedOnly` on both entry points; an executor returning less (revert) or more (distributed), re-entering, calling `mtxTrade` or the puller; `receiveToken == this` on the token; a Path B leg; an outside leg through the puller in `mtxSettle` and `mtxExchange`; a reverting and a gas-burning target; invariant: between calls the DEX holds 0 of every token and residual allowances move nothing |
+| forge | Path A and Path B, one taker × many makers; `mtxTrade` on a closed, cancelled or IOC-pulled order and with `sellFill = 0` reverts; Path B `sellFill ≠ amount` reverts; `dex` = EOA refused; caller ≠ `dex` refused; every `mtxTrade` error; effective minimum fill for taker and makers incl. the remainder close and `minFill > amount`; FOK via `minFill = amount`; taker fee charged once on the aggregate; split rounding; conservation (unit + invariant: the DEX holds 0 after every handler sequence; for the new DEX the unit tests are built in `test/v2/Dex.t.sol` (P2b-1: settle with two makers, maker rounding, aggregate fee, Path B fee, signed `minFill` and refund, Path A figures seen by the token, isolated failure, arrangement checks, `createDex` and the DEX catalogue, registry, fee split, salted domain) and `test/v2/DexOutside.t.sol` (P2b-2: outside legs through the puller, `DexOrder` digest, `ESCROW` refused, DEX cancels, the ERC-1271 cap by codehash, hostile 1271 signers in settle and cancel batches, the bounded `MatchFailed` reason, a starved check reverting the call, fee-on-transfer, rebasing and no-return tokens) and `test/v2/DexExchange.t.sol` (P2c: routes through mock routers, v2-style pairs and executors, cycles, Path B and outside legs, surplus and remainder, leftovers, `InsufficientOutput`, the interaction blocklist, `LISTED_POOLS` × `setListedOnly`, hostile targets and executors, allowances reset, a fee-on-transfer sell token; the Uniswap fork test is open), and the invariant suite is open); `DexOrder` legs incl. a fallback-only "token" classified outside and `ESCROW` refused; cancel per token and per DEX (signature, replay, lane cap); ERC-1271 maker under the 400 k cap; a 1271 maker that burns gas or returns a returndata bomb inside a multi-settlement call (the others still settle) and inside a cancel batch; replay of an order on another token, another DEX or another chain fails; salted-domain KATs for `TradeOrder`, `CancelOrder`, `InvalidateNonces` → `test/vectors/trade_kat.json` (built, P2a); `DexOrder` → `test/vectors/dex_kat.json`, which stays the `SCaaSDexV1` `Order` vector the node reads (controller ruling, pending the owner); the fee round-up cases above; exchange path: an interaction calling `mtxTrade` of a resting order, targeting the DEX or the puller, or `transferFrom(victim, …)` (all refused or failing); surplus split over several legs receiving one token, remainder to the last; a sold-only or intermediate leftover reverts; `InsufficientOutput`; a profitable cycle X→X; multi-hop through mock Uniswap v2/v3 and a fork test with real Uniswap bytecode on anvil; `LISTED_POOLS` × `setListedOnly` on both entry points; an executor returning less (revert) or more (distributed), re-entering, calling `mtxTrade` or the puller; `receiveToken == this` on the token; a Path B leg; an outside leg through the puller in `mtxSettle` and `mtxExchange`; a reverting and a gas-burning target; invariant: between calls the DEX holds 0 of every token and residual allowances move nothing |
 | non-EVM | a third party settling on Cosmos/Soroban/TON fails; `min_nonce` above the cap refused; a dust fill pays fee 1 |
 | e2e (anvil 31950–31959, gateway 18650–18659) | two orders through the gateway → partial match → settle job → balances, no `approve` for SCaaS tokens; cancel ⇒ settle never runs; venue restart ⇒ book intact |
 | managed markets (forge) | one e2e with a regulated equity and an unregulated stablecoin: frozen maker, ineligible taker, ineligible fee recipient, an eligible pair settles |
diff --git a/docs/contracts/settlement.md b/docs/contracts/settlement.md
index 061acb0..686a8ba 100644
--- a/docs/contracts/settlement.md
+++ b/docs/contracts/settlement.md
@@ -6,7 +6,7 @@
 > [docs/README.md](../README.md#status-tags): **BUILT**, **SPECIFIED**, **PLANNED**, and **Transitional (BUILT)** for
 > built code that still differs from the target.
 
-<p align="center"><img src="../assets/settlement-kinds.svg" width="860" alt="Settlement kinds by who checks them. The token: typed transfer and payment (built, v2 tiers), receiver pays (built, EVM and Hedera), signature wrap (built, P2a), confidential Zether (built, unaudited, dev chains only). Another contract takes part: generic gasless call through the selector allowlist (built), DEX order book (token side built, P2a), exchange against AMMs (specified, P2c), mandate through MandateWallet (built), asset-suite action (specified, nothing built), tender (specified, nothing built). Also: gas sponsorship by node policy (specified; SponsorshipPool planned) and the non-EVM families (built as MetaOp v1; target specified)."></p>
+<p align="center"><img src="../assets/settlement-kinds.svg" width="860" alt="Settlement kinds by who checks them. The token: typed transfer and payment (built, v2 tiers), receiver pays (built, EVM and Hedera), signature wrap (built, P2a), confidential Zether (built, unaudited, dev chains only). Another contract takes part: generic gasless call through the selector allowlist (built), DEX order book (token side built, P2a), exchange against AMMs (built, P2c), mandate through MandateWallet (built), asset-suite action (specified, nothing built), tender (specified, nothing built). Also: gas sponsorship by node policy (specified; SponsorshipPool planned) and the non-EVM families (built as MetaOp v1; target specified)."></p>
 
 **Contents**
 
@@ -55,7 +55,7 @@ intent is a booked fact. Every kind below shares these properties:
 | Generic gasless call | `mtxExecute`, `mtxBatch`, `executeMetaTransaction` | subject signs `MetaTransaction`; any relayer | the contract's selector allowlist | per fee class, after the call | tx | **BUILT** | [CTR-MTX-12](metatx.md#CTR-MTX-12), [-19](metatx.md#CTR-MTX-19), [-20](metatx.md#CTR-MTX-20) |
 | Signature wrap | `mtxWrap` | holder signs a `TradeOrder` in the underlying's domain; any relayer | underlying and wrapper | order `fee` to the relayer, out of the minted units | tx | **BUILT** (P2a, `WrappedToken`) | [CTR-TOK-20](token-wrappers.md#CTR-TOK-20) |
 | DEX order book | `SCaaSDex.mtxSettle`, `mtxCancelOrders`, `mtxInvalidateNonces`; token side `mtxTrade` | each party signs a `TradeOrder`; the venue lane | token (Path A) or DEX (Path B, outside legs); DEX conservation | one signed rate, split relayer / treasury by the DEX | tx, then the DEX watcher | token side **BUILT** (P2a); `SCaaSDex` **BUILT** (P2b-1 SCaaS legs, P2b-2 outside legs); `SCaaSDexV1` pair `settle` **BUILT** | [CTR-DEX-13](dex.md#CTR-DEX-13) to [-19](dex.md#CTR-DEX-19), [-22](dex.md#CTR-DEX-22), [-24](dex.md#CTR-DEX-24) |
-| Exchange against AMMs | `mtxExchange`, `mtxExchangeVia` | the same signed orders; the venue lane | token or DEX, DEX conservation | signed rate on the floor; surplus to the signers | tx, then the DEX watcher | **SPECIFIED** (P2c) | [CTR-DEX-20](dex.md#CTR-DEX-20) to [-23](dex.md#CTR-DEX-23) |
+| Exchange against AMMs | `mtxExchange`, `mtxExchangeVia` | the same signed orders; the venue lane | token or DEX, DEX conservation | signed rate on the floor; surplus to the signers | tx, then the DEX watcher | **BUILT** (P2c, `SCaaSDex`) | [CTR-DEX-20](dex.md#CTR-DEX-20) to [-23](dex.md#CTR-DEX-23) |
 | Confidential (Zether) | target `zetherTransfer*`, `zetherShield`, `zetherUnshield`, roll-over; built `transferConfidential*`, `fund`, `burn` | owner signs the call, the proof binds the envelope; any relayer | token verifier | outer NONE / FIXED (never PERCENT), inner `confidentialFee` | tx (dev chains) | **BUILT, UNAUDITED** (dev chains only); target kinds P3 **SPECIFIED**; PQZ **SPECIFIED** | [zether.md](zether.md), [pq-zero-knowledge.md](pq-zero-knowledge.md) |
 | Mandate | `payUnderMandate` (named `mtxPayUnderMandate`), `revoke` | delegate signs; any relayer | `MandateWallet` | NONE; relayer pays gas | tx | **BUILT**; epoch and `mtx` names **SPECIFIED** | [CTR-ACC-06](mandates.md#CTR-ACC-06), [-07](mandates.md#CTR-ACC-07) |
 | Asset-suite action | forced transfer, freeze, `VestingGrant.release`, `Distribution` claim, `ExchangeOffer` | issuer / compliance role, or a permissionless claim | token or action contract | by action | tx | **SPECIFIED**, nothing built | [asset-suite.md](asset-suite.md) |
@@ -232,7 +232,8 @@ token. A plan is atomic with no `try`. Interactions may not call the DEX, the pu
 listed ([CTR-DEX-23](dex.md#CTR-DEX-23)); the holder approves the puller, never the DEX
 ([CTR-DEX-22](dex.md#CTR-DEX-22)). Node: the TradeEngine, off unless enabled, EVM only
 ([NODE-DEX-17](../node/dex-venue.md#NODE-DEX-17)); it keeps no surplus ([NODE-DEX-18](../node/dex-venue.md#NODE-DEX-18)).
-Status **SPECIFIED** (P2c): not built.
+Status **BUILT** (P2c, `SCaaSDex`): the DEX also refuses a sell token that arrives inexact, and resets every allowance an
+`approve` interaction granted (controller ruling, pending the owner; [dex.md](dex.md#CTR-DEX-23)).
 
 ### 3.7 Confidential settlement (Zether, PQZ)
 
```

- [ ] **Step 2: `TODO.md` and `HANDOFF.md`** — the P2 row and bullets (P2b-2 merged `7049c78`, the new P2c bullet, the
  P2b-1 bullet's "Open for P2c" sentence, MT-5), a new HANDOFF top section `## Session 2026-10-11 (P2c)`, the P2b-2
  section's state "merged `7049c78`". After the implementation, put the real code commit in the HANDOFF state line.
  Apply:

```diff
diff --git a/HANDOFF.md b/HANDOFF.md
index 51e2eb9..9a3f494 100644
--- a/HANDOFF.md
+++ b/HANDOFF.md
@@ -1,8 +1,29 @@
 # HANDOFF — scaas
 
+## Session 2026-10-11 (P2c)
+
+**State:** P2c on branch `p2c-dex`, merge pending the final review. Plan `docs/superpowers/plans/2026-10-11-p2c-dex-exchange-path.md`.
+937 forge tests.
+
+**Built:** the exchange path on `SCaaSDex` (`src/dex/SCaaSDex.sol`, `ISCaaSDex.sol` with `IExchangeExecutor`): `mtxExchange`
+(interactions), `mtxExchangeVia` (executor), `setExchangeTarget`, `setListedOnly`, `exchangeTarget`, `tokenKnown`;
+`ExchangeLegSettled`, `ExchangeTargetSet`, `ListedOnlySet`; `NoLegs`, `TokenNotKnown`, `ForbiddenTarget`, `ForbiddenSelector`,
+`TargetNotListed`, `InsufficientOutput`. Tests `test/v2/DexExchange.t.sol` 24 (mock router, v2-style pairs, executor,
+hostile targets). Sizes: `SCaaSDex` 21,761 B (was 14,722); tokens unchanged; no deploy change.
+
+**Rulings J1-J11 (plan header).** **J1** Path A bounds at the pull (token or `TradeLib`), Path B by the DEX, as in
+`mtxSettle`. **J2** known = a side of a listed market, counted per market. **J3** a pull check refuses an inexact sell
+token before any interaction. **J4** every `approve` interaction reset to 0 after the last one (stricter than the spec).
+**J5** leftovers fail the final conservation check. **J6** error arguments. **J7** under the listing condition the tokens
+an interaction calls are targets too. **J8** `NoLegs`. **J9** `receivedFloor` is gross. **J10** no Uniswap fork test yet.
+**J11** no deploy change; two storage fields appended.
+
+**Not done / next:** the Uniswap fork test and the DEX invariant suite (dex.md section 14); the node's TradeEngine (P7);
+`checkOrder` (H7) and the Hedera ED25519 limitation stay as in P2b-2.
+
 ## Session 2026-10-11 (P2b-2)
 
-**State:** P2b-2 on branch `p2b2-dex`, merge pending the final review (code `f4afbca`, plan `7b77cd1`, tests `6b9c645`). Plan
+**State:** P2b-2 on branch `p2b2-dex`, merged `7049c78` (code `f4afbca`, plan `7b77cd1`, tests `6b9c645`). Plan
 `docs/superpowers/plans/2026-10-11-p2b2-dex-outside-legs.md`. 913 forge tests.
 
 **Built:** `src/dex/DexPuller.sol` (`pull(token, from, amount)`, only the DEX), `ISCaaSDex.sol` and `SCaaSDex.sol` extended: outside
diff --git a/TODO.md b/TODO.md
index ea9c774..bd84b1c 100644
--- a/TODO.md
+++ b/TODO.md
@@ -14,7 +14,7 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 |---|---|---|
 | P0 | Spec and fold into the component docs and `decisions.md` | done |
 | P1 | The complete base on the new tree: `MetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`; both structs, allowlist, ticket; approve rule; `salt = chain_uid`; CREATE2 deployer; kinds `NORMAL`, `WRAPPED`; factory `createToken`; the v1/v2 lines to the backup (v2 done in P1e, v1 renamed `…V1` until P3/P5) | MT-1, MT-2, MT-3, MT-4 |
-| P2 | **P2a** `TradeLib` token side + `mtxWrap` (done, merged `6a5c6b0`); **P2b-1** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle` for SCaaS legs (done, merged `0510c7d`; old `SCaaSDex` kept as `SCaaSDexV1` for the node until P5); **P2b-2** outside legs (`DexOrder`, `DexPuller`, DEX-side cancels, ERC-1271 cap, bounded `MatchFailed`) (done on branch `p2b2-dex`, merge pending the final review; `checkOrder` not built, H7); **P2c** exchange path | MT-5 |
+| P2 | **P2a** `TradeLib` token side + `mtxWrap` (done, merged `6a5c6b0`); **P2b-1** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle` for SCaaS legs (done, merged `0510c7d`; old `SCaaSDex` kept as `SCaaSDexV1` for the node until P5); **P2b-2** outside legs (`DexOrder`, `DexPuller`, DEX-side cancels, ERC-1271 cap, bounded `MatchFailed`) (done, merged `7049c78`; `checkOrder` not built, H7); **P2c** exchange path `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly` (done on branch `p2c-dex`, merge pending the final review) | MT-5 |
 | P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; delete `ZetherToken` | MT-6 |
 | P4 | `MandateWallet`, `SmartKeyAccount` (rename, every family) on `MetaTxBase` | MT-7 (+ rename in NM-*) |
 | P5 | Node, clientkeys, encoders for the new ABI | MT-8, MT-9 |
@@ -60,11 +60,12 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 
 **P2 — MT-5**
 - P2a (done, merged `6a5c6b0`): `TradeLib` (`scaas.trade`) and the trade entries on every token, `mtxWrap` + `NativeNotGasless` on `WrappedToken` (D1 closed; a native wrap by `mtxExecute(wrap(…))` still reverts `NativeValueMismatch(0, amount)`); 855 tests. Plan `docs/superpowers/plans/2026-10-11-p2a-trade-token-side.md`. Open for P2b/P2c: the DEX side below. **F4 (owner): `NormalToken` is 22,951 B, over its 20,480 B budget (ratchet baseline), `WrappedToken` 29,974 B: owner — code size is not a concern, the product waits for the Glamsterdam fork (larger code limit); the ratchet baseline records sizes.**
-- P2b-1 (done, merged `0510c7d`): `SCaaSDex` clone (`scaas.dex`, salted domain `SCaaS Dex`; MT-4 domain done for the new DEX), `OpenFactory` DEX catalogue and `createDex`/`isDex`/`dexVersionOf`, deploy key `dex_implementation`, built DEX kept as `SCaaSDexV1`; 891 tests. Plan `docs/superpowers/plans/2026-10-11-p2b1-scaasdex-clone.md`. P2b-2 built them except `checkOrder` (see P2b-2). Open for P2c: `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly` (stored, not read). `SCaaSDexV1` moves to `legacy/` at P5 (owner: backup, not delete).
-- P2b-2 (done on branch `p2b2-dex`, merge pending the final review): outside legs (`DexOrder` in the DEX domain, `TradeLib` on the DEX's own `scaas.trade` state, `ESCROW` refused), `DexPuller` deployed by `initialize`, `mtxCancelOrders` / `mtxInvalidateNonces`, ERC-1271 cap by codehash (constructor takes the `SmartKeyAccount` implementation), `MatchFailed` reason capped at 256 bytes, `SigCheckGasStarved` reverts the whole `mtxSettle` (m8 closed), payouts by `SafeERC20`; 913 tests. Plan `docs/superpowers/plans/2026-10-11-p2b2-dex-outside-legs.md`. Open: `checkOrder` for the new DEX (not specified: dex.md §10 reads are the intake; with the node's P7 intake), the DEX invariant suite (§14), P2c. Size baseline raised by 9 B per token (`precheck` argument). Node P7: a batch reverting with `SigCheckGasStarved` is split and simulated per settlement, never retried whole with more gas (a party's `destination` that is a hook-token recipient can forge the selector; hook tokens are never listed). `mtxSettle` success is not monotonic in gas (a settlement can fail with an empty `MatchFailed` reason at a gas above a starved-revert window), so the node never trusts plain `eth_estimateGas`: it sizes gas from a simulation that requires every planned `ok[i]` true and reads an empty `MatchFailed` reason as out of gas (retry with more gas, never mark the order invalid). Limitation: no HIP-632 branch on DEX signatures, so a Hedera ED25519 account cannot sign a `DexOrder` or a DEX-side cancel (follow-up: `IS_HEDERA` in `SCaaSDex`).
+- P2b-1 (done, merged `0510c7d`): `SCaaSDex` clone (`scaas.dex`, salted domain `SCaaS Dex`; MT-4 domain done for the new DEX), `OpenFactory` DEX catalogue and `createDex`/`isDex`/`dexVersionOf`, deploy key `dex_implementation`, built DEX kept as `SCaaSDexV1`; 891 tests. Plan `docs/superpowers/plans/2026-10-11-p2b1-scaasdex-clone.md`. P2b-2 built them except `checkOrder` (see P2b-2). P2c built `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly`. `SCaaSDexV1` moves to `legacy/` at P5 (owner: backup, not delete).
+- P2b-2 (done, merged `7049c78`): outside legs (`DexOrder` in the DEX domain, `TradeLib` on the DEX's own `scaas.trade` state, `ESCROW` refused), `DexPuller` deployed by `initialize`, `mtxCancelOrders` / `mtxInvalidateNonces`, ERC-1271 cap by codehash (constructor takes the `SmartKeyAccount` implementation), `MatchFailed` reason capped at 256 bytes, `SigCheckGasStarved` reverts the whole `mtxSettle` (m8 closed), payouts by `SafeERC20`; 913 tests. Plan `docs/superpowers/plans/2026-10-11-p2b2-dex-outside-legs.md`. Open: `checkOrder` for the new DEX (not specified: dex.md §10 reads are the intake; with the node's P7 intake), the DEX invariant suite (§14). Size baseline raised by 9 B per token (`precheck` argument). Node P7: a batch reverting with `SigCheckGasStarved` is split and simulated per settlement, never retried whole with more gas (a party's `destination` that is a hook-token recipient can forge the selector; hook tokens are never listed). `mtxSettle` success is not monotonic in gas (a settlement can fail with an empty `MatchFailed` reason at a gas above a starved-revert window), so the node never trusts plain `eth_estimateGas`: it sizes gas from a simulation that requires every planned `ok[i]` true and reads an empty `MatchFailed` reason as out of gas (retry with more gas, never mark the order invalid). Limitation: no HIP-632 branch on DEX signatures, so a Hedera ED25519 account cannot sign a `DexOrder` or a DEX-side cancel (follow-up: `IS_HEDERA` in `SCaaSDex`).
+- P2c (done on branch `p2c-dex`, merge pending the final review): the exchange path on `SCaaSDex` — `mtxExchange` (interactions: never the DEX or the puller, never `mtxTrade`, data of at least 4 bytes), `mtxExchangeVia` (`IExchangeExecutor.exchangeCallback`), `setExchangeTarget` / `setListedOnly` and the `LISTED_POOLS` condition, `tokenKnown` (counted per listed market), the surplus to the signers by floor with the remainder to the last leg, `InsufficientOutput`, conservation over every snapshotted token, a pull check that refuses an inexact sell token, every `approve` interaction reset to 0; `ExchangeLegSettled`; 937 tests. Plan `docs/superpowers/plans/2026-10-11-p2c-dex-exchange-path.md`. Open: the fork test with real Uniswap bytecode (dex.md section 14), the DEX invariant suite, the node's TradeEngine (NODE-DEX-17/18, P7).
 - P2 notes (from P1c, P1d): (2) Named `mtxTransfer` is +9 execution gas over `mtxExecuteTransfer` (33,681 vs 33,672): the row is logged, not asserted; `mtxPay` on a fresh lane is +2.6 k (the `PAYABLE` gate's cold SLOAD, C3). (3) The asset suite's inline per-transfer admin check (CTR-TOK-24) also needs NORMAL bytes: it competes with the size debt in F4.
 - [x] Rename `OrderBookDex` → `SCaaSDex` (owner 2026-10-09; EIP-712 domain name `SCaaS Dex`); git mv + docs + node names. (done 2026-10-09)
-- [~] **MT-5** DEX (P2a done: `TradeOrder` + `mtxTrade`/`mtxCancelOrder`/`mtxInvalidateNonces` in the tokens, `receiveToken == this` accepted, flag 4 not read by the token; P2b done (P2b-1, P2b-2); open: P2c): `SCaaSDex.mtxSettle`
+- [~] **MT-5** DEX (P2a done: `TradeOrder` + `mtxTrade`/`mtxCancelOrder`/`mtxInvalidateNonces` in the tokens, `receiveToken == this` accepted, flag 4 not read by the token; P2b done (P2b-1, P2b-2); P2c done on branch `p2c-dex`; open: the invariant suite, the Uniswap fork test): `SCaaSDex.mtxSettle`
       (Path A/B, 1 taker + N makers, 50 % floor, fee split, conservation invariant); outside-token legs through the
       `DexPuller` (CTR-DEX-22); exchange path `mtxExchange`/`mtxExchangeVia` (CTR-DEX-20), surplus distribution
       (CTR-DEX-21), interaction blocklist + `LISTED_POOLS`/listed-only (CTR-DEX-23), admin `setExchangeTarget`/
```

- [ ] **Step 3: Run** `python3 scripts/test_docs_check.py`, `python3 scripts/docs_check.py check`, `python3
  scripts/docs_check.py facts check` → 0 errors (the `dex.md` and `token-wrappers.md` budget warnings predate this plan;
  `dex.md` stays at 536 counted lines).
- [ ] **Step 4: Commit** `P2c: docs, TODO and HANDOFF` + trailer.

---

### Final

- Whole-branch review (Opus, effort xhigh): rerun both mutation probes (Task 1 Step 4) and probe beyond them — a route
  whose output token is also a sold token (cycle) with a Path B leg in it, `extraTokens` repeating a leg token or holding
  `address(0)`, an `approve` interaction on a non-token target (the reset call), USDT-style tokens on the reset path
  (`forceApprove`), an executor that is an EOA; one fix wave; scoped re-review.
- Merge `p2c-dex` into `main` `--no-ff`; push; remove the worktree `.claude/worktrees/p2c`.
