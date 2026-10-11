# P2b-1 — `SCaaSDex` as a factory clone: `mtxSettle` for SCaaS legs, fee split, conservation; `createDex` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the DEX side of `TradeOrder` for SCaaS tokens (CTR-DEX-16, -17, -11, -03, -24): a new `SCaaSDex`
implementation that `OpenFactory.createDex` clones, settling one taker against many makers per settlement through the
tokens' `mtxTrade` (P2a), paying every party, splitting each fee between the submitter and the treasury, and ending every
settlement with the DEX's balances unchanged. The built DEX is kept as `SCaaSDexV1` for the node until P5.

**Architecture:** `SCaaSDex` (new file) keeps its state in ERC-7201 `scaas.dex` (admin, fee split, listed-only flag,
listed pairs, token kinds) and its domain is `("SCaaS Dex","1",chainId,clone,chain_uid)` through `SaltedEIP712`.
`mtxSettle` runs each settlement in a self-call (`settleOne`) so one failure emits `MatchFailed` and the others run; a
call where none succeeds reverts. `setMarket` classifies each token from the factory (`isToken`, `versionOf`,
`isDeprecated`), never from a leg. `OpenFactory` gains a DEX catalogue (`registerDexImplementation`, `createDex`,
`isDex`, `dexVersionOf`). Outside-token legs (`DexOrder`, `DexPuller`, DEX-side cancels, `checkOrder`, the ERC-1271 cap)
are P2b-2; the exchange path is P2c.

**Tech Stack:** Solidity 0.8.37 (`osaka`), Foundry (forge 1.3.5), OpenZeppelin 5.2.0 (`ReentrancyGuardTransient`,
`Math`, `Clones`), forge-std 1.16.2; `scaas-node` e2e (anvil) as the deploy check.

**Spec:** `docs/contracts/dex.md` CTR-DEX-16, -17, -11, -03, -24, -19, -14 (DEX side for Path B), §10 invariants, §13,
§14; `docs/contracts/token-wrappers.md` CTR-TOK-25 (factory); TODO.md §00 P2.

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; forge in `smartcontracts/evm` of worktree `.claude/worktrees/p2b`
  (branch `p2b-dex`). Heavy commands only through `scripts/capped`, one at a time. `/usr/bin/grep`, `rtk proxy git diff`.
- Namespace `scaas.dex` = `0xb144ea5327f344ea7e3b34dd1898f534c8ce28f9f54d0d89a1b78f8fcf7dac00`.
- `PPM = 1_000_000`; `dexFee = ⌈receiveFill·fee/10⁶⌉` once per order per settlement on its aggregate receive;
  `relayerShare = ⌊dexFee·relayerSharePpm/10⁶⌋` to the submitter, the rest to `treasury`; `treasury ∉ {0, DEX}` unless
  `relayerSharePpm = 10⁶`.
- Maker receive = `⌈fill·receiveAmount/amount⌉` (the maker's price, in its favour); the taker's `fill` must equal the sum.
- Code size is not a concern (owner: wait for the Glamsterdam fork); the ratchet baseline records sizes. Measured in the
  spike: `SCaaSDex` 9,570 B, `OpenFactory` 8,476 B, `SCaaSDexV1` 13,204 B.
- Commit trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never `git add claude-code-api.txt`.

## Review Focus

- A party paid less than its signed price or a fee above its signed rate (maker rounding, taker aggregate fee) — pinned by
  `test_settle_oneTakerTwoMakers_paysEveryone_splitsFees_conserves`, `test_makerPriceRoundsInTheMakersFavour`,
  `test_takerFeeChargedOnceOnTheAggregate`.
- Funds stuck in or drained from the DEX (refunds, fee remainders, conservation) — pinned by the settle test's DEX
  balance asserts and `test_pathB_escrowMakerRefundsTheRest`.
- One bad leg breaking a whole batch, or a batch that settles nothing passing silently — pinned by
  `test_aFailingSettlementIsIsolated` and `NothingSettled` in `test_pathB_dexChecksTheMatchedPart`.
- A submitter-chosen arrangement that bypasses a check (wrong relayer, same signer both sides, the same order twice, an
  unlisted pair, an outside token sent down `mtxTrade`) — pinned by `test_checks`, `test_outsideTokenLegsAreNotBuiltYet`.
- A clone initialised twice, an implementation of another factory or chain registered — pinned by
  `test_createDex_registry_andInitializeOnce`, `test_registerDex_checksFactoryAndChain`.

## Rulings (docs vs code) and defaults taken

- **G1 — P2b is split:** P2b-1 (this plan: SCaaS legs), P2b-2 (outside legs: `DexOrder`, `DexPuller`, DEX-side
  `mtxCancelOrders`/`mtxInvalidateNonces`, `checkOrder`, CTR-DEX-08 ERC-1271 cap), P2c (exchange path,
  `setExchangeTarget`, `setListedOnly`). A market with an outside token can be listed (its kind is recorded) but a
  settlement with it reverts `OutsideLegNotBuilt(token)`.
- **G2 — The built DEX becomes `SCaaSDexV1`** (`git mv`, contract and its two test files renamed) and stays deployed by the
  script for the node (`scaas-node/src/dex.rs`, `dex_kat.json`, e2e key `scaas_dex`) until P5, then moves to `legacy/`
  (owner: backup, not delete). The new `SCaaSDex` is a new file.
- **G3 — Who checks what on the matched part:** Path A bounds are the token's (`mtxTrade`, P2a); the DEX does not repeat
  them. Path B (`ESCROW`) is checked by the DEX on the matched part: `Overfill`, `BelowMinFill` (effective minimum and
  received side, remainder clause), `PriceLimit`; the token checks the escrow shape.
- **G4 — Arrangement checks:** `TokenMismatch` (and taker sell ≠ receive), `SelfTrade` = a maker's `from` equals the
  taker's (makers may share a signer), `DuplicateOrder` = the same order hash twice among the makers, `WrongRelayer`,
  `DexMismatch` (`o.dex ≠ this`), `NoMakers`, `FillMismatch(expected, got)` for the taker's stated fill.
- **G5 — DEX registry names:** `registerDexImplementation`, `dexImplementationOf`, `latestDexVersion`, `createDex`,
  `isDex`, `dexVersionOf` (the spec's `versionOf` is the token one, which returns a token kind). The DEX implementation
  answers `factory()` and `chainUid()`, checked at registration like a token.
- **G6 — Conservation** is asserted on the two tokens of the settlement (`ConservationBroken(token)`); fee shares and
  refunds are sent per leg, one `LegSettled` per leg.
- **G7 — Deploy:** the scripts deploy and register the DEX implementation (JSON key `dex_implementation`); no clone is
  created by the script (the venue's admin calls `createDex`).

---

### Task 1: `SCaaSDex` (clone), the factory's DEX catalogue, `SCaaSDexV1`, tests, deploy

**Model:** Sonnet, effort high (spike-tested transcription on a money path).

**Files:**
- Rename: `smartcontracts/evm/src/dex/SCaaSDex.sol` → `SCaaSDexV1.sol`, `test/SCaaSDex.t.sol` → `test/SCaaSDexV1.t.sol`,
  `test/SCaaSDexInvariant.t.sol` → `test/SCaaSDexV1Invariant.t.sol` (`git mv`; `sed -i -E 's/\bSCaaSDex\b/SCaaSDexV1/g;
  s#/SCaaSDex\.sol"#/SCaaSDexV1.sol"#'` on those three files and `script/Deploy.s.sol`)
- Create: `smartcontracts/evm/src/dex/ISCaaSDex.sol`, `smartcontracts/evm/src/dex/SCaaSDex.sol`,
  `smartcontracts/evm/test/v2/Dex.t.sol`
- Modify: `smartcontracts/evm/src/factory/IOpenFactory.sol`, `smartcontracts/evm/src/factory/OpenFactory.sol`,
  `smartcontracts/evm/script/DeployBase.sol`

**Interfaces:** Consumes P2a's `ITradeToken` (`TradeOrder`, `TradeFill`, `mtxTrade`, `tradeOrderDigest`). Produces
`ISCaaSDex` (structs `DexConfig`, `Leg`, `Settlement`; events; errors), `SCaaSDex(address factory, bytes32 chainUid)`,
`OpenFactory.createDex(uint64, ISCaaSDex.DexConfig, bytes32)`, `isDex`, `dexVersionOf`, `registerDexImplementation`.

- [ ] **Step 1: the renames** (commands above).
- [ ] **Step 2: `src/dex/ISCaaSDex.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ITradeToken} from "../trade/ITradeToken.sol";

/// @title The DEX side of `TradeOrder` (CTR-DEX-16, -17, -11, -03, -24): one taker against many makers per settlement,
///        every leg pulled into the DEX through its token's `mtxTrade`, every party, fee share and refund paid in the
///        same call, and the DEX's balance of every token unchanged at the end.
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

    /// @notice `ref` is the submitter's, echoed in events only; taker/makers is a call-time arrangement.
    struct Settlement {
        bytes32 ref;
        Leg taker;
        Leg[] makers;
    }

    event MarketSet(address indexed base, address indexed quote, bool listed);
    event FeeSplitSet(uint32 relayerSharePpm, address treasury);
    event LegSettled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed from, address destination,
        uint256 sold, uint256 received, uint256 dexFee, uint256 refund, uint256 relayerShare, uint256 treasuryShare);
    event MatchFailed(bytes32 indexed ref, bytes reason);

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
    /// @notice An outside (non-SCaaS) token leg: `DexOrder` + `DexPuller` come with P2b-2.
    error OutsideLegNotBuilt(address token);
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

- [ ] **Step 3: `src/dex/SCaaSDex.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ISCaaSDex} from "./ISCaaSDex.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";

/// @title `SCaaSDex` (CTR-DEX-16, -17, -11, -03, -24): an EIP-1167 clone made by `OpenFactory.createDex`.
/// @notice One settlement = one taker against 1..n makers at each maker's signed price (rounded in the maker's favour).
///         Every leg is pulled into the DEX through its sell token's `mtxTrade` (Path A: the exact fill, the token
///         checks every signed bound; Path B, `ESCROW`: the whole amount, the DEX checks the matched part and refunds
///         the rest), every party is paid in the same call, each order's fee `⌈receiveFill·fee/10⁶⌉` is charged once on
///         its aggregate receive and split between the submitter and the treasury, and the DEX's balance of both
///         tokens is unchanged at the end (`ConservationBroken`). Each settlement is atomic; one that fails emits
///         `MatchFailed` and the others still run. The admin lists markets and sets the fee split, never an amount.
///         Built: SCaaS legs only (outside legs, `DexOrder`, `DexPuller`: P2b-2; exchange path: P2c).
contract SCaaSDex is ISCaaSDex, SaltedEIP712, ReentrancyGuardTransient {
    uint256 internal constant PPM = 1_000_000;
    uint8 internal constant ESCROW = 2;
    uint8 internal constant KIND_SCAAS = 1;
    uint8 internal constant KIND_OUTSIDE = 2;

    /// @custom:storage-location erc7201:scaas.dex
    struct DexStorage {
        bool initialized;
        address admin;
        uint32 relayerSharePpm;
        address treasury;
        bool listedOnly;
        mapping(bytes32 pair => bool) listed;
        mapping(address token => uint8) kind;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.dex")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xb144ea5327f344ea7e3b34dd1898f534c8ce28f9f54d0d89a1b78f8fcf7dac00;

    address public immutable FACTORY;

    /// @dev Per leg, computed before any transfer.
    struct Calc {
        bytes32 h;
        uint256 sold;    // matched sell fill
        uint256 recv;    // gross receive
        uint256 fee;     // dexFee on recv
        uint256 refund;  // Path B: amount - sold
    }

    /// @dev Runs once on the implementation and locks it.
    constructor(address factory_, bytes32 chainUid_) SaltedEIP712("SCaaS Dex", "1", chainUid_) {
        FACTORY = factory_;
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
        if (msg.sender != s.admin || msg.sender == address(0)) revert NotAdmin(msg.sender);
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

    // ------------------------------------------------------------------ settle (CTR-DEX-16)

    /// @notice Each settlement atomic; at least one must succeed, else the call reverts (the relayer's simulation
    ///         catches it).
    function mtxSettle(Settlement[] calldata ss) external nonReentrant returns (bool[] memory ok) {
        ok = new bool[](ss.length);
        bool any;
        for (uint256 i; i < ss.length; ++i) {
            try this.settleOne(ss[i], msg.sender) {
                ok[i] = true;
                any = true;
            } catch (bytes memory reason) {
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
        if (s.kind[a] != KIND_SCAAS) revert OutsideLegNotBuilt(a);
        if (s.kind[b] != KIND_SCAAS) revert OutsideLegNotBuilt(b);
    }

    /// @dev A maker sells `fill` at its own price: it receives `⌈fill·receiveAmount/amount⌉` (in its favour).
    function _makerCalc(Leg calldata m, address submitter) private view returns (Calc memory c) {
        uint256 recv = Math.mulDiv(m.fill, m.o.receiveAmount, m.o.amount, Math.Rounding.Ceil);
        c = _calc(m, submitter, m.fill, recv);
    }

    /// @dev Relayer binding, `dex`, the fee on the aggregate receive; Path B: the DEX's own checks on the matched part.
    function _calc(Leg calldata l, address submitter, uint256 sold, uint256 recv) private view returns (Calc memory c) {
        ITradeToken.TradeOrder calldata o = l.o;
        if (o.relayer != address(0) && o.relayer != submitter) revert WrongRelayer(submitter);
        if (o.dex != address(this)) revert DexMismatch(o.dex);
        c.h = ITradeToken(l.sellToken).tradeOrderDigest(o);
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
        ITradeToken(l.sellToken).mtxTrade(l.o, l.sig, f);
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
        emit LegSettled(ref, c.h, l.o.from, to, c.sold, c.recv, c.fee, c.refund, relayerShare, treasuryShare);
    }

    function _send(address token, address to, uint256 amount) private {
        if (amount != 0) IERC20(token).transfer(to, amount);
    }
}
```

- [ ] **Step 4: the factory** — apply:

```diff
diff --git a/smartcontracts/evm/src/factory/IOpenFactory.sol b/smartcontracts/evm/src/factory/IOpenFactory.sol
index 363064d..7b4e356 100644
--- a/smartcontracts/evm/src/factory/IOpenFactory.sol
+++ b/smartcontracts/evm/src/factory/IOpenFactory.sol
@@ -2,6 +2,7 @@
 pragma solidity ^0.8.24;
 
 import {IFactoryToken} from "./IFactoryToken.sol";
+import {ISCaaSDex} from "../dex/ISCaaSDex.sol";
 
 /// @title The one token factory of a chain (CTR-TOK-03, CTR-TOK-25): an append-only catalogue of implementations per
 ///        kind, EIP-1167 clones by `CREATE2` initialised in the same call, no power over any token it created.
@@ -40,6 +41,13 @@ interface IOpenFactory {
     /// @notice `NONE*` 0 legs, `UNDERLYING*` 1–8.
     error UnderlyingCountInvalid(uint256 n);
     error SaltAlreadyUsed(address existing);
+    error DexVersionUnknown(uint64 version);
+    error DexVersionAlreadyRegistered(uint64 version, address existing);
+
+    /// @notice DEX catalogue (CTR-DEX-24): append-only, versions from 1; the implementation must answer
+    ///         `factory() == this` and `chainUid() == chainUid`.
+    event DexImplementationRegistered(uint64 indexed version, address indexed implementation, address registrar);
+    event DexCreated(address indexed dex, address indexed creator, uint64 version, address implementation, address admin);
 
     function registrar() external view returns (address);
     function chainUid() external view returns (bytes32);
@@ -67,4 +75,13 @@ interface IOpenFactory {
     function getWrapperAt(address creator, address underlying, uint256 index) external view returns (address);
     function deployCountFor(address underlying) external view returns (uint256);
     function deployedFor(address underlying, uint256 index) external view returns (address);
+
+    function registerDexImplementation(uint64 version, address implementation) external;
+    function dexImplementationOf(uint64 version) external view returns (address);
+    function latestDexVersion() external view returns (uint64);
+    /// @notice An `SCaaSDex` clone, `initialize(cfg)` in the same call (CTR-DEX-24).
+    function createDex(uint64 version, ISCaaSDex.DexConfig calldata cfg, bytes32 salt) external returns (address dex);
+    /// @notice Advisory (clients and the node); tokens never consult it (CTR-DEX-19).
+    function isDex(address dex) external view returns (bool);
+    function dexVersionOf(address dex) external view returns (uint64);
 }
```

```diff
diff --git a/smartcontracts/evm/src/factory/OpenFactory.sol b/smartcontracts/evm/src/factory/OpenFactory.sol
index 634464a..9e78774 100644
--- a/smartcontracts/evm/src/factory/OpenFactory.sol
+++ b/smartcontracts/evm/src/factory/OpenFactory.sol
@@ -4,6 +4,7 @@ pragma solidity ^0.8.24;
 import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
 import {IOpenFactory} from "./IOpenFactory.sol";
 import {IFactoryToken} from "./IFactoryToken.sol";
+import {ISCaaSDex} from "../dex/ISCaaSDex.sol";
 import {ITokenAdmin} from "../metatx/ITokenAdmin.sol";
 
 /// @title `OpenFactory` (CTR-TOK-03, CTR-TOK-25): the one token factory of a chain.
@@ -32,6 +33,9 @@ contract OpenFactory is IOpenFactory {
     mapping(address => Info) private _info;
     mapping(address => mapping(address => address[])) private _wrappers;
     mapping(address => address[]) private _byUnderlying;
+    mapping(uint64 => address) private _dexImpl;
+    uint64 private _latestDex;
+    mapping(address => uint64) private _dexVersion; // 0 = not a DEX made here
 
     constructor(address registrar_, bytes32 chainUid_) {
         if (chainUid_ == bytes32(0)) revert ChainUidZero();
@@ -124,6 +128,43 @@ contract OpenFactory is IOpenFactory {
         return _byUnderlying[underlying][index];
     }
 
+    // ------------------------------------------------------------------ DEX (CTR-DEX-24)
+
+    function registerDexImplementation(uint64 version, address implementation) external {
+        if (msg.sender != registrar) revert NotRegistrar();
+        if (version == 0) revert DexVersionUnknown(0);
+        address existing = _dexImpl[version];
+        if (existing != address(0)) revert DexVersionAlreadyRegistered(version, existing);
+        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
+        (bool ok, uint256 got) = _word(implementation, bytes4(keccak256("factory()")));
+        if (!ok || got != uint256(uint160(address(this)))) revert ImplementationFactoryMismatch(implementation);
+        (ok, got) = _word(implementation, bytes4(keccak256("chainUid()")));
+        if (!ok || bytes32(got) != chainUid) revert ChainUidMismatch(chainUid, ok ? bytes32(got) : bytes32(0));
+        _dexImpl[version] = implementation;
+        if (version > _latestDex) _latestDex = version;
+        emit DexImplementationRegistered(version, implementation, msg.sender);
+    }
+
+    function dexImplementationOf(uint64 version) external view returns (address) { return _dexImpl[version]; }
+
+    function latestDexVersion() external view returns (uint64) { return _latestDex; }
+
+    function createDex(uint64 version, ISCaaSDex.DexConfig calldata cfg, bytes32 salt) external returns (address dex) {
+        address impl = _dexImpl[version];
+        if (impl == address(0)) revert DexVersionUnknown(version);
+        bytes32 s = _salt(msg.sender, salt);
+        address predicted = Clones.predictDeterministicAddress(impl, s);
+        if (predicted.code.length != 0 || _dexVersion[predicted] != 0) revert SaltAlreadyUsed(predicted);
+        dex = Clones.cloneDeterministic(impl, s);
+        ISCaaSDex(dex).initialize(msg.sender, version, cfg);
+        _dexVersion[dex] = version;
+        emit DexCreated(dex, msg.sender, version, impl, cfg.admin);
+    }
+
+    function isDex(address dex) external view returns (bool) { return _dexVersion[dex] != 0; }
+
+    function dexVersionOf(address dex) external view returns (uint64) { return _dexVersion[dex]; }
+
     // ------------------------------------------------------------------ internal
 
     /// @dev Code, `kind()`, `factory()`, `chainUid()`: each read by staticcall, a missing or short answer refused.
```

- [ ] **Step 5: `test/v2/Dex.t.sol`** (full text). Build every settlement **before** `vm.prank`/`vm.expectRevert`:
  `_book()`/`_leg()` make external calls (`tradeOrderDigest`) that would consume the cheatcode.

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UID_, noneInit} from "./helpers/V2Fixture.sol";

/// `SCaaSDex` as a factory clone (CTR-DEX-24) settling SCaaS legs (CTR-DEX-16, -17, -11): one taker against many makers,
/// every leg pulled through its token's `mtxTrade`, every party paid in the same call, the fee split, conservation.
contract DexTest is Test {
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant BOB_PK = 0xB0B;
    uint256 constant CAROL_PK = 0xCA401;
    address alice = vm.addr(ALICE_PK);
    address bob = vm.addr(BOB_PK);
    address carol = vm.addr(CAROL_PK);
    address registrar = address(0xF00D);
    address admin = address(0xAD);
    address treasury = address(0x7EA5);
    address relayer = address(0xBEEF);

    OpenFactory f;
    SCaaSDex dexImpl;
    SCaaSDex dex;
    NoUnderlyingToken a; // the taker sells A
    NoUnderlyingToken b; // the makers sell B

    function setUp() public {
        f = new OpenFactory(registrar, UID_);
        address noneImpl = address(new NoUnderlyingToken(address(f), address(0), UID_, false));
        dexImpl = new SCaaSDex(address(f), UID_);
        vm.startPrank(registrar);
        f.registerImplementation(IOpenFactory.TokenKind.NONE, 1, noneImpl);
        f.registerDexImplementation(1, address(dexImpl));
        vm.stopPrank();
        a = NoUnderlyingToken(f.createToken(IOpenFactory.TokenKind.NONE, 1, noneInit("A", "A", 0, 1e6, alice, address(0)), "a"));
        IFactoryToken.TokenConfig memory cb = noneInit("B", "B", 0, 1e6, bob, address(0));
        b = NoUnderlyingToken(f.createToken(IOpenFactory.TokenKind.NONE, 1, cb, "b"));
        vm.prank(bob);
        b.transfer(carol, 500_000);
        dex = SCaaSDex(f.createDex(1, ISCaaSDex.DexConfig(admin, 200_000, treasury, false), "dex"));
        vm.prank(admin);
        dex.setMarket(address(a), address(b), true);
    }

    // ------------------------------------------------------------------ helpers

    function _order(address from, NoUnderlyingToken receiveToken, uint256 amount, uint256 receiveAmount, uint256 fee)
        internal view returns (ITradeToken.TradeOrder memory o)
    {
        o.from = from;
        o.receiveToken = address(receiveToken);
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.fee = fee;
        o.dex = address(dex);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _leg(uint256 pk, NoUnderlyingToken sell, ITradeToken.TradeOrder memory o, uint256 fill)
        internal view returns (ISCaaSDex.Leg memory l)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, sell.tradeOrderDigest(o));
        l = ISCaaSDex.Leg(address(sell), o, abi.encodePacked(r, s, v), fill);
    }

    function _one(ISCaaSDex.Settlement memory s) internal pure returns (ISCaaSDex.Settlement[] memory ss) {
        ss = new ISCaaSDex.Settlement[](1);
        ss[0] = s;
    }

    /// Alice sells 1000 A for at least 1900 B (fee 0.3 %); Bob sells 1000 B for 500 A, Carol 1000 B for 520 A (fee 0.1 %).
    function _book() internal view returns (ISCaaSDex.Settlement memory s) {
        s.ref = "r1";
        s.makers = new ISCaaSDex.Leg[](2);
        s.makers[0] = _leg(BOB_PK, b, _order(bob, a, 1000, 500, 1_000), 1000);
        s.makers[1] = _leg(CAROL_PK, b, _order(carol, a, 1000, 520, 1_000), 1000);
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 1020, 1900, 3_000), 1020); // 500 + 520 at the makers' prices
    }

    // ------------------------------------------------------------------ settle

    function test_settle_oneTakerTwoMakers_paysEveryone_splitsFees_conserves() public {
        ISCaaSDex.Settlement[] memory ss = _one(_book()); // before the prank: _book makes external calls
        vm.recordLogs();
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle(ss);
        assertTrue(ok[0]);
        // taker: receives 2000 B gross, fee ceil(2000·0.3 %) = 6 → 1994; relayer share 20 % of 6 = 1, treasury 5
        assertEq(b.balanceOf(alice), 1994);
        assertEq(a.balanceOf(alice), 1e6 - 1020);
        // makers: 500 A and 520 A gross, fee ceil(0.5) = 1 each → 499 and 519; relayer floor(0.2) = 0
        assertEq(a.balanceOf(bob), 499);
        assertEq(a.balanceOf(carol), 519);
        assertEq(b.balanceOf(relayer), 1);
        assertEq(b.balanceOf(treasury), 5);
        assertEq(a.balanceOf(treasury), 2);
        assertEq(a.balanceOf(address(dex)), 0);
        assertEq(b.balanceOf(address(dex)), 0);
        uint256 legs;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) if (logs[i].topics[0] == ISCaaSDex.LegSettled.selector) ++legs;
        assertEq(legs, 3);
    }

    function test_makerPriceRoundsInTheMakersFavour() public {
        ISCaaSDex.Settlement memory s;
        s.ref = "r";
        s.makers = new ISCaaSDex.Leg[](1);
        s.makers[0] = _leg(BOB_PK, b, _order(bob, a, 1000, 333, 0), 1000); // 1000 B for 333 A
        // a 600 B fill would pay ceil(600·333/1000) = ceil(199.8) = 200 A, but 600 < half-of-1000 floor? 600 ≥ 500: ok
        s.makers[0] = _leg(BOB_PK, b, _order(bob, a, 1000, 333, 0), 600);
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 200, 600, 0), 200);
        vm.prank(relayer);
        dex.mtxSettle(_one(s));
        assertEq(a.balanceOf(bob), 200);
        assertEq(b.balanceOf(alice), 600);
    }

    function test_takerFeeChargedOnceOnTheAggregate() public {
        // each maker leg alone would give the taker 1000 B → ceil(3) = 3 + 3 = 6; on the aggregate 2000 → 6: same here,
        // so use a rate where the per-maker ceilings exceed the aggregate: 0.15 % → per-maker ceil(1.5)=2+2=4, aggregate 3
        ISCaaSDex.Settlement memory s = _book();
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 1020, 1900, 1_500), 1020);
        vm.prank(relayer);
        dex.mtxSettle(_one(s));
        assertEq(b.balanceOf(alice), 1997);
    }

    function test_pathB_escrowMakerRefundsTheRest() public {
        ISCaaSDex.Settlement memory s;
        s.ref = "r";
        s.makers = new ISCaaSDex.Leg[](1);
        ITradeToken.TradeOrder memory mo = _order(bob, a, 1000, 500, 0);
        mo.flags = 3; // IOC | ESCROW
        s.makers[0] = _leg(BOB_PK, b, mo, 600);
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 300, 600, 0), 300);
        uint256 bobB = b.balanceOf(bob);
        vm.prank(relayer);
        dex.mtxSettle(_one(s));
        assertEq(b.balanceOf(bob), bobB - 600); // pulled 1000, refunded 400
        assertEq(a.balanceOf(bob), 300);
        assertEq(b.balanceOf(address(dex)), 0);
    }

    function test_pathB_dexChecksTheMatchedPart() public {
        ITradeToken.TradeOrder memory mo = _order(bob, a, 1000, 500, 0);
        mo.flags = 3;
        ISCaaSDex.Settlement memory s;
        s.ref = "r";
        s.makers = new ISCaaSDex.Leg[](1);
        s.makers[0] = _leg(BOB_PK, b, mo, 400); // below the 50 % floor
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 200, 400, 0), 200);
        bytes32 h = b.tradeOrderDigest(mo);
        vm.prank(relayer);
        vm.expectRevert(ISCaaSDex.NothingSettled.selector);
        dex.mtxSettle(_one(s));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.BelowMinFill.selector, h));
        vm.prank(address(dex));
        dex.settleOne(s, relayer);
    }

    function test_aFailingSettlementIsIsolated() public {
        ISCaaSDex.Settlement[] memory ss = new ISCaaSDex.Settlement[](2);
        ss[0] = _book();
        ss[0].makers[0].sig[0] = bytes1(uint8(ss[0].makers[0].sig[0]) ^ 1); // a bad maker signature
        ss[1] = _book();
        ss[1].ref = "r2";
        ss[1].makers[0].o.nonce = 2;
        ss[1].makers[0] = _leg(BOB_PK, b, ss[1].makers[0].o, 1000);
        ss[1].makers[1].o.nonce = 2;
        ss[1].makers[1] = _leg(CAROL_PK, b, ss[1].makers[1].o, 1000);
        ss[1].taker.o.nonce = 2;
        ss[1].taker = _leg(ALICE_PK, a, ss[1].taker.o, 1020);
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle(ss);
        assertFalse(ok[0]);
        assertTrue(ok[1]);
        assertEq(b.balanceOf(alice), 1994);
    }

    function test_checks() public {
        ISCaaSDex.Settlement memory s = _book();
        s.taker.fill = 1019;
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.FillMismatch.selector, 1020, 1019));
        s = _book();
        s.makers[1] = s.makers[0];
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.DuplicateOrder.selector, b.tradeOrderDigest(s.makers[0].o)));
        s = _book();
        s.makers[0] = _leg(ALICE_PK, b, _order(alice, a, 1000, 500, 1_000), 1000);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.SelfTrade.selector, alice));
        s = _book();
        s.makers[0].sellToken = address(a);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.TokenMismatch.selector));
        s = _book();
        ITradeToken.TradeOrder memory o = _order(alice, b, 1020, 1900, 3_000);
        o.relayer = address(0x5E1);
        s.taker = _leg(ALICE_PK, a, o, 1020);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.WrongRelayer.selector, relayer));
        s = _book();
        s.makers = new ISCaaSDex.Leg[](0);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.NoMakers.selector));
        vm.prank(admin);
        dex.setMarket(address(a), address(b), false);
        _expectOne(_book(), abi.encodeWithSelector(ISCaaSDex.MarketNotListed.selector, address(a), address(b)));
    }

    function test_outsideTokenLegsAreNotBuiltYet() public {
        MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
        vm.prank(admin);
        dex.setMarket(address(a), address(usdc), true);
        assertEq(dex.tokenKind(address(usdc)), 2);
        assertEq(dex.tokenKind(address(a)), 1);
        ISCaaSDex.Settlement memory s = _book();
        s.taker.o.receiveToken = address(usdc);
        s.taker = _leg(ALICE_PK, a, s.taker.o, 1020);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.OutsideLegNotBuilt.selector, address(usdc)));
    }

    function test_settleOneOnlyThroughSettle() public {
        ISCaaSDex.Settlement memory s = _book();
        vm.expectRevert(ISCaaSDex.NotSelf.selector);
        dex.settleOne(s, relayer);
    }

    function _expectOne(ISCaaSDex.Settlement memory s, bytes memory err) internal {
        vm.prank(address(dex));
        vm.expectRevert(err);
        dex.settleOne(s, relayer);
    }

    // ------------------------------------------------------------------ factory and admin (CTR-DEX-24, CTR-DEX-03)

    function test_createDex_registry_andInitializeOnce() public {
        assertTrue(f.isDex(address(dex)));
        assertEq(f.dexVersionOf(address(dex)), 1);
        assertFalse(f.isDex(address(dexImpl)));
        assertEq(dex.admin(), admin);
        assertEq(dex.treasury(), treasury);
        assertEq(dex.relayerSharePpm(), 200_000);
        vm.expectRevert(ISCaaSDex.NotFactory.selector);
        dex.initialize(address(this), 1, ISCaaSDex.DexConfig(admin, 0, treasury, false));
        vm.prank(address(f));
        vm.expectRevert(ISCaaSDex.AlreadyInitialized.selector);
        dex.initialize(address(this), 1, ISCaaSDex.DexConfig(admin, 0, treasury, false));
        vm.prank(address(f));
        vm.expectRevert(ISCaaSDex.AlreadyInitialized.selector);
        dexImpl.initialize(address(this), 1, ISCaaSDex.DexConfig(admin, 0, treasury, false));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.DexVersionUnknown.selector, 2));
        f.createDex(2, ISCaaSDex.DexConfig(admin, 0, treasury, false), "x");
    }

    function test_registerDex_checksFactoryAndChain() public {
        SCaaSDex other = new SCaaSDex(address(0xFAC), UID_);
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationFactoryMismatch.selector, address(other)));
        f.registerDexImplementation(2, address(other));
        SCaaSDex wrongChain = new SCaaSDex(address(f), keccak256("x"));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, keccak256("x")));
        f.registerDexImplementation(2, address(wrongChain));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.DexVersionAlreadyRegistered.selector, 1, address(dexImpl)));
        f.registerDexImplementation(1, address(dexImpl));
        vm.stopPrank();
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.registerDexImplementation(3, address(dexImpl));
    }

    function test_adminOnly_feeSplitBounds() public {
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.NotAdmin.selector, address(this)));
        dex.setMarket(address(a), address(b), false);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.NotAdmin.selector, address(this)));
        dex.setFeeSplit(0, treasury);
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.FeeSplitInvalid.selector, 1, address(0)));
        dex.setFeeSplit(1, address(0));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.FeeSplitInvalid.selector, 1, address(dex)));
        dex.setFeeSplit(1, address(dex));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.FeeSplitInvalid.selector, 1_000_001, treasury));
        dex.setFeeSplit(1_000_001, treasury);
        dex.setFeeSplit(1_000_000, address(0)); // all to the relayer: no treasury needed
        vm.stopPrank();
        ISCaaSDex.Settlement[] memory ss = _one(_book());
        vm.prank(relayer);
        dex.mtxSettle(ss);
        assertEq(b.balanceOf(relayer), 6);
    }

    function test_domainIsTheClone_saltedWithTheChain() public view {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = dex.eip712Domain();
        assertEq(name, "SCaaS Dex");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(vc, address(dex));
        assertEq(salt, UID_);
        assertEq(dex.chainUid(), UID_);
        assertEq(dex.factory(), address(f));
    }
}
```

- [ ] **Step 6: deploy** — apply to `script/DeployBase.sol`:

```diff
diff --git a/smartcontracts/evm/script/DeployBase.sol b/smartcontracts/evm/script/DeployBase.sol
index 0b04445..0ee989c 100644
--- a/smartcontracts/evm/script/DeployBase.sol
+++ b/smartcontracts/evm/script/DeployBase.sol
@@ -5,6 +5,7 @@ import {Script} from "forge-std/Script.sol";
 import {OpenFactory} from "../src/factory/OpenFactory.sol";
 import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
 import {NoUnderlyingToken} from "../src/metatx/NoUnderlyingToken.sol";
+import {SCaaSDex} from "../src/dex/SCaaSDex.sol";
 
 /// @title Shared deploy steps (CTR-GEN-05, CTR-GEN-06, NET-EVM-05): `chain_uid` from the RPC, the deterministic CREATE2
 ///        deployer, the token factory with its implementations, the `chainUid()` gate.
@@ -39,10 +40,10 @@ abstract contract DeployBase is Script {
         require(u != bytes32(0), "RPC gave no block 0 hash");
     }
 
-    /// @notice The token factory and the `NONE` implementation by CREATE2, `NONE` registered as version 1 when the
-    ///         deployer is the registrar; writes `token_factory`, `implementation_none`, `chain_uid` into the JSON
-    ///         object `"deploy"`. Transitional (P1d ruling D2): `UnderlyingToken` is over EIP-170 until the size work,
-    ///         so `UNDERLYING` is not deployed yet.
+    /// @notice The token factory, the `NONE` implementation and the `SCaaSDex` implementation by CREATE2, each
+    ///         registered as version 1 when the deployer is the registrar; writes `token_factory`,
+    ///         `implementation_none`, `dex_implementation`, `chain_uid` into the JSON object `"deploy"`. `UNDERLYING` is
+    ///         not deployed: over EIP-170 on real chains (owner: wait for Glamsterdam).
     function _deployTokenFactory(address registrar, bool register, address smartKeyAccountImpl, bool isHedera)
         internal returns (OpenFactory f)
     {
@@ -53,6 +54,11 @@ abstract contract DeployBase is Script {
         _gate(address(none));
         vm.serializeAddress("deploy", "token_factory", address(f));
         vm.serializeAddress("deploy", "implementation_none", address(none));
+        // The DEX implementation (CTR-DEX-24): clones come from `createDex`; registered as DEX version 1.
+        SCaaSDex dexImpl = new SCaaSDex{salt: salt}(address(f), uid);
+        if (register) f.registerDexImplementation(1, address(dexImpl));
+        _gate(address(dexImpl));
+        vm.serializeAddress("deploy", "dex_implementation", address(dexImpl));
         vm.serializeBytes32("deploy", "chain_uid", uid);
     }
 
```

- [ ] **Step 7: Run** — `--match-path test/v2/Dex.t.sol` (13 passed); full suite 868 (855 + 13); size gate 0 errors;
  e2e (`cargo test --test e2e -- --ignored --test-threads=1`, `--test e2e_hedera -- --ignored`): 4/4 and 1/1.
- [ ] **Step 8: Commit** — `P2b-1: SCaaSDex as a factory clone — mtxSettle (SCaaS legs, Path A/B), fee split, conservation; createDex/isDex; built DEX kept as SCaaSDexV1` + trailer.

---

### Task 2: Docs, TODO, HANDOFF

**Model:** Sonnet, effort medium.

- `docs/contracts/dex.md`: CTR-DEX-16/17/11/03/24 "Transitional (BUILT, P2b-1)" notes (what is built; G1 outside legs and
  G3 Path A/B division; the error names; G5 registry names; G2 `SCaaSDexV1`); §13 rewritten for the two contracts; §14
  forge rows that are now built. Net ≤ 0 lines. Component docs: "controller ruling, pending the owner", no G-ids.
- `docs/contracts/token-wrappers.md` CTR-TOK-25 (`createDex` built with the G5 names) — net ≤ 0 lines.
- `docs/networks/evm.md`/`docs/contracts/README.md`: deploy JSON key `dex_implementation`.
- `TODO.md`: P2b-1 done; P2b-2 and P2c open (list); MT-4 `SCaaSDex` domain salted (built for the new DEX).
  `HANDOFF.md`: new top section (state, built, G1–G7, sizes, next = P2b-2 plan).
- Checkers 0 errors. Commit `P2b-1: docs, TODO and HANDOFF` + trailer.

---

### Final

- Whole-branch review (Opus, effort xhigh) with mutation probing of `settleOne`; one fix wave; scoped re-review.
- Merge `p2b-dex` into `main` `--no-ff`; push; remove the worktree.
